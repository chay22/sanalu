use crate::cli::{
    AsnCommands, CategoryCommands, CloudflareCommands, RegionCommands, WhitelistCommands,
};
use crate::cloudflare::{CloudflareClient, CloudflareRuleBudget};
use crate::config::AppConfig;
use crate::error::SanaluError;
use crate::firewall::{FirewallBackend, NftablesBackend};
use crate::storage::{RedbStore, StoredBanRecord};
use std::io::Write;
use std::net::IpAddr;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

pub fn format_status<W: Write>(
    out: &mut W,
    store: &RedbStore,
    db_path: &Path,
) -> Result<(), SanaluError> {
    let _ = writeln!(out, "=== Sanalu Status ===");
    let _ = writeln!(out, "Database: {:?}", db_path);

    let bans = store.list_active_bans().unwrap_or_default();
    let _ = writeln!(out, "\nActive Bans: {}", bans.len());
    for b in bans.iter().take(15) {
        let exp = match b.expires_at_secs {
            Some(s) => format!("expires in {}s", s),
            None => "permanent".to_string(),
        };
        let _ = writeln!(
            out,
            "  - {} (tier {}, {}, reason: {})",
            b.target, b.tier_level, exp, b.reason
        );
    }
    if bans.len() > 15 {
        let _ = writeln!(out, "  ... and {} more", bans.len() - 15);
    }

    let cats = store.list_blocked_categories().unwrap_or_default();
    let _ = writeln!(out, "\nBlocked Categories in DB: {:?}", cats);

    let asns = store.list_blocked_asns().unwrap_or_default();
    let _ = writeln!(out, "Blocked ASNs in DB: {:?}", asns);

    let regions = store.list_allowed_regions().unwrap_or_default();
    let _ = writeln!(out, "Allowed Regions in DB: {:?}", regions);

    let cf_state = store.get_cloudflare_state().unwrap_or_default();
    let _ = writeln!(out, "\nCloudflare Active Expression: {:?}", cf_state);
    Ok(())
}

pub fn format_check<W: Write>(
    out: &mut W,
    store: &RedbStore,
    target: &str,
) -> Result<(), SanaluError> {
    let maybe_ip = target.parse::<IpAddr>().ok();
    let target_kind = if maybe_ip.is_some() {
        "IP"
    } else if target.contains('/') {
        "CIDR"
    } else {
        "Unknown"
    };

    let _ = writeln!(out, "=== Sanalu Target Diagnostics ===");
    let _ = writeln!(out, "Target:            {} ({})", target, target_kind);

    let ban_status = store.check_ban_status(target)?;
    match ban_status {
        Some(record) => {
            let match_type = if record.target == target {
                "Direct Ban"
            } else {
                "Subnet Ban"
            };
            let _ = writeln!(out, "Status:            BANNED [{}]", match_type);
            if match_type == "Subnet Ban" {
                let _ = writeln!(out, "Matched Subnet:    {}", record.target);
            }
            let _ = writeln!(out, "Tier Level:        {}", record.tier_level);
            let exp = match record.expires_at_secs {
                Some(s) => format!(
                    "expires at unix {} ({}s duration)",
                    s,
                    s.saturating_sub(record.banned_at_secs)
                ),
                None => "permanent".to_string(),
            };
            let _ = writeln!(out, "Expiry:            {}", exp);
            let _ = writeln!(out, "Reason:            {}", record.reason);
            let _ = writeln!(out, "Banned At:         unix {}", record.banned_at_secs);
        }
        None => {
            let _ = writeln!(out, "Status:            CLEAN (Not banned)");
        }
    }

    if let Some(ip) = maybe_ip {
        let is_internal = crate::is_loopback_or_private(ip);
        let whitelisted = is_internal || store.is_whitelisted(ip)?;
        let wl_str = if is_internal {
            "YES [Loopback / Private Network]"
        } else if whitelisted {
            "YES"
        } else {
            "NO"
        };
        let _ = writeln!(out, "Whitelisted:       {}", wl_str);

        if let Some(offense) = store.get_offense(ip)? {
            let _ = writeln!(out, "\nOffense History:");
            let _ = writeln!(out, "  Recorded Count:  {}", offense.count);
            let _ = writeln!(out, "  First Seen:      unix {}", offense.first_seen_secs);
            let _ = writeln!(out, "  Last Seen:       unix {}", offense.last_seen_secs);
        } else {
            let _ = writeln!(out, "Offenses in Window: 0");
        }
    }

    Ok(())
}

pub fn format_ban_list<W: Write>(
    out: &mut W,
    store: &RedbStore,
    all: bool,
    plain: bool,
    filter: Option<String>,
) -> Result<(), SanaluError> {
    let mut bans = store.list_active_bans().unwrap_or_default();
    if let Some(f) = filter {
        let f_lower = f.to_lowercase();
        bans.retain(|b| {
            b.target.to_lowercase().contains(&f_lower) || b.reason.to_lowercase().contains(&f_lower)
        });
    }

    if plain {
        for b in &bans {
            let _ = writeln!(out, "{}", b.target);
        }
        return Ok(());
    }

    let total = bans.len();
    let display_limit = if all { total } else { 50.min(total) };
    let _ = writeln!(out, "=== Active Bans ({total} total) ===");
    for b in bans.iter().take(display_limit) {
        let exp = match b.expires_at_secs {
            Some(s) => format!("expires in {}s", s),
            None => "permanent".to_string(),
        };
        let _ = writeln!(
            out,
            "{:<32} tier {:<2} {:<20} reason: {}",
            b.target, b.tier_level, exp, b.reason
        );
    }
    if !all && total > display_limit {
        let _ = writeln!(
            out,
            "\nShowing {} of {} active bans. Use '--all' to view all, or '--plain' for machine output.",
            display_limit, total
        );
    }
    Ok(())
}

pub fn execute_ban<W: Write>(
    out: &mut W,
    store: &RedbStore,
    firewall: &NftablesBackend,
    target: &str,
    reason: Option<String>,
) -> Result<(), SanaluError> {
    if let Ok(ip) = target.parse::<IpAddr>() {
        if crate::is_loopback_or_private(ip) {
            let _ = writeln!(out, "Cannot ban loopback or private network IP: {}", target);
            return Ok(());
        }
    }
    let reason_str = reason.unwrap_or_else(|| "manual_cli_ban".into());
    let now_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let record = StoredBanRecord {
        target: target.to_string(),
        ip: target.parse::<IpAddr>().ok(),
        tier_level: 0,
        banned_at_secs: now_secs,
        expires_at_secs: None,
        reason: reason_str,
    };
    store.save_ban(&record)?;
    let _ = firewall.ban_target(target, None);
    let _ = writeln!(out, "Banned {} successfully.", target);
    Ok(())
}

pub fn execute_unban<W: Write>(
    out: &mut W,
    store: &RedbStore,
    firewall: &NftablesBackend,
    target: &str,
) -> Result<(), SanaluError> {
    store.remove_ban(target)?;
    let _ = firewall.unban_target(target);
    let _ = writeln!(out, "Unbanned {} successfully.", target);
    Ok(())
}

pub fn execute_whitelist<W: Write>(
    out: &mut W,
    store: &RedbStore,
    action: WhitelistCommands,
) -> Result<(), SanaluError> {
    match action {
        WhitelistCommands::Add { entry } => {
            store.add_whitelist(&entry)?;
            let _ = writeln!(out, "Added {} to whitelist.", entry);
        }
        WhitelistCommands::Remove { entry } => {
            store.remove_whitelist(&entry)?;
            let _ = writeln!(out, "Removed {} from whitelist.", entry);
        }
        WhitelistCommands::List => {
            let list = store.list_whitelist()?;
            let _ = writeln!(out, "Whitelisted entries: {:?}", list);
        }
    }
    Ok(())
}

pub fn execute_category<W: Write>(
    out: &mut W,
    store: &RedbStore,
    action: CategoryCommands,
) -> Result<(), SanaluError> {
    match action {
        CategoryCommands::Block { name } => {
            store.set_category_blocked(&name, true)?;
            let _ = writeln!(out, "Category '{}' is now blocked.", name);
        }
        CategoryCommands::Unblock { name } => {
            store.set_category_blocked(&name, false)?;
            let _ = writeln!(out, "Category '{}' is now unblocked.", name);
        }
        CategoryCommands::List => {
            let list = store.list_blocked_categories()?;
            let _ = writeln!(out, "Blocked categories: {:?}", list);
        }
    }
    Ok(())
}

pub fn execute_asn<W: Write>(
    out: &mut W,
    store: &RedbStore,
    action: AsnCommands,
) -> Result<(), SanaluError> {
    match action {
        AsnCommands::Block { asn } => {
            store.set_asn_blocked(asn, true)?;
            let _ = writeln!(out, "ASN {} is now blocked.", asn);
        }
        AsnCommands::Unblock { asn } => {
            store.set_asn_blocked(asn, false)?;
            let _ = writeln!(out, "ASN {} is now unblocked.", asn);
        }
        AsnCommands::List => {
            let list = store.list_blocked_asns()?;
            let _ = writeln!(out, "Blocked ASNs: {:?}", list);
        }
    }
    Ok(())
}

pub fn execute_region<W: Write>(
    out: &mut W,
    store: &RedbStore,
    action: RegionCommands,
) -> Result<(), SanaluError> {
    match action {
        RegionCommands::Allow { code } => {
            store.set_region_allowed(&code, true)?;
            let _ = writeln!(out, "Region '{}' is now allowed.", code);
        }
        RegionCommands::Disallow { code } => {
            store.set_region_allowed(&code, false)?;
            let _ = writeln!(out, "Region '{}' is now disallowed.", code);
        }
        RegionCommands::List => {
            let list = store.list_allowed_regions()?;
            let _ = writeln!(out, "Allowed regions: {:?}", list);
        }
    }
    Ok(())
}

pub async fn execute_cloudflare<W: Write>(
    out: &mut W,
    store: &RedbStore,
    config: &AppConfig,
    action: CloudflareCommands,
) -> Result<(), SanaluError> {
    match action {
        CloudflareCommands::Status => {
            let _ = writeln!(out, "=== Cloudflare WAF Status ===");
            let _ = writeln!(out, "Sync Enabled:      {}", config.cloudflare.enabled);
            let zone = if config.cloudflare.zone_id.is_empty() {
                "Not configured"
            } else {
                &config.cloudflare.zone_id
            };
            let ruleset = config
                .cloudflare
                .ruleset_id
                .as_deref()
                .unwrap_or("Auto-discover");
            let rule = config
                .cloudflare
                .rule_id
                .as_deref()
                .unwrap_or("Auto-discover");
            let _ = writeln!(out, "Zone ID:           {}", zone);
            let _ = writeln!(out, "Ruleset ID:        {}", ruleset);
            let _ = writeln!(out, "Rule ID:           {}", rule);

            let expr = store.get_cloudflare_state()?.unwrap_or_default();
            let char_count = expr.len();
            let max_budget = config.cloudflare.max_rule_chars;
            let pct = if max_budget > 0 {
                (char_count as f64 / max_budget as f64) * 100.0
            } else {
                0.0
            };
            let _ = writeln!(
                out,
                "Rule Budget:       {}/{} characters ({:.1}% used)",
                char_count, max_budget, pct
            );

            let active_bans = store.list_active_bans()?.len();
            let _ = writeln!(out, "Active Bans:       {} managed locally", active_bans);
            if !expr.is_empty() {
                let preview = if expr.len() > 120 {
                    format!("{}...", &expr[..120])
                } else {
                    expr
                };
                let _ = writeln!(out, "Active Expression: {}", preview);
            }
        }
        CloudflareCommands::List => {
            let _ = writeln!(out, "=== Cloudflare Active WAF Expression ===");
            if let Some(expr) = store.get_cloudflare_state()? {
                let _ = writeln!(out, "{}", expr);
            } else {
                let _ = writeln!(out, "No active expression found in database.");
            }
        }
        CloudflareCommands::Sync => {
            if !config.cloudflare.enabled {
                let _ = writeln!(out, "Cloudflare sync is disabled in configuration.");
                return Ok(());
            }
            let _ = writeln!(out, "Triggering Cloudflare WAF synchronization...");
            let budget = CloudflareRuleBudget::new(
                config.cloudflare.max_rule_chars,
                config.asn_rules.blocked_asns.clone(),
                config.asn_rules.restricted_asns.clone(),
                config.asn_rules.allowed_regions.clone(),
            );
            let client = CloudflareClient::new(config.cloudflare.clone(), false)?;
            let bans = store.list_active_bans()?;
            let mut v4_ips = Vec::new();
            for r in bans {
                let maybe_ip = r.ip.or_else(|| r.target.parse().ok());
                if let Some(IpAddr::V4(v4)) = maybe_ip {
                    v4_ips.push(v4);
                }
            }
            v4_ips.reverse();
            let (expr, _) = budget.render_expression(&v4_ips);
            client.update_waf_rule(&expr).await?;
            store.set_cloudflare_state(&expr)?;
            let _ = writeln!(
                out,
                "Cloudflare WAF successfully updated ({} characters).",
                expr.len()
            );
        }
    }
    Ok(())
}
