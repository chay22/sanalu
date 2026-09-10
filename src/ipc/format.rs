use crate::config::AppConfig;
use crate::error::SanaluError;
use crate::storage::RedbStore;
use std::io::Write;
use std::net::IpAddr;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

pub fn format_datetime(unix_secs: u64) -> String {
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sept", "Oct", "Nov", "Dec",
    ];
    let seconds_in_day = 86400;
    let days = (unix_secs / seconds_in_day) as i64;
    let rem_secs = (unix_secs % seconds_in_day) as u32;

    let hour = rem_secs / 3600;
    let minute = (rem_secs % 3600) / 60;
    let second = rem_secs % 60;

    let z = days + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = (z - era * 146097) as u32;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = (yoe as i64) + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if m <= 2 { y + 1 } else { y };

    let month_str = MONTHS.get((m.saturating_sub(1)) as usize).unwrap_or(&"Jan");
    format!(
        "{d} {month_str} {year} {:02}:{:02}:{:02} UTC",
        hour, minute, second
    )
}

pub fn format_duration(seconds: u64) -> String {
    if seconds == 0 {
        return "0s".to_string();
    }
    let days = seconds / 86400;
    let hours = (seconds % 86400) / 3600;
    let minutes = (seconds % 3600) / 60;
    let secs = seconds % 60;

    let mut parts = Vec::new();
    if days > 0 {
        parts.push(format!("{}d", days));
    }
    if hours > 0 {
        parts.push(format!("{}h", hours));
    }
    if minutes > 0 {
        parts.push(format!("{}m", minutes));
    }
    if secs > 0 || parts.is_empty() {
        parts.push(format!("{}s", secs));
    }
    parts.join(" ")
}

pub fn format_status<W: Write>(
    out: &mut W,
    store: &RedbStore,
    db_path: &Path,
    config: Option<&AppConfig>,
) -> Result<(), SanaluError> {
    let _ = writeln!(out, "=== Sanalu Status ===");
    let _ = writeln!(out, "Database: {:?}", db_path);

    let bans = store.list_active_bans().unwrap_or_default();
    let _ = writeln!(out, "\nActive Bans: {}", bans.len());
    let now_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    for b in bans.iter().take(15) {
        let exp = match b.expires_at_secs {
            Some(s) => {
                let remaining = s.saturating_sub(now_secs);
                format!(
                    "expires {} ({} left)",
                    format_datetime(s),
                    format_duration(remaining)
                )
            }
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

    let db_cats = store.list_blocked_categories().unwrap_or_default();
    if let Some(cfg) = config {
        let effective = crate::engine::get_effective_blocked_categories(cfg, store);
        let _ = writeln!(
            out,
            "\nBlocked Categories: {} in config, {} dynamic in DB ({} effective: {:?})",
            cfg.bots.blocked_categories.len(),
            db_cats.len(),
            effective.len(),
            effective
        );
    } else {
        let _ = writeln!(out, "\nBlocked Categories in DB: {:?}", db_cats);
    }

    let db_asns = store.list_blocked_asns().unwrap_or_default();
    if let Some(cfg) = config {
        let effective = crate::engine::get_effective_blocked_asns(cfg, store);
        let _ = writeln!(
            out,
            "Blocked ASNs: {} in config, {} dynamic in DB ({} effective)",
            cfg.asn_rules.blocked_asns.len(),
            db_asns.len(),
            effective.len()
        );
    } else {
        let _ = writeln!(out, "Blocked ASNs in DB: {:?}", db_asns);
    }

    let db_regions = store.list_allowed_regions().unwrap_or_default();
    if let Some(cfg) = config {
        let effective = crate::engine::get_effective_allowed_regions(cfg, store);
        let _ = writeln!(
            out,
            "Allowed Regions: {} in config, {} dynamic in DB ({} effective: {:?})",
            cfg.asn_rules.allowed_regions.len(),
            db_regions.len(),
            effective.len(),
            effective
        );
    } else {
        let _ = writeln!(out, "Allowed Regions in DB: {:?}", db_regions);
    }

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
                Some(s) => {
                    let remaining = s.saturating_sub(record.banned_at_secs);
                    format!(
                        "{} (expires {})",
                        format_duration(remaining),
                        format_datetime(s)
                    )
                }
                None => "permanent".to_string(),
            };
            let _ = writeln!(out, "Expiry:            {}", exp);
            let _ = writeln!(out, "Reason:            {}", record.reason);
            let _ = writeln!(
                out,
                "Banned At:         {}",
                format_datetime(record.banned_at_secs)
            );
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
            let _ = writeln!(
                out,
                "  First Seen:      {}",
                format_datetime(offense.first_seen_secs)
            );
            let _ = writeln!(
                out,
                "  Last Seen:       {}",
                format_datetime(offense.last_seen_secs)
            );
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
    let now_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    for b in bans.iter().take(display_limit) {
        let exp = match b.expires_at_secs {
            Some(s) => {
                let remaining = s.saturating_sub(now_secs);
                format!(
                    "expires {} ({} left)",
                    format_datetime(s),
                    format_duration(remaining)
                )
            }
            None => "permanent".to_string(),
        };
        let _ = writeln!(
            out,
            "{:<32} tier {:<2} {:<38} reason: {}",
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
