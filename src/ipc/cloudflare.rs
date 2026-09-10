use super::protocol::CloudflareCommands;
use crate::cloudflare::{CloudflareClient, CloudflareRuleBudget};
use crate::config::AppConfig;
use crate::error::SanaluError;
use crate::storage::RedbStore;
use std::io::Write;
use std::net::IpAddr;

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
            let effective_asns = crate::engine::get_effective_blocked_asns(config, store);
            let budget = CloudflareRuleBudget::new(
                config.cloudflare.max_rule_chars,
                effective_asns,
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
