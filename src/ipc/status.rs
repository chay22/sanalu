use super::datetime::{format_datetime, format_duration};
use crate::config::AppConfig;
use crate::error::SanaluError;
use crate::storage::RedbStore;
use std::io::Write;
use std::net::IpAddr;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

pub fn format_status<W: Write>(
    out: &mut W,
    store: &RedbStore,
    db_path: &Path,
    _config: Option<&AppConfig>,
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
    let _ = writeln!(
        out,
        "\nBlocked Categories ({}): {:?}",
        db_cats.len(),
        db_cats
    );

    let db_asns = store.list_blocked_asns().unwrap_or_default();
    let _ = writeln!(out, "Blocked ASNs ({}): {:?}", db_asns.len(), db_asns);

    let db_rasns = store.list_restricted_asns().unwrap_or_default();
    if !db_rasns.is_empty() {
        let _ = writeln!(out, "Restricted ASNs ({}): {:?}", db_rasns.len(), db_rasns);
    }

    let db_regions = store.list_allowed_regions().unwrap_or_default();
    let _ = writeln!(
        out,
        "Allowed Regions ({}): {:?}",
        db_regions.len(),
        db_regions
    );

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
