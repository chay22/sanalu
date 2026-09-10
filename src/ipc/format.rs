use crate::error::SanaluError;
use crate::storage::RedbStore;
use std::io::Write;
use std::time::{SystemTime, UNIX_EPOCH};

pub use super::datetime::{format_datetime, format_duration};
pub use super::status::{format_check, format_status};

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
