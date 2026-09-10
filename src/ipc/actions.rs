use super::protocol::{AsnCommands, CategoryCommands, RegionCommands, WhitelistCommands};
use crate::error::SanaluError;
use crate::firewall::{FirewallBackend, NftablesBackend};
use crate::storage::{RedbStore, StoredBanRecord};
use std::io::Write;
use std::net::IpAddr;
use std::time::{SystemTime, UNIX_EPOCH};

pub use super::cloudflare::execute_cloudflare;

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
