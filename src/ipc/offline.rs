use super::actions::{
    execute_asn, execute_ban, execute_category, execute_cloudflare, execute_region, execute_unban,
    execute_whitelist,
};
use super::format::{format_ban_list, format_check, format_status};
use super::protocol::{
    AsnCommands, CategoryCommands, CloudflareCommands, RegionCommands, WhitelistCommands,
};
use crate::config::AppConfig;
use crate::error::SanaluError;
use crate::firewall::NftablesBackend;
use crate::storage::RedbStore;
use std::path::Path;

pub fn execute_offline_ban(
    db_path: &Path,
    target: &str,
    reason: Option<String>,
    dry_run: bool,
) -> Result<String, SanaluError> {
    let store = RedbStore::open(db_path)?;
    let fw = NftablesBackend::auto_detect(dry_run);
    let mut buf = Vec::new();
    execute_ban(&mut buf, &store, &fw, target, reason)?;
    String::from_utf8(buf).map_err(|e| SanaluError::Storage(e.to_string()))
}

pub fn execute_offline_unban(
    db_path: &Path,
    target: &str,
    dry_run: bool,
) -> Result<String, SanaluError> {
    let store = RedbStore::open(db_path)?;
    let fw = NftablesBackend::auto_detect(dry_run);
    let mut buf = Vec::new();
    execute_unban(&mut buf, &store, &fw, target)?;
    String::from_utf8(buf).map_err(|e| SanaluError::Storage(e.to_string()))
}

pub fn execute_offline_status(
    db_path: &Path,
    config: Option<&AppConfig>,
) -> Result<String, SanaluError> {
    let store = RedbStore::open(db_path)?;
    let mut buf = Vec::new();
    format_status(&mut buf, &store, db_path, config)?;
    String::from_utf8(buf).map_err(|e| SanaluError::Storage(e.to_string()))
}

pub fn execute_offline_check(db_path: &Path, target: &str) -> Result<String, SanaluError> {
    let store = RedbStore::open(db_path)?;
    let mut buf = Vec::new();
    format_check(&mut buf, &store, target)?;
    String::from_utf8(buf).map_err(|e| SanaluError::Storage(e.to_string()))
}

pub fn execute_offline_ban_list(
    db_path: &Path,
    all: bool,
    plain: bool,
    filter: Option<String>,
) -> Result<String, SanaluError> {
    let store = RedbStore::open(db_path)?;
    let mut buf = Vec::new();
    format_ban_list(&mut buf, &store, all, plain, filter)?;
    String::from_utf8(buf).map_err(|e| SanaluError::Storage(e.to_string()))
}

pub fn execute_offline_whitelist(
    db_path: &Path,
    action: WhitelistCommands,
) -> Result<String, SanaluError> {
    let store = RedbStore::open(db_path)?;
    let mut buf = Vec::new();
    execute_whitelist(&mut buf, &store, action)?;
    String::from_utf8(buf).map_err(|e| SanaluError::Storage(e.to_string()))
}

pub fn execute_offline_category(
    db_path: &Path,
    action: CategoryCommands,
) -> Result<String, SanaluError> {
    let store = RedbStore::open(db_path)?;
    let mut buf = Vec::new();
    execute_category(&mut buf, &store, action)?;
    String::from_utf8(buf).map_err(|e| SanaluError::Storage(e.to_string()))
}

pub fn execute_offline_asn(db_path: &Path, action: AsnCommands) -> Result<String, SanaluError> {
    let store = RedbStore::open(db_path)?;
    let mut buf = Vec::new();
    execute_asn(&mut buf, &store, action)?;
    String::from_utf8(buf).map_err(|e| SanaluError::Storage(e.to_string()))
}

pub fn execute_offline_region(
    db_path: &Path,
    action: RegionCommands,
) -> Result<String, SanaluError> {
    let store = RedbStore::open(db_path)?;
    let mut buf = Vec::new();
    execute_region(&mut buf, &store, action)?;
    String::from_utf8(buf).map_err(|e| SanaluError::Storage(e.to_string()))
}

pub async fn execute_offline_cloudflare(
    db_path: &Path,
    action: CloudflareCommands,
    config: &AppConfig,
) -> Result<String, SanaluError> {
    let store = RedbStore::open(db_path)?;
    let mut buf = Vec::new();
    execute_cloudflare(&mut buf, &store, config, action).await?;
    String::from_utf8(buf).map_err(|e| SanaluError::Storage(e.to_string()))
}
