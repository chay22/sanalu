use crate::config::AppConfig;
use crate::error::SanaluError;
use crate::intelligence::{BotCategory, ThreatPipeline};
use crate::storage::RedbStore;
use std::collections::HashSet;
use std::net::IpAddr;

pub fn build_pipeline_from_store(
    store: &RedbStore,
    allowed_endpoints: &[String],
) -> Result<ThreatPipeline, SanaluError> {
    let mut whitelisted_ips = HashSet::new();
    if let Ok(db_whitelist) = store.list_whitelist() {
        for entry in db_whitelist {
            if let Ok(ip) = entry.parse::<IpAddr>() {
                whitelisted_ips.insert(ip);
            }
        }
    }

    let mut banned_ips = HashSet::new();
    if let Ok(active_bans) = store.list_active_bans() {
        for b in active_bans {
            if let Some(ip) = b.ip {
                banned_ips.insert(ip);
            } else if let Ok(ip) = b.target.parse::<IpAddr>() {
                banned_ips.insert(ip);
            }
        }
    }

    let blocked_asns: HashSet<u32> = store
        .list_blocked_asns()
        .unwrap_or_default()
        .into_iter()
        .collect();
    let restricted_asns: HashSet<u32> = store
        .list_restricted_asns()
        .unwrap_or_default()
        .into_iter()
        .collect();
    let allowed_regions: HashSet<String> = store
        .list_allowed_regions()
        .unwrap_or_default()
        .into_iter()
        .collect();

    let blocked_categories: HashSet<BotCategory> = store
        .list_blocked_categories()
        .unwrap_or_default()
        .into_iter()
        .filter_map(|c| BotCategory::from_str_name(&c))
        .collect();

    ThreatPipeline::new(
        whitelisted_ips,
        banned_ips,
        blocked_asns,
        restricted_asns,
        allowed_regions,
        blocked_categories,
        allowed_endpoints,
    )
}

pub fn build_pipeline_from_config(
    config: &AppConfig,
    store: &RedbStore,
) -> Result<ThreatPipeline, SanaluError> {
    let _ = store.sync_from_config(config);
    build_pipeline_from_store(store, &config.nginx.allowed_endpoints)
}

