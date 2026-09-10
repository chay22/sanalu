use crate::config::AppConfig;
use crate::engine::policy::{
    get_effective_allowed_regions, get_effective_blocked_asns, get_effective_blocked_categories,
};
use crate::error::SanaluError;
use crate::intelligence::{BotCategory, ThreatPipeline};
use crate::storage::RedbStore;
use std::collections::HashSet;
use std::net::IpAddr;

pub fn build_pipeline_from_config(
    config: &AppConfig,
    store: &RedbStore,
) -> Result<ThreatPipeline, SanaluError> {
    let mut whitelisted_ips = HashSet::new();
    for entry in &config.general.whitelist {
        if let Ok(ip) = entry.parse::<IpAddr>() {
            whitelisted_ips.insert(ip);
        }
    }
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

    let blocked_asns: HashSet<u32> = get_effective_blocked_asns(config, store)
        .into_iter()
        .collect();

    let mut restricted_asns = HashSet::new();
    for &asn in &config.asn_rules.restricted_asns {
        restricted_asns.insert(asn);
    }

    let allowed_regions: HashSet<String> = get_effective_allowed_regions(config, store)
        .into_iter()
        .collect();

    let blocked_categories: HashSet<BotCategory> = get_effective_blocked_categories(config, store)
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
        &config.nginx.allowed_endpoints,
    )
}
