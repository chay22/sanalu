use crate::config::AppConfig;
use crate::storage::RedbStore;
use std::collections::BTreeSet;

pub fn get_effective_blocked_asns(config: &AppConfig, store: &RedbStore) -> Vec<u32> {
    let mut asns = BTreeSet::new();
    for &asn in &config.asn_rules.blocked_asns {
        asns.insert(asn);
    }
    if let Ok(db_asns) = store.list_blocked_asns() {
        for asn in db_asns {
            asns.insert(asn);
        }
    }
    asns.into_iter().collect()
}

pub fn get_effective_blocked_categories(config: &AppConfig, store: &RedbStore) -> Vec<String> {
    let mut cats = BTreeSet::new();
    for cat in &config.bots.blocked_categories {
        cats.insert(cat.clone());
    }
    if let Ok(db_cats) = store.list_blocked_categories() {
        for cat in db_cats {
            cats.insert(cat);
        }
    }
    cats.into_iter().collect()
}

pub fn get_effective_allowed_regions(config: &AppConfig, store: &RedbStore) -> Vec<String> {
    let mut regions = BTreeSet::new();
    for r in &config.asn_rules.allowed_regions {
        regions.insert(r.clone());
    }
    if let Ok(db_regions) = store.list_allowed_regions() {
        for r in db_regions {
            regions.insert(r);
        }
    }
    regions.into_iter().collect()
}
