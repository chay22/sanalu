#[test]
fn test_merged_asn_state() {
    let temp_dir = tempfile::tempdir().unwrap();
    let db_path = temp_dir.path().join("test.redb");
    let store = sanalu::storage::RedbStore::open(&db_path).unwrap();
    store.set_asn_blocked(99999, true).unwrap();

    let mut cfg = sanalu::config::AppConfig::default();
    cfg.asn_rules.blocked_asns = vec![11111, 22222];

    let effective = sanalu::daemon::get_effective_blocked_asns(&cfg, &store);
    assert_eq!(effective.len(), 3);
    assert!(effective.contains(&11111));
    assert!(effective.contains(&22222));
    assert!(effective.contains(&99999));
}

#[test]
fn test_merged_category_and_region_state() {
    let temp_dir = tempfile::tempdir().unwrap();
    let db_path = temp_dir.path().join("test_cat_reg.redb");
    let store = sanalu::storage::RedbStore::open(&db_path).unwrap();
    store.set_category_blocked("ai_crawler", true).unwrap();
    store.set_region_allowed("ID", true).unwrap();

    let mut cfg = sanalu::config::AppConfig::default();
    cfg.bots.blocked_categories = vec!["security_testing".into()];
    cfg.asn_rules.allowed_regions = vec!["SG".into(), "US".into()];

    let effective_cats = sanalu::daemon::get_effective_blocked_categories(&cfg, &store);
    assert_eq!(effective_cats.len(), 2);
    assert!(effective_cats.contains(&"ai_crawler".to_string()));
    assert!(effective_cats.contains(&"security_testing".to_string()));

    let effective_regions = sanalu::daemon::get_effective_allowed_regions(&cfg, &store);
    assert_eq!(effective_regions.len(), 3);
    assert!(effective_regions.contains(&"ID".to_string()));
    assert!(effective_regions.contains(&"SG".to_string()));
    assert!(effective_regions.contains(&"US".to_string()));
}

#[test]
fn test_format_datetime_and_duration() {
    let epoch_dt = sanalu::ipc::handlers::format_datetime(0);
    assert_eq!(epoch_dt, "1 Jan 1970 00:00:00 UTC");

    let test_dt = sanalu::ipc::handlers::format_datetime(1790001125);
    assert_eq!(test_dt, "21 Sept 2026 14:32:05 UTC");

    let dur_0 = sanalu::ipc::handlers::format_duration(0);
    assert_eq!(dur_0, "0s");

    let dur_3600 = sanalu::ipc::handlers::format_duration(3600);
    assert_eq!(dur_3600, "1h");

    let dur_composite = sanalu::ipc::handlers::format_duration(90061);
    assert_eq!(dur_composite, "1d 1h 1m 1s");
}
