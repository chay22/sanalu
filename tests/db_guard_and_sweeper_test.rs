use sanalu::config::AppConfig;
use sanalu::ipc::status::format_status;
use sanalu::storage::{RedbStore, StoredBanRecord};

#[test]
fn test_cleanup_expired_bans_purges_only_expired() {
    let temp_dir = tempfile::tempdir().unwrap();
    let db_path = temp_dir.path().join("test_cleanup.redb");
    let store = RedbStore::open(&db_path).unwrap();

    let expired_ban_1 = StoredBanRecord {
        target: "198.51.100.1".into(),
        ip: Some("198.51.100.1".parse().unwrap()),
        tier_level: 1,
        banned_at_secs: 100,
        expires_at_secs: Some(200),
        reason: "expired test 1".into(),
    };
    let expired_ban_2 = StoredBanRecord {
        target: "198.51.100.2".into(),
        ip: Some("198.51.100.2".parse().unwrap()),
        tier_level: 2,
        banned_at_secs: 100,
        expires_at_secs: Some(250),
        reason: "expired test 2".into(),
    };
    let active_ban = StoredBanRecord {
        target: "198.51.100.3".into(),
        ip: Some("198.51.100.3".parse().unwrap()),
        tier_level: 1,
        banned_at_secs: 100,
        expires_at_secs: Some(500),
        reason: "active test".into(),
    };
    let permanent_ban = StoredBanRecord {
        target: "198.51.100.4".into(),
        ip: Some("198.51.100.4".parse().unwrap()),
        tier_level: 3,
        banned_at_secs: 100,
        expires_at_secs: None,
        reason: "permanent test".into(),
    };

    store.save_ban(&expired_ban_1).unwrap();
    store.save_ban(&expired_ban_2).unwrap();
    store.save_ban(&active_ban).unwrap();
    store.save_ban(&permanent_ban).unwrap();

    let removed = store.cleanup_expired_bans(300).unwrap();
    assert_eq!(removed, 2);

    assert!(store.get_ban("198.51.100.1").unwrap().is_none());
    assert!(store.get_ban("198.51.100.2").unwrap().is_none());
    assert!(store.get_ban("198.51.100.3").unwrap().is_some());
    assert!(store.get_ban("198.51.100.4").unwrap().is_some());

    let removed_again = store.cleanup_expired_bans(300).unwrap();
    assert_eq!(removed_again, 0);
}

#[test]
fn test_status_output_asn_geo_database_active_and_missing() {
    let temp_dir = tempfile::tempdir().unwrap();
    let db_path = temp_dir.path().join("test_status.redb");
    let store = RedbStore::open(&db_path).unwrap();

    let missing_geo_path = temp_dir.path().join("missing_ip_asn_geo.bin");
    let mut config = AppConfig::default();
    config.general.db_path = db_path.clone();
    config.general.ip_db_path = missing_geo_path.clone();

    let mut buf_missing = Vec::new();
    format_status(&mut buf_missing, &store, &db_path, Some(&config)).unwrap();
    let out_missing = String::from_utf8(buf_missing).unwrap();
    assert!(out_missing.contains("ASN/Geo Database: MISSING"));
    assert!(out_missing.contains("Geo-defense inactive. Run 'sanalu update-db' to activate."));
    assert!(out_missing.contains(&format!("{:?}", missing_geo_path)));

    let active_geo_path = temp_dir.path().join("active_ip_asn_geo.bin");
    std::fs::write(&active_geo_path, b"dummy geo db").unwrap();
    config.general.ip_db_path = active_geo_path.clone();

    let mut buf_active = Vec::new();
    format_status(&mut buf_active, &store, &db_path, Some(&config)).unwrap();
    let out_active = String::from_utf8(buf_active).unwrap();
    assert!(out_active.contains("ASN/Geo Database: Active"));
    assert!(out_active.contains(&format!("{:?}", active_geo_path)));
}
