use sanalu::daemon::restore_active_bans;
use sanalu::firewall::NftablesBackend;
use sanalu::storage::{RedbStore, StoredBanRecord};
use std::time::{SystemTime, UNIX_EPOCH};

#[test]
fn test_restore_active_bans_only_injects_unexpired() {
    let temp_dir = tempfile::tempdir().unwrap();
    let db_path = temp_dir.path().join("restore_test.redb");
    let store = RedbStore::open(&db_path).unwrap();
    let firewall = NftablesBackend::auto_detect(true);

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let active_1 = StoredBanRecord {
        target: "198.51.100.10".into(),
        ip: Some("198.51.100.10".parse().unwrap()),
        tier_level: 1,
        banned_at_secs: now,
        expires_at_secs: Some(now + 3600),
        reason: "active probe".into(),
    };

    let active_permanent = StoredBanRecord {
        target: "2001:db8::1".into(),
        ip: Some("2001:db8::1".parse().unwrap()),
        tier_level: 3,
        banned_at_secs: now,
        expires_at_secs: None,
        reason: "permanent probe".into(),
    };

    let expired = StoredBanRecord {
        target: "198.51.100.30".into(),
        ip: Some("198.51.100.30".parse().unwrap()),
        tier_level: 1,
        banned_at_secs: now - 7200,
        expires_at_secs: Some(now - 3600),
        reason: "expired probe".into(),
    };

    store.save_ban(&active_1).unwrap();
    store.save_ban(&active_permanent).unwrap();
    store.save_ban(&expired).unwrap();

    let count = restore_active_bans(&store, &firewall).unwrap();
    assert_eq!(count, 2);
}

#[test]
fn test_restore_active_bans_empty_store() {
    let temp_dir = tempfile::tempdir().unwrap();
    let db_path = temp_dir.path().join("empty_restore_test.redb");
    let store = RedbStore::open(&db_path).unwrap();
    let firewall = NftablesBackend::auto_detect(true);

    let count = restore_active_bans(&store, &firewall).unwrap();
    assert_eq!(count, 0);
}
