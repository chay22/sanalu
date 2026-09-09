use sanalu::storage::{RedbStore, StoredBanRecord, ip_to_key, key_to_ip};
use std::net::IpAddr;
use std::time::SystemTime;

#[test]
fn test_ip_key_roundtrip() {
    let v4: IpAddr = "192.168.1.1".parse().unwrap();
    assert_eq!(key_to_ip(ip_to_key(v4)), v4);

    let v6: IpAddr = "2001:db8::1".parse().unwrap();
    assert_eq!(key_to_ip(ip_to_key(v6)), v6);
}

#[test]
fn test_redb_ban_lifecycle() {
    let temp_dir = tempfile::tempdir().unwrap();
    let db_path = temp_dir.path().join("sanalu.redb");

    let store = RedbStore::open(&db_path).unwrap();
    let ip: IpAddr = "198.51.100.22".parse().unwrap();
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let record = StoredBanRecord {
        target: ip.to_string(),
        ip: Some(ip),
        tier_level: 0,
        banned_at_secs: now,
        expires_at_secs: Some(now + 3600),
        reason: "ssh_brute_force".into(),
    };

    store.save_ban(&record).unwrap();
    let retrieved = store
        .get_ban(&ip.to_string())
        .unwrap()
        .expect("must find saved ban");
    assert_eq!(retrieved.target, ip.to_string());
    assert_eq!(retrieved.reason, "ssh_brute_force");

    let active = store.list_active_bans().unwrap();
    assert_eq!(active.len(), 1);

    assert!(store.remove_ban(&ip.to_string()).unwrap());
    assert!(store.get_ban(&ip.to_string()).unwrap().is_none());
    assert!(store.list_active_bans().unwrap().is_empty());
}

#[test]
fn test_redb_cidr_ban_and_check() {
    let temp_dir = tempfile::tempdir().unwrap();
    let db_path = temp_dir.path().join("cidr_bans.redb");

    let store = RedbStore::open(&db_path).unwrap();
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let cidr_record = StoredBanRecord {
        target: "192.0.2.0/24".into(),
        ip: None,
        tier_level: 1,
        banned_at_secs: now,
        expires_at_secs: Some(now + 7200),
        reason: "subnet_abuse".into(),
    };

    store.save_ban(&cidr_record).unwrap();

    let direct_hit = store
        .get_ban("192.0.2.0/24")
        .unwrap()
        .expect("must find cidr ban");
    assert_eq!(direct_hit.target, "192.0.2.0/24");

    let checked = store
        .check_ban_status("192.0.2.45")
        .unwrap()
        .expect("must match subnet");
    assert_eq!(checked.target, "192.0.2.0/24");

    assert!(store.check_ban_status("192.0.3.1").unwrap().is_none());

    let offense_ip: IpAddr = "192.0.2.45".parse().unwrap();
    store.record_offense(offense_ip, 600).unwrap();
    let offense = store
        .get_offense(offense_ip)
        .unwrap()
        .expect("must find offense");
    assert_eq!(offense.count, 1);

    assert!(store.remove_ban("192.0.2.0/24").unwrap());
    assert!(store.check_ban_status("192.0.2.45").unwrap().is_none());
}

#[test]
fn test_redb_offense_counter_and_window() {
    let temp_dir = tempfile::tempdir().unwrap();
    let db_path = temp_dir.path().join("offenses.redb");

    let store = RedbStore::open(&db_path).unwrap();
    let ip: IpAddr = "203.0.113.88".parse().unwrap();

    let count1 = store.record_offense(ip, 600).unwrap();
    assert_eq!(count1, 1);

    let count2 = store.record_offense(ip, 600).unwrap();
    assert_eq!(count2, 2);

    let count3 = store.record_offense(ip, 600).unwrap();
    assert_eq!(count3, 3);
}

#[test]
fn test_redb_whitelist_matching() {
    let temp_dir = tempfile::tempdir().unwrap();
    let db_path = temp_dir.path().join("whitelist.redb");

    let store = RedbStore::open(&db_path).unwrap();
    store.add_whitelist("127.0.0.1").unwrap();
    store.add_whitelist("10.0.0.0/8").unwrap();

    assert!(store.is_whitelisted("127.0.0.1".parse().unwrap()).unwrap());
    assert!(store.is_whitelisted("10.2.3.4".parse().unwrap()).unwrap());
    assert!(
        !store
            .is_whitelisted("192.168.1.1".parse().unwrap())
            .unwrap()
    );

    assert!(store.remove_whitelist("127.0.0.1").unwrap());
    assert!(!store.is_whitelisted("127.0.0.1".parse().unwrap()).unwrap());
}

#[test]
fn test_redb_runtime_policies() {
    let temp_dir = tempfile::tempdir().unwrap();
    let db_path = temp_dir.path().join("policies.redb");

    let store = RedbStore::open(&db_path).unwrap();
    store.set_category_blocked("generic_tools", true).unwrap();
    assert!(store.is_category_blocked("generic_tools", false).unwrap());

    store.set_asn_blocked(400529, true).unwrap();
    assert!(store.is_asn_blocked(400529).unwrap());
    assert!(store.list_blocked_asns().unwrap().contains(&400529));

    store.set_region_allowed("JP", true).unwrap();
    assert!(store.is_region_allowed("JP").unwrap());
    assert!(
        store
            .list_allowed_regions()
            .unwrap()
            .contains(&"JP".to_string())
    );
}
