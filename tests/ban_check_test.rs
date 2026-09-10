use sanalu::cli::generate_completions;
use sanalu::storage::{RedbStore, StoredBanRecord, parse_cidr};
use std::net::IpAddr;
use std::time::SystemTime;

#[test]
fn test_ban_cidr_containment_and_matching() {
    let cidr = parse_cidr("198.51.100.0/24").expect("valid cidr");
    let inside_ip: IpAddr = "198.51.100.42".parse().unwrap();
    let outside_ip: IpAddr = "198.51.101.42".parse().unwrap();

    assert!(cidr.contains(inside_ip));
    assert!(!cidr.contains(outside_ip));

    let v6_cidr = parse_cidr("2001:db8::/32").expect("valid ipv6 cidr");
    let inside_v6: IpAddr = "2001:db8:85a3::8a2e:370:7334".parse().unwrap();
    let outside_v6: IpAddr = "2001:db9::1".parse().unwrap();

    assert!(v6_cidr.contains(inside_v6));
    assert!(!v6_cidr.contains(outside_v6));
}

#[test]
fn test_check_ban_diagnostics_flow() {
    let temp_dir = tempfile::tempdir().unwrap();
    let db_path = temp_dir.path().join("diag.redb");
    let store = RedbStore::open(&db_path).unwrap();

    let now_secs = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let direct_rec = StoredBanRecord {
        target: "203.0.113.10".into(),
        ip: Some("203.0.113.10".parse().unwrap()),
        tier_level: 2,
        banned_at_secs: now_secs,
        expires_at_secs: Some(now_secs + 3600),
        reason: "ssh_scanner".into(),
    };
    store.save_ban(&direct_rec).unwrap();

    let subnet_rec = StoredBanRecord {
        target: "192.0.2.0/24".into(),
        ip: None,
        tier_level: 1,
        banned_at_secs: now_secs,
        expires_at_secs: None,
        reason: "abusive_asn_range".into(),
    };
    store.save_ban(&subnet_rec).unwrap();

    let res_direct = store.check_ban_status("203.0.113.10").unwrap();
    assert!(res_direct.is_some());
    let r1 = res_direct.unwrap();
    assert_eq!(r1.target, "203.0.113.10");
    assert_eq!(r1.reason, "ssh_scanner");

    let res_subnet = store.check_ban_status("192.0.2.88").unwrap();
    assert!(res_subnet.is_some());
    let r2 = res_subnet.unwrap();
    assert_eq!(r2.target, "192.0.2.0/24");
    assert_eq!(r2.reason, "abusive_asn_range");

    let res_clean = store.check_ban_status("198.51.100.99").unwrap();
    assert!(res_clean.is_none());

    let tracked_ip: IpAddr = "203.0.113.10".parse().unwrap();
    store.record_offense(tracked_ip, 600).unwrap();
    store.record_offense(tracked_ip, 600).unwrap();

    let offense_info = store
        .get_offense(tracked_ip)
        .unwrap()
        .expect("has offenses");
    assert_eq!(offense_info.count, 2);

    store.add_whitelist("198.51.100.99").unwrap();
    assert!(
        store
            .is_whitelisted("198.51.100.99".parse().unwrap())
            .unwrap()
    );
    assert!(
        !store
            .is_whitelisted("203.0.113.10".parse().unwrap())
            .unwrap()
    );
}

#[test]
fn test_ban_list_filter_and_plain_output() {
    let temp_dir = tempfile::tempdir().unwrap();
    let db_path = temp_dir.path().join("list.redb");
    let store = RedbStore::open(&db_path).unwrap();

    let now_secs = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let r1 = StoredBanRecord {
        target: "1.1.1.1".into(),
        ip: Some("1.1.1.1".parse().unwrap()),
        tier_level: 0,
        banned_at_secs: now_secs,
        expires_at_secs: Some(now_secs + 3600),
        reason: "nginx_probe".into(),
    };
    let r2 = StoredBanRecord {
        target: "2.2.2.0/24".into(),
        ip: None,
        tier_level: 1,
        banned_at_secs: now_secs,
        expires_at_secs: None,
        reason: "ssh_brute".into(),
    };
    let r3 = StoredBanRecord {
        target: "3.3.3.3".into(),
        ip: Some("3.3.3.3".parse().unwrap()),
        tier_level: 0,
        banned_at_secs: now_secs,
        expires_at_secs: Some(now_secs + 1800),
        reason: "nginx_bad_ua".into(),
    };

    store.save_ban(&r1).unwrap();
    store.save_ban(&r2).unwrap();
    store.save_ban(&r3).unwrap();

    let all_bans = store.list_active_bans().unwrap();
    assert_eq!(all_bans.len(), 3);

    let filtered_ssh: Vec<_> = all_bans
        .iter()
        .filter(|b| b.reason.contains("ssh"))
        .collect();
    assert_eq!(filtered_ssh.len(), 1);
    assert_eq!(filtered_ssh[0].target, "2.2.2.0/24");

    let plain_targets: Vec<String> = all_bans.iter().map(|b| b.target.clone()).collect();
    assert!(plain_targets.contains(&"1.1.1.1".to_string()));
    assert!(plain_targets.contains(&"2.2.2.0/24".to_string()));
    assert!(plain_targets.contains(&"3.3.3.3".to_string()));
}

#[test]
fn test_shell_completions_generation() {
    let mut bash_buf = Vec::new();
    generate_completions(clap_complete::Shell::Bash, &mut bash_buf);
    let bash_str = String::from_utf8_lossy(&bash_buf);
    assert!(bash_str.contains("sanalu"));
    assert!(bash_str.contains("ban"));
    assert!(bash_str.contains("unban"));
    assert!(bash_str.contains("check"));
    assert!(bash_str.contains("cloudflare"));

    let mut zsh_buf = Vec::new();
    generate_completions(clap_complete::Shell::Zsh, &mut zsh_buf);
    let zsh_str = String::from_utf8_lossy(&zsh_buf);
    assert!(zsh_str.contains("sanalu"));

    let mut fish_buf = Vec::new();
    generate_completions(clap_complete::Shell::Fish, &mut fish_buf);
    let fish_str = String::from_utf8_lossy(&fish_buf);
    assert!(fish_str.contains("sanalu"));
}
