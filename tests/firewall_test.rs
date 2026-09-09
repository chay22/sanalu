use sanalu::firewall::{FirewallBackend, MockFirewallBackend, NftablesBackend};
use std::net::IpAddr;

#[test]
fn test_nftables_render_init_ruleset() {
    let backend = NftablesBackend::auto_detect(true);
    let ruleset = backend.render_init_ruleset();

    assert!(ruleset.contains("add table inet sanalu"));
    assert!(
        ruleset.contains(
            "add set inet sanalu blacklist_v4 { type ipv4_addr; flags interval, timeout; }"
        )
    );
    assert!(
        ruleset.contains(
            "add set inet sanalu blacklist_v6 { type ipv6_addr; flags interval, timeout; }"
        )
    );
    assert!(ruleset.contains("priority -100"));
    assert!(ruleset.contains("add rule inet sanalu prerouting ip saddr @blacklist_v4 drop"));
    assert!(ruleset.contains("add rule inet sanalu prerouting ip6 saddr @blacklist_v6 drop"));
}

#[test]
fn test_nftables_dry_run_operations() {
    let backend = NftablesBackend::new("inet sanalu", "blacklist_v4", "blacklist_v6", true);
    let ip_v4: IpAddr = "192.0.2.1".parse().unwrap();
    let ip_v6: IpAddr = "2001:db8::1".parse().unwrap();

    assert!(backend.init_tables().is_ok());
    assert!(backend.ban_ip(ip_v4, Some(3600)).is_ok());
    assert!(backend.ban_ip(ip_v6, None).is_ok());
    assert!(backend.ban_target("192.0.2.0/24", Some(3600)).is_ok());
    assert!(
        backend
            .sync_asn_cidrs(&["1.0.0.0/24".to_string(), "8.8.8.0/24".to_string()])
            .is_ok()
    );
    assert!(backend.unban_target("192.0.2.0/24").is_ok());
    assert!(backend.unban_ip(ip_v4).is_ok());
    assert!(backend.list_banned().is_ok());
    assert!(backend.flush().is_ok());
}

#[test]
fn test_mock_firewall_backend() {
    let backend = MockFirewallBackend::new();
    let ip1: IpAddr = "198.51.100.1".parse().unwrap();
    let ip2: IpAddr = "198.51.100.2".parse().unwrap();

    assert!(backend.init_tables().is_ok());
    assert!(backend.ban_ip(ip1, Some(300)).is_ok());
    assert!(backend.ban_ip(ip2, None).is_ok());
    assert!(backend.ban_target("10.0.0.0/8", Some(300)).is_ok());

    let list = backend.list_banned().unwrap();
    assert_eq!(list.len(), 2);
    assert!(list.contains(&ip1));
    assert!(list.contains(&ip2));

    let target_list = backend.list_banned_targets().unwrap();
    assert_eq!(target_list.len(), 3);
    assert!(target_list.contains(&"10.0.0.0/8".to_string()));

    assert!(backend.unban_target("10.0.0.0/8").is_ok());
    let target_list_after = backend.list_banned_targets().unwrap();
    assert_eq!(target_list_after.len(), 2);
    assert!(!target_list_after.contains(&"10.0.0.0/8".to_string()));

    assert!(backend.unban_ip(ip1).is_ok());
    let list_after = backend.list_banned().unwrap();
    assert_eq!(list_after.len(), 1);
    assert!(!list_after.contains(&ip1));
    assert!(list_after.contains(&ip2));

    assert!(backend.flush().is_ok());
    assert!(backend.list_banned().unwrap().is_empty());
    assert!(backend.list_banned_targets().unwrap().is_empty());
}
