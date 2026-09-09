use sanalu::engine::EscalationEngine;
use std::net::IpAddr;
use std::time::Duration;

#[test]
fn test_escalation_tiers() {
    let mut engine = EscalationEngine::new(
        Duration::from_secs(600),
        3,
        vec![
            Some(Duration::from_secs(3600)),
            Some(Duration::from_secs(86400)),
            None,
        ],
    );

    let ip: IpAddr = "198.51.100.1".parse().unwrap();
    assert_eq!(engine.record_offense(ip, "auth_fail", false), None);
    assert_eq!(engine.record_offense(ip, "auth_fail", false), None);
    let ban1 = engine
        .record_offense(ip, "auth_fail", false)
        .expect("3rd offense must ban");
    assert_eq!(ban1.tier_level, 0);
    assert!(ban1.expires_at.is_some());

    let instant_ban = engine
        .record_offense(ip, "exploit_probe", true)
        .expect("instant ban");
    assert!(instant_ban.expires_at.is_none());
}
