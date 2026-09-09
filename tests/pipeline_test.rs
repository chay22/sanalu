use sanalu::geo::IpMetadata;
use sanalu::intelligence::{BotCategory, PipelineAction, ThreatPipeline};
use std::collections::HashSet;
use std::net::IpAddr;

#[test]
fn test_scanner_on_allowed_endpoint_is_still_banned() {
    let pipeline = ThreatPipeline::new_test_instance();
    let action = pipeline.evaluate(
        "203.0.113.10".parse().unwrap(),
        None,
        "zgrab/0.x (compatible; Research)",
        "GET",
        "/api/health",
    );
    match action {
        PipelineAction::Ban { reason, .. } => {
            assert_eq!(reason, "blocked_bot_category:security_testing");
        }
        _ => panic!("Scanner on allowed endpoint must be banned at Stage 2!"),
    }
}

#[test]
fn test_clean_user_agent_on_allowed_endpoint_is_allowed() {
    let pipeline = ThreatPipeline::new_test_instance();
    let action = pipeline.evaluate(
        "203.0.113.10".parse().unwrap(),
        None,
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
        "GET",
        "/api/health",
    );
    assert!(matches!(action, PipelineAction::Allow));
}

#[test]
fn test_clean_user_agent_on_exploit_path_is_banned() {
    let pipeline = ThreatPipeline::new_test_instance();
    let action = pipeline.evaluate(
        "203.0.113.10".parse().unwrap(),
        None,
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
        "GET",
        "/.env",
    );
    match action {
        PipelineAction::Ban { reason, permanent } => {
            assert_eq!(reason, "harmful_probe:.env");
            assert!(permanent);
        }
        _ => panic!("Clean browser hitting .env must be permanently banned!"),
    }
}

#[test]
fn test_whitelist_bypasses_all_subsequent_stages() {
    let mut whitelisted_ips = HashSet::new();
    let ip: IpAddr = "192.0.2.100".parse().unwrap();
    whitelisted_ips.insert(ip);

    let pipeline = ThreatPipeline::new(
        whitelisted_ips,
        HashSet::new(),
        HashSet::new(),
        HashSet::new(),
        HashSet::new(),
        HashSet::new(),
        &[],
    )
    .unwrap();

    let action = pipeline.evaluate(ip, None, "zgrab/0.x", "GET", "/.env");
    assert_eq!(action, PipelineAction::Allow);
}

#[test]
fn test_stage1_asn_policy() {
    let mut blocked_asns = HashSet::new();
    blocked_asns.insert(9009);

    let mut restricted_asns = HashSet::new();
    restricted_asns.insert(16509);

    let mut allowed_regions = HashSet::new();
    allowed_regions.insert("US".into());
    allowed_regions.insert("SG".into());

    let mut blocked_categories = HashSet::new();
    blocked_categories.insert(BotCategory::SecurityTesting);

    let pipeline = ThreatPipeline::new(
        HashSet::new(),
        HashSet::new(),
        blocked_asns,
        restricted_asns,
        allowed_regions,
        blocked_categories,
        &[],
    )
    .unwrap();

    let ip: IpAddr = "198.51.100.1".parse().unwrap();

    let meta_blocked = IpMetadata {
        asn: 9009,
        country: *b"RU",
        as_org: "BAD_ASN".into(),
    };
    let action_blocked = pipeline.evaluate(ip, Some(&meta_blocked), "Mozilla/5.0", "GET", "/");
    assert_eq!(
        action_blocked,
        PipelineAction::Ban {
            reason: "blocked_asn:9009".into(),
            permanent: false,
        }
    );

    let meta_restricted_disallowed = IpMetadata {
        asn: 16509,
        country: *b"RU",
        as_org: "AMAZON".into(),
    };
    let action_disallowed = pipeline.evaluate(
        ip,
        Some(&meta_restricted_disallowed),
        "Mozilla/5.0",
        "GET",
        "/",
    );
    assert_eq!(
        action_disallowed,
        PipelineAction::Ban {
            reason: "restricted_asn_region:16509:RU".into(),
            permanent: false,
        }
    );

    let meta_restricted_allowed = IpMetadata {
        asn: 16509,
        country: *b"US",
        as_org: "AMAZON".into(),
    };
    let action_allowed = pipeline.evaluate(
        ip,
        Some(&meta_restricted_allowed),
        "Mozilla/5.0",
        "GET",
        "/",
    );
    assert_eq!(action_allowed, PipelineAction::Allow);
}

#[test]
fn test_loopback_and_private_ips_automatically_allowed() {
    let pipeline = ThreatPipeline::new_test_instance();
    let loopback_v4: IpAddr = "127.0.0.1".parse().unwrap();
    let loopback_v6: IpAddr = "::1".parse().unwrap();
    let private_10: IpAddr = "10.0.1.50".parse().unwrap();
    let private_172: IpAddr = "172.16.5.10".parse().unwrap();
    let private_192: IpAddr = "192.168.1.100".parse().unwrap();
    let cgnat: IpAddr = "100.64.0.1".parse().unwrap();

    for ip in [loopback_v4, loopback_v6, private_10, private_172, private_192, cgnat] {
        let action = pipeline.evaluate(
            ip,
            None,
            "zgrab/0.x (compatible; Research)",
            "GET",
            "/.env",
        );
        assert_eq!(action, PipelineAction::Allow);
    }
}
