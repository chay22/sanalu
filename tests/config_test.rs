use sanalu::config::{AppConfig, parse_app_config, parse_duration_str};
use std::path::Path;
use std::time::Duration;

#[test]
fn test_default_config_parsing() {
    let cfg = AppConfig::default();
    assert!(cfg.nginx.enabled);
    assert_eq!(cfg.nginx.find_time, "10m");
    assert_eq!(cfg.nginx.max_retry, 1);
    assert_eq!(cfg.ssh.max_retry, 3);
    assert!(!cfg.cloudflare.enabled);
    assert!(cfg.asn_rules.restricted_asns.is_empty());
    assert!(cfg.asn_rules.allowed_regions.is_empty());
    assert!(cfg.general.whitelist.is_empty());
    assert!(cfg.nginx.allowed_endpoints.is_empty());
}

#[test]
fn test_parse_from_toml_string() {
    let toml_str = r#"
        [general]
        whitelist = ["1.1.1.1", "2.2.2.2/24"]

        [nginx]
        enabled = true
        find_time = "5m"
        max_retry = 2
        allowed_endpoints = ["^/api/.*", "^/health$"]

        [cloudflare]
        enabled = true
        api_token = "test_token"
        zone_id = "test_zone"
        sync_batch_seconds = 8
    "#;

    let cfg: AppConfig = toml_str.parse().expect("Failed to parse TOML");
    assert_eq!(cfg.general.whitelist.len(), 2);
    assert_eq!(cfg.nginx.find_time, "5m");
    assert_eq!(cfg.nginx.max_retry, 2);
    assert!(cfg.cloudflare.enabled);
    assert_eq!(cfg.cloudflare.api_token, "test_token");
    assert_eq!(cfg.cloudflare.zone_id, "test_zone");
    assert_eq!(cfg.cloudflare.sync_batch_seconds, 8);
}

#[test]
fn test_cloudflare_lenient_boolean_and_aliases() {
    let toml_str = r#"
        [Cloudflare]
        enabled = "true"
        CF_AUTH_TOKEN = "my_token"
        zone = "my_zone"
        rule = "my_rule"
    "#;
    let cfg: AppConfig = toml_str.parse().unwrap();
    assert!(cfg.cloudflare.enabled);
    assert_eq!(cfg.cloudflare.api_token, "my_token");
    assert_eq!(cfg.cloudflare.zone_id, "my_zone");
    assert_eq!(cfg.cloudflare.rule_id.as_deref(), Some("my_rule"));
}

#[test]
fn test_duration_parsing() {
    assert_eq!(
        parse_duration_str("10s").unwrap(),
        Some(Duration::from_secs(10))
    );
    assert_eq!(
        parse_duration_str("15m").unwrap(),
        Some(Duration::from_secs(900))
    );
    assert_eq!(
        parse_duration_str("2h").unwrap(),
        Some(Duration::from_secs(7200))
    );
    assert_eq!(
        parse_duration_str("1d").unwrap(),
        Some(Duration::from_secs(86400))
    );
    assert_eq!(parse_duration_str("permanent").unwrap(), None);
    assert_eq!(parse_duration_str("PERMANENT").unwrap(), None);
    assert!(parse_duration_str("invalid").is_err());
}

#[test]
fn test_unquoted_ip_diagnostic_hint() {
    let toml_str = r#"
        [general]
        whitelist = [46.250.231.252, 58.84.8.135]
    "#;

    let err = parse_app_config(toml_str, Path::new("/etc/sanalu/sanalu.toml"))
        .unwrap_err()
        .to_string();
    assert!(err.contains("Configuration error in \"/etc/sanalu/sanalu.toml\""));
    assert!(err.contains("Hint: IP addresses in TOML arrays must be enclosed in quotes"));
}

#[test]
fn test_unquoted_ipv6_diagnostic_hint() {
    let toml_str = r#"
        [general]
        whitelist = [2001:db8::1, ::1]
    "#;

    let err = parse_app_config(toml_str, Path::new("/etc/sanalu/sanalu.toml"))
        .unwrap_err()
        .to_string();
    assert!(err.contains("Hint: IP addresses in TOML arrays must be enclosed in quotes"));
}

#[test]
fn test_strict_valid_config_no_hint() {
    let toml_str = r#"
        [general]
        whitelist = ["46.250.231.252", "2001:db8::1"]
    "#;

    let cfg = parse_app_config(toml_str, Path::new("/etc/sanalu/sanalu.toml")).unwrap();
    assert_eq!(cfg.general.whitelist.len(), 2);
}
