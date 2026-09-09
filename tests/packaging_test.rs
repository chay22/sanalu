use sanalu::config::{AppConfig, parse_duration_str};
use std::fs;
use std::path::Path;

#[test]
fn test_systemd_service_file_and_limits() {
    let service_path = Path::new("dist/systemd/sanalu.service");
    assert!(service_path.exists());

    let content = fs::read_to_string(service_path).unwrap();
    assert!(content.contains("LimitNOFILE=1048576"));
    assert!(content.contains("OOMScoreAdjust=-500"));
    assert!(content.contains("TasksMax=infinity"));
    assert!(content.contains("ExecStart=/usr/bin/sanalu run"));
    assert!(content.contains("StandardOutput=journal"));
    assert!(content.contains("RuntimeDirectory=sanalu"));
}

#[test]
fn test_dist_config_template() {
    let conf_path = Path::new("dist/sanalu.toml");
    assert!(conf_path.exists());

    let content = fs::read_to_string(conf_path).unwrap();
    assert!(!content.contains("db_path"));
    assert!(!content.contains("ip_db_path"));
    assert!(!content.contains("socket_path"));
    assert!(!content.contains("ruleset_id"));
    assert!(!content.contains("rule_id"));

    let parsed: AppConfig =
        toml::from_str(&content).expect("dist/sanalu.toml must be valid AppConfig");
    assert_eq!(parsed.nginx.find_time, "10m");
    assert_eq!(
        parse_duration_str(&parsed.nginx.find_time)
            .unwrap()
            .unwrap()
            .as_secs(),
        600
    );
    assert_eq!(parsed.nginx.ban_tiers.len(), 4);
    assert_eq!(parsed.ssh.max_retry, 5);
    assert!(parsed.asn_rules.allowed_regions.is_empty());
    assert!(parsed.general.whitelist.is_empty());
    assert!(parsed.nginx.allowed_endpoints.is_empty());
    assert_eq!(parsed.cloudflare.sync_batch_seconds, 5);
    assert_eq!(
        parsed.general.db_path,
        Path::new("/var/lib/sanalu/sanalu.redb")
    );
    assert_eq!(
        parsed.general.ip_db_path,
        Path::new("/var/lib/sanalu/ip_asn_geo.bin")
    );
    assert_eq!(
        parsed.general.socket_path,
        Path::new("/run/sanalu/sanalu.sock")
    );
    assert!(parsed.cloudflare.ruleset_id.is_none());
    assert!(parsed.cloudflare.rule_id.is_none());
}

#[test]
fn test_custom_override_paths_and_cloudflare_ids() {
    let toml_str = r#"
[general]
db_path = "/custom/db.redb"
socket_path = "/custom/custom.sock"

[cloudflare]
ruleset_id = "my_ruleset"
rule_id = "my_rule"
"#;
    let parsed: AppConfig = toml::from_str(toml_str).unwrap();
    assert_eq!(parsed.general.db_path, Path::new("/custom/db.redb"));
    assert_eq!(parsed.general.socket_path, Path::new("/custom/custom.sock"));
    assert_eq!(parsed.cloudflare.ruleset_id.as_deref(), Some("my_ruleset"));
    assert_eq!(parsed.cloudflare.rule_id.as_deref(), Some("my_rule"));
}

#[test]
fn test_cargo_deb_metadata_exists() {
    let cargo_path = Path::new("Cargo.toml");
    let content = fs::read_to_string(cargo_path).unwrap();
    assert!(content.contains("[package.metadata.deb]"));
    assert!(content.contains("assets = ["));
    assert!(content.contains("dist/completions/sanalu"));
    assert!(content.contains("usr/share/bash-completion/completions/sanalu"));
}

#[test]
fn test_dist_completions_file() {
    let comp_path = Path::new("dist/completions/sanalu");
    assert!(comp_path.exists());
    let content = fs::read_to_string(comp_path).unwrap();
    assert!(content.contains("_sanalu"));
    assert!(content.contains("sanalu,status"));
    assert!(content.contains("sanalu,ban"));
    assert!(content.contains("sanalu,check"));
}
