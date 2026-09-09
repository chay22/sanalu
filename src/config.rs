use crate::error::SanaluError;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::time::Duration;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GeneralConfig {
    #[serde(default = "default_whitelist")]
    pub whitelist: Vec<String>,
    #[serde(default = "default_db_path")]
    pub db_path: PathBuf,
    #[serde(default = "default_ip_db_path")]
    pub ip_db_path: PathBuf,
}

fn default_whitelist() -> Vec<String> {
    vec![
        "127.0.0.1".into(),
        "::1".into(),
        "10.0.0.0/8".into(),
        "172.16.0.0/12".into(),
        "192.168.0.0/16".into(),
    ]
}

fn default_db_path() -> PathBuf {
    PathBuf::from("/var/lib/sanalu/sanalu.redb")
}

fn default_ip_db_path() -> PathBuf {
    PathBuf::from("/var/lib/sanalu/ip_asn_geo.bin")
}

impl Default for GeneralConfig {
    fn default() -> Self {
        Self {
            whitelist: default_whitelist(),
            db_path: default_db_path(),
            ip_db_path: default_ip_db_path(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NginxConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_10m")]
    pub find_time: String,
    #[serde(default = "default_one")]
    pub max_retry: u32,
    #[serde(default = "default_nginx_ban_tiers")]
    pub ban_tiers: Vec<String>,
    #[serde(default = "default_true")]
    pub probe_instant_ban: bool,
    #[serde(default = "default_allowed_endpoints")]
    pub allowed_endpoints: Vec<String>,
}

fn default_10m() -> String {
    "10m".into()
}

fn default_one() -> u32 {
    1
}

fn default_nginx_ban_tiers() -> Vec<String> {
    vec!["15m".into(), "1h".into(), "24h".into(), "permanent".into()]
}

fn default_allowed_endpoints() -> Vec<String> {
    vec![
        "^/api/.*".into(),
        "^/health$".into(),
        "^/metrics$".into(),
        "^/webhooks/.*".into(),
        "^/ws/.*".into(),
    ]
}

impl Default for NginxConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            find_time: default_10m(),
            max_retry: 1,
            ban_tiers: default_nginx_ban_tiers(),
            probe_instant_ban: true,
            allowed_endpoints: default_allowed_endpoints(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SshConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_10m")]
    pub find_time: String,
    #[serde(default = "default_three")]
    pub max_retry: u32,
    #[serde(default = "default_ssh_ban_tiers")]
    pub ban_tiers: Vec<String>,
    #[serde(default = "default_true")]
    pub scanner_instant_ban: bool,
}

fn default_three() -> u32 {
    3
}

fn default_ssh_ban_tiers() -> Vec<String> {
    vec!["1h".into(), "24h".into(), "permanent".into()]
}

impl Default for SshConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            find_time: default_10m(),
            max_retry: 3,
            ban_tiers: default_ssh_ban_tiers(),
            scanner_instant_ban: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BotsConfig {
    #[serde(default = "default_blocked_categories")]
    pub blocked_categories: Vec<String>,
}

fn default_blocked_categories() -> Vec<String> {
    vec![
        "scanners".into(),
        "ai".into(),
        "aggressive_seo".into(),
        "generic_tools".into(),
    ]
}

impl Default for BotsConfig {
    fn default() -> Self {
        Self {
            blocked_categories: default_blocked_categories(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AsnRulesConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_restricted_asns")]
    pub restricted_asns: Vec<u32>,
    #[serde(default = "default_allowed_regions")]
    pub allowed_regions: Vec<String>,
    #[serde(default)]
    pub blocked_asns: Vec<u32>,
}

fn default_restricted_asns() -> Vec<u32> {
    vec![15169, 16509, 14061, 31898, 13238, 13335]
}

fn default_allowed_regions() -> Vec<String> {
    vec![
        "ID".into(),
        "MY".into(),
        "SG".into(),
        "US".into(),
        "PH".into(),
        "JP".into(),
    ]
}

impl Default for AsnRulesConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            restricted_asns: default_restricted_asns(),
            allowed_regions: default_allowed_regions(),
            blocked_asns: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CloudflareConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub api_token: String,
    #[serde(default)]
    pub zone_id: String,
    #[serde(default = "default_rule_name")]
    pub rule_name: String,
    #[serde(default = "default_action")]
    pub action: String,
    #[serde(default = "default_max_rule_chars")]
    pub max_rule_chars: usize,
    #[serde(default = "default_sync_batch_seconds")]
    pub sync_batch_seconds: u64,
    #[serde(default)]
    pub ruleset_id: Option<String>,
    #[serde(default)]
    pub rule_id: Option<String>,
}

fn default_true() -> bool {
    true
}

fn default_rule_name() -> String {
    "sanalu_auto_block".into()
}

fn default_action() -> String {
    "block".into()
}

fn default_max_rule_chars() -> usize {
    3950
}

fn default_sync_batch_seconds() -> u64 {
    5
}

impl Default for CloudflareConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            api_token: String::new(),
            zone_id: String::new(),
            rule_name: default_rule_name(),
            action: default_action(),
            max_rule_chars: default_max_rule_chars(),
            sync_batch_seconds: default_sync_batch_seconds(),
            ruleset_id: None,
            rule_id: None,
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct AppConfig {
    #[serde(default)]
    pub general: GeneralConfig,
    #[serde(default)]
    pub nginx: NginxConfig,
    #[serde(default)]
    pub ssh: SshConfig,
    #[serde(default)]
    pub bots: BotsConfig,
    #[serde(default)]
    pub asn_rules: AsnRulesConfig,
    #[serde(default)]
    pub cloudflare: CloudflareConfig,
}

impl std::str::FromStr for AppConfig {
    type Err = SanaluError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let config: Self = toml::from_str(s)?;
        Ok(config)
    }
}

impl AppConfig {
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self, SanaluError> {
        let content = std::fs::read_to_string(path)?;
        content.parse::<Self>()
    }

    pub fn to_toml_string(&self) -> Result<String, SanaluError> {
        toml::to_string_pretty(self).map_err(|e| SanaluError::Config(e.to_string()))
    }
}

pub fn parse_duration_str(s: &str) -> Result<Option<Duration>, SanaluError> {
    let trimmed = s.trim();
    if trimmed.eq_ignore_ascii_case("permanent") {
        return Ok(None);
    }
    if trimmed.is_empty() {
        return Err(SanaluError::Config(
            "Duration string cannot be empty".into(),
        ));
    }
    let (num_str, unit) = trimmed.split_at(trimmed.len() - 1);
    let num: u64 = num_str
        .parse()
        .map_err(|_| SanaluError::Config(format!("Invalid duration number in: {s}")))?;
    match unit {
        "s" => Ok(Some(Duration::from_secs(num))),
        "m" => Ok(Some(Duration::from_secs(num * 60))),
        "h" => Ok(Some(Duration::from_secs(num * 3600))),
        "d" => Ok(Some(Duration::from_secs(num * 86400))),
        _ => Err(SanaluError::Config(format!(
            "Unknown duration unit '{unit}' in: {s}"
        ))),
    }
}
