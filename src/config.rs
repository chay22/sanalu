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
    #[serde(default = "default_socket_path")]
    pub socket_path: PathBuf,
}

fn default_whitelist() -> Vec<String> {
    Vec::new()
}

fn default_db_path() -> PathBuf {
    PathBuf::from("/var/lib/sanalu/sanalu.redb")
}

fn default_ip_db_path() -> PathBuf {
    PathBuf::from("/var/lib/sanalu/ip_asn_geo.bin")
}

fn default_socket_path() -> PathBuf {
    PathBuf::from("/run/sanalu/sanalu.sock")
}

impl Default for GeneralConfig {
    fn default() -> Self {
        Self {
            whitelist: default_whitelist(),
            db_path: default_db_path(),
            ip_db_path: default_ip_db_path(),
            socket_path: default_socket_path(),
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
    Vec::new()
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
        "security_testing".into(),
        "bad_scraper".into(),
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
    Vec::new()
}

fn default_allowed_regions() -> Vec<String> {
    Vec::new()
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

fn deserialize_bool_lenient<'de, D>(deserializer: D) -> Result<bool, D::Error>
where
    D: serde::Deserializer<'de>,
{
    struct BoolOrStringVisitor;
    impl<'de> serde::de::Visitor<'de> for BoolOrStringVisitor {
        type Value = bool;
        fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
            formatter.write_str("a boolean or string")
        }
        fn visit_bool<E>(self, v: bool) -> Result<Self::Value, E> {
            Ok(v)
        }
        fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<Self::Value, E> {
            match v.trim().to_lowercase().as_str() {
                "true" | "yes" | "1" | "on" => Ok(true),
                "false" | "no" | "0" | "off" => Ok(false),
                _ => Err(E::custom(format!("invalid boolean: {v}"))),
            }
        }
    }
    deserializer.deserialize_any(BoolOrStringVisitor)
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CloudflareConfig {
    #[serde(default, deserialize_with = "deserialize_bool_lenient")]
    pub enabled: bool,
    #[serde(
        default,
        alias = "token",
        alias = "CF_AUTH_TOKEN",
        alias = "cf_auth_token",
        alias = "cf_token"
    )]
    pub api_token: String,
    #[serde(default, alias = "zone", alias = "zone-id")]
    pub zone_id: String,
    #[serde(default = "default_rule_name")]
    pub rule_name: String,
    #[serde(default = "default_action")]
    pub action: String,
    #[serde(default = "default_max_rule_chars")]
    pub max_rule_chars: usize,
    #[serde(default = "default_sync_batch_seconds")]
    pub sync_batch_seconds: u64,
    #[serde(default, alias = "ruleset", alias = "ruleset-id")]
    pub ruleset_id: Option<String>,
    #[serde(default, alias = "rule", alias = "rule-id")]
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
    #[serde(default, alias = "Cloudflare")]
    pub cloudflare: CloudflareConfig,
}

pub fn check_unquoted_ip_hint(content: &str) -> Option<&'static str> {
    let mut in_array = false;
    let mut in_quote = false;
    let mut quote_char = '"';
    let mut token = String::new();

    for ch in content.chars() {
        if in_quote {
            if ch == quote_char {
                in_quote = false;
            }
            continue;
        }
        match ch {
            '"' | '\'' => {
                in_quote = true;
                quote_char = ch;
                token.clear();
            }
            '[' => {
                in_array = true;
                token.clear();
            }
            ']' => {
                in_array = false;
                if is_unquoted_ip_like(&token) {
                    return Some(
                        "Hint: IP addresses in TOML arrays must be enclosed in quotes, e.g. whitelist = [\"1.2.3.4\", \"2001:db8::1\"]",
                    );
                }
                token.clear();
            }
            ',' | '\n' if in_array => {
                if is_unquoted_ip_like(&token) {
                    return Some(
                        "Hint: IP addresses in TOML arrays must be enclosed in quotes, e.g. whitelist = [\"1.2.3.4\", \"2001:db8::1\"]",
                    );
                }
                token.clear();
            }
            _ if in_array => {
                token.push(ch);
            }
            _ => {}
        }
    }
    None
}

fn is_unquoted_ip_like(s: &str) -> bool {
    let t = s.trim();
    if t.is_empty() {
        return false;
    }
    let (ip_part, _) = t.split_once('/').unwrap_or((t, ""));
    let dots = ip_part.bytes().filter(|&b| b == b'.').count();
    if dots == 3 && ip_part.bytes().all(|b| b.is_ascii_digit() || b == b'.') {
        return true;
    }
    if ip_part.contains(':') && ip_part.bytes().all(|b| b.is_ascii_hexdigit() || b == b':') {
        return true;
    }
    false
}

pub fn parse_app_config(content: &str, path: &Path) -> Result<AppConfig, SanaluError> {
    match toml::from_str::<AppConfig>(content) {
        Ok(cfg) => Ok(cfg),
        Err(e) => {
            let mut msg = format!("Configuration error in {:?}: {}", path, e);
            if let Some(hint) = check_unquoted_ip_hint(content) {
                msg.push_str("\n\n");
                msg.push_str(hint);
            }
            Err(SanaluError::Config(msg))
        }
    }
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
        let path_ref = path.as_ref();
        let content = std::fs::read_to_string(path_ref)?;
        parse_app_config(&content, path_ref)
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
