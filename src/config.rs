use crate::error::SanaluError;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::time::Duration;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GeneralConfig {
    #[serde(
        default = "default_whitelist",
        deserialize_with = "deserialize_string_or_vec"
    )]
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

fn deserialize_string_or_vec<'de, D>(deserializer: D) -> Result<Vec<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    struct StringOrVecVisitor;
    impl<'de> serde::de::Visitor<'de> for StringOrVecVisitor {
        type Value = Vec<String>;
        fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
            formatter.write_str("a string or list of strings")
        }
        fn visit_str<E>(self, v: &str) -> Result<Self::Value, E> {
            Ok(vec![v.to_string()])
        }
        fn visit_seq<S>(self, mut seq: S) -> Result<Self::Value, S::Error>
        where
            S: serde::de::SeqAccess<'de>,
        {
            let mut vec = Vec::new();
            while let Some(elem) = seq.next_element()? {
                vec.push(elem);
            }
            Ok(vec)
        }
    }
    deserializer.deserialize_any(StringOrVecVisitor)
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

fn is_ip_or_cidr(token: &str) -> bool {
    let trimmed = token.trim();
    if trimmed.is_empty() {
        return false;
    }
    if trimmed.parse::<std::net::IpAddr>().is_ok() {
        return true;
    }
    if let Some((ip, prefix)) = trimmed.split_once('/') {
        if ip.parse::<std::net::IpAddr>().is_ok() && prefix.parse::<u8>().is_ok() {
            return true;
        }
    }
    false
}

fn flush_token(token: &mut String, res: &mut String) {
    if token.is_empty() {
        return;
    }
    let trimmed = token.trim();
    if is_ip_or_cidr(trimmed) {
        let leading = token.len() - token.trim_start().len();
        let trailing = token.len() - token.trim_end().len();
        res.push_str(&token[..leading]);
        res.push('"');
        res.push_str(trimmed);
        res.push('"');
        if trailing > 0 {
            res.push_str(&token[token.len() - trailing..]);
        }
    } else {
        res.push_str(token);
    }
    token.clear();
}

pub fn sanitize_unquoted_ips(s: &str) -> String {
    let mut in_array = 0;
    let mut in_single_quote = false;
    let mut in_double_quote = false;
    let mut in_comment = false;
    let mut escaped = false;
    let mut result = String::with_capacity(s.len() + 32);
    let mut current_token = String::new();

    for ch in s.chars() {
        if in_comment {
            if ch == '\n' {
                in_comment = false;
            }
            result.push(ch);
            continue;
        }
        if in_single_quote {
            if ch == '\'' {
                in_single_quote = false;
            }
            result.push(ch);
            continue;
        }
        if in_double_quote {
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == '"' {
                in_double_quote = false;
            }
            result.push(ch);
            continue;
        }

        match ch {
            '#' => {
                flush_token(&mut current_token, &mut result);
                in_comment = true;
                result.push(ch);
            }
            '\'' => {
                flush_token(&mut current_token, &mut result);
                in_single_quote = true;
                result.push(ch);
            }
            '"' => {
                flush_token(&mut current_token, &mut result);
                in_double_quote = true;
                result.push(ch);
            }
            '[' => {
                flush_token(&mut current_token, &mut result);
                in_array += 1;
                result.push(ch);
            }
            ']' => {
                flush_token(&mut current_token, &mut result);
                if in_array > 0 {
                    in_array -= 1;
                }
                result.push(ch);
            }
            ',' | '\n' if in_array > 0 => {
                flush_token(&mut current_token, &mut result);
                result.push(ch);
            }
            _ if in_array > 0 => {
                current_token.push(ch);
            }
            _ => {
                result.push(ch);
            }
        }
    }
    flush_token(&mut current_token, &mut result);
    result
}

impl std::str::FromStr for AppConfig {
    type Err = SanaluError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match toml::from_str::<Self>(s) {
            Ok(config) => Ok(config),
            Err(orig_err) => {
                let sanitized = sanitize_unquoted_ips(s);
                if sanitized != s {
                    if let Ok(config) = toml::from_str::<Self>(&sanitized) {
                        return Ok(config);
                    }
                }
                Err(orig_err.into())
            }
        }
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
