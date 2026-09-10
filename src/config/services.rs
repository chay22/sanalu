use serde::{Deserialize, Serialize};

fn default_true() -> bool {
    true
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
