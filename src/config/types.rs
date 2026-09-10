use serde::{Deserialize, Serialize};
use std::path::PathBuf;

pub use super::cloudflare::CloudflareConfig;
pub use super::services::{AsnRulesConfig, BotsConfig, NginxConfig, SshConfig};

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
