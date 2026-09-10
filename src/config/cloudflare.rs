use serde::{Deserialize, Serialize};

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
