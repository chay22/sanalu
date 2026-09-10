use super::diagnostics::check_unquoted_ip_hint;
use super::types::AppConfig;
use crate::error::SanaluError;
use std::path::Path;
use std::time::Duration;

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
