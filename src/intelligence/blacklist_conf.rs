use crate::error::SanaluError;
use std::collections::HashSet;
use std::path::Path;

#[derive(Debug, Default, Clone)]
pub struct BlacklistConfigData {
    pub bad_user_agents: HashSet<String>,
    pub bad_referrers: HashSet<String>,
}

impl BlacklistConfigData {
    pub fn parse_str(content: &str) -> Self {
        let mut data = Self::default();
        let mut in_bad_bot_map = false;
        let mut in_bad_referer_map = false;

        for line in content.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }

            if trimmed.starts_with("map $http_user_agent") {
                in_bad_bot_map = true;
                in_bad_referer_map = false;
                continue;
            } else if trimmed.starts_with("map $http_referer") {
                in_bad_referer_map = true;
                in_bad_bot_map = false;
                continue;
            }

            if trimmed == "}" {
                in_bad_bot_map = false;
                in_bad_referer_map = false;
                continue;
            }

            if in_bad_bot_map {
                if let Some(token) = extract_map_key(trimmed) {
                    data.bad_user_agents.insert(token);
                }
            } else if in_bad_referer_map {
                if let Some(token) = extract_map_key(trimmed) {
                    data.bad_referrers.insert(token);
                }
            }
        }

        data
    }

    pub fn load_from_file(path: &Path) -> Result<Self, SanaluError> {
        let content = std::fs::read_to_string(path)?;
        Ok(Self::parse_str(&content))
    }
}

fn extract_map_key(line: &str) -> Option<String> {
    let mut parts = line.split_whitespace();
    let raw_key = parts.next()?;
    if raw_key == "default" || raw_key == "include" {
        return None;
    }
    let val = parts.next().unwrap_or("");
    if val == "0;" {
        return None;
    }
    let cleaned = raw_key
        .trim_matches('"')
        .trim_matches('\'')
        .trim_start_matches("~*")
        .trim_start_matches(r"(?:\b)")
        .trim_end_matches(r"(?:\b)")
        .replace("\\.", ".");
    if cleaned.is_empty() {
        None
    } else {
        Some(cleaned)
    }
}
