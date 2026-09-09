use std::collections::HashMap;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NginxLogFormatKind {
    Combined,
    CloudflareProxy,
    Json,
    Custom(Vec<NginxFieldToken>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NginxFieldToken {
    RemoteAddr,
    CfConnectingIp,
    XForwardedFor,
    TimeLocal,
    Request,
    Status,
    BytesSent,
    HttpReferer,
    HttpUserAgent,
    Other(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscoveredNginxLog {
    pub path: PathBuf,
    pub format_kind: NginxLogFormatKind,
}

pub fn parse_nginx_config_for_formats(config_content: &str) -> HashMap<String, NginxLogFormatKind> {
    let mut map = HashMap::new();
    for line in config_content.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("log_format") {
            let rest = rest.trim();
            let mut parts = rest.splitn(2, |c: char| c.is_whitespace() || c == '\'' || c == '"');
            let name = parts.next().unwrap_or("").trim();
            let format_body = parts
                .next()
                .unwrap_or("")
                .trim()
                .trim_matches('\'')
                .trim_matches('"')
                .trim_matches(';');
            if !name.is_empty() {
                map.insert(name.to_string(), classify_format_body(format_body));
            }
        }
    }
    map
}

pub fn classify_format_body(body: &str) -> NginxLogFormatKind {
    let trimmed = body.trim();
    if trimmed.starts_with('{') && trimmed.ends_with('}') {
        return NginxLogFormatKind::Json;
    }
    if trimmed.contains("$http_cf_connecting_ip") {
        return NginxLogFormatKind::CloudflareProxy;
    }
    if trimmed.contains("$remote_addr")
        && trimmed.contains("$request")
        && trimmed.contains("$status")
    {
        return NginxLogFormatKind::Combined;
    }
    let mut tokens = Vec::new();
    for word in trimmed.split_whitespace() {
        let clean = word.trim_matches('"').trim_matches('[').trim_matches(']');
        match clean {
            "$remote_addr" => tokens.push(NginxFieldToken::RemoteAddr),
            "$http_cf_connecting_ip" => tokens.push(NginxFieldToken::CfConnectingIp),
            "$http_x_forwarded_for" => tokens.push(NginxFieldToken::XForwardedFor),
            "$time_local" => tokens.push(NginxFieldToken::TimeLocal),
            "$request" => tokens.push(NginxFieldToken::Request),
            "$status" => tokens.push(NginxFieldToken::Status),
            "$body_bytes_sent" => tokens.push(NginxFieldToken::BytesSent),
            "$http_referer" => tokens.push(NginxFieldToken::HttpReferer),
            "$http_user_agent" => tokens.push(NginxFieldToken::HttpUserAgent),
            other => tokens.push(NginxFieldToken::Other(other.to_string())),
        }
    }
    NginxLogFormatKind::Custom(tokens)
}

pub fn parse_nginx_access_logs(
    config_content: &str,
    formats: &HashMap<String, NginxLogFormatKind>,
) -> Vec<DiscoveredNginxLog> {
    let mut logs = Vec::new();
    for line in config_content.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("access_log") {
            let rest = rest.trim().trim_end_matches(';');
            let parts: Vec<&str> = rest.split_whitespace().collect();
            if parts.is_empty() {
                continue;
            }
            let log_path = PathBuf::from(parts[0]);
            let format_kind = if parts.len() > 1 {
                formats
                    .get(parts[1])
                    .cloned()
                    .unwrap_or(NginxLogFormatKind::Combined)
            } else {
                NginxLogFormatKind::Combined
            };
            logs.push(DiscoveredNginxLog {
                path: log_path,
                format_kind,
            });
        }
    }
    logs
}

pub fn discover_nginx_logs_in_dir(log_dir: &Path) -> (Vec<PathBuf>, Vec<PathBuf>) {
    let mut access_logs = Vec::new();
    let mut error_logs = Vec::new();

    if !log_dir.exists() {
        return (access_logs, error_logs);
    }

    for entry in WalkDir::new(log_dir)
        .min_depth(1)
        .max_depth(2)
        .into_iter()
        .flatten()
    {
        let path = entry.path();
        if path.is_file() {
            let file_name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if file_name.ends_with(".gz") || file_name.ends_with(".zip") {
                continue;
            }
            if file_name.contains("access.log") {
                access_logs.push(path.to_path_buf());
            } else if file_name.contains("error.log") {
                error_logs.push(path.to_path_buf());
            }
        }
    }
    (access_logs, error_logs)
}
