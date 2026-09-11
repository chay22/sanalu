use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

pub fn find_active_nginx_conf() -> PathBuf {
    let proc_root = Path::new("/proc");
    let systemd_dirs = [
        Path::new("/etc/systemd/system"),
        Path::new("/lib/systemd/system"),
        Path::new("/usr/lib/systemd/system"),
    ];
    let fallbacks = [
        Path::new("/etc/nginx/nginx.conf"),
        Path::new("/usr/local/nginx/conf/nginx.conf"),
        Path::new("/opt/nginx/conf/nginx.conf"),
    ];
    find_active_nginx_conf_with_paths(proc_root, &systemd_dirs, &fallbacks)
}

pub fn find_active_nginx_conf_with_paths(
    proc_root: &Path,
    systemd_dirs: &[&Path],
    fallbacks: &[&Path],
) -> PathBuf {
    if let Some(conf) = find_conf_from_proc(proc_root) {
        return conf;
    }
    if let Some(conf) = find_conf_from_systemd(systemd_dirs) {
        return conf;
    }
    for fb in fallbacks {
        if fb.exists() {
            return fb.to_path_buf();
        }
    }
    fallbacks
        .first()
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| PathBuf::from("/etc/nginx/nginx.conf"))
}

fn find_conf_from_proc(proc_root: &Path) -> Option<PathBuf> {
    let entries = fs::read_dir(proc_root).ok()?;
    for entry in entries.flatten() {
        let cmdline_path = entry.path().join("cmdline");
        if let Ok(bytes) = fs::read(&cmdline_path) {
            if let Some(conf) = parse_cmdline_bytes(&bytes) {
                return Some(conf);
            }
        }
    }
    None
}

fn parse_cmdline_bytes(bytes: &[u8]) -> Option<PathBuf> {
    if bytes.is_empty() {
        return None;
    }
    let s = String::from_utf8_lossy(bytes);
    let tokens: Vec<&str> = s.split('\0').filter(|t| !t.is_empty()).collect();
    if tokens.is_empty() || !tokens[0].contains("nginx") {
        return None;
    }
    for (i, token) in tokens.iter().enumerate() {
        if *token == "-c" {
            if let Some(next) = tokens.get(i + 1) {
                let p = next.trim();
                if !p.is_empty() {
                    return Some(PathBuf::from(p));
                }
            }
        } else if let Some(stripped) = token.strip_prefix("-c") {
            let p = stripped.trim();
            if !p.is_empty() {
                return Some(PathBuf::from(p));
            }
        }
    }
    None
}

fn find_conf_from_systemd(systemd_dirs: &[&Path]) -> Option<PathBuf> {
    for path in systemd_dirs {
        if path.is_file() {
            if let Some(conf) = parse_systemd_file(path) {
                return Some(conf);
            }
        } else if path.is_dir() {
            let direct = path.join("nginx.service");
            if direct.is_file() {
                if let Some(conf) = parse_systemd_file(&direct) {
                    return Some(conf);
                }
            }
            let wanted = path.join("multi-user.target.wants").join("nginx.service");
            if wanted.is_file() {
                if let Some(conf) = parse_systemd_file(&wanted) {
                    return Some(conf);
                }
            }
        }
    }
    None
}

fn parse_systemd_file(path: &Path) -> Option<PathBuf> {
    let content = fs::read_to_string(path).ok()?;
    for line in content.lines() {
        if let Some(conf) = parse_exec_start_line(line) {
            return Some(conf);
        }
    }
    None
}

fn parse_exec_start_line(line: &str) -> Option<PathBuf> {
    let trimmed = line.trim();
    let rest = trimmed
        .strip_prefix("ExecStart")?
        .trim_start()
        .strip_prefix('=')?;
    let words: Vec<&str> = rest.split_whitespace().collect();
    for (i, word) in words.iter().enumerate() {
        if *word == "-c" {
            if let Some(next) = words.get(i + 1) {
                let clean = next.trim_matches('"').trim_matches('\'').trim();
                if !clean.is_empty() {
                    return Some(PathBuf::from(clean));
                }
            }
        } else if let Some(stripped) = word.strip_prefix("-c") {
            let clean = stripped.trim_matches('"').trim_matches('\'').trim();
            if !clean.is_empty() {
                return Some(PathBuf::from(clean));
            }
        }
    }
    None
}

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
