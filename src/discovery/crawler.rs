use super::nginx::{DiscoveredNginxLog, NginxLogFormatKind, classify_format_body};
use std::collections::{HashMap, HashSet, VecDeque};
use std::fs;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

const DEFAULT_COMBINED_FORMAT: &str = "$remote_addr - $remote_user [$time_local] \"$request\" $status $body_bytes_sent \"$http_referer\" \"$http_user_agent\"";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NginxCrawlerResult {
    pub formats: HashMap<String, String>,
    pub access_logs: Vec<DiscoveredNginxLog>,
    pub error_logs: Vec<PathBuf>,
}

pub fn crawl_nginx_config_tree(root_conf: &Path, nginx_log_dir: &Path) -> NginxCrawlerResult {
    let mut formats = HashMap::new();
    formats.insert("combined".to_string(), DEFAULT_COMBINED_FORMAT.to_string());

    let mut raw_access_logs: Vec<(PathBuf, Option<String>)> = Vec::new();
    let mut error_logs: Vec<PathBuf> = Vec::new();
    let mut visited: HashSet<PathBuf> = HashSet::new();

    let conf_base_dir = root_conf
        .parent()
        .unwrap_or_else(|| Path::new("/etc/nginx"));

    let mut queue = VecDeque::new();
    if root_conf.exists() {
        queue.push_back(root_conf.to_path_buf());
    }

    while let Some(current_path) = queue.pop_front() {
        let canonical = fs::canonicalize(&current_path).unwrap_or_else(|_| current_path.clone());
        if !visited.insert(canonical) {
            continue;
        }

        let content = match fs::read_to_string(&current_path) {
            Ok(c) => c,
            Err(_) => continue,
        };

        let current_dir = current_path.parent().unwrap_or(conf_base_dir);

        let directives = extract_directives(&content);
        let mut state = CrawlerState {
            conf_base_dir,
            current_dir,
            nginx_log_dir,
            formats: &mut formats,
            raw_access_logs: &mut raw_access_logs,
            error_logs: &mut error_logs,
            queue: &mut queue,
        };
        for directive in directives {
            process_directive(&directive, &mut state);
        }
    }

    let mut access_logs: Vec<DiscoveredNginxLog> = Vec::new();
    for (path, fmt_name_opt) in raw_access_logs {
        if access_logs.iter().any(|l| l.path == path) {
            continue;
        }
        let fmt_name = fmt_name_opt.as_deref().unwrap_or("combined");
        let format_kind = if let Some(body) = formats.get(fmt_name) {
            classify_format_body(body)
        } else if fmt_name == "main" {
            formats
                .get("combined")
                .map(|b| classify_format_body(b))
                .unwrap_or(NginxLogFormatKind::Combined)
        } else {
            NginxLogFormatKind::Combined
        };
        access_logs.push(DiscoveredNginxLog { path, format_kind });
    }

    discover_orphan_logs(nginx_log_dir, &formats, &mut access_logs, &mut error_logs);

    NginxCrawlerResult {
        formats,
        access_logs,
        error_logs,
    }
}

struct CrawlerState<'a> {
    conf_base_dir: &'a Path,
    current_dir: &'a Path,
    nginx_log_dir: &'a Path,
    formats: &'a mut HashMap<String, String>,
    raw_access_logs: &'a mut Vec<(PathBuf, Option<String>)>,
    error_logs: &'a mut Vec<PathBuf>,
    queue: &'a mut VecDeque<PathBuf>,
}

fn process_directive(directive: &str, state: &mut CrawlerState) {
    let trimmed = directive.trim();
    if let Some((name, body)) = parse_log_format_directive(trimmed) {
        state.formats.insert(name, body);
    } else if let Some(pattern) = parse_include_directive(trimmed) {
        let matched_files =
            resolve_include_pattern(state.conf_base_dir, state.current_dir, pattern);
        for file in matched_files {
            state.queue.push_back(file);
        }
    } else if let Some((path, fmt)) =
        parse_access_log_directive(trimmed, state.conf_base_dir, state.nginx_log_dir)
    {
        state.raw_access_logs.push((path, fmt));
    } else if let Some(path) =
        parse_error_log_directive(trimmed, state.conf_base_dir, state.nginx_log_dir)
    {
        if !state.error_logs.contains(&path) {
            state.error_logs.push(path);
        }
    }
}

fn parse_include_directive(directive: &str) -> Option<&str> {
    let rest = directive.strip_prefix("include")?.trim();
    let pat = rest
        .trim_matches(';')
        .trim()
        .trim_matches('\'')
        .trim_matches('"')
        .trim();
    if pat.is_empty() { None } else { Some(pat) }
}

fn parse_access_log_directive(
    directive: &str,
    conf_base_dir: &Path,
    nginx_log_dir: &Path,
) -> Option<(PathBuf, Option<String>)> {
    let rest = directive.strip_prefix("access_log")?.trim();
    let parts: Vec<&str> = rest.split_whitespace().collect();
    if parts.is_empty() {
        return None;
    }
    let target = parts[0]
        .trim_matches(';')
        .trim()
        .trim_matches('\'')
        .trim_matches('"')
        .trim();
    if target.is_empty()
        || target == "off"
        || target.starts_with("syslog:")
        || target.starts_with("memory:")
    {
        return None;
    }
    let p = PathBuf::from(target);
    let resolved = if p.is_relative() {
        if nginx_log_dir.join(&p).exists() {
            nginx_log_dir.join(&p)
        } else {
            conf_base_dir.join(&p)
        }
    } else {
        p
    };

    let fmt = if parts.len() > 1 {
        let candidate = parts[1].trim_matches(';').trim();
        if candidate.starts_with("buffer=")
            || candidate.starts_with("gzip")
            || candidate.starts_with("flush=")
            || candidate.starts_with("if=")
        {
            None
        } else {
            Some(candidate.to_string())
        }
    } else {
        None
    };

    Some((resolved, fmt))
}

fn parse_error_log_directive(
    directive: &str,
    conf_base_dir: &Path,
    nginx_log_dir: &Path,
) -> Option<PathBuf> {
    let rest = directive.strip_prefix("error_log")?.trim();
    let parts: Vec<&str> = rest.split_whitespace().collect();
    if parts.is_empty() {
        return None;
    }
    let target = parts[0]
        .trim_matches(';')
        .trim()
        .trim_matches('\'')
        .trim_matches('"')
        .trim();
    if target.is_empty()
        || target == "off"
        || target.starts_with("syslog:")
        || target.starts_with("memory:")
    {
        return None;
    }
    let p = PathBuf::from(target);
    let resolved = if p.is_relative() {
        if nginx_log_dir.join(&p).exists() {
            nginx_log_dir.join(&p)
        } else {
            conf_base_dir.join(&p)
        }
    } else {
        p
    };
    Some(resolved)
}

pub(crate) fn parse_log_format_directive(directive: &str) -> Option<(String, String)> {
    let rest = directive.strip_prefix("log_format")?.trim_start();
    let mut parts = rest.splitn(2, char::is_whitespace);
    let name = parts.next()?.trim().trim_matches(';');
    if name.is_empty() {
        return None;
    }
    let mut body_part = parts.next().unwrap_or("").trim_start();
    if body_part.starts_with("escape=") {
        if let Some(space_idx) = body_part.find(char::is_whitespace) {
            body_part = body_part[space_idx..].trim_start();
        } else {
            body_part = "";
        }
    }
    let body = parse_nginx_format_body(body_part);
    Some((name.to_string(), body))
}

fn parse_nginx_format_body(raw: &str) -> String {
    let mut args = Vec::new();
    let mut chars = raw.chars().peekable();
    while let Some(&c) = chars.peek() {
        if c.is_whitespace() {
            chars.next();
            continue;
        }
        if c == '\'' || c == '"' {
            let quote = c;
            chars.next();
            let mut current = String::new();
            let mut escaped = false;
            while let Some(&ch) = chars.peek() {
                chars.next();
                if escaped {
                    current.push(ch);
                    escaped = false;
                } else if ch == '\\' {
                    escaped = true;
                } else if ch == quote {
                    break;
                } else {
                    current.push(ch);
                }
            }
            args.push(current);
        } else {
            let mut current = String::new();
            while let Some(&ch) = chars.peek() {
                if ch.is_whitespace() || ch == ';' {
                    break;
                }
                chars.next();
                current.push(ch);
            }
            if !current.is_empty() {
                args.push(current);
            }
        }
    }
    args.concat()
}

pub(crate) fn extract_directives(content: &str) -> Vec<String> {
    let mut directives = Vec::new();
    let mut buf = String::new();
    let mut in_single_quote = false;
    let mut in_double_quote = false;
    let mut in_comment = false;
    let mut escaped = false;

    for ch in content.chars() {
        if in_comment {
            if ch == '\n' {
                in_comment = false;
            }
            continue;
        }

        if escaped {
            buf.push(ch);
            escaped = false;
            continue;
        }

        if ch == '\\' && (in_single_quote || in_double_quote) {
            buf.push(ch);
            escaped = true;
            continue;
        }

        if ch == '\'' && !in_double_quote {
            in_single_quote = !in_single_quote;
            buf.push(ch);
            continue;
        }

        if ch == '"' && !in_single_quote {
            in_double_quote = !in_double_quote;
            buf.push(ch);
            continue;
        }

        if !in_single_quote && !in_double_quote {
            if ch == '#' {
                in_comment = true;
                continue;
            }
            if ch == ';' {
                let trimmed = buf.trim();
                if !trimmed.is_empty() {
                    directives.push(trimmed.to_string());
                }
                buf.clear();
                continue;
            }
            if ch == '{' || ch == '}' {
                buf.clear();
                continue;
            }
        }

        buf.push(ch);
    }

    let trimmed = buf.trim();
    if !trimmed.is_empty() {
        directives.push(trimmed.to_string());
    }

    directives
}

fn resolve_include_pattern(
    conf_base_dir: &Path,
    current_dir: &Path,
    pattern: &str,
) -> Vec<PathBuf> {
    let mut files = expand_pattern(conf_base_dir, pattern);
    if files.is_empty() && conf_base_dir != current_dir && !pattern.starts_with('/') {
        files = expand_pattern(current_dir, pattern);
    }
    files
}

fn expand_pattern(base: &Path, pattern: &str) -> Vec<PathBuf> {
    let is_absolute = pattern.starts_with('/');
    let mut candidates = if is_absolute {
        vec![PathBuf::from("/")]
    } else {
        vec![base.to_path_buf()]
    };

    let rel_components: Vec<&str> = pattern.split('/').filter(|s| !s.is_empty()).collect();

    for comp in rel_components {
        let mut next_candidates = Vec::new();
        let has_wildcard = comp.contains('*') || comp.contains('?');

        for parent in candidates {
            if has_wildcard {
                if let Ok(entries) = fs::read_dir(&parent) {
                    for entry in entries.flatten() {
                        let name = entry.file_name();
                        let name_str = name.to_string_lossy();
                        if matches_glob(comp, &name_str) {
                            next_candidates.push(entry.path());
                        }
                    }
                }
            } else {
                next_candidates.push(parent.join(comp));
            }
        }
        candidates = next_candidates;
    }

    let mut result = Vec::new();
    for p in candidates {
        if p.is_file() {
            result.push(p);
        }
    }
    result.sort();
    result
}

fn matches_glob(pattern: &str, text: &str) -> bool {
    let p_bytes = pattern.as_bytes();
    let t_bytes = text.as_bytes();
    let mut p_idx = 0;
    let mut t_idx = 0;
    let mut star_idx = None;
    let mut match_idx = 0;

    while t_idx < t_bytes.len() {
        if p_idx < p_bytes.len() && (p_bytes[p_idx] == b'?' || p_bytes[p_idx] == t_bytes[t_idx]) {
            p_idx += 1;
            t_idx += 1;
        } else if p_idx < p_bytes.len() && p_bytes[p_idx] == b'*' {
            star_idx = Some(p_idx);
            match_idx = t_idx;
            p_idx += 1;
        } else if let Some(star) = star_idx {
            p_idx = star + 1;
            match_idx += 1;
            t_idx = match_idx;
        } else {
            return false;
        }
    }
    while p_idx < p_bytes.len() && p_bytes[p_idx] == b'*' {
        p_idx += 1;
    }
    p_idx == p_bytes.len()
}

fn discover_orphan_logs(
    nginx_log_dir: &Path,
    formats: &HashMap<String, String>,
    access_logs: &mut Vec<DiscoveredNginxLog>,
    error_logs: &mut Vec<PathBuf>,
) {
    if !nginx_log_dir.exists() {
        return;
    }

    for entry in WalkDir::new(nginx_log_dir)
        .min_depth(1)
        .max_depth(2)
        .into_iter()
        .flatten()
    {
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        let file_name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
        if file_name.ends_with(".gz") || file_name.ends_with(".zip") || file_name.ends_with(".tmp")
        {
            continue;
        }

        let is_known_error = file_name.contains("error.log")
            || (file_name.contains("error") && file_name.ends_with(".log"));

        if is_known_error {
            if !error_logs.iter().any(|p| p == path) {
                error_logs.push(path.to_path_buf());
            }
            continue;
        }

        if file_name.ends_with(".log") {
            if is_first_line_error(path) {
                if !error_logs.iter().any(|p| p == path) {
                    error_logs.push(path.to_path_buf());
                }
            } else if !access_logs.iter().any(|l| l.path == path) {
                let format_kind = sniff_log_format(path, formats);
                access_logs.push(DiscoveredNginxLog {
                    path: path.to_path_buf(),
                    format_kind,
                });
            }
        }
    }
}

fn is_first_line_error(path: &Path) -> bool {
    if let Ok(file) = fs::File::open(path) {
        let reader = BufReader::new(file);
        for line in reader.lines().take(5).flatten() {
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            return trimmed.contains("[error]")
                || trimmed.contains("[warn]")
                || trimmed.contains("[crit]")
                || trimmed.contains("[alert]")
                || trimmed.contains("[emerg]");
        }
    }
    false
}

fn sniff_log_format(path: &Path, formats: &HashMap<String, String>) -> NginxLogFormatKind {
    if let Ok(file) = fs::File::open(path) {
        let reader = BufReader::new(file);
        for line in reader.lines().take(10).flatten() {
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            if trimmed.starts_with('{') && trimmed.ends_with('}') {
                return NginxLogFormatKind::Json;
            }
            break;
        }
    }
    if let Some(main_body) = formats.get("main").or_else(|| formats.get("combined")) {
        classify_format_body(main_body)
    } else {
        NginxLogFormatKind::Combined
    }
}
