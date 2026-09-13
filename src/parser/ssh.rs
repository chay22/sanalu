use std::collections::HashMap;
use std::net::IpAddr;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SshEvent {
    AuthFailure { ip: IpAddr, user: String },
    ScannerProbe { ip: IpAddr, reason: &'static str },
    Ignore,
}

fn parse_probe_prefix(trimmed: &str, prefix: &str, reason: &'static str) -> Option<SshEvent> {
    let pos = trimmed.find(prefix)?;
    let after = trimmed.get(pos + prefix.len()..)?;
    let ip_str = after.split_whitespace().next()?;
    let ip = ip_str.parse::<IpAddr>().ok()?;
    Some(SshEvent::ScannerProbe { ip, reason })
}

fn parse_auth_failure(trimmed: &str, marker: &str) -> Option<SshEvent> {
    let pos = trimmed.find(marker)?;
    let after = trimmed.get(pos + marker.len()..)?;
    let after = after.strip_prefix("invalid user ").unwrap_or(after);
    let mut parts = after.split_whitespace();
    let user = parts.next().unwrap_or("unknown").to_string();
    let from_pos = after.find(" from ")?;
    let after_from = after.get(from_pos + " from ".len()..)?;
    let ip_str = after_from.split_whitespace().next()?;
    let ip = ip_str.parse::<IpAddr>().ok()?;
    Some(SshEvent::AuthFailure { ip, user })
}

pub fn parse_ssh_log_line(line: &str) -> SshEvent {
    let trimmed = line.trim();

    if let Some(ev) = parse_probe_prefix(
        trimmed,
        "banner exchange: Connection from ",
        "banner_invalid_format",
    ) {
        return ev;
    }

    if trimmed.contains("kex_exchange_identification") {
        if let Some(ip) = extract_ip_from_phrase(trimmed, "Connection from ")
            .or_else(|| extract_ip_from_phrase(trimmed, "from "))
            .or_else(|| extract_ip_from_phrase(trimmed, "by "))
        {
            return SshEvent::ScannerProbe {
                ip,
                reason: "invalid_protocol_identifier",
            };
        }
    }

    if let Some(ev) = parse_probe_prefix(
        trimmed,
        "Did not receive identification string from ",
        "no_identification_string",
    ) {
        return ev;
    }

    if let Some(ev) = parse_auth_failure(trimmed, "Failed password for ") {
        return ev;
    }

    if let Some(ev) = parse_auth_failure(trimmed, "Invalid user ") {
        return ev;
    }

    SshEvent::Ignore
}

#[derive(Default)]
pub struct SshStatefulParser {
    pub pending_pids: HashMap<u32, &'static str>,
}

impl SshStatefulParser {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn pending_count(&self) -> usize {
        self.pending_pids.len()
    }

    fn insert_pending(&mut self, pid: u32, reason: &'static str) {
        if !self.pending_pids.contains_key(&pid) && self.pending_pids.len() >= 256 {
            if let Some(old_key) = self.pending_pids.keys().next().copied() {
                self.pending_pids.remove(&old_key);
            }
        }
        self.pending_pids.insert(pid, reason);
    }

    pub fn process_line(&mut self, line: &str) -> SshEvent {
        let pid = extract_sshd_pid(line);

        if let Some(p) = pid {
            if let Some(&pending_reason) = self.pending_pids.get(&p) {
                if let Some(ip) = extract_ip_from_phrase(line, "Connection from ")
                    .or_else(|| extract_ip_from_phrase(line, "from "))
                {
                    self.pending_pids.remove(&p);
                    return SshEvent::ScannerProbe {
                        ip,
                        reason: pending_reason,
                    };
                }
            }
        }

        if line.contains("kex_exchange_identification: client sent invalid protocol identifier") {
            if let Some(p) = pid {
                self.insert_pending(p, "invalid_protocol_identifier");
            }
            return SshEvent::Ignore;
        }

        if line.contains("banner line contains invalid characters") {
            if let Some(p) = pid {
                self.insert_pending(p, "banner_invalid_characters");
            }
            return SshEvent::Ignore;
        }

        parse_ssh_log_line(line)
    }
}

fn extract_sshd_pid(line: &str) -> Option<u32> {
    let start = line.find("sshd[")? + 5;
    let end = start + line.get(start..)?.find(']')?;
    line.get(start..end)?.parse().ok()
}

fn extract_ip_from_phrase(line: &str, phrase: &str) -> Option<IpAddr> {
    let pos = line.find(phrase)? + phrase.len();
    let after = line.get(pos..)?;
    let end = after
        .find(|c: char| c.is_whitespace() || c == ':' || c == ',')
        .unwrap_or(after.len());
    after.get(..end)?.parse().ok()
}
