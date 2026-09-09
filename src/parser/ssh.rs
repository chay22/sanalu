use std::collections::HashMap;
use std::net::IpAddr;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SshEvent {
    AuthFailure { ip: IpAddr, user: String },
    ScannerProbe { ip: IpAddr, reason: &'static str },
    Ignore,
}

pub fn parse_ssh_log_line(line: &str) -> SshEvent {
    let trimmed = line.trim();

    if let Some(pos) = trimmed.find("banner exchange: Connection from ") {
        let after = &trimmed[pos + "banner exchange: Connection from ".len()..];
        if let Some(ip_str) = after.split_whitespace().next() {
            if let Ok(ip) = ip_str.parse::<IpAddr>() {
                return SshEvent::ScannerProbe {
                    ip,
                    reason: "banner_invalid_format",
                };
            }
        }
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

    if let Some(pos) = trimmed.find("Did not receive identification string from ") {
        let after = &trimmed[pos + "Did not receive identification string from ".len()..];
        if let Some(ip_str) = after.split_whitespace().next() {
            if let Ok(ip) = ip_str.parse::<IpAddr>() {
                return SshEvent::ScannerProbe {
                    ip,
                    reason: "no_identification_string",
                };
            }
        }
    }

    if let Some(pos) = trimmed.find("Failed password for ") {
        let after = &trimmed[pos + "Failed password for ".len()..];
        let after = after.strip_prefix("invalid user ").unwrap_or(after);
        let mut parts = after.split_whitespace();
        let user = parts.next().unwrap_or("unknown").to_string();
        if let Some(from_pos) = after.find(" from ") {
            let after_from = &after[from_pos + " from ".len()..];
            if let Some(ip_str) = after_from.split_whitespace().next() {
                if let Ok(ip) = ip_str.parse::<IpAddr>() {
                    return SshEvent::AuthFailure { ip, user };
                }
            }
        }
    }

    if let Some(pos) = trimmed.find("Invalid user ") {
        let after = &trimmed[pos + "Invalid user ".len()..];
        let mut parts = after.split_whitespace();
        let user = parts.next().unwrap_or("unknown").to_string();
        if let Some(from_pos) = after.find(" from ") {
            let after_from = &after[from_pos + " from ".len()..];
            if let Some(ip_str) = after_from.split_whitespace().next() {
                if let Ok(ip) = ip_str.parse::<IpAddr>() {
                    return SshEvent::AuthFailure { ip, user };
                }
            }
        }
    }

    SshEvent::Ignore
}

#[derive(Default)]
pub struct SshStatefulParser {
    pending_pids: HashMap<u32, &'static str>,
}

impl SshStatefulParser {
    pub fn new() -> Self {
        Self::default()
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
                self.pending_pids.insert(p, "invalid_protocol_identifier");
            }
            return SshEvent::Ignore;
        }

        if line.contains("banner line contains invalid characters") {
            if let Some(p) = pid {
                self.pending_pids.insert(p, "banner_invalid_characters");
            }
            return SshEvent::Ignore;
        }

        parse_ssh_log_line(line)
    }
}

fn extract_sshd_pid(line: &str) -> Option<u32> {
    let start = line.find("sshd[")? + 5;
    let end = start + line[start..].find(']')?;
    line[start..end].parse().ok()
}

fn extract_ip_from_phrase(line: &str, phrase: &str) -> Option<IpAddr> {
    let pos = line.find(phrase)? + phrase.len();
    let after = &line[pos..];
    let end = after
        .find(|c: char| c.is_whitespace() || c == ':' || c == ',')
        .unwrap_or(after.len());
    after[..end].parse().ok()
}
