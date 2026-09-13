use crate::error::SanaluError;
use crate::intelligence::{BotCategory, PipelineAction, ThreatPipeline};
use crate::parser::nginx::{parse_nginx_combined_line, parse_nginx_json_line};
use crate::parser::ssh::{SshEvent, SshStatefulParser};
use std::collections::HashSet;
use std::fs::File;
use std::io::{BufRead, BufReader, Write};
use std::path::Path;

pub fn replay_log_file(log_path: &Path, allowed_endpoints: &[String]) -> Result<u64, SanaluError> {
    let file = File::open(log_path)?;
    let reader = BufReader::new(file);
    let mut stdout = std::io::stdout();

    let mut blocked_categories = HashSet::new();
    blocked_categories.insert(BotCategory::SecurityTesting);
    blocked_categories.insert(BotCategory::AiCrawler);
    blocked_categories.insert(BotCategory::BadScraper);
    blocked_categories.insert(BotCategory::GenericTools);
    blocked_categories.insert(BotCategory::Empty);

    let pipeline = ThreatPipeline::new(
        HashSet::new(),
        HashSet::new(),
        HashSet::new(),
        HashSet::new(),
        HashSet::new(),
        blocked_categories,
        allowed_endpoints,
    )?;

    let mut ssh_parser = SshStatefulParser::new();
    let mut threat_count = 0u64;

    for line in reader.lines() {
        let line = match line {
            Ok(l) => l,
            Err(_) => continue,
        };

        if let Some(entry) = parse_nginx_combined_line(&line) {
            let action = pipeline.evaluate_request(
                entry.client_ip,
                None,
                entry.user_agent,
                entry.method,
                entry.path,
                entry.status,
                entry.referer,
            );
            if let PipelineAction::Ban { reason, permanent } = action {
                threat_count += 1;
                if let Err(e) = writeln!(
                    stdout,
                    "[NGINX THREAT] IP: {} | Action: BAN (permanent={}) | Reason: {} | Path: {}",
                    entry.client_ip, permanent, reason, entry.path
                ) {
                    if e.kind() == std::io::ErrorKind::BrokenPipe {
                        return Ok(threat_count);
                    }
                }
            }
            continue;
        }

        if let Some((client_ip, method, uri, status, referer, ua)) = parse_nginx_json_line(&line) {
            let action =
                pipeline.evaluate_request(client_ip, None, &ua, &method, &uri, status, &referer);
            if let PipelineAction::Ban { reason, permanent } = action {
                threat_count += 1;
                if let Err(e) = writeln!(
                    stdout,
                    "[NGINX JSON THREAT] IP: {} | Action: BAN (permanent={}) | Reason: {} | Path: {}",
                    client_ip, permanent, reason, uri
                ) {
                    if e.kind() == std::io::ErrorKind::BrokenPipe {
                        return Ok(threat_count);
                    }
                }
            }
            continue;
        }

        let ssh_ev = ssh_parser.process_line(&line);
        let action = pipeline.evaluate_ssh_event(&ssh_ev);
        if let PipelineAction::Ban { reason, permanent } = action {
            threat_count += 1;
            let ip = match ssh_ev {
                SshEvent::ScannerProbe { ip, .. } => ip,
                SshEvent::AuthFailure { ip, .. } => ip,
                SshEvent::Ignore => continue,
            };
            if let Err(e) = writeln!(
                stdout,
                "[SSH THREAT] IP: {} | Action: BAN (permanent={}) | Reason: {}",
                ip, permanent, reason
            ) {
                if e.kind() == std::io::ErrorKind::BrokenPipe {
                    return Ok(threat_count);
                }
            }
        }
    }

    Ok(threat_count)
}
