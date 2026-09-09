use crate::cloudflare::{CloudflareClient, CloudflareRuleBudget, CloudflareSyncWorker};
use crate::config::AppConfig;
use crate::discovery::discover_environment;
use crate::error::SanaluError;
use crate::firewall::{FirewallBackend, NftablesBackend};
use crate::intelligence::{BotCategory, PipelineAction, ThreatPipeline};
use crate::parser::nginx::{parse_nginx_combined_line, parse_nginx_json_line};
use crate::parser::ssh::{SshEvent, SshStatefulParser};
use crate::storage::{RedbStore, StoredBanRecord};
use std::collections::HashSet;
use std::fs::File;
use std::io::{BufRead, BufReader, Seek, SeekFrom, Write};
use std::net::IpAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use clap::CommandFactory;

pub fn is_root() -> bool {
    if let Ok(output) = std::process::Command::new("id").arg("-u").output() {
        let s = String::from_utf8_lossy(&output.stdout);
        s.trim() == "0"
    } else {
        false
    }
}

pub fn generate_completions<W: Write>(shell: clap_complete::Shell, buf: &mut W) {
    let mut cmd = crate::cli::Cli::command();
    clap_complete::generate(shell, &mut cmd, "sanalu", buf);
}

pub fn bootstrap_files(config_path: &Path, db_path: &Path) -> Result<(), SanaluError> {
    if let Some(parent) = db_path.parent() {
        if !parent.exists() {
            std::fs::create_dir_all(parent)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700));
            }
        }
    }

    if !config_path.exists() {
        if let Some(parent) = config_path.parent() {
            if !parent.exists() {
                std::fs::create_dir_all(parent)?;
            }
        }
        let template = include_str!("../dist/sanalu.toml");
        std::fs::write(config_path, template)?;
    }

    let completion_dirs = [
        Path::new("/usr/share/bash-completion/completions"),
        Path::new("/etc/bash_completion.d"),
    ];
    if is_root() {
        let mut buf = Vec::new();
        generate_completions(clap_complete::Shell::Bash, &mut buf);
        for dir in completion_dirs {
            if dir.exists() {
                let file = dir.join("sanalu");
                let _ = std::fs::write(&file, &buf);
            }
        }
    }

    let systemd_dir = Path::new("/etc/systemd/system");
    if systemd_dir.exists() && is_root() {
        let service_file = systemd_dir.join("sanalu.service");
        let lib_service_file = Path::new("/lib/systemd/system/sanalu.service");
        if !service_file.exists() && !lib_service_file.exists() {
            let unit = include_str!("../dist/systemd/sanalu.service");
            let _ = std::fs::write(&service_file, unit);
            let _ = std::process::Command::new("systemctl")
                .arg("daemon-reload")
                .output();
        }
    }

    Ok(())
}

pub fn build_pipeline_from_config(
    config: &AppConfig,
    store: &RedbStore,
) -> Result<ThreatPipeline, SanaluError> {
    let mut whitelisted_ips = HashSet::new();
    for entry in &config.general.whitelist {
        if let Ok(ip) = entry.parse::<IpAddr>() {
            whitelisted_ips.insert(ip);
        }
    }
    if let Ok(db_whitelist) = store.list_whitelist() {
        for entry in db_whitelist {
            if let Ok(ip) = entry.parse::<IpAddr>() {
                whitelisted_ips.insert(ip);
            }
        }
    }

    let mut banned_ips = HashSet::new();
    if let Ok(active_bans) = store.list_active_bans() {
        for b in active_bans {
            if let Some(ip) = b.ip {
                banned_ips.insert(ip);
            } else if let Ok(ip) = b.target.parse::<IpAddr>() {
                banned_ips.insert(ip);
            }
        }
    }

    let mut blocked_asns = HashSet::new();
    for &asn in &config.asn_rules.blocked_asns {
        blocked_asns.insert(asn);
    }
    if let Ok(db_asns) = store.list_blocked_asns() {
        for asn in db_asns {
            blocked_asns.insert(asn);
        }
    }

    let mut restricted_asns = HashSet::new();
    for &asn in &config.asn_rules.restricted_asns {
        restricted_asns.insert(asn);
    }

    let mut allowed_regions = HashSet::new();
    for r in &config.asn_rules.allowed_regions {
        allowed_regions.insert(r.clone());
    }
    if let Ok(db_regions) = store.list_allowed_regions() {
        for r in db_regions {
            allowed_regions.insert(r);
        }
    }

    let mut blocked_categories = HashSet::new();
    for cat_name in &config.bots.blocked_categories {
        if let Some(cat) = BotCategory::from_str_name(cat_name) {
            blocked_categories.insert(cat);
        }
    }
    if let Ok(db_cats) = store.list_blocked_categories() {
        for cat_name in db_cats {
            if let Some(cat) = BotCategory::from_str_name(&cat_name) {
                blocked_categories.insert(cat);
            }
        }
    }

    ThreatPipeline::new(
        whitelisted_ips,
        banned_ips,
        blocked_asns,
        restricted_asns,
        allowed_regions,
        blocked_categories,
        &config.nginx.allowed_endpoints,
    )
}

pub fn replay_log_file(log_path: &Path, allowed_endpoints: &[String]) -> Result<u64, SanaluError> {
    let file = File::open(log_path)?;
    let reader = BufReader::new(file);
    let mut stdout = std::io::stdout();

    let mut blocked_categories = HashSet::new();
    blocked_categories.insert(BotCategory::SecurityTesting);
    blocked_categories.insert(BotCategory::AiCrawler);
    blocked_categories.insert(BotCategory::BadScraper);
    blocked_categories.insert(BotCategory::GenericTools);

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
            let action = pipeline.evaluate(
                entry.client_ip,
                None,
                entry.user_agent,
                entry.method,
                entry.path,
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

        if let Some((client_ip, method, uri, _, _, ua)) = parse_nginx_json_line(&line) {
            let action = pipeline.evaluate(client_ip, None, &ua, &method, &uri);
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
        match ssh_ev {
            SshEvent::ScannerProbe { ip, reason } => {
                threat_count += 1;
                if let Err(e) = writeln!(stdout, "[SSH SCANNER] IP: {} | Reason: {}", ip, reason) {
                    if e.kind() == std::io::ErrorKind::BrokenPipe {
                        return Ok(threat_count);
                    }
                }
            }
            SshEvent::AuthFailure { ip, user } => {
                threat_count += 1;
                if let Err(e) = writeln!(stdout, "[SSH AUTH FAIL] IP: {} | User: {}", ip, user) {
                    if e.kind() == std::io::ErrorKind::BrokenPipe {
                        return Ok(threat_count);
                    }
                }
            }
            SshEvent::Ignore => {}
        }
    }

    Ok(threat_count)
}

pub async fn run_daemon(config_path: &Path, dry_run_cli: bool) -> Result<(), SanaluError> {
    let dry_run = dry_run_cli || !is_root();
    if !dry_run && !is_root() {
        return Err(SanaluError::Firewall(
            "Root privileges required. Run with sudo, or use --dry-run for testing.".into(),
        ));
    }

    let default_db_path = Path::new("/var/lib/sanalu/sanalu.redb");
    let _ = bootstrap_files(config_path, default_db_path);

    let config = if config_path.exists() {
        let content = std::fs::read_to_string(config_path)?;
        content.parse::<AppConfig>().map_err(|e| {
            SanaluError::Config(format!("Configuration error in {:?}: {}", config_path, e))
        })?
    } else {
        AppConfig::default()
    };

    let db_path = &config.general.db_path;
    let store = Arc::new(RedbStore::open(db_path)?);

    let firewall = Arc::new(NftablesBackend::auto_detect(dry_run));
    firewall.init_tables()?;

    let cf_tx = if config.cloudflare.enabled && !config.cloudflare.api_token.is_empty() {
        let cf_client = CloudflareClient::new(config.cloudflare.clone(), dry_run)?;
        let budget = CloudflareRuleBudget::new(
            config.cloudflare.max_rule_chars,
            config.asn_rules.blocked_asns.clone(),
            config.asn_rules.restricted_asns.clone(),
            config.asn_rules.allowed_regions.clone(),
        );
        let tx = CloudflareSyncWorker::spawn(
            cf_client,
            store.clone(),
            budget,
            config.cloudflare.sync_batch_seconds,
        );
        Some(tx)
    } else {
        None
    };

    let pipeline = Arc::new(build_pipeline_from_config(&config, &store)?);
    let env_disc = discover_environment();

    println!("Sanalu security daemon initialized.");
    println!("Database: {:?}", db_path);
    println!("Dry run mode: {}", dry_run);
    println!("Discovered {} Nginx logs", env_disc.nginx_logs.len());
    println!("SSH Source: {:?}", env_disc.ssh_source);

    let socket_path = config.general.socket_path.clone();
    let ipc_server = crate::ipc::IpcServer::new(
        socket_path.clone(),
        store.clone(),
        firewall.clone(),
        cf_tx.clone(),
        Arc::new(config.clone()),
    );
    tokio::spawn(async move {
        let _ = ipc_server.run().await;
    });

    for log in &env_disc.nginx_logs {
        let path = log.path.clone();
        let pipe = pipeline.clone();
        let fw = firewall.clone();
        let st = store.clone();
        let cf = cf_tx.clone();

        tokio::spawn(async move {
            let mut file = match File::open(&path) {
                Ok(f) => f,
                Err(_) => return,
            };
            let _ = file.seek(SeekFrom::End(0));
            let mut reader = BufReader::new(file);

            loop {
                let mut line = String::new();
                match reader.read_line(&mut line) {
                    Ok(0) => {
                        tokio::time::sleep(Duration::from_millis(500)).await;
                    }
                    Ok(_) => {
                        let trimmed = line.trim();
                        if let Some(entry) = parse_nginx_combined_line(trimmed) {
                            let action = pipe.evaluate(
                                entry.client_ip,
                                None,
                                entry.user_agent,
                                entry.method,
                                entry.path,
                            );
                            if let PipelineAction::Ban { reason, permanent } = action {
                                let timeout = if permanent { None } else { Some(3600) };
                                let _ = fw.ban_ip(entry.client_ip, timeout);

                                let now_secs = SystemTime::now()
                                    .duration_since(UNIX_EPOCH)
                                    .unwrap_or_default()
                                    .as_secs();
                                let record = StoredBanRecord {
                                    target: entry.client_ip.to_string(),
                                    ip: Some(entry.client_ip),
                                    tier_level: 0,
                                    banned_at_secs: now_secs,
                                    expires_at_secs: timeout.map(|s| now_secs + s),
                                    reason: reason.clone(),
                                };
                                let _ = st.save_ban(&record);

                                if let Some(ref tx) = cf {
                                    let _ = tx.send(()).await;
                                }
                                println!("[BAN] {} - {}", entry.client_ip, reason);
                            }
                        }
                    }
                    Err(_) => {
                        tokio::time::sleep(Duration::from_millis(500)).await;
                    }
                }
            }
        });
    }

    #[cfg(unix)]
    {
        let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .map_err(SanaluError::Io)?;
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {},
            _ = sigterm.recv() => {},
        }
    }
    #[cfg(not(unix))]
    {
        tokio::signal::ctrl_c().await.map_err(SanaluError::Io)?;
    }

    if socket_path.exists() {
        let _ = std::fs::remove_file(&socket_path);
    }
    println!("Shutting down sanalu...");
    Ok(())
}
