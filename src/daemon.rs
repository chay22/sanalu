use crate::cloudflare::CloudflareSyncWorker;
use crate::config::{AppConfig, parse_app_config};
use crate::discovery::discover_environment;
use crate::error::SanaluError;
use crate::firewall::{FirewallBackend, NftablesBackend};
use crate::storage::RedbStore;
use std::path::Path;
use std::sync::Arc;

pub use crate::cli::generate_completions;

pub fn is_root() -> bool {
    if let Ok(output) = std::process::Command::new("id").arg("-u").output() {
        let s = String::from_utf8_lossy(&output.stdout);
        s.trim() == "0"
    } else {
        false
    }
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

    if is_root() {
        let paths = crate::discovery::detect_completion_paths();
        if !paths.bash_paths.is_empty() {
            let mut buf = Vec::new();
            generate_completions(clap_complete::Shell::Bash, &mut buf);
            for p in &paths.bash_paths {
                let _ = std::fs::write(p, &buf);
            }
        }
        if !paths.zsh_paths.is_empty() {
            let mut buf = Vec::new();
            generate_completions(clap_complete::Shell::Zsh, &mut buf);
            for p in &paths.zsh_paths {
                let _ = std::fs::write(p, &buf);
            }
        }
        if !paths.fish_paths.is_empty() {
            let mut buf = Vec::new();
            generate_completions(clap_complete::Shell::Fish, &mut buf);
            for p in &paths.fish_paths {
                let _ = std::fs::write(p, &buf);
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

pub use crate::engine::{
    build_pipeline_from_config, get_effective_allowed_regions, get_effective_blocked_asns,
    get_effective_blocked_categories, replay_log_file,
};

fn sync_asn_fallback(
    firewall: &NftablesBackend,
    geo_db: &crate::geo::IpLookupDb,
    effective_asns: &[u32],
) {
    let mut asn_cidrs = Vec::new();
    for &asn in effective_asns {
        asn_cidrs.extend(geo_db.cidrs_for_asn(asn));
    }
    if !asn_cidrs.is_empty() {
        let _ = firewall.sync_asn_cidrs(&asn_cidrs);
    }
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
        parse_app_config(&content, config_path)?
    } else {
        AppConfig::default()
    };

    let db_path = &config.general.db_path;
    let store = Arc::new(RedbStore::open(db_path)?);

    let firewall = Arc::new(NftablesBackend::auto_detect(dry_run));
    firewall.init_tables()?;

    let geo_db = Arc::new(if config.general.ip_db_path.exists() {
        crate::geo::IpLookupDb::from_file(&config.general.ip_db_path).unwrap_or_default()
    } else {
        crate::geo::IpLookupDb::empty()
    });

    let effective_asns = get_effective_blocked_asns(&config, &store);
    sync_asn_fallback(&firewall, &geo_db, &effective_asns);

    let cf_tx =
        CloudflareSyncWorker::start_if_enabled(&config, store.clone(), effective_asns, dry_run)
            .await?;

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
        crate::engine::spawn_nginx_watcher(
            log.path.clone(),
            pipeline.clone(),
            firewall.clone(),
            store.clone(),
            cf_tx.clone(),
            geo_db.clone(),
        );
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
