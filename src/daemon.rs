use crate::cloudflare::CloudflareSyncWorker;
use crate::config::{AppConfig, parse_app_config};
use crate::discovery::discover_environment;
use crate::error::SanaluError;
use crate::firewall::{FirewallBackend, NftablesBackend};
use crate::geo::IpLookupDb;
use crate::intelligence::ThreatPipeline;
use crate::storage::RedbStore;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::mpsc;

pub use crate::discovery::is_root;

pub use crate::engine::{
    ActiveWatcher, NginxWatcherRegistry, ReconcileReport, build_pipeline_from_config,
    build_pipeline_from_store, get_effective_allowed_regions, get_effective_blocked_asns,
    get_effective_blocked_categories, replay_log_file, spawn_ssh_watcher,
};

fn ensure_data_dir(db_path: &Path) {
    if let Some(parent) = db_path.parent() {
        if !parent.exists() {
            let _ = std::fs::create_dir_all(parent);
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700));
            }
        }
    }
}

fn sync_asn_fallback(
    firewall: &NftablesBackend,
    geo_db: &crate::geo::IpLookupDb,
    blocked_asns: &[u32],
) {
    let mut asn_cidrs = Vec::new();
    for &asn in blocked_asns {
        asn_cidrs.extend(geo_db.cidrs_for_asn(asn));
    }
    if !asn_cidrs.is_empty() {
        let _ = firewall.sync_asn_cidrs(&asn_cidrs);
    }
}

fn reconcile_watchers(
    registry: &mut NginxWatcherRegistry,
    pipeline: &Arc<ThreatPipeline>,
    firewall: &Arc<NftablesBackend>,
    store: &Arc<RedbStore>,
    cf_tx: &Option<mpsc::Sender<()>>,
    geo_db: &Arc<IpLookupDb>,
) {
    let fresh_disc = discover_environment();
    let report = registry.reconcile(
        &fresh_disc.nginx_logs,
        pipeline.clone(),
        firewall.clone(),
        store.clone(),
        cf_tx.clone(),
        geo_db.clone(),
    );
    if report.added > 0 || report.updated > 0 || report.removed > 0 {
        println!(
            "Nginx watchers reconciled: {} added, {} updated, {} removed, {} unchanged",
            report.added, report.updated, report.removed, report.unchanged
        );
    }
}

fn sweep_expired_bans(store: &RedbStore) {
    let now_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    if let Ok(count) = store.cleanup_expired_bans(now_secs) {
        if count > 0 {
            println!("Purged {} expired temporary bans from database", count);
        }
    }
}

#[cfg(unix)]
async fn wait_for_daemon_events(
    registry: &mut NginxWatcherRegistry,
    pipeline: &Arc<ThreatPipeline>,
    firewall: &Arc<NftablesBackend>,
    store: &Arc<RedbStore>,
    cf_tx: &Option<mpsc::Sender<()>>,
    geo_db: &Arc<IpLookupDb>,
    rescan_interval: Duration,
) -> Result<(), SanaluError> {
    let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .map_err(SanaluError::Io)?;
    let mut sighup = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup()).ok();
    let mut rescan_ticker = tokio::time::interval(rescan_interval);
    let mut sweep_ticker = tokio::time::interval(Duration::from_secs(60));
    rescan_ticker.tick().await;
    sweep_ticker.tick().await;

    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => break,
            _ = sigterm.recv() => break,
            _ = async {
                match sighup.as_mut() {
                    Some(sh) => {
                        if sh.recv().await.is_none() {
                            std::future::pending().await
                        }
                    }
                    None => std::future::pending().await,
                }
            } => {
                reconcile_watchers(registry, pipeline, firewall, store, cf_tx, geo_db);
            }
            _ = rescan_ticker.tick() => {
                reconcile_watchers(registry, pipeline, firewall, store, cf_tx, geo_db);
            }
            _ = sweep_ticker.tick() => {
                sweep_expired_bans(store);
            }
        }
    }
    Ok(())
}

#[cfg(not(unix))]
async fn wait_for_daemon_events(
    registry: &mut NginxWatcherRegistry,
    pipeline: &Arc<ThreatPipeline>,
    firewall: &Arc<NftablesBackend>,
    store: &Arc<RedbStore>,
    cf_tx: &Option<mpsc::Sender<()>>,
    geo_db: &Arc<IpLookupDb>,
    rescan_interval: Duration,
) -> Result<(), SanaluError> {
    let mut rescan_ticker = tokio::time::interval(rescan_interval);
    let mut sweep_ticker = tokio::time::interval(Duration::from_secs(60));
    rescan_ticker.tick().await;
    sweep_ticker.tick().await;

    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => break,
            _ = rescan_ticker.tick() => {
                reconcile_watchers(registry, pipeline, firewall, store, cf_tx, geo_db);
            }
            _ = sweep_ticker.tick() => {
                sweep_expired_bans(store);
            }
        }
    }
    Ok(())
}

pub async fn run_daemon(config_path: &Path, dry_run_cli: bool) -> Result<(), SanaluError> {
    let dry_run = dry_run_cli || !is_root();
    if !dry_run && !is_root() {
        return Err(SanaluError::Firewall(
            "Root privileges required. Run with sudo, or use --dry-run for testing.".into(),
        ));
    }

    let default_db_path = Path::new("/var/lib/sanalu/sanalu.redb");
    ensure_data_dir(default_db_path);

    let config = if config_path.exists() {
        let content = std::fs::read_to_string(config_path)?;
        parse_app_config(&content, config_path)?
    } else {
        AppConfig::default()
    };

    let db_path = &config.general.db_path;
    let store = Arc::new(RedbStore::open(db_path)?);
    store.sync_from_config(&config)?;

    let firewall = Arc::new(NftablesBackend::auto_detect(dry_run));
    firewall.init_tables()?;

    if !config.general.ip_db_path.exists() {
        println!(
            "[WARN] IP/ASN/Geo database not found at {:?}. ASN blocking and regional rules are INACTIVE. Run 'sanalu update-db' to enable geo-defense.",
            config.general.ip_db_path
        );
    }

    let geo_db = Arc::new(if config.general.ip_db_path.exists() {
        crate::geo::IpLookupDb::from_file(&config.general.ip_db_path).unwrap_or_default()
    } else {
        crate::geo::IpLookupDb::empty()
    });

    let blocked_asns = store.list_blocked_asns().unwrap_or_default();
    sync_asn_fallback(&firewall, &geo_db, &blocked_asns);

    let cf_tx =
        CloudflareSyncWorker::start_if_enabled(&config, store.clone(), blocked_asns, dry_run)
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

    let mut registry = NginxWatcherRegistry::new();
    let init_report = registry.reconcile(
        &env_disc.nginx_logs,
        pipeline.clone(),
        firewall.clone(),
        store.clone(),
        cf_tx.clone(),
        geo_db.clone(),
    );
    if init_report.added > 0 || init_report.updated > 0 || init_report.removed > 0 {
        println!(
            "Nginx watchers reconciled: {} added, {} updated, {} removed, {} unchanged",
            init_report.added, init_report.updated, init_report.removed, init_report.unchanged
        );
    }

    let ssh_handle = spawn_ssh_watcher(
        env_disc.ssh_source,
        pipeline.clone(),
        firewall.clone(),
        store.clone(),
        cf_tx.clone(),
        geo_db.clone(),
    );

    let rescan_dur = crate::config::parse_duration_str(&config.nginx.rescan_interval)
        .ok()
        .flatten()
        .unwrap_or(Duration::from_secs(3600));

    wait_for_daemon_events(
        &mut registry,
        &pipeline,
        &firewall,
        &store,
        &cf_tx,
        &geo_db,
        rescan_dur,
    )
    .await?;

    ssh_handle.abort();
    registry.abort_all();

    if socket_path.exists() {
        let _ = std::fs::remove_file(&socket_path);
    }
    println!("Shutting down sanalu...");
    Ok(())
}
