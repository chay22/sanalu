use sanalu::discovery::{DiscoveredNginxLog, NginxLogFormatKind};
use sanalu::engine::{NginxWatcherRegistry, ReconcileReport};
use sanalu::firewall::NftablesBackend;
use sanalu::geo::IpLookupDb;
use sanalu::intelligence::ThreatPipeline;
use sanalu::parser::CompiledLogFormat;
use sanalu::storage::RedbStore;
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;

struct TestEnv {
    _temp_dir: tempfile::TempDir,
    pipeline: Arc<ThreatPipeline>,
    firewall: Arc<NftablesBackend>,
    store: Arc<RedbStore>,
    geo_db: Arc<IpLookupDb>,
}

impl TestEnv {
    fn new() -> Self {
        let temp_dir = tempfile::tempdir().unwrap();
        let db_path = temp_dir.path().join("test.redb");
        let store = Arc::new(RedbStore::open(&db_path).unwrap());
        let firewall = Arc::new(NftablesBackend::auto_detect(true));
        let pipeline = Arc::new(ThreatPipeline::new_test_instance());
        let geo_db = Arc::new(IpLookupDb::from_tsv_reader(b"".as_ref()).unwrap());
        Self {
            _temp_dir: temp_dir,
            pipeline,
            firewall,
            store,
            geo_db,
        }
    }

    fn create_log_file(&self, name: &str) -> PathBuf {
        let path = self._temp_dir.path().join(name);
        fs::write(&path, "").unwrap();
        path
    }
}

#[tokio::test]
async fn test_initial_population_multiple_vhosts() {
    let env = TestEnv::new();
    let log1 = env.create_log_file("vhost1.log");
    let log2 = env.create_log_file("vhost2.log");

    let mut registry = NginxWatcherRegistry::new();
    let discovered = vec![
        DiscoveredNginxLog {
            path: log1.clone(),
            format_kind: NginxLogFormatKind::Combined,
        },
        DiscoveredNginxLog {
            path: log2.clone(),
            format_kind: NginxLogFormatKind::Combined,
        },
    ];

    let report = registry.reconcile(
        &discovered,
        env.pipeline.clone(),
        env.firewall.clone(),
        env.store.clone(),
        None,
        env.geo_db.clone(),
    );

    assert_eq!(
        report,
        ReconcileReport {
            added: 2,
            unchanged: 0,
            updated: 0,
            removed: 0,
        }
    );
    assert_eq!(registry.active_count(), 2);
    assert!(registry.is_watching(&log1));
    assert!(registry.is_watching(&log2));
    assert_eq!(
        registry.get_format(&log1),
        Some(&NginxLogFormatKind::Combined.to_compiled())
    );
    assert_eq!(
        registry.get_format(&log2),
        Some(&NginxLogFormatKind::Combined.to_compiled())
    );

    registry.abort_all();
    assert_eq!(registry.active_count(), 0);
}

#[tokio::test]
async fn test_add_new_vhost_during_reconciliation() {
    let env = TestEnv::new();
    let log1 = env.create_log_file("vhost1.log");
    let log2 = env.create_log_file("vhost2.log");
    let log3 = env.create_log_file("vhost3.log");

    let mut registry = NginxWatcherRegistry::new();
    let initial_discovered = vec![
        DiscoveredNginxLog {
            path: log1.clone(),
            format_kind: NginxLogFormatKind::Combined,
        },
        DiscoveredNginxLog {
            path: log2.clone(),
            format_kind: NginxLogFormatKind::Combined,
        },
    ];

    let init_report = registry.reconcile(
        &initial_discovered,
        env.pipeline.clone(),
        env.firewall.clone(),
        env.store.clone(),
        None,
        env.geo_db.clone(),
    );
    assert_eq!(
        init_report,
        ReconcileReport {
            added: 2,
            unchanged: 0,
            updated: 0,
            removed: 0,
        }
    );

    let updated_discovered = vec![
        DiscoveredNginxLog {
            path: log1.clone(),
            format_kind: NginxLogFormatKind::Combined,
        },
        DiscoveredNginxLog {
            path: log2.clone(),
            format_kind: NginxLogFormatKind::Combined,
        },
        DiscoveredNginxLog {
            path: log3.clone(),
            format_kind: NginxLogFormatKind::Combined,
        },
    ];

    let report = registry.reconcile(
        &updated_discovered,
        env.pipeline.clone(),
        env.firewall.clone(),
        env.store.clone(),
        None,
        env.geo_db.clone(),
    );

    assert_eq!(
        report,
        ReconcileReport {
            added: 1,
            unchanged: 2,
            updated: 0,
            removed: 0,
        }
    );
    assert_eq!(registry.active_count(), 3);
    assert!(registry.is_watching(&log3));

    registry.abort_all();
}

#[tokio::test]
async fn test_change_format_of_existing_log() {
    let env = TestEnv::new();
    let log1 = env.create_log_file("vhost1.log");
    let log2 = env.create_log_file("vhost2.log");
    let log3 = env.create_log_file("vhost3.log");

    let mut registry = NginxWatcherRegistry::new();
    let initial_discovered = vec![
        DiscoveredNginxLog {
            path: log1.clone(),
            format_kind: NginxLogFormatKind::Combined,
        },
        DiscoveredNginxLog {
            path: log2.clone(),
            format_kind: NginxLogFormatKind::Combined,
        },
        DiscoveredNginxLog {
            path: log3.clone(),
            format_kind: NginxLogFormatKind::Combined,
        },
    ];

    let init_report = registry.reconcile(
        &initial_discovered,
        env.pipeline.clone(),
        env.firewall.clone(),
        env.store.clone(),
        None,
        env.geo_db.clone(),
    );
    assert_eq!(
        init_report,
        ReconcileReport {
            added: 3,
            unchanged: 0,
            updated: 0,
            removed: 0,
        }
    );

    let updated_discovered = vec![
        DiscoveredNginxLog {
            path: log1.clone(),
            format_kind: NginxLogFormatKind::Json,
        },
        DiscoveredNginxLog {
            path: log2.clone(),
            format_kind: NginxLogFormatKind::Combined,
        },
        DiscoveredNginxLog {
            path: log3.clone(),
            format_kind: NginxLogFormatKind::Combined,
        },
    ];

    let report = registry.reconcile(
        &updated_discovered,
        env.pipeline.clone(),
        env.firewall.clone(),
        env.store.clone(),
        None,
        env.geo_db.clone(),
    );

    assert_eq!(
        report,
        ReconcileReport {
            added: 0,
            unchanged: 2,
            updated: 1,
            removed: 0,
        }
    );
    assert_eq!(registry.active_count(), 3);
    assert_eq!(registry.get_format(&log1), Some(&CompiledLogFormat::Json));

    registry.abort_all();
}

#[tokio::test]
async fn test_remove_deleted_vhost_log() {
    let env = TestEnv::new();
    let log1 = env.create_log_file("vhost1.log");
    let log2 = env.create_log_file("vhost2.log");
    let log3 = env.create_log_file("vhost3.log");

    let mut registry = NginxWatcherRegistry::new();
    let initial_discovered = vec![
        DiscoveredNginxLog {
            path: log1.clone(),
            format_kind: NginxLogFormatKind::Combined,
        },
        DiscoveredNginxLog {
            path: log2.clone(),
            format_kind: NginxLogFormatKind::Combined,
        },
        DiscoveredNginxLog {
            path: log3.clone(),
            format_kind: NginxLogFormatKind::Combined,
        },
    ];

    let init_report = registry.reconcile(
        &initial_discovered,
        env.pipeline.clone(),
        env.firewall.clone(),
        env.store.clone(),
        None,
        env.geo_db.clone(),
    );
    assert_eq!(
        init_report,
        ReconcileReport {
            added: 3,
            unchanged: 0,
            updated: 0,
            removed: 0,
        }
    );

    let pruned_discovered = vec![
        DiscoveredNginxLog {
            path: log1.clone(),
            format_kind: NginxLogFormatKind::Combined,
        },
        DiscoveredNginxLog {
            path: log2.clone(),
            format_kind: NginxLogFormatKind::Combined,
        },
    ];

    let report = registry.reconcile(
        &pruned_discovered,
        env.pipeline.clone(),
        env.firewall.clone(),
        env.store.clone(),
        None,
        env.geo_db.clone(),
    );

    assert_eq!(
        report,
        ReconcileReport {
            added: 0,
            unchanged: 2,
            updated: 0,
            removed: 1,
        }
    );
    assert_eq!(registry.active_count(), 2);
    assert!(!registry.is_watching(&log3));

    registry.abort_all();
}

#[tokio::test]
async fn test_unchanged_logs_preserved_without_restart() {
    let env = TestEnv::new();
    let log1 = env.create_log_file("vhost1.log");
    let log2 = env.create_log_file("vhost2.log");

    let mut registry = NginxWatcherRegistry::new();
    let discovered = vec![
        DiscoveredNginxLog {
            path: log1.clone(),
            format_kind: NginxLogFormatKind::Combined,
        },
        DiscoveredNginxLog {
            path: log2.clone(),
            format_kind: NginxLogFormatKind::Combined,
        },
    ];

    let init_report = registry.reconcile(
        &discovered,
        env.pipeline.clone(),
        env.firewall.clone(),
        env.store.clone(),
        None,
        env.geo_db.clone(),
    );
    assert_eq!(
        init_report,
        ReconcileReport {
            added: 2,
            unchanged: 0,
            updated: 0,
            removed: 0,
        }
    );

    let report = registry.reconcile(
        &discovered,
        env.pipeline.clone(),
        env.firewall.clone(),
        env.store.clone(),
        None,
        env.geo_db.clone(),
    );

    assert_eq!(
        report,
        ReconcileReport {
            added: 0,
            unchanged: 2,
            updated: 0,
            removed: 0,
        }
    );
    assert_eq!(registry.active_count(), 2);

    registry.abort_all();
}
