use crate::discovery::DiscoveredNginxLog;
use crate::engine::spawn_nginx_watcher;
use crate::firewall::NftablesBackend;
use crate::geo::IpLookupDb;
use crate::intelligence::ThreatPipeline;
use crate::parser::CompiledLogFormat;
use crate::storage::RedbStore;
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::sync::mpsc;
use tokio::task::AbortHandle;

pub struct ActiveWatcher {
    pub format: CompiledLogFormat,
    pub abort_handle: AbortHandle,
}

#[derive(Default)]
pub struct NginxWatcherRegistry {
    watchers: HashMap<PathBuf, ActiveWatcher>,
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct ReconcileReport {
    pub added: usize,
    pub updated: usize,
    pub removed: usize,
    pub unchanged: usize,
}

struct WatcherDeps<'a> {
    pipeline: &'a Arc<ThreatPipeline>,
    firewall: &'a Arc<NftablesBackend>,
    store: &'a Arc<RedbStore>,
    cf_tx: &'a Option<mpsc::Sender<()>>,
    geo_db: &'a Arc<IpLookupDb>,
}

impl NginxWatcherRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn active_count(&self) -> usize {
        self.watchers.len()
    }

    pub fn is_watching(&self, path: &Path) -> bool {
        self.watchers.contains_key(path)
    }

    pub fn get_format(&self, path: &Path) -> Option<&CompiledLogFormat> {
        self.watchers.get(path).map(|w| &w.format)
    }

    pub fn abort_all(&mut self) {
        for watcher in self.watchers.values() {
            watcher.abort_handle.abort();
        }
        self.watchers.clear();
    }

    pub fn reconcile(
        &mut self,
        discovered: &[DiscoveredNginxLog],
        pipeline: Arc<ThreatPipeline>,
        firewall: Arc<NftablesBackend>,
        store: Arc<RedbStore>,
        cf_tx: Option<mpsc::Sender<()>>,
        geo_db: Arc<IpLookupDb>,
    ) -> ReconcileReport {
        let mut report = ReconcileReport::default();
        self.prune_missing(discovered, &mut report);
        let deps = WatcherDeps {
            pipeline: &pipeline,
            firewall: &firewall,
            store: &store,
            cf_tx: &cf_tx,
            geo_db: &geo_db,
        };
        for log in discovered {
            self.reconcile_single_log(log, &deps, &mut report);
        }
        report
    }

    fn prune_missing(&mut self, discovered: &[DiscoveredNginxLog], report: &mut ReconcileReport) {
        let discovered_paths: HashSet<&Path> =
            discovered.iter().map(|l| l.path.as_path()).collect();
        self.watchers.retain(|path, watcher| {
            if !discovered_paths.contains(path.as_path()) {
                watcher.abort_handle.abort();
                report.removed += 1;
                false
            } else {
                true
            }
        });
    }

    fn reconcile_single_log(
        &mut self,
        log: &DiscoveredNginxLog,
        deps: &WatcherDeps<'_>,
        report: &mut ReconcileReport,
    ) {
        let compiled = log.format_kind.to_compiled();
        if let Some(existing) = self.watchers.get_mut(&log.path) {
            if existing.format != compiled {
                existing.abort_handle.abort();
                let handle = spawn_nginx_watcher(
                    log.path.clone(),
                    compiled.clone(),
                    deps.pipeline.clone(),
                    deps.firewall.clone(),
                    deps.store.clone(),
                    deps.cf_tx.clone(),
                    deps.geo_db.clone(),
                );
                existing.format = compiled;
                existing.abort_handle = handle.abort_handle();
                report.updated += 1;
            } else {
                report.unchanged += 1;
            }
        } else {
            let handle = spawn_nginx_watcher(
                log.path.clone(),
                compiled.clone(),
                deps.pipeline.clone(),
                deps.firewall.clone(),
                deps.store.clone(),
                deps.cf_tx.clone(),
                deps.geo_db.clone(),
            );
            self.watchers.insert(
                log.path.clone(),
                ActiveWatcher {
                    format: compiled,
                    abort_handle: handle.abort_handle(),
                },
            );
            report.added += 1;
        }
    }
}

impl Drop for NginxWatcherRegistry {
    fn drop(&mut self) {
        self.abort_all();
    }
}
