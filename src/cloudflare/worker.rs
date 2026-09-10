use super::client::CloudflareClient;
use super::expression::CloudflareRuleBudget;
use crate::config::AppConfig;
use crate::error::SanaluError;
use crate::storage::RedbStore;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;

pub struct CloudflareSyncWorker {
    client: CloudflareClient,
    store: Arc<RedbStore>,
    max_rule_chars: usize,
    batch_seconds: u64,
    rx: mpsc::Receiver<()>,
}

impl CloudflareSyncWorker {
    pub async fn start_if_enabled(
        config: &AppConfig,
        store: Arc<RedbStore>,
        _effective_asns: Vec<u32>,
        dry_run: bool,
    ) -> Result<Option<mpsc::Sender<()>>, SanaluError> {
        if !config.cloudflare.enabled || config.cloudflare.api_token.is_empty() {
            return Ok(None);
        }
        let cf_client = CloudflareClient::new(config.cloudflare.clone(), dry_run)?;
        let tx = Self::spawn(
            cf_client,
            store,
            config.cloudflare.max_rule_chars,
            config.cloudflare.sync_batch_seconds,
        );
        let _ = tx.send(()).await;
        Ok(Some(tx))
    }

    pub fn spawn(
        client: CloudflareClient,
        store: Arc<RedbStore>,
        max_rule_chars: usize,
        batch_seconds: u64,
    ) -> mpsc::Sender<()> {
        let (tx, rx) = mpsc::channel(100);
        let worker = Self {
            client,
            store,
            max_rule_chars,
            batch_seconds,
            rx,
        };

        tokio::spawn(async move {
            worker.run_loop().await;
        });

        tx
    }

    async fn run_loop(mut self) {
        while self.rx.recv().await.is_some() {
            tokio::time::sleep(Duration::from_secs(self.batch_seconds)).await;
            while self.rx.try_recv().is_ok() {}

            let blocked_asns = self.store.list_blocked_asns().unwrap_or_default();
            let restricted_asns = self.store.list_restricted_asns().unwrap_or_default();
            let allowed_regions = self.store.list_allowed_regions().unwrap_or_default();
            let budget = CloudflareRuleBudget::new(
                self.max_rule_chars,
                blocked_asns,
                restricted_asns,
                allowed_regions,
            );

            if let Ok(banned_records) = self.store.list_active_bans() {
                let mut v4_ips = Vec::new();
                for r in banned_records {
                    let maybe_ip = r.ip.or_else(|| r.target.parse().ok());
                    if let Some(std::net::IpAddr::V4(v4)) = maybe_ip {
                        v4_ips.push(v4);
                    }
                }
                v4_ips.reverse();

                let (expr, _) = budget.render_expression(&v4_ips);
                match self.client.update_waf_rule(&expr).await {
                    Ok(()) => {
                        let _ = self.store.set_cloudflare_state(&expr);
                    }
                    Err(e) => {
                        eprintln!("[Cloudflare Sync Error] {e}");
                    }
                }
            }
        }
    }
}
