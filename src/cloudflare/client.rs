use super::expression::CloudflareRuleBudget;
use crate::config::CloudflareConfig;
use crate::error::SanaluError;
use crate::storage::RedbStore;
use reqwest::header::{AUTHORIZATION, CONTENT_TYPE, HeaderMap, HeaderValue};
use serde_json::json;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;

#[derive(Clone)]
pub struct CloudflareClient {
    config: CloudflareConfig,
    dry_run: bool,
    http_client: reqwest::Client,
}

impl CloudflareClient {
    pub fn new(config: CloudflareConfig, dry_run: bool) -> Result<Self, SanaluError> {
        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        if !config.api_token.is_empty() {
            let auth_val = format!("Bearer {}", config.api_token);
            if let Ok(mut val) = HeaderValue::from_str(&auth_val) {
                val.set_sensitive(true);
                headers.insert(AUTHORIZATION, val);
            }
        }

        let http_client = reqwest::Client::builder()
            .default_headers(headers)
            .timeout(Duration::from_secs(15))
            .build()
            .map_err(|e| SanaluError::Cloudflare(e.to_string()))?;

        Ok(Self {
            config,
            dry_run,
            http_client,
        })
    }

    pub fn is_configured(&self) -> bool {
        !self.config.api_token.is_empty() && !self.config.zone_id.is_empty()
    }

    pub async fn update_waf_rule(&self, expression: &str) -> Result<(), SanaluError> {
        if self.dry_run || !self.is_configured() {
            return Ok(());
        }

        let ruleset_id = match &self.config.ruleset_id {
            Some(id) if !id.is_empty() => id,
            _ => return Ok(()),
        };
        let rule_id = match &self.config.rule_id {
            Some(id) if !id.is_empty() => id,
            _ => return Ok(()),
        };

        let url = format!(
            "https://api.cloudflare.com/client/v4/zones/{}/rulesets/{}/rules/{}",
            self.config.zone_id, ruleset_id, rule_id
        );

        let body = json!({
            "action": self.config.action,
            "expression": expression,
            "description": format!("Managed by sanalu: {}", self.config.rule_name)
        });

        let resp = self
            .http_client
            .put(&url)
            .json(&body)
            .send()
            .await
            .map_err(|e| SanaluError::Cloudflare(e.to_string()))?;

        if !resp.status().is_success() {
            let err_text = resp.text().await.unwrap_or_default();
            return Err(SanaluError::Cloudflare(format!(
                "Cloudflare API error: {err_text}"
            )));
        }

        Ok(())
    }
}

pub struct CloudflareSyncWorker {
    client: CloudflareClient,
    store: Arc<RedbStore>,
    budget: CloudflareRuleBudget,
    batch_seconds: u64,
    rx: mpsc::Receiver<()>,
}

impl CloudflareSyncWorker {
    pub fn spawn(
        client: CloudflareClient,
        store: Arc<RedbStore>,
        budget: CloudflareRuleBudget,
        batch_seconds: u64,
    ) -> mpsc::Sender<()> {
        let (tx, rx) = mpsc::channel(100);
        let worker = Self {
            client,
            store,
            budget,
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

            if let Ok(banned_records) = self.store.list_active_bans() {
                let mut v4_ips = Vec::new();
                for r in banned_records {
                    let maybe_ip = r.ip.or_else(|| r.target.parse().ok());
                    if let Some(std::net::IpAddr::V4(v4)) = maybe_ip {
                        v4_ips.push(v4);
                    }
                }
                v4_ips.reverse();

                let (expr, _) = self.budget.render_expression(&v4_ips);
                let _ = self.client.update_waf_rule(&expr).await;
                let _ = self.store.set_cloudflare_state(&expr);
            }
        }
    }
}
