use super::ruleset::{create_entrypoint_ruleset, create_rule, find_sanalu_rule_id, patch_rule};
use crate::config::CloudflareConfig;
use crate::error::SanaluError;
use reqwest::header::{AUTHORIZATION, CONTENT_TYPE, HeaderMap, HeaderValue};
use std::time::Duration;

pub use super::ruleset::parse_cf_error;

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

        let explicit_ruleset = self.config.ruleset_id.as_deref().filter(|s| !s.is_empty());
        let explicit_rule = self.config.rule_id.as_deref().filter(|s| !s.is_empty());

        if explicit_rule.is_some() && explicit_ruleset.is_none() {
            return Err(SanaluError::Cloudflare(
                "ruleset_id is required when rule_id is configured".into(),
            ));
        }

        if let (Some(rs_id), Some(r_id)) = (explicit_ruleset, explicit_rule) {
            return patch_rule(&self.http_client, &self.config, rs_id, r_id, expression).await;
        }

        if let Some(rs_id) = explicit_ruleset {
            let url = format!(
                "https://api.cloudflare.com/client/v4/zones/{}/rulesets/{}",
                self.config.zone_id, rs_id
            );
            let resp = self
                .http_client
                .get(&url)
                .send()
                .await
                .map_err(|e| SanaluError::Cloudflare(e.to_string()))?;

            if !resp.status().is_success() {
                let status = resp.status().as_u16();
                let err_text = resp.text().await.unwrap_or_default();
                return Err(parse_cf_error(status, &err_text));
            }
            let data: serde_json::Value = resp
                .json()
                .await
                .map_err(|e| SanaluError::Cloudflare(e.to_string()))?;
            let empty_rules = Vec::new();
            let rules = data
                .get("result")
                .and_then(|r| r.get("rules"))
                .and_then(|r| r.as_array())
                .unwrap_or(&empty_rules);

            if let Some(rule_id) = find_sanalu_rule_id(rules) {
                return patch_rule(&self.http_client, &self.config, rs_id, &rule_id, expression)
                    .await;
            }
            return create_rule(&self.http_client, &self.config, rs_id, expression).await;
        }

        let entrypoint_url = format!(
            "https://api.cloudflare.com/client/v4/zones/{}/rulesets/phases/http_request_firewall_custom/entrypoint",
            self.config.zone_id
        );
        let resp = self
            .http_client
            .get(&entrypoint_url)
            .send()
            .await
            .map_err(|e| SanaluError::Cloudflare(e.to_string()))?;

        if resp.status().as_u16() == 404 {
            return create_entrypoint_ruleset(&self.http_client, &self.config, expression).await;
        }

        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let err_text = resp.text().await.unwrap_or_default();
            return Err(parse_cf_error(status, &err_text));
        }

        let data: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| SanaluError::Cloudflare(e.to_string()))?;
        let ruleset_id = data
            .get("result")
            .and_then(|r| r.get("id"))
            .and_then(|i| i.as_str())
            .ok_or_else(|| {
                SanaluError::Cloudflare("Cloudflare entrypoint ruleset id missing".into())
            })?;
        let empty_rules = Vec::new();
        let rules = data
            .get("result")
            .and_then(|r| r.get("rules"))
            .and_then(|r| r.as_array())
            .unwrap_or(&empty_rules);

        if let Some(rule_id) = find_sanalu_rule_id(rules) {
            patch_rule(
                &self.http_client,
                &self.config,
                ruleset_id,
                &rule_id,
                expression,
            )
            .await
        } else {
            create_rule(&self.http_client, &self.config, ruleset_id, expression).await
        }
    }
}
