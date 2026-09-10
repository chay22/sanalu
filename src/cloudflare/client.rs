use crate::config::CloudflareConfig;
use crate::error::SanaluError;
use reqwest::header::{AUTHORIZATION, CONTENT_TYPE, HeaderMap, HeaderValue};
use serde_json::json;
use std::time::Duration;

pub fn parse_cf_error(status: u16, body_text: &str) -> SanaluError {
    if let Ok(v) = serde_json::from_str::<serde_json::Value>(body_text) {
        if let Some(errors) = v.get("errors").and_then(|e| e.as_array()) {
            if !errors.is_empty() {
                let msgs: Vec<String> = errors
                    .iter()
                    .map(|e| {
                        let code = e.get("code").and_then(|c| c.as_i64()).unwrap_or(0);
                        let msg = e
                            .get("message")
                            .and_then(|m| m.as_str())
                            .unwrap_or("unknown error");
                        format!("[{code}]: {msg}")
                    })
                    .collect();
                if !msgs.is_empty() {
                    return SanaluError::Cloudflare(format!(
                        "Cloudflare API error {}",
                        msgs.join(", ")
                    ));
                }
            }
        }
    }
    SanaluError::Cloudflare(format!("Cloudflare API error (HTTP {status}): {body_text}"))
}

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

    fn find_sanalu_rule_id(&self, rules: &[serde_json::Value]) -> Option<String> {
        for rule in rules {
            let desc = rule
                .get("description")
                .and_then(|d| d.as_str())
                .unwrap_or("")
                .to_lowercase();
            if desc.contains("sanalu") {
                if let Some(id) = rule.get("id").and_then(|i| i.as_str()) {
                    return Some(id.to_string());
                }
            }
        }
        None
    }

    async fn patch_rule(
        &self,
        ruleset_id: &str,
        rule_id: &str,
        expression: &str,
    ) -> Result<(), SanaluError> {
        let url = format!(
            "https://api.cloudflare.com/client/v4/zones/{}/rulesets/{}/rules/{}",
            self.config.zone_id, ruleset_id, rule_id
        );
        let body = json!({
            "action": self.config.action,
            "expression": expression,
            "description": format!("Managed by sanalu: {}", self.config.rule_name),
            "enabled": true
        });
        let resp = self
            .http_client
            .patch(&url)
            .json(&body)
            .send()
            .await
            .map_err(|e| SanaluError::Cloudflare(e.to_string()))?;

        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let err_text = resp.text().await.unwrap_or_default();
            return Err(parse_cf_error(status, &err_text));
        }
        Ok(())
    }

    async fn create_rule(&self, ruleset_id: &str, expression: &str) -> Result<(), SanaluError> {
        let url = format!(
            "https://api.cloudflare.com/client/v4/zones/{}/rulesets/{}/rules",
            self.config.zone_id, ruleset_id
        );
        let body = json!({
            "action": self.config.action,
            "expression": expression,
            "description": format!("Managed by sanalu: {}", self.config.rule_name),
            "enabled": true
        });
        let resp = self
            .http_client
            .post(&url)
            .json(&body)
            .send()
            .await
            .map_err(|e| SanaluError::Cloudflare(e.to_string()))?;

        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let err_text = resp.text().await.unwrap_or_default();
            return Err(parse_cf_error(status, &err_text));
        }
        Ok(())
    }

    async fn create_entrypoint_ruleset(&self, expression: &str) -> Result<(), SanaluError> {
        let url = format!(
            "https://api.cloudflare.com/client/v4/zones/{}/rulesets",
            self.config.zone_id
        );
        let body = json!({
            "name": "default",
            "kind": "zone",
            "phase": "http_request_firewall_custom",
            "rules": [
                {
                    "action": self.config.action,
                    "expression": expression,
                    "description": format!("Managed by sanalu: {}", self.config.rule_name),
                    "enabled": true
                }
            ]
        });
        let resp = self
            .http_client
            .post(&url)
            .json(&body)
            .send()
            .await
            .map_err(|e| SanaluError::Cloudflare(e.to_string()))?;

        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let err_text = resp.text().await.unwrap_or_default();
            return Err(parse_cf_error(status, &err_text));
        }
        Ok(())
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
            return self.patch_rule(rs_id, r_id, expression).await;
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

            if let Some(rule_id) = self.find_sanalu_rule_id(rules) {
                return self.patch_rule(rs_id, &rule_id, expression).await;
            }
            return self.create_rule(rs_id, expression).await;
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
            return self.create_entrypoint_ruleset(expression).await;
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

        if let Some(rule_id) = self.find_sanalu_rule_id(rules) {
            self.patch_rule(ruleset_id, &rule_id, expression).await
        } else {
            self.create_rule(ruleset_id, expression).await
        }
    }
}
