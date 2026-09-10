use crate::config::CloudflareConfig;
use crate::error::SanaluError;
use serde_json::json;

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

pub fn find_sanalu_rule_id(rules: &[serde_json::Value]) -> Option<String> {
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

pub async fn patch_rule(
    client: &reqwest::Client,
    config: &CloudflareConfig,
    ruleset_id: &str,
    rule_id: &str,
    expression: &str,
) -> Result<(), SanaluError> {
    let url = format!(
        "https://api.cloudflare.com/client/v4/zones/{}/rulesets/{}/rules/{}",
        config.zone_id, ruleset_id, rule_id
    );
    let body = json!({
        "action": config.action,
        "expression": expression,
        "description": format!("Managed by sanalu: {}", config.rule_name),
        "enabled": true
    });
    let resp = client
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

pub async fn create_rule(
    client: &reqwest::Client,
    config: &CloudflareConfig,
    ruleset_id: &str,
    expression: &str,
) -> Result<(), SanaluError> {
    let url = format!(
        "https://api.cloudflare.com/client/v4/zones/{}/rulesets/{}/rules",
        config.zone_id, ruleset_id
    );
    let body = json!({
        "action": config.action,
        "expression": expression,
        "description": format!("Managed by sanalu: {}", config.rule_name),
        "enabled": true
    });
    let resp = client
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

pub async fn create_entrypoint_ruleset(
    client: &reqwest::Client,
    config: &CloudflareConfig,
    expression: &str,
) -> Result<(), SanaluError> {
    let url = format!(
        "https://api.cloudflare.com/client/v4/zones/{}/rulesets",
        config.zone_id
    );
    let body = json!({
        "name": "default",
        "kind": "zone",
        "phase": "http_request_firewall_custom",
        "rules": [
            {
                "action": config.action,
                "expression": expression,
                "description": format!("Managed by sanalu: {}", config.rule_name),
                "enabled": true
            }
        ]
    });
    let resp = client
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
