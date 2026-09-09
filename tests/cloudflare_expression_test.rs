use sanalu::cloudflare::{parse_cf_error, CloudflareClient, CloudflareRuleBudget};
use sanalu::config::CloudflareConfig;
use std::net::Ipv4Addr;

#[test]
fn test_cloudflare_expression_with_regional_asns() {
    let budget = CloudflareRuleBudget::new(
        4000,
        vec![400529, 48090],
        vec![15169, 16509],
        vec!["ID".into(), "US".into()],
    );

    let (expr, included) = budget.render_expression(&["1.2.3.4".parse().unwrap()]);
    assert!(expr.contains("ip.src.asnum in {400529 48090}"));
    assert!(
        expr.contains("ip.src.asnum in {15169 16509} and not ip.src.country in {\"ID\" \"US\"}")
    );
    assert!(expr.contains("ip.src in {1.2.3.4}"));
    assert!(expr.len() <= 4000);
    assert_eq!(included.len(), 1);
}

#[test]
fn test_cloudflare_expression_budget_cap_and_lru_rotation() {
    let budget = CloudflareRuleBudget::new(100, vec![], vec![], vec![]);

    let ips: Vec<Ipv4Addr> = (1..=30)
        .map(|i| format!("192.0.2.{i}").parse().unwrap())
        .collect();

    let (expr, included) = budget.render_expression(&ips);
    assert!(expr.len() <= 100);
    assert!(included.len() < ips.len());
    assert!(!included.is_empty());
    assert_eq!(included[0], ips[0]);
}

#[test]
fn test_cloudflare_expression_empty_budget() {
    let budget = CloudflareRuleBudget::new(4000, vec![], vec![], vec![]);
    let (expr, included) = budget.render_expression(&[]);
    assert_eq!(expr, "");
    assert!(included.is_empty());
}

#[test]
fn test_parse_cf_error_structured() {
    let json_err =
        r#"{"success":false,"errors":[{"code":9106,"message":"Authentication failed"}],"messages":[],"result":null}"#;
    let err = parse_cf_error(400, json_err);
    let msg = err.to_string();
    assert!(msg.contains("Cloudflare API error [9106]: Authentication failed"));
}

#[test]
fn test_parse_cf_error_method_not_allowed() {
    let json_err =
        r#"{"success":false,"errors":[{"code":10405,"message":"Method not allowed for this authentication scheme"}]}"#;
    let err = parse_cf_error(405, json_err);
    let msg = err.to_string();
    assert!(msg.contains("Cloudflare API error [10405]: Method not allowed"));
}

#[test]
fn test_parse_cf_error_fallback() {
    let raw = "502 Bad Gateway";
    let err = parse_cf_error(502, raw);
    let msg = err.to_string();
    assert!(msg.contains("Cloudflare API error (HTTP 502): 502 Bad Gateway"));
}

#[tokio::test]
async fn test_cf_client_inconsistent_rule_id_without_ruleset_id() {
    let config = CloudflareConfig {
        enabled: true,
        api_token: "token123".into(),
        zone_id: "zone123".into(),
        rule_id: Some("rule123".into()),
        ruleset_id: None,
        ..Default::default()
    };

    let client = CloudflareClient::new(config, false).unwrap();
    let res = client.update_waf_rule("ip.src == 1.2.3.4").await;
    assert!(res.is_err());
    let err_msg = res.err().unwrap().to_string();
    assert!(err_msg.contains("ruleset_id is required when rule_id is configured"));
}

#[tokio::test]
async fn test_cf_client_dry_run_bypasses_network() {
    let config = CloudflareConfig {
        enabled: true,
        api_token: "token123".into(),
        zone_id: "zone123".into(),
        ..Default::default()
    };

    let client = CloudflareClient::new(config, true).unwrap();
    let res = client.update_waf_rule("ip.src == 1.2.3.4").await;
    assert!(res.is_ok());
}
