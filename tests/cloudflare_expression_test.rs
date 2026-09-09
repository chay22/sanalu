use sanalu::cloudflare::CloudflareRuleBudget;
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
