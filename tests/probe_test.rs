use sanalu::intelligence::{ProbeMatcher, ProbeResult};

#[test]
fn test_allowed_endpoints_regex() {
    let patterns = vec![
        "^/api/.*".into(),
        "^/health$".into(),
        "^/webhooks/.*".into(),
    ];
    let matcher = ProbeMatcher::new(&patterns).unwrap();

    assert_eq!(matcher.inspect("/health"), ProbeResult::AllowedEndpoint);
    assert_eq!(
        matcher.inspect("/api/v1/status"),
        ProbeResult::AllowedEndpoint
    );
    assert!(matches!(
        matcher.inspect("/.env"),
        ProbeResult::HarmfulPattern(".env")
    ));
    assert!(matches!(
        matcher.inspect("/wp-admin/"),
        ProbeResult::HarmfulPattern("/wp-")
    ));
    assert!(matches!(
        matcher.inspect("/db_backup.sql"),
        ProbeResult::HarmfulPattern(".sql")
    ));
    assert_eq!(matcher.inspect("/dashboard"), ProbeResult::Clean);
}

#[test]
fn test_traversal_and_injection_probes() {
    let matcher = ProbeMatcher::new(&[]).unwrap();

    assert!(matches!(
        matcher.inspect("/static/../../etc/passwd"),
        ProbeResult::HarmfulPattern("../") | ProbeResult::HarmfulPattern("etc/passwd")
    ));
    assert!(matches!(
        matcher.inspect("/images/%2e%2e/secret"),
        ProbeResult::HarmfulPattern("%2e%2e")
    ));
    assert!(matches!(
        matcher.inspect("/item/%00.png"),
        ProbeResult::HarmfulPattern("/%00")
    ));
    assert!(matches!(
        matcher.inspect("/adminer.php"),
        ProbeResult::HarmfulPattern("/adminer")
    ));
    assert!(matches!(
        matcher.inspect("/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php"),
        ProbeResult::HarmfulPattern("phpunit") | ProbeResult::HarmfulPattern("eval-stdin")
    ));
    assert!(matches!(
        matcher.inspect("/actuator/env"),
        ProbeResult::HarmfulPattern("/actuator")
    ));
}
