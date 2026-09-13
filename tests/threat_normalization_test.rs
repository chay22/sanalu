use sanalu::intelligence::{NormalizedUri, ThreatCategory, normalize_request_uri};
use std::borrow::Cow;

#[test]
fn test_threat_category_size_and_repr() {
    assert_eq!(std::mem::size_of::<ThreatCategory>(), 1);
    assert_eq!(ThreatCategory::Common as u8, 1);
    assert_eq!(ThreatCategory::Cloud as u8, 2);
    assert_eq!(ThreatCategory::Ssh as u8, 3);
    assert_eq!(ThreatCategory::Vcs as u8, 4);
    assert_eq!(ThreatCategory::Ide as u8, 5);
    assert_eq!(ThreatCategory::Wordpress as u8, 6);
    assert_eq!(ThreatCategory::Php as u8, 7);
    assert_eq!(ThreatCategory::Laravel as u8, 8);
    assert_eq!(ThreatCategory::Actuator as u8, 9);
    assert_eq!(ThreatCategory::Webmail as u8, 10);
    assert_eq!(ThreatCategory::Backups as u8, 11);
}

#[test]
fn test_threat_category_as_str() {
    assert_eq!(ThreatCategory::Common.as_str(), "common");
    assert_eq!(ThreatCategory::Cloud.as_str(), "cloud");
    assert_eq!(ThreatCategory::Ssh.as_str(), "ssh");
    assert_eq!(ThreatCategory::Vcs.as_str(), "vcs");
    assert_eq!(ThreatCategory::Ide.as_str(), "ide");
    assert_eq!(ThreatCategory::Wordpress.as_str(), "wordpress");
    assert_eq!(ThreatCategory::Php.as_str(), "php");
    assert_eq!(ThreatCategory::Laravel.as_str(), "laravel");
    assert_eq!(ThreatCategory::Actuator.as_str(), "actuator");
    assert_eq!(ThreatCategory::Webmail.as_str(), "webmail");
    assert_eq!(ThreatCategory::Backups.as_str(), "backups");
}

#[test]
fn test_threat_category_from_u8() {
    for i in 1..=11 {
        let cat = ThreatCategory::from_u8(i).expect("valid category u8");
        assert_eq!(cat as u8, i);
    }
    assert_eq!(ThreatCategory::from_u8(0), None);
    assert_eq!(ThreatCategory::from_u8(12), None);
    assert_eq!(ThreatCategory::from_u8(255), None);
}

#[test]
fn test_fast_path_clean_borrowed() {
    let clean_inputs = [
        "/",
        "/index.html",
        "/api/v1/users",
        "/static/css/main.css",
        "/blog/2026/09/release",
    ];

    for path in clean_inputs {
        let res = normalize_request_uri(path);
        match res {
            NormalizedUri::Clean(Cow::Borrowed(borrowed)) => {
                assert_eq!(borrowed, path);
            }
            _ => panic!("expected borrowed Clean for {}", path),
        }
    }
}

#[test]
fn test_immediate_malicious_detection() {
    let malicious_inputs = [
        "/path%00/test",
        "/path\0/test",
        "/login%0d%0ainjection",
        "/login%0D%0Aheader",
        "/admin%0dcmd",
        "/admin%0Dcmd",
        "/user%0ascript",
        "/user%0Ascript",
        "/%00",
        "\0",
        "%0d%0a",
    ];

    for path in malicious_inputs {
        let res = normalize_request_uri(path);
        assert_eq!(
            res,
            NormalizedUri::ImmediateMalicious(ThreatCategory::Common),
            "failed malicious detection on {}",
            path
        );
    }
}

#[test]
fn test_decoding_and_normalization() {
    let cases = [
        ("/test%2fpath", "/test/path"),
        ("/test%2Fpath", "/test/path"),
        ("/path%2e%2e/secret", "/path../secret"),
        ("/path%2E%2E/secret", "/path../secret"),
        ("/win%5cpath", "/win/path"),
        ("/win%5Cpath", "/win/path"),
        ("/win\\back\\slash", "/win/back/slash"),
        ("//double//slash//", "/double/slash/"),
        ("///triple///slash", "/triple/slash"),
        ("/mixed%2f//%5c\\slashes", "/mixed/slashes"),
        ("/%2e%2e/%2f.env", "/../.env"),
    ];

    for (input, expected) in cases {
        let res = normalize_request_uri(input);
        match res {
            NormalizedUri::Clean(Cow::Owned(owned)) => {
                assert_eq!(owned, expected, "input: {}", input);
            }
            NormalizedUri::Clean(Cow::Borrowed(borrowed)) => {
                assert_eq!(borrowed, expected, "input: {}", input);
            }
            NormalizedUri::ImmediateMalicious(_) => {
                panic!("unexpected ImmediateMalicious for {}", input);
            }
        }
    }
}

#[test]
fn test_malicious_after_decoding() {
    let cases = ["/bypass/%2e%2e/%00/file", "/bypass//%0d%0a//header"];

    for path in cases {
        let res = normalize_request_uri(path);
        assert_eq!(
            res,
            NormalizedUri::ImmediateMalicious(ThreatCategory::Common),
            "failed detection for decoded malicious: {}",
            path
        );
    }
}
