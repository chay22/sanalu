use sanalu::parser::{parse_nginx_combined_line, parse_nginx_error_line, parse_nginx_json_line};
use std::net::IpAddr;

#[test]
fn test_parse_real_nginx_access_log() {
    let line = "45.194.92.67 - - [09/Sep/2026:00:09:05 +0700] \"GET / HTTP/1.1\" 302 138 \"http://46.250.231.252:80/\" \"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36\"";
    let entry = parse_nginx_combined_line(line).expect("must parse valid line");
    assert_eq!(entry.client_ip, "45.194.92.67".parse::<IpAddr>().unwrap());
    assert_eq!(entry.method, "GET");
    assert_eq!(entry.path, "/");
    assert_eq!(entry.status, 302);
    assert_eq!(
        entry.user_agent,
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"
    );
}

#[test]
fn test_parse_nginx_json_format() {
    let json_line = r#"{"client": "203.0.113.19", "method": "POST", "uri": "/.env", "status": 404, "ua": "curl/7.68.0"}"#;
    let (ip, method, uri, status, _, ua) = parse_nginx_json_line(json_line).expect("parse json");
    assert_eq!(ip, "203.0.113.19".parse::<IpAddr>().unwrap());
    assert_eq!(method, "POST");
    assert_eq!(uri, "/.env");
    assert_eq!(status, 404);
    assert_eq!(ua, "curl/7.68.0");
}

#[test]
fn test_parse_real_nginx_error_forbidden_index() {
    let line = "2026/09/08 07:32:39 [error] 2806333#2806333: *223382 directory index of \"/var/www/\" is forbidden, client: 172.93.212.236, server: investfund.biz.id, request: \"GET /js/ HTTP/1.1\"";
    let (ip, reason) = parse_nginx_error_line(line).expect("must parse error line");
    assert_eq!(ip, "172.93.212.236".parse::<IpAddr>().unwrap());
    assert!(reason.contains("forbidden"));
}

#[test]
fn test_parse_corrupted_binary_line() {
    let binary_bytes = b"\x16\x03\x01\x00\xee\x01\x00\x00\xea\x03\x03\x82\x90";
    let binary_garbage = String::from_utf8_lossy(binary_bytes);
    assert!(parse_nginx_combined_line(&binary_garbage).is_none());
    assert!(parse_nginx_json_line(&binary_garbage).is_none());
    assert!(parse_nginx_error_line(&binary_garbage).is_none());
}
