use sanalu::parser::{
    CompiledLogFormat, LogVariable, parse_nginx_combined_line, parse_nginx_error_line,
    parse_nginx_json_line,
};
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

#[test]
fn test_compiled_cloudflare_format_parsing() {
    let fmt_str = "$http_cf_connecting_ip - $remote_user [$time_local] \"$request\" $status $body_bytes_sent \"$http_referer\" \"$http_user_agent\"";
    let compiled = CompiledLogFormat::compile(fmt_str);

    let line = "198.51.100.25 - user [12/Sep/2026:06:00:00 +0000] \"GET /admin/db.sql HTTP/1.1\" 404 512 \"https://google.com\" \"Mozilla/5.0\"";
    let entry = compiled.parse_line(line).expect("parse custom line");

    assert_eq!(entry.client_ip, "198.51.100.25".parse::<IpAddr>().unwrap());
    assert_eq!(entry.method, "GET");
    assert_eq!(entry.path, "/admin/db.sql");
    assert_eq!(entry.status, 404);
    assert_eq!(entry.referer, "https://google.com");
    assert_eq!(entry.user_agent, "Mozilla/5.0");
}

#[test]
fn test_compiled_vhost_prefixed_format() {
    let fmt_str = "$host $remote_addr [$time_local] $request_method $request_uri $status";
    let compiled = CompiledLogFormat::compile(fmt_str);

    let line = "api.example.com 203.0.113.88 [12/Sep/2026:06:00:00 +0000] POST /.env 403";
    let entry = compiled.parse_line(line).expect("parse vhost line");

    assert_eq!(entry.client_ip, "203.0.113.88".parse::<IpAddr>().unwrap());
    assert_eq!(entry.host, Some("api.example.com"));
    assert_eq!(entry.method, "POST");
    assert_eq!(entry.path, "/.env");
    assert_eq!(entry.status, 403);
}

#[test]
fn test_compiled_xff_first_public_ip() {
    let fmt_str = "[$time_local] \"$request\" $status \"$http_x_forwarded_for\"";
    let compiled = CompiledLogFormat::compile(fmt_str);

    let line = "[12/Sep/2026:06:00:00 +0000] \"GET /index.html HTTP/1.1\" 200 \"10.0.0.1, 198.51.100.42, 172.16.0.5\"";
    let entry = compiled.parse_line(line).expect("parse xff line");

    assert_eq!(entry.client_ip, "198.51.100.42".parse::<IpAddr>().unwrap());
    assert_eq!(entry.status, 200);
}

#[test]
fn test_compiled_json_format_parsing() {
    let fmt_str = "{\n  \"client\": \"$remote_addr\",\n  \"status\": $status\n}";
    let compiled = CompiledLogFormat::compile(fmt_str);
    assert_eq!(compiled, CompiledLogFormat::Json);

    let line = r#"{"client": "203.0.113.55", "method": "GET", "uri": "/api", "status": 200}"#;
    let entry = compiled.parse_line(line).expect("parse json line");
    assert_eq!(entry.client_ip, "203.0.113.55".parse::<IpAddr>().unwrap());
    assert_eq!(entry.method, "GET");
    assert_eq!(entry.path, "/api");
    assert_eq!(entry.status, 200);
}

#[test]
fn test_compiled_mismatched_and_corrupt_lines() {
    let fmt_str = "$host $remote_addr [$time_local] $request_method $request_uri $status";
    let compiled = CompiledLogFormat::compile(fmt_str);

    let corrupt = "\x00\x01\x02 random garbage without spaces";
    assert!(compiled.parse_line(corrupt).is_none());

    let missing_fields = "api.example.com 203.0.113.88";
    assert!(compiled.parse_line(missing_fields).is_none());
}

#[test]
fn test_compiled_ip_priority_cf_over_all() {
    let fmt_str = "$http_cf_connecting_ip $http_x_forwarded_for $remote_addr [$time_local] \"$request\" $status";
    let compiled = CompiledLogFormat::compile(fmt_str);

    let line =
        "198.51.100.99 198.51.100.50 127.0.0.1 [12/Sep/2026:06:00:00 +0000] \"GET / HTTP/1.1\" 200";
    let entry = compiled.parse_line(line).expect("parse line");
    assert_eq!(entry.client_ip, "198.51.100.99".parse::<IpAddr>().unwrap());
}

#[test]
fn test_discovered_log_to_compiled() {
    use sanalu::discovery::nginx::{DiscoveredNginxLog, NginxLogFormatKind};
    use std::path::PathBuf;

    assert_eq!(
        NginxLogFormatKind::Json.to_compiled(),
        CompiledLogFormat::Json
    );
    let combined = NginxLogFormatKind::Combined.to_compiled();
    assert!(matches!(combined, CompiledLogFormat::Delimited(_)));

    let discovered = DiscoveredNginxLog {
        path: PathBuf::from("/var/log/nginx/access.log"),
        format_kind: NginxLogFormatKind::Combined,
    };
    assert_eq!(discovered.to_compiled(), combined);
}

#[test]
fn test_compiled_segments_structure() {
    let fmt_str = "$remote_addr [$time_local]";
    let compiled = CompiledLogFormat::compile(fmt_str);
    match compiled {
        CompiledLogFormat::Delimited(segments) => {
            assert_eq!(
                segments[0],
                sanalu::parser::FormatSegment::Variable(LogVariable::RemoteAddr)
            );
            assert_eq!(
                segments[1],
                sanalu::parser::FormatSegment::Literal(" [".to_string())
            );
            assert_eq!(
                segments[2],
                sanalu::parser::FormatSegment::Variable(LogVariable::TimeLocal)
            );
            assert_eq!(
                segments[3],
                sanalu::parser::FormatSegment::Literal("]".to_string())
            );
        }
        CompiledLogFormat::Json => panic!("expected delimited"),
    }
}
