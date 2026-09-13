use sanalu::intelligence::{IpStrikeTracker, StrikeResult, ThreatCategory};
use sanalu::parser::{SshStatefulParser, parse_nginx_error_line, parse_ssh_log_line};
use std::net::IpAddr;
use std::sync::Arc;
use std::thread;

#[test]
fn test_strike_tracker_lock_poisoning_recovery() {
    let tracker = Arc::new(IpStrikeTracker::new());
    let ip: IpAddr = "192.168.1.10".parse().unwrap();
    let tracker_clone = Arc::clone(&tracker);

    let handle = thread::spawn(move || {
        let lock = tracker_clone.shard_lock_for_test(&ip);
        let _guard = lock.write().unwrap();
        panic!("simulated worker thread panic");
    });
    let _ = handle.join();

    let res = tracker.record_shared_strike(ip, 3, 60, 1000);
    assert_eq!(res, StrikeResult::UnderThreshold { current: 1, max: 3 });

    let rec = tracker.get_record(&ip);
    assert!(rec.is_some());
    assert_eq!(rec.unwrap().critical_strikes, 1);

    let iso_res = tracker.record_isolated_strike(ip, ThreatCategory::Wordpress, 3, 60, 1001);
    assert_eq!(iso_res, StrikeResult::UnderThreshold { current: 1, max: 3 });

    tracker.cleanup_stale(1002, 600);
    tracker.clear_ip(&ip);
    assert!(tracker.is_empty());
    assert_eq!(tracker.len(), 0);
}

#[test]
fn test_ssh_parsers_resilience_to_malformed_and_binary_data() {
    let mut parser = SshStatefulParser::new();

    let malicious_cases = [
        "",
        "   ",
        "\t\r\n",
        "sshd[",
        "sshd[]",
        "sshd[abc]",
        "sshd[429496729500000000000000]",
        "sshd[-1]",
        "banner exchange: Connection from ",
        "banner exchange: Connection from \x00\x01\x02",
        "banner exchange: Connection from 999.999.999.999",
        "banner exchange: Connection from [::ffff:192.0.2.1]",
        "Did not receive identification string from ",
        "Did not receive identification string from 999.999.999.999",
        "Failed password for ",
        "Failed password for invalid user ",
        "Failed password for invalid user root from ",
        "Failed password for invalid user root from 999.999.999.999",
        "Invalid user ",
        "Invalid user test from ",
        "Invalid user test from not_an_ip",
        "kex_exchange_identification: client sent invalid protocol identifier",
        "banner line contains invalid characters",
    ];

    for case in malicious_cases {
        let _ = parse_ssh_log_line(case);
        let _ = parser.process_line(case);
    }

    let byte_cases: &[&[u8]] = &[
        b"sshd[\x80]",
        b"sshd[\xff\xfe\xfd]",
        b"banner exchange: Connection from \x80\x81\x82",
        b"Did not receive identification string from \x80\x81",
        b"Failed password for \x80 from \x81",
        b"Invalid user \x80 from \x81",
        b"kex_exchange_identification: Connection from \x80",
        b"\x00\xff\xfe\xfd\x80\x81\x82",
        b"sshd[1234] \x80\x81\x82 from 1.2.3.4",
        b"sshd[1234] Connection from \x80\x81\x82",
    ];

    for bytes in byte_cases {
        let lossy = String::from_utf8_lossy(bytes);
        let _ = parse_ssh_log_line(&lossy);
        let _ = parser.process_line(&lossy);
    }
}

#[test]
fn test_nginx_error_parser_resilience() {
    let cases = [
        "",
        "   ",
        ", client: ",
        ", client: 999.999.999.999",
        ", client: [not_an_ip]",
        "[error]",
        "[error]: ",
        "[error]: *",
        "[error]: *1 ",
        "[error]: *1 , client: ",
        "[error]: *1 , client: 127.0.0.1",
        "[error]: *1 broken pipe, client: 127.0.0.1",
        "2026/09/14 00:00:00 [error] 123#456: *1 test error, client: 192.168.1.1, server: example.com",
        "client: 1.1.1.1 [error]",
        ", client: 1.1.1.1 [error] 123: *456 something",
    ];

    for case in cases {
        let _ = parse_nginx_error_line(case);
    }

    let byte_cases: &[&[u8]] = &[
        b", client: \x80\x81",
        b"[error]\x80\x81, client: 127.0.0.1",
        b"[error]: \x80\x81, client: 127.0.0.1",
        b"[error]: *\x80\x81 , client: 127.0.0.1",
        b"[error]: *1 \x80\x81, client: 127.0.0.1",
        b"\xff\xfe\xfd, client: 127.0.0.1",
        b"[error] \xff\xfe: *1 test\x80\x81, client: 1.2.3.4",
    ];

    for bytes in byte_cases {
        let lossy = String::from_utf8_lossy(bytes);
        let _ = parse_nginx_error_line(&lossy);
    }
}

#[test]
fn test_parser_fuzzing_adversarial_patterns() {
    let mut parser = SshStatefulParser::new();
    let seed_fragments = [
        "sshd[",
        "]",
        "123",
        "45678",
        "Failed password for ",
        "invalid user ",
        "root",
        "admin",
        " from ",
        "127.0.0.1",
        "::1",
        "2001:db8::1",
        "banner exchange: Connection from ",
        "Did not receive identification string from ",
        "kex_exchange_identification: ",
        ", client: ",
        "[error]: ",
        "*1 ",
        " ",
        "\t",
        "\n",
        "\0",
        "\u{1F980}",
        "\u{26A1}",
        "\u{4E2D}",
        "\u{65E5}",
        "\u{FFFD}",
    ];

    let mut rng: u64 = 0xdeadbeefcafebabe;
    let mut next_rand = || {
        rng = rng.wrapping_mul(6364136223846793005).wrapping_add(1);
        rng
    };

    for _ in 0..2000 {
        let mut line = String::new();
        let count = (next_rand() % 8) as usize;
        for _ in 0..count {
            let idx = (next_rand() as usize) % seed_fragments.len();
            line.push_str(seed_fragments[idx]);
        }
        let _ = parse_ssh_log_line(&line);
        let _ = parser.process_line(&line);
        let _ = parse_nginx_error_line(&line);
    }
}
