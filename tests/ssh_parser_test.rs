use sanalu::parser::{SshEvent, SshStatefulParser, parse_ssh_log_line};
use std::net::IpAddr;

#[test]
fn test_parse_real_ssh_scanner_and_auth_lines() {
    let probe1 = "Sep  6 09:26:17 vmi1529040 sshd[2698855]: banner exchange: Connection from 44.220.188.23 port 47242: invalid format";
    assert_eq!(
        parse_ssh_log_line(probe1),
        SshEvent::ScannerProbe {
            ip: "44.220.188.23".parse().unwrap(),
            reason: "banner_invalid_format"
        }
    );

    let probe2 = "Sep  6 09:26:18 vmi1529040 sshd[2698856]: error: kex_exchange_identification: Connection from 44.220.188.23 port 47250: client sent invalid protocol identifier \"GET / HTTP/1.1\"";
    assert_eq!(
        parse_ssh_log_line(probe2),
        SshEvent::ScannerProbe {
            ip: "44.220.188.23".parse().unwrap(),
            reason: "invalid_protocol_identifier"
        }
    );

    let failed = "Sep  6 10:00:01 vmi1529040 sshd[2699999]: Failed password for invalid user admin from 192.0.2.1 port 55555 ssh2";
    assert_eq!(
        parse_ssh_log_line(failed),
        SshEvent::AuthFailure {
            ip: "192.0.2.1".parse().unwrap(),
            user: "admin".into()
        }
    );
}

#[test]
fn test_stateful_ssh_paired_lines() {
    let mut parser = SshStatefulParser::new();

    let line1 = "Sep  6 11:33:24 vmi1529040 sshd[2703646]: error: kex_exchange_identification: client sent invalid protocol identifier \"GET /squid-internal-mgr/cachemgr.cgi HTTP/1.1\"";
    let event1 = parser.process_line(line1);
    assert_eq!(event1, SshEvent::Ignore);

    let line2 = "Sep  6 11:33:24 vmi1529040 sshd[2703646]: banner exchange: Connection from 138.68.92.235 port 41478: invalid format";
    let event2 = parser.process_line(line2);
    assert_eq!(
        event2,
        SshEvent::ScannerProbe {
            ip: "138.68.92.235".parse::<IpAddr>().unwrap(),
            reason: "invalid_protocol_identifier"
        }
    );
}
