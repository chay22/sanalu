use sanalu::engine::replay_log_file;
use std::io::Write;

#[test]
fn test_replay_fidelity_nginx_probe_and_clean_traffic() {
    let mut temp = tempfile::NamedTempFile::new().unwrap();

    writeln!(
        temp,
        r#"198.51.100.1 - - [10/Oct/2026:13:55:36 +0000] "GET /index.html HTTP/1.1" 200 2326 "-" "Mozilla/5.0""#
    ).unwrap();

    writeln!(
        temp,
        r#"198.51.100.2 - - [10/Oct/2026:13:55:36 +0000] "GET /wp-login.php HTTP/1.1" 404 162 "-" "Mozilla/5.0""#
    ).unwrap();
    writeln!(
        temp,
        r#"198.51.100.2 - - [10/Oct/2026:13:55:37 +0000] "GET /wp-login.php HTTP/1.1" 404 162 "-" "Mozilla/5.0""#
    ).unwrap();
    writeln!(
        temp,
        r#"198.51.100.2 - - [10/Oct/2026:13:55:38 +0000] "GET /wp-login.php HTTP/1.1" 404 162 "-" "Mozilla/5.0""#
    ).unwrap();
    writeln!(
        temp,
        r#"198.51.100.2 - - [10/Oct/2026:13:55:39 +0000] "GET /wp-login.php HTTP/1.1" 404 162 "-" "Mozilla/5.0""#
    ).unwrap();

    let threats = replay_log_file(temp.path(), &[]).unwrap();
    assert_eq!(threats, 1);
}

#[test]
fn test_replay_fidelity_ssh_evaluation() {
    let mut temp = tempfile::NamedTempFile::new().unwrap();

    writeln!(
        temp,
        "Oct 10 13:55:36 server sshd[1234]: Did not receive identification string from 198.51.100.99 port 54321"
    ).unwrap();

    for _ in 0..4 {
        writeln!(
            temp,
            "Oct 10 13:55:36 server sshd[1234]: Failed password for invalid user admin from 198.51.100.50 port 54321 ssh2"
        ).unwrap();
    }

    let threats_under = replay_log_file(temp.path(), &[]).unwrap();
    assert_eq!(threats_under, 1);

    writeln!(
        temp,
        "Oct 10 13:55:37 server sshd[1234]: Failed password for invalid user admin from 198.51.100.50 port 54321 ssh2"
    ).unwrap();

    let threats_threshold = replay_log_file(temp.path(), &[]).unwrap();
    assert_eq!(threats_threshold, 2);
}
