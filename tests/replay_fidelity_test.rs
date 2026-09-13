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

#[test]
fn test_replay_fidelity_ubuntu22_reference_logs() {
    let mut temp = tempfile::NamedTempFile::new().unwrap();

    writeln!(
        temp,
        r#"45.194.92.67 - - [09/Sep/2026:00:09:05 +0700] "GET / HTTP/1.1" 302 138 "http://46.250.231.252:80/" "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36""#
    ).unwrap();
    writeln!(
        temp,
        r#"47.250.114.23 - - [09/Sep/2026:02:41:37 +0700] "GET / HTTP/1.1" 302 138 "-" "curl/7.74.0""#
    ).unwrap();

    let clean_threats = replay_log_file(temp.path(), &[]).unwrap();
    assert_eq!(clean_threats, 0);

    writeln!(
        temp,
        r#"20.151.10.161 - - [09/Sep/2026:03:45:59 +0700] "GET /f35.update.php HTTP/1.1" 404 142 "-" "-""#
    ).unwrap();

    let one_threat = replay_log_file(temp.path(), &[]).unwrap();
    assert_eq!(one_threat, 1);

    writeln!(
        temp,
        r#"16.5.0.236 - - [09/Sep/2026:00:50:18 +0700] "POST /boaform/admin/formLogin HTTP/1.1" 404 142 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/115.0""#
    ).unwrap();

    let two_threats = replay_log_file(temp.path(), &[]).unwrap();
    assert_eq!(two_threats, 2);
}
