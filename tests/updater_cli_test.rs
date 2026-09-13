use clap::Parser;
use sanalu::cli::{Cli, Commands};
use sanalu::updater::execute_update_with_base_url;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::thread;

#[test]
fn test_cli_parse_update_command() {
    let base = vec!["sanalu", "update"];
    let cli = Cli::try_parse_from(base).expect("parse base update");
    match cli.command {
        Commands::Update { check, yes } => {
            assert!(!check);
            assert!(!yes);
        }
        _ => panic!("wrong command"),
    }

    let check_cmd = vec!["sanalu", "update", "--check"];
    let cli = Cli::try_parse_from(check_cmd).expect("parse update check");
    match cli.command {
        Commands::Update { check, yes } => {
            assert!(check);
            assert!(!yes);
        }
        _ => panic!("wrong command"),
    }

    let yes_cmd = vec!["sanalu", "update", "-y"];
    let cli = Cli::try_parse_from(yes_cmd).expect("parse update yes");
    match cli.command {
        Commands::Update { check, yes } => {
            assert!(!check);
            assert!(yes);
        }
        _ => panic!("wrong command"),
    }
}

#[test]
fn test_execute_update_check_mode_detects_newer_version() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();

    let handle = thread::spawn(move || {
        if let Ok((mut stream, _)) = listener.accept() {
            let mut buf = [0u8; 1024];
            let _ = stream.read(&mut buf);
            let body = r#"{
                "tag_name": "v99.0.0",
                "name": "Release v99.0.0",
                "body": "Future release",
                "assets": [
                    {
                        "name": "sanalu_99.0.0_amd64.deb",
                        "browser_download_url": "http://127.0.0.1/sanalu.deb",
                        "size": 1000
                    }
                ]
            }"#;
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            let _ = stream.write_all(response.as_bytes());
        }
    });

    let mock_base = format!("http://{}", addr);
    let mut out = Vec::new();
    let res = tokio::runtime::Runtime::new()
        .unwrap()
        .block_on(execute_update_with_base_url(
            &mut out,
            true,
            false,
            &mock_base,
            "chay22/sanalu",
        ));

    let _ = handle.join();
    assert!(res.is_ok());
    let output_str = String::from_utf8_lossy(&out);
    assert!(output_str.contains("Current version:"));
    assert!(output_str.contains("Latest version:  v99.0.0"));
    assert!(output_str.contains("Update available!"));
}

#[test]
fn test_execute_update_check_mode_already_up_to_date() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();

    let handle = thread::spawn(move || {
        if let Ok((mut stream, _)) = listener.accept() {
            let mut buf = [0u8; 1024];
            let _ = stream.read(&mut buf);
            let body = format!(
                r#"{{"tag_name": "v{}", "name": "Current", "body": "", "assets": []}}"#,
                env!("CARGO_PKG_VERSION")
            );
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            let _ = stream.write_all(response.as_bytes());
        }
    });

    let mock_base = format!("http://{}", addr);
    let mut out = Vec::new();
    let res = tokio::runtime::Runtime::new()
        .unwrap()
        .block_on(execute_update_with_base_url(
            &mut out,
            true,
            false,
            &mock_base,
            "chay22/sanalu",
        ));

    let _ = handle.join();
    assert!(res.is_ok());
    let output_str = String::from_utf8_lossy(&out);
    assert!(output_str.contains("sanalu is up to date."));
}
