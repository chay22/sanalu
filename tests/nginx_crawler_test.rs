use sanalu::discovery::nginx::{NginxLogFormatKind, crawl_nginx_config_tree};
use std::fs::{self, File};
use std::io::Write;
use tempfile::tempdir;

#[test]
fn test_crawl_multiline_format_and_nested_includes() {
    let dir = tempdir().unwrap();
    let conf_dir = dir.path().join("nginx");
    let sites_dir = conf_dir.join("sites-enabled");
    let log_dir = dir.path().join("logs");
    fs::create_dir_all(&sites_dir).unwrap();
    fs::create_dir_all(&log_dir).unwrap();

    let root_conf = conf_dir.join("nginx.conf");
    let mut root_file = File::create(&root_conf).unwrap();
    root_file
        .write_all(
            b"http {\n\
            log_format cloudflare '$http_cf_connecting_ip - $remote_user [$time_local] '\n\
                                  '\"$request\" $status $body_bytes_sent '\n\
                                  '\"$http_referer\" \"$http_user_agent\"';\n\
            include sites-enabled/*;\n\
        }\n",
        )
        .unwrap();

    let site_conf = sites_dir.join("site1.conf");
    let mut site_file = File::create(&site_conf).unwrap();
    let access_log_path = log_dir.join("site1.access.log");
    site_file
        .write_all(
            format!(
                "server {{\n    access_log {} cloudflare;\n}}\n",
                access_log_path.to_str().unwrap()
            )
            .as_bytes(),
        )
        .unwrap();

    let result = crawl_nginx_config_tree(&root_conf, &log_dir);
    assert!(result.formats.contains_key("cloudflare"));
    assert!(result.formats.contains_key("combined"));

    let found_log = result
        .access_logs
        .iter()
        .find(|l| l.path == access_log_path)
        .expect("must discover site1.access.log");
    assert_eq!(found_log.format_kind, NginxLogFormatKind::CloudflareProxy);
}

#[test]
fn test_crawl_symlink_dedup_and_cycle_prevention() {
    let dir = tempdir().unwrap();
    let conf_dir = dir.path().join("nginx");
    let available_dir = conf_dir.join("sites-available");
    let enabled_dir = conf_dir.join("sites-enabled");
    let log_dir = dir.path().join("logs");
    fs::create_dir_all(&available_dir).unwrap();
    fs::create_dir_all(&enabled_dir).unwrap();
    fs::create_dir_all(&log_dir).unwrap();

    let root_conf = conf_dir.join("nginx.conf");
    let mut root_file = File::create(&root_conf).unwrap();
    root_file
        .write_all(b"events {}\nhttp {\n    include sites-enabled/*;\n}\n")
        .unwrap();

    let site_real = available_dir.join("site.conf");
    let access_log_path = log_dir.join("app.access.log");
    let mut site_file = File::create(&site_real).unwrap();
    site_file
        .write_all(
            format!(
                "server {{\n    access_log {};\n}}\n",
                access_log_path.to_str().unwrap()
            )
            .as_bytes(),
        )
        .unwrap();

    #[cfg(unix)]
    {
        use std::os::unix::fs::symlink;
        let symlink_path = enabled_dir.join("site.conf");
        symlink(&site_real, &symlink_path).unwrap();

        let symlink_loop = enabled_dir.join("loop.conf");
        symlink(&root_conf, &symlink_loop).unwrap();
    }

    let result = crawl_nginx_config_tree(&root_conf, &log_dir);
    let matched_logs: Vec<_> = result
        .access_logs
        .iter()
        .filter(|l| l.path == access_log_path)
        .collect();
    assert_eq!(matched_logs.len(), 1);
    assert_eq!(matched_logs[0].format_kind, NginxLogFormatKind::Combined);
}

#[test]
fn test_crawl_unconfigured_orphan_sniffing() {
    let dir = tempdir().unwrap();
    let conf_dir = dir.path().join("nginx");
    let log_dir = dir.path().join("logs");
    fs::create_dir_all(&conf_dir).unwrap();
    fs::create_dir_all(&log_dir).unwrap();

    let root_conf = conf_dir.join("nginx.conf");
    let mut root_file = File::create(&root_conf).unwrap();
    root_file
        .write_all(b"http {\n    access_log off;\n}\n")
        .unwrap();

    let json_log = log_dir.join("json_app.access.log");
    let mut jf = File::create(&json_log).unwrap();
    jf.write_all(b"{\"client\":\"1.2.3.4\",\"status\":200}\n")
        .unwrap();

    let plain_log = log_dir.join("standard.access.log");
    let mut pf = File::create(&plain_log).unwrap();
    pf.write_all(
        b"1.2.3.4 - - [12/Sep/2026:06:00:00 +0000] \"GET / HTTP/1.1\" 200 123 \"-\" \"curl\"\n",
    )
    .unwrap();

    let err_log = log_dir.join("site.error.log");
    let mut ef = File::create(&err_log).unwrap();
    ef.write_all(b"2026/09/12 06:00:00 [error] 123#123: test\n")
        .unwrap();

    let result = crawl_nginx_config_tree(&root_conf, &log_dir);

    let json_found = result
        .access_logs
        .iter()
        .find(|l| l.path == json_log)
        .expect("must find json log");
    assert_eq!(json_found.format_kind, NginxLogFormatKind::Json);

    let plain_found = result
        .access_logs
        .iter()
        .find(|l| l.path == plain_log)
        .expect("must find plain log");
    assert_eq!(plain_found.format_kind, NginxLogFormatKind::Combined);

    assert!(result.error_logs.iter().any(|l| l == &err_log));
}
