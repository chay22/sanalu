use sanalu::discovery::{
    DiscoveredNginxLog, NginxLogFormatKind, SshLogSource, classify_format_body,
    discover_environment_with_paths, discover_nginx_logs_in_dir, parse_nginx_access_logs,
    parse_nginx_config_for_formats,
};
use std::fs::File;
use std::io::Write;
use std::path::Path;
use tempfile::tempdir;

#[test]
fn test_classify_format_body() {
    let combined = "'$remote_addr - $remote_user [$time_local] \"$request\" ' '$status $body_bytes_sent \"$http_referer\" ' '\"$http_user_agent\"'";
    assert_eq!(classify_format_body(combined), NginxLogFormatKind::Combined);

    let cf = "'$http_cf_connecting_ip - $remote_user [$time_local] \"$request\" ' '$status $body_bytes_sent \"$http_referer\" ' '\"$http_user_agent\"'";
    assert_eq!(
        classify_format_body(cf),
        NginxLogFormatKind::CloudflareProxy
    );

    let json = "{\"time\": \"$time_local\", \"ip\": \"$remote_addr\"}";
    assert_eq!(classify_format_body(json), NginxLogFormatKind::Json);
}

#[test]
fn test_parse_nginx_config_for_formats_and_access_logs() {
    let conf = r#"
events {}
http {
    log_format main '$remote_addr - $remote_user [$time_local] "$request" $status $body_bytes_sent "$http_referer" "$http_user_agent"';
    log_format proxy '$http_cf_connecting_ip - $remote_user [$time_local] "$request" $status $body_bytes_sent "$http_referer" "$http_user_agent"';

    access_log /var/log/nginx/access.log main;
    access_log /var/log/nginx/api.log proxy;
}
"#;
    let formats = parse_nginx_config_for_formats(conf);
    assert_eq!(formats.len(), 2);
    assert_eq!(formats.get("main"), Some(&NginxLogFormatKind::Combined));
    assert_eq!(
        formats.get("proxy"),
        Some(&NginxLogFormatKind::CloudflareProxy)
    );

    let logs = parse_nginx_access_logs(conf, &formats);
    assert_eq!(logs.len(), 2);
    assert_eq!(
        logs[0],
        DiscoveredNginxLog {
            path: std::path::PathBuf::from("/var/log/nginx/access.log"),
            format_kind: NginxLogFormatKind::Combined,
        }
    );
    assert_eq!(
        logs[1],
        DiscoveredNginxLog {
            path: std::path::PathBuf::from("/var/log/nginx/api.log"),
            format_kind: NginxLogFormatKind::CloudflareProxy,
        }
    );
}

#[test]
fn test_discover_nginx_logs_in_dir() {
    let dir = tempdir().unwrap();
    let access_path = dir.path().join("access.log");
    let error_path = dir.path().join("error.log");
    let other_path = dir.path().join("other.txt");

    File::create(&access_path)
        .unwrap()
        .write_all(b"sample")
        .unwrap();
    File::create(&error_path)
        .unwrap()
        .write_all(b"sample")
        .unwrap();
    File::create(&other_path)
        .unwrap()
        .write_all(b"sample")
        .unwrap();

    let (access_logs, error_logs) = discover_nginx_logs_in_dir(dir.path());
    assert_eq!(access_logs.len(), 1);
    assert_eq!(access_logs[0], access_path);
    assert_eq!(error_logs.len(), 1);
    assert_eq!(error_logs[0], error_path);
}

#[test]
fn test_discover_environment_with_paths() {
    let conf_dir = tempdir().unwrap();
    let log_dir = tempdir().unwrap();

    let conf_file = conf_dir.path().join("nginx.conf");
    let conf_content = r#"
http {
    log_format custom '$http_x_forwarded_for - $remote_user [$time_local]';
    access_log /custom/access.log custom;
}
"#;
    File::create(&conf_file)
        .unwrap()
        .write_all(conf_content.as_bytes())
        .unwrap();

    let fs_log = log_dir.path().join("site.access.log");
    File::create(&fs_log).unwrap().write_all(b"dummy").unwrap();

    let env = discover_environment_with_paths(conf_dir.path(), log_dir.path());
    assert!(
        env.nginx_logs
            .iter()
            .any(|l| l.path == Path::new("/custom/access.log"))
    );
    assert!(env.nginx_logs.iter().any(|l| l.path == fs_log));
    assert!(matches!(
        env.ssh_source,
        SshLogSource::JournaldService(_) | SshLogSource::File(_)
    ));
}

#[test]
fn test_os_release_parsing() {
    let debian_os_release = r#"
NAME="Debian GNU/Linux"
VERSION_ID="12"
VERSION="12 (bookworm)"
VERSION_CODENAME=bookworm
ID=debian
HOME_URL="https://www.debian.org/"
SUPPORT_URL="https://www.debian.org/support"
BUG_REPORT_URL="https://bugs.debian.org/"
"#;
    let os = sanalu::discovery::OsInfo::parse(debian_os_release);
    assert_eq!(os.id, "debian");
    assert_eq!(os.name, "Debian GNU/Linux");
    assert_eq!(os.version_id, "12");

    let rhel_os_release = r#"
NAME="Rocky Linux"
VERSION="9.4 (Blue Onyx)"
ID="rocky"
ID_LIKE="rhel centos fedora"
VERSION_ID="9.4"
"#;
    let rhel = sanalu::discovery::OsInfo::parse(rhel_os_release);
    assert_eq!(rhel.id, "rocky");
    assert!(rhel.id_like.contains(&"rhel".to_string()));
    assert!(rhel.id_like.contains(&"fedora".to_string()));
}
