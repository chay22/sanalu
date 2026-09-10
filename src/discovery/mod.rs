pub mod nginx;
pub mod os;
pub mod ssh;

pub use nginx::{
    DiscoveredNginxLog, NginxFieldToken, NginxLogFormatKind, classify_format_body,
    discover_nginx_logs_in_dir, parse_nginx_access_logs, parse_nginx_config_for_formats,
};
pub use os::{CompletionPaths, OsInfo, detect_completion_paths, is_root};
pub use ssh::{SshLogSource, detect_ssh_source};

use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscoveredEnvironment {
    pub nginx_logs: Vec<DiscoveredNginxLog>,
    pub nginx_error_logs: Vec<PathBuf>,
    pub ssh_source: SshLogSource,
}

pub fn discover_environment() -> DiscoveredEnvironment {
    discover_environment_with_paths(Path::new("/etc/nginx"), Path::new("/var/log/nginx"))
}

pub fn discover_environment_with_paths(
    nginx_conf_dir: &Path,
    nginx_log_dir: &Path,
) -> DiscoveredEnvironment {
    let mut discovered_logs = Vec::new();
    let mut discovered_errors = Vec::new();

    let conf_path = nginx_conf_dir.join("nginx.conf");
    let formats = if conf_path.exists() {
        let content = std::fs::read_to_string(&conf_path).unwrap_or_default();
        let parsed_formats = parse_nginx_config_for_formats(&content);
        let parsed_logs = parse_nginx_access_logs(&content, &parsed_formats);
        discovered_logs.extend(parsed_logs);
        parsed_formats
    } else {
        std::collections::HashMap::new()
    };

    let (fs_access_logs, fs_error_logs) = discover_nginx_logs_in_dir(nginx_log_dir);
    discovered_errors.extend(fs_error_logs);

    for access_path in fs_access_logs {
        if !discovered_logs.iter().any(|d| d.path == access_path) {
            let format_kind = formats
                .get("main")
                .or_else(|| formats.get("combined"))
                .cloned()
                .unwrap_or(NginxLogFormatKind::Combined);

            discovered_logs.push(DiscoveredNginxLog {
                path: access_path,
                format_kind,
            });
        }
    }

    let ssh_source = detect_ssh_source();

    DiscoveredEnvironment {
        nginx_logs: discovered_logs,
        nginx_error_logs: discovered_errors,
        ssh_source,
    }
}
