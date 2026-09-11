pub mod crawler;
pub mod nginx;
pub mod os;
pub mod ssh;

pub use nginx::{
    DiscoveredNginxLog, NginxCrawlerResult, NginxFieldToken, NginxLogFormatKind,
    classify_format_body, crawl_nginx_config_tree, discover_nginx_logs_in_dir,
    find_active_nginx_conf, find_active_nginx_conf_with_paths, parse_nginx_access_logs,
    parse_nginx_config_for_formats,
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
    let active_conf = find_active_nginx_conf();
    discover_environment_with_paths(&active_conf, Path::new("/var/log/nginx"))
}

pub fn discover_environment_with_paths(
    nginx_conf_dir: &Path,
    nginx_log_dir: &Path,
) -> DiscoveredEnvironment {
    let conf_path = if nginx_conf_dir.is_file() {
        nginx_conf_dir.to_path_buf()
    } else {
        nginx_conf_dir.join("nginx.conf")
    };

    let result = crawl_nginx_config_tree(&conf_path, nginx_log_dir);
    let ssh_source = detect_ssh_source();

    DiscoveredEnvironment {
        nginx_logs: result.access_logs,
        nginx_error_logs: result.error_logs,
        ssh_source,
    }
}
