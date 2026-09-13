use super::category::ThreatCategory;
use crate::error::SanaluError;
use regex::RegexSet;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThreatDecision {
    Pass,
    InstantBan(ThreatCategory),
    SharedStrike {
        category: ThreatCategory,
        threshold: u8,
        window_secs: u64,
    },
    IsolatedStrike {
        category: ThreatCategory,
        threshold: u8,
        window_secs: u64,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeResult {
    AllowedEndpoint,
    HarmfulPattern(&'static str),
    Clean,
}

pub struct ProbeMatcher {
    allowed_endpoints_regex: Option<RegexSet>,
}

impl ProbeMatcher {
    pub fn new(allowed_patterns: &[String]) -> Result<Self, SanaluError> {
        let allowed_endpoints_regex = if allowed_patterns.is_empty() {
            None
        } else {
            Some(
                RegexSet::new(allowed_patterns)
                    .map_err(|e| SanaluError::Intelligence(e.to_string()))?,
            )
        };
        Ok(Self {
            allowed_endpoints_regex,
        })
    }

    pub fn is_allowed_endpoint(&self, path: &str) -> bool {
        if let Some(ref regex_set) = self.allowed_endpoints_regex {
            regex_set.is_match(path)
        } else {
            false
        }
    }

    pub fn inspect(&self, path: &str) -> ProbeResult {
        if self.is_allowed_endpoint(path) {
            return ProbeResult::AllowedEndpoint;
        }
        if path.contains(".env") {
            return ProbeResult::HarmfulPattern(".env");
        }
        if path.contains("/wp-") {
            return ProbeResult::HarmfulPattern("/wp-");
        }
        if path.contains(".sql") {
            return ProbeResult::HarmfulPattern(".sql");
        }
        if path.contains("../") {
            return ProbeResult::HarmfulPattern("../");
        }
        if path.contains("%2e%2e") {
            return ProbeResult::HarmfulPattern("%2e%2e");
        }
        if path.contains("/%00") {
            return ProbeResult::HarmfulPattern("/%00");
        }
        if path.contains("/adminer") {
            return ProbeResult::HarmfulPattern("/adminer");
        }
        if path.contains("phpunit") {
            return ProbeResult::HarmfulPattern("phpunit");
        }
        if path.contains("/actuator") {
            return ProbeResult::HarmfulPattern("/actuator");
        }
        match inspect_threat("GET", path, 404) {
            ThreatDecision::Pass => ProbeResult::Clean,
            ThreatDecision::InstantBan(c)
            | ThreatDecision::SharedStrike { category: c, .. }
            | ThreatDecision::IsolatedStrike { category: c, .. } => {
                ProbeResult::HarmfulPattern(c.as_str())
            }
        }
    }
}

fn is_get_or_head(method: &str) -> bool {
    method.eq_ignore_ascii_case("GET") || method.eq_ignore_ascii_case("HEAD")
}

fn is_safe_query_method(method: &str) -> bool {
    method.eq_ignore_ascii_case("GET")
        || method.eq_ignore_ascii_case("HEAD")
        || method.eq_ignore_ascii_case("QUERY")
}

fn is_php_rce_probe(path: &str) -> bool {
    path.contains("eval-stdin")
        || path.contains("/vendor/phpunit/")
        || path.starts_with("/php-cgi")
        || path.starts_with("/cgi/php")
        || path.contains("invokefunction")
        || path.contains("auto_prepend_file")
        || path.contains("allow_url_include")
        || path.contains("php://input")
        || path.contains("php://filter")
        || path.contains("pearcmd")
}

fn is_known_webshell(path: &str) -> bool {
    path.ends_with("/wp-asudo.php")
        || path.ends_with("/wp-wlx.php")
        || path.ends_with("/wp-rrtx.php")
        || path.ends_with("/wp-fure.php")
        || path.ends_with("/wp-2019.php")
        || path.ends_with("/wp-aothait.php")
        || path.ends_with("/wp-gzone.php")
        || path.ends_with("/wp-ver.php")
        || path.ends_with("/wp-act.php")
}

fn is_traversal_exploit(path: &str) -> bool {
    path.contains("../") || path.contains("..;/") || path.contains("..\\")
}

fn is_null_byte_exploit(path: &str) -> bool {
    path.contains("%00") || path.contains('\0')
}

fn is_vite_proc_exploit(path: &str, status: u16) -> bool {
    (path.contains("/@fs/proc/") || path.contains("/@fs/etc/")) && status != 200
}

fn inspect_shell_exploit(method: &str, path: &str, status: u16) -> Option<ThreatDecision> {
    if !path.ends_with("/bin/sh") && !path.ends_with("/bin/bash") {
        return None;
    }
    if is_safe_query_method(method) {
        if status != 200 {
            return Some(ThreatDecision::SharedStrike {
                category: ThreatCategory::Common,
                threshold: 3,
                window_secs: 10,
            });
        }
        return Some(ThreatDecision::Pass);
    }
    Some(ThreatDecision::InstantBan(ThreatCategory::Common))
}

fn inspect_stage1_pure_exploits(method: &str, path: &str, status: u16) -> Option<ThreatDecision> {
    if is_traversal_exploit(path) || is_null_byte_exploit(path) {
        return Some(ThreatDecision::InstantBan(ThreatCategory::Common));
    }
    if let Some(decision) = inspect_shell_exploit(method, path, status) {
        return Some(decision);
    }
    if path.contains("mstshash") && status != 200 {
        return Some(ThreatDecision::InstantBan(ThreatCategory::Common));
    }
    if is_vite_proc_exploit(path, status) {
        return Some(ThreatDecision::InstantBan(ThreatCategory::Common));
    }
    if is_php_rce_probe(path) {
        return Some(ThreatDecision::InstantBan(ThreatCategory::Php));
    }
    if path.contains("/_ignition/") {
        return Some(ThreatDecision::InstantBan(ThreatCategory::Laravel));
    }
    if is_known_webshell(path) {
        return Some(ThreatDecision::InstantBan(ThreatCategory::Wordpress));
    }
    None
}

fn is_sensitive_dotfile(path: &str) -> bool {
    path.ends_with("/.zsh_history")
        || path.ends_with("/.bashrc")
        || path.ends_with("/.zshrc")
        || path.ends_with("/.netrc")
        || path.ends_with("/.npmrc")
        || path.ends_with("/.pypirc")
        || path.ends_with("/.auth.json")
        || path.ends_with("/.secrets.json")
}

fn inspect_dotfiles_vcs(method: &str, path: &str, status: u16) -> Option<ThreatDecision> {
    if path.contains("/.git") && !matches!(status, 200 | 301 | 302) {
        if is_safe_query_method(method) {
            return Some(ThreatDecision::SharedStrike {
                category: ThreatCategory::Vcs,
                threshold: 3,
                window_secs: 10,
            });
        }
        return Some(ThreatDecision::InstantBan(ThreatCategory::Vcs));
    }
    if path.contains("/.svn/") || path.contains("/.bzr/") || path.contains("/.bash_") {
        return Some(ThreatDecision::InstantBan(ThreatCategory::Vcs));
    }
    if path.contains("/.hg/") && !matches!(status, 200..=207 | 301 | 302) {
        return Some(ThreatDecision::InstantBan(ThreatCategory::Vcs));
    }
    if path.ends_with("/.ds_store") && status != 200 {
        if is_get_or_head(method) {
            return Some(ThreatDecision::IsolatedStrike {
                category: ThreatCategory::Vcs,
                threshold: 3,
                window_secs: 10,
            });
        }
        return Some(ThreatDecision::InstantBan(ThreatCategory::Vcs));
    }
    if is_sensitive_dotfile(path) {
        return Some(ThreatDecision::InstantBan(ThreatCategory::Vcs));
    }
    None
}

fn inspect_dotfiles_ssh(method: &str, path: &str, status: u16) -> Option<ThreatDecision> {
    if (path.ends_with("/id_rsa") || path.ends_with("/id_ed25519") || path.ends_with("/id_ecdsa"))
        && status != 200
    {
        if is_get_or_head(method) {
            return Some(ThreatDecision::SharedStrike {
                category: ThreatCategory::Ssh,
                threshold: 2,
                window_secs: 10,
            });
        }
        return Some(ThreatDecision::InstantBan(ThreatCategory::Ssh));
    }
    if path.contains("/.ssh/") && !matches!(status, 200..=207 | 301 | 302) {
        return Some(ThreatDecision::InstantBan(ThreatCategory::Ssh));
    }
    None
}

fn is_ide_dotfile(path: &str) -> bool {
    path.contains("/.vscode/")
        || path.contains("/.idea/")
        || path.contains("/.zed/")
        || path.contains("/.xcodeproj/")
        || path.contains("/.xcworkspace/")
        || path.contains("/.vs/")
        || path.contains("/.userprefs/")
        || path.ends_with("/.sln.docstates")
        || path.contains("/.fleet/")
        || path.ends_with("/.sublime-project")
        || path.ends_with("/.sublime-workspace")
        || path.contains("/.cursor/")
        || path.ends_with("/.cursorrules")
        || path.ends_with("/.windsurfrules")
        || path.contains("/.helix/")
        || path.contains("/.vim/")
        || path.contains("/.nvim/")
        || path.contains("/.gradle/")
}

fn inspect_dotfiles_ide(path: &str, status: u16) -> Option<ThreatDecision> {
    if is_ide_dotfile(path) && status != 200 {
        return Some(ThreatDecision::InstantBan(ThreatCategory::Ide));
    }
    None
}

fn is_cloud_credentials_strike_path(path: &str) -> bool {
    path.ends_with("/azure-credentials.json")
        || path.ends_with("/terraform.tfstate")
        || path.ends_with("/terraform.tfvars")
        || path.ends_with("/firebase-adminsdk.json")
        || path.ends_with("/service-account.json")
        || path.ends_with("/application_default_credentials.json")
}

fn is_gcp_key_path(path: &str) -> bool {
    path.ends_with("/gcp-key.json")
        || path.ends_with("/gcp-credentials.json")
        || path.ends_with("/gcp-sa.json")
        || path.ends_with("/google-credentials.json")
        || path.ends_with("/google-key.json")
}

fn is_cloud_config_dotdir(path: &str) -> bool {
    path.contains("/.aws/")
        || path.contains("/.azure/")
        || path.contains("/.kube/")
        || path.contains("/.docker/")
        || path.contains("/.oci/")
}

fn inspect_dotfiles_cloud(method: &str, path: &str, status: u16) -> Option<ThreatDecision> {
    if is_cloud_credentials_strike_path(path) && status != 200 {
        if is_get_or_head(method) {
            return Some(ThreatDecision::SharedStrike {
                category: ThreatCategory::Cloud,
                threshold: 2,
                window_secs: 10,
            });
        }
        return Some(ThreatDecision::InstantBan(ThreatCategory::Cloud));
    }
    if (path.ends_with("/credentials.json") || path.ends_with("/sa.json")) && status != 200 {
        return Some(ThreatDecision::SharedStrike {
            category: ThreatCategory::Cloud,
            threshold: 2,
            window_secs: 10,
        });
    }
    if is_gcp_key_path(path) && status != 200 {
        return Some(ThreatDecision::InstantBan(ThreatCategory::Cloud));
    }
    if is_cloud_config_dotdir(path) && !matches!(status, 200..=207 | 301 | 302) {
        return Some(ThreatDecision::InstantBan(ThreatCategory::Cloud));
    }
    if path.contains("/.config/") && !matches!(status, 200..=207 | 301 | 302) {
        if is_get_or_head(method) {
            return Some(ThreatDecision::SharedStrike {
                category: ThreatCategory::Cloud,
                threshold: 3,
                window_secs: 10,
            });
        }
        return Some(ThreatDecision::InstantBan(ThreatCategory::Cloud));
    }
    None
}

fn inspect_dotfiles_common_and_wp(method: &str, path: &str, status: u16) -> Option<ThreatDecision> {
    if (path.ends_with("/.env") || path.contains("/.env.") || path.ends_with(".flaskenv"))
        && status != 200
    {
        if is_safe_query_method(method) {
            return Some(ThreatDecision::SharedStrike {
                category: ThreatCategory::Common,
                threshold: 3,
                window_secs: 10,
            });
        }
        return Some(ThreatDecision::InstantBan(ThreatCategory::Common));
    }
    if path.contains("/.wp-config.") && matches!(status, 400 | 403 | 404 | 444) {
        return Some(ThreatDecision::InstantBan(ThreatCategory::Wordpress));
    }
    None
}

fn inspect_dotfiles(method: &str, path: &str, status: u16) -> Option<ThreatDecision> {
    if let Some(d) = inspect_dotfiles_vcs(method, path, status) {
        return Some(d);
    }
    if let Some(d) = inspect_dotfiles_ssh(method, path, status) {
        return Some(d);
    }
    if let Some(d) = inspect_dotfiles_ide(path, status) {
        return Some(d);
    }
    if let Some(d) = inspect_dotfiles_cloud(method, path, status) {
        return Some(d);
    }
    inspect_dotfiles_common_and_wp(method, path, status)
}

fn is_wp_core_file(path: &str) -> bool {
    path.ends_with("/wp-manager.php")
        || path.ends_with("/wp-access.php")
        || path.ends_with("/wp-seo.php")
        || path.ends_with("/wp-style.php")
        || path.ends_with("/wp-blogs.php")
        || path.ends_with("/wp-blog.php")
        || path.ends_with("/wp-blog-header.php")
        || path.ends_with("/wp-mails.php")
        || path.ends_with("/wp-mail.php")
        || path.ends_with("/wp-temp.php")
        || path.ends_with("/wp-activate.php")
        || path.ends_with("/wp-load.php")
}

fn is_wp_error_status(status: u16) -> bool {
    matches!(status, 400 | 403 | 404 | 405 | 444)
}

fn is_wp_instant_exploit_path(path: &str) -> bool {
    path.contains("/wp-signup")
        || path.contains("/wp-config.")
        || path.contains("/wp-konfig")
        || path.contains("/xmlrpc.php")
        || is_wp_core_file(path)
}

fn inspect_wp_instant_exploits(path: &str, status: u16) -> Option<ThreatDecision> {
    if path.contains("/wp-l0gin") && status != 200 {
        return Some(ThreatDecision::InstantBan(ThreatCategory::Wordpress));
    }
    if (path.contains("/wp_filemanager") || path.contains("/wp-file-manager")) && status != 200 {
        return Some(ThreatDecision::InstantBan(ThreatCategory::Wordpress));
    }
    if (path.contains("/wp-json") || path.contains("/wp-info")) && status == 444 {
        return Some(ThreatDecision::InstantBan(ThreatCategory::Wordpress));
    }
    if path.contains("woocommerce_stripe_")
        && !matches!(status, 200 | 301 | 302 | 400 | 401 | 403 | 500)
    {
        return Some(ThreatDecision::InstantBan(ThreatCategory::Wordpress));
    }
    if is_wp_instant_exploit_path(path) && is_wp_error_status(status) {
        return Some(ThreatDecision::InstantBan(ThreatCategory::Wordpress));
    }
    None
}

fn inspect_wp_strikes(method: &str, path: &str, status: u16) -> Option<ThreatDecision> {
    if path.contains("/wp-login") && matches!(status, 404 | 405 | 444) {
        return Some(ThreatDecision::SharedStrike {
            category: ThreatCategory::Wordpress,
            threshold: 4,
            window_secs: 10,
        });
    }
    if path.ends_with("/wlwmanifest.xml") && status != 200 {
        return Some(ThreatDecision::SharedStrike {
            category: ThreatCategory::Wordpress,
            threshold: 2,
            window_secs: 10,
        });
    }
    if (path.contains("/wp-admin") || path.contains("/wp-include")) && is_wp_error_status(status) {
        let threshold = if is_safe_query_method(method) { 7 } else { 5 };
        return Some(ThreatDecision::IsolatedStrike {
            category: ThreatCategory::Wordpress,
            threshold,
            window_secs: 10,
        });
    }
    None
}

fn inspect_wordpress(method: &str, path: &str, status: u16) -> Option<ThreatDecision> {
    if let Some(decision) = inspect_wp_instant_exploits(path, status) {
        return Some(decision);
    }
    inspect_wp_strikes(method, path, status)
}

fn inspect_actuator(path: &str, status: u16) -> Option<ThreatDecision> {
    if (path.contains("/actuator/env")
        || path.contains("/actuator/heapdump")
        || path.contains("/actuator/gateway"))
        && status != 200
    {
        return Some(ThreatDecision::InstantBan(ThreatCategory::Actuator));
    }
    if path.contains("/actuator") && status != 200 {
        return Some(ThreatDecision::SharedStrike {
            category: ThreatCategory::Actuator,
            threshold: 3,
            window_secs: 10,
        });
    }
    None
}

fn inspect_laravel(path: &str, status: u16) -> Option<ThreatDecision> {
    if (path.contains("/telescope") || path.contains("/horizon"))
        && !matches!(status, 200 | 301 | 302)
    {
        return Some(ThreatDecision::SharedStrike {
            category: ThreatCategory::Laravel,
            threshold: 2,
            window_secs: 10,
        });
    }
    None
}

fn inspect_webmail(path: &str, status: u16) -> Option<ThreatDecision> {
    if (path.contains("/roundcube") || path.contains("/webmail") || path.contains("/horde"))
        && !matches!(status, 200 | 301 | 302)
    {
        return Some(ThreatDecision::SharedStrike {
            category: ThreatCategory::Webmail,
            threshold: 3,
            window_secs: 15,
        });
    }
    None
}

fn is_backup_extension(path: &str) -> bool {
    path.ends_with(".sql")
        || path.ends_with(".gz")
        || path.ends_with(".bz2")
        || path.ends_with(".tgz")
        || path.ends_with(".7z")
        || path.ends_with(".zip")
}

fn inspect_backups(path: &str, status: u16) -> Option<ThreatDecision> {
    if is_backup_extension(path) && status != 200 {
        return Some(ThreatDecision::IsolatedStrike {
            category: ThreatCategory::Backups,
            threshold: 5,
            window_secs: 10,
        });
    }
    None
}

fn inspect_cloud_or_ssh_standalone(
    method: &str,
    path: &str,
    status: u16,
) -> Option<ThreatDecision> {
    if (path.ends_with("/id_rsa") || path.ends_with("/id_ed25519") || path.ends_with("/id_ecdsa"))
        && status != 200
    {
        if is_get_or_head(method) {
            return Some(ThreatDecision::SharedStrike {
                category: ThreatCategory::Ssh,
                threshold: 2,
                window_secs: 10,
            });
        }
        return Some(ThreatDecision::InstantBan(ThreatCategory::Ssh));
    }
    if is_cloud_credentials_strike_path(path) && status != 200 {
        if is_get_or_head(method) {
            return Some(ThreatDecision::SharedStrike {
                category: ThreatCategory::Cloud,
                threshold: 2,
                window_secs: 10,
            });
        }
        return Some(ThreatDecision::InstantBan(ThreatCategory::Cloud));
    }
    if (path.ends_with("/credentials.json") || path.ends_with("/sa.json")) && status != 200 {
        return Some(ThreatDecision::SharedStrike {
            category: ThreatCategory::Cloud,
            threshold: 2,
            window_secs: 10,
        });
    }
    if is_gcp_key_path(path) && status != 200 {
        return Some(ThreatDecision::InstantBan(ThreatCategory::Cloud));
    }
    None
}

fn is_system_file_probe(path: &str) -> bool {
    path.contains("/etc/passwd") || path.contains("/etc/shadow") || path.contains("/proc/self/")
}

fn is_common_backup_or_config_probe(path: &str) -> bool {
    path.ends_with("/boot.ini")
        || path.ends_with("/win.ini")
        || path.ends_with(".bak")
        || path.ends_with(".swp")
        || path.ends_with(".pyc")
}

fn is_cloud_secret_probe(path: &str) -> bool {
    path.contains("/var/run/secrets")
        || path.contains("/secrets/kubernetes.io")
        || path.ends_with("/rootkey.csv")
}

fn inspect_common_error(method: &str, path: &str, status: u16) -> Option<ThreatDecision> {
    if status == 200 {
        return None;
    }
    if is_system_file_probe(path) {
        if is_safe_query_method(method) {
            return Some(ThreatDecision::SharedStrike {
                category: ThreatCategory::Common,
                threshold: 3,
                window_secs: 10,
            });
        }
        return Some(ThreatDecision::InstantBan(ThreatCategory::Common));
    }
    if path.contains("/proc/1/") || path.contains("/boaform/admin") {
        return Some(ThreatDecision::InstantBan(ThreatCategory::Common));
    }
    if is_common_backup_or_config_probe(path) {
        if is_safe_query_method(method) {
            return Some(ThreatDecision::SharedStrike {
                category: ThreatCategory::Common,
                threshold: 3,
                window_secs: 10,
            });
        }
        return Some(ThreatDecision::InstantBan(ThreatCategory::Common));
    }
    if path.ends_with(".py") {
        if is_safe_query_method(method) {
            return Some(ThreatDecision::IsolatedStrike {
                category: ThreatCategory::Common,
                threshold: 3,
                window_secs: 10,
            });
        }
        return Some(ThreatDecision::InstantBan(ThreatCategory::Common));
    }
    if path.contains("/nbproject/") {
        return Some(ThreatDecision::InstantBan(ThreatCategory::Ide));
    }
    if is_cloud_secret_probe(path) {
        return Some(ThreatDecision::InstantBan(ThreatCategory::Cloud));
    }
    None
}

fn inspect_php(method: &str, path: &str, status: u16) -> Option<ThreatDecision> {
    if path.contains("/cgi-bin/") && status != 200 {
        if is_get_or_head(method) {
            return Some(ThreatDecision::SharedStrike {
                category: ThreatCategory::Php,
                threshold: 3,
                window_secs: 10,
            });
        }
        return Some(ThreatDecision::InstantBan(ThreatCategory::Php));
    }
    if path.contains("/phpinfo") && status != 200 {
        return Some(ThreatDecision::InstantBan(ThreatCategory::Php));
    }
    if (path.ends_with(".php~") || path.ends_with(".php.old") || path.ends_with(".php.save"))
        && status != 200
    {
        return Some(ThreatDecision::InstantBan(ThreatCategory::Php));
    }
    if (path.contains("/phpmyadmin")
        || path.contains("/pma")
        || path.contains("/mysqladmin")
        || path.contains("/adminer.php"))
        && !matches!(status, 200 | 301 | 302)
    {
        return Some(ThreatDecision::SharedStrike {
            category: ThreatCategory::Php,
            threshold: 3,
            window_secs: 15,
        });
    }
    if path.contains("<?php") && !matches!(status, 200 | 400 | 403) {
        if is_safe_query_method(method) {
            return Some(ThreatDecision::SharedStrike {
                category: ThreatCategory::Php,
                threshold: 3,
                window_secs: 10,
            });
        }
        return Some(ThreatDecision::InstantBan(ThreatCategory::Php));
    }
    if path.ends_with(".php") && !matches!(status, 200 | 301 | 302) {
        return Some(ThreatDecision::IsolatedStrike {
            category: ThreatCategory::Php,
            threshold: 15,
            window_secs: 10,
        });
    }
    None
}

pub fn inspect_threat(method: &str, path: &str, status: u16) -> ThreatDecision {
    if path.starts_with("/.well-known/") && (200..=399).contains(&status) {
        return ThreatDecision::Pass;
    }
    if let Some(decision) = inspect_stage1_pure_exploits(method, path, status) {
        return decision;
    }
    if path.contains("/.") {
        if let Some(decision) = inspect_dotfiles(method, path, status) {
            return decision;
        }
    }
    if status == 200 || status == 304 {
        return ThreatDecision::Pass;
    }
    if let Some(decision) = inspect_wordpress(method, path, status) {
        return decision;
    }
    if let Some(decision) = inspect_actuator(path, status) {
        return decision;
    }
    if let Some(decision) = inspect_laravel(path, status) {
        return decision;
    }
    if let Some(decision) = inspect_webmail(path, status) {
        return decision;
    }
    if let Some(decision) = inspect_backups(path, status) {
        return decision;
    }
    if let Some(decision) = inspect_cloud_or_ssh_standalone(method, path, status) {
        return decision;
    }
    if let Some(decision) = inspect_common_error(method, path, status) {
        return decision;
    }
    if let Some(decision) = inspect_php(method, path, status) {
        return decision;
    }
    ThreatDecision::Pass
}
