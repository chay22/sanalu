use sanalu::intelligence::category::ThreatCategory;
use sanalu::intelligence::probes::{ThreatDecision, inspect_threat};

#[test]
fn test_stage0_universal_whitelist() {
    assert_eq!(
        inspect_threat("GET", "/.well-known/acme-challenge/token123", 200),
        ThreatDecision::Pass
    );
    assert_eq!(
        inspect_threat("HEAD", "/.well-known/security.txt", 204),
        ThreatDecision::Pass
    );
    assert_eq!(
        inspect_threat("GET", "/.well-known/pki-validation/cert.txt", 301),
        ThreatDecision::Pass
    );
    assert_eq!(
        inspect_threat("GET", "/.well-known/assetlinks.json", 399),
        ThreatDecision::Pass
    );
}

#[test]
fn test_stage1_traversal_and_null_bytes() {
    assert_eq!(
        inspect_threat("GET", "/static/../../etc/passwd", 200),
        ThreatDecision::InstantBan(ThreatCategory::Common)
    );
    assert_eq!(
        inspect_threat("GET", "/static/..;/..;/etc/passwd", 200),
        ThreatDecision::InstantBan(ThreatCategory::Common)
    );
    assert_eq!(
        inspect_threat("GET", "/static/..\\..\\windows\\win.ini", 200),
        ThreatDecision::InstantBan(ThreatCategory::Common)
    );
    assert_eq!(
        inspect_threat("GET", "/images/%00.png", 200),
        ThreatDecision::InstantBan(ThreatCategory::Common)
    );
    assert_eq!(
        inspect_threat("GET", "/images/\0.png", 200),
        ThreatDecision::InstantBan(ThreatCategory::Common)
    );
}

#[test]
fn test_stage1_shell_execution() {
    assert_eq!(
        inspect_threat("POST", "/cgi-bin/test/bin/sh", 200),
        ThreatDecision::InstantBan(ThreatCategory::Common)
    );
    assert_eq!(
        inspect_threat("POST", "/cgi-bin/test/bin/bash", 200),
        ThreatDecision::InstantBan(ThreatCategory::Common)
    );
    assert_eq!(
        inspect_threat("GET", "/cgi-bin/test/bin/sh", 500),
        ThreatDecision::SharedStrike {
            category: ThreatCategory::Common,
            threshold: 3,
            window_secs: 10,
        }
    );
    assert_eq!(
        inspect_threat("GET", "/cgi-bin/test/bin/bash", 200),
        ThreatDecision::Pass
    );
}

#[test]
fn test_stage1_scanners_and_vite_lfi() {
    assert_eq!(
        inspect_threat("GET", "/rdp/mstshash=test", 404),
        ThreatDecision::InstantBan(ThreatCategory::Common)
    );
    assert_eq!(
        inspect_threat("GET", "/rdp/mstshash=test", 200),
        ThreatDecision::Pass
    );
    assert_eq!(
        inspect_threat("GET", "/@fs/proc/version", 404),
        ThreatDecision::InstantBan(ThreatCategory::Common)
    );
    assert_eq!(
        inspect_threat("GET", "/@fs/etc/shadow", 404),
        ThreatDecision::InstantBan(ThreatCategory::Common)
    );
    assert_eq!(
        inspect_threat("GET", "/@fs/proc/version", 200),
        ThreatDecision::Pass
    );
}

#[test]
fn test_stage1_php_rce_and_ignition() {
    assert_eq!(
        inspect_threat(
            "GET",
            "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php",
            200
        ),
        ThreatDecision::InstantBan(ThreatCategory::Php)
    );
    assert_eq!(
        inspect_threat("GET", "/vendor/phpunit/test", 200),
        ThreatDecision::InstantBan(ThreatCategory::Php)
    );
    assert_eq!(
        inspect_threat("GET", "/php-cgi/test", 200),
        ThreatDecision::InstantBan(ThreatCategory::Php)
    );
    assert_eq!(
        inspect_threat("GET", "/cgi/php/test", 200),
        ThreatDecision::InstantBan(ThreatCategory::Php)
    );
    assert_eq!(
        inspect_threat("GET", "/index.php?s=invokefunction", 200),
        ThreatDecision::InstantBan(ThreatCategory::Php)
    );
    assert_eq!(
        inspect_threat("GET", "/index.php?d=auto_prepend_file", 200),
        ThreatDecision::InstantBan(ThreatCategory::Php)
    );
    assert_eq!(
        inspect_threat("GET", "/index.php?d=allow_url_include", 200),
        ThreatDecision::InstantBan(ThreatCategory::Php)
    );
    assert_eq!(
        inspect_threat("POST", "/index.php?d=php://input", 200),
        ThreatDecision::InstantBan(ThreatCategory::Php)
    );
    assert_eq!(
        inspect_threat("GET", "/index.php?d=php://filter/read", 200),
        ThreatDecision::InstantBan(ThreatCategory::Php)
    );
    assert_eq!(
        inspect_threat("GET", "/index.php?+config-create+/&pearcmd", 200),
        ThreatDecision::InstantBan(ThreatCategory::Php)
    );
    assert_eq!(
        inspect_threat("POST", "/_ignition/execute-solution", 200),
        ThreatDecision::InstantBan(ThreatCategory::Laravel)
    );
}

#[test]
fn test_stage1_known_webshells() {
    let shells = [
        "/wp-asudo.php",
        "/wp-wlx.php",
        "/wp-rrtx.php",
        "/wp-fure.php",
        "/wp-2019.php",
        "/wp-aothait.php",
        "/wp-gzone.php",
        "/wp-ver.php",
        "/wp-act.php",
    ];
    for shell in shells {
        assert_eq!(
            inspect_threat("GET", shell, 404),
            ThreatDecision::InstantBan(ThreatCategory::Wordpress)
        );
        assert_eq!(
            inspect_threat("GET", shell, 200),
            ThreatDecision::InstantBan(ThreatCategory::Wordpress)
        );
    }
}

#[test]
fn test_stage2_dotfiles_vcs() {
    assert_eq!(
        inspect_threat("GET", "/.git/config", 404),
        ThreatDecision::SharedStrike {
            category: ThreatCategory::Vcs,
            threshold: 3,
            window_secs: 10,
        }
    );
    assert_eq!(
        inspect_threat("POST", "/.git/config", 404),
        ThreatDecision::InstantBan(ThreatCategory::Vcs)
    );
    assert_eq!(
        inspect_threat("GET", "/.git/config", 200),
        ThreatDecision::Pass
    );
    assert_eq!(
        inspect_threat("GET", "/.svn/entries", 404),
        ThreatDecision::InstantBan(ThreatCategory::Vcs)
    );
    assert_eq!(
        inspect_threat("GET", "/.bzr/README", 404),
        ThreatDecision::InstantBan(ThreatCategory::Vcs)
    );
    assert_eq!(
        inspect_threat("GET", "/.bash_history", 404),
        ThreatDecision::InstantBan(ThreatCategory::Vcs)
    );
    assert_eq!(
        inspect_threat("GET", "/.hg/dirstate", 404),
        ThreatDecision::InstantBan(ThreatCategory::Vcs)
    );
    assert_eq!(
        inspect_threat("GET", "/.ds_store", 404),
        ThreatDecision::IsolatedStrike {
            category: ThreatCategory::Vcs,
            threshold: 3,
            window_secs: 10,
        }
    );
    assert_eq!(
        inspect_threat("POST", "/.ds_store", 404),
        ThreatDecision::InstantBan(ThreatCategory::Vcs)
    );
    let secret_dotfiles = [
        "/.zsh_history",
        "/.bashrc",
        "/.zshrc",
        "/.netrc",
        "/.npmrc",
        "/.pypirc",
        "/.auth.json",
        "/.secrets.json",
    ];
    for path in secret_dotfiles {
        assert_eq!(
            inspect_threat("GET", path, 404),
            ThreatDecision::InstantBan(ThreatCategory::Vcs)
        );
    }
}

#[test]
fn test_stage2_dotfiles_ssh_and_ide() {
    assert_eq!(
        inspect_threat("GET", "/.ssh/id_rsa", 404),
        ThreatDecision::SharedStrike {
            category: ThreatCategory::Ssh,
            threshold: 2,
            window_secs: 10,
        }
    );
    assert_eq!(
        inspect_threat("POST", "/.ssh/id_rsa", 404),
        ThreatDecision::InstantBan(ThreatCategory::Ssh)
    );
    assert_eq!(
        inspect_threat("GET", "/.ssh/authorized_keys", 404),
        ThreatDecision::InstantBan(ThreatCategory::Ssh)
    );
    assert_eq!(
        inspect_threat("GET", "/.vscode/sftp.json", 404),
        ThreatDecision::InstantBan(ThreatCategory::Ide)
    );
    assert_eq!(
        inspect_threat("GET", "/.idea/workspace.xml", 404),
        ThreatDecision::InstantBan(ThreatCategory::Ide)
    );
    assert_eq!(
        inspect_threat("GET", "/.cursorrules", 404),
        ThreatDecision::InstantBan(ThreatCategory::Ide)
    );
}

#[test]
fn test_stage2_dotfiles_cloud() {
    assert_eq!(
        inspect_threat("GET", "/.aws/credentials", 404),
        ThreatDecision::InstantBan(ThreatCategory::Cloud)
    );
    assert_eq!(
        inspect_threat("GET", "/.azure/credentials", 404),
        ThreatDecision::InstantBan(ThreatCategory::Cloud)
    );
    assert_eq!(
        inspect_threat("GET", "/.kube/config", 404),
        ThreatDecision::InstantBan(ThreatCategory::Cloud)
    );
    assert_eq!(
        inspect_threat("GET", "/.docker/config.json", 404),
        ThreatDecision::InstantBan(ThreatCategory::Cloud)
    );
    assert_eq!(
        inspect_threat("GET", "/.oci/config", 404),
        ThreatDecision::InstantBan(ThreatCategory::Cloud)
    );
    assert_eq!(
        inspect_threat("GET", "/.config/gcloud/credentials", 404),
        ThreatDecision::SharedStrike {
            category: ThreatCategory::Cloud,
            threshold: 3,
            window_secs: 10,
        }
    );
    assert_eq!(
        inspect_threat("POST", "/.config/gcloud/credentials", 404),
        ThreatDecision::InstantBan(ThreatCategory::Cloud)
    );
}

#[test]
fn test_stage2_dotfiles_common_and_wordpress() {
    assert_eq!(
        inspect_threat("GET", "/.env", 404),
        ThreatDecision::SharedStrike {
            category: ThreatCategory::Common,
            threshold: 3,
            window_secs: 10,
        }
    );
    assert_eq!(
        inspect_threat("POST", "/.env", 404),
        ThreatDecision::InstantBan(ThreatCategory::Common)
    );
    assert_eq!(
        inspect_threat("GET", "/.env.production", 404),
        ThreatDecision::SharedStrike {
            category: ThreatCategory::Common,
            threshold: 3,
            window_secs: 10,
        }
    );
    assert_eq!(
        inspect_threat("GET", "/app/.flaskenv", 404),
        ThreatDecision::SharedStrike {
            category: ThreatCategory::Common,
            threshold: 3,
            window_secs: 10,
        }
    );
    assert_eq!(
        inspect_threat("GET", "/.wp-config.php.swp", 404),
        ThreatDecision::InstantBan(ThreatCategory::Wordpress)
    );
    assert_eq!(
        inspect_threat("GET", "/.wp-config.php.bak", 403),
        ThreatDecision::InstantBan(ThreatCategory::Wordpress)
    );
}

#[test]
fn test_stage3_clean_traffic_fast_exit() {
    assert_eq!(
        inspect_threat("GET", "/api/v1/users", 200),
        ThreatDecision::Pass
    );
    assert_eq!(inspect_threat("POST", "/login", 200), ThreatDecision::Pass);
    assert_eq!(
        inspect_threat("GET", "/assets/app.js", 304),
        ThreatDecision::Pass
    );
    assert_eq!(
        inspect_threat("GET", "/wp-login.php", 200),
        ThreatDecision::Pass
    );
    assert_eq!(
        inspect_threat("GET", "/index.php", 200),
        ThreatDecision::Pass
    );
}

#[test]
fn test_stage4_wordpress() {
    assert_eq!(
        inspect_threat("GET", "/wp-login.php", 404),
        ThreatDecision::SharedStrike {
            category: ThreatCategory::Wordpress,
            threshold: 4,
            window_secs: 10,
        }
    );
    assert_eq!(
        inspect_threat("GET", "/wp-l0gin.php", 404),
        ThreatDecision::InstantBan(ThreatCategory::Wordpress)
    );
    assert_eq!(
        inspect_threat("GET", "/wp-signup.php", 400),
        ThreatDecision::InstantBan(ThreatCategory::Wordpress)
    );
    assert_eq!(
        inspect_threat("GET", "/wp-admin/plugins.php", 403),
        ThreatDecision::IsolatedStrike {
            category: ThreatCategory::Wordpress,
            threshold: 7,
            window_secs: 10,
        }
    );
    assert_eq!(
        inspect_threat("POST", "/wp-admin/plugins.php", 403),
        ThreatDecision::IsolatedStrike {
            category: ThreatCategory::Wordpress,
            threshold: 5,
            window_secs: 10,
        }
    );
    assert_eq!(
        inspect_threat("GET", "/wp-config.php.bak", 404),
        ThreatDecision::InstantBan(ThreatCategory::Wordpress)
    );
    assert_eq!(
        inspect_threat("GET", "/wp-konfig.php", 404),
        ThreatDecision::InstantBan(ThreatCategory::Wordpress)
    );
    assert_eq!(
        inspect_threat("GET", "/xmlrpc.php", 404),
        ThreatDecision::InstantBan(ThreatCategory::Wordpress)
    );
    assert_eq!(
        inspect_threat("GET", "/wp-includes/css/style.css", 404),
        ThreatDecision::IsolatedStrike {
            category: ThreatCategory::Wordpress,
            threshold: 7,
            window_secs: 10,
        }
    );
    assert_eq!(
        inspect_threat("GET", "/wlwmanifest.xml", 404),
        ThreatDecision::SharedStrike {
            category: ThreatCategory::Wordpress,
            threshold: 2,
            window_secs: 10,
        }
    );
    assert_eq!(
        inspect_threat("GET", "/wp_filemanager/dialog.php", 404),
        ThreatDecision::InstantBan(ThreatCategory::Wordpress)
    );
    assert_eq!(
        inspect_threat("GET", "/wp-file-manager/lib.php", 404),
        ThreatDecision::InstantBan(ThreatCategory::Wordpress)
    );
    assert_eq!(
        inspect_threat("GET", "/plugins/woocommerce_stripe_checkout", 404),
        ThreatDecision::InstantBan(ThreatCategory::Wordpress)
    );
    assert_eq!(
        inspect_threat("GET", "/wp-json/wp/v2/users", 444),
        ThreatDecision::InstantBan(ThreatCategory::Wordpress)
    );
    assert_eq!(
        inspect_threat("GET", "/wp-manager.php", 404),
        ThreatDecision::InstantBan(ThreatCategory::Wordpress)
    );
}

#[test]
fn test_stage4_actuator_php_laravel_webmail() {
    assert_eq!(
        inspect_threat("GET", "/actuator/env", 404),
        ThreatDecision::InstantBan(ThreatCategory::Actuator)
    );
    assert_eq!(
        inspect_threat("GET", "/actuator/health", 404),
        ThreatDecision::SharedStrike {
            category: ThreatCategory::Actuator,
            threshold: 3,
            window_secs: 10,
        }
    );
    assert_eq!(
        inspect_threat("GET", "/cgi-bin/printenv.pl", 404),
        ThreatDecision::SharedStrike {
            category: ThreatCategory::Php,
            threshold: 3,
            window_secs: 10,
        }
    );
    assert_eq!(
        inspect_threat("POST", "/cgi-bin/printenv.pl", 404),
        ThreatDecision::InstantBan(ThreatCategory::Php)
    );
    assert_eq!(
        inspect_threat("GET", "/phpinfo.php", 404),
        ThreatDecision::InstantBan(ThreatCategory::Php)
    );
    assert_eq!(
        inspect_threat("GET", "/config.php~", 404),
        ThreatDecision::InstantBan(ThreatCategory::Php)
    );
    assert_eq!(
        inspect_threat("GET", "/phpmyadmin/index.php", 404),
        ThreatDecision::SharedStrike {
            category: ThreatCategory::Php,
            threshold: 3,
            window_secs: 15,
        }
    );
    assert_eq!(
        inspect_threat("GET", "/pma/scripts/setup.php", 404),
        ThreatDecision::SharedStrike {
            category: ThreatCategory::Php,
            threshold: 3,
            window_secs: 15,
        }
    );
    assert_eq!(
        inspect_threat("GET", "/adminer.php", 404),
        ThreatDecision::SharedStrike {
            category: ThreatCategory::Php,
            threshold: 3,
            window_secs: 15,
        }
    );
    assert_eq!(
        inspect_threat("GET", "/app/index.php", 404),
        ThreatDecision::IsolatedStrike {
            category: ThreatCategory::Php,
            threshold: 15,
            window_secs: 10,
        }
    );
    assert_eq!(
        inspect_threat("GET", "/test<?phpinfo();?>", 500),
        ThreatDecision::SharedStrike {
            category: ThreatCategory::Php,
            threshold: 3,
            window_secs: 10,
        }
    );
    assert_eq!(
        inspect_threat("GET", "/telescope/requests", 404),
        ThreatDecision::SharedStrike {
            category: ThreatCategory::Laravel,
            threshold: 2,
            window_secs: 10,
        }
    );
    assert_eq!(
        inspect_threat("GET", "/horizon/dashboard", 404),
        ThreatDecision::SharedStrike {
            category: ThreatCategory::Laravel,
            threshold: 2,
            window_secs: 10,
        }
    );
    assert_eq!(
        inspect_threat("GET", "/roundcube/", 404),
        ThreatDecision::SharedStrike {
            category: ThreatCategory::Webmail,
            threshold: 3,
            window_secs: 15,
        }
    );
    assert_eq!(
        inspect_threat("GET", "/webmail/", 404),
        ThreatDecision::SharedStrike {
            category: ThreatCategory::Webmail,
            threshold: 3,
            window_secs: 15,
        }
    );
    assert_eq!(
        inspect_threat("GET", "/horde/login.php", 404),
        ThreatDecision::SharedStrike {
            category: ThreatCategory::Webmail,
            threshold: 3,
            window_secs: 15,
        }
    );
}

#[test]
fn test_stage4_backups_and_common_errors() {
    assert_eq!(
        inspect_threat("GET", "/backup.sql", 404),
        ThreatDecision::IsolatedStrike {
            category: ThreatCategory::Backups,
            threshold: 5,
            window_secs: 10,
        }
    );
    assert_eq!(
        inspect_threat("GET", "/site-backup.zip", 404),
        ThreatDecision::IsolatedStrike {
            category: ThreatCategory::Backups,
            threshold: 5,
            window_secs: 10,
        }
    );
    assert_eq!(
        inspect_threat("GET", "/database.tar.gz", 404),
        ThreatDecision::IsolatedStrike {
            category: ThreatCategory::Backups,
            threshold: 5,
            window_secs: 10,
        }
    );
    assert_eq!(
        inspect_threat("GET", "/etc/passwd", 404),
        ThreatDecision::SharedStrike {
            category: ThreatCategory::Common,
            threshold: 3,
            window_secs: 10,
        }
    );
    assert_eq!(
        inspect_threat("POST", "/etc/passwd", 404),
        ThreatDecision::InstantBan(ThreatCategory::Common)
    );
    assert_eq!(
        inspect_threat("GET", "/proc/1/status", 404),
        ThreatDecision::InstantBan(ThreatCategory::Common)
    );
    assert_eq!(
        inspect_threat("GET", "/boot.ini", 404),
        ThreatDecision::SharedStrike {
            category: ThreatCategory::Common,
            threshold: 3,
            window_secs: 10,
        }
    );
    assert_eq!(
        inspect_threat("GET", "/script.py", 404),
        ThreatDecision::IsolatedStrike {
            category: ThreatCategory::Common,
            threshold: 3,
            window_secs: 10,
        }
    );
    assert_eq!(
        inspect_threat("POST", "/script.py", 404),
        ThreatDecision::InstantBan(ThreatCategory::Common)
    );
    assert_eq!(
        inspect_threat("GET", "/boaform/admin/formLogin", 404),
        ThreatDecision::InstantBan(ThreatCategory::Common)
    );
    assert_eq!(
        inspect_threat("GET", "/nbproject/private/private.xml", 404),
        ThreatDecision::InstantBan(ThreatCategory::Ide)
    );
    assert_eq!(
        inspect_threat("GET", "/var/run/secrets/token", 404),
        ThreatDecision::InstantBan(ThreatCategory::Cloud)
    );
    assert_eq!(
        inspect_threat("GET", "/rootkey.csv", 404),
        ThreatDecision::InstantBan(ThreatCategory::Cloud)
    );
    assert_eq!(
        inspect_threat("GET", "/credentials.json", 404),
        ThreatDecision::SharedStrike {
            category: ThreatCategory::Cloud,
            threshold: 2,
            window_secs: 10,
        }
    );
    assert_eq!(
        inspect_threat("GET", "/sa.json", 404),
        ThreatDecision::SharedStrike {
            category: ThreatCategory::Cloud,
            threshold: 2,
            window_secs: 10,
        }
    );
    assert_eq!(
        inspect_threat("GET", "/id_rsa", 404),
        ThreatDecision::SharedStrike {
            category: ThreatCategory::Ssh,
            threshold: 2,
            window_secs: 10,
        }
    );
    assert_eq!(
        inspect_threat("GET", "/id_ed25519", 404),
        ThreatDecision::SharedStrike {
            category: ThreatCategory::Ssh,
            threshold: 2,
            window_secs: 10,
        }
    );
    assert_eq!(
        inspect_threat("GET", "/not-found-page", 404),
        ThreatDecision::Pass
    );
}
