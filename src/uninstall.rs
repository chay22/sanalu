use crate::cloudflare::CloudflareClient;
use crate::config::AppConfig;
use crate::daemon::is_root;
use crate::error::SanaluError;
use std::io::Write;
use std::path::Path;
use std::process::Command;

pub struct UninstallOptions {
    pub purge: bool,
    pub clean_cloudflare: bool,
    pub dry_run: bool,
}

pub fn remove_service_files<W: Write>(out: &mut W, dry_run: bool) -> Result<(), SanaluError> {
    if !dry_run {
        let _ = Command::new("systemctl").args(["stop", "sanalu"]).output();
        let _ = Command::new("systemctl")
            .args(["disable", "sanalu"])
            .output();
    }
    let service_paths = [
        Path::new("/lib/systemd/system/sanalu.service"),
        Path::new("/etc/systemd/system/sanalu.service"),
    ];
    for p in service_paths {
        if p.exists() {
            if dry_run {
                let _ = writeln!(out, "[dry-run] Would remove systemd unit: {:?}", p);
            } else {
                std::fs::remove_file(p)?;
                let _ = writeln!(out, "[x] Removed systemd unit: {:?}", p);
            }
        }
    }
    if !dry_run {
        let _ = Command::new("systemctl").args(["daemon-reload"]).output();
        let _ = Command::new("systemctl").args(["reset-failed"]).output();
    }
    Ok(())
}

pub fn remove_firewall_table<W: Write>(out: &mut W, dry_run: bool) -> Result<(), SanaluError> {
    if dry_run {
        let _ = writeln!(out, "[dry-run] Would remove nftables table 'inet sanalu'");
        return Ok(());
    }
    let output = Command::new("nft")
        .args(["delete", "table", "inet", "sanalu"])
        .output();
    match output {
        Ok(res) if res.status.success() => {
            let _ = writeln!(out, "[x] Removed nftables table 'inet sanalu'.");
        }
        _ => {
            let _ = writeln!(
                out,
                "[i] Table 'inet sanalu' was not found or already removed."
            );
        }
    }
    Ok(())
}

pub fn remove_completions<W: Write>(out: &mut W, dry_run: bool) -> Result<(), SanaluError> {
    let candidate_files = [
        Path::new("/etc/profile.d/sanalu.sh"),
        Path::new("/etc/bash_completion.d/sanalu"),
        Path::new("/usr/share/bash-completion/completions/sanalu"),
        Path::new("/usr/share/zsh/vendor-completions/_sanalu"),
        Path::new("/usr/share/zsh/site-functions/_sanalu"),
        Path::new("/usr/local/share/zsh/site-functions/_sanalu"),
        Path::new("/usr/share/fish/vendor_completions.d/sanalu.fish"),
        Path::new("/etc/fish/completions/sanalu.fish"),
    ];

    for file in candidate_files {
        if file.exists() {
            if dry_run {
                let _ = writeln!(out, "[dry-run] Would remove completion file: {:?}", file);
            } else {
                std::fs::remove_file(file)?;
                let _ = writeln!(out, "[x] Removed completion file: {:?}", file);
            }
        }
    }
    Ok(())
}

pub fn remove_data_dir<W: Write>(
    out: &mut W,
    db_path: &Path,
    dry_run: bool,
) -> Result<(), SanaluError> {
    let data_dir = db_path
        .parent()
        .unwrap_or_else(|| Path::new("/var/lib/sanalu"));
    if data_dir.exists() {
        if dry_run {
            let _ = writeln!(out, "[dry-run] Would remove data directory: {:?}", data_dir);
        } else {
            std::fs::remove_dir_all(data_dir)?;
            let _ = writeln!(out, "[x] Removed data directory: {:?}", data_dir);
        }
    }
    Ok(())
}

pub fn remove_config_dir<W: Write>(
    out: &mut W,
    config_path: &Path,
    purge: bool,
    dry_run: bool,
) -> Result<(), SanaluError> {
    let config_dir = config_path
        .parent()
        .unwrap_or_else(|| Path::new("/etc/sanalu"));
    if !config_dir.exists() {
        return Ok(());
    }
    if purge {
        if dry_run {
            let _ = writeln!(
                out,
                "[dry-run] Would purge configuration directory: {:?}",
                config_dir
            );
        } else {
            std::fs::remove_dir_all(config_dir)?;
            let _ = writeln!(out, "[x] Purged configuration directory: {:?}", config_dir);
        }
    } else {
        let _ = writeln!(
            out,
            "[i] Preserved configuration at {:?}. (Pass '--purge' to delete configuration).",
            config_dir
        );
    }
    Ok(())
}

pub async fn clean_cloudflare<W: Write>(
    out: &mut W,
    config: &AppConfig,
    dry_run: bool,
) -> Result<(), SanaluError> {
    if !config.cloudflare.enabled || config.cloudflare.api_token.is_empty() {
        return Ok(());
    }
    if dry_run {
        let _ = writeln!(
            out,
            "[dry-run] Would reset Cloudflare WAF rule expression to empty"
        );
        return Ok(());
    }
    let client = CloudflareClient::new(config.cloudflare.clone(), false)?;
    match client.update_waf_rule("").await {
        Ok(_) => {
            let _ = writeln!(out, "[x] Cleared Cloudflare WAF security rule expression.");
        }
        Err(e) => {
            let _ = writeln!(out, "[!] Failed to clear Cloudflare WAF rule: {}", e);
        }
    }
    Ok(())
}

pub fn remove_binary_files<W: Write>(out: &mut W, dry_run: bool) -> Result<(), SanaluError> {
    let known_bin_paths = [
        Path::new("/usr/bin/sanalu"),
        Path::new("/usr/local/bin/sanalu"),
    ];
    for p in known_bin_paths {
        if p.exists() {
            if dry_run {
                let _ = writeln!(out, "[dry-run] Would remove binary executable: {:?}", p);
            } else {
                let _ = std::fs::remove_file(p);
                let _ = writeln!(out, "[x] Removed binary: {:?}", p);
            }
        }
    }
    if let Ok(current) = std::env::current_exe() {
        if !known_bin_paths.contains(&current.as_path()) && current.exists() {
            if dry_run {
                let _ = writeln!(out, "[dry-run] Would remove current binary: {:?}", current);
            } else {
                let _ = std::fs::remove_file(&current);
                let _ = writeln!(out, "[x] Removed current binary: {:?}", current);
            }
        }
    }
    Ok(())
}

pub async fn execute_uninstall<W: Write>(
    out: &mut W,
    config_path: &Path,
    config: &AppConfig,
    options: &UninstallOptions,
) -> Result<(), SanaluError> {
    if !options.dry_run && !is_root() {
        return Err(SanaluError::Config(
            "Uninstall requires root privileges. Please run with 'sudo sanalu uninstall'.".into(),
        ));
    }

    let _ = writeln!(out, "=== Starting Sanalu Uninstallation ===");
    if options.dry_run {
        let _ = writeln!(
            out,
            "(Dry-run mode: simulating actions without changing the system)\n"
        );
    }

    remove_service_files(out, options.dry_run)?;
    remove_firewall_table(out, options.dry_run)?;
    remove_completions(out, options.dry_run)?;

    if options.clean_cloudflare {
        clean_cloudflare(out, config, options.dry_run).await?;
    }

    remove_data_dir(out, &config.general.db_path, options.dry_run)?;
    remove_config_dir(out, config_path, options.purge, options.dry_run)?;
    remove_binary_files(out, options.dry_run)?;

    let _ = writeln!(out, "\n=== Sanalu Uninstallation Finished ===");
    Ok(())
}
