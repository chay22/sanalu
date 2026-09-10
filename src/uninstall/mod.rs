pub mod cleanup;

pub use cleanup::*;

use crate::cloudflare::CloudflareClient;
use crate::config::AppConfig;
use crate::discovery::is_root;
use crate::error::SanaluError;
use std::io::Write;
use std::path::Path;

pub struct UninstallOptions {
    pub purge: bool,
    pub clean_cloudflare: bool,
    pub dry_run: bool,
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
