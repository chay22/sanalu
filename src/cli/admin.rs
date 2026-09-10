use super::query::run_ipc_or_offline;
use crate::cli::args::{CloudflareCommands, Commands};
use crate::config::AppConfig;
use crate::engine::replay_log_file;
use crate::geo::download_ip2asn_db;
use crate::ipc::protocol::IpcRequest;
use std::io::Write;
use std::path::Path;

pub use super::ban::{handle_ban, handle_ban_command, handle_unban};

pub async fn handle_policy_command<W: Write>(
    out: &mut W,
    db_path: &Path,
    socket_path: &Path,
    cmd: &Commands,
) -> Result<(), Box<dyn std::error::Error>> {
    let output = match cmd {
        Commands::Whitelist { action } => {
            let req = IpcRequest::Whitelist {
                action: action.clone(),
            };
            let act = action.clone();
            run_ipc_or_offline(socket_path, req, || {
                Ok(crate::ipc::execute_offline_whitelist(db_path, act)?)
            })
            .await?
        }
        Commands::Category { action } => {
            let req = IpcRequest::Category {
                action: action.clone(),
            };
            let act = action.clone();
            run_ipc_or_offline(socket_path, req, || {
                Ok(crate::ipc::execute_offline_category(db_path, act)?)
            })
            .await?
        }
        Commands::Asn { action } => {
            let req = IpcRequest::Asn {
                action: action.clone(),
            };
            let act = action.clone();
            run_ipc_or_offline(socket_path, req, || {
                Ok(crate::ipc::execute_offline_asn(db_path, act)?)
            })
            .await?
        }
        Commands::Region { action } => {
            let req = IpcRequest::Region {
                action: action.clone(),
            };
            let act = action.clone();
            run_ipc_or_offline(socket_path, req, || {
                Ok(crate::ipc::execute_offline_region(db_path, act)?)
            })
            .await?
        }
        _ => return Ok(()),
    };
    let _ = write!(out, "{}", output);
    Ok(())
}

pub async fn handle_cloudflare<W: Write>(
    out: &mut W,
    db_path: &Path,
    socket_path: &Path,
    config: &AppConfig,
    action: CloudflareCommands,
) -> Result<(), Box<dyn std::error::Error>> {
    let req = IpcRequest::Cloudflare {
        action: action.clone(),
    };
    let output = match crate::ipc::try_send_request(socket_path, &req).await {
        Ok(resp) => {
            if resp.success {
                resp.output
            } else {
                return Err(resp
                    .error
                    .unwrap_or_else(|| "Unknown IPC error".into())
                    .into());
            }
        }
        Err(err) => {
            if crate::ipc::is_offline_error(&err) {
                crate::ipc::execute_offline_cloudflare(db_path, action, config).await?
            } else {
                return Err(err.into());
            }
        }
    };
    let _ = write!(out, "{}", output);
    Ok(())
}

pub async fn handle_update_db<W: Write>(out: &mut W) -> Result<(), Box<dyn std::error::Error>> {
    let _ = writeln!(out, "Downloading latest IP-to-ASN/Country database...");
    let url = "https://iptoasn.com/data/ip2asn-v4.tsv.gz";
    let _db = download_ip2asn_db(url).await?;
    let _ = writeln!(out, "Database downloaded and loaded successfully.");
    Ok(())
}

pub fn handle_test_log<W: Write>(
    out: &mut W,
    path: &Path,
    allowed_endpoints: &[String],
) -> Result<(), Box<dyn std::error::Error>> {
    let _ = writeln!(out, "Replaying log file: {:?}", path);
    let count = replay_log_file(path, allowed_endpoints)?;
    let _ = writeln!(out, "Replay finished: {} threats/attacks detected.", count);
    Ok(())
}

pub async fn handle_uninstall<W: Write>(
    out: &mut W,
    config_path: &Path,
    config: &AppConfig,
    purge: bool,
    clean_cf: bool,
    dry_run: bool,
    yes: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    if !yes && !dry_run {
        let _ = write!(out, "Are you sure you want to uninstall sanalu? [y/N]: ");
        let _ = out.flush();
        let mut input = String::new();
        std::io::stdin().read_line(&mut input)?;
        let trimmed = input.trim().to_lowercase();
        if trimmed != "y" && trimmed != "yes" {
            let _ = writeln!(out, "Uninstall cancelled.");
            return Ok(());
        }
    }
    let options = crate::uninstall::UninstallOptions {
        purge,
        clean_cloudflare: clean_cf,
        dry_run,
    };
    crate::uninstall::execute_uninstall(out, config_path, config, &options).await?;
    Ok(())
}
