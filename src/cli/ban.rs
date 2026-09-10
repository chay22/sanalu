use super::query::run_ipc_or_offline;
use crate::cli::args::BanCommands;
use crate::discovery::is_root;
use crate::ipc::protocol::IpcRequest;
use std::io::Write;
use std::path::Path;

pub async fn handle_ban_command<W: Write>(
    out: &mut W,
    db_path: &Path,
    socket_path: &Path,
    action: Option<BanCommands>,
    target: Option<String>,
    reason: Option<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    if let Some(act) = action {
        match act {
            BanCommands::List { all, plain, filter } => {
                super::query::handle_ban_list(out, db_path, socket_path, all, plain, filter)
                    .await?;
            }
            BanCommands::Add { target, reason } => {
                handle_ban(out, db_path, socket_path, &target, reason).await?;
            }
        }
    } else if let Some(target) = target {
        handle_ban(out, db_path, socket_path, &target, reason).await?;
    } else {
        let _ = writeln!(
            out,
            "Error: Missing target IP or CIDR. Usage: sanalu ban <target> or sanalu ban list"
        );
    }
    Ok(())
}

pub async fn handle_ban<W: Write>(
    out: &mut W,
    db_path: &Path,
    socket_path: &Path,
    target: &str,
    reason: Option<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let req = IpcRequest::Ban {
        target: target.to_string(),
        reason: reason.clone(),
    };
    let output = run_ipc_or_offline(socket_path, req, || {
        Ok(crate::ipc::execute_offline_ban(
            db_path,
            target,
            reason,
            !is_root(),
        )?)
    })
    .await?;
    let _ = write!(out, "{}", output);
    Ok(())
}

pub async fn handle_unban<W: Write>(
    out: &mut W,
    db_path: &Path,
    socket_path: &Path,
    target: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let req = IpcRequest::Unban {
        target: target.to_string(),
    };
    let output = run_ipc_or_offline(socket_path, req, || {
        Ok(crate::ipc::execute_offline_unban(
            db_path,
            target,
            !is_root(),
        )?)
    })
    .await?;
    let _ = write!(out, "{}", output);
    Ok(())
}
