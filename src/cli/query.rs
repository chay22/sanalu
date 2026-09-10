use crate::cli::args::Cli;
use crate::config::AppConfig;
use crate::discovery::discover_environment;
use crate::ipc::protocol::IpcRequest;
use clap::CommandFactory;
use std::io::{IsTerminal, Write};
use std::path::Path;

pub async fn run_ipc_or_offline<F>(
    socket_path: &Path,
    req: IpcRequest,
    offline_fallback: F,
) -> Result<String, Box<dyn std::error::Error>>
where
    F: FnOnce() -> Result<String, Box<dyn std::error::Error>>,
{
    match crate::ipc::try_send_request(socket_path, &req).await {
        Ok(resp) => {
            if resp.success {
                Ok(resp.output)
            } else {
                Err(resp
                    .error
                    .unwrap_or_else(|| "Unknown IPC error".into())
                    .into())
            }
        }
        Err(err) => {
            if crate::ipc::is_offline_error(&err) {
                offline_fallback()
            } else {
                Err(err.into())
            }
        }
    }
}

pub async fn handle_status<W: Write>(
    out: &mut W,
    db_path: &Path,
    socket_path: &Path,
    config: &AppConfig,
) -> Result<(), Box<dyn std::error::Error>> {
    let output = run_ipc_or_offline(socket_path, IpcRequest::Status, || {
        if !db_path.exists() {
            return Ok(format!(
                "Database not found at {:?}. Has sanalu been run?\n",
                db_path
            ));
        }
        Ok(crate::ipc::execute_offline_status(db_path, Some(config))?)
    })
    .await?;
    let _ = write!(out, "{}", output);
    Ok(())
}

pub async fn handle_check<W: Write>(
    out: &mut W,
    db_path: &Path,
    socket_path: &Path,
    target: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let req = IpcRequest::Check {
        target: target.to_string(),
    };
    let output = run_ipc_or_offline(socket_path, req, || {
        Ok(crate::ipc::execute_offline_check(db_path, target)?)
    })
    .await?;
    let _ = write!(out, "{}", output);
    Ok(())
}

pub async fn handle_ban_list<W: Write>(
    out: &mut W,
    db_path: &Path,
    socket_path: &Path,
    all: bool,
    plain: bool,
    filter: Option<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let req = IpcRequest::BanList {
        all,
        plain,
        filter: filter.clone(),
    };
    let output = run_ipc_or_offline(socket_path, req, || {
        Ok(crate::ipc::execute_offline_ban_list(
            db_path, all, plain, filter,
        )?)
    })
    .await?;

    if all && std::io::stdout().is_terminal() {
        let pager_var = std::env::var("PAGER").unwrap_or_else(|_| "less -R".to_string());
        let mut parts = pager_var.split_whitespace();
        if let Some(bin) = parts.next() {
            let mut cmd = std::process::Command::new(bin);
            cmd.args(parts).stdin(std::process::Stdio::piped());
            if let Ok(mut child) = cmd.spawn() {
                if let Some(mut stdin) = child.stdin.take() {
                    let _ = stdin.write_all(output.as_bytes());
                }
                let _ = child.wait();
                return Ok(());
            }
        }
    }

    let _ = write!(out, "{}", output);
    Ok(())
}

pub fn generate_completions<W: Write>(shell: clap_complete::Shell, buf: &mut W) {
    let mut cmd = Cli::command();
    clap_complete::generate(shell, &mut cmd, "sanalu", buf);
}

pub fn handle_completions<W: Write>(out: &mut W, shell: clap_complete::Shell) {
    generate_completions(shell, out);
}

pub fn handle_discover<W: Write>(out: &mut W) {
    let env_info = discover_environment();
    let _ = writeln!(out, "=== Environment Discovery ===");
    let _ = writeln!(
        out,
        "Nginx Access Logs found: {}",
        env_info.nginx_logs.len()
    );
    for l in &env_info.nginx_logs {
        let _ = writeln!(out, "  - {:?} (format: {:?})", l.path, l.format_kind);
    }
    let _ = writeln!(
        out,
        "Nginx Error Logs found: {}",
        env_info.nginx_error_logs.len()
    );
    for e in &env_info.nginx_error_logs {
        let _ = writeln!(out, "  - {:?}", e);
    }
    let _ = writeln!(out, "SSH Source: {:?}", env_info.ssh_source);
}

pub fn handle_version<W: Write>(
    out: &mut W,
    short: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let version = env!("CARGO_PKG_VERSION");
    if short {
        let _ = writeln!(out, "{}", version);
    } else {
        let arch = std::env::consts::ARCH;
        let os = std::env::consts::OS;
        let _ = writeln!(out, "sanalu {} ({}-{})", version, arch, os);
        let _ = writeln!(out, "Repository: https://github.com/chay22/sanalu");
        let _ = writeln!(out, "License:    MIT OR Apache-2.0");
    }
    Ok(())
}
