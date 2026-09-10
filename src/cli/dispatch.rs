use crate::cli::args::{BanCommands, Cli, CloudflareCommands, Commands};
use crate::config::AppConfig;
use crate::daemon::{is_root, replay_log_file, run_daemon};
use crate::discovery::discover_environment;
use crate::firewall::NftablesBackend;
use crate::geo::download_ip2asn_db;
use crate::ipc::handlers;
use crate::ipc::protocol::IpcRequest;
use crate::storage::RedbStore;
use clap::CommandFactory;
use std::io::{IsTerminal, Write};
use std::path::Path;

pub async fn dispatch_cli<W: Write>(
    out: &mut W,
    cli: &Cli,
    config: &AppConfig,
) -> Result<(), Box<dyn std::error::Error>> {
    let db_path = &config.general.db_path;
    let socket_path = &config.general.socket_path;

    match &cli.command {
        Commands::Run { dry_run } => {
            run_daemon(&cli.config, *dry_run).await?;
        }
        Commands::Status => {
            handle_status(out, db_path, socket_path, config).await?;
        }
        Commands::Ban {
            action,
            target,
            reason,
        } => {
            handle_ban_command(
                out,
                db_path,
                socket_path,
                action.clone(),
                target.clone(),
                reason.clone(),
            )
            .await?;
        }
        Commands::Unban { target } => {
            handle_unban(out, db_path, socket_path, target).await?;
        }
        Commands::Check { target } => {
            handle_check(out, db_path, socket_path, target).await?;
        }
        Commands::Cloudflare { action } => {
            handle_cloudflare(out, db_path, socket_path, config, action.clone()).await?;
        }
        Commands::Completions { shell } => {
            handle_completions(out, *shell);
        }
        Commands::Uninstall {
            purge,
            clean_cloudflare,
            dry_run,
            yes,
        } => {
            handle_uninstall(
                out,
                &cli.config,
                config,
                *purge,
                *clean_cloudflare,
                *dry_run,
                *yes,
            )
            .await?;
        }
        Commands::Version { short } => {
            handle_version(out, *short)?;
        }
        cmd @ (Commands::Whitelist { .. }
        | Commands::Category { .. }
        | Commands::Asn { .. }
        | Commands::Region { .. }) => {
            handle_policy_command(out, db_path, socket_path, cmd).await?;
        }
        Commands::Discover => {
            handle_discover(out);
        }
        Commands::UpdateDb => {
            handle_update_db(out).await?;
        }
        Commands::TestLog { path } => {
            handle_test_log(out, path, &config.nginx.allowed_endpoints)?;
        }
    }

    Ok(())
}

async fn run_ipc_or_offline<F>(
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

async fn handle_status<W: Write>(
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
        let store = RedbStore::open(db_path)?;
        let mut buf = Vec::new();
        handlers::format_status(&mut buf, &store, db_path, Some(config))?;
        Ok(String::from_utf8(buf)?)
    })
    .await?;
    let _ = write!(out, "{}", output);
    Ok(())
}

async fn handle_ban_command<W: Write>(
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
                handle_ban_list(out, db_path, socket_path, all, plain, filter).await?;
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

async fn handle_ban<W: Write>(
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
        let store = RedbStore::open(db_path)?;
        let fw = NftablesBackend::auto_detect(!is_root());
        let mut buf = Vec::new();
        handlers::execute_ban(&mut buf, &store, &fw, target, reason)?;
        Ok(String::from_utf8(buf)?)
    })
    .await?;
    let _ = write!(out, "{}", output);
    Ok(())
}

async fn handle_unban<W: Write>(
    out: &mut W,
    db_path: &Path,
    socket_path: &Path,
    target: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let req = IpcRequest::Unban {
        target: target.to_string(),
    };
    let output = run_ipc_or_offline(socket_path, req, || {
        let store = RedbStore::open(db_path)?;
        let fw = NftablesBackend::auto_detect(!is_root());
        let mut buf = Vec::new();
        handlers::execute_unban(&mut buf, &store, &fw, target)?;
        Ok(String::from_utf8(buf)?)
    })
    .await?;
    let _ = write!(out, "{}", output);
    Ok(())
}

async fn handle_ban_list<W: Write>(
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
        let store = RedbStore::open(db_path)?;
        let mut buf = Vec::new();
        handlers::format_ban_list(&mut buf, &store, all, plain, filter)?;
        Ok(String::from_utf8(buf)?)
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

async fn handle_check<W: Write>(
    out: &mut W,
    db_path: &Path,
    socket_path: &Path,
    target: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let req = IpcRequest::Check {
        target: target.to_string(),
    };
    let output = run_ipc_or_offline(socket_path, req, || {
        let store = RedbStore::open(db_path)?;
        let mut buf = Vec::new();
        handlers::format_check(&mut buf, &store, target)?;
        Ok(String::from_utf8(buf)?)
    })
    .await?;
    let _ = write!(out, "{}", output);
    Ok(())
}

async fn handle_policy_command<W: Write>(
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
                let store = RedbStore::open(db_path)?;
                let mut buf = Vec::new();
                handlers::execute_whitelist(&mut buf, &store, act)?;
                Ok(String::from_utf8(buf)?)
            })
            .await?
        }
        Commands::Category { action } => {
            let req = IpcRequest::Category {
                action: action.clone(),
            };
            let act = action.clone();
            run_ipc_or_offline(socket_path, req, || {
                let store = RedbStore::open(db_path)?;
                let mut buf = Vec::new();
                handlers::execute_category(&mut buf, &store, act)?;
                Ok(String::from_utf8(buf)?)
            })
            .await?
        }
        Commands::Asn { action } => {
            let req = IpcRequest::Asn {
                action: action.clone(),
            };
            let act = action.clone();
            run_ipc_or_offline(socket_path, req, || {
                let store = RedbStore::open(db_path)?;
                let mut buf = Vec::new();
                handlers::execute_asn(&mut buf, &store, act)?;
                Ok(String::from_utf8(buf)?)
            })
            .await?
        }
        Commands::Region { action } => {
            let req = IpcRequest::Region {
                action: action.clone(),
            };
            let act = action.clone();
            run_ipc_or_offline(socket_path, req, || {
                let store = RedbStore::open(db_path)?;
                let mut buf = Vec::new();
                handlers::execute_region(&mut buf, &store, act)?;
                Ok(String::from_utf8(buf)?)
            })
            .await?
        }
        _ => return Ok(()),
    };
    let _ = write!(out, "{}", output);
    Ok(())
}

async fn handle_cloudflare<W: Write>(
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
                let store = RedbStore::open(db_path)?;
                let mut buf = Vec::new();
                handlers::execute_cloudflare(&mut buf, &store, config, action).await?;
                String::from_utf8(buf)?
            } else {
                return Err(err.into());
            }
        }
    };
    let _ = write!(out, "{}", output);
    Ok(())
}

pub fn generate_completions<W: Write>(shell: clap_complete::Shell, buf: &mut W) {
    let mut cmd = Cli::command();
    clap_complete::generate(shell, &mut cmd, "sanalu", buf);
}

fn handle_completions<W: Write>(out: &mut W, shell: clap_complete::Shell) {
    generate_completions(shell, out);
}

fn handle_discover<W: Write>(out: &mut W) {
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

async fn handle_update_db<W: Write>(out: &mut W) -> Result<(), Box<dyn std::error::Error>> {
    let _ = writeln!(out, "Downloading latest IP-to-ASN/Country database...");
    let url = "https://iptoasn.com/data/ip2asn-v4.tsv.gz";
    let _db = download_ip2asn_db(url).await?;
    let _ = writeln!(out, "Database downloaded and loaded successfully.");
    Ok(())
}

fn handle_test_log<W: Write>(
    out: &mut W,
    path: &Path,
    allowed_endpoints: &[String],
) -> Result<(), Box<dyn std::error::Error>> {
    let _ = writeln!(out, "Replaying log file: {:?}", path);
    let count = replay_log_file(path, allowed_endpoints)?;
    let _ = writeln!(out, "Replay finished: {} threats/attacks detected.", count);
    Ok(())
}

async fn handle_uninstall<W: Write>(
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

fn handle_version<W: Write>(out: &mut W, short: bool) -> Result<(), Box<dyn std::error::Error>> {
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
