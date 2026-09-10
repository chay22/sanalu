use super::admin::{
    handle_ban_command, handle_cloudflare, handle_policy_command, handle_test_log, handle_unban,
    handle_uninstall, handle_update_db,
};
pub use super::query::generate_completions;
use super::query::{
    handle_check, handle_completions, handle_discover, handle_status, handle_version,
};
use crate::cli::args::{Cli, Commands};
use crate::config::AppConfig;
use crate::daemon::run_daemon;
use std::io::Write;

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
