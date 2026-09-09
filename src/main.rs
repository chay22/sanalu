use clap::{CommandFactory, Parser};
use sanalu::cli::{
    AsnCommands, BanCommands, CategoryCommands, Cli, CloudflareCommands, Commands, RegionCommands,
    WhitelistCommands,
};
use sanalu::cloudflare::{CloudflareClient, CloudflareRuleBudget};
use sanalu::config::AppConfig;
use sanalu::daemon::{bootstrap_files, is_root, replay_log_file, run_daemon};
use sanalu::discovery::discover_environment;
use sanalu::firewall::{FirewallBackend, NftablesBackend};
use sanalu::geo::download_ip2asn_db;
use sanalu::storage::{RedbStore, StoredBanRecord};
use std::io::{IsTerminal, Write};
use std::net::IpAddr;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    let mut stdout = std::io::stdout();

    let config = if cli.config.exists() {
        let content = std::fs::read_to_string(&cli.config).unwrap_or_default();
        toml::from_str::<AppConfig>(&content).unwrap_or_default()
    } else {
        AppConfig::default()
    };

    let db_path = &config.general.db_path;
    if is_root() {
        let _ = bootstrap_files(&cli.config, db_path);
    }

    match cli.command {
        Commands::Run { dry_run } => {
            run_daemon(&cli.config, dry_run).await?;
        }
        Commands::Status => {
            handle_status(&mut stdout, db_path)?;
        }
        Commands::Ban {
            action,
            target,
            reason,
        } => {
            handle_ban_command(&mut stdout, db_path, action, target, reason)?;
        }
        Commands::Unban { target } => {
            handle_unban(&mut stdout, db_path, &target)?;
        }
        Commands::Check { target } => {
            handle_check(&mut stdout, db_path, &target, &config)?;
        }
        Commands::Cloudflare { action } => {
            handle_cloudflare(&mut stdout, db_path, &config, action).await?;
        }
        Commands::Completions { shell } => {
            handle_completions(&mut stdout, shell);
        }
        Commands::Uninstall {
            purge,
            clean_cloudflare,
            dry_run,
            yes,
        } => {
            handle_uninstall(
                &mut stdout,
                &cli.config,
                &config,
                purge,
                clean_cloudflare,
                dry_run,
                yes,
            )
            .await?;
        }
        Commands::Version { short } => {
            handle_version(&mut stdout, short)?;
        }
        cmd @ (Commands::Whitelist { .. }
        | Commands::Category { .. }
        | Commands::Asn { .. }
        | Commands::Region { .. }) => {
            handle_policy_command(&mut stdout, db_path, cmd)?;
        }
        Commands::Discover => {
            handle_discover(&mut stdout);
        }
        Commands::UpdateDb => {
            handle_update_db(&mut stdout).await?;
        }
        Commands::TestLog { path } => {
            handle_test_log(&mut stdout, &path, &config.nginx.allowed_endpoints)?;
        }
    }

    Ok(())
}

fn handle_ban_command<W: Write>(
    out: &mut W,
    db_path: &Path,
    action: Option<BanCommands>,
    target: Option<String>,
    reason: Option<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    if let Some(act) = action {
        match act {
            BanCommands::List { all, plain, filter } => {
                handle_ban_list(out, db_path, all, plain, filter)?;
            }
            BanCommands::Add { target, reason } => {
                handle_ban(out, db_path, &target, reason)?;
            }
        }
    } else if let Some(target) = target {
        handle_ban(out, db_path, &target, reason)?;
    } else {
        let _ = writeln!(
            out,
            "Error: Missing target IP or CIDR. Usage: sanalu ban <target> or sanalu ban list"
        );
    }
    Ok(())
}

fn handle_policy_command<W: Write>(
    out: &mut W,
    db_path: &Path,
    cmd: Commands,
) -> Result<(), Box<dyn std::error::Error>> {
    match cmd {
        Commands::Whitelist { action } => handle_whitelist(out, db_path, action)?,
        Commands::Category { action } => handle_category(out, db_path, action)?,
        Commands::Asn { action } => handle_asn(out, db_path, action)?,
        Commands::Region { action } => handle_region(out, db_path, action)?,
        _ => {}
    }
    Ok(())
}

fn handle_status<W: Write>(out: &mut W, db_path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    if !db_path.exists() {
        let _ = writeln!(
            out,
            "Database not found at {:?}. Has sanalu been run?",
            db_path
        );
        return Ok(());
    }
    let store = RedbStore::open(db_path)?;
    let _ = writeln!(out, "=== Sanalu Status ===");
    let _ = writeln!(out, "Database: {:?}", db_path);

    let bans = store.list_active_bans().unwrap_or_default();
    let _ = writeln!(out, "\nActive Bans: {}", bans.len());
    for b in bans.iter().take(15) {
        let exp = match b.expires_at_secs {
            Some(s) => format!("expires in {}s", s),
            None => "permanent".to_string(),
        };
        let _ = writeln!(
            out,
            "  - {} (tier {}, {}, reason: {})",
            b.target, b.tier_level, exp, b.reason
        );
    }
    if bans.len() > 15 {
        let _ = writeln!(out, "  ... and {} more", bans.len() - 15);
    }

    let cats = store.list_blocked_categories().unwrap_or_default();
    let _ = writeln!(out, "\nBlocked Categories in DB: {:?}", cats);

    let asns = store.list_blocked_asns().unwrap_or_default();
    let _ = writeln!(out, "Blocked ASNs in DB: {:?}", asns);

    let regions = store.list_allowed_regions().unwrap_or_default();
    let _ = writeln!(out, "Allowed Regions in DB: {:?}", regions);

    let cf_state = store.get_cloudflare_state().unwrap_or_default();
    let _ = writeln!(out, "\nCloudflare Active Expression: {:?}", cf_state);
    Ok(())
}

fn handle_ban<W: Write>(
    out: &mut W,
    db_path: &Path,
    target: &str,
    reason: Option<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let reason_str = reason.unwrap_or_else(|| "manual_cli_ban".into());
    let store = RedbStore::open(db_path)?;
    let now_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let record = StoredBanRecord {
        target: target.to_string(),
        ip: target.parse::<IpAddr>().ok(),
        tier_level: 0,
        banned_at_secs: now_secs,
        expires_at_secs: None,
        reason: reason_str,
    };
    store.save_ban(&record)?;

    let fw = NftablesBackend::auto_detect(!is_root());
    let _ = fw.ban_target(target, None);
    let _ = writeln!(out, "Banned {} successfully.", target);
    Ok(())
}

fn handle_ban_list<W: Write>(
    out: &mut W,
    db_path: &Path,
    all: bool,
    plain: bool,
    filter: Option<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let store = RedbStore::open(db_path)?;
    let mut bans = store.list_active_bans().unwrap_or_default();
    if let Some(f) = filter {
        let f_lower = f.to_lowercase();
        bans.retain(|b| {
            b.target.to_lowercase().contains(&f_lower) || b.reason.to_lowercase().contains(&f_lower)
        });
    }

    if plain {
        for b in &bans {
            let _ = writeln!(out, "{}", b.target);
        }
        return Ok(());
    }

    let total = bans.len();
    let display_limit = if all { total } else { 50.min(total) };
    let mut output_str = String::new();
    output_str.push_str(&format!("=== Active Bans ({total} total) ===\n"));
    for b in bans.iter().take(display_limit) {
        let exp = match b.expires_at_secs {
            Some(s) => format!("expires in {}s", s),
            None => "permanent".to_string(),
        };
        output_str.push_str(&format!(
            "{:<32} tier {:<2} {:<20} reason: {}\n",
            b.target, b.tier_level, exp, b.reason
        ));
    }
    if !all && total > display_limit {
        output_str.push_str(&format!(
            "\nShowing {} of {} active bans. Use '--all' to view all, or '--plain' for machine output.\n",
            display_limit, total
        ));
    }

    if all && std::io::stdout().is_terminal() {
        let pager_var = std::env::var("PAGER").unwrap_or_else(|_| "less -R".to_string());
        let mut parts = pager_var.split_whitespace();
        if let Some(bin) = parts.next() {
            let mut cmd = std::process::Command::new(bin);
            cmd.args(parts).stdin(std::process::Stdio::piped());
            if let Ok(mut child) = cmd.spawn() {
                if let Some(mut stdin) = child.stdin.take() {
                    let _ = stdin.write_all(output_str.as_bytes());
                }
                let _ = child.wait();
                return Ok(());
            }
        }
    }

    let _ = write!(out, "{}", output_str);
    Ok(())
}

fn handle_unban<W: Write>(
    out: &mut W,
    db_path: &Path,
    target: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let store = RedbStore::open(db_path)?;
    store.remove_ban(target)?;

    let fw = NftablesBackend::auto_detect(!is_root());
    let _ = fw.unban_target(target);
    let _ = writeln!(out, "Unbanned {} successfully.", target);
    Ok(())
}

fn handle_check<W: Write>(
    out: &mut W,
    db_path: &Path,
    target: &str,
    _config: &AppConfig,
) -> Result<(), Box<dyn std::error::Error>> {
    let store = RedbStore::open(db_path)?;
    let maybe_ip = target.parse::<IpAddr>().ok();
    let target_kind = if maybe_ip.is_some() {
        "IP"
    } else if target.contains('/') {
        "CIDR"
    } else {
        "Unknown"
    };

    let _ = writeln!(out, "=== Sanalu Target Diagnostics ===");
    let _ = writeln!(out, "Target:            {} ({})", target, target_kind);

    let ban_status = store.check_ban_status(target)?;
    match ban_status {
        Some(record) => {
            let match_type = if record.target == target {
                "Direct Ban"
            } else {
                "Subnet Ban"
            };
            let _ = writeln!(out, "Status:            BANNED [{}]", match_type);
            if match_type == "Subnet Ban" {
                let _ = writeln!(out, "Matched Subnet:    {}", record.target);
            }
            let _ = writeln!(out, "Tier Level:        {}", record.tier_level);
            let exp = match record.expires_at_secs {
                Some(s) => format!(
                    "expires at unix {} ({}s duration)",
                    s,
                    s.saturating_sub(record.banned_at_secs)
                ),
                None => "permanent".to_string(),
            };
            let _ = writeln!(out, "Expiry:            {}", exp);
            let _ = writeln!(out, "Reason:            {}", record.reason);
            let _ = writeln!(out, "Banned At:         unix {}", record.banned_at_secs);
        }
        None => {
            let _ = writeln!(out, "Status:            CLEAN (Not banned)");
        }
    }

    if let Some(ip) = maybe_ip {
        let whitelisted = store.is_whitelisted(ip)?;
        let wl_str = if whitelisted { "YES" } else { "NO" };
        let _ = writeln!(out, "Whitelisted:       {}", wl_str);

        if let Some(offense) = store.get_offense(ip)? {
            let _ = writeln!(out, "\nOffense History:");
            let _ = writeln!(out, "  Recorded Count:  {}", offense.count);
            let _ = writeln!(out, "  First Seen:      unix {}", offense.first_seen_secs);
            let _ = writeln!(out, "  Last Seen:       unix {}", offense.last_seen_secs);
        } else {
            let _ = writeln!(out, "Offenses in Window: 0");
        }
    }

    Ok(())
}

async fn handle_cloudflare<W: Write>(
    out: &mut W,
    db_path: &Path,
    config: &AppConfig,
    action: CloudflareCommands,
) -> Result<(), Box<dyn std::error::Error>> {
    let store = RedbStore::open(db_path)?;
    match action {
        CloudflareCommands::Status => {
            let _ = writeln!(out, "=== Cloudflare WAF Status ===");
            let _ = writeln!(out, "Sync Enabled:      {}", config.cloudflare.enabled);
            let zone = if config.cloudflare.zone_id.is_empty() {
                "Not configured"
            } else {
                &config.cloudflare.zone_id
            };
            let rule = config
                .cloudflare
                .rule_id
                .as_deref()
                .unwrap_or("Not configured");
            let _ = writeln!(out, "Zone ID:           {}", zone);
            let _ = writeln!(out, "Rule ID:           {}", rule);

            let expr = store.get_cloudflare_state()?.unwrap_or_default();
            let char_count = expr.len();
            let max_budget = config.cloudflare.max_rule_chars;
            let pct = if max_budget > 0 {
                (char_count as f64 / max_budget as f64) * 100.0
            } else {
                0.0
            };
            let _ = writeln!(
                out,
                "Rule Budget:       {}/{} characters ({:.1}% used)",
                char_count, max_budget, pct
            );

            let active_bans = store.list_active_bans()?.len();
            let _ = writeln!(out, "Active Bans:       {} managed locally", active_bans);
            if !expr.is_empty() {
                let preview = if expr.len() > 120 {
                    format!("{}...", &expr[..120])
                } else {
                    expr
                };
                let _ = writeln!(out, "Active Expression: {}", preview);
            }
        }
        CloudflareCommands::List => {
            let _ = writeln!(out, "=== Cloudflare Active WAF Expression ===");
            if let Some(expr) = store.get_cloudflare_state()? {
                let _ = writeln!(out, "{}", expr);
            } else {
                let _ = writeln!(out, "No active expression found in database.");
            }
        }
        CloudflareCommands::Sync => {
            if !config.cloudflare.enabled {
                let _ = writeln!(out, "Cloudflare sync is disabled in configuration.");
                return Ok(());
            }
            let _ = writeln!(out, "Triggering Cloudflare WAF synchronization...");
            let budget = CloudflareRuleBudget::new(
                config.cloudflare.max_rule_chars,
                config.asn_rules.blocked_asns.clone(),
                config.asn_rules.restricted_asns.clone(),
                config.asn_rules.allowed_regions.clone(),
            );
            let client = CloudflareClient::new(config.cloudflare.clone(), false)?;
            let bans = store.list_active_bans()?;
            let mut v4_ips = Vec::new();
            for r in bans {
                let maybe_ip = r.ip.or_else(|| r.target.parse().ok());
                if let Some(std::net::IpAddr::V4(v4)) = maybe_ip {
                    v4_ips.push(v4);
                }
            }
            v4_ips.reverse();
            let (expr, _) = budget.render_expression(&v4_ips);
            client.update_waf_rule(&expr).await?;
            store.set_cloudflare_state(&expr)?;
            let _ = writeln!(
                out,
                "Cloudflare WAF successfully updated ({} characters).",
                expr.len()
            );
        }
    }
    Ok(())
}

fn handle_completions<W: Write>(out: &mut W, shell: clap_complete::Shell) {
    let mut cmd = Cli::command();
    clap_complete::generate(shell, &mut cmd, "sanalu", out);
}

fn handle_whitelist<W: Write>(
    out: &mut W,
    db_path: &Path,
    action: WhitelistCommands,
) -> Result<(), Box<dyn std::error::Error>> {
    let store = RedbStore::open(db_path)?;
    match action {
        WhitelistCommands::Add { entry } => {
            store.add_whitelist(&entry)?;
            let _ = writeln!(out, "Added {} to whitelist.", entry);
        }
        WhitelistCommands::Remove { entry } => {
            store.remove_whitelist(&entry)?;
            let _ = writeln!(out, "Removed {} from whitelist.", entry);
        }
        WhitelistCommands::List => {
            let list = store.list_whitelist()?;
            let _ = writeln!(out, "Whitelisted entries: {:?}", list);
        }
    }
    Ok(())
}

fn handle_category<W: Write>(
    out: &mut W,
    db_path: &Path,
    action: CategoryCommands,
) -> Result<(), Box<dyn std::error::Error>> {
    let store = RedbStore::open(db_path)?;
    match action {
        CategoryCommands::Block { name } => {
            store.set_category_blocked(&name, true)?;
            let _ = writeln!(out, "Category '{}' is now blocked.", name);
        }
        CategoryCommands::Unblock { name } => {
            store.set_category_blocked(&name, false)?;
            let _ = writeln!(out, "Category '{}' is now unblocked.", name);
        }
        CategoryCommands::List => {
            let list = store.list_blocked_categories()?;
            let _ = writeln!(out, "Blocked categories: {:?}", list);
        }
    }
    Ok(())
}

fn handle_asn<W: Write>(
    out: &mut W,
    db_path: &Path,
    action: AsnCommands,
) -> Result<(), Box<dyn std::error::Error>> {
    let store = RedbStore::open(db_path)?;
    match action {
        AsnCommands::Block { asn } => {
            store.set_asn_blocked(asn, true)?;
            let _ = writeln!(out, "ASN {} is now blocked.", asn);
        }
        AsnCommands::Unblock { asn } => {
            store.set_asn_blocked(asn, false)?;
            let _ = writeln!(out, "ASN {} is now unblocked.", asn);
        }
        AsnCommands::List => {
            let list = store.list_blocked_asns()?;
            let _ = writeln!(out, "Blocked ASNs: {:?}", list);
        }
    }
    Ok(())
}

fn handle_region<W: Write>(
    out: &mut W,
    db_path: &Path,
    action: RegionCommands,
) -> Result<(), Box<dyn std::error::Error>> {
    let store = RedbStore::open(db_path)?;
    match action {
        RegionCommands::Allow { code } => {
            store.set_region_allowed(&code, true)?;
            let _ = writeln!(out, "Region '{}' is now allowed.", code);
        }
        RegionCommands::Disallow { code } => {
            store.set_region_allowed(&code, false)?;
            let _ = writeln!(out, "Region '{}' is now disallowed.", code);
        }
        RegionCommands::List => {
            let list = store.list_allowed_regions()?;
            let _ = writeln!(out, "Allowed regions: {:?}", list);
        }
    }
    Ok(())
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
    let options = sanalu::uninstall::UninstallOptions {
        purge,
        clean_cloudflare: clean_cf,
        dry_run,
    };
    sanalu::uninstall::execute_uninstall(out, config_path, config, &options).await?;
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
