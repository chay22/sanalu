use clap::Parser;
use sanalu::cli::{AsnCommands, BanCommands, CategoryCommands, Cli, CloudflareCommands, Commands};

#[test]
fn test_cli_parse_category_and_asn() {
    let cat_args = vec!["sanalu", "category", "block", "generic_tools"];
    let cli = Cli::try_parse_from(cat_args).expect("parse category");
    match cli.command {
        Commands::Category {
            action: CategoryCommands::Block { name },
        } => assert_eq!(name, "generic_tools"),
        _ => panic!("wrong command"),
    }

    let asn_args = vec!["sanalu", "asn", "block", "400529"];
    let cli = Cli::try_parse_from(asn_args).expect("parse asn");
    match cli.command {
        Commands::Asn {
            action: AsnCommands::Block { asn },
        } => assert_eq!(asn, 400529),
        _ => panic!("wrong command"),
    }
}

#[test]
fn test_cli_parse_ban_commands() {
    let direct_ip = vec!["sanalu", "ban", "192.168.1.1"];
    let cli = Cli::try_parse_from(direct_ip).expect("parse direct ip ban");
    match cli.command {
        Commands::Ban {
            action,
            target,
            reason,
        } => {
            assert!(action.is_none());
            assert_eq!(target.as_deref(), Some("192.168.1.1"));
            assert!(reason.is_none());
        }
        _ => panic!("wrong command"),
    }

    let direct_cidr = vec![
        "sanalu",
        "ban",
        "192.168.1.0/24",
        "--reason",
        "scanner_subnet",
    ];
    let cli = Cli::try_parse_from(direct_cidr).expect("parse cidr ban");
    match cli.command {
        Commands::Ban {
            action,
            target,
            reason,
        } => {
            assert!(action.is_none());
            assert_eq!(target.as_deref(), Some("192.168.1.0/24"));
            assert_eq!(reason.as_deref(), Some("scanner_subnet"));
        }
        _ => panic!("wrong command"),
    }

    let ban_add = vec![
        "sanalu",
        "ban",
        "add",
        "10.0.0.1",
        "--reason",
        "brute_force",
    ];
    let cli = Cli::try_parse_from(ban_add).expect("parse ban add");
    match cli.command {
        Commands::Ban { action, .. } => match action {
            Some(BanCommands::Add { target, reason }) => {
                assert_eq!(target, "10.0.0.1");
                assert_eq!(reason.as_deref(), Some("brute_force"));
            }
            _ => panic!("expected BanCommands::Add"),
        },
        _ => panic!("wrong command"),
    }

    let ban_list_plain = vec!["sanalu", "ban", "list", "--plain"];
    let cli = Cli::try_parse_from(ban_list_plain).expect("parse ban list");
    match cli.command {
        Commands::Ban { action, .. } => match action {
            Some(BanCommands::List { all, plain, filter }) => {
                assert!(!all);
                assert!(plain);
                assert!(filter.is_none());
            }
            _ => panic!("expected BanCommands::List"),
        },
        _ => panic!("wrong command"),
    }

    let ban_list_all_filter = vec!["sanalu", "ban", "list", "--all", "--filter", "ssh"];
    let cli = Cli::try_parse_from(ban_list_all_filter).expect("parse ban list with filter");
    match cli.command {
        Commands::Ban { action, .. } => match action {
            Some(BanCommands::List { all, plain, filter }) => {
                assert!(all);
                assert!(!plain);
                assert_eq!(filter.as_deref(), Some("ssh"));
            }
            _ => panic!("expected BanCommands::List"),
        },
        _ => panic!("wrong command"),
    }
}

#[test]
fn test_cli_parse_unban_and_check() {
    let unban_args = vec!["sanalu", "unban", "192.168.1.0/24"];
    let cli = Cli::try_parse_from(unban_args).expect("parse unban");
    match cli.command {
        Commands::Unban { target } => assert_eq!(target, "192.168.1.0/24"),
        _ => panic!("wrong command"),
    }

    let check_args = vec!["sanalu", "check", "192.168.1.50"];
    let cli = Cli::try_parse_from(check_args).expect("parse check");
    match cli.command {
        Commands::Check { target } => assert_eq!(target, "192.168.1.50"),
        _ => panic!("wrong command"),
    }
}

#[test]
fn test_cli_parse_cloudflare_and_completions() {
    let cf_status = vec!["sanalu", "cloudflare", "status"];
    let cli = Cli::try_parse_from(cf_status).expect("parse cf status");
    match cli.command {
        Commands::Cloudflare {
            action: CloudflareCommands::Status,
        } => {}
        _ => panic!("wrong command"),
    }

    let cf_list = vec!["sanalu", "cloudflare", "list"];
    let cli = Cli::try_parse_from(cf_list).expect("parse cf list");
    match cli.command {
        Commands::Cloudflare {
            action: CloudflareCommands::List,
        } => {}
        _ => panic!("wrong command"),
    }

    let cf_sync = vec!["sanalu", "cloudflare", "sync"];
    let cli = Cli::try_parse_from(cf_sync).expect("parse cf sync");
    match cli.command {
        Commands::Cloudflare {
            action: CloudflareCommands::Sync,
        } => {}
        _ => panic!("wrong command"),
    }

    let comp_bash = vec!["sanalu", "completions", "bash"];
    let cli = Cli::try_parse_from(comp_bash).expect("parse completions");
    match cli.command {
        Commands::Completions { shell } => {
            assert_eq!(shell, clap_complete::Shell::Bash);
        }
        _ => panic!("wrong command"),
    }
}

#[test]
fn test_cli_parse_version_command() {
    let ver_args = vec!["sanalu", "version"];
    let cli = Cli::try_parse_from(ver_args).expect("parse version");
    match cli.command {
        Commands::Version { short } => assert!(!short),
        _ => panic!("wrong command"),
    }

    let ver_short = vec!["sanalu", "version", "--short"];
    let cli = Cli::try_parse_from(ver_short).expect("parse version short");
    match cli.command {
        Commands::Version { short } => assert!(short),
        _ => panic!("wrong command"),
    }
}

#[tokio::test]
async fn test_offline_policy_list_reflects_config() {
    let temp_dir = tempfile::tempdir().unwrap();
    let db_path = temp_dir.path().join("offline_sync.redb");
    let socket_path = temp_dir.path().join("non_existent.sock");

    let mut cfg = sanalu::config::AppConfig::default();
    cfg.asn_rules.blocked_asns = vec![13335, 15169];
    cfg.asn_rules.allowed_regions = vec!["ID".into(), "SG".into()];

    let mut buf = Vec::new();
    let cmd = sanalu::cli::Commands::Asn {
        action: sanalu::cli::AsnCommands::List,
    };
    sanalu::cli::handle_policy_command(&mut buf, &db_path, &socket_path, &cfg, &cmd)
        .await
        .unwrap();

    let output = String::from_utf8(buf).unwrap();
    assert!(output.contains("13335"));
    assert!(output.contains("15169"));

    let mut reg_buf = Vec::new();
    let reg_cmd = sanalu::cli::Commands::Region {
        action: sanalu::cli::RegionCommands::List,
    };
    sanalu::cli::handle_policy_command(&mut reg_buf, &db_path, &socket_path, &cfg, &reg_cmd)
        .await
        .unwrap();

    let reg_output = String::from_utf8(reg_buf).unwrap();
    assert!(reg_output.contains("ID"));
    assert!(reg_output.contains("SG"));
}
