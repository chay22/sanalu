use clap::Parser;
use sanalu::cli::{Cli, Commands};
use sanalu::config::AppConfig;
use sanalu::uninstall::{UninstallOptions, execute_uninstall, remove_config_dir, remove_data_dir};

#[test]
fn test_cli_parse_uninstall_commands() {
    let base = vec!["sanalu", "uninstall"];
    let cli = Cli::try_parse_from(base).expect("parse base uninstall");
    match cli.command {
        Commands::Uninstall {
            purge,
            clean_cloudflare,
            dry_run,
            yes,
        } => {
            assert!(!purge);
            assert!(!clean_cloudflare);
            assert!(!dry_run);
            assert!(!yes);
        }
        _ => panic!("wrong command"),
    }

    let full = vec![
        "sanalu",
        "uninstall",
        "--purge",
        "--clean-cloudflare",
        "--dry-run",
        "-y",
    ];
    let cli = Cli::try_parse_from(full).expect("parse full uninstall");
    match cli.command {
        Commands::Uninstall {
            purge,
            clean_cloudflare,
            dry_run,
            yes,
        } => {
            assert!(purge);
            assert!(clean_cloudflare);
            assert!(dry_run);
            assert!(yes);
        }
        _ => panic!("wrong command"),
    }
}

#[test]
fn test_uninstall_dry_run_safety() {
    let temp_dir = tempfile::tempdir().unwrap();
    let config_dir = temp_dir.path().join("etc_sanalu");
    let data_dir = temp_dir.path().join("var_lib_sanalu");

    std::fs::create_dir_all(&config_dir).unwrap();
    std::fs::create_dir_all(&data_dir).unwrap();

    let config_file = config_dir.join("sanalu.toml");
    let db_file = data_dir.join("sanalu.redb");

    std::fs::write(&config_file, "general.whitelist = []\n").unwrap();
    std::fs::write(&db_file, b"test redb content").unwrap();

    let mut config = AppConfig::default();
    config.general.db_path = db_file.clone();

    let mut output = Vec::new();
    let options = UninstallOptions {
        purge: true,
        clean_cloudflare: false,
        dry_run: true,
    };

    let result = tokio::runtime::Runtime::new()
        .unwrap()
        .block_on(execute_uninstall(
            &mut output,
            &config_file,
            &config,
            &options,
        ));

    assert!(result.is_ok());
    let output_str = String::from_utf8_lossy(&output);
    assert!(output_str.contains("Dry-run mode"));
    assert!(output_str.contains("Would purge configuration directory"));
    assert!(output_str.contains("Would remove data directory"));

    assert!(config_file.exists());
    assert!(db_file.exists());
}

#[test]
fn test_uninstall_data_and_config_removal() {
    let temp_dir = tempfile::tempdir().unwrap();
    let config_dir = temp_dir.path().join("etc_sanalu");
    let data_dir = temp_dir.path().join("var_lib_sanalu");

    std::fs::create_dir_all(&config_dir).unwrap();
    std::fs::create_dir_all(&data_dir).unwrap();

    let config_file = config_dir.join("sanalu.toml");
    let db_file = data_dir.join("sanalu.redb");

    std::fs::write(&config_file, "config").unwrap();
    std::fs::write(&db_file, "db").unwrap();

    let mut out = Vec::new();
    assert!(remove_data_dir(&mut out, &db_file, false).is_ok());
    assert!(!data_dir.exists());

    let mut out_keep = Vec::new();
    assert!(remove_config_dir(&mut out_keep, &config_file, false, false).is_ok());
    assert!(config_dir.exists());
    let keep_str = String::from_utf8_lossy(&out_keep);
    assert!(keep_str.contains("Preserved configuration"));

    let mut out_purge = Vec::new();
    assert!(remove_config_dir(&mut out_purge, &config_file, true, false).is_ok());
    assert!(!config_dir.exists());
    let purge_str = String::from_utf8_lossy(&out_purge);
    assert!(purge_str.contains("Purged configuration directory"));
}
