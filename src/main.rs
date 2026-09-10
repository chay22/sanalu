use clap::Parser;
use sanalu::cli::{Cli, bootstrap_files, dispatch_cli};
use sanalu::config::{AppConfig, parse_app_config};
use sanalu::discovery::is_root;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    let mut stdout = std::io::stdout();

    let config = if cli.config.exists() {
        let content = match std::fs::read_to_string(&cli.config) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("Error reading config {:?}: {}", cli.config, e);
                std::process::exit(1);
            }
        };
        match parse_app_config(&content, &cli.config) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("{e}");
                std::process::exit(1);
            }
        }
    } else {
        AppConfig::default()
    };

    if is_root() {
        let _ = bootstrap_files(&cli.config, &config.general.db_path);
    }

    dispatch_cli(&mut stdout, &cli, &config).await
}
