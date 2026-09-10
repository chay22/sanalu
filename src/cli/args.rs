use clap::{Parser, Subcommand};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(name = "sanalu", version, about = "High-performance security daemon")]
pub struct Cli {
    #[arg(short, long, default_value = "/etc/sanalu/sanalu.toml")]
    pub config: PathBuf,

    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug, PartialEq, Eq)]
pub enum Commands {
    Run {
        #[arg(long)]
        dry_run: bool,
    },
    Status,
    Ban {
        #[command(subcommand)]
        action: Option<BanCommands>,
        target: Option<String>,
        #[arg(long)]
        reason: Option<String>,
    },
    Unban {
        target: String,
    },
    Check {
        target: String,
    },
    Whitelist {
        #[command(subcommand)]
        action: WhitelistCommands,
    },
    Category {
        #[command(subcommand)]
        action: CategoryCommands,
    },
    Asn {
        #[command(subcommand)]
        action: AsnCommands,
    },
    Region {
        #[command(subcommand)]
        action: RegionCommands,
    },
    Cloudflare {
        #[command(subcommand)]
        action: CloudflareCommands,
    },
    Completions {
        shell: clap_complete::Shell,
    },
    Uninstall {
        #[arg(long)]
        purge: bool,
        #[arg(long)]
        clean_cloudflare: bool,
        #[arg(long)]
        dry_run: bool,
        #[arg(short, long)]
        yes: bool,
    },
    Version {
        #[arg(short, long)]
        short: bool,
    },
    Discover,
    UpdateDb,
    TestLog {
        path: PathBuf,
    },
}

#[derive(Subcommand, Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum BanCommands {
    List {
        #[arg(long)]
        all: bool,
        #[arg(long)]
        plain: bool,
        #[arg(long)]
        filter: Option<String>,
    },
    Add {
        target: String,
        #[arg(long)]
        reason: Option<String>,
    },
}

pub use crate::ipc::protocol::{
    AsnCommands, CategoryCommands, CloudflareCommands, RegionCommands, WhitelistCommands,
};
