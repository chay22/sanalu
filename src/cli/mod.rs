pub mod admin;
pub mod args;
pub mod dispatch;
pub mod query;

pub use args::{
    AsnCommands, BanCommands, CategoryCommands, Cli, CloudflareCommands, Commands, RegionCommands,
    WhitelistCommands,
};
pub use dispatch::dispatch_cli;
pub use query::generate_completions;
