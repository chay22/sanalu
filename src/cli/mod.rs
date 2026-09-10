pub mod args;
pub mod dispatch;

pub use args::{
    AsnCommands, BanCommands, CategoryCommands, Cli, CloudflareCommands, Commands, RegionCommands,
    WhitelistCommands,
};
pub use dispatch::{dispatch_cli, generate_completions};
