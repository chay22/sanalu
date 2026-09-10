use clap::Subcommand;
use serde::{Deserialize, Serialize};

#[derive(Subcommand, Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CloudflareCommands {
    Status,
    List,
    Sync,
}

#[derive(Subcommand, Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum WhitelistCommands {
    Add { entry: String },
    Remove { entry: String },
    List,
}

#[derive(Subcommand, Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CategoryCommands {
    Block { name: String },
    Unblock { name: String },
    List,
}

#[derive(Subcommand, Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AsnCommands {
    Block { asn: u32 },
    Unblock { asn: u32 },
    List,
}

#[derive(Subcommand, Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RegionCommands {
    Allow { code: String },
    Disallow { code: String },
    List,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum IpcRequest {
    Status,
    Check {
        target: String,
    },
    Ban {
        target: String,
        reason: Option<String>,
    },
    Unban {
        target: String,
    },
    BanList {
        all: bool,
        plain: bool,
        filter: Option<String>,
    },
    Whitelist {
        action: WhitelistCommands,
    },
    Category {
        action: CategoryCommands,
    },
    Asn {
        action: AsnCommands,
    },
    Region {
        action: RegionCommands,
    },
    Cloudflare {
        action: CloudflareCommands,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpcResponse {
    pub success: bool,
    pub output: String,
    pub error: Option<String>,
}

impl IpcResponse {
    pub fn ok(output: String) -> Self {
        Self {
            success: true,
            output,
            error: None,
        }
    }

    pub fn err(error: String) -> Self {
        Self {
            success: false,
            output: String::new(),
            error: Some(error),
        }
    }
}
