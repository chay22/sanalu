use crate::cli::{
    AsnCommands, CategoryCommands, CloudflareCommands, RegionCommands, WhitelistCommands,
};
use serde::{Deserialize, Serialize};

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
