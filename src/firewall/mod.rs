pub mod exec;
pub mod mock;
pub mod nftables;

pub use mock::MockFirewallBackend;
pub use nftables::NftablesBackend;

use crate::error::SanaluError;
use std::net::IpAddr;

pub trait FirewallBackend: Send + Sync {
    fn init_tables(&self) -> Result<(), SanaluError>;
    fn ban_ip(&self, ip: IpAddr, timeout_secs: Option<u64>) -> Result<(), SanaluError>;
    fn unban_ip(&self, ip: IpAddr) -> Result<(), SanaluError>;
    fn ban_target(&self, target: &str, timeout_secs: Option<u64>) -> Result<(), SanaluError>;
    fn unban_target(&self, target: &str) -> Result<(), SanaluError>;
    fn list_banned(&self) -> Result<Vec<IpAddr>, SanaluError>;
    fn flush(&self) -> Result<(), SanaluError>;
}
