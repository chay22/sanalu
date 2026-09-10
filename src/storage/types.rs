use serde::{Deserialize, Serialize};
use std::net::IpAddr;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StoredBanRecord {
    pub target: String,
    #[serde(default)]
    pub ip: Option<IpAddr>,
    pub tier_level: usize,
    pub banned_at_secs: u64,
    pub expires_at_secs: Option<u64>,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StoredOffenseRecord {
    pub count: u32,
    pub first_seen_secs: u64,
    pub last_seen_secs: u64,
}

pub fn ip_to_key(ip: IpAddr) -> [u8; 16] {
    match ip {
        IpAddr::V4(v4) => v4.to_ipv6_mapped().octets(),
        IpAddr::V6(v6) => v6.octets(),
    }
}

pub fn key_to_ip(octets: [u8; 16]) -> IpAddr {
    let v6 = std::net::Ipv6Addr::from(octets);
    if let Some(v4) = v6.to_ipv4_mapped() {
        IpAddr::V4(v4)
    } else {
        IpAddr::V6(v6)
    }
}
