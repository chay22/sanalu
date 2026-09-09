pub mod cli;
pub mod cloudflare;
pub mod config;
pub mod daemon;
pub mod discovery;
pub mod engine;
pub mod error;
pub mod firewall;
pub mod geo;
pub mod intelligence;
pub mod parser;
pub mod storage;
pub mod uninstall;

use std::net::IpAddr;

pub fn is_loopback_or_private(ip: IpAddr) -> bool {
    if ip.is_loopback() {
        return true;
    }
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            o[0] == 10
                || (o[0] == 172 && (16..=31).contains(&o[1]))
                || (o[0] == 192 && o[1] == 168)
                || (o[0] == 100 && (64..=127).contains(&o[1]))
                || (o[0] == 169 && o[1] == 254)
        }
        IpAddr::V6(v6) => {
            let s = v6.segments();
            (s[0] & 0xfe00) == 0xfc00 || (s[0] & 0xffc0) == 0xfe80
        }
    }
}
