use crate::error::SanaluError;
use std::net::IpAddr;

pub struct SimpleCidr {
    base: u128,
    mask: u128,
}

impl SimpleCidr {
    pub fn contains(&self, ip: IpAddr) -> bool {
        let ip_u128 = match ip {
            IpAddr::V4(v4) => u128::from(u32::from(v4)),
            IpAddr::V6(v6) => u128::from_be_bytes(v6.octets()),
        };
        (ip_u128 & self.mask) == (self.base & self.mask)
    }
}

pub fn parse_cidr(s: &str) -> Result<SimpleCidr, SanaluError> {
    let parts: Vec<&str> = s.split('/').collect();
    if parts.len() != 2 {
        return Err(SanaluError::Config(format!("Invalid CIDR: {s}")));
    }
    let ip: IpAddr = parts[0]
        .parse()
        .map_err(|_| SanaluError::Config(format!("Invalid IP in CIDR: {s}")))?;
    let prefix: u32 = parts[1]
        .parse()
        .map_err(|_| SanaluError::Config(format!("Invalid prefix in CIDR: {s}")))?;

    match ip {
        IpAddr::V4(v4) => {
            if prefix > 32 {
                return Err(SanaluError::Config(format!("IPv4 prefix > 32 in: {s}")));
            }
            let base = u128::from(u32::from(v4));
            let mask = if prefix == 0 {
                0
            } else {
                (!0u32 << (32 - prefix)) as u128
            };
            Ok(SimpleCidr { base, mask })
        }
        IpAddr::V6(v6) => {
            if prefix > 128 {
                return Err(SanaluError::Config(format!("IPv6 prefix > 128 in: {s}")));
            }
            let base = u128::from_be_bytes(v6.octets());
            let mask = if prefix == 0 {
                0
            } else {
                !0u128 << (128 - prefix)
            };
            Ok(SimpleCidr { base, mask })
        }
    }
}
