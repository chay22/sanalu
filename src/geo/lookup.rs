use crate::error::SanaluError;
use std::io::BufRead;
use std::net::{IpAddr, Ipv4Addr};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IpMetadata {
    pub asn: u32,
    pub country: [u8; 2],
    pub as_org: String,
}

impl IpMetadata {
    pub fn country_str(&self) -> String {
        String::from_utf8_lossy(&self.country).to_string()
    }
}

#[derive(Debug, Clone)]
pub struct Ipv4RangeEntry {
    pub start: u32,
    pub end: u32,
    pub asn: u32,
    pub country: [u8; 2],
    pub as_org: String,
}

pub struct IpLookupDb {
    entries_v4: Vec<Ipv4RangeEntry>,
}

impl IpLookupDb {
    pub fn empty() -> Self {
        Self {
            entries_v4: Vec::new(),
        }
    }

    pub fn from_tsv_reader<R: BufRead>(reader: R) -> Result<Self, SanaluError> {
        let mut entries = Vec::new();
        for line in reader.lines() {
            let line = line?;
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }
            let cols: Vec<&str> = trimmed.split('\t').collect();
            if cols.len() < 5 {
                continue;
            }
            let start_ip: Ipv4Addr = match cols[0].parse() {
                Ok(ip) => ip,
                Err(_) => continue,
            };
            let end_ip: Ipv4Addr = match cols[1].parse() {
                Ok(ip) => ip,
                Err(_) => continue,
            };
            let asn: u32 = match cols[2].parse() {
                Ok(n) => n,
                Err(_) => continue,
            };
            let country_bytes = cols[3].as_bytes();
            let mut country = *b"??";
            if country_bytes.len() >= 2 {
                country[0] = country_bytes[0];
                country[1] = country_bytes[1];
            }
            let as_org = cols[4].to_string();

            entries.push(Ipv4RangeEntry {
                start: u32::from(start_ip),
                end: u32::from(end_ip),
                asn,
                country,
                as_org,
            });
        }
        entries.sort_by_key(|e| e.start);
        Ok(Self {
            entries_v4: entries,
        })
    }

    pub fn lookup(&self, ip: IpAddr) -> Option<IpMetadata> {
        match ip {
            IpAddr::V4(v4) => {
                let target = u32::from(v4);
                let idx = match self.entries_v4.binary_search_by(|entry| {
                    if entry.end < target {
                        std::cmp::Ordering::Less
                    } else if entry.start > target {
                        std::cmp::Ordering::Greater
                    } else {
                        std::cmp::Ordering::Equal
                    }
                }) {
                    Ok(i) => i,
                    Err(_) => return None,
                };
                let entry = &self.entries_v4[idx];
                Some(IpMetadata {
                    asn: entry.asn,
                    country: entry.country,
                    as_org: entry.as_org.clone(),
                })
            }
            IpAddr::V6(_) => None,
        }
    }
}

impl Default for IpLookupDb {
    fn default() -> Self {
        Self::empty()
    }
}
