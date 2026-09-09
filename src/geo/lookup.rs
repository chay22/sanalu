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
    pub fn from_file(path: &std::path::Path) -> Result<Self, SanaluError> {
        let file = std::fs::File::open(path)?;
        let reader = std::io::BufReader::new(file);
        Self::from_tsv_reader(reader)
    }

    pub fn cidrs_for_asn(&self, asn: u32) -> Vec<String> {
        let mut cidrs = Vec::new();
        for entry in &self.entries_v4 {
            if entry.asn == asn {
                cidrs.extend(range_to_cidrs(entry.start, entry.end));
            }
        }
        cidrs
    }
}

pub fn range_to_cidrs(start: u32, end: u32) -> Vec<String> {
    if start > end {
        return Vec::new();
    }
    let mut cidrs = Vec::new();
    let mut cur = start as u64;
    let end_u64 = end as u64;

    while cur <= end_u64 {
        let align_bits = if cur == 0 {
            32
        } else {
            cur.trailing_zeros().min(32)
        };
        let max_size_from_align = 1u64 << align_bits;
        let count = end_u64 - cur + 1;
        let max_size_from_count = 1u64 << (63 - count.leading_zeros());
        let block_size = max_size_from_align.min(max_size_from_count);
        let prefix = 32 - block_size.trailing_zeros();

        cidrs.push(format!("{}/{}", Ipv4Addr::from(cur as u32), prefix));
        cur += block_size;
    }

    cidrs
}

impl Default for IpLookupDb {
    fn default() -> Self {
        Self::empty()
    }
}
