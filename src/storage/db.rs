use crate::error::SanaluError;
use redb::{Database, ReadableTable, TableDefinition};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::path::Path;
use std::time::SystemTime;

const TABLE_BANS: TableDefinition<&str, &[u8]> = TableDefinition::new("bans");
const TABLE_OFFENSES: TableDefinition<[u8; 16], &[u8]> = TableDefinition::new("offenses");
const TABLE_WHITELIST: TableDefinition<&str, u64> = TableDefinition::new("whitelist");
const TABLE_CATEGORIES: TableDefinition<&str, bool> = TableDefinition::new("categories");
const TABLE_BLOCKED_ASNS: TableDefinition<u32, ()> = TableDefinition::new("blocked_asns");
const TABLE_RESTRICTED_ASNS: TableDefinition<u32, ()> = TableDefinition::new("restricted_asns");
const TABLE_ALLOWED_REGIONS: TableDefinition<&str, ()> = TableDefinition::new("allowed_regions");
const TABLE_CLOUDFLARE: TableDefinition<&str, &str> = TableDefinition::new("cloudflare");

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

pub struct RedbStore {
    db: Database,
}

impl RedbStore {
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self, SanaluError> {
        let parent = path.as_ref().parent();
        if let Some(p) = parent {
            if !p.exists() {
                std::fs::create_dir_all(p)?;
            }
        }
        let db = Database::create(path)?;
        let write_txn = db.begin_write()?;
        {
            let _ = write_txn.open_table(TABLE_BANS)?;
            let _ = write_txn.open_table(TABLE_OFFENSES)?;
            let _ = write_txn.open_table(TABLE_WHITELIST)?;
            let _ = write_txn.open_table(TABLE_CATEGORIES)?;
            let _ = write_txn.open_table(TABLE_BLOCKED_ASNS)?;
            let _ = write_txn.open_table(TABLE_RESTRICTED_ASNS)?;
            let _ = write_txn.open_table(TABLE_ALLOWED_REGIONS)?;
            let _ = write_txn.open_table(TABLE_CLOUDFLARE)?;
        }
        write_txn.commit()?;
        Ok(Self { db })
    }

    pub fn save_ban(&self, record: &StoredBanRecord) -> Result<(), SanaluError> {
        let encoded =
            serde_json::to_vec(record).map_err(|e| SanaluError::Storage(e.to_string()))?;
        let write_txn = self.db.begin_write()?;
        {
            let mut table = write_txn.open_table(TABLE_BANS)?;
            table.insert(record.target.as_str(), encoded.as_slice())?;
        }
        write_txn.commit()?;
        Ok(())
    }

    pub fn remove_ban(&self, target: &str) -> Result<bool, SanaluError> {
        let write_txn = self.db.begin_write()?;
        let removed = {
            let mut table = write_txn.open_table(TABLE_BANS)?;
            table.remove(target)?.is_some()
        };
        write_txn.commit()?;
        Ok(removed)
    }

    pub fn get_ban(&self, target: &str) -> Result<Option<StoredBanRecord>, SanaluError> {
        let read_txn = self.db.begin_read()?;
        let table = read_txn.open_table(TABLE_BANS)?;
        if let Some(val) = table.get(target)? {
            let record: StoredBanRecord = serde_json::from_slice(val.value())
                .map_err(|e| SanaluError::Storage(e.to_string()))?;
            Ok(Some(record))
        } else {
            Ok(None)
        }
    }

    pub fn get_offense(&self, ip: IpAddr) -> Result<Option<StoredOffenseRecord>, SanaluError> {
        let key = ip_to_key(ip);
        let read_txn = self.db.begin_read()?;
        let table = read_txn.open_table(TABLE_OFFENSES)?;
        if let Some(val) = table.get(key)? {
            let record: StoredOffenseRecord = serde_json::from_slice(val.value())
                .map_err(|e| SanaluError::Storage(e.to_string()))?;
            Ok(Some(record))
        } else {
            Ok(None)
        }
    }

    pub fn check_ban_status(&self, target: &str) -> Result<Option<StoredBanRecord>, SanaluError> {
        if let Some(record) = self.get_ban(target)? {
            return Ok(Some(record));
        }
        if let Ok(ip) = target.parse::<IpAddr>() {
            let active = self.list_active_bans()?;
            for record in active {
                if record.target.contains('/') {
                    if let Ok(cidr) = parse_cidr(&record.target) {
                        if cidr.contains(ip) {
                            return Ok(Some(record));
                        }
                    }
                }
            }
        }
        Ok(None)
    }

    pub fn list_active_bans(&self) -> Result<Vec<StoredBanRecord>, SanaluError> {
        let now_secs = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let read_txn = self.db.begin_read()?;
        let table = read_txn.open_table(TABLE_BANS)?;
        let mut results = Vec::new();

        for item in table.iter()? {
            let (_, val) = item?;
            let record: StoredBanRecord = serde_json::from_slice(val.value())
                .map_err(|e| SanaluError::Storage(e.to_string()))?;
            if let Some(expires_at) = record.expires_at_secs {
                if expires_at <= now_secs {
                    continue;
                }
            }
            results.push(record);
        }
        Ok(results)
    }

    pub fn record_offense(&self, ip: IpAddr, window_secs: u64) -> Result<u32, SanaluError> {
        let key = ip_to_key(ip);
        let now_secs = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let write_txn = self.db.begin_write()?;
        let updated_count = {
            let mut table = write_txn.open_table(TABLE_OFFENSES)?;
            let current = if let Some(val) = table.get(key)? {
                let rec: StoredOffenseRecord = serde_json::from_slice(val.value())
                    .map_err(|e| SanaluError::Storage(e.to_string()))?;
                if now_secs.saturating_sub(rec.last_seen_secs) > window_secs {
                    StoredOffenseRecord {
                        count: 1,
                        first_seen_secs: now_secs,
                        last_seen_secs: now_secs,
                    }
                } else {
                    StoredOffenseRecord {
                        count: rec.count + 1,
                        first_seen_secs: rec.first_seen_secs,
                        last_seen_secs: now_secs,
                    }
                }
            } else {
                StoredOffenseRecord {
                    count: 1,
                    first_seen_secs: now_secs,
                    last_seen_secs: now_secs,
                }
            };
            let count = current.count;
            let encoded =
                serde_json::to_vec(&current).map_err(|e| SanaluError::Storage(e.to_string()))?;
            table.insert(key, encoded.as_slice())?;
            count
        };
        write_txn.commit()?;
        Ok(updated_count)
    }

    pub fn add_whitelist(&self, entry: &str) -> Result<(), SanaluError> {
        let now_secs = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let write_txn = self.db.begin_write()?;
        {
            let mut table = write_txn.open_table(TABLE_WHITELIST)?;
            table.insert(entry, now_secs)?;
        }
        write_txn.commit()?;
        Ok(())
    }

    pub fn remove_whitelist(&self, entry: &str) -> Result<bool, SanaluError> {
        let write_txn = self.db.begin_write()?;
        let removed = {
            let mut table = write_txn.open_table(TABLE_WHITELIST)?;
            table.remove(entry)?.is_some()
        };
        write_txn.commit()?;
        Ok(removed)
    }

    pub fn list_whitelist(&self) -> Result<Vec<String>, SanaluError> {
        let read_txn = self.db.begin_read()?;
        let table = read_txn.open_table(TABLE_WHITELIST)?;
        let mut results = Vec::new();
        for item in table.iter()? {
            let (key, _) = item?;
            results.push(key.value().to_string());
        }
        Ok(results)
    }

    pub fn is_whitelisted(&self, ip: IpAddr) -> Result<bool, SanaluError> {
        let entries = self.list_whitelist()?;
        for entry in entries {
            if let Ok(exact_ip) = entry.parse::<IpAddr>() {
                if exact_ip == ip {
                    return Ok(true);
                }
            } else if entry.contains('/') {
                if let Ok(cidr) = parse_cidr(&entry) {
                    if cidr.contains(ip) {
                        return Ok(true);
                    }
                }
            }
        }
        Ok(false)
    }

    pub fn set_category_blocked(&self, category: &str, blocked: bool) -> Result<(), SanaluError> {
        let write_txn = self.db.begin_write()?;
        {
            let mut table = write_txn.open_table(TABLE_CATEGORIES)?;
            table.insert(category, blocked)?;
        }
        write_txn.commit()?;
        Ok(())
    }

    pub fn is_category_blocked(
        &self,
        category: &str,
        default_val: bool,
    ) -> Result<bool, SanaluError> {
        let read_txn = self.db.begin_read()?;
        let table = read_txn.open_table(TABLE_CATEGORIES)?;
        if let Some(val) = table.get(category)? {
            Ok(val.value())
        } else {
            Ok(default_val)
        }
    }

    pub fn list_blocked_categories(&self) -> Result<Vec<String>, SanaluError> {
        let read_txn = self.db.begin_read()?;
        let table = read_txn.open_table(TABLE_CATEGORIES)?;
        let mut results = Vec::new();
        for item in table.iter()? {
            let (cat, blocked) = item?;
            if blocked.value() {
                results.push(cat.value().to_string());
            }
        }
        Ok(results)
    }

    pub fn set_asn_blocked(&self, asn: u32, blocked: bool) -> Result<(), SanaluError> {
        let write_txn = self.db.begin_write()?;
        {
            let mut table = write_txn.open_table(TABLE_BLOCKED_ASNS)?;
            if blocked {
                table.insert(asn, ())?;
            } else {
                table.remove(asn)?;
            }
        }
        write_txn.commit()?;
        Ok(())
    }

    pub fn is_asn_blocked(&self, asn: u32) -> Result<bool, SanaluError> {
        let read_txn = self.db.begin_read()?;
        let table = read_txn.open_table(TABLE_BLOCKED_ASNS)?;
        Ok(table.get(asn)?.is_some())
    }

    pub fn list_blocked_asns(&self) -> Result<Vec<u32>, SanaluError> {
        let read_txn = self.db.begin_read()?;
        let table = read_txn.open_table(TABLE_BLOCKED_ASNS)?;
        let mut results = Vec::new();
        for item in table.iter()? {
            let (asn, _) = item?;
            results.push(asn.value());
        }
        Ok(results)
    }

    pub fn set_region_allowed(&self, code: &str, allowed: bool) -> Result<(), SanaluError> {
        let write_txn = self.db.begin_write()?;
        {
            let mut table = write_txn.open_table(TABLE_ALLOWED_REGIONS)?;
            if allowed {
                table.insert(code, ())?;
            } else {
                table.remove(code)?;
            }
        }
        write_txn.commit()?;
        Ok(())
    }

    pub fn is_region_allowed(&self, code: &str) -> Result<bool, SanaluError> {
        let read_txn = self.db.begin_read()?;
        let table = read_txn.open_table(TABLE_ALLOWED_REGIONS)?;
        Ok(table.get(code)?.is_some())
    }

    pub fn list_allowed_regions(&self) -> Result<Vec<String>, SanaluError> {
        let read_txn = self.db.begin_read()?;
        let table = read_txn.open_table(TABLE_ALLOWED_REGIONS)?;
        let mut results = Vec::new();
        for item in table.iter()? {
            let (code, _) = item?;
            results.push(code.value().to_string());
        }
        Ok(results)
    }

    pub fn set_cloudflare_state(&self, expression: &str) -> Result<(), SanaluError> {
        let write_txn = self.db.begin_write()?;
        {
            let mut table = write_txn.open_table(TABLE_CLOUDFLARE)?;
            table.insert("active_expression", expression)?;
        }
        write_txn.commit()?;
        Ok(())
    }

    pub fn get_cloudflare_state(&self) -> Result<Option<String>, SanaluError> {
        let read_txn = self.db.begin_read()?;
        let table = read_txn.open_table(TABLE_CLOUDFLARE)?;
        if let Some(val) = table.get("active_expression")? {
            Ok(Some(val.value().to_string()))
        } else {
            Ok(None)
        }
    }
}

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
