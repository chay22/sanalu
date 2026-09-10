use super::cidr::parse_cidr;
use super::db::{
    RedbStore, TABLE_ALLOWED_REGIONS, TABLE_BLOCKED_ASNS, TABLE_CATEGORIES, TABLE_CLOUDFLARE,
    TABLE_WHITELIST,
};
use crate::error::SanaluError;
use redb::ReadableTable;
use std::net::IpAddr;
use std::time::SystemTime;

impl RedbStore {
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
