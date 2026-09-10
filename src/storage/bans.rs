use super::cidr::parse_cidr;
use super::db::{RedbStore, TABLE_BANS};
use super::types::StoredBanRecord;
use crate::error::SanaluError;
use redb::ReadableTable;
use std::net::IpAddr;
use std::time::SystemTime;

impl RedbStore {
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
}
