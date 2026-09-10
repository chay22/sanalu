use super::db::{RedbStore, TABLE_OFFENSES};
use super::types::{StoredOffenseRecord, ip_to_key};
use crate::error::SanaluError;
use redb::ReadableTable;
use std::net::IpAddr;
use std::time::SystemTime;

impl RedbStore {
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
}
