use crate::error::SanaluError;
use redb::{Database, TableDefinition};
use std::path::Path;

pub(crate) const TABLE_BANS: TableDefinition<&str, &[u8]> = TableDefinition::new("bans");
pub(crate) const TABLE_OFFENSES: TableDefinition<[u8; 16], &[u8]> =
    TableDefinition::new("offenses");
pub(crate) const TABLE_WHITELIST: TableDefinition<&str, u64> = TableDefinition::new("whitelist");
pub(crate) const TABLE_CATEGORIES: TableDefinition<&str, bool> = TableDefinition::new("categories");
pub(crate) const TABLE_BLOCKED_ASNS: TableDefinition<u32, ()> =
    TableDefinition::new("blocked_asns");
pub(crate) const TABLE_RESTRICTED_ASNS: TableDefinition<u32, ()> =
    TableDefinition::new("restricted_asns");
pub(crate) const TABLE_ALLOWED_REGIONS: TableDefinition<&str, ()> =
    TableDefinition::new("allowed_regions");
pub(crate) const TABLE_CLOUDFLARE: TableDefinition<&str, &str> = TableDefinition::new("cloudflare");

pub struct RedbStore {
    pub(crate) db: Database,
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
}
