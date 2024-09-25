use std::{path::PathBuf, str::FromStr, sync::Arc};

use redb::{Database, Error, ReadableTable, TableDefinition};

// property key -> value
const CONFIG_TABLE: TableDefinition<&str, &str> = TableDefinition::new("config");
// channeld id -> is claimed
const ISSUED_CHANNELS_TABLE: TableDefinition<[u8; 32], bool> =
    TableDefinition::new("claimed_channels");

const DATABASE_VERSION: u64 = 0;

#[derive(Clone)]
pub(super) struct Db {
    inner: Arc<Database>,
}

impl Db {
    pub(super) fn open(path: PathBuf) -> Result<Self, Error> {
        let db = Database::create(path)?;

        let write_txn = db.begin_write()?;
        // Check database version
        {
            let _ = write_txn.open_table(CONFIG_TABLE)?;
            let mut table = write_txn.open_table(CONFIG_TABLE)?;

            let db_version = table.get("db_version")?;
            let db_version = db_version.map(|v| v.value().to_owned());

            match db_version {
                Some(db_version) => {
                    let current_file_version = u64::from_str(&db_version).unwrap_or_default();
                    if current_file_version.ne(&DATABASE_VERSION) {
                        // Database needs to be upgraded
                        todo!()
                    }
                }
                None => {
                    // Open all tables to init a new db
                    let _ = write_txn.open_table(ISSUED_CHANNELS_TABLE)?;

                    table.insert("db_version", DATABASE_VERSION.to_string().as_str())?;
                }
            }
        }

        write_txn.commit()?;
        Ok(Self {
            inner: Arc::new(db),
        })
    }

    pub(super) async fn insert_channel(&self, channel_id: [u8; 32]) -> Result<(), Error> {
        let write_txn = self.inner.begin_write()?;
        {
            let mut table = write_txn.open_table(ISSUED_CHANNELS_TABLE)?;
            table.insert(channel_id, false)?;
        }
        write_txn.commit()?;
        Ok(())
    }

    pub(super) async fn is_channel_claimed(&self, channel_id: [u8; 32]) -> Result<bool, Error> {
        let read_txn = self.inner.begin_read()?;
        let table = read_txn.open_table(ISSUED_CHANNELS_TABLE)?;
        let is_claimed = match table.get(channel_id)? {
            Some(v) => v.value(),
            None => false,
        };
        Ok(is_claimed)
    }

    pub(super) async fn issue_channel(&self, channel_id: [u8; 32]) -> Result<bool, Error> {
        let write_txn = self.inner.begin_write()?;
        {
            let mut table = write_txn.open_table(ISSUED_CHANNELS_TABLE)?;
            let is_claimed = match table.get(channel_id)? {
                Some(v) => v.value(),
                None => false,
            };
            if is_claimed {
                return Ok(false);
            }
            table.insert(channel_id, true)?;
        }
        write_txn.commit()?;
        Ok(true)
    }
}
