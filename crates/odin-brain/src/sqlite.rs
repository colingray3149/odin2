//! One SQLite discipline for every brain store. A store file is opened by
//! odind and, concurrently, by operator commands (`odind archive ingest` /
//! `backfill`) in other processes: the in-process connection mutex does not
//! serialize them, so a connection waits for the other process's writer
//! instead of failing `database is locked`, and every write transaction
//! takes the write lock up front — under WAL a deferred read-then-write
//! transaction can never be upgraded once another writer committed.

use std::path::Path;
use std::time::Duration;

use rusqlite::{Connection, Transaction, TransactionBehavior};

/// Longest wait for another process's write transaction. The largest brain
/// write (publishing one archive generation's staged chunks) takes seconds.
pub(crate) const BUSY_TIMEOUT: Duration = Duration::from_secs(30);

/// Opens a file-backed store connection: busy wait, foreign keys, WAL.
pub(crate) fn open(path: &Path) -> rusqlite::Result<Connection> {
    let connection = Connection::open(path)?;
    connection.busy_timeout(BUSY_TIMEOUT)?;
    connection.pragma_update(None, "foreign_keys", "ON")?;
    let _: String = connection.query_row("PRAGMA journal_mode = WAL", [], |row| row.get(0))?;
    Ok(connection)
}

/// Begins a write transaction holding the database write lock from the start.
pub(crate) fn write_transaction(connection: &Connection) -> rusqlite::Result<Transaction<'_>> {
    Transaction::new_unchecked(connection, TransactionBehavior::Immediate)
}
