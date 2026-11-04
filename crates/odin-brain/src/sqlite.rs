//! One SQLite discipline for the archive store. Its file is opened by
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

#[cfg(test)]
mod tests {
    use super::*;

    /// A second connection's write waits for the first's open transaction and
    /// then succeeds, instead of failing `database is locked`.
    #[test]
    fn a_writer_waits_for_the_writer_ahead_of_it() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("store.sqlite3");
        let first = open(&path).unwrap();
        first.execute_batch("CREATE TABLE t (n INTEGER)").unwrap();
        let (held, release) = std::sync::mpsc::channel::<()>();
        let (opened, wait) = std::sync::mpsc::channel::<()>();
        let holder = std::thread::spawn(move || {
            let transaction = write_transaction(&first).unwrap();
            transaction.execute("INSERT INTO t VALUES (1)", []).unwrap();
            opened.send(()).unwrap();
            release.recv().unwrap();
            transaction.commit().unwrap();
        });
        wait.recv().unwrap();
        let second = open(&path).unwrap();
        let writer = std::thread::spawn(move || {
            let transaction = write_transaction(&second).unwrap();
            transaction.execute("INSERT INTO t VALUES (2)", []).unwrap();
            transaction.commit().unwrap();
            second
                .query_row("SELECT count(*) FROM t", [], |row| row.get::<_, i64>(0))
                .unwrap()
        });
        // The second writer is parked on the first's lock; releasing it lets both land.
        held.send(()).unwrap();
        holder.join().unwrap();
        assert_eq!(writer.join().unwrap(), 2);
    }
}
