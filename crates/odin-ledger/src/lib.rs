#![forbid(unsafe_code)]
#![deny(dead_code)]

//! Durable SQLite/WAL authority for Odin control-plane state.

use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::time::Duration;

use rusqlite::{Connection, Transaction, TransactionBehavior};
use serde::{Deserialize, Deserializer};
use thiserror::Error;
use time::format_description::well_known::Rfc3339;
use time::{OffsetDateTime, UtcOffset};

pub mod approval;
pub mod approval_feed;
pub mod artifact;
pub mod audit;
pub mod browser_control;
pub mod budget;
pub mod checkpoint;
pub mod command;
pub mod conversation_delivery;
pub mod idempotency;
pub mod inbox;
pub mod incident;
pub mod kube;
pub mod lane_run;
pub mod lease;
pub mod live;
pub mod materialized;
pub mod migration;
pub mod operation;
pub mod plan;
pub mod plan_acceptance;
pub mod pod;
pub mod provider_lease;
pub mod revision;
pub mod snapshot;
pub mod stop;
pub mod task_note;
pub mod trace;
pub mod worker;
#[derive(Debug, Error)]
pub enum LedgerError {
    #[error("SQLite ledger operation failed: {0}")]
    Sql(#[from] rusqlite::Error),
    #[error("ledger JSON is invalid: {0}")]
    Json(#[from] serde_json::Error),
    #[error("could not format ledger timestamp: {0}")]
    TimestampFormat(#[from] time::error::Format),
    #[error("could not parse ledger timestamp: {0}")]
    TimestampParse(#[from] time::error::Parse),
    #[error("database schema version {found} is newer than supported version {supported}")]
    NewerSchema { found: i64, supported: i64 },
    #[error("migration {version} checksum drift: expected {expected}, database contains {found}")]
    ChecksumDrift {
        version: i64,
        expected: String,
        found: String,
    },
    #[error("invalid migration set: {0}")]
    InvalidMigrations(String),
    #[error(
        "stale {actor}: expected revision {expected_revision}, actual revision {actual_revision}"
    )]
    StaleActor {
        actor: String,
        expected_revision: i64,
        actual_revision: i64,
    },
    #[error(
        "invalid ledger data: {what}{separator}{cause}",
        separator = if .source.is_some() { ": " } else { "" },
        cause = .source.as_ref().map(|error| error as &dyn std::fmt::Display).unwrap_or(&"")
    )]
    InvalidData {
        what: String,
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },
    #[error("{kind} {id} was not found")]
    NotFound { kind: &'static str, id: String },
    #[error("ledger conflict: {0}")]
    Conflict(String),
    #[error("ledger conflict: live session {id} is truthfully ended; a terminal session is never reclaimed")]
    SessionEnded { id: String },
    #[error("capsule {capsule_id} lease is closed and accepts no new operations")]
    LeaseClosed { capsule_id: String },
    #[error("capsule {capsule_id} is leased under a different authority: {reason}")]
    LeaseAuthorityMismatch { capsule_id: String, reason: String },
    #[error("capsule {capsule_id} lease rebind is blocked by {pending} unresolved operations")]
    LeaseRebindBlocked { capsule_id: String, pending: i64 },
    #[error("event publication failed: {0}")]
    Publish(String),
    #[error("ledger I/O failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("snapshot destination already exists: {0}")]
    DestinationExists(PathBuf),
    #[error("invalid ledger snapshot: {0}")]
    InvalidSnapshot(String),
}

impl LedgerError {
    pub fn invalid_data(what: String) -> Self {
        Self::InvalidData { what, source: None }
    }

    pub fn invalid_data_caused_by(
        what: impl Into<String>,
        source: impl Into<Box<dyn std::error::Error + Send + Sync>>,
    ) -> Self {
        Self::InvalidData {
            what: what.into(),
            source: Some(source.into()),
        }
    }
}

pub type LedgerResult<T> = Result<T, LedgerError>;

pub struct Ledger {
    connection: Connection,
    additional: Vec<migration::OwnedMigration>,
    commit_events: tokio::sync::watch::Sender<()>,
}

impl Ledger {
    pub fn open(path: impl AsRef<Path>) -> LedgerResult<Self> {
        Self::open_with_migrations(path, &[])
    }

    /// Opens an existing ledger for reading. Does not migrate, create the
    /// file, or set write-mode pragmas, so a live authority ledger is left
    /// untouched.
    pub fn open_read_only(path: impl AsRef<Path>) -> LedgerResult<Self> {
        let connection = Connection::open_with_flags(
            path,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )?;
        connection.busy_timeout(CONNECTION_BUSY_TIMEOUT)?;
        connection.pragma_update(None, "query_only", "ON")?;
        let (commit_events, _) = tokio::sync::watch::channel(());
        Ok(Self {
            connection,
            additional: Vec::new(),
            commit_events,
        })
    }

    /// Opens a durable ledger by applying the complete migration set — the
    /// built-in prefix plus `additional` extension suffix — in one immediate
    /// transaction. There is no migration step after open.
    pub fn open_with_migrations(
        path: impl AsRef<Path>,
        additional: &[migration::Migration<'_>],
    ) -> LedgerResult<Self> {
        let mut connection = Connection::open(path)?;
        configure_connection(&connection)?;
        migration::migrate_with(&mut connection, additional)?;
        let (commit_events, _) = tokio::sync::watch::channel(());
        let events = commit_events.clone();
        connection.commit_hook(Some(move || {
            // A wakeup, not an authority revision. Consumers read the durable
            // state after the writer releases its ledger lock.
            events.send_replace(());
            false
        }));
        Ok(Self {
            connection,
            additional: migration::OwnedMigration::capture(additional),
            commit_events,
        })
    }

    pub fn open_in_memory() -> LedgerResult<Self> {
        Self::open_in_memory_with_migrations(&[])
    }

    /// Opens an in-memory ledger with the complete migration set in one
    /// immediate transaction, exactly like [`Ledger::open_with_migrations`].
    pub fn open_in_memory_with_migrations(
        additional: &[migration::Migration<'_>],
    ) -> LedgerResult<Self> {
        Self::open_with_migrations(":memory:", additional)
    }

    /// Watches local writer commits, including writes through `connection()`.
    /// Notifications are coalesced wakeups, not ledger sequence identities.
    /// A commit can still fail after SQLite invokes the hook; consumers must
    /// always re-read committed authority rather than trusting the event.
    pub fn subscribe_commits(&self) -> tokio::sync::watch::Receiver<()> {
        self.commit_events.subscribe()
    }

    pub fn connection(&self) -> &Connection {
        &self.connection
    }

    pub fn connection_mut(&mut self) -> &mut Connection {
        &mut self.connection
    }

    /// Extension suffix this ledger was opened with. Snapshot verification
    /// and [`Ledger::restore_with_migrations`] must reuse this complete
    /// inventory; an empty suffix is only valid for a builtin-only open.
    pub fn additional_migrations(&self) -> Vec<migration::Migration<'_>> {
        self.additional
            .iter()
            .map(migration::OwnedMigration::as_migration)
            .collect()
    }

    pub fn with_tx<T>(
        &mut self,
        operation: impl FnOnce(&Transaction<'_>) -> LedgerResult<T>,
    ) -> LedgerResult<T> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let result = operation(&transaction)?;
        transaction.commit()?;
        Ok(result)
    }
}

/// Opens an independently versioned SQLite store using ledger connection
/// tuning and the same checked, transactional migration runner.
/// `migrations` is the complete inventory, without control-plane schemas.
pub fn open_database(
    path: impl AsRef<Path>,
    migrations: &[migration::Migration<'_>],
) -> LedgerResult<Connection> {
    let mut connection = open_connection(path)?;
    migration::migrate_inventory(&mut connection, migrations)?;
    Ok(connection)
}

fn open_connection(path: impl AsRef<Path>) -> LedgerResult<Connection> {
    let connection = Connection::open(path)?;
    configure_connection(&connection)?;
    Ok(connection)
}

/// Page cache per connection, in KiB (SQLite's negative `cache_size`): odind
/// holds a dozen connections on the controller ledger, and each one's cache
/// is anonymous memory the daemon cannot swap (`MemorySwapMax=0`).
const CONNECTION_CACHE_KIB: i64 = -8192;
/// Maximum wait for another connection's transaction, also used by read-only exports.
const CONNECTION_BUSY_TIMEOUT: Duration = Duration::from_secs(5);

fn configure_connection(connection: &Connection) -> LedgerResult<()> {
    connection.busy_timeout(CONNECTION_BUSY_TIMEOUT)?;
    connection.pragma_update(None, "foreign_keys", "ON")?;
    let _: String = connection.query_row("PRAGMA journal_mode = WAL", [], |row| row.get(0))?;
    // Authority commits precede external effects. WAL NORMAL can acknowledge
    // a tail that power loss discards; FULL syncs each committed transaction.
    connection.pragma_update(None, "synchronous", "FULL")?;
    connection.pragma_update(None, "mmap_size", 268435456i64)?;
    connection.pragma_update(None, "cache_size", CONNECTION_CACHE_KIB)?;
    connection.pragma_update(None, "temp_store", "MEMORY")?;
    Ok(())
}

pub fn encode_utc(value: OffsetDateTime) -> LedgerResult<String> {
    Ok(value.to_offset(UtcOffset::UTC).format(&Rfc3339)?)
}

pub fn decode_utc(value: &str) -> LedgerResult<OffsetDateTime> {
    Ok(OffsetDateTime::parse(value, &Rfc3339)?.to_offset(UtcOffset::UTC))
}

/// Requires a JSON key to be present while accepting an explicit `null`.
pub(crate) fn required_nullable<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(deserializer)
}

pub(crate) fn parse_id<T>(value: &str, column: usize) -> LedgerResult<T>
where
    T: FromStr,
    T::Err: std::error::Error + Send + Sync + 'static,
{
    value.parse().map_err(|error| {
        LedgerError::Sql(rusqlite::Error::FromSqlConversionFailure(
            column,
            rusqlite::types::Type::Text,
            Box::new(error),
        ))
    })
}

#[cfg(test)]
mod commit_event_tests {
    use super::Ledger;

    #[test]
    fn direct_writes_wake_consumers_only_at_transaction_commit() {
        let mut ledger = Ledger::open_in_memory().unwrap();
        ledger
            .connection()
            .execute_batch("CREATE TABLE event_probe (value INTEGER)")
            .unwrap();
        let mut events = ledger.subscribe_commits();
        {
            let transaction = ledger.connection_mut().transaction().unwrap();
            transaction
                .execute("INSERT INTO event_probe VALUES (1)", [])
                .unwrap();
            assert!(!events.has_changed().unwrap());
            transaction.rollback().unwrap();
        }
        assert!(!events.has_changed().unwrap());
        {
            let transaction = ledger.connection_mut().transaction().unwrap();
            transaction
                .execute("INSERT INTO event_probe VALUES (2)", [])
                .unwrap();
            assert!(!events.has_changed().unwrap());
            transaction.commit().unwrap();
        }
        assert!(events.has_changed().unwrap());
        events.borrow_and_update();
        let values: Vec<i64> = ledger
            .connection()
            .prepare("SELECT value FROM event_probe")
            .unwrap()
            .query_map([], |row| row.get(0))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        assert_eq!(values, vec![2]);
        ledger
            .connection()
            .execute("INSERT INTO event_probe VALUES (3)", [])
            .unwrap();
        assert!(events.has_changed().unwrap());
    }
}
