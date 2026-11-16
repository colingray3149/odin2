//! Per-operation exclusion spanning external callbacks, with durable generations.
//!
//! File-backed ledgers use a persistent sidecar lock file per correlation ID.
//! Never unlink these files: doing so could split the lock domain. File locks are
//! released by the OS on process death; they do not hold a SQLite transaction.
//! In-memory ledgers instead use a lock set owned by the ledger instance.

use std::collections::HashSet;
use std::fs::{File, OpenOptions};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use rusqlite::{params, OptionalExtension, Transaction};

use crate::{Ledger, LedgerError, LedgerResult};
#[cfg(test)]
mod tests;

/// An exclusive operation guard. Keep it alive from before preparing an effect
/// until after its settlement transaction commits. It is independent of the
/// ledger borrow, so callbacks may use the same connection.
pub struct OperationFence {
    correlation_id: String,
    generation: Option<i64>,
    lock: FenceLock,
}

enum FenceLock {
    File(File),
    Memory(Arc<Mutex<HashSet<String>>>),
}

impl Ledger {
    /// Try to acquire exclusive ownership without blocking. `None` means an
    /// active owner holds it. File-backed connections to the same database use
    /// the same canonical SQLite filename and therefore the same lock domain.
    pub fn try_operation_fence(
        &self,
        correlation_id: &str,
    ) -> LedgerResult<Option<OperationFence>> {
        let filename: String = self.connection.query_row(
            "SELECT file FROM pragma_database_list WHERE name = 'main'",
            [],
            |row| row.get(0),
        )?;
        let lock = if filename.is_empty() {
            let mut held = self
                .operation_fences
                .lock()
                .map_err(|_| LedgerError::Conflict("operation fence lock poisoned".into()))?;
            if !held.insert(correlation_id.to_owned()) {
                return Ok(None);
            }
            FenceLock::Memory(Arc::clone(&self.operation_fences))
        } else {
            let database = std::fs::canonicalize(filename)?;
            let mut directory = database.into_os_string();
            directory.push(".operation-fences");
            let directory = PathBuf::from(directory);
            std::fs::create_dir_all(&directory)?;
            let name = blake3::hash(correlation_id.as_bytes()).to_hex().to_string();
            let file = OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .truncate(false)
                .open(directory.join(name))?;
            match file.try_lock() {
                Ok(()) => FenceLock::File(file),
                Err(std::fs::TryLockError::WouldBlock) => return Ok(None),
                Err(std::fs::TryLockError::Error(error)) => return Err(error.into()),
            }
        };
        Ok(Some(OperationFence {
            correlation_id: correlation_id.to_owned(),
            generation: None,
            lock,
        }))
    }
}

impl OperationFence {
    /// Advance the durable generation within an immediate transaction. Commit
    /// this transaction before executing an external effect. A rolled-back
    /// claim is not authority and will fail `check`.
    pub fn claim(&mut self, tx: &Transaction<'_>) -> LedgerResult<()> {
        let generation: i64 = tx.query_row(
            "INSERT INTO operation_fences (correlation_id, generation) VALUES (?1, 1) \
             ON CONFLICT(correlation_id) DO UPDATE SET generation = generation + 1 \
             RETURNING generation",
            params![self.correlation_id],
            |row| row.get(0),
        )?;
        self.generation = Some(generation);
        Ok(())
    }

    /// Check ownership in the same immediate transaction as a state change.
    /// An unclaimed, rolled-back or superseded generation fails closed.
    pub fn check(&self, tx: &Transaction<'_>) -> LedgerResult<()> {
        let current: Option<i64> = tx
            .query_row(
                "SELECT generation FROM operation_fences WHERE correlation_id = ?1",
                params![self.correlation_id],
                |row| row.get(0),
            )
            .optional()?;
        if self.generation.is_none() || current != self.generation {
            return Err(LedgerError::Conflict(format!(
                "operation fence for {} is stale or unclaimed",
                self.correlation_id
            )));
        }
        Ok(())
    }
}

impl Drop for OperationFence {
    fn drop(&mut self) {
        match &self.lock {
            FenceLock::File(file) => {
                let _ = file.unlock();
            }
            FenceLock::Memory(held) => {
                if let Ok(mut held) = held.lock() {
                    held.remove(&self.correlation_id);
                }
            }
        }
    }
}
