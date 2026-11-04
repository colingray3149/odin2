//! Consistent SQLite backups and atomic restore publication.

use crate::{migration, Ledger, LedgerError, LedgerResult};
use rusqlite::params;
use std::ffi::OsString;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT_STAGING_ID: AtomicU64 = AtomicU64::new(0);
const MAX_STAGING_ATTEMPTS: u64 = 128;

impl Ledger {
    /// Writes a consistent snapshot and publishes it only after it passes validation.
    ///
    /// `destination` must not already exist. Publication is an atomic, no-clobber
    /// operation within the destination directory. The snapshot is normalized and
    /// checkpointed so a restore preserves the file digest.
    pub fn backup(&mut self, destination: impl AsRef<Path>) -> LedgerResult<()> {
        let destination = destination.as_ref();
        let staging = StagedDatabase::reserve_for(destination)?;
        let staging_text = staging.path().to_str().ok_or_else(|| {
            LedgerError::InvalidSnapshot(format!(
                "snapshot path is not valid UTF-8: {}",
                staging.path().display()
            ))
        })?;

        self.connection_mut()
            .execute("VACUUM INTO ?1", params![staging_text])?;
        sync_file(staging.path())?;
        let additional = self.additional_migrations();
        verify_database(staging.path(), &additional)?;
        sync_file(staging.path())?;
        staging.publish(destination)
    }

    /// Restores a snapshot into a path that must not already exist.
    ///
    /// Validation and migration happen on a same-directory staging file. The
    /// verified inode is then published atomically before the opened ledger is
    /// returned.
    pub fn restore(
        source: impl AsRef<Path>,
        destination: impl AsRef<Path>,
    ) -> LedgerResult<Ledger> {
        Self::restore_with_migrations(source, destination, &[])
    }

    /// Restores a snapshot and applies the complete migration set — the
    /// built-in prefix plus `additional` extension suffix — to the staged copy
    /// in one immediate transaction before publication. The returned ledger is
    /// opened against that same complete set: no migration ever runs after
    /// open, and a snapshot written at a schema version the supplied set does
    /// not reach fails closed.
    pub fn restore_with_migrations(
        source: impl AsRef<Path>,
        destination: impl AsRef<Path>,
        additional: &[migration::Migration<'_>],
    ) -> LedgerResult<Ledger> {
        let destination = destination.as_ref();
        let staging = StagedDatabase::reserve_for(destination)?;
        copy_database(source.as_ref(), staging.path())?;
        verify_database(staging.path(), additional)?;
        sync_file(staging.path())?;
        staging.publish_open(destination, additional)
    }
}

fn copy_database(source: &Path, staging: &Path) -> LedgerResult<()> {
    let mut input = File::open(source)?;
    let mut output = OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(staging)?;
    io::copy(&mut input, &mut output)?;
    output.flush()?;
    output.sync_all()?;
    Ok(())
}

fn verify_database(path: &Path, additional: &[migration::Migration<'_>]) -> LedgerResult<()> {
    let ledger = Ledger::open_with_migrations(path, additional)?;
    let findings = {
        let mut statement = ledger.connection().prepare("PRAGMA integrity_check")?;
        let rows = statement.query_map([], |row| row.get::<_, String>(0))?;
        rows.collect::<rusqlite::Result<Vec<_>>>()?
    };

    if findings.len() != 1 || findings[0] != "ok" {
        return Err(LedgerError::InvalidSnapshot(format!(
            "integrity_check failed for {}: {}",
            path.display(),
            findings.join("; ")
        )));
    }

    // A migration may have written through WAL. Fold it into the main file before
    // that file is published under its final name.
    ledger
        .connection()
        .execute_batch("PRAGMA wal_checkpoint(TRUNCATE)")?;
    drop(ledger);
    sync_file(path)?;
    Ok(())
}

fn sync_file(path: &Path) -> io::Result<()> {
    OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)?
        .sync_all()
}

fn sync_parent(path: &Path) -> io::Result<()> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    File::open(parent)?.sync_all()
}

struct StagedDatabase {
    path: PathBuf,
}

impl StagedDatabase {
    fn reserve_for(destination: &Path) -> LedgerResult<Self> {
        let parent = destination.parent().unwrap_or_else(|| Path::new("."));
        let file_name = destination.file_name().ok_or_else(|| {
            LedgerError::InvalidSnapshot(format!(
                "snapshot destination has no file name: {}",
                destination.display()
            ))
        })?;
        let process_id = std::process::id();

        for _ in 0..MAX_STAGING_ATTEMPTS {
            let sequence = NEXT_STAGING_ID.fetch_add(1, Ordering::Relaxed);
            let mut staging_name = OsString::from(".");
            staging_name.push(file_name);
            staging_name.push(format!(".odin-{process_id}-{sequence}.tmp"));
            let path = parent.join(staging_name);

            match OpenOptions::new().write(true).create_new(true).open(&path) {
                Ok(file) => {
                    file.sync_all()?;
                    return Ok(Self { path });
                }
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(error) => return Err(error.into()),
            }
        }

        Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            format!(
                "could not reserve a staging file for {}",
                destination.display()
            ),
        )
        .into())
    }

    fn path(&self) -> &Path {
        &self.path
    }

    fn publish(self, destination: &Path) -> LedgerResult<()> {
        self.link_and_finalize(destination, None).map(|_| ())
    }

    fn publish_open(
        self,
        destination: &Path,
        additional: &[migration::Migration<'_>],
    ) -> LedgerResult<Ledger> {
        self.link_and_finalize(destination, Some(additional))?
            .ok_or_else(|| {
                LedgerError::InvalidSnapshot(
                    "destination ledger missing after guarded publish".to_owned(),
                )
            })
    }

    fn link_and_finalize(
        self,
        destination: &Path,
        additional: Option<&[migration::Migration<'_>]>,
    ) -> LedgerResult<Option<Ledger>> {
        match fs::hard_link(&self.path, destination) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                return Err(LedgerError::DestinationExists(destination.to_path_buf()));
            }
            Err(error) => return Err(error.into()),
        }
        let mut rollback = DestinationRollback::arm(destination);
        injected_fault("post-link")?;

        let opened = if let Some(additional) = additional {
            injected_fault("open")?;
            Some(Ledger::open_with_migrations(destination, additional)?)
        } else {
            None
        };

        injected_fault("cleanup")?;
        fs::remove_file(&self.path)?;
        remove_sidecar(&self.path, "-wal")?;
        remove_sidecar(&self.path, "-shm")?;
        sync_parent(destination)?;
        rollback.disarm();
        Ok(opened)
    }
}

impl Drop for StagedDatabase {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
        let _ = remove_sidecar(&self.path, "-wal");
        let _ = remove_sidecar(&self.path, "-shm");
    }
}

fn remove_sidecar(path: &Path, suffix: &str) -> io::Result<()> {
    let mut sidecar = path.as_os_str().to_os_string();
    sidecar.push(suffix);
    match fs::remove_file(PathBuf::from(sidecar)) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

struct DestinationRollback {
    destination: PathBuf,
    armed: bool,
}

impl DestinationRollback {
    fn arm(destination: &Path) -> Self {
        Self {
            destination: destination.to_path_buf(),
            armed: true,
        }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for DestinationRollback {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        let _ = fs::remove_file(&self.destination);
        let _ = remove_sidecar(&self.destination, "-wal");
        let _ = remove_sidecar(&self.destination, "-shm");
        let _ = sync_parent(&self.destination);
    }
}

fn injected_fault(_kind: &'static str) -> LedgerResult<()> {
    #[cfg(test)]
    {
        let hit = PUBLISH_FAULT.with(|cell| {
            if cell.get() == Some(_kind) {
                cell.set(None);
                true
            } else {
                false
            }
        });
        if hit {
            return Err(LedgerError::InvalidSnapshot(format!(
                "injected {_kind} failure"
            )));
        }
    }
    Ok(())
}

#[cfg(test)]
thread_local! {
    static PUBLISH_FAULT: std::cell::Cell<Option<&'static str>> =
        const { std::cell::Cell::new(None) };
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestDirectory {
        scratch: tempfile::TempDir,
    }

    impl TestDirectory {
        fn new() -> io::Result<Self> {
            Ok(Self {
                scratch: tempfile::tempdir()?,
            })
        }

        fn join(&self, name: &str) -> PathBuf {
            self.scratch.path().join(name)
        }
    }

    fn ledger_with_value(path: &Path, value: &str) -> LedgerResult<Ledger> {
        ledger_with_value_and_migrations(path, value, &[])
    }

    fn ledger_with_value_and_migrations(
        path: &Path,
        value: &str,
        additional: &[crate::migration::Migration<'_>],
    ) -> LedgerResult<Ledger> {
        let ledger = Ledger::open_with_migrations(path, additional)?;
        ledger
            .connection()
            .execute_batch("CREATE TABLE snapshot_test (value TEXT NOT NULL);")?;
        ledger.connection().execute(
            "INSERT INTO snapshot_test (value) VALUES (?1)",
            params![value],
        )?;
        Ok(ledger)
    }

    #[test]
    fn failed_restore_verification_publishes_nothing() -> LedgerResult<()> {
        let directory = TestDirectory::new()?;
        let corrupt = directory.join("corrupt.sqlite");
        let destination = directory.join("destination.sqlite");
        fs::write(&corrupt, b"not a sqlite database")?;

        assert!(Ledger::restore(&corrupt, &destination).is_err());
        assert!(!destination.exists());
        Ok(())
    }

    #[test]
    fn backup_and_restore_never_clobber() -> LedgerResult<()> {
        let directory = TestDirectory::new()?;
        let source = directory.join("source.sqlite");
        let backup = directory.join("backup.sqlite");
        let occupied = directory.join("occupied.sqlite");
        let mut ledger = ledger_with_value(&source, "source")?;
        ledger.backup(&backup)?;
        fs::write(&occupied, b"keep me")?;

        assert!(matches!(
            ledger.backup(&occupied),
            Err(LedgerError::DestinationExists(path)) if path == occupied
        ));
        assert_eq!(fs::read(&occupied)?, b"keep me");

        assert!(matches!(
            Ledger::restore(&backup, &occupied),
            Err(LedgerError::DestinationExists(path)) if path == occupied
        ));
        assert_eq!(fs::read(&occupied)?, b"keep me");
        Ok(())
    }

    #[test]
    fn a_restore_matches_its_backup_byte_for_byte() -> LedgerResult<()> {
        let directory = TestDirectory::new()?;
        let source = directory.join("source.sqlite");
        let backup = directory.join("backup.sqlite");
        let restored = directory.join("restored.sqlite");
        let mut ledger = ledger_with_value(&source, "durable")?;

        ledger.backup(&backup)?;
        drop(Ledger::restore(&backup, &restored)?);

        assert_eq!(
            fs::read(&backup)?,
            fs::read(&restored)?,
            "the published snapshot and its restore must agree byte for byte"
        );
        Ok(())
    }
}
