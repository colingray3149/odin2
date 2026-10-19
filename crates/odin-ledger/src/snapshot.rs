//! Consistent SQLite backups and atomic restore publication.

use crate::{migration, Ledger, LedgerError, LedgerResult};
use rusqlite::params;
use std::ffi::OsString;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

static NEXT_STAGING_ID: AtomicU64 = AtomicU64::new(0);
const MAX_STAGING_ATTEMPTS: u64 = 128;

impl Ledger {
    /// Writes a consistent snapshot and publishes it only after it passes validation.
    ///
    /// `destination` must not already exist. Publication is an atomic, no-clobber
    /// operation within the destination directory.
    pub fn backup(&mut self, destination: impl AsRef<Path>) -> LedgerResult<()> {
        self.backup_with_deadline(destination, None)
    }

    /// Backs up under the shared deadline, normalizing and checkpointing WAL state
    /// so restore preserves the file digest.
    pub fn backup_before(
        &mut self,
        destination: impl AsRef<Path>,
        deadline: &Instant,
    ) -> LedgerResult<()> {
        self.backup_with_deadline(destination, Some(deadline))
    }

    fn backup_with_deadline(
        &mut self,
        destination: impl AsRef<Path>,
        deadline: Option<&Instant>,
    ) -> LedgerResult<()> {
        let destination = destination.as_ref();
        let staging = StagedDatabase::reserve_for(destination)?;
        let staging_text = staging.path().to_str().ok_or_else(|| {
            LedgerError::InvalidSnapshot(format!(
                "snapshot path is not valid UTF-8: {}",
                staging.path().display()
            ))
        })?;

        connection_before(self.connection_mut(), deadline, |connection| {
            connection.execute("VACUUM INTO ?1", params![staging_text])?;
            Ok(())
        })?;
        sync_file(staging.path())?;
        let additional = self.additional_migrations();
        verify_database_before(staging.path(), &additional, deadline)?;
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

    /// Restores atomically while interrupting SQLite work and streamed copies at the shared deadline.
    pub fn restore_before(
        source: impl AsRef<Path>,
        destination: impl AsRef<Path>,
        deadline: &Instant,
    ) -> LedgerResult<Ledger> {
        Self::restore_with_migrations_before(source, destination, &[], Some(deadline))
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
        Self::restore_with_migrations_before(source, destination, additional, None)
    }

    fn restore_with_migrations_before(
        source: impl AsRef<Path>,
        destination: impl AsRef<Path>,
        additional: &[migration::Migration<'_>],
        deadline: Option<&Instant>,
    ) -> LedgerResult<Ledger> {
        check_deadline(deadline)?;
        let destination = destination.as_ref();
        let staging = StagedDatabase::reserve_for(destination)?;
        copy_database(source.as_ref(), staging.path(), deadline)?;
        verify_database_before(staging.path(), additional, deadline)?;
        sync_file(staging.path())?;
        check_deadline(deadline)?;
        staging.publish_open(destination, additional, deadline)
    }
}

fn copy_database(source: &Path, staging: &Path, deadline: Option<&Instant>) -> LedgerResult<()> {
    let mut input = File::open(source)?;
    let mut output = OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(staging)?;
    if deadline.is_none() {
        io::copy(&mut input, &mut output)?;
    } else {
        let mut buffer = [0u8; 64 * 1024];
        loop {
            check_deadline(deadline)?;
            let count = input.read(&mut buffer)?;
            if count == 0 {
                break;
            }
            output.write_all(&buffer[..count])?;
        }
    }
    output.flush()?;
    output.sync_all()?;
    Ok(())
}

fn verify_database_before(
    path: &Path,
    additional: &[migration::Migration<'_>],
    deadline: Option<&Instant>,
) -> LedgerResult<()> {
    let mut ledger = Ledger::open_with_migrations_before(path, additional, deadline)?;
    let findings = connection_before(ledger.connection_mut(), deadline, |connection| {
        let mut statement = connection.prepare("PRAGMA integrity_check")?;
        let rows = statement.query_map([], |row| row.get::<_, String>(0))?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    })?;

    if findings.len() != 1 || findings[0] != "ok" {
        return Err(LedgerError::InvalidSnapshot(format!(
            "integrity_check failed for {}: {}",
            path.display(),
            findings.join("; ")
        )));
    }

    // A migration may have written through WAL. Fold it into the main file before
    // that file is published under its final name.
    connection_before(ledger.connection_mut(), deadline, |connection| {
        Ok(connection.execute_batch("PRAGMA wal_checkpoint(TRUNCATE)")?)
    })?;
    drop(ledger);
    sync_file(path)?;
    Ok(())
}

pub(super) fn check_deadline(deadline: Option<&Instant>) -> LedgerResult<()> {
    if deadline.is_some_and(|deadline| Instant::now() >= *deadline) {
        return Err(LedgerError::InvalidSnapshot(
            "restore deadline exceeded".to_owned(),
        ));
    }
    Ok(())
}

/// The scoped watcher is cancelled and joined before the connection can
/// escape. It cannot interrupt an unrelated later use of that connection.
pub(super) fn connection_before<T>(
    connection: &mut rusqlite::Connection,
    deadline: Option<&Instant>,
    operation: impl FnOnce(&mut rusqlite::Connection) -> LedgerResult<T>,
) -> LedgerResult<T> {
    let Some(deadline) = deadline else {
        return operation(connection);
    };
    check_deadline(Some(deadline))?;
    connection.busy_timeout(deadline.saturating_duration_since(Instant::now()))?;
    let expires = *deadline;
    connection.progress_handler(1000, Some(move || Instant::now() >= expires));
    let interrupt = connection.get_interrupt_handle();
    let (cancel, receiver) = std::sync::mpsc::channel::<()>();
    let result = std::thread::scope(|scope| {
        scope.spawn(move || {
            if matches!(
                receiver.recv_timeout(deadline.saturating_duration_since(Instant::now())),
                Err(std::sync::mpsc::RecvTimeoutError::Timeout)
            ) {
                interrupt.interrupt();
            }
        });
        let result = operation(connection);
        drop(cancel);
        check_deadline(Some(deadline))?;
        result
    });
    connection.progress_handler(0, None::<fn() -> bool>);
    result
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
        self.link_and_finalize(destination, None, None).map(|_| ())
    }

    fn publish_open(
        self,
        destination: &Path,
        additional: &[migration::Migration<'_>],
        deadline: Option<&Instant>,
    ) -> LedgerResult<Ledger> {
        self.link_and_finalize(destination, Some(additional), deadline)?
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
        deadline: Option<&Instant>,
    ) -> LedgerResult<Option<Ledger>> {
        check_deadline(deadline)?;
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
            Some(Ledger::open_with_migrations_before(
                destination,
                additional,
                deadline,
            )?)
        } else {
            None
        };

        injected_fault("cleanup")?;
        fs::remove_file(&self.path)?;
        remove_sidecar(&self.path, "-wal")?;
        remove_sidecar(&self.path, "-shm")?;
        sync_parent(destination)?;
        check_deadline(deadline)?;
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
fn inject_publish_fault(kind: &'static str) {
    PUBLISH_FAULT.with(|cell| cell.set(Some(kind)));
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_TEST_DIRECTORY: AtomicU64 = AtomicU64::new(0);

    struct TestDirectory {
        path: PathBuf,
    }

    impl TestDirectory {
        fn new() -> io::Result<Self> {
            for _ in 0..128 {
                let sequence = NEXT_TEST_DIRECTORY.fetch_add(1, Ordering::Relaxed);
                let path = std::env::temp_dir().join(format!(
                    "odin-ledger-snapshot-test-{}-{sequence}",
                    std::process::id()
                ));
                match fs::create_dir(&path) {
                    Ok(()) => return Ok(Self { path }),
                    Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                    Err(error) => return Err(error),
                }
            }
            Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "could not reserve a test directory",
            ))
        }

        fn join(&self, name: &str) -> PathBuf {
            self.path.join(name)
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
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

    fn read_value(path: &Path) -> LedgerResult<String> {
        read_value_with_migrations(path, &[])
    }

    fn read_value_with_migrations(
        path: &Path,
        additional: &[crate::migration::Migration<'_>],
    ) -> LedgerResult<String> {
        let ledger = Ledger::open_with_migrations(path, additional)?;
        Ok(ledger
            .connection()
            .query_row("SELECT value FROM snapshot_test", [], |row| row.get(0))?)
    }

    #[test]
    fn backup_is_consistent_and_reopenable() -> LedgerResult<()> {
        let directory = TestDirectory::new()?;
        let source = directory.join("source.sqlite");
        let backup = directory.join("backup.sqlite");
        let mut ledger = ledger_with_value(&source, "durable")?;

        ledger.backup(&backup)?;

        assert_eq!(read_value(&backup)?, "durable");
        Ok(())
    }

    #[test]
    fn restore_is_reopenable() -> LedgerResult<()> {
        let directory = TestDirectory::new()?;
        let source = directory.join("source.sqlite");
        let backup = directory.join("backup.sqlite");
        let restored = directory.join("restored.sqlite");
        let mut ledger = ledger_with_value(&source, "restored")?;
        ledger.backup(&backup)?;

        let restored_ledger = Ledger::restore(&backup, &restored)?;

        let value = restored_ledger.connection().query_row(
            "SELECT value FROM snapshot_test",
            [],
            |row| row.get::<_, String>(0),
        )?;
        assert_eq!(value, "restored");
        Ok(())
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
    fn backup_before_members_restore_byte_for_byte() -> LedgerResult<()> {
        let directory = TestDirectory::new()?;
        let source = directory.join("source.sqlite");
        let backup = directory.join("backup.sqlite");
        let restored = directory.join("restored.sqlite");
        let mut ledger = ledger_with_value(&source, "durable")?;
        let deadline = Instant::now() + std::time::Duration::from_secs(60);

        ledger.backup_before(&backup, &deadline)?;
        let restored_ledger = Ledger::restore_before(&backup, &restored, &deadline)?;
        drop(restored_ledger);

        assert_eq!(
            fs::read(&backup)?,
            fs::read(&restored)?,
            "the published snapshot and its restore must agree byte for byte"
        );
        Ok(())
    }

    #[test]
    fn restore_with_migrations_reapplies_extension_before_publish() -> LedgerResult<()> {
        use crate::migration::Migration;

        let directory = TestDirectory::new()?;
        let extension_sql = "CREATE TABLE snapshot_extension_test (value TEXT NOT NULL) STRICT;";
        let drifted_sql =
            "CREATE TABLE snapshot_extension_test (value TEXT NOT NULL, extra TEXT) STRICT;";
        let extension_checksum = blake3::hash(extension_sql.as_bytes()).to_hex().to_string();
        let drifted_checksum = blake3::hash(drifted_sql.as_bytes()).to_hex().to_string();
        let extension_path = "schemas/0004_extension.sql";
        let extension = Migration::register(
            crate::migration::LATEST_SCHEMA_VERSION + 1,
            extension_path,
            &extension_checksum,
            extension_sql,
        );
        let drifted = Migration::register(
            crate::migration::LATEST_SCHEMA_VERSION + 1,
            extension_path,
            &drifted_checksum,
            drifted_sql,
        );

        // Builtin snapshot: restore_with_migrations applies the extension
        // suffix on the staged copy before publish.
        let source = directory.join("source.sqlite");
        let backup = directory.join("backup.sqlite");
        let restored = directory.join("restored.sqlite");
        let mut ledger = ledger_with_value(&source, "extended")?;
        ledger.backup(&backup)?;

        let restored_ledger = Ledger::restore_with_migrations(&backup, &restored, &[extension])?;
        let version: i64 = restored_ledger.connection().query_row(
            "SELECT MAX(version) FROM schema_migrations",
            [],
            |row| row.get(0),
        )?;
        let value: String = restored_ledger.connection().query_row(
            "SELECT value FROM snapshot_test",
            [],
            |row| row.get(0),
        )?;
        restored_ledger.connection().execute(
            "INSERT INTO snapshot_extension_test (value) VALUES ('created')",
            [],
        )?;
        assert_eq!(version, crate::migration::LATEST_SCHEMA_VERSION + 1);
        assert_eq!(value, "extended");

        drop(restored_ledger);
        assert!(matches!(
            Ledger::open(&restored),
            Err(LedgerError::NewerSchema { .. })
        ));
        let reopened = Ledger::open_with_migrations(&restored, &[extension])?;
        let extension_value: String = reopened.connection().query_row(
            "SELECT value FROM snapshot_extension_test",
            [],
            |row| row.get(0),
        )?;
        assert_eq!(extension_value, "created");
        drop(reopened);

        // Extension-opened ledger: backup verifies against that complete
        // inventory, and restore_with_migrations with the same set round-trips.
        let extended_source = directory.join("extended-source.sqlite");
        let extended_backup = directory.join("extended-backup.sqlite");
        let extended_restored = directory.join("extended-restored.sqlite");
        let mut extended =
            ledger_with_value_and_migrations(&extended_source, "from-extension", &[extension])?;
        extended.connection().execute(
            "INSERT INTO snapshot_extension_test (value) VALUES ('live')",
            [],
        )?;
        extended.backup(&extended_backup)?;
        assert_eq!(
            read_value_with_migrations(&extended_backup, &[extension])?,
            "from-extension"
        );
        drop(extended);

        let restored_extended =
            Ledger::restore_with_migrations(&extended_backup, &extended_restored, &[extension])?;
        let restored_version: i64 = restored_extended.connection().query_row(
            "SELECT MAX(version) FROM schema_migrations",
            [],
            |row| row.get(0),
        )?;
        let live: String = restored_extended.connection().query_row(
            "SELECT value FROM snapshot_extension_test",
            [],
            |row| row.get(0),
        )?;
        assert_eq!(
            restored_version,
            crate::migration::LATEST_SCHEMA_VERSION + 1
        );
        assert_eq!(live, "live");
        assert_eq!(
            restored_extended.additional_migrations().len(),
            1,
            "restored ledger must retain the complete extension suffix"
        );
        drop(restored_extended);

        let drifted_dest = directory.join("drifted.sqlite");
        assert!(matches!(
            Ledger::restore_with_migrations(&extended_backup, &drifted_dest, &[drifted]),
            Err(LedgerError::ChecksumDrift { version, .. })
                if version == crate::migration::LATEST_SCHEMA_VERSION + 1
        ));
        assert!(
            !drifted_dest.exists(),
            "a drifted restore must publish nothing"
        );
        Ok(())
    }

    fn sidecar_exists(path: &Path, suffix: &str) -> bool {
        let mut sidecar = path.as_os_str().to_os_string();
        sidecar.push(suffix);
        PathBuf::from(sidecar).exists()
    }

    fn destination_absent(path: &Path) -> bool {
        !path.exists() && !sidecar_exists(path, "-wal") && !sidecar_exists(path, "-shm")
    }

    #[test]
    fn publish_rolls_back_destination_on_post_link_failure() -> LedgerResult<()> {
        let directory = TestDirectory::new()?;
        let source = directory.join("source.sqlite");
        let backup = directory.join("backup.sqlite");
        let mut ledger = ledger_with_value(&source, "rollback")?;
        super::inject_publish_fault("post-link");
        assert!(ledger.backup(&backup).is_err());
        assert!(
            destination_absent(&backup),
            "post-link failure must not leave a published path"
        );
        Ok(())
    }

    #[test]
    fn restore_rolls_back_destination_on_open_failure() -> LedgerResult<()> {
        let directory = TestDirectory::new()?;
        let source = directory.join("source.sqlite");
        let backup = directory.join("backup.sqlite");
        let restored = directory.join("restored.sqlite");
        let mut ledger = ledger_with_value(&source, "rollback-open")?;
        ledger.backup(&backup)?;
        super::inject_publish_fault("open");
        assert!(Ledger::restore(&backup, &restored).is_err());
        assert!(
            destination_absent(&restored),
            "open failure after link must delete destination and sidecars"
        );
        Ok(())
    }

    #[test]
    fn restore_rolls_back_destination_on_cleanup_failure() -> LedgerResult<()> {
        let directory = TestDirectory::new()?;
        let source = directory.join("source.sqlite");
        let backup = directory.join("backup.sqlite");
        let restored = directory.join("restored.sqlite");
        let mut ledger = ledger_with_value(&source, "rollback-cleanup")?;
        ledger.backup(&backup)?;
        super::inject_publish_fault("cleanup");
        assert!(Ledger::restore(&backup, &restored).is_err());
        assert!(
            destination_absent(&restored),
            "cleanup failure after link must delete destination and sidecars"
        );
        Ok(())
    }
}
