use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use super::atomic::read_regular_file;
use super::contract::{tombstones_for, Snapshot, SnapshotError};
use super::provenance::ValidatedSnapshotCandidate;
use super::store::{
    decode_publication_receipt, versioned_receipt_path, versioned_snapshot_path,
    PublicationOutcome, PublicationReceipt, PublicationResult, SnapshotBase, SnapshotStore,
    PUBLICATION_RECEIPT_SCHEMA,
};
use crate::snapshot::atomic_write;

impl SnapshotStore {
    /// Serialize publication under a file lock and install immutable snapshot and receipt before the active pointer.
    pub fn publish_committed(
        &self,
        candidate: &ValidatedSnapshotCandidate,
        expected_revision: u64,
    ) -> Result<PublicationResult, SnapshotError> {
        if expected_revision == 0 {
            return Err(SnapshotError::Invalid(
                "expected revision must be positive".to_owned(),
            ));
        }
        let _lock = PublicationLock::acquire(self.path())?;
        candidate.check_runtime_base(self)?;
        match self.base_for_update()? {
            SnapshotBase::Missing => {
                if expected_revision != 1 {
                    return Err(SnapshotError::Stale {
                        expected: expected_revision,
                        active: None,
                    });
                }
                let snapshot = Snapshot::build(1, candidate.objects().to_vec())?;
                self.install_committed(
                    candidate,
                    None,
                    None,
                    None,
                    snapshot,
                    PublicationOutcome::Published,
                )
            }
            SnapshotBase::Current(previous) => {
                let mut objects = candidate.objects().to_vec();
                objects.sort_by(|left, right| {
                    (left.kind(), left.id.as_str()).cmp(&(right.kind(), right.id.as_str()))
                });
                if previous.objects == objects {
                    if previous.revision != expected_revision {
                        return Err(SnapshotError::Stale {
                            expected: expected_revision,
                            active: Some(previous.revision),
                        });
                    }
                    // Replay requires the same commit, tree, and projection; projected completion still advances the anchor.
                    let anchor = match self.publication_at(previous.revision) {
                        Ok((_, receipt)) => {
                            (!candidate.matches_receipt(&receipt)).then_some(receipt)
                        }
                        Err(SnapshotError::Io { source, .. })
                            if source.kind() == std::io::ErrorKind::NotFound =>
                        {
                            None
                        }
                        Err(error) => return Err(error),
                    };
                    let (previous_revision, snapshot, outcome) = match anchor {
                        None => (
                            previous
                                .revision
                                .checked_sub(1)
                                .filter(|revision| *revision > 0),
                            previous.clone(),
                            PublicationOutcome::Unchanged,
                        ),
                        Some(receipt) => {
                            if let Err(reason) = candidate.publishes_on_receipt(self, &receipt) {
                                return Err(SnapshotError::NonChild {
                                    expected_parent: receipt.commit,
                                    commit: candidate.commit().to_owned(),
                                    reason,
                                });
                            }
                            let target = previous.revision.checked_add(1).ok_or_else(|| {
                                SnapshotError::Invalid("snapshot revision exhausted u64".to_owned())
                            })?;
                            (
                                Some(previous.revision),
                                Snapshot::build(target, candidate.objects().to_vec())?,
                                PublicationOutcome::Published,
                            )
                        }
                    };
                    return self.install_committed(
                        candidate,
                        Some(&previous),
                        previous_revision,
                        None,
                        snapshot,
                        outcome,
                    );
                }
                let target = previous.revision.checked_add(1).ok_or_else(|| {
                    SnapshotError::Invalid("snapshot revision exhausted u64".to_owned())
                })?;
                if target != expected_revision {
                    return Err(SnapshotError::Stale {
                        expected: expected_revision,
                        active: Some(previous.revision),
                    });
                }
                let previous_receipt = self.publication_at(previous.revision)?.1;
                if let Err(reason) = candidate.publishes_on_receipt(self, &previous_receipt) {
                    return Err(SnapshotError::NonChild {
                        expected_parent: previous_receipt.commit,
                        commit: candidate.commit().to_owned(),
                        reason,
                    });
                }
                let snapshot = Snapshot::build(target, candidate.objects().to_vec())?;
                self.install_committed(
                    candidate,
                    Some(&previous),
                    Some(previous.revision),
                    None,
                    snapshot,
                    PublicationOutcome::Published,
                )
            }
            SnapshotBase::Incompatible {
                revision,
                archive_path,
            } => {
                self.verify_incompatible_publication(revision)?;
                let target = revision.checked_add(1).ok_or_else(|| {
                    SnapshotError::Invalid("snapshot revision exhausted u64".to_owned())
                })?;
                if target != expected_revision {
                    return Err(SnapshotError::Stale {
                        expected: expected_revision,
                        active: Some(revision),
                    });
                }
                let snapshot = Snapshot::build(target, candidate.objects().to_vec())?;
                self.install_committed(
                    candidate,
                    None,
                    Some(revision),
                    Some(archive_path),
                    snapshot,
                    PublicationOutcome::Published,
                )
            }
        }
    }

    /// Sync files before no-replace claims so crashes leave either absent or complete reusable publications.
    fn install_committed(
        &self,
        candidate: &ValidatedSnapshotCandidate,
        previous: Option<&Snapshot>,
        previous_revision: Option<u64>,
        incompatible_archive: Option<PathBuf>,
        snapshot: Snapshot,
        outcome: PublicationOutcome,
    ) -> Result<PublicationResult, SnapshotError> {
        let mut published = snapshot;
        published.tombstones = tombstones_for(previous, &published)?;
        published.hash = published.canonical_hash()?;
        published.verify()?;

        let mut snapshot_bytes = serde_json::to_vec_pretty(&published)?;
        snapshot_bytes.push(b'\n');
        let versioned_path = versioned_snapshot_path(self.path(), published.revision);
        match create_immutable_file(&versioned_path, &snapshot_bytes)? {
            ImmutableFile::Installed => {}
            ImmutableFile::Existing(existing) => {
                if existing != snapshot_bytes {
                    return Err(SnapshotError::Conflict {
                        revision: published.revision,
                    });
                }
            }
        }
        if let Some(archive_path) = incompatible_archive {
            archive_incompatible_snapshot(self.path(), &archive_path)?;
        }

        let install_receipt = PublicationReceipt {
            schema: PUBLICATION_RECEIPT_SCHEMA.to_owned(),
            outcome: PublicationOutcome::Published,
            revision: published.revision,
            previous_revision,
            commit: candidate.commit().to_owned(),
            tree: candidate.tree().to_owned(),
            snapshot_hash: published.hash.clone(),
            runtime_projection: candidate.projection().cloned(),
        };
        let receipt_path = versioned_receipt_path(self.path(), published.revision);
        let mut receipt_bytes = serde_json::to_vec_pretty(&install_receipt)?;
        receipt_bytes.push(b'\n');
        let durable_receipt = match create_immutable_file(&receipt_path, &receipt_bytes)? {
            ImmutableFile::Installed => install_receipt,
            ImmutableFile::Existing(existing) => {
                let retained = decode_publication_receipt(&receipt_path, &existing, &published)?;
                let completes_projection = match previous
                    .filter(|previous| previous_revision == Some(previous.revision))
                {
                    Some(previous) => self
                        .publication_at(previous.revision)?
                        .1
                        .runtime_projection
                        .is_some(),
                    None => false,
                };
                if (candidate.projection().is_some()
                    || retained.runtime_projection.is_some()
                    || completes_projection)
                    && retained != install_receipt
                {
                    return Err(SnapshotError::Conflict {
                        revision: published.revision,
                    });
                }
                retained
            }
        };

        match self.base_for_update()? {
            SnapshotBase::Current(active) if active.revision == published.revision => {
                if active.hash != published.hash {
                    return Err(SnapshotError::Invalid(format!(
                        "active snapshot at revision {} differs from the committed publication",
                        published.revision
                    )));
                }
                let (verified, bound_receipt) = self.load_verified_publication()?;
                if verified.hash != published.hash || bound_receipt != durable_receipt {
                    return Err(SnapshotError::Invalid(format!(
                        "active snapshot revision {} is not the installed committed publication",
                        published.revision
                    )));
                }
                return Ok(PublicationResult {
                    outcome: PublicationOutcome::Unchanged,
                    receipt: bound_receipt,
                });
            }
            SnapshotBase::Missing if previous_revision.is_none() => {}
            SnapshotBase::Current(active)
                if previous_revision.is_some_and(|revision| revision == active.revision) => {}
            SnapshotBase::Incompatible { revision, .. }
                if previous_revision.is_some_and(|previous| previous == revision) => {}
            SnapshotBase::Current(active) => {
                return Err(SnapshotError::Stale {
                    expected: published.revision,
                    active: Some(active.revision),
                });
            }
            SnapshotBase::Incompatible { revision, .. } => {
                return Err(SnapshotError::Stale {
                    expected: published.revision,
                    active: Some(revision),
                });
            }
            SnapshotBase::Missing => {
                return Err(SnapshotError::Stale {
                    expected: published.revision,
                    active: None,
                });
            }
        }

        atomic_write(
            self.path(),
            &snapshot_bytes[..snapshot_bytes.len().saturating_sub(1)],
        )
        .map_err(SnapshotError::from_atomic)?;
        let (verified, bound_receipt) = self.load_verified_publication()?;
        if verified.hash != published.hash || bound_receipt != durable_receipt {
            return Err(SnapshotError::Invalid(format!(
                "active snapshot revision {} did not install exactly",
                published.revision
            )));
        }
        Ok(PublicationResult {
            outcome,
            receipt: bound_receipt,
        })
    }
}

pub(super) struct PublicationLock {
    file: File,
}

impl PublicationLock {
    pub(super) fn acquire(active_path: &Path) -> Result<Self, SnapshotError> {
        let parent = active_path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        fs::create_dir_all(parent).map_err(|source| SnapshotError::Io {
            action: "create publication directory",
            path: parent.to_path_buf(),
            source,
        })?;
        let file_name = active_path
            .file_name()
            .ok_or_else(|| SnapshotError::Invalid("snapshot path has no filename".to_owned()))?;
        let lock_path = parent.join(format!(".{}.publish.lock", file_name.to_string_lossy()));
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&lock_path)
            .map_err(|source| SnapshotError::Io {
                action: "open publication lock",
                path: lock_path.clone(),
                source,
            })?;
        file.lock().map_err(|source| SnapshotError::Io {
            action: "lock publication",
            path: lock_path,
            source,
        })?;
        Ok(Self { file })
    }
}

impl Drop for PublicationLock {
    fn drop(&mut self) {
        let _ = self.file.unlock();
    }
}

enum ImmutableFile {
    Installed,
    Existing(Vec<u8>),
}

/// Sync a sibling temporary file before a no-replace hard link so partial final files are never visible.
fn create_immutable_file(path: &Path, bytes: &[u8]) -> Result<ImmutableFile, SnapshotError> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    fs::create_dir_all(parent).map_err(|source| SnapshotError::Io {
        action: "create revisions directory",
        path: parent.to_path_buf(),
        source,
    })?;
    match read_regular_file(path) {
        Ok(existing) => return Ok(ImmutableFile::Existing(existing)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(source) => {
            return Err(SnapshotError::Io {
                action: "read existing immutable file",
                path: path.to_path_buf(),
                source,
            });
        }
    }
    let file_name = path
        .file_name()
        .ok_or_else(|| SnapshotError::Invalid("immutable path has no filename".to_owned()))?;
    let file_name = file_name.to_string_lossy();
    let mut staged = None;
    for attempt in 0..128_u16 {
        let staged_path = parent.join(format!(
            ".{file_name}.stage.{}.{}",
            std::process::id(),
            attempt
        ));
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&staged_path)
        {
            Ok(file) => {
                staged = Some((staged_path, file));
                break;
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(source) => {
                return Err(SnapshotError::Io {
                    action: "create staged immutable file",
                    path: staged_path,
                    source,
                });
            }
        }
    }
    let (staged_path, mut file) = staged.ok_or_else(|| SnapshotError::Io {
        action: "allocate staged immutable file",
        path: path.to_path_buf(),
        source: std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            "all immutable staging names are occupied",
        ),
    })?;
    if let Err(source) = file.write_all(bytes) {
        drop(file);
        let _ = fs::remove_file(&staged_path);
        return Err(SnapshotError::Io {
            action: "write staged immutable file",
            path: staged_path,
            source,
        });
    }
    if let Err(source) = file.sync_all() {
        drop(file);
        let _ = fs::remove_file(&staged_path);
        return Err(SnapshotError::Io {
            action: "sync staged immutable file",
            path: staged_path,
            source,
        });
    }
    drop(file);

    let outcome = match fs::hard_link(&staged_path, path) {
        Ok(()) => ImmutableFile::Installed,
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            let existing = read_regular_file(path).map_err(|source| SnapshotError::Io {
                action: "read existing immutable file",
                path: path.to_path_buf(),
                source,
            })?;
            ImmutableFile::Existing(existing)
        }
        Err(source) => {
            let _ = fs::remove_file(&staged_path);
            return Err(SnapshotError::Io {
                action: "claim immutable file",
                path: path.to_path_buf(),
                source,
            });
        }
    };
    match fs::remove_file(&staged_path) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(source) => {
            return Err(SnapshotError::Io {
                action: "remove staged immutable file",
                path: staged_path,
                source,
            });
        }
    }
    sync_archive_directory(path)?;
    Ok(outcome)
}

pub(super) fn archive_path(path: &Path, source: &[u8]) -> Result<PathBuf, SnapshotError> {
    let file_name = path
        .file_name()
        .ok_or_else(|| SnapshotError::Invalid("snapshot path has no filename".to_owned()))?;
    let mut archive_name = file_name.to_os_string();
    archive_name.push(".");
    archive_name.push(blake3::hash(source).to_hex().as_str());
    archive_name.push(".archive");
    Ok(path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or(Path::new("."))
        .join(archive_name))
}

fn archive_incompatible_snapshot(
    active_path: &Path,
    expected_archive_path: &Path,
) -> Result<(), SnapshotError> {
    let source = fs::read(active_path).map_err(|source| SnapshotError::Io {
        action: "read incompatible snapshot for archival",
        path: active_path.to_path_buf(),
        source,
    })?;
    let actual_archive_path = archive_path(active_path, &source)?;
    if actual_archive_path != expected_archive_path {
        return Err(SnapshotError::Invalid(
            "active snapshot changed while its update was being prepared".to_owned(),
        ));
    }
    match fs::hard_link(active_path, expected_archive_path) {
        Ok(()) => {
            let archived = fs::read(expected_archive_path).map_err(|source| SnapshotError::Io {
                action: "verify archived snapshot",
                path: expected_archive_path.to_path_buf(),
                source,
            })?;
            if archived != source {
                let _ = fs::remove_file(expected_archive_path);
                return Err(SnapshotError::Invalid(
                    "archived snapshot bytes differ from the active snapshot".to_owned(),
                ));
            }
            sync_archive_directory(expected_archive_path)
        }
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            let archived = fs::read(expected_archive_path).map_err(|source| SnapshotError::Io {
                action: "read existing snapshot archive",
                path: expected_archive_path.to_path_buf(),
                source,
            })?;
            if archived == source {
                sync_archive_directory(expected_archive_path)
            } else {
                Err(SnapshotError::Invalid(format!(
                    "snapshot archive {} already exists with different bytes",
                    expected_archive_path.display()
                )))
            }
        }
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => Err(SnapshotError::Io {
            action: "archive incompatible snapshot",
            path: expected_archive_path.to_path_buf(),
            source,
        }),
        Err(_) => copy_snapshot_archive(expected_archive_path, &source),
    }
}

fn copy_snapshot_archive(archive_path: &Path, source: &[u8]) -> Result<(), SnapshotError> {
    let mut archive = match OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(archive_path)
    {
        Ok(archive) => archive,
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            let archived = fs::read(archive_path).map_err(|source| SnapshotError::Io {
                action: "read existing snapshot archive",
                path: archive_path.to_path_buf(),
                source,
            })?;
            return if archived == source {
                sync_archive_directory(archive_path)
            } else {
                Err(SnapshotError::Invalid(format!(
                    "snapshot archive {} already exists with different bytes",
                    archive_path.display()
                )))
            };
        }
        Err(source) => {
            return Err(SnapshotError::Io {
                action: "create snapshot archive",
                path: archive_path.to_path_buf(),
                source,
            });
        }
    };
    let result = archive
        .write_all(source)
        .and_then(|()| archive.sync_all())
        .map_err(|source| SnapshotError::Io {
            action: "copy incompatible snapshot to archive",
            path: archive_path.to_path_buf(),
            source,
        });
    if result.is_err() {
        let _ = fs::remove_file(archive_path);
        return result;
    }
    sync_archive_directory(archive_path)
}

fn sync_archive_directory(archive_path: &Path) -> Result<(), SnapshotError> {
    let parent = archive_path.parent().unwrap_or(Path::new("."));
    File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|source| SnapshotError::Io {
            action: "sync snapshot archive directory",
            path: parent.to_path_buf(),
            source,
        })
}
