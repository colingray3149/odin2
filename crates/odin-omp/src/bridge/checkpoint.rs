//! Content-addressed checkpoint evidence: exclusive artifact staging,
//! committed command-anchor recovery, artifact/digest validation, and
//! the pinned completion value.

use super::*;

/// Compatibility key recorded on every bridge checkpoint.
pub const CHECKPOINT_COMPATIBILITY_KEY: &str = "odin-omp/m3/live-session-v1";

/// Process-local suffix for exclusive artifact staging names.
pub(super) static ARTIFACT_SEQUENCE: AtomicU64 = AtomicU64::new(0);

pub(super) fn checkpoint_completion(record: &CheckpointRecord) -> Value {
    json!({
        "kind": "checkpoint",
        "checkpoint_id": record.checkpoint.id.to_string(),
        "artifact_id": record.artifact.artifact_id.to_string(),
        "artifact_digest": record.artifact.digest.to_string(),
        "state_digest": record.state_digest.to_string(),
    })
}

/// Finds at most one checkpoint under the exact command anchor and recovers
/// it only when committed. Multiple anchors are ambiguous and fail closed;
/// every relational/digest invariant is validated before filesystem evidence.
pub(super) fn load_committed_checkpoint_anchor(
    ledger: &Ledger,
    command_id: &CommandId,
    run_id: &RunId,
) -> Result<Option<CheckpointRecord>, LedgerError> {
    let checkpoints = {
        let mut statement = ledger.connection().prepare(
            "SELECT checkpoint_id, committed FROM checkpoints
             WHERE command_id = ?1
             ORDER BY checkpoint_id
             LIMIT 2",
        )?;
        let mut rows = statement.query([command_id.to_string()])?;
        let mut checkpoints = Vec::new();
        while let Some(row) = rows.next()? {
            checkpoints.push((row.get::<_, String>(0)?, row.get::<_, i64>(1)?));
        }
        checkpoints
    };
    if checkpoints.len() > 1 {
        return Err(LedgerError::invalid_data(format!(
            "command {command_id} anchors multiple checkpoints"
        )));
    }
    let Some((raw_id, committed)) = checkpoints.into_iter().next() else {
        return Ok(None);
    };
    if committed != 1 {
        return Ok(None);
    }
    let checkpoint_id = CheckpointId::new(raw_id)
        .map_err(|error| LedgerError::invalid_data_caused_by("invalid checkpoint id", error))?;
    let checkpoint = ledger.checkpoint(&checkpoint_id)?.ok_or_else(|| {
        LedgerError::invalid_data(format!("anchored checkpoint {checkpoint_id} disappeared"))
    })?;
    if !checkpoint.is_committed()
        || checkpoint.command_id.as_ref() != Some(command_id)
        || &checkpoint.run_id != run_id
        || checkpoint.compatibility_key != CHECKPOINT_COMPATIBILITY_KEY
        || checkpoint.rollback_of.is_some()
    {
        return Err(LedgerError::invalid_data(format!(
            "checkpoint {checkpoint_id} does not satisfy the committed command-anchor contract"
        )));
    }
    let artifact = ledger.artifact(&checkpoint.artifact_ref)?.ok_or_else(|| {
        LedgerError::invalid_data(format!(
            "checkpoint {checkpoint_id} references missing artifact {}",
            checkpoint.artifact_ref
        ))
    })?;
    if artifact.artifact_id != checkpoint.artifact_ref
        || artifact.digest != checkpoint.artifact_digest
        || checkpoint.state_digest != checkpoint.artifact_digest
        || artifact.media_type != "application/json"
        || artifact.retention != RetentionClass::Pinned
    {
        return Err(LedgerError::invalid_data(format!(
            "checkpoint {checkpoint_id} artifact metadata or digests are inconsistent"
        )));
    }
    let state_digest = checkpoint.state_digest;
    Ok(Some(CheckpointRecord {
        checkpoint,
        artifact,
        state_digest,
    }))
}

/// Hashes the exact content-addressed file without allocating from its
/// metadata-controlled size. The deterministic path binds bytes to metadata
/// and prevents a stale/misdirected artifact reference from completing a
/// once-only command.
pub(super) fn validate_checkpoint_artifact(
    artifact_root: &Path,
    record: &CheckpointRecord,
) -> Result<(), BridgeError> {
    let hex = digest_hex(&record.artifact.digest);
    let expected_relative = format!("{}/{}", &hex[..2], hex);
    if record.artifact.storage_path != expected_relative {
        return Err(BridgeError::Serialization {
            detail: format!(
                "checkpoint artifact path `{}` does not match digest path `{expected_relative}`",
                record.artifact.storage_path
            ),
        });
    }
    let path = artifact_root.join(&expected_relative);
    let named = fs::symlink_metadata(&path)?;
    if !named.file_type().is_file() {
        return Err(BridgeError::Serialization {
            detail: format!(
                "checkpoint artifact {} is not a regular file",
                path.display()
            ),
        });
    }
    let mut file = fs::File::open(&path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.len() != record.artifact.size_bytes {
        return Err(BridgeError::Serialization {
            detail: format!(
                "checkpoint artifact {} size/type differs from registered metadata",
                path.display()
            ),
        });
    }
    let mut hasher = blake3::Hasher::new();
    let mut buffer = [0_u8; 64 * 1024];
    let mut size = 0_u64;
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        size = size
            .checked_add(read as u64)
            .ok_or_else(|| BridgeError::Serialization {
                detail: "checkpoint artifact byte count overflowed".to_owned(),
            })?;
        hasher.update(&buffer[..read]);
    }
    let actual = Digest::new(*hasher.finalize().as_bytes());
    if size != record.artifact.size_bytes || actual != record.artifact.digest {
        return Err(BridgeError::Serialization {
            detail: format!(
                "checkpoint artifact {} does not match its committed size/digest",
                path.display()
            ),
        });
    }
    Ok(())
}

pub(super) fn write_content_addressed(path: &Path, bytes: &[u8]) -> Result<(), BridgeError> {
    fn verify(path: &Path, expected: &[u8]) -> Result<(), BridgeError> {
        let named = fs::symlink_metadata(path)?;
        if !named.file_type().is_file() {
            return Err(BridgeError::Io(std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                format!(
                    "content-addressed artifact {} is not a regular file",
                    path.display()
                ),
            )));
        }
        let mut file = fs::File::open(path)?;
        let metadata = file.metadata()?;
        if !metadata.is_file() || metadata.len() != expected.len() as u64 {
            return Err(BridgeError::Io(std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                format!(
                    "content-addressed artifact {} exists with different metadata",
                    path.display()
                ),
            )));
        }
        let mut actual = Vec::with_capacity(expected.len());
        (&mut file)
            .take(expected.len() as u64 + 1)
            .read_to_end(&mut actual)?;
        if actual != expected {
            return Err(BridgeError::Io(std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                format!(
                    "content-addressed artifact {} exists with different bytes",
                    path.display()
                ),
            )));
        }
        Ok(())
    }

    let parent = path.parent().ok_or_else(|| {
        BridgeError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "content-addressed artifact has no parent directory",
        ))
    })?;
    fs::create_dir_all(parent)?;
    match fs::symlink_metadata(path) {
        Ok(_) => return verify(path, bytes),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }

    let file_name = path.file_name().ok_or_else(|| {
        BridgeError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "content-addressed artifact has no filename",
        ))
    })?;
    let mut staging = None;
    for _ in 0..64 {
        let candidate = parent.join(format!(
            ".{}.tmp-{}-{}",
            file_name.to_string_lossy(),
            std::process::id(),
            ARTIFACT_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        options.mode(0o600);
        match options.open(&candidate) {
            Ok(file) => {
                staging = Some((candidate, file));
                break;
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error.into()),
        }
    }
    let (staging_path, mut staging_file) = staging.ok_or_else(|| {
        BridgeError::Io(std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            "could not allocate an exclusive artifact staging file",
        ))
    })?;
    let staged = staging_file
        .write_all(bytes)
        .and_then(|()| staging_file.sync_all());
    drop(staging_file);
    if let Err(error) = staged {
        let _ = fs::remove_file(&staging_path);
        return Err(error.into());
    }
    match fs::hard_link(&staging_path, path) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            if let Err(verify_error) = verify(path, bytes) {
                let _ = fs::remove_file(&staging_path);
                return Err(verify_error);
            }
        }
        Err(error) => {
            let _ = fs::remove_file(&staging_path);
            return Err(error.into());
        }
    }
    fs::remove_file(&staging_path)?;
    fs::File::open(parent)?.sync_all()?;
    Ok(())
}
