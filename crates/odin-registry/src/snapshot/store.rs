use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use super::atomic::read_regular_file;
use super::contract::{
    ensure_valid_tombstones, Snapshot, SnapshotError, Tombstone, SNAPSHOT_SCHEMA,
};
use super::publication::archive_path;
use crate::schema::{RegistryKind, RegistryObject};

#[derive(Clone, Debug, PartialEq)]
pub enum SnapshotBase {
    Missing,
    Current(Snapshot),
    Incompatible {
        revision: u64,
        archive_path: PathBuf,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SnapshotStore {
    path: PathBuf,
}

impl SnapshotStore {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Require active bytes to match the immutable revision and receipt, rejecting hand-edited snapshots.
    pub fn load_verified(&self) -> Result<Snapshot, SnapshotError> {
        self.load_verified_publication()
            .map(|(snapshot, _receipt)| snapshot)
    }

    pub fn load_verified_publication(
        &self,
    ) -> Result<(Snapshot, PublicationReceipt), SnapshotError> {
        let snapshot = self.load()?.ok_or_else(|| {
            SnapshotError::Invalid(format!(
                "no published registry snapshot at {}",
                self.path.display()
            ))
        })?;
        let active_bytes = fs::read(&self.path).map_err(|source| SnapshotError::Io {
            action: "read active snapshot",
            path: self.path.clone(),
            source,
        })?;
        let versioned_path = versioned_snapshot_path(&self.path, snapshot.revision);
        let versioned_bytes =
            read_regular_file(&versioned_path).map_err(|source| match source.kind() {
                std::io::ErrorKind::NotFound => SnapshotError::Invalid(format!(
                    "active snapshot revision {} has no immutable revision file at {}",
                    snapshot.revision,
                    versioned_path.display()
                )),
                _ => SnapshotError::Io {
                    action: "read immutable revision",
                    path: versioned_path.clone(),
                    source,
                },
            })?;
        if versioned_bytes != active_bytes {
            return Err(SnapshotError::Invalid(format!(
                "active snapshot diverges from immutable revision {} at {}",
                snapshot.revision,
                versioned_path.display()
            )));
        }
        let receipt_path = versioned_receipt_path(&self.path, snapshot.revision);
        let receipt_bytes =
            read_regular_file(&receipt_path).map_err(|source| match source.kind() {
                std::io::ErrorKind::NotFound => SnapshotError::Invalid(format!(
                    "active snapshot revision {} has no publication receipt at {}",
                    snapshot.revision,
                    receipt_path.display()
                )),
                _ => SnapshotError::Io {
                    action: "read publication receipt",
                    path: receipt_path.clone(),
                    source,
                },
            })?;
        let receipt = decode_publication_receipt(&receipt_path, &receipt_bytes, &snapshot)?;
        Ok((snapshot, receipt))
    }

    pub fn publication_at(
        &self,
        revision: u64,
    ) -> Result<(Snapshot, PublicationReceipt), SnapshotError> {
        if revision == 0 {
            return Err(SnapshotError::Invalid(
                "publication revision must be positive".to_owned(),
            ));
        }
        let snapshot_path = versioned_snapshot_path(&self.path, revision);
        let snapshot_bytes =
            read_regular_file(&snapshot_path).map_err(|source| SnapshotError::Io {
                action: "read versioned snapshot",
                path: snapshot_path.clone(),
                source,
            })?;
        let snapshot: Snapshot =
            serde_json::from_slice(&snapshot_bytes).map_err(|source| SnapshotError::Json {
                path: snapshot_path.clone(),
                source,
            })?;
        snapshot.verify()?;
        if snapshot.revision != revision {
            return Err(SnapshotError::Invalid(format!(
                "versioned snapshot {} declares revision {}",
                snapshot_path.display(),
                snapshot.revision
            )));
        }
        let receipt_path = versioned_receipt_path(&self.path, revision);
        let receipt_bytes =
            read_regular_file(&receipt_path).map_err(|source| SnapshotError::Io {
                action: "read versioned publication receipt",
                path: receipt_path.clone(),
                source,
            })?;
        let receipt = decode_publication_receipt(&receipt_path, &receipt_bytes, &snapshot)?;
        Ok((snapshot, receipt))
    }

    pub fn publication_history(
        &self,
    ) -> Result<Vec<(Snapshot, PublicationReceipt)>, SnapshotError> {
        let current = self.load_verified()?;
        (1..=current.revision)
            .map(|revision| self.publication_at(revision))
            .collect()
    }

    /// Check retained publication bytes and receipts without requiring them to parse under the active schema.
    pub fn validate_retained_publication(
        &self,
        revision: u64,
    ) -> Result<PublicationReceipt, SnapshotError> {
        if revision == 0 {
            return Err(SnapshotError::Invalid(
                "publication revision must be positive".to_owned(),
            ));
        }
        let snapshot_path = versioned_snapshot_path(&self.path, revision);
        let snapshot_bytes =
            read_regular_file(&snapshot_path).map_err(|source| match source.kind() {
                std::io::ErrorKind::NotFound => SnapshotError::Invalid(format!(
                    "retained publication revision {revision} has no immutable revision file at {}",
                    snapshot_path.display()
                )),
                _ => SnapshotError::Io {
                    action: "read retained revision",
                    path: snapshot_path.clone(),
                    source,
                },
            })?;
        let raw: serde_json::Value =
            serde_json::from_slice(&snapshot_bytes).map_err(|source| SnapshotError::Json {
                path: snapshot_path.clone(),
                source,
            })?;
        let object = raw.as_object().ok_or_else(|| {
            SnapshotError::Invalid("retained snapshot must be a JSON object".to_owned())
        })?;
        let declared_revision = object
            .get("revision")
            .and_then(serde_json::Value::as_u64)
            .ok_or_else(|| {
                SnapshotError::Invalid("retained snapshot declares no revision".to_owned())
            })?;
        if declared_revision != revision {
            return Err(SnapshotError::Invalid(format!(
                "retained snapshot {} declares revision {declared_revision}",
                snapshot_path.display()
            )));
        }
        let declared_hash = object
            .get("hash")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| {
                SnapshotError::Invalid("retained snapshot declares no hash".to_owned())
            })?;
        let receipt_path = versioned_receipt_path(&self.path, revision);
        let receipt_bytes =
            read_regular_file(&receipt_path).map_err(|source| match source.kind() {
                std::io::ErrorKind::NotFound => SnapshotError::Invalid(format!(
                    "retained publication revision {revision} has no publication receipt at {}",
                    receipt_path.display()
                )),
                _ => SnapshotError::Io {
                    action: "read retained publication receipt",
                    path: receipt_path.clone(),
                    source,
                },
            })?;
        let receipt: PublicationReceipt =
            serde_json::from_slice(&receipt_bytes).map_err(|source| SnapshotError::Json {
                path: receipt_path.clone(),
                source,
            })?;
        if receipt.schema != PUBLICATION_RECEIPT_SCHEMA
            || receipt.outcome != PublicationOutcome::Published
            || receipt.revision != revision
            || receipt.snapshot_hash != declared_hash
        {
            return Err(SnapshotError::Invalid(format!(
                "publication receipt at {} does not bind retained revision {revision}",
                receipt_path.display()
            )));
        }
        Ok(receipt)
    }

    pub fn load(&self) -> Result<Option<Snapshot>, SnapshotError> {
        match self.base_for_update()? {
            SnapshotBase::Missing => Ok(None),
            SnapshotBase::Current(snapshot) => Ok(Some(snapshot)),
            SnapshotBase::Incompatible { .. } => Err(SnapshotError::Invalid(
                "active snapshot uses an incompatible registry object schema".to_owned(),
            )),
        }
    }

    pub fn base_for_update(&self) -> Result<SnapshotBase, SnapshotError> {
        let source = match fs::read(&self.path) {
            Ok(source) => source,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(SnapshotBase::Missing);
            }
            Err(source) => {
                return Err(SnapshotError::Io {
                    action: "read snapshot",
                    path: self.path.clone(),
                    source,
                });
            }
        };
        match serde_json::from_slice::<Snapshot>(&source) {
            Ok(snapshot) => {
                snapshot.verify()?;
                Ok(SnapshotBase::Current(snapshot))
            }
            Err(strict_error) => {
                let raw: serde_json::Value =
                    serde_json::from_slice(&source).map_err(|source| SnapshotError::Json {
                        path: self.path.clone(),
                        source,
                    })?;
                let Some(revision) = incompatible_revision(&raw)? else {
                    return Err(SnapshotError::Json {
                        path: self.path.clone(),
                        source: strict_error,
                    });
                };
                Ok(SnapshotBase::Incompatible {
                    revision,
                    archive_path: archive_path(&self.path, &source)?,
                })
            }
        }
    }

    /// Migrate incompatible active bytes only when the stored revision and receipt match them exactly.
    pub(super) fn verify_incompatible_publication(
        &self,
        revision: u64,
    ) -> Result<(), SnapshotError> {
        let active = fs::read(&self.path).map_err(|source| SnapshotError::Io {
            action: "read incompatible active snapshot",
            path: self.path.clone(),
            source,
        })?;
        let versioned_path = versioned_snapshot_path(&self.path, revision);
        let versioned = read_regular_file(&versioned_path).map_err(|source| match source.kind() {
            std::io::ErrorKind::NotFound => SnapshotError::Invalid(format!(
                "incompatible active snapshot claims revision {revision} with no immutable publication at {}",
                versioned_path.display()
            )),
            _ => SnapshotError::Io {
                action: "read immutable revision of incompatible base",
                path: versioned_path.clone(),
                source,
            },
        })?;
        if versioned != active {
            return Err(SnapshotError::Invalid(format!(
                "incompatible active snapshot diverges from immutable revision {revision} at {}",
                versioned_path.display()
            )));
        }
        let raw: serde_json::Value =
            serde_json::from_slice(&active).map_err(|source| SnapshotError::Json {
                path: self.path.clone(),
                source,
            })?;
        let declared_hash = raw
            .get("hash")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| {
                SnapshotError::Invalid("incompatible snapshot declares no hash".to_owned())
            })?;
        let receipt_path = versioned_receipt_path(&self.path, revision);
        let receipt_bytes =
            read_regular_file(&receipt_path).map_err(|source| match source.kind() {
                std::io::ErrorKind::NotFound => SnapshotError::Invalid(format!(
                "incompatible active snapshot revision {revision} has no publication receipt at {}",
                receipt_path.display()
            )),
                _ => SnapshotError::Io {
                    action: "read publication receipt of incompatible base",
                    path: receipt_path.clone(),
                    source,
                },
            })?;
        let receipt: PublicationReceipt =
            serde_json::from_slice(&receipt_bytes).map_err(|source| SnapshotError::Json {
                path: receipt_path.clone(),
                source,
            })?;
        if receipt.schema != PUBLICATION_RECEIPT_SCHEMA
            || receipt.outcome != PublicationOutcome::Published
            || receipt.revision != revision
            || receipt.snapshot_hash != declared_hash
        {
            return Err(SnapshotError::Invalid(format!(
                "publication receipt at {} does not bind incompatible revision {revision}",
                receipt_path.display()
            )));
        }
        Ok(())
    }
}

pub const PUBLICATION_RECEIPT_SCHEMA: &str = "odin.registry-publication-receipt.v1";
const REVISIONS_DIRECTORY: &str = "revisions";

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum PublicationOutcome {
    Published,
    Unchanged,
}

/// Apply only the commit's registry delta so runtime publication retains unrelated effective inputs.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeProjection {
    pub tree: String,
}

/// Keep the first publication receipt unchanged so identical retries cannot contradict it.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PublicationReceipt {
    pub schema: String,
    pub outcome: PublicationOutcome,
    pub revision: u64,
    pub previous_revision: Option<u64>,
    pub commit: String,
    pub tree: String,
    pub snapshot_hash: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runtime_projection: Option<RuntimeProjection>,
}

/// Keep the durable receipt stable while reporting whether this call changed the active pointer.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PublicationResult {
    pub outcome: PublicationOutcome,
    pub receipt: PublicationReceipt,
}

pub(super) fn versioned_snapshot_path(active_path: &Path, revision: u64) -> PathBuf {
    revision_directory(active_path).join(format!("{revision:020}.snapshot.json"))
}

pub(super) fn versioned_receipt_path(active_path: &Path, revision: u64) -> PathBuf {
    revision_directory(active_path).join(format!("{revision:020}.receipt.json"))
}

pub(super) fn decode_publication_receipt(
    path: &Path,
    bytes: &[u8],
    snapshot: &Snapshot,
) -> Result<PublicationReceipt, SnapshotError> {
    let receipt: PublicationReceipt =
        serde_json::from_slice(bytes).map_err(|source| SnapshotError::Json {
            path: path.to_path_buf(),
            source,
        })?;
    if receipt.schema != PUBLICATION_RECEIPT_SCHEMA
        || receipt.outcome != PublicationOutcome::Published
        || receipt.revision != snapshot.revision
        || receipt.snapshot_hash != snapshot.hash
    {
        return Err(SnapshotError::Invalid(format!(
            "publication receipt at {} does not bind snapshot revision {} hash",
            path.display(),
            snapshot.revision
        )));
    }
    Ok(receipt)
}

pub(super) fn revision_directory(active_path: &Path) -> PathBuf {
    active_path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or(Path::new("."))
        .join(REVISIONS_DIRECTORY)
}

fn incompatible_revision(raw: &serde_json::Value) -> Result<Option<u64>, SnapshotError> {
    let object = raw
        .as_object()
        .ok_or_else(|| SnapshotError::Invalid("snapshot JSON root must be an object".to_owned()))?;
    if object.keys().any(|key| {
        !matches!(
            key.as_str(),
            "schema" | "revision" | "hash" | "objects" | "tombstones"
        )
    }) {
        return Err(SnapshotError::Invalid(
            "snapshot JSON contains unknown top-level fields".to_owned(),
        ));
    }
    if object.get("schema").and_then(serde_json::Value::as_str) != Some(SNAPSHOT_SCHEMA) {
        return Err(SnapshotError::Invalid(format!(
            "snapshot schema must be {SNAPSHOT_SCHEMA:?}"
        )));
    }
    let revision = object
        .get("revision")
        .and_then(serde_json::Value::as_u64)
        .filter(|revision| *revision > 0)
        .ok_or_else(|| {
            SnapshotError::Invalid("snapshot revision must be a positive integer".to_owned())
        })?;
    let hash = object
        .get("hash")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| SnapshotError::Invalid("snapshot hash must be a string".to_owned()))?;
    if hash.len() != blake3::OUT_LEN * 2 || !hash.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(SnapshotError::Invalid(
            "snapshot hash must be a BLAKE3-sized hexadecimal string".to_owned(),
        ));
    }
    let objects = object
        .get("objects")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| SnapshotError::Invalid("snapshot objects must be an array".to_owned()))?;
    for value in objects {
        validate_raw_object_envelope(value)?;
    }
    if let Some(tombstones) = object.get("tombstones") {
        let tombstones: Vec<Tombstone> =
            serde_json::from_value(tombstones.clone()).map_err(|error| {
                SnapshotError::Invalid(format!("snapshot tombstones are invalid: {error}"))
            })?;
        ensure_valid_tombstones(revision, &tombstones)?;
    }
    Ok(objects
        .iter()
        .any(|value| serde_json::from_value::<RegistryObject>(value.clone()).is_err())
        .then_some(revision))
}

fn validate_raw_object_envelope(value: &serde_json::Value) -> Result<(), SnapshotError> {
    let object = value.as_object().ok_or_else(|| {
        SnapshotError::Invalid("snapshot object entry must be an object".to_owned())
    })?;
    if object.len() != 3
        || object
            .get("id")
            .and_then(serde_json::Value::as_str)
            .is_none()
        || object
            .get("relative_config")
            .and_then(serde_json::Value::as_str)
            .is_none()
    {
        return Err(SnapshotError::Invalid(
            "snapshot object entry has an invalid envelope".to_owned(),
        ));
    }
    let config = object
        .get("config")
        .and_then(serde_json::Value::as_object)
        .ok_or_else(|| {
            SnapshotError::Invalid("snapshot object config must be an object".to_owned())
        })?;
    if config.len() != 2
        || !config
            .get("config")
            .is_some_and(serde_json::Value::is_object)
    {
        return Err(SnapshotError::Invalid(
            "snapshot object config has an invalid envelope".to_owned(),
        ));
    }
    let object_type = config
        .get("object_type")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| {
            SnapshotError::Invalid("snapshot object type must be a string".to_owned())
        })?;
    if object_type != "claudecode"
        && !RegistryKind::ALL
            .into_iter()
            .any(|kind| kind.as_str() == object_type)
    {
        return Err(SnapshotError::Invalid(format!(
            "unknown snapshot object type {object_type:?}"
        )));
    }
    Ok(())
}
