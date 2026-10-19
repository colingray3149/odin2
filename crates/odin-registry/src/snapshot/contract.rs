use std::collections::{BTreeSet, HashMap};
use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::schema::{
    ComposedWorkloadProfile, RegistryKind, RegistryObject, WorkloadProfileLookupError,
};

pub const SNAPSHOT_SCHEMA: &str = "odin.registry-snapshot.v1";

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Tombstone {
    pub kind: RegistryKind,
    pub id: String,
    pub removed_at_revision: u64,
    pub object_hash: String,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Snapshot {
    pub schema: String,
    pub revision: u64,
    pub hash: String,
    pub objects: Vec<RegistryObject>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tombstones: Vec<Tombstone>,
}

/// Match iter().find on raw slices so duplicate entries resolve consistently.
pub struct ObjectIndex<'a> {
    by_key: HashMap<(RegistryKind, &'a str), &'a RegistryObject>,
}

impl<'a> ObjectIndex<'a> {
    pub fn new(objects: &'a [RegistryObject]) -> Self {
        let mut by_key = HashMap::with_capacity(objects.len());
        for object in objects {
            by_key
                .entry((object.kind(), object.id.as_str()))
                .or_insert(object);
        }
        Self { by_key }
    }

    pub fn get(&self, kind: RegistryKind, id: &str) -> Option<&'a RegistryObject> {
        self.by_key.get(&(kind, id)).copied()
    }

    pub fn enabled(&self, kind: RegistryKind, id: &str) -> bool {
        self.get(kind, id).is_some_and(RegistryObject::enabled)
    }
}

pub struct WorkloadProfileRef<'a> {
    pub id: &'a str,
    pub relative_config: &'a std::path::Path,
    pub profile: &'a crate::schema::WorkloadProfileToml,
}

impl Snapshot {
    pub fn build(revision: u64, mut objects: Vec<RegistryObject>) -> Result<Self, SnapshotError> {
        if revision == 0 {
            return Err(SnapshotError::Invalid(
                "snapshot revision must be positive".to_owned(),
            ));
        }
        objects.sort_by(|left, right| {
            (left.kind(), left.id.as_str()).cmp(&(right.kind(), right.id.as_str()))
        });
        ensure_sorted_unique_objects(&objects)?;
        let tombstones = Vec::new();
        let hash = payload_hash(revision, &objects, &tombstones)?;
        Ok(Self {
            schema: SNAPSHOT_SCHEMA.to_owned(),
            revision,
            hash,
            objects,
            tombstones,
        })
    }

    pub fn listed_objects(&self, kind: RegistryKind) -> impl Iterator<Item = &RegistryObject> {
        self.objects
            .iter()
            .filter(move |object| object.kind() == kind && object.enters_listing())
    }

    pub fn canonical_hash(&self) -> Result<String, SnapshotError> {
        payload_hash(self.revision, &self.objects, &self.tombstones)
    }

    pub fn verify(&self) -> Result<(), SnapshotError> {
        if self.schema != SNAPSHOT_SCHEMA {
            return Err(SnapshotError::Invalid(format!(
                "snapshot schema must be {SNAPSHOT_SCHEMA:?}, found {:?}",
                self.schema
            )));
        }
        if self.revision == 0 {
            return Err(SnapshotError::Invalid(
                "snapshot revision must be positive".to_owned(),
            ));
        }
        ensure_sorted_unique_objects(&self.objects)?;
        ensure_valid_tombstones(self.revision, &self.tombstones)?;
        let expected = self.canonical_hash()?;
        if self.hash != expected {
            // An empty tombstone set may use the canonical representation that omits the field.
            let is_legacy = self.tombstones.is_empty()
                && self.hash == legacy_payload_hash(self.revision, &self.objects)?;
            if !is_legacy {
                return Err(SnapshotError::Invalid(format!(
                    "snapshot hash mismatch: stored {:?}, computed {:?}",
                    self.hash, expected
                )));
            }
        }
        Ok(())
    }

    /// Report Disabled for disabled declarations rather than silently skipping them.
    pub fn workload_profile(
        &self,
        id: &str,
    ) -> Result<ComposedWorkloadProfile, WorkloadProfileLookupError> {
        let borrowed = self.workload_profile_ref(id)?;
        Ok(ComposedWorkloadProfile {
            id: borrowed.id.to_owned(),
            relative_config: borrowed.relative_config.to_path_buf(),
            profile: borrowed.profile.clone(),
        })
    }
    /// Verified snapshots are sorted by kind and ID; use ObjectIndex for unsorted slices.
    pub fn object(&self, kind: RegistryKind, id: &str) -> Option<&RegistryObject> {
        self.objects
            .binary_search_by(|object| (object.kind(), object.id.as_str()).cmp(&(kind, id)))
            .ok()
            .map(|index| &self.objects[index])
    }

    pub fn workload_profile_ref(
        &self,
        id: &str,
    ) -> Result<WorkloadProfileRef<'_>, WorkloadProfileLookupError> {
        let object = self
            .object(RegistryKind::Workload, id)
            .ok_or_else(|| WorkloadProfileLookupError::Unknown { id: id.to_owned() })?;
        let crate::schema::ObjectConfig::Workload(profile) = &object.config else {
            return Err(WorkloadProfileLookupError::Unknown { id: id.to_owned() });
        };
        if !object.enabled() {
            return Err(WorkloadProfileLookupError::Disabled { id: id.to_owned() });
        }
        Ok(WorkloadProfileRef {
            id: object.id.as_str(),
            relative_config: object.relative_config.as_path(),
            profile: profile.as_ref(),
        })
    }
}

#[derive(Debug, Error)]
pub enum SnapshotError {
    #[error("{action} {path}: {source}")]
    Io {
        action: &'static str,
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("invalid snapshot JSON at {path}: {source}")]
    Json {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },
    #[error("failed to serialize snapshot: {0}")]
    Serialize(#[from] serde_json::Error),
    #[error("invalid registry snapshot: {0}")]
    Invalid(String),
    #[error("git {operation} failed in {path}: {message}")]
    Git {
        operation: &'static str,
        path: PathBuf,
        message: String,
    },
    #[error("authoring worktree {path} is not clean at the expected commit: {detail}")]
    DirtyWorktree { path: PathBuf, detail: String },
    #[error("authoring worktree HEAD is {actual}, not the expected commit {expected}")]
    HeadMismatch { expected: String, actual: String },
    #[error(
        "candidate commit {commit} cannot publish on published commit {expected_parent}: {reason}"
    )]
    NonChild {
        expected_parent: String,
        commit: String,
        reason: String,
    },
    #[error("stale publication: expected revision {expected}, active revision {active:?}")]
    Stale { expected: u64, active: Option<u64> },
    #[error("snapshot revision {revision} is already occupied by different committed content")]
    Conflict { revision: u64 },
}

#[derive(Serialize)]
struct SnapshotPayload<'a> {
    schema: &'static str,
    revision: u64,
    objects: &'a [RegistryObject],
    tombstones: &'a [Tombstone],
}

#[derive(Serialize)]
struct LegacySnapshotPayload<'a> {
    schema: &'static str,
    revision: u64,
    objects: &'a [RegistryObject],
}

fn payload_hash(
    revision: u64,
    objects: &[RegistryObject],
    tombstones: &[Tombstone],
) -> Result<String, SnapshotError> {
    let payload = SnapshotPayload {
        schema: SNAPSHOT_SCHEMA,
        revision,
        objects,
        tombstones,
    };
    let bytes = serde_json::to_vec(&payload)?;
    Ok(blake3::hash(&bytes).to_hex().to_string())
}

fn legacy_payload_hash(revision: u64, objects: &[RegistryObject]) -> Result<String, SnapshotError> {
    let payload = LegacySnapshotPayload {
        schema: SNAPSHOT_SCHEMA,
        revision,
        objects,
    };
    let bytes = serde_json::to_vec(&payload)?;
    Ok(blake3::hash(&bytes).to_hex().to_string())
}

fn object_hash(object: &RegistryObject) -> Result<String, SnapshotError> {
    let bytes = serde_json::to_vec(object)?;
    Ok(blake3::hash(&bytes).to_hex().to_string())
}

fn ensure_sorted_unique_objects(objects: &[RegistryObject]) -> Result<(), SnapshotError> {
    for pair in objects.windows(2) {
        let left = &pair[0];
        let right = &pair[1];
        match (left.kind(), left.id.as_str()).cmp(&(right.kind(), right.id.as_str())) {
            std::cmp::Ordering::Less => {}
            std::cmp::Ordering::Equal => {
                return Err(SnapshotError::Invalid(format!(
                    "duplicate {} object {:?} in snapshot",
                    left.kind(),
                    left.id
                )));
            }
            std::cmp::Ordering::Greater => {
                return Err(SnapshotError::Invalid(
                    "snapshot objects are not in deterministic kind/id order".to_owned(),
                ));
            }
        }
    }
    Ok(())
}

pub(super) fn ensure_valid_tombstones(
    revision: u64,
    tombstones: &[Tombstone],
) -> Result<(), SnapshotError> {
    let mut previous_key = None;
    for tombstone in tombstones {
        if tombstone.removed_at_revision == 0 || tombstone.removed_at_revision > revision {
            return Err(SnapshotError::Invalid(format!(
                "tombstone for {} {:?} has invalid removal revision {} at snapshot revision {}",
                tombstone.kind, tombstone.id, tombstone.removed_at_revision, revision
            )));
        }
        if tombstone.object_hash.len() != blake3::OUT_LEN * 2
            || !tombstone
                .object_hash
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit())
        {
            return Err(SnapshotError::Invalid(format!(
                "tombstone for {} {:?} has an invalid object hash",
                tombstone.kind, tombstone.id
            )));
        }
        let key = (
            tombstone.removed_at_revision,
            tombstone.kind,
            tombstone.id.as_str(),
        );
        if previous_key
            .as_ref()
            .is_some_and(|previous| previous >= &key)
        {
            return Err(SnapshotError::Invalid(
                "snapshot tombstones are not in deterministic revision/kind/id order".to_owned(),
            ));
        }
        previous_key = Some(key);
    }
    Ok(())
}

#[derive(Clone)]
pub(super) struct ObjectRecord {
    pub(super) kind: RegistryKind,
    pub(super) id: String,
    pub(super) hash: String,
}

pub(super) fn tombstones_for(
    previous: Option<&Snapshot>,
    next: &Snapshot,
) -> Result<Vec<Tombstone>, SnapshotError> {
    let Some(previous) = previous else {
        return Ok(Vec::new());
    };
    let records = previous
        .objects
        .iter()
        .map(|object| {
            Ok(ObjectRecord {
                kind: object.kind(),
                id: object.id.clone(),
                hash: object_hash(object)?,
            })
        })
        .collect::<Result<Vec<_>, SnapshotError>>()?;
    let next_keys = next
        .objects
        .iter()
        .map(|object| (object.kind(), object.id.clone()))
        .collect();
    Ok(merge_tombstones(
        &previous.tombstones,
        &records,
        &next_keys,
        next.revision,
    ))
}

pub(super) fn merge_tombstones(
    history: &[Tombstone],
    previous: &[ObjectRecord],
    next_keys: &BTreeSet<(RegistryKind, String)>,
    revision: u64,
) -> Vec<Tombstone> {
    let mut tombstones = history.to_vec();
    tombstones.extend(
        previous
            .iter()
            .filter(|object| !next_keys.contains(&(object.kind, object.id.clone())))
            .map(|object| Tombstone {
                kind: object.kind,
                id: object.id.clone(),
                removed_at_revision: revision,
                object_hash: object.hash.clone(),
            }),
    );
    tombstones.sort_by(|left, right| {
        (left.removed_at_revision, left.kind, left.id.as_str()).cmp(&(
            right.removed_at_revision,
            right.kind,
            right.id.as_str(),
        ))
    });
    tombstones
}
