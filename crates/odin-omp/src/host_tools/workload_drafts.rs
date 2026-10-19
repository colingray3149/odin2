//! Durable compiled-draft store for the conversational workload authoring
//! seam, sealed through `odin-confined-fs`. `workload_draft` retains the
//! exact compiled declaration here, keyed by the profile id it belongs
//! to, its content digest, and the registry revision it bound as its
//! publication target;
//! `workload_publish` consumes that same immutable record instead of
//! re-deriving the declaration from model answers. The same compiled bytes
//! retained at a different bound revision are a distinct, equally
//! legitimate draft; no retained draft is ever overwritten, and a crashed
//! attempt leaves only an orphan temporary that later attempts skip.
//! Loading checks key agreement, the content digest, and the strict workload
//! schema so corrupt records cannot reach the approval gate as usable drafts.

use std::path::{Path, PathBuf};

use odin_confined_fs::{ConfinedError, PrivateCapability};
use odin_domain::Digest;
use odin_registry::{valid_id, RegistryKind, WorkloadProfileToml};

/// The one capability the retained-draft pre-gate serves: publishing the
/// retained immutable declaration.
pub const WORKLOAD_PUBLISH_CAPABILITY: &str = "workload.publish";

/// One retained compiled draft: the exact published-form declaration bytes,
/// the profile they belong to, and the registry revision the draft bound as
/// its publication target.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct WorkloadDraftRecord {
    pub declaration_digest: String,
    pub profile_id: String,
    pub rendered_toml: String,
    pub bound_registry_revision: u64,
}

/// The durable compiled-draft store: one sealed mode-0700 private directory
/// whose entries are published no-replace (exclusive temporary, fsync,
/// `install_exclusive` link commit with the directory sync) through the
/// confined capability. An entry is adopted only when its bytes are exactly
/// identical; anything else refuses typed.
pub struct WorkloadDraftStore {
    capability: PrivateCapability,
    process_tag: u64,
}

/// The retained draft store failed and the caller must refuse typed rather
/// than re-deriving a declaration from model answers.
#[derive(Debug)]
pub enum WorkloadDraftStoreError {
    Confined(ConfinedError),
    Serialize {
        detail: String,
    },
    DigestCollision {
        digest: String,
        bound_registry_revision: u64,
    },
    MalformedDigest {
        digest: String,
    },
    UnknownDraft {
        digest: String,
        bound_registry_revision: u64,
    },
    /// The entry exists but is not the immutable record its key promises:
    /// the claimed digest or bound revision disagrees with the leaf key,
    /// the bytes do not hash to the retained digest, or the bytes are not
    /// a strict workload declaration. Never a usable draft; the caller
    /// refuses typed.
    CorruptRecord {
        digest: String,
        bound_registry_revision: u64,
        detail: String,
    },
    /// Profile ids must satisfy the registry grammar and fit within 128 bytes.
    MalformedProfileId {
        profile_id: String,
    },
}

impl WorkloadDraftStoreError {
    /// Distinguishes a missing entry from an unreadable or corrupt one.
    pub fn is_absent(&self) -> bool {
        matches!(self, Self::UnknownDraft { .. })
    }
}

impl std::fmt::Display for WorkloadDraftStoreError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Confined(error) => write!(formatter, "{error}"),
            Self::Serialize { detail } => {
                write!(formatter, "draft serialization failed: {detail}")
            }
            Self::DigestCollision {
                digest,
                bound_registry_revision,
            } => write!(
                formatter,
                "draft {digest} is already retained at bound revision \
                 {bound_registry_revision} with different bytes"
            ),
            Self::MalformedDigest { digest } => {
                write!(formatter, "draft digest {digest:?} is malformed")
            }
            Self::UnknownDraft {
                digest,
                bound_registry_revision,
            } => write!(
                formatter,
                "no draft {digest} is retained at bound revision \
                 {bound_registry_revision}; draft it again and obtain a fresh approval"
            ),
            Self::CorruptRecord {
                digest,
                bound_registry_revision,
                detail,
            } => write!(
                formatter,
                "retained draft {digest} at bound revision \
                 {bound_registry_revision} is corrupt: {detail}"
            ),
            Self::MalformedProfileId { profile_id } => write!(
                formatter,
                "draft profile id {profile_id:?} is not a registry identifier"
            ),
        }
    }
}

impl std::error::Error for WorkloadDraftStoreError {}

impl WorkloadDraftStore {
    /// Seals (creating when absent) the durable draft directory under the
    /// state root as a mode-0700 private boundary.
    pub fn seal(state_root: &Path) -> Result<Self, WorkloadDraftStoreError> {
        let capability = PrivateCapability::ensure_dir(state_root, Path::new("workload-drafts"))
            .map_err(WorkloadDraftStoreError::Confined)?;
        Ok(Self {
            capability,
            process_tag: u64::from(std::process::id()),
        })
    }

    /// Retains one compiled draft no-replace: exclusive temporary, data
    /// fsync, `install_exclusive` commit, directory sync. An existing entry
    /// adopts identical bytes and refuses different ones; a crashed attempt
    /// leaves only a private temporary that later attempts skip.
    pub fn retain(&self, record: &WorkloadDraftRecord) -> Result<(), WorkloadDraftStoreError> {
        let stem = draft_file_stem(
            &record.profile_id,
            &record.declaration_digest,
            record.bound_registry_revision,
        )?;
        let bytes = serde_json::to_vec_pretty(record).map_err(|error| {
            WorkloadDraftStoreError::Serialize {
                detail: error.to_string(),
            }
        })?;
        for attempt in 0..8u64 {
            let temporary = PathBuf::from(format!(".{stem}.{}-{}.tmp", self.process_tag, attempt));
            match self.capability.create_atomic(&temporary, &bytes, 0o444) {
                Ok(()) => {}
                Err(ConfinedError::AlreadyExists { .. }) => {
                    // A crashed twin's orphan: skip the name and continue.
                    continue;
                }
                Err(error) => return Err(WorkloadDraftStoreError::Confined(error)),
            }
            return match self
                .capability
                .install_exclusive(&temporary, &leaf_path(stem))
            {
                Ok(()) => Ok(()),
                Err(ConfinedError::AlreadyExists { .. }) => {
                    let _ = self.capability.remove(&temporary);
                    self.adopt_or_collide(record)
                }
                Err(error) => {
                    let _ = self.capability.remove(&temporary);
                    Err(WorkloadDraftStoreError::Confined(error))
                }
            };
        }
        Err(WorkloadDraftStoreError::Confined(
            ConfinedError::AlreadyExists {
                component: "draft temporary".to_owned(),
            },
        ))
    }

    /// Loads the retained draft for one (profile id, declaration digest,
    /// bound revision), or `None` when nothing was retained under it.
    pub fn load(
        &self,
        profile_id: &str,
        declaration_digest: &str,
        bound_registry_revision: u64,
    ) -> Result<Option<WorkloadDraftRecord>, WorkloadDraftStoreError> {
        let stem = draft_file_stem(profile_id, declaration_digest, bound_registry_revision)?;
        let file = match self.capability.open_read(&leaf_path(stem)) {
            Ok(file) => file,
            Err(ConfinedError::ComponentMissing { .. }) => return Ok(None),
            Err(error) => return Err(WorkloadDraftStoreError::Confined(error)),
        };
        let parsed_record: WorkloadDraftRecord =
            serde_json::from_reader(&file).map_err(|error| WorkloadDraftStoreError::Serialize {
                detail: error.to_string(),
            })?;
        validate_retained(
            profile_id,
            declaration_digest,
            bound_registry_revision,
            &parsed_record,
        )?;
        Ok(Some(parsed_record))
    }

    /// Requires an intact draft under the exact profile/digest/revision key before approval.
    pub fn require_retained(
        &self,
        profile_id: &str,
        declaration_digest: &str,
        bound_registry_revision: u64,
    ) -> Result<WorkloadDraftRecord, WorkloadDraftStoreError> {
        match self.load(profile_id, declaration_digest, bound_registry_revision)? {
            Some(record) => Ok(record),
            None => Err(WorkloadDraftStoreError::UnknownDraft {
                digest: declaration_digest.to_owned(),
                bound_registry_revision,
            }),
        }
    }

    /// Adoption-or-collision for an entry that already exists: identical
    /// bytes adopt (idempotent replay); anything else is a digest
    /// collision and the retained draft is untouched.
    fn adopt_or_collide(
        &self,
        record: &WorkloadDraftRecord,
    ) -> Result<(), WorkloadDraftStoreError> {
        let stem = draft_file_stem(
            &record.profile_id,
            &record.declaration_digest,
            record.bound_registry_revision,
        )?;
        let retained = self
            .capability
            .open_read(&leaf_path(stem))
            .map_err(WorkloadDraftStoreError::Confined)?;
        let retained: WorkloadDraftRecord =
            serde_json::from_reader(&retained).map_err(|error| {
                WorkloadDraftStoreError::Serialize {
                    detail: error.to_string(),
                }
            })?;
        if retained == *record {
            Ok(())
        } else {
            Err(WorkloadDraftStoreError::DigestCollision {
                digest: record.declaration_digest.clone(),
                bound_registry_revision: record.bound_registry_revision,
            })
        }
    }
}

/// Checks key agreement, content digest, and the strict registry workload schema.
/// Publication identity comes from the profile key, not the declaration bytes;
/// dispatch includes it in the approval scope and publishing checks the registry snapshot.
fn validate_retained(
    requested_profile_id: &str,
    requested_digest: &str,
    requested_revision: u64,
    record: &WorkloadDraftRecord,
) -> Result<(), WorkloadDraftStoreError> {
    if record.profile_id != requested_profile_id
        || record.declaration_digest != requested_digest
        || record.bound_registry_revision != requested_revision
    {
        return Err(WorkloadDraftStoreError::CorruptRecord {
            digest: requested_digest.to_owned(),
            bound_registry_revision: requested_revision,
            detail: format!(
                "the entry claims profile {}, digest {} at bound revision \
                 {}, not the retained key",
                record.profile_id, record.declaration_digest, record.bound_registry_revision
            ),
        });
    }
    let observed = Digest::hash(record.rendered_toml.as_bytes()).to_string();
    if observed != record.declaration_digest {
        return Err(WorkloadDraftStoreError::CorruptRecord {
            digest: record.declaration_digest.clone(),
            bound_registry_revision: record.bound_registry_revision,
            detail: format!("the retained bytes hash to {observed}"),
        });
    }
    let declaration: WorkloadProfileToml =
        toml::from_str(&record.rendered_toml).map_err(|error| {
            WorkloadDraftStoreError::CorruptRecord {
                digest: record.declaration_digest.clone(),
                bound_registry_revision: record.bound_registry_revision,
                detail: format!("the retained bytes are not a workload declaration: {error}"),
            }
        })?;
    if declaration.kind != RegistryKind::Workload {
        return Err(WorkloadDraftStoreError::CorruptRecord {
            digest: record.declaration_digest.clone(),
            bound_registry_revision: record.bound_registry_revision,
            detail: format!(
                "the retained declaration is kind {}, not a workload profile",
                declaration.kind
            ),
        });
    }
    Ok(())
}

fn leaf_path(stem: String) -> PathBuf {
    PathBuf::from(format!("{stem}.json"))
}

fn draft_file_stem(
    profile_id: &str,
    declaration_digest: &str,
    bound_registry_revision: u64,
) -> Result<String, WorkloadDraftStoreError> {
    // Registry ids exclude separators and leading dots; the length cap keeps the leaf below 255 bytes.
    if profile_id.len() > 128 || !valid_id(profile_id) {
        return Err(WorkloadDraftStoreError::MalformedProfileId {
            profile_id: profile_id.to_owned(),
        });
    }
    let body = declaration_digest
        .strip_prefix("blake3:")
        .unwrap_or(declaration_digest);
    if body.is_empty() || !body.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(WorkloadDraftStoreError::MalformedDigest {
            digest: declaration_digest.to_owned(),
        });
    }
    Ok(format!(
        "{profile_id}-{}-r{}",
        body.to_ascii_lowercase(),
        bound_registry_revision
    ))
}

/// Strict workload declaration fixture with a variable description.
#[cfg(test)]
pub(crate) mod test_material {
    pub(crate) fn declaration(description: &str) -> String {
        format!(
            r#"
schema = "odin.registry.v1"
kind = "workload"
enabled = true
description = "{description}"

[image]
reference = "localhost/odin-fixture@sha256:1111111111111111111111111111111111111111111111111111111111111111"

[runtime]
launcher = "/odin/bin/omp"
browser = "/odin/bin/chromium"
supervisor = "/odin/bin/odind"
playwright = "/odin/lib/playwright-core"

[seat]
seat = "coordinator"
project = "home"
gateway_lane = "fixture.gateway"

[network]
allow_hosts = ["example.com"]

[display]
xvfb = "/odin/bin/Xvfb"
screen = "1280x800x24"
stream = true

[state]
path = "/state"
storage = "2Gi"

[export]
pod_path = "/export"
host_folder = "/srv/odin/fixture"

[brief]
text = "fixture brief"

[memory]
namespace = "atlas.code"

[lifetime]
deadline_seconds = 3600
"#
        )
    }

    /// The real blake3 digest of the exact declaration bytes.
    pub(crate) fn digest_of(rendered: &str) -> String {
        odin_domain::Digest::hash(rendered.as_bytes()).to_string()
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;

    use super::test_material::{declaration, digest_of};
    use super::*;

    const PROFILE: &str = "odind-kubert";

    fn record(revision: u64, rendered: &str) -> WorkloadDraftRecord {
        WorkloadDraftRecord {
            declaration_digest: digest_of(rendered),
            profile_id: PROFILE.to_owned(),
            rendered_toml: rendered.to_owned(),
            bound_registry_revision: revision,
        }
    }

    #[test]
    fn retains_loads_and_adopts_identical_replays() {
        let root = tempfile::TempDir::new().expect("temp dir");
        let store = WorkloadDraftStore::seal(root.path()).expect("seal");
        let rendered = declaration("draft store integrity");
        let record = record(4, &rendered);
        let digest = record.declaration_digest.clone();
        store.retain(&record).expect("first retain");
        store.retain(&record).expect("identical replay adopts");
        let loaded = store
            .load(PROFILE, &digest, 4)
            .expect("load")
            .expect("present");
        assert_eq!(loaded.rendered_toml, rendered);
        assert_eq!(loaded.bound_registry_revision, 4);
        assert!(store.require_retained(PROFILE, &digest, 4).is_ok());
    }

    #[test]
    fn same_digest_at_different_bound_revisions_are_distinct_drafts() {
        let root = tempfile::TempDir::new().expect("temp dir");
        let store = WorkloadDraftStore::seal(root.path()).expect("seal");
        let rendered = declaration("revision-bound draft");
        store.retain(&record(4, &rendered)).expect("retain at 4");
        store.retain(&record(5, &rendered)).expect("retain at 5");
        let digest = digest_of(&rendered);
        assert!(store.load(PROFILE, &digest, 4).expect("load").is_some());
        assert!(store.load(PROFILE, &digest, 5).expect("load").is_some());
        assert!(store.load(PROFILE, &digest, 6).expect("load").is_none());
    }

    #[test]
    fn same_bytes_under_two_profiles_are_distinct_drafts() {
        let root = tempfile::TempDir::new().expect("temp dir");
        let store = WorkloadDraftStore::seal(root.path()).expect("seal");
        let rendered = declaration("shared declaration bytes");
        store
            .retain(&record(4, &rendered))
            .expect("retain the first profile's draft");
        let other = WorkloadDraftRecord {
            profile_id: "odind-other".to_owned(),
            ..record(4, &rendered)
        };
        store
            .retain(&other)
            .expect("retain the second profile's draft");
        let digest = digest_of(&rendered);
        assert!(store.load(PROFILE, &digest, 4).expect("load").is_some());
        let other_loaded = store
            .load("odind-other", &digest, 4)
            .expect("load")
            .expect("present");
        assert_eq!(other_loaded.profile_id, "odind-other");
        // Distinct identities: neither profile's key answers for the other.
        assert!(store
            .load("odind-unretained", &digest, 4)
            .expect("load")
            .is_none());
    }

    #[test]
    fn digest_collision_with_different_bytes_refuses_and_preserves() {
        let root = tempfile::TempDir::new().expect("temp dir");
        let store = WorkloadDraftStore::seal(root.path()).expect("seal");
        let rendered = declaration("preserved draft bytes");
        let honest = record(4, &rendered);
        let digest = honest.declaration_digest.clone();
        store.retain(&honest).expect("first retain");
        let colliding = WorkloadDraftRecord {
            declaration_digest: digest.clone(),
            profile_id: PROFILE.to_owned(),
            rendered_toml: declaration("colliding different bytes"),
            bound_registry_revision: 4,
        };
        assert!(matches!(
            store.retain(&colliding),
            Err(WorkloadDraftStoreError::DigestCollision { .. })
        ));
        let loaded = store
            .load(PROFILE, &digest, 4)
            .expect("load")
            .expect("present");
        assert_eq!(loaded.rendered_toml, rendered);
    }

    #[test]
    fn require_retained_maps_absence_to_unknown_draft() {
        let root = tempfile::TempDir::new().expect("temp dir");
        let store = WorkloadDraftStore::seal(root.path()).expect("seal");
        let rendered = declaration("present draft");
        let absent = digest_of(&declaration("never retained draft"));
        assert!(matches!(
            store.require_retained(PROFILE, &absent, 4),
            Err(WorkloadDraftStoreError::UnknownDraft { .. })
        ));
        store.retain(&record(4, &rendered)).expect("retain");
        assert!(store
            .require_retained(PROFILE, &digest_of(&rendered), 4)
            .is_ok());
    }

    #[test]
    fn swapped_records_refuse_as_corrupt_never_absent() {
        let root = tempfile::TempDir::new().expect("temp dir");
        let store = WorkloadDraftStore::seal(root.path()).expect("seal");
        let rendered = declaration("honest retained bytes");
        let record = record(4, &rendered);
        let digest = record.declaration_digest.clone();
        store.retain(&record).expect("retain the honest record");
        let leaf = root.path().join("workload-drafts").join(leaf_path(
            draft_file_stem(PROFILE, &digest, 4).expect("stem"),
        ));

        // Reject changed declaration bytes with unchanged identity fields.
        let swapped_bytes = WorkloadDraftRecord {
            declaration_digest: digest.clone(),
            profile_id: PROFILE.to_owned(),
            rendered_toml: declaration("foreign swapped bytes"),
            bound_registry_revision: 4,
        };
        write_leaf(&leaf, &swapped_bytes);
        let error = store
            .load(PROFILE, &digest, 4)
            .expect_err("swapped bytes must refuse to load");
        assert!(matches!(
            error,
            WorkloadDraftStoreError::CorruptRecord { .. }
        ));
        assert!(!error.is_absent(), "corruption is not absence");
        assert!(matches!(
            store.require_retained(PROFILE, &digest, 4),
            Err(WorkloadDraftStoreError::CorruptRecord { .. })
        ));

        // Reject a valid record stored under a different digest key.
        let moved_rendered = declaration("another honest record");
        let moved = WorkloadDraftRecord {
            declaration_digest: digest_of(&moved_rendered),
            profile_id: PROFILE.to_owned(),
            rendered_toml: moved_rendered,
            bound_registry_revision: 4,
        };
        write_leaf(&leaf, &moved);
        let error = store
            .load(PROFILE, &digest, 4)
            .expect_err("a record moved under another key must refuse to load");
        assert!(matches!(
            error,
            WorkloadDraftStoreError::CorruptRecord { .. }
        ));
        assert!(
            !error.is_absent(),
            "a moved record is corruption, not absence"
        );
    }

    #[test]
    fn profile_tamper_redirect_refuses_as_corrupt() {
        let root = tempfile::TempDir::new().expect("temp dir");
        let store = WorkloadDraftStore::seal(root.path()).expect("seal");
        let rendered = declaration("destination-bound draft bytes");
        let record = record(4, &rendered);
        let digest = record.declaration_digest.clone();
        store.retain(&record).expect("retain the honest record");
        let leaf = root.path().join("workload-drafts").join(leaf_path(
            draft_file_stem(PROFILE, &digest, 4).expect("stem"),
        ));

        // -- A tampered leaf that redirects the publication: same bytes,
        //    same digest, same revision, but the profile id now claims
        //    another destination. At the approved key this is corruption;
        //    the other profile's key was never retained.
        let redirected = WorkloadDraftRecord {
            profile_id: "odind-other".to_owned(),
            ..record.clone()
        };
        write_leaf(&leaf, &redirected);
        let error = store
            .load(PROFILE, &digest, 4)
            .expect_err("a profile-redirected record must refuse to load");
        assert!(matches!(
            error,
            WorkloadDraftStoreError::CorruptRecord { .. }
        ));
        assert!(!error.is_absent(), "redirection is corruption, not absence");
        assert!(matches!(
            store.require_retained("odind-other", &digest, 4),
            Err(WorkloadDraftStoreError::UnknownDraft { .. })
        ));
        assert!(matches!(
            store.require_retained(PROFILE, &digest, 4),
            Err(WorkloadDraftStoreError::CorruptRecord { .. })
        ));
    }

    #[test]
    fn malformed_profile_ids_refuse_the_leaf_name() {
        let root = tempfile::TempDir::new().expect("temp dir");
        let store = WorkloadDraftStore::seal(root.path()).expect("seal");
        let rendered = declaration("well-formed draft");
        let digest = digest_of(&rendered);
        let long = "a".repeat(129);
        for profile in ["", "../escape", "odin/escape", long.as_str(), "-lead"] {
            assert!(matches!(
                store.require_retained(profile, &digest, 4),
                Err(WorkloadDraftStoreError::MalformedProfileId { .. })
            ));
        }
        assert!(store.retain(&record(4, &rendered)).is_ok());
    }

    /// Overwrites one sealed leaf with the JSON encoding of `record`,
    /// restoring the store's mode-0444 seal — the tamper a broken writer
    /// or an attacker would leave behind.
    fn write_leaf(leaf: &Path, record: &WorkloadDraftRecord) {
        std::fs::set_permissions(leaf, std::fs::Permissions::from_mode(0o644))
            .expect("unlock the sealed leaf");
        let bytes = serde_json::to_vec_pretty(record).expect("encode record");
        std::fs::write(leaf, bytes).expect("overwrite the leaf");
        std::fs::set_permissions(leaf, std::fs::Permissions::from_mode(0o444))
            .expect("reseal the leaf");
    }
}
