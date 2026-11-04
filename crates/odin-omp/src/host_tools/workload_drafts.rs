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

/// Longest profile id a retained draft's leaf name carries.
const MAX_PROFILE_ID_BYTES: usize = 128;

/// Temporary names `retain` tries before giving up on crashed twins' orphans.
const RETAIN_ATTEMPTS: u64 = 8;

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
#[derive(Debug, thiserror::Error)]
pub enum WorkloadDraftStoreError {
    #[error(transparent)]
    Confined(ConfinedError),
    #[error("draft serialization failed: {detail}")]
    Serialize { detail: String },
    #[error("draft digest {digest:?} is not a canonical blake3 digest")]
    MalformedDigest { digest: String },
    #[error(
        "no draft {digest} is retained at bound revision {bound_registry_revision}; \
         draft it again and obtain a fresh approval"
    )]
    UnknownDraft {
        digest: String,
        bound_registry_revision: u64,
    },
    /// The entry exists but is not the immutable record its key promises:
    /// it does not parse, the claimed digest or bound revision disagrees
    /// with the leaf key, the bytes do not hash to the retained digest, or
    /// the bytes are not a strict workload declaration. Never a usable
    /// draft; the caller refuses typed.
    #[error(
        "retained draft {digest} at bound revision {bound_registry_revision} is corrupt: {detail}"
    )]
    CorruptRecord {
        digest: String,
        bound_registry_revision: u64,
        detail: String,
    },
    /// Profile ids must satisfy the registry grammar and fit within [`MAX_PROFILE_ID_BYTES`].
    #[error("draft profile id {profile_id:?} is not a registry identifier")]
    MalformedProfileId { profile_id: String },
}

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
    /// fsync, `install_exclusive` commit, directory sync. The key names the
    /// declaration's own digest, so an entry already under it is the same
    /// draft and the retain is a no-op; `load` re-checks the bytes against
    /// the digest. A crashed attempt leaves only a private temporary that
    /// later attempts skip.
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
        for attempt in 0..RETAIN_ATTEMPTS {
            let temporary = PathBuf::from(format!(".{stem}.{}-{}.tmp", self.process_tag, attempt));
            match self.capability.create_atomic(&temporary, &bytes, 0o444) {
                Ok(()) => {}
                Err(ConfinedError::AlreadyExists { .. }) => {
                    // A crashed twin's orphan: skip the name and continue.
                    continue;
                }
                Err(error) => return Err(WorkloadDraftStoreError::Confined(error)),
            }
            // The link commit leaves the temporary's name behind; the leaf keeps the inode.
            let installed = self
                .capability
                .install_exclusive(&temporary, &leaf_path(stem));
            let _ = self.capability.remove(&temporary);
            return match installed {
                Ok(()) | Err(ConfinedError::AlreadyExists { .. }) => Ok(()),
                Err(error) => Err(WorkloadDraftStoreError::Confined(error)),
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
            serde_json::from_reader(&file).map_err(|error| {
                WorkloadDraftStoreError::CorruptRecord {
                    digest: declaration_digest.to_owned(),
                    bound_registry_revision,
                    detail: format!("the entry is not a draft record: {error}"),
                }
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
    if profile_id.len() > MAX_PROFILE_ID_BYTES || !valid_id(profile_id) {
        return Err(WorkloadDraftStoreError::MalformedProfileId {
            profile_id: profile_id.to_owned(),
        });
    }
    let digest: Digest =
        declaration_digest
            .parse()
            .map_err(|_| WorkloadDraftStoreError::MalformedDigest {
                digest: declaration_digest.to_owned(),
            })?;
    Ok(format!(
        "{profile_id}-{}-r{bound_registry_revision}",
        digest.hex()
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

    fn store() -> (tempfile::TempDir, WorkloadDraftStore) {
        let root = tempfile::TempDir::new().expect("temp dir");
        let store = WorkloadDraftStore::seal(root.path()).expect("seal");
        (root, store)
    }

    fn entries(root: &tempfile::TempDir) -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(root.path().join("workload-drafts"))
            .expect("draft directory")
            .map(|entry| {
                entry
                    .expect("entry")
                    .file_name()
                    .to_string_lossy()
                    .into_owned()
            })
            .collect();
        names.sort();
        names
    }

    /// A retained draft loads back exactly, a replay is a no-op, and each retain leaves one
    /// entry: the leaf, with no temporary beside it.
    #[test]
    fn retains_loads_and_adopts_identical_replays() {
        let (root, store) = store();
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
        assert_eq!(entries(&root).len(), 1, "{:?}", entries(&root));
    }

    /// A draft is keyed by profile, digest and bound revision: the same bytes at another revision
    /// or under another profile are another draft, and neither answers for the other's key.
    #[test]
    fn a_draft_is_keyed_by_profile_digest_and_bound_revision() {
        let (_root, store) = store();
        let rendered = declaration("revision-bound draft");
        let digest = digest_of(&rendered);
        store.retain(&record(4, &rendered)).expect("retain at 4");
        store.retain(&record(5, &rendered)).expect("retain at 5");
        store
            .retain(&WorkloadDraftRecord {
                profile_id: "odind-other".to_owned(),
                ..record(4, &rendered)
            })
            .expect("retain under another profile");
        assert!(store.load(PROFILE, &digest, 4).expect("load").is_some());
        assert!(store.load(PROFILE, &digest, 5).expect("load").is_some());
        assert!(store.load(PROFILE, &digest, 6).expect("load").is_none());
        assert!(store
            .load("odind-other", &digest, 4)
            .expect("load")
            .is_some());
        assert!(store
            .load("odind-unretained", &digest, 4)
            .expect("load")
            .is_none());
    }

    /// An entry that is not the record its key promises refuses as corrupt, never as absent: swapped
    /// bytes, a record moved under another digest, a profile redirect, and a file that is not JSON.
    #[test]
    fn a_tampered_entry_refuses_as_corrupt_never_absent() {
        let (root, store) = store();
        let rendered = declaration("honest retained bytes");
        let honest = record(4, &rendered);
        let digest = honest.declaration_digest.clone();
        store.retain(&honest).expect("retain the honest record");
        let leaf = root.path().join("workload-drafts").join(leaf_path(
            draft_file_stem(PROFILE, &digest, 4).expect("stem"),
        ));
        let moved = declaration("another honest record");
        let tampered: [(&str, Vec<u8>); 4] = [
            (
                "swapped bytes",
                serde_json::to_vec(&WorkloadDraftRecord {
                    rendered_toml: declaration("foreign swapped bytes"),
                    ..honest.clone()
                })
                .unwrap(),
            ),
            (
                "moved record",
                serde_json::to_vec(&record(4, &moved)).unwrap(),
            ),
            (
                "profile redirect",
                serde_json::to_vec(&WorkloadDraftRecord {
                    profile_id: "odind-other".to_owned(),
                    ..honest.clone()
                })
                .unwrap(),
            ),
            ("not json", b"{\"declaration_digest\": ".to_vec()),
        ];
        for (name, bytes) in tampered {
            std::fs::set_permissions(&leaf, std::fs::Permissions::from_mode(0o644)).unwrap();
            std::fs::write(&leaf, bytes).unwrap();
            assert!(
                matches!(
                    store.require_retained(PROFILE, &digest, 4),
                    Err(WorkloadDraftStoreError::CorruptRecord { .. })
                ),
                "{name} refuses as corrupt"
            );
        }
        assert!(matches!(
            store.require_retained("odind-other", &digest, 4),
            Err(WorkloadDraftStoreError::UnknownDraft { .. })
        ));
    }
}
