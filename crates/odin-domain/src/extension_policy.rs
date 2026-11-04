//! Extension operational policy (`odin.extension-policy.v1`) generated from registry
//! and controller revisions. Consumers validate the path, exact bytes, schema,
//! revisions, and BLAKE3 digest before use. Only path and digest cross components,
//! not parsed contents; secrets, credentials, and full registry snapshots are excluded.

use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::Digest;

pub const EXTENSION_POLICY_SCHEMA: &str = "odin.extension-policy.v1";
pub const EXTENSION_POLICY_VERSION: u32 = 1;
pub const EXTENSION_POLICY_MAX_BYTES: usize = 65_536;
/// Environment key carrying the absolute policy path into the OMP child.
pub const EXTENSION_POLICY_PATH_ENV: &str = "ODIN_EXTENSION_POLICY";
/// Environment key carrying the bound BLAKE3 digest into the OMP child.
pub const EXTENSION_POLICY_DIGEST_ENV: &str = "ODIN_EXTENSION_POLICY_DIGEST";

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExtensionPolicyV1 {
    pub schema: String,
    pub version: u32,
    /// Active published registry snapshot revision the policy was resolved
    /// from; a policy bound to an older revision is stale and rejected.
    pub snapshot_revision: u64,
    pub config_revision: u64,
    pub extension: ExtensionArtifactPolicy,
    /// Sidecar operational settings applied by the launcher and revalidated
    /// by the sidecar itself.
    pub sidecar: SidecarOperationalPolicy,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExtensionArtifactPolicy {
    pub path: PathBuf,
    pub digest: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SidecarOperationalPolicy {
    pub accept_timeout_ms: u64,
    pub max_requests: u64,
    pub max_spend: u64,
    pub max_state_bytes: u64,
    pub max_request_bytes: u64,
    pub max_frame_bytes: u64,
}

/// Absolute policy path and BLAKE3 digest of its exact bytes, transported together.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExtensionPolicyBinding {
    pub path: PathBuf,
    pub digest: String,
}

impl ExtensionPolicyBinding {
    pub const fn new(path: PathBuf, digest: String) -> Self {
        Self { path, digest }
    }

    /// Loads and fully validates the bound document: bounded read, exact
    /// BLAKE3 byte check, strict schema/version/revision validation.
    pub fn load(&self) -> Result<ExtensionPolicyV1, ExtensionPolicyError> {
        ExtensionPolicyV1::bind_file(&self.path, &self.digest)
    }
}

impl ExtensionPolicyV1 {
    /// Writes canonical policy bytes and returns the binding for them.
    ///
    /// The file is written once at a fresh path, fsynced, and made read-only;
    /// callers must target a path that does not already exist so an earlier
    /// binding can never be silently replaced.
    pub fn publish(
        path: impl AsRef<Path>,
        policy: &ExtensionPolicyV1,
    ) -> Result<ExtensionPolicyBinding, ExtensionPolicyError> {
        policy.validate()?;
        let path = path.as_ref();
        if !path.is_absolute() {
            return Err(ExtensionPolicyError::Invalid(
                "policy path must be absolute".to_owned(),
            ));
        }
        let bytes = serde_json::to_vec(policy)?;
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .map_err(|source| {
                if source.kind() == std::io::ErrorKind::AlreadyExists {
                    ExtensionPolicyError::Exists(path.to_path_buf())
                } else {
                    ExtensionPolicyError::Io {
                        path: path.to_path_buf(),
                        source,
                    }
                }
            })?;
        file.write_all(&bytes)
            .map_err(|source| ExtensionPolicyError::Io {
                path: path.to_path_buf(),
                source,
            })?;
        file.sync_all().map_err(|source| ExtensionPolicyError::Io {
            path: path.to_path_buf(),
            source,
        })?;
        drop(file);
        make_read_only(path)?;
        let digest = Digest::hash(&bytes).to_string();
        Ok(ExtensionPolicyBinding {
            path: path.to_path_buf(),
            digest,
        })
    }

    /// Strict structural validation without file access.
    pub fn validate(&self) -> Result<(), ExtensionPolicyError> {
        if self.schema != EXTENSION_POLICY_SCHEMA {
            return Err(ExtensionPolicyError::Invalid(format!(
                "schema must be {EXTENSION_POLICY_SCHEMA:?}, found {:?}",
                self.schema
            )));
        }
        if self.version != EXTENSION_POLICY_VERSION {
            return Err(ExtensionPolicyError::Invalid(format!(
                "version must be {EXTENSION_POLICY_VERSION}, found {}",
                self.version
            )));
        }
        if self.snapshot_revision == 0 {
            return Err(ExtensionPolicyError::Invalid(
                "snapshot_revision must be a positive registry snapshot revision".to_owned(),
            ));
        }
        if self.config_revision == 0 {
            return Err(ExtensionPolicyError::Invalid(
                "config_revision must be a positive controller config revision".to_owned(),
            ));
        }
        validate_digest(&self.extension.digest)?;
        if !self.extension.path.is_absolute() {
            return Err(ExtensionPolicyError::Invalid(
                "extension artifact path must be absolute".to_owned(),
            ));
        }
        self.sidecar.validate()?;
        Ok(())
    }

    /// Reads a policy file, verifies its exact bytes against `digest`, parses
    /// it strictly (unknown fields rejected by the derived deserializer), and
    /// validates it. A writable policy file is rejected: a digest-bound
    /// policy must be immutable while bound.
    pub fn bind_file(
        path: impl AsRef<Path>,
        digest: &str,
    ) -> Result<ExtensionPolicyV1, ExtensionPolicyError> {
        let path = path.as_ref();
        if !path.is_absolute() {
            return Err(ExtensionPolicyError::Invalid(
                "policy path must be absolute".to_owned(),
            ));
        }
        validate_digest(digest)?;
        let metadata = fs::metadata(path).map_err(|source| ExtensionPolicyError::Io {
            path: path.to_path_buf(),
            source,
        })?;
        if !metadata.is_file() {
            return Err(ExtensionPolicyError::Invalid(format!(
                "extension policy {} is not a regular file",
                path.display()
            )));
        }
        if !metadata.permissions().readonly() {
            return Err(ExtensionPolicyError::Mutable {
                path: path.to_path_buf(),
            });
        }
        let mut bytes = Vec::new();
        let file = fs::File::open(path).map_err(|source| ExtensionPolicyError::Io {
            path: path.to_path_buf(),
            source,
        })?;
        file.take((EXTENSION_POLICY_MAX_BYTES + 1) as u64)
            .read_to_end(&mut bytes)
            .map_err(|source| ExtensionPolicyError::Io {
                path: path.to_path_buf(),
                source,
            })?;
        if bytes.len() > EXTENSION_POLICY_MAX_BYTES {
            return Err(ExtensionPolicyError::TooLarge {
                path: path.to_path_buf(),
                size: bytes.len(),
            });
        }
        let actual = Digest::hash(&bytes).to_string();
        if actual != digest {
            return Err(ExtensionPolicyError::DigestMismatch {
                path: path.to_path_buf(),
                expected: digest.to_owned(),
                actual,
            });
        }
        let policy: ExtensionPolicyV1 = serde_json::from_slice(&bytes)?;
        policy.validate()?;
        Ok(policy)
    }

    /// Confirms the policy authorizes exactly the artifact at
    /// `actual_extension_path`: same canonical location and same bytes.
    pub fn verify_extension_artifact(
        &self,
        actual_extension_path: impl AsRef<Path>,
    ) -> Result<(), ExtensionPolicyError> {
        let actual = actual_extension_path
            .as_ref()
            .canonicalize()
            .map_err(|source| ExtensionPolicyError::Io {
                path: actual_extension_path.as_ref().to_path_buf(),
                source,
            })?;
        let declared =
            self.extension
                .path
                .canonicalize()
                .map_err(|source| ExtensionPolicyError::Io {
                    path: self.extension.path.clone(),
                    source,
                })?;
        if actual != declared {
            return Err(ExtensionPolicyError::Invalid(format!(
                "extension artifact path mismatch: policy binds {}, runtime uses {}",
                declared.display(),
                actual.display()
            )));
        }
        let bytes = fs::read(&actual).map_err(|source| ExtensionPolicyError::Io {
            path: actual.clone(),
            source,
        })?;
        let digest = Digest::hash(&bytes).to_string();
        if digest != self.extension.digest {
            return Err(ExtensionPolicyError::DigestMismatch {
                path: actual,
                expected: self.extension.digest.clone(),
                actual: digest,
            });
        }
        Ok(())
    }
}

impl SidecarOperationalPolicy {
    /// The limits every sidecar composition runs with; the request and frame ceilings are the
    /// authority wire's own.
    pub const fn compiled_default() -> Self {
        Self {
            accept_timeout_ms: 10_000,
            max_requests: 64,
            max_spend: 262_144,
            max_state_bytes: 1_048_576,
            max_request_bytes: odin_types::MAX_AUTHORITY_REQUEST_BYTES as u64,
            max_frame_bytes: odin_types::MAX_FRAME_BYTES as u64,
        }
    }

    pub fn validate(&self) -> Result<(), ExtensionPolicyError> {
        for (field, value) in [
            ("accept_timeout_ms", self.accept_timeout_ms),
            ("max_requests", self.max_requests),
            ("max_spend", self.max_spend),
            ("max_state_bytes", self.max_state_bytes),
            ("max_request_bytes", self.max_request_bytes),
            ("max_frame_bytes", self.max_frame_bytes),
        ] {
            if value == 0 {
                return Err(ExtensionPolicyError::Invalid(format!(
                    "sidecar.{field} must be positive"
                )));
            }
        }
        if self.max_request_bytes > self.max_frame_bytes {
            return Err(ExtensionPolicyError::Invalid(
                "sidecar.max_request_bytes must not exceed sidecar.max_frame_bytes".to_owned(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ExtensionPolicyError {
    #[error("extension policy I/O failed for {path}: {source}")]
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("extension policy {path} is {size} bytes, above the {EXTENSION_POLICY_MAX_BYTES}-byte bound")]
    TooLarge { path: PathBuf, size: usize },
    #[error("extension policy digest mismatch for {path}: expected {expected}, found {actual}")]
    DigestMismatch {
        path: PathBuf,
        expected: String,
        actual: String,
    },
    #[error("extension policy {path} is mutable; a digest-bound policy must be read-only")]
    Mutable { path: PathBuf },
    #[error("extension policy path {0:?} already exists")]
    Exists(PathBuf),
    #[error("extension policy JSON is invalid: {0}")]
    Json(#[from] serde_json::Error),
    #[error("extension policy is invalid: {0}")]
    Invalid(String),
}

pub fn validate_digest(digest: &str) -> Result<(), ExtensionPolicyError> {
    Digest::parse(digest)
        .map(drop)
        .map_err(|error| ExtensionPolicyError::Invalid(error.to_string()))
}

fn make_read_only(path: &Path) -> Result<(), ExtensionPolicyError> {
    let mut permissions = fs::metadata(path)
        .map_err(|source| ExtensionPolicyError::Io {
            path: path.to_path_buf(),
            source,
        })?
        .permissions();
    permissions.set_readonly(true);
    fs::set_permissions(path, permissions).map_err(|source| ExtensionPolicyError::Io {
        path: path.to_path_buf(),
        source,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_policy() -> ExtensionPolicyV1 {
        ExtensionPolicyV1 {
            schema: EXTENSION_POLICY_SCHEMA.to_owned(),
            version: EXTENSION_POLICY_VERSION,
            snapshot_revision: 7,
            config_revision: 3,
            extension: ExtensionArtifactPolicy {
                path: PathBuf::from("/nix/store/extension/index.ts"),
                digest: format!("blake3:{}", blake3::hash(b"extension bytes").to_hex()),
            },
            sidecar: SidecarOperationalPolicy::compiled_default(),
        }
    }

    #[test]
    fn extension_policy_binds_and_rejects_substitution() {
        let directory = tempfile::tempdir().expect("tempdir");
        let path = directory.path().join("policy.json");
        let policy = sample_policy();
        let binding = ExtensionPolicyV1::publish(&path, &policy).expect("policy publishes");
        assert!(path.metadata().expect("metadata").permissions().readonly());

        let loaded = binding.load().expect("binding loads");
        assert_eq!(loaded, policy);

        let mut tampered = fs::read(&path).expect("policy bytes");
        tampered[0] = tampered[0].wrapping_add(1);
        let tampered_path = directory.path().join("tampered.json");
        std::fs::write(&tampered_path, tampered).expect("write substituted bytes");
        let mut permissions = std::fs::metadata(&tampered_path)
            .expect("metadata")
            .permissions();
        permissions.set_readonly(true);
        std::fs::set_permissions(&tampered_path, permissions).expect("read-only");
        assert!(matches!(
            ExtensionPolicyV1::bind_file(&tampered_path, &binding.digest),
            Err(ExtensionPolicyError::DigestMismatch { .. })
        ));
    }

    #[test]
    fn extension_policy_rejects_missing_and_mutable_files() {
        let directory = tempfile::tempdir().expect("tempdir");
        let missing = directory.path().join("missing.json");
        let digest = Digest::hash(b"{}").to_string();
        assert!(matches!(
            ExtensionPolicyV1::bind_file(&missing, &digest),
            Err(ExtensionPolicyError::Io { .. })
        ));

        let writable = directory.path().join("writable.json");
        let policy = sample_policy();
        let bytes = serde_json::to_vec(&policy).expect("policy bytes");
        std::fs::write(&writable, bytes).expect("writable policy");
        let writable_digest = Digest::hash(&fs::read(&writable).expect("read back")).to_string();
        assert!(matches!(
            ExtensionPolicyV1::bind_file(&writable, &writable_digest),
            Err(ExtensionPolicyError::Mutable { .. })
        ));
    }

    #[test]
    fn extension_policy_publish_never_clobbers() {
        let directory = tempfile::tempdir().expect("tempdir");
        let path = directory.path().join("policy.json");
        let policy = sample_policy();
        ExtensionPolicyV1::publish(&path, &policy).expect("first publish");
        assert!(matches!(
            ExtensionPolicyV1::publish(&path, &policy),
            Err(ExtensionPolicyError::Exists(_))
        ));
    }
}
