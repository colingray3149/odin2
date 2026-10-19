//! Digest-qualified artifact contracts: the immutable artifact reference, the
//! composition runtime support manifest, and the executable identities every
//! generated manifest must bind.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use super::huginn::ConfigError;
use super::odind::OdindConfig;

/// Strict digest-qualified reference to one immutable artifact.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PathDigestRef {
    pub path: PathBuf,
    /// Canonical `blake3:<64 lowercase hex>` over the exact artifact bytes.
    pub digest: String,
}

impl PathDigestRef {
    /// Validates path absoluteness and canonical digest shape.
    pub fn validate(&self) -> Result<(), ConfigError> {
        if !self.path.is_absolute() {
            return Err(ConfigError::Invalid(format!(
                "bound path {} must be absolute",
                self.path.display()
            )));
        }
        let encoded = self.digest.strip_prefix("blake3:").ok_or_else(|| {
            ConfigError::Invalid(format!(
                "digest {:?} must start with \"blake3:\"",
                self.digest
            ))
        })?;
        if encoded.len() != 64
            || !encoded
                .bytes()
                .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
        {
            return Err(ConfigError::Invalid(format!(
                "digest {:?} must be blake3: followed by 64 lowercase hexadecimal digits",
                self.digest
            )));
        }
        Ok(())
    }
}

pub const RUNTIME_MANIFEST_SCHEMA: &str = "odin.runtime-manifest.v1";

/// Executables required in every generated runtime manifest.
pub const REQUIRED_RUNTIME_MANIFEST_KEYS: [&str; 18] = [
    "odin",
    "odind",
    "sweep",
    "omp",
    "git",
    "ssh",
    "ssh-keygen",
    "worker_bootstrap",
    "unshare",
    "bwrap",
    "env",
    "timeout",
    "systemd-run",
    "systemctl",
    "loginctl",
    "xdpyinfo",
    "xprop",
    "scanner",
];

/// The runtime-manifest executable key of one declared adapter backend
/// (`[adapter_backends.<id>]` in the packaged controller configuration).
pub fn adapter_executable_key(adapter: &str) -> String {
    format!("adapter.{adapter}")
}

/// The composition runtime support manifest (`odin.runtime-manifest.v1`).
/// A byte artifact shipped inside the composition store path as
/// `runtime-manifest.json`; consumers resolve pinned executables and the
/// packaged configuration exclusively through it — never PATH discovery.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeManifest {
    pub schema: String,
    /// Pinned tool identities by exact key (see
    /// [`REQUIRED_RUNTIME_MANIFEST_KEYS`]); additional actually consumed
    /// tools appear under their exact IDs.
    pub executables: BTreeMap<String, PathDigestRef>,
    pub odind_config: PathDigestRef,
}

impl RuntimeManifest {
    /// Loads and validates manifest structure; [`Self::load_config`] verifies
    /// the bound configuration bytes before parsing them.
    pub fn load(path: impl AsRef<Path>) -> Result<Self, ConfigError> {
        let path = path.as_ref();
        let text = fs::read_to_string(path).map_err(|source| ConfigError::Io {
            path: path.to_path_buf(),
            message: source.to_string(),
        })?;
        let manifest: Self =
            serde_json::from_str(&text).map_err(|source| ConfigError::Toml(source.to_string()))?;
        manifest.validate()?;
        Ok(manifest)
    }

    /// Verifies the bound document, then applies the same registry adoption
    /// and validation as [`OdindConfig::load`]. Hashing and parsing share
    /// one read, so a replaced path cannot substitute configuration after
    /// verification.
    pub fn load_config(&self) -> Result<OdindConfig, ConfigError> {
        self.odind_config.validate()?;
        let path = &self.odind_config.path;
        let text = fs::read_to_string(path).map_err(|source| ConfigError::Io {
            path: path.clone(),
            message: source.to_string(),
        })?;
        let actual = odin_domain::Digest::hash(text.as_bytes()).to_string();
        if actual != self.odind_config.digest {
            return Err(ConfigError::Invalid(format!(
                "configuration {} digests to {actual}, manifest binds {}",
                path.display(),
                self.odind_config.digest
            )));
        }
        OdindConfig::parse_loaded(&text)
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.schema != RUNTIME_MANIFEST_SCHEMA {
            return Err(ConfigError::Invalid(format!(
                "runtime manifest schema must be {RUNTIME_MANIFEST_SCHEMA:?}, found {:?}",
                self.schema
            )));
        }
        for key in REQUIRED_RUNTIME_MANIFEST_KEYS {
            let entry = self.executables.get(key).ok_or_else(|| {
                ConfigError::Invalid(format!(
                    "runtime manifest is missing required executable key {key:?}"
                ))
            })?;
            entry.validate().map_err(|error| {
                ConfigError::Invalid(format!("runtime manifest key {key:?}: {error}"))
            })?;
        }
        for (key, entry) in &self.executables {
            if key.is_empty() {
                return Err(ConfigError::Invalid(
                    "runtime manifest executable keys must be non-empty".to_owned(),
                ));
            }
            entry.validate().map_err(|error| {
                ConfigError::Invalid(format!("runtime manifest key {key:?}: {error}"))
            })?;
        }
        self.odind_config.validate().map_err(|error| {
            ConfigError::Invalid(format!("runtime manifest odind_config: {error}"))
        })?;
        Ok(())
    }

    /// Resolves one pinned executable identity; no PATH fallback exists.
    pub fn executable(&self, key: &str) -> Result<&PathDigestRef, ConfigError> {
        self.executables.get(key).ok_or_else(|| {
            ConfigError::Invalid(format!("runtime manifest has no executable key {key:?}"))
        })
    }

    /// Fails closed unless every adapter backend the packaged controller
    /// configuration declares has its executable identity
    /// (`adapter.<id>`) in this manifest.
    pub fn require_adapter_support(&self, config: &OdindConfig) -> Result<(), ConfigError> {
        for id in config.adapter_backends.keys() {
            self.executable(&adapter_executable_key(id))?;
        }
        Ok(())
    }
}
