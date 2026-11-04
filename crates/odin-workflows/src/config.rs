//! The declared workflow tools (`services.odin.tools`, rendered to the JSON
//! file `ODIN_TOOLS` names): executables, data roots, secret files and
//! service endpoints, each by key.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::Deserialize;
use url::Url;

/// The environment variable naming the rendered tools file.
pub const ENV: &str = "ODIN_TOOLS";

#[derive(Clone, Debug, Default, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ToolsConfig {
    /// Absolute /nix/store paths by key.
    #[serde(default)]
    pub executables: BTreeMap<String, PathBuf>,
    #[serde(default)]
    pub roots: BTreeMap<String, Root>,
    /// sops-rendered secret files by key; values are never in the store.
    #[serde(default)]
    pub secrets: BTreeMap<String, PathBuf>,
    /// Service base URLs by key.
    #[serde(default)]
    pub endpoints: BTreeMap<String, Url>,
}

/// One declared data root.
#[derive(Clone, Debug, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Root {
    pub path: PathBuf,
    #[serde(default)]
    pub writable: bool,
}

impl ToolsConfig {
    /// Reads the file `ODIN_TOOLS` names; no variable is an empty config, so
    /// every workflow then preflights naming its first missing key.
    pub fn from_env() -> Result<Self, String> {
        match std::env::var_os(ENV) {
            None => Ok(Self::default()),
            Some(path) => Self::load(Path::new(&path)),
        }
    }

    pub fn load(path: &Path) -> Result<Self, String> {
        let bytes = std::fs::read(path)
            .map_err(|error| format!("{ENV} file {} is unreadable: {error}", path.display()))?;
        Self::parse(&bytes).map_err(|cause| format!("{ENV} file {}: {cause}", path.display()))
    }

    pub fn parse(bytes: &[u8]) -> Result<Self, String> {
        let config: Self = serde_json::from_slice(bytes).map_err(|error| error.to_string())?;
        for (key, path) in &config.executables {
            if !path.is_absolute() || !path.starts_with("/nix/store/") {
                return Err(format!(
                    "executable {key} must be an absolute /nix/store path, not {}",
                    path.display()
                ));
            }
        }
        for (key, root) in &config.roots {
            if !root.path.is_absolute() {
                return Err(format!(
                    "root {key} must be an absolute path, not {}",
                    root.path.display()
                ));
            }
        }
        for (key, path) in &config.secrets {
            if !path.is_absolute() {
                return Err(format!(
                    "secret {key} must be an absolute file path, not {}",
                    path.display()
                ));
            }
        }
        Ok(config)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_relative_root_or_secret_is_refused_naming_the_key() {
        let root =
            ToolsConfig::parse(br#"{"roots": {"scratch": {"path": "tmp", "writable": true}}}"#)
                .expect_err("relative root");
        assert!(root.contains("scratch") && root.contains("tmp"), "{root}");
        let secret = ToolsConfig::parse(br#"{"secrets": {"library": "run/key"}}"#)
            .expect_err("relative secret");
        assert!(secret.contains("library"), "{secret}");
    }
}
