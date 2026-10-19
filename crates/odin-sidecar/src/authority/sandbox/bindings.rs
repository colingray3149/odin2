//! Configure interpreter and sandbox paths before accepting caller requests.

use crate::{SidecarError, SidecarErrorCode};
use std::path::{Path, PathBuf};

/// Host-selected paths prevent callers from choosing arbitrary interpreters.
#[derive(Clone, Debug)]
pub struct InterpreterBinding {
    pub python: PathBuf,
    pub bun: PathBuf,
}

impl InterpreterBinding {
    pub fn new(python: PathBuf, bun: PathBuf) -> Result<Self, SidecarError> {
        for (name, path) in [("python", &python), ("bun", &bun)] {
            if !path.is_absolute() {
                return Err(SidecarError::new(
                    SidecarErrorCode::Authority,
                    format!("{name} interpreter must be an absolute authority-bound path"),
                ));
            }
        }
        Ok(Self { python, bun })
    }

    pub(super) fn program(&self, interpreter: &str) -> Option<&Path> {
        match interpreter {
            "python" => Some(self.python.as_path()),
            "bun" => Some(self.bun.as_path()),
            _ => None,
        }
    }
}

/// Supply sandbox paths before accepting requests so callers cannot widen filesystem access.
#[derive(Clone, Debug)]
pub struct EffectorSandboxBinding {
    pub bwrap: PathBuf,
    pub cache_root: PathBuf,
    pub tool_path: String,
    pub context_root: Option<PathBuf>,
    pub cargo_registry_cache: Option<PathBuf>,
    pub cargo_git_cache: Option<PathBuf>,
    pub nix_config_root: Option<PathBuf>,
}

impl EffectorSandboxBinding {
    pub fn new(
        bwrap: PathBuf,
        cache_root: PathBuf,
        tool_path: String,
        context_root: Option<PathBuf>,
        cargo_registry_cache: Option<PathBuf>,
        cargo_git_cache: Option<PathBuf>,
        nix_config_root: Option<PathBuf>,
    ) -> Result<Self, SidecarError> {
        for (name, path) in [("bwrap", &bwrap), ("cache root", &cache_root)] {
            if !path.is_absolute() {
                return Err(SidecarError::new(
                    SidecarErrorCode::Authority,
                    format!("{name} must be an absolute host binding"),
                ));
            }
        }
        if tool_path.is_empty()
            || std::env::split_paths(&tool_path)
                .any(|path| !path.is_absolute() || path.as_os_str().is_empty())
        {
            return Err(SidecarError::new(
                SidecarErrorCode::Authority,
                "sandbox tool PATH must contain only absolute nonempty entries",
            ));
        }
        for (name, path) in [
            ("context root", &context_root),
            ("Cargo registry cache", &cargo_registry_cache),
            ("Cargo git cache", &cargo_git_cache),
            ("Nix config root", &nix_config_root),
        ] {
            if path.as_ref().is_some_and(|path| !path.is_absolute()) {
                return Err(SidecarError::new(
                    SidecarErrorCode::Authority,
                    format!("{name} must be absolute when configured"),
                ));
            }
        }
        Ok(Self {
            bwrap,
            cache_root,
            tool_path,
            context_root,
            cargo_registry_cache,
            cargo_git_cache,
            nix_config_root,
        })
    }
}
