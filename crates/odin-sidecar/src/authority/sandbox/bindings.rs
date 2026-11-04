//! Configure interpreter and sandbox paths before accepting caller requests.

use crate::{SidecarError, SidecarErrorCode};
use odin_kernel::ExecutorFault;
use odin_sidecar_protocol::{EFFECT_MAX_RETAINED_BYTES, SANDBOX_PROJECT};
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

/// Host-selected tool executables for the fixed-argv capsule capabilities.
#[derive(Clone, Debug)]
pub struct ToolBinding {
    pub ast_grep: PathBuf,
    pub look: PathBuf,
}

impl ToolBinding {
    pub fn new(ast_grep: PathBuf, look: PathBuf) -> Result<Self, SidecarError> {
        for (name, path) in [("ast-grep", &ast_grep), ("look", &look)] {
            if !path.is_absolute() {
                return Err(SidecarError::new(
                    SidecarErrorCode::Authority,
                    format!("{name} must be an absolute authority-bound path"),
                ));
            }
        }
        Ok(Self { ast_grep, look })
    }
}

impl EffectorSandboxBinding {
    /// The capsule bubble around one fixed program: capsule writable, `.git` read-only,
    /// no network beyond its own loopback, the sandbox tool PATH and a private HOME.
    pub(super) fn bubble(
        &self,
        capsule_root: &Path,
        program: &Path,
    ) -> Result<Vec<String>, ExecutorFault> {
        let mut argv = odin_process::capsule_sandbox_argv(
            self.bwrap.display().to_string(),
            capsule_root,
            "--bind",
        );
        let git = capsule_root.join(".git");
        match std::fs::symlink_metadata(&git) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(ExecutorFault::Rejected {
                    detail: "capsule .git is a symlink; refusing to bind it read-only".to_owned(),
                });
            }
            Ok(metadata) if metadata.is_dir() => argv.extend([
                "--ro-bind".to_owned(),
                git.display().to_string(),
                format!("{SANDBOX_PROJECT}/.git"),
            ]),
            _ => {}
        }
        for (name, value) in [
            ("PATH", self.tool_path.as_str()),
            ("HOME", "/tmp"),
            ("TMPDIR", "/tmp"),
        ] {
            argv.extend(["--setenv".to_owned(), name.to_owned(), value.to_owned()]);
        }
        argv.extend([
            "--chdir".to_owned(),
            SANDBOX_PROJECT.to_owned(),
            "--".to_owned(),
            program.display().to_string(),
        ]);
        Ok(argv)
    }
}

/// Execute-effect parameters for one bubbled argv; the effector's environment stays empty.
pub(super) fn execute_params(
    argv: Vec<String>,
    capsule_root: &Path,
    timeout_ms: u64,
    max_stdout_bytes: u64,
) -> Result<odin_strict_json::Value, ExecutorFault> {
    let params = serde_json::json!({
        "argv": argv,
        "current_dir": capsule_root.display().to_string(),
        "timeout_ms": timeout_ms,
        "term_grace_ms": super::EVAL_TERM_GRACE_MS,
        "max_stdout_bytes": max_stdout_bytes,
        "max_stderr_bytes": EXECUTE_MAX_STDERR_BYTES,
    });
    let bytes = serde_json::to_vec(&params).map_err(|error| ExecutorFault::Rejected {
        detail: format!("execute parameters are not representable: {error}"),
    })?;
    odin_strict_json::decode(&bytes, odin_sidecar_protocol::EFFECT_MAX_REQUEST_BYTES).map_err(
        |error| ExecutorFault::Rejected {
            detail: format!("execute parameters are not strict JSON: {error}"),
        },
    )
}

const EXECUTE_MAX_STDERR_BYTES: u64 = EFFECT_MAX_RETAINED_BYTES as u64;

/// An optional string argument; absent and null are the same.
pub(super) fn optional_text(
    input: &odin_strict_json::Value,
    field: &str,
) -> Result<Option<String>, ExecutorFault> {
    match super::strict_field(input, field) {
        Err(_) | Ok(odin_strict_json::Value::Null) => Ok(None),
        Ok(odin_strict_json::Value::String(text)) => Ok(Some(text.clone())),
        Ok(other) => Err(ExecutorFault::Rejected {
            detail: format!("{field} must be a string, got {}", other.kind()),
        }),
    }
}
