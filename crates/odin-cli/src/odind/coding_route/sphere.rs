//! Capsule-confined builds and artifact analysis over the declared project sphere.

use std::path::{Path, PathBuf};

use odin_domain::Scope;
use odin_hermes::runtime::coding::CodingRoute;
use serde_json::{json, Value};

use odin_cli::live_authority::{Capture, Retention};

use super::{tail, DaemonCodingRoute, Owned};

/// A build or check: its stdout (paths, JSON) whole, the log's tail.
pub(super) const BUILD_CAPTURE: Capture = Capture {
    stdout: Retention::Complete,
    stderr: Retention::Tail,
};

/// `nix log`: the stored log arrives on stdout; keep its tail.
pub(super) const STORED_LOG_CAPTURE: Capture = Capture {
    stdout: Retention::Tail,
    stderr: Retention::Complete,
};
impl DaemonCodingRoute {
    /// The project's declared sphere, when this dispatch's project has one.
    fn sphere(&self, scope: &Scope) -> Result<Option<odin_omp::process::SphereProjection>, String> {
        let Some(project) = &scope.project else {
            return Ok(None);
        };
        let Some(registry) = &self.registry else {
            return Ok(None);
        };
        let snapshot = registry.current();
        odin_omp::process::project_sphere(snapshot.objects.iter(), project)
            .map(odin_omp::process::SphereProjection::from_sphere)
            .transpose()
    }

    /// Runs one Nix argv inside the lane capsule. Builds go to the host
    /// daemon and run in its build sandbox; the client sees only the
    /// capsule, its sphere and the read-only host store.
    pub(super) fn nix_in_capsule(
        &self,
        owned: &Owned<'_>,
        capsule: &Path,
        nix_argv: Vec<String>,
        environment: Vec<(String, String)>,
        capture: Capture,
    ) -> Result<std::process::Output, String> {
        let nix = self
            .manifest
            .as_ref()
            .ok_or("this build has no runtime manifest")?
            .executable("nix")
            .map_err(|error| format!("runtime manifest nix: {error}"))?
            .path
            .clone();
        let mut command = vec![nix.display().to_string()];
        command.extend(nix_argv);
        let sphere = self.sphere(owned.scope())?;
        let projection = sphere.unwrap_or_else(|| odin_omp::process::SphereProjection {
            data_roots: Vec::new(),
            scratch: capsule.to_path_buf(),
            devices: Vec::new(),
            endpoints: Vec::new(),
        });
        let argv =
            odin_omp::process::capsule_nix_argv(capsule, &projection, &self.tool_path(), &command)?;
        owned.bwrap_captured(capsule, argv, environment, capture)
    }

    /// Directories of the declared sandbox tools (cargo, bash, python3, …).
    /// A missing key is skipped: a test manifest need not pin every one.
    fn tool_path(&self) -> Vec<PathBuf> {
        const KEYS: [&str; 12] = [
            "cargo",
            "rustc",
            "rustdoc",
            "cc",
            "pkg-config",
            "bash",
            "jq",
            "b3sum",
            "git",
            "nix",
            "bun",
            "python3",
        ];
        let Some(manifest) = &self.manifest else {
            return Vec::new();
        };
        let mut dirs = Vec::new();
        for key in KEYS {
            let Ok(executable) = manifest.executable(key) else {
                continue;
            };
            if let Some(dir) = executable.path.parent() {
                if !dirs.iter().any(|have| have == dir) {
                    dirs.push(dir.to_path_buf());
                }
            }
        }
        dirs
    }

    fn capsule_command(
        &self,
        owned: &Owned<'_>,
        capsule: &Path,
        readonly: &[PathBuf],
        command: Vec<String>,
    ) -> Result<std::process::Output, String> {
        let sphere = self.sphere(owned.scope())?;
        let projection = sphere.unwrap_or_else(|| odin_omp::process::SphereProjection {
            data_roots: Vec::new(),
            scratch: capsule.to_path_buf(),
            devices: Vec::new(),
            endpoints: Vec::new(),
        });
        let argv = odin_omp::process::capsule_command_argv(
            capsule,
            &projection,
            readonly,
            &self.tool_path(),
            &command,
        )?;
        owned.bwrap(capsule, argv, Vec::new())
    }

    /// Stages one verified artifact as a read-only file at the capsule's
    /// fixed artifact path, without exposing its host directory.
    pub(super) fn analyze_in_capsule(
        &self,
        owned: &Owned<'_>,
        artifact_id: &str,
        program: Vec<String>,
    ) -> Result<Value, String> {
        if program.is_empty() || program.iter().any(|arg| arg.contains('\0')) {
            return Err("analysis requires an executable and NUL-free arguments".to_owned());
        }
        let (mut file, media_type) = self.artifact_file(owned.scope(), artifact_id)?;
        let capsule = self.workspace(owned.scope())?;
        let mut staged = tempfile::NamedTempFile::new_in(&self.state_root)
            .map_err(|error| format!("stage {artifact_id}: {error}"))?;
        std::io::copy(&mut file, staged.as_file_mut())
            .map_err(|error| format!("stage {artifact_id}: {error}"))?;
        let command = program
            .into_iter()
            .map(|arg| arg.replace("{artifact}", odin_omp::process::STAGED_ARTIFACT))
            .collect();
        let output =
            self.capsule_command(owned, &capsule, &[staged.path().to_path_buf()], command)?;
        let text = |bytes: &[u8]| {
            let lossy = String::from_utf8_lossy(bytes);
            tail(&lossy)
        };
        Ok(json!({
            "ok": output.status.success(),
            "mediaType": media_type,
            "stdout": text(&output.stdout),
            "stderr": text(&output.stderr),
        }))
    }
}
