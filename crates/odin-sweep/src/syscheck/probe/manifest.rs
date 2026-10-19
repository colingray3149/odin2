use super::*;

pub(in crate::syscheck) fn require_manifest(
    context: &SystemContext,
    missing_status: CheckStatus,
) -> Result<RuntimeManifest, CheckFailure> {
    let Some(path) = context.runtime_manifest.as_ref() else {
        return Err(match missing_status {
            CheckStatus::Blocked => CheckFailure::blocked(
                "runtime-manifest-unconfigured",
                "the sweep runtime manifest is unconfigured; the check cannot run",
            ),
            _ => CheckFailure::fail(
                "runtime-manifest-unconfigured",
                "the sweep runtime manifest is unconfigured; runtime integrity cannot be established",
            ),
        });
    };
    RuntimeManifest::load(path).map_err(|error| {
        CheckFailure::fail(
            "runtime-manifest-invalid",
            format!("runtime manifest {} rejected: {error}", path.display()),
        )
    })
}

pub(in crate::syscheck) fn require_config(
    context: &SystemContext,
) -> Result<(RuntimeManifest, OdindConfig), CheckFailure> {
    let runtime = require_manifest(context, CheckStatus::Blocked)?;
    let config = runtime.load_config().map_err(|error| {
        CheckFailure::fail(
            "odind-config-invalid",
            format!(
                "packaged odind config {} rejected: {error}",
                runtime.odind_config.path.display()
            ),
        )
    })?;
    Ok((runtime, config))
}

pub(in crate::syscheck) fn command_scratch(
    context: &SystemContext,
    check: &str,
) -> Result<PathBuf, CheckFailure> {
    let directory = context.scratch_root.join(format!("{check}-commands"));
    fs::create_dir_all(&directory).map_err(|error| {
        CheckFailure::fail(
            "scratch-create-failed",
            format!("could not create the {check} command scratch: {error}"),
        )
    })?;
    Ok(directory)
}

/// Streams one regular file through BLAKE3 without reading it into memory.
fn file_blake3(path: &Path) -> io::Result<(u64, String)> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.is_symlink() || !metadata.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "path is a symlink or not a regular file",
        ));
    }
    let mut file = fs::File::open(path)?;
    let mut hasher = blake3::Hasher::new();
    let mut remaining = EXECUTABLE_CAP_BYTES;
    let mut chunk = [0_u8; 65_536];
    loop {
        let read = file.read(&mut chunk)?;
        if read == 0 {
            break;
        }
        if read as u64 > remaining {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "executable exceeds the bounded read cap",
            ));
        }
        hasher.update(&chunk[..read]);
        remaining -= read as u64;
    }
    Ok((metadata.len(), hasher.finalize().to_hex().to_string()))
}

pub(in crate::syscheck) fn verify_manifest_executable(
    runtime: &RuntimeManifest,
    key: &str,
) -> Result<PathBuf, CheckFailure> {
    let reference = runtime.executable(key).map_err(|error| {
        CheckFailure::fail(
            "runtime-manifest-executable-missing",
            format!("runtime manifest key {key:?} is absent: {error}"),
        )
    })?;
    let encoded = reference.digest.strip_prefix("blake3:").ok_or_else(|| {
        CheckFailure::fail(
            "runtime-manifest-digest-malformed",
            format!("runtime manifest key {key:?} digest lacks the blake3: prefix"),
        )
    })?;
    let (_, observed) = file_blake3(&reference.path).map_err(|error| {
        CheckFailure::fail(
            "runtime-manifest-executable-unreadable",
            format!(
                "runtime manifest key {key:?} executable {} is unreadable: {error}",
                reference.path.display()
            ),
        )
    })?;
    if observed != encoded {
        return Err(CheckFailure::fail(
            "runtime-manifest-digest-mismatch",
            format!(
                "runtime manifest key {key:?} executable {} digests to {observed}, manifest declares {encoded}",
                reference.path.display()
            ),
        ));
    }
    Ok(reference.path.clone())
}

pub(in crate::syscheck) fn read_bounded(path: &Path) -> io::Result<Vec<u8>> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.is_symlink() || !metadata.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "path is a symlink or not a regular file",
        ));
    }
    if metadata.len() > INPUT_FILE_CAP_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "input exceeds bounded file size",
        ));
    }
    fs::read(path)
}

/// Resolves an absolute path for one system tool: a runtime-manifest key when
/// the composition pins it, otherwise the standard developer tooling. Absent
/// tools surface as an explicit blocked condition at the call site.
fn tool_path(name: &str, runtime: Option<&RuntimeManifest>) -> Option<PathBuf> {
    if let Some(runtime) = runtime {
        if let Ok(reference) = runtime.executable(name) {
            if reference.path.is_file() {
                return Some(reference.path.clone());
            }
        }
    }
    runner::find_program(name)
}

pub(in crate::syscheck) fn require_tool(
    name: &str,
    runtime: Option<&RuntimeManifest>,
) -> Result<PathBuf, CheckFailure> {
    tool_path(name, runtime).ok_or_else(|| {
        CheckFailure::blocked(
            "tool-unavailable",
            format!("required tool {name:?} is not configured on this system"),
        )
    })
}

pub(in crate::syscheck) fn flake_locked_revision(lock: &JsonValue, input: &str) -> Option<String> {
    flake_locked_field(lock, input, "rev")
}

pub(in crate::syscheck) fn flake_locked_field(
    lock: &JsonValue,
    input: &str,
    field: &str,
) -> Option<String> {
    let nodes = lock.get("nodes")?.as_object()?;
    let node_name = nodes
        .get("root")?
        .get("inputs")?
        .as_object()?
        .get(input)?
        .as_str()?;
    nodes
        .get(node_name)?
        .get("locked")?
        .get(field)?
        .as_str()
        .map(str::to_owned)
}

pub(in crate::syscheck) fn nix_store_root(path: &Path) -> Option<PathBuf> {
    path.ancestors()
        .find(|candidate| candidate.parent() == Some(Path::new("/nix/store")))
        .map(Path::to_path_buf)
}

/// Retained package-build identity path for one first-party Cargo package.
///
/// The identity file is namespaced per Cargo package under `share/odin` so any
/// set of first-party packages can coinstall into one profile without a
/// metadata path collision.
pub(in crate::syscheck) fn package_build_metadata_path(
    store_root: &Path,
    cargo_package: &str,
) -> PathBuf {
    store_root
        .join("share/odin")
        .join(cargo_package)
        .join("package-build.json")
}

/// Verifies one digest-qualified artifact is a regular file inside its
/// declared package store root with exactly the declared digest.
pub(in crate::syscheck) fn verify_store_artifact(
    path: &Path,
    digest: &str,
    store_root: &Path,
    label: &str,
) -> Result<(), CheckFailure> {
    let fail = |summary: String| CheckFailure::fail("package-artifact-mismatch", summary);
    let Some(encoded) = digest.strip_prefix("blake3:") else {
        return Err(fail(format!("{label} has a malformed digest")));
    };
    if !lower_hex(encoded, 64) {
        return Err(fail(format!("{label} has a malformed digest")));
    }
    let file_type = fs::symlink_metadata(path)
        .map_err(|error| fail(format!("{label} {} is unreadable: {error}", path.display())))?
        .file_type();
    if file_type.is_symlink() || !file_type.is_file() {
        return Err(fail(format!(
            "{label} {} is a symlink or not a regular file",
            path.display()
        )));
    }
    let canonical = fs::canonicalize(path).map_err(|error| {
        fail(format!(
            "{label} {} could not be canonicalized: {error}",
            path.display()
        ))
    })?;
    if canonical != path || nix_store_root(&canonical).as_deref() != Some(store_root) {
        return Err(fail(format!(
            "{label} {} is not inside its declared package store root",
            path.display()
        )));
    }
    let (_, observed) = file_blake3(path)
        .map_err(|error| fail(format!("{label} {} is unreadable: {error}", path.display())))?;
    if observed != encoded {
        return Err(fail(format!(
            "{label} {} digests to {observed}, metadata declares {encoded}",
            path.display()
        )));
    }
    Ok(())
}
