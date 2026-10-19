//! Declared composition and launch wiring: the extension-policy binding,
//! the runtime manifest identity checks, every supervised worker launch
//! and stop authority, and the child-environment, context-read, and
//! renderer composition helpers the serving assembly consumes.

use std::collections::BTreeMap;
use std::env;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration as StdDuration;

use odin_domain::extension_policy::{
    ExtensionArtifactPolicy, ExtensionPolicyBinding, ExtensionPolicyV1, SidecarOperationalPolicy,
    EXTENSION_POLICY_SCHEMA, EXTENSION_POLICY_VERSION,
};
use odin_domain::huginn as live;
use odin_domain::ProjectId;
use odin_huginn::{OdindConfig, RuntimeManifest};
use odin_kernel::{ParentAuthorityClient, StopAuthority};
use odin_ledger::Ledger;
use odin_omp::process::OmpWorkerLaunch;
use odin_process::{
    BusAddress, RegisteredServiceBinding, ScopeLifetime, ScopeLimits, WorkerChannel,
};
use odin_registry::Snapshot;
use odin_types::CorrelationId;

/// Binds ExtensionPolicyV1 to the exact pinned snapshot and config revisions
/// before any OMP child exists. The path is content-addressed and versioned;
/// an existing file is verified byte-for-byte, never deleted or rewritten.
pub(super) fn produce_extension_policy(
    config: &OdindConfig,
    snapshot: &Snapshot,
) -> Result<ExtensionPolicyBinding, String> {
    let extension = config
        .executables
        .extension
        .canonicalize()
        .map_err(|error| format!("could not resolve extension path: {error}"))?;
    if !extension.is_file() {
        return Err(format!(
            "extension entrypoint {} is missing; refusing to bind a policy for it",
            extension.display()
        ));
    }
    let extension_bytes = std::fs::read(&extension)
        .map_err(|error| format!("could not read extension entrypoint: {error}"))?;
    let policy = ExtensionPolicyV1 {
        schema: EXTENSION_POLICY_SCHEMA.to_owned(),
        version: EXTENSION_POLICY_VERSION,
        snapshot_revision: snapshot.revision,
        config_revision: config.revision,
        extension: ExtensionArtifactPolicy {
            path: extension.clone(),
            digest: ExtensionPolicyV1::digest_bytes(&extension_bytes),
        },
        sidecar: SidecarOperationalPolicy::compiled_default(),
    };
    policy
        .validate()
        .map_err(|error| format!("resolved extension policy is invalid: {error}"))?;
    let bytes = serde_json::to_vec(&policy)
        .map_err(|error| format!("could not encode extension policy: {error}"))?;
    let digest = ExtensionPolicyV1::digest_bytes(&bytes);
    let digest_hex = digest
        .strip_prefix("blake3:")
        .ok_or_else(|| "extension policy digest is not blake3-prefixed".to_owned())?;
    let directory = config
        .paths
        .state_root
        .join("huginn")
        .join("extension-policy");
    std::fs::create_dir_all(&directory)
        .map_err(|error| format!("could not create extension policy directory: {error}"))?;
    let path = directory.join(format!(
        "r{}-c{}-{digest_hex}.json",
        snapshot.revision, config.revision
    ));
    let binding = if path.exists() {
        let binding = ExtensionPolicyBinding::new(path, digest);
        let loaded = binding
            .load()
            .map_err(|error| format!("existing extension policy failed verification: {error}"))?;
        if loaded.snapshot_revision != snapshot.revision {
            return Err(
                "existing extension policy is stale against the pinned registry snapshot"
                    .to_owned(),
            );
        }
        if loaded.config_revision != config.revision {
            return Err(
                "existing extension policy does not match the controller config revision"
                    .to_owned(),
            );
        }
        binding
    } else {
        ExtensionPolicyV1::publish(&path, &policy)
            .map_err(|error| format!("could not publish the extension policy: {error}"))?
    };
    let loaded = binding
        .load()
        .map_err(|error| format!("extension policy failed verification: {error}"))?;
    if loaded.snapshot_revision != snapshot.revision {
        return Err("extension policy is stale against the pinned registry snapshot".to_owned());
    }
    if loaded.config_revision != config.revision {
        return Err("extension policy does not match the controller config revision".to_owned());
    }
    loaded
        .verify_extension_artifact(&extension)
        .map_err(|error| format!("extension artifact verification failed: {error}"))?;
    Ok(binding)
}

pub(super) struct RuntimeWorkers {
    pub(super) omp: OmpWorkerLaunch,
    pub(super) zellij: OmpWorkerLaunch,
}

pub(super) fn load_runtime_manifest() -> Result<RuntimeManifest, String> {
    let path = env::var_os("ODIN_RUNTIME_MANIFEST")
        .ok_or_else(|| "ODIN_RUNTIME_MANIFEST is required for odind Huginn workers".to_owned())?;
    RuntimeManifest::load(path).map_err(|error| format!("runtime manifest rejected: {error}"))
}

pub(super) fn registered_runtime_binding(
    manifest: &RuntimeManifest,
    key: &str,
    expected_executable: &Path,
) -> Result<RegisteredServiceBinding, String> {
    let executable = manifest
        .executable(key)
        .map_err(|error| format!("runtime manifest {key}: {error}"))?;
    if executable.path != expected_executable {
        return Err(format!(
            "runtime manifest {key} executable {} does not match configured executable {}",
            executable.path.display(),
            expected_executable.display()
        ));
    }
    let digest = executable
        .digest
        .strip_prefix("blake3:")
        .ok_or_else(|| format!("runtime manifest {key} digest lacks blake3 prefix"))?;
    RegisteredServiceBinding::new(executable.path.clone(), digest.to_owned())
        .map_err(|error| format!("runtime manifest {key} binding rejected: {error}"))
}

/// Verifies a configured executable is exactly the manifest identity with
/// that key. The composition binds the isolated payload paths (the browser
/// scanner and the optional virtual-display Xvfb server), so a config value
/// that drifted from the manifest is rejected instead of launched.
pub(super) fn bound_manifest_identity(
    manifest: &RuntimeManifest,
    key: &str,
    expected_executable: &Path,
) -> Result<(), String> {
    let executable = manifest
        .executable(key)
        .map_err(|error| format!("runtime manifest {key}: {error}"))?;
    if executable.path != expected_executable {
        return Err(format!(
            "runtime manifest {key} executable {} does not match configured executable {}",
            executable.path.display(),
            expected_executable.display()
        ));
    }
    Ok(())
}

fn runtime_worker_channel(
    manifest: &RuntimeManifest,
    worker_bus: &str,
) -> Result<WorkerChannel, String> {
    let bus =
        BusAddress::parse(worker_bus).map_err(|error| format!("worker bus rejected: {error}"))?;
    let bootstrap = manifest
        .executable("worker_bootstrap")
        .map_err(|error| format!("runtime manifest worker_bootstrap: {error}"))?
        .path
        .clone();
    let unshare = manifest
        .executable("unshare")
        .map_err(|error| format!("runtime manifest unshare: {error}"))?
        .path
        .clone();
    WorkerChannel::new(bus, bootstrap, unshare).map_err(|error| error.to_string())
}

pub(super) fn open_stop_authority(
    manifest: &RuntimeManifest,
    worker_bus: &str,
    authority_root: &Path,
    role: &str,
) -> Result<Arc<StopAuthority>, String> {
    let parent = ParentAuthorityClient::from_env()
        .map_err(|error| format!("{role} parent authority rejected: {error}"))?;
    let authority = if parent.is_remote() {
        let store_path = parent
            .expected_store_path()
            .map_err(|error| format!("{role} parent authority store rejected: {error}"))?;
        let ledger = Ledger::open(&store_path)
            .map_err(|error| format!("could not open {role} scoped stop ledger: {error}"))?;
        StopAuthority::from_parent(Arc::new(Mutex::new(ledger)), parent)
            .map_err(|error| format!("could not open {role} scoped authority: {error}"))?
    } else {
        std::fs::create_dir_all(authority_root)
            .map_err(|error| format!("could not create {role} authority root: {error}"))?;
        std::fs::set_permissions(authority_root, std::fs::Permissions::from_mode(0o700))
            .map_err(|error| format!("could not protect {role} authority root: {error}"))?;
        let ledger = Ledger::open(authority_root.join("ledger.sqlite3"))
            .map_err(|error| format!("could not open {role} stop ledger: {error}"))?;
        let channel = runtime_worker_channel(manifest, worker_bus)?;
        StopAuthority::new(Arc::new(Mutex::new(ledger)), channel)
    };
    Ok(Arc::new(authority))
}

pub(super) fn runtime_workers(
    config: &OdindConfig,
    manifest: &RuntimeManifest,
) -> Result<RuntimeWorkers, String> {
    let authority = open_stop_authority(
        manifest,
        &config.worker_bus,
        &config.paths.state_root.join("worker-authority"),
        "Huginn worker",
    )?;
    let correlation_seed = odin_process::mint_worker_id().map_err(|error| error.to_string())?;
    let correlation =
        CorrelationId::new(correlation_seed.as_str()).map_err(|error| error.to_string())?;
    let make_worker =
        |key: &str, executable: &Path, wp_id: &str, limits: ScopeLimits| -> Result<_, String> {
            OmpWorkerLaunch::new(
                Arc::clone(&authority),
                correlation.clone(),
                "odind",
                wp_id,
                1,
                registered_runtime_binding(manifest, key, executable)?,
                limits,
            )
            .map_err(|error| format!("{key} worker launch binding rejected: {error}"))
        };
    Ok(RuntimeWorkers {
        omp: make_worker(
            "omp",
            &config.executables.omp_bin,
            "omp",
            ScopeLimits {
                lifetime: ScopeLifetime::OwnerUnit,
                timeout_stop: StdDuration::from_secs(5),
                ..ScopeLimits::default()
            },
        )?,
        zellij: make_worker(
            "zellij",
            &config.executables.zellij_bin,
            "zellij",
            ScopeLimits {
                lifetime: ScopeLifetime::Bounded(StdDuration::from_secs(30)),
                timeout_stop: StdDuration::from_secs(5),
                ..ScopeLimits::default()
            },
        )?,
    })
}

pub(super) fn child_environment() -> Vec<(String, String)> {
    const PASSTHROUGH: [&str; 12] = [
        "HOME",
        "PATH",
        "TERM",
        "LANG",
        "LC_ALL",
        "USER",
        "LOGNAME",
        "XDG_CONFIG_HOME",
        "XDG_DATA_HOME",
        "XDG_CACHE_HOME",
        "XDG_STATE_HOME",
        "TMPDIR",
    ];
    // The governed OMP overlay pins the native eval backends off; the
    // interpreter re-enable channels (PI_PYTHON_*/PI_NODE_* and similar)
    // are deliberately absent from this allowlist and must never be added.
    PASSTHROUGH
        .iter()
        .filter_map(|name| {
            env::var_os(name)
                .and_then(|value| value.into_string().ok())
                .map(|value| ((*name).to_owned(), value))
        })
        .collect()
}

pub(super) fn context_read_runtime_config(
    config: &OdindConfig,
    project_roots: &BTreeMap<ProjectId, PathBuf>,
    max_bytes: u64,
) -> Result<Option<odin_omp::live::runtime::ContextReadRuntimeConfig>, String> {
    let Some(configured) = &config.paths.operator_context_root else {
        return Ok(None);
    };
    let root = configured.canonicalize().map_err(|error| {
        format!(
            "could not resolve operator context root {}: {error}",
            configured.display()
        )
    })?;
    if !root.is_dir() {
        return Err(format!(
            "operator context root {} is not a directory",
            root.display()
        ));
    }
    if env::var_os("HOME")
        .map(PathBuf::from)
        .and_then(|home| home.canonicalize().ok())
        .is_some_and(|home| home == root)
    {
        return Err("operator context root must not be the whole home directory".to_owned());
    }
    let mut excluded = vec![
        config.paths.state_root.clone(),
        config.paths.authority_token_root.clone(),
        config.paths.authority_verification_key_file.clone(),
    ];
    excluded.extend(project_roots.values().cloned());
    for candidate in excluded {
        let resolved = candidate.canonicalize().unwrap_or(candidate);
        if root == resolved || root.starts_with(&resolved) || resolved.starts_with(&root) {
            return Err(format!(
                "operator context root {} overlaps protected runtime/project root {}",
                root.display(),
                resolved.display()
            ));
        }
    }
    Ok(Some(odin_omp::live::runtime::ContextReadRuntimeConfig {
        root,
        max_bytes,
    }))
}

pub(super) fn renderer_registry() -> Result<odin_huginn::renders::RendererRegistry, String> {
    use odin_huginn::renders::{
        CopyRenderer, RendererDescriptor, RendererRegistry, SvgSanitizingRenderer,
    };

    let registry = RendererRegistry::new();
    registry
        .register(
            RendererDescriptor {
                renderer: live::RendererId::parse("builtin-png")
                    .map_err(|error| error.to_string())?,
                version: "1".to_owned(),
                accepted_media_types: vec!["image/png".to_owned()],
                output_kind: live::RenderKind::RasterImage,
                output_media_type: "image/png".to_owned(),
            },
            Arc::new(CopyRenderer),
        )
        .map_err(|error| error.to_string())?;
    registry
        .register(
            RendererDescriptor {
                renderer: live::RendererId::parse("builtin-pdf")
                    .map_err(|error| error.to_string())?,
                version: "1".to_owned(),
                accepted_media_types: vec!["application/pdf".to_owned()],
                output_kind: live::RenderKind::Pdf,
                output_media_type: "application/pdf".to_owned(),
            },
            Arc::new(CopyRenderer),
        )
        .map_err(|error| error.to_string())?;
    registry
        .register(
            RendererDescriptor {
                renderer: live::RendererId::parse("builtin-svg-sanitizer")
                    .map_err(|error| error.to_string())?,
                version: "1".to_owned(),
                accepted_media_types: vec!["image/svg+xml".to_owned()],
                output_kind: live::RenderKind::SanitizedSvg,
                output_media_type: "image/svg+xml".to_owned(),
            },
            Arc::new(SvgSanitizingRenderer),
        )
        .map_err(|error| error.to_string())?;
    Ok(registry)
}

#[cfg(test)]
#[path = "tests/composition.rs"]
mod tests;
