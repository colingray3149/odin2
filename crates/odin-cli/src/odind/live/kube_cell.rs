//! Kube runtime-cell composition: the lazily-connected k3s cell assembled
//! from the strict `[kube]` config, the pinned published snapshot's
//! workload-allowed nodes, and the declared delegation launch binding.

use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration as StdDuration;

use odin_domain::{Digest, WorkloadImageIdentity};
use odin_huginn::{OdindConfig, RuntimeManifest};
use odin_ledger::artifact::{ArtifactRegistration, RetentionClass};
use odin_ledger::{Ledger, LedgerError};
use odin_registry::{ObjectConfig, Snapshot};

use crate::composition::open_stop_authority;
use crate::kube::{CellInputs, KubeLaunchBinding, KubeRuntimeCell, WorkloadExtensionIdentity};

/// Real k3s execution fabric. `config.kube` absent means typed
/// unavailability: every other surface serves, kube commands fail with a
/// typed Unavailable, and no simulated cluster exists. A configured
/// cluster connects lazily and reconnects on demand: if the API server
/// is unreachable at startup the daemon stays up and keeps retrying on
/// every use and pump tick until the human starts k3s — the configured
/// surface is never permanently disabled. Local config-level faults
/// (unreadable kubeconfig path shape, rejected stop authority) refuse
/// startup. Destructive pod/job deletion never leaves the reconciler:
/// it routes through the sole StopAuthority backend.
pub(super) fn compose(
    config: &OdindConfig,
    manifest: &RuntimeManifest,
    snapshot: &Arc<Snapshot>,
    bridge_ledger: &Arc<Mutex<Ledger>>,
    huginn_root: &Path,
) -> Result<Option<Arc<KubeRuntimeCell>>, String> {
    Ok(match &config.kube {
        None => None,
        Some(kube) => {
            // The declared image identity is the operator-owned trust root:
            // read and fully validated once here, then pinned as a
            // content-addressed ledger artifact. Admission re-reads it only
            // through that digest-verified artifact, never from this path.
            let workload_identity = pin_image_extension_identity(
                &kube.image_identity,
                kube.export_root.as_deref(),
                kube.agent_lane.as_deref(),
                Arc::clone(bridge_ledger),
                &huginn_root.join("artifacts"),
            )?;
            let stops = open_stop_authority(
                manifest,
                &config.worker_bus,
                &config.paths.state_root.join("kube-authority"),
                "kube",
            )?;
            // Real composition context for Job labels: the registry-declared
            // delegation worker model, bound to the pinned published snapshot
            // revision. No configured delegation keeps kube create refused
            // typed.
            let launch_binding = config
                .delegation
                .as_ref()
                .map(|delegation| KubeLaunchBinding {
                    model: delegation.model.clone(),
                    budget_policy_digest: odin_domain::Digest::hash(
                        format!("{}:{}", snapshot.revision, snapshot.hash).as_bytes(),
                    ),
                });
            Some(KubeRuntimeCell::new(CellInputs {
                config: odin_kube::config::KubeConfig {
                    kubeconfig: kube.kubeconfig.clone(),
                    cluster: kube.cluster.clone(),
                    namespace: kube.namespace.clone(),
                    allowed_nodes: snapshot
                        .objects
                        .iter()
                        .filter_map(|object| match &object.config {
                            ObjectConfig::Node(node) if node.enabled && node.allow_workloads => {
                                Some(object.id.clone())
                            }
                            _ => None,
                        })
                        .collect(),
                    request_timeout: StdDuration::from_secs(kube.request_timeout_seconds.get()),
                    teardown_timeout: StdDuration::from_secs(kube.teardown_timeout_seconds.get()),
                },
                ledger: Arc::clone(bridge_ledger),
                stops,
                artifact_root: huginn_root.join("artifacts"),
                snapshot: Arc::clone(snapshot),
                config_revision: config.revision,
                launch_binding,
                workload_identity,
            }))
        }
    })
}

/// Reads the operator-declared workload image identity, validates it
/// strictly, writes its exact bytes once at the content-addressed store
/// path, and registers them as a Pinned ledger artifact. Returns the typed
/// identity bound to that artifact id: the single anchor every later
/// admission re-reads, so a pruned or drifted build output can never
/// silently become launch truth.
fn pin_image_extension_identity(
    declared: &Path,
    export_root: Option<&Path>,
    agent_lane: Option<&str>,
    ledger: Arc<Mutex<Ledger>>,
    artifact_root: &Path,
) -> Result<WorkloadExtensionIdentity, String> {
    let bytes = std::fs::read(declared).map_err(|error| {
        format!(
            "could not read the declared kube.image_identity {}: {error}",
            declared.display()
        )
    })?;
    let identity = WorkloadImageIdentity::parse(&bytes).map_err(|error| {
        format!(
            "the declared kube.image_identity {} is not a valid workload image identity: {error}",
            declared.display()
        )
    })?;
    let hex = Digest::hash(&bytes)
        .to_string()
        .strip_prefix("blake3:")
        .expect("digest display carries the blake3 prefix")
        .to_owned();
    let storage_path = format!("{}/{}", &hex[..2], hex);
    let absolute = artifact_root.join(&storage_path);
    if !absolute.exists() {
        std::fs::create_dir_all(absolute.parent().expect("content-addressed parent")).map_err(
            |error| format!("could not create the identity artifact directory: {error}"),
        )?;
        use std::io::Write as _;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&absolute)
            .map_err(|error| format!("could not pin the image identity bytes: {error}"))?;
        file.write_all(&bytes)
            .map_err(|error| format!("could not write the image identity bytes: {error}"))?;
        file.sync_all()
            .map_err(|error| format!("could not sync the image identity bytes: {error}"))?;
        drop(file);
        let mut permissions = std::fs::metadata(&absolute)
            .map_err(|error| format!("could not stat the image identity bytes: {error}"))?
            .permissions();
        use std::os::unix::fs::PermissionsExt as _;
        permissions.set_mode(0o444);
        std::fs::set_permissions(&absolute, permissions).map_err(|error| {
            format!("could not make the image identity bytes read-only: {error}")
        })?;
    }
    let registration = {
        let guard = ledger
            .lock()
            .map_err(|_| "artifact ledger lock poisoned".to_owned())?;
        guard
            .register_artifact(ArtifactRegistration {
                bytes: &bytes,
                media_type: "application/json",
                storage_path: &storage_path,
                retention: RetentionClass::Pinned,
                created_at: time::OffsetDateTime::now_utc(),
            })
            .map_err(|error: LedgerError| {
                format!("could not register the image identity artifact: {error}")
            })?
    };
    Ok(WorkloadExtensionIdentity {
        artifact: registration.artifact_id,
        deployment: crate::kube::WorkloadDeploymentFacts::of(&identity, export_root, agent_lane),
    })
}
