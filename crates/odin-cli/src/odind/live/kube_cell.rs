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
    snapshot_handle: &Arc<odin_registry::SnapshotHandle>,
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
            Some(KubeRuntimeCell::new_published(
                CellInputs {
                    config: odin_kube::config::KubeConfig {
                        kubeconfig: kube.kubeconfig.clone(),
                        cluster: kube.cluster.clone(),
                        namespace: kube.namespace.clone(),
                        allowed_nodes: snapshot
                            .objects
                            .iter()
                            .filter_map(|object| match &object.config {
                                ObjectConfig::Node(node)
                                    if node.enabled && node.allow_workloads =>
                                {
                                    Some(object.id.clone())
                                }
                                _ => None,
                            })
                            .collect(),
                        node_data_roots: snapshot
                            .objects
                            .iter()
                            .filter_map(|object| match &object.config {
                                ObjectConfig::Node(node)
                                    if node.enabled && node.allow_workloads =>
                                {
                                    Some((object.id.clone(), node.data_roots.clone()))
                                }
                                _ => None,
                            })
                            .collect(),
                        request_timeout: StdDuration::from_secs(kube.request_timeout_seconds.get()),
                        teardown_timeout: StdDuration::from_secs(
                            kube.teardown_timeout_seconds.get(),
                        ),
                        vpn_transport: kube.vpn_transport.as_ref().map(|transport| {
                            odin_kube::VpnTransportBinding {
                                endpoint: transport.endpoint,
                                port: transport.port,
                                dns: transport.dns,
                                launcher: transport.launcher.clone(),
                                resolver: transport.resolver.clone(),
                                forwarded: transport.forwarded,
                            }
                        }),
                    },
                    ledger: Arc::clone(bridge_ledger),
                    stops,
                    artifact_root: huginn_root.join("artifacts"),
                    snapshot: Arc::clone(snapshot),
                    config_revision: config.revision,
                    launch_binding,
                    workload_identity,
                },
                Arc::clone(snapshot_handle),
            ))
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
    let hex = Digest::hash(&bytes).hex();
    let storage_path = format!("{}/{}", &hex[..2], hex);
    let absolute = artifact_root.join(&storage_path);
    // An existing file that is not exactly these bytes (a crash left it short) is replaced.
    if std::fs::read(&absolute).map_or(true, |stored| stored != bytes) {
        std::fs::create_dir_all(absolute.parent().expect("content-addressed parent")).map_err(
            |error| format!("could not create the identity artifact directory: {error}"),
        )?;
        odin_cli::authority_provision::write_private_atomic(&absolute, &bytes)
            .map_err(|error| format!("could not pin the image identity bytes: {error}"))?;
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&absolute, std::fs::Permissions::from_mode(0o444)).map_err(
            |error| format!("could not make the image identity bytes read-only: {error}"),
        )?;
    }
    let registration = {
        let guard = ledger
            .lock()
            .map_err(|error| format!("artifact ledger lock: {error}"))?;
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

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt as _;

    use super::*;

    /// A strict workload image identity: the declared shape, with fixed digests.
    fn identity_bytes() -> Vec<u8> {
        let tool = |name: &str| {
            serde_json::json!({
                "in_image": format!("/odin/bin/{name}"),
                "store": format!("/nix/store/{name}"),
                "blake3": format!("blake3:{}", "a".repeat(64)),
            })
        };
        serde_json::json!({
            "schema": "odin.workload-image-identity.v1",
            "reference": format!("localhost/odin-workload@sha256:{}", "1".repeat(64)),
            "image_name": "localhost/odin-workload",
            "tag": "1",
            "manifest_digest": format!("sha256:{}", "1".repeat(64)),
            "config_digest": format!("sha256:{}", "2".repeat(64)),
            "import_archive": "odin-workload-image-oci.tar",
            "omp_source_revision": "0".repeat(40),
            "archive_sha256": "3".repeat(64),
            "source_revision": "4".repeat(32),
            "tools": {
                "omp": tool("omp"), "odin": tool("odin"), "odind": tool("odind"),
                "node": tool("node"), "chromium": tool("chromium"), "xvfb": tool("Xvfb"),
                "extension": tool("extension"),
            },
            "module_roots": {
                "playwright": {"in_image": "/odin/lib/playwright-core", "store": "/odin/lib/playwright-core"}
            },
            "mount_points": ["/state", "/export"],
            "config": {
                "user": "65534:65534", "working_dir": "/state",
                "entrypoint": null, "command": null,
                "env": ["PATH=/odin/bin:/bin", "HOME=/state"],
            },
        })
        .to_string()
        .into_bytes()
    }

    #[test]
    fn the_identity_is_pinned_read_only_at_its_content_address_and_a_short_copy_is_repaired() {
        let root = tempfile::tempdir().unwrap();
        let declared = root.path().join("identity.json");
        let bytes = identity_bytes();
        std::fs::write(&declared, &bytes).unwrap();
        let artifacts = root.path().join("artifacts");
        let ledger = Arc::new(Mutex::new(Ledger::open_in_memory().unwrap()));
        let pin =
            || pin_image_extension_identity(&declared, None, None, Arc::clone(&ledger), &artifacts);

        let first = pin().expect("a valid identity pins");
        let hex = Digest::hash(&bytes).hex();
        let stored = artifacts.join(&hex[..2]).join(&hex);
        assert_eq!(std::fs::read(&stored).unwrap(), bytes);
        assert_eq!(
            std::fs::metadata(&stored).unwrap().permissions().mode() & 0o777,
            0o444
        );
        assert_eq!(
            pin().expect("pinning again reuses it").artifact,
            first.artifact
        );

        // A crash between create and write leaves a short file, which must not stay the pin.
        std::fs::remove_file(&stored).unwrap();
        std::fs::write(&stored, b"").unwrap();
        pin().expect("a short copy is replaced");
        assert_eq!(std::fs::read(&stored).unwrap(), bytes);

        std::fs::write(&declared, b"{}").unwrap();
        let refused = pin().unwrap_err();
        assert!(refused.contains("identity.json"), "{refused}");
    }
}
