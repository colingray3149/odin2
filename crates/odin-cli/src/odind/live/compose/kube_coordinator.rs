//! Compose the daemon's workload launch coordinator.

use std::collections::BTreeSet;
use std::path::PathBuf;
use std::sync::Arc;

use odin_domain::SeatId;
use odin_huginn::{OdindConfig, RuntimeManifest};
use odin_registry::SnapshotHandle;

use super::super::offload::Offload;
use crate::kube::KubeRuntimeCell;
use crate::kube_runtime::KubeCommandCoordinator;

pub(super) struct LaunchEnvironment<'a> {
    pub(super) models_file: Option<PathBuf>,
    pub(super) conversation_seats: &'a BTreeSet<SeatId>,
    pub(super) local_node: &'a str,
}

pub(super) fn compose(
    config: &OdindConfig,
    manifest: &RuntimeManifest,
    snapshot_handle: &Arc<SnapshotHandle>,
    kube_cell: &Option<Arc<KubeRuntimeCell>>,
    offload: &Option<Arc<Offload>>,
    launch: LaunchEnvironment<'_>,
) -> Result<Arc<KubeCommandCoordinator>, String> {
    let LaunchEnvironment {
        models_file,
        conversation_seats,
        local_node,
    } = launch;
    let mut coordinator = KubeCommandCoordinator::new(kube_cell.clone());
    let stage_transport = Arc::new(crate::stage_transport::StageTransport::new(
        Arc::clone(snapshot_handle),
        crate::claude_host_transport::ClaudeHostTransport::from_config(
            config,
            manifest,
            "stage-transport-authority",
            "stage-transport",
        )?,
    ));
    coordinator = coordinator.with_stage_verifier(Arc::new(move |profile, node, bytes| {
        stage_transport.verify(profile, node, bytes)
    }));
    if let Some(offload) = offload {
        if let Some(cell) = kube_cell {
            cell.set_offload(Arc::clone(offload));
        }
        coordinator = coordinator.with_offload(Arc::clone(offload));
    }
    Ok(Arc::new(
        coordinator
            .with_models_path(models_file)
            .with_overseers(conversation_seats.clone())
            .with_launch_queue(config.paths.state_root.join("launch-queue"))
            .with_vram_probe({
                let registry = Arc::clone(snapshot_handle);
                let local_node = local_node.to_owned();
                let ssh = manifest
                    .executable("ssh")
                    .map_err(|error| format!("runtime manifest ssh: {error}"))?
                    .path
                    .clone();
                Arc::new(move |node: String| {
                    let registry = Arc::clone(&registry);
                    let local_node = local_node.clone();
                    let ssh = ssh.clone();
                    Box::pin(async move {
                        crate::compute_route::desktop_free_vram(&registry, &local_node, &ssh, &node)
                            .await
                    })
                })
            }),
    ))
}
