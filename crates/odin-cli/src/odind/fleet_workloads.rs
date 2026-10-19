//! Drain pods to online nodes matching their declared placement, carrying state.
//! Pods without another eligible node are paused on their volumes and recorded
//! for restore. Moves use kernel lifecycle operations and appear in Huginn.

use std::path::{Path, PathBuf};

use odin_domain::huginn::{KubeOperationKind, KubeResourceOwnership, KubeWorkloadState};
use odin_domain::{Digest, RunId};
use odin_huginn::kube::KubeControl;
use odin_kube::{JobAction, KubeClient};

fn record_path(state_root: &Path, host: &str) -> PathBuf {
    state_root.join("fleet-drain").join(format!("{host}.json"))
}

async fn operate(
    control: &KubeControl,
    run: &RunId,
    kind: KubeOperationKind,
    target_node: Option<String>,
    purpose: &str,
) -> Result<(), String> {
    let observed = control
        .reconciler()
        .observe_run(run)
        .await
        .map_err(|error| error.to_string())?
        .ok_or_else(|| format!("run {run} has no Job any more"))?;
    let resource_version = observed.projection.identity.resource_version;
    let seed = format!(
        "fleet:{purpose}:{run}:{}:{}",
        resource_version.as_str(),
        target_node.as_deref().unwrap_or("-")
    );
    let operation_id =
        odin_types::OperationId::new(&format!("op-{}", uuid::Uuid::new_v4().simple()))
            .map_err(|error| error.to_string())?;
    control
        .operate_at_live_version(
            JobAction {
                run_id: run.clone(),
                kind,
                expected_resource_version: resource_version,
                operation_id,
                idempotency_digest: Digest::hash(seed.as_bytes()),
                target_node,
            },
            time::OffsetDateTime::now_utc(),
        )
        .await
        .map(|_| ())
        .map_err(|error| error.to_string())
}

/// Moves every running Odin pod off `nodes`: rehome to the first candidate
/// node its declared placement fits, else pause and remember it. Returns
/// one sentence per pod.
pub(super) async fn drain(
    control: &KubeControl,
    client: &KubeClient,
    host: &str,
    nodes: &[String],
    candidates: &[String],
    state_root: &Path,
) -> Result<Vec<String>, String> {
    let reconciler = control.reconciler();
    let observed = reconciler.list().await.map_err(|error| error.to_string())?;
    let mut lines = Vec::new();
    let mut paused: Vec<String> = Vec::new();
    for observation in observed {
        let KubeResourceOwnership::Odin { run_id: run, .. } = &observation.workload.ownership
        else {
            continue;
        };
        if !matches!(
            observation.workload.state,
            KubeWorkloadState::Running | KubeWorkloadState::Pending | KubeWorkloadState::Scheduling
        ) {
            continue;
        }
        let Some(node) = reconciler
            .workload_placement(run)
            .await
            .map_err(|error| error.to_string())?
            .and_then(|placement| placement.node)
        else {
            continue;
        };
        if !nodes.contains(&node) {
            continue;
        }
        let job = observation.workload.resource.name.clone();
        let label = observation
            .workload
            .profile
            .clone()
            .unwrap_or_else(|| job.clone());
        let Some(launch) = reconciler
            .stored_launch(run)
            .map_err(|error| error.to_string())?
        else {
            lines.push(format!("{label}: no admitted launch is stored; left alone"));
            continue;
        };
        let mut target = None;
        for candidate in candidates {
            if odin_kube::state_carry::require_node_fits(client, candidate, &launch.node_selector)
                .await
                .is_ok()
            {
                target = Some(candidate.clone());
                break;
            }
        }
        let line = match target {
            Some(target) => match operate(
                control,
                run,
                KubeOperationKind::Restart,
                Some(target.clone()),
                "drain-rehome",
            )
            .await
            {
                Ok(()) => format!("{label}: rehomed {node} → {target} with its state"),
                Err(error) => format!("{label}: rehome to {target} failed: {error}"),
            },
            None => {
                match operate(control, run, KubeOperationKind::Pause, None, "drain-pause").await {
                    Ok(()) => {
                        paused.push(run.to_string());
                        format!(
                            "{label}: paused on {node} — its declared placement holds on no other \
                         online node; it resumes when {host} is back"
                        )
                    }
                    Err(error) => format!("{label}: pause failed: {error}"),
                }
            }
        };
        tracing::debug!("fleet drain host={host} {line}");
        lines.push(line);
    }
    let path = record_path(state_root, host);
    let write = std::fs::create_dir_all(path.parent().unwrap_or(state_root))
        .and_then(|()| std::fs::write(&path, serde_json::to_vec(&paused).unwrap_or_default()));
    if let Err(error) = write {
        lines.push(format!(
            "the paused-pod record for {host} could not be written ({error}); resume them by hand"
        ));
    }
    Ok(lines)
}

/// Resumes the pods a drain of `host` paused. Returns one sentence per pod.
pub(super) async fn restore(control: &KubeControl, host: &str, state_root: &Path) -> Vec<String> {
    let path = record_path(state_root, host);
    let Ok(bytes) = std::fs::read(&path) else {
        return Vec::new();
    };
    let runs: Vec<String> = match serde_json::from_slice(&bytes) {
        Ok(runs) => runs,
        Err(error) => {
            return vec![format!(
                "the paused-pod record for {host} is unreadable: {error}"
            )]
        }
    };
    let mut lines = Vec::new();
    for raw in runs {
        let line = match RunId::new(raw.clone()) {
            Ok(run) => {
                match operate(control, &run, KubeOperationKind::Resume, None, "restore").await {
                    Ok(()) => format!("{run}: resumed"),
                    Err(error) => format!("{run}: resume failed: {error}"),
                }
            }
            Err(error) => format!("{raw}: not a run id ({error})"),
        };
        tracing::debug!("fleet restore host={host} {line}");
        lines.push(line);
    }
    if let Err(error) = std::fs::remove_file(&path) {
        tracing::error!("fleet restore record not removed host={host}: {error}");
    }
    lines
}
