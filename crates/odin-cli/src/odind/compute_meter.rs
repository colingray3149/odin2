//! The compute meter: every cadence (the authority node card's `compute_meter_seconds`), each
//! running Odin pod is charged its requested cores, GPUs and priced node time to its lane and
//! budget lane in `compute-usage.json`. A lane that passes a declared compute cap is told once,
//! through its running pod's launching session; nothing is stopped.

use std::collections::BTreeMap;
use std::sync::Arc;

use k8s_openapi::api::core::v1::{Node, Pod};
use kube::api::ListParams;
use odin_kube::job::{JOB_LABEL_BUDGET_LANE, JOB_LABEL_LANE_ID};
use odin_registry::{
    ComputeUsage, LaneBudgetKind, MeteredPod, ObjectConfig, RaisedLaneBudgets, Snapshot,
};

use super::workload_watch::{launching_session, route_finding, Finding};
use crate::kube::KubeRuntimeCell;

/// The meter's cadence, declared on the authority node card.
fn cadence(snapshot: &Snapshot) -> std::time::Duration {
    let seconds = snapshot
        .objects
        .iter()
        .find_map(|object| match &object.config {
            ObjectConfig::Node(node) if node.enabled && node.authoritative_state => {
                node.compute_meter_seconds
            }
            _ => None,
        })
        .map_or(
            odin_registry::schema::DEFAULT_COMPUTE_METER_SECONDS,
            |seconds| seconds.get(),
        );
    std::time::Duration::from_secs(u64::from(seconds))
}

fn node_price(snapshot: &Snapshot, node: &str) -> f64 {
    snapshot
        .objects
        .iter()
        .find_map(|object| match &object.config {
            ObjectConfig::Node(card) if object.id == node => card.cost,
            _ => None,
        })
        .map_or(0.0, |cost| cost.usd_per_hour)
}

/// A running pod's lanes, request and price share; `None` when it is not running.
fn metered(pod: &Pod, price_share: impl Fn(&str, u64) -> f64) -> Option<MeteredPod> {
    let status = pod.status.as_ref()?;
    if status.phase.as_deref() != Some("Running") {
        return None;
    }
    pod_charge(pod, price_share)
}

fn pod_charge(pod: &Pod, price_share: impl Fn(&str, u64) -> f64) -> Option<MeteredPod> {
    let status = pod.status.as_ref()?;
    let labels = pod.metadata.labels.as_ref()?;
    let mut lanes = vec![labels.get(JOB_LABEL_LANE_ID)?.clone()];
    if let Some(budget) = labels.get(JOB_LABEL_BUDGET_LANE) {
        if !lanes.contains(budget) {
            lanes.push(budget.clone());
        }
    }
    let spec = pod.spec.as_ref()?;
    let request = odin_kube::placement::pod_requests(spec).ok()?;
    let node = spec.node_name.as_deref().unwrap_or_default();
    Some(MeteredPod {
        uid: pod.metadata.uid.clone()?,
        lanes,
        cores: request.cpu_millis as f64 / 1_000.0,
        gpus: f64::from(request.gpu_count),
        usd_per_hour: price_share(node, request.cpu_millis),
        started_ms: status
            .start_time
            .as_ref()
            .and_then(|started| u64::try_from(started.0.as_millisecond()).ok())?,
    })
}

/// A terminated worker's last observed running interval, including short-lived pods.
fn completed(pod: &Pod, price_share: impl Fn(&str, u64) -> f64) -> Option<(MeteredPod, u64)> {
    let status = pod.status.as_ref()?;
    if !matches!(status.phase.as_deref(), Some("Succeeded" | "Failed")) {
        return None;
    }
    let worker = status
        .container_statuses
        .as_ref()?
        .iter()
        .find(|container| container.name == odin_kube::job::JOB_WORKER_CONTAINER)?;
    let finished = worker
        .state
        .as_ref()?
        .terminated
        .as_ref()?
        .finished_at
        .as_ref()?;
    let end_ms = u64::try_from(finished.0.as_millisecond()).ok()?;
    Some((pod_charge(pod, price_share)?, end_ms))
}

/// Settle only a complete, single-pod Job whose original create operation and
/// API-server UID agree. Missing or ambiguous evidence keeps the reservation.
async fn settle_campaigns(
    cell: &KubeRuntimeCell,
    client: &odin_kube::KubeClient,
    state: &std::path::Path,
    pods: &[Pod],
) {
    let Some(control) = cell.control() else {
        return;
    };
    let pending = match odin_ledger::campaign::pending(state) {
        Ok(pending) => pending,
        Err(error) => {
            tracing::warn!("campaign reservations unavailable: {error}");
            return;
        }
    };
    let operations = match control.reconciler().operation_runs() {
        Ok(operations) => operations,
        Err(error) => {
            tracing::warn!("campaign operation history unavailable: {error}");
            return;
        }
    };
    for operation in pending {
        let Ok(Some((run, launch))) = control.reconciler().operation_launch(&operation) else {
            continue;
        };
        if operations
            .iter()
            .filter(|(_, candidate)| candidate == &run)
            .count()
            != 1
        {
            continue;
        }
        if launch.operation_id.as_str() != operation || launch.service {
            continue;
        }
        let Ok(Some(observation)) = control.reconciler().applied_observation(&operation) else {
            continue;
        };
        let Ok(Some(job)) = client.jobs().get_opt(&launch.job_name()).await else {
            continue;
        };
        let Some(uid) = job.metadata.uid.as_deref() else {
            continue;
        };
        if uid != observation.projection.identity.uid.as_str() {
            continue;
        }
        let Some(spec) = job.spec.as_ref() else {
            continue;
        };
        let Some(status) = job.status.as_ref() else {
            continue;
        };
        let succeeded = status.succeeded == Some(1) && status.failed.unwrap_or(0) == 0;
        let failed = status.failed == Some(1) && status.succeeded.unwrap_or(0) == 0;
        if spec.backoff_limit != Some(0)
            || !(succeeded || failed)
            || !status.conditions.as_ref().is_some_and(|conditions| {
                conditions.iter().any(|condition| {
                    condition.status == "True"
                        && ((succeeded && condition.type_ == "Complete")
                            || (failed && condition.type_ == "Failed"))
                })
            })
        {
            continue;
        }
        let matching: Vec<_> = pods
            .iter()
            .filter(|pod| {
                pod.metadata
                    .owner_references
                    .as_ref()
                    .is_some_and(|owners| {
                        owners.iter().any(|owner| {
                            owner.uid == uid
                                && owner.kind == "Job"
                                && owner.controller == Some(true)
                        })
                    })
            })
            .collect();
        let [pod] = matching.as_slice() else { continue };
        let Some(status) = pod.status.as_ref() else {
            continue;
        };
        if status.container_statuses.as_ref().is_none_or(|containers| {
            containers
                .iter()
                .any(|container| container.restart_count != 0)
        }) || status
            .init_container_statuses
            .as_ref()
            .is_some_and(|containers| {
                containers
                    .iter()
                    .any(|container| container.restart_count != 0)
            })
        {
            continue;
        }
        let Some((charge, end)) = completed(pod, |_, _| 0.0) else {
            continue;
        };
        let Some(elapsed) = end.checked_sub(charge.started_ms) else {
            continue;
        };
        let actual = charge.cores * elapsed as f64 / 3_600_000.0;
        if let Err(error) = odin_ledger::campaign::settle(state, &operation, actual) {
            tracing::warn!(%operation, "campaign settlement deferred: {error}");
        }
    }
}

/// The lanes whose metered use now passes a declared (or raised) compute cap, newly, with
/// what to tell them. A lane back under its cap may be told again later.
fn newly_over(
    usage: &mut ComputeUsage,
    snapshot: &Snapshot,
    raised: Option<&RaisedLaneBudgets>,
    now_ms: u64,
) -> Vec<(String, String, String)> {
    let mut told = Vec::new();
    for object in &snapshot.objects {
        let ObjectConfig::Lane(lane) = &object.config else {
            continue;
        };
        let used = usage.used(&object.id, lane.limits.window_days(), now_ms);
        for kind in LaneBudgetKind::COMPUTE {
            let Some(floor) = kind.declared(&lane.limits) else {
                continue;
            };
            let cap = raised
                .and_then(|raised| raised.effective(&object.id, Some(floor), kind))
                .unwrap_or(floor);
            let key = format!("{}:{}", object.id, kind.key());
            let value = used.in_limit_units(kind);
            if value > f64::from(cap) {
                if usage.over_cap.insert(key.clone()) {
                    told.push((
                        object.id.clone(),
                        key,
                        format!(
                            "Lane {} has used {value:.1} of its {} {cap} in the last {} days. \
                             Running pods keep running; new launches are refused until the \
                             window frees or the owner raises it. Cancel what should not finish.",
                            object.id,
                            kind.key(),
                            lane.limits.window_days()
                        ),
                    ));
                }
            } else {
                usage.over_cap.remove(&key);
            }
        }
    }
    told
}

pub(super) fn arm(
    pumps: &mut tokio::task::JoinSet<Result<(), String>>,
    cell: Arc<KubeRuntimeCell>,
    pin: Arc<odin_registry::SnapshotHandle>,
    read_model: Arc<odin_huginn::read_model::MaterializedReadModel>,
    owner: Arc<odin_omp::host_tools::delegation::GovernedTaskOwner>,
    runtime: Arc<odin_hermes::runtime::HermesRuntime>,
) {
    let Some(huginn) = cell.huginn_root().map(std::path::Path::to_path_buf) else {
        return;
    };
    pumps.spawn(async move {
        loop {
            tokio::time::sleep(cadence(&pin.current())).await;
            let snapshot = pin.current();
            let client = match cell.client().await {
                Ok(client) => client,
                Err(error) => {
                    tracing::warn!("compute meter tick skipped: cluster unavailable: {error}");
                    continue;
                }
            };
            let pods = match client
                .pods()
                .list(&ListParams::default().labels(JOB_LABEL_LANE_ID))
                .await
            {
                Ok(pods) => pods.items,
                Err(error) => {
                    tracing::warn!("compute meter tick skipped: pod list failed: {error}");
                    continue;
                }
            };
            if let Some(state) = huginn.parent() {
                settle_campaigns(&cell, &client, state, &pods).await;
            }
            let snapshot = snapshot.as_ref();
            // Allocatable CPU of each priced node, read only when some node has a price.
            let mut allocatable = BTreeMap::new();
            let mut unavailable = std::collections::BTreeSet::new();
            for pod in &pods {
                if !matches!(
                    pod.status
                        .as_ref()
                        .and_then(|status| status.phase.as_deref()),
                    Some("Running" | "Succeeded" | "Failed")
                ) {
                    continue;
                }
                let Some(node) = pod.spec.as_ref().and_then(|spec| spec.node_name.clone()) else {
                    continue;
                };
                if node_price(snapshot, &node) > 0.0
                    && !allocatable.contains_key(&node)
                    && !unavailable.contains(&node)
                {
                    let nodes: kube::Api<Node> = kube::Api::all(client.client.clone());
                    match nodes.get_opt(&node).await {
                        Ok(Some(found)) => {
                            match odin_kube::placement::allocatable_cpu_millis(&found) {
                                Ok(millis) if millis > 0 => {
                                    allocatable.insert(node, millis);
                                }
                                _ => {
                                    unavailable.insert(node);
                                }
                            }
                        }
                        _ => {
                            unavailable.insert(node);
                        }
                    }
                }
            }
            if !unavailable.is_empty() {
                tracing::warn!(
                    ?unavailable,
                    "compute meter defers pods whose priced node CPU is unavailable"
                );
            }
            let share = |node: &str, cpu_millis: u64| match allocatable.get(node) {
                Some(&total) if total > 0 => {
                    node_price(snapshot, node) * cpu_millis as f64 / total as f64
                }
                _ => 0.0,
            };
            let price_known = |pod: &&Pod| {
                pod.spec
                    .as_ref()
                    .and_then(|spec| spec.node_name.as_ref())
                    .is_none_or(|node| !unavailable.contains(node))
            };
            let running: Vec<MeteredPod> = pods
                .iter()
                .filter(price_known)
                .filter_map(|pod| metered(pod, share))
                .collect();
            let finished: Vec<_> = pods
                .iter()
                .filter(price_known)
                .filter_map(|pod| completed(pod, share))
                .collect();
            let raised = RaisedLaneBudgets::load(&huginn).unwrap_or_else(|error| {
                tracing::warn!("compute meter reads no raises: {error}");
                None
            });
            let keep = snapshot
                .objects
                .iter()
                .filter_map(|object| match &object.config {
                    ObjectConfig::Lane(lane) => Some(lane.limits.window_days()),
                    _ => None,
                })
                .max()
                .unwrap_or_else(|| odin_registry::schema::LaneLimitsToml::default().window_days())
                .max(u16::from(odin_domain::huginn::SPEND_MAX_DAYS));
            let now_ms = odin_registry::unix_millis();
            let told = match ComputeUsage::update(&huginn, |usage| {
                for (pod, end_ms) in &finished {
                    usage.charge_completed(pod, *end_ms);
                }
                usage.charge(&running, now_ms);
                usage.prune(keep, now_ms);
                newly_over(usage, snapshot, raised.as_ref(), now_ms)
            }) {
                Ok(told) => told,
                Err(error) => {
                    tracing::error!("compute usage not recorded: {error}");
                    continue;
                }
            };
            match crate::kube_runtime::budget_rows(snapshot, &huginn, now_ms) {
                Ok(rows) => {
                    if let Err(error) = crate::huginn_spend::publish_status(
                        &read_model,
                        crate::huginn_spend::status_object("compute-budgets"),
                        serde_json::json!({"lanes": rows}),
                        time::OffsetDateTime::now_utc(),
                    ) {
                        tracing::error!("compute budget publication failed: {error}");
                    }
                }
                Err(error) => tracing::error!("compute budget view failed: {error}"),
            }
            for (lane, alert_key, text) in told {
                // A live Job of the lane tells its launching session; none wakes the owner.
                let session = client
                    .jobs()
                    .list(&ListParams::default().labels(&format!("{JOB_LABEL_LANE_ID}={lane}")))
                    .await
                    .map(|jobs| jobs.items)
                    .unwrap_or_default()
                    .iter()
                    .filter_map(|job| {
                        odin_kube::status::observe_job(&cell.kube_config().cluster, job, 0).ok()
                    })
                    .find_map(|observed| launching_session(&observed.projection.labels.run_id));
                let finding = Finding {
                    key: format!("compute-budget:{lane}:{now_ms}"),
                    session,
                    source: "compute meter",
                    text,
                    lane: odin_domain::LaneId::new(&lane).ok(),
                };
                if let Err(error) = route_finding(&owner, &runtime, finding).await {
                    tracing::error!("compute budget notice not delivered: {error}");
                    if let Err(error) = ComputeUsage::update(&huginn, |usage| {
                        usage.over_cap.remove(&alert_key);
                    }) {
                        tracing::error!("compute budget notice retry not recorded: {error}");
                    }
                }
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pod(phase: &str) -> Pod {
        serde_json::from_value(serde_json::json!({
            "metadata": {
                "uid": "uid-1",
                "labels": {
                    JOB_LABEL_LANE_ID: "worker-project",
                    JOB_LABEL_BUDGET_LANE: "project-sweeps",
                },
            },
            "spec": {
                "nodeName": "pc",
                "containers": [{
                    "name": "worker",
                    "resources": {"requests": {"cpu": "4", "nvidia.com/gpu": "1"},
                                  "limits": {"cpu": "4", "nvidia.com/gpu": "1"}},
                }],
            },
            "status": {"phase": phase, "startTime": "2026-11-15T10:00:00Z"},
        }))
        .expect("pod fixture")
    }

    #[test]
    fn a_running_pod_is_metered_on_both_its_lanes_and_a_pending_one_is_not() {
        let running = metered(&pod("Running"), |_, _| 0.0).expect("running");
        assert_eq!(running.lanes, ["worker-project", "project-sweeps"]);
        assert!((running.cores - 4.0).abs() < 1e-9);
        assert!((running.gpus - 1.0).abs() < 1e-9);
        assert!(metered(&pod("Pending"), |_, _| 0.0).is_none());
    }

    #[test]
    fn running_pod_charges_both_lanes_and_paused_pod_charges_nothing() {
        let running = metered(&pod("Running"), |_, _| 0.0).expect("running");
        let start = running.started_ms;
        let mut usage = ComputeUsage::default();
        usage.charge(&[running], start + 10_000);
        for lane in ["worker-project", "project-sweeps"] {
            let charged = usage.used(lane, 1, start + 10_000);
            assert!((charged.core_seconds - 40.0).abs() < 1e-9);
            assert!((charged.gpu_seconds - 10.0).abs() < 1e-9);
        }
        let paused: Vec<_> = metered(&pod("Pending"), |_, _| 0.0).into_iter().collect();
        usage.charge(&paused, start + 20_000);
        assert!((usage.used("worker-project", 1, start + 20_000).core_seconds - 40.0).abs() < 1e-9);
    }

    #[test]
    fn a_pod_completed_between_ticks_is_charged_once() {
        let mut pod = pod("Succeeded");
        pod.status.as_mut().unwrap().container_statuses = Some(vec![serde_json::from_value(
            serde_json::json!({"name": odin_kube::job::JOB_WORKER_CONTAINER,
                "ready": false, "restartCount": 0, "image": "fixture", "imageID": "fixture",
                "state": {"terminated": {"exitCode": 0, "finishedAt": "2026-11-15T10:00:10Z"}}}),
        )
        .unwrap()]);
        let (charge, end) = completed(&pod, |_, _| 0.0).unwrap();
        let mut usage = ComputeUsage::default();
        usage.charge_completed(&charge, end);
        usage.charge_completed(&charge, end);
        assert!((usage.used("worker-project", 1, end).core_seconds - 40.0).abs() < 1e-9);
    }
}
