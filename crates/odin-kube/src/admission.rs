//! Seat `limits.max_parallel_runs` and lane `limits.pods` checks of live
//! Jobs and Claude pods. Callers already hold the pod lifecycle lock. A
//! still-live replay is exempt.

use std::time::Duration;

use k8s_openapi::api::batch::v1::Job;
use k8s_openapi::api::core::v1::Pod;
use kube::api::ListParams;
use odin_domain::{LaneId, RunId, SeatId};
use odin_registry::{LaneBudgetKind, ObjectConfig, RegistryKind};

use crate::claude_pod::CLAUDE_SESSION_LABEL;
use crate::client::{KubeClient, KubeError};
use crate::job::{
    bounded_label_value, job_name, JOB_LABEL_BUDGET_LANE, JOB_LABEL_LANE_ID, JOB_LABEL_RUN_ID,
    JOB_LABEL_SEAT_ID,
};

/// Registry key named in every seat parallel-run refusal.
pub const PARALLEL_RUN_LIMIT_KEY: &str = "limits.max_parallel_runs";

/// Registry key named in every lane-pod refusal.
pub const LANE_POD_LIMIT_KEY: &str = odin_registry::PODS_LIMIT_KEY;

fn occupies_job(job: &Job) -> bool {
    !job.status.as_ref().is_some_and(|status| {
        status.conditions.as_ref().is_some_and(|conditions| {
            conditions.iter().any(|condition| {
                matches!(condition.type_.as_str(), "Complete" | "Failed")
                    && condition.status == "True"
            })
        })
    })
}

fn occupies_pod(pod: &Pod) -> bool {
    !matches!(
        pod.status
            .as_ref()
            .and_then(|status| status.phase.as_deref()),
        Some("Succeeded" | "Failed")
    )
}

fn run_label(pod: &Pod) -> Option<&str> {
    pod.metadata
        .labels
        .as_ref()
        .and_then(|labels| labels.get(JOB_LABEL_RUN_ID))
        .map(String::as_str)
}

/// Lists are already this seat's. Jobs and pods are different objects.
fn live_run_count(jobs: &[Job], pods: &[Pod], exempt: Option<&RunId>) -> usize {
    let exempt_job = exempt.map(job_name);
    let exempt_run = exempt.map(|run| bounded_label_value(run.as_str()));

    jobs.iter()
        .filter(|job| {
            occupies_job(job)
                && exempt_job
                    .as_deref()
                    .is_none_or(|name| job.metadata.name.as_deref() != Some(name))
        })
        .count()
        + pods
            .iter()
            .filter(|pod| {
                occupies_pod(pod)
                    && exempt_run
                        .as_deref()
                        .is_none_or(|run| run_label(pod) != Some(run))
            })
            .count()
}

fn live_run_labels(jobs: &[Job], pods: &[Pod]) -> Vec<String> {
    let mut labels = Vec::new();
    for job in jobs {
        if let Some(label) = job
            .metadata
            .labels
            .as_ref()
            .and_then(|labels| labels.get(JOB_LABEL_RUN_ID))
        {
            labels.push(label.clone());
        }
    }
    for pod in pods {
        if let Some(label) = run_label(pod) {
            labels.push(label.to_owned());
        }
    }
    labels
}

async fn listed<T>(
    api: kube::Api<T>,
    selector: String,
    timeout: Duration,
    kind: &str,
) -> Result<Vec<T>, KubeError>
where
    T: Clone + std::fmt::Debug + serde::de::DeserializeOwned + Send,
{
    let page = tokio::time::timeout(timeout, api.list(&ListParams::default().labels(&selector)))
        .await
        .map_err(|error| KubeError::unavailable(format!("{kind} inventory timed out: {error}")))?
        .map_err(KubeError::from)?;
    if page.metadata.continue_.is_some() {
        return Err(KubeError::unavailable(format!(
            "{kind} inventory came back chunked; a partial list cannot admit a run"
        )));
    }
    Ok(page.items)
}

/// Pods without `odin.dev/seat-id` are not listed. Does not take the lifecycle lock.
pub async fn admit_parallel_run(
    client: &KubeClient,
    snapshot: &odin_registry::Snapshot,
    seat: &SeatId,
    exempt: Option<&RunId>,
) -> Result<(), KubeError> {
    let Some(odin_registry::ObjectConfig::Seat(config)) = snapshot
        .object(odin_registry::RegistryKind::Seat, seat.as_str())
        .map(|object| &object.config)
    else {
        return Err(KubeError::rejected(format!(
            "seat {seat} has no seat declaration; {PARALLEL_RUN_LIMIT_KEY} cannot be read"
        )));
    };
    let cap = config.limits.max_parallel_runs;
    let label = bounded_label_value(seat.as_str());
    let timeout = client.request_timeout();
    let jobs = listed(
        client.jobs(),
        format!("{JOB_LABEL_SEAT_ID}={label}"),
        timeout,
        "Job",
    )
    .await?;
    let pods = listed(
        client.pods(),
        format!("{JOB_LABEL_SEAT_ID}={label},{CLAUDE_SESSION_LABEL}"),
        timeout,
        "pod",
    )
    .await?;
    let active = live_run_count(&jobs, &pods, exempt);
    if active >= usize::from(cap) {
        return Err(KubeError::rejected(format!(
            "seat {seat} already has {active} active workload run(s); {PARALLEL_RUN_LIMIT_KEY} is {cap}"
        )));
    }
    Ok(())
}
/// Declared lane pod cap, if the lane declares one. A missing lane is a
/// refusal (the cap cannot be read); an omitted `limits.pods` admits.
pub fn declared_lane_pods(
    snapshot: &odin_registry::Snapshot,
    lane: &LaneId,
) -> Result<Option<u32>, KubeError> {
    let Some(ObjectConfig::Lane(config)) = snapshot
        .object(RegistryKind::Lane, lane.as_str())
        .map(|object| &object.config)
    else {
        return Err(KubeError::rejected(format!(
            "lane {lane} has no lane declaration; {LANE_POD_LIMIT_KEY} cannot be read"
        )));
    };
    Ok(LaneBudgetKind::Pods.declared(&config.limits))
}

/// Refuses when `active` already fills `effective`. A missing cap admits.
/// Callers pass the declaration raised by `lane-budgets.json` when one exists.
pub fn refuse_lane_pods(
    lane: &LaneId,
    effective: Option<u32>,
    active: u32,
) -> Result<(), KubeError> {
    odin_registry::at_cap(LaneBudgetKind::Pods, effective, active)
        .map_err(|detail| KubeError::rejected(format!("lane {lane} pod budget refused: {detail}")))
}

/// Lists this lane's live Jobs and Claude pods and refuses at the raised cap.
/// `huginn` is the root of `lane-budgets.json`. A typed raise there lifts the
/// declared cap. Absent means the declaration alone.
pub async fn admit_lane_pod_budget(
    client: &KubeClient,
    snapshot: &odin_registry::Snapshot,
    lane: &LaneId,
    huginn: Option<&std::path::Path>,
    exempt: Option<&RunId>,
) -> Result<(), KubeError> {
    admit_lane_pod_budget_with_pending(client, snapshot, lane, huginn, exempt, &[]).await
}

/// `pending` are durable create claims for this lane that have not yet
/// produced a Job. They reserve a slot so a retry cannot exceed the cap
/// after another launch consumed the last live object.
pub async fn admit_lane_pod_budget_with_pending(
    client: &KubeClient,
    snapshot: &odin_registry::Snapshot,
    lane: &LaneId,
    huginn: Option<&std::path::Path>,
    exempt: Option<&RunId>,
    pending: &[RunId],
) -> Result<(), KubeError> {
    let declared = declared_lane_pods(snapshot, lane)?;
    let raised = match huginn.map(odin_registry::RaisedLaneBudgets::load) {
        Some(Ok(loaded)) => loaded,
        Some(Err(error)) => {
            return Err(KubeError::rejected(format!(
                "lane {lane} raise file is unreadable: {error}"
            )))
        }
        None => None,
    };
    let effective = raised
        .and_then(|raised| raised.effective(lane.as_str(), declared, LaneBudgetKind::Pods))
        .or(declared);
    if effective.is_none() {
        return Ok(());
    }
    let label = bounded_label_value(lane.as_str());
    let timeout = client.request_timeout();
    let jobs = listed(
        client.jobs(),
        format!("{JOB_LABEL_LANE_ID}={label}"),
        timeout,
        "Job",
    )
    .await?;
    let charged = listed(
        client.jobs(),
        format!("{JOB_LABEL_BUDGET_LANE}={label}"),
        timeout,
        "Job",
    )
    .await?;
    let jobs = union_jobs(jobs, charged);
    let pods = listed(
        client.pods(),
        format!("{JOB_LABEL_LANE_ID}={label},{CLAUDE_SESSION_LABEL}"),
        timeout,
        "pod",
    )
    .await?;
    let live = u32::try_from(live_run_count(&jobs, &pods, exempt)).unwrap_or(u32::MAX);
    let live_runs = live_run_labels(&jobs, &pods);
    let exempt_label = exempt.map(|run| bounded_label_value(run.as_str()));
    let reserved = pending
        .iter()
        .filter(|run| {
            let label = bounded_label_value(run.as_str());
            exempt_label.as_deref() != Some(label.as_str())
                && !live_runs.iter().any(|existing| existing == &label)
        })
        .count();
    let active = live.saturating_add(u32::try_from(reserved).unwrap_or(u32::MAX));
    odin_registry::at_cap(LaneBudgetKind::Pods, effective, active)
        .map_err(|detail| KubeError::rejected(format!("lane {lane} pod budget refused: {detail}")))
}

fn job_key(job: &Job) -> String {
    job.metadata
        .uid
        .clone()
        .or_else(|| job.metadata.name.clone())
        .unwrap_or_default()
}

fn union_jobs(primary: Vec<Job>, extra: Vec<Job>) -> Vec<Job> {
    let mut seen = std::collections::BTreeSet::new();
    let mut jobs = Vec::new();
    for job in primary.into_iter().chain(extra) {
        if seen.insert(job_key(&job)) {
            jobs.push(job);
        }
    }
    jobs
}

/// Refuses when a live worker of this lane has filled `limits.wall_seconds`.
/// The clock is `lane-wall.json` under `huginn`. A missing lease is no live
/// worker. A missing huginn root refuses when the lane declares a wall,
/// because the clock cannot be read.
pub fn admit_lane_wall(
    snapshot: &odin_registry::Snapshot,
    lane: &LaneId,
    huginn: Option<&std::path::Path>,
) -> Result<(), KubeError> {
    let declared = declared_lane_wall(snapshot, lane)?;
    let raised = match huginn.map(odin_registry::RaisedLaneBudgets::load) {
        Some(Ok(loaded)) => loaded,
        Some(Err(error)) => {
            return Err(KubeError::rejected(format!(
                "lane {lane} raise file is unreadable: {error}"
            )))
        }
        None => None,
    };
    let effective = raised
        .as_ref()
        .and_then(|raised| raised.effective(lane.as_str(), declared, LaneBudgetKind::WallSeconds))
        .or(declared);
    if effective.is_none() {
        return Ok(());
    }
    let Some(huginn) = huginn else {
        return Err(KubeError::rejected(format!(
            "lane {lane} wall budget root is missing; {LANE_WALL_KEY} cannot be read"
        )));
    };
    let started = odin_registry::LaneWallLease::load(huginn)
        .map_err(|error| {
            KubeError::rejected(format!("lane {lane} wall lease is unreadable: {error}"))
        })?
        .and_then(|lease| lease.started(lane.as_str()));
    odin_registry::refuse_wall(effective, started, odin_registry::unix_millis())
        .map_err(|detail| KubeError::rejected(format!("lane {lane} wall budget refused: {detail}")))
}

fn declared_lane_wall(
    snapshot: &odin_registry::Snapshot,
    lane: &LaneId,
) -> Result<Option<u32>, KubeError> {
    let Some(ObjectConfig::Lane(config)) = snapshot
        .object(RegistryKind::Lane, lane.as_str())
        .map(|object| &object.config)
    else {
        return Err(KubeError::rejected(format!(
            "lane {lane} has no lane declaration; {LANE_WALL_KEY} cannot be read"
        )));
    };
    Ok(LaneBudgetKind::WallSeconds.declared(&config.limits))
}

const LANE_WALL_KEY: &str = odin_registry::WALL_LIMIT_KEY;

#[cfg(test)]
mod tests {
    use super::*;

    fn job(name: &str, terminal: Option<&str>) -> Job {
        let status = terminal
            .map(|type_| serde_json::json!({"conditions":[{"type": type_, "status":"True"}]}));
        serde_json::from_value(serde_json::json!({"metadata":{"name": name}, "status": status}))
            .unwrap()
    }

    fn pod(run: &str, phase: &str) -> Pod {
        serde_json::from_value(serde_json::json!({
            "metadata": {"labels": {JOB_LABEL_RUN_ID: run}},
            "status": {"phase": phase},
        }))
        .unwrap()
    }

    #[test]
    fn live_jobs_and_claude_pods_fill_the_cap() {
        let run = RunId::new("run-live").unwrap();
        let jobs = [
            job(&job_name(&run), None),
            job("odin-done", Some("Complete")),
        ];
        let pods = [
            pod(&bounded_label_value(run.as_str()), "Running"),
            pod("run-done", "Succeeded"),
        ];
        let cap = 2u16;
        assert_eq!(live_run_count(&jobs, &pods, None), usize::from(cap));
        assert_eq!(live_run_count(&jobs, &pods, Some(&run)), 0);
        assert_eq!(
            live_run_count(
                &[job("odin-done", Some("Failed"))],
                &[pod("run-done", "Failed")],
                None
            ),
            0
        );
    }
}
