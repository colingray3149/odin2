//! The kernel's workload watch: a code-only cycle over the kube read model
//! that turns Odin-owned workload state into findings — finished, failed,
//! crash-looping — and routes each finding once to the seat session that
//! launched the workload (the declared monitor of its own work). A settled
//! agent pod's finished/failed outcome is withheld: the pod-report pump
//! delivers the pod's answer (or its failure) once and releases the Job,
//! so a finding here would only invite the launcher to poll. Script pods
//! and every crash-loop still reach the seat. That seat decides; its answer
//! climbs to the conversation through the delegated report path. Healthy
//! workloads cost no model call at all.

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration as StdDuration;

use kube::api::{ListParams, LogParams};
use odin_domain::huginn::{
    KubeResourceOwnership, KubeWorkloadState, KubeWorkloadView, LiveSessionId, ObjectKind,
};
use odin_domain::SeatId;
use odin_registry::schema::RoutineEvent;

use crate::kube::KubeRuntimeCell;

const WATCH_TICK: StdDuration = StdDuration::from_secs(15);
/// Restarts after which a running workload is reported as crash-looping.
const CRASH_LOOP_RESTARTS: u32 = 3;
/// Workloads that finished longer ago than this are history, never news
/// (a restarted daemon does not re-report old runs).
const REPORT_WINDOW: time::Duration = time::Duration::minutes(15);
/// The most of a finished pod's output kept as its artifact.
const MAX_OUTPUT_BYTES: i64 = 1024 * 1024;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct Finding {
    /// Stable identity: the workload uid plus the finding kind.
    pub(super) key: String,
    /// The launching session (`run:live:<session>`), when it is a live one.
    pub(super) session: Option<LiveSessionId>,
    pub(super) text: String,
}

/// Agent terminal outcomes belong to the pod-report pump; crash loops do not.
pub(super) fn findings(
    views: &[KubeWorkloadView],
    now: time::OffsetDateTime,
    mut is_agent_run: impl FnMut(&odin_domain::RunId) -> bool,
) -> Vec<Finding> {
    let mut found = Vec::new();
    for view in views {
        let KubeResourceOwnership::Odin {
            run_id, seat_id, ..
        } = &view.ownership
        else {
            continue;
        };
        let recent = view
            .finished_at
            .is_none_or(|finished| now - finished <= REPORT_WINDOW);
        let restarts = view
            .containers
            .iter()
            .map(|container| container.restart_count)
            .max()
            .unwrap_or(0);
        let (kind, text) = match view.state {
            KubeWorkloadState::Succeeded if recent => (
                "finished",
                format!("workload {} finished successfully", view.resource.name),
            ),
            KubeWorkloadState::Failed if recent => {
                ("failed", format!("workload {} FAILED", view.resource.name))
            }
            KubeWorkloadState::Running if restarts >= CRASH_LOOP_RESTARTS => (
                "crash-loop",
                format!(
                    "workload {} is crash-looping ({restarts} restarts)",
                    view.resource.name
                ),
            ),
            _ => continue,
        };
        if kind != "crash-loop" && is_agent_run(run_id) {
            // The pump reports this pod's settled outcome once and releases
            // the Job; a finding would send the launcher polling after it.
            continue;
        }
        let session = launching_session(run_id);
        found.push(Finding {
            key: format!("{}:{kind}", view.resource.uid),
            session,
            text: format!(
                "[Odin workload watch — not a message from Colin] The {text}; it was launched by \
                 seat {seat_id}. Check it with your workload tools, act within your declared \
                 capabilities if something is wrong, and report the outcome plainly."
            ),
        });
    }
    found
}

/// Odin pods that finished within the report window, with the routine
/// event each outcome is and when it happened.
fn outcomes(
    views: &[KubeWorkloadView],
    now: time::OffsetDateTime,
) -> Vec<(RoutineEvent, &KubeWorkloadView, time::OffsetDateTime)> {
    views
        .iter()
        .filter(|view| matches!(view.ownership, KubeResourceOwnership::Odin { .. }))
        .filter_map(|view| {
            let event = match view.state {
                KubeWorkloadState::Succeeded => RoutineEvent::WorkloadSucceeded,
                KubeWorkloadState::Failed => RoutineEvent::WorkloadFailed,
                _ => return None,
            };
            let finished = view.finished_at?;
            (now - finished <= REPORT_WINDOW).then_some((event, view, finished))
        })
        .collect()
}

/// A finished pod's output — its container log through the kube API,
/// bounded — kept as an artifact readable by the launching seat and the
/// conversation seat: the next stage of a chain takes it
/// as input, Sinmara can send it to Colin, and nothing is read off a host
/// path. Returns the artifact id; every miss is logged, never fatal.
async fn capture_output(
    cell: &KubeRuntimeCell,
    state_root: &std::path::Path,
    view: &KubeWorkloadView,
    conversation_seat: &SeatId,
) -> Option<String> {
    let KubeResourceOwnership::Odin { seat_id, .. } = &view.ownership else {
        return None;
    };
    let job = view.resource.name.as_str();
    let miss = |reason: String| {
        tracing::error!("pod output not captured job={job} reason={reason}");
        None
    };
    let client = match cell.parts().await {
        Ok((_, client)) => client,
        Err(error) => return miss(format!("the cluster is unreachable: {error}")),
    };
    let pods = match client
        .pods()
        .list(&ListParams::default().labels(&format!("job-name={job}")))
        .await
    {
        Ok(pods) => pods,
        Err(error) => return miss(format!("its pods could not be listed: {error}")),
    };
    // The newest attempt is the one whose outcome the Job reports.
    let Some(newest) = pods
        .items
        .iter()
        .max_by_key(|pod| pod.metadata.creation_timestamp.clone())
    else {
        return miss("it has no pod left".to_owned());
    };
    let Some(pod) = newest.metadata.name.clone() else {
        return miss("its pod has no name".to_owned());
    };
    tracing::debug!(
        "pod phase job={job} pod={pod} node={} kind=finished {}",
        newest
            .spec
            .as_ref()
            .and_then(|spec| spec.node_name.as_deref())
            .unwrap_or("-"),
        odin_kube::pod_phase::PodTimeline::of(newest).fields(None)
    );
    let log = match client
        .pods()
        .logs(
            &pod,
            &LogParams {
                container: view
                    .containers
                    .first()
                    .map(|container| container.name.clone()),
                limit_bytes: Some(MAX_OUTPUT_BYTES),
                ..LogParams::default()
            },
        )
        .await
    {
        Ok(log) if log.trim().is_empty() => return miss("it printed nothing".to_owned()),
        Ok(log) => log,
        Err(error) => return miss(format!("its log could not be read: {error}")),
    };
    let mut shares = vec![("seat", seat_id.to_string())];
    if seat_id != conversation_seat {
        shares.push(("seat", conversation_seat.to_string()));
    }
    let state_root = state_root.to_owned();
    let stored = tokio::task::spawn_blocking(move || {
        crate::coding_route::store_artifact(&state_root, log.as_bytes(), "text/plain", &shares)
    })
    .await;
    match stored {
        Ok(Ok(metadata)) => {
            tracing::debug!(
                "pod output captured job={job} artifact={} bytes={}",
                metadata.artifact_id,
                metadata.size_bytes
            );
            Some(metadata.artifact_id.to_string())
        }
        Ok(Err(error)) => miss(error),
        Err(error) => miss(error.to_string()),
    }
}

/// The most of a finished pod's exported files kept as one artifact.
const MAX_EXPORT_BYTES: u64 = 256 * 1024 * 1024;

/// A finished pod's exported files — its run's own folder under the
/// declared export host folder, on whichever node it ran — kept as one tar
/// artifact readable by the launching seat and the conversation seat
/// , so a chain passes files, not just logs. Returns the
/// artifact id; an empty export or a pod without one is no artifact.
async fn capture_exports(
    cell: &KubeRuntimeCell,
    state_root: &std::path::Path,
    view: &KubeWorkloadView,
    remembered_node: Option<String>,
    conversation_seat: &SeatId,
) -> Option<String> {
    let KubeResourceOwnership::Odin { seat_id, .. } = &view.ownership else {
        return None;
    };
    let job = view.resource.name.as_str();
    let miss = |reason: String| {
        tracing::error!("pod exports not captured job={job} reason={reason}");
        None
    };
    let client = match cell.parts().await {
        Ok((_, client)) => client,
        Err(error) => return miss(format!("the cluster is unreachable: {error}")),
    };
    let declared = match client.jobs().get_opt(job).await {
        Ok(Some(declared)) => declared,
        Ok(None) => return miss("the Job is gone".to_owned()),
        Err(error) => return miss(format!("the Job could not be read: {error}")),
    };
    let node = match client
        .pods()
        .list(&ListParams::default().labels(&format!("job-name={job}")))
        .await
    {
        Ok(pods) => pods
            .items
            .into_iter()
            .max_by_key(|pod| pod.metadata.creation_timestamp.clone())
            .and_then(|pod| pod.spec.and_then(|spec| spec.node_name)),
        Err(error) => return miss(format!("its pods could not be listed: {error}")),
    };
    // A Job ended by its deadline has no pod left to name its node: the
    // node the watch saw it running on is remembered.
    let Some(node) = node
        .or_else(|| view.node_id.as_ref().map(ToString::to_string))
        .or(remembered_node)
    else {
        return miss("no node ran it".to_owned());
    };
    // Jobs without a per-run export have nothing to capture.
    let mut site = odin_kube::state_carry::export_site(&declared, &node)?;
    // The workload image includes tar; the job image may not.
    site.image
        .clone_from(&cell.workload_identity().deployment.image_reference);
    let stops = cell.stop_authority();
    let tar =
        match odin_kube::state_carry::export_tar(&client, &stops, &site, MAX_EXPORT_BYTES).await {
            Ok(tar) => tar,
            Err(error) => return miss(error.to_string()),
        };
    let files = odin_kube::state_carry::tar_file_count(&tar);
    if files == 0 {
        tracing::info!("pod exports none job={job} node={node}");
        return None;
    }
    let mut shares = vec![("seat", seat_id.to_string())];
    if seat_id != conversation_seat {
        shares.push(("seat", conversation_seat.to_string()));
    }
    let state_root = state_root.to_owned();
    let stored = tokio::task::spawn_blocking(move || {
        crate::coding_route::store_artifact(&state_root, &tar, "application/x-tar", &shares)
    })
    .await;
    match stored {
        Ok(Ok(metadata)) => {
            tracing::debug!(
                "pod exports captured job={job} node={node} files={files} artifact={} bytes={}",
                metadata.artifact_id,
                metadata.size_bytes
            );
            Some(metadata.artifact_id.to_string())
        }
        Ok(Err(error)) => miss(error),
        Err(error) => miss(error.to_string()),
    }
}

/// Remember nodes after the controller deletes terminal pods so exports remain discoverable;
/// forget workloads once they leave the read model.
#[derive(Default)]
struct NodeMemory {
    nodes: BTreeMap<String, String>,
}

impl NodeMemory {
    fn observe(&mut self, views: &[KubeWorkloadView]) {
        let present: BTreeSet<&str> = views
            .iter()
            .map(|view| view.resource.uid.as_str())
            .collect();
        self.nodes.retain(|uid, _| present.contains(uid.as_str()));
        for view in views {
            if let Some(node) = &view.node_id {
                self.nodes
                    .insert(view.resource.uid.clone(), node.to_string());
            }
        }
    }

    fn node_of(&self, uid: &str) -> Option<String> {
        self.nodes.get(uid).cloned()
    }
}

fn exports_clause(artifact: Option<&str>) -> String {
    artifact.map_or_else(String::new, |artifact| {
        format!("; the files it exported are artifact {artifact} (a tar: pass it to the next pod as an input, or send it)")
    })
}

/// Arms the watch: each finding is delivered once to the launching seat's
/// session; when that session is gone, the conversation seat is woken with
/// it instead so nothing is silently dropped. A finished pod's output is
/// kept as an artifact first, and both the finding and the routine event
/// name it.
pub(super) fn arm_workload_watch(
    pumps: &mut tokio::task::JoinSet<Result<(), String>>,
    read_model: Arc<odin_huginn::read_model::MaterializedReadModel>,
    owner: Arc<odin_omp::host_tools::delegation::GovernedTaskOwner>,
    runtime: Arc<odin_hermes::runtime::HermesRuntime>,
    kube: Option<Arc<KubeRuntimeCell>>,
    state_root: PathBuf,
    conversation_seat: SeatId,
) {
    pumps.spawn(async move {
        let mut ticker = tokio::time::interval(WATCH_TICK);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let mut delivered: BTreeSet<String> = BTreeSet::new();
        let mut routed: BTreeSet<String> = BTreeSet::new();
        let mut outputs: BTreeMap<String, String> = BTreeMap::new();
        let mut nodes = NodeMemory::default();
        // Runs whose terminal findings were withheld for the pod-report
        // pump: the stored launch is read once, then answered from here
        // (a stored launch never changes once admitted).
        let mut deferred: BTreeSet<String> = BTreeSet::new();
        loop {
            ticker.tick().await;
            let Ok(capture) = read_model.capture_kinds(&[ObjectKind::KubeResource]) else {
                continue;
            };
            let views: Vec<KubeWorkloadView> = capture
                .objects
                .iter()
                .filter_map(|object| serde_json::from_value(object.value.clone()).ok())
                .collect();
            let now = time::OffsetDateTime::now_utc();
            nodes.observe(&views);
            // Routines that follow pod outcomes.
            for (event, view, finished) in outcomes(&views, now) {
                if !routed.insert(view.resource.uid.clone()) {
                    continue;
                }
                let output = match &kube {
                    Some(cell) => capture_output(cell, &state_root, view, &conversation_seat).await,
                    None => None,
                };
                let exports = match &kube {
                    Some(cell) => {
                        let remembered = nodes.node_of(&view.resource.uid);
                        capture_exports(cell, &state_root, view, remembered, &conversation_seat)
                            .await
                    }
                    None => None,
                };
                let clauses = format!(
                    "{}{}",
                    output_clause(output.as_deref()),
                    exports_clause(exports.as_deref())
                );
                if !clauses.is_empty() {
                    outputs.insert(view.resource.uid.clone(), clauses.clone());
                }
                let runtime = Arc::clone(&runtime);
                let (uid, profile) = (view.resource.uid.clone(), view.profile.clone());
                let detail = format!(
                    "pod {} ({}) {}{}",
                    view.resource.name,
                    profile.as_deref().unwrap_or("no profile"),
                    if event == RoutineEvent::WorkloadSucceeded {
                        "finished successfully"
                    } else {
                        "failed"
                    },
                    clauses,
                );
                let occurred =
                    i64::try_from(finished.unix_timestamp_nanos() / 1_000_000).unwrap_or(i64::MAX);
                match tokio::task::spawn_blocking(move || {
                    runtime.routine_event(event, profile.as_deref(), &uid, &detail, occurred)
                })
                .await
                {
                    Ok(Ok(_)) => {}
                    Ok(Err(error)) => tracing::error!("routine event not queued: {error}"),
                    Err(error) => tracing::error!("routine event not queued: {error}"),
                }
            }
            for mut finding in findings(&views, now, |run_id| {
                if deferred.contains(run_id.as_str()) {
                    return true;
                }
                let Some(cell) = kube.as_ref() else {
                    return false;
                };
                if run_declares_agent(cell, run_id) {
                    deferred.insert(run_id.as_str().to_owned());
                    tracing::warn!("pod finding deferred to pod report run={}", run_id.as_str());
                    true
                } else {
                    false
                }
            }) {
                if delivered.contains(&finding.key) {
                    continue;
                }
                let uid = finding.key.rsplit_once(':').map_or("", |(uid, _)| uid);
                if let Some(clauses) = outputs.get(uid) {
                    finding.text.push_str(clauses);
                }
                match route_finding(&owner, &runtime, finding.clone()).await {
                    Ok(key) => {
                        delivered.insert(key);
                    }
                    Err(error) => tracing::error!("workload finding not delivered: {error}"),
                }
            }
        }
    });
}

fn output_clause(artifact: Option<&str>) -> String {
    artifact.map_or_else(String::new, |artifact| {
        format!("; its output is artifact {artifact} (read it, send it, or pass it to the next pod as an input)")
    })
}

/// Missing or unreadable admission evidence keeps the watch notification.
fn run_declares_agent(cell: &KubeRuntimeCell, run_id: &odin_domain::RunId) -> bool {
    let Some(control) = cell.control() else {
        return false;
    };
    match control.reconciler().stored_launch(run_id) {
        Ok(Some(launch)) => launch.workload.is_some_and(|plan| plan.agent.is_some()),
        Ok(None) => false,
        Err(error) => {
            tracing::error!(
                "pod agent plan unread run={} reason={error}",
                run_id.as_str()
            );
            false
        }
    }
}

/// Delivers one finding once: to the launching seat's live session, or —
/// when that session is gone — as a conversation wake, so nothing is
/// silently dropped. Returns the finding key.
pub(super) async fn route_finding(
    owner: &Arc<odin_omp::host_tools::delegation::GovernedTaskOwner>,
    runtime: &Arc<odin_hermes::runtime::HermesRuntime>,
    finding: Finding,
) -> Result<String, String> {
    let (owner, runtime) = (Arc::clone(owner), Arc::clone(runtime));
    tokio::task::spawn_blocking(move || {
        let to_seat = finding
            .session
            .map(|session| owner.notify_child(session, &finding.text));
        match to_seat {
            Some(Ok(())) => Ok(finding.key),
            _ => runtime
                .wake_once(&format!("workload-{}", finding.key), &finding.text)
                .map(|_| finding.key),
        }
    })
    .await
    .map_err(|error| error.to_string())
    .and_then(|result| result)
}

/// The launching live session of an Odin-owned run: `run:live:<session>`, or
/// a pod's own run under it, `run:live:<session>:pod:<profile>`.
pub(super) fn launching_session(run_id: &odin_domain::RunId) -> Option<LiveSessionId> {
    let rest = run_id.as_str().strip_prefix("run:live:")?;
    let session = rest
        .split_once(":pod:")
        .map_or(rest, |(session, _)| session);
    LiveSessionId::parse(session).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use odin_domain::huginn::{KubeContainerView, KubeResourceRef, KubeResources};
    use odin_domain::{LaneId, RunId, SeatId};

    /// Rebinds the fixture workload to a run named like the given pod run.
    fn on_run(run: &str, mut view: KubeWorkloadView) -> KubeWorkloadView {
        if let KubeResourceOwnership::Odin { run_id, .. } = &mut view.ownership {
            *run_id = RunId::new(run).unwrap();
        }
        view
    }

    fn view(
        state: KubeWorkloadState,
        restarts: u32,
        finished_ago: Option<i64>,
        now: time::OffsetDateTime,
    ) -> KubeWorkloadView {
        KubeWorkloadView {
            resource: KubeResourceRef {
                cluster: "default".into(),
                api_version: "batch/v1".into(),
                kind: "Job".into(),
                namespace: Some("default".into()),
                name: "odin-job".into(),
                uid: "uid-1".into(),
            },
            profile: None,
            ownership: KubeResourceOwnership::Odin {
                run_id: RunId::new("run:live:36fa58b0-d622-468e-869e-a0d997c19d18").unwrap(),
                attempt_id: None,
                lane_id: LaneId::new("kubert-odin").unwrap(),
                seat_id: SeatId::new("kubert").unwrap(),
            },
            revision: 1,
            state,
            node_id: None,
            containers: vec![KubeContainerView {
                name: "main".into(),
                image: "odin".into(),
                image_digest: None,
                ready: true,
                restart_count: restarts,
                requested: KubeResources::default(),
                limit: KubeResources::default(),
                usage: KubeResources::default(),
            }],
            requested: KubeResources::default(),
            limit: KubeResources::default(),
            usage: KubeResources::default(),
            usage_stale: true,
            started_at: None,
            finished_at: finished_ago.map(|minutes| now - time::Duration::minutes(minutes)),
            observed_at: now,
            stale: false,
        }
    }

    #[test]
    fn findings_are_decided_in_code_and_route_to_the_launching_session() {
        let now = time::OffsetDateTime::now_utc();
        assert!(findings(
            &[view(KubeWorkloadState::Running, 0, None, now)],
            now,
            |_| false
        )
        .is_empty());
        let failed = findings(
            &[view(KubeWorkloadState::Failed, 0, Some(2), now)],
            now,
            |_| false,
        );
        assert_eq!(failed.len(), 1);
        assert_eq!(failed[0].key, "uid-1:failed");
        assert_eq!(
            failed[0]
                .session
                .map(|session| session.to_string())
                .as_deref(),
            Some("36fa58b0-d622-468e-869e-a0d997c19d18")
        );
        assert!(failed[0].text.contains("FAILED"));
        let looping = findings(
            &[view(KubeWorkloadState::Running, 3, None, now)],
            now,
            |_| false,
        );
        assert_eq!(looping[0].key, "uid-1:crash-loop");
        // Old history is never news.
        assert!(findings(
            &[view(KubeWorkloadState::Succeeded, 0, Some(60), now)],
            now,
            |_| false
        )
        .is_empty());
    }

    #[test]
    fn a_settled_agent_pods_outcome_defers_to_the_pod_report_pump() {
        let now = time::OffsetDateTime::now_utc();
        let agent_run = "run:live:36fa58b0-d622-468e-869e-a0d997c19d18:pod:research-read";
        let is_agent = |run: &RunId| run.as_str() == agent_run;
        let finished = on_run(
            agent_run,
            view(KubeWorkloadState::Succeeded, 0, Some(2), now),
        );
        assert!(findings(std::slice::from_ref(&finished), now, is_agent).is_empty());
        let failed = on_run(agent_run, view(KubeWorkloadState::Failed, 0, Some(2), now));
        assert!(findings(&[failed], now, is_agent).is_empty());
        // The script pod beside it keeps its finding.
        let script = on_run(
            "run:live:36fa58b0-d622-468e-869e-a0d997c19d18:pod:state-counter",
            view(KubeWorkloadState::Succeeded, 0, Some(2), now),
        );
        let kept = findings(std::slice::from_ref(&script), now, is_agent);
        assert_eq!(kept.len(), 1);
        assert_eq!(kept[0].key, "uid-1:finished");
        assert_eq!(
            kept[0]
                .session
                .map(|session| session.to_string())
                .as_deref(),
            Some("36fa58b0-d622-468e-869e-a0d997c19d18")
        );
        // A crash-looping agent pod is still news: its session cannot
        // report a pod that never settles.
        let looping = on_run(agent_run, view(KubeWorkloadState::Running, 3, None, now));
        let crash = findings(&[looping], now, is_agent);
        assert_eq!(crash.len(), 1);
        assert_eq!(crash[0].key, "uid-1:crash-loop");
    }

    #[test]
    fn a_finished_pod_keeps_the_node_it_ran_on() {
        let now = time::OffsetDateTime::now_utc();
        let mut running = view(KubeWorkloadState::Running, 0, None, now);
        running.node_id = Some(odin_domain::NodeId::new("pc").unwrap());
        let finished = view(KubeWorkloadState::Failed, 0, Some(1), now);
        assert!(
            finished.node_id.is_none(),
            "a deadline-ended Job names no node"
        );
        let mut nodes = NodeMemory::default();
        nodes.observe(std::slice::from_ref(&running));
        nodes.observe(std::slice::from_ref(&finished));
        assert_eq!(nodes.node_of("uid-1").as_deref(), Some("pc"));
        nodes.observe(&[]);
        assert_eq!(nodes.node_of("uid-1"), None, "gone workloads are forgotten");
    }

    #[test]
    fn a_pod_run_routes_to_its_launching_session() {
        let pod =
            RunId::new("run:live:36fa58b0-d622-468e-869e-a0d997c19d18:pod:state-counter").unwrap();
        assert_eq!(
            launching_session(&pod)
                .map(|session| session.to_string())
                .as_deref(),
            Some("36fa58b0-d622-468e-869e-a0d997c19d18")
        );
        // A later launch of the same profile (`:<generation>`) too.
        let later = RunId::new("run:live:36fa58b0-d622-468e-869e-a0d997c19d18:pod:state-counter:3")
            .unwrap();
        assert_eq!(
            launching_session(&later).map(|session| session.to_string()),
            launching_session(&pod).map(|session| session.to_string())
        );
        assert!(launching_session(&RunId::new("run.unowned").unwrap()).is_none());
    }
}
