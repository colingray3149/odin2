//! The kernel's workload watch: a code-only cycle over the kube read model
//! that turns Odin-owned workload state into findings — finished, failed,
//! crash-looping — and routes each finding once to its project's standing
//! workload owner when declared, otherwise to the launching session. A settled
//! agent pod's finished/failed outcome is withheld: the pod-report pump
//! delivers the pod's answer (or its failure) once and releases the Job.
//! Script pods and every crash-loop still reach the responsible seat.
//! Healthy workloads cost no model call at all.

use std::collections::{BTreeMap, BTreeSet};
use std::future::Future;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration as StdDuration;

use kube::api::{ListParams, LogParams};
use odin_domain::huginn::{
    KubeResourceOwnership, KubeWorkloadState, KubeWorkloadView, LiveSessionId, ObjectKind,
};
use odin_domain::{RunId, SeatId};
use odin_hermes::runtime::shared_files::HostFileRoute;
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

#[derive(Clone, Copy)]
struct WatchPolicy {
    tick: StdDuration,
    crash_loop_restarts: u32,
    report_window: time::Duration,
    max_output_bytes: i64,
}

impl Default for WatchPolicy {
    fn default() -> Self {
        Self {
            tick: WATCH_TICK,
            crash_loop_restarts: CRASH_LOOP_RESTARTS,
            report_window: REPORT_WINDOW,
            max_output_bytes: MAX_OUTPUT_BYTES,
        }
    }
}

fn watch_policy(runtime: &odin_hermes::runtime::HermesRuntime) -> WatchPolicy {
    let declared = runtime.registry_pin().and_then(|pin| {
        pin.current()
            .objects
            .iter()
            .find_map(|object| match &object.config {
                odin_registry::ObjectConfig::Node(node)
                    if node.enabled && node.authoritative_state =>
                {
                    node.workload_watch
                }
                _ => None,
            })
    });
    policy_from_declaration(declared)
}

fn policy_from_declaration(
    declared: Option<odin_registry::schema::WorkloadWatchToml>,
) -> WatchPolicy {
    let mut policy = WatchPolicy::default();
    if let Some(declared) = declared {
        if let Some(value) = declared.tick_seconds {
            policy.tick = StdDuration::from_secs(value.get().into());
        }
        if let Some(value) = declared.crash_loop_restarts {
            policy.crash_loop_restarts = value.get();
        }
        if let Some(value) = declared.report_window_seconds {
            policy.report_window = time::Duration::seconds(value.get().into());
        }
        if let Some(value) = declared.max_output_bytes {
            policy.max_output_bytes = value.get().into();
        }
    }
    policy
}

/// The daemon's authority and brain bindings for opening a project owner.
/// Serializing wake-or-open prevents concurrent findings from creating two
/// standing sessions for the same project.
struct OwnerOpener {
    config: odin_huginn::OdindConfig,
    brains: BTreeMap<SeatId, Arc<odin_brain::service::BrainService>>,
    lock: tokio::sync::Mutex<()>,
}

static OWNER_OPENER: std::sync::OnceLock<OwnerOpener> = std::sync::OnceLock::new();

pub(super) fn install_owner_opener(
    config: odin_huginn::OdindConfig,
    brains: BTreeMap<SeatId, Arc<odin_brain::service::BrainService>>,
) {
    let _ = OWNER_OPENER.set(OwnerOpener {
        config,
        brains,
        lock: tokio::sync::Mutex::new(()),
    });
}

fn owner_brief(
    project: &odin_domain::ProjectId,
    gathered: odin_brain::service::fresh_sources::FreshKnowledge,
    policy: &odin_omp::live::rollover::RolloverPolicy,
) -> Result<String, String> {
    use odin_omp::live::rollover::{
        FreshBriefMemory, FreshBriefNote, FreshBriefRepo, FreshBriefSources,
    };
    let sources = FreshBriefSources {
        notes: gathered
            .notes
            .into_iter()
            .map(|n| FreshBriefNote {
                task: n.task,
                seat: n.seat,
                noted_at: n.noted_at,
                note: n.note,
            })
            .collect(),
        project_memory: gathered
            .project_memory
            .into_iter()
            .map(|m| FreshBriefMemory {
                source: m.source,
                text: m.text,
            })
            .collect(),
        repos: gathered
            .repos
            .into_iter()
            .map(|r| FreshBriefRepo {
                project: r.project,
                summary: r.summary,
            })
            .collect(),
        reason: format!(
            "standing workload owner for {project}; sources unavailable: {}",
            gathered.unavailable.join("; ")
        ),
        owner_text: String::new(),
    };
    let (_, brief) = odin_omp::live::rollover::render_fresh_brief(&sources, policy)?;
    String::from_utf8(brief).map_err(|error| error.to_string())
}

/// A failed wake is not evidence that no session exists: only an explicit
/// `false` may open another owner.
async fn wake_or_open<W, O, WF, OF>(wake: W, open: O) -> Result<(), String>
where
    W: FnOnce() -> WF,
    O: FnOnce() -> OF,
    WF: Future<Output = Result<bool, String>>,
    OF: Future<Output = Result<(), String>>,
{
    if !wake().await? {
        open().await?;
    }
    Ok(())
}

async fn wake_or_open_owner(
    live: &odin_omp::live::service::OmpLiveService,
    seat: &SeatId,
    project: &odin_domain::ProjectId,
    id: &str,
    text: &str,
) -> Result<(), String> {
    let opener = OWNER_OPENER
        .get()
        .ok_or("workload owner opener unavailable")?;
    let _guard = opener.lock.lock().await;
    let route = odin_omp::live::service::WakeRoute::Project(project.clone());
    wake_or_open(
        || async {
            live.wake_seat(seat, id, text, Some(&route))
                .await
                .map_err(|error| error.to_string())
        },
        || open_owner(opener, live, seat, project, text),
    )
    .await
}

async fn open_owner(
    opener: &OwnerOpener,
    live: &odin_omp::live::service::OmpLiveService,
    seat: &SeatId,
    project: &odin_domain::ProjectId,
    text: &str,
) -> Result<(), String> {
    use odin_domain::huginn::{LiveContentBlock, LiveMessage, OmpLivePlane, OpenSessionRequest};
    let binding = opener
        .config
        .seats
        .iter()
        .find(|binding| binding.seat == *seat)
        .ok_or_else(|| format!("workload owner {seat} has no seat binding"))?;
    let launch = binding
        .launch_options
        .first()
        .ok_or_else(|| format!("workload owner {seat} has no launch option"))?;
    let brain = opener
        .brains
        .get(seat)
        .ok_or_else(|| format!("workload owner {seat} has no brain"))?;
    let gathered = brain
        .fresh_knowledge(Some(project))
        .map_err(|error| error.to_string())?;
    let command = odin_domain::CommandId::new(format!("workload-owner:{}", uuid::Uuid::new_v4()))
        .map_err(|e| e.to_string())?;
    let composition = odin_cli::authority_provision::compose(
        &opener.config,
        seat.as_str(),
        project.as_str(),
        &command,
        odin_cli::authority_provision::LaunchSelection::new(
            launch.provider.as_str(),
            launch.model.as_str(),
        ),
    )?;
    let (snapshot, _) = odin_registry::SnapshotStore::new(&opener.config.paths.registry_snapshot)
        .publication_at(composition.snapshot_revision)
        .map_err(|error| format!("workload owner publication unavailable: {error}"))?;
    let owns_workloads = snapshot.objects.iter().any(|object| {
        object.id == composition.lane.as_str()
            && matches!(&object.config, odin_registry::ObjectConfig::Lane(lane)
                if lane.enabled && lane.owns_workloads && lane.project == *project && lane.default_seat == *seat)
    });
    if !owns_workloads {
        return Err(format!(
            "workload owner {seat} project {project} composes lane {}, not its owned lane",
            composition.lane
        ));
    }
    let inputs =
        odin_cli::runtime_bindings::RuntimeInputs::parse(&opener.config, &snapshot.objects)?;
    let policy = inputs
        .rollover_seats
        .get(seat)
        .map(|declared| declared.policy())
        .unwrap_or_else(|| odin_omp::live::rollover::RolloverPolicy {
            max_brief_bytes: odin_registry::schema::SeatRolloverToml::default().max_brief_bytes,
            ..Default::default()
        });
    let brief = owner_brief(project, gathered, &policy)?;
    odin_cli::authority_provision::mint_for_child_session(
        &opener.config,
        &composition,
        odin_cli::authority_provision::DEFAULT_TOKEN_TTL_SECONDS,
    )?;
    live.open_session(OpenSessionRequest {
        command_id: command,
        seat_id: composition.seat,
        project_id: composition.project,
        slice_id: composition.slice,
        provider: launch.provider.clone(),
        model: launch.model.clone(),
        title: Some(format!("workload owner {project}")),
        target_node: odin_domain::NodeId::new(&opener.config.identity.node).map_err(|e| e.to_string())?,
        open_tab: false,
        initial_prompt: Some(LiveMessage {
            content: vec![LiveContentBlock::Text(format!(
                "You are the standing workload owner for project {project}. Use this project context to handle the finding.\n\n{brief}\n\n{text}"
            ))],
        }),
        workload: None,
        served_revision: Some(composition.snapshot_revision),
    }).await.map_err(|e| e.to_string())?;
    Ok(())
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Finding {
    /// Stable identity: the workload uid plus the finding kind.
    pub(crate) key: String,
    /// The launching session (`run:live:<session>`), when it is a live one.
    pub(crate) session: Option<LiveSessionId>,
    /// Who raised it, in the line that tells the seat this is not the owner speaking.
    pub(crate) source: &'static str,
    pub(crate) text: String,
    /// The workload's lane: its project's `owns_workloads` lane takes the
    /// finding first, and `<watch>:<project>` seats hear it.
    pub(crate) lane: Option<odin_domain::LaneId>,
}

/// Agent terminal outcomes belong to the pod-report pump; crash loops do not.
#[cfg(test)]
fn findings(
    views: &[KubeWorkloadView],
    now: time::OffsetDateTime,
    is_agent_run: impl FnMut(&odin_domain::RunId) -> bool,
) -> Vec<Finding> {
    findings_with_policy(views, now, &WatchPolicy::default(), is_agent_run)
}

fn findings_with_policy(
    views: &[KubeWorkloadView],
    now: time::OffsetDateTime,
    policy: &WatchPolicy,
    mut is_agent_run: impl FnMut(&odin_domain::RunId) -> bool,
) -> Vec<Finding> {
    let mut found = Vec::new();
    for view in views {
        let KubeResourceOwnership::Odin {
            run_id,
            seat_id,
            lane_id,
            ..
        } = &view.ownership
        else {
            continue;
        };
        let recent = view
            .finished_at
            .is_none_or(|finished| now - finished <= policy.report_window);
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
            KubeWorkloadState::Running if restarts >= policy.crash_loop_restarts => (
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
            source: "workload watch",
            text: format!(
                "The {text}; it was launched by seat {seat_id}. Check it with your workload \
                 tools, act within your declared capabilities if something is wrong, and report \
                 the outcome plainly."
            ),
            lane: Some(lane_id.clone()),
        });
    }
    found
}

/// Odin pods that finished within the report window, with the routine
/// event each outcome is and when it happened.
fn outcomes<'a>(
    views: &'a [KubeWorkloadView],
    now: time::OffsetDateTime,
    policy: &WatchPolicy,
) -> Vec<(RoutineEvent, &'a KubeWorkloadView, time::OffsetDateTime)> {
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
            (now - finished <= policy.report_window).then_some((event, view, finished))
        })
        .collect()
}

/// What a finished pod's log yields: its stored output artifact, and the
/// `summary` of its newest status line (a dm's `{summary}`).
#[derive(Default)]
struct PodOutput {
    artifact: Option<String>,
    summary: Option<String>,
}

/// A finished pod's output — its container log through the kube API,
/// bounded — kept as an artifact readable by the launching seat and the
/// conversation seat: the next stage of a chain takes it
/// as input, Sinmara can send it to the owner, and nothing is read off a host
/// path. Every miss is logged, never fatal.
async fn capture_output(
    cell: &KubeRuntimeCell,
    state_root: &std::path::Path,
    view: &KubeWorkloadView,
    conversation_seat: &SeatId,
    max_output_bytes: i64,
) -> PodOutput {
    let KubeResourceOwnership::Odin {
        seat_id, run_id, ..
    } = &view.ownership
    else {
        return PodOutput::default();
    };
    // An agent pod's files came back with its report.
    if stored_plan(cell, run_id).is_some_and(|plan| plan.agent.is_some()) {
        return PodOutput::default();
    }
    let job = view.resource.name.as_str();
    let miss = |reason: String| {
        tracing::error!("pod output not captured job={job} reason={reason}");
        PodOutput::default()
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
                limit_bytes: Some(max_output_bytes),
                ..LogParams::default()
            },
        )
        .await
    {
        Ok(log) if log.trim().is_empty() => return miss("it printed nothing".to_owned()),
        Ok(log) => log,
        Err(error) => return miss(format!("its log could not be read: {error}")),
    };
    let summary = odin_kube::telemetry::latest_summary(&log);
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
            PodOutput {
                artifact: Some(metadata.artifact_id.to_string()),
                summary,
            }
        }
        Ok(Err(error)) => PodOutput {
            summary,
            ..miss(error)
        },
        Err(error) => PodOutput {
            summary,
            ..miss(error.to_string())
        },
    }
}

use odin_omp::host_tools::pod_exec::MAX_EXPORT_BYTES;

/// Where a finished run's export is delivered: the declared files root, the
/// run's folder under it, and the launching seat the root is opened to.
struct ExportDelivery {
    route: Arc<dyn HostFileRoute>,
    root: String,
    folder: String,
    seat: String,
}

/// The launch plan persisted for this run, when it can be read.
fn stored_plan(
    cell: &KubeRuntimeCell,
    run_id: &RunId,
) -> Option<odin_kube::workload::WorkloadPodPlan> {
    let control = cell.control()?;
    match control.reconciler().stored_launch(run_id) {
        Ok(launch) => launch?.workload,
        Err(error) => {
            tracing::error!("pod plan unread run={} reason={error}", run_id.as_str());
            None
        }
    }
}

/// Unpacks a captured export into `<root>/<folder>/`, one save per file
/// through the same files route the report copies use. Returns the files saved.
fn deliver_export(delivery: &ExportDelivery, tar: &[u8]) -> Result<usize, String> {
    let files = odin_kube::state_carry::tar_regular_files(tar)?;
    let count = files.len();
    for (path, bytes) in files {
        let (folder, name) = match path.rsplit_once('/') {
            Some((directory, name)) => (format!("{}/{directory}", delivery.folder), name),
            None => (delivery.folder.clone(), path.as_str()),
        };
        crate::report_settle::save_into_root(
            delivery.route.as_ref(),
            &delivery.seat,
            &delivery.root,
            Some(&folder),
            name,
            bytes,
        )
        .map_err(|error| format!("{path}: {error}"))?;
    }
    Ok(count)
}

/// A finished pod's exported files — its run's own folder under the
/// declared export host folder, on whichever node it ran — kept as one tar
/// artifact readable by the launching seat and the conversation seat
/// , so a chain passes files, not just logs. When the profile declares
/// `export.deliver_root`, the files are also unpacked under that root as
/// `<run>-<label>/`; a delivery failure is logged and the run stands.
/// Returns the artifact id; an empty export or a pod without one is no artifact.
async fn capture_exports(
    cell: &KubeRuntimeCell,
    state_root: &std::path::Path,
    view: &KubeWorkloadView,
    remembered_node: Option<String>,
    conversation_seat: &SeatId,
    runtime: &Arc<odin_hermes::runtime::HermesRuntime>,
) -> Option<String> {
    let KubeResourceOwnership::Odin {
        seat_id, run_id, ..
    } = &view.ownership
    else {
        return None;
    };
    // An agent pod's files came back with its report.
    if stored_plan(cell, run_id).is_some_and(|plan| plan.agent.is_some()) {
        return None;
    }
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
    let delivery = stored_plan(cell, run_id)
        .and_then(|plan| plan.export_deliver_root)
        .and_then(|root| match runtime.host_file_route() {
            Some(route) => Some(ExportDelivery {
                route,
                root,
                folder: match view.profile.as_deref() {
                    Some(label) => format!("{}-{label}", run_id.as_str()),
                    None => run_id.as_str().to_owned(),
                },
                seat: seat_id.to_string(),
            }),
            None => {
                tracing::error!(
                    "pod export not delivered job={job} reason=host folders are not composed"
                );
                None
            }
        });
    let state_root = state_root.to_owned();
    let delivered_job = job.to_owned();
    let stored = tokio::task::spawn_blocking(move || {
        let stored =
            crate::coding_route::store_artifact(&state_root, &tar, "application/x-tar", &shares);
        if stored.is_ok() {
            if let Some(delivery) = delivery {
                match deliver_export(&delivery, &tar) {
                    Ok(saved) => tracing::info!(
                        "pod export delivered job={delivered_job} root={} folder={} files={saved}",
                        delivery.root,
                        delivery.folder
                    ),
                    Err(error) => {
                        tracing::error!(
                            "pod export not delivered job={delivered_job} reason={error}"
                        );
                    }
                }
            }
        }
        stored
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

/// Arms the watch: owned-project findings go to their standing owner; other
/// findings go to the launching session or the conversation seat. A finished
/// pod's output is kept as an artifact first, and both the finding and the
/// routine event name it.
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
        let mut delivered: BTreeSet<String> = BTreeSet::new();
        let mut routed: BTreeSet<String> = BTreeSet::new();
        let mut outputs: BTreeMap<String, String> = BTreeMap::new();
        let mut nodes = NodeMemory::default();
        // Runs whose terminal findings were withheld for the pod-report
        // pump: the stored launch is read once, then answered from here
        // (a stored launch never changes once admitted).
        let mut deferred: BTreeSet<String> = BTreeSet::new();
        // The views parsed at the kube objects' last change: an idle tick
        // reuses them and only re-judges them against the clock.
        let mut views: Vec<KubeWorkloadView> = Vec::new();
        let mut views_revision = None;
        let mut first = true;
        loop {
            if first {
                first = false;
            } else {
                tokio::time::sleep(watch_policy(&runtime).tick).await;
            }
            let policy = watch_policy(&runtime);
            let Ok(revision) = read_model.kinds_revision(&[ObjectKind::KubeResource]) else {
                continue;
            };
            if views_revision != Some(revision) {
                let Ok(capture) = read_model.capture_kinds(&[ObjectKind::KubeResource]) else {
                    continue;
                };
                views = capture
                    .objects
                    .iter()
                    .filter_map(|object| serde_json::from_value(object.value.clone()).ok())
                    .collect();
                views_revision = Some(revision);
            }
            let now = time::OffsetDateTime::now_utc();
            nodes.observe(&views);
            runtime.set_running_jobs(running_agent_pods(&views, kube.as_deref()));
            // Routines that follow pod outcomes.
            for (event, view, finished) in outcomes(&views, now, &policy) {
                if !routed.insert(view.resource.uid.clone()) {
                    continue;
                }
                let output = match &kube {
                    Some(cell) => {
                        capture_output(
                            cell,
                            &state_root,
                            view,
                            &conversation_seat,
                            policy.max_output_bytes,
                        )
                        .await
                    }
                    None => PodOutput::default(),
                };
                let exports = match &kube {
                    Some(cell) => {
                        let remembered = nodes.node_of(&view.resource.uid);
                        capture_exports(
                            cell,
                            &state_root,
                            view,
                            remembered,
                            &conversation_seat,
                            &runtime,
                        )
                        .await
                    }
                    None => None,
                };
                let clauses = format!(
                    "{}{}",
                    output_clause(output.artifact.as_deref()),
                    exports_clause(exports.as_deref())
                );
                if !clauses.is_empty() {
                    outputs.insert(view.resource.uid.clone(), clauses.clone());
                }
                let runtime = Arc::clone(&runtime);
                let summary = output.summary.unwrap_or_default();
                let (uid, profile, label) = (
                    view.resource.uid.clone(),
                    view.profile.clone(),
                    view.label.clone(),
                );
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
                    runtime.routine_workload_event(
                        event,
                        profile.as_deref(),
                        odin_hermes::runtime::RunFacts {
                            label: label.as_deref(),
                            summary: &summary,
                        },
                        &uid,
                        &detail,
                        occurred,
                    )
                })
                .await
                {
                    Ok(Ok(_)) => {}
                    Ok(Err(error)) => tracing::error!("routine event not queued: {error}"),
                    Err(error) => tracing::error!("routine event not queued: {error}"),
                }
            }
            for mut finding in findings_with_policy(&views, now, &policy, |run_id| {
                if deferred.contains(run_id.as_str()) {
                    return true;
                }
                let Some(cell) = kube.as_ref() else {
                    return false;
                };
                if stored_plan(cell, run_id).is_some_and(|plan| plan.agent.is_some()) {
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

/// The agent pods running now: they hold an open ask's wakes back, and live
/// memory lists each under its run id, where notes pin to it.
fn running_agent_pods(
    views: &[KubeWorkloadView],
    kube: Option<&KubeRuntimeCell>,
) -> Vec<odin_hermes::runtime::RunningJob> {
    let Some(cell) = kube else {
        return Vec::new();
    };
    views
        .iter()
        .filter(|view| {
            matches!(
                view.state,
                KubeWorkloadState::Pending
                    | KubeWorkloadState::Scheduling
                    | KubeWorkloadState::Running
            )
        })
        .filter_map(|view| {
            let KubeResourceOwnership::Odin { run_id, .. } = &view.ownership else {
                return None;
            };
            let agent = stored_plan(cell, run_id).is_some_and(|plan| plan.agent.is_some());
            agent.then(|| odin_hermes::runtime::RunningJob {
                id: run_id.as_str().to_owned(),
                title: view
                    .label
                    .clone()
                    .or_else(|| view.profile.clone())
                    .unwrap_or_else(|| view.resource.name.clone()),
                started_ms: u64::try_from(
                    view.started_at
                        .unwrap_or(view.observed_at)
                        .unix_timestamp_nanos()
                        / 1_000_000,
                )
                .unwrap_or(0),
            })
        })
        .collect()
}

/// Delivers a finding to its project's workload owner when one is declared;
/// otherwise it goes to the launching session or the conversation seat.
/// Returns the finding key only after delivery succeeds.
pub(crate) async fn route_finding(
    owner: &Arc<odin_omp::host_tools::delegation::GovernedTaskOwner>,
    runtime: &Arc<odin_hermes::runtime::HermesRuntime>,
    finding: Finding,
) -> Result<String, String> {
    let finding = Finding {
        text: format!(
            "[Odin {} — not a message from {}] {}",
            finding.source,
            runtime.owner_name(),
            finding.text
        ),
        ..finding
    };
    let (project, owning_seat) = finding
        .lane
        .as_ref()
        .map_or((None, None), |lane| runtime.workload_owner(lane));
    let (key, text) = (finding.key.clone(), finding.text.clone());
    if let (Some(project), Some(seat)) = (&project, &owning_seat) {
        let live = odin_omp::live::service::OmpLiveService::installed()
            .ok_or_else(|| format!("live service unavailable for workload owner {seat}"))?;
        wake_or_open_owner(&live, seat, project, &format!("workload-{key}"), &text)
            .await
            .map_err(|error| format!("owned-lane finding for {seat} not delivered: {error}"))?;
    } else {
        let owner = Arc::clone(owner);
        let wake_runtime = Arc::clone(runtime);
        let wake_text = text.clone();
        tokio::task::spawn_blocking(move || {
            let to_seat = finding
                .session
                .map(|session| owner.notify_child(session, &finding.text));
            match to_seat {
                Some(Ok(())) => Ok(finding.key),
                _ => {
                    let (workload, kind) =
                        finding.key.rsplit_once(':').unwrap_or((&finding.key, ""));
                    wake_runtime
                        .wake_event(
                            &format!("workload-{}", finding.key),
                            &wake_text,
                            &format!("workload:{workload}"),
                            kind,
                        )
                        .map(|_| finding.key)
                }
            }
        })
        .await
        .map_err(|error| error.to_string())
        .and_then(|result| result)?;
    }
    crate::child_report::wake_declared_except(
        runtime,
        "workload_watch",
        project.as_ref().map(odin_domain::ProjectId::as_str),
        &format!("workload-{key}"),
        &text,
        owning_seat.as_ref(),
    )
    .await;
    Ok(key)
}

/// The launching live session of an Odin-owned run: `run:live:<session>`, or
/// a pod's own run under it, `run:live:<session>:pod:<profile>`.
pub(crate) fn launching_session(run_id: &odin_domain::RunId) -> Option<LiveSessionId> {
    let rest = run_id.as_str().strip_prefix("run:live:")?;
    let session = rest
        .split_once(":pod:")
        .map_or(rest, |(session, _)| session);
    LiveSessionId::parse(session).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use odin_domain::huginn::RelativePath;
    use odin_domain::huginn::{KubeContainerView, KubeResourceRef, KubeResources};
    use odin_domain::{LaneId, RunId, SeatId};

    #[tokio::test]
    async fn missing_owner_session_opens_but_an_existing_one_does_not() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let opens = AtomicUsize::new(0);
        for present in [false, true] {
            wake_or_open(
                || async { Ok(present) },
                || async {
                    opens.fetch_add(1, Ordering::SeqCst);
                    Ok(())
                },
            )
            .await
            .unwrap();
        }
        assert_eq!(opens.load(Ordering::SeqCst), 1);
        let refused = wake_or_open(
            || async { Err("wake refused".to_owned()) },
            || async {
                opens.fetch_add(1, Ordering::SeqCst);
                Ok(())
            },
        )
        .await;
        assert_eq!(refused.unwrap_err(), "wake refused");
        assert_eq!(opens.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn fresh_owner_brief_carries_project_notes_and_memory() {
        use odin_brain::service::fresh_sources::{FreshKnowledge, GatheredMemory, GatheredNote};
        let gathered = FreshKnowledge {
            notes: vec![GatheredNote {
                task: "campaign".into(),
                seat: "kubert".into(),
                noted_at: "now".into(),
                note: "watch batch 7".into(),
            }],
            project_memory: vec![GatheredMemory {
                source: "memory.project.example".into(),
                text: "campaign limits".into(),
            }],
            unavailable: vec!["state.repos unavailable".into()],
            ..Default::default()
        };
        let brief = owner_brief(
            &odin_domain::ProjectId::new("example").unwrap(),
            gathered,
            &odin_omp::live::rollover::RolloverPolicy::default(),
        )
        .unwrap();
        let json: serde_json::Value = serde_json::from_str(&brief).unwrap();
        assert_eq!(json["task_notes"][0]["note"], "watch batch 7");
        assert_eq!(
            json["project_memory"][0]["source"],
            "memory.project.example"
        );
        assert_eq!(json["project_memory"][0]["text"], "campaign limits");
        assert!(json["reason"]
            .as_str()
            .unwrap()
            .contains("state.repos unavailable"));
    }

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
            label: None,
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
            status: None,
            observed_at: now,
            stale: false,
        }
    }

    #[test]
    fn watch_policy_falls_back_and_uses_each_new_declaration() {
        let defaults = policy_from_declaration(None);
        let first = odin_registry::schema::WorkloadWatchToml {
            tick_seconds: std::num::NonZeroU32::new(7),
            crash_loop_restarts: std::num::NonZeroU32::new(4),
            report_window_seconds: None,
            max_output_bytes: None,
        };
        let resolved = policy_from_declaration(Some(first));
        assert_eq!(resolved.tick, StdDuration::from_secs(7));
        assert_eq!(resolved.crash_loop_restarts, 4);
        assert_eq!(resolved.report_window, defaults.report_window);
        assert_eq!(resolved.max_output_bytes, defaults.max_output_bytes);
        let refreshed = policy_from_declaration(Some(odin_registry::schema::WorkloadWatchToml {
            tick_seconds: std::num::NonZeroU32::new(11),
            report_window_seconds: std::num::NonZeroU32::new(60),
            ..first
        }));
        assert_eq!(refreshed.tick, StdDuration::from_secs(11));
        assert_eq!(refreshed.report_window, time::Duration::seconds(60));
        assert_eq!(policy_from_declaration(None).tick, defaults.tick);
    }

    #[test]
    fn findings_obey_the_configured_restart_and_report_bounds() {
        let now = time::OffsetDateTime::now_utc();
        let policy = WatchPolicy {
            crash_loop_restarts: 5,
            report_window: time::Duration::minutes(1),
            ..WatchPolicy::default()
        };
        let running = view(KubeWorkloadState::Running, 4, None, now);
        assert!(findings_with_policy(&[running], now, &policy, |_| false).is_empty());
        let looping = view(KubeWorkloadState::Running, 5, None, now);
        assert_eq!(
            findings_with_policy(&[looping], now, &policy, |_| false)[0].key,
            "uid-1:crash-loop"
        );
        let old = view(KubeWorkloadState::Failed, 0, Some(2), now);
        assert!(findings_with_policy(&[old], now, &policy, |_| false).is_empty());
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
        let agent_run = "run:live:36fa58b0-d622-468e-869e-a0d997c19d18:pod:research";
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

    /// A test route that saves under its root directory, as the files route
    /// does for a local root: `<base>/<root>/<folder>/<name>`.
    struct FolderRoute(std::path::PathBuf);

    impl HostFileRoute for FolderRoute {
        fn roots(&self, _: &str) -> Vec<serde_json::Value> {
            Vec::new()
        }
        fn list(
            &self,
            _: &str,
            _: &str,
            _: Option<&str>,
            _: Option<&str>,
        ) -> Result<(Vec<serde_json::Value>, bool), String> {
            Err("not used by delivery".to_owned())
        }
        fn read(
            &self,
            _: &str,
            _: &str,
            _: &str,
        ) -> Result<(String, String, std::fs::File), String> {
            Err("not used by delivery".to_owned())
        }
        fn save(
            &self,
            seat: &str,
            root: Option<&str>,
            folder: Option<&str>,
            name: &str,
            source: &mut std::fs::File,
            _: Option<&odin_hermes::runtime::shared_files::RootSource>,
        ) -> Result<serde_json::Value, String> {
            assert_eq!((seat, root), ("sinmara", Some("exports")));
            // The files route's own folder rule: no escapes, no empty segments.
            if let Some(folder) = folder {
                RelativePath::parse(folder).map_err(|error| error.to_string())?;
            }
            let directory = self.0.join("exports").join(folder.unwrap_or_default());
            std::fs::create_dir_all(&directory).map_err(|error| error.to_string())?;
            let mut target =
                std::fs::File::create(directory.join(name)).map_err(|error| error.to_string())?;
            std::io::copy(source, &mut target).map_err(|error| error.to_string())?;
            Ok(serde_json::json!({ "status": "completed" }))
        }
        fn save_status(&self, _: &str, _: &str) -> Result<serde_json::Value, String> {
            Err("not used by delivery".to_owned())
        }
    }

    /// A ustar archive of regular files, as the pod's export folder tars.
    fn tar_of(files: &[(&str, &[u8])]) -> Vec<u8> {
        let mut tar = Vec::new();
        for (name, bytes) in files {
            let mut header = [0u8; 512];
            header[..name.len()].copy_from_slice(name.as_bytes());
            header[124..136].copy_from_slice(format!("{:011o}\0", bytes.len()).as_bytes());
            header[156] = b'0';
            header[257..263].copy_from_slice(b"ustar\0");
            tar.extend(header);
            tar.extend(*bytes);
            tar.resize(tar.len().next_multiple_of(512), 0);
        }
        tar.extend([0u8; 1024]);
        tar
    }

    #[test]
    fn a_delivered_export_lands_under_the_declared_root() {
        let base = tempfile::tempdir().unwrap();
        let delivery = ExportDelivery {
            route: Arc::new(FolderRoute(base.path().to_owned())),
            root: "exports".to_owned(),
            folder: "run:live:s1:pod:heat-sim-heat-sim".to_owned(),
            seat: "sinmara".to_owned(),
        };
        let tar = tar_of(&[
            ("./result.csv", b"iteration,residual\n40,1e-5\n"),
            ("./plots/a.png", b"png"),
        ]);
        assert_eq!(deliver_export(&delivery, &tar), Ok(2));
        let landed = base
            .path()
            .join("exports/run:live:s1:pod:heat-sim-heat-sim");
        assert_eq!(
            std::fs::read(landed.join("result.csv")).unwrap(),
            b"iteration,residual\n40,1e-5\n"
        );
        assert_eq!(std::fs::read(landed.join("plots/a.png")).unwrap(), b"png");
        let escape = tar_of(&[("../outside.txt", b"x")]);
        assert!(deliver_export(&delivery, &escape).is_err());
        assert!(!base.path().join("outside.txt").exists());
    }
}
