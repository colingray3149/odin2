//! The monitoring kernel: every running Odin workload is watched under its
//! container profile's declared `[monitoring]` cadence and `watchdogs`
//! alerts. A pod reports counters on stdout as `ODIN-STATUS {"likes": 3}`
//! lines; code reads every one printed since its last read each cadence, evaluates every declared
//! condition using consecutive-hit and cooldown settings, and applies the
//! declared action — notify the launching seat, or cancel the workload and
//! then tell it. Healthy workloads cost no model call.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::Arc;
use std::time::{Duration as StdDuration, Instant};

use kube::api::{ListParams, LogParams};
use odin_domain::huginn::{
    AbortScope, EventSeq, HistoryQuery, KubeOperationKind, KubeResourceOwnership,
    KubeWorkloadState, KubeWorkloadStatus, LiveCommandBody, LiveEventBody, LiveSessionId,
    LiveSessionState, LiveSessionSummary, OmpLivePlane,
};
use odin_domain::{Digest, NodeId};
use odin_kube::job::{JobAction, JOB_LABEL_CONTAINER_IDENTITY};
use odin_kube::telemetry::{latest_report, numeric_counters, reports_since, STATUS_TAIL_LINES};
use odin_registry::schema::{
    AlertCondition, ContainerAlertActionToml, ContainerAlertToml, ContainerMonitoringToml,
    ContainerToml, ContainerWatchdogToml, WorkloadMonitoringToml,
};
use odin_types::OperationId;
use serde_json::{Map, Value};
use time::OffsetDateTime;

use super::workload_review::{note, send, tell_worker, worker_session, Acting};
use super::workload_watch::{launching_session, route_finding, Finding};
use crate::kube::KubeRuntimeCell;

const MONITOR_TICK: StdDuration = StdDuration::from_secs(15);

pub(super) struct MonitorProfile {
    pub(super) cadence: StdDuration,
    pub(super) alerts: Vec<(ContainerAlertToml, AlertCondition)>,
    /// Declared anti-stuck recovery.
    /// Log lines read per check.
    pub(super) tail_lines: i64,
    pub(super) stall: Option<StallPolicy>,
    /// How long a running pod's session may journal nothing before it is resumed, then restarted.
    pub(super) silence: Option<StdDuration>,
}

/// A pod's declared progress counter, stall window and recovery ladder.
pub(super) struct StallPolicy {
    pub(super) counter: String,
    pub(super) window: StdDuration,
    pub(super) policy: odin_kernel::recovery::RecoveryPolicy,
}

impl MonitorProfile {
    /// Monitoring is active when at least one parsed alert or stall policy exists.
    pub(super) fn of_workload(monitoring: &WorkloadMonitoringToml) -> Option<Self> {
        let alerts: Vec<_> = monitoring
            .watchdogs
            .iter()
            .filter_map(|alert| {
                AlertCondition::parse(&alert.condition)
                    .ok()
                    .map(|condition| (alert.clone(), condition))
            })
            .collect();
        let stall = match (
            &monitoring.progress,
            monitoring.stall_seconds,
            &monitoring.recovery,
        ) {
            (Some(counter), Some(window), Some(recovery)) => {
                match super::workload_recovery::pod_policy(recovery) {
                    Ok(policy) => Some(StallPolicy {
                        counter: counter.clone(),
                        window: StdDuration::from_secs(u64::from(window.get())),
                        policy,
                    }),
                    Err(error) => {
                        tracing::error!("pod recovery ladder unusable: {error}");
                        None
                    }
                }
            }
            _ => None,
        };
        // A stall window with no counter or ladder bounds the pod's silence instead.
        let silence = match (
            &monitoring.progress,
            monitoring.stall_seconds,
            &monitoring.recovery,
        ) {
            (None, Some(seconds), None) => Some(StdDuration::from_secs(u64::from(seconds.get()))),
            _ => None,
        };
        (!alerts.is_empty() || stall.is_some() || silence.is_some()).then(|| Self {
            cadence: StdDuration::from_secs(u64::from(monitoring.cadence_seconds.get())),
            tail_lines: monitoring
                .status_tail_lines
                .map_or(STATUS_TAIL_LINES, |lines| i64::from(lines.get())),
            alerts,
            stall,
            silence,
        })
    }

    pub(super) fn of(container: &ContainerToml) -> Option<Self> {
        let ContainerMonitoringToml::Policy(policy) = &container.monitoring else {
            return None;
        };
        let alerts: Vec<_> = container
            .watchdogs
            .iter()
            .filter_map(|watchdog| match watchdog {
                ContainerWatchdogToml::Alert(alert) => AlertCondition::parse(&alert.condition)
                    .ok()
                    .map(|condition| (alert.clone(), condition)),
                ContainerWatchdogToml::Script(_) => None,
            })
            .collect();
        (!alerts.is_empty()).then(|| Self {
            cadence: StdDuration::from_secs(u64::from(policy.cadence_seconds.get())),
            tail_lines: STATUS_TAIL_LINES,
            alerts,
            stall: None,
            silence: None,
        })
    }
}

/// Consecutive-hit counting and cooldown per (workload, alert).
#[derive(Default)]
pub(super) struct AlertTracker {
    state: HashMap<(String, String), (u16, Option<Instant>)>,
}

impl AlertTracker {
    /// Records one evaluation and returns the alerts that fire now, with
    /// the counter value that fired them. A miss (or an unreported counter)
    /// resets the streak.
    pub(super) fn observe<'a>(
        &mut self,
        workload: &str,
        profile: &'a MonitorProfile,
        counters: &BTreeMap<String, f64>,
        now: Instant,
    ) -> Vec<(&'a ContainerAlertToml, f64)> {
        let mut fired = Vec::new();
        for (alert, condition) in &profile.alerts {
            let (hits, last) = self
                .state
                .entry((workload.to_owned(), alert.id.clone()))
                .or_default();
            match counters.get(&condition.counter) {
                Some(&value) if condition.holds(value) => {
                    *hits = hits.saturating_add(1);
                    let cooled = last.is_none_or(|at| {
                        now.duration_since(at)
                            >= StdDuration::from_secs(u64::from(alert.cooldown_seconds))
                    });
                    if *hits >= alert.consecutive_hits.get() && cooled {
                        *hits = 0;
                        *last = Some(now);
                        fired.push((alert, value));
                    }
                }
                _ => *hits = 0,
            }
        }
        fired
    }

    /// Records each sample read since the last tick, oldest first, so a spike between
    /// cadences counts; an alert fires at most once per tick, with its firing value.
    pub(super) fn observe_all<'a>(
        &mut self,
        workload: &str,
        profile: &'a MonitorProfile,
        samples: &[BTreeMap<String, f64>],
        now: Instant,
    ) -> Vec<(&'a ContainerAlertToml, f64)> {
        let mut fired: Vec<(&'a ContainerAlertToml, f64)> = Vec::new();
        for counters in samples {
            for (alert, value) in self.observe(workload, profile, counters, now) {
                if !fired.iter().any(|(seen, _)| seen.id == alert.id) {
                    fired.push((alert, value));
                }
            }
        }
        fired
    }

    pub(super) fn retain(&mut self, live: &BTreeSet<String>) {
        self.state
            .retain(|(workload, _), _| live.contains(workload));
    }
}

/// The incidents the monitor holds open per running workload (by uid): a
/// watchdog whose condition stops holding, or a pod that is gone, clears
/// its incident, so the next breach is news again.
#[derive(Default)]
pub(super) struct OpenIncidents {
    open: BTreeMap<String, BTreeMap<String, String>>,
}

impl OpenIncidents {
    /// `key` (a watchdog id, or `stall`) of workload `uid` raised `signature`.
    pub(super) fn opened(&mut self, uid: &str, key: &str, signature: String) {
        self.open
            .entry(uid.to_owned())
            .or_default()
            .insert(key.to_owned(), signature);
    }

    /// The signatures of `uid`'s watchdogs whose counter was read and whose
    /// condition no longer holds.
    pub(super) fn settled(
        &mut self,
        uid: &str,
        profile: &MonitorProfile,
        counters: &BTreeMap<String, f64>,
    ) -> Vec<String> {
        let Some(open) = self.open.get_mut(uid) else {
            return Vec::new();
        };
        let mut settled = Vec::new();
        for (alert, condition) in &profile.alerts {
            if counters
                .get(&condition.counter)
                .is_some_and(|value| !condition.holds(*value))
            {
                settled.extend(open.remove(&alert.id));
            }
        }
        settled
    }

    /// The signatures of workloads that are no longer running.
    pub(super) fn gone(&mut self, live: &BTreeSet<String>) -> Vec<String> {
        let gone: Vec<String> = self
            .open
            .keys()
            .filter(|uid| !live.contains(*uid))
            .cloned()
            .collect();
        gone.iter()
            .filter_map(|uid| self.open.remove(uid))
            .flat_map(BTreeMap::into_values)
            .collect()
    }
}

/// Arms the kernel when any published profile declares monitoring; with
/// none declared there is no cycle at all.
pub(super) fn arm_workload_monitor(
    pumps: &mut tokio::task::JoinSet<Result<(), String>>,
    read_model: Arc<odin_huginn::read_model::MaterializedReadModel>,
    cell: Arc<KubeRuntimeCell>,
    owner: Arc<odin_omp::host_tools::delegation::GovernedTaskOwner>,
    runtime: Arc<odin_hermes::runtime::HermesRuntime>,
    desk: Arc<crate::incidents::IncidentDesk>,
    state_root: std::path::PathBuf,
) {
    let profiles: Vec<(Digest, MonitorProfile)> = cell
        .monitored_profiles()
        .into_iter()
        .filter_map(|(identity, container)| {
            MonitorProfile::of(&container).map(|profile| (identity, profile))
        })
        .collect();
    let workloads: BTreeMap<String, MonitorProfile> = cell
        .monitored_workloads()
        .into_iter()
        .filter_map(|(label, monitoring)| {
            MonitorProfile::of_workload(&monitoring).map(|profile| (label, profile))
        })
        .collect();
    if profiles.is_empty() && workloads.is_empty() {
        return;
    }
    tracing::info!(
        "workload-monitor armed container_profiles={} workload_profiles={:?}",
        profiles.len(),
        workloads.keys().collect::<Vec<_>>()
    );
    pumps.spawn(async move {
        let mut ticker = tokio::time::interval(MONITOR_TICK);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let mut tracker = AlertTracker::default();
        let mut incidents = OpenIncidents::default();
        let mut last_read: HashMap<String, Instant> = HashMap::new();
        // The newest report each pod has been evaluated through, by Job uid.
        let mut read_through: HashMap<String, OffsetDateTime> = HashMap::new();
        let book_path = state_root.join("workload-recovery.json");
        let mut book = super::workload_recovery::StallBook::load(&book_path);
        let ledger = state_root.join("ledger.sqlite3");
        // The pods already resumed once for their silence, by Job uid.
        let mut resumed: HashMap<String, bool> = HashMap::new();
        loop {
            ticker.tick().await;
            let (control, client) = match cell.parts().await {
                Ok(parts) => parts,
                Err(error) => {
                    tracing::warn!(
                        "workload monitor tick skipped reason=cluster unavailable: {error}"
                    );
                    continue;
                }
            };
            // The job watch's cache, or one list while that watch is down.
            let jobs = match cell.job_cache().labelled(JOB_LABEL_CONTAINER_IDENTITY) {
                Some(jobs) => jobs,
                None => match client
                    .jobs()
                    .list(&ListParams::default().labels(JOB_LABEL_CONTAINER_IDENTITY))
                    .await
                {
                    Ok(jobs) => jobs.items,
                    Err(error) => {
                        tracing::warn!(
                            "workload monitor tick skipped reason=job list failed: {error}"
                        );
                        continue;
                    }
                },
            };
            let mut live = BTreeSet::new();
            for job in &jobs {
                let Ok(observed) =
                    odin_kube::status::observe_job(&cell.kube_config().cluster, job, 0)
                else {
                    continue;
                };
                if observed.workload.state != KubeWorkloadState::Running {
                    continue;
                }
                let workload_label = job
                    .metadata
                    .labels
                    .as_ref()
                    .and_then(|labels| labels.get(odin_kube::workload::WORKLOAD_LABEL));
                let Some(profile) = profiles
                    .iter()
                    .find(|(identity, _)| {
                        *identity == observed.projection.labels.container_identity
                    })
                    .map(|(_, profile)| profile)
                    .or_else(|| workload_label.and_then(|label| workloads.get(label)))
                else {
                    continue;
                };
                let uid = observed.workload.resource.uid.clone();
                let name = observed.workload.resource.name.clone();
                live.insert(uid.clone());
                if let Some(bound) = profile.silence {
                    watch_silence(
                        Silent {
                            runtime: &runtime,
                            ledger: &ledger,
                            control: &control,
                            observed: &observed,
                            bound,
                            owner: &owner,
                        },
                        resumed.entry(uid.clone()).or_default(),
                    )
                    .await;
                }
                let now = Instant::now();
                if last_read
                    .get(&uid)
                    .is_some_and(|at| now.duration_since(*at) < profile.cadence)
                {
                    continue;
                }
                last_read.insert(uid.clone(), now);
                let after = read_through.get(&uid).copied();
                let Some(report) = read_status(&client, &name, after, profile.tail_lines).await
                else {
                    continue;
                };
                read_through.insert(uid.clone(), report.at);
                // The newest report is the Job's status in the read model.
                let mut published = observed.clone();
                published.workload.node_id = report.node;
                published.workload.status = Some(workload_status(report.at, &report.object));
                match control.observe(vec![published]).await {
                    Ok(deltas) => {
                        for note in control.publish(&read_model, deltas).await {
                            tracing::info!("pod status published job={name}: {note:?}");
                        }
                    }
                    Err(error) => tracing::warn!("pod status not published job={name}: {error}"),
                }
                let counters = numeric_counters(&report.object);
                if let Some(stall) = &profile.stall {
                    if let Some(value) = counters.get(&stall.counter).copied() {
                        let label = workload_label.map_or(name.as_str(), String::as_str);
                        let step = observe_stall(
                            &mut book,
                            &book_path,
                            stall,
                            &observed.projection.labels.run_id,
                            label,
                            &report.pod,
                            value,
                        );
                        if let Some((step, stuck_at)) = step {
                            incidents.opened(&uid, "stall", stall_signature(label, &stall.counter));
                            act_on_stall(StallAction {
                                owner: &owner,
                                runtime: &runtime,
                                desk: &desk,
                                projection: &observed.projection,
                                name: &name,
                                label,
                                stall,
                                step,
                                stuck_at,
                            })
                            .await;
                        }
                    }
                }
                for signature in incidents.settled(&uid, profile, &counters) {
                    let desk = Arc::clone(&desk);
                    let _ = tokio::task::spawn_blocking(move || {
                        desk.clear(&signature, "the watchdog condition no longer holds");
                    })
                    .await;
                }
                let samples: Vec<_> = report.fresh.iter().map(numeric_counters).collect();
                for (alert, value) in tracker.observe_all(&uid, profile, &samples, now) {
                    let mut steered = false;
                    let outcome = match alert.action {
                        ContainerAlertActionToml::Notify => String::new(),
                        ContainerAlertActionToml::Stop => {
                            stop_workload(&control, &observed.projection, &uid, &alert.id).await
                        }
                        ContainerAlertActionToml::Steer => {
                            let (applied, outcome) =
                                steer_workload(&control, &observed.projection, &uid, alert).await;
                            steered = applied;
                            outcome
                        }
                    };
                    // A breached watchdog is an incident: Huginn, the owner's
                    // phone and the conversation hear it —
                    // once: a repeat while it is open only counts.
                    let signature = format!("watchdog:{}:{}", name, alert.id);
                    let raised = crate::incidents::RaisedIncident {
                        source: format!(
                            "monitor:{}/{}",
                            workload_label.map_or(name.as_str(), String::as_str),
                            alert.id
                        ),
                        severity: match alert.severity {
                            odin_registry::schema::ContainerAlertSeverityToml::Info => {
                                odin_huginn::incidents::IncidentSeverityView::Info
                            }
                            odin_registry::schema::ContainerAlertSeverityToml::Warning => {
                                odin_huginn::incidents::IncidentSeverityView::Warning
                            }
                            odin_registry::schema::ContainerAlertSeverityToml::Error => {
                                odin_huginn::incidents::IncidentSeverityView::Error
                            }
                            odin_registry::schema::ContainerAlertSeverityToml::Critical => {
                                odin_huginn::incidents::IncidentSeverityView::Critical
                            }
                        },
                        summary: format!(
                            "Pod {name}: watchdog {} fired — {} (now {value})",
                            alert.id, alert.condition
                        ),
                        detail: format!(
                            "The monitoring kernel read the pod's ODIN-STATUS counters every \
                             {}s; the condition held for {} consecutive checks.{outcome}",
                            profile.cadence.as_secs(),
                            alert.consecutive_hits
                        ),
                        affected: vec![name.clone()],
                        signature: signature.clone(),
                    };
                    incidents.opened(&uid, &alert.id, signature);
                    let desk = Arc::clone(&desk);
                    let receipt =
                        match tokio::task::spawn_blocking(move || desk.raise(raised)).await {
                            Ok(receipt) => Some(receipt),
                            Err(error) => {
                                tracing::error!("monitoring incident not raised: {error}");
                                None
                            }
                        };
                    // A steer that landed corrects the run with no model woken; the incident
                    // records it. Only a failed steer goes to the launching seat.
                    if steered || receipt.as_ref().is_some_and(|receipt| receipt.coalesced) {
                        // Already open and already told: the seat and the
                        // routines heard it the first time.
                        continue;
                    }
                    let finding = Finding {
                        key: format!("{uid}:{}:{}", alert.id, unix_seconds()),
                        session: launching_session(&observed.projection.labels.run_id),
                        source: "monitoring",
                        text: format!(
                            "Workload {name}: watchdog {} ({:?}) fired — `{}` (now {value}).\
                             {outcome} Check it with your workload tools, act within your \
                             declared capabilities, and report the outcome plainly.",
                            alert.id, alert.severity, alert.condition
                        ),
                        lane: Some(observed.projection.labels.lane_id.clone()),
                    };
                    if let Err(error) = route_finding(&owner, &runtime, finding).await {
                        tracing::error!("monitoring finding not delivered: {error}");
                    }
                    // Routines that follow this pod's watchdogs.
                    let runtime = Arc::clone(&runtime);
                    let (profile, key, detail) = (
                        workload_label.cloned(),
                        format!("{uid}:{}:{}", alert.id, unix_seconds()),
                        format!(
                            "Pod {name}: watchdog {} fired — {} (now {value})",
                            alert.id, alert.condition
                        ),
                    );
                    let now_ms = unix_millis();
                    match tokio::task::spawn_blocking(move || {
                        runtime.routine_event(
                            odin_registry::schema::RoutineEvent::Watchdog,
                            profile.as_deref(),
                            &key,
                            &detail,
                            now_ms,
                        )
                    })
                    .await
                    {
                        Ok(Ok(_)) => {}
                        Ok(Err(error)) => tracing::error!("routine event not queued: {error}"),
                        Err(error) => tracing::error!("routine event not queued: {error}"),
                    }
                }
            }
            for signature in incidents.gone(&live) {
                let desk = Arc::clone(&desk);
                let _ = tokio::task::spawn_blocking(move || {
                    desk.clear(&signature, "the pod is no longer running");
                })
                .await;
            }
            tracker.retain(&live);
            last_read.retain(|uid, _| live.contains(uid));
            read_through.retain(|uid, _| live.contains(uid));
            resumed.retain(|uid, _| live.contains(uid));
        }
    });
}

/// One read of a pod's progress counter through its durable ladder; the
/// step when this read is a new stall, with the value it is stuck at.
pub(super) fn observe_stall(
    book: &mut super::workload_recovery::StallBook,
    book_path: &std::path::Path,
    stall: &StallPolicy,
    run: &odin_domain::RunId,
    label: &str,
    pod: &str,
    value: f64,
) -> Option<(super::workload_recovery::StallStep, f64)> {
    let now_ms = unix_millis();
    let window_ms = i64::try_from(stall.window.as_millis()).unwrap_or(i64::MAX);
    let state = book.run(run.as_str(), value, now_ms);
    let stuck_at = state.high_water();
    let signature = stall_signature(label, &stall.counter);
    let step = match state.observe(value, pod, now_ms, window_ms, &stall.policy, &signature) {
        Ok(step) => step,
        Err(error) => {
            tracing::error!("pod stall ladder failed run={run}: {error}");
            None
        }
    };
    if let Err(error) = book.store(book_path, now_ms) {
        tracing::error!("pod stall state not recorded: {error}");
    }
    step.map(|step| (step, stuck_at))
}

/// A detected stall and the runtime owners that apply its selected recovery step.
struct StallAction<'a> {
    owner: &'a Arc<odin_omp::host_tools::delegation::GovernedTaskOwner>,
    runtime: &'a Arc<odin_hermes::runtime::HermesRuntime>,
    desk: &'a Arc<crate::incidents::IncidentDesk>,
    projection: &'a odin_domain::huginn::KubeJobProjection,
    name: &'a str,
    label: &'a str,
    stall: &'a StallPolicy,
    step: super::workload_recovery::StallStep,
    stuck_at: f64,
}

/// Applies one ladder step: the authorized restart goes to the pod's seat as
/// its one instruction; escalation and a spent ladder are an incident for
/// the owner. Every decision is logged.
async fn act_on_stall(action: StallAction<'_>) {
    let StallAction {
        owner,
        runtime,
        desk,
        projection,
        name,
        label,
        stall,
        step,
        stuck_at,
    } = action;
    use super::workload_recovery::StallStep;
    use odin_kernel::recovery::RecoveryRung;
    let run = &projection.labels.run_id;
    let counter = &stall.counter;
    let window = stall.window.as_secs();
    tracing::info!(
        "pod stall job={name} run={run} counter={counter} stuck_at={stuck_at} \
         decision={step:?}"
    );
    let escalation = match step {
        StallStep::Act {
            rung: RecoveryRung::RestartWorker,
            attempt,
        } => {
            let finding = Finding {
                key: format!(
                    "{}:stall:{attempt}:{}",
                    projection.identity.uid.as_str(),
                    unix_seconds()
                ),
                session: launching_session(run),
                source: "recovery",
                text: format!(
                    "Pod {name} ({label}) has made no useful progress on `{counter}` for \
                     {window}s (stuck at {stuck_at}). The recovery ladder authorizes exactly \
                     one step: restart it with kube_workload_restart (runId {run}, \
                     expectedResourceVersion {}). Do only that, then report what happened.",
                    projection.identity.resource_version.as_str()
                ),
                lane: Some(projection.labels.lane_id.clone()),
            };
            if let Err(error) = route_finding(owner, runtime, finding).await {
                tracing::error!("pod recovery step not delivered: {error}");
            }
            return;
        }
        StallStep::Act {
            rung: RecoveryRung::Escalate,
            ..
        } => format!(
            "the authorized restart did not get it past {stuck_at}; the recovery ladder \
             escalates to the owner"
        ),
        StallStep::Blocked { missing_decision } => {
            format!("the recovery ladder is spent: {missing_decision}")
        }
        StallStep::Cooldown => return,
        StallStep::Act { rung, .. } => {
            tracing::warn!("pod recovery rung {rung:?} is not one a pod supports");
            return;
        }
    };
    let raised = crate::incidents::RaisedIncident {
        source: format!("recovery:{label}"),
        severity: odin_huginn::incidents::IncidentSeverityView::Error,
        summary: format!("Pod {name} is stuck — `{counter}` has not passed {stuck_at}"),
        detail: format!(
            "The monitoring kernel saw no useful progress on `{counter}` for {window}s; \
             {escalation}."
        ),
        affected: vec![name.to_owned()],
        signature: stall_signature(label, counter),
    };
    let desk = Arc::clone(desk);
    if let Err(error) = tokio::task::spawn_blocking(move || desk.raise(raised)).await {
        tracing::error!("pod stall incident not raised: {error}");
    }
}

/// Writes the watchdog's patch as the pod's next control document. The tracker's cooldown
/// already bounds this to once per cooldown; the operation id makes a re-read idempotent.
async fn steer_workload(
    control: &odin_huginn::kube::KubeControl,
    projection: &odin_domain::huginn::KubeJobProjection,
    uid: &str,
    alert: &ContainerAlertToml,
) -> (bool, String) {
    let run = &projection.labels.run_id;
    let Some(patch) = &alert.patch else {
        return (false, " It declares no patch to steer with.".to_owned());
    };
    let reconciler = control.reconciler();
    let current = match odin_kube::control::read_control(reconciler.client(), run).await {
        Ok(Some(current)) => current,
        Ok(None) => return (false, " The pod has no control map to steer.".to_owned()),
        Err(error) => return (false, format!(" Reading its control failed: {error}.")),
    };
    let operation = format!("watchdog:{uid}:{}:{}", alert.id, current.seq + 1);
    match reconciler
        .steer_control(
            run,
            current.seq,
            patch.0.clone(),
            &operation,
            &format!("watchdog:{}", alert.id),
        )
        .await
    {
        Ok(applied) => (
            true,
            format!(
                " Odin steered it: control seq {} = {}.",
                applied.seq, patch.0
            ),
        ),
        Err(error) => (false, format!(" Steering it failed: {error}.")),
    }
}

/// Cancels one workload through the kernel's own actuation path, keyed so a
/// repeated firing is the same operation. The outcome is the finding's text.
async fn stop_workload(
    control: &odin_huginn::kube::KubeControl,
    projection: &odin_domain::huginn::KubeJobProjection,
    uid: &str,
    alert: &str,
) -> String {
    let seed = format!("monitor:{uid}:{alert}:stop");
    match operate_workload(control, projection, &seed, KubeOperationKind::Cancel).await {
        Ok(()) => " The kernel stopped it, as the profile declares.".to_owned(),
        Err(error) => format!(" Stopping it as declared FAILED: {error}."),
    }
}

/// Cancels or restarts one workload through the kube path under the operation `seed` names.
async fn operate_workload(
    control: &odin_huginn::kube::KubeControl,
    projection: &odin_domain::huginn::KubeJobProjection,
    seed: &str,
    kind: KubeOperationKind,
) -> Result<(), String> {
    let digest = Digest::hash(seed.as_bytes());
    let operation_id = OperationId::new(&format!(
        "op-monitor-{}",
        digest
            .to_string()
            .trim_start_matches("blake3:")
            .get(..16)
            .unwrap_or_default()
    ))
    .map_err(|_| "no valid operation id".to_owned())?;
    let action = JobAction {
        run_id: projection.labels.run_id.clone(),
        kind,
        expected_resource_version: projection.identity.resource_version.clone(),
        operation_id,
        idempotency_digest: digest,
        target_node: None,
    };
    control
        .operate_at_live_version(action, time::OffsetDateTime::now_utc())
        .await
        .map(|_| ())
        .map_err(|error| error.to_string())
}

/// The events of a session's tail read for an open tool call.
const TAIL_EVENTS: u16 = 256;

/// A running pod, its operation context and the silence its profile allows.
struct Silent<'a> {
    runtime: &'a Arc<odin_hermes::runtime::HermesRuntime>,
    ledger: &'a std::path::Path,
    control: &'a odin_huginn::kube::KubeControl,
    observed: &'a odin_kube::job::JobObservation,
    bound: StdDuration,
    owner: &'a Arc<odin_omp::host_tools::delegation::GovernedTaskOwner>,
}

/// What a pod's silence calls for.
#[derive(Debug, Eq, PartialEq)]
enum Quiet {
    Wait,
    Resume,
    Restart,
}

/// The first time a session is silent for `bound` it is resumed; once resumed, the next time it
/// is stopped. `resumed` is whether it has been.
fn quiet_step(resumed: bool, silent: StdDuration, bound: StdDuration) -> Quiet {
    match (silent >= bound, resumed) {
        (false, _) => Quiet::Wait,
        (true, false) => Quiet::Resume,
        (true, true) => Quiet::Restart,
    }
}

/// Applies the step a silence calls for. A resume that fails is tried again the next tick; the
/// stop's note to the launching job is written once the stop went through.
async fn quiet_pod(
    silent: StdDuration,
    bound: StdDuration,
    resumed: &mut bool,
    resume: impl AsyncFnOnce() -> Result<(), String>,
    restart: impl AsyncFnOnce() -> Result<(), String>,
    note: impl AsyncFnOnce(String),
) {
    let minutes = silent.as_secs() / 60;
    match quiet_step(*resumed, silent, bound) {
        Quiet::Wait => {}
        Quiet::Resume => match resume().await {
            Ok(()) => *resumed = true,
            Err(error) => tracing::error!("pod silent for {minutes} min, not resumed: {error}"),
        },
        Quiet::Restart => match restart().await {
            Ok(()) => {
                note(format!(
                    "its session journaled nothing for {minutes} minutes after it was resumed \
                     once, so it was stopped; its saved evidence stays, and it can be launched \
                     again to carry on."
                ))
                .await
            }
            Err(error) => tracing::error!("pod silent for {minutes} min, not stopped: {error}"),
        },
    }
}

/// A running pod whose session journals nothing for its profile's stall bound is resumed once,
/// then stopped through the kube cancel path, and the job that launched it gets one note.
async fn watch_silence(watch: Silent<'_>, resumed: &mut bool) {
    let Some(omp) = odin_omp::live::service::OmpLiveService::installed() else {
        return;
    };
    let observed = watch.observed;
    let run = &observed.projection.labels.run_id;
    let (uid, job) = (
        observed.workload.resource.uid.as_str(),
        observed.workload.resource.name.as_str(),
    );
    let KubeResourceOwnership::Odin { seat_id, .. } = &observed.workload.ownership else {
        return;
    };
    let worker = match watch.control.reconciler().stored_launch(run) {
        Ok(Some(launch)) => match worker_session(&launch) {
            Ok(worker) => worker,
            Err(error) => return tracing::error!("pod silence {job}: {error}"),
        },
        Ok(None) => return,
        Err(error) => return tracing::error!("pod silence {job}: launch of {run}: {error}"),
    };
    let silent = match silence_of(&omp, worker, OffsetDateTime::now_utc()).await {
        Ok(Some(silent)) => silent,
        Ok(None) => return,
        Err(error) => return tracing::error!("pod silence {job}: {error}"),
    };
    let acting = Acting {
        omp: &omp,
        runtime: watch.runtime,
        owner: watch.owner,
        ledger: watch.ledger,
        seat: seat_id.as_str(),
        job,
    };
    let minutes = silent.as_secs() / 60;
    quiet_pod(
        silent,
        watch.bound,
        resumed,
        async || {
            let abort = LiveCommandBody::Abort {
                scope: AbortScope::CurrentTurn,
            };
            send(&omp, worker, format!("pod-silent-abort:{uid}"), abort).await?;
            let text = format!(
                "[Odin recovery, an automatic message] Your session journaled nothing for \
                 {minutes} minutes, so the turn was cancelled. Carry on from where you \
                 stopped; if the work is done, answer."
            );
            tell_worker(&omp, worker, &format!("pod-silent-resume:{uid}"), &text).await
        },
        // A restarted agent pod comes back without its agent (the session is attached once, at
        // launch), so a pod still silent after its resume is stopped: its evidence stays, its
        // report settles from what it saved, and its launcher can launch it again.
        async || {
            let seed = format!("monitor:{uid}:silent:stop");
            operate_workload(
                watch.control,
                &observed.projection,
                &seed,
                KubeOperationKind::Cancel,
            )
            .await
        },
        async |text| {
            note(
                &acting,
                run,
                &format!("{uid}:silent"),
                format!("Pod {job}: {text}"),
            )
            .await
        },
    )
    .await;
}

/// How long a running session has journaled nothing, when it is the turn that is silent: not a
/// session at rest, and not a tool call still open (that is the tool's wait). `now` is the clock.
async fn silence_of(
    omp: &odin_omp::live::service::OmpLiveService,
    worker: LiveSessionId,
    now: OffsetDateTime,
) -> Result<Option<StdDuration>, String> {
    let Some(summary) = omp
        .supervisor()
        .durable_summary(worker)
        .await
        .map_err(|error| error.to_string())?
    else {
        return Ok(None);
    };
    if summary.state != LiveSessionState::Running || tool_open(omp, &summary).await? {
        return Ok(None);
    }
    Ok(StdDuration::try_from(now - summary.updated_at).ok())
}

async fn tool_open(
    omp: &odin_omp::live::service::OmpLiveService,
    summary: &LiveSessionSummary,
) -> Result<bool, String> {
    let after = EventSeq::new(
        summary
            .event_head
            .get()
            .saturating_sub(u64::from(TAIL_EVENTS)),
    );
    let page = omp
        .history(HistoryQuery {
            session_id: summary.session_id,
            after,
            limit: std::num::NonZeroU16::new(TAIL_EVENTS).expect("nonzero"),
        })
        .await
        .map_err(|error| error.to_string())?;
    Ok(open_tools(page.events.iter().map(|event| &event.body)))
}

/// Whether a tool call is still open at the end of `bodies`; a turn that settled leaves none.
fn open_tools<'a>(bodies: impl IntoIterator<Item = &'a LiveEventBody>) -> bool {
    let mut open = BTreeSet::new();
    for body in bodies {
        match body {
            LiveEventBody::SessionStateChanged(change)
                if change.current == LiveSessionState::Idle =>
            {
                open.clear();
            }
            LiveEventBody::ToolStarted(started) => {
                open.insert(started.tool.tool_use_id.clone());
            }
            LiveEventBody::ToolFinished(finished) => {
                open.remove(&finished.result.tool_use_id);
            }
            _ => {}
        }
    }
    !open.is_empty()
}

/// A running pod's newest status report and reports printed since the last read
/// (oldest first), together with the node it is bound to and its name.
struct PodReport {
    pod: String,
    node: Option<NodeId>,
    at: OffsetDateTime,
    object: Map<String, Value>,
    fresh: Vec<Map<String, Value>>,
}

/// One Job's running pod and its status reports since `after`, from a timestamped
/// kube log. The initial read is bounded; later reads cover the elapsed interval.
/// Nothing is read off a host path.
async fn read_status(
    client: &odin_kube::KubeClient,
    job: &str,
    after: Option<OffsetDateTime>,
    tail_lines: i64,
) -> Option<PodReport> {
    let pods = client
        .pods()
        .list(&ListParams::default().labels(&format!("job-name={job}")))
        .await
        .inspect_err(|error| {
            tracing::error!("workload-monitor status-unread job={job} reason=pod list: {error}")
        })
        .ok()?;
    let pod = pods.items.iter().find(|pod| {
        pod.status
            .as_ref()
            .and_then(|status| status.phase.as_deref())
            == Some("Running")
    })?;
    let name = pod.metadata.name.clone()?;
    let node = odin_kube::status::bound_node(std::slice::from_ref(pod));
    let log = client
        .pods()
        .logs(
            &name,
            &LogParams {
                tail_lines: after.is_none().then_some(tail_lines),
                // Round up and include a second of overlap; reports_since removes duplicates.
                since_seconds: after
                    .map(|at| (OffsetDateTime::now_utc() - at).whole_seconds().max(0) + 2),
                timestamps: true,
                ..LogParams::default()
            },
        )
        .await
        .inspect_err(|error| {
            tracing::error!("workload-monitor status-unread job={job} reason=pod log: {error}")
        })
        .ok()?;
    let (at, object) = match latest_report(&log) {
        Some(report) => report,
        None if after.is_some() => {
            let tail = client
                .pods()
                .logs(
                    &name,
                    &LogParams {
                        tail_lines: Some(tail_lines),
                        timestamps: true,
                        ..LogParams::default()
                    },
                )
                .await
                .ok()?;
            latest_report(&tail)?
        }
        None => return None,
    };
    let fresh = reports_since(&log, after)
        .into_iter()
        .map(|(_, object)| object)
        .collect();
    Some(PodReport {
        pod: name,
        node,
        at,
        object,
        fresh,
    })
}

/// The pod's newest report as the Job's view status: the summary cut to 200
/// characters, `progress` as its own fraction, and at most eight other
/// numeric fields.
fn workload_status(at: OffsetDateTime, object: &Map<String, Value>) -> KubeWorkloadStatus {
    KubeWorkloadStatus {
        at,
        progress: object.get("progress").and_then(Value::as_f64),
        summary: object
            .get("summary")
            .and_then(Value::as_str)
            .map(|text| text.chars().take(200).collect()),
        counters: numeric_counters(object)
            .into_iter()
            .filter(|(key, _)| key != "progress")
            .take(8)
            .collect(),
    }
}

fn unix_seconds() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}

fn unix_millis() -> i64 {
    i64::try_from(unix_seconds()).unwrap_or(i64::MAX / 1000) * 1000
}

/// The open-incident key of one stalled counter: the pump raises, observes and clears by it.
fn stall_signature(label: &str, counter: &str) -> String {
    format!("stall:{label}:{counter}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::num::{NonZeroU16, NonZeroU32};
    use time::format_description::well_known::Rfc3339;

    fn profile(condition: &str, hits: u16, cooldown_seconds: u32) -> MonitorProfile {
        let alert = ContainerAlertToml {
            id: "too-many-dislikes".to_owned(),
            condition: condition.to_owned(),
            consecutive_hits: NonZeroU16::new(hits).unwrap(),
            cooldown_seconds,
            severity: odin_registry::schema::ContainerAlertSeverityToml::Warning,
            slice: odin_domain::SliceId::new("kubert-ops").unwrap(),
            action: ContainerAlertActionToml::Notify,
            patch: None,
        };
        MonitorProfile {
            cadence: StdDuration::from_secs(NonZeroU32::new(30).unwrap().get().into()),
            tail_lines: STATUS_TAIL_LINES,
            alerts: vec![(alert, AlertCondition::parse(condition).unwrap())],
            stall: None,
            silence: None,
        }
    }

    #[test]
    fn an_open_watchdog_incident_clears_when_its_condition_or_its_pod_goes() {
        let profile = profile("residual > 0.001", 3, 0);
        let mut open = OpenIncidents::default();
        open.opened(
            "uid-1",
            "too-many-dislikes",
            "watchdog:odin-a:too-many-dislikes".into(),
        );
        open.opened(
            "uid-2",
            "too-many-dislikes",
            "watchdog:odin-b:too-many-dislikes".into(),
        );
        let still = BTreeMap::from([("residual".to_owned(), 0.009)]);
        assert!(
            open.settled("uid-1", &profile, &still).is_empty(),
            "still breached"
        );
        let unread = BTreeMap::new();
        assert!(
            open.settled("uid-1", &profile, &unread).is_empty(),
            "an unread counter proves nothing"
        );
        let fine = BTreeMap::from([("residual".to_owned(), 0.0001)]);
        assert_eq!(
            open.settled("uid-1", &profile, &fine),
            vec!["watchdog:odin-a:too-many-dislikes".to_owned()]
        );
        assert!(
            open.settled("uid-1", &profile, &fine).is_empty(),
            "cleared once"
        );
        let live = BTreeSet::from(["uid-1".to_owned()]);
        assert_eq!(
            open.gone(&live),
            vec!["watchdog:odin-b:too-many-dislikes".to_owned()]
        );
        assert!(open.gone(&live).is_empty());
    }

    #[test]
    fn alerts_fire_after_consecutive_hits_and_respect_cooldown() {
        let profile = profile("dislikes >= 100", 2, 600);
        let mut tracker = AlertTracker::default();
        let start = Instant::now();
        let high = BTreeMap::from([("dislikes".to_owned(), 120.0)]);
        let low = BTreeMap::from([("dislikes".to_owned(), 5.0)]);
        assert!(
            tracker.observe("job", &profile, &high, start).is_empty(),
            "one hit"
        );
        assert!(
            tracker.observe("job", &profile, &low, start).is_empty(),
            "streak reset"
        );
        assert!(tracker.observe("job", &profile, &high, start).is_empty());
        let fired = tracker.observe("job", &profile, &high, start);
        assert_eq!(fired.len(), 1);
        assert_eq!(fired[0].1, 120.0);
        let soon = start + StdDuration::from_secs(60);
        tracker.observe("job", &profile, &high, soon);
        assert!(
            tracker.observe("job", &profile, &high, soon).is_empty(),
            "cooling down"
        );
        // The condition held throughout the cooldown: the first reading
        // after it fires again.
        let later = start + StdDuration::from_secs(700);
        assert_eq!(tracker.observe("job", &profile, &high, later).len(), 1);
    }

    #[test]
    fn unchanged_status_does_not_count_as_another_hit() {
        let log = "2026-11-14T10:00:00Z ODIN-STATUS {\"courant_max\": 2.0}\n";
        let read = OffsetDateTime::parse("2026-11-14T10:00:00Z", &Rfc3339).unwrap();
        let mut tracker = AlertTracker::default();
        let profile = profile("courant_max > 1.0", 2, 0);
        let initial: Vec<_> = reports_since(log, None)
            .iter()
            .map(|(_, object)| numeric_counters(object))
            .collect();
        assert!(tracker
            .observe_all("job", &profile, &initial, Instant::now())
            .is_empty());
        let fresh: Vec<_> = reports_since(log, Some(read))
            .iter()
            .map(|(_, object)| numeric_counters(object))
            .collect();
        assert!(fresh.is_empty());
        assert!(tracker
            .observe_all("job", &profile, &fresh, Instant::now())
            .is_empty());
        assert_eq!(
            tracker
                .observe_all("job", &profile, &initial, Instant::now())
                .len(),
            1
        );
    }

    #[test]
    fn a_spike_between_cadences_fires() {
        let log = "2026-11-14T10:00:00Z ODIN-STATUS {\"courant_max\": 0.4}\n\
                   2026-11-14T10:00:10Z ODIN-STATUS {\"courant_max\": 1.7}\n\
                   2026-11-14T10:00:20Z ODIN-STATUS {\"courant_max\": 0.5}\n";
        let read = OffsetDateTime::parse("2026-11-14T10:00:00Z", &Rfc3339).unwrap();
        let samples: Vec<_> = reports_since(log, Some(read))
            .iter()
            .map(|(_, object)| numeric_counters(object))
            .collect();
        assert_eq!(samples.len(), 2, "only the reports after the last read");
        let profile = profile("courant_max > 1.0", 1, 0);
        let mut tracker = AlertTracker::default();
        let newest = samples.last().unwrap();
        assert!(
            tracker
                .observe("job", &profile, newest, Instant::now())
                .is_empty(),
            "the newest sample alone misses the spike"
        );
        let fired = tracker.observe_all("job", &profile, &samples, Instant::now());
        assert_eq!(fired.len(), 1, "fires once per tick");
        assert_eq!(fired[0].1, 1.7);
    }

    #[test]
    fn a_steer_watchdog_applies_its_patch_once_per_cooldown() {
        let mut profile = profile("courant_max > 1.0", 1, 600);
        profile.alerts[0].0.action = ContainerAlertActionToml::Steer;
        profile.alerts[0].0.patch = Some(odin_registry::schema::SteerPatch(
            serde_json::json!({"set": {"maxCo": 0.5}}),
        ));
        let mut tracker = AlertTracker::default();
        let hot = vec![BTreeMap::from([("courant_max".to_owned(), 1.4)])];
        let start = Instant::now();
        let fired = tracker.observe_all("job", &profile, &hot, start);
        assert_eq!(fired.len(), 1);
        assert_eq!(fired[0].0.action, ContainerAlertActionToml::Steer);
        assert!(
            fired[0].0.patch.is_some(),
            "the steer carries its declared patch"
        );
        for later in [60, 300, 599] {
            assert!(
                tracker
                    .observe_all("job", &profile, &hot, start + StdDuration::from_secs(later))
                    .is_empty(),
                "no second steer inside the cooldown"
            );
        }
        assert_eq!(
            tracker
                .observe_all("job", &profile, &hot, start + StdDuration::from_secs(601))
                .len(),
            1
        );
    }

    /// One tick of a pod silent for `seconds`, and what was done about it.
    async fn tick(seconds: u64, resumed: &mut bool, restart_refused: bool) -> Vec<String> {
        let done = std::sync::Mutex::new(Vec::new());
        quiet_pod(
            StdDuration::from_secs(seconds),
            StdDuration::from_secs(300),
            resumed,
            async || {
                done.lock().unwrap().push("resumed".to_owned());
                Ok(())
            },
            async || match restart_refused {
                true => Err("the cluster refused".to_owned()),
                false => {
                    done.lock().unwrap().push("restarted".to_owned());
                    Ok(())
                }
            },
            async |text| done.lock().unwrap().push(format!("note: {text}")),
        )
        .await;
        done.into_inner().unwrap()
    }

    #[tokio::test]
    async fn a_silent_pod_is_resumed_once_then_stopped_and_the_launching_job_is_told_once() {
        let mut resumed = false;
        assert!(
            tick(299, &mut resumed, false).await.is_empty(),
            "within its bound"
        );
        assert_eq!(tick(300, &mut resumed, false).await, ["resumed"]);
        assert!(resumed);
        // The resume's own events are not recovery: a quiet minute after them waits.
        assert!(tick(60, &mut resumed, false).await.is_empty());
        // Silent again for the bound, the restart is refused: no note, tried again next tick.
        assert!(tick(310, &mut resumed, true).await.is_empty());
        let done = tick(320, &mut resumed, false).await;
        assert_eq!(done.len(), 2, "{done:?}");
        assert_eq!(done[0], "restarted");
        assert!(
            done[1].starts_with("note: ")
                && done[1].contains("5 minutes after it was resumed once"),
            "{done:?}"
        );
    }

    #[test]
    fn only_a_turn_with_no_tool_open_can_be_silent() {
        use odin_domain::huginn::{
            SessionStateChanged, ToolFinished, ToolResultBlock, ToolStarted, ToolUseBlock,
        };
        use odin_domain::{CapabilityId, TurnId};
        let started = |id: &str| {
            LiveEventBody::ToolStarted(ToolStarted {
                turn_id: TurnId::new("turn:1").unwrap(),
                tool: ToolUseBlock {
                    tool_use_id: id.to_owned(),
                    capability_id: CapabilityId::new("web.save").unwrap(),
                    arguments: serde_json::json!({}),
                },
                intent: None,
            })
        };
        let finished = |id: &str| {
            LiveEventBody::ToolFinished(ToolFinished {
                turn_id: TurnId::new("turn:1").unwrap(),
                result: ToolResultBlock {
                    tool_use_id: id.to_owned(),
                    content: Vec::new(),
                    is_error: false,
                    details: None,
                },
            })
        };
        let idle = LiveEventBody::SessionStateChanged(SessionStateChanged {
            previous: LiveSessionState::Running,
            current: LiveSessionState::Idle,
            reason: None,
        });
        assert!(open_tools([&started("a"), &started("b"), &finished("a")]));
        assert!(!open_tools([&started("a"), &finished("a")]));
        assert!(
            !open_tools([&started("a"), &idle]),
            "a settled turn leaves nothing running"
        );
    }
}
