//! The monitoring kernel: every running Odin workload is watched under its
//! container profile's declared `[monitoring]` cadence and `watchdogs`
//! alerts. A pod reports counters on stdout as `ODIN-STATUS {"likes": 3}`
//! lines; code reads the newest one each cadence, evaluates every declared
//! condition using consecutive-hit and cooldown settings, and applies the
//! declared action — notify the launching seat, or cancel the workload and
//! then tell it. Healthy workloads cost no model call.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::Arc;
use std::time::{Duration as StdDuration, Instant};

use kube::api::{ListParams, LogParams};
use odin_domain::huginn::{KubeOperationKind, KubeWorkloadState};
use odin_domain::Digest;
use odin_kube::job::{JobAction, JOB_LABEL_CONTAINER_IDENTITY};
use odin_kube::telemetry::{latest_status, STATUS_TAIL_LINES};
use odin_registry::schema::{
    AlertCondition, ContainerAlertActionToml, ContainerAlertToml, ContainerMonitoringToml,
    ContainerToml, ContainerWatchdogToml, WorkloadMonitoringToml,
};
use odin_types::OperationId;

use super::workload_watch::{launching_session, route_finding, Finding};
use crate::kube::KubeRuntimeCell;

const MONITOR_TICK: StdDuration = StdDuration::from_secs(15);

pub(super) struct MonitorProfile {
    pub(super) cadence: StdDuration,
    pub(super) alerts: Vec<(ContainerAlertToml, AlertCondition)>,
    /// Declared anti-stuck recovery.
    pub(super) stall: Option<StallPolicy>,
}

/// A pod's declared progress counter, stall window and recovery ladder.
pub(super) struct StallPolicy {
    counter: String,
    window: StdDuration,
    policy: odin_kernel::recovery::RecoveryPolicy,
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
        (!alerts.is_empty() || stall.is_some()).then(|| Self {
            cadence: StdDuration::from_secs(u64::from(monitoring.cadence_seconds.get())),
            alerts,
            stall,
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
            alerts,
            stall: None,
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
        let book_path = state_root.join("workload-recovery.json");
        let mut book = super::workload_recovery::StallBook::load(&book_path);
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
            let jobs = match client
                .jobs()
                .list(&ListParams::default().labels(JOB_LABEL_CONTAINER_IDENTITY))
                .await
            {
                Ok(jobs) => jobs,
                Err(error) => {
                    tracing::warn!("workload monitor tick skipped reason=job list failed: {error}");
                    continue;
                }
            };
            let mut live = BTreeSet::new();
            for job in &jobs.items {
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
                let now = Instant::now();
                if last_read
                    .get(&uid)
                    .is_some_and(|at| now.duration_since(*at) < profile.cadence)
                {
                    continue;
                }
                last_read.insert(uid.clone(), now);
                let Some(counters) = read_status(&client, &name).await else {
                    continue;
                };
                if let Some(stall) = &profile.stall {
                    if let Some(value) = counters.get(&stall.counter).copied() {
                        let label = workload_label.map_or(name.as_str(), String::as_str);
                        let step = observe_stall(
                            &mut book,
                            &book_path,
                            stall,
                            &observed.projection.labels.run_id,
                            label,
                            value,
                        );
                        if let Some((step, stuck_at)) = step {
                            incidents.opened(
                                &uid,
                                "stall",
                                format!("stall:{label}:{}", stall.counter),
                            );
                            act_on_stall(
                                &owner,
                                &runtime,
                                &desk,
                                &observed.projection,
                                &name,
                                label,
                                stall,
                                step,
                                stuck_at,
                            )
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
                for (alert, value) in tracker.observe(&uid, profile, &counters, now) {
                    let outcome = match alert.action {
                        ContainerAlertActionToml::Notify => String::new(),
                        ContainerAlertActionToml::Stop => {
                            stop_workload(&control, &observed.projection, &uid, &alert.id).await
                        }
                    };
                    // A breached watchdog is an incident: Huginn, Colin's
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
                    if receipt.as_ref().is_some_and(|receipt| receipt.coalesced) {
                        // Already open and already told: the seat and the
                        // routines heard it the first time.
                        continue;
                    }
                    let finding = Finding {
                        key: format!("{uid}:{}:{}", alert.id, unix_seconds()),
                        session: launching_session(&observed.projection.labels.run_id),
                        text: format!(
                            "[Odin monitoring — not a message from Colin] Workload {name}: \
                             watchdog {} ({:?}) fired — `{}` (now {value}).{outcome} Check it \
                             with your workload tools, act within your declared capabilities, \
                             and report the outcome plainly.",
                            alert.id, alert.severity, alert.condition
                        ),
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
                    let now_ms = i64::try_from(unix_seconds()).unwrap_or(i64::MAX / 1000) * 1000;
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
        }
    });
}

/// One read of a pod's progress counter through its durable ladder; the
/// step when this read is a new stall, with the value it is stuck at.
fn observe_stall(
    book: &mut super::workload_recovery::StallBook,
    book_path: &std::path::Path,
    stall: &StallPolicy,
    run: &odin_domain::RunId,
    label: &str,
    value: f64,
) -> Option<(super::workload_recovery::StallStep, f64)> {
    let now_ms = i64::try_from(unix_seconds()).unwrap_or(i64::MAX / 1000) * 1000;
    let window_ms = i64::try_from(stall.window.as_millis()).unwrap_or(i64::MAX);
    let state = book.run(run.as_str(), value, now_ms);
    let stuck_at = state.high_water();
    let signature = format!("stall:{label}:{}", stall.counter);
    let step = match state.observe(value, now_ms, window_ms, &stall.policy, &signature) {
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

/// Applies one ladder step: the authorized restart goes to the pod's seat as
/// its one instruction; escalation and a spent ladder are an incident for
/// Colin. Every decision is logged.
#[allow(clippy::too_many_arguments)]
async fn act_on_stall(
    owner: &Arc<odin_omp::host_tools::delegation::GovernedTaskOwner>,
    runtime: &Arc<odin_hermes::runtime::HermesRuntime>,
    desk: &Arc<crate::incidents::IncidentDesk>,
    projection: &odin_domain::huginn::KubeJobProjection,
    name: &str,
    label: &str,
    stall: &StallPolicy,
    step: super::workload_recovery::StallStep,
    stuck_at: f64,
) {
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
                text: format!(
                    "[Odin recovery — not a message from Colin] Pod {name} ({label}) has made no \
                     useful progress on `{counter}` for {window}s (stuck at {stuck_at}). The \
                     recovery ladder authorizes exactly one step: restart it with \
                     kube_workload_restart (runId {run}, expectedResourceVersion {}). Do only \
                     that, then report what happened.",
                    projection.identity.resource_version.as_str()
                ),
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
             escalates to Colin"
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
        signature: format!("stall:{label}:{counter}"),
    };
    let desk = Arc::clone(desk);
    if let Err(error) = tokio::task::spawn_blocking(move || desk.raise(raised)).await {
        tracing::error!("pod stall incident not raised: {error}");
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
    let digest = Digest::hash(seed.as_bytes());
    let Ok(operation_id) = OperationId::new(&format!(
        "op-monitor-{}",
        digest
            .to_string()
            .trim_start_matches("blake3:")
            .get(..16)
            .unwrap_or_default()
    )) else {
        return " Stopping it as declared FAILED: no valid operation id.".to_owned();
    };
    let action = JobAction {
        run_id: projection.labels.run_id.clone(),
        kind: KubeOperationKind::Cancel,
        expected_resource_version: projection.identity.resource_version.clone(),
        operation_id,
        idempotency_digest: digest,
        target_node: None,
    };
    match control
        .operate_at_live_version(action, time::OffsetDateTime::now_utc())
        .await
    {
        Ok(_) => " The kernel stopped it, as the profile declares.".to_owned(),
        Err(error) => format!(" Stopping it as declared FAILED: {error}."),
    }
}

/// The newest status counters of one Job's running pod, from a bounded log
/// tail through the kube API — node-agnostic, nothing read off a host path.
async fn read_status(client: &odin_kube::KubeClient, job: &str) -> Option<BTreeMap<String, f64>> {
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
    let log = client
        .pods()
        .logs(
            pod.metadata.name.as_deref()?,
            &LogParams {
                tail_lines: Some(STATUS_TAIL_LINES),
                ..LogParams::default()
            },
        )
        .await
        .inspect_err(|error| {
            tracing::error!("workload-monitor status-unread job={job} reason=pod log: {error}")
        })
        .ok()?;
    latest_status(&log)
}

fn unix_seconds() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::num::{NonZeroU16, NonZeroU32};

    fn profile(condition: &str, hits: u16, cooldown_seconds: u32) -> MonitorProfile {
        let alert = ContainerAlertToml {
            id: "too-many-dislikes".to_owned(),
            condition: condition.to_owned(),
            consecutive_hits: NonZeroU16::new(hits).unwrap(),
            cooldown_seconds,
            severity: odin_registry::schema::ContainerAlertSeverityToml::Warning,
            slice: odin_domain::SliceId::new("kubert-ops").unwrap(),
            action: ContainerAlertActionToml::Notify,
        };
        MonitorProfile {
            cadence: StdDuration::from_secs(NonZeroU32::new(30).unwrap().get().into()),
            alerts: vec![(alert, AlertCondition::parse(condition).unwrap())],
            stall: None,
        }
    }

    #[test]
    fn the_newest_status_line_carries_the_counters() {
        let log = "starting\nODIN-STATUS {\"likes\": 2, \"dislikes\": 1}\nnoise\n\
                   ODIN-STATUS {\"likes\": 3, \"dislikes\": 7, \"note\": \"x\"}\n\
                   ODIN-STATUS not json\n";
        let counters = latest_status(log).expect("a status line");
        assert_eq!(counters.get("likes"), Some(&3.0));
        assert_eq!(counters.get("dislikes"), Some(&7.0));
        assert!(!counters.contains_key("note"));
        assert!(latest_status("no status here").is_none());
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
    fn an_unreported_counter_never_fires() {
        let profile = profile("likes == 0", 1, 0);
        let mut tracker = AlertTracker::default();
        let other = BTreeMap::from([("errors".to_owned(), 0.0)]);
        assert!(tracker
            .observe("job", &profile, &other, Instant::now())
            .is_empty());
    }
}
