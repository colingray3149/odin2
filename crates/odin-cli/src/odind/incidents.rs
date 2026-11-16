//! The incident desk: one place every source — a seat's
//! `incident.raise`, the monitoring kernel, a routine — raises a typed
//! incident. Raising publishes the Huginn incident card, pages the owner's
//! phone for an error or worse (when a sink is declared), and wakes the
//! conversation once for a warning or worse, which tells him only what he
//! needs to know. Each leg's failure is
//! logged and reported back; none is swallowed and none blocks the others.
//!
//! A repeat of an open incident (same signature, seen within the coalescing
//! window, no higher severity) is coalesced into it: the card's count and
//! last-seen move, but the owner's phone and the conversation are not alerted
//! again until the incident clears or escalates.

use std::collections::HashMap;
use std::sync::{Arc, LazyLock, Mutex};

use odin_domain::IncidentId;
use odin_huginn::incidents::{
    IncidentProjection, IncidentSeverityView, IncidentStatusView, IncidentView,
};
use odin_huginn::read_model::MaterializedReadModel;
use serde_json::json;
use time::OffsetDateTime;

/// Where a card that needs the owner's attention escalates; the recovery drivers' operator identity.
pub(crate) const OPERATOR_ESCALATION: &str = "seat:operator";

/// The wall-clock milliseconds incident identities and shared mints bind.
pub(crate) fn unix_ms(at: OffsetDateTime) -> u64 {
    u64::try_from((at.unix_timestamp_nanos() / 1_000_000).max(0)).unwrap_or(0)
}

#[derive(Clone, Debug)]
pub(crate) struct RaisedIncident {
    /// Who raised it: `seat:<seat>`, `monitor:<profile>/<watchdog>`,
    /// `routine:<id>` — names the source in the card and the logs.
    pub source: String,
    pub severity: IncidentSeverityView,
    /// One line: what happened.
    pub summary: String,
    /// Bounded detail: what was observed and what was expected.
    pub detail: String,
    /// The objects it concerns (a pod, a run, a seat).
    pub affected: Vec<String>,
    /// A stable signature: repeated raises of one condition share it.
    pub signature: String,
}

/// What raising did, leg by leg.
#[derive(Clone, Debug, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct IncidentReceipt {
    pub incident_id: String,
    pub published: bool,
    pub phone_alerted: bool,
    pub conversation_woken: bool,
    /// A repeat folded into the open incident of its signature: nobody is
    /// alerted again.
    pub coalesced: bool,
    /// How many raises the incident has absorbed, this one included.
    pub count: u32,
    /// Each leg that failed, with its reason.
    pub failures: Vec<String>,
}

/// How long an open incident absorbs repeats after it was last seen; a
/// condition that comes back later is news again.
pub(crate) const COALESCE_WINDOW: time::Duration = time::Duration::minutes(30);

/// One open incident, by signature.
#[derive(Clone, Debug)]
struct OpenIncident {
    view: IncidentView,
    count: u32,
}

fn severity_rank(severity: IncidentSeverityView) -> u8 {
    match severity {
        IncidentSeverityView::Info => 0,
        IncidentSeverityView::Warning => 1,
        IncidentSeverityView::Error => 2,
        IncidentSeverityView::Critical => 3,
    }
}

pub(crate) struct IncidentDesk {
    read_model: Arc<MaterializedReadModel>,
    runtime: Option<Arc<odin_hermes::runtime::HermesRuntime>>,
    phone_url: Option<String>,
    open: Mutex<HashMap<String, OpenIncident>>,
}

impl IncidentDesk {
    pub(crate) fn new(
        read_model: Arc<MaterializedReadModel>,
        runtime: Option<Arc<odin_hermes::runtime::HermesRuntime>>,
        phone_url: Option<String>,
    ) -> Self {
        Self {
            read_model,
            runtime,
            phone_url,
            open: Mutex::new(HashMap::new()),
        }
    }

    /// Every open incident, as Huginn shows it.
    pub(crate) fn open_views(&self) -> Vec<IncidentView> {
        self.open
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .values()
            .map(|open| open.view.clone())
            .collect()
    }

    pub(crate) fn raise(&self, incident: RaisedIncident) -> IncidentReceipt {
        self.raise_at(incident, OffsetDateTime::now_utc())
    }

    /// Folds a repeat into the open incident of its signature, when there is
    /// one seen within the window and the repeat does not escalate it.
    fn coalesce(&self, incident: &RaisedIncident, at: OffsetDateTime) -> Option<IncidentReceipt> {
        let mut open = self
            .open
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let entry = open.get_mut(&incident.signature)?;
        if at - entry.view.last_observed_at > COALESCE_WINDOW
            || severity_rank(incident.severity) > severity_rank(entry.view.severity)
        {
            return None;
        }
        entry.count = entry.count.saturating_add(1);
        entry.view.revision += 1;
        entry.view.last_observed_at = at.max(entry.view.first_observed_at);
        entry.view.observed_state = json!({
            "detail": incident.detail,
            "source": incident.source,
            "count": entry.count,
            "latest": incident.summary,
        });
        let view = entry.view.clone();
        let count = entry.count;
        drop(open);
        let mut failures = Vec::new();
        let published = match IncidentProjection::new(Arc::clone(&self.read_model)).publish(
            view.clone(),
            [],
            [],
        ) {
            Ok(_) => true,
            Err(error) => {
                failures.push(format!("huginn: {error}"));
                false
            }
        };
        tracing::info!(
            "incident coalesced id={} source={} signature={} count={count} \
             published={published} failures={failures:?}",
            view.incident_id,
            incident.source,
            incident.signature
        );
        Some(IncidentReceipt {
            incident_id: view.incident_id.to_string(),
            published,
            phone_alerted: false,
            conversation_woken: false,
            coalesced: true,
            count,
            failures,
        })
    }

    /// The condition behind `signature` no longer holds (or its source is
    /// gone): the open incident is resolved, and the next raise is news.
    /// A model account that runs out raises one incident, which wakes the conversation seat;
    /// the incident clears when the account has room again.
    pub(crate) fn out_notice(self: &Arc<Self>) -> odin_hermes::runtime::OutNotice {
        let desk = Arc::clone(self);
        Arc::new(move |account, lanes, cause| {
            let signature = format!("models:out:{account}");
            match cause {
                Some(cause) => {
                    desk.raise(RaisedIncident {
                        source: "models".to_owned(),
                        severity: IncidentSeverityView::Warning,
                        summary: format!(
                            "Model account {account} ran out; lanes {} are passed over until it has room",
                            lanes.join(", ")
                        ),
                        detail: cause.to_owned(),
                        affected: lanes.to_vec(),
                        signature,
                    });
                }
                None => desk.clear(&signature, "the account has room again"),
            }
        })
    }

    pub(crate) fn clear(&self, signature: &str, reason: &str) {
        let Some(mut entry) = self
            .open
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .remove(signature)
        else {
            return;
        };
        let at = OffsetDateTime::now_utc().max(entry.view.last_observed_at);
        entry.view.revision += 1;
        entry.view.status = IncidentStatusView::Resolved;
        entry.view.last_observed_at = at;
        let published = IncidentProjection::new(Arc::clone(&self.read_model))
            .publish(entry.view.clone(), [], [])
            .map_err(|error| error.to_string());
        tracing::info!(
            "incident cleared id={} signature={signature} count={} reason={reason}              published={published:?}",
            entry.view.incident_id, entry.count
        );
    }

    /// Re-publishes a condition that is still true but was already
    /// announced (a daemon restart forgot its card): the card returns to
    /// Huginn with no phone alert, no conversation wake and no routine.
    pub(crate) fn restate(&self, incident: RaisedIncident) -> Option<IncidentReceipt> {
        let open = self
            .open
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .contains_key(&incident.signature);
        (!open).then(|| self.raise_with(incident, OffsetDateTime::now_utc(), false))
    }

    fn raise_at(&self, incident: RaisedIncident, at: OffsetDateTime) -> IncidentReceipt {
        self.raise_with(incident, at, true)
    }

    fn raise_with(
        &self,
        incident: RaisedIncident,
        at: OffsetDateTime,
        announce: bool,
    ) -> IncidentReceipt {
        if let Some(receipt) = self.coalesce(&incident, at) {
            return receipt;
        }
        let mut failures = Vec::new();
        let incident_id =
            match IncidentId::from_parts("incident", unix_ms(at), uuid::Uuid::new_v4()) {
                Ok(id) => id,
                Err(error) => {
                    let reason = format!("incident identity: {error}");
                    tracing::error!(
                        "incident source={} signature={} not raised: {reason}",
                        incident.source,
                        incident.signature
                    );
                    return IncidentReceipt {
                        incident_id: String::new(),
                        published: false,
                        phone_alerted: false,
                        conversation_woken: false,
                        coalesced: false,
                        count: 1,
                        failures: vec![reason],
                    };
                }
            };
        let view = IncidentView {
            incident_id: incident_id.clone(),
            run_id: None,
            severity: incident.severity,
            confidence_micros: 1_000_000,
            deviation: incident.summary.clone(),
            failure_signature: incident.signature.clone(),
            expected_state: json!({}),
            observed_state: json!({ "detail": incident.detail, "source": incident.source }),
            affected_objects: incident.affected.clone(),
            evidence_refs: vec![incident.source.clone()],
            allowed_capabilities: Vec::new(),
            attempt_ids: Vec::new(),
            recommended_next_action: "The conversation seat tells the owner; the raising source \
                                      acts within its declared capabilities."
                .to_owned(),
            escalation_target: "seat:conversation".to_owned(),
            first_observed_at: at,
            last_observed_at: at,
            last_useful_progress_at: None,
            status: IncidentStatusView::Open,
            revision: 1,
        };
        // Escalating an open incident keeps its identity and history.
        let view = match self
            .open
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .get(&incident.signature)
            .filter(|open| at - open.view.last_observed_at <= COALESCE_WINDOW)
        {
            Some(open) => IncidentView {
                incident_id: open.view.incident_id.clone(),
                first_observed_at: open.view.first_observed_at,
                revision: open.view.revision + 1,
                status: IncidentStatusView::Escalated,
                ..view
            },
            None => view,
        };
        let incident_id = view.incident_id.clone();
        let count = {
            let mut open = self
                .open
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let count = open
                .get(&incident.signature)
                .filter(|open| open.view.incident_id == incident_id)
                .map_or(1, |open| open.count.saturating_add(1));
            open.insert(
                incident.signature.clone(),
                OpenIncident {
                    view: view.clone(),
                    count,
                },
            );
            count
        };
        let published =
            match IncidentProjection::new(Arc::clone(&self.read_model)).publish(view, [], []) {
                Ok(_) => true,
                Err(error) => {
                    failures.push(format!("huginn: {error}"));
                    false
                }
            };
        let alerting = announce
            && matches!(
                incident.severity,
                IncidentSeverityView::Warning
                    | IncidentSeverityView::Error
                    | IncidentSeverityView::Critical
            );
        // Only Error and Critical page the phone; warnings use the conversation.
        let paging = announce
            && matches!(
                incident.severity,
                IncidentSeverityView::Error | IncidentSeverityView::Critical
            );
        let phone_alerted = match (&self.phone_url, paging) {
            (Some(url), true) => match phone_alert(url, &incident) {
                Ok(()) => true,
                Err(error) => {
                    failures.push(format!("phone: {error}"));
                    false
                }
            },
            _ => false,
        };
        // Info stays in Huginn; warning and above reaches the owner.
        let conversation_woken = match (&self.runtime, alerting) {
            (Some(runtime), true) => {
                let text = format!(
                    "Incident ({:?}) raised by {}: {}\n{}\nThe governed reads show the current state. \
                     The reply tells the owner what happened and what, if anything, needs \
                     attention. A reply of exactly {} sends nothing.",
                    incident.severity, incident.source, incident.summary, incident.detail,
                    odin_hermes::conversation::QUIET_REPLY
                );
                let cause = format!(
                    "{:?} {}",
                    incident.severity,
                    odin_hermes::runtime::cause_of(&incident.summary)
                );
                match runtime.wake_event(
                    &format!("incident-{incident_id}"),
                    &text,
                    &format!("incident:{}", incident.source),
                    &cause,
                ) {
                    Ok(_) => true,
                    Err(error) => {
                        failures.push(format!("conversation: {error}"));
                        false
                    }
                }
            }
            _ => false,
        };
        // Routines that follow incidents.
        if alerting {
            if let Some(runtime) = &self.runtime {
                if let Err(error) = runtime.routine_event(
                    odin_registry::schema::RoutineEvent::Incident,
                    None,
                    incident_id.as_str(),
                    &format!("{} ({})", incident.summary, incident.source),
                    i64::try_from(unix_ms(at)).unwrap_or(i64::MAX),
                ) {
                    failures.push(format!("routines: {error}"));
                }
            }
        }
        tracing::info!(
            "incident id={incident_id} source={} severity={:?} signature={} \
             count={count} published={published} phone={phone_alerted} \
             woken={conversation_woken} failures={failures:?}",
            incident.source,
            incident.severity,
            incident.signature
        );
        IncidentReceipt {
            incident_id: incident_id.to_string(),
            published,
            phone_alerted,
            conversation_woken,
            coalesced: false,
            count,
            failures,
        }
    }
}
/// The most one phone alert may take, connect and answer included.
const PHONE_ALERT_BOUND: std::time::Duration = std::time::Duration::from_secs(5);
static PHONE_CLIENT: LazyLock<Result<reqwest::blocking::Client, String>> = LazyLock::new(|| {
    reqwest::blocking::Client::builder()
        .timeout(PHONE_ALERT_BOUND)
        .build()
        .map_err(|error| error.to_string())
});

/// One plain POST of the message to the declared ntfy topic, bounded.
fn phone_alert(url: &str, incident: &RaisedIncident) -> Result<(), String> {
    let client = PHONE_CLIENT.as_ref().map_err(Clone::clone)?;
    let response = client
        .post(url)
        .header("Title", format!("Odin {:?}", incident.severity))
        .body(format!("{} ({})", incident.summary, incident.source))
        .send()
        .map_err(|error| error.to_string())?;
    if response.status().is_success() {
        Ok(())
    } else {
        Err(format!("{url} answered {}", response.status()))
    }
}

impl odin_hermes::runtime::incidents::IncidentRoute for IncidentDesk {
    fn raise(
        &self,
        seat: &odin_domain::SeatId,
        severity: &str,
        summary: String,
        detail: String,
        affected: Vec<String>,
    ) -> Result<serde_json::Value, String> {
        let severity = match severity {
            "info" => IncidentSeverityView::Info,
            "warning" => IncidentSeverityView::Warning,
            "error" => IncidentSeverityView::Error,
            "critical" => IncidentSeverityView::Critical,
            other => {
                return Err(format!(
                    "severity {other:?} is not info|warning|error|critical"
                ))
            }
        };
        let signature = format!(
            "seat:{seat}:{}",
            summary.chars().take(80).collect::<String>()
        );
        let receipt = self.raise(RaisedIncident {
            source: format!("seat:{seat}"),
            severity,
            summary,
            detail,
            affected,
            signature,
        });
        serde_json::to_value(receipt).map_err(|error| error.to_string())
    }
}

/// Daemon authorities observed by a changed-only heartbeat.
pub(crate) struct HeartbeatWatch {
    pub(crate) read_model: Arc<odin_huginn::read_model::MaterializedReadModel>,
    pub(crate) incidents: Arc<IncidentDesk>,
    pub(crate) tasks: Arc<dyn odin_brain::source::state::tasks::TaskStateReader>,
    pub(crate) registry: Arc<odin_registry::SnapshotHandle>,
    pub(crate) simulation: Option<Arc<crate::simulation::SimulationDesk>>,
}

fn watches_project(
    watches: &std::collections::BTreeSet<String>,
    kind: &str,
    project: &str,
) -> bool {
    watches
        .iter()
        .any(|watch| watch == kind || watch.split_once(':') == Some((kind, project)))
}

fn incident_is_watched(
    incident: &IncidentView,
    objects: &HashMap<String, String>,
    is_watched: impl Fn(&str) -> bool,
) -> bool {
    incident
        .run_id
        .as_ref()
        .and_then(|run| objects.get(run.as_str()))
        .is_some_and(|project| is_watched(project))
        || incident.affected_objects.iter().any(|object| {
            objects
                .get(object)
                .is_some_and(|project| is_watched(project))
        })
}

fn telemetry_stale(
    now: OffsetDateTime,
    last: Option<OffsetDateTime>,
    policy: Option<(u32, u32)>,
) -> bool {
    match (last, policy) {
        (Some(last), Some((seconds, multiplier))) => {
            now - last
                > time::Duration::seconds(i64::from(seconds).saturating_mul(i64::from(multiplier)))
        }
        _ => false,
    }
}

impl odin_omp::live::service::HeartbeatWatched for HeartbeatWatch {
    fn digest(&self, seat: &odin_domain::SeatId) -> String {
        use odin_registry::{ObjectConfig, RegistryKind};
        let registry = self.registry.current();
        let Some(ObjectConfig::Seat(config)) = registry
            .object(RegistryKind::Seat, seat.as_str())
            .map(|object| &object.config)
        else {
            return format!("seat {seat} unavailable");
        };
        let watches = config.live.as_ref().map(|live| &live.watches);
        let watched = |kind: &str, project: &str| {
            config.project_scope.iter().any(|id| id.as_str() == project)
                && watches.is_some_and(|watches| watches_project(watches, kind, project))
        };
        let mut lines = Vec::new();
        let tasks = match self.tasks.snapshot() {
            Ok(tasks) => tasks,
            Err(error) => {
                lines.push(format!("tasks unreadable: {error}"));
                odin_brain::source::state::tasks::TaskStateSnapshot {
                    delegations: Vec::new(),
                    runs: Vec::new(),
                }
            }
        };
        let mut projects: HashMap<String, String> = tasks
            .runs
            .iter()
            .filter_map(|run| {
                run.project
                    .as_ref()
                    .map(|project| (run.run_id.clone(), project.clone()))
            })
            .collect();
        let mut incident_objects = projects.clone();
        for project in &config.project_scope {
            incident_objects.insert(project.to_string(), project.to_string());
            incident_objects.insert(format!("project:{project}"), project.to_string());
        }
        for task in &tasks.delegations {
            incident_objects.insert(task.child.clone(), task.project.clone());
        }
        let stall = |profile: &str| {
            registry
                .object(RegistryKind::Workload, profile)
                .and_then(|object| match &object.config {
                    ObjectConfig::Workload(profile) => {
                        profile.monitoring.as_ref().and_then(|monitoring| {
                            monitoring.stall_seconds.map(|seconds| {
                                (
                                    seconds.get(),
                                    monitoring
                                        .telemetry_stale_multiplier
                                        .map_or(2, |value| value.get()),
                                )
                            })
                        })
                    }
                    _ => None,
                })
        };
        for run in &tasks.runs {
            if run.seat.as_deref() == Some(seat.as_str())
                || run.project.as_deref().is_some_and(|project| {
                    watched("child_report", project) || watched("stall", project)
                })
            {
                lines.push(format!(
                    "task {} {} {}",
                    run.run_id, run.state, run.session_stopped
                ));
            }
        }
        for task in &tasks.delegations {
            if task.parent_seat.as_deref() == Some(seat.as_str())
                || watched("child_report", &task.project)
            {
                lines.push(format!(
                    "delegation {} {} {:?}",
                    task.child,
                    task.phase.as_str(),
                    task.child_state
                ));
            }
        }
        let now = OffsetDateTime::now_utc();
        match self
            .read_model
            .capture_kinds(&[odin_domain::huginn::ObjectKind::KubeResource])
        {
            Ok(capture) => {
                for object in capture.objects {
                    let Ok(view) = serde_json::from_value::<odin_domain::huginn::KubeWorkloadView>(
                        object.value,
                    ) else {
                        continue;
                    };
                    let odin_domain::huginn::KubeResourceOwnership::Odin {
                        run_id, lane_id, ..
                    } = &view.ownership
                    else {
                        continue;
                    };
                    if !projects.contains_key(run_id.as_str()) {
                        if let Some(ObjectConfig::Lane(lane)) = registry
                            .object(RegistryKind::Lane, lane_id.as_str())
                            .map(|object| &object.config)
                        {
                            projects.insert(run_id.to_string(), lane.project.to_string());
                        }
                    }
                    if let Some(project) = projects.get(run_id.as_str()) {
                        incident_objects.insert(run_id.to_string(), project.clone());
                        incident_objects.insert(view.resource.uid.to_string(), project.clone());
                        incident_objects.insert(view.resource.name.clone(), project.clone());
                    }
                    if !projects
                        .get(run_id.as_str())
                        .is_some_and(|project| watched("workload_watch", project))
                    {
                        continue;
                    }
                    let stale = view.state == odin_domain::huginn::KubeWorkloadState::Running
                        && telemetry_stale(
                            now,
                            view.status
                                .as_ref()
                                .map(|status| status.at)
                                .or(view.started_at),
                            view.profile.as_deref().and_then(&stall),
                        );
                    lines.push(format!(
                        "workload {} {:?} stale={stale}",
                        view.resource.uid, view.state
                    ));
                }
            }
            Err(error) => lines.push(format!("workloads unreadable: {error}")),
        }
        if let Some(simulation) = &self.simulation {
            match simulation.heartbeat_missions() {
                Ok(missions) => {
                    for (run, stage, profile, last, started) in missions {
                        if !projects
                            .get(run.as_str())
                            .is_some_and(|project| watched("simulation", project))
                        {
                            continue;
                        }
                        let stale = stage == odin_domain::huginn::SimulationMissionStage::Running
                            && telemetry_stale(now, last.or(started), stall(&profile));
                        lines.push(format!("mission {run} {stage:?} stale={stale}"));
                    }
                }
                Err(error) => lines.push(format!("missions unreadable: {error}")),
            }
        }
        lines.extend(
            self.incidents
                .open_views()
                .into_iter()
                .filter(|incident| {
                    incident_is_watched(incident, &incident_objects, |project| {
                        [
                            "workload_watch",
                            "simulation",
                            "child_report",
                            "stall",
                            "repo_watch",
                            "project_event",
                        ]
                        .iter()
                        .any(|kind| watched(kind, project))
                    })
                })
                .map(|incident| format!("incident {} {}", incident.incident_id, incident.revision)),
        );
        lines.sort();
        lines.join("\n")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn heartbeat_watch_filters_projects_and_kinds() {
        let watches = [
            "workload_watch:project-alpha".to_owned(),
            "simulation".to_owned(),
        ]
        .into_iter()
        .collect();
        assert!(watches_project(&watches, "workload_watch", "project-alpha"));
        assert!(!watches_project(&watches, "workload_watch", "odin"));
        assert!(watches_project(&watches, "simulation", "odin"));
        assert!(!watches_project(&watches, "stall", "project-alpha"));
    }

    #[test]
    fn heartbeat_telemetry_becomes_stale_only_after_twice_stall() {
        let sample = OffsetDateTime::UNIX_EPOCH;
        assert!(!telemetry_stale(
            sample + time::Duration::seconds(120),
            Some(sample),
            Some((60, 2))
        ));
        assert!(telemetry_stale(
            sample + time::Duration::seconds(121),
            Some(sample),
            Some((60, 2))
        ));
        assert!(!telemetry_stale(
            sample + time::Duration::seconds(121),
            Some(sample),
            Some((60, 3))
        ));
        assert!(!telemetry_stale(
            sample + time::Duration::seconds(121),
            None,
            Some((60, 2))
        ));
        assert!(!telemetry_stale(
            sample + time::Duration::seconds(121),
            Some(sample),
            None
        ));
    }

    fn desk() -> IncidentDesk {
        IncidentDesk::new(
            Arc::new(MaterializedReadModel::new(1024, OffsetDateTime::now_utc())),
            None,
            None,
        )
    }

    /// A loopback sink that answers every POST and counts them.
    fn counting_sink() -> (String, Arc<std::sync::atomic::AtomicUsize>) {
        use std::io::{Read as _, Write as _};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("sink binds");
        let url = format!(
            "http://{}/odin-incidents",
            listener.local_addr().expect("address")
        );
        let posts = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counted = Arc::clone(&posts);
        std::thread::spawn(move || {
            for mut stream in listener.incoming().flatten() {
                let mut request = [0_u8; 4096];
                let _ = stream.read(&mut request);
                counted.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                let _ = stream.write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                );
            }
        });
        (url, posts)
    }

    #[test]
    fn only_an_error_or_worse_pages_the_phone() {
        let (url, posts) = counting_sink();
        let desk = IncidentDesk::new(
            Arc::new(MaterializedReadModel::new(1024, OffsetDateTime::now_utc())),
            None,
            Some(url),
        );
        let warning = desk.raise_at(
            watchdog(IncidentSeverityView::Warning, 0.02),
            OffsetDateTime::now_utc(),
        );
        assert!(!warning.phone_alerted, "a warning is not pushed");
        assert_eq!(posts.load(std::sync::atomic::Ordering::SeqCst), 0);
        let error = desk.raise_at(
            RaisedIncident {
                signature: "watchdog:odin-6df1:diverged".to_owned(),
                ..watchdog(IncidentSeverityView::Error, 9.0)
            },
            OffsetDateTime::now_utc(),
        );
        assert!(error.phone_alerted, "{:?}", error.failures);
        assert!(error.failures.is_empty(), "{:?}", error.failures);
        assert_eq!(posts.load(std::sync::atomic::Ordering::SeqCst), 1);
    }

    fn watchdog(severity: IncidentSeverityView, value: f64) -> RaisedIncident {
        RaisedIncident {
            source: "monitor:residual-watch/residual-high".to_owned(),
            severity,
            summary: format!("Pod odin-6df1: watchdog residual-high fired (now {value})"),
            detail: "held for 3 consecutive checks".to_owned(),
            affected: vec!["odin-6df1".to_owned()],
            signature: "watchdog:odin-6df1:residual-high".to_owned(),
        }
    }

    #[test]
    fn heartbeat_incidents_follow_attributed_projects() {
        let desk = desk();
        desk.raise_at(
            watchdog(IncidentSeverityView::Warning, 0.1),
            OffsetDateTime::now_utc(),
        );
        let incident = desk.open_views().pop().expect("open incident");
        let objects = HashMap::from([("odin-6df1".to_owned(), "project-alpha".to_owned())]);
        assert!(incident_is_watched(&incident, &objects, |project| project == "project-alpha"));
        assert!(!incident_is_watched(&incident, &objects, |project| project == "odin"));
        assert!(!incident_is_watched(&incident, &HashMap::new(), |_| true));
    }

    #[test]
    fn a_repeating_watchdog_is_one_incident_until_it_clears() {
        let desk = desk();
        let t0 = OffsetDateTime::now_utc();
        let first = desk.raise_at(watchdog(IncidentSeverityView::Warning, 0.0099), t0);
        assert!(!first.coalesced);
        assert_eq!(first.count, 1);
        for minute in 1..=5 {
            let again = desk.raise_at(
                watchdog(IncidentSeverityView::Warning, 0.0098),
                t0 + time::Duration::minutes(minute),
            );
            assert!(again.coalesced, "minute {minute} must not alert again");
            assert!(!again.phone_alerted && !again.conversation_woken);
            assert_eq!(again.incident_id, first.incident_id);
            assert_eq!(again.count, u32::try_from(minute).unwrap() + 1);
        }
        // Another condition is its own incident.
        let other = RaisedIncident {
            signature: "watchdog:odin-6df1:beat-negative".to_owned(),
            ..watchdog(IncidentSeverityView::Warning, 1.0)
        };
        assert!(!desk.raise_at(other, t0).coalesced);
        // Cleared, the same condition is news again.
        desk.clear(
            "watchdog:odin-6df1:residual-high",
            "the condition no longer holds",
        );
        let back = desk.raise_at(
            watchdog(IncidentSeverityView::Warning, 0.0097),
            t0 + time::Duration::minutes(6),
        );
        assert!(!back.coalesced);
        assert_ne!(back.incident_id, first.incident_id);
    }
}
