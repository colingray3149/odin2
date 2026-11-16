//! Events a project's own tooling reports (`odin huginn event`), as routine triggers and watcher wakes.
//!
//! The tooling reports over Huginn with its host's paired credential, as
//! odin-cards-watch reports attaches (`device_event.rs`): the report reaches
//! here only on the authenticated port, and a revoked device is refused like
//! an unknown one. The event fires the conversation seat's `project_event`
//! routines for that project, keyed by project and the report's key, so a
//! retried report fires nothing new; then it wakes the seats whose `[live]
//! watches` declare `project_event:<project>`, routed to that project's
//! sessions. That wake is best effort: a seat with no live session misses it,
//! and a key seen among the last [`RECENT_KEYS`] wakes no one again.

use std::collections::VecDeque;
use std::sync::Arc;

use odin_domain::huginn as live;
use odin_huginn::devices::{DeviceTrustStore, SqliteDeviceTrustStore};

pub(crate) trait ProjectRoutines: Send + Sync + 'static {
    /// Queues every matching routine once per `key`; returns how many fired.
    fn project_event(
        &self,
        project: &str,
        kind: &str,
        key: &str,
        detail: &str,
        at_ms: i64,
    ) -> Result<usize, String>;

    /// Wakes the seats declaring `watch`; `true` when one took it or none watches.
    async fn wake_watchers(&self, watch: &str, project: &str, id: &str, text: &str) -> bool;
}

impl ProjectRoutines for odin_hermes::runtime::HermesRuntime {
    fn project_event(
        &self,
        project: &str,
        kind: &str,
        key: &str,
        detail: &str,
        at_ms: i64,
    ) -> Result<usize, String> {
        self.routine_project_event(project, kind, key, detail, at_ms)
    }

    async fn wake_watchers(&self, watch: &str, project: &str, id: &str, text: &str) -> bool {
        crate::child_report::wake_declared(self, watch, Some(project), id, text).await
    }
}

/// How many reported keys the watcher wake remembers.
const RECENT_KEYS: usize = 256;

pub(crate) struct ProjectEventIntake<D, R> {
    devices: Arc<D>,
    routines: Arc<R>,
    recent: parking_lot::Mutex<VecDeque<String>>,
}

pub(crate) type ProjectIntake =
    ProjectEventIntake<SqliteDeviceTrustStore, odin_hermes::runtime::HermesRuntime>;

/// The intake where the conversation seat's runtime is composed.
pub(crate) fn intake(
    devices: &Arc<SqliteDeviceTrustStore>,
    runtime: Option<&Arc<odin_hermes::runtime::HermesRuntime>>,
) -> Option<Arc<ProjectIntake>> {
    runtime.map(|runtime| {
        Arc::new(ProjectEventIntake::new(
            Arc::clone(devices),
            Arc::clone(runtime),
        ))
    })
}

/// `project_event:<project>:<key>`: the watch wake's id names the project, so it reaches that project's sessions.
fn occurrence_key(report: &live::ProjectEventReport) -> String {
    format!("project_event:{}:{}", report.project, report.key)
}

impl<D: DeviceTrustStore + 'static, R: ProjectRoutines> ProjectEventIntake<D, R> {
    pub(crate) fn new(devices: Arc<D>, routines: Arc<R>) -> Self {
        Self {
            devices,
            routines,
            recent: parking_lot::Mutex::new(VecDeque::new()),
        }
    }

    /// `true` the first time `key` is seen among the recent keys.
    fn first_report(&self, key: &str) -> bool {
        let mut recent = self.recent.lock();
        if recent.iter().any(|seen| seen == key) {
            return false;
        }
        if recent.len() == RECENT_KEYS {
            recent.pop_front();
        }
        recent.push_back(key.to_owned());
        true
    }

    pub(crate) async fn report(
        &self,
        device: live::DeviceId,
        report: live::ProjectEventReport,
    ) -> Result<live::HuginnResponse, live::HuginnProtocolError> {
        report
            .check()
            .map_err(|message| live::HuginnProtocolError::InvalidRequest {
                code: "projectEvent".to_owned(),
                message,
            })?;
        let label = match self.devices.get(device).await {
            Ok(Some(record)) if record.revoked_at.is_none() => record.label,
            Ok(_) => {
                tracing::error!("project event refused device={device} reason=not paired");
                return Err(live::HuginnProtocolError::Unauthenticated);
            }
            Err(error) => {
                tracing::error!("project event device_lookup_failed device={device} error={error}");
                return Err(live::HuginnProtocolError::unavailable(
                    "projectEventDevice",
                    error,
                ));
            }
        };
        let key = occurrence_key(&report);
        let detail = format!(
            "{} {}: {} (reported by {label})",
            report.project, report.kind, report.detail
        );
        let at_ms =
            i64::try_from(time::OffsetDateTime::now_utc().unix_timestamp_nanos() / 1_000_000)
                .unwrap_or(i64::MAX);
        let routines = Arc::clone(&self.routines);
        let (project, kind) = (report.project.to_string(), report.kind.clone());
        let (queued_key, queued_detail) = (key.clone(), detail.clone());
        // Queuing writes the schedule store: off the async workers.
        let fired = tokio::task::spawn_blocking(move || {
            routines.project_event(&project, &kind, &queued_key, &queued_detail, at_ms)
        })
        .await
        .map_err(|error| {
            tracing::error!("project event join_failed error={error}");
            live::HuginnProtocolError::unavailable("projectEventRoutines", error)
        })?
        .map_err(|error| {
            tracing::error!(
                "project event not queued project={} kind={} key={} error={error}",
                report.project,
                report.kind,
                report.key
            );
            live::HuginnProtocolError::unavailable("projectEventRoutines", error)
        })?;
        let woken = self.first_report(&key)
            && self
                .routines
                .wake_watchers(
                    "project_event",
                    report.project.as_str(),
                    &key,
                    &format!("Project event: {detail}"),
                )
                .await;
        tracing::info!(
            "project event device={device} surface={label} project={} kind={} key={} routines_fired={fired} watchers_woken={woken}",
            report.project,
            report.kind,
            report.key
        );
        Ok(live::HuginnResponse::Ack)
    }
}

#[cfg(test)]
#[path = "tests/project_event.rs"]
mod tests;
