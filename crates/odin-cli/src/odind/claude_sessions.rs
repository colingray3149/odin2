//! Durable Claude driver ownership, effect intent and transcript projection.
//! Backends own placement-specific journals; this store never guesses orphan ownership.
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use odin_domain::Scope;
use odin_hermes::runtime::claude::*;
use odin_huginn::read_model::MaterializedReadModel;
use odin_omp::host_tools::HostToolError;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

const TOOL: &str = "claude_session";

/// A successful backend result contains observed facts, never planned resource IDs.
#[derive(Default)]
pub struct ClaudeBackendOutcome {
    pub resource: Option<Value>,
    pub claude_session_id: Option<String>,
    pub remote_control: Option<Value>,
    pub events: Vec<Value>,
    /// More owning-host transcript frames remain beyond this bounded observation.
    pub has_more: bool,
    /// The session is gone on its own (a host tab closed); its record stops.
    pub ended: bool,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum CarrierPresence {
    Present,
    Absent,
    #[default]
    Unknown,
}

/// Each backend must journal the session UUID before touching external resources.
/// Errors other than Uncertain/PostEffect must prove no effect occurred. Stop may
/// recover its own per-UUID journal when open failed before returning a receipt.
pub trait ClaudeSessionBackend: Send + Sync {
    fn preflight(&self, request: &ClaudeOpenRequest) -> Result<(), HostToolError>;
    fn resolve(&self, request: &ClaudeOpenRequest) -> Result<ClaudeOpenRequest, HostToolError>;
    fn open(
        &self,
        effect: &odin_kernel::PreparedEffect,
        session: &ClaudeSessionRecord,
    ) -> Result<ClaudeBackendOutcome, HostToolError>;
    fn prompt(
        &self,
        effect: &odin_kernel::PreparedEffect,
        session: &ClaudeSessionRecord,
        text: &str,
    ) -> Result<ClaudeBackendOutcome, HostToolError>;
    fn read(&self, session: &ClaudeSessionRecord) -> Result<ClaudeBackendOutcome, HostToolError>;
    /// Explicit reads may fetch host transcripts; the background pump only observes liveness.
    fn read_transcript(
        &self,
        session: &ClaudeSessionRecord,
    ) -> Result<ClaudeBackendOutcome, HostToolError> {
        self.read(session)
    }
    fn stop(
        &self,
        effect: &odin_kernel::PreparedEffect,
        session: &ClaudeSessionRecord,
        discard_unpushed: bool,
    ) -> Result<ClaudeBackendOutcome, HostToolError>;
    /// Prove a pod is gone. A transport error must return Unknown, never Absent.
    fn carrier_presence(&self, session: &ClaudeSessionRecord) -> CarrierPresence {
        let _ = session;
        CarrierPresence::Unknown
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredSession {
    session: ClaudeSessionRecord,
    events: Vec<ClaudeSessionEvent>,
    observed_at: time::OffsetDateTime,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    ended_at: Option<time::OffsetDateTime>,
    #[serde(skip)]
    needs_persist: bool,
}

pub struct DaemonClaudeSessionRoute {
    root: PathBuf,
    sessions: Mutex<BTreeMap<String, StoredSession>>,
    pod: Arc<dyn ClaudeSessionBackend>,
    host: Arc<dyn ClaudeSessionBackend>,
    read_model: Arc<MaterializedReadModel>,
    pin: Arc<odin_registry::SnapshotHandle>,
    incidents: Option<Arc<crate::incidents::IncidentDesk>>,
}

fn storage(error: impl std::fmt::Display) -> HostToolError {
    HostToolError::Storage {
        tool: TOOL,
        detail: error.to_string(),
    }
}
fn refused(detail: impl Into<String>) -> HostToolError {
    HostToolError::Arguments {
        tool: TOOL,
        detail: detail.into(),
    }
}
fn uncertain(detail: impl Into<String>) -> HostToolError {
    HostToolError::Uncertain {
        tool: TOOL,
        detail: detail.into(),
    }
}

/// The most entries one JSON container of a session record may hold.
const CODEC_CONTAINER_MAX: usize = 65_536;
/// The quiet window of a session whose workload declares none.
const DEFAULT_QUIET_SECONDS: u32 = 600;

// Leave room for the Huginn/tool envelope below the 16 MiB codec frame.
const TRANSCRIPT_MAX_BYTES: usize = 512 * 1024;
const TRANSCRIPT_MAX_EVENTS: usize = 256;
const TRANSCRIPT_ENVELOPE_BYTES: usize = 1024;

struct BoundedJsonSize {
    bytes: usize,
    limit: usize,
}
impl std::io::Write for BoundedJsonSize {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if bytes.len() > self.limit.saturating_sub(self.bytes) {
            return Err(std::io::Error::other(
                "transcript output exceeds byte limit",
            ));
        }
        self.bytes += bytes.len();
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn bounded_json_size(value: &impl Serialize, limit: usize) -> Option<usize> {
    let mut writer = BoundedJsonSize { bytes: 0, limit };
    serde_json::to_writer(&mut writer, value).ok()?;
    Some(writer.bytes)
}

// Arbitrary backend JSON must also respect the codec's container bounds.
fn codec_safe(value: &Value, depth: usize) -> bool {
    if depth > 64 {
        return false;
    }
    match value {
        Value::Array(values) => {
            values.len() <= CODEC_CONTAINER_MAX
                && values.iter().all(|value| codec_safe(value, depth + 1))
        }
        Value::Object(values) => {
            values.len() <= CODEC_CONTAINER_MAX
                && values.values().all(|value| codec_safe(value, depth + 1))
        }
        _ => true,
    }
}

fn transcript_budget(session: &ClaudeSessionRecord) -> Result<usize, HostToolError> {
    let size = bounded_json_size(session, TRANSCRIPT_MAX_BYTES - TRANSCRIPT_ENVELOPE_BYTES)
        .filter(|_| {
            session.request.mcp.len() <= CODEC_CONTAINER_MAX
                && session
                    .resource
                    .as_ref()
                    .is_none_or(|value| codec_safe(value, 0))
                && session
                    .remote_control
                    .as_ref()
                    .is_none_or(|value| codec_safe(value, 0))
        })
        .ok_or_else(|| refused("Claude session metadata exceeds transcript output capacity"))?;
    Ok(TRANSCRIPT_MAX_BYTES - TRANSCRIPT_ENVELOPE_BYTES - size)
}

fn event_size(event: &ClaudeSessionEvent, budget: usize) -> Option<usize> {
    bounded_json_size(event, budget.saturating_sub(1))
        .filter(|_| codec_safe(&event.payload, 0))
        .map(|size| size + 1)
}

fn transcript_page(stored: &StoredSession, since: u64) -> Result<ClaudeReadReply, HostToolError> {
    let mut remaining = transcript_budget(&stored.session)?;
    let mut events = Vec::new();
    let mut next_cursor = since;
    let mut error = None;
    // Durable cursors are contiguous and one-based; do not rescan old pages.
    let start = usize::try_from(since)
        .unwrap_or(usize::MAX)
        .min(stored.events.len());
    for event in stored.events[start..].iter().take(TRANSCRIPT_MAX_EVENTS) {
        let Some(size) = event_size(event, remaining) else {
            if events.is_empty() {
                error = Some(ClaudeReadError::EventTooLarge {
                    cursor: event.cursor,
                    max_bytes: remaining as u64,
                });
            }
            break;
        };
        remaining -= size;
        next_cursor = event.cursor;
        events.push(event.clone());
    }
    Ok(ClaudeReadReply {
        session: stored.session.clone(),
        events,
        next_cursor,
        has_more: next_cursor < stored.session.cursor,
        error,
    })
}

#[derive(Serialize)]
struct TranscriptProjection<'a> {
    session: &'a ClaudeSessionRecord,
    events: &'a [ClaudeSessionEvent],
    observed_at: time::OffsetDateTime,
    #[serde(rename = "endedAt", skip_serializing_if = "Option::is_none")]
    ended_at: Option<time::OffsetDateTime>,
    #[serde(rename = "quietSeconds")]
    quiet_seconds: u32,
    #[serde(rename = "pendingPermissionCount")]
    pending_permission_count: usize,
    event_start: Option<u64>,
    event_end: Option<u64>,
    has_more: bool,
}

fn transcript_projection(
    stored: &StoredSession,
    quiet_seconds: u32,
) -> Result<TranscriptProjection<'_>, HostToolError> {
    let mut remaining = transcript_budget(&stored.session)?;
    let mut start = stored.events.len();
    for event in stored.events.iter().rev().take(TRANSCRIPT_MAX_EVENTS) {
        let Some(size) = event_size(event, remaining) else {
            break;
        };
        remaining -= size;
        start -= 1;
    }
    let events = &stored.events[start..];
    Ok(TranscriptProjection {
        session: &stored.session,
        events,
        observed_at: stored.observed_at,
        ended_at: stored.ended_at,
        quiet_seconds,
        pending_permission_count: pending_permission_ids(&stored.events).len(),
        event_start: events.first().map(|event| event.cursor),
        event_end: events.last().map(|event| event.cursor),
        has_more: start != 0,
    })
}

impl StoredSession {
    fn event(&mut self, kind: &str, payload: Value) -> Result<(), HostToolError> {
        self.session.cursor = self
            .session
            .cursor
            .checked_add(1)
            .ok_or_else(|| storage("transcript cursor exhausted"))?;
        self.observed_at = time::OffsetDateTime::now_utc();
        self.needs_persist = true;
        self.events.push(ClaudeSessionEvent {
            cursor: self.session.cursor,
            kind: kind.into(),
            payload,
        });
        Ok(())
    }

    fn apply(&mut self, outcome: ClaudeBackendOutcome) -> Result<(), HostToolError> {
        if let Some(resource) = outcome.resource {
            self.session.resource = Some(resource);
        }
        if let Some(id) = outcome.claude_session_id {
            self.session.claude_session_id = Some(id);
        }
        if let Some(rc) = outcome.remote_control {
            self.session.remote_control = Some(rc);
        }
        if outcome.ended {
            self.session.state = ClaudeSessionState::Stopped;
            self.ended_at = Some(time::OffsetDateTime::now_utc());
        }
        let mut last_driver_cursor = self.session.last_driver_cursor;
        let mut last_publication_cursor = self.session.last_publication_cursor;
        for event in outcome.events {
            if let Some(cursor) = event.get("driver_cursor").and_then(Value::as_u64) {
                if last_driver_cursor.is_some_and(|last| cursor <= last) {
                    continue;
                }
                last_driver_cursor = Some(cursor);
            }
            if let Some(cursor) = event.get("publication_cursor").and_then(Value::as_u64) {
                if last_publication_cursor.is_some_and(|last| cursor <= last) {
                    continue;
                }
                last_publication_cursor = Some(cursor);
            }
            self.event("backend", event)?;
            self.session.last_driver_cursor = last_driver_cursor;
            self.session.last_publication_cursor = last_publication_cursor;
        }
        Ok(())
    }
}

impl DaemonClaudeSessionRoute {
    pub fn new(
        state_root: &Path,
        pod: Arc<dyn ClaudeSessionBackend>,
        host: Arc<dyn ClaudeSessionBackend>,
        read_model: Arc<MaterializedReadModel>,
        pin: Arc<odin_registry::SnapshotHandle>,
        incidents: Option<Arc<crate::incidents::IncidentDesk>>,
    ) -> Result<Self, HostToolError> {
        let root = state_root.join("claude-sessions");
        fs::create_dir_all(&root).map_err(storage)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).map_err(storage)?;
        }
        let mut sessions = BTreeMap::new();
        for entry in fs::read_dir(&root).map_err(storage)? {
            let path = entry.map_err(storage)?.path();
            if path.extension().and_then(|value| value.to_str()) != Some("json") {
                continue;
            }
            let stored: StoredSession =
                serde_json::from_slice(&fs::read(&path).map_err(storage)?).map_err(storage)?;
            let id = uuid::Uuid::parse_str(&stored.session.session).map_err(storage)?;
            if path.file_stem().and_then(|value| value.to_str()) != Some(id.to_string().as_str()) {
                return Err(storage("session filename does not match durable ownership"));
            }
            if stored
                .events
                .iter()
                .enumerate()
                .any(|(index, event)| event.cursor != index as u64 + 1)
                || stored.events.last().map_or(0, |event| event.cursor) != stored.session.cursor
            {
                return Err(storage("durable transcript cursor is corrupt"));
            }
            for (key, acknowledged) in [
                ("driver_cursor", stored.session.last_driver_cursor),
                ("publication_cursor", stored.session.last_publication_cursor),
            ] {
                let observed = stored
                    .events
                    .iter()
                    .filter(|event| event.kind == "backend")
                    .filter_map(|event| event.payload.get(key).and_then(Value::as_u64))
                    .max();
                if observed != acknowledged {
                    return Err(storage(
                        "durable backend acknowledgement does not match transcript",
                    ));
                }
            }
            sessions.insert(stored.session.session.clone(), stored);
        }
        let route = Self {
            root,
            sessions: Mutex::new(sessions),
            pod,
            host,
            read_model,
            pin,
            incidents,
        };
        {
            let mut sessions = route.sessions.lock().map_err(storage)?;
            for stored in sessions.values_mut() {
                if matches!(
                    stored.session.state,
                    ClaudeSessionState::Opening
                        | ClaudeSessionState::Prompting
                        | ClaudeSessionState::Stopping
                ) {
                    stored.session.state = ClaudeSessionState::InDoubt;
                    stored.session.last_error =
                        Some("daemon restarted during an effect; do not replay blindly".into());
                    stored.event("in_doubt", json!({"reason":"daemon_restart"}))?;
                    route.persist(stored)?;
                } else if stored.session.state == ClaudeSessionState::Running
                    && stored.session.request.placement.unwrap_or_default() == ClaudePlacement::Pod
                    && route
                        .backend(&stored.session.request)
                        .carrier_presence(&stored.session)
                        == CarrierPresence::Absent
                {
                    // Inspect proved the pod object is gone. A transport error
                    // is Unknown and leaves the record Running.
                    const CAUSE: &str = "daemon restarted; pod not found";
                    stored.session.state = ClaudeSessionState::InDoubt;
                    stored.session.last_error = Some(CAUSE.into());
                    stored.event("in_doubt", json!({"reason": CAUSE}))?;
                    route.persist(stored)?;
                }
                route.project(stored)?;
            }
        }
        Ok(route)
    }

    fn backend(&self, request: &ClaudeOpenRequest) -> &dyn ClaudeSessionBackend {
        let placement = request
            .placement
            .or_else(|| {
                let id = request.preset.as_deref()?;
                let preset = super::claude_host::declared_preset(&self.pin.current(), id).ok()?;
                super::claude_host::launch_placement(preset.placement)
            })
            .unwrap_or_default();
        match placement {
            ClaudePlacement::Pod => self.pod.as_ref(),
            ClaudePlacement::HostTab => self.host.as_ref(),
        }
    }

    fn persist(&self, stored: &mut StoredSession) -> Result<(), HostToolError> {
        let destination = self.root.join(format!("{}.json", stored.session.session));
        let bytes = serde_json::to_vec(&*stored).map_err(storage)?;
        odin_cli::authority_provision::write_private_atomic(&destination, &bytes)
            .map_err(storage)?;
        stored.needs_persist = false;
        Ok(())
    }

    fn finish(
        &self,
        stored: &mut StoredSession,
        previous: ClaudeSessionState,
        success: ClaudeSessionState,
        kind: &str,
        result: Result<ClaudeBackendOutcome, HostToolError>,
    ) -> Result<ClaudeSessionRecord, HostToolError> {
        match result {
            Ok(outcome) => {
                if let Err(error) = stored.apply(outcome) {
                    stored.session.state = ClaudeSessionState::InDoubt;
                    stored.session.last_error = Some(error.to_string());
                    stored.needs_persist = true;
                    return Err(uncertain(error.to_string()));
                }
                stored.session.state = success;
                stored.session.last_error = None;
                if success == ClaudeSessionState::Stopped {
                    stored.ended_at = Some(time::OffsetDateTime::now_utc());
                    self.clear_quiet(stored);
                }
                stored
                    .event(kind, json!({}))
                    .map_err(|error| uncertain(error.to_string()))?;
                if let Err(error) = self.persist(stored) {
                    stored.session.state = ClaudeSessionState::InDoubt;
                    stored.session.last_error = Some(error.to_string());
                    return Err(uncertain(error.to_string()));
                }
                self.project(stored)
                    .map_err(|error| uncertain(error.to_string()))?;
                Ok(stored.session.clone())
            }
            Err(error) => {
                let ambiguous = matches!(
                    error,
                    HostToolError::Uncertain { .. } | HostToolError::PostEffect { .. }
                );
                stored.session.state = if ambiguous {
                    ClaudeSessionState::InDoubt
                } else {
                    previous
                };
                stored.session.last_error = Some(error.to_string());
                stored.event(
                    if ambiguous { "in_doubt" } else { "refused" },
                    json!({"reason":error.to_string()}),
                )?;
                if let Err(persist) = self.persist(stored) {
                    stored.session.state = ClaudeSessionState::InDoubt;
                    return Err(uncertain(format!(
                        "{error}; cannot persist result: {persist}"
                    )));
                }
                self.project(stored).map_err(|project| {
                    uncertain(format!("{error}; cannot project result: {project}"))
                })?;
                Err(error)
            }
        }
    }
}

fn owner(scope: &Scope) -> Result<&str, HostToolError> {
    scope
        .run
        .as_ref()
        .map(|run| run.as_str())
        .ok_or(HostToolError::Scope {
            tool: TOOL,
            reason: "a bound caller run is required",
        })
}

impl DaemonClaudeSessionRoute {
    /// Reads only the existing backend spool. No prompts, pushes or new launches.
    pub fn start_projection_pump(self: &Arc<Self>) {
        let weak = Arc::downgrade(self);
        tokio::spawn(async move {
            /// How often the projection reads each backend's spool.
            const PROJECTION_TICK: std::time::Duration = std::time::Duration::from_secs(2);
            let mut interval = tokio::time::interval(PROJECTION_TICK);
            loop {
                interval.tick().await;
                let Some(route) = weak.upgrade() else {
                    break;
                };
                let result =
                    tokio::task::spawn_blocking(move || route.refresh_observations()).await;
                match result {
                    Ok(Ok(())) => {}
                    Ok(Err(error)) => {
                        tracing::warn!("Claude transcript projection unavailable error={error}")
                    }
                    Err(error) => {
                        tracing::error!("Claude transcript projection worker failed error={error}")
                    }
                }
            }
        });
    }

    fn refresh_observations(&self) -> Result<(), HostToolError> {
        let mut sessions = match self.sessions.try_lock() {
            Ok(sessions) => sessions,
            Err(std::sync::TryLockError::WouldBlock) => return Ok(()),
            Err(error) => return Err(storage(error)),
        };
        for stored in sessions.values_mut() {
            if !matches!(
                stored.session.state,
                ClaudeSessionState::Running | ClaudeSessionState::InDoubt
            ) {
                continue;
            }
            match self.observe(stored) {
                Ok(()) => self.note_quiet(stored),
                Err(error) => {
                    tracing::error!(
                        "Claude session observation failed session={} error={error}",
                        stored.session.session
                    );
                }
            }
        }
        Ok(())
    }

    fn observe(&self, stored: &mut StoredSession) -> Result<(), HostToolError> {
        self.observe_with_transcript(stored, false).map(|_| ())
    }

    fn observe_with_transcript(
        &self,
        stored: &mut StoredSession,
        transcript: bool,
    ) -> Result<bool, HostToolError> {
        // A failed post-effect write must not acknowledge volatile transcript
        // cursors to the backend spool or project them as durable evidence.
        if stored.needs_persist {
            self.persist(stored)?;
        }
        let backend = self.backend(&stored.session.request);
        let outcome = if transcript {
            backend.read_transcript(&stored.session)?
        } else {
            backend.read(&stored.session)?
        };
        let has_more = outcome.has_more;
        let previous = stored.session.clone();
        let previous_time = stored.observed_at;
        let previous_len = stored.events.len();
        let result = (|| {
            stored.apply(outcome)?;
            if stored.session.state == ClaudeSessionState::Stopped {
                self.clear_quiet(stored);
            }
            if stored.session != previous {
                if stored.session.cursor == previous.cursor {
                    stored.event("observed", json!({}))?;
                }
                self.persist(stored)?;
            }
            Ok::<(), HostToolError>(())
        })();
        if let Err(error) = result {
            stored.session = previous;
            stored.observed_at = previous_time;
            stored.events.truncate(previous_len);
            return Err(error);
        }
        self.project(stored)?;
        Ok(has_more)
    }

    fn project(&self, stored: &StoredSession) -> Result<(), HostToolError> {
        use odin_domain::huginn::{
            Freshness, FreshnessState, ObjectKind, ObjectRef, QueryScope, Revision, RevisionSource,
        };
        use odin_huginn::read_model::{project_object, ProjectionMetadata};
        let projection = transcript_projection(stored, self.quiet_seconds(stored))?;
        let mut metadata = ProjectionMetadata::new(
            stored
                .session
                .request
                .name
                .as_deref()
                .unwrap_or("Claude driver"),
            format!(
                "Claude {:?} on {:?}",
                stored.session.state,
                stored.session.request.placement.unwrap_or_default()
            ),
        )
        .in_scope(QueryScope::Run(
            odin_domain::RunId::new(&stored.session.owner_run).map_err(storage)?,
        ));
        if !stored.session.request.project.is_empty() {
            metadata = metadata.in_scope(QueryScope::Project(
                odin_domain::ProjectId::new(&stored.session.request.project).map_err(storage)?,
            ));
        }
        let snapshot = project_object(
            ObjectRef {
                kind: ObjectKind::Session,
                id: format!("claude:{}", stored.session.session),
            },
            Revision::new(stored.session.cursor),
            RevisionSource::Adapter {
                name: "claude-driver".into(),
            },
            Freshness {
                state: FreshnessState::Unknown,
                observed_at: stored.observed_at,
                source_updated_at: Some(stored.observed_at),
                stale_after_seconds: None,
            },
            &projection,
            &metadata,
        )
        .map_err(storage)?;
        self.read_model
            .upsert_indexed(snapshot, metadata)
            .map_err(storage)?;
        Ok(())
    }
    fn quiet_seconds(&self, stored: &StoredSession) -> u32 {
        let Some(id) = stored
            .session
            .resource
            .as_ref()
            .and_then(|value| value.get("workload"))
            .and_then(Value::as_str)
        else {
            return DEFAULT_QUIET_SECONDS;
        };
        match self
            .pin
            .current()
            .object(odin_registry::RegistryKind::Workload, id)
            .map(|object| &object.config)
        {
            Some(odin_registry::ObjectConfig::ClaudeCode(profile)) if profile.enabled => {
                profile.quiet_seconds
            }
            _ => DEFAULT_QUIET_SECONDS,
        }
    }

    fn quiet_for(&self, stored: &StoredSession) -> Option<u64> {
        if stored.session.state != ClaudeSessionState::Running
            || !pending_permission_ids(&stored.events).is_empty()
        {
            return None;
        }
        let age = (time::OffsetDateTime::now_utc() - stored.observed_at).whole_seconds();
        (age >= i64::from(self.quiet_seconds(stored))).then_some(u64::try_from(age).unwrap_or(0))
    }

    fn note_quiet(&self, stored: &StoredSession) {
        if stored.session.request.placement.unwrap_or_default() != ClaudePlacement::Pod {
            return;
        }
        let Some(seconds) = self.quiet_for(stored) else {
            self.clear_quiet(stored);
            return;
        };
        let Some(desk) = &self.incidents else {
            return;
        };
        let name = stored
            .session
            .request
            .name
            .as_deref()
            .unwrap_or(stored.session.session.as_str());
        desk.raise(crate::incidents::RaisedIncident {
            source: format!("claude:{}", stored.session.session),
            severity: odin_huginn::incidents::IncidentSeverityView::Error,
            summary: format!("Claude session {name} quiet {}m", seconds / 60),
            detail: format!(
                "no output for {seconds}s; quiet_seconds is {}",
                self.quiet_seconds(stored)
            ),
            affected: vec![format!("claude:{}", stored.session.session)],
            signature: format!("quiet:{}", stored.session.session),
        });
    }

    fn clear_quiet(&self, stored: &StoredSession) {
        if let Some(desk) = &self.incidents {
            desk.clear(
                &format!("quiet:{}", stored.session.session),
                "condition ended",
            );
        }
    }

    fn session_cap(&self, seat: &str) -> Result<u16, HostToolError> {
        let snapshot = self.pin.current();
        let Some(odin_registry::ObjectConfig::Seat(declared)) = snapshot
            .object(odin_registry::RegistryKind::Seat, seat)
            .map(|object| &object.config)
        else {
            return Err(refused(format!(
                "seat {seat} does not declare limits.max_sessions"
            )));
        };
        Ok(declared.limits.max_sessions)
    }

    /// The opening run owns a session. A session opened by a conversation seat
    /// belongs to that conversation, whose run changes on every rollover or
    /// restart, so its later turns and routines keep it; other seats do not.
    fn owns(&self, session: &ClaudeSessionRecord, scope: &Scope) -> Result<bool, HostToolError> {
        if session.owner_run == owner(scope)? {
            return Ok(true);
        }
        Ok(session.seat.is_some()
            && session.seat.as_deref() == scope.seat.as_ref().map(|seat| seat.as_str())
            && owner_facing(&self.pin.current(), scope))
    }

    fn owned<'a>(
        &self,
        sessions: &'a mut BTreeMap<String, StoredSession>,
        scope: &Scope,
        id: &str,
    ) -> Result<&'a mut StoredSession, HostToolError> {
        uuid::Uuid::parse_str(id)
            .map_err(|error| refused(format!("invalid session UUID {id:?}: {error}")))?;
        let stored = sessions
            .get_mut(id)
            .ok_or_else(|| refused("unknown owned Claude session"))?;
        if !self.owns(&stored.session, scope)? {
            return Err(HostToolError::Scope {
                tool: TOOL,
                reason: if stored.session.seat.is_none() {
                    "session records no opening seat, so only its opening run owns it"
                } else {
                    "session belongs to a different caller run or conversation"
                },
            });
        }
        Ok(stored)
    }

    fn intent(
        &self,
        stored: &mut StoredSession,
        state: ClaudeSessionState,
        kind: &str,
    ) -> Result<(), HostToolError> {
        stored.session.state = state;
        stored.event(kind, json!({}))?;
        self.persist(stored)
            .map_err(|error| uncertain(format!("intent durability unknown: {error}")))?;
        self.project(stored)?;
        Ok(())
    }
}

impl DaemonClaudeSessionRoute {
    fn read_stored(
        &self,
        stored: &mut StoredSession,
        since: u64,
    ) -> Result<ClaudeReadReply, HostToolError> {
        if since > stored.session.cursor {
            return Err(refused("read cursor is ahead of session"));
        }
        let more = if stored.session.state != ClaudeSessionState::Stopped {
            self.observe_with_transcript(stored, true)?
        } else {
            if stored.needs_persist {
                self.persist(stored)?;
                self.project(stored)?;
            }
            false
        };
        let mut page = transcript_page(stored, since)?;
        page.has_more |= more;
        Ok(page)
    }
}
/// Outstanding `can_use_tool` request ids. A later stream or tool-progress
/// frame does not answer one. Only a matching response, cancel, or decision does.
fn pending_permission_ids(events: &[ClaudeSessionEvent]) -> Vec<&str> {
    let mut pending = Vec::new();
    for event in events {
        if event.kind != "backend" {
            continue;
        }
        if event.payload.get("type").and_then(Value::as_str) == Some("control_request")
            && event
                .payload
                .pointer("/request/subtype")
                .and_then(Value::as_str)
                == Some("can_use_tool")
        {
            if let Some(id) = event.payload.get("request_id").and_then(Value::as_str) {
                if !id.is_empty() && !pending.contains(&id) {
                    pending.push(id);
                }
            }
            continue;
        }
        if let Some(id) = permission_decision_id(&event.payload) {
            pending.retain(|held| *held != id);
        }
    }
    pending
}

fn permission_decision_id(payload: &Value) -> Option<&str> {
    let id = payload
        .get("request_id")
        .or_else(|| payload.pointer("/response/request_id"))
        .and_then(Value::as_str)
        .filter(|id| !id.is_empty())?;
    let kind = payload.get("type").and_then(Value::as_str);
    let subtype = payload
        .pointer("/request/subtype")
        .or_else(|| payload.pointer("/response/subtype"))
        .and_then(Value::as_str);
    let decision = payload
        .pointer("/response/response/behavior")
        .or_else(|| payload.get("decision"))
        .and_then(Value::as_str);
    let answers = kind == Some("control_response")
        || matches!(subtype, Some("cancel" | "deny" | "allow"))
        || matches!(decision, Some("allow" | "deny" | "cancel"));
    answers.then_some(id)
}

impl ClaudeSessionRoute for DaemonClaudeSessionRoute {
    fn preflight_open(
        &self,
        scope: &Scope,
        request: &ClaudeOpenRequest,
    ) -> Result<(), HostToolError> {
        owner(scope)?;
        let snapshot = self.pin.current();
        if let Some(id) = request.preset.as_deref() {
            let preset = super::claude_host::declared_preset(&snapshot, id).map_err(refused)?;
            let Some(declared) = super::claude_host::launch_placement(preset.placement) else {
                return Err(refused(format!(
                    "preset_placement: {id} is not a session placement"
                )));
            };
            if preset.unsandboxed {
                let target = if request.project.is_empty() {
                    scope
                        .project
                        .as_ref()
                        .map(|id| id.as_str())
                        .ok_or_else(|| HostToolError::Scope {
                            tool: TOOL,
                            reason: "unsandboxed preset requires a bound owner-facing caller",
                        })?
                } else {
                    request.project.as_str()
                };
                authorize_project(&snapshot, scope, target)?;
                if !owner_facing(&snapshot, scope) {
                    return Err(HostToolError::Scope {
                        tool: TOOL,
                        reason: "unsandboxed preset requires an owner-facing conversation",
                    });
                }
            } else if !request.project.is_empty() {
                authorize_project(&snapshot, scope, &request.project)?;
            }
            if request.placement.is_some_and(|asked| asked != declared)
                || request
                    .skip_permissions
                    .is_some_and(|asked| asked != preset.skip_permissions)
            {
                let placement = match declared {
                    ClaudePlacement::HostTab => "host-tab",
                    ClaudePlacement::Pod => "pod",
                };
                return Err(refused(format!(
                    "preset {id} requires {placement} and skip_permissions={}",
                    preset.skip_permissions
                )));
            }
            if declared == ClaudePlacement::HostTab
                && preset.driver == odin_registry::ClaudeDriver::Sinmara
            {
                return Err(refused(super::claude_host::HOST_TAB_UNPROMPTABLE));
            }
        } else {
            authorize_project(&snapshot, scope, &request.project)?;
            if request.account.is_empty() || request.project.is_empty() {
                return Err(refused(
                    "account and project are required for ordinary workload publication",
                ));
            }
            odin_domain::ProjectId::new(&request.project)
                .map_err(|error| refused(error.to_string()))?;
            if request.placement.unwrap_or_default() == ClaudePlacement::Pod
                && request.host.is_some()
            {
                return Err(refused(
                    "host is only valid for a declared host-tab placement",
                ));
            }
            if request.dir.is_some() {
                return Err(refused("dir is only valid for a declared preset"));
            }
        }
        self.backend(request).preflight(request)
    }

    fn open(
        &self,
        effect: &odin_kernel::PreparedEffect,
        scope: Scope,
        request: ClaudeOpenRequest,
    ) -> Result<ClaudeSessionRecord, HostToolError> {
        self.preflight_open(&scope, &request)?;
        let request = self.backend(&request).resolve(&request)?;
        if request.skip_permissions.is_none() || request.placement.is_none() {
            return Err(storage(
                "backend did not resolve the declared launch settings",
            ));
        }
        let owner_run = owner(&scope)?.to_owned();
        let mut sessions = self.sessions.lock().map_err(storage)?;
        for stored in sessions.values() {
            if !self.owns(&stored.session, &scope)? {
                continue;
            }
            if stored.session.state == ClaudeSessionState::Stopped && !stored.needs_persist {
                continue;
            }
            if stored.session.request == request {
                return if stored.needs_persist
                    || matches!(
                        stored.session.state,
                        ClaudeSessionState::InDoubt
                            | ClaudeSessionState::Opening
                            | ClaudeSessionState::Prompting
                            | ClaudeSessionState::Stopping
                    ) {
                    Err(uncertain(format!(
                        "session {} requires recovery or stop",
                        stored.session.session
                    )))
                } else {
                    Ok(stored.session.clone())
                };
            }
            if request.name.is_some()
                && stored.session.request.name == request.name
                && stored.session.state != ClaudeSessionState::Stopped
            {
                return Err(refused(
                    "session name already owns a different launch; stop it first",
                ));
            }
        }
        let seat = scope.seat.as_ref().map(|id| id.as_str().to_owned());
        if let Some(seat) = seat.as_deref() {
            let cap = self.session_cap(seat)?;
            let open = sessions
                .values()
                .filter(|stored| {
                    stored.session.seat.as_deref() == Some(seat)
                        && matches!(
                            stored.session.state,
                            ClaudeSessionState::Opening
                                | ClaudeSessionState::Prompting
                                | ClaudeSessionState::Running
                        )
                })
                .count();
            if open >= usize::from(cap) {
                return Err(refused(format!(
                    "{open} Claude sessions already open; limits.max_sessions is {cap}"
                )));
            }
        }
        let id = uuid::Uuid::new_v4().to_string();
        let mut stored = StoredSession {
            session: ClaudeSessionRecord {
                session: id.clone(),
                request,
                owner_run,
                seat: seat.clone(),
                lane: scope.lane.as_ref().map(|lane| lane.as_str().to_owned()),
                state: ClaudeSessionState::Opening,
                resource: None,
                claude_session_id: None,
                remote_control: None,
                cursor: 0,
                last_error: None,
                last_driver_cursor: None,
                last_publication_cursor: None,
            },
            events: Vec::new(),
            observed_at: time::OffsetDateTime::now_utc(),
            ended_at: None,
            needs_persist: false,
        };
        stored.event("opening", json!({}))?;
        sessions.insert(id.clone(), stored);
        let stored = sessions.get_mut(&id).expect("inserted session");
        if let Err(error) = self.persist(stored).and_then(|()| self.project(stored)) {
            // No backend call has occurred in this process. Settle this
            // attempt without claiming anything about an external resource.
            stored.session.state = ClaudeSessionState::Stopped;
            stored.session.last_error = Some(error.to_string());
            stored.event(
                "no_effect",
                json!({"reason":"open_intent_or_projection_failed","backend_invoked":false}),
            )?;
            self.persist(stored).map_err(|persist| {
                uncertain(format!(
                    "open never reached backend; cannot persist settlement: {persist}"
                ))
            })?;
            return Err(error);
        }
        let outcome = self
            .backend(&stored.session.request)
            .open(effect, &stored.session);
        self.finish(
            stored,
            ClaudeSessionState::Stopped,
            ClaudeSessionState::Running,
            "opened",
            outcome,
        )
    }

    fn preflight_prompt(
        &self,
        scope: &Scope,
        request: &ClaudePromptRequest,
    ) -> Result<(), HostToolError> {
        if request.text.trim().is_empty() {
            return Err(refused("prompt text is empty"));
        }
        let mut sessions = self.sessions.lock().map_err(storage)?;
        let stored = self.owned(&mut sessions, scope, &request.session)?;
        if stored.session.request.placement.unwrap_or_default() != ClaudePlacement::Pod {
            let driver =
                super::claude_host::admitted_driver(&self.pin.current(), &stored.session.request)
                    .map_err(refused)?;
            return Err(refused(super::claude_host::host_tab_prompt_refusal(driver)));
        }
        if stored.session.state != ClaudeSessionState::Running {
            return Err(refused(
                "session is not running; do not replay an uncertain prompt",
            ));
        }
        Ok(())
    }

    fn prompt(
        &self,
        effect: &odin_kernel::PreparedEffect,
        scope: Scope,
        request: ClaudePromptRequest,
    ) -> Result<ClaudeSessionRecord, HostToolError> {
        self.preflight_prompt(&scope, &request)?;
        let mut sessions = self.sessions.lock().map_err(storage)?;
        let stored = self.owned(&mut sessions, &scope, &request.session)?;
        if stored.session.state != ClaudeSessionState::Running {
            return Err(refused("session is not running"));
        }
        self.intent(stored, ClaudeSessionState::Prompting, "prompting")?;
        let outcome =
            self.backend(&stored.session.request)
                .prompt(effect, &stored.session, &request.text);
        self.finish(
            stored,
            ClaudeSessionState::Running,
            ClaudeSessionState::Running,
            "prompted",
            outcome,
        )
    }

    fn preflight_read(
        &self,
        scope: &Scope,
        request: &ClaudeReadRequest,
    ) -> Result<(), HostToolError> {
        let mut sessions = self.sessions.lock().map_err(storage)?;
        let stored = self.owned(&mut sessions, scope, &request.session)?;
        if request
            .since
            .is_some_and(|cursor| cursor > stored.session.cursor)
        {
            return Err(refused("read cursor is ahead of session"));
        }
        Ok(())
    }

    fn read(
        &self,
        scope: Scope,
        request: ClaudeReadRequest,
    ) -> Result<ClaudeReadReply, HostToolError> {
        self.preflight_read(&scope, &request)?;
        let mut sessions = self.sessions.lock().map_err(storage)?;
        let stored = self.owned(&mut sessions, &scope, &request.session)?;
        self.read_stored(stored, request.since.unwrap_or(0))
    }

    fn read_owner(&self, request: ClaudeReadRequest) -> Result<ClaudeReadReply, HostToolError> {
        let mut sessions = self.sessions.lock().map_err(storage)?;
        let stored = sessions
            .get_mut(&request.session)
            .ok_or_else(|| refused("unknown Claude session"))?;
        self.read_stored(stored, request.since.unwrap_or(0))
    }

    fn preflight_stop(
        &self,
        scope: &Scope,
        request: &ClaudeStopRequest,
    ) -> Result<(), HostToolError> {
        let mut sessions = self.sessions.lock().map_err(storage)?;
        self.owned(&mut sessions, scope, &request.session)?;
        Ok(())
    }

    fn stop(
        &self,
        effect: &odin_kernel::PreparedEffect,
        scope: Scope,
        request: ClaudeStopRequest,
    ) -> Result<ClaudeSessionRecord, HostToolError> {
        let mut sessions = self.sessions.lock().map_err(storage)?;
        let stored = self.owned(&mut sessions, &scope, &request.session)?;
        if stored.session.state == ClaudeSessionState::Stopped {
            // A pre-launch failure can prove no effect while its settlement
            // write also failed. Retry that write before acknowledging stop.
            if stored.needs_persist {
                self.persist(stored)?;
            }
            self.project(stored)?;
            return Ok(stored.session.clone());
        }
        let previous = stored.session.state;
        self.intent(stored, ClaudeSessionState::Stopping, "stopping")?;
        let outcome = self.backend(&stored.session.request).stop(
            effect,
            &stored.session,
            request.discard_unpushed,
        );
        self.finish(
            stored,
            previous,
            ClaudeSessionState::Stopped,
            "stopped",
            outcome,
        )
    }
}

#[cfg(test)]
#[path = "claude_sessions_tests.rs"]
pub(crate) mod tests;

/// The caller is a seat's standing conversation: its declared conversation project.
fn owner_facing(snapshot: &odin_registry::Snapshot, scope: &Scope) -> bool {
    scope.seat.as_ref().is_some_and(|seat_id| {
        snapshot
            .object(odin_registry::RegistryKind::Seat, seat_id.as_str())
            .and_then(|object| match &object.config {
                odin_registry::ObjectConfig::Seat(seat) => seat.conversation.as_ref(),
                _ => None,
            })
            .is_some_and(|conversation| {
                scope
                    .project
                    .as_ref()
                    .is_some_and(|project| conversation.project == *project)
            })
    })
}

/// Owner-facing conversation seats may select an enabled declared target;
/// other drivers remain bound to their active lane. Workload narrowing is an
/// additional backend check, never an expansion of this admission.
fn authorize_project(
    snapshot: &odin_registry::Snapshot,
    scope: &Scope,
    target: &str,
) -> Result<(), HostToolError> {
    use odin_registry::{ObjectConfig, RegistryKind};
    let reject = || HostToolError::Scope {
        tool: TOOL,
        reason: "caller seat/lane/project does not admit the requested Claude project",
    };
    let seat_id = scope.seat.as_ref().ok_or_else(reject)?;
    let lane_id = scope.lane.as_ref().ok_or_else(reject)?;
    let project_id = scope.project.as_ref().ok_or_else(reject)?;
    let Some(ObjectConfig::Seat(seat)) = snapshot
        .object(RegistryKind::Seat, seat_id.as_str())
        .map(|object| &object.config)
    else {
        return Err(reject());
    };
    let Some(ObjectConfig::Lane(lane)) = snapshot
        .object(RegistryKind::Lane, lane_id.as_str())
        .map(|object| &object.config)
    else {
        return Err(reject());
    };
    let enabled_project = |id: &str| matches!(snapshot.object(RegistryKind::Project, id).map(|object| &object.config), Some(ObjectConfig::Project(project)) if project.enabled);
    if !seat.enabled
        || !lane.enabled
        || lane.default_seat != *seat_id
        || lane.project != *project_id
        || !seat.project_scope.contains(project_id)
        || !enabled_project(project_id.as_str())
        || !enabled_project(target)
    {
        return Err(reject());
    }
    if target != project_id.as_str()
        && !seat
            .conversation
            .as_ref()
            .is_some_and(|conversation| conversation.project == *project_id)
    {
        return Err(reject());
    }
    Ok(())
}

#[cfg(test)]
#[path = "claude_session_bounds_tests.rs"]
mod bounds_tests;
