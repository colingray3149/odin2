//! Live operational-state source over the shared Huginn read model.
//!
//! [`LiveSource`] is a read-only projection of the daemon's single
//! authoritative [`MaterializedReadModel`]: [`LiveSource::pin`] captures the
//! model head and its objects in one atomic [`ReadModelCapture`], so the
//! pinned revision and the pinned items can never tear, then projects only
//! operationally relevant kinds into deterministic [`SourceItem`] summaries.
//!
//! Item text is a bounded, allowlisted template per entity — sessions, kube
//! pods/workloads, fleet nodes, fleet host liveness and placements, lanes,
//! pending approvals, and incidents (which ride `ObjectKind::Status`). Raw
//! object JSON is never embedded, so tokens, secrets, evidence payloads,
//! and arbitrary fields cannot leak into the brain index.
//!
//! The head digest binds exactly what is projected: the source identity and
//! every item's key and text, freshness included. A read-model move that
//! changes no projected text (a probe stamp, an unprojected kind) keeps the
//! head, so it builds no generation; any projected change, freshness flip or
//! removal moves it. Read-model revisions restart at zero across daemon
//! restarts and are never part of it.
//!
//! [`ReadModelCapture`]: odin_huginn::read_model::ReadModelCapture

use std::collections::BTreeMap;
use std::fmt;

use odin_domain::huginn::{LiveSessionSummary, ObjectKind, ObjectSnapshot};
use odin_domain::knowledge::ids::AtlasId;
use odin_domain::knowledge::retrieval::TrustClass;
use odin_domain::{ApprovalStatus, Digest};
use odin_huginn::approvals::ApprovalView;
use odin_huginn::incidents::{IncidentStatusView, IncidentView};
use odin_huginn::read_model::{MaterializedReadModel, ReadModelError};
use serde_json::Value;
use time::{format_description::well_known::Rfc3339, OffsetDateTime};
use tokio::sync::watch;

use crate::error::{BrainError, BrainResult};
use crate::source::SourceItem;

/// Domain-separation prefix for the live head digest.
const HEAD_DOMAIN: &[u8] = b"odin-brain:live-head:v1";

/// Bounds free-form prose quoted in a summary (titles, descriptions,
/// deviations) to a deterministic single-line excerpt.
fn bounded(text: &str, max_chars: usize) -> String {
    let flattened = text.split_whitespace().collect::<Vec<_>>().join(" ");
    if flattened.chars().count() <= max_chars {
        return flattened;
    }
    let mut excerpt: String = flattened.chars().take(max_chars).collect();
    excerpt.push_str("...");
    excerpt
}

fn unix_ms(at: OffsetDateTime) -> u64 {
    (at.unix_timestamp_nanos() / 1_000_000).max(0) as u64
}

fn field_str<'a>(value: &'a Value, key: &str) -> Option<&'a str> {
    value.get(key).and_then(Value::as_str)
}

/// Digests the projected items: source identity and every item's key and
/// text, in the capture's deterministic `(kind, id)` order.
fn head_digest(source_id: &str, projected: &[(String, String)]) -> Digest {
    let mut payload = Vec::new();
    payload.extend_from_slice(HEAD_DOMAIN);
    payload.push(0);
    payload.extend_from_slice(source_id.as_bytes());
    for (key, text) in projected {
        payload.push(0);
        payload.extend_from_slice(key.as_bytes());
        payload.push(0);
        payload.extend_from_slice(text.as_bytes());
    }
    Digest::hash(&payload)
}

/// Relevance filter and summary projection for one captured object.
///
/// Returns the stable entity group and deterministic summary text, or `None`
/// for objects outside this source's scope. Incidents are identified by the
/// `incidentId` field their projection carries on `ObjectKind::Status`
/// objects; roster and daemon status objects are not incidents and are
/// excluded. Non-requested approvals are decided, not pending, and excluded.
fn project(snapshot: &ObjectSnapshot) -> Option<(&'static str, String)> {
    let id = snapshot.object.id.as_str();
    let value = &snapshot.value;
    match snapshot.object.kind {
        ObjectKind::Session => match session_entry(id, value) {
            Ok(session) => Some(("sessions", session.line)),
            Err(error) => {
                tracing::warn!("live session {id} skipped: {error}");
                None
            }
        },
        ObjectKind::FleetHost => Some(("fleet-hosts", fleet_host_summary(value))),
        ObjectKind::FleetPlacement => Some(("fleet-placement", fleet_placement_summary(value))),
        ObjectKind::KubeResource => Some(("workloads", workload_summary(value))),
        ObjectKind::Node => Some(("nodes", node_summary(id, value))),
        ObjectKind::Lane => Some(("lanes", lane_summary(id, value))),
        ObjectKind::Approval => {
            requested_approval(id, value).map(|view| ("approvals", approval_summary(&view)))
        }
        ObjectKind::Status => value
            .get("incidentId")
            .is_some()
            .then(|| ("incidents", incident_summary(id, value))),
        _ => None,
    }
}

/// One session as live memory shows it.
struct SessionEntry {
    line: String,
    /// It still holds capacity.
    open: bool,
    at: OffsetDateTime,
}

/// Reads a session as `project_object` stores it, `{data, evidenceLinks}`:
/// a seat session's `data` is its [`LiveSessionSummary`]; a Claude driver's
/// (`claude:` ids) is its transcript projection, which keeps state, seat and
/// name under `session`.
fn session_entry(id: &str, value: &Value) -> Result<SessionEntry, String> {
    let data = value.get("data").ok_or("the record has no data field")?;
    let pending = match data.get("pendingPermissionCount").and_then(Value::as_u64) {
        Some(1) => "1 pending permission request".to_owned(),
        Some(count) => format!("{count} pending permission requests"),
        None => "pending permission count not recorded".to_owned(),
    };
    let titled = |head: String, title: Option<&str>| match title {
        Some(title) => format!("{head}: {}; {pending}", bounded(title, 80)),
        None => format!("{head}; {pending}"),
    };
    if id.starts_with("claude:") {
        let session = data
            .get("session")
            .ok_or("the record has no session field")?;
        let state = field_str(session, "state").ok_or("the session has no state")?;
        let observed = data
            .get("observed_at")
            .ok_or("the record has no observed_at")?;
        let at = serde_json::from_value(observed.clone())
            .map_err(|error| format!("observed_at: {error}"))?;
        let seat = field_str(session, "seat").unwrap_or("not recorded");
        let title = session
            .get("request")
            .and_then(|request| field_str(request, "name"));
        return Ok(SessionEntry {
            line: titled(
                format!("Session {id} ({state}) on seat {seat} via Claude Code"),
                title,
            ),
            open: state != "stopped",
            at,
        });
    }
    let session: LiveSessionSummary =
        serde_json::from_value(data.clone()).map_err(|error| error.to_string())?;
    let state = field_str(data, "state").unwrap_or_default();
    Ok(SessionEntry {
        line: titled(
            format!(
                "Session {id} ({state}) on seat {} via {}/{}",
                session.seat_id, session.provider, session.model
            ),
            session.title.as_deref(),
        ),
        open: session.state.holds_capacity(),
        at: session.updated_at,
    })
}

/// Summarizes the externally tagged `KubeResourceOwnership` without
/// embedding any of its raw payload.
fn ownership_summary(value: &Value) -> String {
    match value.get("ownership").and_then(|owned| owned.get("odin")) {
        Some(details) => {
            let run = field_str(details, "runId").unwrap_or("unknown");
            let lane = field_str(details, "laneId").unwrap_or("unknown");
            let seat = field_str(details, "seatId").unwrap_or("unknown");
            format!("owned by run {run} lane {lane} seat {seat}")
        }
        None if value.get("ownership").and_then(Value::as_str) == Some("foreign") => {
            "foreign-owned".to_owned()
        }
        None => "ownership not recorded".to_owned(),
    }
}

fn workload_summary(value: &Value) -> String {
    let resource = value.get("resource").unwrap_or(&Value::Null);
    let kind = field_str(resource, "kind").unwrap_or("resource");
    let name = field_str(resource, "name").unwrap_or("unknown");
    let namespace = field_str(resource, "namespace").unwrap_or("-");
    let cluster = field_str(resource, "cluster").unwrap_or("unknown");
    let state = field_str(value, "state").unwrap_or("not recorded");
    format!(
        "Workload {kind} {namespace}/{name} on cluster {cluster}: {state}; {}",
        ownership_summary(value)
    )
}

fn node_summary(id: &str, value: &Value) -> String {
    let state = field_str(value, "state")
        .map(str::to_owned)
        .unwrap_or_else(|| match value.get("enabled") {
            Some(Value::Bool(false)) => "disabled".to_owned(),
            Some(Value::Bool(true)) => "enabled".to_owned(),
            _ => "unknown".to_owned(),
        });
    let platform = field_str(value, "operatingSystem")
        .zip(field_str(value, "architecture"))
        .map(|(os, arch)| format!(" ({os}/{arch})"))
        .unwrap_or_default();
    format!("Fleet node {id}: {state}{platform}")
}

/// Accepts the time-serde tuple and legacy stamps; malformed observations are omitted.
fn last_seen_stamp(value: Option<&Value>) -> Option<String> {
    match value {
        None | Some(Value::Null) => Some("never".to_owned()),
        Some(Value::String(stamp)) => Some(stamp.clone()),
        Some(stamp) => serde_json::from_value::<OffsetDateTime>(stamp.clone())
            .ok()?
            .format(&Rfc3339)
            .ok(),
    }
}

/// Omit absent observations and online last-seen stamps: probe timestamps
/// would change the projection without changing the host's state.
fn fleet_host_summary(value: &Value) -> String {
    let tailscale = field_str(value, "tailscale").unwrap_or("unknown");
    let role = field_str(value, "role").unwrap_or("unknown");
    let host = field_str(value, "host").unwrap_or("unknown");
    let online = value
        .get("online")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let tailnet = field_str(value, "tailnet").unwrap_or("unknown");
    let k3s = value.get("k3sNodeState").and_then(Value::as_str);
    let liveness = if online {
        let mut proofs = Vec::new();
        if k3s == Some("ready") {
            proofs.push("k3s Ready");
        }
        if tailnet == "reachable" {
            proofs.push("tailnet reachable");
        }
        if value.get("zellijLive").and_then(Value::as_bool) == Some(true) {
            proofs.push("ssh reachable");
        }
        format!("online — {}", proofs.join(", "))
    } else {
        let tailnet = match tailnet {
            "unreachable" => "tailnet unreachable",
            "unknown" => "tailnet unknown",
            _ => "tailnet reachable",
        };
        let k3s = match k3s {
            Some(state) => format!("k3s {state}"),
            None => "no k3s node".to_owned(),
        };
        let last_seen = match last_seen_stamp(value.get("lastSeen")) {
            Some(stamp) => format!("; last seen {stamp}"),
            None => String::new(),
        };
        format!("offline — {tailnet}, {k3s}{last_seen}")
    };
    let capabilities = match value.get("capabilities").and_then(Value::as_array) {
        Some(list) if !list.is_empty() => {
            let csv = list
                .iter()
                .filter_map(Value::as_str)
                .collect::<Vec<_>>()
                .join(", ");
            format!("; capabilities {csv}")
        }
        _ => String::new(),
    };
    format!("Fleet host {tailscale} ({role}, host {host}): {liveness}{capabilities}")
}

/// One placed thing: where it runs and how much of it runs there, each
/// field conditional on the placement's shape.
fn fleet_placement_summary(value: &Value) -> String {
    let thing = field_str(value, "thing").unwrap_or("unknown");
    let mut summary = format!("Placement {thing}");
    if let Some(node) = field_str(value, "node") {
        summary.push_str(&format!(": node {node}"));
    }
    if let Some(host) = field_str(value, "host") {
        summary.push_str(&format!(" host {host}"));
    }
    if let Some(endpoint) = field_str(value, "endpoint") {
        summary.push_str(&format!(" endpoint {endpoint}"));
    }
    if let Some(count) = value.get("count").and_then(Value::as_u64) {
        summary.push_str(&format!(": {count} scheduled"));
    }
    if let Some(names) = value.get("names").and_then(Value::as_array) {
        let csv = names
            .iter()
            .filter_map(Value::as_str)
            .collect::<Vec<_>>()
            .join(", ");
        if !csv.is_empty() {
            summary.push_str(&format!(" running {}", bounded(&csv, 160)));
        }
    }
    if let Some(active) = value.get("activeCount").and_then(Value::as_u64) {
        summary.push_str(&format!("; {active} active sessions"));
    }
    // A placement that carries a live observation says so: the
    // `zellij-sessions` placement of an unreachable host names no sessions,
    // so the suffix is the only honest rendering of its emptiness.
    if value.get("live") == Some(&Value::Bool(false)) {
        summary.push_str(" (unreachable)");
    }
    summary
}

fn lane_summary(id: &str, value: &Value) -> String {
    let enabled = match value.get("enabled") {
        Some(Value::Bool(false)) => "disabled",
        Some(Value::Bool(true)) => "enabled",
        _ => "unknown",
    };
    let project = field_str(value, "project").unwrap_or("unknown");
    let family = field_str(value, "family").unwrap_or("unknown");
    let queue = field_str(value, "queue").unwrap_or("unknown");
    let description = field_str(value, "description")
        .map(|description| bounded(description, 120))
        .unwrap_or_default();
    format!("Lane {id} ({enabled}) project {project} family {family} queue {queue}: {description}")
}

/// The approval as the ledger projects it, when it still awaits a decision.
fn requested_approval(id: &str, value: &Value) -> Option<ApprovalView> {
    match serde_json::from_value::<ApprovalView>(value.clone()) {
        Ok(view) => (view.status == ApprovalStatus::Requested).then_some(view),
        Err(error) => {
            tracing::warn!("live approval {id} skipped: {error}");
            None
        }
    }
}

fn approval_summary(view: &ApprovalView) -> String {
    let expires = view
        .expires_at
        .format(&Rfc3339)
        .unwrap_or_else(|_| "unknown".to_owned());
    format!(
        "Pending approval {}: {} on {} {} requested by {}, expires {expires}",
        view.approval_id, view.capability_id, view.target_kind, view.target_id, view.issuer
    )
}

fn incident_summary(id: &str, value: &Value) -> String {
    let severity = field_str(value, "severity").unwrap_or("unknown");
    let status = field_str(value, "status").unwrap_or("unknown");
    let deviation = field_str(value, "deviation")
        .map(|deviation| bounded(deviation, 160))
        .unwrap_or_else(|| "unspecified deviation".to_owned());
    let run = match field_str(value, "runId") {
        Some(run) => format!(" (run {run})"),
        None => String::new(),
    };
    format!("Incident {id} ({severity}, {status}){run}: {deviation}")
}

/// Live operational state projected from the shared [`MaterializedReadModel`].
///
/// The struct is `Clone` because the read model handle itself is a shared
/// `Arc` around the authoritative state: cloning shares authority, it never
/// forks a copy of the modeled world.
#[derive(Clone)]
pub struct LiveSource {
    id: AtlasId,
    read_model: MaterializedReadModel,
}

impl fmt::Debug for LiveSource {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LiveSource")
            .field("id", &self.id.as_str())
            .finish_non_exhaustive()
    }
}

impl LiveSource {
    /// Binds the source identity to the daemon's shared read-model handle.
    pub fn new(id: AtlasId, read_model: MaterializedReadModel) -> Self {
        Self { id, read_model }
    }

    pub const fn atlas_id(&self) -> &AtlasId {
        &self.id
    }

    /// Subscribes to read-model head movements for daemon event integration.
    ///
    /// The receiver yields the current revision immediately, then one tick
    /// per revision-moving mutation (changed upsert, apply, remove). No-op
    /// writes never emit, so a rebuild driven by this subscription cannot
    /// loop on itself.
    pub fn subscribe_revision(&self) -> BrainResult<watch::Receiver<u64>> {
        self.read_model
            .subscribe_head()
            .map_err(Self::read_model_error)
    }

    /// Live memory's view of the read model at `now_ms`: each session (open
    /// while it holds capacity), each approval still awaiting a decision
    /// and each open incident. A record that won't parse is logged and
    /// skipped; the rest still show.
    pub fn live_entries(&self, now_ms: u64) -> BrainResult<Vec<crate::service::LiveEntry>> {
        let capture = self.read_model.capture().map_err(Self::read_model_error)?;
        let mut entries = Vec::new();
        for snapshot in &capture.objects {
            let (id, value) = (snapshot.object.id.as_str(), &snapshot.value);
            match snapshot.object.kind {
                ObjectKind::Session => match session_entry(id, value) {
                    Ok(session) => entries.push(crate::service::LiveEntry {
                        id: id.to_owned(),
                        line: session.line,
                        open: session.open,
                        at_ms: unix_ms(session.at),
                    }),
                    Err(error) => tracing::warn!("live session {id} skipped: {error}"),
                },
                ObjectKind::Approval => {
                    let Some(approval) = requested_approval(id, value) else {
                        continue;
                    };
                    // A lapsed request cannot be decided; the read model keeps it a day.
                    if unix_ms(approval.expires_at) <= now_ms {
                        continue;
                    }
                    entries.push(crate::service::LiveEntry {
                        id: approval.approval_id.to_string(),
                        line: approval_summary(&approval),
                        open: true,
                        at_ms: unix_ms(approval.requested_at),
                    });
                }
                // An open incident stays in view until it resolves.
                ObjectKind::Status if value.get("incidentId").is_some() => {
                    match serde_json::from_value::<IncidentView>(value.clone()) {
                        Ok(incident) if incident.status != IncidentStatusView::Resolved => {
                            entries.push(crate::service::LiveEntry {
                                id: id.to_owned(),
                                line: incident_summary(id, value),
                                open: true,
                                at_ms: unix_ms(incident.last_observed_at),
                            });
                        }
                        Ok(_) => {}
                        Err(error) => tracing::warn!("live incident {id} skipped: {error}"),
                    }
                }
                _ => {}
            }
        }
        Ok(entries)
    }

    /// Pins the read-model head and projects its relevant objects.
    ///
    /// The returned digest is the head of the captured state; every item
    /// carries it as `source_revision`, so serving always pairs the exact
    /// item set with the exact head it was computed from.
    pub fn pin(&self) -> BrainResult<(Digest, Vec<SourceItem>)> {
        let capture = self.read_model.capture().map_err(Self::read_model_error)?;
        let mut lane_workloads: BTreeMap<&str, BTreeMap<&str, usize>> = BTreeMap::new();
        for object in &capture.objects {
            if object.object.kind != ObjectKind::KubeResource {
                continue;
            }
            let Some(owner) = object
                .value
                .get("ownership")
                .and_then(|value| value.get("odin"))
            else {
                continue;
            };
            let Some(lane) = field_str(owner, "laneId") else {
                continue;
            };
            let state = field_str(&object.value, "state").unwrap_or("not recorded");
            *lane_workloads
                .entry(lane)
                .or_default()
                .entry(state)
                .or_default() += 1;
        }
        let mut projected = Vec::new();
        for snapshot in &capture.objects {
            let Some((group, mut text)) = project(snapshot) else {
                continue;
            };
            let key = format!("{group}/{}", snapshot.object.id);
            if snapshot.object.kind == ObjectKind::Lane {
                match lane_workloads.get(snapshot.object.id.as_str()) {
                    Some(states) => {
                        text.push_str("; observed workload health:");
                        for (state, count) in states {
                            text.push_str(&format!(" {state}={count}"));
                        }
                    }
                    None => text.push_str("; workload health: no observations"),
                }
            }
            text.push_str(&format!(
                "; observation freshness: {:?}",
                snapshot.freshness.state
            ));
            projected.push((key, text));
        }
        let head = head_digest(self.id.as_str(), &projected);
        let mut items = Vec::with_capacity(projected.len());
        for (key, text) in projected {
            // A projection describes authority; it never becomes control authority.
            items.push(SourceItem::new(
                self.id.clone(),
                head,
                key.as_bytes(),
                TrustClass::Observed,
                text,
            )?);
        }
        Ok((head, items))
    }

    /// Fails closed: read-model capture only fails when the state lock is
    /// poisoned (infrastructure loss) or on an invariant violation, and both
    /// surface as typed errors instead of partial pins.
    fn read_model_error(error: ReadModelError) -> BrainError {
        match error {
            ReadModelError::LockPoisoned(_) => BrainError::Unavailable {
                component: "live-read-model",
                reason: error.to_string(),
            },
            other => BrainError::InvalidRequest(format!("live read-model capture failed: {other}")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use odin_domain::huginn::{Freshness, FreshnessState, ObjectRef, Revision, RevisionSource};
    use serde_json::json;
    use time::macros::datetime;
    use time::OffsetDateTime;

    fn model() -> MaterializedReadModel {
        MaterializedReadModel::new(64, OffsetDateTime::UNIX_EPOCH)
    }

    fn source(read_model: MaterializedReadModel) -> LiveSource {
        LiveSource::new(AtlasId::new("live:huginn").unwrap(), read_model)
    }

    fn freshness() -> Freshness {
        Freshness {
            state: FreshnessState::Fresh,
            observed_at: OffsetDateTime::UNIX_EPOCH,
            source_updated_at: None,
            stale_after_seconds: None,
        }
    }

    fn snapshot(kind: ObjectKind, id: &str, revision: u64, value: Value) -> ObjectSnapshot {
        ObjectSnapshot {
            object: ObjectRef {
                kind,
                id: id.to_owned(),
            },
            revision: Revision::new(revision),
            revision_source: RevisionSource::Registry,
            freshness: freshness(),
            content_digest: Digest::hash(value.to_string().as_bytes()),
            value,
        }
    }

    /// A seat session's summary, with `extra` fields merged in.
    fn session_data(state: &str, extra: Value) -> Value {
        let at = serde_json::to_value(datetime!(2027-01-15 08:00 UTC)).unwrap();
        let mut data = json!({
            "sessionId": "00000000-0000-4000-8000-000000000001", "epoch": 1, "seatId": "architect", "provider": "zai",
            "model": "glm-5", "title": null, "state": state, "startedAt": at,
            "updatedAt": at, "eventHead": 0, "terminalHead": 0, "pendingPermissionCount": 0
        });
        for (key, value) in extra.as_object().unwrap() {
            data[key] = value.clone();
        }
        data
    }

    /// A session as odind stores it, through `project_object`.
    fn session_snapshot(id: &str, revision: u64, data: Value) -> ObjectSnapshot {
        odin_huginn::read_model::project_object(
            ObjectRef {
                kind: ObjectKind::Session,
                id: id.to_owned(),
            },
            Revision::new(revision),
            RevisionSource::Registry,
            freshness(),
            &data,
            &odin_huginn::read_model::ProjectionMetadata::new(id, "session"),
        )
        .unwrap()
    }

    fn item_texts(items: &[SourceItem]) -> Vec<&str> {
        items.iter().map(|item| item.text.as_str()).collect()
    }

    /// An approval as the ledger projects it into the read model.
    fn approval_snapshot(
        id: &str,
        status: ApprovalStatus,
        requested_at: OffsetDateTime,
        expires_at: OffsetDateTime,
    ) -> ObjectSnapshot {
        let view = ApprovalView {
            approval_id: odin_domain::ApprovalId::new(id).unwrap(),
            status,
            issuer: "operator".to_owned(),
            target_kind: "kube".to_owned(),
            target_id: "prod/pod".to_owned(),
            capability_id: odin_domain::CapabilityId::new("kube.apply").unwrap(),
            arguments_digest: Digest::hash(b"args"),
            requested_at,
            expires_at,
            decided_at: None,
            decided_by: None,
            consumed_by_command_id: None,
            decision_evidence_ref: None,
            revision: 1,
        };
        snapshot(
            ObjectKind::Approval,
            id,
            1,
            serde_json::to_value(view).unwrap(),
        )
    }

    #[test]
    fn a_pending_approval_is_live_from_its_request_until_it_lapses() {
        let requested = datetime!(2027-01-15 08:00 UTC);
        let read_model = model();
        for snapshot in [
            approval_snapshot(
                "approval:open",
                ApprovalStatus::Requested,
                requested,
                requested + time::Duration::hours(2),
            ),
            approval_snapshot(
                "approval:lapsed",
                ApprovalStatus::Requested,
                requested,
                requested + time::Duration::minutes(30),
            ),
            approval_snapshot(
                "approval:decided",
                ApprovalStatus::Denied,
                requested,
                requested + time::Duration::hours(2),
            ),
        ] {
            read_model.upsert(snapshot).unwrap();
        }
        let now = unix_ms(requested + time::Duration::hours(1));
        let entries = source(read_model).live_entries(now).unwrap();
        assert_eq!(entries.len(), 1, "{entries:?}");
        assert_eq!(entries[0].id, "approval:open");
        assert!(entries[0].open);
        assert_eq!(entries[0].at_ms, unix_ms(requested));
        assert!(entries[0].line.contains("kube.apply on kube prod/pod"));
        assert!(entries[0].line.contains("expires 2027-01-15T10:00:00Z"));
    }

    #[test]
    fn open_incidents_are_live_entries_until_resolved() {
        use odin_huginn::incidents::{IncidentSeverityView, IncidentStatusView, IncidentView};
        let at = OffsetDateTime::from_unix_timestamp(1_800_000_000).unwrap();
        let incident = |id: &str, status| IncidentView {
            incident_id: odin_domain::IncidentId::new(id).unwrap(),
            run_id: None,
            severity: IncidentSeverityView::Info,
            confidence_micros: 1_000_000,
            deviation: format!("{id} failed"),
            failure_signature: format!("unit-failed:{id}"),
            expected_state: json!({}),
            observed_state: json!({}),
            affected_objects: Vec::new(),
            evidence_refs: Vec::new(),
            allowed_capabilities: Vec::new(),
            attempt_ids: Vec::new(),
            recommended_next_action: String::new(),
            escalation_target: String::new(),
            first_observed_at: at,
            last_observed_at: at,
            last_useful_progress_at: None,
            status,
            revision: 1,
        };
        let read_model = model();
        for (id, status) in [
            ("incident:brain-grow", IncidentStatusView::Open),
            ("incident:brain-load", IncidentStatusView::Resolved),
        ] {
            read_model
                .upsert(snapshot(
                    ObjectKind::Status,
                    id,
                    1,
                    serde_json::to_value(incident(id, status)).unwrap(),
                ))
                .unwrap();
        }
        let entries = source(read_model).live_entries(0).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].id, "incident:brain-grow");
        assert!(entries[0].open);
        assert_eq!(entries[0].at_ms, 1_800_000_000_000);
        assert!(entries[0].line.contains("incident:brain-grow failed"));
    }

    /// Seat and Claude sessions both read from their stored records; one that
    /// won't parse is skipped and the rest still show.
    #[test]
    fn live_entries_read_seat_and_claude_sessions_and_skip_a_bad_record() {
        let read_model = model();
        read_model
            .upsert(session_snapshot(
                "sess-1",
                1,
                session_data("running", json!({})),
            ))
            .unwrap();
        let observed = serde_json::to_value(datetime!(2027-01-15 09:00 UTC)).unwrap();
        read_model
            .upsert(session_snapshot(
                "claude:c1",
                1,
                json!({
                    "session": {
                        "session": "c1", "owner_run": "run-1", "seat": "sinmara",
                        "state": "running", "cursor": 3,
                        "request": {"account": "claude", "project": "odin", "name": "review"}
                    },
                    "events": [], "observed_at": observed, "quietSeconds": 600,
                    "pendingPermissionCount": 0, "has_more": false
                }),
            ))
            .unwrap();
        read_model
            .upsert(session_snapshot("sess-bad", 1, json!({"state": "running"})))
            .unwrap();
        let entries = source(read_model).live_entries(0).unwrap();
        let lines: Vec<_> = entries.iter().map(|entry| entry.line.as_str()).collect();
        assert_eq!(
            lines,
            [
                "Session claude:c1 (running) on seat sinmara via Claude Code: review; \
                 0 pending permission requests",
                "Session sess-1 (running) on seat architect via zai/glm-5; \
                 0 pending permission requests",
            ]
        );
        assert!(entries.iter().all(|entry| entry.open));
        assert_eq!(entries[0].at_ms, 1_800_003_600_000);
    }

    #[test]
    fn head_changes_when_content_changes_under_same_numeric_revision() {
        // Two freshly built models both sit at numeric revision 1, but their
        // objects carry different content: the heads must differ, because
        // model revisions restart at zero across daemon restarts.
        let left = source(model());
        let right = source(model());
        left.read_model
            .upsert(session_snapshot(
                "sess-1",
                1,
                session_data("running", json!({})),
            ))
            .unwrap();
        right
            .read_model
            .upsert(session_snapshot(
                "sess-1",
                1,
                session_data("ended", json!({})),
            ))
            .unwrap();

        let (left_head, left_items) = left.pin().unwrap();
        let (right_head, right_items) = right.pin().unwrap();
        assert_ne!(left_head, right_head);
        assert_ne!(left_items, right_items);

        // Within one model, a content change at a new object revision moves
        // both the head and the summary text.
        left.read_model
            .upsert(session_snapshot(
                "sess-1",
                2,
                session_data("ended", json!({})),
            ))
            .unwrap();
        let (moved_head, moved_items) = left.pin().unwrap();
        assert_ne!(moved_head, left_head);
        let texts = item_texts(&moved_items);
        assert!(texts
            .iter()
            .any(|text| text.starts_with("Session sess-1 (ended)")));
    }

    #[test]
    fn revision_subscription_emits_only_on_revision_moves() {
        let read_model = model();
        let source = source(read_model.clone());
        let mut receiver = source.subscribe_revision().unwrap();
        assert_eq!(*receiver.borrow(), 0);
        assert!(!receiver.has_changed().unwrap());

        read_model
            .upsert(snapshot(
                ObjectKind::Lane,
                "delivery",
                1,
                json!({"enabled": true}),
            ))
            .unwrap();
        assert!(receiver.has_changed().unwrap());
        assert_eq!(*receiver.borrow(), 1);
        receiver.borrow_and_update();

        // Identical no-op upsert: no event, so a rebuild pump cannot loop.
        read_model
            .upsert(snapshot(
                ObjectKind::Lane,
                "delivery",
                1,
                json!({"enabled": true}),
            ))
            .unwrap();
        assert!(!receiver.has_changed().unwrap());

        read_model
            .upsert(snapshot(
                ObjectKind::Lane,
                "delivery",
                2,
                json!({"enabled": false}),
            ))
            .unwrap();
        assert!(receiver.has_changed().unwrap());
        assert_eq!(*receiver.borrow(), 2);
    }
}
