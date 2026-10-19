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

use odin_domain::huginn::{ObjectKind, ObjectSnapshot};
use odin_domain::knowledge::ids::AtlasId;
use odin_domain::knowledge::retrieval::TrustClass;
use odin_domain::Digest;
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

fn field_str<'a>(value: &'a Value, key: &str) -> Option<&'a str> {
    value.get(key).and_then(Value::as_str)
}

/// Digests the projected items: source identity and every item's key and
/// text, in the capture's deterministic `(kind, id)` order.
fn head_digest(source_id: &str, projected: &[(String, ObjectKind, String)]) -> Digest {
    let mut payload = Vec::new();
    payload.extend_from_slice(HEAD_DOMAIN);
    payload.push(0);
    payload.extend_from_slice(source_id.as_bytes());
    for (key, _, text) in projected {
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
        ObjectKind::Session => Some(("sessions", session_summary(id, value))),
        ObjectKind::FleetHost => Some(("fleet-hosts", fleet_host_summary(value))),
        ObjectKind::FleetPlacement => Some(("fleet-placement", fleet_placement_summary(value))),
        ObjectKind::KubeResource => Some(("workloads", workload_summary(value))),
        ObjectKind::Node => Some(("nodes", node_summary(id, value))),
        ObjectKind::Lane => Some(("lanes", lane_summary(id, value))),
        ObjectKind::Approval => (field_str(value, "status") == Some("requested"))
            .then(|| ("approvals", approval_summary(value))),
        ObjectKind::Status => value
            .get("incidentId")
            .is_some()
            .then(|| ("incidents", incident_summary(id, value))),
        _ => None,
    }
}

fn session_summary(id: &str, value: &Value) -> String {
    let state = field_str(value, "state").unwrap_or("unknown");
    let seat = field_str(value, "seatId").unwrap_or("unknown");
    let provider = field_str(value, "provider").unwrap_or("unknown");
    let model = field_str(value, "model").unwrap_or("unknown");
    let pending = match value.get("pendingPermissionCount").and_then(Value::as_u64) {
        Some(1) => "1 pending permission request".to_owned(),
        Some(count) => format!("{count} pending permission requests"),
        None => "pending permission count not recorded".to_owned(),
    };
    match field_str(value, "title") {
        Some(title) => format!(
            "Session {id} ({state}) on seat {seat} via {provider}/{model}: {}; {pending}",
            bounded(title, 80)
        ),
        None => format!("Session {id} ({state}) on seat {seat} via {provider}/{model}; {pending}"),
    }
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

fn approval_summary(value: &Value) -> String {
    let id = field_str(value, "approvalId").unwrap_or("unknown");
    let capability = field_str(value, "capabilityId").unwrap_or("unknown");
    let target_kind = field_str(value, "targetKind").unwrap_or("unknown");
    let target_id = field_str(value, "targetId").unwrap_or("unknown");
    let issuer = field_str(value, "issuer").unwrap_or("unknown");
    let expires = field_str(value, "expiresAt").unwrap_or("unknown");
    format!(
        "Pending approval {id}: {capability} on {target_kind} {target_id} requested by \
         {issuer}, expires {expires}"
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

const fn trust_for(_kind: ObjectKind) -> TrustClass {
    // A projection describes authority; it never becomes control authority.
    TrustClass::Observed
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
            projected.push((key, snapshot.object.kind, text));
        }
        let head = head_digest(self.id.as_str(), &projected);
        let mut items = Vec::with_capacity(projected.len());
        for (key, kind, text) in projected {
            items.push(SourceItem::new(
                self.id.clone(),
                head,
                key.as_bytes(),
                trust_for(kind),
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
            ReadModelError::LockPoisoned => BrainError::Unavailable {
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

    use odin_domain::huginn::{
        FleetHostView, FleetTailnetState, Freshness, FreshnessState, KubeNodeState, ObjectDelta,
        ObjectDeltaBody, ObjectRef, Revision, RevisionSource,
    };
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

    fn item_texts(items: &[SourceItem]) -> Vec<&str> {
        items.iter().map(|item| item.text.as_str()).collect()
    }

    /// Exercise the nine-element timestamp tuple emitted without `serde-human-readable`.
    fn host_view(online: bool, last_seen: Option<OffsetDateTime>) -> FleetHostView {
        FleetHostView {
            host: "mini".to_owned(),
            tailscale: "mini".to_owned(),
            hardware: "pc".to_owned(),
            role: "authority".to_owned(),
            capabilities: vec!["operator".to_owned()],
            allow_workloads: false,
            authoritative_state: true,
            gateway_endpoint: None,
            tailnet: if online {
                FleetTailnetState::Reachable
            } else {
                FleetTailnetState::Unreachable
            },
            k3s_node_state: if online {
                Some(KubeNodeState::Ready)
            } else {
                Some(KubeNodeState::NotReady)
            },
            zellij_live: None,
            online,
            last_seen,
            pods_scheduled: 0,
        }
    }

    fn host_snapshot(
        revision: u64,
        online: bool,
        last_seen: Option<OffsetDateTime>,
    ) -> ObjectSnapshot {
        snapshot(
            ObjectKind::FleetHost,
            "fleet:host:mini",
            revision,
            serde_json::to_value(host_view(online, last_seen)).unwrap(),
        )
    }

    #[test]
    fn pins_empty_model_deterministically() {
        let source = source(model());
        let (head, items) = source.pin().unwrap();
        assert!(items.is_empty());
        assert_eq!(source.pin().unwrap().0, head);
    }

    #[test]
    fn projects_only_relevant_kinds_with_deterministic_summaries() {
        let read_model = model();
        read_model
            .upsert(snapshot(
                ObjectKind::Session,
                "sess-1",
                1,
                json!({
                    "sessionId": "sess-1",
                    "seatId": "architect",
                    "provider": "zai",
                    "model": "glm-5",
                    "title": "refactor  the  index",
                    "state": "running",
                    "pendingPermissionCount": 2,
                    "terminalHead": "secret-should-not-appear"
                }),
            ))
            .unwrap();
        read_model
            .upsert(snapshot(
                ObjectKind::Approval,
                "approval:1",
                1,
                json!({
                    "approvalId": "approval:1",
                    "status": "requested",
                    "issuer": "operator",
                    "targetKind": "kube",
                    "targetId": "prod/pod",
                    "capabilityId": "kube.apply",
                    "expiresAt": "2026-01-02T00:00:00Z"
                }),
            ))
            .unwrap();
        // A decided approval is not pending: excluded.
        read_model
            .upsert(snapshot(
                ObjectKind::Approval,
                "approval:2",
                1,
                json!({"approvalId": "approval:2", "status": "denied"}),
            ))
            .unwrap();
        // Incidents ride Status and are identified by incidentId.
        read_model
            .upsert(snapshot(
                ObjectKind::Status,
                "inc-1",
                1,
                json!({
                    "incidentId": "inc-1",
                    "severity": "error",
                    "status": "open",
                    "deviation": "pod crash looping",
                    "expectedState": {"token": "raw-evidence-must-not-leak"}
                }),
            ))
            .unwrap();
        // Roster and daemon status objects are not incidents: excluded.
        read_model
            .upsert(snapshot(
                ObjectKind::Status,
                "roster",
                1,
                json!({"seats": []}),
            ))
            .unwrap();
        read_model
            .upsert(snapshot(
                ObjectKind::KubeResource,
                "c1:Pod:default/api-9",
                1,
                json!({
                    "resource": {
                        "cluster": "c1",
                        "kind": "Pod",
                        "namespace": "default",
                        "name": "api",
                        "uid": "9"
                    },
                    "state": "running",
                    "ownership": {"odin": {
                        "runId": "run-1", "laneId": "lane-1", "seatId": "seat-1"
                    }},
                    "usage": {"cpuMillis": 1}
                }),
            ))
            .unwrap();
        read_model
            .upsert(snapshot(
                ObjectKind::Node,
                "node-a",
                1,
                json!({"nodeId": "node-a", "state": "ready"}),
            ))
            .unwrap();
        read_model
            .upsert(snapshot(
                ObjectKind::Lane,
                "delivery",
                1,
                json!({
                    "enabled": true,
                    "project": "proj.core",
                    "family": "delivery",
                    "queue": "delivery.q",
                    "description": "ships reviewed work"
                }),
            ))
            .unwrap();
        // Outside the live source's scope: excluded.
        read_model
            .upsert(snapshot(
                ObjectKind::File,
                "root-1",
                1,
                json!({"rootId": "root-1"}),
            ))
            .unwrap();

        let source = source(read_model);
        let (head, items) = source.pin().unwrap();
        assert_eq!(items.len(), 6);
        for item in &items {
            assert_eq!(item.source, AtlasId::new("live:huginn").unwrap());
            assert_eq!(item.source_revision, head);
            assert_eq!(item.provenance, None);
        }
        // Distinct entities must mint distinct item identities; a natural-key
        // collision would silently overwrite a projection in the index.
        for (index, item) in items.iter().enumerate() {
            for other in items.iter().skip(index + 1) {
                assert_ne!(item.item_id, other.item_id, "entity keys must not collide");
            }
        }

        let texts = item_texts(&items);
        let session = texts
            .iter()
            .find(|text| text.starts_with("Session sess-1"))
            .expect("session item");
        assert!(session.contains("on seat architect"));
        assert!(session.contains("via zai/glm-5"));
        assert!(session.contains("2 pending permission requests"));
        assert!(!texts.iter().any(|text| text.contains("live rev")));
        assert!(!texts
            .iter()
            .any(|text| text.contains("secret-should-not-appear")));
        assert!(!texts
            .iter()
            .any(|text| text.contains("raw-evidence-must-not-leak")));
        assert!(texts
            .iter()
            .any(|text| text.starts_with("Pending approval approval:1: kube.apply")));
        assert!(!texts.iter().any(|text| text.contains("approval:2")));
        assert!(texts
            .iter()
            .any(|text| text.starts_with("Incident inc-1 (error, open): pod crash looping")));
        assert!(!texts.iter().any(|text| text.contains("\"seats\"")));
        assert!(texts.iter().any(|text| text
            .starts_with("Workload Pod default/api on cluster c1: running; owned by run run-1")));
        assert!(texts
            .iter()
            .any(|text| text.starts_with("Fleet node node-a: ready; observation")));
        assert!(texts.iter().any(|text| text.starts_with(
            "Lane delivery (enabled) project proj.core family delivery queue delivery.q"
        )));

        // Deterministic: the same model state pins to identical items.
        let (replayed_head, replayed_items) = source.pin().unwrap();
        assert_eq!(replayed_head, head);
        assert_eq!(replayed_items, items);
    }

    #[test]
    fn fleet_summaries_render_conditionally_with_offline_facts() {
        let read_model = model();
        read_model
            .upsert(snapshot(
                ObjectKind::FleetHost,
                "online-host",
                1,
                json!({
                    "host": "online-host",
                    "tailscale": "online-host",
                    "role": "control",
                    "capabilities": ["operator", "build"],
                    "tailnet": "reachable",
                    "k3sNodeState": "ready",
                    "online": true,
                    "lastSeen": "2026-09-28T10:00:00Z"
                }),
            ))
            .unwrap();
        read_model
            .upsert(snapshot(
                ObjectKind::FleetHost,
                "offline-host",
                1,
                json!({
                    "host": "offline-host",
                    "tailscale": "offline-host",
                    "role": "worker",
                    "tailnet": "unreachable",
                    "k3sNodeState": "notReady",
                    "online": false,
                    "lastSeen": "2026-09-28T09:00:00Z"
                }),
            ))
            .unwrap();
        read_model
            .upsert(snapshot(
                ObjectKind::FleetHost,
                "bare-host",
                1,
                json!({
                    "host": "bare-host",
                    "tailscale": "bare-host",
                    "role": "worker",
                    "tailnet": "unknown",
                    "online": false
                }),
            ))
            .unwrap();
        read_model
            .upsert(snapshot(
                ObjectKind::FleetPlacement,
                "fleet:placement:authority",
                1,
                json!({"thing": "odind-authority", "node": "node-a", "host": "online-host"}),
            ))
            .unwrap();
        read_model
            .upsert(snapshot(
                ObjectKind::FleetPlacement,
                "fleet:placement:pods:node-a",
                1,
                json!({
                    "thing": "pods",
                    "node": "node-a",
                    "host": "online-host",
                    "count": 2,
                    "names": ["api", "builder"]
                }),
            ))
            .unwrap();
        read_model
            .upsert(snapshot(
                ObjectKind::FleetPlacement,
                "fleet:placement:zellij:online-host",
                1,
                json!({
                    "thing": "zellij-sessions",
                    "host": "online-host",
                    "live": true,
                    "names": ["odin", "foo"]
                }),
            ))
            .unwrap();
        read_model
            .upsert(snapshot(
                ObjectKind::FleetPlacement,
                "fleet:placement:zellij:bare-host",
                1,
                json!({
                    "thing": "zellij-sessions",
                    "host": "bare-host",
                    "live": false,
                    "names": []
                }),
            ))
            .unwrap();

        let (_, items) = source(read_model).pin().unwrap();
        let texts = item_texts(&items);
        assert_eq!(items.len(), 7);
        let online = texts
            .iter()
            .find(|text| text.starts_with("Fleet host online-host (control, host online-host)"))
            .expect("online host item");
        assert!(online.contains("online — k3s Ready, tailnet reachable"));
        assert!(!online.contains("last seen"));
        assert!(online.contains("capabilities operator, build"));
        let offline = texts
            .iter()
            .find(|text| text.starts_with("Fleet host offline-host (worker, host offline-host)"))
            .expect("offline host item");
        assert!(offline.contains("offline — tailnet unreachable, k3s notReady"));
        assert!(offline.contains("last seen 2026-09-28T09:00:00Z"));
        assert!(!offline.contains("capabilities"));
        let bare = texts
            .iter()
            .find(|text| text.starts_with("Fleet host bare-host"))
            .expect("bare host item");
        assert!(bare.contains("offline — tailnet unknown, no k3s node"));
        assert!(bare.contains("last seen never"));
        assert!(texts.iter().any(
            |text| text.starts_with("Placement odind-authority: node node-a host online-host")
        ));
        let pods = texts
            .iter()
            .find(|text| text.starts_with("Placement pods: node node-a host online-host"))
            .expect("pods placement item");
        assert!(pods.contains("2 scheduled running api, builder"));
        // The live zellij placement reads the session names; the
        // unreachable one names none and says so instead of looking empty.
        let zellij = texts
            .iter()
            .find(|text| text.starts_with("Placement zellij-sessions host online-host"))
            .expect("live zellij placement item");
        assert!(zellij.contains("running odin, foo"));
        let zellij_down = texts
            .iter()
            .find(|text| text.starts_with("Placement zellij-sessions host bare-host"))
            .expect("unreachable zellij placement item");
        assert!(zellij_down.contains("(unreachable)"));
        assert!(!zellij_down.contains("running"));
    }

    #[test]
    fn head_changes_when_content_changes_under_same_numeric_revision() {
        // Two freshly built models both sit at numeric revision 1, but their
        // objects carry different content: the heads must differ, because
        // model revisions restart at zero across daemon restarts.
        let left = source(model());
        let right = source(model());
        left.read_model
            .upsert(snapshot(
                ObjectKind::Session,
                "sess-1",
                1,
                json!({"state": "running"}),
            ))
            .unwrap();
        right
            .read_model
            .upsert(snapshot(
                ObjectKind::Session,
                "sess-1",
                1,
                json!({"state": "ended"}),
            ))
            .unwrap();

        let (left_head, left_items) = left.pin().unwrap();
        let (right_head, right_items) = right.pin().unwrap();
        assert_ne!(left_head, right_head);
        assert_ne!(left_items, right_items);

        // Within one model, a content change at a new object revision moves
        // both the head and the summary text.
        left.read_model
            .upsert(snapshot(
                ObjectKind::Session,
                "sess-1",
                2,
                json!({"state": "ended"}),
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
    fn a_probe_stamp_or_an_unprojected_kind_keeps_the_head() {
        let read_model = model();
        let source = source(read_model.clone());
        let host = |revision: u64, seen: &str, online: bool| {
            snapshot(
                ObjectKind::FleetHost,
                "fleet:host:mini",
                revision,
                json!({
                    "tailscale": "mini",
                    "role": "authority",
                    "host": "mini",
                    "online": online,
                    "tailnet": "reachable",
                    "k3sNodeState": "ready",
                    "lastSeen": seen
                }),
            )
        };
        read_model
            .upsert(host(1, "2026-10-05T22:36:38Z", true))
            .unwrap();
        let (head, items) = source.pin().unwrap();
        read_model
            .upsert(host(2, "2026-10-05T22:37:09Z", true))
            .unwrap();
        read_model
            .upsert(snapshot(
                ObjectKind::Device,
                "phone",
                1,
                json!({"lastSeenAt": "2026-10-05T22:37:09Z"}),
            ))
            .unwrap();
        assert_eq!(source.pin().unwrap(), (head, items));
        read_model
            .upsert(host(3, "2026-10-05T22:37:09Z", false))
            .unwrap();
        let (moved, items) = source.pin().unwrap();
        assert_ne!(moved, head);
        assert!(item_texts(&items)[0].contains("last seen 2026-10-05T22:37:09Z"));
    }

    /// An offline host keeps its preserved stamp, and the producer
    /// serializes it as time's nine-element tuple: rendering "never" there
    /// hid real stamps, and a stamp advance between pins left text and
    /// head frozen, so serving reused the stale generation.
    #[test]
    fn offline_last_seen_tuple_moves_text_and_head() {
        let read_model = model();
        let source = source(read_model.clone());
        read_model
            .upsert(host_snapshot(
                1,
                false,
                Some(datetime!(2026-10-05 22:36:38 UTC)),
            ))
            .unwrap();
        let (head, items) = source.pin().unwrap();
        assert!(item_texts(&items)[0].contains("last seen 2026-10-05T22:36:38Z"));

        read_model
            .upsert(host_snapshot(
                2,
                false,
                Some(datetime!(2026-10-05 22:37:09 UTC)),
            ))
            .unwrap();
        let (moved, moved_items) = source.pin().unwrap();
        assert_ne!(moved, head);
        assert!(item_texts(&moved_items)[0].contains("last seen 2026-10-05T22:37:09Z"));

        // Absent stays "never".
        read_model.upsert(host_snapshot(3, false, None)).unwrap();
        let (_, items) = source.pin().unwrap();
        assert!(item_texts(&items)[0].contains("last seen never"));
    }

    /// Online probe timestamps must not change the projection or its head.
    #[test]
    fn online_last_seen_tuple_keeps_the_head() {
        let read_model = model();
        let source = source(read_model.clone());
        read_model
            .upsert(host_snapshot(
                1,
                true,
                Some(datetime!(2026-10-05 22:36:38 UTC)),
            ))
            .unwrap();
        let (head, items) = source.pin().unwrap();
        assert!(!item_texts(&items)[0].contains("last seen"));

        read_model
            .upsert(host_snapshot(
                2,
                true,
                Some(datetime!(2026-10-05 22:37:09 UTC)),
            ))
            .unwrap();
        assert_eq!(source.pin().unwrap(), (head, items));
    }

    /// A stamp the decoder cannot represent is not an observation the
    /// summary may state: the clause drops instead of printing a fabricated
    /// date — or a false "never". A literal null is `None` to serde, so
    /// "never" stays honest there.
    #[test]
    fn undecodable_last_seen_is_omitted_not_fabricated() {
        let read_model = model();
        let source = source(read_model.clone());
        let view = serde_json::to_value(host_view(false, Some(datetime!(2026-10-05 22:37:09 UTC))))
            .unwrap();
        for (revision, stamp) in (1u64..).zip([
            json!([2026, 278, 22, 37]),
            json!([2026, 999, 22, 37, 9, 0, 0, 0, 0]),
            json!([2026, 278, 99, 37, 9, 0, 0, 0, 0]),
            json!(42),
        ]) {
            let mut value = view.clone();
            value["lastSeen"] = stamp;
            read_model
                .upsert(snapshot(
                    ObjectKind::FleetHost,
                    "fleet:host:mini",
                    revision,
                    value,
                ))
                .unwrap();
            let (_, items) = source.pin().unwrap();
            let texts = item_texts(&items);
            assert!(texts[0].contains("offline — tailnet unreachable, k3s notReady"));
            assert!(!texts[0].contains("last seen"));
            assert!(!texts[0].contains("never"));
        }

        let mut value = view;
        value["lastSeen"] = Value::Null;
        read_model
            .upsert(snapshot(ObjectKind::FleetHost, "fleet:host:mini", 5, value))
            .unwrap();
        let (_, items) = source.pin().unwrap();
        assert!(item_texts(&items)[0].contains("last seen never"));
    }

    #[test]
    fn head_changes_on_freshness_flip_and_removal() {
        let read_model = model();
        let source = source(read_model.clone());
        read_model
            .upsert(snapshot(
                ObjectKind::Node,
                "node-a",
                1,
                json!({"state": "ready"}),
            ))
            .unwrap();
        let (fresh_head, fresh_items) = source.pin().unwrap();
        assert_eq!(fresh_items.len(), 1);

        // A freshness flip arrives through an apply delta (an equal-revision
        // upsert would be a conflict, so flips always move the object
        // revision): same content digest, new revision, stale tag — the
        // served head must still invalidate.
        read_model
            .apply(ObjectDelta {
                object: ObjectRef {
                    kind: ObjectKind::Node,
                    id: "node-a".to_owned(),
                },
                from_revision: Revision::new(1),
                to_revision: Revision::new(2),
                revision_source: RevisionSource::Registry,
                freshness: Freshness {
                    state: FreshnessState::Stale,
                    observed_at: OffsetDateTime::UNIX_EPOCH,
                    source_updated_at: None,
                    stale_after_seconds: None,
                },
                body: ObjectDeltaBody::MergePatch(json!({"state": "ready"})),
            })
            .unwrap();
        let (stale_head, stale_items) = source.pin().unwrap();
        assert_ne!(stale_head, fresh_head);
        assert_eq!(stale_items.len(), 1);

        // Removal invalidates and drops the item.
        read_model
            .remove(
                ObjectRef {
                    kind: ObjectKind::Node,
                    id: "node-a".to_owned(),
                },
                Revision::new(3),
                RevisionSource::Registry,
                freshness(),
            )
            .unwrap();
        let (removed_head, removed_items) = source.pin().unwrap();
        assert_ne!(removed_head, stale_head);
        assert!(removed_items.is_empty());
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
