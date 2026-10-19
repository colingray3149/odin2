use std::fmt;
use std::num::{NonZeroU16, ParseIntError};
use std::str::FromStr;

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::{ArtifactId, Digest, LaneId, NodeId, ProjectId, RunId, SeatId};

use super::ids::LiveSessionId;

/// Monotonic revision of a materialized Huginn object.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Revision(u64);

impl Revision {
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    pub const fn get(self) -> u64 {
        self.0
    }

    pub const fn checked_next(self) -> Option<Self> {
        match self.0.checked_add(1) {
            Some(value) => Some(Self(value)),
            None => None,
        }
    }

    pub fn parse(value: &str) -> Result<Self, ParseIntError> {
        value.parse::<u64>().map(Self)
    }
}

impl fmt::Display for Revision {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

impl FromStr for Revision {
    type Err = ParseIntError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::parse(value)
    }
}
/// Authority that assigned an object's revision.
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(
    rename_all = "camelCase",
    rename_all_fields = "camelCase",
    tag = "kind",
    deny_unknown_fields
)]
pub enum RevisionSource {
    Registry,
    Kernel,
    Ledger,
    Omp,
    Kube,
    Browser,
    Fleet,
    Simulation,
    FileSystem { root: super::ids::FileRootId },
    Adapter { name: String },
}

/// Whether an observation is current enough for the operation being shown.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub enum FreshnessState {
    Fresh,
    Stale,
    Unknown,
    Unavailable,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Freshness {
    pub state: FreshnessState,
    pub observed_at: OffsetDateTime,
    pub source_updated_at: Option<OffsetDateTime>,
    pub stale_after_seconds: Option<u64>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub enum ObjectKind {
    Status,
    Seat,
    Agent,
    Lane,
    Session,
    Node,
    KubeResource,
    Container,
    Approval,
    Artifact,
    Browser,
    Simulation,
    Device,
    File,
    Render,
    Terminal,
    FleetHost,
    FleetPlacement,
}

/// Stable typed reference used by heterogeneous snapshots and search results.
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ObjectRef {
    pub kind: ObjectKind,
    pub id: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ObjectSnapshot {
    pub object: ObjectRef,
    pub revision: Revision,
    pub revision_source: RevisionSource,
    pub freshness: Freshness,
    pub content_digest: Digest,
    pub value: serde_json::Value,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(
    rename_all = "camelCase",
    tag = "kind",
    content = "value",
    deny_unknown_fields
)]
pub enum ObjectDeltaBody {
    Replace(serde_json::Value),
    MergePatch(serde_json::Value),
    Remove,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ObjectDelta {
    pub object: ObjectRef,
    pub from_revision: Revision,
    pub to_revision: Revision,
    pub revision_source: RevisionSource,
    pub freshness: Freshness,
    pub body: ObjectDeltaBody,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(
    rename_all = "camelCase",
    tag = "kind",
    content = "id",
    deny_unknown_fields
)]
pub enum QueryScope {
    All,
    Seat(SeatId),
    Project(ProjectId),
    Lane(LaneId),
    Run(RunId),
    Session(LiveSessionId),
    Node(NodeId),
    Artifact(ArtifactId),
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SnapshotQuery {
    pub scope: QueryScope,
    pub kinds: Vec<ObjectKind>,
    pub if_revision: Option<Revision>,
    pub cursor: Option<String>,
    pub limit: NonZeroU16,
    pub include_stale: bool,
}

/// Bounded incremental pages of object deltas after the supplied cursor.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DeltaQuery {
    /// An opaque delta cursor. The literal `"0"` replays from the empty
    /// model (every model is empty at revision zero); anything else must be
    /// a cursor the serving model itself issued — a [`DeltaPage`]'s
    /// `checkpoint` or `nextAfter`, or a [`SnapshotPage`]'s `deltaCursor`.
    /// Revisions restart with every model, so a cursor names its model:
    /// another model's cursor (an earlier daemon's) fails `CursorExpired`
    /// even at an equal revision, as does one outside the retained window;
    /// a malformed or bare numeric cursor fails `InvalidRequest`. Either
    /// way the client takes a fresh snapshot.
    pub after: String,
    /// Most deltas wanted in this page; the server also caps the page by
    /// its own item and frame-byte bounds. Absent: the server's page size.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<std::num::NonZeroU16>,
}
/// One live object subscription: which kinds, in which scope, starting
/// after the global read-model revision `after`. A nonzero `after` resumes
/// only on the connection that handed it out — the revision of a complete
/// snapshot of the same kind set and scope (`includeStale`) whose every
/// page this connection served, or a checkpoint of this connection's
/// subscription; anything else fails `CursorExpired` without replacing the
/// active subscription. The client resumes — and acks each pushed batch —
/// with the checkpoint the batch carries.
/// Only one batch may remain unacknowledged. Resubscription before that
/// batch's transport write completes returns `objectAckPending` without
/// replacing the subscription. Completion during request dispatch counts;
/// once delivered, a valid checkpoint or fresh snapshot may replace it.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ObjectSubscription {
    pub kinds: Vec<ObjectKind>,
    pub scope: QueryScope,
    pub after: Revision,
}

/// The deltas from `from_revision` (exclusive) to `to_revision`
/// (inclusive), in order; both revisions are descriptive only — resume
/// with the opaque `checkpoint`. A cursor older than the retained window
/// fails `CursorExpired`: the client takes a fresh snapshot instead. A page
/// never exceeds the connection's frame bound: when more deltas remain,
/// `next_after` is the cursor of the next page (equal to `checkpoint`).
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DeltaPage {
    pub from_revision: Revision,
    pub to_revision: Revision,
    pub deltas: Vec<ObjectDelta>,
    /// The opaque delta cursor at `to_revision`, bound to the serving
    /// model: the next [`DeltaQuery::after`], on an empty caught-up page
    /// too, and valid on any connection to the same model.
    pub checkpoint: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_after: Option<String>,
}

/// The push payload for one live [`ObjectSubscription`] page: every object
/// the subscription filters in, coalesced to at most one delta per object.
/// `from_revision` echoes the client's checkpoint; `to_revision` is the
/// covering global model revision — every global delta in the range is
/// either carried in `deltas` or deterministically excluded by the
/// subscription's kinds and scope — and the client adopts it only after
/// applying every delta. A page cut by the frame bound names the resume
/// cursor in `next_after` (equal to `to_revision`).
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ObjectDeltaBatch {
    pub from_revision: Revision,
    pub to_revision: Revision,
    pub deltas: Vec<ObjectDelta>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_after: Option<Revision>,
}

/// Push-urgency policy: whether one object's change must flush a coalescing
/// page immediately for the subscriber instead of waiting out the coalescing
/// window. Sessions and approvals are always urgent; incident status is
/// keyed by incident id: every minting path prefixes `incident:` (the
/// `IncidentId::from_parts` desk, pump, and vehicle paths, and
/// `incident:stall:{digest}`) or `incident.` (recovery ids). An
/// `incident`-prefixed id outside those grammars, and roster or spend
/// `Status` ids, coalesce.
pub fn urgent_object(kind: ObjectKind, id: &str) -> bool {
    match kind {
        ObjectKind::Session | ObjectKind::Approval => true,
        ObjectKind::Status => id.starts_with("incident:") || id.starts_with("incident."),
        _ => false,
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SnapshotPage {
    pub revision: Revision,
    pub generated_at: OffsetDateTime,
    pub objects: Vec<ObjectSnapshot>,
    /// Opaque, bound to the serving model, this query's identity (scope,
    /// kind set, `includeStale`; not the page limit) and `revision`: another
    /// model's cursor fails `CursorExpired`, another query's
    /// `InvalidRequest`.
    pub next_cursor: Option<String>,
    /// The raw [`DeltaQuery::after`] cursor at `revision`, only on the final
    /// page of an unfiltered snapshot (`QueryScope::All`, no kinds filter,
    /// `includeStale`): the state that sync applies deltas to. A raw-delta
    /// baseline only; it grants no object-subscription resume.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delta_cursor: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SearchQuery {
    pub text: String,
    pub scope: QueryScope,
    pub kinds: Vec<ObjectKind>,
    pub cursor: Option<String>,
    pub limit: NonZeroU16,
    pub include_stale: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SearchHit {
    pub object: ObjectRef,
    pub revision: Revision,
    pub freshness: Freshness,
    pub title: String,
    pub summary: String,
    pub relevance_micros: u32,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SearchPage {
    pub hits: Vec<SearchHit>,
    pub next_cursor: Option<String>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum DiagnosticSeverity {
    Info,
    Warning,
    Error,
}

/// Redacted diagnostic safe to expose to authenticated clients.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PublicDiagnostic {
    pub code: String,
    pub severity: DiagnosticSeverity,
    pub message: String,
}
