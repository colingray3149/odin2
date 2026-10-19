//! The `ops.history` source: one deterministic, per-UTC-day/per-project
//! compression of the daemon's real operation journals.
//!
//! Three journal authorities inside the one shared ledger feed this source —
//! never a second store:
//! - `audit_events` (odin-ledger audit): the control plane's append-only
//!   operation log. Rows are immutable (SQL triggers) and redacted at write
//!   time; this source binds the stored payload DIGEST plus the recorded
//!   redaction mode, never payload bodies, so no redaction regime can leak
//!   through a history citation.
//! - `operation_journal` (the kernel capability/operation authority): exact
//!   capability operations with their canonical effect states. Requests are
//!   bound by digest only — arguments never enter the projection.
//! - the kube journal (`kube_job_operations`): exact kube operations with
//!   their settlements; rejected rows are the typed failure records.
//!
//! Decisions are the approvals authority's human settlements
//! (`decided_at IS NOT NULL` — approved or denied, with `decided_by`).
//!
//! Self-observation feedback is excluded in SQL, BEFORE the head digest:
//! audit kinds `knowledge.%` (the brain's own audit rows) and operations
//! with capability `brain.search`, `brain.read`, or `knowledge.%` (a
//! governed search/read journals and settles itself; including it would
//! invalidate a history citation because that very read completed). Real
//! `memory.remember`/write operations stay in history.
//!
//! Project attribution resolves ONLY from recorded authority — never
//! inferred, never defaulted: an audit row's recorded `scope.project`, else
//! its `scope.run`/`scope.lane` joined through the recorded `runs`/`lanes`
//! rows; a kernel operation's session joined through the recorded live
//! session row; a kube operation's run joined through `runs` → `lanes`; a
//! decision's recorded target joined the same way. Records that resolve to
//! no project are omitted as individual items and appear — in unrestricted
//! daemon-level sources only — as per-day counts in an explicit "without a
//! resolvable project" summary (counts by kind, no identifiers, no text).
//! A recorded but invalid project identity is corrupt authority and fails
//! the pin with a typed error instead of guessing.
//!
//! Every attributed operation, failure, and decision is individually retrievable,
//! and one deterministic summary item per (UTC day, project) carries counts
//! plus concise failure/decision provenance. Summaries are template text —
//! never LLM-written. A day's summaries form that day's generated-knowledge
//! page ([`SourceItem::with_summary_page`]); records stay in the brain.
//! Per-class windows retain newest records and report omitted counts.
//!
//! The head digest binds every authoritative record's content digest (with
//! its resolved attribution) in canonical order — after the per-seat
//! restriction has filtered the snapshot — plus the exact restriction
//! itself, unrestricted and empty distinct. One head identity is one
//! (authority, restriction) pair: any append, transition, settlement,
//! decision, attribution join change, or composition change moves the head,
//! and an unchanged ledger under an unchanged composition pins the
//! identical head, so a stored index generation can never be reused for a
//! different seat's view. `knowledge.*` audit rows and self-observation
//! operations cannot move it.
//!
//! Freshness: every input lives in the one ledger, so
//! `Ledger::subscribe_commits()` (the commit-hook watch) is the only wakeup
//! the daemon's event pump needs. It fires for every local commit including
//! brain audit rows; redundant wakeups are harmless because pin recomputes
//! the head from the authoritative records.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::sync::{Arc, Mutex};

use odin_domain::knowledge::ids::AtlasId;
use odin_domain::knowledge::retrieval::TrustClass;
use odin_domain::operation::EffectState;
use odin_domain::{Actor, Digest, ProjectId, Redaction, Scope};
use odin_ledger::audit::AuditEvidence;
use odin_ledger::{decode_utc, encode_utc, Ledger};
use rusqlite::Transaction;
use time::OffsetDateTime;

use crate::error::{BrainError, BrainResult};
use crate::source::SourceItem;

/// Domain-separation prefix for the head digest material.
const HEAD_DOMAIN: &[u8] = b"odin-brain:ops-history-head:v1\x00";
/// Record-kind tags inside the head material.
const AUDIT_TAG: u8 = 0x01;
const OPERATION_TAG: u8 = 0x02;
const KUBE_TAG: u8 = 0x03;
const DECISION_TAG: u8 = 0x04;

/// Project newest journal records and report omitted counts in a `window`
/// item; attribution joins still fail if their limits are exceeded.
const MAX_AUDIT_EVENTS: usize = 4096;
const MAX_OPERATIONS: usize = 4096;
const MAX_KUBE_OPERATIONS: usize = 4096;
const MAX_DECISIONS: usize = 4096;
const MAX_ATTRIBUTION_ROWS: usize = 65_536;
/// Concise provenance: failure/decision notes listed per summary before the
/// honest "+N more" (every listed record also exists as an exact item).
const PROVENANCE_LIMIT: usize = 16;
/// Evidence references listed per audit item before the honest "+N more".
const EVIDENCE_LIMIT: usize = 8;
/// Bounded rendering for recorded failure reasons (typed ledger data, but
/// still third-party text — never allowed to dominate an item).
const REASON_CHAR_LIMIT: usize = 200;

/// The brain source over the shared ledger's operation journals.
///
/// [`Clone`] shares the ledger handle (`Arc<Mutex<Ledger>>`): clones read
/// the same live authority; no snapshot state is ever copied. `projects` is
/// the per-seat restriction applied at composition (`restrict_projects`);
/// unrestricted daemon-level sources serve every attributed project.
#[derive(Clone)]
pub struct HistorySource {
    atlas_id: AtlasId,
    ledger: Arc<Mutex<Ledger>>,
    projects: Option<BTreeSet<ProjectId>>,
}

impl HistorySource {
    /// Binds this source to one knowledge-source identity and the shared
    /// ledger authority. The ledger stays the sole authority; the source
    /// only reads it.
    pub fn new(atlas_id: AtlasId, ledger: Arc<Mutex<Ledger>>) -> Self {
        Self {
            atlas_id,
            ledger,
            projects: None,
        }
    }

    /// The knowledge source identity used for items and citations.
    pub const fn atlas_id(&self) -> &AtlasId {
        &self.atlas_id
    }

    /// The per-seat composition: returns a source restricted to the seat's
    /// declared project set. The restriction filters the snapshot BEFORE
    /// the head digest and projection, so a restricted source reads exactly
    /// its declared projects' records — foreign and unattributed records
    /// never enter its head or its items, and an unknown project cannot
    /// grant any visibility.
    pub fn restrict_projects(&self, projects: &BTreeSet<ProjectId>) -> Self {
        Self {
            atlas_id: self.atlas_id.clone(),
            ledger: Arc::clone(&self.ledger),
            projects: Some(projects.clone()),
        }
    }

    /// Pins the current operation history and projects it into the head
    /// digest plus the full item set. One deferred read transaction spans
    /// every class read, so the head and the items are one consistent
    /// projection of one committed ledger snapshot.
    pub fn pin(&self) -> BrainResult<(Digest, Vec<SourceItem>)> {
        let ledger = self
            .ledger
            .lock()
            .map_err(|poisoned| BrainError::Unavailable {
                component: "ops_history_ledger",
                reason: format!("ledger mutex poisoned: {poisoned}"),
            })?;
        let transaction = ledger.connection().unchecked_transaction()?;
        let snapshot = restrict_snapshot(read_snapshot(&transaction)?, self.projects.as_ref());
        transaction.commit()?;
        let head = head_digest(&snapshot, self.projects.as_ref());
        let items = project_items(&self.atlas_id, &snapshot, head)?;
        Ok((head, items))
    }
}

/// Manual [`Debug`]: the ledger handle carries no debug contract, so only
/// the identity and the restriction are shown.
impl fmt::Debug for HistorySource {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HistorySource")
            .field("atlas_id", &self.atlas_id)
            .field("restricted", &self.projects.is_some())
            .finish_non_exhaustive()
    }
}

/// One atomic read of every operation-history input.
#[derive(Clone, Debug, Eq, PartialEq)]
struct HistorySnapshot {
    /// Audit events excluding `knowledge.%` kinds, ordered by sequence.
    audit_events: Vec<AuditRecord>,
    /// Kernel operations excluding self-observation capabilities, ordered
    /// by correlation id.
    operations: Vec<OperationRecord>,
    /// Kube journal operations, ordered by operation id.
    kube_operations: Vec<KubeOperationRecord>,
    /// Decided approvals (approved or denied), ordered by approval id.
    decisions: Vec<DecisionRecord>,
    /// Older records each class left outside its window, by class name.
    omitted: BTreeMap<&'static str, u64>,
}

/// The recorded project-attribution joins, read once per snapshot.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
struct AttributionMaps {
    /// `lanes.lane_id -> lanes.project_id` (`None` = not project-bound).
    lanes: BTreeMap<String, Option<String>>,
    /// `runs.run_id -> runs.lane_id`.
    runs: BTreeMap<String, String>,
    /// `live_sessions.session_id -> live_sessions.project_id`.
    sessions: BTreeMap<String, String>,
}

/// Resolved project attribution for one record.
///
/// [`Attribution::Project`] carries the only attribution that produces
/// items; [`Attribution::Unscoped`] and [`Attribution::Unresolved`] are the
/// explicit omission classes (counted per day, content withheld). The
/// distinction is honest provenance: "nothing recorded" differs from
/// "recorded but unresolvable".
#[derive(Clone, Debug, Eq, PartialEq)]
enum Attribution {
    Project(ProjectId),
    /// The record carries no project-bearing dimension at all.
    Unscoped,
    /// A dimension is recorded but resolves to no project (dangling run,
    /// project-less lane, unrecorded session).
    Unresolved(&'static str),
}

impl Attribution {
    fn project(&self) -> Option<&ProjectId> {
        match self {
            Self::Project(project) => Some(project),
            Self::Unscoped | Self::Unresolved(_) => None,
        }
    }

    /// Canonical digest token binding the resolution itself, so an
    /// attribution change (even to another unresolvable reason) moves the
    /// head.
    fn token(&self) -> String {
        match self {
            Self::Project(project) => format!("project:{project}"),
            Self::Unscoped => "unscoped".to_owned(),
            Self::Unresolved(reason) => format!("unresolved:{reason}"),
        }
    }
}

/// One exact audit record. Payload bodies are never retained — only the
/// BLAKE3 digest over the exact stored payload JSON plus the recorded
/// redaction mode.
#[derive(Clone, Debug, Eq, PartialEq)]
struct AuditRecord {
    sequence: u64,
    event_id: String,
    kind: String,
    actor: Actor,
    actor_json: String,
    scope: Scope,
    scope_json: String,
    evidence: Vec<AuditEvidence>,
    evidence_json: String,
    payload_digest: Digest,
    redaction: Redaction,
    redaction_json: String,
    instant: OffsetDateTime,
    occurred_at: String,
    attribution: Attribution,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct OperationRecord {
    correlation_id: String,
    operation_id: String,
    capsule_id: String,
    seat_id: String,
    session_id: String,
    capability: String,
    state: EffectState,
    request_digest: String,
    evidence_digest: Option<String>,
    executor_id: String,
    instant: OffsetDateTime,
    updated_at: String,
    attribution: Attribution,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct KubeOperationRecord {
    operation_id: String,
    run_id: String,
    kind: String,
    cluster: String,
    namespace: String,
    state: String,
    failure_kind: Option<String>,
    failure_reason: Option<String>,
    created_instant: OffsetDateTime,
    created_at: String,
    updated_instant: OffsetDateTime,
    updated_at: String,
    attribution: Attribution,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct DecisionRecord {
    approval_id: String,
    status: String,
    capability_id: String,
    target_kind: String,
    target_id: String,
    requested_instant: OffsetDateTime,
    requested_at: String,
    decided_instant: OffsetDateTime,
    decided_at: String,
    decided_by: Option<String>,
    evidence_ref: Option<String>,
    attribution: Attribution,
}

/// Reads every journal class inside one transaction and resolves each
/// record's project attribution from the recorded joins.
fn read_snapshot(transaction: &Transaction<'_>) -> BrainResult<HistorySnapshot> {
    let maps = read_attribution_maps(transaction)?;
    let mut omitted = BTreeMap::new();
    Ok(HistorySnapshot {
        audit_events: read_audit_events(transaction, &maps, &mut omitted)?,
        operations: read_operations(transaction, &maps, &mut omitted)?,
        kube_operations: read_kube_operations(transaction, &maps, &mut omitted)?,
        decisions: read_decisions(transaction, &maps, &mut omitted)?,
        omitted,
    })
}

/// Reads the three recorded attribution joins once, each bounded.
fn read_attribution_maps(transaction: &Transaction<'_>) -> BrainResult<AttributionMaps> {
    let lanes = bounded_rows(
        transaction,
        "SELECT lane_id, project_id FROM lanes",
        MAX_ATTRIBUTION_ROWS,
        "lanes",
        |row| Ok((row.get::<_, String>(0)?, row.get::<_, Option<String>>(1)?)),
    )?;
    let runs = bounded_rows(
        transaction,
        "SELECT run_id, lane_id FROM runs",
        MAX_ATTRIBUTION_ROWS,
        "runs",
        |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
    )?;
    let sessions = bounded_rows(
        transaction,
        "SELECT session_id, project_id FROM live_sessions",
        MAX_ATTRIBUTION_ROWS,
        "live_sessions",
        |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
    )?;
    Ok(AttributionMaps {
        lanes: lanes.into_iter().collect(),
        runs: runs.into_iter().collect(),
        sessions: sessions.into_iter().collect(),
    })
}

/// Reads audit events, excluding the brain's `knowledge.%` feedback rows in
/// SQL so they never enter the snapshot or the head.
fn read_audit_events(
    transaction: &Transaction<'_>,
    maps: &AttributionMaps,
    omitted: &mut BTreeMap<&'static str, u64>,
) -> BrainResult<Vec<AuditRecord>> {
    let rows = windowed_rows(
        transaction,
        omitted,
        "SELECT sequence, event_id, kind, actor_json, scope_json, \
                evidence_refs_json, payload_json, redaction_json, occurred_at \
         FROM audit_events WHERE kind NOT LIKE 'knowledge.%'",
        "sequence",
        MAX_AUDIT_EVENTS,
        "audit_events",
        |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, String>(5)?,
                row.get::<_, String>(6)?,
                row.get::<_, String>(7)?,
                row.get::<_, String>(8)?,
            ))
        },
    )?;
    let mut records = Vec::with_capacity(rows.len());
    for (
        sequence,
        event_id,
        kind,
        actor_json,
        scope_json,
        evidence_json,
        payload_json,
        redaction_json,
        occurred_at,
    ) in rows
    {
        let sequence = u64::try_from(sequence).map_err(|_| {
            BrainError::InvalidRequest(format!(
                "audit event {event_id} carries a negative sequence"
            ))
        })?;
        let instant = decode_utc(&occurred_at)?;
        let occurred_at = encode_utc(instant)?;
        let scope: Scope = serde_json::from_str(&scope_json)?;
        let attribution = audit_attribution(&scope, maps)?;
        records.push(AuditRecord {
            sequence,
            event_id,
            kind,
            actor: serde_json::from_str(&actor_json)?,
            actor_json,
            scope,
            scope_json,
            evidence: serde_json::from_str(&evidence_json)?,
            evidence_json,
            payload_digest: Digest::hash(payload_json.as_bytes()),
            redaction: serde_json::from_str(&redaction_json)?,
            redaction_json,
            instant,
            occurred_at,
            attribution,
        });
    }
    Ok(records)
}

/// Reads kernel operations, excluding the self-observation capabilities in
/// SQL so a governed brain search/read can never invalidate its own
/// citation. `memory.remember` and every other capability stays.
fn read_operations(
    transaction: &Transaction<'_>,
    maps: &AttributionMaps,
    omitted: &mut BTreeMap<&'static str, u64>,
) -> BrainResult<Vec<OperationRecord>> {
    let rows = windowed_rows(
        transaction,
        omitted,
        "SELECT correlation_id, operation_id, capsule_id, seat_id, session_id, \
                capability, effect_state, request_digest, evidence_digest, \
                executor_id, updated_at \
         FROM operation_journal \
         WHERE capability NOT LIKE 'knowledge.%' \
           AND capability NOT IN ('brain.search', 'brain.read')",
        "correlation_id",
        MAX_OPERATIONS,
        "operation_journal",
        |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, String>(5)?,
                row.get::<_, String>(6)?,
                row.get::<_, String>(7)?,
                row.get::<_, Option<String>>(8)?,
                row.get::<_, String>(9)?,
                row.get::<_, String>(10)?,
            ))
        },
    )?;
    let mut records = Vec::with_capacity(rows.len());
    for (
        correlation_id,
        operation_id,
        capsule_id,
        seat_id,
        session_id,
        capability,
        effect_state,
        request_digest,
        evidence_digest,
        executor_id,
        updated_at,
    ) in rows
    {
        let state = EffectState::parse(&effect_state).map_err(|error| {
            BrainError::InvalidRequest(format!(
                "operation {correlation_id} carries an unknown effect state: {error}"
            ))
        })?;
        let instant = decode_utc(&updated_at)?;
        let updated_at = encode_utc(instant)?;
        let attribution = match maps.sessions.get(session_id.as_str()) {
            Some(project) => {
                project_attribution(project, &format!("operation {correlation_id} live session"))?
            }
            None => Attribution::Unresolved("operation session is not a recorded live session"),
        };
        records.push(OperationRecord {
            correlation_id,
            operation_id,
            capsule_id,
            seat_id,
            session_id,
            capability,
            state,
            request_digest,
            evidence_digest,
            executor_id,
            instant,
            updated_at,
            attribution,
        });
    }
    Ok(records)
}

/// Reads every kube journal operation. Attribution joins the recorded run;
/// a run absent from `runs` resolves to nothing and is omitted explicitly.
fn read_kube_operations(
    transaction: &Transaction<'_>,
    maps: &AttributionMaps,
    omitted: &mut BTreeMap<&'static str, u64>,
) -> BrainResult<Vec<KubeOperationRecord>> {
    let rows = windowed_rows(
        transaction,
        omitted,
        "SELECT operation_id, run_id, kind, cluster, namespace, state, \
                failure_kind, failure_reason, created_at, updated_at \
         FROM kube_job_operations",
        "operation_id",
        MAX_KUBE_OPERATIONS,
        "kube_job_operations",
        |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, String>(5)?,
                row.get::<_, Option<String>>(6)?,
                row.get::<_, Option<String>>(7)?,
                row.get::<_, String>(8)?,
                row.get::<_, String>(9)?,
            ))
        },
    )?;
    let mut records = Vec::with_capacity(rows.len());
    for (
        operation_id,
        run_id,
        kind,
        cluster,
        namespace,
        state,
        failure_kind,
        failure_reason,
        created_at,
        updated_at,
    ) in rows
    {
        let created_instant = decode_utc(&created_at)?;
        let updated_instant = decode_utc(&updated_at)?;
        let attribution = run_attribution(&run_id, maps)?;
        records.push(KubeOperationRecord {
            attribution,
            operation_id,
            run_id,
            kind,
            cluster,
            namespace,
            state,
            failure_kind,
            failure_reason,
            created_instant,
            created_at: encode_utc(created_instant)?,
            updated_instant,
            updated_at: encode_utc(updated_instant)?,
        });
    }
    Ok(records)
}

/// Reads decided approvals: `decided_at IS NOT NULL` is exactly the
/// approved-or-denied settlement set; pending and expired requests are
/// state, not history decisions.
fn read_decisions(
    transaction: &Transaction<'_>,
    maps: &AttributionMaps,
    omitted: &mut BTreeMap<&'static str, u64>,
) -> BrainResult<Vec<DecisionRecord>> {
    let rows = windowed_rows(
        transaction,
        omitted,
        "SELECT approval_id, status, capability_id, target_kind, target_id, \
                requested_at, decided_at, decided_by, decision_evidence_ref \
         FROM approvals WHERE decided_at IS NOT NULL",
        "approval_id",
        MAX_DECISIONS,
        "approvals",
        |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, String>(5)?,
                row.get::<_, String>(6)?,
                row.get::<_, Option<String>>(7)?,
                row.get::<_, Option<String>>(8)?,
            ))
        },
    )?;
    let mut records = Vec::with_capacity(rows.len());
    for (
        approval_id,
        status,
        capability_id,
        target_kind,
        target_id,
        requested_at,
        decided_at,
        decided_by,
        evidence_ref,
    ) in rows
    {
        let requested_instant = decode_utc(&requested_at)?;
        let decided_instant = decode_utc(&decided_at)?;
        let attribution = match target_kind.as_str() {
            "run" => run_attribution(&target_id, maps)?,
            "lane" => lane_attribution(&target_id, maps)?,
            _ => Attribution::Unscoped,
        };
        records.push(DecisionRecord {
            attribution,
            approval_id,
            status,
            capability_id,
            target_kind,
            target_id,
            requested_instant,
            requested_at: encode_utc(requested_instant)?,
            decided_instant,
            decided_at: encode_utc(decided_instant)?,
            decided_by,
            evidence_ref,
        });
    }
    Ok(records)
}

/// A windowed row read of one journal class: the newest `bound` rows of
/// `base` (by ledger insertion order, `rowid`), returned in `order` order.
/// The count of older rows outside the window is recorded under `class` in
/// `omitted` — stated in the projection, never silently dropped.
fn windowed_rows<T>(
    transaction: &Transaction<'_>,
    omitted: &mut BTreeMap<&'static str, u64>,
    base: &str,
    order: &str,
    bound: usize,
    class: &'static str,
    decode: impl Fn(&rusqlite::Row<'_>) -> rusqlite::Result<T>,
) -> BrainResult<Vec<T>> {
    let total: u64 =
        transaction.query_row(&format!("SELECT COUNT(*) FROM ({base})"), [], |row| {
            row.get(0)
        })?;
    let windowed =
        format!("SELECT * FROM ({base} ORDER BY rowid DESC LIMIT {bound}) ORDER BY {order} ASC");
    let mut statement = transaction.prepare(&windowed)?;
    let rows = statement
        .query_map([], decode)?
        .collect::<Result<Vec<_>, _>>()?;
    let older = total.saturating_sub(rows.len() as u64);
    if older > 0 {
        omitted.insert(class, older);
    }
    Ok(rows)
}

/// A bounded row read: the query itself carries `LIMIT bound + 1`, and that
/// one overflow row is a typed error — the bound is enforced in SQL, never
/// a silent truncation of durable authority.
fn bounded_rows<T>(
    transaction: &Transaction<'_>,
    sql: &str,
    bound: usize,
    class: &str,
    decode: impl Fn(&rusqlite::Row<'_>) -> rusqlite::Result<T>,
) -> BrainResult<Vec<T>> {
    let limited = format!(
        "{sql} LIMIT {}",
        bound.checked_add(1).ok_or_else(|| {
            BrainError::InvalidRequest(
                "operations history projection bound overflowed usize".to_owned(),
            )
        })?
    );
    let mut statement = transaction.prepare(&limited)?;
    let rows = statement
        .query_map([], decode)?
        .collect::<Result<Vec<_>, _>>()?;
    if rows.len() > bound {
        return Err(BrainError::InvalidRequest(format!(
            "{class} exceeds the {bound} row operations-history projection bound; \
             refusing to truncate durable history"
        )));
    }
    Ok(rows)
}

/// Resolves an audit record's project from its recorded scope only:
/// explicit project, else recorded run, else recorded lane, else nothing.
fn audit_attribution(scope: &Scope, maps: &AttributionMaps) -> BrainResult<Attribution> {
    if let Some(project) = &scope.project {
        return project_attribution(project.as_str(), "audit event scope project");
    }
    if let Some(run) = &scope.run {
        return run_attribution(run.as_str(), maps);
    }
    if let Some(lane) = &scope.lane {
        return lane_attribution(lane.as_str(), maps);
    }
    Ok(Attribution::Unscoped)
}

/// Resolves a recorded run through `runs` → `lanes`.
fn run_attribution(run_id: &str, maps: &AttributionMaps) -> BrainResult<Attribution> {
    match maps.runs.get(run_id) {
        Some(lane_id) => lane_attribution(lane_id, maps),
        None => Ok(Attribution::Unresolved(
            "recorded run is not in the runs authority",
        )),
    }
}

/// Resolves a recorded lane's project binding.
fn lane_attribution(lane_id: &str, maps: &AttributionMaps) -> BrainResult<Attribution> {
    match maps.lanes.get(lane_id) {
        Some(Some(project)) => {
            project_attribution(project, &format!("lane {lane_id} project binding"))
        }
        Some(None) => Ok(Attribution::Unresolved(
            "recorded lane is not project-bound",
        )),
        None => Ok(Attribution::Unresolved(
            "recorded lane is not in the lanes authority",
        )),
    }
}

/// Validates one recorded project identity. A recorded but invalid project
/// string is corrupt authority and fails closed — never guessed around.
fn project_attribution(raw: &str, context: &str) -> BrainResult<Attribution> {
    if raw.is_empty() {
        return Err(BrainError::InvalidRequest(format!(
            "{context} records an empty project identity"
        )));
    }
    ProjectId::new(raw)
        .map(Attribution::Project)
        .map_err(|error| {
            BrainError::InvalidRequest(format!(
                "{context} records project {raw:?} that is not a valid project identity: {error}"
            ))
        })
}

/// Applies the per-seat restriction to the snapshot BEFORE the head digest
/// and projection: a restricted source reads exactly its declared projects'
/// records. Foreign records and unattributed records never enter a
/// restricted head or item set, so an unknown project cannot grant any
/// visibility. Unrestricted sources keep the full snapshot, unattributed
/// records included — their per-day unattributed summaries are the only
/// explicit omission channel, and it is daemon-level visibility.
fn restrict_snapshot(
    mut snapshot: HistorySnapshot,
    restricted: Option<&BTreeSet<ProjectId>>,
) -> HistorySnapshot {
    let Some(projects) = restricted else {
        return snapshot;
    };
    // Window counts span every project; a restricted source never sees them.
    snapshot.omitted.clear();
    let admissible = |attribution: &Attribution| {
        attribution
            .project()
            .is_some_and(|project| projects.contains(project))
    };
    snapshot
        .audit_events
        .retain(|record| admissible(&record.attribution));
    snapshot
        .operations
        .retain(|record| admissible(&record.attribution));
    snapshot
        .kube_operations
        .retain(|record| admissible(&record.attribution));
    snapshot
        .decisions
        .retain(|record| admissible(&record.attribution));
    snapshot
}

/// The head digest binds every record of the (already restricted) snapshot
/// in canonical order per class — the exact identity of the pinned history
/// — plus the exact restriction itself: one head identity is one
/// (authority, restriction) pair, so a stored index generation can never be
/// reused across a changed seat composition, and unrestricted and empty are
/// distinct even on an empty ledger. Excluded feedback rows never reach
/// this material.
fn head_digest(snapshot: &HistorySnapshot, restricted: Option<&BTreeSet<ProjectId>>) -> Digest {
    let mut material = Material::new(HEAD_DOMAIN);
    material.u8(AUDIT_TAG);
    material.u64(snapshot.audit_events.len() as u64);
    for record in &snapshot.audit_events {
        material.bytes(record.content_digest().as_bytes());
    }
    material.u8(OPERATION_TAG);
    material.u64(snapshot.operations.len() as u64);
    for record in &snapshot.operations {
        material.bytes(record.content_digest().as_bytes());
    }
    material.u8(KUBE_TAG);
    material.u64(snapshot.kube_operations.len() as u64);
    for record in &snapshot.kube_operations {
        material.bytes(record.content_digest().as_bytes());
    }
    material.u8(DECISION_TAG);
    material.u64(snapshot.decisions.len() as u64);
    for record in &snapshot.decisions {
        material.bytes(record.content_digest().as_bytes());
    }
    match restricted {
        None => material.u8(0x00),
        Some(projects) => {
            material.u8(0x01);
            material.u64(projects.len() as u64);
            for project in projects {
                material.str(project.as_str());
            }
        }
    }
    material.digest()
}

/// Length-prefixed canonical byte material for content and head digests.
struct Material {
    bytes: Vec<u8>,
}

impl Material {
    fn new(domain: &[u8]) -> Self {
        Self {
            bytes: domain.to_vec(),
        }
    }

    fn bytes(&mut self, bytes: &[u8]) {
        self.bytes
            .extend_from_slice(&(bytes.len() as u64).to_be_bytes());
        self.bytes.extend_from_slice(bytes);
    }

    fn str(&mut self, value: &str) {
        self.bytes(value.as_bytes());
    }

    fn u8(&mut self, value: u8) {
        self.bytes(&[value]);
    }

    fn u64(&mut self, value: u64) {
        self.bytes(&value.to_be_bytes());
    }

    fn opt_str(&mut self, value: Option<&str>) {
        match value {
            Some(value) => {
                self.u8(0x01);
                self.str(value);
            }
            None => self.u8(0x00),
        }
    }

    fn digest_value(&mut self, value: &Digest) {
        self.bytes(value.as_bytes());
    }

    fn digest(&self) -> Digest {
        Digest::hash(&self.bytes)
    }
}

impl AuditRecord {
    /// The content digest binding every recorded field, the resolved
    /// attribution included.
    fn content_digest(&self) -> Digest {
        let mut material = Material::new(b"odin-brain:ops-audit-record:v1\x00");
        material.u64(self.sequence);
        material.str(&self.event_id);
        material.str(&self.kind);
        material.str(&self.actor_json);
        material.str(&self.scope_json);
        material.str(&self.evidence_json);
        material.digest_value(&self.payload_digest);
        material.str(&self.redaction_json);
        material.str(&self.occurred_at);
        material.str(&self.attribution.token());
        material.digest()
    }
}

impl OperationRecord {
    /// The content digest binding every recorded field, the resolved
    /// attribution included.
    fn content_digest(&self) -> Digest {
        let mut material = Material::new(b"odin-brain:ops-operation-record:v1\x00");
        material.str(&self.correlation_id);
        material.str(&self.operation_id);
        material.str(&self.capsule_id);
        material.str(&self.seat_id);
        material.str(&self.session_id);
        material.str(&self.capability);
        material.str(self.state.as_str());
        material.str(&self.request_digest);
        material.opt_str(self.evidence_digest.as_deref());
        material.str(&self.executor_id);
        material.str(&self.updated_at);
        material.str(&self.attribution.token());
        material.digest()
    }
}

impl KubeOperationRecord {
    /// The content digest binding every recorded field, the resolved
    /// attribution included.
    fn content_digest(&self) -> Digest {
        let mut material = Material::new(b"odin-brain:ops-kube-record:v1\x00");
        material.str(&self.operation_id);
        material.str(&self.run_id);
        material.str(&self.kind);
        material.str(&self.cluster);
        material.str(&self.namespace);
        material.str(&self.state);
        material.opt_str(self.failure_kind.as_deref());
        material.opt_str(self.failure_reason.as_deref());
        material.str(&self.created_at);
        material.str(&self.updated_at);
        material.str(&self.attribution.token());
        material.digest()
    }
}

impl DecisionRecord {
    /// The content digest binding every recorded field, the resolved
    /// attribution included.
    fn content_digest(&self) -> Digest {
        let mut material = Material::new(b"odin-brain:ops-decision-record:v1\x00");
        material.str(&self.approval_id);
        material.str(&self.status);
        material.str(&self.capability_id);
        material.str(&self.target_kind);
        material.str(&self.target_id);
        material.str(&self.requested_at);
        material.str(&self.decided_at);
        material.opt_str(self.decided_by.as_deref());
        material.opt_str(self.evidence_ref.as_deref());
        material.str(&self.attribution.token());
        material.digest()
    }
}

/// Deterministic per-(day, project) compression tallies. `None` project is
/// the explicit unattributed bucket: counts only, identifiers withheld.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
struct DaySummary {
    audit: ClassTally,
    operations: ClassTally,
    kube: ClassTally,
    decisions: ClassTally,
    /// Concise failure provenance; project buckets only.
    failures: Vec<String>,
    /// Concise decision provenance; project buckets only.
    decision_notes: Vec<String>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
struct ClassTally {
    total: u64,
    buckets: BTreeMap<String, u64>,
}

/// Projects the pinned (already restricted) snapshot into exact items (one
/// per record — every record in the snapshot is admissible by
/// construction) plus one summary item per (UTC day, project). Item order
/// is the canonical natural-key order.
fn project_items(
    atlas_id: &AtlasId,
    snapshot: &HistorySnapshot,
    head: Digest,
) -> BrainResult<Vec<SourceItem>> {
    let mut days: BTreeMap<(String, Option<ProjectId>), DaySummary> = BTreeMap::new();
    let mut keyed: Vec<(String, SourceItem)> = Vec::new();

    for record in &snapshot.audit_events {
        let summary = day_entry(&mut days, record.instant, &record.attribution);
        bump(&mut summary.audit, &record.kind)?;
        if let Some(project) = record.attribution.project() {
            let key = format!("audit/{}", record.event_id);
            let text = audit_text(record);
            let built = item(atlas_id, head, key.clone(), text)?.with_project(project.clone());
            keyed.push((key, built));
        }
    }
    for record in &snapshot.operations {
        let summary = day_entry(&mut days, record.instant, &record.attribution);
        bump(&mut summary.operations, record.state.as_str())?;
        if let Some(project) = record.attribution.project() {
            match record.state {
                EffectState::Aborted => summary.failures.push(format!(
                    "kernel operation {} aborted",
                    record.correlation_id
                )),
                EffectState::InDoubt => summary.failures.push(format!(
                    "kernel operation {} in_doubt (unresolved)",
                    record.correlation_id
                )),
                _ => {}
            }
            let key = format!("operation/{}", record.correlation_id);
            let text = operation_text(record);
            let built = item(atlas_id, head, key.clone(), text)?.with_project(project.clone());
            keyed.push((key, built));
        }
    }
    for record in &snapshot.kube_operations {
        let summary = day_entry(&mut days, record.updated_instant, &record.attribution);
        bump(&mut summary.kube, &record.state)?;
        if record.state == "rejected" && record.attribution.project().is_some() {
            let kind = record.failure_kind.as_deref().unwrap_or("unrecorded");
            let reason = record
                .failure_reason
                .as_deref()
                .map(|reason| bounded(reason, REASON_CHAR_LIMIT))
                .unwrap_or_else(|| "unrecorded".to_owned());
            summary.failures.push(format!(
                "kube operation {} rejected ({kind}): {reason}",
                record.operation_id
            ));
        }
        if let Some(project) = record.attribution.project() {
            let key = format!("kube-operation/{}", record.operation_id);
            let text = kube_text(record);
            let built = item(atlas_id, head, key.clone(), text)?.with_project(project.clone());
            keyed.push((key, built));
        }
    }
    for record in &snapshot.decisions {
        let summary = day_entry(&mut days, record.decided_instant, &record.attribution);
        bump(&mut summary.decisions, &record.status)?;
        if let Some(project) = record.attribution.project() {
            summary.decision_notes.push(format!(
                "{} {} by {}",
                record.approval_id,
                record.status,
                record.decided_by.as_deref().unwrap_or("unrecorded")
            ));
            let key = format!("decision/{}", record.approval_id);
            let text = decision_text(record);
            let built = item(atlas_id, head, key.clone(), text)?.with_project(project.clone());
            keyed.push((key, built));
        }
    }

    for ((day, project), summary) in &days {
        let (key, text) = match project {
            Some(project) => (
                format!("summary/{day}/project/{project}"),
                summary_text(day, project, summary),
            ),
            None => (
                format!("summary/{day}/scope/unattributed"),
                unattributed_text(day, summary),
            ),
        };
        let built = item(atlas_id, head, key.clone(), text)?.with_summary_page(day.as_str());
        let built = match project {
            Some(project) => built.with_project(project.clone()),
            None => built,
        };
        keyed.push((key, built));
    }

    if !snapshot.omitted.is_empty() {
        let classes: Vec<String> = snapshot
            .omitted
            .iter()
            .map(|(class, older)| format!("{class}: {older} older records not projected"))
            .collect();
        let key = "window".to_owned();
        let text = format!(
            "Operations history window: each journal class projects its newest records; \
             the durable ledger keeps the rest. {}.",
            classes.join("; ")
        );
        keyed.push((key.clone(), item(atlas_id, head, key, text)?));
    }
    keyed.sort_by(|left, right| left.0.cmp(&right.0));
    Ok(keyed.into_iter().map(|(_, built)| built).collect())
}

/// The day bucket for one record: (UTC day, resolved project or the
/// unattributed bucket).
fn day_entry<'days>(
    days: &'days mut BTreeMap<(String, Option<ProjectId>), DaySummary>,
    instant: OffsetDateTime,
    attribution: &Attribution,
) -> &'days mut DaySummary {
    let key = (utc_day(instant), attribution.project().cloned());
    days.entry(key).or_default()
}

/// Increments one tally with checked arithmetic — an overflow is a typed
/// error, never a silent wrap.
fn bump(tally: &mut ClassTally, bucket: &str) -> BrainResult<()> {
    tally.total = tally.total.checked_add(1).ok_or_else(tally_overflow)?;
    let entry = tally.buckets.entry(bucket.to_owned()).or_insert(0);
    *entry = entry.checked_add(1).ok_or_else(tally_overflow)?;
    Ok(())
}

fn tally_overflow() -> BrainError {
    BrainError::InvalidRequest(
        "operations history day tally overflowed u64; refusing to project corrupt counts"
            .to_owned(),
    )
}

fn item(atlas_id: &AtlasId, head: Digest, key: String, text: String) -> BrainResult<SourceItem> {
    SourceItem::new(
        atlas_id.clone(),
        head,
        key.as_bytes(),
        TrustClass::Observed,
        text,
    )
}

/// The exact audit record: identity, kind, actor, scope, canonical instant,
/// evidence references, and the payload's digest with its redaction mode.
/// Payload bodies are never rendered.
fn audit_text(record: &AuditRecord) -> String {
    format!(
        "audit event {}\nkind: {}\nactor: {}\nscope: {}\noccurred: {}\n\
         evidence: {}\npayload: {} ({})\n{}",
        record.event_id,
        record.kind,
        actor_text(&record.actor),
        scope_text(&record.scope),
        record.occurred_at,
        evidence_text(&record.evidence),
        record.payload_digest,
        redaction_text(&record.redaction),
        attribution_text(&record.attribution),
    )
}

/// The exact kernel operation: bindings, effect state, request digest only
/// (never request arguments), and the resolved project.
fn operation_text(record: &OperationRecord) -> String {
    format!(
        "kernel operation {}\ncorrelation: {}\ncapability: {}\nseat: {}\n\
         capsule: {}\nstate: {}\nrequest digest: {}\nevidence digest: {}\n\
         executor: {}\nupdated: {}\n{}",
        record.operation_id,
        record.correlation_id,
        record.capability,
        record.seat_id,
        record.capsule_id,
        record.state.as_str(),
        record.request_digest,
        record.evidence_digest.as_deref().unwrap_or("none"),
        record.executor_id,
        record.updated_at,
        attribution_text(&record.attribution),
    )
}

/// The exact kube operation: kind, run, cluster scope, settlement state,
/// and the recorded failure classification with its bounded reason.
fn kube_text(record: &KubeOperationRecord) -> String {
    let mut lines = vec![
        format!("kube operation {}", record.operation_id),
        format!("kind: {}", record.kind),
        format!("run: {}", record.run_id),
        format!(
            "scope: cluster {} namespace {}",
            record.cluster, record.namespace
        ),
        format!("state: {}", record.state),
    ];
    if record.failure_kind.is_some() || record.failure_reason.is_some() {
        let kind = record.failure_kind.as_deref().unwrap_or("unrecorded");
        let reason = record
            .failure_reason
            .as_deref()
            .map(|reason| bounded(reason, REASON_CHAR_LIMIT))
            .unwrap_or_else(|| "unrecorded".to_owned());
        lines.push(format!("failure: {kind}: {reason}"));
    }
    lines.push(format!("created: {}", record.created_at));
    lines.push(format!("updated: {}", record.updated_at));
    lines.push(attribution_text(&record.attribution));
    lines.join("\n")
}

/// The exact approval decision: status, target, both instants, decider,
/// and the decision evidence reference.
fn decision_text(record: &DecisionRecord) -> String {
    format!(
        "approval decision {}\nstatus: {}\ncapability: {}\ntarget: {} {}\n\
         requested: {}\ndecided: {} by {}\nevidence: {}\n{}",
        record.approval_id,
        record.status,
        record.capability_id,
        record.target_kind,
        record.target_id,
        record.requested_at,
        record.decided_at,
        record.decided_by.as_deref().unwrap_or("unrecorded"),
        record.evidence_ref.as_deref().unwrap_or("none"),
        attribution_text(&record.attribution),
    )
}

/// The per-day/per-project compressed summary: counts per class and state,
/// plus concise failure and decision provenance. Template text only —
/// never LLM-written.
fn summary_text(day: &str, project: &ProjectId, summary: &DaySummary) -> String {
    let mut lines = vec![format!("operations history {day} project {project}")];
    tally_line(&mut lines, "audit events", &summary.audit);
    tally_line(&mut lines, "kernel operations", &summary.operations);
    tally_line(&mut lines, "kube operations", &summary.kube);
    tally_line(&mut lines, "decisions", &summary.decisions);
    lines.push(format!("failures: {}", provenance(&summary.failures)));
    lines.push(format!(
        "decision provenance: {}",
        provenance(&summary.decision_notes)
    ));
    lines.join("\n")
}

/// The per-day unattributed summary: counts by class and kind only —
/// identifiers, reasons, and provenance are withheld, and the withholding
/// is stated.
fn unattributed_text(day: &str, summary: &DaySummary) -> String {
    let mut lines = vec![format!(
        "operations history {day} for records without a resolvable project"
    )];
    withheld_line(&mut lines, "audit events", &summary.audit);
    withheld_line(&mut lines, "kernel operations", &summary.operations);
    withheld_line(&mut lines, "kube operations", &summary.kube);
    withheld_line(&mut lines, "decisions", &summary.decisions);
    lines.join("\n")
}

fn tally_line(lines: &mut Vec<String>, label: &str, tally: &ClassTally) {
    if tally.total == 0 {
        return;
    }
    lines.push(format!(
        "{label}: {} ({})",
        tally.total,
        buckets_text(tally)
    ));
}

fn withheld_line(lines: &mut Vec<String>, label: &str, tally: &ClassTally) {
    if tally.total == 0 {
        return;
    }
    lines.push(format!(
        "{label}: {} ({}); content withheld: records carry no resolvable project authority",
        tally.total,
        buckets_text(tally)
    ));
}

fn buckets_text(tally: &ClassTally) -> String {
    tally
        .buckets
        .iter()
        .map(|(bucket, count)| format!("{bucket} {count}"))
        .collect::<Vec<_>>()
        .join(", ")
}

fn provenance(notes: &[String]) -> String {
    if notes.is_empty() {
        return "none recorded".to_owned();
    }
    if notes.len() <= PROVENANCE_LIMIT {
        return notes.join("; ");
    }
    format!(
        "{}; {} more",
        notes[..PROVENANCE_LIMIT].join("; "),
        notes.len() - PROVENANCE_LIMIT
    )
}

fn attribution_text(attribution: &Attribution) -> String {
    match attribution {
        Attribution::Project(project) => format!("project: {project}"),
        Attribution::Unscoped => "project: none recorded".to_owned(),
        Attribution::Unresolved(reason) => format!("project: unresolved ({reason})"),
    }
}

fn scope_text(scope: &Scope) -> String {
    let mut parts = Vec::new();
    if let Some(seat) = &scope.seat {
        parts.push(format!("seat {seat}"));
    }
    if let Some(project) = &scope.project {
        parts.push(format!("project {project}"));
    }
    if let Some(lane) = &scope.lane {
        parts.push(format!("lane {lane}"));
    }
    if let Some(run) = &scope.run {
        parts.push(format!("run {run}"));
    }
    if let Some(attempt) = &scope.attempt {
        parts.push(format!("attempt {attempt}"));
    }
    if let Some(session) = &scope.session {
        parts.push(format!("session {session}"));
    }
    if let Some(node) = &scope.node {
        parts.push(format!("node {node}"));
    }
    if parts.is_empty() {
        "none recorded".to_owned()
    } else {
        parts.join(", ")
    }
}

fn actor_text(actor: &Actor) -> String {
    match actor {
        Actor::Seat { seat, session } => match session {
            Some(session) => format!("seat:{seat}@{session}"),
            None => format!("seat:{seat}"),
        },
        Actor::Node { node } => format!("node:{node}"),
        Actor::System { name } => format!("system:{name}"),
    }
}

fn evidence_text(evidence: &[AuditEvidence]) -> String {
    if evidence.is_empty() {
        return "none".to_owned();
    }
    let rendered = evidence
        .iter()
        .map(|evidence| match evidence {
            AuditEvidence::Artifact(id) => format!("artifact:{id}"),
            AuditEvidence::Event(id) => format!("event:{id}"),
            AuditEvidence::Command(id) => format!("command:{id}"),
            AuditEvidence::Incident(id) => format!("incident:{id}"),
            AuditEvidence::Checkpoint(id) => format!("checkpoint:{id}"),
        })
        .collect::<Vec<_>>();
    if rendered.len() <= EVIDENCE_LIMIT {
        rendered.join(", ")
    } else {
        format!(
            "{}; {} more",
            rendered[..EVIDENCE_LIMIT].join(", "),
            rendered.len() - EVIDENCE_LIMIT
        )
    }
}

fn redaction_text(redaction: &Redaction) -> String {
    match redaction {
        Redaction::None => "redaction none".to_owned(),
        Redaction::Payload => "payload redacted".to_owned(),
        Redaction::Fields { json_pointers } => {
            format!("fields redacted ({})", json_pointers.len())
        }
    }
}

/// The canonical UTC day (YYYY-MM-DD) of one recorded instant.
fn utc_day(instant: OffsetDateTime) -> String {
    let (year, month, day) = instant
        .to_offset(time::UtcOffset::UTC)
        .date()
        .to_calendar_date();
    format!("{year:04}-{:02}-{day:02}", month as u8)
}

/// Char-boundary-safe bounded rendering for recorded third-party text.
fn bounded(text: &str, limit: usize) -> String {
    if text.chars().count() <= limit {
        return text.to_owned();
    }
    format!("{}…", text.chars().take(limit).collect::<String>())
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::sync::{Arc, Mutex};

    use odin_domain::knowledge::ids::AtlasId;
    use odin_domain::operation::EffectState;
    use odin_domain::{
        Actor, ApprovalId, CapabilityId, Digest, EventId, LaneId, ProjectId, Redaction, RunId,
        Scope, SeatId, SessionId,
    };
    use odin_ledger::approval::{ApprovalDecision, ApprovalScope, NewApproval};
    use odin_ledger::audit::{NewAuditEvent, RedactedPayload};
    use odin_ledger::kube::{self, Journal};
    use odin_ledger::lane_run::{create_lane, create_run, NewLane, NewRun};
    use odin_ledger::live::NewLiveSession;
    use odin_ledger::operation::{prepare_operation, transition_operation, NewOperation};
    use odin_ledger::{encode_utc, Ledger};
    use rusqlite::Connection;
    use serde_json::json;
    use time::OffsetDateTime;

    use super::{HistorySource, MAX_AUDIT_EVENTS};
    use crate::source::SourceItem;

    fn at(seconds: i64) -> OffsetDateTime {
        OffsetDateTime::from_unix_timestamp(seconds).unwrap()
    }

    fn shared(ledger: Ledger) -> Arc<Mutex<Ledger>> {
        Arc::new(Mutex::new(ledger))
    }

    fn history(ledger: &Arc<Mutex<Ledger>>) -> HistorySource {
        HistorySource::new(AtlasId::new("ops.history").unwrap(), Arc::clone(ledger))
    }

    fn alpha_scope() -> Scope {
        Scope {
            project: Some(ProjectId::new("alpha").unwrap()),
            ..Scope::default()
        }
    }

    fn audit(id: &str, kind: &str, seconds: i64, scope: Scope) -> NewAuditEvent {
        NewAuditEvent {
            event_id: EventId::new(id).unwrap(),
            kind: kind.to_owned(),
            actor: Actor::Seat {
                seat: SeatId::new("kubert").unwrap(),
                session: None,
            },
            scope,
            evidence: Vec::new(),
            payload: RedactedPayload::new(json!({"detail": "metadata-only"}), Redaction::None)
                .unwrap(),
            occurred_at: at(seconds),
        }
    }

    fn lane(connection: &Connection, lane_id: &str, project: Option<&str>) {
        create_lane(
            connection,
            &NewLane {
                lane_id: LaneId::new(lane_id).unwrap(),
                seat_id: SeatId::new("kubert").unwrap(),
                project_id: project.map(|project| ProjectId::new(project).unwrap()),
                template_id: "template".to_owned(),
                backend: "local_omp".to_owned(),
                created_by: "colin".to_owned(),
                created_at: at(0),
                retained: true,
            },
        )
        .unwrap();
    }

    fn run(connection: &Connection, run_id: &str, lane_id: &str) {
        create_run(
            connection,
            &NewRun {
                run_id: RunId::new(run_id).unwrap(),
                lane_id: LaneId::new(lane_id).unwrap(),
                attempt_number: 1,
                workflow_id: None,
                workflow_version: None,
                input_hash: "input-hash".to_owned(),
                accepted_capability_revision: None,
                lease_id: None,
                absolute_deadline: None,
                retry_budget: 0,
                created_at: at(0),
            },
        )
        .unwrap();
    }

    fn live_session(ledger: &mut Ledger, session: &str, lane_id: &str, project: &str) {
        ledger
            .create_live_session(&NewLiveSession {
                session_id: SessionId::new(session).unwrap(),
                seat_id: "kubert".to_owned(),
                project_id: project.to_owned(),
                slice_id: "slice".to_owned(),
                lane_id: lane_id.to_owned(),
                target_node_id: "node-1".to_owned(),
                provider: "provider".to_owned(),
                model: "model".to_owned(),
                title: None,
                manifest: json!({}),
                open_tab: false,
                state: "running".to_owned(),
                created_at: at(0),
            })
            .unwrap();
    }

    fn kernel_op(
        ledger: &mut Ledger,
        correlation: &str,
        capability: &str,
        session: &str,
        seconds: i64,
    ) {
        let new = NewOperation {
            capsule_id: "capsule.test",
            seat_id: "kubert",
            token_id: "token-1",
            session_id: session,
            policy_digest: "policy-digest",
            listing_digest: "listing-digest",
            executor_id: "executor-1",
            prepared_binding: "binding",
            binding_digest: "binding-digest",
            correlation_id: correlation,
            capability,
            request_digest: "request-digest",
            request_json: r#"{"payload": "secret-payload"}"#,
            reconciliation_json: "{}",
            now: at(seconds),
        };
        ledger
            .with_tx(|tx| prepare_operation(tx, &new).map(|_| ()))
            .unwrap();
    }

    fn transition(
        ledger: &mut Ledger,
        correlation: &str,
        from: EffectState,
        to: EffectState,
        seconds: i64,
    ) {
        ledger
            .with_tx(|tx| {
                transition_operation(tx, correlation, from, to, None, at(seconds)).map(|_| ())
            })
            .unwrap();
    }

    fn kube_insert(ledger: &Ledger, id: &str, run_id: &str, seconds: i64) {
        Journal(ledger.connection())
            .insert(
                &kube::Operation {
                    id: id.to_owned(),
                    fingerprint: "fingerprint".to_owned(),
                    request: "{}".to_owned(),
                    progress: "{}".to_owned(),
                    state: "pending".to_owned(),
                    result: None,
                    failure_kind: None,
                    failure_reason: None,
                },
                &kube::Identity {
                    run: &RunId::new(run_id).unwrap(),
                    kind: "create",
                    digest: &Digest::hash(b"idempotency"),
                },
                &kube::Scope {
                    cluster: "cluster-0",
                    namespace: "odin",
                },
                &encode_utc(at(seconds)).unwrap(),
            )
            .unwrap();
    }

    fn kube_reject(ledger: &Ledger, id: &str, kind: &str, reason: &str, seconds: i64) {
        Journal(ledger.connection())
            .finish(
                id,
                &kube::Settlement {
                    state: "rejected",
                    result: None,
                    failure_kind: Some(kind),
                    failure_reason: Some(reason),
                },
                &encode_utc(at(seconds)).unwrap(),
            )
            .unwrap();
    }

    fn denied_approval(ledger: &mut Ledger, approval: &str, target_run: &str, seconds: i64) {
        ledger
            .request_approval(NewApproval {
                approval_id: ApprovalId::new(approval).unwrap(),
                issuer: "issuer-1".to_owned(),
                scope: ApprovalScope {
                    target_kind: "run".to_owned(),
                    target_id: target_run.to_owned(),
                    capability_id: CapabilityId::new("kube.workload.cancel").unwrap(),
                    arguments_digest: Digest::hash(b"arguments"),
                },
                requested_at: at(seconds),
                expires_at: at(seconds + 3600),
            })
            .unwrap();
        ledger
            .decide_approval(
                &ApprovalId::new(approval).unwrap(),
                ApprovalDecision::Deny {
                    evidence_ref: "artifact:denial".to_owned(),
                },
                "colin",
                at(seconds + 60),
                1,
            )
            .unwrap();
    }

    fn texts(items: &[SourceItem]) -> Vec<String> {
        let mut texts: Vec<String> = items.iter().map(|item| item.text.clone()).collect();
        texts.sort();
        texts
    }

    fn has_prefix(items: &[SourceItem], prefix: &str) -> bool {
        items.iter().any(|item| item.text.starts_with(prefix))
    }

    #[test]
    fn append_changes_head_and_repin_is_stable() {
        let ledger = shared(Ledger::open_in_memory().unwrap());
        let source = history(&ledger);
        let (empty_head, empty_items) = source.pin().unwrap();
        assert!(empty_items.is_empty());
        let (repinned, _) = source.pin().unwrap();
        assert_eq!(empty_head, repinned);

        ledger
            .lock()
            .unwrap()
            .append_audit_event(audit("event-1", "lane.observed", 10, alpha_scope()))
            .unwrap();

        let (head, items) = source.pin().unwrap();
        assert_ne!(head, empty_head);
        assert_eq!(items.len(), 2);
        assert!(has_prefix(&items, "audit event event-1"));
        assert!(has_prefix(
            &items,
            "operations history 1970-01-01 project alpha"
        ));
        // Every project-specific item carries its recorded project.
        assert!(items
            .iter()
            .all(|item| item.project.as_ref().is_some_and(|p| p.as_str() == "alpha")));

        let (same_head, same_items) = source.pin().unwrap();
        assert_eq!(head, same_head);
        assert_eq!(items, same_items);

        ledger
            .lock()
            .unwrap()
            .append_audit_event(audit("event-2", "lane.observed", 20, alpha_scope()))
            .unwrap();
        let (moved, items_after) = source.pin().unwrap();
        assert_ne!(moved, head);
        assert_eq!(items_after.len(), 3);
    }

    #[test]
    fn self_observation_feedback_never_moves_head() {
        let mut ledger = Ledger::open_in_memory().unwrap();
        {
            let connection = ledger.connection();
            lane(connection, "lane-alpha", Some("alpha"));
        }
        live_session(&mut ledger, "session-1", "lane-alpha", "alpha");
        let ledger = shared(ledger);
        let source = history(&ledger);

        let (head0, items0) = source.pin().unwrap();

        // Brain audit feedback cannot move the head.
        ledger
            .lock()
            .unwrap()
            .append_audit_event(audit(
                "brain-noise",
                "knowledge.index.rebuilt",
                10,
                Scope::default(),
            ))
            .unwrap();
        let (head1, items1) = source.pin().unwrap();
        assert_eq!((head0, &items0), (head1, &items1));

        // A governed brain search/read journals and settles itself; it must
        // not move the head or appear in history, or citations would
        // invalidate because the read completed.
        {
            let mut guard = ledger.lock().unwrap();
            kernel_op(&mut guard, "corr-search", "brain.search", "session-1", 20);
            kernel_op(&mut guard, "corr-read", "brain.read", "session-1", 21);
        }
        let (head2, items2) = source.pin().unwrap();
        assert_eq!((head0, &items0), (head2, &items2));

        // Real memory operations stay in history and move the head.
        {
            let mut guard = ledger.lock().unwrap();
            kernel_op(
                &mut guard,
                "corr-remember",
                "memory.remember",
                "session-1",
                30,
            );
        }
        let (head3, items3) = source.pin().unwrap();
        assert_ne!(head3, head0);
        assert!(items3.iter().any(|item| {
            item.text.contains("corr-remember") && item.text.contains("memory.remember")
        }));
        assert!(has_prefix(
            &items3,
            "operations history 1970-01-01 project alpha"
        ));
    }

    #[test]
    fn project_isolation_under_restriction() {
        let ledger = Ledger::open_in_memory().unwrap();
        {
            let connection = ledger.connection();
            lane(connection, "lane-alpha", Some("alpha"));
            lane(connection, "lane-beta", Some("beta"));
        }
        ledger
            .append_audit_event(audit(
                "evt-alpha",
                "lane.observed",
                10,
                Scope {
                    lane: Some(LaneId::new("lane-alpha").unwrap()),
                    ..Scope::default()
                },
            ))
            .unwrap();
        ledger
            .append_audit_event(audit(
                "evt-beta",
                "lane.observed",
                11,
                Scope {
                    project: Some(ProjectId::new("beta").unwrap()),
                    ..Scope::default()
                },
            ))
            .unwrap();
        ledger
            .append_audit_event(audit("evt-unowned", "lane.observed", 12, Scope::default()))
            .unwrap();
        let ledger = shared(ledger);
        let source = history(&ledger);

        let (head, unrestricted) = source.pin().unwrap();
        assert_eq!(unrestricted.len(), 5);
        assert!(has_prefix(&unrestricted, "audit event evt-alpha"));
        assert!(has_prefix(&unrestricted, "audit event evt-beta"));
        assert!(has_prefix(
            &unrestricted,
            "operations history 1970-01-01 project alpha"
        ));
        assert!(has_prefix(
            &unrestricted,
            "operations history 1970-01-01 project beta"
        ));
        assert!(has_prefix(
            &unrestricted,
            "operations history 1970-01-01 for records without a resolvable project"
        ));
        // Only the unattributed summary is allowed to lack a project.
        assert!(unrestricted
            .iter()
            .all(|item| item.project.is_some() || item.text.contains("without a resolvable")));

        // Restricted to alpha: beta's records never enter the snapshot at
        // all — no exact items, no beta summary, and no unattributed
        // summary either (an unknown project cannot grant visibility).
        let alpha_only: BTreeSet<ProjectId> = BTreeSet::from([ProjectId::new("alpha").unwrap()]);
        let (alpha_head, alpha_items) = source.restrict_projects(&alpha_only).pin().unwrap();
        assert_eq!(alpha_items.len(), 2);
        assert!(has_prefix(&alpha_items, "audit event evt-alpha"));
        assert!(has_prefix(
            &alpha_items,
            "operations history 1970-01-01 project alpha"
        ));
        assert!(!has_prefix(&alpha_items, "audit event evt-beta"));
        assert!(!has_prefix(
            &alpha_items,
            "operations history 1970-01-01 project beta"
        ));
        assert!(!has_prefix(
            &alpha_items,
            "operations history 1970-01-01 for records without"
        ));
        assert!(alpha_items
            .iter()
            .all(|item| item.project.as_ref().is_some_and(|p| p.as_str() == "alpha")));

        // Restricted to nothing: no items at all.
        let empty: BTreeSet<ProjectId> = BTreeSet::new();
        let (empty_head, empty_items) = source.restrict_projects(&empty).pin().unwrap();
        assert!(empty_items.is_empty());

        // One head identity is one (authority, restriction) pair: the
        // three compositions are three distinct heads, and a re-pin of the
        // same composition is byte-identical.
        assert_ne!(alpha_head, head);
        assert_ne!(empty_head, head);
        assert_ne!(alpha_head, empty_head);
        let (alpha_again, alpha_again_items) = source.restrict_projects(&alpha_only).pin().unwrap();
        assert_eq!(
            (alpha_head, &alpha_items),
            (alpha_again, &alpha_again_items)
        );
    }

    #[test]
    fn deterministic_day_grouping() {
        let events = [("evt-a", 10), ("evt-b", 20), ("evt-c", 86_400 + 30)];
        let build = |order: &[usize]| -> (Digest, Vec<String>) {
            let ledger = Ledger::open_in_memory().unwrap();
            {
                let connection = ledger.connection();
                lane(connection, "lane-alpha", Some("alpha"));
            }
            for &index in order {
                let (id, second) = events[index];
                ledger
                    .append_audit_event(audit(id, "lane.observed", second, alpha_scope()))
                    .unwrap();
            }
            let ledger = shared(ledger);
            let source = history(&ledger);
            let (head, items) = source.pin().unwrap();
            (head, texts(&items))
        };

        // The SAME records (ids and instants) appended in both orders; two
        // records land on day one, one on day two.
        let (head_forward, forward) = build(&[0, 1, 2]);
        let (head_backward, backward) = build(&[2, 1, 0]);
        let (head_again, _) = build(&[0, 1, 2]);

        // The same durable world pins the identical head; a different
        // append order is a different durable world (audit sequences are
        // durable identity) and moves it.
        assert_eq!(head_forward, head_again);
        assert_ne!(head_forward, head_backward);

        // Day grouping is a pure function of record content: the summary
        // items are identical regardless of append order.
        let summaries = |texts: &[String]| -> Vec<String> {
            texts
                .iter()
                .filter(|text| text.starts_with("operations history"))
                .cloned()
                .collect()
        };
        assert_eq!(summaries(&forward), summaries(&backward));

        let day_one = summaries(&forward)
            .into_iter()
            .find(|text| text.starts_with("operations history 1970-01-01 project alpha"))
            .expect("day one summary");
        assert!(day_one.contains("audit events: 2 (lane.observed 2)"));
        let day_two = summaries(&forward)
            .into_iter()
            .find(|text| text.starts_with("operations history 1970-01-02 project alpha"))
            .expect("day two summary");
        assert!(day_two.contains("audit events: 1 (lane.observed 1)"));
    }

    #[test]
    fn recorded_failure_and_decision_are_reflected() {
        let mut ledger = Ledger::open_in_memory().unwrap();
        {
            let connection = ledger.connection();
            lane(connection, "lane-alpha", Some("alpha"));
            run(connection, "run-kube", "lane-alpha");
        }
        live_session(&mut ledger, "session-1", "lane-alpha", "alpha");
        let ledger = shared(ledger);
        let source = history(&ledger);
        let (baseline_head, _) = source.pin().unwrap();

        // An audit record whose redacted secret must never surface.
        let mut secret_event = audit("evt-secret", "lane.observed", 10, alpha_scope());
        secret_event.payload = RedactedPayload::new(
            json!({"secret": "s3cr3t-value"}),
            Redaction::Fields {
                json_pointers: BTreeSet::from(["/secret".to_owned()]),
            },
        )
        .unwrap();
        ledger
            .lock()
            .unwrap()
            .append_audit_event(secret_event)
            .unwrap();

        {
            let mut guard = ledger.lock().unwrap();
            kernel_op(&mut guard, "corr-abort", "build.run", "session-1", 20);
            transition(
                &mut guard,
                "corr-abort",
                EffectState::Prepared,
                EffectState::Aborted,
                25,
            );
        }
        {
            let guard = ledger.lock().unwrap();
            kube_insert(&guard, "kube-op-1", "run-kube", 30);
            kube_reject(
                &guard,
                "kube-op-1",
                "admission",
                "pod label rejected by policy",
                35,
            );
        }
        {
            let mut guard = ledger.lock().unwrap();
            denied_approval(&mut guard, "approval-1", "run-kube", 40);
        }

        let (head, items) = source.pin().unwrap();
        assert_ne!(head, baseline_head);
        assert_eq!(items.len(), 5);

        let audit_item = items
            .iter()
            .find(|item| item.text.starts_with("audit event evt-secret"))
            .unwrap();
        assert!(audit_item.text.contains("fields redacted (1)"));
        assert!(!audit_item.text.contains("s3cr3t-value"));

        let operation_item = items
            .iter()
            .find(|item| item.text.starts_with("kernel operation "))
            .unwrap();
        assert!(operation_item.text.contains("state: aborted"));
        assert!(operation_item
            .text
            .contains("request digest: request-digest"));
        assert!(!operation_item.text.contains("secret-payload"));
        assert!(operation_item.text.contains("project: alpha"));

        let kube_item = items
            .iter()
            .find(|item| item.text.starts_with("kube operation kube-op-1"))
            .unwrap();
        assert!(kube_item
            .text
            .contains("failure: admission: pod label rejected by policy"));
        assert!(kube_item.text.contains("project: alpha"));

        let decision_item = items
            .iter()
            .find(|item| item.text.starts_with("approval decision approval-1"))
            .unwrap();
        assert!(decision_item.text.contains("status: denied"));
        assert!(decision_item.text.contains("by colin"));
        assert!(decision_item.text.contains("project: alpha"));

        let summary = items
            .iter()
            .find(|item| {
                item.text
                    .starts_with("operations history 1970-01-01 project alpha")
            })
            .unwrap();
        assert!(summary.text.contains("audit events: 1 (lane.observed 1)"));
        assert!(summary.text.contains("kernel operations: 1 (aborted 1)"));
        assert!(summary.text.contains("kube operations: 1 (rejected 1)"));
        assert!(summary.text.contains("decisions: 1 (denied 1)"));
        assert!(summary.text.contains(
            "failures: kernel operation corr-abort aborted; \
             kube operation kube-op-1 rejected (admission): pod label rejected by policy"
        ));
        assert!(summary
            .text
            .contains("decision provenance: approval-1 denied by colin"));
    }

    #[test]
    fn unresolvable_records_are_omitted_and_counted_explicitly() {
        let ledger = shared(Ledger::open_in_memory().unwrap());
        {
            let guard = ledger.lock().unwrap();
            kube_insert(&guard, "kube-ghost", "run-ghost", 10);
            kube_reject(&guard, "kube-ghost", "admission", "dangling run", 20);
        }
        let source = history(&ledger);

        let (head, items) = source.pin().unwrap();
        // No exact item for the unattributed record; the omission is
        // explicit as a per-day count with no identifiers.
        assert_eq!(items.len(), 1);
        let unattributed = &items[0];
        assert!(unattributed
            .text
            .contains("kube operations: 1 (rejected 1)"));
        assert!(unattributed.text.contains("content withheld"));
        assert!(!unattributed.text.contains("kube-ghost"));
        assert!(!unattributed.text.contains("dangling run"));
        assert!(unattributed.project.is_none());

        // A restricted source has no visibility into unattributed records
        // at all — the omission channel is daemon-level only.
        let alpha_only: BTreeSet<ProjectId> = BTreeSet::from([ProjectId::new("alpha").unwrap()]);
        let (restricted_head, restricted) = source.restrict_projects(&alpha_only).pin().unwrap();
        assert!(restricted.is_empty());
        assert_ne!(restricted_head, head);

        // Once the run's lane resolves to a project, the record becomes an
        // exact item and leaves the unattributed bucket — and the head
        // moves, because the resolved attribution is bound content.
        {
            let guard = ledger.lock().unwrap();
            let connection = guard.connection();
            lane(connection, "lane-alpha", Some("alpha"));
            run(connection, "run-ghost", "lane-alpha");
        }
        let (resolved_head, resolved) = source.pin().unwrap();
        assert_ne!(resolved_head, head);
        assert!(has_prefix(&resolved, "kube operation kube-ghost"));
        assert!(has_prefix(
            &resolved,
            "operations history 1970-01-01 project alpha"
        ));
        assert_eq!(resolved.len(), 2);

        // The restricted source now sees exactly the resolved project's
        // two items under its own head.
        let (_, restricted_resolved) = source.restrict_projects(&alpha_only).pin().unwrap();
        assert_eq!(restricted_resolved.len(), 2);
        assert!(has_prefix(
            &restricted_resolved,
            "kube operation kube-ghost"
        ));
    }

    #[test]
    fn invalid_recorded_project_authority_fails_closed() {
        let ledger = Ledger::open_in_memory().unwrap();
        {
            let connection = ledger.connection();
            lane(connection, "lane-alpha", Some("alpha"));
        }
        ledger
            .connection()
            .execute(
                "INSERT INTO lanes (lane_id, seat_id, project_id, template_id, backend, \
                 created_by, created_at, updated_at) \
                 VALUES ('lane-bad', 'kubert', 'not a project', 'template', 'local_omp', \
                 'colin', '1970-01-01T00:00:00Z', '1970-01-01T00:00:00Z')",
                [],
            )
            .unwrap();
        ledger
            .append_audit_event(audit(
                "evt-bad",
                "lane.observed",
                10,
                Scope {
                    lane: Some(LaneId::new("lane-bad").unwrap()),
                    ..Scope::default()
                },
            ))
            .unwrap();
        let ledger = shared(ledger);
        let source = history(&ledger);

        let error = source.pin().unwrap_err();
        assert!(error.to_string().contains("not a valid project identity"));
    }

    #[test]
    fn projection_windows_the_newest_records_and_states_the_rest() {
        let ledger = Ledger::open_in_memory().unwrap();
        for index in 0..MAX_AUDIT_EVENTS + 3 {
            ledger
                .append_audit_event(audit(
                    &format!("evt-{index:05}"),
                    "lane.observed",
                    10,
                    alpha_scope(),
                ))
                .unwrap();
        }
        let ledger = shared(ledger);
        let source = history(&ledger);

        let (_, items) = source.pin().unwrap();
        let texts: Vec<String> = items.iter().map(|item| item.text.clone()).collect();
        let window = texts
            .iter()
            .find(|text| text.starts_with("Operations history window"))
            .expect("a window item states the omission");
        assert!(window.contains("audit_events: 3 older records not projected"));
        assert!(!texts.iter().any(|text| text.contains("evt-00000")));
        assert!(texts
            .iter()
            .any(|text| text.contains(&format!("evt-{:05}", MAX_AUDIT_EVENTS + 2))));
    }
}
