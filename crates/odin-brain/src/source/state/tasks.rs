//! The task state source: one deterministic brain projection of the governed
//! delegation authority and the ledger's workload runs.
//!
//! Two real authorities feed this source, read through one runtime adapter —
//! never re-derived here:
//! - The durable delegation links (`odin.delegation-link.v1` rows, file-backed
//!   behind `odin-omp`'s `DelegationLinkLedger`). One row per delegated
//!   worker: parent→child lineage, owner seat, project, lifecycle phase, and
//!   the durable typed-result annotation (`learning_result_sequence`). The
//!   rows are NOT ledger tables, so the projection consumes them only as
//!   adapter-carried snapshots; the brain never parses link storage itself.
//! - The ledger's own `runs`, `lanes`, and pending `approvals` rows: workload
//!   runs with their state tokens, lane-owned seat/project attribution, and
//!   pending operator approvals (`status = 'requested'`) as honest blockers.
//!
//! [`TaskStateReader`] is the single authoritative handle: the runtime (which
//! owns both the link ledger and the `odin_ledger::Ledger`) implements it and
//! hands over one atomic [`TaskStateSnapshot`].
//!
//! Deterministic projection of recorded status:
//! - One [`SourceItem`] per delegation row under the stable natural key
//!   `delegation/<child>` and one per run under `run/<run_id>`, at
//!   [`TrustClass::Observed`] (state observations, never control instructions).
//! - Every summary field is either the exact recorded value or an explicit
//!   honest absence: a legacy link row without durable seat attribution reads
//!   `owner seat: unknown`; missing session observations and timestamps read
//!   as not observed or not recorded. Absence never implies lifecycle progress.
//! - The head digest hashes every item's key and text. Per-event counters and
//!   timestamps stay out so session activity alone does not rebuild the source.
//! - Records are sorted by the source itself (delegations by creation instant
//!   then child, runs by id, blockers by approval id), so the projection is
//!   order-stable regardless of adapter delivery order.
//!
//! Errors fail closed: an adapter error propagates and a record with an empty
//! identity field is refused — never silently skipped.

use std::fmt;
use std::sync::Arc;

use odin_domain::knowledge::ids::AtlasId;
use odin_domain::knowledge::retrieval::TrustClass;
use odin_domain::Digest;

use crate::error::{BrainError, BrainResult};
use crate::source::SourceItem;

/// Domain-separation prefix for the head digest material.
const HEAD_DOMAIN: &[u8] = b"odin-brain:tasks-head:v3\x00";

/// One delegated worker task: the exact projection of one durable
/// `odin.delegation-link.v1` row joined with the child session's live row.
///
/// Identity fields carry the exact recorded id strings; `parent_seat` stays
/// `None` when the row predates durable seat attribution; the child-session
/// fields stay `None` until the child's live session row exists.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DelegationTask {
    /// The child (worker) session identity.
    pub child: String,
    /// The delegating parent session identity.
    pub parent: String,
    /// The delegating parent's seat; `None` only on legacy rows, never
    /// guessed.
    pub parent_seat: Option<String>,
    /// The parent run whose accepted plan the child inherited.
    pub parent_run: String,
    /// The child run carrying the inherited plan.
    pub child_run: String,
    /// The validated in-scope child project.
    pub project: String,
    /// The durable lifecycle phase.
    pub phase: DelegationPhase,
    /// Delegation depth (1 for a worker of a root session).
    pub depth: u8,
    /// Creation instant in Unix milliseconds.
    pub created_at_ms: u64,
    /// Sequence of the child's typed `Result` event once durably observed;
    /// `None` until then — absence is honest, never a completed status.
    pub result_sequence: Option<u64>,
    /// The child session's recorded state token; `None` when the child has
    /// not opened a live session row yet.
    pub child_state: Option<String>,
    /// The model lanes (`provider/model`) the worker ran on, launch lane
    /// first, then the fallback the kernel moved it to after a repeated
    /// stall.
    pub lanes: Vec<String>,
    /// The lane of each recorded stall, in order.
    pub stalls: Vec<String>,
}

/// The lifecycle phase of one delegation link row: the exact durable tokens
/// of `odin.delegation-link.v1`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DelegationPhase {
    /// The link is durable; the child token/open has not completed.
    Provisioning,
    /// The child opened idle, inherited the plan, and was prompted.
    Running,
    /// The owner observed the child inactive after a running phase.
    Ended,
    /// Provisioning or the pre-prompt sequence failed honestly, and any
    /// child opened along the way was verifiably stopped.
    Failed,
}

impl DelegationPhase {
    /// The exact wire token of the phase.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Provisioning => "provisioning",
            Self::Running => "running",
            Self::Ended => "ended",
            Self::Failed => "failed",
        }
    }
}

/// One pending operator approval bound to a run: the honest blocker record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PendingBlocker {
    /// The durable approval id.
    pub approval_id: String,
    /// The capability the approval gates (for example a `seat.ask.*` ask).
    pub capability_id: String,
    /// The request instant (RFC 3339).
    pub requested_at: String,
}

/// One workload run: the exact projection of one ledger `runs` row joined
/// with its lane's seat/project attribution and its pending approvals.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkloadRun {
    /// The run identity.
    pub run_id: String,
    /// The lane the run executes on.
    pub lane_id: String,
    /// The lane's owner seat.
    pub seat: Option<String>,
    /// The lane's bound project; `None` when the lane is not project-bound.
    pub project: Option<String>,
    /// The exact run state token (`desired`, `running`, `waiting_approval`,
    /// `blocked`, ...). Never reinterpreted or invented.
    pub state: String,
    /// The attempt number of this run.
    pub attempt_number: i64,
    /// The start instant (RFC 3339); `None` before the run starts.
    pub started_at: Option<String>,
    /// The last update instant (RFC 3339).
    pub updated_at: String,
    /// The end instant (RFC 3339); `None` while the run is not terminal.
    pub ended_at: Option<String>,
    /// Pending operator approvals targeting this run, sorted by approval id.
    pub blockers: Vec<PendingBlocker>,
}

/// One atomic read of every task-authority input.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TaskStateSnapshot {
    /// Delegation rows, sorted by (creation instant, child).
    pub delegations: Vec<DelegationTask>,
    /// Workload runs, sorted by run id.
    pub runs: Vec<WorkloadRun>,
}

/// The authoritative task-state handle, implemented by the runtime over the
/// real delegation link ledger and the durable ledger.
///
/// [`Clone`] on the source shares this handle (`Arc`): clones observe the
/// same authority; no snapshot is ever copied ahead of the reader.
pub trait TaskStateReader: Send + Sync {
    /// Reads one atomic, internally consistent snapshot of every authority
    /// input. An error is explicit unavailability — never a partial snapshot.
    fn snapshot(&self) -> BrainResult<TaskStateSnapshot>;
}

/// The brain source over the governed delegation and workload-run authority.
///
/// [`Clone`] shares the runtime reader (`Arc`): clones read the same live
/// authority; no snapshot state is ever copied.
#[derive(Clone)]
pub struct TasksSource {
    atlas_id: AtlasId,
    reader: Arc<dyn TaskStateReader>,
}

impl TasksSource {
    /// Binds this source to one knowledge-source identity and the runtime
    /// task-state reader. The reader stays the sole authority; the source
    /// only reads through it.
    pub fn new(atlas_id: AtlasId, reader: Arc<dyn TaskStateReader>) -> Self {
        Self { atlas_id, reader }
    }

    /// The knowledge source identity used for items and citations.
    pub const fn atlas_id(&self) -> &AtlasId {
        &self.atlas_id
    }

    /// Pins the current task authority and projects it into the head digest
    /// plus the full item set. The snapshot is read exactly once, so the head
    /// and the items are one consistent projection.
    pub fn pin(&self) -> BrainResult<(Digest, Vec<SourceItem>)> {
        let snapshot = normalize(self.reader.snapshot()?)?;
        let projected = project(&snapshot);
        let head = head_digest(&projected);
        let items = projected
            .into_iter()
            .map(|(key, text)| {
                SourceItem::new(
                    self.atlas_id.clone(),
                    head,
                    key.as_bytes(),
                    TrustClass::Observed,
                    text,
                )
            })
            .collect::<BrainResult<Vec<_>>>()?;
        Ok((head, items))
    }
}

/// Manual [`Debug`]: the authority handle carries no debug contract, so only
/// the identity is shown.
impl fmt::Debug for TasksSource {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TasksSource")
            .field("atlas_id", &self.atlas_id)
            .finish_non_exhaustive()
    }
}

/// Sorts every record set into the projection's canonical order.
fn normalize(mut snapshot: TaskStateSnapshot) -> BrainResult<TaskStateSnapshot> {
    for task in &snapshot.delegations {
        validate_delegation(task)?;
    }
    for run in &snapshot.runs {
        validate_run(run)?;
    }
    snapshot.delegations.sort_by(|left, right| {
        (left.created_at_ms, left.child.as_str()).cmp(&(right.created_at_ms, right.child.as_str()))
    });
    snapshot
        .runs
        .sort_by(|left, right| left.run_id.cmp(&right.run_id));
    for run in &mut snapshot.runs {
        run.blockers
            .sort_by(|left, right| left.approval_id.cmp(&right.approval_id));
    }
    Ok(snapshot)
}

fn validate_delegation(task: &DelegationTask) -> BrainResult<()> {
    for (name, value) in [
        ("child", task.child.as_str()),
        ("parent", task.parent.as_str()),
        ("parent run", task.parent_run.as_str()),
        ("child run", task.child_run.as_str()),
        ("project", task.project.as_str()),
    ] {
        if value.is_empty() {
            return Err(BrainError::InvalidRequest(format!(
                "task state snapshot delegation {} must not be empty",
                name
            )));
        }
    }
    if let Some(seat) = &task.parent_seat {
        if seat.is_empty() {
            return Err(BrainError::InvalidRequest(
                "task state snapshot delegation owner seat must be absent, not empty".to_owned(),
            ));
        }
    }
    Ok(())
}

fn validate_run(run: &WorkloadRun) -> BrainResult<()> {
    for (name, value) in [
        ("run id", run.run_id.as_str()),
        ("lane id", run.lane_id.as_str()),
        ("state", run.state.as_str()),
        ("updated at", run.updated_at.as_str()),
    ] {
        if value.is_empty() {
            return Err(BrainError::InvalidRequest(format!(
                "task state snapshot run {} must not be empty",
                name
            )));
        }
    }
    if let Some(seat) = &run.seat {
        if seat.is_empty() {
            return Err(BrainError::InvalidRequest(
                "task state snapshot run owner seat must be absent, not empty".to_owned(),
            ));
        }
    }
    if let Some(project) = &run.project {
        if project.is_empty() {
            return Err(BrainError::InvalidRequest(
                "task state snapshot run project must be absent, not empty".to_owned(),
            ));
        }
    }
    for blocker in &run.blockers {
        for (name, value) in [
            ("approval id", blocker.approval_id.as_str()),
            ("capability id", blocker.capability_id.as_str()),
            ("requested at", blocker.requested_at.as_str()),
        ] {
            if value.is_empty() {
                return Err(BrainError::InvalidRequest(format!(
                    "task state snapshot run {} blocker {} must not be empty",
                    run.run_id, name
                )));
            }
        }
    }
    Ok(())
}

/// Digests every projected item's key and text in projection order.
fn head_digest(projected: &[(String, String)]) -> Digest {
    let mut material = HEAD_DOMAIN.to_vec();
    for (key, text) in projected {
        for part in [key, text] {
            material.extend_from_slice(&(part.len() as u64).to_be_bytes());
            material.extend_from_slice(part.as_bytes());
        }
    }
    Digest::hash(&material)
}

/// Projects every delegation and run into one `(key, text)` each, in fixed
/// kind order (delegations first, then runs) and canonical order within each.
fn project(snapshot: &TaskStateSnapshot) -> Vec<(String, String)> {
    let mut projected = Vec::with_capacity(snapshot.delegations.len() + snapshot.runs.len() + 1);
    for task in &snapshot.delegations {
        projected.push((format!("delegation/{}", task.child), delegation_text(task)));
    }
    if let Some(text) = lane_stall_text(&snapshot.delegations) {
        projected.push(("lanes/stall-rates".to_owned(), text));
    }
    for run in &snapshot.runs {
        projected.push((format!("run/{}", run.run_id), run_text(run)));
    }
    projected
}

/// The exact delegation summary: owner seat, project, status, last progress,
/// and the parent→child lineage. Absent fields are stated, never invented.
fn delegation_text(task: &DelegationTask) -> String {
    let lines = [
        format!("delegated task {}", task.child),
        match &task.parent_seat {
            Some(seat) => format!("owner seat: {seat}"),
            None => "owner seat: unknown (row predates durable seat attribution)".to_owned(),
        },
        format!("project: {}", task.project),
        format!("status: {}", task.phase.as_str()),
        match task.result_sequence {
            Some(sequence) => {
                format!("progress: typed result durably observed at child event {sequence}")
            }
            None => "progress: no typed result observed".to_owned(),
        },
        match &task.child_state {
            Some(state) => format!("child session: {state}"),
            None => "child session: not observed in the current read model".to_owned(),
        },
        match task.lanes.as_slice() {
            [] => "model lane: not recorded".to_owned(),
            [lane] => format!("model lane: {lane}"),
            [launch, rest @ ..] => format!(
                "model lane: {} (switched from {launch} after repeated stalls)",
                rest.join(", ")
            ),
        },
        if task.stalls.is_empty() {
            "stalls: none".to_owned()
        } else {
            format!(
                "stalls: {} (on {})",
                task.stalls.len(),
                task.stalls.join(", ")
            )
        },
        "blockers: not recorded by the delegation authority".to_owned(),
        format!(
            "lineage: {} (run {}) delegated worker {} (run {}) at depth {}",
            task.parent, task.parent_run, task.child, task.child_run, task.depth,
        ),
    ];
    lines.join("\n")
}

/// Worker model-lane stall rates over every delegation the snapshot holds:
/// per lane, the workers that ran on it, how many of them stalled there, and
/// the stalls. `None` before any worker records a
/// lane.
fn lane_stall_text(delegations: &[DelegationTask]) -> Option<String> {
    let mut rates: std::collections::BTreeMap<&str, (u32, u32, u32)> =
        std::collections::BTreeMap::new();
    for task in delegations {
        for lane in &task.lanes {
            let stalls = task.stalls.iter().filter(|stall| *stall == lane).count();
            let rate = rates.entry(lane.as_str()).or_default();
            rate.0 += 1;
            rate.1 += u32::from(stalls > 0);
            rate.2 += u32::try_from(stalls).unwrap_or(u32::MAX);
        }
    }
    if rates.is_empty() {
        return None;
    }
    let mut lines = vec![
        "worker model-lane stall rates (delegated workers; a stall is a model call that went \
         silent and was cancelled)"
            .to_owned(),
    ];
    for (lane, (workers, stalled, stalls)) in rates {
        lines.push(format!(
            "{lane}: {stalls} stalls over {workers} workers; {stalled} of them stalled"
        ));
    }
    Some(lines.join("\n"))
}

/// The exact run summary: owner seat, project, status, last progress, pending
/// approval blockers, and the lane lineage.
fn run_text(run: &WorkloadRun) -> String {
    let mut lines = vec![
        format!("workload run {}", run.run_id),
        match &run.seat {
            Some(seat) => format!("owner seat: {seat}"),
            None => "owner seat: unknown (lane records no seat)".to_owned(),
        },
        match &run.project {
            Some(project) => format!("project: {project}"),
            None => "project: none (lane not project-bound)".to_owned(),
        },
        format!("status: {}", run.state),
        match &run.started_at {
            Some(started_at) => format!("started: {started_at}"),
            None => "started: not recorded".to_owned(),
        },
        format!("updated: {}", run.updated_at),
        match &run.ended_at {
            Some(ended_at) => format!("ended: {ended_at}"),
            None => "ended: not recorded".to_owned(),
        },
    ];
    if run.blockers.is_empty() {
        lines.push("pending approvals: none; other blockers: not recorded".to_owned());
    } else {
        lines.push(format!(
            "blockers: {} pending approval(s):",
            run.blockers.len()
        ));
        for blocker in &run.blockers {
            lines.push(format!(
                "  {} ({}, requested {})",
                blocker.approval_id, blocker.capability_id, blocker.requested_at,
            ));
        }
    }
    lines.push(format!(
        "lineage: lane {}, attempt {}",
        run.lane_id, run.attempt_number,
    ));
    lines.join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn atlas_id() -> AtlasId {
        AtlasId::new("tasks:test").expect("atlas id")
    }

    fn delegation() -> DelegationTask {
        DelegationTask {
            child: "ses:live:child-1".to_owned(),
            parent: "ses:root-1".to_owned(),
            parent_seat: Some("skald".to_owned()),
            parent_run: "run:live:root-1".to_owned(),
            child_run: "run:live:child-1".to_owned(),
            project: "odin".to_owned(),
            phase: DelegationPhase::Running,
            depth: 1,
            created_at_ms: 1_000,
            result_sequence: None,
            child_state: Some("running".to_owned()),
            lanes: Vec::new(),
            stalls: Vec::new(),
        }
    }

    fn blocker(approval_id: &str) -> PendingBlocker {
        PendingBlocker {
            approval_id: approval_id.to_owned(),
            capability_id: "seat.ask.kubert".to_owned(),
            requested_at: "2026-09-28T00:01:00Z".to_owned(),
        }
    }

    fn run(run_id: &str) -> WorkloadRun {
        WorkloadRun {
            run_id: run_id.to_owned(),
            lane_id: "lane:1".to_owned(),
            seat: Some("kubert".to_owned()),
            project: Some("odin".to_owned()),
            state: "running".to_owned(),
            attempt_number: 1,
            started_at: Some("2026-09-28T00:00:30Z".to_owned()),
            updated_at: "2026-09-28T00:02:00Z".to_owned(),
            ended_at: None,
            blockers: Vec::new(),
        }
    }

    fn snapshot(delegations: Vec<DelegationTask>, runs: Vec<WorkloadRun>) -> TaskStateSnapshot {
        TaskStateSnapshot { delegations, runs }
    }

    struct FixedReader {
        snapshot: std::sync::Mutex<TaskStateSnapshot>,
    }

    impl TaskStateReader for FixedReader {
        fn snapshot(&self) -> BrainResult<TaskStateSnapshot> {
            Ok(self.snapshot.lock().expect("snapshot").clone())
        }
    }

    struct FailingReader;

    impl TaskStateReader for FailingReader {
        fn snapshot(&self) -> BrainResult<TaskStateSnapshot> {
            Err(BrainError::Unavailable {
                component: "task-state adapter",
                reason: "link ledger unreachable".to_owned(),
            })
        }
    }

    fn source<T: TaskStateReader + 'static>(reader: Arc<T>) -> TasksSource {
        TasksSource::new(atlas_id(), reader)
    }

    #[test]
    fn delegation_progress_reports_the_durable_result_sequence() {
        let observed = DelegationTask {
            result_sequence: Some(42),
            ..delegation()
        };
        let (_, items) = source(Arc::new(FixedReader {
            snapshot: std::sync::Mutex::new(snapshot(vec![observed], vec![])),
        }))
        .pin()
        .expect("pin");
        assert!(
            items[0]
                .text
                .contains("progress: typed result durably observed at child event 42"),
            "result sequence must be reported exactly: {}",
            items[0].text
        );
        assert!(
            items[0].text.contains("child session: running"),
            "child session join must be exact: {}",
            items[0].text
        );
    }

    #[test]
    fn head_moves_with_projected_text_only() {
        let head_of = |delegation: DelegationTask, run: WorkloadRun| {
            source(Arc::new(FixedReader {
                snapshot: std::sync::Mutex::new(snapshot(vec![delegation], vec![run])),
            }))
            .pin()
            .expect("pin")
            .0
        };
        let baseline = head_of(delegation(), run("run:live:1"));
        assert_eq!(head_of(delegation(), run("run:live:1")), baseline);
        let ended = DelegationTask {
            phase: DelegationPhase::Ended,
            ..delegation()
        };
        assert_ne!(head_of(ended, run("run:live:1")), baseline);
        let blocked = WorkloadRun {
            blockers: vec![blocker("approval:a")],
            ..run("run:live:1")
        };
        assert_ne!(head_of(delegation(), blocked), baseline);
    }

    #[test]
    fn projection_is_deterministic_and_follows_authority() {
        let reader = Arc::new(FixedReader {
            snapshot: std::sync::Mutex::new(snapshot(vec![delegation()], vec![run("run:live:1")])),
        });
        let first = source(Arc::clone(&reader)).pin().expect("pin");
        let second = source(Arc::clone(&reader)).pin().expect("pin");
        assert_eq!(first, second, "re-pinning an unchanged authority is exact");

        {
            let mut guard = reader.snapshot.lock().expect("snapshot");
            guard.delegations[0].phase = DelegationPhase::Failed;
        }
        let third = source(Arc::clone(&reader)).pin().expect("pin");
        assert_ne!(third.0, first.0, "the head follows the authority change");
        assert!(
            third.1[0].text.contains("status: failed"),
            "the projection follows the authority change: {}",
            third.1[0].text
        );
        assert_eq!(third.1[0].source_revision, third.0);
    }

    #[test]
    fn unsorted_input_is_normalized_without_changing_the_head() {
        let late = DelegationTask {
            child: "ses:live:child-2".to_owned(),
            created_at_ms: 2_000,
            ..delegation()
        };
        let shuffled = snapshot(
            vec![late.clone(), delegation()],
            vec![run("run:live:2"), run("run:live:1")],
        );
        let ordered = snapshot(
            vec![delegation(), late],
            vec![run("run:live:1"), run("run:live:2")],
        );
        assert_ne!(shuffled.delegations, ordered.delegations);

        let (head, items) = source(Arc::new(FixedReader {
            snapshot: std::sync::Mutex::new(shuffled),
        }))
        .pin()
        .expect("pin");
        let (ordered_head, ordered_items) = source(Arc::new(FixedReader {
            snapshot: std::sync::Mutex::new(ordered),
        }))
        .pin()
        .expect("pin");
        assert_eq!(head, ordered_head, "delivery order must not move the head");
        assert_eq!(
            items, ordered_items,
            "delivery order must not change projected items"
        );
    }

    #[test]
    fn reader_failure_fails_closed_with_no_items() {
        let error = source(Arc::new(FailingReader))
            .pin()
            .expect_err("an unavailable authority must fail the pin");
        assert!(
            error.to_string().contains("task-state adapter"),
            "the adapter failure must surface verbatim: {error}"
        );
    }

    #[test]
    fn empty_identity_fields_fail_closed() {
        let anonymous = DelegationTask {
            child: String::new(),
            ..delegation()
        };
        let error = TasksSource::new(
            atlas_id(),
            Arc::new(FixedReader {
                snapshot: std::sync::Mutex::new(snapshot(vec![anonymous], vec![])),
            }),
        )
        .pin()
        .expect_err("an empty child identity must fail closed");
        assert!(
            error.to_string().contains("child"),
            "the refused field must be named: {error}"
        );

        let unblocked = WorkloadRun {
            blockers: vec![PendingBlocker {
                approval_id: String::new(),
                ..blocker("approval:x")
            }],
            ..run("run:live:3")
        };
        let error = TasksSource::new(
            atlas_id(),
            Arc::new(FixedReader {
                snapshot: std::sync::Mutex::new(snapshot(vec![], vec![unblocked])),
            }),
        )
        .pin()
        .expect_err("an empty blocker identity must fail closed");
        assert!(
            error.to_string().contains("blocker"),
            "the refused blocker field must be named: {error}"
        );
    }
}
