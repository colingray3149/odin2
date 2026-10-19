//! Worker persistence uses the caller's immediate transaction and guards phase changes.
//! Nonterminal rows remain recoverable and block correlation reuse; terminal rows are immutable.
//! The manager confirms InvocationID before payload release.

use odin_domain::worker::{can_transition_worker, WorkerPhase};
use rusqlite::{params, Connection, OptionalExtension, Transaction};
use time::OffsetDateTime;

use crate::{encode_utc, LedgerError, LedgerResult};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkerRow {
    pub worker_id: String,
    pub unit: String,
    pub invocation_id: Option<String>,
    pub correlation_id: String,
    pub tx_id: String,
    pub wp_id: String,
    pub attempt: u32,
    pub cgroup_path: Option<String>,
    pub cgroup_inode: Option<u64>,
    pub leader_pid: Option<u32>,
    pub leader_start_ticks: Option<u64>,
    pub phase: WorkerPhase,
    pub residue_json: String,
    pub created_at: String,
    pub updated_at: String,
}

/// Callers validate identifiers; the store checks structural invariants.
#[derive(Clone, Debug)]
pub struct NewWorker<'a> {
    pub worker_id: &'a str,
    pub unit: &'a str,
    pub correlation_id: &'a str,
    pub tx_id: &'a str,
    pub wp_id: &'a str,
    pub attempt: u32,
    pub now: OffsetDateTime,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RegisterOutcome {
    Inserted,
    /// The exact same intent was already recorded; the row is replayed.
    Replay {
        row: Box<WorkerRow>,
    },
}

/// Scope identity confirmed by the user manager before payload release.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ScopeProof<'a> {
    pub invocation_id: &'a str,
    pub cgroup_path: &'a str,
    pub cgroup_inode: u64,
    pub leader_pid: u32,
    pub leader_start_ticks: u64,
}

/// Terminal settlements. `Residual` carries the supplemental `/proc`
/// correlation evidence that describes what survived.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Settlement {
    Stopped,
    Failed,
    Residual,
}

impl Settlement {
    fn phase(self) -> WorkerPhase {
        match self {
            Self::Stopped => WorkerPhase::Stopped,
            Self::Failed => WorkerPhase::Failed,
            Self::Residual => WorkerPhase::Residual,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WorkerTransitionOutcome {
    Applied,
    Replay,
}

const WORKER_COLUMNS: &str = "worker_id, unit, invocation_id, correlation_id, tx_id, wp_id, \
     attempt, cgroup_path, cgroup_inode, leader_pid, leader_start_ticks, state, \
     residue_json, created_at, updated_at";

fn read_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<WorkerRow> {
    let state: String = row.get(11)?;
    let phase = WorkerPhase::parse(&state).ok_or_else(|| {
        rusqlite::Error::FromSqlConversionFailure(
            11,
            rusqlite::types::Type::Text,
            LedgerError::invalid_data(format!("unknown worker phase {state:?}")).into(),
        )
    })?;
    Ok(WorkerRow {
        worker_id: row.get(0)?,
        unit: row.get(1)?,
        invocation_id: row.get(2)?,
        correlation_id: row.get(3)?,
        tx_id: row.get(4)?,
        wp_id: row.get(5)?,
        attempt: row.get(6)?,
        cgroup_path: row.get(7)?,
        cgroup_inode: row.get(8)?,
        leader_pid: row.get(9)?,
        leader_start_ticks: row.get(10)?,
        phase,
        residue_json: row.get(12)?,
        created_at: row.get(13)?,
        updated_at: row.get(14)?,
    })
}

fn query_row(conn: &Connection, worker_id: &str) -> LedgerResult<Option<WorkerRow>> {
    let mut statement = conn.prepare_cached(&format!(
        "SELECT {WORKER_COLUMNS} FROM worker_registry WHERE worker_id = ?1"
    ))?;
    statement
        .query_row([worker_id], read_row)
        .optional()
        .map_err(LedgerError::from)
}

/// Idempotently records a fresh worker intent. A duplicate worker id replays
/// the recorded row only when every immutable binding matches; any difference
/// is a hard conflict. The unit name is unique across the registry, so a
/// second worker can never silently adopt another worker's scope.
#[doc(hidden)]
pub fn register_worker(tx: &Transaction<'_>, new: &NewWorker<'_>) -> LedgerResult<RegisterOutcome> {
    if new.worker_id.is_empty() {
        return Err(LedgerError::invalid_data(
            "worker id must not be empty".to_owned(),
        ));
    }
    if new.unit.is_empty() {
        return Err(LedgerError::invalid_data(
            "worker unit must not be empty".to_owned(),
        ));
    }
    if new.correlation_id.is_empty() {
        return Err(LedgerError::invalid_data(
            "worker correlation id must not be empty".to_owned(),
        ));
    }
    let updated_at = encode_utc(new.now)?;
    let inserted = tx.execute(
        "INSERT INTO worker_registry (worker_id, unit, invocation_id, correlation_id, \
         tx_id, wp_id, attempt, cgroup_path, cgroup_inode, leader_pid, leader_start_ticks, \
         state, residue_json, created_at, updated_at) \
         VALUES (?1, ?2, NULL, ?3, ?4, ?5, ?6, NULL, NULL, NULL, NULL, 'registered', '{}', ?7, ?7) \
         ON CONFLICT(worker_id) DO NOTHING",
        params![
            new.worker_id,
            new.unit,
            new.correlation_id,
            new.tx_id,
            new.wp_id,
            new.attempt,
            updated_at,
        ],
    )?;
    if inserted == 1 {
        return Ok(RegisterOutcome::Inserted);
    }
    let row = query_row(tx, new.worker_id)?.ok_or_else(|| {
        LedgerError::invalid_data(
            "worker registration reported no insert but the row is missing".to_owned(),
        )
    })?;
    let identical = row.unit == new.unit
        && row.correlation_id == new.correlation_id
        && row.tx_id == new.tx_id
        && row.wp_id == new.wp_id
        && row.attempt == new.attempt;
    if identical {
        Ok(RegisterOutcome::Replay { row: Box::new(row) })
    } else {
        Err(LedgerError::Conflict(format!(
            "worker id {} already names a different worker intent",
            new.worker_id
        )))
    }
}

pub fn worker_row(conn: &Connection, worker_id: &str) -> LedgerResult<Option<WorkerRow>> {
    query_row(conn, worker_id)
}

/// Recovers by InvocationID because unit names and PIDs can be reused.
pub fn worker_by_invocation(
    conn: &Connection,
    invocation_id: &str,
) -> LedgerResult<Option<WorkerRow>> {
    let mut statement = conn.prepare_cached(&format!(
        "SELECT {WORKER_COLUMNS} FROM worker_registry WHERE invocation_id = ?1"
    ))?;
    statement
        .query_row([invocation_id], read_row)
        .optional()
        .map_err(LedgerError::from)
}

/// Records scope identity and advances registered to scope_created; identical replays
/// succeed and conflicting identity or phase fails.
#[doc(hidden)]
pub fn record_scope_proof(
    tx: &Transaction<'_>,
    worker_id: &str,
    proof: &ScopeProof<'_>,
    now: OffsetDateTime,
) -> LedgerResult<WorkerTransitionOutcome> {
    let updated = tx.execute(
        "UPDATE worker_registry SET invocation_id = ?1, cgroup_path = ?2, \
         cgroup_inode = ?3, leader_pid = ?4, leader_start_ticks = ?5, \
         state = 'scope_created', updated_at = ?6 \
         WHERE worker_id = ?7 AND state = 'registered'",
        params![
            proof.invocation_id,
            proof.cgroup_path,
            proof.cgroup_inode,
            proof.leader_pid,
            proof.leader_start_ticks,
            encode_utc(now)?,
            worker_id,
        ],
    )?;
    if updated == 1 {
        return Ok(WorkerTransitionOutcome::Applied);
    }
    let row = query_row(tx, worker_id)?.ok_or_else(|| LedgerError::NotFound {
        kind: "worker",
        id: worker_id.to_owned(),
    })?;
    let replay = row.phase == WorkerPhase::ScopeCreated
        && row.invocation_id.as_deref() == Some(proof.invocation_id)
        && row.cgroup_path.as_deref() == Some(proof.cgroup_path)
        && row.cgroup_inode == Some(proof.cgroup_inode)
        && row.leader_pid == Some(proof.leader_pid)
        && row.leader_start_ticks == Some(proof.leader_start_ticks);
    if replay {
        return Ok(WorkerTransitionOutcome::Replay);
    }
    Err(invalid_transition(row.phase, "scope proof"))
}

/// Records payload release; repeated calls leave the phase unchanged.
#[doc(hidden)]
pub fn mark_payload_running(
    tx: &Transaction<'_>,
    worker_id: &str,
    now: OffsetDateTime,
) -> LedgerResult<WorkerTransitionOutcome> {
    transition(
        tx,
        worker_id,
        WorkerPhase::ScopeCreated,
        WorkerPhase::PayloadRunning,
        None,
        now,
    )
}

/// Settles a worker into a terminal phase with residue evidence. The
/// `from` phase is the exact phase the caller decided against; a stale
/// authority that lost a race fails with the actual phase.
#[doc(hidden)]
pub fn settle_worker(
    tx: &Transaction<'_>,
    worker_id: &str,
    from: WorkerPhase,
    settlement: Settlement,
    residue_json: &str,
    now: OffsetDateTime,
) -> LedgerResult<WorkerTransitionOutcome> {
    if settlement == Settlement::Residual {
        validate_residue(residue_json)?;
    }
    transition(
        tx,
        worker_id,
        from,
        settlement.phase(),
        Some(residue_json),
        now,
    )
}

fn transition(
    tx: &Transaction<'_>,
    worker_id: &str,
    from: WorkerPhase,
    to: WorkerPhase,
    residue_json: Option<&str>,
    now: OffsetDateTime,
) -> LedgerResult<WorkerTransitionOutcome> {
    if !can_transition_worker(from, to) {
        return Err(invalid_transition(from, "transition"));
    }
    let updated = tx.execute(
        "UPDATE worker_registry SET state = ?1, \
         residue_json = COALESCE(?2, residue_json), updated_at = ?3 \
         WHERE worker_id = ?4 AND state = ?5",
        params![
            to.as_str(),
            residue_json,
            encode_utc(now)?,
            worker_id,
            from.as_str(),
        ],
    )?;
    if updated == 1 {
        return Ok(WorkerTransitionOutcome::Applied);
    }
    let row = query_row(tx, worker_id)?.ok_or_else(|| LedgerError::NotFound {
        kind: "worker",
        id: worker_id.to_owned(),
    })?;
    if row.phase == to {
        return Ok(WorkerTransitionOutcome::Replay);
    }
    Err(invalid_transition(row.phase, "transition"))
}

/// All workers in a nonterminal phase, optionally scoped to one capsule-side
/// correlation. Nonterminal rows are the durable recovery queue.
pub fn nonterminal_rows(
    conn: &Connection,
    correlation_id: Option<&str>,
) -> LedgerResult<Vec<WorkerRow>> {
    let mut statement = conn.prepare(&format!(
        "SELECT {WORKER_COLUMNS} FROM worker_registry \
         WHERE state IN ('registered', 'scope_created', 'payload_running') \
         AND (?1 IS NULL OR correlation_id = ?1) ORDER BY created_at, worker_id"
    ))?;
    let rows = statement
        .query_map([correlation_id], read_row)?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(rows)
}

/// Every worker still carrying residual evidence, with the residue payload
/// decoded. A residual row always names what survived.
pub fn residual_rows(conn: &Connection) -> LedgerResult<Vec<(WorkerRow, serde_json::Value)>> {
    let mut statement = conn.prepare_cached(&format!(
        "SELECT {WORKER_COLUMNS} FROM worker_registry \
         WHERE state = 'residual' ORDER BY created_at, worker_id"
    ))?;
    let rows = statement
        .query_map([], read_row)?
        .collect::<Result<Vec<_>, _>>()?;
    rows.into_iter()
        .map(|row| {
            let residue = validate_residue(&row.residue_json)?;
            Ok((row, residue))
        })
        .collect()
}

fn validate_residue(raw: &str) -> LedgerResult<serde_json::Value> {
    let value: serde_json::Value = serde_json::from_str(raw).map_err(|error| {
        LedgerError::invalid_data_caused_by("worker residue evidence is invalid JSON", error)
    })?;
    if !value.as_object().is_some_and(|object| !object.is_empty()) {
        return Err(LedgerError::invalid_data(
            "worker residue evidence must be a nonempty JSON object".to_owned(),
        ));
    }
    Ok(value)
}

fn invalid_transition(phase: WorkerPhase, action: &'static str) -> LedgerError {
    LedgerError::Conflict(format!(
        "worker in phase {} cannot accept {action}",
        phase.as_str()
    ))
}

// Job workers use observed cluster/namespace/name/UID, never a systemd unit, PID, or cgroup.

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JobWorkerRow {
    pub worker_id: String,
    pub backend: String,
    pub cluster: String,
    pub namespace: String,
    pub job_name: String,
    pub job_uid: String,
    pub correlation_id: String,
    pub operation_id: String,
    pub phase: JobWorkerPhase,
    pub residue_json: String,
    pub created_at: String,
    pub updated_at: String,
}

/// Lifecycle phases of a Job worker. `registered` proves only the durable
/// intent recorded by the authority: a Job created suspended may not execute
/// until the authority releases it, and `released` proves that release. A
/// stopping row is awaiting terminal settlement; terminal phases never move.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum JobWorkerPhase {
    Registered,
    Released,
    Stopping,
    Stopped,
    Failed,
    Residual,
}

impl JobWorkerPhase {
    pub fn parse(raw: &str) -> Option<Self> {
        match raw {
            "registered" => Some(Self::Registered),
            "released" => Some(Self::Released),
            "stopping" => Some(Self::Stopping),
            "stopped" => Some(Self::Stopped),
            "failed" => Some(Self::Failed),
            "residual" => Some(Self::Residual),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Registered => "registered",
            Self::Released => "released",
            Self::Stopping => "stopping",
            Self::Stopped => "stopped",
            Self::Failed => "failed",
            Self::Residual => "residual",
        }
    }

    pub fn is_terminal(self) -> bool {
        matches!(self, Self::Stopped | Self::Failed | Self::Residual)
    }
}

fn can_transition_job_worker(from: JobWorkerPhase, to: JobWorkerPhase) -> bool {
    if from.is_terminal() {
        return false;
    }
    match to {
        JobWorkerPhase::Released => from == JobWorkerPhase::Registered,
        JobWorkerPhase::Stopping => {
            matches!(from, JobWorkerPhase::Registered | JobWorkerPhase::Released)
        }
        JobWorkerPhase::Stopped | JobWorkerPhase::Failed | JobWorkerPhase::Residual => true,
        JobWorkerPhase::Registered => false,
    }
}

/// A fresh transaction-qualified Job worker intent. The identifier strings
/// must already be validated by the authority; the store re-checks only
/// shape-independent invariants.
#[derive(Clone, Debug)]
pub struct NewJobWorker<'a> {
    pub worker_id: &'a str,
    pub cluster: &'a str,
    pub namespace: &'a str,
    pub job_name: &'a str,
    pub job_uid: &'a str,
    pub correlation_id: &'a str,
    pub operation_id: &'a str,
    pub now: OffsetDateTime,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum JobRegisterOutcome {
    Inserted,
    /// The exact same intent was already recorded; the row is replayed.
    Replay {
        row: Box<JobWorkerRow>,
    },
}

const JOB_WORKER_COLUMNS: &str = "worker_id, backend, cluster, namespace, job_name, job_uid, \
     correlation_id, operation_id, state, residue_json, created_at, updated_at";

fn read_job_worker_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<JobWorkerRow> {
    let backend: String = row.get(1)?;
    let state_raw: String = row.get(8)?;
    let phase = JobWorkerPhase::parse(&state_raw).ok_or_else(|| {
        rusqlite::Error::FromSqlConversionFailure(
            8,
            rusqlite::types::Type::Text,
            LedgerError::invalid_data(format!("unknown job worker phase {state_raw:?}")).into(),
        )
    })?;
    Ok(JobWorkerRow {
        worker_id: row.get(0)?,
        backend,
        cluster: row.get(2)?,
        namespace: row.get(3)?,
        job_name: row.get(4)?,
        job_uid: row.get(5)?,
        correlation_id: row.get(6)?,
        operation_id: row.get(7)?,
        phase,
        residue_json: row.get(9)?,
        created_at: row.get(10)?,
        updated_at: row.get(11)?,
    })
}

fn query_job_worker_row(conn: &Connection, worker_id: &str) -> LedgerResult<Option<JobWorkerRow>> {
    let mut statement = conn.prepare_cached(&format!(
        "SELECT {JOB_WORKER_COLUMNS} FROM job_worker_registry WHERE worker_id = ?1"
    ))?;
    statement
        .query_row([worker_id], read_job_worker_row)
        .optional()
        .map_err(LedgerError::from)
}

/// Registers a Job worker idempotently; replay requires identical fields.
/// A reused Job UID requires every earlier worker to be stopped; failed and residual rows block reuse.
/// Kubernetes UIDs are opaque: validation checks bounded nonemptiness, not their layout.
#[doc(hidden)]
pub fn register_job_worker(
    tx: &Transaction<'_>,
    new: &NewJobWorker<'_>,
) -> LedgerResult<JobRegisterOutcome> {
    for (value, name) in [
        (new.worker_id, "worker id"),
        (new.cluster, "cluster"),
        (new.namespace, "namespace"),
        (new.job_name, "job name"),
        (new.job_uid, "job uid"),
        (new.correlation_id, "correlation id"),
        (new.operation_id, "operation id"),
    ] {
        if value.is_empty() {
            return Err(LedgerError::invalid_data(format!(
                "job worker {name} must not be empty"
            )));
        }
        if name == "job uid" && value.len() > 128 {
            return Err(LedgerError::invalid_data(
                "job worker job uid must stay within 128 characters".to_owned(),
            ));
        }
    }
    let holder = tx
        .query_row(
            "SELECT worker_id FROM job_worker_registry \
             WHERE cluster = ?1 AND namespace = ?2 AND job_name = ?3 AND job_uid = ?4 \
             AND state <> 'stopped'",
            params![new.cluster, new.namespace, new.job_name, new.job_uid],
            |row| row.get::<_, String>(0),
        )
        .optional()?;
    if holder.as_deref().is_some_and(|held| held != new.worker_id) {
        return Err(LedgerError::Conflict(format!(
            "job {}/{}/{} already backs an unproved worker {}",
            new.cluster,
            new.namespace,
            new.job_name,
            holder.unwrap()
        )));
    }
    let updated_at = encode_utc(new.now)?;
    let inserted = tx.execute(
        "INSERT INTO job_worker_registry (worker_id, backend, cluster, namespace, \
         job_name, job_uid, correlation_id, operation_id, state, \
         residue_json, created_at, updated_at) \
         VALUES (?1, 'kube.job', ?2, ?3, ?4, ?5, ?6, ?7, 'registered', '{}', ?8, ?8) \
         ON CONFLICT(worker_id) DO NOTHING",
        params![
            new.worker_id,
            new.cluster,
            new.namespace,
            new.job_name,
            new.job_uid,
            new.correlation_id,
            new.operation_id,
            updated_at,
        ],
    )?;
    if inserted == 1 {
        return Ok(JobRegisterOutcome::Inserted);
    }
    let row = query_job_worker_row(tx, new.worker_id)?.ok_or_else(|| {
        LedgerError::invalid_data(
            "job worker registration reported no insert but the row is missing".to_owned(),
        )
    })?;
    let identical = row.cluster == new.cluster
        && row.namespace == new.namespace
        && row.job_name == new.job_name
        && row.job_uid == new.job_uid
        && row.correlation_id == new.correlation_id
        && row.operation_id == new.operation_id;
    if identical {
        Ok(JobRegisterOutcome::Replay { row: Box::new(row) })
    } else {
        Err(LedgerError::Conflict(format!(
            "worker id {} already names a different job worker intent",
            new.worker_id
        )))
    }
}

pub fn job_worker_row(conn: &Connection, worker_id: &str) -> LedgerResult<Option<JobWorkerRow>> {
    query_job_worker_row(conn, worker_id)
}

/// All Job workers in a nonterminal phase, optionally scoped to one exact
/// correlation. Nonterminal rows are the durable Job recovery queue; the
/// kernel StopAuthority reconciles them through the registered backend.
pub fn nonterminal_job_rows(
    conn: &Connection,
    correlation_id: Option<&str>,
) -> LedgerResult<Vec<JobWorkerRow>> {
    let mut statement = conn.prepare(&format!(
        "SELECT {JOB_WORKER_COLUMNS} FROM job_worker_registry \
         WHERE state IN ('registered', 'released', 'stopping') \
         AND (?1 IS NULL OR correlation_id = ?1) ORDER BY created_at, worker_id"
    ))?;
    let rows = statement
        .query_map([correlation_id], read_job_worker_row)?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(rows)
}

/// Every Job worker still carrying residual evidence, with the residue
/// payload decoded. A residual row always names the pods that survived.
pub fn residual_job_rows(
    conn: &Connection,
) -> LedgerResult<Vec<(JobWorkerRow, serde_json::Value)>> {
    let mut statement = conn.prepare(&format!(
        "SELECT {JOB_WORKER_COLUMNS} FROM job_worker_registry \
         WHERE state = 'residual' ORDER BY created_at, worker_id"
    ))?;
    let rows = statement
        .query_map([], read_job_worker_row)?
        .collect::<Result<Vec<_>, _>>()?;
    rows.into_iter()
        .map(|row| {
            let residue = validate_residue(&row.residue_json)?;
            Ok((row, residue))
        })
        .collect()
}

fn job_transition(
    tx: &Transaction<'_>,
    worker_id: &str,
    from: JobWorkerPhase,
    to: JobWorkerPhase,
    residue_json: Option<&str>,
    now: OffsetDateTime,
) -> LedgerResult<WorkerTransitionOutcome> {
    if !can_transition_job_worker(from, to) {
        return Err(LedgerError::Conflict(format!(
            "job worker in phase {} cannot transition to {}",
            from.as_str(),
            to.as_str()
        )));
    }
    let updated = tx.execute(
        "UPDATE job_worker_registry SET state = ?1, \
         residue_json = COALESCE(?2, residue_json), updated_at = ?3 \
         WHERE worker_id = ?4 AND state = ?5",
        params![
            to.as_str(),
            residue_json,
            encode_utc(now)?,
            worker_id,
            from.as_str(),
        ],
    )?;
    if updated == 1 {
        return Ok(WorkerTransitionOutcome::Applied);
    }
    let row = query_job_worker_row(tx, worker_id)?.ok_or_else(|| LedgerError::NotFound {
        kind: "job worker",
        id: worker_id.to_owned(),
    })?;
    if row.phase == to {
        return Ok(WorkerTransitionOutcome::Replay);
    }
    Err(LedgerError::Conflict(format!(
        "job worker in phase {} cannot transition to {}",
        row.phase.as_str(),
        to.as_str()
    )))
}

/// Marks a durably registered suspended Job as released by the authority:
/// the payload may now run. Only `registered` rows move to `released`.
#[doc(hidden)]
pub fn mark_job_released(
    tx: &Transaction<'_>,
    worker_id: &str,
    now: OffsetDateTime,
) -> LedgerResult<WorkerTransitionOutcome> {
    job_transition(
        tx,
        worker_id,
        JobWorkerPhase::Registered,
        JobWorkerPhase::Released,
        None,
        now,
    )
}

/// Marks a Job worker as stopping under a journaled stop intent. Both
/// `registered` and `released` rows may stop; replay leaves the phase.
#[doc(hidden)]
pub fn mark_job_stopping(
    tx: &Transaction<'_>,
    worker_id: &str,
    from: JobWorkerPhase,
    now: OffsetDateTime,
) -> LedgerResult<WorkerTransitionOutcome> {
    job_transition(tx, worker_id, from, JobWorkerPhase::Stopping, None, now)
}

/// Settles a Job worker; residual settlements must identify surviving pods.
#[doc(hidden)]
pub fn settle_job_worker(
    tx: &Transaction<'_>,
    worker_id: &str,
    from: JobWorkerPhase,
    settlement: Settlement,
    residue_json: &str,
    now: OffsetDateTime,
) -> LedgerResult<WorkerTransitionOutcome> {
    if settlement == Settlement::Residual {
        validate_residue(residue_json)?;
    }
    let to = match settlement {
        Settlement::Stopped => JobWorkerPhase::Stopped,
        Settlement::Failed => JobWorkerPhase::Failed,
        Settlement::Residual => JobWorkerPhase::Residual,
    };
    job_transition(tx, worker_id, from, to, Some(residue_json), now)
}

/// Expected phase, terminal outcome, and residue for atomic Job settlement.
#[derive(Clone, Debug)]
pub struct JobWorkerSettlement<'a> {
    pub from: JobWorkerPhase,
    pub settlement: Settlement,
    pub residue_json: &'a str,
}

/// Settles the Job stop intent and the Job worker phase in one transaction:
/// stop evidence and worker state can never disagree. The caller supplies
/// its own immediate transaction.
#[doc(hidden)]
pub fn settle_job_stop_and_worker(
    tx: &Transaction<'_>,
    worker_id: &str,
    state: odin_domain::StopState,
    evidence_json: &str,
    worker: JobWorkerSettlement<'_>,
    now: OffsetDateTime,
) -> LedgerResult<(crate::stop::StopSettleOutcome, WorkerTransitionOutcome)> {
    let stop = crate::stop::settle_job_stop(tx, worker_id, state, evidence_json, now)?;
    let outcome = settle_job_worker(
        tx,
        worker_id,
        worker.from,
        worker.settlement,
        worker.residue_json,
        now,
    )?;
    Ok((stop, outcome))
}

#[cfg(test)]
mod tests;
