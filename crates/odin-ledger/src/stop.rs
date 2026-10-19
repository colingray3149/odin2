//! Durable worker-stop intent and evidence store.
//!
//! The kernel stop authority inserts a `requested` row before any process
//! actuation. Each indeterminate attempt replaces the pending evidence and
//! increments `attempts` without settling the row, so recovery retries it.
//! Confirmed clean teardown settles to `stopped`; detected residue settles to `failed`.
//! Writes require the pending state, and terminal rows never move.

use odin_domain::{
    can_transition_stop, StopAudit, StopMissing, StopState, StopTraceRow, StopVerdictTag,
    WORKER_STOP_EVIDENCE_SCHEMA,
};
use rusqlite::{params, Connection, OptionalExtension, Transaction};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::{encode_utc, LedgerError, LedgerResult};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StopRow {
    pub worker_id: String,
    pub correlation_id: String,
    pub state: StopState,
    pub evidence_json: String,
    pub attempts: u64,
    pub requested_at: String,
    pub updated_at: String,
    pub settled_at: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum StopIntentOutcome {
    /// The intent was made durable before any actuation.
    Inserted,
    /// The exact worker/correlation intent already exists.
    Replay { row: Box<StopRow> },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StopAttemptOutcome {
    Recorded,
    TerminalReplay,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StopSettleOutcome {
    Settled,
    Replay,
}

const STOP_COLUMNS: &str = "worker_id, correlation_id, state, evidence_json, attempts, \
     requested_at, updated_at, settled_at";

fn read_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<StopRow> {
    let state_raw: String = row.get(2)?;
    let state = StopState::parse(&state_raw).ok_or_else(|| {
        rusqlite::Error::FromSqlConversionFailure(
            2,
            rusqlite::types::Type::Text,
            LedgerError::invalid_data(format!("unknown worker stop state {state_raw:?}")).into(),
        )
    })?;
    let attempts: i64 = row.get(4)?;
    let attempts = u64::try_from(attempts).map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(
            4,
            rusqlite::types::Type::Integer,
            LedgerError::invalid_data_caused_by(
                format!("negative worker stop attempt count {attempts}"),
                error,
            )
            .into(),
        )
    })?;
    Ok(StopRow {
        worker_id: row.get(0)?,
        correlation_id: row.get(1)?,
        state,
        evidence_json: row.get(3)?,
        attempts,
        requested_at: row.get(5)?,
        updated_at: row.get(6)?,
        settled_at: row.get(7)?,
    })
}

fn query_row(conn: &Connection, worker_id: &str) -> LedgerResult<Option<StopRow>> {
    conn.query_row(
        &format!("SELECT {STOP_COLUMNS} FROM worker_stop_intent WHERE worker_id = ?1"),
        [worker_id],
        read_row,
    )
    .optional()
    .map_err(LedgerError::from)
}

/// Idempotently records a worker stop intent. The supplied evidence must be
/// the exact `Requested` record for the same logical worker and correlation.
/// A duplicate worker id replays only when the immutable binding matches;
/// otherwise it is a conflict.
#[doc(hidden)]
pub fn request_stop(
    tx: &Transaction<'_>,
    worker_id: &str,
    correlation_id: &str,
    evidence_json: &str,
    now: OffsetDateTime,
) -> LedgerResult<StopIntentOutcome> {
    validate_evidence(
        evidence_json,
        worker_id,
        correlation_id,
        StopVerdictTag::Requested,
    )?;
    let stamp = encode_utc(now)?;
    let inserted = tx.execute(
        "INSERT INTO worker_stop_intent (
             worker_id, correlation_id, state, evidence_json, attempts,
             requested_at, updated_at, settled_at
         ) VALUES (?1, ?2, 'requested', ?3, 0, ?4, ?4, NULL)
         ON CONFLICT(worker_id) DO NOTHING",
        params![worker_id, correlation_id, evidence_json, stamp],
    )?;
    if inserted == 1 {
        return Ok(StopIntentOutcome::Inserted);
    }
    let row = query_row(tx, worker_id)?.ok_or_else(|| {
        LedgerError::invalid_data(format!(
            "worker stop intent conflict for {worker_id} reported no durable row"
        ))
    })?;
    if row.correlation_id != correlation_id {
        return Err(LedgerError::Conflict(format!(
            "worker stop intent {worker_id} belongs to correlation {}, not {correlation_id}",
            row.correlation_id
        )));
    }
    validate_row(&row)?;
    Ok(StopIntentOutcome::Replay { row: Box::new(row) })
}

/// Records an indeterminate stop attempt and leaves the intent pending.
/// Missing evidence can never settle to success; durable recovery retries the
/// row. A concurrently terminal row is replayed without mutation.
#[doc(hidden)]
pub fn record_indeterminate(
    tx: &Transaction<'_>,
    worker_id: &str,
    evidence_json: &str,
    now: OffsetDateTime,
) -> LedgerResult<StopAttemptOutcome> {
    let row = query_row(tx, worker_id)?.ok_or_else(|| LedgerError::NotFound {
        kind: "worker stop intent",
        id: worker_id.to_owned(),
    })?;
    validate_evidence(
        evidence_json,
        worker_id,
        &row.correlation_id,
        StopVerdictTag::Indeterminate,
    )?;
    if row.state.is_terminal() {
        return Ok(StopAttemptOutcome::TerminalReplay);
    }
    let changed = tx.execute(
        "UPDATE worker_stop_intent
         SET evidence_json = ?2, attempts = attempts + 1, updated_at = ?3
         WHERE worker_id = ?1 AND state = 'requested'",
        params![worker_id, evidence_json, encode_utc(now)?],
    )?;
    if changed == 1 {
        Ok(StopAttemptOutcome::Recorded)
    } else {
        Ok(StopAttemptOutcome::TerminalReplay)
    }
}

/// Settles a pending worker stop to `stopped` or `failed` with exact evidence.
/// Terminal rows never move; an exact replay is returned, while a
/// contradictory terminal verdict is a conflict.
#[doc(hidden)]
pub fn settle_stop(
    tx: &Transaction<'_>,
    worker_id: &str,
    state: StopState,
    evidence_json: &str,
    now: OffsetDateTime,
) -> LedgerResult<StopSettleOutcome> {
    if !matches!(state, StopState::Stopped | StopState::Failed)
        || !can_transition_stop(StopState::Requested, state)
    {
        return Err(LedgerError::invalid_data(format!(
            "worker stop state {state} is not terminal"
        )));
    }
    let current = query_row(tx, worker_id)?.ok_or_else(|| LedgerError::NotFound {
        kind: "worker stop intent",
        id: worker_id.to_owned(),
    })?;
    let verdict = match state {
        StopState::Stopped => StopVerdictTag::Stopped,
        StopState::Failed => StopVerdictTag::Failed,
        StopState::Requested => unreachable!("validated terminal state"),
    };
    validate_evidence(evidence_json, worker_id, &current.correlation_id, verdict)?;
    if current.state.is_terminal() {
        if current.state == state && current.evidence_json == evidence_json {
            return Ok(StopSettleOutcome::Replay);
        }
        return Err(LedgerError::Conflict(format!(
            "worker stop {worker_id} already settled {} with different evidence",
            current.state
        )));
    }
    let stamp = encode_utc(now)?;
    let changed = tx.execute(
        "UPDATE worker_stop_intent
         SET state = ?2, evidence_json = ?3, attempts = attempts + 1,
             updated_at = ?4, settled_at = ?4
         WHERE worker_id = ?1 AND state = 'requested'",
        params![worker_id, state.as_str(), evidence_json, stamp],
    )?;
    if changed == 1 {
        Ok(StopSettleOutcome::Settled)
    } else {
        Ok(StopSettleOutcome::Replay)
    }
}

pub fn stop_row(conn: &Connection, worker_id: &str) -> LedgerResult<Option<StopRow>> {
    let row = query_row(conn, worker_id)?;
    if let Some(row) = &row {
        validate_row(row)?;
    }
    Ok(row)
}

/// Every pending stop intent, optionally restricted to one exact correlation.
/// These rows are the durable stop-recovery queue.
pub fn pending_stops(
    conn: &Connection,
    correlation_id: Option<&str>,
) -> LedgerResult<Vec<StopRow>> {
    let sql = match correlation_id {
        Some(_) => format!(
            "SELECT {STOP_COLUMNS} FROM worker_stop_intent
             WHERE state = 'requested' AND correlation_id = ?1 ORDER BY requested_at, worker_id"
        ),
        None => format!(
            "SELECT {STOP_COLUMNS} FROM worker_stop_intent
             WHERE state = 'requested' ORDER BY requested_at, worker_id"
        ),
    };
    let mut statement = conn.prepare(&sql)?;
    let rows = match correlation_id {
        Some(correlation_id) => statement.query_map([correlation_id], read_row)?,
        None => statement.query_map([], read_row)?,
    };
    let rows = rows.collect::<rusqlite::Result<Vec<_>>>()?;
    for row in &rows {
        validate_row(row)?;
    }
    Ok(rows)
}

fn validate_row(row: &StopRow) -> LedgerResult<()> {
    let audit: StopAudit = serde_json::from_str(&row.evidence_json)?;
    if audit.evidence.worker_id != row.worker_id {
        return Err(LedgerError::invalid_data(format!(
            "worker stop evidence for {} has a different immutable binding",
            row.worker_id
        )));
    }
    let valid = match row.state {
        StopState::Requested => matches!(
            audit.verdict,
            StopVerdictTag::Requested | StopVerdictTag::Indeterminate
        ),
        StopState::Stopped => audit.verdict == StopVerdictTag::Stopped,
        StopState::Failed => audit.verdict == StopVerdictTag::Failed,
    };
    if !valid
        || audit.evidence.schema != WORKER_STOP_EVIDENCE_SCHEMA
        || audit.stop_verdict().is_err()
    {
        return Err(LedgerError::invalid_data(format!(
            "worker stop evidence for {} contradicts durable state {}",
            row.worker_id, row.state
        )));
    }
    if row.state.is_terminal() != row.settled_at.is_some() {
        return Err(LedgerError::invalid_data(format!(
            "worker stop {} has inconsistent settlement timestamp",
            row.worker_id
        )));
    }
    Ok(())
}

fn validate_evidence(
    raw: &str,
    worker_id: &str,
    _correlation_id: &str,
    verdict: StopVerdictTag,
) -> LedgerResult<StopAudit> {
    let audit: StopAudit = serde_json::from_str(raw)?;
    if audit.evidence.schema != WORKER_STOP_EVIDENCE_SCHEMA
        || audit.evidence.worker_id != worker_id
        || audit.verdict != verdict
        || audit.stop_verdict().is_err()
    {
        return Err(LedgerError::invalid_data(format!(
            "worker stop evidence does not match {worker_id}/{verdict}"
        )));
    }
    Ok(audit)
}

pub const JOB_STOP_EVIDENCE_SCHEMA: &str = "odin.job-stop-evidence.v1";

/// The sole durable backend tag for Kubernetes Job workers. The registry
/// CHECK constraint and every evidence body repeat this exact value; a Job
/// worker row never carries a systemd unit, PID, or cgroup anchor.
pub const JOB_BACKEND_TAG: &str = "kube.job";

/// Terminal disposition of one Job worker's workload. `Delete` proves the
/// Job and its pods gone; `Suspend` proves the Job suspended and its pods
/// gone. Both are authorized only through the kernel StopAuthority.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum JobStopAction {
    Delete,
    Suspend,
}

impl JobStopAction {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Delete => "delete",
            Self::Suspend => "suspend",
        }
    }

    pub fn parse(raw: &str) -> Option<Self> {
        match raw {
            "delete" => Some(Self::Delete),
            "suspend" => Some(Self::Suspend),
            _ => None,
        }
    }
}

/// One pod that provably survived a stop attempt.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct JobPodResidue {
    pub name: String,
    pub uid: String,
    pub phase: Option<String>,
}

/// Pod residue present on failed verdicts.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct JobStopResidue {
    pub pods: Vec<JobPodResidue>,
}

/// Fault probes a Job backend may report. A probe records only what the
/// backend actually observed; unobserved facts stay absent, never fabricated.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum JobFaultProbeKind {
    JobQueryFailure,
    PodQueryFailure,
    JobPresent,
    JobNotSuspended,
    PodResidue,
    BackendUnavailable,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct JobFaultProbe {
    pub probe: JobFaultProbeKind,
    pub detected: bool,
}

/// Backend-collected evidence for one Job stop attempt. Every field reports
/// a real observation about the named Job: `job_absent`, the suspension bit,
/// and surviving pods come from the Kubernetes API, never from invention.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct JobStopEvidenceBody {
    pub schema: String,
    pub worker_id: String,
    pub backend: String,
    pub cluster: String,
    pub namespace: String,
    pub job_name: String,
    pub job_uid: String,
    pub job_absent: bool,
    pub job_suspended: Option<bool>,
    pub pod_residue: Vec<JobPodResidue>,
    pub evidence_complete: bool,
    pub fault_probes: Vec<JobFaultProbe>,
}

/// Job-stop audit: residue is present for failed verdicts and missing evidence for indeterminate ones.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct JobStopAudit {
    pub verdict: StopVerdictTag,
    pub recovered: bool,
    pub action: JobStopAction,
    pub residue: Option<JobStopResidue>,
    pub missing: Option<StopMissing>,
    pub evidence: JobStopEvidenceBody,
    pub trace: Vec<StopTraceRow>,
}

impl JobStopAudit {
    /// Checks that the recorded payload pair matches the verdict exactly.
    /// A stopped verdict requires complete evidence proving the workload
    /// gone — an absent Job or a suspended Job, never surviving pods. A
    /// failed verdict requires complete evidence with surviving pods, and
    /// the residue list must repeat every surviving pod.
    pub fn verify(&self) -> Result<(), String> {
        if self.evidence.schema != JOB_STOP_EVIDENCE_SCHEMA {
            return Err(format!(
                "job stop evidence schema {:?} is not {JOB_STOP_EVIDENCE_SCHEMA}",
                self.evidence.schema
            ));
        }
        if self.evidence.backend != JOB_BACKEND_TAG {
            return Err(format!(
                "job stop evidence backend {:?} is not {JOB_BACKEND_TAG}",
                self.evidence.backend
            ));
        }
        match self.verdict {
            StopVerdictTag::Requested => {
                if self.residue.is_some() || self.missing.is_some() {
                    return Err(
                        "requested job stop evidence carries residue or a missing reason"
                            .to_owned(),
                    );
                }
            }
            StopVerdictTag::Indeterminate => {
                if self.residue.is_some() || self.missing.is_none() {
                    return Err(
                        "indeterminate job stop needs exactly one missing reason".to_owned()
                    );
                }
                if self.missing.as_ref().map(|m| m.reason.is_empty()) == Some(true) {
                    return Err("indeterminate job stop reason must not be empty".to_owned());
                }
            }
            StopVerdictTag::Stopped => {
                if self.residue.is_some() || self.missing.is_some() {
                    return Err(
                        "stopped job stop must not carry residue or a missing reason".to_owned(),
                    );
                }
                if !self.evidence.evidence_complete {
                    return Err("stopped job stop evidence is incomplete".to_owned());
                }
                let workload_gone =
                    self.evidence.job_absent || self.evidence.job_suspended == Some(true);
                if !workload_gone {
                    return Err(
                        "stopped job stop without Job absence or suspension proof".to_owned()
                    );
                }
                if !self.evidence.pod_residue.is_empty() {
                    return Err("stopped job stop claims success over surviving pods".to_owned());
                }
            }
            StopVerdictTag::Failed => {
                if self.missing.is_some() {
                    return Err("failed job stop must not carry a missing reason".to_owned());
                }
                if !self.evidence.evidence_complete {
                    return Err("failed job stop evidence is incomplete".to_owned());
                }
                let residue = match &self.residue {
                    Some(residue) if !residue.pods.is_empty() => residue,
                    _ => return Err("failed job stop without surviving pod residue".to_owned()),
                };
                if residue.pods.len() != self.evidence.pod_residue.len() {
                    return Err(
                        "failed job stop residue disagrees with the evidence pods".to_owned()
                    );
                }
                for (recorded, observed) in residue.pods.iter().zip(&self.evidence.pod_residue) {
                    if recorded.name != observed.name || recorded.uid != observed.uid {
                        return Err(
                            "failed job stop residue disagrees with the evidence pods".to_owned()
                        );
                    }
                }
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JobStopRow {
    pub worker_id: String,
    pub correlation_id: String,
    pub action: JobStopAction,
    pub state: StopState,
    pub evidence_json: String,
    pub attempts: u64,
    pub requested_at: String,
    pub updated_at: String,
    pub settled_at: Option<String>,
}

const JOB_STOP_COLUMNS: &str = "worker_id, correlation_id, action, state, evidence_json, \
     attempts, requested_at, updated_at, settled_at";

fn read_job_stop_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<JobStopRow> {
    let action_raw: String = row.get(2)?;
    let action = JobStopAction::parse(&action_raw).ok_or_else(|| {
        rusqlite::Error::FromSqlConversionFailure(
            2,
            rusqlite::types::Type::Text,
            LedgerError::invalid_data(format!("unknown job stop action {action_raw:?}")).into(),
        )
    })?;
    let state_raw: String = row.get(3)?;
    let state = StopState::parse(&state_raw).ok_or_else(|| {
        rusqlite::Error::FromSqlConversionFailure(
            3,
            rusqlite::types::Type::Text,
            LedgerError::invalid_data(format!("unknown job stop state {state_raw:?}")).into(),
        )
    })?;
    let attempts: i64 = row.get(5)?;
    let attempts = u64::try_from(attempts).map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(
            5,
            rusqlite::types::Type::Integer,
            LedgerError::invalid_data_caused_by(
                format!("negative job stop attempt count {attempts}"),
                error,
            )
            .into(),
        )
    })?;
    Ok(JobStopRow {
        worker_id: row.get(0)?,
        correlation_id: row.get(1)?,
        action,
        state,
        evidence_json: row.get(4)?,
        attempts,
        requested_at: row.get(6)?,
        updated_at: row.get(7)?,
        settled_at: row.get(8)?,
    })
}

fn query_job_stop_row(conn: &Connection, worker_id: &str) -> LedgerResult<Option<JobStopRow>> {
    conn.query_row(
        &format!("SELECT {JOB_STOP_COLUMNS} FROM job_stop_intent WHERE worker_id = ?1"),
        [worker_id],
        read_job_stop_row,
    )
    .optional()
    .map_err(LedgerError::from)
}

fn validate_job_row(row: &JobStopRow) -> LedgerResult<()> {
    let audit: JobStopAudit = serde_json::from_str(&row.evidence_json)?;
    if audit.evidence.worker_id != row.worker_id {
        return Err(LedgerError::invalid_data(format!(
            "job stop evidence for {} has a different immutable binding",
            row.worker_id
        )));
    }
    if audit.action != row.action {
        return Err(LedgerError::invalid_data(format!(
            "job stop evidence for {} carries action {}, bound action is {}",
            row.worker_id,
            audit.action.as_str(),
            row.action.as_str()
        )));
    }
    let valid = match row.state {
        StopState::Requested => matches!(
            audit.verdict,
            StopVerdictTag::Requested | StopVerdictTag::Indeterminate
        ),
        StopState::Stopped => audit.verdict == StopVerdictTag::Stopped,
        StopState::Failed => audit.verdict == StopVerdictTag::Failed,
    };
    if !valid || audit.verify().is_err() {
        return Err(LedgerError::invalid_data(format!(
            "job stop evidence for {} contradicts durable state {}",
            row.worker_id, row.state
        )));
    }
    if row.state.is_terminal() != row.settled_at.is_some() {
        return Err(LedgerError::invalid_data(format!(
            "job stop {} has inconsistent settlement timestamp",
            row.worker_id
        )));
    }
    Ok(())
}

fn validate_job_evidence(
    raw: &str,
    worker_id: &str,
    action: JobStopAction,
    verdict: StopVerdictTag,
) -> LedgerResult<JobStopAudit> {
    let audit: JobStopAudit = serde_json::from_str(raw)?;
    if audit.evidence.worker_id != worker_id || audit.action != action || audit.verdict != verdict {
        return Err(LedgerError::invalid_data(format!(
            "job stop evidence does not match {worker_id}/{}/{verdict}",
            action.as_str()
        )));
    }
    audit.verify().map_err(LedgerError::invalid_data)?;
    Ok(audit)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum JobStopIntentOutcome {
    /// The intent was made durable before any actuation.
    Inserted,
    /// The exact worker/correlation intent already exists; a pending intent
    /// may have been re-bound to the newly requested action.
    Replay { row: Box<JobStopRow> },
}

/// Idempotently records a Job stop intent before any backend actuation,
/// durably binding the user's chosen action. A duplicate worker id replays
/// only when the immutable correlation matches; otherwise it is a conflict.
/// A still-pending intent may be re-bound to the other action — the user's
/// latest verb wins until the stop settles; terminal rows never move.
#[doc(hidden)]
pub fn request_job_stop(
    tx: &Transaction<'_>,
    worker_id: &str,
    correlation_id: &str,
    action: JobStopAction,
    evidence_json: &str,
    now: OffsetDateTime,
) -> LedgerResult<JobStopIntentOutcome> {
    validate_job_evidence(evidence_json, worker_id, action, StopVerdictTag::Requested)?;
    let stamp = encode_utc(now)?;
    let inserted = tx.execute(
        "INSERT INTO job_stop_intent (
             worker_id, correlation_id, action, state, evidence_json, attempts,
             requested_at, updated_at, settled_at
         ) VALUES (?1, ?2, ?3, 'requested', ?4, 0, ?5, ?5, NULL)
         ON CONFLICT(worker_id) DO NOTHING",
        params![
            worker_id,
            correlation_id,
            action.as_str(),
            evidence_json,
            stamp
        ],
    )?;
    if inserted == 1 {
        return Ok(JobStopIntentOutcome::Inserted);
    }
    let row = query_job_stop_row(tx, worker_id)?.ok_or_else(|| {
        LedgerError::invalid_data(format!(
            "job stop intent conflict for {worker_id} reported no durable row"
        ))
    })?;
    if row.correlation_id != correlation_id {
        return Err(LedgerError::Conflict(format!(
            "job stop intent {worker_id} belongs to correlation {}, not {correlation_id}",
            row.correlation_id
        )));
    }
    if row.state == StopState::Requested
        && (row.action != action || row.evidence_json != evidence_json)
    {
        tx.execute(
            "UPDATE job_stop_intent
                 SET action = ?2, evidence_json = ?3, updated_at = ?4
                 WHERE worker_id = ?1 AND state = 'requested'",
            params![worker_id, action.as_str(), evidence_json, stamp],
        )?;
        let rebound = query_job_stop_row(tx, worker_id)?.ok_or_else(|| {
            LedgerError::invalid_data(format!(
                "job stop intent rebind for {worker_id} reported no durable row"
            ))
        })?;
        validate_job_row(&rebound)?;
        return Ok(JobStopIntentOutcome::Replay {
            row: Box::new(rebound),
        });
    }
    validate_job_row(&row)?;
    Ok(JobStopIntentOutcome::Replay { row: Box::new(row) })
}

/// Records an indeterminate Job stop attempt and leaves the intent pending.
/// A concurrently terminal row is replayed without mutation.
#[doc(hidden)]
pub fn record_job_indeterminate(
    tx: &Transaction<'_>,
    worker_id: &str,
    evidence_json: &str,
    now: OffsetDateTime,
) -> LedgerResult<StopAttemptOutcome> {
    let row = query_job_stop_row(tx, worker_id)?.ok_or_else(|| LedgerError::NotFound {
        kind: "job stop intent",
        id: worker_id.to_owned(),
    })?;
    validate_job_evidence(
        evidence_json,
        worker_id,
        row.action,
        StopVerdictTag::Indeterminate,
    )?;
    if row.state.is_terminal() {
        return Ok(StopAttemptOutcome::TerminalReplay);
    }
    let changed = tx.execute(
        "UPDATE job_stop_intent
         SET evidence_json = ?2, attempts = attempts + 1, updated_at = ?3
         WHERE worker_id = ?1 AND state = 'requested'",
        params![worker_id, evidence_json, encode_utc(now)?],
    )?;
    if changed == 1 {
        Ok(StopAttemptOutcome::Recorded)
    } else {
        Ok(StopAttemptOutcome::TerminalReplay)
    }
}

/// Settles a pending Job stop to `stopped` or `failed` with exact evidence.
/// Terminal rows never move; an exact replay is returned, while a
/// contradictory terminal verdict is a conflict.
#[doc(hidden)]
pub fn settle_job_stop(
    tx: &Transaction<'_>,
    worker_id: &str,
    state: StopState,
    evidence_json: &str,
    now: OffsetDateTime,
) -> LedgerResult<StopSettleOutcome> {
    if !matches!(state, StopState::Stopped | StopState::Failed)
        || !can_transition_stop(StopState::Requested, state)
    {
        return Err(LedgerError::invalid_data(format!(
            "job stop state {state} is not terminal"
        )));
    }
    let current = query_job_stop_row(tx, worker_id)?.ok_or_else(|| LedgerError::NotFound {
        kind: "job stop intent",
        id: worker_id.to_owned(),
    })?;
    let verdict = match state {
        StopState::Stopped => StopVerdictTag::Stopped,
        StopState::Failed => StopVerdictTag::Failed,
        StopState::Requested => unreachable!("validated terminal state"),
    };
    validate_job_evidence(evidence_json, worker_id, current.action, verdict)?;
    if current.state.is_terminal() {
        if current.state == state && current.evidence_json == evidence_json {
            return Ok(StopSettleOutcome::Replay);
        }
        return Err(LedgerError::Conflict(format!(
            "job stop {worker_id} already settled {} with different evidence",
            current.state
        )));
    }
    let stamp = encode_utc(now)?;
    let changed = tx.execute(
        "UPDATE job_stop_intent
         SET state = ?2, evidence_json = ?3, attempts = attempts + 1,
             updated_at = ?4, settled_at = ?4
         WHERE worker_id = ?1 AND state = 'requested'",
        params![worker_id, state.as_str(), evidence_json, stamp],
    )?;
    if changed == 1 {
        Ok(StopSettleOutcome::Settled)
    } else {
        Ok(StopSettleOutcome::Replay)
    }
}

pub fn job_stop_row(conn: &Connection, worker_id: &str) -> LedgerResult<Option<JobStopRow>> {
    let row = query_job_stop_row(conn, worker_id)?;
    if let Some(row) = &row {
        validate_job_row(row)?;
    }
    Ok(row)
}

#[cfg(test)]
mod tests {
    use super::*;
    use odin_domain::{StopEvidence, StopMissing, StopResidue, StopResidueProcess};

    fn evidence(worker_id: &str, _correlation_id: &str, verdict: StopVerdictTag) -> String {
        let (residue, missing, leader_reaped, descendants, complete) = match verdict {
            StopVerdictTag::Requested => (None, None, false, 0, false),
            StopVerdictTag::Stopped => (None, None, true, 0, true),
            StopVerdictTag::Failed => (
                Some(StopResidue {
                    unit_active: true,
                    cgroup_present: true,
                    processes: vec![StopResidueProcess {
                        pid: 42,
                        start_time_ticks: 99,
                    }],
                }),
                None,
                true,
                1,
                true,
            ),
            StopVerdictTag::Indeterminate => (
                None,
                Some(StopMissing {
                    reason: "manager unavailable".to_owned(),
                }),
                false,
                0,
                false,
            ),
        };
        serde_json::to_string(&StopAudit {
            verdict,
            recovered: false,
            term_sent: false,
            cgroup_kill: false,
            unit_identity_verified: verdict == StopVerdictTag::Stopped,
            residue,
            missing,
            evidence: StopEvidence {
                schema: WORKER_STOP_EVIDENCE_SCHEMA.to_owned(),
                worker_id: worker_id.to_owned(),
                unit: "tx-wp-attempt-0-deadbeef.scope".to_owned(),
                cgroup: "/odin-test/tx-wp-attempt-0-deadbeef.scope".to_owned(),
                leader_reaped,
                cgroup_descendants: descendants,
                evidence_complete: complete,
                fault_probes: Vec::new(),
            },
            trace: Vec::new(),
        })
        .expect("serialize evidence")
    }

    fn register_worker(ledger: &mut crate::Ledger, worker_id: &str, correlation_id: &str) {
        ledger
            .with_tx(|tx| {
                crate::worker::register_worker(
                    tx,
                    &crate::worker::NewWorker {
                        worker_id,
                        unit: "tx-wp-attempt-0-deadbeef.scope",
                        correlation_id,
                        tx_id: "tx",
                        wp_id: "wp",
                        attempt: 0,
                        now: OffsetDateTime::UNIX_EPOCH,
                    },
                )?;
                Ok(())
            })
            .expect("register worker");
    }

    #[test]
    fn durable_stop_intent_retries_indeterminate_then_settles() {
        let worker_id = "worker-stop-test";
        let correlation_id = "0123456789abcdef0123456789abcdef";
        let mut ledger = crate::Ledger::open_in_memory().expect("ledger");
        register_worker(&mut ledger, worker_id, correlation_id);
        ledger
            .with_tx(|tx| {
                request_stop(
                    tx,
                    worker_id,
                    correlation_id,
                    &evidence(worker_id, correlation_id, StopVerdictTag::Requested),
                    OffsetDateTime::UNIX_EPOCH,
                )?;
                record_indeterminate(
                    tx,
                    worker_id,
                    &evidence(worker_id, correlation_id, StopVerdictTag::Indeterminate),
                    OffsetDateTime::UNIX_EPOCH,
                )?;
                Ok(())
            })
            .expect("request and record");
        let pending = pending_stops(ledger.connection(), Some(correlation_id)).expect("pending");
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].attempts, 1);
        ledger
            .with_tx(|tx| {
                settle_stop(
                    tx,
                    worker_id,
                    StopState::Stopped,
                    &evidence(worker_id, correlation_id, StopVerdictTag::Stopped),
                    OffsetDateTime::UNIX_EPOCH,
                )?;
                Ok(())
            })
            .expect("settle");
        let row = stop_row(ledger.connection(), worker_id)
            .expect("read")
            .expect("row");
        assert_eq!(row.state, StopState::Stopped);
        assert_eq!(row.attempts, 2);
        assert!(pending_stops(ledger.connection(), None)
            .expect("pending")
            .is_empty());
    }

    #[test]
    fn terminal_stop_rows_never_move() {
        let worker_id = "worker-terminal-stop";
        let correlation_id = "abcdef0123456789abcdef0123456789";
        let mut ledger = crate::Ledger::open_in_memory().expect("ledger");
        register_worker(&mut ledger, worker_id, correlation_id);
        ledger
            .with_tx(|tx| {
                request_stop(
                    tx,
                    worker_id,
                    correlation_id,
                    &evidence(worker_id, correlation_id, StopVerdictTag::Requested),
                    OffsetDateTime::UNIX_EPOCH,
                )?;
                settle_stop(
                    tx,
                    worker_id,
                    StopState::Stopped,
                    &evidence(worker_id, correlation_id, StopVerdictTag::Stopped),
                    OffsetDateTime::UNIX_EPOCH,
                )?;
                Ok(())
            })
            .expect("settle");
        let conflict = ledger.with_tx(|tx| {
            settle_stop(
                tx,
                worker_id,
                StopState::Failed,
                &evidence(worker_id, correlation_id, StopVerdictTag::Failed),
                OffsetDateTime::UNIX_EPOCH,
            )?;
            Ok(())
        });
        assert!(matches!(conflict, Err(LedgerError::Conflict(_))));
    }
}
