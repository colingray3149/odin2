use std::{fmt::Display, str::FromStr};

use odin_domain::{
    AttemptId, AttemptStatus, LaneId, LaneStatus, ProjectId, RunId, RunStatus, SeatId,
};
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::revision::{decode_lane_status, encode_lane_status, guard_expected_revision};
use crate::{decode_utc, encode_utc, LedgerError, LedgerResult};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum LaneBackend {
    #[serde(rename = "local_omp")]
    LocalOmp,
    #[serde(rename = "local_worker")]
    LocalWorker,
    #[serde(rename = "k3s")]
    K3s,
    #[serde(rename = "browser")]
    Browser,
    #[serde(rename = "research")]
    Research,
    #[serde(rename = "slurm")]
    Slurm,
}

impl LaneBackend {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::LocalOmp => "local_omp",
            Self::LocalWorker => "local_worker",
            Self::K3s => "k3s",
            Self::Browser => "browser",
            Self::Research => "research",
            Self::Slurm => "slurm",
        }
    }

    pub fn parse(value: &str) -> LedgerResult<Self> {
        match value {
            "local_omp" => Ok(Self::LocalOmp),
            "local_worker" => Ok(Self::LocalWorker),
            "k3s" => Ok(Self::K3s),
            "browser" => Ok(Self::Browser),
            "research" => Ok(Self::Research),
            "slurm" => Ok(Self::Slurm),
            other => Err(LedgerError::invalid_data(format!(
                "unknown lane backend {other:?}"
            ))),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NewLane {
    pub lane_id: LaneId,
    pub seat_id: SeatId,
    pub project_id: Option<ProjectId>,
    pub template_id: String,
    pub backend: String,
    pub created_by: String,
    pub created_at: OffsetDateTime,
    pub retained: bool,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LaneRecord {
    pub lane_id: LaneId,
    pub seat_id: SeatId,
    pub project_id: Option<ProjectId>,
    pub template_id: String,
    pub backend: String,
    pub status: LaneStatus,
    pub revision: i64,
    pub desired_revision: i64,
    pub current_run_id: Option<RunId>,
    pub session_ref: Option<String>,
    pub provider_lease_id: Option<String>,
    pub created_by: String,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
    pub retained: bool,
}

fn validate_lane_record(record: &LaneRecord) -> LedgerResult<()> {
    LaneBackend::parse(&record.backend)?;
    validate_lane_header(
        &record.template_id,
        &record.created_by,
        record.revision,
        record.desired_revision,
    )
}

/// Schema `id` pattern: `^[a-zA-Z0-9][a-zA-Z0-9._:-]{0,127}$`.
fn is_schema_id(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.is_empty() || bytes.len() > 128 {
        return false;
    }
    bytes[0].is_ascii_alphanumeric()
        && bytes[1..]
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-'))
}

fn validate_lane_header(
    template_id: &str,
    created_by: &str,
    revision: i64,
    desired_revision: i64,
) -> LedgerResult<()> {
    if !is_schema_id(template_id) {
        return Err(LedgerError::invalid_data(
            "lane template ID must be a schema id".into(),
        ));
    }
    if !is_schema_id(created_by) {
        return Err(LedgerError::invalid_data(
            "lane creator must be a schema id".into(),
        ));
    }
    if revision < 1 || desired_revision < 1 {
        return Err(LedgerError::invalid_data(
            "lane revisions must be positive".into(),
        ));
    }
    Ok(())
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NewRun {
    pub run_id: RunId,
    pub lane_id: LaneId,
    pub attempt_number: i64,
    pub workflow_id: Option<String>,
    pub workflow_version: Option<i64>,
    pub input_hash: String,
    pub accepted_capability_revision: Option<String>,
    pub lease_id: Option<String>,
    pub absolute_deadline: Option<OffsetDateTime>,
    pub retry_budget: i64,
    pub created_at: OffsetDateTime,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RunRecord {
    pub run_id: RunId,
    pub lane_id: LaneId,
    pub attempt_number: i64,
    pub workflow_id: Option<String>,
    pub workflow_version: Option<i64>,
    pub status: RunStatus,
    pub revision: i64,
    pub input_hash: String,
    pub accepted_capability_revision: Option<String>,
    pub lease_id: Option<String>,
    pub absolute_deadline: Option<OffsetDateTime>,
    pub retry_budget: i64,
    pub retries_used: i64,
    pub started_at: Option<OffsetDateTime>,
    pub ended_at: Option<OffsetDateTime>,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NewAttempt {
    pub attempt_id: AttemptId,
    pub run_id: RunId,
    pub attempt_number: i64,
    pub executor_id: Option<String>,
    pub created_at: OffsetDateTime,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AttemptRecord {
    pub attempt_id: AttemptId,
    pub run_id: RunId,
    pub attempt_number: i64,
    pub status: AttemptStatus,
    pub revision: i64,
    pub executor_id: Option<String>,
    pub started_at: Option<OffsetDateTime>,
    pub ended_at: Option<OffsetDateTime>,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
}

pub fn create_lane(c: &Connection, lane: &NewLane) -> LedgerResult<LaneRecord> {
    validate_lane_header(&lane.template_id, &lane.created_by, 1, 1)?;
    let now = encode_utc(lane.created_at)?;
    c.execute("INSERT INTO lanes (lane_id,seat_id,project_id,template_id,backend,status,revision,desired_revision,created_by,created_at,updated_at,retained) VALUES (?1,?2,?3,?4,?5,?6,1,1,?7,?8,?8,?9)",
        params![lane.lane_id.to_string(),lane.seat_id.to_string(),lane.project_id.as_ref().map(ToString::to_string),lane.template_id,lane.backend,encode_lane_status(LaneStatus::Desired),lane.created_by,now,i64::from(lane.retained)])?;
    read_lane(c, &lane.lane_id)?.ok_or_else(|| not_found("lane", &lane.lane_id))
}
/// Reads the lane, creating it from `lane` when absent. An existing row
/// bound to a different seat or project is a conflict, never rebound.
pub fn ensure_lane(c: &Connection, lane: &NewLane) -> LedgerResult<LaneRecord> {
    let Some(existing) = read_lane(c, &lane.lane_id)? else {
        return create_lane(c, lane);
    };
    if existing.seat_id != lane.seat_id
        || (lane.project_id.is_some() && existing.project_id != lane.project_id)
    {
        return Err(LedgerError::Conflict(format!(
            "lane {} is already bound to seat {} project {:?}",
            lane.lane_id, existing.seat_id, existing.project_id
        )));
    }
    Ok(existing)
}
pub fn read_lane(c: &Connection, id: &LaneId) -> LedgerResult<Option<LaneRecord>> {
    type R = (
        String,
        String,
        Option<String>,
        String,
        String,
        String,
        i64,
        i64,
        Option<String>,
        Option<String>,
        Option<String>,
        String,
        String,
        String,
        i64,
    );
    let r:Option<R>=c.query_row("SELECT lane_id,seat_id,project_id,template_id,backend,status,revision,desired_revision,current_run_id,session_ref,provider_lease_id,created_by,created_at,updated_at,retained FROM lanes WHERE lane_id=?1",[id.to_string()],|x|Ok((x.get(0)?,x.get(1)?,x.get(2)?,x.get(3)?,x.get(4)?,x.get(5)?,x.get(6)?,x.get(7)?,x.get(8)?,x.get(9)?,x.get(10)?,x.get(11)?,x.get(12)?,x.get(13)?,x.get(14)?))).optional()?;
    r.map(|x| {
        let record = LaneRecord {
            lane_id: parse("lane_id", &x.0)?,
            seat_id: parse("seat_id", &x.1)?,
            project_id: parse_opt("project_id", x.2)?,
            template_id: x.3,
            backend: x.4,
            status: decode_lane_status(&x.5)?,
            revision: x.6,
            desired_revision: x.7,
            current_run_id: parse_opt("current_run_id", x.8)?,
            session_ref: x.9,
            provider_lease_id: x.10,
            created_by: x.11,
            created_at: decode_utc(&x.12)?,
            updated_at: decode_utc(&x.13)?,
            retained: bool_value("retained", x.14)?,
        };
        validate_lane_record(&record)?;
        Ok(record)
    })
    .transpose()
}
pub fn create_run(c: &Connection, run: &NewRun) -> LedgerResult<RunRecord> {
    if run.attempt_number < 1 || run.retry_budget < 0 {
        return Err(LedgerError::invalid_data(
            "run attempt_number must be positive and retry_budget non-negative".into(),
        ));
    }
    let now = encode_utc(run.created_at)?;
    let deadline = run.absolute_deadline.map(encode_utc).transpose()?;
    c.execute("INSERT INTO runs (run_id,lane_id,attempt_number,workflow_id,workflow_version,status,revision,input_hash,accepted_capability_revision,lease_id,absolute_deadline,retry_budget,retries_used,created_at,updated_at) VALUES (?1,?2,?3,?4,?5,?6,1,?7,?8,?9,?10,?11,0,?12,?12)",params![run.run_id.to_string(),run.lane_id.to_string(),run.attempt_number,run.workflow_id,run.workflow_version,encode_run_status(RunStatus::Pending),run.input_hash,run.accepted_capability_revision,run.lease_id,deadline,run.retry_budget,now])?;
    read_run(c, &run.run_id)?.ok_or_else(|| not_found("run", &run.run_id))
}
pub fn read_run(c: &Connection, id: &RunId) -> LedgerResult<Option<RunRecord>> {
    type R = (
        String,
        String,
        i64,
        Option<String>,
        Option<i64>,
        String,
        i64,
        String,
        Option<String>,
        Option<String>,
        Option<String>,
        i64,
        i64,
        Option<String>,
        Option<String>,
        String,
        String,
    );
    let r:Option<R>=c.query_row("SELECT run_id,lane_id,attempt_number,workflow_id,workflow_version,status,revision,input_hash,accepted_capability_revision,lease_id,absolute_deadline,retry_budget,retries_used,started_at,ended_at,created_at,updated_at FROM runs WHERE run_id=?1",[id.to_string()],|x|Ok((x.get(0)?,x.get(1)?,x.get(2)?,x.get(3)?,x.get(4)?,x.get(5)?,x.get(6)?,x.get(7)?,x.get(8)?,x.get(9)?,x.get(10)?,x.get(11)?,x.get(12)?,x.get(13)?,x.get(14)?,x.get(15)?,x.get(16)?))).optional()?;
    r.map(|x| {
        Ok(RunRecord {
            run_id: parse("run_id", &x.0)?,
            lane_id: parse("lane_id", &x.1)?,
            attempt_number: x.2,
            workflow_id: x.3,
            workflow_version: x.4,
            status: decode_run_status(&x.5)?,
            revision: x.6,
            input_hash: x.7,
            accepted_capability_revision: x.8,
            lease_id: x.9,
            absolute_deadline: time_opt(x.10)?,
            retry_budget: x.11,
            retries_used: x.12,
            started_at: time_opt(x.13)?,
            ended_at: time_opt(x.14)?,
            created_at: decode_utc(&x.15)?,
            updated_at: decode_utc(&x.16)?,
        })
    })
    .transpose()
}
/// The live-session runs (`run:live:<session>`) bound to one lane, oldest
/// first — the sessions a Huginn lane command reaches.
pub fn live_runs_for_lane(c: &Connection, lane: &LaneId) -> LedgerResult<Vec<RunId>> {
    let mut statement = c.prepare(
        "SELECT run_id FROM runs WHERE lane_id=?1 AND run_id LIKE 'run:live:%' ORDER BY created_at, run_id",
    )?;
    let rows = statement.query_map([lane.to_string()], |row| row.get::<_, String>(0))?;
    rows.map(|row| parse("run_id", &row?)).collect()
}
pub fn create_attempt(c: &Connection, a: &NewAttempt) -> LedgerResult<AttemptRecord> {
    if a.attempt_number < 1 {
        return Err(LedgerError::invalid_data(
            "attempt_number must be positive".into(),
        ));
    }
    let now = encode_utc(a.created_at)?;
    c.execute("INSERT INTO attempts (attempt_id,run_id,attempt_number,status,revision,executor_id,created_at,updated_at) VALUES (?1,?2,?3,?4,1,?5,?6,?6)",params![a.attempt_id.to_string(),a.run_id.to_string(),a.attempt_number,encode_attempt_status(AttemptStatus::Pending),a.executor_id,now])?;
    read_attempt(c, &a.attempt_id)?.ok_or_else(|| not_found("attempt", &a.attempt_id))
}
pub fn read_attempt(c: &Connection, id: &AttemptId) -> LedgerResult<Option<AttemptRecord>> {
    type R = (
        String,
        String,
        i64,
        String,
        i64,
        Option<String>,
        Option<String>,
        Option<String>,
        String,
        String,
    );
    let r:Option<R>=c.query_row("SELECT attempt_id,run_id,attempt_number,status,revision,executor_id,started_at,ended_at,created_at,updated_at FROM attempts WHERE attempt_id=?1",[id.to_string()],|x|Ok((x.get(0)?,x.get(1)?,x.get(2)?,x.get(3)?,x.get(4)?,x.get(5)?,x.get(6)?,x.get(7)?,x.get(8)?,x.get(9)?))).optional()?;
    r.map(|x| {
        Ok(AttemptRecord {
            attempt_id: parse("attempt_id", &x.0)?,
            run_id: parse("run_id", &x.1)?,
            attempt_number: x.2,
            status: decode_attempt_status(&x.3)?,
            revision: x.4,
            executor_id: x.5,
            started_at: time_opt(x.6)?,
            ended_at: time_opt(x.7)?,
            created_at: decode_utc(&x.8)?,
            updated_at: decode_utc(&x.9)?,
        })
    })
    .transpose()
}

pub fn transition_run(
    c: &Connection,
    id: &RunId,
    to: RunStatus,
    rev: i64,
    now: OffsetDateTime,
) -> LedgerResult<i64> {
    transition(
        c,
        &TransitionTarget {
            target: Target::Run,
            id: &id.to_string(),
            expected: rev,
        },
        encode_run_status(to),
        now,
        |v| Ok(decode_run_status(v)?.can_transition_to(to)),
        to.is_terminal(),
        matches!(to, RunStatus::Running),
    )
}
/// Marks a live session's new run running: the session is starting.
pub fn start_live_run(c: &Connection, id: &RunId, now: OffsetDateTime) -> LedgerResult<()> {
    let revision = transition_run(c, id, RunStatus::Planning, 1, now)?;
    transition_run(c, id, RunStatus::Running, revision, now).map(drop)
}

/// Closes the run of a live session that has ended: a running run
/// succeeded, one that never reached running is cancelled. A closed or
/// missing run is left as it is.
pub fn close_live_run(c: &Connection, session: &str, now: OffsetDateTime) -> LedgerResult<()> {
    let run = RunId::new(format!("run:live:{session}"))
        .map_err(|error| LedgerError::invalid_data(error.to_string()))?;
    let Some((status, revision)) = c
        .query_row(
            "SELECT status,revision FROM runs WHERE run_id=?1",
            [run.to_string()],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?)),
        )
        .optional()?
    else {
        return Ok(());
    };
    let status = decode_run_status(&status)?;
    if status.is_terminal() {
        return Ok(());
    }
    let to = if status.can_transition_to(RunStatus::Succeeded) {
        RunStatus::Succeeded
    } else {
        RunStatus::Cancelled
    };
    transition_run(c, &run, to, revision, now).map(drop)
}

/// Closes every open live-session run whose session has ended, or whose
/// session row is gone and that was created before `orphaned_before`.
/// A failed session can still be resumed, so its run stays open.
pub fn close_ended_live_runs(
    c: &Connection,
    orphaned_before: OffsetDateTime,
    now: OffsetDateTime,
) -> LedgerResult<usize> {
    let sessions = c
        .prepare(
            "SELECT substr(r.run_id, 10) FROM runs r \
             LEFT JOIN live_sessions s ON s.session_id = substr(r.run_id, 10) \
             WHERE r.run_id LIKE 'run:live:%' AND r.ended_at IS NULL \
               AND (s.state = 'ended' OR (s.session_id IS NULL AND r.created_at < ?1))",
        )?
        .query_map([encode_utc(orphaned_before)?], |row| {
            row.get::<_, String>(0)
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    for session in &sessions {
        close_live_run(c, session, now)?;
    }
    Ok(sessions.len())
}
pub fn transition_attempt(
    c: &Connection,
    id: &AttemptId,
    to: AttemptStatus,
    rev: i64,
    now: OffsetDateTime,
) -> LedgerResult<i64> {
    transition(
        c,
        &TransitionTarget {
            target: Target::Attempt,
            id: &id.to_string(),
            expected: rev,
        },
        encode_attempt_status(to),
        now,
        |v| Ok(decode_attempt_status(v)?.can_transition_to(to)),
        to.is_terminal(),
        matches!(to, AttemptStatus::Starting | AttemptStatus::Running),
    )
}
#[derive(Clone, Copy)]
enum Target {
    Run,
    Attempt,
}
impl Target {
    const fn kind(self) -> &'static str {
        match self {
            Self::Run => "run",
            Self::Attempt => "attempt",
        }
    }
    const fn select(self) -> &'static str {
        match self {
            Self::Run => "SELECT status,revision FROM runs WHERE run_id=?1",
            Self::Attempt => "SELECT status,revision FROM attempts WHERE attempt_id=?1",
        }
    }
    const fn update(self) -> &'static str {
        match self{Self::Run=>"UPDATE runs SET status=?1,revision=?2,updated_at=?3,started_at=COALESCE(started_at,?4),ended_at=COALESCE(?5,ended_at) WHERE run_id=?6 AND revision=?7 AND status=?8",Self::Attempt=>"UPDATE attempts SET status=?1,revision=?2,updated_at=?3,started_at=COALESCE(started_at,?4),ended_at=COALESCE(?5,ended_at) WHERE attempt_id=?6 AND revision=?7 AND status=?8"}
    }
}
struct TransitionTarget<'a> {
    target: Target,
    id: &'a str,
    expected: i64,
}

fn transition(
    c: &Connection,
    row: &TransitionTarget<'_>,
    to: &str,
    now: OffsetDateTime,
    legal: impl FnOnce(&str) -> LedgerResult<bool>,
    terminal: bool,
    starts: bool,
) -> LedgerResult<i64> {
    let TransitionTarget {
        target,
        id,
        expected,
    } = *row;
    let current = c
        .query_row(target.select(), [id], |r| {
            Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?))
        })
        .optional()?
        .ok_or_else(|| LedgerError::NotFound {
            kind: target.kind(),
            id: id.into(),
        })?;
    let actor = format!("{}:{id}", target.kind());
    guard_expected_revision(&actor, expected, current.1)?;
    if !legal(&current.0)? {
        return Err(LedgerError::invalid_data(format!(
            "illegal {} transition for {id}: {} -> {to}",
            target.kind(),
            current.0
        )));
    }
    let next = expected.checked_add(1).ok_or_else(|| {
        LedgerError::invalid_data(format!("{} {id} revision overflow", target.kind()))
    })?;
    let now = encode_utc(now)?;
    let changed = c.execute(
        target.update(),
        params![
            to,
            next,
            now,
            starts.then_some(now.as_str()),
            terminal.then_some(now.as_str()),
            id,
            expected,
            current.0
        ],
    )?;
    if changed == 1 {
        return Ok(next);
    }
    let actual = c
        .query_row(target.select(), [id], |r| r.get::<_, i64>(1))
        .optional()?
        .ok_or_else(|| LedgerError::NotFound {
            kind: target.kind(),
            id: id.into(),
        })?;
    guard_expected_revision(actor, expected, actual)?;
    Err(LedgerError::Conflict(format!(
        "{} {id} changed during transition",
        target.kind()
    )))
}

fn not_found(kind: &'static str, id: impl Display) -> LedgerError {
    LedgerError::NotFound {
        kind,
        id: id.to_string(),
    }
}
fn parse<T: FromStr>(column: &str, value: &str) -> LedgerResult<T>
where
    T::Err: std::error::Error + Send + Sync + 'static,
{
    value.parse().map_err(|error| {
        LedgerError::invalid_data_caused_by(format!("invalid {column} {value:?}"), error)
    })
}
fn parse_opt<T: FromStr>(column: &str, value: Option<String>) -> LedgerResult<Option<T>>
where
    T::Err: std::error::Error + Send + Sync + 'static,
{
    value.map(|v| parse(column, &v)).transpose()
}
fn time_opt(value: Option<String>) -> LedgerResult<Option<OffsetDateTime>> {
    value.map(|v| decode_utc(&v)).transpose()
}
fn bool_value(column: &str, value: i64) -> LedgerResult<bool> {
    match value {
        0 => Ok(false),
        1 => Ok(true),
        v => Err(LedgerError::invalid_data(format!(
            "{column} must be 0 or 1, found {v}"
        ))),
    }
}

pub(crate) const fn encode_run_status(s: RunStatus) -> &'static str {
    match s {
        RunStatus::Pending => "pending",
        RunStatus::Planning => "planning",
        RunStatus::Running => "running",
        RunStatus::WaitingApproval => "waitingApproval",
        RunStatus::Paused => "paused",
        RunStatus::Recovering => "recovering",
        RunStatus::Succeeded => "succeeded",
        RunStatus::Failed => "failed",
        RunStatus::Blocked => "blocked",
        RunStatus::Cancelled => "cancelled",
    }
}
pub(crate) fn decode_run_status(v: &str) -> LedgerResult<RunStatus> {
    match v {
        "pending" => Ok(RunStatus::Pending),
        "planning" => Ok(RunStatus::Planning),
        "running" => Ok(RunStatus::Running),
        "waitingApproval" => Ok(RunStatus::WaitingApproval),
        "paused" => Ok(RunStatus::Paused),
        "recovering" => Ok(RunStatus::Recovering),
        "succeeded" => Ok(RunStatus::Succeeded),
        "failed" => Ok(RunStatus::Failed),
        "blocked" => Ok(RunStatus::Blocked),
        "cancelled" => Ok(RunStatus::Cancelled),
        x => Err(LedgerError::invalid_data(format!(
            "unknown run status {x:?}"
        ))),
    }
}
pub(crate) const fn encode_attempt_status(s: AttemptStatus) -> &'static str {
    match s {
        AttemptStatus::Pending => "pending",
        AttemptStatus::Starting => "starting",
        AttemptStatus::Running => "running",
        AttemptStatus::WaitingApproval => "waitingApproval",
        AttemptStatus::Paused => "paused",
        AttemptStatus::Orphaned => "orphaned",
        AttemptStatus::Recovering => "recovering",
        AttemptStatus::Succeeded => "succeeded",
        AttemptStatus::Failed => "failed",
        AttemptStatus::Blocked => "blocked",
        AttemptStatus::Cancelled => "cancelled",
    }
}
pub(crate) fn decode_attempt_status(v: &str) -> LedgerResult<AttemptStatus> {
    match v {
        "pending" => Ok(AttemptStatus::Pending),
        "starting" => Ok(AttemptStatus::Starting),
        "running" => Ok(AttemptStatus::Running),
        "waitingApproval" => Ok(AttemptStatus::WaitingApproval),
        "paused" => Ok(AttemptStatus::Paused),
        "orphaned" => Ok(AttemptStatus::Orphaned),
        "recovering" => Ok(AttemptStatus::Recovering),
        "succeeded" => Ok(AttemptStatus::Succeeded),
        "failed" => Ok(AttemptStatus::Failed),
        "blocked" => Ok(AttemptStatus::Blocked),
        "cancelled" => Ok(AttemptStatus::Cancelled),
        x => Err(LedgerError::invalid_data(format!(
            "unknown attempt status {x:?}"
        ))),
    }
}

#[cfg(test)]
mod tests;
