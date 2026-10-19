use odin_domain::StopVerdictTag;
use odin_types::WorkerId;
use rusqlite::{params, Connection, OptionalExtension, Transaction};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::{encode_utc, LedgerError, LedgerResult};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PodWorkerIdentity {
    pub cluster: String,
    pub namespace: String,
    pub pod_name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pod_uid: Option<String>,
    pub policy_name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_uid: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secret_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secret_uid: Option<String>,
    pub correlation_id: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PodStopEvidenceBody {
    pub schema: String,
    pub worker_id: WorkerId,
    pub backend: String,
    pub cluster: String,
    pub namespace: String,
    pub pod_name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pod_uid: Option<String>,
    pub policy_name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_uid: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secret_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secret_uid: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secret_absent: Option<bool>,
    pub pod_absent: bool,
    pub policy_absent: bool,
    pub evidence_complete: bool,
    pub pod_residue: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub missing: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PodStopAudit {
    pub verdict: StopVerdictTag,
    pub action: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub residue: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub missing: Option<String>,
    pub evidence: PodStopEvidenceBody,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PodWorkerRow {
    pub worker_id: String,
    pub identity: PodWorkerIdentity,
    pub phase: String,
    pub audit: Option<PodStopAudit>,
    pub attempts: u64,
    pub retained_workspace: bool,
    pub release_attempted: bool,
    pub stop_admitted: bool,
}

const COLUMNS: &str = "worker_id, cluster, namespace, pod_name, pod_uid, policy_name, policy_uid, correlation_id, state, stop_audit_json, attempts, secret_name, secret_uid, retained_workspace, release_attempted, stop_admitted";

fn read_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<PodWorkerRow> {
    let json: Option<String> = row.get(9)?;
    let audit = json
        .map(|json| {
            serde_json::from_str(&json).map_err(|error| {
                rusqlite::Error::FromSqlConversionFailure(
                    9,
                    rusqlite::types::Type::Text,
                    Box::new(error),
                )
            })
        })
        .transpose()?;
    Ok(PodWorkerRow {
        worker_id: row.get(0)?,
        identity: PodWorkerIdentity {
            cluster: row.get(1)?,
            namespace: row.get(2)?,
            pod_name: row.get(3)?,
            pod_uid: row.get(4)?,
            policy_name: row.get(5)?,
            policy_uid: row.get(6)?,
            secret_name: row.get(11)?,
            secret_uid: row.get(12)?,
            correlation_id: row.get(7)?,
        },
        phase: row.get(8)?,
        audit,
        attempts: row.get(10)?,
        retained_workspace: row.get(13)?,
        release_attempted: row.get(14)?,
        stop_admitted: row.get(15)?,
    })
}

pub fn worker_row(conn: &Connection, worker: &str) -> LedgerResult<Option<PodWorkerRow>> {
    Ok(conn
        .query_row(
            &format!("SELECT {COLUMNS} FROM pod_worker_registry WHERE worker_id=?1"),
            [worker],
            read_row,
        )
        .optional()?)
}

pub fn worker_for_correlation(
    conn: &Connection,
    correlation: &str,
) -> LedgerResult<Option<PodWorkerRow>> {
    Ok(conn.query_row(&format!("SELECT {COLUMNS} FROM pod_worker_registry WHERE correlation_id=?1 ORDER BY (state <> 'stopped') DESC, created_at DESC, rowid DESC LIMIT 1"), [correlation], read_row).optional()?)
}

pub fn pending_rows(
    conn: &Connection,
    correlation: Option<&str>,
) -> LedgerResult<Vec<PodWorkerRow>> {
    let mut statement = conn.prepare(&format!("SELECT {COLUMNS} FROM pod_worker_registry WHERE state <> 'stopped' AND (?1 IS NULL OR correlation_id=?1) ORDER BY worker_id"))?;
    let rows = statement
        .query_map([correlation], read_row)?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(rows)
}

fn required(conn: &Connection, worker: &str) -> LedgerResult<PodWorkerRow> {
    worker_row(conn, worker)?.ok_or_else(|| LedgerError::NotFound {
        kind: "pod worker",
        id: worker.to_owned(),
    })
}

pub fn register_worker(
    tx: &Transaction<'_>,
    worker: &str,
    identity: &PodWorkerIdentity,
    now: OffsetDateTime,
) -> LedgerResult<()> {
    register_worker_with_retention(tx, worker, identity, false, now)
}

pub fn register_worker_with_retention(
    tx: &Transaction<'_>,
    worker: &str,
    identity: &PodWorkerIdentity,
    retained: bool,
    now: OffsetDateTime,
) -> LedgerResult<()> {
    if [
        worker,
        &identity.cluster,
        &identity.namespace,
        &identity.pod_name,
        &identity.policy_name,
        &identity.correlation_id,
    ]
    .iter()
    .any(|value| value.is_empty())
    {
        return Err(LedgerError::invalid_data(
            "pod intent contains an empty binding".to_owned(),
        ));
    }
    if identity.secret_name.as_deref() == Some("") || identity.secret_uid.is_some() {
        return Err(LedgerError::invalid_data(
            "secret intent must name an uncreated resource".to_owned(),
        ));
    }
    if identity.pod_uid.is_some() || identity.policy_uid.is_some() {
        return Err(LedgerError::invalid_data(
            "pod registration must precede resource creation".to_owned(),
        ));
    }
    if let Some(existing) = worker_row(tx, worker)? {
        let mut binding = existing.identity;
        binding.pod_uid = None;
        binding.policy_uid = None;
        binding.secret_uid = None;
        if binding == *identity
            && existing.phase == "registered"
            && existing.retained_workspace == retained
            && (!retained || !existing.release_attempted)
            && !existing.stop_admitted
        {
            return Ok(());
        }
        return Err(LedgerError::Conflict(
            "pod worker intent differs or is no longer registered".to_owned(),
        ));
    }
    let now = encode_utc(now)?;
    tx.execute("INSERT INTO pod_worker_registry(worker_id,cluster,namespace,pod_name,policy_name,correlation_id,secret_name,state,created_at,updated_at) VALUES (?1,?2,?3,?4,?5,?6,?7,'registered',?8,?8)",
        params![worker,identity.cluster,identity.namespace,identity.pod_name,identity.policy_name,identity.correlation_id,identity.secret_name,now])?;
    tx.execute(
        "UPDATE pod_worker_registry SET retained_workspace=?2 WHERE worker_id=?1",
        params![worker, retained],
    )?;
    Ok(())
}

pub fn record_proof(
    tx: &Transaction<'_>,
    worker: &str,
    pod_uid: Option<&str>,
    policy_uid: Option<&str>,
    now: OffsetDateTime,
) -> LedgerResult<()> {
    let row = required(tx, worker)?;
    if row.phase == "stopped" {
        return Err(LedgerError::Conflict(
            "stopped pod proof is immutable".to_owned(),
        ));
    }
    for (old, observed) in [
        (row.identity.pod_uid.as_deref(), pod_uid),
        (row.identity.policy_uid.as_deref(), policy_uid),
    ] {
        if observed == Some("") || matches!((old, observed), (Some(old), Some(new)) if old != new) {
            return Err(LedgerError::Conflict(
                "pod resource UID proof changed".to_owned(),
            ));
        }
    }
    tx.execute("UPDATE pod_worker_registry SET pod_uid=COALESCE(pod_uid,?2),policy_uid=COALESCE(policy_uid,?3),updated_at=?4 WHERE worker_id=?1 AND state=?5",
        params![worker,pod_uid,policy_uid,encode_utc(now)?,row.phase])?;
    Ok(())
}

pub fn record_secret_proof(
    tx: &Transaction<'_>,
    worker: &str,
    secret_uid: Option<&str>,
    now: OffsetDateTime,
) -> LedgerResult<()> {
    let row = required(tx, worker)?;
    if row.phase == "stopped"
        || secret_uid == Some("")
        || (secret_uid.is_some() && row.identity.secret_name.is_none())
        || matches!((row.identity.secret_uid.as_deref(), secret_uid), (Some(old), Some(new)) if old != new)
    {
        return Err(LedgerError::Conflict(
            "secret UID proof changed or lacks intent".to_owned(),
        ));
    }
    tx.execute("UPDATE pod_worker_registry SET secret_uid=COALESCE(secret_uid,?2),updated_at=?3 WHERE worker_id=?1 AND state=?4",
        params![worker,secret_uid,encode_utc(now)?,row.phase])?;
    Ok(())
}

/// Once a gate release is attempted, absence of its acknowledgement cannot
/// prove that the workspace remained unused. This bit is never cleared.
pub fn mark_release_attempted(
    tx: &Transaction<'_>,
    worker: &str,
    now: OffsetDateTime,
) -> LedgerResult<()> {
    let changed = tx.execute("UPDATE pod_worker_registry SET release_attempted=1,updated_at=?2 WHERE worker_id=?1 AND state='registered' AND stop_admitted=0", params![worker, encode_utc(now)?])?;
    if changed != 1 {
        return Err(LedgerError::Conflict(
            "pod release is no longer permitted".to_owned(),
        ));
    }
    Ok(())
}

pub fn admit_stop(
    tx: &Transaction<'_>,
    worker: &str,
    expected: &PodWorkerIdentity,
    now: OffsetDateTime,
) -> LedgerResult<()> {
    let row = required(tx, worker)?;
    if !row.retained_workspace || row.identity != *expected {
        return Err(LedgerError::Conflict(
            "retained pod stop admission binding differs".to_owned(),
        ));
    }
    tx.execute(
        "UPDATE pod_worker_registry SET stop_admitted=1,updated_at=?2 WHERE worker_id=?1",
        params![worker, encode_utc(now)?],
    )?;
    Ok(())
}

impl PodWorkerRow {
    pub fn stop_requires_admission(&self) -> bool {
        self.retained_workspace
            && (self.release_attempted || self.phase == "released")
            && !self.stop_admitted
    }
}

pub fn mark_released(tx: &Transaction<'_>, worker: &str, now: OffsetDateTime) -> LedgerResult<()> {
    let changed = tx.execute("UPDATE pod_worker_registry SET state='released',updated_at=?2 WHERE worker_id=?1 AND state='registered' AND pod_uid IS NOT NULL AND policy_uid IS NOT NULL AND (secret_name IS NULL OR secret_uid IS NOT NULL)", params![worker,encode_utc(now)?])?;
    if changed != 1 {
        return Err(LedgerError::Conflict(
            "pod worker cannot release in its current phase".to_owned(),
        ));
    }
    Ok(())
}

pub fn request_stop(
    tx: &Transaction<'_>,
    worker: &str,
    audit: &PodStopAudit,
    now: OffsetDateTime,
) -> LedgerResult<()> {
    let row = required(tx, worker)?;
    if row.stop_requires_admission() {
        return Err(LedgerError::Conflict(
            "retained pod requires explicit stop admission".to_owned(),
        ));
    }
    if row.phase == "stopped" || row.phase == "stopping" {
        return Ok(());
    }
    let now = encode_utc(now)?;
    let audit_json = serde_json::to_string(audit)?;
    tx.execute(
        "INSERT INTO pod_stop_intent (
             worker_id, correlation_id, action, state, evidence_json, attempts,
             requested_at, updated_at, settled_at
         ) VALUES (?1, ?2, 'delete', 'requested', ?3, 0, ?4, ?4, NULL)
         ON CONFLICT(worker_id) DO NOTHING",
        params![worker, row.identity.correlation_id, audit_json, now],
    )?;
    tx.execute("UPDATE pod_worker_registry SET state='stopping',stop_audit_json=?2,requested_at=?3,updated_at=?3 WHERE worker_id=?1 AND state=?4", params![worker,audit_json,now,row.phase])?;
    Ok(())
}

pub fn record_stop(
    tx: &Transaction<'_>,
    worker: &str,
    audit: &PodStopAudit,
    now: OffsetDateTime,
) -> LedgerResult<()> {
    let row = required(tx, worker)?;
    let body = &audit.evidence;
    if row.phase != "stopping"
        || body.worker_id.as_str() != worker
        || body.schema != "odin.pod-stop-evidence.v1"
        || body.backend != "kube.pod"
        || body.cluster != row.identity.cluster
        || body.namespace != row.identity.namespace
        || body.pod_name != row.identity.pod_name
        || body.pod_uid != row.identity.pod_uid
        || body.policy_name != row.identity.policy_name
        || body.policy_uid != row.identity.policy_uid
        || body.secret_name != row.identity.secret_name
        || body.secret_uid != row.identity.secret_uid
        || body.secret_absent.is_some() != row.identity.secret_name.is_some()
        || audit.action != "delete"
    {
        return Err(LedgerError::Conflict(
            "pod stop evidence binding or phase differs".to_owned(),
        ));
    }
    let stopped = audit.verdict == StopVerdictTag::Stopped;
    if stopped
        && (body.pod_uid.is_none()
            || body.policy_uid.is_none()
            || (body.secret_name.is_some() && body.secret_uid.is_none()))
    {
        return Err(LedgerError::invalid_data(
            "pod creation outcome is uncertain without all resource UIDs".to_owned(),
        ));
    }
    if stopped
        && (!body.evidence_complete
            || !body.pod_absent
            || !body.policy_absent
            || body.secret_absent == Some(false)
            || !body.pod_residue.is_empty()
            || body.missing.is_some()
            || audit.missing.is_some()
            || audit.residue.is_some())
    {
        return Err(LedgerError::invalid_data(
            "pod stopped verdict lacks complete absence evidence".to_owned(),
        ));
    }
    let now = encode_utc(now)?;
    let audit_json = serde_json::to_string(audit)?;
    tx.execute(
        "UPDATE pod_stop_intent
             SET state=?2, evidence_json=?3, attempts=attempts+1, updated_at=?4, settled_at=?5
             WHERE worker_id=?1 AND state='requested'",
        params![
            worker,
            if stopped { "stopped" } else { "requested" },
            audit_json,
            now,
            if stopped { Some(&now) } else { None }
        ],
    )?;
    tx.execute("UPDATE pod_worker_registry SET state=?2,stop_audit_json=?3,attempts=attempts+1,updated_at=?4,settled_at=?5 WHERE worker_id=?1 AND state='stopping'", params![worker,if stopped {"stopped"} else {"stopping"},audit_json,now,if stopped {Some(&now)} else {None}])?;
    Ok(())
}

#[cfg(test)]
mod tests;
