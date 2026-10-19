use super::job::{JobReleaseEvidence, JobStopEvidenceRecord, JobStopOutcome, JobWorkerIdentity};
use super::types::{StopEvidenceRecord, StopOutcome};
use super::StopAuthorityError;
use odin_domain::{
    InvocationId, StopAudit, StopEvidence, StopFaultProbe, StopMissing, StopResidue,
    StopResidueProcess, StopTraceEvent, StopTraceRow, StopVerdict, StopVerdictTag,
    STOP_AUTHORITY_TRACE_SCHEMA,
};
use odin_ledger::stop as stop_store;
use odin_ledger::worker as worker_store;
use odin_process::{RecoveryAnchors, WorkerAuthority, WorkerInspection, WorkerStopReport};
use odin_types::{CorrelationId, WorkerId};
use std::time::Instant;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

pub(super) fn actuate_concrete(
    row: &worker_store::WorkerRow,
    mut trace: Vec<StopTraceRow>,
    recovered: bool,
    authority: &mut WorkerAuthority,
    deadline: Option<Instant>,
) -> StopAudit {
    let stopped = match deadline {
        Some(deadline) => authority.stop_bounded(deadline),
        None => authority.stop(),
    };
    let report = match stopped {
        Ok(report) => report,
        Err(error) => {
            return indeterminate_audit(
                row,
                trace,
                recovered,
                false,
                false,
                format!("stop worker failed: {error}"),
            );
        }
    };
    if report.frozen {
        push_trace(&mut trace, &row.worker_id, StopTraceEvent::Freeze);
    }
    if report.term_sent {
        push_trace(&mut trace, &row.worker_id, StopTraceEvent::Term);
    }
    if report.cgroup_kill {
        push_trace(&mut trace, &row.worker_id, StopTraceEvent::CgroupKill);
    }
    match authority.inspection() {
        Ok(inspection) => {
            if inspection.leader_reaped {
                push_trace(&mut trace, &row.worker_id, StopTraceEvent::Reap);
            }
            push_trace(&mut trace, &row.worker_id, StopTraceEvent::ResidueQuery);
            audit_from_inspection(row, trace, recovered, report, inspection)
        }
        Err(error) => indeterminate_audit(
            row,
            trace,
            recovered,
            report.term_sent,
            report.cgroup_kill,
            format!("independent post-stop proof failed: {error}"),
        ),
    }
}

pub(super) fn validate_worker_id(
    requested: &WorkerId,
    row: &worker_store::WorkerRow,
) -> Result<(), StopAuthorityError> {
    if requested.as_str() != row.worker_id {
        return Err(StopAuthorityError::InvalidWorker(format!(
            "logical worker lookup returned {:?} for {:?}",
            row.worker_id,
            requested.as_str()
        )));
    }
    WorkerId::new(&row.worker_id).map_err(|error| {
        StopAuthorityError::InvalidWorker(format!("worker id {:?}: {error}", row.worker_id))
    })?;
    CorrelationId::new(&row.correlation_id).map_err(|error| {
        StopAuthorityError::InvalidWorker(format!(
            "worker {} correlation {:?}: {error}",
            row.worker_id, row.correlation_id
        ))
    })?;
    Ok(())
}

pub(super) fn parse_recovery(
    row: &worker_store::WorkerRow,
) -> Result<(InvocationId, RecoveryAnchors), String> {
    let invocation_raw = row
        .invocation_id
        .as_deref()
        .ok_or_else(|| "worker has no proven InvocationID".to_owned())?;
    let invocation = InvocationId::from_hex(invocation_raw)
        .map_err(|error| format!("worker InvocationID is invalid: {error}"))?;
    let cgroup_path = row
        .cgroup_path
        .clone()
        .ok_or_else(|| "worker has no proven cgroup path".to_owned())?;
    let cgroup_inode = row
        .cgroup_inode
        .ok_or_else(|| "worker has no proven cgroup inode".to_owned())?;
    let leader_pid = row
        .leader_pid
        .ok_or_else(|| "worker has no proven leader PID".to_owned())?;
    let leader_start_ticks = row
        .leader_start_ticks
        .ok_or_else(|| "worker has no proven leader start identity".to_owned())?;
    Ok((
        invocation,
        RecoveryAnchors {
            cgroup_path,
            cgroup_inode,
            leader_pid,
            leader_start_ticks,
        },
    ))
}

// A terminal launch may still be starting immediately after registration.
pub(super) const ABANDONED_REGISTRATION: time::Duration = time::Duration::minutes(10);

pub(super) fn abandoned_registration_audit(
    row: &worker_store::WorkerRow,
    now: OffsetDateTime,
    unit_absent: impl FnOnce() -> bool,
) -> Result<Option<StopAudit>, StopAuthorityError> {
    if row.invocation_id.is_some() || row.phase != odin_domain::WorkerPhase::Registered {
        return Ok(None);
    }
    let updated = OffsetDateTime::parse(&row.updated_at, &Rfc3339).map_err(|error| {
        StopAuthorityError::InvalidWorker(format!(
            "read worker {} registration time failed: {error}",
            row.worker_id
        ))
    })?;
    if now - updated < ABANDONED_REGISTRATION || !unit_absent() {
        return Ok(None);
    }
    let mut audit = requested_audit(row);
    push_trace(
        &mut audit.trace,
        &row.worker_id,
        StopTraceEvent::ResidueQuery,
    );
    audit.verdict = StopVerdictTag::Stopped;
    audit.recovered = true;
    audit.unit_identity_verified = true;
    audit.evidence.leader_reaped = true;
    audit.evidence.cgroup_descendants = 0;
    audit.evidence.evidence_complete = true;
    Ok(Some(audit))
}

pub(super) fn requested_audit(row: &worker_store::WorkerRow) -> StopAudit {
    let mut trace = Vec::new();
    push_trace(&mut trace, &row.worker_id, StopTraceEvent::Resolve);
    push_trace(&mut trace, &row.worker_id, StopTraceEvent::Intent);
    StopAudit {
        verdict: StopVerdictTag::Requested,
        recovered: false,
        term_sent: false,
        cgroup_kill: false,
        unit_identity_verified: false,
        residue: None,
        missing: None,
        evidence: StopEvidence::new(
            row.worker_id.clone(),
            row.unit.clone(),
            row.cgroup_path.clone().unwrap_or_default(),
        ),
        trace,
    }
}

pub(super) fn audit_from_inspection(
    row: &worker_store::WorkerRow,
    trace: Vec<StopTraceRow>,
    recovered: bool,
    report: WorkerStopReport,
    inspection: WorkerInspection,
) -> StopAudit {
    let mut processes = inspection.processes.clone();
    if let Some(leader) = &inspection.leader {
        if !processes.iter().any(|process| {
            process.pid == leader.pid && process.start_time_ticks == leader.start_time_ticks
        }) {
            processes.push(leader.clone());
        }
    }
    processes.sort_by_key(|process| (process.pid, process.start_time_ticks));
    let residue = StopResidue {
        unit_active: inspection.unit_active,
        cgroup_present: inspection.cgroup_present,
        processes: processes
            .into_iter()
            .map(|process| StopResidueProcess {
                pid: process.pid,
                start_time_ticks: process.start_time_ticks,
            })
            .collect(),
    };
    let verdict = if !residue.is_empty() || inspection.cgroup_descendants != 0 {
        StopVerdict::Failed(residue)
    } else if inspection.unit_identity_verified
        && inspection.leader_reaped
        && inspection.cgroup_descendants == 0
    {
        StopVerdict::Stopped
    } else {
        StopVerdict::Indeterminate(StopMissing {
            reason: "post-stop evidence did not prove identity and reap".to_owned(),
        })
    };
    let (residue, missing) = match &verdict {
        StopVerdict::Failed(residue) => (Some(residue.clone()), None),
        StopVerdict::Indeterminate(missing) => (None, Some(missing.clone())),
        StopVerdict::Requested | StopVerdict::Stopped => (None, None),
    };
    StopAudit {
        verdict: verdict.tag(),
        recovered,
        term_sent: report.term_sent,
        cgroup_kill: report.cgroup_kill,
        unit_identity_verified: inspection.unit_identity_verified,
        residue,
        missing,
        evidence: StopEvidence {
            schema: odin_domain::WORKER_STOP_EVIDENCE_SCHEMA.to_owned(),
            worker_id: row.worker_id.clone(),
            unit: row.unit.clone(),
            cgroup: row.cgroup_path.clone().unwrap_or_default(),
            leader_reaped: inspection.leader_reaped,
            cgroup_descendants: inspection.cgroup_descendants,
            evidence_complete: true,
            fault_probes: Vec::<StopFaultProbe>::new(),
        },
        trace,
    }
}

pub(super) fn indeterminate_audit(
    row: &worker_store::WorkerRow,
    trace: Vec<StopTraceRow>,
    recovered: bool,
    term_sent: bool,
    cgroup_kill: bool,
    reason: String,
) -> StopAudit {
    StopAudit {
        verdict: StopVerdictTag::Indeterminate,
        recovered,
        term_sent,
        cgroup_kill,
        unit_identity_verified: false,
        residue: None,
        missing: Some(StopMissing { reason }),
        evidence: StopEvidence::new(
            row.worker_id.clone(),
            row.unit.clone(),
            row.cgroup_path.clone().unwrap_or_default(),
        ),
        trace,
    }
}

pub(super) fn push_trace(trace: &mut Vec<StopTraceRow>, worker_id: &str, event: StopTraceEvent) {
    let seq = u64::try_from(trace.len())
        .ok()
        .and_then(|length| length.checked_add(1))
        .unwrap_or(u64::MAX);
    trace.push(StopTraceRow {
        schema: STOP_AUTHORITY_TRACE_SCHEMA.to_owned(),
        seq,
        event,
        worker_id: worker_id.to_owned(),
        path: None,
    });
}

pub(super) fn outcome_from_row(
    row: stop_store::StopRow,
    replay: bool,
) -> Result<StopOutcome, StopAuthorityError> {
    let worker_id = WorkerId::new(&row.worker_id).map_err(|error| {
        StopAuthorityError::InvalidWorker(format!("worker id {:?}: {error}", row.worker_id))
    })?;
    let audit: StopAudit = serde_json::from_str(&row.evidence_json)?;
    outcome_from_audit(worker_id, audit, replay)
}

pub(super) fn outcome_from_audit(
    worker_id: WorkerId,
    audit: StopAudit,
    replay: bool,
) -> Result<StopOutcome, StopAuthorityError> {
    let verdict = audit.stop_verdict().map_err(|error| {
        StopAuthorityError::InvalidWorker(format!(
            "stop audit for {} is invalid: {error}",
            worker_id.as_str()
        ))
    })?;
    Ok(StopOutcome {
        worker_id,
        verdict,
        replay,
        evidence: audit.evidence,
        trace: audit.trace,
    })
}

pub(super) fn record_from_row(
    row: stop_store::StopRow,
) -> Result<StopEvidenceRecord, StopAuthorityError> {
    let worker_id = WorkerId::new(&row.worker_id).map_err(|error| {
        StopAuthorityError::InvalidWorker(format!("worker id {:?}: {error}", row.worker_id))
    })?;
    let correlation_id = CorrelationId::new(&row.correlation_id).map_err(|error| {
        StopAuthorityError::InvalidWorker(format!(
            "worker {} correlation {:?}: {error}",
            row.worker_id, row.correlation_id
        ))
    })?;
    let evidence: StopAudit = serde_json::from_str(&row.evidence_json)?;
    evidence.stop_verdict().map_err(|error| {
        StopAuthorityError::InvalidWorker(format!(
            "stop audit for {} is invalid: {error}",
            row.worker_id
        ))
    })?;
    Ok(StopEvidenceRecord {
        worker_id,
        correlation_id,
        state: row.state,
        evidence,
        attempts: row.attempts,
        requested_at: row.requested_at,
        updated_at: row.updated_at,
        settled_at: row.settled_at,
    })
}

pub(super) fn job_identity(row: &worker_store::JobWorkerRow) -> JobWorkerIdentity {
    JobWorkerIdentity {
        cluster: row.cluster.clone(),
        namespace: row.namespace.clone(),
        job_name: row.job_name.clone(),
        job_uid: row.job_uid.clone(),
    }
}

pub(super) fn validate_job_worker_id(
    requested: &WorkerId,
    row: &worker_store::JobWorkerRow,
) -> Result<(), StopAuthorityError> {
    if requested.as_str() != row.worker_id {
        return Err(StopAuthorityError::InvalidWorker(format!(
            "job worker lookup returned {:?} for {:?}",
            row.worker_id,
            requested.as_str()
        )));
    }
    WorkerId::new(&row.worker_id).map_err(|error| {
        StopAuthorityError::InvalidWorker(format!("worker id {:?}: {error}", row.worker_id))
    })?;
    CorrelationId::new(&row.correlation_id).map_err(|error| {
        StopAuthorityError::InvalidWorker(format!(
            "job worker {} correlation {:?}: {error}",
            row.worker_id, row.correlation_id
        ))
    })?;
    if row.backend != stop_store::JOB_BACKEND_TAG {
        return Err(StopAuthorityError::InvalidWorker(format!(
            "job worker {} names unknown backend {:?}",
            row.worker_id, row.backend
        )));
    }
    Ok(())
}

pub(super) fn job_stopping_from(
    phase: worker_store::JobWorkerPhase,
) -> Option<worker_store::JobWorkerPhase> {
    match phase {
        worker_store::JobWorkerPhase::Registered | worker_store::JobWorkerPhase::Released => {
            Some(phase)
        }
        _ => None,
    }
}

fn job_requested_body(row: &worker_store::JobWorkerRow) -> stop_store::JobStopEvidenceBody {
    stop_store::JobStopEvidenceBody {
        schema: stop_store::JOB_STOP_EVIDENCE_SCHEMA.to_owned(),
        worker_id: row.worker_id.clone(),
        backend: row.backend.clone(),
        cluster: row.cluster.clone(),
        namespace: row.namespace.clone(),
        job_name: row.job_name.clone(),
        job_uid: row.job_uid.clone(),
        job_absent: false,
        job_suspended: None,
        pod_residue: Vec::new(),
        evidence_complete: false,
        fault_probes: Vec::new(),
    }
}

pub(super) fn requested_job_audit(
    row: &worker_store::JobWorkerRow,
    action: stop_store::JobStopAction,
) -> stop_store::JobStopAudit {
    let mut trace = Vec::new();
    push_trace(&mut trace, &row.worker_id, StopTraceEvent::Resolve);
    push_trace(&mut trace, &row.worker_id, StopTraceEvent::Intent);
    stop_store::JobStopAudit {
        verdict: StopVerdictTag::Requested,
        recovered: false,
        action,
        residue: None,
        missing: None,
        evidence: job_requested_body(row),
        trace,
    }
}

pub(super) fn indeterminate_job_audit(
    row: &worker_store::JobWorkerRow,
    action: stop_store::JobStopAction,
    trace: Vec<StopTraceRow>,
    recovered: bool,
    reason: String,
) -> stop_store::JobStopAudit {
    indeterminate_job_audit_with(action, job_requested_body(row), trace, recovered, reason)
}

fn indeterminate_job_audit_with(
    action: stop_store::JobStopAction,
    body: stop_store::JobStopEvidenceBody,
    trace: Vec<StopTraceRow>,
    recovered: bool,
    reason: String,
) -> stop_store::JobStopAudit {
    stop_store::JobStopAudit {
        verdict: StopVerdictTag::Indeterminate,
        recovered,
        action,
        residue: None,
        missing: Some(StopMissing { reason }),
        evidence: body,
        trace,
    }
}

pub(super) fn job_audit_from_body(
    row: &worker_store::JobWorkerRow,
    action: stop_store::JobStopAction,
    trace: Vec<StopTraceRow>,
    body: stop_store::JobStopEvidenceBody,
) -> stop_store::JobStopAudit {
    let binding_matches = body.worker_id == row.worker_id
        && body.backend == row.backend
        && body.cluster == row.cluster
        && body.namespace == row.namespace
        && body.job_name == row.job_name
        && body.job_uid == row.job_uid;
    if !binding_matches {
        return indeterminate_job_audit(
            row,
            action,
            trace,
            false,
            "backend evidence names a different Job worker identity".to_owned(),
        );
    }
    if !body.evidence_complete {
        return indeterminate_job_audit_with(
            action,
            body,
            trace,
            false,
            "backend reported incomplete evidence".to_owned(),
        );
    }
    let workload_gone = body.job_absent || body.job_suspended == Some(true);
    let (verdict, residue, missing) = if !workload_gone {
        (
            StopVerdictTag::Indeterminate,
            None,
            Some(StopMissing {
                reason: "backend evidence shows the workload neither deleted nor suspended"
                    .to_owned(),
            }),
        )
    } else if body.pod_residue.is_empty() {
        (StopVerdictTag::Stopped, None, None)
    } else {
        (
            StopVerdictTag::Failed,
            Some(stop_store::JobStopResidue {
                pods: body.pod_residue.clone(),
            }),
            None,
        )
    };
    stop_store::JobStopAudit {
        verdict,
        recovered: false,
        action,
        residue,
        missing,
        evidence: body,
        trace,
    }
}

pub(super) fn release_binding_matches(
    requested: &WorkerId,
    row: &worker_store::JobWorkerRow,
    proof: &JobReleaseEvidence,
) -> bool {
    requested.as_str() == row.worker_id
        && proof.backend == row.backend
        && proof.cluster == row.cluster
        && proof.namespace == row.namespace
        && proof.job_name == row.job_name
        && proof.job_uid == row.job_uid
}

pub(super) fn job_outcome_from_row(
    row: stop_store::JobStopRow,
    replay: bool,
) -> Result<JobStopOutcome, StopAuthorityError> {
    let worker_id = WorkerId::new(&row.worker_id).map_err(|error| {
        StopAuthorityError::InvalidWorker(format!("worker id {:?}: {error}", row.worker_id))
    })?;
    let audit: stop_store::JobStopAudit = serde_json::from_str(&row.evidence_json)?;
    job_outcome_from_audit(worker_id, audit, replay)
}

pub(super) fn job_outcome_from_audit(
    worker_id: WorkerId,
    audit: stop_store::JobStopAudit,
    replay: bool,
) -> Result<JobStopOutcome, StopAuthorityError> {
    audit.verify().map_err(|reason| {
        StopAuthorityError::InvalidWorker(format!(
            "job stop audit for {} is invalid: {reason}",
            worker_id.as_str()
        ))
    })?;
    let trace = audit.trace.clone();
    Ok(JobStopOutcome {
        worker_id,
        verdict: audit.verdict,
        replay,
        evidence: audit.evidence,
        trace,
    })
}

pub(super) fn job_record_from_row(
    row: stop_store::JobStopRow,
) -> Result<JobStopEvidenceRecord, StopAuthorityError> {
    let worker_id = WorkerId::new(&row.worker_id).map_err(|error| {
        StopAuthorityError::InvalidWorker(format!("worker id {:?}: {error}", row.worker_id))
    })?;
    let correlation_id = CorrelationId::new(&row.correlation_id).map_err(|error| {
        StopAuthorityError::InvalidWorker(format!(
            "worker {} correlation {:?}: {error}",
            row.worker_id, row.correlation_id
        ))
    })?;
    let evidence: stop_store::JobStopAudit = serde_json::from_str(&row.evidence_json)?;
    evidence.verify().map_err(|reason| {
        StopAuthorityError::InvalidWorker(format!(
            "job stop audit for {} is invalid: {reason}",
            row.worker_id
        ))
    })?;
    Ok(JobStopEvidenceRecord {
        worker_id,
        correlation_id,
        state: row.state,
        evidence,
        attempts: row.attempts,
        requested_at: row.requested_at,
        updated_at: row.updated_at,
        settled_at: row.settled_at,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use odin_domain::WorkerPhase;

    #[test]
    fn an_abandoned_registration_with_no_unit_is_proven_stopped() {
        let row = worker_store::WorkerRow {
            worker_id: "worker-abandoned".to_owned(),
            unit: "odind-omp-attempt-1-3bfca6e1.scope".to_owned(),
            invocation_id: None,
            correlation_id: "22222222222222222222222222222222".to_owned(),
            tx_id: "odind".to_owned(),
            wp_id: "omp".to_owned(),
            attempt: 1,
            cgroup_path: None,
            cgroup_inode: None,
            leader_pid: None,
            leader_start_ticks: None,
            phase: WorkerPhase::Registered,
            residue_json: "{}".to_owned(),
            created_at: "2026-09-08T06:29:41.893826205Z".to_owned(),
            updated_at: "2026-09-08T06:29:41.893826205Z".to_owned(),
        };
        let registered = OffsetDateTime::parse(&row.updated_at, &Rfc3339).unwrap();
        let later = registered + time::Duration::days(25);
        let audit = abandoned_registration_audit(&row, later, || true)
            .unwrap()
            .expect("abandoned");
        assert_eq!(audit.stop_verdict().unwrap(), StopVerdict::Stopped);
        assert!(audit.evidence.evidence_complete);
        assert!(
            abandoned_registration_audit(&row, later, || false)
                .unwrap()
                .is_none(),
            "a unit the manager holds is never assumed stopped"
        );
        assert!(
            abandoned_registration_audit(&row, registered + time::Duration::seconds(5), || true)
                .unwrap()
                .is_none(),
            "a fresh registration's launch may still be in flight"
        );
        let launched = worker_store::WorkerRow {
            invocation_id: Some("11111111111111111111111111111111".to_owned()),
            ..row.clone()
        };
        assert!(abandoned_registration_audit(&launched, later, || true)
            .unwrap()
            .is_none());
    }

    #[test]
    fn stop_verdict_matrix() {
        let row = worker_store::WorkerRow {
            worker_id: "worker-matrix".to_owned(),
            unit: "tx-wp-attempt-1-deadbeef.scope".to_owned(),
            invocation_id: Some("11111111111111111111111111111111".to_owned()),
            correlation_id: "22222222222222222222222222222222".to_owned(),
            tx_id: "tx".to_owned(),
            wp_id: "wp".to_owned(),
            attempt: 1,
            cgroup_path: Some("/odin/tx-wp-attempt-1-deadbeef.scope".to_owned()),
            cgroup_inode: Some(9),
            leader_pid: Some(42),
            leader_start_ticks: Some(99),
            phase: WorkerPhase::PayloadRunning,
            residue_json: "{}".to_owned(),
            created_at: "2026-09-05T00:00:00Z".to_owned(),
            updated_at: "2026-09-05T00:00:00Z".to_owned(),
        };
        let requested = requested_audit(&row);
        assert_eq!(requested.stop_verdict().unwrap(), StopVerdict::Requested);

        let clean = audit_from_inspection(
            &row,
            Vec::new(),
            true,
            WorkerStopReport {
                frozen: true,
                term_sent: true,
                cgroup_kill: true,
                stopped: true,
                residual: None,
            },
            WorkerInspection {
                unit_identity_verified: true,
                leader_reaped: true,
                ..WorkerInspection::default()
            },
        );
        assert_eq!(clean.stop_verdict().unwrap(), StopVerdict::Stopped);

        let residual = audit_from_inspection(
            &row,
            Vec::new(),
            true,
            WorkerStopReport::default(),
            WorkerInspection {
                unit_identity_verified: true,
                unit_active: true,
                cgroup_present: true,
                cgroup_descendants: 1,
                leader_reaped: true,
                ..WorkerInspection::default()
            },
        );
        assert!(matches!(
            residual.stop_verdict().unwrap(),
            StopVerdict::Failed(StopResidue {
                unit_active: true,
                cgroup_present: true,
                ..
            })
        ));

        let unknown = indeterminate_audit(
            &row,
            Vec::new(),
            true,
            false,
            false,
            "manager query unavailable".to_owned(),
        );
        assert!(matches!(
            unknown.stop_verdict().unwrap(),
            StopVerdict::Indeterminate(StopMissing { .. })
        ));
    }
}
