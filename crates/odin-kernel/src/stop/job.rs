use std::sync::Arc;

use odin_domain::{StopState, StopTraceEvent, StopTraceRow, StopVerdictTag};
use odin_ledger::stop as stop_store;
use odin_ledger::worker as worker_store;
use odin_types::{CorrelationId, WorkerId};
use time::OffsetDateTime;

use super::evidence::{
    indeterminate_job_audit, job_audit_from_body, job_identity, job_outcome_from_audit,
    job_outcome_from_row, job_record_from_row, job_stopping_from, push_trace,
    release_binding_matches, requested_job_audit, validate_job_worker_id,
};
use super::{StopAuthority, StopAuthorityError};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JobWorkerIdentity {
    pub cluster: String,
    pub namespace: String,
    pub job_name: String,
    pub job_uid: String,
}

#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum JobWorkerBackendFault {
    #[error("job backend is unavailable: {reason}")]
    Unavailable { reason: String },
    #[error("job backend rejected the operation: {reason}")]
    Rejected { reason: String },
    #[error("job backend observed a conflicting workload: {reason}")]
    Conflict { reason: String },
    #[error("job backend input is invalid: {reason}")]
    Invalid { reason: String },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JobReleaseEvidence {
    pub backend: String,
    pub cluster: String,
    pub namespace: String,
    pub job_name: String,
    pub job_uid: String,
    pub job_present: bool,
    pub job_suspended: Option<bool>,
    pub evidence_complete: bool,
    pub fault_probes: Vec<odin_ledger::stop::JobFaultProbe>,
    pub missing: Option<String>,
}

pub trait JobWorkerBackend: Send + Sync {
    fn tag(&self) -> &'static str;

    fn release(
        &self,
        worker_id: &WorkerId,
        identity: &JobWorkerIdentity,
    ) -> Result<JobReleaseEvidence, JobWorkerBackendFault>;

    fn stop(
        &self,
        worker_id: &WorkerId,
        identity: &JobWorkerIdentity,
        action: odin_ledger::stop::JobStopAction,
    ) -> Result<odin_ledger::stop::JobStopEvidenceBody, JobWorkerBackendFault>;
}

#[derive(Clone, Debug)]
pub struct JobWorkerRegistration<'a> {
    pub worker_id: &'a WorkerId,
    pub identity: &'a JobWorkerIdentity,
    pub correlation_id: &'a CorrelationId,
    pub operation_id: &'a str,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum JobWorkerRegistrationOutcome {
    Inserted,
    Replay,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JobReleaseOutcome {
    pub worker_id: WorkerId,
    pub applied: bool,
    pub evidence: JobReleaseEvidence,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JobStopOutcome {
    pub worker_id: WorkerId,
    pub verdict: StopVerdictTag,
    pub replay: bool,
    pub evidence: odin_ledger::stop::JobStopEvidenceBody,
    pub trace: Vec<StopTraceRow>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JobStopEvidenceRecord {
    pub worker_id: WorkerId,
    pub correlation_id: CorrelationId,
    pub state: StopState,
    pub evidence: odin_ledger::stop::JobStopAudit,
    pub attempts: u64,
    pub requested_at: String,
    pub updated_at: String,
    pub settled_at: Option<String>,
}

impl StopAuthority {
    pub fn register_job_backend(&self, backend: Arc<dyn JobWorkerBackend>) {
        match self.job_backend.lock() {
            Ok(mut slot) => *slot = Some(backend),
            Err(error) => tracing::error!(error = %error, "Register job backend failed"),
        }
    }

    pub fn register_job_worker(
        &self,
        registration: JobWorkerRegistration<'_>,
    ) -> Result<JobWorkerRegistrationOutcome, StopAuthorityError> {
        let outcome = {
            let mut ledger = self.lock_store()?;
            ledger.with_tx(|tx| {
                worker_store::register_job_worker(
                    tx,
                    &worker_store::NewJobWorker {
                        worker_id: registration.worker_id.as_str(),
                        cluster: &registration.identity.cluster,
                        namespace: &registration.identity.namespace,
                        job_name: &registration.identity.job_name,
                        job_uid: &registration.identity.job_uid,
                        correlation_id: registration.correlation_id.as_str(),
                        operation_id: registration.operation_id,
                        now: OffsetDateTime::now_utc(),
                    },
                )
            })?
        };
        Ok(match outcome {
            worker_store::JobRegisterOutcome::Inserted => JobWorkerRegistrationOutcome::Inserted,
            worker_store::JobRegisterOutcome::Replay { .. } => JobWorkerRegistrationOutcome::Replay,
        })
    }

    pub fn release_job_worker(
        &self,
        worker_id: &WorkerId,
    ) -> Result<JobReleaseOutcome, StopAuthorityError> {
        let row = self.job_worker_row(worker_id)?;
        if row.phase != worker_store::JobWorkerPhase::Registered {
            return Err(StopAuthorityError::JobBackend(format!(
                "release job {}: worker is {}, not registered",
                worker_id.as_str(),
                row.phase.as_str()
            )));
        }
        let backend = self.registered_job_backend(&row)?.ok_or_else(|| {
            StopAuthorityError::JobBackend(format!(
                "release job {}: no backend is registered",
                worker_id.as_str()
            ))
        })?;
        let identity = job_identity(&row);
        let proof = backend.release(worker_id, &identity).map_err(|error| {
            StopAuthorityError::JobBackend(format!(
                "release job {} failed: {error}",
                worker_id.as_str()
            ))
        })?;
        if !release_binding_matches(worker_id, &row, &proof) {
            return Err(StopAuthorityError::JobBackend(format!(
                "release job {}: backend returned a different Job identity",
                worker_id.as_str()
            )));
        }
        let proved =
            proof.evidence_complete && proof.job_present && proof.job_suspended == Some(false);
        if !proved {
            return Err(StopAuthorityError::JobBackend(format!(
                "release job {}: {}",
                worker_id.as_str(),
                proof.missing.as_deref().unwrap_or("Job is not running")
            )));
        }
        let mut ledger = self.lock_store()?;
        ledger.with_tx(|tx| {
            worker_store::mark_job_released(tx, worker_id.as_str(), OffsetDateTime::now_utc())
        })?;
        Ok(JobReleaseOutcome {
            worker_id: worker_id.clone(),
            applied: true,
            evidence: proof,
        })
    }

    pub fn stop_job_worker(
        &self,
        worker_id: &WorkerId,
        action: odin_ledger::stop::JobStopAction,
    ) -> Result<JobStopOutcome, StopAuthorityError> {
        let row = self.job_worker_row(worker_id)?;
        validate_job_worker_id(worker_id, &row)?;
        let requested = requested_job_audit(&row, action);

        let requested_json = serde_json::to_string(&requested)?;
        let intent = {
            let mut ledger = self.lock_store()?;
            ledger.with_tx(|tx| {
                let outcome = stop_store::request_job_stop(
                    tx,
                    worker_id.as_str(),
                    &row.correlation_id,
                    action,
                    &requested_json,
                    OffsetDateTime::now_utc(),
                )?;
                if matches!(&outcome, stop_store::JobStopIntentOutcome::Inserted) {
                    if let Some(phase) = job_stopping_from(row.phase) {
                        worker_store::mark_job_stopping(
                            tx,
                            worker_id.as_str(),
                            phase,
                            OffsetDateTime::now_utc(),
                        )?;
                    }
                }
                Ok(outcome)
            })?
        };
        if let stop_store::JobStopIntentOutcome::Replay { row: existing } = intent {
            if existing.state.is_terminal() {
                return job_outcome_from_row(*existing, true);
            }
        }

        let audit = match self.registered_job_backend(&row)? {
            Some(backend) => self.actuate_job(worker_id, &row, action, backend),
            None => indeterminate_job_audit(
                &row,
                action,
                requested.trace.clone(),
                false,
                "no job worker backend is registered; the stop stays pending".to_owned(),
            ),
        };
        if audit.verdict != StopVerdictTag::Stopped {
            tracing::error!(worker_id = %worker_id.as_str(), reason = ?audit.missing, residue = ?audit.residue, "Stop job worker failed");
        }
        match audit.verdict {
            StopVerdictTag::Stopped | StopVerdictTag::Failed => {
                let state = if audit.verdict == StopVerdictTag::Stopped {
                    StopState::Stopped
                } else {
                    StopState::Failed
                };
                let settlement = if state == StopState::Stopped {
                    worker_store::Settlement::Stopped
                } else {
                    worker_store::Settlement::Residual
                };
                let evidence_json = serde_json::to_string(&audit)?;
                let residue_json =
                    serde_json::to_string(&audit.residue.clone().unwrap_or_default())?;
                let mut ledger = self.lock_store()?;
                ledger.with_tx(|tx| {
                    worker_store::settle_job_stop_and_worker(
                        tx,
                        worker_id.as_str(),
                        state,
                        &evidence_json,
                        worker_store::JobWorkerSettlement {
                            from: worker_store::JobWorkerPhase::Stopping,
                            settlement,
                            residue_json: &residue_json,
                        },
                        OffsetDateTime::now_utc(),
                    )
                })?;
            }
            _ => {
                let evidence_json = serde_json::to_string(&audit)?;
                let mut ledger = self.lock_store()?;
                ledger.with_tx(|tx| {
                    stop_store::record_job_indeterminate(
                        tx,
                        worker_id.as_str(),
                        &evidence_json,
                        OffsetDateTime::now_utc(),
                    )
                })?;
            }
        }
        job_outcome_from_audit(worker_id.clone(), audit, false)
    }

    pub fn job_stop_record(
        &self,
        worker_id: &WorkerId,
    ) -> Result<Option<JobStopEvidenceRecord>, StopAuthorityError> {
        let row = {
            let ledger = self.lock_store()?;
            stop_store::job_stop_row(ledger.connection(), worker_id.as_str())?
        };
        row.map(job_record_from_row).transpose()
    }

    pub fn job_worker_status(
        &self,
        worker_id: &WorkerId,
    ) -> Result<Option<(JobWorkerIdentity, worker_store::JobWorkerPhase)>, StopAuthorityError> {
        let row = {
            let ledger = self.lock_store()?;
            worker_store::job_worker_row(ledger.connection(), worker_id.as_str())?
        };
        Ok(row.map(|row| (job_identity(&row), row.phase)))
    }

    // Startup cleanup stops registered workloads rather than resuming them.
    pub fn recover_pending_jobs(
        &self,
        correlation_id: Option<&CorrelationId>,
    ) -> Result<Vec<JobStopOutcome>, StopAuthorityError> {
        let rows = {
            let ledger = self.lock_store()?;
            worker_store::nonterminal_job_rows(
                ledger.connection(),
                correlation_id.map(CorrelationId::as_str),
            )?
        };
        let mut outcomes = Vec::with_capacity(rows.len());
        for row in rows {
            let worker_id = WorkerId::new(&row.worker_id).map_err(|error| {
                StopAuthorityError::InvalidWorker(format!(
                    "worker id {:?} is invalid: {error}",
                    row.worker_id
                ))
            })?;
            outcomes.push(self.stop_job_worker(&worker_id, stop_store::JobStopAction::Delete)?);
        }
        Ok(outcomes)
    }

    fn job_worker_row(
        &self,
        worker_id: &WorkerId,
    ) -> Result<worker_store::JobWorkerRow, StopAuthorityError> {
        let row = {
            let ledger = self.lock_store()?;
            worker_store::job_worker_row(ledger.connection(), worker_id.as_str())?
        };
        row.ok_or_else(|| StopAuthorityError::UnknownWorker(worker_id.as_str().to_owned()))
    }

    fn registered_job_backend(
        &self,
        row: &worker_store::JobWorkerRow,
    ) -> Result<Option<Arc<dyn JobWorkerBackend>>, StopAuthorityError> {
        let backend = match self.job_backend.lock() {
            Ok(slot) => slot.clone(),
            Err(_) => return Err(StopAuthorityError::JobBackendLock),
        };
        match backend {
            Some(backend) if backend.tag() == row.backend => Ok(Some(backend)),
            Some(_) => Err(StopAuthorityError::JobBackend(format!(
                "registered job backend tag does not match the durable backend {:?}",
                row.backend
            ))),
            None => Ok(None),
        }
    }

    fn actuate_job(
        &self,
        worker_id: &WorkerId,
        row: &worker_store::JobWorkerRow,
        action: stop_store::JobStopAction,
        backend: Arc<dyn JobWorkerBackend>,
    ) -> stop_store::JobStopAudit {
        let mut trace = Vec::new();
        push_trace(&mut trace, &row.worker_id, StopTraceEvent::Cooperative);
        let identity = job_identity(row);
        match backend.stop(worker_id, &identity, action) {
            Ok(body) => {
                push_trace(&mut trace, &row.worker_id, StopTraceEvent::ResidueQuery);
                job_audit_from_body(row, action, trace, body)
            }
            Err(fault) => {
                let reason = fault.to_string();
                indeterminate_job_audit(row, action, trace, false, reason)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stop::recovery_worker_channel;
    use odin_ledger::Ledger;
    use odin_process::mint_worker_id;
    use std::sync::Mutex;

    fn test_stop_authority(store: &Arc<Mutex<Ledger>>) -> StopAuthority {
        let channel =
            recovery_worker_channel("unix:path=/tmp/odin-stop-authority-test-absent-bus.sock")
                .expect("recovery channel");
        StopAuthority::new(Arc::clone(store), channel)
    }

    fn seed_job_worker_row(
        store: &Arc<Mutex<Ledger>>,
        phase: worker_store::JobWorkerPhase,
    ) -> WorkerId {
        let worker_id = mint_worker_id().expect("worker id");
        let mut ledger = store.lock().expect("ledger");
        ledger
            .with_tx(|tx| {
                worker_store::register_job_worker(
                    tx,
                    &worker_store::NewJobWorker {
                        worker_id: worker_id.as_str(),
                        cluster: "test-cluster",
                        namespace: "test-ns",
                        job_name: "test-job",
                        job_uid: "job-uid-no-backend",
                        correlation_id: "22222222222222222222222222222222",
                        operation_id: "op-no-backend",
                        now: OffsetDateTime::now_utc(),
                    },
                )?;
                if phase == worker_store::JobWorkerPhase::Released {
                    worker_store::mark_job_released(
                        tx,
                        worker_id.as_str(),
                        OffsetDateTime::now_utc(),
                    )?;
                }
                Ok(())
            })
            .expect("seed job worker row");
        worker_id
    }

    #[test]
    fn job_stop_without_backend_stays_indeterminate_and_pending() {
        let store = Arc::new(Mutex::new(Ledger::open_in_memory().unwrap()));
        let authority = test_stop_authority(&store);
        let worker_id = seed_job_worker_row(&store, worker_store::JobWorkerPhase::Registered);

        let outcome = authority
            .stop_job_worker(&worker_id, odin_ledger::stop::JobStopAction::Delete)
            .expect("a missing backend must stay pending, never fail the request");
        assert_eq!(outcome.verdict, StopVerdictTag::Indeterminate);
        assert!(!outcome.replay);
        assert!(!outcome.evidence.evidence_complete);

        let record = authority
            .job_stop_record(&worker_id)
            .expect("read the durable job stop record")
            .expect("the indeterminate attempt must be durable");
        assert_eq!(record.state, StopState::Requested);
        assert_eq!(record.attempts, 1);
        assert_eq!(record.evidence.verdict, StopVerdictTag::Indeterminate);
        assert_eq!(
            record.evidence.action,
            odin_ledger::stop::JobStopAction::Delete
        );
        assert!(!record.evidence.evidence.evidence_complete);
        assert!(record.settled_at.is_none());
        assert!(matches!(
            &record.evidence.missing,
            Some(missing) if !missing.reason.is_empty()
        ));

        let (identity, phase) = authority
            .job_worker_status(&worker_id)
            .expect("read job worker status")
            .expect("the seeded job worker row must resolve");
        assert_eq!(identity.job_uid, "job-uid-no-backend");
        assert!(!phase.is_terminal());
    }

    #[test]
    fn release_without_backend_returns_error_and_keeps_registration() {
        let store = Arc::new(Mutex::new(Ledger::open_in_memory().unwrap()));
        let authority = test_stop_authority(&store);
        let worker = seed_job_worker_row(&store, worker_store::JobWorkerPhase::Registered);

        assert!(matches!(
            authority.release_job_worker(&worker),
            Err(StopAuthorityError::JobBackend(_))
        ));
        assert_eq!(
            authority.job_worker_status(&worker).unwrap().unwrap().1,
            worker_store::JobWorkerPhase::Registered
        );
    }
}
