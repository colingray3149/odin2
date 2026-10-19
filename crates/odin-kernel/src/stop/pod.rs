use std::sync::Arc;

use odin_domain::StopVerdictTag;
use odin_ledger::pod as store;
use time::OffsetDateTime;

use super::{
    CorrelationId, PodStopAudit, PodStopEvidenceBody, PodWorkerIdentity, StopAuthority,
    StopAuthorityError, WorkerId,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PodIdentityProof {
    pub pod_uid: Option<String>,
    pub policy_uid: Option<String>,
    pub secret_uid: Option<String>,
    pub complete: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum PodWorkerBackendFault {
    #[error("pod backend unavailable: {reason}")]
    Unavailable { reason: String },
    #[error("pod backend rejected operation: {reason}")]
    Rejected { reason: String },
    #[error("pod backend identity conflict: {reason}")]
    Conflict { reason: String },
    #[error("pod backend invalid input: {reason}")]
    Invalid { reason: String },
    #[error("pod creation outcome is uncertain: {reason}")]
    CreationUncertain { reason: String },
}

pub trait PodWorkerBackend: Send + Sync {
    fn stop(
        &self,
        worker: &WorkerId,
        identity: &PodWorkerIdentity,
    ) -> Result<(), PodWorkerBackendFault>;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PodStopOutcome {
    pub worker_id: WorkerId,
    pub verdict: StopVerdictTag,
    pub replay: bool,
    pub evidence: PodStopEvidenceBody,
}

impl StopAuthority {
    pub fn register_pod_backend(
        &self,
        backend: Arc<dyn PodWorkerBackend>,
    ) -> Result<(), StopAuthorityError> {
        *self
            .pod_backend
            .lock()
            .map_err(|_| StopAuthorityError::PodAuthorityLock)? = Some(backend);
        Ok(())
    }

    pub fn register_pod_worker(
        &self,
        worker: &WorkerId,
        identity: &PodWorkerIdentity,
        correlation: &CorrelationId,
    ) -> Result<(), StopAuthorityError> {
        self.register_pod_worker_with_retention(worker, identity, correlation, false)
    }

    pub fn register_retained_pod_worker(
        &self,
        worker: &WorkerId,
        identity: &PodWorkerIdentity,
        correlation: &CorrelationId,
    ) -> Result<(), StopAuthorityError> {
        self.register_pod_worker_with_retention(worker, identity, correlation, true)
    }

    fn register_pod_worker_with_retention(
        &self,
        worker: &WorkerId,
        identity: &PodWorkerIdentity,
        correlation: &CorrelationId,
        retained: bool,
    ) -> Result<(), StopAuthorityError> {
        if identity.correlation_id != correlation.as_str() {
            return Err(PodWorkerBackendFault::Invalid {
                reason: "pod intent correlation differs".to_owned(),
            }
            .into());
        }
        let _operation = self
            .pod_operations
            .lock()
            .map_err(|_| StopAuthorityError::PodAuthorityLock)?;
        self.lock_store()?.with_tx(|tx| {
            store::register_worker_with_retention(
                tx,
                worker.as_str(),
                identity,
                retained,
                OffsetDateTime::now_utc(),
            )
        })?;
        tracing::info!(
            worker_id = %worker.as_str(),
            correlation = %correlation.as_str(),
            "pod_worker_registered"
        );
        Ok(())
    }

    // Retained work must be published or discarded before its pod is deleted.
    pub fn admit_pod_stop(
        &self,
        worker: &WorkerId,
        expected_identity: &PodWorkerIdentity,
    ) -> Result<(), StopAuthorityError> {
        let _operation = self
            .pod_operations
            .lock()
            .map_err(|_| StopAuthorityError::PodAuthorityLock)?;
        self.lock_store()?.with_tx(|tx| {
            store::admit_stop(
                tx,
                worker.as_str(),
                expected_identity,
                OffsetDateTime::now_utc(),
            )
        })?;
        Ok(())
    }

    pub fn update_pod_worker_identity(
        &self,
        worker: &WorkerId,
        identity: &PodWorkerIdentity,
    ) -> Result<(), StopAuthorityError> {
        let _operation = self
            .pod_operations
            .lock()
            .map_err(|_| StopAuthorityError::PodAuthorityLock)?;
        let now = OffsetDateTime::now_utc();
        self.lock_store()?.with_tx(|tx| {
            let row = store::worker_row(tx, worker.as_str())?.ok_or_else(|| {
                odin_ledger::LedgerError::Conflict(format!(
                    "unknown pod worker {}",
                    worker.as_str()
                ))
            })?;
            store::record_proof(
                tx,
                worker.as_str(),
                identity.pod_uid.as_deref(),
                identity.policy_uid.as_deref(),
                now,
            )?;
            store::record_secret_proof(tx, worker.as_str(), identity.secret_uid.as_deref(), now)?;
            if row.phase == "registered"
                && row
                    .identity
                    .pod_uid
                    .as_ref()
                    .or(identity.pod_uid.as_ref())
                    .is_some()
                && row
                    .identity
                    .policy_uid
                    .as_ref()
                    .or(identity.policy_uid.as_ref())
                    .is_some()
                && (row.identity.secret_name.is_none()
                    || row
                        .identity
                        .secret_uid
                        .as_ref()
                        .or(identity.secret_uid.as_ref())
                        .is_some())
            {
                store::mark_released(tx, worker.as_str(), now)?;
            }
            Ok(())
        })?;
        Ok(())
    }

    pub fn pod_worker_for_correlation(
        &self,
        correlation: &CorrelationId,
    ) -> Result<Option<(WorkerId, PodWorkerIdentity, String)>, StopAuthorityError> {
        let ledger = self.lock_store()?;
        store::worker_for_correlation(ledger.connection(), correlation.as_str())?
            .map(|row| Ok((pod_worker_id(&row.worker_id)?, row.identity, row.phase)))
            .transpose()
    }

    pub fn pod_stop_record(
        &self,
        worker: &WorkerId,
    ) -> Result<Option<PodStopAudit>, StopAuthorityError> {
        let ledger = self.lock_store()?;
        Ok(store::worker_row(ledger.connection(), worker.as_str())?.and_then(|row| row.audit))
    }

    pub fn recover_pending_pods(
        &self,
        correlation: Option<&CorrelationId>,
    ) -> Result<Vec<PodStopOutcome>, StopAuthorityError> {
        let rows = {
            let ledger = self.lock_store()?;
            store::pending_rows(ledger.connection(), correlation.map(CorrelationId::as_str))?
        };
        rows.into_iter()
            .filter(|row| !row.stop_requires_admission())
            .map(|row| self.stop_pod_worker(&pod_worker_id(&row.worker_id)?))
            .collect()
    }

    pub fn recover_pending_pod_stops(&self) -> Result<Vec<PodStopOutcome>, StopAuthorityError> {
        let rows = {
            let ledger = self.lock_store()?;
            store::pending_rows(ledger.connection(), None)?
        };
        rows.into_iter()
            .filter(|row| {
                !row.stop_requires_admission() && (row.phase != "released" || row.stop_admitted)
            })
            .map(|row| self.stop_pod_worker(&pod_worker_id(&row.worker_id)?))
            .collect()
    }

    // Cancellation must be durable before waiting for backend I/O.
    pub fn request_pod_stop(&self, worker: &WorkerId) -> Result<(), StopAuthorityError> {
        self.lock_store()?.with_tx(|tx| {
            let row = store::worker_row(tx, worker.as_str())?.ok_or_else(|| {
                odin_ledger::LedgerError::Conflict(format!("unknown pod worker {}", worker.as_str()))
            })?;
            if row.stop_requires_admission() {
                return Err(odin_ledger::LedgerError::Conflict(
                    "retained pod requires explicit stop admission".to_owned(),
                ));
            }
            let now = odin_ledger::encode_utc(OffsetDateTime::now_utc())?;
            let requested = serde_json::to_string(&stop_audit(
                worker,
                &row.identity,
                Some("pod stop requested".to_owned()),
            ))?;
            tx.execute(
                "UPDATE pod_worker_registry SET state='stopping',stop_audit_json=?3,requested_at=?2,updated_at=?2 WHERE worker_id=?1 AND state NOT IN ('stopping','stopped')",
                [worker.as_str(), now.as_str(), requested.as_str()],
            )?;
            Ok(())
        })?;
        Ok(())
    }

    pub fn stop_pod_worker(&self, worker: &WorkerId) -> Result<PodStopOutcome, StopAuthorityError> {
        let _operation = self
            .pod_operations
            .lock()
            .map_err(|_| StopAuthorityError::PodAuthorityLock)?;
        let row = self.pod_row(worker)?;
        if row.phase == "stopped" {
            let audit = row.audit.ok_or_else(|| {
                StopAuthorityError::InvalidWorker("stopped pod has no audit".to_owned())
            })?;
            return Ok(outcome(worker, audit, true));
        }
        if row.stop_requires_admission() {
            return Err(PodWorkerBackendFault::Conflict {
                reason: "retained pod requires explicit stop admission".to_owned(),
            }
            .into());
        }
        self.request_pod_stop(worker)?;
        let attempt = self
            .registered_pod_backend()
            .and_then(|backend| backend.stop(worker, &row.identity).map_err(Into::into));
        let failure = attempt.as_ref().err().map(ToString::to_string);
        if let Some(error) = failure.as_deref() {
            if row
                .audit
                .as_ref()
                .and_then(|audit| audit.missing.as_deref())
                != Some(error)
            {
                tracing::error!(worker_id = %worker.as_str(), error, "pod stop failed; retry from the ledger at next start");
            }
        }
        let audit = stop_audit(worker, &row.identity, failure);
        if let Err(error) = self.lock_store()?.with_tx(|tx| {
            let now = odin_ledger::encode_utc(OffsetDateTime::now_utc())?;
            let audit_json = serde_json::to_string(&audit)?;
            let stopped = attempt.is_ok();
            let settled_at = stopped.then_some(now.as_str());
            tx.execute(
                "UPDATE pod_worker_registry SET state=?2,stop_audit_json=?3,attempts=attempts+1,updated_at=?4,settled_at=?5 WHERE worker_id=?1 AND state='stopping'",
                (worker.as_str(), if stopped { "stopped" } else { "stopping" }, audit_json.as_str(), now.as_str(), settled_at),
            )?;
            tx.execute(
                "UPDATE pod_stop_intent SET state=?2,evidence_json=?3,attempts=attempts+1,updated_at=?4,settled_at=?5 WHERE worker_id=?1 AND state='requested'",
                (worker.as_str(), if stopped { "stopped" } else { "requested" }, audit_json.as_str(), now.as_str(), settled_at),
            )?;
            Ok(())
        }) {
            tracing::error!(worker_id = %worker.as_str(), %error, "pod stop result could not be saved to the ledger");
            return Err(error.into());
        }
        if attempt.is_ok() {
            tracing::info!(worker_id = %worker.as_str(), "pod worker stopped");
        }
        Ok(outcome(worker, audit, false))
    }

    fn pod_row(&self, worker: &WorkerId) -> Result<store::PodWorkerRow, StopAuthorityError> {
        let ledger = self.lock_store()?;
        store::worker_row(ledger.connection(), worker.as_str())?
            .ok_or_else(|| StopAuthorityError::UnknownWorker(worker.as_str().to_owned()))
    }

    fn registered_pod_backend(&self) -> Result<Arc<dyn PodWorkerBackend>, StopAuthorityError> {
        self.pod_backend
            .lock()
            .map_err(|_| StopAuthorityError::PodAuthorityLock)?
            .clone()
            .ok_or_else(|| {
                PodWorkerBackendFault::Unavailable {
                    reason: "no pod worker backend is registered".to_owned(),
                }
                .into()
            })
    }
}

fn pod_worker_id(raw: &str) -> Result<WorkerId, StopAuthorityError> {
    WorkerId::new(raw).map_err(|error| StopAuthorityError::InvalidWorker(error.to_string()))
}

fn outcome(worker: &WorkerId, audit: PodStopAudit, replay: bool) -> PodStopOutcome {
    PodStopOutcome {
        worker_id: worker.clone(),
        verdict: audit.verdict,
        replay,
        evidence: audit.evidence,
    }
}

// The audit flags record the backend stop result.
fn stop_audit(
    worker: &WorkerId,
    identity: &PodWorkerIdentity,
    missing: Option<String>,
) -> PodStopAudit {
    let stopped = missing.is_none();
    PodStopAudit {
        verdict: if stopped {
            StopVerdictTag::Stopped
        } else {
            StopVerdictTag::Indeterminate
        },
        action: "delete".to_owned(),
        residue: None,
        missing: missing.clone(),
        evidence: PodStopEvidenceBody {
            schema: "odin.pod-stop-evidence.v1".to_owned(),
            worker_id: worker.clone(),
            backend: "kube.pod".to_owned(),
            cluster: identity.cluster.clone(),
            namespace: identity.namespace.clone(),
            pod_name: identity.pod_name.clone(),
            pod_uid: identity.pod_uid.clone(),
            policy_name: identity.policy_name.clone(),
            policy_uid: identity.policy_uid.clone(),
            secret_name: identity.secret_name.clone(),
            secret_uid: identity.secret_uid.clone(),
            secret_absent: identity.secret_name.as_ref().map(|_| stopped),
            pod_absent: stopped,
            policy_absent: stopped,
            evidence_complete: stopped,
            pod_residue: Vec::new(),
            missing,
        },
    }
}

#[cfg(test)]
mod tests;
