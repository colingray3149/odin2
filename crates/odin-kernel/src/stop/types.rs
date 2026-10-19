use std::process::{ChildStderr, ChildStdout};

use odin_domain::{StopAudit, StopEvidence, StopState, StopTraceRow, StopVerdict};
use odin_ledger::LedgerError;
use odin_process::{WorkerError, WorkerIdentity};
use odin_types::{CorrelationId, WorkerId};

pub struct WorkerLaunch {
    pub identity: WorkerIdentity,
    pub stdout: ChildStdout,
    pub stderr: ChildStderr,
}

impl WorkerLaunch {
    pub fn worker_id(&self) -> &WorkerId {
        &self.identity.worker_id
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StopOutcome {
    pub worker_id: WorkerId,
    pub verdict: StopVerdict,
    pub replay: bool,
    pub evidence: StopEvidence,
    pub trace: Vec<StopTraceRow>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StopEvidenceRecord {
    pub worker_id: WorkerId,
    pub correlation_id: CorrelationId,
    pub state: StopState,
    pub evidence: StopAudit,
    pub attempts: u64,
    pub requested_at: String,
    pub updated_at: String,
    pub settled_at: Option<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum StopAuthorityError {
    #[error("stop ledger lock is poisoned")]
    LedgerLock,
    #[error("live worker authority registry lock is poisoned")]
    WorkerRegistryLock,
    #[error("stop ledger operation failed: {0}")]
    Ledger(#[from] LedgerError),
    #[error("worker authority failed: {0}")]
    Worker(#[from] WorkerError),
    #[error("stop evidence serialization failed: {0}")]
    Json(#[from] serde_json::Error),
    #[error("logical worker {0} was not found")]
    UnknownWorker(String),
    #[error("durable worker record is invalid: {0}")]
    InvalidWorker(String),
    #[error("worker channel is invalid: {0}")]
    InvalidChannel(String),
    #[error("job worker backend registry lock is poisoned")]
    JobBackendLock,
    #[error("job worker backend violation: {0}")]
    JobBackend(String),
    #[error("pod worker authority lock is poisoned")]
    PodAuthorityLock,
    #[error("pod worker backend failed: {0}")]
    PodBackend(#[from] super::PodWorkerBackendFault),
}
