//! Journal launch and stop intent before acting so workers remain recoverable after a crash.

mod evidence;
mod job;
mod local;
mod pod;
mod types;

pub use job::{
    JobReleaseEvidence, JobReleaseOutcome, JobStopEvidenceRecord, JobStopOutcome, JobWorkerBackend,
    JobWorkerBackendFault, JobWorkerIdentity, JobWorkerRegistration, JobWorkerRegistrationOutcome,
};
pub use odin_ledger::pod::{PodStopAudit, PodStopEvidenceBody, PodWorkerIdentity};
pub use odin_process::{
    mint_worker_id, process_cgroup_line, BusAddress, CommandSpec, EnvironmentBuilder, FrozenArgv,
    ManagerClient, RecoveryAnchors, RegisteredServiceBinding, ScopeLifetime, ScopeLimits, Value,
    WorkerAuthority, WorkerChannel, WorkerError, WorkerIdentity, WorkerInspection, WorkerNaming,
    WorkerStopReport, CORRELATION_ENV, STDIN_WRITE_TIMEOUT,
};
pub use odin_types::{CorrelationId, WorkerId};
pub use pod::{PodIdentityProof, PodStopOutcome, PodWorkerBackend, PodWorkerBackendFault};
pub use types::{StopAuthorityError, StopEvidenceRecord, StopOutcome, WorkerLaunch};

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, MutexGuard};

use odin_ledger::Ledger;

use crate::worker_broker::ParentAuthorityClient;

/// Resolve channels and executables from configuration, never the ambient environment or PATH.
pub struct StopAuthority {
    store: Arc<Mutex<Ledger>>,
    channel: Option<WorkerChannel>,
    client: ParentAuthorityClient,
    active: Mutex<BTreeMap<String, Arc<Mutex<WorkerAuthority>>>>,
    job_backend: Mutex<Option<Arc<dyn JobWorkerBackend>>>,
    abandoned: Arc<std::sync::atomic::AtomicBool>,
    abandonment_gate: Mutex<()>,
    pod_backend: Mutex<Option<Arc<dyn PodWorkerBackend>>>,
    pod_operations: Mutex<()>,
}

/// Uses the configured bus without ambient discovery or permission to spawn executables.
pub fn recovery_worker_channel(raw: &str) -> Result<WorkerChannel, StopAuthorityError> {
    let bus = odin_process::BusAddress::parse(raw).map_err(StopAuthorityError::InvalidChannel)?;
    WorkerChannel::for_recovery(bus).map_err(StopAuthorityError::Worker)
}

impl StopAuthority {
    /// Freeze admission first; abandonment prevents destructive drops but cannot cancel reserved cleanup.
    pub fn abandon(&self) {
        let gate = self
            .abandonment_gate
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        self.abandoned
            .store(true, std::sync::atomic::Ordering::Release);
        drop(gate);
        self.abandon_active_workers();
    }

    fn abandon_active_workers(&self) {
        let active = self
            .active
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        for worker in active.values() {
            worker
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .abandon();
        }
    }

    pub fn new(store: Arc<Mutex<Ledger>>, channel: WorkerChannel) -> Self {
        Self {
            store,
            channel: Some(channel),
            client: ParentAuthorityClient::root_local(),
            active: Mutex::new(BTreeMap::new()),
            job_backend: Mutex::new(None),
            abandoned: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            abandonment_gate: Mutex::new(()),
            pod_backend: Mutex::new(None),
            pod_operations: Mutex::new(()),
        }
    }

    pub fn open(
        store: Arc<Mutex<Ledger>>,
        channel: WorkerChannel,
        client: ParentAuthorityClient,
    ) -> Self {
        Self {
            store,
            channel: Some(channel),
            client,
            active: Mutex::new(BTreeMap::new()),
            job_backend: Mutex::new(None),
            abandoned: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            abandonment_gate: Mutex::new(()),
            pod_backend: Mutex::new(None),
            pod_operations: Mutex::new(()),
        }
    }

    /// Workers without bus access use only their parent descriptor for launch and stop.
    pub fn from_parent(
        store: Arc<Mutex<Ledger>>,
        client: ParentAuthorityClient,
    ) -> Result<Self, StopAuthorityError> {
        if !client.is_remote() {
            return Err(StopAuthorityError::InvalidChannel(
                "parent authority constructor requires a remote descriptor".to_owned(),
            ));
        }
        Ok(Self {
            store,
            channel: None,
            client,
            active: Mutex::new(BTreeMap::new()),
            job_backend: Mutex::new(None),
            abandoned: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            abandonment_gate: Mutex::new(()),
            pod_backend: Mutex::new(None),
            pod_operations: Mutex::new(()),
        })
    }

    pub fn store(&self) -> Arc<Mutex<Ledger>> {
        Arc::clone(&self.store)
    }

    fn remove_active(&self, worker_id: &WorkerId) -> Result<(), StopAuthorityError> {
        self.active
            .lock()
            .map_err(|_| StopAuthorityError::WorkerRegistryLock)?
            .remove(worker_id.as_str());
        Ok(())
    }

    fn active_worker(
        &self,
        worker_id: &WorkerId,
    ) -> Result<Option<Arc<Mutex<WorkerAuthority>>>, StopAuthorityError> {
        Ok(self
            .active
            .lock()
            .map_err(|_| StopAuthorityError::WorkerRegistryLock)?
            .get(worker_id.as_str())
            .cloned())
    }

    fn require_active_worker(
        &self,
        worker_id: &WorkerId,
    ) -> Result<Arc<Mutex<WorkerAuthority>>, StopAuthorityError> {
        self.active_worker(worker_id)?.ok_or_else(|| {
            StopAuthorityError::UnknownWorker(format!("{} (not live)", worker_id.as_str()))
        })
    }

    fn local_channel(&self) -> Result<&WorkerChannel, StopAuthorityError> {
        self.channel.as_ref().ok_or_else(|| {
            StopAuthorityError::InvalidChannel(
                "remote parent authority has no local manager channel".to_owned(),
            )
        })
    }

    fn lock_store(&self) -> Result<MutexGuard<'_, Ledger>, StopAuthorityError> {
        self.store
            .lock()
            .map_err(|_| StopAuthorityError::LedgerLock)
    }
}

impl Drop for StopAuthority {
    fn drop(&mut self) {
        if self.abandoned.load(std::sync::atomic::Ordering::Acquire) {
            self.abandon_active_workers();
        }
    }
}
