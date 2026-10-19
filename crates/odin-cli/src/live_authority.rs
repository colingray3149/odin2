//! Per-live-session capsule authority for odind: one exact sidecar authority
//! per live session, bound to that session's real host-issued identity, seat
//! operation binding, and the session's selected configured project root.
//!
//! Each session has a private state root, projection, signed seat token,
//! and sidecar worker. Unprovisioned capsules are rejected rather than routed
//! to another session's sidecar.
//!
//! Parent-side stop cascade: normal pool drop retires each sidecar worker.
//! Daemon shutdown closes admission first and explicitly retires within its
//! shared deadline; incomplete shutdown disarms every Drop fallback.

mod scoped_tests;

pub use scoped_tests::{
    permit_deadline, AttrNix, Capture, Captured, OwnedProgram, OwnedStep, Retention,
    ScopedTestInput,
};

use std::collections::BTreeMap;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use odin_domain::huginn::LiveError;
use odin_domain::{Digest, SeatId, SeatToken, SessionId};
use odin_huginn::{OdindConfig, RuntimeManifest};
use odin_omp::host_tools::operations::{session_capsule_id, SessionOperationBinding};
use odin_omp::host_tools::{CanonicalV2CapabilityOwner, HostInvocation, HostToolError};
use odin_omp::live::runtime::SessionCapsuleAuthority;
use odin_registry::SnapshotStore;
use odin_types::{CapsuleId, CorrelationId};

use crate::eval_daemon::{
    create_private_dir, verify_or_clone_capsule_project, CanonicalEffectReceiptReader,
    CanonicalV2SidecarOwner, PersistentEffectReceiptReader, RegisteredGit,
};

mod child_control;
mod child_provisioner;

pub use child_control::{BranchReader, ReloadGate, SupervisorChildControl};
pub use child_provisioner::PoolChildProvisioner;

pub type SupervisorHandle =
    Arc<std::sync::OnceLock<std::sync::Weak<odin_omp::live::supervisor::LiveSupervisor>>>;

fn block_on<T, E>(future: impl Future<Output = Result<T, E>>) -> Result<T, String>
where
    E: std::fmt::Display,
{
    let runtime = tokio::runtime::Handle::try_current()
        .map_err(|_| "no tokio runtime for supervisor control".to_owned())?;
    wait(&runtime, future).map_err(|error| error.to_string())
}

/// Drives `future` from synchronous control code. On a runtime worker the
/// worker is handed off first (`Handle::block_on` there panics, or
/// deadlocks the actor it waits on); elsewhere it blocks the thread.
fn wait<F: Future>(runtime: &tokio::runtime::Handle, future: F) -> F::Output {
    tokio::task::block_in_place(|| runtime.block_on(future))
}

/// Weak handle to the global session authority pool, following the same cell
/// pattern as [`SupervisorHandle`] so this control never forms a strong Arc
/// cycle with the runtime composition.
pub type SessionPoolHandle = Arc<std::sync::OnceLock<std::sync::Weak<SessionAuthorityPool>>>;

/// One exact registered live-session capsule. Registration carries only
/// host-owned identity/policy/root state; no sidecar exists until an already
/// authorized host-tool invocation reaches the private backend owner.
#[derive(Clone)]
struct SessionRegistration {
    session: SessionId,
    binding: SessionOperationBinding,
    capsule_id: CapsuleId,
    declared_project: PathBuf,
    capsule_project: PathBuf,
    source_commit: String,
    source_kind: String,
}

/// The registered Git capsule of one session, as the coding route binds
/// test runs, reviews and reviewed offers to it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RegisteredCodeCapsule {
    pub session: SessionId,
    pub seat: SeatId,
    /// The canonical declared project root the capsule was cloned from.
    pub declared_project: PathBuf,
    pub capsule_project: PathBuf,
    /// The source commit the capsule was registered at: the work's base.
    pub source_commit: String,
}

struct PrivateBackend {
    token_id: String,
    owner: Option<Arc<CanonicalV2SidecarOwner>>,
    lifecycle: Option<crate::eval_daemon::SessionSidecarLifecycle>,
    /// Set when a deadline owner explicitly gave up on this backend: Drop
    /// must never re-enter retirement for it — not bounded, not classic.
    abandoned: bool,
    pool_closed: Arc<AtomicBool>,
    retirement: Option<Result<(), String>>,
}

impl PrivateBackend {
    fn abandon(&mut self) {
        drop(self.owner.take());
        if let Some(lifecycle) = self.lifecycle.as_mut() {
            lifecycle.abandon();
        }
        self.abandoned = true;
    }

    fn retire_bounded(&mut self, deadline: Instant) -> Result<(), String> {
        if let Some(result) = &self.retirement {
            return result.clone();
        }
        if self.abandoned {
            return Err("authority retirement was abandoned".to_owned());
        }
        if Instant::now() >= deadline {
            self.abandon();
            let result =
                Err("session retirement budget was already spent; stop is unproved".to_owned());
            self.retirement = Some(result.clone());
            return result;
        }
        self.abandoned = true;
        let owner = self.owner.take();
        let result = crate::eval_daemon::bounded_retirement(deadline, move || {
            drop(owner);
            Ok(())
        })
        .and_then(|()| {
            if let Some(lifecycle) = self.lifecycle.as_mut() {
                lifecycle.retire_bounded(deadline)?;
            }
            Ok(())
        });
        if result.is_err() {
            self.abandon();
        }
        self.retirement = Some(result.clone());
        result
    }
}

impl Drop for PrivateBackend {
    fn drop(&mut self) {
        if self.abandoned || self.pool_closed.load(Ordering::Acquire) {
            self.abandon();
            return;
        }
        let _ = self.retire_bounded(Instant::now() + Duration::from_secs(10));
    }
}

struct SessionAuthority {
    registration: SessionRegistration,
    backend: Option<PrivateBackend>,
    scoped_tests: Option<Arc<scoped_tests::ScopedTests>>,
}

impl SessionAuthority {
    fn retire_scoped_tests(&self, deadline: Instant) -> Result<(), String> {
        self.scoped_tests
            .as_ref()
            .map_or(Ok(()), |owner| owner.retire(deadline))
    }

    fn abandon_scoped_tests(&self) {
        if let Some(owner) = &self.scoped_tests {
            owner.abandon();
        }
    }
}

struct PoolInner {
    sessions: BTreeMap<CapsuleId, SessionAuthority>,
}

/// Retirement results for each capsule's worker, broker, and socket cleanup.
/// A gap without a capsule ID means the pool mutex could not be drained.
#[derive(Debug, Default)]
pub struct RetirementProof {
    pub retired: Vec<CapsuleId>,
    pub incomplete: Vec<RetirementGap>,
}

impl RetirementProof {
    pub fn complete(&self) -> bool {
        self.incomplete.is_empty()
    }
}

/// Cleanup failure retained for recovery; Drop must not retry retirement.
#[derive(Debug)]
pub struct RetirementGap {
    pub capsule_id: Option<CapsuleId>,
    pub reason: String,
}

/// Registration-only per-session authority pool. Factory open records the
/// exact session/binding/root. The private sidecar backend starts lazily on
/// the first kernel-prepared HostToolOperations invocation, provisioned with
/// the ACTUAL current operator SeatToken. Explicit renewal changes token_id
/// and therefore retires/reopens the backend; revocation/expiry/plan removal
/// fail in the mandatory HostToolOperations gate before this owner is reached.
pub struct SessionAuthorityPool {
    config: OdindConfig,
    manifest: RuntimeManifest,
    worker_channel: Option<odin_process::WorkerChannel>,
    signing_key: Option<Vec<u8>>,
    state_root: PathBuf,
    inner: Mutex<PoolInner>,
    /// The owner of permitless lifecycle workers (generic harness hand-back,
    /// claim carry, repository watch); retired with the pool.
    lifecycle: Mutex<Option<Arc<scoped_tests::ScopedTests>>>,
    closed: Arc<AtomicBool>,
    retirement_failed: AtomicBool,
}

/// Safety owner established before live composition can spawn authority work.
/// Explicit shutdown owns retirement; early return only closes and abandons.
pub struct SessionAuthorityShutdownGuard(Arc<SessionAuthorityPool>);

impl Drop for SessionAuthorityShutdownGuard {
    fn drop(&mut self) {
        self.0.abandon_all();
    }
}

impl SessionCapsuleAuthority for SessionAuthorityPool {
    fn open_session(
        &self,
        session: &SessionId,
        binding: &SessionOperationBinding,
        capsule_root: &Path,
    ) -> Result<(), LiveError> {
        self.register_session(session, binding, capsule_root)
            .map_err(|reason| {
                // The typed refusal stays Unauthorized; the operator still learns WHY.
                tracing::error!("session capsule registration refused for {session}: {reason}");
                LiveError::Unauthorized
            })
    }
}

impl CanonicalV2CapabilityOwner for SessionAuthorityPool {
    fn invoke_authority_binding(
        &self,
        binding: odin_omp::host_tools::CanonicalV2CapabilityBinding,
        capsule_id: CapsuleId,
        correlation_id: CorrelationId,
        invocation: HostInvocation,
    ) -> Result<serde_json::Value, HostToolError> {
        let session = invocation
            .scope
            .session
            .as_ref()
            .ok_or(HostToolError::Scope {
                tool: "capsule_authority",
                reason: "the prepared scope has no session identity",
            })?;
        let expected = session_capsule_id(session).map_err(|error| HostToolError::Catalog {
            detail: format!("prepared capsule identity rejected: {error}"),
        })?;
        if expected != capsule_id {
            return Err(HostToolError::Catalog {
                detail: "prepared capsule identity contradicts the registered session".to_owned(),
            });
        }
        let owner = self.backend_for(session, &capsule_id)?;
        owner.invoke_authority_binding(binding, capsule_id, correlation_id, invocation)
    }

    fn preflight_authority_binding(
        &self,
        _contract: &odin_kernel::CapabilityContract,
        binding: odin_omp::host_tools::CanonicalV2CapabilityBinding,
        scope: &odin_domain::Scope,
        arguments: &serde_json::Value,
    ) -> Result<(), HostToolError> {
        // Check identity, arguments, secret, and registration before approval.
        // Backend creation waits for a permit; evidence requires a later receipt.
        if binding.is_evidence_extractor() {
            return Ok(());
        }
        let tool = "capsule_authority";
        let session = scope.session.as_ref().ok_or(HostToolError::Scope {
            tool,
            reason: "the prepared scope has no session identity",
        })?;
        let capsule_id = session_capsule_id(session).map_err(|error| HostToolError::Catalog {
            detail: format!("prepared capsule identity rejected: {error}"),
        })?;
        crate::eval_daemon::strict_arguments(tool, arguments)?;
        if self.signing_key.is_none() {
            return Err(HostToolError::Catalog {
                detail: "this node does not hold the session authority minting secret \
                     (read-only follower); capsule backend provisioning is denied"
                    .to_owned(),
            });
        }
        let inner = self.inner.lock().map_err(|_| HostToolError::Storage {
            tool,
            detail: "session authority pool lock is poisoned".to_owned(),
        })?;
        let authority =
            inner
                .sessions
                .get(&capsule_id)
                .ok_or_else(|| HostToolError::Unavailable {
                    tool,
                    reason: format!(
                        "capsule {} is not registered for this session",
                        capsule_id.as_str()
                    ),
                })?;
        if authority.registration.session != *session {
            return Err(HostToolError::Catalog {
                detail: "registered session contradicts the invocation scope".to_owned(),
            });
        }
        Ok(())
    }
}

impl SessionAuthorityPool {
    pub fn open(
        config: &OdindConfig,
        manifest: &RuntimeManifest,
        signing_key: Vec<u8>,
    ) -> Result<Arc<Self>, String> {
        Self::open_inner(config, manifest, signing_key, None)
    }

    /// Composes the session owner with its explicit registered worker channel.
    /// The channel retains manager/cgroup identity; no ambient fallback is used.
    pub fn open_with_worker_channel(
        config: &OdindConfig,
        manifest: &RuntimeManifest,
        signing_key: Vec<u8>,
        channel: odin_process::WorkerChannel,
    ) -> Result<Arc<Self>, String> {
        Self::open_inner(config, manifest, signing_key, Some(channel))
    }

    fn open_inner(
        config: &OdindConfig,
        manifest: &RuntimeManifest,
        signing_key: Vec<u8>,
        worker_channel: Option<odin_process::WorkerChannel>,
    ) -> Result<Arc<Self>, String> {
        let state_root = config.paths.state_root.join("session-authorities");
        create_private_dir(&state_root)?;
        Ok(Arc::new(Self {
            config: config.clone(),
            manifest: manifest.clone(),
            worker_channel,
            signing_key: Some(signing_key),
            state_root,
            closed: Arc::new(AtomicBool::new(false)),
            retirement_failed: AtomicBool::new(false),
            inner: Mutex::new(PoolInner {
                sessions: BTreeMap::new(),
            }),
            lifecycle: Mutex::new(None),
        }))
    }

    /// A pool that holds NO signing material: composed on read-only follower
    /// nodes, which must never receive the authority minting secret
    /// (SeatToken verification is HMAC-SHA256, so the verification key IS
    /// the secret). Session registration and every private backend
    /// provisioning attempt fail typed-closed.
    pub fn open_denied(
        config: &OdindConfig,
        manifest: &RuntimeManifest,
    ) -> Result<Arc<Self>, String> {
        Ok(Arc::new(Self {
            config: config.clone(),
            manifest: manifest.clone(),
            worker_channel: None,
            signing_key: None,
            state_root: config.paths.state_root.join("session-authorities"),
            closed: Arc::new(AtomicBool::new(false)),
            retirement_failed: AtomicBool::new(false),
            inner: Mutex::new(PoolInner {
                sessions: BTreeMap::new(),
            }),
            lifecycle: Mutex::new(None),
        }))
    }

    /// Close registration and backend admission without waiting for synchronous
    /// provisioning that already owns the pool mutex.
    pub fn close(&self) {
        self.closed.store(true, Ordering::Release);
    }

    /// Whether [`Self::close`] ran: the daemon is stopping.
    pub fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Acquire)
    }

    pub fn shutdown_guard(self: &Arc<Self>) -> SessionAuthorityShutdownGuard {
        SessionAuthorityShutdownGuard(Arc::clone(self))
    }

    /// The registered Git capsule of `session`: `Ok(None)` when the session
    /// is registered over a knowledge root (no Git capsule exists), an
    /// error when no registration of this exact session exists.
    pub fn registered_code_capsule(
        &self,
        session: &SessionId,
    ) -> Result<Option<RegisteredCodeCapsule>, String> {
        let capsule_id = session_capsule_id(session).map_err(|error| error.to_string())?;
        let inner = self
            .inner
            .lock()
            .map_err(|_| "session pool lock poisoned")?;
        let registration = &inner
            .sessions
            .get(&capsule_id)
            .filter(|authority| authority.registration.session == *session)
            .ok_or_else(|| format!("session {session} has no registered capsule"))?
            .registration;
        if registration.source_kind != odin_sidecar_protocol::SOURCE_KIND_GIT_COMMIT {
            return Ok(None);
        }
        Ok(Some(RegisteredCodeCapsule {
            session: registration.session.clone(),
            seat: registration.binding.policy.seat_id.clone(),
            declared_project: registration.declared_project.clone(),
            capsule_project: registration.capsule_project.clone(),
            source_commit: registration.source_commit.clone(),
        }))
    }

    pub fn retire_session(&self, capsule_id: &CapsuleId) -> Result<bool, String> {
        self.retire_session_until(capsule_id, Instant::now() + Duration::from_secs(10))
    }

    /// Child teardown shares its caller's absolute deadline, including lock
    /// acquisition. Failed retirement is retained and cannot become success.
    /// Closing mint admission does not prohibit retirement of an existing
    /// registration: parent bridges must finish this step during daemon stop.
    pub fn retire_session_until(
        &self,
        capsule_id: &CapsuleId,
        deadline: Instant,
    ) -> Result<bool, String> {
        let result = (|| {
            let mut inner = lock_until(&self.inner, deadline)?;
            let Some(authority) = inner.sessions.get_mut(capsule_id) else {
                return Ok(false);
            };
            authority.retire_scoped_tests(deadline)?;
            if let Some(backend) = authority.backend.as_mut() {
                backend.retire_bounded(deadline)?;
            }
            inner.sessions.remove(capsule_id);
            Ok(true)
        })();
        if result.is_err() {
            self.retirement_failed.store(true, Ordering::Release);
        }
        result
    }

    /// Disarms cleanup without signaling, joining, or removing sockets.
    /// Reports all remaining capsules as incomplete; subsequent calls are empty.
    pub fn abandon_all(&self) -> RetirementProof {
        self.close();
        let (drained, mut proof) = self.drain_for_shutdown();
        for (capsule_id, mut authority) in drained {
            if authority.scoped_tests.is_some() {
                authority.abandon_scoped_tests();
                proof.incomplete.push(RetirementGap {
                    capsule_id: Some(capsule_id.clone()),
                    reason: "scoped test retirement was abandoned".to_owned(),
                });
            }
            match authority.backend.as_mut() {
                None if authority.scoped_tests.is_none() => proof.retired.push(capsule_id),
                None => {}
                Some(backend) => {
                    backend.abandon();
                    proof.incomplete.push(RetirementGap {
                        capsule_id: Some(capsule_id),
                        reason: "authority retirement abandoned before any stop was \
                             attempted; durable worker and broker state retained, \
                             synchronous handler termination unproved"
                            .to_owned(),
                    });
                }
            }
        }
        if self.abandon_lifecycle() {
            proof.incomplete.push(RetirementGap {
                capsule_id: None,
                reason: "lifecycle worker retirement was abandoned".to_owned(),
            });
        }
        proof
    }

    /// Drains the pool and retires capsules serially under one shared deadline.
    /// Incomplete cleanup is reported and disarmed so Drop cannot retry it.
    pub fn retire_all(&self, deadline: Instant) -> RetirementProof {
        self.close();
        let (drained, mut proof) = self.drain_for_shutdown();
        let mut spent = false;
        for (capsule_id, mut authority) in drained {
            if let Err(reason) = authority.retire_scoped_tests(deadline) {
                authority.abandon_scoped_tests();
                if let Some(backend) = authority.backend.as_mut() {
                    backend.abandon();
                }
                proof.incomplete.push(RetirementGap {
                    capsule_id: Some(capsule_id),
                    reason,
                });
                continue;
            }
            let Some(mut backend) = authority.backend.take() else {
                // Registration-only capsule: nothing was ever provisioned.
                proof.retired.push(capsule_id);
                continue;
            };
            if spent {
                backend.abandon();
                proof.incomplete.push(RetirementGap {
                    capsule_id: Some(capsule_id),
                    reason: "authority retirement deadline was spent by an earlier capsule"
                        .to_owned(),
                });
                continue;
            }
            match backend.retire_bounded(deadline) {
                Ok(()) => proof.retired.push(capsule_id),
                Err(reason) => {
                    backend.abandon();
                    if Instant::now() >= deadline {
                        spent = true;
                    }
                    proof.incomplete.push(RetirementGap {
                        capsule_id: Some(capsule_id),
                        reason,
                    });
                }
            }
        }
        if let Err(reason) = self.retire_lifecycle(deadline) {
            proof.incomplete.push(RetirementGap {
                capsule_id: None,
                reason: format!("lifecycle workers: {reason}"),
            });
        }
        if self.retirement_failed.load(Ordering::Acquire) {
            proof.incomplete.push(RetirementGap {
                capsule_id: None,
                reason: "an earlier session retirement did not prove stop".to_owned(),
            });
        }
        if !proof.complete() {
            self.retirement_failed.store(true, Ordering::Release);
        }
        proof
    }

    /// Never wait behind synchronous provisioning after the daemon deadline.
    /// The shared closed flag disarms backend Drop even if this lock is busy.
    fn drain_for_shutdown(&self) -> (BTreeMap<CapsuleId, SessionAuthority>, RetirementProof) {
        match self.inner.try_lock() {
            Ok(mut inner) => (std::mem::take(&mut inner.sessions), RetirementProof::default()),
            Err(std::sync::TryLockError::Poisoned(error)) => {
                let mut inner = error.into_inner();
                let mut drained = std::mem::take(&mut inner.sessions);
                for authority in drained.values_mut() {
                    authority.abandon_scoped_tests();
                    if let Some(backend) = authority.backend.as_mut() {
                        backend.abandon();
                    }
                }
                (drained, RetirementProof {
                    incomplete: vec![RetirementGap {
                        capsule_id: None,
                        reason: "session authority pool lock is poisoned; backends disarmed".to_owned(),
                    }],
                    ..RetirementProof::default()
                })
            }
            Err(std::sync::TryLockError::WouldBlock) => (BTreeMap::new(), RetirementProof {
                incomplete: vec![RetirementGap {
                    capsule_id: None,
                    reason: "session authority pool is still in use; retirement skipped and Drop disarmed".to_owned(),
                }],
                ..RetirementProof::default()
            }),
        }
    }

    fn register_session(
        &self,
        session: &SessionId,
        binding: &SessionOperationBinding,
        capsule_root: &Path,
    ) -> Result<(), String> {
        if self.closed.load(Ordering::Acquire) {
            return Err("session authority pool is shutting down".to_owned());
        }
        if self.signing_key.is_none() {
            return Err(
                "this node does not hold the session authority minting secret \
                 (read-only follower); session capsule registration is denied"
                    .to_owned(),
            );
        }
        let capsule_id = session_capsule_id(session).map_err(|error| error.to_string())?;
        let declared_project = capsule_root
            .canonicalize()
            .map_err(|error| format!("session capsule root {}: {error}", capsule_root.display()))?;
        if !declared_project.is_dir() {
            return Err(format!(
                "session capsule root {} is not a directory",
                declared_project.display()
            ));
        }
        let (source_commit, source_kind) =
            capsule_source_identity(&self.manifest, &declared_project)?;
        // One creation policy per verified session identity. The pool mutex
        // is deliberately held across the provisioning git commands — one
        // local clone or a HEAD verify, a bounded session-open cost — so two
        // registrations of one capsule can never race.
        let mut inner = self.inner.lock().map_err(|_| "pool lock poisoned")?;
        if self.closed.load(Ordering::Acquire) {
            return Err("session authority pool is shutting down".to_owned());
        }
        let session_state = self
            .state_root
            .join(format!("capsule-{}", capsule_id.as_str().replace(':', "-")));
        create_private_dir(&session_state)?;
        let git_program = self
            .manifest
            .executable("git")
            .map_err(|error| error.to_string())?
            .path
            .clone();
        // The manifest-pinned git, run environment-free exactly like
        // `current_head_commit` below and config-free exactly like the
        // eval-daemon `run_git`; no ambient git config can leak into the
        // capsule provisioning.
        let mut registered_git = |cwd: &Path, args: &[&str]| -> Result<String, String> {
            let output = std::process::Command::new(&git_program)
                .args(args)
                .current_dir(cwd)
                .env_clear()
                .env("GIT_CONFIG_GLOBAL", "/dev/null")
                .env("GIT_CONFIG_SYSTEM", "/dev/null")
                .env("GIT_CONFIG_NOSYSTEM", "1")
                .env("LC_ALL", "C")
                .output()
                .map_err(|error| format!("registered capsule git failed: {error}"))?;
            if !output.status.success() {
                return Err(format!(
                    "registered capsule git exited {:?}: {}",
                    output.status.code(),
                    String::from_utf8_lossy(&output.stderr).trim()
                ));
            }
            Ok(String::from_utf8_lossy(&output.stdout).trim().to_owned())
        };
        let capsule_project = session_capsule_root(
            &mut registered_git,
            &session_state,
            &declared_project,
            &source_commit,
            &source_kind,
        )?;
        let registration = SessionRegistration {
            session: session.clone(),
            binding: binding.clone(),
            capsule_id: capsule_id.clone(),
            declared_project,
            capsule_project,
            source_commit,
            source_kind,
        };
        let replace = inner.sessions.get(&capsule_id).is_none_or(|current| {
            current.registration.session != registration.session
                || current.registration.capsule_project != registration.capsule_project
                || current.registration.source_kind != registration.source_kind
                || current.registration.binding.context_policy_digest
                    != registration.binding.context_policy_digest
        });
        if replace {
            if let Some(current) = inner.sessions.get_mut(&capsule_id) {
                current
                    .retire_scoped_tests(Instant::now() + Duration::from_secs(10))
                    .inspect_err(|_| {
                        self.retirement_failed.store(true, Ordering::Release);
                    })?;
                if let Some(backend) = current.backend.as_mut() {
                    backend
                        .retire_bounded(Instant::now() + Duration::from_secs(10))
                        .inspect_err(|_| {
                            self.retirement_failed.store(true, Ordering::Release);
                        })?;
                }
            }
            inner.sessions.insert(
                capsule_id,
                SessionAuthority {
                    registration,
                    backend: None,
                    scoped_tests: None,
                },
            );
        }
        Ok(())
    }

    /// Obtains a private backend for one already kernel-authorized call. This
    /// is the only launch seam: a raw model/extension request cannot reach it.
    fn backend_for(
        &self,
        session: &SessionId,
        capsule_id: &CapsuleId,
    ) -> Result<Arc<CanonicalV2SidecarOwner>, HostToolError> {
        if self.closed.load(Ordering::Acquire) {
            return Err(HostToolError::Storage {
                tool: "capsule_authority",
                detail: "session authority pool is shutting down".to_owned(),
            });
        }
        let signing_key = self
            .signing_key
            .as_ref()
            .ok_or_else(|| HostToolError::Catalog {
                detail: "this node does not hold the session authority minting secret \
                     (read-only follower); capsule backend provisioning is denied"
                    .to_owned(),
            })?;
        let token_path = self
            .config
            .paths
            .authority_token_root
            .join(format!("{}.json", session.as_str()));
        let token_bytes = std::fs::read(&token_path).map_err(|error| HostToolError::Storage {
            tool: "capsule_authority",
            detail: format!("operator token is unavailable: {error}"),
        })?;
        let operator_token: SeatToken =
            serde_json::from_slice(&token_bytes).map_err(|error| HostToolError::Catalog {
                detail: format!("operator token is invalid: {error}"),
            })?;
        let token_id = operator_token.token_id.to_string();

        let mut inner = self.inner.lock().map_err(|_| HostToolError::Storage {
            tool: "capsule_authority",
            detail: "session authority pool lock is poisoned".to_owned(),
        })?;
        if self.closed.load(Ordering::Acquire) {
            return Err(HostToolError::Storage {
                tool: "capsule_authority",
                detail: "session authority pool is shutting down".to_owned(),
            });
        }
        let authority =
            inner
                .sessions
                .get_mut(capsule_id)
                .ok_or_else(|| HostToolError::Catalog {
                    detail: format!("capsule {} is not registered", capsule_id.as_str()),
                })?;
        if authority.registration.session != *session {
            return Err(HostToolError::Catalog {
                detail: "registered session contradicts the invocation scope".to_owned(),
            });
        }
        if let Some(backend) = &authority.backend {
            if backend.token_id == token_id {
                return backend.owner.as_ref().map(Arc::clone).ok_or_else(|| {
                    HostToolError::Storage {
                        tool: "capsule_authority",
                        detail: "cached backend has no owner".to_owned(),
                    }
                });
            }
        }
        // A renewal must prove the old backend stopped before the new token
        // receives any private execution authority.
        if let Some(stale) = authority.backend.as_mut() {
            stale
                .retire_bounded(Instant::now() + Duration::from_secs(10))
                .map_err(|detail| {
                    self.retirement_failed.store(true, Ordering::Release);
                    HostToolError::Storage {
                        tool: "capsule_authority",
                        detail,
                    }
                })?;
        }

        let registration = authority.registration.clone();
        // The sidecar must use the publication against which the session token was minted.
        let store = SnapshotStore::new(&self.config.paths.registry_snapshot);
        let revision = registration.binding.served_revision;
        let snapshot = store
            .publication_at(revision)
            .map(|(snapshot, _)| snapshot)
            .map_err(|error| HostToolError::Catalog {
                detail: format!(
                    "session authority snapshot (revision {revision}) rejected: {error}"
                ),
            })?;
        let seat_binding = self
            .config
            .seats
            .iter()
            .find(|seat| seat.seat == registration.binding.policy.seat_id)
            .ok_or_else(|| HostToolError::Catalog {
                detail: format!(
                    "seat {} has no configured controller binding",
                    registration.binding.policy.seat_id
                ),
            })?;
        // Reaching this owner proves HostToolOperations already consumed the
        // current operator token and current accepted plan into a
        // kernel-minted PreparedEffect. This is therefore a real accepted
        // verdict, not a synthetic model/controller flag.
        let (projection_bytes, projected_token, _seat) =
            crate::eval_daemon::projection_and_token_session(
                &self.config,
                &snapshot,
                seat_binding,
                &registration.binding.policy.lane_id,
                &registration.capsule_id,
                &registration.capsule_project,
                crate::eval_daemon::SeatTokenIssuance {
                    session: registration.session.clone(),
                    signing_key,
                    provided_token: Some(&operator_token),
                    plan_accepted: true,
                },
            )
            .map_err(|detail| HostToolError::Catalog { detail })?;
        if projected_token.token_id != operator_token.token_id {
            return Err(HostToolError::Catalog {
                detail: "typed projection did not retain the operator token identity".to_owned(),
            });
        }
        let backend_root = self
            .state_root
            .join(format!("capsule-{}", capsule_id.as_str().replace(':', "-")))
            .join("backends")
            .join(token_id.replace(':', "-"));
        create_private_dir(&backend_root).map_err(|detail| HostToolError::Storage {
            tool: "capsule_authority",
            detail,
        })?;
        let projection_path = backend_root.join(format!("projection-r{}.json", snapshot.revision));
        crate::eval_daemon::publish_exact(&projection_path, &projection_bytes, 0o600).map_err(
            |detail| HostToolError::Storage {
                tool: "capsule_authority",
                detail,
            },
        )?;
        let extension_policy =
            crate::eval_daemon::session_extension_policy(&self.config, &snapshot, &backend_root)
                .map_err(|detail| HostToolError::Catalog { detail })?;
        let authority_root = backend_root.join("worker-authority");
        create_private_dir(&authority_root).map_err(|detail| HostToolError::Storage {
            tool: "capsule_authority",
            detail,
        })?;
        let launcher = crate::eval_daemon::SessionWorkerLauncher::open(
            &self.config,
            &self.manifest,
            &authority_root,
        )
        .map_err(|detail| HostToolError::Storage {
            tool: "capsule_authority",
            detail,
        })?;
        let socket_root = private_socket_root()?;
        let sidecar_state = backend_root.join("state");
        create_private_dir(&sidecar_state).map_err(|detail| HostToolError::Storage {
            tool: "capsule_authority",
            detail,
        })?;
        let launch = crate::eval_daemon::launch_session_sidecar(
            &self.config,
            &self.manifest,
            &launcher,
            &crate::eval_daemon::SessionSidecarCapsule {
                capsule_id: &registration.capsule_id,
                capsule_root: &registration.capsule_project,
                source_commit: &registration.source_commit,
                source_kind: &registration.source_kind,
                projection_path: &projection_path,
                extension_policy: &extension_policy,
            },
            &crate::eval_daemon::SessionSidecarRoots {
                socket_root: &socket_root,
                session_state: &sidecar_state,
            },
            &operator_token,
            signing_key,
        );
        let (client, lifecycle) = match launch {
            Ok(launch) => launch,
            Err(detail) => {
                self.retirement_failed.store(true, Ordering::Release);
                return Err(HostToolError::Storage {
                    tool: "capsule_authority",
                    detail,
                });
            }
        };
        let receipts: Arc<dyn CanonicalEffectReceiptReader> = Arc::new(
            PersistentEffectReceiptReader::new(sidecar_state).map_err(|detail| {
                self.retirement_failed.store(true, Ordering::Release);
                HostToolError::Storage {
                    tool: "capsule_authority",
                    detail,
                }
            })?,
        );
        let owner = Arc::new(CanonicalV2SidecarOwner::adopt(client, receipts));
        authority.backend = Some(PrivateBackend {
            token_id,
            owner: Some(Arc::clone(&owner)),
            lifecycle: Some(lifecycle),
            abandoned: false,
            pool_closed: Arc::clone(&self.closed),
            retirement: None,
        });
        Ok(owner)
    }
}

fn lock_until<T>(
    mutex: &Mutex<T>,
    deadline: Instant,
) -> Result<std::sync::MutexGuard<'_, T>, String> {
    loop {
        if Instant::now() >= deadline {
            return Err("session authority pool retirement deadline elapsed".to_owned());
        }
        match mutex.try_lock() {
            Ok(guard) => return Ok(guard),
            Err(std::sync::TryLockError::Poisoned(_)) => {
                return Err("pool lock poisoned".to_owned())
            }
            Err(std::sync::TryLockError::WouldBlock) => {
                std::thread::sleep(
                    Duration::from_millis(1)
                        .min(deadline.saturating_duration_since(Instant::now())),
                );
            }
        }
    }
}

impl Drop for SessionAuthorityPool {
    fn drop(&mut self) {
        if !self.closed.load(Ordering::Acquire) {
            let _ = self.retire_all(Instant::now() + Duration::from_secs(10));
        }
        let inner = self
            .inner
            .get_mut()
            .unwrap_or_else(|error| error.into_inner());
        for authority in inner.sessions.values_mut() {
            authority.abandon_scoped_tests();
            if let Some(backend) = authority.backend.as_mut() {
                backend.abandon();
            }
        }
    }
}

fn private_socket_root() -> Result<PathBuf, HostToolError> {
    use std::os::unix::ffi::OsStrExt as _;
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    static SERIAL: AtomicU64 = AtomicU64::new(1);
    let runtime_root = std::env::var_os("XDG_RUNTIME_DIR")
        .map(PathBuf::from)
        .ok_or_else(|| HostToolError::Storage {
            tool: "capsule_authority",
            detail: "XDG_RUNTIME_DIR is required for the private sidecar socket".to_owned(),
        })?;
    let metadata =
        std::fs::symlink_metadata(&runtime_root).map_err(|error| HostToolError::Storage {
            tool: "capsule_authority",
            detail: format!("cannot inspect XDG_RUNTIME_DIR: {error}"),
        })?;
    if !runtime_root.is_absolute()
        || !metadata.is_dir()
        || metadata.file_type().is_symlink()
        || metadata.permissions().mode() & 0o077 != 0
        || metadata.uid() != rustix::process::geteuid().as_raw()
    {
        return Err(HostToolError::Storage {
            tool: "capsule_authority",
            detail: "XDG_RUNTIME_DIR must be an absolute owner-private real directory".to_owned(),
        });
    }
    let serial = SERIAL.fetch_add(1, Ordering::Relaxed);
    let socket_root = runtime_root.join(format!(".osa-{}-{serial}", std::process::id()));
    let socket_path = socket_root.join("authority.sock");
    if socket_path.as_os_str().as_bytes().len() >= 108 {
        return Err(HostToolError::Storage {
            tool: "capsule_authority",
            detail: "XDG_RUNTIME_DIR is too long for a private Unix socket".to_owned(),
        });
    }
    std::fs::create_dir(&socket_root).map_err(|error| HostToolError::Storage {
        tool: "capsule_authority",
        detail: format!("cannot create private socket root: {error}"),
    })?;
    if let Err(error) =
        std::fs::set_permissions(&socket_root, std::fs::Permissions::from_mode(0o700))
    {
        let _ = std::fs::remove_dir(&socket_root);
        return Err(HostToolError::Storage {
            tool: "capsule_authority",
            detail: format!("cannot protect private socket root: {error}"),
        });
    }
    Ok(socket_root)
}

fn current_head_commit(manifest: &RuntimeManifest, capsule_root: &Path) -> Result<String, String> {
    let output = std::process::Command::new(
        manifest
            .executable("git")
            .map_err(|error| error.to_string())?
            .path
            .clone(),
    )
    .arg("rev-parse")
    .arg("HEAD")
    .current_dir(capsule_root)
    .env_clear()
    .output()
    .map_err(|error| format!("could not read capsule HEAD: {error}"))?;
    if !output.status.success() {
        return Err("capsule HEAD is unavailable; project root must be a git worktree".to_owned());
    }
    let commit = String::from_utf8_lossy(&output.stdout).trim().to_owned();
    if commit.len() != 40
        || !commit
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err("capsule HEAD is not a full lowercase commit".to_owned());
    }
    Ok(commit)
}

/// Git roots use their verified HEAD; knowledge roots use a canonical-path digest.
/// Knowledge roots cannot authorize source-verified effects. Git read failures propagate.
fn capsule_source_identity(
    manifest: &RuntimeManifest,
    capsule_root: &Path,
) -> Result<(String, String), String> {
    if !capsule_root.join(".git").exists() {
        let root_digest = Digest::hash(capsule_root.display().to_string().as_bytes()).to_string();
        return Ok((
            root_digest,
            odin_sidecar_protocol::SOURCE_KIND_KNOWLEDGE_ROOT.to_owned(),
        ));
    }
    current_head_commit(manifest, capsule_root).map(|commit| {
        (
            commit,
            odin_sidecar_protocol::SOURCE_KIND_GIT_COMMIT.to_owned(),
        )
    })
}

/// Retained Git capsules are verified in place, never replaced on commit mismatch.
/// Registration, not file mode, establishes ownership. Knowledge roots remain read-only.
fn session_capsule_root(
    registered_git: RegisteredGit<'_>,
    session_state: &Path,
    declared_root: &Path,
    source_commit: &str,
    source_kind: &str,
) -> Result<PathBuf, String> {
    if source_kind != odin_sidecar_protocol::SOURCE_KIND_GIT_COMMIT {
        create_private_dir(&declared_root.join(".odin-eval"))?;
        return Ok(declared_root.to_path_buf());
    }
    let capsule_parent = session_state.join("capsule");
    create_private_dir(&capsule_parent)?;
    verify_or_clone_capsule_project(
        registered_git,
        &capsule_parent,
        declared_root,
        source_commit,
    )
}

#[cfg(test)]
mod session_capsule_tests {
    use std::fs;
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
    use std::path::{Path, PathBuf};
    use std::process::Command;

    use tempfile::TempDir;

    use super::*;
    use crate::test_support::{commit_all, git};

    const SOURCE_KIND_GIT: &str = odin_sidecar_protocol::SOURCE_KIND_GIT_COMMIT;
    const SOURCE_KIND_KNOWLEDGE: &str = odin_sidecar_protocol::SOURCE_KIND_KNOWLEDGE_ROOT;

    /// The session-pool git runner, environment-free exactly like the
    /// production closure in `register_session`.
    fn registered_git(cwd: &Path, args: &[&str]) -> Result<String, String> {
        let output = Command::new("git")
            .args(args)
            .current_dir(cwd)
            .env_clear()
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_CONFIG_SYSTEM", "/dev/null")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("LC_ALL", "C")
            .output()
            .map_err(|error| format!("registered capsule git failed: {error}"))?;
        if !output.status.success() {
            return Err(format!(
                "registered capsule git exited {:?}: {}",
                output.status.code(),
                String::from_utf8_lossy(&output.stderr).trim()
            ));
        }
        Ok(String::from_utf8_lossy(&output.stdout).trim().to_owned())
    }

    fn fixture_git_project(root: &Path, name: &str, mode: u32) -> (PathBuf, String) {
        let project = root.join(name);
        fs::create_dir(&project).expect("create fixture project");
        fs::write(project.join("flake.nix"), b"{ }\n").expect("write fixture file");
        git(&project, &["-c", "init.defaultBranch=main", "init"]);
        let head = commit_all(&project, "fixture commit");
        fs::set_permissions(&project, fs::Permissions::from_mode(mode))
            .expect("set fixture project mode");
        (project, head)
    }

    fn mode_of(path: &Path) -> u32 {
        fs::metadata(path)
            .expect("path exists")
            .permissions()
            .mode()
            & 0o7777
    }

    #[test]
    fn user_owned_checkout_materializes_capsule_regardless_of_mode() {
        // Ownership comes from materialization, never from a permission
        // mode: a user's own private checkout must not become a mutable
        // capsule any more than a world-readable one, so both materialize
        // the same private retained capsule.
        for mode in [0o700, 0o755] {
            let temporary = TempDir::new().expect("fixture root");
            let session_state = temporary.path().join("state").join("capsule-x");
            let (root, head) = fixture_git_project(temporary.path(), "project", mode);
            let mut registered = registered_git;
            let capsule = session_capsule_root(
                &mut registered,
                &session_state,
                &root,
                &head,
                SOURCE_KIND_GIT,
            )
            .expect("declared git project materializes its capsule");
            assert_eq!(
                capsule,
                session_state.join("capsule").join("project"),
                "the capsule must be the kernel-issued retained capsule"
            );
            assert_eq!(mode_of(&capsule), 0o700, "the capsule root must be 0700");
            assert_eq!(mode_of(&root), mode, "the declared root must not change");
            assert!(
                !root.join(".odin-eval").exists(),
                "the declared root must not gain an eval scratch directory"
            );
            odin_confined_fs::PrivateCapability::seal(&capsule).expect("the capsule must seal");
        }
    }

    #[test]
    fn declared_git_project_capsule_retains_and_never_deletes() {
        let temporary = TempDir::new().expect("fixture root");
        let session_state = temporary.path().join("state").join("capsule-x");
        let (root, head) = fixture_git_project(temporary.path(), "project", 0o755);
        let mut registered = registered_git;

        let capsule = session_capsule_root(
            &mut registered,
            &session_state,
            &root,
            &head,
            SOURCE_KIND_GIT,
        )
        .expect("declared git project materializes its capsule");
        assert_eq!(
            mode_of(&capsule.join(".odin-eval")),
            0o700,
            "the capsule scratch root must be 0700"
        );
        assert_eq!(
            git(&capsule, &["rev-parse", "HEAD"]),
            head,
            "the capsule must pin the declared source commit"
        );
        assert!(
            !capsule.join(".git/objects/info/alternates").exists(),
            "the dissociated capsule object store must be self-contained"
        );

        // Re-registration with an unchanged commit retains the capsule.
        let identity = fs::metadata(&capsule).expect("capsule metadata").ino();
        let retained = session_capsule_root(
            &mut registered,
            &session_state,
            &root,
            &head,
            SOURCE_KIND_GIT,
        )
        .expect("re-registration succeeds");
        assert_eq!(retained, capsule);
        assert_eq!(
            fs::metadata(&capsule).expect("capsule metadata").ino(),
            identity,
            "an unchanged capsule must be retained, not re-created"
        );

        // A moved source commit is a typed refusal; the retained capsule and
        // its work are untouched.
        fs::write(root.join("flake.nix"), b"{ } // drift\n").expect("write drift fixture source");
        let _second = commit_all(&root, "second fixture commit");
        let error = session_capsule_root(
            &mut registered,
            &session_state,
            &root,
            &_second,
            SOURCE_KIND_GIT,
        )
        .expect_err("source drift must refuse typed");
        assert!(
            error.contains("does not match its source commit"),
            "the refusal must name the capsule drift: {error}"
        );
        assert_eq!(
            fs::metadata(&capsule).expect("capsule metadata").ino(),
            identity,
            "a drifted re-registration must never delete the retained capsule"
        );
        assert_eq!(
            git(&capsule, &["rev-parse", "HEAD"]),
            head,
            "the retained capsule must keep its original work"
        );
    }

    #[test]
    fn knowledge_root_registers_directly_read_only() {
        // A declared knowledge root has no materializer and no mutable
        // capsule: registration stays on the declared root — including its
        // eval scratch root — mode-independently, so the session opens as
        // before.
        for mode in [0o755, 0o700] {
            let temporary = TempDir::new().expect("fixture root");
            let session_state = temporary.path().join("state").join("capsule-x");
            let knowledge = temporary.path().join("vault");
            fs::create_dir(&knowledge).expect("create knowledge root");
            fs::write(knowledge.join("note.md"), b"facts\n").expect("write note");
            fs::set_permissions(&knowledge, fs::Permissions::from_mode(mode))
                .expect("set knowledge root mode");
            let mut registered = registered_git;
            let registered_root = session_capsule_root(
                &mut registered,
                &session_state,
                &knowledge,
                "0".repeat(40).as_str(),
                SOURCE_KIND_KNOWLEDGE,
            )
            .expect("knowledge root session registers");
            assert_eq!(
                registered_root, knowledge,
                "the knowledge root registers as itself"
            );
            assert!(
                knowledge.join(".odin-eval").exists(),
                "the knowledge root keeps its eval scratch root"
            );
            assert_eq!(
                mode_of(&knowledge),
                mode,
                "the knowledge root must not change"
            );
            assert!(
                !session_state.join("capsule").join("project").exists(),
                "no mutable capsule may be materialized for a knowledge root"
            );
        }
    }

    #[test]
    fn capsule_object_store_survives_its_borrowing_source() {
        // A declared root that only borrows objects (--shared clone) must
        // still yield a capsule whose git evidence is fully local: after the
        // source and its object store are gone, the capsule still resolves
        // its pinned commit and still seals.
        let temporary = TempDir::new().expect("fixture root");
        let origin = temporary.path().join("origin");
        fs::create_dir(&origin).expect("create origin");
        fs::write(origin.join("flake.nix"), b"{ }\n").expect("write origin file");
        git(&origin, &["-c", "init.defaultBranch=main", "init"]);
        let head = commit_all(&origin, "origin commit");
        let worktree = temporary.path().join("worktree");
        git(
            &origin,
            &[
                "clone",
                "--quiet",
                "--shared",
                &origin.display().to_string(),
                &worktree.display().to_string(),
            ],
        );
        fs::set_permissions(&worktree, fs::Permissions::from_mode(0o755))
            .expect("set worktree mode");
        let session_state = temporary.path().join("state").join("capsule-x");
        let mut registered = registered_git;
        let capsule = session_capsule_root(
            &mut registered,
            &session_state,
            &worktree,
            &head,
            SOURCE_KIND_GIT,
        )
        .expect("a borrowing source materializes its capsule");

        fs::remove_dir_all(&worktree).expect("remove the declared source");
        fs::remove_dir_all(&origin).expect("remove the borrowed object store");
        assert_eq!(
            git(&capsule, &["show", "-s", "--format=%H", "HEAD"]),
            head,
            "the capsule's git evidence must not need its source"
        );
        odin_confined_fs::PrivateCapability::seal(&capsule)
            .expect("the capsule must seal without its source");
    }

    #[test]
    fn every_created_capsule_sees_the_mergiraf_driver() {
        let temporary = TempDir::new().expect("fixture root");
        let session_state = temporary.path().join("state").join("capsule-x");
        let (root, head) = fixture_git_project(temporary.path(), "project", 0o755);
        let mut registered = registered_git;
        let capsule = session_capsule_root(
            &mut registered,
            &session_state,
            &root,
            &head,
            SOURCE_KIND_GIT,
        )
        .expect("declared git project materializes its capsule");
        assert_eq!(
            registered(&capsule, &["config", "merge.mergiraf.name"]).unwrap(),
            "mergiraf"
        );
        assert_eq!(
            registered(&capsule, &["config", "merge.mergiraf.driver"]).unwrap(),
            crate::eval_daemon::mergiraf_driver()
        );
        assert_eq!(
            registered(&capsule, &["config", "merge.conflictstyle"]).unwrap(),
            "diff3"
        );
        let attributes = fs::read_to_string(capsule.join(".git").join("info").join("attributes"))
            .expect("the capsule's local attribute block");
        assert!(attributes
            .lines()
            .any(|line| line.trim() == "* merge=mergiraf"));
    }
}

// Preflight checks the declared terminal through the resolver without creating resources.
#[cfg(test)]
mod preflight_tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::fs;
    use std::num::NonZeroU16;
    use std::os::unix::fs::PermissionsExt as _;
    use std::sync::Mutex as StdMutex;
    use std::time::Duration as StdDuration;

    use async_trait::async_trait;
    use odin_domain::huginn::{LiveError, SessionManifest};
    use odin_kernel::StopAuthority;
    use odin_ledger::lane_run::{create_lane, create_run, NewLane, NewRun};
    use odin_ledger::plan::{TodoSpec, TodoStatus};
    use odin_omp::host_tools::delegation::ChildAuthorityProvisioner as _;
    use odin_omp::live::ledger::fs::FsLiveLedger;
    use odin_omp::live::supervisor::{LiveSessionLauncher, LiveSupervisor, SessionRuntime};
    use odin_omp::live::target::TerminalTargetAdmin;
    use odin_omp::live::zellij::ZellijCliFactory;
    use odin_omp::process::OmpWorkerLaunch;
    use odin_process::test_support::RegisteredWorkerFixture;
    use odin_process::{RegisteredServiceBinding, ScopeLimits};
    use odin_types::CorrelationId;
    use time::OffsetDateTime;

    use crate::authority_provision::fixture::{self, Fixture};

    /// Exact libtest entry the registered-worker fixture re-execs as the
    /// real bootstrap for the scripted zellij process boundary.
    #[test]
    fn worker_bootstrap_fixture_entry() {
        odin_process::test_support::run_bootstrap_if_active();
    }

    const BOOTSTRAP_ENTRY: &str = "live_authority::preflight_tests::worker_bootstrap_fixture_entry";

    /// One scripted `zellij` executable: records every argv line at
    /// `log_path` (the recorded process boundary proving preflight never
    /// creates a surface) and answers `list-sessions --no-formatting`
    /// with the observed zellij 0.45 line format for `live_sessions`.
    fn write_zellij_script(root: &Path, live_sessions: &[&str]) -> (PathBuf, PathBuf) {
        let executable = root.join("zellij-script.sh");
        let log_path = root.join("zellij-argv.log");
        let mut list = String::new();
        for session in live_sessions {
            list.push_str(&format!("printf '%s\\n' '{session} [Created 1h ago] '\n"));
        }
        let script = format!(
            "#!/bin/sh\n\
             printf '%s\\n' \"$*\" >> '{}'\n\
             if [ \"$1\" = \"list-sessions\" ]; then\n{list}fi\n",
            log_path.display()
        );
        fs::write(&executable, script).expect("write scripted zellij");
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o755))
            .expect("chmod scripted zellij");
        (executable, log_path)
    }

    fn unshare_bin() -> PathBuf {
        if let Some(value) = std::env::var_os("ODIN_TEST_WORKER_UNSHARE") {
            let path = PathBuf::from(value);
            assert!(path.is_absolute() && path.is_file(), "unshare override");
            return path;
        }
        let path_var = std::env::var_os("PATH").unwrap_or_default();
        std::env::split_paths(&path_var)
            .map(|directory| directory.join("unshare"))
            .find(|candidate| candidate.is_absolute() && candidate.is_file())
            .expect("no absolute unshare found on PATH")
    }

    /// The production launch contract over the private registered-worker
    /// fixture, mirroring the odin-omp process test harness. The fixture
    /// owns the fake manager that serves the worker bootstrap's private
    /// gate, so the returned Arc MUST be retained for every launch use —
    /// `OmpWorkerLaunch`'s retention field is odin-omp-private, and the
    /// fixture's Drop stops the manager and deletes the bootstrap wrapper.
    fn zellij_worker_launch(executable: &Path) -> (OmpWorkerLaunch, Arc<RegisteredWorkerFixture>) {
        let fixture = Arc::new(RegisteredWorkerFixture::new().expect("registered worker fixture"));
        let harness = std::env::current_exe().expect("test harness executable");
        let channel = fixture
            .channel_for_harness(&harness, BOOTSTRAP_ENTRY, &unshare_bin())
            .expect("worker fixture channel");
        let canonical = fs::canonicalize(executable).expect("scripted zellij");
        let digest = blake3::hash(&fs::read(&canonical).expect("hash scripted zellij"))
            .to_hex()
            .to_string();
        let binding = RegisteredServiceBinding::new(canonical, digest).expect("service binding");
        let ledger = odin_ledger::Ledger::open_in_memory().expect("in-memory ledger");
        let authority = Arc::new(StopAuthority::new(Arc::new(Mutex::new(ledger)), channel));
        let correlation =
            CorrelationId::new("0123456789abcdef0123456789abcdef").expect("test correlation");
        let launch = OmpWorkerLaunch::new(
            authority,
            correlation,
            "odin-cli",
            "delegation-preflight",
            1,
            binding,
            ScopeLimits::default(),
        )
        .expect("worker launch");
        (launch, fixture)
    }

    /// A launcher that owns no bridge: `open` is unreachable from the
    /// preflight path under test, and the terminal administration is the
    /// REAL composed zellij factory.
    struct TerminalOnlyLauncher {
        admin: Arc<dyn TerminalTargetAdmin>,
        opens: Arc<StdMutex<usize>>,
    }

    #[async_trait]
    impl LiveSessionLauncher for TerminalOnlyLauncher {
        fn harness_turns(&self) -> Option<std::sync::Arc<odin_omp::live::harness::HarnessTurns>> {
            None
        }

        async fn open(
            &self,
            _manifest: &SessionManifest,
            _epoch: odin_domain::huginn::SessionEpoch,
            _reclaim: bool,
        ) -> Result<SessionRuntime, LiveError> {
            *self.opens.lock().expect("opens") += 1;
            Err(LiveError::Unavailable {
                code: "terminal_only_launcher".to_owned(),
            })
        }

        fn terminal_target_admin(&self) -> Option<Arc<dyn TerminalTargetAdmin>> {
            Some(self.admin.clone())
        }
    }

    /// Production dispatch calls the sync `preflight_child` from a thread
    /// that carries the daemon runtime's current handle WITHOUT the
    /// runtime-entered flag; the provisioner's observation seam
    /// (`Handle::block_on`) panics on an entered thread and errors with no
    /// current handle. An async test body IS an entered thread, so the
    /// sync preflight under test runs here on a plain thread with only the
    /// current handle installed — exactly production's thread state, no
    /// production seam changed.
    fn run_sync<T>(run: impl FnOnce() -> T + Send) -> T
    where
        T: Send,
    {
        let handle = tokio::runtime::Handle::current();
        std::thread::scope(|scope| {
            scope
                .spawn(move || {
                    let _current = handle.enter();
                    run()
                })
                .join()
                .expect("the sync preflight thread must not panic")
        })
    }

    /// The assembled readiness path under test: fixture
    /// config/publication kept alive, an accepted parent plan, a real fs
    /// live ledger, a real supervisor over the REAL scripted-zellij
    /// factory, and the provisioner.
    struct PreflightFixture {
        _authority_fixture: Fixture,
        _temporary: tempfile::TempDir,
        // The fixture holds the ONLY strong supervisor handle: the
        // provisioner and the preflight path observe the supervisor
        // through a Weak, so a dropped strong handle reads as "live
        // supervisor is not running". The supervisor outlives every
        // preflight assertion.
        _supervisor: Arc<LiveSupervisor>,
        // The registered-worker fixture owns the fake manager serving the
        // worker bootstrap's private gate; dropping it stops the manager
        // and deletes the bootstrap wrapper, so it lives exactly as long
        // as the factory may still launch the scripted zellij.
        _worker_fixture: Arc<RegisteredWorkerFixture>,
        config: OdindConfig,
        provisioner: PoolChildProvisioner,
        launcher_opens: Arc<StdMutex<usize>>,
        argv_log: PathBuf,
        token_root_before: Vec<PathBuf>,
        parent_session: SessionId,
        caller_seat: SeatId,
        lane: odin_domain::LaneId,
        project: odin_domain::ProjectId,
    }

    fn walk_files(root: &Path) -> Vec<PathBuf> {
        let mut files = Vec::new();
        let mut pending = vec![root.to_path_buf()];
        while let Some(directory) = pending.pop() {
            if let Ok(entries) = fs::read_dir(&directory) {
                for entry in entries.flatten() {
                    let path = entry.path();
                    if path.is_dir() {
                        pending.push(path);
                    } else {
                        files.push(path);
                    }
                }
            }
        }
        files.sort();
        files
    }

    fn assemble(live_sessions: &[&str], attach_command: Vec<String>) -> PreflightFixture {
        let authority_fixture = fixture::fixture();
        let temporary = tempfile::TempDir::new().expect("preflight root");
        let root = temporary.path();
        let mut config = authority_fixture.config.clone();
        let declared_session = "brain-m6b";
        config.executables.zellij_session = declared_session.to_owned();
        config.executables.attach_command = attach_command;

        // The parent's accepted plan through the same ledger API
        // production uses.
        let bridge_ledger = Arc::new(Mutex::new(
            odin_ledger::Ledger::open_in_memory().expect("bridge ledger"),
        ));
        let parent_session =
            odin_domain::SessionId::new("00000000-0000-4000-8000-0000000000a1").expect("session");
        let parent_run =
            odin_domain::RunId::new(format!("run:live:{parent_session}")).expect("parent run");
        let lane = odin_domain::LaneId::new("architect-odin").expect("lane");
        {
            let mut guard = bridge_ledger.lock().expect("bridge ledger lock");
            create_lane(
                guard.connection(),
                &NewLane {
                    lane_id: lane.clone(),
                    seat_id: SeatId::new("architect").expect("seat"),
                    project_id: None,
                    template_id: "template:dev".to_owned(),
                    backend: "local_omp".to_owned(),
                    created_by: "operator".to_owned(),
                    created_at: OffsetDateTime::UNIX_EPOCH,
                    retained: false,
                },
            )
            .expect("parent lane");
            create_run(
                guard.connection(),
                &NewRun {
                    run_id: parent_run.clone(),
                    lane_id: lane.clone(),
                    attempt_number: 1,
                    workflow_id: Some("live:fixture".to_owned()),
                    workflow_version: Some(1),
                    input_hash: "fixture".to_owned(),
                    accepted_capability_revision: None,
                    lease_id: None,
                    absolute_deadline: None,
                    retry_budget: 0,
                    created_at: OffsetDateTime::UNIX_EPOCH,
                },
            )
            .expect("parent run");
            let plan = guard
                .replace_plan(
                    &parent_run,
                    "Parent objective",
                    &[TodoSpec {
                        id: odin_domain::TodoId::new("todo:parent").expect("todo"),
                        title: "Parent todo".to_owned(),
                        status: TodoStatus::Pending,
                    }],
                    0,
                    OffsetDateTime::UNIX_EPOCH,
                )
                .expect("parent plan");
            guard
                .accept_plan(
                    &parent_run,
                    plan.revision,
                    "operator:fixture",
                    OffsetDateTime::UNIX_EPOCH,
                )
                .expect("accept parent plan");
        }

        let live_ledger =
            Arc::new(FsLiveLedger::open(root.join("live-ledger")).expect("fs live ledger"));
        let (script, argv_log) = write_zellij_script(root, live_sessions);
        let (worker_launch, worker_fixture) = zellij_worker_launch(&script);
        let factory = ZellijCliFactory::open(
            &script,
            declared_session,
            root.join("terminal"),
            StdDuration::from_secs(15),
            NonZeroU16::new(80).expect("80 is non-zero"),
            NonZeroU16::new(24).expect("24 is non-zero"),
            worker_launch,
        )
        .expect("real zellij factory");
        let launcher_opens = Arc::new(StdMutex::new(0usize));
        let launcher: Arc<dyn LiveSessionLauncher> = Arc::new(TerminalOnlyLauncher {
            admin: Arc::new(factory),
            opens: Arc::clone(&launcher_opens),
        });
        let supervisor = LiveSupervisor::new(live_ledger, launcher, 8, None);
        let supervisor_handle: SupervisorHandle = Arc::new(std::sync::OnceLock::new());
        supervisor_handle
            .set(Arc::downgrade(&supervisor))
            .expect("supervisor handle");

        let manifest = odin_huginn::RuntimeManifest {
            schema: odin_huginn::RUNTIME_MANIFEST_SCHEMA.to_owned(),
            executables: BTreeMap::new(),
            odind_config: odin_huginn::PathDigestRef {
                path: root.join("odind-binding.toml"),
                digest: format!("blake3:{}", "b".repeat(64)),
            },
        };
        let pool = SessionAuthorityPool::open_denied(&config, &manifest).expect("pool");
        let provisioner = PoolChildProvisioner::new(
            pool,
            &config,
            "gateway".to_owned(),
            "zai-glm".to_owned(),
            300,
            supervisor_handle,
            bridge_ledger,
        );
        PreflightFixture {
            token_root_before: walk_files(&config.paths.authority_token_root),
            _authority_fixture: authority_fixture,
            _temporary: temporary,
            _supervisor: supervisor,
            _worker_fixture: worker_fixture,
            config,
            provisioner,
            launcher_opens,
            argv_log,
            parent_session,
            // The fixture has one seat; cross-seat equality is rejected by the caller.
            caller_seat: SeatId::new("architect").expect("caller seat"),
            lane,
            project: odin_domain::ProjectId::new("odin").expect("project"),
        }
    }

    impl PreflightFixture {
        fn preflight_same_seat(&self) -> Result<(), String> {
            self.provisioner.preflight_child(
                &self.caller_seat,
                &self.lane,
                &self.parent_session,
                &self.project,
                None,
                None,
            )
        }

        fn preflight_cross_seat(&self) -> Result<(), String> {
            self.provisioner.preflight_child(
                &self.caller_seat,
                &self.lane,
                &self.parent_session,
                &self.project,
                Some(&SeatId::new("architect").expect("target seat")),
                None,
            )
        }

        /// The recorded process boundary: every zellij argv observed, in
        /// order. `list-sessions` is the ONLY lawful preflight invocation —
        /// no `action`, no `new-tab`, no attach client. The log appears at
        /// the first invocation, so a missing file proves zero invocations.
        fn observed_argv(&self) -> Vec<String> {
            fs::read_to_string(&self.argv_log)
                .map(|text| text.lines().map(|line| line.to_owned()).collect())
                .unwrap_or_default()
        }

        fn assert_nothing_was_created(&self) {
            assert!(
                self.observed_argv()
                    .iter()
                    .all(|line| line.starts_with("list-sessions")),
                "preflight must never create a surface: every observed zellij \
                 invocation is a read-only list-sessions, got {:?}",
                self.observed_argv()
            );
            assert_eq!(
                *self.launcher_opens.lock().expect("opens"),
                0,
                "preflight never opens a child session"
            );
            assert_eq!(
                walk_files(&self.config.paths.authority_token_root),
                self.token_root_before,
                "preflight mints no child token: the authority token root is byte-identical"
            );
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn cross_seat_preflight_refuses_missing_declared_surface() {
        let fixture = assemble(
            &["unrelated-operator"],
            vec!["/bin/echo".to_owned(), "attach".to_owned()],
        );
        let error = run_sync(|| fixture.preflight_cross_seat())
            .expect_err("a dead declared surface refuses at preflight");
        assert!(
            error.contains("not found") && error.contains("brain-m6b"),
            "the real resolver names the missing declared surface: {error}"
        );
        assert_eq!(
            fixture.observed_argv(),
            vec!["list-sessions --no-formatting"]
        );
        fixture.assert_nothing_was_created();
    }

    /// The ready surface follows the normal path: preflight observes the
    /// declared session live through the real boundary and passes, still
    /// without minting or opening anything.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn cross_seat_preflight_passes_when_the_declared_surface_is_live() {
        let fixture = assemble(
            &["brain-m6b"],
            vec!["/bin/echo".to_owned(), "attach".to_owned()],
        );
        run_sync(|| fixture.preflight_cross_seat())
            .expect("the live declared surface passes preflight");
        assert_eq!(
            fixture.observed_argv(),
            vec!["list-sessions --no-formatting"]
        );
        fixture.assert_nothing_was_created();
    }

    // Same-seat workers open no terminal tab, so they need no terminal preflight.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn same_seat_preflight_declares_no_terminal_gate() {
        let fixture = assemble(&[], Vec::new());
        run_sync(|| fixture.preflight_same_seat())
            .expect("the same-seat route never observes the terminal surface");
        fixture.assert_nothing_was_created();
    }

    /// The cross-seat tab requires the declared attach client: an
    /// unconfigured attach command refuses typed even on a live surface —
    /// the exact refusal `open_terminal` would produce at the open.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn cross_seat_preflight_requires_the_attach_client() {
        let fixture = assemble(&["brain-m6b"], Vec::new());
        let error = run_sync(|| fixture.preflight_cross_seat())
            .expect_err("an unconfigured attach client refuses the cross-seat tab");
        assert!(
            error.contains("terminal_attach_command_unconfigured"),
            "unexpected refusal: {error}"
        );
        fixture.assert_nothing_was_created();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn preflight_runs_the_composition_law_read_only() {
        let fixture = assemble(&["brain-m6b"], Vec::new());
        let error = run_sync(|| {
            fixture.provisioner.preflight_child(
                &fixture.caller_seat,
                &fixture.lane,
                &fixture.parent_session,
                &odin_domain::ProjectId::new("research").expect("project"),
                None,
                None,
            )
        })
        .expect_err("an unbound project refuses the derivation law");
        assert!(
            error.contains("no configured session lane"),
            "unexpected refusal: {error}"
        );
        assert!(
            fixture.observed_argv().is_empty(),
            "a derivation refusal never reaches the surface observation"
        );
        fixture.assert_nothing_was_created();
    }
}

#[cfg(test)]
mod wait_tests {
    /// Q2: delegation control reached from a runtime worker used to call
    /// `Handle::block_on` there, which panics inside an async context.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn supervisor_control_waits_from_a_runtime_worker() {
        assert_eq!(
            super::block_on(async { Ok::<_, String>(7) }),
            Ok(7),
            "a worker hands itself off instead of panicking"
        );
    }
}

// Retirement must respect the shared deadline and disarm cleanup on abandonment.
#[cfg(test)]
mod retirement_tests {
    use std::fs;
    use std::os::unix::fs::PermissionsExt as _;
    use std::sync::Mutex as StdMutex;
    use std::time::{Duration, Instant};

    use odin_kernel::{
        recovery_worker_channel, AllowedParentBindings, ParentBrokerServer, StopAuthority,
    };
    use odin_ledger::Ledger;
    use odin_process::mint_worker_id;
    use tempfile::TempDir;

    use super::*;
    use crate::eval_daemon::SessionSidecarLifecycle;

    /// One owner-private 0700 directory beneath the probe root — the same
    /// contract the broker's root validation enforces in production.
    fn private_dir(root: &Path, name: &str) -> PathBuf {
        let dir = root.join(name);
        fs::create_dir(&dir).expect("private probe directory");
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).expect("0700 probe directory");
        dir
    }

    // An empty worker registry makes every stop fail immediately.
    fn probe_lifecycle(socket_root: &Path) -> (Arc<StopAuthority>, SessionSidecarLifecycle) {
        let channel = recovery_worker_channel("unix:path=/tmp/odin-retirement-probe-bus.sock")
            .expect("probe worker channel");
        let ledger = Arc::new(StdMutex::new(
            Ledger::open_in_memory().expect("probe ledger"),
        ));
        let authority = Arc::new(StopAuthority::new(ledger, channel));
        let lifecycle = SessionSidecarLifecycle::new(
            None,
            Arc::clone(&authority),
            Some(mint_worker_id().expect("probe worker id")),
            socket_root.to_path_buf(),
        );
        (authority, lifecycle)
    }

    #[test]
    fn retire_bounded_surfaces_the_stop_failure_within_the_deadline() {
        let temporary = TempDir::new().expect("probe root");
        let socket_root = temporary.path().join("sockets");
        fs::create_dir(&socket_root).expect("socket root");
        let (_authority, mut lifecycle) = probe_lifecycle(&socket_root);
        let started = Instant::now();
        let error = lifecycle
            .retire_bounded(started + Duration::from_secs(10))
            .expect_err("an unregistered worker must not stop cleanly");
        assert!(
            error.contains("session sidecar stop failed"),
            "the surfaced failure must name the stop: {error}"
        );
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "a failed stop must surface immediately, took {:?}",
            started.elapsed()
        );
        // The failed deadline-owned guard retains its identity and disarms
        // classic retirement rather than starting a second budget in Drop.
        drop(lifecycle);
    }

    #[test]
    fn retire_bounded_refuses_a_spent_budget_without_any_stop() {
        let temporary = TempDir::new().expect("probe root");
        let socket_root = temporary.path().join("sockets");
        fs::create_dir(&socket_root).expect("socket root");
        let (_authority, mut lifecycle) = probe_lifecycle(&socket_root);
        let error = lifecycle
            .retire_bounded(Instant::now() - Duration::from_secs(1))
            .expect_err("a spent budget must refuse the stop");
        assert!(
            error.contains("budget was already spent"),
            "the refusal must name the spent budget: {error}"
        );
        drop(lifecycle);
    }

    #[test]
    fn multiple_backends_share_expired_deadline_without_drop_retirement() {
        let temporary = TempDir::new().expect("probe root");
        let closed = Arc::new(AtomicBool::new(true));
        let deadline = Instant::now() - Duration::from_secs(1);
        for name in ["first", "second"] {
            let socket_root = private_dir(temporary.path(), name);
            let socket = socket_root.join("authority.sock");
            fs::write(&socket, b"retained capability").expect("socket marker");
            let (_authority, lifecycle) = probe_lifecycle(&socket_root);
            let mut backend = PrivateBackend {
                token_id: name.to_owned(),
                owner: None,
                lifecycle: Some(lifecycle),
                abandoned: false,
                pool_closed: Arc::clone(&closed),
                retirement: None,
            };
            assert!(backend
                .retire_bounded(deadline)
                .expect_err("shared deadline is spent")
                .contains("budget was already spent"));
            drop(backend);
            assert!(socket.exists(), "no hidden Drop cleanup for {name}");
        }
    }

    // Unguarded broker cleanup would remove this socket; abandonment must preserve it.
    #[test]
    fn abandon_disarms_the_drop_fallback_for_worker_and_broker() {
        let temporary = TempDir::new().expect("probe root");
        let runtime_root = private_dir(temporary.path(), "runtime");
        let storage_root = private_dir(temporary.path(), "storage");
        let socket_root = private_dir(temporary.path(), "sockets");

        let channel = recovery_worker_channel("unix:path=/tmp/odin-retirement-probe-bus.sock")
            .expect("probe worker channel");
        let owner = Arc::new(StdMutex::new(
            Ledger::open_in_memory().expect("owner ledger"),
        ));
        let broker = ParentBrokerServer::bind(
            &runtime_root,
            &storage_root,
            channel.clone(),
            AllowedParentBindings::default(),
            owner,
        )
        .expect("probe broker");
        let scoped = mint_worker_id().expect("scoped worker id");
        broker.prepare_scope(&scoped).expect("prepared scope");

        let ledger = Arc::new(StdMutex::new(
            Ledger::open_in_memory().expect("probe ledger"),
        ));
        let authority = Arc::new(StopAuthority::new(ledger, channel));
        let mut lifecycle = crate::eval_daemon::SessionSidecarLifecycle::new(
            Some(broker),
            authority,
            Some(mint_worker_id().expect("probe worker id")),
            socket_root,
        );
        lifecycle.abandon();
        drop(lifecycle);

        let socket_path = runtime_root.join("broker").join("authority.sock");
        assert!(
            socket_path.exists(),
            "an abandoned broker must keep its capability socket; Drop settled it"
        );
        assert!(
            storage_root.join(scoped.as_str()).exists(),
            "an abandoned broker must keep the scope store untouched"
        );
    }

    #[test]
    fn pool_retirement_surface_is_complete_and_idempotent_when_empty() {
        let temporary = TempDir::new().expect("probe root");
        let pool = probe_pool(temporary.path());
        let proof = pool.retire_all(Instant::now() + Duration::from_secs(8));
        assert!(proof.complete(), "an empty pool must retire completely");
        assert!(proof.retired.is_empty());
        assert!(pool.abandon_all().complete());
    }

    #[test]
    fn expired_retirement_never_waits_for_an_inflight_pool_owner() {
        let temporary = TempDir::new().expect("probe root");
        let pool = probe_pool(temporary.path());
        let guard = pool.inner.lock().expect("pool owner");
        let proof = pool.retire_all(Instant::now() - Duration::from_secs(1));
        assert!(!proof.complete());
        assert!(proof.incomplete[0].reason.contains("still in use"));
        assert!(pool.closed.load(Ordering::Acquire));
        assert!(!pool.abandon_all().complete());
        drop(guard);
        assert!(pool.abandon_all().complete());
    }

    #[test]
    fn poisoned_pool_is_disarmed_instead_of_leaving_a_drop_fallback() {
        let temporary = TempDir::new().expect("probe root");
        let pool = probe_pool(temporary.path());
        let poisoned = Arc::clone(&pool);
        assert!(std::thread::spawn(move || {
            let _guard = poisoned.inner.lock().expect("pool owner");
            panic!("poison the pool");
        })
        .join()
        .is_err());
        let proof = pool.retire_all(Instant::now());
        assert!(!proof.complete());
        assert!(proof.incomplete[0].reason.contains("backends disarmed"));
        assert!(pool.closed.load(Ordering::Acquire));
    }

    #[test]
    fn setup_owner_drop_closes_pool_without_waiting_for_inflight_work() {
        let temporary = TempDir::new().expect("probe root");
        let pool = probe_pool(temporary.path());
        let shutdown = pool.shutdown_guard();
        let inflight = pool.inner.lock().expect("inflight authority work");
        drop(shutdown);
        assert!(pool.closed.load(Ordering::Acquire));
        drop(inflight);
        assert!(pool.abandon_all().complete());
    }

    fn probe_pool(root: &Path) -> Arc<SessionAuthorityPool> {
        let mut executables = BTreeMap::new();
        executables.insert(
            "git".to_owned(),
            odin_huginn::PathDigestRef {
                path: PathBuf::from("/run/current-system/sw/bin/git"),
                digest: format!("blake3:{}", "a".repeat(64)),
            },
        );
        let manifest = RuntimeManifest {
            schema: odin_huginn::RUNTIME_MANIFEST_SCHEMA.to_owned(),
            executables,
            odind_config: odin_huginn::PathDigestRef {
                path: PathBuf::from("/tmp/retirement-probe-odind.toml"),
                digest: format!("blake3:{}", "b".repeat(64)),
            },
        };
        let config_text =
            format!(
            "schema = 'odin.odind-config.v1'\nrevision = 1\nworker_bus = 'unix:path=/tmp/bus.sock'\n\
             [identity]\nnode = 'laptop'\n[paths]\nregistry_root = '/'\nstate_root = '{}'\n\
             registry_snapshot = '/'\nauthority_verification_key_file = '/'\n\
             authority_token_root = '{}'\n[listener]\naddress = '127.0.0.1:18420'\n\
             [executables]\nomp_bin = '/omp'\nomp_revision = '{}'\nextension = '/ext.ts'\n\
             zellij_bin = '/zellij'\nzellij_session = 'odin'\n\
             [catalogs.gateway_projection]\npath = '/p.json'\ndigest = 'blake3:{}'\n\
             [publish]\nrender_session = 'live'\nfile_lane = 'f'\nrender_lane = 'r'\n\
             [capacity]\n",
            root.join("state").display(),
            root.join("state").join("authority/tokens").display(),
            "a".repeat(40),
            "c".repeat(64),
        );
        let config = OdindConfig::parse(&config_text).expect("probe config parses");
        SessionAuthorityPool::open(&config, &manifest, vec![0u8; 32]).expect("pool")
    }

    #[test]
    fn pool_lock_wait_obeys_absolute_deadline() {
        let mutex = Mutex::new(());
        let _guard = mutex.lock().expect("test mutex is not poisoned");
        let started = Instant::now();
        let result = lock_until(&mutex, started + Duration::from_millis(20));
        assert!(result.unwrap_err().contains("deadline elapsed"));
        assert!(started.elapsed() < Duration::from_secs(1));
    }

    #[test]
    fn expired_backend_retirement_remains_failed_without_drop_retry() {
        let mut backend = PrivateBackend {
            token_id: "test".to_owned(),
            owner: None,
            lifecycle: None,
            abandoned: false,
            pool_closed: Arc::new(AtomicBool::new(false)),
            retirement: None,
        };
        let failure = backend.retire_bounded(Instant::now()).unwrap_err();
        assert_eq!(
            backend.retire_bounded(Instant::now() + Duration::from_secs(10)),
            Err(failure)
        );
    }

    #[test]
    fn pool_timeout_cannot_later_prove_capture_safe() {
        let temporary = TempDir::new().expect("probe root");
        let pool = probe_pool(temporary.path());
        let guard = pool.inner.lock().expect("pool owner");
        assert!(!pool.retire_all(Instant::now()).complete());
        assert!(pool.closed.load(Ordering::Acquire));
        drop(guard);
        assert!(!pool
            .retire_all(Instant::now() + Duration::from_secs(1))
            .complete());
    }

    #[test]
    fn all_backend_failures_stay_sticky_under_one_deadline() {
        let mut backends = ["first", "second", "third"].map(|token| PrivateBackend {
            token_id: token.to_owned(),
            owner: None,
            lifecycle: None,
            abandoned: false,
            pool_closed: Arc::new(AtomicBool::new(false)),
            retirement: None,
        });
        let deadline = Instant::now();
        let failures: Vec<_> = backends
            .iter_mut()
            .map(|backend| backend.retire_bounded(deadline).unwrap_err())
            .collect();
        let later = Instant::now() + Duration::from_secs(10);
        for (backend, failure) in backends.iter_mut().zip(failures) {
            assert_eq!(backend.retire_bounded(later), Err(failure));
        }
    }
}
