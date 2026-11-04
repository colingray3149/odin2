//! The governed local browser's on-demand lifecycle.
//!
//! odind composes the validated browser runtime at startup but launches no
//! Chromium: the first governed browser call or checkout opens a fresh
//! durable session, and the per-session supervisor closes it once the
//! declared idle-close window passes with no in-flight command. A page that
//! died is recreated on the next governed use; when reopening fails, the
//! refusal names why the page closed.

use std::future::Future;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex as StdMutex};

use async_trait::async_trait;
use odin_domain::huginn as live;
use odin_huginn::browser::BrowserProjection;
use odin_huginn::dispatch::AuthenticatedCommandPort;
use odin_omp::host_tools::{
    BrowserCapabilityBinding, BrowserCapabilityOwner, ConsumedHostCommand, HostInvocation,
    HostToolError,
};
use serde_json::Value;

use super::coordinator::BrowserCommandCoordinator;
use super::dispatch::{browser_runtime, extract_action_evidence, extract_observe_evidence};
use super::launch::LocalSessionLaunch;

/// The lazy governed local browser.
///
/// Cheap to clone; every clone serves the same underlying lifecycle. The
/// session id is fixed by the validated policy, so routing stays stable
/// across closes and reopens.
#[derive(Clone)]
pub struct LocalBrowser {
    session_id: live::BrowserSessionId,
    shared: Arc<Shared>,
}

struct Shared {
    launcher: Arc<dyn LocalSessionLaunch>,
    idle_close: std::time::Duration,
    runtime: tokio::runtime::Handle,
    /// Set by [`LocalBrowser::retire`]: the daemon is stopping, so no new
    /// session may open.
    retired: AtomicBool,
    /// Serializes session launches and retirements.
    open_lock: tokio::sync::Mutex<()>,
    state: StdMutex<LocalState>,
    /// Signalled on every in-flight transition (zero and non-zero).
    activity: tokio::sync::Notify,
}

struct LocalState {
    open: Option<OpenSession>,
    in_flight: usize,
    /// Why the currently absent session closed; cleared on a fresh open.
    closed_reason: Option<String>,
}

struct OpenSession {
    coordinator: BrowserCommandCoordinator,
    supervisor: tokio::task::JoinHandle<Vec<String>>,
    retire: Arc<tokio::sync::Notify>,
}

/// One in-flight governed call over the open session. Dropping it lets the
/// idle supervisor see the session go quiet.
struct LeasedCoordinator {
    shared: Arc<Shared>,
    coordinator: BrowserCommandCoordinator,
}

impl Drop for LeasedCoordinator {
    fn drop(&mut self) {
        if let Ok(mut state) = self.shared.state.lock() {
            state.in_flight = state.in_flight.saturating_sub(1);
        }
        self.shared.activity.notify_waiters();
    }
}

fn in_flight(shared: &Shared) -> usize {
    shared
        .state
        .lock()
        .map(|state| state.in_flight)
        .unwrap_or(0)
}

impl LocalBrowser {
    /// Composes the lazy lifecycle over the validated launch seam. No
    /// browser is launched here.
    pub fn new(launcher: Arc<dyn LocalSessionLaunch>, idle_close: std::time::Duration) -> Self {
        Self {
            session_id: launcher.session_id(),
            shared: Arc::new(Shared {
                launcher,
                idle_close,
                runtime: tokio::runtime::Handle::current(),
                retired: AtomicBool::new(false),
                open_lock: tokio::sync::Mutex::new(()),
                state: StdMutex::new(LocalState {
                    open: None,
                    in_flight: 0,
                    closed_reason: None,
                }),
                activity: tokio::sync::Notify::new(),
            }),
        }
    }

    /// The durable identity every launch of this browser reopens.
    pub fn session_id(&self) -> live::BrowserSessionId {
        self.session_id
    }

    /// Whether a session is currently open.
    pub fn is_open(&self) -> bool {
        self.shared
            .state
            .lock()
            .map(|state| state.open.is_some())
            .unwrap_or(false)
    }

    /// Acquires the open session for one in-flight call, or `None` when no
    /// session is open (or the daemon retired the browser).
    fn acquire(&self) -> Option<LeasedCoordinator> {
        let mut state = self
            .shared
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let coordinator = state.open.as_ref().map(|open| open.coordinator.clone())?;
        state.in_flight += 1;
        Some(LeasedCoordinator {
            shared: Arc::clone(&self.shared),
            coordinator,
        })
    }

    /// Acquires the open session, launching a fresh one when none is open.
    async fn lease(&self) -> Result<LeasedCoordinator, String> {
        loop {
            if let Some(lease) = self.acquire() {
                return Ok(lease);
            }
            self.ensure_open().await?;
        }
    }

    /// Opens the session if none is open. Concurrent callers wait on one
    /// launch; a failed reopen names why the previous session closed.
    async fn ensure_open(&self) -> Result<(), String> {
        if self.shared.retired.load(Ordering::Relaxed) {
            return Err("the governed browser retired with the daemon's shutdown".to_owned());
        }
        let _guard = self.shared.open_lock.lock().await;
        if self.is_open() {
            return Ok(());
        }
        let previous_close = self
            .shared
            .state
            .lock()
            .ok()
            .and_then(|state| state.closed_reason.clone());
        let (projection, coordinator) = self.shared.launcher.launch_session().await.map_err(|error| match previous_close {
            Some(reason) => {
                format!("the governed browser closed because {reason}; reopening it failed: {error}")
            }
            None => format!("opening the governed browser failed: {error}"),
        })?;
        let retire = Arc::new(tokio::sync::Notify::new());
        let supervisor = tokio::spawn(supervise_session(
            Arc::clone(&self.shared),
            projection,
            coordinator.clone(),
            Arc::clone(&retire),
        ));
        let mut state = self
            .shared
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.closed_reason = None;
        state.open = Some(OpenSession {
            coordinator,
            supervisor,
            retire,
        });
        Ok(())
    }

    /// Runs one governed call against the open session, launching a fresh
    /// session when none is open. The in-flight lease keeps the idle
    /// supervisor from closing the session mid-call.
    pub async fn with_coordinator<T, F, Fut>(&self, call: F) -> Result<T, String>
    where
        F: FnOnce(BrowserCommandCoordinator) -> Fut,
        Fut: Future<Output = T>,
    {
        let lease = self.lease().await?;
        Ok(call(lease.coordinator.clone()).await)
    }

    /// Synchronous [`Self::with_coordinator`] for the governed host-tool
    /// surface, which blocks on the runtime the same way the coordinator
    /// itself does.
    pub fn with_coordinator_blocking<T, F, Fut>(&self, call: F) -> Result<T, String>
    where
        F: FnOnce(BrowserCommandCoordinator) -> Fut,
        Fut: Future<Output = T>,
    {
        let browser = self.clone();
        self.shared.runtime.block_on(async move {
            let lease = browser.lease().await?;
            Ok(call(lease.coordinator.clone()).await)
        })
    }

    fn with_coordinator_sync<T>(
        &self,
        call: impl FnOnce(BrowserCommandCoordinator) -> T,
    ) -> Result<T, String> {
        // Acquire asynchronously, then leave the runtime before calling
        // the synchronous owner, which drives its own async operation.
        let lease = self.shared.runtime.block_on(self.lease())?;
        Ok(call(lease.coordinator.clone()))
    }

    /// The daemon's shutdown ladder: no new session may open, and the open
    /// one (if any) closes through its supervisor. Returns the graceful
    /// ladder's failures.
    pub async fn retire(&self) -> Vec<String> {
        self.shared.retired.store(true, Ordering::Relaxed);
        let _guard = self.shared.open_lock.lock().await;
        // Taking the slot closes it to new governed calls; the supervisor
        // still owns the projection and finishes the graceful ladder.
        let session = {
            let mut state = self
                .shared
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            match state.open.take() {
                Some(open) => {
                    state.closed_reason = Some("the daemon stopped".to_owned());
                    open
                }
                None => return Vec::new(),
            }
        };
        session.retire.notify_one();
        match session.supervisor.await {
            Ok(failures) => failures,
            Err(error) => vec![format!("the browser supervisor join failed: {error}")],
        }
    }

    /// The typed refusal for a call that finds no open session, naming why
    /// the page closed when that is known.
    fn closed_refusal(&self, tail: &str) -> String {
        let reason = self
            .shared
            .state
            .lock()
            .ok()
            .and_then(|state| state.closed_reason.clone());
        match reason {
            Some(reason) => {
                format!("the governed browser closed because {reason}, so {tail}")
            }
            None => format!("the governed browser is not open, so {tail}"),
        }
    }
}

/// One session's owner: closes it when its projection ends (the page died),
/// when the declared idle-close window passes with no in-flight call, or
/// when the daemon retires it — in every case settling its pending actions
/// and tearing the page and worker down before returning the failures.
async fn supervise_session(
    shared: Arc<Shared>,
    projection: BrowserProjection,
    coordinator: BrowserCommandCoordinator,
    retire: Arc<tokio::sync::Notify>,
) -> Vec<String> {
    let handle = projection.handle();
    let terminal = handle.wait_terminal();
    tokio::pin!(terminal);
    let idle = async {
        loop {
            let activity = shared.activity.notified();
            if in_flight(&shared) != 0 {
                activity.await;
                continue;
            }
            let deadline = tokio::time::Instant::now() + shared.idle_close;
            tokio::select! {
                () = tokio::time::sleep_until(deadline) => {
                    if in_flight(&shared) == 0 {
                        return;
                    }
                }
                () = activity => {}
            }
        }
    };
    let reason = tokio::select! {
        result = &mut terminal => {
            match result {
                Ok(()) => "its projection ended cleanly".to_owned(),
                Err(error) => format!("its projection ended: {error}"),
            }
        }
        () = idle => "it sat idle".to_owned(),
        () = retire.notified() => "the daemon stopped".to_owned(),
    };
    // Remove the session first so new governed calls reopen fresh.
    {
        let mut state = shared
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if state.open.is_some() {
            state.open = None;
            state.closed_reason = Some(reason.clone());
        }
    }
    // Let in-flight calls finish before tearing the page down.
    loop {
        let activity = shared.activity.notified();
        if in_flight(&shared) == 0 {
            break;
        }
        activity.await;
    }
    tracing::info!("governed browser closed because {reason}");
    let mut failures = Vec::new();
    if let Err(error) = coordinator.shutdown_pending().await {
        failures.push(format!("browser pending shutdown failed: {error}"));
    }
    if let Err(error) = projection.shutdown().await {
        failures.push(format!("browser runtime shutdown failed: {error}"));
    }
    failures
}

#[async_trait]
impl live::HuginnCommandPort for LocalBrowser {
    async fn execute(
        &self,
        request: live::HuginnRequest,
    ) -> Result<live::HuginnResponse, live::HuginnProtocolError> {
        // Unauthenticated intake never launches a browser.
        match request {
            live::HuginnRequest::BrowserObserve(_)
            | live::HuginnRequest::BrowserCommand(_)
            | live::HuginnRequest::ApprovalDecision(_) => {
                Err(live::HuginnProtocolError::Unauthenticated)
            }
            _ => Err(live::HuginnProtocolError::Unsupported {
                operation: "non-browser command".to_owned(),
            }),
        }
    }
}

#[async_trait]
impl AuthenticatedCommandPort for LocalBrowser {
    async fn execute_authenticated(
        &self,
        device: live::DeviceId,
        request: live::HuginnRequest,
    ) -> Result<live::HuginnResponse, live::HuginnProtocolError> {
        match request {
            live::HuginnRequest::BrowserObserve(_) | live::HuginnRequest::BrowserCommand(_) => {
                match self
                    .with_coordinator(|coordinator| async move {
                        coordinator.execute_authenticated(device, request).await
                    })
                    .await
                {
                    Ok(result) => result,
                    Err(detail) => Err(live::HuginnProtocolError::unavailable(
                        "browserLaunch",
                        detail,
                    )),
                }
            }
            // A decision never launches a browser: the pending action it
            // decides was settled when the session closed.
            live::HuginnRequest::ApprovalDecision(_) => {
                if let Some(lease) = self.acquire() {
                    lease
                        .coordinator
                        .execute_authenticated(device, request)
                        .await
                } else {
                    Err(live::HuginnProtocolError::InvalidRequest {
                        code: "browserApproval".to_owned(),
                        message: self
                            .closed_refusal("no pending browser action can take this decision"),
                    })
                }
            }
            other => <Self as live::HuginnCommandPort>::execute(self, other).await,
        }
    }
}

impl BrowserCapabilityOwner for LocalBrowser {
    fn invoke_browser_capability(
        &self,
        binding: BrowserCapabilityBinding,
        invocation: HostInvocation,
    ) -> Result<Value, HostToolError> {
        // Evidence extraction is pure argument decoding: it never launches
        // a browser, open or not.
        if binding.is_evidence_extractor() {
            return match self.acquire() {
                Some(lease) => lease
                    .coordinator
                    .invoke_browser_capability(binding, invocation),
                None => extract_evidence_without_session(binding, invocation),
            };
        }
        self.with_coordinator_sync(|coordinator| {
            coordinator.invoke_browser_capability(binding, invocation)
        })
        .map_err(|detail| browser_runtime(binding.id(), detail))?
    }

    fn invoke_consumed(
        &self,
        binding: BrowserCapabilityBinding,
        invocation: HostInvocation,
        consumed: &ConsumedHostCommand,
    ) -> Result<Value, HostToolError> {
        self.with_coordinator_sync(|coordinator| {
            coordinator.invoke_consumed(binding, invocation, consumed)
        })
        .map_err(|detail| browser_runtime(binding.id(), detail))?
    }

    fn preflight_browser_capability(
        &self,
        contract: &odin_kernel::CapabilityContract,
        binding: BrowserCapabilityBinding,
        scope: &odin_domain::Scope,
        arguments: &Value,
    ) -> Result<(), HostToolError> {
        if binding.is_evidence_extractor() {
            return Ok(());
        }
        self.with_coordinator_sync(|coordinator| {
            coordinator.preflight_browser_capability(contract, binding, scope, arguments)
        })
        .map_err(|detail| browser_runtime(binding.id(), detail))?
    }
}

/// Evidence extraction with no open session: the same pure decoders the
/// coordinator serves, so a closed browser still answers evidence bindings.
fn extract_evidence_without_session(
    binding: BrowserCapabilityBinding,
    invocation: HostInvocation,
) -> Result<Value, HostToolError> {
    match binding {
        BrowserCapabilityBinding::ObserveEvidence => {
            extract_observe_evidence(binding.id(), invocation.arguments)
        }
        BrowserCapabilityBinding::InteractEvidence
        | BrowserCapabilityBinding::ConsequentialEvidence => {
            extract_action_evidence(binding.id(), invocation.arguments)
        }
        _ => unreachable!("non-evidence bindings never reach the closed-session extractor"),
    }
}
