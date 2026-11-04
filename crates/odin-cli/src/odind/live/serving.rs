//! Stop admission and drain runtime tasks within the serving grace; the browser ladder
//! and the authority retirement after it run on their own, longer budget.

use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::composition::produce_extension_policy;
use crate::controller;
use crate::kernel_mcp::KernelDispatches;
use odin_cli::runtime_bindings::RuntimeInputs;
use odin_huginn::browser::BrowserProjectionError;
use odin_huginn::ConnectionRegistry;
use odin_huginn::{HuginnConfig, NodePosture, OdindConfig};
use odin_registry::{SnapshotHandle, SnapshotStore};
use tokio::sync::watch;

use super::super::device_open::{DeviceOpenStop, DeviceOpenStopIncomplete};
use super::browser_capsule;

pub(super) struct HuginnServe {
    pub(super) config: OdindConfig,
    pub(super) validated: odin_huginn::ValidatedHuginnConfig,
    pub(super) snapshot: Arc<odin_registry::Snapshot>,
    pub(super) snapshot_handle: Arc<SnapshotHandle>,
    pub(super) runtime: RuntimeInputs,
    pub(super) extension_policy: odin_domain::extension_policy::ExtensionPolicyBinding,
    pub(super) posture: NodePosture,
    pub(super) shutdown_started: Arc<Mutex<Option<Instant>>>,
    /// When odind began serving; the `odind ready` line measures from here.
    pub(super) launched: Instant,
}

/// Creates the private cursor parent before the first durable feed discovery.
pub(crate) fn ensure_feeds_dir(huginn_root: &std::path::Path) -> Result<(), String> {
    odin_cli::eval_daemon::create_private_dir(&huginn_root.join("feeds"))
        .map_err(|error| format!("could not provision the feeds directory: {error}"))
}

/// One cooperative deadline for serving, session actors and device rollback.
pub(super) const SHUTDOWN_GRACE: Duration = Duration::from_secs(8);

/// Tokio worker threads of the daemon's runtimes.
const RUNTIME_WORKER_THREADS: usize = 8;

/// Browser teardown starts at the same signal but outlasts the serving grace: before any
/// teardown the ladder waits for in-flight browser commands (up to COMMAND_TTL, 5 min —
/// their durable outcomes cannot be cancelled the way pending approvals can). The worker
/// scope itself stops in ~20 ms; the unit's default stop timeout (90 s) bounds the daemon
/// above this budget.
pub(super) const BROWSER_STOP_GRACE: Duration = Duration::from_secs(30);

// Failed stops remain in the worker ledger for the next daemon start.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum ShutdownOutcome {
    Drained { tracked: usize },
    Stragglers { tracked: usize, stragglers: usize },
}

// Cleanup failures do not turn a successful daemon exit into a failed restart.
pub(super) struct ShutdownAccounting {
    pub(super) outcome: ShutdownOutcome,
    pub(super) started: Instant,
    /// The later of the serving grace and the browser budget: finalization runs under it.
    pub(super) deadline: Instant,
    pub(super) capsule_failures: Vec<String>,
    pub(super) device_stop: Result<(), DeviceOpenStopIncomplete>,
}

/// Drains the runtime within what remains of the serving grace that began at
/// the stop, then returns the serve result.
pub(super) fn finish_runtime(
    runtime: tokio::runtime::Runtime,
    served: Result<(), String>,
    started: Option<Instant>,
) -> Result<(), String> {
    let started = started.unwrap_or_else(Instant::now);
    runtime.shutdown_timeout(SHUTDOWN_GRACE.saturating_sub(started.elapsed()));
    served
}

pub(crate) fn serve_huginn(config: OdindConfig) -> Result<(), String> {
    let launched = Instant::now();
    if config.executables.omp_revision != odin_omp::probe::PINNED_OMP_SOURCE_REVISION {
        return Err(format!(
            "OMP revision must be the pinned {}",
            odin_omp::probe::PINNED_OMP_SOURCE_REVISION
        ));
    }
    let huginn = HuginnConfig {
        bind: config.listener_address(),
        limits: config.capacity.clone(),
        state_root: config.paths.state_root.join("huginn"),
    };
    let validated = huginn.validate().map_err(|error| error.to_string())?;
    // Pin one published snapshot for every runtime policy in this process.
    let handle = SnapshotHandle::open(SnapshotStore::new(&config.paths.registry_snapshot))
        .map_err(|error| {
            format!(
                "published registry snapshot {} is not a verified publication: {error}",
                config.paths.registry_snapshot.display()
            )
        })?;
    let handle = Arc::new(handle);
    let snapshot = handle.current();
    let runtime = RuntimeInputs::parse(&config, &snapshot.objects)?;
    let report = controller::check_snapshot(
        &config.paths.state_root,
        Arc::clone(&snapshot),
        &config.identity.node,
    )
    .map_err(|error| error.to_string())?;
    let posture = if report.authoritative {
        NodePosture::Authoritative
    } else {
        tracing::error!(
            "node {:?} is not the snapshot authority ({:?} is); serving READ-ONLY \
             follower: health/status/read-model only, every mutating request is refused",
            report.node,
            report.authoritative_node
        );
        NodePosture::Follower
    };
    let policy = produce_extension_policy(&config, &snapshot)?;
    let tokio = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(RUNTIME_WORKER_THREADS)
        .enable_all()
        .build()
        .map_err(|error| format!("could not start Huginn runtime: {error}"))?;
    let shutdown_started = Arc::new(Mutex::new(None));
    let served = tokio.block_on(super::serve_huginn_async(HuginnServe {
        config,
        validated,
        snapshot,
        snapshot_handle: Arc::clone(&handle),
        runtime,
        extension_policy: policy,
        posture,
        shutdown_started: Arc::clone(&shutdown_started),
        launched,
    }));
    let started = *shutdown_started
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    finish_runtime(tokio, served, started)
}

#[cfg(test)]
mod publication_tests {}

/// SIGTERM/SIGINT/SIGHUP only resolve the returned future, so a stop leaves the serving select and the owning
/// shutdown (browser capsule, capsules, pumps) always runs; the default disposition would kill the process with no
/// shutdown and leave the browser worker scope and its Xvfb child behind.
pub(super) fn arm_stop_signal() -> Result<impl Future<Output = ()>, String> {
    let arm_failed =
        |error: std::io::Error| format!("could not arm the graceful stop signal: {error}");
    let (signalled, signal_writer) = std::os::unix::net::UnixStream::pair().map_err(arm_failed)?;
    for signal in [
        signal_hook::consts::SIGHUP,
        signal_hook::consts::SIGTERM,
        signal_hook::consts::SIGINT,
    ] {
        signal_hook::low_level::pipe::register(
            signal,
            signal_writer.try_clone().map_err(arm_failed)?,
        )
        .map_err(arm_failed)?;
    }
    signalled.set_nonblocking(true).map_err(arm_failed)?;
    let signalled = tokio::net::UnixStream::from_std(signalled).map_err(arm_failed)?;
    Ok(async move {
        let _ = signalled.readable().await;
    })
}

pub(super) struct ServingShutdown {
    stop: watch::Sender<bool>,
    connections: Option<ConnectionRegistry>,
    mcp_listeners: Vec<tokio::task::JoinHandle<()>>,
    dispatches: KernelDispatches,
    /// The live plane's session supervisor: the stop drains every session
    /// actor through its bridge's own bounded ladder before any other
    /// join, so no session runtime, bridge pump, heartbeat, or
    /// observation feed outlives the seam.
    session_supervisor: Option<Arc<odin_omp::live::supervisor::LiveSupervisor>>,
    harness_turns: Option<Arc<odin_omp::live::harness::HarnessTurns>>,
    device_opens: Option<DeviceOpenStop>,
    authority_pool: Option<Arc<crate::live_authority::SessionAuthorityPool>>,
    background_root: Option<Arc<odin_hermes::conversation::ConversationRoot>>,
    notifications: Option<Arc<odin_hermes::runtime::HermesRuntime>>,
    terminals: Option<odin_omp::live::zellij::ZellijCliFactory>,
    /// Serving and browser budgets of `finish`, each counted from the stop signal.
    serving_grace: Duration,
    browser_grace: Duration,
}

impl ServingShutdown {
    pub(super) fn own(
        stop: watch::Sender<bool>,
        connections: ConnectionRegistry,
        mcp_listeners: Vec<tokio::task::JoinHandle<()>>,
        dispatches: KernelDispatches,
        device_opens: DeviceOpenStop,
    ) -> Self {
        Self {
            stop,
            connections: Some(connections),
            mcp_listeners,
            dispatches,
            session_supervisor: None,
            harness_turns: None,
            device_opens: Some(device_opens),
            authority_pool: None,
            background_root: None,
            notifications: None,
            terminals: None,
            serving_grace: SHUTDOWN_GRACE,
            browser_grace: BROWSER_STOP_GRACE,
        }
    }

    pub(super) fn with_session_supervisor(
        mut self,
        supervisor: Arc<odin_omp::live::supervisor::LiveSupervisor>,
    ) -> Self {
        self.session_supervisor = Some(supervisor);
        self
    }

    pub(super) fn with_harness_turns(
        mut self,
        turns: Option<Arc<odin_omp::live::harness::HarnessTurns>>,
    ) -> Self {
        self.harness_turns = turns;
        self
    }

    pub(super) fn with_authority_pool(
        mut self,
        authority_pool: Arc<crate::live_authority::SessionAuthorityPool>,
    ) -> Self {
        self.authority_pool = Some(authority_pool);
        self
    }

    pub(super) fn with_background_root(
        mut self,
        root: Option<Arc<odin_hermes::conversation::ConversationRoot>>,
    ) -> Self {
        self.background_root = root;
        self
    }

    pub(super) fn with_notifications(
        mut self,
        runtime: Option<Arc<odin_hermes::runtime::HermesRuntime>>,
    ) -> Self {
        self.notifications = runtime;
        self
    }

    pub(super) fn with_terminals(
        mut self,
        terminals: odin_omp::live::zellij::ZellijCliFactory,
    ) -> Self {
        self.terminals = Some(terminals);
        self
    }

    /// A test instance owning nothing: a fresh token, no registry, no listeners, no in-flight
    /// calls, no sessions.
    #[cfg(test)]
    pub(super) fn detached() -> Self {
        Self {
            stop: watch::channel(false).0,
            connections: None,
            mcp_listeners: Vec::new(),
            dispatches: KernelDispatches::new(),
            session_supervisor: None,
            harness_turns: None,
            device_opens: None,
            authority_pool: None,
            background_root: None,
            notifications: None,
            terminals: None,
            serving_grace: SHUTDOWN_GRACE,
            browser_grace: BROWSER_STOP_GRACE,
        }
    }

    /// Shortens the budgets so a test reaches the deadline without waiting out the production ones.
    #[cfg(test)]
    pub(super) fn with_graces(mut self, serving: Duration, browser: Duration) -> Self {
        self.serving_grace = serving;
        self.browser_grace = browser;
        self
    }

    /// Closes every admission synchronously before spawning browser retirement or awaiting any
    /// drain. The pinned serve future remains alive until all these notifications are issued.
    fn signal(&self, supervision: &mut Option<browser_capsule::BrowserCapsuleSupervision>) {
        if let Some(device_opens) = &self.device_opens {
            device_opens.close();
        }
        if let Some(turns) = &self.harness_turns {
            turns.stop();
        }
        if let Some(authority_pool) = &self.authority_pool {
            authority_pool.close();
        }
        if let Some(root) = &self.background_root {
            root.close_background();
        }
        if let Some(runtime) = &self.notifications {
            runtime.close_notifications();
        }
        // Queued terminal work refuses from here; started opens roll back now, while the grace
        // is still whole, not when the runtime later drops their callers.
        if let Some(terminals) = &self.terminals {
            terminals.close();
        }
        if let Some(connections) = &self.connections {
            connections.stop_all();
        }
        // Disconnected clients can leave dispatches running after their listeners stop.
        self.dispatches.close();
        self.stop.send_replace(true);
        if let Some(supervision) = supervision.as_mut() {
            supervision.retire();
        }
    }

    // Start all shutdowns together so slow tasks cannot consume another task's grace.
    pub(super) async fn finish(
        self,
        pumps: tokio::task::JoinSet<Result<(), String>>,
        supervision: &mut Option<browser_capsule::BrowserCapsuleSupervision>,
    ) -> ShutdownAccounting {
        let started = Instant::now();
        let now = tokio::time::Instant::now();
        let deadline = now + self.serving_grace;
        // The browser ladder gets a longer budget from the same start; finish_until's other
        // callers keep owning their own deadline, including an already-expired one.
        let browser_deadline = now + self.browser_grace;
        self.finish_until(pumps, supervision, started, deadline, browser_deadline)
            .await
    }

    async fn finish_until(
        mut self,
        mut pumps: tokio::task::JoinSet<Result<(), String>>,
        supervision: &mut Option<browser_capsule::BrowserCapsuleSupervision>,
        started: Instant,
        deadline: tokio::time::Instant,
        browser_deadline: tokio::time::Instant,
    ) -> ShutdownAccounting {
        self.signal(supervision);
        // Egress cancellation never waits behind the connection drain.
        pumps.abort_all();

        // The browser ladder's join runs on its own budget; finalization carries the later
        // deadline, so a slow ladder still retires its authority instead of abandoning it
        // for the next daemon start.
        let browser_deadline = browser_deadline.max(deadline);

        let mut tracked = 0;
        let mut stragglers = 0;

        // Stop session actors first to unblock callers waiting for their answers.
        if let Some(supervisor) = &self.session_supervisor {
            match tokio::time::timeout_at(deadline, supervisor.shutdown()).await {
                Ok(Ok(stopped)) => tracked += stopped,
                Ok(Err(error)) => {
                    stragglers += 1;
                    tracing::error!(worker = "live-sessions", cause = %error, "shutdown failed");
                }
                Err(_elapsed) => {
                    stragglers += 1;
                    tracing::error!(
                        worker = "live-sessions",
                        cause = "shutdown deadline expired",
                        "shutdown failed"
                    );
                }
            }
        }

        if let Some(runtime) = &self.notifications {
            match runtime.drain_notifications_until(deadline).await {
                Ok(()) => tracked += 1,
                Err(error) => {
                    stragglers += 1;
                    tracing::error!(worker = "notifications", cause = %error, "shutdown failed");
                }
            }
        }

        if let Some(turns) = &self.harness_turns {
            let (drained, missed) = turns.join(deadline).await;
            tracked += drained;
            stragglers += missed;
            if missed != 0 {
                tracing::error!(
                    worker = "harness-turns",
                    remaining = missed,
                    cause = "shutdown deadline expired",
                    "shutdown failed"
                );
            }
        }

        if let Some(connections) = &self.connections {
            let served = connections.served_connections();
            if tokio::time::timeout_at(deadline, connections.drained())
                .await
                .is_ok()
            {
                tracked += served;
            } else {
                let left = connections.served_connections();
                tracked += served.saturating_sub(left);
                stragglers += left;
                tracing::error!(
                    worker = "connections",
                    remaining = left,
                    cause = "shutdown deadline expired",
                    "shutdown failed"
                );
            }
        }

        while let Ok(Some(result)) = tokio::time::timeout_at(deadline, pumps.join_next()).await {
            tracked += 1;
            match result {
                Ok(Err(error)) => {
                    tracing::error!(worker = "pump", cause = %error, "shutdown failed");
                }
                Err(error) if !error.is_cancelled() => {
                    tracing::error!(worker = %error.id(), cause = %error, "shutdown failed");
                }
                Ok(Ok(())) | Err(_) => {}
            }
        }
        let pending_pumps = pumps.len();
        stragglers += pending_pumps;
        if pending_pumps != 0 {
            tracing::error!(
                worker = "pumps",
                remaining = pending_pumps,
                cause = "shutdown deadline expired",
                "shutdown failed"
            );
        }

        for mut listener in self.mcp_listeners.drain(..) {
            match tokio::time::timeout_at(deadline, &mut listener).await {
                Ok(result) => {
                    tracked += 1;
                    if let Err(error) = result {
                        tracing::error!(worker = %error.id(), cause = %error, "shutdown failed");
                    }
                }
                Err(error) => {
                    listener.abort();
                    stragglers += 1;
                    tracing::error!(worker = %listener.id(), cause = %error, "shutdown failed");
                }
            }
        }

        // A stopped listener can still have active dispatches.
        let in_flight = self.dispatches.active();
        if tokio::time::timeout_at(deadline, self.dispatches.drained())
            .await
            .is_ok()
        {
            tracked += in_flight;
        } else {
            let active = self.dispatches.active();
            stragglers += active;
            tracing::error!(
                worker = "kernel-dispatches",
                remaining = active,
                cause = "shutdown deadline expired",
                "shutdown failed"
            );
        }

        // Terminal opens hold the action lock until their cleanup finishes.
        if let Some(terminals) = &self.terminals {
            if terminals.quiesce_until(deadline).await {
                tracked += 1;
            } else {
                stragglers += 1;
                tracing::error!(
                    worker = "terminal-drain",
                    cause = "shutdown deadline expired",
                    "shutdown failed"
                );
            }
        }

        // Device rollback is cooperative, never aborted to manufacture a successful drain.
        // The browser was already signalled, so this join cannot prevent its retirement.
        let device_stop = match &self.device_opens {
            Some(device_opens) => {
                let result = device_opens.stop_until(deadline).await;
                if result.is_ok() {
                    tracked += 1;
                } else {
                    stragglers += 1;
                }
                result
            }
            None => Ok(()),
        };

        // Browser shutdown started at the signal; the ladder joins on its own budget.
        let capsule_failures = match supervision.as_mut() {
            Some(supervision) => {
                match tokio::time::timeout_at(browser_deadline, supervision.retire_and_join()).await
                {
                    Ok(failures) => {
                        tracked += 1;
                        failures
                    }
                    Err(_) => {
                        stragglers += 1;
                        tracing::error!(
                            worker = "browser",
                            cause = "browser stop budget expired",
                            "shutdown failed"
                        );
                        Vec::new()
                    }
                }
            }
            None => Vec::new(),
        };

        let outcome = if stragglers == 0 {
            ShutdownOutcome::Drained { tracked }
        } else {
            ShutdownOutcome::Stragglers {
                tracked,
                stragglers,
            }
        };
        ShutdownAccounting {
            outcome,
            started,
            deadline: browser_deadline.into_std(),
            capsule_failures,
            device_stop,
        }
    }
}

// Signal shutdown even when serving setup fails.
pub(super) async fn orchestrate_serving<S, T, R, F>(
    setup: Result<S, String>,
    pumps: tokio::task::JoinSet<Result<(), String>>,
    signal_stop: impl Future<Output = ()>,
    browser_capsule: Option<(T, R)>,
    shutdown: ServingShutdown,
) -> (Result<(), String>, ShutdownAccounting)
where
    S: Future<Output = std::io::Result<()>>,
    T: Future<Output = Result<(), BrowserProjectionError>> + Send + 'static,
    R: FnOnce() -> F + Send + 'static,
    F: Future<Output = Vec<String>> + Send + 'static,
{
    let mut supervision = browser_capsule.map(|(terminal, retire)| {
        browser_capsule::BrowserCapsuleSupervision::spawn(terminal, retire)
    });
    let (result, accounting) = match setup {
        Ok(serve) => {
            // Keep the actual serve future pinned through signalling AND draining; pinning only
            // inside the select's scope would drop it before its admission was closed.
            tokio::pin!(serve);
            let (result, pumps) = serve_huginn_arms(serve.as_mut(), pumps, signal_stop).await;
            let accounting = shutdown.finish(pumps, &mut supervision).await;
            (result, accounting)
        }
        Err(error) => {
            let accounting = shutdown.finish(pumps, &mut supervision).await;
            (Err(error), accounting)
        }
    };
    (result, accounting)
}

/// The owning serving select: the serve future (pinned by the caller, so the loser-drop never reaches it),
/// the pump set, and the stop signal — the three arms the daemon may end on. The browser capsule's terminal
/// stays off-loop in `BrowserCapsuleSupervision`.
async fn serve_huginn_arms<S: Future<Output = std::io::Result<()>>>(
    mut serve: Pin<&mut S>,
    mut pumps: tokio::task::JoinSet<Result<(), String>>,
    signal_stop: impl Future<Output = ()>,
) -> (Result<(), String>, tokio::task::JoinSet<Result<(), String>>) {
    tokio::pin!(signal_stop);
    let result = tokio::select! {
        result = serve.as_mut() => result.map_err(|error| format!("Huginn service failed: {error}")),
        Some(pump) = pumps.join_next(), if !pumps.is_empty() => match pump {
            Ok(Ok(())) => {
                tracing::error!("a serving pump returned Ok; the daemon is shutting down");
                Err("a serving pump ended; odind stops so systemd restarts it".to_owned())
            }
            Ok(Err(error)) => Err(error),
            Err(error) => Err(format!("a serving pump failed: {error}")),
        },
        () = &mut signal_stop => {
            tracing::info!(
                "stop signal received; running the owning shutdown \
                 (browser capsule, capsules, pumps)"
            );
            Ok(())
        }
    };
    (result, pumps)
}

#[cfg(test)]
mod serving_shutdown_tests {
    use std::future::{pending, Future};
    use std::pin::Pin;
    use std::sync::atomic::Ordering;
    use std::sync::mpsc as std_mpsc;
    use std::sync::Arc;
    use std::time::Duration;

    use crate::kernel_mcp::KernelDispatches;
    use odin_domain::huginn::{ConnectionId, DeviceId, TailnetNodeId, VerifiedOwnerDevice};
    use odin_huginn::auth::AuthError;
    use odin_huginn::browser::BrowserProjectionError;
    use odin_huginn::devices::{DeviceTrustStore as _, NewDeviceRecord, SqliteDeviceTrustStore};
    use tokio::sync::{oneshot, watch};

    use super::{orchestrate_serving, ServingShutdown, ShutdownOutcome};

    type NoCapsule = (
        Pin<Box<dyn Future<Output = Result<(), BrowserProjectionError>> + Send>>,
        fn() -> Pin<Box<dyn Future<Output = Vec<String>> + Send>>,
    );

    fn shutdown_without_devices(
        stop: watch::Sender<bool>,
        connections: odin_huginn::ConnectionRegistry,
        mcp_listeners: Vec<tokio::task::JoinHandle<()>>,
        dispatches: KernelDispatches,
    ) -> ServingShutdown {
        ServingShutdown {
            stop,
            connections: Some(connections),
            mcp_listeners,
            dispatches,
            ..ServingShutdown::detached()
        }
    }

    struct HarnessRunOnly;

    #[async_trait::async_trait]
    impl odin_omp::live::supervisor::LiveSessionLauncher for HarnessRunOnly {
        fn harness_turns(&self) -> Option<Arc<odin_omp::live::harness::HarnessTurns>> {
            None
        }

        async fn open(
            &self,
            _: &odin_domain::huginn::SessionManifest,
            _: odin_domain::huginn::SessionEpoch,
            _: bool,
        ) -> Result<odin_omp::live::supervisor::SessionRuntime, odin_domain::huginn::LiveError>
        {
            panic!("this fixture runs only the real generic launcher")
        }

        async fn ensure_session_run(
            &self,
            _: &odin_domain::huginn::SessionManifest,
        ) -> Result<(), odin_domain::huginn::LiveError> {
            Ok(())
        }
    }

    struct PrivateHarnessWorkspace {
        root: std::path::PathBuf,
        hand_backs: std::sync::atomic::AtomicUsize,
    }

    #[async_trait::async_trait]
    impl odin_omp::live::harness::HarnessWorkspace for PrivateHarnessWorkspace {
        async fn prepare(
            &self,
            _: &odin_domain::huginn::SessionManifest,
            _: &odin_omp::live::harness::HarnessRoute,
        ) -> Result<std::path::PathBuf, odin_domain::huginn::LiveError> {
            Ok(self.root.clone())
        }

        async fn hand_back(
            &self,
            _: &odin_domain::huginn::SessionManifest,
            _: &odin_omp::live::harness::HarnessRoute,
            _: &std::path::Path,
        ) -> Result<Option<String>, odin_domain::huginn::LiveError> {
            self.hand_backs.fetch_add(1, Ordering::SeqCst);
            Ok(None)
        }
    }

    #[tokio::test]
    async fn an_unproved_generic_ssh_turn_allows_exit_without_claiming_remote_stop() {
        use odin_domain::huginn::{
            HarnessBinding, LiveContentBlock, LiveError, LiveMessage, LiveSessionId, ModelName,
            ProviderName, SessionEpoch, SessionManifest,
        };
        use odin_omp::live::harness::{HarnessLauncher, HarnessRoute};
        use odin_omp::live::supervisor::LiveSessionLauncher;
        use tokio::io::AsyncReadExt;

        let fixture = crate::live::hermes_routes::tests::gate_fixture().await;
        // A real SSH client reaches only this private listener. No SSH
        // handshake, account, remote command, or owner host is involved.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut environment: odin_registry::EnvironmentToml = toml::from_str(include_str!(
            "../../../../../registry/environments/fleet-authority/environment.toml"
        ))
        .unwrap();
        environment.transport = odin_registry::EnvironmentTransport::SshHost;
        environment.host = Some(format!("ssh://{}", listener.local_addr().unwrap()));
        let seat = odin_domain::SeatId::new("private-harness").unwrap();
        environment.seats = vec![seat.clone()];
        let route = HarnessRoute {
            harness_id: "private-process".to_owned(),
            environment_id: "private-loopback".to_owned(),
            account: None,
            environment,
            harness: toml::from_str(
                r#"
schema = "odin.registry.v1"
kind = "harness"
enabled = true
description = "Private SSH shutdown boundary."
protocol = "process"
governance = "observed"
command = ["never-executed-private-agent"]
prompt = "argv"
output = "claude-stream-json"
[stop]
signal = "SIGTERM"
grace_seconds = 1
"#,
            )
            .unwrap(),
        };
        let manifest = SessionManifest {
            session_id: LiveSessionId::new(uuid::Uuid::new_v4()).unwrap(),
            seat_id: seat,
            slice_id: odin_domain::SliceId::new("private-harness").unwrap(),
            project_id: odin_domain::ProjectId::new("private-harness").unwrap(),
            provider: ProviderName::new("private-process").unwrap(),
            model: ModelName::new("private-model").unwrap(),
            title: None,
            target_node: odin_domain::NodeId::new("private-node").unwrap(),
            open_tab: false,
            workload: None,
            served_revision: None,
            harness: Some(HarnessBinding {
                harness: route.harness_id.clone(),
                environment: route.environment_id.clone(),
                account: None,
            }),
        };
        let workspace = Arc::new(PrivateHarnessWorkspace {
            root: fixture._root.path().to_path_buf(),
            hand_backs: std::sync::atomic::AtomicUsize::new(0),
        });
        let launcher = HarnessLauncher::new(
            Arc::new(HarnessRunOnly),
            vec![route],
            workspace.clone(),
            None,
        );
        let turns = launcher.harness_turns().unwrap();
        let runtime = launcher
            .open(&manifest, SessionEpoch::new(1), false)
            .await
            .unwrap();
        let message =
            LiveMessage::new(vec![LiveContentBlock::Text("private stop probe".into())]).unwrap();
        runtime.control.prompt(&message, None).await.unwrap();
        let (mut peer, _) = tokio::time::timeout(Duration::from_secs(5), listener.accept())
            .await
            .unwrap()
            .unwrap();
        let accounting = ServingShutdown::detached()
            .with_harness_turns(Some(turns))
            .finish_until(
                tokio::task::JoinSet::new(),
                &mut None,
                std::time::Instant::now(),
                tokio::time::Instant::now() + Duration::from_secs(5),
                tokio::time::Instant::now() + Duration::from_secs(5),
            )
            .await;
        assert!(matches!(
            accounting.outcome,
            ShutdownOutcome::Stragglers { stragglers: 1, .. }
        ));
        assert!(
            super::super::shutdown::finalize(Ok(()), accounting, None, &fixture.session_pool,)
                .await
                .is_ok()
        );
        // Local EOF proves client cleanup only; it never upgrades remote
        // teardown, permits hand-back, or reopens prompt admission.
        tokio::time::timeout(Duration::from_secs(5), peer.read_to_end(&mut Vec::new()))
            .await
            .unwrap()
            .unwrap();
        assert!(matches!(runtime.control.shutdown().await,
            Err(LiveError::Unavailable { code, .. }) if code == "harness_stop_unproven"));
        assert!(runtime.control.prompt(&message, None).await.is_err());
        assert!(launcher
            .open(&manifest, SessionEpoch::new(1), false)
            .await
            .is_err());
        assert_eq!(workspace.hand_backs.load(Ordering::SeqCst), 0);
    }

    /// Exact libtest entry the registered-worker fixture re-execs as the real bootstrap for the
    /// scripted terminal boundary below.
    #[test]
    fn worker_bootstrap_fixture_entry() {
        odin_process::test_support::run_bootstrap_if_active();
    }

    /// Z1: a terminal open still running at the shutdown deadline is a counted straggler, so
    /// finalization never retires authority beneath it. The open is held inside its first
    /// `list-sessions` by a private scripted zellij run as a real registered worker; once
    /// released, the still-owned workflow ends and a later drain proves it.
    #[tokio::test]
    async fn a_terminal_workflow_running_at_the_deadline_is_a_counted_straggler() {
        use odin_omp::live::zellij::ZellijCliFactory;
        use std::os::unix::fs::PermissionsExt;
        let temporary = tempfile::tempdir().expect("terminal root");
        let root = temporary.path().canonicalize().expect("terminal root");
        let (entered, gate) = (root.join("entered"), root.join("gate"));
        std::fs::write(&gate, "").expect("gate");
        let executable = root.join("zellij");
        std::fs::write(
            &executable,
            format!(
                "#!/bin/sh\ncase \"$1\" in\n\
                 list-sessions) : > '{}'; while [ -e '{}' ]; do sleep 0.01; done ;;\n\
                 *) echo '[]' ;;\nesac\n",
                entered.display(),
                gate.display()
            ),
        )
        .expect("scripted zellij");
        std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o755))
            .expect("chmod");
        let fixture = odin_process::test_support::RegisteredWorkerFixture::new().expect("fixture");
        let unshare = std::env::split_paths(&std::env::var_os("PATH").unwrap_or_default())
            .map(|directory| directory.join("unshare"))
            .find(|candidate| candidate.is_absolute() && candidate.is_file())
            .expect("absolute unshare");
        let channel = fixture
            .channel_for_harness(
                &std::env::current_exe().expect("harness"),
                "live::serving::serving_shutdown_tests::worker_bootstrap_fixture_entry",
                &unshare,
            )
            .expect("channel");
        let digest = blake3::hash(&std::fs::read(&executable).expect("script"))
            .to_hex()
            .to_string();
        let binding = odin_process::RegisteredServiceBinding::new(executable.clone(), digest)
            .expect("binding");
        let ledger = odin_ledger::Ledger::open_in_memory().expect("ledger");
        let store = Arc::new(std::sync::Mutex::new(ledger));
        let launch = odin_omp::process::OmpWorkerLaunch::new(
            Arc::new(odin_kernel::StopAuthority::new(store, channel)),
            odin_types::CorrelationId::new("0123456789abcdef0123456789abcdef").expect("id"),
            "odin-cli",
            "terminal-shutdown",
            1,
            binding,
            odin_process::ScopeLimits::default(),
        )
        .expect("launch");
        let columns = std::num::NonZeroU16::new(80).expect("columns");
        let rows = std::num::NonZeroU16::new(24).expect("rows");
        let timeout = Duration::from_secs(15);
        let state = root.join("state");
        let terminals = ZellijCliFactory::open(
            &executable,
            "hub.test",
            state,
            timeout,
            columns,
            rows,
            launch,
        )
        .expect("factory")
        .with_attach_command(["attach".to_owned()])
        .expect("attach");
        let opening = {
            use odin_domain::huginn::{LiveSessionId, SessionEpoch, TerminalSeq};
            let (terminals, root) = (terminals.clone(), root.clone());
            tokio::spawn(async move {
                let session = LiveSessionId::new(uuid::Uuid::new_v4()).expect("session");
                let (epoch, head) = (SessionEpoch::new(1), TerminalSeq::new(0));
                let opened = terminals.open_terminal(session, epoch, head, &root, "held");
                opened.await.map(|_| ())
            })
        };
        tokio::time::timeout(Duration::from_secs(30), async {
            while !entered.exists() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("the open is held in its list-sessions");

        let spent = tokio::time::Instant::now() - Duration::from_millis(1);
        let started = std::time::Instant::now();
        let accounting = ServingShutdown::detached()
            .with_terminals(terminals.clone())
            .finish_until(
                tokio::task::JoinSet::new(),
                &mut None,
                started,
                spent,
                spent,
            )
            .await;
        assert_eq!(
            accounting.outcome,
            ShutdownOutcome::Stragglers {
                tracked: 0,
                stragglers: 1
            }
        );
        let config = crate::authority_fixture::fixture();
        let manifest =
            crate::test_fixture::manifest_identity_fixture("git", std::path::Path::new("git"));
        let pool =
            crate::live_authority::SessionAuthorityPool::open_denied(&config.config, &manifest)
                .expect("pool");
        let finalized = super::super::shutdown::finalize(Ok(()), accounting, None, &pool).await;
        finalized.expect("terminal residue does not fail the daemon exit");

        std::fs::remove_file(&gate).expect("release list-sessions");
        let drain = tokio::time::Instant::now() + Duration::from_secs(30);
        assert!(
            terminals.quiesce_until(drain).await,
            "the owned workflow ended"
        );
        assert!(
            opening.await.expect("open task").is_err(),
            "the closed open rolled back"
        );
        drop(fixture);
    }

    fn connection() -> VerifiedOwnerDevice {
        VerifiedOwnerDevice {
            device_id: DeviceId::new(uuid::Uuid::new_v4()).unwrap(),
            tailnet_node_id: TailnetNodeId::parse("node.laptop").unwrap(),
            connection_id: ConnectionId::new(uuid::Uuid::new_v4()).unwrap(),
        }
    }

    async fn register_connection(
        registry: &odin_huginn::ConnectionRegistry,
        device: &VerifiedOwnerDevice,
    ) -> Result<odin_huginn::dispatch::ConnectionRegistration, AuthError> {
        let store = SqliteDeviceTrustStore::open_in_memory().expect("device store");
        store
            .insert(NewDeviceRecord {
                device_id: device.device_id,
                tailnet_node_id: device.tailnet_node_id.clone(),
                label: "shutdown test".to_owned(),
                credential_digest: odin_domain::Digest::hash(b"shutdown test"),
                created_at: time::OffsetDateTime::UNIX_EPOCH,
            })
            .await
            .expect("enrolled device");
        store
            .register_connection(device, registry, usize::MAX)
            .await
    }

    #[tokio::test]
    async fn deadline_bounds_unresponsive_work_instead_of_hanging_the_stop() {
        // Tokio cannot auto-advance a paused clock while blocking work runs; use real deadlines.
        const GRACE: Duration = Duration::from_millis(300);
        const HANDSHAKE_BOUND: Duration = Duration::from_secs(5);
        // Keep the pump active past shutdown's deadline without stranding the blocking thread.
        const HOLD_BOUND: Duration = Duration::from_secs(24);

        let registry = odin_huginn::ConnectionRegistry::new();
        let registration = register_connection(&registry, &connection())
            .await
            .expect("admitted");
        // Retain the unresponsive writer so the test can abort and join it afterward.
        let served = tokio::spawn(async move {
            let _registration = registration;
            pending::<()>().await;
        });

        // Abort cannot cancel a blocking pump; only the deadline keeps the stop moving. The pump
        // announces its startup on a channel and then holds until released, so it is provably
        // mid-flight when the deadline passes — no wall-clock sleep for the virtual clock to race.
        let (started_tx, started_rx) = std_mpsc::channel::<()>();
        let (release_tx, release_rx) = std_mpsc::channel::<()>();
        let (witness_tx, witness_rx) = std_mpsc::channel::<()>();
        let mut pumps = tokio::task::JoinSet::new();
        pumps.spawn_blocking(move || {
            started_tx
                .send(())
                .expect("the test still waits for the blocking pump to start");
            release_rx
                .recv_timeout(HOLD_BOUND)
                .expect("the test releases the blocking pump after the outcome");
            witness_tx
                .send(())
                .expect("the test joins the blocking pump's completion witness");
            Ok::<(), String>(())
        });
        // The blocking work has started before the shutdown: the hold is provably
        // mid-flight before the stop seam runs.
        started_rx
            .recv_timeout(HANDSHAKE_BOUND)
            .expect("the blocking pump started before the stop");

        let (stop_tx, _stop_rx) = watch::channel(false);
        let shutdown = shutdown_without_devices(
            stop_tx,
            registry.clone(),
            Vec::new(),
            KernelDispatches::new(),
        )
        .with_graces(GRACE, GRACE);
        let (signal_tx, signal_rx) = oneshot::channel::<()>();
        signal_tx.send(()).expect("the test owns the stop signal");
        let bounded_stop = tokio::time::Instant::now();
        let (result, accounting) = orchestrate_serving(
            Ok(pending::<std::io::Result<()>>()),
            pumps,
            async move {
                let _ = signal_rx.await;
            },
            None::<NoCapsule>,
            shutdown,
        )
        .await;
        let elapsed = bounded_stop.elapsed();

        assert!(
            result.is_ok(),
            "a bounded stop with stragglers still succeeds: {result:?}"
        );
        assert!(
            elapsed >= GRACE,
            "the unresponsive work held the stop to the shared deadline: \
             {elapsed:?} < {GRACE:?}"
        );
        assert!(
            elapsed <= GRACE + Duration::from_secs(2),
            "the shared deadline bounded the whole stop: {elapsed:?}"
        );
        assert_eq!(
            registry.served_connections(),
            1,
            "the unresponsive connection is truthfully still served at the bound"
        );
        assert_eq!(
            accounting.outcome,
            ShutdownOutcome::Stragglers {
                tracked: 0,
                stragglers: 2,
            },
            "both owned tasks were honestly mid-flight at the deadline: the unresponsive served \
             connection and the blocking pump held until release",
        );

        // Deterministic state asserted, then release: the held pump is freed and its completion
        // witness joined under a real-time bound; the served connection — a straggler the seam
        // aborted without joining — is aborted and joined here instead of detached.
        release_tx
            .send(())
            .expect("the test owns the blocking pump's release");
        witness_rx
            .recv_timeout(HANDSHAKE_BOUND)
            .expect("the released blocking pump completed and its witness joined");
        served.abort();
        // One yield lets the runtime finish the cancellation before the join is polled.
        tokio::task::yield_now().await;
        let joined = tokio::time::timeout(HANDSHAKE_BOUND, served)
            .await
            .expect("the aborted unresponsive connection joined within its bound");
        assert!(
            joined
                .expect_err("an aborted connection never yields output")
                .is_cancelled(),
            "the unresponsive connection handle ended cancelled",
        );
    }

    use std::num::NonZeroU16;
    use std::sync::atomic::AtomicUsize;
    use std::time::Duration as StdDuration;

    use async_trait::async_trait;
    use odin_domain::huginn::{
        ArtifactReadRequest, ArtifactReadStream, ArtifactRef, CommandReceipt, ContentTicket,
        ContentTicketIssuer, ContentTicketRequest, DeltaPage, DeltaQuery, HistoryPage,
        HistoryQuery, HuginnCommandPort, HuginnMessageStream, HuginnProtocolError, HuginnReadModel,
        HuginnRequest, HuginnResponse, HuginnStreamSource, LiveClientRequest, LiveCommand,
        LiveError, LiveEventStream, LiveSessionId, LiveSessionSummary, OmpLivePlane,
        OpenSessionRequest, RequestId, SearchPage, SearchQuery, SeatRoster, SessionListPage,
        SessionListQuery, SnapshotPage, SnapshotQuery, SubscribeRequest, SubscriptionSet,
        TerminalControlLeaseId, TerminalControlRequest, TerminalControlStatus, TerminalInput,
        TerminalResize, TransferChunk, TransferId, TransferStatus, UploadManifest,
    };
    use odin_domain::CommandId;
    use odin_huginn::dispatch::{
        AuthenticatedCommandPort, ConnectionFrame, DispatchGuard, FrameReader, FrameWriter,
        LiveDispatcher, LiveDispatcherLimits, RegistryError, ServerConnection,
    };
    use odin_huginn::protocol::{encode_frame, ClientFrame, CodecLimits};
    use tokio::sync::{mpsc, Semaphore};

    fn unavailable() -> LiveError {
        LiveError::unavailable("fixture", "the fixture serves nothing")
    }

    fn protocol_unsupported() -> HuginnProtocolError {
        HuginnProtocolError::Unsupported {
            operation: "fixture".to_owned(),
        }
    }

    struct StubPlane {
        listings: AtomicUsize,
    }

    #[async_trait]
    impl HuginnCommandPort for StubPlane {
        async fn execute(
            &self,
            _request: HuginnRequest,
        ) -> Result<HuginnResponse, HuginnProtocolError> {
            Err(protocol_unsupported())
        }
    }

    #[async_trait]
    impl AuthenticatedCommandPort for StubPlane {
        async fn execute_authenticated(
            &self,
            _device: DeviceId,
            _request: HuginnRequest,
        ) -> Result<HuginnResponse, HuginnProtocolError> {
            Err(protocol_unsupported())
        }
    }

    #[async_trait]
    impl OmpLivePlane for StubPlane {
        async fn terminal_snapshot(
            &self,
            _session: odin_domain::huginn::LiveSessionId,
        ) -> Result<odin_domain::huginn::TerminalSnapshot, LiveError> {
            Err(unavailable())
        }

        async fn roster(&self) -> Result<SeatRoster, LiveError> {
            Err(unavailable())
        }

        async fn sessions(&self, _query: SessionListQuery) -> Result<SessionListPage, LiveError> {
            self.listings.fetch_add(1, Ordering::SeqCst);
            std::future::pending().await
        }

        async fn history(&self, _query: HistoryQuery) -> Result<HistoryPage, LiveError> {
            Err(unavailable())
        }

        async fn subscribe(
            &self,
            _request: SubscribeRequest,
        ) -> Result<LiveEventStream, LiveError> {
            Err(unavailable())
        }

        async fn open_session(
            &self,
            _request: OpenSessionRequest,
        ) -> Result<LiveSessionSummary, LiveError> {
            Err(unavailable())
        }

        async fn command(&self, _command: LiveCommand) -> Result<CommandReceipt, LiveError> {
            Err(unavailable())
        }

        async fn begin_upload(
            &self,
            _manifest: UploadManifest,
        ) -> Result<TransferStatus, LiveError> {
            Err(unavailable())
        }

        async fn upload_chunk(
            &self,
            _transfer: TransferId,
            _chunk: TransferChunk,
        ) -> Result<(), LiveError> {
            Err(unavailable())
        }

        async fn commit_upload(&self, _transfer: TransferId) -> Result<ArtifactRef, LiveError> {
            Err(unavailable())
        }

        async fn cancel_transfer(
            &self,
            _command_id: CommandId,
            _transfer: TransferId,
        ) -> Result<TransferStatus, LiveError> {
            Err(unavailable())
        }

        async fn grant_download_credit(
            &self,
            _command_id: CommandId,
            _transfer: TransferId,
            _chunks: NonZeroU16,
        ) -> Result<(), LiveError> {
            Ok(())
        }

        async fn read_artifact(
            &self,
            _request: ArtifactReadRequest,
        ) -> Result<(ArtifactRef, ArtifactReadStream), LiveError> {
            Err(unavailable())
        }

        async fn acquire_terminal_control(
            &self,
            _command_id: CommandId,
            _device: DeviceId,
            _request: TerminalControlRequest,
        ) -> Result<TerminalControlStatus, LiveError> {
            Err(unavailable())
        }

        async fn write_terminal(
            &self,
            _command_id: CommandId,
            _session: LiveSessionId,
            _input: TerminalInput,
        ) -> Result<(), LiveError> {
            Err(unavailable())
        }

        async fn resize_terminal(
            &self,
            _command_id: CommandId,
            _session: LiveSessionId,
            _resize: TerminalResize,
        ) -> Result<(), LiveError> {
            Err(unavailable())
        }

        async fn release_terminal_control(
            &self,
            _command_id: CommandId,
            _session: LiveSessionId,
            _lease: TerminalControlLeaseId,
        ) -> Result<TerminalControlStatus, LiveError> {
            Err(unavailable())
        }
    }

    struct StubReadModel;

    #[async_trait]
    impl HuginnReadModel for StubReadModel {
        async fn snapshot(
            &self,
            _query: SnapshotQuery,
        ) -> Result<SnapshotPage, HuginnProtocolError> {
            Err(protocol_unsupported())
        }

        async fn search(&self, _query: SearchQuery) -> Result<SearchPage, HuginnProtocolError> {
            Err(protocol_unsupported())
        }

        async fn deltas(
            &self,
            _query: DeltaQuery,
            _max_bytes: usize,
        ) -> Result<DeltaPage, HuginnProtocolError> {
            Err(protocol_unsupported())
        }
    }

    struct StubStreams;

    #[async_trait]
    impl HuginnStreamSource for StubStreams {
        async fn subscribe(
            &self,
            _subscriptions: SubscriptionSet,
        ) -> Result<HuginnMessageStream, HuginnProtocolError> {
            Err(protocol_unsupported())
        }
    }

    struct StubTickets;

    #[async_trait]
    impl ContentTicketIssuer for StubTickets {
        async fn issue(
            &self,
            _device: DeviceId,
            _request: ContentTicketRequest,
        ) -> Result<ContentTicket, HuginnProtocolError> {
            Err(protocol_unsupported())
        }
    }

    struct StubGuard;

    #[async_trait]
    impl DispatchGuard for StubGuard {
        async fn check_stop(&self) -> Result<(), HuginnProtocolError> {
            Ok(())
        }
    }

    /// A peer whose writer never drains: every send parks on an empty permit set.
    struct BlockedConnection {
        incoming: mpsc::UnboundedReceiver<ConnectionFrame>,
        writer: BlockedWriter,
    }

    struct BlockedReader(mpsc::UnboundedReceiver<ConnectionFrame>);

    #[derive(Clone)]
    struct BlockedWriter {
        permits: Arc<Semaphore>,
        written: Arc<parking_lot::Mutex<Vec<ConnectionFrame>>>,
    }

    impl ServerConnection for BlockedConnection {
        type Reader = BlockedReader;
        type Writer = BlockedWriter;

        fn split(self) -> (Self::Reader, Self::Writer) {
            (BlockedReader(self.incoming), self.writer)
        }
    }

    #[async_trait]
    impl FrameReader for BlockedReader {
        async fn receive(&mut self) -> Result<Option<ConnectionFrame>, String> {
            Ok(self.0.recv().await)
        }
    }

    #[async_trait]
    impl FrameWriter for BlockedWriter {
        async fn send(&mut self, frame: ConnectionFrame) -> Result<(), String> {
            self.permits
                .acquire()
                .await
                .map_err(|error| error.to_string())?
                .forget();
            self.written.lock().push(frame);
            Ok(())
        }
    }

    /// At the daemon seam, through the REAL serve loop: a peer whose writer is blocked and whose
    /// command the plane never answers is given up, closed without a revocation, and drained when the
    /// owning shutdown stops the registry — no registration watcher stands in for the connection.
    #[tokio::test(start_paused = true)]
    async fn daemon_stop_cancels_a_blocked_write_and_outstanding_command_through_the_real_dispatcher(
    ) {
        let registry = odin_huginn::ConnectionRegistry::new();
        let plane = Arc::new(StubPlane {
            listings: AtomicUsize::new(0),
        });
        let device = connection();
        let registration = register_connection(&registry, &device)
            .await
            .expect("admitted");
        let (to_server, incoming) = mpsc::unbounded_channel();
        let writer = BlockedWriter {
            permits: Arc::new(Semaphore::new(0)),
            written: Arc::new(parking_lot::Mutex::new(Vec::new())),
        };
        let limits = CodecLimits::default();
        let dispatcher = LiveDispatcher::with_limits(
            Arc::new(StubReadModel),
            Arc::clone(&plane),
            Arc::new(StubStreams),
            Arc::new(StubGuard),
            Arc::new(StubTickets),
            LiveDispatcherLimits::new(limits, 64, NonZeroU16::new(16).unwrap()),
        );
        let transport = BlockedConnection {
            incoming,
            writer: writer.clone(),
        };
        let served = tokio::spawn(async move {
            dispatcher
                .serve_connection(transport, device, registration)
                .await
        });
        to_server
            .send(ConnectionFrame::Ping(vec![7].into()))
            .unwrap();
        to_server
            .send(ConnectionFrame::Binary(
                encode_frame(
                    &ClientFrame::Live(LiveClientRequest::ListSessions {
                        request_id: RequestId::parse(&uuid::Uuid::new_v4().to_string()).unwrap(),
                        seat_id: None,
                        include_ended: false,
                        cursor: None,
                        limit: NonZeroU16::MIN,
                    }),
                    &limits,
                )
                .unwrap()
                .into(),
            ))
            .unwrap();
        tokio::time::timeout(StdDuration::from_secs(5), async {
            while plane.listings.load(Ordering::SeqCst) == 0 {
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("the command reached the plane while the write was blocked");

        let (stop_tx, _stop_rx) = watch::channel(false);
        let (signal_tx, signal_rx) = oneshot::channel::<()>();
        signal_tx.send(()).expect("the test owns the stop signal");
        let started = tokio::time::Instant::now();
        let (_result, accounting) = orchestrate_serving(
            Ok(pending::<std::io::Result<()>>()),
            tokio::task::JoinSet::new(),
            async move {
                let _ = signal_rx.await;
            },
            None::<NoCapsule>,
            shutdown_without_devices(
                stop_tx,
                registry.clone(),
                Vec::new(),
                KernelDispatches::new(),
            ),
        )
        .await;
        assert!(started.elapsed() <= StdDuration::from_millis(2_100));
        assert_eq!(accounting.outcome, ShutdownOutcome::Drained { tracked: 1 });

        tokio::time::timeout(StdDuration::from_secs(2), served)
            .await
            .expect("the real serve loop ended within the close bound")
            .expect("the serve loop joined")
            .expect("the serve loop ended cleanly");
        assert!(writer.written.lock().is_empty());
        assert_eq!(registry.served_connections(), 0);
        assert!(matches!(
            register_connection(&registry, &connection()).await,
            Err(AuthError::Registry(RegistryError::Stopping))
        ));
    }
}
