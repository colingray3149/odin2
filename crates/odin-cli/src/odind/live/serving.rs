//! Stop admission and drain runtime tasks within one shutdown deadline.

use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::composition::produce_extension_policy;
use crate::controller;
use crate::harness::ObservedSessions;
use crate::kernel_mcp::KernelDispatches;
use odin_cli::runtime_bindings::RuntimeInputs;
use odin_huginn::browser::BrowserProjectionError;
use odin_huginn::ConnectionRegistry;
use odin_huginn::{HuginnConfig, NodePosture, OdindConfig};
use odin_registry::{SnapshotHandle, SnapshotStore};
use tokio::sync::watch;

use super::super::device_open::{DeviceOpenStop, DeviceOpenStopIncomplete};
use super::browser_capsule;

/// One cooperative deadline for serving, device rollback, and live authority retirement.
pub(super) const SHUTDOWN_GRACE: Duration = Duration::from_secs(8);

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
        .worker_threads(8)
        .enable_all()
        .build()
        .map_err(|error| format!("could not start Huginn runtime: {error}"))?;
    let shutdown_started = Arc::new(Mutex::new(None));
    let served = tokio.block_on(super::serve_huginn_async(
        config,
        validated,
        snapshot,
        Arc::clone(&handle),
        runtime,
        policy,
        posture,
        Arc::clone(&shutdown_started),
    ));
    let started = *shutdown_started
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    finish_runtime(tokio, served, started)
}

#[cfg(test)]
mod publication_tests {
    use super::{finish_runtime, SHUTDOWN_GRACE};
    use std::sync::mpsc;
    use std::time::{Duration, Instant};

    fn huginn_runtime() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(8)
            .enable_all()
            .build()
            .expect("huginn runtime")
    }

    /// Runs `finish_runtime` while one blocking task is held past the stop,
    /// then releases it; returns the teardown result and how long it took.
    fn finish_with_held_task(served: Result<(), String>) -> (Result<(), String>, Duration) {
        let runtime = huginn_runtime();
        let (started_tx, started_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let (finished_tx, finished_rx) = mpsc::channel();
        let task = runtime.spawn_blocking(move || {
            started_tx.send(()).unwrap();
            release_rx.recv().unwrap();
            finished_tx.send(()).unwrap();
        });
        started_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        let before = Instant::now();
        let result = finish_runtime(runtime, served, Some(before - SHUTDOWN_GRACE));
        let elapsed = before.elapsed();
        release_tx.send(()).unwrap();
        finished_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        drop(task);
        (result, elapsed)
    }

    #[test]
    fn runtime_drain_does_not_restart_expired_serving_grace() {
        let (result, elapsed) = finish_with_held_task(Ok(()));
        assert!(
            elapsed < Duration::from_secs(2),
            "runtime drain restarted an exhausted serving grace: {elapsed:?}"
        );
        result.expect("ordinary teardown returns the serve result");
    }

    #[test]
    fn a_serving_failure_is_the_teardown_result() {
        let (result, _) = finish_with_held_task(Err("Huginn service failed".into()));
        let error = result.unwrap_err();
        assert!(error.contains("Huginn service failed"), "{error}");
    }

    #[test]
    fn ordinary_stop_returns_the_serve_result() {
        let runtime = huginn_runtime();
        runtime.block_on(async { tokio::task::spawn_blocking(|| ()).await.unwrap() });
        let before = Instant::now();
        finish_runtime(runtime, Ok(()), Some(before)).expect("ordinary stop succeeds");
        assert!(before.elapsed() < SHUTDOWN_GRACE);
    }
}

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
    observers: Option<Arc<ObservedSessions>>,
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
}

impl ServingShutdown {
    pub(super) fn own(
        stop: watch::Sender<bool>,
        connections: ConnectionRegistry,
        mcp_listeners: Vec<tokio::task::JoinHandle<()>>,
        dispatches: KernelDispatches,
        observers: Option<Arc<ObservedSessions>>,
        device_opens: DeviceOpenStop,
    ) -> Self {
        Self {
            stop,
            connections: Some(connections),
            mcp_listeners,
            dispatches,
            observers,
            session_supervisor: None,
            harness_turns: None,
            device_opens: Some(device_opens),
            authority_pool: None,
            background_root: None,
            notifications: None,
            terminals: None,
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
    /// calls, no observer, no sessions.
    #[cfg(test)]
    pub(super) fn detached() -> Self {
        Self {
            stop: watch::channel(false).0,
            connections: None,
            mcp_listeners: Vec::new(),
            dispatches: KernelDispatches::new(),
            observers: None,
            session_supervisor: None,
            harness_turns: None,
            device_opens: None,
            authority_pool: None,
            background_root: None,
            notifications: None,
            terminals: None,
        }
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
        if let Some(observers) = &self.observers {
            observers.stop();
        }
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
        let deadline = tokio::time::Instant::now() + SHUTDOWN_GRACE;
        self.finish_until(pumps, supervision, started, deadline)
            .await
    }

    async fn finish_until(
        mut self,
        mut pumps: tokio::task::JoinSet<Result<(), String>>,
        supervision: &mut Option<browser_capsule::BrowserCapsuleSupervision>,
        started: Instant,
        deadline: tokio::time::Instant,
    ) -> ShutdownAccounting {
        self.signal(supervision);
        // Egress cancellation never waits behind the connection drain.
        pumps.abort_all();

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

        if let Some(observers) = &self.observers {
            let (drained, missed) = observers.join(deadline).await;
            tracked += drained;
            stragglers += missed;
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

        // Browser shutdown started at the signal and shares the same deadline.
        let capsule_failures = match supervision.as_mut() {
            Some(supervision) => {
                match tokio::time::timeout_at(deadline, supervision.retire_and_join()).await {
                    Ok(failures) => {
                        tracked += 1;
                        failures
                    }
                    Err(_) => {
                        stragglers += 1;
                        tracing::error!(
                            worker = "browser",
                            cause = "shutdown deadline expired",
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
            deadline: deadline.into_std(),
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
        pump = pumps.join_next(), if !pumps.is_empty() => match pump {
            Some(Ok(result)) => result,
            Some(Err(error)) => Err(format!("artifact egress task failed: {error}")),
            None => Err("artifact egress task set closed".to_owned()),
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
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::mpsc as std_mpsc;
    use std::sync::Arc;
    use std::time::Duration;

    use crate::kernel_mcp::KernelDispatches;
    use odin_domain::huginn::{ConnectionId, DeviceId, TailnetNodeId, VerifiedColinDevice};
    use odin_huginn::auth::AuthError;
    use odin_huginn::browser::BrowserProjectionError;
    use odin_huginn::devices::{DeviceTrustStore as _, NewDeviceRecord, SqliteDeviceTrustStore};
    use tokio::sync::{oneshot, watch};

    use super::{orchestrate_serving, ServingShutdown, ShutdownOutcome, SHUTDOWN_GRACE};

    type NoCapsule = (
        Pin<Box<dyn Future<Output = Result<(), BrowserProjectionError>> + Send>>,
        fn() -> Pin<Box<dyn Future<Output = Vec<String>> + Send>>,
    );

    fn shutdown_without_devices(
        stop: watch::Sender<bool>,
        connections: odin_huginn::ConnectionRegistry,
        mcp_listeners: Vec<tokio::task::JoinHandle<()>>,
        dispatches: KernelDispatches,
        observers: Option<Arc<crate::harness::ObservedSessions>>,
    ) -> ServingShutdown {
        ServingShutdown {
            stop,
            connections: Some(connections),
            mcp_listeners,
            dispatches,
            observers,
            session_supervisor: None,
            harness_turns: None,
            device_opens: None,
            authority_pool: None,
            background_root: None,
            notifications: None,
            terminals: None,
        }
    }

    struct NotificationSink {
        entered: std_mpsc::Sender<()>,
        released: parking_lot::Mutex<bool>,
        changed: parking_lot::Condvar,
        delivered: std::sync::atomic::AtomicUsize,
    }

    impl NotificationSink {
        fn release(&self) {
            *self.released.lock() = true;
            self.changed.notify_all();
        }
    }

    #[async_trait::async_trait]
    impl odin_hermes::egress::OutgoingSink for NotificationSink {
        async fn deliver(
            &self,
            _: odin_hermes::egress::OutboundMessage,
            _: Arc<dyn odin_hermes::egress::DeliveryCheckpoint>,
        ) -> Result<odin_hermes::egress::ReplyChunks, odin_hermes::egress::EgressError> {
            Err(odin_hermes::egress::EgressError::InvalidState(
                "unused fixture route",
            ))
        }

        async fn send(
            &self,
            message: odin_hermes::egress::OutboundMessage,
        ) -> Result<odin_hermes::egress::ReplyChunks, odin_hermes::egress::EgressError> {
            let _ = self.entered.send(());
            let deadline = std::time::Instant::now() + Duration::from_secs(10);
            let mut released = self.released.lock();
            while !*released {
                if self.changed.wait_until(&mut released, deadline).timed_out() {
                    return Err(odin_hermes::egress::EgressError::ReplyLost);
                }
            }
            self.delivered.fetch_add(1, Ordering::SeqCst);
            Ok(odin_hermes::egress::ReplyChunks::single(
                odin_hermes::discord::DiscordMessageRef {
                    message_id: "notification-fixture-1".to_owned(),
                    channel_id: message.channel_id,
                },
            ))
        }

        async fn edit(
            &self,
            _: &odin_hermes::egress::ReplyChunks,
            _: odin_hermes::egress::OutboundMessage,
        ) -> Result<odin_hermes::egress::ReplyChunks, odin_hermes::egress::EgressError> {
            Err(odin_hermes::egress::EgressError::InvalidState(
                "unused fixture route",
            ))
        }

        async fn typing(&self, _: &str) -> Result<(), odin_hermes::egress::EgressError> {
            Ok(())
        }
    }

    struct NotificationCaller {
        sink: Arc<NotificationSink>,
        thread: Option<std::thread::JoinHandle<Result<(), String>>>,
    }

    impl Drop for NotificationCaller {
        fn drop(&mut self) {
            self.sink.release();
            if let Some(thread) = self.thread.take() {
                let _ = thread.join();
            }
        }
    }

    fn held_notification(runtime: &Arc<odin_hermes::runtime::HermesRuntime>) -> NotificationCaller {
        let (entered, observed) = std_mpsc::channel();
        let sink = Arc::new(NotificationSink {
            entered,
            released: parking_lot::Mutex::new(false),
            changed: parking_lot::Condvar::new(),
            delivered: std::sync::atomic::AtomicUsize::new(0),
        });
        runtime
            .bind_notify_sink(sink.clone())
            .expect("private notification sink");
        let runtime = Arc::clone(runtime);
        let caller = NotificationCaller {
            sink,
            thread: Some(std::thread::spawn(move || {
                runtime.notify("private shutdown probe")
            })),
        };
        observed
            .recv_timeout(Duration::from_secs(10))
            .expect("notification entered its sink");
        caller
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn notification_straggler_allows_exit_without_reopening_delivery() {
        let fixture = crate::live::hermes_routes::tests::gate_fixture().await;
        let mut caller = held_notification(&fixture.runtime);
        let accounting = ServingShutdown::detached()
            .with_notifications(Some(Arc::clone(&fixture.runtime)))
            .finish_until(
                tokio::task::JoinSet::new(),
                &mut None,
                std::time::Instant::now(),
                tokio::time::Instant::now(),
            )
            .await;
        let outcome = accounting.outcome;
        let finalized =
            super::super::shutdown::finalize(Ok(()), accounting, None, &fixture.session_pool).await;
        let late = fixture.runtime.notify("must not be sent");
        let pending = caller
            .thread
            .take()
            .unwrap()
            .join()
            .expect("notification caller joined");
        caller.sink.release();
        fixture
            .runtime
            .drain_notifications_until(tokio::time::Instant::now() + Duration::from_secs(10))
            .await
            .expect("released notification worker joined");
        assert!(matches!(
            outcome,
            ShutdownOutcome::Stragglers { stragglers: 1, .. }
        ));
        finalized.expect("shutdown residue does not fail the daemon exit");
        assert!(pending.is_err() && late.is_err());
        assert_eq!(caller.sink.delivered.load(Ordering::SeqCst), 1);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn notification_drain_allows_daemon_exit_and_refuses_late_sends() {
        let fixture = crate::live::hermes_routes::tests::gate_fixture().await;
        let mut caller = held_notification(&fixture.runtime);
        caller.sink.release();
        caller
            .thread
            .take()
            .unwrap()
            .join()
            .expect("notification caller joined")
            .unwrap();
        let accounting = ServingShutdown::detached()
            .with_notifications(Some(Arc::clone(&fixture.runtime)))
            .finish_until(
                tokio::task::JoinSet::new(),
                &mut None,
                std::time::Instant::now(),
                tokio::time::Instant::now() + Duration::from_secs(10),
            )
            .await;
        assert!(matches!(
            accounting.outcome,
            ShutdownOutcome::Drained { .. }
        ));
        super::super::shutdown::finalize(Ok(()), accounting, None, &fixture.session_pool)
            .await
            .expect("the notification worker was joined before authority retirement");
        assert!(fixture.runtime.notify("must not be sent").is_err());
        assert_eq!(caller.sink.delivered.load(Ordering::SeqCst), 1);
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
        runtime.control.prompt(&message).await.unwrap();
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
            Err(LiveError::Unavailable { code }) if code == "harness_stop_unproven"));
        assert!(runtime.control.prompt(&message).await.is_err());
        assert!(launcher
            .open(&manifest, SessionEpoch::new(1), false)
            .await
            .is_err());
        assert_eq!(workspace.hand_backs.load(Ordering::SeqCst), 0);
    }

    async fn combined_device_browser_shutdown(setup_error: bool) {
        let registry = odin_huginn::ConnectionRegistry::new();
        let registration = register_connection(&registry, &connection())
            .await
            .expect("admitted before stop");
        let _connection_stop = spawn_served_connection(registration);
        let (retired, retirement) = oneshot::channel();
        let mut device_tasks = tokio::task::JoinSet::new();
        device_tasks.spawn(async move {
            retirement
                .await
                .expect("browser retirement releases device rollback");
        });
        let (device_stop, device_closed) = super::DeviceOpenStop::test_owner(device_tasks);
        let (pumps, mut pump_closed) = stopped_pump();
        let browser_registry = registry.clone();
        let capsule = Some((
            pending::<Result<(), BrowserProjectionError>>(),
            move || async move {
                assert!(
                    *device_closed.borrow(),
                    "device admission closes before browser retirement"
                );
                assert!(matches!(
                    register_connection(&browser_registry, &connection()).await,
                    Err(AuthError::Registry(RegistryError::Stopping))
                ));
                retired.send(()).expect("device rollback remains owned");
                Vec::new()
            },
        ));
        let shutdown = ServingShutdown::own(
            watch::channel(false).0,
            registry.clone(),
            Vec::new(),
            KernelDispatches::new(),
            None,
            device_stop,
        );
        let setup = if setup_error {
            Err("pump setup refused".to_owned())
        } else {
            Ok(pending::<std::io::Result<()>>())
        };
        let (result, accounting) =
            orchestrate_serving(setup, pumps, async {}, capsule, shutdown).await;
        if setup_error {
            assert_eq!(result.unwrap_err(), "pump setup refused");
        } else {
            result.expect("normal stop succeeds");
        }
        assert!(accounting.device_stop.is_ok());
        assert_eq!(accounting.outcome, ShutdownOutcome::Drained { tracked: 4 });
        assert!(matches!(
            pump_closed.try_recv(),
            Err(oneshot::error::TryRecvError::Closed)
        ));
        assert_eq!(registry.served_connections(), 0);
        assert!(matches!(
            register_connection(&registry, &connection()).await,
            Err(AuthError::Registry(RegistryError::Stopping))
        ));
    }

    /// Exact libtest entry the registered-worker fixture re-execs as the real bootstrap for the
    /// scripted terminal boundary below.
    #[test]
    fn worker_bootstrap_fixture_entry() {
        odin_process::test_support::run_bootstrap_if_active();
    }

    /// Z1: a terminal open still running at the shutdown deadline is a counted straggler, so
    /// finalization never retires authority beneath it. The open is held inside its `new-tab`
    /// (never cut: its tab id must be read) by a private scripted zellij run as a real
    /// registered worker; once released, the still-owned workflow ends and a later drain proves it.
    #[tokio::test]
    async fn a_terminal_workflow_running_at_the_deadline_blocks_authority_retirement() {
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
                "#!/bin/sh\ncase \"$1 $4\" in\n\
                 'list-sessions ') printf '%s\\n' 'odin [Created 1h ago] ' ;;\n\
                 *' new-tab') : > '{}'; while [ -e '{}' ]; do sleep 0.01; done; echo 1 ;;\n\
                 *' list-clients') ;;\n*) echo '[]' ;;\nesac\n",
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
        let terminals =
            ZellijCliFactory::open(&executable, "odin", state, timeout, columns, rows, launch)
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
        .expect("the open is held in its new-tab");

        let spent = tokio::time::Instant::now() - Duration::from_millis(1);
        let started = std::time::Instant::now();
        let accounting = ServingShutdown::detached()
            .with_terminals(terminals.clone())
            .finish_until(tokio::task::JoinSet::new(), &mut None, started, spent)
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

        std::fs::remove_file(&gate).expect("release new-tab");
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

    /// The live-plane fixture of the seam tests: one real supervisor over
    /// a real FS ledger, one bound seat, one open session whose backend
    /// records its shutdown — and can hold it past any deadline, the
    /// unproven-stop shape the seam must count, never hide.
    struct HeldBackend {
        shutdowns: Arc<std::sync::atomic::AtomicUsize>,
        hold: std::sync::Mutex<Option<oneshot::Receiver<()>>>,
    }

    #[async_trait::async_trait]
    impl odin_omp::live::control::LiveControlBackend for HeldBackend {
        async fn bridge_ready(&self) -> bool {
            true
        }
        async fn prompt(
            &self,
            _: &odin_domain::huginn::LiveMessage,
        ) -> Result<(), odin_domain::huginn::LiveError> {
            Ok(())
        }
        async fn follow_up(
            &self,
            _: &odin_domain::huginn::LiveMessage,
        ) -> Result<(), odin_domain::huginn::LiveError> {
            Ok(())
        }
        async fn steer(
            &self,
            _: &odin_domain::huginn::LiveMessage,
        ) -> Result<(), odin_domain::huginn::LiveError> {
            Ok(())
        }
        async fn pause(&self) -> Result<(), odin_domain::huginn::LiveError> {
            Ok(())
        }
        async fn resume(&self) -> Result<(), odin_domain::huginn::LiveError> {
            Ok(())
        }
        async fn checkpoint(&self) -> Result<(), odin_domain::huginn::LiveError> {
            Ok(())
        }
        async fn restart(&self) -> Result<(), odin_domain::huginn::LiveError> {
            Ok(())
        }
        async fn rehome(
            &self,
            _: &odin_domain::NodeId,
        ) -> Result<(), odin_domain::huginn::LiveError> {
            Ok(())
        }
        async fn set_model(
            &self,
            _: &odin_domain::huginn::ProviderName,
            _: &odin_domain::huginn::ModelName,
        ) -> Result<(), odin_domain::huginn::LiveError> {
            Ok(())
        }
        async fn abort_turn(&self) -> Result<(), odin_domain::huginn::LiveError> {
            Ok(())
        }
        async fn abort_session(&self) -> Result<(), odin_domain::huginn::LiveError> {
            Ok(())
        }
        async fn shutdown(&self) -> Result<(), odin_domain::huginn::LiveError> {
            let hold = self.hold.lock().expect("held shutdown").take();
            if let Some(hold) = hold {
                let _ = hold.await;
            }
            self.shutdowns.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
        async fn decide_permission(
            &self,
            _: &odin_domain::huginn::PermissionRequestId,
            _: odin_domain::huginn::PermissionDecision,
        ) -> Result<(), odin_domain::huginn::LiveError> {
            Ok(())
        }
        async fn decide_approval(
            &self,
            _: &odin_domain::ApprovalId,
            _: u64,
            _: odin_domain::huginn::ApprovalDecision,
        ) -> Result<(), odin_domain::huginn::LiveError> {
            Ok(())
        }
    }

    struct HeldLauncher {
        shutdowns: Arc<std::sync::atomic::AtomicUsize>,
        hold: std::sync::Mutex<Option<oneshot::Receiver<()>>>,
    }

    #[async_trait::async_trait]
    impl odin_omp::live::supervisor::LiveSessionLauncher for HeldLauncher {
        fn harness_turns(&self) -> Option<Arc<odin_omp::live::harness::HarnessTurns>> {
            None
        }

        async fn open(
            &self,
            _manifest: &odin_domain::huginn::SessionManifest,
            _epoch: odin_domain::huginn::SessionEpoch,
            _reclaim: bool,
        ) -> Result<odin_omp::live::supervisor::SessionRuntime, odin_domain::huginn::LiveError>
        {
            Ok(odin_omp::live::supervisor::SessionRuntime {
                control: Arc::new(HeldBackend {
                    shutdowns: Arc::clone(&self.shutdowns),
                    // The one fixture session takes the hold; any later
                    // open starts unheld.
                    hold: std::sync::Mutex::new(self.hold.lock().expect("held open").take()),
                }),
                terminal: None,
                observations: None,
                failed_notices: None,
            })
        }
    }

    fn seam_live_binding() -> odin_omp::live::supervisor::LiveSeatBinding {
        odin_omp::live::supervisor::LiveSeatBinding {
            seat_id: odin_domain::SeatId::new("seam-live-seat").expect("seat id"),
            slice_id: odin_domain::SliceId::new("seam-live-slice").expect("slice id"),
            display_name: "Seam live fixture".to_owned(),
            launch_options: vec![odin_domain::huginn::LiveLaunchOption {
                provider: odin_domain::huginn::ProviderName::new("seam-provider")
                    .expect("provider name"),
                model: odin_domain::huginn::ModelName::new("seam-model").expect("model name"),
                skeleton_ref: "seam-fixture".to_owned(),
                container_id: odin_domain::ContainerId::new("seam-native").expect("container"),
                harness: None,
            }],
            allowed_nodes: vec![odin_domain::NodeId::new("seam-node").expect("node id")],
            max_sessions: 4,
            turn_budget: None,
        }
    }

    async fn held_plane(
        ledger_root: &std::path::Path,
        hang: bool,
    ) -> (
        Arc<odin_omp::live::supervisor::LiveSupervisor>,
        Arc<std::sync::atomic::AtomicUsize>,
        Option<oneshot::Sender<()>>,
    ) {
        let shutdowns = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let (release, hold) = if hang {
            let (release, hold) = oneshot::channel();
            (Some(release), Some(hold))
        } else {
            (None, None)
        };
        let ledger: Arc<dyn odin_omp::live::ledger::LiveLedger> = Arc::new(
            odin_omp::live::ledger::fs::FsLiveLedger::open(ledger_root.join("live"))
                .expect("live ledger"),
        );
        let supervisor = odin_omp::live::supervisor::LiveSupervisor::new(
            ledger,
            Arc::new(HeldLauncher {
                shutdowns: Arc::clone(&shutdowns),
                hold: std::sync::Mutex::new(hold),
            }),
            4,
            None,
        );
        supervisor
            .bind(seam_live_binding())
            .await
            .expect("bind fixture seat");
        supervisor
            .open(odin_domain::huginn::OpenSessionRequest {
                command_id: odin_domain::CommandId::new("command:seam-live-drain")
                    .expect("command id"),
                seat_id: odin_domain::SeatId::new("seam-live-seat").expect("seat id"),
                project_id: odin_domain::ProjectId::new("seam-live-project").expect("project"),
                slice_id: odin_domain::SliceId::new("seam-live-slice").expect("slice id"),
                provider: odin_domain::huginn::ProviderName::new("seam-provider")
                    .expect("provider name"),
                model: odin_domain::huginn::ModelName::new("seam-model").expect("model name"),
                title: None,
                target_node: odin_domain::NodeId::new("seam-node").expect("node id"),
                open_tab: false,
                initial_prompt: None,
                workload: None,
                served_revision: None,
            })
            .await
            .expect("open fixture session");
        (supervisor, shutdowns, release)
    }

    /// Z-live: a coordinated stop drains the live plane FIRST — every
    /// session actor through its bridge's own bounded ladder — so the
    /// accounting proves the sessions ended inside the deadline instead of
    /// leaving their runtimes and detached feed tasks to the runtime's
    /// thread accounting.
    #[tokio::test]
    async fn the_stop_drains_session_actors_through_their_own_bridge_ladder() {
        let root = tempfile::TempDir::new().expect("fixture root");
        let (supervisor, shutdowns, _release) = held_plane(root.path(), false).await;
        let accounting = ServingShutdown::detached()
            .with_session_supervisor(Arc::clone(&supervisor))
            .finish_until(
                tokio::task::JoinSet::new(),
                &mut None,
                std::time::Instant::now(),
                tokio::time::Instant::now() + Duration::from_secs(10),
            )
            .await;
        assert_eq!(
            accounting.outcome,
            ShutdownOutcome::Drained { tracked: 1 },
            "the one session actor is the seam's first drained stage"
        );
        assert_eq!(
            shutdowns.load(Ordering::SeqCst),
            1,
            "the bridge's own stop ladder ran"
        );
    }

    /// Incomplete session shutdown must prevent authority retirement.
    #[tokio::test]
    async fn an_unproven_session_stop_blocks_authority_retirement() {
        let root = tempfile::TempDir::new().expect("fixture root");
        let (supervisor, shutdowns, release) = held_plane(root.path(), true).await;
        let started = std::time::Instant::now();
        let spent = tokio::time::Instant::now() - Duration::from_millis(1);
        let accounting = ServingShutdown::detached()
            .with_session_supervisor(Arc::clone(&supervisor))
            .finish_until(tokio::task::JoinSet::new(), &mut None, started, spent)
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
        finalized.expect("unproved session stop does not fail the daemon exit");

        // Release the held ladder so the fixture's actor task ends inside
        // the test, and prove the ladder completed rather than vanished.
        drop(release);
        let mut proven = false;
        for _ in 0..500 {
            if shutdowns.load(Ordering::SeqCst) == 1 {
                proven = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(proven, "the held bridge ladder completed after release");
    }

    #[tokio::test]
    async fn combined_stop_closes_admission_before_browser_and_joins_pumps() {
        combined_device_browser_shutdown(false).await;
    }

    #[tokio::test]
    async fn combined_setup_error_still_drains_devices_browser_and_pumps() {
        combined_device_browser_shutdown(true).await;
    }

    #[tokio::test(start_paused = true)]
    async fn expired_deadline_closes_admission_and_initiates_browser_without_fresh_grace() {
        let registry = odin_huginn::ConnectionRegistry::new();
        let (device_stop, device_closed) =
            super::DeviceOpenStop::test_owner(tokio::task::JoinSet::new());
        let (retired, retirement) = oneshot::channel();
        let mut browser = Some(super::browser_capsule::BrowserCapsuleSupervision::spawn(
            pending::<Result<(), BrowserProjectionError>>(),
            move || async move {
                assert!(*device_closed.borrow());
                retired
                    .send(())
                    .expect("retirement is observed after expired drain");
                Vec::new()
            },
        ));
        let shutdown = ServingShutdown::own(
            watch::channel(false).0,
            registry.clone(),
            Vec::new(),
            KernelDispatches::new(),
            None,
            device_stop,
        );
        let now = tokio::time::Instant::now();
        let deadline = now - Duration::from_millis(1);
        let accounting = shutdown
            .finish_until(
                tokio::task::JoinSet::new(),
                &mut browser,
                std::time::Instant::now(),
                deadline,
            )
            .await;
        assert_eq!(accounting.deadline, deadline.into_std());
        assert_eq!(tokio::time::Instant::now(), now, "no replacement grace");
        assert!(
            accounting.device_stop.is_err(),
            "elapsed rollback never counts as drained"
        );
        assert!(matches!(
            accounting.outcome,
            ShutdownOutcome::Stragglers { .. }
        ));
        assert!(matches!(
            register_connection(&registry, &connection()).await,
            Err(AuthError::Registry(RegistryError::Stopping))
        ));
        tokio::time::timeout(Duration::from_secs(1), retirement)
            .await
            .unwrap()
            .unwrap();
        browser.as_mut().unwrap().retire_and_join().await;
    }

    async fn uninterruptible_device_shutdown(setup_error: bool) {
        const HANDSHAKE_BOUND: Duration = Duration::from_secs(5);
        let (started, startup) = oneshot::channel();
        let (release, released) = oneshot::channel();
        let (completed, completion) = oneshot::channel();
        let mut tasks = tokio::task::JoinSet::new();
        // The held rollback is an async task the stop never aborts. A real
        // blocking hold would pin tokio's paused clock: while a blocking task
        // runs, the runtime declines to auto-advance, so the shared deadline
        // could never fire virtually under it. The real-thread rollback is
        // proven on the real clock in tests/device_open.rs.
        tasks.spawn(async move {
            started.send(()).expect("rollback hold starts");
            released.await.expect("release uninterruptible rollback");
            completed.send(()).expect("rollback completion witnessed");
        });
        startup
            .await
            .expect("the rollback hold runs before the stop");
        let (device_stop, device_closed) = super::DeviceOpenStop::test_owner(tasks);
        let (pumps, mut pump_closed) = stopped_pump();
        let retired = Arc::new(AtomicBool::new(false));
        let browser_retired = Arc::clone(&retired);
        let capsule = Some((
            pending::<Result<(), BrowserProjectionError>>(),
            move || async move {
                assert!(*device_closed.borrow());
                browser_retired.store(true, Ordering::Release);
                Vec::new()
            },
        ));
        let mut shutdown = ServingShutdown::detached();
        shutdown.device_opens = Some(device_stop.clone());
        let before = tokio::time::Instant::now();
        let setup = if setup_error {
            Err("pump setup refused".to_owned())
        } else {
            Ok(pending::<std::io::Result<()>>())
        };
        let (result, accounting) =
            orchestrate_serving(setup, pumps, async {}, capsule, shutdown).await;
        if setup_error {
            assert_eq!(result.unwrap_err(), "pump setup refused");
        } else {
            result.unwrap();
        }
        assert_eq!(before.elapsed(), SHUTDOWN_GRACE);
        assert!(accounting.device_stop.is_err());
        assert_eq!(
            accounting.outcome,
            ShutdownOutcome::Stragglers {
                tracked: 2,
                stragglers: 1
            }
        );
        assert!(retired.load(Ordering::Acquire));
        assert!(matches!(
            pump_closed.try_recv(),
            Err(oneshot::error::TryRecvError::Closed)
        ));
        release
            .send(())
            .expect("the test owns the rollback release");
        tokio::time::timeout(HANDSHAKE_BOUND, completion)
            .await
            .expect("the retained rollback completes once released")
            .expect("the rollback completion is witnessed");
        device_stop
            .stop_until(tokio::time::Instant::now() + HANDSHAKE_BOUND)
            .await
            .expect("timed out device tasks were retained, not aborted");
    }

    #[tokio::test(start_paused = true)]
    async fn uninterruptible_device_work_is_incomplete_but_browser_and_pumps_join() {
        uninterruptible_device_shutdown(false).await;
    }

    #[tokio::test(start_paused = true)]
    async fn setup_failure_preserves_incomplete_device_stop_and_requests_browser_retirement() {
        uninterruptible_device_shutdown(true).await;
    }

    fn connection() -> VerifiedColinDevice {
        VerifiedColinDevice {
            device_id: DeviceId::new(uuid::Uuid::new_v4()).unwrap(),
            tailnet_node_id: TailnetNodeId::parse("node.laptop").unwrap(),
            connection_id: ConnectionId::new(uuid::Uuid::new_v4()).unwrap(),
        }
    }

    async fn register_connection(
        registry: &odin_huginn::ConnectionRegistry,
        device: &VerifiedColinDevice,
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

    /// Panics on drop unless the registry already stopped: the seam must notify before the pinned serve
    /// future ever drops.
    struct NotifiedBeforeDrop(watch::Receiver<bool>);

    impl Drop for NotifiedBeforeDrop {
        fn drop(&mut self) {
            assert!(
                *self.0.borrow(),
                "the serve future dropped before the shutdown notification"
            );
        }
    }

    /// A served connection's loop: parks on the registration's stopping watch and ends — dropping the
    /// registration — when the seam stops the registry.
    fn spawn_served_connection(
        registration: odin_huginn::dispatch::ConnectionRegistration,
    ) -> watch::Receiver<bool> {
        let witness = registration.stopping();
        let loop_stopping = registration.stopping();
        tokio::spawn(async move {
            let _registration = registration;
            let mut stopping = loop_stopping;
            loop {
                if *stopping.borrow_and_update() {
                    break;
                }
                if stopping.changed().await.is_err() {
                    break;
                }
            }
        });
        witness
    }

    fn stopped_pump() -> (
        tokio::task::JoinSet<Result<(), String>>,
        oneshot::Receiver<()>,
    ) {
        let (pump_tx, pump_rx) = oneshot::channel::<()>();
        let mut pumps = tokio::task::JoinSet::new();
        pumps.spawn(async move {
            let _held = pump_tx;
            pending::<()>().await;
            #[allow(unreachable_code)]
            Ok::<(), String>(())
        });
        (pumps, pump_rx)
    }

    #[tokio::test]
    async fn signal_notifies_before_serving_drops_and_drains_and_joins() {
        let registry = odin_huginn::ConnectionRegistry::new();
        let registration = register_connection(&registry, &connection())
            .await
            .expect("admitted");
        let witness = spawn_served_connection(registration);
        let (pumps, mut pump_rx) = stopped_pump();

        let (stop_tx, _stop_rx) = watch::channel(false);
        let shutdown = shutdown_without_devices(
            stop_tx,
            registry.clone(),
            Vec::new(),
            KernelDispatches::new(),
            None,
        );

        let (signal_tx, signal_rx) = oneshot::channel::<()>();
        signal_tx.send(()).expect("the test owns the stop signal");
        let guard = NotifiedBeforeDrop(witness);
        let serve = async move {
            let _guard = guard;
            pending::<std::io::Result<()>>().await
        };
        let (result, accounting) = orchestrate_serving(
            Ok(serve),
            pumps,
            async move {
                let _ = signal_rx.await;
            },
            None::<NoCapsule>,
            shutdown,
        )
        .await;

        assert!(result.is_ok(), "the stop path stays clean: {result:?}");
        assert_eq!(accounting.outcome, ShutdownOutcome::Drained { tracked: 2 });
        assert_eq!(
            registry.served_connections(),
            0,
            "the served connection observed stopping and drained"
        );
        assert!(
            matches!(
                pump_rx.try_recv(),
                Err(oneshot::error::TryRecvError::Closed)
            ),
            "the pump was aborted and joined inside the seam"
        );
    }

    #[tokio::test]
    async fn deadline_bounds_unresponsive_work_instead_of_hanging_the_stop() {
        // Tokio cannot auto-advance a paused clock while blocking work runs; use real deadlines.
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
            None,
        );
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
            elapsed >= SHUTDOWN_GRACE,
            "the unresponsive work held the stop to the shared deadline: \
             {elapsed:?} < {SHUTDOWN_GRACE:?}"
        );
        assert!(
            elapsed <= SHUTDOWN_GRACE + Duration::from_secs(2),
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

    #[tokio::test]
    async fn serving_error_stops_and_joins_owned_work_before_returning() {
        let registry = odin_huginn::ConnectionRegistry::new();
        let registration = register_connection(&registry, &connection())
            .await
            .expect("admitted");
        let _witness = spawn_served_connection(registration);
        let (pumps, mut pump_rx) = stopped_pump();

        let (stop_tx, _stop_rx) = watch::channel(false);
        let shutdown = shutdown_without_devices(
            stop_tx,
            registry.clone(),
            Vec::new(),
            KernelDispatches::new(),
            None,
        );
        let (result, accounting) = orchestrate_serving(
            Err::<std::future::Pending<std::io::Result<()>>, _>("boom".to_owned()),
            pumps,
            pending(),
            None::<NoCapsule>,
            shutdown,
        )
        .await;

        assert!(
            result.err().is_some_and(|error| error.contains("boom")),
            "the setup error is preserved verbatim"
        );
        assert_eq!(accounting.outcome, ShutdownOutcome::Drained { tracked: 2 });
        assert_eq!(
            registry.served_connections(),
            0,
            "an error exit still stops and drains the registry"
        );
        assert!(
            matches!(
                pump_rx.try_recv(),
                Err(oneshot::error::TryRecvError::Closed)
            ),
            "an error exit still aborts and joins the pumps"
        );
    }

    #[tokio::test]
    async fn mcp_listeners_join_on_their_owned_token_and_other_instances_are_untouched() {
        let (stop_a, mut rx_a) = watch::channel(false);
        let served_a = Arc::new(AtomicBool::new(false));
        let listener = {
            let served_a = Arc::clone(&served_a);
            tokio::spawn(async move {
                while !*rx_a.borrow_and_update() {
                    if rx_a.changed().await.is_err() {
                        break;
                    }
                }
                served_a.store(true, Ordering::SeqCst);
            })
        };
        let (stop_b, rx_b) = watch::channel(false);

        let accounting = shutdown_without_devices(
            stop_a,
            odin_huginn::ConnectionRegistry::new(),
            vec![listener],
            KernelDispatches::new(),
            None,
        )
        .finish(tokio::task::JoinSet::new(), &mut None)
        .await;
        assert!(
            served_a.load(Ordering::SeqCst),
            "the listener drained on its own instance's token"
        );
        assert_eq!(accounting.outcome, ShutdownOutcome::Drained { tracked: 1 });
        assert!(
            !*rx_b.borrow(),
            "a second daemon instance's token is untouched: no process-global stop"
        );

        assert_eq!(
            shutdown_without_devices(
                stop_b,
                odin_huginn::ConnectionRegistry::new(),
                Vec::new(),
                KernelDispatches::new(),
                None,
            )
            .finish(tokio::task::JoinSet::new(), &mut None)
            .await
            .outcome,
            ShutdownOutcome::Drained { tracked: 0 }
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
        LiveError::Unavailable {
            code: "fixture".to_owned(),
        }
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

    /// P0-4 at the daemon seam, through the REAL serve loop: a peer whose writer is blocked and whose
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
                None,
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

    /// Browser retirement runs concurrently with unrelated drains.
    #[tokio::test(start_paused = true)]
    async fn browser_ladder_joins_even_when_unrelated_stragglers_fill_the_deadline() {
        let registry = odin_huginn::ConnectionRegistry::new();
        let registration = register_connection(&registry, &connection())
            .await
            .expect("admitted");
        // Serves without ever observing stopping: the unrelated straggler.
        tokio::spawn(async move {
            let _registration = registration;
            pending::<()>().await;
        });
        // The capsule never reaches terminal on its own; the stop side's signal retires it.
        let retirements = Arc::new(AtomicUsize::new(0));
        let capsule_retirements = Arc::clone(&retirements);
        let capsule = Some((pending::<Result<(), BrowserProjectionError>>(), move || {
            let retirements = Arc::clone(&capsule_retirements);
            async move {
                retirements.fetch_add(1, Ordering::SeqCst);
                Vec::new()
            }
        }));

        let (stop_tx, _stop_rx) = watch::channel(false);
        let (signal_tx, signal_rx) = oneshot::channel::<()>();
        signal_tx.send(()).expect("the test owns the stop signal");
        let (result, accounting) = orchestrate_serving(
            Ok(pending::<std::io::Result<()>>()),
            tokio::task::JoinSet::new(),
            async move {
                let _ = signal_rx.await;
            },
            capsule,
            shutdown_without_devices(
                stop_tx,
                registry.clone(),
                Vec::new(),
                KernelDispatches::new(),
                None,
            ),
        )
        .await;

        assert_eq!(
            accounting.outcome,
            ShutdownOutcome::Stragglers {
                tracked: 1,
                stragglers: 1
            },
            "the joined capsule ladder is tracked even while the connection straggles"
        );
        assert!(
            result.is_ok(),
            "the seam reports the straggler; the verdict is the caller's: {result:?}"
        );
        assert_eq!(
            retirements.load(Ordering::SeqCst),
            1,
            "the browser ladder ran and joined exactly once despite the straggler"
        );
    }

    /// An unfinished ladder is counted as a straggler at the shared deadline.
    #[tokio::test(start_paused = true)]
    async fn every_owned_stage_joins_under_the_one_deadline() {
        let (_stop_tx, _stop_rx) = watch::channel(false);
        let (signal_tx, signal_rx) = oneshot::channel::<()>();
        signal_tx.send(()).expect("the test owns the stop signal");
        let retirements = Arc::new(AtomicUsize::new(0));
        let capsule_retirements = Arc::clone(&retirements);
        let capsule = Some((pending::<Result<(), BrowserProjectionError>>(), move || {
            let retirements = Arc::clone(&capsule_retirements);
            async move {
                // The ladder the deadline cuts off: attempted, never finished.
                retirements.fetch_add(1, Ordering::SeqCst);
                pending::<()>().await;
                #[allow(unreachable_code)]
                Vec::new()
            }
        }));

        let started = tokio::time::Instant::now();
        let (result, accounting) = orchestrate_serving(
            Ok(pending::<std::io::Result<()>>()),
            tokio::task::JoinSet::new(),
            async move {
                let _ = signal_rx.await;
            },
            capsule,
            ServingShutdown::detached(),
        )
        .await;

        assert_eq!(
            started.elapsed(),
            SHUTDOWN_GRACE,
            "the one deadline bounded every owned stage"
        );
        assert_eq!(
            accounting.outcome,
            ShutdownOutcome::Stragglers {
                tracked: 0,
                stragglers: 1
            },
            "the unfinished ladder is an honest straggler at the bound"
        );
        assert!(
            result.is_ok(),
            "the seam reports the straggler; the verdict is the caller's: {result:?}"
        );
        assert_eq!(
            retirements.load(Ordering::SeqCst),
            1,
            "the ladder was attempted exactly once even though the deadline cut it off"
        );
        assert!(
            accounting.capsule_failures.is_empty(),
            "an unfinished ladder contributes no graceful failures, only the straggler count"
        );
    }

    /// Cleanup failure is logged without replacing a successful serving result.
    #[tokio::test]
    async fn capsule_cleanup_failure_does_not_fail_daemon_exit() {
        let (_stop_tx, _stop_rx) = watch::channel(false);
        let (signal_tx, signal_rx) = oneshot::channel::<()>();
        signal_tx.send(()).expect("the test owns the stop signal");
        let capsule = Some((
            pending::<Result<(), BrowserProjectionError>>(),
            || async move { vec!["browser runtime shutdown failed: gone".to_owned()] },
        ));

        let (result, accounting) = orchestrate_serving(
            Ok(pending::<std::io::Result<()>>()),
            tokio::task::JoinSet::new(),
            async move {
                let _ = signal_rx.await;
            },
            capsule,
            ServingShutdown::detached(),
        )
        .await;

        assert_eq!(
            accounting.outcome,
            ShutdownOutcome::Drained { tracked: 1 },
            "the ladder joined cleanly inside the deadline"
        );
        let config = crate::authority_fixture::fixture();
        let manifest =
            crate::test_fixture::manifest_identity_fixture("git", std::path::Path::new("git"));
        let pool =
            crate::live_authority::SessionAuthorityPool::open_denied(&config.config, &manifest)
                .expect("pool");
        super::super::shutdown::finalize(result, accounting, None, &pool)
            .await
            .expect("cleanup failure does not turn a stop into a serving failure");
    }
}
