//! Session construction and explicit bounded teardown.
//!
//! Launches a fresh in-memory runtime or reopens the durable control
//! generation, wires the frame stream, download manager, and takeover
//! coordinator into the serialized state, hands out control/read aliases,
//! performs the explicit bounded shutdown. A local runtime drops the last
//! session/handle alias onto `Drop`, which stops owned WorkerIds through
//! StopAuthority and leaves the marked profile; a relayed runtime owns no
//! local process and never stops the remote carrier.

use std::sync::{Arc, Mutex as StdMutex};

use odin_domain::huginn::ids::BrowserSessionId;
use odin_ledger::Ledger;
use time::OffsetDateTime;
use tokio::sync::Mutex;

use crate::config::{BrowserConfig, BrowserStopHost};
use crate::download::DownloadManager;
use crate::policy::BrowserPolicySnapshot;
use crate::relay::RelayedWorkerLaunch;
use crate::safety::BrowserSafetyGate;
use crate::stream::FrameStream;
use crate::takeover::TakeoverCoordinator;

use super::control::{open_durable_control_owner, ControlInit};
use super::runtime;
use super::{
    BrowserHandle, BrowserSession, FrameWiring, SessionError, SessionLimits, SessionPhase,
    SessionTeardown, State,
};

/// Which worker transport a new session drives: the locally owned mechanism
/// through the kernel's stop authority, or the established relay to a
/// governed remote worker. Everything above the transport is shared.
enum RuntimeStart {
    Local(BrowserConfig),
    Relayed(RelayedWorkerLaunch),
}

impl BrowserSession {
    /// Launches a fresh in-memory headed runtime with no takeover holder at
    /// control revision one. Production composition uses
    /// [`Self::open_durable`]; this entry point remains for isolated mechanism
    /// fixtures that have no durable command authority. There is no default
    /// policy or safety bypass.
    pub async fn launch(
        config: BrowserConfig,
        host: BrowserStopHost,
        policy: BrowserPolicySnapshot,
        gate: Arc<BrowserSafetyGate>,
        wiring: FrameWiring,
        limits: SessionLimits,
    ) -> Result<Self, SessionError> {
        Self::launch_with_control_revision(
            RuntimeStart::Local(config),
            host,
            policy,
            gate,
            wiring,
            limits,
            ControlInit {
                initial_control_revision: 1,
                durable_control: None,
            },
        )
        .await
    }

    /// Creates or reopens the real durable BrowserArm control generation.
    /// Existing state is validated canonically, then CAS-advanced to an
    /// available coordinator before any replacement runtime launches. A prior
    /// holder, lease token, deadline, or stale writer can never survive the
    /// reopen. Fresh rows begin at control revision one.
    pub async fn open_durable(
        config: BrowserConfig,
        host: BrowserStopHost,
        policy: BrowserPolicySnapshot,
        gate: Arc<BrowserSafetyGate>,
        wiring: FrameWiring,
        limits: SessionLimits,
        ledger: Arc<StdMutex<Ledger>>,
    ) -> Result<Self, SessionError> {
        // Reject mechanism input before fencing the durable generation; the
        // runtime validates again at its process-creation boundary.
        limits.validate()?;
        config.validate()?;
        let session_id = policy.session_id();
        let (initial_control_revision, durable_control) =
            open_durable_control_owner(ledger, session_id, OffsetDateTime::now_utc())?;
        Self::launch_with_control_revision(
            RuntimeStart::Local(config),
            host,
            policy,
            gate,
            wiring,
            limits,
            ControlInit {
                initial_control_revision,
                durable_control: Some(durable_control),
            },
        )
        .await
    }

    /// Advance the control generation before attaching so old holders cannot control the replacement.
    pub async fn open_relayed(
        launch: crate::relay::RelayedWorkerLaunch,
        host: BrowserStopHost,
        policy: BrowserPolicySnapshot,
        gate: Arc<BrowserSafetyGate>,
        wiring: FrameWiring,
        limits: SessionLimits,
        ledger: Arc<StdMutex<Ledger>>,
    ) -> Result<Self, SessionError> {
        // Reject session input before fencing the durable generation.
        limits.validate()?;
        let session_id = policy.session_id();
        let (initial_control_revision, durable_control) =
            open_durable_control_owner(ledger, session_id, OffsetDateTime::now_utc())?;
        Self::launch_with_control_revision(
            RuntimeStart::Relayed(launch),
            host,
            policy,
            gate,
            wiring,
            limits,
            ControlInit {
                initial_control_revision,
                durable_control: Some(durable_control),
            },
        )
        .await
    }

    async fn launch_with_control_revision(
        start: RuntimeStart,
        host: BrowserStopHost,
        policy: BrowserPolicySnapshot,
        gate: Arc<BrowserSafetyGate>,
        wiring: FrameWiring,
        limits: SessionLimits,
        control: ControlInit,
    ) -> Result<Self, SessionError> {
        let ControlInit {
            initial_control_revision,
            durable_control,
        } = control;
        limits.validate()?;
        let (download_limits, worker_command_deadline, takeover_lease, navigate_hosts, mut runtime) =
            match start {
                RuntimeStart::Local(config) => (
                    config.limits.download,
                    config.deadlines.command,
                    config.deadlines.takeover_lease,
                    None,
                    runtime::BrowserRuntime::launch(config, host).await?,
                ),
                RuntimeStart::Relayed(launch) => (
                    launch.limits.download,
                    launch.command,
                    launch.takeover_lease,
                    launch.navigate_host_set(),
                    runtime::BrowserRuntime::launch_relayed(launch, host).await?,
                ),
            };
        let events = match runtime.take_event_stream() {
            Ok(events) => events,
            Err(error) => {
                let _ = runtime.shutdown().await;
                return Err(SessionError::Launch(format!(
                    "failed to acquire the worker event stream: {error}"
                )));
            }
        };
        let session_id = policy.session_id();
        let publisher = Arc::clone(&wiring.publisher);
        let frames = Arc::new(FrameStream::new(
            wiring.stream_id,
            session_id,
            wiring.stream,
            wiring.limits,
            Arc::clone(&publisher),
        ));
        let downloads = match DownloadManager::new(
            session_id,
            runtime.download_root().to_path_buf(),
            download_limits,
            Arc::clone(&gate),
            Arc::clone(&publisher),
        ) {
            Ok(downloads) => downloads,
            Err(error) => {
                drop(events);
                let _ = runtime.shutdown().await;
                return Err(error.into());
            }
        };
        let takeover = TakeoverCoordinator::with_lease_ttl(
            session_id,
            takeover_lease,
            OffsetDateTime::now_utc(),
        );
        let profile_id = runtime.profile_id().to_owned();
        let stream_id = wiring.stream_id;
        let mut state = State {
            phase: SessionPhase::Live,
            runtime: Some(runtime),
            policy,
            gate,
            takeover,
            takeover_lease_token: None,
            control_revision: initial_control_revision,
            durable_control,
            lease_expiry_unreported: None,
            pending: None,
            next_action_id: 1,
            limits,
            worker_command_deadline,
            frames: Arc::clone(&frames),
            downloads,
            publisher,
            stream_id,
            profile_id,
            navigate_hosts,
            opened_at: OffsetDateTime::now_utc(),
            view_revision: 0,
            view: None,
            view_unreported: false,
            page: None,
        };
        // The first bounded page observation feeds the initial public view.
        // A blank-page observation failure still launches: the view reports
        // a session without page facts rather than faking one.
        state.refresh_page_view().await;
        Ok(Self {
            events,
            state: Arc::new(Mutex::new(state)),
            frames,
            session_id,
            dropped_seen: 0,
        })
    }

    /// Cheap alias for concurrent control and read callers. Event consumption
    /// remains exclusively owned by this [`BrowserSession`].
    pub fn handle(&self) -> BrowserHandle {
        BrowserHandle {
            state: self.state.clone(),
            frames: self.frames.clone(),
            session_id: self.session_id,
        }
    }

    pub fn session_id(&self) -> BrowserSessionId {
        self.session_id
    }

    /// Bounded frame stream, safe to poll (`latest`, `counters`) without the
    /// session mutex. Admission happens only through [`Self::next_event`].
    pub fn frames(&self) -> Arc<FrameStream> {
        self.frames.clone()
    }

    /// Explicit, bounded teardown: drop the typed event receiver, stop frame
    /// production, close the Playwright page/context and JSONL channel,
    /// stop owned worker and optional Xvfb WorkerIds through StopAuthority,
    /// and only then remove the profile after authoritative absence.
    pub async fn shutdown(self) -> Result<SessionTeardown, SessionError> {
        let Self { state, events, .. } = self;
        let runtime = {
            let mut state = state.lock().await;
            state.begin_shutdown()
        };
        drop(events);
        match runtime {
            Some(runtime) => Ok(SessionTeardown::from(runtime.shutdown().await?)),
            None => Err(SessionError::Stopped),
        }
    }
}
