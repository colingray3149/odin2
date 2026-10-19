//! Headed Playwright worker, isolated profile, and display launch lifecycle.
//!
//! This is mechanism only. Launch of the worker, owned Xvfb, and correlated
//! Chromium descendants go through StopAuthority opaque WorkerIds; the exact
//! bounded teardown and its authoritative stop evidence live in
//! `runtime/stop.rs`. Policy, authorization, protected values, journal
//! state, and publication remain exclusively in the session actor. A
//! borrowed display is never launched or stopped.

use odin_kernel::stop::{CorrelationId, WorkerId};
use odin_kernel::StopAuthority;
use std::fs;
use std::future::Future;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use odin_process::{
    mint_worker_id, CommandSpec, EnvironmentBuilder, FrozenArgv, ScopeLifetime, ScopeLimits,
    WorkerNaming, CORRELATION_ENV,
};
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::time::Instant;

use crate::config::{BrowserConfig, BrowserStopHost, DisplaySource, WorkerLimits};
use crate::profile::IsolatedProfile;
use crate::relay::{RelayedStreams, RelayedWorkerLaunch, RemoteExit};
use crate::worker::{
    LaunchParams, LaunchResult, WorkerCaller, WorkerConnection, WorkerError, WorkerErrorCode,
    WorkerEventStream, WorkerMethod, WorkerStdinHandle, WorkerStdinSink, WORKER_SOURCE,
};

use super::{BrowserLaunchStage, SessionError};

use crate::display::{
    display_accepts, display_number, write_xauthority, x_lock_path, x_socket_path,
};

#[path = "runtime/stop.rs"]
mod stop;

const READINESS_POLL: Duration = Duration::from_millis(25);
const XVFB_DISPLAY_PROBES: u16 = 64;
const ARGV_ITEM_CEILING: usize = 32;
const ARGV_BYTE_CEILING: usize = 64 * 1024;
const DRAIN_CHUNK_BYTES: usize = 4096;
const DRAIN_BYTE_CEILING: u64 = 1024 * 1024;

/// Observable facts from an explicit, bounded runtime teardown.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct RuntimeTeardown {
    pub(super) profile_id: String,
    pub(super) frame_producer_stopped: bool,
    pub(super) browser_close_attempted: bool,
    pub(super) worker_channel_closed: bool,
    pub(super) worker_owned: bool,
    pub(super) worker_term_sent: bool,
    pub(super) worker_kill_sent: bool,
    pub(super) worker_reaped: bool,
    pub(super) xvfb_owned: bool,
    pub(super) xvfb_term_sent: bool,
    pub(super) xvfb_kill_sent: bool,
    pub(super) xvfb_reaped: bool,
    pub(super) profile_removed: bool,
    /// Remote exit details; local workers instead report reaping by worker id.
    pub(super) relayed_exit: Option<String>,
}

/// Live browser mechanism owned by one serialized session actor.
pub(super) struct BrowserRuntime {
    host: BrowserStopHost,
    profile: Option<IsolatedProfile>,
    worker: Option<OwnedWorker>,
    xvfb: Option<OwnedWorker>,
    owned_virtual_display: Option<u16>,
    client: Option<WorkerCaller>,
    connection: Option<WorkerConnection>,
    frame_producer_started: bool,
    browser_launched: bool,
    shutdown_timeout: Duration,
    relayed: Option<RelayedRuntimeState>,
}

/// The remote-side facts of a relayed runtime: the bounded identity the
/// session view projects, the host-side download staging root, and the
/// pending remote-exit evidence. None of it is a local process; stopping
/// the remote carrier is never this runtime's power.
struct RelayedRuntimeState {
    identity: String,
    download_root: PathBuf,
    /// The transport's one-shot remote-exit resolution. `std::sync::Mutex`
    /// exists only so the session actor's shared state satisfies its `Sync`
    /// bound: every access is already serialized by the owning session
    /// actor, and bounded teardown consumes the future exactly once through
    /// exclusive ownership. The slot is never `lock`ed, so it cannot poison.
    exit: Mutex<Option<RemoteExit>>,
}

struct OwnedWorker {
    worker_id: WorkerId,
}

impl BrowserRuntime {
    /// Validate mechanism configuration, create fresh marked storage, resolve
    /// the display, materialize the embedded script, and launch one headed,
    /// sandboxed Chromium tree correlated to its owning profile.
    pub(super) async fn launch(
        config: BrowserConfig,
        host: BrowserStopHost,
    ) -> Result<Self, SessionError> {
        config.validate()?;
        let profile = IsolatedProfile::create(&config.profile_parent)?;
        let mut runtime = Self {
            host,
            profile: Some(profile),
            worker: None,
            xvfb: None,
            owned_virtual_display: None,
            client: None,
            connection: None,
            frame_producer_started: false,
            browser_launched: false,
            shutdown_timeout: config.deadlines.shutdown,
            relayed: None,
        };
        let startup_deadline = Instant::now() + config.deadlines.startup;
        match runtime.initialize(&config, startup_deadline).await {
            Ok(()) => Ok(runtime),
            Err(error) => {
                if let Err(cleanup) = runtime.shutdown_inner().await {
                    return Err(SessionError::Launch(format!(
                        "{error}; browser cleanup failed: {cleanup}"
                    )));
                }
                Err(error)
            }
        }
    }

    /// The relay verifies remote identity; there is no local profile, display, or worker id.
    /// Closing the relay does not stop the pod. The attached stream's ready line is
    /// consumed before startup, using remote paths supplied by the host.
    pub(super) async fn launch_relayed(
        launch: RelayedWorkerLaunch,
        host: BrowserStopHost,
    ) -> Result<Self, SessionError> {
        launch
            .validate()
            .map_err(|reason| SessionError::Launch(format!("relayed launch rejected: {reason}")))?;
        let worker_limits = launch.limits.worker;
        let mut runtime = Self {
            host,
            profile: None,
            worker: None,
            xvfb: None,
            owned_virtual_display: None,
            client: None,
            connection: None,
            frame_producer_started: false,
            browser_launched: false,
            shutdown_timeout: launch.shutdown,
            relayed: None,
        };
        let startup_deadline = Instant::now() + launch.startup;
        match runtime
            .initialize_relayed(launch, worker_limits, startup_deadline)
            .await
        {
            Ok(()) => Ok(runtime),
            Err(error) => {
                if let Err(cleanup) = runtime.shutdown_inner().await {
                    return Err(SessionError::Launch(format!(
                        "{error}; browser relay cleanup failed: {cleanup}"
                    )));
                }
                Err(error)
            }
        }
    }

    /// Relayed startup: split the relay exactly once, take the handshake
    /// over its streams, drain the remote diagnostic side channel without
    /// ever letting it backpressure the protocol, and launch the remote
    /// browser against the host-composed paths.
    async fn initialize_relayed(
        &mut self,
        launch: RelayedWorkerLaunch,
        worker_limits: WorkerLimits,
        startup_deadline: Instant,
    ) -> Result<(), SessionError> {
        let RelayedStreams {
            stdin,
            stdout,
            stderr,
            exit,
        } = launch.relay.split();
        tokio::spawn(drain_relayed_stderr(stderr));
        self.relayed = Some(RelayedRuntimeState {
            identity: launch.identity.clone(),
            download_root: launch.download_staging_root.clone(),
            exit: Mutex::new(Some(exit)),
        });
        let handshake_budget =
            self.startup_budget(startup_deadline, BrowserLaunchStage::WorkerHandshake)?;
        let connection = self
            .run_startup_step(
                BrowserLaunchStage::WorkerHandshake,
                startup_deadline,
                WorkerConnection::connect(
                    WorkerStdinHandle {
                        sink: WorkerStdinSink::Relayed(stdin),
                    },
                    stdout,
                    worker_limits,
                    handshake_budget,
                ),
            )
            .await?;
        let client = connection.caller();
        self.client = Some(client.clone());
        self.connection = Some(connection);

        let launch_params = LaunchParams {
            playwright_module_root: launch.paths.playwright_module_root,
            chromium_executable: launch.paths.chromium_executable,
            user_data_dir: launch.paths.user_data_dir,
            download_root: launch.paths.download_root,
            chromium_arguments: Vec::new(),
            viewport_width: launch.viewport.width.get(),
            viewport_height: launch.viewport.height.get(),
            max_message_bytes: launch.limits.worker.max_message_bytes.get(),
            max_encoded_frame_bytes: launch.limits.frame.max_encoded_frame_bytes.get(),
            max_decoded_frame_bytes: launch.limits.frame.max_decoded_frame_bytes.get(),
            max_active_downloads: launch.limits.download.max_active_downloads.get(),
            max_download_file_bytes: launch.limits.download.max_file_bytes,
            max_download_total_bytes: launch.limits.download.max_total_bytes,
        };
        let launch_budget =
            self.startup_budget(startup_deadline, BrowserLaunchStage::BrowserLaunch)?;
        let result = self
            .run_worker_launch(
                startup_deadline,
                client.call::<_, LaunchResult>(WorkerMethod::Launch, &launch_params, launch_budget),
            )
            .await?;
        if !result.browser_launched {
            return Err(launch_stage(BrowserLaunchStage::BrowserLaunch));
        }
        self.browser_launched = true;
        if !result.frame_producer_started {
            return Err(launch_stage(BrowserLaunchStage::FrameProducerStart));
        }
        self.frame_producer_started = true;
        Ok(())
    }

    /// Cloneable caller front for all fixed page operations.
    pub(super) fn client(&self) -> &WorkerCaller {
        self.client
            .as_ref()
            .expect("a returned BrowserRuntime always has a worker caller")
    }

    /// Transfers the connection's sole bounded event consumer while retaining
    /// command, shutdown, process-tree, and profile authority.
    pub(super) fn take_event_stream(&mut self) -> Result<WorkerEventStream, WorkerError> {
        self.connection
            .as_mut()
            .expect("a returned BrowserRuntime always has a worker connection")
            .take_event_stream()
    }

    /// per-download directory admitted by the Rust DownloadManager. A
    /// relayed runtime stages on the host: remote files never enter the
    /// host staging root, so relayed downloads are typed-rejected at
    /// staging confirmation rather than admitted unscanned.
    pub(super) fn download_root(&self) -> &Path {
        match &self.relayed {
            Some(relayed) => &relayed.download_root,
            None => self.profile().download_dir(),
        }
    }

    /// Opaque identity projected to session views; never an on-disk path.
    pub(super) fn profile_id(&self) -> &str {
        match &self.relayed {
            Some(relayed) => &relayed.identity,
            None => self.profile().id(),
        }
    }

    /// Ordered bounded teardown. Profile removal is attempted only after every
    /// owned WorkerId stop proves authoritative absence. Indeterminate evidence
    /// retains the marked profile.
    pub(super) async fn shutdown(mut self) -> Result<RuntimeTeardown, SessionError> {
        self.shutdown_inner().await
    }

    async fn initialize(
        &mut self,
        config: &BrowserConfig,
        startup_deadline: Instant,
    ) -> Result<(), SessionError> {
        let (display, authority) =
            match config.display.as_ref().ok_or_else(|| {
                SessionError::Launch("headed browser has no display source".into())
            })? {
                DisplaySource::Existing {
                    display,
                    authority_file,
                } => {
                    if let Some(authority) = authority_file {
                        let metadata = fs::metadata(authority)
                            .map_err(|_| launch_stage(BrowserLaunchStage::BrowserLaunch))?;
                        if !metadata.is_file() {
                            return Err(launch_stage(BrowserLaunchStage::BrowserLaunch));
                        }
                    }
                    let number = display_number(display)
                        .map_err(|_| launch_stage(BrowserLaunchStage::BrowserLaunch))?;
                    wait_for_display(number, startup_deadline, None, None)
                        .await
                        .map_err(|_| launch_stage(BrowserLaunchStage::BrowserLaunch))?;
                    (display.clone(), authority_file.clone())
                }
                DisplaySource::Virtual {
                    xvfb_binary,
                    display_base,
                    screen,
                } => {
                    self.start_xvfb(xvfb_binary, *display_base, screen, startup_deadline)
                        .await?
                }
            };

        let worker_script = self
            .profile()
            .materialize_worker(WORKER_SOURCE)
            .map_err(|_| launch_stage(BrowserLaunchStage::WorkerSpawn))?;
        let (owned, stdout) =
            self.spawn_playwright_worker(config, &worker_script, &display, authority.as_deref())?;
        self.worker = Some(owned);
        let stdin = WorkerStdinHandle {
            sink: WorkerStdinSink::Authority {
                authority: Arc::clone(&self.host.authority),
                worker_id: self
                    .worker
                    .as_ref()
                    .expect("worker recorded before handshake")
                    .worker_id
                    .clone(),
            },
        };

        let handshake_budget =
            self.startup_budget(startup_deadline, BrowserLaunchStage::WorkerHandshake)?;
        let connection = self
            .run_startup_step(
                BrowserLaunchStage::WorkerHandshake,
                startup_deadline,
                WorkerConnection::connect(
                    stdin,
                    Box::new(stdout),
                    config.limits.worker,
                    handshake_budget,
                ),
            )
            .await?;
        let client = connection.caller();
        self.client = Some(client.clone());
        self.connection = Some(connection);

        let launch_params = LaunchParams {
            playwright_module_root: path_text(&config.playwright.module_root)
                .ok_or_else(|| launch_stage(BrowserLaunchStage::BrowserLaunch))?,
            chromium_executable: path_text(&config.chromium.binary)
                .ok_or_else(|| launch_stage(BrowserLaunchStage::BrowserLaunch))?,
            user_data_dir: path_text(self.profile().chromium_data_dir())
                .ok_or_else(|| launch_stage(BrowserLaunchStage::BrowserLaunch))?,
            download_root: path_text(self.profile().download_dir())
                .ok_or_else(|| launch_stage(BrowserLaunchStage::BrowserLaunch))?,
            chromium_arguments: config.chromium.extra_arguments.clone(),
            viewport_width: config.viewport.width.get(),
            viewport_height: config.viewport.height.get(),
            max_message_bytes: config.limits.worker.max_message_bytes.get(),
            max_encoded_frame_bytes: config.limits.frame.max_encoded_frame_bytes.get(),
            max_decoded_frame_bytes: config.limits.frame.max_decoded_frame_bytes.get(),
            max_active_downloads: config.limits.download.max_active_downloads.get(),
            max_download_file_bytes: config.limits.download.max_file_bytes,
            max_download_total_bytes: config.limits.download.max_total_bytes,
        };
        let launch_budget =
            self.startup_budget(startup_deadline, BrowserLaunchStage::BrowserLaunch)?;
        let result = self
            .run_worker_launch(
                startup_deadline,
                client.call::<_, LaunchResult>(WorkerMethod::Launch, &launch_params, launch_budget),
            )
            .await?;
        if !result.browser_launched {
            return Err(launch_stage(BrowserLaunchStage::BrowserLaunch));
        }
        self.browser_launched = true;
        if !result.frame_producer_started {
            return Err(launch_stage(BrowserLaunchStage::FrameProducerStart));
        }
        self.frame_producer_started = true;
        Ok(())
    }

    async fn run_worker_launch<F>(
        &mut self,
        startup_deadline: Instant,
        future: F,
    ) -> Result<LaunchResult, SessionError>
    where
        F: Future<Output = Result<LaunchResult, WorkerError>>,
    {
        self.check_owned_children(BrowserLaunchStage::BrowserLaunch)?;
        tokio::pin!(future);
        loop {
            let now = Instant::now();
            if now >= startup_deadline {
                self.check_owned_children(BrowserLaunchStage::BrowserLaunch)?;
                return Err(launch_stage(BrowserLaunchStage::BrowserLaunch));
            }
            let observe_at = (now + READINESS_POLL).min(startup_deadline);
            tokio::select! {
                result = &mut future => {
                    self.check_owned_children(BrowserLaunchStage::BrowserLaunch)?;
                    return result.map_err(|error| match error {
                        WorkerError::Remote {
                            code: WorkerErrorCode::FrameProducerStartFailed,
                            ..
                        } => launch_stage(BrowserLaunchStage::FrameProducerStart),
                        _ => launch_stage(BrowserLaunchStage::BrowserLaunch),
                    });
                }
                () = tokio::time::sleep_until(observe_at) => {
                    self.check_owned_children(BrowserLaunchStage::BrowserLaunch)?;
                }
            }
        }
    }

    async fn run_startup_step<T, E, F>(
        &mut self,
        stage: BrowserLaunchStage,
        startup_deadline: Instant,
        future: F,
    ) -> Result<T, SessionError>
    where
        F: Future<Output = Result<T, E>>,
    {
        self.check_owned_children(stage)?;
        tokio::pin!(future);
        loop {
            let now = Instant::now();
            if now >= startup_deadline {
                self.check_owned_children(stage)?;
                return Err(launch_stage(stage));
            }
            let observe_at = (now + READINESS_POLL).min(startup_deadline);
            tokio::select! {
                result = &mut future => {
                    self.check_owned_children(stage)?;
                    return result.map_err(|_| launch_stage(stage));
                }
                () = tokio::time::sleep_until(observe_at) => {
                    self.check_owned_children(stage)?;
                }
            }
        }
    }

    fn startup_budget(
        &mut self,
        startup_deadline: Instant,
        stage: BrowserLaunchStage,
    ) -> Result<Duration, SessionError> {
        self.check_owned_children(stage)?;
        let now = Instant::now();
        if now >= startup_deadline {
            Err(launch_stage(stage))
        } else {
            Ok(startup_deadline - now)
        }
    }

    fn check_owned_children(&mut self, stage: BrowserLaunchStage) -> Result<(), SessionError> {
        if let Some(worker) = self.worker.as_ref() {
            match self.host.authority.try_wait_worker(&worker.worker_id) {
                Ok(Some(_)) => return Err(launch_stage(BrowserLaunchStage::WorkerExited)),
                Ok(None) => {}
                Err(_) => return Err(launch_stage(stage)),
            }
        }
        if let Some(xvfb) = self.xvfb.as_ref() {
            match self.host.authority.try_wait_worker(&xvfb.worker_id) {
                Ok(Some(_)) => return Err(launch_stage(BrowserLaunchStage::XvfbExited)),
                Ok(None) => {}
                Err(_) => return Err(launch_stage(stage)),
            }
        }
        Ok(())
    }

    async fn start_xvfb(
        &mut self,
        binary: &Path,
        display_base: u16,
        screen: &str,
        startup_deadline: Instant,
    ) -> Result<(String, Option<PathBuf>), SessionError> {
        for offset in 0..XVFB_DISPLAY_PROBES {
            if Instant::now() >= startup_deadline {
                break;
            }
            let Some(number) = display_base.checked_add(offset) else {
                break;
            };
            if x_socket_path(number).exists() || x_lock_path(number).exists() {
                continue;
            }
            let xauth = write_xauthority(self.profile().xvfb_dir(), number).map_err(|source| {
                SessionError::Launch(format!(
                    "cannot write Xauthority for display :{number}: {source}"
                ))
            })?;
            let display = format!(":{number}");
            let xvfb = self.spawn_xvfb(binary, &display, screen, &xauth.path)?;
            self.xvfb = Some(xvfb);
            self.owned_virtual_display = Some(number);
            let xvfb_id = self
                .xvfb
                .as_ref()
                .expect("owned Xvfb recorded before readiness")
                .worker_id
                .clone();
            match wait_for_display(
                number,
                startup_deadline,
                Some((&self.host.authority, &xvfb_id)),
                Some(&xauth.cookie),
            )
            .await
            {
                Ok(()) => return Ok((display, Some(xauth.path))),
                Err(DisplayWaitError::Exited) => {
                    return Err(launch_stage(BrowserLaunchStage::XvfbExited));
                }
                Err(DisplayWaitError::Timeout | DisplayWaitError::Observation) => {
                    return Err(launch_stage(BrowserLaunchStage::XvfbReadiness));
                }
            }
        }
        Err(launch_stage(BrowserLaunchStage::XvfbReadiness))
    }

    fn spawn_playwright_worker(
        &self,
        config: &BrowserConfig,
        script: &Path,
        display: &str,
        authority: Option<&Path>,
    ) -> Result<(OwnedWorker, tokio::process::ChildStdout), SessionError> {
        let argv = FrozenArgv::new(
            [
                config.playwright.node_binary.as_os_str().to_owned(),
                script.as_os_str().to_owned(),
            ],
            ARGV_ITEM_CEILING,
            ARGV_BYTE_CEILING,
        )
        .map_err(|_| launch_stage(BrowserLaunchStage::WorkerSpawn))?;
        let (owned, stdout) = self.launch_owned(
            "worker",
            argv,
            Some(display),
            authority,
            Some(&self.host.worker_binding),
            BrowserLaunchStage::WorkerSpawn,
        )?;
        match tokio::process::ChildStdout::from_std(stdout) {
            Ok(stdout) => Ok((owned, stdout)),
            Err(_) => {
                let _ = self.host.authority.stop_worker(&owned.worker_id);
                Err(launch_stage(BrowserLaunchStage::WorkerSpawn))
            }
        }
    }

    fn spawn_xvfb(
        &self,
        binary: &Path,
        display: &str,
        screen: &str,
        authority: &Path,
    ) -> Result<OwnedWorker, SessionError> {
        let argv = FrozenArgv::new(
            crate::display::xvfb_argv(binary, display, screen, authority),
            ARGV_ITEM_CEILING,
            ARGV_BYTE_CEILING,
        )
        .map_err(|source| SessionError::Launch(format!("cannot freeze Xvfb argv: {source}")))?;
        let (owned, stdout) = self.launch_owned(
            "xvfb",
            argv,
            None,
            None,
            None,
            BrowserLaunchStage::XvfbReadiness,
        )?;
        drain_output(stdout);
        Ok(owned)
    }

    fn launch_owned(
        &self,
        role: &str,
        argv: FrozenArgv,
        display: Option<&str>,
        authority: Option<&Path>,
        binding: Option<&odin_process::RegisteredServiceBinding>,
        stage: BrowserLaunchStage,
    ) -> Result<(OwnedWorker, std::process::ChildStdout), SessionError> {
        let worker_id = mint_worker_id().map_err(|_| launch_stage(stage))?;
        let correlation = worker_correlation(&self.host, &worker_id, role)?;
        let naming = WorkerNaming::new(
            self.host.tx_id.clone(),
            self.host.wp_id.clone(),
            self.host.attempt,
            worker_id.clone(),
        )
        .map_err(|_| launch_stage(stage))?;
        let environment = browser_environment(self.profile(), &correlation, display, authority)?;
        let spec = CommandSpec {
            argv,
            environment,
            current_dir: self.profile().home_dir().to_path_buf(),
        };
        // Persistent mechanisms follow their proven owner, not a job timer.
        let limits = ScopeLimits {
            lifetime: ScopeLifetime::OwnerUnit,
            timeout_stop: self.shutdown_timeout,
            memory_high: None,
            memory_max: None,
            tasks_max: None,
        };
        let launch = match binding {
            Some(binding) => self.host.authority.launch_registered_service(
                naming,
                &correlation,
                &spec,
                limits,
                binding,
            ),
            None => self
                .host
                .authority
                .launch_worker(naming, &correlation, &spec, limits),
        }
        .map_err(|_| launch_stage(stage))?;
        drain_output(launch.stderr);
        Ok((OwnedWorker { worker_id }, launch.stdout))
    }

    fn profile(&self) -> &IsolatedProfile {
        self.profile
            .as_ref()
            .expect("runtime profile remains present until teardown")
    }
}

async fn wait_for_display(
    number: u16,
    deadline: Instant,
    worker: Option<(&StopAuthority, &WorkerId)>,
    cookie: Option<&[u8; 16]>,
) -> Result<(), DisplayWaitError> {
    loop {
        if let Some((authority, worker_id)) = worker.as_ref() {
            match authority.try_wait_worker(worker_id) {
                Ok(Some(_)) => return Err(DisplayWaitError::Exited),
                Ok(None) => {}
                Err(_) => return Err(DisplayWaitError::Observation),
            }
        }
        if display_accepts(number, cookie) {
            return Ok(());
        }
        let now = Instant::now();
        if now >= deadline {
            return Err(DisplayWaitError::Timeout);
        }
        tokio::time::sleep((deadline - now).min(READINESS_POLL)).await;
    }
}

#[derive(Debug)]
enum DisplayWaitError {
    Exited,
    Timeout,
    Observation,
}
fn launch_stage(stage: BrowserLaunchStage) -> SessionError {
    SessionError::LaunchStage { stage }
}

fn path_text(path: &Path) -> Option<String> {
    path.to_str().map(str::to_owned)
}

fn worker_correlation(
    host: &BrowserStopHost,
    worker_id: &WorkerId,
    role: &str,
) -> Result<CorrelationId, SessionError> {
    let material = format!(
        "{}\0{}\0{}\0{}\0{role}",
        host.tx_id,
        host.wp_id,
        host.attempt,
        worker_id.as_str()
    );
    let hex = blake3::hash(material.as_bytes()).to_hex();
    CorrelationId::new(&hex.as_str()[..32])
        .map_err(|error| SessionError::Launch(format!("cannot bind worker correlation: {error}")))
}

pub(crate) fn browser_environment(
    profile: &IsolatedProfile,
    correlation: &CorrelationId,
    display: Option<&str>,
    authority: Option<&Path>,
) -> Result<odin_process::AllowlistedEnvironment, SessionError> {
    let mut keys = vec![
        CORRELATION_ENV,
        "HOME",
        "XDG_CONFIG_HOME",
        "XDG_CACHE_HOME",
        "XDG_DATA_HOME",
        "XDG_RUNTIME_DIR",
        "TMPDIR",
        "LANG",
        "LC_ALL",
        "TZ",
        "XDG_SESSION_TYPE",
        "GDK_BACKEND",
        "GSETTINGS_BACKEND",
        "GIO_USE_VFS",
        "NO_AT_BRIDGE",
    ];
    if display.is_some() {
        keys.push("DISPLAY");
    }
    if authority.is_some() {
        keys.push("XAUTHORITY");
    }
    let mut builder = EnvironmentBuilder::new(keys)
        .map_err(|error| SessionError::Launch(format!("worker environment rejected: {error}")))?;
    builder = builder
        .set(CORRELATION_ENV, correlation.as_str())
        .and_then(|builder| builder.set("HOME", profile.home_dir().as_os_str()))
        .and_then(|builder| builder.set("XDG_CONFIG_HOME", profile.xdg_config_dir().as_os_str()))
        .and_then(|builder| builder.set("XDG_CACHE_HOME", profile.xdg_cache_dir().as_os_str()))
        .and_then(|builder| builder.set("XDG_DATA_HOME", profile.xdg_data_dir().as_os_str()))
        .and_then(|builder| builder.set("XDG_RUNTIME_DIR", profile.scratch_dir().as_os_str()))
        .and_then(|builder| builder.set("TMPDIR", profile.scratch_dir().as_os_str()))
        .and_then(|builder| builder.set("LANG", "C.UTF-8"))
        .and_then(|builder| builder.set("LC_ALL", "C.UTF-8"))
        .and_then(|builder| builder.set("TZ", "UTC"))
        .and_then(|builder| builder.set("XDG_SESSION_TYPE", "x11"))
        .and_then(|builder| builder.set("GDK_BACKEND", "x11"))
        .and_then(|builder| builder.set("GSETTINGS_BACKEND", "memory"))
        .and_then(|builder| builder.set("GIO_USE_VFS", "local"))
        .and_then(|builder| builder.set("NO_AT_BRIDGE", "1"))
        .map_err(|error| SessionError::Launch(format!("worker environment rejected: {error}")))?;
    if let Some(display) = display {
        builder = builder.set("DISPLAY", display).map_err(|error| {
            SessionError::Launch(format!("worker environment rejected: {error}"))
        })?;
    }
    if let Some(authority) = authority {
        builder = builder
            .set("XAUTHORITY", authority.as_os_str())
            .map_err(|error| {
                SessionError::Launch(format!("worker environment rejected: {error}"))
            })?;
    }
    Ok(builder.build())
}

/// Discards the relayed remote worker's diagnostic output for the transport
/// lifetime. The prefix is echoed like a local drain; afterwards the bytes
/// are read and dropped without storing, because a blocked side channel
/// would backpressure the entire relayed transport. Never allocates per
/// chunk and never drops the reader half.
pub(crate) async fn drain_relayed_stderr(mut reader: Box<dyn AsyncRead + Unpin + Send>) {
    let mut buf = [0_u8; DRAIN_CHUNK_BYTES];
    let mut total = 0_u64;
    loop {
        match reader.read(&mut buf).await {
            Ok(0) | Err(_) => return,
            Ok(count) => {
                if total < DRAIN_BYTE_CEILING {
                    eprint!("{}", String::from_utf8_lossy(&buf[..count]));
                }
                total = total.saturating_add(count as u64);
            }
        }
    }
}
fn drain_output<R: Read + Send + 'static>(mut reader: R) {
    let _ = thread::Builder::new()
        .name("odin-browser-drain".to_owned())
        .spawn(move || {
            let mut buf = [0_u8; DRAIN_CHUNK_BYTES];
            let mut total = 0_u64;
            loop {
                match reader.read(&mut buf) {
                    Ok(0) => return,
                    Ok(count) => {
                        eprint!("{}", String::from_utf8_lossy(&buf[..count]));
                        total = total.saturating_add(count as u64);
                        if total >= DRAIN_BYTE_CEILING {
                            return;
                        }
                    }
                    Err(_) => return,
                }
            }
        });
}

#[cfg(test)]
mod tests {
    use odin_domain::{StopEvidence, StopMissing, StopVerdict, WORKER_STOP_EVIDENCE_SCHEMA};
    use odin_kernel::stop::{StopOutcome, WorkerId};

    use super::stop::{process_stop_from_outcome, ProcessStop};

    fn outcome(
        verdict: StopVerdict,
        leader_reaped: bool,
        descendants: u64,
        complete: bool,
    ) -> StopOutcome {
        let evidence = StopEvidence {
            schema: WORKER_STOP_EVIDENCE_SCHEMA.to_owned(),
            worker_id: "worker".to_owned(),
            unit: "tx-wp-attempt-1-deadbeef.scope".to_owned(),
            cgroup: "/odin/tx-wp-attempt-1-deadbeef.scope".to_owned(),
            leader_reaped,
            cgroup_descendants: descendants,
            evidence_complete: complete,
            fault_probes: Vec::new(),
        };
        StopOutcome {
            worker_id: WorkerId::new("0123456789abcdef0123456789abcdef").expect("worker id"),
            verdict,
            replay: false,
            evidence,
            trace: Vec::new(),
        }
    }

    #[test]
    fn worker_teardown() {
        let stopped = process_stop_from_outcome(&outcome(StopVerdict::Stopped, true, 0, true));
        assert!(stopped.reaped);
        assert!(!stopped.term_sent);
        assert!(!stopped.kill_sent);

        let incomplete = process_stop_from_outcome(&outcome(StopVerdict::Stopped, true, 0, false));
        assert!(
            !incomplete.reaped,
            "empty or incomplete stop evidence must not look like absence"
        );

        let residue = process_stop_from_outcome(&outcome(StopVerdict::Stopped, true, 2, true));
        assert!(!residue.reaped);

        let indeterminate = process_stop_from_outcome(&outcome(
            StopVerdict::Indeterminate(StopMissing {
                reason: "manager query failed".to_owned(),
            }),
            false,
            0,
            false,
        ));
        assert!(!indeterminate.reaped);

        assert!(ProcessStop::not_owned().reaped);
        assert!(
            process_stop_from_outcome(&outcome(StopVerdict::Stopped, true, 0, true)).reaped
                && ProcessStop::not_owned().reaped
        );
        assert!(
            !indeterminate.reaped,
            "Indeterminate must retain the profile by refusing reaped"
        );
    }
}
