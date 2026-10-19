//! The pod-side browser relay supervisor: one governed pod's browser
//! container runs exactly this mechanism as its init.
//!
//! The container's PID namespace is the containment: this process is PID 1
//! (process namespace sharing is off), so its return — clean or not —
//! takes every descendant down. The crate refuses to run anywhere else.
//!
//! Accepts one activation on a private socket, starts the display and worker,
//! and bridges bytes without interpreting protocol lines. Teardown stops the
//! worker before the display; PID namespace exit kills any remaining descendants.
//!
//! Worker status and transport results determine the outcome, not select order.
//! Exit 0 requires an acknowledged `Shutdown`; EOF without acknowledgement,
//! channel errors, and panics exit 70. Success also requires clean transports.

use std::path::{Path, PathBuf};
use std::process::{ExitStatus, Stdio};
use std::time::Duration;

use odin_domain::huginn::ids::BrowserSessionId;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixListener;

use crate::config::{ensure_executable_file, valid_screen_spec};
use crate::display::{display_accepts, write_xauthority, x_lock_path, x_socket_path, xvfb_argv};
use crate::profile::IsolatedProfile;
use crate::worker::WORKER_SOURCE;

/// The supervisor must run as the container init: any other position has no
/// namespace containment, and this crate refuses the launch instead of
/// providing a weaker one.
const PID1: u32 = 1;
/// The activation preface is one short typed line on the private socket.
const ACTIVATION_MAX_BYTES: usize = 256;
/// The whole activation line must arrive within this bound of the attach.
const ACTIVATION_DEADLINE: Duration = Duration::from_secs(10);
/// The only activation version this supervisor speaks.
pub const ACTIVATION_VERSION: u32 = 1;
/// Bounded display readiness budget; the host's own startup deadline covers
/// the whole handshake on top of this.
const DISPLAY_READY_DEADLINE: Duration = Duration::from_secs(90);
/// Readiness poll, matching the locally owned runtime.
const DISPLAY_READY_POLL: Duration = Duration::from_millis(25);
/// Display numbers probed upward from the base, matching the locally owned
/// runtime's probe bound.
const DISPLAY_PROBES: u16 = 64;
/// Lowest display number probed.
const DISPLAY_BASE: u16 = 90;
/// After the worker's stdin is closed, the worker reaps within this grace
/// before the TERM/KILL ladder starts.
const WORKER_EXIT_GRACE: Duration = Duration::from_secs(10);
/// Each ladder step bound.
const LADDER_STEP: Duration = Duration::from_secs(5);
/// The orchestration poll while the bridge is healthy.
const BRIDGE_POLL: Duration = Duration::from_millis(10);

/// The typed supervisor input, every field host-composed from admitted
/// material: the pinned node and declared Xvfb of the image plan, the
/// declared screen, the per-session state dir under the plan's state mount,
/// and the container-private socket path.
#[derive(Clone, Debug)]
pub struct ServeInput {
    pub node: PathBuf,
    pub xvfb: PathBuf,
    pub screen: String,
    pub state_dir: PathBuf,
    pub socket: PathBuf,
}

/// The typed evidence of one served relay. `serve` returns `Ok` only when
/// every owned child provably reaped and the display left no residue.
#[derive(Clone, Debug)]
pub struct ServeReport {
    pub session: BrowserSessionId,
    pub display_number: u16,
    /// The worker's reaped exit status.
    pub worker_exit: Option<ExitStatus>,
    pub xvfb_reaped: bool,
    /// Probed after the owned Xvfb stop: the display socket must be gone.
    pub display_residue_absent: bool,
}

#[derive(Debug, Error)]
pub enum RelaySupervisorError {
    #[error("the browser relay must run as the container init (pid 1); refusing pid {actual}")]
    NotPid1 { actual: u32 },
    #[error("the browser relay input {0} is invalid: {1}")]
    Input(&'static str, String),
    #[error("the relay profile layout failed: {0}")]
    Layout(#[from] crate::profile::ProfileError),
    #[error("the relay socket {0:?} cannot be served: {1}")]
    Socket(PathBuf, std::io::Error),
    #[error("the activation preface is invalid: {0}")]
    Activation(String),
    #[error("the stop signals cannot be armed: {0}")]
    Signals(std::io::Error),
    #[error("the relay bridge failed: {0}")]
    Bridge(std::io::Error),
    #[error("the owned display never became ready")]
    DisplayNotReady,
    #[error("the worker cannot spawn: {0}")]
    WorkerSpawn(std::io::Error),
    #[error("the worker's exit cannot be observed: {0}")]
    WorkerWait(std::io::Error),
    #[error("the owned worker did not reap within the teardown budget")]
    WorkerNotReaped,
    #[error("the owned Xvfb did not reap within the teardown budget")]
    XvfbNotReaped,
    #[error("the display :{number} still accepts connections after the owned stop")]
    DisplayResidue { number: u16 },
    #[error("a stop signal arrived before the relay served a session")]
    SignalledBeforeServed,
    #[error("the worker exited before an acknowledged shutdown: {status}")]
    WorkerExitedUnexpectedly { status: String },
}

/// The bounded typed activation the host's connect tool sends on the
/// private socket before any protocol byte may flow: one JSON line, one
/// version, one session identity. Encoding and decoding live here so both
/// ends speak one grammar.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActivationPreface {
    pub v: u32,
    pub session: String,
}

impl ActivationPreface {
    pub fn encode(&self) -> Result<Vec<u8>, String> {
        if self.v != ACTIVATION_VERSION {
            return Err(format!(
                "activation version {} is not {ACTIVATION_VERSION}",
                self.v
            ));
        }
        let mut line = serde_json::to_vec(self)
            .map_err(|error| format!("cannot encode the activation preface: {error}"))?;
        line.push(b'\n');
        if line.len() > ACTIVATION_MAX_BYTES {
            return Err("the activation preface exceeds its bound".to_owned());
        }
        Ok(line)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, String> {
        let preface: Self = serde_json::from_slice(bytes)
            .map_err(|error| format!("not the typed activation: {error}"))?;
        if preface.v != ACTIVATION_VERSION {
            return Err(format!(
                "activation version {} is not {ACTIVATION_VERSION}",
                preface.v
            ));
        }
        Ok(preface)
    }
}

/// The armed stop signals of one supervisor lifetime: created once, held
/// through activation, readiness, bridge, and teardown — never recreated,
/// so a signal is never lost to a dropped receiver.
struct StopSignals {
    term: tokio::signal::unix::Signal,
    int: tokio::signal::unix::Signal,
    hup: tokio::signal::unix::Signal,
}

impl StopSignals {
    fn arm() -> Result<Self, RelaySupervisorError> {
        use tokio::signal::unix::{signal, SignalKind};
        Ok(Self {
            term: signal(SignalKind::terminate()).map_err(RelaySupervisorError::Signals)?,
            int: signal(SignalKind::interrupt()).map_err(RelaySupervisorError::Signals)?,
            hup: signal(SignalKind::hangup()).map_err(RelaySupervisorError::Signals)?,
        })
    }

    /// Resolves once any of the three stop signals arrives.
    async fn hit(&mut self) {
        tokio::select! {
            _ = self.term.recv() => {}
            _ = self.int.recv() => {}
            _ = self.hup.recv() => {}
        }
    }
}

/// How the healthy bridge's wait resolved. The outcome classification
/// never keys on this alone: the worker's real exit status and the
/// transports' results decide success or failure.
enum BridgeEnd {
    /// The host's half closed first; its copy task finished.
    Upstream(Transport),
    /// The worker's half closed first; its copy task finished.
    Downstream(Transport),
    /// A stop signal arrived: an orderly operator stop.
    Signalled,
    /// The worker's own wait resolved: the reaped status, or the real
    /// wait error — never a synthesized status.
    WorkerExit(std::io::Result<ExitStatus>),
}
/// Aborts every tracked drain task when dropped, after the child reaps
/// have been proven: the drains stay live while their pipes live and end
/// with them.
struct DrainGuard {
    drains: Vec<tokio::task::JoinHandle<()>>,
}

impl DrainGuard {
    fn track(&mut self, handle: tokio::task::JoinHandle<()>) {
        self.drains.push(handle);
    }
}

impl Drop for DrainGuard {
    fn drop(&mut self) {
        for handle in self.drains.drain(..) {
            handle.abort();
        }
    }
}

/// One bridge copy task's transport result: bytes carried, or the IO error
/// that ended the copy.
type Transport = std::result::Result<u64, std::io::Error>;

/// Serves exactly one relayed browser session and returns its typed
/// evidence. `Ok` means the worker exited 0 after an acknowledged
/// shutdown, both transports carried no error, every owned child provably
/// reaped, and the display left no residue. Every other ending is typed —
/// the process return takes the PID namespace down as the final kill
/// regardless.
pub async fn serve(input: ServeInput) -> Result<ServeReport, RelaySupervisorError> {
    if std::process::id() != PID1 {
        return Err(RelaySupervisorError::NotPid1 {
            actual: std::process::id(),
        });
    }
    ensure_executable_file("browser relay node", &input.node)
        .map_err(|error| RelaySupervisorError::Input("node", error.to_string()))?;
    ensure_executable_file("browser relay Xvfb", &input.xvfb)
        .map_err(|error| RelaySupervisorError::Input("xvfb", error.to_string()))?;
    if !valid_screen_spec(&input.screen) {
        return Err(RelaySupervisorError::Input(
            "screen",
            format!(
                "{:?} is not `<width>x<height>x<depth>` within the mechanism bound",
                input.screen
            ),
        ));
    }
    if !input.state_dir.is_absolute() {
        return Err(RelaySupervisorError::Input(
            "state dir",
            format!("{:?} is not absolute", input.state_dir),
        ));
    }
    if !input.socket.is_absolute() {
        return Err(RelaySupervisorError::Input(
            "socket",
            format!("{:?} is not absolute", input.socket),
        ));
    }

    let mut signals = StopSignals::arm()?;

    // Exactly one activation: bind, accept once, drop the listener. A stop
    // signal before any activation ends the supervisor typed — the PID
    // namespace teardown is the same final kill as after a served session.
    let listener = UnixListener::bind(&input.socket)
        .map_err(|error| RelaySupervisorError::Socket(input.socket.clone(), error))?;
    let (mut connection, _) = tokio::select! {
        accepted = listener.accept() => accepted.map_err(|error| {
            RelaySupervisorError::Socket(input.socket.clone(), error)
        })?,
        _ = signals.hit() => {
            return Err(RelaySupervisorError::SignalledBeforeServed);
        }
    };
    drop(listener);

    // The supervisor owns the socket file: it is removed on every exit —
    // a stale socket file would refuse any restarted serve in this path.
    struct SocketCleanup(PathBuf);
    impl Drop for SocketCleanup {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }
    let _socket_cleanup = SocketCleanup(input.socket.clone());

    let activation = read_activation(&mut connection, &mut signals).await?;
    let session = BrowserSessionId::parse(&activation.session).map_err(|_| {
        RelaySupervisorError::Activation("the session id is not a valid UUID".to_owned())
    })?;

    IsolatedProfile::ensure_serve_state_dir(&input.state_dir)?;
    let profile = IsolatedProfile::create_for_session(&input.state_dir, &session)?;
    let mut display = start_display(&input, profile.xvfb_dir(), &mut signals).await?;
    let script = profile
        .materialize_worker(WORKER_SOURCE)
        .map_err(RelaySupervisorError::Layout)?;
    let mut worker = spawn_worker(&input, &profile, &script, display.number, &session)
        .await
        .map_err(RelaySupervisorError::WorkerSpawn)?;
    let mut drains = DrainGuard { drains: Vec::new() };
    if let Some(stderr) = worker.stderr.take() {
        drains.track(tokio::spawn(crate::session::runtime::drain_relayed_stderr(
            Box::new(stderr),
        )));
    }
    if let Some(stderr) = display.child.stderr.take() {
        drains.track(tokio::spawn(crate::session::runtime::drain_relayed_stderr(
            Box::new(stderr),
        )));
    }

    // The bridge. The worker's stdin and stdout move into two tracked,
    // cancelable copy tasks; the healthy bridge waits indefinitely on
    // their joins, the worker's own exit, or a stop signal — never on a
    // timer. Only a real end starts the bounded teardown.
    let mut worker_stdin = worker
        .stdin
        .take()
        .ok_or_else(|| std::io::Error::other("the worker stdin is unavailable"))
        .map_err(RelaySupervisorError::WorkerSpawn)?;
    let mut worker_stdout = worker
        .stdout
        .take()
        .ok_or_else(|| std::io::Error::other("the worker stdout is unavailable"))
        .map_err(RelaySupervisorError::WorkerSpawn)?;
    let (mut socket_read, mut socket_write) = tokio::io::split(connection);
    let mut upstream = tokio::spawn(async move {
        let copied = tokio::io::copy(&mut socket_read, &mut worker_stdin).await;
        // Dropping the worker's stdin is the graceful remote stop.
        let _ = worker_stdin.shutdown().await;
        copied
    });
    let mut downstream = tokio::spawn(async move {
        let copied = tokio::io::copy(&mut worker_stdout, &mut socket_write).await;
        let _ = socket_write.shutdown().await;
        copied
    });

    // One coherent wait over the healthy bridge: the two copy joins, the
    // worker's own reaped exit, or a stop signal — never a timer while the
    // bridge is healthy. The reaped status and the retained transport
    // results decide the verdict, never which arm woke first.
    let ended = tokio::select! {
        outcome = &mut upstream => BridgeEnd::Upstream(outcome.unwrap_or_else(|join| {
            Err(std::io::Error::other(join.to_string()))
        })),
        outcome = &mut downstream => BridgeEnd::Downstream(outcome.unwrap_or_else(|join| {
            Err(std::io::Error::other(join.to_string()))
        })),
        status = worker.wait() => BridgeEnd::WorkerExit(status),
        _ = signals.hit() => BridgeEnd::Signalled,
    };

    // Await cancellation to close stdin before reaping, without polling a completed join twice.
    if !matches!(ended, BridgeEnd::Upstream(..)) {
        upstream.abort();
        let _ = upstream.await;
    }

    // Only WorkerExit(Ok) has reaped the child; all other outcomes still require stop/reap.
    let worker_exit = match &ended {
        BridgeEnd::WorkerExit(Ok(status)) => Some(*status),
        _ => stop_worker(&mut worker).await,
    };
    let Some(worker_exit) = worker_exit else {
        if let BridgeEnd::WorkerExit(Err(error)) = &ended {
            return Err(RelaySupervisorError::WorkerWait(clone_io_error(error)));
        }
        return Err(RelaySupervisorError::WorkerNotReaped);
    };
    let xvfb_reaped = ladder(&mut display.child).await.is_some();
    if !xvfb_reaped {
        return Err(RelaySupervisorError::XvfbNotReaped);
    }
    let display_residue_absent = !display_accepts(display.number, None);
    if !display_residue_absent {
        return Err(RelaySupervisorError::DisplayResidue {
            number: display.number,
        });
    }

    // The worker's final stdout is drained with a bounded deadline — the
    // downstream is cancelled only after the reaps are proven, so the host
    // observes the worker's real ending before anything is torn down. A
    // stream that never drains is a typed failure, never a silent Ok.
    let downstream_transport = match &ended {
        BridgeEnd::Downstream(outcome) => {
            Some(outcome.as_ref().map(|bytes| *bytes).map_err(clone_io_error))
        }
        _ => match tokio::time::timeout(LADDER_STEP, &mut downstream).await {
            Ok(outcome) => {
                Some(outcome.unwrap_or_else(|join| Err(std::io::Error::other(join.to_string()))))
            }
            Err(_) => {
                downstream.abort();
                let _ = downstream.await;
                None
            }
        },
    };
    // Drains stop last, after the reaps; the guard's drop aborts them.
    drop(drains);

    if let BridgeEnd::Upstream(Err(error)) = &ended {
        return Err(RelaySupervisorError::Bridge(clone_io_error(error)));
    }
    if let Some(Err(error)) = downstream_transport {
        return Err(RelaySupervisorError::Bridge(error));
    }
    if worker_exit.code() != Some(0) {
        return Err(RelaySupervisorError::WorkerExitedUnexpectedly {
            status: worker_exit.to_string(),
        });
    }
    if downstream_transport.is_none() {
        return Err(RelaySupervisorError::Bridge(std::io::Error::other(
            "the final downstream drain did not end within its bound",
        )));
    }
    Ok(ServeReport {
        session,
        display_number: display.number,
        worker_exit: Some(worker_exit),
        xvfb_reaped,
        display_residue_absent,
    })
}

/// Clones a transport result for the typed error paths (`io::Error` is not
/// `Clone`).
fn clone_io_error(error: &std::io::Error) -> std::io::Error {
    std::io::Error::other(error.to_string())
}

/// Reads the bounded typed activation: the WHOLE line arrives within one
/// deadline, the bound is checked before every byte is pushed, a stop
/// signal preempts it, and the preface is never forwarded to the protocol
/// channel.
async fn read_activation(
    connection: &mut (impl AsyncRead + Unpin + Send),
    signals: &mut StopSignals,
) -> Result<ActivationPreface, RelaySupervisorError> {
    tokio::time::timeout(ACTIVATION_DEADLINE, async move {
        tokio::select! {
            line = activation_line(connection) => line,
            _ = signals.hit() => Err(RelaySupervisorError::SignalledBeforeServed),
        }
    })
    .await
    .map_err(|_| RelaySupervisorError::Activation("the preface timed out".to_owned()))?
}

async fn activation_line(
    connection: &mut (impl AsyncRead + Unpin + Send),
) -> Result<ActivationPreface, RelaySupervisorError> {
    let mut buffered = Vec::new();
    let mut byte = [0_u8; 1];
    loop {
        let read = connection
            .read(&mut byte)
            .await
            .map_err(|_| RelaySupervisorError::Activation("the preface read failed".to_owned()))?;
        if read == 0 {
            return Err(RelaySupervisorError::Activation(
                "the preface ended without a line".to_owned(),
            ));
        }
        if byte[0] == b'\n' {
            return ActivationPreface::decode(&buffered).map_err(RelaySupervisorError::Activation);
        }
        if buffered.len() + read > ACTIVATION_MAX_BYTES {
            return Err(RelaySupervisorError::Activation(
                "the preface exceeds its bound".to_owned(),
            ));
        }
        buffered.push(byte[0]);
    }
}

/// One owned display: the number it serves and the live Xvfb child.
struct OwnedDisplay {
    number: u16,
    child: tokio::process::Child,
}

/// Starts the owned Xvfb on a probed display: the shared authority record,
/// the shared argv, and the authenticated readiness probe within a bounded
/// budget. A stop signal preempts the readiness wait; a display that dies
/// before readiness is skipped and its kill is proven reaped within a
/// bound, never awaited blind.
async fn start_display(
    input: &ServeInput,
    xvfb_dir: &Path,
    signals: &mut StopSignals,
) -> Result<OwnedDisplay, RelaySupervisorError> {
    let deadline = tokio::time::Instant::now() + DISPLAY_READY_DEADLINE;
    for offset in 0..DISPLAY_PROBES {
        let Some(number) = DISPLAY_BASE.checked_add(offset) else {
            break;
        };
        if x_socket_path(number).exists() || x_lock_path(number).exists() {
            continue;
        }
        let authority = write_xauthority(xvfb_dir, number)
            .map_err(|_| RelaySupervisorError::DisplayNotReady)?;
        let mut argv = xvfb_argv(
            &input.xvfb,
            &format!(":{number}"),
            &input.screen,
            &authority.path,
        );
        let program = argv.remove(0);
        let mut child = tokio::process::Command::new(program)
            .args(argv)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|_| RelaySupervisorError::DisplayNotReady)?;
        if let Some(stderr) = child.stderr.take() {
            let drain = crate::session::runtime::drain_relayed_stderr(Box::new(stderr));
            tokio::spawn(drain);
        }
        loop {
            if display_accepts(number, Some(&authority.cookie)) {
                return Ok(OwnedDisplay { number, child });
            }
            if let Ok(Some(_)) = child.try_wait() {
                break;
            }
            if tokio::time::Instant::now() >= deadline {
                let _ = child.start_kill();
                if !reap_bounded(&mut child, LADDER_STEP).await {
                    return Err(RelaySupervisorError::DisplayNotReady);
                }
                break;
            }
            tokio::select! {
                _ = tokio::time::sleep(DISPLAY_READY_POLL) => {}
                _ = signals.hit() => {
                    let _ = child.start_kill();
                    let _ = reap_bounded(&mut child, LADDER_STEP).await;
                    return Err(RelaySupervisorError::SignalledBeforeServed);
                }
            }
        }
    }
    Err(RelaySupervisorError::DisplayNotReady)
}

/// Spawns the pinned node over the profile-materialized worker. The
/// environment is the allowlisted browser environment the locally owned
/// runtime builds — nothing is inherited from the container beyond it. The
/// correlation is the session's own UUID identity, not a second scheme.
async fn spawn_worker(
    input: &ServeInput,
    profile: &IsolatedProfile,
    script: &Path,
    display_number: u16,
    session: &BrowserSessionId,
) -> Result<tokio::process::Child, std::io::Error> {
    let correlation =
        odin_kernel::stop::CorrelationId::new(session.as_uuid().simple().to_string().as_str())
            .map_err(|error| std::io::Error::other(error.to_string()))?;
    let display_name = format!(":{display_number}");
    let authority_path = profile
        .xvfb_dir()
        .join(format!("Xauthority-{display_number}"));
    let environment = crate::session::runtime::browser_environment(
        profile,
        &correlation,
        Some(display_name.as_str()),
        Some(authority_path.as_path()),
    )
    .map_err(|error| std::io::Error::other(error.to_string()))?;
    let mut command = tokio::process::Command::new(&input.node);
    command
        .arg(script)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .current_dir(profile.home_dir())
        .env_clear();
    for (key, value) in environment.iter() {
        command.env(key, value);
    }
    command.spawn()
}

/// The bounded worker stop once its stdin is closed: reap within the
/// grace, then the ladder proves TERM/KILL reap. `Some(status)` only when
/// provably reaped — a signal death still carries a status.
async fn stop_worker(worker: &mut tokio::process::Child) -> Option<ExitStatus> {
    let deadline = tokio::time::Instant::now() + WORKER_EXIT_GRACE;
    while tokio::time::Instant::now() < deadline {
        match worker.try_wait() {
            Ok(Some(status)) => return Some(status),
            Ok(None) => {}
            Err(_) => return None,
        }
        tokio::time::sleep(BRIDGE_POLL).await;
    }
    ladder(worker).await
}

/// TERM within the step bound, then KILL within another. `Some(status)`
/// only when the child provably reaped; every wait is bounded.
async fn ladder(child: &mut tokio::process::Child) -> Option<ExitStatus> {
    if let Ok(Some(status)) = child.try_wait() {
        return Some(status);
    }
    if let Some(pid) = child.id() {
        if let Some(pid) = rustix::process::Pid::from_raw(i32::try_from(pid).ok()?) {
            let _ = rustix::process::kill_process(pid, rustix::process::Signal::TERM);
        }
    }
    if !reap_bounded(child, LADDER_STEP).await {
        let _ = child.start_kill();
        if !reap_bounded(child, LADDER_STEP).await {
            return None;
        }
    }
    child.try_wait().ok().flatten()
}

/// Bounded reap poll: `try_wait` never blocks; the wait sleeps through the
/// async timer so the surrounding runtime is never stalled.
async fn reap_bounded(child: &mut tokio::process::Child, budget: Duration) -> bool {
    let deadline = tokio::time::Instant::now() + budget;
    loop {
        if let Ok(Some(_)) = child.try_wait() {
            return true;
        }
        if tokio::time::Instant::now() >= deadline {
            return false;
        }
        tokio::time::sleep(BRIDGE_POLL).await;
    }
}
