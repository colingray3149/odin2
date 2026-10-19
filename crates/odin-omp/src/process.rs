//! Trusted OMP process boundary: exactly one `omp --mode rpc` worker.
//!
//! [`OmpProcess`] supervises one pinned-OMP child launched exclusively through
//! [`odin_kernel::StopAuthority`]. There is no direct `Command` spawn, no
//! process-group authority, and no PID/PGID/unit stop. The host
//! supplies a registered [`OmpWorkerLaunch`] (StopAuthority, correlation,
//! transaction-qualified naming, compiled service binding, and scope limits).
//! `--mode rpc` is appended by the host at one composition point
//! (`OmpProcessSpec::launch_args`), which the local spawn and the remote
//! attach both consume; caller args may not set it. Stdout
//! and stderr pipes stay here; stdin writes, waits, and stop go through
//! logical [`odin_types::WorkerId`] methods on StopAuthority.
//!
//! Framing retains raw bytes with bounded allocation. Stdout is read one exact
//! newline-terminated physical frame at a time — never an unbounded `read_until` —
//! capped at [`crate::frames::MAX_FRAME_BYTES`] before any buffer grows, and handed as raw bytes
//! to [`RpcFrameDecoder::push_physical_line`]. Stderr is drained continuously into
//! a bounded tail, so a full pipe can never deadlock the child; the tail is only
//! exposed through explicit exit observation and is never logged.
//!
//! Startup consumes the exact `ready` frame, validates the v1/current supported
//! list and both advertised limits, then performs the fixed prefer-v2 negotiation
//! under [`NEGOTIATE_REQUEST_ID`]; the decoder upgrades only after the v1 response
//! matches id, command, success, and data. The pinned client may
//! interleave auxiliary frames (extension UI requests, session updates) inside
//! the negotiation window: they are retained in arrival order — bounded in count
//! and bytes, never discarded — until the exact id+command response arrives; any
//! other response fails startup. A startup that fails after the ready
//! frame — timeout, EOF, mismatch, or the auxiliary ceiling — moves the
//! retained ready frame, the in-cap auxiliary window, and the offending
//! decoded response into [`OmpProcessError::StartupFailed`] before the
//! worker is stopped, so the rejection stays reconstructable from bounded
//! typed evidence after the child is gone. Chunk frames arriving before that
//! upgrade fail as protocol violations. Every operation validates the current
//! [`OmpLifecycleState`] and fails with a typed error instead of resetting any
//! state implicitly.
//!
//! Per-lane supervision — journal ownership, lease exclusion, restart policy —
//! lives above this module; this module owns exactly one logical worker.

use std::fmt;
use std::io;
use std::path::PathBuf;
use std::process::ExitStatus;
use std::sync::atomic::AtomicU32;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use odin_kernel::StopAuthority;
use odin_ledger::stop::JobStopAction;
use odin_process::{RegisteredServiceBinding, ScopeLimits};
use odin_types::{CorrelationId, WorkerId};
use thiserror::Error;
use tokio::io::{AsyncRead, BufReader};
use tokio::task::JoinHandle;

use crate::frames::{DecodedRpcFrame, RpcFrameDecoder, RpcFrameError, RpcProtocolVersion};

mod launch;
mod lifecycle;
mod remote;
mod sandbox;
mod startup;
mod streams;

pub use launch::governed_harness_args;
#[cfg(test)]
pub(crate) use launch::{launch_for_fixture, launch_with_ledger_for_fixture};
pub(crate) use lifecycle::{DRAIN_BYTE_CAP, DRAIN_FRAME_CAP};
pub use remote::{
    HarnessStdin, RemoteAttachError, RemoteExit, RemoteExitWait, RemoteHarnessAdmission,
    RemoteHarnessChannel, RemoteHarnessFactory,
};
pub use sandbox::{
    apply_seat_sandbox, resolve_sandbox_paths, sandbox_host_from_env, seat_sandbox_argv,
    shell_wrapper_script, SandboxSubject, SeatSandboxHost, SeatSandboxProfile, SYSTEM_PROMPT_FILE,
};
pub use startup::NEGOTIATE_REQUEST_ID;
pub(crate) use streams::async_pipe;

use streams::{snapshot_tail, PhysicalLineState};

#[cfg(test)]
mod tests;

/// Configuration must come from the host, never model or peer input.
/// The child inherits no environment; `explicit_env` supplies all values.
/// `OmpProcessSpec::launch_args` appends `--mode rpc`, so `explicit_args`
/// must not set a mode.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OmpProcessSpec {
    /// Trusted OMP executable; canonicalized and validated before use.
    pub executable: PathBuf,
    /// Existing working directory for the child.
    pub cwd: PathBuf,
    /// Complete argument list, excluding the host-supplied run mode.
    pub explicit_args: Vec<String>,
    /// Complete environment; nothing is inherited.
    pub explicit_env: Vec<(String, String)>,
    /// Exact pinned OMP source revision this executable is configured to be.
    pub expected_source_revision: String,
    /// Timeout for the whole startup handshake, including the `--version` probe.
    pub startup_timeout: Duration,
    /// Timeout for the stdin-close-to-EOF drain and the wait after stdout EOF.
    pub drain_timeout: Duration,
    pub kill_timeout: Duration,
}

/// The channel inside [`StopAuthority`] comes from validated config plus the
/// compiled executable map. This type never discovers a bus or program through
/// the ambient environment or PATH.
#[derive(Clone)]
pub struct OmpWorkerLaunch {
    /// Sole kernel launch and stop authority.
    pub authority: Arc<StopAuthority>,
    /// Durable correlation echoed into the payload environment.
    pub correlation_id: CorrelationId,
    /// Transaction id component of the transient unit name.
    pub tx_id: String,
    /// Work-package id component of the transient unit name.
    pub wp_id: String,
    attempt: Arc<AtomicU32>,
    /// Compiled registered-service binding for the pinned executable.
    pub binding: RegisteredServiceBinding,
    /// Scope limits applied at launch.
    pub limits: ScopeLimits,
    #[cfg(test)]
    _test_fixture: Option<Arc<odin_process::test_support::RegisteredWorkerFixture>>,
}

/// Canonical executable path and its reported version and source revision.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OmpExecutableIdentity {
    canonical_path: PathBuf,
    source_revision: String,
    version: String,
}

/// The only legal walk is `Stopped -> StartingV1 -> NegotiatingV2 ->
/// Ready(_) -> Draining -> Exited`; `Ready(V1)` is reached directly when the
/// ready frame does not advertise v2. Every operation validates the current
/// state and fails with [`OmpProcessError::InvalidTransition`] rather than
/// resetting anything implicitly.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OmpLifecycleState {
    /// Constructed but never launched.
    Stopped,
    /// Child spawned; consuming the exact `ready` frame under protocol v1.
    StartingV1,
    /// `ready` validated; the fixed prefer-v2 negotiation is in flight.
    NegotiatingV2,
    /// Handshake complete; frames flow at the negotiated protocol.
    Ready(RpcProtocolVersion),
    /// Stdin closed; stdout is being drained to EOF.
    Draining,
    /// Terminal; the exact exit record is retained.
    Exited,
}

impl fmt::Display for OmpLifecycleState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Stopped => f.write_str("stopped"),
            Self::StartingV1 => f.write_str("starting(v1)"),
            Self::NegotiatingV2 => f.write_str("negotiating(v2)"),
            Self::Ready(protocol) => write!(f, "ready(v{})", protocol.number()),
            Self::Draining => f.write_str("draining"),
            Self::Exited => f.write_str("exited"),
        }
    }
}

/// Exact terminal evidence of one child process.
#[derive(Clone, Debug)]
pub struct OmpExitRecord {
    status: Option<ExitStatus>,
    stderr_tail: Vec<u8>,
    unfinished: Option<RpcFrameError>,
    remote: Option<OmpRemoteExit>,
}

impl OmpExitRecord {
    /// The exit status, when the process manager supplied one.
    pub fn status(&self) -> Option<ExitStatus> {
        self.status
    }

    /// Whether the process exited or the remote job stop completed.
    pub fn termination_proven(&self) -> bool {
        self.status.is_some() || self.remote.as_ref().is_some_and(OmpRemoteExit::clean)
    }

    pub fn success(&self) -> bool {
        self.status.as_ref().is_some_and(ExitStatus::success)
    }

    /// `None` when the child was killed by a signal or no status was supplied.
    pub fn code(&self) -> Option<i32> {
        self.status.as_ref().and_then(ExitStatus::code)
    }

    /// The killing signal on unix, when the child did not exit normally.
    #[cfg(unix)]
    pub fn signal(&self) -> Option<i32> {
        self.status
            .as_ref()
            .and_then(std::os::unix::process::ExitStatusExt::signal)
    }

    pub fn stderr_tail(&self) -> &[u8] {
        &self.stderr_tail
    }

    pub fn stderr_tail_lossy(&self) -> String {
        String::from_utf8_lossy(&self.stderr_tail).into_owned()
    }

    /// The v2 chunk sequence interrupted by stdout EOF, retained with its raw
    /// chunk evidence; `None` when the decoder ended cleanly or the child was
    /// killed before EOF.
    pub fn unfinished_sequence(&self) -> Option<&RpcFrameError> {
        self.unfinished.as_ref()
    }
}

// Remote exit status is absent when the job was stopped through the backend.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OmpRemoteExit {
    status: Option<i32>,
    clean: bool,
    failure: Option<String>,
}

impl OmpRemoteExit {
    pub(crate) fn from_transport(exit: RemoteExit) -> Self {
        Self {
            status: exit.status,
            clean: exit.clean,
            failure: exit.failure,
        }
    }

    pub(crate) fn stopped() -> Self {
        Self {
            status: None,
            clean: true,
            failure: None,
        }
    }

    /// The transport-reported exit status, when the channel carried one.
    pub fn status(&self) -> Option<i32> {
        self.status
    }

    /// Whether the carrier exited or its job stop completed.
    pub fn clean(&self) -> bool {
        self.clean
    }

    /// The exact transport failure when the channel broke without status.
    pub fn failure(&self) -> Option<&str> {
        self.failure.as_deref()
    }
}

impl fmt::Display for OmpExitRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.status {
            Some(status) => write!(f, "exit status: {status}")?,
            None => f.write_str("exit status unobservable")?,
        }
        if let Some(remote) = &self.remote {
            write!(
                f,
                "carrier exit {}",
                match (remote.status, remote.clean) {
                    (Some(code), _) => format!("status {code}"),
                    (None, true) => "closed cleanly".to_owned(),
                    (None, false) => "closed without status".to_owned(),
                }
            )?;
            if let Some(failure) = &remote.failure {
                write!(f, "; {failure}")?;
            }
        }
        if let Some(unfinished) = &self.unfinished {
            write!(f, "; {}", unfinished.kind())?;
        }
        write!(
            f,
            "; stderr: {}",
            String::from_utf8_lossy(&self.stderr_tail)
        )
    }
}

/// Frames drained plus the exact exit record of a graceful stop.
#[derive(Clone, Debug)]
pub struct OmpShutdown {
    frames: Vec<DecodedRpcFrame>,
    exit: OmpExitRecord,
}

impl OmpShutdown {
    /// Frames the child emitted after stdin was closed, in arrival order.
    pub fn frames(&self) -> &[DecodedRpcFrame] {
        &self.frames
    }

    pub fn exit(&self) -> &OmpExitRecord {
        &self.exit
    }

    pub fn into_parts(self) -> (Vec<DecodedRpcFrame>, OmpExitRecord) {
        (self.frames, self.exit)
    }
}

/// Every variant retains the evidence needed to act on it: frame rejections
/// carry the decoder's exact physical bytes, startup failures carry the
/// bounded stderr tail plus the ordered retained startup frames, and EOF
/// carries the full exit record.
#[derive(Debug, Error)]
pub enum OmpProcessError {
    /// The trusted launch description is malformed or self-contradictory.
    #[error("invalid omp process spec: {detail}")]
    InvalidSpec {
        /// What the validation rejected.
        detail: String,
    },
    /// The trusted executable does not resolve to an executable regular file.
    #[error("trusted omp executable is unusable: {path}: {detail}")]
    ExecutableUnavailable {
        /// The path that failed validation.
        path: PathBuf,
        /// Why it is unusable.
        detail: String,
    },
    /// The bounded `--version` identity probe failed.
    #[error("omp --version probe failed: {detail}")]
    VersionProbe {
        /// What failed: spawn, timeout, oversize, non-zero exit, or encoding.
        detail: String,
        /// Bounded exact stderr of the probe child.
        stderr_tail: Vec<u8>,
    },
    /// The child could not be spawned.
    #[error("spawning the omp child failed: {detail}")]
    SpawnFailed {
        /// The operating-system error.
        detail: String,
    },
    /// The startup handshake exceeded the configured startup timeout.
    #[error("omp startup exceeded the configured startup timeout")]
    StartupTimeout,
    /// A startup failure with the bounded evidence retained at failure time.
    #[error("omp startup failed: {inner}")]
    StartupFailed {
        /// The underlying startup failure; never replaced by cleanup
        /// evidence, so the rejection itself is always reconstructable.
        #[source]
        inner: Box<OmpProcessError>,
        /// Bounded exact stderr at failure time.
        stderr_tail: Vec<u8>,
        /// Validated ready frame, auxiliary frames, and rejected negotiation
        /// response in arrival order. [`OmpProcessError::StartupAuxLimit`]
        /// retains its own window instead, avoiding duplicate retention.
        startup_frames: Vec<DecodedRpcFrame>,
        /// Cleanup failure, or `None` when the failed-startup child was stopped.
        cleanup: Option<Box<OmpProcessError>>,
    },
    /// Stdout reached EOF; the exact exit record is retained, including any
    /// chunk sequence the EOF interrupted.
    /// Inside the startup negotiation window it is the inner evidence of
    /// [`OmpProcessError::StartupFailed`].
    #[error("omp stdout closed: {exit}")]
    StdoutClosed {
        /// Boxed to avoid inflating every `Result<_, OmpProcessError>`.
        exit: Box<OmpExitRecord>,
    },
    /// The first stdout frame violates the exact ready contract.
    #[error("stdout startup frame violates the ready contract: {detail}")]
    InvalidReadyFrame {
        /// What the validation rejected.
        detail: String,
        /// Exact physical bytes including newlines.
        lines: Vec<Vec<u8>>,
    },
    /// A startup-window frame that is not a response at all, or a response
    /// naming an unexpected command, arrived where the exact negotiation
    /// response completes startup.
    #[error("unexpected stdout frame during startup: {detail}")]
    UnexpectedStartupFrame {
        /// What was expected instead.
        detail: String,
        /// Exact physical bytes including newlines.
        lines: Vec<Vec<u8>>,
    },
    /// The negotiation response does not match the deterministic request.
    #[error("protocol negotiation mismatch: {detail}")]
    NegotiationMismatch {
        /// Which field mismatched.
        detail: String,
        /// Exact physical bytes including newlines.
        lines: Vec<Vec<u8>>,
    },
    /// Auxiliary startup frames crossed their retained-evidence ceiling
    /// before the exact negotiation response arrived. `frames` stays within
    /// both configured caps; `overflow` is the exact first frame that would
    /// cross one of them.
    #[error(
        "startup auxiliary frames crossed their retained-evidence ceiling after {} frame(s) and {bytes} byte(s)",
        .frames.len()
    )]
    StartupAuxLimit {
        /// In-cap auxiliary frames retained before the ceiling was crossed.
        frames: Vec<DecodedRpcFrame>,
        /// Logical bytes in `frames`.
        bytes: usize,
        /// Exact first frame outside the retained window.
        overflow: Box<DecodedRpcFrame>,
    },
    /// A stdout frame exceeded the transport ceiling before allocation.
    #[error(
        "physical stdout frame of {size} bytes exceeded the transport ceiling before allocation"
    )]
    PhysicalFrameTooLarge {
        /// Exact physical byte count including the terminator when one
        /// arrived; the count at EOF otherwise.
        size: usize,
    },
    /// The decoder rejected a frame; the exact physical evidence is inside.
    #[error("rpc frame rejected: {0}")]
    FrameRejected(RpcFrameError),
    /// A stdin write failed; stdin is closed because partial bytes cannot
    /// recover JSONL framing.
    #[error("stdin write failed: {detail}")]
    StdinBroken {
        /// The operating-system error.
        detail: String,
    },
    /// A stdin write exceeded its bound; stdin is closed.
    #[error("stdin write of a {size}-byte frame exceeded its bound; stdin closed")]
    SendTimeout {
        /// The frame size including the newline.
        size: usize,
    },
    /// A request exceeds the unchunked stdin ceiling and was not written.
    #[error("request of {size} bytes exceeds the unchunked stdin ceiling")]
    RequestTooLarge {
        /// The request size including the newline.
        size: usize,
    },
    /// A request frame could not be serialized.
    #[error("request frame is not serializable json: {detail}")]
    RequestNotSerializable {
        /// The serialization error.
        detail: String,
    },
    /// The operation is not legal in the current lifecycle state.
    #[error("invalid lifecycle transition: {operation} is not valid from {from}")]
    InvalidTransition {
        /// The rejected operation.
        operation: &'static str,
        /// The state it was rejected from.
        from: OmpLifecycleState,
    },
    /// The graceful drain exceeded its bound; the frames read so far are
    /// retained and the child is left for the caller to kill or drop.
    #[error("graceful drain exceeded the configured drain timeout; {} frame(s) retained", .frames.len())]
    DrainTimeout {
        /// Frames read before the deadline.
        frames: Vec<DecodedRpcFrame>,
    },
    /// The graceful drain crossed its retained-evidence ceiling. `frames`
    /// stays within both configured caps; `overflow` is the exact first frame
    /// that would cross one of them.
    #[error(
        "graceful drain crossed its retained-evidence ceiling after {} frame(s) and {bytes} byte(s)",
        .frames.len()
    )]
    DrainLimit {
        /// In-cap frames retained before the ceiling was crossed.
        frames: Vec<DecodedRpcFrame>,
        /// Logical bytes in `frames`.
        bytes: usize,
        /// Exact first frame outside the retained window.
        overflow: Box<DecodedRpcFrame>,
    },
    /// StopAuthority has not confirmed termination. The worker remains
    /// nonterminal so a later `kill` can continue the stop.
    #[error(
        "omp process tree cleanup remains unconfirmed (root reaped: {root_reaped}, worker: {worker_id}): {detail}"
    )]
    ReapIncomplete {
        /// Whether the root child has already yielded an exact exit status.
        root_reaped: bool,
        /// The logical worker still tracked by StopAuthority.
        worker_id: String,
        /// The wait/probe failure, timeout, or stop-verdict evidence.
        detail: String,
    },
    /// An operating-system error while reading stdout.
    #[error("stdout read failed: {0}")]
    Io(#[from] io::Error),
}

/// A read failure that already consumed stream bytes; replayed for every
/// subsequent read because the decoder cannot resynchronize.
#[derive(Clone, Debug)]
enum ReadPoison {
    FrameRejected(RpcFrameError),
}

impl From<ReadPoison> for OmpProcessError {
    fn from(poison: ReadPoison) -> Self {
        match poison {
            ReadPoison::FrameRejected(error) => OmpProcessError::FrameRejected(error),
        }
    }
}

/// One supervised OMP harness carrier, launched and stopped only through
/// StopAuthority: locally as a registered child, remotely as a host-admitted
/// exec channel over the workload's confined pod.
///
/// The single reader is the owner of this value: exactly one task should call
/// [`OmpProcess::next_frame`] or [`OmpProcess::graceful_stop`] at a time, and
/// every frame read flows to that caller. The partially read physical frame is
/// the only internal buffer: it persists across calls so a cancelled read loses
/// no consumed bytes.
pub struct OmpProcess {
    spec: OmpProcessSpec,
    worker: OmpWorkerLaunch,
    state: OmpLifecycleState,
    /// RPC framing, handshake, and draining are identical for both transports.
    carrier: HarnessCarrier,
    /// The local worker id; remote jobs are stored in the carrier.
    worker_id: Option<WorkerId>,
    /// The stdin half, transport-uniform: local authority writes or the
    /// supplied remote channel writer.
    stdin: Option<Box<dyn HarnessStdin>>,
    stdout: Option<BufReader<Box<dyn AsyncRead + Unpin + Send>>>,
    line_state: PhysicalLineState,
    stderr_task: Option<JoinHandle<()>>,
    stderr_tail: Arc<Mutex<Vec<u8>>>,
    decoder: RpcFrameDecoder,
    ready_frame: Option<DecodedRpcFrame>,
    negotiation_frame: Option<DecodedRpcFrame>,
    startup_aux_frames: Vec<DecodedRpcFrame>,
    exit_record: Option<OmpExitRecord>,
    pending_status: Option<ExitStatus>,
    pending_unfinished: Option<RpcFrameError>,
    /// The one-shot remote terminal-status waiter; taken exactly once after
    /// stdout EOF.
    remote_exit_waiter: Option<RemoteExitWait>,
    poison: Option<ReadPoison>,
}

/// The carrier underpinning one supervised harness.
#[derive(Debug)]
enum HarnessCarrier {
    /// The registered local child: authority stdin/stop, `ExitStatus` reaps.
    Local,
    Remote {
        job_worker: WorkerId,
        stop_action: JobStopAction,
    },
}

impl fmt::Debug for OmpProcess {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OmpProcess")
            .field("state", &self.state)
            .field("worker_id", &self.worker_id)
            .field(
                "remote",
                &matches!(self.carrier, HarnessCarrier::Remote { .. }),
            )
            .finish_non_exhaustive()
    }
}

impl OmpProcess {
    /// The trusted spec this child was launched from.
    pub fn spec(&self) -> &OmpProcessSpec {
        &self.spec
    }

    /// The current lifecycle state.
    pub fn state(&self) -> OmpLifecycleState {
        self.state
    }

    /// The logical worker id, `None` before launch, for a remote carrier,
    /// or after a proved stop.
    pub fn worker_id(&self) -> Option<&WorkerId> {
        self.worker_id.as_ref()
    }

    /// Whether this carrier runs over the remote harness transport.
    pub fn is_remote(&self) -> bool {
        matches!(self.carrier, HarnessCarrier::Remote { .. })
    }

    /// The exact `ready` frame retained as startup evidence.
    pub fn ready_frame(&self) -> Option<&DecodedRpcFrame> {
        self.ready_frame.as_ref()
    }

    /// The exact negotiation response retained as startup evidence; `None`
    /// when the peer did not advertise v2 and no negotiation ran. Both a
    /// v2-accepting and a typed-failure v1 response are retained.
    pub fn negotiation_frame(&self) -> Option<&DecodedRpcFrame> {
        self.negotiation_frame.as_ref()
    }
    /// Every startup frame in exact arrival order: the `ready` frame, any
    /// auxiliary frames retained inside the negotiation window, and the
    /// negotiation response when one ran.
    pub fn startup_frames(&self) -> impl Iterator<Item = &DecodedRpcFrame> + '_ {
        self.ready_frame
            .iter()
            .chain(&self.startup_aux_frames)
            .chain(&self.negotiation_frame)
    }

    /// The exact exit record once the child reached a terminal state.
    pub fn exit_record(&self) -> Option<&OmpExitRecord> {
        self.exit_record.as_ref()
    }

    /// A bounded snapshot of the child's stderr tail.
    pub fn stderr_tail(&self) -> Vec<u8> {
        snapshot_tail(&self.stderr_tail)
    }

    /// The stderr tail as lossy UTF-8, for human-facing evidence.
    pub fn stderr_tail_lossy(&self) -> String {
        String::from_utf8_lossy(&self.stderr_tail()).into_owned()
    }
}
