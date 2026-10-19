//! Startup ready/version negotiation: the constructor plus `launch`
//! handshake that consumes the exact `ready` frame, validates the
//! v1/current supported list and both advertised limits, runs the fixed
//! prefer-v2 negotiation under `NEGOTIATE_REQUEST_ID`, retains interleaved
//! auxiliary frames in a bounded window until the exact id+command response
//! arrives, and moves ready, window, and offending response into
//! `OmpProcessError::StartupFailed` before the worker is stopped.

use std::time::Instant;

use crate::frames::{MAX_FRAME_BYTES, MAX_REASSEMBLED_BYTES};

use serde_json::{json, Value};
use tokio::time::timeout;

use super::launch::{
    canonicalize_executable, invalid_spec, spawn_registered, AuthorityStdin, HOST_MODE_ARGS,
};
use super::streams::{
    async_pipe, drain_stderr, snapshot_tail, PhysicalLineState, LINE_READ_CAPACITY,
};
use super::*;

use tokio::io::AsyncRead;

/// Deterministic request id of the fixed prefer-v2 negotiation round-trip.
///
/// The startup handshake must be reproducible from protocol evidence alone, so
/// the id is a constant rather than a random or time-derived value; the
/// response is accepted only when it echoes this exact id.
pub const NEGOTIATE_REQUEST_ID: &str = "odin-omp-negotiate-protocol";

/// Maximum number of auxiliary (non-response) decoded frames retained inside
/// the startup negotiation window while awaiting the exact negotiation
/// response.
pub(super) const STARTUP_AUX_FRAME_CAP: usize = 256;

/// Maximum logical bytes retained by startup auxiliary frames before the
/// offending frame fails startup as exact overflow evidence.
pub(super) const STARTUP_AUX_BYTE_CAP: usize = 4 * MAX_FRAME_BYTES;

/// `type` discriminant of the startup ready frame.
const READY_TYPE: &str = "ready";
/// `type` discriminant of command responses.
const RESPONSE_TYPE: &str = "response";
/// `command` discriminant of the negotiation response.
pub(super) const NEGOTIATE_COMMAND: &str = "negotiate_protocol";

impl OmpProcess {
    /// Launches one trusted `omp --mode rpc` child and completes the startup
    /// handshake, returning it [`OmpLifecycleState::Ready`] at the negotiated
    /// protocol.
    ///
    /// Startup consumes the exact `ready` frame first, validates the
    /// v1/current supported list and both advertised limits, then requests
    /// protocol v2 under [`NEGOTIATE_REQUEST_ID`] when the peer advertises it.
    /// Auxiliary (non-response) frames interleaved inside the negotiation
    /// window are retained in arrival order under `STARTUP_AUX_FRAME_CAP`
    /// and `STARTUP_AUX_BYTE_CAP`, never discarded; the decoder upgrades
    /// only after the exact id+command v1 response matches success and data,
    /// and a typed failure response keeps the child at v1.
    ///
    /// A failed startup never strands that evidence inside the dropped
    /// process: [`OmpProcessError::StartupFailed`] owns the ordered retained
    /// frames — the validated ready frame, the auxiliary window still held
    /// at failure time, and the offending decoded negotiation response —
    /// alongside the bounded stderr tail and the underlying failure, and
    /// stdout EOF inside the negotiation window is the same typed failure
    /// with the exact exit record as its inner evidence.
    pub async fn spawn(
        spec: OmpProcessSpec,
        worker: OmpWorkerLaunch,
    ) -> Result<Self, OmpProcessError> {
        spec.validate()?;
        if canonicalize_executable(&spec.executable)? != worker.binding.executable() {
            return Err(invalid_spec(format!(
                "process executable {} does not match registered binding {}",
                spec.executable.display(),
                worker.binding.executable().display()
            )));
        }
        let mut process = Self::new(spec, worker);
        process.launch().await?;
        Ok(process)
    }

    pub(super) fn new(spec: OmpProcessSpec, worker: OmpWorkerLaunch) -> Self {
        Self {
            spec,
            worker,
            state: OmpLifecycleState::Stopped,
            carrier: HarnessCarrier::Local,
            worker_id: None,
            stdin: None,
            stdout: None,
            line_state: PhysicalLineState::default(),
            stderr_task: None,
            stderr_tail: Arc::new(Mutex::new(Vec::new())),
            decoder: RpcFrameDecoder::new(RpcProtocolVersion::V1),
            ready_frame: None,
            negotiation_frame: None,
            startup_aux_frames: Vec::new(),
            exit_record: None,
            pending_status: None,
            pending_unfinished: None,
            remote_exit_waiter: None,
            poison: None,
        }
    }

    async fn launch(&mut self) -> Result<(), OmpProcessError> {
        let spec = self.spec.clone();
        let executable = canonicalize_executable(&spec.executable)?;
        let mut args = Vec::with_capacity(
            spec.explicit_args
                .len()
                .saturating_add(HOST_MODE_ARGS.len() + 1),
        );
        args.push(executable.to_string_lossy().into_owned());
        args.extend(spec.launch_args());
        let launched = spawn_registered(&self.worker, &args, &spec.explicit_env, &spec.cwd)?;
        let worker_id = launched.identity.worker_id.clone();
        self.worker_id = Some(worker_id.clone());
        let stdout = async_pipe(launched.stdout).map_err(|error| OmpProcessError::SpawnFailed {
            detail: format!("stdout pipe is not async: {error}"),
        })?;
        let stderr = async_pipe(launched.stderr).map_err(|error| OmpProcessError::SpawnFailed {
            detail: format!("stderr pipe is not async: {error}"),
        })?;
        self.stdin = Some(Box::new(AuthorityStdin::new(
            Arc::clone(&self.worker.authority),
            worker_id,
        )));
        self.stdout = Some(BufReader::with_capacity(
            LINE_READ_CAPACITY,
            Box::new(stdout) as Box<dyn AsyncRead + Unpin + Send>,
        ));
        self.stderr_tail = Arc::new(Mutex::new(Vec::new()));
        self.stderr_task = Some(tokio::spawn(drain_stderr(
            stderr,
            Arc::clone(&self.stderr_tail),
        )));
        self.state = OmpLifecycleState::StartingV1;
        self.handshake().await
    }

    // The factory attaches streams before the handshake so no startup frames are lost.
    pub async fn spawn_remote(
        spec: OmpProcessSpec,
        worker: OmpWorkerLaunch,
        channel: RemoteHarnessChannel,
        job_worker: WorkerId,
        stop_action: JobStopAction,
    ) -> Result<Self, OmpProcessError> {
        spec.validate()?;
        let mut process = Self::new(spec, worker);
        process.carrier = HarnessCarrier::Remote {
            job_worker,
            stop_action,
        };
        process.stdin = Some(channel.stdin);
        process.stdout = Some(BufReader::with_capacity(LINE_READ_CAPACITY, channel.stdout));
        if let Some(stderr) = channel.stderr {
            process.stderr_tail = Arc::new(Mutex::new(Vec::new()));
            process.stderr_task = Some(tokio::spawn(drain_stderr(
                stderr,
                Arc::clone(&process.stderr_tail),
            )));
        }
        process.remote_exit_waiter = Some(channel.exit);
        process.state = OmpLifecycleState::StartingV1;
        process.handshake().await?;
        Ok(process)
    }

    // Startup failures stop the carrier before returning the handshake error.
    async fn handshake(&mut self) -> Result<(), OmpProcessError> {
        let deadline = Instant::now() + self.spec.startup_timeout;
        let ready = match timeout(
            deadline.saturating_duration_since(Instant::now()),
            self.read_frame(),
        )
        .await
        {
            Ok(result) => result,
            Err(_elapsed) => {
                return Err(self
                    .startup_failed(OmpProcessError::StartupTimeout, None)
                    .await)
            }
        };
        let ready = match ready {
            Ok(frame) => frame,
            Err(error @ OmpProcessError::StdoutClosed { .. }) => return Err(error),
            Err(error) => return Err(self.startup_failed(error, None).await),
        };
        let prefer_v2 = match validate_ready_frame(&ready) {
            Ok(prefer) => prefer,
            Err(error) => return Err(self.startup_failed(error, None).await),
        };
        self.ready_frame = Some(ready);

        let mut protocol = RpcProtocolVersion::V1;
        if prefer_v2 {
            self.state = OmpLifecycleState::NegotiatingV2;
            let request = json!({
                "id": NEGOTIATE_REQUEST_ID,
                "type": NEGOTIATE_COMMAND,
                "protocolVersion": 2,
            });
            let bytes = serde_json::to_vec(&request).map_err(|error| {
                OmpProcessError::RequestNotSerializable {
                    detail: error.to_string(),
                }
            })?;
            let budget = deadline.saturating_duration_since(Instant::now());
            if let Err(error) = self.write_request(&bytes, budget).await {
                return Err(self.startup_failed(error, None).await);
            }
            // The pinned client may interleave auxiliary frames (extension UI
            // requests, session updates) inside the negotiation window, before
            // it answers the deterministic request. They are retained in
            // arrival order — bounded in count and bytes, never discarded —
            // until the exact id+command response arrives; any other response
            // fails startup in `validate_negotiation_response`.
            let mut aux_bytes = 0usize;
            let response = loop {
                let frame = match timeout(
                    deadline.saturating_duration_since(Instant::now()),
                    self.read_frame(),
                )
                .await
                {
                    Ok(result) => result,
                    Err(_elapsed) => {
                        return Err(self
                            .startup_failed(OmpProcessError::StartupTimeout, None)
                            .await)
                    }
                };
                let frame = match frame {
                    Ok(frame) => frame,
                    Err(OmpProcessError::StdoutClosed { exit }) => {
                        // EOF inside the negotiation window: the bounded reap
                        // already ran inside `read_frame`, so only the
                        // retained window still needs to move into the typed
                        // failure evidence.
                        let startup_frames = self.take_startup_evidence(None);
                        return Err(self.startup_failure_evidence(
                            OmpProcessError::StdoutClosed { exit },
                            startup_frames,
                            None,
                        ));
                    }
                    Err(error) => return Err(self.startup_failed(error, None).await),
                };
                if frame.value().get("type").and_then(Value::as_str) == Some(RESPONSE_TYPE) {
                    break frame;
                }
                let next_bytes = aux_bytes.saturating_add(frame.raw().len());
                if self.startup_aux_frames.len() >= STARTUP_AUX_FRAME_CAP
                    || next_bytes > STARTUP_AUX_BYTE_CAP
                {
                    let limit = OmpProcessError::StartupAuxLimit {
                        frames: std::mem::take(&mut self.startup_aux_frames),
                        bytes: aux_bytes,
                        overflow: Box::new(frame),
                    };
                    return Err(self.startup_failed(limit, None).await);
                }
                aux_bytes = next_bytes;
                self.startup_aux_frames.push(frame);
            };
            protocol = match validate_negotiation_response(&response) {
                Ok(protocol) => protocol,
                Err(error) => return Err(self.startup_failed(error, Some(response)).await),
            };
            self.negotiation_frame = Some(response);
        }
        self.decoder.set_protocol(protocol);
        self.state = OmpLifecycleState::Ready(protocol);
        Ok(())
    }

    /// Stops the failed-startup worker through StopAuthority so an immediate
    /// retry cannot race a surviving worker or its session lock.
    /// The retained startup frames move into the typed failure before the
    /// stop, and the startup failure stays the primary `inner`: a bounded
    /// cleanup failure rides in `cleanup` alongside it rather than replacing
    /// the rejection evidence, and no terminal record is manufactured from
    /// an unobserved wait. `offending` is the decoded negotiation response
    /// whose rejection failed startup; it closes the retained frame order.
    async fn startup_failed(
        &mut self,
        startup: OmpProcessError,
        offending: Option<DecodedRpcFrame>,
    ) -> OmpProcessError {
        let startup_frames = self.take_startup_evidence(offending);
        self.begin_reaping(None);
        let cleanup = match self.force_reap().await {
            Ok(_) => None,
            Err(cleanup) => Some(Box::new(cleanup)),
        };
        self.startup_failure_evidence(startup, startup_frames, cleanup)
    }

    /// Moves the startup frames still owned by the process into one ordered
    /// evidence vector: the validated ready frame first, then any in-cap
    /// auxiliary frames in arrival order, then the offending decoded
    /// negotiation response whose rejection failed startup. Frames already
    /// moved into a typed inner error — the auxiliary-ceiling window — stay
    /// there; nothing is duplicated past the existing caps.
    fn take_startup_evidence(
        &mut self,
        offending: Option<DecodedRpcFrame>,
    ) -> Vec<DecodedRpcFrame> {
        let mut frames = Vec::with_capacity(
            self.ready_frame.is_some() as usize
                + self.startup_aux_frames.len()
                + offending.is_some() as usize,
        );
        if let Some(ready) = self.ready_frame.take() {
            frames.push(ready);
        }
        frames.append(&mut self.startup_aux_frames);
        frames.extend(offending);
        frames
    }

    /// Assembles the typed startup failure: the underlying failure, the
    /// bounded stderr tail, the ordered retained startup frames, and the
    /// bounded cleanup failure when reaping the failed child itself failed.
    fn startup_failure_evidence(
        &self,
        inner: OmpProcessError,
        startup_frames: Vec<DecodedRpcFrame>,
        cleanup: Option<Box<OmpProcessError>>,
    ) -> OmpProcessError {
        OmpProcessError::StartupFailed {
            inner: Box::new(inner),
            stderr_tail: snapshot_tail(&self.stderr_tail),
            startup_frames,
            cleanup,
        }
    }
}

/// Validates the exact pinned ready contract and reports whether protocol v2
/// may be requested.
fn validate_ready_frame(frame: &DecodedRpcFrame) -> Result<bool, OmpProcessError> {
    let value = frame.value();
    let reject = |detail: String| OmpProcessError::InvalidReadyFrame {
        detail,
        lines: frame.lines().to_vec(),
    };
    if value.get("type").and_then(Value::as_str) != Some(READY_TYPE) {
        return Err(reject(format!(
            "`type` is {:?}, not {READY_TYPE:?}",
            value.get("type")
        )));
    }
    if value.get("protocolVersion").and_then(Value::as_u64) != Some(1) {
        return Err(reject(
            "the current wire protocol at ready must be v1".to_owned(),
        ));
    }
    let Some(supported) = value
        .get("supportedProtocolVersions")
        .and_then(Value::as_array)
    else {
        return Err(reject(
            "supportedProtocolVersions must be an array".to_owned(),
        ));
    };
    let Some(supported) = supported
        .iter()
        .map(Value::as_u64)
        .collect::<Option<Vec<u64>>>()
    else {
        return Err(reject(
            "supportedProtocolVersions entries must be numbers".to_owned(),
        ));
    };
    if !supported.contains(&1) {
        return Err(reject("the peer must support protocol v1".to_owned()));
    }
    if value.get("maxFrameBytes").and_then(Value::as_u64) != Some(MAX_FRAME_BYTES as u64) {
        return Err(reject(format!(
            "maxFrameBytes must be exactly {MAX_FRAME_BYTES}"
        )));
    }
    if value
        .get("maxReassembledFrameBytes")
        .and_then(Value::as_u64)
        != Some(MAX_REASSEMBLED_BYTES as u64)
    {
        return Err(reject(format!(
            "maxReassembledFrameBytes must be exactly {MAX_REASSEMBLED_BYTES}"
        )));
    }
    Ok(supported.contains(&2))
}

/// Validates the v1 negotiation response against the deterministic request
/// and reports the agreed protocol. A typed failure response keeps the child
/// at v1; anything else mismatched is a startup failure.
fn validate_negotiation_response(
    frame: &DecodedRpcFrame,
) -> Result<RpcProtocolVersion, OmpProcessError> {
    let value = frame.value();
    let lines = frame.lines().to_vec();
    if value.get("type").and_then(Value::as_str) != Some(RESPONSE_TYPE) {
        return Err(OmpProcessError::UnexpectedStartupFrame {
            detail: format!("`type` is {:?}, not {RESPONSE_TYPE:?}", value.get("type")),
            lines,
        });
    }
    if value.get("command").and_then(Value::as_str) != Some(NEGOTIATE_COMMAND) {
        return Err(OmpProcessError::UnexpectedStartupFrame {
            detail: format!(
                "`command` is {:?}, not {NEGOTIATE_COMMAND:?}",
                value.get("command")
            ),
            lines,
        });
    }
    if value.get("id").and_then(Value::as_str) != Some(NEGOTIATE_REQUEST_ID) {
        return Err(OmpProcessError::NegotiationMismatch {
            detail: format!(
                "response id does not match the deterministic request id {NEGOTIATE_REQUEST_ID:?}"
            ),
            lines,
        });
    }
    match value.get("success").and_then(Value::as_bool) {
        Some(true) => {}
        Some(false) => return Ok(RpcProtocolVersion::V1),
        None => {
            return Err(OmpProcessError::NegotiationMismatch {
                detail: "`success` is not a boolean".to_owned(),
                lines,
            });
        }
    }
    if value
        .get("data")
        .and_then(|data| data.get("protocolVersion"))
        .and_then(Value::as_u64)
        != Some(2)
    {
        return Err(OmpProcessError::NegotiationMismatch {
            detail: "advertised data.protocolVersion is not 2".to_owned(),
            lines,
        });
    }
    Ok(RpcProtocolVersion::V2)
}
