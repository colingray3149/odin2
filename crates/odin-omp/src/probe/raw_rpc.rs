//! The probe's direct RPC child driver: one deterministic owner for reads and
//! writes against a single pinned-OMP child (or the Bun fault fixture),
//! retaining every decoded frame in arrival order under explicit transcript
//! caps.

use std::time::Instant;

use serde_json::{Map, Value};
use thiserror::Error;
use tokio::time;

use crate::process::{
    OmpExitRecord, OmpProcess, OmpProcessError, OmpProcessSpec, OmpShutdown, OmpWorkerLaunch,
    DRAIN_BYTE_CAP, DRAIN_FRAME_CAP,
};

use super::contracts::{CleanupOutcome, CleanupReceipt};

/// Maximum decoded frames retained by one raw RPC transcript.
pub const RAW_RPC_TRANSCRIPT_FRAME_CAP: usize = DRAIN_FRAME_CAP;
/// Maximum logical frame bytes retained by one raw RPC transcript.
pub const RAW_RPC_TRANSCRIPT_BYTE_CAP: usize = DRAIN_BYTE_CAP;

/// Typed failure from the shared direct RPC process driver.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum RawRpcError {
    /// The trusted process boundary rejected an operation.
    #[error(transparent)]
    Process(#[from] OmpProcessError),
    /// The raw request was not an object that can be given host-owned identity.
    #[error("raw RPC request rejected: {detail}")]
    InvalidRequest { detail: String },
    /// A bounded frame collection did not satisfy its predicate in time.
    #[error("raw RPC {operation} reached its deadline")]
    Deadline {
        /// Stable name of the bounded operation.
        operation: &'static str,
    },
    /// Preparing the child working directory failed.
    #[error("raw RPC fixture I/O failed: {0}")]
    Io(#[from] std::io::Error),
    /// The transcript crossed its explicit retained-evidence ceiling. Every
    /// frame in the rejected batch remains available in `retained`.
    #[error(
        "raw RPC transcript crossed its evidence ceiling at {frames} frame(s) and {bytes} logical byte(s)"
    )]
    EvidenceLimit {
        /// Prospective transcript frame count.
        frames: usize,
        /// Prospective transcript logical byte count.
        bytes: usize,
        /// Exact newly collected frames that did not fit the transcript.
        retained: Vec<crate::frames::DecodedRpcFrame>,
    },
}

/// Direct, deterministic driver for pinned-OMP commands not exposed by
/// [`crate::bridge::OmpBridge`].
///
/// One owner performs both reads and writes, so response ordering cannot race
/// between helper tasks. Every decoded frame is retained in arrival order,
/// including every startup frame consumed by [`OmpProcess::spawn`]: the ready
/// frame, any auxiliary frames interleaved inside the negotiation window, and
/// the negotiation response. Collection is always predicate-terminated under an
/// absolute deadline and retained under [`RAW_RPC_TRANSCRIPT_FRAME_CAP`] and
/// [`RAW_RPC_TRANSCRIPT_BYTE_CAP`]; the exact newly collected batch rides in
/// [`RawRpcError::EvidenceLimit`] rather than being discarded.
pub struct RawRpcDriver {
    process: OmpProcess,
    next_request: u64,
    transcript: Vec<crate::frames::DecodedRpcFrame>,
    transcript_bytes: usize,
}

impl RawRpcDriver {
    /// Creates the cwd and negotiates startup, retaining all startup frames in arrival order.
    pub async fn spawn(spec: OmpProcessSpec, worker: OmpWorkerLaunch) -> Result<Self, RawRpcError> {
        std::fs::create_dir_all(&spec.cwd)?;
        let process = OmpProcess::spawn(spec, worker).await?;
        let transcript: Vec<_> = process.startup_frames().cloned().collect();
        let transcript_bytes = transcript.iter().map(|frame| frame.raw().len()).sum();
        Ok(Self {
            process,
            next_request: 1,
            transcript,
            transcript_bytes,
        })
    }

    /// Mints the next deterministic request id for `command`.
    pub fn request_id(&mut self, command: &str) -> String {
        let sequence = self.next_request;
        self.next_request = self.next_request.saturating_add(1);
        let command = command
            .chars()
            .take(48)
            .map(|character| {
                if character.is_ascii_alphanumeric() || matches!(character, '-' | '_') {
                    character
                } else {
                    '-'
                }
            })
            .collect::<String>();
        format!("odin-probe-{sequence:04}-{command}")
    }

    /// Inserts `id` and `type`; callers supply only command-specific fields.
    pub async fn send(&mut self, command: &str, fields: Value) -> Result<String, RawRpcError> {
        if command.is_empty() {
            return Err(RawRpcError::InvalidRequest {
                detail: "command is empty".to_owned(),
            });
        }
        let Value::Object(fields) = fields else {
            return Err(RawRpcError::InvalidRequest {
                detail: "command fields must be a JSON object".to_owned(),
            });
        };
        if fields.contains_key("id") || fields.contains_key("type") {
            return Err(RawRpcError::InvalidRequest {
                detail: "command fields may not override host-owned id or type".to_owned(),
            });
        }
        let id = self.request_id(command);
        let mut frame = Map::new();
        frame.insert("id".to_owned(), Value::String(id.clone()));
        frame.insert("type".to_owned(), Value::String(command.to_owned()));
        frame.extend(fields);
        self.process.send_json(&Value::Object(frame)).await?;
        Ok(id)
    }

    /// Sends an already assembled raw frame. This is intentionally lower-level
    /// than [`RawRpcDriver::send`] for malformed/mismatched conformance input.
    pub async fn send_frame(&mut self, frame: Value) -> Result<(), RawRpcError> {
        if !frame.is_object() {
            return Err(RawRpcError::InvalidRequest {
                detail: "raw frame must be a JSON object".to_owned(),
            });
        }
        self.process.send_json(&frame).await?;
        Ok(())
    }

    /// Returns the exact response matching both wire id and command.
    ///
    /// Already collected frames are searched first, making the operation safe
    /// after a broader lifecycle collection. A response matching only one
    /// field is retained as evidence but never accepted.
    pub async fn wait_for_response(
        &mut self,
        id: &str,
        command: &str,
        deadline: Instant,
    ) -> Result<crate::frames::DecodedRpcFrame, RawRpcError> {
        if let Some(frame) = self
            .transcript
            .iter()
            .find(|frame| response_matches(frame, id, command))
        {
            return Ok(frame.clone());
        }
        let frames = self
            .collect_until(deadline, |frame| response_matches(frame, id, command))
            .await?;
        frames
            .into_iter()
            .find(|frame| response_matches(frame, id, command))
            .ok_or(RawRpcError::Deadline {
                operation: "response wait",
            })
    }

    /// Collects newly arriving frames through and including the first frame
    /// accepted by `predicate`.
    pub async fn collect_until<F>(
        &mut self,
        deadline: Instant,
        mut predicate: F,
    ) -> Result<Vec<crate::frames::DecodedRpcFrame>, RawRpcError>
    where
        F: FnMut(&crate::frames::DecodedRpcFrame) -> bool,
    {
        let mut collected = Vec::new();
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(RawRpcError::Deadline {
                    operation: "frame collection",
                });
            }
            let frame = match time::timeout(remaining, self.process.next_frame()).await {
                Ok(result) => result?,
                Err(_) => {
                    return Err(RawRpcError::Deadline {
                        operation: "frame collection",
                    })
                }
            };
            self.retain_batch(std::slice::from_ref(&frame))?;
            let complete = predicate(&frame);
            collected.push(frame);
            if complete {
                return Ok(collected);
            }
        }
    }

    /// Every decoded frame in arrival order, including every startup frame.
    pub fn transcript(&self) -> &[crate::frames::DecodedRpcFrame] {
        &self.transcript
    }

    pub fn process(&self) -> &OmpProcess {
        &self.process
    }

    /// Closes stdin and drains the child within its configured bound. Drained
    /// frames are appended to the transcript before the result is returned.
    pub async fn close(&mut self) -> Result<OmpShutdown, RawRpcError> {
        match self.process.graceful_stop().await {
            Ok(shutdown) => {
                self.retain_batch(shutdown.frames())?;
                Ok(shutdown)
            }
            Err(OmpProcessError::DrainTimeout { frames }) => {
                self.retain_batch(&frames)?;
                Err(RawRpcError::Process(OmpProcessError::DrainTimeout {
                    frames,
                }))
            }
            Err(OmpProcessError::DrainLimit {
                frames,
                bytes,
                overflow,
            }) => {
                let prospective_frames = self
                    .transcript
                    .len()
                    .saturating_add(frames.len())
                    .saturating_add(1);
                let prospective_bytes = self
                    .transcript_bytes
                    .saturating_add(bytes)
                    .saturating_add(overflow.raw().len());
                let mut retained = frames;
                retained.push(*overflow);
                Err(RawRpcError::EvidenceLimit {
                    frames: prospective_frames,
                    bytes: prospective_bytes,
                    retained,
                })
            }
            Err(error) => Err(error.into()),
        }
    }

    /// Forcibly tree-kills and reaps the child within its configured bound.
    pub async fn kill(&mut self) -> Result<OmpExitRecord, RawRpcError> {
        self.process.kill().await.map_err(RawRpcError::from)
    }

    /// Performs explicit case cleanup: graceful close first, then bounded
    /// tree-kill if draining failed. Exactly one receipt step is appended; a
    /// successful fallback kill still returns the original close error so its
    /// evidence cannot disappear behind cleanup success.
    pub async fn cleanup(
        &mut self,
        receipt: &mut CleanupReceipt,
        subject: impl Into<String>,
    ) -> Result<OmpExitRecord, RawRpcError> {
        let subject = subject.into();
        match self.close().await {
            Ok(shutdown) => {
                receipt.push("child_stop", subject, CleanupOutcome::Clean);
                Ok(shutdown.into_parts().1)
            }
            Err(close_error) => match self.kill().await {
                Ok(_exit) => {
                    receipt.push("child_kill", subject, CleanupOutcome::Clean);
                    Err(close_error)
                }
                Err(kill_error) => {
                    receipt.push(
                        "child_kill",
                        subject,
                        CleanupOutcome::Failed {
                            reason: format!("graceful close failed: {close_error}; forced kill failed: {kill_error}"),
                        },
                    );
                    Err(kill_error)
                }
            },
        }
    }

    fn retain_batch(
        &mut self,
        frames: &[crate::frames::DecodedRpcFrame],
    ) -> Result<(), RawRpcError> {
        let added_bytes = frames.iter().fold(0usize, |total, frame| {
            total.saturating_add(frame.raw().len())
        });
        let prospective_frames = self.transcript.len().saturating_add(frames.len());
        let prospective_bytes = self.transcript_bytes.saturating_add(added_bytes);
        if prospective_frames > RAW_RPC_TRANSCRIPT_FRAME_CAP
            || prospective_bytes > RAW_RPC_TRANSCRIPT_BYTE_CAP
        {
            return Err(RawRpcError::EvidenceLimit {
                frames: prospective_frames,
                bytes: prospective_bytes,
                retained: frames.to_vec(),
            });
        }
        self.transcript.extend(frames.iter().cloned());
        self.transcript_bytes = prospective_bytes;
        Ok(())
    }
}

fn response_matches(frame: &crate::frames::DecodedRpcFrame, id: &str, command: &str) -> bool {
    let value = frame.value();
    value.get("type").and_then(Value::as_str) == Some("response")
        && value.get("id").and_then(Value::as_str) == Some(id)
        && value.get("command").and_then(Value::as_str) == Some(command)
}
