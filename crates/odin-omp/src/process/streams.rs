//! Bounded stdout/stderr/stdin ownership: the async pipe wrapper, the
//! physical-frame stdout reader that never grows an allocation past the
//! transport ceiling, the bounded stderr drainer, and the stdin writers.
//! Every buffer here is bounded before it grows, so a full pipe can never
//! deadlock the child and a cancelled read never loses consumed bytes.

use std::io;
use std::os::fd::OwnedFd;

use serde_json::Value;
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncRead, AsyncReadExt};
use tokio::task::JoinHandle;
use tokio::time::timeout;

use crate::frames::{RpcFrameError, MAX_FRAME_BYTES};

use super::*;

/// Bound of the stderr tail retained as exact exit evidence.
const STDERR_TAIL_BYTES: usize = 64 * 1024;

/// Bound for one stdin write. The spec freezes only startup/drain/kill
/// budgets, so the write bound is a module constant.
const SEND_TIMEOUT: Duration = Duration::from_secs(10);

/// Read-buffer capacity for stdout physical-frame reading.
pub(super) const LINE_READ_CAPACITY: usize = 64 * 1024;

/// Read-chunk size for the bounded stderr drainer.
const STDERR_READ_CHUNK: usize = 4096;

/// A child's stdout or stderr pipe, read through the runtime's reactor.
pub(crate) type AsyncPipe = tokio::net::unix::pipe::Receiver;

/// Takes the pipe's read end; tokio checks it is a pipe opened for reading and makes it non-blocking.
pub(crate) fn async_pipe<T: Into<OwnedFd>>(pipe: T) -> io::Result<AsyncPipe> {
    AsyncPipe::from_owned_fd(pipe.into())
}

/// Joins a stderr drainer within `budget`, aborting it on expiry: a surviving
/// pipe writer can never block shutdown past the bound, and the tail drained
/// so far remains available.
pub(super) async fn join_drainer(drainer: JoinHandle<()>, budget: Duration) {
    let mut drainer = drainer;
    if timeout(budget, &mut drainer).await.is_err() {
        drainer.abort();
    }
}

/// One bounded read of the child's stdout.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) enum PhysicalLine {
    /// Exact bytes including the terminating newline, within [`MAX_FRAME_BYTES`].
    Terminated(Vec<u8>),
    /// EOF bytes without a terminator; the decoder classifies this exactly.
    Unterminated(Vec<u8>),
    /// The frame crossed [`MAX_FRAME_BYTES`]; `size` is the exact physical
    /// byte count including the terminator when one arrived, while `prefix`
    /// retains the exact in-ceiling bytes as bounded rejection evidence.
    Oversized { size: usize, prefix: Vec<u8> },
}

/// Persistent accumulation state of one stdout physical-frame reader.
///
/// Kept in the process rather than in the read future so a cancelled read
/// never loses the consumed prefix: the only await point is `fill_buf`, and
/// bytes move into this state synchronously before each await, so a resumed
/// read continues the same physical frame instead of restarting mid-JSON.
#[derive(Debug, Default)]
pub(super) struct PhysicalLineState {
    /// Exact prefix accumulated for the in-flight frame. Once the frame
    /// crosses the ceiling this remains capped at [`MAX_FRAME_BYTES`] while
    /// `counted` continues tracking its full physical size.
    line: Vec<u8>,
    /// Exact running byte count once the frame crossed the ceiling.
    counted: usize,
    /// Whether the in-flight frame crossed the ceiling: retain the bounded
    /// prefix and count every later byte.
    oversized: bool,
}

impl PhysicalLineState {
    /// Clears the in-flight frame after a complete read, keeping the
    /// accumulator's capacity for the next frame.
    fn reset(&mut self) {
        self.line.clear();
        self.counted = 0;
        self.oversized = false;
    }

    /// Publishes an exact-length copy and keeps the warm accumulator.
    /// Moving the read buffer out would retain its spare capacity in every
    /// later evidence frame while budgets charge only `len`. `Vec::clone`
    /// allocates `len`, not `capacity`; `clear` (via [`Self::reset`]) retains
    /// the accumulator for the next frame.
    fn take_line(&mut self) -> Vec<u8> {
        let line = self.line.clone();
        self.reset();
        line
    }
}

/// Reads one newline-terminated physical frame without ever growing an
/// allocation past the transport ceiling. Bytes accumulate in `state` only
/// through the in-ceiling prefix; past that the run is counted while that
/// prefix remains available as bounded rejection evidence.
/// The returned in-limit bytes retain the terminating newline.
pub(super) async fn read_physical_line<R: AsyncBufRead + Unpin>(
    reader: &mut R,
    state: &mut PhysicalLineState,
) -> io::Result<Option<PhysicalLine>> {
    loop {
        let buffered = reader.fill_buf().await?;
        if buffered.is_empty() {
            let result = if state.oversized {
                Some(PhysicalLine::Oversized {
                    size: state.counted,
                    prefix: state.take_line(),
                })
            } else if state.line.is_empty() {
                state.reset();
                None
            } else {
                Some(PhysicalLine::Unterminated(state.take_line()))
            };
            return Ok(result);
        }
        let buffered_len = buffered.len();
        match buffered.iter().position(|&byte| byte == b'\n') {
            Some(end) => {
                let physical = if state.oversized {
                    state.counted.saturating_add(end).saturating_add(1)
                } else {
                    state.line.len().saturating_add(end).saturating_add(1)
                };
                if physical > MAX_FRAME_BYTES {
                    if !state.oversized {
                        let remaining = MAX_FRAME_BYTES.saturating_sub(state.line.len());
                        state
                            .line
                            .extend_from_slice(&buffered[..remaining.min(end + 1)]);
                    }
                    reader.consume(end + 1);
                    let prefix = state.take_line();
                    return Ok(Some(PhysicalLine::Oversized {
                        size: physical,
                        prefix,
                    }));
                }
                state.line.extend_from_slice(&buffered[..=end]);
                reader.consume(end + 1);
                let line = state.take_line();
                return Ok(Some(PhysicalLine::Terminated(line)));
            }
            None => {
                if state.oversized {
                    state.counted = state.counted.saturating_add(buffered_len);
                    reader.consume(buffered_len);
                } else if state.line.len().saturating_add(buffered_len) > MAX_FRAME_BYTES {
                    // The bytes actually consumed crossed the ceiling. Retain
                    // the exact in-ceiling prefix and count from here. An
                    // exact-ceiling prefix stays in-limit until a later byte
                    // (including a newline) actually crosses the ceiling.
                    let remaining = MAX_FRAME_BYTES.saturating_sub(state.line.len());
                    state.line.extend_from_slice(&buffered[..remaining]);
                    state.counted = state.line.len().saturating_add(buffered_len - remaining);
                    state.oversized = true;
                    reader.consume(buffered_len);
                } else {
                    state.line.extend_from_slice(buffered);
                    reader.consume(buffered_len);
                }
            }
        }
    }
}

/// Drains the child's stderr into the bounded tail until EOF. The tail keeps
/// the last [`STDERR_TAIL_BYTES`] bytes exactly; it is never logged.
pub(super) async fn drain_stderr<R: AsyncRead + Unpin>(mut stderr: R, tail: Arc<Mutex<Vec<u8>>>) {
    let mut chunk = [0u8; STDERR_READ_CHUNK];
    loop {
        match stderr.read(&mut chunk).await {
            Ok(0) | Err(_) => break,
            Ok(read) => {
                let mut guard = match tail.lock() {
                    Ok(guard) => guard,
                    Err(poisoned) => poisoned.into_inner(),
                };
                guard.extend_from_slice(&chunk[..read]);
                if guard.len() > STDERR_TAIL_BYTES {
                    let overflow = guard.len() - STDERR_TAIL_BYTES;
                    guard.drain(..overflow);
                }
            }
        }
    }
}

/// Copies the bounded stderr tail; byte-buffer poisoning cannot lose evidence,
/// so the data behind a poisoned lock is still returned.
pub(super) fn snapshot_tail(tail: &Mutex<Vec<u8>>) -> Vec<u8> {
    let mut guard = match tail.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    };
    if guard.len() > STDERR_TAIL_BYTES {
        let overflow = guard.len() - STDERR_TAIL_BYTES;
        guard.drain(..overflow);
    }
    guard.clone()
}

impl OmpProcess {
    /// Writes one bounded, unchunked stdin JSONL object.
    ///
    /// The frame is serialized and newline-terminated, checked against the
    /// [`MAX_FRAME_BYTES`] physical ceiling, and written within a bounded
    /// window. A failed or late write closes stdin and moves a `Ready`
    /// process to `Draining`: partial bytes cannot recover the framing, so
    /// the process stops accepting commands and drains toward a stop instead
    /// of reporting `Ready` on a half-written stream.
    pub async fn send_json(&mut self, frame: &Value) -> Result<(), OmpProcessError> {
        match self.state {
            OmpLifecycleState::Ready => {}
            from => {
                return Err(OmpProcessError::InvalidTransition {
                    operation: "send_json",
                    from,
                })
            }
        }
        let mut bytes = frame.to_string().into_bytes();
        bytes.push(b'\n');
        if bytes.len() > MAX_FRAME_BYTES {
            return Err(OmpProcessError::RequestTooLarge { size: bytes.len() });
        }
        self.write_owned(bytes, SEND_TIMEOUT).await
    }

    /// Writes one newline-terminated stdin frame within `budget`.
    pub(super) async fn write_request(
        &mut self,
        bytes: &[u8],
        budget: Duration,
    ) -> Result<(), OmpProcessError> {
        let mut payload = Vec::with_capacity(bytes.len().saturating_add(1));
        payload.extend_from_slice(bytes);
        payload.push(b'\n');
        self.write_owned(payload, budget).await
    }

    /// Writes one already newline-terminated stdin frame within `budget`.
    async fn write_owned(
        &mut self,
        payload: Vec<u8>,
        budget: Duration,
    ) -> Result<(), OmpProcessError> {
        let size = payload.len();
        let Some(stdin) = self.stdin.as_mut() else {
            self.discard_stdin();
            return Err(OmpProcessError::StdinBroken {
                detail: "stdin is closed".to_owned(),
            });
        };
        match timeout(budget, stdin.write_all(payload)).await {
            Ok(Ok(())) => Ok(()),
            Ok(Err(error)) => {
                self.discard_stdin();
                Err(OmpProcessError::StdinBroken {
                    detail: error.to_string(),
                })
            }
            Err(_elapsed) => {
                self.discard_stdin();
                Err(OmpProcessError::SendTimeout {
                    size,
                    limit: budget,
                })
            }
        }
    }

    /// Discards stdin after a write failure: partial bytes cannot recover the
    /// JSONL framing, so a `Ready` process leaves for `Draining` — the closed
    /// pipe drives the child toward exit and no further command is accepted on
    /// the half-written stream.
    fn discard_stdin(&mut self) {
        let _ = self.close_owned_stdin();
        if matches!(self.state, OmpLifecycleState::Ready) {
            self.state = OmpLifecycleState::Draining;
        }
    }

    /// Closes the stdin half of the carrier, whichever transport it runs
    /// over: the local authority pipe or the remote exec writer. Consuming,
    /// so a half can never be closed twice.
    pub(super) fn close_owned_stdin(&mut self) -> Result<(), OmpProcessError> {
        let Some(stdin) = self.stdin.take() else {
            return Ok(());
        };
        stdin
            .shutdown()
            .map_err(|error| OmpProcessError::StdinBroken {
                detail: error.to_string(),
            })
    }

    /// Remembers a frame rejection so every later read replays it.
    fn poison_with(&mut self, error: RpcFrameError) -> OmpProcessError {
        self.poison = Some(error.clone());
        OmpProcessError::FrameRejected(error)
    }

    /// Reads until one logical frame completes or the stream fails. A frame
    /// rejection is replayed on every later read: the decoder cannot
    /// resynchronize after it.
    pub(super) async fn read_frame(&mut self) -> Result<DecodedRpcFrame, OmpProcessError> {
        if let Some(poison) = &self.poison {
            return Err(OmpProcessError::FrameRejected(poison.clone()));
        }
        loop {
            let from = self.state;
            let line = match read_physical_line(
                self.stdout
                    .as_mut()
                    .ok_or(OmpProcessError::InvalidTransition {
                        operation: "next_frame",
                        from,
                    })?,
                &mut self.line_state,
            )
            .await
            {
                Ok(Some(PhysicalLine::Terminated(bytes))) => bytes,
                Ok(Some(PhysicalLine::Unterminated(bytes))) => bytes,
                Ok(Some(PhysicalLine::Oversized { size, prefix })) => {
                    return Err(self.poison_with(RpcFrameError::oversized(size, prefix)));
                }
                Ok(None) => {
                    // Finalize the decoder first: a v2 sequence interrupted by
                    // EOF must surface its violation and raw chunk evidence
                    // inside the exit record, not die in `pending`.
                    let unfinished = self.decoder.finish().err();
                    return match self.observe_exit(self.spec.drain_timeout, unfinished).await {
                        Ok(exit) => Err(OmpProcessError::StdoutClosed {
                            exit: Box::new(exit),
                        }),
                        Err(error) => Err(error),
                    };
                }
                Err(error) => return Err(OmpProcessError::Io(error)),
            };
            match self.decoder.push_owned_line(line) {
                Ok(Some(frame)) => return Ok(frame),
                Ok(None) => continue,
                Err(error) => return Err(self.poison_with(error)),
            }
        }
    }
}
