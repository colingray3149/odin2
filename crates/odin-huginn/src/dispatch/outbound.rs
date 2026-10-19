//! A served connection's outgoing side: one owned write in flight at a
//! time, a byte-bounded outbox behind it, and the end of the connection
//! (revocation, stop, protocol close) under one close deadline.

use std::collections::VecDeque;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use odin_domain::huginn::DeviceId;
use tokio::sync::watch;
use tokio::time::Instant;

use super::live::DispatchError;
use super::registry::{ConnectionFrame, ConnectionRegistration, FrameWriter};

/// How long one frame may take to reach the peer before the connection is
/// given up as a peer that stopped reading.
pub(super) const SEND_BOUND: Duration = Duration::from_secs(30);
/// How long a closing connection gets, from the moment it is told to end,
/// to say why and close.
pub(super) const CLOSE_BOUND: Duration = Duration::from_secs(2);
/// Queued bytes past which streamed frames wait for the peer.
const STREAM_ROOM_BYTES: usize = 256 * 1024;
/// Bookkeeping charged per queued frame, so tiny frames are bounded too.
const FRAME_OVERHEAD_BYTES: usize = 64;

type Write<W> = Pin<Box<dyn Future<Output = (W, Result<(), String>)> + Send>>;

pub(super) struct DeliveryReceipt {
    written: Arc<AtomicU64>,
    mark: u64,
}

impl DeliveryReceipt {
    pub(super) fn delivered(&self) -> bool {
        self.written.load(Ordering::Acquire) >= self.mark
    }
}

pub(super) struct Outbound<W> {
    writer: Option<W>,
    in_flight: Option<(Write<W>, Instant, u64)>,
    in_flight_bytes: usize,
    queue: VecDeque<(u64, ConnectionFrame)>,
    queued_bytes: usize,
    limit_bytes: usize,
    device: DeviceId,
    /// FIFO completion is shared with page receipts so request dispatch
    /// observes writes drained by either connection driver.
    enqueued: u64,
    written: Arc<AtomicU64>,
}

impl<W: FrameWriter> Outbound<W> {
    /// The whole outbox — the queue plus the one write in flight — holds
    /// two whole frames past the stream room, so a request's answer and its
    /// replay markers are always admitted behind a backlog.
    pub(super) fn new(writer: W, device: DeviceId, max_frame_bytes: usize) -> Self {
        Self {
            writer: Some(writer),
            in_flight: None,
            in_flight_bytes: 0,
            queue: VecDeque::new(),
            queued_bytes: 0,
            limit_bytes: STREAM_ROOM_BYTES + 2 * max_frame_bytes,
            device,
            enqueued: 0,
            written: Arc::new(AtomicU64::new(0)),
        }
    }

    /// Queues the frame and returns its mark for a delivery receipt.
    pub(super) fn push(&mut self, frame: ConnectionFrame) -> Result<u64, DispatchError> {
        let cost = frame_cost(&frame);
        if self.queued_bytes + self.in_flight_bytes + cost > self.limit_bytes {
            return Err(DispatchError::Overflow {
                limit: self.limit_bytes,
            });
        }
        self.queued_bytes += cost;
        self.enqueued += 1;
        let mark = self.enqueued;
        self.queue.push_back((mark, frame));
        Ok(mark)
    }

    /// Streamed frames are pulled only while the outbox has room; requests
    /// and their answers are never held behind this.
    pub(super) fn has_room(&self) -> bool {
        self.queued_bytes + self.in_flight_bytes < STREAM_ROOM_BYTES
    }

    pub(super) fn busy(&self) -> bool {
        self.in_flight.is_some() || !self.queue.is_empty()
    }

    /// Drives the write in flight (starting the next queued one) until it
    /// completes. Cancel-safe: the write lives in `self`, never in this
    /// future, so a select that drops this future loses nothing.
    pub(super) async fn progress(&mut self) -> Result<(), DispatchError> {
        if self.in_flight.is_none() {
            self.start_next();
        }
        let Some((write, deadline, _)) = self.in_flight.as_mut() else {
            return Ok(());
        };
        match tokio::time::timeout_at(*deadline, write.as_mut()).await {
            Ok((writer, sent)) => {
                let (_, _, mark) = self.in_flight.take().expect("write in flight");
                self.in_flight_bytes = 0;
                self.writer = Some(writer);
                if sent.is_ok() {
                    self.written.store(mark, Ordering::Release);
                }
                sent.map_err(DispatchError::Transport)
            }
            Err(_) => {
                tracing::warn!(
                    device = %self.device,
                    bound_s = SEND_BOUND.as_secs(),
                    outbox_bytes = self.queued_bytes + self.in_flight_bytes,
                    "huginn send_stalled"
                );
                Err(DispatchError::Stalled {
                    seconds: SEND_BOUND.as_secs(),
                })
            }
        }
    }

    pub(super) fn receipt(&self, mark: u64) -> DeliveryReceipt {
        DeliveryReceipt {
            written: Arc::clone(&self.written),
            mark,
        }
    }

    fn start_next(&mut self) {
        let Some(mut writer) = self.writer.take() else {
            return;
        };
        let Some((mark, frame)) = self.queue.pop_front() else {
            self.writer = Some(writer);
            return;
        };
        let cost = frame_cost(&frame);
        self.queued_bytes = self.queued_bytes.saturating_sub(cost);
        self.in_flight_bytes = cost;
        let write: Write<W> = Box::pin(async move {
            let sent = writer.send(frame).await;
            (writer, sent)
        });
        self.in_flight = Some((write, Instant::now() + SEND_BOUND, mark));
    }

    /// Enqueues a frame that must not be refused by the outbox bound (the
    /// revocation or close notice of an already-full connection), keeping
    /// the same mark and byte accounting as [`Self::push`].
    fn enqueue_unbounded(&mut self, frame: ConnectionFrame) {
        self.queued_bytes += frame_cost(&frame);
        self.enqueued += 1;
        self.queue.push_back((self.enqueued, frame));
    }

    /// Ends the connection within [`CLOSE_BOUND`] of `told`: the write in
    /// flight finishes, then `last` (a reason, when there is one) and a
    /// close. Queued application data goes first only when `keep_queue`;
    /// a revoked or stopping connection discards it. Answers the frames
    /// discarded.
    pub(super) async fn close(
        mut self,
        told: Instant,
        keep_queue: bool,
        last: Option<ConnectionFrame>,
    ) -> usize {
        let discarded = if keep_queue { 0 } else { self.queue.len() };
        if !keep_queue {
            self.queue.clear();
            self.queued_bytes = 0;
        }
        if let Some(frame) = last {
            self.enqueue_unbounded(frame);
        }
        self.enqueue_unbounded(ConnectionFrame::Close);
        let _ = tokio::time::timeout_at(told + CLOSE_BOUND, async {
            while self.busy() {
                if self.progress().await.is_err() {
                    break;
                }
            }
        })
        .await;
        discarded
    }
}

fn frame_cost(frame: &ConnectionFrame) -> usize {
    FRAME_OVERHEAD_BYTES
        + match frame {
            ConnectionFrame::Binary(bytes)
            | ConnectionFrame::Ping(bytes)
            | ConnectionFrame::Pong(bytes) => bytes.len(),
            ConnectionFrame::Text | ConnectionFrame::Close => 0,
        }
}

/// Why a served connection must end now, whatever it was doing.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Ending {
    /// The device was revoked: it is told so before the close.
    Revoked,
    /// The registry let the connection go without a revocation.
    Released,
    /// The daemon is stopping: the client reconnects to the next one.
    Stopping,
}

impl Ending {
    pub(super) const fn as_str(self) -> &'static str {
        match self {
            Self::Revoked => "revoked",
            Self::Released => "released",
            Self::Stopping => "stopping",
        }
    }
}

/// The registration's revocation and the daemon's stop, observed together.
pub(super) struct Control {
    revocation: watch::Receiver<bool>,
    stopping: watch::Receiver<bool>,
}

impl Control {
    pub(super) fn new(registration: &ConnectionRegistration) -> Self {
        Self {
            revocation: registration.revocation(),
            stopping: registration.stopping(),
        }
    }

    /// Resolves when the connection must end. Cancel-safe.
    pub(super) async fn ended(&mut self) -> Ending {
        let stopping = &mut self.stopping;
        tokio::select! {
            biased;
            changed = self.revocation.changed() => {
                if changed.is_ok() && *self.revocation.borrow() {
                    Ending::Revoked
                } else {
                    Ending::Released
                }
            }
            () = async {
                if stopping.wait_for(|stopping| *stopping).await.is_err() {
                    std::future::pending::<()>().await;
                }
            } => Ending::Stopping,
        }
    }
}

/// Runs `work` (a request's dispatch) while the connection's writes keep
/// draining, and gives it up the moment the connection must end: a
/// revoked or stopping connection never waits on an outstanding command.
pub(super) async fn until_ended<F, W>(
    work: F,
    control: &mut Control,
    outbound: &mut Outbound<W>,
) -> Result<Result<F::Output, Ending>, DispatchError>
where
    F: Future,
    W: FrameWriter,
{
    tokio::pin!(work);
    loop {
        tokio::select! {
            biased;
            ending = control.ended() => return Ok(Err(ending)),
            sent = outbound.progress(), if outbound.busy() => sent?,
            output = &mut work => return Ok(Ok(output)),
        }
    }
}
