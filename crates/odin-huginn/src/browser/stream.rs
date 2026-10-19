//! Lossy, bounded browser frame streams. Dropped frames change counters, never control truth.

use std::collections::VecDeque;
use std::num::{NonZeroU32, NonZeroUsize};

use odin_domain::huginn::{
    BrowserSessionId, HuginnProtocolError, LiveStreamKind, LiveStreamMode, Sequence,
    StreamBackpressureLimits, StreamFrame, StreamId, StreamLifecycle, StreamStatus,
};
use time::Duration;
use time::OffsetDateTime;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FrameEnqueue {
    Buffered,
    /// Incoming frame dropped because the per-second pacing cap was hit.
    DroppedRate,
    /// Oldest buffered frame evicted to make room (latest-frame semantics).
    EvictedOldest,
}

/// A paced latest-frame queue; frame loss never changes revisioned session or takeover state.
pub struct BrowserFrameStream {
    session_id: BrowserSessionId,
    stream_id: StreamId,
    queue: VecDeque<StreamFrame>,
    frame_queue_depth: NonZeroUsize,
    max_frames_per_second: NonZeroU32,
    max_stream_frame_bytes: NonZeroUsize,
    limits: StreamBackpressureLimits,
    recent_frames: VecDeque<OffsetDateTime>,
    dropped_items: u64,
    buffered_bytes: u64,
    last_delivered: Option<Sequence>,
    last_enqueued: Option<Sequence>,
    control_revision: u64,
    lifecycle: StreamLifecycle,
    last_poll_at: Option<OffsetDateTime>,
    failure: Option<String>,
}

impl BrowserFrameStream {
    pub fn new(
        session_id: BrowserSessionId,
        stream_id: StreamId,
        frame_queue_depth: NonZeroUsize,
        max_frames_per_second: NonZeroU32,
        max_stream_frame_bytes: NonZeroUsize,
        limits: StreamBackpressureLimits,
    ) -> Self {
        Self {
            session_id,
            stream_id,
            queue: VecDeque::new(),
            frame_queue_depth,
            max_frames_per_second,
            max_stream_frame_bytes,
            limits,
            recent_frames: VecDeque::new(),
            dropped_items: 0,
            buffered_bytes: 0,
            last_delivered: None,
            last_enqueued: None,
            control_revision: 0,
            lifecycle: StreamLifecycle::Live,
            last_poll_at: None,
            failure: None,
        }
    }

    pub fn session_id(&self) -> &BrowserSessionId {
        &self.session_id
    }

    pub fn stream_id(&self) -> &StreamId {
        &self.stream_id
    }

    pub fn lifecycle(&self) -> StreamLifecycle {
        self.lifecycle
    }

    pub fn fail(&mut self, failure: String) {
        self.lifecycle = StreamLifecycle::Failed;
        self.failure = Some(failure);
    }

    pub fn close(&mut self) {
        self.lifecycle = StreamLifecycle::Closed;
    }

    fn prune_rate_window(&mut self, produced_at: OffsetDateTime) {
        let window_start = produced_at - Duration::seconds(1);
        while self
            .recent_frames
            .front()
            .is_some_and(|oldest| *oldest < window_start)
        {
            self.recent_frames.pop_front();
        }
    }

    /// Enqueues one produced frame. Oversized payloads are rejected outright; pacing and queue
    /// overflow are absorbed as visible loss.
    pub fn enqueue(&mut self, frame: StreamFrame) -> Result<FrameEnqueue, HuginnProtocolError> {
        if matches!(
            self.lifecycle,
            StreamLifecycle::Closed | StreamLifecycle::Failed
        ) {
            return Err(HuginnProtocolError::Unavailable {
                code: "browserFrameStreamClosed".to_string(),
            });
        }
        if frame.kind != LiveStreamKind::BrowserFrames || frame.stream_id != self.stream_id {
            return Err(HuginnProtocolError::InvalidRequest {
                code: "browserFrameIdentity".to_string(),
                message: "frame does not belong to this browser frame stream".to_string(),
            });
        }
        let frame_bytes = frame.content.byte_len;
        if frame_bytes > u64::try_from(self.max_stream_frame_bytes.get()).unwrap_or(u64::MAX) {
            return Err(HuginnProtocolError::ResourceLimit {
                limit: "browserFrameBytes".to_string(),
            });
        }
        if self
            .last_enqueued
            .is_some_and(|head| frame.sequence <= head)
        {
            return Err(HuginnProtocolError::Conflict {
                code: "browserFrameSequence".to_string(),
                message: format!(
                    "frame sequence {} does not exceed the enqueued head",
                    frame.sequence
                ),
            });
        }

        self.prune_rate_window(frame.produced_at);
        if self.recent_frames.len() >= self.max_frames_per_second.get() as usize {
            self.dropped_items += 1;
            return Ok(FrameEnqueue::DroppedRate);
        }

        let max_buffered_bytes = self.limits.max_buffered_bytes.get();
        if frame_bytes > max_buffered_bytes {
            return Err(HuginnProtocolError::ResourceLimit {
                limit: "browserFrameBufferBytes".to_string(),
            });
        }
        let mut outcome = FrameEnqueue::Buffered;
        while self.queue.len() >= self.frame_queue_depth.get()
            || self.buffered_bytes.saturating_add(frame_bytes) > max_buffered_bytes
        {
            match self.queue.pop_front() {
                Some(evicted) => {
                    self.buffered_bytes -= evicted.content.byte_len;
                    self.dropped_items += 1;
                    outcome = FrameEnqueue::EvictedOldest;
                }
                None => break,
            }
        }

        self.recent_frames.push_back(frame.produced_at);
        self.buffered_bytes += frame_bytes;
        self.control_revision = frame.control_revision;
        self.last_enqueued = Some(frame.sequence);
        self.queue.push_back(frame);
        Ok(outcome)
    }

    /// Delivers the next buffered frame; recovering from a stalled lifecycle on activity.
    pub fn take(&mut self, at: OffsetDateTime) -> Option<StreamFrame> {
        self.last_poll_at = Some(at);
        if self.lifecycle == StreamLifecycle::Stalled {
            self.lifecycle = StreamLifecycle::Live;
        }
        let frame = self.queue.pop_front()?;
        self.buffered_bytes -= frame.content.byte_len;
        self.last_delivered = Some(frame.sequence);
        Some(frame)
    }

    pub fn mark_stalled(&mut self, now: OffsetDateTime, stall_window: Duration) {
        if self.lifecycle != StreamLifecycle::Live {
            return;
        }
        if let Some(last_poll_at) = self.last_poll_at {
            if now - last_poll_at > stall_window {
                self.lifecycle = StreamLifecycle::Stalled;
            }
        }
    }

    pub fn status(&self, at: OffsetDateTime) -> StreamStatus {
        StreamStatus {
            stream_id: self.stream_id,
            kind: LiveStreamKind::BrowserFrames,
            mode: LiveStreamMode::LatestFrame,
            lifecycle: self.lifecycle,
            durable_head: None,
            last_delivered: self.last_delivered,
            control_revision: self.control_revision,
            buffered_items: u32::try_from(self.queue.len()).unwrap_or(u32::MAX),
            buffered_bytes: self.buffered_bytes,
            dropped_items: self.dropped_items,
            limits: self.limits,
            updated_at: at,
            failure: self.failure.clone(),
        }
    }
}
