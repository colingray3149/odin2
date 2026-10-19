//! Bounded durable telemetry rings and the compact model-facing projection.

use std::collections::VecDeque;
use std::num::{NonZeroU64, NonZeroUsize};

use crate::kube::SurfaceArtifacts;
use odin_domain::huginn::{
    ArtifactKind, HuginnProtocolError, LiveStreamKind, LiveStreamMode, Sequence,
    SimulationOutputId, SimulationTelemetryView, StreamBackpressureLimits, StreamFrame, StreamId,
    StreamLifecycle, StreamStatus,
};
use odin_domain::{Digest, RunId};
use serde::{Deserialize, Serialize};
use time::{Duration, OffsetDateTime};

pub type Result<T, E = HuginnProtocolError> = std::result::Result<T, E>;

/// The only simulation data shape that reaches a model stream: counts, digests, and revision
/// links. Raw numerical series and named fields stay in the referenced artifact, so raw-field
/// model injection is unrepresentable.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CompactTelemetry {
    pub run_id: RunId,
    pub output_id: SimulationOutputId,
    pub sequence: Sequence,
    pub control_revision: u64,
    pub sample_count: u64,
    pub truncated: bool,
    pub recorded_at: OffsetDateTime,
    pub content_digest: String,
}

impl CompactTelemetry {
    pub fn of(batch: &SimulationTelemetryView) -> Self {
        Self {
            run_id: batch.run_id.clone(),
            output_id: batch.output_id,
            sequence: batch.sequence,
            control_revision: batch.control_revision,
            sample_count: batch.sample_count,
            truncated: batch.truncated,
            recorded_at: batch.recorded_at,
            content_digest: batch.content.content_digest.to_string(),
        }
    }

    /// Builds the model-stream frame whose content is the compact summary document, never the
    /// raw batch.
    pub fn model_frame(
        &self,
        artifacts: &mut SurfaceArtifacts,
        frame_artifact_id: odin_domain::ArtifactId,
        stream_id: StreamId,
        at: OffsetDateTime,
    ) -> Result<StreamFrame> {
        let document =
            serde_json::to_vec(self).map_err(|error| HuginnProtocolError::InvalidRequest {
                code: "compactTelemetry".to_string(),
                message: error.to_string(),
            })?;
        let content = artifacts.publish(
            frame_artifact_id,
            ArtifactKind::File,
            "simulation-telemetry-compact",
            "application/json",
            &document,
        )?;
        Ok(StreamFrame {
            stream_id,
            kind: LiveStreamKind::SimulationTelemetry,
            sequence: self.sequence,
            control_revision: self.control_revision,
            produced_at: at,
            key_frame: false,
            content,
        })
    }
}

/// Durable, bounded telemetry queue for one run. Overflow closes exactly this queue; reconnect
/// replays from the retained cursor.
pub struct TelemetryRing {
    run_id: RunId,
    stream_id: StreamId,
    batches: VecDeque<SimulationTelemetryView>,
    max_batches: NonZeroUsize,
    max_bytes: NonZeroU64,
    limits: StreamBackpressureLimits,
    buffered_bytes: u64,
    last_delivered: Option<Sequence>,
    last_enqueued: Option<Sequence>,
    control_revision: u64,
    lifecycle: StreamLifecycle,
    last_poll_at: Option<OffsetDateTime>,
    failure: Option<String>,
}

impl TelemetryRing {
    pub fn new(
        run_id: RunId,
        stream_id: StreamId,
        max_batches: NonZeroUsize,
        max_bytes: NonZeroU64,
        limits: StreamBackpressureLimits,
    ) -> Self {
        Self {
            run_id,
            stream_id,
            batches: VecDeque::new(),
            max_batches,
            max_bytes,
            limits,
            buffered_bytes: 0,
            last_delivered: None,
            last_enqueued: None,
            control_revision: 0,
            lifecycle: StreamLifecycle::Live,
            last_poll_at: None,
            failure: None,
        }
    }

    pub fn run_id(&self) -> &RunId {
        &self.run_id
    }

    pub fn stream_id(&self) -> &StreamId {
        &self.stream_id
    }

    pub fn lifecycle(&self) -> StreamLifecycle {
        self.lifecycle
    }

    pub fn close(&mut self, failure: String) {
        self.lifecycle = StreamLifecycle::Closed;
        self.failure = Some(failure);
    }

    /// Enqueues one telemetry batch. The raw bytes are digest-verified here and never retained;
    /// only the artifact-referencing view enters the ring.
    pub fn push(&mut self, batch: SimulationTelemetryView, raw_bytes: &[u8]) -> Result<()> {
        if matches!(
            self.lifecycle,
            StreamLifecycle::Closed | StreamLifecycle::Failed
        ) {
            return Err(HuginnProtocolError::Unavailable {
                code: "simulationTelemetryQueueClosed".to_string(),
            });
        }
        if batch.run_id != self.run_id {
            return Err(HuginnProtocolError::InvalidRequest {
                code: "simulationTelemetryIdentity".to_string(),
                message: "telemetry batch does not belong to this run".to_string(),
            });
        }
        if self
            .last_enqueued
            .is_some_and(|head| batch.sequence <= head)
        {
            return Err(HuginnProtocolError::Conflict {
                code: "simulationTelemetrySequence".to_string(),
                message: format!(
                    "telemetry sequence {} does not exceed the enqueued head",
                    batch.sequence
                ),
            });
        }
        if Digest::hash(raw_bytes) != batch.content.content_digest {
            return Err(HuginnProtocolError::InvalidRequest {
                code: "simulationTelemetryDigest".to_string(),
                message: "telemetry batch bytes do not match the published artifact digest"
                    .to_string(),
            });
        }
        let raw_len = u64::try_from(raw_bytes.len()).unwrap_or(u64::MAX);
        if raw_len != batch.content.byte_len {
            return Err(HuginnProtocolError::InvalidRequest {
                code: "simulationTelemetryLength".to_string(),
                message: "telemetry batch length does not match the published artifact".to_string(),
            });
        }
        let max_item_bytes = self.limits.max_item_bytes.get();
        if raw_len > self.max_bytes.get() || raw_len > max_item_bytes {
            return Err(HuginnProtocolError::ResourceLimit {
                limit: "simulationTelemetryBatchBytes".to_string(),
            });
        }
        if self.batches.len() >= self.max_batches.get()
            || self.buffered_bytes.saturating_add(raw_len) > self.max_bytes.get()
        {
            self.close("telemetry queue overflowed its declared bounds".to_string());
            return Err(HuginnProtocolError::ResourceLimit {
                limit: "simulationTelemetryQueue".to_string(),
            });
        }

        self.buffered_bytes += raw_len;
        self.control_revision = batch.control_revision;
        self.last_enqueued = Some(batch.sequence);
        self.batches.push_back(batch);
        Ok(())
    }

    /// Delivers the next retained batch in durable order; recovers from stalled on activity.
    pub fn take(&mut self, at: OffsetDateTime) -> Option<SimulationTelemetryView> {
        self.last_poll_at = Some(at);
        if self.lifecycle == StreamLifecycle::Stalled {
            self.lifecycle = StreamLifecycle::Live;
        }
        let batch = self.batches.pop_front()?;
        self.buffered_bytes = self.buffered_bytes.saturating_sub(batch.content.byte_len);
        self.last_delivered = Some(batch.sequence);
        Some(batch)
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
            kind: LiveStreamKind::SimulationTelemetry,
            mode: LiveStreamMode::Durable,
            lifecycle: self.lifecycle,
            durable_head: self.last_enqueued,
            last_delivered: self.last_delivered,
            control_revision: self.control_revision,
            buffered_items: u32::try_from(self.batches.len()).unwrap_or(u32::MAX),
            buffered_bytes: self.buffered_bytes,
            dropped_items: 0,
            limits: self.limits,
            updated_at: at,
            failure: self.failure.clone(),
        }
    }
}
