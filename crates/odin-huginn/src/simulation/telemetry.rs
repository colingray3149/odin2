//! Bounded durable telemetry rings and the compact model-facing projection.

use std::collections::VecDeque;
use std::num::{NonZeroU64, NonZeroUsize};

use crate::kube::SurfaceArtifacts;
use odin_domain::huginn::{
    ArtifactKind, HuginnProtocolError, LiveStreamKind, Sequence, SimulationOutputId,
    SimulationTelemetryView, StreamBackpressureLimits, StreamFrame, StreamId, StreamLifecycle,
};
use odin_domain::{Digest, RunId};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

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
            failure: None,
        }
    }

    pub fn stream_id(&self) -> &StreamId {
        &self.stream_id
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
            return Err(HuginnProtocolError::unavailable(
                "simulationTelemetryQueueClosed",
                format!("the telemetry queue is {:?}", self.lifecycle),
            ));
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

    /// Delivers the next retained batch in durable order.
    pub fn take(&mut self) -> Option<SimulationTelemetryView> {
        let batch = self.batches.pop_front()?;
        self.buffered_bytes = self.buffered_bytes.saturating_sub(batch.content.byte_len);
        self.last_delivered = Some(batch.sequence);
        Some(batch)
    }
}

#[cfg(test)]
mod tests {
    use std::num::{NonZeroU32, NonZeroU64, NonZeroUsize};

    use odin_domain::huginn::{
        ArtifactKind, ArtifactRef, HuginnProtocolError, LiveSessionId, Sequence,
        SimulationOutputId, SimulationTelemetryView, StreamBackpressureLimits, StreamId,
    };
    use odin_domain::{ArtifactId, Digest, LaneId, RunId};
    use time::OffsetDateTime;

    use super::TelemetryRing;

    const RAW: &[u8] = b"0123456789";

    fn batch(run: &str, sequence: u64, raw: &[u8]) -> SimulationTelemetryView {
        SimulationTelemetryView {
            run_id: RunId::new(run).unwrap(),
            output_id: SimulationOutputId::parse("00000000-0000-4000-8000-00000000000a").unwrap(),
            sequence: Sequence::new(sequence),
            control_revision: 1,
            recorded_at: OffsetDateTime::UNIX_EPOCH,
            sample_count: 1,
            content: ArtifactRef {
                artifact_id: ArtifactId::parse("00000000-0000-4000-8000-000000000002").unwrap(),
                session_id: LiveSessionId::parse("00000000-0000-4000-8000-000000000003").unwrap(),
                lane_id: LaneId::new("lane-sim").unwrap(),
                kind: ArtifactKind::File,
                display_name: "telemetry.bin".to_owned(),
                media_type: "application/octet-stream".to_owned(),
                byte_len: raw.len() as u64,
                content_digest: Digest::hash(raw),
            },
            truncated: false,
        }
    }

    fn ring(max_batches: usize) -> TelemetryRing {
        TelemetryRing::new(
            RunId::new("run-1").unwrap(),
            StreamId::parse("00000000-0000-4000-8000-000000000001").unwrap(),
            NonZeroUsize::new(max_batches).unwrap(),
            NonZeroU64::new(1024).unwrap(),
            StreamBackpressureLimits {
                max_buffered_items: NonZeroU32::new(8).unwrap(),
                max_buffered_bytes: NonZeroU64::new(1024).unwrap(),
                max_item_bytes: NonZeroU64::new(64).unwrap(),
                max_items_per_second: NonZeroU32::new(8).unwrap(),
                max_in_flight_bytes: NonZeroU64::new(1024).unwrap(),
            },
        )
    }

    fn code(error: HuginnProtocolError) -> String {
        match error {
            HuginnProtocolError::InvalidRequest { code, .. }
            | HuginnProtocolError::Conflict { code, .. } => code,
            HuginnProtocolError::ResourceLimit { limit } => limit,
            other => panic!("unexpected {other}"),
        }
    }

    #[test]
    fn telemetry_that_does_not_match_its_artifact_or_order_never_enters_the_ring() {
        let mut ring = ring(2);
        ring.push(batch("run-1", 1, RAW), RAW).unwrap();

        let refused = [
            (batch("run-2", 2, RAW), RAW, "simulationTelemetryIdentity"),
            (batch("run-1", 1, RAW), RAW, "simulationTelemetrySequence"),
            (
                batch("run-1", 2, RAW),
                b"other bytes",
                "simulationTelemetryDigest",
            ),
        ];
        for (view, bytes, expected) in refused {
            assert_eq!(code(ring.push(view, bytes).unwrap_err()), expected);
        }
        let mut short = batch("run-1", 2, RAW);
        short.content.byte_len += 1;
        assert_eq!(
            code(ring.push(short, RAW).unwrap_err()),
            "simulationTelemetryLength"
        );
        assert_eq!(
            ring.take().map(|taken| taken.sequence),
            Some(Sequence::new(1))
        );
        assert!(ring.take().is_none(), "nothing refused was kept");

        // Past its declared depth the ring closes, and a closed ring takes nothing more.
        ring.push(batch("run-1", 2, RAW), RAW).unwrap();
        ring.push(batch("run-1", 3, RAW), RAW).unwrap();
        assert_eq!(
            code(ring.push(batch("run-1", 4, RAW), RAW).unwrap_err()),
            "simulationTelemetryQueue"
        );
        assert!(matches!(
            ring.push(batch("run-1", 5, RAW), RAW),
            Err(HuginnProtocolError::Unavailable { .. })
        ));
    }
}
