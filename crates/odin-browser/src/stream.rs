//! Bounded latest-frame stream projecting Playwright worker frames into the
//! frozen domain views.
//!
//! The stream bounds both the encoded (base64 transport) and decoded frame
//! payloads, retains only the newest frame, allocates an increasing sequence
//! that is independent of the control revision, and validates the publisher
//! returned [`ArtifactRef`] against the exact bytes before any
//! [`BrowserFrameView`] or [`StreamFrame`] is constructed. Frame loss is a
//! delivery fact counted here; it never mutates control truth.

use std::num::NonZeroU32;
use std::sync::{Arc, Mutex, MutexGuard};

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use odin_domain::huginn::artifact::{ArtifactKind, ArtifactRef};
use odin_domain::huginn::browser::BrowserFrameView;
use odin_domain::huginn::ids::{BrowserSessionId, Sequence, StreamId};
use odin_domain::huginn::stream::{LiveStreamKind, StreamFrame};
use odin_domain::huginn::RenderKind;
use odin_domain::Digest;
use thiserror::Error;
use time::OffsetDateTime;

use crate::capability::{ArtifactPublication, ArtifactPublisher, CapabilityError, PublicationKind};
use crate::config::FrameLimits;

/// One bounded frame received from the private Playwright worker, still
/// base64 encoded.
#[derive(Clone, Debug)]
pub struct IncomingFrame {
    /// Revision of the control view observed when this frame was received.
    /// Carried into the projections verbatim; never used for ordering.
    pub control_revision: u64,
    pub captured_at: OffsetDateTime,
    pub key_frame: bool,
    /// Number of protected runtime-value regions masked in the captured image.
    pub masked_runtime_value_regions: u32,
    /// Base64 transport payload exactly as the worker delivered it.
    pub encoded: Vec<u8>,
}

/// The validated frame record: the frozen frame view and its stream item,
/// plus the worker-reported count retained as acceptance evidence without
/// changing the domain [`BrowserFrameView`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FrameRecord {
    pub view: BrowserFrameView,
    pub frame: StreamFrame,
    pub masked_runtime_value_regions: u32,
}

/// Delivery counters. Dropped and rejected frames are facts, never control
/// state.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct FrameCounters {
    pub accepted: u64,
    pub dropped_stale: u64,
    pub rejected_encoded_bound: u64,
    pub rejected_decoded_bound: u64,
    pub rejected_encoding: u64,
    pub rejected_empty_payload: u64,
    pub rejected_dimensions: u64,
    pub rejected_publication: u64,
    pub rejected_binding: u64,
    pub rejected_stream_disabled: u64,
}

/// Errors raised while admitting one frame. The previous latest frame stays
/// intact in every case.
#[derive(Debug, Error)]
pub enum FrameStreamError {
    /// The session was composed with owner frame streaming disabled; the
    /// frame is dropped before any decode or publication.
    #[error("owner frame streaming is disabled for this session")]
    StreamingDisabled,
    #[error("encoded frame is {size} bytes; limit is {limit}")]
    EncodedBound { size: u64, limit: u64 },
    #[error("decoded frame is {size} bytes; limit is {limit}")]
    DecodedBound { size: u64, limit: u64 },
    #[error("decoded frame payload is empty")]
    EmptyPayload,
    #[error("frame payload is not valid base64")]
    InvalidEncoding,
    #[error("frame raster dimensions are invalid: {reason}")]
    InvalidDimensions { reason: &'static str },
    #[error("frame publication failed: {0}")]
    Publication(#[source] Box<CapabilityError>),
    #[error("published frame artifact does not match the frame bytes: {reason}")]
    ArtifactBinding { reason: &'static str },
    #[error("frame sequence overflowed")]
    SequenceOverflow,
    #[error("frame sequence {sequence} was superseded before retention")]
    Superseded { sequence: Sequence },
}

impl From<CapabilityError> for FrameStreamError {
    fn from(error: CapabilityError) -> Self {
        Self::Publication(Box::new(error))
    }
}

struct Slot {
    last_sequence: Option<Sequence>,
    latest: Option<FrameRecord>,
    counters: FrameCounters,
}

/// The per-session frame stream. Only the session event router feeds it;
/// callers may concurrently read the retained latest record and counters.
///
/// `stream_enabled` is the composition-time owner-frame publication gate:
/// when `false`, `offer` refuses every frame before any decode, publication,
/// or retention, so a stream-disabled session publishes nothing.
pub struct FrameStream {
    stream_id: StreamId,
    session_id: BrowserSessionId,
    stream_enabled: bool,
    limits: FrameLimits,
    publisher: Arc<dyn ArtifactPublisher>,
    slot: Mutex<Slot>,
}

impl FrameStream {
    pub fn new(
        stream_id: StreamId,
        session_id: BrowserSessionId,
        stream_enabled: bool,
        limits: FrameLimits,
        publisher: Arc<dyn ArtifactPublisher>,
    ) -> Self {
        Self {
            stream_id,
            session_id,
            stream_enabled,
            limits,
            publisher,
            slot: Mutex::new(Slot {
                last_sequence: None,
                latest: None,
                counters: FrameCounters::default(),
            }),
        }
    }

    pub fn stream_id(&self) -> StreamId {
        self.stream_id
    }

    /// Sequence is allocated here and strictly increases per accepted frame;
    /// it is independent of `control_revision`, which is per-frame metadata.
    /// Rejections (disabled streaming, bounds, encoding, dimensions,
    /// publication, binding) drop the frame, bump a counter, and leave the
    /// retained latest frame untouched.
    pub(crate) fn offer(&self, frame: IncomingFrame) -> Result<FrameRecord, FrameStreamError> {
        if !self.stream_enabled {
            let mut slot = self.lock();
            increment(&mut slot.counters.rejected_stream_disabled);
            return Err(FrameStreamError::StreamingDisabled);
        }
        let encoded_size = frame.encoded.len() as u64;
        let encoded_limit = u64::from(self.limits.max_encoded_frame_bytes.get());
        if encoded_size > encoded_limit {
            let mut slot = self.lock();
            increment(&mut slot.counters.rejected_encoded_bound);
            return Err(FrameStreamError::EncodedBound {
                size: encoded_size,
                limit: encoded_limit,
            });
        }

        let decoded = match STANDARD.decode(&frame.encoded) {
            Ok(decoded) => decoded,
            Err(_) => {
                let mut slot = self.lock();
                increment(&mut slot.counters.rejected_encoding);
                return Err(FrameStreamError::InvalidEncoding);
            }
        };
        let decoded_size = decoded.len() as u64;
        if decoded.is_empty() {
            let mut slot = self.lock();
            increment(&mut slot.counters.rejected_empty_payload);
            return Err(FrameStreamError::EmptyPayload);
        }
        let decoded_limit = u64::from(self.limits.max_decoded_frame_bytes.get());
        if decoded_size > decoded_limit {
            let mut slot = self.lock();
            increment(&mut slot.counters.rejected_decoded_bound);
            return Err(FrameStreamError::DecodedBound {
                size: decoded_size,
                limit: decoded_limit,
            });
        }

        let (width, height) = match jpeg_dimensions(&decoded) {
            Ok(dimensions) => dimensions,
            Err(reason) => {
                let mut slot = self.lock();
                increment(&mut slot.counters.rejected_dimensions);
                return Err(FrameStreamError::InvalidDimensions { reason });
            }
        };

        let sequence = self.next_sequence()?;
        let digest = Digest::hash(&decoded);
        let display_name = format!("frame-{}", sequence.get());
        let artifact = match self.publisher.publish(ArtifactPublication {
            session_id: self.session_id,
            kind: PublicationKind::Frame,
            display_name: display_name.clone(),
            media_type: "image/jpeg".to_owned(),
            content_digest: digest,
            bytes: decoded,
        }) {
            Ok(artifact) => artifact,
            Err(error) => {
                let mut slot = self.lock();
                increment(&mut slot.counters.rejected_publication);
                return Err(error.into());
            }
        };
        if let Err(error) = validate_frame_artifact(&artifact, decoded_size, digest) {
            let mut slot = self.lock();
            increment(&mut slot.counters.rejected_binding);
            return Err(error);
        }
        if artifact.display_name != display_name {
            let mut slot = self.lock();
            increment(&mut slot.counters.rejected_binding);
            return Err(FrameStreamError::ArtifactBinding {
                reason: "display name disagrees with the frame publication",
            });
        }

        let record = FrameRecord {
            view: BrowserFrameView {
                session_id: self.session_id,
                frame_number: sequence,
                control_revision: frame.control_revision,
                captured_at: frame.captured_at,
                width,
                height,
                key_frame: frame.key_frame,
                content: artifact.clone(),
            },
            frame: StreamFrame {
                stream_id: self.stream_id,
                kind: LiveStreamKind::BrowserFrames,
                sequence,
                control_revision: frame.control_revision,
                produced_at: frame.captured_at,
                key_frame: frame.key_frame,
                content: artifact,
            },
            masked_runtime_value_regions: frame.masked_runtime_value_regions,
        };
        if !self.retain(sequence, record.clone()) {
            return Err(FrameStreamError::Superseded { sequence });
        }
        let mut slot = self.lock();
        increment(&mut slot.counters.accepted);
        Ok(record)
    }

    /// The retained latest frame, if any.
    pub fn latest(&self) -> Option<FrameRecord> {
        self.lock().latest.clone()
    }

    /// Current delivery counters.
    pub fn counters(&self) -> FrameCounters {
        self.lock().counters
    }

    fn next_sequence(&self) -> Result<Sequence, FrameStreamError> {
        let mut slot = self.lock();
        let next = match slot.last_sequence {
            Some(previous) => previous
                .checked_increment()
                .ok_or(FrameStreamError::SequenceOverflow)?,
            None => Sequence::new(1),
        };
        slot.last_sequence = Some(next);
        Ok(next)
    }

    fn retain(&self, sequence: Sequence, record: FrameRecord) -> bool {
        let mut slot = self.lock();
        let newer = slot
            .latest
            .as_ref()
            .is_none_or(|current| sequence > current.view.frame_number);
        if newer {
            slot.latest = Some(record);
            true
        } else {
            increment(&mut slot.counters.dropped_stale);
            false
        }
    }

    fn lock(&self) -> MutexGuard<'_, Slot> {
        self.slot
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

fn increment(counter: &mut u64) {
    *counter = counter.saturating_add(1);
}

/// Validates the publisher-returned [`ArtifactRef`] against the exact frame
/// bytes and the frozen artifact rules. The session-owned frame admission
/// path calls this before constructing any projection.
pub fn validate_frame_artifact(
    artifact: &ArtifactRef,
    byte_len: u64,
    digest: Digest,
) -> Result<(), FrameStreamError> {
    let reason = match &artifact.kind {
        ArtifactKind::Render(RenderKind::RasterImage) if artifact.media_type == "image/jpeg" => {
            if artifact.byte_len != byte_len {
                Some("byte length disagrees with the frame bytes")
            } else if artifact.content_digest != digest {
                Some("digest disagrees with the frame bytes")
            } else {
                None
            }
        }
        _ => Some("kind or media type is not a raster frame"),
    };
    match reason {
        Some(reason) => Err(FrameStreamError::ArtifactBinding { reason }),
        None => Ok(()),
    }
}

fn jpeg_dimensions(bytes: &[u8]) -> Result<(NonZeroU32, NonZeroU32), &'static str> {
    if !bytes.starts_with(&[0xff, 0xd8]) {
        return Err("payload does not start with a JPEG SOI marker");
    }

    let mut cursor = 2usize;
    loop {
        if bytes.get(cursor) != Some(&0xff) {
            return Err("JPEG ended or contains data before a SOF marker");
        }
        while bytes.get(cursor) == Some(&0xff) {
            cursor = cursor
                .checked_add(1)
                .ok_or("JPEG marker offset overflowed")?;
        }
        let marker = *bytes
            .get(cursor)
            .ok_or("JPEG marker is truncated before a SOF marker")?;
        cursor = cursor
            .checked_add(1)
            .ok_or("JPEG marker offset overflowed")?;

        match marker {
            0x00 => return Err("JPEG contains an escaped byte outside scan data"),
            0xd8 => return Err("JPEG contains a duplicate SOI marker"),
            0xd9 => return Err("JPEG ended before a SOF marker"),
            0x01 | 0xd0..=0xd7 => continue,
            _ => {}
        }

        let length_end = cursor
            .checked_add(2)
            .ok_or("JPEG segment length offset overflowed")?;
        let length_bytes = bytes
            .get(cursor..length_end)
            .ok_or("JPEG segment length is truncated")?;
        let segment_length = usize::from(u16::from_be_bytes([length_bytes[0], length_bytes[1]]));
        if segment_length < 2 {
            return Err("JPEG segment length is smaller than its length field");
        }
        let segment_end = cursor
            .checked_add(segment_length)
            .filter(|end| *end <= bytes.len())
            .ok_or("JPEG segment exceeds the decoded frame buffer")?;

        if is_jpeg_sof(marker) {
            if segment_length < 8 {
                return Err("JPEG SOF segment is too short");
            }
            let component_count = usize::from(bytes[cursor + 7]);
            let expected_length = 8usize
                .checked_add(
                    component_count
                        .checked_mul(3)
                        .ok_or("JPEG SOF component length overflowed")?,
                )
                .ok_or("JPEG SOF component length overflowed")?;
            if component_count == 0 || segment_length != expected_length {
                return Err("JPEG SOF segment has an invalid component layout");
            }
            let height = u32::from(u16::from_be_bytes([bytes[cursor + 3], bytes[cursor + 4]]));
            let width = u32::from(u16::from_be_bytes([bytes[cursor + 5], bytes[cursor + 6]]));
            return nonzero_dimensions(width, height, "JPEG SOF dimensions are zero");
        }
        if marker == 0xda {
            return Err("JPEG scan begins before a SOF marker");
        }
        cursor = segment_end;
    }
}

const fn is_jpeg_sof(marker: u8) -> bool {
    matches!(
        marker,
        0xc0..=0xc3 | 0xc5..=0xc7 | 0xc9..=0xcb | 0xcd..=0xcf
    )
}

fn nonzero_dimensions(
    width: u32,
    height: u32,
    zero_reason: &'static str,
) -> Result<(NonZeroU32, NonZeroU32), &'static str> {
    match (NonZeroU32::new(width), NonZeroU32::new(height)) {
        (Some(width), Some(height)) => Ok((width, height)),
        _ => Err(zero_reason),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use odin_domain::huginn::artifact::ArtifactRefInit;
    use odin_domain::huginn::ids::{BrowserSessionId, LiveSessionId, StreamId};
    use odin_domain::{ArtifactId, LaneId};

    /// The smallest frame the mechanism admits: SOI plus one SOF0 segment
    /// declaring a 3x2 raster, exactly the bytes `jpeg_dimensions` parses.
    fn frame_bytes() -> Vec<u8> {
        vec![
            0xff, 0xd8, // SOI
            0xff, 0xc0, // SOF0
            0x00, 0x0b, // segment length: 8 + 1 component * 3
            0x08, // sample precision
            0x00, 0x02, // height
            0x00, 0x03, // width
            0x01, // one component
            0x01, 0x11, 0x00, // component record
        ]
    }

    /// A publisher honouring the durable adapter's contract: the returned
    /// artifact binds the exact publication bytes, and the call count lets
    /// the gate prove what reaches publication.
    struct BindingPublisher(Mutex<u64>);

    impl BindingPublisher {
        fn count(&self) -> u64 {
            *self
                .0
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
        }
    }

    impl ArtifactPublisher for BindingPublisher {
        fn publish(
            &self,
            publication: ArtifactPublication,
        ) -> Result<ArtifactRef, CapabilityError> {
            *self
                .0
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner()) += 1;
            let invalid = |error: String| CapabilityError::PublisherFailure { reason: error };
            ArtifactRef::new(ArtifactRefInit {
                artifact_id: ArtifactId::new("frame-stream-test")
                    .map_err(|error| invalid(error.to_string()))?,
                session_id: LiveSessionId::parse("8c1d1a56-6d84-4f3d-9a55-2c6f24a90b21")
                    .map_err(|error| invalid(error.to_string()))?,
                lane_id: LaneId::new("frame-stream-test")
                    .map_err(|error| invalid(error.to_string()))?,
                kind: ArtifactKind::Render(RenderKind::RasterImage),
                display_name: publication.display_name.clone(),
                media_type: publication.media_type.clone(),
                byte_len: publication.byte_len(),
                content_digest: publication.content_digest,
            })
            .map_err(|error| invalid(error.to_string()))
        }
    }

    fn frame(encoded: impl Into<Vec<u8>>) -> IncomingFrame {
        IncomingFrame {
            control_revision: 1,
            captured_at: OffsetDateTime::UNIX_EPOCH,
            key_frame: true,
            masked_runtime_value_regions: 0,
            encoded: encoded.into(),
        }
    }

    fn stream(stream_enabled: bool, publisher: Arc<BindingPublisher>) -> FrameStream {
        FrameStream::new(
            StreamId::parse("2f1e5a34-901e-4d1f-9d7a-7d1b0b6e5a11").expect("stream id"),
            BrowserSessionId::parse("8c1d1a56-6d84-4f3d-9a55-2c6f24a90b21").expect("session id"),
            stream_enabled,
            FrameLimits::default(),
            publisher,
        )
    }

    /// The composition-time gate decides the whole frame path: with
    /// streaming disabled the SAME valid frame is refused before decode,
    /// publication, or retention; with streaming enabled it publishes
    /// exactly once and is retained as the latest frame.
    #[test]
    fn stream_gate_decides_publication_and_retention_of_one_valid_frame() {
        let publisher = Arc::new(BindingPublisher(Mutex::new(0)));
        let encoded = STANDARD.encode(frame_bytes());

        let disabled = stream(false, Arc::clone(&publisher));
        let error = disabled
            .offer(frame(encoded.clone()))
            .expect_err("a stream-disabled session refuses every frame");
        assert!(
            matches!(error, FrameStreamError::StreamingDisabled),
            "the gate refuses before decode: {error:?}"
        );
        assert_eq!(publisher.count(), 0, "nothing reaches publication");
        assert!(disabled.latest().is_none(), "nothing is retained");
        let counters = disabled.counters();
        assert_eq!(counters.rejected_stream_disabled, 1);
        assert_eq!(counters.accepted, 0);

        let enabled = stream(true, Arc::clone(&publisher));
        let record = enabled
            .offer(frame(encoded))
            .expect("the same valid frame publishes when streaming is enabled");
        assert_eq!(publisher.count(), 1, "exactly one publication");
        assert_eq!(record.view.frame_number.get(), 1);
        assert_eq!(record.view.width.get(), 3);
        assert_eq!(record.view.height.get(), 2);
        assert_eq!(enabled.latest().as_ref(), Some(&record), "retained latest");
        let counters = enabled.counters();
        assert_eq!(counters.accepted, 1);
        assert_eq!(counters.rejected_stream_disabled, 0);
    }
}
