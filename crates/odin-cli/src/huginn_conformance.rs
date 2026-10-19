//! Production stream frame publishing shared by kube and simulation.

use odin_domain::huginn as live;
use odin_domain::huginn::{
    HuginnMessage, LiveStreamKind, LiveStreamMode, Sequence, StreamBackpressureLimits, StreamFrame,
    StreamId, StreamLifecycle, StreamStatus,
};
use odin_huginn::streams::{BoundedMultiplexer, MultiplexedItem};
use time::OffsetDateTime;

type Result<T, E = String> = std::result::Result<T, E>;

pub(crate) fn stream_backpressure_limits(
    limits: &odin_huginn::HuginnLimits,
) -> Result<StreamBackpressureLimits> {
    let buffered_items = u32::try_from(limits.streams.frame_queue_depth.get())
        .map_err(|_| "configured frame queue depth does not fit u32".to_owned())?;
    let item_bytes = u64::try_from(limits.streams.max_stream_frame_bytes.get())
        .map_err(|_| "configured stream frame bytes do not fit u64".to_owned())?;
    let buffered_bytes = item_bytes
        .checked_mul(u64::from(buffered_items))
        .ok_or_else(|| "configured stream buffer bytes overflowed".to_owned())?;
    let in_flight_bytes = item_bytes
        .checked_mul(2)
        .ok_or_else(|| "configured in-flight bytes overflowed".to_owned())?;
    Ok(StreamBackpressureLimits {
        max_buffered_items: std::num::NonZeroU32::new(buffered_items)
            .ok_or("zero buffered item bound")?,
        max_buffered_bytes: non_zero_u64(buffered_bytes)?,
        max_item_bytes: non_zero_u64(item_bytes)?,
        max_items_per_second: limits.streams.max_frames_per_second,
        max_in_flight_bytes: non_zero_u64(in_flight_bytes)?,
    })
}

fn non_zero_u64(value: u64) -> Result<std::num::NonZeroU64> {
    std::num::NonZeroU64::new(value).ok_or_else(|| "zero bound".to_owned())
}

pub(crate) struct StreamFrameSpec {
    pub(crate) stream_id: StreamId,
    pub(crate) kind: LiveStreamKind,
    pub(crate) mode: LiveStreamMode,
    pub(crate) sequence: u64,
    pub(crate) control_revision: u64,
    pub(crate) content: live::ArtifactRef,
}

pub(crate) fn publish_frame(
    streams: &BoundedMultiplexer,
    spec: StreamFrameSpec,
    backpressure: &StreamBackpressureLimits,
    now: OffsetDateTime,
) -> Result<()> {
    let StreamFrameSpec {
        stream_id,
        kind,
        mode,
        sequence,
        control_revision,
        content,
    } = spec;
    let durable = matches!(mode, LiveStreamMode::Durable);
    streams
        .publish(
            MultiplexedItem::new(
                StreamFrame {
                    stream_id,
                    kind,
                    sequence: Sequence::new(sequence),
                    control_revision,
                    produced_at: now,
                    key_frame: true,
                    content,
                },
                HuginnMessage::StreamStatus(StreamStatus {
                    stream_id,
                    kind,
                    mode,
                    lifecycle: StreamLifecycle::Live,
                    durable_head: durable.then(|| Sequence::new(sequence)),
                    last_delivered: Some(Sequence::new(sequence)),
                    control_revision,
                    buffered_items: 0,
                    buffered_bytes: 0,
                    dropped_items: 0,
                    limits: *backpressure,
                    updated_at: now,
                    failure: None,
                }),
            ),
            now,
        )
        .map_err(|error| error.to_string())
}
