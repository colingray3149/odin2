//! Transport-neutral contracts for bounded live streams.

use std::num::{NonZeroU32, NonZeroU64};

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::Digest;

use super::{artifact::ArtifactRef, ids::Sequence, StreamId};

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub enum LiveStreamKind {
    AgentEvents,
    Terminal,
    Logs,
    BrowserFrames,
    RenderFrames,
    SimulationTelemetry,
    SimulationFrames,
    FileChanges,
    KubeEvents,
}

impl LiveStreamKind {
    pub const fn mode(self) -> LiveStreamMode {
        match self {
            Self::AgentEvents
            | Self::Terminal
            | Self::Logs
            | Self::SimulationTelemetry
            | Self::FileChanges
            | Self::KubeEvents => LiveStreamMode::Durable,
            Self::BrowserFrames | Self::RenderFrames | Self::SimulationFrames => {
                LiveStreamMode::LatestFrame
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub enum LiveStreamMode {
    /// Ordered items are retained by the source and can be replayed.
    Durable,
    /// Only the newest frame is useful; intermediate frames may be dropped.
    LatestFrame,
}

/// A reconnect position. Latest-frame streams deliberately have no durable sequence.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(
    rename_all = "camelCase",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum StreamCursor {
    Durable {
        stream_id: StreamId,
        /// Last durably processed sequence; `None` requests replay from the retained beginning.
        after: Option<Sequence>,
    },
    LatestFrame {
        stream_id: StreamId,
    },
}

impl StreamCursor {
    pub fn stream_id(&self) -> &StreamId {
        match self {
            Self::Durable { stream_id, .. } | Self::LatestFrame { stream_id } => stream_id,
        }
    }

    pub const fn mode(&self) -> LiveStreamMode {
        match self {
            Self::Durable { .. } => LiveStreamMode::Durable,
            Self::LatestFrame { .. } => LiveStreamMode::LatestFrame,
        }
    }
}

/// One live stream item. The payload is always content-addressed, never an inline field array.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StreamFrame {
    pub stream_id: StreamId,
    pub kind: LiveStreamKind,
    pub sequence: Sequence,
    /// Revision of the independent control view observed when this frame was produced.
    pub control_revision: u64,
    pub produced_at: OffsetDateTime,
    pub key_frame: bool,
    pub content: ArtifactRef,
}

/// Resource ceilings enforced independently for every subscription.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StreamBackpressureLimits {
    pub max_buffered_items: NonZeroU32,
    pub max_buffered_bytes: NonZeroU64,
    pub max_item_bytes: NonZeroU64,
    pub max_items_per_second: NonZeroU32,
    pub max_in_flight_bytes: NonZeroU64,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum StreamLifecycle {
    Opening,
    Live,
    Stalled,
    Closed,
    Failed,
}

/// Observable delivery state. Dropped frames affect counters, never control revision.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StreamStatus {
    pub stream_id: StreamId,
    pub kind: LiveStreamKind,
    pub mode: LiveStreamMode,
    pub lifecycle: StreamLifecycle,
    pub durable_head: Option<Sequence>,
    pub last_delivered: Option<Sequence>,
    pub control_revision: u64,
    pub buffered_items: u32,
    pub buffered_bytes: u64,
    pub dropped_items: u64,
    pub limits: StreamBackpressureLimits,
    pub updated_at: OffsetDateTime,
    pub failure: Option<String>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StreamCredit {
    pub items: NonZeroU32,
    pub bytes: NonZeroU64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StreamSubscription {
    pub kind: LiveStreamKind,
    pub cursor: StreamCursor,
    pub credit: StreamCredit,
    pub limits: StreamBackpressureLimits,
}

impl StreamSubscription {
    pub fn has_valid_mode(&self) -> bool {
        self.kind.mode() == self.cursor.mode()
    }
}

/// Streams joined atomically by a client subscription request.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SubscriptionSet {
    pub subscriptions: Vec<StreamSubscription>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SubscriptionSetWire {
    subscriptions: Vec<StreamSubscription>,
}

impl<'de> Deserialize<'de> for SubscriptionSet {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let wire = SubscriptionSetWire::deserialize(deserializer)?;
        let set = Self {
            subscriptions: wire.subscriptions,
        };
        if !set.is_valid() {
            return Err(serde::de::Error::custom(
                "subscription set must be nonempty with unique durable stream identities",
            ));
        }
        Ok(set)
    }
}

impl SubscriptionSet {
    /// Requires a nonempty set with valid stream/mode pairings and unique stream identities.
    pub fn is_valid(&self) -> bool {
        !self.subscriptions.is_empty()
            && self
                .subscriptions
                .iter()
                .enumerate()
                .all(|(index, subscription)| {
                    subscription.has_valid_mode()
                        && self.subscriptions[index + 1..].iter().all(|other| {
                            other.cursor.stream_id() != subscription.cursor.stream_id()
                        })
                })
    }
}

/// One bounded transport chunk. Large objects remain artifacts; chunks are transient credit-bound
/// fragments whose digest is verified before delivery or assembly.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BinaryChunk {
    pub stream_id: StreamId,
    pub sequence: Sequence,
    pub offset: u64,
    pub bytes: Vec<u8>,
    pub digest: Digest,
    pub final_chunk: bool,
}

impl BinaryChunk {
    pub fn has_valid_digest(&self) -> bool {
        Digest::hash(&self.bytes) == self.digest
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct BinaryChunkWire {
    stream_id: StreamId,
    sequence: Sequence,
    offset: u64,
    bytes: Vec<u8>,
    digest: Digest,
    final_chunk: bool,
}

impl<'de> Deserialize<'de> for BinaryChunk {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let wire = BinaryChunkWire::deserialize(deserializer)?;
        let chunk = Self {
            stream_id: wire.stream_id,
            sequence: wire.sequence,
            offset: wire.offset,
            bytes: wire.bytes,
            digest: wire.digest,
            final_chunk: wire.final_chunk,
        };
        if !chunk.has_valid_digest() {
            return Err(serde::de::Error::custom(
                "binary chunk digest does not match its bytes",
            ));
        }
        Ok(chunk)
    }
}

#[cfg(test)]
mod tests {
    use std::num::{NonZeroU32, NonZeroU64};

    use super::{
        LiveStreamKind, Sequence, StreamBackpressureLimits, StreamCredit, StreamCursor, StreamId,
        StreamSubscription, SubscriptionSet,
    };

    fn stream_id(last_group: u64) -> StreamId {
        StreamId::parse(&format!("00000000-0000-4000-8000-{last_group:012}")).expect("stream id")
    }

    fn subscription(kind: LiveStreamKind, cursor: StreamCursor) -> StreamSubscription {
        StreamSubscription {
            kind,
            cursor,
            credit: StreamCredit {
                items: NonZeroU32::new(64).expect("credit items"),
                bytes: NonZeroU64::new(1 << 20).expect("credit bytes"),
            },
            limits: StreamBackpressureLimits {
                max_buffered_items: NonZeroU32::new(1024).expect("buffered items"),
                max_buffered_bytes: NonZeroU64::new(1 << 24).expect("buffered bytes"),
                max_item_bytes: NonZeroU64::new(1 << 20).expect("item bytes"),
                max_items_per_second: NonZeroU32::new(256).expect("items per second"),
                max_in_flight_bytes: NonZeroU64::new(1 << 22).expect("in-flight bytes"),
            },
        }
    }

    /// The exact subscription `odin huginn watch --kind agent-events --after 0` sends.
    fn watch_set() -> SubscriptionSet {
        SubscriptionSet {
            subscriptions: vec![subscription(
                LiveStreamKind::AgentEvents,
                StreamCursor::Durable {
                    stream_id: stream_id(4),
                    after: Some(Sequence::new(0)),
                },
            )],
        }
    }

    #[test]
    fn subscription_set_rejects_bare_sequence_wire_form() {
        let set = watch_set();
        let encoded = serde_json::to_value(&set).expect("subscription set encodes");
        let bare_sequence = encoded["subscriptions"].clone();
        assert!(
            serde_json::from_value::<SubscriptionSet>(bare_sequence).is_err(),
            "the bare sequence is not an accepted wire form"
        );
    }

    #[test]
    fn subscription_set_rejects_empty_duplicate_and_mismatched_mode() {
        let cases = [
            SubscriptionSet {
                subscriptions: Vec::new(),
            },
            SubscriptionSet {
                subscriptions: vec![
                    subscription(
                        LiveStreamKind::AgentEvents,
                        StreamCursor::Durable {
                            stream_id: stream_id(4),
                            after: None,
                        },
                    ),
                    subscription(
                        LiveStreamKind::Logs,
                        StreamCursor::Durable {
                            stream_id: stream_id(4),
                            after: None,
                        },
                    ),
                ],
            },
            SubscriptionSet {
                subscriptions: vec![subscription(
                    LiveStreamKind::AgentEvents,
                    StreamCursor::LatestFrame {
                        stream_id: stream_id(5),
                    },
                )],
            },
        ];
        for set in cases {
            assert!(!set.is_valid());
            let encoded = serde_json::to_value(&set).expect("invalid sets still encode");
            assert!(
                serde_json::from_value::<SubscriptionSet>(encoded).is_err(),
                "the wire boundary must reject invalid subscription sets"
            );
        }
    }
}
