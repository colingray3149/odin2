use std::collections::BTreeSet;
use std::num::{NonZeroU16, NonZeroU64};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::LaneId;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LiveSlicePolicy {
    pub max_sessions_per_seat: NonZeroU16,
    pub max_prompt_bytes: NonZeroU64,
    pub transfer_chunk_bytes: NonZeroU64,
    pub max_file_bytes: NonZeroU64,
    pub max_render_bytes: NonZeroU64,
    pub allowed_file_media_types: BTreeSet<String>,
    pub allowed_render_media_types: BTreeSet<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LiveSeatPolicy {
    pub max_sessions: NonZeroU16,
    pub lanes: LiveLaneBindings,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LiveLaneBindings {
    pub file_ingress_lane: LaneId,
    pub file_egress_lane: LaneId,
    pub render_ingress_lane: LaneId,
    pub render_egress_lane: LaneId,
}

/// Monotonic result of resolving a seat policy within its slice policy.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EffectiveLivePolicy {
    pub max_sessions: NonZeroU16,
    pub max_prompt_bytes: NonZeroU64,
    pub transfer_chunk_bytes: NonZeroU64,
    pub max_file_bytes: NonZeroU64,
    pub max_render_bytes: NonZeroU64,
    pub allowed_file_media_types: BTreeSet<String>,
    pub allowed_render_media_types: BTreeSet<String>,
    pub lanes: LiveLaneBindings,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum LiveLaneBinding {
    FileIngress,
    FileEgress,
    RenderIngress,
    RenderEgress,
}

impl LiveLaneBinding {
    pub const fn field_name(self) -> &'static str {
        match self {
            Self::FileIngress => "fileIngressLane",
            Self::FileEgress => "fileEgressLane",
            Self::RenderIngress => "renderIngressLane",
            Self::RenderEgress => "renderEgressLane",
        }
    }
}

/// Read-only lane inventory used while resolving live policy.
pub trait LaneCatalog {
    /// Returns whether `lane_id` exists and is declared for `binding`'s payload and direction.
    fn supports(&self, lane_id: &LaneId, binding: LiveLaneBinding) -> bool;
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum LivePolicyError {
    #[error("lane '{lane_id}' is unavailable for live binding '{binding}'", binding = binding.field_name())]
    LaneUnavailable {
        binding: LiveLaneBinding,
        lane_id: LaneId,
    },
}
