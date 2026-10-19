//! Safe, bounded render requests and their immutable output manifests.

use std::num::{NonZeroU32, NonZeroU64};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use time::OffsetDateTime;

use crate::{ArtifactId, CommandId, Digest, DomainError};

use super::file::ContentSource;
use super::ids::{RenderId, RendererId};

/// Safe output formats. Active HTML is deliberately not representable.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub enum RenderKind {
    RasterImage,
    SanitizedSvg,
    Pdf,
}

impl RenderKind {
    pub fn media_type_is_valid(self, media_type: &str) -> bool {
        match self {
            Self::RasterImage => matches!(
                media_type,
                "image/png" | "image/jpeg" | "image/webp" | "image/avif"
            ),
            Self::SanitizedSvg => matches!(media_type, "image/svg+xml"),
            Self::Pdf => matches!(media_type, "application/pdf"),
        }
    }
}

/// Hard ceilings applied by a renderer before allocating or emitting output.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RenderLimits {
    pub max_output_bytes: NonZeroU64,
    pub max_width_pixels: NonZeroU32,
    pub max_height_pixels: NonZeroU32,
    pub max_frames: NonZeroU32,
}

impl RenderLimits {
    pub const fn max_pixel_count(self) -> Option<u64> {
        (self.max_width_pixels.get() as u64).checked_mul(self.max_height_pixels.get() as u64)
    }
}
/// Request to run one declared renderer against one authority-bearing source.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RenderRequest {
    pub command_id: CommandId,
    pub source: ContentSource,
    pub renderer: RendererId,
    pub renderer_version: String,
    pub parameters: Value,
    pub limits: RenderLimits,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RenderRequestWire {
    command_id: CommandId,
    source: ContentSource,
    renderer: RendererId,
    renderer_version: String,
    parameters: Value,
    limits: RenderLimits,
}

impl<'de> Deserialize<'de> for RenderRequest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let wire = RenderRequestWire::deserialize(deserializer)?;
        let request = Self {
            command_id: wire.command_id,
            source: wire.source,
            renderer: wire.renderer,
            renderer_version: wire.renderer_version,
            parameters: wire.parameters,
            limits: wire.limits,
        };
        request.validate().map_err(serde::de::Error::custom)?;
        Ok(request)
    }
}

impl RenderRequest {
    pub fn validate(&self) -> Result<(), DomainError> {
        if self.renderer_version.is_empty() || self.renderer_version.as_bytes().contains(&0) {
            return Err(invalid_render(
                "renderer version must be non-empty and contain no NUL",
            ));
        }
        self.limits
            .max_pixel_count()
            .ok_or_else(|| invalid_render("render pixel limit overflows u64"))?;
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RenderStatusRequest {
    pub render_id: RenderId,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RenderWatchRequest {
    pub render_id: RenderId,
}

#[derive(Clone, Debug)]
pub struct RenderManifestInit {
    pub render_id: RenderId,
    pub command_id: CommandId,
    pub renderer: RendererId,
    pub renderer_version: String,
    pub kind: RenderKind,
    pub media_type: String,
    pub byte_len: u64,
    pub content_digest: Digest,
    pub artifact_id: ArtifactId,
    pub completed_at: OffsetDateTime,
}

/// Immutable description of a completed render output.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RenderManifest {
    pub render_id: RenderId,
    pub command_id: CommandId,
    pub renderer: RendererId,
    pub renderer_version: String,
    pub kind: RenderKind,
    pub media_type: String,
    pub byte_len: u64,
    pub content_digest: Digest,
    pub artifact_id: ArtifactId,
    pub completed_at: OffsetDateTime,
}

impl RenderManifest {
    pub fn new(init: RenderManifestInit) -> Result<Self, DomainError> {
        let RenderManifestInit {
            render_id,
            command_id,
            renderer,
            renderer_version,
            kind,
            media_type,
            byte_len,
            content_digest,
            artifact_id,
            completed_at,
        } = init;
        if renderer_version.is_empty() || renderer_version.as_bytes().contains(&0) {
            return Err(invalid_render(
                "renderer version must be non-empty and contain no NUL",
            ));
        }
        if !kind.media_type_is_valid(&media_type) {
            return Err(invalid_render(
                "output media type is not valid for the declared safe render kind",
            ));
        }
        Ok(Self {
            render_id,
            command_id,
            renderer,
            renderer_version,
            kind,
            media_type,
            byte_len,
            content_digest,
            artifact_id,
            completed_at,
        })
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum RenderState {
    Queued,
    Rendering,
    Completed,
    Rejected,
    Cancelled,
    Failed,
}

impl RenderState {
    pub const fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Completed | Self::Rejected | Self::Cancelled | Self::Failed
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RenderStatus {
    pub render_id: RenderId,
    pub command_id: CommandId,
    pub state: RenderState,
    pub manifest: Option<RenderManifest>,
    pub diagnostic: Option<String>,
}

impl RenderStatus {
    pub fn validate(&self) -> Result<(), DomainError> {
        if self.state == RenderState::Completed && self.manifest.is_none() {
            return Err(invalid_render(
                "completed status requires an output manifest",
            ));
        }
        if self.state != RenderState::Completed && self.manifest.is_some() {
            return Err(invalid_render(
                "only a completed status may carry an output manifest",
            ));
        }
        Ok(())
    }
}

fn invalid_render(message: impl Into<String>) -> DomainError {
    DomainError::InvalidEnvelope(format!("invalid render: {}", message.into()))
}
