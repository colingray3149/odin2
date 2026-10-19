//! Headed BrowserArm views and revision-checked control commands.

use std::num::NonZeroU32;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use time::OffsetDateTime;

use crate::{ApprovalId, CommandId, Digest};

use super::{
    artifact::ArtifactRef,
    ids::{BrowserSessionId, DeviceId, DownloadId, Sequence, StreamId},
};

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum BrowserSessionState {
    Launching,
    Active,
    Closing,
    Closed,
    Failed,
}

/// Controller ownership is durable control truth and is not inferred from the frame stream.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", rename_all_fields = "camelCase")]
pub enum BrowserTakeoverStatus {
    Available,
    Held {
        device_id: DeviceId,
        acquired_at: OffsetDateTime,
    },
    ReclaimedLocally {
        reclaimed_at: OffsetDateTime,
    },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BrowserTakeoverView {
    pub session_id: BrowserSessionId,
    pub revision: u64,
    pub status: BrowserTakeoverStatus,
    pub updated_at: OffsetDateTime,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BrowserSessionView {
    pub session_id: BrowserSessionId,
    pub revision: u64,
    pub state: BrowserSessionState,
    pub isolated_profile: String,
    pub current_url: Option<String>,
    pub current_origin: Option<String>,
    pub page_title: Option<String>,
    pub frame_stream_id: StreamId,
    pub takeover: BrowserTakeoverStatus,
    /// The typed action timeline is stored as an artifact rather than an unbounded inline list.
    pub action_timeline: Option<ArtifactRef>,
    pub opened_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
    pub stale: bool,
    pub failure: Option<String>,
}

/// A lossy visual frame. `control_revision` links it to, but never replaces, session truth.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BrowserFrameView {
    pub session_id: BrowserSessionId,
    pub frame_number: Sequence,
    pub control_revision: u64,
    pub captured_at: OffsetDateTime,
    pub width: NonZeroU32,
    pub height: NonZeroU32,
    pub key_frame: bool,
    pub content: ArtifactRef,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum BrowserDownloadStatus {
    Pending,
    InProgress,
    Complete,
    Rejected,
    Cancelled,
    Failed,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BrowserDownloadView {
    pub session_id: BrowserSessionId,
    pub download_id: DownloadId,
    pub revision: u64,
    pub suggested_name: String,
    pub source_url: String,
    pub media_type: Option<String>,
    pub expected_bytes: Option<u64>,
    pub received_bytes: u64,
    pub status: BrowserDownloadStatus,
    pub content: Option<ArtifactRef>,
    pub started_at: OffsetDateTime,
    pub finished_at: Option<OffsetDateTime>,
    pub failure: Option<String>,
}

/// Closed browser observation vocabulary exposed through the authenticated
/// Huginn shared protocol. No effect/action variant exists on this path.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum BrowserObserveKind {
    Text,
    Links,
    Tables,
    Accessibility,
    SanitizedDom,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BrowserObserveRequest {
    pub session_id: BrowserSessionId,
    pub kind: BrowserObserveKind,
    pub max_bytes: NonZeroU32,
}

impl BrowserObserveRequest {
    pub const MAX_BYTES: u32 = 1_048_576;

    pub fn validate(&self) -> Result<(), &'static str> {
        if self.max_bytes.get() <= Self::MAX_BYTES {
            Ok(())
        } else {
            Err("browser observe max_bytes exceeds the shared protocol ceiling")
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BrowserObservation {
    pub session_id: BrowserSessionId,
    pub kind: BrowserObserveKind,
    pub payload: Value,
    pub payload_digest: Digest,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", rename_all_fields = "camelCase")]
pub enum BrowserTakeoverCommand {
    Acquire { device_id: DeviceId },
    Release { device_id: DeviceId },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BrowserCommandContext {
    pub command_id: CommandId,
    pub session_id: BrowserSessionId,
    pub expected_revision: u64,
    pub arguments_digest: Digest,
    pub approval_id: Option<ApprovalId>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", rename_all_fields = "camelCase")]
pub enum BrowserCommand {
    Navigate {
        context: BrowserCommandContext,
        url: String,
    },
    Back {
        context: BrowserCommandContext,
    },
    Forward {
        context: BrowserCommandContext,
    },
    Reload {
        context: BrowserCommandContext,
    },
    Click {
        context: BrowserCommandContext,
        selector: String,
    },
    TypeText {
        context: BrowserCommandContext,
        selector: String,
        text: String,
    },
    PressKey {
        context: BrowserCommandContext,
        key: String,
    },
    Scroll {
        context: BrowserCommandContext,
        delta_x: i32,
        delta_y: i32,
    },
    CaptureScreenshot {
        context: BrowserCommandContext,
    },
    Takeover {
        context: BrowserCommandContext,
        command: BrowserTakeoverCommand,
    },
    Close {
        context: BrowserCommandContext,
    },
}

impl BrowserCommand {
    pub const fn context(&self) -> &BrowserCommandContext {
        match self {
            Self::Navigate { context, .. }
            | Self::Back { context }
            | Self::Forward { context }
            | Self::Reload { context }
            | Self::Click { context, .. }
            | Self::TypeText { context, .. }
            | Self::PressKey { context, .. }
            | Self::Scroll { context, .. }
            | Self::CaptureScreenshot { context }
            | Self::Takeover { context, .. }
            | Self::Close { context } => context,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", rename_all_fields = "camelCase")]
pub enum BrowserView {
    Session(BrowserSessionView),
    Frame(BrowserFrameView),
    Download(BrowserDownloadView),
    Takeover(BrowserTakeoverView),
}

/// Derive a distinct UUIDv8 session per owner so the pod agent, relay, and clients agree without lookup.
pub fn pod_browser_session_id(owner: &super::ids::LiveSessionId) -> BrowserSessionId {
    BrowserSessionId::new(derived_uuid(
        b"odin.pod-browser.session.v1",
        owner.as_uuid(),
    ))
    .expect("a derived v8 UUID is never nil")
}

/// The frame stream of one pod browser session, derived from the session
/// the same way: one stream per session, never shared with the authority's
/// own browser stream.
pub fn pod_browser_stream_id(session: &BrowserSessionId) -> StreamId {
    StreamId::new(derived_uuid(
        b"odin.pod-browser.stream.v1",
        session.as_uuid(),
    ))
    .expect("a derived v8 UUID is never nil")
}

fn derived_uuid(domain: &[u8], source: &uuid::Uuid) -> uuid::Uuid {
    let mut hasher = blake3::Hasher::new();
    hasher.update(domain);
    hasher.update(source.as_bytes());
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&hasher.finalize().as_bytes()[..16]);
    uuid::Builder::from_custom_bytes(bytes).into_uuid()
}

#[cfg(test)]
mod pod_browser_tests {
    use super::*;
    use crate::huginn::ids::LiveSessionId;

    #[test]
    fn a_pod_browser_session_is_derived_from_its_owner_and_never_shared() {
        let first = LiveSessionId::parse("6f1c2a52-8d0e-4b8f-9c55-0d7f1d2f5a10").unwrap();
        let second = LiveSessionId::parse("6f1c2a52-8d0e-4b8f-9c55-0d7f1d2f5a11").unwrap();
        let session = pod_browser_session_id(&first);
        assert_eq!(session, pod_browser_session_id(&first));
        assert_ne!(session, pod_browser_session_id(&second));
        assert_ne!(session.as_uuid(), first.as_uuid());
        // The id survives the strict wire grammar every client parses with.
        assert_eq!(
            BrowserSessionId::parse(&session.to_string()).unwrap(),
            session
        );
        let stream = pod_browser_stream_id(&session);
        assert_eq!(stream, pod_browser_stream_id(&session));
        assert_ne!(stream.as_uuid(), session.as_uuid());
    }
}
