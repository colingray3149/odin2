//! Read-only terminal reconstruction and explicit operator control leases.

use std::num::{NonZeroU16, NonZeroU32};

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::{ArtifactId, CommandId, Digest, DomainError};

use super::ids::{DeviceId, LiveSessionId, SessionEpoch, TerminalControlLeaseId, TerminalSeq};

/// Cursor position within a non-empty terminal grid.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TerminalCursor {
    pub row: u16,
    pub column: u16,
    pub visible: bool,
}

/// A durable read-only terminal reset point.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TerminalSnapshot {
    pub session_id: LiveSessionId,
    pub epoch: SessionEpoch,
    pub sequence: TerminalSeq,
    pub recorded_at: OffsetDateTime,
    pub columns: NonZeroU16,
    pub rows: NonZeroU16,
    pub contents: String,
    pub cursor: TerminalCursor,
}

impl TerminalSnapshot {
    pub fn validate(&self) -> Result<(), DomainError> {
        if self.cursor.row >= self.rows.get() || self.cursor.column >= self.columns.get() {
            return Err(invalid_terminal("cursor lies outside terminal dimensions"));
        }
        if self.contents.as_bytes().contains(&0) {
            return Err(invalid_terminal("snapshot contents contain NUL"));
        }
        Ok(())
    }
}

/// Ordered raw PTY output following a snapshot or prior delta.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TerminalDelta {
    pub session_id: LiveSessionId,
    pub epoch: SessionEpoch,
    pub after: TerminalSeq,
    pub sequence: TerminalSeq,
    pub recorded_at: OffsetDateTime,
    pub bytes: Vec<u8>,
}

impl TerminalDelta {
    pub fn validate(&self) -> Result<(), DomainError> {
        if self.sequence <= self.after {
            return Err(invalid_terminal(
                "delta sequence must be greater than its predecessor",
            ));
        }
        if self.bytes.is_empty() {
            return Err(invalid_terminal("terminal delta must not be empty"));
        }
        Ok(())
    }
}

/// Blob reference used by semantic history without embedding a terminal snapshot.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TerminalSnapshotRef {
    pub session_id: LiveSessionId,
    pub epoch: SessionEpoch,
    pub sequence: TerminalSeq,
    pub columns: NonZeroU16,
    pub rows: NonZeroU16,
    pub artifact_id: ArtifactId,
    pub byte_len: u64,
    pub content_digest: Digest,
}

/// Blob reference used by semantic history without embedding PTY output bytes.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TerminalDeltaRef {
    pub session_id: LiveSessionId,
    pub epoch: SessionEpoch,
    pub after: TerminalSeq,
    pub sequence: TerminalSeq,
    pub artifact_id: ArtifactId,
    pub byte_len: u64,
    pub content_digest: Digest,
}

impl TerminalDeltaRef {
    pub fn validate(&self) -> Result<(), DomainError> {
        if self.sequence <= self.after {
            return Err(invalid_terminal(
                "delta reference sequence must be greater than its predecessor",
            ));
        }
        if self.byte_len == 0 {
            return Err(invalid_terminal("delta reference must not be empty"));
        }
        Ok(())
    }
}

/// Request for a bounded, single-owner operator PTY control lease.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TerminalControlRequest {
    pub session_id: LiveSessionId,
    pub expected_epoch: SessionEpoch,
    pub columns: NonZeroU16,
    pub rows: NonZeroU16,
    pub requested_ttl_seconds: NonZeroU32,
}

/// Idempotent terminal-control acquisition.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TerminalAcquireRequest {
    pub command_id: CommandId,
    pub request: TerminalControlRequest,
}

/// An authority token issued only after authenticating the Colin device.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TerminalControlLease {
    pub lease_id: TerminalControlLeaseId,
    pub session_id: LiveSessionId,
    pub device_id: DeviceId,
    pub epoch: SessionEpoch,
    pub acquired_at: OffsetDateTime,
    pub expires_at: OffsetDateTime,
}

impl TerminalControlLease {
    pub fn validate(&self) -> Result<(), DomainError> {
        if self.expires_at <= self.acquired_at {
            return Err(invalid_terminal(
                "control lease expiry must follow acquisition",
            ));
        }
        Ok(())
    }
}

/// Raw operator input remains visibly separate from typed live commands.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TerminalInput {
    pub lease_id: TerminalControlLeaseId,
    pub bytes: Vec<u8>,
}

impl TerminalInput {
    pub fn validate(&self) -> Result<(), DomainError> {
        if self.bytes.is_empty() {
            return Err(invalid_terminal("terminal input must not be empty"));
        }
        Ok(())
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct TerminalInputWire {
    lease_id: TerminalControlLeaseId,
    bytes: Vec<u8>,
}

impl<'de> Deserialize<'de> for TerminalInput {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let wire = TerminalInputWire::deserialize(deserializer)?;
        let input = Self {
            lease_id: wire.lease_id,
            bytes: wire.bytes,
        };
        input.validate().map_err(serde::de::Error::custom)?;
        Ok(input)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TerminalResize {
    pub lease_id: TerminalControlLeaseId,
    pub columns: NonZeroU16,
    pub rows: NonZeroU16,
}

/// Idempotent raw input under an explicit terminal-control lease.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TerminalWriteRequest {
    pub command_id: CommandId,
    pub session_id: LiveSessionId,
    pub input: TerminalInput,
}

/// Idempotent resize under an explicit terminal-control lease.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TerminalResizeRequest {
    pub command_id: CommandId,
    pub session_id: LiveSessionId,
    pub resize: TerminalResize,
}

/// Idempotent release of an explicit terminal-control lease.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TerminalReleaseRequest {
    pub command_id: CommandId,
    pub session_id: LiveSessionId,
    pub lease_id: TerminalControlLeaseId,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum TerminalControlState {
    Granted,
    Denied,
    Released,
    Revoked,
    Expired,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TerminalControlStatus {
    pub session_id: LiveSessionId,
    pub state: TerminalControlState,
    pub lease: Option<TerminalControlLease>,
    pub diagnostic: Option<String>,
}

impl TerminalControlStatus {
    pub fn validate(&self) -> Result<(), DomainError> {
        if self.state == TerminalControlState::Granted && self.lease.is_none() {
            return Err(invalid_terminal("granted status requires a lease"));
        }
        if self.state != TerminalControlState::Granted && self.lease.is_some() {
            return Err(invalid_terminal("only granted status may carry a lease"));
        }
        Ok(())
    }
}

fn invalid_terminal(message: impl Into<String>) -> DomainError {
    DomainError::InvalidEnvelope(format!("invalid terminal: {}", message.into()))
}
