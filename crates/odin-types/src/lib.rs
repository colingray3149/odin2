//! Shared validated identifiers, hashes, and protocol reason codes.

#![deny(unsafe_code)]
#![deny(dead_code)]
#![deny(unused)]

pub mod gate;
pub mod hash;
pub mod ids;

pub use gate::{ReasonCategory, ReasonCode};
pub use hash::{sha256_hex, HashError, HashHex};
/// Largest newline-delimited frame, newline included, on any Odin line protocol.
pub const MAX_FRAME_BYTES: usize = 1 << 20;
/// Largest authority-wire request payload: a whole-file code edit travels in one request.
pub const MAX_AUTHORITY_REQUEST_BYTES: usize = 1 << 18;

pub use ids::{
    CapsuleId, CapsuleLeaseId, CorrelationId, IdError, OperationId, PredecessorHash, ToolId,
    WorkerId, MAX_ID_BYTES,
};

/// The text a panicking thread left in its join payload.
pub fn panic_message(payload: &(dyn std::any::Any + Send)) -> &str {
    payload
        .downcast_ref::<&str>()
        .copied()
        .or_else(|| payload.downcast_ref::<String>().map(String::as_str))
        .unwrap_or("non-string panic payload")
}
