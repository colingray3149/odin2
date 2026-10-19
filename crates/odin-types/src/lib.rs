//! Shared validated identifiers, hashes, and protocol reason codes.

#![deny(unsafe_code)]
#![deny(dead_code)]
#![deny(unused)]

pub mod gate;
pub mod hash;
pub mod ids;

pub use gate::{ReasonCategory, ReasonCode};
pub use hash::{sha256_hex, HashError, HashHex};
pub use ids::{
    CapsuleId, CapsuleLeaseId, CorrelationId, IdError, OperationId, PredecessorHash, ToolId,
    WorkerId,
};
