use thiserror::Error;

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum DomainError {
    #[error("invalid {kind} ID {value:?}: {reason}")]
    InvalidId {
        kind: &'static str,
        value: String,
        reason: &'static str,
    },
    #[error("invalid digest {value:?}: {reason}")]
    InvalidDigest { value: String, reason: &'static str },
    #[error("invalid {machine} transition from {from:?} to {to:?}")]
    InvalidTransition {
        machine: &'static str,
        from: String,
        to: String,
    },
    #[error("invalid scope: {0}")]
    InvalidScope(String),
    #[error("invalid envelope: {0}")]
    InvalidEnvelope(String),
    #[error("invalid token: {0}")]
    InvalidToken(String),
    #[error("token expired at {expires_at_ms} ms (current time {now_ms} ms)")]
    TokenExpired { expires_at_ms: u64, now_ms: u64 },
    #[error("invalid subscription: {0}")]
    InvalidSubscription(String),
    #[error("invalid subscription capacity {capacity}: capacity must be greater than zero")]
    InvalidCapacity { capacity: usize },
}
