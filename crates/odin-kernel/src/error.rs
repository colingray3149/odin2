use odin_domain::{DomainError, SeatTokenId};
use odin_ledger::LedgerError;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum KernelError {
    #[error(transparent)]
    Domain(#[from] DomainError),
    #[error(transparent)]
    Ledger(#[from] LedgerError),
    #[error("registry operation failed: {0}")]
    Registry(String),
    #[error("invalid capability contract: {0}")]
    InvalidContract(String),
    #[error("invalid authority: {0}")]
    InvalidAuthority(String),
    #[error("seat token {0} is revoked")]
    Revoked(SeatTokenId),
    #[error("schema validation failed: {0}")]
    Schema(String),
    #[error("{kind} {id} was not found")]
    NotFound { kind: &'static str, id: String },
    #[error("kernel conflict: {0}")]
    Conflict(String),
    #[error("authorization denied: {0}")]
    Denied(String),
}

pub type KernelResult<T> = std::result::Result<T, KernelError>;
