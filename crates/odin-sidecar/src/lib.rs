//! Transport-only host of the sole kernel operation authority.

#![forbid(unsafe_code)]

mod authority;
mod client;
mod lifecycle;
mod protocol_error;
mod server;
mod sidecar_error;
mod storage;

pub use authority::{
    authorization_code, effect_receipt_at, rejection_code, rejection_response, system_clock,
    AuthorityConfig, AuthoritySnapshot, Clock, EffectReceipt, EffectorExecutor,
    EffectorSandboxBinding, InterpreterBinding, PeerCredentials, Provisioning, ReceiptEvent,
    ReceiptFileChange, Sidecar, TransportProjection, TransportRejection,
};
pub use client::SidecarClient;
pub use server::{ServerConfig, SidecarServer};
pub use sidecar_error::{SidecarError, SidecarErrorCode};
pub use storage::read_bounded;
