//! Shared account errors and scoped credential leases for life adapters.
//!
//! Leases expose opaque handles, not secrets, and cannot be serialized; Debug redacts the handle.
//! Issuance checks account and secret-file availability, and consumers recheck scope at use time.
//! Errors exclude upstream text and credentials so outgoing envelopes cannot leak them.

mod effect;
mod errors;
mod lease;

/// The largest file the fleet reads, stores or attaches: an owner's attachment, an image, an
/// artifact, a mail attachment.
pub const MAX_ATTACHMENT_BYTES: u64 = 25 * 1024 * 1024;

pub(crate) use effect::{
    check_account,
    record_dispatch_intent,
    run_ungated_effect,
    settle_gated_effect,
    DurableEffect,
    EffectIntent,
    EffectRoute,
};
pub use effect::{
    denial_result, failed_result, EffectIdentity, EffectStatus, HostConsumeProof, SettledEffect,
    EFFECT_TTL_SECONDS, MAX_ACCOUNT_CHARS, MAX_IDENTITY_CHARS, PARTIAL_EFFECT_AUDIT_KIND,
};
pub use errors::{
    AccountUnavailable, BatchFault, DenialRecord, GateRedirect, LeaseRejection, LedgerFailure,
    LifeError, TransportFault,
};
pub use lease::{
    AccountSecretRef, CredentialLeases, FileCredentialLeases, ScopedCredentialLease,
    LEASE_TTL_SECONDS,
};
