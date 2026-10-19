//! Operator-side keys, seat tokens, and device pairing stay outside the Nix
//! store and Git worktrees. Shared runtime composition keeps provisioned
//! tokens consistent with server-side verification.
//!
//! Renewal requires explicit `--renew` or a `TokenRenewalPolicy`; revoked,
//! malformed, foreign, or overlong tokens are rejected.

#[path = "authority_provision/admin_wire.rs"]
mod admin_wire;
#[path = "authority_provision/authority_key.rs"]
mod authority_key;
#[path = "authority_provision/composition.rs"]
mod composition;
#[path = "authority_provision/ensure.rs"]
mod ensure;
#[path = "authority_provision/entropy.rs"]
mod entropy;
#[path = "authority_provision/pairing.rs"]
mod pairing;
#[path = "authority_provision/private_fs.rs"]
mod private_fs;
#[path = "authority_provision/token.rs"]
mod token;

pub use admin_wire::{
    admin_socket_path, AdminRevokeRequest, AdminRevokeResponse, ADMIN_EXCHANGE_TIMEOUT,
    MAX_ADMIN_REQUEST_BYTES,
};
pub use authority_key::{init, load_signing_key, AuthorityInitReport};
pub use composition::{
    compose, compose_for_session, compose_for_session_at_revision, mint_for_child_session,
    preflight_compose, LaunchReadiness, LaunchSelection, SessionComposition,
};
pub use ensure::{
    ensure_session_token, EnsureSessionTokenError, StalePublishedBinding, TokenReissueReason,
    TokenRenewalPolicy,
};
pub use entropy::{hex_string, os_random_bytes, parse_command_uuid, random_command_uuid};
pub use pairing::{
    enroll_device, ledger_file_revoke_pass, ledger_revoke_pass, pair_device,
    redrive_device_revocations, revoke_device, DevicePairReport, DeviceRevokeReport,
};
pub use private_fs::write_private_atomic;
pub use token::{mint, mint_for_composition, remove_session_token_if_owned, MintReport};

/// Default and maximum lifetime of a one-shot seat token.
pub const DEFAULT_TOKEN_TTL_SECONDS: u64 = 24 * 60 * 60;
pub const MAX_TOKEN_TTL_SECONDS: u64 = 24 * 60 * 60;

pub const MAX_PROMPT_FILE_BYTES: u64 = 256 * 1024;

#[cfg(test)]
#[path = "authority_provision/fixture.rs"]
pub(crate) mod fixture;

#[cfg(test)]
fn dir_mode(path: &std::path::Path) -> u32 {
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::symlink_metadata(path)
        .expect("path exists")
        .permissions()
        .mode()
        & 0o777
}
