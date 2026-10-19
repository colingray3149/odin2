//! Provisioned seat-token verification and the live session-binding registry.

use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use odin_domain::{SeatToken, SessionId};
use odin_kernel::{ExpectedBindings, FreshAuthority, LedgerRevocations};
use odin_ledger::Ledger;

use super::{HostToolOperationError, HostToolOperations, SessionOperationBinding};

/// File-backed provider for externally provisioned signed seat tokens.
///
/// The provider owns only verification material. It never possesses an issuer
/// and never writes token files. One deny-unknown `SeatToken` JSON file named
/// `<session-id>.json` is reloaded for each authorization, so atomic external
/// replacement and durable revocation take effect before the next dispatch.
pub struct ProvisionedFreshAuthorityProvider {
    token_root: Option<PathBuf>,
    verification_key: Option<Arc<Vec<u8>>>,
}

impl ProvisionedFreshAuthorityProvider {
    /// Opens a concrete provider over an existing absolute token directory and
    /// host-provisioned verification key.
    pub fn open(
        token_root: impl Into<PathBuf>,
        verification_key: Vec<u8>,
    ) -> Result<Self, HostToolOperationError> {
        let token_root = token_root.into();
        if !token_root.is_absolute() {
            return Err(HostToolOperationError::PublishedAuthorityUnavailable {
                detail: "provisioned token root must be absolute".to_owned(),
            });
        }
        if verification_key.len() < 32 {
            return Err(HostToolOperationError::PublishedAuthorityUnavailable {
                detail: "verification key must contain at least 32 bytes".to_owned(),
            });
        }
        let token_root = token_root.canonicalize().map_err(|error| {
            HostToolOperationError::PublishedAuthorityUnavailable {
                detail: format!(
                    "could not open provisioned token root {}: {error}",
                    token_root.display()
                ),
            }
        })?;
        if !token_root.is_dir() {
            return Err(HostToolOperationError::PublishedAuthorityUnavailable {
                detail: format!(
                    "provisioned token root {} is not a directory",
                    token_root.display()
                ),
            });
        }
        Ok(Self {
            token_root: Some(token_root),
            verification_key: Some(Arc::new(verification_key)),
        })
    }

    /// Followers receive no HMAC key because verification material can also sign tokens.
    /// Every verification through this provider is denied.
    pub fn denying() -> Self {
        Self {
            token_root: None,
            verification_key: None,
        }
    }

    fn denied() -> HostToolOperationError {
        HostToolOperationError::PublishedAuthorityUnavailable {
            detail: "this node does not hold the operation seat-token authority \
                     (read-only follower); verification is denied"
                .to_owned(),
        }
    }

    /// Reloads the token so replacement and revocation take effect on every authorization.
    pub(super) fn verify(
        &self,
        binding: &SessionOperationBinding,
        session: &SessionId,
        ledger: &Ledger,
        now_ms: u64,
    ) -> Result<FreshAuthority, HostToolOperationError> {
        let Some(verification_key) = self.verification_key.as_ref() else {
            return Err(Self::denied());
        };
        let token = self.read_token(session)?;
        let policy = &binding.policy;
        Ok(FreshAuthority::verify(
            &token,
            ExpectedBindings {
                seat: &policy.seat_id,
                slice: &policy.slice_id,
                lane: &policy.lane_id,
                session,
                seat_revision: policy.seat_revision,
                slice_revision: policy.slice_revision,
                capability_policy_digest: policy.capability_policy_digest,
                context_policy_digest: binding.context_policy_digest,
            },
            (**verification_key).clone(),
            LedgerRevocations::new(ledger),
            now_ms,
        )?)
    }

    pub(super) fn read_token(
        &self,
        session: &SessionId,
    ) -> Result<SeatToken, HostToolOperationError> {
        let path = self
            .token_root
            .as_ref()
            .map(|root| root.join(format!("{}.json", session.as_str())))
            .ok_or_else(Self::denied)?;
        let bytes = fs::read(&path).map_err(|error| {
            HostToolOperationError::PublishedAuthorityUnavailable {
                detail: format!(
                    "provisioned token for session {} is unavailable at {}: {error}",
                    session,
                    path.display()
                ),
            }
        })?;
        serde_json::from_slice(&bytes).map_err(|error| {
            HostToolOperationError::PublishedAuthorityUnavailable {
                detail: format!(
                    "provisioned token for session {} is invalid: {error}",
                    session
                ),
            }
        })
    }
}

/// The host-composed operation binding of every live session, registered as
/// sessions open, for serving paths (the per-turn brain context listing) that
/// must verify the exact authority the session dispatches under.
/// Registration only makes a session resolvable; every use re-verifies.
pub(crate) struct LiveSessionBindings {
    operations: HostToolOperations,
    bindings: Mutex<BTreeMap<SessionId, SessionOperationBinding>>,
}

impl LiveSessionBindings {
    pub(crate) fn new(operations: HostToolOperations) -> Self {
        Self {
            operations,
            bindings: Mutex::new(BTreeMap::new()),
        }
    }

    pub(crate) fn register(&self, session: SessionId, binding: SessionOperationBinding) {
        if let Ok(mut bindings) = self.bindings.lock() {
            bindings.insert(session, binding);
        }
    }

    pub(crate) fn operations(&self) -> &HostToolOperations {
        &self.operations
    }

    pub(crate) fn binding_for(&self, session: &SessionId) -> Option<SessionOperationBinding> {
        self.bindings.lock().ok()?.get(session).cloned()
    }
}

/// Generates test-only signing material for provisioned fixture tokens.
///
/// Production receives verification material from an operator-owned file and
/// receives signed tokens through [`ProvisionedFreshAuthorityProvider`];
/// neither this function nor a token issuer exists in non-test builds.
#[cfg(test)]
pub fn generate_signing_key() -> Vec<u8> {
    use uuid::Uuid;

    let mut key = Vec::with_capacity(32);
    key.extend_from_slice(Uuid::new_v4().as_bytes());
    key.extend_from_slice(Uuid::new_v4().as_bytes());
    key
}

/// Host wall clock in Unix milliseconds for the authority's trusted clock.
pub fn wall_clock() -> odin_kernel::Clock {
    Arc::new(|| {
        let now = time::OffsetDateTime::now_utc();
        u64::try_from(now.unix_timestamp())
            .unwrap_or(0)
            .saturating_mul(1_000)
            .saturating_add(u64::from(now.nanosecond()) / 1_000_000)
    })
}
