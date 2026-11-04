//! Intake checks against admitted capabilities, live authority and durable revocation state.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use odin_domain::CapabilityId;
use odin_kernel::CapabilityContract;

use super::IntakeAuthorityFacts;

/// Checks contract/version, live seat revocation and stop state, and durable intent
/// revocation on each intake. Rejects until authority facts are configured.
pub(super) struct PublishedIntakeGovernance {
    pub(super) contracts: Arc<BTreeMap<CapabilityId, CapabilityContract>>,
    pub(super) seat: String,
    pub(super) authorization_ref: String,
    /// The live authority facts cell, shared with
    /// [`super::HermesRuntime::set_intake_authority`].
    pub(super) authority: Arc<Mutex<Option<Arc<dyn IntakeAuthorityFacts>>>>,
    /// Durable revocation probe: `true` means the named intent's exact
    /// approval row is cancelled/denied, or its task row is terminally
    /// stopped. Backed by the shared correlation store's kernel gate.
    pub(super) revoked: Box<dyn Fn(&str) -> bool + Send + Sync>,
}

impl crate::ingress::IntakeGovernance for PublishedIntakeGovernance {
    fn authorize_intake(
        &self,
        invocation: crate::ingress::IntakeInvocation,
    ) -> crate::ingress::GovernanceDecision {
        // Live published authority: the contract must be admitted by the
        // map right now, at exactly the invoked version — a stale or
        // disabled capability refuses here, never downstream.
        let admitted = match self.contracts.get(&invocation.capability) {
            Some(contract) => contract.version,
            None => {
                return crate::ingress::GovernanceDecision::Rejected {
                    reason: format!(
                        "intake names capability {}, which the published authority \
                         does not currently admit",
                        invocation.capability
                    ),
                };
            }
        };
        if u64::from(admitted) != invocation.capability_version {
            return crate::ingress::GovernanceDecision::Rejected {
                reason: format!(
                    "intake names capability {} v{}, but the published authority \
                     admits v{admitted}",
                    invocation.capability, invocation.capability_version
                ),
            };
        }
        // Live seat authority: current token revocation and stop state from
        // the daemon's real operation authority. Unbound refuses closed.
        let facts = self
            .authority
            .lock()
            .ok()
            .and_then(|cell| cell.as_ref().cloned());
        let Some(facts) = facts else {
            return crate::ingress::GovernanceDecision::Rejected {
                reason: "the live seat-authority facts are not bound; intake refuses \
                         closed"
                    .to_owned(),
            };
        };
        if facts.seat_token_revoked(&self.seat) {
            return crate::ingress::GovernanceDecision::Rejected {
                reason: format!("seat {} token is currently revoked", self.seat),
            };
        }
        let identity = crate::correlation::identity_from_key(&invocation.idempotency_key);
        if facts.stopped(&identity) {
            return crate::ingress::GovernanceDecision::Rejected {
                reason: format!("intent {identity} is under a real current stop"),
            };
        }
        if (self.revoked)(&identity) {
            return crate::ingress::GovernanceDecision::Rejected {
                reason: format!("intent {identity} is revoked or stopped in the durable ledger"),
            };
        }
        crate::ingress::GovernanceDecision::Authorized {
            authorization_ref: self.authorization_ref.clone(),
        }
    }
}
