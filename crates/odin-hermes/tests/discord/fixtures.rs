//! Shared private fixtures for this suite; visible only to child modules here.

use odin_domain::{CapabilityId, EffectClass, SeatId};
use odin_hermes::correlation::ConversationTaskStore;
use odin_hermes::discord::DiscordMessage;
use odin_hermes::ingress::{
    GovernanceDecision, IngressConfig, IntakeGovernance, IntakeInvocation, OwnerPairing,
};
use odin_ledger::Ledger;
use serde_json::Value;
use std::sync::Arc;
use time::OffsetDateTime;

pub(crate) const OWNER: &str = "222222222222222222";

pub(crate) const DM_CHANNEL: &str = "900000000000000001";

/// The declared ask capability this fixture conversation binds: pure
/// configuration data, exactly as the daemon's strict wire section
/// supplies it.
pub(crate) const ASK_CAPABILITY: &str = "seat.ask.sinmara";

pub(crate) fn now() -> OffsetDateTime {
    OffsetDateTime::from_unix_timestamp(1_789_000_000).unwrap()
}

pub(crate) fn pairing() -> OwnerPairing {
    OwnerPairing::new(OWNER).unwrap()
}

pub(crate) fn ingress_config(effect_class: EffectClass) -> IngressConfig {
    IngressConfig::new(
        SeatId::new("sinmara").unwrap(),
        CapabilityId::new(ASK_CAPABILITY).unwrap(),
        1,
        effect_class,
        900,
        Some(DM_CHANNEL.to_owned()),
    )
    .unwrap()
}

pub(crate) fn message(id: &str, author: &str, content: &str) -> DiscordMessage {
    DiscordMessage {
        id: id.to_owned(),
        channel_id: DM_CHANNEL.to_owned(),
        author_id: author.to_owned(),
        guild_id: None,
        content: content.to_owned(),
        attachments: Vec::new(),
    }
}

pub(crate) fn store(ledger: Ledger) -> Arc<ConversationTaskStore> {
    Arc::new(ConversationTaskStore::new(ledger))
}

struct AllowingGovernance;

impl IntakeGovernance for AllowingGovernance {
    fn authorize_intake(&self, _invocation: IntakeInvocation) -> GovernanceDecision {
        GovernanceDecision::Authorized {
            authorization_ref: "authz:test".to_owned(),
        }
    }
}

pub(crate) fn allowing() -> Arc<dyn IntakeGovernance> {
    Arc::new(AllowingGovernance)
}

pub(crate) struct CapturedRequest {
    pub(super) channel_id: String,
    pub(super) authorization: String,
    pub(super) body: Value,
}
