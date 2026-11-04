//! Composition refusals: ownership, admitted capabilities, delegation targets, and the Discord surface must agree.

use crate::runtime::fixtures::{
    conversation_ownership, discord_settings, fixture_bound_projects, intake_contract,
    owner_ask_contract,
};
use odin_domain::{CapabilityId, SeatId};
use odin_hermes::runtime::{ConversationOwnership, HermesRuntime, HermesRuntimeError};
use odin_kernel::CapabilityContract;
use odin_ledger::Ledger;
use parking_lot::Mutex;
use std::collections::BTreeMap;
use std::sync::Arc;

/// Why opening a runtime with these facts is refused; adapter-only composition
/// (no Discord surface) may declare ownership too.
fn composition_refusal(
    discord: bool,
    contracts: BTreeMap<CapabilityId, CapabilityContract>,
    ownership: Option<ConversationOwnership>,
) -> String {
    let dir = tempfile::tempdir().unwrap();
    let settings = odin_hermes::config::HermesSettings::new(
        dir.path().join("state"),
        discord.then(discord_settings),
        None,
        Vec::new(),
    )
    .unwrap();
    let opened = HermesRuntime::open(
        settings,
        odin_hermes::runtime::HermesLedgers {
            conversation: Ledger::open_in_memory().unwrap(),
            adapter: Arc::new(Mutex::new(Ledger::open_in_memory().unwrap())),
            purchase: Arc::new(std::sync::Mutex::new(Ledger::open_in_memory().unwrap())),
        },
        &contracts,
        None,
        8_192,
        fixture_bound_projects(),
        ownership,
    );
    match opened {
        Err(HermesRuntimeError::Composition(reason)) => reason,
        Err(other) => panic!("expected a composition refusal, got {other:?}"),
        Ok(_) => panic!("the composition must be refused"),
    }
}

/// The intake and owner-ask contracts a Discord conversation needs.
fn discord_contracts() -> BTreeMap<CapabilityId, CapabilityContract> {
    let intake = intake_contract(odin_domain::EffectClass::R1);
    let ask = owner_ask_contract();
    BTreeMap::from([(intake.id.clone(), intake), (ask.id.clone(), ask)])
}

#[test]
fn discord_surface_without_declared_ownership_refuses_composition() {
    let reason = composition_refusal(true, discord_contracts(), None);
    assert!(reason.contains("none was supplied"), "{reason}");
}

#[test]
fn ownership_with_mismatched_delegation_target_refuses_composition() {
    let mut contract = owner_ask_contract();
    contract.delegate_to = Some(SeatId::new("kubert").unwrap());
    let contracts = BTreeMap::from([(contract.id.clone(), contract)]);
    let reason = composition_refusal(false, contracts, Some(conversation_ownership()));
    assert!(reason.contains("delegates to kubert"), "{reason}");
}
