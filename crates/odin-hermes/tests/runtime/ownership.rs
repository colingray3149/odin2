//! Composition refusals: ownership, admitted capabilities, delegation targets, and the Discord surface must agree.

use crate::fixtures::{
    conversation_ownership, discord_settings, fixture_bound_projects, intake_contract,
    owner_ask_contract,
};
use odin_domain::{CapabilityId, ProjectId, SeatId};
use odin_hermes::runtime::{ConversationOwnership, HermesRuntime};
use odin_kernel::CapabilityContract;
use odin_ledger::Ledger;
use parking_lot::Mutex;
use std::collections::BTreeMap;
use std::sync::Arc;

#[test]
fn discord_surface_without_declared_ownership_refuses_composition() {
    let dir = tempfile::tempdir().unwrap();
    let settings = odin_hermes::config::HermesSettings::new(
        dir.path().join("state"),
        Some(discord_settings()),
        None,
        None,
        Vec::new(),
    )
    .unwrap();
    let mut contracts = BTreeMap::from([(
        CapabilityId::new("discord.intake").unwrap(),
        intake_contract(odin_domain::EffectClass::R1),
    )]);
    contracts.insert(owner_ask_contract().id.clone(), owner_ask_contract());
    let error = HermesRuntime::open(
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
        None,
    )
    .err()
    .expect("a configured Discord surface without ownership must refuse");
    assert!(matches!(
        error,
        odin_hermes::runtime::HermesRuntimeError::Composition(_)
    ));
}
#[test]
fn ownership_with_unadmitted_ask_capability_refuses_composition() {
    let dir = tempfile::tempdir().unwrap();
    let settings = odin_hermes::config::HermesSettings::new(
        dir.path().join("state"),
        None, // adapter-only composition may declare ownership without Discord
        None,
        None,
        Vec::new(),
    )
    .unwrap();
    let error = HermesRuntime::open(
        settings,
        odin_hermes::runtime::HermesLedgers {
            conversation: Ledger::open_in_memory().unwrap(),
            adapter: Arc::new(Mutex::new(Ledger::open_in_memory().unwrap())),
            purchase: Arc::new(std::sync::Mutex::new(Ledger::open_in_memory().unwrap())),
        },
        &BTreeMap::<CapabilityId, CapabilityContract>::new(),
        None,
        8_192,
        fixture_bound_projects(),
        Some(conversation_ownership()),
    )
    .err()
    .expect("an unadmitted ask capability must refuse");
    assert!(matches!(
        error,
        odin_hermes::runtime::HermesRuntimeError::Composition(_)
    ));
}
#[test]
fn ownership_with_mismatched_delegation_target_refuses_composition() {
    let dir = tempfile::tempdir().unwrap();
    let settings = odin_hermes::config::HermesSettings::new(
        dir.path().join("state"),
        None,
        None,
        None,
        Vec::new(),
    )
    .unwrap();
    let mut contract = owner_ask_contract();
    contract.delegate_to = Some(SeatId::new("kubert").unwrap());
    let contracts = BTreeMap::from([(contract.id.clone(), contract)]);
    let error = HermesRuntime::open(
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
        Some(conversation_ownership()),
    )
    .err()
    .expect("an ask contract delegating elsewhere must refuse");
    assert!(matches!(
        error,
        odin_hermes::runtime::HermesRuntimeError::Composition(_)
    ));
}
#[test]
fn ownership_mismatching_the_discord_surface_refuses_composition() {
    for (seat, project) in [("kubert", "life"), ("sinmara", "odin")] {
        let dir = tempfile::tempdir().unwrap();
        let settings = odin_hermes::config::HermesSettings::new(
            dir.path().join("state"),
            Some(discord_settings()),
            None,
            None,
            Vec::new(),
        )
        .unwrap();
        let contract = intake_contract(odin_domain::EffectClass::R1);
        let mut contracts = BTreeMap::from([(contract.id.clone(), contract)]);
        contracts.insert(owner_ask_contract().id.clone(), owner_ask_contract());
        let ownership = ConversationOwnership {
            seat: SeatId::new(seat).unwrap(),
            project: ProjectId::new(project).unwrap(),
            ask_capability: CapabilityId::new("seat.ask.sinmara").unwrap(),
        };
        let error = HermesRuntime::open(
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
            Some(ownership),
        )
        .err()
        .expect("ownership not matching the surface must refuse");
        assert!(matches!(
            error,
            odin_hermes::runtime::HermesRuntimeError::Composition(_)
        ));
    }
}
