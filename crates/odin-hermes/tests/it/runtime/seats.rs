//! Model-facing ask surfaces: retry selectors, bound-project constraints, declaration-only generation, and typed status seams.

use crate::runtime::fixtures::{
    delegation_contracts, delegation_tool_names, fixture_bound_projects, settings, tool_named,
};
use odin_domain::CapabilityId;
use odin_hermes::runtime::HermesRuntime;
use odin_kernel::CapabilityContract;
use odin_ledger::Ledger;
use parking_lot::Mutex;
use std::collections::BTreeMap;
use std::sync::Arc;

/// With no admitted delegation declarations, NO ask surface exists: the
/// model-facing listing carries no seat-named tool and no target guess.
#[test]
fn seat_ask_surfaces_are_generated_only_from_declared_targets() {
    let dir = tempfile::tempdir().unwrap();
    let runtime = runtime_in(dir.path());
    let tools = odin_hermes::runtime::hermes_host_tools(&runtime);
    for name in delegation_tool_names() {
        assert!(
            !tools.iter().any(|tool| tool.definition().name == name),
            "{name} must not exist without an admitted delegation declaration"
        );
    }
}
#[test]
fn seat_ask_serves_an_unbound_seat_with_no_named_projects() {
    let dir = tempfile::tempdir().unwrap();
    let runtime = HermesRuntime::open(
        settings(dir.path()),
        odin_hermes::runtime::HermesLedgers {
            conversation: Ledger::open_in_memory().unwrap(),
            adapter: Arc::new(Mutex::new(Ledger::open_in_memory().unwrap())),
            purchase: Arc::new(std::sync::Mutex::new(Ledger::open_in_memory().unwrap())),
        },
        &delegation_contracts(),
        None,
        8_192,
        BTreeMap::new(),
        None,
    )
    .unwrap();
    let tool = tool_named(&runtime, "seat_ask_architect");

    let project = tool
        .definition()
        .parameters
        .get("properties")
        .and_then(|properties| properties.get("project"))
        .expect("an unbound target still declares the project property");
    assert!(
        project.get("enum").is_none(),
        "the project set is never a frozen enum"
    );
}
/// Evidence extractors must relay handler results unchanged under the owning capability.
#[test]
fn capability_bindings_resolve_and_extractors_relay() {
    let dir = tempfile::tempdir().unwrap();
    let runtime = runtime_in(dir.path());
    let bindings = odin_hermes::runtime::hermes_capability_bindings(&runtime);

    let mut relays = 0;

    for (id, tool) in &bindings {
        let Some(owner) = id
            .strip_prefix("odin_hermes_")
            .and_then(|name| name.strip_suffix("_evidence"))
        else {
            continue;
        };
        let invocation = odin_omp::host_tools::HostInvocation {
            scope: odin_domain::Scope::default(),
            arguments: serde_json::json!({ "output": { "probe": id } }),
        };
        let relayed = tool
            .invoke(invocation)
            .expect("the evidence extractor performs no I/O and relays verbatim");
        assert_eq!(
            relayed,
            serde_json::json!({ "capability": owner, "result": { "probe": id } }),
            "{id} must relay the handler result verbatim"
        );
        relays += 1;
    }
    assert!(
        relays > 0,
        "the compiled binding table must hold evidence extractors to relay"
    );
}
fn runtime_in(dir: &std::path::Path) -> Arc<HermesRuntime> {
    HermesRuntime::open(
        settings(dir),
        odin_hermes::runtime::HermesLedgers {
            conversation: Ledger::open_in_memory().unwrap(),
            adapter: Arc::new(Mutex::new(Ledger::open_in_memory().unwrap())),
            purchase: Arc::new(std::sync::Mutex::new(Ledger::open_in_memory().unwrap())),
        },
        &BTreeMap::<CapabilityId, CapabilityContract>::new(),
        None,
        8_192,
        fixture_bound_projects(),
        None,
    )
    .unwrap()
}
