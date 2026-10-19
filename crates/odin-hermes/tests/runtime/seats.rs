//! Model-facing ask surfaces: retry selectors, bound-project constraints, declaration-only generation, and typed status seams.

use crate::fixtures::{
    delegation_contracts, delegation_tool_names, fixture_bound_projects, runtime_with_declarations,
    settings,
};
use odin_domain::CapabilityId;
use odin_hermes::runtime::HermesRuntime;
use odin_kernel::CapabilityContract;
use odin_ledger::Ledger;
use parking_lot::Mutex;
use std::collections::BTreeMap;
use std::sync::Arc;

/// The R3 seat asks must admit the `approvalId` retry selector on their
/// model-facing surface — optional, never required — because the approval
/// gate's first-dispatch refusal returns a durable approval id the model can
/// only present through this key. A surface without it orphans the request.
#[test]
fn seat_ask_surfaces_declare_the_approval_retry_selector() {
    let dir = tempfile::tempdir().unwrap();
    let runtime = runtime_with_declarations(dir.path());
    let tools = odin_hermes::runtime::hermes_host_tools(&runtime);

    for name in delegation_tool_names() {
        let tool = tools
            .iter()
            .find(|tool| tool.definition().name == name)
            .unwrap_or_else(|| panic!("{name} must be registered"));
        let parameters = &tool.definition().parameters;
        let selector = parameters
            .get("properties")
            .and_then(|properties| properties.get("approvalId"))
            .unwrap_or_else(|| panic!("{name} must declare the approvalId property"));
        assert!(
            selector.get("type").and_then(serde_json::Value::as_str) == Some("string"),
            "{name} approvalId must be a string selector"
        );
        let required = parameters
            .get("required")
            .and_then(serde_json::Value::as_array)
            .cloned()
            .unwrap_or_default();
        assert!(
            !required
                .iter()
                .any(|entry| entry == &serde_json::json!("approvalId")),
            "{name} must not require approvalId on the first dispatch"
        );
    }
}
/// The host-injected reserved target argument must NEVER appear on a
/// model-facing ask surface — not as a property, not as required — and no
/// seat/target field may exist at all: the model cannot name or see the
/// delegation target.
#[test]
fn seat_ask_surfaces_never_declare_the_host_target_argument() {
    let dir = tempfile::tempdir().unwrap();
    let runtime = runtime_with_declarations(dir.path());
    let tools = odin_hermes::runtime::hermes_host_tools(&runtime);

    for name in delegation_tool_names() {
        let tool = tools
            .iter()
            .find(|tool| tool.definition().name == name)
            .unwrap_or_else(|| panic!("{name} must be registered"));
        let parameters = &tool.definition().parameters;
        let properties = parameters
            .get("properties")
            .and_then(|properties| properties.as_object())
            .expect("the ask surface declares an object schema");
        for forbidden in ["_delegate_to", "target", "target_seat", "seat"] {
            assert!(
                !properties.contains_key(forbidden),
                "{name} must not declare the {forbidden} property: the target is \
                 never model input"
            );
        }
        let required = parameters
            .get("required")
            .and_then(serde_json::Value::as_array)
            .cloned()
            .unwrap_or_default();
        assert!(
            !required
                .iter()
                .any(|entry| entry == &serde_json::json!("_delegate_to")),
            "{name} must not require the host-only target argument"
        );
    }
}
#[test]
fn seat_ask_surfaces_name_the_bound_projects_and_freeze_no_enum() {
    let dir = tempfile::tempdir().unwrap();
    let runtime = runtime_with_declarations(dir.path());
    let tools = odin_hermes::runtime::hermes_host_tools(&runtime);

    for (name, admitted) in [
        ("seat_ask_sinmara", vec!["life"]),
        ("seat_ask_kubert", vec!["odin"]),
        ("seat_ask_gungnir", vec!["odin", "skuld"]),
    ] {
        let tool = tools
            .iter()
            .find(|tool| tool.definition().name == name)
            .unwrap_or_else(|| panic!("{name} must be registered"));
        let project = tool
            .definition()
            .parameters
            .get("properties")
            .and_then(|properties| properties.get("project"))
            .unwrap_or_else(|| panic!("{name} must declare the project property"));
        assert!(
            project.get("enum").is_none(),
            "{name} must not freeze the project set into an enum"
        );
        let description = project
            .get("description")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_else(|| panic!("{name} must describe the project property"));
        for bound in &admitted {
            assert!(
                description.contains(bound),
                "{name} must name its bound project {bound}: {description}"
            );
        }
    }
}
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
    let tools = odin_hermes::runtime::hermes_host_tools(&runtime);
    let tool = tools
        .iter()
        .find(|tool| tool.definition().name == "seat_ask_architect")
        .expect("seat_ask_architect must still be listed for an unbound seat");

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
#[test]
fn status_pump_reports_unconfigured_discord_typed() {
    let dir = tempfile::tempdir().unwrap();
    let runtime = runtime_in(dir.path());
    let error = runtime
        .pump_status_egress(4)
        .expect_err("a Discord-less runtime cannot send status");
    assert!(
        error.contains("discord surface is not configured"),
        "the typed unavailability must name the unconfigured surface: {error}"
    );
}
#[test]
fn purchase_transport_reports_undeclared_deployment() {
    let dir = tempfile::tempdir().unwrap();
    let runtime = runtime_in(dir.path());
    assert!(
        !runtime.purchase_transport_deployed(),
        "no backend deployment was bound"
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
