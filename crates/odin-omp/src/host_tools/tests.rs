use std::fs;
use std::sync::{Arc, Mutex};

use odin_atlas::{AtlasScope, AtlasSources};
use odin_domain::Scope;
use odin_ledger::Ledger;
use odin_types::OperationId;
use serde_json::{json, Value};

use super::context_read::{ContextReadTool, CONTEXT_READ_EVIDENCE_ID, CONTEXT_READ_HANDLER_ID};
use super::dispatch::MODEL_VISIBLE_TOOL_NAMES;
use super::*;

mod binding;
mod catalog;
mod framed_custody;

struct StubTool {
    definition: RpcHostToolDefinition,
    response: Value,
}

impl StubTool {
    fn new(name: impl Into<Cow<'static, str>>) -> Self {
        Self {
            definition: RpcHostToolDefinition {
                name: name.into(),
                label: Cow::Borrowed("Stub"),
                description: Cow::Borrowed("registry contract stub"),
                parameters: json!({
                    "type": "object",
                    "properties": {},
                    "additionalProperties": false
                }),
                hidden: false,
                load_mode: ToolLoadMode::Discoverable,
            },
            response: json!({ "ok": true }),
        }
    }
}

impl HostTool for StubTool {
    fn definition(&self) -> &RpcHostToolDefinition {
        &self.definition
    }

    fn preflight(
        &self,
        _contract: &odin_kernel::CapabilityContract,
        _scope: &Scope,
        _arguments: &Value,
    ) -> Result<(), HostToolError> {
        // Registry-composition stub: no external readiness exists, so the
        // gate is the explicit no-op; the stub never executes a real
        // effect.
        Ok(())
    }

    fn invoke(&self, _invocation: HostInvocation) -> Result<Value, HostToolError> {
        Ok(self.response.clone())
    }
}

struct BoundTestOwner;

impl BrowserCapabilityOwner for BoundTestOwner {
    fn invoke_browser_capability(
        &self,
        _binding: BrowserCapabilityBinding,
        _invocation: HostInvocation,
    ) -> Result<Value, HostToolError> {
        Ok(json!({ "ok": true }))
    }

    fn preflight_browser_capability(
        &self,
        _contract: &odin_kernel::CapabilityContract,
        _binding: BrowserCapabilityBinding,
        _scope: &Scope,
        _arguments: &Value,
    ) -> Result<(), HostToolError> {
        // Composition fixture: no external readiness exists, so the gate is
        // the explicit no-op.
        Ok(())
    }
}

struct CanonicalTestOwner;

impl CanonicalV2CapabilityOwner for CanonicalTestOwner {
    fn invoke_authority_binding(
        &self,
        _binding: CanonicalV2CapabilityBinding,
        _capsule_id: CapsuleId,
        _correlation_id: CorrelationId,
        _invocation: HostInvocation,
    ) -> Result<Value, HostToolError> {
        Ok(json!({ "ok": true }))
    }

    fn preflight_authority_binding(
        &self,
        _contract: &odin_kernel::CapabilityContract,
        _binding: CanonicalV2CapabilityBinding,
        _scope: &Scope,
        _arguments: &Value,
    ) -> Result<(), HostToolError> {
        // Composition fixture: no external readiness exists, so the gate is
        // the explicit no-op.
        Ok(())
    }
}

struct KubeTestOwner;

impl kube::KubeCapabilityOwner for KubeTestOwner {
    fn launchable_profiles(&self) -> Vec<kube::LaunchableProfile> {
        vec![kube::LaunchableProfile {
            id: "gpu-smoke".to_owned(),
            description: "Bounded one-GPU smoke test.".to_owned(),
            gpu_count: 1,
            seats: vec!["kubert".to_owned()],
        }]
    }

    fn invoke_kube_capability(
        &self,
        _binding: kube::KubeCapabilityBinding,
        _timeout_seconds: u32,
        _operation_id: OperationId,
        _invocation: HostInvocation,
    ) -> Result<Value, HostToolError> {
        Ok(json!({ "ok": true }))
    }

    fn preflight_kube_capability(
        &self,
        _contract: &odin_kernel::CapabilityContract,
        _binding: kube::KubeCapabilityBinding,
        _scope: &Scope,
        _arguments: &Value,
    ) -> Result<(), HostToolError> {
        // The fixture declares no pre-consume gate: execution-time
        // validation governs, exactly as production owners without one.
        Ok(())
    }
}

struct CatalogTestTaskOwner;

impl delegation::TaskOwner for CatalogTestTaskOwner {
    fn create_task(
        &self,
        _request: delegation::TaskCreateRequest,
    ) -> Result<delegation::TaskCreateReceipt, delegation::TaskToolFailure> {
        Err(delegation::TaskToolFailure {
            kind: "catalog_fixture",
            detail: "the catalog composition fixture does not execute tasks".to_owned(),
            effect_may_have_started: false,
        })
    }

    fn preflight_task(
        &self,
        _request: &delegation::TaskCreateRequest,
    ) -> Result<(), delegation::TaskToolFailure> {
        // The composition fixture declares no readiness surface to observe:
        // it provisions nothing and owns no runtime seam. Its execution
        // paths refuse typed regardless.
        Ok(())
    }

    fn read_task(
        &self,
        _request: delegation::TaskReadRequest,
    ) -> Result<delegation::TaskReadReport, delegation::TaskToolFailure> {
        Err(delegation::TaskToolFailure {
            kind: "catalog_fixture",
            detail: "the catalog composition fixture does not execute tasks".to_owned(),
            effect_may_have_started: false,
        })
    }
}

#[test]
fn duplicate_names_are_rejected_and_leave_the_registry_intact() {
    let mut registry = HostToolRegistry::new();
    let mut original = StubTool::new("odin_plan_set".to_owned());
    original.response = json!("original");
    let mut replacement = StubTool::new("odin_plan_set");
    replacement.response = json!("replacement");
    registry
        .register(Arc::new(original))
        .expect("first registration succeeds");

    let error = registry
        .register(Arc::new(replacement))
        .expect_err("duplicate names are rejected");

    assert!(matches!(
        error,
        HostToolError::DuplicateTool { name } if name == "odin_plan_set"
    ));
    let result = registry
        .dispatch(
            "odin_plan_set",
            HostInvocation {
                scope: Scope::default(),
                arguments: json!({}),
            },
        )
        .expect("original tool remains callable");
    assert_eq!(result, json!("original"));
}

#[test]
fn definitions_follow_lexicographic_name_order() {
    let mut registry = HostToolRegistry::new();
    for name in ["odin_todo_update", "odin_plan_set", "odin_lane_status"] {
        registry
            .register(Arc::new(StubTool::new(name)))
            .expect("unique stub names register");
    }

    let definitions = registry.definitions();
    let names: Vec<&str> = definitions
        .iter()
        .map(|definition| definition.name.as_ref())
        .collect();

    assert_eq!(
        names,
        ["odin_lane_status", "odin_plan_set", "odin_todo_update"]
    );
    assert_eq!(registry.listed_names().collect::<Vec<_>>(), names);
}

#[test]
fn dispatch_routes_by_name_and_rejects_unknown_names() {
    let mut registry = HostToolRegistry::new();
    registry
        .register(Arc::new(StubTool::new("odin_plan_set")))
        .expect("registration succeeds");

    let routed = registry
        .dispatch(
            "odin_plan_set",
            HostInvocation {
                scope: Scope::default(),
                arguments: json!({}),
            },
        )
        .expect("known names dispatch");
    assert_eq!(routed["ok"], true);

    let error = registry
        .dispatch(
            "odin_atlas_query",
            HostInvocation {
                scope: Scope::default(),
                arguments: json!({}),
            },
        )
        .expect_err("unknown names are rejected");
    assert!(matches!(
        error,
        HostToolError::UnknownTool { name } if name == "odin_atlas_query"
    ));
}

#[test]
fn model_visible_assembles_exactly_the_six_visible_tools_with_strict_schemas() {
    let root = std::env::temp_dir().join(format!(
        "odin-omp-model-visible-tools-{}",
        std::process::id()
    ));
    for directory in ["crates/demo/src", "extension", "registry", "skeletons"] {
        fs::create_dir_all(root.join(directory)).expect("create atlas fixture directory");
    }
    fs::write(
        root.join("crates/demo/src/lib.rs"),
        "pub fn stable(value: u64) -> u64 { value }\n",
    )
    .expect("write Rust fixture");

    let registry = HostToolRegistry::model_visible(ModelVisibleToolConfig {
        ledger: Arc::new(Mutex::new(
            Ledger::open_in_memory().expect("in-memory ledger opens"),
        )),
        atlas: Arc::new(odin_atlas::build(AtlasSources::new(&root)).expect("build atlas fixture")),
        allowed_atlas_scope: AtlasScope::seat(["coding".to_owned()]).expect("valid seat scope"),
        artifact_root: root.clone(),
    })
    .expect("real model-visible constructors assemble");

    let definitions = registry.definitions();
    let names: Vec<&str> = definitions
        .iter()
        .map(|definition| definition.name.as_ref())
        .collect();
    assert_eq!(
        names, MODEL_VISIBLE_TOOL_NAMES,
        "assembly must equal the six-name set"
    );

    for definition in &definitions {
        assert!(
            !definition.hidden,
            "{} must be model-visible",
            definition.name
        );
        assert!(
            definition.parameters.is_object(),
            "{} must have an object schema",
            definition.name
        );
        assert_eq!(
            definition.parameters["type"], "object",
            "{} must declare an object schema",
            definition.name
        );
        assert_eq!(
            definition.parameters["additionalProperties"], false,
            "{} must reject unknown arguments",
            definition.name
        );
    }

    let _ = fs::remove_dir_all(&root);
}

fn real_enabled_capabilities() -> Vec<(String, odin_registry::schema::CapabilityToml)> {
    let capabilities_root =
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../registry/capabilities");
    let mut entries: Vec<_> = fs::read_dir(&capabilities_root)
        .expect("list the real registry capability tree")
        .collect();
    entries.sort_by_key(|entry| entry.as_ref().ok().map(|value| value.file_name()));

    let mut enabled = Vec::new();
    for entry in entries {
        let entry = entry.expect("readable capability directory entry");
        if !entry.file_type().expect("capability entry type").is_dir() {
            continue;
        }
        let id = entry.file_name().into_string().expect("capability id");
        let declaration = entry.path().join("capability.toml");
        let source = fs::read_to_string(&declaration).expect("read real capability declaration");
        let object = odin_registry::schema::parse_object_toml(
            odin_registry::RegistryKind::Capability,
            id.clone(),
            std::path::PathBuf::from(format!("registry/capabilities/{id}/capability.toml")),
            &source,
        )
        .expect("parse real capability declaration");
        let odin_registry::ObjectConfig::Capability(capability) = object.config else {
            panic!("real declaration must parse as a capability");
        };
        if capability.enabled {
            enabled.push((object.id, *capability));
        }
    }
    enabled
}

/// Real registry capability tags must admit the coordinator seat that delegates.
#[test]
fn coordinator_seat_effective_listing_admits_the_declared_task_and_browser_tools() {
    let parse_real = |kind: odin_registry::RegistryKind, id: &str, relative: &str| {
        let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
        let source = fs::read_to_string(root.join(relative)).expect("read real registry object");
        odin_registry::schema::parse_object_toml(
            kind,
            id.to_owned(),
            std::path::PathBuf::from(relative),
            &source,
        )
        .expect("parse real registry object")
    };
    let odin_registry::ObjectConfig::Seat(seat) = parse_real(
        odin_registry::RegistryKind::Seat,
        "sinmara",
        "registry/seats/sinmara/seat.toml",
    )
    .config
    else {
        panic!("sinmara seat must parse as a seat");
    };
    let odin_registry::ObjectConfig::Slice(slice) = parse_real(
        odin_registry::RegistryKind::Slice,
        "sinmara-life",
        "registry/slices/sinmara-life/slice.toml",
    )
    .config
    else {
        panic!("sinmara-life slice must parse as a slice");
    };

    // Contracts exactly as the daemon assembles them: every enabled
    // registry capability converted through its compiled admitted tuple.
    let mut contracts = std::collections::BTreeMap::new();
    for (id, capability) in real_enabled_capabilities() {
        let object = parse_real(
            odin_registry::RegistryKind::Capability,
            &id,
            &format!("registry/capabilities/{id}/capability.toml"),
        );
        let admitted = odin_registry::relational::AdmittedBinding {
            version: capability.version,
            input_schema: capability.input_schema.clone().expect("input schema"),
            output_schema: capability.output_schema.clone().expect("output schema"),
            handler: capability.handler.clone().expect("handler"),
            evidence_extractor: capability.evidence_extractor.clone().expect("extractor"),
        };
        let contract = odin_kernel::CapabilityContract::try_from_registry(&object, &admitted)
            .unwrap_or_else(|error| panic!("capability {id} contract failed: {error}"));
        contracts.insert(contract.id.clone(), contract);
    }

    // The (seat, lane) policy exactly as runtime_bindings composes it.
    let slice_capabilities: std::collections::BTreeSet<CapabilityId> =
        slice.capabilities.iter().cloned().collect();
    let denied_tools = seat
        .tools
        .iter()
        .flat_map(|tools| tools.deny.iter().cloned())
        .chain(
            slice
                .tools
                .iter()
                .flat_map(|tools| tools.deny.iter().cloned()),
        )
        .collect();
    let binding = crate::host_tools::operations::seat_operation_policy(
        crate::host_tools::operations::SeatOperationPolicyInputs {
            seat_id: odin_domain::SeatId::new("sinmara").expect("seat id"),
            slice_id: odin_domain::SliceId::new("sinmara-life").expect("slice id"),
            lane_id: odin_domain::LaneId::new("sinmara-life").expect("lane id"),
            seat_revision: Digest::hash(b"test-seat-revision"),
            slice_revision: Digest::hash(b"test-slice-revision"),
            admission: Digest::hash(b"test-admission"),
            seat_tool_refs: seat.tool_refs.iter().cloned().collect(),
            slice_capabilities: slice_capabilities.clone(),
            project_capabilities: slice_capabilities.clone(),
            lane_capabilities: slice_capabilities,
            denied_capabilities: std::collections::BTreeSet::new(),
            denied_tools,
            resource_constraints: std::collections::BTreeMap::new(),
            seat_categories: seat.categories.iter().cloned().collect(),
        },
    );
    let effective = odin_kernel::policy::effective(&binding.policy, &contracts);
    for id in ["task.create", "task.read", "browser.observe"] {
        let capability_id = CapabilityId::parse(id).expect("capability id");
        assert!(
            effective.contains(&capability_id),
            "{id} must stay effective for the delegating coordinator seat — \
             the seat and the slice both declare it"
        );
    }
    // The converse pin: a capability the slice does not declare stays out.
    let absent = CapabilityId::parse("kube.health.read").expect("capability id");
    assert!(
        !effective.contains(&absent),
        "kube.health.read must stay outside the sinmara projection"
    );
}

#[test]
fn internal_bindings_are_never_reachable_by_name() {
    // Permit-gated reachability through the executor is proven end to end
    // by the production_operation_dispatch matrix in host_tools::operations.
    let mut registry = HostToolRegistry::new();
    registry
        .register_internal(
            InternalBindingKey::Builtin("odin_internal_stub".to_owned()),
            Arc::new(StubTool::new("odin_internal_stub")),
        )
        .expect("internal binding registers");
    assert!(registry.definitions().is_empty());
    let error = registry
        .dispatch(
            "odin_internal_stub",
            HostInvocation {
                scope: Scope::default(),
                arguments: json!({}),
            },
        )
        .expect_err("internal binding without a listed tool name is unknown by name");
    assert!(matches!(error, HostToolError::UnknownTool { .. }));
}

/// A follower carries no operator context root: the published snapshot
/// decides that `context.read` must serve, so the node composes the real
/// bounded provider over its own sealed state-root `context` directory, and
/// startup admission must resolve both compiled bindings against that
/// concrete registry.
#[test]
fn context_read_composes_on_follower_posture_and_resolves_in_catalog() {
    use std::collections::{BTreeMap, BTreeSet};
    use std::num::NonZeroU32;

    use odin_domain::knowledge::ToolName;
    use odin_domain::{CapabilityId, EffectClass};
    use odin_kernel::{
        ApprovalRequirement, CapabilityContract, HandlerBinding, IdempotencyPolicy, RetryPolicy,
    };

    let state_root = std::env::temp_dir().join(format!(
        "odin-omp-follower-context-read-{}",
        std::process::id()
    ));
    let context_root = state_root.join("context");
    fs::create_dir_all(&context_root).expect("create node-local context root");
    for directory in ["crates/demo/src", "extension", "registry", "skeletons"] {
        fs::create_dir_all(state_root.join(directory)).expect("create atlas fixture directory");
    }
    fs::write(
        state_root.join("crates/demo/src/lib.rs"),
        "pub fn stable(value: u64) -> u64 { value }\n",
    )
    .expect("write Rust fixture");

    let mut registry = HostToolRegistry::model_visible(ModelVisibleToolConfig {
        ledger: Arc::new(Mutex::new(
            Ledger::open_in_memory().expect("in-memory ledger opens"),
        )),
        atlas: Arc::new(
            odin_atlas::build(AtlasSources::new(&state_root)).expect("build atlas fixture"),
        ),
        allowed_atlas_scope: AtlasScope::seat(["coding".to_owned()]).expect("valid seat scope"),
        artifact_root: state_root.clone(),
    })
    .expect("follower-shaped HostTool registry assembles");
    registry
        .register_context_read(&context_root, 4_096)
        .expect("context.read provider composes on the follower posture");

    let capability = CapabilityId::new("context.read").expect("capability id");
    let contract = CapabilityContract {
        id: capability.clone(),
        delegate_to: None,
        version: 1,
        tool_name: ToolName::new(ContextReadTool::NAME).expect("tool name"),
        description: "Follower-admitted bounded context read.".to_owned(),
        handler: HandlerBinding::Builtin {
            name: CONTEXT_READ_HANDLER_ID.to_owned(),
        },
        input_schema_ref: "schemas/capability/context.read.input.json".to_owned(),
        output_schema_ref: "schemas/capability/context.read.output.json".to_owned(),
        effect_class: EffectClass::R0,
        seat_tags: BTreeSet::from(["*".to_owned()]),
        timeout_seconds: NonZeroU32::new(5).expect("timeout"),
        idempotency: IdempotencyPolicy::Required,
        retry: RetryPolicy { max_attempts: 1 },
        approval: ApprovalRequirement::None,
        evidence_extractor: HandlerBinding::Builtin {
            name: CONTEXT_READ_EVIDENCE_ID.to_owned(),
        },
        adapter: None,
        preview: None,
        batchable: false,
        batch: None,
    };
    let contracts = BTreeMap::from([(capability, contract)]);
    let admission =
        crate::host_tools::operations::admission_digest(&contracts, 1).expect("admission digest");
    crate::host_tools::operations::DeclaredOperationCatalog::from_contracts(
        &contracts,
        1,
        admission,
        Arc::new(registry),
        &BTreeSet::new(),
    )
    .expect("context.read bindings resolve against the follower registry");
}

/// A follower carries no `[delegation]` section, so no governed task owner
/// ever exists — yet the pinned snapshot may still enable the task family.
/// The real task-owner slot composes permanently unbound: the compiled
/// catalog admits both capability bindings against their concrete handlers,
/// and the slot stays empty, so every invocation fails closed and no
/// mutation can ever land.
#[test]
fn task_capability_bindings_compose_unbound_on_follower_and_resolve_in_catalog() {
    use std::collections::{BTreeMap, BTreeSet};
    use std::num::NonZeroU32;

    use odin_domain::knowledge::ToolName;
    use odin_domain::{CapabilityId, EffectClass};
    use odin_kernel::{
        ApprovalRequirement, CapabilityContract, HandlerBinding, IdempotencyPolicy,
        OperationCatalog, RetryPolicy,
    };

    let root = std::env::temp_dir().join(format!(
        "odin-omp-follower-task-slot-{}",
        std::process::id()
    ));
    for directory in ["crates/demo/src", "extension", "registry", "skeletons"] {
        fs::create_dir_all(root.join(directory)).expect("create atlas fixture directory");
    }
    fs::write(
        root.join("crates/demo/src/lib.rs"),
        "pub fn stable(value: u64) -> u64 { value }\n",
    )
    .expect("write Rust fixture");

    let mut registry = HostToolRegistry::model_visible(ModelVisibleToolConfig {
        ledger: Arc::new(Mutex::new(
            Ledger::open_in_memory().expect("in-memory ledger opens"),
        )),
        atlas: Arc::new(odin_atlas::build(AtlasSources::new(&root)).expect("build atlas fixture")),
        allowed_atlas_scope: AtlasScope::seat(["coding".to_owned()]).expect("valid seat scope"),
        artifact_root: root.clone(),
    })
    .expect("follower-shaped HostTool registry assembles");
    let task_slot = Arc::new(delegation::TaskOwnerSlot::new());
    registry
        .register_task_capabilities(Arc::clone(&task_slot))
        .expect("task providers compose over the unbound follower slot");
    assert!(
        !task_slot.is_bound().expect("slot binding state reads"),
        "a follower never binds a task owner"
    );

    let task_contract = |id: &'static str,
                         tool: &'static str,
                         handler: &'static str,
                         evidence: &'static str,
                         effect_class| {
        CapabilityContract {
            id: CapabilityId::new(id).expect("capability id"),
            delegate_to: None,
            version: 1,
            tool_name: ToolName::new(tool).expect("tool name"),
            description: "Follower-admitted governed task capability.".to_owned(),
            handler: HandlerBinding::Builtin {
                name: handler.to_owned(),
            },
            input_schema_ref: format!("schemas/capability/{id}.input.json"),
            output_schema_ref: format!("schemas/capability/{id}.output.json"),
            effect_class,
            seat_tags: BTreeSet::from(["*".to_owned()]),
            timeout_seconds: NonZeroU32::new(5).expect("timeout"),
            idempotency: IdempotencyPolicy::Required,
            retry: RetryPolicy { max_attempts: 1 },
            approval: ApprovalRequirement::None,
            evidence_extractor: HandlerBinding::Builtin {
                name: evidence.to_owned(),
            },
            adapter: None,
            preview: None,
            batchable: false,
            batch: None,
        }
    };
    let contracts = BTreeMap::from([
        (
            CapabilityId::new("task.create").expect("capability id"),
            task_contract(
                "task.create",
                delegation::TASK_CREATE_TOOL,
                delegation::TASK_CREATE_HANDLER_ID,
                delegation::TASK_CREATE_EVIDENCE_ID,
                EffectClass::R1,
            ),
        ),
        (
            CapabilityId::new("task.read").expect("capability id"),
            task_contract(
                "task.read",
                delegation::TASK_READ_TOOL,
                delegation::TASK_READ_HANDLER_ID,
                delegation::TASK_READ_EVIDENCE_ID,
                EffectClass::R0,
            ),
        ),
    ]);
    let admission =
        crate::host_tools::operations::admission_digest(&contracts, 1).expect("admission digest");
    let catalog = crate::host_tools::operations::DeclaredOperationCatalog::from_contracts(
        &contracts,
        1,
        admission,
        Arc::new(registry),
        &BTreeSet::new(),
    )
    .expect("task bindings resolve against the unbound follower registry");
    for id in ["task.create", "task.read"] {
        let capability = CapabilityId::new(id).expect("capability id");
        assert!(
            catalog.admitted(&capability).is_some(),
            "{id} resolves in the follower catalog"
        );
    }
}

/// Direct task invocation requires a prepared operation; the owner slot permits one binding.
#[test]
fn unbound_task_slot_denies_direct_invocation_and_keeps_the_bind_law() {
    let task_slot = Arc::new(delegation::TaskOwnerSlot::new());
    let create = delegation::TaskCreateTool::new(Arc::clone(&task_slot))
        .expect("task.create tool assembles over the unbound slot");
    let read = delegation::TaskReadTool::new(Arc::clone(&task_slot))
        .expect("task.read tool assembles over the unbound slot");
    for tool in [&create as &dyn HostTool, &read as &dyn HostTool] {
        let error = tool
            .invoke(HostInvocation {
                scope: Scope::default(),
                arguments: json!({}),
            })
            .expect_err("direct invocation never bypasses the prepared-operation authority");
        assert!(
            matches!(error, HostToolError::Catalog { ref detail }
                        if detail.contains("requires a kernel-minted prepared operation")),
            "unexpected denial: {error:?}"
        );
    }
    assert!(
        !task_slot.is_bound().expect("slot binding state reads"),
        "composition alone never binds an owner"
    );
    let owner: Arc<dyn delegation::TaskOwner> = Arc::new(CatalogTestTaskOwner);
    task_slot
        .bind(owner)
        .expect("the authority posture binds its governed owner exactly once");
    let second: Arc<dyn delegation::TaskOwner> = Arc::new(CatalogTestTaskOwner);
    let error = task_slot
        .bind(second)
        .expect_err("the slot binds exactly one owner");
    assert!(
        matches!(error, HostToolError::Catalog { ref detail } if detail.contains("already bound")),
        "unexpected rebinding outcome: {error:?}"
    );
}
