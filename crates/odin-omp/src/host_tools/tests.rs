use std::fs;
use std::sync::{Arc, Mutex, OnceLock};

use odin_atlas::{AtlasScope, AtlasSources};
use odin_domain::Scope;
use odin_ledger::Ledger;
use odin_types::OperationId;
use serde_json::{json, Value};

use super::context_read::{CONTEXT_READ_EVIDENCE_ID, CONTEXT_READ_HANDLER_ID};
use super::*;

mod binding;
mod catalog;
mod framed_deadlines;

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
    fn launchable_profiles(
        &self,
        _project: Option<&odin_domain::ProjectId>,
    ) -> Vec<kube::LaunchableProfile> {
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
    fn acknowledge_inline_answer(
        &self,
        _child: odin_domain::huginn::LiveSessionId,
        _key: &str,
    ) -> Result<(), String> {
        Err("the catalog composition fixture does not deliver task answers".to_owned())
    }

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
