use std::borrow::Cow;
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use odin_atlas::{Atlas, AtlasScope};
use odin_domain::Scope;
use odin_kernel::PreparedEffect;
use odin_ledger::Ledger;
use odin_registry::schema::HandlerBindingToml;
use serde_json::Value;

use super::approval_request::ApprovalRequestTool;
use super::artifact_read::ArtifactReadTool;
use super::atlas_query::AtlasQueryTool;
use super::binding::{
    BrowserCapabilityBinding, BrowserCapabilityOwner, BrowserCapabilityTool, BrowserListedTool,
    CanonicalV2CapabilityBinding, CanonicalV2CapabilityOwner, CanonicalV2CapabilityTool,
    CapsuleListedTool, FramedExecTool,
};
use super::catalog::{CompiledHandlerBinding, PRE_ADMITTED_BINDINGS};
use super::context_read::{
    ContextReadEvidenceTool, ContextReadTool, CONTEXT_READ_EVIDENCE_ID, CONTEXT_READ_HANDLER_ID,
};
use super::delegation;
use super::executor;
use super::kube;
use super::lane_status::{LaneStatusEvidenceTool, LaneStatusTool};
use super::plan_set::PlanSetTool;
use super::todo_update::TodoUpdateTool;
use super::{ConsumedHostCommand, HostInvocation, HostTool, HostToolError, RpcHostToolDefinition};

/// The exact six model-visible tool names, in the registry's lexicographic order.
pub(super) const MODEL_VISIBLE_TOOL_NAMES: [&str; 6] = [
    ApprovalRequestTool::NAME,
    ArtifactReadTool::NAME,
    AtlasQueryTool::NAME,
    LaneStatusTool::NAME,
    PlanSetTool::NAME,
    TodoUpdateTool::NAME,
];

/// Constructor inputs are fixed by the host, never supplied as model arguments.
pub struct ModelVisibleToolConfig {
    /// Shared durable state behind the five ledger-backed tools.
    pub ledger: Arc<Mutex<Ledger>>,
    /// Immutable knowledge-index snapshot behind `odin_atlas_query`.
    pub atlas: Arc<Atlas>,
    /// The fixed scope granted to `odin_atlas_query`.
    pub allowed_atlas_scope: AtlasScope,
    /// The storage root behind `odin_artifact_read`.
    pub artifact_root: PathBuf,
}

/// Name-keyed host-tool registry.
///
/// Iteration and [`HostToolRegistry::definitions`] follow lexicographic tool-name
/// order regardless of registration order; duplicate names are rejected.
#[derive(Clone, Default)]
pub struct HostToolRegistry {
    pub(super) tools: BTreeMap<Cow<'static, str>, Arc<dyn HostTool>>,
    pub(super) bindings: BTreeMap<InternalBindingKey, Arc<dyn HostTool>>,
}

/// Identity of one internal, non-listed handler or extractor binding.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum InternalBindingKey {
    Builtin(String),
    Exec {
        executable: String,
        argv: Vec<String>,
    },
}

impl InternalBindingKey {
    pub(super) fn from_compiled(binding: CompiledHandlerBinding) -> Result<Self, HostToolError> {
        match binding {
            CompiledHandlerBinding::Builtin { id } if !id.is_empty() => {
                Ok(Self::Builtin(id.to_owned()))
            }
            CompiledHandlerBinding::Exec { executable, argv } => Ok(Self::Exec {
                executable: executable.to_owned(),
                argv: argv.iter().map(|value| (*value).to_owned()).collect(),
            }),
            CompiledHandlerBinding::Builtin { .. } => Err(HostToolError::Catalog {
                detail: "builtin id must not be empty".to_owned(),
            }),
        }
    }
}

impl HostToolRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Validates the atlas scope before registration and rejects an unexpected tool set.
    pub fn model_visible(config: ModelVisibleToolConfig) -> Result<Self, HostToolError> {
        let ModelVisibleToolConfig {
            ledger,
            atlas,
            allowed_atlas_scope,
            artifact_root,
        } = config;
        let atlas_query =
            AtlasQueryTool::new(atlas, allowed_atlas_scope).map_err(HostToolError::Atlas)?;

        let mut registry = Self::new();
        for tool in [
            Arc::new(ApprovalRequestTool::new(Arc::clone(&ledger))) as Arc<dyn HostTool>,
            Arc::new(ArtifactReadTool::new(Arc::clone(&ledger), artifact_root))
                as Arc<dyn HostTool>,
            Arc::new(atlas_query) as Arc<dyn HostTool>,
            Arc::new(LaneStatusTool::new(Arc::clone(&ledger))) as Arc<dyn HostTool>,
            Arc::new(PlanSetTool::new(Arc::clone(&ledger))) as Arc<dyn HostTool>,
            Arc::new(TodoUpdateTool::new(Arc::clone(&ledger))) as Arc<dyn HostTool>,
        ] {
            let evidence_id = format!("{}_evidence", tool.definition().name);
            registry.register(tool)?;
            if evidence_id != LaneStatusEvidenceTool::ID {
                registry.register_internal(
                    InternalBindingKey::Builtin(evidence_id.clone()),
                    Arc::new(DeclaredOutputEvidence::new(evidence_id)),
                )?;
            }
        }
        registry.register_internal(
            InternalBindingKey::Builtin(LaneStatusEvidenceTool::ID.to_owned()),
            Arc::new(LaneStatusEvidenceTool::new()),
        )?;

        let assembled: Vec<&str> = registry.tools.keys().map(|name| name.as_ref()).collect();
        assert_eq!(
            assembled, MODEL_VISIBLE_TOOL_NAMES,
            "assembly must hold exactly the six model-visible tools",
        );
        Ok(registry)
    }

    /// Dispatches only the handler or extractor named by the executor's permit.
    pub(crate) fn dispatch_internal(
        &self,
        permit: &PreparedEffect,
        consumed: &ConsumedHostCommand,
        key: &InternalBindingKey,
        invocation: HostInvocation,
        execution: Option<&crate::uri::ExecutionBinding>,
    ) -> Result<Value, HostToolError> {
        let handler = executor::internal_key_of(&permit.contract().handler);
        let extractor = executor::internal_key_of(&permit.contract().evidence_extractor);
        if key != &handler && key != &extractor {
            return Err(HostToolError::Catalog {
                detail: format!(
                    "prepared operation {} does not bind internal key {key:?}",
                    permit.operation_id()
                ),
            });
        }
        self.binding(key)?
            .invoke_execution(permit, consumed, invocation, execution)
    }

    pub fn register_framed_exec(
        &mut self,
        executable: String,
        argv: Vec<String>,
        worker: crate::process::OmpWorkerLaunch,
    ) -> Result<(), HostToolError> {
        self.register_internal(
            InternalBindingKey::Exec {
                executable: executable.clone(),
                argv: argv.clone(),
            },
            Arc::new(FramedExecTool::new(executable, argv, worker)),
        )
    }

    /// Listed browser routes still require operation dispatch and seat-scope authorization.
    pub fn register_browser_capabilities(
        &mut self,
        owner: Arc<dyn BrowserCapabilityOwner>,
    ) -> Result<(), HostToolError> {
        for binding in BrowserCapabilityBinding::ALL {
            let tool = Arc::new(BrowserCapabilityTool::new(binding, Arc::clone(&owner))?);
            self.register_internal(InternalBindingKey::Builtin(binding.id().to_owned()), tool)?;
        }
        for binding in [
            BrowserCapabilityBinding::Observe,
            BrowserCapabilityBinding::Interact,
            BrowserCapabilityBinding::Consequential,
        ] {
            let listed = Arc::new(BrowserListedTool::new(binding, Arc::clone(&owner))?);
            self.register(Arc::clone(&listed) as Arc<dyn HostTool>)?;
        }
        self.validate_registered_builtin_ids(
            &BrowserCapabilityBinding::ALL.map(BrowserCapabilityBinding::id),
        )
    }

    /// Kube routes require operation dispatch; the owner must be set before listener startup.
    pub fn register_kube_capabilities(
        &mut self,
        owner: Arc<dyn kube::KubeCapabilityOwner>,
    ) -> Result<(), HostToolError> {
        for binding in kube::KubeCapabilityBinding::ALL {
            let tool = Arc::new(kube::KubeCapabilityTool::new(binding, Arc::clone(&owner))?);
            self.register_internal(InternalBindingKey::Builtin(binding.id().to_owned()), tool)?;
        }
        for binding in kube::KubeCapabilityBinding::ALL {
            if binding.is_evidence_extractor() {
                continue;
            }
            let inner = Arc::new(kube::KubeCapabilityTool::new(binding, Arc::clone(&owner))?);
            let mut definition = inner.definition().clone();
            definition.name = Cow::Borrowed(binding.listed_name());
            definition.hidden = false;
            if binding == kube::KubeCapabilityBinding::WorkloadCreate {
                kube::annotate_launchable_profiles(&mut definition, &owner.launchable_profiles());
            }
            let listed = Arc::new(kube::KubeListedTool { inner, definition });
            self.register(Arc::clone(&listed) as Arc<dyn HostTool>)?;
        }
        self.validate_registered_builtin_ids(
            &kube::KubeCapabilityBinding::ALL.map(kube::KubeCapabilityBinding::id),
        )
    }
    /// Capsule routes use operation dispatch, not direct access to the private sidecar.
    /// The host supplies `source_sha256`; the model schema omits it.
    pub fn register_capsule_listed_tools(
        &mut self,
        owner: Arc<dyn CanonicalV2CapabilityOwner>,
    ) -> Result<(), HostToolError> {
        for (binding, name, label) in [
            (
                CanonicalV2CapabilityBinding::EvalRun,
                "capsule_eval_run",
                "Capsule Eval",
            ),
            (
                CanonicalV2CapabilityBinding::FileEdit,
                "capsule_file_edit",
                "Capsule Edit",
            ),
        ] {
            let inner = Arc::new(CanonicalV2CapabilityTool::new(binding, Arc::clone(&owner))?);
            let mut definition = inner.definition().clone();
            definition.name = Cow::Borrowed(name);
            definition.label = Cow::Borrowed(label);
            definition.hidden = false;
            if binding == CanonicalV2CapabilityBinding::EvalRun {
                strip_model_source_sha256(&mut definition.parameters)?;
            }
            let listed = Arc::new(CapsuleListedTool { inner, definition });
            self.register(Arc::clone(&listed) as Arc<dyn HostTool>)?;
        }
        Ok(())
    }

    pub fn register_canonical_v2_capabilities(
        &mut self,
        owner: Arc<dyn CanonicalV2CapabilityOwner>,
    ) -> Result<(), HostToolError> {
        for binding in CanonicalV2CapabilityBinding::ALL {
            let tool = Arc::new(CanonicalV2CapabilityTool::new(binding, Arc::clone(&owner))?);
            self.register_internal(InternalBindingKey::Builtin(binding.id().to_owned()), tool)?;
        }
        self.register_capsule_listed_tools(Arc::clone(&owner))?;
        self.validate_registered_builtin_ids(
            &CanonicalV2CapabilityBinding::ALL.map(CanonicalV2CapabilityBinding::id),
        )
    }

    /// Fixes the context root before model calls; enabled but absent readers fail composition.
    pub fn register_context_read(
        &mut self,
        root: &std::path::Path,
        max_bytes: u64,
    ) -> Result<(), HostToolError> {
        let tool = Arc::new(ContextReadTool::new(root, max_bytes)?);
        self.register(Arc::clone(&tool) as Arc<dyn HostTool>)?;
        self.register_internal(
            InternalBindingKey::Builtin(CONTEXT_READ_HANDLER_ID.to_owned()),
            tool as Arc<dyn HostTool>,
        )?;
        self.register_internal(
            InternalBindingKey::Builtin(CONTEXT_READ_EVIDENCE_ID.to_owned()),
            Arc::new(ContextReadEvidenceTool::new()),
        )?;
        self.validate_registered_builtin_ids(&[CONTEXT_READ_HANDLER_ID, CONTEXT_READ_EVIDENCE_ID])
    }

    fn validate_registered_builtin_ids(&self, ids: &[&str]) -> Result<(), HostToolError> {
        for id in ids {
            let admitted = PRE_ADMITTED_BINDINGS.iter().any(|binding| {
                [binding.handler, binding.evidence_extractor]
                    .into_iter()
                    .any(|candidate| {
                        matches!(
                            candidate,
                            CompiledHandlerBinding::Builtin { id: compiled } if compiled == *id
                        )
                    })
            });
            if !admitted {
                return Err(HostToolError::Catalog {
                    detail: format!("registered builtin {id:?} is not globally pre-admitted"),
                });
            }
            if !self
                .bindings
                .contains_key(&InternalBindingKey::Builtin((*id).to_owned()))
            {
                return Err(HostToolError::Catalog {
                    detail: format!("pre-admitted builtin {id:?} has no concrete owner"),
                });
            }
        }
        Ok(())
    }
    /// Task calls fail when no owner is configured; registration checks catalog admission.
    pub fn register_task_capabilities(
        &mut self,
        owner: Arc<delegation::TaskOwnerSlot>,
    ) -> Result<(), HostToolError> {
        let create = Arc::new(delegation::TaskCreateTool::new(Arc::clone(&owner))?);
        let read = Arc::new(delegation::TaskReadTool::new(Arc::clone(&owner))?);
        self.register(Arc::clone(&create) as Arc<dyn HostTool>)?;
        self.register(Arc::clone(&read) as Arc<dyn HostTool>)?;
        self.register_internal(
            InternalBindingKey::Builtin(delegation::TASK_CREATE_HANDLER_ID.to_owned()),
            create,
        )?;
        self.register_internal(
            InternalBindingKey::Builtin(delegation::TASK_READ_HANDLER_ID.to_owned()),
            read,
        )?;
        self.register_internal(
            InternalBindingKey::Builtin(delegation::TASK_CREATE_EVIDENCE_ID.to_owned()),
            Arc::new(delegation::TaskCreateEvidenceTool),
        )?;
        self.register_internal(
            InternalBindingKey::Builtin(delegation::TASK_READ_EVIDENCE_ID.to_owned()),
            Arc::new(delegation::TaskReadEvidenceTool),
        )?;
        for (kind, handler, evidence) in [
            (
                delegation::TaskControlKind::Pause,
                delegation::TASK_PAUSE_HANDLER_ID,
                delegation::TASK_PAUSE_EVIDENCE_ID,
            ),
            (
                delegation::TaskControlKind::Steer,
                delegation::TASK_STEER_HANDLER_ID,
                delegation::TASK_STEER_EVIDENCE_ID,
            ),
        ] {
            let tool = Arc::new(delegation::TaskControlTool::new(Arc::clone(&owner), kind)?);
            self.register(Arc::clone(&tool) as Arc<dyn HostTool>)?;
            self.register_internal(InternalBindingKey::Builtin(handler.to_owned()), tool)?;
            self.register_internal(
                InternalBindingKey::Builtin(evidence.to_owned()),
                Arc::new(delegation::TaskControlEvidenceTool::new(kind)),
            )?;
        }
        self.validate_registered_builtin_ids(&[
            delegation::TASK_CREATE_HANDLER_ID,
            delegation::TASK_CREATE_EVIDENCE_ID,
            delegation::TASK_READ_HANDLER_ID,
            delegation::TASK_READ_EVIDENCE_ID,
            delegation::TASK_PAUSE_HANDLER_ID,
            delegation::TASK_PAUSE_EVIDENCE_ID,
            delegation::TASK_STEER_HANDLER_ID,
            delegation::TASK_STEER_EVIDENCE_ID,
        ])
    }

    /// Registers an internal, non-listed handler/extractor HostTool.
    pub fn register_internal(
        &mut self,
        key: InternalBindingKey,
        tool: Arc<dyn HostTool>,
    ) -> Result<(), HostToolError> {
        if self.bindings.contains_key(&key) {
            return Err(HostToolError::DuplicateTool {
                name: match &key {
                    InternalBindingKey::Builtin(id) => id.clone(),
                    InternalBindingKey::Exec { executable, .. } => executable.clone(),
                },
            });
        }
        self.bindings.insert(key, tool);
        Ok(())
    }

    /// Registers a listed model-visible tool under its definition name.
    pub fn register(&mut self, tool: Arc<dyn HostTool>) -> Result<(), HostToolError> {
        let name = tool.definition().name.clone();
        if self.tools.contains_key(name.as_ref()) {
            return Err(HostToolError::DuplicateTool {
                name: name.as_ref().to_owned(),
            });
        }
        self.tools.insert(name, tool);
        Ok(())
    }

    /// Listed model-visible definitions only, lexicographic name order.
    pub fn definitions(&self) -> Vec<RpcHostToolDefinition> {
        self.tools
            .values()
            .map(|tool| tool.definition().clone())
            .collect()
    }

    /// Marks tools unavailable when this caller cannot supply their execution binding.
    pub fn definition(
        &self,
        name: &str,
        execution_proof_supported: bool,
    ) -> Option<RpcHostToolDefinition> {
        let tool = self.tools.get(name)?;
        let definition = tool.definition();
        let description = if !execution_proof_supported && tool.requires_execution_proof() {
            const NOTICE: &str = "Unavailable in this session: this tool requires a trusted \
                execution proof that the foreign-harness MCP bridge cannot supply. \
                Calls are refused before knowledge access.\n\n";
            let mut description =
                String::with_capacity(NOTICE.len() + definition.description.len());
            description.push_str(NOTICE);
            description.push_str(&definition.description);
            Cow::Owned(description)
        } else {
            definition.description.clone()
        };
        Some(RpcHostToolDefinition {
            name: definition.name.clone(),
            label: definition.label.clone(),
            description,
            parameters: definition.parameters.clone(),
            hidden: definition.hidden,
            load_mode: definition.load_mode,
        })
    }

    /// Listed tool names in the same lexicographic order as [`Self::definitions`].
    pub fn listed_names(&self) -> impl Iterator<Item = &str> {
        self.tools.keys().map(|name| name.as_ref())
    }

    /// Direct invocation for tests only; production calls require operation authorization.
    #[cfg(test)]
    pub(crate) fn dispatch(
        &self,
        name: &str,
        invocation: HostInvocation,
    ) -> Result<Value, HostToolError> {
        let tool = self
            .tools
            .get(name)
            .ok_or_else(|| HostToolError::UnknownTool {
                name: name.to_owned(),
            })?;
        tool.invoke(invocation)
    }

    pub(super) fn binding(
        &self,
        key: &InternalBindingKey,
    ) -> Result<Arc<dyn HostTool>, HostToolError> {
        if let Some(tool) = self.bindings.get(key) {
            return Ok(Arc::clone(tool));
        }
        match key {
            // A cataloged builtin handler may be served by the listed tool
            // registered under its exact id (the executor reaches the
            // model-visible tools this way after authorization); exec
            // identities are internal only.
            InternalBindingKey::Builtin(id) => self
                .tools
                .get(id.as_str())
                .cloned()
                .ok_or_else(|| HostToolError::UnknownTool { name: id.clone() }),
            InternalBindingKey::Exec { executable, .. } => Err(HostToolError::UnknownTool {
                name: executable.clone(),
            }),
        }
    }

    /// Uses the execution handler for read-only prerequisite checks.
    pub(crate) fn preflight_internal(
        &self,
        key: &InternalBindingKey,
        contract: &odin_kernel::CapabilityContract,
        scope: &Scope,
        arguments: &Value,
    ) -> Result<(), HostToolError> {
        self.binding(key)?.preflight(contract, scope, arguments)
    }

    pub fn resolves_admitted(&self, binding: &HandlerBindingToml) -> bool {
        match binding {
            HandlerBindingToml::Builtin(builtin) => {
                self.tools.contains_key(builtin.id.as_str())
                    || self
                        .bindings
                        .contains_key(&InternalBindingKey::Builtin(builtin.id.clone()))
            }
            HandlerBindingToml::Exec(exec) => {
                self.bindings.contains_key(&InternalBindingKey::Exec {
                    executable: exec.executable.clone(),
                    argv: exec.argv.clone(),
                })
            }
        }
    }
    /// Whether one internal binding identity resolves against this concrete
    /// registry: builtin ids resolve through an internal binding or a listed
    /// tool of the exact name; exec identities resolve only through an
    /// internal binding with the exact executable and argv.
    pub(crate) fn resolves_key(&self, key: &InternalBindingKey) -> bool {
        match key {
            InternalBindingKey::Builtin(id) => {
                self.bindings.contains_key(key) || self.tools.contains_key(id.as_str())
            }
            InternalBindingKey::Exec { .. } => self.bindings.contains_key(key),
        }
    }
}

/// The host computes `source_sha256` at dispatch, so only the model schema omits it.
fn strip_model_source_sha256(parameters: &mut Value) -> Result<(), HostToolError> {
    let object = parameters
        .as_object_mut()
        .ok_or_else(|| HostToolError::Catalog {
            detail: "capsule.eval.run input schema is not an object".to_owned(),
        })?;
    let properties = object
        .get_mut("properties")
        .and_then(Value::as_object_mut)
        .ok_or_else(|| HostToolError::Catalog {
            detail: "capsule.eval.run input schema has no properties object".to_owned(),
        })?;
    if properties.remove("source_sha256").is_none() {
        return Err(HostToolError::Catalog {
            detail: "capsule.eval.run input schema does not declare source_sha256".to_owned(),
        });
    }
    let required = object
        .get_mut("required")
        .and_then(Value::as_array_mut)
        .ok_or_else(|| HostToolError::Catalog {
            detail: "capsule.eval.run input schema has no required array".to_owned(),
        })?;
    required.retain(|entry| entry.as_str() != Some("source_sha256"));
    Ok(())
}

struct DeclaredOutputEvidence {
    definition: RpcHostToolDefinition,
}

impl DeclaredOutputEvidence {
    fn new(id: String) -> Self {
        Self {
            definition: RpcHostToolDefinition {
                name: Cow::Owned(id),
                label: Cow::Borrowed("Declared output evidence"),
                description: Cow::Borrowed("Projects the handler output as evidence."),
                parameters: serde_json::json!({
                    "type": "object",
                    "additionalProperties": false,
                    "properties": {
                        "output": { "type": "object" }
                    },
                    "required": ["output"]
                }),
                hidden: true,
                load_mode: super::ToolLoadMode::Essential,
            },
        }
    }
}

impl HostTool for DeclaredOutputEvidence {
    fn definition(&self) -> &RpcHostToolDefinition {
        &self.definition
    }

    fn preflight(
        &self,
        _contract: &odin_kernel::CapabilityContract,
        _scope: &odin_domain::Scope,
        _arguments: &Value,
    ) -> Result<(), HostToolError> {
        Ok(())
    }

    fn invoke(&self, invocation: HostInvocation) -> Result<Value, HostToolError> {
        let name = self.definition.name.as_ref();
        invocation
            .arguments
            .get("output")
            .cloned()
            .ok_or_else(|| HostToolError::Arguments {
                tool: "declared_output_evidence",
                detail: format!("{name} evidence has no output"),
            })
    }
}
