//! Shared dispatch fixture using signed token files, the declared catalog, and the production executor.

use std::borrow::Cow;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::Write;
use std::num::{NonZeroU16, NonZeroU32, NonZeroU64};
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::OnceLock;
use std::sync::{Arc, Mutex};

use odin_atlas::{Atlas, AtlasCounts, AtlasScope, ATLAS_SCHEMA, ATLAS_VERSION};
use odin_brain::config::EffectiveBrainPolicy;
use odin_brain::error::BrainResult;
use odin_brain::retrieval::{LaneEmbeddingProvider, QueryEmbedder};
use odin_brain::service::{BrainService, BrainServiceConfig, BrainSourceConfig};
use odin_domain::huginn::ids::ModelName;
use odin_domain::knowledge::ids::{EmbeddingModelId, TokenizerId};
use odin_domain::knowledge::retrieval::ModelDescriptor;
use odin_domain::knowledge::{AtlasId, EmbeddingBackend, RetrievalMode};
use odin_ledger::live::NewLiveSession;
use odin_registry::schema::{
    AccountingWindowToml, ApprovalDefaultToml, ApprovalDefaultsToml, BudgetPolicyToml, ProjectToml,
    RegistryKind, SeatContextToml, SeatKnowledgeToml, SeatLimitsToml, SeatToml,
    SeatToolRedirectsToml, SeatToolsToml, SliceContextToml, SliceKnowledgeToml, SliceRedirectsToml,
    SliceToml, SliceToolRedirectsToml, SliceToolsToml, REGISTRY_SCHEMA,
};

use odin_domain::knowledge::{ResourceConstraint, ToolName, ToolSchema};
use odin_domain::operation::Limits;
use odin_domain::{
    CapabilityId, Digest, EffectClass, LaneId, ProjectId, RunId, Scope, SeatId, SeatTokenId,
    SessionId, SliceId,
};
use odin_kernel::{
    ApprovalRequirement, CapabilityContract, HandlerBinding, IdempotencyPolicy, MintRequest,
    PreparedEffect, RetryPolicy, SchemaCatalog, TokenIssuer,
};
use odin_ledger::operation as operation_store;
use odin_ledger::Ledger;
use serde_json::{json, Value};
use time::OffsetDateTime;

use crate::bridge::BridgeBinding;
use crate::host_tools::brain::{BrainToolsSlot, READ_EVIDENCE, SEARCH_EVIDENCE};
use crate::host_tools::executor::HostToolExecutor;
use crate::host_tools::operations::LiveSessionBindings;
use crate::host_tools::operations::{
    admission_digest, correlation_for, generate_signing_key, seat_operation_policy,
    session_capsule_id, DeclaredOperationCatalog, HostAdapterStatus, HostToolOperationError,
    HostToolOperations, OperationStackInputs, ProvisionedFreshAuthorityProvider, RevisionMaterial,
    RevisionMaterialSource, SeatOperationPolicyInputs, SessionOperationBinding,
    SessionOperationContext, StaticSchemaCatalog, SupervisedAdapterStatus,
    UnsupervisedAdapterStatus,
};
use crate::host_tools::plan_set::PlanSetTool;
use crate::host_tools::{
    ConsumedHostCommand, HostInvocation, HostTool, HostToolError, HostToolRegistry,
    InternalBindingKey, RpcHostToolDefinition, ToolLoadMode,
};
use crate::live::runtime::brain_tools::RuntimeBrainTools;
use crate::uri::{ExecutionBinding, ScopedUriRouter};
use odin_domain::SeatToken;
pub(super) const NOW_MS: u64 = 10_000;
pub(super) const TOKEN_EXPIRES_MS: u64 = 100_000;
pub(super) const INPUT_SCHEMA: &str = "fixture.operation.input.json";
pub(super) const OUTPUT_SCHEMA: &str = "fixture.operation.output.json";
pub(super) const READ_CAPABILITY: &str = "fixture.read";
pub(super) const READ_TOOL: &str = "fixture_read";
pub(super) const READ_HANDLER: &str = "fixture.handler.read";
pub(super) const READ_EXTRACTOR: &str = "fixture.extract.read";
pub(super) const EXEC_CAPABILITY: &str = "fixture.execute";
pub(super) const EXEC_TOOL: &str = "fixture_execute";
pub(super) const EXEC_HANDLER: &str = "fixture.handler.execute";
pub(super) const EXEC_EXTRACTOR: &str = "fixture.extract.execute";
/// The R2-class fixture family: an externally visible, operator-recoverable
/// effect. The plain variant needs no approval row, so the preflight gate's
/// no-journal/no-effect contract is observable on its own; the operator
/// variant declares `ApprovalRequirement::Operator` and must gate exactly
/// like R3.
pub(super) const DRAFT_CAPABILITY: &str = "fixture.draft";
pub(super) const DRAFT_TOOL: &str = "fixture_draft";
pub(super) const DRAFT_HANDLER: &str = "fixture.handler.draft";
pub(super) const DRAFT_EXTRACTOR: &str = "fixture.extract.draft";
pub(super) const SEARCH_ADAPTER: &str = "adapter-status-fixture";
pub(super) const SEARCH_CAPABILITY: &str = "fixture.web_search";
pub(super) const SEARCH_TOOL: &str = "fixture_web_search";
pub(super) const EVAL_CAPABILITY: &str = "capsule.eval.run";
pub(super) const EVAL_TOOL: &str = "capsule_eval_run";
pub(super) const EVAL_HANDLER: &str = "fixture.handler.eval";
pub(super) const EVAL_EXTRACTOR: &str = "fixture.extract.eval";
pub(super) const EVAL_INPUT_SCHEMA: &str = "fixture.capsule.eval.run.input.json";
pub(super) const FILE_EDIT_TOOL: &str = "capsule_file_edit";
pub(super) const FILE_EDIT_HANDLER: &str = "fixture.handler.file_edit";
pub(super) const FILE_EDIT_EXTRACTOR: &str = "fixture.extract.file_edit";
const FILE_EDIT_INPUT_SCHEMA: &str = "schemas/capability/capsule.file.edit.input.json";
pub(super) const SEAT_ASK_CAPABILITY: &str = "seat.ask.kubert";
pub(super) const SEAT_ASK_TOOL: &str = "seat_ask_kubert";
pub(super) const SEAT_ASK_HANDLER: &str = "fixture.handler.seat_ask";
pub(super) const SEAT_ASK_EXTRACTOR: &str = "fixture.extract.seat_ask";
/// The real registry contract reference, so the fixture validates against
/// the exact generic `seat.ask` schema file the operation authority loads
/// in production. The per-seat capability id stays declaration data.
pub(super) const SEAT_ASK_INPUT_SCHEMA: &str = "schemas/capability/seat.ask.input.json";

/// The governed knowledge surface: the real canonical contracts and the
/// real tool/handler identities the production brain tools register, so
/// the fixture dispatches through `crate::host_tools::brain::register`.
pub(super) const BRAIN_SEARCH_CAPABILITY: &str = "brain.search";
pub(super) const BRAIN_READ_CAPABILITY: &str = "brain.read";
pub(super) const BRAIN_SEARCH_TOOL: &str = "brain_search";
pub(super) const BRAIN_READ_TOOL: &str = "brain_read";
const BRAIN_SEARCH_INPUT_SCHEMA: &str = "fixture.brain.search.input.json";
const BRAIN_READ_INPUT_SCHEMA: &str = "fixture.brain.read.input.json";
/// The atlas source identity the fixture brain composes and the session
/// may search — declared in slice, seat, and project, wired as a real
/// source root, and the only source the policy serves.
pub(super) const BRAIN_ATLAS_SOURCE: &str = "atlas:fixture-brain";
const BRAIN_PROJECT: &str = "project.fixture";
/// The declared bound projects of the fixture Kubert seat — the same
/// deployment fact production Hermes renders into the listed `project`
/// enum from the daemon's configured lane bindings. Tests that declare a
/// different set change admission purely by declaration; no Rust branch
/// names a project.
pub(super) const SEAT_ASK_BOUND_PROJECTS: &[&str] = &["odin"];

pub(super) const BROWSER_CONSEQUENTIAL_CAPABILITY: &str = "browser.consequential";
pub(super) const WORKLOAD_PUBLISH_CAPABILITY: &str = "workload.publish";
pub(super) const WORKLOAD_PUBLISH_TOOL: &str = "workload_publish";
pub(super) const WORKLOAD_PUBLISH_HANDLER: &str = "fixture.handler.workload_publish";
pub(super) const WORKLOAD_PUBLISH_EXTRACTOR: &str = "fixture.extractor.workload_publish";
pub(super) const WORKLOAD_PUBLISH_INPUT_SCHEMA: &str =
    "schemas/capability/workload.publish.input.json";
pub(super) const BROWSER_CONSEQUENTIAL_TOOL: &str = "browser_consequential";
pub(super) const BROWSER_CONSEQUENTIAL_HANDLER: &str = "fixture.handler.browser_consequential";
pub(super) const BROWSER_CONSEQUENTIAL_EXTRACTOR: &str = "fixture.extract.browser_consequential";
/// The real registry contract reference, so the fixture validates against
/// the exact canonical pairing schema the operation authority loads in
/// production.
pub(super) const BROWSER_CONSEQUENTIAL_INPUT_SCHEMA: &str =
    "schemas/capability/browser.consequential.input.json";
pub(super) const UNBOUND_MODEL_TOOL: &str = "odin_plan_set";
pub(super) const PLAN_CAPABILITY: &str = "odin.plan_set";
pub(super) const PLAN_TOOL: &str = "odin_plan_set";
pub(super) const PLAN_HANDLER: &str = "odin_plan_set";
pub(super) const PLAN_EXTRACTOR: &str = "odin_plan_set_evidence";
pub(super) const PLAN_INPUT_SCHEMA: &str = "schemas/capability/odin.plan_set.input.json";
pub(super) const SIDE_EFFECT_CAPABILITY: &str = "fixture.side_effect";
pub(super) const SIDE_EFFECT_TOOL: &str = "fixture_side_effect";
pub(super) const SIDE_EFFECT_HANDLER: &str = "fixture.handler.side_effect";
pub(super) const SIDE_EFFECT_EXTRACTOR: &str = "fixture.extract.side_effect";
/// A binding digest in the `blake3:<64 hex>` grammar.
pub(super) const ADMITTED_IDENTITY: &str =
    "blake3:00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";

static NEXT_ROOT: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Copy)]
enum FixtureRole {
    Handler,
    Extractor,
    Eval,
    /// A confined create-only fixture effect, not the compiled capsule effector.
    FileCreate,
    /// A listed model surface that never serves a bare invocation: the
    /// bridge routes capability-bound calls through the operation
    /// authority, exactly like the production listed wrappers.
    Listed,
    /// Reports the retained digest and publication revision without committing registry files.
    WorkloadPublish,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum FixtureKind {
    ReadExec,
    /// Only the canonical capsule.eval.run route on its real tool name.
    EvalRun,
    /// Canonical file-edit schema with a confined fixture create handler.
    FileEdit,
    /// One R0 capability bound to an adapter whose health is decided by
    /// the live status source injected at assembly.
    AdapterSearch,
    /// The real `seat.ask.kubert` cross-seat contract pinned to the real
    /// generic `seat.ask` registry input schema file, on a fixture handler
    /// pair.
    SeatAsk,
    /// The real `browser.consequential` contract pinned to the real canonical
    /// pairing schema file, on a fixture handler pair.
    BrowserConsequential,
    /// The real `workload.publish` contract pinned to the real canonical input
    /// schema file, on a fixture handler pair, with the retained-draft store
    /// wired into the operation stack.
    WorkloadPublish,
    /// One R2-class contract on the generic fixture schema: no approval
    /// lifecycle, so a preflight refusal's no-journal/no-effect outcome
    /// stands alone.
    DraftR2,
    /// The same R2-class contract declaring operator approval: the
    /// capability-aware gate must treat it exactly like R3, mint on first
    /// refusal, and consume the exact approval once.
    DraftR2Operator,
    /// The real governed knowledge surface: `brain.search` and `brain.read`
    /// contracts on the production tool/handler identities, with the real
    /// `RuntimeBrainTools` backend bound into the brain tool slot over a
    /// real brain service, scoped router, and live seeded session.
    Brain,
    /// Production `odin_plan_set` plus one ordinary R1 side effect. Plan
    /// management must write with no accepted plan; the side effect must not.
    PlanWriter,
}

pub(super) struct BrainEmbedding {
    pub(super) mode: RetrievalMode,
    pub(super) embedder: Arc<QueryEmbedder>,
}

/// The lane seam runtime composition wires, over one fixed query embedder.
struct FixtureLaneEmbedding(Arc<QueryEmbedder>);

impl LaneEmbeddingProvider for FixtureLaneEmbedding {
    fn bind_lane(self: Arc<Self>, _lane: &LaneId) -> BrainResult<Arc<QueryEmbedder>> {
        Ok(Arc::clone(&self.0))
    }
}

#[derive(Default)]
pub(super) struct FixtureWorld {
    pub(super) calls: Mutex<Vec<&'static str>>,
    pub(super) effects: AtomicU64,
    file_root: Option<odin_confined_fs::PrivateCapability>,
    /// Proof strings the production executor delivered to each bound call
    /// through [`HostTool::invoke_consumed`].
    pub(super) proofs: Mutex<Vec<String>>,
    /// Binding names whose declared-admissibility preflight refuses typed,
    /// simulating a deterministic execution prerequisite (a missing owner,
    /// executable, or declared binding) the handler's executed path would
    /// also refuse. Tests flip a name in and out between a refused
    /// dispatch and its ready retry; arguments stay identical, so the only
    /// variable is the gate.
    pub(super) preflight_refusals: Mutex<std::collections::BTreeSet<&'static str>>,
    /// The shared fixture clock the operation stack's `Clock` seam reads.
    /// Tests schedule an advance that the declared preflight applies, so
    /// wall time passing WHILE a blocking readiness preflight runs is
    /// observable at the re-verification boundary.
    pub(super) clock_ms: AtomicU64,
    /// Milliseconds the next declared preflight adds to the shared clock —
    /// simulating the blocking readiness window. One-shot: the preflight
    /// swaps it out before applying.
    preflight_advance_ms: AtomicU64,
    /// One-shot hooks the next declared preflight runs inside the
    /// readiness window — simulating durable state that changes while the
    /// preflight blocks (a plan replacement, an operator decision). Runs
    /// after the refusal check, so the declared gate itself stays
    /// admitted and the only variable is the re-verified observation.
    preflight_hooks: Mutex<Vec<Box<dyn FnOnce() + Send>>>,
}

impl FixtureWorld {
    pub(super) fn calls(&self) -> Vec<&'static str> {
        self.calls.lock().expect("fixture call lock").clone()
    }

    pub(super) fn refuse_preflight(&self, name: &'static str) {
        self.preflight_refusals
            .lock()
            .expect("fixture preflight lock")
            .insert(name);
    }

    pub(super) fn allow_preflight(&self, name: &'static str) {
        self.preflight_refusals
            .lock()
            .expect("fixture preflight lock")
            .remove(name);
    }

    /// Schedules a one-shot clock advance the next declared preflight
    /// applies before returning: the authority admitted before the
    /// readiness window is observed again at the advanced instant.
    pub(super) fn schedule_preflight_clock_advance(&self, milliseconds: u64) {
        self.preflight_advance_ms
            .store(milliseconds, Ordering::SeqCst);
    }

    /// Schedules a one-shot hook the next declared preflight runs inside
    /// the readiness window, after the gate's own refusal check.
    pub(super) fn schedule_preflight_hook(&self, hook: impl FnOnce() + Send + 'static) {
        self.preflight_hooks
            .lock()
            .expect("fixture preflight hook lock")
            .push(Box::new(hook));
    }

    /// Applies the scheduled clock advance; the declared gate itself stays
    /// admitted. Called by the fixture tools' preflight.
    pub(super) fn apply_preflight_clock_advance(&self) {
        let advance = self.preflight_advance_ms.swap(0, Ordering::SeqCst);
        if advance > 0 {
            self.clock_ms.fetch_add(advance, Ordering::SeqCst);
        }
    }

    pub(super) fn run_preflight_hooks(&self) {
        let hooks = std::mem::take(
            &mut *self
                .preflight_hooks
                .lock()
                .expect("fixture preflight hook lock"),
        );
        for hook in hooks {
            hook();
        }
    }
}

struct FixtureTool {
    role: FixtureRole,
    world: Arc<FixtureWorld>,
    /// The fixture's static binding name, kept beside the definition so
    /// error labels and call records stay allocation-free.
    name: &'static str,
    definition: RpcHostToolDefinition,
}

impl FixtureTool {
    fn new(name: &'static str, role: FixtureRole, world: Arc<FixtureWorld>) -> Self {
        Self::with_model_surface(
            name,
            role,
            world,
            json!({
                "type": "object",
                "additionalProperties": false
            }),
        )
    }

    /// A fixture whose listed model surface is supplied verbatim — the
    /// exact projection production registers for the route and the sole
    /// data the operation surface compiles its pre-gate argument
    /// narrowing from.
    fn with_model_surface(
        name: &'static str,
        role: FixtureRole,
        world: Arc<FixtureWorld>,
        parameters: Value,
    ) -> Self {
        Self {
            role,
            world,
            name,
            definition: RpcHostToolDefinition {
                name: Cow::Borrowed(name),
                label: Cow::Borrowed("Authority Fixture"),
                description: Cow::Borrowed("Permit-gated operation authority fixture"),
                parameters,
                hidden: true,
                load_mode: ToolLoadMode::Essential,
            },
        }
    }
}

impl HostTool for FixtureTool {
    fn definition(&self) -> &RpcHostToolDefinition {
        &self.definition
    }

    fn preflight(
        &self,
        _contract: &odin_kernel::CapabilityContract,
        _scope: &Scope,
        _arguments: &Value,
    ) -> Result<(), HostToolError> {
        // The declared-admissibility gate the shared dispatch path runs
        // BEFORE anything is journaled, minted, requested, or consumed. A
        // name the test world marked refused simulates a deterministic
        // execution prerequisite with the typed `Unavailable` class — the
        // refusal a missing owner, executable, or declared binding
        // produces — so the dispatch contract around the gate is exercised
        // end to end against observable ledger outcomes.
        if self
            .world
            .preflight_refusals
            .lock()
            .expect("fixture preflight lock")
            .contains(self.name)
        {
            return Err(HostToolError::Unavailable {
                tool: self.name,
                reason: "fixture declared gate: the execution prerequisite is missing".to_owned(),
            });
        }
        // A scheduled advance simulates the blocking readiness window: the
        // gate stays admitted, but the clock moves and scheduled durable
        // changes land before the dispatch path re-verifies its
        // observations.
        self.world.apply_preflight_clock_advance();
        self.world.run_preflight_hooks();
        Ok(())
    }

    fn invoke(&self, invocation: HostInvocation) -> Result<Value, HostToolError> {
        // A listed route fails closed on bare invocation — the bridge
        // routes capability-bound calls through the operation authority —
        // and records nothing, exactly like the production wrappers.
        if matches!(self.role, FixtureRole::Listed) {
            return Err(HostToolError::Arguments {
                tool: self.name,
                detail: "the listed route must dispatch through the operation authority".to_owned(),
            });
        }
        self.world
            .calls
            .lock()
            .expect("fixture call lock")
            .push(self.name);
        match self.role {
            FixtureRole::Handler => {
                let mode = invocation
                    .arguments
                    .get("mode")
                    .and_then(Value::as_str)
                    .unwrap_or("success");
                if mode == "reject" {
                    return Err(HostToolError::Arguments {
                        tool: self.name,
                        detail: "fixture rejected before mutation".to_owned(),
                    });
                }
                let value = invocation
                    .arguments
                    .get("value")
                    .and_then(Value::as_str)
                    .ok_or_else(|| HostToolError::Arguments {
                        tool: self.name,
                        detail: "fixture value is missing".to_owned(),
                    })?;
                self.world.effects.fetch_add(1, Ordering::SeqCst);
                Ok(json!({
                    "extractorFailure": mode == "extractor_failure",
                    "handledBy": self.name,
                    "scope": invocation.scope,
                    "value": value,
                }))
            }
            FixtureRole::WorkloadPublish => {
                let digest = invocation
                    .arguments
                    .get("declarationDigest")
                    .and_then(Value::as_str)
                    .ok_or_else(|| HostToolError::Arguments {
                        tool: self.name,
                        detail: "declarationDigest is required".to_owned(),
                    })?;
                let revision = invocation
                    .arguments
                    .get("expectedRegistryRevision")
                    .and_then(Value::as_u64)
                    .ok_or_else(|| HostToolError::Arguments {
                        tool: self.name,
                        detail: "expectedRegistryRevision is required".to_owned(),
                    })?;
                self.world.effects.fetch_add(1, Ordering::SeqCst);
                Ok(json!({
                    "handledBy": self.name,
                    "declarationDigest": digest,
                    "publishedRevision": revision,
                }))
            }
            FixtureRole::FileCreate => {
                let arguments = &invocation.arguments;
                if arguments.get("preimage_sha256") != Some(&Value::Null) {
                    return Err(HostToolError::Arguments {
                        tool: self.name,
                        detail: "fixture create requires an explicit null preimage".to_owned(),
                    });
                }
                let path = arguments
                    .get("path")
                    .and_then(Value::as_str)
                    .expect("canonical schema requires path");
                let content = arguments
                    .get("content")
                    .and_then(Value::as_str)
                    .expect("fixture uses content mode");
                let mut file = self
                    .world
                    .file_root
                    .as_ref()
                    .expect("sealed fixture root")
                    .create_exclusive(Path::new(path), 0o600)
                    .expect("confined fixture create");
                file.write_all(content.as_bytes())
                    .expect("write exact fixture bytes");
                self.world.effects.fetch_add(1, Ordering::SeqCst);
                Ok(json!({
                    "handledBy": self.name,
                    "arguments": invocation.arguments,
                }))
            }
            FixtureRole::Eval => {
                self.world.effects.fetch_add(1, Ordering::SeqCst);
                Ok(json!({
                    "extractorFailure": false,
                    "handledBy": self.name,
                    "arguments": invocation.arguments,
                }))
            }
            FixtureRole::Extractor => {
                let output = invocation.arguments.get("output").cloned().ok_or_else(|| {
                    HostToolError::Arguments {
                        tool: self.name,
                        detail: "fixture extractor input is missing".to_owned(),
                    }
                })?;
                if output
                    .get("extractorFailure")
                    .and_then(Value::as_bool)
                    .unwrap_or(false)
                {
                    return Err(HostToolError::Arguments {
                        tool: self.name,
                        detail: "fixture extractor failed after the handler effect".to_owned(),
                    });
                }
                Ok(json!({
                    "extractedBy": self.name,
                    "output": output,
                }))
            }
            // Unreachable through `invoke` — the guard above refuses a
            // listed route before anything is recorded — but the match
            // must stay exhaustive.
            FixtureRole::Listed => Err(HostToolError::Arguments {
                tool: self.name,
                detail: "the listed route must dispatch through the operation authority".to_owned(),
            }),
        }
    }

    /// Records the proof the production executor delivers with every bound
    /// call: the exact consumed host command, capability, version, target,
    /// and full arguments, then runs the ordinary fixture behavior.
    fn invoke_consumed(
        &self,
        _effect: &PreparedEffect,
        consumed: &ConsumedHostCommand,
        invocation: HostInvocation,
    ) -> Result<Value, HostToolError> {
        self.world
            .proofs
            .lock()
            .expect("fixture proof lock")
            .push(format!(
                "{}|{}|{}|{}|{}|{}",
                consumed.command_id(),
                consumed.capability_id(),
                consumed.capability_version(),
                consumed.target().kind,
                consumed.target().id,
                consumed.arguments(),
            ));
        self.invoke(invocation)
    }
}

/// Mirrors Hermes's seat-ask projection so project admission comes from the declared enum.
fn seat_ask_model_parameters(bound_projects: &[&str]) -> Value {
    json!({
        "type": "object",
        "properties": {
            "approvalId": {
                "type": "string",
                "minLength": 1,
                "maxLength": 128
            },
            "project": {
                "type": "string",
                "enum": bound_projects
            },
            "subject": { "type": "string", "minLength": 1, "maxLength": 200 },
            "question": { "type": "string", "minLength": 1, "maxLength": 8192 },
            "options": {
                "type": "array",
                "maxItems": 8,
                "items": {
                    "type": "object",
                    "properties": {
                        "label": { "type": "string", "maxLength": 128 },
                        "action_ref": { "type": "string", "maxLength": 256 }
                    },
                    "required": ["label", "action_ref"],
                    "additionalProperties": false
                }
            },
            "urgency": { "type": "string", "enum": ["low", "medium", "high"] },
            "wait_seconds": {
                "type": "integer",
                "minimum": 0,
                "maximum": 600
            }
        },
        "required": ["project", "subject", "question", "urgency"],
        "additionalProperties": false
    })
}

/// The exact eval model projection production lists (mod.rs
/// `strip_model_source_sha256`): the canonical schema minus
/// `source_sha256` — the digest the trusted host derives from the exact
/// source bytes at dispatch while the canonical schema still requires it
/// on the authority wire.
fn eval_model_projection() -> Value {
    let mut parameters = serde_json::from_str::<Value>(include_str!(
        "../../../../../../schemas/capability/capsule.eval.run.input.json"
    ))
    .expect("real capsule.eval.run input schema");
    let object = parameters
        .as_object_mut()
        .expect("eval schema is an object");
    object
        .get_mut("properties")
        .and_then(Value::as_object_mut)
        .expect("eval schema has properties")
        .remove("source_sha256")
        .expect("eval schema declares source_sha256");
    object
        .get_mut("required")
        .and_then(Value::as_array_mut)
        .expect("eval schema has required")
        .retain(|entry| entry.as_str() != Some("source_sha256"));
    parameters
}

/// The exact browser model projection production lists (mod.rs
/// `strip_model_action_pairing`): the canonical pairing schema minus ONLY
/// the top-level `oneOf`, so a dead action/argument pair passes the
/// projected object shape and the canonical schema alone refuses it.
fn browser_model_projection() -> Value {
    let mut parameters = serde_json::from_str::<Value>(include_str!(
        "../../../../../../schemas/capability/browser.consequential.input.json"
    ))
    .expect("real browser.consequential input schema");
    parameters
        .as_object_mut()
        .expect("browser schema is an object")
        .remove("oneOf")
        .expect("browser schema carries the top-level action pairing");
    parameters
}

/// Mirrors Hermes's workload-publish projection; the canonical schema validates the complete request.
fn workload_publish_model_projection() -> Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "properties": {
            "profileId": {
                "type": "string",
                "minLength": 1,
                "maxLength": 128,
                "description": "The profile id the retained draft belongs to — the \
                                exact identity this publication installs."
            },
            "declarationDigest": {
                "type": "string",
                "minLength": 1,
                "maxLength": 80,
                "description": "The draft's blake3 declaration digest; the publication \
                                consumes the retained compiled declaration under exactly \
                                this digest."
            },
            "expectedRegistryRevision": {
                "type": "integer",
                "minimum": 1,
                "description": "Exact NEW registry revision this publication installs — \
                                the draft response's publishRevision, verbatim (base \
                                revision + 1), not the base."
            },
            "approvalId": { "type": "string", "minLength": 1, "maxLength": 128 }
        },
        "required": [
            "profileId",
            "declarationDigest",
            "expectedRegistryRevision",
            "approvalId"
        ]
    })
}

pub(super) struct Fixture {
    pub(super) root: PathBuf,
    pub(super) operations: HostToolOperations,
    pub(super) binding: SessionOperationBinding,
    pub(super) registry: Arc<HostToolRegistry>,
    pub(super) ledger: Arc<Mutex<Ledger>>,
    pub(super) contracts: BTreeMap<CapabilityId, CapabilityContract>,
    pub(super) schemas: Arc<dyn SchemaCatalog + Send + Sync>,
    pub(super) world: Arc<FixtureWorld>,
    pub(super) session: SessionId,
    pub(super) scope: Scope,
    pub(super) resource: ResourceConstraint,
    pub(super) token_id: SeatTokenId,
    /// The provisioning key the fixture's provider verifies with, so a test
    /// can mint further generation-bound tokens in the same trust world.
    pub(super) signing_key: Vec<u8>,
    pub(super) token_root: PathBuf,
    /// The fixture's retained-publication source (shared with the stack).
    pub(super) material_source: Arc<FixtureMaterialSource>,
    /// The brain tool slot the brain kind fills with the production
    /// backend; `None` for every other kind.
    pub(super) _brain_slot: Option<BrainToolsSlot>,
    /// The live execution proof of the seeded session; `None` for every
    /// non-brain kind.
    pub(super) execution: Option<ExecutionBinding>,
    _brain_sessions: Option<Arc<LiveSessionBindings>>,
    /// The journal file a durable fixture reopens; `None` for the in-memory
    /// ledger every other fixture uses.
    ledger_path: Option<PathBuf>,
    kind: FixtureKind,
    adapter_status: Arc<dyn HostAdapterStatus>,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

impl Fixture {
    pub(super) fn new() -> Self {
        Self::assemble(FixtureKind::ReadExec, None)
    }

    /// The read/execute world over a file-backed journal that
    /// [`Self::reopen_ledger`] can reopen like a restarted host.
    pub(super) fn durable() -> Self {
        Self::assemble_with_model_surfaces(
            FixtureKind::ReadExec,
            None,
            SEAT_ASK_BOUND_PROJECTS,
            true,
            None,
        )
    }

    pub(super) fn for_file_edit() -> Self {
        Self::assemble(FixtureKind::FileEdit, None)
    }

    pub(super) fn for_eval() -> Self {
        Self::assemble(FixtureKind::EvalRun, None)
    }

    pub(super) fn for_seat_ask() -> Self {
        Self::for_seat_ask_declaring(SEAT_ASK_BOUND_PROJECTS)
    }

    /// The listed project enum controls admission, as in Hermes's runtime projection.
    pub(super) fn for_seat_ask_declaring(bound_projects: &'static [&'static str]) -> Self {
        Self::assemble_with_model_surfaces(FixtureKind::SeatAsk, None, bound_projects, false, None)
    }

    pub(super) fn for_browser_consequential() -> Self {
        Self::assemble(FixtureKind::BrowserConsequential, None)
    }

    pub(super) fn for_draft_r2() -> Self {
        Self::assemble(FixtureKind::DraftR2, None)
    }

    pub(super) fn for_plan_writer() -> Self {
        Self::assemble(FixtureKind::PlanWriter, None)
    }

    pub(super) fn for_brain() -> Self {
        Self::assemble(FixtureKind::Brain, None)
    }

    pub(super) fn for_brain_embedding(embedding: BrainEmbedding) -> Self {
        Self::assemble_with_model_surfaces(
            FixtureKind::Brain,
            None,
            SEAT_ASK_BOUND_PROJECTS,
            false,
            Some(embedding),
        )
    }

    pub(super) fn for_draft_r2_operator() -> Self {
        Self::assemble(FixtureKind::DraftR2Operator, None)
    }

    pub(super) fn for_workload_publish() -> Self {
        Self::assemble(FixtureKind::WorkloadPublish, None)
    }

    /// A fixture whose single admitted capability is adapter-bound; the
    /// injected live status source decides its listing.
    pub(super) fn for_adapter_search(status: Arc<SupervisedAdapterStatus>) -> Self {
        Self::assemble(FixtureKind::AdapterSearch, Some(status))
    }

    /// Seeds the bridge-owned lane/run state for tests that intentionally
    /// advance a real plan gate. Missing and Draft tests opt in here
    /// instead of inheriting accepted state from fixture assembly.
    pub(super) fn seed_bridge_run(&self) {
        let run = self.scope.run.clone().expect("bound run");
        let lane = self.binding.policy.lane_id.clone();
        let created_at = OffsetDateTime::UNIX_EPOCH;
        let ledger = self.ledger.lock().expect("ledger lock");
        odin_ledger::lane_run::create_lane(
            ledger.connection(),
            &odin_ledger::lane_run::NewLane {
                lane_id: lane.clone(),
                seat_id: self.binding.policy.seat_id.clone(),
                project_id: self.scope.project.clone(),
                template_id: "template:fixture".to_owned(),
                backend: "local_omp".to_owned(),
                created_by: "operator:fixture".to_owned(),
                created_at,
                retained: false,
            },
        )
        .expect("fixture bridge lane");
        odin_ledger::lane_run::create_run(
            ledger.connection(),
            &odin_ledger::lane_run::NewRun {
                run_id: run,
                lane_id: lane,
                attempt_number: 1,
                workflow_id: Some("live:fixture".to_owned()),
                workflow_version: Some(1),
                input_hash: "fixture".to_owned(),
                accepted_capability_revision: None,
                lease_id: None,
                absolute_deadline: None,
                retry_budget: 0,
                created_at,
            },
        )
        .expect("fixture bridge run");
    }

    fn assemble(kind: FixtureKind, status: Option<Arc<dyn HostAdapterStatus>>) -> Self {
        Self::assemble_with_model_surfaces(kind, status, SEAT_ASK_BOUND_PROJECTS, false, None)
    }

    /// The single assembly site. `seat_ask_bound_projects` is the declared
    /// bound-project set rendered into the listed seat-ask model surface;
    /// every other kind ignores it. `durable` journals to a file under the
    /// fixture root instead of memory. `brain_embedding` binds the brain
    /// kind's embedding leg; `None` keeps it lexical.
    fn assemble_with_model_surfaces(
        kind: FixtureKind,
        status: Option<Arc<dyn HostAdapterStatus>>,
        seat_ask_bound_projects: &'static [&'static str],
        durable: bool,
        brain_embedding: Option<BrainEmbedding>,
    ) -> Self {
        let root = std::env::temp_dir().join(format!(
            "odin-omp-operation-authority-{}-{}",
            std::process::id(),
            NEXT_ROOT.fetch_add(1, Ordering::Relaxed)
        ));
        let token_root = root.join("tokens");
        fs::create_dir_all(&token_root).expect("create provisioned token root");

        let session = SessionId::new("00000000-0000-4000-8000-000000000707").expect("session id");
        let seat = SeatId::new("seat.fixture").expect("seat id");
        let slice = SliceId::new("slice.fixture").expect("slice id");
        let lane = LaneId::new("lane.fixture").expect("lane id");
        let seat_revision = Digest::hash(b"fixture seat revision");
        let slice_revision = Digest::hash(b"fixture slice revision");
        let resource = ResourceConstraint::Named {
            kind: "workspace".to_owned(),
            value: "fixture".to_owned(),
        };
        let input_schema_ref = match kind {
            FixtureKind::ReadExec
            | FixtureKind::AdapterSearch
            | FixtureKind::DraftR2
            | FixtureKind::DraftR2Operator
            | FixtureKind::PlanWriter => INPUT_SCHEMA,
            FixtureKind::EvalRun => EVAL_INPUT_SCHEMA,
            FixtureKind::FileEdit => FILE_EDIT_INPUT_SCHEMA,
            FixtureKind::SeatAsk => SEAT_ASK_INPUT_SCHEMA,
            FixtureKind::BrowserConsequential => BROWSER_CONSEQUENTIAL_INPUT_SCHEMA,
            FixtureKind::WorkloadPublish => WORKLOAD_PUBLISH_INPUT_SCHEMA,
            // Brain carries one schema per operation; the catalog below
            // registers both explicitly.
            FixtureKind::Brain => BRAIN_SEARCH_INPUT_SCHEMA,
        };
        let contracts = match kind {
            FixtureKind::ReadExec => {
                let read = contract(
                    READ_CAPABILITY,
                    READ_TOOL,
                    READ_HANDLER,
                    READ_EXTRACTOR,
                    EffectClass::R0,
                );
                let execute = contract(
                    EXEC_CAPABILITY,
                    EXEC_TOOL,
                    EXEC_HANDLER,
                    EXEC_EXTRACTOR,
                    EffectClass::R3,
                );
                BTreeMap::from([(read.id.clone(), read), (execute.id.clone(), execute)])
            }
            FixtureKind::AdapterSearch => {
                let mut search = contract(
                    SEARCH_CAPABILITY,
                    SEARCH_TOOL,
                    READ_HANDLER,
                    READ_EXTRACTOR,
                    EffectClass::R0,
                );
                search.adapter = Some(SEARCH_ADAPTER.to_owned());
                BTreeMap::from([(search.id.clone(), search)])
            }
            FixtureKind::DraftR2 => {
                let draft = contract(
                    DRAFT_CAPABILITY,
                    DRAFT_TOOL,
                    DRAFT_HANDLER,
                    DRAFT_EXTRACTOR,
                    EffectClass::R2,
                );
                BTreeMap::from([(draft.id.clone(), draft)])
            }
            FixtureKind::DraftR2Operator => {
                let mut draft = contract(
                    DRAFT_CAPABILITY,
                    DRAFT_TOOL,
                    DRAFT_HANDLER,
                    DRAFT_EXTRACTOR,
                    EffectClass::R2,
                );
                draft.approval = ApprovalRequirement::Operator;
                BTreeMap::from([(draft.id.clone(), draft)])
            }
            FixtureKind::EvalRun => {
                let mut eval = contract(
                    EVAL_CAPABILITY,
                    EVAL_TOOL,
                    EVAL_HANDLER,
                    EVAL_EXTRACTOR,
                    EffectClass::R1,
                );
                eval.input_schema_ref = input_schema_ref.to_owned();
                BTreeMap::from([(eval.id.clone(), eval)])
            }
            FixtureKind::FileEdit => {
                let mut edit = contract(
                    "capsule.file.edit",
                    FILE_EDIT_TOOL,
                    FILE_EDIT_HANDLER,
                    FILE_EDIT_EXTRACTOR,
                    EffectClass::R1,
                );
                edit.input_schema_ref = input_schema_ref.to_owned();
                BTreeMap::from([(edit.id.clone(), edit)])
            }
            FixtureKind::SeatAsk => {
                let mut ask = contract(
                    SEAT_ASK_CAPABILITY,
                    SEAT_ASK_TOOL,
                    SEAT_ASK_HANDLER,
                    SEAT_ASK_EXTRACTOR,
                    EffectClass::R3,
                );
                ask.input_schema_ref = input_schema_ref.to_owned();
                // The real `seat.ask.kubert` declaration names Kubert as its
                // delegation target: dispatch arguments carry the canonical
                // `_delegate_to` binding derived from this contract, and the
                // generic schema requires it.
                ask.delegate_to = Some(SeatId::new("kubert").expect("fixture seat id"));
                BTreeMap::from([(ask.id.clone(), ask)])
            }
            FixtureKind::BrowserConsequential => {
                let mut interact = contract(
                    BROWSER_CONSEQUENTIAL_CAPABILITY,
                    BROWSER_CONSEQUENTIAL_TOOL,
                    BROWSER_CONSEQUENTIAL_HANDLER,
                    BROWSER_CONSEQUENTIAL_EXTRACTOR,
                    EffectClass::R3,
                );
                interact.input_schema_ref = input_schema_ref.to_owned();
                interact.preview = Some(odin_registry::schema::PreviewKindToml::Browser);
                interact.batchable = true;
                BTreeMap::from([(interact.id.clone(), interact)])
            }
            FixtureKind::WorkloadPublish => {
                let mut publish = contract(
                    WORKLOAD_PUBLISH_CAPABILITY,
                    WORKLOAD_PUBLISH_TOOL,
                    WORKLOAD_PUBLISH_HANDLER,
                    WORKLOAD_PUBLISH_EXTRACTOR,
                    EffectClass::R3,
                );
                publish.input_schema_ref = input_schema_ref.to_owned();
                BTreeMap::from([(publish.id.clone(), publish)])
            }
            FixtureKind::Brain => {
                let mut search = contract(
                    BRAIN_SEARCH_CAPABILITY,
                    BRAIN_SEARCH_TOOL,
                    crate::host_tools::brain::SEARCH_HANDLER,
                    SEARCH_EVIDENCE,
                    EffectClass::R0,
                );
                search.input_schema_ref = BRAIN_SEARCH_INPUT_SCHEMA.to_owned();
                let mut read = contract(
                    BRAIN_READ_CAPABILITY,
                    BRAIN_READ_TOOL,
                    crate::host_tools::brain::READ_HANDLER,
                    READ_EVIDENCE,
                    EffectClass::R0,
                );
                read.input_schema_ref = BRAIN_READ_INPUT_SCHEMA.to_owned();
                BTreeMap::from([(search.id.clone(), search), (read.id.clone(), read)])
            }
            FixtureKind::PlanWriter => {
                let mut plan = contract(
                    PLAN_CAPABILITY,
                    PLAN_TOOL,
                    PLAN_HANDLER,
                    PLAN_EXTRACTOR,
                    EffectClass::R1,
                );
                plan.input_schema_ref = PLAN_INPUT_SCHEMA.to_owned();
                let side_effect = contract(
                    SIDE_EFFECT_CAPABILITY,
                    SIDE_EFFECT_TOOL,
                    SIDE_EFFECT_HANDLER,
                    SIDE_EFFECT_EXTRACTOR,
                    EffectClass::R1,
                );
                BTreeMap::from([
                    (plan.id.clone(), plan),
                    (side_effect.id.clone(), side_effect),
                ])
            }
        };
        let admission = admission_digest(&contracts, 1).expect("admission digest");
        let allowed = contracts.keys().cloned().collect::<BTreeSet<_>>();
        let policy = seat_operation_policy(SeatOperationPolicyInputs {
            seat_id: seat.clone(),
            slice_id: slice.clone(),
            lane_id: lane.clone(),
            seat_revision,
            slice_revision,
            admission,
            seat_tool_refs: allowed.clone(),
            slice_capabilities: allowed.clone(),
            project_capabilities: allowed.clone(),
            lane_capabilities: allowed,
            denied_capabilities: BTreeSet::new(),
            denied_tools: BTreeSet::new(),
            resource_constraints: contracts
                .keys()
                .map(|id| (id.clone(), vec![resource.clone()]))
                .collect::<BTreeMap<_, _>>(),
            seat_categories: BTreeSet::from(["tester".to_owned()]),
        });
        // The fixture's own single-generation material source: the exact
        // contracts and policy this fixture composed, pinned at revision 1
        // — the generation the binding below and the listing/dispatch
        // pipeline resolve. Any other revision refuses.
        let material_source = Arc::new(FixtureMaterialSource::new(
            &contracts,
            &policy,
            seat.clone(),
            lane.clone(),
        ));
        let binding = SessionOperationBinding {
            policy: policy.policy,
            context_policy_digest: policy.context_policy_digest,
            capsule_id: session_capsule_id(&session).expect("capsule id"),
            served_revision: 1,
            parent: None,
        };

        let key = generate_signing_key();
        let signing_key = key.clone();
        let issuer = TokenIssuer::new(key.clone()).expect("test token issuer");
        let token = issuer
            .mint(MintRequest {
                seat,
                slice,
                lane,
                session: session.clone(),
                seat_revision,
                slice_revision,
                capability_policy_digest: admission,
                context_policy_digest: binding.context_policy_digest,
                issued_at_ms: 0,
                expires_at_ms: TOKEN_EXPIRES_MS,
                entropy: b"production-operation-dispatch-fixture",
            })
            .expect("mint provisioned fixture token");
        let token_id = token.token_id.clone();
        fs::write(
            token_root.join(format!("{}.json", session.as_str())),
            serde_json::to_vec(&token).expect("encode fixture token"),
        )
        .expect("write provisioned fixture token");
        let authority_provider = Arc::new(
            ProvisionedFreshAuthorityProvider::open(token_root.clone(), key)
                .expect("open provisioned provider"),
        );

        let input = ToolSchema::from_value(match kind {
            FixtureKind::ReadExec
            | FixtureKind::AdapterSearch
            | FixtureKind::DraftR2
            | FixtureKind::DraftR2Operator
            | FixtureKind::PlanWriter => json!({
                "type": "object",
                "properties": {
                    "approvalId": {"type": "string"},
                    "mode": {
                        "type": "string",
                        "enum": ["success", "reject", "extractor_failure"]
                    },
                    "preWorld": {"type": "string"},
                    "value": {"type": "string"}
                },
                "required": ["value"],
                "additionalProperties": false
            }),
            FixtureKind::EvalRun => json!({
                "type": "object",
                "properties": {
                    "interpreter": {"type": "string", "enum": ["python", "bun"]},
                    "source": {"type": "string"},
                    "source_sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
                    "timeout_ms": {"type": "integer", "minimum": 1},
                    "max_stdout_bytes": {"type": "integer", "minimum": 1},
                    "max_stderr_bytes": {"type": "integer", "minimum": 1}
                },
                "required": [
                    "interpreter",
                    "source",
                    "source_sha256",
                    "timeout_ms",
                    "max_stdout_bytes",
                    "max_stderr_bytes"
                ],
                "additionalProperties": false
            }),
            FixtureKind::FileEdit => serde_json::from_str(include_str!(
                "../../../../../../schemas/capability/capsule.file.edit.input.json"
            ))
            .expect("real canonical capsule.file.edit input schema"),
            FixtureKind::SeatAsk => serde_json::from_str(include_str!(
                "../../../../../../schemas/capability/seat.ask.input.json"
            ))
            .expect("real seat.ask input schema"),
            FixtureKind::BrowserConsequential => serde_json::from_str(include_str!(
                "../../../../../../schemas/capability/browser.consequential.input.json"
            ))
            .expect("real canonical browser.consequential input schema"),
            FixtureKind::WorkloadPublish => serde_json::from_str(include_str!(
                "../../../../../../schemas/capability/workload.publish.input.json"
            ))
            .expect("real canonical workload.publish input schema"),
            // The brain catalog above carries the real per-operation
            // schemas; this placeholder keeps the match exhaustive.
            FixtureKind::Brain => json!({"type": "object", "additionalProperties": false}),
        })
        .expect("input schema");
        let output = ToolSchema::from_value(json!({
            "type": "object",
            "additionalProperties": true
        }))
        .expect("output schema");
        // Brain validates against one strict schema per operation, exactly
        // the shape the production tool deserializes; every other kind
        // keeps the single generic fixture schema.
        let schemas: Arc<dyn SchemaCatalog + Send + Sync> = if kind == FixtureKind::Brain {
            Arc::new(
                StaticSchemaCatalog::new([
                    (
                        BRAIN_SEARCH_INPUT_SCHEMA.to_owned(),
                        brain_search_input_schema(),
                    ),
                    (
                        BRAIN_READ_INPUT_SCHEMA.to_owned(),
                        brain_read_input_schema(),
                    ),
                    (OUTPUT_SCHEMA.to_owned(), output),
                ])
                .expect("brain schema catalog"),
            )
        } else if kind == FixtureKind::PlanWriter {
            let plan_input = ToolSchema::from_value(
                serde_json::from_str(include_str!(
                    "../../../../../../schemas/capability/odin.plan_set.input.json"
                ))
                .expect("real odin.plan_set input schema"),
            )
            .expect("plan input schema");
            Arc::new(
                StaticSchemaCatalog::new([
                    (PLAN_INPUT_SCHEMA.to_owned(), plan_input),
                    (INPUT_SCHEMA.to_owned(), input),
                    (OUTPUT_SCHEMA.to_owned(), output),
                ])
                .expect("plan writer schema catalog"),
            )
        } else {
            Arc::new(
                StaticSchemaCatalog::new([
                    (input_schema_ref.to_owned(), input),
                    (OUTPUT_SCHEMA.to_owned(), output),
                ])
                .expect("schema catalog"),
            )
        };

        let file_root = if kind == FixtureKind::FileEdit {
            let path = root.join("files");
            fs::create_dir(&path).expect("create private file fixture root");
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
                .expect("make file fixture root private");
            Some(odin_confined_fs::PrivateCapability::seal(&path).expect("seal file fixture root"))
        } else {
            None
        };
        let world = Arc::new(FixtureWorld {
            clock_ms: AtomicU64::new(NOW_MS),
            file_root,
            ..FixtureWorld::default()
        });
        let ledger_path = durable.then(|| root.join("operation-ledger.sqlite"));
        let ledger = Arc::new(Mutex::new(
            match &ledger_path {
                Some(path) => Ledger::open(path),
                None => Ledger::open_in_memory(),
            }
            .expect("operation ledger"),
        ));
        let mut registry = HostToolRegistry::new();
        let handlers: &[(&str, FixtureRole)] = match kind {
            FixtureKind::ReadExec => &[
                (READ_HANDLER, FixtureRole::Handler),
                (READ_EXTRACTOR, FixtureRole::Extractor),
                (EXEC_HANDLER, FixtureRole::Handler),
                (EXEC_EXTRACTOR, FixtureRole::Extractor),
            ],
            FixtureKind::EvalRun => &[
                (EVAL_HANDLER, FixtureRole::Eval),
                (EVAL_EXTRACTOR, FixtureRole::Extractor),
            ],
            FixtureKind::FileEdit => &[
                (FILE_EDIT_HANDLER, FixtureRole::FileCreate),
                (FILE_EDIT_EXTRACTOR, FixtureRole::Extractor),
            ],
            // The brain tools register their own handler and evidence
            // bindings through `brain::register` below.
            FixtureKind::Brain => &[],
            FixtureKind::SeatAsk => &[
                (SEAT_ASK_HANDLER, FixtureRole::Eval),
                (SEAT_ASK_EXTRACTOR, FixtureRole::Extractor),
            ],
            FixtureKind::BrowserConsequential => &[
                (BROWSER_CONSEQUENTIAL_HANDLER, FixtureRole::Eval),
                (BROWSER_CONSEQUENTIAL_EXTRACTOR, FixtureRole::Extractor),
            ],
            FixtureKind::WorkloadPublish => &[
                (WORKLOAD_PUBLISH_HANDLER, FixtureRole::WorkloadPublish),
                (WORKLOAD_PUBLISH_EXTRACTOR, FixtureRole::Extractor),
            ],
            FixtureKind::AdapterSearch => &[
                (READ_HANDLER, FixtureRole::Handler),
                (READ_EXTRACTOR, FixtureRole::Extractor),
            ],
            FixtureKind::DraftR2 | FixtureKind::DraftR2Operator => &[
                (DRAFT_HANDLER, FixtureRole::Handler),
                (DRAFT_EXTRACTOR, FixtureRole::Extractor),
            ],
            FixtureKind::PlanWriter => &[
                (PLAN_EXTRACTOR, FixtureRole::Extractor),
                (SIDE_EFFECT_HANDLER, FixtureRole::Handler),
                (SIDE_EFFECT_EXTRACTOR, FixtureRole::Extractor),
            ],
        };
        for &(name, role) in handlers {
            registry
                .register_internal(
                    InternalBindingKey::Builtin(name.to_owned()),
                    Arc::new(FixtureTool::new(name, role, Arc::clone(&world))),
                )
                .expect("register fixture binding");
        }
        if kind == FixtureKind::PlanWriter {
            registry
                .register(Arc::new(PlanSetTool::new(Arc::clone(&ledger))))
                .expect("register plan writer");
        } else {
            registry
                .register(Arc::new(FixtureTool::new(
                    UNBOUND_MODEL_TOOL,
                    FixtureRole::Handler,
                    Arc::clone(&world),
                )))
                .expect("register unbound familiar implementation");
        }
        // Capability-bound routes register their exact production model
        // surface as listed definitions: the operation surface compiles
        // its pre-gate argument narrowing from these declarations alone.
        match kind {
            FixtureKind::SeatAsk => registry
                .register(Arc::new(FixtureTool::with_model_surface(
                    SEAT_ASK_TOOL,
                    FixtureRole::Listed,
                    Arc::clone(&world),
                    seat_ask_model_parameters(seat_ask_bound_projects),
                )))
                .expect("register declared seat-ask model surface"),
            FixtureKind::EvalRun => registry
                .register(Arc::new(FixtureTool::with_model_surface(
                    EVAL_TOOL,
                    FixtureRole::Listed,
                    Arc::clone(&world),
                    eval_model_projection(),
                )))
                .expect("register projected eval model surface"),
            FixtureKind::BrowserConsequential => registry
                .register(Arc::new(FixtureTool::with_model_surface(
                    BROWSER_CONSEQUENTIAL_TOOL,
                    FixtureRole::Listed,
                    Arc::clone(&world),
                    browser_model_projection(),
                )))
                .expect("register projected browser model surface"),
            FixtureKind::WorkloadPublish => registry
                .register(Arc::new(FixtureTool::with_model_surface(
                    WORKLOAD_PUBLISH_TOOL,
                    FixtureRole::Listed,
                    Arc::clone(&world),
                    workload_publish_model_projection(),
                )))
                .expect("register projected workload publish surface"),
            FixtureKind::ReadExec
            | FixtureKind::AdapterSearch
            | FixtureKind::FileEdit
            | FixtureKind::DraftR2
            | FixtureKind::DraftR2Operator
            | FixtureKind::Brain
            | FixtureKind::PlanWriter => {}
        }
        let brain_slot: Option<BrainToolsSlot> = if kind == FixtureKind::Brain {
            let slot: BrainToolsSlot = Arc::new(OnceLock::new());
            crate::host_tools::brain::register(&mut registry, Arc::clone(&slot))
                .expect("register production brain tools");
            Some(slot)
        } else {
            None
        };
        let registry = Arc::new(registry);
        let adapter_status: Arc<dyn HostAdapterStatus> = status.unwrap_or_else(|| {
            Arc::new(SupervisedAdapterStatus::new(
                Arc::new(UnsupervisedAdapterStatus),
                std::collections::BTreeSet::new(),
                std::time::Duration::ZERO,
            ))
        });
        let operations = operation_stack(
            kind,
            &root,
            &registry,
            &contracts,
            &schemas,
            &world,
            &ledger,
            &material_source,
            &adapter_status,
            authority_provider,
        );
        let scope = Scope {
            seat: Some(binding.policy.seat_id.clone()),
            project: Some(ProjectId::new(BRAIN_PROJECT).expect("project id")),
            lane: Some(binding.policy.lane_id.clone()),
            run: Some(RunId::new("run.fixture").expect("run id")),
            session: Some(session.clone()),
            ..Scope::default()
        };
        // The governed knowledge world exists only behind the brain kind:
        // the live session row whose columns equal the dispatch scope, the
        // registered session binding the backend verifies against, the real
        // brain service and scoped router, and the live execution proof.
        let brain_world = if kind == FixtureKind::Brain {
            Some(assemble_brain_world(
                &root,
                &ledger,
                &operations,
                &binding,
                &session,
                &scope,
                brain_slot.as_ref().expect("brain slot"),
                brain_embedding,
            ))
        } else {
            None
        };
        Self {
            root,
            operations,
            binding,
            registry,
            ledger,
            contracts,
            schemas,
            world,
            session,
            scope,
            resource,
            token_id,
            signing_key,
            token_root,
            material_source,
            _brain_slot: brain_slot,
            execution: brain_world.as_ref().map(|(execution, _)| execution.clone()),
            _brain_sessions: brain_world.map(|(_, sessions)| sessions),
            ledger_path,
            kind,
            adapter_status,
        }
    }

    /// A real restart over the durable journal: the ledger file reopens on a
    /// fresh connection — connection-private state such as a TEMP trigger
    /// dies with the old one — and the production stack is reassembled over
    /// it with a freshly opened token provider, so construction runs the
    /// same crash recovery a restarted host runs.
    pub(super) fn reopen_ledger(&mut self) {
        let path = self
            .ledger_path
            .clone()
            .expect("only a durable fixture reopens its ledger");
        let ledger = Arc::new(Mutex::new(
            Ledger::open(&path).expect("reopen operation ledger"),
        ));
        let authority_provider = Arc::new(
            ProvisionedFreshAuthorityProvider::open(
                self.token_root.clone(),
                self.signing_key.clone(),
            )
            .expect("reopen provisioned provider"),
        );
        self.operations = operation_stack(
            self.kind,
            &self.root,
            &self.registry,
            &self.contracts,
            &self.schemas,
            &self.world,
            &ledger,
            &self.material_source,
            &self.adapter_status,
            authority_provider,
        );
        self.ledger = ledger;
    }

    /// The live execution proof of the seeded session: session, run, lane,
    /// and epoch 1 exactly as the host bridge would capture them.
    pub(super) fn execution(&self) -> ExecutionBinding {
        self.execution
            .clone()
            .expect("brain fixture execution proof")
    }

    /// A proof for the same bound dimensions at an arbitrary epoch — stale
    /// by construction against the seeded live row at epoch 1.
    pub(super) fn execution_at_epoch(&self, epoch: i64) -> ExecutionBinding {
        let mut binding = BridgeBinding::new(
            self.scope.clone(),
            self.session.clone(),
            self.scope.run.clone().expect("bound run"),
            self.binding.policy.lane_id.clone(),
            "fixture-owner",
        );
        binding.epoch = epoch;
        ExecutionBinding::from_binding(&binding)
    }

    /// Dispatches with the caller-carried execution proof the bridge
    /// produces; `None` dispatches proof-free like every ordinary tool.
    pub(super) fn dispatch_execution(
        &self,
        tool_name: &str,
        resource: Option<ResourceConstraint>,
        arguments: Value,
        request_id: &str,
        execution: Option<&ExecutionBinding>,
    ) -> Result<Value, HostToolOperationError> {
        self.operations.dispatch_tool(
            SessionOperationContext {
                binding: &self.binding,
                session: &self.session,
                scope: &self.scope,
                execution,
            },
            tool_name,
            resource,
            arguments,
            request_id,
        )
    }

    pub(super) fn dispatch(
        &self,
        arguments: Value,
        request_id: &str,
    ) -> Result<Value, HostToolOperationError> {
        self.dispatch_named(
            READ_TOOL,
            Some(self.resource.clone()),
            arguments,
            request_id,
        )
    }

    pub(super) fn dispatch_named(
        &self,
        tool_name: &str,
        resource: Option<ResourceConstraint>,
        arguments: Value,
        request_id: &str,
    ) -> Result<Value, HostToolOperationError> {
        self.operations.dispatch_tool(
            SessionOperationContext {
                binding: &self.binding,
                session: &self.session,
                scope: &self.scope,
                execution: None,
            },
            tool_name,
            resource,
            arguments,
            request_id,
        )
    }

    pub(super) fn row(&self, request_id: &str) -> Option<operation_store::OperationRow> {
        let correlation = correlation_for(&self.session, request_id).expect("request correlation");
        operation_store::operation_row(
            self.ledger.lock().expect("ledger lock").connection(),
            correlation.as_str(),
        )
        .expect("operation row query")
    }
}

/// Assembles the production operation stack over one ledger handle — the
/// declared catalog, the production executor, and `HostToolOperations::new`,
/// whose construction recovers crash orphans — exactly as a (re)starting
/// host composes it. First assembly and a durable reopen share this site.
#[allow(clippy::too_many_arguments)]
fn operation_stack(
    kind: FixtureKind,
    root: &Path,
    registry: &Arc<HostToolRegistry>,
    contracts: &BTreeMap<CapabilityId, CapabilityContract>,
    schemas: &Arc<dyn SchemaCatalog + Send + Sync>,
    world: &Arc<FixtureWorld>,
    ledger: &Arc<Mutex<Ledger>>,
    material_source: &Arc<FixtureMaterialSource>,
    adapter_status: &Arc<dyn HostAdapterStatus>,
    authority_provider: Arc<ProvisionedFreshAuthorityProvider>,
) -> HostToolOperations {
    let admission = admission_digest(contracts, 1).expect("admission digest");
    let catalog: Arc<dyn odin_kernel::OperationCatalog> = Arc::new(
        DeclaredOperationCatalog::from_contracts(
            contracts,
            1,
            admission,
            Arc::clone(registry),
            &BTreeSet::new(),
        )
        .expect("declared operation catalog"),
    );
    let executor = Arc::new(HostToolExecutor::new(Arc::clone(registry)));
    let workload_drafts = Some(Arc::new(
        crate::host_tools::WorkloadDraftStore::seal(root).expect("seal retained-draft store"),
    ));
    HostToolOperations::new(
        OperationStackInputs {
            workload_drafts,
            catalog,
            schemas: Arc::clone(schemas),
            adapter_executor: match kind {
                FixtureKind::AdapterSearch => Arc::new(PageNotLoaded(Arc::clone(&executor))),
                _ => Arc::clone(&executor) as Arc<dyn odin_kernel::OperationExecutor>,
            },
            adapter_status: Arc::clone(adapter_status),
            executor,
            limits: Limits::new(100, 100, 100),
            clock: {
                let world = Arc::clone(world);
                Arc::new(move || world.clock_ms.load(Ordering::SeqCst))
            },
            ledger: Arc::clone(ledger),
            revisions: Arc::clone(material_source) as Arc<dyn RevisionMaterialSource>,
        },
        contracts.clone(),
        authority_provider,
    )
    .expect("operation surface")
}

pub(crate) fn contract(
    id: &str,
    tool_name: &str,
    handler: &str,
    extractor: &str,
    effect_class: EffectClass,
) -> CapabilityContract {
    CapabilityContract {
        id: CapabilityId::new(id).expect("capability id"),
        delegate_to: None,
        version: 1,
        tool_name: ToolName::new(tool_name).expect("tool name"),
        description: format!("{tool_name} fixture"),
        handler: HandlerBinding::Builtin {
            name: handler.to_owned(),
        },
        input_schema_ref: INPUT_SCHEMA.to_owned(),
        output_schema_ref: OUTPUT_SCHEMA.to_owned(),
        effect_class,
        seat_tags: BTreeSet::from(["tester".to_owned()]),
        timeout_seconds: NonZeroU32::new(5).expect("timeout"),
        idempotency: IdempotencyPolicy::Required,
        retry: RetryPolicy { max_attempts: 1 },
        approval: if effect_class == EffectClass::R3 {
            ApprovalRequirement::Operator
        } else {
            ApprovalRequirement::None
        },
        evidence_extractor: HandlerBinding::Builtin {
            name: extractor.to_owned(),
        },
        adapter: None,
        preview: None,
        batchable: false,
        batch: None,
    }
}

/// Serves revision 1 and explicitly added test publications; unknown and legacy revisions are refused.
pub(crate) struct FixtureMaterialSource {
    materials: Mutex<BTreeMap<u64, RevisionMaterial>>,
}

impl FixtureMaterialSource {
    pub(crate) fn new(
        contracts: &BTreeMap<CapabilityId, CapabilityContract>,
        policy: &crate::host_tools::operations::SeatOperationPolicy,
        seat: SeatId,
        lane: LaneId,
    ) -> Self {
        let materials = Mutex::new(BTreeMap::from([(
            1,
            Self::compose(contracts, policy, seat, lane, 1),
        )]));
        Self { materials }
    }

    /// Marks a capability declaration-decided in every pinned publication.
    pub(super) fn declare_decided(&self, capability: &str) {
        for material in self
            .materials
            .lock()
            .expect("fixture material lock")
            .values_mut()
        {
            material
                .declaration_decided
                .insert(CapabilityId::new(capability).expect("capability id"));
        }
    }

    /// Publishes the declared grant-batch policy onto the current revision.
    /// Limits live on `task.grant`; the named effects are the ones a batch
    /// may cover. Listing still admits only the policy's bound set, so the
    /// grant row needs no handler.
    pub(super) fn declare_grant_batch(&self, effects: &[&str]) {
        let mut materials = self.materials.lock().expect("fixture material lock");
        for material in materials.values_mut() {
            let contracts = std::sync::Arc::make_mut(&mut material.contracts);
            for effect in effects {
                let id = CapabilityId::new(*effect).expect("capability id");
                contracts.get_mut(&id).expect("effect capability").batchable = true;
            }
            if contracts.values().any(|contract| contract.batch.is_some()) {
                continue;
            }
            let mut grant = contract(
                "task.grant",
                "task_grant",
                "task_grant",
                "odin_hermes_task_grant_evidence",
                EffectClass::R3,
            );
            grant.preview = Some(odin_registry::schema::PreviewKindToml::Batch);
            grant.batch = Some(odin_registry::schema::BatchLimitsToml {
                max_effects: 16,
                max_minutes: 1440,
                max_uses: 500,
            });
            let id = grant.id.clone();
            material
                .tool_index
                .insert(grant.tool_name.as_ref().to_owned(), id.clone());
            contracts.insert(id, grant);
        }
    }

    /// Pins one further publication the test opened sessions under.
    pub(super) fn add_generation(
        &self,
        revision: u64,
        contracts: &BTreeMap<CapabilityId, CapabilityContract>,
        policy: &crate::host_tools::operations::SeatOperationPolicy,
        seat: SeatId,
        lane: LaneId,
    ) {
        self.materials
            .lock()
            .expect("fixture material lock")
            .insert(
                revision,
                Self::compose(contracts, policy, seat, lane, revision),
            );
    }

    fn compose(
        contracts: &BTreeMap<CapabilityId, CapabilityContract>,
        policy: &crate::host_tools::operations::SeatOperationPolicy,
        seat: SeatId,
        lane: LaneId,
        revision: u64,
    ) -> RevisionMaterial {
        let admission =
            admission_digest(contracts, revision as i64).expect("fixture admission digest");
        let mut tool_index = BTreeMap::new();
        for (id, contract) in contracts {
            if let Some(existing) =
                tool_index.insert(contract.tool_name.as_ref().to_owned(), id.clone())
            {
                panic!("fixture binds tool twice: {existing} and {id}");
            }
        }
        RevisionMaterial {
            revision,
            contracts: Arc::new(contracts.clone()),
            admission_digest: admission,
            seat_operation_bindings: BTreeMap::from([((seat, lane), policy.clone())]),
            session_lanes: BTreeMap::new(),
            tool_index,
            contract_adapters: contracts
                .values()
                .filter_map(|contract| contract.adapter.clone())
                .collect(),
            declaration_decided: BTreeSet::new(),
            escalation_targets: Default::default(),
        }
    }
}

impl RevisionMaterialSource for FixtureMaterialSource {
    fn material_at(&self, revision: u64) -> Result<RevisionMaterial, String> {
        self.materials
            .lock()
            .expect("fixture material lock")
            .get(&revision)
            .cloned()
            .ok_or_else(|| format!("fixture serves no publication revision {revision}"))
    }

    fn resolve_legacy(&self, _token: &SeatToken) -> Result<u64, String> {
        Err("fixture authority resolves no legacy generation".to_owned())
    }
}

/// The strict brain search input schema — the exact shape the production
/// tool deserializes with `deny_unknown_fields`.
fn brain_search_input_schema() -> ToolSchema {
    ToolSchema::from_value(json!({
        "type": "object",
        "properties": {
            "query": {"type": "string", "minLength": 1, "maxLength": 4096},
            "source": {"type": "string", "minLength": 1, "maxLength": 128}
        },
        "required": ["query"],
        "additionalProperties": false
    }))
    .expect("brain search input schema")
}

/// The strict brain read input schema — an identified canonical URL only.
fn brain_read_input_schema() -> ToolSchema {
    ToolSchema::from_value(json!({
        "type": "object",
        "properties": {"url": {"type": "string", "minLength": 1, "maxLength": 1024}},
        "required": ["url"],
        "additionalProperties": false
    }))
    .expect("brain read input schema")
}

fn brain_slice(retrieval_mode: RetrievalMode) -> SliceToml {
    SliceToml {
        schema: REGISTRY_SCHEMA.to_owned(),
        kind: RegistryKind::Slice,
        enabled: true,
        description: "brain fixture slice".to_owned(),
        capabilities: BTreeSet::new(),
        variables: BTreeMap::new(),
        redirects: SliceRedirectsToml {
            out_of_scope: "NeedsPlan".to_owned(),
        },
        knowledge: Some(SliceKnowledgeToml {
            required: false,
            atlas_sources: atlas_id_set(),
            retrieval_mode,
            candidate_limit: nz16(128),
            top_k: nz16(16),
            min_score_micros: 100_000,
            chunk_tokens: nz32(512),
            chunk_overlap_tokens: 64,
            embedding_backend: EmbeddingBackend::Local,
        }),
        context: Some(SliceContextToml {
            max_bundle_tokens: nz32(32768),
            reserve_output_tokens: nz32(8192),
            control_tokens: nz32(4096),
            history_tokens: nz32(12288),
            core_tokens: nz32(2048),
            prefetch_tokens: nz32(6144),
            tool_result_tokens: nz32(4096),
            tool_schema_tokens: nz32(4096),
            max_item_tokens: nz32(2048),
        }),
        tools: Some(SliceToolsToml {
            allow: BTreeSet::new(),
            deny: BTreeSet::new(),
            redirects: SliceToolRedirectsToml {
                max_http_hops: 2,
                allow_cross_origin: false,
                allow_https_downgrade: false,
            },
            alias_redirect: BTreeSet::new(),
        }),
        live: None,
        budget: None,
    }
}

fn brain_seat() -> SeatToml {
    SeatToml {
        schema: REGISTRY_SCHEMA.to_owned(),
        kind: RegistryKind::Seat,
        enabled: true,
        description: "brain fixture seat".to_owned(),
        categories: BTreeSet::new(),
        tool_refs: BTreeSet::new(),
        project_scope: BTreeSet::from([
            odin_domain::ProjectId::new(BRAIN_PROJECT).expect("brain fixture project id")
        ]),
        read_project_scope: BTreeSet::new(),
        models: Vec::new(),
        approval_defaults: ApprovalDefaultsToml {
            r0: ApprovalDefaultToml::Auto,
            r1: ApprovalDefaultToml::Auto,
            r2: ApprovalDefaultToml::Auto,
            r3: ApprovalDefaultToml::Approval,
        },
        brain_scope: atlas_id_set(),
        limits: SeatLimitsToml {
            max_parallel_runs: 4,
            max_sessions: 4,
            budget: Some(BudgetPolicyToml {
                usd_micros: 30_000_000,
                window: AccountingWindowToml {
                    duration_seconds: NonZeroU64::new(2_592_000).unwrap(),
                },
            }),
        },
        live: None,
        knowledge: Some(SeatKnowledgeToml {
            atlas_sources: atlas_id_set(),
            required_tags: BTreeSet::new(),
            denied_tags: BTreeSet::new(),
            top_k: nz16(8),
        }),
        context: Some(SeatContextToml {
            max_bundle_tokens: nz32(24576),
            profile: "sized".into(),
            review_lane: None,
        }),
        tools: Some(SeatToolsToml {
            deny: BTreeSet::new(),
            redirects: SeatToolRedirectsToml {
                max_http_hops: 2,
                allow_cross_origin: false,
                disabled_aliases: BTreeSet::new(),
            },
            always: BTreeSet::new(),
        }),
        guidance: None,
        conversation: None,
        profile_namespace: None,
        ephemeral: None,
        sandbox: odin_registry::schema::SeatSandboxToml::default(),
    }
}

fn brain_project() -> ProjectToml {
    ProjectToml {
        schema: REGISTRY_SCHEMA.to_owned(),
        kind: RegistryKind::Project,
        enabled: true,
        description: "brain fixture project".to_owned(),
        source_root: String::new(),
        default_seat: SeatId::new("seat.fixture").expect("brain fixture seat id"),
        memory_namespaces: atlas_id_set(),
        artifact_policy: "standard".to_owned(),
        privacy: None,
        accounts: Default::default(),
        review_verdict: None,
    }
}

fn atlas_id_set() -> BTreeSet<AtlasId> {
    BTreeSet::from([AtlasId::new(BRAIN_ATLAS_SOURCE).expect("brain fixture atlas id")])
}

fn nz16(value: u16) -> NonZeroU16 {
    NonZeroU16::new(value).unwrap()
}

fn nz32(value: u32) -> NonZeroU32 {
    NonZeroU32::new(value).unwrap()
}

/// Keeps atlas routing empty so brain scope checks depend only on provenance.
fn empty_fixture_atlas() -> Atlas {
    Atlas {
        schema: ATLAS_SCHEMA.to_owned(),
        version: ATLAS_VERSION,
        generation: "fixture-brain-generation".to_owned(),
        source_paths: BTreeMap::new(),
        source_hashes: BTreeMap::new(),
        counts: AtlasCounts {
            files: 0,
            nodes: 0,
            parse_errors: 0,
            by_source: BTreeMap::new(),
        },
        files: Vec::new(),
        parse_errors: Vec::new(),
        nodes: Vec::new(),
    }
}

/// Assembles the governed knowledge world behind the brain fixture: the
/// bridge-owned lane/run/live-session rows whose columns equal the dispatch
/// scope, the registered session binding the backend re-verifies against,
/// the real brain service over one wired atlas source, the real scoped URI
/// router over the same ledger, and the production `RuntimeBrainTools`
/// backend bound into the brain tool slot. `embedding` declares the
/// slice's retrieval mode and binds the lane embedder; `None` serves the
/// lexical plan with no embedding leg. Returns the live execution proof
/// the host would capture at epoch 1.
#[allow(clippy::too_many_arguments)]
fn assemble_brain_world(
    root: &Path,
    ledger: &Arc<Mutex<Ledger>>,
    operations: &HostToolOperations,
    binding: &SessionOperationBinding,
    session: &SessionId,
    scope: &Scope,
    slot: &BrainToolsSlot,
    embedding: Option<BrainEmbedding>,
) -> (ExecutionBinding, Arc<LiveSessionBindings>) {
    let seat = &binding.policy.seat_id;
    let lane = &binding.policy.lane_id;
    let run = scope.run.clone().expect("brain fixture bound run");
    let project = scope.project.clone().expect("brain fixture bound project");
    let created_at = OffsetDateTime::UNIX_EPOCH;
    {
        let mut guard = ledger.lock().expect("brain fixture ledger lock");
        odin_ledger::lane_run::create_lane(
            guard.connection(),
            &odin_ledger::lane_run::NewLane {
                lane_id: lane.clone(),
                seat_id: seat.clone(),
                project_id: Some(project.clone()),
                template_id: "template:fixture".to_owned(),
                backend: "local_omp".to_owned(),
                created_by: "operator:fixture".to_owned(),
                created_at,
                retained: false,
            },
        )
        .expect("brain fixture lane");
        odin_ledger::lane_run::create_run(
            guard.connection(),
            &odin_ledger::lane_run::NewRun {
                run_id: run.clone(),
                lane_id: lane.clone(),
                attempt_number: 1,
                workflow_id: Some("live:fixture".to_owned()),
                workflow_version: Some(1),
                input_hash: "fixture".to_owned(),
                accepted_capability_revision: None,
                lease_id: None,
                absolute_deadline: None,
                retry_budget: 0,
                created_at,
            },
        )
        .expect("brain fixture run");
        guard
            .create_live_session(&NewLiveSession {
                session_id: session.clone(),
                seat_id: seat.to_string(),
                project_id: project.to_string(),
                slice_id: binding.policy.slice_id.to_string(),
                lane_id: lane.to_string(),
                target_node_id: "node.fixture".to_owned(),
                provider: "fixture-provider".to_owned(),
                model: "fixture-model".to_owned(),
                title: None,
                manifest: json!({}),
                open_tab: false,
                state: "ready".to_owned(),
                created_at,
            })
            .expect("brain fixture live session");
    }

    // Register the same session binding used for dispatch.
    let sessions = Arc::new(LiveSessionBindings::new(operations.clone()));
    sessions.register(session.clone(), binding.clone());

    // A real brain authority: one atlas source tree, a registry-resolved
    // policy at the session's served revision, empty stores.
    let atlas_root = root.join("brain-atlas-src");
    let src = atlas_root.join("crates/demo/src");
    fs::create_dir_all(&src).expect("brain fixture source dir");
    fs::write(
        src.join("lib.rs"),
        "//! Fixture brain crate.\n\n/// Marker.\npub fn fixture_brain_marker() -> u64 { 1 }\n",
    )
    .expect("brain fixture source");
    for class in ["extension", "registry", "skeletons"] {
        fs::create_dir_all(atlas_root.join(class)).expect("brain fixture source classes");
    }
    let model = ModelDescriptor {
        name: ModelName::new("model.fixture-brain").expect("brain fixture model"),
        tokenizer: TokenizerId::new("odin.tokenizer.utf8-bytes.v1").expect("tokenizer"),
        context_window_tokens: nz32(8192),
    };
    let mode = embedding
        .as_ref()
        .map_or(RetrievalMode::Lexical, |embedding| embedding.mode);
    let policy = EffectiveBrainPolicy::resolve(
        binding.served_revision,
        &brain_slice(mode),
        &brain_seat(),
        &BTreeMap::from([(BRAIN_PROJECT, &brain_project())]),
        &std::collections::BTreeMap::from([(
            "sized",
            &odin_registry::ContextProfileToml::sized(nz32(2048), nz32(6144)),
        )]),
        &model,
    )
    .expect("brain fixture policy");
    let service = Arc::new(
        BrainService::open(
            BrainServiceConfig {
                store_root: root.join("brain-store"),
                sources: BTreeMap::from([(
                    AtlasId::new(BRAIN_ATLAS_SOURCE).expect("brain fixture atlas id"),
                    BrainSourceConfig::Atlas { root: atlas_root },
                )]),
                embedding_available: embedding.is_some(),
                embedding_model: embedding.as_ref().map(|_| {
                    EmbeddingModelId::new("test:fixture-brain-v1")
                        .expect("brain fixture embedding model")
                }),
                archive_ingest_gate: None,
                postgres: None,
            },
            policy,
            Arc::clone(ledger),
        )
        .expect("brain fixture service"),
    );

    let artifact_dir = root.join("brain-artifacts");
    fs::create_dir_all(&artifact_dir).expect("brain fixture artifact root");
    let router = ScopedUriRouter::new(
        Arc::clone(ledger),
        Arc::new(empty_fixture_atlas()),
        AtlasScope::all(),
        artifact_dir,
        262_144,
        BTreeMap::from([(seat.clone(), Arc::clone(&service))]),
    )
    .expect("brain fixture router");
    let backend = RuntimeBrainTools {
        brains: BTreeMap::from([(seat.clone(), Arc::clone(&service))]),
        sessions: Arc::downgrade(&sessions),
        router,
        embedding: embedding.map(|embedding| {
            Arc::new(FixtureLaneEmbedding(embedding.embedder)) as Arc<dyn LaneEmbeddingProvider>
        }),
    };
    assert!(
        slot.set(Arc::new(backend)).is_ok(),
        "bind brain backend exactly once"
    );

    // The proof the host bridge would capture from its completed binding
    // at the seeded epoch: the same session, run, and lane the scope
    // binds, at live-session epoch 1.
    let mut bridge_binding = BridgeBinding::new(
        scope.clone(),
        session.clone(),
        run,
        lane.clone(),
        "fixture-owner",
    );
    bridge_binding.epoch = 1;
    (ExecutionBinding::from_binding(&bridge_binding), sessions)
}

/// The fixture adapter answers every call with Obscura's typed failure for
/// a page that did not load, relayed beside an in-doubt settlement as the
/// declared-adapter executor does.
struct PageNotLoaded(Arc<HostToolExecutor>);

pub(super) const PAGE_NOT_LOADED: &str =
    "the page did not load: https://arxiv.org/abs/missing answered HTTP 404";

impl odin_kernel::OperationExecutor for PageNotLoaded {
    fn id(&self) -> &'static str {
        self.0.id()
    }

    fn declared_pre_world(
        &self,
        contract: &CapabilityContract,
        payload: &odin_kernel::Payload,
    ) -> Result<Option<odin_kernel::PreWorld>, odin_kernel::ExecutorFault> {
        self.0.declared_pre_world(contract, payload)
    }

    fn observe(
        &self,
        contract: &CapabilityContract,
        payload: &odin_kernel::Payload,
    ) -> Result<odin_kernel::PreWorld, odin_kernel::ExecutorFault> {
        self.0.observe(contract, payload)
    }

    fn expected_post_world(
        &self,
        contract: &CapabilityContract,
        payload: &odin_kernel::Payload,
    ) -> Result<Option<Digest>, odin_kernel::ExecutorFault> {
        self.0.expected_post_world(contract, payload)
    }

    fn execute(
        &self,
        effect: odin_kernel::PreparedEffect,
    ) -> Result<odin_kernel::EffectOutcome, odin_kernel::ExecutorFault> {
        odin_adapter_core::dispatch::AdapterResultSink::relay_result(
            &*self.0,
            effect.correlation_id().as_str(),
            json!({"code": -32603, "message": PAGE_NOT_LOADED}),
        )
        .expect("relayed");
        Err(odin_kernel::ExecutorFault::Uncertain {
            detail: "adapter fixture reported a typed failure".to_owned(),
        })
    }
}
