//! Shared host-tool contracts and OMP RPC definitions.
//!
//! Mutating tools check the invocation scope before touching the ledger,
//! convert caller timestamps explicitly, and report lock poisoning as a typed error.

use std::borrow::Cow;
use std::sync::{Mutex, MutexGuard};

use odin_atlas::AtlasError;
use odin_domain::{CapabilityId, CommandId, Digest, RunId, Scope};
use odin_kernel::{ApprovalScope, PreparedEffect, Target};
use odin_ledger::{Ledger, LedgerError};
use odin_types::{CapsuleId, CorrelationId, OperationId};
use serde::Serialize;
use serde_json::Value;
use thiserror::Error;
use time::OffsetDateTime;

pub mod adapter;
pub mod approval_request;
pub mod artifact_read;
pub mod atlas_query;
mod binding;
pub mod brain;
mod catalog;
pub mod context_read;
pub mod delegation;
mod dispatch;
pub mod executor;
pub mod kube;
pub mod task_grants;
pub use kube::{KubeCapabilityBinding, KubeCapabilityOwner, LaunchableProfile};
pub mod lane_status;
pub mod operations;
pub mod workload_drafts;
pub use workload_drafts::{WorkloadDraftRecord, WorkloadDraftStore, WorkloadDraftStoreError};
pub mod plan_set;
pub mod schema_compat;
pub mod todo_update;

pub use binding::{
    BrowserCapabilityBinding, BrowserCapabilityOwner, BrowserCapabilityOwnerSlot,
    CanonicalV2CapabilityBinding, CanonicalV2CapabilityOwner,
};
use catalog::is_store_executable_form;
pub use catalog::{
    production_bindings, CompiledCapabilityBinding, CompiledHandlerBinding,
    CompiledHostToolCatalog, PRE_ADMITTED_BINDINGS,
};
pub use dispatch::{HostToolRegistry, InternalBindingKey, ModelVisibleToolConfig};

/// How the pinned OMP session presents an enabled host tool.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ToolLoadMode {
    /// Loaded into the session tool registry up front.
    Essential,
    /// Activated through tool discovery.
    Discoverable,
}

/// The exact host-tool definition shape of the pinned OMP `set_host_tools`
/// payload.
///
/// `parameters` is a JSON Schema object that must set
/// `additionalProperties: false`; actual enforcement lives in each tool's
/// strict deserialization, never in the schema alone.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RpcHostToolDefinition {
    /// Model-visible tool name, e.g. `odin_plan_set`.
    ///
    /// Compiled tools borrow their static names; declaration-derived
    /// definitions own theirs. Neither leaks a `'static` lifetime.
    pub name: Cow<'static, str>,
    /// Short human-facing label.
    pub label: Cow<'static, str>,
    /// What the tool does and what it rejects; the model reads this.
    pub description: Cow<'static, str>,
    /// Strict JSON Schema for the arguments object.
    pub parameters: Value,
    /// Whether the tool stays out of ordinary tool listings.
    pub hidden: bool,
    /// How an enabled tool is presented by the pinned OMP session.
    pub load_mode: ToolLoadMode,
}

/// The bridge supplies the scope; the model supplies only the arguments.
pub struct HostInvocation {
    /// Tools must check the required dimension here, not accept a model-named scope.
    pub scope: Scope,
    /// Raw arguments to be schema-validated by the tool.
    pub arguments: Value,
}
/// Dispatch identities and arguments recorded when the executor consumes a kernel permit.
///
/// Only the executor constructs this value. Adapters must still check durable
/// approval and operation records before performing their effects.
pub struct ConsumedHostCommand {
    command_id: CommandId,
    operation_id: OperationId,
    correlation_id: CorrelationId,
    capsule_id: CapsuleId,
    capability_id: CapabilityId,
    capability_version: u16,
    target: Target,
    arguments: Value,
    arguments_digest: Digest,
}

impl ConsumedHostCommand {
    /// Equals an approval's `consumed_by_command_id` when this dispatch consumed it.
    pub fn command_id(&self) -> &CommandId {
        &self.command_id
    }

    /// Durable settlement key of the consumed operation.
    pub fn operation_id(&self) -> &OperationId {
        &self.operation_id
    }

    pub fn correlation_id(&self) -> &CorrelationId {
        &self.correlation_id
    }

    pub fn capsule_id(&self) -> &CapsuleId {
        &self.capsule_id
    }

    pub fn capability_id(&self) -> &CapabilityId {
        &self.capability_id
    }

    pub fn capability_version(&self) -> u16 {
        self.capability_version
    }

    pub fn target(&self) -> &Target {
        &self.target
    }

    /// The complete journaled arguments, not a caller projection.
    pub fn arguments(&self) -> &Value {
        &self.arguments
    }

    /// Canonical arguments digest recorded in the permit.
    pub fn arguments_digest(&self) -> Digest {
        self.arguments_digest
    }

    /// Matches the durable approval scope consumed by this dispatch.
    pub fn approval_scope(&self) -> ApprovalScope {
        ApprovalScope {
            target_kind: self.target.kind.clone(),
            target_id: self.target.id.clone(),
            capability_id: self.capability_id.clone(),
            arguments_digest: self.arguments_digest,
        }
    }
}

#[derive(Debug, Error)]
pub enum HostToolError {
    /// The invocation scope does not satisfy the tool's required binding.
    #[error("host tool `{tool}` requires an exact scope: {reason}")]
    Scope {
        tool: &'static str,
        reason: &'static str,
    },
    /// The arguments violate the tool's schema or invariants.
    #[error("host tool `{tool}` received invalid arguments: {detail}")]
    Arguments { tool: &'static str, detail: String },
    /// The durable result could not be projected to JSON.
    #[error("host tool `{tool}` result could not be serialized: {detail}")]
    Response { tool: &'static str, detail: String },
    /// The effect landed, but a later step failed. The producer must store the
    /// receipt before returning its content digest; failed capture is `Uncertain`.
    #[error("host tool `{tool}` landed its effect but a post-effect step failed: {detail}")]
    PostEffect {
        tool: &'static str,
        detail: String,
        /// The stored content digest of the durably captured receipt.
        evidence_digest: Digest,
    },
    /// The ledger rejected the operation. `StaleActor` and state-machine
    /// rejections keep their full typed payload; nothing was written.
    #[error("host tool ledger operation failed: {0}")]
    Ledger(#[from] LedgerError),
    /// The effect's outcome is unknown; record uncertainty rather than retry blindly.
    #[error("host tool `{tool}` cannot prove its effect state: {detail}")]
    Uncertain { tool: &'static str, detail: String },
    /// The atlas rejected the fixed allowed scope while building
    /// `odin_atlas_query`; the typed atlas reason is preserved.
    #[error("host tool `odin_atlas_query` rejected the allowed atlas scope: {0}")]
    Atlas(#[from] AtlasError),
    /// Shared state is poisoned; the call made no mutation.
    #[error("host tool `{tool}` shared state is unavailable: {detail}")]
    Storage { tool: &'static str, detail: String },
    /// The backing service is unavailable and no mutation has occurred.
    #[error("host tool `{tool}` is unavailable: {reason}")]
    Unavailable { tool: &'static str, reason: String },
    /// Dispatch named a tool the registry does not hold.
    #[error("host tool `{name}` is not registered")]
    UnknownTool { name: String },
    /// Registration hit an existing name; the registry stays unchanged.
    #[error("host tool `{name}` is already registered")]
    DuplicateTool { name: String },
    /// The compiled pre-admitted catalog rejected a binding, or a capability
    /// handler could not resolve through it.
    #[error("compiled host tool catalog: {detail}")]
    Catalog { detail: String },
    /// The governed delegation surface rejected the call before any child
    /// effect: depth, scope, plan, concurrency, or provisioning bounds.
    #[error("host tool `{tool}` delegation rejected: {detail}")]
    Delegation { tool: &'static str, detail: String },
    /// Preserves typed URI errors, including stale authority and scope denial.
    /// No effect has started.
    #[error(transparent)]
    KnowledgeUri(#[from] crate::uri::UriError),
}

pub trait HostTool: Send + Sync {
    /// The static definition sent to the pinned OMP session.
    fn definition(&self) -> &RpcHostToolDefinition;

    /// Validates the invocation and performs the tool's effect synchronously.
    fn invoke(&self, invocation: HostInvocation) -> Result<Value, HostToolError>;

    /// Internal operation-authority dispatch. Ordinary tools use the public
    /// invocation shape unchanged; canonical-v2 adapters override this to
    /// consume the real operation and correlation identities from the
    /// kernel-minted permit rather than model arguments.
    fn invoke_prepared(
        &self,
        _effect: &PreparedEffect,
        invocation: HostInvocation,
    ) -> Result<Value, HostToolError> {
        self.invoke(invocation)
    }

    /// Checks execution prerequisites before journaling or requesting approval.
    /// This must be read-only, including external readiness checks. Execution
    /// must repeat the checks because state can change after preflight.
    fn preflight(
        &self,
        contract: &odin_kernel::CapabilityContract,
        scope: &Scope,
        arguments: &Value,
    ) -> Result<(), HostToolError>;

    /// Supplies executor-recorded identities to adapters that check durable approvals.
    /// Other tools forward to [`HostTool::invoke_prepared`].
    fn invoke_consumed(
        &self,
        effect: &PreparedEffect,
        _consumed: &ConsumedHostCommand,
        invocation: HostInvocation,
    ) -> Result<Value, HostToolError> {
        self.invoke_prepared(effect, invocation)
    }

    /// Supplies the bridge execution binding stored with the permit, including on replay.
    /// Knowledge tools require a valid session/run/lane/epoch before materialization;
    /// other tools forward to [`HostTool::invoke_consumed`].
    fn invoke_execution(
        &self,
        effect: &PreparedEffect,
        consumed: &ConsumedHostCommand,
        invocation: HostInvocation,
        _execution: Option<&crate::uri::ExecutionBinding>,
    ) -> Result<Value, HostToolError> {
        self.invoke_consumed(effect, consumed, invocation)
    }

    /// Lets tool listings report the same execution-binding requirement as dispatch.
    fn requires_execution_proof(&self) -> bool {
        false
    }
}

pub fn require_run_scope<'scope>(
    tool: &'static str,
    scope: &'scope Scope,
) -> Result<&'scope RunId, HostToolError> {
    scope.run.as_ref().ok_or_else(|| HostToolError::Scope {
        tool,
        reason: "the invocation scope is not bound to a run",
    })
}

/// Converts an explicit caller Unix-millisecond timestamp to the ledger's
/// timestamp form. There is no ambient clock: the caller names the instant.
pub fn parse_unix_milliseconds(
    tool: &'static str,
    milliseconds: i64,
) -> Result<OffsetDateTime, HostToolError> {
    // Whole seconds plus a sub-second remainder; euclidean division keeps
    // pre-epoch instants exact.
    let seconds = milliseconds.div_euclid(1_000);
    let nanosecond_remainder = milliseconds.rem_euclid(1_000) as u32 * 1_000_000;
    let moment =
        OffsetDateTime::from_unix_timestamp(seconds).map_err(|error| HostToolError::Arguments {
            tool,
            detail: format!("timestamp {milliseconds}ms is not a representable instant: {error}"),
        })?;
    moment
        .replace_nanosecond(nanosecond_remainder)
        .map_err(|error| HostToolError::Arguments {
            tool,
            detail: format!("timestamp {milliseconds}ms is not a representable instant: {error}"),
        })
}

/// Locks the shared ledger, mapping mutex poisoning to a typed storage error.
pub fn lock_ledger<'ledger>(
    tool: &'static str,
    ledger: &'ledger Mutex<Ledger>,
) -> Result<MutexGuard<'ledger, Ledger>, HostToolError> {
    ledger.lock().map_err(|poisoned| HostToolError::Storage {
        tool,
        detail: format!("ledger mutex poisoned: {poisoned}"),
    })
}

pub fn response<T: Serialize>(tool: &'static str, value: &T) -> Result<Value, HostToolError> {
    serde_json::to_value(value).map_err(|error| HostToolError::Response {
        tool,
        detail: format!("durable aggregate rejected serialization: {error}"),
    })
}

/// Scope dimensions an approval target or artifact reference may name.
pub(crate) const SCOPE_DIMENSIONS: [&str; 7] = [
    "seat", "project", "lane", "run", "attempt", "session", "node",
];

/// The value `kind` binds, or `None` when it is not a scope dimension or is unbound.
pub(crate) fn bound_scope_dimension<'a>(scope: &'a Scope, kind: &str) -> Option<&'a str> {
    match kind {
        "seat" => scope.seat.as_ref().map(|id| id.as_str()),
        "project" => scope.project.as_ref().map(|id| id.as_str()),
        "lane" => scope.lane.as_ref().map(|id| id.as_str()),
        "run" => scope.run.as_ref().map(|id| id.as_str()),
        "attempt" => scope.attempt.as_ref().map(|id| id.as_str()),
        "session" => scope.session.as_ref().map(|id| id.as_str()),
        "node" => scope.node.as_ref().map(|id| id.as_str()),
        _ => None,
    }
}

/// Evidence extractors wrap the parsed schema as `{output}`; other bindings list it directly.
pub(crate) fn hidden_essential_definition(
    name: &'static str,
    label: &'static str,
    description: &'static str,
    schema_json: &str,
    evidence: bool,
) -> Result<RpcHostToolDefinition, HostToolError> {
    let schema: Value =
        serde_json::from_str(schema_json).map_err(|error| HostToolError::Catalog {
            detail: format!("{name} schema is invalid: {error}"),
        })?;
    let parameters = if evidence {
        serde_json::json!({
            "type": "object",
            "additionalProperties": false,
            "properties": { "output": schema },
            "required": ["output"]
        })
    } else {
        schema
    };
    Ok(RpcHostToolDefinition {
        name: Cow::Borrowed(name),
        label: Cow::Borrowed(label),
        description: Cow::Borrowed(description),
        parameters,
        hidden: true,
        load_mode: ToolLoadMode::Essential,
    })
}

/// Shared fixtures for host-tool tests whose durable aggregates hang off the
/// lane/run foreign keys.
#[cfg(test)]
pub(crate) mod fixtures {
    use std::sync::Mutex;

    use odin_domain::{LaneId, RunId, SeatId};
    use odin_ledger::lane_run::{self, NewLane, NewRun};
    use odin_ledger::Ledger;
    use time::OffsetDateTime;

    /// Deterministic creation instant shared by the seeded lane and run.
    const SEEDED_UNIX_SECONDS: i64 = 1_700_000_000;

    /// Creates the lane and run needed to satisfy plan-row foreign keys.
    pub(crate) fn seed_local_omp_run(ledger: &Mutex<Ledger>, run_id: &RunId) {
        let created_at =
            OffsetDateTime::from_unix_timestamp(SEEDED_UNIX_SECONDS).expect("seed instant");
        let lane_id: LaneId = run_id
            .as_str()
            .replacen("run:", "lane:", 1)
            .parse()
            .expect("seeded lane id");
        let seat_id: SeatId = run_id
            .as_str()
            .replacen("run:", "seat:", 1)
            .parse()
            .expect("seeded seat id");
        let guard = ledger.lock().expect("ledger lock");
        lane_run::create_lane(
            guard.connection(),
            &NewLane {
                lane_id: lane_id.clone(),
                seat_id,
                project_id: None,
                template_id: "template:dev".to_owned(),
                backend: "local_omp".to_owned(),
                created_by: "operator".to_owned(),
                created_at,
                retained: false,
            },
        )
        .expect("seeded lane");
        lane_run::create_run(
            guard.connection(),
            &NewRun {
                run_id: run_id.clone(),
                lane_id,
                attempt_number: 1,
                workflow_id: None,
                workflow_version: None,
                input_hash: "seed-input-hash".to_owned(),
                accepted_capability_revision: None,
                lease_id: None,
                absolute_deadline: None,
                retry_budget: 0,
                created_at,
            },
        )
        .expect("seeded run");
    }

    pub(crate) fn fixture_contract() -> odin_kernel::CapabilityContract {
        use std::collections::BTreeSet;
        use std::num::NonZeroU32;
        odin_kernel::CapabilityContract {
            id: odin_domain::CapabilityId::new("fixture.preflight").expect("capability id"),
            delegate_to: None,
            version: 1,
            tool_name: odin_domain::knowledge::ToolName::new("fixture_preflight")
                .expect("tool name"),
            description: "preflight fixture".to_owned(),
            handler: odin_kernel::HandlerBinding::Builtin {
                name: "fixture.handler".to_owned(),
            },
            input_schema_ref: "fixture.input".to_owned(),
            output_schema_ref: "fixture.output".to_owned(),
            effect_class: odin_domain::EffectClass::R1,
            seat_tags: BTreeSet::new(),
            timeout_seconds: NonZeroU32::new(30).expect("timeout"),
            idempotency: odin_kernel::IdempotencyPolicy::Required,
            retry: odin_kernel::RetryPolicy { max_attempts: 1 },
            approval: odin_kernel::ApprovalRequirement::None,
            evidence_extractor: odin_kernel::HandlerBinding::Builtin {
                name: "fixture.extract".to_owned(),
            },
            adapter: None,
            preview: None,
            batchable: false,
            batch: None,
        }
    }
}

#[cfg(test)]
mod tests;
