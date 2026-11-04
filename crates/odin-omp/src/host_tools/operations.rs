//! Authorizes host-tool calls through the kernel operation authority.
//!
//! Every dispatch reloads the provisioned token, checks current revocations and
//! session bindings, recomputes the listing, and runs policy, approval, and resource
//! checks. The host does not mint production tokens or cache authorization results.
//! The host-only authorization probe shares dispatch's fresh, nonconsuming
//! admission prefix and stops before the plan/readiness/approval/budget gates.
//! A passed prefix is not authorization and never invokes a tool.
//!
//! Identity rules: the provisioned token authority owns token identities; the
//! kernel authority mints leases and operations. The host derives only the
//! two untrusted idempotency inputs — the per-session capsule identity and
//! per-request correlation identity — from host-owned session state. A
//! duplicated side-channel request therefore replays its recorded operation
//! instead of running a second effect, and a conflicting payload under the
//! same correlation is a hard durable conflict. The wire ceiling narrows only:
//! the in-host transport never narrows the authority-derived reservation.
//!
//! A capability invocation's logical target is its bound run, which is a
//! ledger-safe approval identity. The complete host-owned [`odin_domain::Scope`] travels
//! separately as canonical executor-binding data covered by the operation's
//! request and prepared-binding digests; it is never encoded into an ID.
//!
//! The kernel derives reservations from the invocation and contract; callers cannot lower them.

mod adapters;
mod admission;
mod authority;
mod catalog;
mod composition;
mod dispatch;
mod generation;
mod loose;
mod policy;
mod toolsets;
pub use loose::{with_ignored, IGNORED_FIELDS};
pub use toolsets::PreparedToolCall;

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};

use odin_domain::knowledge::ToolSchema;
use odin_domain::operation::Limits;
use odin_domain::{ApprovalId, CapabilityId, DomainError, EffectClass, SeatToken, SessionId};
use odin_kernel::{
    AuthorizationRejection, CapabilityContract, Clock, KernelError, OperationAuthority,
    OperationCatalog, OperationExecutor, OperationRejection, SchemaCatalog, TokenError,
};
use odin_ledger::{Ledger, LedgerError};
use serde_json::Value;
use thiserror::Error;

use crate::host_tools::executor::HostToolExecutor;

pub use adapters::{
    HostAdapterStatus, HostAdapterStatusTransport, SupervisedAdapterStatus,
    UnsupervisedAdapterStatus,
};
#[cfg(test)]
pub use authority::generate_signing_key;
pub(crate) use authority::LiveSessionBindings;
pub use authority::{wall_clock, ProvisionedFreshAuthorityProvider};
pub use catalog::{DeclaredOperationCatalog, FilesystemSchemaCatalog, StaticSchemaCatalog};
pub use generation::{
    resolve_session_generation, CompositionEquivalence, RevisionMaterial, RevisionMaterialSource,
};
pub(crate) use policy::host_tool_command_id;
pub use policy::{
    admission_digest, context_policy_digest, correlation_for, seat_operation_policy,
    session_capsule_id, SeatOperationPolicy, SeatOperationPolicyInputs, SessionOperationBinding,
    SessionOperationContext,
};

/// Typed failure of the host operation surface. Authorization and authority
/// rejections keep their typed payload; nothing settles caller-side.
#[derive(Debug, Error)]
pub enum HostToolOperationError {
    /// The named tool is not bound to an admitted capability contract.
    #[error("host tool `{name}` is not bound to an admitted capability")]
    UnknownTool { name: String },
    /// The arguments, or the handler's own readiness check of them (a private desktop,
    /// an offline host, a missing session), refused the call. `detail` is that cause.
    #[error("{detail}")]
    Arguments { detail: String },
    /// Nothing executed; an exact-scope approval request was stored and parked with its call.
    /// the owner's yes runs the call once; the seat does not repeat it.
    #[error("approval required: capability `{capability_id}` is effect class {effect_class:?} and needs the owner's yes; approval `{approval_id}` (revision {revision}) is requested and he is being asked — nothing executed; when he says yes the call runs by itself and its result comes back to you, so do not make the call again")]
    ApprovalRequired {
        capability_id: CapabilityId,
        effect_class: EffectClass,
        approval_id: ApprovalId,
        revision: i64,
    },
    /// The presented exact-scope approval expired. Nothing ran. `expired_id`
    /// is the unanswered request; `approval_id` is the fresh exact-scope one.
    #[error("approval expired: the earlier request `{expired_id}` expired unanswered; nothing executed; approval `{approval_id}` (revision {revision}) asks him again for the same call — when he says yes it runs by itself, so do not make the call again")]
    ApprovalExpired {
        capability_id: CapabilityId,
        effect_class: EffectClass,
        expired_id: ApprovalId,
        approval_id: ApprovalId,
        revision: i64,
    },
    /// The fresh authorization pipeline rejected the invocation.
    #[error("{}", rejection_text(.0))]
    Rejected(AuthorizationRejection),
    /// The adapter ran the operation and answered with a typed failure.
    #[error("{capability_id} failed: {message}")]
    AdapterFailed {
        capability_id: CapabilityId,
        code: i64,
        message: String,
    },
    /// The operation authority rejected or could not settle the operation.
    #[error("operation authority: {0}")]
    Authority(#[from] OperationRejection),
    /// The kernel policy/listing pipeline failed.
    #[error("kernel policy pipeline: {0}")]
    Kernel(#[from] KernelError),
    /// A provisioned seat-token failed cryptographic or binding verification.
    #[error("seat token verification: {0}")]
    Token(#[from] TokenError),
    /// Published/provisioned authority material is missing or unreadable.
    #[error("published operation authority unavailable: {detail}")]
    PublishedAuthorityUnavailable {
        /// Fail-closed provider detail; token/key bytes are never included.
        detail: String,
    },
    /// The durable ledger failed.
    #[error("durable ledger: {0}")]
    Ledger(#[from] LedgerError),
    /// Identity material failed its shape rules.
    #[error("invalid identity material: {0}")]
    Identity(#[from] DomainError),
    /// The correlation already settled; a replay never re-executes, and no
    /// fresh result exists to report.
    #[error("operation already settled by an earlier execution; nothing re-executed")]
    Replayed,
    /// The operation aborted durably without an effect.
    #[error("operation aborted without effect")]
    Aborted,
    /// The operation outcome is durably in doubt and blocks until reconciled
    /// from evidence.
    #[error("operation outcome is durably in doubt and blocked until reconciled")]
    InDoubt,
    /// A committed fresh execution must relay its handler result; its absence
    /// is a composition defect, never a synthesized result.
    #[error("committed operation relayed no handler result")]
    MissingResult,
    /// The assembled operation surface is self-contradictory.
    #[error("operation composition is invalid: {detail}")]
    Composition { detail: String },
    /// Parent token, plan acceptance, or delegation depth validation failed before any child effect.
    /// Do not renew or retry automatically.
    #[error("delegated session authority rejected: {detail}")]
    Delegation {
        /// Why the parent chain or child authority failed.
        detail: String,
    },
    /// The session's authority generation could not be served: the bound
    /// revision is unknown or pruned from the retained store, so no
    /// material can be recomposed. The remedy is a re-open under the
    /// current revision — never a silent move to current material.
    #[error("session authority generation unavailable: {detail}")]
    Generation {
        /// Which generation failed and why.
        detail: String,
    },
    /// One adapter's supervised status refresh failed or produced unusable
    /// data. The adapter fails closed until a later refresh proves Ready;
    /// backend payload bytes are never surfaced verbatim.
    #[error("adapter `{adapter}` status refresh failed: {detail}")]
    AdapterStatus {
        /// The adapter whose status could not be proven.
        adapter: String,
        /// Fail-closed refresh detail.
        detail: String,
    },
}

/// A refused approval names its cause; every other rejection keeps its typed form.
fn rejection_text(rejection: &AuthorizationRejection) -> String {
    match rejection {
        AuthorizationRejection::NeedsApproval {
            capability_id,
            cause: Some(cause),
            ..
        } => format!("`{capability_id}` did not run: {cause}"),
        other => format!("authorization rejected the invocation: {other:?}"),
    }
}

impl HostToolOperationError {
    /// Stable class for export. The inner host-tool variant is already flattened
    /// by the operation authority before this error exists.
    pub fn error_kind(&self) -> &'static str {
        match self {
            Self::UnknownTool { .. } => "unknown_tool",
            Self::Arguments { .. } => "arguments",
            Self::ApprovalRequired { .. } => "approval_required",
            Self::ApprovalExpired { .. } => "approval_expired",
            Self::Rejected(_) => "rejected",
            Self::AdapterFailed { .. } => "adapter_failed",
            Self::Authority(_) => "authority",
            Self::Kernel(_) => "kernel",
            Self::Token(_) => "token",
            Self::PublishedAuthorityUnavailable { .. } => "published_authority",
            Self::Ledger(_) => "ledger",
            Self::Identity(_) => "identity",
            Self::Replayed => "replayed",
            Self::Aborted => "aborted",
            Self::InDoubt => "indoubt",
            Self::MissingResult => "missing_result",
            Self::Composition { .. } => "composition",
            Self::Delegation { .. } => "delegation",
            Self::Generation { .. } => "generation",
            Self::AdapterStatus { .. } => "adapter_status",
        }
    }
}

/// The concrete seams one host operation stack runs on: the operation
/// catalog, schema catalog, executor, resource limits, trusted clock, and
/// ledger. They travel together from [`HostToolOperations::new`] into the
/// kernel operation authority.
pub struct OperationStackInputs {
    pub catalog: Arc<dyn OperationCatalog>,
    pub schemas: Arc<dyn SchemaCatalog + Send + Sync>,
    pub executor: Arc<HostToolExecutor>,
    /// The adapter executor composed behind the authority: AdapterEvidence's
    /// receipt-persisting executor over [`Self::executor`] as fallback,
    /// stamped with this host's origin. Normal outputs keep relaying through
    /// the concrete executor handle.
    pub adapter_executor: Arc<dyn OperationExecutor>,
    /// The live Ready-only adapter-health source read at both listing and
    /// authorization. Required; unknown adapters fail closed.
    pub adapter_status: Arc<dyn HostAdapterStatus>,
    pub limits: Limits,
    pub clock: Clock,
    pub ledger: Arc<Mutex<Ledger>>,
    /// The retained-publication recomposition seam: derives one revision's
    /// exact operation material on demand. The bounded per-revision memo
    /// lives on the assembled stack, never in the source.
    pub revisions: Arc<dyn RevisionMaterialSource>,
    /// Durable compiled-draft retention for the conversational workload
    /// authoring seam. `None` composes no retention: `workload.publish`
    /// then fails typed before the approval gate instead of ever
    /// re-deriving a declaration from model answers.
    pub workload_drafts: Option<Arc<crate::host_tools::WorkloadDraftStore>>,
}

/// Rewrites a dispatched tool's result: the scope, the compiled tool name, the result.
pub type ResultTransformer = Arc<
    dyn Fn(&odin_domain::Scope, &str, serde_json::Value) -> Result<serde_json::Value, String>
        + Send
        + Sync,
>;
/// Host callback invoked only after inline transport delivery succeeds.
pub type DeliveryAcknowledger = Arc<dyn Fn(&Value) -> Result<(), String> + Send + Sync>;
#[derive(Clone)]
/// Combines kernel operation authorization with the catalog, schemas, and executors.
pub struct HostToolOperations {
    authority: Arc<OperationAuthority>,
    contracts: Arc<BTreeMap<CapabilityId, CapabilityContract>>,
    tool_index: Arc<BTreeMap<String, CapabilityId>>,
    toolset_routes: Arc<BTreeMap<(String, String), String>>,
    /// Declared toolsets of the published registry; their examples show in each listing.
    toolsets: Arc<BTreeMap<String, odin_registry::schema::ToolsetToml>>,
    projection_memo: Arc<Mutex<BTreeMap<u64, Arc<toolsets::ProjectionIndex>>>>,
    contract_adapters: Arc<BTreeSet<String>>,
    schemas: Arc<dyn SchemaCatalog + Send + Sync>,
    /// Deployment constraints such as per-seat project enums, checked after the canonical schema.
    /// These do not replace fresh authorization on each dispatch.
    narrowing_schemas: Arc<BTreeMap<String, ToolSchema>>,
    executor: Arc<HostToolExecutor>,
    adapter_status: Arc<dyn HostAdapterStatus>,
    authority_provider: Arc<ProvisionedFreshAuthorityProvider>,
    revisions: Arc<dyn RevisionMaterialSource>,
    /// Durable compiled-draft retention backing the `workload.publish`
    /// pre-gate. `None` composes no retention and every `workload.publish`
    /// dispatch fails typed before the approval gate.
    workload_drafts: Option<Arc<crate::host_tools::WorkloadDraftStore>>,
    /// The owner's task grants; `None` composes none, so every
    /// owner-decided call asks the owner.
    task_grants: Option<Arc<crate::host_tools::task_grants::TaskGrantStore>>,
    /// Where gated calls wait for the owner's yes; `None` parks nothing, so his yes cannot run a call.
    approved_calls: Option<Arc<crate::host_tools::approved_calls::ApprovedCalls>>,
    /// The conversation seat's background jobs; `None` runs every call in
    /// the foreground.
    jobs: Option<Arc<crate::host_tools::jobs::JobBoard>>,
    delivery_acknowledger: Option<DeliveryAcknowledger>,
    result_transformer: Option<ResultTransformer>,
    /// Derived publication material can be safely evicted and recomposed from durable snapshots.
    material_memo: Arc<Mutex<BTreeMap<u64, Arc<RevisionMaterial>>>>,
    clock: Clock,
    ledger: Arc<Mutex<Ledger>>,
}

impl HostToolOperations {
    pub fn with_toolsets(
        mut self,
        toolsets: BTreeMap<String, odin_registry::schema::ToolsetToml>,
    ) -> Self {
        self.toolsets = Arc::new(toolsets);
        self
    }

    pub fn with_result_transformer(mut self, transformer: ResultTransformer) -> Self {
        self.result_transformer = Some(transformer);
        self
    }

    /// Registers the host callback for a successfully delivered inline result.
    pub fn with_delivery_acknowledger(mut self, acknowledge: DeliveryAcknowledger) -> Self {
        self.delivery_acknowledger = Some(acknowledge);
        self
    }

    /// Called only after the transport confirms delivery, never on result construction.
    pub fn acknowledge_delivery(&self, result: &Value) -> Result<(), String> {
        match &self.delivery_acknowledger {
            Some(acknowledge) => acknowledge(result),
            None => Ok(()),
        }
    }

    /// Delegation owns its bounded wait and eventual child report. It must
    /// not also emit a generic background-job report of the same answer.
    pub fn reports_delegated_completion(&self, tool: &str) -> bool {
        self.tool_index
            .get(tool)
            .and_then(|capability| self.contracts.get(capability))
            .is_some_and(|contract| contract.delegate_to.is_some())
    }

    /// Recomposes (or recalls from the bounded memo) the exact operation
    /// material of one retained publication revision. Unknown or pruned
    /// revisions fail typed; nothing ever substitutes current material.
    pub fn material_at(
        &self,
        revision: u64,
    ) -> Result<Arc<RevisionMaterial>, HostToolOperationError> {
        if let Ok(memo) = self.material_memo.lock() {
            if let Some(material) = memo.get(&revision) {
                return Ok(Arc::clone(material));
            }
        }
        let material = Arc::new(self.revisions.material_at(revision).map_err(|detail| {
            HostToolOperationError::Generation {
                detail: format!("revision {revision}: {detail}"),
            }
        })?);
        if let Ok(mut memo) = self.material_memo.lock() {
            if memo.len() >= generation::GENERATION_MEMO_CAP && !memo.contains_key(&revision) {
                // Evict the lowest retained revision: the oldest generation
                // is the one least likely to serve live traffic, and its
                // recomposition stays available from the durable store.
                if let Some(oldest) = memo.keys().next().copied() {
                    memo.remove(&oldest);
                }
            }
            memo.insert(revision, Arc::clone(&material));
        }
        Ok(material)
    }

    /// Whether two publication revisions compose identically: the same
    /// revision, or two retained publications with equal composition
    /// digests (a routine publication between them changes nothing
    /// composed). An unprovable digest is a different composition.
    pub(crate) fn same_composition(&self, left: u64, right: u64) -> bool {
        generation::same_composition(self.revisions.as_ref(), left, right)
    }

    /// Uses the session's served revision, not the stack's construction-time contracts.
    pub(crate) fn generation_material(
        &self,
        binding: &SessionOperationBinding,
    ) -> Result<Arc<RevisionMaterial>, HostToolOperationError> {
        self.material_at(binding.served_revision)
    }

    /// Reloads the session's provisioned token without verifying it: the
    /// session factory resolves the session's generation from the token's
    /// own signed claim before any binding exists. A read failure is the
    /// same typed unavailability the verification path reports.
    pub fn provisioned_token(
        &self,
        session: &SessionId,
    ) -> Result<SeatToken, HostToolOperationError> {
        self.authority_provider.read_token(session)
    }
}

#[cfg(test)]
#[path = "operations/tests.rs"]
mod production_operation_dispatch;
