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
mod dispatch;
mod generation;
mod policy;

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
pub use catalog::{
    AdmissionEquivalence, DeclaredOperationCatalog, FilesystemSchemaCatalog, StaticSchemaCatalog,
};
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
    /// Invocation arguments could not be shaped into authority-safe input.
    #[error("invocation arguments are not authority-safe: {detail}")]
    Arguments { detail: String },
    /// Nothing executed; an exact-scope approval request was stored.
    /// After approval, retry identical arguments with its `approvalId` for one-shot consumption.
    #[error("approval required: capability `{capability_id}` is effect class {effect_class:?} and no approval covered this call; approval `{approval_id}` (revision {revision}) is now durably requested — nothing executed; once the owner decides it, retry the identical call with approvalId `{approval_id}`")]
    ApprovalRequired {
        capability_id: CapabilityId,
        effect_class: EffectClass,
        approval_id: ApprovalId,
        revision: i64,
    },
    /// The fresh authorization pipeline rejected the invocation.
    #[error("authorization rejected the invocation: {0:?}")]
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

/// Combines kernel operation authorization with the catalog, schemas, and executors.
#[derive(Clone)]
pub struct HostToolOperations {
    authority: Arc<OperationAuthority>,
    contracts: Arc<BTreeMap<CapabilityId, CapabilityContract>>,
    tool_index: Arc<BTreeMap<String, CapabilityId>>,
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
    /// Derived publication material can be safely evicted and recomposed from durable snapshots.
    material_memo: Arc<Mutex<BTreeMap<u64, Arc<RevisionMaterial>>>>,
    clock: Clock,
    ledger: Arc<Mutex<Ledger>>,
}

impl HostToolOperations {
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
