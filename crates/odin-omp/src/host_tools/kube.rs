//! Compiled kube workload, snapshot, and health handler/extractor bindings.
//!
//! The shape mirrors [`crate::host_tools::BrowserCapabilityBinding`]:
//! every binding is a compiled, globally pre-admitted identity. Model-visible
//! invocation is never raw: a bare [`HostTool::invoke`] fails closed, and the
//! only production route is the kernel-minted [`PreparedEffect`] permit —
//! which carries the exact admitted operation, its R3 approval settlement,
//! and the host-owned dispatch scope — decoded by the executor before this
//! adapter forwards to the concrete [`KubeCapabilityOwner`].
//!
//! Effect classes follow the contract: `create`, `pause`, `resume`,
//! `restart`, and `cancel` are R3 mutations requiring operator approval;
//! `summarize`, `snapshot.read`, and `health.read` are R0 pure reads.
//! Evidence extractor bindings consume the validated handler output
//! (`{"output": ...}`) and never re-execute the underlying capability.

use odin_domain::Scope;
use odin_kernel::PreparedEffect;
use odin_types::OperationId;
use serde_json::Value;
use std::sync::{Arc, RwLock};

use crate::host_tools::{HostInvocation, HostTool, HostToolError, RpcHostToolDefinition};

/// The sixteen compiled kube handler/extractor bindings.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KubeCapabilityBinding {
    WorkloadCreate,
    WorkloadCreateEvidence,
    WorkloadPause,
    WorkloadPauseEvidence,
    WorkloadResume,
    WorkloadResumeEvidence,
    WorkloadRestart,
    WorkloadRestartEvidence,
    WorkloadCancel,
    WorkloadCancelEvidence,
    WorkloadSummarize,
    WorkloadSummarizeEvidence,
    SnapshotRead,
    SnapshotReadEvidence,
    HealthRead,
    HealthReadEvidence,
}

impl KubeCapabilityBinding {
    /// Every compiled binding, in handler/evidence pair order.
    pub const ALL: [Self; 16] = [
        Self::WorkloadCreate,
        Self::WorkloadCreateEvidence,
        Self::WorkloadPause,
        Self::WorkloadPauseEvidence,
        Self::WorkloadResume,
        Self::WorkloadResumeEvidence,
        Self::WorkloadRestart,
        Self::WorkloadRestartEvidence,
        Self::WorkloadCancel,
        Self::WorkloadCancelEvidence,
        Self::WorkloadSummarize,
        Self::WorkloadSummarizeEvidence,
        Self::SnapshotRead,
        Self::SnapshotReadEvidence,
        Self::HealthRead,
        Self::HealthReadEvidence,
    ];

    /// The exact compiled builtin handler id (`binding_id = handler`).
    pub const fn id(self) -> &'static str {
        match self {
            Self::WorkloadCreate => "odin_kube.workload.create",
            Self::WorkloadCreateEvidence => "odin_kube.workload.create_evidence",
            Self::WorkloadPause => "odin_kube.workload.pause",
            Self::WorkloadPauseEvidence => "odin_kube.workload.pause_evidence",
            Self::WorkloadResume => "odin_kube.workload.resume",
            Self::WorkloadResumeEvidence => "odin_kube.workload.resume_evidence",
            Self::WorkloadRestart => "odin_kube.workload.restart",
            Self::WorkloadRestartEvidence => "odin_kube.workload.restart_evidence",
            Self::WorkloadCancel => "odin_kube.workload.cancel",
            Self::WorkloadCancelEvidence => "odin_kube.workload.cancel_evidence",
            Self::WorkloadSummarize => "odin_kube.workload.summarize",
            Self::WorkloadSummarizeEvidence => "odin_kube.workload.summarize_evidence",
            Self::SnapshotRead => "odin_kube.snapshot.read",
            Self::SnapshotReadEvidence => "odin_kube.snapshot.read_evidence",
            Self::HealthRead => "odin_kube.health.read",
            Self::HealthReadEvidence => "odin_kube.health.read_evidence",
        }
    }

    /// The fixed kernel capability id the binding resolves against.
    pub const fn capability_id(self) -> &'static str {
        match self {
            Self::WorkloadCreate | Self::WorkloadCreateEvidence => "kube.workload.create",
            Self::WorkloadPause | Self::WorkloadPauseEvidence => "kube.workload.pause",
            Self::WorkloadResume | Self::WorkloadResumeEvidence => "kube.workload.resume",
            Self::WorkloadRestart | Self::WorkloadRestartEvidence => "kube.workload.restart",
            Self::WorkloadCancel | Self::WorkloadCancelEvidence => "kube.workload.cancel",
            Self::WorkloadSummarize | Self::WorkloadSummarizeEvidence => "kube.workload.summarize",
            Self::SnapshotRead | Self::SnapshotReadEvidence => "kube.snapshot.read",
            Self::HealthRead | Self::HealthReadEvidence => "kube.health.read",
        }
    }

    /// The exact model-visible listed tool name the kernel listing derives
    /// from the capability id (dots become underscores). The listed wrapper
    /// must register under this name or the effective listing can never
    /// admit the capability for a seat.
    pub const fn listed_name(self) -> &'static str {
        match self {
            Self::WorkloadCreate | Self::WorkloadCreateEvidence => "kube_workload_create",
            Self::WorkloadPause | Self::WorkloadPauseEvidence => "kube_workload_pause",
            Self::WorkloadResume | Self::WorkloadResumeEvidence => "kube_workload_resume",
            Self::WorkloadRestart | Self::WorkloadRestartEvidence => "kube_workload_restart",
            Self::WorkloadCancel | Self::WorkloadCancelEvidence => "kube_workload_cancel",
            Self::WorkloadSummarize | Self::WorkloadSummarizeEvidence => "kube_workload_summarize",
            Self::SnapshotRead | Self::SnapshotReadEvidence => "kube_snapshot_read",
            Self::HealthRead | Self::HealthReadEvidence => "kube_health_read",
        }
    }

    pub const fn is_evidence_extractor(self) -> bool {
        matches!(
            self,
            Self::WorkloadCreateEvidence
                | Self::WorkloadPauseEvidence
                | Self::WorkloadResumeEvidence
                | Self::WorkloadRestartEvidence
                | Self::WorkloadCancelEvidence
                | Self::WorkloadSummarizeEvidence
                | Self::SnapshotReadEvidence
                | Self::HealthReadEvidence
        )
    }

    const fn label(self) -> &'static str {
        match self {
            Self::WorkloadCreate => "Kube Workload Create",
            Self::WorkloadCreateEvidence => "Kube Workload Create Evidence",
            Self::WorkloadPause => "Kube Workload Pause",
            Self::WorkloadPauseEvidence => "Kube Workload Pause Evidence",
            Self::WorkloadResume => "Kube Workload Resume",
            Self::WorkloadResumeEvidence => "Kube Workload Resume Evidence",
            Self::WorkloadRestart => "Kube Workload Restart",
            Self::WorkloadRestartEvidence => "Kube Workload Restart Evidence",
            Self::WorkloadCancel => "Kube Workload Cancel",
            Self::WorkloadCancelEvidence => "Kube Workload Cancel Evidence",
            Self::WorkloadSummarize => "Kube Workload Summarize",
            Self::WorkloadSummarizeEvidence => "Kube Workload Summarize Evidence",
            Self::SnapshotRead => "Kube Snapshot Read",
            Self::SnapshotReadEvidence => "Kube Snapshot Read Evidence",
            Self::HealthRead => "Kube Health Read",
            Self::HealthReadEvidence => "Kube Health Read Evidence",
        }
    }

    const fn description(self) -> &'static str {
        match self {
            Self::WorkloadCreate => {
                "Launch one pod from a published profile. Optional targetNode narrows initial placement to a node in the pinned declared allowed_nodes, intersecting unchanged profile labels and live placement checks; arbitrary selectors are forbidden. For an agent pod it must equal the resolved serving/session node. Omit it for normal placement. This initial choice does not pin the profile or constrain later restart rehome, which uses its own targetNode. A script pod may take inputs: artifact ids (blake3:…) shared with you, which it reads in order at /var/run/odin/staging/input-0, input-1, …"
            }
            Self::WorkloadCreateEvidence => {
                "Extract validated evidence from one workload creation."
            }
            Self::WorkloadPause => {
                "Pause one of your running pods — a finite job or a long-lived service — until resumed; with checkpoint: true its state is also captured as a checkpoint artifact. runId and expectedResourceVersion are that pod's row in kube_workload_summarize (find it by its profile)."
            }
            Self::WorkloadPauseEvidence => {
                "Extract validated evidence from one workload suspension."
            }
            Self::WorkloadResume => {
                "Resume one of your paused pods (job or service). runId and expectedResourceVersion are its row in kube_workload_summarize."
            }
            Self::WorkloadResumeEvidence => {
                "Extract validated evidence from one workload resumption."
            }
            Self::WorkloadRestart => {
                "Restart one of your pods (job or service) from its published profile; with targetNode, rehome it onto that node (its state is checkpointed and carried). runId and expectedResourceVersion are its row in kube_workload_summarize."
            }
            Self::WorkloadRestartEvidence => {
                "Extract validated evidence from one workload restart."
            }
            Self::WorkloadCancel => {
                "Stop one of your pods for good (job or service). runId and expectedResourceVersion are its row in kube_workload_summarize."
            }
            Self::WorkloadCancelEvidence => {
                "Extract validated evidence from one workload cancellation."
            }
            Self::WorkloadSummarize => {
                "List your pods and your project's (or one by runId): each row names its profile, node, state, runId and resourceVersion — the runId and resourceVersion the pause, resume, restart and stop tools take — and a running pod's status: its newest reported values against the previous ones (how a simulation is converging), so you never need its log."
            }
            Self::WorkloadSummarizeEvidence => {
                "Extract validated evidence from one workload summary."
            }
            Self::SnapshotRead => "Read one workload snapshot observation from the bound cluster.",
            Self::SnapshotReadEvidence => "Extract validated evidence from one snapshot read.",
            Self::HealthRead => {
                "Read one bounded cluster health observation from the bound cluster."
            }
            Self::HealthReadEvidence => "Extract validated evidence from one cluster health read.",
        }
    }

    const fn schema(self) -> &'static str {
        match self {
            Self::WorkloadCreate => {
                include_str!("../../../../schemas/capability/kube.workload.create.input.json")
            }
            Self::WorkloadCreateEvidence => {
                include_str!("../../../../schemas/capability/kube.workload.create.output.json")
            }
            Self::WorkloadPause => {
                include_str!("../../../../schemas/capability/kube.workload.pause.input.json")
            }
            Self::WorkloadPauseEvidence => {
                include_str!("../../../../schemas/capability/kube.workload.pause.output.json")
            }
            Self::WorkloadResume => {
                include_str!("../../../../schemas/capability/kube.workload.resume.input.json")
            }
            Self::WorkloadResumeEvidence => {
                include_str!("../../../../schemas/capability/kube.workload.resume.output.json")
            }
            Self::WorkloadRestart => {
                include_str!("../../../../schemas/capability/kube.workload.restart.input.json")
            }
            Self::WorkloadRestartEvidence => {
                include_str!("../../../../schemas/capability/kube.workload.restart.output.json")
            }
            Self::WorkloadCancel => {
                include_str!("../../../../schemas/capability/kube.workload.cancel.input.json")
            }
            Self::WorkloadCancelEvidence => {
                include_str!("../../../../schemas/capability/kube.workload.cancel.output.json")
            }
            Self::WorkloadSummarize => {
                include_str!("../../../../schemas/capability/kube.workload.summarize.input.json")
            }
            Self::WorkloadSummarizeEvidence => {
                include_str!("../../../../schemas/capability/kube.workload.summarize.output.json")
            }
            Self::SnapshotRead => {
                include_str!("../../../../schemas/capability/kube.snapshot.read.input.json")
            }
            Self::SnapshotReadEvidence => {
                include_str!("../../../../schemas/capability/kube.snapshot.read.output.json")
            }
            Self::HealthRead => {
                include_str!("../../../../schemas/capability/kube.health.read.input.json")
            }
            Self::HealthReadEvidence => {
                include_str!("../../../../schemas/capability/kube.health.read.output.json")
            }
        }
    }
}

/// One published profile a seat may launch through `kube_workload_create`,
/// as the model-visible route lists it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LaunchableProfile {
    pub id: String,
    pub description: String,
    pub gpu_count: u32,
    /// Seats the profile is offered to; empty offers it to every seat.
    pub seats: Vec<String>,
}

/// Keeps the kube runtime independent of this crate. Implementations must preserve
/// the executor-supplied scope and kernel authorization, not accept model-named authority.
pub trait KubeCapabilityOwner: Send + Sync {
    /// The published profiles `kube_workload_create` can launch, listed on
    /// the model-visible route so a seat can choose one. Admission at
    /// invocation stays the sole authority; an owner without a pinned
    /// snapshot lists none.
    fn launchable_profiles(&self) -> Vec<LaunchableProfile> {
        Vec::new()
    }

    /// Executes one compiled kube binding. `operation_id` is the kernel
    /// operation journal identity decoded from the minted permit — the sole
    /// durable settlement key, never taken from model arguments. Handler
    /// bindings settle idempotently under it; evidence bindings must
    /// reconcile the executor-supplied `{"output": ...}` against the
    /// recorded settlement for this exact operation id and fail closed
    /// rather than echo unverified bytes. `timeout_seconds` is the
    /// published capability actuation bound carried by the permit's
    /// contract: the actuation window the owner derives must never exceed
    /// it, and an owner whose configured bounds cannot fit inside refuses
    /// typed rather than being clipped by the outer declaration.
    fn invoke_kube_capability(
        &self,
        binding: KubeCapabilityBinding,
        timeout_seconds: u32,
        operation_id: OperationId,
        invocation: HostInvocation,
    ) -> Result<Value, HostToolError>;

    /// Read-only prerequisite checks before approval; errors refuse dispatch.
    fn preflight_kube_capability(
        &self,
        contract: &odin_kernel::CapabilityContract,
        _binding: KubeCapabilityBinding,
        _scope: &Scope,
        _arguments: &Value,
    ) -> Result<(), HostToolError>;
}

/// Single-assignment construction-order bridge for the real kube owner.
///
/// The production factory binds the concrete coordinator exactly once before
/// listener startup; invocation and production-composition checks fail closed
/// while unbound. There is no rebinding and no in-memory fallback owner.
/// Composition-time failures (double bind) are [`HostToolError::Catalog`];
/// invocation-time failures are typed [`HostToolError::Unavailable`] — the
/// provably pre-effect class, since an unbound or poisoned slot can never
/// have dispatched an effect.
#[derive(Default)]
pub struct KubeCapabilityOwnerSlot {
    owner: RwLock<Option<Arc<dyn KubeCapabilityOwner>>>,
}

impl KubeCapabilityOwnerSlot {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn bind(&self, owner: Arc<dyn KubeCapabilityOwner>) -> Result<(), HostToolError> {
        let mut binding = self.owner.write().map_err(|_| HostToolError::Catalog {
            detail: "kube capability owner slot is poisoned".to_owned(),
        })?;
        if binding.is_some() {
            return Err(HostToolError::Catalog {
                detail: "kube capability owner is already bound".to_owned(),
            });
        }
        *binding = Some(owner);
        Ok(())
    }

    fn owner(
        &self,
        binding: KubeCapabilityBinding,
    ) -> Result<Arc<dyn KubeCapabilityOwner>, HostToolError> {
        self.owner
            .read()
            .map_err(|_| HostToolError::Unavailable {
                tool: binding.id(),
                reason: "kube capability owner slot is poisoned".to_owned(),
            })?
            .clone()
            .ok_or_else(|| HostToolError::Unavailable {
                tool: binding.id(),
                reason: "kube capability owner is not bound".to_owned(),
            })
    }
}

impl KubeCapabilityOwner for KubeCapabilityOwnerSlot {
    fn launchable_profiles(&self) -> Vec<LaunchableProfile> {
        self.owner(KubeCapabilityBinding::WorkloadCreate)
            .map(|owner| owner.launchable_profiles())
            .unwrap_or_default()
    }

    fn invoke_kube_capability(
        &self,
        binding: KubeCapabilityBinding,
        timeout_seconds: u32,
        operation_id: OperationId,
        invocation: HostInvocation,
    ) -> Result<Value, HostToolError> {
        self.owner(binding)?.invoke_kube_capability(
            binding,
            timeout_seconds,
            operation_id,
            invocation,
        )
    }

    fn preflight_kube_capability(
        &self,
        contract: &odin_kernel::CapabilityContract,
        binding: KubeCapabilityBinding,
        scope: &Scope,
        arguments: &Value,
    ) -> Result<(), HostToolError> {
        // An unconfigured owner is unavailable before dispatch.
        self.owner(binding)?
            .preflight_kube_capability(contract, binding, scope, arguments)
    }
}

/// Internal compiled adapter for one kube handler or evidence extractor.
pub(crate) struct KubeCapabilityTool {
    binding: KubeCapabilityBinding,
    owner: Arc<dyn KubeCapabilityOwner>,
    definition: RpcHostToolDefinition,
}

impl KubeCapabilityTool {
    pub(super) fn new(
        binding: KubeCapabilityBinding,
        owner: Arc<dyn KubeCapabilityOwner>,
    ) -> Result<Self, HostToolError> {
        Ok(Self {
            binding,
            owner,
            definition: super::hidden_essential_definition(
                binding.id(),
                binding.label(),
                binding.description(),
                binding.schema(),
                binding.is_evidence_extractor(),
            )?,
        })
    }
}

impl HostTool for KubeCapabilityTool {
    fn definition(&self) -> &RpcHostToolDefinition {
        &self.definition
    }

    fn invoke(&self, _invocation: HostInvocation) -> Result<Value, HostToolError> {
        Err(HostToolError::Catalog {
            detail: format!(
                "{} requires a kernel-minted prepared operation",
                self.binding.id()
            ),
        })
    }

    fn invoke_prepared(
        &self,
        effect: &PreparedEffect,
        invocation: HostInvocation,
    ) -> Result<Value, HostToolError> {
        if effect.contract().id.as_str() != self.binding.capability_id() {
            return Err(HostToolError::Catalog {
                detail: format!(
                    "prepared operation {} binds {}, not {}",
                    effect.operation_id(),
                    effect.contract().id,
                    self.binding.capability_id()
                ),
            });
        }
        self.owner.invoke_kube_capability(
            self.binding,
            effect.contract().timeout_seconds.get(),
            effect.operation_id().clone(),
            invocation,
        )
    }

    fn preflight(
        &self,
        contract: &odin_kernel::CapabilityContract,
        scope: &Scope,
        arguments: &Value,
    ) -> Result<(), HostToolError> {
        self.owner
            .preflight_kube_capability(contract, self.binding, scope, arguments)
    }
}

/// Listed model-facing wrapper over one kube internal adapter.
///
/// A bare `invoke` fails closed: reaching the real cluster always requires
/// the kernel-minted prepared operation produced by HostToolOperations —
/// fresh seat authority, effective listing, plan gate, and for the R3
/// mutations the operator approval settlement. The wrapper only carries the
/// model-visible definition; the executor reaches the inner adapter through
/// the permit, never through this name.
pub(crate) struct KubeListedTool {
    pub(crate) inner: Arc<KubeCapabilityTool>,
    pub(crate) definition: RpcHostToolDefinition,
}

impl HostTool for KubeListedTool {
    fn definition(&self) -> &RpcHostToolDefinition {
        &self.definition
    }

    fn invoke(&self, _invocation: HostInvocation) -> Result<Value, HostToolError> {
        Err(HostToolError::Catalog {
            detail: format!(
                "{} must be dispatched through the operation authority",
                self.definition.name
            ),
        })
    }

    fn invoke_prepared(
        &self,
        effect: &PreparedEffect,
        invocation: HostInvocation,
    ) -> Result<Value, HostToolError> {
        self.inner.invoke_prepared(effect, invocation)
    }

    fn preflight(
        &self,
        contract: &odin_kernel::CapabilityContract,
        scope: &Scope,
        arguments: &Value,
    ) -> Result<(), HostToolError> {
        self.inner.preflight(contract, scope, arguments)
    }
}

/// Lists the launchable profiles on the create route's `profile` parameter:
/// without them a seat has no governed way to learn which workloads exist.
pub(super) fn annotate_launchable_profiles(
    definition: &mut super::RpcHostToolDefinition,
    profiles: &[LaunchableProfile],
) {
    if profiles.is_empty() {
        return;
    }
    let listed = profiles
        .iter()
        .map(|profile| {
            let mut entry = format!("`{}`: {}", profile.id, profile.description);
            if profile.gpu_count > 0 {
                entry.push_str(&format!(" [{} GPU]", profile.gpu_count));
            }
            if !profile.seats.is_empty() {
                entry.push_str(&format!(" (seats: {})", profile.seats.join(", ")));
            }
            entry
        })
        .collect::<Vec<_>>()
        .join("; ");
    if let Some(profile) = definition
        .parameters
        .pointer_mut("/properties/profile")
        .and_then(Value::as_object_mut)
    {
        profile.insert(
            "description".to_owned(),
            Value::String(format!(
                "Published profile id. Launchable profiles: {listed}."
            )),
        );
    }
    definition.description = std::borrow::Cow::Owned(format!(
        "{} Choose one of the launchable profiles listed on `profile`.",
        definition.description
    ));
}
