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
//! `restart`, `cancel` and `queue` (whose drop removes held launches) are R3 mutations (their cards decide them by declaration);
//! `summarize`, `snapshot.read`, and `health.read` are R0 pure reads.
//! Evidence extractor bindings consume the validated handler output
//! (`{"output": ...}`) and never re-execute the underlying capability.

use odin_domain::Scope;
use odin_kernel::PreparedEffect;
use odin_types::OperationId;
use serde_json::Value;
use std::sync::{Arc, RwLock};

use crate::host_tools::{HostInvocation, HostTool, HostToolError, RpcHostToolDefinition};

/// The compiled kube handler/extractor bindings.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KubeCapabilityBinding {
    WorkloadCreate,
    WorkloadCreateEvidence,
    WorkloadCreateMany,
    WorkloadCreateManyEvidence,
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
    WorkloadSteer,
    WorkloadSteerEvidence,
    WorkloadQueue,
    WorkloadQueueEvidence,
    WorkloadQueueDrop,
    WorkloadQueueDropEvidence,
    SnapshotRead,
    SnapshotReadEvidence,
    HealthRead,
    HealthReadEvidence,
}

impl KubeCapabilityBinding {
    /// Every compiled binding, in handler/evidence pair order.
    pub const ALL: [Self; 24] = [
        Self::WorkloadCreate,
        Self::WorkloadCreateEvidence,
        Self::WorkloadCreateMany,
        Self::WorkloadCreateManyEvidence,
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
        Self::WorkloadSteer,
        Self::WorkloadSteerEvidence,
        Self::WorkloadQueue,
        Self::WorkloadQueueEvidence,
        Self::WorkloadQueueDrop,
        Self::WorkloadQueueDropEvidence,
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
            Self::WorkloadCreateMany => "odin_kube.workload.create_many",
            Self::WorkloadCreateManyEvidence => "odin_kube.workload.create_many_evidence",
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
            Self::WorkloadSteer => "odin_kube.workload.steer",
            Self::WorkloadSteerEvidence => "odin_kube.workload.steer_evidence",
            Self::WorkloadQueue => "odin_kube.workload.queue",
            Self::WorkloadQueueEvidence => "odin_kube.workload.queue_evidence",
            Self::WorkloadQueueDrop => "odin_kube.workload.queue_drop",
            Self::WorkloadQueueDropEvidence => "odin_kube.workload.queue_drop_evidence",
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
            Self::WorkloadCreateMany | Self::WorkloadCreateManyEvidence => {
                "kube.workload.create_many"
            }
            Self::WorkloadPause | Self::WorkloadPauseEvidence => "kube.workload.pause",
            Self::WorkloadResume | Self::WorkloadResumeEvidence => "kube.workload.resume",
            Self::WorkloadRestart | Self::WorkloadRestartEvidence => "kube.workload.restart",
            Self::WorkloadCancel | Self::WorkloadCancelEvidence => "kube.workload.cancel",
            Self::WorkloadSummarize | Self::WorkloadSummarizeEvidence => "kube.workload.summarize",
            Self::WorkloadSteer | Self::WorkloadSteerEvidence => "kube.workload.steer",
            Self::WorkloadQueue | Self::WorkloadQueueEvidence => "kube.workload.queue",
            Self::WorkloadQueueDrop | Self::WorkloadQueueDropEvidence => "kube.workload.queue_drop",
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
            Self::WorkloadCreateMany | Self::WorkloadCreateManyEvidence => {
                "kube_workload_create_many"
            }
            Self::WorkloadPause | Self::WorkloadPauseEvidence => "kube_workload_pause",
            Self::WorkloadResume | Self::WorkloadResumeEvidence => "kube_workload_resume",
            Self::WorkloadRestart | Self::WorkloadRestartEvidence => "kube_workload_restart",
            Self::WorkloadCancel | Self::WorkloadCancelEvidence => "kube_workload_cancel",
            Self::WorkloadSummarize | Self::WorkloadSummarizeEvidence => "kube_workload_summarize",
            Self::WorkloadSteer | Self::WorkloadSteerEvidence => "kube_workload_steer",
            Self::WorkloadQueue | Self::WorkloadQueueEvidence => "kube_workload_queue",
            Self::WorkloadQueueDrop | Self::WorkloadQueueDropEvidence => "kube_workload_queue_drop",
            Self::SnapshotRead | Self::SnapshotReadEvidence => "kube_snapshot_read",
            Self::HealthRead | Self::HealthReadEvidence => "kube_health_read",
        }
    }

    pub const fn is_evidence_extractor(self) -> bool {
        matches!(
            self,
            Self::WorkloadCreateEvidence
                | Self::WorkloadCreateManyEvidence
                | Self::WorkloadPauseEvidence
                | Self::WorkloadResumeEvidence
                | Self::WorkloadRestartEvidence
                | Self::WorkloadCancelEvidence
                | Self::WorkloadSummarizeEvidence
                | Self::WorkloadSteerEvidence
                | Self::WorkloadQueueEvidence
                | Self::WorkloadQueueDropEvidence
                | Self::SnapshotReadEvidence
                | Self::HealthReadEvidence
        )
    }

    const fn label(self) -> &'static str {
        match self {
            Self::WorkloadCreate => "Kube Workload Create",
            Self::WorkloadCreateEvidence => "Kube Workload Create Evidence",
            Self::WorkloadCreateMany => "Kube Workload Create Many",
            Self::WorkloadCreateManyEvidence => "Kube Workload Create Many Evidence",
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
            Self::WorkloadSteer => "Kube Workload Steer",
            Self::WorkloadSteerEvidence => "Kube Workload Steer Evidence",
            Self::WorkloadQueue => "Kube Workload Queue",
            Self::WorkloadQueueEvidence => "Kube Workload Queue Evidence",
            Self::WorkloadQueueDrop => "Kube Workload Queue Drop",
            Self::WorkloadQueueDropEvidence => "Kube Workload Queue Drop Evidence",
            Self::SnapshotRead => "Kube Snapshot Read",
            Self::SnapshotReadEvidence => "Kube Snapshot Read Evidence",
            Self::HealthRead => "Kube Health Read",
            Self::HealthReadEvidence => "Kube Health Read Evidence",
        }
    }

    const fn description(self) -> &'static str {
        match self {
            Self::WorkloadCreate => {
                "Launch one pod from a published profile. Optional targetNode narrows initial placement to a node in the pinned declared allowed_nodes, intersecting unchanged profile labels and live placement checks; arbitrary selectors are forbidden. For an agent pod it must equal the resolved serving/session node. Omit it for normal placement. This initial choice does not pin the profile or constrain later restart rehome, which uses its own targetNode. A script pod may take inputs: artifact ids (blake3:…) shared with you, which it reads in order at /var/run/odin/staging/input-0, input-1, …. An optional label (up to 60 printable characters) names the run in views. continueFrom names a finished run of the same profile whose state this run takes over, starting on the node that holds it."
            }
            Self::WorkloadCreateEvidence => {
                "Extract validated evidence from one workload creation."
            }
            Self::WorkloadCreateMany => {
                "Queue labeled launches of one published profile. All items are validated before any launch is held; the queue starts each when capacity and seat and lane limits permit."
            }
            Self::WorkloadCreateManyEvidence => {
                "Extract validated evidence from one batch launch."
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
                "List your pods and your project's (or one by runId): each row names its profile, node, state, runId and resourceVersion — the runId and resourceVersion the pause, resume, restart and stop tools take — and a running pod's status: its newest reported values against the previous ones (how a simulation is converging). With runId, logLines also reads that pod's newest log lines."
            }
            Self::WorkloadSummarizeEvidence => {
                "Extract validated evidence from one workload summary."
            }
            Self::WorkloadQueue => "List your held launches, oldest first, with their batch.",
            Self::WorkloadQueueEvidence => "Extract validated evidence from a launch queue read.",
            Self::WorkloadQueueDrop => {
                "Drop a held batch or launch by operation id so it never starts."
            }
            Self::WorkloadQueueDropEvidence => {
                "Extract validated evidence from a launch queue drop."
            }
            Self::WorkloadSteer => {
                "Change a running pod's control values without stopping it: writes document (checked against its profile's control schema) to the pod's control file as the next seq. expectedSeq is the seq you last saw (0 before any steer); a stale one is refused with the current seq. The pod reads it within about a minute and reports control_seq in its status."
            }
            Self::WorkloadSteerEvidence => "Extract validated evidence from one workload steer.",
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
            Self::WorkloadCreateMany => {
                include_str!("../../../../schemas/capability/kube.workload.create_many.input.json")
            }
            Self::WorkloadCreateManyEvidence => {
                include_str!("../../../../schemas/capability/kube.workload.create_many.output.json")
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
            Self::WorkloadSteer => {
                include_str!("../../../../schemas/capability/kube.workload.steer.input.json")
            }
            Self::WorkloadSteerEvidence => {
                include_str!("../../../../schemas/capability/kube.workload.steer.output.json")
            }
            Self::WorkloadQueue => {
                include_str!("../../../../schemas/capability/kube.workload.queue.input.json")
            }
            Self::WorkloadQueueEvidence => {
                include_str!("../../../../schemas/capability/kube.workload.queue.output.json")
            }
            Self::WorkloadQueueDrop => {
                include_str!("../../../../schemas/capability/kube.workload.queue_drop.input.json")
            }
            Self::WorkloadQueueDropEvidence => {
                include_str!("../../../../schemas/capability/kube.workload.queue_drop.output.json")
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
    ///
    /// `project` is the caller's bound project. When that project declares a
    /// sphere, the returned profiles are already narrowed to its
    /// `pod_profiles`. `None` means the caller has no project yet: the owner
    /// lists every published profile and the listed route applies the seat
    /// offer only.
    fn launchable_profiles(
        &self,
        project: Option<&odin_domain::ProjectId>,
    ) -> Vec<LaunchableProfile> {
        let _ = project;
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
        let mut binding = self.owner.write().map_err(|error| HostToolError::Catalog {
            detail: format!("kube capability owner slot: {error}"),
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
            .map_err(|error| {
                HostToolError::unavailable(
                    binding.id(),
                    format!("kube capability owner slot: {error}"),
                )
            })?
            .clone()
            .ok_or_else(|| {
                HostToolError::unavailable(binding.id(), "kube capability owner is not bound")
            })
    }
}

impl KubeCapabilityOwner for KubeCapabilityOwnerSlot {
    fn launchable_profiles(
        &self,
        project: Option<&odin_domain::ProjectId>,
    ) -> Vec<LaunchableProfile> {
        self.owner(KubeCapabilityBinding::WorkloadCreate)
            .map(|owner| owner.launchable_profiles(project))
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
/// fresh seat authority, effective listing, plan gate, and the approval
/// settlement the card declares. The wrapper only carries the
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

    fn parameters_for_scope(&self, scope: &Scope) -> Option<Value> {
        if !matches!(
            self.inner.binding,
            KubeCapabilityBinding::WorkloadCreate | KubeCapabilityBinding::WorkloadCreateMany
        ) {
            return None;
        }
        let profiles: Vec<_> = self
            .inner
            .owner
            .launchable_profiles(scope.project.as_ref())
            .into_iter()
            .filter(|profile| {
                profile.seats.is_empty()
                    || scope.seat.as_ref().is_some_and(|seat| {
                        profile.seats.iter().any(|allowed| allowed == seat.as_str())
                    })
            })
            .collect();
        let mut definition = self.definition.clone();
        annotate_launchable_profiles(&mut definition, &profiles);
        Some(definition.parameters)
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
/// The ids also resolve at the dispatch seam, so a near-miss names the
/// launchable set instead of failing an enum.
pub(super) fn annotate_launchable_profiles(
    definition: &mut super::RpcHostToolDefinition,
    profiles: &[LaunchableProfile],
) {
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
    definition.parameters = crate::host_tools::schema_compat::resolve_ids(
        std::mem::take(&mut definition.parameters),
        "/properties/profile",
        profiles.iter().map(|profile| profile.id.as_str()),
    );
    if let Some(profile) = definition
        .parameters
        .pointer_mut("/properties/profile")
        .and_then(Value::as_object_mut)
    {
        profile.insert(
            "description".to_owned(),
            Value::String(if profiles.is_empty() {
                "No workload profiles are launchable by this seat.".to_owned()
            } else {
                format!("Published profile id. Launchable profiles: {listed}.")
            }),
        );
    }
    if !profiles.is_empty() {
        definition.description = std::borrow::Cow::Owned(format!(
            "{} Choose one of the launchable profiles listed on `profile`.",
            definition.description
        ));
    }
}
