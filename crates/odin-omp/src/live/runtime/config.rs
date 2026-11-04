use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use odin_atlas::AtlasScope;
use odin_brain::config::EffectiveBrainPolicy;
use odin_brain::retrieval::LaneEmbeddingProvider;
use odin_brain::service::BrainSourceConfig;
use odin_domain::huginn::{SessionManifest, WorkloadSessionBinding};
use odin_domain::knowledge::{AtlasId, EmbeddingModelId};
use odin_domain::operation::Limits;
use odin_domain::{CapabilityId, LaneId, NodeId, ProjectId, SeatId};
use odin_kernel::{CapabilityContract, Clock, SchemaCatalog};
use odin_ledger::Ledger;

use super::assembly::SessionCapsuleAuthority;
use crate::host_tools::atlas_query::SharedAtlas;
use crate::host_tools::delegation::DelegationLinkLedger;
use crate::host_tools::operations::{ProvisionedFreshAuthorityProvider, SeatOperationPolicy};
use crate::live::ledger::LiveLedger;
use crate::live::zellij::ZellijCliFactory;
use crate::process::OmpProcessSpec;

/// Host-admitted remote carrier resolution for one kube-launched workload
/// session: the returned factory attaches the exact admitted pod exec
/// channel of the binding's operation, proved against kube-side durable
/// launch state. No composition here means workload sessions refuse
/// typed — the local process carrier never carries a workload manifest.
#[async_trait]
pub trait WorkloadCarrierPort: Send + Sync {
    async fn carrier_for(
        &self,
        binding: &WorkloadSessionBinding,
        manifest: &SessionManifest,
    ) -> Result<Arc<dyn crate::process::RemoteHarnessFactory>, odin_domain::huginn::LiveError>;
}

/// A seat's declared system guidance and the declaration vehicle that
/// carried it. A conversation seat's `[conversation] guidance` is the
/// seat's whole system prompt; a coding seat's plain `guidance` only
/// supplements the harness's default coding-assistant prompt.
#[derive(Clone, Debug)]
pub struct DeclaredGuidance {
    pub text: String,
    /// True when the text came from the seat's `[conversation]` block.
    pub conversation: bool,
}

/// Each enabled seat's declared system guidance: its conversation guidance, else its seat guidance.
pub fn declared_conversation_guidance(
    registry: &[odin_registry::RegistryObject],
) -> Result<BTreeMap<SeatId, DeclaredGuidance>, String> {
    registry
        .iter()
        .filter_map(|object| {
            let odin_registry::ObjectConfig::Seat(seat) = &object.config else {
                return None;
            };
            if !seat.enabled {
                return None;
            }
            let (guidance, conversation) = match &seat.conversation {
                Some(conversation) => (Some(&conversation.guidance), true),
                None => (seat.guidance.as_ref(), false),
            };
            guidance.map(|text| {
                let seat = SeatId::new(&object.id).map_err(|error| {
                    format!(
                        "{}: invalid seat identity: {error}",
                        object.relative_config.display()
                    )
                })?;
                let text = with_toolset_index(registry, &object.id, text)?;
                Ok((seat, DeclaredGuidance { text, conversation }))
            })
        })
        .collect()
}

/// The guidance line replaced by the seat's generated category index.
const TOOLSETS_LINE: &str = "{toolsets}";

/// Replace a guidance line that is exactly `{toolsets}` with the seat's category index.
fn with_toolset_index(
    registry: &[odin_registry::RegistryObject],
    seat: &str,
    text: &str,
) -> Result<String, String> {
    if !text.split('\n').any(|line| line == TOOLSETS_LINE) {
        return Ok(text.to_owned());
    }
    let index = odin_registry::toolsets::seat_index(registry, seat)
        .map_err(|error| format!("seat {seat} guidance index: {error}"))?;
    Ok(text
        .split('\n')
        .map(|line| {
            if line == TOOLSETS_LINE {
                index.as_str()
            } else {
                line
            }
        })
        .collect::<Vec<_>>()
        .join("\n"))
}

/// Result limits are slice declarations, independent of whether brain serving
/// is enabled on this daemon.
pub fn declared_tool_result_budgets<'a>(
    registry: &[odin_registry::RegistryObject],
    bindings: impl IntoIterator<Item = (&'a SeatId, &'a odin_domain::SliceId)>,
) -> Result<BTreeMap<SeatId, u32>, String> {
    let mut budgets = BTreeMap::new();
    for (seat, slice) in bindings {
        let declared = registry
            .iter()
            .find_map(|object| match &object.config {
                odin_registry::ObjectConfig::Slice(declared) if object.id == slice.as_str() => {
                    Some(declared)
                }
                _ => None,
            })
            .ok_or_else(|| format!("seat {seat}'s slice {slice} is absent from the registry"))?;
        if let Some(context) = &declared.context {
            budgets.insert(seat.clone(), context.tool_result_tokens.get());
        }
    }
    Ok(budgets)
}
/// MemoryMax per seat, from each enabled container that declares one.
pub fn declared_seat_memory_max(
    registry: &[odin_registry::RegistryObject],
) -> BTreeMap<SeatId, u64> {
    registry
        .iter()
        .filter_map(|object| match &object.config {
            odin_registry::ObjectConfig::Container(container) if container.enabled => container
                .memory_max
                .map(|max| (container.seats_offered.clone(), max)),
            _ => None,
        })
        .flat_map(|(seats, max)| seats.into_iter().map(move |seat| (seat, max)))
        .collect()
}

/// Each enabled seat's `[sandbox]` table. A seat that omits the table keeps
/// the shell-disabled default.
pub fn declared_seat_sandboxes(
    registry: &[odin_registry::RegistryObject],
) -> Result<BTreeMap<SeatId, odin_registry::schema::SeatSandboxToml>, String> {
    registry
        .iter()
        .filter_map(|object| {
            let odin_registry::ObjectConfig::Seat(seat) = &object.config else {
                return None;
            };
            if !seat.enabled {
                return None;
            }
            Some(
                SeatId::new(&object.id)
                    .map(|id| (id, seat.sandbox.clone()))
                    .map_err(|error| {
                        format!(
                            "{}: invalid seat identity: {error}",
                            object.relative_config.display()
                        )
                    }),
            )
        })
        .collect()
}

/// Workload guidance and grants from the validated registry. A pod's turns carry
/// no memory: its context is its brief, its launch input and its own task.
#[derive(Clone, Debug)]
pub struct WorkloadSessionLaw {
    /// Registry-validated pod task brief.
    pub brief: String,
    /// The profile's declared memory namespace, validated against the bound
    /// seat's authorized knowledge sources at composition. No turn reads it.
    pub memory_namespace: AtlasId,
    /// The profile's declared bound on facts per turn. No turn reads it.
    pub max_facts: u16,
    /// Granted pod capabilities; all other seat tools are denied for the session.
    pub tools: std::collections::BTreeSet<odin_domain::CapabilityId>,
}

#[derive(Clone)]
pub struct ContextReadRuntimeConfig {
    /// Trusted absolute read-only root sealed before the model exists.
    pub root: PathBuf,
    /// Per-call hard response ceiling, further narrowed by each request.
    pub max_bytes: u64,
}

/// The declared context window of one seat launch option: the exact lane
/// identity a session of the seat may run, the window its context guard
/// binds to while it runs, and the tokenizer that counts against it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LaneWindow {
    pub provider: String,
    pub model: String,
    pub window: std::num::NonZeroU32,
    pub tokenizer: odin_domain::knowledge::ids::TokenizerId,
}

#[derive(Clone)]
pub struct ProductionBridgeRuntimeConfig {
    pub process: OmpProcessSpec,
    /// Sole StopAuthority launch/stop contract for the pinned OMP worker.
    pub worker: crate::process::OmpWorkerLaunch,
    pub bridge_ledger: Arc<Mutex<Ledger>>,
    pub live_ledger: Arc<dyn LiveLedger>,
    /// The generated-knowledge index the URI router and `odin_atlas_query`
    /// read within the granted scope; odind fills it after its listeners bind.
    pub atlas: SharedAtlas,
    pub allowed_atlas_scope: AtlasScope,
    /// Published real brain policy (registry-resolved, digest-verified) of
    /// EACH served seat. Seats intentionally serve different knowledge
    /// scopes, so policies compose per seat and are never converged or
    /// widened; a seat absent from the map serves no brain surface at all —
    /// `brain://` fails typed-unavailable for its sessions while every
    /// other seat and unrelated surface keeps serving.
    pub brain_policies: BTreeMap<SeatId, EffectiveBrainPolicy>,
    /// Trusted knowledge sources (immutable Atlas roots and loopback
    /// SilverBullet vaults) the brain service pins and indexes, keyed by
    /// exact `AtlasId`. The service composes exactly the sources the
    /// published policy authorizes; a zero-, one-, or many-source policy all
    /// compose their exact set, and an absent knowledge authority composes
    /// no serving surface at all — the affected operations fail
    /// typed-unavailable instead of refusing unrelated sessions.
    pub brain_sources: BTreeMap<AtlasId, BrainSourceConfig>,
    /// Pre-resolved embedding executor factory for the brain services.
    /// Required exactly when the published policy's retrieval mode needs
    /// embeddings; `None` composes a lexical-only service and vector or
    /// hybrid retrieval fails typed instead of downgrading. Each session
    /// binds its OWN runtime lane once through
    /// [`LaneEmbeddingProvider::bind_lane`] at context construction — the
    /// kernel provider lease binds to the requesting session lane, never to
    /// the gateway projection's route lane, which remains selection policy
    /// only.
    pub brain_embedding: Option<Arc<dyn LaneEmbeddingProvider>>,
    /// Declared embedding model of the actual backend binding the injected
    /// executor executes under, carried into every generation's vector-pool
    /// identity check. `None` composes lexical-only.
    pub brain_embedding_model: Option<EmbeddingModelId>,
    /// The brain's PostgreSQL store every seat's brain serves from.
    pub brain_postgres: Option<Arc<odin_brain::index::postgres::BrainPostgres>>,
    /// The cross-encoder every seat's turns rerank by (`[brain.rerank]`).
    pub brain_rerank: Option<odin_brain::retrieval::rerank::Reranker>,
    pub artifact_root: PathBuf,
    /// Where injected-context traces are written (`context_trace::root`);
    /// `None` records nothing.
    pub context_trace_root: Option<PathBuf>,
    /// Every served seat's declared tool-result ceiling, also when brain is disabled.
    pub tool_result_budgets: BTreeMap<SeatId, u32>,
    pub project_roots: BTreeMap<ProjectId, PathBuf>,
    pub session_lanes: BTreeMap<(SeatId, ProjectId), LaneId>,
    pub allowed_nodes: BTreeSet<NodeId>,
    /// READ-ONLY follower posture (`NodePosture::Follower`): the runtime
    /// composes with exactly the served sets the config declares —
    /// legitimately all empty (no seat operation bindings, projects,
    /// session lanes, or allowed nodes) — while every observation surface
    /// stays live and reports exactly those empty sets. The sole
    /// authoritative posture keeps the non-empty requirements and typed
    /// refusals unchanged.
    pub read_only: bool,
    pub owner_id: String,
    pub hooks_root: PathBuf,
    pub lease_ttl: Duration,
    pub max_artifact_read_bytes: u64,
    pub zellij: Option<ZellijCliFactory>,
    /// Exactly the capability contracts assembled from validated registry
    /// declarations. Required; the sole authority admits nothing else.
    pub operation_contracts: BTreeMap<CapabilityId, CapabilityContract>,
    /// The capability ids whose concrete owner is the one-shot operator CLI
    /// rather than a session HostTool. They are admitted at registry
    /// publication by the operator catalog and are excluded from the
    /// dispatch catalog here: the kernel never invokes them, so no HostTool
    /// owner exists or is invented, and a session can never dispatch them.
    pub operator_capabilities: BTreeSet<CapabilityId>,
    /// Published snapshot revision that issued these contracts.
    pub admission_revision: i64,
    /// The real schema source the authority validates payloads against.
    pub schema_catalog: Arc<dyn SchemaCatalog + Send + Sync>,
    /// Authority usage ceilings over the durable operation journal.
    pub operation_limits: Limits,
    /// The host-owned trusted clock the authority reads; callers never
    /// supply time.
    pub operation_clock: Clock,
    /// Governed delegation task-owner slot. When present, the factory
    /// registers the task capabilities over it during assembly; an unbound
    /// slot fails closed at invocation, never by omission.
    pub task_slot: Option<Arc<crate::host_tools::delegation::TaskOwnerSlot>>,
    /// Concrete provider for externally provisioned signed seat tokens and
    /// host-owned verification material. Required; the runtime never issues a
    /// production token.
    pub operation_authority_provider: Arc<ProvisionedFreshAuthorityProvider>,
    /// The retained-publication recomposition seam: derives any served
    /// generation's exact operation material on demand, so every session
    /// resolves the publication its own token binds instead of the
    /// runtime's startup revision. Required; there is no current-revision
    /// fallback anywhere in the surface.
    pub revision_material: Arc<dyn crate::host_tools::operations::RevisionMaterialSource>,
    /// Durable compiled-draft retention for the conversational workload
    /// authoring seam. `None` composes no retention: `workload.publish`
    /// then fails typed before the approval gate instead of ever
    /// re-deriving a declaration from model answers.
    pub workload_drafts: Option<Arc<crate::host_tools::WorkloadDraftStore>>,
    /// The owner's task grants the dispatch decides covered calls against;
    /// `None` composes none and every owner-decided call asks the owner.
    pub task_grants: Option<Arc<crate::host_tools::task_grants::TaskGrantStore>>,
    /// Where gated calls wait for the owner's yes; `None` parks nothing, so no yes can run a call.
    pub approved_calls: Option<Arc<crate::host_tools::approved_calls::ApprovedCalls>>,
    /// The conversation seat's background jobs; `None` runs every call in the foreground.
    pub jobs: Option<Arc<crate::host_tools::jobs::JobBoard>>,
    /// Receipts acknowledged only after their inline transport delivery succeeds.
    pub delivery_acknowledger: Option<crate::host_tools::operations::DeliveryAcknowledger>,
    /// Declared backends used for dispatch and health probes; absent backends are unavailable.
    pub adapters: Arc<crate::host_tools::adapter::DeclaredAdapterBackends>,
    /// Freshness bound an adapter status snapshot must meet to count.
    pub adapter_status_ttl: Duration,
    /// Host-owned per-session capsule authority provider. Required; the
    /// factory never reuses a fixture authority across sessions.
    pub session_capsule_authority: std::sync::Arc<dyn SessionCapsuleAuthority>,
    /// Per-(seat, lane) host-owned operation bindings assembled from
    /// validated registry policy. A session without one fails closed.
    pub seat_operation_bindings: BTreeMap<(SeatId, LaneId), SeatOperationPolicy>,
    /// Durable delegation link ledger: the session build reads the exact
    /// persisted parent link from it, so a delegated child's operation
    /// binding carries its real parent chain — never model input.
    pub delegation_links: DelegationLinkLedger,
    /// Declared bounded rollover policies, keyed by the seat that declared
    /// them (`[live.rollover]` in the seat's registry declaration). The
    /// factory resolves the effective per-seat policy against the bound
    /// lane's declared context ceiling at composition time
    /// (`live::rollover::lane_rollover_config`): an explicit declaration is
    /// narrowed to the ceiling, and a seat that declares nothing still
    /// receives a lane-derived policy when the lane ceiling is below the
    /// compiled default threshold. Lanes at or above the default whose
    /// seats declare nothing keep exactly the no-rollover behavior, and the
    /// respawned incarnation reuses the session's own process spec — the
    /// seat's declared model stays free of this policy.
    pub rollover_by_seat: BTreeMap<SeatId, crate::live::rollover::RolloverRuntimeConfig>,
    /// Declared context windows of each seat's launch options. A session's
    /// guard binds to the window of the model it is running, so a declared
    /// model switch keeps the guard; options absent here run unguarded.
    pub lane_windows_by_seat: BTreeMap<SeatId, Vec<LaneWindow>>,
    /// Effective context window of every selectable model card, keyed by
    /// the card id (`gateway/terra`, `claude/claude-opus-5-5`). A fractional
    /// rollover binds this window. A selectable card absent from the map
    /// is refused at composition.
    pub card_windows: BTreeMap<String, u64>,
    /// Declared system guidance, keyed by the seat that declared it
    /// (`[conversation] guidance`, or a coding seat's plain `guidance`, in
    /// the seat's registry declaration, composed by the daemon from the
    /// validated registry). A session whose seat declared conversation
    /// guidance receives the composed guidance as its whole system prompt
    /// through the pinned harness's `--system-prompt`; every other seat
    /// keeps the harness default and only appends through
    /// `--append-system-prompt`.
    pub conversation_guidance: BTreeMap<SeatId, DeclaredGuidance>,
    /// Declared toolsets of the published registry, whose examples each listing shows.
    pub toolsets: BTreeMap<String, odin_registry::schema::ToolsetToml>,
    /// Workload settings by published profile ID; missing profiles fail launch.
    pub workload_sessions: BTreeMap<String, WorkloadSessionLaw>,
    /// The admitted remote carrier resolver for workload sessions. `None`
    /// refuses workload sessions typed; there is no local fallback.
    pub workload_carrier: Option<Arc<dyn WorkloadCarrierPort>>,
    /// Optional trusted bounded context reader. If registry policy enables
    /// `context.read`, this must be present or capability composition fails.
    pub context_read: Option<ContextReadRuntimeConfig>,
    /// The daemon's registry, state root, and pinned bwrap for `device.run`.
    /// Absent only in tests that never dispatch a device action.
    pub device_run: Option<crate::host_tools::device::DeviceRunBinding>,
    /// Additional daemon-supplied tools; duplicate names fail composition.
    pub hermes_tools: Vec<Arc<dyn crate::host_tools::HostTool>>,
    /// The image blocks a turn's photo markers name (Hermes intake);
    /// `None` sends marker text verbatim.
    pub turn_images: Option<Arc<dyn crate::live::control::TurnImages>>,
    /// Internal handlers keyed by compiled builtin ID, never model-visible.
    /// Missing handlers for cataloged builtins fail production composition.
    pub hermes_internal_bindings: Vec<(&'static str, Arc<dyn crate::host_tools::HostTool>)>,
    /// Declared `[sandbox]` tables, keyed by seat.
    pub seat_sandboxes: BTreeMap<SeatId, odin_registry::schema::SeatSandboxToml>,
    /// Declared project spheres, keyed by project. A lane of a listed
    /// project binds that sphere instead of the seat's path roles.
    pub project_spheres: BTreeMap<ProjectId, crate::process::SphereProjection>,
    /// Declared MemoryMax bytes for native seat processes, keyed by seat.
    pub seat_memory_max: BTreeMap<SeatId, u64>,
    /// Host bwrap/bash/auth paths. Absent only in tests that never exec the
    /// manifest wrapper; production composition refuses to start without it.
    pub sandbox_host: Option<crate::process::SeatSandboxHost>,
}

#[cfg(test)]
mod tests {
    #[test]
    fn result_budgets_exist_without_any_brain_runtime() {
        let source = r#"schema = "odin.registry.v1"
kind = "slice"
enabled = true
description = "A slice with a declared result budget."
variables = {}
[redirects]
out_of_scope = "NeedsPlan"
[knowledge]
required = false
atlas_sources = ["memory.sinmara"]
retrieval_mode = "hybrid"
candidate_limit = 8
top_k = 4
min_score_micros = 1
chunk_tokens = 512
chunk_overlap_tokens = 64
embedding_backend = "local"
[context]
max_bundle_tokens = 196608
reserve_output_tokens = 16384
control_tokens = 8192
history_tokens = 139264
core_tokens = 2048
prefetch_tokens = 2048
tool_result_tokens = 12345
tool_schema_tokens = 16384
max_item_tokens = 16384
[tools]
deny = []
[tools.redirects]
max_http_hops = 2
allow_cross_origin = false
allow_https_downgrade = false
"#;
        let object = odin_registry::schema::parse_object_toml(
            odin_registry::RegistryKind::Slice,
            "test-slice",
            "registry/slices/test-slice/slice.toml",
            source,
        )
        .unwrap();
        let seat = odin_domain::SeatId::new("sinmara").unwrap();
        let slice = odin_domain::SliceId::new("test-slice").unwrap();
        let budgets = super::declared_tool_result_budgets(&[object], [(&seat, &slice)]).unwrap();
        assert_eq!(budgets[&seat], 12345);
    }
}
