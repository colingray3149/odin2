//! Shared runtime composition keeps token provisioning and server verification
//! consistent for the same configuration and pinned registry snapshot.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::Arc;

use odin_domain::huginn as live;
use odin_domain::{CapabilityId, Digest, LaneId, NodeId, ProjectId, SeatId, SeatToken};
use odin_huginn::{OdindConfig, OdindLaneBinding};
use odin_kernel::CapabilityContract;
use odin_node::config::NodeIdentity;
use odin_omp::host_tools::operations::{
    admission_digest, seat_operation_policy, RevisionMaterial, RevisionMaterialSource,
    SeatOperationPolicy,
};
use odin_registry::snapshot::ObjectIndex;
use odin_registry::{ObjectConfig, RegistryKind, RegistryObject, SnapshotStore};

/// Reserve room for the rollover marker so the brief fits `max_item_tokens`.
/// Each token covers at least one byte. Validate the current registry only;
/// historical generations must remain composable.
const BRIEF_MARKER_MARGIN: usize = 64;

pub fn brief_fits_item_ceiling(max_brief_bytes: usize, max_item_tokens: u32) -> bool {
    max_brief_bytes + BRIEF_MARKER_MARGIN <= max_item_tokens as usize
}

/// Validated inputs shared by the live runtime and operator provisioning.
pub struct RuntimeInputs {
    pub node: NodeIdentity,
    pub project_roots: BTreeMap<ProjectId, PathBuf>,
    pub session_lanes: BTreeMap<(SeatId, ProjectId), LaneId>,
    pub seat_bindings: Vec<odin_omp::live::supervisor::LiveSeatBinding>,
    pub transfer_lanes: BTreeMap<SeatId, odin_omp::live::transfer::SeatTransferLanes>,
    /// Seats without a `[live.rollover]` policy do not roll over at turn boundaries.
    pub rollover_seats: BTreeMap<SeatId, odin_omp::live::rollover::RolloverRuntimeConfig>,
    pub egress_lanes: BTreeSet<LaneId>,
    pub file_roots: Vec<live::FileRoot>,
    pub tailnet_peers: BTreeMap<IpAddr, live::TailnetNodeId>,
    pub allowed_nodes: BTreeSet<NodeId>,
    pub render_session: live::LiveSessionId,
    pub file_publish_lane: LaneId,
    pub render_publish_lane: LaneId,
}

impl RuntimeInputs {
    /// Fails the entire composition on invalid configuration rather than
    /// silently authorizing a narrower runtime.
    pub fn parse(config: &OdindConfig, registry: &[RegistryObject]) -> Result<Self, String> {
        let index = ObjectIndex::new(registry);
        let enabled = |kind: RegistryKind, id: &str| index.enabled(kind, id);
        let node = NodeIdentity::from_snapshot(&config.identity.node, registry)
            .map_err(|error| error.to_string())?;

        let mut project_roots = BTreeMap::new();
        for (project, entry) in &config.projects {
            let project_id = ProjectId::new(project.as_str())
                .map_err(|error| format!("invalid configured project {project:?}: {error}"))?;
            if !enabled(RegistryKind::Project, project_id.as_str()) {
                // Older generations omit runtime-created projects and their lanes.
                if entry.runtime {
                    continue;
                }
                return Err(format!(
                    "project {project_id} is not enabled in the registry"
                ));
            }
            if !entry.root.is_absolute() {
                return Err(format!("project {project_id} root must be absolute"));
            }
            if project_roots
                .insert(project_id.clone(), entry.root.clone())
                .is_some()
            {
                return Err(format!(
                    "project {project_id} has duplicate root configuration"
                ));
            }
        }

        // Runtime-created seats a generation predates (see projects above).
        let unknown_runtime_seats: BTreeSet<&SeatId> = config
            .seats
            .iter()
            .filter(|binding| {
                binding.runtime && !enabled(RegistryKind::Seat, binding.seat.as_str())
            })
            .map(|binding| &binding.seat)
            .collect();
        let mut session_lanes = BTreeMap::new();
        for binding in &config.lane_bindings {
            let runtime_project = config
                .projects
                .get(binding.project.as_str())
                .is_some_and(|project| project.runtime);
            if (runtime_project && !project_roots.contains_key(&binding.project))
                || unknown_runtime_seats.contains(&binding.seat)
                || (binding.runtime && !enabled(RegistryKind::Lane, binding.lane.as_str()))
            {
                continue;
            }
            validate_session_lane(&index, binding)?;
            // A BOUND project fails closed: every configured session lane
            // must name a project with a configured absolute root, so a
            // session opened on it resolves a real workspace and never a
            // phantom. Merely permitted scope projects (the registry's
            // upper bound) are not required to be configured here.
            if !project_roots.contains_key(&binding.project) {
                return Err(format!(
                    "seat {} project {} has a lane binding but no configured \
                     projects.{}.root",
                    binding.seat, binding.project, binding.project
                ));
            }
            if session_lanes
                .insert(
                    (binding.seat.clone(), binding.project.clone()),
                    binding.lane.clone(),
                )
                .is_some()
            {
                return Err(format!(
                    "duplicate default lane for seat {} project {}",
                    binding.seat, binding.project
                ));
            }
        }

        let mut seat_bindings = Vec::new();
        let mut allowed_nodes = BTreeSet::new();
        let mut bound_seats = BTreeSet::new();
        for binding in &config.seats {
            if unknown_runtime_seats.contains(&binding.seat) {
                continue;
            }
            if !enabled(RegistryKind::Seat, binding.seat.as_str()) {
                return Err(format!(
                    "seat {} is not enabled in the registry",
                    binding.seat
                ));
            }
            if !enabled(RegistryKind::Slice, binding.slice.as_str()) {
                return Err(format!(
                    "slice {} is not enabled in the registry",
                    binding.slice
                ));
            }
            if binding.display_name.trim().is_empty()
                || binding.launch_options.is_empty()
                || binding.allowed_nodes.is_empty()
                || binding.max_sessions == 0
            {
                return Err(format!(
                    "seat {} binding requires display name, launch options, nodes, and sessions",
                    binding.seat
                ));
            }
            let seat = match index
                .get(RegistryKind::Seat, binding.seat.as_str())
                .map(|object| &object.config)
            {
                Some(ObjectConfig::Seat(seat)) => seat.as_ref(),
                _ => return Err(format!("seat {} has no live configuration", binding.seat)),
            };
            let seat_limit = seat
                .live
                .as_ref()
                .map(|live| {
                    usize::from(live.max_sessions.get()).min(usize::from(seat.limits.max_sessions))
                })
                .ok_or_else(|| format!("seat {} has no live configuration", binding.seat))?;
            // The declared elapsed budget of ONE model turn, when the seat
            // declares one. The range is validated here exactly once so a
            // mis-authored declaration fails composition instead of
            // arming a nonsense timer; absent declares no product budget.
            let turn_budget = seat
                .live
                .as_ref()
                .and_then(|live| live.max_turn_seconds)
                .map(|seconds| {
                    if seconds.get() > odin_registry::MAX_TURN_SECONDS {
                        return Err(format!(
                            "seat {} declares max_turn_seconds {} beyond the {} second bound",
                            binding.seat,
                            seconds.get(),
                            odin_registry::MAX_TURN_SECONDS
                        ));
                    }
                    Ok(std::time::Duration::from_secs(seconds.get()))
                })
                .transpose()?;
            if binding.max_sessions > seat_limit {
                return Err(format!(
                    "seat {} binding requests {} sessions but registry permits {seat_limit}",
                    binding.seat, binding.max_sessions
                ));
            }
            for option in &binding.launch_options {
                if !enabled(RegistryKind::Provider, option.provider.as_str()) {
                    return Err(format!(
                        "launch provider {} is not enabled in the registry",
                        option.provider
                    ));
                }
                if !enabled(RegistryKind::Container, option.container_id.as_str()) {
                    return Err(format!(
                        "launch container {} is not enabled in the registry",
                        option.container_id
                    ));
                }
            }
            if !bound_seats.insert(binding.seat.clone()) {
                return Err(format!("duplicate seat binding {}", binding.seat));
            }
            for node in &binding.allowed_nodes {
                if !enabled(RegistryKind::Node, node.as_str()) {
                    return Err(format!("node {node} is not enabled in the registry"));
                }
                allowed_nodes.insert(node.clone());
            }
            validate_seat_projects(&binding.seat, &session_lanes)?;
            seat_bindings.push(odin_omp::live::supervisor::LiveSeatBinding {
                seat_id: binding.seat.clone(),
                slice_id: binding.slice.clone(),
                display_name: binding.display_name.clone(),
                launch_options: binding.launch_options.clone(),
                allowed_nodes: binding.allowed_nodes.clone(),
                max_sessions: binding.max_sessions,
                turn_budget,
            });
        }

        let mut transfer_lanes = BTreeMap::new();
        let mut rollover_seats = BTreeMap::new();
        let mut egress_lanes = BTreeSet::new();
        for object in registry {
            let ObjectConfig::Seat(seat) = &object.config else {
                continue;
            };
            if !seat.enabled
                || !bound_seats.contains(&SeatId::new(object.id.as_str()).map_err(|error| {
                    format!("invalid registry seat ID {:?}: {error}", object.id)
                })?)
            {
                continue;
            }
            let live = seat.live.as_ref().ok_or_else(|| {
                format!("seat {:?} has no live transfer configuration", object.id)
            })?;
            for lane in [
                &live.file_ingress_lane,
                &live.file_egress_lane,
                &live.render_ingress_lane,
                &live.render_egress_lane,
            ] {
                if !enabled(RegistryKind::Lane, lane.as_str()) {
                    return Err(format!(
                        "transfer lane {lane} is not enabled in the registry"
                    ));
                }
            }
            let seat_id = SeatId::new(object.id.as_str())
                .map_err(|error| format!("invalid registry seat ID {:?}: {error}", object.id))?;
            if let Some(declared) = &live.rollover {
                let policy = odin_omp::live::rollover::RolloverRuntimeConfig::new(
                    odin_omp::live::rollover::RolloverPolicy {
                        threshold_tokens: declared.threshold_tokens,
                        max_brief_bytes: declared.max_brief_bytes,
                        history_tail_events: declared.history_tail_events,
                    },
                )
                .map_err(|error| {
                    format!(
                        "seat {:?} declares an invalid [live.rollover] policy: {error}",
                        object.id
                    )
                })?;
                rollover_seats.insert(seat_id.clone(), policy);
            }
            transfer_lanes.insert(
                seat_id,
                odin_omp::live::transfer::SeatTransferLanes {
                    file_ingress: live.file_ingress_lane.clone(),
                    file_egress: live.file_egress_lane.clone(),
                    render_ingress: live.render_ingress_lane.clone(),
                    render_egress: live.render_egress_lane.clone(),
                },
            );
            egress_lanes.insert(live.file_egress_lane.clone());
            egress_lanes.insert(live.render_egress_lane.clone());
        }

        let mut file_roots = Vec::new();
        for root in &config.file_roots {
            for seat in &root.allowed_seats {
                if !enabled(RegistryKind::Seat, seat.as_str()) {
                    return Err(format!("file root allows unknown or disabled seat {seat}"));
                }
            }
            let canonical_path = root.canonical_path.canonicalize().map_err(|error| {
                format!(
                    "could not resolve file root {} path {}: {error}",
                    root.root_id,
                    root.canonical_path.display()
                )
            })?;
            if !canonical_path.is_dir() {
                return Err(format!(
                    "file root {} path {} is not a directory",
                    root.root_id,
                    canonical_path.display()
                ));
            }
            file_roots.push(
                live::FileRoot::new(live::FileRootInit {
                    root_id: root.root_id.clone(),
                    display_name: root.display_name.clone(),
                    canonical_path,
                    access: root.access,
                    media_policy: root.media_policy.clone(),
                    max_object_bytes: root.max_object_bytes,
                    watch_policy: root.watch_policy,
                    allowed_seats: root.allowed_seats.clone(),
                })
                .map_err(|error| error.to_string())?,
            );
        }

        let mut tailnet_peers = BTreeMap::new();
        for (raw_ip, node) in &config.tailnet_peers {
            let ip: IpAddr = raw_ip
                .parse()
                .map_err(|error| format!("invalid tailnet peer IP {raw_ip:?}: {error}"))?;
            if !odin_huginn::private_network::is_tailnet_address(ip) {
                return Err(format!("tailnet peer IP {ip} is outside Tailscale ranges"));
            }
            let node = live::TailnetNodeId::new(node)
                .map_err(|error| format!("invalid tailnet node ID {node:?}: {error}"))?;
            if tailnet_peers.insert(ip, node).is_some() {
                return Err(format!("tailnet peer IP {ip} is configured more than once"));
            }
        }
        if !config.listener.address.ip().is_loopback() && tailnet_peers.is_empty() {
            return Err("a Tailscale listener requires at least one tailnet peer".to_owned());
        }

        let render_session = live::LiveSessionId::parse(&config.publish.render_session)
            .map_err(|error| error.to_string())?;
        let file_publish_lane =
            LaneId::new(config.publish.file_lane.as_str()).map_err(|error| error.to_string())?;
        let render_publish_lane =
            LaneId::new(config.publish.render_lane.as_str()).map_err(|error| error.to_string())?;
        for lane in [&file_publish_lane, &render_publish_lane] {
            if !enabled(RegistryKind::Lane, lane.as_str()) {
                return Err(format!(
                    "publish lane {lane} is not enabled in the registry"
                ));
            }
        }
        Ok(Self {
            node,
            project_roots,
            session_lanes,
            seat_bindings,
            transfer_lanes,
            rollover_seats,
            egress_lanes,
            file_roots,
            tailnet_peers,
            allowed_nodes,
            render_session,
            file_publish_lane,
            render_publish_lane,
        })
    }
}

fn validate_session_lane(
    index: &ObjectIndex<'_>,
    binding: &OdindLaneBinding,
) -> Result<(), String> {
    let lane = index
        .get(RegistryKind::Lane, binding.lane.as_str())
        .ok_or_else(|| format!("default lane {} is absent from the registry", binding.lane))?;
    let ObjectConfig::Lane(lane_config) = &lane.config else {
        return Err(format!("registry object {} is not a lane", binding.lane));
    };
    if !lane_config.enabled
        || lane_config.project != binding.project
        || lane_config.default_seat != binding.seat
    {
        return Err(format!(
            "default lane {} does not bind enabled seat {} project {}",
            binding.lane, binding.seat, binding.project
        ));
    }
    let seat = index
        .get(RegistryKind::Seat, binding.seat.as_str())
        .ok_or_else(|| format!("default-lane seat {} is absent", binding.seat))?;
    let ObjectConfig::Seat(seat) = &seat.config else {
        return Err(format!("registry object {} is not a seat", binding.seat));
    };
    if !seat.enabled || !seat.project_scope.contains(&binding.project) {
        return Err(format!(
            "seat {} does not admit project {}",
            binding.seat, binding.project
        ));
    }
    Ok(())
}

fn validate_seat_projects(
    seat_id: &SeatId,
    session_lanes: &BTreeMap<(SeatId, ProjectId), LaneId>,
) -> Result<(), String> {
    // The registry's seat `project_scope` is the seat's PERMITTED upper
    // bound, not a demand that every allowed project be configured now:
    // future projects (no configured root, no lane binding) stay
    // unconfigured, and opening one fails typed at session composition
    // ("no configured session lane for project") instead of failing daemon
    // startup. The bound set is what startup validates fail-closed: every
    // configured lane already proved its project has a root and sits inside
    // the seat's scope, and a bound seat with no session lane at all is
    // dead wiring — a seat that can open no session refuses composition.
    if session_lanes
        .keys()
        .any(|(lane_seat, _)| lane_seat == seat_id)
    {
        return Ok(());
    }
    Err(format!(
        "seat {seat_id} binds no session lane; declare a [[lane_bindings]] entry for one of its \
         permitted projects"
    ))
}

/// Assembles the exact capability contract set the sole operation authority
/// admits: every enabled registry capability, converted through the kernel's
/// registry binding rules against the compiled admitted tuples enforced at
/// load.
pub fn operation_contracts(
    registry: &[RegistryObject],
) -> Result<BTreeMap<CapabilityId, CapabilityContract>, String> {
    let mut contracts = BTreeMap::new();
    for object in registry {
        if object.kind() != RegistryKind::Capability || !object.enabled() {
            continue;
        }
        let ObjectConfig::Capability(capability) = &object.config else {
            return Err(format!("registry object {} is not a capability", object.id));
        };
        let admitted = odin_registry::relational::declared_admitted_binding(capability)
            .ok_or_else(|| format!("enabled capability {} has no admitted binding", object.id))?;
        let contract = odin_kernel::CapabilityContract::try_from_registry(object, &admitted)
            .map_err(|error| format!("capability {} contract failed: {error}", object.id))?;
        if contracts.insert(contract.id.clone(), contract).is_some() {
            return Err(format!("capability {} is declared twice", object.id));
        }
    }
    Ok(contracts)
}

/// Validates seat tools against slice grants for the current revision only;
/// retained generations must remain composable for existing sessions.
pub fn ensure_seat_tools_granted(
    registry: &[RegistryObject],
    seat_bindings: &[odin_omp::live::supervisor::LiveSeatBinding],
) -> Result<(), String> {
    let index = ObjectIndex::new(registry);
    for binding in seat_bindings {
        let seat = index
            .get(RegistryKind::Seat, binding.seat_id.as_str())
            .and_then(|object| match &object.config {
                ObjectConfig::Seat(seat) => Some(seat.as_ref()),
                _ => None,
            });
        let slice = index
            .get(RegistryKind::Slice, binding.slice_id.as_str())
            .and_then(|object| match &object.config {
                ObjectConfig::Slice(slice) => Some(slice.as_ref()),
                _ => None,
            });
        let (Some(seat), Some(slice)) = (seat, slice) else {
            continue;
        };
        let ungranted: Vec<&str> = seat
            .tool_refs
            .difference(&slice.capabilities)
            .map(|capability| capability.as_str())
            .collect();
        if !ungranted.is_empty() {
            return Err(format!(
                "seat {} declares {ungranted:?}, which its bound slice {} does not grant; \
                 add them to the slice or remove them from the seat",
                binding.seat_id, binding.slice_id
            ));
        }
    }
    Ok(())
}

/// Assembles every session lane's (seat, lane) operation policy binding from
/// validated registry objects. Seat and slice revisions are the digests of
/// their canonical registry bytes; there are no project- or lane-level
/// capability declarations today, so both narrow to the slice set.
pub fn seat_operation_bindings(
    registry: &[RegistryObject],
    seat_bindings: &[odin_omp::live::supervisor::LiveSeatBinding],
    session_lanes: &BTreeMap<(SeatId, ProjectId), LaneId>,
    admission: Digest,
) -> Result<BTreeMap<(SeatId, LaneId), SeatOperationPolicy>, String> {
    let index = ObjectIndex::new(registry);
    let mut revisions = HashMap::new();
    let mut revision_of = |kind: RegistryKind, id: &str| -> Result<Digest, String> {
        let key = (kind, id.to_owned());
        if let Some(digest) = revisions.get(&key) {
            return Ok(*digest);
        }
        let object = index
            .get(kind, id)
            .ok_or_else(|| format!("registry object {id} is absent"))?;
        let digest = object
            .canonical_bytes()
            .map(|bytes| Digest::hash(&bytes))
            .map_err(|error| format!("cannot encode revision for {id}: {error}"))?;
        revisions.insert(key, digest);
        Ok(digest)
    };
    let mut bindings = BTreeMap::new();
    for ((seat, _project), lane) in session_lanes {
        let seat_binding = seat_bindings
            .iter()
            .find(|binding| binding.seat_id == *seat)
            .ok_or_else(|| format!("seat {seat} has a session lane but no seat binding"))?;
        let seat_object = index
            .get(RegistryKind::Seat, seat.as_str())
            .ok_or_else(|| format!("seat {seat} is absent from the registry"))?;
        let ObjectConfig::Seat(seat_config) = &seat_object.config else {
            return Err(format!("registry object {seat} is not a seat"));
        };
        let slice_object = index
            .get(RegistryKind::Slice, seat_binding.slice_id.as_str())
            .ok_or_else(|| {
                format!(
                    "slice {} is absent from the registry",
                    seat_binding.slice_id
                )
            })?;
        let ObjectConfig::Slice(slice_config) = &slice_object.config else {
            return Err(format!(
                "registry object {} is not a slice",
                seat_binding.slice_id
            ));
        };
        let denied_tools = seat_config
            .tools
            .iter()
            .flat_map(|tools| tools.deny.iter().cloned())
            .chain(
                slice_config
                    .tools
                    .iter()
                    .flat_map(|tools| tools.deny.iter().cloned()),
            )
            .collect();
        let policy = seat_operation_policy(
            odin_omp::host_tools::operations::SeatOperationPolicyInputs {
                seat_id: seat.clone(),
                slice_id: seat_binding.slice_id.clone(),
                lane_id: lane.clone(),
                seat_revision: revision_of(RegistryKind::Seat, seat.as_str())?,
                slice_revision: revision_of(RegistryKind::Slice, seat_binding.slice_id.as_str())?,
                admission,
                seat_tool_refs: seat_config.tool_refs.clone(),
                slice_capabilities: slice_config.capabilities.clone(),
                project_capabilities: slice_config.capabilities.clone(),
                lane_capabilities: slice_config.capabilities.clone(),
                denied_capabilities: BTreeSet::new(),
                denied_tools,
                resource_constraints: BTreeMap::new(),
                seat_categories: seat_config.categories.clone(),
            },
        );
        bindings.insert((seat.clone(), lane.clone()), policy);
    }
    Ok(bindings)
}

// ---------------------------------------------------------------------------

/// Why a publication's composition digest could not be proven.
#[derive(Debug, thiserror::Error)]
pub enum CompositionDigestError {
    #[error("retained publication {revision} is unavailable: {source}")]
    Unretained {
        revision: u64,
        #[source]
        source: odin_registry::SnapshotError,
    },
    #[error("publication {revision} composition could not be digested: {source}")]
    Digest {
        revision: u64,
        #[source]
        source: odin_registry::SnapshotError,
    },
}

/// The composition digest of one retained publication
/// ([`odin_registry::CompositionDigest`]).
pub fn composition_digest_at(
    store: &SnapshotStore,
    revision: u64,
) -> Result<odin_registry::CompositionDigest, CompositionDigestError> {
    let (snapshot, _receipt) = store
        .publication_at(revision)
        .map_err(|source| CompositionDigestError::Unretained { revision, source })?;
    snapshot
        .composition_digest()
        .map_err(|source| CompositionDigestError::Digest { revision, source })
}

/// The daemon's retained-publication material source: recomposes any
/// retained revision's exact operation material through the SAME pure
/// functions the startup composition and the provisioning path run, so a
/// session bound to generation N is served — byte-for-byte — the material
/// publication N admitted. Unknown or pruned revisions fail typed; the
/// per-revision memo lives on the operation stack, never here.
pub struct StoreRevisionMaterial {
    store: SnapshotStore,
    config: OdindConfig,
}

impl StoreRevisionMaterial {
    pub fn new(store: SnapshotStore, config: OdindConfig) -> Self {
        Self { store, config }
    }

    /// The exact material of one publication's object set.
    fn material_for_objects(
        &self,
        objects: &[RegistryObject],
        revision: u64,
    ) -> Result<RevisionMaterial, String> {
        let contracts = operation_contracts(objects)?;
        let revision_i64 = i64::try_from(revision)
            .map_err(|_| format!("snapshot revision {revision} exceeds the admission range"))?;
        let admission = admission_digest(&contracts, revision_i64)
            .map_err(|error| format!("admission digest failed: {error}"))?;
        let config = config_for_generation(&self.config, objects);
        let inputs = RuntimeInputs::parse(&config, objects)?;
        let seat_operation_bindings = seat_operation_bindings(
            objects,
            &inputs.seat_bindings,
            &inputs.session_lanes,
            admission,
        )?;
        let mut tool_index = BTreeMap::new();
        for (id, contract) in &contracts {
            let name = contract.tool_name.as_ref().to_owned();
            if let Some(existing) = tool_index.insert(name.clone(), id.clone()) {
                return Err(format!(
                    "publication {revision} binds tool {name} to both {existing} and {id}"
                ));
            }
        }
        let contract_adapters = contracts
            .values()
            .filter_map(|contract| contract.adapter.clone())
            .collect();
        let declaration_decided = objects
            .iter()
            .filter_map(|object| match &object.config {
                ObjectConfig::Capability(capability)
                    if capability.approval_decider
                        == odin_registry::schema::ApprovalDeciderToml::Declaration =>
                {
                    CapabilityId::new(object.id.as_str()).ok()
                }
                _ => None,
            })
            .filter(|id| contracts.contains_key(id))
            .collect();
        Ok(RevisionMaterial {
            revision,
            contracts: Arc::new(contracts),
            admission_digest: admission,
            seat_operation_bindings,
            session_lanes: inputs.session_lanes,
            tool_index,
            contract_adapters,
            declaration_decided,
            escalation_targets: objects
                .iter()
                .filter_map(|object| match &object.config {
                    ObjectConfig::Seat(seat) if seat.enabled && seat.conversation.is_some() => {
                        SeatId::new(object.id.as_str()).ok()
                    }
                    _ => None,
                })
                .collect(),
        })
    }
}

/// Omits launches whose provider or container is absent from the retained generation.
/// Current configuration is validated separately at startup.
fn config_for_generation(config: &OdindConfig, objects: &[RegistryObject]) -> OdindConfig {
    let mut config = config.clone();
    retain_generation_launches(&mut config.seats, objects);
    config
}

fn retain_generation_launches(
    seats: &mut [odin_huginn::config::OdindSeatBinding],
    objects: &[RegistryObject],
) {
    let index = ObjectIndex::new(objects);
    let enabled = |kind: RegistryKind, id: &str| index.enabled(kind, id);
    for seat in seats {
        seat.launch_options.retain(|option| {
            enabled(RegistryKind::Provider, option.provider.as_str())
                && enabled(RegistryKind::Container, option.container_id.as_str())
        });
    }
}

impl RevisionMaterialSource for StoreRevisionMaterial {
    fn composition_digest_at(
        &self,
        revision: u64,
    ) -> Result<odin_registry::CompositionDigest, String> {
        composition_digest_at(&self.store, revision).map_err(|error| error.to_string())
    }

    fn material_at(&self, revision: u64) -> Result<RevisionMaterial, String> {
        let (snapshot, _receipt) = self
            .store
            .publication_at(revision)
            .map_err(|error| format!("retained publication {revision} is unavailable: {error}"))?;
        self.material_for_objects(&snapshot.objects, revision)
    }

    /// Resolves a legacy token only when exactly one retained publication
    /// matches its signed digests and seat, slice, and lane identities.
    fn resolve_legacy(&self, token: &SeatToken) -> Result<u64, String> {
        let history = self
            .store
            .publication_history()
            .map_err(|error| format!("retained publication history is unavailable: {error}"))?;
        let wanted_lane = (token.seat.clone(), token.lane.clone());
        let mut matches: Vec<u64> = Vec::new();
        for (snapshot, _receipt) in &history {
            // An uncomposable publication cannot be excluded from possible matches.
            let material = match self.material_for_objects(&snapshot.objects, snapshot.revision) {
                Ok(material) => material,
                Err(error) => {
                    return Err(format!(
                        "retained publication {} cannot be recomposed to test the token's \
                         generation: {error}; re-open the session under the current revision",
                        snapshot.revision
                    ));
                }
            };
            if material.admission_digest != token.capability_policy_digest {
                continue;
            }
            let Some(policy) = material.seat_operation_bindings.get(&wanted_lane) else {
                // Proven absence: the publication composed and binds no
                // policy for this seat/lane, so it cannot be the admission.
                continue;
            };
            // The full signed identity must match — seat, slice, and lane
            // fields included, not just the map key or the digests.
            let policy_matches = policy.policy.seat_id == token.seat
                && policy.policy.slice_id == token.slice
                && policy.policy.lane_id == token.lane
                && policy.policy.seat_revision == token.seat_revision
                && policy.policy.slice_revision == token.slice_revision
                && policy.policy.capability_policy_digest == token.capability_policy_digest
                && policy.context_policy_digest == token.context_policy_digest;
            if policy_matches {
                matches.push(snapshot.revision);
            }
        }
        match matches.as_slice() {
            [only] => Ok(*only),
            [] => Err(
                "no retained publication's material matches the token's signed digests".to_owned(),
            ),
            multiple => Err(format!(
                "the token's digests match multiple retained publications ({})",
                multiple
                    .iter()
                    .map(std::string::ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(", ")
            )),
        }
    }
}

/// One compiled OPERATOR capability tuple: a capability whose concrete owner
/// is the one-shot operator CLI surface, never a session HostTool.
///
/// Governed archive ingest is such a capability. Its exact R3 demand binds
/// `archive.source` as the approval target and the (source, declaration,
/// content) digest as the approval arguments, while every kernel-dispatched
/// host tool binds the calling run as its target (`invocation_target` in the
/// host operation surface) — so one capability can never be both, and the
/// model-dispatch catalog stays host-only. The tuple is compiled here, is
/// admitted by registry publication exactly like a host-tool tuple, and is
/// re-verified field-for-field by the operator path that owns the work.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OperatorCapabilityBinding {
    /// The logical capability this operator tuple admits.
    pub capability: &'static str,
    /// The `implementation` value the declaration must carry. It marks the
    /// capability as operator-owned, so the host-tool catalog never claims a
    /// HostTool owner for it.
    pub implementation: &'static str,
    /// The exact capability version the binding admits.
    pub version: u16,
    /// The dedicated input schema the admitted tuple must declare.
    pub input_schema: &'static str,
    /// The dedicated output schema the admitted tuple must declare.
    pub output_schema: &'static str,
    /// The compiled handler id the admitted tuple must name.
    pub handler: &'static str,
    /// The compiled evidence-extractor id the admitted tuple must name.
    pub evidence_extractor: &'static str,
    /// The exact run ceiling, in seconds, the operator command enforces for
    /// this capability: the one-shot path bounds the run with it, so the
    /// published declaration can never promise a ceiling the path ignores.
    pub timeout_seconds: u32,
    /// The exact dispatch-retry policy the declaration must carry. The
    /// operator path never retries automatically — an identical rerun is an
    /// explicit operator command that replays or resumes — so the declared
    /// value is fixed here and drift is refused.
    pub retry_max_attempts: u8,
    /// The exact seat tag the declaration must carry: the operator surface
    /// is the sole holder of this capability, and no session dispatch route
    /// exists for it.
    pub seat_tag: &'static str,
    /// The approval decider the admitted declaration must carry; drift is
    /// refused. `Declaration` has the operator path decide the standing
    /// demand itself (`declaration:<device>`), never the owner.
    pub approval_decider: odin_registry::schema::ApprovalDeciderToml,
    /// The compiled owner: the operator command surface implementing the
    /// capability. Declared data, never a dispatch route.
    pub owner: &'static str,
}

impl OperatorCapabilityBinding {
    /// The registry admission input this tuple compiles to.
    pub fn admitted_binding(&self) -> odin_registry::relational::AdmittedBinding {
        odin_registry::relational::AdmittedBinding {
            version: self.version,
            input_schema: self.input_schema.to_owned(),
            output_schema: self.output_schema.to_owned(),
            handler: odin_registry::schema::HandlerBindingToml::Builtin(
                odin_registry::schema::BuiltinHandlerToml {
                    id: self.handler.to_owned(),
                },
            ),
            evidence_extractor: odin_registry::schema::HandlerBindingToml::Builtin(
                odin_registry::schema::BuiltinHandlerToml {
                    id: self.evidence_extractor.to_owned(),
                },
            ),
        }
    }
}

/// The compiled operator tuples this build owns. Enabled declarations naming
/// one of these are admitted at publication; nothing here is a model tool.
pub const OPERATOR_CAPABILITY_BINDINGS: &[&OperatorCapabilityBinding] = &[&ARCHIVE_INGEST_BINDING];

/// The governed archive ingest: R3, declaration-decided demand, idempotency
/// required; admitted against exactly this compiled tuple.
pub const ARCHIVE_INGEST_BINDING: OperatorCapabilityBinding = OperatorCapabilityBinding {
    capability: "archive.ingest",
    implementation: "operator",
    version: 1,
    input_schema: "schemas/capability/archive.ingest.input.json",
    output_schema: "schemas/capability/archive.ingest.output.json",
    handler: "odind_archive_ingest",
    evidence_extractor: "odind_archive_ingest_evidence",
    timeout_seconds: 1800,
    retry_max_attempts: 0,
    seat_tag: "operator",
    approval_decider: odin_registry::schema::ApprovalDeciderToml::Declaration,
    owner: "odind archive prepare|ingest|status|backfill",
};

/// The complete compiled registry-admission catalog: every host-tool tuple
/// this build dispatches plus every operator tuple it owns. Registry
/// publication and every validation of a full enabled snapshot compose
/// exactly this set, so a caller can never admit a strict subset.
pub fn admitted_registry_bindings() -> Vec<odin_registry::relational::AdmittedBinding> {
    odin_omp::host_tools::production_bindings()
        .iter()
        .map(|binding| binding.to_admitted_binding())
        .chain(
            OPERATOR_CAPABILITY_BINDINGS
                .iter()
                .map(|binding| binding.admitted_binding()),
        )
        .collect()
}

#[cfg(test)]
mod seat_tool_law_tests {
    use super::*;

    #[test]
    fn declared_gungnir_builder_authorizes_claude_lifecycle_only_with_exact_grants() {
        use odin_kernel::approval::ApprovalGate;
        use odin_kernel::capability::{
            list_capabilities, AuthorizationRejection, InvocationTarget, ToolInvocation,
        };
        use odin_kernel::policy::{
            arguments_digest, authorize, AuthorizationEnvironment, AuthorizationOutcome, PlanGate,
        };
        use odin_kernel::token::{
            ExpectedBindings, FreshAuthority, MemoryRevocations, MintRequest, TokenIssuer,
        };
        use odin_omp::host_tools::operations::FilesystemSchemaCatalog;

        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let objects =
            odin_registry::parse_objects(&odin_registry::walk(root.join("registry")).objects)
                .objects;
        let contracts = operation_contracts(&objects).expect("repository capability contracts");
        let schemas = FilesystemSchemaCatalog::new(&root);
        let seat = SeatId::new("gungnir").unwrap();
        let lane = LaneId::new("gungnir-odin").unwrap();
        let binding = odin_omp::live::supervisor::LiveSeatBinding {
            seat_id: seat.clone(),
            slice_id: odin_domain::SliceId::new("gungnir-build").unwrap(),
            display_name: "Gungnir".to_owned(),
            launch_options: Vec::new(),
            allowed_nodes: vec![NodeId::new("mini").unwrap()],
            max_sessions: 1,
            turn_budget: None,
        };
        let lanes = BTreeMap::from([(
            (seat.clone(), ProjectId::new("odin").unwrap()),
            lane.clone(),
        )]);
        let bindings = seat_operation_bindings(
            &objects,
            std::slice::from_ref(&binding),
            &lanes,
            admission_digest(&contracts, 1).unwrap(),
        )
        .expect("parsed Gungnir operation policy");
        let bound = &bindings[&(seat, lane)];
        let policy = &bound.policy;
        assert!(policy.seat_categories.contains("builder"));
        assert!(!policy.seat_categories.contains("coordinator"));

        let session = odin_domain::SessionId::new("00000000-0000-4000-8000-000000000001").unwrap();
        let key = b"Gungnir Claude authorization regression";
        let issuer = TokenIssuer::new(key.to_vec()).unwrap();
        let token = issuer
            .mint(MintRequest {
                seat: policy.seat_id.clone(),
                slice: policy.slice_id.clone(),
                lane: policy.lane_id.clone(),
                session: session.clone(),
                seat_revision: policy.seat_revision,
                slice_revision: policy.slice_revision,
                capability_policy_digest: policy.capability_policy_digest,
                context_policy_digest: bound.context_policy_digest,
                issued_at_ms: 0,
                expires_at_ms: 1_000,
                entropy: b"gungnir-claude",
            })
            .unwrap();
        let fresh = FreshAuthority::verify(
            &token,
            ExpectedBindings {
                seat: &policy.seat_id,
                slice: &policy.slice_id,
                lane: &policy.lane_id,
                session: &session,
                seat_revision: policy.seat_revision,
                slice_revision: policy.slice_revision,
                capability_policy_digest: policy.capability_policy_digest,
                context_policy_digest: bound.context_policy_digest,
            },
            key.to_vec(),
            MemoryRevocations::new(),
            20,
        )
        .unwrap();
        let authority = fresh.get();
        let listing = list_capabilities(authority, policy, &contracts, &schemas, 20).unwrap();

        for (name, arguments) in [
            (
                "claude.open",
                serde_json::json!({"account": "colin", "project": "odin"}),
            ),
            (
                "claude.prompt",
                serde_json::json!({"session": "claude-test", "text": "Inspect the workspace"}),
            ),
            ("claude.read", serde_json::json!({"session": "claude-test"})),
            ("claude.stop", serde_json::json!({"session": "claude-test"})),
        ] {
            let capability = CapabilityId::new(name).unwrap();
            let contract = &contracts[&capability];
            let invocation = ToolInvocation {
                command_id: odin_domain::CommandId::new(format!("gungnir-{name}")).unwrap(),
                capability_id: capability.clone(),
                capability_version: contract.version,
                listing_digest: listing.digest,
                arguments_digest: arguments_digest(&arguments),
                arguments,
                target: InvocationTarget {
                    kind: "lane".to_owned(),
                    id: policy.lane_id.to_string(),
                },
                executor_binding: None,
                expected_revision: None,
                plan_id: Some(odin_domain::PlanId::new("gungnir-claude-plan").unwrap()),
                approval_id: None,
                resource: None,
            };
            let authorize_with = |context: &odin_kernel::policy::PolicyContext| {
                let mut ledger = odin_ledger::Ledger::open_in_memory().unwrap();
                let mut approvals = ApprovalGate::new(&mut ledger);
                authorize(
                    AuthorizationEnvironment {
                        authority,
                        policy: context,
                        contracts: &contracts,
                        schemas: &schemas,
                        listing: &listing,
                    },
                    &invocation,
                    PlanGate::Accepted,
                    &mut approvals,
                    20,
                )
                .unwrap()
            };
            let outcome = authorize_with(policy);
            assert!(
                matches!(outcome, AuthorizationOutcome::Authorized(_)),
                "declared Gungnir builder must authorize {name}: {outcome:?}"
            );

            // A listing minted with the grant cannot preserve authority after
            // any layer of the effective permission intersection loses it.
            for omission in ["builder category", "slice capability", "seat tool ref"] {
                let mut narrowed = policy.clone();
                match omission {
                    "builder category" => {
                        narrowed.seat_categories.remove("builder");
                    }
                    "slice capability" => {
                        narrowed.slice_capabilities.remove(&capability);
                    }
                    _ => {
                        narrowed.seat_tool_refs.remove(&capability);
                    }
                }
                let outcome = authorize_with(&narrowed);
                assert!(
                    matches!(
                        outcome,
                        AuthorizationOutcome::Rejected(AuthorizationRejection::Unavailable { .. })
                    ),
                    "{name} must be refused without its {omission}: {outcome:?}"
                );
            }
        }
    }

    /// A conversation can remain bound to a generation published before
    /// another seat gains a provider launch. The generation's view leaves
    /// out launches it never declared and keeps the rest; Codex represents
    /// the newer provider here.
    #[test]
    fn an_older_generation_leaves_out_launches_it_never_declared() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../registry");
        let objects: Vec<_> = odin_registry::parse_objects(&odin_registry::walk(&root).objects)
            .objects
            .into_iter()
            .filter(|object| object.id != "codex")
            .collect();
        let option = |provider: &str| odin_domain::huginn::LiveLaunchOption {
            provider: odin_domain::huginn::ProviderName::new(provider).expect("provider"),
            model: odin_domain::huginn::ModelName::new("m").expect("model"),
            skeleton_ref: "gungnir-native".to_owned(),
            container_id: odin_domain::ContainerId::new("gungnir-native").expect("container"),
            harness: None,
        };
        let mut seats = vec![odin_huginn::config::OdindSeatBinding {
            seat: SeatId::new("gungnir").expect("seat"),
            slice: odin_domain::SliceId::new("gungnir-build").expect("slice"),
            display_name: "Gungnir".to_owned(),
            max_sessions: 1,
            launch_options: vec![option("gateway"), option("codex")],
            allowed_nodes: vec![NodeId::new("mini").expect("node")],
            runtime: false,
        }];
        retain_generation_launches(&mut seats, &objects);
        let providers: Vec<_> = seats[0]
            .launch_options
            .iter()
            .map(|option| option.provider.as_str().to_owned())
            .collect();
        assert_eq!(providers, ["gateway"]);
    }

    #[test]
    fn a_retained_generation_recomposes_though_todays_seat_tool_law_refuses_it() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../registry");
        let mut objects = odin_registry::parse_objects(&odin_registry::walk(&root).objects).objects;
        // An older generation: the seat declared a tool its slice lacked.
        objects
            .iter_mut()
            .find_map(|object| match &mut object.config {
                ObjectConfig::Seat(seat) if object.id == "gungnir" => Some(seat),
                _ => None,
            })
            .expect("the gungnir seat")
            .tool_refs
            .insert(CapabilityId::new("web.search").expect("capability"));
        let binding: odin_omp::live::supervisor::LiveSeatBinding =
            odin_omp::live::supervisor::LiveSeatBinding {
                seat_id: SeatId::new("gungnir").expect("seat"),
                slice_id: odin_domain::SliceId::new("gungnir-build").expect("slice"),
                display_name: "Gungnir".to_owned(),
                launch_options: Vec::new(),
                allowed_nodes: vec![NodeId::new("mini").expect("node")],
                max_sessions: 1,
                turn_budget: None,
            };
        let lanes = BTreeMap::from([(
            (
                SeatId::new("gungnir").unwrap(),
                ProjectId::new("odin").unwrap(),
            ),
            LaneId::new("gungnir-odin").unwrap(),
        )]);
        seat_operation_bindings(
            &objects,
            std::slice::from_ref(&binding),
            &lanes,
            Digest::hash(b"admission"),
        )
        .expect("a retained generation recomposes");
        let refused = ensure_seat_tools_granted(&objects, std::slice::from_ref(&binding))
            .expect_err("today's law refuses the current revision");
        assert!(
            refused.contains("gungnir")
                && refused.contains("web.search")
                && refused.contains("gungnir-build"),
            "{refused}"
        );
    }
}
