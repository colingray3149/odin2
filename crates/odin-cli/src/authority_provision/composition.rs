use std::path::PathBuf;

use odin_domain::huginn::{LiveSessionId, ModelName, ProviderName};
use odin_domain::{CommandId, ProjectId, SeatId};
use odin_huginn::OdindConfig;
use odin_kernel::ExpectedBindings;
use odin_omp::host_tools::operations::{admission_digest, SeatOperationPolicy};
use odin_omp::live::supervisor::{session_id_for, LiveSeatBinding};
use odin_registry::{SnapshotHandle, SnapshotStore};

use super::token::{mint_for_composition, MintReport};

/// One exact session composition derived from the pinned snapshot and the
/// strict controller configuration through the shared runtime bindings.
#[derive(Clone)]
pub struct SessionComposition {
    pub command_id: CommandId,
    pub live_session: LiveSessionId,
    /// The token-bound session identity; the token file is named after it.
    pub session: odin_domain::SessionId,
    pub seat: SeatId,
    pub project: ProjectId,
    pub slice: odin_domain::SliceId,
    pub lane: odin_domain::LaneId,
    pub provider: odin_domain::huginn::ProviderName,
    pub model: odin_domain::huginn::ModelName,
    pub project_root: PathBuf,
    pub snapshot_revision: u64,
    pub admission_digest: odin_domain::Digest,
    pub policy: SeatOperationPolicy,
}

impl std::fmt::Debug for SessionComposition {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SessionComposition")
            .field("command_id", &self.command_id)
            .field("live_session", &self.live_session)
            .field("session", &self.session)
            .field("seat", &self.seat)
            .field("project", &self.project)
            .field("slice", &self.slice)
            .field("lane", &self.lane)
            .field("provider", &self.provider)
            .field("model", &self.model)
            .field("project_root", &self.project_root)
            .field("snapshot_revision", &self.snapshot_revision)
            .field("admission_digest", &self.admission_digest)
            .finish_non_exhaustive()
    }
}

pub(super) fn expected_bindings(composition: &SessionComposition) -> ExpectedBindings<'_> {
    ExpectedBindings {
        seat: &composition.seat,
        slice: &composition.slice,
        lane: &composition.lane,
        session: &composition.session,
        seat_revision: composition.policy.policy.seat_revision,
        slice_revision: composition.policy.policy.slice_revision,
        capability_policy_digest: composition.policy.policy.capability_policy_digest,
        context_policy_digest: composition.policy.context_policy_digest,
    }
}

/// The launch one session entry explicitly selects: the `(provider, model)`
/// pair named by the operator, the caller, or durable session state. It
/// carries the selection only — whether the seat DECLARES the pair is proven
/// by `LiveSeatBinding::declared_launch_option` inside the derivation, so
/// carrying a selection never asserts membership.
#[derive(Clone, Copy, Debug)]
pub struct LaunchSelection<'a> {
    provider: &'a str,
    model: &'a str,
}

impl<'a> LaunchSelection<'a> {
    pub fn new(provider: &'a str, model: &'a str) -> Self {
        Self { provider, model }
    }
}

/// Derives the exact seat/slice/lane/launch composition of one operator
/// command from the verified published snapshot and the strict configuration.
///
/// `selection` names the declared launch the session opens with; the
/// derivation proves it one of the seat's declared launch options before
/// anything is minted, so declaration order is never a default. The live
/// session identity is the supervisor's own deterministic derivation of the
/// command identity (`session_id_for`), so a token minted here always binds
/// the session the daemon will actually open for this command. A command id
/// never names an already-existing session: composition for a durable
/// session recovered from durable state uses [`compose_for_session`].
pub fn compose(
    config: &OdindConfig,
    seat: &str,
    project: &str,
    command_id: &CommandId,
    selection: LaunchSelection<'_>,
) -> Result<SessionComposition, String> {
    let live_session = session_id_for(command_id).map_err(|error| error.to_string())?;
    compose_for_session(config, seat, project, command_id, live_session, selection)
}

/// Composes the exact authority of one already-existing durable session.
///
/// `live_session` is the session identity carried by durable state — NOT a
/// derivation of `command_id`; the command id stays governance provenance
/// only, and pretending every command hashes to the durable session would
/// mint authority for a session the daemon never opened. `selection` is the
/// durable session's OWN persisted pair, passed through unchanged and
/// revalidated against the declaration, so a recovered session never
/// silently changes model. Every other derivation comes from the current
/// published snapshot exactly as [`compose`] derives it, so the ensured
/// token carries the current published policy under the durable session's
/// exact identity.
pub fn compose_for_session(
    config: &OdindConfig,
    seat: &str,
    project: &str,
    command_id: &CommandId,
    live_session: LiveSessionId,
    selection: LaunchSelection<'_>,
) -> Result<SessionComposition, String> {
    config
        .validate()
        .map_err(|error| format!("controller configuration is invalid: {error}"))?;
    let seat_id = SeatId::new(seat).map_err(|error| format!("invalid seat {seat:?}: {error}"))?;
    let project_id =
        ProjectId::new(project).map_err(|error| format!("invalid project {project:?}: {error}"))?;
    let snapshot = SnapshotHandle::open(SnapshotStore::new(&config.paths.registry_snapshot))
        .map_err(|error| format!("published registry snapshot is invalid: {error}"))?
        .current();
    derive_for_session(
        config,
        seat_id,
        project_id,
        command_id,
        live_session,
        snapshot.as_ref(),
        selection,
    )
}

/// Composes the exact authority of one session against ONE SPECIFIC
/// retained publication. The workload launch path pins the revision its
/// kube admission captured, so the ensured token binds the admitted
/// snapshot generation even when a later publication has already landed —
/// authority never silently widens past the approved material. The
/// revision must still be retained; a pruned publication refuses typed.
/// `selection` is the persisted pair of that same durable session,
/// revalidated against the RETAINED generation's declaration.
pub fn compose_for_session_at_revision(
    config: &OdindConfig,
    seat: &str,
    project: &str,
    command_id: &CommandId,
    live_session: LiveSessionId,
    revision: u64,
    selection: LaunchSelection<'_>,
) -> Result<SessionComposition, String> {
    config
        .validate()
        .map_err(|error| format!("controller configuration is invalid: {error}"))?;
    let seat_id = SeatId::new(seat).map_err(|error| format!("invalid seat {seat:?}: {error}"))?;
    let project_id =
        ProjectId::new(project).map_err(|error| format!("invalid project {project:?}: {error}"))?;
    let store = SnapshotStore::new(&config.paths.registry_snapshot);
    let (snapshot, _receipt) = store
        .publication_at(revision)
        .map_err(|error| format!("retained publication {revision} is unavailable: {error}"))?;
    derive_for_session(
        config,
        seat_id,
        project_id,
        command_id,
        live_session,
        &snapshot,
        selection,
    )
}

/// Launch and policy inputs shared by preflight and execution, without session
/// identities or token issuance, so invalid declarations fail before approval.
#[derive(Clone)]
pub struct LaunchReadiness {
    /// The seat's pinned session lane for the project.
    pub lane: odin_domain::LaneId,
    /// The seat's declared slice.
    pub slice: odin_domain::SliceId,
    /// The explicitly selected launch provider, proven a declared launch
    /// option of the seat's live binding.
    pub provider: odin_domain::huginn::ProviderName,
    /// The explicitly selected launch model, proven a declared launch
    /// option of the seat's live binding.
    pub model: odin_domain::huginn::ModelName,
    /// The publication's admission digest over the operation contracts.
    pub admission_digest: odin_domain::Digest,
    /// The (seat, lane) operation policy binding, exactly as composed.
    pub policy: odin_omp::host_tools::operations::SeatOperationPolicy,
    /// The project's configured root.
    pub project_root: PathBuf,
}

impl std::fmt::Debug for LaunchReadiness {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("LaunchReadiness")
            .field("lane", &self.lane)
            .field("slice", &self.slice)
            .field("provider", &self.provider)
            .field("model", &self.model)
            .field("admission_digest", &self.admission_digest)
            .field("project_root", &self.project_root)
            .finish_non_exhaustive()
    }
}

/// Resolves declared lane, launch, admission digest, policy, and project root
/// without minting, writing, or reserving resources.
fn derive_launch(
    inputs: &crate::runtime_bindings::RuntimeInputs,
    seat_id: &SeatId,
    project_id: &ProjectId,
    objects: &[odin_registry::RegistryObject],
    revision: u64,
    selection: LaunchSelection<'_>,
) -> Result<LaunchReadiness, String> {
    let lane = inputs
        .session_lanes
        .get(&(seat_id.clone(), project_id.clone()))
        .cloned()
        .ok_or_else(|| {
            format!("seat {seat_id} has no configured session lane for project {project_id}")
        })?;
    let binding = inputs
        .seat_bindings
        .iter()
        .find(|binding| binding.seat_id == *seat_id)
        .ok_or_else(|| format!("seat {seat_id} has no configured live seat binding"))?;
    // Use the supervisor's predicate so composition cannot admit a rejected launch.
    let provider = ProviderName::new(selection.provider)
        .map_err(|error| format!("selected launch provider is invalid: {error}"))?;
    let model = ModelName::new(selection.model)
        .map_err(|error| format!("selected launch model is invalid: {error}"))?;
    if binding.declared_launch_option(&provider, &model).is_none() {
        return Err(format!(
            "seat {seat_id} does not declare the selected launch {provider}/{model}; its \
             declared launch options are {}",
            declared_launch_options(binding)
        ));
    }
    let snapshot_revision = i64::try_from(revision).map_err(|_| {
        format!("snapshot revision {revision} exceeds the admission revision range")
    })?;
    let contracts = crate::runtime_bindings::operation_contracts(objects)?;
    let admission = admission_digest(&contracts, snapshot_revision)
        .map_err(|error| format!("admission digest failed: {error}"))?;
    let mut policies = crate::runtime_bindings::seat_operation_bindings(
        objects,
        &inputs.seat_bindings,
        &inputs.session_lanes,
        admission,
    )?;
    let policy = policies
        .remove(&(seat_id.clone(), lane.clone()))
        .ok_or_else(|| format!("seat {seat_id} lane {lane} has no operation policy binding",))?;
    let project_root = inputs
        .project_roots
        .get(project_id)
        .cloned()
        .ok_or_else(|| format!("project {project_id} has no configured root"))?;
    Ok(LaunchReadiness {
        lane,
        slice: binding.slice_id.clone(),
        provider,
        model,
        admission_digest: admission,
        policy,
        project_root,
    })
}

/// Renders a binding's declared launch options for a typed refusal. A seat
/// that declares none says so explicitly, so the refusal never reads as a
/// truncated list.
fn declared_launch_options(binding: &LiveSeatBinding) -> String {
    if binding.launch_options.is_empty() {
        return "none declared".to_owned();
    }
    binding
        .launch_options
        .iter()
        .map(|option| format!("{}/{}", option.provider, option.model))
        .collect::<Vec<_>>()
        .join(", ")
}

/// The one composition derivation shared by every entry point: a validated
/// configuration plus one publication derive the exact seat/slice/lane/launch
/// authority of the selected declared launch, and the publication's revision
/// rides the composition as its admitted generation.
fn derive_for_session(
    config: &OdindConfig,
    seat_id: SeatId,
    project_id: ProjectId,
    command_id: &CommandId,
    live_session: LiveSessionId,
    snapshot: &odin_registry::Snapshot,
    selection: LaunchSelection<'_>,
) -> Result<SessionComposition, String> {
    let inputs = crate::runtime_bindings::RuntimeInputs::parse(config, &snapshot.objects)?;
    let readiness = derive_launch(
        &inputs,
        &seat_id,
        &project_id,
        &snapshot.objects,
        snapshot.revision,
        selection,
    )?;
    let session = odin_domain::SessionId::parse(&live_session.to_string())
        .map_err(|error| format!("the pinned session identity is invalid: {error}"))?;
    Ok(SessionComposition {
        command_id: command_id.clone(),
        live_session,
        session,
        seat: seat_id,
        project: project_id,
        slice: readiness.slice,
        lane: readiness.lane,
        provider: readiness.provider,
        model: readiness.model,
        project_root: readiness.project_root,
        snapshot_revision: snapshot.revision,
        admission_digest: readiness.admission_digest,
        policy: readiness.policy,
    })
}

/// Runs composition against the current snapshot before approval, without
/// generating command identities, minting tokens, or writing state.
pub fn preflight_compose(
    config: &OdindConfig,
    seat: &str,
    project: &str,
    selection: LaunchSelection<'_>,
) -> Result<LaunchReadiness, String> {
    config
        .validate()
        .map_err(|error| format!("controller configuration is invalid: {error}"))?;
    let seat_id = SeatId::new(seat).map_err(|error| format!("invalid seat {seat:?}: {error}"))?;
    let project_id =
        ProjectId::new(project).map_err(|error| format!("invalid project {project:?}: {error}"))?;
    let snapshot = SnapshotHandle::open(SnapshotStore::new(&config.paths.registry_snapshot))
        .map_err(|error| format!("published registry snapshot is invalid: {error}"))?
        .current();
    let inputs = crate::runtime_bindings::RuntimeInputs::parse(config, &snapshot.objects)?;
    derive_launch(
        &inputs,
        &seat_id,
        &project_id,
        &snapshot.objects,
        snapshot.revision,
        selection,
    )
}

/// Mints and writes the provisioned token file for one host-side child
/// composition using the identical private-write path as the operator mint.
/// `renew` must be `false` here: a child token that already exists for the
/// same session identity is a composition conflict, never something the host
/// silently replaces.
pub fn mint_for_child_session(
    config: &OdindConfig,
    composition: &SessionComposition,
    ttl_seconds: u64,
) -> Result<MintReport, String> {
    mint_for_composition(config, composition, ttl_seconds, false)
}

#[cfg(test)]
#[path = "composition_tests.rs"]
mod tests;
