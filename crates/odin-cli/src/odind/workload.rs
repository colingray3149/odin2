//! Declared workload environment composition: the daemon-side consumer of
//! published workload profiles. Every enabled profile whose bound seat and
//! session lane this daemon actually serves composes one
//! [`WorkloadSessionLaw`] — the declared brief and the memory namespace the
//! per-turn facts refresh retrieves through the bound seat's own brain
//! service — plus the exact model policy resolved from the profile's
//! gateway lane against the seat's odind `launch_options` (the same list
//! the supervisor admission enforces). A lane with no enabled provider
//! route composes as typed [`WorkloadModelPolicy::Unavailable`] carrying
//! the seat's other declared, route-reachable launch options as the
//! fallback OFFER — never an automatic swap.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use odin_domain::huginn as live;
use odin_domain::{CommandId, LaneId, NodeId, ProjectId, SeatId, SliceId};
use odin_omp::live::supervisor::LiveSeatBinding;
use odin_registry::RegistryKind;
use odin_types::OperationId;

use odin_omp::live::runtime::WorkloadSessionLaw;

/// The bound-seat model policy of one composed workload profile, resolved
/// against the seat's exact odind launch options.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum WorkloadModelPolicy {
    /// The declared gateway lane resolves through exactly one enabled
    /// provider route, and the resolved (provider, model) is one of the
    /// seat's declared launch options: the admitted exact policy.
    Exact { provider: String, model: String },
    /// The declared lane is dead for this seat (no enabled provider route,
    /// or the resolved model is not among the seat's launch options). The
    /// other route-reachable declared options of the same seat ride as the
    /// fallback OFFER — rendered as one sentence by the caller, never
    /// applied without an explicit approved choice.
    Unavailable {
        lane: String,
        reason: String,
        fallback: Vec<(String, String)>,
    },
}

/// Every workload profile this daemon composes, keyed by the exact
/// published profile id.
pub(crate) struct WorkloadComposition {
    pub laws: BTreeMap<String, WorkloadSessionLaw>,
    pub models: BTreeMap<String, WorkloadModelPolicy>,
    /// The served session slice, lane, and the daemon's declared serving
    /// node per profile id — the admission facts the session open needs.
    pub bindings: BTreeMap<String, (SliceId, LaneId, NodeId)>,
    /// Unservable profiles retain launch refusal reasons; check and generation remain strict.
    pub skipped: BTreeMap<String, String>,
}

/// Compose served workload policies, collecting per-profile wiring errors in `skipped`.
pub(crate) fn compose_workload(
    registry: &[odin_registry::RegistryObject],
    seat_bindings: &[LiveSeatBinding],
    session_lanes: &BTreeMap<(SeatId, ProjectId), odin_domain::LaneId>,
    brain_atlas_sources: &BTreeMap<SeatId, BTreeSet<String>>,
    serving_node: &NodeId,
) -> Result<WorkloadComposition, String> {
    let mut provider_routes: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    for object in registry {
        if object.kind() != RegistryKind::Provider || !object.enabled() {
            continue;
        }
        let odin_registry::ObjectConfig::Provider(provider) = &object.config else {
            continue;
        };
        for route in &provider.policy.routes {
            provider_routes
                .entry(route.gateway_lane_id.as_str())
                .or_default()
                .push(object.id.as_str());
        }
    }
    let context_profiles = odin_registry::context_profiles(registry);
    let mut laws = BTreeMap::new();
    let mut bindings = BTreeMap::new();
    let mut models = BTreeMap::new();
    let mut skipped = BTreeMap::new();
    for profile in odin_registry::compose_workload_profiles(registry) {
        // Script pods run commands without agent sessions or model policies.
        let Some(agent) = profile.profile.agent() else {
            continue;
        };
        let composed = (|| -> Result<_, String> {
            let seat = SeatId::new(profile.profile.seat.seat.as_str())
                .map_err(|error| format!("workload {}: invalid seat: {error}", profile.id))?;
            let binding = seat_bindings
                .iter()
                .find(|served| served.seat_id == seat)
                .ok_or_else(|| {
                    format!(
                        "workload {}: seat {} is not served by this daemon",
                        profile.id, seat
                    )
                })?;
            let project = ProjectId::new(profile.profile.seat.project.as_str())
                .map_err(|error| format!("workload {}: invalid project: {error}", profile.id))?;
            let lane = session_lanes
                .get(&(seat.clone(), project.clone()))
                .ok_or_else(|| {
                    format!(
                        "workload {}: project {} of seat {} has no served session lane",
                        profile.id, profile.profile.seat.project, seat
                    )
                })?
                .clone();
            let authorized = brain_atlas_sources.get(&seat).ok_or_else(|| {
                format!(
                    "workload {}: seat {} serves no brain policy for the memory namespace",
                    profile.id, seat
                )
            })?;
            if !authorized.contains(&agent.memory.namespace) {
                return Err(format!(
                    "workload {}: memory namespace {} is outside seat {} brain scope",
                    profile.id, agent.memory.namespace, seat
                ));
            }
            let namespace =
                odin_domain::knowledge::AtlasId::new(&agent.memory.namespace).map_err(|error| {
                    format!(
                        "workload {}: memory namespace is not a valid atlas id: {error}",
                        profile.id
                    )
                })?;
            // The pod's memory profile sizes the facts one context epoch
            // carries; without one, eight. The seat's knowledge policy
            // bounds the retrieval itself.
            let max_facts = match agent.memory.profile.as_deref() {
                None => 8,
                Some(name) => context_profiles
                    .get(name)
                    .filter(|declared| declared.enabled)
                    .map(|declared| declared.inject_k.get())
                    .ok_or_else(|| {
                        format!(
                            "workload {}: memory profile {name:?} is not an enabled context-profile",
                            profile.id
                        )
                    })?,
            };
            laws.insert(
                profile.id.clone(),
                WorkloadSessionLaw {
                    brief: profile.profile.brief.text.clone(),
                    memory_namespace: namespace,
                    max_facts,
                    tools: profile.profile.tools.iter().cloned().collect(),
                },
            );
            models.insert(
                profile.id.clone(),
                resolve_model(&profile.id, agent.gateway_lane, binding, &provider_routes),
            );
            // The seat must explicitly admit the daemon's declared node; never choose by position.
            if !binding.allowed_nodes.contains(serving_node) {
                return Err(format!(
                    "workload {}: seat {} binding does not allow the daemon's \
                     declared serving node {}",
                    profile.id, seat, serving_node
                ));
            }
            let target_node = serving_node.clone();
            bindings.insert(
                profile.id.clone(),
                (binding.slice_id.clone(), lane, target_node),
            );
            Ok(())
        })();
        if let Err(reason) = composed {
            laws.remove(&profile.id);
            models.remove(&profile.id);
            bindings.remove(&profile.id);
            skipped.insert(profile.id.clone(), reason);
        }
    }
    Ok(WorkloadComposition {
        laws,
        models,
        bindings,
        skipped,
    })
}

/// The per-seat brain scope workload composition checks memory namespaces
/// against: every served seat policy's authorized atlas sources. Shared by
/// the daemon startup composition and `odind check` so both run the
/// identical subset.
pub(crate) fn brain_source_scopes(
    policies: &BTreeMap<odin_domain::SeatId, odin_brain::config::EffectiveBrainPolicy>,
) -> BTreeMap<SeatId, BTreeSet<String>> {
    policies
        .iter()
        .map(|(seat, policy)| {
            (
                seat.clone(),
                policy
                    .knowledge
                    .as_ref()
                    .map(|knowledge| {
                        knowledge
                            .atlas_sources
                            .iter()
                            .map(|id| id.as_str().to_owned())
                            .collect()
                    })
                    .unwrap_or_default(),
            )
        })
        .collect()
}

/// Strictly validate exact model routes and declared credentials for check/generation.
/// Unavailable model policies remain launch-time refusals with their declared fallback offers.
pub(crate) fn validate_workload_gateway_routes(
    config: &odin_huginn::OdindConfig,
    composition: &WorkloadComposition,
) -> Result<(), String> {
    if let Some((profile, reason)) = composition.skipped.iter().next() {
        return Err(format!("workload {profile}: {reason}"));
    }
    if composition.models.is_empty() {
        return Ok(());
    }
    let projection = crate::projection::load_gateway_projection(config)?;
    validate_workload_routes(config, &projection, composition)
}

/// Move unresolvable profiles to `skipped` without stopping the serving daemon.
pub(crate) fn retain_servable_workloads(
    config: &odin_huginn::OdindConfig,
    composition: &mut WorkloadComposition,
) {
    let projection = match crate::projection::load_gateway_projection(config) {
        Ok(projection) => projection,
        Err(reason) => {
            for profile in composition.models.keys() {
                composition.skipped.insert(profile.clone(), reason.clone());
            }
            composition.models.clear();
            composition.laws.clear();
            composition.bindings.clear();
            return;
        }
    };
    retain_servable_with(config, &projection, composition);
}

/// [`retain_servable_workloads`] over an already loaded projection.
pub(crate) fn retain_servable_with(
    config: &odin_huginn::OdindConfig,
    projection: &odin_registry::GatewayProjectionManifest,
    composition: &mut WorkloadComposition,
) {
    let profiles: Vec<String> = composition.models.keys().cloned().collect();
    for profile in profiles {
        let single = WorkloadComposition {
            laws: BTreeMap::new(),
            models: composition
                .models
                .get(&profile)
                .cloned()
                .into_iter()
                .map(|m| (profile.clone(), m))
                .collect(),
            bindings: composition
                .bindings
                .get(&profile)
                .cloned()
                .into_iter()
                .map(|b| (profile.clone(), b))
                .collect(),
            skipped: BTreeMap::new(),
        };
        if let Err(reason) = validate_workload_routes(config, projection, &single) {
            composition.models.remove(&profile);
            composition.laws.remove(&profile);
            composition.bindings.remove(&profile);
            composition.skipped.insert(profile, reason);
        }
    }
}

/// Shared exact lane/model and credential validation for startup, check, and generation.
pub(crate) fn validate_workload_routes(
    config: &odin_huginn::OdindConfig,
    projection: &odin_registry::GatewayProjectionManifest,
    composition: &WorkloadComposition,
) -> Result<(), String> {
    for (profile_id, policy) in &composition.models {
        let WorkloadModelPolicy::Exact { model, .. } = policy else {
            continue;
        };
        let Some((_, lane, _)) = composition.bindings.get(profile_id) else {
            return Err(format!(
                "workload {profile_id} has a model policy but no served seat binding"
            ));
        };
        let credential_handle =
            crate::projection::workload_gateway_credential(projection, lane.as_str(), model)
                .map_err(|reason| format!("workload {profile_id}: {reason}"))?;
        if !config.kube.as_ref().is_some_and(|kube| {
            kube.gateway_credentials
                .contains_key(credential_handle.as_str())
        }) {
            return Err(format!(
                "workload {profile_id}: gateway credential handle {credential_handle:?} has no \
                 declared Secret custody"
            ));
        }
    }
    Ok(())
}

/// Resolves one profile's exact model policy: the declared gateway lane
/// must resolve through exactly one enabled provider, and the resolved
/// (provider, model) must be one of the seat's declared launch options —
/// the same admission list the supervisor enforces at session open.
fn resolve_model(
    profile_id: &str,
    lane: &str,
    binding: &LiveSeatBinding,
    provider_routes: &BTreeMap<&str, Vec<&str>>,
) -> WorkloadModelPolicy {
    let Some(providers) = provider_routes.get(lane) else {
        return WorkloadModelPolicy::Unavailable {
            lane: lane.to_owned(),
            reason: format!(
                "workload {profile_id}: gateway lane {lane:?} has no enabled provider route"
            ),
            fallback: reachable_options(binding, provider_routes),
        };
    };
    if providers.len() > 1 {
        return WorkloadModelPolicy::Unavailable {
            lane: lane.to_owned(),
            reason: format!(
                "workload {profile_id}: gateway lane {lane:?} is ambiguous across providers \
                 {providers:?}"
            ),
            fallback: reachable_options(binding, provider_routes),
        };
    }
    let provider = providers[0];
    if binding
        .launch_options
        .iter()
        .any(|option| option.provider.as_str() == provider && option.model.as_str() == lane)
    {
        WorkloadModelPolicy::Exact {
            provider: provider.to_owned(),
            model: lane.to_owned(),
        }
    } else {
        WorkloadModelPolicy::Unavailable {
            lane: lane.to_owned(),
            reason: format!(
                "workload {profile_id}: resolved model {provider}/{lane} is not among seat {} \
                 declared launch options",
                binding.seat_id
            ),
            fallback: reachable_options(binding, provider_routes),
        }
    }
}

/// Resolve the explicitly selected node's gateway, without daemon-local or positional defaults.
fn resolve_node_gateway(
    snapshot: &odin_registry::Snapshot,
    target_node: &NodeId,
) -> Result<odin_registry::schema::NodeGatewayEndpoint, String> {
    let identity =
        odin_node::config::NodeIdentity::from_snapshot(target_node.as_str(), &snapshot.objects)
            .map_err(|error| error.to_string())?;
    identity
        .gateway_endpoint()
        .map_err(|error| error.to_string())
}

/// The seat's declared launch options whose model is a lane some enabled
/// provider actually serves — the declared fallback offers for a dead
/// lane. Options without an enabled provider route are never offered.
fn reachable_options(
    binding: &LiveSeatBinding,
    provider_routes: &BTreeMap<&str, Vec<&str>>,
) -> Vec<(String, String)> {
    binding
        .launch_options
        .iter()
        .filter(|option| provider_routes.contains_key(option.model.as_str()))
        .map(|option| {
            (
                option.provider.as_str().to_owned(),
                option.model.as_str().to_owned(),
            )
        })
        .collect()
}

/// The daemon's workload launch port: the shared snapshot handle (post-
/// publish adoption is immediate — the authoring receipt reloads the
/// handle in-chain, so `current()` already names every published profile),
/// the composed surface, the supervisor armed after composition, and the
/// strict controller configuration the session-token ensure runs through.
pub(crate) struct LaunchPort {
    pub snapshot: Arc<odin_registry::SnapshotHandle>,
    pub composition: WorkloadComposition,
    pub supervisor: Arc<std::sync::OnceLock<Arc<odin_omp::live::supervisor::LiveSupervisor>>>,
    pub config: odin_huginn::OdindConfig,
    /// The deployed platform workload image (`None` without a cluster).
    pub deployment: Option<crate::kube::WorkloadDeploymentFacts>,
    /// Every served (seat, project) session lane: a script pod runs under
    /// its bound seat's lane on the declared project.
    pub session_lanes: BTreeMap<(SeatId, ProjectId), LaneId>,
}

/// The launching session's run of a pod run: a pod run is
/// `<session run>:pod:<profile>[:<generation>]` (`kube_runtime` admission),
/// so the session run is everything before the first `:pod:`.
pub(crate) fn launching_session_run(pod_run: &odin_domain::RunId) -> &str {
    pod_run
        .as_str()
        .split_once(":pod:")
        .map_or(pod_run.as_str(), |(session, _)| session)
}

#[cfg(test)]
mod launching_run_tests {
    #[test]
    fn a_pod_run_names_its_launching_session_run() {
        for (pod, session) in [
            ("run:live:abc:pod:browser-probe", "run:live:abc"),
            ("run:live:abc:pod:browser-probe:3", "run:live:abc"),
            ("run:live:abc", "run:live:abc"),
        ] {
            let run = odin_domain::RunId::new(pod).unwrap();
            assert_eq!(super::launching_session_run(&run), session);
        }
    }
}

/// Platform references track the deployed workload image; other references remain exact pins.
pub(crate) fn follow_platform_image(
    profile: &mut odin_registry::ComposedWorkloadProfile,
    deployment: Option<&crate::kube::WorkloadDeploymentFacts>,
) -> Result<(), NoDeployedPlatformImage> {
    if !profile.profile.image.is_platform() {
        return Ok(());
    }
    let deployment = deployment.ok_or_else(|| NoDeployedPlatformImage {
        profile: profile.id.clone(),
    })?;
    profile
        .profile
        .image
        .reference
        .clone_from(&deployment.image_reference);
    if let Some(runtime) = profile.profile.runtime.as_mut() {
        runtime.launcher.clone_from(&deployment.launcher);
        runtime.browser.clone_from(&deployment.browser);
        runtime.supervisor.clone_from(&deployment.supervisor);
        runtime.playwright.clone_from(&deployment.playwright);
    }
    if let Some(display) = profile.profile.display.as_mut() {
        display.xvfb.clone_from(&deployment.xvfb);
    }
    Ok(())
}

/// A "platform" profile on a daemon that declares no deployed workload
/// image identity has no image to run.
#[derive(Debug, thiserror::Error)]
#[error(
    "workload profile {profile:?} runs the platform image, but this daemon declares no \
     deployed workload image identity (kube.image_identity)"
)]
pub(crate) struct NoDeployedPlatformImage {
    profile: String,
}

impl LaunchPort {
    /// Ensure a token for the exact child session and admitted publication before opening it;
    /// failure leaves the landed Job journaled without a half-open session.
    fn ensure_session_token(
        &self,
        inputs: &crate::kube_runtime::WorkloadLaunchInputs,
        command_id: &odin_domain::CommandId,
    ) -> Result<(), String> {
        let live_session = odin_omp::live::supervisor::session_id_for(command_id)
            .map_err(|error| error.to_string())?;
        let composition = odin_cli::authority_provision::compose_for_session_at_revision(
            &self.config,
            inputs.seat.as_str(),
            inputs.project.as_str(),
            command_id,
            live_session,
            inputs.snapshot_revision,
            odin_cli::authority_provision::LaunchSelection::new(
                inputs.provider.as_str(),
                inputs.model.as_str(),
            ),
        )?;
        // The caller profile binding must stay exact: the composition the
        // token binds is the admitted seat/project/slice/lane of THIS
        // launch, never a silently re-derived neighbor from a later
        // publication or another lane.
        if composition.slice != inputs.slice_id || composition.lane != inputs.lane {
            return Err(format!(
                "workload profile {} admitted seat {} slice {} lane {}, but publication {} \
                 serves slice {} lane {}; re-resolve the launch against the published material",
                inputs.profile.id,
                inputs.seat,
                inputs.slice_id,
                inputs.lane,
                inputs.snapshot_revision,
                composition.slice,
                composition.lane,
            ));
        }
        // Mint missing tokens once; replacing expired, revoked, or mismatched tokens requires the operator.
        odin_cli::authority_provision::ensure_session_token(
            &self.config,
            &composition,
            odin_cli::authority_provision::DEFAULT_TOKEN_TTL_SECONDS,
            odin_cli::authority_provision::TokenRenewalPolicy::OperatorOnly,
        )
        .map_err(|error| {
            format!(
                "workload session {} (profile {}) has no usable authority: {error}",
                composition.live_session, inputs.profile.id
            )
        })?;
        Ok(())
    }
    fn open_request(
        &self,
        inputs: &crate::kube_runtime::WorkloadLaunchInputs,
        operation_id: &OperationId,
        launching_run: &str,
    ) -> Result<live::OpenSessionRequest, String> {
        let command_id = CommandId::new(format!("kube-workload-open:{operation_id}"))
            .map_err(|error| format!("workload open command id rejected: {error}"))?;
        let provider = live::ProviderName::new(&inputs.provider)
            .map_err(|error| format!("workload provider rejected: {error}"))?;
        let model = live::ModelName::new(&inputs.model)
            .map_err(|error| format!("workload model rejected: {error}"))?;
        Ok(live::OpenSessionRequest {
            command_id,
            seat_id: inputs.seat.clone(),
            project_id: inputs.project.clone(),
            slice_id: inputs.slice_id.clone(),
            provider,
            model,
            title: Some(inputs.profile.id.clone()),
            target_node: inputs.target_node.clone(),
            open_tab: false,
            workload: Some(live::WorkloadSessionBinding {
                profile: inputs.profile.id.clone(),
                snapshot_revision: inputs.snapshot_revision,
                operation: operation_id.to_string(),
                inputs: inputs.staged_inputs.clone(),
                launching_run: Some(launching_run.to_owned()),
            }),
            // The brief rides system guidance only; this instruction must
            // not duplicate it into the compactable transcript.
            initial_prompt: Some(live::LiveMessage {
                content: vec![live::LiveContentBlock::Text(
                    "Workload session admitted. Your session guidance carries \
                     the declared task brief; begin executing it now, grounding \
                     each step in the fresh memory facts provided with each turn."
                        .to_owned(),
                )],
            }),
            served_revision: Some(inputs.snapshot_revision),
        })
    }
}

#[async_trait::async_trait]
impl crate::kube_runtime::WorkloadLaunchPort for LaunchPort {
    fn resolve_launch(&self, profile_id: &str) -> crate::kube_runtime::WorkloadResolve {
        let snapshot = self.snapshot.current();
        let mut profile = match snapshot.workload_profile(profile_id) {
            Ok(profile) => profile,
            Err(odin_registry::WorkloadProfileLookupError::Unknown { .. }) => {
                return crate::kube_runtime::WorkloadResolve::NotWorkload
            }
            // A declared-but-disabled workload must not fall through to the
            // container path, which would answer "unknown profile".
            Err(error) => return crate::kube_runtime::WorkloadResolve::Refused(error.to_string()),
        };
        if let Err(error) = follow_platform_image(&mut profile, self.deployment.as_ref()) {
            return crate::kube_runtime::WorkloadResolve::Refused(error.to_string());
        }
        if !profile.profile.runs_agent() {
            let (seat, project) = match (
                SeatId::new(profile.profile.seat.seat.as_str()),
                ProjectId::new(profile.profile.seat.project.as_str()),
            ) {
                (Ok(seat), Ok(project)) => (seat, project),
                _ => {
                    return crate::kube_runtime::WorkloadResolve::Refused(format!(
                        "workload profile {profile_id:?} binds an invalid seat or project"
                    ))
                }
            };
            let Some(lane) = self.session_lanes.get(&(seat.clone(), project.clone())) else {
                return crate::kube_runtime::WorkloadResolve::Refused(format!(
                    "workload profile {profile_id:?}: seat {seat} has no served session lane on \
                     project {project}"
                ));
            };
            return crate::kube_runtime::WorkloadResolve::Script(Box::new(
                crate::kube_runtime::ScriptLaunchInputs {
                    lane: lane.clone(),
                    profile,
                    seat,
                    project,
                },
            ));
        }
        let Some(model) = self.composition.models.get(profile_id) else {
            return crate::kube_runtime::WorkloadResolve::Refused(
                match self.composition.skipped.get(profile_id) {
                    Some(reason) => format!(
                        "workload profile {profile_id:?} is not served by this daemon: {reason}"
                    ),
                    None => format!("workload profile {profile_id:?} is not served by this daemon"),
                },
            );
        };
        let Some((slice_id, lane, target_node)) = self.composition.bindings.get(profile_id) else {
            return crate::kube_runtime::WorkloadResolve::Refused(format!(
                "workload profile {profile_id:?} has no served seat binding"
            ));
        };
        let seat = profile.profile.seat.seat.clone();
        let project = profile.profile.seat.project.clone();
        match model {
            WorkloadModelPolicy::Exact { provider, model } => {
                // The credential handle composes from the receipt-bound
                // gateway projection at admission: exactly one eligible
                // route for this exact (lane, model) pair, else the launch
                // refuses — a missing, dead, or ambiguous route never
                // composes a plan. The route does NOT supply the address:
                // credentials and model identity stay route-declared, while
                // the pod's address is the selected node's declared gateway
                // endpoint.
                let projection = match crate::projection::load_gateway_projection(&self.config) {
                    Ok(projection) => projection,
                    Err(reason) => {
                        return crate::kube_runtime::WorkloadResolve::Refused(format!(
                            "workload profile {profile_id:?} cannot read its pinned gateway \
                             projection: {reason}"
                        ))
                    }
                };
                let credential_handle = match crate::projection::workload_gateway_credential(
                    &projection,
                    lane.as_str(),
                    model,
                ) {
                    Ok(handle) => handle,
                    Err(reason) => {
                        return crate::kube_runtime::WorkloadResolve::Refused(format!(
                            "workload profile {profile_id:?}: {reason}"
                        ))
                    }
                };
                // Require the declared Secret mapping; never infer or substitute a gateway key.
                let custody = match self
                    .config
                    .kube
                    .as_ref()
                    .and_then(|kube| kube.gateway_credentials.get(credential_handle.as_str()))
                {
                    Some(custody) => custody,
                    None => {
                        return crate::kube_runtime::WorkloadResolve::Refused(format!(
                            "workload profile {profile_id:?}: gateway credential handle \
                             {credential_handle:?} has no declared Secret custody"
                        ))
                    }
                };
                let credential = odin_kube::workload::WorkloadCredentialEnv {
                    env_name: odin_kube::workload::WORKLOAD_CREDENTIAL_ENV.to_owned(),
                    secret: custody.secret.clone(),
                    key: custody.key.clone(),
                };
                // The pod's model endpoint is the EXPLICITLY SELECTED target
                // node's declared gateway endpoint, parsed by the owning
                // node-declaration seam: a missing or invalid declaration is
                // that seam's typed refusal — never a default, a loopback
                // inference, a neighboring node's value, or the daemon-local
                // route URL. Resolution happens here, in the shared resolver
                // the executed handler runs first, so the pre-mint preflight
                // and execution cannot drift; reachability is measured
                // separately by the bounded pre-mint probe.
                let gateway = match resolve_node_gateway(&snapshot, target_node) {
                    Ok(gateway) => gateway,
                    Err(error) => {
                        return crate::kube_runtime::WorkloadResolve::Refused(format!(
                            "workload profile {profile_id:?}: {error}"
                        ))
                    }
                };
                crate::kube_runtime::WorkloadResolve::Launch(Box::new(
                    crate::kube_runtime::WorkloadLaunchInputs {
                        snapshot_revision: snapshot.revision,
                        profile,
                        provider: provider.clone(),
                        model: model.clone(),
                        slice_id: slice_id.clone(),
                        seat,
                        project,
                        lane: lane.clone(),
                        target_node: target_node.clone(),
                        gateway,
                        credential,
                        staged_inputs: Vec::new(),
                    },
                ))
            }
            WorkloadModelPolicy::Unavailable {
                lane,
                reason,
                fallback,
            } => {
                let offer = match fallback.first() {
                    Some((provider, model)) => format!(
                        " The seat's declared alternative {provider}/{model} is available if \
                         you choose it explicitly."
                    ),
                    None => String::new(),
                };
                crate::kube_runtime::WorkloadResolve::Refused(format!(
                    "the declared gateway lane {lane:?} is unavailable: {reason}.{offer}"
                ))
            }
        }
    }

    async fn open_session(
        &self,
        inputs: &crate::kube_runtime::WorkloadLaunchInputs,
        run_id: &odin_domain::RunId,
        operation_id: &OperationId,
    ) -> Result<(), crate::kube_runtime::WorkloadSessionOpenError> {
        use crate::kube_runtime::WorkloadSessionOpenError;
        // Strict post-effect typing: the cluster effect is durable before
        // this port runs, so every failure here reports the ATTACHMENT —
        // the typed surface code and reason travel structured through the
        // owning boundary, never laundered into a flat invalid-arguments
        // string.
        let attach = |code: &str, detail: String| WorkloadSessionOpenError {
            code: code.to_owned(),
            detail,
        };
        let supervisor = self.supervisor.get().ok_or_else(|| {
            attach(
                "workload_session_supervisor",
                "the workload session supervisor is not armed".to_owned(),
            )
        })?;
        let request = self
            .open_request(inputs, operation_id, launching_session_run(run_id))
            .map_err(|detail| attach("workload_open_request", detail))?;
        // Token provisioning strictly precedes the child open: an ensure
        // failure returns before `open_workload`, so no half-open session
        // exists and the already-landed Job effect stays journaled.
        self.ensure_session_token(inputs, &request.command_id)
            .map_err(|detail| attach("workload_session_token", detail))?;
        let binding = odin_domain::huginn::WorkloadSessionBinding {
            profile: inputs.profile.id.clone(),
            snapshot_revision: inputs.snapshot_revision,
            operation: operation_id.to_string(),
            inputs: inputs.staged_inputs.clone(),
            launching_run: Some(launching_session_run(run_id).to_owned()),
        };
        supervisor
            .open_workload(request, binding)
            .await
            .map(|_| ())
            .map_err(WorkloadSessionOpenError::from)
    }
}

/// The live plane's stable client-visible failure keeps its typed code and
/// reason at the port boundary: a code-bearing refusal (the supervisor
/// bridge's `omp_bridge_start` attach refusal, conflicts, transfer faults)
/// travels verbatim, and a code-less variant keeps its human-readable
/// reason under one stable port code. Nothing is flattened into a bare
/// string and no bridge error is redesigned here.
impl From<odin_domain::huginn::LiveError> for crate::kube_runtime::WorkloadSessionOpenError {
    fn from(error: odin_domain::huginn::LiveError) -> Self {
        use crate::kube_runtime::WorkloadSessionOpenError;
        use odin_domain::huginn::LiveError;
        let (code, detail) = match error {
            LiveError::InvalidRequest { code, message }
            | LiveError::Conflict { code, message }
            | LiveError::Transfer { code, message } => (code, message),
            LiveError::Unavailable { code } => {
                (code.clone(), format!("live service unavailable: {code}"))
            }
            other => ("live_session_open".to_owned(), other.to_string()),
        };
        WorkloadSessionOpenError { code, detail }
    }
}

#[cfg(test)]
mod platform_image_tests {
    fn deployment() -> crate::kube::WorkloadDeploymentFacts {
        crate::kube::WorkloadDeploymentFacts {
            image_reference: "localhost/odin-workload:18.1.18-new@sha256:".to_owned()
                + &"b".repeat(64),
            launcher: "/odin/bin/omp".to_owned(),
            browser: "/odin/bin/chromium".to_owned(),
            supervisor: "/odin/bin/odind".to_owned(),
            playwright: "/odin/lib/playwright-core".to_owned(),
            xvfb: "/odin/bin/Xvfb".to_owned(),
            state_path: None,
            export_pod_path: None,
            export_host_folder: None,
            agent_lane: None,
        }
    }

    fn registry_profile(id: &str) -> odin_registry::ComposedWorkloadProfile {
        let relative = format!("registry/workloads/{id}/profile.toml");
        let source = std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../..")
                .join(&relative),
        )
        .expect("the registry profile exists");
        let object = odin_registry::schema::parse_object_toml(
            odin_registry::RegistryKind::Workload,
            id,
            &relative,
            &source,
        )
        .expect("the registry profile parses");
        let odin_registry::ObjectConfig::Workload(toml) = object.config else {
            panic!("a workload")
        };
        odin_registry::ComposedWorkloadProfile {
            id: id.to_owned(),
            relative_config: relative.into(),
            profile: *toml,
        }
    }

    /// a profile pinned to the platform image's
    /// draft-time digest went stale at the next odin deploy. Odin's own
    /// agent pods declare "platform" and launch on the deployed identity.
    #[test]
    fn platform_profiles_launch_on_the_deployed_identity() {
        let deployment = deployment();
        for id in [
            "browser-probe",
            "astra-hello",
            "browser-contain",
            "surtr-readme-heading",
        ] {
            let mut profile = registry_profile(id);
            assert!(
                profile.profile.image.is_platform(),
                "{id} runs \"platform\""
            );
            super::follow_platform_image(&mut profile, Some(&deployment)).expect("resolved");
            assert_eq!(profile.profile.image.reference, deployment.image_reference);
            let runtime = profile.profile.runtime.expect("an agent pod");
            assert_eq!(runtime.supervisor, deployment.supervisor);
        }
    }

    #[test]
    fn an_exact_pin_is_never_rewritten() {
        let mut profile = registry_profile("browser-probe");
        let pin = "localhost/odin-workload@sha256:".to_owned() + &"a".repeat(64);
        profile.profile.image.reference.clone_from(&pin);
        super::follow_platform_image(&mut profile, Some(&deployment())).expect("a pin");
        assert_eq!(profile.profile.image.reference, pin);
    }

    #[test]
    fn platform_without_a_deployed_identity_is_refused() {
        let mut profile = registry_profile("browser-probe");
        let error = super::follow_platform_image(&mut profile, None).unwrap_err();
        assert!(error.to_string().contains("kube.image_identity"), "{error}");
    }
}
