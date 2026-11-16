//! Capability admission, scope checks, argument decoding, deadlines, and permit replay.

use std::sync::Arc;
use std::time::Duration;

use crate::KubeRuntimeCell;
use odin_domain::huginn::{HuginnProtocolError, KubeResourceVersion};
use odin_domain::{AttemptId, LaneId, ProjectId, RunId, Scope, SeatId};
use odin_huginn::kube::KubeControl;
use odin_kube::KubeError;
use odin_omp::host_tools::{
    HostInvocation, HostToolError, KubeCapabilityBinding, KubeCapabilityOwner,
};
use odin_types::OperationId;
use serde::Deserialize;
use serde_json::Value;

use super::evidence::{
    extract_health_evidence, extract_mutation_evidence, extract_snapshot_evidence,
    extract_summarize_evidence, mutation_settlement, serialize_output, MutationStatus,
};
use super::{WorkloadLaunchInputs, WorkloadLaunchPort, WorkloadResolve};

pub(super) fn require_no_campaign_policy(
    tool: &'static str,
    required: bool,
) -> Result<(), HostToolError> {
    if required {
        return Err(arguments_error(
            tool,
            "this workload profile requires an approved campaign launch",
        ));
    }
    Ok(())
}

#[cfg(test)]
#[test]
fn campaign_required_profiles_fail_closed_without_verified_launch() {
    assert!(require_no_campaign_policy("kube.workload.create", false).is_ok());
    assert!(require_no_campaign_policy("kube.workload.create", true).is_err());
}

#[tokio::test]
async fn campaign_verifier_must_be_composed() {
    let coordinator = KubeCommandCoordinator::new(None);
    assert!(coordinator.ensure_campaign_verifier("test").is_err());
    assert!(coordinator
        .verify_campaign_stage("test", "profile", "node", b"{}")
        .is_err());
}

/// The single production kube capability owner, composed exactly once by
/// `odind` before listener startup.
///
/// `runtime_cell` is the daemon's kube runtime cell: `None` means the kube
/// surface is not configured (typed unavailable, no in-memory fallback), and
/// a cell whose control is momentarily disconnected means the configured
/// cluster is unreachable right now (typed unavailable, never fabricated
/// results). The cell also carries the pinned published container profiles
/// and the launch policy binding resolved by the composition root.
pub struct KubeCommandCoordinator {
    pub(super) runtime_cell: Option<Arc<KubeRuntimeCell>>,
    /// The daemon's workload launch port, armed once during composition
    /// (after the shared snapshot handle, the workload surface, and the
    /// supervisor exist). Unarmed, workload profile ids refuse typed as
    /// not-composed instead of falling into the container path.
    workload: std::sync::OnceLock<Arc<dyn WorkloadLaunchPort>>,
    runtime: tokio::runtime::Handle,
    pub(super) models_path: Option<std::path::PathBuf>,
    /// Seats that read every run, not only their own and their project's:
    /// the owner-facing conversation seats.
    pub(super) overseers: std::collections::BTreeSet<SeatId>,
    /// Where launches no node has room for wait. Unset, such a launch refuses as before.
    launch_queue: Option<super::LaunchQueue>,
    /// Free GPU memory of a desktop node; unset, declared GPU memory is not checked.
    pub(super) vram_probe: Option<super::VramProbe>,
    /// The executor of profiles that declare `[offload]`; unset, they refuse.
    pub(super) offload: Option<Arc<crate::live::offload::Offload>>,
    stage_verifier: Option<super::stage::StageVerifier>,
}

impl KubeCommandCoordinator {
    /// Composition-construction contract of `odind`: the kube runtime cell
    /// (lazily connecting/reconnecting) that carries the real control surface
    /// and the pinned published profile context.
    pub fn new(runtime_cell: Option<Arc<KubeRuntimeCell>>) -> Self {
        Self {
            runtime_cell,
            workload: std::sync::OnceLock::new(),
            runtime: tokio::runtime::Handle::current(),
            models_path: None,
            overseers: std::collections::BTreeSet::new(),
            launch_queue: None,
            vram_probe: None,
            offload: None,
            stage_verifier: None,
        }
    }

    pub(crate) fn with_stage_verifier(mut self, verifier: super::stage::StageVerifier) -> Self {
        self.stage_verifier = Some(verifier);
        self
    }

    pub(super) fn ensure_campaign_verifier(&self, tool: &'static str) -> Result<(), HostToolError> {
        if self.stage_verifier.is_none() {
            return Err(HostToolError::Unavailable {
                tool,
                reason: "trusted campaign stage verification is not configured".to_owned(),
            });
        }
        Ok(())
    }

    pub(super) fn verify_campaign_stage(
        &self,
        tool: &'static str,
        profile: &str,
        node: &str,
        manifest: &[u8],
    ) -> Result<super::stage::VerifiedStage, HostToolError> {
        let verifier = self
            .stage_verifier
            .as_ref()
            .ok_or_else(|| HostToolError::Unavailable {
                tool,
                reason: "trusted campaign stage verification is not configured".to_owned(),
            })?;
        verifier(profile, node, manifest)
            .map_err(|reason| HostToolError::Unavailable { tool, reason })
    }

    /// Holds launches that no node has room for in this directory.
    pub fn with_launch_queue(mut self, dir: std::path::PathBuf) -> Self {
        self.launch_queue = Some(super::LaunchQueue::new(dir));
        self
    }

    /// Reads a node's free GPU memory before a launch that declares its need is placed there.
    pub fn with_vram_probe(mut self, probe: super::VramProbe) -> Self {
        self.vram_probe = Some(probe);
        self
    }

    /// Runs offload profiles on their declared compute targets.
    pub(crate) fn with_offload(mut self, offload: Arc<crate::live::offload::Offload>) -> Self {
        self.offload = Some(offload);
        self
    }

    pub fn launch_queue(&self) -> Option<super::LaunchQueue> {
        self.launch_queue.clone()
    }

    /// Uses the same explicit models declaration as the native OMP sandbox.
    pub fn with_models_path(mut self, path: Option<std::path::PathBuf>) -> Self {
        self.models_path = path;
        self
    }

    /// The seats that read every run (the owner's conversation seats answer
    /// "which pods ran today" without asking the seat that launched them).
    pub fn with_overseers(mut self, seats: std::collections::BTreeSet<SeatId>) -> Self {
        self.overseers = seats;
        self
    }

    /// Arms the workload launch port exactly once; a second arming is a
    /// composition defect, never a silent replacement.
    pub fn arm_workload_port(&self, port: Arc<dyn WorkloadLaunchPort>) -> Result<(), String> {
        if self.workload.set(port).is_err() {
            return Err("workload launch port was already armed".to_owned());
        }
        Ok(())
    }

    pub(super) fn workload_port(&self) -> Option<Arc<dyn WorkloadLaunchPort>> {
        self.workload.get().cloned()
    }

    pub(super) fn require_create_target(
        &self,
        tool: &'static str,
        target: Option<&str>,
        agent_node: Option<&str>,
    ) -> Result<(), HostToolError> {
        let Some(target) = target else {
            return Ok(());
        };
        validate_target_node(tool, target)?;
        if agent_node.is_some_and(|node| node != target) {
            return Err(arguments_error(
                tool,
                "targetNode disagrees with the agent's bound serving node",
            ));
        }
        let cell = self
            .runtime_cell
            .as_ref()
            .ok_or_else(|| HostToolError::Unavailable {
                tool,
                reason: "initial placement requires pinned kube placement authority".to_owned(),
            })?;
        if !cell.kube_config().allowed_nodes.contains(target) {
            return Err(arguments_error(
                tool,
                format!("targetNode {target:?} is outside admitted placement authority"),
            ));
        }
        tracing::info!(
            "workload-initial-placement-authority target={target} agent_node={agent_node:?}"
        );
        Ok(())
    }

    /// Checks route, credentials, attempt, gateway reachability, and generated
    /// material before creating approval rows or other durable state.
    pub(super) fn preflight_create(
        &self,
        scope: &Scope,
        arguments: &Value,
    ) -> Result<(), HostToolError> {
        self.preflight_create_campaign(scope, arguments, false)
    }

    pub(super) fn preflight_create_campaign(
        &self,
        scope: &Scope,
        arguments: &Value,
        trusted_campaign: bool,
    ) -> Result<(), HostToolError> {
        let tool = KubeCapabilityBinding::WorkloadCreate.id();
        // Use the same scope checks as execution.
        let seat = require_kube_seat_scope(tool, scope)?;
        let input: ProfileInput = decode_arguments(tool, arguments.clone())?;
        if let Some(cell) = self.runtime_cell.as_ref() {
            let (_, max_inputs) = super::create_many::seat_batch_limits(&cell.snapshot(), &seat);
            super::create_many::validate_input_count(tool, input.inputs.len(), max_inputs)?;
        }
        validate_run_label(tool, input.label.as_deref())?;
        let scope = &pod_launch_scope(tool, scope, &input, 1)?;
        let (run_id, project_id, _) = require_kube_launch_scope(tool, scope)?;
        // A declared sphere narrows before any route, journal, or cluster
        // probe. An absent sphere does not. An unconfigured cell has no
        // pinned snapshot, so this check waits for execution's cell.
        if let Some(cell) = self.runtime_cell.as_ref() {
            require_sphere_profile(tool, &cell.snapshot(), &project_id, &input.profile)?;
        }
        // An un-armed launch port falls to the container-profile path at
        // execution; no declared gate exists to run here.
        let resolution = self
            .workload_port()
            .map_or(WorkloadResolve::NotWorkload, |port| {
                port.resolve_launch(&input.profile)
            });
        // The route refusal stays FIRST and verbatim: a dispatch the
        // served projection cannot route never reaches cell or journal
        // checks.
        let inputs = match resolution {
            WorkloadResolve::NotWorkload => {
                let cell =
                    self.runtime_cell
                        .as_ref()
                        .ok_or_else(|| HostToolError::Unavailable {
                            tool,
                            reason: "the kube surface is not configured".to_owned(),
                        })?;
                let container = cell
                    .container_profile(&input.profile)
                    .filter(|profile| profile.enabled)
                    .ok_or_else(|| {
                        arguments_error(
                            tool,
                            format!(
                                "published container profile {:?} is not admitted",
                                input.profile
                            ),
                        )
                    })?;
                let seat = require_kube_seat_scope(tool, scope)?;
                if !container.seats_offered.is_empty() && !container.seats_offered.contains(&seat) {
                    return Err(HostToolError::Scope {
                        tool,
                        reason: "the bound seat is not offered the requested container profile",
                    });
                }
                if !input.inputs.is_empty() || input.prompt.is_some() {
                    return Err(arguments_error(
                        tool,
                        "container profiles do not take inputs or prompts",
                    ));
                }
                None
            }
            WorkloadResolve::Script(mut inputs) => {
                require_no_campaign_policy(
                    tool,
                    inputs.profile.profile.require_campaign_approval && !trusted_campaign,
                )?;
                super::launch::admit_script_limits(tool, &mut inputs, &input)?;
                require_workload_scope(tool, scope, &inputs.profile.profile, &inputs.lane)?;
                if let Some(gateway) = &inputs.gateway {
                    self.preflight_workload_gateway(tool, &inputs.profile.id, &gateway.endpoint)?;
                }
                None
            }
            WorkloadResolve::Launch(inputs) => {
                require_no_campaign_policy(
                    tool,
                    inputs.profile.profile.require_campaign_approval && !trusted_campaign,
                )?;
                require_workload_scope(tool, scope, &inputs.profile.profile, &inputs.lane)?;
                admitted_limits(tool, &inputs.profile, &input)?;
                Some(inputs)
            }
            WorkloadResolve::Refused(reason) => return Err(arguments_error(tool, reason)),
        };
        self.require_create_target(
            tool,
            input.target_node.as_deref(),
            inputs.as_ref().map(|inputs| inputs.target_node.as_str()),
        )?;
        // Check the stored attempt before approval and recheck it before execution.
        let declared = self
            .runtime_cell
            .as_ref()
            .map(|cell| (cell.ledger(), cell.kube_config()))
            .map(|(ledger, config)| {
                odin_kube::stored_launch(&ledger, &config.cluster, &config.namespace, &run_id)
                    .map_err(|error| kube_failure(tool, error))
            })
            .transpose()?
            .flatten()
            .map(|stored| stored.labels.attempt_id);
        resolve_create_attempt(tool, declared, scope.attempt.clone())?;
        match inputs {
            Some(inputs) => {
                agent_pod_launch_admissible(tool, crate::project_authoring::reload_requested())?;
                self.preflight_workload_gateway(tool, &inputs.profile.id, &inputs.gateway)?;
                self.preflight_workload_material(tool, &inputs)
            }
            None => Ok(()),
        }
    }

    /// Probes host DNS/TCP reachability before approval, not pod networking or
    /// provider health. Uses one deadline and creates no probe pod.
    fn preflight_workload_gateway(
        &self,
        tool: &'static str,
        profile_id: &str,
        gateway: &odin_registry::schema::NodeGatewayEndpoint,
    ) -> Result<(), HostToolError> {
        let target = odin_kube::workload::WorkloadGatewayTarget {
            host: gateway.host().to_owned(),
            port: gateway.port(),
        };
        // The probe's resolution and connect run on a real tokio runtime
        // under one shared deadline — never a blocking resolver call and
        // never a detached thread. The production dispatch thread has no
        // runtime context, so the coordinator's own handle drives it; a
        // caller already inside a runtime (tests, embedded callers) drives
        // the same future on its own handle instead of nesting runtimes.
        let probe = odin_kube::workload::probe_gateway_target(&target);
        let outcome = match tokio::runtime::Handle::try_current() {
            Ok(handle) => tokio::task::block_in_place(|| handle.block_on(probe)),
            Err(_) => self.runtime.clone().block_on(probe),
        };
        outcome.map_err(|error| HostToolError::Unavailable {
            tool,
            reason: format!("workload profile {profile_id:?}: {error}"),
        })
    }

    /// Shares execution's pure composition without registering or binding material.
    fn preflight_workload_material(
        &self,
        tool: &'static str,
        inputs: &WorkloadLaunchInputs,
    ) -> Result<(), HostToolError> {
        let Some(cell) = self.runtime_cell.as_ref() else {
            return Err(HostToolError::Unavailable {
                tool,
                reason: "the kube surface is not configured".to_owned(),
            });
        };
        let agent = inputs.profile.profile.agent().ok_or_else(|| {
            arguments_error(
                tool,
                format!(
                    "workload {} runs no agent harness; only an agent pod composes admission \
                     material",
                    inputs.profile.id
                ),
            )
        })?;
        super::models_config::compose_models_document(
            tool,
            self.models_path.as_deref(),
            inputs.provider.as_str(),
            inputs.model.as_str(),
            &inputs.gateway,
        )?;
        super::extension::compose_extension_policy(
            tool,
            &cell.artifact_store(),
            &cell.workload_identity().artifact,
            cell.config_revision(),
            &super::extension::ProfileBinding {
                image_reference: &inputs.profile.profile.image.reference,
                launcher: &agent.runtime.launcher,
                supervisor: &agent.runtime.supervisor,
                browser: &agent.runtime.browser,
                playwright: &agent.runtime.playwright,
                xvfb: &agent.display.xvfb,
            },
            inputs.snapshot_revision,
        )?;
        Ok(())
    }

    async fn invoke_host_capability(
        &self,
        binding: KubeCapabilityBinding,
        timeout_seconds: u32,
        operation_id: OperationId,
        invocation: HostInvocation,
    ) -> Result<Value, HostToolError> {
        match binding {
            KubeCapabilityBinding::WorkloadCreate => {
                self.create(binding.id(), timeout_seconds, operation_id, invocation)
                    .await
            }
            KubeCapabilityBinding::WorkloadCreateMany => {
                self.create_many(binding.id(), timeout_seconds, operation_id, invocation)
            }
            KubeCapabilityBinding::WorkloadCreateManyEvidence => {
                super::create_many::extract_batch_evidence(binding.id(), invocation.arguments)
            }
            KubeCapabilityBinding::WorkloadPause => {
                self.mutate(
                    binding.id(),
                    "pause",
                    timeout_seconds,
                    operation_id,
                    invocation,
                )
                .await
            }
            KubeCapabilityBinding::WorkloadResume => {
                self.mutate(
                    binding.id(),
                    "resume",
                    timeout_seconds,
                    operation_id,
                    invocation,
                )
                .await
            }
            KubeCapabilityBinding::WorkloadRestart => {
                self.mutate(
                    binding.id(),
                    "restart",
                    timeout_seconds,
                    operation_id,
                    invocation,
                )
                .await
            }
            KubeCapabilityBinding::WorkloadCancel => {
                self.mutate(
                    binding.id(),
                    "cancel",
                    timeout_seconds,
                    operation_id,
                    invocation,
                )
                .await
            }
            KubeCapabilityBinding::WorkloadSummarize => {
                self.summarize(binding.id(), invocation).await
            }
            KubeCapabilityBinding::WorkloadSteer => {
                self.steer(binding.id(), operation_id, invocation).await
            }
            KubeCapabilityBinding::WorkloadSteerEvidence => {
                super::steer::extract_steer_evidence(binding.id(), invocation.arguments)
            }
            KubeCapabilityBinding::WorkloadQueue => self.queue_op(binding.id(), invocation, false),
            KubeCapabilityBinding::WorkloadQueueDrop => {
                self.queue_op(binding.id(), invocation, true)
            }
            KubeCapabilityBinding::SnapshotRead => {
                self.snapshot_read(binding.id(), invocation).await
            }
            KubeCapabilityBinding::HealthRead => self.health_read(binding.id(), invocation).await,
            KubeCapabilityBinding::WorkloadCreateEvidence
            | KubeCapabilityBinding::WorkloadPauseEvidence
            | KubeCapabilityBinding::WorkloadResumeEvidence
            | KubeCapabilityBinding::WorkloadRestartEvidence
            | KubeCapabilityBinding::WorkloadCancelEvidence => {
                extract_mutation_evidence(binding.id(), invocation.arguments)
            }
            KubeCapabilityBinding::WorkloadSummarizeEvidence => {
                extract_summarize_evidence(binding.id(), invocation.arguments)
            }
            KubeCapabilityBinding::WorkloadQueueEvidence
            | KubeCapabilityBinding::WorkloadQueueDropEvidence => {
                super::launch_queue::extract_queue_evidence(binding.id(), invocation.arguments)
            }
            KubeCapabilityBinding::SnapshotReadEvidence => {
                extract_snapshot_evidence(binding.id(), invocation.arguments)
            }
            KubeCapabilityBinding::HealthReadEvidence => {
                extract_health_evidence(binding.id(), invocation.arguments)
            }
        }
    }

    /// Resolves the live control surface with the cell's declared
    /// actuation bounds (per-request, teardown), or the typed
    /// unavailability reason.
    pub(super) fn resolve_control(
        &self,
    ) -> Result<(Arc<KubeControl>, (Duration, Duration)), String> {
        let Some(cell) = self.runtime_cell.as_ref() else {
            return Err("the kube surface is not configured".to_owned());
        };
        let bounds = cell.kube_bounds();
        let control = cell
            .control()
            .ok_or_else(|| "the k3s API server is unreachable".to_owned())?;
        Ok((control, bounds))
    }
}

impl KubeCapabilityOwner for KubeCommandCoordinator {
    fn launchable_profiles(
        &self,
        project: Option<&odin_domain::ProjectId>,
    ) -> Vec<odin_omp::host_tools::LaunchableProfile> {
        let profiles = self
            .runtime_cell
            .as_ref()
            .map(|cell| cell.launchable_profiles())
            .or_else(|| self.workload_port().map(|port| port.launchable_profiles()))
            .unwrap_or_default();
        let Some(project) = project else {
            return profiles;
        };
        let Some(cell) = self.runtime_cell.as_ref() else {
            return profiles;
        };
        let snapshot = cell.snapshot();
        match crate::kube::spheres::project_sphere(&snapshot, project) {
            Ok(sphere) => profiles
                .into_iter()
                .filter(|profile| crate::kube::spheres::sphere_admits_profile(sphere, &profile.id))
                .collect(),
            // A disabled project cannot launch. Listing names nothing rather
            // than offering profiles admission will refuse.
            Err(_) => Vec::new(),
        }
    }

    fn invoke_kube_capability(
        &self,
        binding: KubeCapabilityBinding,
        timeout_seconds: u32,
        operation_id: OperationId,
        invocation: HostInvocation,
    ) -> Result<Value, HostToolError> {
        let runtime = self.runtime.clone();
        runtime.block_on(self.invoke_host_capability(
            binding,
            timeout_seconds,
            operation_id,
            invocation,
        ))
    }

    fn preflight_kube_capability(
        &self,
        contract: &odin_kernel::CapabilityContract,
        binding: KubeCapabilityBinding,
        scope: &Scope,
        arguments: &Value,
    ) -> Result<(), HostToolError> {
        match binding {
            // Invalid declarations must fail before creating an approval row.
            KubeCapabilityBinding::WorkloadCreate => self.preflight_create(scope, arguments),
            KubeCapabilityBinding::WorkloadCreateMany => {
                self.preflight_create_many(binding.id(), scope, arguments)
            }
            KubeCapabilityBinding::WorkloadPause => {
                self.preflight_mutate(contract, binding.id(), "pause", scope, arguments)
            }
            KubeCapabilityBinding::WorkloadResume => {
                self.preflight_mutate(contract, binding.id(), "resume", scope, arguments)
            }
            KubeCapabilityBinding::WorkloadRestart => {
                self.preflight_mutate(contract, binding.id(), "restart", scope, arguments)
            }
            KubeCapabilityBinding::WorkloadCancel => {
                self.preflight_mutate(contract, binding.id(), "cancel", scope, arguments)
            }
            KubeCapabilityBinding::WorkloadSummarize => {
                self.preflight_summarize(binding.id(), scope, arguments)
            }
            KubeCapabilityBinding::WorkloadSteer => self.preflight_steer(
                binding.id(),
                HostInvocation {
                    scope: scope.clone(),
                    arguments: arguments.clone(),
                },
            ),
            KubeCapabilityBinding::WorkloadQueue => {
                require_kube_seat_scope(binding.id(), scope)?;
                decode_arguments::<NoInput>(binding.id(), arguments.clone()).map(|_| ())
            }
            KubeCapabilityBinding::WorkloadQueueDrop => {
                require_kube_seat_scope(binding.id(), scope)?;
                super::launch_queue::QueueInput::decode(binding.id(), arguments.clone()).map(|_| ())
            }
            KubeCapabilityBinding::SnapshotRead => {
                self.preflight_snapshot_read(binding.id(), scope, arguments)
            }
            KubeCapabilityBinding::HealthRead => {
                self.preflight_health_read(binding.id(), scope, arguments)
            }
            // Evidence bindings consume the handler's post-effect output,
            // which does not exist at dispatch time, so their gate is the
            // explicit documented no-op; the extractor's strict output
            // validation is the execution and governs at the permit.
            KubeCapabilityBinding::WorkloadCreateEvidence
            | KubeCapabilityBinding::WorkloadCreateManyEvidence
            | KubeCapabilityBinding::WorkloadPauseEvidence
            | KubeCapabilityBinding::WorkloadResumeEvidence
            | KubeCapabilityBinding::WorkloadRestartEvidence
            | KubeCapabilityBinding::WorkloadCancelEvidence
            | KubeCapabilityBinding::WorkloadSummarizeEvidence
            | KubeCapabilityBinding::WorkloadSteerEvidence
            | KubeCapabilityBinding::WorkloadQueueEvidence
            | KubeCapabilityBinding::WorkloadQueueDropEvidence
            | KubeCapabilityBinding::SnapshotReadEvidence
            | KubeCapabilityBinding::HealthReadEvidence => Ok(()),
        }
    }
}

/// The mutation family's shared input resolution: strict run-input
/// decoding plus typed id validation. Preflight observes it read-only;
/// the executed mutation runs the identical helper, so the two cannot
/// drift.
pub(super) fn resolve_mutation_input(
    tool: &'static str,
    arguments: Value,
) -> Result<MutationInput, HostToolError> {
    let input: RunInput = decode_arguments(tool, arguments)?;
    let run_id = RunId::new(input.run_id)
        .map_err(|error| arguments_error(tool, format!("invalid runId: {error}")))?;
    let expected_resource_version = KubeResourceVersion::new(input.expected_resource_version)
        .map_err(|error| {
            arguments_error(tool, format!("invalid expectedResourceVersion: {error}"))
        })?;
    if let Some(node) = &input.target_node {
        validate_target_node(tool, node)?;
    }
    Ok(MutationInput {
        run_id,
        expected_resource_version,
        target_node: input.target_node,
        checkpoint: input.checkpoint,
    })
}

fn validate_target_node(tool: &'static str, node: &str) -> Result<(), HostToolError> {
    let endpoint = |byte: u8| byte.is_ascii_lowercase() || byte.is_ascii_digit();
    let bytes = node.as_bytes();
    if bytes.is_empty()
        || bytes.len() > 63
        || !endpoint(bytes[0])
        || !endpoint(bytes[bytes.len() - 1])
        || !bytes
            .iter()
            .all(|byte| endpoint(*byte) || matches!(*byte, b'-' | b'.'))
    {
        return Err(arguments_error(
            tool,
            format!("targetNode {node:?} is not a node name"),
        ));
    }
    Ok(())
}

/// One decoded lifecycle mutation.
pub(super) struct MutationInput {
    pub(super) run_id: RunId,
    pub(super) expected_resource_version: KubeResourceVersion,
    pub(super) target_node: Option<String>,
    pub(super) checkpoint: bool,
}

impl KubeCommandCoordinator {
    /// Checks the launch, ownership, resource version, and deadline read-only.
    /// Raw observation avoids read-model updates; execution repeats validation
    /// and performs compare-and-swap through the reconciler at the permit.
    pub(super) fn preflight_mutate(
        &self,
        contract: &odin_kernel::CapabilityContract,
        tool: &'static str,
        verb: &'static str,
        scope: &Scope,
        arguments: &Value,
    ) -> Result<(), HostToolError> {
        require_kube_seat_scope(tool, scope)?;
        let MutationInput {
            run_id,
            expected_resource_version,
            ..
        } = resolve_mutation_input(tool, arguments.clone())?;
        let (control, bounds) = self
            .resolve_control()
            .map_err(|reason| HostToolError::Unavailable { tool, reason })?;
        let declared = self
            .runtime_cell
            .as_ref()
            .map(|cell| (cell.ledger(), cell.kube_config()))
            .map(|(ledger, config)| {
                odin_kube::stored_launch(&ledger, &config.cluster, &config.namespace, &run_id)
                    .map_err(|error| kube_failure(tool, error))
            })
            .transpose()?
            .flatten();
        if declared.is_none() {
            return Err(arguments_error(
                tool,
                format!("run {run_id} has no durably declared launch to {verb}"),
            ));
        }
        if verb == "restart" {
            if let (Some(launch), Some(cell)) = (declared.as_ref(), self.runtime_cell.as_ref()) {
                let deployed = &cell.workload_identity().deployment.image_reference;
                if let Some(refusal) = replaced_image_refusal(launch, deployed) {
                    return Err(arguments_error(tool, format!("run {run_id}: {refusal}")));
                }
            }
        }
        // Observe without journal stamps, read-model updates, or deltas.
        let observation = self
            .runtime
            .block_on(control.reconciler().observe_run_readonly(&run_id))
            .map_err(|error| kube_failure(tool, error))?;
        let Some(observation) = observation else {
            return Err(arguments_error(
                tool,
                format!("run {run_id} has no cluster workload to {verb}"),
            ));
        };
        let owned = matches!(
            &observation.workload.ownership,
            odin_domain::huginn::KubeResourceOwnership::Odin { run_id: owned, .. }
                if owned == &run_id
        );
        if !owned {
            return Err(arguments_error(
                tool,
                format!("run {run_id}'s workload is foreign and read-only"),
            ));
        }
        if observation.projection.identity.resource_version.as_str()
            != expected_resource_version.as_str()
        {
            return Err(arguments_error(
                tool,
                format!(
                    "the invocation's expected resource version is stale; the workload now observes {}",
                    observation.projection.identity.resource_version.as_str()
                ),
            ));
        }
        checked_deadline(
            tool,
            mutation_deadline(bounds),
            contract.timeout_seconds.get(),
        )?;
        Ok(())
    }

    pub(super) fn preflight_summarize(
        &self,
        tool: &'static str,
        scope: &Scope,
        arguments: &Value,
    ) -> Result<(), HostToolError> {
        require_kube_seat_scope(tool, scope)?;
        let input: OptionalRunInput = decode_arguments(tool, arguments.clone())?;
        input.checked_log_lines(tool)?;
        if let Some(raw) = input.run_id {
            let _run_id = RunId::new(raw)
                .map_err(|error| arguments_error(tool, format!("invalid runId: {error}")))?;
        }
        self.resolve_control()
            .map_err(|reason| HostToolError::Unavailable { tool, reason })?;
        Ok(())
    }

    pub(super) fn preflight_snapshot_read(
        &self,
        tool: &'static str,
        scope: &Scope,
        arguments: &Value,
    ) -> Result<(), HostToolError> {
        require_kube_seat_scope(tool, scope)?;
        if scope.run.is_none() {
            return Err(HostToolError::Scope {
                tool,
                reason: "snapshot reads address the invocation's bound run",
            });
        }
        let _: NoInput = decode_arguments(tool, arguments.clone())?;
        self.resolve_control()
            .map_err(|reason| HostToolError::Unavailable { tool, reason })?;
        Ok(())
    }

    pub(super) fn preflight_health_read(
        &self,
        tool: &'static str,
        scope: &Scope,
        arguments: &Value,
    ) -> Result<(), HostToolError> {
        require_kube_seat_scope(tool, scope)?;
        let _: NoInput = decode_arguments(tool, arguments.clone())?;
        self.resolve_control()
            .map_err(|reason| HostToolError::Unavailable { tool, reason })?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Scope checks and shared dispatch helpers.
// ---------------------------------------------------------------------------

pub(super) fn require_kube_seat_scope(
    tool: &'static str,
    scope: &odin_domain::Scope,
) -> Result<SeatId, HostToolError> {
    scope.seat.clone().ok_or(HostToolError::Scope {
        tool,
        reason: "kube capabilities require a seat-bound invocation",
    })
}

/// The runtime derives run, project, and lane from scope; the model cannot select them.
pub(super) fn require_kube_launch_scope(
    tool: &'static str,
    scope: &odin_domain::Scope,
) -> Result<(RunId, ProjectId, LaneId), HostToolError> {
    let run_id = scope.run.clone().ok_or(HostToolError::Scope {
        tool,
        reason: "workload creation addresses the invocation's bound run",
    })?;
    let project_id = scope.project.clone().ok_or(HostToolError::Scope {
        tool,
        reason: "workload creation binds the invocation's project",
    })?;
    let lane_id = scope.lane.clone().ok_or(HostToolError::Scope {
        tool,
        reason: "workload creation binds the invocation's lane",
    })?;
    Ok((run_id, project_id, lane_id))
}

/// Offered callers may launch across bindings; execution always uses the profile's own identity.
pub(super) fn require_workload_scope(
    tool: &'static str,
    scope: &Scope,
    profile: &odin_registry::schema::WorkloadProfileToml,
    lane: &LaneId,
) -> Result<(), HostToolError> {
    let seat = require_kube_seat_scope(tool, scope)?;
    let (_, project, caller_lane) = require_kube_launch_scope(tool, scope)?;
    if profile.seats_offered.contains(&seat)
        || (profile.seat.seat == seat && profile.seat.project == project && lane == &caller_lane)
    {
        Ok(())
    } else {
        Err(HostToolError::Scope {
            tool,
            reason: "the bound seat is not offered the requested workload profile",
        })
    }
}

/// A declared project sphere admits only its `pod_profiles`.
///
/// An absent sphere does not narrow: the seat-offer checks remain the
/// authority. An empty declared set launches nothing. The refusal names the
/// project and the profiles it offers, so a near-miss is actionable.
pub(super) fn require_sphere_profile(
    tool: &'static str,
    snapshot: &odin_registry::Snapshot,
    project: &ProjectId,
    profile: &str,
) -> Result<(), HostToolError> {
    let sphere = crate::kube::spheres::project_sphere(snapshot, project)
        .map_err(|reason| arguments_error(tool, reason))?;
    if crate::kube::spheres::sphere_admits_profile(sphere, profile) {
        return Ok(());
    }
    let offered = sphere
        .map(|sphere| {
            sphere
                .pod_profiles
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>()
                .join(", ")
        })
        .filter(|offered| !offered.is_empty());
    Err(arguments_error(
        tool,
        match offered {
            Some(offered) => format!(
                "project {project} launches only its declared pod profiles ({offered}); \
                 {profile:?} is not one of them"
            ),
            None => format!(
                "project {project} declares a sphere with no pod profiles; \
                 {profile:?} is not launchable"
            ),
        },
    ))
}

/// The run limits a launch admits: the profile's declared values with the launch's overrides.
pub(super) fn admitted_limits(
    tool: &'static str,
    profile: &odin_registry::ComposedWorkloadProfile,
    input: &ProfileInput,
) -> Result<odin_domain::huginn::WorkloadLimits, HostToolError> {
    profile
        .profile
        .resolve_limits(&input.limits.unwrap_or_default())
        .map_err(|reason| arguments_error(tool, reason))
}

/// The invocation scope a pod launch runs under: the session's run plus one
/// run per distinct launch, `<session run>:pod:<profile>:<launch>`, where
/// `<launch>` digests what the create asks beyond the profile (its inputs
/// and target node). A run owns exactly one Job (its name, idempotency
/// digest and stored launch all derive from the run), so launches that
/// shared a run refused each other: a seat asked for three pods of one
/// profile (one question each) at once got one pod and "operation identity
/// or idempotency digest was reused with different arguments". Distinct
/// launches now never share a run, even when issued concurrently, and an
/// identical create is the same run (an idempotent replay). The pod run
/// keeps the session as its prefix, so a pod's findings still reach the
/// launching session (`workload_watch::launching_session`).
///
/// `generation` numbers the session's identical launches: the first is the
/// bare run, a later one (after the earlier run finished) appends
/// `:<generation>` — see [`pod_run_generation`].
pub(super) fn pod_launch_scope(
    tool: &'static str,
    scope: &Scope,
    input: &ProfileInput,
    generation: u32,
) -> Result<Scope, HostToolError> {
    let session_run = scope.run.as_ref().ok_or(HostToolError::Scope {
        tool,
        reason: "workload creation addresses the invocation's bound run",
    })?;
    let profile = input.profile.as_str();
    let short = |bytes: &[u8], len: usize| {
        let digest = odin_domain::Digest::hash(bytes).to_string();
        digest.trim_start_matches("blake3:")[..len].to_owned()
    };
    // Preserve existing launch identities when no prompt or company was supplied.
    let mut asked = match (&input.prompt, &input.company) {
        (Some(prompt), Some(company)) => {
            serde_json::to_vec(&(&input.inputs, &input.target_node, prompt, company))
        }
        (Some(prompt), None) => serde_json::to_vec(&(&input.inputs, &input.target_node, prompt)),
        (None, Some(company)) => serde_json::to_vec(&(&input.inputs, &input.target_node, company)),
        (None, None) => serde_json::to_vec(&(&input.inputs, &input.target_node)),
    }
    .map_err(|error| arguments_error(tool, format!("cannot digest the launch: {error}")))?;
    // Declared limits and seeds join the identity; a launch without them keeps its digest.
    if let Some(limits) = &input.limits {
        asked.extend(serde_json::to_vec(limits).map_err(|error| {
            arguments_error(tool, format!("cannot digest the launch limits: {error}"))
        })?);
    }
    if !input.seeds.is_empty() {
        asked.extend(serde_json::to_vec(&input.seeds).map_err(|error| {
            arguments_error(tool, format!("cannot digest the launch seeds: {error}"))
        })?);
    }
    if let Some(from) = &input.continue_from {
        asked.extend(format!("continue-from:{from}").as_bytes());
    }
    let launch = short(&asked, 8);
    let suffix = if generation > 1 {
        format!(":{generation}")
    } else {
        String::new()
    };
    let readable = format!("{session_run}:pod:{profile}:{launch}{suffix}");
    let run = RunId::new(readable.as_str())
        .or_else(|_| {
            // Use a digest when the profile cannot fit the run ID's format or 128-byte limit.
            let both = short(format!("{profile}:{launch}").as_bytes(), 32);
            RunId::new(format!("{session_run}:pod:{both}{suffix}").as_str())
        })
        .map_err(|error| {
            arguments_error(
                tool,
                format!("cannot derive the pod run for {profile:?} under {session_run}: {error}"),
            )
        })?;
    let mut pod = scope.clone();
    pod.run = Some(run);
    Ok(pod)
}

/// An agent pod's session can run no turn while a publication waits for
/// odind's idle reload: its first prompt is refused
/// `brain_turn_publication_mismatch`, and the reload then cuts the pod's
/// session off. tool-probe-mini launched while
/// a publication was pending; its task prompt failed at once, the pod sat
/// idle, and the reload restarted odind two minutes later with the task
/// never started. The launch is refused before any effect instead, in words
/// the launching seat can act on. Script pods run no session and are not
/// affected.
pub(super) fn agent_pod_launch_admissible(
    tool: &'static str,
    reload_pending: bool,
) -> Result<(), HostToolError> {
    if reload_pending {
        tracing::error!(
            "agent pod launch refused reason=reload_pending \
             detail=\"a publication waits for odind's idle reload\""
        );
        return Err(HostToolError::Unavailable {
            tool,
            reason: "Odin restarts in about a minute to activate a new publication, and an \
                     agent pod launched now could not start its task. Launch it again after \
                     the restart."
                .to_owned(),
        });
    }
    Ok(())
}

/// What the journal and cluster say about one candidate pod run.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum PodRunUse {
    /// Never launched: a create may take it.
    Unused,
    /// Launched and still live (pending, staging, running, paused): an
    /// identical create is the same pod (idempotent replay).
    Live,
    /// Launched and finished: succeeded, failed, cancelled or gone.
    Finished,
}

/// The most identical launches a single session may make.
pub(super) const MAX_POD_GENERATIONS: u32 = 64;

/// The generation an identical create in one session takes: the first
/// that is unused or still live. A finished run is never the target of a
/// new create. Kubert cancelled tool-probe and
/// created it again from the same session; the create bound the same run,
/// the journal replayed the first launch's "Job ... was created", and no
/// Job ran.
pub(super) fn pod_run_generation(
    tool: &'static str,
    mut use_of: impl FnMut(u32) -> Result<PodRunUse, HostToolError>,
) -> Result<u32, HostToolError> {
    for generation in 1..=MAX_POD_GENERATIONS {
        match use_of(generation)? {
            PodRunUse::Unused | PodRunUse::Live => return Ok(generation),
            PodRunUse::Finished => {}
        }
    }
    Err(arguments_error(
        tool,
        format!(
            "this session already launched that profile with these inputs \
             {MAX_POD_GENERATIONS} times; continue in a new session"
        ),
    ))
}

/// The longest optional run label.
const MAX_RUN_LABEL_CHARS: usize = 60;

/// The optional run label: one to `MAX_RUN_LABEL_CHARS` printable characters.
pub(super) fn validate_run_label(
    tool: &'static str,
    label: Option<&str>,
) -> Result<(), HostToolError> {
    let Some(label) = label else {
        return Ok(());
    };
    let length = label.chars().count();
    if length == 0 || length > MAX_RUN_LABEL_CHARS || label.chars().any(char::is_control) {
        return Err(arguments_error(
            tool,
            format!(
                "label must be 1 to {MAX_RUN_LABEL_CHARS} printable characters; it has {length}"
            ),
        ));
    }
    Ok(())
}

/// Strict, schema-shaped argument decoding: unknown fields reject.
pub(super) fn decode_arguments<T: for<'de> Deserialize<'de>>(
    tool: &'static str,
    value: Value,
) -> Result<T, HostToolError> {
    serde_json::from_value(value)
        .map_err(|error| arguments_error(tool, format!("invalid arguments: {error}")))
}

/// Reuses the declared attempt and rejects explicit mismatches before effects.
/// Without a declared attempt, passes the invocation's attempt through for minting.
pub(super) fn resolve_create_attempt(
    tool: &'static str,
    declared: Option<AttemptId>,
    invocation: Option<AttemptId>,
) -> Result<Option<AttemptId>, HostToolError> {
    match (declared, invocation) {
        (Some(declared), Some(invocation)) if invocation != declared => Err(arguments_error(
            tool,
            format!(
                "the invocation declares attempt {invocation:?}, but the run's admitted \
                 launch declares {declared:?}; create may only re-declare the admitted attempt"
            ),
        )),
        (Some(declared), _) => Ok(Some(declared)),
        (None, invocation) => Ok(invocation),
    }
}
pub(super) fn arguments_error(tool: &'static str, detail: impl Into<String>) -> HostToolError {
    HostToolError::Arguments {
        tool,
        detail: detail.into(),
    }
}

pub(super) fn storage_error(tool: &'static str, detail: impl Into<String>) -> HostToolError {
    HostToolError::Storage {
        tool,
        detail: detail.into(),
    }
}

/// Maps typed reconciler/client failures onto host-tool failures. Typed
/// unavailability becomes the schema's `unavailable` settlement at the call
/// sites (which know the output shape); everything else is a named host-tool
/// rejection, and opaque API failures stay `Uncertain` — the settlement state
/// of an API-layer failure cannot be proven, so it is never claimed.
pub(super) fn kube_failure(tool: &'static str, error: KubeError) -> HostToolError {
    match error {
        KubeError::Conflict { reason } | KubeError::Rejected { reason } => {
            arguments_error(tool, reason)
        }
        KubeError::Storage { reason } => HostToolError::Storage {
            tool,
            detail: reason,
        },
        other => HostToolError::Uncertain {
            tool,
            detail: other.to_string(),
        },
    }
}

/// Maps the control surface's protocol failures. `Unavailable` is consumed by
/// the call sites as the typed `unavailable` settlement; the remaining
/// rejections are non-retryable argument-level failures carrying the typed
/// protocol reason.
pub(super) fn protocol_failure(tool: &'static str, error: HuginnProtocolError) -> HostToolError {
    arguments_error(tool, error.to_string())
}

/// The actuation bound for `create`: the declared per-request bound times
/// the bounded journal/staging/job phases, plus fixed scheduling slack.
pub(super) fn create_deadline(bounds: (Duration, Duration)) -> Duration {
    bounds.0.saturating_mul(4) + Duration::from_secs(10)
}

/// The actuation bound for one run-addressed mutation: the declared
/// teardown window — cancellation settles a graceful Job teardown — plus
/// two bounded request phases and fixed slack. Never shorter than the
/// declared teardown, so a legitimate teardown is never abandoned mid
/// flight and reported as failed while it still settles.
pub(super) fn mutation_deadline(bounds: (Duration, Duration)) -> Duration {
    bounds.1 + bounds.0.saturating_mul(2) + Duration::from_secs(10)
}

/// Fails closed when the configured deployment bounds require a wider
/// actuation window than the permit's published capability timeout: the
/// outer declaration must never clip the inner actuation, so an
/// unsupported configuration is a typed refusal before any effect.
pub(super) fn checked_deadline(
    tool: &'static str,
    inner: Duration,
    published_seconds: u32,
) -> Result<Duration, HostToolError> {
    let outer = Duration::from_secs(u64::from(published_seconds));
    if inner > outer {
        return Err(HostToolError::Unavailable {
            tool,
            reason: format!(
                "configured kube bounds require a {inner:?} actuation window, exceeding the published {published_seconds}s capability timeout"
            ),
        });
    }
    Ok(inner)
}

pub(super) fn create_replay_or_fresh(
    tool: &'static str,
    control: &KubeControl,
    run_id: &RunId,
    operation_id: &OperationId,
    target: Option<&str>,
) -> Result<Option<Value>, HostToolError> {
    if let Some(stored) = control
        .reconciler()
        .stored_launch(run_id)
        .map_err(|error| kube_failure(tool, error))?
    {
        if stored.initial_target_node.as_deref() != target {
            return Err(arguments_error(
                tool,
                "initial target differs from the run's admitted declaration",
            ));
        }
    }
    replay_or_fresh(tool, control, run_id, operation_id)
}

/// Replays settled outcomes by permit operation ID without repeating effects.
/// `None` allows execution under the same permit, with replay handled by the reconciler.
pub(super) fn replay_or_fresh(
    tool: &'static str,
    control: &KubeControl,
    run_id: &RunId,
    operation_id: &OperationId,
) -> Result<Option<Value>, HostToolError> {
    let Some(outcome) = control
        .reconciler()
        .operation_outcome(operation_id)
        .map_err(|error| kube_failure(tool, error))?
    else {
        return Ok(None);
    };
    let settled = match outcome {
        Ok(observation) => {
            let settlement = mutation_settlement(
                MutationStatus::Duplicate,
                run_id.as_str(),
                operation_id.as_str(),
                &observation,
            );
            serialize_output(tool, &settlement)?
        }
        Err(KubeError::Unavailable { reason }) => {
            // A journaled unavailability verdict is post-dispatch: stop
            // intent, staging, or API calls may already have acted, so the
            // replayed outcome is unproved settlement, never a clean
            // no-effect rejection.
            return Err(HostToolError::Uncertain {
                tool,
                detail: format!(
                    "the journaled operation recorded unavailability: {reason}; its settlement state is unproven"
                ),
            });
        }
        Err(KubeError::Conflict { reason }) => {
            return Err(arguments_error(
                tool,
                format!(
                    "the admitted operation already conflicts with the cluster revision: {reason}"
                ),
            ));
        }
        Err(KubeError::Rejected { reason }) => return Err(arguments_error(tool, reason)),
        Err(KubeError::Storage { reason }) => return Err(storage_error(tool, reason)),
        Err(other) => return Err(kube_failure(tool, other)),
    };
    Ok(Some(settled))
}

// ---------------------------------------------------------------------------
// Argument wire contracts: exactly the published capability input schemas.
// ---------------------------------------------------------------------------

/// `kube.workload.create.input`: exactly one admitted published profile name.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct ProfileInput {
    pub(super) profile: String,
    #[serde(default)]
    pub(super) target_node: Option<String>,
    /// Artifacts (blake3 ids) a script pod receives, in order, at
    /// `/var/run/odin/staging/input-<n>`.
    #[serde(default)]
    pub(super) inputs: Vec<String>,
    /// Stored as a run-bound artifact and staged after explicit inputs.
    #[serde(default)]
    pub(super) prompt: Option<String>,
    /// One directory segment. Absent launches name no company.
    #[serde(default)]
    pub(super) company: Option<String>,
    /// Shown in views as the run's label (the Job's `odin.label` annotation); never identity.
    #[serde(default)]
    pub(super) label: Option<String>,
    /// Run limits this launch lowers from the profile's declared values.
    #[serde(default)]
    pub(super) limits: Option<odin_domain::huginn::WorkloadLimits>,
    /// What the run is about: odin-recon runs on these as soon as the pod is up.
    #[serde(default)]
    pub(super) seeds: Vec<String>,
    /// A finished run of the same profile whose state this run takes over, on its node.
    #[serde(default)]
    pub(super) continue_from: Option<String>,
    /// The caller-presented approval selector on the phase-two dispatch. The
    /// kernel gate consumes it before the handler runs; the handler itself
    /// never interprets it.
    #[serde(default, rename = "approvalId")]
    _approval_id: Option<serde::de::IgnoredAny>,
}

/// Run-addressed mutation inputs: the schema-sanctioned run plus the exact
/// opaque `expectedResourceVersion` observed at admission, which travels
/// to the reconciler verbatim as the compare-and-swap.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct RunInput {
    pub(super) run_id: String,
    pub(super) expected_resource_version: String,
    /// Restart only: rehome the pod onto this cluster node.
    /// The reconciler admits it only inside the deployment's
    /// placement authority and the pod's declared placement, and carries
    /// node-bound state there.
    #[serde(default)]
    pub(super) target_node: Option<String>,
    /// Pause only: also capture the paused pod's per-pod state as a
    /// checkpoint artifact.
    #[serde(default)]
    pub(super) checkpoint: bool,
    /// The caller-presented approval selector on the phase-two dispatch. The
    /// kernel gate consumes it before the handler runs; the handler itself
    /// never interprets it.
    #[serde(default, rename = "approvalId")]
    _approval_id: Option<serde::de::IgnoredAny>,
}

/// `kube.workload.summarize.input`: optional run selector, and how many of
/// that run's newest log lines to read.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct OptionalRunInput {
    #[serde(default)]
    pub(super) run_id: Option<String>,
    #[serde(default)]
    pub(super) log_lines: Option<i64>,
}

/// The most log lines one summarize reads.
pub(super) const MAX_LOG_LINES: i64 = 200;

impl OptionalRunInput {
    /// A log read names one run and keeps 1 to [`MAX_LOG_LINES`] lines.
    pub(super) fn checked_log_lines(
        &self,
        tool: &'static str,
    ) -> Result<Option<i64>, HostToolError> {
        let Some(lines) = self.log_lines else {
            return Ok(None);
        };
        if self.run_id.is_none() {
            return Err(arguments_error(
                tool,
                "logLines reads one run's log: name its runId",
            ));
        }
        if !(1..=MAX_LOG_LINES).contains(&lines) {
            return Err(arguments_error(
                tool,
                format!("logLines must be an integer from 1 to {MAX_LOG_LINES}"),
            ));
        }
        Ok(Some(lines))
    }
}

/// `kube.snapshot.read.input`: no parameters.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct NoInput {}

#[cfg(test)]
#[path = "tests/preflight.rs"]
mod tests;

/// Restart reuses the admitted image, which deployment may have pruned;
/// require a fresh launch when the platform image has changed.
pub(crate) fn replaced_image_refusal(
    launch: &odin_kube::JobLaunch,
    deployed: &str,
) -> Option<String> {
    let repository = |image: &str| {
        image.split('@').next().map(|name| {
            name.rsplit_once(':')
                .filter(|(_, tag)| !tag.contains('/'))
                .map_or(name, |(repository, _)| repository)
                .to_owned()
        })
    };
    (launch.extension.is_some()
        && launch.image != deployed
        && repository(&launch.image) == repository(deployed))
    .then(|| {
        format!(
            "it launched image {}, which a deploy has since replaced with {deployed}; a restart \
             would reuse the replaced image, so launch the profile again (kube_workload_create)",
            launch.image
        )
    })
}

#[cfg(test)]
mod launch_limit_tests {
    use odin_domain::{RunId, Scope};

    use super::{decode_arguments, pod_launch_scope, ProfileInput};

    const TOOL: &str = "kube.workload.create";

    #[test]
    fn a_launch_names_only_declared_limit_fields_and_its_limits_join_the_run() {
        let with_limits = |limits: serde_json::Value| {
            decode_arguments::<ProfileInput>(
                TOOL,
                serde_json::json!({"profile": "research", "limits": limits}),
            )
        };
        assert!(with_limits(serde_json::json!({"outputTokens": 1})).is_err());
        let lowered =
            with_limits(serde_json::json!({"deadlineSeconds": 3600})).expect("a declared field");
        let scope = Scope {
            run: Some(RunId::new("run:live:session").expect("run")),
            ..Scope::default()
        };
        let plain: ProfileInput =
            decode_arguments(TOOL, serde_json::json!({"profile": "research"}))
                .expect("plain launch");
        let run =
            |input: &ProfileInput| pod_launch_scope(TOOL, &scope, input, 1).expect("scope").run;
        assert_ne!(
            run(&lowered),
            run(&plain),
            "declared limits change the run identity"
        );
        assert_eq!(
            run(&plain),
            pod_launch_scope(TOOL, &scope, &plain, 1)
                .expect("scope")
                .run,
            "a launch without limits keeps its identity"
        );
    }
}

#[cfg(test)]
mod sphere_profile_tests {
    use super::require_sphere_profile;
    use odin_domain::ProjectId;
    use odin_omp::host_tools::HostToolError;
    use odin_registry::schema::{ObjectConfig, ProjectSphereToml, ProjectToml, RegistryKind};
    use odin_registry::{RegistryObject, Snapshot};
    use std::collections::BTreeSet;

    const TOOL: &str = "odin_kube.workload.create";

    fn project(id: &str, enabled: bool, sphere: Option<ProjectSphereToml>) -> RegistryObject {
        RegistryObject {
            id: id.to_owned(),
            relative_config: format!("projects/{id}/project.toml").into(),
            config: ObjectConfig::Project(Box::new(ProjectToml {
                schema: odin_registry::schema::REGISTRY_SCHEMA.to_owned(),
                kind: RegistryKind::Project,
                enabled,
                description: "fixture".to_owned(),
                source_root: "/work".to_owned(),
                default_seat: "gungnir".parse().expect("seat"),
                memory_namespaces: BTreeSet::new(),
                privacy: None,
                accounts: Default::default(),
                review_verdict: None,
                repo: None,
                hub_refresh_seconds: None,
                deploy: None,
                sphere,
                agents: Default::default(),
            })),
        }
    }

    fn sphere(profiles: &[&str]) -> ProjectSphereToml {
        ProjectSphereToml {
            data_roots: vec!["/data/reference".to_owned()],
            scratch: "/scratch/results".to_owned(),
            pod_profiles: profiles
                .iter()
                .map(|profile| (*profile).to_owned())
                .collect(),
            devices: Vec::new(),
        }
    }

    fn snapshot(objects: Vec<RegistryObject>) -> Snapshot {
        Snapshot::build(1, objects).expect("fixture snapshot")
    }

    fn project_id(id: &str) -> ProjectId {
        ProjectId::new(id).expect("project id")
    }

    fn refusal(snapshot: &Snapshot, project: &str, profile: &str) -> String {
        match require_sphere_profile(TOOL, snapshot, &project_id(project), profile) {
            Err(HostToolError::Arguments { detail, .. }) => detail,
            other => panic!("expected a scope refusal, got {other:?}"),
        }
    }

    #[test]
    fn a_declared_sphere_admits_only_its_pod_profiles() {
        let pinned = snapshot(vec![project(
            "sim",
            true,
            Some(sphere(&["sim-gpu", "research"])),
        )]);
        let sim = project_id("sim");
        assert!(require_sphere_profile(TOOL, &pinned, &sim, "sim-gpu").is_ok());
        assert!(require_sphere_profile(TOOL, &pinned, &sim, "research").is_ok());
        let reason = refusal(&pinned, "sim", "browser-contain");
        assert!(reason.contains("sim-gpu"), "{reason}");
        assert!(reason.contains("research"), "{reason}");
        assert!(reason.contains("browser-contain"), "{reason}");
    }
}
