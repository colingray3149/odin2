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
    /// Seats that read every run, not only their own and their project's:
    /// the owner-facing conversation seats.
    pub(super) overseers: std::collections::BTreeSet<SeatId>,
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
            overseers: std::collections::BTreeSet::new(),
        }
    }

    /// The seats that read every run (Colin's conversation seats answer
    /// "which pods ran today" without asking the seat that launched them).
    pub fn with_overseers(mut self, seats: std::collections::BTreeSet<SeatId>) -> Self {
        self.overseers = seats;
        self
    }

    /// Arms the workload launch port exactly once; a second arming is a
    /// composition defect, never a silent replacement.
    pub fn arm_workload_port(&self, port: Arc<dyn WorkloadLaunchPort>) -> Result<(), String> {
        self.workload
            .set(port)
            .map_err(|_| "workload launch port was already armed".to_owned())
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
        let tool = KubeCapabilityBinding::WorkloadCreate.id();
        // Use the same scope checks as execution.
        require_kube_seat_scope(tool, scope)?;
        let input: ProfileInput = decode_arguments(tool, arguments.clone())?;
        let scope = &pod_launch_scope(tool, scope, &input.profile, 1)?;
        let (run_id, _, _) = require_kube_launch_scope(tool, scope)?;
        // An un-armed launch port falls to the container-profile path at
        // execution; no declared gate exists to run here.
        let Some(port) = self.workload_port() else {
            return self.require_create_target(tool, input.target_node.as_deref(), None);
        };
        let resolution = port.resolve_launch(&input.profile);
        // The route refusal stays FIRST and verbatim: a dispatch the
        // served projection cannot route never reaches cell or journal
        // checks.
        let inputs = match resolution {
            WorkloadResolve::NotWorkload | WorkloadResolve::Script(_) => None,
            WorkloadResolve::Launch(inputs) => Some(inputs),
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
                self.preflight_workload_gateway(tool, &inputs)?;
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
        inputs: &WorkloadLaunchInputs,
    ) -> Result<(), HostToolError> {
        let target = odin_kube::workload::WorkloadGatewayTarget {
            host: inputs.gateway.host().to_owned(),
            port: inputs.gateway.port(),
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
            reason: format!("workload profile {:?}: {error}", inputs.profile.id),
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
    fn launchable_profiles(&self) -> Vec<odin_omp::host_tools::LaunchableProfile> {
        self.runtime_cell
            .as_ref()
            .map(|cell| cell.launchable_profiles())
            .unwrap_or_default()
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
            | KubeCapabilityBinding::WorkloadPauseEvidence
            | KubeCapabilityBinding::WorkloadResumeEvidence
            | KubeCapabilityBinding::WorkloadRestartEvidence
            | KubeCapabilityBinding::WorkloadCancelEvidence
            | KubeCapabilityBinding::WorkloadSummarizeEvidence
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

/// The invocation scope a pod launch runs under: the session's run plus one
/// run per launched profile, `<session run>:pod:<profile>`. A run owns
/// exactly one Job (its name, idempotency digest and stored launch all
/// derive from the run), so a create bound to the bare session run let a
/// seat session own one pod: Kubert asked to launch four pods got the first
/// and three "operation identity or idempotency digest was reused" refusals
/// The pod run keeps the session
/// as its prefix, so a pod's findings still reach the launching session
/// (`workload_watch::launching_session`), and a retried create of the same
/// profile in the same session stays the same run (idempotent).
///
/// `generation` numbers the session's launches of that profile: the first
/// is the bare `<session run>:pod:<profile>`, a later one (after the
/// earlier run finished) appends `:<generation>` — see
/// [`pod_run_generation`].
pub(super) fn pod_launch_scope(
    tool: &'static str,
    scope: &Scope,
    profile: &str,
    generation: u32,
) -> Result<Scope, HostToolError> {
    let session_run = scope.run.as_ref().ok_or(HostToolError::Scope {
        tool,
        reason: "workload creation addresses the invocation's bound run",
    })?;
    let suffix = if generation > 1 {
        format!(":{generation}")
    } else {
        String::new()
    };
    let readable = format!("{session_run}:pod:{profile}{suffix}");
    let run = RunId::new(readable.as_str())
        .or_else(|_| {
            // Use a digest when the profile cannot fit the run ID's format or 128-byte limit.
            let digest = odin_domain::Digest::hash(profile.as_bytes()).to_string();
            let short = digest.trim_start_matches("blake3:");
            RunId::new(format!("{session_run}:pod:{}{suffix}", &short[..32]).as_str())
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
    /// Launched and still live (pending, staging, running, paused): a
    /// create of the same profile is the same pod (idempotent replay).
    Live,
    /// Launched and finished: succeeded, failed, cancelled or gone.
    Finished,
}

/// The most launches of one profile a single session may make.
pub(super) const MAX_POD_GENERATIONS: u32 = 64;

/// The generation a create of one profile in one session takes: the first
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
            "this session already launched that profile {MAX_POD_GENERATIONS} times; \
             continue in a new session"
        ),
    ))
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
                tool,
                MutationStatus::Duplicate,
                run_id.as_str(),
                operation_id.as_str(),
                &observation,
            )?;
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

/// `kube.workload.summarize.input`: optional run selector.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct OptionalRunInput {
    #[serde(default)]
    pub(super) run_id: Option<String>,
}

/// `kube.snapshot.read.input`: no parameters.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct NoInput {}

#[cfg(test)]
mod approval_selector_decode_tests {
    use super::*;

    #[test]
    fn the_phase_two_approval_selector_rides_the_kube_arguments_lawfully() {
        let input: ProfileInput = decode_arguments(
            "kube_workload_create",
            serde_json::json!({
                "profile": "gpu-smoke",
                "approvalId": "approval:r3:kube.workload.create:blake3:c63667cf"
            }),
        )
        .expect("the schema-declared approval selector decodes");
        assert_eq!(input.profile, "gpu-smoke");

        let run: RunInput = decode_arguments(
            "kube_workload_cancel",
            serde_json::json!({
                "runId": "run:live:efe4a728",
                "expectedResourceVersion": "12345",
                "approvalId": "approval:r3:kube.workload.cancel:blake3:aa"
            }),
        )
        .expect("the run-addressed mutations decode the selector too");
        assert_eq!(run.run_id, "run:live:efe4a728");
    }
}

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
