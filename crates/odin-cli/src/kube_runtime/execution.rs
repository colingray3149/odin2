//! Mutation and read execution: the handlers that actuate or observe the
//! real cluster through the control surface.

use std::future::Future;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use odin_domain::huginn::{HuginnProtocolError, KubeWorkloadState};
use odin_domain::RunId;
use odin_kube::workload::WorkloadPlacement;
use odin_kube::{JobAction, JobObservation, KubeError};
use odin_ledger::Ledger;
use odin_omp::host_tools::{HostInvocation, HostToolError};
use odin_types::OperationId;
use serde_json::Value;
use time::OffsetDateTime;

use super::launch_queue::QueuedLaunch;
use super::{WorkloadLaunchInputs, WorkloadLaunchPort, WorkloadResolve, WorkloadSessionOpenError};

use super::admission::{
    admitted_limits, agent_pod_launch_admissible, arguments_error, checked_deadline,
    create_deadline, create_replay_or_fresh, decode_arguments, kube_failure, mutation_deadline,
    pod_launch_scope, pod_run_generation, protocol_failure, replay_or_fresh,
    require_kube_launch_scope, require_kube_seat_scope, require_no_campaign_policy,
    require_sphere_profile, require_workload_scope, resolve_create_attempt, validate_run_label,
    NoInput, OptionalRunInput, PodRunUse, ProfileInput,
};
use super::evidence::{
    health_unavailable, mutation_settlement, offload_summarize_row, serialize_output,
    serialize_value, snapshot_unavailable, summarize_row, summarize_unavailable, HealthOutput,
    MutationOutput, MutationStatus, ReadStatus, SnapshotOutput, SummarizeOutput, AGENT_POD_REPORT,
};
use super::launch::{container_identity, mutation_operation, profile_launch, LaunchRequest};
use super::KubeCommandCoordinator;

#[path = "pod_logs.rs"]
mod pod_logs;
use pod_logs::{pod_log, pod_status};

#[path = "execution_offload.rs"]
mod execution_offload;
#[path = "execution_workload.rs"]
mod execution_workload;

/// The extra actuation window a rehome that carries node-bound state may
/// take: two helper pods (each bounded to start in 120 s) and the copy.
const REHOME_CARRY_WINDOW: Duration = Duration::from_secs(320);
/// Copy the daemon's resolved transport onto a protected launch. A missing
/// binding refuses the launch; it never selects direct routing.
fn bind_vpn_transport(
    tool: &'static str,
    transport: odin_registry::WorkloadTransport,
    config: &odin_kube::KubeConfig,
) -> Result<Option<odin_kube::workload::WorkloadVpnTransportPlan>, HostToolError> {
    if transport != odin_registry::WorkloadTransport::VpnRequired {
        return Ok(None);
    }
    let Some(binding) = &config.vpn_transport else {
        return Err(arguments_error(
            tool,
            "vpn-required workload has no resolved transport binding; refusing direct fallback",
        ));
    };
    binding
        .validate()
        .map_err(|reason| arguments_error(tool, reason))?;
    Ok(Some(odin_kube::workload::WorkloadVpnTransportPlan {
        endpoint: binding.endpoint,
        port: binding.port,
        dns: binding.dns,
        launcher: binding.launcher.display().to_string(),
        resolver: binding
            .resolver
            .as_ref()
            .map(|path| path.display().to_string()),
        forwarded: binding.forwarded,
    }))
}
pub(super) fn batch_run_scope(
    tool: &'static str,
    caller: &odin_domain::Scope,
    operation: &OperationId,
) -> Result<odin_domain::Scope, HostToolError> {
    let mut scope = caller.clone();
    let parent = scope.run.as_ref().ok_or(HostToolError::Scope {
        tool,
        reason: "workload creation addresses the invocation's bound run",
    })?;
    let digest = blake3::hash(operation.as_str().as_bytes())
        .to_hex()
        .to_string();
    let run = format!("{parent}:pod:batch:{digest}");
    scope.run = Some(
        RunId::new(&run)
            .or_else(|_| RunId::new(format!("{parent}:pod:batch:{}", &digest[..16])))
            .map_err(|error| arguments_error(tool, format!("cannot derive batch run: {error}")))?,
    );
    Ok(scope)
}

#[cfg(test)]
mod batch_run_tests {
    use super::*;

    #[test]
    fn batch_items_have_distinct_replayable_runs() {
        let caller = odin_domain::Scope {
            run: Some(RunId::new("run:live:session").unwrap()),
            ..Default::default()
        };
        let first = OperationId::new("item-1").unwrap();
        let second = OperationId::new("item-2").unwrap();
        let one = batch_run_scope("test", &caller, &first).unwrap();
        assert_eq!(one, batch_run_scope("test", &caller, &first).unwrap());
        assert_ne!(
            one.run,
            batch_run_scope("test", &caller, &second).unwrap().run
        );
        assert!(one
            .run
            .unwrap()
            .as_str()
            .starts_with("run:live:session:pod:"));
    }
}

struct ScriptCreate<'a> {
    held: &'a QueuedLaunch,
    inputs: &'a crate::kube_runtime::ScriptLaunchInputs,
    campaign_reservation: Option<&'a odin_ledger::campaign::Reservation>,
    artifacts: &'a [String],
    prompt: Option<&'a str>,
    label: Option<String>,
    continue_from: Option<RunId>,
    caller_scope: &'a odin_domain::Scope,
    target_node: Option<&'a str>,
    tool: &'static str,
    timeout_seconds: u32,
    operation_id: OperationId,
    scope: &'a odin_domain::Scope,
}

struct WorkloadCreate<'a> {
    held: &'a QueuedLaunch,
    port: Arc<dyn WorkloadLaunchPort>,
    inputs: Box<WorkloadLaunchInputs>,
    artifacts: &'a [String],
    prompt: Option<&'a str>,
    label: Option<String>,
    company: Option<String>,
    continue_from: Option<RunId>,
    caller_scope: &'a odin_domain::Scope,
    target_node: Option<&'a str>,
    tool: &'static str,
    timeout_seconds: u32,
    operation_id: OperationId,
    scope: &'a odin_domain::Scope,
}

impl KubeCommandCoordinator {
    /// `kube.workload.create`: launches the named published container profile
    /// as one finite batch/v1 Job for the scope-bound run.
    pub(super) async fn create(
        &self,
        tool: &'static str,
        timeout_seconds: u32,
        operation_id: OperationId,
        invocation: HostInvocation,
    ) -> Result<Value, HostToolError> {
        let held = QueuedLaunch::new(&operation_id, timeout_seconds, &invocation);
        self.create_held(tool, timeout_seconds, operation_id, invocation, held)
            .await
    }

    pub(super) async fn create_held(
        &self,
        tool: &'static str,
        timeout_seconds: u32,
        operation_id: OperationId,
        invocation: HostInvocation,
        held: QueuedLaunch,
    ) -> Result<Value, HostToolError> {
        let HostInvocation { scope, arguments } = invocation;
        let seat = require_kube_seat_scope(tool, &scope)?;
        let input: ProfileInput = decode_arguments(tool, arguments)?;
        let campaign_reservation =
            if held.campaign.is_some() || held.campaign_stage_sha256.is_some() {
                let campaign = held
                    .campaign
                    .as_deref()
                    .ok_or_else(|| arguments_error(tool, "campaign reservation is missing"))?;
                let digest = held
                    .campaign_stage_sha256
                    .as_deref()
                    .ok_or_else(|| arguments_error(tool, "campaign stage pin is missing"))?;
                if digest.len() != 64
                    || !digest
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
                {
                    return Err(arguments_error(tool, "invalid campaign stage pin"));
                }
                let queue = self
                    .launch_queue()
                    .ok_or_else(|| HostToolError::Unavailable {
                        tool,
                        reason: "campaign launch queue is not configured".to_owned(),
                    })?;
                let root = queue
                    .campaign_state_dir()
                    .map_err(|reason| HostToolError::Unavailable { tool, reason })?;
                let (reserved_campaign, reservation, state) =
                    odin_ledger::campaign::lookup(root, operation_id.as_str()).map_err(
                        |error| HostToolError::Unavailable {
                            tool,
                            reason: format!("campaign reservation unavailable: {error}"),
                        },
                    )?;
                if held.operation_id != operation_id.as_str()
                    || reserved_campaign != campaign
                    || state != "reserved"
                    || reservation.node != input.target_node.as_deref().unwrap_or("")
                    || reservation.stage_sha256 != digest
                    || reservation.profile != input.profile
                {
                    return Err(arguments_error(
                        tool,
                        "campaign launch does not match its active reservation",
                    ));
                }
                Some(reservation)
            } else {
                None
            };
        validate_run_label(tool, input.label.as_deref())?;
        let continue_from = input
            .continue_from
            .as_deref()
            .map(RunId::new)
            .transpose()
            .map_err(|error| arguments_error(tool, format!("invalid continueFrom: {error}")))?;
        let caller_scope = scope;
        // Each distinct launch owns its own run under the session's run, so
        // one session can launch several pods, of one profile or many — and
        // a launch made again after its earlier run finished gets a fresh run.
        let scope = if held.batch.is_some() {
            batch_run_scope(tool, &caller_scope, &operation_id)?
        } else {
            self.pod_create_scope(tool, &caller_scope, &input, &operation_id)
                .await?
        };
        let (run_id, project_id, lane_id) = require_kube_launch_scope(tool, &scope)?;
        if let Some(cell) = self.runtime_cell.as_ref() {
            require_sphere_profile(tool, &cell.snapshot(), &project_id, &input.profile)?;
        }
        // A published workload-profile id resolves through the daemon's
        // workload launch port FIRST: profiles are registry data across two
        // namespaces, so only the port's typed lookup decides container
        // versus workload — an id that is neither refuses on the container
        // path exactly as before.
        if let Some(port) = self.workload_port() {
            match port.resolve_launch(&input.profile) {
                WorkloadResolve::NotWorkload => {}
                WorkloadResolve::Refused(reason) => {
                    return Err(arguments_error(tool, reason));
                }
                WorkloadResolve::Launch(mut inputs) => {
                    if campaign_reservation.is_some() {
                        return Err(arguments_error(
                            tool,
                            "campaign launches require a script workload",
                        ));
                    }
                    require_no_campaign_policy(
                        tool,
                        inputs.profile.profile.require_campaign_approval,
                    )?;
                    inputs.limits = admitted_limits(tool, &inputs.profile, &input)?;
                    inputs.seeds = input.seeds.clone();
                    self.require_create_target(
                        tool,
                        input.target_node.as_deref(),
                        Some(inputs.target_node.as_str()),
                    )?;
                    agent_pod_launch_admissible(
                        tool,
                        crate::project_authoring::reload_requested(),
                    )?;
                    return self
                        .create_workload(WorkloadCreate {
                            held: &held,
                            port,
                            inputs,
                            artifacts: &input.inputs,
                            prompt: input.prompt.as_deref(),
                            label: input.label.clone(),
                            company: input.company.clone(),
                            continue_from,
                            caller_scope: &caller_scope,
                            target_node: input.target_node.as_deref(),
                            tool,
                            timeout_seconds,
                            operation_id,
                            scope: &scope,
                        })
                        .await;
                }
                WorkloadResolve::Script(mut inputs) => {
                    require_no_campaign_policy(
                        tool,
                        inputs.profile.profile.require_campaign_approval && held.campaign.is_none(),
                    )?;
                    super::launch::admit_script_limits(tool, &mut inputs, &input)?;
                    if let Some(reservation) = &campaign_reservation {
                        if inputs.profile.profile.offload.is_some() {
                            return Err(arguments_error(
                                tool,
                                "campaign launches cannot use offload profiles",
                            ));
                        }
                        let profile = &inputs.profile.profile;
                        let cpu = profile
                            .resources
                            .as_ref()
                            .map(|resources| resources.cpu)
                            .filter(|cpu| *cpu > 0)
                            .ok_or_else(|| {
                                arguments_error(tool, "campaign profile requires a CPU reservation")
                            })?;
                        let deadline = profile
                            .deadline_seconds()
                            .filter(|deadline| *deadline > 0)
                            .ok_or_else(|| {
                                arguments_error(tool, "campaign profile requires a finite deadline")
                            })?;
                        if f64::from(cpu) * f64::from(deadline) / 3600.0 > reservation.core_hours {
                            return Err(arguments_error(
                                tool,
                                "campaign workload exceeds its reserved core-hours",
                            ));
                        }
                    }
                    self.require_create_target(tool, input.target_node.as_deref(), None)?;
                    return self
                        .create_script(ScriptCreate {
                            held: &held,
                            inputs: &inputs,
                            campaign_reservation: campaign_reservation.as_ref(),
                            artifacts: &input.inputs,
                            prompt: input.prompt.as_deref(),
                            label: input.label.clone(),
                            continue_from,
                            caller_scope: &caller_scope,
                            target_node: input.target_node.as_deref(),
                            tool,
                            timeout_seconds,
                            operation_id,
                            scope: &scope,
                        })
                        .await;
                }
            }
        }
        if campaign_reservation.is_some() {
            return Err(arguments_error(
                tool,
                "campaign launches require a script workload",
            ));
        }
        if continue_from.is_some() {
            return Err(arguments_error(
                tool,
                format!(
                    "{} declares no state: continueFrom applies to script and agent pods",
                    input.profile
                ),
            ));
        }
        if !input.inputs.is_empty() || input.prompt.is_some() {
            return Err(arguments_error(
                tool,
                format!(
                    "{} takes no inputs: artifacts reach script and agent pods only",
                    input.profile
                ),
            ));
        }
        let Some(cell) = self.runtime_cell.as_ref() else {
            return Err(HostToolError::Unavailable {
                tool,
                reason: "the kube surface is not configured".to_owned(),
            });
        };
        let Some(container) = cell
            .container_profile(&input.profile)
            .filter(|container| container.enabled)
        else {
            // A profile published moments ago is served only after odind's
            // reload; say so, or the model retries the same launch in a loop.
            if crate::project_authoring::reload_requested() {
                return Err(HostToolError::Unavailable {
                    tool,
                    reason: format!(
                        "{:?} may be newly published: it goes live when Odin restarts in about a \
                         minute to activate the publication. Launch it again after the restart.",
                        input.profile
                    ),
                });
            }
            return Err(arguments_error(
                tool,
                format!(
                    "published container profile {:?} is not admitted",
                    input.profile
                ),
            ));
        };
        if !container.seats_offered.is_empty() && !container.seats_offered.contains(&seat) {
            return Err(HostToolError::Scope {
                tool,
                reason: "the bound seat is not offered the requested container profile",
            });
        }
        self.require_create_target(tool, input.target_node.as_deref(), None)?;
        let Some(launch_binding) = cell.launch_binding() else {
            return Err(HostToolError::Unavailable {
                tool,
                reason: "the daemon cannot resolve the published model and budget binding for workload labels"
                    .to_owned(),
            });
        };
        let identity = container_identity(tool, &container)?;
        let (control, bounds) = match self.resolve_control() {
            Ok(resolved) => resolved,
            Err(reason) => return Err(HostToolError::Unavailable { tool, reason }),
        };
        // The permit's operation id is the sole durable settlement key: a
        // journaled outcome answers from the journal and never re-launches.
        if let Some(settled) = create_replay_or_fresh(
            tool,
            &control,
            &run_id,
            &operation_id,
            input.target_node.as_deref(),
        )? {
            return Ok(settled);
        }

        // Reuse the declared attempt; reject explicit mismatches before effects.
        let attempt = resolve_create_attempt(
            tool,
            control
                .reconciler()
                .stored_launch(&run_id)
                .map_err(|error| kube_failure(tool, error))?
                .map(|stored| stored.labels.attempt_id),
            scope.attempt.clone(),
        )?;
        let request = LaunchRequest {
            tool,
            binding: &launch_binding,
            run_id: run_id.clone(),
            project_id,
            lane_id,
            budget_lane: None,
            seat_id: seat.clone(),
            attempt,
            operation_id: operation_id.clone(),
            initial_target_node: input.target_node,
            label: input.label.clone(),
            continue_from: None,
        };
        let mut launch = profile_launch(request, &container, identity)?;
        if let Some(queued) = self
            .hold_when_full(tool, &control, &mut launch, &held, &run_id)
            .await?
        {
            return Ok(queued);
        }
        let deadline = checked_deadline(tool, create_deadline(bounds), timeout_seconds)?;
        let staged = control.create(launch, OffsetDateTime::now_utc());
        let observation = match tokio::time::timeout(deadline, staged).await {
            Ok(result) => result.map_err(|error| protocol_failure(tool, error))?,
            Err(_elapsed) => {
                return Err(HostToolError::Uncertain {
                    tool,
                    detail: "the workload create exceeded its declared actuation bound; the settlement state is unproven"
                        .to_owned(),
                });
            }
        };
        let settlement = mutation_settlement(
            MutationStatus::Accepted,
            run_id.as_str(),
            operation_id.as_str(),
            &observation,
        );
        serialize_output(tool, &settlement)
    }

    /// The pod run one create binds: the run an already-admitted operation
    /// launched (a retried permit replays, never relaunches), else the
    /// first generation of the launch's run ([`pod_launch_scope`]) that is
    /// unused or still live ([`pod_run_generation`]).
    async fn pod_create_scope(
        &self,
        tool: &'static str,
        scope: &odin_domain::Scope,
        input: &ProfileInput,
        operation_id: &OperationId,
    ) -> Result<odin_domain::Scope, HostToolError> {
        // Without a reachable cluster the create refuses further on; the
        // first generation keeps that refusal unchanged.
        let Ok((control, _)) = self.resolve_control() else {
            return pod_launch_scope(tool, scope, input, 1);
        };
        let reconciler = control.reconciler();
        if let Some((run, _)) = reconciler
            .operation_launch(operation_id.as_str())
            .map_err(|error| kube_failure(tool, error))?
        {
            let mut admitted = scope.clone();
            admitted.run = Some(run);
            return Ok(admitted);
        }
        let mut uses = Vec::new();
        for generation in 1..=super::admission::MAX_POD_GENERATIONS {
            let candidate = pod_launch_scope(tool, scope, input, generation)?;
            let run = candidate
                .run
                .clone()
                .expect("a pod launch scope binds a run");
            let launched = reconciler
                .stored_launch(&run)
                .map_err(|error| kube_failure(tool, error))?
                .is_some();
            let used = if !launched {
                PodRunUse::Unused
            } else {
                match control.summarize(&run).await {
                    Ok(Some(observation)) => pod_run_use(observation.projection.lifecycle),
                    // The Job is gone: that run ended.
                    Ok(None) => PodRunUse::Finished,
                    // Unreadable: keep the run (an idempotent replay at
                    // worst), never mint a second pod for a live one.
                    Err(_) => PodRunUse::Live,
                }
            };
            uses.push(used);
            if used != PodRunUse::Finished {
                break;
            }
        }
        let generation = pod_run_generation(tool, |generation| {
            Ok(uses
                .get(generation as usize - 1)
                .copied()
                .unwrap_or(PodRunUse::Finished))
        })?;
        if generation > 1 {
            tracing::warn!(
                "pod run generation profile={} generation={generation} \
                 reason=\"the session's earlier identical launch finished\"",
                input.profile
            );
        }
        pod_launch_scope(tool, scope, input, generation)
    }

    /// The script pod create path: the declared command
    /// in the declared image under the SAME control surface, journal, and
    /// settlement as every workload mutation; no session opens.
    async fn create_script(&self, create: ScriptCreate<'_>) -> Result<Value, HostToolError> {
        let ScriptCreate {
            held,
            inputs,
            campaign_reservation,
            artifacts,
            prompt,
            label,
            continue_from,
            caller_scope,
            target_node,
            tool,
            timeout_seconds,
            operation_id,
            scope,
        } = create;
        require_workload_scope(tool, scope, &inputs.profile.profile, &inputs.lane)?;
        let (run_id, _, _) = require_kube_launch_scope(tool, scope)?;
        let seat = &inputs.seat;
        let Some(cell) = self.runtime_cell.as_ref() else {
            return Err(HostToolError::Unavailable {
                tool,
                reason: "the kube surface is not configured".to_owned(),
            });
        };
        let Some(launch_binding) = cell.launch_binding() else {
            return Err(HostToolError::Unavailable {
                tool,
                reason: "the daemon cannot resolve the published budget binding for workload \
                         labels"
                    .to_owned(),
            });
        };
        let (control, bounds) = match self.resolve_control() {
            Ok(resolved) => resolved,
            Err(reason) => return Err(HostToolError::Unavailable { tool, reason }),
        };
        if let Some(settled) =
            create_replay_or_fresh(tool, &control, &run_id, &operation_id, target_node)?
        {
            return Ok(settled);
        }
        let attempt = resolve_create_attempt(
            tool,
            control
                .reconciler()
                .stored_launch(&run_id)
                .map_err(|error| kube_failure(tool, error))?
                .map(|stored| stored.labels.attempt_id),
            scope.attempt.clone(),
        )?;
        let staged_inputs = workload_input_artifacts(
            tool,
            &cell.artifact_store(),
            &cell.ledger(),
            artifacts,
            prompt,
            caller_scope,
            &run_id,
        )?;
        let request = LaunchRequest {
            tool,
            binding: &launch_binding,
            run_id: run_id.clone(),
            project_id: inputs.project.clone(),
            lane_id: inputs.lane.clone(),
            budget_lane: scope.lane.clone().filter(|lane| lane != &inputs.lane),
            seat_id: inputs.seat.clone(),
            attempt,
            operation_id: operation_id.clone(),
            initial_target_node: target_node.map(str::to_owned),
            label,
            continue_from,
        };
        let mut launch = super::launch::script_profile_launch(
            request,
            inputs,
            staged_inputs,
            bind_vpn_transport(
                tool,
                inputs.profile.profile.network.transport,
                cell.kube_config(),
            )?,
        )?;
        if let Some(reservation) = campaign_reservation {
            let cpu = launch
                .workload
                .as_ref()
                .and_then(|plan| plan.resources)
                .map(|resources| resources.cpu)
                .filter(|cpu| *cpu > 0)
                .ok_or_else(|| {
                    arguments_error(tool, "campaign launch requires a CPU reservation")
                })?;
            let seconds = launch
                .deadline_seconds
                .ok_or_else(|| arguments_error(tool, "campaign launch requires a deadline"))?;
            let budget = u64::from(cpu)
                .checked_mul(1000)
                .and_then(|value| value.checked_mul(u64::from(seconds)))
                .ok_or_else(|| arguments_error(tool, "campaign compute budget overflow"))?;
            let expires_at_unix_seconds = OffsetDateTime::now_utc()
                .unix_timestamp()
                .checked_add(i64::from(seconds))
                .ok_or_else(|| arguments_error(tool, "campaign deadline overflow"))?;
            launch.campaign_reservation = Some(odin_kube::CampaignReservation {
                approved_node: reservation.node.clone(),
                core_millis_seconds: budget,
                expires_at_unix_seconds,
            });
        }
        if let Some(digest) = &held.campaign_stage_sha256 {
            launch.args.push("--expected-stage-sha256".to_owned());
            launch.args.push(digest.clone());
        }
        tracing::info!(
            "script-pod create profile={} run={run_id} seat={seat} image={} gpus={} \
             placement={:?} service={}",
            inputs.profile.id,
            launch.image,
            launch.gpu_count,
            launch.node_selector,
            launch.service
        );
        if inputs.profile.profile.offload.is_some() {
            return self
                .create_offload(tool, &control, &launch, inputs, held, &operation_id)
                .await;
        }
        if let Some(queued) = self
            .hold_when_full(tool, &control, &mut launch, held, &run_id)
            .await?
        {
            return Ok(queued);
        }
        let deadline = checked_deadline(tool, create_deadline(bounds), timeout_seconds)?;
        let staged = control.create(launch, OffsetDateTime::now_utc());
        let observation = match tokio::time::timeout(deadline, staged).await {
            Ok(result) => result.map_err(|error| protocol_failure(tool, error))?,
            Err(_elapsed) => {
                return Err(HostToolError::Uncertain {
                    tool,
                    detail: "the script pod create exceeded its declared actuation bound; the \
                             settlement state is unproven"
                        .to_owned(),
                });
            }
        };
        let settlement = mutation_settlement(
            MutationStatus::Accepted,
            run_id.as_str(),
            operation_id.as_str(),
            &observation,
        );
        serialize_output(tool, &settlement)
    }

    /// Passes the admitted opaque resource version unchanged to compare-and-swap.
    /// A stale version is final for this permit; rereading would invalidate approval.
    /// Unlike phone commands, this surface allows restarting Running workloads.
    /// Cancellation remains routed through the reconciler's StopAuthority.
    pub(super) async fn mutate(
        &self,
        tool: &'static str,
        verb: &'static str,
        timeout_seconds: u32,
        operation_id: OperationId,
        invocation: HostInvocation,
    ) -> Result<Value, HostToolError> {
        require_kube_seat_scope(tool, &invocation.scope)?;
        let super::admission::MutationInput {
            run_id,
            expected_resource_version,
            target_node,
            checkpoint,
        } = super::admission::resolve_mutation_input(tool, invocation.arguments)?;
        if target_node.is_some() && verb != "restart" {
            return Err(super::admission::arguments_error(
                tool,
                "targetNode rehomes a restart; no other verb takes it",
            ));
        }
        if checkpoint && verb != "pause" {
            return Err(super::admission::arguments_error(
                tool,
                "checkpoint is taken of a paused pod; only pause takes it",
            ));
        }
        if let Some(run) = self
            .offload
            .as_ref()
            .and_then(|offload| offload.run(&run_id))
        {
            return self
                .mutate_offload(tool, verb, &run_id, &operation_id, run)
                .await;
        }
        let (control, bounds) = match self.resolve_control() {
            Ok(resolved) => resolved,
            Err(reason) => return Err(HostToolError::Unavailable { tool, reason }),
        };
        if let Some(settled) = replay_or_fresh(tool, &control, &run_id, &operation_id)? {
            return Ok(settled);
        }
        let (kind, idempotency_digest) = mutation_operation(
            tool,
            verb,
            &run_id,
            &expected_resource_version,
            target_node.as_deref(),
        )?;
        // The configured-bounds actuation window is checked BEFORE the
        // operation is dispatched to the reconciler: an unsupported
        // configuration is a typed pre-effect refusal, never a dispatch
        // that the outer declaration would clip mid-flight.
        // A rehome may carry node-bound state: two helper pods and the
        // volume's bytes ride inside the same declared window.
        let window = mutation_deadline(bounds)
            + if target_node.is_some() || checkpoint {
                REHOME_CARRY_WINDOW
            } else {
                Duration::ZERO
            };
        let deadline = checked_deadline(tool, window, timeout_seconds)?;
        let operate = control.operate(
            JobAction {
                run_id: run_id.clone(),
                kind,
                expected_resource_version,
                operation_id: operation_id.clone(),
                idempotency_digest,
                target_node,
            },
            OffsetDateTime::now_utc(),
        );
        match tokio::time::timeout(deadline, operate).await {
            Ok(Ok(updated)) => {
                let mut settlement = mutation_settlement(
                    MutationStatus::Accepted,
                    run_id.as_str(),
                    operation_id.as_str(),
                    &updated,
                );
                if checkpoint {
                    // The pause settled (no pod writes the volume): the
                    // checkpoint is consistent. A failed capture is an
                    // honest error — the pod stays paused either way.
                    let taken = control
                        .reconciler()
                        .checkpoint_state(&run_id)
                        .await
                        .map_err(|error| HostToolError::Uncertain {
                            tool,
                            detail: format!(
                                "the pod is paused, but its checkpoint failed: {error}"
                            ),
                        })?;
                    settlement = settlement
                        .with_checkpoint(taken.artifact_id.to_string(), taken.size_bytes);
                }
                serialize_output(tool, &settlement)
            }
            Ok(Err(HuginnProtocolError::Unavailable { code, detail })) => {
                // Post-dispatch unavailability is not provably pre-effect:
                // staging, stop intent, or API calls may already have acted,
                // so the settlement state is durable uncertainty, never a
                // clean no-effect rejection.
                Err(HostToolError::Uncertain {
                    tool,
                    detail: format!(
                        "the reconciler reported {code} ({detail}) after dispatch; the settlement state is unproven"
                    ),
                })
            }
            Ok(Err(error)) => Err(protocol_failure(tool, error)),
            Err(_elapsed) => Err(HostToolError::Uncertain {
                tool,
                detail: format!(
                    "the {verb} exceeded its declared actuation bound; the settlement state is unproven"
                ),
            }),
        }
    }

    /// `kube.workload.summarize`: pure lifecycle truth for one run or every
    /// Odin-owned finite Job in the configured namespace. Never mutates.
    pub(super) async fn summarize(
        &self,
        tool: &'static str,
        invocation: HostInvocation,
    ) -> Result<Value, HostToolError> {
        let seat = require_kube_seat_scope(tool, &invocation.scope)?;
        let project = invocation.scope.project.clone();
        let input: OptionalRunInput = decode_arguments(tool, invocation.arguments)?;
        let log_lines = input.checked_log_lines(tool)?;
        let control = match self.resolve_control() {
            Ok((control, _)) => control,
            Err(reason) => return Ok(summarize_unavailable(reason)),
        };
        // A seat sees the pods it launched and the pods of the project it is
        // bound to (a builder asks about its project's simulation).
        let overseer = self.overseers.contains(&seat);
        let visible = |observation: &JobObservation| {
            let labels = &observation.projection.labels;
            overseer || labels.seat_id == seat || project.as_ref() == Some(&labels.project_id)
        };
        // An offload run has no Job; the offload journal holds its row.
        let offload_runs: Vec<crate::live::offload::OffloadRun> = self
            .offload
            .as_ref()
            .map(|offload| offload.runs())
            .unwrap_or_default()
            .into_iter()
            .filter(|run| {
                overseer
                    || run.seat_id.as_ref() == Some(&seat)
                    || (project.is_some() && run.project_id == project)
            })
            .collect();
        let listing = input.run_id.is_none();
        let observations = match input.run_id {
            Some(raw) => {
                let run_id = RunId::new(raw)
                    .map_err(|error| arguments_error(tool, format!("invalid runId: {error}")))?;
                if let Some(run) = offload_runs.iter().find(|run| run.run_id == run_id) {
                    return serialize_output(
                        tool,
                        &SummarizeOutput {
                            status: ReadStatus::Ok,
                            runs: Some(vec![offload_summarize_row(run)]),
                            reason: None,
                        },
                    );
                }
                match control.summarize(&run_id).await {
                    // An unknown run id is said so, with the way to the
                    // list: a bare empty list read as "the pod is gone".
                    Ok(None) => {
                        return serialize_output(
                            tool,
                            &SummarizeOutput {
                                status: ReadStatus::Ok,
                                runs: Some(Vec::new()),
                                reason: Some(format!(
                                    "no workload has run id {:?}; call without runId to list \
                                     every run you can see",
                                    run_id.as_str()
                                )),
                            },
                        );
                    }
                    Ok(Some(observation)) => vec![observation],
                    Err(HuginnProtocolError::Unavailable { code, detail }) => {
                        return serialize_output(
                            tool,
                            &SummarizeOutput {
                                status: ReadStatus::Unavailable,
                                runs: None,
                                reason: Some(format!("{code}: {detail}")),
                            },
                        );
                    }
                    Err(error) => return Err(protocol_failure(tool, error)),
                }
            }
            None => control
                .reconciler()
                .list()
                .await
                .map_err(|error| kube_failure(tool, error))?,
        };
        let client = match self.runtime_cell.as_ref() {
            Some(cell) => cell.parts().await.ok().map(|(_, client)| client),
            None => None,
        };
        // A Job names no node; its pod does, running or finished: one pod
        // list places every row.
        let nodes = match &client {
            Some(client) => Some(
                odin_kube::status::job_nodes(client)
                    .await
                    .map_err(|error| format!("unreadable: {error}")),
            ),
            None => None,
        };
        let mut runs = Vec::new();
        for observation in observations
            .iter()
            .filter(|observation| visible(observation))
        {
            let mut row = summarize_row(tool, observation)?;
            let job = &observation.workload.resource.name;
            if let (Some(client), KubeWorkloadState::Running) =
                (&client, observation.workload.state)
            {
                row.status = pod_status(client, job).await;
            }
            if let (Some(client), Some(lines)) = (&client, log_lines) {
                row.log = Some(pod_log(client, job, lines).await);
            }
            if row.node.is_none() {
                row.node = match &nodes {
                    Some(Ok(nodes)) => nodes.get(job).map(ToString::to_string),
                    Some(Err(unreadable)) => Some(unreadable.clone()),
                    None => None,
                };
            }
            runs.push(row);
        }
        if listing {
            runs.extend(offload_runs.iter().map(offload_summarize_row));
        }
        runs.sort_by(|left, right| right.started_at.cmp(&left.started_at));
        serialize_output(
            tool,
            &SummarizeOutput {
                status: ReadStatus::Ok,
                runs: Some(runs),
                reason: None,
            },
        )
    }

    /// `kube.snapshot.read`: pure read of the scope-bound run's live
    /// `odin.kube.job-projection.v1` wire projection, or `null` when the run
    /// has no cluster workload yet. Never mutates.
    pub(super) async fn snapshot_read(
        &self,
        tool: &'static str,
        invocation: HostInvocation,
    ) -> Result<Value, HostToolError> {
        require_kube_seat_scope(tool, &invocation.scope)?;
        let run_id = invocation.scope.run.clone().ok_or(HostToolError::Scope {
            tool,
            reason: "snapshot reads address the invocation's bound run",
        })?;
        let _: NoInput = decode_arguments(tool, invocation.arguments)?;
        let control = match self.resolve_control() {
            Ok((control, _)) => control,
            Err(reason) => return Ok(snapshot_unavailable(reason)),
        };
        let projection = match control.summarize(&run_id).await {
            Ok(None) => Value::Null,
            Ok(Some(observation)) => serialize_value(
                tool,
                &observation.projection,
                "cannot serialize the job projection",
            )?,
            Err(HuginnProtocolError::Unavailable { code, detail }) => {
                return serialize_output(
                    tool,
                    &SnapshotOutput {
                        status: ReadStatus::Unavailable,
                        projection: None,
                        lanes: None,
                        reason: Some(format!("{code}: {detail}")),
                    },
                );
            }
            Err(error) => return Err(protocol_failure(tool, error)),
        };
        let cell = self
            .runtime_cell
            .as_ref()
            .expect("resolved control has a runtime cell");
        let lanes = match cell.huginn_root() {
            Some(root) => match super::budget_rows(
                &cell.snapshot(),
                root,
                u64::try_from(OffsetDateTime::now_utc().unix_timestamp_nanos() / 1_000_000)
                    .unwrap_or(0),
            ) {
                Ok(rows) => rows,
                Err(reason) => {
                    return Ok(snapshot_unavailable(format!("compute budget: {reason}")))
                }
            },
            None => {
                return Ok(snapshot_unavailable(
                    "compute budget state root unavailable".to_owned(),
                ))
            }
        };
        serialize_output(
            tool,
            &SnapshotOutput {
                status: ReadStatus::Ok,
                projection: Some(projection),
                lanes: Some(lanes),
                reason: None,
            },
        )
    }

    /// `kube.health.read`: one bounded, read-only live cluster health
    /// observation — node readiness and pressure, pods with observed
    /// problems, and recent warning events — exactly as the API server
    /// returned them. An unreachable cluster or an incomplete scan is the
    /// schema's `unavailable` settlement with the typed reason, never a
    /// synthesized healthy-looking report. Never mutates.
    pub(super) async fn health_read(
        &self,
        tool: &'static str,
        invocation: HostInvocation,
    ) -> Result<Value, HostToolError> {
        require_kube_seat_scope(tool, &invocation.scope)?;
        let _: NoInput = decode_arguments(tool, invocation.arguments)?;
        let control = match self.resolve_control() {
            Ok((control, _)) => control,
            Err(reason) => return Ok(health_unavailable(reason)),
        };
        let health = match control.cluster_health().await {
            Ok(health) => health,
            Err(KubeError::Unavailable { reason }) => {
                return serialize_output(
                    tool,
                    &HealthOutput {
                        status: ReadStatus::Unavailable,
                        health: None,
                        reason: Some(reason),
                    },
                );
            }
            Err(error) => return Err(kube_failure(tool, error)),
        };
        serialize_output(
            tool,
            &HealthOutput {
                status: ReadStatus::Ok,
                health: Some(health),
                reason: None,
            },
        )
    }
}

/// The existing 250ms attach-poll/watch-backoff precedent as a local
/// pacing constant — never a configuration knob.
const CARRIER_READINESS_POLL: Duration = Duration::from_millis(250);

#[derive(Clone, Debug, Eq, PartialEq)]
struct CarrierProbe {
    /// The observed workload state (Job conditions first, then activeness
    /// counts): used ONLY for terminal detection — its `Running` is the
    /// Job's active count and may count Pending pods.
    workload: Option<KubeWorkloadState>,
    /// Attach readiness requires this pod's actual Running phase.
    pod: Option<WorkloadPlacement>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum CarrierReadiness {
    Ready(Box<WorkloadPlacement>),
    /// The carrier reached a terminal phase; an attach cannot succeed.
    Terminal {
        phase: String,
    },
    /// A hard typed placement refusal (ambiguous binding, stale claim, a
    /// storage verdict): polling further cannot help.
    Refused {
        reason: String,
    },
    /// The deadline leaves no time for attach.
    Expired,
}

/// Bounded read-only carrier readiness: polls the owned placement until
/// the carrier pod is actually Running, a terminal phase, a hard typed
/// refusal, or the readiness end (`end - exec_reserve` — the whole request
/// window stays reserved for the single attach, so expiry means NO
/// attach). Reads clamp to that end; only genuinely transient faults poll.
async fn await_carrier_ready<R, RF>(
    mut read: R,
    end: tokio::time::Instant,
    exec_reserve: Duration,
) -> CarrierReadiness
where
    R: FnMut() -> RF,
    RF: Future<Output = Result<CarrierProbe, KubeError>>,
{
    let read_end = end - exec_reserve;
    loop {
        if tokio::time::Instant::now() >= read_end {
            return CarrierReadiness::Expired;
        }
        match tokio::time::timeout_at(read_end, read()).await {
            Err(_elapsed) => return CarrierReadiness::Expired,
            Ok(Err(error)) => {
                if hard_refusal(&error) {
                    return CarrierReadiness::Refused {
                        reason: error.to_string(),
                    };
                }
            }
            Ok(Ok(probe)) => {
                // Terminal Job conditions beat everything: a Failed or
                // Succeeded carrier can never attach, exec or not.
                match probe.workload {
                    Some(KubeWorkloadState::Failed) => {
                        return CarrierReadiness::Terminal {
                            phase: "Failed".to_owned(),
                        };
                    }
                    Some(KubeWorkloadState::Succeeded) => {
                        return CarrierReadiness::Terminal {
                            phase: "Succeeded".to_owned(),
                        };
                    }
                    _ => {}
                }
                // Job active counts include Pending pods; require the pod's actual phase.
                if let Some(pod) = probe
                    .pod
                    .filter(|found| found.phase.as_deref() == Some("Running"))
                {
                    return CarrierReadiness::Ready(Box::new(pod));
                }
            }
        }
        if tokio::time::Instant::now() + CARRIER_READINESS_POLL >= read_end {
            return CarrierReadiness::Expired;
        }
        tokio::time::sleep(CARRIER_READINESS_POLL).await;
    }
}

/// Typed transport truth on status codes and variants, never strings: the
/// reconciler's Conflict/Rejected/Storage verdicts and Api statuses naming
/// invalid-request/authentication/authorization are hard refusals; server
/// and transport faults are transient within the shared bound.
fn hard_refusal(error: &KubeError) -> bool {
    match error {
        KubeError::Conflict { .. } | KubeError::Rejected { .. } | KubeError::Storage { .. } => true,
        KubeError::Api(kube::Error::Api(status)) => {
            matches!(status.code, 400 | 401 | 403 | 422)
        }
        _ => false,
    }
}

fn persist_refused_attach(
    result: Result<(), WorkloadSessionOpenError>,
    persist: impl FnOnce() -> Result<(), KubeError>,
) -> Result<(), WorkloadSessionOpenError> {
    if result
        .as_ref()
        .is_err_and(|error| error.refused_before_open)
    {
        // No await between proof and persistence: cancellation cannot lose
        // the intent once the refusal has been observed.
        if let Err(error) = persist() {
            return Err(WorkloadSessionOpenError {
                code: "workload_release_journal".to_owned(),
                detail: format!("{result:?}; failed to persist carrier release: {error}"),
                refused_before_open: true,
            });
        }
    }
    result
}

async fn settle_applied_create<R, RF, A, AF>(
    tool: &'static str,
    settlement: &MutationOutput,
    read: R,
    attach: A,
    connected: impl FnOnce(&WorkloadPlacement),
    end: tokio::time::Instant,
    exec_reserve: Duration,
) -> Result<Value, HostToolError>
where
    R: FnMut() -> RF,
    RF: Future<Output = Result<CarrierProbe, KubeError>>,
    A: FnOnce() -> AF,
    AF: Future<Output = Result<(), WorkloadSessionOpenError>>,
{
    let failure = |cause: String| HostToolError::Uncertain {
        tool,
        detail: format!("workload run {} was created; {cause}", settlement.run_id),
    };
    let readiness = await_carrier_ready(read, end, exec_reserve).await;
    let refusal = match &readiness {
        CarrierReadiness::Ready(_) if tokio::time::Instant::now() + exec_reserve > end => Some(
            "the reserved agent attach window is gone; the attach was not attempted".to_owned(),
        ),
        CarrierReadiness::Terminal { phase } => Some(format!(
            "the carrier pod reached terminal phase {phase} before the agent attach; the \
             attach was not attempted"
        )),
        CarrierReadiness::Refused { reason } => Some(format!(
            "the carrier readiness read refused typed: {reason}; the attach was not \
             attempted"
        )),
        CarrierReadiness::Expired => Some(
            "the carrier pod did not reach Running within the create timeout; the \
             agent attach was not attempted"
                .to_owned(),
        ),
        CarrierReadiness::Ready(_) => None,
    };
    if let Some(cause) = refusal {
        return Err(failure(cause));
    }
    match tokio::time::timeout_at(end, attach()).await {
        Ok(Ok(())) => {
            if let CarrierReadiness::Ready(pod) = &readiness {
                connected(pod);
            }
            serialize_output(tool, settlement)
        }
        Ok(Err(error)) => Err(failure(format!("attach workload session failed: {error}"))),
        Err(error) => Err(failure(format!(
            "attach workload session timed out: {error}"
        ))),
    }
}

#[cfg(test)]
#[path = "tests/create_attach.rs"]
mod create_attach;

#[cfg(test)]
#[path = "tests/job_verbs.rs"]
mod job_verbs;

#[cfg(test)]
#[path = "tests/workload_inputs.rs"]
mod workload_inputs;

/// Whether a launched pod run is still live or finished.
fn pod_run_use(lifecycle: odin_domain::huginn::KubeJobLifecycle) -> PodRunUse {
    use odin_domain::huginn::KubeJobLifecycle as L;
    match lifecycle {
        L::Pending | L::Staging | L::Running | L::Paused => PodRunUse::Live,
        L::Succeeded | L::Failed | L::Cancelling | L::Retired => PodRunUse::Finished,
    }
}

/// Resolves each named artifact to its ledger identity, in order. Staging
/// itself later proves a ledger reference binds it to this Job's seat,
/// project, lane or run before any byte moves.
pub(super) fn resolve_input_artifacts(
    tool: &'static str,
    ledger: &Arc<Mutex<Ledger>>,
    artifacts: &[String],
) -> Result<Vec<odin_domain::huginn::KubeContentIdentity>, HostToolError> {
    let ledger = ledger
        .lock()
        .map_err(|error| arguments_error(tool, format!("the artifact ledger: {error}")))?;
    let mut staged = Vec::with_capacity(artifacts.len());
    for artifact in artifacts {
        let id = odin_domain::ArtifactId::new(artifact.as_str()).map_err(|error| {
            arguments_error(tool, format!("{artifact:?} is not an artifact id: {error}"))
        })?;
        let metadata = ledger
            .artifact(&id)
            .map_err(|error| arguments_error(tool, error.to_string()))?
            .ok_or_else(|| arguments_error(tool, format!("no artifact {artifact}")))?;
        staged.push(odin_domain::huginn::KubeContentIdentity {
            artifact_id: metadata.artifact_id,
            content_digest: metadata.digest,
            byte_len: metadata.size_bytes,
        });
    }
    Ok(staged)
}

/// Validate explicit inputs without attaching them to a child run.
pub(super) fn validate_input_artifacts(
    tool: &'static str,
    ledger: &Arc<Mutex<Ledger>>,
    artifacts: &[String],
    caller: &odin_domain::Scope,
) -> Result<Vec<odin_domain::huginn::KubeContentIdentity>, HostToolError> {
    let declared = resolve_input_artifacts(tool, ledger, artifacts)?;
    let ledger = ledger
        .lock()
        .map_err(|error| arguments_error(tool, format!("the artifact ledger: {error}")))?;
    for identity in &declared {
        let references = ledger
            .artifact_references(&identity.artifact_id)
            .map_err(|error| arguments_error(tool, error.to_string()))?;
        if !references.iter().any(|reference| {
            let expected = match reference.object_kind.as_str() {
                "run" => caller.run.as_ref().map(|id| id.as_str()),
                "attempt" => caller.attempt.as_ref().map(|id| id.as_str()),
                "seat" => caller.seat.as_ref().map(|id| id.as_str()),
                "project" => caller.project.as_ref().map(|id| id.as_str()),
                "lane" => caller.lane.as_ref().map(|id| id.as_str()),
                _ => None,
            };
            expected == Some(reference.object_id.as_str())
        }) {
            return Err(HostToolError::Scope {
                tool,
                reason: "a workload input is not readable by the launching scope",
            });
        }
    }
    Ok(declared)
}

/// Prove the caller can read explicit inputs before sharing them with the child run.
/// Prompt sugar uses the same run-scoped registration and staging transport.
fn workload_input_artifacts(
    tool: &'static str,
    store: &odin_kube::artifacts::ArtifactStore,
    ledger: &Arc<Mutex<Ledger>>,
    artifacts: &[String],
    prompt: Option<&str>,
    caller: &odin_domain::Scope,
    run: &RunId,
) -> Result<Vec<odin_domain::huginn::KubeContentIdentity>, HostToolError> {
    if prompt.is_some_and(|text| text.trim().is_empty()) {
        return Err(arguments_error(tool, "prompt must not be empty"));
    }
    let mut declared = validate_input_artifacts(tool, ledger, artifacts, caller)?;
    {
        let mut ledger = ledger
            .lock()
            .map_err(|error| arguments_error(tool, format!("the artifact ledger: {error}")))?;
        for identity in &declared {
            let metadata = ledger
                .artifact(&identity.artifact_id)
                .map_err(|error| arguments_error(tool, error.to_string()))?
                .ok_or_else(|| arguments_error(tool, "the workload input disappeared"))?;
            ledger
                .attach_artifact_reference(
                    &identity.artifact_id,
                    metadata.revision,
                    odin_ledger::artifact::NewArtifactReference {
                        object_kind: "run",
                        object_id: run.as_str(),
                        relation: "kube-content",
                        created_at: OffsetDateTime::now_utc(),
                    },
                )
                .map_err(|error| arguments_error(tool, error.to_string()))?;
        }
    }
    if let Some(prompt) = prompt {
        let digest = odin_domain::Digest::hash(prompt.as_bytes());
        let hex = digest.hex();
        let metadata = super::scoped_registration::register_scoped_bytes(
            tool,
            store,
            ledger,
            prompt.as_bytes(),
            &format!("{}/{}", &hex[..2], hex),
            run,
        )?;
        declared.push(odin_domain::huginn::KubeContentIdentity {
            artifact_id: metadata.artifact_id,
            content_digest: metadata.digest,
            byte_len: metadata.size_bytes,
        });
    }
    Ok(declared)
}

/// The staging slots an agent pod's own launch material occupies ahead of
/// its declared inputs: `input-0` the extension policy, `input-1` the
/// models document (see `launch::workload_profile_launch`).
pub(super) const AGENT_POD_RESERVED_INPUTS: usize = 2;

/// The exact read-only in-pod path of each declared agent-pod input, in
/// staging order after the reserved launch material. The launch prompt, when
/// present, is the last declared input (see `workload_input_artifacts`).
pub(super) fn agent_input_bindings(
    declared: &[odin_domain::huginn::KubeContentIdentity],
    prompt: bool,
) -> Vec<odin_domain::huginn::WorkloadInputBinding> {
    let last = declared.len().saturating_sub(1);
    declared
        .iter()
        .enumerate()
        .map(|(index, input)| odin_domain::huginn::WorkloadInputBinding {
            artifact_id: input.artifact_id.to_string(),
            path: format!(
                "{}/input-{}",
                odin_kube::job::KUBE_STAGING_MOUNT_PATH,
                index + AGENT_POD_RESERVED_INPUTS
            ),
            prompt: prompt && index == last,
        })
        .collect()
}
