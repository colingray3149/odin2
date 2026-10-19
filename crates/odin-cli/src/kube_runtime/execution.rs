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

use super::{WorkloadLaunchInputs, WorkloadLaunchPort, WorkloadResolve, WorkloadSessionOpenError};

use super::admission::{
    agent_pod_launch_admissible, arguments_error, checked_deadline, create_deadline,
    create_replay_or_fresh, decode_arguments, kube_failure, mutation_deadline, pod_launch_scope,
    pod_run_generation, protocol_failure, replay_or_fresh, require_kube_launch_scope,
    require_kube_seat_scope, resolve_create_attempt, NoInput, OptionalRunInput, PodRunUse,
    ProfileInput,
};
use super::evidence::{
    health_unavailable, mutation_settlement, serialize_output, serialize_value,
    snapshot_unavailable, summarize_row, summarize_unavailable, HealthOutput, MutationOutput,
    MutationStatus, ReadStatus, SnapshotOutput, SummarizeOutput, AGENT_POD_REPORT,
};
use super::launch::{container_identity, mutation_operation, profile_launch};
use super::KubeCommandCoordinator;

/// The extra actuation window a rehome that carries node-bound state may
/// take: two helper pods (each bounded to start in 120 s) and the copy.
const REHOME_CARRY_WINDOW: Duration = Duration::from_secs(320);

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
        let HostInvocation { scope, arguments } = invocation;
        let seat = require_kube_seat_scope(tool, &scope)?;
        let input: ProfileInput = decode_arguments(tool, arguments)?;
        // Each launched profile owns its own run under the session's run, so
        // one session can launch several pods — and a profile launched again
        // after its earlier run finished gets a fresh run.
        let scope = self
            .pod_create_scope(tool, &scope, &input.profile, &operation_id)
            .await?;
        let (run_id, project_id, lane_id) = require_kube_launch_scope(tool, &scope)?;
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
                WorkloadResolve::Launch(inputs) => {
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
                        .create_workload(
                            port,
                            inputs,
                            &input.inputs,
                            input.target_node.as_deref(),
                            tool,
                            timeout_seconds,
                            operation_id,
                            &scope,
                        )
                        .await;
                }
                WorkloadResolve::Script(inputs) => {
                    self.require_create_target(tool, input.target_node.as_deref(), None)?;
                    return self
                        .create_script(
                            &inputs,
                            &input.inputs,
                            input.target_node.as_deref(),
                            tool,
                            timeout_seconds,
                            operation_id,
                            &scope,
                        )
                        .await;
                }
            }
        }
        if !input.inputs.is_empty() {
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
        let identity = container_identity(tool, container)?;
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
        let launch = profile_launch(
            tool,
            container,
            identity,
            &launch_binding,
            run_id.clone(),
            project_id,
            lane_id,
            seat.clone(),
            attempt,
            operation_id.clone(),
            input.target_node,
        )?;
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
            tool,
            MutationStatus::Accepted,
            run_id.as_str(),
            operation_id.as_str(),
            &observation,
        )?;
        serialize_output(tool, &settlement)
    }

    /// The pod run one create binds: the run an already-admitted operation
    /// launched (a retried permit replays, never relaunches), else the
    /// first generation of `<session run>:pod:<profile>` that is unused or
    /// still live ([`pod_run_generation`]).
    async fn pod_create_scope(
        &self,
        tool: &'static str,
        scope: &odin_domain::Scope,
        profile: &str,
        operation_id: &OperationId,
    ) -> Result<odin_domain::Scope, HostToolError> {
        // Without a reachable cluster the create refuses further on; the
        // first generation keeps that refusal unchanged.
        let Ok((control, _)) = self.resolve_control() else {
            return pod_launch_scope(tool, scope, profile, 1);
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
            let candidate = pod_launch_scope(tool, scope, profile, generation)?;
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
                "pod run generation profile={profile} generation={generation} \
                 reason=\"the session's earlier run of this profile finished\""
            );
        }
        pod_launch_scope(tool, scope, profile, generation)
    }

    /// The script pod create path: the declared command
    /// in the declared image under the SAME control surface, journal, and
    /// settlement as every workload mutation; no session opens.
    #[allow(clippy::too_many_arguments)]
    async fn create_script(
        &self,
        inputs: &crate::kube_runtime::ScriptLaunchInputs,
        artifacts: &[String],
        target_node: Option<&str>,
        tool: &'static str,
        timeout_seconds: u32,
        operation_id: OperationId,
        scope: &odin_domain::Scope,
    ) -> Result<Value, HostToolError> {
        let seat = require_kube_seat_scope(tool, scope)?;
        let (run_id, project_id, lane_id) = require_kube_launch_scope(tool, scope)?;
        if inputs.seat != seat || inputs.project != project_id || inputs.lane != lane_id {
            return Err(HostToolError::Scope {
                tool,
                reason: "the workload profile binding disagrees with the invocation scope",
            });
        }
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
        let staged_inputs = resolve_input_artifacts(tool, &cell.ledger(), artifacts)?;
        let launch = super::launch::script_profile_launch(
            tool,
            inputs,
            staged_inputs,
            &launch_binding,
            run_id.clone(),
            attempt,
            operation_id.clone(),
            target_node.map(str::to_owned),
        )?;
        tracing::info!(
            "script-pod create profile={} run={run_id} seat={seat} image={} gpus={} \
             placement={:?} service={}",
            inputs.profile.id,
            launch.image,
            launch.gpu_count,
            launch.node_selector,
            launch.service
        );
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
            tool,
            MutationStatus::Accepted,
            run_id.as_str(),
            operation_id.as_str(),
            &observation,
        )?;
        serialize_output(tool, &settlement)
    }

    /// Creates the declared workload and opens its Huginn session, using the
    /// permit's operation ID as the durable settlement key.
    // The admitted profile, its named inputs and the dispatch identity are
    // independent facts; bundling them would only hide the call shape.
    #[allow(clippy::too_many_arguments)]
    async fn create_workload(
        &self,
        port: Arc<dyn WorkloadLaunchPort>,
        mut inputs: Box<WorkloadLaunchInputs>,
        artifacts: &[String],
        target_node: Option<&str>,
        tool: &'static str,
        timeout_seconds: u32,
        operation_id: OperationId,
        scope: &odin_domain::Scope,
    ) -> Result<Value, HostToolError> {
        use odin_kube::workload::WorkloadPodPlan;

        let seat = require_kube_seat_scope(tool, scope)?;
        let (run_id, project_id, lane_id) = require_kube_launch_scope(tool, scope)?;
        // The admitted inputs must agree with the invocation's bound scope:
        // the profile's seat binding names this seat, project, and lane — a
        // mismatch is a typed refusal, never a silent rebind.
        if inputs.seat != seat || inputs.project != project_id || inputs.lane != lane_id {
            return Err(HostToolError::Scope {
                tool,
                reason: "the workload profile binding disagrees with the invocation scope",
            });
        }
        let Some(cell) = self.runtime_cell.as_ref() else {
            return Err(HostToolError::Unavailable {
                tool,
                reason: "the kube surface is not configured".to_owned(),
            });
        };
        let Some(launch_binding) = cell.launch_binding() else {
            return Err(HostToolError::Unavailable {
                tool,
                reason:
                    "the daemon cannot resolve the published budget binding for workload labels"
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
        let profile = &inputs.profile.profile;
        let agent = profile.agent().ok_or_else(|| {
            arguments_error(
                tool,
                format!(
                    "workload {} runs no agent harness; only an agent pod opens a session",
                    inputs.profile.id
                ),
            )
        })?;
        // Reserve exactly the storage quantity validated at publication.
        let state_storage = profile.state.storage.clone();
        let ledger = cell.ledger();
        // Each named artifact is proven in the ledger and staged after
        // the launch's own policy and models inputs; the session binding
        // records exactly where each lands so the brief can name it.
        let declared_inputs = resolve_input_artifacts(tool, &ledger, artifacts)?;
        inputs.staged_inputs = agent_input_bindings(&declared_inputs);
        if !inputs.staged_inputs.is_empty() {
            tracing::info!(
                "agent-pod inputs profile={} run={run_id} staged={}",
                inputs.profile.id,
                inputs
                    .staged_inputs
                    .iter()
                    .map(|input| format!("{}@{}", input.artifact_id, input.path))
                    .collect::<Vec<_>>()
                    .join(",")
            );
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
        // The extension binding composes from the pinned image identity
        // BEFORE the launch exists: identity re-read and manifest-pin
        // cross-check are typed refusals, the policy registers as
        // content-addressed admission material, and the launch's staging
        // projection carries the policy bytes into the read-only pod mount.
        let material = super::extension::compose_extension_launch(
            tool,
            &cell.artifact_store(),
            &ledger,
            &cell.workload_identity().artifact,
            cell.config_revision(),
            &super::extension::ProfileBinding {
                image_reference: &profile.image.reference,
                launcher: &agent.runtime.launcher,
                supervisor: &agent.runtime.supervisor,
                browser: &agent.runtime.browser,
                playwright: &agent.runtime.playwright,
                xvfb: &agent.display.xvfb,
            },
            inputs.snapshot_revision,
            &run_id,
        )?;
        let plan = WorkloadPodPlan {
            profile: inputs.profile.id.clone(),
            state_mount: profile.state.path.clone(),
            export_mount: profile.export.pod_path.clone(),
            export_host_folder: profile.export.host_folder.clone(),
            state_storage,
            state_storage_class: None,
            allow_hosts: profile.network.allow_hosts.clone(),
            agent: Some(odin_kube::workload::WorkloadAgentPlan {
                launcher: agent.runtime.launcher.clone(),
                // The ONE declared gateway target of the explicitly selected
                // target node, resolved at admission from that node's declared
                // gateway endpoint (a missing, invalid, or unreachable endpoint
                // refused the launch already). The egress pin carries the
                // endpoint's own effective TCP port — a declared nonstandard
                // port is enforced as declared — while the model config carries
                // the same endpoint's full URI as `baseUrl`.
                gateway: odin_kube::workload::WorkloadGatewayTarget {
                    host: inputs.gateway.host().to_owned(),
                    port: inputs.gateway.port(),
                },
                browser: agent.runtime.browser.clone(),
                supervisor: agent.runtime.supervisor.clone(),
                playwright: agent.runtime.playwright.clone(),
                display: odin_kube::workload::WorkloadDisplayPlan {
                    xvfb: agent.display.xvfb.clone(),
                    screen: agent.display.screen.clone(),
                    stream: agent.display.stream,
                },
                // The resolved in-image node binding of the SAME parsed identity
                // the extension composition just verified: complete at
                // construction, never a placeholder filled in later.
                browser_node: material.browser_node.clone(),
                browser_engine: profile.browser_engine(),
                home_dir: None,
                credential: inputs.credential.clone(),
            }),
        };

        // The per-session models document composes from the SAME declared
        // node endpoint the egress pin came from: baseUrl is that endpoint
        // URI verbatim, the apiKey is the SecretKeyRef env NAME (never
        // bytes), and the only model entry is the admitted one. The document
        // rides the staging projection beside the extension policy and is
        // digest-re-proven in-pod before any copy.
        let models_config = super::models_config::compose_models_config_launch(
            tool,
            &cell.artifact_store(),
            &ledger,
            inputs.provider.as_str(),
            inputs.model.as_str(),
            &inputs.gateway,
            &run_id,
        )?;
        let launch = super::launch::workload_profile_launch(
            tool,
            profile,
            plan,
            &launch_binding,
            run_id.clone(),
            project_id,
            lane_id,
            seat,
            attempt,
            operation_id.clone(),
            inputs.model.clone(),
            material.launch,
            material.staging_input,
            models_config.staging_input,
            declared_inputs,
            inputs.credential.clone(),
            target_node.map(str::to_owned),
        )?;
        // ONE absolute end anchored once before the create phase: the same
        // instant governs the create actuation, every readiness read, and
        // the at-most-one attach. No budget is ever reset or recomputed,
        // and at least one declared request window stays reserved for the
        // attach itself.
        let end = tokio::time::Instant::now()
            + checked_deadline(tool, create_deadline(bounds), timeout_seconds)?;
        let staged = control.create(launch, OffsetDateTime::now_utc());
        let observation = match tokio::time::timeout_at(end, staged).await {
            Ok(result) => result.map_err(|error| protocol_failure(tool, error))?,
            Err(_elapsed) => {
                return Err(HostToolError::Uncertain {
                    tool,
                    detail: "the workload create exceeded its declared actuation bound; the \
                             settlement state is unproven"
                        .to_owned(),
                });
            }
        };
        let settlement = mutation_settlement(
            tool,
            MutationStatus::Accepted,
            run_id.as_str(),
            operation_id.as_str(),
            &observation,
        )?
        .with_report(AGENT_POD_REPORT);
        // Job activity includes Pending pods, so wait for the carrier itself.
        let reconciler = control.reconciler();
        let readiness = || async {
            let workload = reconciler
                .observe_run(&run_id)
                .await?
                .map(|observed| observed.workload.state);
            let pod = reconciler.workload_placement(&run_id).await?;
            Ok(CarrierProbe { workload, pod })
        };
        settle_applied_create(
            tool,
            &settlement,
            readiness,
            || port.open_session(&inputs, &run_id, &operation_id),
            |pod| {
                let connected = time::OffsetDateTime::now_utc().unix_timestamp_nanos() / 1_000_000;
                tracing::debug!(
                    "pod phase run={run_id} pod={} node={} kind=agent {}",
                    pod.pod,
                    pod.node.as_deref().unwrap_or("-"),
                    pod.timeline.fields(Some((
                        "connected_ms",
                        i64::try_from(connected).unwrap_or(i64::MAX)
                    )))
                );
            },
            end,
            bounds.0,
        )
        .await
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
                    tool,
                    MutationStatus::Accepted,
                    run_id.as_str(),
                    operation_id.as_str(),
                    &updated,
                )?;
                if checkpoint {
                    // The pause settled (no pod writes the volume): the
                    // checkpoint is consistent. A failed capture is an
                    // honest error — the pod stays paused either way.
                    let taken = control
                        .reconciler()
                        .checkpoint_state(&run_id)
                        .await
                        .map_err(|error| HostToolError::Unavailable {
                            tool,
                            reason: format!(
                                "the pod is paused, but its checkpoint failed: {error}"
                            ),
                        })?;
                    settlement = settlement
                        .with_checkpoint(taken.artifact_id.to_string(), taken.size_bytes);
                }
                serialize_output(tool, &settlement)
            }
            Ok(Err(HuginnProtocolError::Unavailable { code })) => {
                // Post-dispatch unavailability is not provably pre-effect:
                // staging, stop intent, or API calls may already have acted,
                // so the settlement state is durable uncertainty, never a
                // clean no-effect rejection.
                Err(HostToolError::Uncertain {
                    tool,
                    detail: format!(
                        "the reconciler reported {code} after dispatch; the settlement state is unproven"
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
        let observations = match input.run_id {
            Some(raw) => {
                let run_id = RunId::new(raw)
                    .map_err(|error| arguments_error(tool, format!("invalid runId: {error}")))?;
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
                    Err(HuginnProtocolError::Unavailable { code }) => {
                        return serialize_output(
                            tool,
                            &SummarizeOutput {
                                status: ReadStatus::Unavailable,
                                runs: None,
                                reason: Some(code),
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
            if row.node.is_none() {
                row.node = match &nodes {
                    Some(Ok(nodes)) => nodes.get(job).map(ToString::to_string),
                    Some(Err(unreadable)) => Some(unreadable.clone()),
                    None => None,
                };
            }
            runs.push(row);
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
            Err(HuginnProtocolError::Unavailable { code }) => {
                return serialize_output(
                    tool,
                    &SnapshotOutput {
                        status: ReadStatus::Unavailable,
                        projection: None,
                        reason: Some(code),
                    },
                );
            }
            Err(error) => return Err(protocol_failure(tool, error)),
        };
        serialize_output(
            tool,
            &SnapshotOutput {
                status: ReadStatus::Ok,
                projection: Some(projection),
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

/// A running pod's status delta: its newest
/// `ODIN-STATUS` against the one before, from a bounded timestamped log tail
/// through the kube API. `None` when it reports no status or the read fails.
async fn pod_status(client: &odin_kube::KubeClient, job: &str) -> Option<String> {
    use kube::api::{ListParams, LogParams};
    let pods = client
        .pods()
        .list(&ListParams::default().labels(&format!("job-name={job}")))
        .await
        .ok()?;
    let pod = pods.items.iter().find(|pod| {
        pod.status
            .as_ref()
            .and_then(|status| status.phase.as_deref())
            == Some("Running")
    })?;
    let log = client
        .pods()
        .logs(
            pod.metadata.name.as_deref()?,
            &LogParams {
                tail_lines: Some(odin_kube::telemetry::STATUS_TAIL_LINES),
                timestamps: true,
                ..LogParams::default()
            },
        )
        .await
        .ok()?;
    odin_kube::telemetry::status_delta(&log, OffsetDateTime::now_utc())
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
        .map_err(|_| arguments_error(tool, "the artifact ledger is poisoned".to_owned()))?;
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

/// The staging slots an agent pod's own launch material occupies ahead of
/// its declared inputs: `input-0` the extension policy, `input-1` the
/// models document (see `launch::workload_profile_launch`).
pub(super) const AGENT_POD_RESERVED_INPUTS: usize = 2;

/// The exact read-only in-pod path of each declared agent-pod input, in
/// staging order after the reserved launch material.
pub(super) fn agent_input_bindings(
    declared: &[odin_domain::huginn::KubeContentIdentity],
) -> Vec<odin_domain::huginn::WorkloadInputBinding> {
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
        })
        .collect()
}
