use super::*;

impl KubeCommandCoordinator {
    /// Creates the declared workload and opens its Huginn session, using the
    /// permit's operation ID as the durable settlement key.
    pub(super) async fn create_workload(
        &self,
        create: WorkloadCreate<'_>,
    ) -> Result<Value, HostToolError> {
        let WorkloadCreate {
            held,
            port,
            mut inputs,
            artifacts,
            prompt,
            label,
            company,
            continue_from,
            caller_scope,
            target_node,
            tool,
            timeout_seconds,
            operation_id,
            scope,
        } = create;
        let company = match company.as_deref() {
            Some(company) => Some(odin_kube::company_directory(company).map_err(|reason| {
                arguments_error(
                    tool,
                    format!("company {company:?} is not a folder segment: {reason}"),
                )
            })?),
            None => None,
        };
        use odin_kube::workload::WorkloadPodPlan;

        require_workload_scope(tool, scope, &inputs.profile.profile, &inputs.lane)?;
        let (run_id, _, _) = require_kube_launch_scope(tool, scope)?;
        let seat = inputs.seat.clone();
        let project_id = inputs.project.clone();
        let lane_id = inputs.lane.clone();
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
        let declared_inputs = workload_input_artifacts(
            tool,
            &cell.artifact_store(),
            &ledger,
            artifacts,
            prompt,
            caller_scope,
            &run_id,
        )?;
        inputs.staged_inputs = agent_input_bindings(&declared_inputs, prompt.is_some());
        inputs.opening_prompt = prompt.map(str::to_owned);
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
        let material = super::super::extension::compose_extension_launch(
            super::super::extension::ExtensionLaunchRequest {
                tool,
                store: &cell.artifact_store(),
                ledger: &ledger,
                identity_artifact: &cell.workload_identity().artifact,
                config_revision: cell.config_revision(),
                profile: &super::super::extension::ProfileBinding {
                    image_reference: &profile.image.reference,
                    launcher: &agent.runtime.launcher,
                    supervisor: &agent.runtime.supervisor,
                    browser: &agent.runtime.browser,
                    playwright: &agent.runtime.playwright,
                    xvfb: &agent.display.xvfb,
                },
                snapshot_revision: inputs.snapshot_revision,
                run_id: &run_id,
            },
        )?;
        let plan = WorkloadPodPlan {
            resources: super::super::launch::profile_resources(tool, profile)?,
            termination_grace_seconds: profile.stop_grace_seconds,
            data: super::super::launch::profile_data(profile),
            control: profile.control.clone(),
            keep_finished_seconds: profile
                .lifetime
                .as_ref()
                .and_then(|lifetime| lifetime.keep_finished_seconds)
                .map(std::num::NonZeroU32::get),
            on_yield: profile.on_yield,
            script_gateway: None,
            profile: inputs.profile.id.clone(),
            state_mount: profile.state.path.clone(),
            export_mount: profile.export.pod_path.clone(),
            export_host_folder: profile.export.host_folder.clone(),
            state_storage,
            state_storage_class: None,
            state_carry: profile.state.carry != Some(false),
            allow_hosts: profile.network.allow_hosts.clone(),
            network_open: profile.network.open,
            transport: profile.network.transport,
            vpn: bind_vpn_transport(tool, profile.network.transport, cell.kube_config())?,
            report_pdf: profile.report_pdf(),
            report_downloads_root: profile
                .report
                .as_ref()
                .and_then(|report| report.downloads_root.clone()),
            export_deliver_root: profile.export.deliver_root.clone(),
            company,
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
        let models_config = super::super::models_config::compose_models_config_launch(
            tool,
            self.models_path.as_deref(),
            &cell.artifact_store(),
            &ledger,
            (inputs.provider.as_str(), inputs.model.as_str()),
            &inputs.gateway,
            &run_id,
        )?;
        let budget_lane = scope.lane.clone().filter(|lane| lane != &lane_id);
        let request = LaunchRequest {
            tool,
            binding: &launch_binding,
            run_id: run_id.clone(),
            project_id,
            lane_id,
            budget_lane,
            seat_id: seat,
            attempt,
            operation_id: operation_id.clone(),
            initial_target_node: target_node.map(str::to_owned),
            label,
            continue_from,
        };
        let mut launch = super::super::launch::workload_profile_launch(
            super::super::launch::WorkloadLaunchParts {
                request,
                profile,
                plan,
                deadline_seconds: inputs.limits.deadline_seconds,
                model: inputs.model.clone(),
                extension: material.launch,
                policy_input: material.staging_input,
                models_input: models_config.staging_input,
                declared_inputs,
                credential: inputs.credential.clone(),
            },
        )?;
        // ONE absolute end anchored once before the create phase: the same
        // instant governs the create actuation, every readiness read, and
        // the at-most-one attach. No budget is ever reset or recomputed,
        // and at least one declared request window stays reserved for the
        // attach itself.
        if let Some(queued) = self
            .hold_when_full(tool, &control, &mut launch, held, &run_id)
            .await?
        {
            return Ok(queued);
        }
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
        inputs.unresolved_hosts = observation.unresolved_hosts.clone();
        let settlement = mutation_settlement(
            MutationStatus::Accepted,
            run_id.as_str(),
            operation_id.as_str(),
            &observation,
        )
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
            || async {
                let result = port
                    .open_session(
                        &inputs,
                        caller_scope
                            .run
                            .as_ref()
                            .expect("the launch requires a caller run"),
                        &operation_id,
                    )
                    .await;
                persist_refused_attach(result, || {
                    reconciler.request_refused_release(operation_id.as_str(), &run_id)
                })
            },
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
}
