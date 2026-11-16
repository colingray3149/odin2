use super::*;

/// Profiles that declare `[offload]`: the run goes to a compute target instead of a Job.
impl KubeCommandCoordinator {
    pub(super) async fn create_offload(
        &self,
        tool: &'static str,
        control: &odin_huginn::kube::KubeControl,
        launch: &odin_kube::JobLaunch,
        inputs: &super::super::ScriptLaunchInputs,
        held: &QueuedLaunch,
        operation_id: &OperationId,
    ) -> Result<Value, HostToolError> {
        let Some(offload) = self.offload.as_ref() else {
            return Err(HostToolError::Unavailable {
                tool,
                reason: "offload is not configured on this daemon".to_owned(),
            });
        };
        // Hold the same lifecycle lock as Job creation until the offload journal
        // publishes the run, so neither executor can admit against a stale view.
        let reconciler = control.reconciler();
        let _admission = reconciler.admission_guard().await;
        let cell = self
            .runtime_cell
            .as_ref()
            .ok_or_else(|| HostToolError::Unavailable {
                tool,
                reason: "compute budget admission has no runtime cell".to_owned(),
            })?;
        let client = cell
            .client()
            .await
            .map_err(|error| HostToolError::Unavailable {
                tool,
                reason: format!("compute budget admission cannot reach the cluster: {error}"),
            })?;
        let resources = inputs.profile.profile.resources.as_ref();
        let request = odin_domain::huginn::KubeResources {
            cpu_millis: resources.map_or(0, |resources| u64::from(resources.cpu) * 1_000),
            gpu_count: launch.gpu_count,
            ..Default::default()
        };
        let snapshot = cell.snapshot();
        let max_target_rate = inputs
            .profile
            .profile
            .offload
            .as_ref()
            .into_iter()
            .flat_map(|offload| &offload.targets)
            .filter_map(|target| {
                snapshot.object(odin_registry::RegistryKind::ComputeTarget, target)
            })
            .filter_map(|object| match &object.config {
                odin_registry::ObjectConfig::ComputeTarget(target) if target.enabled => {
                    target.cost.as_ref()
                }
                _ => None,
            })
            .map(|cost| {
                cost.usd_per_hour.unwrap_or(0.0)
                    + cost.usd_per_core_hour.unwrap_or(0.0) * request.cpu_millis as f64 / 1_000.0
            })
            .fold(0.0_f64, f64::max);
        let new_usd = max_target_rate * f64::from(launch.deadline_seconds.unwrap_or(0)) / 3_600.0;
        let runs = offload.runs();
        if !runs.iter().any(|run| run.run_id == launch.labels.run_id) {
            let seat_active = runs
                .iter()
                .filter(|run| {
                    !run.state.finished() && run.seat_id.as_ref() == Some(&launch.labels.seat_id)
                })
                .count();
            if let Err(error) = odin_kube::admit_parallel_run_with_extra(
                &client,
                &snapshot,
                &launch.labels.seat_id,
                None,
                seat_active,
            )
            .await
            {
                if held.queue_caps && odin_kube::is_cap_refusal(&error) {
                    if let Some(queue) = self.launch_queue() {
                        return Self::hold(tool, &queue, held, &launch.labels.run_id);
                    }
                }
                return Err(kube_failure(tool, error));
            }
            let mut lanes = vec![&launch.labels.lane_id];
            if let Some(budget) = launch.budget_lane.as_ref() {
                if budget != &launch.labels.lane_id {
                    lanes.push(budget);
                }
            }
            for lane in lanes {
                odin_kube::admit_lane_wall(&snapshot, lane, cell.huginn_root())
                    .map_err(|error| kube_failure(tool, error))?;
                let active: Vec<RunId> = runs
                    .iter()
                    .filter(|run| {
                        !run.state.finished() && run.lanes.iter().any(|id| id == lane.as_str())
                    })
                    .map(|run| run.run_id.clone())
                    .collect();
                if let Err(error) = odin_kube::admit_lane_pod_budget_with_pending(
                    &client,
                    &snapshot,
                    lane,
                    cell.huginn_root(),
                    None,
                    &active,
                )
                .await
                {
                    if held.queue_caps && odin_kube::is_cap_refusal(&error) {
                        if let Some(queue) = self.launch_queue() {
                            return Self::hold(tool, &queue, held, &launch.labels.run_id);
                        }
                    }
                    return Err(kube_failure(tool, error));
                }
                let extra = runs
                    .iter()
                    .filter(|run| {
                        !run.state.finished() && run.lanes.iter().any(|id| id == lane.as_str())
                    })
                    .fold(
                        (
                            request.cpu_millis as f64 / 1_000.0
                                * f64::from(launch.deadline_seconds.unwrap_or(0)),
                            f64::from(request.gpu_count)
                                * f64::from(launch.deadline_seconds.unwrap_or(0)),
                            new_usd,
                        ),
                        |(cores, gpus, usd), run| {
                            let seconds = run.remaining_seconds() as f64;
                            (
                                cores + f64::from(run.cores) * seconds,
                                gpus + f64::from(run.gpus) * seconds,
                                usd + run.usd_per_hour * seconds / 3_600.0,
                            )
                        },
                    );
                if let Err(error) = odin_kube::admit_lane_compute_with_projection(
                    &client,
                    &snapshot,
                    lane,
                    cell.huginn_root(),
                    None,
                    odin_kube::ComputeLaunchProjection {
                        request: Default::default(),
                        deadline_seconds: None,
                    },
                    extra,
                )
                .await
                {
                    if held.queue_caps && odin_kube::is_compute_budget_refusal(&error) {
                        let Some(queue) = self.launch_queue() else {
                            return Err(kube_failure(tool, error));
                        };
                        return Self::hold(tool, &queue, held, &launch.labels.run_id);
                    }
                    return Err(kube_failure(tool, error));
                }
            }
        }
        let files = control
            .reconciler()
            .staged_files(launch)
            .map_err(|error| kube_failure(tool, error))?;
        match offload
            .submit(launch, &inputs.profile.id, &inputs.profile.profile, files)
            .await
        {
            Ok(run) => serialize_output(
                tool,
                &super::super::evidence::offload_settlement(
                    MutationStatus::Accepted,
                    operation_id.as_str(),
                    &run,
                ),
            ),
            Err(crate::live::offload::OffloadRefusal::Full(reason)) => {
                let Some(queue) = self.launch_queue() else {
                    return Err(HostToolError::Unavailable { tool, reason });
                };
                tracing::info!(run = %launch.labels.run_id.as_str(), "offload launch held: {reason}");
                Self::hold(tool, &queue, held, &launch.labels.run_id)
            }
            Err(crate::live::offload::OffloadRefusal::Refused(reason)) => {
                Err(HostToolError::Unavailable { tool, reason })
            }
        }
    }

    pub(super) async fn mutate_offload(
        &self,
        tool: &'static str,
        verb: &'static str,
        run_id: &RunId,
        operation_id: &OperationId,
        run: crate::live::offload::OffloadRun,
    ) -> Result<Value, HostToolError> {
        if verb != "cancel" {
            return Err(super::super::admission::arguments_error(
                tool,
                format!(
                    "{run_id} runs on compute target {}; an offload run takes only cancel",
                    run.target
                ),
            ));
        }
        let Some(offload) = self.offload.as_ref() else {
            return Err(HostToolError::Unavailable {
                tool,
                reason: "offload is not configured on this daemon".to_owned(),
            });
        };
        let stopped = offload
            .stop(run_id)
            .await
            .map_err(|reason| HostToolError::Unavailable { tool, reason })?;
        serialize_output(
            tool,
            &super::super::evidence::offload_settlement(
                MutationStatus::Accepted,
                operation_id.as_str(),
                &stopped,
            ),
        )
    }
}
