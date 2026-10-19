//! Resume, restart, and rehome Jobs using their registered launch profile.

use k8s_openapi::api::batch::v1::Job;
use odin_domain::huginn::KubeJobProjection;
use odin_ledger::stop::JobStopAction;
use odin_ledger::worker::JobWorkerPhase;
use odin_types::WorkerId;

use super::JobReconciler;
use crate::client::KubeError;
use crate::job::{JobAction, JobLaunch, JobObservation, JOB_PROJECTION_ANNOTATION};
use crate::journal::{storage, Progress};
use crate::status::mint_worker_id;

impl JobReconciler {
    async fn live_job(
        &self,
        action: &JobAction,
        job: Option<Job>,
    ) -> Result<Option<Job>, KubeError> {
        match job {
            Some(job) => Ok(Some(job)),
            None => self.get_job(&action.job_name()).await,
        }
    }

    fn stored_projection(job: &Job) -> Result<KubeJobProjection, KubeError> {
        let encoded = job
            .metadata
            .annotations
            .as_ref()
            .and_then(|values| values.get(JOB_PROJECTION_ANNOTATION))
            .ok_or_else(|| {
                KubeError::rejected("Job is not Odin-bound: missing projection annotation")
            })?;
        serde_json::from_str(encoded).map_err(|error| {
            KubeError::rejected(format!("Job projection fails domain schema: {error}"))
        })
    }

    fn bound_worker(job: &Job) -> Result<WorkerId, KubeError> {
        Ok(Self::stored_projection(job)?.worker.worker_id)
    }

    // Reuse the admitted launch profile, not mutable fields from the live Job.
    pub(super) fn fresh_launch(&self, action: &JobAction) -> Result<JobLaunch, KubeError> {
        let mut launch = self.journal.load_launch(&action.run_id)?.ok_or_else(|| {
            KubeError::rejected("no durably admitted launch is stored for this run")
        })?;
        launch
            .validate()
            .map_err(|reason| KubeError::Rejected { reason })?;
        launch.worker_id = mint_worker_id().map_err(storage)?;
        launch.operation_id = action.operation_id.clone();
        launch.idempotency_digest = action.idempotency_digest;
        Ok(launch)
    }
}
impl JobReconciler {
    pub(super) async fn resume_job(
        &self,
        action: &JobAction,
        operation: &str,
        progress: &mut Progress,
        job: Option<Job>,
    ) -> Result<JobObservation, KubeError> {
        let job = self.live_job(action, job).await?.ok_or_else(|| {
            KubeError::rejected(
                "Resume requires the live Job; there is no admitted object to resume",
            )
        })?;
        let old_worker = Self::bound_worker(&job)?;
        let launch = match progress.next_launch.clone() {
            Some(launch) => launch,
            None => {
                let phase = self
                    .stops
                    .job_worker_status(&old_worker)
                    .map_err(storage)?
                    .map(|(_, phase)| phase)
                    .ok_or_else(|| {
                        KubeError::rejected(format!(
                            "suspended Job worker {} is not registered to the stop authority",
                            old_worker.as_str()
                        ))
                    })?;
                if phase != JobWorkerPhase::Stopped {
                    return Err(KubeError::rejected(format!(
                        "resume requires a stopped worker without pods; {} is {phase:?}",
                        old_worker.as_str()
                    )));
                }
                let launch = self.fresh_launch(action)?;
                // Persist the new worker before changing the Job annotation.
                progress.stop_worker = Some(old_worker);
                progress.next_launch = Some(launch.clone());
                if progress.prior.is_none() {
                    progress.prior = Some(self.owned_observation(&job)?);
                }
                self.journal.progress(operation, progress)?;
                launch
            }
        };
        self.bind_worker(&job, &launch, operation).await?;
        self.restore_paused_deadline(&action.job_name()).await?;
        self.release_worker(&launch.worker_id).await?;
        let live = self.get_job(&action.job_name()).await?.ok_or_else(|| {
            KubeError::rejected("resumed Job disappeared from the API before observation")
        })?;
        self.owned_observation(&live)
    }

    // Preserve the remaining runtime by extending the deadline over the pause.
    async fn restore_paused_deadline(&self, name: &str) -> Result<(), KubeError> {
        let Some(job) = self.get_job(name).await? else {
            return Ok(());
        };
        let deadline = job
            .spec
            .as_ref()
            .and_then(|spec| spec.active_deadline_seconds);
        let status = job.status.as_ref();
        let started = status.and_then(|status| status.start_time.as_ref());
        let suspended = status
            .and_then(|status| status.conditions.as_ref())
            .and_then(|conditions| {
                conditions
                    .iter()
                    .find(|condition| condition.type_ == "Suspended" && condition.status == "True")
            })
            .and_then(|condition| condition.last_transition_time.as_ref());
        let (Some(deadline), Some(started), Some(suspended)) = (deadline, started, suspended)
        else {
            return Ok(());
        };
        let now = k8s_openapi::jiff::Timestamp::now().as_second();
        let extended = resumed_deadline(
            deadline,
            started.0.as_second(),
            suspended.0.as_second(),
            now,
        );
        if extended > deadline {
            self.patch_job(
                name,
                serde_json::json!({"spec": {"activeDeadlineSeconds": extended}}),
            )
            .await?;
        }
        Ok(())
    }

    // A terminal Suspend cannot be reused for Delete; register a new worker first.
    pub(super) async fn restart_job(
        &self,
        action: &JobAction,
        operation: &str,
        progress: &mut Progress,
        job: Option<Job>,
    ) -> Result<JobObservation, KubeError> {
        crate::placement::require_placement_authority(
            &self.client.config.allowed_nodes,
            action.rehome_target(),
        )?;
        let old = self.live_job(action, job).await?;
        let launch = match progress.next_launch.clone() {
            Some(launch) => launch,
            None => self.fresh_launch(action)?,
        };
        // Admit placement and state movement before stopping the existing workload.
        let mut carry_from = None;
        if let Some(plan) = &launch.workload {
            if let Some(target) = action.rehome_target() {
                crate::state_carry::require_node_fits(&self.client, target, &launch.node_selector)
                    .await?;
            }
            // A replay past the carry's checkpoint finds the old claim gone.
            if progress.carried.is_none() {
                if let Some(target) = action.rehome_target() {
                    if let Err(refusal) = crate::workload::verify_state_admits_node(
                        &self.client,
                        &action.run_id,
                        plan,
                        target,
                    )
                    .await
                    {
                        let source =
                            crate::state_carry::state_node(&self.client, &action.run_id).await?;
                        match (&refusal, source) {
                            (KubeError::Rejected { .. }, Some(source)) if source != target => {
                                carry_from = Some(source);
                            }
                            _ => return Err(refusal),
                        }
                    }
                }
                crate::workload::require_state_claim(&self.client, &action.run_id, plan).await?;
            }
            crate::workload::verify_egress_scope(&self.client, &action.run_id, plan).await?;
        }
        if let Some(old) = old.as_ref() {
            let current = Self::bound_worker(old)?;
            if progress.stop_worker.is_none() {
                progress.stop_worker = Some(current.clone());
            }
            if progress.prior.is_none() {
                progress.prior = Some(self.owned_observation(old)?);
            }
        }
        if progress.next_launch.is_none() {
            progress.next_launch = Some(launch.clone());
            self.journal.progress(operation, progress)?;
        }
        if let Some(old) = old.as_ref() {
            let current = Self::bound_worker(old)?;
            let phase = self
                .stops
                .job_worker_status(&current)
                .map_err(storage)?
                .map(|(_, phase)| phase)
                .ok_or_else(|| {
                    KubeError::rejected(format!(
                        "Job worker {} is not registered to the stop authority",
                        current.as_str()
                    ))
                })?;
            match phase {
                JobWorkerPhase::Failed | JobWorkerPhase::Residual => {
                    return Err(KubeError::rejected(format!(
                        "Job worker {} left workload residue; recreation requires a clean stop",
                        current.as_str()
                    )));
                }
                JobWorkerPhase::Stopped => {
                    let custodian = self.fresh_launch(action)?;
                    self.bind_worker(old, &custodian, operation).await?;
                    self.authority_stop(&custodian.worker_id, JobStopAction::Delete)
                        .await?;
                }
                _ => self.authority_stop(&current, JobStopAction::Delete).await?,
            }
        }
        if let (Some(plan), Some(target)) = (&launch.workload, action.rehome_target()) {
            self.carry_state(
                action, &launch, plan, target, carry_from, operation, progress,
            )
            .await?;
        }
        self.create_job_on(&launch, action.rehome_target(), operation, progress)
            .await
    }

    // Persist the checkpoint before deleting the old volume.
    #[allow(clippy::too_many_arguments)]
    async fn carry_state(
        &self,
        action: &JobAction,
        launch: &JobLaunch,
        plan: &crate::workload::WorkloadPodPlan,
        target: &str,
        carry_from: Option<String>,
        operation: &str,
        progress: &mut Progress,
    ) -> Result<(), KubeError> {
        let run = &action.run_id;
        let tar = match (&progress.carried, carry_from) {
            (Some(checkpoint), _) => self.artifacts.read_bounded(
                checkpoint,
                odin_registry::schema::storage_quantity_bytes(&plan.state_storage)
                    .unwrap_or(1 << 30)
                    + (1 << 20),
            )?,
            (None, Some(source)) => {
                let tar = crate::state_carry::snapshot(
                    &self.client,
                    &self.stops,
                    run,
                    plan,
                    &source,
                    &launch.image,
                )
                .await?;
                let checkpoint = self.artifacts.register_checkpoint(&tar)?;
                tracing::info!(
                    run = %run,
                    "state checkpoint run={run} from={source} to={target} \
                     artifact={} bytes={}",
                    checkpoint.artifact_id, checkpoint.size_bytes
                );
                progress.carried = Some(checkpoint.artifact_id);
                self.journal.progress(operation, progress)?;
                tar
            }
            (None, None) => return Ok(()),
        };
        crate::state_carry::replant(
            &self.client,
            &self.stops,
            run,
            plan,
            target,
            &launch.image,
            &tar,
        )
        .await?;
        tracing::info!(run = %run, "state carried run={run} to={target}");
        Ok(())
    }
}

/// Slack for the release that follows the deadline patch.
const RESUME_DEADLINE_SLACK_SECONDS: i64 = 30;

// Include the pause duration so the resumed Job retains its remaining runtime.
fn resumed_deadline(deadline: i64, started: i64, suspended: i64, now: i64) -> i64 {
    let ran = suspended.saturating_sub(started).max(0);
    let left = deadline.saturating_sub(ran).max(0);
    let elapsed = now.saturating_sub(started).max(0);
    elapsed
        .saturating_add(left)
        .saturating_add(RESUME_DEADLINE_SLACK_SECONDS)
        .max(deadline)
}

#[cfg(test)]
mod deadline_tests {
    #[test]
    fn a_resumed_pod_keeps_the_time_it_had_left() {
        let (started, paused, resumed) = (0, 52 * 60, 64 * 60);
        let deadline = super::resumed_deadline(3600, started, paused, resumed);
        assert_eq!(deadline - (resumed - started), 8 * 60 + 30);
        assert_eq!(super::resumed_deadline(3600, 0, 600, 700), 3600 + 100 + 30);
    }
}
