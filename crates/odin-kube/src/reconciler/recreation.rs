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
        super::create::campaign_deadline(&launch, None)?;
        self.bind_worker(&job, &launch, operation).await?;
        self.release_worker(&launch.worker_id).await?;
        let live = self.get_job(&action.job_name()).await?.ok_or_else(|| {
            KubeError::rejected("resumed Job disappeared from the API before observation")
        })?;
        self.owned_observation(&live)
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
        super::create::campaign_deadline(&launch, action.rehome_target())?;
        // Admit placement and state movement before stopping the existing workload.
        let mut carry_from = None;
        if let Some(plan) = &launch.workload {
            if let Some(target) = action.rehome_target() {
                crate::state_carry::require_node_fits(
                    &self.client,
                    target,
                    &launch.node_requirements(),
                    &plan.data,
                )
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
                                if !plan.state_carry {
                                    return Err(state_stays(&plan.profile, &source));
                                }
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
                action,
                &launch,
                plan,
                (target, carry_from),
                operation,
                progress,
            )
            .await?;
        }
        // A started old Job's remaining time carries over, floored; an unstarted one has none.
        let now = k8s_openapi::jiff::Timestamp::now().as_second();
        let deadline = old.as_ref().and_then(|job| {
            let deadline = job.spec.as_ref()?.active_deadline_seconds?;
            let started = job.status.as_ref()?.start_time.as_ref()?;
            Some(if launch.campaign_reservation.is_some() {
                deadline
                    .saturating_sub(now.saturating_sub(started.0.as_second()).max(0))
                    .max(0)
            } else {
                restarted_deadline(deadline, started.0.as_second(), now)
            })
        });
        if launch.campaign_reservation.is_some() && deadline == Some(0) {
            return Err(KubeError::rejected("campaign compute budget is exhausted"));
        }
        self.create_job_on(
            &launch,
            action.rehome_target(),
            deadline,
            operation,
            progress,
        )
        .await
    }

    // Persist the checkpoint before deleting the old volume.
    // The source and destination describe one state-volume move.
    async fn carry_state(
        &self,
        action: &JobAction,
        launch: &JobLaunch,
        plan: &crate::workload::WorkloadPodPlan,
        placement: (&str, Option<String>),
        operation: &str,
        progress: &mut Progress,
    ) -> Result<(), KubeError> {
        let (target, carry_from) = placement;
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

/// The least runtime a restarted pod gets, however little its old Job had left.
const RESTART_DEADLINE_FLOOR_SECONDS: i64 = 300;

// A restarted Job runs for what its old Job had left, never less than the floor.
fn restarted_deadline(deadline: i64, started: i64, now: i64) -> i64 {
    let elapsed = now.saturating_sub(started).max(0);
    deadline
        .saturating_sub(elapsed)
        .max(RESTART_DEADLINE_FLOOR_SECONDS)
}

/// A profile declaring `state.carry = false` keeps its state on its node: rehome refuses.
pub(super) fn state_stays(profile: &str, node: &str) -> KubeError {
    KubeError::rejected(format!(
        "profile {profile} declares state.carry = false: its state stays on {node}; restart it \
         in place or cancel it"
    ))
}

#[cfg(test)]
mod deadline_tests {
    #[test]
    fn a_restarted_pod_gets_what_its_old_job_had_left_but_not_less_than_the_floor() {
        assert_eq!(super::restarted_deadline(3600, 0, 600), 3000);
        assert_eq!(
            super::restarted_deadline(3600, 0, 3500),
            super::RESTART_DEADLINE_FLOOR_SECONDS
        );
    }
}
