//! Run-addressed Job mutations through the stop authority.

use std::sync::Arc;

use k8s_openapi::api::batch::v1::Job;
use odin_domain::huginn::{KubeJobLifecycle, KubeJobProjection, KubeOperationKind};
use odin_domain::{RunId, StopVerdictTag};
use odin_ledger::stop::JobStopAction;
use odin_ledger::worker::JobWorkerPhase;
use odin_types::WorkerId;
use serde_json::json;

use super::{JobReconciler, OPERATION_CLAIM};
use crate::client::KubeError;
use crate::job::{JobAction, JobObservation, JOB_PROJECTION_ANNOTATION};
use crate::journal::{Journal, Progress};

impl JobReconciler {
    // The authority performs blocking ledger and backend I/O.
    pub(super) async fn authority_stop(
        &self,
        worker: &WorkerId,
        action: JobStopAction,
    ) -> Result<(), KubeError> {
        let stops = Arc::clone(&self.stops);
        let worker_id = worker.clone();
        let attempt =
            tokio::task::spawn_blocking(move || stops.stop_job_worker(&worker_id, action))
                .await
                .map_err(|error| {
                    KubeError::unavailable(format!("stop authority task failed to join: {error}"))
                })?
                .map_err(|error| {
                    KubeError::unavailable(format!("stop authority could not be reached: {error}"))
                })?;
        match attempt.verdict {
            StopVerdictTag::Stopped => {}
            StopVerdictTag::Failed => {
                return Err(KubeError::rejected(format!(
                    "stop of job worker {} left workload residue",
                    attempt.worker_id.as_str()
                )));
            }
            StopVerdictTag::Requested | StopVerdictTag::Indeterminate => {
                return Err(KubeError::unavailable(format!(
                    "stop of job worker {} did not settle (verdict {}); the intent stays pending for recovery",
                    attempt.worker_id.as_str(),
                    attempt.verdict
                )));
            }
        }
        // A terminal replay can belong to an earlier Suspend, not this Delete.
        let evidence = &attempt.evidence;
        let settled = match action {
            JobStopAction::Delete => evidence.job_absent,
            JobStopAction::Suspend => evidence.job_absent || evidence.job_suspended == Some(true),
        };
        if !settled {
            return Err(KubeError::rejected(format!(
                "stop of job worker {} did not apply the requested {action:?} disposition",
                attempt.worker_id.as_str()
            )));
        }
        Ok(())
    }
}

impl JobReconciler {
    pub(super) async fn apply_action(
        &self,
        action: &JobAction,
        operation: &str,
        progress: &mut Progress,
    ) -> Result<JobObservation, KubeError> {
        if action.kind == KubeOperationKind::Create {
            return Err(KubeError::rejected(
                "Create is admitted only through the create entry; a JobAction can never mint a Job",
            ));
        }
        let job = self.get_job(&action.job_name()).await?;
        let observation = match &job {
            Some(job) => Some(self.checked_observation(job)?),
            None => None,
        };
        let own_claim = match (&job, &observation) {
            (Some(job), Some(_)) => self.own_pending_claim(job, operation)?,
            _ => false,
        };
        if let Some(observation) = &observation {
            if !own_claim {
                self.check_expected_version(action, observation)?;
                if !action.is_pure() {
                    self.claim_operation(action, operation).await?;
                }
            }
            if !action.is_pure() && progress.prior.is_none() {
                // Persist the pre-action identity before any effect can remove the Job.
                progress.prior = Some(observation.clone());
                self.journal.progress(operation, progress)?;
            }
        }
        match action.kind {
            KubeOperationKind::Summarize => observation.ok_or_else(|| {
                KubeError::rejected("summarize requires the live Job; there is nothing to observe")
            }),
            KubeOperationKind::Pause => self.pause_job(action, operation, progress, job).await,
            KubeOperationKind::Cancel => self.cancel_job(action, operation, progress, job).await,
            KubeOperationKind::Resume => self.resume_job(action, operation, progress, job).await,
            KubeOperationKind::Restart => self.restart_job(action, operation, progress, job).await,
            KubeOperationKind::Create => unreachable!("Create is rejected before admission"),
        }
    }
}

// Version conflicts stay pending until the caller admits a fresh observation.
pub(super) const VERSION_MOVED_REASON: &str =
    "Job resourceVersion moved past the caller's opaque version";

impl JobReconciler {
    fn checked_observation(&self, job: &Job) -> Result<JobObservation, KubeError> {
        let observation = self.owned_observation(job)?;
        self.verify_authority(&observation)?;
        Ok(observation)
    }

    // Never replace the caller's admitted version with a fresher one.
    fn check_expected_version(
        &self,
        action: &JobAction,
        observation: &JobObservation,
    ) -> Result<(), KubeError> {
        if observation.projection.identity.resource_version != action.expected_resource_version {
            return Err(KubeError::Conflict {
                reason: VERSION_MOVED_REASON.to_owned(),
            });
        }
        Ok(())
    }

    fn own_pending_claim(&self, job: &Job, operation: &str) -> Result<bool, KubeError> {
        let holder = job
            .metadata
            .annotations
            .as_ref()
            .and_then(|values| values.get(OPERATION_CLAIM))
            .map(String::as_str);
        match holder {
            Some(holder) if holder == operation => Ok(true),
            Some(holder) => {
                if self.journal.pending_claim(holder)? {
                    return Err(KubeError::Conflict {
                        reason: format!("pending operation {holder} still holds the Job claim"),
                    });
                }
                Ok(false)
            }
            None => Ok(false),
        }
    }

    async fn claim_operation(&self, action: &JobAction, operation: &str) -> Result<(), KubeError> {
        let claim = json!({
            "metadata": {
                "resourceVersion": action.expected_resource_version,
                "annotations": { (OPERATION_CLAIM): operation },
            }
        });
        self.patch_job(&action.job_name(), claim).await?;
        Ok(())
    }
}

fn bound_worker(job: &Job) -> Result<WorkerId, KubeError> {
    let encoded = job
        .metadata
        .annotations
        .as_ref()
        .and_then(|values| values.get(JOB_PROJECTION_ANNOTATION))
        .ok_or_else(|| KubeError::rejected("Job carries no Odin projection annotation"))?;
    let projection: KubeJobProjection = serde_json::from_str(encoded).map_err(|error| {
        KubeError::rejected(format!("Job projection fails domain schema: {error}"))
    })?;
    Ok(projection.worker.worker_id)
}

impl JobReconciler {
    async fn pause_job(
        &self,
        action: &JobAction,
        operation: &str,
        progress: &mut Progress,
        job: Option<Job>,
    ) -> Result<JobObservation, KubeError> {
        let job = job.ok_or_else(|| {
            KubeError::rejected("pause requires the live Job; there is nothing to suspend")
        })?;
        let worker = bound_worker(&job)?;
        if progress.stop_worker.as_ref() != Some(&worker) {
            progress.stop_worker = Some(worker.clone());
            self.journal.progress(operation, progress)?;
        }
        self.authority_stop(&worker, JobStopAction::Suspend).await?;
        let live = self.get_job(&action.job_name()).await?.ok_or_else(|| {
            KubeError::rejected("paused Job disappeared from the API before observation")
        })?;
        self.owned_observation(&live)
    }

    // Stopped workers replay their terminal action, so deleting a paused Job needs a new worker.
    async fn cancel_job(
        &self,
        action: &JobAction,
        operation: &str,
        progress: &mut Progress,
        job: Option<Job>,
    ) -> Result<JobObservation, KubeError> {
        let job = match job {
            Some(job) => job,
            None => {
                // Job absence alone does not establish that its pods have been reaped.
                let worker =
                    absent_job_cancel(&self.journal, &action.run_id, progress.stop_worker.clone())?;
                self.authority_stop(&worker, JobStopAction::Delete).await?;
                self.delete_run_residue(&action.run_id).await?;
                return self.retired_prior(progress);
            }
        };
        let bound = bound_worker(&job)?;
        let phase = self
            .stops
            .job_worker_status(&bound)
            .map_err(|error| {
                KubeError::unavailable(format!("stop authority status read failed: {error}"))
            })?
            .map(|(_, phase)| phase);
        if phase == Some(JobWorkerPhase::Stopped) {
            let custodian = match progress.next_launch.clone() {
                Some(launch) => launch,
                None => {
                    // Persist the replacement worker before changing the Job annotation.
                    let custodian = self.fresh_launch(action)?;
                    progress.stop_worker = Some(custodian.worker_id.clone());
                    progress.next_launch = Some(custodian.clone());
                    self.journal.progress(operation, progress)?;
                    custodian
                }
            };
            self.bind_worker(&job, &custodian, operation).await?;
            self.authority_stop(&custodian.worker_id, JobStopAction::Delete)
                .await?;
        } else {
            if progress.stop_worker.as_ref() != Some(&bound) {
                progress.stop_worker = Some(bound.clone());
                self.journal.progress(operation, progress)?;
            }
            self.authority_stop(&bound, JobStopAction::Delete).await?;
        }
        self.delete_run_residue(&action.run_id).await?;
        self.retired_prior(progress)
    }

    fn retired_prior(&self, progress: &Progress) -> Result<JobObservation, KubeError> {
        let prior = progress.prior.clone().ok_or_else(|| {
            KubeError::rejected("the Job is absent with no journaled prior observation to retire")
        })?;
        let mut retired = prior;
        if let Some(launch) = &progress.next_launch {
            retired.projection.worker.worker_id = launch.worker_id.clone();
        }
        retired.projection.lifecycle = KubeJobLifecycle::Retired;
        self.stamp_observation(retired)
    }
}

// Keep the registered worker available for pod cleanup even when the Job has disappeared.
fn absent_job_cancel(
    journal: &Journal,
    run: &RunId,
    stop_worker: Option<WorkerId>,
) -> Result<WorkerId, KubeError> {
    if !journal.has_registered_launch(run)? {
        return Err(KubeError::Rejected {
            reason: format!(
                "cancel of run {}: no Odin Job was ever registered in this cluster and namespace, so the observed absence is genuine and no delete disposition is owed",
                run.as_str()
            ),
        });
    }
    stop_worker.ok_or_else(|| {
        KubeError::unavailable("the Job is absent but no stop worker was recorded for pod cleanup")
    })
}

#[cfg(test)]
mod absent_job_cancel_tests {
    use std::sync::{Arc, Mutex};

    use odin_domain::RunId;
    use odin_ledger::Ledger;
    use odin_types::WorkerId;

    use super::absent_job_cancel;
    use crate::client::KubeError;
    use crate::journal::Journal;

    fn journal() -> Journal {
        Journal::new(
            Arc::new(Mutex::new(
                Ledger::open_in_memory().expect("in-memory ledger with the kube schema"),
            )),
            "unit-cluster".to_owned(),
            "unit-namespace".to_owned(),
        )
    }

    fn register_launch(journal: &Journal, run: &RunId) {
        journal
            .ledger
            .lock()
            .expect("operation ledger lock")
            .connection()
            .execute(
                "INSERT INTO kube_job_runs(run_id,cluster,namespace,launch_json,created_at) VALUES(?1,?2,?3,'{}','2026-01-01T00:00:00Z')",
                rusqlite::params![run.as_str(), "unit-cluster", "unit-namespace"],
            )
            .expect("ownership row inserted");
    }

    #[test]
    fn cancel_of_never_registered_run_is_rejected_not_unproved() {
        let journal = journal();
        let run = RunId::new("run-foreign-stranger").expect("valid run id");

        let error = absent_job_cancel(&journal, &run, None).expect_err("nothing to cancel");
        assert!(
            !error.is_unavailable(),
            "genuine absence is a terminal verdict, not unproved teardown: {error:?}"
        );
        assert!(matches!(error, KubeError::Rejected { .. }), "{error:?}");
    }

    #[test]
    fn cancel_of_previously_owned_run_still_requires_stop_authority() {
        let journal = journal();
        let run = RunId::new("run-previously-owned").expect("valid run id");
        register_launch(&journal, &run);

        let error = absent_job_cancel(&journal, &run, None).expect_err("reaping is unproved");
        assert!(
            error.is_unavailable(),
            "an owned run's absence is unproved without the stop authority: {error:?}"
        );
    }

    #[test]
    fn registered_run_drives_its_journaled_stop_worker() {
        let journal = journal();
        let run = RunId::new("run-owned-custodian").expect("valid run id");
        register_launch(&journal, &run);
        let worker = WorkerId::new("worker-owned-custodian").expect("valid worker id");

        let custodian =
            absent_job_cancel(&journal, &run, Some(worker.clone())).expect("proof law satisfied");
        assert_eq!(custodian, worker);
    }
}
