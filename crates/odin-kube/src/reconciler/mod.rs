//! Durable run-addressed Job operations. Kubernetes resourceVersion claims are the
//! command admission point; only StopAuthority releases, suspends, or deletes workers.
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use k8s_openapi::api::batch::v1::Job;
use kube::api::{ListParams, Patch, PatchParams};
use odin_domain::huginn::{KubeNodeView, KubeOperationKind, KubeWorkloadView};
use odin_domain::{ArtifactId, Digest, RunId};
use odin_kernel::StopAuthority;
use odin_ledger::Ledger;
use odin_types::OperationId;

mod actions;
mod create;
mod orphans;
pub use orphans::{orphan_verdict, OrphanVerdict, ORPHAN_ENDED_GRACE, ORPHAN_STARTED_GRACE};
mod recreation;
pub(crate) use create::{
    bounded_resources, worker_pod_security, worker_security, WORKER_RESERVATION,
};

use crate::artifacts::ArtifactStore;
use crate::client::{KubeClient, KubeError};
use crate::job::{
    job_name, JobAction, JobLaunch, JobObservation, JOB_PROJECTION_ANNOTATION, KUBE_OWNED_SELECTOR,
};
use crate::journal::{storage, Journal};

/// A concrete non-root UID lets images whose default USER is root pass `runAsNonRoot` checks.
pub(crate) const WORKER_RUN_AS_USER: i64 = 65534;

const OPERATION_CLAIM: &str = "odin.dev/operation-id";
// A claim version race leaves the operation pending for retry.
const CLAIM_VERSION_MOVED: &str = "Job resourceVersion changed";
const FIELD_MANAGER: &str = "odin";
// Limit retries when controller updates race with command admission.
const LIVE_VERSION_ATTEMPTS: u32 = 5;
const LIVE_VERSION_BACKOFF: std::time::Duration = std::time::Duration::from_millis(200);

pub struct JobReconciler {
    client: KubeClient,
    journal: Journal,
    stops: Arc<StopAuthority>,
    artifacts: ArtifactStore,
    commands: Arc<crate::terminal_pod::PodLifecycle>,
}

impl JobReconciler {
    /// Returns `None` if the operation or its launch has not been recorded.
    pub fn operation_launch(
        &self,
        operation: &str,
    ) -> Result<Option<(RunId, JobLaunch)>, KubeError> {
        let Some(run) = self.journal.operation_run(operation)? else {
            return Ok(None);
        };
        let Some(launch) = self.journal.load_launch(&run)? else {
            return Ok(None);
        };
        Ok(Some((run, launch)))
    }

    /// Reads all operation/run pairs at once to avoid a journal query per Job.
    pub fn operation_runs(&self) -> Result<Vec<(String, RunId)>, KubeError> {
        self.journal.operation_runs()
    }

    /// Uses paths recorded during staging rather than recomputing artifact locations.
    pub fn staged_paths(&self, run: &RunId) -> Result<BTreeMap<ArtifactId, String>, KubeError> {
        self.journal.staged_paths(run)
    }

    pub fn stored_launch(&self, run: &RunId) -> Result<Option<JobLaunch>, KubeError> {
        self.journal.load_launch(run)
    }

    pub fn exec_client(&self) -> KubeClient {
        self.client.clone()
    }

    pub fn new(
        client: KubeClient,
        ledger: Arc<Mutex<Ledger>>,
        stops: Arc<StopAuthority>,
        pod_lifecycle: Arc<crate::terminal_pod::PodLifecycle>,
        artifact_root: PathBuf,
    ) -> Result<Self, KubeError> {
        stops.register_job_backend(crate::job_worker_backend(client.clone())?);
        Ok(Self {
            journal: Journal::new(
                Arc::clone(&ledger),
                client.config.cluster.clone(),
                client.config.namespace.clone(),
            ),
            artifacts: ArtifactStore::new(ledger, artifact_root),
            client,
            stops,
            commands: pod_lifecycle,
        })
    }

    pub async fn create(&self, launch: JobLaunch) -> Result<JobObservation, KubeError> {
        let _command = self.commands.lock().await;
        let started = self.journal.begin(
            &launch.operation_id,
            &launch.labels.run_id,
            KubeOperationKind::Create,
            &launch.idempotency_digest,
            &launch,
        )?;
        if let Some(outcome) = started.replay {
            return outcome;
        }
        let launch: JobLaunch = serde_json::from_value(started.request).map_err(storage)?;
        let mut progress = started.progress;
        let outcome = self
            .create_job(&launch, &started.operation_id, &mut progress)
            .await;
        self.journal.finish(&started.operation_id, outcome)
    }

    pub async fn operate(&self, action: JobAction) -> Result<JobObservation, KubeError> {
        let _command = self.commands.lock().await;
        // Reject stale versions before journaling so they do not consume the operation ID.
        // An attempt that already holds the claim resumes without this version check.
        // apply_action rechecks the live Job before the compare-and-swap claim.
        if let Some(job) = self.get_job(&action.job_name()).await? {
            let own_claim = job
                .metadata
                .annotations
                .as_ref()
                .and_then(|values| values.get(OPERATION_CLAIM))
                .map(String::as_str)
                == Some(action.operation_id.as_str());
            if !own_claim {
                let observation = crate::status::observe_job(&self.client.config.cluster, &job, 0)?;
                self.verify_authority(&observation)?;
                if observation.projection.identity.resource_version
                    != action.expected_resource_version
                {
                    return Err(KubeError::Conflict {
                        reason: actions::VERSION_MOVED_REASON.to_owned(),
                    });
                }
            }
        }
        let started = self.journal.begin(
            &action.operation_id,
            &action.run_id,
            action.kind,
            &action.idempotency_digest,
            &action,
        )?;
        if let Some(outcome) = started.replay {
            return outcome;
        }
        let action: JobAction = serde_json::from_value(started.request).map_err(storage)?;
        let mut progress = started.progress;
        let outcome = self
            .apply_action(&action, &started.operation_id, &mut progress)
            .await;
        match outcome {
            // Keep version races pending so the same command can retry with a fresh version.
            Err(error) if version_race(&error) => Err(error),
            outcome => self.journal.finish(&started.operation_id, outcome),
        }
    }

    /// Retries version races for internal callers, not user-supplied preconditions.
    /// Refreshes only the version; the operation ID and digest stay unchanged.
    pub async fn operate_at_live_version(
        &self,
        mut action: JobAction,
    ) -> Result<JobObservation, KubeError> {
        let mut attempt = 1;
        loop {
            let error = match self.operate(action.clone()).await {
                Err(error) if version_race(&error) && attempt < LIVE_VERSION_ATTEMPTS => error,
                outcome => return outcome,
            };
            let Some(fresh) = self.observe_run_readonly(&action.run_id).await? else {
                return Err(error);
            };
            tracing::warn!(
                run = %action.run_id,
                "version race run={} kind={:?} operation={} attempt={attempt} \
                 stale={} live={}",
                action.run_id.as_str(),
                action.kind,
                action.operation_id.as_str(),
                action.expected_resource_version.as_str(),
                fresh.projection.identity.resource_version.as_str()
            );
            action.expected_resource_version = fresh.projection.identity.resource_version;
            tokio::time::sleep(LIVE_VERSION_BACKOFF * attempt).await;
            attempt += 1;
        }
    }

    /// Replays pending operations at the live Job version; reports any still pending.
    /// Released Jobs survive controller restarts and are not stopped by recovery.
    pub async fn recover_pending_operations(&self) -> Result<(), KubeError> {
        for (kind, request) in self.journal.pending()? {
            let outcome = if kind == "create" {
                self.create(serde_json::from_value(request).map_err(storage)?)
                    .await
            } else {
                self.operate_at_live_version(serde_json::from_value(request).map_err(storage)?)
                    .await
            };
            if let Err(error) = outcome {
                if error.is_unavailable() {
                    return Err(error);
                }
            }
        }
        match self.journal.pending()?.len() {
            0 => Ok(()),
            left => Err(KubeError::unavailable(format!(
                "{left} admitted kube operation(s) still pending after recovery"
            ))),
        }
    }

    // A paused worker cannot write while the helper captures its state.
    pub async fn checkpoint_state(
        &self,
        run: &RunId,
    ) -> Result<odin_ledger::artifact::ArtifactMetadata, KubeError> {
        // Serialize helpers with commands and startup cleanup.
        let _command = self.commands.lock().await;
        let launch = self.journal.load_launch(run)?.ok_or_else(|| {
            KubeError::rejected("no durably admitted launch is stored for this run")
        })?;
        let plan = launch.workload.as_ref().ok_or_else(|| {
            KubeError::rejected("this run declares no per-pod state to checkpoint")
        })?;
        let node = crate::state_carry::state_node(&self.client, run)
            .await?
            .ok_or_else(|| {
                KubeError::rejected("the run's state volume is not bound to a node yet")
            })?;
        let tar = crate::state_carry::snapshot(
            &self.client,
            &self.stops,
            run,
            plan,
            &node,
            &launch.image,
        )
        .await?;
        let checkpoint = self.artifacts.register_checkpoint(&tar)?;
        tracing::info!(
            run = %run,
            "state checkpoint run={run} node={node} artifact={} bytes={}",
            checkpoint.artifact_id, checkpoint.size_bytes
        );
        Ok(checkpoint)
    }

    pub async fn observe_run(&self, run: &RunId) -> Result<Option<JobObservation>, KubeError> {
        self.get_job(&job_name(run))
            .await?
            .map(|job| self.owned_observation(&job))
            .transpose()
    }

    /// Validates the launch, worker, UID, and labels without writing a journal revision.
    /// The returned workload revision remains zero.
    pub async fn observe_run_readonly(
        &self,
        run: &RunId,
    ) -> Result<Option<JobObservation>, KubeError> {
        let Some(job) = self.get_job(&job_name(run)).await? else {
            return Ok(None);
        };
        let observation = crate::status::observe_job(&self.client.config.cluster, &job, 0)?;
        self.verify_authority(&observation)?;
        Ok(Some(observation))
    }

    /// Reads pod placement for browser attachment after rehome; Jobs have no node address.
    pub async fn workload_placement(
        &self,
        run: &RunId,
    ) -> Result<Option<crate::workload::WorkloadPlacement>, KubeError> {
        crate::workload::placement(&self.client, run).await
    }

    pub async fn list(&self) -> Result<Vec<JobObservation>, KubeError> {
        let jobs = tokio::time::timeout(
            self.client.config.request_timeout,
            self.client.jobs().list(
                &ListParams::default()
                    .labels(KUBE_OWNED_SELECTOR)
                    .limit(1024),
            ),
        )
        .await
        .map_err(|_| KubeError::unavailable("Job observation timed out"))??;
        if jobs
            .metadata
            .continue_
            .as_ref()
            .is_some_and(|value| !value.is_empty())
        {
            return Err(KubeError::unavailable(
                "Job inventory exceeds its observation bound",
            ));
        }
        let mut observed = Vec::with_capacity(jobs.items.len());
        for job in jobs.items {
            // A suspended Job is not ready for publication until its API identity is registered.
            if job
                .metadata
                .annotations
                .as_ref()
                .and_then(|values| values.get(JOB_PROJECTION_ANNOTATION))
                .is_none()
            {
                continue;
            }
            match self.owned_observation(&job) {
                Ok(value) => observed.push(value),
                Err(KubeError::Rejected { .. }) => {}
                Err(error) => return Err(error),
            }
        }
        Ok(observed)
    }

    pub fn stamp_observation(
        &self,
        mut observation: JobObservation,
    ) -> Result<JobObservation, KubeError> {
        self.verify_authority(&observation)?;
        let key = serde_json::to_string(&(
            "job",
            &self.client.config.cluster,
            &self.client.config.namespace,
            &observation.projection.labels.run_id,
        ))
        .map_err(storage)?;
        observation.workload.revision = self.journal.revision(&key, &observation)?;
        Ok(observation)
    }

    pub fn stamp_node(&self, mut node: KubeNodeView) -> Result<KubeNodeView, KubeError> {
        let key =
            serde_json::to_string(&("node", &self.client.config.cluster, &node.resource.name))
                .map_err(storage)?;
        node.revision = self.journal.revision(&key, &node)?;
        Ok(node)
    }

    /// Assigns a persistent revision because Kubernetes resourceVersions are opaque.
    /// Unchanged foreign views keep their revision; no launch or worker is registered.
    pub fn stamp_foreign(&self, mut view: KubeWorkloadView) -> Result<KubeWorkloadView, KubeError> {
        let key = serde_json::to_string(&(
            "foreign-job",
            &self.client.config.cluster,
            &self.client.config.namespace,
            &view.resource,
        ))
        .map_err(storage)?;
        view.revision = self.journal.revision(&key, &view)?;
        Ok(view)
    }

    /// Returns `None` while pending, otherwise the recorded outcome, without executing it.
    pub fn operation_outcome(
        &self,
        operation: &OperationId,
    ) -> Result<Option<Result<JobObservation, KubeError>>, KubeError> {
        self.journal.operation_outcome(operation.as_str())
    }

    /// Replays only the stored action matching this operation ID, run, kind, and digest.
    /// Returns `None` if no matching attempt was admitted; create uses its own replay path.
    /// `operate` acquires the command lock and repeats admission checks.
    pub async fn recover_admitted_operation(
        &self,
        operation: &OperationId,
        run: &RunId,
        kind: KubeOperationKind,
        digest: &Digest,
    ) -> Result<Option<JobObservation>, KubeError> {
        if kind == KubeOperationKind::Create {
            return Err(KubeError::Rejected {
                reason:
                    "create recovery replays through the create path, not admitted-action recovery"
                        .to_owned(),
            });
        }
        match self.journal.admitted_action(operation, run, kind, digest)? {
            Some(action) => self.operate(action).await.map(Some),
            None => Ok(None),
        }
    }

    fn owned_observation(&self, job: &Job) -> Result<JobObservation, KubeError> {
        self.stamp_observation(crate::status::observe_job(
            &self.client.config.cluster,
            job,
            0,
        )?)
    }

    fn verify_authority(&self, observation: &JobObservation) -> Result<(), KubeError> {
        let launch = self
            .journal
            .load_launch(&observation.projection.labels.run_id)?
            .ok_or_else(|| KubeError::rejected("Job run is not registered to Odin"))?;
        let identity = self
            .stops
            .job_worker_status(&observation.projection.worker.worker_id)
            .map_err(storage)?
            .map(|(identity, _)| identity)
            .ok_or_else(|| KubeError::rejected("Job worker is not registered to this authority"))?;
        if observation.projection.labels != launch.labels
            || identity.cluster != self.client.config.cluster
            || identity.namespace != self.client.config.namespace
            || identity.job_name != observation.workload.resource.name
            || identity.job_uid != observation.projection.identity.uid.as_str()
            || observation.workload.resource.namespace.as_deref()
                != Some(self.client.config.namespace.as_str())
        {
            return Err(KubeError::rejected(
                "Job API identity or labels disagree with its durable worker binding",
            ));
        }
        Ok(())
    }

    async fn get_job(&self, name: &str) -> Result<Option<Job>, KubeError> {
        tokio::time::timeout(
            self.client.config.request_timeout,
            self.client.jobs().get_opt(name),
        )
        .await
        .map_err(|_| KubeError::unavailable("Job query timed out"))?
        .map_err(Into::into)
    }

    async fn apply_job(&self, name: &str, value: serde_json::Value) -> Result<Job, KubeError> {
        tokio::time::timeout(
            self.client.config.request_timeout,
            self.client.jobs().patch(
                name,
                &PatchParams::apply(FIELD_MANAGER).force(),
                &Patch::Apply(value),
            ),
        )
        .await
        .map_err(|_| KubeError::unavailable("Job binding apply timed out"))?
        .map_err(Into::into)
    }

    async fn patch_job(&self, name: &str, value: serde_json::Value) -> Result<Job, KubeError> {
        let result = tokio::time::timeout(
            self.client.config.request_timeout,
            self.client
                .jobs()
                .patch(name, &PatchParams::default(), &Patch::Merge(value)),
        )
        .await
        .map_err(|_| KubeError::unavailable("Job metadata claim timed out"))?;
        match result {
            Err(kube::Error::Api(error)) if error.code == 409 => Err(KubeError::Conflict {
                reason: CLAIM_VERSION_MOVED.to_owned(),
            }),
            other => other.map_err(Into::into),
        }
    }
}

// A version race must leave the operation pending rather than record a final outcome.
fn version_race(error: &KubeError) -> bool {
    match error {
        KubeError::Conflict { reason } => {
            reason == actions::VERSION_MOVED_REASON || reason == CLAIM_VERSION_MOVED
        }
        _ => false,
    }
}
