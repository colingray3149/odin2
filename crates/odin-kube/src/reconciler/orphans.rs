//! Collect abandoned unregistered Jobs after their age grace period.

use std::collections::BTreeSet;
use std::time::Duration;

use k8s_openapi::api::batch::v1::Job;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
use kube::api::{DeleteParams, Patch, PatchParams, Preconditions};
use odin_domain::huginn::KubeWorkloadState;
use odin_domain::RunId;
use time::OffsetDateTime;

use super::JobReconciler;
use crate::client::KubeError;
use crate::job::{bounded_label_value, JobObservation, JOB_LABEL_RUN_ID};

/// How long an ended orphan stays observable before it is collected.
pub const ORPHAN_ENDED_GRACE: Duration = Duration::from_secs(3_600);
/// Maximum orphan age, whether finished or still running.
pub const ORPHAN_STARTED_GRACE: Duration = Duration::from_secs(24 * 3_600);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OrphanVerdict {
    Registered,
    /// Too young, missing timestamps, or outside this namespace.
    NotDue,
    Collect,
}

pub fn orphan_verdict(
    registered: bool,
    own_namespace: bool,
    state: KubeWorkloadState,
    started_at: Option<OffsetDateTime>,
    finished_at: Option<OffsetDateTime>,
    now: OffsetDateTime,
) -> OrphanVerdict {
    if registered {
        return OrphanVerdict::Registered;
    }
    let older = |at: Option<OffsetDateTime>, grace: Duration| {
        at.is_some_and(|at| {
            now - at >= time::Duration::try_from(grace).unwrap_or(time::Duration::MAX)
        })
    };
    let ended = matches!(
        state,
        KubeWorkloadState::Succeeded | KubeWorkloadState::Failed
    );
    let abandoned = (ended && older(finished_at, ORPHAN_ENDED_GRACE))
        || older(started_at, ORPHAN_STARTED_GRACE);
    if own_namespace && abandoned {
        OrphanVerdict::Collect
    } else {
        OrphanVerdict::NotDue
    }
}

impl JobReconciler {
    pub fn registers_run(&self, run: &odin_domain::RunId) -> Result<bool, KubeError> {
        Ok(self.journal.load_launch(run)?.is_some())
    }

    // Keep run resources until foreground deletion has removed the Job and its pods.
    pub async fn collect_orphan(
        &self,
        observation: &JobObservation,
        now: OffsetDateTime,
    ) -> Result<OrphanVerdict, KubeError> {
        let workload = &observation.workload;
        let verdict = orphan_verdict(
            self.registers_run(&observation.projection.labels.run_id)?,
            workload.resource.namespace.as_deref() == Some(self.client.config.namespace.as_str()),
            workload.state,
            workload.started_at,
            workload.finished_at,
            now,
        );
        if verdict != OrphanVerdict::Collect {
            return Ok(verdict);
        }
        let params = DeleteParams {
            preconditions: Some(Preconditions {
                uid: Some(observation.projection.identity.uid.as_str().to_owned()),
                resource_version: None,
            }),
            ..DeleteParams::foreground()
        };
        match tokio::time::timeout(
            self.client.config.request_timeout,
            self.client.jobs().delete(&workload.resource.name, &params),
        )
        .await
        {
            Err(_) => Err(KubeError::unavailable("orphan Job deletion timed out")),
            Ok(Ok(_)) => {
                self.collect_if_gone(
                    &observation.projection.labels.run_id,
                    &workload.resource.name,
                    verdict,
                )
                .await
            }
            Ok(Err(kube::Error::Api(status))) if status.code == 404 => {
                let _command = self.commands.lock().await;
                self.delete_run_residue(&observation.projection.labels.run_id)
                    .await?;
                Ok(verdict)
            }
            Ok(Err(kube::Error::Api(status))) if status.code == 409 => Err(KubeError::Conflict {
                reason: "orphan Job UID precondition missed; the Job is still there".to_owned(),
            }),
            Ok(Err(error)) => Err(error.into()),
        }
    }

    // A successful delete request may still be waiting for foreground collection.
    async fn collect_if_gone(
        &self,
        run: &RunId,
        name: &str,
        verdict: OrphanVerdict,
    ) -> Result<OrphanVerdict, KubeError> {
        let still = tokio::time::timeout(
            self.client.config.request_timeout,
            self.client.jobs().get_opt(name),
        )
        .await
        .map_err(|_| KubeError::unavailable("orphan Job absence query timed out"))?
        .map_err(KubeError::from)?;
        if still.is_some() {
            let _command = self.commands.lock().await;
            self.note_run_finished(run, true).await?;
            return Err(KubeError::unavailable(
                "orphan Job deletion has not settled",
            ));
        }
        let _command = self.commands.lock().await;
        self.delete_run_residue(run).await?;
        Ok(verdict)
    }

    /// Marks finished Jobs for cleanup; deletion preserves the mark and a live restart clears it.
    pub async fn note_watched_job(&self, observation: &JobObservation) -> Result<(), KubeError> {
        let _command = self.commands.lock().await;
        let run = &observation.projection.labels.run_id;
        if adoption_in_flight(&self.journal.pending()?, run) {
            return Ok(());
        }
        let finished = match observation.workload.state {
            KubeWorkloadState::Succeeded | KubeWorkloadState::Failed => true,
            // Terminating hides Complete/Failed, so deletion alone must not change the mark.
            KubeWorkloadState::Terminating => return Ok(()),
            _ => false,
        };
        self.note_run_finished(run, finished).await
    }

    /// Retains resources if a recreated Job still carries this run label.
    pub async fn reap_watched_deletion(&self, run_label: Option<&str>) -> Result<(), KubeError> {
        let Some(label) = run_label else {
            return Ok(());
        };
        let _command = self.commands.lock().await;
        if self.job_with_run_label(label).await? {
            return Ok(());
        }
        let pending = self.journal.pending()?;
        if let Some(run) = self.run_for_label(label)? {
            if adoption_in_flight(&pending, &run) || !self.run_marked_finished(&run).await? {
                return Ok(());
            }
            return self.delete_run_residue(&run).await;
        }
        if label_adoption_in_flight(&pending, label) {
            return Ok(());
        }
        self.delete_labelled_residue(label).await
    }

    /// Lists run-labelled resources marked finished rather than scanning every registered run.
    pub async fn reap_marked_residue(&self) -> Result<(), KubeError> {
        let _command = self.commands.lock().await;
        let pending = self.journal.pending()?;
        let jobs = self.list_owned_jobs().await?;
        let mut live: BTreeSet<String> = BTreeSet::new();
        for job in &jobs {
            let Some(label) = run_label_of(&job.metadata) else {
                continue;
            };
            live.insert(label);
            // Hashed labels cannot supply the RunId; read it from the validated projection.
            let Ok(observed) = crate::status::observe_job(&self.client.config.cluster, job, 0)
            else {
                continue;
            };
            let run = observed.projection.labels.run_id;
            if adoption_in_flight(&pending, &run) {
                continue;
            }
            if job_finished(job) {
                self.note_run_finished(&run, true).await?;
            } else if job.metadata.deletion_timestamp.is_none() {
                // Clear stale finish marks on live restarts, but leave deleting Jobs unchanged.
                self.note_run_finished(&run, false).await?;
            }
        }
        let mut marked: BTreeSet<String> = BTreeSet::new();
        for claim in self.list_labelled_claims().await? {
            if finished_mark(&claim.metadata) {
                if let Some(label) = run_label_of(&claim.metadata) {
                    marked.insert(label);
                }
            }
        }
        for policy in self.list_labelled_policies().await? {
            if finished_mark(&policy.metadata) {
                if let Some(label) = run_label_of(&policy.metadata) {
                    marked.insert(label);
                }
            }
        }
        for map in self.list_labelled_maps().await? {
            if finished_mark(&map.metadata) {
                if let Some(label) = run_label_of(&map.metadata) {
                    marked.insert(label);
                }
            }
        }
        for label in marked {
            if live.contains(&label) {
                continue;
            }
            if let Some(run) = self.run_for_label(&label)? {
                if adoption_in_flight(&pending, &run) {
                    continue;
                }
                self.delete_run_residue(&run).await?;
            } else if !label_adoption_in_flight(&pending, &label) {
                self.delete_labelled_residue(&label).await?;
            }
        }
        Ok(())
    }

    async fn job_with_run_label(&self, label: &str) -> Result<bool, KubeError> {
        let selector = format!("{JOB_LABEL_RUN_ID}={label}");
        Ok(!list_bounded(
            self.client.jobs(),
            &selector,
            self.client.config.request_timeout,
        )
        .await?
        .is_empty())
    }

    async fn list_owned_jobs(&self) -> Result<Vec<Job>, KubeError> {
        list_bounded(
            self.client.jobs(),
            JOB_LABEL_RUN_ID,
            self.client.config.request_timeout,
        )
        .await
    }

    async fn list_labelled_claims(
        &self,
    ) -> Result<Vec<k8s_openapi::api::core::v1::PersistentVolumeClaim>, KubeError> {
        list_bounded(
            self.client.persistent_volume_claims(),
            JOB_LABEL_RUN_ID,
            self.client.config.request_timeout,
        )
        .await
    }

    async fn list_labelled_policies(
        &self,
    ) -> Result<Vec<k8s_openapi::api::networking::v1::NetworkPolicy>, KubeError> {
        list_bounded(
            self.client.network_policies(),
            JOB_LABEL_RUN_ID,
            self.client.config.request_timeout,
        )
        .await
    }

    async fn list_labelled_maps(
        &self,
    ) -> Result<Vec<k8s_openapi::api::core::v1::ConfigMap>, KubeError> {
        list_bounded(
            self.client.config_maps(),
            JOB_LABEL_RUN_ID,
            self.client.config.request_timeout,
        )
        .await
    }

    /// Resolves hashed labels through registered runs; unregistered labels return None.
    fn run_for_label(&self, label: &str) -> Result<Option<RunId>, KubeError> {
        if let Some(run) = run_of_label(label) {
            if self.registers_run(&run)? {
                return Ok(Some(run));
            }
        }
        for run in self.journal.registered_runs()? {
            if bounded_label_value(run.as_str()) == label {
                return Ok(Some(run));
            }
        }
        Ok(None)
    }

    // Labels allow cleanup even when the ledger has no corresponding RunId.
    async fn delete_labelled_residue(&self, label: &str) -> Result<(), KubeError> {
        let selector = format!("{JOB_LABEL_RUN_ID}={label}");
        let timeout = self.client.config.request_timeout;
        for claim in
            list_bounded(self.client.persistent_volume_claims(), &selector, timeout).await?
        {
            let Some(name) = claim.metadata.name.clone() else {
                continue;
            };
            delete_uid(
                self.client.persistent_volume_claims(),
                &name,
                claim.metadata.uid,
                timeout,
            )
            .await?;
        }
        for policy in list_bounded(self.client.network_policies(), &selector, timeout).await? {
            let Some(name) = policy.metadata.name.clone() else {
                continue;
            };
            delete_uid(
                self.client.network_policies(),
                &name,
                policy.metadata.uid,
                timeout,
            )
            .await?;
        }
        for map in list_bounded(self.client.config_maps(), &selector, timeout).await? {
            let Some(name) = map.metadata.name.clone() else {
                continue;
            };
            delete_uid(self.client.config_maps(), &name, map.metadata.uid, timeout).await?;
        }
        Ok(())
    }

    pub(super) async fn delete_run_residue(&self, run: &RunId) -> Result<(), KubeError> {
        self.delete_owned_policy(run).await?;
        self.artifacts.remove_run_maps(&self.client, run).await?;
        self.delete_owned_claim(run).await
    }
}

fn adoption_in_flight(pending: &[(String, serde_json::Value)], run: &RunId) -> bool {
    label_adoption_in_flight(pending, run.as_str())
}

fn label_adoption_in_flight(pending: &[(String, serde_json::Value)], label: &str) -> bool {
    pending.iter().any(|(kind, request)| {
        if matches!(kind.as_str(), "cancel" | "summarize") {
            return false;
        }
        let top = request.get("run_id").and_then(|value| value.as_str());
        let nested = request
            .pointer("/labels/run_id")
            .and_then(|value| value.as_str());
        top == Some(label)
            || nested == Some(label)
            || top.is_some_and(|value| bounded_label_value(value) == label)
            || nested.is_some_and(|value| bounded_label_value(value) == label)
    })
}

impl JobReconciler {
    async fn delete_owned_policy(&self, run: &RunId) -> Result<(), KubeError> {
        let name = crate::workload::egress_policy_name(run);
        let Some(policy) = tokio::time::timeout(
            self.client.config.request_timeout,
            self.client.network_policies().get_opt(&name),
        )
        .await
        .map_err(|_| KubeError::unavailable("egress policy query timed out"))?
        .map_err(KubeError::from)?
        else {
            return Ok(());
        };
        if !run_label_matches(&policy.metadata, run) {
            tracing::warn!(
                run = %run,
                "egress policy {name} is not run {}'s; left in place",
                run.as_str()
            );
            return Ok(());
        }
        delete_uid(
            self.client.network_policies(),
            &name,
            policy.metadata.uid,
            self.client.config.request_timeout,
        )
        .await
    }

    async fn delete_owned_claim(&self, run: &RunId) -> Result<(), KubeError> {
        let name = crate::workload::state_claim_name(run);
        let Some(claim) = tokio::time::timeout(
            self.client.config.request_timeout,
            self.client.persistent_volume_claims().get_opt(&name),
        )
        .await
        .map_err(|_| KubeError::unavailable("state claim query timed out"))?
        .map_err(KubeError::from)?
        else {
            return Ok(());
        };
        if !run_label_matches(&claim.metadata, run) {
            tracing::warn!(
                run = %run,
                "state claim {name} is not run {}'s; left in place",
                run.as_str()
            );
            return Ok(());
        }
        delete_uid(
            self.client.persistent_volume_claims(),
            &name,
            claim.metadata.uid,
            self.client.config.request_timeout,
        )
        .await
    }

    async fn note_run_finished(&self, run: &RunId, finished: bool) -> Result<(), KubeError> {
        let timeout = self.client.config.request_timeout;
        set_finished(
            self.client.persistent_volume_claims(),
            &crate::workload::state_claim_name(run),
            run,
            finished,
            timeout,
        )
        .await?;
        set_finished(
            self.client.network_policies(),
            &crate::workload::egress_policy_name(run),
            run,
            finished,
            timeout,
        )
        .await?;
        self.artifacts
            .set_run_maps_finished(&self.client, run, finished)
            .await
    }

    async fn run_marked_finished(&self, run: &RunId) -> Result<bool, KubeError> {
        let timeout = self.client.config.request_timeout;
        if object_marked(
            self.client.persistent_volume_claims(),
            &crate::workload::state_claim_name(run),
            run,
            timeout,
        )
        .await?
        {
            return Ok(true);
        }
        if object_marked(
            self.client.network_policies(),
            &crate::workload::egress_policy_name(run),
            run,
            timeout,
        )
        .await?
        {
            return Ok(true);
        }
        self.artifacts.run_maps_marked(&self.client, run).await
    }
}

fn run_label_matches(metadata: &ObjectMeta, run: &RunId) -> bool {
    metadata
        .labels
        .as_ref()
        .and_then(|labels| labels.get(JOB_LABEL_RUN_ID))
        .is_some_and(|value| value == &bounded_label_value(run.as_str()))
}

fn job_finished(job: &Job) -> bool {
    job.status
        .as_ref()
        .and_then(|status| status.conditions.as_ref())
        .is_some_and(|conditions| {
            conditions.iter().any(|condition| {
                condition.status == "True"
                    && matches!(condition.type_.as_str(), "Complete" | "Failed")
            })
        })
}

fn run_label_of(metadata: &ObjectMeta) -> Option<String> {
    metadata
        .labels
        .as_ref()
        .and_then(|labels| labels.get(JOB_LABEL_RUN_ID))
        .cloned()
}

fn run_of_label(label: &str) -> Option<RunId> {
    let run = RunId::new(label).ok()?;
    (bounded_label_value(run.as_str()) == label).then_some(run)
}

fn finished_mark(metadata: &ObjectMeta) -> bool {
    metadata
        .annotations
        .as_ref()
        .and_then(|annotations| annotations.get(crate::artifacts::RUN_FINISHED))
        .is_some_and(|value| value == "true")
}

async fn set_finished<T>(
    api: kube::Api<T>,
    name: &str,
    run: &RunId,
    finished: bool,
    timeout: Duration,
) -> Result<(), KubeError>
where
    T: kube::Resource<DynamicType = ()>
        + Clone
        + serde::de::DeserializeOwned
        + serde::Serialize
        + std::fmt::Debug
        + k8s_openapi::Metadata<Ty = ObjectMeta>,
{
    let Some(object) = tokio::time::timeout(timeout, api.get_opt(name))
        .await
        .map_err(|_| KubeError::unavailable(format!("{name} query timed out")))?
        .map_err(KubeError::from)?
    else {
        return Ok(());
    };
    if !run_label_matches(object.metadata(), run) || finished_mark(object.metadata()) == finished {
        return Ok(());
    }
    let patch = serde_json::json!({
        "metadata": {
            "annotations": {
                crate::artifacts::RUN_FINISHED: if finished { "true" } else { "false" }
            }
        }
    });
    match tokio::time::timeout(
        timeout,
        api.patch(name, &PatchParams::default(), &Patch::Merge(patch)),
    )
    .await
    {
        Err(_) => Err(KubeError::unavailable(format!(
            "{name} finished mark timed out"
        ))),
        Ok(Ok(_)) => Ok(()),
        Ok(Err(kube::Error::Api(status))) if status.code == 404 => Ok(()),
        Ok(Err(kube::Error::Api(status))) if status.code == 409 => Err(KubeError::Conflict {
            reason: format!("{name} changed during the finished mark"),
        }),
        Ok(Err(error)) => Err(error.into()),
    }
}

async fn object_marked<T>(
    api: kube::Api<T>,
    name: &str,
    run: &RunId,
    timeout: Duration,
) -> Result<bool, KubeError>
where
    T: kube::Resource<DynamicType = ()>
        + Clone
        + serde::de::DeserializeOwned
        + std::fmt::Debug
        + k8s_openapi::Metadata<Ty = ObjectMeta>,
{
    let Some(object) = tokio::time::timeout(timeout, api.get_opt(name))
        .await
        .map_err(|_| KubeError::unavailable(format!("{name} query timed out")))?
        .map_err(KubeError::from)?
    else {
        return Ok(false);
    };
    Ok(run_label_matches(object.metadata(), run) && finished_mark(object.metadata()))
}

async fn list_bounded<T>(
    api: kube::Api<T>,
    selector: &str,
    timeout: Duration,
) -> Result<Vec<T>, KubeError>
where
    T: kube::Resource<DynamicType = ()>
        + Clone
        + serde::de::DeserializeOwned
        + std::fmt::Debug
        + k8s_openapi::Metadata<Ty = ObjectMeta>,
{
    let params = kube::api::ListParams::default()
        .labels(selector)
        .limit(1024);
    let page = tokio::time::timeout(timeout, api.list(&params))
        .await
        .map_err(|_| KubeError::unavailable("labelled residue list timed out"))?
        .map_err(KubeError::from)?;
    if page
        .metadata
        .continue_
        .as_ref()
        .is_some_and(|token| !token.is_empty())
    {
        return Err(KubeError::unavailable(
            "labelled residue list exceeded its bound",
        ));
    }
    Ok(page.items)
}

async fn delete_uid<T>(
    api: kube::Api<T>,
    name: &str,
    uid: Option<String>,
    timeout: Duration,
) -> Result<(), KubeError>
where
    T: kube::Resource + Clone + serde::de::DeserializeOwned + std::fmt::Debug,
{
    let params = DeleteParams {
        preconditions: Some(Preconditions {
            uid,
            resource_version: None,
        }),
        ..Default::default()
    };
    match tokio::time::timeout(timeout, api.delete(name, &params)).await {
        Err(_) => Err(KubeError::unavailable(format!("{name} deletion timed out"))),
        Ok(Ok(_)) => Ok(()),
        Ok(Err(kube::Error::Api(status))) if status.code == 404 || status.code == 409 => Ok(()),
        Ok(Err(error)) => Err(error.into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use KubeWorkloadState::*;

    fn hours_ago(now: OffsetDateTime, hours: i64) -> Option<OffsetDateTime> {
        Some(now - time::Duration::hours(hours))
    }

    #[test]
    fn abandoned_orphans_are_collected_and_young_ones_left_alone() {
        let now = OffsetDateTime::now_utc();
        let verdict = |registered, own, state, started, finished| {
            orphan_verdict(registered, own, state, started, finished, now)
        };
        assert_eq!(
            verdict(
                false,
                true,
                Succeeded,
                hours_ago(now, 34),
                hours_ago(now, 34)
            ),
            OrphanVerdict::Collect
        );
        assert_eq!(
            verdict(false, true, Running, hours_ago(now, 31), None),
            OrphanVerdict::Collect
        );
        assert_eq!(
            verdict(
                false,
                true,
                Failed,
                hours_ago(now, 2),
                Some(now - time::Duration::minutes(10))
            ),
            OrphanVerdict::NotDue
        );
        assert_eq!(
            verdict(false, true, Running, hours_ago(now, 3), None),
            OrphanVerdict::NotDue
        );
        assert_eq!(
            verdict(false, true, Pending, None, None),
            OrphanVerdict::NotDue
        );
        assert_eq!(
            verdict(
                false,
                false,
                Succeeded,
                hours_ago(now, 34),
                hours_ago(now, 34)
            ),
            OrphanVerdict::NotDue
        );
        assert_eq!(
            verdict(
                true,
                true,
                Succeeded,
                hours_ago(now, 34),
                hours_ago(now, 34)
            ),
            OrphanVerdict::Registered
        );
    }
}
