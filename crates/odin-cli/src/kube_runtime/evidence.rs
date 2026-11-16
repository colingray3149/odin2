//! Evidence projection: the published capability wire contracts, the
//! settlement projection, and the evidence extractors.

use odin_domain::huginn::{KubeResourceOwnership, KubeWorkloadState};
use odin_kube::JobObservation;
use odin_omp::host_tools::HostToolError;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::admission::{arguments_error, decode_arguments, storage_error};

// ---------------------------------------------------------------------------
// Wire contracts: exactly the published capability output schemas.
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub(super) enum MutationStatus {
    Accepted,
    Duplicate,
    Unavailable,
    Queued,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub(super) enum ReadStatus {
    Ok,
    Unavailable,
}

/// `kube.workload.{create,pause,resume,restart,cancel}.output`:
/// accepted/duplicate bind jobName and resourceVersion; unavailable carries a
/// typed reason.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct MutationOutput {
    status: MutationStatus,
    pub(super) run_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    operation_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    worker_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    job_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    resource_version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    reason: Option<String>,
    /// A pause's checkpoint: the artifact holding the pod's state.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    checkpoint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    checkpoint_bytes: Option<u64>,
    /// What becomes of an agent pod's answer, so its launcher ends its turn
    /// instead of waiting in it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    report: Option<String>,
}

// Agent pods report asynchronously, so their launchers should not wait in the current turn.
pub(super) const AGENT_POD_REPORT: &str = "This agent pod's final answer is reported to \
     the owner's conversation when it finishes, and its pod is released then. End your turn now: \
     do not wait for it, poll it or stop it.";

impl MutationOutput {
    /// Names what becomes of an agent pod's answer.
    pub(super) fn with_report(mut self, report: &str) -> Self {
        self.report = Some(report.to_owned());
        self
    }

    /// Records the checkpoint a paused pod's state was captured into.
    pub(super) fn with_checkpoint(mut self, artifact: String, bytes: u64) -> Self {
        self.checkpoint = Some(artifact);
        self.checkpoint_bytes = Some(bytes);
        self
    }

    /// The schema's conditional requirements, enforced beyond serde shape.
    fn validate(&self) -> Result<(), String> {
        match self.status {
            MutationStatus::Unavailable | MutationStatus::Queued => {
                if self.reason.as_deref().unwrap_or_default().is_empty() {
                    return Err(
                        "an unavailable or queued settlement requires a typed reason".to_owned(),
                    );
                }
            }
            MutationStatus::Accepted | MutationStatus::Duplicate => {
                if self.job_name.as_deref().unwrap_or_default().is_empty()
                    || self
                        .resource_version
                        .as_deref()
                        .unwrap_or_default()
                        .is_empty()
                {
                    return Err(
                        "an accepted or duplicate settlement binds jobName and resourceVersion"
                            .to_owned(),
                    );
                }
            }
        }
        Ok(())
    }
}

/// `kube.workload.summarize.output`: ok carries one bounded row per run.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct SummarizeOutput {
    pub(super) status: ReadStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) runs: Option<Vec<SummarizeRun>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) reason: Option<String>,
}

impl SummarizeOutput {
    fn validate(&self) -> Result<(), String> {
        match self.status {
            ReadStatus::Ok => {
                if self.runs.is_none() {
                    return Err("an ok summary carries the runs array".to_owned());
                }
            }
            ReadStatus::Unavailable => {
                if self.reason.as_deref().unwrap_or_default().is_empty() {
                    return Err("an unavailable summary requires a typed reason".to_owned());
                }
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct SummarizeRun {
    run_id: String,
    job_name: String,
    state: String,
    resource_version: String,
    /// The declared pod profile (its workload label), so a seat finds "the
    /// heartbeat pod" without guessing which run it is.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    profile: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) node: Option<String>,
    /// The seat that launched it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    seat: Option<String>,
    /// When it started and finished (RFC 3339 UTC); sorts newest first.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) started_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    finished_at: Option<String>,
    /// A running pod's status delta: its newest `ODIN-STATUS` against the
    /// one before — what a seat reads instead of the log.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) status: Option<String>,
    /// The tail of its newest pod's log, redacted, when the read asked for it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) log: Option<Vec<String>>,
}

/// `kube.snapshot.read.output`: ok carries the wire projection (null when the
/// run has no cluster workload yet).
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct SnapshotOutput {
    pub(super) status: ReadStatus,
    /// Successful snapshots require this field even when null. Preserve presence
    /// during deserialization because plain `Option` conflates null and absence.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_present_projection"
    )]
    pub(super) projection: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) lanes: Option<Vec<Value>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) reason: Option<String>,
}

/// Deserializes the projection field preserving the wire distinction
/// between an absent field (`None`) and a present null (`Some(null)`): the
/// schema's ok branch requires the field and its value may legitimately be
/// null when the bound run has no cluster workload yet.
fn deserialize_present_projection<'de, D>(deserializer: D) -> Result<Option<Value>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Option::<Value>::deserialize(deserializer).map(|value| Some(value.unwrap_or(Value::Null)))
}

impl SnapshotOutput {
    fn validate(&self) -> Result<(), String> {
        match self.status {
            ReadStatus::Ok => {
                if self.projection.is_none() {
                    return Err("an ok snapshot carries the projection field".to_owned());
                }
            }

            ReadStatus::Unavailable => {
                if self.reason.as_deref().unwrap_or_default().is_empty() {
                    return Err("an unavailable snapshot requires a typed reason".to_owned());
                }
            }
        }
        Ok(())
    }
}

/// `kube.health.read.output`: ok carries the cluster health observation
/// exactly as read (empty arrays are real observations from a reachable
/// cluster, never an inferred-healthy placeholder).
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct HealthOutput {
    pub(super) status: ReadStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) health: Option<odin_domain::huginn::KubeClusterHealth>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) reason: Option<String>,
}

impl HealthOutput {
    fn validate(&self) -> Result<(), String> {
        match self.status {
            ReadStatus::Ok => {
                let Some(health) = self.health.as_ref() else {
                    return Err("an ok health read carries the health observation".to_owned());
                };
                if health.cluster.trim().is_empty() {
                    return Err("an ok health read names its cluster".to_owned());
                }
            }
            ReadStatus::Unavailable => {
                if self.reason.as_deref().unwrap_or_default().is_empty() {
                    return Err("an unavailable health read requires a typed reason".to_owned());
                }
            }
        }
        Ok(())
    }
}

pub(super) fn summarize_unavailable(reason: String) -> Value {
    serde_json::to_value(SummarizeOutput {
        status: ReadStatus::Unavailable,
        runs: None,
        reason: Some(reason),
    })
    .unwrap_or(Value::Null)
}

pub(super) fn snapshot_unavailable(reason: String) -> Value {
    serde_json::to_value(SnapshotOutput {
        status: ReadStatus::Unavailable,
        projection: None,
        lanes: None,
        reason: Some(reason),
    })
    .unwrap_or(Value::Null)
}

pub(super) fn health_unavailable(reason: String) -> Value {
    serde_json::to_value(HealthOutput {
        status: ReadStatus::Unavailable,
        health: None,
        reason: Some(reason),
    })
    .unwrap_or(Value::Null)
}

/// The settlement record bound to the exact post-mutation cluster object.
pub(super) fn mutation_settlement(
    status: MutationStatus,
    run_id: &str,
    operation_id: &str,
    observation: &JobObservation,
) -> MutationOutput {
    MutationOutput {
        status,
        run_id: run_id.to_owned(),
        operation_id: Some(operation_id.to_owned()),
        worker_id: Some(observation.projection.worker.worker_id.as_str().to_owned()),
        job_name: Some(observation.workload.resource.name.clone()),
        resource_version: Some(
            observation
                .projection
                .identity
                .resource_version
                .as_str()
                .to_owned(),
        ),
        reason: None,
        checkpoint: None,
        checkpoint_bytes: None,
        report: None,
    }
}

/// Nothing was created: no node had room, so the launch waits in the launch queue.
pub(super) fn queued_settlement(run_id: &str, operation_id: &str) -> MutationOutput {
    MutationOutput {
        status: MutationStatus::Queued,
        run_id: run_id.to_owned(),
        operation_id: Some(operation_id.to_owned()),
        worker_id: None,
        job_name: None,
        resource_version: None,
        reason: Some(
            "this pod cannot start now (no node has room, or for a batch item its seat or lane \
             pod cap is full), so it is queued; it starts when a running pod ends, and the \
             session that launched it is told how it went"
                .to_owned(),
        ),
        checkpoint: None,
        checkpoint_bytes: None,
        report: None,
    }
}

/// An offload run's settlement: the run on its compute target, named by its folder there.
pub(super) fn offload_settlement(
    status: MutationStatus,
    operation_id: &str,
    run: &crate::live::offload::OffloadRun,
) -> MutationOutput {
    MutationOutput {
        status,
        run_id: run.run_id.as_str().to_owned(),
        operation_id: Some(operation_id.to_owned()),
        worker_id: None,
        job_name: Some(run.name.clone()),
        // An offload run has no cluster object: the target's own job (the Slurm id or the
        // transient systemd unit) is what the settlement binds.
        resource_version: Some(run.job.clone()),
        reason: Some(format!(
            "offload run on compute target {} (job {}), {:?}",
            run.target, run.job, run.state
        )),
        checkpoint: None,
        checkpoint_bytes: None,
        report: None,
    }
}

/// The summary row of an offload run, read from the offload journal: it has no Job to observe.
pub(super) fn offload_summarize_row(run: &crate::live::offload::OffloadRun) -> SummarizeRun {
    SummarizeRun {
        run_id: run.run_id.as_str().to_owned(),
        job_name: run.name.clone(),
        state: state_name(run.workload_state()),
        resource_version: run.job.clone(),
        profile: Some(run.profile.clone()),
        node: run.node_id().map(|node| node.to_string()),
        seat: run.seat_id.as_ref().map(ToString::to_string),
        started_at: run.started_at.and_then(rfc3339),
        finished_at: run.finished_at.and_then(rfc3339),
        status: None,
        log: None,
    }
}

pub(super) fn summarize_row(
    tool: &'static str,
    observation: &JobObservation,
) -> Result<SummarizeRun, HostToolError> {
    let state: KubeWorkloadState = observation.workload.state;
    let run_id = match &observation.workload.ownership {
        KubeResourceOwnership::Odin { run_id, .. } => run_id.to_string(),
        KubeResourceOwnership::Foreign => {
            return Err(storage_error(
                tool,
                "a foreign workload cannot be summarized",
            ));
        }
    };
    Ok(SummarizeRun {
        run_id,
        job_name: observation.workload.resource.name.clone(),
        state: state_name(state),
        resource_version: observation
            .projection
            .identity
            .resource_version
            .as_str()
            .to_owned(),
        profile: observation.workload.profile.clone(),
        node: observation
            .workload
            .node_id
            .as_ref()
            .map(ToString::to_string),
        seat: Some(observation.projection.labels.seat_id.to_string()),
        started_at: observation.workload.started_at.and_then(rfc3339),
        finished_at: observation.workload.finished_at.and_then(rfc3339),
        status: None,
        log: None,
    })
}

fn rfc3339(at: time::OffsetDateTime) -> Option<String> {
    at.format(&time::format_description::well_known::Rfc3339)
        .ok()
}

/// The workload state's exact wire name (`running`, `suspended`, ...).
fn state_name(state: KubeWorkloadState) -> String {
    serde_json::to_value(state)
        .ok()
        .and_then(|name| name.as_str().map(str::to_owned))
        .unwrap_or_default()
}

pub(super) fn serialize_value<T: Serialize>(
    tool: &'static str,
    value: &T,
    detail: &str,
) -> Result<Value, HostToolError> {
    serde_json::to_value(value).map_err(|error| storage_error(tool, format!("{detail}: {error}")))
}

pub(super) fn serialize_output<T: Serialize>(
    tool: &'static str,
    output: &T,
) -> Result<Value, HostToolError> {
    serialize_value(tool, output, "cannot serialize the settlement")
}

// ---------------------------------------------------------------------------
// Evidence extraction: the validated handler output, never re-executed.
// ---------------------------------------------------------------------------

/// Evidence extractor input: the validated handler output, never re-executed.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct EvidenceInput {
    output: Value,
}

pub(super) fn extract_mutation_evidence(
    tool: &'static str,
    arguments: Value,
) -> Result<Value, HostToolError> {
    let input: EvidenceInput = decode_arguments(tool, arguments)?;
    let output: MutationOutput = serde_json::from_value(input.output)
        .map_err(|error| arguments_error(tool, format!("invalid mutation output: {error}")))?;
    output
        .validate()
        .map_err(|detail| arguments_error(tool, detail))?;
    serialize_output(tool, &output)
}

pub(super) fn extract_summarize_evidence(
    tool: &'static str,
    arguments: Value,
) -> Result<Value, HostToolError> {
    let input: EvidenceInput = decode_arguments(tool, arguments)?;
    let output: SummarizeOutput = serde_json::from_value(input.output)
        .map_err(|error| arguments_error(tool, format!("invalid summarize output: {error}")))?;
    output
        .validate()
        .map_err(|detail| arguments_error(tool, detail))?;
    serialize_output(tool, &output)
}

pub(super) fn extract_snapshot_evidence(
    tool: &'static str,
    arguments: Value,
) -> Result<Value, HostToolError> {
    let input: EvidenceInput = decode_arguments(tool, arguments)?;
    let output: SnapshotOutput = serde_json::from_value(input.output)
        .map_err(|error| arguments_error(tool, format!("invalid snapshot output: {error}")))?;
    output
        .validate()
        .map_err(|detail| arguments_error(tool, detail))?;
    serialize_output(tool, &output)
}

pub(super) fn extract_health_evidence(
    tool: &'static str,
    arguments: Value,
) -> Result<Value, HostToolError> {
    let input: EvidenceInput = decode_arguments(tool, arguments)?;
    let output: HealthOutput = serde_json::from_value(input.output)
        .map_err(|error| arguments_error(tool, format!("invalid health output: {error}")))?;
    output
        .validate()
        .map_err(|detail| arguments_error(tool, detail))?;
    serialize_output(tool, &output)
}

#[cfg(test)]
mod snapshot_evidence_tests {
    use super::*;

    fn extract(output: serde_json::Value) -> Result<serde_json::Value, HostToolError> {
        extract_snapshot_evidence(
            "kube_snapshot_read",
            serde_json::json!({ "output": output }),
        )
    }

    #[test]
    fn snapshot_evidence_accepts_a_present_null_projection() {
        let evidence = extract(serde_json::json!({
            "status": "ok",
            "projection": null,
        }))
        .expect("an ok snapshot with a present null projection is lawful");
        assert_eq!(
            evidence,
            serde_json::json!({ "status": "ok", "projection": null }),
            "the relayed evidence keeps the projection field explicitly null"
        );
    }

    #[test]
    fn snapshot_evidence_preserves_lane_compute_budgets() {
        let output = serde_json::json!({
            "status": "ok", "projection": null,
            "lanes": [{"lane": "sweep", "windowDays": 7,
                "coreHours": {"used": 2.5, "cap": 10},
                "gpuHours": {"used": 1.0, "cap": null},
                "computeUsd": {"used": 0.5, "cap": 20}}]
        });
        assert_eq!(extract(output.clone()).unwrap(), output);
    }
}

#[cfg(test)]
mod health_evidence_tests {
    use super::*;

    fn extract(output: serde_json::Value) -> Result<serde_json::Value, HostToolError> {
        extract_health_evidence("kube_health_read", serde_json::json!({ "output": output }))
    }

    /// The governing rule for this read: an ok health observation with
    /// empty arrays is REAL data from a reachable cluster (no nodes, no
    /// problem pods, no warnings) and must survive the evidence relay —
    /// it is never treated as absence of an observation.
    #[test]
    fn health_evidence_accepts_an_ok_observation_with_empty_arrays() {
        let evidence = extract(serde_json::json!({
            "status": "ok",
            "health": {
                "cluster": "default",
                "observedAt": "2026-09-15T15:00:00Z",
                "nodes": [],
                "podsObserved": 12,
                "podProblems": [],
                "warningEvents": []
            }
        }))
        .expect("an ok health read with empty arrays is a real observation");
        assert_eq!(
            evidence,
            serde_json::json!({
                "status": "ok",
                "health": {
                    "cluster": "default",
                    "observedAt": "2026-09-15T15:00:00Z",
                    "nodes": [],
                    "podsObserved": 12,
                    "podProblems": [],
                    "warningEvents": []
                }
            }),
            "the relayed evidence preserves the observation verbatim"
        );
    }
}

#[cfg(test)]
mod mutation_evidence_tests {
    use super::*;

    fn extract(output: serde_json::Value) -> Result<serde_json::Value, HostToolError> {
        extract_mutation_evidence(
            "kube_workload_pause",
            serde_json::json!({ "output": output }),
        )
    }

    #[test]
    fn a_settlement_binds_its_job_or_names_why_it_did_not_happen() {
        let accepted = serde_json::json!({
            "status": "accepted",
            "runId": "run.a",
            "jobName": "odin-run-a",
            "resourceVersion": "17",
        });
        assert_eq!(
            extract(accepted.clone()).expect("a bound settlement")["jobName"],
            "odin-run-a"
        );

        let mut unbound = accepted.clone();
        unbound["jobName"] = serde_json::Value::Null;
        assert!(extract(unbound).is_err(), "accepted without its job");

        let unavailable = serde_json::json!({ "status": "unavailable", "runId": "run.a" });
        assert!(
            extract(unavailable.clone()).is_err(),
            "unavailable without a reason"
        );
        let mut explained = unavailable;
        explained["reason"] = "the cluster is not configured".into();
        assert!(extract(explained).is_ok());
    }

    /// An offload create has no Job: it binds the run's folder and the target's own job, so its
    /// settlement passes the create evidence and the run lists like a pod.
    #[test]
    fn an_offload_settlement_binds_its_target_job_and_lists() {
        let run: crate::live::offload::OffloadRun = serde_json::from_value(serde_json::json!({
            "run_id": "run.offload", "profile": "stub", "target": "mini",
            "name": "run-offload", "remote_dir": "/tmp/odin/run-offload",
            "job": "odin-offload-run-offload.service", "state": "running",
            "submitted_at": serde_json::to_value(time::OffsetDateTime::UNIX_EPOCH).unwrap(),
            "export_host_folder": "/srv/odin/export",
        }))
        .expect("an offload run");
        let settled = serialize_output(
            "kube_workload_create",
            &offload_settlement(MutationStatus::Accepted, "op-1", &run),
        )
        .expect("the settlement serializes");
        let evidence = extract_mutation_evidence(
            "kube_workload_create",
            serde_json::json!({ "output": settled }),
        )
        .expect("an offload create settles with evidence");
        assert_eq!(evidence["jobName"], run.name.as_str());
        assert_eq!(evidence["resourceVersion"], run.job.as_str());

        let row = serde_json::to_value(offload_summarize_row(&run)).unwrap();
        assert_eq!(row["runId"], "run.offload");
        assert_eq!(row["state"], "running");
        assert_eq!(row["resourceVersion"], run.job.as_str());
    }
}
