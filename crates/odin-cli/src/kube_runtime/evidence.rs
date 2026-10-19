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
     Colin's conversation when it finishes, and its pod is released then. End your turn now: \
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
            MutationStatus::Unavailable => {
                if self.reason.as_deref().unwrap_or_default().is_empty() {
                    return Err("an unavailable settlement requires a typed reason".to_owned());
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
    tool: &'static str,
    status: MutationStatus,
    run_id: &str,
    operation_id: &str,
    observation: &JobObservation,
) -> Result<MutationOutput, HostToolError> {
    let _ = tool;
    Ok(MutationOutput {
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
    })
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
    })
}

fn rfc3339(at: time::OffsetDateTime) -> Option<String> {
    at.format(&time::format_description::well_known::Rfc3339)
        .ok()
}

/// The workload state's exact wire name (`running`, `suspended`, ...).
fn state_name(state: KubeWorkloadState) -> String {
    match state {
        KubeWorkloadState::Pending => "pending".to_owned(),
        KubeWorkloadState::Scheduling => "scheduling".to_owned(),
        KubeWorkloadState::Running => "running".to_owned(),
        KubeWorkloadState::Succeeded => "succeeded".to_owned(),
        KubeWorkloadState::Failed => "failed".to_owned(),
        KubeWorkloadState::Suspended => "suspended".to_owned(),
        KubeWorkloadState::Terminating => "terminating".to_owned(),
        KubeWorkloadState::Unknown => "unknown".to_owned(),
    }
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
    fn snapshot_evidence_still_refuses_an_absent_projection() {
        let error = extract(serde_json::json!({ "status": "ok" }))
            .expect_err("an ok snapshot without the projection field is invalid");
        assert!(
            error
                .to_string()
                .contains("an ok snapshot carries the projection field"),
            "the negative stays refused, got {error:?}"
        );
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

    #[test]
    fn health_evidence_refuses_an_ok_read_without_the_observation() {
        let error = extract(serde_json::json!({ "status": "ok" }))
            .expect_err("an ok health read without the health object is invalid");
        assert!(
            error
                .to_string()
                .contains("an ok health read carries the health observation"),
            "the negative stays refused, got {error:?}"
        );
    }

    #[test]
    fn health_evidence_refuses_an_unavailable_read_without_a_reason() {
        let error = extract(serde_json::json!({ "status": "unavailable" }))
            .expect_err("an unavailable health read requires a typed reason");
        assert!(
            error
                .to_string()
                .contains("an unavailable health read requires a typed reason"),
            "the negative stays refused, got {error:?}"
        );
    }

    #[test]
    fn health_evidence_rejects_unknown_fields_on_the_settlement() {
        let error = extract(serde_json::json!({
            "status": "ok",
            "health": {
                "cluster": "default",
                "observedAt": "2026-09-15T15:00:00Z",
                "nodes": [],
                "podsObserved": 0,
                "podProblems": [],
                "warningEvents": []
            },
            "projection": null
        }))
        .expect_err("an unknown settlement field is refused");
        assert!(
            error.to_string().contains("invalid health output"),
            "the wire contract stays strict, got {error:?}"
        );
    }
}
