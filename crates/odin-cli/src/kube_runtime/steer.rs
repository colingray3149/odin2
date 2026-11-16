//! `kube.workload.steer`: one schema-checked control document written to a running pod's
//! control map. The schema is the copy admitted with the run's launch, so a later profile
//! edit never changes what a running pod accepts.

use odin_domain::RunId;
use odin_kube::KubeError;
use odin_omp::host_tools::{HostInvocation, HostToolError};
use odin_types::OperationId;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::admission::{arguments_error, decode_arguments, kube_failure, require_kube_seat_scope};
use super::evidence::serialize_output;
use super::KubeCommandCoordinator;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct SteerInput {
    run_id: String,
    expected_seq: u64,
    document: Value,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
enum SteerStatus {
    Accepted,
    Duplicate,
    Unavailable,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct SteerOutput {
    status: SteerStatus,
    run_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    operation_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    seq: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    reason: Option<String>,
}

/// The run, its admitted control declaration, and the checked document.
struct Admitted {
    run_id: RunId,
    expected_seq: u64,
    document: Value,
}

/// Refuses a document the run's admitted schema does not allow, or a run without control.
fn admit_document(
    tool: &'static str,
    run_id: &RunId,
    control: Option<&odin_registry::WorkloadControlToml>,
    document: &Value,
) -> Result<(), HostToolError> {
    let control = control.ok_or_else(|| {
        arguments_error(
            tool,
            format!("run {run_id} declares no [control]; nothing can steer it"),
        )
    })?;
    control
        .admit(document)
        .map_err(|reason| arguments_error(tool, format!("run {run_id}: {reason}")))
}

impl KubeCommandCoordinator {
    fn admit_steer(
        &self,
        tool: &'static str,
        invocation: &HostInvocation,
    ) -> Result<Admitted, HostToolError> {
        let seat = require_kube_seat_scope(tool, &invocation.scope)?;
        let input: SteerInput = decode_arguments(tool, invocation.arguments.clone())?;
        let run_id = RunId::new(input.run_id)
            .map_err(|error| arguments_error(tool, format!("invalid runId: {error}")))?;
        if let Some(run) = self
            .offload
            .as_ref()
            .and_then(|offload| offload.run(&run_id))
        {
            let visible = self.overseers.contains(&seat)
                || run.seat_id.as_ref() == Some(&seat)
                || (run.project_id.is_some() && invocation.scope.project == run.project_id);
            if !visible {
                return Err(arguments_error(
                    tool,
                    format!("run {run_id} is neither yours nor your project's"),
                ));
            }
            admit_document(tool, &run_id, run.control.as_ref(), &input.document)?;
            return Ok(Admitted {
                run_id,
                expected_seq: input.expected_seq,
                document: input.document,
            });
        }
        let cell = self
            .runtime_cell
            .as_ref()
            .ok_or(HostToolError::Unavailable {
                tool,
                reason: "the kube surface is not configured".to_owned(),
            })?;
        let config = cell.kube_config();
        let launch =
            odin_kube::stored_launch(&cell.ledger(), &config.cluster, &config.namespace, &run_id)
                .map_err(|error| kube_failure(tool, error))?;
        // The same visibility summarize gives: the seat's own pods and its project's.
        if let Some(labels) = launch.as_ref().map(|launch| &launch.labels) {
            let visible = self.overseers.contains(&seat)
                || labels.seat_id == seat
                || invocation.scope.project.as_ref() == Some(&labels.project_id);
            if !visible {
                return Err(arguments_error(
                    tool,
                    format!("run {run_id} is neither yours nor your project's"),
                ));
            }
        }
        let control = launch
            .as_ref()
            .and_then(|launch| launch.workload.as_ref())
            .and_then(|plan| plan.control.as_ref());
        admit_document(tool, &run_id, control, &input.document)?;
        Ok(Admitted {
            run_id,
            expected_seq: input.expected_seq,
            document: input.document,
        })
    }

    pub(super) fn preflight_steer(
        &self,
        tool: &'static str,
        invocation: HostInvocation,
    ) -> Result<(), HostToolError> {
        self.admit_steer(tool, &invocation).map(|_| ())
    }

    pub(super) async fn steer(
        &self,
        tool: &'static str,
        operation_id: OperationId,
        invocation: HostInvocation,
    ) -> Result<Value, HostToolError> {
        let Admitted {
            run_id,
            expected_seq,
            document,
        } = self.admit_steer(tool, &invocation)?;
        if let Some((offload, run)) = self
            .offload
            .as_ref()
            .and_then(|offload| offload.run(&run_id).map(|run| (offload, run)))
        {
            let by = invocation
                .scope
                .seat
                .as_ref()
                .map_or("odin".to_owned(), ToString::to_string);
            return match offload
                .steer(&run, expected_seq, document, operation_id.as_str(), &by)
                .await
            {
                Ok(applied) => serialize_output(
                    tool,
                    &SteerOutput {
                        status: if applied.duplicate {
                            SteerStatus::Duplicate
                        } else {
                            SteerStatus::Accepted
                        },
                        run_id: run_id.to_string(),
                        operation_id: Some(operation_id.to_string()),
                        seq: Some(applied.seq),
                        reason: None,
                    },
                ),
                Err(reason) => serialize_output(
                    tool,
                    &SteerOutput {
                        status: SteerStatus::Unavailable,
                        run_id: run_id.to_string(),
                        operation_id: Some(operation_id.to_string()),
                        seq: None,
                        reason: Some(reason),
                    },
                ),
            };
        }
        let control = match self.resolve_control() {
            Ok((control, _)) => control,
            Err(reason) => {
                return serialize_output(
                    tool,
                    &SteerOutput {
                        status: SteerStatus::Unavailable,
                        run_id: run_id.to_string(),
                        operation_id: Some(operation_id.to_string()),
                        seq: None,
                        reason: Some(reason),
                    },
                )
            }
        };
        let by = invocation
            .scope
            .seat
            .as_ref()
            .map_or("odin".to_owned(), ToString::to_string);
        match control
            .reconciler()
            .steer_control(&run_id, expected_seq, document, operation_id.as_str(), &by)
            .await
        {
            Ok(applied) => serialize_output(
                tool,
                &SteerOutput {
                    status: if applied.duplicate {
                        SteerStatus::Duplicate
                    } else {
                        SteerStatus::Accepted
                    },
                    run_id: run_id.to_string(),
                    operation_id: Some(operation_id.to_string()),
                    seq: Some(applied.seq),
                    reason: None,
                },
            ),
            Err(KubeError::Unavailable { reason }) => serialize_output(
                tool,
                &SteerOutput {
                    status: SteerStatus::Unavailable,
                    run_id: run_id.to_string(),
                    operation_id: Some(operation_id.to_string()),
                    seq: None,
                    reason: Some(reason),
                },
            ),
            Err(error) => Err(kube_failure(tool, error)),
        }
    }
}

pub(super) fn extract_steer_evidence(
    tool: &'static str,
    arguments: Value,
) -> Result<Value, HostToolError> {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct EvidenceInput {
        output: Value,
    }
    let input: EvidenceInput = decode_arguments(tool, arguments)?;
    let output: SteerOutput = serde_json::from_value(input.output)
        .map_err(|error| arguments_error(tool, format!("invalid steer output: {error}")))?;
    let settled = matches!(
        output.status,
        SteerStatus::Accepted | SteerStatus::Duplicate
    );
    if settled != output.seq.is_some()
        || (output.status == SteerStatus::Unavailable) != output.reason.is_some()
    {
        return Err(arguments_error(
            tool,
            "steer output fields disagree with its status",
        ));
    }
    serialize_output(tool, &output)
}

#[cfg(test)]
mod tests;
