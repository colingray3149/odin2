//! Validation and durable enqueue of a batch of workload launches.
use odin_domain::Scope;
use odin_omp::host_tools::{HostInvocation, HostToolError};
use odin_types::OperationId;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use super::admission::{
    arguments_error, decode_arguments, require_kube_seat_scope, validate_run_label,
};
use super::execution::validate_input_artifacts;
use super::launch_queue::QueuedLaunch;
use super::KubeCommandCoordinator;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct BatchInput {
    profile: String,
    #[serde(default)]
    campaign_id: Option<String>,
    items: Vec<BatchItem>,
    #[serde(default)]
    target_node: Option<String>,
    #[serde(default)]
    limits: Option<Value>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BatchItem {
    label: String,
    #[serde(default)]
    prompt: Option<String>,
    #[serde(default)]
    inputs: Vec<String>,
}

fn validate_items(
    tool: &'static str,
    items: &[BatchItem],
    max_launches: u32,
    max_inputs: u32,
) -> Result<(), HostToolError> {
    if items.is_empty() || items.len() as u64 > u64::from(max_launches) {
        return Err(arguments_error(
            tool,
            format!("items must contain between 1 and {max_launches} launches"),
        ));
    }
    for item in items {
        validate_run_label(tool, Some(&item.label))?;
        if item.prompt.as_ref().is_some_and(|p| p.trim().is_empty())
            || (item.prompt.is_some() && !item.inputs.is_empty())
        {
            return Err(arguments_error(
                tool,
                "each item takes a nonempty prompt or inputs, not both",
            ));
        }
        validate_input_count(tool, item.inputs.len(), max_inputs)?;
    }
    Ok(())
}

fn validate_campaign_item(tool: &'static str, item: &BatchItem) -> Result<(), HostToolError> {
    if item.inputs.is_empty() || item.prompt.is_some() {
        return Err(arguments_error(
            tool,
            "campaign items require a stage manifest as their first input",
        ));
    }
    Ok(())
}

pub(super) fn validate_input_count(
    tool: &'static str,
    count: usize,
    max_inputs: u32,
) -> Result<(), HostToolError> {
    if count as u64 > u64::from(max_inputs) {
        return Err(arguments_error(
            tool,
            format!("inputs must contain at most {max_inputs} artifacts"),
        ));
    }
    Ok(())
}

pub(super) fn seat_batch_limits(
    snapshot: &odin_registry::Snapshot,
    seat: &odin_domain::SeatId,
) -> (u32, u32) {
    snapshot
        .object(odin_registry::RegistryKind::Seat, seat.as_str())
        .and_then(|object| match &object.config {
            odin_registry::ObjectConfig::Seat(seat) => {
                Some((seat.limits.max_batch_launches, seat.limits.max_batch_inputs))
            }
            _ => None,
        })
        .unwrap_or((256, 16))
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct BatchOutput {
    batch: String,
    items: Vec<BatchResult>,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct BatchResult {
    label: String,
    operation: String,
    status: String,
}

struct ValidatedBatch {
    items: Vec<(String, Value)>,
    campaign: Option<String>,
    node: Option<String>,
    core_hours: Option<f64>,
}

impl KubeCommandCoordinator {
    fn validate_batch(
        &self,
        tool: &'static str,
        scope: &Scope,
        arguments: &Value,
    ) -> Result<ValidatedBatch, HostToolError> {
        let seat = require_kube_seat_scope(tool, scope)?;
        let input: BatchInput = decode_arguments(tool, arguments.clone())?;
        if input
            .campaign_id
            .as_deref()
            .is_some_and(|id| id.trim().is_empty())
        {
            return Err(arguments_error(tool, "campaignId must not be empty"));
        }
        let resolution = self
            .workload_port()
            .map(|port| port.resolve_launch(&input.profile));
        let requires_campaign = match &resolution {
            Some(super::WorkloadResolve::Script(inputs)) => {
                inputs.profile.profile.require_campaign_approval
            }
            Some(super::WorkloadResolve::Launch(inputs)) => {
                inputs.profile.profile.require_campaign_approval
            }
            _ => false,
        };
        if requires_campaign && input.campaign_id.is_none() {
            return Err(arguments_error(
                tool,
                "this workload profile requires campaignId",
            ));
        }
        let core_hours = if input.campaign_id.is_some() {
            self.ensure_campaign_verifier(tool)?;
            let profile = match &resolution {
                Some(super::WorkloadResolve::Script(inputs))
                    if inputs.profile.profile.offload.is_none() =>
                {
                    &inputs.profile.profile
                }
                _ => {
                    return Err(arguments_error(
                        tool,
                        "campaign launches require a non-offload script profile",
                    ))
                }
            };
            if input.target_node.as_deref().is_none_or(str::is_empty) {
                return Err(arguments_error(
                    tool,
                    "campaign launches require targetNode",
                ));
            }
            let cpu = profile
                .resources
                .as_ref()
                .map(|resources| resources.cpu)
                .filter(|cpu| *cpu > 0)
                .ok_or_else(|| {
                    arguments_error(tool, "campaign profile requires a declared CPU reservation")
                })?;
            let deadline = profile
                .deadline_seconds()
                .filter(|deadline| *deadline > 0)
                .ok_or_else(|| {
                    arguments_error(tool, "campaign profile requires a finite job deadline")
                })?;
            Some(f64::from(cpu) * f64::from(deadline) / 3600.0)
        } else {
            None
        };
        let cell = self
            .runtime_cell
            .as_ref()
            .ok_or_else(|| HostToolError::Unavailable {
                tool,
                reason: "the kube surface is not configured".to_owned(),
            })?;
        let (max_launches, max_inputs) = seat_batch_limits(&cell.snapshot(), &seat);
        validate_items(tool, &input.items, max_launches, max_inputs)?;
        if matches!(resolution, None | Some(super::WorkloadResolve::NotWorkload))
            && input
                .items
                .iter()
                .any(|item| item.prompt.is_some() || !item.inputs.is_empty())
        {
            return Err(arguments_error(
                tool,
                "container profiles do not take inputs or prompts",
            ));
        }
        let mut result = Vec::with_capacity(input.items.len());
        for item in input.items {
            validate_input_artifacts(tool, &cell.ledger(), &item.inputs, scope)?;
            if input.campaign_id.is_some() {
                validate_campaign_item(tool, &item)?;
            }
            let mut args = json!({"profile": input.profile, "label": item.label});
            if let Some(prompt) = item.prompt {
                args["prompt"] = json!(prompt);
            }
            if !item.inputs.is_empty() {
                args["inputs"] = json!(item.inputs);
            }
            if let Some(target) = &input.target_node {
                args["targetNode"] = json!(target);
            }
            if let Some(limits) = &input.limits {
                args["limits"] = limits.clone();
            }
            result.push((item.label, args));
        }
        // Profile, scope, limits and target are shared by every item.
        self.preflight_create_campaign(scope, &result[0].1, input.campaign_id.is_some())?;
        Ok(ValidatedBatch {
            items: result,
            campaign: input.campaign_id,
            node: input.target_node,
            core_hours,
        })
    }

    pub(super) fn preflight_create_many(
        &self,
        tool: &'static str,
        scope: &Scope,
        arguments: &Value,
    ) -> Result<(), HostToolError> {
        self.validate_batch(tool, scope, arguments).map(|_| ())
    }

    pub(super) fn create_many(
        &self,
        tool: &'static str,
        timeout_seconds: u32,
        operation_id: OperationId,
        invocation: HostInvocation,
    ) -> Result<Value, HostToolError> {
        let validated = self.validate_batch(tool, &invocation.scope, &invocation.arguments)?;
        let items = validated.items;
        let queue = self
            .launch_queue()
            .ok_or_else(|| HostToolError::Unavailable {
                tool,
                reason: "the launch queue is not configured".to_owned(),
            })?;
        let batch = operation_id.as_str().to_owned();
        let mut launches = Vec::with_capacity(items.len());
        let mut results = Vec::with_capacity(items.len());
        let mut reservations = Vec::new();
        for (index, (label, mut arguments)) in items.into_iter().enumerate() {
            let mut hasher = blake3::Hasher::new();
            hasher.update(operation_id.as_str().as_bytes());
            hasher.update(&(index as u64).to_be_bytes());
            let id = format!("{}", hasher.finalize().to_hex());
            let child =
                OperationId::new(&id).map_err(|error| arguments_error(tool, error.to_string()))?;
            super::execution::batch_run_scope(tool, &invocation.scope, &child)?;
            let mut stage_digest = None;
            if let Some(campaign) = &validated.campaign {
                let cell =
                    self.runtime_cell
                        .as_ref()
                        .ok_or_else(|| HostToolError::Unavailable {
                            tool,
                            reason: "the kube surface is not configured".to_owned(),
                        })?;
                let artifact = arguments["inputs"][0]
                    .as_str()
                    .ok_or_else(|| arguments_error(tool, "campaign stage manifest is missing"))?;
                let identities = validate_input_artifacts(
                    tool,
                    &cell.ledger(),
                    &[artifact.to_owned()],
                    &invocation.scope,
                )?;
                let bytes = cell
                    .artifact_store()
                    .read_registered(&identities[0].artifact_id)
                    .map_err(|error| {
                        arguments_error(
                            tool,
                            format!("cannot read campaign stage manifest: {error}"),
                        )
                    })?;
                let profile = arguments["profile"]
                    .as_str()
                    .ok_or_else(|| arguments_error(tool, "missing profile"))?
                    .to_owned();
                let node = validated
                    .node
                    .as_deref()
                    .ok_or_else(|| arguments_error(tool, "campaign launches require targetNode"))?;
                let verified = self.verify_campaign_stage(tool, &profile, node, &bytes)?;
                if verified.campaign != *campaign {
                    return Err(arguments_error(
                        tool,
                        "stage manifest campaign does not match campaignId",
                    ));
                }
                let caller_run = invocation.scope.run.as_ref().ok_or_else(|| {
                    arguments_error(tool, "campaign launches require a caller run")
                })?;
                let digest = odin_domain::Digest::hash(&verified.manifest);
                let hex = digest.hex();
                let metadata = super::scoped_registration::register_scoped_bytes(
                    tool,
                    &cell.artifact_store(),
                    &cell.ledger(),
                    &verified.manifest,
                    &format!("{}/{}", &hex[..2], hex),
                    caller_run,
                )?;
                arguments["inputs"][0] = json!(metadata.artifact_id.as_str());
                reservations.push(odin_ledger::campaign::Reservation {
                    operation_id: id.clone(),
                    profile,
                    node: node.to_owned(),
                    rung: verified.rung,
                    point: verified.point,
                    core_hours: validated.core_hours.expect("campaign resource bounds"),
                    stage_sha256: verified.sha256.clone(),
                });
                stage_digest = Some(verified.sha256);
            }
            let child_invocation = HostInvocation {
                scope: invocation.scope.clone(),
                arguments,
            };
            let mut launch =
                QueuedLaunch::new(&child, timeout_seconds, &child_invocation).in_batch(&batch);
            launch.campaign = validated.campaign.clone();
            launch.campaign_stage_sha256 = stage_digest;
            launches.push(launch);
            results.push(BatchResult {
                label,
                operation: id,
                status: "queued".to_owned(),
            });
        }
        let output = BatchOutput {
            batch,
            items: results,
        };
        if let Some(campaign) = &validated.campaign {
            queue
                .hold_campaign_batch(
                    &operation_id,
                    &invocation,
                    &launches,
                    campaign,
                    &reservations,
                )
                .map_err(|detail| HostToolError::Uncertain {
                    tool,
                    detail: format!(
                        "campaign batch publication may complete during recovery: {detail}"
                    ),
                })?;
        } else {
            queue
                .hold_batch(&operation_id, &invocation, &launches)
                .map_err(|detail| HostToolError::Storage { tool, detail })?;
        }
        super::evidence::serialize_output(tool, &output)
    }
}

pub(super) fn extract_batch_evidence(
    tool: &'static str,
    arguments: Value,
) -> Result<Value, HostToolError> {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Evidence {
        output: BatchOutput,
    }
    let evidence: Evidence = decode_arguments(tool, arguments)?;
    if evidence.output.batch.is_empty()
        || evidence.output.items.is_empty()
        || evidence.output.items.iter().any(|item| {
            item.status != "queued" || item.operation.is_empty() || item.label.is_empty()
        })
    {
        return Err(arguments_error(tool, "invalid batch settlement"));
    }
    super::evidence::serialize_output(tool, &evidence.output)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_many_refuses_every_item_when_one_is_invalid() {
        let items = vec![
            BatchItem {
                label: "valid".into(),
                prompt: None,
                inputs: vec![],
            },
            BatchItem {
                label: "".into(),
                prompt: None,
                inputs: vec![],
            },
        ];
        assert!(validate_items("kube.workload.create_many", &items, 256, 16).is_err());
    }

    #[test]
    fn campaign_requires_first_input_manifest() {
        let empty = BatchItem {
            label: "x".into(),
            prompt: None,
            inputs: vec![],
        };
        let prompt = BatchItem {
            label: "x".into(),
            prompt: Some("task".into()),
            inputs: vec![],
        };
        let manifest = BatchItem {
            label: "x".into(),
            prompt: None,
            inputs: vec!["artifact".into()],
        };
        assert!(validate_campaign_item("test", &empty).is_err());
        assert!(validate_campaign_item("test", &prompt).is_err());
        assert!(validate_campaign_item("test", &manifest).is_ok());
    }

    #[test]
    fn batch_limits_follow_declared_values() {
        let item = || BatchItem {
            label: "valid".into(),
            prompt: None,
            inputs: vec!["a".into(), "b".into()],
        };
        assert!(validate_items("test", &[item(), item()], 2, 2).is_ok());
        assert!(validate_items("test", &[item(), item()], 1, 2).is_err());
        assert!(validate_items("test", &[item()], 2, 1).is_err());
        assert!(validate_items("test", &[], 2, 2).is_err());
        let many: Vec<_> = (0..257).map(|_| item()).collect();
        assert!(validate_items("test", &many, 257, 2).is_ok());
        let many_inputs = BatchItem {
            label: "valid".into(),
            prompt: None,
            inputs: vec!["a".into(); 80],
        };
        assert!(validate_items("test", &[many_inputs], 1, 80).is_ok());
    }

    #[test]
    fn batch_limits_use_each_published_snapshot() {
        let seat = odin_domain::SeatId::new("builder").unwrap();
        let make = |launches, inputs| {
            let text = format!("schema = 'odin.registry.v1'\nkind = 'seat'\nenabled = true\ndescription = 'test'\ncategories = []\ntool_refs = []\nproject_scope = []\nbrain_scope = []\n[limits]\nmax_parallel_runs = 1\nmax_sessions = 1\nmax_batch_launches = {launches}\nmax_batch_inputs = {inputs}\n");
            let object = odin_registry::schema::parse_object_toml(
                odin_registry::RegistryKind::Seat,
                "builder",
                "seats/builder/seat.toml",
                &text,
            )
            .unwrap();
            odin_registry::Snapshot::build(1, vec![object]).unwrap()
        };
        let old = make(2, 3);
        let published = make(300, 80);
        assert_eq!(seat_batch_limits(&old, &seat), (2, 3));
        assert_eq!(seat_batch_limits(&published, &seat), (300, 80));
        assert_eq!(seat_batch_limits(&old, &seat), (2, 3));
    }
}
