use odin_browser::capability::{ActionArguments, ActionRequest, ElementRef};
use odin_browser::{StructuralAction, TypedRead};
use odin_domain::huginn as live;
use odin_domain::{CommandId, Digest};
use odin_omp::host_tools::{HostInvocation, HostToolError};
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NoActionArguments {}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NavigateArguments {
    url: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SelectorArguments {
    selector: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FillArguments {
    selector: String,
    text: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct KeyArguments {
    key: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ScrollArguments {
    delta_x: i32,
    delta_y: i32,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BrowserEvidenceInvocation {
    output: Value,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
enum BrowserActionDisposition {
    Accepted,
    Duplicate,
    Applied,
    Denied,
    Failed,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct BrowserActionEvidence {
    status: BrowserActionDisposition,
    command_id: CommandId,
    evidence_refs: Vec<Digest>,
    artifact_refs: Vec<Digest>,
}

pub(super) fn require_browser_seat_scope(
    tool: &'static str,
    invocation: &HostInvocation,
) -> Result<String, HostToolError> {
    invocation
        .scope
        .seat
        .as_ref()
        .map(ToString::to_string)
        .ok_or(HostToolError::Scope {
            tool,
            reason: "browser capability requires a seat-bound invocation",
        })
}

pub(super) fn browser_arguments(tool: &'static str, detail: impl Into<String>) -> HostToolError {
    HostToolError::Arguments {
        tool,
        detail: detail.into(),
    }
}

pub(super) fn browser_runtime(tool: &'static str, detail: impl Into<String>) -> HostToolError {
    HostToolError::Storage {
        tool,
        detail: detail.into(),
    }
}

fn decode_action_arguments<T: for<'de> Deserialize<'de>>(
    tool: &'static str,
    value: Value,
) -> Result<T, HostToolError> {
    serde_json::from_value(value)
        .map_err(|error| browser_arguments(tool, format!("invalid action arguments: {error}")))
}

pub(super) fn host_action_request(
    tool: &'static str,
    action: StructuralAction,
    arguments: Value,
) -> Result<ActionRequest, HostToolError> {
    let arguments = match action {
        StructuralAction::Navigate => {
            let input: NavigateArguments = decode_action_arguments(tool, arguments)?;
            ActionArguments::Url { url: input.url }
        }
        StructuralAction::Back
        | StructuralAction::Forward
        | StructuralAction::Reload
        | StructuralAction::Screenshot
        | StructuralAction::Close => {
            let _: NoActionArguments = decode_action_arguments(tool, arguments)?;
            ActionArguments::None
        }
        StructuralAction::Fill => {
            let input: FillArguments = decode_action_arguments(tool, arguments)?;
            ActionArguments::Fill {
                selector: ElementRef::new(input.selector)
                    .map_err(|error| browser_arguments(tool, error.to_string()))?,
                text: input.text,
            }
        }
        StructuralAction::Activate | StructuralAction::SubmitForm => {
            let input: SelectorArguments = decode_action_arguments(tool, arguments)?;
            ActionArguments::Selector {
                selector: ElementRef::new(input.selector)
                    .map_err(|error| browser_arguments(tool, error.to_string()))?,
            }
        }
        StructuralAction::PressKey => {
            let input: KeyArguments = decode_action_arguments(tool, arguments)?;
            ActionArguments::Key { key: input.key }
        }
        StructuralAction::Scroll => {
            let input: ScrollArguments = decode_action_arguments(tool, arguments)?;
            ActionArguments::Scroll {
                delta_x: input.delta_x,
                delta_y: input.delta_y,
            }
        }
    };
    ActionRequest::new(action, arguments)
        .map_err(|error| browser_arguments(tool, error.to_string()))
}

pub(super) fn extract_observe_evidence(
    tool: &'static str,
    arguments: Value,
) -> Result<Value, HostToolError> {
    let input: BrowserEvidenceInvocation = serde_json::from_value(arguments)
        .map_err(|error| browser_arguments(tool, format!("invalid evidence input: {error}")))?;
    let read: TypedRead = serde_json::from_value(input.output)
        .map_err(|error| browser_arguments(tool, format!("invalid observe output: {error}")))?;
    read.validate()
        .map_err(|error| browser_arguments(tool, error.to_string()))?;
    serde_json::to_value(read)
        .map_err(|error| browser_runtime(tool, format!("cannot serialize evidence: {error}")))
}

pub(super) fn extract_action_evidence(
    tool: &'static str,
    arguments: Value,
) -> Result<Value, HostToolError> {
    let input: BrowserEvidenceInvocation = serde_json::from_value(arguments)
        .map_err(|error| browser_arguments(tool, format!("invalid evidence input: {error}")))?;
    let evidence: BrowserActionEvidence = serde_json::from_value(input.output)
        .map_err(|error| browser_arguments(tool, format!("invalid action output: {error}")))?;
    serde_json::to_value(evidence)
        .map_err(|error| browser_runtime(tool, format!("cannot serialize evidence: {error}")))
}

pub(super) fn browser_action_output(
    tool: &'static str,
    response: live::HuginnResponse,
) -> Result<Value, HostToolError> {
    let (status, command_id) = match response {
        live::HuginnResponse::Command(live::CommandReceipt::Accepted { command_id }) => {
            (BrowserActionDisposition::Accepted, command_id)
        }
        live::HuginnResponse::Command(live::CommandReceipt::Duplicate { command_id, .. }) => {
            (BrowserActionDisposition::Duplicate, command_id)
        }
        live::HuginnResponse::Command(live::CommandReceipt::Rejected { command_id, .. }) => {
            (BrowserActionDisposition::Denied, command_id)
        }
        _ => {
            return Err(browser_runtime(
                tool,
                "browser coordinator returned a non-command response",
            ));
        }
    };
    serde_json::to_value(BrowserActionEvidence {
        status,
        command_id,
        evidence_refs: Vec::new(),
        artifact_refs: Vec::new(),
    })
    .map_err(|error| browser_runtime(tool, format!("cannot serialize action result: {error}")))
}
