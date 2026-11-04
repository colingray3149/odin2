use odin_browser::capability::{ActionArguments, ActionRequest, CapabilityError, ElementRef};
use odin_browser::session::SessionError;
use odin_browser::StructuralAction;
use odin_domain::huginn as live;
use odin_domain::{CommandId, Digest};
use serde_json::Value;

pub(super) fn action_request(
    command: live::BrowserCommand,
) -> Result<(live::BrowserCommandContext, ActionRequest), live::HuginnProtocolError> {
    let (context, action, arguments) = match command {
        live::BrowserCommand::Navigate { context, url } => (
            context,
            StructuralAction::Navigate,
            ActionArguments::Url { url },
        ),
        live::BrowserCommand::Back { context } => {
            (context, StructuralAction::Back, ActionArguments::None)
        }
        live::BrowserCommand::Forward { context } => {
            (context, StructuralAction::Forward, ActionArguments::None)
        }
        live::BrowserCommand::Reload { context } => {
            (context, StructuralAction::Reload, ActionArguments::None)
        }
        live::BrowserCommand::Click { context, selector } => (
            context,
            StructuralAction::Activate,
            ActionArguments::Selector {
                selector: ElementRef::new(selector).map_err(|error| {
                    invalid_request(
                        "browserSelector",
                        &format!("browser selector is invalid: {error}"),
                    )
                })?,
            },
        ),
        live::BrowserCommand::TypeText {
            context,
            selector,
            text,
        } => (
            context,
            StructuralAction::Fill,
            ActionArguments::Fill {
                selector: ElementRef::new(selector).map_err(|error| {
                    invalid_request(
                        "browserSelector",
                        &format!("browser selector is invalid: {error}"),
                    )
                })?,
                text,
            },
        ),
        live::BrowserCommand::PressKey { context, key } => (
            context,
            StructuralAction::PressKey,
            ActionArguments::Key { key },
        ),
        live::BrowserCommand::Scroll {
            context,
            delta_x,
            delta_y,
        } => (
            context,
            StructuralAction::Scroll,
            ActionArguments::Scroll { delta_x, delta_y },
        ),
        live::BrowserCommand::CaptureScreenshot { context } => {
            (context, StructuralAction::Screenshot, ActionArguments::None)
        }
        live::BrowserCommand::Close { context } => {
            (context, StructuralAction::Close, ActionArguments::None)
        }
        live::BrowserCommand::Takeover { .. } => {
            return Err(invalid_request(
                "browserCommand",
                "browser takeover is not an ordinary action",
            ));
        }
    };
    let request = ActionRequest::new(action, arguments).map_err(|error| {
        invalid_request(
            "browserArguments",
            &format!("browser action arguments are invalid: {error}"),
        )
    })?;
    Ok((context, request))
}

pub(super) fn durable_revision(revision: u64) -> Result<i64, live::HuginnProtocolError> {
    i64::try_from(revision).map_err(|error| {
        invalid_request(
            "browserRevision",
            &format!("browser revision {revision} does not fit the durable ledger: {error}"),
        )
    })
}

pub(super) fn digest_json(value: &Value) -> Result<Digest, live::HuginnProtocolError> {
    serde_json::to_vec(value)
        .map(|bytes| Digest::hash(&bytes))
        .map_err(|error| live::HuginnProtocolError::unavailable("browserArgumentsDigest", error))
}

pub(super) fn accepted_response(command_id: CommandId) -> live::HuginnResponse {
    live::HuginnResponse::Command(live::CommandReceipt::Accepted { command_id })
}

pub(super) fn prepare_action_failure_code(error: &SessionError) -> &'static str {
    match error {
        SessionError::Capability(_) => "browserActionPrepareCapability",
        SessionError::Transport(_) => "browserActionPrepareTransport",
        SessionError::Timeout { .. } => "browserActionPrepareTimeout",
        SessionError::Stopped => "browserActionPrepareStopped",
        SessionError::TargetClosed => "browserActionPrepareTargetClosed",
        SessionError::InputUncertain => "browserActionPrepareInputUncertain",
        SessionError::OutcomeUncertain { .. } => "browserActionPrepareOutcomeUncertain",
        SessionError::PendingActionExists { .. } => "browserActionPreparePending",
        SessionError::PolicyUnmapped { .. } => "browserActionPreparePolicy",
        SessionError::NavigateHostDenied => "browserActionPrepareHostDenied",
        SessionError::UnknownAction { .. }
        | SessionError::StalePolicyBinding { .. }
        | SessionError::StaleControlBinding { .. }
        | SessionError::ApprovalRequired { .. }
        | SessionError::ApprovalMismatch { .. }
        | SessionError::DurableControlUnavailable(_)
        | SessionError::DurableControlInvalid(_)
        | SessionError::DurableControlStale
        | SessionError::TakeoverExpiryUnobserved
        | SessionError::ControlRevisionOverflow(_) => "browserActionPrepareState",
        SessionError::Launch(_)
        | SessionError::LaunchStage { .. }
        | SessionError::Shutdown(_)
        | SessionError::Config(_)
        | SessionError::Profile(_)
        | SessionError::Policy(_)
        | SessionError::Takeover(_)
        | SessionError::Frame(_)
        | SessionError::Download(_)
        | SessionError::OutboundBlocked { .. } => "browserActionPrepareOther",
    }
}

pub(super) fn failed_outcome(
    command_id: &CommandId,
    code: &str,
    message: &str,
) -> live::CommandOutcome {
    live::CommandOutcome::Failed {
        command_id: command_id.clone(),
        error: live::CommandFailure {
            code: code.to_owned(),
            message: message.to_owned(),
            retryable: false,
        },
    }
}

pub(super) fn execute_action_failure_code(error: &SessionError) -> &'static str {
    match error {
        SessionError::Capability(error) => match error.as_ref() {
            CapabilityError::InvalidRequest { .. } => "browserActionUnknownInvalidRequest",
            CapabilityError::BoundExceeded { .. } => "browserActionUnknownBound",
            CapabilityError::DigestMismatch { .. } => "browserActionUnknownDigest",
            // Stable coordinator boundary: worker binding failures are normalized by
            // odin-browser, but node, structure, expected-target, document, and
            // argument staleness remain distinct command outcome codes.
            CapabilityError::StaleBinding { reason } => match reason.as_str() {
                "document changed after action preparation" => "browserActionUnknownStaleDocument",
                "selector resolved to a different DOM node" => "browserActionUnknownStaleNode",
                "target structure changed after action preparation" => {
                    "browserActionUnknownStaleStructure"
                }
                "prepared target evidence changed after action preparation" => {
                    "browserActionUnknownExpectedTarget"
                }
                "action arguments changed after action preparation" => {
                    "browserActionUnknownArguments"
                }
                "fill target could not be focused" => "browserActionUnknownFocus",
                _ => "browserActionUnknownStaleBinding",
            },
            CapabilityError::PublisherFailure { .. } => "browserActionUnknownPublisher",
            CapabilityError::AuthorityDenied { .. } | CapabilityError::AuthorityRequired { .. } => {
                "browserActionUnknownAuthority"
            }
        },
        SessionError::Transport(_) => "browserActionUnknownTransport",
        SessionError::Timeout { .. } => "browserActionUnknownTimeout",
        SessionError::Stopped => "browserActionUnknownStopped",
        SessionError::TargetClosed => "browserActionUnknownTargetClosed",
        SessionError::InputUncertain => "browserActionUnknownInputUncertain",
        SessionError::OutcomeUncertain { .. } => "browserActionUnknownOutcomeUncertain",
        SessionError::StalePolicyBinding { .. } => "browserActionUnknownPolicy",
        SessionError::StaleControlBinding { .. } => "browserActionUnknownControl",
        SessionError::ApprovalRequired { .. } | SessionError::ApprovalMismatch { .. } => {
            "browserActionUnknownApproval"
        }
        _ => "browserActionUnknownOther",
    }
}

pub(super) fn invalid_request(code: &str, message: &str) -> live::HuginnProtocolError {
    live::HuginnProtocolError::InvalidRequest {
        code: code.to_owned(),
        message: message.to_owned(),
    }
}

pub(super) fn conflict(code: &str, message: &str) -> live::HuginnProtocolError {
    live::HuginnProtocolError::Conflict {
        code: code.to_owned(),
        message: message.to_owned(),
    }
}

pub(super) fn unsupported(operation: &str) -> live::HuginnProtocolError {
    live::HuginnProtocolError::Unsupported {
        operation: operation.to_owned(),
    }
}
