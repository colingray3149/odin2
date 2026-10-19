//! The `session` command domain: session lifecycle, prompting, steering,
//! model and permission control, and aborts.

use clap::{Args, Subcommand, ValueEnum};
use odin_domain::huginn as live;

use super::surface::{non_empty, parse_id, HuginnPlan};

#[derive(Debug, Args)]
pub(crate) struct HuginnSessionArgs {
    #[command(subcommand)]
    pub(super) command: HuginnSessionCommand,
}

#[derive(Debug, Subcommand)]
pub(super) enum HuginnSessionCommand {
    Open(HuginnSessionOpenArgs),
    Prompt(HuginnSessionMessageArgs),
    FollowUp(HuginnSessionMessageArgs),
    Steer(HuginnSessionMessageArgs),
    Pause(HuginnSessionTargetArgs),
    Resume(HuginnSessionTargetArgs),
    Checkpoint(HuginnSessionTargetArgs),
    Restart(HuginnSessionTargetArgs),
    Rehome(HuginnSessionRehomeArgs),
    SetModel(HuginnSessionModelArgs),
    Permission(HuginnSessionPermissionArgs),
    Abort(HuginnSessionAbortArgs),
}

#[derive(Debug, Args)]
pub(super) struct HuginnSessionOpenArgs {
    #[arg(long, value_name = "ID")]
    command_id: String,
    #[arg(long, value_name = "ID")]
    seat: String,
    #[arg(long, value_name = "ID")]
    project: String,
    #[arg(long, value_name = "ID")]
    slice: String,
    #[arg(long, value_name = "NAME")]
    provider: String,
    #[arg(long, value_name = "NAME")]
    model: String,
    #[arg(long, value_name = "ID")]
    node: String,
    #[arg(long)]
    title: Option<String>,
    #[arg(long)]
    initial_prompt: Option<String>,
    #[arg(long)]
    headless: bool,
}

#[derive(Clone, Debug, Args)]
pub(super) struct HuginnSessionTargetArgs {
    #[arg(long, value_name = "ID")]
    command_id: String,
    #[arg(long, value_name = "UUID")]
    session: String,
    #[arg(long, value_name = "EPOCH")]
    expected_epoch: u64,
    #[arg(long, value_name = "SEQUENCE")]
    expected_event_head: Option<u64>,
}

#[derive(Debug, Args)]
pub(super) struct HuginnSessionMessageArgs {
    #[command(flatten)]
    target: HuginnSessionTargetArgs,
    #[arg(value_name = "MESSAGE")]
    message: String,
}

#[derive(Debug, Args)]
pub(super) struct HuginnSessionRehomeArgs {
    #[command(flatten)]
    target: HuginnSessionTargetArgs,
    #[arg(long, value_name = "ID")]
    node: String,
}

#[derive(Debug, Args)]
pub(super) struct HuginnSessionModelArgs {
    #[command(flatten)]
    target: HuginnSessionTargetArgs,
    #[arg(long, value_name = "NAME")]
    provider: String,
    #[arg(long, value_name = "NAME")]
    model: String,
}

#[derive(Debug, Args)]
pub(super) struct HuginnSessionPermissionArgs {
    #[command(flatten)]
    target: HuginnSessionTargetArgs,
    #[arg(long, value_name = "ID")]
    request: String,
    #[arg(long, value_enum)]
    decision: HuginnPermissionDecisionArg,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
enum HuginnPermissionDecisionArg {
    AllowOnce,
    Deny,
}

#[derive(Debug, Args)]
pub(super) struct HuginnSessionAbortArgs {
    #[command(flatten)]
    target: HuginnSessionTargetArgs,
    #[arg(long, value_enum, default_value = "current-turn")]
    scope: HuginnAbortScopeArg,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
enum HuginnAbortScopeArg {
    CurrentTurn,
    Session,
}

impl HuginnSessionCommand {
    pub(super) fn into_plan(self) -> Result<HuginnPlan, String> {
        let request = match self {
            Self::Open(arguments) => live::HuginnRequest::OpenSession(live::OpenSessionRequest {
                command_id: parse_id(&arguments.command_id, "command ID")?,
                seat_id: parse_id(&arguments.seat, "seat ID")?,
                project_id: parse_id(&arguments.project, "project ID")?,
                slice_id: parse_id(&arguments.slice, "slice ID")?,
                provider: live::ProviderName::parse(&arguments.provider)
                    .map_err(|error| error.to_string())?,
                model: live::ModelName::parse(&arguments.model)
                    .map_err(|error| error.to_string())?,
                title: arguments
                    .title
                    .map(|title| non_empty(title, "session title"))
                    .transpose()?,
                target_node: parse_id(&arguments.node, "target node ID")?,
                open_tab: !arguments.headless,
                initial_prompt: arguments.initial_prompt.map(text_message).transpose()?,
                workload: None,
                // A raw protocol open admits no generation of its own: the
                // daemon resolves the session's generation from the token's
                // signed claim.
                served_revision: None,
            }),
            Self::Prompt(arguments) => session_message_request(arguments, |message| {
                live::LiveCommandBody::Prompt { message }
            })?,
            Self::FollowUp(arguments) => session_message_request(arguments, |message| {
                live::LiveCommandBody::FollowUp { message }
            })?,
            Self::Steer(arguments) => session_message_request(arguments, |message| {
                live::LiveCommandBody::Steer { message }
            })?,
            Self::Pause(target) => session_command_request(target, live::LiveCommandBody::Pause)?,
            Self::Resume(target) => session_command_request(target, live::LiveCommandBody::Resume)?,
            Self::Checkpoint(target) => {
                session_command_request(target, live::LiveCommandBody::Checkpoint)?
            }
            Self::Restart(target) => {
                session_command_request(target, live::LiveCommandBody::Restart)?
            }
            Self::Rehome(arguments) => session_command_request(
                arguments.target,
                live::LiveCommandBody::Rehome {
                    target_node: parse_id(&arguments.node, "target node ID")?,
                },
            )?,
            Self::SetModel(arguments) => session_command_request(
                arguments.target,
                live::LiveCommandBody::SetModel {
                    provider: live::ProviderName::parse(&arguments.provider)
                        .map_err(|error| error.to_string())?,
                    model: live::ModelName::parse(&arguments.model)
                        .map_err(|error| error.to_string())?,
                },
            )?,
            Self::Permission(arguments) => session_command_request(
                arguments.target,
                live::LiveCommandBody::DecidePermission {
                    request_id: live::PermissionRequestId::parse(&arguments.request)
                        .map_err(|error| error.to_string())?,
                    decision: match arguments.decision {
                        HuginnPermissionDecisionArg::AllowOnce => {
                            live::PermissionDecision::AllowOnce
                        }
                        HuginnPermissionDecisionArg::Deny => live::PermissionDecision::Deny,
                    },
                },
            )?,
            Self::Abort(arguments) => session_command_request(
                arguments.target,
                live::LiveCommandBody::Abort {
                    scope: match arguments.scope {
                        HuginnAbortScopeArg::CurrentTurn => live::AbortScope::CurrentTurn,
                        HuginnAbortScopeArg::Session => live::AbortScope::Session,
                    },
                },
            )?,
        };
        Ok(HuginnPlan::request(request))
    }
}

fn session_message_request(
    arguments: HuginnSessionMessageArgs,
    body: impl FnOnce(live::LiveMessage) -> live::LiveCommandBody,
) -> Result<live::HuginnRequest, String> {
    let message = text_message(arguments.message)?;
    session_command_request(arguments.target, body(message))
}

fn session_command_request(
    target: HuginnSessionTargetArgs,
    body: live::LiveCommandBody,
) -> Result<live::HuginnRequest, String> {
    body.validate_message().map_err(|error| error.to_string())?;
    Ok(live::HuginnRequest::SessionCommand(live::LiveCommand {
        command_id: parse_id(&target.command_id, "command ID")?,
        session_id: live::LiveSessionId::parse(&target.session)
            .map_err(|error| error.to_string())?,
        expected_epoch: live::SessionEpoch::new(target.expected_epoch),
        expected_event_head: target.expected_event_head.map(live::EventSeq::new),
        body,
    }))
}

fn text_message(text: String) -> Result<live::LiveMessage, String> {
    live::LiveMessage::new(vec![live::LiveContentBlock::Text(non_empty(
        text, "message",
    )?)])
    .map_err(|error| error.to_string())
}
