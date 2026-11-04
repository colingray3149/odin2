//! The `terminal` command domain: terminal listing, control-lease attach,
//! write, resize, and release.

use std::num::{NonZeroU16, NonZeroU32};

use clap::{Args, Subcommand};
use odin_domain::huginn as live;

use super::surface::{
    parse_id, snapshot_plan, watch_plan, HuginnPageArgs, HuginnPlan, HuginnStreamKindArg,
    HuginnWatchArgs,
};

#[derive(Debug, Args)]
pub(crate) struct HuginnTerminalArgs {
    #[command(subcommand)]
    pub(super) command: HuginnTerminalCommand,
}

#[derive(Debug, Subcommand)]
pub(super) enum HuginnTerminalCommand {
    List(HuginnPageArgs),
    Attach(HuginnTerminalAttachArgs),
    Write(HuginnTerminalWriteArgs),
    Resize(HuginnTerminalResizeArgs),
    Release(HuginnTerminalReleaseArgs),
}

#[derive(Debug, Args)]
pub(super) struct HuginnTerminalAttachArgs {
    #[arg(long, value_name = "UUID")]
    session: String,
    #[arg(long, value_name = "EPOCH")]
    expected_epoch: u64,
    #[arg(long)]
    control: bool,
    #[arg(long, value_name = "ID")]
    command_id: Option<String>,
    #[arg(long, default_value = "80")]
    columns: NonZeroU16,
    #[arg(long, default_value = "24")]
    rows: NonZeroU16,
    #[arg(long, default_value = "60")]
    ttl_seconds: NonZeroU32,
    #[arg(long, value_name = "UUID")]
    stream: Option<String>,
}

#[derive(Debug, Args)]
pub(super) struct HuginnTerminalWriteArgs {
    #[arg(long, value_name = "ID")]
    command_id: String,
    #[arg(long, value_name = "UUID")]
    session: String,
    #[arg(long, value_name = "UUID")]
    lease: String,
    #[arg(value_name = "INPUT")]
    input: String,
}

#[derive(Debug, Args)]
pub(super) struct HuginnTerminalResizeArgs {
    #[arg(long, value_name = "ID")]
    command_id: String,
    #[arg(long, value_name = "UUID")]
    session: String,
    #[arg(long, value_name = "UUID")]
    lease: String,
    #[arg(long)]
    columns: NonZeroU16,
    #[arg(long)]
    rows: NonZeroU16,
}

#[derive(Debug, Args)]
pub(super) struct HuginnTerminalReleaseArgs {
    #[arg(long, value_name = "ID")]
    command_id: String,
    #[arg(long, value_name = "UUID")]
    session: String,
    #[arg(value_name = "UUID")]
    lease: String,
}

impl HuginnTerminalCommand {
    pub(super) fn into_plan(self) -> Result<HuginnPlan, String> {
        match self {
            Self::List(page) => Ok(snapshot_plan(live::ObjectKind::Terminal, page)),
            Self::Attach(arguments) if arguments.control => {
                let command_id = arguments.command_id.ok_or_else(|| {
                    "terminal attach --control requires --command-id <ID>".to_owned()
                })?;
                Ok(HuginnPlan::request(
                    live::HuginnRequest::AcquireTerminalControl(live::TerminalAcquireRequest {
                        command_id: parse_id(&command_id, "command ID")?,
                        request: live::TerminalControlRequest {
                            session_id: live::LiveSessionId::parse(&arguments.session)
                                .map_err(|error| error.to_string())?,
                            expected_epoch: live::SessionEpoch::new(arguments.expected_epoch),
                            columns: arguments.columns,
                            rows: arguments.rows,
                            requested_ttl_seconds: arguments.ttl_seconds,
                        },
                    }),
                ))
            }
            Self::Attach(arguments) => {
                let stream = arguments.stream.ok_or_else(|| {
                    "terminal attach without --control watches a stream and requires --stream <UUID>"
                        .to_owned()
                })?;
                watch_plan(HuginnWatchArgs::with_default_limits(
                    HuginnStreamKindArg::Terminal,
                    stream,
                ))
            }
            Self::Write(arguments) => Ok(HuginnPlan::request(live::HuginnRequest::WriteTerminal(
                live::TerminalWriteRequest {
                    command_id: parse_id(&arguments.command_id, "command ID")?,
                    session_id: live::LiveSessionId::parse(&arguments.session)
                        .map_err(|error| error.to_string())?,
                    input: live::TerminalInput {
                        lease_id: live::TerminalControlLeaseId::parse(&arguments.lease)
                            .map_err(|error| error.to_string())?,
                        bytes: arguments.input.into_bytes(),
                    },
                },
            ))),
            Self::Resize(arguments) => Ok(HuginnPlan::request(
                live::HuginnRequest::ResizeTerminal(live::TerminalResizeRequest {
                    command_id: parse_id(&arguments.command_id, "command ID")?,
                    session_id: live::LiveSessionId::parse(&arguments.session)
                        .map_err(|error| error.to_string())?,
                    resize: live::TerminalResize {
                        lease_id: live::TerminalControlLeaseId::parse(&arguments.lease)
                            .map_err(|error| error.to_string())?,
                        columns: arguments.columns,
                        rows: arguments.rows,
                    },
                }),
            )),
            Self::Release(arguments) => Ok(HuginnPlan::request(
                live::HuginnRequest::ReleaseTerminalControl(live::TerminalReleaseRequest {
                    command_id: parse_id(&arguments.command_id, "command ID")?,
                    session_id: live::LiveSessionId::parse(&arguments.session)
                        .map_err(|error| error.to_string())?,
                    lease_id: live::TerminalControlLeaseId::parse(&arguments.lease)
                        .map_err(|error| error.to_string())?,
                }),
            )),
        }
    }
}
