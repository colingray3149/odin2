//! The `render` command domain: render requests, status, watches, and
//! content-ticket opens.

use std::num::NonZeroU64;

use clap::{Args, Subcommand};
use odin_domain::huginn as live;

use super::surface::{
    parse_id, parse_protocol_json, snapshot_plan, HuginnIdArgs, HuginnPageArgs, HuginnPlan,
    HuginnProtocolJsonArgs,
};

#[derive(Debug, Args)]
pub(crate) struct HuginnRenderArgs {
    #[command(subcommand)]
    pub(super) command: HuginnRenderCommand,
}

#[derive(Debug, Subcommand)]
pub(super) enum HuginnRenderCommand {
    /// Lists render jobs with their state and output manifest (read model).
    List(HuginnPageArgs),
    Request(HuginnProtocolJsonArgs),
    Status(HuginnIdArgs),
    Watch(HuginnIdArgs),
    Open(HuginnRenderOpenArgs),
}

#[derive(Debug, Args)]
pub(super) struct HuginnRenderOpenArgs {
    #[arg(long, value_name = "ID")]
    command_id: String,
    #[arg(value_name = "ARTIFACT_ID")]
    artifact: String,
    #[arg(long, default_value = "8388608", value_name = "BYTES")]
    max_bytes: NonZeroU64,
}

impl HuginnRenderCommand {
    pub(super) fn into_plan(self) -> Result<HuginnPlan, String> {
        match self {
            Self::List(page) => Ok(snapshot_plan(live::ObjectKind::Render, page)),
            Self::Request(arguments) => {
                let request = parse_protocol_json(&arguments.request_json, "render request")?;
                Ok(HuginnPlan::request(live::HuginnRequest::RequestRender(
                    request,
                )))
            }
            Self::Status(arguments) => Ok(HuginnPlan::request(live::HuginnRequest::RenderStatus(
                live::RenderStatusRequest {
                    render_id: live::RenderId::parse(&arguments.id)
                        .map_err(|error| error.to_string())?,
                },
            ))),
            Self::Watch(arguments) => Ok(HuginnPlan::request_stream(
                live::HuginnRequest::WatchRender(live::RenderWatchRequest {
                    render_id: live::RenderId::parse(&arguments.id)
                        .map_err(|error| error.to_string())?,
                }),
            )),
            Self::Open(arguments) => Ok(HuginnPlan::request(
                live::HuginnRequest::IssueContentTicket(live::ContentTicketRequest {
                    command_id: parse_id(&arguments.command_id, "command ID")?,
                    source: live::ContentSource::Artifact(parse_id(
                        &arguments.artifact,
                        "artifact ID",
                    )?),
                    max_bytes: arguments.max_bytes,
                }),
            )),
        }
    }
}
