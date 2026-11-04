//! The `simulation` command domain: simulation snapshots, searches, bounded
//! telemetry and frame watches, and typed protocol commands.

use std::num::NonZeroU16;

use clap::{Args, Subcommand};
use odin_domain::huginn as live;

use super::surface::{
    parse_protocol_json, search_plan, snapshot_plan, watch_plan_for, HuginnIdArgs, HuginnPageArgs,
    HuginnPlan, HuginnProtocolJsonArgs, HuginnWatchArgs,
};

#[derive(Debug, Args)]
pub(crate) struct HuginnSimulationArgs {
    #[command(subcommand)]
    pub(super) command: HuginnSimulationCommand,
}

#[derive(Debug, Subcommand)]
pub(super) enum HuginnSimulationCommand {
    List(HuginnPageArgs),
    Show(HuginnIdArgs),
    Telemetry(HuginnWatchArgs),
    Render(HuginnProtocolJsonArgs),
    Watch(HuginnWatchArgs),
    Checkpoint(HuginnProtocolJsonArgs),
    Command(HuginnProtocolJsonArgs),
}

impl HuginnSimulationCommand {
    pub(super) fn into_plan(self) -> Result<HuginnPlan, String> {
        match self {
            Self::List(page) => Ok(snapshot_plan(live::ObjectKind::Simulation, page)),
            Self::Show(arguments) => Ok(search_plan(
                live::ObjectKind::Simulation,
                arguments.id,
                NonZeroU16::new(1).expect("one is non-zero"),
            )),
            Self::Telemetry(arguments) => watch_plan_for(
                arguments,
                live::LiveStreamKind::SimulationTelemetry,
                "simulation telemetry",
            ),
            Self::Watch(arguments) => watch_plan_for(
                arguments,
                live::LiveStreamKind::SimulationFrames,
                "simulation watch",
            ),
            Self::Render(arguments) => simulation_command_plan(arguments, "requestRender"),
            Self::Checkpoint(arguments) => simulation_command_plan(arguments, "createCheckpoint"),
            Self::Command(arguments) => simulation_command_plan(arguments, ""),
        }
    }
}

fn simulation_command_plan(
    arguments: HuginnProtocolJsonArgs,
    expected_kind: &str,
) -> Result<HuginnPlan, String> {
    let command: live::SimulationCommand =
        parse_protocol_json(&arguments.request_json, "simulation command")?;
    let valid = match expected_kind {
        "" => true,
        "requestRender" => matches!(&command, live::SimulationCommand::RequestRender { .. }),
        "createCheckpoint" => matches!(&command, live::SimulationCommand::CreateCheckpoint { .. }),
        _ => false,
    };
    if !valid {
        return Err(format!(
            "simulation subcommand requires a {expected_kind} typed protocol command"
        ));
    }
    Ok(HuginnPlan::request(live::HuginnRequest::SimulationCommand(
        command,
    )))
}
