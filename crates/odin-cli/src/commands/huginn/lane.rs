//! The `lane` command domain: one control verb for a whole
//! lane — `odin huginn lane <LANE> pause|resume|restart|checkpoint|abort|
//! rehome --node <NODE>` — sent as the shared `LaneCommand` request. odind
//! turns it into one ordinary session command per live session of the lane,
//! at the lane revision the caller read (`odin huginn lanes`).

use clap::{Args, Subcommand};
use odin_domain::huginn as live;

use super::surface::{parse_id, HuginnPlan};

#[derive(Debug, Args)]
pub(crate) struct HuginnLaneArgs {
    /// The lane to control (an id from `odin huginn lanes`).
    #[arg(value_name = "LANE")]
    lane: String,
    /// The lane revision the caller read; a lane that moved since refuses.
    #[arg(long, value_name = "REVISION")]
    expected_revision: u64,
    /// The command's idempotency id; one is minted when omitted.
    #[arg(long, value_name = "ID")]
    command_id: Option<String>,
    #[command(subcommand)]
    verb: HuginnLaneVerb,
}

#[derive(Debug, Subcommand)]
enum HuginnLaneVerb {
    Pause,
    Resume,
    Restart,
    Checkpoint,
    Abort,
    Rehome {
        /// The node every live session of the lane moves to.
        #[arg(long, value_name = "ID")]
        node: String,
    },
}

impl HuginnLaneArgs {
    pub(super) fn into_plan(self) -> Result<HuginnPlan, String> {
        let body = match self.verb {
            HuginnLaneVerb::Pause => live::LaneCommandBody::Pause,
            HuginnLaneVerb::Resume => live::LaneCommandBody::Resume,
            HuginnLaneVerb::Restart => live::LaneCommandBody::Restart,
            HuginnLaneVerb::Checkpoint => live::LaneCommandBody::Checkpoint,
            HuginnLaneVerb::Abort => live::LaneCommandBody::Abort,
            HuginnLaneVerb::Rehome { node } => {
                live::LaneCommandBody::Rehome(parse_id(&node, "target node ID")?)
            }
        };
        let command_id = self
            .command_id
            .unwrap_or_else(|| format!("cli:lane:{}", uuid::Uuid::new_v4()));
        Ok(HuginnPlan::request(live::HuginnRequest::LaneCommand(
            live::LaneCommand {
                command_id: parse_id(&command_id, "command ID")?,
                lane_id: parse_id(&self.lane, "lane ID")?,
                expected_revision: self.expected_revision,
                body,
            },
        )))
    }
}
