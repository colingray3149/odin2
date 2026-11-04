//! The `devices` command domain: device listing, loopback-local pairing,
//! and revocation.

use std::path::PathBuf;

use clap::{Args, Subcommand};
use odin_domain::huginn as live;

use super::surface::{snapshot_plan, HuginnIdArgs, HuginnPageArgs, HuginnPlan};

#[derive(Debug, Args)]
pub(crate) struct HuginnDevicesArgs {
    #[command(subcommand)]
    pub(super) command: HuginnDevicesCommand,
}

#[derive(Debug, Args)]
pub(super) struct HuginnDevicePairArgs {
    #[arg(long, value_name = "LABEL")]
    label: String,
    #[arg(long, value_name = "UUID")]
    node: String,
    /// Revoke active local device authority and replace the stored credential.
    #[arg(long)]
    force: bool,
    /// Enroll another device (a phone): its credential is written to this new
    /// 0600 file and this workstation's own pairing is left alone.
    #[arg(long, value_name = "PATH")]
    out: Option<PathBuf>,
}

#[derive(Debug, Subcommand)]
pub(super) enum HuginnDevicesCommand {
    List(HuginnPageArgs),
    Pair(HuginnDevicePairArgs),
    Revoke(HuginnIdArgs),
}

impl HuginnDevicesCommand {
    pub(super) fn into_plan(self) -> Result<HuginnPlan, String> {
        match self {
            Self::List(page) => Ok(snapshot_plan(live::ObjectKind::Device, page)),
            Self::Pair(arguments) => Ok(HuginnPlan::PairDevice {
                label: arguments.label,
                node: arguments.node,
                force: arguments.force,
                out: arguments.out,
            }),
            Self::Revoke(arguments) => Ok(HuginnPlan::RevokeDevice(
                live::DeviceId::parse(&arguments.id).map_err(|error| error.to_string())?,
            )),
        }
    }
}
