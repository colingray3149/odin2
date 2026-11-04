//! The `approvals` command domain: listing, inspection, and typed approve
//! and reject decisions.

use std::num::NonZeroU16;

use super::surface::{
    parse_id, search_plan, snapshot_plan, HuginnIdArgs, HuginnPageArgs, HuginnPlan,
};
use clap::{Args, Subcommand};
use odin_domain::huginn as live;

#[derive(Debug, Args)]
pub(crate) struct HuginnApprovalsArgs {
    #[command(subcommand)]
    pub(super) command: HuginnApprovalsCommand,
}

#[derive(Debug, Subcommand)]
pub(super) enum HuginnApprovalsCommand {
    List(HuginnPageArgs),
    Show(HuginnIdArgs),
    Approve(HuginnApprovalDecisionArgs),
    Reject(HuginnApprovalDecisionArgs),
}

#[derive(Debug, Args)]
pub(super) struct HuginnApprovalDecisionArgs {
    #[arg(long, value_name = "ID")]
    command_id: String,
    #[arg(long, value_name = "ID")]
    approval: String,
    #[arg(long, value_name = "REVISION")]
    expected_revision: u64,
}

impl HuginnApprovalsCommand {
    pub(super) fn into_plan(self) -> Result<HuginnPlan, String> {
        match self {
            Self::List(page) => Ok(snapshot_plan(live::ObjectKind::Approval, page)),
            Self::Show(arguments) => Ok(search_plan(
                live::ObjectKind::Approval,
                arguments.id,
                NonZeroU16::new(1).expect("one is non-zero"),
            )),
            Self::Approve(arguments) => approval_plan(arguments, live::ApprovalDecision::Approve),
            Self::Reject(arguments) => approval_plan(arguments, live::ApprovalDecision::Reject),
        }
    }
}

fn approval_plan(
    arguments: HuginnApprovalDecisionArgs,
    decision: live::ApprovalDecision,
) -> Result<HuginnPlan, String> {
    Ok(HuginnPlan::request(live::HuginnRequest::ApprovalDecision(
        live::ApprovalDecisionCommand {
            command_id: parse_id(&arguments.command_id, "command ID")?,
            approval_id: parse_id(&arguments.approval, "approval ID")?,
            expected_revision: arguments.expected_revision,
            decision,
        },
    )))
}
