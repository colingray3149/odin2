use std::io::Write;
use std::path::{Path, PathBuf};

use clap::Args;
use odin_domain::{ApprovalId, ApprovalStatus};
use odin_kernel::{
    ApprovalDecision, ApprovalGate, ApprovalRedirect, DecisionOutcome, DenialEvidence,
};
use odin_ledger::Ledger;
use odin_registry::ObjectConfig;
use serde::Serialize;
use time::OffsetDateTime;

use super::{load_registry_objects, resolve_odin_root};
use crate::RunStatus;

#[derive(Debug, Args)]
pub(crate) struct DecisionTarget {
    #[arg(long, value_name = "PATH")]
    pub(crate) state_root: PathBuf,
    #[arg(long, value_name = "ID")]
    pub(crate) approval: String,
    #[arg(long, value_name = "N")]
    pub(crate) expected_revision: i64,
    #[arg(long, value_name = "ACTOR")]
    pub(crate) decider: String,
    #[arg(long)]
    pub(crate) json: bool,
}

#[derive(Debug, Args)]
pub(crate) struct ApproveArgs {
    #[command(flatten)]
    pub(crate) target: DecisionTarget,
    #[arg(long, value_name = "REF")]
    pub(crate) evidence: Option<String>,
}

#[derive(Debug, Args)]
pub(crate) struct RejectArgs {
    #[command(flatten)]
    pub(crate) target: DecisionTarget,
    #[arg(long, value_name = "REF")]
    pub(crate) evidence: String,
}

struct SeatMenuEntry {
    id: String,
    description: String,
    categories: String,
}

#[derive(Debug, Serialize)]
struct DecisionReport {
    schema: &'static str,
    approval: String,
    status: Option<ApprovalStatus>,
    revision: Option<i64>,
    decider: Option<String>,
    evidence: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    redirect: Option<DecisionRedirect>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase", tag = "kind")]
enum DecisionRedirect {
    NeedsApproval,
    Denied,
    Expired,
    AlreadyConsumed {
        command: String,
    },
    Cancelled,
    ScopeMismatch,
    AlreadyApproved,
    NotFound,
    StaleRevision {
        #[serde(rename = "expectedRevision")]
        expected_revision: i64,
        #[serde(rename = "actualRevision")]
        actual_revision: i64,
    },
    PreviewRequired,
}

pub(crate) fn decide(
    target: DecisionTarget,
    decision: ApprovalDecision,
    output: &mut impl Write,
) -> Result<RunStatus, String> {
    let approval_id = ApprovalId::new(target.approval)
        .map_err(|error| format!("invalid approval ID: {error}"))?;
    if target.decider.trim().is_empty() {
        return Err("decider must not be empty".to_owned());
    }

    let ledger_path = target.state_root.join("ledger.sqlite3");
    let mut ledger = Ledger::open(&ledger_path)
        .map_err(|error| format!("could not open ledger {}: {error}", ledger_path.display()))?;
    let stored = ledger
        .approval(&approval_id)
        .map_err(|error| format!("could not read approval {approval_id}: {error}"))?;
    let owner_preview = match stored.as_ref() {
        Some(approval) => {
            declares_owner_preview(&target.state_root, approval.scope.capability_id.as_str())?
        }
        None => false,
    };
    let preview = stored.is_some_and(|approval| {
        odin_kernel::approval::requires_owner_preview(&approval.scope, owner_preview)
    });
    let mut gate = ApprovalGate::new(&mut ledger);
    let outcome = if preview {
        // Owner consent binds the complete question the owner's conversation
        // already showed; without one the request stays pending.
        let identity = format!(
            "{}\u{0}{approval_id}\u{0}{}",
            target.decider, target.expected_revision
        );
        let intake = odin_kernel::approval::DecisionIntake {
            consumer_id: "operator-cli".to_owned(),
            message_id: format!(
                "decision-{}",
                odin_domain::Digest::hash(identity.as_bytes())
            ),
        };
        gate.decide_owner(
            &approval_id,
            target.expected_revision,
            decision,
            &target.decider,
            OffsetDateTime::now_utc(),
            &intake,
            owner_preview,
        )
        .map_err(|error| format!("could not decide approval {approval_id}: {error}"))?
        .ok_or_else(|| format!("this exact decision on approval {approval_id} was already made"))?
    } else {
        gate.decide(
            &approval_id,
            target.expected_revision,
            decision,
            &target.decider,
            OffsetDateTime::now_utc(),
        )
        .map_err(|error| format!("could not decide approval {approval_id}: {error}"))?
    };
    let (report, status) = decision_report(&approval_id, outcome);
    write_decision_report(output, &report, target.json)?;
    Ok(status)
}

fn declares_owner_preview(state_root: &Path, capability: &str) -> Result<bool, String> {
    let path = state_root.join("registry/snapshot.json");
    let snapshot = odin_registry::SnapshotStore::new(path)
        .load_verified()
        .map_err(|error| format!("{capability}: {error}"))?;
    let contracts = odin_cli::runtime_bindings::operation_contracts(&snapshot.objects)
        .map_err(|error| format!("{capability}: {error}"))?;
    let id = odin_domain::CapabilityId::new(capability)
        .map_err(|error| format!("{capability}: {error}"))?;
    let Some(contract) = contracts.get(&id) else {
        return Err(format!(
            "{capability}: capability is not admitted by the state-root snapshot"
        ));
    };
    Ok(contract.preview.is_some())
}

fn decision_report(
    requested_approval: &ApprovalId,
    outcome: DecisionOutcome,
) -> (DecisionReport, RunStatus) {
    match outcome {
        DecisionOutcome::Approved(approval) => (
            DecisionReport {
                schema: "odin.approval-decision.v1",
                approval: approval.approval_id.to_string(),
                status: Some(approval.status),
                revision: Some(approval.revision),
                decider: approval.decided_by,
                evidence: approval.decision_evidence_ref,
                redirect: None,
            },
            RunStatus::Success,
        ),
        DecisionOutcome::Denied(evidence) => (denied_report(evidence, None), RunStatus::Success),
        DecisionOutcome::Redirect(redirect) => (
            redirect_report(requested_approval, redirect),
            RunStatus::Redirect,
        ),
    }
}

fn denied_report(evidence: DenialEvidence, redirect: Option<DecisionRedirect>) -> DecisionReport {
    DecisionReport {
        schema: "odin.approval-decision.v1",
        approval: evidence.approval_id.to_string(),
        status: Some(ApprovalStatus::Denied),
        revision: Some(evidence.revision),
        decider: Some(evidence.decided_by),
        evidence: Some(evidence.evidence_ref),
        redirect,
    }
}

fn redirect_report(requested_approval: &ApprovalId, redirect: ApprovalRedirect) -> DecisionReport {
    let mut report = DecisionReport {
        schema: "odin.approval-decision.v1",
        approval: requested_approval.to_string(),
        status: None,
        revision: None,
        decider: None,
        evidence: None,
        redirect: None,
    };
    report.redirect = Some(match redirect {
        ApprovalRedirect::NeedsApproval { .. } => DecisionRedirect::NeedsApproval,
        ApprovalRedirect::Denied(evidence) => {
            return denied_report(evidence, Some(DecisionRedirect::Denied));
        }
        ApprovalRedirect::Expired { .. } => {
            report.status = Some(ApprovalStatus::Expired);
            DecisionRedirect::Expired
        }
        ApprovalRedirect::AlreadyConsumed { command_id, .. } => {
            report.status = Some(ApprovalStatus::Consumed);
            DecisionRedirect::AlreadyConsumed {
                command: command_id.to_string(),
            }
        }
        ApprovalRedirect::Cancelled { .. } => {
            report.status = Some(ApprovalStatus::Cancelled);
            DecisionRedirect::Cancelled
        }
        ApprovalRedirect::ScopeMismatch { .. } => DecisionRedirect::ScopeMismatch,
        ApprovalRedirect::AlreadyApproved { .. } => {
            report.status = Some(ApprovalStatus::Approved);
            DecisionRedirect::AlreadyApproved
        }
        ApprovalRedirect::NotFound { .. } => DecisionRedirect::NotFound,
        ApprovalRedirect::StaleRevision {
            expected_revision,
            actual_revision,
            ..
        } => {
            report.revision = Some(actual_revision);
            DecisionRedirect::StaleRevision {
                expected_revision,
                actual_revision,
            }
        }
        ApprovalRedirect::PreviewRequired { .. } => {
            report.status = Some(ApprovalStatus::Requested);
            DecisionRedirect::PreviewRequired
        }
    });
    report
}

fn write_decision_report(
    output: &mut impl Write,
    report: &DecisionReport,
    json: bool,
) -> Result<(), String> {
    if json {
        serde_json::to_writer(&mut *output, report)
            .map_err(|error| format!("could not serialize decision: {error}"))?;
        writeln!(output).map_err(|error| format!("could not write decision: {error}"))
    } else if let Some(redirect) = &report.redirect {
        writeln!(
            output,
            "approval {}: redirect {redirect:?}",
            report.approval
        )
        .map_err(|error| format!("could not write decision: {error}"))
    } else {
        let status = report.status.map(approval_status_name).unwrap_or("unknown");
        let revision = report
            .revision
            .map_or_else(|| "unknown".to_owned(), |revision| revision.to_string());
        let decider = report.decider.as_deref().unwrap_or("unknown");
        let evidence = report.evidence.as_deref().unwrap_or("none");
        writeln!(
            output,
            "approval {}: {status} at revision {revision} by {decider}; evidence {evidence}",
            report.approval
        )
        .map_err(|error| format!("could not write decision: {error}"))
    }
}

fn approval_status_name(status: ApprovalStatus) -> &'static str {
    match status {
        ApprovalStatus::Requested => "requested",
        ApprovalStatus::Approved => "approved",
        ApprovalStatus::Denied => "denied",
        ApprovalStatus::Expired => "expired",
        ApprovalStatus::Consumed => "consumed",
        ApprovalStatus::Cancelled => "cancelled",
    }
}

pub(crate) fn print_seat_menu(output: &mut impl Write) -> Result<(), String> {
    let registry_root = resolve_odin_root()?.join("registry");
    let objects = load_registry_objects(&registry_root)?;

    let mut seats = objects
        .into_iter()
        .filter_map(|object| match object.config {
            ObjectConfig::Seat(seat) if seat.enabled => Some(SeatMenuEntry {
                id: object.id,
                description: seat.description,
                categories: seat.categories.into_iter().collect::<Vec<_>>().join(", "),
            }),
            _ => None,
        })
        .collect::<Vec<_>>();
    seats.sort_by(|left, right| left.id.cmp(&right.id));
    if seats.is_empty() {
        return Err("registry contains no enabled seats".to_owned());
    }

    for (index, seat) in seats.iter().enumerate() {
        writeln!(
            output,
            "{}. {} — {} — {}",
            index + 1,
            seat.id,
            seat.categories,
            seat.description
        )
        .map_err(|error| format!("could not write seat menu: {error}"))?;
    }
    Ok(())
}
