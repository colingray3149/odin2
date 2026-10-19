//! Complete-preview consent and command replay for device-submitted owner decisions.

use odin_domain::{huginn as live, CapabilityId, Digest};
use odin_kernel::{
    ApprovalDecision as KernelApprovalDecision, ApprovalGate, ApprovalRedirect, DecisionOutcome,
};
use odin_ledger::command::{
    CommandOutcome as LedgerCommandOutcome, CommandSpec, CommandTerminalStatus, RecordCommand,
};
use time::OffsetDateTime;

use super::{unavailable, RuntimeCommandPort};

/// A device decision on an owner question whose complete preview has not
/// reached the owner's conversation: nothing is decided and it stays pending.
fn approval_preview_required() -> live::HuginnProtocolError {
    live::HuginnProtocolError::Conflict {
        code: "approvalPreviewRequired".to_owned(),
        message: "this approval needs its complete question delivered to the owner's \
                  conversation first; it stays pending"
            .to_owned(),
    }
}

impl RuntimeCommandPort {
    pub(super) fn decide_approval(
        &self,
        command: live::ApprovalDecisionCommand,
        device: live::DeviceId,
    ) -> Result<live::HuginnResponse, live::HuginnProtocolError> {
        let now = OffsetDateTime::now_utc();
        let actor = device.to_string();
        let arguments =
            serde_json::to_value(&command).map_err(|_| unavailable("approvalCommand"))?;
        let arguments_hash = Digest::hash(
            &serde_json::to_vec(&arguments).map_err(|_| unavailable("approvalCommand"))?,
        );
        let expected_revision = i64::try_from(command.expected_revision).map_err(|_| {
            live::HuginnProtocolError::InvalidRequest {
                code: "approvalRevision".to_owned(),
                message: "approval revision does not fit the durable ledger".to_owned(),
            }
        })?;
        let spec = CommandSpec {
            id: command.command_id.clone(),
            idempotency_key: command.command_id.to_string(),
            correlation_id: command.approval_id.to_string(),
            causation_id: None,
            issuer: actor.clone(),
            approval_id: Some(command.approval_id.clone()),
            target_kind: "approval".to_owned(),
            target_id: command.approval_id.to_string(),
            capability_id: CapabilityId::new("approval.decide")
                .map_err(|_| unavailable("approvalCapability"))?,
            capability_version: 1,
            arguments_hash,
            arguments,
            expected_desired_revision: Some(expected_revision),
            issued_at: now,
            expires_at: now + time::Duration::minutes(5),
        };
        let mut ledger = self
            .ledger
            .lock()
            .map_err(|_| unavailable("approvalLedgerLock"))?;
        let owner_preview = ledger
            .approval(&command.approval_id)
            .map_err(|_| unavailable("approvalProjection"))?
            .is_some_and(|approval| {
                self.owner_preview
                    .contains(approval.scope.capability_id.as_str())
            });
        if command.decision == live::ApprovalDecision::Approve
            && ledger
                .owner_preview_missing(&command.approval_id, owner_preview)
                .map_err(|_| unavailable("approvalProjection"))?
        {
            return Err(approval_preview_required());
        }
        let recorded = match ledger
            .record_command(&spec)
            .map_err(|_| unavailable("approvalCommandJournal"))?
        {
            RecordCommand::Existing(recorded) => {
                let stored = recorded.command();
                if stored.arguments_hash != spec.arguments_hash
                    || stored.target_id != spec.target_id
                    || stored.expected_desired_revision != spec.expected_desired_revision
                {
                    return Err(live::HuginnProtocolError::Conflict {
                        code: "commandIdReuse".to_owned(),
                        message: "command ID is already bound to different approval arguments"
                            .to_owned(),
                    });
                }
                let prior_outcome = stored
                    .terminal_result
                    .clone()
                    .and_then(|value| serde_json::from_value(value).ok())
                    .map(Box::new);
                return Ok(live::HuginnResponse::Command(
                    live::CommandReceipt::Duplicate {
                        command_id: command.command_id,
                        prior_outcome,
                    },
                ));
            }
            RecordCommand::Inserted(recorded) => recorded,
        };
        let accepted = ledger
            .accept_command(&recorded, recorded.command().revision, now)
            .map_err(|_| unavailable("approvalCommandAccept"))?;
        let gate_decision = match command.decision {
            live::ApprovalDecision::Approve => KernelApprovalDecision::Approve {
                evidence_ref: Some(format!("huginn:{}", command.command_id)),
            },
            live::ApprovalDecision::Reject => KernelApprovalDecision::Deny {
                evidence_ref: format!("huginn:{}", command.command_id),
            },
        };
        // A device shows no exact effect preview: owner consent that needs one
        // binds the complete question the conversation already delivered.
        let decision = ApprovalGate::new(&mut ledger)
            .decide_owner(
                &command.approval_id,
                expected_revision,
                gate_decision,
                &actor,
                now,
                &odin_ledger::approval::DecisionIntake {
                    consumer_id: format!("huginn-owner:{device}"),
                    message_id: command.command_id.to_string(),
                },
                owner_preview,
            )
            .map_err(|_| unavailable("approvalDecision"))?
            .ok_or_else(|| unavailable("approvalDecisionAlreadyConsumed"))?;
        match decision {
            DecisionOutcome::Approved(_) | DecisionOutcome::Denied(_) => {
                let outcome = live::CommandOutcome::Applied {
                    command_id: command.command_id.clone(),
                };
                ledger
                    .complete_command(
                        &accepted,
                        &LedgerCommandOutcome {
                            status: CommandTerminalStatus::Completed,
                            result: serde_json::to_value(&outcome)
                                .map_err(|_| unavailable("approvalOutcome"))?,
                        },
                        accepted.command().revision,
                        now,
                    )
                    .map_err(|_| unavailable("approvalCommandComplete"))?;
                let approval = ledger
                    .approval(&command.approval_id)
                    .map_err(|_| unavailable("approvalProjection"))?
                    .ok_or_else(|| unavailable("approvalProjection"))?;
                self.publish_approval(&approval)?;
                Ok(live::HuginnResponse::Command(
                    live::CommandReceipt::Accepted {
                        command_id: command.command_id,
                    },
                ))
            }
            DecisionOutcome::Redirect(redirect) => {
                let error = match redirect {
                    ApprovalRedirect::PreviewRequired { .. } => approval_preview_required(),
                    redirect => live::HuginnProtocolError::Conflict {
                        code: "approvalRedirect".to_owned(),
                        message: format!("{redirect:?}"),
                    },
                };
                ledger
                    .complete_command(
                        &accepted,
                        &LedgerCommandOutcome {
                            status: CommandTerminalStatus::Blocked,
                            result: serde_json::to_value(&error)
                                .map_err(|_| unavailable("approvalOutcome"))?,
                        },
                        accepted.command().revision,
                        now,
                    )
                    .map_err(|_| unavailable("approvalCommandComplete"))?;
                Err(error)
            }
        }
    }
}
