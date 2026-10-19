use std::collections::btree_map::Entry;

use odin_browser::session::{ConsumedApproval, PreparedActionView, SessionError};
use odin_domain::huginn as live;
use odin_domain::{ApprovalId, CapabilityId};
use odin_huginn::browser::{BrowserActionOutcome, BrowserActionRecord};
use odin_kernel::{
    ApprovalCommand, ApprovalDecision as KernelApprovalDecision, ApprovalGate, ApprovalRedirect,
    ConsumeOutcome, DecisionOutcome,
};
use odin_ledger::approval::{Approval, ApprovalScope, NewApproval};
use odin_ledger::command::{AcceptedCommand, CommandSpec, CommandTerminalStatus};
use time::OffsetDateTime;

use super::protocol::{
    accepted_response, conflict, digest_json, durable_revision, failed_outcome, invalid_request,
    unavailable,
};
use super::{
    ActionAuthorization, AppliedApprovalDecision, BrowserCommandCoordinator, JournalDisposition,
    PendingAction, PendingActions, COMMAND_TTL,
};

const APPROVAL_TTL: time::Duration = time::Duration::minutes(5);
const BROWSER_APPROVAL_TARGET_KIND: &str = "browserSession";

impl BrowserCommandCoordinator {
    pub(super) async fn consume_takeover_expiry(&self) -> Result<(), live::HuginnProtocolError> {
        let Some(expiry) = self
            .projection
            .take_expiry_observation()
            .map_err(|_| unavailable("browserTakeoverExpiry"))?
        else {
            return Ok(());
        };
        if expiry.holder_after_expiry.is_some() || expiry.outstanding_after_expiry != 0 {
            return Err(unavailable("browserTakeoverExpiry"));
        }
        let Some(cancelled) = expiry.cancelled_action else {
            return Ok(());
        };
        let pending = {
            let mut state = self
                .pending
                .lock()
                .map_err(|_| unavailable("browserPendingLock"))?;
            let approval_id = state.by_approval.iter().find_map(|(approval_id, pending)| {
                (pending.prepared.action_id == cancelled.action_id).then(|| approval_id.clone())
            });
            approval_id.and_then(|approval_id| state.by_approval.remove(&approval_id))
        }
        .ok_or_else(|| unavailable("browserTakeoverExpiryPending"))?;
        let command_id = pending.accepted.command().id.clone();
        self.projection
            .record_action(BrowserActionRecord::from_prepared(
                command_id.clone(),
                &pending.prepared,
                BrowserActionOutcome::Abandoned,
                OffsetDateTime::now_utc(),
            ))
            .await
            .map_err(|_| unavailable("browserActionProjection"))?;
        self.complete_command(
            &pending.accepted,
            CommandTerminalStatus::Cancelled,
            live::CommandOutcome::Cancelled {
                command_id,
                reason: "browser takeover lease expired".to_owned(),
            },
        )?;
        Ok(())
    }

    pub(super) fn authorize_prepared(
        &self,
        accepted: &AcceptedCommand,
        approval_id: Option<&ApprovalId>,
        prepared: &PreparedActionView,
        issuer: &str,
    ) -> Result<ActionAuthorization, live::HuginnProtocolError> {
        let scope = ApprovalScope {
            target_kind: BROWSER_APPROVAL_TARGET_KIND.to_owned(),
            target_id: self.projection.browser().session_id().to_string(),
            capability_id: prepared.rule.capability_id.clone(),
            arguments_digest: prepared.arguments_digest,
        };
        let mut pending_state = if prepared.rule.approval_required {
            Some(
                self.pending
                    .lock()
                    .map_err(|_| unavailable("browserPendingLock"))?,
            )
        } else {
            None
        };
        let mut ledger = self
            .ledger
            .lock()
            .map_err(|_| unavailable("browserLedgerLock"))?;
        let existing = approval_id
            .map(|approval_id| {
                ledger
                    .approval(approval_id)
                    .map_err(|_| unavailable("browserApprovalLookup"))
            })
            .transpose()?
            .flatten();

        if prepared.rule.approval_required && existing.is_none() {
            let approval_id = approval_id.ok_or_else(|| {
                invalid_request(
                    "browserApprovalId",
                    "browser action requires an explicit approval ID",
                )
            })?;
            let state = pending_state
                .as_mut()
                .ok_or_else(|| unavailable("browserPendingLock"))?;
            Self::retain_pending(state, accepted, approval_id, prepared, &scope)?;
            let now = OffsetDateTime::now_utc();
            let approval = match ApprovalGate::new(&mut ledger).request(NewApproval {
                approval_id: approval_id.clone(),
                issuer: issuer.to_owned(),
                scope,
                requested_at: now,
                expires_at: now + APPROVAL_TTL,
            }) {
                Ok(approval) => approval,
                Err(_) => {
                    state.by_approval.remove(approval_id);
                    return Err(unavailable("browserApprovalRequest"));
                }
            };
            return Ok(ActionAuthorization::Pending(approval));
        }

        let expected_revision = existing.as_ref().map(|approval| approval.revision);
        let outcome = ApprovalGate::new(&mut ledger)
            .authorize_command(
                prepared.rule.effect_class,
                ApprovalCommand {
                    command_id: &accepted.command().id,
                    approval_id,
                    scope: &scope,
                    expected_revision,
                    now: OffsetDateTime::now_utc(),
                },
            )
            .map_err(|_| unavailable("browserApprovalAuthorize"))?;
        match outcome {
            ConsumeOutcome::NotRequired => {
                if prepared.rule.approval_required {
                    Ok(ActionAuthorization::Redirect)
                } else {
                    Ok(ActionAuthorization::NotRequired)
                }
            }
            ConsumeOutcome::Consumed(approval) => {
                let evidence = ConsumedApproval {
                    capability_id: approval.scope.capability_id.clone(),
                    arguments_digest: approval.scope.arguments_digest,
                };
                Ok(ActionAuthorization::Consumed { approval, evidence })
            }
            ConsumeOutcome::Redirect(ApprovalRedirect::NeedsApproval { .. }) => {
                let approval = existing.ok_or_else(|| unavailable("browserApprovalRequest"))?;
                let state = pending_state
                    .as_mut()
                    .ok_or_else(|| unavailable("browserPendingLock"))?;
                Self::retain_pending(
                    state,
                    accepted,
                    &approval.approval_id,
                    prepared,
                    &approval.scope,
                )?;
                Ok(ActionAuthorization::Pending(approval))
            }
            ConsumeOutcome::Redirect(ApprovalRedirect::Denied(_)) => {
                Ok(ActionAuthorization::Denied)
            }
            ConsumeOutcome::Redirect(_) => Ok(ActionAuthorization::Redirect),
        }
    }

    fn retain_pending(
        state: &mut PendingActions,
        accepted: &AcceptedCommand,
        approval_id: &ApprovalId,
        prepared: &PreparedActionView,
        scope: &ApprovalScope,
    ) -> Result<(), live::HuginnProtocolError> {
        if state.by_approval.len() >= state.limit.get() {
            return Err(live::HuginnProtocolError::ResourceLimit {
                limit: "browserPendingActions".to_owned(),
            });
        }
        match state.by_approval.entry(approval_id.clone()) {
            Entry::Vacant(entry) => {
                entry.insert(PendingAction {
                    accepted: accepted.clone(),
                    approval_id: approval_id.clone(),
                    prepared: prepared.clone(),
                    scope: scope.clone(),
                });
                Ok(())
            }
            Entry::Occupied(_) => Err(live::HuginnProtocolError::ResourceLimit {
                limit: "browserPendingActions".to_owned(),
            }),
        }
    }

    pub async fn shutdown_pending(&self) -> Result<(), live::HuginnProtocolError> {
        self.close_admission_and_wait().await?;
        self.consume_takeover_expiry().await?;
        let pending = {
            let mut state = self
                .pending
                .lock()
                .map_err(|_| unavailable("browserPendingLock"))?;
            std::mem::take(&mut state.by_approval)
        };
        let mut cleanup_failed = false;
        for (_, pending) in pending {
            let timeline_outcome = match self
                .projection
                .browser()
                .abandon_action(pending.prepared.action_id)
                .await
            {
                Ok(_) => BrowserActionOutcome::Abandoned,
                Err(SessionError::UnknownAction { action_id })
                    if action_id == pending.prepared.action_id =>
                {
                    BrowserActionOutcome::Abandoned
                }
                Err(_) => {
                    cleanup_failed = true;
                    BrowserActionOutcome::Unknown
                }
            };
            if self
                .projection
                .record_action(BrowserActionRecord::from_prepared(
                    pending.accepted.command().id.clone(),
                    &pending.prepared,
                    timeline_outcome,
                    OffsetDateTime::now_utc(),
                ))
                .await
                .is_err()
            {
                cleanup_failed = true;
            }
            let command_id = pending.accepted.command().id.clone();
            if self
                .complete_command(
                    &pending.accepted,
                    CommandTerminalStatus::Cancelled,
                    live::CommandOutcome::Cancelled {
                        command_id,
                        reason: "browser runtime shut down while approval was pending".to_owned(),
                    },
                )
                .is_err()
            {
                cleanup_failed = true;
            }
        }
        if cleanup_failed {
            Err(unavailable("browserPendingShutdown"))
        } else {
            Ok(())
        }
    }

    pub(super) fn publish_approval(
        &self,
        approval: &Approval,
    ) -> Result<(), live::HuginnProtocolError> {
        let revision = u64::try_from(approval.revision)
            .map_err(|_| unavailable("browserApprovalProjection"))?;
        odin_huginn::approvals::ApprovalProjection::new(self.read_model.clone())
            .publish(
                odin_huginn::approvals::ApprovalView {
                    approval_id: approval.approval_id.clone(),
                    status: approval.status,
                    issuer: approval.issuer.clone(),
                    target_kind: approval.scope.target_kind.clone(),
                    target_id: approval.scope.target_id.clone(),
                    capability_id: approval.scope.capability_id.clone(),
                    arguments_digest: approval.scope.arguments_digest,
                    requested_at: approval.requested_at,
                    expires_at: approval.expires_at,
                    decided_at: approval.decided_at,
                    decided_by: approval.decided_by.clone(),
                    consumed_by_command_id: approval.consumed_by_command_id.clone(),
                    decision_evidence_ref: approval.decision_evidence_ref.clone(),
                    revision,
                },
                std::iter::empty(),
                std::iter::empty(),
            )
            .map_err(|_| unavailable("browserApprovalProjection"))?;
        Ok(())
    }

    pub(super) async fn decide_approval(
        &self,
        device: live::DeviceId,
        command: live::ApprovalDecisionCommand,
    ) -> Result<live::HuginnResponse, live::HuginnProtocolError> {
        let now = OffsetDateTime::now_utc();
        let arguments =
            serde_json::to_value(&command).map_err(|_| unavailable("approvalCommandArguments"))?;
        let arguments_hash = digest_json(&arguments)?;
        let expected_revision = durable_revision(command.expected_revision)?;
        // Refused before anything is journaled or consumed: the same command
        let owner_preview = self
            .ledger
            .lock()
            .map_err(|_| unavailable("approvalLedgerLock"))?
            .approval(&command.approval_id)
            .map_err(|_| unavailable("approvalProjection"))?
            .is_some_and(|approval| {
                self.owner_preview
                    .contains(approval.scope.capability_id.as_str())
            });
        if command.decision == live::ApprovalDecision::Approve
            && self
                .ledger
                .lock()
                .map_err(|_| unavailable("approvalLedgerLock"))?
                .owner_preview_missing(&command.approval_id, owner_preview)
                .map_err(|_| unavailable("approvalProjection"))?
        {
            return Err(conflict(
                "approvalPreviewRequired",
                "this approval needs its complete question delivered to the owner's \
                 conversation first; it stays pending",
            ));
        }
        let spec = CommandSpec {
            id: command.command_id.clone(),
            idempotency_key: command.command_id.to_string(),
            correlation_id: command.approval_id.to_string(),
            causation_id: None,
            issuer: device.to_string(),
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
            expires_at: now + COMMAND_TTL,
        };
        let accepted = match self.journal(spec)? {
            JournalDisposition::Duplicate(response) => return Ok(response),
            JournalDisposition::Accepted(accepted) => accepted,
        };

        let (applied, pending) = {
            let mut pending_state = self
                .pending
                .lock()
                .map_err(|_| unavailable("browserPendingLock"))?;
            let mut ledger = self
                .ledger
                .lock()
                .map_err(|_| unavailable("approvalLedgerLock"))?;
            let decision = match command.decision {
                live::ApprovalDecision::Approve => KernelApprovalDecision::Approve {
                    evidence_ref: Some(format!("huginn:{}", command.command_id)),
                },
                live::ApprovalDecision::Reject => KernelApprovalDecision::Deny {
                    evidence_ref: format!("huginn:{}", command.command_id),
                },
            };
            // Native browser-session approvals decide as before; an owner
            // question that needs the complete preview binds the question
            // the owner's conversation already received.
            let applied = match ApprovalGate::new(&mut ledger)
                .decide_owner(
                    &command.approval_id,
                    expected_revision,
                    decision,
                    &device.to_string(),
                    now,
                    &odin_ledger::approval::DecisionIntake {
                        consumer_id: format!("huginn-owner:{device}"),
                        message_id: command.command_id.to_string(),
                    },
                    owner_preview,
                )
                .map_err(|_| unavailable("approvalDecision"))?
                .ok_or_else(|| unavailable("approvalDecisionAlreadyConsumed"))?
            {
                DecisionOutcome::Approved(approval) => AppliedApprovalDecision::Approved(approval),
                DecisionOutcome::Denied(_) => {
                    let approval = ledger
                        .approval(&command.approval_id)
                        .map_err(|_| unavailable("approvalProjection"))?
                        .ok_or_else(|| unavailable("approvalProjection"))?;
                    AppliedApprovalDecision::Denied(approval)
                }
                DecisionOutcome::Redirect(_) => AppliedApprovalDecision::Redirect,
            };
            let pending = if matches!(applied, AppliedApprovalDecision::Redirect) {
                None
            } else {
                pending_state.by_approval.remove(&command.approval_id)
            };
            (applied, pending)
        };

        if matches!(applied, AppliedApprovalDecision::Redirect) {
            self.complete_command(
                &accepted,
                CommandTerminalStatus::Blocked,
                failed_outcome(
                    &command.command_id,
                    "approvalRedirect",
                    "approval decision did not apply",
                ),
            )?;
            return Err(conflict(
                "approvalRedirect",
                "approval decision did not apply",
            ));
        }

        let (approval, approved) = match applied {
            AppliedApprovalDecision::Approved(approval) => (approval, true),
            AppliedApprovalDecision::Denied(approval) => (approval, false),
            AppliedApprovalDecision::Redirect => unreachable!("redirect returned above"),
        };
        let completion_error = self
            .complete_command(
                &accepted,
                CommandTerminalStatus::Completed,
                live::CommandOutcome::Applied {
                    command_id: command.command_id.clone(),
                },
            )
            .err();
        let publication_error = self.publish_approval(&approval).err();
        let pending_error = match pending {
            Some(pending) => self
                .resolve_pending_decision(pending, &approval, approved)
                .await
                .err(),
            None => None,
        };
        if let Some(error) = pending_error.or(completion_error).or(publication_error) {
            return Err(error);
        }
        Ok(accepted_response(command.command_id))
    }

    async fn resolve_pending_decision(
        &self,
        pending: PendingAction,
        approval: &Approval,
        approved: bool,
    ) -> Result<(), live::HuginnProtocolError> {
        if !approved {
            return self
                .finish_without_execution(
                    &pending.accepted,
                    &pending.prepared,
                    BrowserActionOutcome::Denied,
                    CommandTerminalStatus::Cancelled,
                    live::CommandOutcome::Cancelled {
                        command_id: pending.accepted.command().id.clone(),
                        reason: "browser approval was denied".to_owned(),
                    },
                )
                .await;
        }

        let control_revision = self.projection.browser().control_revision().await;
        let policy = self.projection.browser().policy().await;
        if control_revision != pending.prepared.control_revision
            || pending.prepared.policy_binding.revision != policy.revision()
            || pending.prepared.policy_binding.digest != policy.digest()
        {
            self.finish_without_execution(
                &pending.accepted,
                &pending.prepared,
                BrowserActionOutcome::Abandoned,
                CommandTerminalStatus::Blocked,
                failed_outcome(
                    &pending.accepted.command().id,
                    "browserBindingChanged",
                    "browser command binding changed before approval",
                ),
            )
            .await?;
            return Err(conflict(
                "browserBindingChanged",
                "browser command binding changed before approval",
            ));
        }

        let consumed = match self.ledger.lock() {
            Ok(mut ledger) => ApprovalGate::new(&mut ledger)
                .authorize_command(
                    pending.prepared.rule.effect_class,
                    ApprovalCommand {
                        command_id: &pending.accepted.command().id,
                        approval_id: Some(&pending.approval_id),
                        scope: &pending.scope,
                        expected_revision: Some(approval.revision),
                        now: OffsetDateTime::now_utc(),
                    },
                )
                .map_err(|_| unavailable("browserApprovalConsume")),
            Err(_) => Err(unavailable("browserLedgerLock")),
        };
        let consumed = match consumed {
            Ok(ConsumeOutcome::Consumed(consumed)) => consumed,
            Ok(ConsumeOutcome::NotRequired | ConsumeOutcome::Redirect(_)) => {
                self.finish_without_execution(
                    &pending.accepted,
                    &pending.prepared,
                    BrowserActionOutcome::Abandoned,
                    CommandTerminalStatus::Blocked,
                    failed_outcome(
                        &pending.accepted.command().id,
                        "browserApprovalConsume",
                        "browser approval could not be consumed exactly",
                    ),
                )
                .await?;
                return Err(conflict(
                    "browserApprovalConsume",
                    "browser approval could not be consumed exactly",
                ));
            }
            Err(error) => {
                let cleanup_error = self
                    .finish_without_execution(
                        &pending.accepted,
                        &pending.prepared,
                        BrowserActionOutcome::Abandoned,
                        CommandTerminalStatus::Blocked,
                        failed_outcome(
                            &pending.accepted.command().id,
                            "browserApprovalConsume",
                            "browser approval could not be consumed exactly",
                        ),
                    )
                    .await
                    .err();
                return Err(cleanup_error.unwrap_or(error));
            }
        };
        let publication_error = self.publish_approval(&consumed).err();
        let evidence = ConsumedApproval {
            capability_id: consumed.scope.capability_id.clone(),
            arguments_digest: consumed.scope.arguments_digest,
        };
        let execution_error = self
            .execute_prepared(&pending.accepted, &pending.prepared, Some(evidence))
            .await
            .err();
        if let Some(error) = execution_error.or(publication_error) {
            return Err(error);
        }
        Ok(())
    }
}
