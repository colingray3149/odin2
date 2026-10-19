//! Durable, exact-scope approval authority.

use odin_domain::{ApprovalId, ApprovalStatus, CommandId, EffectClass};
pub use odin_ledger::approval::{
    requires_owner_preview, Approval, ApprovalDecision, ApprovalScope, DecisionIntake, NewApproval,
};
use odin_ledger::{
    approval::{ConsumeApproval, DecideApproval, ExpireApproval},
    decode_utc, Ledger, LedgerError,
};
use time::OffsetDateTime;

use crate::capability::ApprovalRequirement;
use crate::{KernelError, KernelResult};

/// Compare scope structurally so callers cannot widen an approval.
#[derive(Clone, Copy, Debug)]
pub struct ApprovalCommand<'a> {
    pub command_id: &'a CommandId,
    pub approval_id: Option<&'a ApprovalId>,
    pub scope: &'a ApprovalScope,
    pub expected_revision: Option<i64>,
    pub now: OffsetDateTime,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DenialEvidence {
    pub approval_id: ApprovalId,
    pub evidence_ref: String,
    pub decided_by: String,
    pub decided_at: OffsetDateTime,
    pub revision: i64,
}

/// Redirects must be handled before dispatching an effect.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ApprovalRedirect {
    NeedsApproval {
        approval_id: Option<ApprovalId>,
    },
    Denied(DenialEvidence),
    Expired {
        approval_id: ApprovalId,
    },
    AlreadyConsumed {
        approval_id: ApprovalId,
        command_id: CommandId,
    },
    Cancelled {
        approval_id: ApprovalId,
    },
    ScopeMismatch {
        approval_id: ApprovalId,
    },
    AlreadyApproved {
        approval_id: ApprovalId,
    },
    NotFound {
        approval_id: ApprovalId,
    },
    StaleRevision {
        approval_id: ApprovalId,
        expected_revision: i64,
        actual_revision: i64,
    },
    /// Keep consent pending until its complete question reaches the owner.
    PreviewRequired {
        approval_id: ApprovalId,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DecisionOutcome {
    Approved(Approval),
    Denied(DenialEvidence),
    Redirect(ApprovalRedirect),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ExpireOutcome {
    Expired(Approval),
    NotDue(Approval),
    Redirect(ApprovalRedirect),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExpirySweep {
    pub expired: Vec<Approval>,
    pub redirects: Vec<ApprovalRedirect>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ConsumeOutcome {
    NotRequired,
    Consumed(Approval),
    Redirect(ApprovalRedirect),
}

pub struct ApprovalGate<'ledger> {
    ledger: &'ledger mut Ledger,
}

impl<'ledger> ApprovalGate<'ledger> {
    pub fn new(ledger: &'ledger mut Ledger) -> Self {
        Self { ledger }
    }

    pub fn request(&mut self, request: NewApproval) -> KernelResult<Approval> {
        validate_request(&request)?;
        Ok(self.ledger.request_approval(request)?)
    }

    /// Approves or denies a request at exactly the revision the decider saw.
    pub fn decide(
        &mut self,
        approval_id: &ApprovalId,
        expected_revision: i64,
        decision: ApprovalDecision,
        decided_by: &str,
        decided_at: OffsetDateTime,
    ) -> KernelResult<DecisionOutcome> {
        validate_decision(&decision, decided_by)?;

        let outcome = self.ledger.decide_approval(
            approval_id,
            decision,
            decided_by,
            decided_at,
            expected_revision,
        );
        project_decision(approval_id, outcome)
    }

    /// Consume intake atomically with the decision; `None` means the message was already consumed.
    #[allow(clippy::too_many_arguments)]
    pub fn decide_consuming_intake(
        &mut self,
        approval_id: &ApprovalId,
        expected_revision: i64,
        decision: ApprovalDecision,
        decided_by: &str,
        decided_at: OffsetDateTime,
        intake: &DecisionIntake,
        owner_preview: bool,
    ) -> KernelResult<Option<DecisionOutcome>> {
        validate_decision(&decision, decided_by)?;
        match self.ledger.decide_approval_consuming_intake(
            approval_id,
            decision,
            decided_by,
            decided_at,
            expected_revision,
            intake,
            owner_preview,
        ) {
            Ok(Some(outcome)) => project_decision(approval_id, Ok(outcome)).map(Some),
            Ok(None) => Ok(None),
            Err(error) => project_decision(approval_id, Err(error)).map(Some),
        }
    }

    /// Surfaces without a preview require the complete question to have reached the owner first.
    #[allow(clippy::too_many_arguments)]
    pub fn decide_owner(
        &mut self,
        approval_id: &ApprovalId,
        expected_revision: i64,
        decision: ApprovalDecision,
        decided_by: &str,
        decided_at: OffsetDateTime,
        intake: &DecisionIntake,
        owner_preview: bool,
    ) -> KernelResult<Option<DecisionOutcome>> {
        let decision = match (decision, self.ledger.approval(approval_id)?) {
            (ApprovalDecision::Approve { .. }, Some(approval))
                if requires_owner_preview(&approval.scope, owner_preview) =>
            {
                match self.ledger.owner_preview_evidence(&approval)? {
                    Some(evidence) => ApprovalDecision::Approve {
                        evidence_ref: Some(evidence),
                    },
                    None => {
                        return Ok(Some(DecisionOutcome::Redirect(
                            ApprovalRedirect::PreviewRequired {
                                approval_id: approval_id.clone(),
                            },
                        )))
                    }
                }
            }
            (decision, _) => decision,
        };
        self.decide_consuming_intake(
            approval_id,
            expected_revision,
            decision,
            decided_by,
            decided_at,
            intake,
            owner_preview,
        )
    }

    /// Expires one approval at the revision observed by the caller.
    pub fn expire(
        &mut self,
        approval_id: &ApprovalId,
        expected_revision: i64,
        now: OffsetDateTime,
    ) -> KernelResult<ExpireOutcome> {
        match self
            .ledger
            .expire_approval(approval_id, now, expected_revision)
        {
            Ok(ExpireApproval::Expired(approval)) => Ok(ExpireOutcome::Expired(approval)),
            Ok(ExpireApproval::NotDue(approval)) => Ok(ExpireOutcome::NotDue(approval)),
            Ok(ExpireApproval::NotFound) => {
                Ok(ExpireOutcome::Redirect(ApprovalRedirect::NotFound {
                    approval_id: approval_id.clone(),
                }))
            }
            Ok(ExpireApproval::Final(approval)) => {
                Ok(ExpireOutcome::Redirect(redirect_for_status(approval)?))
            }
            Err(error) => match stale_redirect(approval_id, error) {
                Ok(redirect) => Ok(ExpireOutcome::Redirect(redirect)),
                Err(error) => Err(error),
            },
        }
    }

    pub fn sweep_expired(&mut self, now: OffsetDateTime) -> KernelResult<ExpirySweep> {
        let due = {
            let mut statement = self
                .ledger
                .connection()
                .prepare(
                    "SELECT approval_id, revision, expires_at
                     FROM approvals
                     WHERE status IN ('requested', 'approved')
                     ORDER BY approval_id",
                )
                .map_err(LedgerError::from)?;
            let rows = statement
                .query_map([], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, String>(2)?,
                    ))
                })
                .map_err(LedgerError::from)?;
            let mut due = Vec::new();
            for row in rows {
                let (raw_id, revision, raw_expiry) = row.map_err(LedgerError::from)?;
                if now >= decode_utc(&raw_expiry)? {
                    let approval_id = ApprovalId::parse(&raw_id)
                        .map_err(|error| invalid_record(error.to_string()))?;
                    due.push((approval_id, revision));
                }
            }
            due
        };

        let mut sweep = ExpirySweep {
            expired: Vec::with_capacity(due.len()),
            redirects: Vec::new(),
        };
        for (approval_id, revision) in due {
            match self.expire(&approval_id, revision, now)? {
                ExpireOutcome::Expired(approval) => sweep.expired.push(approval),
                ExpireOutcome::NotDue(approval) => {
                    sweep.redirects.push(redirect_for_status(approval)?);
                }
                ExpireOutcome::Redirect(redirect) => sweep.redirects.push(redirect),
            }
        }
        Ok(sweep)
    }

    /// R3 requires approval; lower risk classes do not consume it.
    pub fn authorize_command(
        &mut self,
        effect_class: EffectClass,
        command: ApprovalCommand<'_>,
    ) -> KernelResult<ConsumeOutcome> {
        if effect_class != EffectClass::R3 {
            return Ok(ConsumeOutcome::NotRequired);
        }
        self.consume_exact(command)
    }

    /// Explicit operator approval also gates lower risk contracts; R3 is always gated.
    pub fn authorize_capability_command(
        &mut self,
        effect_class: EffectClass,
        approval: ApprovalRequirement,
        command: ApprovalCommand<'_>,
    ) -> KernelResult<ConsumeOutcome> {
        if effect_class != EffectClass::R3 && approval != ApprovalRequirement::Operator {
            return Ok(ConsumeOutcome::NotRequired);
        }
        self.consume_exact(command)
    }

    fn consume_exact(&mut self, command: ApprovalCommand<'_>) -> KernelResult<ConsumeOutcome> {
        let Some(approval_id) = command.approval_id else {
            return Ok(ConsumeOutcome::Redirect(ApprovalRedirect::NeedsApproval {
                approval_id: None,
            }));
        };
        let Some(expected_revision) = command.expected_revision else {
            return Ok(ConsumeOutcome::Redirect(ApprovalRedirect::NeedsApproval {
                approval_id: Some(approval_id.clone()),
            }));
        };

        match self.ledger.consume_approval(
            approval_id,
            command.scope,
            command.command_id,
            command.now,
            expected_revision,
        ) {
            Ok(ConsumeApproval::Consumed(approval)) => Ok(ConsumeOutcome::Consumed(approval)),
            Ok(ConsumeApproval::NotFound) => {
                Ok(ConsumeOutcome::Redirect(ApprovalRedirect::NotFound {
                    approval_id: approval_id.clone(),
                }))
            }
            Ok(ConsumeApproval::ScopeMismatch(approval)) => {
                Ok(ConsumeOutcome::Redirect(ApprovalRedirect::ScopeMismatch {
                    approval_id: approval.approval_id,
                }))
            }
            Ok(ConsumeApproval::NotAuthorized(approval)) => {
                Ok(ConsumeOutcome::Redirect(redirect_for_status(approval)?))
            }
            Ok(ConsumeApproval::Expired(approval)) => {
                Ok(ConsumeOutcome::Redirect(ApprovalRedirect::Expired {
                    approval_id: approval.approval_id,
                }))
            }
            Err(error) => match stale_redirect(approval_id, error) {
                Ok(redirect) => Ok(ConsumeOutcome::Redirect(redirect)),
                Err(error) => Err(error),
            },
        }
    }
}

fn validate_decision(decision: &ApprovalDecision, decided_by: &str) -> KernelResult<()> {
    if decided_by.trim().is_empty() {
        return Err(invalid_authority("the deciding actor must not be empty"));
    }
    if matches!(
        decision,
        ApprovalDecision::Deny { evidence_ref } if evidence_ref.trim().is_empty()
    ) {
        return Err(invalid_authority(
            "a denial must carry an evidence reference",
        ));
    }
    Ok(())
}

fn project_decision(
    approval_id: &ApprovalId,
    outcome: Result<DecideApproval, LedgerError>,
) -> KernelResult<DecisionOutcome> {
    match outcome {
        Ok(DecideApproval::Decided(approval)) => match approval.status {
            ApprovalStatus::Approved => Ok(DecisionOutcome::Approved(approval)),
            ApprovalStatus::Denied => Ok(DecisionOutcome::Denied(denial_evidence(&approval)?)),
            status => Err(invalid_record(format!(
                "decision returned status {status:?}"
            ))),
        },
        Ok(DecideApproval::NotFound) => Ok(DecisionOutcome::Redirect(ApprovalRedirect::NotFound {
            approval_id: approval_id.clone(),
        })),
        Ok(DecideApproval::NotRequested(approval)) => {
            Ok(DecisionOutcome::Redirect(redirect_for_status(approval)?))
        }
        Ok(DecideApproval::PreviewRequired(approval)) => Ok(DecisionOutcome::Redirect(
            ApprovalRedirect::PreviewRequired {
                approval_id: approval.approval_id,
            },
        )),
        Err(error) => match stale_redirect(approval_id, error) {
            Ok(redirect) => Ok(DecisionOutcome::Redirect(redirect)),
            Err(error) => Err(error),
        },
    }
}

fn validate_request(request: &NewApproval) -> KernelResult<()> {
    if request.issuer.trim().is_empty() {
        return Err(invalid_authority("the issuer must not be empty"));
    }
    if request.scope.target_kind.trim().is_empty() {
        return Err(invalid_authority("the target kind must not be empty"));
    }
    if request.scope.target_id.trim().is_empty() {
        return Err(invalid_authority("the target id must not be empty"));
    }
    if request.expires_at <= request.requested_at {
        return Err(invalid_authority("expiry must be after request time"));
    }
    Ok(())
}

fn stale_redirect(approval_id: &ApprovalId, error: LedgerError) -> KernelResult<ApprovalRedirect> {
    match error {
        LedgerError::StaleActor {
            expected_revision,
            actual_revision,
            ..
        } => Ok(ApprovalRedirect::StaleRevision {
            approval_id: approval_id.clone(),
            expected_revision,
            actual_revision,
        }),
        other => Err(other.into()),
    }
}

fn denial_evidence(approval: &Approval) -> KernelResult<DenialEvidence> {
    let evidence_ref = approval.decision_evidence_ref.clone().ok_or_else(|| {
        invalid_record(format!(
            "denied approval {} has no evidence reference",
            approval.approval_id
        ))
    })?;
    if evidence_ref.trim().is_empty() {
        return Err(invalid_record(format!(
            "denied approval {} has an empty evidence reference",
            approval.approval_id
        )));
    }
    let decided_by = approval.decided_by.clone().ok_or_else(|| {
        invalid_record(format!(
            "denied approval {} has no deciding actor",
            approval.approval_id
        ))
    })?;
    let decided_at = approval.decided_at.ok_or_else(|| {
        invalid_record(format!(
            "denied approval {} has no decision time",
            approval.approval_id
        ))
    })?;
    Ok(DenialEvidence {
        approval_id: approval.approval_id.clone(),
        evidence_ref,
        decided_by,
        decided_at,
        revision: approval.revision,
    })
}

fn redirect_for_status(approval: Approval) -> KernelResult<ApprovalRedirect> {
    match approval.status {
        ApprovalStatus::Requested => Ok(ApprovalRedirect::NeedsApproval {
            approval_id: Some(approval.approval_id),
        }),
        ApprovalStatus::Approved => Ok(ApprovalRedirect::AlreadyApproved {
            approval_id: approval.approval_id,
        }),
        ApprovalStatus::Denied => Ok(ApprovalRedirect::Denied(denial_evidence(&approval)?)),
        ApprovalStatus::Expired => Ok(ApprovalRedirect::Expired {
            approval_id: approval.approval_id,
        }),
        ApprovalStatus::Consumed => {
            let command_id = approval.consumed_by_command_id.ok_or_else(|| {
                invalid_record(format!(
                    "consumed approval {} has no command",
                    approval.approval_id
                ))
            })?;
            Ok(ApprovalRedirect::AlreadyConsumed {
                approval_id: approval.approval_id,
                command_id,
            })
        }
        ApprovalStatus::Cancelled => Ok(ApprovalRedirect::Cancelled {
            approval_id: approval.approval_id,
        }),
    }
}

fn invalid_authority(reason: impl Into<String>) -> KernelError {
    KernelError::InvalidAuthority(reason.into())
}

fn invalid_record(reason: impl Into<String>) -> KernelError {
    KernelError::InvalidAuthority(format!(
        "invalid durable approval record: {}",
        reason.into()
    ))
}

#[cfg(test)]
mod tests {
    use odin_domain::{ApprovalId, ApprovalStatus, CapabilityId, CommandId, Digest, EffectClass};
    use odin_ledger::{
        approval::{ApprovalDecision, ApprovalScope, NewApproval},
        command::CommandSpec,
        Ledger,
    };
    use serde_json::json;
    use time::{Duration, OffsetDateTime};

    use super::{ApprovalCommand, ApprovalGate, ApprovalRedirect, ConsumeOutcome, DecisionOutcome};

    fn at(seconds: i64) -> OffsetDateTime {
        OffsetDateTime::from_unix_timestamp(seconds).unwrap()
    }

    fn scope() -> ApprovalScope {
        ApprovalScope {
            target_kind: "lane".to_owned(),
            target_id: "lane:one".to_owned(),
            capability_id: CapabilityId::new("capability:exec").unwrap(),
            arguments_digest: Digest::hash(b"exact arguments"),
        }
    }

    fn request(id: &str, scope: ApprovalScope) -> NewApproval {
        NewApproval {
            approval_id: ApprovalId::new(id).unwrap(),
            issuer: "seat:operator".to_owned(),
            scope,
            requested_at: at(1_000),
            expires_at: at(1_000) + Duration::minutes(5),
        }
    }

    fn approve(gate: &mut ApprovalGate<'_>, request: NewApproval) {
        let approval_id = request.approval_id.clone();
        gate.request(request).unwrap();
        assert!(matches!(
            gate.decide(
                &approval_id,
                1,
                ApprovalDecision::Approve {
                    evidence_ref: Some("artifact:approval".to_owned()),
                },
                "human:operator",
                at(1_001),
            )
            .unwrap(),
            DecisionOutcome::Approved(_)
        ));
    }

    fn record_command(
        gate: &mut ApprovalGate<'_>,
        command_id: &CommandId,
        approval_id: &ApprovalId,
        scope: &ApprovalScope,
    ) {
        gate.ledger
            .record_command(&CommandSpec {
                id: command_id.clone(),
                idempotency_key: format!("idempotency:{}", command_id.as_str()),
                correlation_id: format!("correlation:{}", command_id.as_str()),
                causation_id: None,
                issuer: "seat:operator".to_owned(),
                approval_id: Some(approval_id.clone()),
                target_kind: scope.target_kind.clone(),
                target_id: scope.target_id.clone(),
                capability_id: scope.capability_id.clone(),
                capability_version: 1,
                arguments_hash: scope.arguments_digest,
                arguments: json!({"fixture": "exact arguments"}),
                expected_desired_revision: Some(1),
                issued_at: at(1_001),
                expires_at: at(1_000) + Duration::minutes(5),
            })
            .unwrap();
    }

    fn consume(
        gate: &mut ApprovalGate<'_>,
        approval_id: &ApprovalId,
        command_id: &CommandId,
        scope: &ApprovalScope,
        revision: i64,
        now: OffsetDateTime,
    ) -> ConsumeOutcome {
        gate.authorize_command(
            EffectClass::R3,
            ApprovalCommand {
                command_id,
                approval_id: Some(approval_id),
                scope,
                expected_revision: Some(revision),
                now,
            },
        )
        .unwrap()
    }

    #[test]
    fn capability_gate_honors_declared_operator_approval() {
        let mut ledger = Ledger::open_in_memory().unwrap();
        let mut gate = ApprovalGate::new(&mut ledger);
        let exact = scope();
        let approval_id = ApprovalId::new("approval:r2-operator").unwrap();
        let command_id = CommandId::new("command:r2").unwrap();

        // A declared-operator R2 demand without an approval routes to the
        // same typed request redirect R3 gets.
        assert!(matches!(
            gate.authorize_capability_command(
                EffectClass::R2,
                crate::capability::ApprovalRequirement::Operator,
                ApprovalCommand {
                    command_id: &command_id,
                    approval_id: None,
                    scope: &exact,
                    expected_revision: None,
                    now: at(1_002),
                },
            )
            .unwrap(),
            ConsumeOutcome::Redirect(ApprovalRedirect::NeedsApproval { approval_id: None })
        ));

        approve(&mut gate, request(approval_id.as_str(), exact.clone()));
        record_command(&mut gate, &command_id, &approval_id, &exact);
        assert!(matches!(
            gate.authorize_capability_command(
                EffectClass::R2,
                crate::capability::ApprovalRequirement::Operator,
                ApprovalCommand {
                    command_id: &command_id,
                    approval_id: Some(&approval_id),
                    scope: &exact,
                    expected_revision: Some(2),
                    now: at(1_002),
                },
            )
            .unwrap(),
            ConsumeOutcome::Consumed(_)
        ));

        // One-shot: the replay of the same exact scope is refused.
        let replay_command = CommandId::new("command:r2-replay").unwrap();
        record_command(&mut gate, &replay_command, &approval_id, &exact);
        assert!(matches!(
            gate.authorize_capability_command(
                EffectClass::R2,
                crate::capability::ApprovalRequirement::Operator,
                ApprovalCommand {
                    command_id: &replay_command,
                    approval_id: Some(&approval_id),
                    scope: &exact,
                    expected_revision: Some(3),
                    now: at(1_003),
                },
            )
            .unwrap(),
            ConsumeOutcome::Redirect(ApprovalRedirect::AlreadyConsumed { .. })
        ));
    }

    #[test]
    fn capability_gate_keeps_plain_effects_free_and_r3_mandatory() {
        let mut ledger = Ledger::open_in_memory().unwrap();
        let mut gate = ApprovalGate::new(&mut ledger);
        let exact = scope();
        let approval_id = ApprovalId::new("approval:plain").unwrap();
        approve(&mut gate, request(approval_id.as_str(), exact.clone()));
        // An R2 contract that declares no operator approval is never gated,
        // even when an approval id is presented.
        assert_eq!(
            gate.authorize_capability_command(
                EffectClass::R2,
                crate::capability::ApprovalRequirement::None,
                ApprovalCommand {
                    command_id: &CommandId::new("command:plain").unwrap(),
                    approval_id: Some(&approval_id),
                    scope: &exact,
                    expected_revision: Some(2),
                    now: at(1_002),
                },
            )
            .unwrap(),
            ConsumeOutcome::NotRequired
        );
        // R3 stays mandatory whatever the contract declares.
        assert!(matches!(
            gate.authorize_capability_command(
                EffectClass::R3,
                crate::capability::ApprovalRequirement::None,
                ApprovalCommand {
                    command_id: &CommandId::new("command:r3").unwrap(),
                    approval_id: None,
                    scope: &exact,
                    expected_revision: None,
                    now: at(1_002),
                },
            )
            .unwrap(),
            ConsumeOutcome::Redirect(ApprovalRedirect::NeedsApproval { approval_id: None })
        ));
    }

    #[test]
    fn approval_is_consumed_exactly_once() {
        let mut ledger = Ledger::open_in_memory().unwrap();
        let mut gate = ApprovalGate::new(&mut ledger);
        let exact = scope();
        let approval_id = ApprovalId::new("approval:once").unwrap();
        approve(&mut gate, request(approval_id.as_str(), exact.clone()));
        let first_command = CommandId::new("command:one").unwrap();
        record_command(&mut gate, &first_command, &approval_id, &exact);
        assert!(matches!(
            consume(
                &mut gate,
                &approval_id,
                &first_command,
                &exact,
                2,
                at(1_002)
            ),
            ConsumeOutcome::Consumed(_)
        ));

        let replay_command = CommandId::new("command:replay").unwrap();
        record_command(&mut gate, &replay_command, &approval_id, &exact);
        assert!(matches!(
            consume(&mut gate, &approval_id, &replay_command, &exact, 3, at(1_003)),
            ConsumeOutcome::Redirect(ApprovalRedirect::AlreadyConsumed { command_id, .. })
                if command_id == first_command
        ));
    }

    #[test]
    fn changed_target_capability_or_arguments_cannot_consume() {
        let mut ledger = Ledger::open_in_memory().unwrap();
        let mut gate = ApprovalGate::new(&mut ledger);
        let exact = scope();
        let approval_id = ApprovalId::new("approval:scope").unwrap();
        approve(&mut gate, request(approval_id.as_str(), exact.clone()));
        let command_id = CommandId::new("command:scope").unwrap();
        record_command(&mut gate, &command_id, &approval_id, &exact);
        let widened = [
            ApprovalScope {
                target_id: "lane:other".to_owned(),
                ..exact.clone()
            },
            ApprovalScope {
                capability_id: CapabilityId::new("capability:other").unwrap(),
                ..exact.clone()
            },
            ApprovalScope {
                arguments_digest: Digest::hash(b"changed arguments"),
                ..exact.clone()
            },
        ];
        for changed in &widened {
            assert!(matches!(
                consume(&mut gate, &approval_id, &command_id, changed, 2, at(1_002)),
                ConsumeOutcome::Redirect(ApprovalRedirect::ScopeMismatch { .. })
            ));
        }
        assert!(matches!(
            consume(&mut gate, &approval_id, &command_id, &exact, 2, at(1_002)),
            ConsumeOutcome::Consumed(_)
        ));
    }

    #[test]
    fn expiry_prevents_execution_and_is_durable() {
        let mut ledger = Ledger::open_in_memory().unwrap();
        let mut gate = ApprovalGate::new(&mut ledger);
        let exact = scope();
        let approval_id = ApprovalId::new("approval:expired").unwrap();
        approve(&mut gate, request(approval_id.as_str(), exact.clone()));
        let command_id = CommandId::new("command:expired").unwrap();
        assert!(matches!(
            consume(
                &mut gate,
                &approval_id,
                &command_id,
                &exact,
                2,
                at(1_000) + Duration::minutes(5)
            ),
            ConsumeOutcome::Redirect(ApprovalRedirect::Expired { .. })
        ));
        assert_eq!(
            gate.ledger.approval(&approval_id).unwrap().unwrap().status,
            ApprovalStatus::Expired
        );
    }

    #[test]
    fn denial_redirect_carries_evidence() {
        let mut ledger = Ledger::open_in_memory().unwrap();
        let mut gate = ApprovalGate::new(&mut ledger);
        let exact = scope();
        let approval_id = ApprovalId::new("approval:denied").unwrap();
        gate.request(request(approval_id.as_str(), exact.clone()))
            .unwrap();
        assert!(matches!(
            gate.decide(
                &approval_id,
                1,
                ApprovalDecision::Deny { evidence_ref: "artifact:denial".to_owned() },
                "human:operator",
                at(1_001),
            ).unwrap(),
            DecisionOutcome::Denied(ref evidence) if evidence.evidence_ref == "artifact:denial"
        ));
        let command_id = CommandId::new("command:denied").unwrap();
        assert!(matches!(
            consume(&mut gate, &approval_id, &command_id, &exact, 2, at(1_002)),
            ConsumeOutcome::Redirect(ApprovalRedirect::Denied(ref evidence))
                if evidence.evidence_ref == "artifact:denial"
                    && evidence.decided_by == "human:operator"
        ));
    }

    #[test]
    fn expiry_sweep_only_expires_due_open_approvals() {
        let mut ledger = Ledger::open_in_memory().unwrap();
        let mut gate = ApprovalGate::new(&mut ledger);
        let due_id = ApprovalId::new("approval:sweep-due").unwrap();
        let live_id = ApprovalId::new("approval:sweep-live").unwrap();
        gate.request(request(due_id.as_str(), scope())).unwrap();
        let mut live_request = request(live_id.as_str(), scope());
        live_request.expires_at += Duration::minutes(5);
        gate.request(live_request).unwrap();

        let sweep = gate
            .sweep_expired(at(1_000) + Duration::minutes(5))
            .unwrap();
        assert_eq!(sweep.expired.len(), 1);
        assert_eq!(sweep.expired[0].approval_id, due_id);
        assert!(sweep.redirects.is_empty());
        assert_eq!(
            gate.ledger.approval(&live_id).unwrap().unwrap().status,
            ApprovalStatus::Requested
        );
    }

    #[test]
    fn stale_revision_is_a_typed_redirect() {
        let mut ledger = Ledger::open_in_memory().unwrap();
        let mut gate = ApprovalGate::new(&mut ledger);
        let approval_id = ApprovalId::new("approval:stale").unwrap();
        gate.request(request(approval_id.as_str(), scope()))
            .unwrap();
        assert!(matches!(
            gate.decide(
                &approval_id,
                0,
                ApprovalDecision::Approve { evidence_ref: None },
                "human:operator",
                at(1_001),
            )
            .unwrap(),
            DecisionOutcome::Redirect(ApprovalRedirect::StaleRevision {
                expected_revision: 0,
                actual_revision: 1,
                ..
            })
        ));
    }

    #[test]
    fn r3_without_approval_redirects() {
        let mut ledger = Ledger::open_in_memory().unwrap();
        let mut gate = ApprovalGate::new(&mut ledger);
        let command_id = CommandId::new("command:missing").unwrap();
        let exact = scope();
        assert_eq!(
            gate.authorize_command(
                EffectClass::R3,
                ApprovalCommand {
                    command_id: &command_id,
                    approval_id: None,
                    scope: &exact,
                    expected_revision: None,
                    now: at(1_002),
                },
            )
            .unwrap(),
            ConsumeOutcome::Redirect(ApprovalRedirect::NeedsApproval { approval_id: None })
        );
    }
}
