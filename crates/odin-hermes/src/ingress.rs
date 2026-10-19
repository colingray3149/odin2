//! Paired-owner Discord intents become durable tasks; other authors are rejected without recording.
//! Replays reuse the same idempotency claim, task, and outcome across restarts.
//! Consequential effects require kernel approval, and published receipts omit message content.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use odin_domain::envelope::EventEnvelopeInit;
use odin_domain::{
    Actor, ApprovalId, CapabilityId, CommandId, Correlation, Digest, DomainError, EffectClass,
    EventEnvelope, EventId, Producer, Redaction, Scope, SeatId, SessionId, SUBJECT_COMMAND_CHANGED,
};
use odin_kernel::{
    ApprovalCommand, ApprovalDecision, ApprovalRedirect, ApprovalScope, ConsumeOutcome,
    DecisionOutcome, KernelError, NewApproval,
};
use odin_ledger::command::{
    AcceptedCommand, CommandOutcome, CommandSpec, CommandTerminalStatus, RecordCommand,
    RecordedCommand,
};
use serde_json::json;
use time::{Duration, OffsetDateTime};

use crate::correlation::{
    identity_from_key, surface_correlation, surface_session, ConversationTaskStore, DiscordSurface,
};
use crate::discord::DiscordMessage;

/// Events published for admitted intents ride the existing command subject.
pub const INTENT_EVENT_KIND: &str = SUBJECT_COMMAND_CHANGED;

pub const INTENT_COMMAND_PREFIX: &str = "command:discord-intent:";

/// Deterministic approval prefix for internal intent lifecycle records, suppressed from DMs.
pub const INTENT_APPROVAL_PREFIX: &str = "approval:discord-intent:";

/// Issuer identity stamped on intents and their approval requests.
pub const INTENT_ISSUER: &str = "odin-hermes.discord-intake";

/// The paired owner. Pairing is a human/deployment fact (dotfiles), never a
/// compiled default: construction requires the owner's Discord user id.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OwnerPairing {
    owner_user_id: String,
}

impl OwnerPairing {
    pub fn new(owner_user_id: impl Into<String>) -> Result<Self, DomainError> {
        let owner_user_id = owner_user_id.into();
        if owner_user_id.is_empty()
            || owner_user_id.len() > 32
            || !owner_user_id.bytes().all(|byte| byte.is_ascii_digit())
        {
            return Err(DomainError::InvalidId {
                kind: "OwnerPairing",
                value: owner_user_id,
                reason: "owner user id must be a non-empty decimal snowflake of at most 32 digits",
            });
        }
        Ok(Self { owner_user_id })
    }

    pub fn owner_user_id(&self) -> &str {
        &self.owner_user_id
    }

    /// The pairing decision for one message author. Non-owners are refused
    /// before any durable work happens.
    pub fn authorize(&self, author_id: &str) -> bool {
        author_id == self.owner_user_id
    }
}

/// Task-contract binding for this ingress, supplied by the runtime from the
/// registry and dotfiles deployment facts (no compiled defaults).
#[derive(Clone, Debug)]
pub struct IngressConfig {
    pub seat: SeatId,
    pub capability: CapabilityId,
    pub capability_version: u64,
    /// Effect class of the intent's consequential leg. R3 binds the kernel
    /// approval gate; lower classes pass the gate as not-required.
    pub effect_class: EffectClass,
    pub ttl_seconds: i64,
    /// The paired owner DM channel. When bound, intents from any other
    /// channel are refused at the adapter boundary (the pairing scope is
    /// this surface, not Discord at large); `None` admits the paired
    /// author from any DM channel.
    pub paired_channel_id: Option<String>,
}

impl IngressConfig {
    pub fn new(
        seat: SeatId,
        capability: CapabilityId,
        capability_version: u64,
        effect_class: EffectClass,
        ttl_seconds: i64,
        paired_channel_id: Option<String>,
    ) -> Result<Self, DomainError> {
        if capability_version < 1 {
            return Err(DomainError::InvalidEnvelope(
                "ingress capability version must be positive".to_owned(),
            ));
        }
        if ttl_seconds <= 0 {
            return Err(DomainError::InvalidEnvelope(
                "ingress ttl must be positive".to_owned(),
            ));
        }
        if let Some(channel) = &paired_channel_id {
            if channel.is_empty()
                || channel.len() > 32
                || !channel.bytes().all(|b| b.is_ascii_digit())
            {
                return Err(DomainError::InvalidId {
                    kind: "IngressConfig",
                    value: channel.clone(),
                    reason: "paired channel id must be a decimal snowflake of at most 32 digits",
                });
            }
        }
        Ok(Self {
            seat,
            capability,
            capability_version,
            effect_class,
            ttl_seconds,
            paired_channel_id,
        })
    }
}

pub struct TaskReceipt {
    pub command_id: CommandId,
    pub idempotency_key: String,
    pub session: SessionId,
    /// Notification envelope for the egress surface: task identity and status
    /// only, never intent content.
    pub event: EventEnvelope,
    recorded: RecordedCommand,
}

impl TaskReceipt {
    pub const fn recorded(&self) -> &RecordedCommand {
        &self.recorded
    }
}

/// The outcome of admitting one Discord message.
pub enum IntentOutcome {
    /// New durable task recorded (idempotency key claimed in the same
    /// transaction).
    Admitted(TaskReceipt),
    /// Replayed intent: the originally recorded task, unchanged.
    Duplicate(TaskReceipt),
    /// Author is not the paired owner. Nothing is recorded and nothing
    /// executes; the response carries no echo of the message.
    Unauthorized,
    /// New durable task whose consequential leg requires a kernel approval.
    EffectGated(TaskReceipt, PendingApproval),
    /// Published capability governance refused the intake. The intent keeps
    /// its separate durable record, terminally non-executable; nothing runs.
    GovernanceRejected { command_id: CommandId },
}

/// An approval request created in the kernel gate for one intent's
/// consequential leg, with the revision the decider must act on.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PendingApproval {
    pub approval_id: ApprovalId,
    pub revision: i64,
}

/// Result of presenting a gated effect to the kernel approval gate.
pub enum EffectGate {
    /// Execution may begin after consumption; boxed to keep the other enum variants small.
    Approved { accepted: Box<AcceptedCommand> },
    /// The gate recorded a denial; the task is settled `Rejected` with the
    /// denial evidence reference before this returns.
    Denied { evidence_ref: String },
    /// The gate refused without a denial decision (not requested, expired,
    /// scope mismatch, ...); the task is settled `Rejected` with the reason.
    Blocked { reason: String },
}

#[derive(Debug, thiserror::Error)]
pub enum IngressError {
    #[error("durable task store failed: {0}")]
    Ledger(#[from] odin_ledger::LedgerError),
    #[error("domain contract violated: {0}")]
    Domain(#[from] DomainError),
    #[error("kernel approval authority failed: {0}")]
    Approval(#[from] KernelError),
    #[error("intake capability governance is unavailable: {0}")]
    GovernanceUnavailable(String),
}

/// Result of presenting an admitted (non-gated) intent at the executable
/// boundary: the mirror of [`EffectGate`] for the class that has no
/// approval leg.
// This short-lived result transfers one command inline; boxing adds an allocation to every admission.
#[allow(clippy::large_enum_variant)]
pub enum AdmittedAccept {
    /// Governance re-proved and the acceptance is durable; execution may
    /// begin.
    Accepted(AcceptedCommand),
    /// Governance refused at the executable boundary; the task is settled
    /// `Rejected` durably before this returns.
    Rejected { reason: String },
}

/// One intake invocation presented to the published capability governance
/// port before a durable task may become executable. The caller is the
/// adapter identity only — a Discord author never inherits seat, model-call,
/// or dispatch authority.
#[derive(Clone, Debug)]
pub struct IntakeInvocation {
    pub capability: CapabilityId,
    pub capability_version: u64,
    pub arguments_digest: Digest,
    pub target_seat: SeatId,
    pub idempotency_key: String,
    pub issuer: String,
}

/// The decision of the published capability governance (the kernel
/// `policy::authorize` path over the registry's published
/// `discord.intake` contract, composed by the runtime). The adapter never
/// self-certifies: without a decision there is no executable task.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum GovernanceDecision {
    Authorized { authorization_ref: String },
    Rejected { reason: String },
    Unavailable { reason: String },
}

pub trait IntakeGovernance: Send + Sync {
    fn authorize_intake(&self, invocation: IntakeInvocation) -> GovernanceDecision;
}

/// The Discord ingress adapter: pairing check, correlation, published
/// capability governance, durable task creation, and the R3 approval
/// binding.
pub struct DiscordIngress {
    pairing: OwnerPairing,
    store: Arc<ConversationTaskStore>,
    governance: Arc<dyn IntakeGovernance>,
    config: IngressConfig,
    sequence: AtomicU64,
}

impl DiscordIngress {
    pub fn new(
        pairing: OwnerPairing,
        store: Arc<ConversationTaskStore>,
        governance: Arc<dyn IntakeGovernance>,
        config: IngressConfig,
    ) -> Self {
        Self {
            pairing,
            store,
            governance,
            config,
            sequence: AtomicU64::new(1),
        }
    }

    /// Admits one Discord message as an intent.
    pub fn admit(
        &self,
        message: &DiscordMessage,
        now: OffsetDateTime,
    ) -> Result<IntentOutcome, IngressError> {
        if !self.pairing.authorize(&message.author_id) {
            return Ok(IntentOutcome::Unauthorized);
        }
        // DM-only surface: guild messages are outside the paired surface and
        // are refused with nothing recorded, exactly like non-owner authors.
        if message.guild_id.is_some() {
            return Ok(IntentOutcome::Unauthorized);
        }
        // The paired channel bound, when configured, refuses intents from
        // any other channel at the adapter boundary.
        if let Some(paired) = &self.config.paired_channel_id {
            if &message.channel_id != paired {
                return Ok(IntentOutcome::Unauthorized);
            }
        }
        if message.content.trim().is_empty() {
            return Err(IngressError::Domain(DomainError::InvalidEnvelope(
                "discord intent content must not be empty".to_owned(),
            )));
        }

        let surface = DiscordSurface::new(&message.channel_id, &message.id)?;
        let correlation = surface_correlation(&surface)?;
        let session = surface_session(&surface)?;
        let identity = identity_from_key(correlation.idempotency_key.as_str());
        let command_id = CommandId::new(format!("{INTENT_COMMAND_PREFIX}{identity}"))?;
        let arguments = json!({
            "request": message.content,
            "channel_id": message.channel_id,
            "message_id": message.id,
            "author_id": message.author_id,
            "guild_id": message.guild_id,
        });
        let arguments_string = arguments.to_string();
        let spec = CommandSpec {
            id: command_id.clone(),
            idempotency_key: correlation.idempotency_key.clone(),
            correlation_id: correlation.idempotency_key.clone(),
            causation_id: Some(format!("discord:message:{}", message.id)),
            issuer: INTENT_ISSUER.to_owned(),
            approval_id: None,
            target_kind: "seat".to_owned(),
            target_id: self.config.seat.to_string(),
            capability_id: self.config.capability.clone(),
            capability_version: self.config.capability_version as i64,
            arguments_hash: Digest::hash(arguments_string.as_bytes()),
            arguments,
            expected_desired_revision: None,
            issued_at: now,
            expires_at: now + Duration::seconds(self.config.ttl_seconds),
        };

        let (status, recorded) = match self.store.record_task(&spec)? {
            RecordCommand::Inserted(recorded) => ("recorded", recorded),
            RecordCommand::Existing(recorded) => ("duplicate", recorded),
        };

        // A governance-rejected intent keeps its separate durable record,
        // terminally non-executable; replays resolve to the same refusal.
        if recorded.command().terminal_status == Some(CommandTerminalStatus::Rejected) {
            return Ok(IntentOutcome::GovernanceRejected {
                command_id: command_id.clone(),
            });
        }

        let receipt = TaskReceipt {
            command_id: command_id.clone(),
            idempotency_key: correlation.idempotency_key.clone(),
            session,
            event: self.receipt_event(&command_id, status, now)?,
            recorded,
        };

        // Load the durable row once; both the fresh and the replay path
        // re-derive from it instead of trusting the insertion shortcut.
        let stored = self.store.task(&command_id)?.ok_or(IngressError::Domain(
            DomainError::InvalidEnvelope(
                "recorded discord intent is missing from the durable store".to_owned(),
            ),
        ))?;

        if status == "duplicate" {
            // Crash-window recovery: the record may predate its governance
            // decision, so the replay re-proves governance durably; an R3
            // record restores its approval binding from the deterministic
            // durable approval id instead of assuming it was never created.
            if self.config.effect_class == EffectClass::R3 {
                let pending = self.restore_or_request_effect_approval(&receipt, now)?;
                return Ok(IntentOutcome::EffectGated(receipt, pending));
            }
            return match self
                .governance
                .authorize_intake(self.intake_invocation(&stored)?)
            {
                GovernanceDecision::Authorized { .. } => Ok(IntentOutcome::Duplicate(receipt)),
                GovernanceDecision::Rejected { reason } => {
                    self.settle_governance_rejection(&receipt, reason, now)?;
                    Ok(IntentOutcome::GovernanceRejected {
                        command_id: command_id.clone(),
                    })
                }
                GovernanceDecision::Unavailable { reason } => {
                    Err(IngressError::GovernanceUnavailable(reason))
                }
            };
        }

        // Published capability governance: the intake capability must
        // authorize before the recorded task may become executable.
        match self
            .governance
            .authorize_intake(self.intake_invocation(&stored)?)
        {
            GovernanceDecision::Authorized { .. } => {}
            GovernanceDecision::Rejected { reason } => {
                self.settle_governance_rejection(&receipt, reason, now)?;
                return Ok(IntentOutcome::GovernanceRejected {
                    command_id: command_id.clone(),
                });
            }
            GovernanceDecision::Unavailable { reason } => {
                // The record stays durable and non-executable; this is a
                // typed unavailable outcome, never a success.
                return Err(IngressError::GovernanceUnavailable(reason));
            }
        }

        if self.config.effect_class == EffectClass::R3 {
            let pending = self.request_effect_approval(&receipt, now)?;
            Ok(IntentOutcome::EffectGated(receipt, pending))
        } else {
            Ok(IntentOutcome::Admitted(receipt))
        }
    }

    /// Creates the exact-scope kernel approval request for a gated effect.
    /// The scope binds capability id and arguments digest exactly, so no
    /// other effect can ride this approval.
    pub fn request_effect_approval(
        &self,
        receipt: &TaskReceipt,
        now: OffsetDateTime,
    ) -> Result<PendingApproval, IngressError> {
        let identity = identity_from_key(&receipt.idempotency_key);
        let approval_id = ApprovalId::new(format!("{INTENT_APPROVAL_PREFIX}{identity}"))?;
        let scope = self.approval_scope(receipt)?;
        let request = NewApproval {
            approval_id: approval_id.clone(),
            issuer: INTENT_ISSUER.to_owned(),
            scope,
            requested_at: now,
            expires_at: now + Duration::seconds(self.config.ttl_seconds),
        };
        let approval = self
            .store
            .with_approval_gate(|gate| gate.request(request))?;
        Ok(PendingApproval {
            approval_id,
            revision: approval.revision,
        })
    }

    /// Records the operator's decision through the kernel gate.
    pub fn decide_effect_approval(
        &self,
        pending: &PendingApproval,
        decision: ApprovalDecision,
        decided_by: &str,
        now: OffsetDateTime,
    ) -> Result<DecisionOutcome, IngressError> {
        Ok(self.store.decide_effect_approval(
            &pending.approval_id,
            pending.revision,
            decision,
            decided_by,
            now,
        )?)
    }

    /// Checks the approval revision observed by the caller; only `Approved` permits execution.
    pub fn gate_effect(
        &self,
        receipt: &TaskReceipt,
        approval_id: &ApprovalId,
        observed_revision: i64,
        now: OffsetDateTime,
    ) -> Result<EffectGate, IngressError> {
        // The intake route is the sole approval consumer and only for tasks
        // that never rode model dispatch; governance must still authorize
        // this exact invocation at the executable boundary.
        let command_row = self
            .store
            .task(&receipt.command_id)?
            .ok_or(IngressError::Domain(DomainError::InvalidEnvelope(
                "gated discord intent is missing from the durable store".to_owned(),
            )))?;
        match self
            .governance
            .authorize_intake(self.intake_invocation(&command_row)?)
        {
            GovernanceDecision::Authorized { .. } => {}
            GovernanceDecision::Rejected { reason } => {
                self.settle_rejection_once(
                    receipt,
                    json!({
                        "status": "governance_rejected",
                        "reason": reason,
                    }),
                    now,
                )?;
                return Ok(EffectGate::Blocked {
                    reason: format!("governance: {reason}"),
                });
            }
            GovernanceDecision::Unavailable { reason } => {
                return Err(IngressError::GovernanceUnavailable(reason));
            }
        }
        let scope = self.approval_scope(receipt)?;
        let command = ApprovalCommand {
            command_id: &receipt.command_id,
            approval_id: Some(approval_id),
            scope: &scope,
            expected_revision: Some(observed_revision),
            now,
        };
        let outcome = self
            .store
            .with_approval_gate(|gate| gate.authorize_command(self.config.effect_class, command))?;
        match outcome {
            ConsumeOutcome::NotRequired | ConsumeOutcome::Consumed(_) => {
                let accepted = self.store.accept_task(receipt.recorded(), now)?;
                Ok(EffectGate::Approved {
                    accepted: Box::new(accepted),
                })
            }
            // Resume unsettled accepted tasks using their existing acceptance, without consuming again.
            ConsumeOutcome::Redirect(ApprovalRedirect::AlreadyConsumed { .. })
                if command_row.accepted_at.is_some() && command_row.terminal_status.is_none() =>
            {
                let accepted = self.store.accept_task(receipt.recorded(), now)?;
                Ok(EffectGate::Approved {
                    accepted: Box::new(accepted),
                })
            }
            ConsumeOutcome::Redirect(redirect) => {
                let detail = match &redirect {
                    ApprovalRedirect::Denied(evidence) => json!({
                        "status": "denied",
                        "approval": approval_id.to_string(),
                        "evidence_ref": evidence.evidence_ref,
                    }),
                    other => json!({
                        "status": "blocked",
                        "approval": approval_id.to_string(),
                        "reason": redirect_reason(other),
                    }),
                };
                self.settle_rejection_once(receipt, detail, now)?;
                match redirect {
                    ApprovalRedirect::Denied(evidence) => Ok(EffectGate::Denied {
                        evidence_ref: evidence.evidence_ref,
                    }),
                    other => Ok(EffectGate::Blocked {
                        reason: redirect_reason(&other),
                    }),
                }
            }
        }
    }

    /// The composed effect class of the intake capability — the published
    /// authority fact that decided `Admitted` versus `EffectGated` at
    /// admit, and the fact the reconcile recovery classifies by.
    pub const fn effect_class(&self) -> EffectClass {
        self.config.effect_class
    }

    /// Presents one admitted (non-gated) intent at the executable
    /// boundary, mirroring [`DiscordIngress::gate_effect`] for the class
    /// with no approval leg: governance is re-proved from the durable row
    /// (never trusted from admission), the kernel gate is consulted for
    /// the composed class — an R1/R2 class neither requires nor consumes
    /// an approval — and only then is the acceptance made durable.
    pub fn accept_admitted(
        &self,
        receipt: &TaskReceipt,
        now: OffsetDateTime,
    ) -> Result<AdmittedAccept, IngressError> {
        if self.config.effect_class == EffectClass::R3 {
            return Err(IngressError::Domain(DomainError::InvalidEnvelope(
                "an R3 intent must present through the approval gate, not the admitted \
                 boundary"
                    .to_owned(),
            )));
        }
        let command_row = self
            .store
            .task(&receipt.command_id)?
            .ok_or(IngressError::Domain(DomainError::InvalidEnvelope(
                "admitted discord intent is missing from the durable store".to_owned(),
            )))?;
        match self
            .governance
            .authorize_intake(self.intake_invocation(&command_row)?)
        {
            GovernanceDecision::Authorized { .. } => {}
            GovernanceDecision::Rejected { reason } => {
                self.settle_governance_rejection(receipt, reason.clone(), now)?;
                return Ok(AdmittedAccept::Rejected { reason });
            }
            GovernanceDecision::Unavailable { reason } => {
                return Err(IngressError::GovernanceUnavailable(reason));
            }
        }
        let scope = self.approval_scope(receipt)?;
        let command = ApprovalCommand {
            command_id: &receipt.command_id,
            approval_id: None,
            scope: &scope,
            expected_revision: None,
            now,
        };
        match self
            .store
            .with_approval_gate(|gate| gate.authorize_command(self.config.effect_class, command))?
        {
            ConsumeOutcome::NotRequired | ConsumeOutcome::Consumed(_) => Ok(
                AdmittedAccept::Accepted(self.store.accept_task(receipt.recorded(), now)?),
            ),
            ConsumeOutcome::Redirect(redirect) => {
                Err(IngressError::Domain(DomainError::InvalidEnvelope(format!(
                    "the approval gate redirected a non-gated intent: {}",
                    redirect_reason(&redirect)
                ))))
            }
        }
    }

    /// Settles an approved, executed task with its terminal outcome.
    pub fn settle_effect(
        &self,
        accepted: &AcceptedCommand,
        result: serde_json::Value,
        now: OffsetDateTime,
    ) -> Result<(), IngressError> {
        self.store.settle_task(
            accepted,
            &CommandOutcome {
                status: CommandTerminalStatus::Completed,
                result,
            },
            now,
        )?;
        Ok(())
    }

    /// Settles an intent whose execution route refused or errored: the
    /// terminal outcome is the honest `failed` status with the typed
    /// reason — never a completed task carrying a failure payload.
    pub fn settle_effect_failure(
        &self,
        accepted: &AcceptedCommand,
        reason: String,
        now: OffsetDateTime,
    ) -> Result<(), IngressError> {
        self.store.settle_task(
            accepted,
            &CommandOutcome {
                status: CommandTerminalStatus::Failed,
                result: json!({ "status": "failed", "reason": reason }),
            },
            now,
        )?;
        Ok(())
    }

    fn approval_scope(&self, receipt: &TaskReceipt) -> Result<ApprovalScope, IngressError> {
        let command = self
            .store
            .task(&receipt.command_id)?
            .ok_or(IngressError::Domain(DomainError::InvalidEnvelope(
                "gated discord intent is missing from the durable store".to_owned(),
            )))?;
        Ok(ApprovalScope {
            target_kind: command.target_kind,
            target_id: command.target_id,
            capability_id: command.capability_id,
            arguments_digest: command.arguments_hash,
        })
    }

    fn receipt_event(
        &self,
        command_id: &CommandId,
        status: &str,
        now: OffsetDateTime,
    ) -> Result<EventEnvelope, IngressError> {
        let event = EventEnvelope::new(EventEnvelopeInit {
            id: EventId::new(format!("event:{}", command_id.as_str()))?,
            sequence: self.sequence.fetch_add(1, Ordering::Relaxed),
            revision: 1,
            occurred_at_ms: unix_ms(now),
            kind: INTENT_EVENT_KIND.to_owned(),
            actor: Actor::system(INTENT_ISSUER)?,
            scope: Scope::default(),
            correlation: Correlation::new(INTENT_ISSUER)?,
            payload: json!({
                "task": command_id.to_string(),
                "status": status,
            }),
            redaction: Redaction::None,
            producer: Producer::new("odin-hermes", env!("CARGO_PKG_VERSION"), None)?,
        })?;
        Ok(event)
    }
}

fn redirect_reason(redirect: &ApprovalRedirect) -> String {
    match redirect {
        ApprovalRedirect::NeedsApproval { .. } => "approval not yet granted".to_owned(),
        ApprovalRedirect::Denied(_) => "denied".to_owned(),
        ApprovalRedirect::Expired { .. } => "approval expired".to_owned(),
        ApprovalRedirect::AlreadyConsumed { .. } => "approval already consumed".to_owned(),
        ApprovalRedirect::Cancelled { .. } => "approval cancelled".to_owned(),
        ApprovalRedirect::ScopeMismatch { .. } => "approval scope mismatch".to_owned(),
        ApprovalRedirect::AlreadyApproved { .. } => "approval awaiting decision".to_owned(),
        ApprovalRedirect::NotFound { .. } => "approval not found".to_owned(),
        ApprovalRedirect::StaleRevision { .. } => "stale approval revision".to_owned(),
        ApprovalRedirect::PreviewRequired { .. } => {
            "approval needs the complete question delivered first".to_owned()
        }
    }
}

fn unix_ms(now: OffsetDateTime) -> u64 {
    let seconds = now.unix_timestamp();
    if seconds <= 0 {
        return 0;
    }
    u64::try_from(seconds).unwrap_or(u64::MAX) * 1000 + u64::from(now.microsecond() / 1000)
}

impl DiscordIngress {
    /// The intake invocation derived from the durable task row, so fresh
    /// admissions and replays prove governance against the capability facts
    /// actually recorded with the intent — never against this process's
    /// current config copy, which a later edit could silently change.
    fn intake_invocation(
        &self,
        stored: &odin_ledger::command::Command,
    ) -> Result<IntakeInvocation, IngressError> {
        Ok(IntakeInvocation {
            capability: stored.capability_id.clone(),
            capability_version: stored.capability_version as u64,
            arguments_digest: stored.arguments_hash,
            target_seat: SeatId::new(stored.target_id.clone())?,
            idempotency_key: stored.idempotency_key.clone(),
            issuer: INTENT_ISSUER.to_owned(),
        })
    }

    /// Settles a governance refusal terminally and durably, unless a prior
    /// attempt already moved the task row out of the recorded state.
    fn settle_governance_rejection(
        &self,
        receipt: &TaskReceipt,
        reason: String,
        now: OffsetDateTime,
    ) -> Result<(), IngressError> {
        self.settle_rejection_once(
            receipt,
            json!({
                "status": "governance_rejected",
                "capability": self.config.capability.to_string(),
                "reason": reason,
            }),
            now,
        )?;
        Ok(())
    }

    /// Writes a terminal rejection only while the task row is still purely
    /// recorded. A replayed gate or admit attempt on a row that already left
    /// the recorded state — accepted, or terminally settled by an earlier
    /// attempt — must not re-write history: the ledger FSM forbids
    /// rejecting an accepted command, and the first durable outcome wins.
    /// Returns whether the rejection was written; the typed outcome is the
    /// caller's either way.
    fn settle_rejection_once(
        &self,
        receipt: &TaskReceipt,
        detail: serde_json::Value,
        now: OffsetDateTime,
    ) -> Result<bool, IngressError> {
        let row = self
            .store
            .task(&receipt.command_id)?
            .ok_or(IngressError::Domain(DomainError::InvalidEnvelope(
                "gated discord intent is missing from the durable store".to_owned(),
            )))?;
        if row.accepted_at.is_some() || row.terminal_status.is_some() {
            return Ok(false);
        }
        self.store.reject_task(receipt.recorded(), detail, now)?;
        Ok(true)
    }
    /// Restores the approval binding for a replayed R3 record from its
    /// deterministic durable approval id, creating the request only when no
    /// approval exists yet (crash between task record and request).
    fn restore_or_request_effect_approval(
        &self,
        receipt: &TaskReceipt,
        now: OffsetDateTime,
    ) -> Result<PendingApproval, IngressError> {
        let identity = identity_from_key(&receipt.idempotency_key);
        let approval_id = ApprovalId::new(format!("{INTENT_APPROVAL_PREFIX}{identity}"))?;
        if let Some(existing) = self.store.approval(&approval_id)? {
            return Ok(PendingApproval {
                approval_id,
                revision: existing.revision,
            });
        }
        self.request_effect_approval(receipt, now)
    }

    /// Restores an intent's queue entry from its durable row; terminal and unrelated rows return None.
    /// Accepted tasks reuse acceptance, while route admission prevents resending an admitted prompt.
    pub fn recover_intent(
        &self,
        row: &odin_ledger::command::Command,
        now: OffsetDateTime,
    ) -> Result<Option<RecoveredIntent>, IngressError> {
        if !row.id.as_str().starts_with(INTENT_COMMAND_PREFIX) {
            return Ok(None);
        }
        if row.terminal_status.is_some() {
            return Ok(None);
        }
        // Expired intents settle as failed so the runtime can report the undelivered message.
        if now > row.expires_at {
            let recorded = match self.store.record_task(&respecify_command(row))? {
                RecordCommand::Existing(recorded) => recorded,
                RecordCommand::Inserted(_) => {
                    return Err(IngressError::Domain(DomainError::InvalidEnvelope(
                        "expired intent recovery re-claimed a row that did not exist".to_owned(),
                    )));
                }
            };
            let content = recorded
                .command()
                .arguments
                .get("request")
                .and_then(serde_json::Value::as_str)
                .unwrap_or_default()
                .to_owned();
            let command_id = recorded.command().id.clone();
            // Accept (idempotent for an already-accepted row) then settle
            // terminally; both transitions are durable before the notice.
            let accepted = self.store.accept_task(&recorded, now)?;
            self.store.settle_task(
                &accepted,
                &CommandOutcome {
                    status: CommandTerminalStatus::Failed,
                    result: json!({ "status": "failed", "reason": "expired" }),
                },
                now,
            )?;
            return Ok(Some(RecoveredIntent::Expired {
                command_id,
                content,
            }));
        }
        if row.accepted_at.is_some() {
            tracing::warn!(
                "odin-hermes: intent {} is accepted but unsettled; the accepting run is \
                 gone, recovery re-drives it exactly once through the normal path",
                row.id
            );
        }
        let recorded = match self.store.record_task(&respecify_command(row))? {
            RecordCommand::Existing(recorded) => recorded,
            RecordCommand::Inserted(_) => {
                return Err(IngressError::Domain(DomainError::InvalidEnvelope(
                    "intent recovery re-claimed a row that did not exist".to_owned(),
                )));
            }
        };
        let command = recorded.command();
        let surface = DiscordSurface::new(
            command
                .arguments
                .get("channel_id")
                .and_then(serde_json::Value::as_str)
                .unwrap_or_default(),
            command
                .arguments
                .get("message_id")
                .and_then(serde_json::Value::as_str)
                .unwrap_or_default(),
        )?;
        let correlation = surface_correlation(&surface)?;
        let receipt = TaskReceipt {
            command_id: command.id.clone(),
            idempotency_key: correlation.idempotency_key.clone(),
            session: surface_session(&surface)?,
            event: self.receipt_event(&command.id, "recorded", now)?,
            recorded,
        };
        match self
            .governance
            .authorize_intake(self.intake_invocation(receipt.recorded().command())?)
        {
            GovernanceDecision::Authorized { .. } => {}
            GovernanceDecision::Rejected { reason } => {
                self.settle_governance_rejection(&receipt, reason, now)?;
                return Ok(None);
            }
            GovernanceDecision::Unavailable { reason } => {
                return Err(IngressError::GovernanceUnavailable(reason));
            }
        }
        if self.config.effect_class == EffectClass::R3 {
            let pending = self.restore_or_request_effect_approval(&receipt, now)?;
            return Ok(Some(RecoveredIntent::Gated(receipt, pending)));
        }
        Ok(Some(RecoveredIntent::Admitted(receipt)))
    }
}

/// The reconcile queue entry restored for one durable non-terminal intent
/// row by [`DiscordIngress::recover_intent`].
pub enum RecoveredIntent {
    /// An admitted (non-gated) intent awaiting the conversation route.
    Admitted(TaskReceipt),
    /// A gated intent whose approval binding was restored from its
    /// deterministic durable approval id.
    Gated(TaskReceipt, PendingApproval),
    /// An intent that expired unsettled: it is settled terminally
    /// `failed: expired` here, and the runtime owes the owner the ONE
    /// plain lost-message sentence carried in `content`. Never silence.
    Expired {
        command_id: CommandId,
        content: String,
    },
}

/// Rebuilds a command spec from a durable row so an idempotent re-claim
/// can present the row to the ledger again (the claim resolves to the
/// existing row; the ledger requires the full spec).
pub(crate) fn respecify_command(
    command: &odin_ledger::command::Command,
) -> odin_ledger::command::CommandSpec {
    odin_ledger::command::CommandSpec {
        id: command.id.clone(),
        idempotency_key: command.idempotency_key.clone(),
        correlation_id: command.correlation_id.clone(),
        causation_id: command.causation_id.clone(),
        issuer: command.issuer.clone(),
        approval_id: command.approval_id.clone(),
        target_kind: command.target_kind.clone(),
        target_id: command.target_id.clone(),
        capability_id: command.capability_id.clone(),
        capability_version: command.capability_version,
        arguments_hash: command.arguments_hash,
        arguments: command.arguments.clone(),
        expected_desired_revision: command.expected_desired_revision,
        issued_at: command.issued_at,
        expires_at: command.expires_at,
    }
}
