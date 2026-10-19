//! Shared durable recording, replay, and settlement of external life effects.

use odin_domain::{Actor, ApprovalId, CapabilityId, CommandId, Digest, EventId, Redaction, Scope};
use odin_ledger::audit::{AuditEvidence, NewAuditEvent, RedactedPayload};
use parking_lot::{Mutex, MutexGuard};

use serde::Serialize;
use serde_json::Value;
use time::OffsetDateTime;

use super::errors::{
    AccountUnavailable, BatchFault, DenialRecord, GateRedirect, LeaseRejection, LedgerFailure,
    LifeError, TransportFault,
};
use super::lease::{CredentialLeases, ScopedCredentialLease};

/// Lifetime of a recorded durable effect intent (a ledger command).
pub const EFFECT_TTL_SECONDS: i64 = 900;

/// Longest idempotency key / correlation id accepted for a life effect.
pub const MAX_IDENTITY_CHARS: usize = 256;

pub const MAX_ACCOUNT_CHARS: usize = 128;

/// The audit kind of the one durable record a partially applied effect
/// leaves beside its in-doubt command.
pub const PARTIAL_EFFECT_AUDIT_KIND: &str = "odin.hermes.life_effect.partial";

const PARTIAL_EVIDENCE_ACTOR: &str = "odin-hermes.account";

/// Most known ids one partial-effect record retains (the largest batch).
const MAX_PARTIAL_IDS: usize = 128;

/// Longest known upstream id one partial-effect record retains.
const MAX_PARTIAL_ID_CHARS: usize = 128;

/// How a settled durable effect terminated. Only these statuses are
/// ever recorded; an effect whose dispatch outcome is unknowable is
/// never given one (it stays in-doubt in the ledger).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum EffectStatus {
    /// The effect executed and its typed result is durable.
    Completed,
    /// The authority denied the effect; it never executed.
    Rejected,
    /// The effect failed before dispatch.
    Failed,
}

/// Caller-supplied ids validated before ledger writes; the key determines the command id for replay.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EffectIdentity {
    pub idempotency_key: String,
    pub correlation_id: String,
}

impl EffectIdentity {
    /// Validates the identity and derives the durable command id.
    pub fn command_id(&self) -> Result<CommandId, LifeError> {
        self.validate()?;
        CommandId::new(format!("command:{}", self.idempotency_key))
            .map_err(|_| LifeError::InvalidInput("the idempotency key cannot name a command id"))
    }

    /// Rejects blank ids and ids longer than `MAX_IDENTITY_CHARS` bytes.
    pub fn validate(&self) -> Result<(), LifeError> {
        for (field, value) in [
            ("the idempotency key", self.idempotency_key.as_str()),
            ("the correlation id", self.correlation_id.as_str()),
        ] {
            if value.trim().is_empty() || value.len() > MAX_IDENTITY_CHARS {
                return Err(LifeError::InvalidInput(field));
            }
        }
        Ok(())
    }
}

/// A settled durable effect: the command id, its terminal class, and
/// the adapter-private result document. The owning adapter projects this
/// into an identifier-only public receipt before returning it; durable
/// transport evidence must never enter status envelopes. `replayed` marks
/// an outcome read back from the durable record rather than settled here.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SettledEffect {
    pub command_id: CommandId,
    pub status: EffectStatus,
    pub result: Value,
    pub replayed: bool,
}

/// The terminal result document of a denied effect. Carries identifiers
/// and the durable evidence reference only.
pub fn denial_result(denial: &DenialRecord) -> Value {
    serde_json::json!({
        "denied": true,
        "approvalId": denial.approval_id.to_string(),
        "evidenceRef": denial.evidence_ref,
        "decidedBy": denial.decided_by,
    })
}

/// A static reason class for an effect that failed before dispatch.
pub fn failed_result(fault: TransportFault) -> Value {
    serde_json::json!({
        "executed": false,
        "reason": fault_reason(fault),
    })
}

fn fault_reason(fault: TransportFault) -> &'static str {
    match fault {
        TransportFault::Unavailable(AccountUnavailable::Account) => "account-unavailable",
        TransportFault::Unavailable(AccountUnavailable::Credentials) => "credential-unavailable",
        TransportFault::Unavailable(AccountUnavailable::Service) => "service-unavailable",
        TransportFault::Refused(_) => "lease-refused",
        TransportFault::Protocol(_) | TransportFault::ProtocolDetail { .. } => "protocol-failure",
        TransportFault::Timeout => "timeout",
    }
}

/// Locks the shared durable ledger (non-poisoning `parking_lot`).
/// Every life effect holds this lock for its whole record→verify→settle
/// sequence; the human approval decision happens through the same
/// ledger outside any such sequence.
pub(crate) fn lock_ledger(
    ledger: &Mutex<odin_ledger::Ledger>,
) -> MutexGuard<'_, odin_ledger::Ledger> {
    ledger.lock()
}

// Record before dispatch and replay settled results without another transport call.
// Unsettled commands remain in doubt; gated effects require consumed kernel approval.

use odin_ledger::command::CommandSpec;
use odin_ledger::{Ledger, LedgerError};

/// Sorted JSON keys make the effect-argument digest deterministic.
fn canonical_digest(arguments: &Value) -> Result<Digest, LifeError> {
    let canonical = serde_json::to_string(arguments).map_err(|error| LifeError::Ledger {
        class: LedgerFailure::Invalid,
        detail: error.to_string(),
    })?;
    Ok(Digest::hash(canonical.as_bytes()))
}

pub(crate) fn fault_into_life(fault: TransportFault) -> LifeError {
    match fault {
        TransportFault::Unavailable(unavailable) => LifeError::Unavailable(unavailable),
        TransportFault::Refused(message) => LifeError::InvalidInput(message),
        TransportFault::Timeout => LifeError::Timeout,
        TransportFault::Protocol(message) => LifeError::Protocol(message),
        TransportFault::ProtocolDetail { message, status } => LifeError::ProtocolDetail {
            message,
            detail: format!("HTTP {status}"),
        },
    }
}

/// Maps a local transport readiness fault onto the life error surface.
/// Readiness never exchanges anything, so an account the transport does
/// not serve stays typed and every other fault is local credential
/// material the provider would refuse at use.
pub(crate) fn readiness_into_life(fault: TransportFault) -> LifeError {
    match fault {
        TransportFault::Unavailable(unavailable) => LifeError::Unavailable(unavailable),
        TransportFault::Refused(_)
        | TransportFault::Timeout
        | TransportFault::Protocol(_)
        | TransportFault::ProtocolDetail { .. } => {
            LifeError::Unavailable(AccountUnavailable::Credentials)
        }
    }
}

pub(crate) fn lease_into_life(rejection: LeaseRejection) -> LifeError {
    match rejection {
        LeaseRejection::UnknownAccount => LifeError::Unavailable(AccountUnavailable::Account),
        LeaseRejection::CredentialsUnavailable => {
            LifeError::Unavailable(AccountUnavailable::Credentials)
        }
        LeaseRejection::Expired | LeaseRejection::ScopeMismatch => {
            LifeError::InvalidInput("the credential lease was refused")
        }
    }
}

fn ledger_into_life(error: LedgerError) -> LifeError {
    LifeError::Ledger {
        class: LedgerFailure::Invalid,
        detail: error.to_string(),
    }
}

/// Rebuilds the exact command specification of a loaded command so the
/// idempotency claim yields its [`odin_ledger::command::RecordedCommand`] again.
fn respecify(command: &odin_ledger::command::Command) -> CommandSpec {
    CommandSpec {
        id: command.id.clone(),
        idempotency_key: command.idempotency_key.clone(),
        correlation_id: command.correlation_id.clone(),
        causation_id: None,
        issuer: command.issuer.clone(),
        approval_id: None,
        target_kind: command.target_kind.clone(),
        target_id: command.target_id.clone(),
        capability_id: command.capability_id.clone(),
        capability_version: command.capability_version,
        arguments_hash: command.arguments_hash,
        arguments: command.arguments.clone(),
        expected_desired_revision: None,
        issued_at: command.issued_at,
        expires_at: command.expires_at,
    }
}

fn settled_outcome(command: &odin_ledger::command::Command) -> Option<SettledEffect> {
    let status = command.terminal_status?;
    let result = command.terminal_result.clone().unwrap_or(Value::Null);
    let status = match status {
        odin_ledger::command::CommandTerminalStatus::Completed => EffectStatus::Completed,
        odin_ledger::command::CommandTerminalStatus::Rejected => EffectStatus::Rejected,
        _ => EffectStatus::Failed,
    };
    Some(SettledEffect {
        command_id: command.id.clone(),
        status,
        result,
        replayed: true,
    })
}

/// Ledger and caller identity shared across recording and settlement.
#[derive(Clone, Copy)]
pub(crate) struct DurableEffect<'a> {
    pub ledger: &'a Mutex<Ledger>,
    pub issuer: &'a str,
    pub identity: &'a EffectIdentity,
}

#[derive(Clone, Copy)]
pub(crate) struct EffectRoute<'a> {
    pub capability: &'a CapabilityId,
    pub account: &'a str,
    pub result_key: &'static str,
}

pub(crate) struct EffectIntent<'a> {
    pub target_kind: &'a str,
    pub target_id: &'a str,
    pub arguments: Value,
}

fn gated_intent_spec(
    issuer: &str,
    identity: &EffectIdentity,
    capability: &CapabilityId,
    intent: EffectIntent<'_>,
    now: OffsetDateTime,
) -> Result<CommandSpec, LifeError> {
    let EffectIntent {
        target_kind,
        target_id,
        arguments,
    } = intent;
    let command_id = identity.command_id()?;
    let digest = canonical_digest(&arguments)?;
    Ok(CommandSpec {
        id: command_id,
        idempotency_key: identity.idempotency_key.clone(),
        correlation_id: identity.correlation_id.clone(),
        causation_id: None,
        issuer: issuer.to_owned(),
        approval_id: None,
        target_kind: target_kind.to_owned(),
        target_id: target_id.to_owned(),
        capability_id: capability.clone(),
        capability_version: 1,
        arguments_hash: digest,
        arguments,
        expected_desired_revision: None,
        issued_at: now,
        expires_at: now + time::Duration::seconds(EFFECT_TTL_SECONDS),
    })
}

/// Rejects idempotency-key reuse for different effect content or targets.
fn intent_facts_match(command: &odin_ledger::command::Command, spec: &CommandSpec) -> bool {
    command.arguments_hash == spec.arguments_hash
        && command.capability_id == spec.capability_id
        && command.target_id == spec.target_id
        && command.target_kind == spec.target_kind
}

/// Records intent without issuing approval or credentials or contacting the provider.
/// Identical rows are reused; conflicting effect details are rejected.
pub(crate) fn record_dispatch_intent(
    effect: DurableEffect<'_>,
    capability: &CapabilityId,
    intent: EffectIntent<'_>,
    now: OffsetDateTime,
) -> Result<(), LifeError> {
    let DurableEffect {
        ledger,
        issuer,
        identity,
    } = effect;
    let spec = gated_intent_spec(issuer, identity, capability, intent, now)?;
    let mut guard = lock_ledger(ledger);
    if let Some(existing) = guard.command(&spec.id).map_err(ledger_into_life)? {
        if !intent_facts_match(&existing, &spec) {
            return Err(LifeError::InvalidInput(
                "the idempotency key was already recorded for a different effect",
            ));
        }
        return Ok(());
    }
    guard.record_command(&spec).map_err(ledger_into_life)?;
    Ok(())
}

/// Host command, consumed approval, and invocation scope, rechecked against the ledger at settlement.
#[derive(Clone, Copy, Debug)]
pub struct HostConsumeProof<'a> {
    /// The consumed approval id, when the host projection carries it.
    /// When absent it is resolved from the journaled host command row
    /// (the commands table binds command → approval), so a model never
    /// becomes the source of the binding.
    pub approval_id: Option<&'a ApprovalId>,
    pub command_id: &'a CommandId,
    pub scope: &'a odin_ledger::approval::ApprovalScope,
}

/// Verifies approval consumption at the host gate without consuming it again.
pub(crate) fn settle_gated_effect<F, E>(
    effect: DurableEffect<'_>,
    leases: &dyn CredentialLeases,
    route: EffectRoute<'_>,
    proof: &HostConsumeProof,
    now: OffsetDateTime,
    execute: F,
) -> Result<SettledEffect, LifeError>
where
    F: FnOnce(&ScopedCredentialLease, &Value) -> Result<String, E>,
    E: Into<BatchFault>,
{
    let DurableEffect {
        ledger,
        issuer: _,
        identity,
    } = effect;
    let EffectRoute {
        capability,
        account,
        result_key,
    } = route;
    let command_id = identity.command_id()?;
    let mut guard = lock_ledger(ledger);
    let command = guard
        .command(&command_id)
        .map_err(ledger_into_life)?
        .ok_or(LifeError::InvalidInput(
            "no recorded intent for this idempotency key",
        ))?;
    if command.capability_id != *capability {
        return Err(LifeError::InvalidInput(
            "the idempotency key was already recorded for a different effect",
        ));
    }
    if let Some(settled) = settled_outcome(&command) {
        return Ok(settled);
    }
    if command.arguments.get("account").and_then(Value::as_str) != Some(account) {
        return Err(LifeError::InvalidInput(
            "the recorded intent names a different account",
        ));
    }
    if command.accepted_at.is_some() {
        return Err(accepted_unsettled(&guard, &command));
    }

    // Resolve credentials first so missing credentials are not reported as gate refusals.
    let lease = leases
        .issue(capability, account, now)
        .map_err(|rejection| {
            let fault = match rejection {
                LeaseRejection::UnknownAccount => {
                    TransportFault::Unavailable(AccountUnavailable::Account)
                }
                LeaseRejection::CredentialsUnavailable => {
                    TransportFault::Unavailable(AccountUnavailable::Credentials)
                }
                LeaseRejection::Expired | LeaseRejection::ScopeMismatch => {
                    TransportFault::Protocol("the credential lease was refused")
                }
            };
            settle_failed(&mut guard, &command, fault, now);
            lease_into_life(rejection)
        })?;

    // Check the host command and full approval scope against the ledger before dispatch.
    let proof_approval_id = match proof.approval_id {
        Some(approval_id) => approval_id.clone(),
        None => guard
            .command(proof.command_id)
            .map_err(ledger_into_life)?
            .and_then(|host_command| host_command.approval_id)
            .ok_or(LifeError::InvalidInput(
                "the consumed host command names no approval",
            ))?,
    };
    if proof.scope.capability_id != *capability {
        return Err(LifeError::InvalidInput(
            "the host permit names a different capability",
        ));
    }
    let approval = guard
        .approval(&proof_approval_id)
        .map_err(ledger_into_life)?
        .ok_or_else(|| {
            LifeError::Gate(GateRedirect::NotFound {
                approval_id: proof_approval_id.clone(),
            })
        })?;
    match approval.status {
        odin_domain::ApprovalStatus::Consumed => {
            if approval.consumed_by_command_id.as_ref() != Some(proof.command_id) {
                return Err(LifeError::InvalidInput(
                    "the consumed approval names a different command",
                ));
            }
            if approval.scope != *proof.scope {
                return Err(LifeError::InvalidInput(
                    "the consumed approval scope does not match the host permit",
                ));
            }
            execute_settled(&mut guard, &command, &lease, result_key, now, execute)
        }
        odin_domain::ApprovalStatus::Denied => {
            let evidence_ref = approval
                .decision_evidence_ref
                .clone()
                .filter(|reference| !reference.trim().is_empty())
                .ok_or_else(|| LifeError::Ledger {
                    class: LedgerFailure::Invalid,
                    detail: "denied approval has no decision evidence".to_owned(),
                })?;
            let denial = DenialRecord {
                approval_id: approval.approval_id,
                evidence_ref,
                decided_by: approval.decided_by.unwrap_or_else(|| "unknown".to_owned()),
            };
            settle_denied(&mut guard, &command, &denial, now)?;
            Err(LifeError::Denied(denial))
        }
        odin_domain::ApprovalStatus::Approved => {
            Err(LifeError::Gate(GateRedirect::AlreadyApproved {
                approval_id: proof_approval_id.clone(),
            }))
        }
        odin_domain::ApprovalStatus::Requested => {
            Err(LifeError::Gate(GateRedirect::NeedsApproval {
                approval_id: Some(proof_approval_id.clone()),
            }))
        }
        odin_domain::ApprovalStatus::Expired => Err(LifeError::Gate(GateRedirect::Expired {
            approval_id: proof_approval_id.clone(),
        })),
        odin_domain::ApprovalStatus::Cancelled => {
            // Cancellation rejects the effect without inventing a decision or dispatching it.
            settle_rejected(
                &mut guard,
                &command,
                serde_json::json!({
                    "cancelled": true,
                    "approvalId": proof_approval_id.to_string(),
                }),
                now,
            )?;
            Err(LifeError::Gate(GateRedirect::Cancelled {
                approval_id: proof_approval_id.clone(),
            }))
        }
    }
}

fn settle_denied(
    guard: &mut Ledger,
    command: &odin_ledger::command::Command,
    denial: &DenialRecord,
    now: OffsetDateTime,
) -> Result<(), LifeError> {
    settle_rejected(guard, command, denial_result(denial), now)
}

/// Records a gated command as terminal without any dispatch: the
/// terminal document carries the sanitized reason class only, never
/// effect content.
fn settle_rejected(
    guard: &mut Ledger,
    command: &odin_ledger::command::Command,
    result: Value,
    now: OffsetDateTime,
) -> Result<(), LifeError> {
    let recorded = guard
        .record_command(&respecify(command))
        .map_err(ledger_into_life)?;
    guard
        .reject_command(
            recorded.recorded(),
            recorded.recorded().command().revision,
            result,
            now,
        )
        .map_err(ledger_into_life)?;
    Ok(())
}

/// Accepts before dispatch and records the outcome after the transport returns.
fn execute_settled<F, E>(
    guard: &mut Ledger,
    command: &odin_ledger::command::Command,
    lease: &ScopedCredentialLease,
    result_key: &'static str,
    now: OffsetDateTime,
    execute: F,
) -> Result<SettledEffect, LifeError>
where
    F: FnOnce(&ScopedCredentialLease, &Value) -> Result<String, E>,
    E: Into<BatchFault>,
{
    let recorded = guard
        .record_command(&respecify(command))
        .map_err(ledger_into_life)?;
    let accepted = guard
        .accept_command(
            recorded.recorded(),
            recorded.recorded().command().revision,
            now,
        )
        .map_err(ledger_into_life)?;
    match execute(lease, &command.arguments) {
        Ok(id) => {
            let mut result = serde_json::Map::new();
            result.insert(result_key.to_owned(), Value::String(id));
            let completed = guard
                .complete_command(
                    &accepted,
                    &odin_ledger::command::CommandOutcome {
                        status: odin_ledger::command::CommandTerminalStatus::Completed,
                        result: Value::Object(result),
                    },
                    accepted.command().revision,
                    now,
                )
                // The effect landed; an unrecorded completion leaves the
                // accepted command in-doubt, never a pre-effect failure.
                .map_err(|_| LifeError::InDoubt)?;
            Ok(SettledEffect {
                command_id: completed.id.clone(),
                status: EffectStatus::Completed,
                result: completed.terminal_result.clone().unwrap_or(Value::Null),
                replayed: false,
            })
        }
        Err(fault) => Err(settle_dispatch_fault(
            guard,
            &accepted,
            result_key,
            fault.into(),
            now,
        )),
    }
}

/// Keeps partial or uncertain effects unsettled; only failures before dispatch settle as failed.
fn settle_dispatch_fault(
    guard: &mut Ledger,
    accepted: &odin_ledger::command::AcceptedCommand,
    result_key: &'static str,
    fault: BatchFault,
    now: OffsetDateTime,
) -> LifeError {
    let BatchFault { applied, fault } = fault;
    if !applied.is_empty() {
        return record_partial(guard, accepted.command(), result_key, applied, fault, now);
    }
    if fault.proves_not_dispatched() {
        settle_not_dispatched(guard, accepted, fault, now);
    }
    fault_into_life(fault)
}

/// Hashing the command id keeps the deterministic event id within its length limit.
fn partial_evidence_id(command_id: &CommandId) -> Option<EventId> {
    let digest = Digest::hash(format!("{PARTIAL_EFFECT_AUDIT_KIND}\u{0}{command_id}").as_bytes());
    EventId::new(format!("life-effect-partial:{digest}")).ok()
}

/// Persists applied ids before reporting partial execution, leaving the command unsettled.
/// Invalid ids or failed writes return in-doubt rather than an unrecorded partial result.
fn record_partial(
    guard: &Ledger,
    command: &odin_ledger::command::Command,
    result_key: &'static str,
    applied: Vec<String>,
    fault: TransportFault,
    now: OffsetDateTime,
) -> LifeError {
    let bounded = applied.len() <= MAX_PARTIAL_IDS
        && applied
            .iter()
            .all(|id| !id.is_empty() && id.chars().count() <= MAX_PARTIAL_ID_CHARS);
    let Some(event_id) = partial_evidence_id(&command.id).filter(|_| bounded) else {
        tracing::error!(
            command = %command.id,
            "odin-hermes: account effect partial evidence out of bounds command={}",
            command.id
        );
        return LifeError::InDoubt;
    };
    let payload = serde_json::json!({
        "commandId": command.id.to_string(),
        "capabilityId": command.capability_id.as_str(),
        "resultKey": result_key,
        "knownIds": applied,
        "stopReason": fault_reason(fault),
        "remainder": "unknown",
    });
    let written = RedactedPayload::new(payload, Redaction::None).and_then(|payload| {
        guard.append_audit_event(NewAuditEvent {
            event_id,
            kind: PARTIAL_EFFECT_AUDIT_KIND.to_owned(),
            actor: Actor::System {
                name: PARTIAL_EVIDENCE_ACTOR.to_owned(),
            },
            scope: Scope::default(),
            evidence: vec![AuditEvidence::Command(command.id.clone())],
            payload,
            occurred_at: now,
        })
    });
    match written {
        Ok(_) => LifeError::PartiallyApplied { known_ids: applied },
        Err(error) => {
            tracing::error!(
                command = %command.id,
                error = %error,
                "odin-hermes: account effect could not record partial evidence command={}: {error}",
                command.id
            );
            LifeError::InDoubt
        }
    }
}

/// Returns recorded partial results for this command, otherwise in-doubt, without dispatching.
fn accepted_unsettled(guard: &Ledger, command: &odin_ledger::command::Command) -> LifeError {
    let Some(event_id) = partial_evidence_id(&command.id) else {
        return LifeError::InDoubt;
    };
    let event = match guard.audit_event(&event_id) {
        Ok(Some(event)) => event,
        Ok(None) => return LifeError::InDoubt,
        Err(error) => {
            tracing::error!(
                command = %command.id,
                error = %error,
                "odin-hermes: account effect partial evidence unreadable command={}: {error}",
                command.id
            );
            return LifeError::InDoubt;
        }
    };
    let linked = event.kind == PARTIAL_EFFECT_AUDIT_KIND
        && event.evidence == [AuditEvidence::Command(command.id.clone())]
        && event.payload["commandId"].as_str() == Some(command.id.as_str());
    let known_ids = event.payload["knownIds"].as_array().and_then(|ids| {
        ids.iter()
            .map(|id| id.as_str().map(str::to_owned))
            .collect::<Option<Vec<_>>>()
    });
    match known_ids {
        Some(known_ids) if linked && !known_ids.is_empty() => {
            LifeError::PartiallyApplied { known_ids }
        }
        _ => {
            tracing::error!(
                command = %command.id,
                "odin-hermes: account effect partial evidence does not match command={}",
                command.id
            );
            LifeError::InDoubt
        }
    }
}

/// Reads only completed effects with the requested identity and capability, without dispatching.
/// Unsettled commands retain their in-doubt or partial result.
pub(crate) fn completed_effect(
    ledger: &Mutex<Ledger>,
    identity: &EffectIdentity,
    capability: &CapabilityId,
) -> Result<odin_ledger::command::Command, LifeError> {
    let command_id = identity.command_id()?;
    let guard = lock_ledger(ledger);
    let command = guard
        .command(&command_id)
        .map_err(ledger_into_life)?
        .ok_or(LifeError::InvalidInput(
            "no recorded effect for this identity",
        ))?;
    if command.capability_id != *capability || command.correlation_id != identity.correlation_id {
        return Err(LifeError::InvalidInput(
            "the identity names a different effect",
        ));
    }
    match command.terminal_status {
        Some(odin_ledger::command::CommandTerminalStatus::Completed) => Ok(command),
        Some(_) => Err(LifeError::InvalidInput("the effect did not complete")),
        None if command.accepted_at.is_some() => Err(accepted_unsettled(&guard, &command)),
        None => Err(LifeError::InvalidInput("the effect never dispatched")),
    }
}

/// Records, executes, and settles reversible changes without approval.
/// Settled effects replay their results; uncertain effects are not retried.
pub(crate) fn run_ungated_effect<F, E>(
    effect: DurableEffect<'_>,
    leases: &dyn CredentialLeases,
    route: EffectRoute<'_>,
    arguments: Value,
    now: OffsetDateTime,
    execute: F,
) -> Result<SettledEffect, LifeError>
where
    F: FnOnce(&ScopedCredentialLease, &Value) -> Result<String, E>,
    E: Into<BatchFault>,
{
    let DurableEffect {
        ledger,
        issuer,
        identity,
    } = effect;
    let EffectRoute {
        capability,
        account,
        result_key,
    } = route;
    let command_id = identity.command_id()?;
    let digest = canonical_digest(&arguments)?;
    let spec = CommandSpec {
        id: command_id.clone(),
        idempotency_key: identity.idempotency_key.clone(),
        correlation_id: identity.correlation_id.clone(),
        causation_id: None,
        issuer: issuer.to_owned(),
        approval_id: None,
        target_kind: capability.as_str().to_owned(),
        target_id: account.to_owned(),
        capability_id: capability.clone(),
        capability_version: 1,
        arguments_hash: digest,
        arguments,
        expected_desired_revision: None,
        issued_at: now,
        expires_at: now + time::Duration::seconds(EFFECT_TTL_SECONDS),
    };
    let mut guard = lock_ledger(ledger);
    let recorded = guard.record_command(&spec).map_err(ledger_into_life)?;
    let command = recorded.recorded().command();
    if command.arguments_hash != digest || command.capability_id != *capability {
        return Err(LifeError::InvalidInput(
            "the idempotency key was already recorded for a different effect",
        ));
    }
    if let Some(settled) = settled_outcome(command) {
        return Ok(settled);
    }
    if command.accepted_at.is_some() {
        return Err(accepted_unsettled(&guard, command));
    }
    let lease = leases
        .issue(capability, account, now)
        .map_err(lease_into_life)?;
    let accepted = guard
        .accept_command(recorded.recorded(), command.revision, now)
        .map_err(ledger_into_life)?;
    match execute(&lease, &command.arguments) {
        Ok(id) => {
            let mut result = serde_json::Map::new();
            result.insert(result_key.to_owned(), Value::String(id));
            let completed = guard
                .complete_command(
                    &accepted,
                    &odin_ledger::command::CommandOutcome {
                        status: odin_ledger::command::CommandTerminalStatus::Completed,
                        result: Value::Object(result),
                    },
                    accepted.command().revision,
                    now,
                )
                // The effect landed; an unrecorded completion leaves the
                // accepted command in-doubt, never a pre-effect failure.
                .map_err(|_| LifeError::InDoubt)?;
            Ok(SettledEffect {
                command_id: completed.id.clone(),
                status: EffectStatus::Completed,
                result: completed.terminal_result.clone().unwrap_or(Value::Null),
                replayed: false,
            })
        }
        Err(fault) => Err(settle_dispatch_fault(
            &mut guard,
            &accepted,
            result_key,
            fault.into(),
            now,
        )),
    }
}

/// Rejects a command before acceptance; ledger failures are logged and leave it unsettled.
fn settle_failed(
    guard: &mut Ledger,
    command: &odin_ledger::command::Command,
    fault: TransportFault,
    now: OffsetDateTime,
) {
    let recorded = match guard.record_command(&respecify(command)) {
        Ok(recorded) => recorded,
        Err(error) => {
            tracing::error!(
                command = %command.id,
                error = %error,
                "odin-hermes: account effect could not settle failed command={} step=record: {error}",
                command.id
            );
            return;
        }
    };
    let revision = recorded.recorded().command().revision;
    if let Err(error) =
        guard.reject_command(recorded.recorded(), revision, failed_result(fault), now)
    {
        tracing::error!(
            command = %command.id,
            error = %error,
            "odin-hermes: account effect could not settle failed command={} step=reject: {error}",
            command.id
        );
    }
}

/// Marks an accepted command failed only when nothing was dispatched.
/// Ledger failures are logged and leave the command unsettled.
fn settle_not_dispatched(
    guard: &mut Ledger,
    accepted: &odin_ledger::command::AcceptedCommand,
    fault: TransportFault,
    now: OffsetDateTime,
) {
    let recorded = match guard.record_command(&respecify(accepted.command())) {
        Ok(recorded) => recorded,
        Err(error) => {
            tracing::error!(
                command = %accepted.command().id,
                error = %error,
                "odin-hermes: account effect could not settle not-dispatched command={} step=record: {error}",
                accepted.command().id
            );
            return;
        }
    };
    let revision = recorded.recorded().command().revision;
    if let Err(error) = guard.complete_command(
        accepted,
        &odin_ledger::command::CommandOutcome {
            status: odin_ledger::command::CommandTerminalStatus::Failed,
            result: failed_result(fault),
        },
        revision,
        now,
    ) {
        tracing::error!(
            command = %accepted.command().id,
            error = %error,
            "odin-hermes: account effect could not settle not-dispatched command={} step=complete: {error}",
            accepted.command().id
        );
    }
}
