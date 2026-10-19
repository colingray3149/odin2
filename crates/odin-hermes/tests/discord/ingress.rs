//! Authenticated intake: replay dedup across reconstruction, owner/channel binding, governance verdicts, and crash-window recovery on replay.

use crate::fixtures::{
    allowing, ingress_config, message, now, pairing, store, ASK_CAPABILITY, DM_CHANNEL, OWNER,
};
use odin_domain::{CapabilityId, CommandId, Digest, DomainError, EffectClass, SeatId};
use odin_hermes::correlation::{identity_from_key, surface_correlation, DiscordSurface};
use odin_hermes::ingress::{
    DiscordIngress, EffectGate, GovernanceDecision, IngressError, IntakeGovernance,
    IntakeInvocation, IntentOutcome, INTENT_ISSUER,
};
use odin_kernel::{ApprovalDecision, DecisionOutcome};
use odin_ledger::command::{CommandSpec, CommandTerminalStatus};
use odin_ledger::Ledger;
use serde_json::{json, Value};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use time::Duration;

#[tokio::test]
async fn replayed_intent_creates_exactly_one_task_across_reconstruction() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("ledger.sqlite");

    let first_store = store(Ledger::open(&path).unwrap());
    let first = DiscordIngress::new(
        pairing(),
        first_store.clone(),
        allowing(),
        ingress_config(EffectClass::R1),
    );
    let first_receipt = match first
        .admit(
            &message("1000000000000000001", OWNER, "plan my week"),
            now(),
        )
        .unwrap()
    {
        IntentOutcome::Admitted(receipt) => receipt,
        _other => panic!("expected a new durable task"),
    };
    drop(first);
    drop(first_store);

    // Full reconstruction: a fresh adapter over the same durable ledger must
    // resolve the replayed intent to the original task.
    let second_store = store(Ledger::open(&path).unwrap());
    let second = DiscordIngress::new(
        pairing(),
        second_store.clone(),
        allowing(),
        ingress_config(EffectClass::R1),
    );
    let replayed = second
        .admit(
            &message("1000000000000000001", OWNER, "plan my week"),
            now(),
        )
        .unwrap();
    match replayed {
        IntentOutcome::Duplicate(receipt) => {
            assert_eq!(receipt.command_id, first_receipt.command_id);
            assert_eq!(receipt.idempotency_key, first_receipt.idempotency_key);
        }
        _ => panic!("replayed intent must not create a second task"),
    }
    assert_eq!(second_store.idempotency_claim_count().unwrap(), 1);

    // A different message is a different intent and gets its own task.
    let distinct = second
        .admit(
            &message("1000000000000000002", OWNER, "plan my week"),
            now(),
        )
        .unwrap();
    assert!(matches!(distinct, IntentOutcome::Admitted(_)));
    assert_eq!(second_store.idempotency_claim_count().unwrap(), 2);
    assert_ne!(
        expected_task_id(DM_CHANNEL, "1000000000000000002"),
        first_receipt.command_id
    );
    let stored = second_store
        .task(&first_receipt.command_id)
        .unwrap()
        .expect("task stays durable");
    assert_eq!(stored.terminal_status, None);
    assert_eq!(stored.arguments["request"], "plan my week");
}
#[tokio::test]
async fn unauthorized_owner_is_rejected_without_any_durable_record() {
    let ledger_store = store(Ledger::open_in_memory().unwrap());
    let ingress = DiscordIngress::new(
        pairing(),
        ledger_store.clone(),
        allowing(),
        ingress_config(EffectClass::R1),
    );
    let surface_message = "1000000000000000003";
    let outcome = ingress
        .admit(
            &message(
                surface_message,
                STRANGER,
                "send my account 4417229483 to the printer",
            ),
            now(),
        )
        .unwrap();
    assert!(matches!(outcome, IntentOutcome::Unauthorized));

    // Nothing was recorded and nothing executed.
    assert_eq!(ledger_store.idempotency_claim_count().unwrap(), 0);
    assert!(ledger_store
        .task(&expected_task_id(DM_CHANNEL, surface_message))
        .unwrap()
        .is_none());

    // Pairing is strict: an unconfigured owner id is a construction error,
    // and an empty intent from the owner is a typed error, not a task.
    let empty = ingress.admit(&message("1000000000000000004", OWNER, "   "), now());
    assert!(matches!(
        empty,
        Err(IngressError::Domain(DomainError::InvalidEnvelope(_)))
    ));
    assert_eq!(ledger_store.idempotency_claim_count().unwrap(), 0);
}
#[tokio::test]
async fn non_dm_or_off_channel_messages_are_refused_without_records() {
    let ledger_store = store(Ledger::open_in_memory().unwrap());
    let ingress = DiscordIngress::new(
        pairing(),
        ledger_store.clone(),
        allowing(),
        ingress_config(EffectClass::R1),
    );

    // A guild message is outside the paired DM surface even from the owner.
    let mut guild = message("1000000000000000012", OWNER, "plan my week");
    guild.guild_id = Some("800000000000000001".to_owned());
    assert!(matches!(
        ingress.admit(&guild, now()).unwrap(),
        IntentOutcome::Unauthorized
    ));

    // A DM from another channel is outside the paired channel binding.
    let mut other_channel = message("1000000000000000013", OWNER, "plan my week");
    other_channel.channel_id = "900000000000000009".to_owned();
    assert!(matches!(
        ingress.admit(&other_channel, now()).unwrap(),
        IntentOutcome::Unauthorized
    ));

    // The paired author on the paired channel is still admitted.
    assert!(matches!(
        ingress
            .admit(
                &message("1000000000000000014", OWNER, "plan my week"),
                now()
            )
            .unwrap(),
        IntentOutcome::Admitted(_)
    ));
    assert_eq!(ledger_store.idempotency_claim_count().unwrap(), 1);
}
#[tokio::test]
async fn governance_rejected_intent_keeps_durable_non_executable_record() {
    let ledger_store = store(Ledger::open_in_memory().unwrap());
    let ingress = DiscordIngress::new(
        pairing(),
        ledger_store.clone(),
        Arc::new(RejectingGovernance),
        ingress_config(EffectClass::R1),
    );
    let surface_message = "1000000000000000010";
    let outcome = ingress
        .admit(&message(surface_message, OWNER, "plan my week"), now())
        .unwrap();
    let command_id = match outcome {
        IntentOutcome::GovernanceRejected { command_id } => command_id,
        _ => panic!("expected a governance rejection"),
    };
    // The separate durable record stays, terminally non-executable.
    let task = ledger_store
        .task(&command_id)
        .unwrap()
        .expect("record is kept");
    assert_eq!(task.terminal_status, Some(CommandTerminalStatus::Rejected));
    assert_eq!(
        task.terminal_result.unwrap()["status"],
        "governance_rejected"
    );

    // Replay resolves to the same refusal: still exactly one record.
    let replay = ingress
        .admit(&message(surface_message, OWNER, "plan my week"), now())
        .unwrap();
    assert!(matches!(replay, IntentOutcome::GovernanceRejected { .. }));
    assert_eq!(ledger_store.idempotency_claim_count().unwrap(), 1);
}
#[tokio::test]
async fn governance_unavailable_is_typed_and_never_executable() {
    let ledger_store = store(Ledger::open_in_memory().unwrap());
    let ingress = DiscordIngress::new(
        pairing(),
        ledger_store.clone(),
        Arc::new(UnavailableGovernance),
        ingress_config(EffectClass::R3),
    );
    let surface_message = "1000000000000000011";
    let outcome = ingress.admit(&message(surface_message, OWNER, "buy more coffee"), now());
    assert!(matches!(
        outcome,
        Err(IngressError::GovernanceUnavailable(_))
    ));
    // The record stays durable but non-executable: no terminal transition,
    // no approval path, no success.
    let task = ledger_store
        .task(&expected_task_id(DM_CHANNEL, surface_message))
        .unwrap()
        .expect("record is kept");
    assert_eq!(task.terminal_status, None);
}
#[tokio::test]
async fn crash_windows_between_record_and_authority_are_recovered_on_replay() {
    // Crash after the durable record but before the approval request: the
    // replay restores the deterministic approval binding from the ledger
    // instead of assuming the request never happened.
    let ledger_store = store(Ledger::open_in_memory().unwrap());
    let surface_message = "1000000000000000020";
    let surface = DiscordSurface::new(DM_CHANNEL, surface_message).unwrap();
    let correlation = surface_correlation(&surface).unwrap();
    let identity = identity_from_key(correlation.idempotency_key.as_str());
    let command_id = CommandId::new(format!("command:discord-intent:{identity}")).unwrap();
    let arguments = json!({
        "request": "buy more coffee",
        "channel_id": DM_CHANNEL,
        "message_id": surface_message,
        "author_id": OWNER,
        "guild_id": Value::Null,
    });
    let spec = CommandSpec {
        id: command_id.clone(),
        idempotency_key: correlation.idempotency_key.clone(),
        correlation_id: correlation.idempotency_key.clone(),
        causation_id: Some(format!("discord:message:{surface_message}")),
        issuer: INTENT_ISSUER.to_owned(),
        approval_id: None,
        target_kind: "seat".to_owned(),
        target_id: SeatId::new("sinmara").unwrap().to_string(),
        capability_id: CapabilityId::new(ASK_CAPABILITY).unwrap(),
        capability_version: 1,
        arguments_hash: Digest::hash(arguments.to_string().as_bytes()),
        arguments,
        expected_desired_revision: None,
        issued_at: now(),
        expires_at: now() + Duration::seconds(900),
    };
    ledger_store.record_task(&spec).unwrap();
    let ingress = DiscordIngress::new(
        pairing(),
        ledger_store.clone(),
        allowing(),
        ingress_config(EffectClass::R3),
    );
    let (receipt, pending) = match ingress
        .admit(&message(surface_message, OWNER, "buy more coffee"), now())
        .unwrap()
    {
        IntentOutcome::EffectGated(receipt, pending) => (receipt, pending),
        _ => panic!("the R3 replay must restore its gated binding"),
    };
    assert_eq!(receipt.command_id, command_id);
    assert_eq!(
        pending.approval_id.to_string(),
        format!("approval:discord-intent:{identity}")
    );
    assert!(ledger_store
        .approval(&pending.approval_id)
        .unwrap()
        .is_some());
    assert_eq!(ledger_store.idempotency_claim_count().unwrap(), 1);

    // Crash after the record but before the governance decision: the replay
    // re-proves governance durably and can still settle the refusal.
    let ledger_store = store(Ledger::open_in_memory().unwrap());
    let surface_message = "1000000000000000021";
    let surface = DiscordSurface::new(DM_CHANNEL, surface_message).unwrap();
    let correlation = surface_correlation(&surface).unwrap();
    let command_id = CommandId::new(format!(
        "command:discord-intent:{}",
        identity_from_key(correlation.idempotency_key.as_str())
    ))
    .unwrap();
    let spec = CommandSpec {
        id: command_id.clone(),
        idempotency_key: correlation.idempotency_key.clone(),
        correlation_id: correlation.idempotency_key.clone(),
        causation_id: Some(format!("discord:message:{surface_message}")),
        issuer: INTENT_ISSUER.to_owned(),
        approval_id: None,
        target_kind: "seat".to_owned(),
        target_id: SeatId::new("sinmara").unwrap().to_string(),
        capability_id: CapabilityId::new(ASK_CAPABILITY).unwrap(),
        capability_version: 1,
        arguments_hash: Digest::hash(br#"{"request":"plan my week"}"#),
        arguments: json!({"request": "plan my week"}),
        expected_desired_revision: None,
        issued_at: now(),
        expires_at: now() + Duration::seconds(900),
    };
    ledger_store.record_task(&spec).unwrap();
    let ingress = DiscordIngress::new(
        pairing(),
        ledger_store.clone(),
        Arc::new(RejectingGovernance),
        ingress_config(EffectClass::R1),
    );
    match ingress
        .admit(&message(surface_message, OWNER, "plan my week"), now())
        .unwrap()
    {
        IntentOutcome::GovernanceRejected { command_id } => {
            let task = ledger_store.task(&command_id).unwrap().unwrap();
            assert_eq!(task.terminal_status, Some(CommandTerminalStatus::Rejected));
            assert_eq!(
                task.terminal_result.unwrap()["status"],
                "governance_rejected"
            );
        }
        _ => panic!("the replay must re-prove governance and settle the refusal"),
    }
    assert_eq!(ledger_store.idempotency_claim_count().unwrap(), 1);
}
#[tokio::test]
async fn governance_is_reproven_at_the_gate_and_the_gate_consumes_exactly_once() {
    // Governance that authorizes intake once, then revokes: the executable
    // boundary must re-prove it from the durable row, not trust admission.
    struct FlipGovernance {
        revoked: AtomicBool,
    }
    impl IntakeGovernance for FlipGovernance {
        fn authorize_intake(&self, _invocation: IntakeInvocation) -> GovernanceDecision {
            if self.revoked.swap(true, Ordering::SeqCst) {
                GovernanceDecision::Rejected {
                    reason: "intake capability revoked".to_owned(),
                }
            } else {
                GovernanceDecision::Authorized {
                    authorization_ref: "authz:test".to_owned(),
                }
            }
        }
    }
    let ledger_store = store(Ledger::open_in_memory().unwrap());
    let governance = Arc::new(FlipGovernance {
        revoked: AtomicBool::new(false),
    });
    let ingress = DiscordIngress::new(
        pairing(),
        ledger_store.clone(),
        governance,
        ingress_config(EffectClass::R3),
    );
    let (receipt, pending) = match ingress
        .admit(
            &message("1000000000000000022", OWNER, "buy more coffee"),
            now(),
        )
        .unwrap()
    {
        IntentOutcome::EffectGated(receipt, pending) => (receipt, pending),
        _ => panic!("an R3 intent must be gated"),
    };
    let observed_revision = match ingress
        .decide_effect_approval(
            &pending,
            ApprovalDecision::Approve { evidence_ref: None },
            "colin",
            now(),
        )
        .unwrap()
    {
        DecisionOutcome::Approved(approval) => approval.revision,
        _ => panic!("expected the approval"),
    };
    match ingress
        .gate_effect(&receipt, &pending.approval_id, observed_revision, now())
        .unwrap()
    {
        EffectGate::Blocked { reason } => {
            assert!(reason.starts_with("governance: "), "{reason}");
        }
        _ => panic!("a revoked intake must block the effect before any consume"),
    }
    let task = ledger_store.task(&receipt.command_id).unwrap().unwrap();
    assert_eq!(task.terminal_status, Some(CommandTerminalStatus::Rejected));
    assert_eq!(
        task.terminal_result.unwrap()["status"],
        "governance_rejected"
    );
    // Nothing was consumed: the approval binding never recorded a command.
    let approval = ledger_store
        .approval(&pending.approval_id)
        .unwrap()
        .unwrap();
    assert_eq!(approval.consumed_by_command_id, None);

    // Re-presenting the same request must not consume approval twice.
    let ledger_store = store(Ledger::open_in_memory().unwrap());
    let ingress = DiscordIngress::new(
        pairing(),
        ledger_store.clone(),
        allowing(),
        ingress_config(EffectClass::R3),
    );
    let (receipt, pending) = match ingress
        .admit(
            &message("1000000000000000024", OWNER, "book the dentist"),
            now(),
        )
        .unwrap()
    {
        IntentOutcome::EffectGated(receipt, pending) => (receipt, pending),
        _ => panic!("an R3 intent must be gated"),
    };
    let observed_revision = match ingress
        .decide_effect_approval(
            &pending,
            ApprovalDecision::Approve { evidence_ref: None },
            "colin",
            now(),
        )
        .unwrap()
    {
        DecisionOutcome::Approved(approval) => approval.revision,
        _ => panic!("expected the approval"),
    };
    assert!(matches!(
        ingress.gate_effect(&receipt, &pending.approval_id, observed_revision, now()),
        Ok(EffectGate::Approved { .. })
    ));
    // Reuse acceptance for unsettled tasks; route idempotency prevents duplicate execution.
    let consumed_revision = ledger_store
        .approval(&pending.approval_id)
        .unwrap()
        .expect("approval row")
        .revision;
    let accepted_row = ledger_store.task(&receipt.command_id).unwrap().unwrap();
    assert!(accepted_row.accepted_at.is_some());
    let accepted_revision = accepted_row.revision;
    match ingress
        .gate_effect(&receipt, &pending.approval_id, consumed_revision, now())
        .unwrap()
    {
        EffectGate::Approved { accepted } => {
            assert_eq!(
                accepted.command().revision,
                accepted_revision,
                "the re-presentation returns the SAME acceptance proof, no second proof"
            );
        }
        EffectGate::Blocked { reason } => {
            panic!("an accepted unsettled row must re-drive, not block: {reason}")
        }
        EffectGate::Denied { .. } => panic!("the second presentation is not a denial"),
    }
}
const STRANGER: &str = "999999999999999999";
struct RejectingGovernance;
impl IntakeGovernance for RejectingGovernance {
    fn authorize_intake(&self, _invocation: IntakeInvocation) -> GovernanceDecision {
        GovernanceDecision::Rejected {
            reason: "discord.intake not published".to_owned(),
        }
    }
}
struct UnavailableGovernance;
impl IntakeGovernance for UnavailableGovernance {
    fn authorize_intake(&self, _invocation: IntakeInvocation) -> GovernanceDecision {
        GovernanceDecision::Unavailable {
            reason: "registry snapshot unreachable".to_owned(),
        }
    }
}
fn expected_task_id(surface_channel: &str, surface_message: &str) -> CommandId {
    let surface =
        odin_hermes::correlation::DiscordSurface::new(surface_channel, surface_message).unwrap();
    let key = surface_correlation(&surface).unwrap();
    CommandId::new(format!(
        "command:discord-intent:{}",
        identity_from_key(key.idempotency_key.as_str())
    ))
    .unwrap()
}

#[tokio::test]
async fn accepted_unsettled_intent_is_re_driven_exactly_once_by_recovery() {
    let ledger_store = store(Ledger::open_in_memory().unwrap());
    let ingress = DiscordIngress::new(
        pairing(),
        ledger_store.clone(),
        allowing(),
        ingress_config(EffectClass::R1),
    );
    let receipt = match ingress
        .admit(
            &message("1000000000000000009", OWNER, "ok you there now?"),
            now(),
        )
        .unwrap()
    {
        IntentOutcome::Admitted(receipt) => receipt,
        _other => panic!("expected a new durable task"),
    };
    // The crashed run's acceptance: the row is accepted and unsettled.
    ingress.accept_admitted(&receipt, now()).unwrap();
    let row = ledger_store.task(&receipt.command_id).unwrap().unwrap();
    assert!(row.accepted_at.is_some());
    assert!(row.terminal_status.is_none());

    // Recovery on the reconstructed adapter: the accepted-unsettled row
    // is re-driven through the SAME normal path, not refused.
    let recovered = ingress
        .recover_intent(&row, now())
        .unwrap()
        .expect("an accepted unsettled intent is re-driven, not wedged");
    let recovered_receipt = match recovered {
        odin_hermes::ingress::RecoveredIntent::Admitted(receipt) => receipt,
        _other => panic!("expected an admitted recovery entry"),
    };
    assert_eq!(recovered_receipt.command_id, receipt.command_id);

    // The acceptance boundary is idempotent for the already-accepted row,
    // and the re-drive settles terminally — no loop, no wedge.
    let reaccepted = match ingress.accept_admitted(&recovered_receipt, now()).unwrap() {
        odin_hermes::ingress::AdmittedAccept::Accepted(accepted) => accepted,
        _other => panic!("expected the idempotent re-acceptance"),
    };
    ingress
        .settle_effect_failure(
            &reaccepted,
            "the conversation answer did not settle within its bound".to_owned(),
            now(),
        )
        .unwrap();
    let settled = ledger_store.task(&receipt.command_id).unwrap().unwrap();
    assert_eq!(
        settled.terminal_status,
        Some(CommandTerminalStatus::Failed),
        "the re-driven row settles terminally"
    );
    // A terminal row never re-enters the queue.
    assert!(ingress.recover_intent(&settled, now()).unwrap().is_none());
}
