//! Resume accepted intents without consuming approval again; expired intents retain owner-notice content.

use crate::fixtures::{allowing, ingress_config, message, now, pairing, store, OWNER};
use odin_domain::EffectClass;
use odin_hermes::correlation::identity_from_key;
use odin_hermes::ingress::{DiscordIngress, IntentOutcome};
use odin_ledger::Ledger;
#[tokio::test]
async fn r3_accepted_unsettled_recovery_re_drives_through_the_consumed_gate() {
    let ledger_store = store(Ledger::open_in_memory().unwrap());
    let ingress = DiscordIngress::new(
        pairing(),
        ledger_store.clone(),
        allowing(),
        ingress_config(EffectClass::R3),
    );
    let receipt = match ingress
        .admit(
            &message("1000000000000000077", OWNER, "remember my midterm moved"),
            now(),
        )
        .unwrap()
    {
        IntentOutcome::EffectGated(receipt, pending) => {
            // The production admit path: the paired owner's own message IS
            // the operator approval for the intent's execution gate.
            ingress
                .decide_effect_approval(
                    &pending,
                    odin_ledger::approval::ApprovalDecision::Approve { evidence_ref: None },
                    "discord-owner:260116911398977548",
                    now(),
                )
                .unwrap();
            receipt
        }
        _other => panic!("expected gated"),
    };
    // Decide the approval (the owner's own message approved it), then the
    // gate ACCEPTS — and the run dies before any settle.
    let approval_id = odin_domain::ApprovalId::new(format!(
        "approval:discord-intent:{}",
        identity_from_key(receipt.idempotency_key.as_str())
    ))
    .unwrap();
    let approval = ledger_store.approval(&approval_id).unwrap().unwrap();
    let accepted = match ingress
        .gate_effect(&receipt, &approval_id, approval.revision, now())
        .unwrap()
    {
        odin_hermes::ingress::EffectGate::Approved { accepted } => accepted,
        _other => panic!("expected approved gate"),
    };
    drop(accepted); // crash: no settle
    let row = ledger_store.task(&receipt.command_id).unwrap().unwrap();
    assert!(row.accepted_at.is_some());
    assert!(row.terminal_status.is_none());

    // Recovery: the reconstructed adapter must re-drive the row.
    let recovered = ingress
        .recover_intent(&row, now())
        .unwrap()
        .expect("recovered");
    let (r_receipt, r_pending) = match recovered {
        odin_hermes::ingress::RecoveredIntent::Gated(receipt, pending) => (receipt, pending),
        _other => panic!("expected gated recovery"),
    };
    // The re-drive through the gate must be idempotent for the accepted row.
    let approval2 = ledger_store
        .approval(&r_pending.approval_id)
        .unwrap()
        .unwrap();
    match ingress
        .gate_effect(
            &r_receipt,
            &r_pending.approval_id,
            approval2.revision,
            now(),
        )
        .unwrap()
    {
        odin_hermes::ingress::EffectGate::Approved { .. } => println!("PROBE: re-gate OK"),
        odin_hermes::ingress::EffectGate::Denied { .. } => panic!("re-gate DENIED"),
        odin_hermes::ingress::EffectGate::Blocked { reason } => panic!("re-gate BLOCKED: {reason}"),
    }
    // The re-driven row settles terminally through the normal path.
    match ingress
        .gate_effect(
            &r_receipt,
            &r_pending.approval_id,
            approval2.revision,
            now(),
        )
        .unwrap()
    {
        odin_hermes::ingress::EffectGate::Approved { accepted } => {
            ingress
                .settle_effect_failure(
                    &accepted,
                    "the conversation answer did not settle within its bound".to_owned(),
                    now(),
                )
                .unwrap();
        }
        _other => panic!("second re-gate failed"),
    }
    let settled = ledger_store.task(&receipt.command_id).unwrap().unwrap();
    assert_eq!(
        settled.terminal_status,
        Some(odin_ledger::command::CommandTerminalStatus::Failed)
    );
}

#[tokio::test]
async fn expired_unsettled_intent_settles_and_carries_its_content() {
    let ledger_store = store(Ledger::open_in_memory().unwrap());
    let ingress = DiscordIngress::new(
        pairing(),
        ledger_store.clone(),
        allowing(),
        ingress_config(EffectClass::R1),
    );
    let issued = now();
    let receipt = match ingress
        .admit(
            &message("1000000000000000088", OWNER, "remember my midterm moved"),
            issued,
        )
        .unwrap()
    {
        IntentOutcome::Admitted(receipt) => receipt,
        _other => panic!("expected admitted"),
    };
    // Far past the declared TTL.
    let later = issued + time::Duration::seconds(4000);
    let row = ledger_store.task(&receipt.command_id).unwrap().unwrap();
    let recovered = ingress
        .recover_intent(&row, later)
        .unwrap()
        .expect("expired recovery");
    match recovered {
        odin_hermes::ingress::RecoveredIntent::Expired {
            command_id,
            content,
        } => {
            assert_eq!(command_id, receipt.command_id);
            assert_eq!(content, "remember my midterm moved");
        }
        _other => panic!("expected the expired outcome"),
    }
    let settled = ledger_store.task(&receipt.command_id).unwrap().unwrap();
    assert_eq!(
        settled.terminal_status,
        Some(odin_ledger::command::CommandTerminalStatus::Failed)
    );
    assert_eq!(
        settled.terminal_result.clone().unwrap()["reason"],
        serde_json::json!("expired")
    );
    // A terminal row never re-enters any queue.
    assert!(ingress.recover_intent(&settled, later).unwrap().is_none());
}
