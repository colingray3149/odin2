//! Resume accepted intents without consuming approval again; expired intents retain owner-notice content.

use crate::discord::fixtures::{allowing, ingress_config, message, now, pairing, store, OWNER};
use odin_domain::EffectClass;
use odin_hermes::ingress::{DiscordIngress, IntentOutcome};
use odin_ledger::Ledger;

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
