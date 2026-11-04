//! A settled reply names the live prompts it owns. The oracle is the live
//! journal's own admission record, never the reply text or an id shape: a
//! consumer holding only an original key's durable receipt must learn which
//! admitted `(session, command)` pairs that key's result and effects belong to.

use super::*;
use crate::runtime::ApprovedIntentRoute as _;

fn said(key: &str) -> ApprovedIntentExecution {
    ApprovedIntentExecution {
        content: "the same words".to_owned(),
        ..intent(key)
    }
}

fn owned(projection: &serde_json::Value) -> Option<Vec<(String, String)>> {
    projection.get("promptCommands").map(|list| {
        list.as_array()
            .expect("promptCommands is a list")
            .iter()
            .map(|prompt| {
                (
                    prompt["session"]
                        .as_str()
                        .expect("prompt session")
                        .to_owned(),
                    prompt["commandId"]
                        .as_str()
                        .expect("prompt command")
                        .to_owned(),
                )
            })
            .collect()
    })
}

fn pair(session: &LiveSessionId, command: &str) -> (String, String) {
    (session.to_string(), command.to_owned())
}

/// Two original keys with the same words and the same answer stay
/// distinguishable by their own admitted prompts after a newer turn, a root
/// reopen and a replay; the replay sends nothing and admits nothing.
#[tokio::test(start_paused = true)]
async fn identical_replies_to_different_keys_keep_their_own_admitted_prompt() {
    let (dir, plane, egress, approvals, root) = harness().await;
    root.initialize().await.expect("initialize");
    let session = root
        .current_vehicle_session()
        .await
        .expect("vehicle")
        .expect("vehicle");
    for key in ["twin-a", "twin-b", "twin-c"] {
        root.execute(said(key)).await.expect("settles");
    }
    let admissions = admitted(&plane, session, "command:intent:").await;
    assert_eq!(admissions.len(), 3, "{admissions:?}");
    drop(root);
    let sends = egress.sends();
    let commands = plane.commands.lock().len();

    let reopened = root_in(dir.path(), plane.clone(), egress.clone(), approvals.clone());
    let first = reopened.execute(said("twin-a")).await.expect("receipt a");
    let second = reopened.execute(said("twin-b")).await.expect("receipt b");
    assert_eq!(first["answer"], second["answer"]);
    assert_eq!(owned(&first), Some(vec![pair(&session, &admissions[0])]));
    assert_eq!(owned(&second), Some(vec![pair(&session, &admissions[1])]));
    assert_eq!(egress.sends(), sends, "a replay never resends");
    assert_eq!(plane.commands.lock().len(), commands, "nor re-admits");
}

/// An original key's replay keeps the vehicle and prompt that answered it,
/// not the successor vehicle or the newer turn that moved the conversation on.
/// A turn whose first prompt was admitted and then refused still owns that
/// prompt (admission is not success) beside the one that answered on the
/// successor, each with its own session.
#[tokio::test(start_paused = true)]
async fn an_original_replay_never_borrows_the_successor_vehicle_or_a_newer_prompt() {
    let (dir, plane, egress, approvals, root) = harness().await;
    root.initialize().await.expect("initialize");
    let first = root
        .current_vehicle_session()
        .await
        .expect("vehicle")
        .expect("vehicle");
    root.execute(said("orig")).await.expect("settles");
    let original = admitted(&plane, first, "command:intent:").await;
    assert_eq!(original.len(), 1, "{original:?}");

    plane.refuse_context.store(1, Ordering::SeqCst);
    root.execute(said("newer"))
        .await
        .expect("answers on the successor");
    let successor = root
        .current_vehicle_session()
        .await
        .expect("vehicle")
        .expect("vehicle");
    assert_ne!(successor, first, "the conversation rolled");
    let newer = admitted(&plane, successor, "command:intent:").await;
    assert_eq!(newer.len(), 1, "{newer:?}");
    let on_first = admitted(&plane, first, "command:intent:").await;
    assert_eq!(
        on_first.len(),
        2,
        "the refused attempt was admitted: {on_first:?}"
    );
    drop(root);
    let sends = egress.sends();
    let commands = plane.commands.lock().len();

    let reopened = root_in(dir.path(), plane.clone(), egress.clone(), approvals.clone());
    let replay = reopened.execute(said("orig")).await.expect("receipt");
    assert_eq!(replay["session"], first.to_string());
    assert_eq!(on_first[0], original[0]);
    assert_eq!(owned(&replay), Some(vec![pair(&first, &original[0])]));
    let newer_receipt = reopened.execute(said("newer")).await.expect("receipt");
    assert_eq!(
        owned(&newer_receipt),
        Some(vec![
            pair(&first, &on_first[1]),
            pair(&successor, &newer[0])
        ])
    );
    assert_eq!(egress.sends(), sends, "a replay never resends");
    assert_eq!(plane.commands.lock().len(), commands, "nor re-admits");
}

/// A silent turn's single reprompt belongs to the same logical intent: its
/// receipt owns the original prompt and the reprompt, in admission order.
#[tokio::test(start_paused = true)]
async fn a_reprompted_turn_owns_both_admitted_prompts() {
    let (dir, plane, egress, approvals, root) = harness().await;
    root.initialize().await.expect("initialize");
    let session = root
        .current_vehicle_session()
        .await
        .expect("vehicle")
        .expect("vehicle");
    plane.silent_turns.store(1, Ordering::SeqCst);
    let settled = root.execute(said("silent-ask")).await.expect("answers");
    let original = admitted(&plane, session, "command:intent:").await;
    let reprompt = admitted(&plane, session, "command:silent:").await;
    assert_eq!((original.len(), reprompt.len()), (1, 1));
    let expected = Some(vec![
        pair(&session, &original[0]),
        pair(&session, &reprompt[0]),
    ]);
    assert_eq!(owned(&settled), expected);
    drop(root);
    let sends = egress.sends();

    let reopened = root_in(dir.path(), plane.clone(), egress.clone(), approvals.clone());
    let replay = reopened.execute(said("silent-ask")).await.expect("receipt");
    assert_eq!(owned(&replay), expected);
    assert_eq!(egress.sends(), sends);
}

#[tokio::test(start_paused = true)]
async fn a_failed_reply_freeze_preserves_the_admitted_flight_across_reopen() {
    let (dir, plane, egress, approvals, root) = harness().await;
    root.initialize().await.expect("initialize");
    let session = root.current_vehicle_session().await.unwrap().unwrap();
    let connection = rusqlite::Connection::open(state_ledger_path(dir.path())).unwrap();
    connection
        .execute(
            "CREATE TRIGGER fault_reply_freeze BEFORE UPDATE ON materialized_status \
             WHEN NEW.object_kind = 'conversation_delivery' \
             AND json_extract(NEW.status_json, '$.final_answer') IS NOT NULL \
             BEGIN SELECT RAISE(ABORT, 'injected freeze failure'); END",
            [],
        )
        .unwrap();
    root.execute(said("freeze"))
        .await
        .expect_err("the final receipt could not be frozen");
    let commands = admitted(&plane, session, "command:intent:").await;
    assert_eq!(commands.len(), 1);
    let flight = root
        .load_record()
        .unwrap()
        .in_flight
        .expect("admission retained");
    assert_eq!(flight.command_id, commands[0]);
    drop(root);
    connection
        .execute("DROP TRIGGER fault_reply_freeze", [])
        .unwrap();

    let reopened = root_in(dir.path(), plane.clone(), egress.clone(), approvals.clone());
    let settled = reopened
        .execute(said("freeze"))
        .await
        .expect("settles after repair");
    assert_eq!(admitted(&plane, session, "command:intent:").await, commands);
    assert_eq!(owned(&settled), Some(vec![pair(&session, &commands[0])]));
    assert_eq!(settled["replySent"], true);
    let sends = egress.sends();
    assert_eq!(sends.len(), 1);
    reopened.execute(said("freeze")).await.expect("replay");
    assert_eq!(egress.sends(), sends);
    assert_eq!(admitted(&plane, session, "command:intent:").await, commands);
}
