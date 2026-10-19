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

async fn admitted(plane: &FakePlane, session: LiveSessionId, prefix: &str) -> Vec<String> {
    plane
        .history(HistoryQuery {
            session_id: session,
            after: EventSeq::new(0),
            limit: std::num::NonZeroU16::new(500).expect("limit"),
        })
        .await
        .expect("history")
        .events
        .into_iter()
        .filter_map(|event| match event.body {
            LiveEventBody::ControlAccepted(CommandReceipt::Accepted { command_id })
                if command_id.as_str().starts_with(prefix) =>
            {
                Some(command_id.to_string())
            }
            _ => None,
        })
        .collect()
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

/// Every ask folded into one queued prompt owns that one queued prompt, not
/// the direct turns that came before or after it.
#[tokio::test(start_paused = true)]
async fn queued_asks_own_only_their_one_queued_prompt() {
    let (dir, plane, egress, approvals, root) = harness().await;
    root.initialize().await.expect("initialize");
    let session = root
        .current_vehicle_session()
        .await
        .expect("vehicle")
        .expect("vehicle");
    root.execute(said("before")).await.expect("settles");
    let outcomes = root.execute_batch(vec![said("ask-a"), said("ask-b")]).await;
    for outcome in &outcomes {
        assert_eq!(outcome.as_ref().expect("queued")["queued"], true);
    }
    sends_reach(&egress, 2).await;
    root.join_background(StdDuration::from_secs(600)).await;
    root.execute(said("after")).await.expect("settles");
    let direct = admitted(&plane, session, "command:intent:").await;
    let queued = admitted(&plane, session, "command:queued-turn:").await;
    assert_eq!(
        (direct.len(), queued.len()),
        (2, 1),
        "{direct:?} {queued:?}"
    );
    drop(root);
    let sends = egress.sends();
    let commands = plane.commands.lock().len();

    let reopened = root_in(dir.path(), plane.clone(), egress.clone(), approvals.clone());
    let receipt = |key: &'static str| {
        let reopened = Arc::clone(&reopened);
        async move { reopened.execute(said(key)).await.expect("receipt") }
    };
    let queued_pair = Some(vec![pair(&session, &queued[0])]);
    assert_eq!(owned(&receipt("ask-a").await), queued_pair);
    assert_eq!(owned(&receipt("ask-b").await), queued_pair);
    assert_eq!(
        owned(&receipt("before").await),
        Some(vec![pair(&session, &direct[0])])
    );
    assert_eq!(
        owned(&receipt("after").await),
        Some(vec![pair(&session, &direct[1])])
    );
    assert_eq!(egress.sends(), sends, "a replay never resends");
    assert_eq!(plane.commands.lock().len(), commands, "nor re-admits");
}

/// A turn that was silent, was reprompted, and then outlived the answer bound
/// is delivered late; its final receipt still owns both prompts the handed-off
/// turn ran, though the in-flight record was retired at the handoff.
#[tokio::test(start_paused = true)]
async fn a_late_answer_receipt_keeps_the_prompts_the_handed_off_turn_ran() {
    let (dir, plane, egress, approvals, root) = harness().await;
    root.initialize().await.expect("initialize");
    let session = root
        .current_vehicle_session()
        .await
        .expect("vehicle")
        .expect("vehicle");
    plane.silent_turns.store(1, Ordering::SeqCst);
    plane.hold_running.store(true, Ordering::SeqCst);
    let handed = root.execute(said("slow-silent")).await.expect("handed off");
    assert_eq!(handed["lateAnswer"], true);
    plane.hold_running.store(false, Ordering::SeqCst);
    plane.finish_turn(&session, "The late answer.").await;
    sends_reach(&egress, 2).await;
    root.join_background(StdDuration::from_secs(600)).await;
    assert_eq!(egress.sends().len(), 2, "{:?}", egress.sends());
    let original = admitted(&plane, session, "command:intent:").await;
    let reprompt = admitted(&plane, session, "command:silent:").await;
    assert_eq!((original.len(), reprompt.len()), (1, 1));
    drop(root);
    let sends = egress.sends();
    let commands = plane.commands.lock().len();

    let reopened = root_in(dir.path(), plane.clone(), egress.clone(), approvals.clone());
    let replay = reopened
        .execute(said("slow-silent"))
        .await
        .expect("late original-key receipt");
    assert_eq!(replay["replySent"], true);
    assert_eq!(
        owned(&replay),
        Some(vec![
            pair(&session, &original[0]),
            pair(&session, &reprompt[0]),
        ])
    );
    assert_eq!(egress.sends(), sends);
    assert_eq!(plane.commands.lock().len(), commands);
}

/// A flight the journal never admitted is observed unbound and still settles;
/// its receipt names no prompt, and never the unadmitted command's id. A
/// neighbouring bound turn on the same session keeps its own admitted prompt.
#[tokio::test(start_paused = true)]
async fn an_unadmitted_flight_settles_without_inventing_a_prompt_identity() {
    let (dir, plane, egress, approvals, root) = harness().await;
    root.initialize().await.expect("initialize");
    let session = root
        .current_vehicle_session()
        .await
        .expect("vehicle")
        .expect("vehicle");
    root.execute(said("bound")).await.expect("settles");
    let bound = admitted(&plane, session, "command:intent:").await;
    assert_eq!(bound.len(), 1, "{bound:?}");

    let unadmitted = crate::conversation::identity::bounded_command("intent", &["unbound"])
        .expect("command id")
        .to_string();
    let head = plane.ledger.head(session).await.expect("head").get();
    let mut record = root.load_record().expect("record");
    record.in_flight = Some(
        serde_json::from_value(serde_json::json!({
            "idempotencyKey": "unbound",
            "content": "the same words",
            "commandId": unadmitted,
            "sessionId": session.to_string(),
            "kind": "prompt",
            "expectedEpoch": 1,
            "eventCursor": head,
            "phase": "sent",
        }))
        .expect("in-flight prompt"),
    );
    record.last_idempotency_key = None;
    record.last_projection = None;
    root.store_record(&mut record).expect("record stored");
    plane
        .push_event(
            &session,
            LiveEventBody::AssistantMessage(text_message("The unbound answer.")),
        )
        .await;
    plane
        .push_state_change(&session, LiveSessionState::Idle)
        .await;

    let settled = root
        .execute(said("unbound"))
        .await
        .expect("observed settle");
    assert_eq!(settled["answer"], "The unbound answer.");
    assert!(plane.command_entries(&unadmitted).is_empty());
    drop(root);

    let reopened = root_in(dir.path(), plane.clone(), egress.clone(), approvals.clone());
    let replay = reopened.execute(said("unbound")).await.expect("receipt");
    for projection in [&settled, &replay] {
        assert_eq!(owned(projection), None, "{projection}");
        assert!(
            !projection.to_string().contains(&unadmitted),
            "{projection}"
        );
    }
    let neighbour = reopened.execute(said("bound")).await.expect("receipt");
    assert_eq!(owned(&neighbour), Some(vec![pair(&session, &bound[0])]));
}

/// Makes every write to a conversation reply's durable row fail, as a full or
/// read-only ledger would, while the journal and the conversation record file
/// stay writable. `repair` removes it again.
fn break_reply_ledger(dir: &std::path::Path) {
    let connection = rusqlite::Connection::open(state_ledger_path(dir)).expect("ledger");
    for (name, event) in [
        ("fault_reply_insert", "INSERT"),
        ("fault_reply_update", "UPDATE"),
    ] {
        connection
            .execute(
                &format!(
                    "CREATE TRIGGER {name} BEFORE {event} ON materialized_status \
                     WHEN NEW.object_kind = 'conversation_delivery' \
                     BEGIN SELECT RAISE(ABORT, 'injected reply ledger fault'); END"
                ),
                [],
            )
            .expect("install fault");
    }
}

fn repair_reply_ledger(dir: &std::path::Path) {
    let connection = rusqlite::Connection::open(state_ledger_path(dir)).expect("ledger");
    for name in ["fault_reply_insert", "fault_reply_update"] {
        connection
            .execute(&format!("DROP TRIGGER {name}"), [])
            .expect("repair fault");
    }
}

/// The journal admitted the prompt, then the reply ledger could not record
/// that proof. The failure is observable, but the admitted command is not
/// erased: after repair the same key owns its one existing prompt, which is
/// neither re-admitted nor resent, and the receipt names exactly it.
#[tokio::test(start_paused = true)]
async fn an_admitted_prompt_survives_a_failed_provenance_write() {
    let (dir, plane, egress, approvals, root) = harness().await;
    root.initialize().await.expect("initialize");
    let session = root
        .current_vehicle_session()
        .await
        .expect("vehicle")
        .expect("vehicle");

    break_reply_ledger(dir.path());
    let failure = root
        .execute(said("custody"))
        .await
        .expect_err("an unrecorded admission is not a settled turn");
    assert_eq!(failure, IntentFailure::ReplyStateUnavailable);
    let first = admitted(&plane, session, "command:intent:").await;
    assert_eq!(first.len(), 1, "the journal admitted it: {first:?}");
    assert!(egress.sends().is_empty(), "{:?}", egress.sends());
    let flight = root
        .load_record()
        .expect("durable record")
        .in_flight
        .expect("proven admission survives a reply-ledger failure");
    assert_eq!(flight.command_id, first[0]);

    repair_reply_ledger(dir.path());
    let settled = root.execute(said("custody")).await.expect("settles");
    assert_eq!(
        admitted(&plane, session, "command:intent:").await,
        first,
        "the retry must observe the admitted command, not admit another"
    );
    assert_eq!(plane.prompt_count("command:intent:"), 1);
    assert_eq!(owned(&settled), Some(vec![pair(&session, &first[0])]));
    assert_eq!(egress.sends().len(), 1, "{:?}", egress.sends());
    drop(root);
    let sends = egress.sends();
    let commands = plane.commands.lock().len();

    let reopened = root_in(dir.path(), plane.clone(), egress.clone(), approvals.clone());
    let replay = reopened.execute(said("custody")).await.expect("receipt");
    assert_eq!(owned(&replay), Some(vec![pair(&session, &first[0])]));
    assert_eq!(egress.sends(), sends, "a replay never resends");
    assert_eq!(plane.commands.lock().len(), commands, "nor re-admits");
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

/// A frozen receipt is immutable: re-recording its own admission is
/// idempotent, but a different command or session for the same key is
/// refused, and the original provenance is what every replay still returns.
#[tokio::test(start_paused = true)]
async fn a_frozen_receipt_refuses_a_contradictory_admission() {
    let (dir, plane, egress, approvals, root) = harness().await;
    root.initialize().await.expect("initialize");
    let session = root
        .current_vehicle_session()
        .await
        .expect("vehicle")
        .expect("vehicle");
    let settled = root.execute(said("sealed")).await.expect("settles");
    let ids = admitted(&plane, session, "command:intent:").await;
    assert_eq!(ids.len(), 1, "{ids:?}");
    let original = Some(vec![pair(&session, &ids[0])]);
    assert_eq!(owned(&settled), original);

    root.record_admitted_prompt("sealed", &session.to_string(), &ids[0])
        .expect("the same admission again is idempotent");
    root.record_admitted_prompt("sealed", &session.to_string(), "command:intent:foreign")
        .expect_err("another command cannot join a frozen receipt");
    root.record_admitted_prompt("sealed", "run:live:foreign-session", &ids[0])
        .expect_err("nor the same command on another session");
    drop(root);
    let sends = egress.sends();
    let commands = plane.commands.lock().len();

    let reopened = root_in(dir.path(), plane.clone(), egress.clone(), approvals.clone());
    let replay = reopened.execute(said("sealed")).await.expect("receipt");
    assert_eq!(owned(&replay), original, "{replay}");
    assert_eq!(egress.sends(), sends, "a replay never resends");
    assert_eq!(plane.commands.lock().len(), commands, "nor re-admits");
}

/// No row is an unknown receipt (nothing stamped); an unreadable row is an
/// error, never that absence.
#[tokio::test(start_paused = true)]
async fn an_unreadable_provenance_row_is_an_error_not_an_absent_proof() {
    let (dir, _plane, _egress, _approvals, root) = harness().await;
    root.initialize().await.expect("initialize");
    let mut unseen = serde_json::json!({"answer": "x"});
    root.stamp_prompts("no-row", &mut unseen)
        .expect("a key with no row is unknown, not unreadable");
    assert_eq!(owned(&unseen), None);

    root.reply_delivery("garbled", None, None)
        .expect("open the row");
    rusqlite::Connection::open(state_ledger_path(dir.path()))
        .expect("ledger")
        .execute(
            "UPDATE materialized_status SET status_json = 'not json' \
             WHERE object_kind = 'conversation_delivery'",
            [],
        )
        .expect("corrupt the row");
    let mut projection = serde_json::json!({"answer": "x"});
    root.stamp_prompts("garbled", &mut projection)
        .expect_err("an undecodable row is not an absent proof");
    assert_eq!(projection, serde_json::json!({"answer": "x"}));
}

/// A receipt frozen before this provenance existed stays unknown: a live turn
/// with identical words and answer in the journal is not borrowed for it.
#[tokio::test(start_paused = true)]
async fn a_legacy_frozen_receipt_never_borrows_a_matching_live_prompt() {
    let (dir, plane, egress, approvals, root) = harness().await;
    root.initialize().await.expect("initialize");
    let session = root
        .current_vehicle_session()
        .await
        .expect("vehicle")
        .expect("vehicle");
    let live = root.execute(said("live")).await.expect("settles");
    let admissions = admitted(&plane, session, "command:intent:").await;
    assert_eq!(admissions.len(), 1, "{admissions:?}");
    assert_eq!(owned(&live), Some(vec![pair(&session, &admissions[0])]));

    let legacy = serde_json::json!({
        "conversationId": root.conversation_id,
        "session": session.to_string(),
        "commandId": "cmd-legacy",
        "idempotencyKey": "legacy",
        "answer": live["answer"],
        "waitingOnApproval": false,
        "replySent": true,
    });
    root.deliver_final("legacy", "A plain answer.", Some(&legacy))
        .expect("legacy receipt committed");
    drop(root);
    let sends = egress.sends();

    let reopened = root_in(dir.path(), plane.clone(), egress.clone(), approvals.clone());
    let replay = reopened.execute(said("legacy")).await.expect("receipt");
    assert_eq!(replay["commandId"], "cmd-legacy");
    assert_eq!(replay["session"], session.to_string());
    assert_eq!(owned(&replay), None, "{replay}");
    assert_eq!(egress.sends(), sends);
}
