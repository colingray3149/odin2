//! Prompt, cancellation, uncertain receipt and ordered output invariants.

use super::*;

#[tokio::test]
async fn first_prompt_gates_once_and_follow_ups_keep_the_plan() {
    let mut rig = make_rig("lifecycle", vec![], vec![]).await;
    open_session(&mut rig).await;
    assert_eq!(rig.ctx.subscribes.lock().as_slice(), [0]);

    let mut sequence = 0_u64;
    complete_first_turn(&mut rig, &mut sequence).await;
    assert_eq!(rig.gate_calls.load(Ordering::SeqCst), 1);
    let first = commands(&rig.ctx, 1).await;
    assert_eq!(first[0].command_id.to_string(), "command:first-prompt");
    assert_eq!(first[0].expected_epoch.get(), 1);
    assert!(matches!(
        first[0].body,
        live::LiveCommandBody::Prompt { .. }
    ));

    // An ordinary follow-up never runs the acceptance path again, and it
    // carries a fresh governed identity.
    send_message(
        Message::request(
            json!(3),
            "session/prompt",
            json!({ "sessionId": rig.session, "prompt": [{ "type": "text", "text": "second" }] }),
        ),
        &mut rig,
    )
    .await;
    let found = commands(&rig.ctx, 2).await;
    assert_eq!(rig.gate_calls.load(Ordering::SeqCst), 1);
    assert_ne!(found[1].command_id.to_string(), "command:first-prompt");
    assert!(matches!(
        found[1].body,
        live::LiveCommandBody::Prompt { .. }
    ));
    sequence += 1;
    push_event(&rig, sequence, state_body("idle", "running"));
    sequence += 1;
    push_event(&rig, sequence, state_body("running", "idle"));
    let response = next_message(&mut rig).await;
    assert_eq!(response.id, Some(json!(3)));
    assert_eq!(response.result.expect("result")["stopReason"], "end_turn");

    // A prompt while the turn is running becomes a governed FollowUp.
    sequence += 1;
    push_event(&rig, sequence, state_body("idle", "running"));
    sequence += 1;
    push_event(&rig, sequence, delta_body("state observed"));
    let observed = next_message(&mut rig).await;
    assert_eq!(
        observed.params.unwrap()["update"]["content"]["text"],
        "state observed"
    );
    send_message(
        Message::request(
            json!(4),
            "session/prompt",
            json!({ "sessionId": rig.session, "prompt": [{ "type": "text", "text": "steer" }] }),
        ),
        &mut rig,
    )
    .await;
    let found = commands(&rig.ctx, 3).await;
    assert!(matches!(
        found[2].body,
        live::LiveCommandBody::FollowUp { .. }
    ));
    sequence += 1;
    push_event(&rig, sequence, state_body("running", "idle"));
    let response = next_message(&mut rig).await;
    assert_eq!(response.id, Some(json!(4)));
}

#[tokio::test(start_paused = true)]
async fn cancel_sends_abort_current_turn_and_reports_cancelled() {
    let mut rig = make_rig("cancel", vec![], vec![]).await;
    open_session(&mut rig).await;
    let mut sequence = 0_u64;
    complete_first_turn(&mut rig, &mut sequence).await;

    // Start a new turn, cancel it, and observe the real outcome only.
    send_message(
        Message::request(
            json!(3),
            "session/prompt",
            json!({ "sessionId": rig.session, "prompt": [{ "type": "text", "text": "long" }] }),
        ),
        &mut rig,
    )
    .await;
    let _ = commands(&rig.ctx, 2).await;
    sequence += 1;
    push_event(&rig, sequence, state_body("idle", "running"));

    send_message(
        Message::notification("session/cancel", json!({ "sessionId": rig.session })),
        &mut rig,
    )
    .await;
    let found = commands(&rig.ctx, 3).await;
    assert!(matches!(
        found[2].body,
        live::LiveCommandBody::Abort {
            scope: live::AbortScope::CurrentTurn
        }
    ));
    sequence += 1;
    push_event(&rig, sequence, state_body("running", "idle"));
    expect_silence(&mut rig).await;
    sequence += 1;
    push_event(
        &rig,
        sequence,
        json!({
            "kind": "controlCompleted",
            "payload": live::CommandOutcome::Applied { command_id: found[2].command_id.clone() },
        }),
    );
    let response = next_message(&mut rig).await;
    assert_eq!(response.id, Some(json!(3)));
    assert_eq!(response.result.expect("result")["stopReason"], "cancelled");

    // Cancelling while nothing runs sends no command at all.
    let before = rig.ctx.received.lock().len();
    send_message(
        Message::notification("session/cancel", json!({ "sessionId": rig.session })),
        &mut rig,
    )
    .await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(rig.ctx.received.lock().len(), before);
}

#[tokio::test(start_paused = true)]
async fn cancel_before_running_sends_one_abort_when_running_arrives() {
    let mut rig = make_rig("cancel-pending", vec![], vec![]).await;
    open_session(&mut rig).await;

    // The prompt receipt is withheld: the send's fate is unknown and the
    // local state still looks idle.
    rig.ctx.stall_next_command.store(true, Ordering::SeqCst);
    send_message(
        Message::request(
            json!(2),
            "session/prompt",
            json!({ "sessionId": rig.session, "prompt": [{ "type": "text", "text": "go" }] }),
        ),
        &mut rig,
    )
    .await;
    let _ = commands(&rig.ctx, 1).await;

    // The cancel notification is still processed: the intent is recorded.
    send_message(
        Message::notification("session/cancel", json!({ "sessionId": rig.session })),
        &mut rig,
    )
    .await;

    // The running state arrives late from a real event: exactly one abort.
    push_event(&rig, 1, state_body("idle", "running"));
    let found = commands(&rig.ctx, 2).await;
    assert!(matches!(
        found[1].body,
        live::LiveCommandBody::Abort {
            scope: live::AbortScope::CurrentTurn
        }
    ));

    // Acceptance is not proof that abort took effect. Idle can arrive first.
    push_event(&rig, 2, state_body("running", "idle"));
    expect_silence(&mut rig).await;
    push_event(
        &rig,
        3,
        json!({
            "kind": "controlCompleted",
            "payload": live::CommandOutcome::Applied { command_id: found[1].command_id.clone() },
        }),
    );
    let response = next_message(&mut rig).await;
    assert_eq!(response.id, Some(json!(2)));
    assert_eq!(response.result.expect("result")["stopReason"], "cancelled");

    // Never a second abort for the same turn.
    let before = rig.ctx.received.lock().len();
    send_message(
        Message::notification("session/cancel", json!({ "sessionId": rig.session })),
        &mut rig,
    )
    .await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(rig.ctx.received.lock().len(), before);
}

#[tokio::test]
async fn failed_abort_reports_the_real_outcome() {
    let mut rig = make_rig("abort-refused", vec![], vec![]).await;
    open_session(&mut rig).await;
    let mut sequence = 0_u64;
    complete_first_turn(&mut rig, &mut sequence).await;

    send_message(
        Message::request(
            json!(3),
            "session/prompt",
            json!({ "sessionId": rig.session, "prompt": [{ "type": "text", "text": "long" }] }),
        ),
        &mut rig,
    )
    .await;
    let _ = commands(&rig.ctx, 2).await;
    sequence += 1;
    push_event(&rig, sequence, state_body("idle", "running"));

    // The controller refuses the abort: the cancel intent alone must never
    // turn the natural completion into a cancellation.
    rig.ctx
        .reject_next
        .lock()
        .replace(live::CommandRejection::EpochMismatch {
            expected: live::SessionEpoch::new(1),
            actual: live::SessionEpoch::new(2),
        });
    send_message(
        Message::notification("session/cancel", json!({ "sessionId": rig.session })),
        &mut rig,
    )
    .await;
    let found = commands(&rig.ctx, 3).await;
    assert!(matches!(
        found[2].body,
        live::LiveCommandBody::Abort {
            scope: live::AbortScope::CurrentTurn
        }
    ));
    sequence += 1;
    push_event(&rig, sequence, state_body("running", "idle"));
    let response = next_message(&mut rig).await;
    assert_eq!(response.id, Some(json!(3)));
    assert_eq!(response.result.expect("result")["stopReason"], "end_turn");
}

#[tokio::test]
async fn unknown_fate_turn_stays_pending_and_rejects_new_prompt_identity() {
    let mut rig = make_rig("unknown-fate", vec![], vec![]).await;
    open_session(&mut rig).await;
    let mut sequence = 0_u64;
    complete_first_turn(&mut rig, &mut sequence).await;

    // The connection drops before the receipt returns: no failure is
    // reported and the turn keeps its exact identity.
    rig.ctx.drop_next_command.store(true, Ordering::SeqCst);
    send_message(
        Message::request(
            json!(3),
            "session/prompt",
            json!({ "sessionId": rig.session, "prompt": [{ "type": "text", "text": "again" }] }),
        ),
        &mut rig,
    )
    .await;
    let found = commands(&rig.ctx, 2).await;
    assert_ne!(found[1].command_id.to_string(), "command:first-prompt");

    // A retry under a fresh identity is refused while the original turn is
    // still pending: no duplicate work, no second plan gate.
    send_message(
        Message::request(
            json!(4),
            "session/prompt",
            json!({ "sessionId": rig.session, "prompt": [{ "type": "text", "text": "retry" }] }),
        ),
        &mut rig,
    )
    .await;
    let response = next_message(&mut rig).await;
    let error = response.error.expect("in-flight refusal");
    assert_eq!(error.code, RpcError::INVALID_REQUEST);

    // Reconciliation on replay resends the EXACT command, never a remint.
    rig.ctx.pending.lock().push_back(None);
    let found = commands(&rig.ctx, 3).await;
    assert_eq!(found[1].command_id, found[2].command_id);

    // The original request is answered by the real turn outcome.
    sequence += 1;
    push_event(&rig, sequence, state_body("idle", "running"));
    sequence += 1;
    push_event(&rig, sequence, state_body("running", "idle"));
    let response = next_message(&mut rig).await;
    assert_eq!(response.id, Some(json!(3)));
    assert_eq!(response.result.expect("result")["stopReason"], "end_turn");
}

#[tokio::test]
async fn accepted_turn_that_fails_completes_with_an_error() {
    let mut rig = make_rig("accepted-failed", vec![], vec![]).await;
    open_session(&mut rig).await;
    send_message(
        Message::request(
            json!(2),
            "session/prompt",
            json!({ "sessionId": rig.session, "prompt": [{ "type": "text", "text": "go" }] }),
        ),
        &mut rig,
    )
    .await;
    let _ = commands(&rig.ctx, 1).await;
    push_event(&rig, 1, state_body("idle", "running"));

    // The real backend journals ControlAccepted(Accepted) and then
    // ControlCompleted(Failed) — without any Idle transition in between.
    let command_id = commands(&rig.ctx, 1).await.remove(0).command_id;
    push_event(&rig, 2, control_completed_failed(&command_id));
    let response = next_message(&mut rig).await;
    assert_eq!(response.id, Some(json!(2)));
    let error = response.error.expect("failed turn");
    assert_eq!(error.code, RpcError::GOVERNED_REFUSAL);

    // The session is not stuck: the next prompt is admitted under a fresh
    // identity and completes normally.
    push_event(&rig, 3, state_body("running", "idle"));
    send_message(
        Message::request(
            json!(3),
            "session/prompt",
            json!({ "sessionId": rig.session, "prompt": [{ "type": "text", "text": "next" }] }),
        ),
        &mut rig,
    )
    .await;
    let found = commands(&rig.ctx, 2).await;
    assert_ne!(found[1].command_id, command_id);
    push_event(&rig, 4, state_body("idle", "running"));
    push_event(&rig, 5, state_body("running", "idle"));
    let response = next_message(&mut rig).await;
    assert_eq!(response.id, Some(json!(3)));
    assert_eq!(response.result.expect("result")["stopReason"], "end_turn");
}

#[tokio::test]
async fn duplicate_receipt_replays_the_prior_command_outcome() {
    // A duplicate whose prior outcome failed completes the turn with the
    // real durable failure.
    let mut rig = make_rig("dup-failed", vec![], vec![]).await;
    open_session(&mut rig).await;
    rig.ctx
        .duplicate_outcome
        .lock()
        .replace(live::CommandOutcome::Failed {
            command_id: CommandId::new("command:first-prompt").expect("command id"),
            error: live::CommandFailure {
                code: "control_failed".to_owned(),
                message: "bridge went away".to_owned(),
                retryable: false,
            },
        });
    send_message(
        Message::request(
            json!(2),
            "session/prompt",
            json!({ "sessionId": rig.session, "prompt": [{ "type": "text", "text": "go" }] }),
        ),
        &mut rig,
    )
    .await;
    let _ = commands(&rig.ctx, 1).await;
    let response = next_message(&mut rig).await;
    assert_eq!(response.id, Some(json!(2)));
    let error = response.error.expect("failed duplicate");
    assert_eq!(error.code, RpcError::GOVERNED_REFUSAL);

    // A duplicate whose prior outcome was applied is NOT end-of-turn: the
    // turn waits for the real state change.
    let mut rig = make_rig("dup-applied", vec![], vec![]).await;
    open_session(&mut rig).await;
    rig.ctx
        .duplicate_outcome
        .lock()
        .replace(live::CommandOutcome::Applied {
            command_id: CommandId::new("command:first-prompt").expect("command id"),
        });
    send_message(
        Message::request(
            json!(2),
            "session/prompt",
            json!({ "sessionId": rig.session, "prompt": [{ "type": "text", "text": "go" }] }),
        ),
        &mut rig,
    )
    .await;
    let _ = commands(&rig.ctx, 1).await;
    expect_silence(&mut rig).await;
    push_event(&rig, 1, state_body("idle", "running"));
    push_event(&rig, 2, state_body("running", "idle"));
    let response = next_message(&mut rig).await;
    assert_eq!(response.id, Some(json!(2)));
    assert_eq!(response.result.expect("result")["stopReason"], "end_turn");
}

#[tokio::test]
async fn typed_epoch_refusal_stays_a_refusal_until_events_refresh() {
    let mut rig = make_rig("epoch-refusal", vec![], vec![]).await;
    open_session(&mut rig).await;
    let mut sequence = 0_u64;
    complete_first_turn(&mut rig, &mut sequence).await;

    // The typed epoch refusal is definitive: no remint, no resend, no
    // silent recovery — the prompt fails.
    rig.ctx
        .reject_next
        .lock()
        .replace(live::CommandRejection::EpochMismatch {
            expected: live::SessionEpoch::new(1),
            actual: live::SessionEpoch::new(2),
        });
    send_message(
        Message::request(
            json!(3),
            "session/prompt",
            json!({ "sessionId": rig.session, "prompt": [{ "type": "text", "text": "stale" }] }),
        ),
        &mut rig,
    )
    .await;
    let found = commands(&rig.ctx, 2).await;
    assert_eq!(found[1].expected_epoch.get(), 1);
    let response = next_message(&mut rig).await;
    let error = response.error.expect("epoch refusal");
    assert_eq!(error.code, RpcError::GOVERNED_REFUSAL);
    assert_eq!(rig.gate_calls.load(Ordering::SeqCst), 1);

    // Authoritative events refresh the epoch; only then does an explicit
    // new prompt succeed, under the refreshed fact.
    rig.ctx.session_epoch.store(2, Ordering::SeqCst);
    sequence += 1;
    push_event(&rig, sequence, state_body("idle", "running"));
    sequence += 1;
    push_event(&rig, sequence, state_body("running", "idle"));
    sequence += 1;
    push_event(&rig, sequence, delta_body("epoch observed"));
    let observed = next_message(&mut rig).await;
    assert_eq!(
        observed.params.unwrap()["update"]["content"]["text"],
        "epoch observed"
    );
    send_message(
        Message::request(
            json!(4),
            "session/prompt",
            json!({ "sessionId": rig.session, "prompt": [{ "type": "text", "text": "fresh" }] }),
        ),
        &mut rig,
    )
    .await;
    let found = commands(&rig.ctx, 3).await;
    assert_eq!(found[2].expected_epoch.get(), 2);
    sequence += 1;
    push_event(&rig, sequence, state_body("idle", "running"));
    sequence += 1;
    push_event(&rig, sequence, state_body("running", "idle"));
    let response = next_message(&mut rig).await;
    assert_eq!(response.id, Some(json!(4)));
    assert_eq!(response.result.expect("result")["stopReason"], "end_turn");
}

#[tokio::test]
async fn full_outbound_queue_still_delivers_the_terminal_response() {
    // A one-slot outbound queue: streaming updates fill it, and the turn
    // completes while it is still full.
    let mut rig = make_raw_rig_capacity("queue", vec![], vec![], 1, false).await;
    send_message(
        Message::request(
            json!(0),
            "initialize",
            json!({ "protocolVersion": ACP_PROTOCOL_VERSION, "clientCapabilities": {} }),
        ),
        &mut rig,
    )
    .await;
    let _ = next_message(&mut rig).await;
    open_session(&mut rig).await;
    send_message(
        Message::request(
            json!(2),
            "session/prompt",
            json!({ "sessionId": rig.session, "prompt": [{ "type": "text", "text": "go" }] }),
        ),
        &mut rig,
    )
    .await;
    let _ = commands(&rig.ctx, 1).await;

    push_event(&rig, 1, state_body("idle", "running"));
    push_event(&rig, 2, delta_body("one"));
    push_event(&rig, 3, delta_body("two"));
    push_event(&rig, 4, state_body("running", "idle"));

    // Everything is delivered, in order, including the terminal response
    // that was queued while the channel was full.
    let first = next_message(&mut rig).await;
    assert_eq!(first.params.expect("p")["update"]["content"]["text"], "one");
    let second = next_message(&mut rig).await;
    assert_eq!(
        second.params.expect("p")["update"]["content"]["text"],
        "two"
    );
    let response = next_message(&mut rig).await;
    assert_eq!(response.id, Some(json!(2)));
    assert_eq!(response.result.expect("result")["stopReason"], "end_turn");
}

#[tokio::test]
async fn gated_prompt_refusal_fails_the_prompt_without_fabricating_a_turn() {
    let mut rig = make_rig("gate-fail", vec![], vec![]).await;
    open_session(&mut rig).await;
    rig.gate_fail.store(true, Ordering::SeqCst);
    send_message(
        Message::request(
            json!(2),
            "session/prompt",
            json!({ "sessionId": rig.session, "prompt": [{ "type": "text", "text": "hello" }] }),
        ),
        &mut rig,
    )
    .await;
    let response = next_message(&mut rig).await;
    let error = response.error.expect("gate refusal");
    assert_eq!(error.code, RpcError::GOVERNED_REFUSAL);
    assert_eq!(rig.gate_calls.load(Ordering::SeqCst), 1);
    assert_eq!(rig.ctx.received.lock().len(), 1); // only Subscribe

    // The operator can retry once the gate can succeed.
    rig.gate_fail.store(false, Ordering::SeqCst);
    send_message(
        Message::request(
            json!(3),
            "session/prompt",
            json!({ "sessionId": rig.session, "prompt": [{ "type": "text", "text": "hello" }] }),
        ),
        &mut rig,
    )
    .await;
    let _ = commands(&rig.ctx, 1).await;
    assert_eq!(rig.gate_calls.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn backend_events_stream_as_acp_updates_in_order() {
    let mut rig = make_rig("updates", vec![], vec![]).await;
    open_session(&mut rig).await;
    send_message(
        Message::request(
            json!(2),
            "session/prompt",
            json!({ "sessionId": rig.session, "prompt": [{ "type": "text", "text": "go" }] }),
        ),
        &mut rig,
    )
    .await;
    let _ = commands(&rig.ctx, 1).await;

    push_event(&rig, 1, state_body("idle", "running"));
    push_event(&rig, 2, delta_body("working..."));
    let tool_started = json!({
        "kind": "toolStarted",
        "payload": { "turnId": "turn:1", "tool": {
            "toolUseId": "tool-9",
            "capabilityId": "seat.shell",
            "arguments": { "command": "ls" }
        }}
    });
    push_event(&rig, 3, tool_started);
    let tool_finished = json!({
        "kind": "toolFinished",
        "payload": { "turnId": "turn:1", "result": {
            "toolUseId": "tool-9",
            "content": [{ "kind": "text", "value": "done" }],
            "isError": false
        }}
    });
    push_event(&rig, 4, tool_finished);

    let update = next_message(&mut rig).await;
    assert_eq!(
        update.params.expect("p")["update"]["sessionUpdate"],
        "agent_message_chunk"
    );
    let update = next_message(&mut rig).await;
    let params = update.params.expect("p");
    assert_eq!(params["update"]["sessionUpdate"], "tool_call");
    assert_eq!(params["update"]["toolCallId"], "tool-9");
    assert_eq!(params["update"]["kind"], "execute");
    assert_eq!(params["update"]["rawInput"]["command"], "ls");
    let update = next_message(&mut rig).await;
    let params = update.params.expect("p");
    assert_eq!(params["update"]["sessionUpdate"], "tool_call_update");
    assert_eq!(params["update"]["status"], "completed");

    push_event(
        &rig,
        5,
        json!({
            "kind": "result",
            "payload": { "summary": "result summary", "artifacts": [] },
        }),
    );
    let result = next_message(&mut rig).await;
    assert_eq!(
        result.params.unwrap()["update"]["content"]["text"],
        "result summary"
    );
    push_event(&rig, 6, state_body("running", "idle"));
    let response = next_message(&mut rig).await;
    assert_eq!(response.id, Some(json!(2)));
    assert_eq!(response.result.expect("result")["stopReason"], "end_turn");
}

/// A terminal Result can repeat the assistant message already shown to the editor.
#[tokio::test]
async fn a_turn_result_repeating_the_final_answer_is_shown_once() {
    let mut rig = make_rig("result-once", vec![], vec![]).await;
    open_session(&mut rig).await;
    send_message(
        Message::request(
            json!(2),
            "session/prompt",
            json!({ "sessionId": rig.session, "prompt": [{ "type": "text", "text": "go" }] }),
        ),
        &mut rig,
    )
    .await;
    let _ = commands(&rig.ctx, 1).await;
    push_event(&rig, 1, state_body("idle", "running"));
    push_event(&rig, 2, message_body("Final answer."));
    push_event(
        &rig,
        3,
        json!({ "kind": "result", "payload": { "summary": "Final answer.", "artifacts": [] } }),
    );
    push_event(&rig, 4, state_body("running", "idle"));
    let shown = next_message(&mut rig).await;
    assert_eq!(
        shown.params.expect("p")["update"]["content"]["text"],
        "Final answer."
    );
    let response = next_message(&mut rig).await;
    assert_eq!(
        response.id,
        Some(json!(2)),
        "the turn ends without a second copy of the answer"
    );
}

#[tokio::test]
async fn a_provider_failure_restarts_instead_of_leaving_the_turn_open() {
    let mut rig = make_rig("provider-failed", vec![], vec![]).await;
    open_session(&mut rig).await;
    send_message(
        Message::request(
            json!(2),
            "session/prompt",
            json!({ "sessionId": rig.session, "prompt": [{ "type": "text", "text": "hello" }] }),
        ),
        &mut rig,
    )
    .await;
    let _ = commands(&rig.ctx, 1).await;
    push_event(&rig, 1, state_body("idle", "running"));
    push_event(&rig, 2, state_body("running", "failed"));
    let response = next_message(&mut rig).await;
    assert_eq!(response.id, Some(json!(2)));
    assert!(
        response.error.is_some(),
        "the stuck turn ends with the failure, not silence"
    );
    let found = commands(&rig.ctx, 2).await;
    assert!(
        matches!(found[1].body, live::LiveCommandBody::Restart),
        "a provider failure requests Restart: {:?}",
        found[1].body
    );
}

#[tokio::test]
async fn a_replayed_provider_failure_settles_only_when_replay_completes() {
    let mut rig = make_rig("replay-failed", vec![], vec![]).await;
    open_session(&mut rig).await;
    send_message(
        Message::request(
            json!(2),
            "session/prompt",
            json!({ "sessionId": rig.session, "prompt": [{ "type": "text", "text": "hello" }] }),
        ),
        &mut rig,
    )
    .await;
    let prompted = commands(&rig.ctx, 1).await;
    assert_eq!(prompted.len(), 1);

    let session_id = live::LiveSessionId::parse(&rig.session).expect("session");
    push_live(
        &rig,
        live::LiveServerMessage::ReplayBegin {
            session_id,
            requested_after: live::EventSeq::new(1),
            head: live::EventSeq::new(3),
        },
    );
    push_event(&rig, 2, state_body("running", "failed"));
    push_event(&rig, 3, message_body("still replaying"));
    let update = next_message(&mut rig).await;
    assert!(
        update.id.is_none() && update.error.is_none(),
        "a Failed state seen only in replay must not settle the prompt: {update:?}"
    );
    tokio::time::sleep(std::time::Duration::from_millis(150)).await;
    assert_eq!(
        commands(&rig.ctx, 1).await.len(),
        1,
        "Restart must wait until replay completes"
    );

    rig.ctx.stall_next_command.store(true, Ordering::SeqCst);
    push_live(
        &rig,
        live::LiveServerMessage::ReplayComplete {
            session_id,
            head: live::EventSeq::new(3),
        },
    );
    let response = next_message(&mut rig).await;
    assert_eq!(response.id, Some(json!(2)));
    assert!(
        response.error.is_some(),
        "replay completion settles the failed turn"
    );
    let found = commands(&rig.ctx, 2).await;
    assert!(
        matches!(found[1].body, live::LiveCommandBody::Restart),
        "replay completion requests Restart once: {:?}",
        found[1].body
    );
    push_live(
        &rig,
        live::LiveServerMessage::ReplayBegin {
            session_id,
            requested_after: live::EventSeq::new(3),
            head: live::EventSeq::new(4),
        },
    );
    push_event(&rig, 4, state_body("idle", "failed"));
    push_live(
        &rig,
        live::LiveServerMessage::ReplayComplete {
            session_id,
            head: live::EventSeq::new(4),
        },
    );
    tokio::time::sleep(std::time::Duration::from_millis(150)).await;
    let after = commands(&rig.ctx, 2).await;
    assert_eq!(
        after.len(),
        2,
        "an unsettled Restart must not mint a second id: {after:?}"
    );
    assert_eq!(after[1].command_id, found[1].command_id);
}
