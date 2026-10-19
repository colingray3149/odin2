//! Exact native and kernel decision binding and resolution invariants.

use super::*;

#[tokio::test]
async fn permission_decision_binds_to_the_exact_outstanding_request() {
    let mut rig = make_rig("permission", vec![], vec![]).await;
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
    push_event(&rig, 2, permission_body("perm:abc", "tool-1"));

    // The frontend asks the ACP client, bound to the session and tool call.
    let request = next_message(&mut rig).await;
    assert_eq!(
        request.method.as_deref(),
        Some("session/request_permission")
    );
    let outgoing_id = request.id.expect("outgoing id");
    let params = request.params.expect("params");
    assert_eq!(params["sessionId"], rig.session);
    assert_eq!(params["toolCall"]["toolCallId"], "tool-1");
    let kinds: Vec<&str> = params["options"]
        .as_array()
        .expect("options")
        .iter()
        .map(|option| option["kind"].as_str().expect("kind"))
        .collect();
    assert_eq!(kinds, ["allow_once", "reject_once"]);

    // The allow-once answer becomes a typed DecidePermission under a
    // deterministic command identity.
    send_message(
        Message::success(
            outgoing_id,
            json!({ "outcome": { "outcome": "selected", "optionId": "allow" } }),
        ),
        &mut rig,
    )
    .await;
    let found = commands(&rig.ctx, 2).await;
    match &found[1].body {
        live::LiveCommandBody::DecidePermission {
            request_id,
            decision,
        } => {
            assert_eq!(request_id.as_str(), "perm:abc");
            assert!(matches!(decision, live::PermissionDecision::AllowOnce));
        }
        other => panic!("expected DecidePermission, got {other:?}"),
    }

    push_event(&rig, 3, resolved_body("perm:abc"));
    push_event(&rig, 4, control_completed_applied(&found[1].command_id));
    push_event(&rig, 5, state_body("running", "idle"));
    let response = next_message(&mut rig).await;
    assert_eq!(response.id, Some(json!(2)));
    assert_eq!(response.result.expect("result")["stopReason"], "end_turn");
}

#[tokio::test]
async fn kernel_approval_binds_to_the_exact_durable_revision() {
    let approvals = vec![KernelApprovalView {
        approval_id: "approval:r3:seat.shell:x".to_owned(),
        revision: 2,
        capability_id: "seat.shell".to_owned(),
        target_kind: "run".to_owned(),
        target_id: "run:live:00000000-0000-4000-8000-0000000000a1".to_owned(),
        arguments_digest: DIGEST.to_owned(),
    }];
    let mut rig = make_rig("approval", vec![], approvals).await;
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
    push_event(&rig, 2, state_body("running", "requiresAction"));

    // The durable approval surfaces bound to its exact revision.
    let request = next_message(&mut rig).await;
    assert_eq!(
        request.method.as_deref(),
        Some("session/request_permission")
    );
    let outgoing_id = request.id.expect("outgoing id");
    let params = request.params.expect("params");
    assert_eq!(params["toolCall"]["toolCallId"], "approval:r3:seat.shell:x");
    assert_eq!(params["toolCall"]["rawInput"]["argumentsDigest"], DIGEST);

    send_message(
        Message::success(
            outgoing_id,
            json!({ "outcome": { "outcome": "selected", "optionId": "deny" } }),
        ),
        &mut rig,
    )
    .await;
    let found = commands(&rig.ctx, 2).await;
    match &found[1].body {
        live::LiveCommandBody::DecideApproval {
            approval_id,
            expected_revision,
            decision,
        } => {
            assert_eq!(approval_id.as_str(), "approval:r3:seat.shell:x");
            assert_eq!(*expected_revision, 2);
            assert!(matches!(decision, live::ApprovalDecision::Reject));
        }
        other => panic!("expected DecideApproval, got {other:?}"),
    }
}

fn idle_approval_rows() -> Vec<KernelApprovalView> {
    vec![KernelApprovalView {
        approval_id: "approval:r3:seat.shell:x".to_owned(),
        revision: 2,
        capability_id: "seat.shell".to_owned(),
        target_kind: "run".to_owned(),
        target_id: format!("run:live:{SESSION}"),
        arguments_digest: DIGEST.to_owned(),
    }]
}

#[tokio::test]
async fn failed_tool_approval_holds_the_turn_until_the_decision_settles() {
    // Kernel R3 approval errors never create RequiresAction: a failed tool
    // settles to Idle. The approval surfaces on the failed tool, the idle
    // transition does NOT complete the prompt, and only the settled
    // decision and its continuation resolve the turn.
    let mut rig = make_rig("approval-idle", vec![], vec![]).await;
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
    *rig.approvals.lock() = idle_approval_rows();
    push_event(&rig, 2, failed_tool_body());
    let update = next_message(&mut rig).await;
    assert_eq!(update.params.expect("p")["update"]["status"], "failed");
    let request = next_message(&mut rig).await;
    assert_eq!(
        request.method.as_deref(),
        Some("session/request_permission")
    );
    let outgoing_id = request.id.expect("outgoing id");
    assert_eq!(
        request.params.expect("p")["toolCall"]["toolCallId"],
        "approval:r3:seat.shell:x"
    );

    // The idle transition arrives with the approval undecided: the turn
    // stays pending instead of reporting a fabricated completion.
    push_event(&rig, 3, state_body("running", "idle"));
    expect_silence(&mut rig).await;

    // The operator allows; the typed decision carries the exact revision.
    send_message(
        Message::success(
            outgoing_id,
            json!({ "outcome": { "outcome": "selected", "optionId": "allow" } }),
        ),
        &mut rig,
    )
    .await;
    let decision_id = {
        let found = commands(&rig.ctx, 2).await;
        match &found[1].body {
            live::LiveCommandBody::DecideApproval {
                approval_id,
                expected_revision,
                decision,
            } => {
                assert_eq!(approval_id.as_str(), "approval:r3:seat.shell:x");
                assert_eq!(*expected_revision, 2);
                assert!(matches!(decision, live::ApprovalDecision::Approve));
            }
            other => panic!("expected DecideApproval, got {other:?}"),
        }
        found[1].command_id.clone()
    };
    rig.approvals.lock().clear();

    // The shared executor settles the decision and continues the session;
    // the original prompt resolves on the real post-continuation outcome.
    push_event(&rig, 4, control_completed_applied(&decision_id));
    push_event(&rig, 5, state_body("idle", "running"));
    push_event(&rig, 6, state_body("running", "idle"));
    let response = next_message(&mut rig).await;
    assert_eq!(response.id, Some(json!(2)));
    assert_eq!(response.result.expect("result")["stopReason"], "end_turn");
}

#[tokio::test]
async fn failed_decision_resolution_fails_the_pending_turn_honestly() {
    let mut rig = make_rig("approval-decision-fail", vec![], vec![]).await;
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
    *rig.approvals.lock() = idle_approval_rows();
    push_event(&rig, 2, failed_tool_body());
    let _ = next_message(&mut rig).await; // failed tool_call_update
    let request = next_message(&mut rig).await;
    let outgoing_id = request.id.expect("outgoing id");
    push_event(&rig, 3, state_body("running", "idle"));
    expect_silence(&mut rig).await;

    send_message(
        Message::success(
            outgoing_id,
            json!({ "outcome": { "outcome": "selected", "optionId": "allow" } }),
        ),
        &mut rig,
    )
    .await;
    let decision_id = commands(&rig.ctx, 2).await.remove(1).command_id;

    // The decision itself fails durably: the held turn resolves with the
    // real failure instead of hanging forever.
    push_event(&rig, 4, control_completed_decision_failed(&decision_id));
    let response = next_message(&mut rig).await;
    assert_eq!(response.id, Some(json!(2)));
    let error = response.error.expect("failed decision resolution");
    assert_eq!(error.code, RpcError::GOVERNED_REFUSAL);
}
