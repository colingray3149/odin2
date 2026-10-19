//! Attachment, declared binding and replay exposure invariants.

use super::*;

#[tokio::test]
async fn initialize_advertises_exactly_the_implemented_surface() {
    let mut rig = make_raw_rig("init", vec![], vec![]).await;
    send_message(
        Message::request(
            json!(1),
            "initialize",
            json!({ "protocolVersion": ACP_PROTOCOL_VERSION, "clientCapabilities": {} }),
        ),
        &mut rig,
    )
    .await;
    let response = next_message(&mut rig).await;
    assert_eq!(response.id, Some(json!(1)));
    let result = response.result.expect("initialize result");
    assert_eq!(result["protocolVersion"], ACP_PROTOCOL_VERSION);
    // loadSession is implemented; nothing else is claimed.
    let capabilities = result["agentCapabilities"]
        .as_object()
        .expect("capabilities");
    assert_eq!(capabilities.len(), 1);
    assert_eq!(capabilities["loadSession"], true);
    assert_eq!(
        result["authMethods"]
            .as_array()
            .expect("auth methods")
            .len(),
        0
    );
    assert_eq!(result["agentInfo"]["name"], "odin-acp");

    // authenticate is not advertised, so it is not implemented either.
    send_message(
        Message::request(json!(2), "authenticate", json!({})),
        &mut rig,
    )
    .await;
    let response = next_message(&mut rig).await;
    assert_eq!(
        response.error.expect("error").code,
        RpcError::METHOD_NOT_FOUND
    );

    // Unsupported protocol versions refuse explicitly.
    let mut rig = make_raw_rig("init-version", vec![], vec![]).await;
    send_message(
        Message::request(json!(1), "initialize", json!({ "protocolVersion": 99 })),
        &mut rig,
    )
    .await;
    let response = next_message(&mut rig).await;
    let error = response.error.expect("version refusal");
    assert_eq!(error.code, RpcError::GOVERNED_REFUSAL);

    // Session methods before initialize refuse.
    let mut rig = make_raw_rig("init-order", vec![], vec![]).await;
    send_message(
        Message::request(
            json!(1),
            "session/new",
            json!({ "cwd": "/tmp", "mcpServers": [] }),
        ),
        &mut rig,
    )
    .await;
    let response = next_message(&mut rig).await;
    let error = response.error.expect("ordering refusal");
    assert_eq!(error.code, RpcError::GOVERNED_REFUSAL);
}

#[tokio::test]
async fn session_new_rejects_mcp_and_foreign_cwd() {
    let mut rig = make_rig("binding-mcp", vec![], vec![]).await;
    let cwd = rig.root.display().to_string();
    send_message(
        Message::request(
            json!(1),
            "session/new",
            json!({ "cwd": cwd, "mcpServers": [{ "name": "host-tools" }] }),
        ),
        &mut rig,
    )
    .await;
    let response = next_message(&mut rig).await;
    let error = response.error.expect("mcp refusal");
    assert_eq!(error.code, RpcError::GOVERNED_REFUSAL);

    let mut rig = make_rig("binding-extra", vec![], vec![]).await;
    let cwd = rig.root.display().to_string();
    send_message(
        Message::request(
            json!(1),
            "session/new",
            json!({ "cwd": cwd, "mcpServers": [], "additionalDirectories": ["/elsewhere"] }),
        ),
        &mut rig,
    )
    .await;
    let response = next_message(&mut rig).await;
    assert_eq!(
        response.error.expect("directories refusal").code,
        RpcError::GOVERNED_REFUSAL
    );

    // A foreign cwd is refused against the exact composed project root.
    let mut rig = make_rig("binding-cwd", vec![], vec![]).await;
    send_message(
        Message::request(
            json!(1),
            "session/new",
            json!({ "cwd": "/tmp", "mcpServers": [] }),
        ),
        &mut rig,
    )
    .await;
    let response = next_message(&mut rig).await;
    let error = response.error.expect("cwd refusal");
    assert_eq!(error.code, RpcError::GOVERNED_REFUSAL);
}

#[tokio::test]
async fn session_new_returns_a_usable_session_identity() {
    let mut rig = make_rig("new-identity", vec![], vec![]).await;
    open_session(&mut rig).await;
    // The response names exactly the session the opener provisioned, and
    // that identity addresses the session for real work afterwards.
    assert_eq!(rig.session, SESSION);
    let mut sequence = 0_u64;
    complete_first_turn(&mut rig, &mut sequence).await;
}

#[tokio::test]
async fn load_surfaces_only_outstanding_permissions() {
    // perm:abc is requested and resolved in history; perm:xyz is still
    // outstanding when the replay settles.
    let mut rig = make_rig(
        "load-permissions",
        vec![
            opened_body(SESSION, PROJECT),
            state_body("starting", "running"),
            permission_body("perm:abc", "tool-1"),
            resolved_body("perm:abc"),
            permission_body("perm:xyz", "tool-2"),
            state_body("running", "requiresAction"),
        ],
        vec![],
    )
    .await;
    send_message(Message::request(
        json!(1),
        "session/load",
        json!({ "sessionId": SESSION, "cwd": rig.root.display().to_string(), "mcpServers": [] }),
    ), &mut rig)
    .await;
    let response = next_message(&mut rig).await;
    assert!(response.error.is_none(), "load should prove the binding");

    // Only the genuinely outstanding request is asked after ReplayComplete.
    let request = next_message(&mut rig).await;
    assert_eq!(
        request.method.as_deref(),
        Some("session/request_permission")
    );
    let outgoing_id = request.id.expect("outgoing id");
    let params = request.params.expect("params");
    assert_eq!(params["sessionId"], SESSION);
    assert_eq!(params["toolCall"]["toolCallId"], "tool-2");

    // The allow-once answer becomes the typed decision for that exact
    // outstanding request.
    send_message(
        Message::success(
            outgoing_id,
            json!({ "outcome": { "outcome": "selected", "optionId": "allow" } }),
        ),
        &mut rig,
    )
    .await;
    let found = commands(&rig.ctx, 1).await;
    match &found[0].body {
        live::LiveCommandBody::DecidePermission {
            request_id,
            decision,
        } => {
            assert_eq!(request_id.as_str(), "perm:xyz");
            assert!(matches!(decision, live::PermissionDecision::AllowOnce));
        }
        other => panic!("expected DecidePermission, got {other:?}"),
    }

    // Nothing else is asked: the resolved request is never surfaced.
    expect_silence(&mut rig).await;
}

#[tokio::test]
async fn load_refuses_foreign_history_without_exposing_it() {
    // Durable history names a different project: load refuses, and none of
    // that history's content ever reaches the ACP client.
    let mut rig = make_rig(
        "load-foreign",
        vec![opened_body(SESSION, OTHER_PROJECT), message_body("secret")],
        vec![],
    )
    .await;
    send_message(Message::request(
        json!(1),
        "session/load",
        json!({ "sessionId": SESSION, "cwd": rig.root.display().to_string(), "mcpServers": [] }),
    ), &mut rig)
    .await;
    let response = next_message(&mut rig).await;
    let error = response.error.expect("binding refusal");
    assert_eq!(error.code, RpcError::GOVERNED_REFUSAL);
    expect_silence(&mut rig).await;

    // Durable history matches the configured seat and project: load proves.
    let mut rig = make_rig("load-proof", vec![opened_body(SESSION, PROJECT)], vec![]).await;
    send_message(Message::request(
        json!(1),
        "session/load",
        json!({ "sessionId": SESSION, "cwd": rig.root.display().to_string(), "mcpServers": [] }),
    ), &mut rig)
    .await;
    let response = next_message(&mut rig).await;
    assert!(response.error.is_none(), "load should prove the binding");
    assert_eq!(response.id, Some(json!(1)));

    // A session identity that is not live on the controller refuses.
    let mut rig = make_rig("load-missing", vec![], vec![]).await;
    send_message(
        Message::request(
            json!(1),
            "session/load",
            json!({
                "sessionId": OTHER_SESSION,
                "cwd": rig.root.display().to_string(),
                "mcpServers": []
            }),
        ),
        &mut rig,
    )
    .await;
    let response = next_message(&mut rig).await;
    let error = response.error.expect("missing session refusal");
    assert_eq!(error.code, RpcError::GOVERNED_REFUSAL);
}

#[tokio::test]
async fn loaded_session_continues_without_resetting_the_plan() {
    // The durable owner reports an already accepted plan: the continuation
    // never runs the acceptance path, so the plan and its todos survive.
    let mut rig = make_raw_rig_capacity(
        "load-continue",
        vec![opened_body(SESSION, PROJECT)],
        vec![],
        128,
        true,
    )
    .await;
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
    send_message(Message::request(
        json!(1),
        "session/load",
        json!({ "sessionId": SESSION, "cwd": rig.root.display().to_string(), "mcpServers": [] }),
    ), &mut rig)
    .await;
    let response = next_message(&mut rig).await;
    assert!(response.error.is_none(), "load should prove the binding");

    send_message(
        Message::request(
            json!(2),
            "session/prompt",
            json!({ "sessionId": rig.session, "prompt": [{ "type": "text", "text": "continue" }] }),
        ),
        &mut rig,
    )
    .await;
    let found = commands(&rig.ctx, 1).await;
    assert_eq!(rig.gate_calls.load(Ordering::SeqCst), 0);
    assert_ne!(found[0].command_id.to_string(), "command:first-prompt");
    assert!(matches!(
        found[0].body,
        live::LiveCommandBody::Prompt { .. }
    ));
    push_event(&rig, 2, state_body("idle", "running"));
    push_event(&rig, 3, state_body("running", "idle"));
    let response = next_message(&mut rig).await;
    assert_eq!(response.id, Some(json!(2)));
    assert_eq!(response.result.expect("result")["stopReason"], "end_turn");
}

#[tokio::test]
async fn stream_disconnect_resubscribes_with_the_current_cursor() {
    let mut rig = make_rig("resubscribe", vec![], vec![]).await;
    rig.ctx
        .drop_stream_after_replay
        .store(true, Ordering::SeqCst);
    open_session(&mut rig).await;

    // The first stream dropped after its replay; the frontend re-subscribed
    // once with the cursor the replay advanced it to.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        let subscribes = rig.ctx.subscribes.lock().clone();
        if subscribes.len() >= 2 {
            assert_eq!(subscribes, [0, 1]);
            break;
        }
        assert!(tokio::time::Instant::now() < deadline, "no resubscribe");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    // Events keep flowing over the new stream, in order, under the same
    // backend session id.
    push_event(&rig, 2, state_body("idle", "running"));
    push_event(&rig, 3, delta_body("hello there"));
    let update = next_message(&mut rig).await;
    assert_eq!(update.method.as_deref(), Some("session/update"));
    let params = update.params.expect("update params");
    assert_eq!(params["sessionId"], rig.session);
    assert_eq!(params["update"]["sessionUpdate"], "agent_message_chunk");
    assert_eq!(params["update"]["content"]["text"], "hello there");
}

/// Failed reconnects must restore the resubscribe request for another attempt.
#[tokio::test]
async fn an_attached_session_outlasts_failed_reconnects() {
    let mut rig = make_rig("reconnect-refused", vec![], vec![]).await;
    rig.ctx
        .drop_stream_after_replay
        .store(true, Ordering::SeqCst);
    rig.ctx.refuse_connections.store(2, Ordering::SeqCst);
    open_session(&mut rig).await;

    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        let subscribes = rig.ctx.subscribes.lock().clone();
        if subscribes.len() >= 2 {
            assert_eq!(subscribes, [0, 1]);
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "the stream never came back"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(rig.ctx.refuse_connections.load(Ordering::SeqCst), 0);
    push_event(&rig, 2, state_body("idle", "running"));
    push_event(&rig, 3, delta_body("back again"));
    let update = next_message(&mut rig).await;
    assert_eq!(
        update.params.expect("params")["update"]["content"]["text"],
        "back again"
    );
}

#[tokio::test]
async fn load_keeps_current_epoch_and_does_not_reask_retired_dialogs() {
    let mut rig = make_rig(
        "load-reclaimed",
        vec![
            opened_body(SESSION, PROJECT),
            state_body("running", "requiresAction"),
            permission_body("old-dialog", "old-tool"),
        ],
        vec![],
    )
    .await;
    rig.ctx.session_epoch.store(2, Ordering::SeqCst);
    send_message(
        Message::request(
            json!(1),
            "session/load",
            json!({
                "sessionId": SESSION, "cwd": rig.root.display().to_string(), "mcpServers": [],
            }),
        ),
        &mut rig,
    )
    .await;
    let loaded = next_message(&mut rig).await;
    assert_eq!(loaded.id, Some(json!(1)));
    assert!(loaded.error.is_none());
    expect_silence(&mut rig).await;
    send_message(
        Message::request(
            json!(2),
            "session/prompt",
            json!({
                "sessionId": SESSION, "prompt": [{"type": "text", "text": "continue"}],
            }),
        ),
        &mut rig,
    )
    .await;
    let sent = commands(&rig.ctx, 1).await;
    assert_eq!(sent[0].expected_epoch.get(), 2);
    assert!(matches!(sent[0].body, live::LiveCommandBody::Prompt { .. }));
}

#[tokio::test]
async fn a_first_subscription_lost_to_a_broken_connection_is_retried() {
    let mut rig = make_rig("first-subscribe-drop", vec![], vec![]).await;
    rig.ctx.drop_next_subscribe.store(true, Ordering::SeqCst);
    open_session(&mut rig).await;
    assert_eq!(
        rig.ctx.subscribes.lock().len(),
        1,
        "one answered subscription"
    );
}
