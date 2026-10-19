use super::*;

#[test]
fn correlation_resolves_only_exact_id_and_command_pairs() {
    let mut correlation = Correlation::default();
    let first = command_id("odin-omp:cmd:1000:1-0");
    let second = command_id("odin-omp:cmd:1000:1-1");
    let (first_tx, mut first_rx) = oneshot::channel();
    let (second_tx, mut second_rx) = oneshot::channel();
    assert!(correlation.register(
        first.to_string(),
        "prompt",
        first.clone(),
        first_tx,
        InFlightKind::Mutating,
        ReplyDelivery::Observed,
    ));
    assert!(correlation.register(
        second.to_string(),
        "get_state",
        second.clone(),
        second_tx,
        InFlightKind::Informational,
        ReplyDelivery::Awaited,
    ));
    assert_eq!(correlation.active_mutating(), Some(first.clone()));
    assert!(
        correlation.take_pending("odin-omp:cmd:1000:1-9").is_none(),
        "no fuzzy matching"
    );
    let pending = correlation
        .take_pending(&first.to_string())
        .expect("exact id resolves");
    assert_eq!(pending.command, "prompt");
    assert_eq!(
        pending.delivery,
        ReplyDelivery::Observed,
        "the dispatch-time delivery mode is retained on the pending entry"
    );
    drop(pending.reply);
    assert!(
        correlation.take_pending(&first.to_string()).is_none(),
        "taken once"
    );
    correlation.finish_response(&first, "prompt", true);
    assert_eq!(
        correlation.active_mutating(),
        Some(first.clone()),
        "an accepted prompt remains the lifecycle anchor"
    );
    correlation.settle_frame(&json!({"type": "agent_end", "isTerminal": false}));
    assert_eq!(
        correlation.active_mutating(),
        Some(first.clone()),
        "an agent_end an async delivery resumes keeps the turn anchored"
    );
    assert!(correlation.active_turn_anchor(&first));
    correlation.settle_frame(&json!({"type": "agent_end", "willContinue": true}));
    assert_eq!(correlation.active_mutating(), Some(first.clone()));
    correlation.settle_frame(&json!({"type": "agent_end"}));
    assert_eq!(correlation.active_mutating(), None);

    correlation.fail_all(BridgeError::ProcessDown {
        detail: "test".to_owned(),
    });
    let settled = first_rx.try_recv();
    assert!(
        settled.is_err(),
        "the taken waiter is the caller's, never fail_all's"
    );
    let reply = second_rx.try_recv().expect("waiter settled by fail_all");
    assert!(matches!(reply, Err(BridgeError::ProcessDown { .. })));
}

#[test]
fn command_sets_are_disjoint_and_exact() {
    let mut mutating = MUTATING_COMMANDS;
    mutating.sort_unstable();
    assert_eq!(
        mutating,
        [
            "abort",
            "checkpoint",
            "follow_up",
            "prompt",
            "set_model",
            "steer"
        ]
    );
    assert_eq!(
        REGISTRATION_COMMANDS,
        ["get_state", "set_host_tools", "set_host_uri_schemes"]
    );
    assert!(
        !MUTATING_COMMANDS
            .iter()
            .any(|command| REGISTRATION_COMMANDS.contains(command)),
        "re-registered commands cannot be crash-blocking mutators"
    );
}

#[test]
fn with_request_id_stamps_the_wire_id() {
    let stamped = with_request_id(json!({ "type": "abort" }), "odin-omp:cmd:1:1-0");
    assert_eq!(
        stamped,
        json!({ "type": "abort", "id": "odin-omp:cmd:1:1-0" })
    );
    let restamped = with_request_id(stamped, "odin-omp:cmd:1:1-1");
    assert_eq!(
        restamped,
        json!({ "type": "abort", "id": "odin-omp:cmd:1:1-1" })
    );
}
