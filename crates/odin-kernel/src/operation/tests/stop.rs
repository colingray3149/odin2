//! Stop-intent invariants: a capsule-wide stop settles only when every
//! operation in the capsule is terminal; a stop recorded before the effect
//! starts aborts with zero effect and settles under its own correlation, never
//! leaking the invoke correlation into the stop journal; and canonical
//! handler keys stay collision-free under separator bytes.

use super::*;

#[test]
fn two_in_flight_operations_first_cannot_terminalize_capsule_stop() {
    let fixture = fixture();
    let capsule_id = CapsuleId::new(CAPSULE).unwrap();
    let stop_correlation = correlation("two-op-stop");
    // A Prepared sibling keeps the capsule-wide stop pending.
    let first_authorized = fixture.authorize(&write_arguments("first"), 20);
    fixture.open_test_lease(&first_authorized, CAPSULE, 19);
    let sibling = correlation("two-sibling");
    fixture.seed_in_flight_operation(&sibling, &capsule_id, &first_authorized);
    fixture
        .authority
        .stop_intent(fresh_proof(19), &capsule_id, &stop_correlation, None)
        .expect("capsule-wide stop records");

    // FIRST operation: the race guard aborts it pre-effect, but the
    // capsule-wide stop stays `requested` because a sibling may still be
    // in flight (the gate requires ALL operations terminal).
    let first = correlation("two-first");
    let request = invoke_request(&first, 1);
    let outcome = fixture
        .authority
        .invoke_authorized(first_authorized, &request);
    assert!(
        outcome.is_err(),
        "first aborts on the capsule stop, got {outcome:?}"
    );
    let stop_row = {
        let ledger = fixture.authority.store.lock().unwrap();
        odin_ledger::operation::stop_row(ledger.connection(), stop_correlation.as_str())
            .unwrap()
            .expect("stop intent exists")
    };
    assert_eq!(
        stop_row.state, "requested",
        "first-child abort cannot terminalize the capsule-wide stop \
             while other operations may still be nonterminal"
    );

    // The in-flight sibling recovers through the public resume path: a
    // prepared row never dispatched an effect and aborts durably without
    // settling the capsule-wide intent.
    let sibling_operation_id = fixture.operation_id(sibling.as_str());
    let recovered = fixture
        .authority
        .resume(
            fresh_proof(500),
            &capsule_id,
            &sibling,
            &sibling_operation_id,
        )
        .expect("in-flight sibling recovers aborted");
    assert_eq!(recovered.state, EffectState::Aborted);
    assert_eq!(fixture.world.executions.load(Ordering::SeqCst), 0);

    // SECOND (and last) operation: aborting it drives the capsule to
    // all-terminal, which lets the gate settle the capsule-wide stop.
    let second = correlation("two-second");
    let request = invoke_request(&second, 1);
    let outcome = fixture
        .authority
        .invoke_authorized(fixture.authorize(&write_arguments("second"), 21), &request);
    assert!(
        outcome.is_err(),
        "second also aborts on the capsule stop, got {outcome:?}"
    );
    let stop_row = {
        let ledger = fixture.authority.store.lock().unwrap();
        odin_ledger::operation::stop_row(ledger.connection(), stop_correlation.as_str())
            .unwrap()
            .expect("stop intent exists")
    };
    assert_eq!(
        stop_row.state, "stopped",
        "all operations terminal: capsule-wide stop settles to stopped"
    );
    assert_eq!(fixture.world.executions.load(Ordering::SeqCst), 0);
}

#[test]
fn stop_recorded_before_start_settles_stop_and_aborts_with_zero_effect() {
    let fixture = fixture();
    let capsule_id = CapsuleId::new(CAPSULE).unwrap();
    // Distinct ids: the stop correlation is its own journal row, never
    // the invoke correlation.
    let stop_correlation = correlation("pre-start-stop");
    let invoke_correlation = correlation("pre-start-invoke");
    assert_ne!(stop_correlation, invoke_correlation);

    // Capsule-wide stop recorded BEFORE the operation exists (None
    // operation id): the durable row carries no operation identity.
    let arguments = write_arguments("never written");
    let authorized = fixture.authorize(&arguments, 20);
    fixture.open_test_lease(&authorized, CAPSULE, 19);
    let recorded = fixture
        .authority
        .stop_intent(fresh_proof(19), &capsule_id, &stop_correlation, None)
        .expect("capsule-wide stop records before invoke");
    assert_eq!(recorded.state, "requested");

    // The invocation runs: the dispatch race guard observes the pending
    // stop, aborts with ZERO effect, and settles the stop intent.
    let request = invoke_request(&invoke_correlation, 1);
    let outcome = fixture.authority.invoke_authorized(authorized, &request);
    assert!(
        matches!(
            &outcome,
            Err(OperationRejection::Executor(ExecutorFault::Rejected { detail }))
                if detail.contains("stop intent")
        ),
        "pre-start stop must abort the operation, got {outcome:?}"
    );
    assert_eq!(fixture.world.executions.load(Ordering::SeqCst), 0);

    // The stop journal row terminalized under its OWN correlation.
    let stop_row = {
        let ledger = fixture.authority.store.lock().unwrap();
        odin_ledger::operation::stop_row(ledger.connection(), stop_correlation.as_str())
            .unwrap()
            .expect("stop intent exists under its own correlation")
    };
    assert_eq!(stop_row.state, "stopped");
    assert!(stop_row.operation_id.is_none());

    // The invocation correlation NEVER leaked into the stop journal.
    let invoke_leak = {
        let ledger = fixture.authority.store.lock().unwrap();
        odin_ledger::operation::stop_row(ledger.connection(), invoke_correlation.as_str())
            .unwrap()
            .is_some()
    };
    assert!(!invoke_leak, "invoke correlation leaked into stop journal");

    // The invocation row exists aborted under its OWN correlation.
    let row = {
        let ledger = fixture.authority.store.lock().unwrap();
        odin_ledger::operation::operation_row(ledger.connection(), invoke_correlation.as_str())
            .unwrap()
            .expect("invocation row exists")
    };
    assert_eq!(row.effect_state, EffectState::Aborted);
    assert_eq!(row.correlation_id, invoke_correlation.as_str());
}

#[test]
fn capsule_wide_stop_needs_no_operation_row_and_is_idempotent() {
    let fixture = fixture();
    let capsule_id = CapsuleId::new(CAPSULE).unwrap();
    let correlation_id = correlation("capsule-stop");
    let authorized = fixture.authorize(&write_arguments("lease"), 20);
    fixture.open_test_lease(&authorized, CAPSULE, 20);
    let first = fixture
        .authority
        .stop_intent(fresh_proof(20), &capsule_id, &correlation_id, None)
        .expect("capsule-wide stop records");
    assert_eq!(first.state, "requested");
    assert!(!first.replay);
    assert!(first.operation_id.is_none());
    let second = fixture
        .authority
        .stop_intent(fresh_proof(21), &capsule_id, &correlation_id, None)
        .expect("replayed capsule-wide stop");
    assert!(second.replay);
}

#[test]
fn canonical_binding_keys_are_collision_free_under_separator_bytes() {
    let merged = HandlerBinding::Exec {
        executable: "/store/bin/e".to_owned(),
        argv: vec!["a\u{1f}b".to_owned()],
    };
    let split = HandlerBinding::Exec {
        executable: "/store/bin/e".to_owned(),
        argv: vec!["a".to_owned(), "b".to_owned()],
    };
    assert_ne!(merged.canonical_key(), split.canonical_key());
}

/// Replaying a committed operation leaves its later stop pending and does not charge again.
#[test]
fn invoke_replay_after_targeted_cancel_replays_the_verdict_and_leaves_the_stop_requested() {
    let path = lease_ledger_path("cancel-replay");
    let world = Arc::new(World::default());
    let ledger = Arc::new(Mutex::new(Ledger::open(&path).expect("file-backed ledger")));
    let fixture = fixture_with(
        Arc::clone(&world),
        Arc::new(Executor(Arc::clone(&world))),
        ledger,
    );
    let capsule_id = CapsuleId::new(CAPSULE).unwrap();
    let invoke_correlation = correlation("cancel-replay-invoke");
    let stop_correlation = correlation("cancel-replay-stop");
    assert_ne!(invoke_correlation, stop_correlation);

    // The effect commits exactly once.
    let arguments = write_arguments("landed once");
    let request = invoke_request(&invoke_correlation, 1);
    let committed = fixture
        .authority
        .invoke_authorized(fixture.authorize(&arguments, 20), &request)
        .expect("the effect commits");
    assert_eq!(committed.state, EffectState::Committed);
    assert!(!committed.replay);
    assert_eq!(fixture.world.executions.load(Ordering::SeqCst), 1);

    // A targeted cancel records while the capsule is open.
    let recorded = fixture
        .authority
        .stop_intent(
            fresh_proof(20),
            &capsule_id,
            &stop_correlation,
            Some(committed.operation_id.clone()),
        )
        .expect("targeted cancel records");
    assert_eq!(recorded.state, "requested");
    assert!(!recorded.replay);

    // The retry replays the committed verdict: no second effect, and the
    // operation identity is the original one.
    let retried = fixture
        .authority
        .invoke_authorized(fixture.authorize(&arguments, 21), &request)
        .expect("the retry replays the verdict");
    assert!(retried.replay);
    assert_eq!(retried.state, EffectState::Committed);
    assert_eq!(retried.operation_id, committed.operation_id);
    assert_eq!(fixture.world.executions.load(Ordering::SeqCst), 1);

    // The stop stays requested, adds no operation row, and charges only once.
    {
        let ledger = fixture.authority.store.lock().unwrap();
        let stop_row =
            odin_ledger::operation::stop_row(ledger.connection(), stop_correlation.as_str())
                .unwrap()
                .expect("the cancel intent exists");
        assert_eq!(stop_row.state, "requested");
        assert_eq!(
            stop_row.operation_id.as_deref(),
            Some(committed.operation_id.as_str())
        );
        assert!(
            odin_ledger::operation::operation_row(ledger.connection(), stop_correlation.as_str())
                .unwrap()
                .is_none(),
            "a cancel fabricates no operation row"
        );
        let usage =
            store::usage(ledger.connection(), "00000000-0000-4000-8000-000000000001").unwrap();
        assert_eq!((usage.requests, usage.stops, usage.spend), (1, 1, 0));
    }

    // Restart: the verdict replays from the persisted row, the intent is
    // still requested, and nothing re-executes.
    drop(fixture);
    let reopened = Arc::new(Mutex::new(Ledger::open(&path).expect("reopen ledger")));
    let after = fixture_with(
        Arc::clone(&world),
        Arc::new(Executor(Arc::clone(&world))),
        reopened,
    );
    let replayed = after
        .authority
        .invoke_authorized(after.authorize(&arguments, 500), &request)
        .expect("the reopened authority replays the verdict");
    assert!(replayed.replay);
    assert_eq!(replayed.state, EffectState::Committed);
    assert_eq!(replayed.operation_id, committed.operation_id);
    assert_eq!(after.world.executions.load(Ordering::SeqCst), 1);
    {
        let ledger = after.authority.store.lock().unwrap();
        let stop_row =
            odin_ledger::operation::stop_row(ledger.connection(), stop_correlation.as_str())
                .unwrap()
                .expect("the cancel intent survives the reopen");
        assert_eq!(stop_row.state, "requested");
    }
    drop(after);
    discard_ledger(&path);
}
