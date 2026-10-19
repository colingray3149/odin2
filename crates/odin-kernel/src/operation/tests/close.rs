//! Close and reconcile release the ledger during observation and revalidate before settlement.

use super::*;

#[test]
fn close_observation_releases_the_ledger_for_reentrant_observers() {
    let world = Arc::new(World::default());
    let ledger = Arc::new(Mutex::new(Ledger::open_in_memory().unwrap()));
    let observer = Arc::new(ReenteringExecutor::new(
        Arc::clone(&world),
        Arc::clone(&ledger),
    ));
    let fixture = fixture_with(Arc::clone(&world), observer.clone(), ledger);
    let capsule_id = CapsuleId::new(CAPSULE).unwrap();
    let correlation_id = correlation("close-reentrant");
    let request = invoke_request(&correlation_id, 1);
    // Leave an unresolved row so close must observe it before settlement.
    fixture.world.uncertain.store(true, Ordering::SeqCst);
    let outcome = fixture.authority.invoke_authorized(
        fixture.authorize(&write_arguments("close-me"), 20),
        &request,
    );
    assert!(
        matches!(
            &outcome,
            Err(OperationRejection::Executor(
                ExecutorFault::Uncertain { .. }
            ))
        ),
        "uncertain executor must block the operation, got {outcome:?}"
    );
    assert_eq!(
        fixture.row_state(correlation_id.as_str()),
        EffectState::InDoubt
    );
    fixture.world.uncertain.store(false, Ordering::SeqCst);

    // The observer uses try_lock so holding the ledger during observation fails without hanging.
    let closed = fixture
        .authority
        .close_capsule(
            fresh_proof(500),
            &capsule_id,
            &correlation("close-reentrant-call"),
            CloseMode::Abort,
        )
        .expect("close completes while its observer re-enters the same ledger");
    assert_eq!(observer.blocked.load(Ordering::SeqCst), 0);
    assert!(observer.reentries.load(Ordering::SeqCst) >= 1);
    assert!(!closed.replay);
    assert_eq!(closed.drained, 1);
    assert_eq!(
        fixture.row_state(correlation_id.as_str()),
        EffectState::Aborted
    );
    assert_eq!(fixture.world.executions.load(Ordering::SeqCst), 1);
}

#[test]
fn close_rejects_stale_observation_after_concurrent_settlement() {
    let world = Arc::new(World::default());
    let ledger = Arc::new(Mutex::new(Ledger::open_in_memory().unwrap()));
    let observer = Arc::new(ReenteringExecutor::new(
        Arc::clone(&world),
        Arc::clone(&ledger),
    ));
    let fixture = fixture_with(Arc::clone(&world), observer.clone(), ledger);
    let capsule_id = CapsuleId::new(CAPSULE).unwrap();
    let correlation_id = correlation("stale-close");
    let content = "stale-close";
    let request = invoke_request(&correlation_id, 1);
    fixture.world.uncertain.store(true, Ordering::SeqCst);
    let outcome = fixture
        .authority
        .invoke_authorized(fixture.authorize(&write_arguments(content), 20), &request);
    assert!(matches!(
        &outcome,
        Err(OperationRejection::Executor(
            ExecutorFault::Uncertain { .. }
        ))
    ));
    fixture.world.uncertain.store(false, Ordering::SeqCst);
    // The world now shows the effect landed, so the close's own drain
    // observation would COMMIT the row...
    fixture
        .world
        .files
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .insert("docs/note.md".to_owned(), content.to_owned());
    // ...but a concurrent authority settles it first, from inside the
    // close's unlocked observation window, through the same ledger.
    observer
        .race
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .replace(Race::SettleAborted);

    let closed = fixture
        .authority
        .close_capsule(
            fresh_proof(500),
            &capsule_id,
            &correlation("stale-close-call"),
            CloseMode::Drain,
        )
        .expect("close counts the concurrent durable settlement");
    // Preserve the concurrent abort rather than applying the stale commit observation.
    assert_eq!(
        fixture.row_state(correlation_id.as_str()),
        EffectState::Aborted
    );
    assert_eq!(fixture.row_evidence(correlation_id.as_str()), None);
    assert!(!closed.replay);
    assert_eq!(closed.drained, 1);
    assert_eq!(fixture.world.executions.load(Ordering::SeqCst), 1);
}

#[test]
fn close_blocked_while_snapshot_goes_stale_without_settlement() {
    let world = Arc::new(World::default());
    let ledger = Arc::new(Mutex::new(Ledger::open_in_memory().unwrap()));
    let observer = Arc::new(ReenteringExecutor::new(
        Arc::clone(&world),
        Arc::clone(&ledger),
    ));
    let fixture = fixture_with(Arc::clone(&world), observer.clone(), ledger);
    let capsule_id = CapsuleId::new(CAPSULE).unwrap();
    let correlation_id = correlation("stale-midflight");
    let arguments = write_arguments("midflight");
    let authorized = fixture.authorize(&arguments, 20);
    fixture.open_test_lease(&authorized, CAPSULE, 19);
    fixture.seed_in_flight_operation(&correlation_id, &capsule_id, &authorized);
    // Simulate EffectStarted before injecting a concurrent recovery transition.
    {
        let mut ledger = fixture
            .authority
            .store
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let now = utc(20).unwrap();
        ledger
            .with_tx(|tx| {
                store::transition_operation(
                    tx,
                    correlation_id.as_str(),
                    EffectState::Prepared,
                    EffectState::EffectStarted,
                    None,
                    now,
                )
            })
            .unwrap();
    }
    // During the close's observation window a concurrent `recover`
    // moves the row effect_started -> in_doubt: the snapshot goes stale
    // without the row settling.
    observer
        .race
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .replace(Race::MarkInDoubt);
    let blocked = fixture
        .authority
        .close_capsule(
            fresh_proof(500),
            &capsule_id,
            &correlation("stale-midflight-call"),
            CloseMode::Drain,
        )
        .expect_err("a stale snapshot settles nothing and blocks the close");
    assert!(
        matches!(
            &blocked,
            OperationRejection::CapsuleBlocked { blocked: 1, .. }
        ),
        "stale observation must block the close, got {blocked:?}"
    );
    assert_eq!(fixture.lease_state(CAPSULE), "open");
    assert_eq!(
        fixture.row_state(correlation_id.as_str()),
        EffectState::InDoubt
    );

    // The next close observes the row fresh and settles it: no wedge.
    let closed = fixture
        .authority
        .close_capsule(
            fresh_proof(500),
            &capsule_id,
            &correlation("stale-midflight-call-2"),
            CloseMode::Drain,
        )
        .expect("a fresh observation settles what the stale one could not");
    assert_eq!(closed.drained, 1);
    assert!(!closed.replay);
    assert_eq!(
        fixture.row_state(correlation_id.as_str()),
        EffectState::Aborted
    );
}

#[test]
fn reconcile_revalidates_its_observation_before_settlement() {
    let world = Arc::new(World::default());
    let ledger = Arc::new(Mutex::new(Ledger::open_in_memory().unwrap()));
    let observer = Arc::new(ReenteringExecutor::new(
        Arc::clone(&world),
        Arc::clone(&ledger),
    ));
    let fixture = fixture_with(Arc::clone(&world), observer.clone(), ledger);
    let capsule_id = CapsuleId::new(CAPSULE).unwrap();
    let correlation_id = correlation("stale-reconcile");
    let content = "stale-reconcile";
    let request = invoke_request(&correlation_id, 1);
    fixture.world.uncertain.store(true, Ordering::SeqCst);
    let outcome = fixture
        .authority
        .invoke_authorized(fixture.authorize(&write_arguments(content), 20), &request);
    assert!(matches!(
        &outcome,
        Err(OperationRejection::Executor(
            ExecutorFault::Uncertain { .. }
        ))
    ));
    fixture.world.uncertain.store(false, Ordering::SeqCst);
    // The world landed, so reconcile's unlocked observation would
    // commit — but a concurrent authority aborts the row during that
    // observation window.
    fixture
        .world
        .files
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .insert("docs/note.md".to_owned(), content.to_owned());
    observer
        .race
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .replace(Race::SettleAborted);
    let operation_id = fixture.operation_id(correlation_id.as_str());
    let resumed = fixture
        .authority
        .resume(
            fresh_proof(500),
            &capsule_id,
            &correlation_id,
            &operation_id,
        )
        .expect("reconcile replays the fresh durable truth of a lost race");
    // The stale commit never applied: the fresh durable state is the
    // verdict, reported as a replay.
    assert_eq!(resumed.state, EffectState::Aborted);
    assert!(resumed.replay);
    assert_eq!(fixture.row_evidence(correlation_id.as_str()), None);
    assert_eq!(fixture.world.executions.load(Ordering::SeqCst), 1);
}

#[test]
fn close_drain_commits_from_evidence_and_abort_refuses_landed_effects() {
    let fixture = fixture();
    let capsule_id = CapsuleId::new(CAPSULE).unwrap();
    let correlation_id = correlation("close-contract");
    let sibling_correlation = correlation("close-contract-sibling");
    let content = "close-contract";
    let arguments = write_arguments(content);
    // Create an uncertain row and a sibling that has not dispatched.
    fixture.world.uncertain.store(true, Ordering::SeqCst);
    let outcome = fixture.authority.invoke_authorized(
        fixture.authorize(&arguments, 20),
        &invoke_request(&correlation_id, 1),
    );
    assert!(matches!(
        &outcome,
        Err(OperationRejection::Executor(
            ExecutorFault::Uncertain { .. }
        ))
    ));
    fixture.world.uncertain.store(false, Ordering::SeqCst);
    let authorized = fixture.authorize(&arguments, 20);
    fixture.seed_in_flight_operation(&sibling_correlation, &capsule_id, &authorized);
    // The in-doubt effect actually landed in the world.
    fixture
        .world
        .files
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .insert("docs/note.md".to_owned(), content.to_owned());

    // Abort the undispatched sibling, but keep the capsule open while the landed effect is unresolved.
    let blocked = fixture
        .authority
        .close_capsule(
            fresh_proof(500),
            &capsule_id,
            &correlation("close-contract-abort"),
            CloseMode::Abort,
        )
        .expect_err("a landed effect cannot be aborted");
    assert!(
        matches!(
            &blocked,
            OperationRejection::CapsuleBlocked { blocked: 1, .. }
        ),
        "abort must refuse the landed effect, got {blocked:?}"
    );
    assert_eq!(fixture.lease_state(CAPSULE), "open");
    assert_eq!(
        fixture.row_state(correlation_id.as_str()),
        EffectState::InDoubt
    );
    assert_eq!(
        fixture.row_state(sibling_correlation.as_str()),
        EffectState::Aborted
    );

    // Drain settles the in-doubt row from the world observation alone.
    let closed = fixture
        .authority
        .close_capsule(
            fresh_proof(500),
            &capsule_id,
            &correlation("close-contract-drain"),
            CloseMode::Drain,
        )
        .expect("drain settles from evidence");
    assert!(!closed.replay);
    assert_eq!(closed.drained, 1);
    assert_eq!(
        fixture.row_state(correlation_id.as_str()),
        EffectState::Committed
    );
    assert_eq!(fixture.world.executions.load(Ordering::SeqCst), 1);

    // A close of an already-closed capsule replays without draining.
    let replayed = fixture
        .authority
        .close_capsule(
            fresh_proof(500),
            &capsule_id,
            &correlation("close-contract-replay"),
            CloseMode::Drain,
        )
        .expect("closed capsule replays");
    assert!(replayed.replay);
    assert_eq!(replayed.drained, 0);
}
