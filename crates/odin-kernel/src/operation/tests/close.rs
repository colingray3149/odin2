//! Close and reconcile release the ledger during observation and revalidate before settlement.

use super::*;

/// An executor that cannot look at the world can never say whether an in-doubt effect landed: a drain keeps
/// waiting on it, and the owner's abort abandons it so the capsule closes.
#[test]
fn an_unmeasurable_in_doubt_effect_blocks_a_drain_and_is_abandoned_by_an_abort() {
    let fixture = fixture();
    let capsule_id = CapsuleId::new(CAPSULE).unwrap();
    let correlation_id = correlation("close-unmeasured");
    fixture.world.unmeasured.store(true, Ordering::SeqCst);
    fixture.world.uncertain.store(true, Ordering::SeqCst);
    let outcome = fixture.authority.invoke_authorized(
        fixture.authorize(&write_arguments("unmeasured"), 20),
        &invoke_request(&correlation_id, 1),
    );
    assert!(matches!(
        outcome,
        Err(OperationRejection::Executor(
            ExecutorFault::Uncertain { .. }
        ))
    ));
    fixture.world.uncertain.store(false, Ordering::SeqCst);

    let close = |mode, tag: &str| {
        fixture
            .authority
            .close_capsule(fresh_proof(500), &capsule_id, &correlation(tag), mode)
    };
    assert!(matches!(
        close(CloseMode::Drain, "close-unmeasured-drain"),
        Err(OperationRejection::CapsuleBlocked { blocked: 1, .. })
    ));
    assert_eq!(
        fixture.row_state(correlation_id.as_str()),
        EffectState::InDoubt
    );
    let closed = close(CloseMode::Abort, "close-unmeasured-abort").expect("the abort closes");
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
