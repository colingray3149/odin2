//! Only active dispatch may settle its effect; retries and reopen must not re-execute it.

use super::*;

#[test]
fn an_exact_retry_cannot_abort_a_live_prepared_owner() -> Result<(), &'static str> {
    let world = Arc::new(World::default());
    let ledger = Arc::new(Mutex::new(Ledger::open_in_memory().expect("ledger")));
    let executor = Arc::new(MidflightRetryExecutor::new(Arc::clone(&world)));
    let fixture = fixture_with(Arc::clone(&world), executor.clone(), Arc::clone(&ledger));
    let correlation = correlation("prepared-retry");
    let arguments = write_arguments("one prepared owner");
    let request = invoke_request(&correlation, 1);
    executor.arm(&fixture.authority, &fixture, &arguments);
    executor
        .before_start
        .set((ledger, correlation.clone()))
        .map_err(|_| "prepared retry already armed")?;
    let outcome = fixture
        .authority
        .invoke_authorized(fixture.authorize(&arguments, 20), &request)
        .expect("a duplicate must not abort the live prepared owner");
    assert_eq!(outcome.state, EffectState::Committed);
    assert!(!outcome.replay);
    assert_eq!(world.executions.load(Ordering::SeqCst), 1);
    let duplicate = executor
        .take_retry_verdict()
        .expect("the real retry ran before EffectStarted")
        .expect("the duplicate observed its original operation");
    assert_eq!(duplicate.state, EffectState::Prepared);
    assert!(duplicate.replay);
    assert_eq!(duplicate.operation_id, outcome.operation_id);
    assert_eq!(
        fixture.row_state(correlation.as_str()),
        EffectState::Committed
    );
    assert_eq!(
        fixture.row_evidence(correlation.as_str()),
        Some(receipt_digest("one prepared owner").to_string())
    );
    Ok(())
}

#[test]
fn midflight_retry_cannot_abort_an_executing_effect_across_reopen() {
    let path = lease_ledger_path("midflight-retry");
    let world = Arc::new(World::default());
    let ledger = Arc::new(Mutex::new(Ledger::open(&path).expect("file-backed ledger")));
    let executor = Arc::new(MidflightRetryExecutor::new(Arc::clone(&world)));
    let fixture = fixture_with(Arc::clone(&world), executor.clone(), ledger);

    let correlation_id = correlation("midflight-retry");
    let content = "midflight";
    let arguments = write_arguments(content);
    let request = invoke_request(&correlation_id, 1);
    executor.arm(&fixture.authority, &fixture, &arguments);
    let decision = fixture
        .authority
        .invoke_authorized(fixture.authorize(&arguments, 20), &request)
        .expect("the owning dispatch settles its own effect");
    assert_eq!(decision.state, EffectState::Committed);
    assert!(!decision.replay);
    assert_eq!(fixture.world.executions.load(Ordering::SeqCst), 1);

    // The mid-flight retry was refused settlement: it observed the row
    // still `effect_started`, blocked as a replay — never an abort.
    let retried = executor
        .take_retry_verdict()
        .expect("the executor replayed the correlation mid-flight")
        .expect("mid-flight retry is answered, not failed");
    assert_eq!(retried.state, EffectState::EffectStarted);
    assert!(retried.replay);
    assert_eq!(retried.correlation_id, correlation_id);
    assert_eq!(retried.operation_id, decision.operation_id);

    // The dispatch commits its captured evidence after one execution.
    assert_eq!(
        fixture.row_state(correlation_id.as_str()),
        EffectState::Committed
    );
    assert_eq!(
        fixture.row_evidence(correlation_id.as_str()),
        Some(receipt_digest(content).to_string())
    );

    // Reopen: the committed operation replays its terminal state from the
    // journal without re-executing anything.
    drop(fixture);
    drop(executor);
    let reopened = Arc::new(Mutex::new(Ledger::open(&path).expect("reopen ledger")));
    let after = fixture_with(
        Arc::clone(&world),
        Arc::new(Executor(Arc::clone(&world))),
        reopened,
    );
    let resumed = after
        .authority
        .resume(
            fresh_proof(500),
            &request.capsule_id,
            &correlation_id,
            &decision.operation_id,
        )
        .expect("reopened authority replays the terminal row");
    assert_eq!(resumed.state, EffectState::Committed);
    assert!(resumed.replay);
    assert_eq!(after.world.executions.load(Ordering::SeqCst), 1);
    drop(after);
    discard_ledger(&path);
}

/// Reopen reconciles uncertainty from recorded inputs without re-executing.
#[test]
fn midflight_retry_then_reopen_reconciles_uncertainty_from_evidence() {
    let path = lease_ledger_path("midflight-uncertain");
    let world = Arc::new(World::default());
    let ledger = Arc::new(Mutex::new(Ledger::open(&path).expect("file-backed ledger")));
    let executor = Arc::new(MidflightRetryExecutor::new(Arc::clone(&world)));
    let fixture = fixture_with(Arc::clone(&world), executor.clone(), ledger);
    world.uncertain.store(true, Ordering::SeqCst);

    let correlation_id = correlation("midflight-uncertain");
    let arguments = write_arguments("uncertain-retry");
    let request = invoke_request(&correlation_id, 1);
    executor.arm(&fixture.authority, &fixture, &arguments);
    let outcome = fixture
        .authority
        .invoke_authorized(fixture.authorize(&arguments, 20), &request);
    assert!(
        matches!(
            &outcome,
            Err(OperationRejection::Executor(
                ExecutorFault::Uncertain { .. }
            ))
        ),
        "pre-output uncertainty blocks, got {outcome:?}"
    );

    // The mid-flight retry was refused settlement while the effect was
    // executing: it saw the row still in flight, never an abort.
    let retried = executor
        .take_retry_verdict()
        .expect("the executor replayed the correlation mid-flight")
        .expect("mid-flight retry is answered, not failed");
    assert_eq!(retried.state, EffectState::EffectStarted);
    assert!(retried.replay);

    // Pre-output uncertainty records InDoubt without output evidence.
    assert_eq!(
        fixture.row_state(correlation_id.as_str()),
        EffectState::InDoubt
    );
    assert_eq!(fixture.row_evidence(correlation_id.as_str()), None);

    // Reopen without in-flight registrations; absence aborts the row without re-execution.
    drop(fixture);
    drop(executor);
    let reopened = Arc::new(Mutex::new(Ledger::open(&path).expect("reopen ledger")));
    let after = fixture_with(
        Arc::clone(&world),
        Arc::new(Executor(Arc::clone(&world))),
        reopened,
    );
    let resumed = after
        .authority
        .resume(
            fresh_proof(500),
            &request.capsule_id,
            &correlation_id,
            &after.operation_id(correlation_id.as_str()),
        )
        .expect("reopened authority reconciles from the recorded binding");
    assert_eq!(resumed.state, EffectState::Aborted);
    assert!(resumed.replay);
    assert_eq!(
        after.row_state(correlation_id.as_str()),
        EffectState::Aborted
    );
    assert_eq!(after.row_evidence(correlation_id.as_str()), None);
    assert_eq!(world.executions.load(Ordering::SeqCst), 1);
    drop(after);
    discard_ledger(&path);
}
