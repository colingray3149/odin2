//! Persist captured output evidence with uncertainty and preserve it through settlement
//! and conflicting repairs.

use super::*;

#[test]
fn uncertain_effect_blocks_then_reconciles_from_recorded_binding() {
    let fixture = fixture();
    let correlation_id = correlation("uncertain");
    let arguments = write_arguments("uncertain");
    let request = invoke_request(&correlation_id, 1);
    fixture.world.uncertain.store(true, Ordering::SeqCst);
    let authorized = fixture.authorize(&arguments, 20);
    let outcome = fixture.authority.invoke_authorized(authorized, &request);
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
    let operation_id = fixture.operation_id(correlation_id.as_str());
    let resumed = fixture
        .authority
        .resume(
            fresh_proof(500),
            &request.capsule_id,
            &correlation_id,
            &operation_id,
        )
        .expect("resume reconciles from the recorded binding");
    assert_eq!(resumed.state, EffectState::Aborted);
    assert!(resumed.replay);
    assert_eq!(fixture.world.executions.load(Ordering::SeqCst), 1);
}

#[test]
fn post_effect_uncertain_binds_genuine_evidence_and_reconcile_preserves_it() {
    let fixture = fixture();
    let correlation_id = correlation("post-effect-uncertain");
    let content = "post-effect";
    let arguments = write_arguments(content);
    let request = invoke_request(&correlation_id, 1);
    fixture
        .world
        .post_effect_uncertain
        .store(true, Ordering::SeqCst);
    let genuine = receipt_digest(content);
    let expected_post = Digest::hash(content.as_bytes());
    assert_ne!(
        genuine, expected_post,
        "fixture receipt digest must differ from the predicted post-world hash"
    );

    let outcome = fixture
        .authority
        .invoke_authorized(fixture.authorize(&arguments, 20), &request);
    assert!(
        matches!(
            &outcome,
            Err(OperationRejection::Executor(
                ExecutorFault::PostEffectUncertain { evidence_digest, .. }
            )) if *evidence_digest == genuine
        ),
        "post-effect uncertainty must carry the captured evidence, got {outcome:?}"
    );
    assert_eq!(
        fixture.row_state(correlation_id.as_str()),
        EffectState::InDoubt
    );
    // The digest is recorded atomically with the transition to InDoubt.
    assert_eq!(
        fixture.row_evidence(correlation_id.as_str()),
        Some(genuine.to_string())
    );

    // Commit the observed output without replacing its captured evidence with a world hash.
    let operation_id = fixture.operation_id(correlation_id.as_str());
    let reopened = fixture
        .authority
        .resume(
            fresh_proof(500),
            &request.capsule_id,
            &correlation_id,
            &operation_id,
        )
        .expect("reopened authority reconciles from the recorded binding");
    assert_eq!(reopened.state, EffectState::Committed);
    assert!(reopened.replay);
    assert_eq!(
        fixture.row_evidence(correlation_id.as_str()),
        Some(genuine.to_string())
    );

    // Replay preserves the operation and evidence without repeating the effect.
    let replayed = fixture
        .authority
        .invoke_authorized(fixture.authorize(&arguments, 21), &request)
        .expect("duplicate replay settles from the durable row");
    assert!(replayed.replay);
    assert_eq!(replayed.state, EffectState::Committed);
    assert_eq!(replayed.operation_id, reopened.operation_id);
    assert_eq!(
        fixture.row_evidence(correlation_id.as_str()),
        Some(genuine.to_string())
    );
    assert_eq!(fixture.world.executions.load(Ordering::SeqCst), 1);
}

#[test]
fn no_output_uncertain_stays_unbound_and_cannot_fake_a_receipt() {
    let fixture = fixture();
    let correlation_id = correlation("no-output-uncertain");
    let arguments = write_arguments("never landed");
    let request = invoke_request(&correlation_id, 1);
    fixture.world.uncertain.store(true, Ordering::SeqCst);
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
        "pre-output uncertainty stays unbound, got {outcome:?}"
    );
    assert_eq!(
        fixture.row_state(correlation_id.as_str()),
        EffectState::InDoubt
    );
    assert_eq!(
        fixture.row_evidence(correlation_id.as_str()),
        None,
        "no captured evidence may exist for a pre-output uncertainty"
    );

    // Absent output aborts the row without storing the predicted world hash as evidence.
    let operation_id = fixture.operation_id(correlation_id.as_str());
    let reopened = fixture
        .authority
        .resume(
            fresh_proof(500),
            &request.capsule_id,
            &correlation_id,
            &operation_id,
        )
        .expect("reopened authority reconciles the no-output uncertainty");
    assert_eq!(reopened.state, EffectState::Aborted);
    assert_eq!(
        fixture.row_state(correlation_id.as_str()),
        EffectState::Aborted
    );
    assert_eq!(
        fixture.row_evidence(correlation_id.as_str()),
        None,
        "aborted settlement must not fabricate receipt evidence"
    );
}

#[test]
fn recorded_evidence_is_immutable_under_conflicting_repair() {
    let fixture = fixture();
    let correlation_id = correlation("evidence-tamper");
    let content = "tamper";
    let arguments = write_arguments(content);
    let request = invoke_request(&correlation_id, 1);
    fixture
        .world
        .post_effect_uncertain
        .store(true, Ordering::SeqCst);
    let genuine = receipt_digest(content);
    let forged = Digest::hash(b"forged evidence");
    let outcome = fixture
        .authority
        .invoke_authorized(fixture.authorize(&arguments, 20), &request);
    assert!(outcome.is_err(), "the decorated effect stays uncertain");
    assert_eq!(
        fixture.row_evidence(correlation_id.as_str()),
        Some(genuine.to_string())
    );

    // Reject conflicting evidence instead of overwriting the captured digest.
    let error = {
        let mut ledger = fixture.authority.store.lock().unwrap();
        ledger
            .with_tx(|tx| {
                store::transition_operation(
                    tx,
                    correlation_id.as_str(),
                    EffectState::InDoubt,
                    EffectState::Committed,
                    Some(&forged.to_string()),
                    utc(20).unwrap(),
                )
            })
            .unwrap_err()
    };
    assert!(
        matches!(error, LedgerError::Conflict(_)),
        "conflicting evidence claims must conflict, got {error:?}"
    );
    assert_eq!(
        fixture.row_state(correlation_id.as_str()),
        EffectState::InDoubt
    );
    assert_eq!(
        fixture.row_evidence(correlation_id.as_str()),
        Some(genuine.to_string())
    );

    // An observation-only settlement preserves the recorded digest via
    // the CAS COALESCE — it never substitutes a world hash.
    {
        let mut ledger = fixture.authority.store.lock().unwrap();
        ledger
            .with_tx(|tx| {
                store::transition_operation(
                    tx,
                    correlation_id.as_str(),
                    EffectState::InDoubt,
                    EffectState::Committed,
                    None,
                    utc(21).unwrap(),
                )
            })
            .unwrap();
    }
    assert_eq!(
        fixture.row_state(correlation_id.as_str()),
        EffectState::Committed
    );
    assert_eq!(
        fixture.row_evidence(correlation_id.as_str()),
        Some(genuine.to_string())
    );
}
