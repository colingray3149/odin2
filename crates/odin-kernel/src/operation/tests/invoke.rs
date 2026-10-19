//! Admission, charging, and replay equality: correlations identify exact requests,
//! and replay must not repeat execution or charges.

use super::*;

#[test]
fn fresh_invoke_commits_replays_without_reexecution_and_charges_once() {
    let fixture = fixture();
    let correlation_id = correlation("fresh");
    let arguments = write_arguments("first");
    let request = invoke_request(&correlation_id, 1);
    let decision = fixture
        .authority
        .invoke_authorized(fixture.authorize(&arguments, 20), &request)
        .expect("fresh invocation commits");
    assert_eq!(decision.state, EffectState::Committed);
    assert!(!decision.replay);
    assert_eq!(fixture.world.executions.load(Ordering::SeqCst), 1);
    {
        let ledger = fixture.authority.lock_store().expect("ledger lock");
        let row = store::operation_row(ledger.connection(), correlation_id.as_str())
            .unwrap()
            .expect("fresh row");
        assert!(!row.request_json.contains("executor_binding"));
        assert!(!row.prepared_binding.contains("executor_binding"));
    }
    let replay = fixture
        .authority
        .invoke_authorized(fixture.authorize(&arguments, 21), &request)
        .expect("replayed invocation");
    assert!(replay.replay);
    assert_eq!(replay.state, EffectState::Committed);
    assert_eq!(replay.operation_id, decision.operation_id);
    assert_eq!(fixture.world.executions.load(Ordering::SeqCst), 1);
}

#[test]
fn zero_ceiling_denies_and_binds_nothing() {
    let fixture = fixture();
    let correlation_id = correlation("zero-ceiling");
    let arguments = write_arguments("never");
    let request = invoke_request(&correlation_id, 0);
    let authorized = fixture.authorize(&arguments, 20);
    assert!(matches!(
        fixture.authority.invoke_authorized(authorized, &request),
        Err(OperationRejection::BudgetDenied { .. })
    ));
    assert_eq!(fixture.world.executions.load(Ordering::SeqCst), 0);
    let ledger = fixture.authority.store.lock().unwrap();
    assert!(
        odin_ledger::operation::operation_row(ledger.connection(), correlation_id.as_str())
            .unwrap()
            .is_none()
    );
}

#[test]
fn replay_with_changed_ceiling_is_a_hard_conflict() {
    let fixture = fixture();
    let correlation_id = correlation("ceiling-drift");
    let arguments = write_arguments("same");
    fixture
        .authority
        .invoke_authorized(
            fixture.authorize(&arguments, 20),
            &invoke_request(&correlation_id, 1),
        )
        .expect("first commits");
    assert!(matches!(
        fixture.authority.invoke_authorized(
            fixture.authorize(&arguments, 21),
            &invoke_request(&correlation_id, 5),
        ),
        Err(OperationRejection::DuplicateConflict { .. })
    ));
}

#[test]
fn changed_capability_same_correlation_is_typed_duplicate_conflict() {
    let fixture = fixture();
    let correlation_id = correlation("capability-drift");
    let arguments = write_arguments("same");
    fixture
        .authority
        .invoke_authorized(
            fixture.authorize(&arguments, 20),
            &invoke_request(&correlation_id, 1),
        )
        .expect("first commits");
    let conflicting = InvokeRequest {
        capsule_id: CapsuleId::new("capsule-other").unwrap(),
        correlation_id: correlation_id.clone(),
        requested_ceiling: RequestCost {
            requests: 1,
            stops: 0,
            spend: 0,
        },
    };
    let authorized = fixture.authorize(&arguments, 21);
    assert!(matches!(
        fixture
            .authority
            .invoke_authorized(authorized, &conflicting),
        Err(OperationRejection::DuplicateConflict { .. })
    ));
}

#[test]
fn spoofed_clock_rejects_expired_tokens() {
    let fixture = fixture();
    let correlation_id = correlation("stale");
    let arguments = write_arguments("stale");
    let request = invoke_request(&correlation_id, 1);
    fixture.clock_ms.store(5_000, Ordering::SeqCst);
    let authorized = fixture.authorize(&arguments, 20);
    let outcome = fixture.authority.invoke_authorized(authorized, &request);
    assert!(
        matches!(&outcome, Err(OperationRejection::IdentityExpired { .. })),
        "expired token must reject, got {outcome:?}"
    );
}

#[test]
fn revoked_tokens_produce_no_usable_proof() {
    let bindings = bindings();
    let issuer = TokenIssuer::new(KEY.to_vec()).unwrap();
    let token = issuer
        .mint(MintRequest {
            seat: bindings.seat.clone(),
            slice: bindings.slice.clone(),
            lane: bindings.lane.clone(),
            session: bindings.session.clone(),
            seat_revision: bindings.seat_revision,
            slice_revision: bindings.slice_revision,
            capability_policy_digest: bindings.capability_policy_digest,
            context_policy_digest: bindings.context_policy_digest,
            issued_at_ms: 0,
            expires_at_ms: 1_000,
            entropy: b"entropy",
        })
        .unwrap();
    let mut revocations = MemoryRevocations::new();
    revocations
        .revoke(&token.token_id, 5)
        .expect("revoke records");
    assert!(FreshAuthority::verify(&token, bindings, KEY.to_vec(), revocations, 20,).is_err());
}

#[test]
fn changed_command_identity_same_correlation_is_typed_duplicate_conflict() {
    let fixture = fixture();
    let correlation_id = correlation("command-drift");
    let arguments = write_arguments("same");
    let request = invoke_request(&correlation_id, 1);
    let first = fixture
        .authority
        .invoke_authorized(fixture.authorize(&arguments, 20), &request)
        .expect("original commits");
    assert_eq!(first.state, EffectState::Committed);
    let outcome = fixture.authority.invoke_authorized(
        fixture.authorize_command(fresh_proof(21), &arguments, 21, "command.two"),
        &request,
    );
    assert!(
        matches!(&outcome, Err(OperationRejection::DuplicateConflict { .. })),
        "a different command under the same correlation must conflict, got {outcome:?}"
    );
    assert_eq!(fixture.world.executions.load(Ordering::SeqCst), 1);
}

#[test]
fn changed_payload_same_correlation_is_typed_duplicate_conflict() {
    let fixture = fixture();
    let correlation_id = correlation("payload-drift");
    let request = invoke_request(&correlation_id, 1);
    fixture
        .authority
        .invoke_authorized(
            fixture.authorize(&write_arguments("original"), 20),
            &request,
        )
        .expect("original commits");
    let outcome = fixture.authority.invoke_authorized(
        fixture.authorize(&write_arguments("tampered"), 21),
        &request,
    );
    assert!(
        matches!(&outcome, Err(OperationRejection::DuplicateConflict { .. })),
        "a changed payload under the same correlation must conflict, got {outcome:?}"
    );
    assert_eq!(fixture.world.executions.load(Ordering::SeqCst), 1);
    assert_eq!(
        fixture.row_state(correlation_id.as_str()),
        EffectState::Committed
    );
}
