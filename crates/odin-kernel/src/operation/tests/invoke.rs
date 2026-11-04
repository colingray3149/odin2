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
    let replay = fixture
        .authority
        .invoke_authorized(fixture.authorize(&arguments, 21), &request)
        .expect("replayed invocation");
    assert!(replay.replay);
    assert_eq!(replay.state, EffectState::Committed);
    assert_eq!(replay.operation_id, decision.operation_id);
    assert_eq!(fixture.world.executions.load(Ordering::SeqCst), 1);
    let usage = {
        let ledger = fixture.authority.lock_store().expect("ledger lock");
        store::usage(ledger.connection(), "00000000-0000-4000-8000-000000000001").unwrap()
    };
    assert_eq!((usage.requests, usage.stops, usage.spend), (1, 0, 0));
}

/// A correlation names one exact request: changing the ceiling, the capsule, the command or the payload under it is a
/// conflict, never a second effect.
#[test]
fn a_changed_request_under_the_same_correlation_is_a_duplicate_conflict() {
    for changed in ["ceiling", "capsule", "command", "payload"] {
        let fixture = fixture();
        let correlation_id = correlation(&format!("drift-{changed}"));
        let first = fixture
            .authority
            .invoke_authorized(
                fixture.authorize(&write_arguments("original"), 20),
                &invoke_request(&correlation_id, 1),
            )
            .expect("original commits");
        assert_eq!(first.state, EffectState::Committed);

        let mut request = invoke_request(&correlation_id, 1);
        let mut arguments = write_arguments("original");
        let mut command = "command.one";
        match changed {
            "ceiling" => request.requested_ceiling.requests = 5,
            "capsule" => request.capsule_id = CapsuleId::new("capsule-other").unwrap(),
            "command" => command = "command.two",
            _ => arguments = write_arguments("tampered"),
        }
        let outcome = fixture.authority.invoke_authorized(
            fixture.authorize_command(fresh_proof(21), &arguments, 21, command),
            &request,
        );
        assert!(
            matches!(&outcome, Err(OperationRejection::DuplicateConflict { .. })),
            "a changed {changed} must conflict, got {outcome:?}"
        );
        assert_eq!(
            fixture.world.executions.load(Ordering::SeqCst),
            1,
            "{changed}"
        );
        assert_eq!(
            fixture.row_state(correlation_id.as_str()),
            EffectState::Committed,
            "{changed}"
        );
    }
}
