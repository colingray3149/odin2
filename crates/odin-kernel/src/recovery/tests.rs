//! Recovery ladder bounds, transitions and terminality invariants.

use super::*;

fn at(second: i64) -> OffsetDateTime {
    OffsetDateTime::from_unix_timestamp(second).expect("test timestamp")
}

fn incident() -> IncidentId {
    IncidentId::new("incident:one").expect("incident id")
}

fn policy(limits: RungLimits, cooldown: Duration) -> RecoveryPolicy {
    RecoveryPolicy::new(
        limits,
        RungCooldowns::uniform(cooldown),
        "operator must decide",
    )
    .expect("recovery policy")
}

fn activate(policy: RecoveryPolicy) -> RecoveryState {
    RecoveryState::new(policy)
        .observe(RecoveryObservation::Failure {
            failure_signature: "worker:stalled:v1".to_owned(),
            incident_ref: incident(),
            observed_at: at(0),
        })
        .expect("failure observation")
        .into_state()
}

#[test]
fn ladder_transitions_once_then_blocks() {
    let mut state = activate(policy(RungLimits::new(1, 1, 1, 1, 1), Duration::ZERO));
    let expected = [
        RecoveryRung::Retry,
        RecoveryRung::RestartWorker,
        RecoveryRung::Checkpoint,
        RecoveryRung::Rehome,
        RecoveryRung::Escalate,
    ];

    for (index, expected_rung) in expected.into_iter().enumerate() {
        let decision = state.next(at(index as i64)).expect("recovery decision");
        let RecoveryDecision::Action {
            action,
            state: next,
        } = decision
        else {
            panic!("expected action");
        };
        assert_eq!(action.rung, expected_rung);
        state = next;
    }

    let decision = state.next(at(5)).expect("terminal decision");
    assert!(matches!(&decision, RecoveryDecision::Blocked { .. }));
    let state = decision.into_state();
    assert_eq!(state.total_attempts(), 5);
    assert_eq!(
        state.phase(),
        &RecoveryPhase::Blocked {
            missing_decision: "operator must decide".to_owned(),
        }
    );
    assert!(matches!(
        state.next(at(6)).expect("repeated terminal decision"),
        RecoveryDecision::Blocked { .. }
    ));
}

#[test]
fn repeated_failure_signature_storm_is_deduplicated() {
    let mut state = activate(policy(RungLimits::new(0, 0, 0, 0, 0), Duration::ZERO));
    let activated_revision = state.revision();

    for second in 1..=100 {
        let update = state
            .observe(RecoveryObservation::Failure {
                failure_signature: "worker:stalled:v1".to_owned(),
                incident_ref: incident(),
                observed_at: at(second),
            })
            .expect("duplicate failure");
        assert_eq!(
            update.disposition(),
            ObservationDisposition::DuplicateFailure
        );
        state = update.into_state();
    }
    assert_eq!(state.revision(), activated_revision);
    assert_eq!(state.failure_signatures().count(), 1);
    assert_eq!(state.incident_refs().count(), 1);

    let blocked = state.next(at(101)).expect("blocked decision").into_state();
    let blocked_revision = blocked.revision();
    let update = blocked
        .observe(RecoveryObservation::Failure {
            failure_signature: "worker:stalled:v1".to_owned(),
            incident_ref: incident(),
            observed_at: at(102),
        })
        .expect("terminal duplicate");
    assert_eq!(
        update.disposition(),
        ObservationDisposition::TerminalBlocked
    );
    assert_eq!(update.state().revision(), blocked_revision);
}

#[test]
fn recovery_state_reopen_preserves_cooldown_and_exhaustion() {
    let policy = policy(RungLimits::new(1, 0, 0, 0, 0), Duration::seconds(30));
    let state = activate(policy);
    let decision = state.next(at(0)).expect("first attempt");
    let RecoveryDecision::Action { state, .. } = decision else {
        panic!("expected the first attempt to dispatch");
    };
    let cooldown_until = state.cooldown_until().expect("attempt set a cooldown");

    // Reopening preserves the cooldown deadline and cannot spend an attempt early.
    let json = serde_json::to_string(&state.snapshot()).expect("snapshot serializes");
    let reopened =
        RecoveryState::from_snapshot(serde_json::from_str(&json).expect("snapshot deserializes"))
            .expect("snapshot restores");
    assert_eq!(reopened.cooldown_until(), Some(cooldown_until));
    assert!(matches!(
        reopened.clone().next(at(10)).expect("early decision"),
        RecoveryDecision::Cooldown { .. }
    ));

    // The exhausted retry budget remains exhausted after reopen.
    let decision = reopened.next(at(30)).expect("post-cooldown decision");
    let RecoveryDecision::Blocked { state } = decision else {
        panic!("expected exhaustion after the single retry attempt");
    };
    assert_eq!(
        state.phase(),
        &RecoveryPhase::Blocked {
            missing_decision: "operator must decide".to_owned(),
        }
    );
    assert_eq!(state.total_attempts(), 1);
    let json = serde_json::to_string(&state.snapshot()).expect("snapshot serializes");
    let reopened =
        RecoveryState::from_snapshot(serde_json::from_str(&json).expect("snapshot deserializes"))
            .expect("blocked snapshot restores");
    assert!(matches!(
        reopened.next(at(31)).expect("post-reopen terminal"),
        RecoveryDecision::Blocked { .. }
    ));
}
