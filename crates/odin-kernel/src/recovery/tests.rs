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
fn cooldown_does_not_consume_an_attempt_or_revision() {
    let state = activate(policy(
        RungLimits::new(1, 1, 0, 0, 0),
        Duration::seconds(10),
    ));
    let first = state.next(at(0)).expect("first action");
    let first_revision = first.state().revision();
    let state = first.into_state();

    let cooling = state.next(at(9)).expect("cooldown decision");
    assert!(matches!(&cooling, RecoveryDecision::Cooldown { .. }));
    assert_eq!(cooling.state().revision(), first_revision);
    assert_eq!(cooling.state().total_attempts(), 1);

    let decision = cooling
        .into_state()
        .next(at(10))
        .expect("post-cooldown action");
    let RecoveryDecision::Action { action, .. } = decision else {
        panic!("expected restart action");
    };
    assert_eq!(action.rung, RecoveryRung::RestartWorker);
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
fn heartbeat_does_not_clear_or_advance_recovery() {
    let state = activate(policy(RungLimits::default(), Duration::ZERO));
    let revision = state.revision();

    let update = state
        .observe(RecoveryObservation::Heartbeat {
            observed_at: at(10),
        })
        .expect("heartbeat observation");

    assert_eq!(update.disposition(), ObservationDisposition::HeartbeatOnly);
    assert_eq!(update.state().revision(), revision);
    assert_eq!(
        update.state().phase(),
        &RecoveryPhase::Recovering {
            rung: RecoveryRung::Retry,
        }
    );
    assert_eq!(update.state().total_attempts(), 0);
}

#[test]
fn recovery_state_reopen() {
    // Restore the exact rung and counters without resetting the attempt budget.
    let original = activate(policy(RungLimits::new(2, 1, 1, 1, 1), Duration::ZERO));
    let decision = original.next(at(0)).expect("first attempt");
    let RecoveryDecision::Action { action, state } = decision else {
        panic!("expected the first attempt to dispatch");
    };
    assert_eq!(action.rung, RecoveryRung::Retry);
    assert_eq!(action.attempt_on_rung, 1);
    assert_eq!(action.total_attempt, 1);
    assert_eq!(action.revision, state.revision());

    let json = serde_json::to_string(&state.snapshot()).expect("snapshot serializes");
    let restored =
        RecoveryState::from_snapshot(serde_json::from_str(&json).expect("snapshot deserializes"))
            .expect("snapshot restores");
    assert_eq!(restored, state);
    assert_eq!(restored.revision(), state.revision());
    assert_eq!(restored.total_attempts(), 1);
    assert_eq!(restored.attempts_on(RecoveryRung::Retry), 1);
    assert_eq!(
        restored.phase(),
        &RecoveryPhase::Recovering {
            rung: RecoveryRung::Retry,
        }
    );
    assert_eq!(
        restored.failure_signatures().collect::<Vec<_>>(),
        vec!["worker:stalled:v1"]
    );

    // Resume at retry attempt two, not attempt one.
    let decision = restored.next(at(1)).expect("post-reopen attempt");
    let RecoveryDecision::Action { action, .. } = decision else {
        panic!("expected the reopened ladder to continue");
    };
    assert_eq!(action.rung, RecoveryRung::Retry);
    assert_eq!(action.attempt_on_rung, 2);
    assert_eq!(action.total_attempt, 2);
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

#[test]
fn recovery_state_reopen_rejects_unknown_version() {
    let state = activate(policy(RungLimits::new(1, 1, 1, 1, 1), Duration::ZERO));
    let mut snapshot = state.snapshot();
    snapshot.snapshot_version = RECOVERY_SNAPSHOT_VERSION + 1;
    assert_eq!(
        RecoveryState::from_snapshot(snapshot),
        Err(RecoveryError::UnsupportedSnapshotVersion(
            RECOVERY_SNAPSHOT_VERSION + 1
        ))
    );
}

#[test]
fn recovery_state_heartbeat_survives_reopen_without_progress() {
    // Heartbeat and reopen preserve phase, revision, and counters.
    let state = activate(policy(RungLimits::default(), Duration::ZERO));
    let revision = state.revision();
    let update = state
        .clone()
        .observe(RecoveryObservation::Heartbeat {
            observed_at: at(10),
        })
        .expect("heartbeat observation");
    assert_eq!(update.disposition(), ObservationDisposition::HeartbeatOnly);
    let state = update.into_state();

    let json = serde_json::to_string(&state.snapshot()).expect("snapshot serializes");
    let reopened =
        RecoveryState::from_snapshot(serde_json::from_str(&json).expect("snapshot deserializes"))
            .expect("snapshot restores");
    assert_eq!(reopened.revision(), revision);
    assert_eq!(reopened.total_attempts(), 0);
    assert!(matches!(
        reopened.next(at(11)).expect("post-reopen decision"),
        RecoveryDecision::Action { .. }
    ));
}

#[test]
fn recovery_state_block_is_terminal_and_revises() {
    let state = activate(policy(RungLimits::default(), Duration::ZERO));
    let revision = state.revision();
    let blocked = state
        .block("retry capability missing from incident card")
        .expect("durable block");
    assert_eq!(blocked.revision(), revision + 1);
    assert_eq!(
        blocked.phase(),
        &RecoveryPhase::Blocked {
            missing_decision: "retry capability missing from incident card".to_owned(),
        }
    );
    assert!(blocked.cooldown_until().is_none());
    let json = serde_json::to_string(&blocked.snapshot()).expect("snapshot serializes");
    let reopened =
        RecoveryState::from_snapshot(serde_json::from_str(&json).expect("snapshot deserializes"))
            .expect("blocked snapshot restores");
    assert!(matches!(
        reopened.next(at(0)).expect("post-reopen terminal"),
        RecoveryDecision::Blocked { .. }
    ));
}
