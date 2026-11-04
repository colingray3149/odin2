//! Durable lane and run lifecycle invariants.

use super::*;
use crate::Ledger;
use time::Duration;

fn now() -> OffsetDateTime {
    OffsetDateTime::from_unix_timestamp(1_767_312_000).expect("valid timestamp")
}

fn new_lane(id: &str) -> NewLane {
    NewLane {
        lane_id: LaneId::new(id).unwrap(),
        seat_id: SeatId::new("gungnir").unwrap(),
        project_id: None,
        template_id: "template".to_owned(),
        backend: "local_omp".to_owned(),
        created_by: "operator".to_owned(),
        created_at: now(),
        retained: false,
    }
}

fn new_run(id: &str, lane: &str, attempt_number: i64, created_at: OffsetDateTime) -> NewRun {
    NewRun {
        run_id: RunId::new(id).unwrap(),
        lane_id: LaneId::new(lane).unwrap(),
        attempt_number,
        workflow_id: None,
        workflow_version: None,
        input_hash: "input".to_owned(),
        accepted_capability_revision: None,
        lease_id: None,
        absolute_deadline: None,
        retry_budget: 0,
        created_at,
    }
}

#[test]
fn runs_and_attempts_move_only_along_legal_edges_at_their_current_revision() {
    let ledger = Ledger::open_in_memory().unwrap();
    let connection = ledger.connection();
    create_lane(connection, &new_lane("lane:walk")).unwrap();
    let run = create_run(connection, &new_run("run:walk", "lane:walk", 1, now()))
        .unwrap()
        .run_id;
    let attempt = create_attempt(
        connection,
        &NewAttempt {
            attempt_id: AttemptId::new("attempt:walk").unwrap(),
            run_id: run.clone(),
            attempt_number: 1,
            executor_id: None,
            created_at: now(),
        },
    )
    .unwrap()
    .attempt_id;

    assert_eq!(
        transition_run(connection, &run, RunStatus::Planning, 1, now()).unwrap(),
        2
    );
    assert_eq!(
        transition_attempt(connection, &attempt, AttemptStatus::Starting, 1, now()).unwrap(),
        2
    );

    // A planning run cannot jump to pending, and a stale revision cannot overwrite.
    let illegal = transition_run(connection, &run, RunStatus::Pending, 2, now()).unwrap_err();
    assert!(
        matches!(illegal, LedgerError::InvalidData { .. }),
        "{illegal:?}"
    );
    assert!(matches!(
        transition_attempt(connection, &attempt, AttemptStatus::Running, 1, now()),
        Err(LedgerError::StaleActor { .. })
    ));
    assert_eq!(
        read_run(connection, &run).unwrap().unwrap().status,
        RunStatus::Planning
    );
    assert_eq!(
        read_attempt(connection, &attempt).unwrap().unwrap().status,
        AttemptStatus::Starting
    );
}

/// Live-session runs are filtered by lane and returned oldest first.
#[test]
fn live_runs_for_lane_lists_only_that_lanes_live_sessions() {
    let ledger = Ledger::open_in_memory().unwrap();
    create_lane(ledger.connection(), &new_lane("gungnir-rig")).unwrap();
    create_lane(ledger.connection(), &new_lane("gungnir-odin")).unwrap();
    for (run, lane, attempt, minutes) in [
        ("run:live:b", "gungnir-rig", 1, 2),
        ("run:live:a", "gungnir-rig", 2, 1),
        ("run:workflow", "gungnir-rig", 3, 0),
        ("run:live:other", "gungnir-odin", 1, 0),
    ] {
        let created_at = now() + Duration::minutes(minutes);
        create_run(
            ledger.connection(),
            &new_run(run, lane, attempt, created_at),
        )
        .unwrap();
    }
    let runs =
        live_runs_for_lane(ledger.connection(), &LaneId::new("gungnir-rig").unwrap()).unwrap();
    let ids: Vec<String> = runs.iter().map(ToString::to_string).collect();
    assert_eq!(ids, ["run:live:a", "run:live:b"]);
}
