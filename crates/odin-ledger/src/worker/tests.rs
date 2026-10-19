//! Durable worker identity, phase and recovery invariants.

use odin_domain::worker::WorkerPhase;
use time::macros::datetime;

use super::{
    job_worker_row, mark_job_stopping, register_job_worker, register_worker, settle_job_worker,
    JobRegisterOutcome, JobWorkerPhase, NewJobWorker, NewWorker, RegisterOutcome, ScopeProof,
    Settlement,
};
use crate::{Ledger, LedgerError};

const WORKER_ID: &str = "wkr0123456789abcdef0123456789abcdef";
const UNIT: &str = "tx0123456789abcdef-wp-11a-attempt-1-0123abcd.scope";
const INVOCATION: &str = "0123456789abcdeffedcba9876543210";

fn new_worker<'a>(unit: &'a str) -> NewWorker<'a> {
    NewWorker {
        worker_id: WORKER_ID,
        unit,
        correlation_id: "corr0123456789abcdef0123456789ab",
        tx_id: "tx0123456789abcdef",
        wp_id: "wp-11a",
        attempt: 1,
        now: datetime!(2026-09-05 12:00:00 UTC),
    }
}

fn proof() -> ScopeProof<'static> {
    ScopeProof {
        invocation_id: INVOCATION,
        cgroup_path: "/user.slice/user-1000.slice/user@1000.service/app.slice/tx.scope",
        cgroup_inode: 4096,
        leader_pid: 4711,
        leader_start_ticks: 1_845_673,
    }
}

const JOB_WORKER_A: &str = "wkr0123456789abcdef0123456789abcdea";
const JOB_WORKER_B: &str = "wkr0123456789abcdef0123456789abcdeb";
const JOB_WORKER_C: &str = "wkr0123456789abcdef0123456789ababec";

fn new_job_worker<'a>(worker_id: &'a str, job_uid: &'a str) -> NewJobWorker<'a> {
    NewJobWorker {
        worker_id,
        cluster: "test-cluster",
        namespace: "test-ns",
        job_name: "test-job",
        job_uid,
        correlation_id: "corr0123456789abcdef0123456789ab",
        operation_id: "op0123456789abcdef0123456789ab",
        now: datetime!(2026-09-05 12:00:00 UTC),
    }
}

/// A Job UID can be reused only after all earlier workers stop; failed or residual workers block reuse.
#[test]
fn job_reincarnation_requires_proved_stopped_identity() {
    let mut ledger = Ledger::open_in_memory().expect("open ledger");

    let inserted = ledger
        .with_tx(|tx| register_job_worker(tx, &new_job_worker(JOB_WORKER_A, "job-uid-1")))
        .expect("register the first incarnation");
    assert_eq!(inserted, JobRegisterOutcome::Inserted);
    let blocked = ledger
        .with_tx(|tx| register_job_worker(tx, &new_job_worker(JOB_WORKER_B, "job-uid-1")))
        .expect_err("a live job worker must block reincarnation");
    assert!(
        matches!(&blocked, LedgerError::Conflict(message)
                if message.contains("already backs an unproved worker")),
        "unexpected error: {blocked}"
    );

    ledger
        .with_tx(|tx| {
            mark_job_stopping(
                tx,
                JOB_WORKER_A,
                JobWorkerPhase::Registered,
                datetime!(2026-09-05 12:01:00 UTC),
            )
        })
        .expect("journal the stop");
    ledger
        .with_tx(|tx| {
            settle_job_worker(
                tx,
                JOB_WORKER_A,
                JobWorkerPhase::Stopping,
                Settlement::Stopped,
                "{}",
                datetime!(2026-09-05 12:02:00 UTC),
            )
        })
        .expect("prove the stop");
    let reincarnated = ledger
        .with_tx(|tx| register_job_worker(tx, &new_job_worker(JOB_WORKER_B, "job-uid-1")))
        .expect("a proved-stopped identity must permit reincarnation");
    assert_eq!(reincarnated, JobRegisterOutcome::Inserted);

    let old = job_worker_row(ledger.connection(), JOB_WORKER_A)
        .expect("read stopped row")
        .expect("the stopped row must be preserved");
    assert_eq!(old.phase, JobWorkerPhase::Stopped);
    assert_eq!(old.job_uid, "job-uid-1");
    let fresh = job_worker_row(ledger.connection(), JOB_WORKER_B)
        .expect("read fresh row")
        .expect("the fresh incarnation row");
    assert_eq!(fresh.phase, JobWorkerPhase::Registered);
    assert_eq!(fresh.job_uid, "job-uid-1");

    let residual = ledger
        .with_tx(|tx| register_job_worker(tx, &new_job_worker(JOB_WORKER_C, "job-uid-2")))
        .expect("register the residual scenario worker");
    assert_eq!(residual, JobRegisterOutcome::Inserted);
    ledger
        .with_tx(|tx| {
            mark_job_stopping(
                tx,
                JOB_WORKER_C,
                JobWorkerPhase::Registered,
                datetime!(2026-09-05 12:03:00 UTC),
            )
        })
        .expect("journal the residual stop");
    ledger
        .with_tx(|tx| {
            settle_job_worker(
                tx,
                JOB_WORKER_C,
                JobWorkerPhase::Stopping,
                Settlement::Residual,
                r#"{"pods":[{"name":"test-job-x","uid":"pod-1","phase":"Running"}]}"#,
                datetime!(2026-09-05 12:04:00 UTC),
            )
        })
        .expect("settle residual");
    let still_blocked = ledger
        .with_tx(|tx| register_job_worker(tx, &new_job_worker(JOB_WORKER_B, "job-uid-2")))
        .expect_err("a residual job worker must block reincarnation");
    assert!(matches!(still_blocked, LedgerError::Conflict(_)));
}

#[test]
fn worker_registration_replays_and_conflicts() {
    let mut ledger = Ledger::open_in_memory().expect("open ledger");
    let outcome = ledger
        .with_tx(|tx| register_worker(tx, &new_worker(UNIT)))
        .expect("register worker");
    assert_eq!(outcome, RegisterOutcome::Inserted);
    let replay = ledger
        .with_tx(|tx| register_worker(tx, &new_worker(UNIT)))
        .expect("replay worker registration");
    match replay {
        RegisterOutcome::Replay { row } => {
            assert_eq!(row.worker_id, WORKER_ID);
            assert_eq!(row.unit, UNIT);
            assert_eq!(row.phase, WorkerPhase::Registered);
            assert_eq!(row.invocation_id, None);
            assert_eq!(row.cgroup_path, None);
            assert_eq!(row.leader_pid, None);
        }
        other => panic!("expected replay, found {other:?}"),
    }
    let conflict = NewWorker {
        unit: "tx0123456789abcdef-wp-11a-attempt-2-deadbeef.scope",
        ..new_worker(UNIT)
    };
    let error = ledger
        .with_tx(|tx| register_worker(tx, &conflict))
        .expect_err("conflicting intent must fail");
    assert!(
        matches!(error, LedgerError::Conflict(ref message)
                if message.contains("different worker intent")),
        "unexpected error: {error}"
    );
}

#[test]
fn worker_scope_proof_is_compare_and_set() {
    let mut ledger = Ledger::open_in_memory().expect("open ledger");
    ledger
        .with_tx(|tx| register_worker(tx, &new_worker(UNIT)))
        .expect("register worker");
    let applied = ledger
        .with_tx(|tx| {
            super::record_scope_proof(tx, WORKER_ID, &proof(), datetime!(2026-09-05 12:00:01 UTC))
        })
        .expect("record scope proof");
    assert_eq!(applied, super::WorkerTransitionOutcome::Applied);
    let replay = ledger
        .with_tx(|tx| {
            super::record_scope_proof(tx, WORKER_ID, &proof(), datetime!(2026-09-05 12:00:02 UTC))
        })
        .expect("replay scope proof");
    assert_eq!(replay, super::WorkerTransitionOutcome::Replay);
    let row = super::worker_row(ledger.connection(), WORKER_ID)
        .expect("read worker")
        .expect("worker row exists");
    assert_eq!(row.phase, WorkerPhase::ScopeCreated);
    assert_eq!(row.invocation_id.as_deref(), Some(INVOCATION));
    assert_eq!(row.leader_pid, Some(4711));
    assert_eq!(row.cgroup_inode, Some(4096));
    // Recorded scope identity cannot be replaced.
    let divergent = ScopeProof {
        invocation_id: "ffffffffffffffffffffffffffffffff",
        ..proof()
    };
    let error = ledger
        .with_tx(|tx| {
            super::record_scope_proof(
                tx,
                WORKER_ID,
                &divergent,
                datetime!(2026-09-05 12:00:03 UTC),
            )
        })
        .expect_err("divergent proof must fail");
    assert!(matches!(error, LedgerError::Conflict(_)));
    // Recording scope identity requires an existing worker.
    let error = ledger
        .with_tx(|tx| {
            super::record_scope_proof(
                tx,
                "wkrmissing",
                &proof(),
                datetime!(2026-09-05 12:00:04 UTC),
            )
        })
        .expect_err("missing worker must fail");
    assert!(matches!(
        error,
        LedgerError::NotFound { kind: "worker", .. }
    ));
}

#[test]
fn worker_settlements_follow_the_transition_law() {
    let mut ledger = Ledger::open_in_memory().expect("open ledger");
    ledger
        .with_tx(|tx| register_worker(tx, &new_worker(UNIT)))
        .expect("register worker");
    // Registered cannot transition directly to payload_running.
    let error = ledger
        .with_tx(|tx| {
            super::mark_payload_running(tx, WORKER_ID, datetime!(2026-09-05 12:00:01 UTC))
        })
        .expect_err("registered cannot run");
    assert!(matches!(error, LedgerError::Conflict(_)));
    ledger
        .with_tx(|tx| {
            super::record_scope_proof(tx, WORKER_ID, &proof(), datetime!(2026-09-05 12:00:01 UTC))
        })
        .expect("record scope proof");
    let applied = ledger
        .with_tx(|tx| {
            super::mark_payload_running(tx, WORKER_ID, datetime!(2026-09-05 12:00:02 UTC))
        })
        .expect("mark payload running");
    assert_eq!(applied, super::WorkerTransitionOutcome::Applied);
    let replay = ledger
        .with_tx(|tx| {
            super::mark_payload_running(tx, WORKER_ID, datetime!(2026-09-05 12:00:03 UTC))
        })
        .expect("replay mark payload running");
    assert_eq!(replay, super::WorkerTransitionOutcome::Replay);
    let residue = r#"{"survivors":[]}"#;
    let applied = ledger
        .with_tx(|tx| {
            super::settle_worker(
                tx,
                WORKER_ID,
                WorkerPhase::PayloadRunning,
                Settlement::Stopped,
                residue,
                datetime!(2026-09-05 12:00:04 UTC),
            )
        })
        .expect("settle stopped");
    assert_eq!(applied, super::WorkerTransitionOutcome::Applied);
    // Terminal phases never move again, in either direction.
    let error = ledger
        .with_tx(|tx| {
            super::settle_worker(
                tx,
                WORKER_ID,
                WorkerPhase::Stopped,
                Settlement::Residual,
                residue,
                datetime!(2026-09-05 12:00:05 UTC),
            )
        })
        .expect_err("terminal worker must never move");
    assert!(matches!(error, LedgerError::Conflict(_)));
    let row = super::worker_row(ledger.connection(), WORKER_ID)
        .expect("read worker")
        .expect("worker row exists");
    assert_eq!(row.phase, WorkerPhase::Stopped);
    assert_eq!(row.residue_json, residue);
    assert!(super::nonterminal_rows(ledger.connection(), None)
        .expect("read nonterminal rows")
        .is_empty());
}

#[test]
fn worker_recovers_by_invocation_across_reopen() {
    let path = std::env::temp_dir().join(format!(
        "odin-ledger-worker-invocation-{}-{}.sqlite3",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_nanos()
    ));
    let invocation = {
        let mut ledger = Ledger::open(&path).expect("open ledger");
        ledger
            .with_tx(|tx| register_worker(tx, &new_worker(UNIT)))
            .expect("register worker");
        ledger
            .with_tx(|tx| {
                super::record_scope_proof(
                    tx,
                    WORKER_ID,
                    &proof(),
                    datetime!(2026-09-05 12:00:01 UTC),
                )
            })
            .expect("record scope proof");
        let row = super::worker_by_invocation(ledger.connection(), INVOCATION)
            .expect("query by invocation")
            .expect("worker found by invocation");
        assert_eq!(row.worker_id, WORKER_ID);
        assert_eq!(row.phase, WorkerPhase::ScopeCreated);
        row.invocation_id.expect("invocation recorded")
    };
    // Reopen recovers the worker by its InvocationID.
    let ledger = Ledger::open(&path).expect("reopen ledger");
    let row = super::worker_by_invocation(ledger.connection(), &invocation)
        .expect("query by invocation after reopen")
        .expect("worker survives reopen");
    assert_eq!(row.worker_id, WORKER_ID);
    assert_eq!(row.phase, WorkerPhase::ScopeCreated);
    assert!(row.phase.is_nonterminal());
    let nonterminal =
        super::nonterminal_rows(ledger.connection(), Some(row.correlation_id.as_str()))
            .expect("read nonterminal rows");
    assert_eq!(nonterminal.len(), 1);
    assert_eq!(nonterminal[0].worker_id, WORKER_ID);
    assert!(
        super::worker_by_invocation(ledger.connection(), "ffffffffffffffffffffffffffffffff")
            .expect("query unknown invocation")
            .is_none()
    );
    std::fs::remove_file(&path).expect("remove test database");
}

#[test]
fn residual_workers_carry_evidence() {
    let mut ledger = Ledger::open_in_memory().expect("open ledger");
    ledger
        .with_tx(|tx| register_worker(tx, &new_worker(UNIT)))
        .expect("register worker");
    ledger
        .with_tx(|tx| {
            super::record_scope_proof(tx, WORKER_ID, &proof(), datetime!(2026-09-05 12:00:01 UTC))
        })
        .expect("record scope proof");
    let residue = r#"{"units":["tx.scope"],"processes":[]}"#;
    ledger
        .with_tx(|tx| {
            super::settle_worker(
                tx,
                WORKER_ID,
                WorkerPhase::ScopeCreated,
                Settlement::Residual,
                residue,
                datetime!(2026-09-05 12:00:02 UTC),
            )
        })
        .expect("settle residual");
    let residuals = super::residual_rows(ledger.connection()).expect("read residuals");
    assert_eq!(residuals.len(), 1);
    let (row, evidence) = &residuals[0];
    assert_eq!(row.worker_id, WORKER_ID);
    assert_eq!(row.phase, WorkerPhase::Residual);
    assert_eq!(
        evidence
            .get("units")
            .and_then(serde_json::Value::as_array)
            .and_then(|units| units.first())
            .and_then(serde_json::Value::as_str),
        Some("tx.scope")
    );
    // Reject empty or malformed residue before storing it.
    for invalid in ["{}", "not-json"] {
        let mut second = Ledger::open_in_memory().expect("open ledger");
        second
            .with_tx(|tx| register_worker(tx, &new_worker(UNIT)))
            .expect("register worker");
        second
            .with_tx(|tx| {
                super::record_scope_proof(
                    tx,
                    WORKER_ID,
                    &proof(),
                    datetime!(2026-09-05 12:00:01 UTC),
                )
            })
            .expect("record scope proof");
        let error = second
            .with_tx(|tx| {
                super::settle_worker(
                    tx,
                    WORKER_ID,
                    WorkerPhase::ScopeCreated,
                    Settlement::Residual,
                    invalid,
                    datetime!(2026-09-05 12:00:02 UTC),
                )
            })
            .expect_err("invalid residue evidence must fail");
        assert!(matches!(error, LedgerError::InvalidData { .. }));
    }
}
