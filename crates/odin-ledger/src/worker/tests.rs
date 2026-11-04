//! Durable worker identity, phase and recovery invariants.

use odin_domain::worker::WorkerPhase;
use time::macros::datetime;

use super::{register_worker, NewWorker, ScopeProof, Settlement};
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
    let scratch = tempfile::tempdir().unwrap();
    let path = scratch.path().join("worker.sqlite3");
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
}
