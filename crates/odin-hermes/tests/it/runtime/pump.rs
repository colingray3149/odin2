//! Gate runtime mechanics: receipt commits without sends, durable vehicle bindings, unauthenticated refusals, restart recovery, post-approval gating.

use crate::runtime::fixtures::{
    discord_runtime, gate_runtime, intent_task_id, now, owner_dm, request_gate_approval, FakeRoute,
    RecordingNotifySink, INTENT_DM_CHANNEL,
};
use odin_domain::{ProjectId, SeatId};
use odin_ledger::Ledger;
use parking_lot::Mutex;
use std::sync::Arc;

#[test]
fn pump_commits_receipts_without_sends_and_notify_still_delivers() {
    let dir = tempfile::tempdir().unwrap();
    let runtime = gate_runtime(dir.path());
    let sink = Arc::new(RecordingNotifySink::default());
    runtime.bind_notify_sink(sink.clone()).unwrap();

    // Drive a real receipt through the intake path.
    let projection = runtime
        .admit_message(&owner_dm("1000000000000000110", "Hello"))
        .unwrap();
    assert_eq!(projection["status"], "queued", "projection: {projection}");

    // The pump commits the receipt without a send.
    let committed = runtime.pump_status_egress(8).unwrap();
    assert!(committed >= 1, "the receipt must be committed: {committed}");
    assert_eq!(projection["status"], "queued");
    assert!(
        sink.calls.lock().is_empty(),
        "no lifecycle receipt may reach the sink: {:?}",
        sink.calls.lock()
    );

    // The explicit notify seam still delivers the assistant's own words.
    runtime.notify("Here is your answer.").unwrap();
    assert_eq!(sink.calls.lock().len(), 1);
    assert_eq!(sink.calls.lock()[0], "Here is your answer.");
}
/// A message that is not the paired owner's in the paired conversation is
/// refused before any approval is even looked at.
#[test]
fn decisions_refuse_unauthenticated_contexts() {
    let dir = tempfile::tempdir().unwrap();
    let runtime = gate_runtime(dir.path());
    let ledger = Arc::new(Mutex::new(
        Ledger::open(dir.path().join("approvals.sqlite3")).unwrap(),
    ));
    let (approval_id, revision) = request_gate_approval(&mut ledger.lock(), "three", now());
    let stranger = odin_hermes::runtime::AuthenticatedOwnerMessage {
        owner_user_id: "999999999999999999".to_owned(),
        channel_id: INTENT_DM_CHANNEL.to_owned(),
        message_id: "1000000000000000103".to_owned(),
        seat: SeatId::new("sinmara").unwrap(),
        project: ProjectId::new("home").unwrap(),
        content: "yes".to_owned(),
    };
    let outcome = runtime.decide_delivered_approval(
        &ledger,
        &stranger,
        &approval_id,
        revision,
        odin_hermes::natural::OwnerDecision::AllowOnce,
        now(),
    );
    assert!(matches!(
        outcome,
        Err(odin_hermes::runtime::DecisionRefusal::NotAuthenticated)
    ));
}
#[test]
fn restart_rebuilds_the_admitted_queue_from_the_durable_rows_alone() {
    let dir = tempfile::tempdir().unwrap();
    let ledger_path = dir.path().join("state").join("intents.sqlite3");
    std::fs::create_dir_all(dir.path().join("state")).unwrap();
    let projection = {
        let runtime = discord_runtime(
            dir.path(),
            Ledger::open(&ledger_path).unwrap(),
            odin_domain::EffectClass::R1,
        );
        // No route bound and no reconcile: the process "crashes" right
        // after admission, losing the in-memory queue.
        runtime
            .admit_message(&owner_dm("1000000000000000040", "Hello"))
            .unwrap()
    };
    assert_eq!(projection["status"], "queued");

    let runtime = discord_runtime(
        dir.path(),
        Ledger::open(&ledger_path).unwrap(),
        odin_domain::EffectClass::R1,
    );
    let route = FakeRoute::answering();
    runtime.set_approved_intent_route(route.clone());
    assert_eq!(runtime.reconcile_admitted_intents().unwrap(), 1);
    assert_eq!(route.count(), 1, "the durable row re-drove the intent");
    assert_eq!(route.sole_execution().content, "Hello");
    let row = runtime
        .store()
        .task(&intent_task_id(&projection))
        .unwrap()
        .unwrap();
    assert_eq!(
        row.terminal_status,
        Some(odin_ledger::command::CommandTerminalStatus::Completed)
    );
}
