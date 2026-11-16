//! Root-plan consent through the durable owner delivery and decision path.

use std::sync::Arc;

use odin_domain::{ApprovalId, ApprovalStatus, LaneId, ProjectId, RunId, SeatId, SessionId};
use odin_hermes::natural::OwnerDecision;
use odin_hermes::runtime::{AuthenticatedOwnerMessage, HermesRuntime};
use odin_ledger::lane_run::{create_run, NewRun};
use odin_ledger::plan::{TodoSpec, TodoStatus};
use odin_ledger::Ledger;
use parking_lot::Mutex;

use super::fixtures::{
    gate_runtime_with_adapter, now, RecordingNotifySink, INTENT_DM_CHANNEL, INTENT_OWNER,
};
use super::gate::create_vehicle;

const OBJECTIVE: &str = "Investigate the incident and report the findings";

fn setup(
    dir: &std::path::Path,
) -> (
    Arc<Mutex<Ledger>>,
    Arc<HermesRuntime>,
    Arc<RecordingNotifySink>,
    RunId,
    ApprovalId,
) {
    let ledger = Arc::new(Mutex::new(
        Ledger::open(dir.join("root-consent.sqlite3")).unwrap(),
    ));
    let session = SessionId::new("test-vehicle").unwrap();
    let run = RunId::new("run:live:test-vehicle").unwrap();
    let id = {
        let mut guard = ledger.lock();
        create_vehicle(&mut guard, session.as_str(), now());
        create_run(
            guard.connection(),
            &NewRun {
                run_id: run.clone(),
                lane_id: LaneId::new("sinmara-life").unwrap(),
                attempt_number: 1,
                workflow_id: None,
                workflow_version: None,
                input_hash: "fixture".to_owned(),
                accepted_capability_revision: None,
                lease_id: None,
                absolute_deadline: None,
                retry_budget: 0,
                created_at: now(),
            },
        )
        .unwrap();
        let todos = [
            TodoSpec {
                id: "inspect".parse().unwrap(),
                title: "Inspect logs".to_owned(),
                status: TodoStatus::Pending,
            },
            TodoSpec {
                id: "report".parse().unwrap(),
                title: "Report findings".to_owned(),
                status: TodoStatus::Pending,
            },
        ];
        let plan = guard
            .replace_plan(&run, OBJECTIVE, &todos, 0, now())
            .unwrap();
        guard
            .request_root_plan_consent(&run, &session, "sinmara", plan.revision, OBJECTIVE, now())
            .unwrap()
    };
    let runtime = gate_runtime_with_adapter(dir, ledger.clone());
    let sink = Arc::new(RecordingNotifySink::default());
    runtime.bind_notify_sink(sink.clone()).unwrap();
    (ledger, runtime, sink, run, id)
}

fn message(offset: u64) -> AuthenticatedOwnerMessage {
    AuthenticatedOwnerMessage {
        owner_user_id: INTENT_OWNER.to_owned(),
        channel_id: INTENT_DM_CHANNEL.to_owned(),
        message_id: RecordingNotifySink::message_id(offset),
        seat: SeatId::new("sinmara").unwrap(),
        project: ProjectId::new("home").unwrap(),
        content: "yes".to_owned(),
    }
}

#[test]
fn idle_pump_delivers_exact_plan_and_one_yes_survives_restart() {
    let dir = tempfile::tempdir().unwrap();
    let (ledger, runtime, sink, run, id) = setup(dir.path());
    assert!(!ledger.lock().plan_is_accepted(&run).unwrap());
    runtime.pump_status_egress(8).unwrap();
    let card = sink.calls.lock().join("\n");
    assert!(card.contains(OBJECTIVE), "{card}");
    assert!(card.contains(run.as_str()), "{card}");
    assert!(card.contains("Plan revision: 1"), "{card}");
    assert!(card.contains("Session: test-vehicle"), "{card}");
    assert!(card.contains("Seat: sinmara"), "{card}");
    let first = card.find("Inspect logs").expect("first todo in preview");
    let second = card
        .find("Report findings")
        .expect("second todo in preview");
    assert!(first < second, "todos must retain their plan order: {card}");
    assert!(
        card.contains("inspect") && card.contains("report") && card.contains("Pending"),
        "{card}"
    );
    let pending = runtime
        .delivered_pending_approvals(&ledger, INTENT_DM_CHANNEL, INTENT_OWNER, now())
        .unwrap();
    assert_eq!(pending.len(), 1);
    assert!(matches!(
        runtime.delivered_pending_approvals(&ledger, "unpaired-channel", INTENT_OWNER, now()),
        Err(odin_hermes::runtime::DecisionRefusal::NotAuthenticated)
    ));
    assert_eq!(pending[0].approval_id, id);
    let revision = pending[0].revision;
    let result = runtime
        .decide_delivered_approval(
            &ledger,
            &message(100),
            &id,
            revision,
            OwnerDecision::AllowOnce,
            now(),
        )
        .unwrap();
    assert!(matches!(result, odin_kernel::DecisionOutcome::Approved(_)));
    assert!(ledger.lock().plan_is_accepted(&run).unwrap());
    assert!(
        ledger
            .lock()
            .root_plan_consent(&id)
            .unwrap()
            .unwrap()
            .applied
    );
    assert!(runtime
        .decide_delivered_approval(
            &ledger,
            &message(100),
            &id,
            revision,
            OwnerDecision::AllowOnce,
            now()
        )
        .is_err());
    drop(runtime);
    drop(ledger);
    let reopened = Arc::new(Mutex::new(
        Ledger::open(dir.path().join("root-consent.sqlite3")).unwrap(),
    ));
    assert!(reopened.lock().plan_is_accepted(&run).unwrap());
    assert!(
        reopened
            .lock()
            .root_plan_consent(&id)
            .unwrap()
            .unwrap()
            .applied
    );
    let restarted = gate_runtime_with_adapter(dir.path(), reopened.clone());
    let next_sink = Arc::new(RecordingNotifySink::default());
    restarted.bind_notify_sink(next_sink.clone()).unwrap();
    restarted.pump_status_egress(8).unwrap();
    assert!(
        next_sink.calls.lock().is_empty(),
        "settled consent must not be asked again"
    );
}

#[test]
fn wrong_owner_and_revision_cannot_accept_the_delivered_plan() {
    let dir = tempfile::tempdir().unwrap();
    let (ledger, runtime, _sink, run, id) = setup(dir.path());
    runtime.pump_status_egress(8).unwrap();
    let pending = runtime
        .delivered_pending_approvals(&ledger, INTENT_DM_CHANNEL, INTENT_OWNER, now())
        .unwrap();
    let revision = pending[0].revision;
    let mut stranger = message(100);
    stranger.owner_user_id = "100000000000000099".to_owned();
    assert!(runtime
        .decide_delivered_approval(
            &ledger,
            &stranger,
            &id,
            revision,
            OwnerDecision::AllowOnce,
            now()
        )
        .is_err());
    assert!(matches!(
        runtime.decide_delivered_approval(
            &ledger,
            &message(101),
            &id,
            revision + 1,
            OwnerDecision::AllowOnce,
            now()
        ),
        Ok(odin_kernel::DecisionOutcome::Redirect(_))
    ));
    let guard = ledger.lock();
    assert!(!guard.plan_is_accepted(&run).unwrap());
    assert_eq!(
        guard.approval(&id).unwrap().unwrap().status,
        ApprovalStatus::Requested
    );
}

#[test]
fn changed_plan_rolls_back_decision_and_intake_together() {
    let dir = tempfile::tempdir().unwrap();
    let (ledger, runtime, _sink, run, id) = setup(dir.path());
    runtime.pump_status_egress(8).unwrap();
    let pending = runtime
        .delivered_pending_approvals(&ledger, INTENT_DM_CHANNEL, INTENT_OWNER, now())
        .unwrap();
    let revision = pending[0].revision;
    ledger
        .lock()
        .replace_plan(&run, "A different objective", &[], 1, now())
        .unwrap();
    assert!(runtime
        .decide_delivered_approval(
            &ledger,
            &message(100),
            &id,
            revision,
            OwnerDecision::AllowOnce,
            now()
        )
        .is_err());
    let guard = ledger.lock();
    assert!(!guard.plan_is_accepted(&run).unwrap());
    let approval = guard.approval(&id).unwrap().unwrap();
    assert_eq!(approval.status, ApprovalStatus::Requested);
    assert!(!guard.approval_has_owner_decision(&approval, true).unwrap());
    assert!(!guard.root_plan_consent(&id).unwrap().unwrap().applied);
    drop(guard);
    let replacement = ledger
        .lock()
        .request_root_plan_consent(
            &run,
            &SessionId::new("test-vehicle").unwrap(),
            "sinmara",
            2,
            "A different objective",
            now(),
        )
        .unwrap();
    runtime.pump_status_egress(8).unwrap();
    let replacement_revision = ledger
        .lock()
        .approval(&replacement)
        .unwrap()
        .unwrap()
        .revision;
    let result = runtime
        .decide_delivered_approval(
            &ledger,
            &message(100),
            &replacement,
            replacement_revision,
            OwnerDecision::AllowOnce,
            now(),
        )
        .unwrap();
    assert!(
        matches!(result, odin_kernel::DecisionOutcome::Approved(_)),
        "failed settlement must not consume the message"
    );
    assert!(ledger.lock().plan_is_accepted(&run).unwrap());
}
