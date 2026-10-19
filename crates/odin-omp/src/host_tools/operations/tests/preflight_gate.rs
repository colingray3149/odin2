//! Readiness refusals must leave operation and approval rows untouched for every effect class.
//! Authorization is checked again after readiness probes complete.

use std::sync::atomic::Ordering;

use odin_domain::{ApprovalId, ApprovalStatus};
use odin_kernel::{ApprovalDecision, ApprovalGate, DecisionOutcome};
use serde_json::json;
use time::OffsetDateTime;

use crate::host_tools::operations::HostToolOperationError;

use super::fixture::{
    Fixture, DRAFT_HANDLER, DRAFT_TOOL, EVAL_HANDLER, EVAL_TOOL, EXEC_HANDLER, EXEC_TOOL, NOW_MS,
    READ_HANDLER, READ_TOOL, TOKEN_EXPIRES_MS,
};

fn seed_accepted_plan(fixture: &Fixture) {
    let run = fixture.scope.run.clone().expect("bound run");
    fixture.seed_bridge_run();
    let mut ledger = fixture.ledger.lock().expect("ledger lock");
    let plan = ledger
        .replace_plan(
            &run,
            "Exercise the shared preflight gate",
            &[odin_ledger::plan::TodoSpec {
                id: odin_domain::TodoId::new("todo:preflight-gate").expect("todo id"),
                title: "Exercise the shared preflight gate".to_owned(),
                status: odin_ledger::plan::TodoStatus::Pending,
            }],
            0,
            OffsetDateTime::UNIX_EPOCH,
        )
        .expect("fixture preflight plan");
    ledger
        .accept_plan(
            &run,
            plan.revision,
            "operator:fixture",
            OffsetDateTime::UNIX_EPOCH,
        )
        .expect("record fixture acceptance");
}

fn approve_minted(fixture: &Fixture, approval_id: &ApprovalId, revision: i64) {
    let mut ledger = fixture.ledger.lock().expect("ledger lock");
    let mut gate = ApprovalGate::new(&mut ledger);
    match gate
        .decide(
            approval_id,
            revision,
            ApprovalDecision::Approve {
                evidence_ref: Some("operator:preflight-fixture".to_owned()),
            },
            "operator:preflight-fixture",
            OffsetDateTime::UNIX_EPOCH + time::Duration::seconds(1),
        )
        .expect("decide the minted request")
    {
        DecisionOutcome::Approved(_) => {}
        other => panic!("unexpected approval outcome: {other:?}"),
    }
}

fn refusal_detail(error: &HostToolOperationError) -> String {
    match error {
        HostToolOperationError::Arguments { detail } => detail.clone(),
        other => panic!("expected the typed preflight refusal, got {other:?}"),
    }
}

#[test]
fn r0_preflight_refusal_neither_journals_nor_executes() {
    let fixture = Fixture::new();
    fixture.world.refuse_preflight(READ_HANDLER);

    let refused = fixture
        .dispatch_named(
            READ_TOOL,
            Some(fixture.resource.clone()),
            json!({"value": "alpha"}),
            "preflight-r0-refused",
        )
        .expect_err("the declared gate refuses the R0 dispatch typed");
    assert!(
        refusal_detail(&refused).contains("the execution prerequisite is missing"),
        "the refusal names the missing prerequisite: {refused:?}"
    );
    assert!(
        fixture.row("preflight-r0-refused").is_none(),
        "a refused dispatch never journals an operation row"
    );
    assert_eq!(
        fixture.world.effects.load(Ordering::SeqCst),
        0,
        "a refused dispatch never executes an effect"
    );
    assert!(
        fixture.world.calls().is_empty(),
        "a refused dispatch never reaches a handler or extractor"
    );

    fixture.world.allow_preflight(READ_HANDLER);
    let result = fixture
        .dispatch_named(
            READ_TOOL,
            Some(fixture.resource.clone()),
            json!({"value": "alpha"}),
            "preflight-r0-ready",
        )
        .expect("the ready R0 dispatch commits");
    assert_eq!(result["value"], "alpha");
    assert!(
        fixture.row("preflight-r0-ready").is_some(),
        "the ready dispatch journals its operation"
    );
    assert_eq!(
        fixture.world.effects.load(Ordering::SeqCst),
        1,
        "the ready dispatch executes exactly once"
    );
}

#[test]
fn r1_preflight_refusal_neither_journals_nor_executes() {
    let fixture = Fixture::for_eval();
    seed_accepted_plan(&fixture);
    fixture.world.refuse_preflight(EVAL_HANDLER);
    let eval_arguments = json!({
        "interpreter": "python",
        "source": "print('preflight')",
        "timeout_ms": 1_000,
        "max_stdout_bytes": 1_024,
        "max_stderr_bytes": 1_024
    });

    let refused = fixture
        .dispatch_named(
            EVAL_TOOL,
            Some(fixture.resource.clone()),
            eval_arguments.clone(),
            "preflight-r1-refused",
        )
        .expect_err("the declared gate refuses the R1 dispatch typed");
    assert!(
        refusal_detail(&refused).contains("the execution prerequisite is missing"),
        "the refusal names the missing prerequisite: {refused:?}"
    );
    assert!(fixture.row("preflight-r1-refused").is_none());
    assert_eq!(fixture.world.effects.load(Ordering::SeqCst), 0);
    assert!(fixture.world.calls().is_empty());

    fixture.world.allow_preflight(EVAL_HANDLER);
    fixture
        .dispatch_named(
            EVAL_TOOL,
            Some(fixture.resource.clone()),
            eval_arguments,
            "preflight-r1-ready",
        )
        .expect("the ready R1 dispatch commits");
    assert_eq!(
        fixture.world.effects.load(Ordering::SeqCst),
        1,
        "the ready R1 dispatch executes exactly once"
    );
}

#[test]
fn r2_preflight_refusal_neither_journals_nor_executes() {
    let fixture = Fixture::for_draft_r2();
    seed_accepted_plan(&fixture);
    fixture.world.refuse_preflight(DRAFT_HANDLER);

    let refused = fixture
        .dispatch_named(
            DRAFT_TOOL,
            Some(fixture.resource.clone()),
            json!({"value": "draft"}),
            "preflight-r2-refused",
        )
        .expect_err("the declared gate refuses the R2 dispatch typed");
    assert!(
        refusal_detail(&refused).contains("the execution prerequisite is missing"),
        "the refusal names the missing prerequisite: {refused:?}"
    );
    assert!(fixture.row("preflight-r2-refused").is_none());
    assert_eq!(fixture.world.effects.load(Ordering::SeqCst), 0);
    assert!(fixture.world.calls().is_empty());

    fixture.world.allow_preflight(DRAFT_HANDLER);
    fixture
        .dispatch_named(
            DRAFT_TOOL,
            Some(fixture.resource.clone()),
            json!({"value": "draft"}),
            "preflight-r2-ready",
        )
        .expect("the ready R2 dispatch commits");
    assert_eq!(
        fixture.world.effects.load(Ordering::SeqCst),
        1,
        "the ready R2 dispatch executes exactly once"
    );
}

#[test]
fn r3_preflight_refusal_never_mints_and_approved_retry_never_consumes() {
    let fixture = Fixture::new();
    seed_accepted_plan(&fixture);
    fixture.world.refuse_preflight(EXEC_HANDLER);

    // -- First R3 dispatch under a refused gate: the refusal lands BEFORE
    //    the approval gate, so no request row is minted, nothing is
    //    journaled, and no effect runs.
    let refused = fixture
        .dispatch_named(
            EXEC_TOOL,
            Some(fixture.resource.clone()),
            json!({"value": "go"}),
            "preflight-r3-refused",
        )
        .expect_err("the declared gate refuses the first R3 dispatch typed");
    assert!(
        refusal_detail(&refused).contains("the execution prerequisite is missing"),
        "the refusal names the missing prerequisite: {refused:?}"
    );
    assert!(fixture.row("preflight-r3-refused").is_none());
    {
        let ledger = fixture.ledger.lock().expect("ledger lock");
        assert!(
            ledger.approvals().expect("approval rows").is_empty(),
            "a refused first dispatch never mints an approval request"
        );
    }
    assert_eq!(fixture.world.effects.load(Ordering::SeqCst), 0);
    assert!(fixture.world.calls().is_empty());

    // -- Ready first dispatch: the gate mints the exact-scope request.
    fixture.world.allow_preflight(EXEC_HANDLER);
    let demanded = fixture
        .dispatch_named(
            EXEC_TOOL,
            Some(fixture.resource.clone()),
            json!({"value": "go"}),
            "preflight-r3-mint",
        )
        .expect_err("the ready first R3 dispatch demands approval");
    let (approval_id, revision) = match demanded {
        HostToolOperationError::ApprovalRequired {
            approval_id,
            revision,
            ..
        } => (approval_id, revision),
        other => panic!("expected an actionable approval demand, got {other:?}"),
    };
    approve_minted(&fixture, &approval_id, revision);

    // -- Owner-approved retry under the refused gate: the refusal lands
    //    BEFORE the gate can consume, so the approved row stays exactly
    //    Approved — never consumed — nothing journals, nothing runs.
    fixture.world.refuse_preflight(EXEC_HANDLER);
    let retry_arguments = json!({"value": "go", "approvalId": approval_id.as_str()});
    let refused_retry = fixture
        .dispatch_named(
            EXEC_TOOL,
            Some(fixture.resource.clone()),
            retry_arguments.clone(),
            "preflight-r3-retry-refused",
        )
        .expect_err("the declared gate refuses the approved retry typed");
    assert!(
        refusal_detail(&refused_retry).contains("the execution prerequisite is missing"),
        "the refusal names the missing prerequisite: {refused_retry:?}"
    );
    assert!(
        fixture.row("preflight-r3-retry-refused").is_none(),
        "a refused retry never journals an operation row"
    );
    {
        let ledger = fixture.ledger.lock().expect("ledger lock");
        let approval = ledger
            .approval(&approval_id)
            .expect("approval readable")
            .expect("the approved row exists");
        assert_eq!(
            approval.status,
            ApprovalStatus::Approved,
            "a refused retry never consumes the approved row"
        );
        assert!(
            approval.consumed_by_command_id.is_none(),
            "no consuming command was journaled"
        );
    }
    assert_eq!(fixture.world.effects.load(Ordering::SeqCst), 0);
    assert!(fixture.world.calls().is_empty());

    // -- Ready retry: the exact approved scope consumes exactly once and
    //    the effect executes exactly once.
    fixture.world.allow_preflight(EXEC_HANDLER);
    fixture
        .dispatch_named(
            EXEC_TOOL,
            Some(fixture.resource.clone()),
            retry_arguments.clone(),
            "preflight-r3-retry-ready",
        )
        .expect("the approved ready retry dispatches");
    assert_eq!(
        fixture.world.effects.load(Ordering::SeqCst),
        1,
        "the approved retry executes exactly once"
    );
    {
        let ledger = fixture.ledger.lock().expect("ledger lock");
        let approval = ledger
            .approval(&approval_id)
            .expect("approval readable")
            .expect("the consumed row exists");
        assert_eq!(approval.status, ApprovalStatus::Consumed);
        assert!(
            approval.consumed_by_command_id.is_some(),
            "exactly the journaled command consumed the row"
        );
    }

    // -- The spent row never revives: a further retry under the ready gate
    //    is refused by the approval gate itself, executes nothing, and the
    //    row stays consumed forever.
    let replay = fixture
        .dispatch_named(
            EXEC_TOOL,
            Some(fixture.resource.clone()),
            retry_arguments,
            "preflight-r3-retry-replay",
        )
        .expect_err("a consumed approval never authorizes again");
    assert!(
        matches!(
            replay,
            HostToolOperationError::Rejected(
                odin_kernel::AuthorizationRejection::NeedsApproval { .. }
            )
        ),
        "the spent row refuses as an approval demand, never revives: {replay:?}"
    );
    assert_eq!(
        fixture.world.effects.load(Ordering::SeqCst),
        1,
        "the replayed demand never executes"
    );
    {
        let ledger = fixture.ledger.lock().expect("ledger lock");
        let approval = ledger
            .approval(&approval_id)
            .expect("approval readable")
            .expect("the spent row exists");
        assert_eq!(
            approval.status,
            ApprovalStatus::Consumed,
            "the spent row stays consumed terminal"
        );
    }
}

#[test]
fn authority_expiring_during_readiness_preflight_refuses_before_the_journal() {
    let fixture = Fixture::for_draft_r2();
    seed_accepted_plan(&fixture);
    // The declared gate admits, but the readiness window advances the
    // clock past the provisioned token's expiry: admission observed the
    // authority live, and at the instant anything durable could run it is
    // dead. The dispatch must refuse at the re-verified instant — the
    // stale pre-preflight observation must never journal or execute under
    // a clock the kernel gate never re-read.
    fixture
        .world
        .schedule_preflight_clock_advance(TOKEN_EXPIRES_MS - NOW_MS + 1);

    let refused = fixture
        .dispatch_named(
            DRAFT_TOOL,
            Some(fixture.resource.clone()),
            json!({"value": "draft"}),
            "preflight-expired-mid-readiness",
        )
        .expect_err("an authority that expired during the readiness preflight refuses");
    assert!(
        matches!(refused, HostToolOperationError::Token(_)),
        "the refusal is the post-preflight re-verification failure, not the declared gate: \
         {refused:?}"
    );
    assert!(
        fixture.row("preflight-expired-mid-readiness").is_none(),
        "the stale-observation refusal lands before the operation journal"
    );
    assert_eq!(
        fixture.world.effects.load(Ordering::SeqCst),
        0,
        "a stale-observation refusal never executes"
    );
    assert!(
        fixture.world.calls().is_empty(),
        "the refusal never reaches a handler or extractor"
    );
}

#[test]
fn plan_changed_during_readiness_preflight_refuses_with_the_fresh_observation() {
    use std::sync::{Arc, Mutex};

    let fixture = Fixture::for_draft_r2();
    seed_accepted_plan(&fixture);
    // Inside the readiness window the operator replaces the run's plan:
    // the pre-preflight observation is an accepted revision-1 plan, but
    // the plan the dispatch would execute under is a different,
    // unaccepted aggregate. The dispatch must fail closed on the
    // RE-READ plan gate — never execute under the stale accepted plan.
    let run = fixture.scope.run.clone().expect("bound run");
    let ledger: Arc<Mutex<odin_ledger::Ledger>> = Arc::clone(&fixture.ledger);
    fixture.world.schedule_preflight_hook(move || {
        ledger
            .lock()
            .expect("ledger lock")
            .replace_plan(
                &run,
                "replaced mid-readiness",
                &[odin_ledger::plan::TodoSpec {
                    id: odin_domain::TodoId::new("todo:preflight-gate").expect("todo id"),
                    title: "replaced mid-readiness".to_owned(),
                    status: odin_ledger::plan::TodoStatus::Pending,
                }],
                1,
                OffsetDateTime::UNIX_EPOCH,
            )
            .expect("mid-readiness plan replacement");
    });

    let refused = fixture
        .dispatch_named(
            DRAFT_TOOL,
            Some(fixture.resource.clone()),
            json!({"value": "draft"}),
            "preflight-plan-changed-mid-readiness",
        )
        .expect_err("a plan changed during the readiness preflight refuses on the fresh gate");
    assert!(
        matches!(
            refused,
            HostToolOperationError::Rejected(odin_kernel::AuthorizationRejection::NeedsPlan { .. })
        ),
        "the fresh plan gate refuses the unaccepted plan: {refused:?}"
    );
    assert_eq!(
        fixture.world.effects.load(Ordering::SeqCst),
        0,
        "the stale-accepted plan never authorizes an effect"
    );
    assert!(
        fixture.world.calls().is_empty(),
        "the refusal never reaches a handler or extractor"
    );
    {
        let ledger = fixture.ledger.lock().expect("ledger lock");
        assert!(
            ledger.approvals().expect("approval rows").is_empty(),
            "a post-preflight gate refusal never mints or consumes an approval row"
        );
    }
}
