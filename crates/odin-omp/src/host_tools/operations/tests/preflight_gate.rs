//! Readiness refusals must leave operation and approval rows untouched for every effect class.
//! Authorization is checked again after readiness probes complete.

use std::sync::atomic::Ordering;

use odin_domain::ApprovalStatus;
use serde_json::json;

use crate::host_tools::approved_calls::ApprovedCallError;
use crate::host_tools::operations::HostToolOperationError;

use super::fixture::{
    Fixture, DRAFT_HANDLER, DRAFT_TOOL, EVAL_HANDLER, EVAL_TOOL, EXEC_HANDLER, EXEC_TOOL,
    READ_HANDLER, READ_TOOL,
};

fn refusal_detail(error: &HostToolOperationError) -> String {
    match error {
        HostToolOperationError::Arguments { detail } => detail.clone(),
        other => panic!("expected the typed preflight refusal, got {other:?}"),
    }
}

/// A refused readiness gate leaves no operation row and runs no effect for every effect
/// class below approval; the ready retry commits and executes exactly once.
#[test]
fn a_refused_readiness_gate_journals_nothing_and_the_ready_retry_runs_once() {
    let eval_arguments = json!({
        "interpreter": "python",
        "source": "print('preflight')",
        "timeout_ms": 1_000,
        "max_stdout_bytes": 1_024,
        "max_stderr_bytes": 1_024
    });
    for (label, fixture, handler, tool, arguments) in [
        (
            "R0",
            Fixture::new(),
            READ_HANDLER,
            READ_TOOL,
            json!({"value": "alpha"}),
        ),
        (
            "R1",
            Fixture::for_eval(),
            EVAL_HANDLER,
            EVAL_TOOL,
            eval_arguments,
        ),
        (
            "R2",
            Fixture::for_draft_r2(),
            DRAFT_HANDLER,
            DRAFT_TOOL,
            json!({"value": "draft"}),
        ),
    ] {
        if label != "R0" {
            fixture.accept_plan("Exercise the shared preflight gate");
        }
        fixture.world.refuse_preflight(handler);
        let refused = fixture
            .dispatch_named(
                tool,
                Some(fixture.resource.clone()),
                arguments.clone(),
                "preflight-refused",
            )
            .expect_err("the declared gate refuses the dispatch typed");
        let cause = refusal_detail(&refused);
        assert!(
            cause.contains("the execution prerequisite is missing"),
            "{label}: the refusal names the missing prerequisite: {refused:?}"
        );
        // The owner's yes that runs this call later hears the cause, not the error chain.
        assert_eq!(
            ApprovedCallError::Refused(refused).to_string(),
            "fixture declared gate: the execution prerequisite is missing",
            "{label}"
        );
        assert!(
            fixture.row("preflight-refused").is_none(),
            "{label}: a refused dispatch never journals an operation row"
        );
        assert_eq!(
            fixture.world.effects.load(Ordering::SeqCst),
            0,
            "{label}: a refused dispatch never executes an effect"
        );
        assert!(
            fixture.world.calls().is_empty(),
            "{label}: a refused dispatch never reaches a handler or extractor"
        );

        fixture.world.allow_preflight(handler);
        fixture
            .dispatch_named(
                tool,
                Some(fixture.resource.clone()),
                arguments,
                "preflight-ready",
            )
            .unwrap_or_else(|error| panic!("{label}: the ready dispatch commits: {error:?}"));
        assert!(
            fixture.row("preflight-ready").is_some(),
            "{label}: the ready dispatch journals its operation"
        );
        assert_eq!(
            fixture.world.effects.load(Ordering::SeqCst),
            1,
            "{label}: the ready dispatch executes exactly once"
        );
    }
}

#[test]
fn r3_preflight_refusal_never_mints_and_approved_retry_never_consumes() {
    let fixture = Fixture::new();
    fixture.accept_plan("Exercise the shared preflight gate");
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
    fixture.approve(&approval_id, revision);

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
