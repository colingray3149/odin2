//! Approval scope, validation ordering, consumption, and replay tests for R3 and operator-gated R2 calls.

use std::sync::atomic::Ordering;

use odin_domain::{ApprovalId, ApprovalStatus, CapabilityId, CommandId, EffectClass};
use odin_kernel::{
    arguments_digest, ApprovalDecision, ApprovalGate, AuthorizationRejection, DecisionOutcome,
};
use serde_json::{json, Value};
use time::OffsetDateTime;

use crate::host_tools::operations::{
    correlation_for, HostToolOperationError, SessionOperationContext,
};

use super::fixture::{
    Fixture, BROWSER_CONSEQUENTIAL_TOOL, DRAFT_CAPABILITY, DRAFT_HANDLER, DRAFT_TOOL,
    EXEC_CAPABILITY, EXEC_EXTRACTOR, EXEC_HANDLER, EXEC_TOOL, SEAT_ASK_HANDLER, SEAT_ASK_TOOL,
};

/// Requests one exact-scope approval for the dispatched arguments and
/// decides it. `arguments` must already carry the `approvalId` the host
/// dispatch will present, because the consumed scope digests the complete
/// invocation arguments.
fn settle_fixture_approval(
    fixture: &Fixture,
    approval_key: &str,
    arguments: &Value,
    decision: ApprovalDecision,
) -> ApprovalId {
    let approval_id = ApprovalId::new(approval_key).expect("approval id");
    let scope = odin_kernel::ApprovalScope {
        target_kind: "run".to_owned(),
        target_id: fixture
            .scope
            .run
            .as_ref()
            .expect("bound run")
            .as_str()
            .to_owned(),
        capability_id: CapabilityId::new(EXEC_CAPABILITY).expect("capability id"),
        arguments_digest: arguments_digest(arguments),
    };
    let mut ledger = fixture.ledger.lock().expect("ledger lock");
    let mut gate = ApprovalGate::new(&mut ledger);
    let requested = gate
        .request(odin_kernel::NewApproval {
            approval_id: approval_id.clone(),
            issuer: "fixture-requester".to_owned(),
            scope,
            requested_at: OffsetDateTime::UNIX_EPOCH,
            expires_at: OffsetDateTime::UNIX_EPOCH + time::Duration::hours(1),
        })
        .expect("request approval");
    match gate
        .decide(
            &approval_id,
            requested.revision,
            decision,
            "fixture-operator",
            OffsetDateTime::UNIX_EPOCH + time::Duration::seconds(1),
        )
        .expect("decide approval")
    {
        DecisionOutcome::Approved(_) | DecisionOutcome::Denied(_) => approval_id,
        other => panic!("unexpected approval outcome: {other:?}"),
    }
}

#[test]
fn r3_dispatch_proves_one_consumed_command_and_refuses_replay_scope_and_denial() {
    let fixture = Fixture::new();
    let run = fixture.scope.run.clone().expect("bound run");
    fixture.seed_bridge_run();
    {
        let mut ledger = fixture.ledger.lock().expect("ledger lock");
        let plan = ledger
            .replace_plan(
                &run,
                "Approve one governed R3 dispatch",
                &[odin_ledger::plan::TodoSpec {
                    id: odin_domain::TodoId::new("todo:r3-proof").expect("todo id"),
                    title: "Approve one governed R3 dispatch".to_owned(),
                    status: odin_ledger::plan::TodoStatus::Pending,
                }],
                0,
                OffsetDateTime::UNIX_EPOCH,
            )
            .expect("fixture r3 plan");
        ledger
            .accept_plan(
                &run,
                plan.revision,
                "operator:fixture",
                OffsetDateTime::UNIX_EPOCH,
            )
            .expect("record fixture acceptance");
    }

    // -- A denied approval dispatches nothing.
    settle_fixture_approval(
        &fixture,
        "approval:r3-denied",
        &json!({"value": "denied", "approvalId": "approval:r3-denied"}),
        ApprovalDecision::Deny {
            evidence_ref: "operator:fixture-refusal".to_owned(),
        },
    );
    let denial = fixture
        .dispatch_named(
            EXEC_TOOL,
            Some(fixture.resource.clone()),
            json!({"value": "denied", "approvalId": "approval:r3-denied"}),
            "request-denied",
        )
        .expect_err("a denied approval refuses the dispatch");
    assert!(matches!(
        denial,
        HostToolOperationError::Rejected(AuthorizationRejection::NeedsApproval { .. })
    ));
    assert!(
        fixture.world.calls().is_empty(),
        "a denial never reaches a handler or extractor"
    );
    assert_eq!(fixture.world.effects.load(Ordering::SeqCst), 0);
    assert!(fixture.world.proofs.lock().expect("proof lock").is_empty());
    assert!(
        fixture.row("request-denied").is_none(),
        "an unauthorized dispatch never prepares an operation"
    );
    let denied_id = ApprovalId::new("approval:r3-denied").expect("approval id");
    {
        let ledger = fixture.ledger.lock().expect("ledger lock");
        let approval = ledger
            .approval(&denied_id)
            .expect("approval readable")
            .expect("denied approval record");
        assert_eq!(approval.status, ApprovalStatus::Denied);
    }

    // -- An approved scope covers exactly its arguments: different
    //    arguments under the same approval are refused and the approval
    //    stays unconsumed.
    settle_fixture_approval(
        &fixture,
        "approval:r3-scope",
        &json!({"value": "expected", "approvalId": "approval:r3-scope"}),
        ApprovalDecision::Approve {
            evidence_ref: Some("operator:fixture".to_owned()),
        },
    );
    let mismatch = fixture
        .dispatch_named(
            EXEC_TOOL,
            Some(fixture.resource.clone()),
            json!({"value": "changed", "approvalId": "approval:r3-scope"}),
            "request-mismatch",
        )
        .expect_err("an approval never covers different arguments");
    assert!(matches!(
        mismatch,
        HostToolOperationError::Rejected(AuthorizationRejection::NeedsApproval { .. })
    ));
    assert_eq!(fixture.world.effects.load(Ordering::SeqCst), 0);
    let scope_id = ApprovalId::new("approval:r3-scope").expect("approval id");
    {
        let ledger = fixture.ledger.lock().expect("ledger lock");
        let approval = ledger
            .approval(&scope_id)
            .expect("approval readable")
            .expect("scope approval record");
        assert_eq!(
            approval.status,
            ApprovalStatus::Approved,
            "a scope mismatch never consumes the approval"
        );
    }

    // -- The once-approved exact request dispatches exactly once, and the
    //    bound adapter receives the actual consumed host command as proof.
    let approved_arguments = json!({"value": "go", "approvalId": "approval:r3-go"});
    let approved_id = settle_fixture_approval(
        &fixture,
        "approval:r3-go",
        &approved_arguments,
        ApprovalDecision::Approve {
            evidence_ref: Some("operator:fixture".to_owned()),
        },
    );
    let result = fixture
        .dispatch_named(
            EXEC_TOOL,
            Some(fixture.resource.clone()),
            approved_arguments.clone(),
            "request-go",
        )
        .expect("the once-approved exact request dispatches");
    assert_eq!(result["handledBy"], EXEC_HANDLER);
    assert_eq!(fixture.world.calls(), vec![EXEC_HANDLER, EXEC_EXTRACTOR]);
    assert_eq!(fixture.world.effects.load(Ordering::SeqCst), 1);

    // Consumption must identify the journaled command and its dispatched scope.
    let correlation = correlation_for(&fixture.session, "request-go").expect("correlation");
    let consumed_command_id =
        CommandId::new(format!("odin.omp.host_tool:{correlation}")).expect("command id");
    {
        let ledger = fixture.ledger.lock().expect("ledger lock");
        let approval = ledger
            .approval(&approved_id)
            .expect("approval readable")
            .expect("consumed approval record");
        assert_eq!(approval.status, ApprovalStatus::Consumed);
        assert_eq!(
            approval.consumed_by_command_id.as_ref(),
            Some(&consumed_command_id),
            "the durable approval names exactly the host command the dispatch journaled"
        );
        assert_eq!(approval.scope.capability_id.as_str(), EXEC_CAPABILITY);
        assert_eq!(approval.scope.target_kind, "run");
        assert_eq!(approval.scope.target_id, run.as_str());
        assert_eq!(
            approval.scope.arguments_digest,
            arguments_digest(&approved_arguments)
        );
    }

    // The hook delivered the identical proof to both bound calls: the same
    // journaled command, capability, version, target, and full arguments.
    let expected_proof = format!(
        "odin.omp.host_tool:{correlation}|{EXEC_CAPABILITY}|1|run|{}|{approved_arguments}",
        run.as_str()
    );
    let proofs = fixture.world.proofs.lock().expect("proof lock").clone();
    assert_eq!(
        proofs,
        vec![expected_proof.clone(), expected_proof],
        "handler and extractor receive the identical consumed-command proof"
    );

    // A replay neither repeats the effect nor rebinds the consumed approval.
    fixture
        .dispatch_named(
            EXEC_TOOL,
            Some(fixture.resource.clone()),
            json!({"value": "go", "approvalId": "approval:r3-go"}),
            "request-go",
        )
        .expect_err("a consumed approval cannot dispatch again");
    assert_eq!(fixture.world.calls(), vec![EXEC_HANDLER, EXEC_EXTRACTOR]);
    assert_eq!(fixture.world.effects.load(Ordering::SeqCst), 1);
    assert_eq!(fixture.world.proofs.lock().expect("proof lock").len(), 2);
    {
        let ledger = fixture.ledger.lock().expect("ledger lock");
        let approval = ledger
            .approval(&approved_id)
            .expect("approval readable")
            .expect("consumed approval record");
        assert_eq!(
            approval.consumed_by_command_id.as_ref(),
            Some(&consumed_command_id),
            "the replay never rebinds the approval to another command"
        );
    }
}
/// The governed approval lifecycle for a first R3 dispatch: the gate's
/// refusal must not dead-end. The bridge mints the durable exact-scope
/// request (issuer = dispatching seat, scope = the retry arguments'
/// digest), the owner decides it through the ledger gate, and the retried
/// call presenting `approvalId` dispatches exactly once — the second
/// presentation is refused and a repeat first dispatch rolls to a fresh
/// request instead of resurrecting the consumed row.
#[test]
fn r3_first_dispatch_mints_durable_request_then_retry_consumes_once() {
    let fixture = Fixture::new();
    let run = fixture.scope.run.clone().expect("bound run");
    fixture.seed_bridge_run();
    {
        let mut ledger = fixture.ledger.lock().expect("ledger lock");
        let plan = ledger
            .replace_plan(
                &run,
                "Approve one governed R3 dispatch",
                &[odin_ledger::plan::TodoSpec {
                    id: odin_domain::TodoId::new("todo:r3-mint").expect("todo id"),
                    title: "Approve one governed R3 dispatch".to_owned(),
                    status: odin_ledger::plan::TodoStatus::Pending,
                }],
                0,
                OffsetDateTime::UNIX_EPOCH,
            )
            .expect("fixture r3 plan");
        ledger
            .accept_plan(
                &run,
                plan.revision,
                "operator:fixture",
                OffsetDateTime::UNIX_EPOCH,
            )
            .expect("record fixture acceptance");
    }

    // -- First dispatch without an approval: typed refusal plus a durable
    //    exact-scope request, and nothing executed.
    let refusal = fixture
        .dispatch_named(
            EXEC_TOOL,
            Some(fixture.resource.clone()),
            json!({"value": "go"}),
            "request-mint",
        )
        .expect_err("a first R3 dispatch without approval is refused");
    let HostToolOperationError::ApprovalRequired {
        capability_id,
        effect_class: _,
        approval_id,
        revision,
    } = &refusal
    else {
        panic!("expected an actionable approval refusal, got {refusal:?}");
    };
    assert_eq!(capability_id.as_str(), EXEC_CAPABILITY);
    assert_eq!(*revision, 1, "a fresh request starts at revision one");
    assert!(
        fixture.world.calls().is_empty(),
        "the refused dispatch never reached a handler"
    );
    assert_eq!(fixture.world.effects.load(Ordering::SeqCst), 0);
    let mut retry_arguments = json!({"value": "go"});
    retry_arguments["approvalId"] = json!(approval_id.to_string());
    {
        let ledger = fixture.ledger.lock().expect("ledger lock");
        let approval = ledger
            .approval(approval_id)
            .expect("approval readable")
            .expect("the refusal minted a durable request");
        assert_eq!(approval.status, ApprovalStatus::Requested);
        assert_eq!(
            approval.issuer,
            fixture.scope.seat.as_ref().expect("seat").as_str(),
            "the issuer is the dispatching seat, the caller"
        );
        assert_eq!(approval.scope.target_kind, "run");
        assert_eq!(approval.scope.target_id, run.as_str());
        assert_eq!(approval.scope.capability_id.as_str(), EXEC_CAPABILITY);
        assert_eq!(
            approval.scope.arguments_digest,
            arguments_digest(&retry_arguments),
            "the request binds the exact retry arguments, approvalId included"
        );
    }

    // -- The owner decides through the same ledger gate the CLI uses.
    {
        let mut ledger = fixture.ledger.lock().expect("ledger lock");
        let mut gate = ApprovalGate::new(&mut ledger);
        match gate
            .decide(
                approval_id,
                *revision,
                ApprovalDecision::Approve {
                    evidence_ref: Some("operator:fixture".to_owned()),
                },
                "fixture-operator",
                OffsetDateTime::now_utc(),
            )
            .expect("owner decision settles")
        {
            DecisionOutcome::Approved(decided) => {
                assert_eq!(decided.revision, 2, "the decision records a proof revision");
            }
            other => panic!("unexpected decision outcome: {other:?}"),
        }
    }

    // -- The retry presenting the approvalId dispatches exactly once.
    let result = fixture
        .dispatch_named(
            EXEC_TOOL,
            Some(fixture.resource.clone()),
            retry_arguments.clone(),
            "request-consume",
        )
        .expect("the decided approval admits the identical retry");
    assert_eq!(result["handledBy"], EXEC_HANDLER);
    assert_eq!(fixture.world.effects.load(Ordering::SeqCst), 1);
    let correlation = correlation_for(&fixture.session, "request-consume").expect("correlation");
    let consumed_command_id =
        CommandId::new(format!("odin.omp.host_tool:{correlation}")).expect("command id");
    {
        let ledger = fixture.ledger.lock().expect("ledger lock");
        let approval = ledger
            .approval(approval_id)
            .expect("approval readable")
            .expect("consumed approval record");
        assert_eq!(approval.status, ApprovalStatus::Consumed);
        assert_eq!(
            approval.consumed_by_command_id.as_ref(),
            Some(&consumed_command_id),
            "the consumption names exactly the retried command"
        );
    }

    // -- The approval is one-shot: presenting it again is refused and
    //    nothing re-executes.
    let replay = fixture
        .dispatch_named(
            EXEC_TOOL,
            Some(fixture.resource.clone()),
            retry_arguments.clone(),
            "request-replay",
        )
        .expect_err("a consumed approval cannot dispatch again");
    assert!(matches!(
        replay,
        HostToolOperationError::Rejected(AuthorizationRejection::NeedsApproval { .. })
    ));
    assert_eq!(fixture.world.effects.load(Ordering::SeqCst), 1);

    // -- A repeat FIRST dispatch (no approvalId) rolls to a fresh request
    //    instead of resurrecting the consumed row.
    let repeat = fixture
        .dispatch_named(
            EXEC_TOOL,
            Some(fixture.resource.clone()),
            json!({"value": "go"}),
            "request-mint-2",
        )
        .expect_err("a repeat first dispatch is still gated");
    let HostToolOperationError::ApprovalRequired {
        approval_id: rolled_id,
        revision: rolled_revision,
        ..
    } = &repeat
    else {
        panic!("expected an actionable approval refusal, got {repeat:?}");
    };
    assert_ne!(
        rolled_id, approval_id,
        "a terminal row rolls to a fresh request identity"
    );
    assert_eq!(*rolled_revision, 1);
    {
        let ledger = fixture.ledger.lock().expect("ledger lock");
        let rolled = ledger
            .approval(rolled_id)
            .expect("approval readable")
            .expect("the rolled request exists");
        assert_eq!(rolled.status, ApprovalStatus::Requested);
    }
    assert_eq!(
        fixture.world.effects.load(Ordering::SeqCst),
        1,
        "nothing else ever executed"
    );
}
/// An identical retry binds the decided approval for its exact scope — with
/// a mistyped id or none at all — and still executes exactly once.
#[test]
fn an_identical_retry_binds_the_decided_approval_without_echoing_its_id() {
    let fixture = Fixture::new();
    let run = fixture.scope.run.clone().expect("bound run");
    fixture.seed_bridge_run();
    {
        let mut ledger = fixture.ledger.lock().expect("ledger lock");
        let plan = ledger
            .replace_plan(
                &run,
                "Approve governed R3 dispatches",
                &[odin_ledger::plan::TodoSpec {
                    id: odin_domain::TodoId::new("todo:r3-adopt").expect("todo id"),
                    title: "Approve governed R3 dispatches".to_owned(),
                    status: odin_ledger::plan::TodoStatus::Pending,
                }],
                0,
                OffsetDateTime::UNIX_EPOCH,
            )
            .expect("fixture r3 plan");
        ledger
            .accept_plan(
                &run,
                plan.revision,
                "operator:fixture",
                OffsetDateTime::UNIX_EPOCH,
            )
            .expect("record fixture acceptance");
    }
    let approve = |approval_id: &ApprovalId, revision: i64| {
        let mut ledger = fixture.ledger.lock().expect("ledger lock");
        ApprovalGate::new(&mut ledger)
            .decide(
                approval_id,
                revision,
                ApprovalDecision::Approve {
                    evidence_ref: Some("operator:fixture".to_owned()),
                },
                "fixture-operator",
                OffsetDateTime::now_utc(),
            )
            .expect("owner decision settles");
    };
    let first_demand = |value: &str, request: &str| match fixture
        .dispatch_named(
            EXEC_TOOL,
            Some(fixture.resource.clone()),
            json!({"value": value}),
            request,
        )
        .expect_err("a first R3 dispatch is refused")
    {
        HostToolOperationError::ApprovalRequired {
            approval_id,
            revision,
            ..
        } => (approval_id, revision),
        other => panic!("expected an approval request, got {other:?}"),
    };

    // A mistyped id: one hex digit changed.
    let (approval_id, revision) = first_demand("go", "adopt-mint-1");
    approve(&approval_id, revision);
    let mut typo = approval_id.to_string();
    let last = typo.pop().expect("hex id");
    typo.push(if last == '0' { '1' } else { '0' });
    fixture
        .dispatch_named(
            EXEC_TOOL,
            Some(fixture.resource.clone()),
            json!({"value": "go", "approvalId": typo}),
            "adopt-typo",
        )
        .expect("the decided approval admits the identical retry");
    assert_eq!(fixture.world.effects.load(Ordering::SeqCst), 1);

    // No id at all: the identical call re-issued.
    let (approval_id, revision) = first_demand("again", "adopt-mint-2");
    approve(&approval_id, revision);
    fixture
        .dispatch_named(
            EXEC_TOOL,
            Some(fixture.resource.clone()),
            json!({"value": "again"}),
            "adopt-bare",
        )
        .expect("the decided approval admits the identical retry");
    assert_eq!(fixture.world.effects.load(Ordering::SeqCst), 2);
    let ledger = fixture.ledger.lock().expect("ledger lock");
    assert_eq!(
        ledger
            .approval(&approval_id)
            .expect("readable")
            .expect("row")
            .status,
        ApprovalStatus::Consumed,
        "consumed exactly once"
    );
}

/// Seat asks omit `options` when none were offered; the canonical schema must accept that retry.
#[test]
fn r3_seat_ask_retry_with_the_live_generated_shape_completes_the_lifecycle() {
    let fixture = Fixture::for_seat_ask();
    let run = fixture.scope.run.clone().expect("bound run");
    fixture.seed_bridge_run();
    {
        let mut ledger = fixture.ledger.lock().expect("ledger lock");
        let plan = ledger
            .replace_plan(
                &run,
                "Approve one governed cluster-health ask",
                &[odin_ledger::plan::TodoSpec {
                    id: odin_domain::TodoId::new("todo:seat-ask-live").expect("todo id"),
                    title: "Approve one governed cluster-health ask".to_owned(),
                    status: odin_ledger::plan::TodoStatus::Pending,
                }],
                0,
                OffsetDateTime::UNIX_EPOCH,
            )
            .expect("fixture seat ask plan");
        ledger
            .accept_plan(
                &run,
                plan.revision,
                "operator:fixture",
                OffsetDateTime::UNIX_EPOCH,
            )
            .expect("record fixture acceptance");
    }

    let first = json!({
        "project": "odin",
        "question": "Perform a read-only health check of the configured cluster. Inspect node readiness and pressure, workload availability, unhealthy or pending pods, crash loops and restarts, and recent warning events. Report concrete problems with affected resources, severity, and supporting command output; distinguish active failures from historical/transient events. Do not modify resources or remediate. If access or configuration is unavailable, report the exact blocker rather than infer health.",
        "subject": "Read-only cluster health check",
        "urgency": "medium",
        "wait_seconds": 60
    });
    let refusal = fixture
        .dispatch_named(
            SEAT_ASK_TOOL,
            Some(fixture.resource.clone()),
            first.clone(),
            "ask-mint",
        )
        .expect_err("a first R3 dispatch without approval is refused");
    let HostToolOperationError::ApprovalRequired {
        approval_id,
        revision,
        ..
    } = &refusal
    else {
        panic!("expected an actionable approval refusal, got {refusal:?}");
    };
    assert_eq!(*revision, 1);
    assert_eq!(
        fixture.world.effects.load(Ordering::SeqCst),
        0,
        "the refused dispatch never reached a handler"
    );

    {
        let mut ledger = fixture.ledger.lock().expect("ledger lock");
        let mut gate = ApprovalGate::new(&mut ledger);
        gate.decide(
            approval_id,
            *revision,
            ApprovalDecision::Approve {
                evidence_ref: Some("operator:fixture".to_owned()),
            },
            "fixture-operator",
            OffsetDateTime::now_utc(),
        )
        .expect("owner decision settles");
    }

    // The exact canonical retry shape: the first shape plus approvalId.
    let mut retry = first.clone();
    retry["approvalId"] = json!(approval_id.to_string());
    let result = fixture
        .dispatch_named(
            SEAT_ASK_TOOL,
            Some(fixture.resource.clone()),
            retry,
            "ask-consume",
        )
        .expect("the approved live-shaped retry dispatches through the real schema");
    assert_eq!(result["handledBy"], SEAT_ASK_HANDLER);
    assert_eq!(
        fixture.world.effects.load(Ordering::SeqCst),
        1,
        "the approved ask executed exactly once"
    );
    let correlation = correlation_for(&fixture.session, "ask-consume").expect("correlation");
    let consumed_command_id =
        CommandId::new(format!("odin.omp.host_tool:{correlation}")).expect("command id");
    {
        let ledger = fixture.ledger.lock().expect("ledger lock");
        let approval = ledger
            .approval(approval_id)
            .expect("approval readable")
            .expect("consumed approval record");
        assert_eq!(approval.status, ApprovalStatus::Consumed);
        assert_eq!(
            approval.consumed_by_command_id.as_ref(),
            Some(&consumed_command_id)
        );
    }
}

#[test]
fn schema_dead_seat_ask_scopes_never_mint_or_spend_approvals() {
    let fixture = Fixture::for_seat_ask();
    let run = fixture.scope.run.clone().expect("bound run");
    fixture.seed_bridge_run();
    {
        let mut ledger = fixture.ledger.lock().expect("ledger lock");
        let plan = ledger
            .replace_plan(
                &run,
                "Approve one governed cluster-health ask",
                &[odin_ledger::plan::TodoSpec {
                    id: odin_domain::TodoId::new("todo:seat-ask-dead").expect("todo id"),
                    title: "Approve one governed cluster-health ask".to_owned(),
                    status: odin_ledger::plan::TodoStatus::Pending,
                }],
                0,
                OffsetDateTime::UNIX_EPOCH,
            )
            .expect("fixture seat ask plan");
        ledger
            .accept_plan(
                &run,
                plan.revision,
                "operator:fixture",
                OffsetDateTime::UNIX_EPOCH,
            )
            .expect("record fixture acceptance");
    }

    // `cluster-operations` is a label, not a declared project id.
    let labeled = json!({
        "project": "cluster-operations",
        "question": "Perform a read-only health check of the configured cluster.",
        "subject": "Read-only cluster health check",
        "urgency": "medium",
        "wait_seconds": 60
    });
    let refused = fixture
        .dispatch_named(
            SEAT_ASK_TOOL,
            Some(fixture.resource.clone()),
            labeled,
            "ask-dead-project",
        )
        .expect_err("a schema-dead scope is refused, never minted");
    assert!(matches!(
        refused,
        HostToolOperationError::Authority(odin_kernel::OperationRejection::SchemaInvalid { .. })
    ));
    assert_eq!(
        fixture.world.effects.load(Ordering::SeqCst),
        0,
        "nothing executed for the schema-dead scope"
    );
    {
        let ledger = fixture.ledger.lock().expect("ledger lock");
        assert!(
            ledger.approvals().expect("approval list").is_empty(),
            "no approval request was minted for a schema-dead scope"
        );
    }

    // Validate the retry before consuming its approval.
    let valid = json!({
        "project": "odin",
        "question": "Perform a read-only health check of the configured cluster.",
        "subject": "Read-only cluster health check",
        "urgency": "medium"
    });
    let minted = fixture
        .dispatch_named(
            SEAT_ASK_TOOL,
            Some(fixture.resource.clone()),
            valid.clone(),
            "ask-mint-valid",
        )
        .expect_err("a first R3 dispatch without approval is refused");
    let HostToolOperationError::ApprovalRequired {
        approval_id,
        revision,
        ..
    } = &minted
    else {
        panic!("expected an actionable approval refusal, got {minted:?}");
    };
    {
        let mut ledger = fixture.ledger.lock().expect("ledger lock");
        ApprovalGate::new(&mut ledger)
            .decide(
                approval_id,
                *revision,
                ApprovalDecision::Approve {
                    evidence_ref: Some("operator:fixture".to_owned()),
                },
                "fixture-operator",
                OffsetDateTime::now_utc(),
            )
            .expect("owner decision settles");
    }
    let mut poisoned = valid.clone();
    poisoned["approvalId"] = json!(approval_id.to_string());
    poisoned["seat"] = json!("gungnir");
    let spent = fixture
        .dispatch_named(
            SEAT_ASK_TOOL,
            Some(fixture.resource.clone()),
            poisoned,
            "ask-retry-dead",
        )
        .expect_err("a schema-dead retry is refused before the gate consumes");
    assert!(matches!(
        spent,
        HostToolOperationError::Authority(odin_kernel::OperationRejection::SchemaInvalid { .. })
    ));
    {
        let ledger = fixture.ledger.lock().expect("ledger lock");
        let approval = ledger
            .approval(approval_id)
            .expect("approval readable")
            .expect("decided approval record");
        assert_eq!(
            approval.status,
            ApprovalStatus::Approved,
            "the schema-dead retry never consumed the decision"
        );
    }
    assert_eq!(fixture.world.effects.load(Ordering::SeqCst), 0);

    // The lawful retry still spends the decision exactly once.
    let mut lawful = valid.clone();
    lawful["approvalId"] = json!(approval_id.to_string());
    fixture
        .dispatch_named(
            SEAT_ASK_TOOL,
            Some(fixture.resource.clone()),
            lawful,
            "ask-retry-valid",
        )
        .expect("the decided approval admits the lawful retry");
    assert_eq!(fixture.world.effects.load(Ordering::SeqCst), 1);
}

#[test]
fn absent_project_seat_ask_is_refused_before_any_approval() {
    let fixture = Fixture::for_seat_ask();
    let run = fixture.scope.run.clone().expect("bound run");
    fixture.seed_bridge_run();
    {
        let mut ledger = fixture.ledger.lock().expect("ledger lock");
        let plan = ledger
            .replace_plan(
                &run,
                "Approve one governed cluster-health ask",
                &[odin_ledger::plan::TodoSpec {
                    id: odin_domain::TodoId::new("todo:seat-ask-absent").expect("todo id"),
                    title: "Approve one governed cluster-health ask".to_owned(),
                    status: odin_ledger::plan::TodoStatus::Pending,
                }],
                0,
                OffsetDateTime::UNIX_EPOCH,
            )
            .expect("fixture seat ask plan");
        ledger
            .accept_plan(
                &run,
                plan.revision,
                "operator:fixture",
                OffsetDateTime::UNIX_EPOCH,
            )
            .expect("record fixture acceptance");
    }

    // Every other field is lawful; only `project` is missing — exactly the
    // shape a handler-side-only guard would let reach the approval gate.
    let projectless = json!({
        "question": "Perform a read-only health check of the configured cluster.",
        "subject": "Read-only cluster health check",
        "urgency": "medium"
    });
    let refused = fixture
        .dispatch_named(
            SEAT_ASK_TOOL,
            Some(fixture.resource.clone()),
            projectless,
            "ask-absent-project",
        )
        .expect_err("a projectless ask is refused, never minted");
    assert!(matches!(
        refused,
        HostToolOperationError::Authority(odin_kernel::OperationRejection::SchemaInvalid { .. })
    ));
    assert_eq!(
        fixture.world.effects.load(Ordering::SeqCst),
        0,
        "nothing executed for the projectless ask"
    );
    let ledger = fixture.ledger.lock().expect("ledger lock");
    assert!(
        ledger.approvals().expect("approval list").is_empty(),
        "no approval request was minted for a projectless ask"
    );
}

/// The bound-project admission IS the listed declaration: a fixture whose
/// model surface declares `colinremote` admits the ask purely from that
/// declaration — the identical pre-gate path, with no Rust identity branch
/// anywhere — while a project the same declaration does not list is
/// refused before anything is journaled or minted.
#[test]
fn declared_project_enum_admits_the_ask_without_identity_branches() {
    let fixture = Fixture::for_seat_ask_declaring(&["colinremote"]);
    let run = fixture.scope.run.clone().expect("bound run");
    fixture.seed_bridge_run();
    {
        let mut ledger = fixture.ledger.lock().expect("ledger lock");
        let plan = ledger
            .replace_plan(
                &run,
                "Approve one governed ask",
                &[odin_ledger::plan::TodoSpec {
                    id: odin_domain::TodoId::new("todo:seat-ask-declared").expect("todo id"),
                    title: "Approve one governed ask".to_owned(),
                    status: odin_ledger::plan::TodoStatus::Pending,
                }],
                0,
                OffsetDateTime::UNIX_EPOCH,
            )
            .expect("fixture seat ask plan");
        ledger
            .accept_plan(
                &run,
                plan.revision,
                "operator:fixture",
                OffsetDateTime::UNIX_EPOCH,
            )
            .expect("record fixture acceptance");
    }

    let declared = json!({
        "project": "colinremote",
        "question": "Perform a read-only health check of the configured cluster.",
        "subject": "Read-only cluster health check",
        "urgency": "medium",
        "wait_seconds": 60
    });
    let minted = fixture
        .dispatch_named(
            SEAT_ASK_TOOL,
            Some(fixture.resource.clone()),
            declared,
            "ask-declared-project",
        )
        .expect_err("the declared project passes the pre-gate and reaches the approval gate");
    let HostToolOperationError::ApprovalRequired { approval_id, .. } = &minted else {
        panic!("expected an actionable approval refusal, got {minted:?}");
    };
    {
        let ledger = fixture.ledger.lock().expect("ledger lock");
        let approvals = ledger.approvals().expect("approval list");
        assert_eq!(
            approvals.len(),
            1,
            "exactly the declared project's ask is durably requested"
        );
    }

    let undeclared = json!({
        "project": "odin",
        "question": "Perform a read-only health check of the configured cluster.",
        "subject": "Read-only cluster health check",
        "urgency": "medium"
    });
    let refused = fixture
        .dispatch_named(
            SEAT_ASK_TOOL,
            Some(fixture.resource.clone()),
            undeclared,
            "ask-undeclared-project",
        )
        .expect_err("a project outside the declared enum is refused pre-gate");
    assert!(matches!(
        refused,
        HostToolOperationError::Authority(odin_kernel::OperationRejection::SchemaInvalid { .. })
    ));
    let ledger = fixture.ledger.lock().expect("ledger lock");
    assert_eq!(
        ledger.approvals().expect("approval list").len(),
        1,
        "the undeclared project minted nothing"
    );
    let approval = ledger
        .approval(approval_id)
        .expect("approval readable")
        .expect("declared ask approval");
    assert_eq!(
        approval.status,
        ApprovalStatus::Requested,
        "the refused undeclared dispatch never touched the declared ask's decision"
    );
}

/// Canonical action pairing must still be validated when the listed schema omits `oneOf`.
/// A decision without the complete delivered preview cannot authorize the effect.
#[test]
fn schema_dead_browser_pairing_never_mints_or_spends_approvals() {
    let fixture = Fixture::for_browser_consequential();
    let run = fixture.scope.run.clone().expect("bound run");
    fixture.seed_bridge_run();
    {
        let mut ledger = fixture.ledger.lock().expect("ledger lock");
        let plan = ledger
            .replace_plan(
                &run,
                "Approve one governed browser action",
                &[odin_ledger::plan::TodoSpec {
                    id: odin_domain::TodoId::new("todo:browser-pair-dead").expect("todo id"),
                    title: "Approve one governed browser action".to_owned(),
                    status: odin_ledger::plan::TodoStatus::Pending,
                }],
                0,
                OffsetDateTime::UNIX_EPOCH,
            )
            .expect("fixture browser plan");
        ledger
            .accept_plan(
                &run,
                plan.revision,
                "operator:fixture",
                OffsetDateTime::UNIX_EPOCH,
            )
            .expect("record fixture acceptance");
    }

    // Every field of the plain object shape is individually lawful: the
    // `navigate` action, well-typed `fill` arguments, valid digests. Only
    // the canonical action/argument pairing is dead — exactly the contract
    // the provider-facing projection cannot express and the authority must.
    let digest = "blake3:00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
    let mismatched = json!({
        "sessionId": "00000000-0000-4000-8000-000000000909",
        "expectedRevision": 0,
        "action": "navigate",
        "arguments": {"selector": "#submit", "text": "paired with the wrong action"},
        "argumentsDigest": digest,
        "policyRevision": 1,
        "policyDigest": digest
    });
    let refused = fixture
        .dispatch_named(
            BROWSER_CONSEQUENTIAL_TOOL,
            Some(fixture.resource.clone()),
            mismatched,
            "browser-pair-dead",
        )
        .expect_err("a pairing-dead action is refused, never minted");
    assert!(matches!(
        refused,
        HostToolOperationError::Authority(odin_kernel::OperationRejection::SchemaInvalid { .. })
    ));
    assert_eq!(
        fixture.world.effects.load(Ordering::SeqCst),
        0,
        "nothing executed for the pairing-dead action"
    );
    {
        let ledger = fixture.ledger.lock().expect("ledger lock");
        assert!(
            ledger.approvals().expect("approval list").is_empty(),
            "no approval request was minted for a pairing-dead action"
        );
    }

    // The lawful pairing mints the operator decision.
    let valid = json!({
        "sessionId": "00000000-0000-4000-8000-000000000909",
        "expectedRevision": 0,
        "action": "navigate",
        "arguments": {"url": "https://odin.local/fixture"},
        "argumentsDigest": digest,
        "policyRevision": 1,
        "policyDigest": digest
    });
    let minted = fixture
        .dispatch_named(
            BROWSER_CONSEQUENTIAL_TOOL,
            Some(fixture.resource.clone()),
            valid.clone(),
            "browser-pair-mint-valid",
        )
        .expect_err("a first R3 dispatch without approval is refused");
    let HostToolOperationError::ApprovalRequired {
        approval_id,
        revision,
        ..
    } = &minted
    else {
        panic!("expected an actionable approval refusal, got {minted:?}");
    };
    {
        let mut ledger = fixture.ledger.lock().expect("ledger lock");
        ApprovalGate::new(&mut ledger)
            .decide(
                approval_id,
                *revision,
                ApprovalDecision::Approve {
                    evidence_ref: Some("operator:fixture".to_owned()),
                },
                "fixture-operator",
                OffsetDateTime::now_utc(),
            )
            .expect("owner decision settles");
    }

    // Validate the retry's action pairing before consuming its approval.
    let mut poisoned = valid.clone();
    poisoned["approvalId"] = json!(approval_id.to_string());
    poisoned["arguments"] = json!({"selector": "#submit", "text": "wrong shape for navigate"});
    let spent = fixture
        .dispatch_named(
            BROWSER_CONSEQUENTIAL_TOOL,
            Some(fixture.resource.clone()),
            poisoned,
            "browser-pair-retry-dead",
        )
        .expect_err("a pairing-dead retry is refused before the gate consumes");
    assert!(matches!(
        spent,
        HostToolOperationError::Authority(odin_kernel::OperationRejection::SchemaInvalid { .. })
    ));
    {
        let ledger = fixture.ledger.lock().expect("ledger lock");
        let approval = ledger
            .approval(approval_id)
            .expect("approval readable")
            .expect("decided approval record");
        assert_eq!(
            approval.status,
            ApprovalStatus::Approved,
            "the pairing-dead retry never consumed the decision"
        );
    }
    assert_eq!(fixture.world.effects.load(Ordering::SeqCst), 0);

    // A bare operator decision never bound the complete delivered preview:
    // even the lawful retry cannot spend it, and the owner is asked anew.
    let mut lawful = valid.clone();
    lawful["approvalId"] = json!(approval_id.to_string());
    let unproven = fixture.dispatch_named(
        BROWSER_CONSEQUENTIAL_TOOL,
        Some(fixture.resource.clone()),
        lawful,
        "browser-pair-retry-valid",
    );
    assert!(
        matches!(
            unproven,
            Err(HostToolOperationError::ApprovalRequired { .. })
        ),
        "{unproven:?}"
    );
    assert_eq!(fixture.world.effects.load(Ordering::SeqCst), 0);
}

/// A required `approvalId` starts as a placeholder because the model cannot know the minted id yet.
#[test]
fn placeholder_approval_id_mints_requested_scope_and_consumes_once() {
    let fixture = Fixture::new();
    let run = fixture.scope.run.clone().expect("bound run");
    fixture.seed_bridge_run();
    {
        let mut ledger = fixture.ledger.lock().expect("ledger lock");
        let plan = ledger
            .replace_plan(
                &run,
                "Approve one governed R3 dispatch",
                &[odin_ledger::plan::TodoSpec {
                    id: odin_domain::TodoId::new("todo:r3-placeholder-mint").expect("todo id"),
                    title: "Approve one governed R3 dispatch".to_owned(),
                    status: odin_ledger::plan::TodoStatus::Pending,
                }],
                0,
                OffsetDateTime::UNIX_EPOCH,
            )
            .expect("fixture r3 plan");
        ledger
            .accept_plan(
                &run,
                plan.revision,
                "operator:fixture",
                OffsetDateTime::UNIX_EPOCH,
            )
            .expect("record fixture acceptance");
    }

    // -- The placeholder dispatch mints the durable request: typed
    //    ApprovalRequired payload, Requested row, retry-arguments scope.
    let placeholder = json!({"value": "publish-me", "approvalId": "pending"});
    let required = fixture
        .dispatch_named(
            EXEC_TOOL,
            Some(fixture.resource.clone()),
            placeholder.clone(),
            "request-placeholder",
        )
        .expect_err("the first placeholder dispatch demands an approval");
    let (minted_id, _revision) = match &required {
        HostToolOperationError::ApprovalRequired {
            approval_id,
            revision,
            ..
        } => (approval_id.clone(), *revision),
        other => panic!("expected the payload-bearing approval demand: {other:?}"),
    };
    {
        let ledger = fixture.ledger.lock().expect("ledger lock");
        let approval = ledger
            .approval(&minted_id)
            .expect("approval readable")
            .expect("the minted approval is durable");
        assert_eq!(approval.status, ApprovalStatus::Requested);
        assert_eq!(approval.scope.capability_id.as_str(), EXEC_CAPABILITY);
        assert_eq!(approval.scope.target_kind, "run");
        assert_eq!(approval.scope.target_id, run.as_str());
    }
    assert!(fixture.world.calls().is_empty(), "nothing executed yet");

    // -- The retry arguments digest the minted id: the row's scope binds
    //    exactly the retry shape the model is told to send.
    let retry_arguments = json!({"value": "publish-me", "approvalId": minted_id.clone()});
    {
        let ledger = fixture.ledger.lock().expect("ledger lock");
        let approval = ledger
            .approval(&minted_id)
            .expect("approval readable")
            .expect("row");
        let expected = odin_kernel::ApprovalScope {
            target_kind: "run".to_owned(),
            target_id: run.as_str().to_owned(),
            capability_id: CapabilityId::new(EXEC_CAPABILITY).expect("capability id"),
            arguments_digest: arguments_digest(&retry_arguments),
        };
        assert_eq!(
            approval.scope, expected,
            "the minted scope binds exactly the retry arguments"
        );
    }

    // -- The owner approves through the ledger decision API: the row is
    //    Approved before the retry, the delivery-side consumption record.
    {
        let mut ledger = fixture.ledger.lock().expect("ledger lock");
        let approval = ledger.approval(&minted_id).expect("readable").expect("row");
        let mut gate = ApprovalGate::new(&mut ledger);
        match gate
            .decide(
                &minted_id,
                approval.revision,
                ApprovalDecision::Approve {
                    evidence_ref: Some("operator:fixture".to_owned()),
                },
                "fixture-operator",
                OffsetDateTime::UNIX_EPOCH + time::Duration::seconds(1),
            )
            .expect("owner decision recorded")
        {
            DecisionOutcome::Approved(_) => {}
            other => panic!("unexpected approval outcome: {other:?}"),
        }
    }

    // -- The identical retry consumes exactly once: the handler and its
    //    extractor receive the consumed-command proof.
    let result = fixture
        .dispatch_named(
            EXEC_TOOL,
            Some(fixture.resource.clone()),
            retry_arguments.clone(),
            "request-retry",
        )
        .expect("the approved retry dispatches");
    assert_eq!(result["handledBy"], EXEC_HANDLER);
    assert_eq!(fixture.world.calls(), vec![EXEC_HANDLER, EXEC_EXTRACTOR]);
    let correlation = correlation_for(&fixture.session, "request-retry").expect("correlation");
    {
        let ledger = fixture.ledger.lock().expect("ledger lock");
        let approval = ledger.approval(&minted_id).expect("readable").expect("row");
        assert_eq!(approval.status, ApprovalStatus::Consumed);
        let consumed =
            CommandId::new(format!("odin.omp.host_tool:{correlation}")).expect("command id");
        assert_eq!(approval.consumed_by_command_id.as_ref(), Some(&consumed));
        assert_eq!(
            approval.scope.arguments_digest,
            arguments_digest(&retry_arguments)
        );
    }

    // -- Changed arguments under the consumed approval can never consume:
    //    the refusal is typed and nothing executes.
    let changed = json!({"value": "changed", "approvalId": minted_id.clone()});
    let refused = fixture
        .dispatch_named(
            EXEC_TOOL,
            Some(fixture.resource.clone()),
            changed,
            "request-changed",
        )
        .expect_err("changed arguments cannot consume the spent approval");
    assert!(matches!(
        refused,
        HostToolOperationError::Rejected(AuthorizationRejection::NeedsApproval { .. })
    ));
    assert_eq!(
        fixture.world.calls().len(),
        2,
        "only the handler and extractor of the one approved dispatch ran"
    );
}

#[test]
fn r2_operator_contract_follows_the_r3_mint_consume_and_replay_law() {
    let fixture = Fixture::for_draft_r2_operator();
    let run = fixture.scope.run.clone().expect("bound run");
    fixture.seed_bridge_run();
    {
        let mut ledger = fixture.ledger.lock().expect("ledger lock");
        let plan = ledger
            .replace_plan(
                &run,
                "Approve one governed R2 dispatch",
                &[odin_ledger::plan::TodoSpec {
                    id: odin_domain::TodoId::new("todo:r2-mint").expect("todo id"),
                    title: "Approve one governed R2 dispatch".to_owned(),
                    status: odin_ledger::plan::TodoStatus::Pending,
                }],
                0,
                OffsetDateTime::UNIX_EPOCH,
            )
            .expect("fixture r2 plan");
        ledger
            .accept_plan(
                &run,
                plan.revision,
                "operator:fixture",
                OffsetDateTime::UNIX_EPOCH,
            )
            .expect("record fixture acceptance");
    }

    // -- First dispatch without an approval: typed refusal plus a durable
    //    exact-scope request in the R2 identity space, nothing executed.
    let refusal = fixture
        .dispatch_named(
            DRAFT_TOOL,
            Some(fixture.resource.clone()),
            json!({"value": "go"}),
            "request-mint",
        )
        .expect_err("a first operator-gated R2 dispatch is refused");
    let HostToolOperationError::ApprovalRequired {
        capability_id,
        effect_class,
        approval_id,
        revision,
    } = &refusal
    else {
        panic!("expected an actionable approval refusal, got {refusal:?}");
    };
    assert_eq!(capability_id.as_str(), DRAFT_CAPABILITY);
    assert_eq!(*effect_class, EffectClass::R2);
    assert_eq!(*revision, 1, "a fresh request starts at revision one");
    assert!(
        approval_id
            .as_str()
            .starts_with("approval:r2:fixture.draft:"),
        "the R2 request mints in its own derived identity space: {approval_id}"
    );
    assert!(
        fixture.world.calls().is_empty(),
        "the refused dispatch never reached a handler"
    );
    assert_eq!(fixture.world.effects.load(Ordering::SeqCst), 0);
    let mut retry_arguments = json!({"value": "go"});
    retry_arguments["approvalId"] = json!(approval_id.to_string());
    {
        let ledger = fixture.ledger.lock().expect("ledger lock");
        let approval = ledger
            .approval(approval_id)
            .expect("approval readable")
            .expect("the refusal minted a durable request");
        assert_eq!(approval.status, ApprovalStatus::Requested);
        assert_eq!(
            approval.issuer,
            fixture.scope.seat.as_ref().expect("seat").as_str(),
            "the issuer is the dispatching seat, the caller"
        );
        assert_eq!(approval.scope.capability_id.as_str(), DRAFT_CAPABILITY);
        assert_eq!(
            approval.scope.arguments_digest,
            arguments_digest(&retry_arguments),
            "the request binds the exact retry arguments, approvalId included"
        );
    }

    // -- An identical re-request adopts the same durable row instead of
    //    widening or reminting.
    let adopted = fixture
        .dispatch_named(
            DRAFT_TOOL,
            Some(fixture.resource.clone()),
            json!({"value": "go"}),
            "request-adopt",
        )
        .expect_err("the identical first dispatch is still gated");
    let HostToolOperationError::ApprovalRequired {
        approval_id: adopted_id,
        revision: adopted_revision,
        ..
    } = &adopted
    else {
        panic!("expected an actionable approval refusal, got {adopted:?}");
    };
    assert_eq!(
        adopted_id, approval_id,
        "an identical re-request adopts its own request row"
    );
    assert_eq!(*adopted_revision, 1);

    // -- The owner decides through the same ledger gate the CLI uses.
    {
        let mut ledger = fixture.ledger.lock().expect("ledger lock");
        let mut gate = ApprovalGate::new(&mut ledger);
        match gate
            .decide(
                approval_id,
                *revision,
                ApprovalDecision::Approve {
                    evidence_ref: Some("operator:fixture".to_owned()),
                },
                "fixture-operator",
                OffsetDateTime::now_utc(),
            )
            .expect("owner decision settles")
        {
            DecisionOutcome::Approved(_) => {}
            other => panic!("unexpected decision outcome: {other:?}"),
        }
    }

    // -- A wrong scope never admits: the approval stays unconsumed and
    //    nothing executes.
    let mismatch = fixture
        .dispatch_named(
            DRAFT_TOOL,
            Some(fixture.resource.clone()),
            json!({"value": "changed", "approvalId": approval_id.to_string()}),
            "request-mismatch",
        )
        .expect_err("an approval never covers different arguments");
    assert!(matches!(
        mismatch,
        HostToolOperationError::Rejected(AuthorizationRejection::NeedsApproval { .. })
    ));
    assert_eq!(fixture.world.effects.load(Ordering::SeqCst), 0);
    {
        let ledger = fixture.ledger.lock().expect("ledger lock");
        let approval = ledger
            .approval(approval_id)
            .expect("approval readable")
            .expect("scope approval record");
        assert_eq!(
            approval.status,
            ApprovalStatus::Approved,
            "a scope mismatch never consumes the approval"
        );
    }

    // -- The exact approved retry dispatches exactly once, consumed by
    //    exactly the journaled host command.
    let result = fixture
        .dispatch_named(
            DRAFT_TOOL,
            Some(fixture.resource.clone()),
            retry_arguments.clone(),
            "request-consume",
        )
        .expect("the decided approval admits the identical retry");
    assert_eq!(result["handledBy"], DRAFT_HANDLER);
    assert_eq!(fixture.world.effects.load(Ordering::SeqCst), 1);
    let correlation = correlation_for(&fixture.session, "request-consume").expect("correlation");
    let consumed_command_id =
        CommandId::new(format!("odin.omp.host_tool:{correlation}")).expect("command id");
    {
        let ledger = fixture.ledger.lock().expect("ledger lock");
        let approval = ledger
            .approval(approval_id)
            .expect("approval readable")
            .expect("consumed approval record");
        assert_eq!(approval.status, ApprovalStatus::Consumed);
        assert_eq!(
            approval.consumed_by_command_id.as_ref(),
            Some(&consumed_command_id),
            "the consumption names exactly the retried command"
        );
    }

    // A replay neither repeats the effect nor rebinds the consumed approval.
    fixture
        .dispatch_named(
            DRAFT_TOOL,
            Some(fixture.resource.clone()),
            retry_arguments.clone(),
            "request-consume",
        )
        .expect_err("a consumed approval cannot dispatch again");
    assert_eq!(fixture.world.effects.load(Ordering::SeqCst), 1);
    {
        let ledger = fixture.ledger.lock().expect("ledger lock");
        let approval = ledger
            .approval(approval_id)
            .expect("approval readable")
            .expect("consumed approval record");
        assert_eq!(
            approval.consumed_by_command_id.as_ref(),
            Some(&consumed_command_id),
            "the replay never rebinds the approval to another command"
        );
    }

    // -- A repeat first dispatch rolls to a fresh R2 request instead of
    //    resurrecting the consumed row.
    let repeat = fixture
        .dispatch_named(
            DRAFT_TOOL,
            Some(fixture.resource.clone()),
            json!({"value": "go"}),
            "request-mint-2",
        )
        .expect_err("a repeat first dispatch is still gated");
    let HostToolOperationError::ApprovalRequired {
        approval_id: rolled_id,
        revision: rolled_revision,
        ..
    } = &repeat
    else {
        panic!("expected an actionable approval refusal, got {repeat:?}");
    };
    assert_ne!(
        rolled_id, approval_id,
        "a terminal row rolls to a fresh request identity"
    );
    assert_eq!(*rolled_revision, 1);
    {
        let ledger = fixture.ledger.lock().expect("ledger lock");
        let rolled = ledger
            .approval(rolled_id)
            .expect("approval readable")
            .expect("the rolled request exists");
        assert_eq!(rolled.status, ApprovalStatus::Requested);
    }
    assert_eq!(
        fixture.world.effects.load(Ordering::SeqCst),
        1,
        "nothing else ever executed"
    );
}

/// A declaration-decided operator capability dispatches on the first call
/// with no owner in the loop. The approval is still minted, decided by
/// `declaration:<seat>`, and consumed exactly once by the journaled command,
/// so the audit trail is identical to an owner decision; nothing waits on a
/// human.
#[test]
fn declaration_decided_capability_dispatches_first_call_with_an_audited_decision() {
    let fixture = Fixture::new();
    let run = fixture.scope.run.clone().expect("bound run");
    fixture.seed_bridge_run();
    {
        let mut ledger = fixture.ledger.lock().expect("ledger lock");
        let plan = ledger
            .replace_plan(
                &run,
                "Declared governed dispatch",
                &[odin_ledger::plan::TodoSpec {
                    id: odin_domain::TodoId::new("todo:declared").expect("todo id"),
                    title: "Declared governed dispatch".to_owned(),
                    status: odin_ledger::plan::TodoStatus::Pending,
                }],
                0,
                OffsetDateTime::UNIX_EPOCH,
            )
            .expect("fixture plan");
        ledger
            .accept_plan(
                &run,
                plan.revision,
                "operator:fixture",
                OffsetDateTime::UNIX_EPOCH,
            )
            .expect("record fixture acceptance");
    }
    fixture.material_source.declare_decided(EXEC_CAPABILITY);
    // Another connection presents Requested rows to the owner, so automatic decisions must commit atomically.
    let pending = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let commits = std::sync::Arc::new(std::sync::Mutex::new(
        Vec::<Vec<rusqlite::hooks::Action>>::new(),
    ));
    {
        let ledger = fixture.ledger.lock().expect("ledger lock");
        let seen = std::sync::Arc::clone(&pending);
        ledger
            .connection()
            .update_hook(Some(move |action, _: &str, table: &str, _: i64| {
                if table == "approvals" {
                    seen.lock().expect("hook lock").push(action);
                }
            }));
        let (seen, committed) = (
            std::sync::Arc::clone(&pending),
            std::sync::Arc::clone(&commits),
        );
        ledger.connection().commit_hook(Some(move || {
            let actions = std::mem::take(&mut *seen.lock().expect("hook lock"));
            committed.lock().expect("hook lock").push(actions);
            false
        }));
    }
    fixture
        .dispatch_named(
            EXEC_TOOL,
            Some(fixture.resource.clone()),
            json!({"value": "go"}),
            "request-declared",
        )
        .expect("a declaration-decided capability dispatches on the first call");
    assert_eq!(fixture.world.effects.load(Ordering::SeqCst), 1);
    for actions in commits.lock().expect("hook lock").iter() {
        assert!(
            !actions.contains(&rusqlite::hooks::Action::SQLITE_INSERT)
                || actions.contains(&rusqlite::hooks::Action::SQLITE_UPDATE),
            "a kernel-decided approval committed as requested: {actions:?}"
        );
    }
    let ledger = fixture.ledger.lock().expect("ledger lock");
    let seat = fixture
        .scope
        .seat
        .as_ref()
        .expect("seat")
        .as_str()
        .to_owned();
    let decided: Vec<(String, Option<String>)> = ledger
        .connection()
        .prepare("SELECT status, decided_by FROM approvals WHERE capability_id = ?1")
        .expect("approval query")
        .query_map([EXEC_CAPABILITY], |row| Ok((row.get(0)?, row.get(1)?)))
        .expect("approval rows")
        .collect::<Result<_, _>>()
        .expect("approval rows decode");
    assert_eq!(
        decided,
        vec![("consumed".to_owned(), Some(format!("declaration:{seat}")))],
        "exactly one audited decision, consumed by the dispatch"
    );
}

/// An approval for another capability never authorizes this call, so it is
/// dropped and the declaration decides.
#[test]
fn a_foreign_approval_id_never_blocks_the_declaration_decider() {
    let fixture = Fixture::new();
    let run = fixture.scope.run.clone().expect("bound run");
    fixture.seed_bridge_run();
    let foreign = odin_domain::ApprovalId::new("approval:r3:task.grant:foreign").expect("id");
    {
        let mut ledger = fixture.ledger.lock().expect("ledger lock");
        let plan = ledger
            .replace_plan(
                &run,
                "Declared governed dispatch",
                &[odin_ledger::plan::TodoSpec {
                    id: odin_domain::TodoId::new("todo:declared").expect("todo id"),
                    title: "Declared governed dispatch".to_owned(),
                    status: odin_ledger::plan::TodoStatus::Pending,
                }],
                0,
                OffsetDateTime::UNIX_EPOCH,
            )
            .expect("fixture plan");
        ledger
            .accept_plan(
                &run,
                plan.revision,
                "operator:fixture",
                OffsetDateTime::UNIX_EPOCH,
            )
            .expect("record fixture acceptance");
        ledger
            .request_approval(odin_ledger::approval::NewApproval {
                approval_id: foreign.clone(),
                issuer: "fixture".to_owned(),
                scope: odin_ledger::approval::ApprovalScope {
                    target_kind: "session".to_owned(),
                    target_id: "elsewhere".to_owned(),
                    capability_id: odin_domain::CapabilityId::new("task.grant").expect("cap"),
                    arguments_digest: odin_domain::Digest::hash(b"grant"),
                },
                requested_at: OffsetDateTime::UNIX_EPOCH,
                expires_at: OffsetDateTime::now_utc() + time::Duration::hours(1),
            })
            .expect("a foreign approval row");
    }
    fixture.material_source.declare_decided(EXEC_CAPABILITY);
    fixture
        .dispatch_named(
            EXEC_TOOL,
            Some(fixture.resource.clone()),
            json!({"value": "go", "approvalId": foreign.as_str()}),
            "request-declared-foreign",
        )
        .expect("the declaration decides despite a foreign approval id");
    assert_eq!(fixture.world.effects.load(Ordering::SeqCst), 1);
}

/// A selector naming no approval selects nothing, so an invented id never
/// skips the declaration decision.
#[test]
fn an_invented_approval_id_never_blocks_the_declaration_decider() {
    let fixture = Fixture::new();
    let run = fixture.scope.run.clone().expect("bound run");
    fixture.seed_bridge_run();
    {
        let mut ledger = fixture.ledger.lock().expect("ledger lock");
        let plan = ledger
            .replace_plan(
                &run,
                "Declared governed dispatch",
                &[odin_ledger::plan::TodoSpec {
                    id: odin_domain::TodoId::new("todo:declared").expect("todo id"),
                    title: "Declared governed dispatch".to_owned(),
                    status: odin_ledger::plan::TodoStatus::Pending,
                }],
                0,
                OffsetDateTime::UNIX_EPOCH,
            )
            .expect("fixture plan");
        ledger
            .accept_plan(
                &run,
                plan.revision,
                "operator:fixture",
                OffsetDateTime::UNIX_EPOCH,
            )
            .expect("record fixture acceptance");
    }
    fixture.material_source.declare_decided(EXEC_CAPABILITY);
    fixture
        .dispatch_named(
            EXEC_TOOL,
            Some(fixture.resource.clone()),
            json!({"value": "go", "approvalId": "blake3:heartbeat-svc-pause-6ab8d801"}),
            "request-declared-invented",
        )
        .expect("the declaration decides despite an invented approval id");
    assert_eq!(fixture.world.effects.load(Ordering::SeqCst), 1);
}

#[test]
fn an_unproven_task_grant_cannot_decide_owner_calls() {
    let mut fixture = Fixture::new();
    let run = fixture.scope.run.clone().expect("bound run");
    fixture.seed_bridge_run();
    {
        let mut ledger = fixture.ledger.lock().expect("ledger lock");
        let plan = ledger
            .replace_plan(
                &run,
                "Granted task",
                &[odin_ledger::plan::TodoSpec {
                    id: odin_domain::TodoId::new("todo:granted").expect("todo id"),
                    title: "Granted task".to_owned(),
                    status: odin_ledger::plan::TodoStatus::Pending,
                }],
                0,
                OffsetDateTime::UNIX_EPOCH,
            )
            .expect("fixture plan");
        ledger
            .accept_plan(
                &run,
                plan.revision,
                "operator:fixture",
                OffsetDateTime::UNIX_EPOCH,
            )
            .expect("record fixture acceptance");
    }
    let dir = tempfile::tempdir().expect("tempdir");
    let grants = std::sync::Arc::new(crate::host_tools::task_grants::TaskGrantStore::open(
        dir.path().join("task-grants.json"),
    ));
    grants
        .record(
            crate::host_tools::task_grants::TaskGrant {
                id: "approval:owner-plan".to_owned(),
                task: "one granted effect".to_owned(),
                session: fixture.session.clone(),
                capabilities: [odin_domain::CapabilityId::new(EXEC_CAPABILITY).expect("id")].into(),
                expires_at_ms: u64::MAX / 2,
                max_uses: 1,
                used: 0,
                revoked: false,
                request: None,
                reservations: Vec::new(),
            },
            0,
        )
        .expect("record grant");
    fixture
        .material_source
        .declare_grant_batch(&[EXEC_CAPABILITY]);
    fixture.operations = fixture.operations.clone().with_task_grants(grants);
    let result = fixture.dispatch_named(
        EXEC_TOOL,
        Some(fixture.resource.clone()),
        json!({"value": "go"}),
        "request-unproven-grant",
    );
    assert!(
        matches!(result, Err(HostToolOperationError::ApprovalRequired { .. })),
        "an agent-created grant cannot substitute for the owner's decision: {result:?}"
    );
    assert_eq!(fixture.world.effects.load(Ordering::SeqCst), 0);
    let mut ledger = fixture.ledger.lock().expect("ledger lock");
    let approvals = ledger.approvals().expect("approvals");
    assert_eq!(approvals.len(), 1);
    assert_eq!(approvals[0].status, odin_domain::ApprovalStatus::Requested);
    assert_eq!(approvals[0].decided_by, None);
    let id = approvals[0].approval_id.clone();
    ledger
        .decide_approval(
            &id,
            ApprovalDecision::Approve {
                evidence_ref: Some("grant:approval:owner-plan".to_owned()),
            },
            "grant:approval:owner-plan",
            OffsetDateTime::UNIX_EPOCH,
            approvals[0].revision,
        )
        .unwrap();
    drop(ledger);
    // Both automatic adoption and a caller-presented old derived selector
    // must revalidate the original owner's batch before authorizing.
    for arguments in [
        json!({"value": "go"}),
        json!({"value": "go", "approvalId": id.to_string()}),
    ] {
        let refused = fixture.dispatch_named(
            EXEC_TOOL,
            Some(fixture.resource.clone()),
            arguments,
            "request-old-derived-grant",
        );
        assert!(
            matches!(
                refused,
                Err(HostToolOperationError::ApprovalRequired { .. })
            ),
            "{refused:?}"
        );
        assert_eq!(fixture.world.effects.load(Ordering::SeqCst), 0);
    }
}

/// The gate consumes the owner's approval under the ledger lock and the
/// operation authority prepares only after that lock is released. A failure
/// between the two — a connection-private trigger refusing the real
/// `operation_journal` insert inside the kernel's prepare transaction, then a
/// real ledger reopen — strands the consumed decision with no operation row
/// and no effect. The identical retry of exactly that journaled command must
/// recover through production dispatch and execute exactly once, even with
/// an interleaved duplicate; an altered retry under the same request and a
/// foreign command presenting the same approval stay refused, and nothing
/// is reminted, rebound, or rewritten.
#[test]
fn a_consumed_approval_stranded_before_preparation_recovers_only_its_exact_command(
) -> Result<(), &'static str> {
    let mut fixture = Fixture::durable();
    let run = fixture.scope.run.clone().expect("bound run");
    fixture.seed_bridge_run();
    {
        let mut ledger = fixture
            .ledger
            .lock()
            .map_err(|_| "fixture ledger poisoned")?;
        let plan = ledger
            .replace_plan(
                &run,
                "Approve one governed R3 dispatch",
                &[odin_ledger::plan::TodoSpec {
                    id: odin_domain::TodoId::new("todo:r3-strand").expect("todo id"),
                    title: "Approve one governed R3 dispatch".to_owned(),
                    status: odin_ledger::plan::TodoStatus::Pending,
                }],
                0,
                OffsetDateTime::UNIX_EPOCH,
            )
            .expect("fixture r3 plan");
        ledger
            .accept_plan(
                &run,
                plan.revision,
                "operator:fixture",
                OffsetDateTime::UNIX_EPOCH,
            )
            .expect("record fixture acceptance");
    }

    // -- The owner decides the minted exact-scope request.
    let refusal = fixture
        .dispatch_named(
            EXEC_TOOL,
            Some(fixture.resource.clone()),
            json!({"value": "go"}),
            "strand-mint",
        )
        .expect_err("a first R3 dispatch is refused");
    let HostToolOperationError::ApprovalRequired {
        approval_id,
        revision,
        ..
    } = &refusal
    else {
        panic!("expected an actionable approval refusal, got {refusal:?}");
    };
    let approval_id = approval_id.clone();
    {
        let mut ledger = fixture
            .ledger
            .lock()
            .map_err(|_| "fixture ledger poisoned")?;
        ApprovalGate::new(&mut ledger)
            .decide(
                &approval_id,
                *revision,
                ApprovalDecision::Approve {
                    evidence_ref: Some("operator:fixture".to_owned()),
                },
                "fixture-operator",
                OffsetDateTime::UNIX_EPOCH + time::Duration::seconds(1),
            )
            .expect("owner decision settles");
    }
    let mut arguments = json!({"value": "go"});
    arguments["approvalId"] = json!(approval_id.to_string());

    // -- Preparation fails after consumption: the TEMP trigger lives only on
    //    this connection and refuses the kernel's own prepare insert.
    fixture
        .ledger
        .lock()
        .map_err(|_| "fixture ledger poisoned")?
        .connection()
        .execute_batch(
            "CREATE TEMP TRIGGER fixture_refuse_prepare BEFORE INSERT ON operation_journal \
             BEGIN SELECT RAISE(ABORT, 'fixture: no preparation after consumption'); END;",
        )
        .expect("install the private preparation fault");
    let stranded = fixture
        .dispatch_named(
            EXEC_TOOL,
            Some(fixture.resource.clone()),
            arguments.clone(),
            "strand-go",
        )
        .expect_err("preparation fails after the approval was consumed");
    assert!(
        matches!(
            stranded,
            HostToolOperationError::Authority(odin_kernel::OperationRejection::Durable(_))
        ),
        "{stranded:?}"
    );
    let correlation = correlation_for(&fixture.session, "strand-go").expect("correlation");
    let command_id =
        CommandId::new(format!("odin.omp.host_tool:{correlation}")).expect("command id");

    // -- A real reopen: the fault dies with its connection, and the durable
    //    stranding survives — consumed by exactly the journaled command, with
    //    no operation row and nothing executed.
    fixture.reopen_ledger();
    let (stranded_approval, stranded_command, original_binding) = {
        let ledger = fixture
            .ledger
            .lock()
            .map_err(|_| "fixture ledger poisoned")?;
        let approval = ledger
            .approval(&approval_id)
            .expect("approval readable")
            .expect("consumed approval record");
        assert_eq!(approval.status, ApprovalStatus::Consumed);
        assert_eq!(approval.consumed_by_command_id.as_ref(), Some(&command_id));
        let command = ledger
            .command(&command_id)
            .expect("command readable")
            .expect("the consuming command is journaled");
        assert_eq!(command.arguments, arguments);
        assert_eq!(command.approval_id.as_ref(), Some(&approval_id));
        let binding = ledger
            .host_command_binding(&command_id)
            .expect("binding readable")
            .expect("the original binding was recorded before consumption");
        (approval, command, binding)
    };
    let unchanged = |label: &str| -> Result<(), &'static str> {
        let ledger = fixture
            .ledger
            .lock()
            .map_err(|_| "fixture ledger poisoned")?;
        assert_eq!(
            ledger.approval(&approval_id).expect("approval readable"),
            Some(stranded_approval.clone()),
            "{label}: the consumed approval is never rebound, reopened, or re-consumed"
        );
        assert_eq!(
            ledger.approvals().expect("approval list").len(),
            1,
            "{label}: nothing is reminted"
        );
        assert_eq!(
            ledger.command(&command_id).expect("command readable"),
            Some(stranded_command.clone()),
            "{label}: the original command row is stable"
        );
        assert_eq!(
            ledger
                .host_command_binding(&command_id)
                .expect("binding readable"),
            Some(original_binding.clone()),
            "{label}: the original binding never changes"
        );
        Ok(())
    };
    assert!(
        fixture.row("strand-go").is_none(),
        "no operation was prepared"
    );
    assert!(fixture.world.calls().is_empty());
    assert_eq!(fixture.world.effects.load(Ordering::SeqCst), 0);

    // -- An altered retry under the same request conflicts with the
    //    journaled command before any gate runs.
    let mut altered = arguments.clone();
    altered["value"] = json!("changed");
    let refused = fixture
        .dispatch_named(
            EXEC_TOOL,
            Some(fixture.resource.clone()),
            altered,
            "strand-go",
        )
        .expect_err("an altered retry never recovers the stranded command");
    assert!(
        matches!(
            refused,
            HostToolOperationError::Authority(
                odin_kernel::OperationRejection::DuplicateConflict { .. }
            )
        ),
        "{refused:?}"
    );

    // -- A foreign command presenting the same consumed approval is refused.
    let foreign = fixture
        .dispatch_named(
            EXEC_TOOL,
            Some(fixture.resource.clone()),
            arguments.clone(),
            "strand-foreign",
        )
        .expect_err("a consumed approval never authorizes a foreign command");
    assert!(
        matches!(
            foreign,
            HostToolOperationError::Rejected(AuthorizationRejection::NeedsApproval { .. })
        ),
        "{foreign:?}"
    );
    assert!(fixture.row("strand-foreign").is_none());
    assert_eq!(fixture.world.effects.load(Ordering::SeqCst), 0);
    unchanged("refused retries")?;

    // -- The exact journaled command recovers through production dispatch
    //    and executes exactly once under its original consumed approval. An
    //    identical duplicate interleaved inside the readiness window of a
    //    first retry recovers and executes; the outer retry cannot execute again.
    let (sent, interleaved) = std::sync::mpsc::channel();
    let duplicate = (
        fixture.operations.clone(),
        fixture.binding.clone(),
        fixture.session.clone(),
        fixture.scope.clone(),
        fixture.resource.clone(),
        arguments.clone(),
    );
    fixture.world.schedule_preflight_hook(move || {
        let (operations, binding, session, scope, resource, arguments) = duplicate;
        let result = operations.dispatch_tool(
            SessionOperationContext {
                binding: &binding,
                session: &session,
                scope: &scope,
                execution: None,
            },
            EXEC_TOOL,
            Some(resource),
            arguments,
            "strand-go",
        );
        sent.send(result).expect("the test awaits the duplicate");
    });
    fixture
        .dispatch_named(
            EXEC_TOOL,
            Some(fixture.resource.clone()),
            arguments.clone(),
            "strand-go",
        )
        .expect_err("the duplicate does not execute the completed command again");
    let result = interleaved
        .try_recv()
        .expect("the duplicate ran inside the readiness window")
        .expect("the exact stranded command recovers through production dispatch");
    assert_eq!(result["handledBy"], EXEC_HANDLER);
    assert_eq!(fixture.world.calls(), vec![EXEC_HANDLER, EXEC_EXTRACTOR]);
    assert_eq!(fixture.world.effects.load(Ordering::SeqCst), 1);
    let expected_proof = format!(
        "{command_id}|{EXEC_CAPABILITY}|1|run|{}|{arguments}",
        run.as_str()
    );
    assert_eq!(
        *fixture
            .world
            .proofs
            .lock()
            .map_err(|_| "fixture proof lock poisoned")?,
        vec![expected_proof.clone(), expected_proof],
        "handler and extractor receive the original consumed command"
    );
    assert_eq!(
        fixture.row("strand-go").expect("prepared row").effect_state,
        odin_domain::operation::EffectState::Committed
    );
    unchanged("recovery")?;

    // -- Recovery made nothing reusable: neither the same command again nor
    //    another command presenting the approval executes anything.
    for request in ["strand-go", "strand-foreign-after"] {
        let again = fixture.dispatch_named(
            EXEC_TOOL,
            Some(fixture.resource.clone()),
            arguments.clone(),
            request,
        );
        assert!(again.is_err(), "{request}: {again:?}");
    }
    assert_eq!(fixture.world.effects.load(Ordering::SeqCst), 1);
    assert_eq!(fixture.world.calls().len(), 2);
    unchanged("post-recovery retries")?;
    Ok(())
}

#[test]
fn a_declaration_decided_strand_recovers_the_original_bare_request() -> Result<(), &'static str> {
    let mut fixture = Fixture::durable();
    fixture.seed_bridge_run();
    let run = fixture.scope.run.clone().expect("run");
    {
        let mut ledger = fixture.ledger.lock().map_err(|_| "ledger poisoned")?;
        let plan = ledger
            .replace_plan(
                &run,
                "Declared exact recovery",
                &[odin_ledger::plan::TodoSpec {
                    id: odin_domain::TodoId::new("todo:declared-strand").expect("todo"),
                    title: "Declared exact recovery".into(),
                    status: odin_ledger::plan::TodoStatus::Pending,
                }],
                0,
                OffsetDateTime::UNIX_EPOCH,
            )
            .expect("plan");
        ledger
            .accept_plan(
                &run,
                plan.revision,
                "operator:fixture",
                OffsetDateTime::UNIX_EPOCH,
            )
            .expect("accept");
        ledger
            .connection()
            .execute_batch(
                "CREATE TEMP TRIGGER fixture_refuse_prepare BEFORE INSERT ON operation_journal \
             BEGIN SELECT RAISE(ABORT, 'fixture: no preparation after consumption'); END;",
            )
            .expect("private prepare fault");
    }
    fixture.material_source.declare_decided(EXEC_CAPABILITY);
    let arguments = json!({"value": "declared"});
    let refused = fixture
        .dispatch_named(
            EXEC_TOOL,
            Some(fixture.resource.clone()),
            arguments.clone(),
            "declared-strand",
        )
        .expect_err("prepare fails after implicit consumption");
    assert!(matches!(
        refused,
        HostToolOperationError::Authority(odin_kernel::OperationRejection::Durable(_))
    ));
    let correlation = correlation_for(&fixture.session, "declared-strand").expect("correlation");
    let command_id = CommandId::new(format!("odin.omp.host_tool:{correlation}")).expect("command");
    fixture.reopen_ledger();
    let (command, approval, binding) = {
        let ledger = fixture.ledger.lock().map_err(|_| "ledger poisoned")?;
        let command = ledger
            .command(&command_id)
            .expect("command read")
            .expect("command");
        let approval = ledger
            .approval(command.approval_id.as_ref().expect("implicit approval"))
            .expect("approval read")
            .expect("approval");
        assert_eq!(approval.status, ApprovalStatus::Consumed);
        assert_eq!(approval.consumed_by_command_id.as_ref(), Some(&command_id));
        assert_eq!(
            approval.decided_by,
            Some(format!("declaration:{}", command.issuer))
        );
        let binding = ledger
            .host_command_binding(&command_id)
            .expect("binding read")
            .expect("binding");
        (command, approval, binding)
    };
    assert!(fixture.row("declared-strand").is_none());
    assert_eq!(fixture.world.effects.load(Ordering::SeqCst), 0);
    let recovered = fixture
        .dispatch_named(
            EXEC_TOOL,
            Some(fixture.resource.clone()),
            arguments.clone(),
            "declared-strand",
        )
        .expect("the original bare request resumes without learning an internal approval id");
    assert_eq!(recovered["handledBy"], EXEC_HANDLER);
    assert_eq!(fixture.world.effects.load(Ordering::SeqCst), 1);
    assert_eq!(
        fixture
            .row("declared-strand")
            .expect("operation")
            .effect_state,
        odin_domain::operation::EffectState::Committed
    );
    let _replay = fixture.dispatch_named(
        EXEC_TOOL,
        Some(fixture.resource.clone()),
        arguments.clone(),
        "declared-strand",
    );
    let mut foreign = arguments.clone();
    foreign["approvalId"] = json!(approval.approval_id.to_string());
    assert!(fixture
        .dispatch_named(
            EXEC_TOOL,
            Some(fixture.resource.clone()),
            foreign,
            "declared-foreign",
        )
        .is_err());
    assert!(fixture.row("declared-foreign").is_none());
    assert_eq!(fixture.world.effects.load(Ordering::SeqCst), 1);
    {
        let ledger = fixture.ledger.lock().map_err(|_| "ledger poisoned")?;
        assert_eq!(
            ledger.command(&command_id).expect("command read"),
            Some(command)
        );
        assert_eq!(
            ledger
                .approval(&approval.approval_id)
                .expect("approval read"),
            Some(approval.clone())
        );
        assert_eq!(
            ledger
                .host_command_binding(&command_id)
                .expect("binding read"),
            Some(binding)
        );
        assert_eq!(ledger.approvals().expect("approvals").len(), 1);
    }
    fixture
        .dispatch_named(
            EXEC_TOOL,
            Some(fixture.resource.clone()),
            arguments,
            "declared-fresh-action",
        )
        .expect("a fresh declared action is not suppressed by an earlier action's content");
    assert_eq!(fixture.world.effects.load(Ordering::SeqCst), 2);
    assert_eq!(
        fixture
            .ledger
            .lock()
            .map_err(|_| "ledger poisoned")?
            .approvals()
            .expect("approvals")
            .len(),
        2
    );
    Ok(())
}
