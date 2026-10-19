//! Authorization failures must not consume approvals or reach the executor.

use std::sync::atomic::Ordering;

use crate::host_tools::operations::correlation_for;
use crate::host_tools::operations::dispatch::{
    executor_binding, invocation_target, journal_invocation_command, NO_NARROWING,
};
use odin_domain::knowledge::ResourceConstraint;
use odin_domain::operation::EffectState;
use odin_domain::{ApprovalId, ApprovalStatus, CapabilityId, CommandId, PlanId};
use odin_kernel::{
    arguments_digest, authorize, ApprovalDecision, ApprovalGate, AuthorizationOutcome,
    AuthorizationRejection, DecisionOutcome, InvokeRequest, PlanGate, ToolInvocation,
};
use serde_json::{json, Value};
use time::OffsetDateTime;

use super::fixture::{Fixture, EXEC_CAPABILITY, EXEC_EXTRACTOR, EXEC_HANDLER, NOW_MS};

fn invocation(
    fixture: &Fixture,
    listing_digest: odin_domain::knowledge::CapabilityListingDigest,
    correlation_id: &odin_types::CorrelationId,
    approval_id: Option<ApprovalId>,
    expected_revision: Option<i64>,
    resource: ResourceConstraint,
    arguments: Value,
) -> ToolInvocation {
    ToolInvocation {
        command_id: CommandId::new(format!("command:{correlation_id}")).expect("command id"),
        capability_id: CapabilityId::new(EXEC_CAPABILITY).expect("exec capability id"),
        capability_version: 1,
        listing_digest,
        arguments_digest: arguments_digest(&arguments),
        arguments,
        target: invocation_target(&fixture.scope).expect("run target"),
        executor_binding: Some(executor_binding(&fixture.scope, None).expect("scope binding")),
        expected_revision,
        plan_id: Some(PlanId::new("plan.fixture").expect("plan id")),
        approval_id,
        resource: Some(resource),
    }
}

#[test]
fn approval_and_resource_precedence_reach_the_real_executor_once() {
    let fixture = Fixture::new();
    let correlation = correlation_for(&fixture.session, "request-approved").expect("correlation");
    let arguments = json!({"value": "approved"});
    let (fresh, listing, _) = fixture
        .operations
        .fresh_listing(&fixture.binding, &fixture.session, NOW_MS)
        .expect("fresh listing");
    let no_approval = invocation(
        &fixture,
        listing.digest,
        &correlation,
        None,
        None,
        fixture.resource.clone(),
        arguments.clone(),
    );
    let outcome = {
        let mut ledger = fixture.ledger.lock().expect("ledger lock");
        journal_invocation_command(&mut ledger, &no_approval, &correlation, &fresh, NOW_MS)
            .expect("the unapproved intent journals before the gate");
        let mut gate = ApprovalGate::new(&mut ledger);
        authorize(
            odin_kernel::policy::AuthorizationEnvironment {
                authority: fresh.get(),
                policy: &fixture.binding.policy,
                contracts: &fixture.contracts,
                schemas: &*fixture.schemas,
                listing: &listing,
            },
            &no_approval,
            PlanGate::Accepted,
            &mut gate,
            NOW_MS,
        )
        .expect("authorization result")
    };
    assert!(matches!(
        outcome,
        AuthorizationOutcome::Rejected(AuthorizationRejection::NeedsApproval { .. })
    ));

    let approval_id = ApprovalId::new("approval.fixture").expect("approval id");
    let approval_scope = odin_kernel::ApprovalScope {
        target_kind: no_approval.target.kind.clone(),
        target_id: no_approval.target.id.clone(),
        capability_id: no_approval.capability_id.clone(),
        arguments_digest: no_approval.arguments_digest,
    };
    assert_eq!(approval_scope.target_kind, "run");
    assert_eq!(
        approval_scope.target_id,
        fixture.scope.run.as_ref().expect("bound run").as_str()
    );
    let approved_revision = {
        let mut ledger = fixture.ledger.lock().expect("ledger lock");
        let mut gate = ApprovalGate::new(&mut ledger);
        let requested = gate
            .request(odin_kernel::NewApproval {
                approval_id: approval_id.clone(),
                issuer: "fixture-requester".to_owned(),
                scope: approval_scope,
                requested_at: OffsetDateTime::UNIX_EPOCH,
                expires_at: OffsetDateTime::UNIX_EPOCH + time::Duration::hours(1),
            })
            .expect("request approval");
        match gate
            .decide(
                &approval_id,
                requested.revision,
                ApprovalDecision::Approve {
                    evidence_ref: Some("operator:fixture".to_owned()),
                },
                "fixture-operator",
                OffsetDateTime::UNIX_EPOCH + time::Duration::seconds(1),
            )
            .expect("approve exact scope")
        {
            DecisionOutcome::Approved(approval) => approval.revision,
            other => panic!("unexpected approval outcome: {other:?}"),
        }
    };

    let (fresh, listing, _) = fixture
        .operations
        .fresh_listing(&fixture.binding, &fixture.session, NOW_MS)
        .expect("fresh listing after approval");
    let wrong_resource = invocation(
        &fixture,
        listing.digest,
        &correlation,
        Some(approval_id.clone()),
        Some(approved_revision),
        ResourceConstraint::Named {
            kind: "workspace".to_owned(),
            value: "other".to_owned(),
        },
        arguments.clone(),
    );
    let outcome = {
        let mut ledger = fixture.ledger.lock().expect("ledger lock");
        journal_invocation_command(&mut ledger, &wrong_resource, &correlation, &fresh, NOW_MS)
            .expect("the denied intent journals before the gate");
        let mut gate = ApprovalGate::new(&mut ledger);
        authorize(
            odin_kernel::policy::AuthorizationEnvironment {
                authority: fresh.get(),
                policy: &fixture.binding.policy,
                contracts: &fixture.contracts,
                schemas: &*fixture.schemas,
                listing: &listing,
            },
            &wrong_resource,
            PlanGate::Accepted,
            &mut gate,
            NOW_MS,
        )
        .expect("resource denial")
    };
    assert!(matches!(
        outcome,
        AuthorizationOutcome::Rejected(AuthorizationRejection::ResourceDenied { .. })
    ));
    {
        let ledger = fixture.ledger.lock().expect("ledger lock");
        let approval = ledger
            .approval(&approval_id)
            .expect("approval is readable")
            .expect("approved approval record");
        assert_eq!(
            approval.status,
            ApprovalStatus::Approved,
            "resource denial must leave the approval unconsumed"
        );
    }

    let (fresh, listing, _) = fixture
        .operations
        .fresh_listing(&fixture.binding, &fixture.session, NOW_MS)
        .expect("fresh listing for approved invocation");
    let approved = invocation(
        &fixture,
        listing.digest,
        &correlation,
        Some(approval_id.clone()),
        Some(approved_revision),
        fixture.resource.clone(),
        arguments,
    );
    let authorized = {
        let mut ledger = fixture.ledger.lock().expect("ledger lock");
        journal_invocation_command(&mut ledger, &approved, &correlation, &fresh, NOW_MS)
            .expect("the approved intent journals before the gate");
        let mut gate = ApprovalGate::new(&mut ledger);
        match authorize(
            odin_kernel::policy::AuthorizationEnvironment {
                authority: fresh.get(),
                policy: &fixture.binding.policy,
                contracts: &fixture.contracts,
                schemas: &*fixture.schemas,
                listing: &listing,
            },
            &approved,
            PlanGate::Accepted,
            &mut gate,
            NOW_MS,
        )
        .expect("approved authorization")
        {
            AuthorizationOutcome::Authorized(proof) => *proof,
            AuthorizationOutcome::Rejected(reason) => {
                panic!("approved invocation was rejected: {reason:?}")
            }
        }
    };
    let decision = fixture
        .operations
        .authority()
        .invoke_authorized(
            authorized,
            &InvokeRequest {
                capsule_id: fixture.binding.capsule_id.clone(),
                correlation_id: correlation.clone(),
                requested_ceiling: NO_NARROWING,
            },
        )
        .expect("approved invocation commits");
    assert_eq!(decision.state, EffectState::Committed);
    assert!(!decision.replay);
    let result = fixture
        .operations
        .executor()
        .take_result(&correlation)
        .expect("real handler result is relayed");
    assert_eq!(result["handledBy"], EXEC_HANDLER);
    assert_eq!(
        fixture.world.calls(),
        vec![EXEC_HANDLER, EXEC_EXTRACTOR],
        "resource denial did not consume approval or reach a handler"
    );
    assert_eq!(fixture.world.effects.load(Ordering::SeqCst), 1);
    {
        let ledger = fixture.ledger.lock().expect("ledger lock");
        let approval = ledger
            .approval(&approval_id)
            .expect("consumed approval is readable")
            .expect("consumed approval record");
        assert_eq!(approval.status, ApprovalStatus::Consumed);
        assert_eq!(
            approval.consumed_by_command_id.as_ref(),
            Some(&approved.command_id),
            "the approval is consumed by exactly the journaled command"
        );
        let command = ledger
            .command(&approved.command_id)
            .expect("journaled command is readable")
            .expect("the consuming command row exists");
        assert_eq!(command.idempotency_key, approved.command_id.to_string());
        assert_eq!(command.correlation_id, correlation.as_str());
        assert_eq!(command.arguments_hash, approved.arguments_digest);
        assert_eq!(command.capability_id, approved.capability_id);
        assert_eq!(command.target_kind, approved.target.kind);
        assert_eq!(command.target_id, approved.target.id);
    }
}
