//! Protected invariant: a fresh provisioned authority commits exactly once
//! with exact durable bindings — replay, conflicting payload/scope, and
//! revocation never re-execute; policy, schema, resource, and pre-world
//! refusals fail before any internal dispatch; pre-start rejection aborts
//! while post-handler failure is durably in doubt; the plan gate reflects
//! only recorded matching acceptance; and a delegated child requires a
//! still-verifying parent authority.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::Ordering;
use std::sync::Arc;

use odin_domain::knowledge::ResourceConstraint;
use odin_domain::operation::EffectState;
use odin_domain::{CapabilityId, Digest, ProjectId, Scope, SessionId};
use odin_kernel::{
    AuthorizationRejection, ExecutorFault, LedgerRevocations, MintRequest, PlanGate,
    Reconciliation, RevocationStore, TokenError,
};
use odin_ledger::operation as operation_store;
use serde_json::json;
use time::OffsetDateTime;

use crate::host_tools::operations::dispatch::executor_binding;
use crate::host_tools::operations::{
    admission_digest, correlation_for, resolve_session_generation, seat_operation_policy,
    session_capsule_id, HostToolOperationError, SeatOperationPolicyInputs, SessionOperationBinding,
    SessionOperationContext,
};
use crate::host_tools::{HostInvocation, HostToolError};

use super::fixture::{
    Fixture, NOW_MS, READ_CAPABILITY, READ_EXTRACTOR, READ_HANDLER, READ_TOOL, UNBOUND_MODEL_TOOL,
};

#[test]
fn fresh_listing_policy_resource_commit_and_exact_bindings() {
    let fixture = Fixture::new();
    let listing = fixture
        .operations
        .session_listing(&fixture.binding, &fixture.session)
        .expect("fresh provisioned token produces a listing");
    assert_eq!(listing.seat_token_id, fixture.token_id);
    assert_eq!(listing.tools.len(), 2);
    let listed = listing
        .tools
        .iter()
        .find(|tool| tool.capability_id.as_str() == READ_CAPABILITY)
        .expect("read capability is listed");
    assert_eq!(listed.resource_constraints, vec![fixture.resource.clone()]);

    let result = fixture
        .dispatch(json!({"value": "alpha"}), "request-commit")
        .expect("authorized dispatch commits");
    assert_eq!(result["handledBy"], READ_HANDLER);
    assert_eq!(result["value"], "alpha");
    assert_eq!(
        fixture.world.calls(),
        vec![READ_HANDLER, READ_EXTRACTOR],
        "the permit resolves the exact handler then exact extractor"
    );
    assert_eq!(fixture.world.effects.load(Ordering::SeqCst), 1);

    let row = fixture
        .row("request-commit")
        .expect("durable operation row");
    assert_eq!(row.effect_state, EffectState::Committed);
    assert_eq!(row.token_id.as_str(), fixture.token_id.as_str());
    assert_eq!(
        row.executor_id.as_str(),
        odin_kernel::PreparedEffect::OMP_HOST_EXECUTOR
    );
    let recorded =
        odin_kernel::RecordedBinding::parse(&row).expect("durable prepared binding verifies");
    assert_eq!(
        recorded.executor_binding,
        Some(executor_binding(&fixture.scope, None).expect("canonical scope binding"))
    );
    assert_eq!(
        Reconciliation::decode(&row.reconciliation_json).pre_world,
        odin_kernel::PreWorld::Absent
    );
    let evidence = json!({
        "extractedBy": READ_EXTRACTOR,
        "output": result,
    });
    let evidence_bytes = odin_strict_json::canonicalize(&evidence).expect("canonical evidence");
    assert_eq!(
        row.evidence_digest,
        Some(Digest::hash(&evidence_bytes).to_string())
    );
    let usage = operation_store::usage(
        fixture.ledger.lock().expect("ledger lock").connection(),
        fixture.session.as_str(),
    )
    .expect("usage row");
    assert_eq!(usage.requests, 1);
    assert_eq!(usage.stops, 0);
    assert_eq!(usage.spend, 0);
}

#[test]
fn replay_conflict_and_revocation_never_reexecute() {
    let fixture = Fixture::new();
    fixture
        .dispatch(json!({"value": "alpha"}), "request-replay")
        .expect("first dispatch commits");
    let replay = fixture
        .dispatch(json!({"value": "alpha"}), "request-replay")
        .expect_err("identical retry is a typed replay");
    assert!(matches!(replay, HostToolOperationError::Replayed));
    assert_eq!(fixture.world.effects.load(Ordering::SeqCst), 1);
    assert_eq!(fixture.world.calls(), vec![READ_HANDLER, READ_EXTRACTOR]);

    let correlation = correlation_for(&fixture.session, "request-replay").expect("correlation");
    let conflict = fixture
        .dispatch(json!({"value": "changed"}), "request-replay")
        .expect_err("changed payload under one correlation conflicts");
    assert!(matches!(
        conflict,
        HostToolOperationError::Authority(
            odin_kernel::OperationRejection::DuplicateConflict {
                correlation_id
            }
        ) if correlation_id == correlation
    ));
    assert_eq!(fixture.world.effects.load(Ordering::SeqCst), 1);
    let changed_scope = Scope {
        project: Some(ProjectId::new("project.changed").expect("changed project id")),
        ..fixture.scope.clone()
    };
    let scope_conflict = fixture
        .operations
        .dispatch_tool(
            SessionOperationContext {
                binding: &fixture.binding,
                session: &fixture.session,
                scope: &changed_scope,
                execution: None,
            },
            READ_TOOL,
            Some(fixture.resource.clone()),
            json!({"value": "alpha"}),
            "request-replay",
        )
        .expect_err("changed scope under one correlation conflicts");
    assert!(matches!(
        scope_conflict,
        HostToolOperationError::Authority(
            odin_kernel::OperationRejection::DuplicateConflict {
                correlation_id
            }
        ) if correlation_id == correlation
    ));
    assert_eq!(fixture.world.effects.load(Ordering::SeqCst), 1);

    {
        let ledger = fixture.ledger.lock().expect("ledger lock");
        let mut revocations = LedgerRevocations::new(&ledger);
        revocations
            .revoke(&fixture.token_id, NOW_MS)
            .expect("durable token revocation");
    }
    let revoked = fixture
        .dispatch(json!({"value": "blocked"}), "request-revoked")
        .expect_err("revoked provisioned token fails fresh verification");
    assert!(matches!(
        revoked,
        HostToolOperationError::Token(TokenError::Revoked { token_id })
            if token_id.as_str() == fixture.token_id.as_str()
    ));
    assert!(fixture.row("request-revoked").is_none());
    assert_eq!(fixture.world.effects.load(Ordering::SeqCst), 1);
}

#[test]
fn policy_schema_resource_and_pre_world_fail_before_internal_dispatch() {
    let fixture = Fixture::new();
    let unbound = fixture
        .dispatch_named(
            UNBOUND_MODEL_TOOL,
            None,
            json!({"value": "must-not-run"}),
            "request-unbound",
        )
        .expect_err("static registration alone cannot authorize a familiar tool");
    assert!(matches!(
        unbound,
        HostToolOperationError::UnknownTool { name } if name == UNBOUND_MODEL_TOOL
    ));
    assert!(fixture.world.calls().is_empty());
    assert!(fixture.row("request-unbound").is_none());
    let targetless_scope = Scope {
        run: None,
        ..fixture.scope.clone()
    };
    let targetless = fixture
        .operations
        .dispatch_tool(
            SessionOperationContext {
                binding: &fixture.binding,
                session: &fixture.session,
                scope: &targetless_scope,
                execution: None,
            },
            READ_TOOL,
            Some(fixture.resource.clone()),
            json!({"value": "must-not-run"}),
            "request-targetless",
        )
        .expect_err("capability dispatch without a run target fails closed");
    assert!(matches!(
        targetless,
        HostToolOperationError::Arguments { detail }
            if detail.contains("bind a run target")
    ));
    assert!(fixture.row("request-targetless").is_none());
    assert!(fixture.world.calls().is_empty());

    let mut denied_binding = fixture.binding.clone();
    denied_binding
        .policy
        .denied_capabilities
        .insert(CapabilityId::new(READ_CAPABILITY).expect("read capability"));
    let denied = fixture
        .operations
        .dispatch_tool(
            SessionOperationContext {
                binding: &denied_binding,
                session: &fixture.session,
                scope: &fixture.scope,
                execution: None,
            },
            READ_TOOL,
            Some(fixture.resource.clone()),
            json!({"value": "denied"}),
            "request-policy-denied",
        )
        .expect_err("current policy denial wins");
    assert!(matches!(
        denied,
        HostToolOperationError::Rejected(AuthorizationRejection::Unavailable { .. })
    ));

    let wrong_resource = fixture
        .dispatch_named(
            READ_TOOL,
            Some(ResourceConstraint::Named {
                kind: "workspace".to_owned(),
                value: "other".to_owned(),
            }),
            json!({"value": "denied"}),
            "request-resource-denied",
        )
        .expect_err("non-listed resource is denied");
    assert!(matches!(
        wrong_resource,
        HostToolOperationError::Rejected(AuthorizationRejection::ResourceDenied { .. })
    ));

    let schema = fixture
        .dispatch(json!({"value": 7}), "request-schema-denied")
        .expect_err("schema-invalid payload is rejected");
    assert!(matches!(
        schema,
        HostToolOperationError::Authority(odin_kernel::OperationRejection::SchemaInvalid { .. })
    ));

    let pre_world = fixture
        .dispatch(
            json!({
                "value": "denied",
                "preWorld": Digest::hash(b"caller claimed pre-world").to_string()
            }),
            "request-pre-world-denied",
        )
        .expect_err("unobservable declared pre-world is rejected");
    assert!(matches!(
        pre_world,
        HostToolOperationError::Authority(odin_kernel::OperationRejection::PreWorldMismatch { .. })
    ));

    for request_id in [
        "request-unbound",
        "request-policy-denied",
        "request-resource-denied",
        "request-schema-denied",
        "request-pre-world-denied",
    ] {
        assert!(
            fixture.row(request_id).is_none(),
            "{request_id} must not create an operation row"
        );
    }
    assert!(fixture.world.calls().is_empty());
    let direct = fixture
        .registry
        .dispatch(
            READ_HANDLER,
            HostInvocation {
                scope: fixture.scope.clone(),
                arguments: json!({"value": "raw"}),
            },
        )
        .expect_err("an internal binding is never name-reachable");
    assert!(matches!(direct, HostToolError::UnknownTool { .. }));
}

#[test]
fn pre_start_rejection_aborts_but_post_handler_failure_is_uncertain() {
    let fixture = Fixture::new();
    let rejected = fixture
        .dispatch(
            json!({"value": "never", "mode": "reject"}),
            "request-rejected",
        )
        .expect_err("pre-start rejection is surfaced");
    assert!(matches!(
        rejected,
        HostToolOperationError::Authority(odin_kernel::OperationRejection::Executor(
            ExecutorFault::Rejected { .. }
        ))
    ));
    assert_eq!(
        fixture
            .row("request-rejected")
            .expect("aborted operation row")
            .effect_state,
        EffectState::Aborted
    );
    assert_eq!(fixture.world.effects.load(Ordering::SeqCst), 0);
    assert_eq!(fixture.world.calls(), vec![READ_HANDLER]);

    let uncertain = fixture
        .dispatch(
            json!({"value": "landed", "mode": "extractor_failure"}),
            "request-uncertain",
        )
        .expect_err("post-handler extractor failure is uncertain");
    assert!(matches!(
        uncertain,
        HostToolOperationError::Authority(odin_kernel::OperationRejection::Executor(
            ExecutorFault::Uncertain { .. }
        ))
    ));
    assert_eq!(
        fixture
            .row("request-uncertain")
            .expect("in-doubt operation row")
            .effect_state,
        EffectState::InDoubt
    );
    assert_eq!(fixture.world.effects.load(Ordering::SeqCst), 1);
    assert_eq!(
        fixture.world.calls(),
        vec![READ_HANDLER, READ_HANDLER, READ_EXTRACTOR]
    );

    let replay = fixture
        .dispatch(
            json!({"value": "landed", "mode": "extractor_failure"}),
            "request-uncertain",
        )
        .expect_err("in-doubt replay remains blocked");
    assert!(matches!(replay, HostToolOperationError::InDoubt));
    assert_eq!(fixture.world.effects.load(Ordering::SeqCst), 1);
    assert_eq!(
        fixture.world.calls(),
        vec![READ_HANDLER, READ_HANDLER, READ_EXTRACTOR],
        "blocked replay must not reach either internal binding"
    );
}

#[test]
fn plan_gate_reflects_only_recorded_matching_acceptance() {
    let fixture = Fixture::new();
    let run = fixture.scope.run.clone().expect("bound run");

    // No plan row: the gate stays Missing with no plan identity.
    let (gate, plan_id) = fixture.operations.plan_gate(&fixture.scope).expect("gate");
    assert!(matches!(gate, PlanGate::Missing));
    assert!(plan_id.is_none());

    // The run row exists in production because the bridge created it;
    // the fixture reproduces the lane foreign-key parent and run
    // through the canonical lane/run APIs before any plan lands.
    fixture.seed_bridge_run();

    // A plan that merely exists stays Draft — never Accepted.
    let plan = {
        let mut ledger = fixture.ledger.lock().expect("ledger lock");
        ledger
            .replace_plan(
                &run,
                "Gate plan",
                &[odin_ledger::plan::TodoSpec {
                    id: odin_domain::TodoId::new("todo:gate").expect("todo id"),
                    title: "Gate todo".to_owned(),
                    status: odin_ledger::plan::TodoStatus::Pending,
                }],
                0,
                OffsetDateTime::UNIX_EPOCH,
            )
            .expect("fixture plan")
    };
    let (gate, plan_id) = fixture.operations.plan_gate(&fixture.scope).expect("gate");
    assert!(matches!(gate, PlanGate::Draft));
    assert_eq!(
        plan_id.expect("plan id").to_string(),
        format!("plan:{}:{}", run.as_str(), plan.revision)
    );

    // Only a recorded acceptance that matches the plan fingerprint makes
    // the gate Accepted.
    {
        let mut ledger = fixture.ledger.lock().expect("ledger lock");
        ledger
            .accept_plan(
                &run,
                plan.revision,
                "operator:fixture",
                OffsetDateTime::UNIX_EPOCH,
            )
            .expect("record acceptance");
    }
    let (gate, _) = fixture.operations.plan_gate(&fixture.scope).expect("gate");
    assert!(matches!(gate, PlanGate::Accepted));
}

#[test]
fn delegated_child_dispatch_requires_a_verifying_parent_authority() {
    let fixture = Fixture::new();
    // A child binding whose parent names a session with no provisioned
    // token must fail the parent-first chain before its own verification.
    let parent_session = SessionId::new("00000000-0000-4000-8000-0000000009a0").expect("session");
    let child_binding = SessionOperationBinding {
        policy: fixture.binding.policy.clone(),
        context_policy_digest: fixture.binding.context_policy_digest,
        capsule_id: session_capsule_id(&fixture.session).expect("capsule id"),
        served_revision: fixture.binding.served_revision,
        parent: Some(Arc::new(crate::host_tools::delegation::ParentSessionLink {
            session: parent_session,
            binding: fixture.binding.clone(),
            run: fixture.scope.run.clone().expect("bound run"),
            depth: 0,
        })),
    };
    let error = fixture
        .operations
        .session_listing(&child_binding, &fixture.session)
        .expect_err("an unverifiable parent must fail the child listing");
    assert!(
        matches!(error, HostToolOperationError::Delegation { .. }),
        "expected a delegation rejection, got {error}"
    );
}

/// Later publications affect new sessions, not the retained material of existing ones.
#[test]
fn sessions_resolve_their_own_publication_generation() {
    let fixture = Fixture::new();
    // Publication 2: the R3 exec capability is REMOVED from the admitted
    // set; the admission digest is the one this publication admits.
    let mut gen2_contracts = fixture.contracts.clone();
    let removed_id = CapabilityId::new(super::fixture::EXEC_CAPABILITY).expect("exec id");
    assert!(
        gen2_contracts.remove(&removed_id).is_some(),
        "exec admitted"
    );
    let gen2_admission = admission_digest(&gen2_contracts, 2).expect("generation 2 admission");
    let gen2_policy = seat_operation_policy(SeatOperationPolicyInputs {
        seat_id: fixture.binding.policy.seat_id.clone(),
        slice_id: fixture.binding.policy.slice_id.clone(),
        lane_id: fixture.binding.policy.lane_id.clone(),
        seat_revision: fixture.binding.policy.seat_revision,
        slice_revision: fixture.binding.policy.slice_revision,
        admission: gen2_admission,
        seat_tool_refs: gen2_contracts.keys().cloned().collect(),
        slice_capabilities: gen2_contracts.keys().cloned().collect(),
        project_capabilities: gen2_contracts.keys().cloned().collect(),
        lane_capabilities: gen2_contracts.keys().cloned().collect(),
        denied_capabilities: BTreeSet::new(),
        denied_tools: BTreeSet::new(),
        resource_constraints: BTreeMap::new(),
        seat_categories: BTreeSet::from(["tester".to_owned()]),
    });
    let session2 = SessionId::new("00000000-0000-4000-8000-0000000002a0").expect("session");
    fixture.material_source.add_generation(
        2,
        &gen2_contracts,
        &gen2_policy,
        fixture.binding.policy.seat_id.clone(),
        fixture.binding.policy.lane_id.clone(),
    );
    // The fresh open's token: minted bound to publication 2, the opener's
    // captured generation.
    let issuer = odin_kernel::TokenIssuer::new(fixture.signing_key.clone()).expect("token issuer");
    let token2 = issuer
        .mint_bound(
            odin_kernel::MintRequest {
                seat: fixture.binding.policy.seat_id.clone(),
                slice: fixture.binding.policy.slice_id.clone(),
                lane: fixture.binding.policy.lane_id.clone(),
                session: session2.clone(),
                seat_revision: fixture.binding.policy.seat_revision,
                slice_revision: fixture.binding.policy.slice_revision,
                capability_policy_digest: gen2_admission,
                context_policy_digest: gen2_policy.context_policy_digest,
                issued_at_ms: NOW_MS,
                expires_at_ms: super::fixture::TOKEN_EXPIRES_MS,
                entropy: b"publication two fresh open",
            },
            2,
        )
        .expect("mint generation two token");
    std::fs::write(
        fixture
            .token_root
            .join(format!("{}.json", session2.as_str())),
        serde_json::to_vec(&token2).expect("encode generation two token"),
    )
    .expect("write generation two token");
    let binding2 = SessionOperationBinding {
        policy: gen2_policy.policy,
        context_policy_digest: gen2_policy.context_policy_digest,
        capsule_id: session_capsule_id(&session2).expect("capsule id"),
        served_revision: 2,
        parent: None,
    };

    // The NEW open resolves the N+1 generation: its listing admits exactly
    // publication 2's set — the removed capability is gone.
    let listing2 = fixture
        .operations
        .session_listing(&binding2, &session2)
        .expect("the fresh open lists under its own publication");
    assert!(!listing2
        .tools
        .iter()
        .any(|tool| tool.capability_id.as_str() == super::fixture::EXEC_CAPABILITY));
    assert!(listing2
        .tools
        .iter()
        .any(|tool| tool.capability_id.as_str() == super::fixture::READ_CAPABILITY));
    // Dispatching the removed capability refuses at generation 2's own
    // tool index — never routed through the older admission.
    let removed = fixture.operations.dispatch_tool(
        SessionOperationContext {
            binding: &binding2,
            session: &session2,
            scope: &fixture.scope,
            execution: None,
        },
        super::fixture::EXEC_TOOL,
        None,
        json!({"value": "x"}),
        "generation-two-removed",
    );
    assert!(
        matches!(removed, Err(HostToolOperationError::UnknownTool { .. })),
        "the removed capability must refuse for the new generation"
    );

    // The original session retains the capability removed from publication 2.
    let listing1 = fixture
        .operations
        .session_listing(&fixture.binding, &fixture.session)
        .expect("the existing session keeps its own generation");
    assert!(listing1
        .tools
        .iter()
        .any(|tool| tool.capability_id.as_str() == super::fixture::EXEC_CAPABILITY));

    // An unknown revision refuses typed — never current material.
    match fixture.operations.material_at(3) {
        Err(HostToolOperationError::Generation { .. }) => {}
        Err(error) => panic!("expected the Generation refusal, got: {error}"),
        Ok(_) => panic!("revision 3 must refuse; current material is never substituted"),
    }
}

#[test]
fn resolution_rejects_generation_mismatch_against_a_frozen_binding() {
    let fixture = Fixture::new();
    let issuer = odin_kernel::TokenIssuer::new(fixture.signing_key.clone()).expect("token issuer");
    let mint = |session: &SessionId, revision: u64| {
        let entropy = format!("resolution-fixture:{revision}").into_bytes();
        issuer
            .mint_bound(
                MintRequest {
                    seat: fixture.binding.policy.seat_id.clone(),
                    slice: fixture.binding.policy.slice_id.clone(),
                    lane: fixture.binding.policy.lane_id.clone(),
                    session: session.clone(),
                    seat_revision: fixture.binding.policy.seat_revision,
                    slice_revision: fixture.binding.policy.slice_revision,
                    capability_policy_digest: fixture.binding.policy.capability_policy_digest,
                    context_policy_digest: fixture.binding.context_policy_digest,
                    issued_at_ms: NOW_MS,
                    expires_at_ms: super::fixture::TOKEN_EXPIRES_MS,
                    entropy: &entropy,
                },
                revision,
            )
            .expect("mint resolution fixture token")
    };
    let bound = SessionId::new("00000000-0000-4000-8000-000000000b01").expect("session");
    let fresh = SessionId::new("00000000-0000-4000-8000-000000000b02").expect("session");
    let token1 = mint(&bound, 1);
    let token2 = mint(&fresh, 2);

    // Bound session + matching generation: resolves to the binding.
    assert_eq!(
        resolve_session_generation(&bound, &token1, Some(1), fixture.material_source.as_ref(),)
            .expect("matching generation resolves"),
        1
    );
    // Bound session + a validly signed NEWER claim: typed mismatch — the
    // binding is frozen and no renewal silently rebinds it.
    let mismatch =
        resolve_session_generation(&bound, &token2, Some(1), fixture.material_source.as_ref())
            .expect_err("a newer claim against a frozen binding must refuse");
    assert!(
        mismatch.contains("bound to publication 1"),
        "expected the frozen-binding mismatch, got: {mismatch}"
    );
    // Bound session + legacy token (claim replaced): refuses, never rebinds.
    let mut stripped = token1.clone();
    stripped.served_revision = None;
    let legacy =
        resolve_session_generation(&bound, &stripped, Some(1), fixture.material_source.as_ref())
            .expect_err("a claim-less token on a bound session must refuse");
    assert!(legacy.contains("predates revision binding"));
    // Genuinely new open: adopts the token's exact signed generation.
    assert_eq!(
        resolve_session_generation(&fresh, &token2, None, fixture.material_source.as_ref(),)
            .expect("a new open adopts the signed generation"),
        2
    );
}

/// An ask to a conversation seat is an escalation; task creation and asks
/// to worker seats stay bounded.
#[test]
fn a_workers_ask_to_a_conversation_seat_escalates_past_the_depth_law() {
    use crate::host_tools::operations::dispatch::delegates_beyond_depth;
    let fixture = Fixture::new();
    let conversation: std::collections::BTreeSet<odin_domain::SeatId> =
        [odin_domain::SeatId::new("sinmara").expect("seat")].into();
    let mut ask = fixture
        .contracts
        .values()
        .next()
        .expect("a fixture contract")
        .clone();
    ask.delegate_to = Some(odin_domain::SeatId::new("sinmara").expect("seat"));
    assert!(!delegates_beyond_depth(&ask, &conversation));
    ask.delegate_to = Some(odin_domain::SeatId::new("kubert").expect("seat"));
    assert!(delegates_beyond_depth(&ask, &conversation));
    let mut create = ask.clone();
    create.delegate_to = None;
    create.id =
        odin_domain::CapabilityId::new(crate::host_tools::delegation::TASK_CREATE_CAPABILITY)
            .expect("id");
    assert!(delegates_beyond_depth(&create, &conversation));
}
