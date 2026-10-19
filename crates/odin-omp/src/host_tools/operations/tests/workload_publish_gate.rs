//! Retained-draft validation must precede approval creation and consumption.
//! These tests use the production schema and store but a fixture publish handler.
//! Registry commits are covered in `odin-cli/src/odind/tests/workload_authoring.rs`.

use std::os::unix::fs::PermissionsExt;
use std::sync::atomic::Ordering;

use odin_domain::{ApprovalId, ApprovalStatus, CommandId, EffectClass};
use odin_kernel::{
    arguments_digest, ApprovalDecision, ApprovalGate, AuthorizationRejection, DecisionOutcome,
};
use odin_ledger::approval::Approval;
use serde_json::{json, Value};
use time::OffsetDateTime;

use crate::host_tools::operations::{correlation_for, HostToolOperationError};
use crate::host_tools::workload_drafts::{test_material, WorkloadDraftRecord, WorkloadDraftStore};

use super::fixture::{
    Fixture, WORKLOAD_PUBLISH_CAPABILITY, WORKLOAD_PUBLISH_EXTRACTOR, WORKLOAD_PUBLISH_HANDLER,
    WORKLOAD_PUBLISH_TOOL,
};

const PROFILE_ID: &str = "odind-kubert-7c31b9e2";
/// D1 and D2 differ only in description, yielding distinct digests and approval scopes.
fn rendered_d1() -> String {
    test_material::declaration("D1 workload declaration for the governed publish proof")
}

fn rendered_d2() -> String {
    test_material::declaration("D2 workload declaration for the governed publish proof")
}

/// The registry revision every fixture draft binds as its publication
/// target. Within one test every retain, demand, and retry uses the same
/// bound revision, so only the digest distinguishes approved scopes.
const BOUND_REVISION: u64 = 4;

/// Retains one compiled draft through the real sealed store: the exact
/// bytes live under (profile id, blake3 digest, bound revision) — the
/// same key the dispatch pre-gate loads. `profile` selects whose draft
/// the bytes belong to: distinct profiles are distinct identities even
/// over identical bytes.
fn retain(fixture: &Fixture, profile: &str, digest: &str, rendered: &str) {
    let store = WorkloadDraftStore::seal(&fixture.root).expect("seal draft store");
    store
        .retain(&WorkloadDraftRecord {
            declaration_digest: digest.to_owned(),
            profile_id: profile.to_owned(),
            rendered_toml: rendered.to_owned(),
            bound_registry_revision: BOUND_REVISION,
        })
        .expect("retain compiled draft");
}

/// Include the presented approval id because the approved scope digests the complete retry arguments.
fn publish_arguments(profile: &str, digest: &str, approval_id: &str) -> Value {
    json!({
        "profileId": profile,
        "declarationDigest": digest,
        "expectedRegistryRevision": BOUND_REVISION,
        "approvalId": approval_id,
    })
}

fn digest_of(rendered: &str) -> String {
    odin_domain::Digest::hash(rendered.as_bytes()).to_string()
}

/// Drives the governed mint through the real dispatch: one first publish
/// presenting the placeholder approval id the model can only have before
/// its first refusal. Returns the durable exact-scope request the gate
/// minted.
fn mint_publish_approval(fixture: &Fixture, digest: &str, request_id: &str) -> (ApprovalId, i64) {
    let demanded = fixture
        .dispatch_named(
            WORKLOAD_PUBLISH_TOOL,
            Some(fixture.resource.clone()),
            publish_arguments(PROFILE_ID, digest, "pending"),
            request_id,
        )
        .expect_err("the first publish dispatch demands approval");
    match demanded {
        HostToolOperationError::ApprovalRequired {
            capability_id,
            effect_class,
            approval_id,
            revision,
        } => {
            assert_eq!(
                capability_id.as_str(),
                WORKLOAD_PUBLISH_CAPABILITY,
                "the demand names the publish capability"
            );
            assert!(
                matches!(effect_class, EffectClass::R3),
                "publish is an R3 capability, got {effect_class:?}"
            );
            (approval_id, revision)
        }
        other => panic!("expected the actionable approval demand, got {other:?}"),
    }
}

fn approve(fixture: &Fixture, approval_id: &ApprovalId, revision: i64) {
    let mut ledger = fixture.ledger.lock().expect("ledger lock");
    let mut gate = ApprovalGate::new(&mut ledger);
    match gate
        .decide(
            approval_id,
            revision,
            ApprovalDecision::Approve {
                evidence_ref: Some("scenario3-operator".to_owned()),
            },
            "fixture-operator",
            OffsetDateTime::UNIX_EPOCH + time::Duration::seconds(1),
        )
        .expect("decide the minted publish approval")
    {
        DecisionOutcome::Approved(_) => {}
        other => panic!("expected Approved, got {other:?}"),
    }
}

fn workload_publish_approvals(fixture: &Fixture) -> Vec<Approval> {
    fixture
        .ledger
        .lock()
        .expect("ledger lock")
        .approvals()
        .expect("approval rows")
        .into_iter()
        .filter(|approval| approval.scope.capability_id.as_str() == WORKLOAD_PUBLISH_CAPABILITY)
        .collect()
}

/// Seeds the durable accepted plan the R3 dispatch plan gate requires for
/// the fixture's bound run.
fn seed_plan(fixture: &Fixture) {
    let run = fixture.scope.run.clone().expect("bound run");
    let mut ledger = fixture.ledger.lock().expect("ledger lock");
    let plan = ledger
        .replace_plan(
            &run,
            "Govern the workload.publish proof",
            &[odin_ledger::plan::TodoSpec {
                id: odin_domain::TodoId::new("todo:workload-publish-proof").expect("todo id"),
                title: "Publish the approved workload profile".to_owned(),
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

#[test]
fn approved_d1_survives_d2_redraft_and_publish_selects_exact_retained_d1() {
    let fixture = Fixture::for_workload_publish();
    fixture.seed_bridge_run();
    seed_plan(&fixture);

    // -- Draft D1: the real store retains the exact compiled bytes under
    //    the real blake3 digest of those bytes at the bound revision.
    let rendered1 = rendered_d1();
    let d1 = digest_of(&rendered1);
    retain(&fixture, PROFILE_ID, &d1, &rendered1);

    // -- The first publish dispatch presents the placeholder id and is
    //    refused: the gate mints the durable request over exactly the
    //    retry shape (the same arguments with the minted id), issued by
    //    the dispatching seat. Nothing executed.
    let (minted, minted_revision) = mint_publish_approval(&fixture, &d1, "publish-demand");
    {
        let ledger = fixture.ledger.lock().expect("ledger lock");
        let approval = ledger
            .approval(&minted)
            .expect("approval readable")
            .expect("the minted approval is durable");
        assert_eq!(approval.status, ApprovalStatus::Requested);
        assert_eq!(
            approval.issuer,
            fixture.scope.seat.as_ref().expect("bound seat").as_str(),
            "the mint's issuer is the dispatching seat, not the model"
        );
        assert_eq!(approval.scope.target_kind, "run");
        assert_eq!(
            approval.scope.target_id,
            fixture.scope.run.as_ref().expect("bound run").as_str()
        );
        assert_eq!(
            approval.scope.arguments_digest,
            arguments_digest(&publish_arguments(PROFILE_ID, &d1, minted.as_str())),
            "the minted scope binds exactly the retry arguments: same digest, \
             same bound revision, same approval id"
        );
    }
    assert!(
        fixture.world.calls().is_empty(),
        "nothing executed before the owner decision"
    );

    // -- The operator approves the MINTED row: the scope is exactly
    //    Approved and still unconsumed.
    approve(&fixture, &minted, minted_revision);
    let rows = workload_publish_approvals(&fixture);
    assert_eq!(rows.len(), 1, "exactly one publish approval exists");
    assert_eq!(rows[0].approval_id, minted);
    assert_eq!(rows[0].status, ApprovalStatus::Approved);
    assert_eq!(rows[0].consumed_by_command_id, None);

    // -- A redraft retains D2 — a different compiled declaration, a
    //    distinct scope. The approved D1 scope must not stretch to it.
    let rendered2 = rendered_d2();
    let d2 = digest_of(&rendered2);
    retain(&fixture, PROFILE_ID, &d2, &rendered2);

    // -- The approved retry: the SAME original approved digest at the SAME
    //    bound revision and the ACTUAL minted approval id — the placeholder
    //    is gone. The exact approved scope consumes once.
    let retry = publish_arguments(PROFILE_ID, &d1, minted.as_str());
    fixture
        .dispatch_named(
            WORKLOAD_PUBLISH_TOOL,
            Some(fixture.resource.clone()),
            retry.clone(),
            "publish-d1",
        )
        .expect("the approved D1 publish succeeds");

    // -- Exactly one consumption, by exactly the journaled host command of
    //    the approved dispatch, over exactly the approved scope.
    let correlation = correlation_for(&fixture.session, "publish-d1").expect("correlation");
    let consumed_command =
        CommandId::new(format!("odin.omp.host_tool:{correlation}")).expect("command id");
    let rows = workload_publish_approvals(&fixture);
    assert_eq!(
        rows.len(),
        1,
        "the retry minted nothing: the row was reused"
    );
    assert_eq!(rows[0].approval_id, minted);
    assert_eq!(rows[0].status, ApprovalStatus::Consumed);
    assert_eq!(
        rows[0].consumed_by_command_id.as_ref(),
        Some(&consumed_command)
    );
    assert_eq!(
        rows[0].scope.arguments_digest,
        arguments_digest(&retry),
        "the consumed scope is exactly the approved D1 retry scope"
    );

    // -- The handler and its extractor ran once, on exactly the approved
    //    arguments: the D1 digest, never the redrafted D2's.
    assert_eq!(
        fixture.world.calls(),
        vec![WORKLOAD_PUBLISH_HANDLER, WORKLOAD_PUBLISH_EXTRACTOR]
    );
    assert_eq!(
        fixture.world.effects.load(Ordering::SeqCst),
        1,
        "exactly one publish effect ran"
    );
    let proofs = fixture
        .world
        .proofs
        .lock()
        .expect("fixture proof lock")
        .clone();
    // The executor delivers the consumed-command proof to each bound call
    // of the one dispatch — the handler and its extractor: two identical
    // proofs of the SAME consumed command, one command, one dispatch.
    assert_eq!(
        proofs.len(),
        2,
        "the consumed command reached the handler and its extractor: {proofs:?}"
    );
    assert_eq!(
        proofs[0], proofs[1],
        "both bound calls received the same consumed command"
    );
    let proof = &proofs[0];
    let mut fields = proof.splitn(5, '|');
    assert!(fields.next().is_some(), "proof names the consumed command");
    assert_eq!(
        fields.next(),
        Some(WORKLOAD_PUBLISH_CAPABILITY),
        "the consumed command is the publish capability"
    );
    assert!(
        fields.next().is_some(),
        "proof names the capability version"
    );
    assert!(fields.next().is_some(), "proof names the target kind");
    let rest = fields.next().expect("proof names the target and arguments");
    let (target_id, arguments_json) = rest.split_once('|').expect("proof carries arguments");
    assert_eq!(
        target_id,
        fixture.scope.run.as_ref().expect("bound run").as_str()
    );
    let delivered: Value = serde_json::from_str(arguments_json).expect("delivered arguments");
    assert_eq!(
        delivered, retry,
        "the consumed command delivered exactly the approved D1 arguments"
    );

    // -- Replaying the consumed scope: the terminal row is never reminted
    //    and nothing re-executes — no duplicate effect.
    let replay = fixture
        .dispatch_named(
            WORKLOAD_PUBLISH_TOOL,
            Some(fixture.resource.clone()),
            retry.clone(),
            "publish-d1-replay",
        )
        .expect_err("a consumed approval cannot authorize a second publish");
    assert!(
        matches!(
            replay,
            HostToolOperationError::Rejected(AuthorizationRejection::NeedsApproval { .. })
        ),
        "the replay must route to the gate's typed refusal, got {replay:?}"
    );
    assert_eq!(
        fixture.world.calls().len(),
        2,
        "only the one approved dispatch's handler and extractor ever ran"
    );
    assert_eq!(
        fixture.world.effects.load(Ordering::SeqCst),
        1,
        "the replay produced no duplicate effect"
    );
    let rows = workload_publish_approvals(&fixture);
    assert_eq!(rows.len(), 1, "the replay minted nothing");
    assert_eq!(rows[0].status, ApprovalStatus::Consumed);
    assert_eq!(
        rows[0].consumed_by_command_id.as_ref(),
        Some(&consumed_command),
        "the consumption still names only the one approved dispatch"
    );

    // Both retained drafts remain intact; only D1 was approved.
    let store = WorkloadDraftStore::seal(&fixture.root).expect("seal draft store");
    let retained_d1 = store
        .load(PROFILE_ID, &d1, BOUND_REVISION)
        .expect("retained D1 loads")
        .expect("retained D1 intact");
    assert_eq!(retained_d1.declaration_digest, d1);
    assert_eq!(retained_d1.rendered_toml, rendered1);
    let retained_d2 = store
        .load(PROFILE_ID, &d2, BOUND_REVISION)
        .expect("retained D2 loads")
        .expect("retained D2 intact");
    assert_eq!(retained_d2.rendered_toml, rendered2);
    assert_ne!(
        retained_d1.rendered_toml, retained_d2.rendered_toml,
        "the redrafted bytes stayed distinct from the published ones"
    );
}

#[test]
fn corrupt_retained_record_refuses_before_consume_and_stays_approved() {
    let fixture = Fixture::for_workload_publish();
    fixture.seed_bridge_run();
    seed_plan(&fixture);

    // Retain D1 and drive the governed flow to an Approved, unconsumed
    // row over the exact retry shape.
    let rendered1 = rendered_d1();
    let d1 = digest_of(&rendered1);
    retain(&fixture, PROFILE_ID, &d1, &rendered1);
    let (minted, minted_revision) = mint_publish_approval(&fixture, &d1, "publish-demand");
    approve(&fixture, &minted, minted_revision);
    let before = workload_publish_approvals(&fixture);
    assert_eq!(before.len(), 1, "exactly one approved row exists");
    assert_eq!(before[0].status, ApprovalStatus::Approved);
    assert_eq!(before[0].consumed_by_command_id, None);

    // Corrupt the retained D1 entry in place: the sealed mode-0444 leaf
    // holds the retained record as JSON, so the test unlocks it and
    // overwrites it with foreign bytes. The record the pre-gate loads no
    // longer parses as the retained draft.
    let leaf = fixture.root.join("workload-drafts").join(format!(
        "{}-{}-r{}.json",
        PROFILE_ID,
        d1.strip_prefix("blake3:").expect("blake3 prefix"),
        BOUND_REVISION
    ));
    std::fs::set_permissions(&leaf, std::fs::Permissions::from_mode(0o644))
        .expect("unlock the sealed draft leaf");
    std::fs::write(&leaf, b"tampered bytes").expect("tamper the retained leaf");

    // Corrupt retained data must fail before journaling or consuming the approval.
    let refused = fixture
        .dispatch_named(
            WORKLOAD_PUBLISH_TOOL,
            Some(fixture.resource.clone()),
            publish_arguments(PROFILE_ID, &d1, minted.as_str()),
            "publish-corrupted",
        )
        .expect_err("a corrupt retained record refuses the publish");
    assert!(
        matches!(refused, HostToolOperationError::Arguments { .. }),
        "the corrupt record must refuse as typed pre-gate arguments law, got {refused:?}"
    );
    assert_eq!(
        workload_publish_approvals(&fixture),
        before,
        "the approved row survives the corrupt dispatch byte-identical: \
         exactly Approved, unchanged revision, unconsumed"
    );
    assert!(
        fixture.world.calls().is_empty(),
        "the corrupt dispatch executed nothing"
    );
}

#[test]
fn unknown_or_stale_retained_scope_refuses_before_any_approval_is_minted() {
    let fixture = Fixture::for_workload_publish();
    fixture.seed_bridge_run();
    seed_plan(&fixture);

    let rendered1 = rendered_d1();
    let d1 = digest_of(&rendered1);
    retain(&fixture, PROFILE_ID, &d1, &rendered1);

    // An unknown digest is real bytes' real blake3 digest — well formed
    // for the schema — but nothing was ever retained under it. A stale
    // bound revision is equally dead: the retained draft binds exactly
    // one publication target. Both refuse typed before the gate can mint
    // or journal anything.
    let unknown = digest_of("never retained by any draft");
    for (label, request_id, arguments) in [
        (
            "unknown digest",
            "publish-unknown",
            publish_arguments(PROFILE_ID, &unknown, "pending"),
        ),
        (
            "stale bound revision",
            "publish-stale",
            json!({
                "profileId": PROFILE_ID,
                "declarationDigest": d1,
                "expectedRegistryRevision": BOUND_REVISION + 1,
                "approvalId": "pending",
            }),
        ),
    ] {
        let refused = fixture
            .dispatch_named(
                WORKLOAD_PUBLISH_TOOL,
                Some(fixture.resource.clone()),
                arguments,
                request_id,
            )
            .expect_err(&format!("{label} must refuse the publish"));
        assert!(
            matches!(refused, HostToolOperationError::Arguments { .. }),
            "{label} must refuse as typed pre-gate arguments law, got {refused:?}"
        );
        assert!(
            fixture
                .ledger
                .lock()
                .expect("ledger lock")
                .approvals()
                .expect("approval rows")
                .is_empty(),
            "{label} refused before the gate minted anything"
        );
        assert!(
            fixture.row(request_id).is_none(),
            "{label} journaled no invocation command"
        );
        assert!(fixture.world.calls().is_empty(), "{label} executed nothing");
    }
}

#[test]
fn swapped_retained_bytes_refuse_before_consume_and_stay_approved() {
    let fixture = Fixture::for_workload_publish();
    fixture.seed_bridge_run();
    seed_plan(&fixture);

    // Retain D1 and drive the governed flow to an Approved, unconsumed
    // row over the exact retry shape.
    let rendered1 = rendered_d1();
    let d1 = digest_of(&rendered1);
    retain(&fixture, PROFILE_ID, &d1, &rendered1);
    let (minted, minted_revision) = mint_publish_approval(&fixture, &d1, "publish-demand");
    approve(&fixture, &minted, minted_revision);
    let before = workload_publish_approvals(&fixture);
    assert_eq!(before.len(), 1, "exactly one approved row exists");
    assert_eq!(before[0].status, ApprovalStatus::Approved);
    assert_eq!(before[0].consumed_by_command_id, None);

    // Keep the approved key but substitute another valid declaration, then reseal the leaf.
    let swapped = WorkloadDraftRecord {
        declaration_digest: d1.clone(),
        profile_id: PROFILE_ID.to_owned(),
        rendered_toml: rendered_d2(),
        bound_registry_revision: BOUND_REVISION,
    };
    let leaf = fixture.root.join("workload-drafts").join(format!(
        "{}-{}-r{}.json",
        PROFILE_ID,
        d1.strip_prefix("blake3:").expect("blake3 prefix"),
        BOUND_REVISION
    ));
    std::fs::set_permissions(&leaf, std::fs::Permissions::from_mode(0o644))
        .expect("unlock the sealed draft leaf");
    std::fs::write(
        &leaf,
        serde_json::to_vec_pretty(&swapped).expect("encode swapped record"),
    )
    .expect("swap the retained bytes");
    std::fs::set_permissions(&leaf, std::fs::Permissions::from_mode(0o444))
        .expect("reseal the swapped leaf");

    // Corruption must be distinguished from an absent draft.
    let store = WorkloadDraftStore::seal(&fixture.root).expect("seal draft store");
    let error = store
        .load(PROFILE_ID, &d1, BOUND_REVISION)
        .expect_err("swapped retained bytes must refuse to load");
    assert!(
        !error.is_absent(),
        "the swapped record is corrupt, not absent"
    );

    // The approved retry refuses typed before anything is journaled or
    // consumed: the approved row is byte-identical afterwards — exactly
    // Approved, unchanged revision, no consumer, no second row.
    let refused = fixture
        .dispatch_named(
            WORKLOAD_PUBLISH_TOOL,
            Some(fixture.resource.clone()),
            publish_arguments(PROFILE_ID, &d1, minted.as_str()),
            "publish-swapped",
        )
        .expect_err("swapped retained bytes must refuse the publish");
    assert!(
        matches!(refused, HostToolOperationError::Arguments { .. }),
        "the swapped record must refuse as typed pre-gate arguments law, got {refused:?}"
    );
    assert_eq!(
        workload_publish_approvals(&fixture),
        before,
        "the approved row survives the swapped-bytes dispatch byte-identical"
    );
    assert!(
        fixture.row("publish-swapped").is_none(),
        "the pre-gate refusal journaled no invocation command"
    );
    assert!(
        fixture.world.calls().is_empty(),
        "the swapped-bytes dispatch executed nothing"
    );
}

#[test]
fn profile_redirection_and_cross_profile_scopes_refuse() {
    let fixture = Fixture::for_workload_publish();
    fixture.seed_bridge_run();
    seed_plan(&fixture);

    // Retain the SAME compiled bytes under TWO profiles: distinct
    // identities over identical bytes, both lawful drafts.
    let rendered1 = rendered_d1();
    let d1 = digest_of(&rendered1);
    retain(&fixture, PROFILE_ID, &d1, &rendered1);
    const OTHER_PROFILE: &str = "odind-other-9a2b";
    retain(&fixture, OTHER_PROFILE, &d1, &rendered1);

    // Drive the governed flow to an Approved, unconsumed row over the
    // FIRST profile's exact scope.
    let (minted, minted_revision) = mint_publish_approval(&fixture, &d1, "publish-demand");
    approve(&fixture, &minted, minted_revision);
    let before = workload_publish_approvals(&fixture);
    assert_eq!(before.len(), 1, "exactly one approved row exists");
    assert_eq!(before[0].status, ApprovalStatus::Approved);

    // -- A tampered leaf that REDIRECTS the destination: at the approved
    //    key the record now claims the other profile. The store refuses
    //    it as corrupt — never absent — and the dispatch refuses typed
    //    before anything is journaled or consumed.
    let leaf = fixture.root.join("workload-drafts").join(format!(
        "{}-{}-r{}.json",
        PROFILE_ID,
        d1.strip_prefix("blake3:").expect("blake3 prefix"),
        BOUND_REVISION
    ));
    let redirected = WorkloadDraftRecord {
        profile_id: OTHER_PROFILE.to_owned(),
        declaration_digest: d1.clone(),
        rendered_toml: rendered1.clone(),
        bound_registry_revision: BOUND_REVISION,
    };
    std::fs::set_permissions(&leaf, std::fs::Permissions::from_mode(0o644))
        .expect("unlock the sealed draft leaf");
    std::fs::write(
        &leaf,
        serde_json::to_vec_pretty(&redirected).expect("encode redirect"),
    )
    .expect("redirect the retained profile");
    std::fs::set_permissions(&leaf, std::fs::Permissions::from_mode(0o444))
        .expect("reseal the redirected leaf");

    let store = WorkloadDraftStore::seal(&fixture.root).expect("seal draft store");
    let error = store
        .load(PROFILE_ID, &d1, BOUND_REVISION)
        .expect_err("a redirected record must refuse to load");
    assert!(
        !error.is_absent(),
        "destination redirection is corruption, not absence"
    );
    let refused = fixture
        .dispatch_named(
            WORKLOAD_PUBLISH_TOOL,
            Some(fixture.resource.clone()),
            publish_arguments(PROFILE_ID, &d1, minted.as_str()),
            "publish-redirected",
        )
        .expect_err("a redirected record must refuse the publish");
    assert!(
        matches!(refused, HostToolOperationError::Arguments { .. }),
        "the redirected record must refuse as typed pre-gate arguments law, got {refused:?}"
    );
    assert_eq!(
        workload_publish_approvals(&fixture),
        before,
        "the approved row survives the redirect attempt byte-identical"
    );
    assert!(
        fixture.row("publish-redirected").is_none(),
        "the redirect refusal journaled no invocation command"
    );

    // -- The cross-profile scope: publishing the SAME bytes under the
    //    OTHER profile is a DIFFERENT dispatch scope — the first
    //    profile's approval cannot cover it, nothing executes, and the
    //    approved row stays exactly Approved and unconsumed.
    let cross = fixture
        .dispatch_named(
            WORKLOAD_PUBLISH_TOOL,
            Some(fixture.resource.clone()),
            publish_arguments(OTHER_PROFILE, &d1, minted.as_str()),
            "publish-cross-profile",
        )
        .expect_err("another profile's publish cannot consume this approval");
    assert!(
        matches!(
            cross,
            HostToolOperationError::Rejected(AuthorizationRejection::NeedsApproval { .. })
        ),
        "the cross-profile dispatch must route to the gate's typed refusal, got {cross:?}"
    );
    let rows = workload_publish_approvals(&fixture);
    assert_eq!(rows.len(), 1, "the cross-profile dispatch minted nothing");
    assert_eq!(rows[0].approval_id, minted);
    assert_eq!(rows[0].status, ApprovalStatus::Approved);
    assert_eq!(rows[0].consumed_by_command_id, None);
    assert!(
        fixture.world.calls().is_empty(),
        "neither the redirect nor the cross-profile dispatch executed anything"
    );

    // -- The other profile's honest draft is intact and distinct: the
    //    same bytes, its own identity.
    let other_draft = store
        .load(OTHER_PROFILE, &d1, BOUND_REVISION)
        .expect("the other profile's draft loads")
        .expect("the other profile's draft is intact");
    assert_eq!(other_draft.profile_id, OTHER_PROFILE);
    assert_eq!(other_draft.rendered_toml, rendered1);
}
