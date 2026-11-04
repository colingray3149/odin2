//! Retained-draft validation must precede approval creation and consumption.
//! These tests use the production schema and store but a fixture publish handler.
//! Registry commits are covered in `odin-cli/src/odind/tests/workload_authoring.rs`.

use serde_json::{json, Value};

use crate::host_tools::operations::HostToolOperationError;
use crate::host_tools::workload_drafts::{test_material, WorkloadDraftRecord, WorkloadDraftStore};

use super::fixture::{Fixture, WORKLOAD_PUBLISH_TOOL};

const PROFILE_ID: &str = "odind-kubert-7c31b9e2";
fn rendered_d1() -> String {
    test_material::declaration("D1 workload declaration for the governed publish proof")
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

fn publish_arguments(profile: &str, digest: &str) -> Value {
    json!({
        "profileId": profile,
        "declarationDigest": digest,
        "expectedRegistryRevision": BOUND_REVISION,
    })
}

fn digest_of(rendered: &str) -> String {
    odin_domain::Digest::hash(rendered.as_bytes()).to_string()
}

#[test]
fn unknown_or_stale_retained_scope_refuses_before_any_approval_is_minted() {
    let fixture = Fixture::for_workload_publish();
    fixture.accept_plan("Govern the workload.publish proof");

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
            publish_arguments(PROFILE_ID, &unknown),
        ),
        (
            "stale bound revision",
            "publish-stale",
            json!({
                "profileId": PROFILE_ID,
                "declarationDigest": d1,
                "expectedRegistryRevision": BOUND_REVISION + 1,
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
