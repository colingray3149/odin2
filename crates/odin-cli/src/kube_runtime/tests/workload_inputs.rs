//! Prompt sugar and cross-seat artifact transfer use the normal staging identities.

use super::{agent_input_bindings, workload_input_artifacts};
use odin_domain::{RunId, Scope, SeatId};
use odin_kube::artifacts::ArtifactStore;
use odin_ledger::Ledger;
use std::sync::{Arc, Mutex};

#[test]
fn prompt_is_a_registered_run_scoped_normal_input_and_retries_reuse_it() {
    let root = tempfile::tempdir().unwrap();
    let ledger = Arc::new(Mutex::new(Ledger::open_in_memory().unwrap()));
    let store = ArtifactStore::new(ledger.clone(), root.path().to_owned());
    let caller = Scope {
        seat: Some(SeatId::new("sinmara").unwrap()),
        run: Some(RunId::new("run:asker").unwrap()),
        ..Scope::default()
    };
    let run = RunId::new("run:asker:pod:research").unwrap();
    let prompt = "Find public primary sources about Etched.";
    let staged = workload_input_artifacts(
        "kube_workload_create",
        &store,
        &ledger,
        &[],
        Some(prompt),
        &caller,
        &run,
    )
    .unwrap();
    assert_eq!(staged.len(), 1);
    assert_eq!(
        store.read_registered(&staged[0].artifact_id).unwrap(),
        prompt.as_bytes()
    );
    assert_eq!(
        staged[0].content_digest,
        odin_domain::Digest::hash(prompt.as_bytes())
    );
    assert_eq!(
        agent_input_bindings(&staged, true)[0].path,
        "/var/run/odin/staging/input-2"
    );
    assert!(agent_input_bindings(&staged, true)[0].prompt);
    let repeated = workload_input_artifacts(
        "kube_workload_create",
        &store,
        &ledger,
        &[],
        Some(prompt),
        &caller,
        &run,
    )
    .unwrap();
    assert_eq!(staged, repeated);
    let references = ledger
        .lock()
        .expect("artifact ledger")
        .artifact_references(&staged[0].artifact_id)
        .unwrap();
    assert!(references.iter().any(|reference| {
        reference.object_kind == "run" && reference.object_id == run.as_str()
    }));
    assert!(!references
        .iter()
        .any(|reference| reference.object_kind == "seat"));
}

#[test]
fn explicit_inputs_require_caller_authority_before_child_run_sharing() {
    let root = tempfile::tempdir().unwrap();
    let ledger = Arc::new(Mutex::new(Ledger::open_in_memory().unwrap()));
    let store = ArtifactStore::new(ledger.clone(), root.path().to_owned());
    let caller_run = RunId::new("run:asker").unwrap();
    let metadata = crate::kube_runtime::scoped_registration::register_scoped_bytes(
        "kube_workload_create",
        &store,
        &ledger,
        b"source material",
        "source/input.txt",
        &caller_run,
    )
    .unwrap();
    let artifact = metadata.artifact_id.to_string();
    let caller = Scope {
        run: Some(caller_run),
        ..Scope::default()
    };
    let foreign = Scope {
        run: Some(RunId::new("run:foreign").unwrap()),
        ..Scope::default()
    };
    let child = RunId::new("run:asker:pod:research").unwrap();
    assert!(workload_input_artifacts(
        "kube_workload_create",
        &store,
        &ledger,
        std::slice::from_ref(&artifact),
        None,
        &foreign,
        &child,
    )
    .is_err());
    let staged = workload_input_artifacts(
        "kube_workload_create",
        &store,
        &ledger,
        &[artifact],
        Some("question"),
        &caller,
        &child,
    )
    .unwrap();
    assert_eq!(staged.len(), 2);
    assert_eq!(staged[0].artifact_id, metadata.artifact_id);
    assert_eq!(
        agent_input_bindings(&staged, true)[1].path,
        "/var/run/odin/staging/input-3"
    );
    let bindings = agent_input_bindings(&staged, true);
    assert!(!bindings[0].prompt && bindings[1].prompt);
    let references = ledger
        .lock()
        .expect("artifact ledger")
        .artifact_references(&metadata.artifact_id)
        .unwrap();
    assert!(references.iter().any(|reference| {
        reference.object_kind == "run" && reference.object_id == child.as_str()
    }));
}

#[test]
fn a_long_multi_line_prompt_round_trips_byte_identical_through_staging() {
    let root = tempfile::tempdir().unwrap();
    let ledger = Arc::new(Mutex::new(Ledger::open_in_memory().unwrap()));
    let store = ArtifactStore::new(ledger.clone(), root.path().to_owned());
    let caller = Scope {
        run: Some(RunId::new("run:asker").unwrap()),
        ..Scope::default()
    };
    let run = RunId::new("run:asker:pod:deep").unwrap();
    let prompt = format!("first line\n{}\nlast line ✓\n", "漢".repeat(5_000));
    let staged = workload_input_artifacts(
        "kube_workload_create",
        &store,
        &ledger,
        &[],
        Some(&prompt),
        &caller,
        &run,
    )
    .unwrap();
    assert_eq!(
        store.read_registered(&staged[0].artifact_id).unwrap(),
        prompt.as_bytes()
    );
}

#[test]
fn the_opening_message_quotes_a_short_prompt_and_points_past_a_long_one() {
    let short = "Find sources about Etched.";
    assert_eq!(
        crate::kube_runtime::opening_prompt_text(short, "/var/run/odin/staging/input-3"),
        format!(
            "Workload session admitted. Your task brief from the launcher follows; the profile \
             brief is in your session guidance.\n\n{short}"
        )
    );
    // Multi-byte characters: the cut lands on a character boundary, never inside one.
    let long = "漢".repeat(crate::kube_runtime::OPENING_PROMPT_CHARS + 10);
    let text = crate::kube_runtime::opening_prompt_text(&long, "/var/run/odin/staging/input-3");
    let marker = "\n[continued in /var/run/odin/staging/input-3: read it with :raw]";
    let quoted = text
        .strip_suffix(marker)
        .and_then(|head| head.split_once("\n\n").map(|(_, body)| body))
        .expect("long prompt carries the continuation marker");
    assert_eq!(
        quoted.chars().count(),
        crate::kube_runtime::OPENING_PROMPT_CHARS
    );
    assert!(long.starts_with(quoted));
}
