//! Host-derived delegation targets and source digests are validated before journaling or approval.

use std::sync::atomic::Ordering;

use crate::host_tools::operations::dispatch::normalize_capability_arguments;
use crate::host_tools::operations::{correlation_for, HostToolOperationError};
use odin_domain::{CommandId, EffectClass};
use odin_kernel::arguments_digest;
use serde_json::{json, Value};
use time::OffsetDateTime;

use super::fixture::{
    contract, Fixture, EVAL_HANDLER, EVAL_TOOL, FILE_EDIT_EXTRACTOR, FILE_EDIT_HANDLER,
    FILE_EDIT_TOOL, SEAT_ASK_CAPABILITY, SEAT_ASK_EXTRACTOR, SEAT_ASK_HANDLER, SEAT_ASK_TOOL,
};

#[test]
fn eval_run_missing_source_sha256_is_supplied_from_exact_source_bytes() {
    let fixture = Fixture::for_eval();
    // `capsule.eval.run` is R1. Reproduce the production bridge's durable
    // lane/run state and record real acceptance for the exact plan
    // structure; the positive dispatch must cross the ordinary plan gate.
    fixture.accept_plan("Evaluate exact source bytes");

    let source = "print('café')\n";
    let supplied = odin_types::sha256_hex(source.as_bytes()).to_string();

    // The model surface omits the digest entirely: the trusted host
    // supplies it from the exact UTF-8 source bytes before the
    // invocation is digested, journaled, or executed.
    let arguments = json!({
        "interpreter": "python",
        "source": source,
        "timeout_ms": 10_000,
        "max_stdout_bytes": 4_096,
        "max_stderr_bytes": 4_096
    });
    let result = fixture
        .dispatch_named(
            EVAL_TOOL,
            Some(fixture.resource.clone()),
            arguments.clone(),
            "request-eval-supplied",
        )
        .expect("host-supplied source digest authorizes the dispatch");
    assert_eq!(result["handledBy"], EVAL_HANDLER);
    assert_eq!(result["arguments"]["source_sha256"], supplied.as_str());
    assert_eq!(result["arguments"]["source"], source);
    assert_eq!(fixture.world.effects.load(Ordering::SeqCst), 1);

    // The journaled command intent digests the normalized arguments, so
    // the durable authority binding covers exactly the canonical payload
    // the executor received — with the digest in it.
    let correlation =
        correlation_for(&fixture.session, "request-eval-supplied").expect("correlation");
    let command_id =
        CommandId::new(format!("odin.omp.host_tool:{correlation}")).expect("command id");
    let command = fixture
        .ledger
        .lock()
        .expect("ledger lock")
        .command(&command_id)
        .expect("command readable")
        .expect("journaled eval command");
    let mut normalized = arguments;
    normalized["source_sha256"] = Value::String(supplied.clone());
    assert_eq!(command.arguments_hash, arguments_digest(&normalized));

    // A supplied digest that already matches the source is binding and
    // passes through unchanged.
    let explicit = fixture
        .dispatch_named(
            EVAL_TOOL,
            Some(fixture.resource.clone()),
            json!({
                "interpreter": "bun",
                "source": source,
                "source_sha256": supplied,
                "timeout_ms": 10_000,
                "max_stdout_bytes": 4_096,
                "max_stderr_bytes": 4_096
            }),
            "request-eval-explicit",
        )
        .expect("a supplied matching digest is kept");
    assert_eq!(
        explicit["arguments"]["source_sha256"],
        odin_types::sha256_hex(source.as_bytes()).as_ref()
    );
    assert_eq!(fixture.world.effects.load(Ordering::SeqCst), 2);
}

#[test]
fn eval_run_wrong_explicit_source_sha256_is_rejected_before_any_effect() {
    let fixture = Fixture::for_eval();
    let mismatch = fixture
        .dispatch_named(
            EVAL_TOOL,
            Some(fixture.resource.clone()),
            json!({
                "interpreter": "python",
                "source": "print(1)",
                "source_sha256": "0".repeat(64),
                "timeout_ms": 10_000,
                "max_stdout_bytes": 4_096,
                "max_stderr_bytes": 4_096
            }),
            "request-eval-mismatch",
        )
        .expect_err("a declared digest that disagrees with the source is rejected");
    assert!(matches!(
        mismatch,
        HostToolOperationError::Arguments { detail }
            if detail.contains("source_sha256 mismatch")
    ));
    assert!(
        fixture.world.calls().is_empty(),
        "a mismatched digest never reaches a handler or extractor"
    );
    assert_eq!(fixture.world.effects.load(Ordering::SeqCst), 0);
    assert!(fixture.row("request-eval-mismatch").is_none());
}

#[test]
fn resolvable_ids_resolve_at_the_seam_and_name_the_values_on_failure() {
    let ask = contract(
        SEAT_ASK_CAPABILITY,
        SEAT_ASK_TOOL,
        SEAT_ASK_HANDLER,
        SEAT_ASK_EXTRACTOR,
        EffectClass::R3,
    );
    let mut narrowing = json!({
        "type": "object",
        "properties": {
            "project": {
                "type": "string",
                "enum": ["odin", "solar", "surreal"]
            }
        }
    });
    narrowing["properties"]["project"][crate::host_tools::schema_compat::RESOLVED_IDS] =
        json!(true);
    let arguments = json!({
        "project": "Sol",
        "question": "q",
        "subject": "s",
        "urgency": "medium",
    });
    let normalized = normalize_capability_arguments(&ask, &narrowing, arguments)
        .expect("a unique prefix resolves");
    assert_eq!(normalized["project"], json!("solar"));

    let ambiguous = json!({
        "project": "s",
        "question": "q",
        "subject": "s",
        "urgency": "medium",
    });
    let error = normalize_capability_arguments(&ask, &narrowing, ambiguous)
        .expect_err("an ambiguous prefix is rejected with the values named");
    assert!(matches!(
        error,
        HostToolOperationError::Arguments { detail }
            if detail.contains(SEAT_ASK_TOOL)
                && detail.contains("\"odin\", \"solar\", \"surreal\"")
                && detail.contains("\"s\" is not")
    ));
}

#[test]
fn seat_ask_wrong_explicit_delegate_to_is_rejected_before_any_effect() {
    let fixture = Fixture::for_seat_ask();
    let mismatch = fixture
        .dispatch_named(
            SEAT_ASK_TOOL,
            Some(fixture.resource.clone()),
            json!({
                "_delegate_to": "architect",
                "project": "odin",
                "question": "q",
                "subject": "s",
                "urgency": "medium",
            }),
            "request-ask-mismatch",
        )
        .expect_err("a payload retargeted away from the declaration is rejected");
    assert!(matches!(
        mismatch,
        HostToolOperationError::Arguments { detail }
            if detail.contains("_delegate_to mismatch")
    ));
    assert!(
        fixture.world.calls().is_empty(),
        "a retargeted ask never reaches a handler or extractor"
    );
    assert_eq!(fixture.world.effects.load(Ordering::SeqCst), 0);
    assert!(fixture.row("request-ask-mismatch").is_none());
}

fn accept_file_edit_plan(fixture: &Fixture) {
    fixture.seed_bridge_run();
    let run = fixture.scope.run.as_ref().expect("bound run");
    let mut ledger = fixture.ledger.lock().expect("ledger lock");
    let plan = ledger
        .replace_plan(
            run,
            "Create an exact file",
            &[odin_ledger::plan::TodoSpec {
                id: odin_domain::TodoId::new("todo:file-create").expect("todo id"),
                title: "Create an exact file".to_owned(),
                status: odin_ledger::plan::TodoStatus::Pending,
            }],
            0,
            OffsetDateTime::UNIX_EPOCH,
        )
        .expect("file edit plan");
    ledger
        .accept_plan(
            run,
            plan.revision,
            "operator:fixture",
            OffsetDateTime::UNIX_EPOCH,
        )
        .expect("accept file edit plan");
}

#[test]
fn file_edit_explicit_null_preimage_creates_exact_bytes_and_is_journaled() {
    let fixture = Fixture::for_file_edit();
    accept_file_edit_plan(&fixture);
    let content = "café\nexact trailing bytes\n";
    let arguments = json!({
        "path": "created.txt",
        "content": content,
        "preimage_sha256": null,
        "old_text": null,
        "new_text": null
    });
    let normalized = json!({
        "path": "created.txt",
        "content": content,
        "preimage_sha256": null
    });
    let result = fixture
        .dispatch_named(
            FILE_EDIT_TOOL,
            Some(fixture.resource.clone()),
            arguments,
            "request-file-create",
        )
        .expect("explicit-null create passes the governed dispatch");
    assert_eq!(result["arguments"], normalized);
    assert_eq!(result["handledBy"], FILE_EDIT_HANDLER);
    // The fixture handler uses PrivateCapability, not the compiled capsule effector.
    assert_eq!(
        std::fs::read(fixture.root.join("files/created.txt")).expect("created file"),
        content.as_bytes()
    );
    assert_eq!(
        fixture.world.calls(),
        vec![FILE_EDIT_HANDLER, FILE_EDIT_EXTRACTOR]
    );
    assert_eq!(fixture.world.effects.load(Ordering::SeqCst), 1);
    assert_eq!(
        fixture
            .row("request-file-create")
            .expect("journaled operation")
            .effect_state,
        odin_domain::operation::EffectState::Committed,
    );
    let correlation =
        correlation_for(&fixture.session, "request-file-create").expect("correlation");
    let command_id =
        CommandId::new(format!("odin.omp.host_tool:{correlation}")).expect("command id");
    let command = fixture
        .ledger
        .lock()
        .expect("ledger lock")
        .command(&command_id)
        .expect("command readable")
        .expect("journaled create command");
    assert_eq!(command.arguments_hash, arguments_digest(&normalized));
    let mut missing = normalized;
    missing
        .as_object_mut()
        .expect("arguments object")
        .remove("preimage_sha256");
    assert_ne!(command.arguments_hash, arguments_digest(&missing));
}

#[test]
fn projection_routes_and_timeouts_come_from_the_served_publication() {
    use super::fixture::BRAIN_SEARCH_TOOL;
    use crate::host_tools::operations::RevisionMaterialSource;
    let fixture = Fixture::for_brain();
    let material = fixture
        .material_source
        .material_at(fixture.binding.served_revision)
        .unwrap();
    let seat = fixture.scope.seat.clone().unwrap();
    let lane = fixture.scope.lane.clone().unwrap();
    let policy = material.seat_operation_bindings[&(seat.clone(), lane.clone())].clone();
    let mut contracts = (*material.contracts).clone();
    let id = material.tool_index[BRAIN_SEARCH_TOOL].clone();
    let contract = contracts.get_mut(&id).unwrap();
    contract.toolset = Some("renamed".into());
    contract.op = Some("lookup".into());
    contract.timeout_seconds = std::num::NonZeroU32::new(77).unwrap();
    let revision = fixture.binding.served_revision + 1;
    fixture
        .material_source
        .add_generation(revision, &contracts, &policy, seat, lane);
    let mut binding = fixture.binding.clone();
    binding.served_revision = revision;
    let view = fixture.operations.projection_view(&binding).unwrap();
    let admitted = std::collections::BTreeSet::from([BRAIN_SEARCH_TOOL.to_owned()]);
    assert!(view
        .prepare_tool_call(
            &admitted,
            "renamed",
            json!({"op":"lookup","query":"marker"}),
            Some(&fixture.scope)
        )
        .is_ok());
    let current = fixture
        .operations
        .prepare_tool_call(
            &admitted,
            "renamed",
            json!({"op":"lookup","query":"marker"}),
            Some(&fixture.scope),
        )
        .err()
        .expect("the current publication does not route the renamed toolset");
    assert!(
        matches!(current, HostToolOperationError::UnknownTool { .. }),
        "{current:?}"
    );
    assert_eq!(
        view.declared_timeout(BRAIN_SEARCH_TOOL),
        Some(std::time::Duration::from_secs(77))
    );
}
