//! Host-derived delegation targets and source digests are validated before journaling or approval.

use std::sync::atomic::Ordering;

use crate::host_tools::operations::dispatch::normalize_capability_arguments;
use crate::host_tools::operations::{correlation_for, HostToolOperationError};
use odin_domain::{CommandId, EffectClass, SeatId};
use odin_kernel::arguments_digest;
use serde_json::{json, Value};
use time::OffsetDateTime;

use super::fixture::{
    contract, Fixture, EVAL_CAPABILITY, EVAL_EXTRACTOR, EVAL_HANDLER, EVAL_TOOL, EXEC_CAPABILITY,
    EXEC_EXTRACTOR, EXEC_HANDLER, EXEC_TOOL, FILE_EDIT_EXTRACTOR, FILE_EDIT_HANDLER,
    FILE_EDIT_TOOL, SEAT_ASK_CAPABILITY, SEAT_ASK_EXTRACTOR, SEAT_ASK_HANDLER, SEAT_ASK_TOOL,
};

#[test]
fn eval_run_missing_source_sha256_is_supplied_from_exact_source_bytes() {
    let fixture = Fixture::for_eval();
    // `capsule.eval.run` is R1. Reproduce the production bridge's durable
    // lane/run state and record real acceptance for the exact plan
    // structure; the positive dispatch must cross the ordinary plan gate.
    let run = fixture.scope.run.clone().expect("bound run");
    fixture.seed_bridge_run();
    {
        let mut ledger = fixture.ledger.lock().expect("ledger lock");
        let plan = ledger
            .replace_plan(
                &run,
                "Evaluate exact source bytes",
                &[odin_ledger::plan::TodoSpec {
                    id: odin_domain::TodoId::new("todo:eval-digest").expect("todo id"),
                    title: "Evaluate exact source bytes".to_owned(),
                    status: odin_ledger::plan::TodoStatus::Pending,
                }],
                0,
                OffsetDateTime::UNIX_EPOCH,
            )
            .expect("fixture eval plan");
        ledger
            .accept_plan(
                &run,
                plan.revision,
                "operator:fixture",
                OffsetDateTime::UNIX_EPOCH,
            )
            .expect("record fixture eval acceptance");
    }

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
fn eval_normalization_touches_only_the_eval_capability_arguments() {
    // Another capability's arguments pass through byte-for-byte, even
    // when they carry digest-shaped keys.
    let exec = contract(
        EXEC_CAPABILITY,
        EXEC_TOOL,
        EXEC_HANDLER,
        EXEC_EXTRACTOR,
        EffectClass::R3,
    );
    let foreign = json!({
        "source": "untouched",
        "source_sha256": "f".repeat(64),
        "value": "alpha"
    });
    assert_eq!(
        normalize_capability_arguments(&exec, foreign.clone()).expect("foreign passthrough"),
        foreign
    );

    // Eval arguments with nothing digestable stay untouched for the
    // canonical schema to reject; the seam invents nothing.
    let eval = contract(
        EVAL_CAPABILITY,
        EVAL_TOOL,
        EVAL_HANDLER,
        EVAL_EXTRACTOR,
        EffectClass::R1,
    );
    let sourceless = json!({"interpreter": "python", "timeout_ms": 1});
    assert_eq!(
        normalize_capability_arguments(&eval, sourceless.clone()).expect("sourceless kept"),
        sourceless
    );

    // And the dispatch path never reshapes a non-eval payload: the
    // journaled intent digests the arguments exactly as they arrived.
    let fixture = Fixture::new();
    let arguments = json!({"value": "alpha"});
    fixture
        .dispatch(arguments.clone(), "request-foreign-passthrough")
        .expect("read dispatch commits");
    let correlation =
        correlation_for(&fixture.session, "request-foreign-passthrough").expect("correlation");
    let command_id =
        CommandId::new(format!("odin.omp.host_tool:{correlation}")).expect("command id");
    let command = fixture
        .ledger
        .lock()
        .expect("ledger lock")
        .command(&command_id)
        .expect("command readable")
        .expect("journaled command");
    assert_eq!(command.arguments_hash, arguments_digest(&arguments));
}

#[test]
fn seat_ask_normalization_binds_the_declared_delegation_target() {
    let mut ask = contract(
        SEAT_ASK_CAPABILITY,
        SEAT_ASK_TOOL,
        SEAT_ASK_HANDLER,
        SEAT_ASK_EXTRACTOR,
        EffectClass::R3,
    );
    ask.delegate_to = Some(SeatId::new("kubert").expect("fixture seat id"));

    // A dispatch without the key carries the canonical target derived
    // from the contract: the model can neither see nor choose it.
    let arguments = json!({
        "project": "odin",
        "question": "q",
        "subject": "s",
        "urgency": "medium",
    });
    let normalized =
        normalize_capability_arguments(&ask, arguments.clone()).expect("target derived");
    assert_eq!(normalized["_delegate_to"], json!("kubert"));
    assert_eq!(normalized["project"], json!("odin"));

    // A matching supplied value is preserved verbatim, so a canonical
    // replay of journaled arguments digests identically.
    let mut replay = arguments.clone();
    replay["_delegate_to"] = json!("kubert");
    assert_eq!(
        normalize_capability_arguments(&ask, replay.clone()).expect("replay kept"),
        replay
    );

    // A supplied value that disagrees with the declaration is a typed
    // rejection, never a correction: approved arguments for one target
    // can never be reused after the declaration names another.
    let mut foreign = arguments;
    foreign["_delegate_to"] = json!("architect");
    let error = normalize_capability_arguments(&ask, foreign)
        .expect_err("a retargeted payload is rejected");
    assert!(matches!(
        error,
        HostToolOperationError::Arguments { detail }
            if detail.contains("_delegate_to mismatch")
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
fn file_edit_missing_preimage_is_refused_before_operation_or_file_creation() {
    let fixture = Fixture::for_file_edit();
    accept_file_edit_plan(&fixture);
    let error = fixture.dispatch_named(
        FILE_EDIT_TOOL,
        Some(fixture.resource.clone()),
        json!({"path": "missing.txt", "content": "must not be written", "old_text": null, "new_text": null}),
        "request-file-missing-preimage",
    ).expect_err("missing preimage is not an explicit create request");
    assert!(matches!(
        error,
        HostToolOperationError::Authority(odin_kernel::OperationRejection::SchemaInvalid { .. })
    ));
    assert!(fixture.world.calls().is_empty());
    assert_eq!(fixture.world.effects.load(Ordering::SeqCst), 0);
    assert!(fixture.row("request-file-missing-preimage").is_none());
    assert!(!fixture.root.join("files/missing.txt").exists());
}

#[test]
fn optional_approval_null_is_omitted_before_dispatch() {
    {
        let approval = Value::Null;
        let fixture = Fixture::new();
        fixture
            .dispatch(
                json!({"value": "alpha", "approvalId": approval}),
                "request-optional-approval",
            )
            .expect("null optional approval is omitted");
        let correlation =
            correlation_for(&fixture.session, "request-optional-approval").expect("correlation");
        let command_id =
            CommandId::new(format!("odin.omp.host_tool:{correlation}")).expect("command id");
        let command = fixture
            .ledger
            .lock()
            .expect("ledger lock")
            .command(&command_id)
            .expect("command readable")
            .expect("journaled command");
        assert_eq!(
            command.arguments_hash,
            arguments_digest(&json!({"value": "alpha"}))
        );
        assert_eq!(fixture.world.effects.load(Ordering::SeqCst), 1);
    }
}

#[test]
fn invalid_optional_approval_values_are_refused_before_dispatch() {
    for approval in [json!(""), json!(42)] {
        let fixture = Fixture::new();
        let error = fixture
            .dispatch(
                json!({"value":"alpha", "approvalId":approval}),
                "request-invalid-approval",
            )
            .expect_err("invalid approvalId");
        assert!(error.to_string().contains("approvalId"), "{error}");
        assert!(fixture.world.calls().is_empty());
        assert_eq!(fixture.world.effects.load(Ordering::SeqCst), 0);
        assert!(fixture.row("request-invalid-approval").is_none());
    }
}
