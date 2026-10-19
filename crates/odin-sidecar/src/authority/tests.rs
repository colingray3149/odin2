//! Transport-only host tests: every case drives the real kernel
//! authority over the real ledger with a really provisioned seat token.
//! The compiled-effector round trips (successful invoke, cancellation
//! uncertainty, stop-during-execute concurrency) live in the
//! odin-effector crate, which builds that binary.
use super::sandbox::{builtin_behavior, EVAL_TERM_GRACE_MS};
use super::store::RECEIPT_SCHEMA;
use odin_domain::operation::{EffectState, Limits};
use odin_domain::{Digest, SessionId};
use odin_kernel::stop::WorkerChannel;
use odin_kernel::ExecutorFault;
use odin_sidecar_protocol::{
    Arguments, Budget, CapsuleBinding, EffectBehavior, Request, U64Wire, Version,
    EFFECT_MAX_REQUEST_BYTES,
};
use odin_strict_json::decode;
use odin_types::{CapsuleId, CorrelationId, OperationId, ToolId};
use std::path::{Path, PathBuf};

use super::*;
use odin_kernel::stop::BusAddress;
use odin_kernel::token::{MintRequest, TokenIssuer};
use std::os::unix::fs::PermissionsExt;
use std::time::{SystemTime, UNIX_EPOCH};

const SIGNING_KEY: &[u8] = b"wp07 transport fixture signing key";

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_millis() as u64)
        .unwrap_or(0)
}

fn digest_of(seed: &[u8]) -> String {
    Digest::hash(seed).to_string()
}

fn fixture_token(issuer: &TokenIssuer, issued_at: u64, expires_at: u64) -> SeatToken {
    issuer
        .mint(MintRequest {
            seat: odin_domain::SeatId::parse("seat.wp07").expect("seat"),
            slice: odin_domain::SliceId::parse("slice.wp07").expect("slice"),
            lane: odin_domain::LaneId::parse("lane.wp07").expect("lane"),
            session: SessionId::parse("00000000-0000-4000-8000-000000000007").expect("session"),
            seat_revision: Digest::hash(b"seat revision"),
            slice_revision: Digest::hash(b"slice revision"),
            capability_policy_digest: Digest::hash(b"capability policy"),
            context_policy_digest: Digest::hash(b"context policy"),
            issued_at_ms: issued_at,
            expires_at_ms: expires_at,
            entropy: b"wp07-entropy",
        })
        .expect("token")
}

fn fixture_projection() -> TransportProjection {
    let projection_json = serde_json::json!({
        "schema": PROJECTION_SCHEMA,
        "snapshot_revision": 7,
        "snapshot_digest": digest_of(b"capability policy"),
        "expected": {
            "seat": "seat.wp07",
            "slice": "slice.wp07",
            "lane": "lane.wp07",
            "session": "00000000-0000-4000-8000-000000000007",
            "seat_revision": digest_of(b"seat revision"),
            "slice_revision": digest_of(b"slice revision"),
            "capability_policy_digest": digest_of(b"capability policy"),
            "context_policy_digest": digest_of(b"context policy"),
        },
        "plan": { "gate": "accepted", "plan_id": "plan-wp07" },
        "policy": {
            "seat_tool_refs": ["capsule.write"],
            "slice_capabilities": ["capsule.write"],
            "project_capabilities": ["capsule.write"],
            "lane_capabilities": ["capsule.write"],
            "seat_categories": ["builder"],
        },
        "capabilities": [{
            "id": "capsule.write",
            "version": 1,
            "tool_name": "capsule_write",
            "description": "write one capsule file",
            "handler": {
                "kind": "exec",
                "executable": "/store/odin-effector",
                "argv": ["write"]
            },
            "evidence_extractor": { "kind": "builtin", "name": "effector_evidence" },
            "input_schema_ref": "schemas/capsule.write.input.json",
            "output_schema_ref": "schemas/capsule.write.output.json",
            "effect_class": "R1",
            "seat_tags": ["builder"],
            "timeout_seconds": 5,
            "idempotency": "required",
            "retry_max_attempts": 1,
            "approval": "none"
        }],
        "schemas": {
            "schemas/capsule.write.input.json": {
                "type": "object",
                "additionalProperties": false,
                "required": ["path", "content_hex"],
                "properties": {
                    "path": { "type": "string" },
                    "content_hex": { "type": "string" }
                }
            },
            "schemas/capsule.write.output.json": { "type": "object" }
        },
        "builtins": ["effector_evidence"]
    })
    .to_string();
    TransportProjection::from_bytes(projection_json.as_bytes()).expect("projection")
}

fn fixture_channel() -> WorkerChannel {
    let bus = BusAddress::unix_socket(PathBuf::from("/run/odin/sidecar-test-bus.sock"))
        .expect("test bus");
    WorkerChannel::for_recovery(bus).expect("recovery channel")
}

fn fixture_host(root: &Path, token: SeatToken) -> Sidecar {
    let executor = EffectorExecutor::new(
        PathBuf::from("/store/odin-effector"),
        "0000000000000000000000000000000000000000000000000000000000000000",
        CapsuleBinding {
            capsule_id: "capsule-alpha".to_owned(),
            root: root.join("capsule").display().to_string(),
            source_commit: "0123456789abcdef0123456789abcdef01234567".to_owned(),
            source_kind: "git-commit".to_owned(),
            git_bin: "/store/git".to_owned(),
        },
        system_clock(),
        fixture_channel(),
    )
    .expect("executor");
    let config = AuthorityConfig::new(Limits::new(64, 8, 0), 65_536, executor).expect("config");
    let provisioning = Provisioning::new(token, SIGNING_KEY.to_vec()).expect("provisioning");
    Sidecar::create_or_open(root, config, fixture_projection(), provisioning).expect("host")
}

fn invoke_request(
    capsule_id: &str,
    correlation_id: &str,
    requests: u64,
    arguments: &str,
) -> Request {
    Request::InvokeCapability {
        wire: Version,
        capsule_id: CapsuleId::new(capsule_id).expect("capsule id"),
        correlation_id: CorrelationId::new(correlation_id).expect("correlation id"),
        capability: ToolId::new("capsule.write").expect("tool id"),
        budget: Budget {
            requests: U64Wire::new(requests),
            stops: U64Wire::new(0),
            spend: U64Wire::new(0),
        },
        arguments: Arguments::new(
            odin_strict_json::decode(arguments.as_bytes(), EFFECT_MAX_REQUEST_BYTES)
                .expect("strict arguments"),
        )
        .expect("arguments"),
    }
}

#[test]
fn v1_wire_payloads_never_decode_as_v2_requests() {
    // The v1 prepare request shape is rejected outright by the v2
    // decoder: no compatibility adapter exists.
    let v1 = br#"{"kind":"prepare","session_id":"session-wp07","request":{"correlation_id":"00112233445566778899aabbccddeeff","operation_id":"op-x","capability":"capsule.write","requested_grant":{"capabilities":["write"],"stop_budget":0,"spend_budget":0},"cost":{"requests":1,"stops":0,"spend":0}}}"#;
    let framed = {
        let mut frame = Vec::new();
        frame.extend_from_slice(&(v1.len() as u32).to_be_bytes());
        frame.extend_from_slice(v1);
        frame
    };
    let decoded = odin_sidecar_protocol::read_request(
        &mut framed.as_slice(),
        odin_sidecar_protocol::WireLimits::new(4096, 8192).expect("limits"),
    );
    assert!(decoded.is_err(), "v1 payloads must not decode as v2");
}

#[test]
fn missing_effector_rejects_before_any_durable_row() {
    let root = tempfile_root("no-effector");
    let now = now_ms();
    let issuer = TokenIssuer::new(SIGNING_KEY.to_vec()).expect("issuer");
    let host = fixture_host(&root, fixture_token(&issuer, now, now + 60_000));
    let rejection = host
        .transport(invoke_request(
            "capsule-alpha",
            "00112233445566778899aabbccddeeff",
            1,
            r#"{"path":"notes.txt","content_hex":"6869"}"#,
        ))
        .expect_err("missing effector");
    assert_eq!(rejection.code, "executor.rejected", "{rejection:?}");
    // The executor refusal happened pre-prepare: the journal stays empty.
    assert!(host.snapshot().expect("snapshot").nonterminal.is_empty());
}

#[test]
fn ceiling_schema_and_unknown_capability_denials_are_typed() {
    let root = tempfile_root("denials");
    let now = now_ms();
    let issuer = TokenIssuer::new(SIGNING_KEY.to_vec()).expect("issuer");
    let host = fixture_host(&root, fixture_token(&issuer, now, now + 60_000));

    // A zero ceiling denies the authority-derived reservation (1, 0, 0).
    let ceiling = host
        .transport(invoke_request(
            "capsule-alpha",
            "00112233445566778899aabbccddeeff",
            0,
            r#"{"path":"notes.txt","content_hex":"6869"}"#,
        ))
        .expect_err("ceiling denial");
    assert_eq!(ceiling.code, "authority.budget_denied", "{ceiling:?}");

    // Arguments violating the declared input schema.
    let schema = host
        .transport(invoke_request(
            "capsule-alpha",
            "0123456789abcdef0123456789abcdef",
            1,
            r#"{"bogus":true}"#,
        ))
        .expect_err("schema denial");
    assert_eq!(schema.code, "authority.schema_invalid", "{schema:?}");

    // An unadmitted capability is typed as unknown.
    let mut request = invoke_request(
        "capsule-alpha",
        "022233445566778899aabbccddeeff11",
        1,
        r#"{"path":"notes.txt","content_hex":"6869"}"#,
    );
    let Request::InvokeCapability { capability, .. } = &mut request else {
        panic!("invoke request");
    };
    *capability = ToolId::new("capsule.delete").expect("tool id");
    let unknown = host.transport(request).expect_err("unknown capability");
    assert_eq!(unknown.code, "authority.unknown_capability", "{unknown:?}");

    let wrong_capsule = host
        .transport(invoke_request(
            "capsule-unbound",
            "122233445566778899aabbccddeeff11",
            1,
            r#"{"path":"notes.txt","content_hex":"6869"}"#,
        ))
        .expect_err("unbound capsule");
    assert_eq!(
        wrong_capsule.code, "authority.resource_denied",
        "{wrong_capsule:?}"
    );
}

#[test]
fn expired_tokens_reject_as_identity_expiry() {
    let root = tempfile_root("expired");
    let now = now_ms();
    let issuer = TokenIssuer::new(SIGNING_KEY.to_vec()).expect("issuer");
    let token = fixture_token(
        &issuer,
        now.saturating_sub(120_000),
        now.saturating_sub(60_000),
    );
    let host = fixture_host(&root, token);
    let rejection = host
        .transport(invoke_request(
            "capsule-alpha",
            "00112233445566778899aabbccddeeff",
            1,
            r#"{"path":"notes.txt","content_hex":"6869"}"#,
        ))
        .expect_err("expired token");
    assert_eq!(
        rejection.code, "authority.identity_expired",
        "{rejection:?}"
    );
}

#[test]
fn legacy_state_imports_exactly_once_and_archives() {
    let root = tempfile_root("legacy");
    let now = now_ms();
    let issuer = TokenIssuer::new(SIGNING_KEY.to_vec()).expect("issuer");
    // A genuine legacy OdinSidecarState/v2 authority file, including an
    // effect_started row and a requested stop.
    let legacy = serde_json::json!({
            "schema": "OdinSidecarState/v2",
            "grant": { "capabilities": ["write"], "stop_budget": 4, "spend_budget": 0 },
            "limits": { "requests": 64, "stops": 8, "spend": 0 },
            "usage": { "requests": 2, "stops": 0, "spend": 0 },
            "policy": { "operations": {
                "3344556677889900aabbccddeeff0011": {
                    "request": {
                        "correlation_id": "3344556677889900aabbccddeeff0011",
                        "operation_id": "op-legacy-0001",
                        "capability": "capsule.write",
                        "requested_grant": { "capabilities": ["write"], "stop_budget": 1, "spend_budget": 0 },
                        "cost": { "requests": 1, "stops": 0, "spend": 0 }
                    },
                    "state": "effect_started"
                }
            } },
            "operations": {
                "3344556677889900aabbccddeeff0011": {
                    "operation_id": "op-legacy-0001",
                    "session_id": "session-wp07",
                    "permit_issued": true
                }
            },
            "stops": {
                "44556677889900aabbccddeeff0011223": {
                    "helper": null,
                    "state": "requested",
                    "survivors": []
                }
            }
        })
        .to_string();
    let state_root = root.join("state");
    std::fs::create_dir_all(&state_root).expect("state root");
    std::fs::set_permissions(&state_root, std::fs::Permissions::from_mode(0o700))
        .expect("protect state root");
    std::fs::write(state_root.join(LEGACY_STATE_FILE), &legacy).expect("legacy file");

    let host = fixture_host(&state_root, fixture_token(&issuer, now, now + 60_000));
    let snapshot = host.snapshot().expect("snapshot");
    // The legacy effect_started row imports as in_doubt (blocking) and
    // the receipt exists.
    assert!(snapshot.legacy_imported);
    assert_eq!(
        snapshot.nonterminal.get("3344556677889900aabbccddeeff0011"),
        Some(&EffectState::InDoubt)
    );
    assert!(state_root.join("authority-state.json.archived").exists());
    assert!(!state_root.join(LEGACY_STATE_FILE).exists());

    // A second import attempt conflicts on the one-time receipt.
    std::fs::write(state_root.join(LEGACY_STATE_FILE), &legacy).expect("second file");
    let replay = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _ = fixture_host(&state_root, fixture_token(&issuer, now, now + 120_000));
    }));
    assert!(
        replay.is_err(),
        "a second legacy import must fail on the durable receipt"
    );
}

#[test]
fn file_edit_whole_file_requires_explicit_preimage() {
    let call = decode(
        br#"{"content":"hello","path":"notes.txt"}"#,
        EFFECT_MAX_REQUEST_BYTES,
    )
    .expect("strict file call");
    assert!(matches!(
        EffectorExecutor::file_edit_arguments(&call),
        Err(ExecutorFault::Rejected { detail })
            if detail == "builtin arguments omit required field \"preimage_sha256\""
    ));
}

#[test]
fn builtin_handlers_map_to_fixed_effects_and_derive_exact_arguments() {
    assert_eq!(
        builtin_behavior("odin_file.edit"),
        Some(EffectBehavior::Write)
    );
    assert_eq!(
        builtin_behavior("odin_eval.run"),
        Some(EffectBehavior::Eval)
    );
    assert_eq!(builtin_behavior("/caller/chosen/program"), None);

    let file_call: odin_strict_json::Value = decode(
        br#"{"content":"hello","path":"notes.txt","preimage_sha256":null}"#,
        EFFECT_MAX_REQUEST_BYTES,
    )
    .expect("strict file call");
    let write = EffectorExecutor::file_edit_arguments(&file_call).expect("derived write");
    assert_eq!(
        strict_to_serde(&write).expect("write json"),
        serde_json::json!({
            "path": "notes.txt",
            "content_hex": "68656c6c6f"
        })
    );

    let replace_call: odin_strict_json::Value = decode(
        br#"{"new_text":"b","old_text":"a","path":"notes.txt"}"#,
        EFFECT_MAX_REQUEST_BYTES,
    )
    .expect("strict replace call");
    let replace = EffectorExecutor::file_edit_arguments(&replace_call).expect("derived replace");
    assert_eq!(
        strict_to_serde(&replace).expect("replace json"),
        serde_json::json!({"path": "notes.txt", "old_hex": "61", "new_hex": "62"})
    );
    for refused in [
        br#"{"content":"x","new_text":"b","old_text":"a","path":"n","preimage_sha256":null}"#
            .as_slice(),
        br#"{"path":"n"}"#,
        br#"{"new_text":"b","old_text":"","path":"n"}"#,
        br#"{"old_text":"a","path":"n"}"#,
    ] {
        let call = decode(refused, EFFECT_MAX_REQUEST_BYTES).expect("strict call");
        assert!(
            EffectorExecutor::file_edit_arguments(&call).is_err(),
            "{}",
            String::from_utf8_lossy(refused)
        );
    }

    let executor = EffectorExecutor::new(
        PathBuf::from("/store/odin-effector"),
        "0000000000000000000000000000000000000000000000000000000000000000",
        CapsuleBinding {
            capsule_id: "capsule-alpha".to_owned(),
            root: "/capsule".to_owned(),
            source_commit: "0123456789abcdef0123456789abcdef01234567".to_owned(),
            source_kind: "git-commit".to_owned(),
            git_bin: "/store/git".to_owned(),
        },
        system_clock(),
        fixture_channel(),
    )
    .expect("executor")
    .with_interpreters(
        InterpreterBinding::new(PathBuf::from("/store/python3"), PathBuf::from("/store/bun"))
            .expect("interpreter binding"),
    );
    let eval_call: odin_strict_json::Value = decode(
            br#"{"interpreter":"python","max_stderr_bytes":4096,"max_stdout_bytes":4096,"source":"print(1)","source_sha256":"d287bb7f9d15abdc5b6e98536263815744b6ef21c8f3c3b7e7d3a3f5d55ef7aa","timeout_ms":1000}"#,
            EFFECT_MAX_REQUEST_BYTES,
        )
        .expect("strict eval call");
    let operation_id = OperationId::new("op-derived-0001").expect("operation id");
    let derived = executor
        .eval_arguments(&eval_call, Some(&operation_id))
        .expect("derived eval");
    let derived = strict_to_serde(&derived).expect("eval json");
    assert_eq!(derived["interpreter_program"], "/store/python3");
    assert_eq!(derived["scratch"], ".odin-eval/op-derived-0001");
    assert_eq!(derived["source"], "print(1)");
    assert_eq!(derived["term_grace_ms"], EVAL_TERM_GRACE_MS);
}
fn sample_receipt() -> EffectReceipt {
    let mut receipt = EffectReceipt {
        schema: RECEIPT_SCHEMA.to_owned(),
        correlation_id: "00112233445566778899aabbccddeeff".to_owned(),
        operation_id: "op-receipt-0001".to_owned(),
        capability: "capsule.file.edit".to_owned(),
        capsule_id: "capsule-alpha".to_owned(),
        evidence_digest: String::new(),
        outcome: "completed".to_owned(),

        exit_code: None,
        signal: None,
        stdout_hex: "6f64696e0a".to_owned(),
        stdout_bytes: 5,
        stdout_truncated: false,
        stderr_hex: String::new(),
        stderr_bytes: 0,
        stderr_truncated: false,
        events: vec![
            ReceiptEvent {
                name: "effect_dispatched".to_owned(),
                at_ms: 1,
                detail: "sidecar dispatched the real effect".to_owned(),
            },
            ReceiptEvent {
                name: "handler_entry".to_owned(),
                at_ms: 2,
                detail: "compiled effector entered the handler".to_owned(),
            },
            ReceiptEvent {
                name: "handler_exit".to_owned(),
                at_ms: 3,
                detail: "compiled effector exited the handler".to_owned(),
            },
            ReceiptEvent {
                name: "response_received".to_owned(),
                at_ms: 4,
                detail: "sidecar received the real response".to_owned(),
            },
            ReceiptEvent {
                name: "receipt_recorded".to_owned(),
                at_ms: 5,
                detail: "sidecar recorded the measured receipt".to_owned(),
            },
        ],
        network_connections: Vec::new(),
        filesystem_changes: vec![ReceiptFileChange {
            op: "write".to_owned(),
            path: "/capsule/notes.txt".to_owned(),
        }],
        post_world: Some(Digest::hash(b"post").to_string()),
        worker_stopped: true,
        residual_workers: 0,
        post_world_unchanged: Some(true),
    };
    receipt.seal_digest().expect("receipt digest");
    receipt
}

#[test]
fn receipt_digest_and_bounds_detect_tamper() {
    let receipt = sample_receipt();
    assert_eq!(
        receipt.digest().expect("recomputed digest").to_string(),
        receipt.evidence_digest
    );

    let mut tampered = receipt.clone();
    tampered.stdout_hex = "74616d70657265640a".to_owned();
    tampered.stdout_bytes = 9;
    assert_ne!(
        tampered.digest().expect("tampered digest").to_string(),
        receipt.evidence_digest,
        "changed measured output must change the evidence digest"
    );

    let mut oversized = receipt.clone();
    oversized.stdout_hex = "00".repeat(65_537);
    oversized.stdout_bytes = 65_537;
    assert_eq!(
        oversized.validate_bounds().unwrap_err().code(),
        SidecarErrorCode::ReceiptMismatch
    );

    let mut contradictory = receipt.clone();
    contradictory.stdout_bytes = contradictory.stdout_bytes.saturating_add(1);
    assert_eq!(
        contradictory.validate_bounds().unwrap_err().code(),
        SidecarErrorCode::ReceiptMismatch
    );

    let mut empty_event = receipt;
    empty_event.events[0].detail.clear();
    assert_eq!(
        empty_event.validate_bounds().unwrap_err().code(),
        SidecarErrorCode::ReceiptMismatch
    );
}

#[test]
fn provisioning_round_trip_preserves_only_the_sealed_fault_switch() {
    let now = now_ms();
    let issuer = TokenIssuer::new(SIGNING_KEY.to_vec()).expect("issuer");
    let provisioning = Provisioning::new(
        fixture_token(&issuer, now, now + 60_000),
        SIGNING_KEY.to_vec(),
    )
    .expect("provisioning")
    .with_post_effect_uncertainty_once();
    let mut framed = Vec::new();
    provisioning.write_to(&mut framed).expect("sealed write");
    let decoded = Provisioning::read_from(&mut framed.as_slice()).expect("sealed read");
    assert!(decoded.post_effect_uncertainty_once());
    assert_eq!(decoded.signing_key(), SIGNING_KEY);
}

fn tempfile_root(label: &str) -> PathBuf {
    let root = std::env::temp_dir().join(format!(
        "odin-sidecar-{label}-{}-{}",
        std::process::id(),
        now_ms()
    ));
    std::fs::create_dir_all(&root).expect("fixture root");
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700))
        .expect("protect fixture root");
    root
}
