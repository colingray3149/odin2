//! Transport-only host tests: every case drives the real kernel
//! authority over the real ledger with a really provisioned seat token.
//! The compiled-effector round trips (successful invoke, cancellation
//! uncertainty, stop-during-execute concurrency) live in the
//! odin-effector crate, which builds that binary.
use super::sandbox::{builtin_behavior, EVAL_TERM_GRACE_MS};
use odin_domain::operation::Limits;
use odin_domain::{Digest, SessionId};
use odin_kernel::stop::WorkerChannel;
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

pub(crate) const SIGNING_KEY: &[u8] = b"wp07 transport fixture signing key";

pub(crate) fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_millis() as u64)
        .unwrap_or(0)
}

fn digest_of(seed: &[u8]) -> String {
    Digest::hash(seed).to_string()
}

pub(crate) fn fixture_token(issuer: &TokenIssuer, issued_at: u64, expires_at: u64) -> SeatToken {
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

pub(crate) fn fixture_host(root: &Path, token: SeatToken) -> Sidecar {
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

pub(crate) fn invoke_request(
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
fn missing_effector_rejects_before_any_durable_row() {
    let scratch = tempfile_root();
    let root = scratch.path().to_path_buf();
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
    let scratch = tempfile_root();
    let root = scratch.path().to_path_buf();
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
    let scratch = tempfile_root();
    let root = scratch.path().to_path_buf();
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
    assert_eq!(
        builtin_behavior("odin_code.rewrite"),
        Some(EffectBehavior::Execute)
    );
    assert_eq!(
        builtin_behavior("odin_code.look"),
        Some(EffectBehavior::Execute)
    );

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
#[test]
fn provisioning_carries_the_seat_token_and_key_over_the_sealed_channel() {
    let now = now_ms();
    let issuer = TokenIssuer::new(SIGNING_KEY.to_vec()).expect("issuer");
    let token = fixture_token(&issuer, now, now + 60_000);
    let provisioning =
        Provisioning::new(token.clone(), SIGNING_KEY.to_vec()).expect("provisioning");
    let mut framed = Vec::new();
    provisioning.write_to(&mut framed).expect("sealed write");
    let decoded = Provisioning::read_from(&mut framed.as_slice()).expect("sealed read");
    assert_eq!(decoded.signing_key(), SIGNING_KEY);
    assert_eq!(decoded.seat_token, token);
}

pub(crate) fn tempfile_root() -> tempfile::TempDir {
    let root = tempfile::tempdir().expect("fixture root");
    // The authority requires an owner-private root; tempdir() is 0755 here.
    std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700))
        .expect("fixture root private");
    root
}
