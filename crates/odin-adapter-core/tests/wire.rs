//! Behavioral cross-checks of the typed wire models against the embedded
//! canonical schemas: every fixture below is exercised through the public
//! `from_wire`/`to_wire` APIs, so each parse runs the embedded schema plus
//! the typed semantic checks.

use odin_adapter_core::descriptor::AdapterDescriptor;
use odin_adapter_core::ids::AdapterTaint;
use odin_adapter_core::operation::AdapterOperationRecord;
use odin_adapter_core::status::{AdapterHealthState, AdapterStatusSnapshot};
use odin_domain::EffectState;
use serde_json::{json, Value};

const DIGEST: &str = "blake3:00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
const CRED: &str = "cred:web-search-primary";

fn identity() -> Value {
    json!({
        "adapter_id": "web-search",
        "version": "1.4.2",
        "binding_digest": DIGEST,
    })
}

fn operation(kind: &str, output_schema: &str) -> Value {
    json!({
        "kind": kind,
        "input_schema": "schemas/evidence/web-query.json",
        "output_schema": output_schema,
        "effect_class": "R1",
        "idempotency": "required",
        "evidence": [{
            "kind": "web-evidence",
            "schema": "schemas/evidence/web-result.json",
            "required": true,
        }],
        "credential_handle": CRED,
        "taint_after": "credential_tainted",
    })
}

fn descriptor_wire(operations: Value) -> Value {
    json!({
        "schema": "odin.adapter.descriptor.v1",
        "adapter": identity(),
        "protocol_version": 1,
        "operations": operations,
        "credential_handles": [CRED],
        "initial_taint": "credential_tainted",
    })
}

#[test]
fn descriptor_roundtrip() {
    let wire = descriptor_wire(json!([operation(
        "web.search",
        "schemas/evidence/web-results.json"
    )]));
    let descriptor = AdapterDescriptor::from_wire(&wire).expect("valid descriptor parses");
    assert_eq!(descriptor.adapter().adapter_id.as_str(), "web-search");
    assert_eq!(descriptor.protocol_version(), 1);
    assert_eq!(descriptor.operations().len(), 1);
    assert_eq!(descriptor.initial_taint(), AdapterTaint::CredentialTainted);
    assert_eq!(descriptor.to_wire(), wire);
}

#[test]
fn descriptor_rejects_duplicate_operation_kinds() {
    // The two contracts differ structurally, so the schema's `uniqueItems`
    // passes; the typed kind-uniqueness admission check must still reject.
    let first = operation("web.search", "schemas/evidence/web-results.json");
    let duplicate = descriptor_wire(json!([
        first.clone(),
        operation("web.search", "schemas/evidence/web-results-v2.json"),
    ]));
    assert!(
        AdapterDescriptor::from_wire(&duplicate).is_err(),
        "duplicate operation kinds must be rejected"
    );

    let unique = descriptor_wire(json!([first]));
    AdapterDescriptor::from_wire(&unique).expect("otherwise-identical unique descriptor parses");
}

#[test]
fn descriptor_rejects_wrong_protocol_version() {
    let mut wire = descriptor_wire(json!([operation(
        "web.search",
        "schemas/evidence/web-results.json"
    )]));
    wire["protocol_version"] = json!(2);
    assert!(
        AdapterDescriptor::from_wire(&wire).is_err(),
        "protocol_version 2 must be rejected"
    );
}

#[test]
fn descriptor_rejects_invalid_operation_kind_grammar() {
    let wire = descriptor_wire(json!([operation(
        "Web.Search",
        "schemas/evidence/web-results.json"
    )]));
    assert!(
        AdapterDescriptor::from_wire(&wire).is_err(),
        "uppercase kind violates the schema pattern"
    );
}

#[test]
fn operation_record_roundtrip() {
    let wire = json!({
        "schema": "odin.adapter.operation.v1",
        "operation_id": "op-20260912-a1",
        "adapter": identity(),
        "kind": "web.search",
        "effect_class": "R1",
        "input_schema": "schemas/evidence/web-query.json",
        "input_digest": DIGEST,
        "credential_handles": [CRED],
        "idempotency_key": "query:odin-wire-tests:2026-09-12",
        "taint": "credential_tainted",
        "state": "prepared",
        "output_schema": "schemas/evidence/web-results.json",
        "output_digest": null,
        "evidence_refs": ["ev-1"],
    });
    let record = AdapterOperationRecord::from_wire(&wire).expect("valid record parses");
    assert_eq!(record.schema, "odin.adapter.operation.v1");
    assert_eq!(record.state.to_effect_state(), Some(EffectState::Prepared));
    assert_eq!(record.to_wire(), wire);
    let reparsed = AdapterOperationRecord::from_wire(&record.to_wire()).expect("re-parses");
    assert_eq!(record, reparsed);
}

#[test]
fn status_rejects_invalid_observed_at() {
    let base = json!({
        "schema": "odin.adapter.status.v1",
        "adapter": identity(),
        "revision": 7,
        "health": "ready",
        "taint": "clean",
        "active_operations": 0,
        "last_failure": null,
        "evidence_refs": [],
    });

    let mut invalid = base.clone();
    invalid["observed_at"] = json!("2026-09-12 10:00:00");
    assert!(
        AdapterStatusSnapshot::from_wire(&invalid).is_err(),
        "non-RFC 3339 observed_at must be rejected"
    );

    let mut valid = base;
    valid["observed_at"] = json!("2026-09-12T10:00:00Z");
    let snapshot = AdapterStatusSnapshot::from_wire(&valid).expect("RFC 3339 timestamp parses");
    assert!(matches!(snapshot.health(), AdapterHealthState::Ready));
    assert_eq!(snapshot.evidence_refs().len(), 0);
    assert_eq!(snapshot.revision(), 7);
}
