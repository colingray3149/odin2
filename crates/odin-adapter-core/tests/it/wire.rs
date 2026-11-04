//! Behavioral cross-checks of the typed wire models against the embedded
//! canonical schemas: every fixture below is exercised through the public
//! `from_wire`/`to_wire` APIs, so each parse runs the embedded schema plus
//! the typed semantic checks.

use odin_adapter_core::descriptor::AdapterDescriptor;
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
