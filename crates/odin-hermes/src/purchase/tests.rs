//! Purchase approval and dispatch outcome tests.

use super::*;

/// Minimal backend descriptor using the production wire shape.
fn descriptor_wire(idempotency: &str) -> serde_json::Value {
    let digest = odin_domain::Digest::hash(b"purchase-submit-fixture").to_string();
    serde_json::json!({
        "schema": "odin.adapter.descriptor.v1",
        "adapter": {
            "adapter_id": PURCHASE_BACKEND_ADAPTER_ID,
            "version": "1.0.0",
            "binding_digest": digest,
        },
        "protocol_version": 1,
        "operations": [{
            "kind": PURCHASE_OPERATION_WIRE_ID,
            "input_schema": "schemas/capability/purchase.submit.input.json",
            "output_schema": "schemas/capability/purchase.submit.output.json",
            "effect_class": "R3",
            "idempotency": idempotency,
            "evidence": [{
                "kind": "purchase.submit.evidence",
                "schema": "schemas/capability/purchase.submit.evidence.json",
                "required": true,
            }],
            "credential_handle": "cred:fixture-purchase",
            "taint_after": "credential_tainted",
        }],
        "credential_handles": ["cred:fixture-purchase"],
        "initial_taint": "credential_tainted",
    })
}

fn contract() -> PurchaseAdapterContract {
    let descriptor =
        AdapterDescriptor::from_wire(&descriptor_wire("required")).expect("descriptor parses");
    PurchaseAdapterContract::admit(descriptor).expect("the lawful purchase backend contract admits")
}

fn command() -> CommandEnvelope {
    let request =
        PurchaseRequest::new("Fixture Vendor", "Fixture Gadget", 4_999, "EUR").expect("request");
    let init = PurchasePrepareInit {
        command_id: odin_domain::CommandId::from_parts("cmd", 1, "unit").expect("command id"),
        sequence: 1,
        issued_at_ms: 1,
        expires_at_ms: 2,
        actor: Actor::system("unit").expect("actor"),
        scope: Scope::default(),
        target: CommandTarget::Seat(odin_domain::SeatId::new("seat-unit").expect("seat id")),
        producer: Producer::new("odin-hermes", "0.0.0", None).expect("producer"),
        approval_id: odin_domain::ApprovalId::from_parts("purchase", 1, "unit")
            .expect("approval id"),
    };
    prepare(&request, init).expect("prepare").command
}

#[derive(Clone)]
struct ScriptedExchange {
    reply: Result<String, PurchaseFault>,
}

impl PurchaseFrameExchange for ScriptedExchange {
    fn exchange(&self, _request_line: String) -> Result<String, PurchaseFault> {
        self.reply.clone()
    }
}

#[test]
fn an_unlawful_descriptor_never_becomes_a_purchase_backend() {
    // Purchases require idempotency; a pure operation is not an admissible backend.
    let descriptor =
        AdapterDescriptor::from_wire(&descriptor_wire("pure")).expect("descriptor parses");
    assert!(matches!(
        PurchaseAdapterContract::admit(descriptor),
        Err(PurchaseError::Contract(
            "the purchase.submit operation must require idempotency",
        ))
    ));
}

#[test]
fn the_frame_carries_exactly_the_admitted_operation_and_no_deployment_facts() {
    let submitter = M10PurchaseSubmitter::new(contract(), {
        Arc::new(ScriptedExchange {
            reply: Err(PurchaseFault::Rejected),
        })
    });
    let command = command();
    // Inspect the same frame builder used by the exchange path.
    let frame = submitter.frame(&command).expect("the frame builds");
    let wire: serde_json::Value = serde_json::from_str(&frame).expect("single-line JSON");
    assert_eq!(wire["jsonrpc"], "2.0");
    assert_eq!(wire["method"], "purchase.submit");
    assert_eq!(wire["id"], command.id.to_string());
    let params = wire["params"].as_object().expect("object params");
    let keys: Vec<_> = params.keys().map(String::as_str).collect();
    assert_eq!(keys, ["idempotency_key", "input", "operation_id"]);
    assert_eq!(params["operation_id"], "purchase.submit");
    assert_eq!(
        params["idempotency_key"],
        command.correlation.idempotency_key
    );
    assert_eq!(params["input"], command.payload);
    let serialized = frame;
    assert!(!serialized.contains("cred:"));
    assert!(!serialized.contains("https://"));
}

#[test]
fn typed_backend_refusals_relay_verbatim_and_doubt_stays_doubt() {
    let lawful = contract();
    // Replies must answer THIS command: the fixture id is stable.
    let id = command().id.to_string();
    let settle = |reply: &str| {
        let submitter = M10PurchaseSubmitter::new(
            lawful.clone(),
            Arc::new(ScriptedExchange {
                reply: Ok(reply.to_owned()),
            }),
        );
        submitter.settle(reply, &command())
    };

    // Credentials unavailable at the backend: refused before any
    // provider exchange, typed code -32000 traveling verbatim.
    let refused = format!(
        r#"{{"jsonrpc":"2.0","id":"{id}","error":{{"code":-32000,"message":"the configured credential is unavailable"}}}}"#
    );
    assert!(matches!(
        settle(&refused),
        Err(PurchaseFault::BackendRefused(
            AdapterErrorCode::CredentialsUnavailable,
        ))
    ));

    // An internal error leaves the dispatch outcome unknown.
    let internal = format!(
        r#"{{"jsonrpc":"2.0","id":"{id}","error":{{"code":-32603,"message":"internal"}}}}"#
    );
    assert!(matches!(settle(&internal), Err(PurchaseFault::Uncertain)));

    assert!(matches!(settle("not json"), Err(PurchaseFault::Uncertain)));

    // A stale or foreign response id must never settle this command.
    let foreign = r#"{"jsonrpc":"2.0","id":"someone-else","result":{"provider_ref":"stolen"}}"#;
    assert!(matches!(settle(foreign,), Err(PurchaseFault::Uncertain)));

    // Neither may a non-2.0 envelope.
    let old_envelope =
        format!(r#"{{"jsonrpc":"1.1","id":"{id}","result":{{"provider_ref":"stale"}}}}"#);
    assert!(matches!(
        settle(&old_envelope),
        Err(PurchaseFault::Uncertain)
    ));

    // Success settles into a bounded receipt only.
    let settled = settle(&format!(
        r#"{{"jsonrpc":"2.0","id":"{id}","result":{{"provider_ref":"order-fixture-1"}}}}"#
    ))
    .expect("a real result settles");
    assert_eq!(settled.provider_ref, "order-fixture-1");

    // A result without a bounded provider reference is in doubt.
    let unbounded = format!(r#"{{"jsonrpc":"2.0","id":"{id}","result":{{}}}}"#);
    assert!(matches!(settle(&unbounded), Err(PurchaseFault::Uncertain)));
}
