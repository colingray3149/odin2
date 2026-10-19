//! The executor's fault-mapping contract at the owning boundary: every
//! [`HostToolError`] variant whose contract proves the effect never started
//! stays a durable [`ExecutorFault::Rejected`]; the variants that cannot
//! prove the effect state stay [`ExecutorFault::Uncertain`]; and the typed
//! post-effect fault maps STRAIGHT onto the kernel's truthful partial
//! receipt, binding the producer's real stored content digest verbatim —
//! no re-hashing, no re-canonicalization, no trust decision.

use odin_domain::Digest;
use odin_kernel::ExecutorFault;
use serde_json::{json, Value};

use super::{map_dispatch_error, scope_and_execution_from_binding, DurableExecutorBinding};
use crate::host_tools::HostToolError;

const TOOL: &str = "odin_kube.workload.create";

/// The wire shape of an applied `kube.workload.create` settlement, used
/// here only to simulate the producer's real stored content digest.
fn applied_receipt() -> Value {
    json!({
        "status": "accepted",
        "runId": "run:1738000000000:receipt",
        "operationId": "op-22c426c1receiptproof",
        "workerId": "worker-receipt-proof",
        "jobName": "odin-1daaae036receipt",
        "resourceVersion": "104207"
    })
}

#[test]
fn post_effect_fault_binds_the_producer_captured_digest_verbatim() {
    // The producer durably captured and stored the receipt and passes its
    // real stored content digest; the executor binds it verbatim.
    let canonical =
        odin_strict_json::canonicalize(&applied_receipt()).expect("receipt canonicalizes");
    let stored = Digest::hash(&canonical);
    let fault = map_dispatch_error(HostToolError::PostEffect {
        tool: TOOL,
        detail: "run run:1738000000000:receipt is applied on the cluster: Job \
                 odin-1daaae036receipt was created at resourceVersion 104207 — the workload \
                 resources were created; the agent session attach failed [omp_bridge_start]: \
                 remote harness attach failed: workload carrier is not running"
            .to_owned(),
        evidence_digest: stored,
    });
    let ExecutorFault::PostEffectUncertain {
        detail: _,
        evidence_digest,
    } = fault
    else {
        panic!("a typed post-effect fault must map to the partial receipt, got {fault:?}");
    };
    assert_eq!(
        evidence_digest, stored,
        "the stored digest is bound verbatim"
    );
}

#[test]
fn pre_effect_argument_faults_stay_durable_rejections() {
    let fault = map_dispatch_error(HostToolError::Arguments {
        tool: TOOL,
        detail: "profile is not admitted".to_owned(),
    });
    let ExecutorFault::Rejected { .. } = fault else {
        panic!("a provably pre-effect fault must stay Rejected, got {fault:?}");
    };
}

#[test]
fn pre_effect_unavailability_stays_a_durable_rejection() {
    let fault = map_dispatch_error(HostToolError::Unavailable {
        tool: TOOL,
        reason: "the kube surface is not configured".to_owned(),
    });
    assert!(
        matches!(fault, ExecutorFault::Rejected { .. }),
        "an unbound surface can never have dispatched an effect, got {fault:?}"
    );
}

#[test]
fn unprovable_faults_stay_uncertain() {
    let fault = map_dispatch_error(HostToolError::Uncertain {
        tool: TOOL,
        detail: "the actuation bound elapsed".to_owned(),
    });
    assert!(
        matches!(fault, ExecutorFault::Uncertain { .. }),
        "a pre-output timeout proves nothing, got {fault:?}"
    );
    let fault = map_dispatch_error(HostToolError::Response {
        tool: TOOL,
        detail: "cannot serialize the settlement".to_owned(),
    });
    let ExecutorFault::Uncertain { .. } = fault else {
        panic!("a landed effect with an unproducible result is uncertain, got {fault:?}");
    };
}

/// The bound scope one fixture permit carries, with every dimension the
/// executor's target check proves.
fn bound_scope() -> odin_domain::Scope {
    odin_domain::Scope {
        seat: Some("seat-a".parse().unwrap()),
        lane: Some("lane-a".parse().unwrap()),
        run: Some("run-a".parse().unwrap()),
        session: Some("session-a".parse().unwrap()),
        ..odin_domain::Scope::default()
    }
}

fn live_proof() -> crate::uri::ExecutionBinding {
    let mut binding = crate::bridge::BridgeBinding::new(
        bound_scope(),
        "session-a".parse().unwrap(),
        "run-a".parse().unwrap(),
        "lane-a".parse().unwrap(),
        "owner",
    );
    binding.epoch = 3;
    crate::uri::ExecutionBinding::from_binding(&binding)
}

#[test]
fn envelope_bindings_decode_scope_and_proof_and_refuse_foreign_shapes() {
    let scope = bound_scope();
    let proof = live_proof();
    let envelope = serde_json::to_value(DurableExecutorBinding {
        scope: scope.clone(),
        execution: Some(proof.clone()),
    })
    .unwrap();
    let (decoded, execution) =
        scope_and_execution_from_binding(Some(&envelope)).expect("envelope binding");
    assert_eq!(decoded, scope);
    assert_eq!(execution.as_ref(), Some(&proof));

    // A foreign extra field breaks the canonical round-trip: the journaled
    // bytes are the only truth, so anything else is a rejection.
    let mut foreign = envelope.clone();
    foreign["extra"] = serde_json::json!(1);
    assert!(scope_and_execution_from_binding(Some(&foreign)).is_err());
    // A truncated envelope that is neither envelope nor canonical scope.
    assert!(scope_and_execution_from_binding(Some(&serde_json::json!({
        "scope": {}
    })))
    .is_err());
    assert!(
        scope_and_execution_from_binding(Some(&serde_json::to_value(&scope).unwrap())).is_err()
    );
}

#[test]
fn typed_knowledge_uri_refusals_stay_durable_rejections() {
    // Rejected execution credentials prevent the read, so the outcome is not uncertain.
    let fault = map_dispatch_error(HostToolError::KnowledgeUri(
        crate::uri::UriError::ExecutionProof {
            url: "brain://blake3:00".to_owned(),
            reason: "the proof's epoch is stale".to_owned(),
        },
    ));
    let ExecutorFault::Rejected { .. } = fault else {
        panic!("a typed knowledge refusal must reject, got {fault:?}");
    };
}
