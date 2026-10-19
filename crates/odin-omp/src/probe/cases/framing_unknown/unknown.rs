//! Case 21 machinery: the fault fixture emits one unknown future object and
//! the case proves it was retained byte- and field-exactly.

use std::time::{Duration, Instant};

use async_trait::async_trait;
use serde_json::{json, Value};

use crate::bridge::{classify_frame, FrameClass};
use crate::frames::{DecodedRpcFrame, RpcProtocolVersion};
use crate::probe::{
    CaseContext, CaseEvidence, CaseFailure, CaseOutcome, CleanupReceipt, ConformanceCase,
    ConformanceCaseId, RawRpcDriver,
};
use crate::process::OmpLifecycleState;

use super::*;

const UNKNOWN_CASE_DEADLINE: Duration = Duration::from_secs(60);
const UNKNOWN_WORK_BUDGET: Duration = Duration::from_secs(40);
const UNKNOWN_RAW: &str = r#"{"type":"odin_future_frame","sequence":21,"future_field":"retained-byte-exact","nested":{"glyph":"\u00b5","flags":[true,false,null]}}"#;

pub(super) struct UnknownFrameEvidenceCase;

#[async_trait]
impl ConformanceCase for UnknownFrameEvidenceCase {
    fn id(&self) -> ConformanceCaseId {
        UNKNOWN_FRAME_EVIDENCE
    }

    fn name(&self) -> &'static str {
        "unknown_frame_evidence"
    }

    fn deadline(&self) -> Duration {
        UNKNOWN_CASE_DEADLINE
    }

    async fn run(&self, context: &CaseContext) -> CaseOutcome {
        let deadline = Instant::now() + UNKNOWN_WORK_BUDGET;
        let mut failures = Vec::new();
        let mut evidence = Vec::new();
        let mut cleanup = CleanupReceipt::default();
        let mut started_children = 0;
        let mut retained = false;

        let spec = context.fault_spec(Vec::new());
        let worker = context.worker_for(&spec);
        match RawRpcDriver::spawn(spec, worker).await {
            Ok(mut driver) => {
                started_children += 1;
                let before = failures.len();
                if driver.process().state() != OmpLifecycleState::Ready(RpcProtocolVersion::V2) {
                    fail(
                        &mut failures,
                        "unknown_protocol",
                        format!("fault fixture negotiated {}", driver.process().state()),
                    );
                }

                match driver
                    .send("fixture_emit", json!({ "lines": [UNKNOWN_RAW] }))
                    .await
                {
                    Ok(request_id) => {
                        match driver
                            .wait_for_response(&request_id, "fixture_emit", deadline)
                            .await
                        {
                            Ok(response)
                                if response_success(&response, &request_id, "fixture_emit") =>
                            {
                                match driver.collect_until(deadline, |_| true).await {
                                    Ok(frames) => {
                                        if let Some(frame) = frames.first() {
                                            validate_unknown_frame(
                                                frame,
                                                &mut failures,
                                                &mut evidence,
                                            );
                                        } else {
                                            fail(
                                                &mut failures,
                                                "unknown_delivery",
                                                "fixture collection returned no frame",
                                            );
                                        }
                                    }
                                    Err(error) => fail(
                                        &mut failures,
                                        "unknown_delivery",
                                        format!("unknown frame was not decoded: {error}"),
                                    ),
                                }
                            }
                            Ok(response) => fail(
                                &mut failures,
                                "unknown_injection_ack",
                                response_failure_detail(&response, &request_id, "fixture_emit"),
                            ),
                            Err(error) => fail(
                                &mut failures,
                                "unknown_injection_ack",
                                format!("fixture acknowledgement failed: {error}"),
                            ),
                        }
                    }
                    Err(error) => fail(
                        &mut failures,
                        "unknown_injection_send",
                        format!("unknown-frame injection failed: {error}"),
                    ),
                }
                retained = failures.len() == before;

                cleanup_driver(
                    &mut driver,
                    &mut cleanup,
                    "unknown-frame-fixture",
                    &mut failures,
                )
                .await;
            }
            Err(error) => fail(
                &mut failures,
                "unknown_fixture_spawn",
                format!("fault fixture did not start: {error}"),
            ),
        }

        if !retained {
            fail(
                &mut failures,
                "unknown_retention_effect",
                "the unknown object was not retained byte- and field-exactly",
            );
        }

        finish_case(
            failures,
            evidence,
            cleanup,
            started_children,
            2,
            "unknown future object remained byte- and field-exact raw evidence",
            "unknown future object retention checks failed",
        )
    }
}

fn validate_unknown_frame(
    frame: &DecodedRpcFrame,
    failures: &mut Vec<CaseFailure>,
    evidence: &mut Vec<CaseEvidence>,
) {
    retain_raw(
        frame,
        "unknown_frame",
        "future-object-logical",
        failures,
        evidence,
    );
    retain_lines(
        frame.lines(),
        "unknown_frame_wire",
        "future-object-physical",
        failures,
        evidence,
    );

    if frame.raw() != UNKNOWN_RAW.as_bytes() {
        fail(
            failures,
            "unknown_raw_bytes",
            "decoded unknown-frame bytes differed from the fixture input",
        );
    }
    let mut expected_line = Vec::with_capacity(UNKNOWN_RAW.len() + 1);
    expected_line.extend_from_slice(UNKNOWN_RAW.as_bytes());
    expected_line.push(b'\n');
    if frame.lines().len() != 1 || frame.lines().first() != Some(&expected_line) {
        fail(
            failures,
            "unknown_physical_bytes",
            "unknown frame did not retain its one exact newline-terminated physical line",
        );
    }
    if classify_frame(frame.value()) != FrameClass::Unknown {
        fail(
            failures,
            "unknown_classification",
            "future type was not classified as unknown",
        );
    }

    let exact_fields = frame.value().as_object().is_some_and(|object| {
        object.len() == 4
            && object.get("type").and_then(Value::as_str) == Some("odin_future_frame")
            && object.get("sequence").and_then(Value::as_u64) == Some(21)
            && object.get("future_field").and_then(Value::as_str) == Some("retained-byte-exact")
            && object.get("nested")
                == Some(&json!({
                    "glyph": "\u{00b5}",
                    "flags": [true, false, null],
                }))
    });
    if !exact_fields {
        fail(
            failures,
            "unknown_fields",
            "unknown object lost or changed one of its future fields",
        );
    }
    match serde_json::from_slice::<Value>(frame.raw()) {
        Ok(reparsed) if &reparsed == frame.value() => {}
        Ok(_) => fail(
            failures,
            "unknown_raw_parse",
            "unknown raw bytes parsed to a different retained object",
        ),
        Err(error) => fail(
            failures,
            "unknown_raw_parse",
            format!("unknown raw bytes no longer parsed as JSON: {error}"),
        ),
    }
}
