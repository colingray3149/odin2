//! Case 2 machinery: the v2 handshake and oversized-response validation, the
//! `rpc_chunk` line builder, and the typed malformed-train fault experiments
//! against the fault fixture.

use std::str;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use serde_json::{json, Value};

use crate::frames::{
    DecodedRpcFrame, RpcFrameErrorKind, RpcProtocolVersion, CHUNK_PAYLOAD_BYTES, MAX_CHUNK_COUNT,
    MAX_FRAME_BYTES, MAX_REASSEMBLED_BYTES,
};
use crate::probe::{
    CaseContext, CaseEvidence, CaseFailure, CaseOutcome, CleanupOutcome, CleanupReceipt,
    ConformanceCase, ConformanceCaseId, RawRpcDriver, RawRpcError, DEFAULT_MODEL_SELECTOR,
};
use crate::process::{OmpLifecycleState, OmpProcessError, NEGOTIATE_REQUEST_ID};

use super::*;

const PROTOCOL_CASE_DEADLINE: Duration = Duration::from_secs(120);
const PROTOCOL_WORK_BUDGET: Duration = Duration::from_secs(100);

pub(super) struct ProtocolReassemblyCase;

#[async_trait]
impl ConformanceCase for ProtocolReassemblyCase {
    fn id(&self) -> ConformanceCaseId {
        PROTOCOL_REASSEMBLY
    }

    fn name(&self) -> &'static str {
        "protocol_reassembly"
    }

    fn deadline(&self) -> Duration {
        PROTOCOL_CASE_DEADLINE
    }

    async fn run(&self, context: &CaseContext) -> CaseOutcome {
        let deadline = Instant::now() + PROTOCOL_WORK_BUDGET;
        let mut failures = Vec::new();
        let mut evidence = Vec::new();
        let mut cleanup = CleanupReceipt::default();
        let mut started_children = 0;

        let spec = context.process_spec(DEFAULT_MODEL_SELECTOR, Vec::new());
        let worker = context.worker_for(&spec);
        let real_response_validated = match RawRpcDriver::spawn(spec, worker).await {
            Ok(mut driver) => {
                started_children += 1;
                let validated =
                    exercise_real_v2_response(&mut driver, deadline, &mut failures, &mut evidence)
                        .await;
                cleanup_driver(
                    &mut driver,
                    &mut cleanup,
                    "pinned-omp-oversized-response",
                    &mut failures,
                )
                .await;
                validated
            }
            Err(error) => {
                fail(
                    &mut failures,
                    "real_process_spawn",
                    format!("pinned OMP did not start: {error}"),
                );
                false
            }
        };

        let mut validated_faults = 0;
        for fault in Fault::ALL {
            if observe_fault(
                context,
                fault,
                deadline,
                &mut started_children,
                &mut failures,
                &mut evidence,
                &mut cleanup,
            )
            .await
            {
                validated_faults += 1;
            }
        }

        if !real_response_validated {
            fail(
                &mut failures,
                "oversized_response_effect",
                "the real pinned child did not produce a fully validated oversized v2 response",
            );
        }
        if validated_faults != Fault::ALL.len() {
            fail(
                &mut failures,
                "typed_fault_effects",
                format!(
                    "validated {validated_faults} of {} required typed framing rejections",
                    Fault::ALL.len()
                ),
            );
        }

        finish_case(
            failures,
            evidence,
            cleanup,
            started_children,
            6 + Fault::ALL.len(),
            "protocol v2 reassembled the real oversized response and rejected every corrupt train",
            "protocol v2 oversized-response or rejection checks failed",
        )
    }
}

async fn exercise_real_v2_response(
    driver: &mut RawRpcDriver,
    deadline: Instant,
    failures: &mut Vec<CaseFailure>,
    evidence: &mut Vec<CaseEvidence>,
) -> bool {
    let before = failures.len();
    validate_v2_handshake(driver, failures, evidence);

    let prompt_id = match driver
        .send(
            "prompt",
            json!({
                "message": format!("odin-mock:big {BIG_REPLY_BYTES}"),
                "images": [],
            }),
        )
        .await
    {
        Ok(id) => id,
        Err(error) => {
            fail(
                failures,
                "oversized_prompt_send",
                format!("oversized provider directive was not sent: {error}"),
            );
            return false;
        }
    };

    let terminal_frames = match driver
        .collect_until(deadline, |frame| {
            frame.value().get("type").and_then(Value::as_str) == Some("agent_end")
                && frame.value().get("willContinue").and_then(Value::as_bool) != Some(true)
        })
        .await
    {
        Ok(frames) => frames,
        Err(error) => {
            fail(
                failures,
                "oversized_turn_terminal",
                format!("oversized provider turn did not finish: {error}"),
            );
            return false;
        }
    };
    if let Some(terminal) = terminal_frames.last() {
        retain_raw(
            terminal,
            "turn_terminal",
            "oversized-agent-end",
            failures,
            evidence,
        );
    } else {
        fail(
            failures,
            "oversized_turn_terminal",
            "terminal collection returned no frame",
        );
        return false;
    }

    let prompt_response = match driver
        .wait_for_response(&prompt_id, "prompt", deadline)
        .await
    {
        Ok(response) => response,
        Err(error) => {
            fail(
                failures,
                "oversized_prompt_response",
                format!("prompt response was not correlated: {error}"),
            );
            return false;
        }
    };
    retain_raw(
        &prompt_response,
        "command_response",
        "oversized-prompt",
        failures,
        evidence,
    );
    if !validate_success_response(
        &prompt_response,
        &prompt_id,
        "prompt",
        "oversized_prompt_response",
        failures,
    ) {
        return false;
    }

    let messages_id = match driver.send("get_messages", json!({})).await {
        Ok(id) => id,
        Err(error) => {
            fail(
                failures,
                "oversized_response_send",
                format!("get_messages was not sent: {error}"),
            );
            return false;
        }
    };
    let response = match driver
        .wait_for_response(&messages_id, "get_messages", deadline)
        .await
    {
        Ok(response) => response,
        Err(error) => {
            fail(
                failures,
                "oversized_response_receive",
                format!("oversized get_messages response was not received: {error}"),
            );
            return false;
        }
    };
    validate_oversized_response(&response, &messages_id, failures, evidence);

    failures.len() == before
}

fn validate_v2_handshake(
    driver: &RawRpcDriver,
    failures: &mut Vec<CaseFailure>,
    evidence: &mut Vec<CaseEvidence>,
) {
    if driver.process().state() != OmpLifecycleState::Ready(RpcProtocolVersion::V2) {
        fail(
            failures,
            "protocol_negotiation",
            format!("pinned child reached {}", driver.process().state()),
        );
    }

    match driver.process().ready_frame() {
        Some(ready) => {
            retain_raw(ready, "ready_frame", "pinned-ready", failures, evidence);
            let supported = ready
                .value()
                .get("supportedProtocolVersions")
                .and_then(Value::as_array);
            let exact_versions = supported.is_some_and(|versions| {
                versions.len() == 2
                    && versions[0].as_u64() == Some(1)
                    && versions[1].as_u64() == Some(2)
            });
            if ready.value().get("protocolVersion").and_then(Value::as_u64) != Some(1)
                || !exact_versions
                || ready.value().get("maxFrameBytes").and_then(Value::as_u64)
                    != Some(MAX_FRAME_BYTES as u64)
                || ready
                    .value()
                    .get("maxReassembledFrameBytes")
                    .and_then(Value::as_u64)
                    != Some(MAX_REASSEMBLED_BYTES as u64)
            {
                fail(
                    failures,
                    "protocol_limits",
                    "ready frame did not advertise versions [1,2] and the exact physical/reassembled ceilings",
                );
            }
        }
        None => fail(
            failures,
            "ready_evidence",
            "pinned child retained no ready frame",
        ),
    }

    match driver.process().negotiation_frame() {
        Some(negotiation) => {
            retain_raw(
                negotiation,
                "protocol_negotiation",
                "prefer-v2-response",
                failures,
                evidence,
            );
            let value = negotiation.value();
            if value.get("type").and_then(Value::as_str) != Some("response")
                || value.get("id").and_then(Value::as_str) != Some(NEGOTIATE_REQUEST_ID)
                || value.get("command").and_then(Value::as_str) != Some("negotiate_protocol")
                || value.get("success").and_then(Value::as_bool) != Some(true)
                || value
                    .get("data")
                    .and_then(|data| data.get("protocolVersion"))
                    .and_then(Value::as_u64)
                    != Some(2)
            {
                fail(
                    failures,
                    "protocol_negotiation",
                    "prefer-v2 negotiation response was not the exact successful v2 acknowledgement",
                );
            }
        }
        None => fail(
            failures,
            "protocol_negotiation_evidence",
            "pinned child retained no negotiation response",
        ),
    }
}

fn validate_oversized_response(
    frame: &DecodedRpcFrame,
    request_id: &str,
    failures: &mut Vec<CaseFailure>,
    evidence: &mut Vec<CaseEvidence>,
) {
    retain_raw(
        frame,
        "oversized_response",
        "get-messages-logical",
        failures,
        evidence,
    );
    retain_lines(
        frame.lines(),
        "chunk_train",
        "get-messages-physical",
        failures,
        evidence,
    );

    validate_success_response(
        frame,
        request_id,
        "get_messages",
        "oversized_response_shape",
        failures,
    );

    if frame.raw().len() <= MAX_FRAME_BYTES {
        fail(
            failures,
            "oversized_response_size",
            format!(
                "logical response was {} bytes, not above the {MAX_FRAME_BYTES}-byte physical ceiling",
                frame.raw().len()
            ),
        );
    }
    if frame.raw().len() > MAX_REASSEMBLED_BYTES {
        fail(
            failures,
            "reassembly_ceiling",
            format!(
                "logical response was {} bytes, above the {MAX_REASSEMBLED_BYTES}-byte ceiling",
                frame.raw().len()
            ),
        );
    }
    if str::from_utf8(frame.raw()).is_err() {
        fail(
            failures,
            "reassembled_utf8",
            "successful logical response was not valid UTF-8",
        );
    }
    match serde_json::from_slice::<Value>(frame.raw()) {
        Ok(reparsed) => {
            if &reparsed != frame.value() {
                fail(
                    failures,
                    "reassembled_json",
                    "parsed reassembly differed from the decoder's retained object",
                );
            }
            if !reparsed.is_object() {
                fail(
                    failures,
                    "reassembled_object",
                    "successful reassembly was valid JSON but not an object",
                );
            }
        }
        Err(error) => fail(
            failures,
            "reassembled_json",
            format!("successful reassembly was not valid JSON: {error}"),
        ),
    }
    if !contains_big_payload(frame.value(), &payload_bytes(BIG_REPLY_BYTES)) {
        fail(
            failures,
            "oversized_response_content",
            format!(
                "response did not retain the deterministic {BIG_REPLY_BYTES}-byte assistant payload"
            ),
        );
    }

    validate_chunk_train(frame, failures);
}

fn validate_chunk_train(frame: &DecodedRpcFrame, failures: &mut Vec<CaseFailure>) {
    let lines = frame.lines();
    let expected_count = frame.raw().len().div_ceil(CHUNK_PAYLOAD_BYTES);
    if lines.len() < 2 || lines.len() != expected_count || lines.len() > MAX_CHUNK_COUNT {
        fail(
            failures,
            "chunk_count",
            format!(
                "observed {} chunks; expected {expected_count} within the {MAX_CHUNK_COUNT}-chunk ceiling",
                lines.len()
            ),
        );
    }

    let mut chunk_id: Option<String> = None;
    let mut offset = 0usize;
    for (ordinal, line) in lines.iter().enumerate() {
        if line.len() > MAX_FRAME_BYTES {
            fail(
                failures,
                "physical_frame_ceiling",
                format!("chunk {ordinal} occupied {} physical bytes", line.len()),
            );
        }
        if line.last() != Some(&b'\n') {
            fail(
                failures,
                "chunk_newline",
                format!("chunk {ordinal} lacked its exact transport newline"),
            );
            continue;
        }
        let content = &line[..line.len() - 1];
        if content.contains(&b'\n') {
            fail(
                failures,
                "chunk_newline",
                format!("chunk {ordinal} contained an embedded newline"),
            );
        }
        let physical = match serde_json::from_slice::<Value>(content) {
            Ok(value) => value,
            Err(error) => {
                fail(
                    failures,
                    "chunk_json",
                    format!("chunk {ordinal} was not JSON: {error}"),
                );
                continue;
            }
        };
        if !physical.is_object()
            || physical.get("type").and_then(Value::as_str) != Some("rpc_chunk")
        {
            fail(
                failures,
                "chunk_object",
                format!("physical frame {ordinal} was not an rpc_chunk object"),
            );
            continue;
        }

        let observed_id = physical.get("chunkId").and_then(Value::as_str);
        match (chunk_id.as_deref(), observed_id) {
            (None, Some(id)) if !id.is_empty() && id.encode_utf16().count() <= 128 => {
                chunk_id = Some(id.to_owned());
            }
            (Some(expected), Some(id)) if id == expected => {}
            _ => fail(
                failures,
                "chunk_identity",
                format!("chunk {ordinal} did not retain one bounded sequence id"),
            ),
        }
        if physical.get("index").and_then(Value::as_u64) != Some(ordinal as u64) {
            fail(
                failures,
                "chunk_order",
                format!("chunk at ordinal {ordinal} carried a different index"),
            );
        }
        if physical.get("count").and_then(Value::as_u64) != Some(lines.len() as u64) {
            fail(
                failures,
                "chunk_count",
                format!("chunk {ordinal} did not declare count {}", lines.len()),
            );
        }
        if physical.get("byteLength").and_then(Value::as_u64) != Some(frame.raw().len() as u64) {
            fail(
                failures,
                "chunk_byte_length",
                format!(
                    "chunk {ordinal} did not declare logical byte length {}",
                    frame.raw().len()
                ),
            );
        }

        let Some(data) = physical.get("data").and_then(Value::as_str) else {
            fail(
                failures,
                "chunk_base64",
                format!("chunk {ordinal} had no base64 string"),
            );
            continue;
        };
        let decoded = match STANDARD.decode(data.as_bytes()) {
            Ok(bytes) => bytes,
            Err(error) => {
                fail(
                    failures,
                    "chunk_base64",
                    format!("chunk {ordinal} base64 failed to decode: {error}"),
                );
                continue;
            }
        };
        if data.is_empty() || STANDARD.encode(&decoded) != data {
            fail(
                failures,
                "chunk_base64",
                format!("chunk {ordinal} was not canonical padded standard base64"),
            );
        }
        if decoded.is_empty() || decoded.len() > CHUNK_PAYLOAD_BYTES {
            fail(
                failures,
                "chunk_payload_ceiling",
                format!("chunk {ordinal} decoded to {} bytes", decoded.len()),
            );
        }
        if ordinal + 1 < lines.len() && decoded.len() != CHUNK_PAYLOAD_BYTES {
            fail(
                failures,
                "chunk_payload_length",
                format!(
                    "non-final chunk {ordinal} decoded to {} rather than {CHUNK_PAYLOAD_BYTES} bytes",
                    decoded.len()
                ),
            );
        }

        let Some(end) = offset.checked_add(decoded.len()) else {
            fail(
                failures,
                "chunk_reassembly",
                "chunk offsets overflowed usize",
            );
            continue;
        };
        if end > frame.raw().len() || frame.raw().get(offset..end) != Some(decoded.as_slice()) {
            fail(
                failures,
                "chunk_reassembly",
                format!("chunk {ordinal} did not reproduce its logical byte range"),
            );
        }
        offset = end;
    }
    if offset != frame.raw().len() {
        fail(
            failures,
            "chunk_reassembly",
            format!(
                "ordered chunk bytes covered {offset} of {} logical bytes",
                frame.raw().len()
            ),
        );
    }
}

#[derive(Clone, Copy)]
enum Fault {
    BadOrder,
    BadLength,
    ChunkPayloadOversize,
    PhysicalOversize,
    InvalidFrameUtf8,
    ReassemblyOversize,
}

impl Fault {
    const ALL: [Self; 6] = [
        Self::BadOrder,
        Self::BadLength,
        Self::ChunkPayloadOversize,
        Self::PhysicalOversize,
        Self::InvalidFrameUtf8,
        Self::ReassemblyOversize,
    ];

    fn label(self) -> &'static str {
        match self {
            Self::BadOrder => "bad-order",
            Self::BadLength => "bad-length",
            Self::ChunkPayloadOversize => "chunk-payload-oversize",
            Self::PhysicalOversize => "physical-oversize",
            Self::InvalidFrameUtf8 => "reassembled-invalid-utf8",
            Self::ReassemblyOversize => "reassembly-oversize",
        }
    }

    fn check(self) -> &'static str {
        match self {
            Self::BadOrder => "reject_bad_order",
            Self::BadLength => "reject_bad_length",
            Self::ChunkPayloadOversize => "reject_chunk_payload_oversize",
            Self::PhysicalOversize => "reject_physical_oversize",
            Self::InvalidFrameUtf8 => "reject_invalid_frame_utf8",
            Self::ReassemblyOversize => "reject_reassembly_oversize",
        }
    }

    fn injection(self) -> (&'static str, Value) {
        match self {
            Self::BadOrder => (
                "fixture_emit",
                json!({
                    "lines": [chunk_line(
                        "odin-bad-order",
                        1,
                        2,
                        MAX_FRAME_BYTES as u64,
                        b"{}",
                    )],
                }),
            ),
            Self::BadLength => (
                "fixture_emit",
                json!({
                    "lines": [
                        chunk_line(
                            "odin-bad-length",
                            0,
                            2,
                            MAX_FRAME_BYTES as u64,
                            b"{",
                        ),
                        chunk_line(
                            "odin-bad-length",
                            1,
                            2,
                            MAX_FRAME_BYTES as u64,
                            b"}",
                        ),
                    ],
                }),
            ),
            Self::ChunkPayloadOversize => {
                let payload = vec![b'x'; CHUNK_PAYLOAD_BYTES + 1];
                (
                    "fixture_emit",
                    json!({
                        "lines": [chunk_line(
                            "odin-payload-oversize",
                            0,
                            2,
                            MAX_FRAME_BYTES as u64,
                            &payload,
                        )],
                    }),
                )
            }
            Self::PhysicalOversize => (
                "fixture_emit_fault",
                json!({ "fault": "physical_oversize" }),
            ),
            Self::InvalidFrameUtf8 => (
                "fixture_emit_fault",
                json!({ "fault": "reassembled_invalid_utf8" }),
            ),
            Self::ReassemblyOversize => (
                "fixture_emit",
                json!({
                    "lines": [chunk_line(
                        "odin-reassembly-oversize",
                        0,
                        2,
                        MAX_REASSEMBLED_BYTES as u64 + 1,
                        b"x",
                    )],
                }),
            ),
        }
    }

    fn matches(self, error: &OmpProcessError) -> bool {
        match (self, error) {
            (fault, OmpProcessError::FrameRejected(rejection)) => match (fault, rejection.kind()) {
                (Self::BadOrder, RpcFrameErrorKind::ChunkSequenceStart { index }) => *index == 1,
                (
                    Self::BadLength,
                    RpcFrameErrorKind::ChunkSequenceLengthMismatch { received, declared },
                ) => *received == 2 && *declared == MAX_FRAME_BYTES as u64,
                (Self::ChunkPayloadOversize, RpcFrameErrorKind::ChunkPayloadTooLarge { size }) => {
                    *size == CHUNK_PAYLOAD_BYTES + 1
                }
                (Self::PhysicalOversize, RpcFrameErrorKind::FrameTooLarge { size }) => {
                    let [prefix] = rejection.evidence() else {
                        return false;
                    };
                    *size == MAX_FRAME_BYTES + 1
                        && prefix.len() == MAX_FRAME_BYTES
                        && prefix.iter().all(|byte| *byte == b'x')
                }
                (Self::InvalidFrameUtf8, RpcFrameErrorKind::InvalidFrameUtf8) => true,
                (Self::ReassemblyOversize, RpcFrameErrorKind::InvalidChunkMetadata) => true,
                _ => false,
            },
            _ => false,
        }
    }
}

async fn observe_fault(
    context: &CaseContext,
    fault: Fault,
    deadline: Instant,
    started_children: &mut usize,
    failures: &mut Vec<CaseFailure>,
    evidence: &mut Vec<CaseEvidence>,
    cleanup: &mut CleanupReceipt,
) -> bool {
    if Instant::now() >= deadline {
        fail(
            failures,
            fault.check(),
            format!("work deadline elapsed before {} injection", fault.label()),
        );
        return false;
    }

    let spec = context.fault_spec(Vec::new());
    let worker = context.worker_for(&spec);
    let mut driver = match RawRpcDriver::spawn(spec, worker).await {
        Ok(driver) => driver,
        Err(error) => {
            fail(
                failures,
                fault.check(),
                format!("fault fixture did not start for {}: {error}", fault.label()),
            );
            return false;
        }
    };
    *started_children += 1;

    let validated =
        inject_and_validate_fault(&mut driver, fault, deadline, failures, evidence).await;
    kill_fault_driver(
        &mut driver,
        cleanup,
        &format!("framing-fault-{}", fault.label()),
        failures,
    )
    .await;
    validated
}

async fn inject_and_validate_fault(
    driver: &mut RawRpcDriver,
    fault: Fault,
    deadline: Instant,
    failures: &mut Vec<CaseFailure>,
    evidence: &mut Vec<CaseEvidence>,
) -> bool {
    let (command, fields) = fault.injection();
    let request_id = match driver.send(command, fields).await {
        Ok(id) => id,
        Err(error) => {
            fail(
                failures,
                fault.check(),
                format!("{} injection was not sent: {error}", fault.label()),
            );
            return false;
        }
    };
    let acknowledgement = match driver
        .wait_for_response(&request_id, command, deadline)
        .await
    {
        Ok(response) => response,
        Err(error) => {
            fail(
                failures,
                fault.check(),
                format!("{} injection was not acknowledged: {error}", fault.label()),
            );
            return false;
        }
    };
    if !response_success(&acknowledgement, &request_id, command) {
        fail(
            failures,
            fault.check(),
            response_failure_detail(&acknowledgement, &request_id, command),
        );
        return false;
    }

    match driver.collect_until(deadline, |_| true).await {
        Err(RawRpcError::Process(error)) => {
            record_process_rejection(fault, &error, failures, evidence);
            let matched = fault.matches(&error);
            if !matched {
                fail(
                    failures,
                    fault.check(),
                    format!("{} produced the wrong typed error: {error}", fault.label()),
                );
            }
            matched
        }
        Err(error) => {
            fail(
                failures,
                fault.check(),
                format!(
                    "{} did not produce a process rejection: {error}",
                    fault.label()
                ),
            );
            false
        }
        Ok(frames) => {
            if let Some(frame) = frames.first() {
                retain_raw(frame, "unexpected_frame", fault.label(), failures, evidence);
            }
            fail(
                failures,
                fault.check(),
                format!("{} was accepted as a logical frame", fault.label()),
            );
            false
        }
    }
}

fn record_process_rejection(
    fault: Fault,
    error: &OmpProcessError,
    failures: &mut Vec<CaseFailure>,
    evidence: &mut Vec<CaseEvidence>,
) {
    let typed = match error {
        OmpProcessError::FrameRejected(rejection) => format!("{:?}\n", rejection.kind()),
        _ => format!("{error}\n"),
    };
    evidence.push(CaseEvidence {
        kind: "typed_rejection",
        label: fault.label().to_owned(),
        bytes: typed.into_bytes(),
    });

    if let OmpProcessError::FrameRejected(rejection) = error {
        if rejection.evidence().is_empty() {
            fail(
                failures,
                "fault_wire_evidence",
                format!("{} rejection retained no physical input", fault.label()),
            );
        }
        retain_lines(
            rejection.evidence(),
            "fault_wire",
            &format!("{}-physical", fault.label()),
            failures,
            evidence,
        );
    }
}

fn chunk_line(chunk_id: &str, index: u64, count: u64, byte_length: u64, payload: &[u8]) -> String {
    json!({
        "type": "rpc_chunk",
        "chunkId": chunk_id,
        "index": index,
        "count": count,
        "byteLength": byte_length,
        "data": STANDARD.encode(payload),
    })
    .to_string()
}

fn validate_success_response(
    frame: &DecodedRpcFrame,
    request_id: &str,
    command: &str,
    check: &'static str,
    failures: &mut Vec<CaseFailure>,
) -> bool {
    if response_success(frame, request_id, command) {
        true
    } else {
        fail(
            failures,
            check,
            response_failure_detail(frame, request_id, command),
        );
        false
    }
}

async fn kill_fault_driver(
    driver: &mut RawRpcDriver,
    cleanup: &mut CleanupReceipt,
    subject: &str,
    failures: &mut Vec<CaseFailure>,
) {
    let outcome = match driver.kill().await {
        Ok(_) => CleanupOutcome::Clean,
        Err(error) => {
            fail(
                failures,
                "bounded_cleanup",
                format!("{subject} bounded kill failed: {error}"),
            );
            CleanupOutcome::Failed {
                reason: error.to_string(),
            }
        }
    };
    cleanup.push("child_kill", subject, outcome);
}
