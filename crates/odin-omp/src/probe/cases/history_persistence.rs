//! Case module `history_persistence` — history paging and session durability.
//!
//! Owns cases 14 and 15 of the frozen conformance suite. Long histories use
//! the deterministic mock
//! provider; resume reopens the same pinned OMP session after a bounded stop.

mod paging;
mod stop_resume;

use std::collections::HashSet;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use serde_json::{json, Map, Value};
use tokio::time::sleep;

use crate::frames::DecodedRpcFrame;
pub(super) use crate::probe::cases::wire::{contains_text, message_text};
use crate::probe::{
    CaseEvidence, CaseFailure, CaseOutcome, CleanupReceipt, ConformanceCase, ConformanceCaseId,
    RawRpcDriver,
};

use self::paging::HistoryPagingCase;
use self::stop_resume::SessionStopResumeCase;

/// Case 14 — page a long message history on top of the session's captured
/// baseline: every echo turn must append exactly one semantic user/assistant
/// pair, page totals and cursors must match the final state without
/// duplication, and busy/stale-cursor handling must never silently mix
/// snapshots.
pub const HISTORY_PAGING: ConformanceCaseId = ConformanceCaseId::new(14);
/// Case 15 — persist, stop, and resume a session.
pub const SESSION_STOP_RESUME: ConformanceCaseId = ConformanceCaseId::new(15);

const CASE_DEADLINE: Duration = Duration::from_secs(120);
const RESPONSE_DEADLINE: Duration = Duration::from_secs(10);
const IDLE_POLL_INTERVAL: Duration = Duration::from_millis(20);
const MAX_IDLE_POLLS: usize = 256;

const PAGE_LIMIT: usize = 4;
const MAX_HISTORY_PAGES: usize = 64;
const MAX_PAGE_MESSAGE_BYTES: usize = 768 * 1024;
const MAX_CURSOR_CHARS: usize = 2048;

#[derive(Debug)]
struct CaseCheck {
    check: &'static str,
    detail: String,
}
type CheckResult<T> = Result<T, CaseCheck>;

impl CaseCheck {
    fn new(check: &'static str, detail: impl Into<String>) -> Self {
        Self {
            check,
            detail: detail.into(),
        }
    }
}

struct PageDrain {
    messages: Vec<Value>,
    responses: Vec<Value>,
    total: usize,
    first_next_cursor: Option<String>,
}

/// The module's two fixed registration slots.
pub fn cases() -> Vec<Arc<dyn ConformanceCase>> {
    vec![Arc::new(HistoryPagingCase), Arc::new(SessionStopResumeCase)]
}

async fn prompt_and_wait(
    driver: &mut RawRpcDriver,
    message: &str,
    minimum_count: usize,
    check: &'static str,
) -> CheckResult<Value> {
    let response = request(
        driver,
        "prompt",
        json!({"message": message, "images": []}),
        check,
    )
    .await?;
    expect_success(&response, "prompt", check)?;
    wait_for_idle(driver, minimum_count, check).await
}

async fn wait_for_idle(
    driver: &mut RawRpcDriver,
    minimum_count: usize,
    check: &'static str,
) -> CheckResult<Value> {
    let mut attempt = 0;
    loop {
        let state = get_state(driver, check).await?;
        let message_count = state_message_count(&state, check)?;
        let streaming = state.get("isStreaming").and_then(Value::as_bool);
        let compacting = state.get("isCompacting").and_then(Value::as_bool);
        if streaming == Some(false) && compacting == Some(false) && message_count >= minimum_count {
            return Ok(state);
        }
        attempt += 1;
        if attempt == MAX_IDLE_POLLS {
            return Err(CaseCheck::new(
                check,
                format!(
                    "session did not become idle at {minimum_count} messages; \
                     last count {message_count}"
                ),
            ));
        }
        sleep(IDLE_POLL_INTERVAL).await;
    }
}

async fn get_state(driver: &mut RawRpcDriver, check: &'static str) -> CheckResult<Value> {
    let response = request(driver, "get_state", json!({}), check).await?;
    expect_success(&response, "get_state", check)?;
    let data = response_data(&response, check)?.clone();
    if !data.is_object() {
        return Err(CaseCheck::new(check, "get_state data was not an object"));
    }
    Ok(data)
}

async fn page_all(driver: &mut RawRpcDriver, check: &'static str) -> CheckResult<PageDrain> {
    let mut messages = Vec::new();
    let mut responses = Vec::new();
    let mut cursor: Option<String> = None;
    let mut first_next_cursor = None;
    let mut total = None;
    let mut cursor_identity: Option<Value> = None;
    let mut seen_cursors = HashSet::new();

    for page_index in 0..MAX_HISTORY_PAGES {
        let response = request(
            driver,
            "get_messages_page",
            page_fields(cursor.as_deref()),
            check,
        )
        .await?;
        expect_success(&response, "get_messages_page", check)?;
        let object = response_data(&response, check)?
            .as_object()
            .ok_or_else(|| CaseCheck::new(check, "page data was not an object"))?;
        let page = object
            .get("messages")
            .and_then(Value::as_array)
            .ok_or_else(|| CaseCheck::new(check, "page omitted its message array"))?;
        if page.len() > PAGE_LIMIT {
            return Err(CaseCheck::new(
                check,
                format!(
                    "page {page_index} returned {} messages above limit {PAGE_LIMIT}",
                    page.len()
                ),
            ));
        }
        let page_bytes = serde_json::to_vec(page)
            .map_err(|error| CaseCheck::new(check, format!("serializing page: {error}")))?
            .len();
        if page_bytes > MAX_PAGE_MESSAGE_BYTES {
            return Err(CaseCheck::new(
                check,
                format!("page {page_index} used {page_bytes} message bytes above the pinned bound"),
            ));
        }

        let page_total = object
            .get("totalMessages")
            .and_then(Value::as_u64)
            .and_then(|value| usize::try_from(value).ok())
            .ok_or_else(|| CaseCheck::new(check, "page totalMessages was not a bounded integer"))?;
        match total {
            Some(expected) if page_total != expected => {
                return Err(CaseCheck::new(
                    check,
                    format!("page total changed from {expected} to {page_total}"),
                ));
            }
            None => total = Some(page_total),
            _ => {}
        }

        let next_cursor = match object.get("nextCursor") {
            Some(Value::String(value)) => Some(value.clone()),
            Some(_) => return Err(CaseCheck::new(check, "nextCursor was not a string")),
            None => None,
        };
        if next_cursor.is_some() && page.is_empty() {
            return Err(CaseCheck::new(check, "non-terminal page made no progress"));
        }

        messages.extend(page.iter().cloned());
        if messages.len() > page_total {
            return Err(CaseCheck::new(
                check,
                format!("page drain exceeded advertised total {page_total}"),
            ));
        }
        if let Some(next) = &next_cursor {
            if !seen_cursors.insert(next.clone()) {
                return Err(CaseCheck::new(
                    check,
                    "paging repeated a continuation cursor",
                ));
            }
            let identity = validate_cursor(next, page_total, messages.len(), check)?;
            match &cursor_identity {
                Some(expected) if expected != &identity => {
                    return Err(CaseCheck::new(
                        check,
                        "cursor session/leaf/message-count identity changed within one drain",
                    ));
                }
                None => cursor_identity = Some(identity),
                _ => {}
            }
            if first_next_cursor.is_none() {
                first_next_cursor = Some(next.clone());
            }
        }

        responses.push(response.value().clone());
        cursor = next_cursor;
        if cursor.is_none() {
            if messages.len() != page_total {
                return Err(CaseCheck::new(
                    check,
                    format!(
                        "paging ended at {} messages before total {page_total}",
                        messages.len()
                    ),
                ));
            }
            return Ok(PageDrain {
                messages,
                responses,
                total: page_total,
                first_next_cursor,
            });
        }
    }

    Err(CaseCheck::new(
        check,
        format!("paging exceeded the fixed {MAX_HISTORY_PAGES}-page bound"),
    ))
}

async fn request(
    driver: &mut RawRpcDriver,
    command: &str,
    fields: Value,
    check: &'static str,
) -> CheckResult<DecodedRpcFrame> {
    let id = driver
        .send(command, fields)
        .await
        .map_err(|error| CaseCheck::new(check, error.to_string()))?;
    driver
        .wait_for_response(&id, command, Instant::now() + RESPONSE_DEADLINE)
        .await
        .map_err(|error| CaseCheck::new(check, error.to_string()))
}

fn expect_success(
    response: &DecodedRpcFrame,
    command: &str,
    check: &'static str,
) -> CheckResult<()> {
    let value = response.value();
    if value.get("success").and_then(Value::as_bool) != Some(true) {
        return Err(CaseCheck::new(
            check,
            format!("{command} returned a non-success response: {value}"),
        ));
    }
    Ok(())
}

fn expect_page_error(
    response: &DecodedRpcFrame,
    expected_code: &str,
    check: &'static str,
) -> CheckResult<()> {
    let value = response.value();
    if value.get("success").and_then(Value::as_bool) != Some(false)
        || value.get("code").and_then(Value::as_str) != Some(expected_code)
    {
        return Err(CaseCheck::new(
            check,
            format!("expected paging error code `{expected_code}`, observed {value}"),
        ));
    }
    if value.get("data").is_some() || value.get("messages").is_some() {
        return Err(CaseCheck::new(
            check,
            format!("paging error `{expected_code}` leaked partial snapshot data"),
        ));
    }
    Ok(())
}

fn response_data<'a>(response: &'a DecodedRpcFrame, check: &'static str) -> CheckResult<&'a Value> {
    response
        .value()
        .get("data")
        .ok_or_else(|| CaseCheck::new(check, "successful response omitted data"))
}

fn page_fields(cursor: Option<&str>) -> Value {
    let mut fields = Map::new();
    fields.insert("limit".to_owned(), json!(PAGE_LIMIT));
    if let Some(cursor) = cursor {
        fields.insert("cursor".to_owned(), Value::String(cursor.to_owned()));
    }
    Value::Object(fields)
}

fn validate_cursor(
    cursor: &str,
    total: usize,
    expected_offset: usize,
    check: &'static str,
) -> CheckResult<Value> {
    if cursor.is_empty() || cursor.len() > MAX_CURSOR_CHARS {
        return Err(CaseCheck::new(
            check,
            format!("cursor length {} is outside the pinned bound", cursor.len()),
        ));
    }
    let bytes = URL_SAFE_NO_PAD
        .decode(cursor)
        .map_err(|error| CaseCheck::new(check, format!("cursor was not base64url: {error}")))?;
    if URL_SAFE_NO_PAD.encode(&bytes) != cursor {
        return Err(CaseCheck::new(
            check,
            "cursor base64url encoding was not canonical",
        ));
    }
    let payload: Value = serde_json::from_slice(&bytes)
        .map_err(|error| CaseCheck::new(check, format!("cursor JSON was invalid: {error}")))?;
    let object = payload
        .as_object()
        .ok_or_else(|| CaseCheck::new(check, "cursor payload was not an object"))?;
    if object.get("version").and_then(Value::as_u64) != Some(1) {
        return Err(CaseCheck::new(check, "cursor version was not 1"));
    }
    let session_id = object
        .get("sessionId")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| CaseCheck::new(check, "cursor omitted sessionId"))?;
    let leaf_id = object
        .get("leafId")
        .cloned()
        .ok_or_else(|| CaseCheck::new(check, "cursor omitted leafId"))?;
    if !(leaf_id.is_null() || leaf_id.as_str().is_some_and(|value| !value.is_empty())) {
        return Err(CaseCheck::new(
            check,
            "cursor leafId was neither null nor a non-empty string",
        ));
    }
    let message_count = object
        .get("messageCount")
        .and_then(Value::as_u64)
        .and_then(|value| usize::try_from(value).ok())
        .ok_or_else(|| CaseCheck::new(check, "cursor messageCount was invalid"))?;
    let offset = object
        .get("offset")
        .and_then(Value::as_u64)
        .and_then(|value| usize::try_from(value).ok())
        .ok_or_else(|| CaseCheck::new(check, "cursor offset was invalid"))?;
    if message_count != total || offset != expected_offset {
        return Err(CaseCheck::new(
            check,
            format!(
                "cursor snapshot/offset mismatch: count {message_count}/{total}, \
                 offset {offset}/{expected_offset}"
            ),
        ));
    }
    Ok(json!({
        "sessionId": session_id,
        "leafId": leaf_id,
        "messageCount": message_count,
    }))
}

fn state_message_count(state: &Value, check: &'static str) -> CheckResult<usize> {
    state
        .get("messageCount")
        .and_then(Value::as_u64)
        .and_then(|value| usize::try_from(value).ok())
        .ok_or_else(|| CaseCheck::new(check, "state messageCount was not a bounded integer"))
}

fn session_dir_args(session_dir: &Path) -> Vec<String> {
    vec![
        "--session-dir".to_owned(),
        session_dir.to_string_lossy().into_owned(),
    ]
}

fn child_subject(driver: &RawRpcDriver, label: &str) -> String {
    match driver.process().worker_id().map(ToString::to_string) {
        Some(worker) => format!("{label} worker {worker}"),
        None => label.to_owned(),
    }
}

fn digest_value(value: &Value, check: &'static str) -> CheckResult<String> {
    let bytes = serde_json::to_vec(value)
        .map_err(|error| CaseCheck::new(check, format!("serializing digest input: {error}")))?;
    Ok(blake3::hash(&bytes).to_hex().to_string())
}

fn push_json_evidence(
    evidence: &mut Vec<CaseEvidence>,
    kind: &'static str,
    label: &str,
    value: &Value,
    check: &'static str,
) -> CheckResult<()> {
    let bytes = serde_json::to_vec(value)
        .map_err(|error| CaseCheck::new(check, format!("serializing evidence: {error}")))?;
    evidence.push(CaseEvidence {
        kind,
        label: label.to_owned(),
        bytes,
    });
    Ok(())
}

fn push_transcript_evidence(
    evidence: &mut Vec<CaseEvidence>,
    label: &str,
    transcript: &[DecodedRpcFrame],
) -> CheckResult<()> {
    let frames = transcript
        .iter()
        .enumerate()
        .map(|(index, frame)| {
            let value = frame.value();
            json!({
                "index": index,
                "type": value.get("type"),
                "id": value.get("id"),
                "command": value.get("command"),
                "success": value.get("success"),
                "logical_bytes": frame.raw().len(),
                "physical_frames": frame.lines().len(),
                "digest": blake3::hash(frame.raw()).to_hex().to_string(),
            })
        })
        .collect::<Vec<_>>();
    push_json_evidence(
        evidence,
        "rpc_transcript",
        label,
        &Value::Array(frames),
        "transcript_evidence",
    )
}

fn finish_case(
    pass_summary: &'static str,
    fail_summary: &'static str,
    result: CheckResult<()>,
    mut evidence: Vec<CaseEvidence>,
    cleanup: CleanupReceipt,
    required_evidence: &[&str],
    minimum_cleanup_steps: usize,
) -> CaseOutcome {
    let mut failures = Vec::new();
    if let Err(error) = result {
        evidence.push(CaseEvidence {
            kind: "failure",
            label: error.check.to_owned(),
            bytes: error.detail.as_bytes().to_vec(),
        });
        failures.push(CaseFailure {
            check: (error.check).to_owned(),
            detail: error.detail,
        });
    }
    for required in required_evidence {
        if !evidence.iter().any(|item| item.kind == *required) {
            failures.push(CaseFailure {
                check: ("evidence").to_owned(),
                detail: format!("required `{required}` evidence was not produced"),
            });
        }
    }
    if cleanup.steps.len() < minimum_cleanup_steps {
        failures.push(CaseFailure {
            check: ("cleanup").to_owned(),
            detail: format!(
                "expected at least {minimum_cleanup_steps} cleanup step(s), recorded {}",
                cleanup.steps.len()
            ),
        });
    }
    if !cleanup.is_clean() {
        failures.push(CaseFailure {
            check: ("cleanup").to_owned(),
            detail: "one or more explicit cleanup steps failed".to_owned(),
        });
    }

    let mut outcome = if failures.is_empty() {
        CaseOutcome::pass(pass_summary)
    } else {
        CaseOutcome::fail(fail_summary, failures)
    };
    outcome.evidence = evidence;
    outcome.cleanup = cleanup;
    outcome
}

#[cfg(test)]
mod tests {
    use super::stop_resume::{changed_projection_keys, durable_state_projection};
    use super::*;

    /// A `get_state` wire fixture carrying every required durable field; the
    /// optional fields are inserted only when `Some`, so `None` reproduces a
    /// genuinely absent wire key rather than an explicit null.
    fn wire_state(thinking_level: Option<Value>, session_name: Option<Value>) -> Value {
        let mut state = json!({
            "model": "odin-mock",
            "steeringMode": "off",
            "followUpMode": "off",
            "interruptMode": "off",
            "sessionId": "session-1",
            "sessionFile": "/tmp/session-1.jsonl",
            "autoCompactionEnabled": true,
            "fastModeEnabled": false,
            "messageCount": 8,
            "queuedMessageCount": 0,
            "todoPhases": [],
        });
        let object = state.as_object_mut().expect("fixture state object");
        if let Some(level) = thinking_level {
            object.insert("thinkingLevel".to_owned(), level);
        }
        if let Some(name) = session_name {
            object.insert("sessionName".to_owned(), name);
        }
        state
    }

    fn projection_for(thinking_level: Option<Value>, session_name: Option<Value>) -> Value {
        durable_state_projection(
            &wire_state(thinking_level, session_name),
            "projection_fixture",
        )
        .expect("fixture projection")
    }

    /// A real setting never normalizes into another: absence is "off", so a configured level,
    /// a different level, or a changed required field is drift named by its key.
    #[test]
    fn a_real_change_is_named_by_its_key() {
        let level = |value: &str| Some(json!(value));
        for (before, after, changed) in [
            (
                projection_for(None, None),
                projection_for(level("high"), Some(json!("resume lane"))),
                vec!["sessionName", "thinkingLevel"],
            ),
            (
                projection_for(level("low"), None),
                projection_for(level("high"), None),
                vec!["thinkingLevel"],
            ),
            (
                projection_for(level("off"), None),
                projection_for(level("low"), None),
                vec!["thinkingLevel"],
            ),
        ] {
            assert_eq!(changed_projection_keys(&before, &after), changed);
        }

        let before = wire_state(None, None);
        let mut after = before.clone();
        after["model"] = json!("odin-mock-alt");
        let project = |state: &Value| durable_state_projection(state, "fixture").unwrap();
        assert_eq!(
            changed_projection_keys(&project(&before), &project(&after)),
            ["model"]
        );
    }

    fn cursor(payload: Value) -> String {
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(&payload).unwrap())
    }

    /// One canonical cursor passes; each rule that makes paging continuity provable refuses its own corruption.
    #[test]
    fn a_page_cursor_must_be_canonical_and_name_the_snapshot_and_offset() {
        let valid =
            json!({"version": 1, "sessionId": "s", "leafId": null, "messageCount": 8, "offset": 4});
        assert!(validate_cursor(&cursor(valid.clone()), 8, 4, "c").is_ok());

        let with = |key: &str, value: Value| {
            let mut payload = valid.clone();
            payload[key] = value;
            cursor(payload)
        };
        let mut missing_session = valid.clone();
        missing_session.as_object_mut().unwrap().remove("sessionId");
        let refused = [
            String::new(),
            "not base64url!".to_owned(),
            URL_SAFE_NO_PAD.encode(b"[1]"),
            with("version", json!(2)),
            cursor(missing_session),
            with("leafId", json!("")),
            with("messageCount", json!(9)),
            with("offset", json!(5)),
        ];
        for cursor in refused {
            assert!(validate_cursor(&cursor, 8, 4, "c").is_err(), "{cursor:?}");
        }
        // The same bytes with a trailing pad character are not the canonical encoding.
        let padded = format!("{}=", cursor(valid));
        assert!(validate_cursor(&padded, 8, 4, "c").is_err());
    }
}
