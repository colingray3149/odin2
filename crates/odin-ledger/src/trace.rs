//! Content-addressed model-request traces and the local export that
//! reconstructs them.
//!
//! Blobs are stored once, keyed by the ledger BLAKE3 of their serde JSON
//! and looked up by the extension's wire SHA-256. A second wire hash of the
//! same body is an alias, not a second blob. A call row names those blobs
//! by JSON path. Export reads this ledger, never a transcript.

use crate::{decode_utc, encode_utc, Ledger, LedgerError, LedgerResult};
use odin_domain::job_report::{reported_jobs, started_job, REPORT_TURN};
use odin_domain::knowledge::PrivacyClass;
use odin_domain::{Digest, SessionId};
use rusqlite::{params, OptionalExtension};
use serde_json::{Map, Value};
use std::collections::BTreeMap;
use time::OffsetDateTime;

pub const EXPORT_SCHEMA: &str = "odin.trace.export.v2";

#[derive(Clone, Debug, PartialEq)]
pub struct TraceBlob {
    pub digest: Digest,
    pub wire_sha256: String,
    pub kind: String,
    pub body: Value,
}

#[derive(Clone, Debug, PartialEq)]
pub struct NewTraceCall {
    pub session_id: SessionId,
    pub entry_id: String,
    pub occurred_at: OffsetDateTime,
    pub call_id: String,
    pub payload_digest: String,
    pub provider: Option<String>,
    pub model: Option<String>,
    pub api: Option<String>,
    pub skeleton: Value,
    pub trace_error: Option<String>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct TraceLink {
    pub session_id: SessionId,
    pub call_id: String,
    pub payload_digest: String,
    pub request_id: Option<String>,
    pub response_id: Option<String>,
    pub tool_ids: Vec<String>,
    pub trace_error: Option<String>,
    /// Deployment that answered (`x-litellm-model-name`). Absent means unknown, never a copy of the request.
    pub served_model: Option<String>,
    /// Gateway lane (`x-litellm-model-group`).
    pub model_group: Option<String>,
    /// `x-litellm-attempted-fallbacks`, including zero.
    pub attempted_fallbacks: Option<i64>,
    /// `x-litellm-call-id`.
    pub gateway_call_id: Option<String>,
    /// `x-litellm-response-cost` when that header was present. Streams omit it.
    pub response_cost: Option<String>,
}

#[derive(Clone, Debug)]
pub struct TraceCursor {
    pub path: String,
    pub offset: u64,
}

impl Ledger {
    /// Inserts a blob once. The digest must be the ledger hash of the serde
    /// body. A repeated wire hash with different bytes is a conflict. A new
    /// wire hash of an already stored body records an alias.
    pub fn put_trace_blob(&mut self, blob: &TraceBlob) -> LedgerResult<()> {
        let body = serde_json::to_string(&blob.body)?;
        if blob.digest != Digest::hash(body.as_bytes()) {
            return Err(LedgerError::Conflict(format!(
                "trace blob digest {} is not the ledger hash of its body",
                blob.digest
            )));
        }
        let digest = blob.digest.to_string();
        self.with_tx(|tx| {
            let existing: Option<(String, String)> = tx
                .query_row(
                    "SELECT digest, body_json FROM trace_blobs WHERE wire_sha256=?1",
                    [&blob.wire_sha256],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .optional()?;
            if let Some((stored_digest, stored_body)) = existing {
                if stored_digest != digest || stored_body != body {
                    return Err(LedgerError::Conflict(format!(
                        "trace blob {} already stores different bytes",
                        blob.wire_sha256
                    )));
                }
                return Ok(());
            }
            let alias: Option<String> = tx
                .query_row(
                    "SELECT digest FROM trace_blob_aliases WHERE wire_sha256=?1",
                    [&blob.wire_sha256],
                    |row| row.get(0),
                )
                .optional()?;
            if let Some(stored) = alias {
                if stored != digest {
                    return Err(LedgerError::Conflict(format!(
                        "trace blob alias {} already names a different body",
                        blob.wire_sha256
                    )));
                }
                return Ok(());
            }
            let stored_body: Option<String> = tx
                .query_row(
                    "SELECT body_json FROM trace_blobs WHERE digest=?1",
                    [&digest],
                    |row| row.get(0),
                )
                .optional()?;
            if let Some(stored_body) = stored_body {
                if stored_body != body {
                    return Err(LedgerError::Conflict(format!(
                        "trace blob digest {digest} already stores different bytes"
                    )));
                }
                tx.execute(
                    "INSERT INTO trace_blob_aliases(wire_sha256,digest) VALUES(?1,?2)",
                    params![blob.wire_sha256, digest],
                )?;
                return Ok(());
            }
            tx.execute(
                "INSERT INTO trace_blobs(digest,wire_sha256,kind,body_json) VALUES(?1,?2,?3,?4)",
                params![digest, blob.wire_sha256, blob.kind, body],
            )?;
            Ok(())
        })
    }

    pub fn trace_blob_by_wire(&self, wire_sha256: &str) -> LedgerResult<Option<Value>> {
        let body: Option<String> = self
            .connection()
            .query_row(
                "SELECT body_json FROM trace_blobs WHERE wire_sha256=?1 \
                 UNION ALL \
                 SELECT b.body_json FROM trace_blob_aliases a \
                   JOIN trace_blobs b ON b.digest=a.digest \
                  WHERE a.wire_sha256=?1 \
                 LIMIT 1",
                [wire_sha256],
                |row| row.get(0),
            )
            .optional()?;
        body.map(|raw| serde_json::from_str(&raw).map_err(LedgerError::from))
            .transpose()
    }

    /// Inserts one captured request. A repeated entry id is a no-op so a
    /// cursor replay of the same line cannot duplicate the call.
    pub fn insert_trace_call(&mut self, call: &NewTraceCall) -> LedgerResult<bool> {
        let at = encode_utc(call.occurred_at)?;
        let skeleton = serde_json::to_string(&call.skeleton)?;
        self.with_tx(|tx| {
            let inserted = tx.execute(
                "INSERT OR IGNORE INTO trace_calls(session_id,entry_id,occurred_at,call_id,payload_digest,provider,model,api,skeleton_json,tool_ids_json,trace_error) VALUES(?1,?2,?3,NULLIF(?4,''),?5,?6,?7,?8,?9,'[]',?10)",
                params![
                    call.session_id.as_str(),
                    call.entry_id,
                    at,
                    call.call_id,
                    call.payload_digest,
                    call.provider,
                    call.model,
                    call.api,
                    skeleton,
                    call.trace_error,
                ],
            )?;
            Ok(inserted == 1)
        })
    }

    /// Attaches actual request, response, and tool ids the extension observed.
    /// Missing ids stay null and the error text is kept. The response is not
    /// dropped.
    pub fn link_trace_call(&mut self, link: &TraceLink) -> LedgerResult<bool> {
        if link.call_id.is_empty() {
            return Ok(false);
        }
        let tools = serde_json::to_string(&link.tool_ids)?;
        self.with_tx(|tx| {
            let updated = tx.execute(
                "UPDATE trace_calls SET request_id=COALESCE(?3, request_id), response_id=COALESCE(?4, response_id), tool_ids_json=CASE WHEN ?5 = '[]' THEN tool_ids_json ELSE ?5 END, trace_error=CASE WHEN ?6 IS NULL THEN trace_error WHEN trace_error IS NULL THEN ?6 ELSE trace_error || '; ' || ?6 END, served_model=COALESCE(?7, served_model), model_group=COALESCE(?8, model_group), attempted_fallbacks=COALESCE(?9, attempted_fallbacks), gateway_call_id=COALESCE(?10, gateway_call_id), response_cost=COALESCE(?11, response_cost) WHERE session_id=?1 AND call_id=?2",
                params![
                    link.session_id.as_str(),
                    link.call_id,
                    link.request_id,
                    link.response_id,
                    tools,
                    link.trace_error,
                    link.served_model,
                    link.model_group,
                    link.attempted_fallbacks,
                    link.gateway_call_id,
                    link.response_cost,
                ],
            )?;
            Ok(updated > 0)
        })
    }

    pub fn trace_cursor(&self, session: &SessionId) -> LedgerResult<Option<TraceCursor>> {
        let stored = self
            .connection()
            .query_row(
                "SELECT path, byte_offset FROM trace_cursors WHERE session_id=?1",
                [session.as_str()],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?)),
            )
            .optional()?;
        stored
            .map(|(path, offset)| {
                let offset = u64::try_from(offset).map_err(|_| {
                    LedgerError::invalid_data(format!(
                        "trace cursor of session {session} holds the negative offset {offset}"
                    ))
                })?;
                Ok(TraceCursor { path, offset })
            })
            .transpose()
    }

    /// Advances the cursor. A shrink below the stored offset is refused: the
    /// caller must not reread the file from byte 0.
    pub fn advance_trace_cursor(
        &mut self,
        session: &SessionId,
        path: &str,
        offset: u64,
    ) -> LedgerResult<()> {
        let offset = i64::try_from(offset).map_err(|error| {
            LedgerError::invalid_data_caused_by(
                format!("trace cursor {offset} does not fit a signed integer"),
                error,
            )
        })?;
        self.with_tx(|tx| {
            let current: Option<(String, i64)> = tx
                .query_row(
                    "SELECT path, byte_offset FROM trace_cursors WHERE session_id=?1",
                    [session.as_str()],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .optional()?;
            if let Some((stored_path, stored)) = current {
                if stored_path == path && offset < stored {
                    return Err(LedgerError::Conflict(format!(
                        "trace cursor for {session} would move backward from {stored} to {offset}"
                    )));
                }
            }
            tx.execute(
                "INSERT INTO trace_cursors(session_id,path,byte_offset) VALUES(?1,?2,?3) ON CONFLICT(session_id) DO UPDATE SET path=excluded.path, byte_offset=excluded.byte_offset",
                params![session.as_str(), path, offset],
            )?;
            Ok(())
        })
    }

    /// Reconstructs export rows for one seat at or after `since`. Each row is
    /// one captured call. A missing blob is a `trace_error`, not a stand-in body.
    #[allow(clippy::too_many_lines, clippy::cognitive_complexity)]
    pub fn export_traces(&self, seat: &str, since: OffsetDateTime) -> LedgerResult<Vec<Value>> {
        let bound = encode_utc(since)?;
        let mut statement = self.connection().prepare_cached(
            // `turn` numbers each call within its whole session, not just the exported window.
            "SELECT c.session_id, s.seat_id, c.entry_id, c.occurred_at, c.payload_digest, c.provider, c.model, c.api, c.skeleton_json, c.request_id, c.response_id, c.tool_ids_json, c.trace_error, s.project_id, c.served_model, c.model_group, c.attempted_fallbacks, c.gateway_call_id, c.response_cost, c.turn FROM (SELECT *, ROW_NUMBER() OVER (PARTITION BY session_id ORDER BY occurred_at, entry_id) AS turn FROM trace_calls) c JOIN live_sessions s ON s.session_id=c.session_id WHERE s.seat_id=?1 AND c.occurred_at>=substr(?2,1,19) ORDER BY c.session_id",
        )?;
        let rows = statement.query_map(params![seat, bound], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, Option<String>>(5)?,
                row.get::<_, Option<String>>(6)?,
                row.get::<_, Option<String>>(7)?,
                row.get::<_, String>(8)?,
                row.get::<_, Option<String>>(9)?,
                row.get::<_, Option<String>>(10)?,
                row.get::<_, String>(11)?,
                row.get::<_, Option<String>>(12)?,
                row.get::<_, String>(13)?,
                row.get::<_, Option<String>>(14)?,
                row.get::<_, Option<String>>(15)?,
                row.get::<_, Option<i64>>(16)?,
                row.get::<_, Option<String>>(17)?,
                row.get::<_, Option<String>>(18)?,
                row.get::<_, i64>(19)?,
            ))
        })?;
        let mut ranked = Vec::new();
        // Rows come grouped by session: each session's history loads once.
        let mut history: Option<(String, Vec<crate::live::LiveEvent>)> = None;
        for row in rows {
            let (
                session_id,
                seat_id,
                entry_id,
                occurred_at,
                _payload_digest,
                provider,
                requested_model,
                api,
                skeleton,
                request_id,
                response_id,
                tool_ids,
                trace_error,
                project_id,
                served_model,
                model_group,
                attempted_fallbacks,
                gateway_call_id,
                response_cost,
                turn,
            ) = row?;
            let occurred = decode_utc(&occurred_at)?;
            if occurred < since {
                continue;
            }
            let skeleton: Value = serde_json::from_str(&skeleton)?;
            let tool_ids: Vec<String> = serde_json::from_str(&tool_ids)?;
            let (request, reconstruct_error) = reconstruct(self, &skeleton)?;
            let mut error = join_error(trace_error, reconstruct_error);
            if history
                .as_ref()
                .is_none_or(|(loaded, _)| *loaded != session_id)
            {
                history = Some((session_id.clone(), session_events(self, &session_id)?));
            }
            let events = history.as_ref().map_or(&[][..], |(_, events)| events);
            let follow = journaled_follow(events, response_id.as_deref(), &tool_ids, &mut error)?;
            let latency_ms = follow.response_at.and_then(|end| {
                let ms = (end - occurred).whole_milliseconds();
                if ms < 0 {
                    error = join_error(
                        error.take(),
                        Some(
                            "journaled message_end is earlier than the captured request; latency was not invented"
                                .to_owned(),
                        ),
                    );
                    None
                } else {
                    i64::try_from(ms).ok()
                }
            });
            let previous = request.as_ref().and_then(last_user_text);
            let inferred = previous
                .as_deref()
                .zip(follow.next_user.as_deref())
                .is_some_and(|(previous, next)| inferred_redo(previous, next));
            let approval = approval_labels(&tool_ids, &follow.approvals);
            let jobs = if follow.jobs.is_empty() {
                Value::Null
            } else {
                Value::Array(follow.jobs)
            };
            let error_class = if follow.error_classes.is_empty() {
                Value::Null
            } else {
                serde_json::to_value(&follow.error_classes)?
            };
            // A conversation with the owner is personal. A refusal or a note that
            // declares its own class raises that floor; prose that merely
            // names a class does not.
            let privacy = [&request, &follow.response]
                .into_iter()
                .flatten()
                .chain(&follow.results)
                .filter_map(privacy_of)
                .fold(PrivacyClass::Personal, PrivacyClass::max);
            ranked.push((
                occurred,
                entry_id.clone(),
                serde_json::json!({
                    "schema": EXPORT_SCHEMA,
                    "source": "omp",
                    "session_id": session_id,
                    "turn": turn,
                    "seat_id": seat_id,
                    "project_id": project_id,
                    "entry_id": entry_id,
                    "occurred_at": occurred_at,
                    "provider": provider,
                    "requested_model": requested_model,
                    "served_model": served_model,
                    "class_route": journaled_class_route(events, occurred),
                    "model_group": model_group,
                    "attempted_fallbacks": attempted_fallbacks,
                    "api": api,
                    "request_id": request_id,
                    "response_id": response_id,
                    "gateway_call_id": gateway_call_id,
                    "request": request,
                    "messages": request.as_ref().and_then(message_array),
                    "tools": request.as_ref().and_then(tools_value),
                    "response": follow.response,
                    "tool_calls": follow.calls,
                    "tool_results": follow.results,
                    "usage": follow.usage,
                    "estimated_cost_usd": estimated_cost(response_cost.as_deref(), follow.usage.as_ref()),
                    "latency_ms": latency_ms,
                    "stop_reason": follow.stop_reason,
                    "approval": approval,
                    "job": jobs,
                    "error_class": error_class,
                    "lessons": follow.lessons,
                    "inferred_redo": inferred,
                    "inference": inferred.then(|| "inferred, not a recorded correction".to_owned()),
                    "privacy": privacy,
                    "trace_error": error,
                }),
            ));
        }
        ranked.sort_by(|left, right| left.0.cmp(&right.0).then_with(|| left.1.cmp(&right.1)));
        Ok(ranked.into_iter().map(|(_, _, row)| row).collect())
    }
}

/// Inspect values before serialization: escaping newlines hides note frontmatter.
/// Tool results can themselves be JSON strings containing declared metadata.
fn privacy_of(value: &Value) -> Option<PrivacyClass> {
    match value {
        Value::String(text) => {
            let declared = PrivacyClass::strictest_in(text);
            let nested = if text.trim_start().starts_with(['{', '[']) {
                serde_json::from_str::<Value>(text)
                    .ok()
                    .and_then(|value| privacy_of(&value))
            } else {
                None
            };
            declared.max(nested)
        }
        Value::Array(values) => values.iter().filter_map(privacy_of).max(),
        Value::Object(fields) => fields
            .iter()
            .filter_map(|(key, value)| {
                let declared =
                    if matches!(key.as_str(), "privacy" | "privacy_class" | "privacyClass") {
                        value.as_str().and_then(PrivacyClass::parse_token)
                    } else {
                        None
                    };
                declared.max(privacy_of(value))
            })
            .max(),
        _ => None,
    }
}

fn join_error(left: Option<String>, right: Option<String>) -> Option<String> {
    match (left, right) {
        (Some(left), Some(right)) => Some(format!("{left}; {right}")),
        (Some(value), None) | (None, Some(value)) => Some(value),
        (None, None) => None,
    }
}

fn reconstruct(ledger: &Ledger, skeleton: &Value) -> LedgerResult<(Option<Value>, Option<String>)> {
    match fill(ledger, skeleton)? {
        Fill::Value(value) => Ok((Some(value), None)),
        Fill::Missing(_) => Ok((
            None,
            Some(
                "a content-addressed block of this request is not in the ledger; the request body was not invented"
                    .to_owned(),
            ),
        )),
    }
}

enum Fill {
    Value(Value),
    Missing(String),
}

const FILL_DEPTH: usize = 4096;

/// Tools whose results are lessons the owner taught, linked to the turn that earned them.
const MEMORY_LESSON_TOOLS: [&str; 2] = ["memory_remember", "memory_forget"];

fn fill(ledger: &Ledger, value: &Value) -> LedgerResult<Fill> {
    fill_at(ledger, value, 0)
}

fn blob_ref(value: &Value) -> Option<&str> {
    let Value::Object(map) = value else {
        return None;
    };
    if map.len() != 1 {
        return None;
    }
    map.get("blob").and_then(Value::as_str)
}

fn chain_node(value: &Value) -> Option<(&str, &Vec<Value>)> {
    let Value::Object(map) = value else {
        return None;
    };
    if map.len() != 2 {
        return None;
    }
    let prefix = map.get("prefix").and_then(Value::as_str)?;
    let suffix = map.get("suffix").and_then(Value::as_array)?;
    Some((prefix, suffix))
}

fn fill_at(ledger: &Ledger, value: &Value, depth: usize) -> LedgerResult<Fill> {
    if depth > FILL_DEPTH {
        return Err(LedgerError::invalid_data(format!(
            "trace history chain exceeds {FILL_DEPTH} steps"
        )));
    }
    if let Some(digest) = blob_ref(value) {
        return match ledger.trace_blob_by_wire(digest)? {
            Some(body) => fill_stored(ledger, &body, depth + 1),
            None => Ok(Fill::Missing(digest.to_owned())),
        };
    }
    if let Some((prefix, suffix)) = chain_node(value) {
        let Some(prefix_body) = ledger.trace_blob_by_wire(prefix)? else {
            return Ok(Fill::Missing(prefix.to_owned()));
        };
        let mut messages = match fill_stored(ledger, &prefix_body, depth + 1)? {
            Fill::Missing(digest) => return Ok(Fill::Missing(digest)),
            Fill::Value(Value::Array(messages)) => messages,
            Fill::Value(_) => {
                return Err(LedgerError::invalid_data(
                    "history prefix blob is not an array".into(),
                ));
            }
        };
        messages.extend(suffix.iter().cloned());
        return Ok(Fill::Value(Value::Array(messages)));
    }
    match value {
        Value::Array(_) => Ok(Fill::Value(value.clone())),
        Value::Object(map) => {
            let mut out = Map::new();
            for (key, item) in map {
                match fill_at(ledger, item, depth + 1)? {
                    Fill::Value(filled) => {
                        out.insert(key.clone(), filled);
                    }
                    missing @ Fill::Missing(_) => return Ok(missing),
                }
            }
            Ok(Fill::Value(Value::Object(out)))
        }
        other => Ok(Fill::Value(other.clone())),
    }
}

/// A loaded blob is another history node, or opaque bytes. Message arrays,
/// tool arrays, and suffix items are not walked, so a user key named `blob`
/// or `prefix` is not a ledger address.
fn fill_stored(ledger: &Ledger, body: &Value, depth: usize) -> LedgerResult<Fill> {
    if blob_ref(body).is_some() || chain_node(body).is_some() {
        return fill_at(ledger, body, depth);
    }
    Ok(Fill::Value(body.clone()))
}

fn message_array(request: &Value) -> Option<Value> {
    for key in ["messages", "input", "contents"] {
        if request.get(key).is_some() {
            return request.get(key).cloned();
        }
    }
    request.pointer("/request/contents").cloned()
}

fn tools_value(request: &Value) -> Option<Value> {
    request
        .get("tools")
        .or_else(|| request.get("toolConfig"))
        .cloned()
}

struct JournalFollow {
    response: Option<Value>,
    usage: Option<Value>,
    stop_reason: Option<Value>,
    response_at: Option<OffsetDateTime>,
    calls: Vec<Value>,
    results: Vec<Value>,
    lessons: Vec<Value>,
    approvals: BTreeMap<String, String>,
    jobs: Vec<Value>,
    error_classes: BTreeMap<String, String>,
    next_user: Option<String>,
}

/// Every journaled event of one traced session.
fn session_events(ledger: &Ledger, session_id: &str) -> LedgerResult<Vec<crate::live::LiveEvent>> {
    let session = SessionId::parse(session_id).map_err(|failure| {
        LedgerError::invalid_data_caused_by(
            format!("trace session id {session_id} is invalid"),
            failure,
        )
    })?;
    let head = ledger.reconnect_head(&session)?;
    ledger.live_event_history(&session, 0, head)
}

#[allow(clippy::too_many_lines, clippy::cognitive_complexity)]
fn journaled_follow(
    events: &[crate::live::LiveEvent],
    response_id: Option<&str>,
    tool_ids: &[String],
    error: &mut Option<String>,
) -> LedgerResult<JournalFollow> {
    let mut response = None;
    let mut usage = None;
    let mut stop_reason = None;
    let mut response_at = None;
    let mut calls = Vec::new();
    let mut results = Vec::new();
    let mut lessons = Vec::new();
    let mut response_sequence = None;
    let mut request_tool: BTreeMap<String, String> = BTreeMap::new();
    let mut decision: BTreeMap<String, String> = BTreeMap::new();
    let mut started: Vec<String> = Vec::new();
    let mut reported: BTreeMap<String, bool> = BTreeMap::new();
    let mut error_classes = BTreeMap::new();
    let mut next_user = None;
    for event in events {
        if let Some(frame) = event.body.get("frame") {
            let kind = frame.get("type").and_then(Value::as_str);
            if kind == Some("message_end") {
                let message = frame.get("message");
                let id = message
                    .and_then(|message| message.get("responseId"))
                    .and_then(Value::as_str);
                if response_id.is_some() && id == response_id {
                    response = message.cloned();
                    usage = message.and_then(|message| message.get("usage")).cloned();
                    stop_reason = message
                        .and_then(|message| message.get("stopReason"))
                        .cloned();
                    response_sequence = Some(event.sequence);
                    response_at = Some(event.occurred_at);
                } else if response_id.is_some() && id.is_none() && response.is_none() {
                    *error = join_error(
                        error.take(),
                        Some(
                            "a journaled message_end has no responseId; it was not attached by guessing"
                                .to_owned(),
                        ),
                    );
                }
            }
            if matches!(
                kind,
                Some("tool_execution_start" | "tool_execution_end" | "tool_execution_update")
            ) {
                if let Some(id) = frame
                    .get("toolCallId")
                    .or_else(|| frame.get("toolUseId"))
                    .and_then(Value::as_str)
                    .map(str::to_owned)
                {
                    let name = frame.get("toolName").and_then(Value::as_str).unwrap_or("");
                    let in_call = tool_ids.iter().any(|wanted| wanted == &id);
                    let later_lesson = !in_call
                        && MEMORY_LESSON_TOOLS.contains(&name)
                        && response_sequence.is_some_and(|end| event.sequence > end);
                    if in_call || later_lesson {
                        if kind == Some("tool_execution_end") {
                            if in_call {
                                results.push(frame.clone());
                                if let Some(job) = started_job(&frame_text(frame)) {
                                    if !started.iter().any(|id| id == job) {
                                        started.push(job.to_owned());
                                    }
                                }
                                if let Some(class) = frame_error_kind(frame) {
                                    error_classes.insert(id.clone(), class);
                                }
                            }
                            if MEMORY_LESSON_TOOLS.contains(&name) {
                                lessons.push(serde_json::json!({
                                    "tool_call_id": id,
                                    "tool_name": name,
                                    "event_id": event.event_id.to_string(),
                                    "result": frame.get("result"),
                                }));
                            }
                        } else if kind == Some("tool_execution_start") && in_call {
                            calls.push(frame.clone());
                        }
                    }
                }
            }
            if kind == Some("extension_ui_request")
                && frame.get("method").and_then(Value::as_str) == Some("confirm")
            {
                if let Some(id) = frame.get("id").and_then(Value::as_str) {
                    let tool = frame
                        .get("toolCallId")
                        .or_else(|| frame.get("id"))
                        .and_then(Value::as_str)
                        .unwrap_or(id);
                    request_tool.insert(id.to_owned(), tool.to_owned());
                }
            }
            if kind == Some("extension_ui_response") {
                if let Some(id) = frame.get("id").and_then(Value::as_str) {
                    if let Some(label) = ui_decision(frame) {
                        decision.insert(id.to_owned(), label);
                    }
                }
            }
            if kind == Some("prompt") {
                note_user_text(
                    &frame_text(frame),
                    event.sequence,
                    response_sequence,
                    &mut reported,
                    &mut next_user,
                );
            }
        }
        note_actor_event(
            event,
            tool_ids,
            response_sequence,
            ActorEventNotes {
                request_tool: &mut request_tool,
                decision: &mut decision,
                reported: &mut reported,
                error_classes: &mut error_classes,
                next_user: &mut next_user,
            },
        );
    }
    if response_id.is_some() && response.is_none() {
        *error = join_error(
            error.take(),
            Some(format!(
                "no journaled message_end carries responseId {}",
                response_id.unwrap_or_default()
            )),
        );
    }
    let mut approvals = BTreeMap::new();
    for (request, tool) in &request_tool {
        if tool_ids.iter().any(|id| id == tool) {
            if let Some(label) = decision.get(request) {
                approvals.insert(tool.clone(), label.clone());
            }
        }
    }
    let jobs = started
        .into_iter()
        .map(|id| {
            let state = match reported.get(&id) {
                Some(true) => "succeeded",
                Some(false) => "failed",
                None => "none",
            };
            let mut job = serde_json::json!({ "id": id, "state": state });
            if state == "none" {
                job["note"] = Value::String(
                    "jobs live in memory; a restart leaves an unreported job as none".to_owned(),
                );
            }
            job
        })
        .collect();
    Ok(JournalFollow {
        response,
        usage,
        stop_reason,
        response_at,
        calls,
        results,
        lessons,
        approvals,
        jobs,
        error_classes,
        next_user,
    })
}

fn estimated_cost(header: Option<&str>, usage: Option<&Value>) -> Option<f64> {
    if let Some(raw) = header {
        if let Ok(value) = raw.parse::<f64>() {
            if value.is_finite() {
                return Some(value);
            }
        }
    }
    let usage = usage?;
    let cost = usage.get("cost")?;
    cost.as_f64()
        .or_else(|| cost.get("total").and_then(Value::as_f64))
        .filter(|value| value.is_finite())
}

fn approval_labels(tool_ids: &[String], approvals: &BTreeMap<String, String>) -> Value {
    if tool_ids.is_empty() {
        return Value::Null;
    }
    let mut map = Map::new();
    for id in tool_ids {
        map.insert(
            id.clone(),
            Value::String(
                approvals
                    .get(id)
                    .cloned()
                    .unwrap_or_else(|| "none".to_owned()),
            ),
        );
    }
    Value::Object(map)
}

fn last_user_text(request: &Value) -> Option<String> {
    message_array(request)?
        .as_array()?
        .iter()
        .rev()
        .find_map(|message| {
            let role = message.get("role").and_then(Value::as_str)?;
            if !role.eq_ignore_ascii_case("user") {
                return None;
            }
            let text = texts(message);
            (!text.trim().is_empty()).then_some(text)
        })
}

/// the owner's own words in a user turn: the text after the turn context line
/// (`[the owner's local time: …] [You are running on …]`), so recalled memory and
/// the clock every turn starts with never read as a repeat. Routine wakes and
/// job reports are Odin's, not his.
fn owner_words(text: &str) -> Option<&str> {
    let words = match text.rsplit_once("[You are running on ") {
        Some((_, rest)) => rest.split_once(']').map_or("", |(_, words)| words),
        None => text,
    }
    .trim();
    (!words.starts_with("[Routine ") && !words.starts_with(REPORT_TURN)).then_some(words)
}

/// A follow-up is a likely redo when its opening repeats the earlier turn (or the reverse), or it
/// carries a correction cue and reuses one of the earlier turn's longer words.
fn inferred_redo(previous: &str, next: &str) -> bool {
    const MIN_PREVIOUS_BYTES: usize = 12;
    const MIN_NEXT_BYTES: usize = 8;
    const OPENING_CHARS: usize = 24;
    const MIN_SHARED_WORD_BYTES: usize = 5;
    const CORRECTION_CUES: [&str; 4] = ["no,", "wrong", "instead", "try again"];

    let (Some(previous), Some(next)) = (owner_words(previous), owner_words(next)) else {
        return false;
    };
    let previous = previous.to_lowercase();
    let next = next.to_lowercase();
    if previous.len() < MIN_PREVIOUS_BYTES || next.len() < MIN_NEXT_BYTES {
        return false;
    }
    let opening_chars = OPENING_CHARS
        .min(previous.chars().count())
        .min(next.chars().count());
    let opening = |text: &str| text.chars().take(opening_chars).collect::<String>();
    next.contains(&opening(&previous))
        || previous.contains(&opening(&next))
        || (CORRECTION_CUES.iter().any(|cue| next.contains(cue))
            && next
                .split_whitespace()
                .any(|word| word.len() >= MIN_SHARED_WORD_BYTES && previous.contains(word)))
}

fn frame_text(frame: &Value) -> String {
    ["result", "content", "message", "text"]
        .into_iter()
        .filter_map(|key| frame.get(key))
        .map(texts)
        .filter(|text| !text.is_empty())
        .collect::<Vec<_>>()
        .join("\n")
}

fn texts(value: &Value) -> String {
    match value {
        Value::String(text) => text.clone(),
        Value::Array(items) => items
            .iter()
            .map(texts)
            .filter(|text| !text.is_empty())
            .collect::<Vec<_>>()
            .join("\n"),
        Value::Object(map) => {
            if map.get("kind").and_then(Value::as_str) == Some("text") {
                if let Some(text) = map.get("value").and_then(Value::as_str) {
                    return text.to_owned();
                }
            }
            ["text", "content", "message", "result"]
                .into_iter()
                .filter_map(|key| map.get(key))
                .map(texts)
                .filter(|text| !text.is_empty())
                .collect::<Vec<_>>()
                .join("\n")
        }
        _ => String::new(),
    }
}

/// Link the existing between-turn control journal to the call it governed. The gateway's
/// served_model remains independent: a selected lane is never reported as an observed model.
fn journaled_class_route(events: &[crate::live::LiveEvent], at: OffsetDateTime) -> Option<&Value> {
    events.iter().rev().find_map(|event| {
        (event.occurred_at <= at
            && event.body.get("kind").and_then(Value::as_str) == Some("modelRouted"))
        .then(|| event.body.get("payload"))
        .flatten()
    })
}

fn frame_error_kind(frame: &Value) -> Option<String> {
    frame
        .pointer("/details/errorKind")
        .or_else(|| frame.pointer("/result/details/errorKind"))
        .or_else(|| frame.pointer("/result/errorKind"))
        .and_then(Value::as_str)
        .filter(|kind| !kind.is_empty())
        .map(str::to_owned)
}

fn ui_decision(frame: &Value) -> Option<String> {
    if frame.get("cancelled").and_then(Value::as_bool) == Some(true) {
        return Some("cancelled".to_owned());
    }
    match frame.get("confirmed").and_then(Value::as_bool) {
        Some(true) => Some("granted".to_owned()),
        Some(false) => Some("denied".to_owned()),
        None => None,
    }
}

fn note_user_text(
    text: &str,
    sequence: i64,
    response_sequence: Option<i64>,
    reported: &mut BTreeMap<String, bool>,
    next_user: &mut Option<String>,
) {
    if text.is_empty() {
        return;
    }
    let jobs = reported_jobs(text);
    if !jobs.is_empty() {
        for report in jobs {
            reported.insert(report.job.to_owned(), report.ok);
        }
        return;
    }
    if next_user.is_none() && response_sequence.is_some_and(|end| sequence > end) {
        *next_user = Some(text.to_owned());
    }
}

struct ActorEventNotes<'a> {
    request_tool: &'a mut BTreeMap<String, String>,
    decision: &'a mut BTreeMap<String, String>,
    reported: &'a mut BTreeMap<String, bool>,
    error_classes: &'a mut BTreeMap<String, String>,
    next_user: &'a mut Option<String>,
}

fn note_actor_event(
    event: &crate::live::LiveEvent,
    tool_ids: &[String],
    response_sequence: Option<i64>,
    notes: ActorEventNotes<'_>,
) {
    let ActorEventNotes {
        request_tool,
        decision,
        reported,
        error_classes,
        next_user,
    } = notes;
    let kind = event.body.get("kind").and_then(Value::as_str);
    let payload = event.body.get("payload");
    match kind {
        Some("permissionRequested") => {
            let Some(payload) = payload else {
                return;
            };
            let (Some(id), Some(tool)) = (
                payload.get("requestId").and_then(Value::as_str),
                payload.get("toolUseId").and_then(Value::as_str),
            ) else {
                return;
            };
            request_tool.insert(id.to_owned(), tool.to_owned());
        }
        Some("permissionResolved") => {
            let Some(payload) = payload else {
                return;
            };
            let Some(id) = payload.get("requestId").and_then(Value::as_str) else {
                return;
            };
            let label = match payload.get("decision").and_then(Value::as_str) {
                Some("allowOnce") => "granted",
                Some("deny") => "denied",
                _ => return,
            };
            decision.insert(id.to_owned(), label.to_owned());
        }
        Some("userMessage") => {
            note_user_text(
                &payload.map(texts).unwrap_or_default(),
                event.sequence,
                response_sequence,
                reported,
                next_user,
            );
        }
        Some("side_channel_outcome") => {
            let Some(id) = event.body.get("request_id").and_then(Value::as_str) else {
                return;
            };
            if !tool_ids.iter().any(|tool| tool == id) {
                return;
            }
            if let Some(class) = event
                .body
                .pointer("/status/errorKind")
                .and_then(Value::as_str)
                .filter(|class| !class.is_empty())
            {
                error_classes
                    .entry(id.to_owned())
                    .or_insert_with(|| class.to_owned());
            }
        }
        _ => {}
    }
}

/// How a call ended, for training: `aborted` (it never finished: stopped,
/// errored, cut off at its length, or its approval cancelled), `rejected`
/// (the owner denied an approval), `redo` (his next message redid it),
/// `tool_error` (a tool it called failed), else `ok`.
fn outcome(row: &Value) -> &'static str {
    let approvals = || {
        row.get("approval")
            .and_then(Value::as_object)
            .into_iter()
            .flat_map(|approvals| approvals.values().filter_map(Value::as_str))
    };
    let finished = matches!(
        row.get("stop_reason").and_then(Value::as_str),
        Some("stop" | "toolUse")
    );
    if !finished || approvals().any(|label| label == "cancelled") {
        "aborted"
    } else if approvals().any(|label| label == "denied") {
        "rejected"
    } else if row.get("inferred_redo") == Some(&Value::Bool(true)) {
        "redo"
    } else if row.get("error_class").is_some_and(|class| !class.is_null()) {
        "tool_error"
    } else {
        "ok"
    }
}

/// Chat messages, function tools, and labels outside `messages`.
pub fn finetune_row(row: &Value) -> Value {
    let mut error = row
        .get("trace_error")
        .and_then(Value::as_str)
        .map(str::to_owned);
    let messages = match finetune_messages(row) {
        Ok(messages) => Value::Array(messages),
        Err(cause) => {
            error = join_error(error, Some(cause));
            Value::Null
        }
    };
    serde_json::json!({
        "messages": messages,
        "tools": row.get("tools").and_then(function_tools),
        "labels": labels(row),
        "trace_error": error,
    })
}

/// `train` is `sft` for an `ok` call. `served_model` is the deployment that
/// answered, labelled `fallback` when the gateway fell back to it; an absent
/// header stays null rather than copying the lane that was asked. `cost` is
/// the turn's total. `session_id`, `turn` and `occurred_at` reassemble
/// conversations.
/// `privacy` is the strictest class the call touched.
fn labels(row: &Value) -> Value {
    let outcome = outcome(row);
    let field = |name: &str| row.get(name).cloned().unwrap_or(Value::Null);
    serde_json::json!({
        "outcome": outcome,
        "train": if outcome == "ok" { "sft" } else { "exclude" },
        "served_model": served_model(row),
        "cost": cost(row),
        "session_id": field("session_id"),
        "turn": field("turn"),
        "occurred_at": field("occurred_at"),
        "privacy": field("privacy"),
    })
}

/// The deployment that answered. A gateway fallback is labelled on that
/// name; the requested lane is never copied in to fill an absent header.
fn served_model(row: &Value) -> Value {
    let Some(served) = row.get("served_model").and_then(Value::as_str) else {
        return Value::Null;
    };
    let fell_back = row
        .get("attempted_fallbacks")
        .and_then(Value::as_i64)
        .is_some_and(|count| count > 0);
    if fell_back {
        Value::String(format!("fallback {served}"))
    } else {
        Value::String(served.to_owned())
    }
}

fn cost(row: &Value) -> Value {
    let Some(cost) = row.get("estimated_cost_usd") else {
        return Value::Null;
    };
    let total = cost.get("total").unwrap_or(cost);
    total
        .as_f64()
        .filter(|value| value.is_finite())
        .map(Value::from)
        .unwrap_or(Value::Null)
}

fn finetune_messages(row: &Value) -> Result<Vec<Value>, String> {
    let api = row.get("api").and_then(Value::as_str).unwrap_or("unknown");
    let Some(source) = row
        .get("messages")
        .filter(|value| value.is_array())
        .and_then(Value::as_array)
    else {
        return Err(format!(
            "finetune converter has no chat messages for api {api}"
        ));
    };
    let mut messages: Vec<Value> = source.iter().filter_map(chat_turn).collect();
    if let Some(turn) = row
        .get("response")
        .filter(|value| !value.is_null())
        .and_then(chat_turn)
    {
        messages.push(turn);
    }
    if messages.is_empty() {
        return Err(format!(
            "finetune converter has no chat messages for api {api}"
        ));
    }
    Ok(messages)
}

fn chat_turn(message: &Value) -> Option<Value> {
    let role = message
        .get("role")
        .and_then(Value::as_str)
        .or_else(|| message.get("content").is_some().then_some("assistant"))?;
    let mut out = serde_json::json!({ "role": role });
    let content = message.get("content")?;
    if let Some(text) = content.as_str() {
        out["content"] = Value::String(text.to_owned());
    } else if let Some(blocks) = content.as_array() {
        let text = blocks
            .iter()
            .filter_map(|block| {
                (block.get("type").and_then(Value::as_str) == Some("text"))
                    .then(|| block.get("text").and_then(Value::as_str))
                    .flatten()
            })
            .collect::<Vec<_>>()
            .join("");
        if !text.is_empty() {
            out["content"] = Value::String(text);
        }
        let calls = function_calls(blocks);
        if !calls.is_empty() {
            out["tool_calls"] = Value::Array(calls);
        }
    }
    (out.get("content").is_some() || out.get("tool_calls").is_some()).then_some(out)
}

fn function_calls(blocks: &[Value]) -> Vec<Value> {
    blocks.iter().filter_map(|block| {
        let kind = block.get("type").and_then(Value::as_str)?;
        if kind != "toolCall" && kind != "tool_use" {
            return None;
        }
        let arguments = block.get("arguments").or_else(|| block.get("input")).cloned().unwrap_or(Value::Null);
        Some(serde_json::json!({
            "id": block.get("id").and_then(Value::as_str).unwrap_or(""),
            "type": "function",
            "function": {
                "name": block.get("name").and_then(Value::as_str).unwrap_or(""),
                "arguments": if arguments.is_string() { arguments } else { Value::String(arguments.to_string()) },
            }
        }))
    }).collect()
}

fn function_tools(tools: &Value) -> Option<Value> {
    Some(Value::Array(tools.as_array()?.iter().map(|tool| {
        if tool.get("type").and_then(Value::as_str) == Some("function") {
            return tool.clone();
        }
        serde_json::json!({
            "type": "function",
            "function": {
                "name": tool.get("name").cloned().unwrap_or(Value::Null),
                "parameters": tool.get("parameters").or_else(|| tool.get("input_schema")).cloned().unwrap_or(serde_json::json!({})),
            }
        })
    }).collect()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::live::{NewLiveEvent, NewLiveSession};
    use odin_domain::EventId;
    use serde_json::{json, Value};

    fn session(ledger: &mut Ledger) {
        ledger
            .connection()
            .execute(
                "INSERT OR IGNORE INTO lanes(lane_id,seat_id,template_id,backend,status,created_by,created_at,updated_at)
                 VALUES('lane:trace','seat:trace','template:test','local_omp','ready','test','2026-08-31T12:00:00Z','2026-08-31T12:00:00Z')",
                [],
            )
            .unwrap();
        ledger
            .create_live_session(&NewLiveSession {
                session_id: SessionId::new("session:trace").unwrap(),
                seat_id: "seat:trace".into(),
                project_id: "project:test".into(),
                slice_id: "slice:test".into(),
                lane_id: "lane:trace".into(),
                target_node_id: "node:test".into(),
                provider: "provider".into(),
                model: "model".into(),
                title: None,
                manifest: json!({}),
                open_tab: false,
                state: "running".to_owned(),
                created_at: OffsetDateTime::UNIX_EPOCH,
            })
            .unwrap();
    }
    fn store(ledger: &mut Ledger, wire: &str, body: Value) {
        let bytes = serde_json::to_vec(&body).unwrap();
        ledger
            .put_trace_blob(&TraceBlob {
                digest: Digest::hash(&bytes),
                wire_sha256: wire.into(),
                kind: "history".into(),
                body,
            })
            .unwrap();
    }

    fn insert_call(
        ledger: &mut Ledger,
        entry: &str,
        call_id: &str,
        at: OffsetDateTime,
        payload: &str,
        skeleton: Value,
    ) {
        ledger
            .insert_trace_call(&NewTraceCall {
                session_id: SessionId::new("session:trace").unwrap(),
                entry_id: entry.into(),
                occurred_at: at,
                call_id: call_id.into(),
                payload_digest: payload.into(),
                provider: None,
                model: None,
                api: None,
                skeleton,
                trace_error: None,
            })
            .unwrap();
    }

    fn append_frame(ledger: &mut Ledger, id: &str, frame: Value) {
        ledger
            .append_live_event_after_blobs(&NewLiveEvent {
                event_id: EventId::new(id).unwrap(),
                session_id: SessionId::new("session:trace").unwrap(),
                expected_epoch: 1,
                occurred_at: OffsetDateTime::UNIX_EPOCH,
                body: json!({"kind": "session", "frame": frame}),
                blob_refs: json!([]),
            })
            .unwrap();
    }

    #[test]
    fn blob_and_call_roundtrip_reconstructs_the_request() {
        let mut ledger = Ledger::open_in_memory().unwrap();
        session(&mut ledger);
        let system = json!("You are a seat.");
        let tools = json!([{"name": "task_read"}]);
        let history = json!([{"role": "user", "content": "hello"}]);
        for (kind, body) in [
            ("system", &system),
            ("tools", &tools),
            ("history", &history),
        ] {
            let bytes = serde_json::to_vec(body).unwrap();
            ledger
                .put_trace_blob(&TraceBlob {
                    digest: Digest::hash(&bytes),
                    wire_sha256: format!("sha-{kind}"),
                    kind: kind.into(),
                    body: body.clone(),
                })
                .unwrap();
        }
        ledger
            .insert_trace_call(&NewTraceCall {
                session_id: SessionId::new("session:trace").unwrap(),
                entry_id: "entry-1".into(),
                occurred_at: OffsetDateTime::UNIX_EPOCH,
                call_id: "call-1".into(),
                payload_digest: "sha-payload".into(),
                provider: Some("gateway".into()),
                model: Some("herald".into()),
                api: Some("openai-completions".into()),
                skeleton: json!({
                    "model": "herald",
                    "system": {"blob": "sha-system"},
                    "tools": {"blob": "sha-tools"},
                    "messages": {"prefix": "sha-history", "suffix": []}
                }),
                trace_error: None,
            })
            .unwrap();
        assert!(!ledger
            .insert_trace_call(&NewTraceCall {
                session_id: SessionId::new("session:trace").unwrap(),
                entry_id: "entry-1".into(),
                occurred_at: OffsetDateTime::UNIX_EPOCH,
                call_id: "call-1".into(),
                payload_digest: "sha-payload".into(),
                provider: None,
                model: None,
                api: None,
                skeleton: json!({}),
                trace_error: None,
            })
            .unwrap());
        ledger
            .link_trace_call(&TraceLink {
                session_id: SessionId::new("session:trace").unwrap(),
                call_id: "call-1".into(),
                payload_digest: "sha-payload".into(),
                request_id: Some("req-1".into()),
                response_id: None,
                tool_ids: Vec::new(),
                trace_error: Some("responseId absent".into()),
                served_model: None,
                model_group: None,
                attempted_fallbacks: None,
                gateway_call_id: None,
                response_cost: None,
            })
            .unwrap();
        let rows = ledger
            .export_traces("seat:trace", OffsetDateTime::UNIX_EPOCH)
            .unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0]["request"]["system"], "You are a seat.");
        assert_eq!(rows[0]["request"]["messages"][0]["content"], "hello");
        assert_eq!(rows[0]["request_id"], "req-1");
        assert_eq!(rows[0]["trace_error"], "responseId absent");
        assert!(rows[0].get("payload_digest").is_none());
        assert!(rows[0]["response"].is_null());
    }

    #[test]
    fn a_delta_chain_reconstructs_and_a_missing_prefix_is_not_invented() {
        let mut ledger = Ledger::open_in_memory().unwrap();
        session(&mut ledger);
        store(
            &mut ledger,
            "wire-1",
            json!([{
                "role": "user",
                "content": "one",
                "arguments": {"blob": "not-a-ledger-digest"}
            }]),
        );
        store(
            &mut ledger,
            "wire-2",
            json!({
                "prefix": "wire-1",
                "suffix": [
                    {
                        "role": "assistant",
                        "content": "two",
                        "prefix": "user-prefix",
                        "suffix": ["kept"]
                    },
                    {"prefix": "also-user", "suffix": [{"text": "leave"}]}
                ]
            }),
        );
        store(
            &mut ledger,
            "wire-3",
            json!({"prefix": "wire-2", "suffix": [{"role": "user", "content": "three"}]}),
        );
        insert_call(
            &mut ledger,
            "entry-chain",
            "call-chain",
            OffsetDateTime::UNIX_EPOCH,
            "payload-chain",
            json!({"messages": {"blob": "wire-3"}}),
        );
        store(
            &mut ledger,
            "wire-gap",
            json!({"prefix": "absent", "suffix": [{"role": "user", "content": "lost"}]}),
        );
        insert_call(
            &mut ledger,
            "entry-gap",
            "call-gap",
            OffsetDateTime::UNIX_EPOCH,
            "payload-gap",
            json!({"messages": {"blob": "wire-gap"}}),
        );
        store(
            &mut ledger,
            "wire-mid",
            json!({"prefix": "absent-nested", "suffix": [{"role": "user", "content": "mid"}]}),
        );
        store(
            &mut ledger,
            "wire-outer",
            json!({"prefix": "wire-mid", "suffix": [{"role": "assistant", "content": "outer"}]}),
        );
        insert_call(
            &mut ledger,
            "entry-nested",
            "call-nested",
            OffsetDateTime::UNIX_EPOCH,
            "payload-nested",
            json!({"messages": {"blob": "wire-outer"}}),
        );
        let rows = ledger
            .export_traces("seat:trace", OffsetDateTime::UNIX_EPOCH)
            .unwrap();
        let chain = rows
            .iter()
            .find(|row| row["entry_id"] == "entry-chain")
            .unwrap();
        assert_eq!(
            chain["messages"],
            json!([
                {
                    "role": "user",
                    "content": "one",
                    "arguments": {"blob": "not-a-ledger-digest"}
                },
                {
                    "role": "assistant",
                    "content": "two",
                    "prefix": "user-prefix",
                    "suffix": ["kept"]
                },
                {"prefix": "also-user", "suffix": [{"text": "leave"}]},
                {"role": "user", "content": "three"}
            ])
        );
        assert!(chain["trace_error"].is_null());
        for id in ["entry-gap", "entry-nested"] {
            let row = rows.iter().find(|row| row["entry_id"] == id).unwrap();
            assert!(row["request"].is_null(), "{id}");
            assert!(
                row["trace_error"]
                    .as_str()
                    .unwrap()
                    .contains("not in the ledger"),
                "{id}: {}",
                row["trace_error"]
            );
        }
    }

    fn gateway_link(
        call_id: &str,
        payload: &str,
        response_id: Option<&str>,
        tool_ids: Vec<String>,
        served: Option<&str>,
        fallbacks: Option<i64>,
    ) -> TraceLink {
        TraceLink {
            session_id: SessionId::new("session:trace").unwrap(),
            call_id: call_id.into(),
            payload_digest: payload.into(),
            request_id: Some("req-gw".into()),
            response_id: response_id.map(str::to_owned),
            tool_ids,
            trace_error: None,
            served_model: served.map(str::to_owned),
            model_group: Some("free-fast".into()),
            attempted_fallbacks: fallbacks,
            gateway_call_id: Some("gw-1".into()),
            response_cost: None,
        }
    }

    #[test]
    fn a_denied_approval_and_a_failed_job_are_labelled_from_the_journal() {
        let mut ledger = Ledger::open_in_memory().unwrap();
        session(&mut ledger);
        append_frame(
            &mut ledger,
            "event:ask",
            json!({
                "type": "extension_ui_request",
                "method": "confirm",
                "id": "perm-1",
                "toolCallId": "tool-1"
            }),
        );
        append_frame(
            &mut ledger,
            "event:deny",
            json!({
                "type": "extension_ui_response",
                "id": "perm-1",
                "confirmed": false
            }),
        );
        append_frame(
            &mut ledger,
            "event:job",
            json!({
                "type": "tool_execution_end",
                "toolCallId": "tool-1",
                "toolName": "bash",
                "result": "Still running after 3 s, so it continues in the background as job j7 (deadline 180 s).",
                "details": {"errorKind": "arguments"}
            }),
        );
        append_frame(
            &mut ledger,
            "event:report",
            json!({
                "type": "prompt",
                "message": "[Job report from Odin — not a message from the owner: Background job j7 (bash) failed after 4 s: boom"
            }),
        );
        insert_call(
            &mut ledger,
            "entry-labels",
            "call-labels",
            OffsetDateTime::UNIX_EPOCH,
            "payload-labels",
            json!({"messages": [{"role": "user", "content": "please rename the workspace file"}]}),
        );
        append_frame(
            &mut ledger,
            "event:end-labels",
            json!({
                "type": "message_end",
                "message": {"responseId": "resp-labels", "stopReason": "toolUse"}
            }),
        );
        ledger
            .link_trace_call(&gateway_link(
                "call-labels",
                "payload-labels",
                Some("resp-labels"),
                vec!["tool-1".into()],
                None,
                None,
            ))
            .unwrap();
        append_frame(
            &mut ledger,
            "event:redo",
            json!({
                "type": "prompt",
                "message": "no, please rename the workspace file again"
            }),
        );
        let row = &ledger
            .export_traces("seat:trace", OffsetDateTime::UNIX_EPOCH)
            .unwrap()[0];
        assert_eq!(row["approval"]["tool-1"], "denied");
        assert_eq!(row["job"][0]["id"], "j7");
        assert_eq!(row["job"][0]["state"], "failed");
        assert_eq!(row["error_class"]["tool-1"], "arguments");
        assert_eq!(row["served_model"], Value::Null);
        assert_eq!(row["inferred_redo"], true);
        assert!(row["inference"].as_str().unwrap().contains("inferred"));
    }

    #[test]
    fn the_turn_clock_and_routine_wakes_are_not_a_redo() {
        let turn = |words: &str| {
            format!("[the owner's local time: Wednesday 2026-10-21 04:49 PDT (America/Los_Angeles)] [You are running on gateway/grok]\n{words}")
        };
        assert!(!inferred_redo(
            &turn("what jobs are running now?"),
            &turn("book a haircut for friday")
        ));
        let wake = turn("[Routine odinschool-watch from Odin — not a message from the owner. He set this routine; it fires now: \"check\".]");
        assert!(!inferred_redo(&wake, &wake));
        assert!(inferred_redo(
            &turn("rename the workspace file"),
            &turn("no, rename the workspace file again")
        ));
    }

    #[test]
    fn privacy_uses_nested_declarations_without_matching_class_names_in_prose() {
        assert_eq!(
            privacy_of(&json!({"messages": [{"content": "---\nprivacy: school\n---\nnotes"}]})),
            Some(PrivacyClass::School)
        );
        assert_eq!(
            privacy_of(
                &json!({"result": "{\"privacy_class\":\"thesis_unreleased\",\"text\":\"notes\"}"})
            ),
            Some(PrivacyClass::ThesisUnreleased)
        );
        assert_eq!(
            privacy_of(&json!({"content": "explain SECRET and PUBLIC"})),
            None
        );
    }

    #[test]
    fn finetune_rows_keep_labels_outside_the_chat_messages() {
        let row = json!({
            "api": "openai-completions",
            "messages": [{"role": "user", "content": "read the file"}],
            "tools": [{"name": "task_read", "description": "read", "parameters": {"type": "object"}}],
            "response": {"content": [{"type": "toolCall", "id": "t1", "name": "task_read", "arguments": {"path": "a"}}]},
            "approval": {"t1": "none"},
            "inferred_redo": false,
            "stop_reason": "toolUse",
            "trace_error": null
        });
        let out = finetune_row(&row);
        assert_eq!(
            out["messages"][1]["tool_calls"][0]["function"]["arguments"],
            "{\"path\":\"a\"}"
        );
        assert!(out["messages"][1].get("labels").is_none());
        assert_eq!(out["labels"]["outcome"], "ok");
        assert_eq!(out["labels"]["train"], "sft");
        assert_eq!(out["tools"][0]["type"], "function");
        let labelled = |change: Value| {
            let mut row = row.clone();
            row.as_object_mut()
                .unwrap()
                .extend(change.as_object().unwrap().clone());
            finetune_row(&row)["labels"].clone()
        };
        for (change, outcome) in [
            (json!({"stop_reason": "aborted"}), "aborted"),
            (json!({"approval": {"t1": "denied"}}), "rejected"),
            (json!({"inferred_redo": true}), "redo"),
            (json!({"error_class": {"t1": "timeout"}}), "tool_error"),
        ] {
            let labels = labelled(change);
            assert_eq!(labels["outcome"], outcome);
            assert_eq!(labels["train"], "exclude");
        }
        let unserved = labelled(json!({}));
        assert_eq!(unserved["served_model"], Value::Null);
        let priced = labelled(json!({"estimated_cost_usd": {"total": 0.07, "input": 0.06}}));
        assert_eq!(priced["cost"], 0.07);
    }
}
