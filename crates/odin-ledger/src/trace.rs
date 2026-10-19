//! Content-addressed model-request traces and the local export that
//! reconstructs them.
//!
//! Blobs are stored once, keyed by the ledger BLAKE3 of their serde JSON
//! and looked up by the extension's wire SHA-256. A second wire hash of the
//! same body is an alias, not a second blob. A call row names those blobs
//! by JSON path. Export reads this ledger, never a transcript.

use crate::{decode_utc, encode_utc, Ledger, LedgerError, LedgerResult};
use odin_domain::{Digest, SessionId};
use rusqlite::{params, OptionalExtension};
use serde_json::{Map, Value};
use time::OffsetDateTime;

pub const EXPORT_SCHEMA: &str = "odin.trace.export.v1";

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
                "UPDATE trace_calls SET request_id=COALESCE(?3, request_id), response_id=COALESCE(?4, response_id), tool_ids_json=CASE WHEN ?5 = '[]' THEN tool_ids_json ELSE ?5 END, trace_error=CASE WHEN ?6 IS NULL THEN trace_error WHEN trace_error IS NULL THEN ?6 ELSE trace_error || '; ' || ?6 END WHERE session_id=?1 AND call_id=?2",
                params![
                    link.session_id.as_str(),
                    link.call_id,
                    link.request_id,
                    link.response_id,
                    tools,
                    link.trace_error,
                ],
            )?;
            Ok(updated > 0)
        })
    }

    pub fn trace_cursor(&self, session: &SessionId) -> LedgerResult<Option<TraceCursor>> {
        self.connection()
            .query_row(
                "SELECT path, byte_offset FROM trace_cursors WHERE session_id=?1",
                [session.as_str()],
                |row| {
                    Ok(TraceCursor {
                        path: row.get(0)?,
                        offset: u64::try_from(row.get::<_, i64>(1)?).unwrap_or(0),
                    })
                },
            )
            .optional()
            .map_err(LedgerError::from)
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
    pub fn export_traces(&self, seat: &str, since: OffsetDateTime) -> LedgerResult<Vec<Value>> {
        let bound = encode_utc(since)?;
        let mut statement = self.connection().prepare_cached(
            "SELECT c.session_id, s.seat_id, c.entry_id, c.occurred_at, c.payload_digest, c.provider, c.model, c.api, c.skeleton_json, c.request_id, c.response_id, c.tool_ids_json, c.trace_error FROM trace_calls c JOIN live_sessions s ON s.session_id=c.session_id WHERE s.seat_id=?1 AND c.occurred_at>=substr(?2,1,19)",
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
            ))
        })?;
        let mut ranked = Vec::new();
        for row in rows {
            let (
                session_id,
                seat_id,
                entry_id,
                occurred_at,
                _payload_digest,
                provider,
                model,
                api,
                skeleton,
                request_id,
                response_id,
                tool_ids,
                trace_error,
            ) = row?;
            let occurred = decode_utc(&occurred_at)?;
            if occurred < since {
                continue;
            }
            let skeleton: Value = serde_json::from_str(&skeleton)?;
            let tool_ids: Vec<String> = serde_json::from_str(&tool_ids)?;
            let (request, reconstruct_error) = reconstruct(self, &skeleton)?;
            let mut error = join_error(trace_error, reconstruct_error);
            let follow = journaled_follow(
                self,
                &session_id,
                response_id.as_deref(),
                &tool_ids,
                &mut error,
            )?;
            ranked.push((
                occurred,
                entry_id.clone(),
                serde_json::json!({
                    "schema": EXPORT_SCHEMA,
                    "session_id": session_id,
                    "seat_id": seat_id,
                    "entry_id": entry_id,
                    "occurred_at": occurred_at,
                    "provider": provider,
                    "model": model,
                    "api": api,
                    "request_id": request_id,
                    "response_id": response_id,
                    "request": request,
                    "messages": request.as_ref().and_then(message_array),
                    "tools": request.as_ref().and_then(tools_value),
                    "response": follow.response,
                    "tool_calls": follow.calls,
                    "tool_results": follow.results,
                    "usage": follow.usage,
                    "outcome": follow.outcome,
                    "lessons": follow.lessons,
                    "trace_error": error,
                }),
            ));
        }
        ranked.sort_by(|left, right| left.0.cmp(&right.0).then_with(|| left.1.cmp(&right.1)));
        Ok(ranked.into_iter().map(|(_, _, row)| row).collect())
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
        return Err(LedgerError::invalid_data(
            "trace history chain exceeds 4096 steps".into(),
        ));
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
    outcome: Option<Value>,
    calls: Vec<Value>,
    results: Vec<Value>,
    lessons: Vec<Value>,
}

fn journaled_follow(
    ledger: &Ledger,
    session_id: &str,
    response_id: Option<&str>,
    tool_ids: &[String],
    error: &mut Option<String>,
) -> LedgerResult<JournalFollow> {
    let session = SessionId::parse(session_id).map_err(|failure| {
        LedgerError::invalid_data_caused_by(
            format!("trace session id {session_id} is invalid"),
            failure,
        )
    })?;
    let head = ledger.reconnect_head(&session)?;
    let events = ledger.live_event_history(&session, 0, head)?;
    let mut response = None;
    let mut usage = None;
    let mut outcome = None;
    let mut calls = Vec::new();
    let mut results = Vec::new();
    let mut lessons = Vec::new();
    let mut response_sequence = None;
    for event in events {
        let Some(frame) = event.body.get("frame") else {
            continue;
        };
        let kind = frame.get("type").and_then(Value::as_str);
        if kind == Some("message_end") {
            let message = frame.get("message");
            let id = message
                .and_then(|message| message.get("responseId"))
                .and_then(Value::as_str);
            if response_id.is_some() && id == response_id {
                response = message.cloned();
                usage = message.and_then(|message| message.get("usage")).cloned();
                outcome = message
                    .and_then(|message| message.get("stopReason"))
                    .cloned();
                response_sequence = Some(event.sequence);
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
            let id = frame
                .get("toolCallId")
                .or_else(|| frame.get("toolUseId"))
                .and_then(Value::as_str)
                .map(str::to_owned);
            let Some(id) = id else {
                continue;
            };
            let name = frame.get("toolName").and_then(Value::as_str).unwrap_or("");
            let in_call = tool_ids.iter().any(|wanted| wanted == &id);
            let later_lesson = !in_call
                && matches!(name, "memory_remember" | "memory_forget")
                && response_sequence.is_some_and(|end| event.sequence > end);
            if !in_call && !later_lesson {
                continue;
            }
            if kind == Some("tool_execution_end") {
                if in_call {
                    results.push(frame.clone());
                }
                if matches!(name, "memory_remember" | "memory_forget") {
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
    if response_id.is_some() && response.is_none() {
        *error = join_error(
            error.take(),
            Some(format!(
                "no journaled message_end carries responseId {}",
                response_id.unwrap_or_default()
            )),
        );
    }
    Ok(JournalFollow {
        response,
        usage,
        outcome,
        calls,
        results,
        lessons,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::live::{NewLiveEvent, NewLiveSession};
    use odin_domain::EventId;
    use serde_json::{json, Value};
    use time::format_description::well_known::Rfc3339;
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
    fn stamp(raw: &str) -> OffsetDateTime {
        OffsetDateTime::parse(raw, &Rfc3339).unwrap()
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
    fn a_missing_blob_is_an_error_not_a_stand_in() {
        let mut ledger = Ledger::open_in_memory().unwrap();
        session(&mut ledger);
        ledger
            .insert_trace_call(&NewTraceCall {
                session_id: SessionId::new("session:trace").unwrap(),
                entry_id: "entry-missing".into(),
                occurred_at: OffsetDateTime::UNIX_EPOCH,
                call_id: "call-missing".into(),
                payload_digest: "sha-missing".into(),
                provider: None,
                model: None,
                api: None,
                skeleton: json!({"system": {"blob": "absent"}}),
                trace_error: None,
            })
            .unwrap();
        let rows = ledger
            .export_traces("seat:trace", OffsetDateTime::UNIX_EPOCH)
            .unwrap();
        assert!(rows[0]["request"].is_null());
        assert!(rows[0]["trace_error"]
            .as_str()
            .unwrap()
            .contains("not in the ledger"));
    }

    #[test]
    fn cursor_refuses_to_move_backward() {
        let mut ledger = Ledger::open_in_memory().unwrap();
        let session = SessionId::new("session:trace").unwrap();
        ledger
            .advance_trace_cursor(&session, "/tmp/s.jsonl", 40)
            .unwrap();
        assert!(ledger
            .advance_trace_cursor(&session, "/tmp/s.jsonl", 10)
            .is_err());
        assert_eq!(ledger.trace_cursor(&session).unwrap().unwrap().offset, 40);
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

    #[test]
    fn identical_payloads_link_only_the_addressed_call() {
        let mut ledger = Ledger::open_in_memory().unwrap();
        session(&mut ledger);
        insert_call(
            &mut ledger,
            "entry-a",
            "call-a",
            OffsetDateTime::UNIX_EPOCH,
            "same-payload",
            json!({}),
        );
        insert_call(
            &mut ledger,
            "entry-b",
            "call-b",
            OffsetDateTime::UNIX_EPOCH,
            "same-payload",
            json!({}),
        );
        assert!(ledger
            .link_trace_call(&TraceLink {
                session_id: SessionId::new("session:trace").unwrap(),
                call_id: "call-b".into(),
                payload_digest: "same-payload".into(),
                request_id: Some("req-b".into()),
                response_id: None,
                tool_ids: Vec::new(),
                trace_error: None,
            })
            .unwrap());
        assert!(!ledger
            .link_trace_call(&TraceLink {
                session_id: SessionId::new("session:trace").unwrap(),
                call_id: String::new(),
                payload_digest: "same-payload".into(),
                request_id: Some("req-empty".into()),
                response_id: None,
                tool_ids: Vec::new(),
                trace_error: None,
            })
            .unwrap());
        assert!(!ledger
            .link_trace_call(&TraceLink {
                session_id: SessionId::new("session:trace").unwrap(),
                call_id: "call-missing".into(),
                payload_digest: "same-payload".into(),
                request_id: Some("req-missing".into()),
                response_id: None,
                tool_ids: Vec::new(),
                trace_error: None,
            })
            .unwrap());
        let rows = ledger
            .export_traces("seat:trace", OffsetDateTime::UNIX_EPOCH)
            .unwrap();
        let row = |id: &str| rows.iter().find(|row| row["entry_id"] == id).unwrap();
        assert!(row("entry-a")["request_id"].is_null());
        assert_eq!(row("entry-b")["request_id"], "req-b");
    }

    #[test]
    fn fractional_since_is_inclusive_despite_lexical_order() {
        let mut ledger = Ledger::open_in_memory().unwrap();
        session(&mut ledger);
        let whole = stamp("2026-08-31T00:00:00Z");
        let frac = stamp("2026-08-31T00:00:00.1Z");
        let stored_frac = crate::encode_utc(frac).unwrap();
        let stored_whole = crate::encode_utc(whole).unwrap();
        assert!(stored_frac.contains('.'), "{stored_frac}");
        assert!(
            stored_frac.as_str() < stored_whole.as_str(),
            "{stored_frac} vs {stored_whole}"
        );
        insert_call(
            &mut ledger,
            "entry-whole",
            "call-whole",
            whole,
            "payload-whole",
            json!({}),
        );
        insert_call(
            &mut ledger,
            "entry-frac",
            "call-frac",
            frac,
            "payload-frac",
            json!({}),
        );
        let ordered = |since: OffsetDateTime| {
            ledger
                .export_traces("seat:trace", since)
                .unwrap()
                .into_iter()
                .map(|row| row["entry_id"].as_str().unwrap().to_owned())
                .collect::<Vec<_>>()
        };
        assert_eq!(
            ordered(whole),
            vec!["entry-whole".to_owned(), "entry-frac".to_owned()]
        );
        assert_eq!(ordered(frac), vec!["entry-frac".to_owned()]);
        let exported = ledger.export_traces("seat:trace", whole).unwrap();
        assert_eq!(exported[0]["entry_id"], "entry-whole");
        assert_eq!(exported[1]["entry_id"], "entry-frac");
        assert!(exported[1]["occurred_at"].as_str().unwrap().contains('.'));
    }

    #[test]
    fn later_lessons_follow_the_response_and_an_unlinked_call_does_not() {
        let mut ledger = Ledger::open_in_memory().unwrap();
        session(&mut ledger);
        append_frame(
            &mut ledger,
            "event:before",
            json!({
                "type": "tool_execution_end",
                "toolCallId": "before-foreign",
                "toolName": "memory_remember",
                "result": {"kept": false}
            }),
        );
        append_frame(
            &mut ledger,
            "event:incall",
            json!({
                "type": "tool_execution_end",
                "toolCallId": "tool-in-call",
                "toolName": "memory_remember",
                "result": {"kept": true}
            }),
        );
        append_frame(
            &mut ledger,
            "event:end",
            json!({
                "type": "message_end",
                "message": {
                    "responseId": "resp-1",
                    "usage": {"input": 1, "output": 1},
                    "stopReason": "stop"
                }
            }),
        );
        append_frame(
            &mut ledger,
            "event:after",
            json!({
                "type": "tool_execution_end",
                "toolCallId": "after-foreign",
                "toolName": "memory_remember",
                "result": {"kept": true}
            }),
        );
        append_frame(
            &mut ledger,
            "event:other",
            json!({
                "type": "tool_execution_end",
                "toolCallId": "after-other",
                "toolName": "bash",
                "result": {"ok": true}
            }),
        );
        insert_call(
            &mut ledger,
            "entry-linked",
            "call-linked",
            OffsetDateTime::UNIX_EPOCH,
            "payload-linked",
            json!({}),
        );
        insert_call(
            &mut ledger,
            "entry-open",
            "call-open",
            OffsetDateTime::UNIX_EPOCH,
            "payload-open",
            json!({}),
        );
        assert!(ledger
            .link_trace_call(&TraceLink {
                session_id: SessionId::new("session:trace").unwrap(),
                call_id: "call-linked".into(),
                payload_digest: "payload-linked".into(),
                request_id: Some("req-1".into()),
                response_id: Some("resp-1".into()),
                tool_ids: vec!["tool-in-call".into()],
                trace_error: None,
            })
            .unwrap());
        let rows = ledger
            .export_traces("seat:trace", OffsetDateTime::UNIX_EPOCH)
            .unwrap();
        let linked = rows
            .iter()
            .find(|row| row["entry_id"] == "entry-linked")
            .unwrap();
        let open = rows
            .iter()
            .find(|row| row["entry_id"] == "entry-open")
            .unwrap();
        let lesson_ids: Vec<_> = linked["lessons"]
            .as_array()
            .unwrap()
            .iter()
            .map(|lesson| lesson["tool_call_id"].as_str().unwrap().to_owned())
            .collect();
        assert_eq!(
            lesson_ids,
            vec!["tool-in-call".to_owned(), "after-foreign".to_owned()]
        );
        let result_ids: Vec<_> = linked["tool_results"]
            .as_array()
            .unwrap()
            .iter()
            .map(|frame| frame["toolCallId"].as_str().unwrap().to_owned())
            .collect();
        assert_eq!(result_ids, vec!["tool-in-call".to_owned()]);
        assert!(linked["trace_error"].is_null());
        assert_eq!(open["lessons"], json!([]));
        assert!(open["trace_error"].is_null());
    }

    #[test]
    fn a_second_wire_hash_aliases_and_a_conflicting_body_is_rejected() {
        let mut ledger = Ledger::open_in_memory().unwrap();
        let body = json!({"role": "user", "content": "same"});
        let bytes = serde_json::to_vec(&body).unwrap();
        ledger
            .put_trace_blob(&TraceBlob {
                digest: Digest::hash(&bytes),
                wire_sha256: "wire-a".into(),
                kind: "history".into(),
                body: body.clone(),
            })
            .unwrap();
        ledger
            .put_trace_blob(&TraceBlob {
                digest: Digest::hash(&bytes),
                wire_sha256: "wire-b".into(),
                kind: "history".into(),
                body: body.clone(),
            })
            .unwrap();
        assert_eq!(
            ledger.trace_blob_by_wire("wire-b").unwrap().as_ref(),
            Some(&body)
        );
        let blobs: i64 = ledger
            .connection()
            .query_row("SELECT COUNT(*) FROM trace_blobs", [], |row| row.get(0))
            .unwrap();
        let aliases: i64 = ledger
            .connection()
            .query_row("SELECT COUNT(*) FROM trace_blob_aliases", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(blobs, 1);
        assert_eq!(aliases, 1);
        let other = json!({"role": "user", "content": "other"});
        let other_bytes = serde_json::to_vec(&other).unwrap();
        assert!(matches!(
            ledger.put_trace_blob(&TraceBlob {
                digest: Digest::hash(&other_bytes),
                wire_sha256: "wire-a".into(),
                kind: "history".into(),
                body: other.clone(),
            }),
            Err(LedgerError::Conflict(_))
        ));
        assert!(matches!(
            ledger.put_trace_blob(&TraceBlob {
                digest: Digest::hash(b"not-the-body"),
                wire_sha256: "wire-c".into(),
                kind: "history".into(),
                body: other,
            }),
            Err(LedgerError::Conflict(_))
        ));
    }
}
