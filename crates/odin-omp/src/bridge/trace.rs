//! Append-only ingest of local `odin.extension.model_request` entries.

use std::path::Path;

use odin_domain::huginn::LiveSessionId;
use odin_domain::{Digest, SessionId};
use odin_ledger::trace::{NewTraceCall, TraceBlob, TraceLink};
use serde_json::Value;
use time::OffsetDateTime;

use super::*;
use crate::live::context_trace;

const REQUEST: &str = "odin.extension.model_request";
const LINK: &str = "odin.extension.model_request_link";

impl Shared {
    // Kube exec has no pod transcript reader; never inspect the host filesystem for it.
    pub(super) async fn ingest_model_requests(&self) -> Result<(), BridgeError> {
        if self.transport.is_some() {
            return Ok(());
        }
        let binding = self.binding_snapshot()?;
        let spec = self.process_spec.clone();
        let ledger = Arc::clone(&self.ledger);
        let session = binding.session_id.clone();
        let trace = match &self.context_trace_root {
            Some(root) => {
                let live = LiveSessionId::parse(&session.to_string()).map_err(|error| {
                    BridgeError::Config {
                        detail: format!("context trace session id: {error}"),
                    }
                })?;
                Some((root.clone(), live))
            }
            None => None,
        };
        let outcome = tokio::task::spawn_blocking(move || {
            let trace = trace.as_ref().map(|(root, live)| (root.as_path(), *live));
            ingest_blocking(&ledger, &session, &spec, trace)
        })
        .await
        .map_err(BridgeError::task("model-request ingest"))?;
        match outcome {
            Ok(Ingest::Applied | Ingest::NotYet) => {}
            Err(error) => {
                tracing::error!("odind: model-request ingest failed: {error}");
                if let Err(journal) = self
                    .append_event(json!({
                        "kind": "trace_error",
                        "error": error,
                    }))
                    .await
                {
                    tracing::error!(
                        "odind: model-request trace_error was not journaled: {journal}"
                    );
                }
            }
        }
        Ok(())
    }
}

/// `NotYet` is ordinary local readiness: the harness has not written a
/// transcript. It is not a read of an empty file and it does not move the cursor.
#[derive(Debug)]
enum Ingest {
    Applied,
    NotYet,
}

/// `trace` is where each request's prefix is recorded, when the session keeps a context trace.
fn ingest_blocking(
    ledger: &Mutex<Ledger>,
    session: &SessionId,
    spec: &OmpProcessSpec,
    trace: Option<(&Path, LiveSessionId)>,
) -> Result<Ingest, String> {
    let mut guard = ledger
        .lock()
        .map_err(|error| format!("ledger mutex: {error}"))?;
    let cursor = guard
        .trace_cursor(session)
        .map_err(|error| error.to_string())?;
    // The newest transcript of the session: a fresh incarnation writes a new
    // file, and the superseded one never grows again.
    let Some(path) = resumable_transcript(spec)?.map(|path| path.display().to_string()) else {
        return Ok(Ingest::NotYet);
    };
    let offset = cursor
        .as_ref()
        .filter(|cursor| cursor.path == path)
        .map(|cursor| cursor.offset)
        .unwrap_or(0);
    let bytes = read_local(Path::new(&path), offset)?;
    let consumed = complete_lines(&bytes);
    let mut failed = Vec::new();
    for line in consumed.split_inclusive(|byte| *byte == b'\n') {
        // A line that is not valid JSON (or UTF-8) is skipped; it must not hide later entries.
        let Ok(value) = serde_json::from_slice::<Value>(line) else {
            continue;
        };
        if value.get("type").and_then(Value::as_str) != Some("custom") {
            continue;
        }
        let result = match value.get("customType").and_then(Value::as_str) {
            Some(REQUEST) => ingest_request(&mut guard, session, &value, trace),
            Some(LINK) => ingest_link(&mut guard, session, &value),
            _ => Ok(()),
        };
        if let Err(error) = result {
            failed.push(error);
        }
    }
    let advanced = offset + consumed.len() as u64;
    if advanced != offset {
        guard
            .advance_trace_cursor(session, &path, advanced)
            .map_err(|error| error.to_string())?;
    }
    if failed.is_empty() {
        Ok(Ingest::Applied)
    } else {
        Err(failed.join("; "))
    }
}

fn read_local(path: &Path, offset: u64) -> Result<Vec<u8>, String> {
    let file =
        std::fs::File::open(path).map_err(|error| format!("open {}: {error}", path.display()))?;
    let length = file
        .metadata()
        .map_err(|error| format!("stat {}: {error}", path.display()))?
        .len();
    if length < offset {
        return Err(format!(
            "transcript {} shrank below cursor {offset}; refusing to reread from byte 0",
            path.display()
        ));
    }
    use std::io::{Read, Seek};
    let mut file = file;
    file.seek(std::io::SeekFrom::Start(offset))
        .map_err(|error| error.to_string())?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)
        .map_err(|error| error.to_string())?;
    Ok(bytes)
}

/// The prefix of `bytes` that ends at the last newline; a partial final line waits for its newline.
fn complete_lines(bytes: &[u8]) -> &[u8] {
    match bytes.iter().rposition(|byte| *byte == b'\n') {
        Some(end) => &bytes[..=end],
        None => &[],
    }
}

fn ingest_request(
    ledger: &mut Ledger,
    session: &SessionId,
    entry: &Value,
    trace: Option<(&Path, LiveSessionId)>,
) -> Result<(), String> {
    let data = entry
        .get("data")
        .ok_or_else(|| "model_request entry has no data".to_owned())?;
    let entry_id = entry
        .get("id")
        .and_then(Value::as_str)
        .ok_or_else(|| "model_request entry has no id".to_owned())?;
    let blocks = data
        .get("blocks")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    for block in &blocks {
        let Some(digest) = block.get("sha256").and_then(Value::as_str) else {
            return Err(format!("model_request {entry_id} block has no sha256"));
        };
        let Some(body) = block.get("body") else {
            if ledger
                .trace_blob_by_wire(digest)
                .map_err(|error| error.to_string())?
                .is_none()
            {
                return Err(format!(
                    "model_request {entry_id} references blob {digest} that was never stored"
                ));
            }
            continue;
        };
        let bytes = serde_json::to_vec(body).map_err(|error| error.to_string())?;
        ledger
            .put_trace_blob(&TraceBlob {
                digest: Digest::hash(&bytes),
                wire_sha256: digest.to_owned(),
                kind: block
                    .get("role")
                    .and_then(Value::as_str)
                    .unwrap_or("block")
                    .to_owned(),
                body: body.clone(),
            })
            .map_err(|error| error.to_string())?;
    }
    let (occurred, stamp_error) = match entry.get("timestamp").and_then(Value::as_str) {
        Some(stamp) => OffsetDateTime::parse(stamp, &time::format_description::well_known::Rfc3339)
            .map(|stamp| (stamp, None))
            .unwrap_or_else(|_| {
                (
                    OffsetDateTime::now_utc(),
                    Some(
                        "transcript entry timestamp is not RFC3339; occurred_at is ingest time, not the request time"
                            .to_owned(),
                    ),
                )
            }),
        None => (
            OffsetDateTime::now_utc(),
            Some(
                "transcript entry has no timestamp; occurred_at is ingest time, not the request time"
                    .to_owned(),
            ),
        ),
    };
    let trace_error = join_text(
        data.get("trace_error")
            .and_then(Value::as_str)
            .map(str::to_owned),
        stamp_error,
    );
    let inserted = ledger
        .insert_trace_call(&NewTraceCall {
            session_id: session.clone(),
            entry_id: entry_id.to_owned(),
            occurred_at: occurred,
            call_id: data
                .get("call_id")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_owned(),
            payload_digest: data
                .get("payload_digest")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_owned(),
            provider: data
                .get("provider")
                .and_then(Value::as_str)
                .map(str::to_owned),
            model: data.get("model").and_then(Value::as_str).map(str::to_owned),
            api: data.get("api").and_then(Value::as_str).map(str::to_owned),
            skeleton: data.get("skeleton").cloned().unwrap_or(Value::Null),
            trace_error,
        })
        .map_err(|error| error.to_string())?;
    // A re-read entry keeps its one ledger row and its one trace record.
    if let (true, Some((root, live))) = (inserted, trace) {
        match context_trace::Prefix::of(&blocks) {
            Some(prefix) => context_trace::record_request(root, live, prefix)?,
            // The session still runs the extension from before block sizes were stored.
            None => tracing::debug!(
                "odind: model_request {entry_id} carries no block sizes; its prefix is not traced"
            ),
        }
    }
    Ok(())
}

fn text_field(data: &Value, key: &str) -> Option<String> {
    data.get(key)
        .and_then(Value::as_str)
        .filter(|text| !text.is_empty())
        .map(str::to_owned)
}

fn integer_field(data: &Value, key: &str) -> Option<i64> {
    data.get(key).and_then(Value::as_i64).or_else(|| {
        data.get(key)
            .and_then(Value::as_str)
            .and_then(|raw| raw.parse().ok())
    })
}

fn join_text(left: Option<String>, right: Option<String>) -> Option<String> {
    match (left, right) {
        (Some(left), Some(right)) => Some(format!("{left}; {right}")),
        (Some(value), None) | (None, Some(value)) => Some(value),
        (None, None) => None,
    }
}

fn ingest_link(ledger: &mut Ledger, session: &SessionId, entry: &Value) -> Result<(), String> {
    let data = entry
        .get("data")
        .ok_or_else(|| "model_request_link entry has no data".to_owned())?;
    let call_id = data
        .get("call_id")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_owned();
    if call_id.is_empty() {
        if data.get("trace_error").and_then(Value::as_str).is_some() {
            return Ok(());
        }
        return Err("model_request_link has no call_id; the response was not dropped".to_owned());
    }
    let payload = data
        .get("payload_digest")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_owned();
    let tool_ids = data
        .get("tool_call_ids")
        .and_then(Value::as_array)
        .map(|ids| {
            ids.iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default();
    let linked = ledger
        .link_trace_call(&TraceLink {
            session_id: session.clone(),
            call_id,
            payload_digest: payload,
            request_id: data
                .get("request_id")
                .and_then(Value::as_str)
                .map(str::to_owned),
            response_id: data
                .get("response_id")
                .and_then(Value::as_str)
                .map(str::to_owned),
            tool_ids,
            trace_error: data
                .get("trace_error")
                .and_then(Value::as_str)
                .map(str::to_owned),
            served_model: text_field(data, "served_model"),
            model_group: text_field(data, "model_group"),
            attempted_fallbacks: integer_field(data, "attempted_fallbacks"),
            gateway_call_id: text_field(data, "gateway_call_id"),
            response_cost: text_field(data, "response_cost"),
        })
        .map_err(|error| error.to_string())?;
    if !linked {
        return Err(
            "model_request_link names a call id that is not stored; the response was not dropped"
                .to_owned(),
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec(cwd: &Path, home: &Path) -> OmpProcessSpec {
        OmpProcessSpec {
            executable: Path::new("/omp").to_path_buf(),
            cwd: cwd.to_path_buf(),
            explicit_args: Vec::new(),
            explicit_env: vec![("HOME".to_owned(), home.display().to_string())],
            expected_source_revision: "test".to_owned(),
            startup_timeout: std::time::Duration::from_secs(1),
            drain_timeout: std::time::Duration::from_secs(1),
            kill_timeout: std::time::Duration::from_secs(1),
        }
    }

    /// A transcript that does not exist yet is readiness, not a read. Once it
    /// appears the cursor follows complete lines only, and a shrink stays an error.
    #[test]
    fn absent_local_transcript_is_not_ready_and_does_not_move_the_cursor() {
        let root = tempfile::tempdir().expect("tempdir");
        let session_id = "28b3fc48-21e3-4e56-a0df-547737cdef65";
        let launch = "e690e7ac-2038-4dc5-be98-14fa142f0558";
        let cwd = root.path().join("harness").join(session_id).join(launch);
        std::fs::create_dir_all(&cwd).expect("harness cwd");
        let home = root.path().join("home");
        std::fs::create_dir_all(&home).expect("home");
        let session = SessionId::new(format!("session:{session_id}")).expect("session id");
        let ledger = Mutex::new(Ledger::open_in_memory().expect("ledger"));
        let process = spec(&cwd, &home);

        assert!(matches!(
            ingest_blocking(&ledger, &session, &process, None),
            Ok(Ingest::NotYet)
        ));
        assert!(
            ledger
                .lock()
                .expect("ledger")
                .trace_cursor(&session)
                .expect("cursor")
                .is_none(),
            "not-yet must not look like an empty transcript was read"
        );

        let sessions = home.join(".omp/agent/sessions");
        std::fs::create_dir_all(sessions.parent().expect("sessions parent"))
            .expect("sessions parent");
        std::fs::write(&sessions, b"not a directory").expect("block the sessions root");
        let unreadable = ingest_blocking(&ledger, &session, &process, None)
            .expect_err("an unreadable sessions root is a real failure");
        assert!(
            unreadable.contains("unreadable"),
            "the failure keeps its cause: {unreadable}"
        );
        std::fs::remove_file(&sessions).expect("clear the blocked root");
        assert!(
            ledger
                .lock()
                .expect("ledger")
                .trace_cursor(&session)
                .expect("cursor")
                .is_none(),
            "a failed read must not advance the cursor"
        );

        let project = sessions.join(format!("-harness-{session_id}-{launch}"));
        std::fs::create_dir_all(&project).expect("project dir");
        let path = project.join("2026-09-16T23-07-37-242Z_a.jsonl");
        let line = "{\"type\":\"not-a-request\"}\n";
        std::fs::write(&path, format!("{line}partial")).expect("transcript");

        assert!(matches!(
            ingest_blocking(&ledger, &session, &process, None),
            Ok(Ingest::Applied)
        ));
        let cursor = ledger
            .lock()
            .expect("ledger")
            .trace_cursor(&session)
            .expect("cursor")
            .expect("cursor stored");
        assert_eq!(cursor.path, path.display().to_string());
        assert_eq!(cursor.offset, line.len() as u64);

        let file = std::fs::File::options()
            .write(true)
            .open(&path)
            .expect("reopen transcript");
        file.set_len(cursor.offset - 1).expect("shrink transcript");
        drop(file);
        let shrunk = ingest_blocking(&ledger, &session, &process, None)
            .expect_err("a transcript shorter than the cursor is a real failure");
        assert!(
            shrunk.contains("shrank below cursor"),
            "the shrink keeps its cause: {shrunk}"
        );
        assert_eq!(
            ledger
                .lock()
                .expect("ledger")
                .trace_cursor(&session)
                .expect("cursor")
                .expect("cursor stored")
                .offset,
            cursor.offset,
            "a refused shrink must leave the cursor where it was"
        );
    }

    /// A fresh incarnation writes a newer transcript beside the superseded one; ingest
    /// follows it, and a line that is not valid UTF-8 costs only that line.
    #[test]
    fn ingest_follows_the_newest_transcript_past_a_corrupt_line() {
        let root = tempfile::tempdir().expect("tempdir");
        let session_id = "28b3fc48-21e3-4e56-a0df-547737cdef65";
        let launch = "e690e7ac-2038-4dc5-be98-14fa142f0558";
        let cwd = root.path().join("harness").join(session_id).join(launch);
        std::fs::create_dir_all(&cwd).expect("harness cwd");
        let home = root.path().join("home");
        let project = home
            .join(".omp/agent/sessions")
            .join(format!("-harness-{session_id}-{launch}"));
        std::fs::create_dir_all(&project).expect("project dir");
        let session = SessionId::new(format!("session:{session_id}")).expect("session id");
        let ledger = Mutex::new(Ledger::open_in_memory().expect("ledger"));
        let process = spec(&cwd, &home);
        let request = |id: &str| {
            let mut line = serde_json::to_vec(&json!({
                "type": "custom", "customType": REQUEST, "id": id,
                "data": {"call_id": id, "payload_digest": id, "blocks": [], "skeleton": {}},
            }))
            .expect("entry");
            line.push(b'\n');
            line
        };
        let calls = || -> i64 {
            ledger
                .lock()
                .expect("ledger")
                .connection()
                .query_row("SELECT COUNT(*) FROM trace_calls", [], |row| row.get(0))
                .expect("count")
        };

        let old = project.join("2026-09-16T23-07-37-242Z_a.jsonl");
        std::fs::write(&old, request("before-rollover")).expect("old transcript");
        ingest_blocking(&ledger, &session, &process, None).expect("old transcript ingests");
        assert_eq!(calls(), 1);

        let new = project.join("2026-09-17T08-00-00-000Z_b.jsonl");
        let mut written = b"\xff\xfe not utf-8\n".to_vec();
        written.extend(request("after-rollover"));
        std::fs::write(&new, &written).expect("new transcript");
        assert!(matches!(
            ingest_blocking(&ledger, &session, &process, None),
            Ok(Ingest::Applied)
        ));
        assert_eq!(calls(), 2, "the newer transcript's request is ingested");
        let cursor = ledger
            .lock()
            .expect("ledger")
            .trace_cursor(&session)
            .expect("cursor")
            .expect("cursor stored");
        assert_eq!(cursor.path, new.display().to_string());
        assert_eq!(cursor.offset, written.len() as u64);
    }

    /// History that grows and memory that is injected change a request's size,
    /// never the hash of its system and tools; a changed tool listing does.
    #[test]
    fn a_sessions_stable_prefix_hash_does_not_change_between_turns() {
        let state = tempfile::tempdir().expect("state root");
        let root = context_trace::root(state.path());
        let live = LiveSessionId::parse("28b3fc48-21e3-4e56-a0df-547737cdef65").expect("session");
        let session = SessionId::new(live.to_string()).expect("session id");
        let mut ledger = Ledger::open_in_memory().expect("ledger");
        let block = |role: &str, text: &str, bytes: u64| json!({"path": "/x", "role": role, "sha256": format!("{role}:{text}"), "bytes": bytes, "body": text});
        let request = |id: &str, tools: &str, history: &str, memory: Option<&str>| {
            let mut blocks = vec![
                block("system", "guidance", 5_000),
                block("tools", tools, 30_000),
                block("history", history, 100),
            ];
            blocks.extend(memory.map(|text| block("memory", text, 900)));
            json!({
                "type": "custom", "customType": REQUEST, "id": id,
                "data": {"call_id": id, "payload_digest": history, "blocks": blocks, "skeleton": {}},
            })
        };
        let first = request("a", "listing", "one", None);
        for entry in [
            first.clone(),
            request("b", "listing", "one two", Some("brain://x")),
            request("c", "listing", "one two three", Some("brain://x")),
            request(
                "d",
                "another listing",
                "one two three four",
                Some("brain://x"),
            ),
            // The same entry read again, as after a crash before the cursor moved.
            first,
        ] {
            ingest_request(&mut ledger, &session, &entry, Some((&root, live))).expect("ingest");
        }
        let prefixes: Vec<_> = context_trace::read(&root, live)
            .expect("read")
            .expect("a trace")
            .into_iter()
            .map(|record| record.prefix.expect("a request record"))
            .collect();
        assert_eq!(prefixes.len(), 4, "a re-read entry adds no second record");
        assert_eq!(prefixes[0].hash, prefixes[1].hash);
        assert_eq!(prefixes[0].hash, prefixes[2].hash);
        assert_ne!(prefixes[0].hash, prefixes[3].hash);
        assert_eq!(
            (
                prefixes[0].system_bytes,
                prefixes[0].tool_bytes,
                prefixes[0].injected_bytes
            ),
            (5_000, 30_000, 0)
        );
        assert_eq!(prefixes[1].injected_bytes, 900);
    }
}
