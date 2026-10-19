//! Append-only ingest of local `odin.extension.model_request` entries.

use std::path::Path;

use odin_domain::{Digest, SessionId};
use odin_ledger::trace::{NewTraceCall, TraceBlob, TraceLink};
use serde_json::Value;
use time::OffsetDateTime;

use super::*;

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
        let outcome =
            tokio::task::spawn_blocking(move || ingest_blocking(&ledger, &session, &spec))
                .await
                .map_err(|error| BridgeError::Serialization {
                    detail: format!("model-request ingest task failed: {error}"),
                })?;
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

fn ingest_blocking(
    ledger: &Mutex<Ledger>,
    session: &SessionId,
    spec: &OmpProcessSpec,
) -> Result<Ingest, String> {
    let mut guard = ledger
        .lock()
        .map_err(|_| "ledger mutex poisoned".to_owned())?;
    let cursor = guard
        .trace_cursor(session)
        .map_err(|error| error.to_string())?;
    let Some(path) = transcript_target(spec, cursor.as_ref().map(|cursor| cursor.path.as_str()))?
    else {
        return Ok(Ingest::NotYet);
    };
    let offset = cursor
        .as_ref()
        .filter(|cursor| cursor.path == path)
        .map(|cursor| cursor.offset)
        .unwrap_or(0);
    let (bytes, _) = read_local(Path::new(&path), offset)?;
    let consumed = complete_lines(&bytes);
    let mut failed = Vec::new();
    for line in consumed.split_inclusive('\n') {
        let Ok(value) = serde_json::from_str::<Value>(line.trim()) else {
            continue;
        };
        if value.get("type").and_then(Value::as_str) != Some("custom") {
            continue;
        }
        let result = match value.get("customType").and_then(Value::as_str) {
            Some(REQUEST) => ingest_request(&mut guard, session, &value),
            Some(LINK) => ingest_link(&mut guard, session, &value),
            _ => Ok(()),
        };
        if let Err(error) = result {
            failed.push(error);
        }
    }
    let advanced = offset + consumed.len() as u64;
    if advanced != offset {
        // A malformed line must not hide later entries.
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

fn transcript_target(
    spec: &OmpProcessSpec,
    stored: Option<&str>,
) -> Result<Option<String>, String> {
    if let Some(path) = stored {
        if Path::new(path).is_file() {
            return Ok(Some(path.to_owned()));
        }
    }
    resumable_transcript(spec).map(|path| path.map(|path| path.display().to_string()))
}

fn read_local(path: &Path, offset: u64) -> Result<(String, ()), String> {
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
    let valid = std::str::from_utf8(&bytes)
        .map(|text| text.len())
        .unwrap_or_else(|error| error.valid_up_to());
    Ok((String::from_utf8_lossy(&bytes[..valid]).into_owned(), ()))
}

fn complete_lines(bytes: &str) -> &str {
    match bytes.rfind('\n') {
        Some(end) => &bytes[..=end],
        None => "",
    }
}

fn ingest_request(ledger: &mut Ledger, session: &SessionId, entry: &Value) -> Result<(), String> {
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
    for block in blocks {
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
    let occurred = entry
        .get("timestamp")
        .and_then(Value::as_str)
        .and_then(|stamp| {
            OffsetDateTime::parse(stamp, &time::format_description::well_known::Rfc3339).ok()
        })
        .unwrap_or_else(OffsetDateTime::now_utc);
    ledger
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
            trace_error: data
                .get("trace_error")
                .and_then(Value::as_str)
                .map(str::to_owned),
        })
        .map_err(|error| error.to_string())?;
    Ok(())
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
            ingest_blocking(&ledger, &session, &process),
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
        let unreadable = ingest_blocking(&ledger, &session, &process)
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
            ingest_blocking(&ledger, &session, &process),
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
        let shrunk = ingest_blocking(&ledger, &session, &process)
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
    #[test]
    fn context_refusal_link_without_call_id_is_accepted() {
        let mut ledger = Ledger::open_in_memory().expect("ledger");
        let session =
            SessionId::new("session:28b3fc48-21e3-4e56-a0df-547737cdef65").expect("session id");
        let refusal = json!({
            "type": "custom",
            "customType": LINK,
            "data": { "trace_error": "context window exceeded" },
        });

        ingest_link(&mut ledger, &session, &refusal).expect("deliberate context refusal");
        assert!(ingest_link(&mut ledger, &session, &json!({"data": {}})).is_err());
    }
}
