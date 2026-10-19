//! Bounded supervisor RPCs and read-only reconstruction of the Claude stream.
use std::time::Duration;

use base64::{engine::general_purpose::STANDARD, Engine as _};
use odin_kube::{
    claude_pod::{self, ClaudePodReceipt},
    exec::{WorkloadExecStream, WorkloadLauncherSpec},
    KubeClient,
};
use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::claude_protocol::{ClaudeProtocol, ProtocolError, ProtocolLimits};

const RPC_LIMIT: usize = 1024 * 1024;
const READ_LIMIT: u64 = 262144;
const DEADLINE: Duration = Duration::from_secs(30);
const PROTOCOL_ERROR: &str = "Claude supervisor protocol failed";

pub(super) async fn request(
    client: &KubeClient,
    receipt: &ClaudePodReceipt,
    input: Value,
) -> Result<Value, String> {
    let mut input = serde_json::to_vec(&input)
        .map_err(|_| "Claude supervisor request encoding failed".to_owned())?;
    if input.len() >= RPC_LIMIT {
        return Err("Claude supervisor request exceeds bound".into());
    }
    input.push(b'\n');
    tokio::time::timeout(DEADLINE, async {
        let launcher = client_launcher();
        let stream = claude_pod::exec(client, receipt, &launcher)
            .await
            .map_err(|_| "Claude supervisor attach failed".to_owned())?;
        exchange(stream, &input).await
    })
    .await
    .map_err(|_| "Claude supervisor request timed out".to_owned())?
}

fn client_launcher() -> WorkloadLauncherSpec {
    // The supervisor client runs privileged: never import from the workspace or
    // honor user-provided Python environment settings.
    WorkloadLauncherSpec {
        launcher_path: "/bin/python3".into(),
        arguments: vec![
            "-I".into(),
            "/run/odin-material/supervisor.py".into(),
            "client".into(),
        ],
    }
}

async fn exchange(stream: WorkloadExecStream, input: &[u8]) -> Result<Value, String> {
    let WorkloadExecStream {
        mut stdin,
        mut stdout,
        stderr,
        exit,
        ..
    } = stream;
    let send = async move {
        let result = stdin.write_all(input).await;
        let closed = stdin.shutdown().await;
        result
            .and(closed)
            .map_err(|_| "Claude supervisor input failed".to_owned())
    };
    let receive = async move {
        let mut bytes = Vec::new();
        let mut buffer = [0u8; 8192];
        let mut oversized = false;
        loop {
            let count = stdout
                .read(&mut buffer)
                .await
                .map_err(|_| "Claude supervisor output failed".to_owned())?;
            if count == 0 {
                break;
            }
            if count > RPC_LIMIT.saturating_sub(bytes.len()) {
                oversized = true;
            }
            if !oversized {
                bytes.extend_from_slice(&buffer[..count]);
            }
        }
        if oversized {
            return Err("Claude supervisor output exceeds bound".to_owned());
        }
        Ok(bytes)
    };
    let discard = async move {
        if let Some(mut stderr) = stderr {
            tokio::io::copy(&mut stderr, &mut tokio::io::sink())
                .await
                .map_err(|_| "Claude supervisor error stream failed".to_owned())?;
        }
        Ok::<(), String>(())
    };
    // Do not short-circuit on I/O failure: retain and await the attach pump's
    // exit future. The outer deadline drops it only on abnormal channel loss.
    let (sent, received, discarded, status) = tokio::join!(send, receive, discard, exit);
    sent?;
    let bytes = received?;
    discarded?;
    if status.is_some() {
        return Err("Claude supervisor command failed".into());
    }
    let value: Value = serde_json::from_slice(&bytes)
        .map_err(|_| "Claude supervisor response is invalid".to_owned())?;
    if value.get("ok").and_then(Value::as_bool) != Some(true) {
        return Err("Claude supervisor request rejected".into());
    }
    Ok(value)
}

pub(super) struct Replay {
    pub protocol: ClaudeProtocol,
    pub offset: u64,
    pub events: Vec<Value>,
    pub last_seq: u64,
    /// Latest inspected state; only `running` admits a new prompt.
    pub state: String,
}

pub(super) async fn replay(
    client: &KubeClient,
    receipt: &ClaudePodReceipt,
    session: &str,
    version: &str,
    require_rc: bool,
    name: &str,
) -> Result<Replay, String> {
    let state = request(client, receipt, json!({"op":"inspect"})).await?;
    let (snapshot, last_seq) = replay_snapshot(&state, session)?;
    let mut protocol = ClaudeProtocol::new(session, version, require_rc, ProtocolLimits::default())
        .map_err(|_| PROTOCOL_ERROR.to_owned())?;
    // Reconstruct local correlation state only. Replaying must never write a
    // second initialize or Remote Control request into the live conversation.
    drop(
        protocol
            .initialize()
            .map_err(|_| PROTOCOL_ERROR.to_owned())?,
    );
    let mut offset = 0;
    let mut events = Vec::new();
    let mut enabled = false;
    while offset < snapshot {
        let bytes = read_chunk(
            client,
            receipt,
            session,
            offset,
            (snapshot - offset).min(READ_LIMIT),
        )
        .await?;
        if bytes.is_empty() {
            return Err("Claude supervisor replay made no progress".into());
        }
        events.extend(ingest(&mut protocol, &bytes, |protocol| {
            if require_rc && !enabled && protocol.is_initialized() {
                drop(
                    protocol
                        .enable_remote_control(name)
                        .map_err(|_| PROTOCOL_ERROR.to_owned())?,
                );
                enabled = true;
            }
            Ok(())
        })?);
        offset += bytes.len() as u64;
    }
    finish_exited_stream(&mut protocol, state["state"].as_str() == Some("exited"))?;
    Ok(Replay {
        protocol,
        offset,
        events,
        last_seq,
        state: state["state"]
            .as_str()
            .ok_or_else(|| PROTOCOL_ERROR.to_owned())?
            .to_owned(),
    })
}

/// Follow only newly appended output, preserving partial frames and correlation
/// state. The caller owns Remote Control transmission during live initialization.
pub(super) async fn follow(
    client: &KubeClient,
    receipt: &ClaudePodReceipt,
    session: &str,
    replay: &mut Replay,
) -> Result<Vec<Value>, String> {
    let state = request(client, receipt, json!({"op":"inspect"})).await?;
    let (snapshot, last_seq) = replay_snapshot(&state, session)?;
    if snapshot < replay.offset || last_seq < replay.last_seq {
        return Err("Claude supervisor replay position regressed".into());
    }
    replay.last_seq = last_seq;
    replay.state = state["state"]
        .as_str()
        .ok_or_else(|| PROTOCOL_ERROR.to_owned())?
        .to_owned();
    let mut events = Vec::new();
    while replay.offset < snapshot {
        // A bounded final read must not consume bytes appended after inspect.
        let bytes = read_chunk(
            client,
            receipt,
            session,
            replay.offset,
            (snapshot - replay.offset).min(READ_LIMIT),
        )
        .await?;
        if bytes.is_empty() {
            return Err("Claude supervisor replay made no progress".into());
        }
        events.extend(ingest(&mut replay.protocol, &bytes, |_| Ok(()))?);
        replay.offset += bytes.len() as u64;
    }
    finish_exited_stream(&mut replay.protocol, replay.state == "exited")?;
    Ok(events)
}

// A drained child exit observed by the supervisor is EOF; an exec reconnect or the
// current end of a live spool is not. Complete terminal observations remain
// readable, while a partial final frame requires raw-preserving stop recovery.
fn finish_exited_stream(protocol: &mut ClaudeProtocol, exited: bool) -> Result<(), String> {
    if !exited {
        return Ok(());
    }
    match protocol.eof() {
        Err(ProtocolError::UnexpectedEof) => Ok(()),
        Err(ProtocolError::PartialLine) => Err("Claude exited with a partial output frame".into()),
        Err(_) => Err(PROTOCOL_ERROR.into()),
        Ok(()) => Ok(()),
    }
}

fn replay_snapshot(state: &Value, session: &str) -> Result<(u64, u64), String> {
    if session.is_empty()
        || state.get("session").and_then(Value::as_str) != Some(session)
        || !matches!(
            state.get("state").and_then(Value::as_str),
            Some("running" | "frozen" | "exited")
        )
        || state.get("uncertain").and_then(Value::as_bool) != Some(false)
    {
        return Err("Claude supervisor session is not replayable".into());
    }
    Ok((number(state, "output_bytes")?, number(state, "last_seq")?))
}

pub(super) async fn read_more(
    client: &KubeClient,
    receipt: &ClaudePodReceipt,
    session: &str,
    protocol: &mut ClaudeProtocol,
    offset: &mut u64,
) -> Result<Vec<Value>, String> {
    let bytes = read_chunk(client, receipt, session, *offset, READ_LIMIT).await?;
    let events = ingest(protocol, &bytes, |_| Ok(()))?;
    *offset += bytes.len() as u64;
    Ok(events)
}

fn number(value: &Value, field: &str) -> Result<u64, String> {
    value
        .get(field)
        .and_then(Value::as_u64)
        .ok_or_else(|| PROTOCOL_ERROR.to_owned())
}

async fn read_chunk(
    client: &KubeClient,
    receipt: &ClaudePodReceipt,
    session: &str,
    offset: u64,
    limit: u64,
) -> Result<Vec<u8>, String> {
    let response = request(
        client,
        receipt,
        json!({
            "op":"read", "session":session, "offset":offset, "limit":limit,
        }),
    )
    .await?;
    if response.get("session").and_then(Value::as_str) != Some(session) {
        return Err("Claude supervisor session changed".into());
    }
    let data = response
        .get("data")
        .and_then(Value::as_str)
        .ok_or_else(|| PROTOCOL_ERROR.to_owned())?;
    let bytes = STANDARD
        .decode(data)
        .map_err(|_| PROTOCOL_ERROR.to_owned())?;
    if bytes.len() as u64 > limit
        || offset.checked_add(bytes.len() as u64) != Some(number(&response, "next_offset")?)
    {
        return Err(PROTOCOL_ERROR.into());
    }
    Ok(bytes)
}

fn ingest(
    protocol: &mut ClaudeProtocol,
    mut bytes: &[u8],
    mut after_frame: impl FnMut(&mut ClaudeProtocol) -> Result<(), String>,
) -> Result<Vec<Value>, String> {
    let mut events = Vec::new();
    while !bytes.is_empty() {
        let consumed = protocol
            .ingest(bytes)
            .map_err(|_| PROTOCOL_ERROR.to_owned())?;
        if consumed == 0 {
            return Err(PROTOCOL_ERROR.into());
        }
        bytes = &bytes[consumed..];
        while let Some(event) = protocol.pop_event() {
            let mut value = event.event;
            value
                .as_object_mut()
                .ok_or_else(|| PROTOCOL_ERROR.to_owned())?
                .insert("driver_cursor".into(), Value::from(event.cursor));
            events.push(value);
        }
        after_frame(protocol)?;
    }
    Ok(events)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    };

    const SESSION: &str = "f439b375-bba0-436b-b264-c1278988be9b";
    #[test]
    fn only_proven_exit_finishes_a_partial_stream() {
        let mut protocol =
            ClaudeProtocol::new(SESSION, "2.1.280", false, ProtocolLimits::default()).unwrap();
        protocol.initialize().unwrap();
        assert_eq!(protocol.ingest(b"{\"type\":"), Ok(8));
        assert!(finish_exited_stream(&mut protocol, false).is_ok());
        assert!(finish_exited_stream(&mut protocol, true).is_err());
        let mut complete =
            ClaudeProtocol::new(SESSION, "2.1.280", false, ProtocolLimits::default()).unwrap();
        assert!(finish_exited_stream(&mut complete, true).is_ok());
        assert!(complete.prompt("never restart").is_err());
    }

    fn channel(
        response: Vec<u8>,
        status: Option<String>,
        exited: Arc<AtomicBool>,
    ) -> (WorkloadExecStream, tokio::task::JoinHandle<Vec<u8>>) {
        let (stdin, mut input) = tokio::io::duplex(32);
        let (stdout, mut output) = tokio::io::duplex(32);
        let (stderr, mut errors) = tokio::io::duplex(32);
        let (done, completion) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            let mut request = Vec::new();
            input.read_to_end(&mut request).await.unwrap();
            let write_output = async {
                output.write_all(&response).await.unwrap();
                output.shutdown().await.unwrap();
            };
            let write_errors = async {
                errors.write_all(&vec![b'x'; 4096]).await.unwrap();
                errors.shutdown().await.unwrap();
            };
            tokio::join!(write_output, write_errors);
            let _ = done.send(());
            request
        });
        (
            WorkloadExecStream {
                pod: "test".into(),
                stdin: Box::new(stdin),
                stdout: Box::new(stdout),
                stderr: Some(Box::new(stderr)),
                exit: Box::pin(async move {
                    completion.await.unwrap();
                    exited.store(true, Ordering::SeqCst);
                    status
                }),
            },
            server,
        )
    }

    #[tokio::test]
    async fn rpc_shuts_input_drains_both_streams_and_awaits_exit() {
        let exited = Arc::new(AtomicBool::new(false));
        let (stream, server) = channel(b"{\"ok\":true}\n".to_vec(), None, exited.clone());
        let result = tokio::time::timeout(DEADLINE, exchange(stream, b"{\"op\":\"inspect\"}\n"))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(result, json!({"ok":true}));
        assert_eq!(server.await.unwrap(), b"{\"op\":\"inspect\"}\n");
        assert!(exited.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn oversized_output_is_drained_with_exit_retained() {
        let exited = Arc::new(AtomicBool::new(false));
        let (stream, server) = channel(vec![b'x'; RPC_LIMIT + 1], None, exited.clone());
        let error = tokio::time::timeout(DEADLINE, exchange(stream, b"{}\n"))
            .await
            .unwrap()
            .unwrap_err();
        assert_eq!(error, "Claude supervisor output exceeds bound");
        server.await.unwrap();
        assert!(exited.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn command_failure_never_exposes_remote_reason() {
        let exited = Arc::new(AtomicBool::new(false));
        let (stream, server) = channel(
            b"{\"ok\":true}".to_vec(),
            Some("secret".into()),
            exited.clone(),
        );
        assert_eq!(
            exchange(stream, b"{}\n").await.unwrap_err(),
            "Claude supervisor command failed"
        );
        server.await.unwrap();
        assert!(exited.load(Ordering::SeqCst));
    }

    #[test]
    fn replay_transitions_between_adjacent_control_frames() {
        let mut protocol =
            ClaudeProtocol::new(SESSION, "2.1.280", true, ProtocolLimits::default()).unwrap();
        drop(protocol.initialize().unwrap());
        let frames = [
            json!({"type":"control_response","response":{"request_id":"odin-init-1","subtype":"success"}}),
            json!({"type":"control_response","response":{"request_id":"odin-rc-1","subtype":"success","response":{
                "session_url":"https://example.com/session", "connect_url":"https://example.com/connect",
                "environment_id":"environment", "bridge_epoch":1, "bridge_session_id":"bridge"
            }}}),
        ];
        let mut bytes = Vec::new();
        for frame in frames {
            serde_json::to_writer(&mut bytes, &frame).unwrap();
            bytes.push(b'\n');
        }
        let mut enabled = false;
        let events = ingest(&mut protocol, &bytes, |protocol| {
            if !enabled && protocol.is_initialized() {
                drop(protocol.enable_remote_control("test").unwrap());
                enabled = true;
            }
            Ok(())
        })
        .unwrap();
        assert!(protocol.is_ready());
        assert_eq!(events.len(), 2);
        assert_eq!(events[0]["driver_cursor"], 1);
        assert_eq!(events[1]["driver_cursor"], 2);
    }

    #[test]
    fn live_ingestion_retains_partial_lines_without_enabling_remote_control() {
        let mut protocol =
            ClaudeProtocol::new(SESSION, "2.1.280", true, ProtocolLimits::default()).unwrap();
        drop(protocol.initialize().unwrap());
        let bytes = b"{\"type\":\"control_response\",\"response\":{\"request_id\":\"odin-init-1\",\"subtype\":\"success\"}}\n";
        assert!(ingest(&mut protocol, &bytes[..20], |_| Ok(()))
            .unwrap()
            .is_empty());
        assert_eq!(
            ingest(&mut protocol, &bytes[20..], |_| Ok(()))
                .unwrap()
                .len(),
            1
        );
        assert!(protocol.is_initialized());
        assert!(!protocol.is_ready());
        assert!(protocol.enable_remote_control("test").is_ok());
    }

    #[tokio::test]
    async fn supervisor_rejection_is_sanitized_and_still_awaits_exit() {
        let exited = Arc::new(AtomicBool::new(false));
        let (stream, server) = channel(
            b"{\"ok\":false,\"error\":\"private remote diagnostic\"}\n".to_vec(),
            None,
            exited.clone(),
        );
        assert_eq!(
            exchange(stream, b"{}\n").await.unwrap_err(),
            "Claude supervisor request rejected"
        );
        server.await.unwrap();
        assert!(exited.load(Ordering::SeqCst));
    }

    #[test]
    fn replay_and_live_continuation_preserve_exact_events_and_prompt_routing() {
        let frames = [
            json!({"type":"control_response","response":{"request_id":"odin-init-1","subtype":"success"}}),
            json!({"type":"control_response","response":{"request_id":"odin-rc-1","subtype":"success","response":{
                "session_url":"https://example.com/session", "connect_url":"https://example.com/connect",
                "environment_id":"environment", "bridge_epoch":7, "bridge_session_id":"bridge"
            }}}),
            json!({"type":"assistant","session_id":SESSION,"message":{"content":[{"type":"text","text":"preserve me"}]}}),
        ];
        let mut bytes = Vec::new();
        for frame in &frames {
            serde_json::to_writer(&mut bytes, frame).unwrap();
            bytes.push(b'\n');
        }
        let mut protocol =
            ClaudeProtocol::new(SESSION, "2.1.280", true, ProtocolLimits::default()).unwrap();
        drop(protocol.initialize().unwrap());
        let mut enable_count = 0;
        let mut events = Vec::new();
        // Every frame, including both control replies, crosses read boundaries.
        for chunk in bytes.chunks(7) {
            events.extend(
                ingest(&mut protocol, chunk, |protocol| {
                    if enable_count == 0 && protocol.is_initialized() {
                        drop(protocol.enable_remote_control("test").unwrap());
                        enable_count += 1;
                    }
                    Ok(())
                })
                .unwrap(),
            );
        }
        assert_eq!(enable_count, 1);
        assert_eq!(events.len(), frames.len());
        for (index, original) in frames.iter().enumerate() {
            let mut expected = original.clone();
            expected
                .as_object_mut()
                .unwrap()
                .insert("driver_cursor".into(), json!(index + 1));
            assert_eq!(events[index], expected);
        }
        assert_eq!(protocol.remote_control().unwrap().bridge_epoch, 7);
        let prompt: Value = serde_json::from_slice(&protocol.prompt("continue").unwrap()).unwrap();
        assert_eq!(
            prompt,
            json!({"type":"user","message":{"role":"user","content":"continue"},
            "parent_tool_use_id":null,"session_id":"default"})
        );
        assert!(protocol.initialize().is_err());
        assert!(protocol.enable_remote_control("duplicate").is_err());

        let result =
            json!({"type":"result","session_id":SESSION,"result":"complete","is_error":false});
        let mut result_bytes = serde_json::to_vec(&result).unwrap();
        result_bytes.push(b'\n');
        let split = result_bytes.len() - 1;
        assert!(ingest(&mut protocol, &result_bytes[..split], |_| Ok(()))
            .unwrap()
            .is_empty());
        let continuation = ingest(&mut protocol, &result_bytes[split..], |_| Ok(())).unwrap();
        let mut expected = result;
        expected
            .as_object_mut()
            .unwrap()
            .insert("driver_cursor".into(), json!(4));
        assert_eq!(continuation, vec![expected]);
    }

    #[test]
    fn uncorrelated_replay_control_is_rejected_without_remote_details() {
        let mut protocol =
            ClaudeProtocol::new(SESSION, "2.1.280", true, ProtocolLimits::default()).unwrap();
        drop(protocol.initialize().unwrap());
        let error = ingest(&mut protocol,
            b"{\"type\":\"control_response\",\"response\":{\"request_id\":\"wrong-sequence\",\"subtype\":\"error\",\"error\":\"secret\"}}\n",
            |_| Ok(())).unwrap_err();
        assert_eq!(error, PROTOCOL_ERROR);
    }
}

#[cfg(test)]
mod snapshot_tests {
    use super::*;

    #[test]
    fn snapshot_requires_matching_certain_observable_session_and_numeric_positions() {
        let state = json!({"session":"session", "state":"running", "uncertain":false,
            "output_bytes":31, "last_seq":4});
        assert_eq!(replay_snapshot(&state, "session").unwrap(), (31, 4));
        assert!(replay_snapshot(&state, "other").is_err());
        assert!(replay_snapshot(&state, "").is_err());
        for (field, invalid) in [
            ("session", Value::Null),
            ("state", json!("empty")),
            ("state", json!("uncertain")),
            ("uncertain", json!(true)),
            ("uncertain", Value::Null),
            ("output_bytes", json!(-1)),
            ("last_seq", json!("4")),
        ] {
            let mut rejected = state.clone();
            rejected[field] = invalid;
            assert!(replay_snapshot(&rejected, "session").is_err());
        }
        let mut frozen = state;
        frozen["state"] = json!("frozen");
        assert_eq!(replay_snapshot(&frozen, "session").unwrap(), (31, 4));
        frozen["state"] = json!("exited");
        assert_eq!(replay_snapshot(&frozen, "session").unwrap(), (31, 4));
    }
}

#[cfg(test)]
mod launcher_tests {
    use super::*;

    #[test]
    fn supervisor_client_uses_isolated_python() {
        let launcher = client_launcher();
        assert_eq!(launcher.launcher_path, "/bin/python3");
        assert_eq!(
            launcher.arguments,
            ["-I", "/run/odin-material/supervisor.py", "client"]
        );
    }
}
