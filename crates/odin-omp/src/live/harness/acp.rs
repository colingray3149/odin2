//! The `acp` harness protocol: one Agent Client Protocol conversation per
//! turn over the agent's stdio (JSON-RPC, one message per
//! line). Odin is the client: `initialize`, then `session/load` of the
//! agent's own session when it has one and the agent can load it, else
//! `session/new`, then one `session/prompt`. The agent's `session/update`
//! notifications become the same canonical frames the line decoders yield;
//! its `session/request_permission` requests are answered from the
//! declared posture (an observed agent runs its own tools inside the
//! environment's confinement, so the first allow-once option is taken and
//! logged); client methods Odin does not offer (`fs/*`, `terminal/*`) are
//! refused, so the agent uses its own tools in its workspace.

use std::collections::BTreeMap;
use std::path::Path;

use serde_json::{json, Value};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::{ChildStdin, ChildStdout};
use tokio::sync::oneshot;

use super::decode::Decoded;

/// The ACP protocol version Odin speaks.
pub const PROTOCOL_VERSION: u64 = 1;

/// Why an ACP turn did not finish.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AcpError {
    /// The agent closed its output before the turn ended.
    Closed { during: &'static str },
    /// The agent answered a request with a JSON-RPC error.
    Refused {
        method: &'static str,
        message: String,
    },
    /// The agent's answer lacked a field the protocol requires.
    Malformed {
        method: &'static str,
        detail: String,
    },
    /// Writing to the agent failed.
    Write { detail: String },
}

impl std::fmt::Display for AcpError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Closed { during } => write!(formatter, "the agent exited during {during}"),
            Self::Refused { method, message } => {
                write!(formatter, "the agent refused {method}: {message}")
            }
            Self::Malformed { method, detail } => {
                write!(
                    formatter,
                    "the agent's {method} answer is malformed: {detail}"
                )
            }
            Self::Write { detail } => write!(formatter, "writing to the agent failed: {detail}"),
        }
    }
}

/// Frames from `session/update` notifications, plus the turn's text.
pub struct UpdateDecoder {
    prefix: String,
    tools: BTreeMap<String, String>,
    text: String,
}

impl UpdateDecoder {
    pub fn new(harness: &str) -> Self {
        Self {
            prefix: harness.to_owned(),
            tools: BTreeMap::new(),
            text: String::new(),
        }
    }

    fn tool_name(&self, update: &Value) -> String {
        let raw = update
            .get("kind")
            .and_then(Value::as_str)
            .or_else(|| update.get("title").and_then(Value::as_str))
            .unwrap_or("tool");
        format!("{}.{}", self.prefix, raw.to_ascii_lowercase())
    }

    /// The frames one `session/update` params value yields.
    pub fn update(&mut self, params: &Value) -> Vec<Value> {
        let Some(update) = params.get("update") else {
            return Vec::new();
        };
        match update.get("sessionUpdate").and_then(Value::as_str) {
            Some("agent_message_chunk") => {
                let text = update
                    .pointer("/content/text")
                    .and_then(Value::as_str)
                    .unwrap_or("");
                if text.is_empty() {
                    return Vec::new();
                }
                self.text.push_str(text);
                vec![json!({"type": "message_update", "delta": text})]
            }
            Some("tool_call") => {
                let Some(id) = update.get("toolCallId").and_then(Value::as_str) else {
                    return Vec::new();
                };
                let name = self.tool_name(update);
                self.tools.insert(id.to_owned(), name.clone());
                let args = update.get("rawInput").cloned().unwrap_or_else(
                    || json!({"title": update.get("title").cloned().unwrap_or(Value::Null)}),
                );
                let mut frames = vec![
                    json!({"type": "tool_execution_start", "toolCallId": id, "toolName": name, "args": args}),
                ];
                frames.extend(self.tool_finished(id, update));
                frames
            }
            Some("tool_call_update") => {
                let Some(id) = update.get("toolCallId").and_then(Value::as_str) else {
                    return Vec::new();
                };
                self.tool_finished(id, update)
            }
            _ => Vec::new(),
        }
    }

    /// A tool call that reached a terminal status ends exactly once.
    fn tool_finished(&mut self, id: &str, update: &Value) -> Vec<Value> {
        let status = update.get("status").and_then(Value::as_str);
        if !matches!(status, Some("completed" | "failed")) {
            return Vec::new();
        }
        let Some(name) = self.tools.remove(id) else {
            return Vec::new();
        };
        let result = update
            .get("rawOutput")
            .cloned()
            .or_else(|| {
                update
                    .get("content")
                    .and_then(Value::as_array)
                    .map(|blocks| {
                        Value::String(
                            blocks
                                .iter()
                                .filter_map(|block| {
                                    block.pointer("/content/text").and_then(Value::as_str)
                                })
                                .collect::<Vec<_>>()
                                .join("\n"),
                        )
                    })
            })
            .unwrap_or(Value::Null);
        vec![json!({
            "type": "tool_execution_end",
            "toolCallId": id,
            "toolName": name,
            "result": result,
            "isError": status == Some("failed"),
        })]
    }

    /// The text the agent said this turn; cleared for the next message.
    pub fn take_text(&mut self) -> String {
        std::mem::take(&mut self.text)
    }
}

/// The answer to one `session/request_permission`: the first allow-once
/// option (else allow-always), never a reject; cancelled when the agent
/// offered no allow option.
pub fn permission_outcome(params: &Value) -> (Value, String) {
    let options = params
        .get("options")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let pick = |kind: &str| {
        options
            .iter()
            .find(|option| option.get("kind").and_then(Value::as_str) == Some(kind))
            .and_then(|option| option.get("optionId").and_then(Value::as_str))
            .map(str::to_owned)
    };
    match pick("allow_once").or_else(|| pick("allow_always")) {
        Some(option) => (
            json!({"outcome": {"outcome": "selected", "optionId": option}}),
            option,
        ),
        None => (
            json!({"outcome": {"outcome": "cancelled"}}),
            "cancelled".to_owned(),
        ),
    }
}

/// One ACP turn's inputs.
pub struct AcpTurn<'a> {
    pub session: String,
    pub harness: &'a str,
    pub workspace: &'a Path,
    pub agent_session: Option<String>,
    pub brief: Option<&'a str>,
    pub prompt: String,
    /// The session's MCP servers (Odin's kernel bridge), offered when the
    /// agent says it speaks MCP over HTTP.
    pub mcp_servers: Vec<Value>,
}

/// The client side of one turn's conversation.
struct Client {
    stdin: ChildStdin,
    lines: tokio::io::Lines<BufReader<ChildStdout>>,
    next_id: u64,
}

impl Client {
    async fn send(&mut self, message: Value) -> Result<(), AcpError> {
        let mut line = message.to_string();
        line.push('\n');
        self.stdin
            .write_all(line.as_bytes())
            .await
            .map_err(|error| AcpError::Write {
                detail: error.to_string(),
            })?;
        self.stdin.flush().await.map_err(|error| AcpError::Write {
            detail: error.to_string(),
        })
    }

    async fn request(&mut self, method: &str, params: Value) -> Result<u64, AcpError> {
        self.next_id += 1;
        let id = self.next_id;
        self.send(json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params}))
            .await?;
        Ok(id)
    }
}

/// What the turn's message loop saw.
enum Event {
    /// The response to the awaited request.
    Answer(Result<Value, String>),
    /// The agent's output ended.
    Closed,
    /// Odin stopped the turn.
    Stopped,
}

/// Runs one turn: emits frames through `emit`, returns the outcome and
/// whether it was stopped. `stop` fires when Odin stops the turn; a stop
/// sends `session/cancel` and returns at once (the caller kills the agent).
pub async fn converse(
    stdin: ChildStdin,
    stdout: ChildStdout,
    turn: AcpTurn<'_>,
    stop: &mut oneshot::Receiver<()>,
    emit: &(dyn Fn(Value) + Send + Sync),
) -> (Decoded, bool) {
    let mut client = Client {
        stdin,
        lines: BufReader::new(stdout).lines(),
        next_id: 0,
    };
    let mut decoder = UpdateDecoder::new(turn.harness);
    let mut outcome = Decoded::default();
    let result = run_turn(&mut client, &turn, &mut decoder, &mut outcome, stop, emit).await;
    let stopped = matches!(result, Ok(Event::Stopped));
    match result {
        Ok(Event::Answer(Ok(answer))) => {
            let reason = answer
                .get("stopReason")
                .and_then(Value::as_str)
                .unwrap_or("end_turn")
                .to_owned();
            if reason != "end_turn" && reason != "cancelled" {
                outcome.failed = Some(format!("the agent stopped its turn: {reason}"));
            }
            tracing::info!(
                "odind: harness acp turn_end session={} harness={} stop_reason={reason}",
                turn.session,
                turn.harness
            );
        }
        Ok(Event::Answer(Err(message))) => {
            outcome.failed = Some(
                AcpError::Refused {
                    method: "session/prompt",
                    message,
                }
                .to_string(),
            );
        }
        Ok(Event::Closed) => {
            outcome.failed = Some(
                AcpError::Closed {
                    during: "the prompt",
                }
                .to_string(),
            );
        }
        Ok(Event::Stopped) => {}
        Err(error) => {
            tracing::error!(
                "odind: harness acp failed session={} harness={} error=\"{error}\"",
                turn.session,
                turn.harness
            );
            outcome.failed = Some(error.to_string());
        }
    }
    let text = decoder.take_text();
    if !text.trim().is_empty() {
        emit(json!({
            "type": "message_end",
            "message": {"role": "assistant", "content": [{"type": "text", "text": text}]},
        }));
        outcome.final_text = Some(text);
    }
    // Closing stdin ends the agent's conversation; the caller reaps it.
    drop(client);
    (outcome, stopped)
}

async fn run_turn(
    client: &mut Client,
    turn: &AcpTurn<'_>,
    decoder: &mut UpdateDecoder,
    outcome: &mut Decoded,
    stop: &mut oneshot::Receiver<()>,
    emit: &(dyn Fn(Value) + Send + Sync),
) -> Result<Event, AcpError> {
    let id = client
        .request(
            "initialize",
            json!({
                "protocolVersion": PROTOCOL_VERSION,
                "clientCapabilities": {
                    "fs": {"readTextFile": false, "writeTextFile": false},
                    "terminal": false,
                },
            }),
        )
        .await?;
    let init = answer(
        client,
        id,
        "initialize",
        turn,
        decoder,
        stop,
        &|_: Value| {},
    )
    .await?;
    let init = match init {
        Event::Answer(Ok(init)) => init,
        Event::Answer(Err(message)) => {
            return Err(AcpError::Refused {
                method: "initialize",
                message,
            })
        }
        other => return Ok(other),
    };
    let can_load = init
        .pointer("/agentCapabilities/loadSession")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let speaks_http = init
        .pointer("/agentCapabilities/mcpCapabilities/http")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let mcp_servers = if speaks_http || turn.mcp_servers.is_empty() {
        Value::Array(turn.mcp_servers.clone())
    } else {
        tracing::warn!(
            "odind: mcp skipped session={} harness={} reason=agent_lacks_http_mcp",
            turn.session,
            turn.harness
        );
        json!([])
    };
    let cwd = turn.workspace.display().to_string();
    let mut session = None;
    if let (Some(previous), true) = (&turn.agent_session, can_load) {
        let id = client
            .request(
                "session/load",
                json!({"sessionId": previous, "cwd": cwd, "mcpServers": mcp_servers}),
            )
            .await?;
        // The agent replays the conversation as updates: not this turn's.
        match answer(
            client,
            id,
            "session/load",
            turn,
            decoder,
            stop,
            &|_: Value| {},
        )
        .await?
        {
            Event::Answer(Ok(_)) => session = Some(previous.clone()),
            Event::Answer(Err(message)) => tracing::warn!(
                "odind: harness acp load-refused session={} harness={} agent_session={previous} \
                 error=\"{message}\"; starting a new agent session",
                turn.session,
                turn.harness
            ),
            other => return Ok(other),
        }
        decoder.take_text();
    }
    let fresh = session.is_none();
    let session = match session {
        Some(session) => session,
        None => {
            let id = client
                .request(
                    "session/new",
                    json!({"cwd": cwd, "mcpServers": mcp_servers}),
                )
                .await?;
            match answer(
                client,
                id,
                "session/new",
                turn,
                decoder,
                stop,
                &|_: Value| {},
            )
            .await?
            {
                Event::Answer(Ok(created)) => created
                    .get("sessionId")
                    .and_then(Value::as_str)
                    .map(str::to_owned)
                    .ok_or(AcpError::Malformed {
                        method: "session/new",
                        detail: "no sessionId".to_owned(),
                    })?,
                Event::Answer(Err(message)) => {
                    return Err(AcpError::Refused {
                        method: "session/new",
                        message,
                    })
                }
                other => return Ok(other),
            }
        }
    };
    outcome.agent_session = Some(session.clone());
    tracing::info!(
        "odind: harness acp session session={} harness={} agent_session={session} \
         loaded={} load_supported={can_load}",
        turn.session,
        turn.harness,
        !fresh
    );
    let text = match (turn.brief, fresh) {
        (Some(brief), true) => format!("{}\n\n{}", brief.trim(), turn.prompt),
        _ => turn.prompt.clone(),
    };
    let id = client
        .request(
            "session/prompt",
            json!({"sessionId": session, "prompt": [{"type": "text", "text": text}]}),
        )
        .await?;
    let event = answer(client, id, "session/prompt", turn, decoder, stop, emit).await?;
    if matches!(event, Event::Stopped) {
        // Best effort: the agent is killed right after.
        let _ = client
            .send(json!({"jsonrpc": "2.0", "method": "session/cancel", "params": {"sessionId": session}}))
            .await;
    }
    Ok(event)
}

/// Reads messages until the response to `id`, serving the agent's own
/// requests and turning its updates into frames meanwhile.
async fn answer(
    client: &mut Client,
    id: u64,
    method: &'static str,
    turn: &AcpTurn<'_>,
    decoder: &mut UpdateDecoder,
    stop: &mut oneshot::Receiver<()>,
    emit: &(dyn Fn(Value) + Send + Sync),
) -> Result<Event, AcpError> {
    loop {
        let line = tokio::select! {
            line = client.lines.next_line() => line,
            _ = &mut *stop => return Ok(Event::Stopped),
        };
        let line = match line {
            Ok(Some(line)) => line,
            Ok(None) | Err(_) => {
                return if method == "session/prompt" {
                    Ok(Event::Closed)
                } else {
                    Err(AcpError::Closed { during: method })
                }
            }
        };
        let Ok(message) = serde_json::from_str::<Value>(line.trim()) else {
            continue;
        };
        let incoming = message.get("method").and_then(Value::as_str);
        match (message.get("id"), incoming) {
            // The agent's request to the client.
            (Some(request), Some(incoming)) => {
                let reply = if incoming == "session/request_permission" {
                    let params = message.get("params").cloned().unwrap_or(Value::Null);
                    let (result, option) = permission_outcome(&params);
                    let tool = params
                        .pointer("/toolCall/title")
                        .and_then(Value::as_str)
                        .unwrap_or("?");
                    tracing::info!(
                        "odind: harness acp permission session={} harness={} tool={tool} \
                         option={option} governance=observed",
                        turn.session,
                        turn.harness
                    );
                    json!({"jsonrpc": "2.0", "id": request, "result": result})
                } else {
                    json!({"jsonrpc": "2.0", "id": request, "error": {
                        "code": -32601,
                        "message": format!("{incoming} is not offered by this client"),
                    }})
                };
                client.send(reply).await?;
            }
            (None, Some("session/update")) => {
                if let Some(params) = message.get("params") {
                    for frame in decoder.update(params) {
                        emit(frame);
                    }
                }
            }
            (Some(answered), None) if answered.as_u64() == Some(id) => {
                return Ok(Event::Answer(match message.get("error") {
                    Some(error) => Err(error
                        .get("message")
                        .and_then(Value::as_str)
                        .unwrap_or("unknown error")
                        .to_owned()),
                    None => Ok(message.get("result").cloned().unwrap_or(Value::Null)),
                }));
            }
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// claude-agent-acp's update shapes: a text chunk is a delta, a tool
    /// call starts once and ends once at its terminal status.
    #[test]
    fn updates_become_canonical_frames() {
        let mut decoder = UpdateDecoder::new("fixture-acp");
        let frames: Vec<Value> = [
            json!({"sessionId": "s", "update": {"sessionUpdate": "agent_message_chunk", "content": {"type": "text", "text": "Looking."}}}),
            json!({"sessionId": "s", "update": {"sessionUpdate": "tool_call", "toolCallId": "t1", "title": "ls", "kind": "execute", "status": "pending", "rawInput": {"command": "ls"}}}),
            json!({"sessionId": "s", "update": {"sessionUpdate": "tool_call_update", "toolCallId": "t1", "status": "in_progress"}}),
            json!({"sessionId": "s", "update": {"sessionUpdate": "tool_call_update", "toolCallId": "t1", "status": "completed", "content": [{"type": "content", "content": {"type": "text", "text": "a.txt"}}]}}),
            json!({"sessionId": "s", "update": {"sessionUpdate": "tool_call_update", "toolCallId": "t1", "status": "completed"}}),
            json!({"sessionId": "s", "update": {"sessionUpdate": "plan", "entries": []}}),
        ]
        .iter()
        .flat_map(|params| decoder.update(params))
        .collect();
        let kinds: Vec<&str> = frames
            .iter()
            .filter_map(|frame| frame.get("type").and_then(Value::as_str))
            .collect();
        assert_eq!(
            kinds,
            [
                "message_update",
                "tool_execution_start",
                "tool_execution_end"
            ]
        );
        assert_eq!(frames[1]["toolName"], "fixture-acp.execute");
        assert_eq!(frames[2]["result"], "a.txt");
        assert_eq!(frames[2]["isError"], false);
        assert_eq!(decoder.take_text(), "Looking.");
    }

    /// An observed agent's permission request takes allow-once, never a
    /// reject; with no allow option it is cancelled, not guessed.
    #[test]
    fn permission_takes_allow_once_or_cancels() {
        let offered = json!({"options": [
            {"optionId": "always", "kind": "allow_always", "name": "Always"},
            {"optionId": "once", "kind": "allow_once", "name": "Allow"},
            {"optionId": "no", "kind": "reject_once", "name": "Reject"},
        ]});
        let (result, option) = permission_outcome(&offered);
        assert_eq!(option, "once");
        assert_eq!(result["outcome"]["optionId"], "once");
        let rejects_only = json!({"options": [{"optionId": "no", "kind": "reject_once"}]});
        let (result, option) = permission_outcome(&rejects_only);
        assert_eq!(option, "cancelled");
        assert_eq!(result["outcome"]["outcome"], "cancelled");
    }

    /// A whole turn against a scripted agent (fixed request ids 1..3): the
    /// brief leads a new session, a permission request is answered
    /// allow-once, updates stream as frames, the session id is kept.
    #[tokio::test]
    async fn one_turn_over_stdio() {
        let script = r#"read -r a; echo '{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":1,"agentCapabilities":{"loadSession":true}}}'
read -r b; echo '{"jsonrpc":"2.0","id":2,"result":{"sessionId":"agent-7"}}'
read -r c; case "$c" in *BRIEF*hello*) ;; *) echo "bad prompt: $c" >&2; exit 3;; esac
echo '{"jsonrpc":"2.0","id":"p1","method":"session/request_permission","params":{"sessionId":"agent-7","toolCall":{"title":"edit"},"options":[{"optionId":"ok","kind":"allow_once"},{"optionId":"no","kind":"reject_once"}]}}'
read -r d; case "$d" in *'"optionId":"ok"'*) ;; *) echo "bad permission reply: $d" >&2; exit 4;; esac
echo '{"jsonrpc":"2.0","method":"session/update","params":{"sessionId":"agent-7","update":{"sessionUpdate":"agent_message_chunk","content":{"type":"text","text":"Done."}}}}'
echo '{"jsonrpc":"2.0","id":3,"result":{"stopReason":"end_turn"}}'
"#;
        let mut child = tokio::process::Command::new("sh")
            .args(["-c", script])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .expect("sh runs");
        let (stdin, stdout) = (child.stdin.take().unwrap(), child.stdout.take().unwrap());
        let frames = std::sync::Mutex::new(Vec::new());
        let emit = |frame: Value| frames.lock().unwrap().push(frame);
        let (_stop_tx, mut stop) = oneshot::channel();
        let turn = AcpTurn {
            session: "s".to_owned(),
            harness: "fixture-acp",
            workspace: Path::new("/tmp"),
            agent_session: None,
            brief: Some("BRIEF"),
            prompt: "hello".to_owned(),
            mcp_servers: Vec::new(),
        };
        let (outcome, stopped) = converse(stdin, stdout, turn, &mut stop, &emit).await;
        assert!(!stopped);
        assert_eq!(outcome.failed, None);
        assert_eq!(outcome.agent_session.as_deref(), Some("agent-7"));
        assert_eq!(outcome.final_text.as_deref(), Some("Done."));
        let kinds: Vec<String> = frames
            .lock()
            .unwrap()
            .iter()
            .filter_map(|frame| frame.get("type").and_then(Value::as_str).map(str::to_owned))
            .collect();
        assert_eq!(kinds, ["message_update", "message_end"]);
        assert!(child.wait().await.unwrap().success());
    }

    /// An agent that speaks MCP over HTTP is handed Odin's kernel bridge in
    /// `session/new`; one that does not gets none (an unusable server would
    /// fail its session).
    #[tokio::test]
    async fn the_kernel_bridge_rides_session_new_when_the_agent_speaks_http() {
        async fn new_session_params(http: bool) -> Value {
            let script = format!(
                r#"read -r a; echo '{{"jsonrpc":"2.0","id":1,"result":{{"protocolVersion":1,"agentCapabilities":{{"mcpCapabilities":{{"http":{http}}}}}}}}}'
read -r b; printf '%s\n' "$b" >&2; echo '{{"jsonrpc":"2.0","id":2,"result":{{"sessionId":"agent-8"}}}}'
read -r c; echo '{{"jsonrpc":"2.0","id":3,"result":{{"stopReason":"end_turn"}}}}'
"#
            );
            let mut child = tokio::process::Command::new("sh")
                .args(["-c", &script])
                .stdin(std::process::Stdio::piped())
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped())
                .kill_on_drop(true)
                .spawn()
                .expect("sh runs");
            let (stdin, stdout) = (child.stdin.take().unwrap(), child.stdout.take().unwrap());
            let (_stop_tx, mut stop) = oneshot::channel();
            let endpoint = crate::live::kernel_mcp::McpEndpoint {
                url: "http://127.0.0.1:18430/mcp/s".to_owned(),
                bearer: "cd".repeat(32),
            };
            let turn = AcpTurn {
                session: "s".to_owned(),
                harness: "fixture-acp",
                workspace: Path::new("/tmp"),
                agent_session: None,
                brief: None,
                prompt: "hello".to_owned(),
                mcp_servers: vec![endpoint.acp_server()],
            };
            let (outcome, _) = converse(stdin, stdout, turn, &mut stop, &|_: Value| {}).await;
            assert_eq!(outcome.failed, None);
            let output = child.wait_with_output().await.expect("agent output");
            let line = String::from_utf8(output.stderr).expect("utf8");
            let request: Value = serde_json::from_str(line.trim()).expect("session/new line");
            assert_eq!(request["method"], "session/new");
            request["params"].clone()
        }
        let offered = new_session_params(true).await;
        assert_eq!(offered["mcpServers"][0]["name"], "odin");
        assert_eq!(offered["mcpServers"][0]["type"], "http");
        assert_eq!(new_session_params(false).await["mcpServers"], json!([]));
    }

    /// An agent that exits mid-prompt is a named failure, not a hang.
    #[tokio::test]
    async fn an_agent_exiting_mid_turn_fails_the_turn() {
        let script = r#"read -r a; echo '{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":1}}'
read -r b; echo '{"jsonrpc":"2.0","id":2,"result":{"sessionId":"x"}}'
read -r c; exit 0
"#;
        let mut child = tokio::process::Command::new("sh")
            .args(["-c", script])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .expect("sh runs");
        let (stdin, stdout) = (child.stdin.take().unwrap(), child.stdout.take().unwrap());
        let (_stop_tx, mut stop) = oneshot::channel();
        let turn = AcpTurn {
            session: "s".to_owned(),
            harness: "fixture-acp",
            workspace: Path::new("/tmp"),
            agent_session: Some("old".to_owned()),
            mcp_servers: Vec::new(),
            brief: None,
            prompt: "hi".to_owned(),
        };
        let (outcome, _) = converse(stdin, stdout, turn, &mut stop, &|_: Value| {}).await;
        assert_eq!(
            outcome.failed.as_deref(),
            Some("the agent exited during the prompt")
        );
    }
}
