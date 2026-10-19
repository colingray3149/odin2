//! Output decoders: one per declared harness output family, each turning
//! the agent's own lines into the canonical session-event frames the
//! normalizer journals (`message_end`, `tool_execution_start`/`_end`), and
//! collecting the turn's outcome (the agent's session id for resume, its
//! final answer, a failure). Unknown lines are skipped, never guessed at.

use odin_registry::HarnessOutput;
use serde_json::{json, Value};

/// What one turn's output amounted to.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Decoded {
    pub agent_session: Option<String>,
    pub final_text: Option<String>,
    pub failed: Option<String>,
}

pub struct OutputDecoder {
    family: HarnessOutput,
    /// Tool names are namespaced by the harness (`claude-code.bash`).
    prefix: String,
    outcome: Decoded,
    last_text: Option<String>,
}

fn assistant(text: &str) -> Value {
    json!({
        "type": "message_end",
        "message": {"role": "assistant", "content": [{"type": "text", "text": text}]},
    })
}

fn tool_start(id: &str, name: &str, args: Value) -> Value {
    json!({"type": "tool_execution_start", "toolCallId": id, "toolName": name, "args": args})
}

fn tool_end(id: &str, name: &str, result: Value, is_error: bool) -> Value {
    json!({
        "type": "tool_execution_end",
        "toolCallId": id,
        "toolName": name,
        "result": result,
        "isError": is_error,
    })
}

/// Tool-result content as text: a string, or the text blocks of a list.
fn content_text(content: &Value) -> String {
    match content {
        Value::String(text) => text.clone(),
        Value::Array(blocks) => blocks
            .iter()
            .filter_map(|block| block.get("text").and_then(Value::as_str))
            .collect::<Vec<_>>()
            .join("\n"),
        Value::Null => String::new(),
        other => other.to_string(),
    }
}
/// Whether a transcript record ends the agent's turn. Only an assistant
/// record whose stop reason is `end_turn` does; a tool round does not.
pub fn ends_turn(record: &Value) -> bool {
    record.get("type").and_then(Value::as_str) == Some("assistant")
        && record
            .pointer("/message/stop_reason")
            .and_then(Value::as_str)
            == Some("end_turn")
}

/// Frames from one output line, plus whether that line ended the turn.
/// The flag is decided from the parse `line` already did.
pub struct DecodedLine {
    pub frames: Vec<Value>,
    pub ends_turn: bool,
}

fn decoded(frames: Vec<Value>, ends_turn: bool) -> DecodedLine {
    DecodedLine { frames, ends_turn }
}
impl OutputDecoder {
    pub fn new(family: HarnessOutput, harness: &str) -> Self {
        assert_ne!(
            family,
            HarnessOutput::Environment,
            "observation must resolve its environment output family before decoding"
        );
        Self {
            family,
            prefix: harness.to_owned(),
            outcome: Decoded::default(),
            last_text: None,
        }
    }

    fn tool_name(&self, raw: &str) -> String {
        format!("{}.{}", self.prefix, raw.to_ascii_lowercase())
    }

    /// The frames one output line yields, and whether it ended the turn.
    pub fn line(&mut self, line: &str) -> DecodedLine {
        let line = line.trim();
        if line.is_empty() {
            return decoded(Vec::new(), false);
        }
        match self.family {
            HarnessOutput::Text => {
                self.last_text = Some(match self.last_text.take() {
                    Some(previous) => format!("{previous}\n{line}"),
                    None => line.to_owned(),
                });
                decoded(
                    vec![json!({"type": "message_update", "delta": format!("{line}\n")})],
                    false,
                )
            }
            HarnessOutput::ClaudeStreamJson => match serde_json::from_str::<Value>(line) {
                Ok(value) => {
                    let ended = ends_turn(&value);
                    decoded(self.claude(&value), ended)
                }
                Err(_) => decoded(Vec::new(), false),
            },
            HarnessOutput::CodexJson => match serde_json::from_str::<Value>(line) {
                Ok(value) => decoded(self.codex(&value), false),
                Err(_) => decoded(Vec::new(), false),
            },
            // Protocol families are never line-decoded here.
            HarnessOutput::OmpRpc | HarnessOutput::Acp => decoded(Vec::new(), false),
            HarnessOutput::Environment => {
                unreachable!("environment output is resolved before decoding")
            }
        }
    }

    /// Claude Code `stream-json` (and its transcript files, which carry the
    /// same `assistant`/`user` records).
    fn claude(&mut self, value: &Value) -> Vec<Value> {
        if let Some(session) = value.get("session_id").and_then(Value::as_str) {
            self.outcome.agent_session = Some(session.to_owned());
        }
        let mut frames = Vec::new();
        match value.get("type").and_then(Value::as_str) {
            Some("assistant") => {
                let blocks = value
                    .pointer("/message/content")
                    .and_then(Value::as_array)
                    .cloned()
                    .unwrap_or_default();
                for block in blocks {
                    match block.get("type").and_then(Value::as_str) {
                        Some("text") => {
                            if let Some(text) = block.get("text").and_then(Value::as_str) {
                                if !text.trim().is_empty() {
                                    self.last_text = Some(text.to_owned());
                                    frames.push(assistant(text));
                                }
                            }
                        }
                        Some("tool_use") => {
                            let id = block.get("id").and_then(Value::as_str).unwrap_or("tool");
                            let name = block.get("name").and_then(Value::as_str).unwrap_or("tool");
                            frames.push(tool_start(
                                id,
                                &self.tool_name(name),
                                block.get("input").cloned().unwrap_or(Value::Null),
                            ));
                        }
                        _ => {}
                    }
                }
            }
            Some("user") => {
                let blocks = value
                    .pointer("/message/content")
                    .and_then(Value::as_array)
                    .cloned()
                    .unwrap_or_default();
                for block in blocks {
                    if block.get("type").and_then(Value::as_str) == Some("tool_result") {
                        let id = block
                            .get("tool_use_id")
                            .and_then(Value::as_str)
                            .unwrap_or("tool");
                        frames.push(tool_end(
                            id,
                            &self.tool_name("tool"),
                            Value::String(content_text(
                                block.get("content").unwrap_or(&Value::Null),
                            )),
                            block
                                .get("is_error")
                                .and_then(Value::as_bool)
                                .unwrap_or(false),
                        ));
                    }
                }
            }
            Some("result") => {
                if let Some(text) = value.get("result").and_then(Value::as_str) {
                    self.outcome.final_text = Some(text.to_owned());
                }
                if value.get("is_error").and_then(Value::as_bool) == Some(true) {
                    self.outcome.failed = Some(format!(
                        "the agent reported an error ({})",
                        value
                            .get("subtype")
                            .and_then(Value::as_str)
                            .unwrap_or("error")
                    ));
                }
            }
            _ => {}
        }
        frames
    }

    /// Codex `exec --json`.
    fn codex(&mut self, value: &Value) -> Vec<Value> {
        let mut frames = Vec::new();
        let item = value.get("item").cloned().unwrap_or(Value::Null);
        let id = item.get("id").and_then(Value::as_str).unwrap_or("item");
        let kind = item.get("type").and_then(Value::as_str).unwrap_or("");
        match value.get("type").and_then(Value::as_str) {
            Some("thread.started") => {
                if let Some(thread) = value.get("thread_id").and_then(Value::as_str) {
                    self.outcome.agent_session = Some(thread.to_owned());
                }
            }
            Some("item.started") => match kind {
                "command_execution" => frames.push(tool_start(
                    id,
                    &self.tool_name("shell"),
                    json!({"command": item.get("command").cloned().unwrap_or(Value::Null)}),
                )),
                "mcp_tool_call" | "web_search" => {
                    frames.push(tool_start(id, &self.tool_name(kind), item.clone()))
                }
                _ => {}
            },
            Some("item.completed") => match kind {
                "agent_message" => {
                    if let Some(text) = item.get("text").and_then(Value::as_str) {
                        self.last_text = Some(text.to_owned());
                        frames.push(assistant(text));
                    }
                }
                "command_execution" => frames.push(tool_end(
                    id,
                    &self.tool_name("shell"),
                    Value::String(
                        item.get("aggregated_output")
                            .and_then(Value::as_str)
                            .unwrap_or("")
                            .to_owned(),
                    ),
                    item.get("exit_code").and_then(Value::as_i64).unwrap_or(0) != 0,
                )),
                "file_change" => {
                    let name = self.tool_name("patch");
                    let changes = item.get("changes").cloned().unwrap_or(Value::Null);
                    frames.push(tool_start(id, &name, changes.clone()));
                    frames.push(tool_end(
                        id,
                        &name,
                        changes,
                        item.get("status").and_then(Value::as_str) == Some("failed"),
                    ));
                }
                "mcp_tool_call" | "web_search" => {
                    frames.push(tool_end(id, &self.tool_name(kind), item.clone(), false))
                }
                _ => {}
            },
            Some("turn.failed") | Some("error") => {
                let message = value
                    .pointer("/error/message")
                    .or_else(|| value.get("message"))
                    .and_then(Value::as_str)
                    .unwrap_or("the agent reported an error");
                self.outcome.failed = Some(message.to_owned());
            }
            _ => {}
        }
        frames
    }

    /// The turn's outcome; the final answer defaults to the last assistant
    /// text when the family has no explicit result record.
    pub fn finish(&mut self) -> Decoded {
        let mut outcome = std::mem::take(&mut self.outcome);
        if outcome.final_text.is_none() {
            outcome.final_text = self.last_text.take();
        }
        outcome
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Preserve the resume ID, map tool rounds to frames, and take the result as final answer.
    #[test]
    fn claude_stream_json_turn() {
        let mut decoder = OutputDecoder::new(HarnessOutput::ClaudeStreamJson, "claude-code");
        let lines = [
            r#"{"type":"system","subtype":"init","cwd":"/w","session_id":"76a0","tools":["Bash"]}"#,
            r#"{"type":"assistant","message":{"role":"assistant","content":[{"type":"tool_use","id":"t1","name":"Write","input":{"file_path":"/w/a","content":"hi"}}]},"session_id":"76a0"}"#,
            r#"{"type":"user","message":{"role":"user","content":[{"tool_use_id":"t1","type":"tool_result","content":"File created"}]},"session_id":"76a0"}"#,
            r#"{"type":"assistant","message":{"role":"assistant","content":[{"type":"text","text":"Done."}]},"session_id":"76a0"}"#,
            r#"{"type":"result","subtype":"success","is_error":false,"result":"Done.","session_id":"76a0"}"#,
        ];
        let frames: Vec<Value> = lines
            .iter()
            .flat_map(|line| decoder.line(line).frames)
            .collect();
        let kinds: Vec<&str> = frames
            .iter()
            .filter_map(|frame| frame.get("type").and_then(Value::as_str))
            .collect();
        assert_eq!(
            kinds,
            ["tool_execution_start", "tool_execution_end", "message_end"]
        );
        assert_eq!(frames[0]["toolName"], "claude-code.write");
        let outcome = decoder.finish();
        assert_eq!(outcome.agent_session.as_deref(), Some("76a0"));
        assert_eq!(outcome.final_text.as_deref(), Some("Done."));
        assert_eq!(outcome.failed, None);
    }

    /// Real Codex exec --json lines: the thread id is the resume key, a
    /// failed command is an error tool result, the last message answers.
    #[test]
    fn codex_json_turn() {
        let mut decoder = OutputDecoder::new(HarnessOutput::CodexJson, "codex");
        let lines = [
            r#"{"type":"thread.started","thread_id":"01a0"}"#,
            r#"{"type":"turn.started"}"#,
            r#"{"type":"item.started","item":{"id":"i0","type":"command_execution","command":"ls","status":"in_progress"}}"#,
            r#"{"type":"item.completed","item":{"id":"i0","type":"command_execution","command":"ls","aggregated_output":"denied","exit_code":1,"status":"failed"}}"#,
            r#"{"type":"item.completed","item":{"id":"i1","type":"agent_message","text":"Could not list."}}"#,
            r#"{"type":"turn.completed","usage":{"input_tokens":1}}"#,
        ];
        let frames: Vec<Value> = lines
            .iter()
            .flat_map(|line| decoder.line(line).frames)
            .collect();
        assert_eq!(frames.len(), 3);
        assert_eq!(frames[1]["isError"], true);
        let outcome = decoder.finish();
        assert_eq!(outcome.agent_session.as_deref(), Some("01a0"));
        assert_eq!(outcome.final_text.as_deref(), Some("Could not list."));
    }

    #[test]
    fn line_reports_end_of_turn_from_the_parse_it_already_did() {
        let mut decoder = OutputDecoder::new(HarnessOutput::ClaudeStreamJson, "claude-code");
        let done = decoder.line(
            r#"{"type":"assistant","message":{"stop_reason":"end_turn","content":[{"type":"text","text":"Done."}]}}"#,
        );
        assert!(done.ends_turn);
        assert_eq!(
            done.frames[0].get("type").and_then(Value::as_str),
            Some("message_end")
        );
        let tool = decoder.line(
            r#"{"type":"assistant","message":{"stop_reason":"tool_use","content":[{"type":"tool_use","id":"t","name":"Bash","input":{}}]}}"#,
        );
        assert!(!tool.ends_turn);
    }
}
