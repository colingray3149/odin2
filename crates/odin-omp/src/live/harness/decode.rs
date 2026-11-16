//! Output decoders: one per declared harness output family, each turning
//! the agent's own lines into the canonical session-event frames the
//! normalizer journals (`message_end`, `tool_execution_start`/`_end`), and
//! collecting the turn's outcome (the agent's session id for resume, its
//! final answer, a failure). Unknown lines are skipped, never guessed at.

use std::collections::HashMap;

use odin_registry::HarnessOutput;
use serde_json::{json, Value};

/// What one turn's output amounted to.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Decoded {
    pub agent_session: Option<String>,
    pub final_text: Option<String>,
    pub failed: Option<String>,
    /// The provider's own usage object from the last record that carried one.
    /// Absent fields stay absent; nothing here is estimated.
    pub usage: Option<Value>,
}

pub struct OutputDecoder {
    family: HarnessOutput,
    /// Tool names are namespaced by the harness (`claude-code.bash`).
    prefix: String,
    outcome: Decoded,
    last_text: Option<String>,
    /// Claude's `tool_use` ids with the name their start frame carried, so the result names the same tool.
    tools: HashMap<String, String>,
}

pub(super) fn assistant(text: &str) -> Value {
    json!({
        "type": "message_end",
        "message": {"role": "assistant", "content": [{"type": "text", "text": text}]},
    })
}

pub(super) fn tool_start(id: &str, name: &str, args: Value) -> Value {
    json!({"type": "tool_execution_start", "toolCallId": id, "toolName": name, "args": args})
}

pub(super) fn tool_end(id: &str, name: &str, result: Value, is_error: bool) -> Value {
    json!({
        "type": "tool_execution_end",
        "toolCallId": id,
        "toolName": name,
        "result": result,
        "isError": is_error,
    })
}

/// The frame that closes a turn: a normal stop, or an error carrying its cause. The turn id is
/// left off when the emitter stamps it, and usage is the provider's own object when it reported one.
pub(super) fn agent_end(
    turn_id: Option<&str>,
    failure: Option<&str>,
    usage: Option<&Value>,
) -> Value {
    let mut frame = match failure {
        None => json!({"type": "agent_end", "stopReason": "stop"}),
        Some(reason) => json!({"type": "agent_end", "stopReason": "error", "errorMessage": reason}),
    };
    if let Some(turn_id) = turn_id {
        frame["turnId"] = json!(turn_id);
    }
    if let Some(usage) = usage {
        frame["usage"] = usage.clone();
    }
    frame
}

/// The frame that carries the turn's answer to whoever prompted it.
pub(super) fn prompt_result(turn_id: Option<&str>, text: &str) -> Value {
    let mut frame = json!({"type": "prompt_result", "text": text});
    if let Some(turn_id) = turn_id {
        frame["turnId"] = json!(turn_id);
    }
    frame
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
        Self {
            family,
            prefix: harness.to_owned(),
            outcome: Decoded::default(),
            last_text: None,
            tools: HashMap::new(),
        }
    }

    /// The provider usage the records reported, if any. `None` is no measurement.
    pub fn usage(&self) -> Option<&Value> {
        self.outcome.usage.as_ref()
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
            // Protocol families are never line-decoded here.
            HarnessOutput::OmpRpc => decoded(Vec::new(), false),
        }
    }

    /// Claude Code `stream-json` (and its transcript files, which carry the
    /// same `assistant`/`user` records).
    fn claude(&mut self, value: &Value) -> Vec<Value> {
        if let Some(session) = value.get("session_id").and_then(Value::as_str) {
            self.outcome.agent_session = Some(session.to_owned());
        }
        // Claude reports measured usage on the assistant record and again on
        // `result`. Keep the provider's object; do not fill a missing count.
        if let Some(usage) = value
            .get("usage")
            .or_else(|| value.pointer("/message/usage"))
            .filter(|usage| usage.is_object())
        {
            self.outcome.usage = Some(usage.clone());
        }
        let mut frames = Vec::new();
        match value.get("type").and_then(Value::as_str) {
            Some("assistant") => {
                let blocks = value.pointer("/message/content").and_then(Value::as_array);
                for block in blocks.into_iter().flatten() {
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
                            let name = self.tool_name(name);
                            self.tools.insert(id.to_owned(), name.clone());
                            frames.push(tool_start(
                                id,
                                &name,
                                block.get("input").cloned().unwrap_or(Value::Null),
                            ));
                        }
                        _ => {}
                    }
                }
            }
            Some("user") => {
                let blocks = value.pointer("/message/content").and_then(Value::as_array);
                for block in blocks.into_iter().flatten() {
                    if block.get("type").and_then(Value::as_str) == Some("tool_result") {
                        let id = block
                            .get("tool_use_id")
                            .and_then(Value::as_str)
                            .unwrap_or("tool");
                        let name = self
                            .tools
                            .remove(id)
                            .unwrap_or_else(|| self.tool_name("tool"));
                        frames.push(tool_end(
                            id,
                            &name,
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
        assert_eq!(
            frames[1]["toolName"], "claude-code.write",
            "the result names the tool its start named"
        );
        let outcome = decoder.finish();
        assert_eq!(outcome.agent_session.as_deref(), Some("76a0"));
        assert_eq!(outcome.final_text.as_deref(), Some("Done."));
        assert_eq!(outcome.failed, None);
    }

    /// A failed run reaches the driver as the outcome's `failed`, whichever family spoke.
    #[test]
    fn a_failed_turn_carries_its_cause_in_the_outcome() {
        let mut claude = OutputDecoder::new(HarnessOutput::ClaudeStreamJson, "claude-code");
        claude.line(r#"{"type":"result","subtype":"error_max_turns","is_error":true}"#);
        assert_eq!(
            claude.finish().failed.as_deref(),
            Some("the agent reported an error (error_max_turns)")
        );
    }
}
