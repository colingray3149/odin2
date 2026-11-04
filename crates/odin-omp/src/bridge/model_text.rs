//! The text a seat's model reads for one host tool result or refusal. The
//! handler value stays whole in `details`, the evidence extractor and the
//! ledger; this projection drops the provenance the model never passes back
//! (receipt digests, ids, timelines, content hashes), so a digest is not the
//! most copyable string in its context.

use serde_json::{Map, Value};

use crate::host_tools::operations::IGNORED_FIELDS;

const MAX_HEX_CHARS: usize = 524_288;
const EVIDENCE_MARK: &str = "captured evidence blake3:";
const DIGEST_HEX: usize = 64;

pub(crate) fn model_tool_text(result: &Value) -> Result<String, serde_json::Error> {
    let Some(object) = result.as_object() else {
        return serde_json::to_string(result);
    };
    let mut visible = if object.contains_key("evidence_digest") && object.contains_key("outcome") {
        receipt_view(object)
    } else if object.contains_key("policyDigest") && object.contains_key("results") {
        search_view(object)
    } else if !object.contains_key("artifactId") && !object.contains_key("contentDigest") {
        // Nothing to strip: serialize the object the handler already owns,
        // with what the call did leading.
        return outcome_first(object);
    } else {
        let mut visible = object.clone();
        if visible.contains_key("artifactId") {
            for provenance in ["digest", "revision", "retention"] {
                visible.remove(provenance);
            }
        }
        visible.remove("contentDigest");
        visible
    };
    // What a read dropped is the model's to see in every view.
    if let Some(ignored) = object.get(IGNORED_FIELDS) {
        visible.insert(IGNORED_FIELDS.to_owned(), ignored.clone());
    }
    outcome_first(&visible)
}

/// Handler fields that state what the call did. A success's text leads with
/// the outcome ("sent", "did", the settled effect's result) instead of a
/// bare ok, the success twin of the error-prefix strip.
const OUTCOME_LEADS: [&str; 16] = [
    "did", "outcome", "result", "ack", "sentId", "opened", "saved", "status", "content", "text",
    "roots", "entries", "results", "path", "answer", "id",
];

/// Serializes an object with its outcome-bearing fields first; the rest
/// keeps the map's own order.
fn outcome_first(object: &Map<String, Value>) -> Result<String, serde_json::Error> {
    if !OUTCOME_LEADS.iter().any(|lead| object.contains_key(*lead)) {
        return serde_json::to_string(object);
    }
    let mut text = String::from("{");
    let mut first = true;
    let leads = OUTCOME_LEADS
        .iter()
        .filter_map(|lead| object.get_key_value(*lead).map(|(key, _)| key));
    let rest = object
        .keys()
        .filter(|key| !OUTCOME_LEADS.contains(&key.as_str()));
    for key in leads.chain(rest) {
        if !first {
            text.push(',');
        }
        first = false;
        text.push_str(&serde_json::to_string(key)?);
        text.push(':');
        text.push_str(&serde_json::to_string(&object[key])?);
    }
    text.push('}');
    Ok(text)
}

/// A refusal as the model reads it: the handler's own reason leading —
/// every wrapper prefix this error chain adds around it is stripped — and
/// no trailing evidence digest, which the journal row already carries.
pub(crate) fn model_error_text(detail: &str) -> String {
    let stripped = strip_wrapper_prefixes(detail);
    let mut text = String::with_capacity(stripped.len());
    let mut rest = stripped.as_str();
    while let Some(at) = rest.find(EVIDENCE_MARK) {
        let digest_end = at + EVIDENCE_MARK.len() + DIGEST_HEX;
        let is_digest = rest
            .get(at + EVIDENCE_MARK.len()..digest_end)
            .is_some_and(|hex| {
                hex.bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            });
        if !is_digest {
            text.push_str(&rest[..at + EVIDENCE_MARK.len()]);
            rest = &rest[at + EVIDENCE_MARK.len()..];
            continue;
        }
        text.push_str(rest[..at].trim_end_matches([';', ',', ' ']));
        rest = &rest[digest_end..];
    }
    text.push_str(rest);
    text
}

/// Wrapper clauses the error chain prefixes around the handler's own
/// reason. The refusal the model reads leads with what happened and the
/// fix, so these go; a message that is itself the answer (an approval
/// request, a replay note) matches none and stays whole.
const WRAPPER_PREFIXES: &[&str] = &[
    "operation authority: ",
    "effect rejected: ",
    "kernel policy pipeline: ",
    "durable ledger: ",
    "host tool ledger operation failed: ",
    "seat token verification: ",
    "published operation authority unavailable: ",
    "operation composition is invalid: ",
    "delegated session authority rejected: ",
    "session authority generation unavailable: ",
    "bridge configuration rejected: ",
    "bridge serialization failed: ",
    "bridge background task failed: ",
];

/// The `host tool `X` …: ` wrappers: the tool name is variable, the phrase
/// after it is one of these.
const HOST_TOOL_PHRASES: &[&str] = &[
    "is unavailable: ",
    "received invalid arguments: ",
    "requires an exact scope: ",
    "landed its effect but a post-effect step failed: ",
    "cannot prove its effect state: ",
    "result could not be serialized: ",
    "shared state is unavailable: ",
    "delegation rejected: ",
];

/// Strips wrapper prefixes, outermost first, until the cause leads. Bounded:
/// a real reason never nests more than a few wrappers deep.
fn strip_wrapper_prefixes(detail: &str) -> String {
    let mut text = detail.to_owned();
    for _ in 0..4 {
        let Some(stripped) = wrapper_stripped(&text) else {
            return text;
        };
        text = stripped;
    }
    text
}

fn wrapper_stripped(text: &str) -> Option<String> {
    for prefix in WRAPPER_PREFIXES {
        if let Some(rest) = text.strip_prefix(prefix) {
            return Some(rest.to_owned());
        }
    }
    let rest = text.strip_prefix("host tool `")?;
    let closing = rest.find('`')?;
    let after = rest[closing + 1..].strip_prefix(' ')?;
    let phrase = HOST_TOOL_PHRASES
        .iter()
        .find(|phrase| after.starts_with(**phrase))?;
    Some(after[phrase.len()..].to_owned())
}

/// An effect receipt keeps what the next call acts on: outcome, exit,
/// decoded output, truncation, and the capsule-relative changed paths.
fn receipt_view(receipt: &Map<String, Value>) -> Map<String, Value> {
    let mut view = Map::new();
    for key in ["outcome", "exit_code", "signal"] {
        if let Some(value) = receipt.get(key).filter(|value| !value.is_null()) {
            view.insert(key.to_owned(), value.clone());
        }
    }
    for (encoded, decoded, truncated) in [
        ("stdout_hex", "stdout", "stdout_truncated"),
        ("stderr_hex", "stderr", "stderr_truncated"),
    ] {
        if let Some(text) = receipt
            .get(encoded)
            .and_then(Value::as_str)
            .and_then(decode_hex)
        {
            view.insert(decoded.to_owned(), Value::String(text));
        }
        if receipt.get(truncated).and_then(Value::as_bool) == Some(true) {
            view.insert(truncated.to_owned(), Value::Bool(true));
        }
    }
    if let Some(changes) = receipt.get("filesystem_changes").and_then(Value::as_array) {
        let changed = changes
            .iter()
            .filter_map(|change| {
                let op = change.get("op")?.as_str()?;
                let path = change.get("path")?.as_str()?;
                let relative = path
                    .split_once("/capsule/project/")
                    .map_or(path, |(_, relative)| relative);
                Some(Value::String(format!("{op} {relative}")))
            })
            .collect();
        view.insert("changed".to_owned(), Value::Array(changed));
    }
    if let Some(unchanged) = receipt
        .get("post_world_unchanged")
        .filter(|value| value.is_boolean())
    {
        view.insert("post_world_unchanged".to_owned(), unchanged.clone());
    }
    view
}

/// A brain search keeps its serving posture (a lexical-only search says so,
/// with its reason) and its hits, already cut to handle, source, trust,
/// score and text; the policy digest and registry revision stay in `details`.
fn search_view(search: &Map<String, Value>) -> Map<String, Value> {
    ["posture", "results", "truncated"]
        .into_iter()
        .filter_map(|key| search.get(key).map(|value| (key.to_owned(), value.clone())))
        .collect()
}

fn decode_hex(raw: &str) -> Option<String> {
    if raw.len() > MAX_HEX_CHARS {
        return None;
    }
    let bytes = odin_types::hash::hex_decode(raw).ok()?;
    Some(String::from_utf8_lossy(&bytes).into_owned())
}

#[cfg(test)]
mod tests {
    use serde_json::{json, Value};

    use super::{model_error_text, model_tool_text};
    use crate::bridge::BridgeError;
    use crate::host_tools::executor::map_dispatch_error;
    use crate::host_tools::operations::HostToolOperationError;
    use crate::host_tools::HostToolError;
    use odin_kernel::OperationRejection;

    const DIGEST: &str = "blake3:00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";

    fn rendered(result: &Value) -> (String, Value) {
        let text = model_tool_text(result).unwrap();
        let value = serde_json::from_str(&text).unwrap();
        (text, value)
    }

    #[test]
    fn a_capsule_receipt_reaches_the_model_without_digests_ids_or_hex() {
        for schema in [Some("OdinEffectReceipt/v1"), None] {
            let mut receipt = json!({
                "outcome": "completed", "exit_code": 0, "signal": null,
                "stdout_hex": "68690aff", "stderr_hex": "", "stdout_bytes": 4, "stderr_bytes": 0,
                "stdout_truncated": false, "stderr_truncated": false,
                "filesystem_changes": [
                    {"op": "write", "path": "/var/lib/odin/s/capsule/project/src/main.rs"},
                    {"op": "create", "path": "notes.txt"}
                ],
                "post_world": DIGEST, "post_world_unchanged": true,
                "events": [{"name": "handler_entry", "at_ms": 1, "detail": "op-1 dispatched"}],
                "worker_stopped": true, "residual_workers": 0, "network_connections": [],
                "evidence_digest": DIGEST, "correlation_id": "c", "operation_id": "op-1",
                "capability": "capsule.eval.run", "capsule_id": "capsule:s"
            });
            if let Some(schema) = schema {
                receipt["schema"] = json!(schema);
            }
            let before = receipt.clone();
            let (text, value) = rendered(&receipt);
            assert!(!text.contains("blake3:"), "{text}");
            assert_eq!(
                value,
                json!({
                    "outcome": "completed", "exit_code": 0, "stdout": "hi\n\u{fffd}", "stderr": "",
                    "changed": ["write src/main.rs", "create notes.txt"],
                    "post_world_unchanged": true
                })
            );
            assert_eq!(
                receipt, before,
                "details and evidence keep the whole receipt"
            );
        }
    }

    #[test]
    fn a_refusal_leads_with_the_handler_reason_not_the_wrapper() {
        assert_eq!(
            model_error_text(
                "host tool `email_send` is unavailable: mail op send needs account (one of: \
                 personal, school)"
            ),
            "mail op send needs account (one of: personal, school)"
        );
        // A bad argument the executor rejected is that reason, not "unavailable".
        assert_eq!(
            model_error_text(
                "operation authority: effect rejected: host tool `media_tag` is unavailable: \
                 tag needs a title"
            ),
            "tag needs a title"
        );
        // Every bridge error's own wrapper text is on the strip list.
        for error in [
            BridgeError::Config {
                detail: "the reason".to_owned(),
            },
            BridgeError::Serialization {
                detail: "the reason".to_owned(),
            },
            BridgeError::Task("the reason".to_owned()),
        ] {
            assert_eq!(model_error_text(&error.to_string()), "the reason");
        }
        // A message that is itself the answer stays whole.
        let approval = "approval required: capability `email.send` is effect class R3";
        assert_eq!(model_error_text(approval), approval);
    }

    /// A handler's refusal travels the executor and operation authority before it reaches the
    /// model; neither its class nor the handler id may lead the text.
    #[test]
    fn a_handler_failure_through_the_executor_reaches_the_model_as_its_cause() {
        let reached = |error: HostToolError| {
            let refused = HostToolOperationError::from(OperationRejection::Executor(
                map_dispatch_error(error),
            ));
            model_error_text(&refused.to_string())
        };
        assert_eq!(
            reached(HostToolError::Unavailable {
                tool: "odin_pod_exec.run",
                reason: "web.save: https://example.test/: Error: Timed out fetching".to_owned(),
            }),
            "web.save: https://example.test/: Error: Timed out fetching"
        );
        assert_eq!(
            reached(HostToolError::Arguments {
                tool: "odin_workflow.run",
                detail: "2 titles match \"Dune\"; call again with id or year".to_owned(),
            }),
            "2 titles match \"Dune\"; call again with id or year"
        );
    }
}
