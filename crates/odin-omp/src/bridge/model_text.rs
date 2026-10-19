//! The text a seat's model reads for one host tool result or refusal. The
//! handler value stays whole in `details`, the evidence extractor and the
//! ledger; this projection drops the provenance the model never passes back
//! (receipt digests, ids, timelines, content hashes), so a digest is not the
//! most copyable string in its context.

use serde_json::{Map, Value};

const MAX_HEX_CHARS: usize = 524_288;
const EVIDENCE_MARK: &str = "captured evidence blake3:";
const DIGEST_HEX: usize = 64;

pub(crate) fn model_tool_text(result: &Value) -> Result<String, serde_json::Error> {
    let Some(object) = result.as_object() else {
        return serde_json::to_string(result);
    };
    let visible = if object.contains_key("evidence_digest") && object.contains_key("outcome") {
        receipt_view(object)
    } else if object.contains_key("policyDigest") && object.contains_key("results") {
        search_view(object)
    } else if !object.contains_key("artifactId") && !object.contains_key("contentDigest") {
        // Nothing to strip: serialize the object the handler already owns.
        return serde_json::to_string(object);
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
    serde_json::to_string(&visible)
}

/// A refusal as the model reads it: the kernel's operator wording without
/// the trailing evidence digest, which the journal row already carries.
pub(crate) fn model_error_text(detail: &str) -> String {
    let mut text = String::with_capacity(detail.len());
    let mut rest = detail;
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
/// with its reason) and each hit's `brain://` handle, source, trust, score
/// and text; revisions, content digests and the citation copy stay in
/// `details`.
fn search_view(search: &Map<String, Value>) -> Map<String, Value> {
    let mut view = Map::new();
    if let Some(posture) = search.get("posture") {
        view.insert("posture".to_owned(), posture.clone());
    }
    if let Some(results) = search.get("results").and_then(Value::as_array) {
        let hits = results
            .iter()
            .map(|result| {
                let mut hit = Map::new();
                if let Some(url) = result.get("url") {
                    hit.insert("url".to_owned(), url.clone());
                }
                for key in ["source", "trust", "score", "content"] {
                    if let Some(value) = result.get("hit").and_then(|inner| inner.get(key)) {
                        hit.insert(key.to_owned(), value.clone());
                    }
                }
                Value::Object(hit)
            })
            .collect();
        view.insert("results".to_owned(), Value::Array(hits));
    }
    if let Some(truncated) = search.get("truncated") {
        view.insert("truncated".to_owned(), truncated.clone());
    }
    view
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
    fn a_brain_search_keeps_handles_and_text_but_not_provenance() {
        let search = json!({
            "policyDigest": DIGEST, "registryRevision": DIGEST, "truncated": false,
            "posture": {"mode": "lexicalOnly", "reason": "the lane is down"},
            "results": [{"url": format!("brain://{DIGEST}"), "hit": {
                "itemId": DIGEST, "source": "archive.grok", "sourceRevision": DIGEST,
                "factId": null, "trust": "operator", "contentDigest": DIGEST,
                "content": "oolong", "score": 800000,
                "citation": {"itemId": DIGEST, "sourceRevision": DIGEST}
            }}]
        });
        let (text, value) = rendered(&search);
        assert_eq!(
            text.matches("blake3:").count(),
            1,
            "only the brain:// handle: {text}"
        );
        assert_eq!(
            value,
            json!({
                "truncated": false,
                "posture": {"mode": "lexicalOnly", "reason": "the lane is down"},
                "results": [{
                    "url": format!("brain://{DIGEST}"), "source": "archive.grok",
                    "trust": "operator", "score": 800000, "content": "oolong"
                }]
            })
        );
    }

    #[test]
    fn a_plain_object_is_serialized_unchanged() {
        let result = json!({"ok": true, "text": "kept", "n": 1});
        assert_eq!(
            model_tool_text(&result).unwrap(),
            serde_json::to_string(&result).unwrap()
        );
    }

    #[test]
    fn reads_drop_content_hashes_and_keep_handles() {
        let (_, context) =
            rendered(&json!({"path": "a.md", "content": "x", "contentDigest": DIGEST}));
        assert_eq!(context, json!({"path": "a.md", "content": "x"}));
        let (_, artifact) = rendered(&json!({
            "artifactId": DIGEST, "digest": DIGEST, "revision": 3, "retention": "durable",
            "mediaType": "text/plain", "sizeBytes": 1, "bytesBase64": "eA=="
        }));
        assert_eq!(
            artifact,
            json!({"artifactId": DIGEST, "mediaType": "text/plain", "sizeBytes": 1, "bytesBase64": "eA=="})
        );
        let (_, approval) = rendered(&json!({"approvalId": format!("approval:r3:x:{DIGEST}")}));
        assert_eq!(approval["approvalId"], format!("approval:r3:x:{DIGEST}"));
    }

    #[test]
    fn a_refusal_loses_its_evidence_digest_and_keeps_the_rest() {
        assert_eq!(
            model_error_text(&format!(
                "effect landed but stayed uncertain: `tools` is missing; captured evidence {DIGEST}"
            )),
            "effect landed but stayed uncertain: `tools` is missing"
        );
        let approval = format!("retry with approvalId approval:r3:email.send:{DIGEST}");
        assert_eq!(model_error_text(&approval), approval);
        assert_eq!(
            model_error_text("captured evidence blake3:short"),
            "captured evidence blake3:short"
        );
    }
}
