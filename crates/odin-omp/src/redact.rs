//! Line redaction shared by the seat screen and the trace export.
//!
//! Credential-shaped words are withheld. This is best effort: a secret that
//! does not match these shapes is left as written.

/// Prefixes of credential tokens that common tools print.
const TOKEN_PREFIXES: &[&str] = &[
    "sk-",
    "ghp_",
    "gho_",
    "ghs_",
    "github_pat_",
    "glpat-",
    "xoxb-",
    "xoxp-",
    "AKIA",
    "AIza",
];

/// Keys whose value is withheld, in `key=value`, `key: value` or a quoted JSON
/// `"key":`; after a key with no value a `Bearer`/`Basic` scheme word is kept
/// and its credential withheld.
const SECRET_KEYS: &[&str] = &[
    "password",
    "passwd",
    "secret",
    "token",
    "api_key",
    "apikey",
    "authorization",
];

/// A token-shaped word is withheld only when this many characters follow its prefix.
const MIN_TOKEN_TAIL: usize = 16;

const WITHHELD: &str = "[withheld]";

/// One line with its secrets withheld; `None` drops a private key's body.
pub fn redact_line(line: &str, in_key: &mut bool) -> Option<String> {
    if *in_key {
        if line.contains("-----END") {
            *in_key = false;
        }
        return None;
    }
    if line.contains("-----BEGIN") && line.contains("PRIVATE KEY") {
        *in_key = !line.contains("-----END");
        return Some("[private key withheld]".to_owned());
    }
    let mut withhold_next = false;
    let words: Vec<String> = line
        .split(' ')
        .map(|word| {
            if word.is_empty() {
                return String::new();
            }
            let bare = word.trim_matches(|ch: char| matches!(ch, '"' | '\'' | '`' | ',' | ';'));
            if withhold_next && scheme(bare) {
                return word.to_owned();
            }
            if std::mem::take(&mut withhold_next) {
                return WITHHELD.to_owned();
            }
            if TOKEN_PREFIXES.iter().any(|prefix| {
                bare.starts_with(prefix) && bare.len() >= prefix.len() + MIN_TOKEN_TAIL
            }) {
                return WITHHELD.to_owned();
            }
            if let Some(url) = url_query_redacted(word) {
                return url;
            }
            if let Some((key, value)) = bare.split_once(['=', ':']) {
                if secret_key(key) {
                    if value.is_empty() {
                        withhold_next = true;
                        return word.to_owned();
                    }
                    return format!("{key}{}{WITHHELD}", &bare[key.len()..=key.len()]);
                }
            }
            word.to_owned()
        })
        .collect();
    Some(words.join(" "))
}

/// Redacts every line of `text`, keeping private-key state across lines.
pub fn redact_text(text: &str) -> String {
    let mut in_key = false;
    let mut out = Vec::new();
    for line in text.split_inclusive('\n') {
        let (line, newline) = line
            .strip_suffix('\n')
            .map_or((line, false), |line| (line, true));
        if let Some(redacted) = redact_line(line, &mut in_key) {
            out.push(redacted);
            if newline {
                out.push("\n".to_owned());
            }
        }
    }
    out.concat()
}

/// Redacts every string leaf. Object keys are left as written.
pub fn redact_value(value: &serde_json::Value) -> serde_json::Value {
    match value {
        serde_json::Value::String(text) => serde_json::Value::String(redact_text(text)),
        serde_json::Value::Array(items) => {
            serde_json::Value::Array(items.iter().map(redact_value).collect())
        }
        serde_json::Value::Object(map) => {
            let mut out = serde_json::Map::new();
            for (key, item) in map {
                out.insert(key.clone(), redact_value(item));
            }
            serde_json::Value::Object(out)
        }
        other => other.clone(),
    }
}

/// A URL whose query carries a secret key (`?access_token=…`) with those
/// values withheld; `None` when there is nothing to withhold. The `key=value`
/// rule below would split at the scheme's `:` and never see the query.
fn url_query_redacted(word: &str) -> Option<String> {
    let (head, query) = word.split_once('?')?;
    if !head.contains("://") {
        return None;
    }
    let mut changed = false;
    let pairs: Vec<String> = query
        .split('&')
        .map(|pair| match pair.split_once('=') {
            Some((key, value)) if !value.is_empty() && secret_key(key) => {
                changed = true;
                format!("{key}={WITHHELD}")
            }
            _ => pair.to_owned(),
        })
        .collect();
    changed.then(|| format!("{head}?{}", pairs.join("&")))
}

fn scheme(word: &str) -> bool {
    word.eq_ignore_ascii_case("bearer") || word.eq_ignore_ascii_case("basic")
}

fn secret_key(key: &str) -> bool {
    let key = key.trim_end_matches(['"', '\'', '`']).to_ascii_lowercase();
    SECRET_KEYS.iter().any(|secret| key.ends_with(secret))
}

#[cfg(test)]
mod tests {
    use super::{redact_text, redact_value};
    use serde_json::json;

    #[test]
    fn a_planted_token_in_a_tool_result_is_masked() {
        let row = json!({
            "tool_results": [{
                "toolCallId": "tool-1",
                "result": "token sk-ant-api03-abcdefghijklmnopqrstuv in the result"
            }]
        });
        let redacted = redact_value(&row);
        let text = redacted["tool_results"][0]["result"].as_str().unwrap();
        assert!(text.contains("[withheld]"), "{text}");
        assert!(!text.contains("sk-ant-api03"), "{text}");
    }

    #[test]
    fn credentials_are_withheld_in_every_shape_and_prose_is_kept() {
        for (input, hidden) in [
            ("password: hunter2", "hunter2"),
            ("curl -H 'Authorization: Bearer abc123' x", "abc123"),
            (r#"{"api_key":"abc123"}"#, "abc123"),
            (r#"{"api_key": "abc123"}"#, "abc123"),
            ("{'token': 'abc123'}", "abc123"),
            ("key ghp_abcdefghijklmnopqrstuvwxyz0123 end", "abcdefghijkl"),
        ] {
            let out = redact_text(input);
            assert!(
                out.contains("[withheld]") && !out.contains(hidden),
                "{input} -> {out}"
            );
        }
        for kept in [
            "a basic check passed",
            "the bearer of news",
            "ghp_short is not a token",
        ] {
            assert_eq!(redact_text(kept), kept);
        }
    }

    #[test]
    fn a_private_key_block_is_dropped_across_lines() {
        let text = "before\n-----BEGIN RSA PRIVATE KEY-----\nMIIEabc\n-----END RSA PRIVATE KEY-----\nafter\n";
        assert_eq!(redact_text(text), "before\n[private key withheld]\nafter\n");
    }
}
