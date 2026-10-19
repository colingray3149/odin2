//! Exact identity literals inside one natural query.
//!
//! A natural question can *address* an archive record rather than describe
//! its content: the user quotes a message id, a conversation id, or a
//! timestamp verbatim and asks what that record contains. Those literals are
//! opaque — the lexical tokenizer splits them into fragments that occur in no
//! indexed body text, so they carry no retrieval signal — but they can be
//! resolved exactly against the published records' own stored identity.
//!
//! Extraction is deliberately shape-agnostic and case-preserving. A literal
//! is one whitespace-delimited run trimmed of surrounding punctuation and
//! transport brackets, at least `MIN_LITERAL_BYTES` long, and carrying at
//! least one identifier separator (`-`, `@`, `:`, `+`, `.`). Nothing is
//! lowercased and no shape is assumed: every ingest format normalizes its own
//! identity (angle brackets stripped for RFC 822 message ids, case preserved
//! for export uuids, RFC 3339 for timestamps), so only an exact comparison
//! against the stored value can decide whether a literal addresses a record.
//! Ordinary question words carry no separator and are never candidates;
//! hyphenated prose ("state-of-the-art") is a candidate that simply resolves
//! to nothing, which is a miss, never an inferred match.

/// Longest literal accepted, so a pathological run never reaches the store.
const MAX_LITERAL_BYTES: usize = 256;

/// Shortest literal accepted; below this a punctuated run is prose ("1.").
const MIN_LITERAL_BYTES: usize = 6;

/// Punctuation trimmed from either end of a run: quotation, transport
/// brackets, and sentence punctuation around a quoted literal.
const TRIM: &[char] = &[
    '"', '\'', '`', '<', '>', '(', ')', '[', ']', '{', '}', ',', ';', ':', '!', '?', '*', '.',
];

/// Separators that make a run an identifier rather than a word.
const SEPARATORS: &[char] = &['-', '@', ':', '+', '.'];

/// The distinct identity literals one query text carries, in deterministic
/// order. Empty when the query addresses nothing.
pub fn identity_literals(text: &str) -> Vec<String> {
    let mut seen = std::collections::BTreeSet::new();
    for run in text.split_whitespace() {
        let trimmed = run.trim_matches(|character| TRIM.contains(&character));
        if trimmed.len() < MIN_LITERAL_BYTES || trimmed.len() > MAX_LITERAL_BYTES {
            continue;
        }
        if !trimmed
            .chars()
            .any(|character| character.is_ascii_alphanumeric())
        {
            continue;
        }
        if !trimmed.contains(SEPARATORS) {
            continue;
        }
        seen.insert(trimmed.to_owned());
    }
    seen.into_iter().collect()
}

#[cfg(test)]
mod tests {
    use super::identity_literals;

    #[test]
    fn extraction_keeps_identity_and_case_and_drops_prose() {
        let text = "In the memory of this archive source, in the conversation titled \
             \"A fixture conversation about a typo\" (message \
             3f9c1a70-2222-4333-8444-555566667777 at 2026-01-02T03:04:05.678901Z, sent by \
             assistant), which path did that message contain? Answer with the exact path \
             from the message and name the source it came from.";
        // Extraction is deterministic (sorted), so the timestamp precedes the
        // uuid; nothing is lowercased and no prose run becomes a candidate.
        let literals = identity_literals(text);
        assert_eq!(
            literals,
            vec![
                "2026-01-02T03:04:05.678901Z".to_owned(),
                "3f9c1a70-2222-4333-8444-555566667777".to_owned(),
            ]
        );
    }

    #[test]
    fn transport_brackets_are_trimmed_but_case_is_never_lowered() {
        let literals =
            identity_literals("message <FIXTURE-Ab3D@mail.example.test>; and nothing else");
        assert_eq!(literals, vec!["FIXTURE-Ab3D@mail.example.test".to_owned()]);
    }

    #[test]
    fn prose_and_short_runs_are_not_candidates() {
        assert!(
            identity_literals("which path did that message contain, and from where? 1. 2.")
                .is_empty()
        );
        assert!(identity_literals("2,000 people").is_empty());
        assert!(identity_literals("state-of-the-art hyphenation").len() == 1);
    }
}
