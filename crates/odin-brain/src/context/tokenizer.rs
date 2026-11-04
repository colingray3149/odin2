//! Declared context token counting for context compilation.
//!
//! Counting dispatches over explicitly declared [`TokenizerId`]s and never
//! approximates: an identity without an implementation here is a typed
//! unavailable failure, never a guess.
//!
//! - [`PINNED_TOKENIZER_ID`] (`odin.tokenizer.utf8-bytes.v1`): the exact
//!   UTF-8 byte length ([`PinnedTokenizer`]). Every model token consumes at
//!   least one UTF-8 byte, so the byte length bounds any tokenizer's count
//!   from above without claiming equivalence with any provider tokenizer.
//! - [`QWEN3_TOKENIZER_ID`] (`odin.tokenizer.qwen3.v1`): the pinned
//!   Qwen3-family counter. It loads the official Qwen3 tokenizer asset
//!   embedded in this crate and applies its declared semantics — NFC
//!   normalization, byte-level BPE, and `encode_ordinary` (declared
//!   special tokens in the input are plain content, never matched).
//!
//! The qwen3 engine is parsed once per process and shared by every call.

use odin_domain::knowledge::ids::TokenizerId;

use crate::error::{BrainError, BrainResult};

/// The conservative byte-count identity every configuration keeps by
/// default: the exact UTF-8 byte-length token count.
pub const PINNED_TOKENIZER_ID: &str = "odin.tokenizer.utf8-bytes.v1";

/// The declared identity of the pinned Qwen3-family counter. Selecting it
/// charges context with exact Qwen3 tokens instead of the conservative
/// byte bound.
pub const QWEN3_TOKENIZER_ID: &str = "odin.tokenizer.qwen3.v1";

/// Pinned tokenizer identity gate plus declared-semantics counting.
pub struct PinnedTokenizer;

impl PinnedTokenizer {
    pub fn id() -> BrainResult<TokenizerId> {
        TokenizerId::new(PINNED_TOKENIZER_ID).map_err(|error| BrainError::Unavailable {
            component: "context_tokenizer",
            reason: format!("declared tokenizer id {PINNED_TOKENIZER_ID} is invalid: {error}"),
        })
    }

    /// Counts tokens per the declared pinned semantics: exactly one token
    /// per UTF-8 byte, so every byte of text — including multibyte
    /// characters — contributes one token. Empty text counts zero. This is
    /// the declared byte count of this crate, never a claim of equivalence
    /// with any provider model tokenizer.
    pub fn count_text(text: &str) -> BrainResult<u32> {
        u32::try_from(text.len()).map_err(|error| {
            BrainError::InvalidRequest(format!(
                "context text of {} bytes exceeds the pinned tokenizer counting range: {error}",
                text.len()
            ))
        })
    }
}

/// A declared context tokenizer resolved by identity. Construction is
/// deliberately private: the only way to obtain one is
/// [`ContextTokenizer::for_id`], so an unsupported declared identity can
/// never silently degrade to another counter.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ContextTokenizer(Identity);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Identity {
    /// Exact UTF-8 byte length ([`PinnedTokenizer`]).
    Bytes,
    /// Pinned Qwen3-family tokenizer ([`QWEN3_TOKENIZER_ID`]).
    Qwen3,
}

impl ContextTokenizer {
    /// Resolves a declared tokenizer identity to its counter. The
    /// conservative byte identity and the pinned qwen3 identity are
    /// supported; anything else is a typed unavailable failure — never an
    /// approximation and never an inference from a model name.
    pub fn for_id(id: &TokenizerId) -> BrainResult<Self> {
        match id.as_str() {
            PINNED_TOKENIZER_ID => Ok(Self(Identity::Bytes)),
            QWEN3_TOKENIZER_ID => Ok(Self(Identity::Qwen3)),
            _ => Err(BrainError::Unavailable {
                component: "context_tokenizer",
                reason: format!(
                    "declared tokenizer {id} has no implementation; supported identities are \
                     {PINNED_TOKENIZER_ID} and {QWEN3_TOKENIZER_ID}"
                ),
            }),
        }
    }

    pub fn id(&self) -> BrainResult<TokenizerId> {
        match self.0 {
            Identity::Bytes => PinnedTokenizer::id(),
            Identity::Qwen3 => qwen3_id(),
        }
    }

    /// Counts tokens of `text` under this counter's declared semantics.
    /// Valid text never errors short of the `u32` counting range.
    pub fn count_text(&self, text: &str) -> BrainResult<u32> {
        match self.0 {
            Identity::Bytes => PinnedTokenizer::count_text(text),
            Identity::Qwen3 => qwen3::count(text),
        }
    }

    /// Returns a UTF-8-safe (never codepoint-splitting) top prefix of
    /// `text` whose counted token total fits `max_tokens`, verified by
    /// recounting — token boundaries are never assumed to survive
    /// truncation. The prefix always starts at the text head, so the
    /// highest-ranked evidence is retained first. Empty text or
    /// `max_tokens == 0` yields `""`; a non-empty `text` yields `""` only
    /// when even its first character alone exceeds `max_tokens`.
    /// Deterministic; no maximality claim is made.
    pub fn fit_prefix<'a>(&self, text: &'a str, max_tokens: u32) -> BrainResult<&'a str> {
        match self.0 {
            Identity::Bytes => Ok(byte_fit_prefix(text, max_tokens)),
            Identity::Qwen3 => qwen3::fit_prefix(text, max_tokens),
        }
    }
}

fn qwen3_id() -> BrainResult<TokenizerId> {
    TokenizerId::new(QWEN3_TOKENIZER_ID).map_err(|error| BrainError::Unavailable {
        component: "context_tokenizer",
        reason: format!("declared tokenizer id {QWEN3_TOKENIZER_ID} is invalid: {error}"),
    })
}

/// Longest char-boundary prefix of at most `max_tokens` bytes (the byte
/// counter's token is the byte, so the token bound is a byte bound). This
/// is also the truncation primitive of a declared embedding protocol: the
/// embeddings transport prefix-truncates inputs under this same canonical
/// pinned tokenizer (`INDEX_TOKENIZER`) the chunker counts with.
pub(crate) fn byte_fit_prefix(text: &str, max_tokens: u32) -> &str {
    if max_tokens == 0 {
        return "";
    }
    let mut end = text.len().min(max_tokens as usize);
    while end > 0 && !text.is_char_boundary(end) {
        end -= 1;
    }
    &text[..end]
}

/// The HF byte-level BPE engine parses the pinned Qwen3 asset once per process.
mod qwen3 {
    use std::sync::LazyLock;

    use tokenizers::Tokenizer;

    use super::{BrainError, BrainResult};

    /// The pinned official Qwen3-family tokenizer asset (HF `tokenizer.json`
    /// format; NFC normalizer, byte-level BPE, 248,044-token vocabulary,
    /// 33 declared special tokens). Provenance, upstream identity, and
    /// redistribution facts live in `assets/qwen3.8.tokenizer.json.NOTICE`;
    /// the digests recorded there are checked by a test. Embedded at
    /// compile time: never fetched at runtime, never read from a checkout.
    const ASSET: &[u8] = include_bytes!("../../assets/qwen3.8.tokenizer.json");

    /// The shared per-process engine. The load outcome is cached too: a
    /// corrupted asset fails every call identically instead of re-parsing.
    fn engine() -> BrainResult<&'static Tokenizer> {
        static ENGINE: LazyLock<Result<Tokenizer, String>> = LazyLock::new(load);
        ENGINE.as_ref().map_err(|reason| BrainError::Unavailable {
            component: "context_tokenizer",
            reason: reason.clone(),
        })
    }

    /// Parses the embedded asset under the declared ordinary encoding
    /// semantics: `set_encode_special_tokens(true)` makes the
    /// tokenizers-0.23.2 added-vocabulary splitter skip declared special
    /// tokens (`added_vocabulary::find_matches` ignores them while the
    /// flag is set), so a special-token string inside the input is
    /// byte-level BPE'd as plain content and never resolves to its
    /// added-token id. The `false` second `encode` argument only disables
    /// template insertion around the input.
    fn load() -> Result<Tokenizer, String> {
        let mut tokenizer = Tokenizer::from_bytes(ASSET)
            .map_err(|error| format!("embedded qwen3 tokenizer asset failed to parse: {error}"))?;
        tokenizer.set_encode_special_tokens(true);
        Ok(tokenizer)
    }

    fn encode_fast(text: &str) -> BrainResult<tokenizers::Encoding> {
        engine()?
            .encode_fast(text, false)
            .map_err(|error| BrainError::Unavailable {
                component: "context_tokenizer",
                reason: format!("qwen3 tokenizer failed to encode context text: {error}"),
            })
    }

    /// Encoding with offsets; only the prefix fit needs them.
    fn encode_with_offsets(text: &str) -> BrainResult<tokenizers::Encoding> {
        engine()?
            .encode(text, false)
            .map_err(|error| BrainError::Unavailable {
                component: "context_tokenizer",
                reason: format!("qwen3 tokenizer failed to encode context text: {error}"),
            })
    }

    fn count_units(text: &str) -> BrainResult<usize> {
        Ok(encode_fast(text)?.get_ids().len())
    }

    /// Exact Qwen3 content token count of `text`.
    pub(super) fn count(text: &str) -> BrainResult<u32> {
        let units = count_units(text)?;
        u32::try_from(units).map_err(|error| {
            BrainError::InvalidRequest(format!(
                "context text of {units} tokens exceeds the qwen3 tokenizer counting range: {error}"
            ))
        })
    }

    /// A verified UTF-8-safe top prefix of `text` within `max_tokens`.
    ///
    /// Encodes once with offsets; the candidate cut is the end of the
    /// `max_tokens`-th token, stepped back proportionally while the
    /// recount overshoots (byte-prefix counts are never assumed: the
    /// splitter has look-around and merges shift at truncation
    /// boundaries). At the text head a char-boundary scan returns a
    /// fitting head prefix; `""` means the budget carries not even the
    /// first character. Deterministic; no maximality is claimed.
    pub(super) fn fit_prefix(text: &str, max_tokens: u32) -> BrainResult<&str> {
        if max_tokens == 0 || text.is_empty() {
            return Ok("");
        }
        let encoding = encode_with_offsets(text)?;
        let ids = encoding.get_ids();
        if ids.len() <= max_tokens as usize {
            return Ok(text);
        }
        let offsets = encoding.get_offsets();
        let mut k = max_tokens as usize;
        loop {
            let end = floor_char_boundary(text, offsets[k - 1].1.min(text.len()));
            if end == 0 {
                // Degenerate spans (a normalizer that deletes the head)
                // must still honor the documented contract: fall back to
                // the verified head scan; "" stays reserved for a budget
                // that cannot carry even the first character.
                return head_boundary_prefix_fit(text, max_tokens);
            }
            let count = count_units(&text[..end])?;
            if count <= max_tokens as usize {
                return Ok(&text[..end]);
            }
            if k == 1 {
                return head_boundary_prefix_fit(&text[..end], max_tokens);
            }
            k = k.saturating_sub(count - max_tokens as usize).max(1);
        }
    }

    /// A fitting head prefix of `span` at a char boundary, scanning
    /// candidates longest-first. `span` is normally the short first token
    /// span; on the degenerate-offsets fallback it is the whole text.
    fn head_boundary_prefix_fit(span: &str, max_tokens: u32) -> BrainResult<&str> {
        for end in (1..=span.len()).rev() {
            if !span.is_char_boundary(end) {
                continue;
            }
            let candidate = &span[..end];
            if count_units(candidate)? <= max_tokens as usize {
                return Ok(candidate);
            }
        }
        Ok("")
    }

    fn floor_char_boundary(text: &str, mut index: usize) -> usize {
        if index >= text.len() {
            return text.len();
        }
        while index > 0 && !text.is_char_boundary(index) {
            index -= 1;
        }
        index
    }

    /// Test-only: exact qwen3 token ids of `text`, for pinning reference
    /// vectors.
    #[cfg(test)]
    pub(super) fn encode_ids(text: &str) -> BrainResult<Vec<u32>> {
        Ok(encode_fast(text)?.get_ids().to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn both_declared_identities_dispatch_to_their_counter() {
        let bytes = ContextTokenizer::for_id(&PinnedTokenizer::id().unwrap()).unwrap();
        let qwen3 = ContextTokenizer::for_id(&TokenizerId::new(QWEN3_TOKENIZER_ID).unwrap())
            .unwrap_or_else(|error| panic!("declared qwen3 identity must resolve: {error}"));
        assert_eq!(bytes.id().unwrap(), PinnedTokenizer::id().unwrap());
        assert_eq!(qwen3.id().unwrap().as_str(), QWEN3_TOKENIZER_ID);

        // The byte counter stays byte-identical to PinnedTokenizer through
        // the dispatch.
        for text in ["", "a", "漢字漢", "✓✓", "mixed 漢 text"] {
            assert_eq!(
                bytes.count_text(text).unwrap(),
                PinnedTokenizer::count_text(text).unwrap()
            );
        }
    }

    #[test]
    fn unknown_tokenizer_identity_is_typed_rejected() {
        let foreign = TokenizerId::new("other.vendor.model").unwrap();
        assert!(matches!(
            ContextTokenizer::for_id(&foreign),
            Err(BrainError::Unavailable {
                component: "context_tokenizer",
                ..
            })
        ));
    }

    /// The reference uses the same asset with `add_special_tokens=false` and
    /// no special-token text; token IDs and counts must match exactly.
    #[test]
    fn qwen3_matches_pinned_reference_fixture() {
        let raw = include_str!("../../tests/fixtures/qwen3-reference.json");
        let fixture: serde_json::Value = serde_json::from_str(raw).expect("fixture parses");
        let cases = fixture["cases"].as_array().expect("cases array");
        assert!(!cases.is_empty());
        let qwen3 = ContextTokenizer::for_id(&TokenizerId::new(QWEN3_TOKENIZER_ID).unwrap())
            .expect("declared qwen3 identity resolves");
        for case in cases {
            let text = case["text"].as_str().expect("text");
            let want: Vec<u32> = case["ids"]
                .as_array()
                .expect("ids")
                .iter()
                .map(|v| v.as_u64().expect("id") as u32)
                .collect();
            let count = u32::try_from(case["count"].as_u64().expect("count")).expect("count");
            assert_eq!(
                count as usize,
                want.len(),
                "fixture self-consistency: {text:?}"
            );
            assert_eq!(
                qwen3::encode_ids(text).unwrap(),
                want,
                "qwen3 ids diverge from the pinned reference on {text:?}"
            );
            assert_eq!(
                qwen3.count_text(text).unwrap(),
                count,
                "qwen3 count diverges from the pinned reference on {text:?}"
            );
        }
    }

    #[test]
    fn qwen3_fit_prefix_returns_verified_char_aligned_prefixes() {
        let qwen3 = ContextTokenizer::for_id(&TokenizerId::new(QWEN3_TOKENIZER_ID).unwrap())
            .expect("declared qwen3 identity resolves");
        assert_eq!(qwen3.fit_prefix("", 8).unwrap(), "");
        assert_eq!(qwen3.fit_prefix("hello world", 0).unwrap(), "");

        let text = "hello world, this prefix fitter must verify every cut it returns 漢字 ✓";
        let total = qwen3.count_text(text).unwrap();
        // Within budget: the whole text is kept.
        assert_eq!(qwen3.fit_prefix(text, total).unwrap(), text);
        assert_eq!(qwen3.fit_prefix(text, total + 50).unwrap(), text);
        // Under budget: the prefix is codepoint-aligned, counted within
        // budget, and a strict prefix of the text.
        for max in [1u32, 2, 3, 5, 8, 13, 21, total.saturating_sub(1)] {
            let prefix = qwen3.fit_prefix(text, max).unwrap();
            assert!(text.starts_with(prefix), "result must be a prefix");
            assert!(
                text.is_char_boundary(prefix.len()),
                "prefix must end on a char boundary"
            );
            let count = qwen3.count_text(prefix).unwrap();
            assert!(
                count <= max,
                "verified prefix of {max} tokens recounted to {count}"
            );
            if max >= 1 && !text.is_empty() {
                // A non-empty budget on ASCII-leading text yields a
                // non-empty prefix.
                assert!(!prefix.is_empty(), "max {max} must fit the first token");
            }
        }
    }
}
