//! Declared context policy and pinned token counting for `odin-brain`:
//! token counting dispatches over explicitly declared tokenizer identities
//! ([`tokenizer::ContextTokenizer`]) — the exact-byte default and the pinned
//! Qwen3-family counter; every other identity is rejected as unavailable.

pub mod budget;
pub mod tokenizer;

pub use budget::{
    resolve_context_policy, EffectiveContextPolicy, SeatContextPolicy, SliceContextPolicy,
};
pub use tokenizer::{ContextTokenizer, PinnedTokenizer, PINNED_TOKENIZER_ID, QWEN3_TOKENIZER_ID};
