#![forbid(unsafe_code)]
#![deny(dead_code)]

//! `odin-omp`: the supervised, journaled RPC bridge over the pinned OMP
//! harness (`omp --mode rpc` @ `eab72e8`). [`process`] owns exactly one
//! child and the bounded framing; [`bridge`] owns scope-bound commands, host
//! side channels, checkpoints, and recovery; [`host_tools`] and [`uri`] are
//! the six model-visible tools and seven scope-enforced schemes; [`probe`]
//! is the conformance harness.

pub mod bridge;
pub mod frames;
pub mod host_tools;
pub mod live;
pub mod probe;
pub mod process;
#[cfg(test)]
mod test_support;
pub mod uri;

/// The per-session model-gateway tag prefix: every live session tags its
/// gateway requests `session:<session id>` beside `seat:<seat>`, so the
/// kernel can read which gateway lane really served a worker.
pub const SESSION_SPEND_TAG_PREFIX: &str = "session:";

/// Every models document a session runs with names this as the gateway
/// provider's `x-litellm-tags` header value; OMP resolves a header value
/// from the environment first, so every request a session sends is tagged
/// and LiteLLM aggregates spend per tag.
pub const SPEND_TAG_ENV: &str = "ODIN_SPEND_TAG";
pub const SPEND_TAG_HEADER: &str = "x-litellm-tags";
