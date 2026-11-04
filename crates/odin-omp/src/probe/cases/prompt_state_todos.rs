//! Case module `prompt_state_todos` — prompt correlation, state queries, and
//! todo synchronization.
//!
//! Owns cases 3, 4, and 5 of the frozen conformance suite. The deterministic
//! model behavior behind
//! these cases is driven by the `odin-mock` provider fixture directives
//! (see `fixtures/mock-provider.ts`).

use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::frames::DecodedRpcFrame;
use crate::probe::{
    CaseContext, CaseEvidence, CaseFailure, CaseOutcome, CleanupReceipt, ConformanceCase,
    ConformanceCaseId, RawRpcDriver, DEFAULT_MODEL_SELECTOR,
};

/// Case 3 — send a prompt; correlate the immediate response, `prompt_result`
/// where applicable, local `command_output`, and streamed lifecycle events.
pub const PROMPT_CORRELATION: ConformanceCaseId = ConformanceCaseId::new(3);

/// Case 4 — query state before, during, and after a turn.
pub const STATE_ACROSS_TURN: ConformanceCaseId = ConformanceCaseId::new(4);

/// Case 5 — seed or update todos and observe the normalized state/events.
pub const TODO_SEED_UPDATE: ConformanceCaseId = ConformanceCaseId::new(5);

mod prompt;
mod shared;
mod state;
mod todos;

pub fn cases() -> Vec<Arc<dyn ConformanceCase>> {
    vec![
        Arc::new(prompt::PromptCorrelationCase),
        Arc::new(state::StateAcrossTurnCase),
        Arc::new(todos::TodoSeedUpdateCase),
    ]
}
