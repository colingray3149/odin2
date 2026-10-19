//! Case module `controls_model` — turn controls and model selection.
//!
//! Owns cases 6 through 10 of the frozen conformance suite. Mid-turn windows
//! are created with the
//! `odin-mock:delay <ms> <text>` fixture directive, whose scripted delay
//! honors the pinned abort signal.

use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use serde_json::{json, Value};
use tokio::time;

use crate::frames::DecodedRpcFrame;
use crate::probe::{
    CaseContext, CaseEvidence, CaseFailure, CaseOutcome, CleanupOutcome, CleanupReceipt,
    ConformanceCase, ConformanceCaseId, RawRpcDriver, DEFAULT_MODEL_SELECTOR, FIXTURE_MODEL_A,
    FIXTURE_MODEL_B, FIXTURE_PROVIDER,
};

/// Case 6 — steer while the model is working.
pub const STEER_DURING_TURN: ConformanceCaseId = ConformanceCaseId::new(6);

/// Case 7 — queue a follow-up.
pub const FOLLOW_UP_QUEUE: ConformanceCaseId = ConformanceCaseId::new(7);

/// Case 8 — abort a normal provider call.
pub const ABORT_PROVIDER_CALL: ConformanceCaseId = ConformanceCaseId::new(8);

/// Case 9 — abort or recover during compaction and a background local command.
pub const ABORT_COMPACTION_AND_BASH: ConformanceCaseId = ConformanceCaseId::new(9);

/// Case 10 — change model and observe the effective model. The fixture
/// registers `mock-a` and `mock-b` on the `odin-mock` provider for exactly
/// this switch.
pub const SET_MODEL_OBSERVATION: ConformanceCaseId = ConformanceCaseId::new(10);

mod abort_compaction_bash;
mod abort_provider;
mod follow_up;
mod set_model;
mod shared;
mod steer;

/// The module's five fixed registration slots.
pub fn cases() -> Vec<Arc<dyn ConformanceCase>> {
    vec![
        Arc::new(steer::SteerDuringTurn),
        Arc::new(follow_up::FollowUpQueue),
        Arc::new(abort_provider::AbortProviderCall),
        Arc::new(abort_compaction_bash::AbortCompactionAndBash),
        Arc::new(set_model::SetModelObservation),
    ]
}
