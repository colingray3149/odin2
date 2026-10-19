//! Cases 18-20: local slash commands, layered RPC configuration, and bounded
//! stdin-EOF shutdown against the pinned OMP child.

use std::fs;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use serde_json::{json, Value};

use crate::frames::DecodedRpcFrame;
use crate::probe::{
    CaseContext, CaseEvidence, CaseFailure, CaseOutcome, CleanupReceipt, ConformanceCase,
    ConformanceCaseId, RawRpcDriver, DEFAULT_MODEL_SELECTOR, FIXTURE_COMMAND,
    MAX_EVIDENCE_ARTIFACT_BYTES,
};
use crate::process::{OmpExitRecord, OmpLifecycleState, OmpProcessSpec};

/// Case 18 — pinned command-API discovery plus local slash-command result
/// visibility and completion semantics.
pub const SLASH_COMMAND_RESULT: ConformanceCaseId = ConformanceCaseId::new(18);

/// Case 19 — RPC configuration against isolated user/project/extra config,
/// including defaults, resets, and ignored keys.
pub const RPC_CONFIGURATION: ConformanceCaseId = ConformanceCaseId::new(19);

/// Case 20 — close stdin and verify bounded drain, request cancellation,
/// session disposal, and exit status.
pub const STDIN_CLOSE_SHUTDOWN: ConformanceCaseId = ConformanceCaseId::new(20);

mod config;
mod shared;
mod shutdown;
mod slash;

pub fn cases() -> Vec<Arc<dyn ConformanceCase>> {
    vec![
        Arc::new(slash::SlashCommandCase),
        Arc::new(config::RpcConfigurationCase),
        Arc::new(shutdown::StdinCloseShutdownCase),
    ]
}
