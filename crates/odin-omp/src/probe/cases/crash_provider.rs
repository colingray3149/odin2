//! Case module `crash_provider` — process death and provider failure.
//!
//! Owns cases 16 and 17 of the frozen conformance suite: every durable
//! command crash window is
//! recovered without replaying an ambiguous effect, and unavailable
//! provider/model failures exercise OMP's configured retry/fallback lifecycle.

mod process_kill;
mod provider_fallback;

use std::sync::Arc;
use std::time::Duration;

use serde_json::Value;

use crate::probe::{
    CaseEvidence, CaseFailure, CaseOutcome, CaseStatus, CleanupReceipt, ConformanceCase,
    ConformanceCaseId,
};

use self::process_kill::ProcessKillRecovery;
use self::provider_fallback::ProviderUnavailableFallback;

pub const PROCESS_KILL_RECOVERY: ConformanceCaseId = ConformanceCaseId::new(16);
pub const PROVIDER_UNAVAILABLE_FALLBACK: ConformanceCaseId = ConformanceCaseId::new(17);

const CASE_DEADLINE: Duration = Duration::from_secs(120);

pub fn cases() -> Vec<Arc<dyn ConformanceCase>> {
    vec![
        Arc::new(ProcessKillRecovery),
        Arc::new(ProviderUnavailableFallback),
    ]
}

fn append_raw(output: &mut Vec<u8>, bytes: &[u8]) {
    output.extend_from_slice(bytes);
    if !output.ends_with(b"\n") {
        output.push(b'\n');
    }
}

fn json_evidence(kind: &'static str, label: &'static str, value: &Value) -> CaseEvidence {
    CaseEvidence {
        kind,
        label: label.to_owned(),
        bytes: serde_json::to_vec_pretty(value).expect("JSON values always serialize"),
    }
}

fn finish_outcome(
    summary: &'static str,
    mut failures: Vec<CaseFailure>,
    evidence: Vec<CaseEvidence>,
    cleanup: CleanupReceipt,
) -> CaseOutcome {
    if evidence.is_empty() || evidence.iter().any(|item| item.bytes.is_empty()) {
        failures.push(CaseFailure {
            check: ("required_evidence").to_owned(),
            detail: "case did not return every required non-empty evidence artifact".to_owned(),
        });
    }
    if cleanup.steps.is_empty() {
        failures.push(CaseFailure {
            check: ("cleanup").to_owned(),
            detail: "case returned no cleanup receipt".to_owned(),
        });
    } else if !cleanup.is_clean() {
        failures.push(CaseFailure {
            check: ("cleanup").to_owned(),
            detail: "one or more child/lease cleanup steps failed".to_owned(),
        });
    }
    CaseOutcome {
        status: if failures.is_empty() {
            CaseStatus::Pass
        } else {
            CaseStatus::Fail
        },
        summary: summary.to_owned(),
        failures,
        evidence,
        cleanup,
    }
}
