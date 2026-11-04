//! Runs the pinned OMP conformance cases and emits a deterministic report.
//!
//! Registration requires all 21 case IDs exactly once, each from its assigned
//! module. Each case runs with a deadline and retains artifacts with content
//! digests; aggregation sorts results by ID before deciding acceptance.
//!
//! Test fixtures use no network or secrets: `fixtures/mock-provider.ts` serves
//! the in-process `odin-mock` provider, and `fixtures/rpc-fault-fixture.ts`
//! injects transport faults that the provider cannot produce.

pub mod cases;

mod config;
mod context;
mod contracts;
mod raw_rpc;
mod runner;

pub use config::{
    default_fixture_root, pinned_omp_version, FaultFixtureRuntime, OmpLaunchTemplate, ProbeConfig,
    SuiteDeadlines, DEFAULT_MODEL_SELECTOR, FAULT_FIXTURE_FILE, FIXTURE_COMMAND, FIXTURE_MODEL_A,
    FIXTURE_MODEL_B, FIXTURE_PROVIDER, PINNED_OMP_SOURCE_REVISION, PROVIDER_FIXTURE_FILE,
};
pub use context::CaseIds;
pub use contracts::{
    aggregate, registered_cases, AggregationError, CaseEvidence, CaseFailure, CaseIdError,
    CaseModule, CaseOutcome, CaseReportEntry, CaseResult, CaseStatus, CleanupOutcome,
    CleanupReceipt, CleanupStep, ConformanceCase, ConformanceCaseId, ConformanceReport,
    EvidenceArtifact, ProbeError, ProbePin, ProbeVerdict, RegisteredCase, MAX_CASE_ARTIFACTS,
    MAX_CASE_EVIDENCE_BYTES, MAX_EVIDENCE_ARTIFACT_BYTES, REPORT_SCHEMA, TOTAL_CASES,
};
pub use raw_rpc::{RawRpcDriver, RawRpcError};
pub use runner::{run_case, run_suite};

#[cfg(test)]
use crate::process::OmpWorkerLaunch;
#[cfg(test)]
use async_trait::async_trait;
#[cfg(test)]
use odin_atlas::Atlas;
#[cfg(test)]
use std::time::Duration;
#[cfg(test)]
use tokio::time;

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use odin_ledger::Ledger;

/// Runs a case against a fresh in-memory ledger with deterministic identities.
///
/// Construction performs no filesystem I/O; [`run_case`] creates the retained
/// work dir before the case body runs, and process/bridge helpers create their
/// own subdirectories on demand.
#[derive(Clone)]
pub struct CaseContext {
    config: Arc<ProbeConfig>,
    ids: CaseIds,
    work_dir: PathBuf,
    ledger: Arc<Mutex<Ledger>>,
}

/// Requires each case exactly once from its assigned module.
fn check_membership(
    entries: impl IntoIterator<Item = (ConformanceCaseId, CaseModule)>,
) -> Result<(), AggregationError> {
    let mut seen = [false; TOTAL_CASES as usize + 1];
    for (id, module) in entries {
        let owner = CaseModule::owner_of(id);
        if owner != module {
            return Err(AggregationError::ModuleViolation { id, module, owner });
        }
        let slot = &mut seen[id.get() as usize];
        if *slot {
            return Err(AggregationError::DuplicateCase { id });
        }
        *slot = true;
    }
    let missing: Vec<ConformanceCaseId> = ConformanceCaseId::ALL
        .iter()
        .copied()
        .filter(|id| !seen[id.get() as usize])
        .collect();
    if !missing.is_empty() {
        return Err(AggregationError::SuiteIncomplete { missing });
    }
    Ok(())
}

/// Longest file-name fragment a label or command contributes.
const FILE_FRAGMENT_CHARS: usize = 48;

/// A bounded file-name-safe fragment: ASCII alphanumerics, `-` and `_` kept, anything else `-`.
fn file_fragment(text: &str) -> String {
    text.chars()
        .take(FILE_FRAGMENT_CHARS)
        .map(|character| {
            if character.is_ascii_alphanumeric() || matches!(character, '-' | '_') {
                character
            } else {
                '-'
            }
        })
        .collect()
}

#[cfg(test)]
mod tests;
