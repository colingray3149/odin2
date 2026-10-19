//! The frozen conformance contract: case id/module vocabulary, outcome and
//! result types, the canonical report, errors, the case trait, and the
//! registration/aggregation that enforces the frozen 21-case list.

use std::fmt;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use odin_ledger::LedgerError;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::host_tools::HostToolError;
use crate::uri::UriError;

use super::cases;
use super::{check_membership, digest_hex, CaseContext};

/// Number of cases in the frozen conformance list.
pub const TOTAL_CASES: u8 = 21;

/// `schema` value of the canonical conformance report.
pub const REPORT_SCHEMA: &str = "odin.omp.conformance.v1";

/// Byte cap for one persisted evidence artifact.
pub const MAX_EVIDENCE_ARTIFACT_BYTES: usize = 8 * 1024 * 1024;
/// Entry cap for one case's evidence set.
pub const MAX_CASE_ARTIFACTS: usize = 128;
/// Total byte cap for one case's evidence set.
pub const MAX_CASE_EVIDENCE_BYTES: usize = 32 * 1024 * 1024;

/// A conformance case id: exactly `1..=21`, the frozen case list.
///
/// [`ConformanceCaseId::new`] is const and panics out of range, which makes it
/// usable for module-level vocabulary constants (a wrong constant fails at
/// compile time); [`ConformanceCaseId::try_new`] reports runtime input.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ConformanceCaseId(u8);

impl ConformanceCaseId {
    /// Smallest legal id.
    pub const MIN: u8 = 1;
    /// Largest legal id.
    pub const MAX: u8 = TOTAL_CASES;
    /// Every legal id, ascending.
    pub const ALL: [Self; TOTAL_CASES as usize] = {
        let mut all = [Self(0); TOTAL_CASES as usize];
        let mut index = 0;
        while index < TOTAL_CASES as usize {
            all[index] = Self(index as u8 + 1);
            index += 1;
        }
        all
    };

    /// Compile-time constructor; panics when `id` is outside 1..=21.
    pub const fn new(id: u8) -> Self {
        assert!(
            id >= Self::MIN && id <= Self::MAX,
            "conformance case id outside 1..=21"
        );
        Self(id)
    }

    /// Runtime constructor for untrusted input.
    pub const fn try_new(id: u8) -> Result<Self, CaseIdError> {
        if id >= Self::MIN && id <= Self::MAX {
            Ok(Self(id))
        } else {
            Err(CaseIdError::OutOfRange { got: id })
        }
    }

    /// The numeric id, 1..=21.
    pub const fn get(self) -> u8 {
        self.0
    }
}

impl fmt::Display for ConformanceCaseId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "case-{}", self.0)
    }
}

impl Serialize for ConformanceCaseId {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_u8(self.0)
    }
}
impl<'de> Deserialize<'de> for ConformanceCaseId {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = u8::deserialize(deserializer)?;
        Self::try_new(value).map_err(serde::de::Error::custom)
    }
}

/// Why a case id was rejected.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CaseIdError {
    /// The id is outside the frozen 1..=21 list.
    OutOfRange {
        /// The rejected value.
        got: u8,
    },
}

impl fmt::Display for CaseIdError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OutOfRange { got } => {
                write!(
                    formatter,
                    "conformance case id {got} is outside 1..={TOTAL_CASES}"
                )
            }
        }
    }
}

impl std::error::Error for CaseIdError {}

/// One of the eight disjoint case modules under [`cases`].
///
/// The partition is fixed: each module owns exactly the ids in
/// [`CaseModule::case_ids`], and registration enforces that ownership so the
/// eight case waves can never collide or silently cover for each other.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum CaseModule {
    /// `startup.rs` — cold start, ready frame, protocol versions, frame limits.
    Startup,
    /// `framing_unknown.rs` — negotiation/reassembly limits; unknown future frames.
    FramingUnknown,
    /// `prompt_state_todos.rs` — prompt correlation, state across a turn, todos.
    PromptStateTodos,
    /// `controls_model.rs` — steer, follow-up, aborts, compaction/bash, set_model.
    ControlsModel,
    /// `subagents_tools.rs` — subagent observation, read tool, host tool/URI.
    SubagentsTools,
    /// `history_persistence.rs` — history paging, session stop/resume.
    HistoryPersistence,
    /// `crash_provider.rs` — kill/recovery, unavailable provider fallback.
    CrashProvider,
    /// `slash_config_shutdown.rs` — slash commands, RPC config, stdin shutdown.
    SlashConfigShutdown,
}

impl CaseModule {
    /// All modules in the fixed aggregation order.
    pub const ALL: [Self; 8] = [
        Self::Startup,
        Self::FramingUnknown,
        Self::PromptStateTodos,
        Self::ControlsModel,
        Self::SubagentsTools,
        Self::HistoryPersistence,
        Self::CrashProvider,
        Self::SlashConfigShutdown,
    ];

    /// Stable snake-case module name (the file stem under `src/probe/cases/`).
    pub const fn name(self) -> &'static str {
        match self {
            Self::Startup => "startup",
            Self::FramingUnknown => "framing_unknown",
            Self::PromptStateTodos => "prompt_state_todos",
            Self::ControlsModel => "controls_model",
            Self::SubagentsTools => "subagents_tools",
            Self::HistoryPersistence => "history_persistence",
            Self::CrashProvider => "crash_provider",
            Self::SlashConfigShutdown => "slash_config_shutdown",
        }
    }

    /// The exact case ids this module owns, ascending.
    pub const fn case_ids(self) -> &'static [u8] {
        match self {
            Self::Startup => &[1],
            Self::FramingUnknown => &[2, 21],
            Self::PromptStateTodos => &[3, 4, 5],
            Self::ControlsModel => &[6, 7, 8, 9, 10],
            Self::SubagentsTools => &[11, 12, 13],
            Self::HistoryPersistence => &[14, 15],
            Self::CrashProvider => &[16, 17],
            Self::SlashConfigShutdown => &[18, 19, 20],
        }
    }

    /// Whether this module owns `id`.
    pub fn owns(self, id: ConformanceCaseId) -> bool {
        self.case_ids().contains(&id.get())
    }

    /// The module that owns `id`; total because the id type is range-checked.
    pub fn owner_of(id: ConformanceCaseId) -> Self {
        Self::ALL
            .iter()
            .copied()
            .find(|module| module.owns(id))
            .expect("every in-range case id has exactly one owning module")
    }

    /// Pulls the module's registration slot.
    fn collect(self) -> Vec<Arc<dyn ConformanceCase>> {
        match self {
            Self::Startup => cases::startup::cases(),
            Self::FramingUnknown => cases::framing_unknown::cases(),
            Self::PromptStateTodos => cases::prompt_state_todos::cases(),
            Self::ControlsModel => cases::controls_model::cases(),
            Self::SubagentsTools => cases::subagents_tools::cases(),
            Self::HistoryPersistence => cases::history_persistence::cases(),
            Self::CrashProvider => cases::crash_provider::cases(),
            Self::SlashConfigShutdown => cases::slash_config_shutdown::cases(),
        }
    }
}

impl fmt::Display for CaseModule {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.name())
    }
}

impl Serialize for CaseModule {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.name())
    }
}

/// Terminal status of one case.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum CaseStatus {
    /// Every check the case performed held.
    Pass,
    /// At least one check failed, or the runner forced a failure (deadline,
    /// panic, evidence budget).
    Fail,
}

impl CaseStatus {
    /// Stable lowercase report token.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pass => "pass",
            Self::Fail => "fail",
        }
    }
}

impl Serialize for CaseStatus {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CaseFailure {
    /// Stable snake-case check name, e.g. `ready_frame`, `chunk_order`.
    pub check: String,
    /// What was expected vs observed.
    pub detail: String,
}

/// One evidence item produced by a case body; the runner persists and digests
/// it into an [`EvidenceArtifact`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CaseEvidence {
    /// Stable snake-case kind, e.g. `ready_frame`, `event_stream`, `journal`.
    pub kind: &'static str,
    /// Case-relative label; sanitized into the persisted file name.
    pub label: String,
    /// Exact bytes retained; bounded by [`MAX_EVIDENCE_ARTIFACT_BYTES`].
    pub bytes: Vec<u8>,
}

/// A persisted evidence item: content-addressed by digest, located under the
/// case's retained work dir.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceArtifact {
    pub kind: String,
    pub label: String,
    /// BLAKE3 hex digest of the exact persisted bytes.
    pub digest: String,
    pub size_bytes: u64,
    /// Persisted path, relative to the suite work root when it lives under it.
    pub path: PathBuf,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "state", rename_all = "lowercase")]
pub enum CleanupOutcome {
    Clean,
    /// The step failed; residue may remain. Nothing may ever destroy data, so
    /// a failed cleanup is reported, never retried destructively.
    Failed {
        reason: String,
    },
}

/// One cleanup step the case performed, in the order performed.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CleanupStep {
    /// Stable snake-case kind: `child_kill`, `lease_release`, `fixture_remove`, ...
    pub kind: String,
    /// What was cleaned (pid, lease id, path).
    pub subject: String,
    /// Terminal outcome.
    pub outcome: CleanupOutcome,
}

/// Every cleanup step a case performed. Cases record steps for everything they
/// started or created; the harness work dir itself is retained as evidence and
/// is never a cleanup subject.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CleanupReceipt {
    /// The performed steps, in order.
    pub steps: Vec<CleanupStep>,
}

impl CleanupReceipt {
    /// Appends one performed step.
    pub fn push(
        &mut self,
        kind: impl Into<String>,
        subject: impl Into<String>,
        outcome: CleanupOutcome,
    ) {
        self.steps.push(CleanupStep {
            kind: kind.into(),
            subject: subject.into(),
            outcome,
        });
    }

    /// Whether every recorded step completed.
    pub fn is_clean(&self) -> bool {
        self.steps
            .iter()
            .all(|step| matches!(step.outcome, CleanupOutcome::Clean))
    }
}

/// What a case body returns: status, one-line summary, failed checks, evidence
/// to persist, and the cleanup it already performed.
#[derive(Clone, Debug)]
pub struct CaseOutcome {
    /// Terminal status.
    pub status: CaseStatus,
    /// One stable line describing the outcome.
    pub summary: String,
    /// Failed checks; empty on a clean pass. A non-empty list forces
    /// [`CaseStatus::Fail`] in the assembled result regardless of `status`.
    pub failures: Vec<CaseFailure>,
    /// Evidence items for the runner to persist and digest.
    pub evidence: Vec<CaseEvidence>,
    /// Cleanup the case performed.
    pub cleanup: CleanupReceipt,
}

impl CaseOutcome {
    /// A passing outcome with no failures, evidence, or cleanup yet.
    pub fn pass(summary: impl Into<String>) -> Self {
        Self {
            status: CaseStatus::Pass,
            summary: summary.into(),
            failures: Vec::new(),
            evidence: Vec::new(),
            cleanup: CleanupReceipt::default(),
        }
    }

    /// A failing outcome with its failed checks.
    pub fn fail(summary: impl Into<String>, failures: Vec<CaseFailure>) -> Self {
        Self {
            status: CaseStatus::Fail,
            summary: summary.into(),
            failures,
            evidence: Vec::new(),
            cleanup: CleanupReceipt::default(),
        }
    }
}

/// One case's assembled result: the outcome plus the runner's timing and the
/// persisted evidence artifacts.
#[derive(Clone, Debug)]
pub struct CaseResult {
    pub id: ConformanceCaseId,
    /// The case's stable snake-case name.
    pub name: &'static str,
    pub module: CaseModule,
    /// Terminal status after runner enforcement.
    pub status: CaseStatus,
    /// Wall-clock duration of the run; operational metadata, deliberately
    /// absent from the canonical report bytes.
    pub duration: Duration,
    /// One-line stable summary.
    pub summary: String,
    /// Failed checks, including runner-forced ones.
    pub failures: Vec<CaseFailure>,
    pub evidence: Vec<EvidenceArtifact>,
    pub cleanup: CleanupReceipt,
}

impl CaseResult {
    /// The canonical, timing-free report projection of this result.
    fn report_entry(&self) -> CaseReportEntry {
        CaseReportEntry {
            id: self.id,
            name: self.name.to_owned(),
            module: self.module,
            status: self.status,
            summary: self.summary.clone(),
            failures: self.failures.clone(),
            evidence: self.evidence.clone(),
            cleanup: self.cleanup.clone(),
        }
    }
}

/// The serializable per-case entry of a [`ConformanceReport`]: everything in
/// [`CaseResult`] except wall-clock timing, so identical outcomes produce
/// identical bytes.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CaseReportEntry {
    pub id: ConformanceCaseId,
    /// The case's stable snake-case name.
    pub name: String,
    pub module: CaseModule,
    pub status: CaseStatus,
    /// One-line stable summary.
    pub summary: String,
    pub failures: Vec<CaseFailure>,
    pub evidence: Vec<EvidenceArtifact>,
    pub cleanup: CleanupReceipt,
}

/// The recorded pin the suite ran against.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProbePin {
    /// The trusted OMP executable as configured.
    pub omp_executable: PathBuf,
    /// The configured source revision; validated to be
    /// [`crate::probe::PINNED_OMP_SOURCE_REVISION`].
    pub expected_source_revision: String,
    /// BLAKE3 hex digest of the provider fixture bytes.
    pub provider_fixture_digest: String,
    /// BLAKE3 hex digest of the fault fixture bytes.
    pub fault_fixture_digest: String,
}

/// The accept/reject verdict over the full suite.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum ProbeVerdict {
    /// Every case passed; the adapter is accepted.
    Accept,
    /// At least one case failed; the adapter is rejected.
    Reject,
}

impl ProbeVerdict {
    /// Stable lowercase report token.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Accept => "accept",
            Self::Reject => "reject",
        }
    }
}

impl Serialize for ProbeVerdict {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

/// The deterministic suite report: fixed field order, fixed case order, no
/// timestamps and no durations. Identical case outcomes serialize to identical
/// bytes.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ConformanceReport {
    /// [`REPORT_SCHEMA`].
    pub schema: String,
    /// The recorded pin.
    pub pin: ProbePin,
    /// The accept/reject verdict.
    pub verdict: ProbeVerdict,
    /// Exactly 21 entries, ordered by ascending case id.
    pub cases: Vec<CaseReportEntry>,
}

impl ConformanceReport {
    /// Canonical report bytes (compact JSON over the fixed field order).
    pub fn to_canonical_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(self).expect("conformance report serialization is infallible")
    }

    /// BLAKE3 hex digest of the canonical bytes.
    pub fn digest(&self) -> String {
        digest_hex(&self.to_canonical_bytes())
    }
}

/// Why a registration or result set cannot form a suite.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum AggregationError {
    /// The suite does not cover the frozen list.
    #[error(
        "conformance suite is incomplete; missing {}",
        format_case_ids(missing)
    )]
    SuiteIncomplete {
        /// The missing ids, ascending.
        missing: Vec<ConformanceCaseId>,
    },
    /// One id appeared more than once.
    #[error("conformance {id} is registered more than once")]
    DuplicateCase { id: ConformanceCaseId },
    /// A case was filed under a module that does not own its id.
    #[error("{id} belongs to module `{owner}` but was registered by `{module}`")]
    ModuleViolation {
        id: ConformanceCaseId,
        module: CaseModule,
        owner: CaseModule,
    },
}

fn format_case_ids(ids: &[ConformanceCaseId]) -> String {
    let numbers: Vec<u8> = ids.iter().map(|id| id.get()).collect();
    format!("case ids {numbers:?}")
}

/// Everything above the case bodies that can fail honestly.
#[derive(Debug, Error)]
pub enum ProbeError {
    /// Registration or aggregation rejected the suite.
    #[error(transparent)]
    Aggregation(#[from] AggregationError),
    /// A fixture file was missing, unreadable, or oversized.
    #[error("probe fixture rejected: {detail}")]
    Fixture { detail: String },
    /// The durable ledger rejected an operation.
    #[error(transparent)]
    Ledger(#[from] LedgerError),
    /// Host-tool assembly failed.
    #[error(transparent)]
    HostTool(#[from] HostToolError),
    /// URI router construction failed.
    #[error(transparent)]
    Uri(#[from] UriError),
    /// Filesystem I/O behind the suite failed.
    #[error("probe I/O failed: {0}")]
    Io(#[from] std::io::Error),
    /// Host configuration or input validation rejected the probe.
    #[error("probe configuration rejected: {detail}")]
    Config { detail: String },
}

/// One registered case and the module it was collected from.
pub struct RegisteredCase {
    /// The owning module (registration association, not self-declared).
    pub module: CaseModule,
    pub case: Arc<dyn ConformanceCase>,
}

/// One conformance case: identity, bounded deadline, and body.
///
/// Implementations live exactly one per file under [`cases`]; they are spawned
/// on the tokio runtime by [`crate::probe::run_case`], so `run` must be `Send`. Cases never
/// write evidence files themselves; they return [`CaseEvidence`] and record
/// cleanup in a [`CleanupReceipt`].
#[async_trait]
pub trait ConformanceCase: Send + Sync {
    /// The exact frozen case id.
    fn id(&self) -> ConformanceCaseId;
    /// Stable snake-case case name, unique in the suite.
    fn name(&self) -> &'static str;
    /// Hard wall-clock bound; the runner cancels the case at this deadline and
    /// records a `deadline` failure.
    fn deadline(&self) -> Duration;
    async fn run(&self, context: &CaseContext) -> CaseOutcome;
}

/// Collects every module's registration slot and validates the suite
/// structurally: each case filed under the module that owns its id, no id
/// repeated, and the frozen list covered exactly. The returned cases are
/// sorted by ascending id, which is also the execution order of
/// [`crate::probe::run_suite`].
pub fn registered_cases() -> Result<Vec<RegisteredCase>, AggregationError> {
    let mut registered = Vec::new();
    for module in CaseModule::ALL {
        for case in module.collect() {
            registered.push(RegisteredCase { module, case });
        }
    }
    check_membership(
        registered
            .iter()
            .map(|entry| (entry.case.id(), entry.module)),
    )?;
    registered.sort_by_key(|entry| entry.case.id());
    Ok(registered)
}

/// Aggregates per-case results into the deterministic report. The results are
/// validated exactly like registration (duplicates, ownership, completeness),
/// sorted into ascending id order, and stamped with the accept/reject verdict:
/// accept exactly when all 21 cases passed.
pub fn aggregate(
    mut results: Vec<CaseResult>,
    pin: ProbePin,
) -> Result<ConformanceReport, AggregationError> {
    check_membership(results.iter().map(|result| (result.id, result.module)))?;
    results.sort_by_key(|result| result.id);
    let verdict = if results
        .iter()
        .all(|result| result.status == CaseStatus::Pass)
    {
        ProbeVerdict::Accept
    } else {
        ProbeVerdict::Reject
    };
    Ok(ConformanceReport {
        schema: REPORT_SCHEMA.to_owned(),
        pin,
        verdict,
        cases: results.iter().map(CaseResult::report_entry).collect(),
    })
}
