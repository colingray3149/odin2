//! The bounded runner: per-case deadline enforcement over the spawned case
//! task, sequential suite sequencing under the suite deadline, and
//! deterministic evidence persistence with content digests.

use std::sync::Arc;
use std::time::{Duration, Instant};

use super::config::ProbeConfig;
use super::contracts::{
    aggregate, registered_cases, CaseEvidence, CaseFailure, CaseOutcome, CaseResult, CaseStatus,
    CleanupOutcome, CleanupReceipt, ConformanceReport, EvidenceArtifact, ProbeError,
    RegisteredCase, MAX_CASE_ARTIFACTS, MAX_CASE_EVIDENCE_BYTES, MAX_EVIDENCE_ARTIFACT_BYTES,
    TOTAL_CASES,
};
use super::{digest_hex, ensure_case_work_dir, CaseContext};
use tokio::time;

/// Runs one registered case under its bounded deadline and assembles the
/// result.
///
/// The runner creates the case's retained work dir before spawning the body:
/// raw identity probes and child launches bind it as their working directory
/// and fail with ENOENT when it is absent. Creation failure is a typed
/// `work_dir` failure carrying a cleanup receipt; the body never runs.
///
/// The case body is spawned on the runtime and cancelled at
/// `min(case.deadline(), deadline_override)`; the runner retains the task
/// handle and awaits terminal cancellation before persisting evidence or
/// returning. Cancellation and panics become `Fail` results with
/// `deadline`/`panic`/`cancelled` checks. Returned evidence is persisted under
/// the case's work dir (`evidence/{NN}-{kind}-{label}`, digested); budget or
/// persistence violations downgrade the result to `Fail` with
/// `evidence_budget`/`evidence_persist` checks.
pub async fn run_case(
    registered: &RegisteredCase,
    context: CaseContext,
    deadline_override: Option<Duration>,
) -> CaseResult {
    let case = Arc::clone(&registered.case);
    let id = case.id();
    let name = case.name();
    let module = registered.module;
    let effective_deadline =
        deadline_override.map_or_else(|| case.deadline(), |over| case.deadline().min(over));
    let started = Instant::now();
    let outcome = match ensure_case_work_dir(context.work_dir()) {
        Err(failure) => {
            let mut outcome = CaseOutcome::fail(
                "case work dir could not be created; the body never ran",
                vec![failure],
            );
            outcome.cleanup.push(
                "runner_work_dir",
                context.work_dir().display().to_string(),
                CleanupOutcome::Failed {
                    reason: "retained case work dir could not be created".to_owned(),
                },
            );
            outcome.cleanup.push(
                "case_cleanup_receipt",
                name,
                CleanupOutcome::Failed {
                    reason: "case body never ran; no cleanup receipt was returned".to_owned(),
                },
            );
            outcome
        }
        Ok(()) => {
            let run_context = context.clone();
            let mut join = tokio::spawn(async move { case.run(&run_context).await });
            match time::timeout(effective_deadline, &mut join).await {
                Ok(Ok(outcome)) => outcome,
                Ok(Err(join_error)) => {
                    // Receiving a JoinError is terminal: Tokio does not yield it until
                    // the case task has finished cancelling or unwinding.
                    let check = if join_error.is_panic() {
                        "panic"
                    } else {
                        "cancelled"
                    };
                    let mut outcome = CaseOutcome::fail(
                        format!("case {check}: {join_error}"),
                        vec![CaseFailure {
                            check: check.to_owned(),
                            detail: join_error.to_string(),
                        }],
                    );
                    outcome
                        .cleanup
                        .push("runner_task_join", name, CleanupOutcome::Clean);
                    outcome.cleanup.push(
                        "case_cleanup_receipt",
                        name,
                        CleanupOutcome::Failed {
                            reason: format!(
                                "case task terminated by {check} before returning its cleanup receipt"
                            ),
                        },
                    );
                    outcome
                }
                Err(_elapsed) => {
                    let deadline_summary = format!(
                        "case exceeded its deadline of {} ms",
                        effective_deadline.as_millis()
                    );
                    let deadline_failure = CaseFailure {
                        check: ("deadline").to_owned(),
                        detail: format!("no outcome within {} ms", effective_deadline.as_millis()),
                    };

                    join.abort();
                    match join.await {
                        Ok(mut late_outcome) => {
                            // The task won the abort race. Preserve everything it
                            // returned while retaining the deadline as authoritative.
                            late_outcome.status = CaseStatus::Fail;
                            late_outcome.summary = deadline_summary;
                            late_outcome.failures.insert(0, deadline_failure);
                            late_outcome.cleanup.push(
                                "runner_join_after_deadline",
                                name,
                                CleanupOutcome::Clean,
                            );
                            late_outcome
                        }
                        Err(join_error) if join_error.is_cancelled() => {
                            let mut outcome =
                                CaseOutcome::fail(deadline_summary, vec![deadline_failure]);
                            // This receipt is appended only after awaiting the aborted
                            // handle proves that the case task has terminated.
                            outcome
                                .cleanup
                                .push("runner_cancel", name, CleanupOutcome::Clean);
                            outcome
                        }
                        Err(join_error) => {
                            let check = if join_error.is_panic() {
                                "panic"
                            } else {
                                "cancelled"
                            };
                            let mut outcome = CaseOutcome::fail(
                                deadline_summary,
                                vec![
                                    deadline_failure,
                                    CaseFailure {
                                        check: check.to_owned(),
                                        detail: format!("case task {check} while deadline termination was awaited: {join_error}"),
                                    },
                                ],
                            );
                            outcome
                                .cleanup
                                .push("runner_task_join", name, CleanupOutcome::Clean);
                            outcome.cleanup.push(
                                "case_cleanup_receipt",
                                name,
                                CleanupOutcome::Failed {
                                    reason: format!(
                                        "case task {check} while deadline termination was awaited; no cleanup receipt was returned"
                                    ),
                                },
                            );
                            outcome
                        }
                    }
                }
            }
        }
    };
    let duration = started.elapsed();
    let (evidence, evidence_failures) = persist_case_evidence(&context, outcome.evidence);
    let mut failures = outcome.failures;
    failures.extend(evidence_failures);
    let status = if failures.is_empty() {
        outcome.status
    } else {
        CaseStatus::Fail
    };
    CaseResult {
        id,
        name,
        module,
        status,
        duration,
        summary: outcome.summary,
        failures,
        evidence,
        cleanup: outcome.cleanup,
    }
}

/// Runs the complete registered suite sequentially, in fixed id order, under
/// the suite deadline, and aggregates the deterministic report. Cases not
/// reached before the suite deadline are recorded as `suite_deadline` failures
/// so the report always covers all 21 ids.
pub async fn run_suite(config: ProbeConfig) -> Result<ConformanceReport, ProbeError> {
    config.validate()?;
    let pin = config.probe_pin()?;
    let registered = registered_cases()?;
    let config = Arc::new(config);
    std::fs::create_dir_all(&config.work_root)?;
    let suite_started = Instant::now();
    let mut results = Vec::with_capacity(TOTAL_CASES as usize);
    for entry in &registered {
        let remaining = config
            .deadlines
            .suite
            .checked_sub(suite_started.elapsed())
            .filter(|budget| !budget.is_zero());
        let Some(remaining) = remaining else {
            results.push(skipped_result(entry));
            continue;
        };
        let context = CaseContext::for_case(&config, entry.case.id(), entry.case.name())?;
        results.push(run_case(entry, context, Some(remaining)).await);
    }
    Ok(aggregate(results, pin)?)
}

/// The recorded result for a case the suite deadline kept from running.
fn skipped_result(entry: &RegisteredCase) -> CaseResult {
    CaseResult {
        id: entry.case.id(),
        name: entry.case.name(),
        module: entry.module,
        status: CaseStatus::Fail,
        duration: Duration::ZERO,
        summary: "case did not run: suite deadline exhausted".to_owned(),
        failures: vec![CaseFailure {
            check: "suite_deadline".to_owned(),
            detail: "the suite deadline was exhausted before this case started".to_owned(),
        }],
        evidence: Vec::new(),
        cleanup: CleanupReceipt::default(),
    }
}

/// Persists one case's evidence under its work dir, enforcing the artifact
/// count and byte budgets. Violating items are not written; each violation or
/// I/O failure is returned as a `CaseFailure` and downgrades the case.
fn persist_case_evidence(
    context: &CaseContext,
    evidence: Vec<CaseEvidence>,
) -> (Vec<EvidenceArtifact>, Vec<CaseFailure>) {
    let mut artifacts = Vec::with_capacity(evidence.len());
    let mut failures = Vec::new();
    if evidence.len() > MAX_CASE_ARTIFACTS {
        failures.push(CaseFailure {
            check: ("evidence_budget").to_owned(),
            detail: format!(
                "{} artifacts exceed the cap of {MAX_CASE_ARTIFACTS}",
                evidence.len()
            ),
        });
        return (artifacts, failures);
    }
    let mut total_bytes = 0usize;
    let mut dir_created = false;
    for (index, item) in evidence.into_iter().enumerate() {
        let size = item.bytes.len();
        if size > MAX_EVIDENCE_ARTIFACT_BYTES || total_bytes + size > MAX_CASE_EVIDENCE_BYTES {
            failures.push(CaseFailure {
                check: ("evidence_budget").to_owned(),
                detail: format!(
                    "artifact `{}` ({} bytes) exceeds the per-artifact or per-case evidence budget",
                    item.label, size
                ),
            });
            continue;
        }
        let dir = context.evidence_dir();
        if !dir_created {
            if let Err(error) = std::fs::create_dir_all(&dir) {
                failures.push(CaseFailure {
                    check: ("evidence_persist").to_owned(),
                    detail: format!(
                        "evidence dir {} could not be created: {error}",
                        dir.display()
                    ),
                });
                return (artifacts, failures);
            }
            dir_created = true;
        }
        let path = dir.join(format!(
            "{index:02}-{}-{}",
            item.kind,
            sanitize_label(&item.label)
        ));
        match std::fs::write(&path, &item.bytes) {
            Ok(()) => {
                total_bytes += size;
                let stored = path
                    .strip_prefix(&context.config.work_root)
                    .unwrap_or(&path)
                    .to_path_buf();
                artifacts.push(EvidenceArtifact {
                    kind: item.kind.to_owned(),
                    label: item.label,
                    digest: digest_hex(&item.bytes),
                    size_bytes: size as u64,
                    path: stored,
                });
            }
            Err(error) => failures.push(CaseFailure {
                check: ("evidence_persist").to_owned(),
                detail: format!(
                    "artifact `{}` could not be written to {}: {error}",
                    item.label,
                    path.display()
                ),
            }),
        }
    }
    (artifacts, failures)
}

/// Maps an evidence label into a bounded file-name-safe fragment.
fn sanitize_label(label: &str) -> String {
    let sanitized: String = label
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || character == '-' || character == '_' {
                character.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .take(48)
        .collect();
    if sanitized.is_empty() {
        "evidence".to_owned()
    } else {
        sanitized
    }
}
