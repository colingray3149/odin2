//! Unit tests for the probe harness core, extracted verbatim from the
//! inline `mod tests` in `probe.rs`.

use super::*;
use std::sync::atomic::{AtomicBool, Ordering};

/// Minimal case body for exercising the runner and aggregator.
struct StubCase {
    id: ConformanceCaseId,
    name: &'static str,
    deadline: Duration,
    behavior: StubBehavior,
}

#[derive(Clone)]
enum StubBehavior {
    Pass,
    Sleep(Duration),
    DeadlineMutation {
        active: Arc<AtomicBool>,
        mutated: Arc<AtomicBool>,
        delay: Duration,
    },
    Evidence(Vec<u8>),
    RequireWorkDir {
        ran: Arc<AtomicBool>,
    },
}

struct ActiveCaseGuard(Arc<AtomicBool>);

impl Drop for ActiveCaseGuard {
    fn drop(&mut self) {
        self.0.store(false, Ordering::SeqCst);
    }
}

#[async_trait]
impl ConformanceCase for StubCase {
    fn id(&self) -> ConformanceCaseId {
        self.id
    }

    fn name(&self) -> &'static str {
        self.name
    }

    fn deadline(&self) -> Duration {
        self.deadline
    }

    async fn run(&self, context: &CaseContext) -> CaseOutcome {
        match &self.behavior {
            StubBehavior::Pass => CaseOutcome::pass(format!("stub {} passed", self.id.get())),
            StubBehavior::Sleep(duration) => {
                time::sleep(*duration).await;
                CaseOutcome::pass("stub slept")
            }
            StubBehavior::DeadlineMutation {
                active,
                mutated,
                delay,
            } => {
                active.store(true, Ordering::SeqCst);
                let _active = ActiveCaseGuard(Arc::clone(active));
                time::sleep(*delay).await;
                mutated.store(true, Ordering::SeqCst);
                CaseOutcome::pass("stub mutated after sleeping")
            }
            StubBehavior::Evidence(bytes) => {
                let mut outcome = CaseOutcome::pass("stub evidence");
                outcome.evidence.push(CaseEvidence {
                    kind: "stub_stream",
                    label: "Stub Label 1".to_owned(),
                    bytes: bytes.clone(),
                });
                outcome
            }
            StubBehavior::RequireWorkDir { ran } => {
                ran.store(true, Ordering::SeqCst);
                // Identity/spawn-like cwd check: exactly the precondition
                // `establish_identity` and `OmpProcess::spawn` place on a
                // spec -- its working directory must already exist.
                let spec = context.process_spec(DEFAULT_MODEL_SELECTOR, Vec::new());
                match std::fs::metadata(&spec.cwd) {
                    Ok(metadata) if metadata.is_dir() => {
                        CaseOutcome::pass("case began with an existing working directory")
                    }
                    observed => CaseOutcome::fail(
                        "case began without an existing working directory",
                        vec![CaseFailure {
                            check: "spawn_cwd".to_owned(),
                            detail: format!(
                                "spec cwd {} is not an existing directory: {observed:?}",
                                spec.cwd.display()
                            ),
                        }],
                    ),
                }
            }
        }
    }
}

fn stub(id: u8) -> RegisteredCase {
    let id = ConformanceCaseId::new(id);
    RegisteredCase {
        module: CaseModule::owner_of(id),
        case: Arc::new(StubCase {
            id,
            name: "stub_case",
            deadline: Duration::from_secs(5),
            behavior: StubBehavior::Pass,
        }),
    }
}

fn full_registration() -> Vec<RegisteredCase> {
    (1..=TOTAL_CASES).map(stub).collect()
}

fn registration_of(entries: Vec<RegisteredCase>) -> Result<Vec<RegisteredCase>, AggregationError> {
    check_membership(entries.iter().map(|entry| (entry.case.id(), entry.module)))?;
    Ok(entries)
}

fn fixture_executable() -> PathBuf {
    let executable = std::env::current_exe().expect("test executable path");
    std::fs::canonicalize(executable).expect("canonical test executable path")
}

fn fixture_binding(executable: &Path, digest: &str) -> odin_process::RegisteredServiceBinding {
    odin_process::RegisteredServiceBinding::new(executable.to_path_buf(), digest.to_owned())
        .expect("test executable binding")
}

fn test_config(work_root: &Path) -> ProbeConfig {
    let executable = fixture_executable();
    let executable_digest =
        blake3::hash(&std::fs::read(&executable).expect("read test executable for binding digest"))
            .to_hex()
            .to_string();
    let authority = Arc::new(odin_kernel::StopAuthority::new(
        Arc::new(Mutex::new(Ledger::open_in_memory().expect("test ledger"))),
        odin_kernel::recovery_worker_channel("unix:path=/nonexistent/probe-bus")
            .expect("recovery-only test channel"),
    ));
    let worker = |id: &str| {
        OmpWorkerLaunch::new(
            Arc::clone(&authority),
            odin_types::CorrelationId::new("00000000000000000000000000000001")
                .expect("test correlation"),
            "probe-test".to_owned(),
            id.to_owned(),
            1,
            fixture_binding(&executable, &executable_digest),
            odin_process::ScopeLimits::default(),
        )
        .expect("test worker naming")
    };
    ProbeConfig {
        omp: OmpLaunchTemplate {
            executable: executable.clone(),
            worker: worker("omp"),
            explicit_args: Vec::new(),
            explicit_env: Vec::new(),
            expected_source_revision: PINNED_OMP_SOURCE_REVISION.to_owned(),
            startup_timeout: Duration::from_secs(1),
            drain_timeout: Duration::from_secs(1),
            kill_timeout: Duration::from_secs(1),
        },
        fault: FaultFixtureRuntime {
            bun: executable.clone(),
            worker: worker("bun"),
            explicit_env: Vec::new(),
        },
        fixture_root: default_fixture_root(),
        work_root: work_root.to_path_buf(),
        atlas: Arc::new(Atlas {
            schema: "odin.atlas.test".to_owned(),
            version: 1,
            generation: "probe-test".to_owned(),
            source_paths: Default::default(),
            source_hashes: Default::default(),
            counts: odin_atlas::AtlasCounts {
                files: 0,
                nodes: 0,
                parse_errors: 0,
                by_source: Default::default(),
            },
            files: Vec::new(),
            parse_errors: Vec::new(),
            nodes: Vec::new(),
        }),
        deadlines: SuiteDeadlines::default(),
    }
}

fn test_context(id: u8, work_root: &Path) -> CaseContext {
    let config = Arc::new(test_config(work_root));
    let id = ConformanceCaseId::new(id);
    CaseContext::for_case(&config, id, "stub_case").expect("context builds")
}

fn pin() -> ProbePin {
    ProbePin {
        omp_executable: fixture_executable(),
        expected_source_revision: PINNED_OMP_SOURCE_REVISION.to_owned(),
        provider_fixture_digest: "a".repeat(64),
        fault_fixture_digest: "b".repeat(64),
    }
}

fn passing_result(id: u8) -> CaseResult {
    let id = ConformanceCaseId::new(id);
    CaseResult {
        id,
        name: "stub_case",
        module: CaseModule::owner_of(id),
        status: CaseStatus::Pass,
        duration: Duration::from_millis(7),
        summary: format!("stub {} passed", id.get()),
        failures: Vec::new(),
        evidence: Vec::new(),
        cleanup: CleanupReceipt::default(),
    }
}

#[test]
fn case_id_range_is_exactly_one_to_twenty_one() {
    assert_eq!(
        ConformanceCaseId::try_new(0),
        Err(CaseIdError::OutOfRange { got: 0 })
    );
    assert_eq!(
        ConformanceCaseId::try_new(22),
        Err(CaseIdError::OutOfRange { got: 22 })
    );
    assert_eq!(ConformanceCaseId::ALL.len(), TOTAL_CASES as usize);
    for (index, id) in ConformanceCaseId::ALL.iter().enumerate() {
        assert_eq!(id.get(), index as u8 + 1);
    }
}

#[test]
fn module_partition_is_an_exact_disjoint_cover_in_fixed_order() {
    let mut covered = Vec::new();
    for module in CaseModule::ALL {
        for id in module.case_ids() {
            let id = ConformanceCaseId::new(*id);
            assert_eq!(CaseModule::owner_of(id), module);
            covered.push(id.get());
        }
    }
    covered.sort_unstable();
    assert_eq!(covered, (1..=TOTAL_CASES).collect::<Vec<u8>>());
    let names: Vec<&str> = CaseModule::ALL.iter().map(|module| module.name()).collect();
    let mut deduped = names.clone();
    deduped.sort_unstable();
    deduped.dedup();
    assert_eq!(names.len(), deduped.len(), "module names must be unique");
}

#[test]
fn registration_rejects_missing_duplicate_and_misfiled_cases() {
    let incomplete = registration_of(
        full_registration()
            .into_iter()
            .filter(|entry| entry.case.id().get() != 7)
            .collect(),
    );
    assert_eq!(
        incomplete.err(),
        Some(AggregationError::SuiteIncomplete {
            missing: vec![ConformanceCaseId::new(7)]
        })
    );

    let mut duplicated = full_registration();
    let extra = stub(3);
    duplicated.push(extra);
    assert!(matches!(
        registration_of(duplicated),
        Err(AggregationError::DuplicateCase { id }) if id == ConformanceCaseId::new(3)
    ));

    let mut misfiled = full_registration();
    misfiled.retain(|entry| entry.case.id().get() != 21);
    let id = ConformanceCaseId::new(21);
    misfiled.push(RegisteredCase {
        module: CaseModule::Startup,
        case: Arc::new(StubCase {
            id,
            name: "misfiled_case",
            deadline: Duration::from_secs(5),
            behavior: StubBehavior::Pass,
        }),
    });
    assert_eq!(
        registration_of(misfiled).err(),
        Some(AggregationError::ModuleViolation {
            id,
            module: CaseModule::Startup,
            owner: CaseModule::FramingUnknown,
        })
    );

    assert!(registration_of(full_registration()).is_ok());
}

#[test]
fn aggregate_sorts_to_fixed_order_and_rejects_incomplete_sets() {
    let mut results: Vec<CaseResult> = (1..=TOTAL_CASES).map(passing_result).collect();
    results.reverse();
    let report = aggregate(results, pin()).expect("full set aggregates");
    assert_eq!(report.verdict, ProbeVerdict::Accept);
    assert_eq!(
        report
            .cases
            .iter()
            .map(|entry| entry.id.get())
            .collect::<Vec<u8>>(),
        (1..=TOTAL_CASES).collect::<Vec<u8>>()
    );

    let incomplete: Vec<CaseResult> = (1..=TOTAL_CASES)
        .filter(|id| *id != 12)
        .map(passing_result)
        .collect();
    assert!(matches!(
        aggregate(incomplete, pin()),
        Err(AggregationError::SuiteIncomplete { .. })
    ));
}

#[test]
fn report_is_byte_deterministic_for_identical_outcomes() {
    let forward: Vec<CaseResult> = (1..=TOTAL_CASES).map(passing_result).collect();
    let mut reversed = forward.clone();
    reversed.reverse();
    // Durations differ between the two runs; the canonical report must not.
    let mut timed = forward.clone();
    for result in &mut timed {
        result.duration = Duration::from_secs(999);
    }
    let a = aggregate(forward, pin()).expect("forward aggregates");
    let b = aggregate(reversed, pin()).expect("reversed aggregates");
    let c = aggregate(timed, pin()).expect("timed aggregates");
    assert_eq!(a.to_canonical_bytes(), b.to_canonical_bytes());
    assert_eq!(a.to_canonical_bytes(), c.to_canonical_bytes());
    assert_eq!(a.digest(), b.digest());
    assert_eq!(a.schema, REPORT_SCHEMA);
    assert_eq!(a.pin.expected_source_revision, PINNED_OMP_SOURCE_REVISION);
}

#[test]
fn verdict_rejects_when_any_case_fails() {
    let mut results: Vec<CaseResult> = (1..=TOTAL_CASES).map(passing_result).collect();
    let failed = &mut results[4];
    failed.status = CaseStatus::Fail;
    failed.failures.push(CaseFailure {
        check: ("stub").to_owned(),
        detail: "deliberate".to_owned(),
    });
    let report = aggregate(results, pin()).expect("full set aggregates");
    assert_eq!(report.verdict, ProbeVerdict::Reject);
}

#[test]
fn shipped_registration_is_exactly_the_frozen_twenty_one() {
    let registered = registered_cases().expect("shipped cases form one exact suite");
    assert_eq!(registered.len(), TOTAL_CASES as usize);
    assert_eq!(
        registered
            .iter()
            .map(|entry| entry.case.id().get())
            .collect::<Vec<_>>(),
        (1..=TOTAL_CASES).collect::<Vec<_>>(),
    );
}

#[test]
fn case_context_seeds_its_bound_lane_and_run() {
    let root = std::env::temp_dir().join(format!("odin-probe-test-ledger-{}", std::process::id()));
    let context = test_context(13, &root);
    let ledger = context.ledger();
    let guard = ledger.lock().expect("case ledger lock");
    let lane = lane_run::read_lane(guard.connection(), &context.ids().lane)
        .expect("lane read")
        .expect("bound lane seeded");
    let run = lane_run::read_run(guard.connection(), &context.ids().run)
        .expect("run read")
        .expect("bound run seeded");
    assert_eq!(lane.seat_id, context.ids().seat);
    assert_eq!(lane.project_id.as_ref(), Some(&context.ids().project));
    assert_eq!(lane.backend, "local_omp");
    assert_eq!(run.lane_id, context.ids().lane);
}

#[tokio::test]
async fn run_case_enforces_the_bounded_deadline() {
    let root =
        std::env::temp_dir().join(format!("odin-probe-test-deadline-{}", std::process::id()));
    let entry = RegisteredCase {
        module: CaseModule::Startup,
        case: Arc::new(StubCase {
            id: ConformanceCaseId::new(1),
            name: "sleepy_case",
            deadline: Duration::from_millis(50),
            behavior: StubBehavior::Sleep(Duration::from_secs(30)),
        }),
    };
    let context = test_context(1, &root);
    let result = run_case(&entry, context, None).await;
    assert_eq!(result.status, CaseStatus::Fail);
    assert!(result
        .failures
        .iter()
        .any(|failure| failure.check == "deadline"));
    assert!(result.duration < Duration::from_secs(5));
    assert!(result.cleanup.is_clean());
    assert!(result.cleanup.steps.iter().any(|step| {
        step.kind == "runner_cancel" && matches!(&step.outcome, CleanupOutcome::Clean)
    }));
}

#[tokio::test]
async fn timed_out_case_is_terminated_before_run_case_returns() {
    let root = std::env::temp_dir().join(format!(
        "odin-probe-test-termination-{}",
        std::process::id()
    ));
    let active = Arc::new(AtomicBool::new(false));
    let mutated = Arc::new(AtomicBool::new(false));
    let entry = RegisteredCase {
        module: CaseModule::Startup,
        case: Arc::new(StubCase {
            id: ConformanceCaseId::new(1),
            name: "deadline_mutation_case",
            deadline: Duration::from_millis(50),
            behavior: StubBehavior::DeadlineMutation {
                active: Arc::clone(&active),
                mutated: Arc::clone(&mutated),
                delay: Duration::from_millis(250),
            },
        }),
    };
    let context = test_context(1, &root);

    let result = run_case(&entry, context, None).await;

    assert_eq!(result.status, CaseStatus::Fail);
    assert!(result
        .failures
        .iter()
        .any(|failure| failure.check == "deadline"));
    assert!(
        !active.load(Ordering::SeqCst),
        "case task remained active after its terminal result"
    );
    assert!(
        !mutated.load(Ordering::SeqCst),
        "case task mutated state before its terminal result"
    );
    assert!(result.cleanup.steps.iter().any(|step| {
        step.kind == "runner_cancel" && matches!(&step.outcome, CleanupOutcome::Clean)
    }));

    time::sleep(Duration::from_millis(300)).await;
    assert!(
        !active.load(Ordering::SeqCst),
        "case task became active after its terminal result"
    );
    assert!(
        !mutated.load(Ordering::SeqCst),
        "case task mutated state after its terminal result"
    );
}

#[tokio::test]
async fn run_case_persists_evidence_with_digests() {
    let root =
        std::env::temp_dir().join(format!("odin-probe-test-evidence-{}", std::process::id()));
    let bytes = b"stub evidence bytes".to_vec();
    let entry = RegisteredCase {
        module: CaseModule::Startup,
        case: Arc::new(StubCase {
            id: ConformanceCaseId::new(1),
            name: "evidence_case",
            deadline: Duration::from_secs(5),
            behavior: StubBehavior::Evidence(bytes.clone()),
        }),
    };
    let context = test_context(1, &root);
    let result = run_case(&entry, context, None).await;
    assert_eq!(result.status, CaseStatus::Pass);
    assert_eq!(result.evidence.len(), 1);
    let artifact = &result.evidence[0];
    assert_eq!(artifact.digest, digest_hex(&bytes));
    assert_eq!(artifact.size_bytes, bytes.len() as u64);
    let persisted =
        std::fs::read(root.join(&artifact.path)).expect("artifact persisted under work root");
    assert_eq!(persisted, bytes);
    assert!(artifact.path.starts_with("cases"));
    std::fs::remove_dir_all(&root).expect("test work root removed");
}

#[test]
fn work_dir_preparation_refuses_the_filesystem_root() {
    let failure = ensure_case_work_dir(Path::new("/")).expect_err("filesystem root refused");
    assert_eq!(failure.check, "work_dir");
}

#[tokio::test]
async fn run_case_prepares_the_retained_work_dir_before_the_body_runs() {
    let root =
        std::env::temp_dir().join(format!("odin-probe-test-cwd-ready-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let ran = Arc::new(AtomicBool::new(false));
    let id = ConformanceCaseId::new(15);
    let entry = RegisteredCase {
        module: CaseModule::owner_of(id),
        case: Arc::new(StubCase {
            id,
            name: "cwd_probe_case",
            deadline: Duration::from_secs(5),
            behavior: StubBehavior::RequireWorkDir {
                ran: Arc::clone(&ran),
            },
        }),
    };
    let context = test_context(15, &root);
    let work_dir = context.work_dir().to_path_buf();
    let result = run_case(&entry, context, None).await;

    assert!(ran.load(Ordering::SeqCst), "case body must have run");
    assert!(
        result.status == CaseStatus::Pass,
        "expected a pass, got {:?} with failures {:?}",
        result.status,
        result.failures
    );
    // The work dir is retained evidence: neither it nor the work root may
    // be removed by the runner or the case.
    assert!(work_dir.is_dir(), "retained work dir must survive the case");
    assert!(root.is_dir(), "suite work root must survive the case");
    std::fs::remove_dir_all(&root).expect("test work root removed");
}

#[tokio::test]
async fn run_case_fails_typed_and_skips_the_body_when_the_work_dir_is_unavailable() {
    let root =
        std::env::temp_dir().join(format!("odin-probe-test-cwd-fail-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).expect("test work root created");
    // A regular file where the per-case directory tree would live makes
    // work-dir creation fail deterministically.
    std::fs::write(root.join("cases"), b"not a directory").expect("blocker written");
    let ran = Arc::new(AtomicBool::new(false));
    let id = ConformanceCaseId::new(15);
    let entry = RegisteredCase {
        module: CaseModule::owner_of(id),
        case: Arc::new(StubCase {
            id,
            name: "cwd_probe_case",
            deadline: Duration::from_secs(5),
            behavior: StubBehavior::RequireWorkDir {
                ran: Arc::clone(&ran),
            },
        }),
    };
    let context = test_context(15, &root);
    let result = run_case(&entry, context, None).await;

    assert_eq!(result.status, CaseStatus::Fail);
    let failure = result
        .failures
        .iter()
        .find(|failure| failure.check == "work_dir")
        .expect("typed work_dir failure");
    assert!(
        failure.detail.contains("could not be created"),
        "unexpected detail: {}",
        failure.detail
    );
    assert!(
        !ran.load(Ordering::SeqCst),
        "the body must never run without its work dir"
    );
    assert!(result.evidence.is_empty());
    assert!(!result.cleanup.is_clean());
    assert!(result.cleanup.steps.iter().any(|step| {
        step.kind == "runner_work_dir" && matches!(&step.outcome, CleanupOutcome::Failed { .. })
    }));
    assert!(root.is_dir(), "suite work root must survive the failure");
    std::fs::remove_dir_all(&root).expect("test work root removed");
}
