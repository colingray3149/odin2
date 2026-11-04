//! Tests for the probe runner, registration and aggregation, driven by stub cases.

use super::*;
use std::path::Path;
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
    DeadlineMutation {
        active: Arc<AtomicBool>,
        mutated: Arc<AtomicBool>,
        delay: Duration,
    },
    Evidence(Vec<(String, Vec<u8>)>),
    Panic,
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

    async fn run(&self, _context: &CaseContext) -> CaseOutcome {
        match &self.behavior {
            StubBehavior::Pass => CaseOutcome::pass(format!("stub {} passed", self.id.get())),
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
            StubBehavior::Evidence(items) => {
                let mut outcome = CaseOutcome::pass("stub evidence");
                outcome
                    .evidence
                    .extend(items.iter().map(|(label, bytes)| CaseEvidence {
                        kind: "stub_stream",
                        label: label.clone(),
                        bytes: bytes.clone(),
                    }));
                outcome
            }
            StubBehavior::Panic => panic!("stub case body panicked"),
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
    // The binding checks only the digest's shape; no case here spawns the executable.
    let executable_digest = "0".repeat(64);
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
fn verdict_rejects_when_any_case_fails() {
    let mut results: Vec<CaseResult> = (1..=TOTAL_CASES).map(passing_result).collect();
    let failed = &mut results[4];
    failed.status = CaseStatus::Fail;
    failed.failures.push(CaseFailure {
        check: "stub".to_owned(),
        detail: "deliberate".to_owned(),
    });
    let report = aggregate(results, pin()).expect("full set aggregates");
    assert_eq!(report.verdict, ProbeVerdict::Reject);
}

#[test]
fn a_config_is_refused_before_any_effect_when_it_is_not_the_pin() {
    let scratch = tempfile::tempdir().expect("tempdir");
    let valid = test_config(scratch.path());
    valid.validate().expect("the test config is valid");

    let mut wrong_revision = valid.clone();
    wrong_revision.omp.expected_source_revision = "not-the-pin".to_owned();
    let mut no_work_root = valid.clone();
    no_work_root.work_root = PathBuf::new();
    let mut inverted = valid.clone();
    inverted.deadlines = SuiteDeadlines {
        default_case: Duration::from_secs(60),
        suite: Duration::from_secs(10),
    };
    for (what, config) in [
        ("expected_source_revision", wrong_revision),
        ("work root", no_work_root),
        ("deadlines", inverted),
    ] {
        let error = config.validate().expect_err(what);
        assert!(
            matches!(&error, ProbeError::Config { detail } if detail.contains(what)),
            "{what}: {error:?}"
        );
    }
}

fn entry_of(behavior: StubBehavior, id: u8, deadline: Duration) -> RegisteredCase {
    let id = ConformanceCaseId::new(id);
    RegisteredCase {
        module: CaseModule::owner_of(id),
        case: Arc::new(StubCase {
            id,
            name: "stub_case",
            deadline,
            behavior,
        }),
    }
}

#[tokio::test(start_paused = true)]
async fn a_timed_out_case_is_terminated_before_run_case_returns() {
    let scratch = tempfile::tempdir().expect("tempdir");
    let active = Arc::new(AtomicBool::new(false));
    let mutated = Arc::new(AtomicBool::new(false));
    let entry = entry_of(
        StubBehavior::DeadlineMutation {
            active: Arc::clone(&active),
            mutated: Arc::clone(&mutated),
            delay: Duration::from_millis(250),
        },
        1,
        Duration::from_millis(50),
    );
    let result = run_case(&entry, test_context(1, scratch.path()), None).await;

    assert_eq!(result.status, CaseStatus::Fail);
    assert!(result
        .failures
        .iter()
        .any(|failure| failure.check == "deadline"));
    assert!(
        result.summary.contains("its deadline of 50 ms"),
        "{}",
        result.summary
    );
    assert!(
        !active.load(Ordering::SeqCst),
        "the case task outlived its terminal result"
    );
    // Well past the delay the aborted body must still never have run on.
    time::sleep(Duration::from_millis(300)).await;
    assert!(!active.load(Ordering::SeqCst));
    assert!(
        !mutated.load(Ordering::SeqCst),
        "the aborted case task kept running"
    );
}

#[tokio::test]
async fn a_panicking_case_body_fails_the_case_instead_of_the_suite() {
    let scratch = tempfile::tempdir().expect("tempdir");
    let entry = entry_of(StubBehavior::Panic, 1, Duration::from_secs(5));
    let result = run_case(&entry, test_context(1, scratch.path()), None).await;
    assert_eq!(result.status, CaseStatus::Fail);
    assert!(result
        .failures
        .iter()
        .any(|failure| failure.check == "panic"));
}

#[tokio::test]
async fn evidence_over_budget_fails_the_case_and_writes_nothing() {
    let scratch = tempfile::tempdir().expect("tempdir");
    for (name, items) in [
        (
            "too many artifacts",
            (0..=MAX_CASE_ARTIFACTS)
                .map(|index| (format!("item {index}"), vec![b'x']))
                .collect::<Vec<_>>(),
        ),
        (
            "one oversized artifact",
            vec![(
                "big".to_owned(),
                vec![b'x'; MAX_EVIDENCE_ARTIFACT_BYTES + 1],
            )],
        ),
    ] {
        let entry = entry_of(StubBehavior::Evidence(items), 1, Duration::from_secs(5));
        let result = run_case(&entry, test_context(1, scratch.path()), None).await;
        assert_eq!(result.status, CaseStatus::Fail, "{name}");
        assert!(
            result
                .failures
                .iter()
                .any(|failure| failure.check == "evidence_budget"),
            "{name}"
        );
        assert!(result.evidence.is_empty(), "{name}");
    }
}
