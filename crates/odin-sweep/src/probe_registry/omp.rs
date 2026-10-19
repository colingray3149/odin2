//! INT-OMP: the pinned-OMP conformance suite.

use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use odin_atlas::{build as build_atlas, AtlasSources};
use odin_huginn::RuntimeManifest;
use odin_kernel::StopAuthority;
use odin_ledger::Ledger;
use odin_omp::probe::{
    run_suite, CaseStatus, FaultFixtureRuntime, OmpLaunchTemplate, ProbeConfig, ProbeVerdict,
    SuiteDeadlines, PINNED_OMP_SOURCE_REVISION,
};
use odin_omp::process::OmpWorkerLaunch;
use odin_process::{
    BusAddress, RegisteredServiceBinding, ScopeLifetime, ScopeLimits, WorkerChannel,
};
use odin_types::CorrelationId;

use crate::report::{CheckResult, CheckStatus};
use crate::syscheck::SystemContext;

use super::{elapsed_ms, OMP_CHECK_ID};

const OMP_CHECK_NAME: &str = "OMP bridge conformance";

const OMP_WORK_DIR: &str = "omp-conformance";
const OMP_AUTHORITY_LEDGER: &str = "worker-authority.sqlite3";
const OMP_LAUNCH_OWNER: &str = "sweep-integration";
const OMP_WORKER_RUNTIME_MAX: Duration = Duration::from_secs(960);

pub(super) fn omp_conformance_check(context: &SystemContext) -> CheckResult {
    let started = Instant::now();
    let Some(manifest_path) = context.runtime_manifest.as_ref() else {
        return CheckResult::new(
            OMP_CHECK_ID,
            OMP_CHECK_NAME,
            CheckStatus::Blocked,
            elapsed_ms(started),
            "not run: no configured runtime manifest",
            Vec::new(),
        )
        .with_reason(
            "the pinned-OMP conformance suite requires a configured composition runtime \
             manifest (odin.runtime-manifest.v1) binding omp, bun, worker_bootstrap, and \
             unshare plus the packaged odind config; it never falls back to discovery",
        );
    };
    let manifest_display = manifest_path.display().to_string();
    match run_omp_conformance(context, manifest_path) {
        Ok((summary, mut evidence)) => {
            evidence.insert(0, format!("runtime manifest: {manifest_display}"));
            CheckResult::new(
                OMP_CHECK_ID,
                OMP_CHECK_NAME,
                CheckStatus::Pass,
                elapsed_ms(started),
                summary,
                evidence,
            )
        }
        Err(reason) => CheckResult::new(
            OMP_CHECK_ID,
            OMP_CHECK_NAME,
            CheckStatus::Fail,
            elapsed_ms(started),
            "OMP conformance suite rejected",
            vec![format!("runtime manifest: {manifest_display}")],
        )
        .with_reason(reason),
    }
}

fn run_omp_conformance(
    context: &SystemContext,
    manifest_path: &Path,
) -> Result<(String, Vec<String>), String> {
    let runtime = RuntimeManifest::load(manifest_path)
        .map_err(|error| format!("runtime manifest rejected: {error}"))?;
    let odind_config_path = runtime.odind_config.path.clone();
    let daemon = runtime.load_config().map_err(|error| {
        format!(
            "packaged odind config {} rejected: {error}",
            odind_config_path.display()
        )
    })?;
    let bus = BusAddress::parse(&daemon.worker_bus)
        .map_err(|error| format!("worker bus endpoint rejected: {error}"))?;
    let worker_bootstrap = manifest_executable(&runtime, "worker_bootstrap")?;
    let unshare = manifest_executable(&runtime, "unshare")?;
    let channel = WorkerChannel::new(bus, worker_bootstrap, unshare)
        .map_err(|error| format!("worker channel rejected: {error}"))?;

    let suite_root = context.scratch_root.join(OMP_WORK_DIR);
    fs::create_dir_all(&suite_root).map_err(|error| {
        format!(
            "could not create the disposable conformance root {}: {error}",
            suite_root.display()
        )
    })?;
    let authority_ledger = Ledger::open(suite_root.join(OMP_AUTHORITY_LEDGER))
        .map_err(|error| format!("authority ledger rejected: {error}"))?;
    let authority = Arc::new(StopAuthority::new(
        Arc::new(Mutex::new(authority_ledger)),
        channel,
    ));
    let correlation =
        CorrelationId::new(&blake3::hash(OMP_CHECK_ID.as_bytes()).to_hex().as_str()[..32])
            .map_err(|error| format!("correlation identity rejected: {error}"))?;

    let omp_executable = manifest_executable(&runtime, "omp")?;
    let bun_executable = manifest_executable(&runtime, "bun")?;
    let child_env = integration_child_env(&suite_root)?;
    let atlas = Arc::new(
        build_atlas(AtlasSources::new(&context.odin_root)).map_err(|error| {
            format!(
                "could not build the bounded Atlas snapshot from {}: {error}",
                context.odin_root.display()
            )
        })?,
    );
    let work_root = suite_root.join("suite");
    let config = ProbeConfig {
        omp: OmpLaunchTemplate {
            executable: omp_executable.clone(),
            worker: worker_launch(&authority, &correlation, &runtime, "omp")?,
            explicit_args: Vec::new(),
            explicit_env: child_env.clone(),
            expected_source_revision: PINNED_OMP_SOURCE_REVISION.to_owned(),
            startup_timeout: Duration::from_secs(30),
            drain_timeout: Duration::from_secs(10),
            kill_timeout: Duration::from_secs(5),
        },
        fault: FaultFixtureRuntime {
            bun: bun_executable,
            worker: worker_launch(&authority, &correlation, &runtime, "bun")?,
            explicit_env: child_env,
        },
        fixture_root: context.odin_root.join("crates/odin-omp/fixtures"),
        work_root: work_root.clone(),
        atlas,
        deadlines: SuiteDeadlines::default(),
    };

    let tokio_runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|error| format!("could not start the suite runtime: {error}"))?;
    let report = tokio_runtime
        .block_on(run_suite(config))
        .map_err(|error| format!("OMP conformance suite failed to run: {error}"))?;

    let total = report.cases.len();
    let passed = report
        .cases
        .iter()
        .filter(|case| case.status == CaseStatus::Pass)
        .count();
    let evidence = vec![
        format!("pinned OMP executable: {}", omp_executable.display()),
        format!("expected OMP source revision: {PINNED_OMP_SOURCE_REVISION}"),
        format!("suite schema: {}", report.schema),
        format!("report digest: {}", report.digest()),
        format!("retained case work root: {}", work_root.display()),
    ];
    if report.verdict != ProbeVerdict::Accept {
        let failing: Vec<String> = report
            .cases
            .iter()
            .filter(|case| case.status == CaseStatus::Fail)
            // Include failure details because disposable suite scratch is removed after the run.
            .map(|case| match case.failures.first() {
                Some(failure) => format!(
                    "{} {} [{}: {}]",
                    case.id,
                    case.name,
                    failure.check,
                    failure.detail.chars().take(400).collect::<String>()
                ),
                None => format!("{} {}", case.id, case.name),
            })
            .collect();
        return Err(format!(
            "{passed}/{total} conformance cases passed against pinned OMP {}; failing: {}",
            omp_executable.display(),
            failing.join("; "),
        ));
    }
    Ok((
        format!(
            "all {total} conformance cases passed against pinned OMP {}",
            omp_executable.display()
        ),
        evidence,
    ))
}

/// Launches one digest-verified runtime-manifest executable under the suite's
/// StopAuthority, mirroring the retained production launch contract.
fn worker_launch(
    authority: &Arc<StopAuthority>,
    correlation: &CorrelationId,
    runtime: &RuntimeManifest,
    id: &str,
) -> Result<OmpWorkerLaunch, String> {
    let executable = runtime.executable(id).map_err(|error| error.to_string())?;
    let digest = executable
        .digest
        .strip_prefix("blake3:")
        .ok_or_else(|| format!("runtime manifest executable {id} lacks a blake3 binding digest"))?;
    let binding = RegisteredServiceBinding::new(executable.path.clone(), digest.to_owned())
        .map_err(|error| format!("runtime manifest executable {id} binding rejected: {error}"))?;
    OmpWorkerLaunch::new(
        Arc::clone(authority),
        correlation.clone(),
        OMP_LAUNCH_OWNER.to_owned(),
        format!("omp-conformance-{id}"),
        1,
        binding,
        ScopeLimits {
            lifetime: ScopeLifetime::Bounded(OMP_WORKER_RUNTIME_MAX),
            timeout_stop: Duration::from_secs(5),
            ..ScopeLimits::default()
        },
    )
    .map_err(|error| format!("runtime manifest executable {id} launch rejected: {error}"))
}

fn manifest_executable(runtime: &RuntimeManifest, id: &str) -> Result<PathBuf, String> {
    let executable = runtime.executable(id).map_err(|error| error.to_string())?;
    Ok(executable.path.clone())
}

/// The disposable child environment for the conformance suite. The shared
/// runner helper owns the disposable HOME/XDG layout, rooted under the
/// integration scratch tree, including `XDG_RUNTIME_DIR`; the child
/// additionally receives the caller's PATH plus a deterministic locale and
/// user identity. Nothing is discovered outside the scratch tree.
fn integration_child_env(suite_root: &Path) -> Result<Vec<(String, String)>, String> {
    let data_home = suite_root.join("data");
    fs::create_dir_all(&data_home)
        .map_err(|error| format!("could not create isolated OMP data: {error}"))?;
    let mut env_probe = Command::new("true");
    crate::runner::configure_command(&mut env_probe, suite_root)?;
    env_probe.env("XDG_DATA_HOME", data_home);
    let mut child_env: Vec<(String, String)> = env_probe
        .get_envs()
        .filter_map(|(key, value)| {
            let value = value?;
            Some((
                key.to_string_lossy().into_owned(),
                value.to_string_lossy().into_owned(),
            ))
        })
        .collect();
    child_env.push((
        "PATH".to_owned(),
        env::var("PATH").map_err(|error| format!("probe child PATH is unavailable: {error}"))?,
    ));
    child_env.push(("TERM".to_owned(), "dumb".to_owned()));
    child_env.push(("LANG".to_owned(), "C.UTF-8".to_owned()));
    child_env.push(("LC_ALL".to_owned(), "C.UTF-8".to_owned()));
    child_env.push(("USER".to_owned(), OMP_LAUNCH_OWNER.to_owned()));
    child_env.push(("LOGNAME".to_owned(), OMP_LAUNCH_OWNER.to_owned()));
    Ok(child_env)
}
