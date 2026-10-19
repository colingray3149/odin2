//! Suite configuration for the probe: the pinned source revision, pinned
//! package version resolution, fixture vocabulary, the OMP and fault-fixture
//! launch templates, per-case and whole-suite deadlines, and the assembled
//! configuration with its validation and pin evidence.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use odin_atlas::Atlas;

use crate::process::{OmpProcessSpec, OmpWorkerLaunch};

use super::contracts::{ProbeError, ProbePin};
use super::digest_hex;

/// Revision baked from the same flake input that builds OMP; missing identity fails compilation.
/// Case 1 checks the executable against this revision.
pub const PINNED_OMP_SOURCE_REVISION: &str = match option_env!("ODIN_PINNED_OMP_SOURCE_REVISION") {
    Some(revision) => revision,
    None => panic!(
        "ODIN_PINNED_OMP_SOURCE_REVISION is not baked: build through the odin flake \
             or a shell exporting the pinned omp input revision; the expected source \
             revision must never be a second literal"
    ),
};

/// Reads the pinned package version from the build or shell environment.
/// Missing identity is a configuration error; no fallback version is assumed.
pub fn pinned_omp_version() -> Result<String, ProbeError> {
    if let Ok(version) = std::env::var("ODIN_PINNED_OMP_VERSION") {
        return Ok(version);
    }
    if let Some(baked) = option_env!("ODIN_PINNED_OMP_VERSION") {
        return Ok(baked.to_owned());
    }
    Err(ProbeError::Config {
        detail: "ODIN_PINNED_OMP_VERSION is not set: the expected OMP version must \
                 derive from the nix-pinned stock OMP package, never a second literal"
            .to_owned(),
    })
}

/// File name of the pinned-OMP provider fixture under [`ProbeConfig::fixture_root`].
pub const PROVIDER_FIXTURE_FILE: &str = "mock-provider.ts";
/// File name of the RPC transport fault fixture under [`ProbeConfig::fixture_root`].
pub const FAULT_FIXTURE_FILE: &str = "rpc-fault-fixture.ts";

/// Provider name the fixture extension registers inside the pinned child.
pub const FIXTURE_PROVIDER: &str = "odin-mock";
/// First fixture model id; the default launch selects it.
pub const FIXTURE_MODEL_A: &str = "mock-a";
/// Second fixture model id; case 10 switches between the two.
pub const FIXTURE_MODEL_B: &str = "mock-b";
/// Default `--model` selector for fixture launches.
pub const DEFAULT_MODEL_SELECTOR: &str = "odin-mock/mock-a";
/// Local slash command the fixture extension registers.
pub const FIXTURE_COMMAND: &str = "odin-fixture";

/// Read cap for digesting a fixture file into the probe pin.
const MAX_FIXTURE_BYTES: usize = 1024 * 1024;

/// Startup bound for the fault fixture child.
const FAULT_STARTUP_TIMEOUT: Duration = Duration::from_secs(10);
/// Drain bound for the fault fixture child.
const FAULT_DRAIN_TIMEOUT: Duration = Duration::from_secs(10);
/// Forced-kill bound for the fault fixture child.
const FAULT_KILL_TIMEOUT: Duration = Duration::from_secs(5);

/// Host-owned OMP launch template: every field of an [`OmpProcessSpec`] except
/// the per-case working directory and the fixture/model arguments the harness
/// appends, plus the sole StopAuthority worker contract.
#[derive(Clone)]
pub struct OmpLaunchTemplate {
    /// Trusted pinned-OMP executable.
    pub executable: PathBuf,
    /// Complete host-owned argument list beyond the harness-appended
    /// `--extension`/`--model` pair (never `--mode`).
    pub explicit_args: Vec<String>,
    /// Complete sanitized child environment; nothing is inherited.
    pub explicit_env: Vec<(String, String)>,
    /// Must equal [`PINNED_OMP_SOURCE_REVISION`].
    pub expected_source_revision: String,
    /// Startup handshake bound.
    pub startup_timeout: Duration,
    /// Graceful drain bound.
    pub drain_timeout: Duration,
    /// Forced-kill bound.
    pub kill_timeout: Duration,
    /// Sole StopAuthority launch/stop contract.
    pub worker: OmpWorkerLaunch,
}

impl OmpLaunchTemplate {
    /// Builds the full child spec for one case working directory, appending
    /// `extra_args` after the template arguments.
    pub fn spec_for(&self, cwd: PathBuf, extra_args: Vec<String>) -> OmpProcessSpec {
        let mut explicit_args = self.explicit_args.clone();
        explicit_args.extend(extra_args);
        OmpProcessSpec {
            executable: self.executable.clone(),
            cwd,
            explicit_args,
            explicit_env: self.explicit_env.clone(),
            expected_source_revision: self.expected_source_revision.clone(),
            startup_timeout: self.startup_timeout,
            drain_timeout: self.drain_timeout,
            kill_timeout: self.kill_timeout,
        }
    }
}

/// Bun runtime that executes the RPC transport fault fixture.
#[derive(Clone)]
pub struct FaultFixtureRuntime {
    /// Trusted Bun executable.
    pub bun: PathBuf,
    /// Complete sanitized environment for the fixture child.
    pub explicit_env: Vec<(String, String)>,
    /// Sole StopAuthority launch/stop contract for the Bun executable.
    pub worker: OmpWorkerLaunch,
}

impl FaultFixtureRuntime {
    /// Builds the child spec launching `script` under Bun in `cwd`.
    pub fn spec_for(
        &self,
        script: PathBuf,
        cwd: PathBuf,
        script_args: Vec<String>,
    ) -> OmpProcessSpec {
        let mut explicit_args = vec![script.to_string_lossy().into_owned()];
        explicit_args.extend(script_args);
        OmpProcessSpec {
            executable: self.bun.clone(),
            cwd,
            explicit_args,
            explicit_env: self.explicit_env.clone(),
            // The fixture speaks the pinned protocol; the pin is retained as
            // identity evidence exactly as for the real child.
            expected_source_revision: PINNED_OMP_SOURCE_REVISION.to_owned(),
            startup_timeout: FAULT_STARTUP_TIMEOUT,
            drain_timeout: FAULT_DRAIN_TIMEOUT,
            kill_timeout: FAULT_KILL_TIMEOUT,
        }
    }
}

/// Per-case and whole-suite wall-clock bounds.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SuiteDeadlines {
    /// Deadline available to a case that does not need a tighter one
    /// (`CaseContext::default_case_deadline`).
    pub default_case: Duration,
    /// Whole-suite cap; once exhausted, remaining cases are recorded as
    /// `suite_deadline` failures without being run.
    pub suite: Duration,
}

impl Default for SuiteDeadlines {
    /// 120 s per case, 1200 s per suite.
    fn default() -> Self {
        Self {
            default_case: Duration::from_secs(120),
            suite: Duration::from_secs(1200),
        }
    }
}

#[derive(Clone)]
pub struct ProbeConfig {
    /// Pinned-OMP launch template.
    pub omp: OmpLaunchTemplate,
    /// Bun runtime for the fault fixture.
    pub fault: FaultFixtureRuntime,
    /// Directory holding the two TypeScript fixtures.
    pub fixture_root: PathBuf,
    /// Suite work root; per-case work dirs live under `work_root/cases/` and
    /// are retained as evidence after the run.
    pub work_root: PathBuf,
    /// Immutable atlas snapshot behind `odin_atlas_query` and `atlas://`.
    pub atlas: Arc<Atlas>,
    /// Per-case and suite bounds.
    pub deadlines: SuiteDeadlines,
}

impl ProbeConfig {
    /// Assembles a configuration with the crate-shipped fixture root and the
    /// default deadlines; adjust the public fields before `validate`.
    pub fn new(
        omp: OmpLaunchTemplate,
        fault: FaultFixtureRuntime,
        work_root: PathBuf,
        atlas: Arc<Atlas>,
    ) -> Self {
        Self {
            omp,
            fault,
            fixture_root: default_fixture_root(),
            work_root,
            atlas,
            deadlines: SuiteDeadlines::default(),
        }
    }

    pub fn provider_fixture_path(&self) -> PathBuf {
        self.fixture_root.join(PROVIDER_FIXTURE_FILE)
    }

    pub fn fault_fixture_path(&self) -> PathBuf {
        self.fixture_root.join(FAULT_FIXTURE_FILE)
    }

    /// Validates the configuration before any process or ledger effect: the
    /// launch templates must satisfy the process boundary's own validation and
    /// the configured revision must be the exact pin.
    pub fn validate(&self) -> Result<(), ProbeError> {
        if self.omp.expected_source_revision != PINNED_OMP_SOURCE_REVISION {
            return Err(ProbeError::Config {
                detail: format!(
                    "expected_source_revision `{}` is not the pinned {PINNED_OMP_SOURCE_REVISION}",
                    self.omp.expected_source_revision
                ),
            });
        }
        if self.work_root.as_os_str().is_empty() {
            return Err(ProbeError::Config {
                detail: "work root is empty".to_owned(),
            });
        }
        if self.deadlines.default_case.is_zero()
            || self.deadlines.suite.is_zero()
            || self.deadlines.suite < self.deadlines.default_case
        {
            return Err(ProbeError::Config {
                detail: "deadlines must be positive with suite >= default_case".to_owned(),
            });
        }
        self.omp
            .spec_for(self.work_root.clone(), Vec::new())
            .validate()
            .map_err(|error| ProbeError::Config {
                detail: format!("omp launch template: {error}"),
            })?;
        self.fault
            .spec_for(
                self.fault_fixture_path(),
                self.work_root.clone(),
                Vec::new(),
            )
            .validate()
            .map_err(|error| ProbeError::Config {
                detail: format!("fault fixture runtime: {error}"),
            })?;
        Ok(())
    }

    /// Records the pin evidence: configured executable and revision plus the
    /// content digests of both fixtures.
    pub fn probe_pin(&self) -> Result<ProbePin, ProbeError> {
        Ok(ProbePin {
            omp_executable: self.omp.executable.clone(),
            expected_source_revision: self.omp.expected_source_revision.clone(),
            provider_fixture_digest: digest_file(&self.provider_fixture_path())?,
            fault_fixture_digest: digest_file(&self.fault_fixture_path())?,
        })
    }
}

/// The crate-shipped fixture directory.
pub fn default_fixture_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures")
}

/// Bounded read + BLAKE3 hex digest of a fixture file.
fn digest_file(path: &Path) -> Result<String, ProbeError> {
    let bytes = std::fs::read(path).map_err(|error| ProbeError::Fixture {
        detail: format!("{}: {error}", path.display()),
    })?;
    if bytes.len() > MAX_FIXTURE_BYTES {
        return Err(ProbeError::Fixture {
            detail: format!(
                "{}: {} bytes exceed the {MAX_FIXTURE_BYTES}-byte fixture cap",
                path.display(),
                bytes.len()
            ),
        });
    }
    Ok(digest_hex(&bytes))
}
