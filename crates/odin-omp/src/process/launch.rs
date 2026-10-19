//! Registered StopAuthority launch: trusted spec validation, the host-owned
//! `OmpWorkerLaunch` contract, the registered-service spawn, and the bounded
//! `--version` identity probe. Every launch and every stop stays behind
//! StopAuthority; there is no direct spawn and no PID/PGID/unit authority.
//! The types implemented here are defined by the `process` parent module.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering;

use async_trait::async_trait;
use odin_domain::StopVerdict;
use odin_kernel::WorkerLaunch;
use odin_process::{
    mint_worker_id, CommandSpec, EnvironmentBuilder, FrozenArgv, WorkerNaming, CORRELATION_ENV,
};
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::time::timeout;

use super::streams::{drain_stderr, join_drainer, snapshot_tail};
use super::*;

/// Ceiling for `--version` output of the trusted executable.
const VERSION_OUTPUT_LIMIT: usize = 4096;

/// Read-chunk size for the bounded `--version` capture.
const PROBE_READ_CHUNK: usize = 4096;

/// The host-owned OMP run mode appended to every spec.
pub(super) const HOST_MODE_ARGS: [&str; 2] = ["--mode", "rpc"];
/// Frozen argv item ceiling for registered OMP launch.
const ARGV_ITEM_CAP: usize = 128;
/// Frozen argv byte ceiling for registered OMP launch.
const ARGV_BYTE_CAP: usize = 1024 * 1024;

impl OmpProcessSpec {
    /// Validates the trusted launch description before it becomes a process.
    ///
    /// Rejects host-mode duplication, NUL bytes, empty or malformed
    /// environment names, and zero timeouts, which would make the
    /// bounded-lifecycle guarantees vacuous.
    pub fn validate(&self) -> Result<(), OmpProcessError> {
        if self.executable.as_os_str().is_empty() {
            return Err(invalid_spec("executable path is empty"));
        }
        if self.cwd.as_os_str().is_empty() {
            return Err(invalid_spec("cwd is empty"));
        }
        if self.startup_timeout.is_zero()
            || self.drain_timeout.is_zero()
            || self.kill_timeout.is_zero()
        {
            return Err(invalid_spec(
                "startup, drain, and kill timeouts must be positive",
            ));
        }
        if self.expected_source_revision.len() != 40
            || !self
                .expected_source_revision
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(invalid_spec(
                "expected source revision must be a 40-character lowercase hexadecimal commit id",
            ));
        }
        for argument in &self.explicit_args {
            if contains_nul(argument) {
                return Err(invalid_spec("arguments must not contain NUL bytes"));
            }
            if argument == "--mode" || argument.starts_with("--mode=") {
                return Err(invalid_spec(
                    "the run mode is host-owned; explicit args must not set --mode",
                ));
            }
        }
        let mut environment_names = BTreeSet::new();
        for (name, value) in &self.explicit_env {
            if name.is_empty() || name.contains('=') {
                return Err(invalid_spec(
                    "environment variable names must be non-empty and contain no '='",
                ));
            }
            if contains_nul(name) || contains_nul(value) {
                return Err(invalid_spec(
                    "environment variables must not contain NUL bytes",
                ));
            }
            if !environment_names.insert(name.as_str()) {
                return Err(invalid_spec(format!(
                    "environment variable `{name}` is declared more than once"
                )));
            }
        }
        Ok(())
    }

    /// Appends exactly one `--mode rpc` pair for either transport.
    pub(crate) fn launch_args(&self) -> impl Iterator<Item = String> + '_ {
        self.explicit_args
            .iter()
            .cloned()
            .chain(HOST_MODE_ARGS.into_iter().map(|value| value.to_owned()))
    }

    /// Validates the executable and captures `--version` under startup and output limits.
    /// The configured revision is retained verbatim; conformance checks the pin separately.
    pub async fn establish_identity(
        &self,
        worker: &OmpWorkerLaunch,
    ) -> Result<OmpExecutableIdentity, OmpProcessError> {
        self.validate()?;
        let canonical = canonicalize_executable(&self.executable)?;
        if canonical != worker.binding.executable() {
            return Err(invalid_spec(format!(
                "process executable {} does not match registered binding {}",
                canonical.display(),
                worker.binding.executable().display()
            )));
        }
        let captured = probe_version(&canonical, self, worker).await?;
        let version = match std::str::from_utf8(&captured.stdout) {
            Ok(version) => version.trim(),
            Err(_) => {
                return Err(OmpProcessError::VersionProbe {
                    detail: "--version output is not valid utf-8".to_owned(),
                    stderr_tail: captured.stderr,
                });
            }
        };
        if version.is_empty() {
            return Err(OmpProcessError::VersionProbe {
                detail: "--version printed no version text".to_owned(),
                stderr_tail: captured.stderr,
            });
        }
        Ok(OmpExecutableIdentity {
            canonical_path: canonical,
            source_revision: self.expected_source_revision.clone(),
            version: version.to_owned(),
        })
    }
}

impl OmpWorkerLaunch {
    /// `tx_id` and `wp_id` require safe identifier characters for unit names.
    pub fn new(
        authority: Arc<StopAuthority>,
        correlation_id: CorrelationId,
        tx_id: impl Into<String>,
        wp_id: impl Into<String>,
        attempt: u32,
        binding: RegisteredServiceBinding,
        limits: ScopeLimits,
    ) -> Result<Self, OmpProcessError> {
        let tx_id = tx_id.into();
        let wp_id = wp_id.into();
        for (role, value) in [("tx_id", tx_id.as_str()), ("wp_id", wp_id.as_str())] {
            if value.is_empty() {
                return Err(invalid_spec(format!("{role} must not be empty")));
            }
            if !value.chars().all(odin_types::ids::is_safe) {
                return Err(invalid_spec(format!(
                    "{role} {value:?} must use the safe identifier charset"
                )));
            }
        }
        Ok(Self {
            authority,
            correlation_id,
            tx_id,
            wp_id,
            attempt: Arc::new(AtomicU32::new(attempt)),
            binding,
            limits,
            #[cfg(test)]
            _test_fixture: None,
        })
    }

    pub(crate) fn next_naming(&self) -> Result<WorkerNaming, OmpProcessError> {
        let worker_id = mint_worker_id().map_err(map_spawn)?;
        let attempt = self.attempt.fetch_add(1, Ordering::Relaxed);
        WorkerNaming::new(&self.tx_id, &self.wp_id, attempt, worker_id).map_err(map_spawn)
    }
}

impl OmpExecutableIdentity {
    /// Canonical absolute path the trusted config resolved to.
    pub fn canonical_path(&self) -> &Path {
        &self.canonical_path
    }

    /// The configured exact OMP source revision, retained verbatim.
    pub fn source_revision(&self) -> &str {
        &self.source_revision
    }

    /// Trimmed stdout of the bounded `--version` probe.
    pub fn version(&self) -> &str {
        &self.version
    }
}

fn map_spawn(error: impl std::fmt::Display) -> OmpProcessError {
    OmpProcessError::SpawnFailed {
        detail: error.to_string(),
    }
}

pub(super) fn spawn_registered(
    worker: &OmpWorkerLaunch,
    args: &[String],
    env: &[(String, String)],
    cwd: &Path,
) -> Result<WorkerLaunch, OmpProcessError> {
    let naming = worker.next_naming()?;
    let argv =
        FrozenArgv::new(args.iter().cloned(), ARGV_ITEM_CAP, ARGV_BYTE_CAP).map_err(map_spawn)?;
    if Path::new(argv.executable()) != worker.binding.executable() {
        return Err(invalid_spec(
            "argv executable does not match the registered service binding",
        ));
    }
    let mut allowed: Vec<&str> = env.iter().map(|(name, _)| name.as_str()).collect();
    if !allowed.contains(&CORRELATION_ENV) {
        allowed.push(CORRELATION_ENV);
    }
    let mut builder = EnvironmentBuilder::new(allowed).map_err(map_spawn)?;
    for (name, value) in env {
        if name == CORRELATION_ENV && value != worker.correlation_id.as_str() {
            return Err(invalid_spec(
                "payload correlation does not match the durable correlation",
            ));
        }
        builder = builder.set(name, value).map_err(map_spawn)?;
    }
    builder = builder
        .set(CORRELATION_ENV, worker.correlation_id.as_str())
        .map_err(map_spawn)?;
    let spec = CommandSpec {
        argv,
        environment: builder.build(),
        current_dir: cwd.to_path_buf(),
    };
    worker
        .authority
        .launch_registered_service(
            naming,
            &worker.correlation_id,
            &spec,
            worker.limits,
            &worker.binding,
        )
        .map_err(map_spawn)
}

/// The local carrier's stdin half: logical StopAuthority writes for the
/// registered worker, wrapped so the process boundary is transport-blind.
/// The exact error text of the authority surfaces unchanged inside the
/// mapped I/O error.
pub(super) struct AuthorityStdin {
    authority: Arc<StopAuthority>,
    worker_id: WorkerId,
}

impl AuthorityStdin {
    pub(super) fn new(authority: Arc<StopAuthority>, worker_id: WorkerId) -> Self {
        Self {
            authority,
            worker_id,
        }
    }
}

#[async_trait]
impl HarnessStdin for AuthorityStdin {
    async fn write_all(&mut self, bytes: Vec<u8>) -> std::io::Result<()> {
        let authority = Arc::clone(&self.authority);
        let worker_id = self.worker_id.clone();
        match tokio::task::spawn_blocking(move || authority.write_worker_stdin(&worker_id, &bytes))
            .await
        {
            Ok(Ok(())) => Ok(()),
            Ok(Err(error)) => Err(std::io::Error::other(error.to_string())),
            Err(error) => Err(std::io::Error::other(format!(
                "stdin write task failed: {error}"
            ))),
        }
    }

    fn shutdown(self: Box<Self>) -> std::io::Result<()> {
        self.authority
            .close_worker_stdin(&self.worker_id)
            .map_err(|error| std::io::Error::other(error.to_string()))
    }
}

/// Captured `--version` output of the trusted executable.
struct CapturedVersion {
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

/// Runs one bounded `--version` probe through StopAuthority and returns
/// the byte-capped stdout plus the bounded stderr tail. Every wait stays
/// inside the configured budgets: StopAuthority covers the reap and the
/// drainer join, so a descendant holding stderr open can never hang the
/// probe past `startup_timeout` plus `kill_timeout`.
async fn probe_version(
    executable: &Path,
    spec: &OmpProcessSpec,
    worker: &OmpWorkerLaunch,
) -> Result<CapturedVersion, OmpProcessError> {
    let args = vec![
        executable.to_string_lossy().into_owned(),
        "--version".to_owned(),
    ];
    let launched =
        spawn_registered(worker, &args, &spec.explicit_env, &spec.cwd).map_err(|error| {
            OmpProcessError::VersionProbe {
                detail: error.to_string(),
                stderr_tail: Vec::new(),
            }
        })?;
    let worker_id = launched.identity.worker_id.clone();
    let mut stdout =
        async_pipe(launched.stdout).map_err(|error| OmpProcessError::VersionProbe {
            detail: format!("stdout pipe is not async: {error}"),
            stderr_tail: Vec::new(),
        })?;
    let stderr = async_pipe(launched.stderr).map_err(|error| OmpProcessError::VersionProbe {
        detail: format!("stderr pipe is not async: {error}"),
        stderr_tail: Vec::new(),
    })?;
    let _ = worker.authority.close_worker_stdin(&worker_id);
    let tail = Arc::new(Mutex::new(Vec::new()));
    let drainer = tokio::spawn(drain_stderr(stderr, Arc::clone(&tail)));
    let capture = async { read_bounded_to_eof(&mut stdout, VERSION_OUTPUT_LIMIT).await };
    let captured = timeout(spec.startup_timeout, capture).await;
    let stop = {
        let authority = Arc::clone(&worker.authority);
        let id = worker_id.clone();
        timeout(
            spec.kill_timeout,
            tokio::task::spawn_blocking(move || authority.stop_worker(&id)),
        )
        .await
    };
    join_drainer(drainer, spec.kill_timeout).await;
    let stderr_tail = snapshot_tail(&tail);
    match stop {
        Ok(Ok(Ok(outcome))) if outcome.verdict == StopVerdict::Stopped => {}
        Ok(Ok(Ok(outcome))) => {
            return Err(OmpProcessError::VersionProbe {
                detail: format!("version probe stop did not complete: {:?}", outcome.verdict),
                stderr_tail,
            })
        }
        Ok(Ok(Err(error))) => {
            return Err(OmpProcessError::VersionProbe {
                detail: format!("version probe stop failed: {error}"),
                stderr_tail,
            })
        }
        Ok(Err(error)) => {
            return Err(OmpProcessError::VersionProbe {
                detail: format!("version probe stop task failed: {error}"),
                stderr_tail,
            })
        }
        Err(_) => {
            return Err(OmpProcessError::VersionProbe {
                detail: "version probe stop exceeded kill timeout".to_owned(),
                stderr_tail,
            })
        }
    };
    match captured {
        Ok(Ok((stdout_bytes, stdout_total))) => {
            if stdout_total > VERSION_OUTPUT_LIMIT as u64 {
                return Err(OmpProcessError::VersionProbe {
                    detail: format!(
                        "printed {stdout_total} bytes, above the {VERSION_OUTPUT_LIMIT}-byte limit"
                    ),
                    stderr_tail,
                });
            }
            Ok(CapturedVersion {
                stdout: stdout_bytes,
                stderr: stderr_tail,
            })
        }
        Ok(Err(error)) => Err(OmpProcessError::VersionProbe {
            detail: format!("capture failed: {error}"),
            stderr_tail,
        }),
        Err(_elapsed) => Err(OmpProcessError::VersionProbe {
            detail: format!("did not exit within {:?}", spec.startup_timeout),
            stderr_tail,
        }),
    }
}

/// Reads a bounded stream to EOF, keeping at most `cap` leading bytes and
/// counting everything received.
async fn read_bounded_to_eof<R: AsyncRead + Unpin>(
    reader: &mut R,
    cap: usize,
) -> io::Result<(Vec<u8>, u64)> {
    let mut kept = Vec::new();
    let mut total: u64 = 0;
    let mut chunk = [0u8; PROBE_READ_CHUNK];
    loop {
        let read = reader.read(&mut chunk).await?;
        if read == 0 {
            return Ok((kept, total));
        }
        total += read as u64;
        if kept.len() < cap {
            let take = (cap - kept.len()).min(read);
            kept.extend_from_slice(&chunk[..take]);
        }
    }
}

/// Canonicalizes the trusted executable and proves it is an executable
/// regular file.
pub(super) fn canonicalize_executable(executable: &Path) -> Result<PathBuf, OmpProcessError> {
    let unavailable = |path: &Path, detail: String| OmpProcessError::ExecutableUnavailable {
        path: path.to_owned(),
        detail,
    };
    let canonical = fs::canonicalize(executable)
        .map_err(|error| unavailable(executable, format!("canonicalize failed: {error}")))?;
    let metadata = fs::metadata(&canonical)
        .map_err(|error| unavailable(&canonical, format!("stat failed: {error}")))?;
    if !metadata.is_file() {
        return Err(unavailable(&canonical, "not a regular file".to_owned()));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o111 == 0 {
            return Err(unavailable(
                &canonical,
                "no executable permission bit".to_owned(),
            ));
        }
    }
    Ok(canonical)
}

pub(super) fn invalid_spec(detail: impl Into<String>) -> OmpProcessError {
    OmpProcessError::InvalidSpec {
        detail: detail.into(),
    }
}

fn contains_nul(value: &str) -> bool {
    value.as_bytes().contains(&0)
}

/// The governed built-in tool exposure of one pinned-harness session launch:
/// the read tool and nothing else, with every environment-supplied surface
/// off. The read tool is what resolves `brain://` items and the other
/// registered host URI schemes through this host's scoped resolvers; the
/// trusted extension confines what that tool may target. Every other tool the
/// model may call arrives as a host tool through `set_host_tools`.
pub fn governed_harness_args(extension: &Path) -> Vec<String> {
    vec![
        "--trusted-extension".to_owned(),
        extension.display().to_string(),
        "--no-skills".to_owned(),
        "--no-rules".to_owned(),
        "--tools".to_owned(),
        "read".to_owned(),
        "--no-lsp".to_owned(),
        "--no-pty".to_owned(),
    ]
}

/// Exact libtest entry selected when the worker fixture re-executes this
/// crate's test harness as the real bootstrap.
#[cfg(test)]
const TEST_WORKER_BOOTSTRAP_ENTRY: &str = "process::tests::worker_bootstrap_fixture_entry";

/// Resolves a fixture program from an explicit override or the test runner's
/// PATH while retaining only an absolute file path.
#[cfg(test)]
fn absolute_fixture_tool(name: &str, env_key: &str) -> PathBuf {
    if let Some(value) = std::env::var_os(env_key) {
        let path = PathBuf::from(value);
        assert!(path.is_absolute(), "{env_key} must be an absolute path");
        assert!(path.is_file(), "{env_key} must name a file");
        return path;
    }
    let path_var = std::env::var_os("PATH").unwrap_or_default();
    std::env::split_paths(&path_var)
        .map(|directory| directory.join(name))
        .find(|candidate| candidate.is_absolute() && candidate.is_file())
        .unwrap_or_else(|| panic!("no absolute {name} found on PATH"))
}

#[cfg(test)]
static FIXTURE_UNSHARE_BIN: std::sync::LazyLock<PathBuf> =
    std::sync::LazyLock::new(|| absolute_fixture_tool("unshare", "ODIN_TEST_WORKER_UNSHARE"));

/// Builds the production StopAuthority launch contract over an in-memory
/// ledger and a private registered-worker broker. The guard is retained by
/// every launch clone, so its bus and cgroup fixture outlive worker teardown
/// without process-global environment mutation.
#[cfg(test)]
pub(super) fn launch_for_test_fixture(executable: &Path, wp_id: &str) -> OmpWorkerLaunch {
    launch_and_ledger_for_test_fixture(executable, wp_id).0
}

/// The same launch contract plus the in-memory ledger its authority settles
/// into: a test reads the worker rows the authority left nonterminal.
#[cfg(test)]
fn launch_and_ledger_for_test_fixture(
    executable: &Path,
    wp_id: &str,
) -> (OmpWorkerLaunch, Arc<Mutex<odin_ledger::Ledger>>) {
    let fixture = Arc::new(
        odin_process::test_support::RegisteredWorkerFixture::new()
            .expect("start isolated registered-worker fixture"),
    );
    let harness = std::env::current_exe().expect("test harness executable");
    let channel = fixture
        .channel_for_harness(
            &harness,
            TEST_WORKER_BOOTSTRAP_ENTRY,
            FIXTURE_UNSHARE_BIN.as_path(),
        )
        .expect("build isolated registered-worker channel");
    let canonical = fs::canonicalize(executable).expect("fixture executable");
    let digest = blake3::hash(&fs::read(&canonical).expect("hash fixture"))
        .to_hex()
        .to_string();
    let binding = RegisteredServiceBinding::new(canonical, digest).expect("fixture binding");
    let ledger = Arc::new(Mutex::new(
        odin_ledger::Ledger::open_in_memory().expect("in-memory ledger"),
    ));
    let authority = Arc::new(StopAuthority::new(Arc::clone(&ledger), channel));
    let correlation =
        CorrelationId::new("0123456789abcdef0123456789abcdef").expect("test correlation");
    let mut launch = OmpWorkerLaunch::new(
        authority,
        correlation,
        "odin-omp",
        wp_id,
        1,
        binding,
        ScopeLimits::default(),
    )
    .expect("fixture worker launch");
    launch._test_fixture = Some(fixture);
    (launch, ledger)
}

/// Crate-test helper used by sibling modules that need a real isolated worker.
#[cfg(test)]
pub(crate) fn launch_for_fixture(executable: &Path) -> OmpWorkerLaunch {
    launch_for_test_fixture(executable, "bridge-fixture")
}

/// [`launch_for_fixture`] plus its authority's ledger.
#[cfg(test)]
pub(crate) fn launch_with_ledger_for_fixture(
    executable: &Path,
) -> (OmpWorkerLaunch, Arc<Mutex<odin_ledger::Ledger>>) {
    launch_and_ledger_for_test_fixture(executable, "bridge-fixture")
}
