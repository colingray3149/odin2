//! Serve one framed effect request per process; exit code 2 indicates rejection.
use mimalloc::MiMalloc;

#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;

mod capsule;

use std::collections::BTreeMap;
use std::env;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::{Arc, Mutex, OnceLock};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use odin_kernel::{ParentAuthorityClient, StopAuthority, StopAuthorityProcessTransport};
use odin_ledger::Ledger;
use odin_process::{
    CancellationToken, CommandSpec, EnvironmentBuilder, ExitDisposition, FrozenArgv, ProcessLimits,
    ProcessSupervisor, ProcessTransport, ScanCriteria, SurvivorScanner, WorkerChannel,
};
use odin_sidecar_protocol::{
    read_effect_request, write_effect_response, CapsuleBinding, EffectBehavior, EffectIdentity,
    EffectOp, EffectRequest, EffectResponse, EFFECTOR_BWRAP_ENV, EFFECTOR_CACHE_ROOT_ENV,
    EFFECTOR_CARGO_GIT_CACHE_ENV, EFFECTOR_CARGO_REGISTRY_CACHE_ENV, EFFECTOR_CONTEXT_ROOT_ENV,
    EFFECTOR_NIX_CONFIG_ROOT_ENV, EFFECTOR_TOOL_PATH_ENV, EFFECT_MAX_CAPTURE_BYTES,
    EFFECT_MAX_REQUEST_BYTES, EFFECT_MAX_RESPONSE_BYTES, EFFECT_MAX_RETAINED_BYTES,
    SANDBOX_PROJECT,
};
use odin_strict_json::{canonicalize, decode, Value};
use odin_types::hash::hex_encode;
use serde::Deserialize;
use sha2::{Digest as _, Sha256};

const MAX_ARGV_ITEMS: usize = 128;
const MAX_ARGV_BYTES: usize = 32_768;
const MAX_ENV_KEYS: usize = 64;
const MAX_ENV_VALUE_BYTES: usize = 4_096;
/// How often the supervisor checks a running program.
const POLL_INTERVAL: Duration = Duration::from_millis(5);
const MAX_TIMEOUT_MS: u64 = 600_000;
const MAX_TERM_GRACE_MS: u64 = 30_000;

const SANDBOX_CONTEXT: &str = "/workspace/context";
const SANDBOX_CARGO_HOME: &str = "/run/odin/cargo-home";
const SANDBOX_TARGET: &str = "/run/odin/target";
const SANDBOX_HOME: &str = "/run/odin/home";

#[derive(Debug)]
struct SandboxRuntime {
    bwrap: PathBuf,
    cache_root: PathBuf,
    tool_path: String,
    context_root: Option<PathBuf>,
    cargo_registry_cache: Option<PathBuf>,
    cargo_git_cache: Option<PathBuf>,
    nix_config_root: Option<PathBuf>,
}

impl SandboxRuntime {
    fn from_env() -> Result<Self, String> {
        fn required_path(name: &str) -> Result<PathBuf, String> {
            let path = env::var_os(name)
                .map(PathBuf::from)
                .ok_or_else(|| format!("{name} is required for governed eval"))?;
            if !path.is_absolute() {
                return Err(format!("{name} must be absolute"));
            }
            Ok(path)
        }
        fn optional_path(name: &str) -> Result<Option<PathBuf>, String> {
            let Some(value) = env::var_os(name) else {
                return Ok(None);
            };
            let path = PathBuf::from(value);
            if !path.is_absolute() {
                return Err(format!("{name} must be absolute"));
            }
            Ok(Some(path))
        }

        let tool_path = env::var(EFFECTOR_TOOL_PATH_ENV).map_err(|error| {
            format!("{EFFECTOR_TOOL_PATH_ENV} is required for governed eval: {error}")
        })?;
        if tool_path.is_empty()
            || env::split_paths(&tool_path)
                .any(|path| path.as_os_str().is_empty() || !path.is_absolute())
        {
            return Err(format!(
                "{EFFECTOR_TOOL_PATH_ENV} must contain only absolute nonempty entries"
            ));
        }
        Ok(Self {
            bwrap: required_path(EFFECTOR_BWRAP_ENV)?,
            cache_root: required_path(EFFECTOR_CACHE_ROOT_ENV)?,
            tool_path,
            context_root: optional_path(EFFECTOR_CONTEXT_ROOT_ENV)?,
            cargo_registry_cache: optional_path(EFFECTOR_CARGO_REGISTRY_CACHE_ENV)?,
            cargo_git_cache: optional_path(EFFECTOR_CARGO_GIT_CACHE_ENV)?,
            nix_config_root: optional_path(EFFECTOR_NIX_CONFIG_ROOT_ENV)?,
        })
    }

    fn command(
        &self,
        capsule_root: &Path,
        scratch_relative: &str,
        interpreter: &Path,
    ) -> Result<CommandSpec, String> {
        for directory in ["cargo-home", "target", "home"] {
            let path = self.cache_root.join(directory);
            if !path.is_dir() {
                return Err(format!(
                    "sandbox cache directory {} is absent",
                    path.display()
                ));
            }
        }
        // No --die-with-parent: its PDEATHSIG would track the short-lived broker thread and kill a healthy worker when it exits.
        let mut argv = odin_process::capsule_sandbox_argv(
            self.bwrap.display().to_string(),
            capsule_root,
            "--bind",
        );
        // Read-only Git metadata prevents the payload from planting hooks for later host observations.
        let git_dir = capsule_root.join(".git");
        match std::fs::symlink_metadata(&git_dir) {
            Ok(metadata) if metadata.file_type().is_dir() => argv.extend([
                "--ro-bind".to_owned(),
                git_dir.display().to_string(),
                format!("{SANDBOX_PROJECT}/.git"),
            ]),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Ok(_) => return Err("capsule .git is neither a directory nor absent".to_owned()),
            Err(error) => return Err(format!("capsule .git cannot be inspected: {error}")),
        }
        argv.extend([
            "--dir".to_owned(),
            "/run".to_owned(),
            "--dir".to_owned(),
            "/run/odin".to_owned(),
            "--bind".to_owned(),
            self.cache_root.join("cargo-home").display().to_string(),
            SANDBOX_CARGO_HOME.to_owned(),
            "--bind".to_owned(),
            self.cache_root.join("target").display().to_string(),
            SANDBOX_TARGET.to_owned(),
            "--bind".to_owned(),
            self.cache_root.join("home").display().to_string(),
            SANDBOX_HOME.to_owned(),
        ]);
        if let Some(path) = &self.context_root {
            argv.extend([
                "--ro-bind".to_owned(),
                path.display().to_string(),
                SANDBOX_CONTEXT.to_owned(),
            ]);
        }
        for (source, destination) in [
            (
                &self.cargo_registry_cache,
                format!("{SANDBOX_CARGO_HOME}/registry"),
            ),
            (&self.cargo_git_cache, format!("{SANDBOX_CARGO_HOME}/git")),
        ] {
            if let Some(source) = source {
                argv.extend([
                    "--ro-bind-try".to_owned(),
                    source.display().to_string(),
                    destination,
                ]);
            }
        }
        if let Some(path) = &self.nix_config_root {
            argv.extend([
                "--dir".to_owned(),
                "/etc".to_owned(),
                "--ro-bind".to_owned(),
                path.display().to_string(),
                "/etc/nix".to_owned(),
            ]);
        }
        for (name, value) in [
            ("PATH", self.tool_path.as_str()),
            ("HOME", SANDBOX_HOME),
            ("TMPDIR", "/tmp"),
            ("CARGO_HOME", SANDBOX_CARGO_HOME),
            ("CARGO_TARGET_DIR", SANDBOX_TARGET),
            ("ODIN_PROJECT_ROOT", SANDBOX_PROJECT),
        ] {
            argv.extend(["--setenv".to_owned(), name.to_owned(), value.to_owned()]);
        }
        if self.context_root.is_some() {
            argv.extend([
                "--setenv".to_owned(),
                "ODIN_CONTEXT_ROOT".to_owned(),
                SANDBOX_CONTEXT.to_owned(),
            ]);
        }
        let scratch = Path::new(SANDBOX_PROJECT).join(scratch_relative);
        argv.extend([
            "--chdir".to_owned(),
            SANDBOX_PROJECT.to_owned(),
            "--".to_owned(),
            interpreter.display().to_string(),
            scratch.display().to_string(),
        ]);
        let argv = FrozenArgv::new(argv, MAX_ARGV_ITEMS, MAX_ARGV_BYTES)
            .map_err(|error| format!("sandbox argv rejected: {error}"))?;
        Ok(CommandSpec {
            argv,
            environment: EnvironmentBuilder::new(Vec::<&str>::new())
                .expect("empty environment is valid")
                .build(),
            current_dir: capsule_root.to_path_buf(),
        })
    }
}

/// Nested effectors use the parent StopAuthority because their manager socket is masked.
static PROCESS_TRANSPORT: OnceLock<Result<Arc<StopAuthorityProcessTransport>, String>> =
    OnceLock::new();

fn process_transport() -> Result<Arc<dyn ProcessTransport>, String> {
    match PROCESS_TRANSPORT.get_or_init(build_process_transport) {
        Ok(transport) => Ok(Arc::clone(transport) as Arc<dyn ProcessTransport>),
        Err(error) => Err(error.clone()),
    }
}

fn build_process_transport() -> Result<Arc<StopAuthorityProcessTransport>, String> {
    let parent = ParentAuthorityClient::from_env()
        .map_err(|error| format!("parent process authority rejected: {error}"))?;
    let authority = if parent.is_remote() {
        let store_path = parent
            .expected_store_path()
            .map_err(|error| format!("parent process authority store rejected: {error}"))?;
        let store = Arc::new(Mutex::new(Ledger::open(&store_path).map_err(|error| {
            format!("parent process authority ledger failed: {error}")
        })?));
        StopAuthority::from_parent(store, parent)
            .map_err(|error| format!("parent process authority failed: {error}"))?
    } else {
        // The outer StopAuthority contains this fixture effector's whole cgroup.
        let channel = WorkerChannel::from_registered_env()
            .map_err(|error| format!("registered process channel rejected: {error}"))?;
        let store = Arc::new(Mutex::new(Ledger::open_in_memory().map_err(|error| {
            format!("local process authority ledger failed: {error}")
        })?));
        StopAuthority::new(store, channel)
    };
    Ok(Arc::new(StopAuthorityProcessTransport::new(Arc::new(
        authority,
    ))))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ExecuteParams {
    argv: Vec<String>,
    #[serde(default)]
    environment: BTreeMap<String, String>,
    current_dir: PathBuf,
    timeout_ms: u64,
    term_grace_ms: u64,
    max_stdout_bytes: usize,
    max_stderr_bytes: usize,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EvalParams {
    interpreter_program: String,
    source: String,
    source_sha256: String,
    #[serde(default)]
    scratch: String,
    timeout_ms: u64,
    term_grace_ms: u64,
    max_stdout_bytes: usize,
    max_stderr_bytes: usize,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WriteParams {
    path: PathBuf,
    content_hex: String,
    #[serde(default)]
    preimage_sha256: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReplaceParams {
    path: PathBuf,
    old_hex: String,
    new_hex: String,
}

fn reject(detail: String) -> ! {
    tracing::error!(%detail, "odin-effector");
    std::process::exit(2)
}

fn try_params<T: serde::de::DeserializeOwned>(arguments: &Value) -> Result<T, String> {
    let bytes = canonicalize(arguments).map_err(|error| format!("arguments rejected: {error}"))?;
    decode(&bytes, EFFECT_MAX_REQUEST_BYTES).map_err(|error| format!("arguments rejected: {error}"))
}

fn read_request() -> EffectRequest {
    let request = read_effect_request(&mut std::io::stdin().lock(), EFFECT_MAX_REQUEST_BYTES)
        .unwrap_or_else(|error| reject(format!("effect request rejected: {error}")));
    request.unwrap_or_else(|| reject("effect request frame is empty".to_string()))
}

fn digest_of(bytes: &[u8]) -> String {
    format!("blake3:{}", blake3::hash(bytes).to_hex())
}

fn emit(response: &EffectResponse) {
    write_effect_response(
        &mut std::io::stdout().lock(),
        response,
        EFFECT_MAX_RESPONSE_BYTES,
    )
    .unwrap_or_else(|error| reject(format!("effect response failed: {error}")));
}

fn accepted(op: EffectOp) -> EffectResponse {
    EffectResponse {
        ok: true,
        op,
        observed: None,
        expected_post: None,
        outcome: None,
        detail: None,
        exit_code: None,
        signal: None,
        cancelled: None,
        identity: None,
        survivors: Vec::new(),
        worker_stopped: None,
        stdout_hex: None,
        stderr_hex: None,
        stdout_bytes: None,
        stderr_bytes: None,
        stdout_truncated: None,
        stderr_truncated: None,
        handler_entry_ms: None,
        handler_exit_ms: None,
        filesystem_changes: Vec::new(),
    }
}

fn completed(op: EffectOp) -> EffectResponse {
    let mut response = accepted(op);
    response.outcome = Some("completed".to_string());
    response
}

fn rejected(op: EffectOp, outcome: &'static str, detail: String) -> EffectResponse {
    EffectResponse {
        ok: false,
        op,
        outcome: Some(outcome.to_string()),
        detail: Some(detail),
        ..accepted(op)
    }
}

fn survivor_fields(response: &mut EffectResponse, observation: (Vec<Survivor>, bool)) {
    let (survivors, stopped) = observation;
    response.worker_stopped = Some(stopped);
    response.survivors = survivors
        .into_iter()
        .map(|survivor| EffectIdentity {
            pid: survivor.pid as i32,
            start_time_ticks: survivor.start_time_ticks,
            process_group: survivor.process_group,
        })
        .collect();
}

fn disposition_fields(response: &mut EffectResponse, disposition: &ExitDisposition) {
    // Truncated output does not turn a payload's independent exit into a stop.
    match disposition {
        ExitDisposition::Exited(code) => response.exit_code = Some(*code),
        ExitDisposition::Signaled(signal) => response.signal = Some(*signal),
        ExitDisposition::TimedOut { .. } => {
            response.outcome = Some("timed_out".to_string());
            response.detail = Some(
                "the program was stopped at its deadline; captured output is partial and this is not a finished result"
                    .to_string(),
            );
        }
        ExitDisposition::Interrupted { .. } => {
            response.outcome = Some("uncertain".to_string());
            response.detail = Some(
                "the program was stopped before it finished; captured output is partial and this is not a finished result"
                    .to_string(),
            );
        }
        ExitDisposition::OutputLimit { .. } => {
            response.outcome = Some("uncertain".to_string());
            response.detail = Some(
                "the program was stopped because its output exceeded the capture ceiling; captured output is partial and this is not a finished result"
                    .to_string(),
            );
        }
    }
}

/// Measure handler time here because the sidecar observes only the surrounding exchange.
fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_millis() as u64)
        .unwrap_or(0)
}

/// Preserve truncation from both supervisor capture and response retention limits.
fn capture(output: &odin_process::CapturedOutput) -> (String, u64, bool) {
    let bytes = output.as_bytes();
    let retained = bytes.len().min(EFFECT_MAX_RETAINED_BYTES);
    (
        odin_types::hash::hex_encode(&bytes[..retained]),
        bytes.len() as u64,
        output.truncated() || bytes.len() > EFFECT_MAX_RETAINED_BYTES,
    )
}

fn capture_fields(
    response: &mut EffectResponse,
    stdout: &odin_process::CapturedOutput,
    stderr: &odin_process::CapturedOutput,
) {
    let (stdout_hex, stdout_bytes, stdout_truncated) = capture(stdout);
    let (stderr_hex, stderr_bytes, stderr_truncated) = capture(stderr);
    response.stdout_hex = Some(stdout_hex);
    response.stderr_hex = Some(stderr_hex);
    response.stdout_bytes = Some(stdout_bytes);
    response.stderr_bytes = Some(stderr_bytes);
    response.stdout_truncated = Some(stdout_truncated);
    response.stderr_truncated = Some(stderr_truncated);
}

/// A failed filesystem observation is uncertain, not an empty change list.
fn filesystem_changes(
    capsule_root: &Path,
    git_bin: &Path,
) -> Result<Vec<odin_sidecar_protocol::EffectFileChange>, String> {
    Ok(capsule::observed_changes(git_bin, capsule_root)?
        .into_iter()
        .map(|(op, path)| odin_sidecar_protocol::EffectFileChange { op, path })
        .collect())
}

#[derive(Debug)]
struct Survivor {
    pid: u32,
    start_time_ticks: u64,
    process_group: i32,
}

fn survivors(supervisor: &mut ProcessSupervisor, group: i32) -> (Vec<Survivor>, bool) {
    let mut criteria = ScanCriteria::new("", "");
    criteria.add_process_group(group);
    let report = supervisor
        .cleanup(&criteria, &SurvivorScanner)
        .unwrap_or_else(|error| reject(format!("teardown scan failed: {error}")));
    let stopped = report.stopped;
    let survivors = report
        .identities
        .processes
        .iter()
        .map(|identity| Survivor {
            pid: identity.pid,
            start_time_ticks: identity.start_time_ticks,
            process_group: identity.process_group,
        })
        .collect();
    (survivors, stopped)
}

/// The timeouts and output ceilings every supervised program runs under.
fn process_limits(
    timeout_ms: u64,
    term_grace_ms: u64,
    max_stdout_bytes: usize,
    max_stderr_bytes: usize,
) -> Result<ProcessLimits, String> {
    if timeout_ms == 0 || timeout_ms > MAX_TIMEOUT_MS {
        return Err(format!("timeout_ms must be within 1..={MAX_TIMEOUT_MS}"));
    }
    if term_grace_ms == 0 || term_grace_ms > MAX_TERM_GRACE_MS {
        return Err(format!(
            "term_grace_ms must be within 1..={MAX_TERM_GRACE_MS}"
        ));
    }
    let ceiling = 1..=EFFECT_MAX_CAPTURE_BYTES;
    if !ceiling.contains(&max_stdout_bytes) || !ceiling.contains(&max_stderr_bytes) {
        return Err(format!(
            "output ceilings must be within 1..={EFFECT_MAX_CAPTURE_BYTES}"
        ));
    }
    Ok(ProcessLimits {
        timeout: Duration::from_millis(timeout_ms),
        termination_grace: Duration::from_millis(term_grace_ms),
        poll_interval: POLL_INTERVAL,
        max_stdout_bytes,
        max_stderr_bytes,
    })
}

/// Run one command under the process authority and describe how it ended, survivors included.
fn run_supervised(
    op: EffectOp,
    command: &CommandSpec,
    limits: ProcessLimits,
    token: &CancellationToken,
) -> EffectResponse {
    let transport = match process_transport() {
        Ok(transport) => transport,
        Err(error) => {
            return rejected(
                op,
                "rejected",
                format!("process authority transport rejected: {error}"),
            );
        }
    };
    let mut supervisor = match ProcessSupervisor::new(limits, transport) {
        Ok(supervisor) => supervisor,
        Err(error) => {
            return rejected(
                op,
                "rejected",
                format!("supervisor rejected limits: {error}"),
            );
        }
    };
    let outcome = match supervisor.run(command, token) {
        Ok(outcome) => outcome,
        Err(error) => {
            let mut response = rejected(op, "spawn_failed", format!("spawn failed: {error}"));
            let teardown = survivors(&mut supervisor, 0);
            survivor_fields(&mut response, teardown);
            return response;
        }
    };
    let mut response = accepted(op);
    response.outcome = Some("completed".to_string());
    response.cancelled = Some(token.is_cancelled());
    response.exit_code = match &outcome.disposition {
        ExitDisposition::Exited(code) => Some(*code),
        _ => None,
    };
    response.identity = Some(EffectIdentity {
        pid: outcome.identity.pid as i32,
        start_time_ticks: outcome.identity.start_time_ticks,
        process_group: outcome.identity.process_group,
    });
    disposition_fields(&mut response, &outcome.disposition);
    if token.is_cancelled() && response.outcome.as_deref() == Some("completed") {
        response.outcome = Some("cancelled".to_string());
        response.cancelled = Some(true);
    }
    capture_fields(&mut response, &outcome.stdout, &outcome.stderr);
    let teardown = survivors(&mut supervisor, outcome.identity.process_group);
    survivor_fields(&mut response, teardown);
    response
}

fn run_execute(op: EffectOp, params: ExecuteParams, token: &CancellationToken) -> EffectResponse {
    let ExecuteParams {
        argv,
        environment,
        current_dir,
        timeout_ms,
        term_grace_ms,
        max_stdout_bytes,
        max_stderr_bytes,
    } = params;
    let frozen = match FrozenArgv::new(&argv, MAX_ARGV_ITEMS, MAX_ARGV_BYTES) {
        Ok(frozen) => frozen,
        Err(error) => return rejected(op, "rejected", format!("argv rejected: {error}")),
    };
    if environment.len() > MAX_ENV_KEYS {
        return rejected(
            op,
            "rejected",
            format!(
                "environment has {} keys; ceiling is {MAX_ENV_KEYS}",
                environment.len()
            ),
        );
    }
    let mut builder = match EnvironmentBuilder::new(environment.keys()) {
        Ok(builder) => builder,
        Err(error) => {
            return rejected(op, "rejected", format!("environment key rejected: {error}"));
        }
    };
    for (key, value) in &environment {
        if value.len() > MAX_ENV_VALUE_BYTES {
            return rejected(
                op,
                "rejected",
                format!("environment value for {key} exceeds byte bound"),
            );
        }
        builder = match builder.set(key, value) {
            Ok(builder) => builder,
            Err(error) => {
                return rejected(op, "rejected", format!("environment rejected: {error}"));
            }
        };
    }
    if !current_dir.is_absolute() {
        return rejected(
            op,
            "rejected",
            "current_dir must be an absolute path".to_string(),
        );
    }
    let limits = match process_limits(
        timeout_ms,
        term_grace_ms,
        max_stdout_bytes,
        max_stderr_bytes,
    ) {
        Ok(limits) => limits,
        Err(detail) => return rejected(op, "rejected", detail),
    };
    let command = CommandSpec {
        argv: frozen,
        environment: builder.build(),
        current_dir,
    };
    run_supervised(op, &command, limits, token)
}

/// Leftover or unrestorable scratch makes an eval outcome uncertain.
fn run_eval(
    op: EffectOp,
    params: EvalParams,
    capsule_root: &Path,
    identity: &capsule::CapsuleSourceIdentity,
    git_bin: &Path,
    token: &CancellationToken,
) -> EffectResponse {
    let EvalParams {
        interpreter_program,
        source,
        source_sha256,
        scratch,
        timeout_ms,
        term_grace_ms,
        max_stdout_bytes,
        max_stderr_bytes,
    } = params;
    if let Err(detail) = capsule::verify(capsule_root, identity, git_bin) {
        return rejected(op, "rejected", detail);
    }
    let program = PathBuf::from(&interpreter_program);
    if !program.is_absolute() {
        return rejected(
            op,
            "rejected",
            "interpreter_program must be an absolute authority-bound path".to_string(),
        );
    }
    let observed_sha256 = hex_encode(&Sha256::digest(source.as_bytes()));
    if observed_sha256 != source_sha256 {
        return rejected(
            op,
            "rejected",
            format!("source_sha256 mismatch: declared {source_sha256}, observed {observed_sha256}"),
        );
    }
    let scratch_relative = match capsule::validate_scratch_path(&scratch) {
        Ok(scratch) => scratch,
        Err(detail) => return rejected(op, "rejected", detail),
    };
    let limits = match process_limits(
        timeout_ms,
        term_grace_ms,
        max_stdout_bytes,
        max_stderr_bytes,
    ) {
        Ok(limits) => limits,
        Err(detail) => return rejected(op, "rejected", detail),
    };
    let sandbox = match SandboxRuntime::from_env() {
        Ok(sandbox) => sandbox,
        Err(detail) => return rejected(op, "rejected", detail),
    };
    let command = match sandbox.command(capsule_root, &scratch_relative, &program) {
        Ok(command) => command,
        Err(detail) => return rejected(op, "rejected", detail),
    };
    if let Err(detail) = capsule::stage_scratch(capsule_root, &scratch_relative, &source) {
        return rejected(op, "rejected", detail);
    }
    let mut response = run_supervised(op, &command, limits, token);
    // Remove scratch before observing the capsule so leftover files cannot go unreported.
    if let Err(cleanup) = capsule::remove_scratch(capsule_root, &scratch_relative) {
        response.ok = false;
        response.outcome = Some("uncertain".to_string());
        response.detail = Some(match response.detail.take() {
            Some(prior) => format!("{prior}; {cleanup}"),
            None => cleanup,
        });
    }
    response
}

fn watch_stdin(token: CancellationToken) {
    let _ = thread::spawn(move || {
        let mut discarded = 0_usize;
        let mut chunk = [0_u8; 8_192];
        loop {
            match std::io::stdin().read(&mut chunk) {
                Ok(0) => break,
                Ok(count) => {
                    discarded += count;
                    if discarded > EFFECT_MAX_REQUEST_BYTES * 4 {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
        token.cancel();
    });
}

/// Eval observes tracked state; file operations observe their target path.
fn observe_target(
    behavior: EffectBehavior,
    arguments: &Value,
    capsule_root: &Path,
    identity: &capsule::CapsuleSourceIdentity,
    git_bin: &Path,
) -> Result<Option<String>, String> {
    match behavior {
        EffectBehavior::Eval => {
            let _ = try_params::<EvalParams>(arguments)?;
            capsule::tracked_state_digest(git_bin, capsule_root, identity).map(Some)
        }
        EffectBehavior::Write => {
            let path: PathBuf = match try_params::<WriteParams>(arguments) {
                Ok(write) => write.path,
                Err(_) => try_params::<ReplaceParams>(arguments)?.path,
            };
            capsule::content_digest(capsule_root, &path)
        }
        EffectBehavior::Execute => Ok(None),
    }
}

/// Eval must preserve the tracked state captured before execution.
fn declare_target(
    behavior: EffectBehavior,
    arguments: &Value,
    capsule_root: &Path,
    identity: &capsule::CapsuleSourceIdentity,
    git_bin: &Path,
) -> Result<Option<String>, String> {
    match behavior {
        EffectBehavior::Eval => {
            let _ = try_params::<EvalParams>(arguments)?;
            capsule::tracked_state_digest(git_bin, capsule_root, identity).map(Some)
        }
        EffectBehavior::Write => {
            if let Ok(replace) = try_params::<ReplaceParams>(arguments) {
                let post = capsule::replaced_content(
                    capsule_root,
                    &replace.path,
                    &replace.old_hex,
                    &replace.new_hex,
                )?;
                return Ok(Some(digest_of(&post)));
            }
            let Ok(write) = try_params::<WriteParams>(arguments) else {
                return Ok(None);
            };
            let content = odin_types::hash::hex_decode(&write.content_hex)
                .map_err(|error| format!("content_hex rejected: {error}"))?;
            Ok(Some(digest_of(&content)))
        }
        EffectBehavior::Execute => Ok(None),
    }
}

/// Failed post-effect observation downgrades success to uncertainty.
fn attach_filesystem_changes(response: &mut EffectResponse, capsule_root: &Path, git_bin: &Path) {
    let landed_or_uncertain = response.ok || response.outcome.as_deref() == Some("uncertain");
    if !landed_or_uncertain {
        return;
    }
    match filesystem_changes(capsule_root, git_bin) {
        Ok(changes) => response.filesystem_changes = changes,
        Err(detail) => {
            if response.ok {
                response.ok = false;
                response.outcome = Some("uncertain".to_string());
                response.detail = Some(format!("capsule change observation failed: {detail}"));
            }
        }
    }
}

fn dispatch(request: EffectRequest, op: EffectOp, token: &CancellationToken) -> EffectResponse {
    let behavior = request.behavior();
    let capsule_binding: &CapsuleBinding = request.capsule();
    let capsule_root = PathBuf::from(&capsule_binding.root);
    let git_bin = PathBuf::from(&capsule_binding.git_bin);
    let identity = match capsule::CapsuleSourceIdentity::parse(
        capsule_binding.source_kind.as_str(),
        capsule_binding.source_commit.as_str(),
    ) {
        Ok(identity) => identity,
        Err(detail) => return rejected(op, "rejected", detail),
    };
    let arguments = request.arguments();
    match request.op() {
        EffectOp::Declare => {
            let expected_post =
                match declare_target(behavior, arguments, &capsule_root, &identity, &git_bin) {
                    Ok(expected_post) => expected_post,
                    Err(detail) => return rejected(op, "rejected", detail),
                };
            let mut response = accepted(op);
            response.expected_post = expected_post;
            response
        }
        EffectOp::Observe => {
            let observed =
                match observe_target(behavior, arguments, &capsule_root, &identity, &git_bin) {
                    Ok(observed) => observed,
                    Err(detail) => return rejected(op, "rejected", detail),
                };
            let mut response = accepted(op);
            response.observed = observed;
            response
        }
        EffectOp::Execute => {
            let mut response = match behavior {
                EffectBehavior::Execute => match try_params::<ExecuteParams>(arguments) {
                    Ok(params) => run_execute(op, params, token),
                    Err(detail) => return rejected(op, "rejected", detail),
                },
                EffectBehavior::Eval => match try_params::<EvalParams>(arguments) {
                    Ok(params) => run_eval(op, params, &capsule_root, &identity, &git_bin, token),
                    Err(detail) => return rejected(op, "rejected", detail),
                },
                EffectBehavior::Write => {
                    write_effect(op, arguments, &capsule_root, &identity, &git_bin)
                }
            };
            attach_filesystem_changes(&mut response, &capsule_root, &git_bin);
            response
        }
    }
}

/// An exact-text replacement or a whole-file write, with the phase a failed write stopped in.
fn write_effect(
    op: EffectOp,
    arguments: &Value,
    capsule_root: &Path,
    identity: &capsule::CapsuleSourceIdentity,
    git_bin: &Path,
) -> EffectResponse {
    let written = match try_params::<ReplaceParams>(arguments) {
        Ok(replace) => capsule::replace(
            capsule_root,
            identity,
            git_bin,
            &replace.path,
            &replace.old_hex,
            &replace.new_hex,
        ),
        Err(_) => match try_params::<WriteParams>(arguments) {
            Ok(params) => capsule::write(
                capsule_root,
                identity,
                git_bin,
                &params.path,
                &params.content_hex,
                params.preimage_sha256.as_deref(),
            ),
            Err(detail) => return rejected(op, "rejected", detail),
        },
    };
    match written {
        Ok(_) => completed(op),
        Err(error) => match error.phase {
            "unchanged" => rejected(op, "rejected", error.detail),
            phase => {
                let mut response = accepted(op);
                // A replaced file landed; anything else may or may not have.
                response.outcome = Some(
                    if phase == "replaced" {
                        "completed"
                    } else {
                        "uncertain"
                    }
                    .to_string(),
                );
                response.detail = Some(error.detail);
                response
            }
        },
    }
}

fn main() -> ExitCode {
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_ansi(false)
        .compact()
        .with_writer(std::io::stderr)
        .init();
    let mut argv = std::env::args_os().skip(1);
    let op = match argv.next().and_then(|value| value.into_string().ok()) {
        Some(op) => op,
        None => reject("the behavior verb argv[1] is required".to_string()),
    };
    let op = match op.as_str() {
        "declare" => EffectOp::Declare,
        "observe" => EffectOp::Observe,
        "execute" => EffectOp::Execute,
        other => reject(format!(
            "behavior verb {other:?} is not one of declare,observe,execute"
        )),
    };
    let request = read_request();
    if request.op() != op {
        reject(format!(
            "argv verb {op:?} does not match the framed request op {:?}",
            request.op()
        ));
    }
    let token = CancellationToken::new();
    // Stdin EOF must stop children even if the handler never returns to main.
    watch_stdin(token.clone());
    let handler_entry_ms = now_ms();
    let mut response = dispatch(request, op, &token);
    response.handler_entry_ms = Some(handler_entry_ms);
    response.handler_exit_ms = Some(now_ms());
    emit(&response);
    ExitCode::SUCCESS
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_symlinked_capsule_git_is_refused_not_bound() {
        let scratch = tempfile::tempdir().unwrap();
        let root = scratch.path();
        let capsule = root.join("capsule");
        let cache = root.join("cache");
        for directory in [
            &capsule,
            &cache.join("cargo-home"),
            &cache.join("target"),
            &cache.join("home"),
        ] {
            std::fs::create_dir_all(directory).unwrap();
        }
        let outside = root.join("outside");
        std::fs::create_dir_all(&outside).unwrap();
        let runtime = SandboxRuntime {
            bwrap: PathBuf::from("/bin/bwrap"),
            cache_root: cache,
            tool_path: "/bin".to_owned(),
            context_root: None,
            cargo_registry_cache: None,
            cargo_git_cache: None,
            nix_config_root: None,
        };
        let interpreter = Path::new("/bin/sh");
        assert!(runtime
            .command(&capsule, ".odin-eval/x", interpreter)
            .is_ok());
        std::os::unix::fs::symlink(&outside, capsule.join(".git")).unwrap();
        let refused = runtime.command(&capsule, ".odin-eval/x", interpreter);
        assert!(refused.is_err(), "a symlinked .git must refuse");
    }
    /// Arguments that do not fit the behavior are a typed refusal the sidecar can settle, not a
    /// silent exit it must treat as in doubt.
    #[test]
    fn arguments_that_do_not_fit_the_behavior_answer_a_rejection() {
        for (behavior, arguments) in [
            (
                EffectBehavior::Execute,
                serde_json::json!({"argv": ["true"]}),
            ),
            (
                EffectBehavior::Eval,
                serde_json::json!({"source": "print(1)"}),
            ),
            (
                EffectBehavior::Write,
                serde_json::json!({"content_hex": "00"}),
            ),
        ] {
            let arguments = {
                let bytes = serde_json::to_vec(&arguments).unwrap();
                decode(&bytes, EFFECT_MAX_REQUEST_BYTES).unwrap()
            };
            let request = EffectRequest::Execute {
                capsule: CapsuleBinding {
                    capsule_id: "capsule-effector".to_owned(),
                    root: "/nonexistent/capsule".to_owned(),
                    source_commit: "0123456789abcdef0123456789abcdef01234567".to_owned(),
                    source_kind: odin_sidecar_protocol::SOURCE_KIND_GIT_COMMIT.to_owned(),
                    git_bin: "/nonexistent/git".to_owned(),
                },
                behavior,
                arguments,
            };
            let response = dispatch(request, EffectOp::Execute, &CancellationToken::new());
            assert!(!response.ok, "{behavior:?}");
            assert_eq!(
                response.outcome.as_deref(),
                Some("rejected"),
                "{behavior:?}"
            );
        }
    }
}
