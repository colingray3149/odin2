//! Test runs and Git/Nix steps registered to the session's worker scope.

use std::collections::VecDeque;
use std::io::{ErrorKind, Read};
use std::os::fd::AsFd;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use odin_domain::{Scope, StopVerdict};
use odin_hermes::runtime::coding::{CargoTests, NixLog};
use odin_kernel::operation::PreparedEffect;
use odin_types::WorkerId;

use super::SessionAuthorityPool;
use crate::eval_daemon::{WorkerLaunchSpec, WorkerLauncher};

/// The most bytes one captured stream keeps.
pub const OUTPUT_LIMIT: usize = 8 * 1024 * 1024;

/// What one captured stream keeps beyond the capture bound. Successful steps
/// still drain both pipes to EOF and prove the worker stopped.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Retention {
    /// The whole output or the step fails: for evidence and for output a
    /// program parses.
    #[default]
    Complete,
    /// The first bound's worth of bytes: for text read from its beginning.
    Head,
    /// The last bound's worth of bytes: for text read from its end.
    Tail,
}

/// The retention of each stream of one step.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Capture {
    pub stdout: Retention,
    pub stderr: Retention,
}

/// A finished step's complete exit and what each stream kept, with whether
/// bytes were dropped from it. A stream that is not `Retention::Complete` is
/// cut only when its flag is set.
#[derive(Debug)]
pub struct Captured {
    pub output: std::process::Output,
    pub stdout_cut: bool,
    pub stderr_cut: bool,
}

/// The operation itself owns and drains each pipe. An unproved stop can
/// return without stranding a blocking reader thread or its descriptor.
///
/// Invariant: `bytes` never holds more than `OUTPUT_LIMIT`. Only `Tail`
/// drops from the front (one bounded pop per read); `Head` stops appending.
struct CapturedPipe<R> {
    reader: R,
    retention: Retention,
    bytes: VecDeque<u8>,
    cut: bool,
    eof: bool,
}

impl<R: Read + AsFd> CapturedPipe<R> {
    fn new(reader: R, retention: Retention) -> Result<Self, String> {
        let flags = rustix::fs::fcntl_getfl(&reader).map_err(|error| error.to_string())?;
        rustix::fs::fcntl_setfl(&reader, flags | rustix::fs::OFlags::NONBLOCK)
            .map_err(|error| error.to_string())?;
        Ok(Self {
            reader,
            retention,
            bytes: VecDeque::new(),
            cut: false,
            eof: false,
        })
    }

    fn keep(&mut self, chunk: &[u8]) -> Result<(), String> {
        let room = OUTPUT_LIMIT - self.bytes.len();
        match self.retention {
            Retention::Complete if chunk.len() > room => {
                return Err("scoped test output limit exceeded".to_owned());
            }
            Retention::Complete => self.bytes.extend(chunk),
            Retention::Head => {
                let take = chunk.len().min(room);
                self.bytes.extend(&chunk[..take]);
                self.cut |= take < chunk.len();
            }
            Retention::Tail => {
                // drain() supplies at most one 8 KiB chunk. Drop before extending:
                // temporarily exceeding the bound would grow the ring unnecessarily.
                let excess = chunk.len().saturating_sub(room);
                if excess > 0 {
                    self.bytes.drain(..excess);
                    self.cut = true;
                }
                self.bytes.extend(chunk);
            }
        }
        Ok(())
    }

    fn into_parts(self) -> (Vec<u8>, bool) {
        (Vec::from(self.bytes), self.cut)
    }

    fn drain(&mut self) -> Result<bool, String> {
        if self.eof {
            return Ok(false);
        }
        let mut progressed = false;
        let mut buffer = [0; 8192];
        // Bound each drain to 64 KiB so a continuously writing worker
        // cannot starve cancellation, deadline or the other pipe.
        for _ in 0..8 {
            match self.reader.read(&mut buffer) {
                Ok(0) => {
                    self.eof = true;
                    break;
                }
                Ok(count) => {
                    self.keep(&buffer[..count])?;
                    progressed = true;
                }
                Err(error) if error.kind() == ErrorKind::WouldBlock => break,
                Err(error) if error.kind() == ErrorKind::Interrupted => continue,
                Err(error) => return Err(error.to_string()),
            }
        }
        Ok(progressed)
    }
}

/// Cancellation prevents launch and stops running steps; permits also track the leader.
pub(super) enum Cancel<'a> {
    Permit(&'a odin_kernel::operation::StopHandle),
    Lifecycle(&'a AtomicBool),
}

impl Cancel<'_> {
    fn requested(&self) -> bool {
        match self {
            Self::Permit(stop) => stop.is_cancelled(),
            Self::Lifecycle(flag) => flag.load(Ordering::Acquire),
        }
    }

    fn register(&self, identity: odin_kernel::ProcessIdentity) {
        if let Self::Permit(stop) = self {
            stop.register_process(identity);
        }
    }
}

struct Scratch(std::path::PathBuf);

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

impl Drop for ScopedTests {
    fn drop(&mut self) {
        if !self.closed.load(Ordering::Acquire) {
            let _ = self.retire(Instant::now() + Duration::from_secs(5));
        }
    }
}

/// Tracks concurrent session workers until their steps finish or the session retires.
pub(super) struct ScopedTests {
    launcher: WorkerLauncher,
    active: Mutex<std::collections::BTreeSet<WorkerId>>,
    closed: AtomicBool,
    /// A worker whose stop was not proved stays named in `active`, and this
    /// owner launches nothing more until retirement proves it.
    stranded: AtomicBool,
}

impl ScopedTests {
    fn new(launcher: WorkerLauncher) -> Self {
        Self {
            launcher,
            active: Mutex::new(std::collections::BTreeSet::new()),
            closed: AtomicBool::new(false),
            stranded: AtomicBool::new(false),
        }
    }

    pub(super) fn retire(&self, deadline: Instant) -> Result<(), String> {
        self.closed.store(true, Ordering::Release);
        let active = super::lock_until(&self.active, deadline)?;
        for worker in active.iter() {
            let outcome = self
                .launcher
                .authority
                .stop_worker_bounded(worker, deadline)
                .map_err(|error| error.to_string())?;
            if outcome.verdict != StopVerdict::Stopped {
                return Err("scoped test worker stop was not proved".to_owned());
            }
        }
        Ok(())
    }

    pub(super) fn abandon(&self) {
        self.closed.store(true, Ordering::Release);
        self.launcher.authority.abandon();
    }

    fn run(
        &self,
        pool: &SessionAuthorityPool,
        stop: Cancel<'_>,
        spec: WorkerLaunchSpec<'_>,
        capture: Capture,
    ) -> Result<Captured, String> {
        let deadline = Instant::now() + spec.runtime_max;
        let launch = {
            let mut active = self
                .active
                .lock()
                .map_err(|_| "scoped worker lock poisoned")?;
            if self.closed.load(Ordering::Acquire)
                || pool.closed.load(Ordering::Acquire)
                || stop.requested()
                || self.stranded.load(Ordering::Acquire)
                || spec.runtime_max.is_zero()
            {
                return Err("scoped test owner is stopped or stranded".to_owned());
            }
            let (launch, _) = self.launcher.launch(&pool.manifest, spec)?;
            active.insert(launch.identity.worker_id.clone());
            if let (Ok(pid), Ok(stat)) = (
                i32::try_from(launch.identity.leader_pid),
                std::fs::read_to_string(format!("/proc/{}/stat", launch.identity.leader_pid)),
            ) {
                if let Some(process_group) = stat
                    .rsplit(')')
                    .next()
                    .and_then(|fields| fields.split_whitespace().nth(2))
                    .and_then(|group| group.parse().ok())
                {
                    stop.register(odin_kernel::ProcessIdentity {
                        pid,
                        start_time_ticks: launch.identity.leader_start_ticks,
                        process_group,
                    });
                }
            }
            launch
        };
        let worker = launch.identity.worker_id;
        let _ = self.launcher.authority.close_worker_stdin(&worker);
        let result = (|| {
            let mut stdout = CapturedPipe::new(launch.stdout, capture.stdout)?;
            let mut stderr = CapturedPipe::new(launch.stderr, capture.stderr)?;
            loop {
                if stop.requested()
                    || self.closed.load(Ordering::Acquire)
                    || pool.closed.load(Ordering::Acquire)
                {
                    return Err("scoped test cancelled".to_owned());
                }
                if Instant::now() >= deadline {
                    return Err("scoped test deadline exceeded".to_owned());
                }
                let progressed = stdout.drain()? | stderr.drain()?;
                if let Some(status) = self
                    .launcher
                    .authority
                    .try_wait_worker(&worker)
                    .map_err(|error| error.to_string())?
                {
                    return Ok((status, stdout, stderr));
                }
                if !progressed {
                    std::thread::sleep(Duration::from_millis(10));
                }
            }
        })();
        // A successful leader exit does not mean its descendants have stopped.
        let cleanup_deadline = Instant::now() + Duration::from_secs(5);
        let cleanup = self
            .launcher
            .authority
            .stop_worker_bounded(&worker, cleanup_deadline)
            .map_err(|error| error.to_string());
        if !matches!(&cleanup, Ok(outcome) if outcome.verdict == StopVerdict::Stopped) {
            self.stranded.store(true, Ordering::Release);
            return Err(cleanup
                .err()
                .unwrap_or_else(|| "scoped test worker stop was not proved".to_owned()));
        }
        self.active
            .lock()
            .map_err(|_| "scoped worker lock poisoned")?
            .remove(&worker);
        let (status, mut stdout, mut stderr) = result?;
        while !stdout.eof || !stderr.eof {
            if Instant::now() >= cleanup_deadline {
                return Err("scoped worker output closure was not proved".to_owned());
            }
            let progressed = stdout.drain()? | stderr.drain()?;
            if !progressed && (!stdout.eof || !stderr.eof) {
                std::thread::sleep(Duration::from_millis(10));
            }
        }
        if stop.requested()
            || self.closed.load(Ordering::Acquire)
            || pool.closed.load(Ordering::Acquire)
        {
            return Err("scoped test cancelled".to_owned());
        }
        let (stdout, stdout_cut) = stdout.into_parts();
        let (stderr, stderr_cut) = stderr.into_parts();
        Ok(Captured {
            output: std::process::Output {
                status,
                stdout,
                stderr,
            },
            stdout_cut,
            stderr_cut,
        })
    }
}

/// The exact frozen capsule snapshot one scoped run executes: the coding
/// route's registered capsule and base, and the snapshot commit pinned by
/// the run's own ref inside that capsule.
pub struct ScopedTestInput<'a> {
    pub capsule_project: &'a std::path::Path,
    pub source_commit: &'a str,
    pub reference: &'a str,
    pub revision: &'a str,
}

/// What one scoped run executes in the capsule sandbox.
pub enum ScopedRun<'a> {
    /// Exactly these capsule-relative pytest files.
    Pytest(&'a [String]),
    /// One Cargo package's tests with cargo-nextest.
    Cargo(&'a CargoTests),
}

/// Copies the snapshot into a writable `/tmp/project` and enters the dev
/// environment; each run's command follows.
const SANDBOX_SETUP: &str = "export HOME=/tmp TMPDIR=/tmp PYTHONDONTWRITEBYTECODE=1; \"$1\" /tmp/project && \"$2\" -a /workspace/project/. /tmp/project/ && \"$3\" -R u+w /tmp/project && cd /tmp/project || exit; shift 3; source /tmp/environment; ";

const PYTEST: &str = "exec pytest --color=no -p no:cacheprovider -- \"$@\"";

const CARGO: &str = "export CARGO_HOME=/tmp/cargo CARGO_TARGET_DIR=/tmp/target; command -v cargo-nextest >/dev/null || { echo \"test.run cargo: cargo-nextest is not in the capsule's Nix dev environment\" >&2; exit 127; }; exec \"$@\"";

/// The account the sandbox's own user maps to in its generated passwd.
const SANDBOX_USER: &str = "capsule";

/// One-user passwd and group files for the sandbox, whose uid has no account there. Postgres' `initdb`, and
/// anything else that looks the running user up, refuses to start without one.
fn write_accounts(dir: &std::path::Path) -> Result<[std::path::PathBuf; 2], String> {
    use std::os::unix::fs::MetadataExt;
    let owner = std::fs::metadata(dir).map_err(|error| format!("{}: {error}", dir.display()))?;
    let (uid, gid) = (owner.uid(), owner.gid());
    let files = [
        (
            dir.join("passwd"),
            format!("{SANDBOX_USER}:x:{uid}:{gid}:{SANDBOX_USER}:/tmp:/bin/sh\n"),
        ),
        (dir.join("group"), format!("{SANDBOX_USER}:x:{gid}:\n")),
    ];
    for (path, text) in &files {
        std::fs::write(path, text).map_err(|error| format!("{}: {error}", path.display()))?;
    }
    Ok(files.map(|(path, _)| path))
}

/// The host's timezone database, the one the gate's tests read, resolved to where it really lives. The sandbox
/// has no `/usr/share/zoneinfo`; a dev environment that declares its own `TZDIR` overrides this one.
fn host_zoneinfo() -> Option<std::path::PathBuf> {
    let declared = std::env::var_os("TZDIR").unwrap_or_else(|| "/etc/zoneinfo".into());
    std::fs::canonicalize(declared)
        .ok()
        .filter(|path| path.is_dir())
}

/// The snapshot's crates as one store directory, from its own `Cargo.lock`
/// and its own `nixpkgs` input: the sandbox has no network.
fn vendor_expr(flake: &str) -> String {
    let system = format!("{}-{}", std::env::consts::ARCH, std::env::consts::OS);
    format!(
        "let flake = builtins.getFlake \"{flake}\"; lock = flake.outPath + \"/Cargo.lock\"; in \
         if !(flake.inputs ? nixpkgs) then throw \"test.run cargo needs a flake input named nixpkgs\" \
         else if !(builtins.pathExists lock) then throw \"test.run cargo needs Cargo.lock at the capsule root\" \
         else flake.inputs.nixpkgs.legacyPackages.{system}.rustPlatform.importCargoLock \
         {{ lockFile = lock; allowBuiltinFetchGit = true; }}"
    )
}

/// The command a cargo selection runs, as its run records it.
pub fn cargo_command(cargo: &CargoTests) -> Vec<String> {
    let mut args: Vec<String> =
        "cargo nextest run --locked --offline --no-fail-fast --color never -p"
            .split(' ')
            .map(str::to_owned)
            .collect();
    args.push(cargo.package.clone());
    match cargo.test.as_deref() {
        Some("lib") => args.push("--lib".to_owned()),
        Some(test) => args.extend(["--test".to_owned(), test.to_owned()]),
        None => {}
    }
    args.extend(cargo.filter.clone());
    args
}

/// The immutable store source Nix locked for exactly `revision`.
fn locked_source(metadata: &[u8], revision: &str) -> Result<std::path::PathBuf, String> {
    let metadata: serde_json::Value = serde_json::from_slice(metadata)
        .map_err(|error| format!("scoped test source metadata is unreadable: {error}"))?;
    if metadata["locked"]["rev"].as_str() != Some(revision) {
        return Err("scoped test source is not locked to the frozen snapshot".to_owned());
    }
    let logical = std::path::PathBuf::from(metadata["path"].as_str().unwrap_or_default());
    use std::path::Component;
    let shaped = logical.starts_with("/nix/store")
        && logical.components().count() == 4
        && logical
            .components()
            .all(|part| matches!(part, Component::RootDir | Component::Normal(_)));
    if !shaped {
        return Err("scoped test source is not an immutable store path".to_owned());
    }
    if logical.is_dir() {
        return Ok(logical);
    }
    Err("scoped test source is not an immutable store path".to_owned())
}

/// Programs pinned by the runtime manifest. Nix is not one of them: a
/// build or eval runs inside the lane bubble, never as a host process.
pub enum OwnedProgram {
    Git,
    /// The registered SSH client. Permitless lifecycles only (the remote
    /// generic harness hand-back).
    Ssh,
    /// bwrap around a daemon-owned command. The args are the bubble's own
    /// options and the inner command; the executable is the pinned bwrap.
    Bwrap,
}

/// One fixed step of an admitted coding operation or a permitless lifecycle.
pub struct OwnedStep<'a> {
    pub program: OwnedProgram,
    pub args: Vec<String>,
    pub environment: Vec<(String, String)>,
    pub current_dir: &'a std::path::Path,
    pub capture: Capture,
}

/// The earlier of `bound` and the permit's own expiry.
pub fn permit_deadline(effect: &PreparedEffect, bound: Instant) -> Result<Instant, String> {
    let now = u64::try_from(time::OffsetDateTime::now_utc().unix_timestamp_nanos() / 1_000_000)
        .map_err(|error| error.to_string())?;
    let remaining = effect.expires_at_ms().saturating_sub(now);
    if remaining == 0 {
        return Err("scoped test permit expired".to_owned());
    }
    Ok(bound.min(Instant::now() + Duration::from_millis(remaining)))
}

/// The snapshot commit through its own ref; the mutable working tree is
/// never read.
fn snapshot_flake(capsule: &std::path::Path, input: &ScopedTestInput<'_>) -> String {
    format!(
        "git+file://{}?ref={}&rev={}",
        capsule.display(),
        input.reference,
        input.revision
    )
}

/// The fixed Nix argv of one step, evaluated inside the lane bubble. The
/// host daemon builds; flake config from the project is never accepted.
fn nix_args(command: &[&str], flags: &[&str], target: String) -> Vec<String> {
    let mut args: Vec<String> = ["--extra-experimental-features", "nix-command flakes"]
        .iter()
        .chain(command)
        .chain(&[
            "--no-write-lock-file",
            "--option",
            "accept-flake-config",
            "false",
            "--option",
            "substitute",
            "true",
        ])
        .chain(flags)
        .map(|part| (*part).to_owned())
        .collect();
    args.push(target);
    args
}

fn confined_nix_argv(
    manifest: &odin_huginn::RuntimeManifest,
    capsule: &std::path::Path,
    nix_argv: &[String],
    sphere: Option<&odin_omp::process::SphereProjection>,
) -> Result<Vec<String>, String> {
    let nix = manifest
        .executable("nix")
        .map_err(|error| error.to_string())?;
    let mut command = vec![nix.path.display().to_string()];
    command.extend(nix_argv.iter().cloned());
    let mut tools = Vec::new();
    for key in ["nix", "git", "bash"] {
        if let Ok(executable) = manifest.executable(key) {
            if let Some(dir) = executable.path.parent() {
                if !tools.iter().any(|have| have == dir) {
                    tools.push(dir.to_path_buf());
                }
            }
        }
    }
    let fallback = odin_omp::process::SphereProjection {
        data_roots: Vec::new(),
        scratch: capsule.to_path_buf(),
        devices: Vec::new(),
        endpoints: Vec::new(),
    };
    let projection = sphere.unwrap_or(&fallback);
    odin_omp::process::capsule_nix_argv(capsule, projection, &tools, &command)
}

impl SessionAuthorityPool {
    /// Runs in an already admitted directory, with or without a code capsule.
    /// Cancelled or expired permits prevent launch; cleanup completes before return.
    pub fn run_owned_step(
        &self,
        effect: &PreparedEffect,
        scope: &Scope,
        step: OwnedStep<'_>,
        deadline: Instant,
    ) -> Result<Captured, String> {
        let (owner, _, _) = self.session_owner(effect, scope, None)?;
        let deadline = permit_deadline(effect, deadline)?;
        self.run_step(
            &owner,
            Cancel::Permit(&effect.stop_handle()),
            step,
            deadline,
        )
    }

    /// Runs permitless lifecycle Git/SSH work under the pool's registration.
    /// Cancellation, closure, or expiry prevents launch. Unconfirmed worker cleanup
    /// blocks further launches until pool retirement.
    pub fn run_lifecycle_step(
        &self,
        step: OwnedStep<'_>,
        cancel: &AtomicBool,
        deadline: Instant,
    ) -> Result<Captured, String> {
        let owner = self.lifecycle_owner()?;
        self.run_step(&owner, Cancel::Lifecycle(cancel), step, deadline)
    }

    /// The pool's one owner of permitless lifecycle workers, opened on first
    /// use and retired with the pool.
    fn lifecycle_owner(&self) -> Result<Arc<ScopedTests>, String> {
        let mut lifecycle = self
            .lifecycle
            .lock()
            .map_err(|_| "lifecycle worker owner lock poisoned")?;
        if self.closed.load(Ordering::Acquire) {
            return Err("session pool is closed".to_owned());
        }
        if let Some(owner) = lifecycle.as_ref() {
            return Ok(Arc::clone(owner));
        }
        let owner = Arc::new(ScopedTests::new(WorkerLauncher::open_with_channel(
            &self.config,
            &self.manifest,
            &self.state_root.join("lifecycle-workers"),
            self.worker_channel.clone(),
        )?));
        *lifecycle = Some(Arc::clone(&owner));
        Ok(owner)
    }

    /// Retires the lifecycle owner's workers by `deadline` (the pool's
    /// shutdown stage). Nothing to retire when no lifecycle step ever ran.
    pub(super) fn retire_lifecycle(&self, deadline: Instant) -> Result<(), String> {
        let Some(owner) = super::lock_until(&self.lifecycle, deadline)?.take() else {
            return Ok(());
        };
        let retired = owner.retire(deadline);
        if retired.is_err() {
            // Unproved workers stay disarmed and named; nothing retires them
            // again behind the shutdown's back.
            owner.abandon();
        }
        retired
    }

    /// Gives the lifecycle owner up without any stop; true when one existed.
    pub(super) fn abandon_lifecycle(&self) -> bool {
        let owner = match self.lifecycle.try_lock() {
            Ok(mut lifecycle) => lifecycle.take(),
            Err(std::sync::TryLockError::Poisoned(error)) => error.into_inner().take(),
            Err(std::sync::TryLockError::WouldBlock) => return true,
        };
        owner.is_some_and(|owner| {
            owner.abandon();
            true
        })
    }

    fn run_step(
        &self,
        owner: &ScopedTests,
        cancel: Cancel<'_>,
        step: OwnedStep<'_>,
        deadline: Instant,
    ) -> Result<Captured, String> {
        let OwnedStep {
            program,
            args,
            environment,
            current_dir,
            capture,
        } = step;
        let (executable_id, role) = match (program, &cancel) {
            (OwnedProgram::Git, Cancel::Permit(_)) => ("git", "coding-git"),
            (OwnedProgram::Git, Cancel::Lifecycle(_)) => ("git", "lifecycle-git"),
            (OwnedProgram::Ssh, Cancel::Lifecycle(_)) => ("ssh", "lifecycle-ssh"),
            (OwnedProgram::Bwrap, Cancel::Permit(_)) => ("bwrap", "coding-bwrap"),
            (OwnedProgram::Ssh, Cancel::Permit(_)) => {
                return Err("an admitted coding step runs Git or a capsule command".to_owned())
            }
            (OwnedProgram::Bwrap, Cancel::Lifecycle(_)) => {
                return Err("a lifecycle step runs Git or SSH only".to_owned())
            }
        };
        owner.run(
            self,
            cancel,
            WorkerLaunchSpec {
                parent_broker: None,
                executable_id,
                role,
                args,
                environment,
                current_dir,
                runtime_max: deadline.saturating_duration_since(Instant::now()),
            },
            capture,
        )
    }

    /// The admitted session's owner of its workers and its registered
    /// capsule, when the permit and scope name this registration — and, for a
    /// test run, its frozen `input` names the registered Git capsule.
    fn session_owner(
        &self,
        effect: &PreparedEffect,
        scope: &Scope,
        input: Option<&ScopedTestInput<'_>>,
    ) -> Result<(Arc<ScopedTests>, std::path::PathBuf, u64), String> {
        let session = scope
            .session
            .as_ref()
            .ok_or("scoped tests require a session")?;
        let capsule_id = odin_omp::host_tools::operations::session_capsule_id(session)
            .map_err(|error| error.to_string())?;
        if &capsule_id != effect.capsule_id() {
            return Err("scoped test capsule differs from permit".to_owned());
        }
        let (owner, capsule, revision) = {
            let mut inner = self
                .inner
                .lock()
                .map_err(|_| "session pool lock poisoned")?;
            if self.closed.load(Ordering::Acquire) {
                return Err("session pool is closed".to_owned());
            }
            let session_owner = inner
                .sessions
                .get_mut(&capsule_id)
                .ok_or("session capsule is not registered")?;
            if session_owner.registration.session != *session
                || scope.seat.as_ref() != Some(&session_owner.registration.binding.policy.seat_id)
            {
                return Err("scoped test session differs from registration".to_owned());
            }
            // The frozen input must be the registered Git capsule itself:
            // a derived path never selects another registration's tree.
            let registration = &session_owner.registration;
            if input.is_some_and(|input| {
                registration.source_kind != odin_sidecar_protocol::SOURCE_KIND_GIT_COMMIT
                    || registration.capsule_project != input.capsule_project
                    || registration.source_commit != input.source_commit
            }) {
                return Err("scoped test input differs from the registered Git capsule".to_owned());
            }
            if session_owner.scoped_tests.is_none() {
                let root = self
                    .state_root
                    .join(format!("capsule-{}", capsule_id.as_str().replace(':', "-")));
                session_owner.scoped_tests = Some(Arc::new(ScopedTests::new(
                    WorkerLauncher::open_with_channel(
                        &self.config,
                        &self.manifest,
                        &root.join("scoped-tests"),
                        self.worker_channel.clone(),
                    )?,
                )));
            }
            (
                Arc::clone(
                    session_owner
                        .scoped_tests
                        .as_ref()
                        .ok_or("scoped test owner absent")?,
                ),
                session_owner.registration.capsule_project.clone(),
                session_owner.registration.binding.served_revision,
            )
        };
        Ok((owner, capsule, revision))
    }

    /// Runs only the admitted session's selected tests on the frozen
    /// snapshot `input` pins; shell setup is interpreted inside the capsule
    /// sandbox, never by the daemon's shell.
    pub fn run_scoped_tests(
        &self,
        effect: &PreparedEffect,
        scope: &Scope,
        input: &ScopedTestInput<'_>,
        run: ScopedRun<'_>,
    ) -> Result<NixLog, String> {
        let (owner, capsule, revision) = self.session_owner(effect, scope, Some(input))?;
        let (snapshot, _) = odin_registry::SnapshotStore::new(&self.config.paths.registry_snapshot)
            .publication_at(revision)
            .map_err(|error| format!("test sphere publication {revision}: {error}"))?;
        let sphere = scope
            .project
            .as_ref()
            .and_then(|project| odin_omp::process::project_sphere(snapshot.objects.iter(), project))
            .map(odin_omp::process::SphereProjection::from_sphere)
            .transpose()?;
        let started = Instant::now();
        let deadline = permit_deadline(effect, started + Duration::from_millis(1_200_000))?;
        let scratch = Scratch(
            self.state_root
                .join(format!("scoped-test-{}", uuid::Uuid::new_v4())),
        );
        crate::eval_daemon::create_private_dir(&scratch.0)?;
        let flake = snapshot_flake(&capsule, input);
        let stop = effect.stop_handle();
        let nix = |role: &'static str, args: Vec<String>| {
            let argv = confined_nix_argv(&self.manifest, &capsule, &args, sphere.as_ref())?;
            owner
                .run(
                    self,
                    Cancel::Permit(&stop),
                    WorkerLaunchSpec {
                        parent_broker: None,
                        executable_id: "bwrap",
                        role,
                        args: argv,
                        environment: Vec::new(),
                        current_dir: &capsule,
                        runtime_max: deadline.saturating_duration_since(Instant::now()),
                    },
                    Capture::default(),
                )
                .map(|captured| captured.output)
        };
        let failed = |output: &std::process::Output| NixLog {
            ok: false,
            log: String::from_utf8_lossy(&output.stderr).into_owned(),
            seconds: started.elapsed().as_secs(),
        };
        let metadata = nix(
            "test-source",
            nix_args(&["flake", "metadata"], &["--json"], flake.clone()),
        )?;
        if !metadata.status.success() {
            return Ok(failed(&metadata));
        }
        let source = locked_source(&metadata.stdout, input.revision)?;
        let environment = nix(
            "test-environment",
            nix_args(&["print-dev-env"], &[], flake.clone()),
        )?;
        if !environment.status.success() {
            return Ok(failed(&environment));
        }
        let env_text = String::from_utf8_lossy(&environment.stdout).into_owned();
        let setup = scratch.0.join("environment");
        std::fs::write(&setup, &env_text).map_err(|error| error.to_string())?;
        let bwrap = self
            .manifest
            .executable("bwrap")
            .map_err(|error| error.to_string())?;
        let bash = self
            .manifest
            .executable("bash")
            .map_err(|error| error.to_string())?;
        // The locked immutable source of the snapshot, never the capsule.
        let mut args = odin_process::capsule_sandbox_argv(
            bwrap.path.display().to_string(),
            &source,
            "--ro-bind",
        );
        args.remove(0);
        if let Some(sphere) = sphere.as_ref() {
            for root in &sphere.data_roots {
                args.extend([
                    "--ro-bind".into(),
                    root.display().to_string(),
                    root.display().to_string(),
                ]);
            }
            args.extend([
                "--bind".into(),
                sphere.scratch.display().to_string(),
                sphere.scratch.display().to_string(),
            ]);
        }
        // `/bin/sh` as in Nix's build sandbox: test fakes start `#!/bin/sh`.
        args.extend([
            "--ro-bind".into(),
            setup.display().to_string(),
            "/tmp/environment".into(),
            "--ro-bind".into(),
            bash.path.display().to_string(),
            "/bin/sh".into(),
        ]);
        for (account, sandboxed) in write_accounts(&scratch.0)?.iter().zip(["passwd", "group"]) {
            args.extend([
                "--ro-bind".into(),
                account.display().to_string(),
                format!("/etc/{sandboxed}"),
            ]);
        }
        if let Some(zoneinfo) = host_zoneinfo() {
            let zoneinfo = zoneinfo.display().to_string();
            args.extend([
                "--ro-bind".into(),
                zoneinfo.clone(),
                zoneinfo.clone(),
                "--setenv".into(),
                "TZDIR".into(),
                zoneinfo,
            ]);
        }
        let (role, command, selected) = match run {
            ScopedRun::Pytest(paths) => ("pytest", PYTEST, paths.to_vec()),
            ScopedRun::Cargo(cargo) => {
                let vendored = nix(
                    "test-crates",
                    nix_args(
                        &["build"],
                        &["--no-link", "--print-out-paths", "--expr"],
                        vendor_expr(&flake),
                    ),
                )?;
                if !vendored.status.success() {
                    return Ok(failed(&vendored));
                }
                let logical = String::from_utf8_lossy(&vendored.stdout).trim().to_owned();
                let config = std::fs::read_to_string(
                    std::path::Path::new(&logical).join(".cargo/config.toml"),
                )
                .map_err(|error| format!("vendored crates of {logical}: {error}"))?
                .replace("\"cargo-vendor-dir\"", &format!("\"{logical}\""));
                let config_path = scratch.0.join("cargo-config.toml");
                let target = scratch.0.join("target");
                std::fs::write(&config_path, config).map_err(|error| error.to_string())?;
                crate::eval_daemon::create_private_dir(&target)?;
                args.extend([
                    "--ro-bind".into(),
                    config_path.display().to_string(),
                    "/tmp/cargo/config.toml".into(),
                    "--bind".into(),
                    target.display().to_string(),
                    "/tmp/target".into(),
                ]);
                ("cargo-nextest", CARGO, cargo_command(cargo))
            }
        };
        args.extend([
            "--chdir".into(),
            "/workspace/project".into(),
            "--".into(),
            bash.path.display().to_string(),
            "--noprofile".into(),
            "--norc".into(),
            "-c".into(),
            format!("{SANDBOX_SETUP}{command}"),
            "scoped-test".into(),
        ]);
        for utility in ["mkdir", "cp", "chmod"] {
            args.push(
                self.manifest
                    .executable(utility)
                    .map_err(|error| error.to_string())?
                    .path
                    .display()
                    .to_string(),
            );
        }
        args.extend(selected);
        let output = owner
            .run(
                self,
                Cancel::Permit(&stop),
                WorkerLaunchSpec {
                    parent_broker: None,
                    executable_id: "bwrap",
                    role,
                    args,
                    environment: Vec::new(),
                    current_dir: &capsule,
                    runtime_max: deadline.saturating_duration_since(Instant::now()),
                },
                // A runner's failures and summary come last, so a long run keeps its tail.
                Capture {
                    stdout: Retention::Tail,
                    stderr: Retention::Tail,
                },
            )?
            .output;
        let mut log = String::from_utf8_lossy(&output.stderr).into_owned();
        log.push('\n');
        log.push_str(&String::from_utf8_lossy(&output.stdout));
        if log.len() > OUTPUT_LIMIT {
            let mut start = log.len() - OUTPUT_LIMIT;
            while !log.is_char_boundary(start) {
                start += 1;
            }
            log.drain(..start);
        }
        Ok(NixLog {
            ok: output.status.success(),
            log,
            seconds: started.elapsed().as_secs(),
        })
    }
}
