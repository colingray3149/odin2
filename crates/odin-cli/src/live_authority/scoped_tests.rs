//! Test runs and Git/Nix steps registered to the session's worker scope.

use std::collections::VecDeque;
use std::io::{ErrorKind, Read};
use std::os::fd::AsFd;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use odin_domain::{Scope, StopVerdict};
use odin_hermes::runtime::coding::NixLog;
use odin_kernel::operation::PreparedEffect;
use odin_types::WorkerId;

use super::SessionAuthorityPool;
use crate::eval_daemon::{WorkerLaunchSpec, WorkerLauncher};

const OUTPUT_LIMIT: usize = 8 * 1024 * 1024;

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

/// The immutable store source Nix locked for exactly `revision`.
fn locked_source(metadata: &[u8], revision: &str) -> Result<std::path::PathBuf, String> {
    let metadata: serde_json::Value = serde_json::from_slice(metadata)
        .map_err(|error| format!("scoped test source metadata is unreadable: {error}"))?;
    if metadata["locked"]["rev"].as_str() != Some(revision) {
        return Err("scoped test source is not locked to the frozen snapshot".to_owned());
    }
    let path = std::path::PathBuf::from(metadata["path"].as_str().unwrap_or_default());
    use std::path::Component;
    let immutable = path.starts_with("/nix/store")
        && path.components().count() == 4
        && path
            .components()
            .all(|part| matches!(part, Component::RootDir | Component::Normal(_)))
        && path.is_dir();
    if !immutable {
        return Err("scoped test source is not an immutable store path".to_owned());
    }
    Ok(path)
}

/// One Nix step of a flake-attr test run over its frozen snapshot.
pub enum AttrNix<'a> {
    /// `nix build` of the named output, printing its build log.
    Build(&'a str),
    /// `nix flake check`, printing every build log.
    Check,
    /// The stored build log of the named output (a cached build printed none).
    Log(&'a str),
}

/// Programs pinned by the runtime manifest.
pub enum OwnedProgram {
    Git,
    /// Nix, with a private per-step fetcher cache. Admitted operations only.
    Nix,
    /// The registered SSH client. Permitless lifecycles only (the remote
    /// generic harness hand-back).
    Ssh,
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

/// The fixed Nix argv of one step: pure flake options, then `target`.
fn nix_args(verb: &[&str], target: String) -> Vec<String> {
    let mut args: Vec<String> = ["--extra-experimental-features", "nix-command flakes"]
        .iter()
        .chain(verb)
        .chain(&[
            "--no-write-lock-file",
            "--option",
            "accept-flake-config",
            "false",
            "--option",
            "sandbox",
            "true",
        ])
        .map(|part| (*part).to_owned())
        .collect();
    args.push(target);
    args
}

impl SessionAuthorityPool {
    /// Runs against the frozen snapshot; cancellation and the permit deadline
    /// stop the registered worker before returning.
    pub fn run_attr_nix(
        &self,
        effect: &PreparedEffect,
        scope: &Scope,
        input: &ScopedTestInput<'_>,
        step: AttrNix<'_>,
        deadline: Instant,
    ) -> Result<std::process::Output, String> {
        let (owner, capsule) = self.session_owner(effect, scope, Some(input))?;
        let flake = snapshot_flake(&capsule, input);
        let capture = match &step {
            AttrNix::Log(_) => Capture {
                stdout: Retention::Tail,
                ..Capture::default()
            },
            AttrNix::Build(_) | AttrNix::Check => Capture {
                stderr: Retention::Tail,
                ..Capture::default()
            },
        };
        let args = match step {
            AttrNix::Build(attr) => nix_args(
                &[
                    "build",
                    "--no-link",
                    "--print-out-paths",
                    "--print-build-logs",
                ],
                format!("{flake}#{attr}"),
            ),
            AttrNix::Check => nix_args(&["flake", "check", "--print-build-logs"], flake),
            AttrNix::Log(attr) => nix_args(&["log"], format!("{flake}#{attr}")),
        };
        let step = OwnedStep {
            program: OwnedProgram::Nix,
            args,
            environment: Vec::new(),
            current_dir: &capsule,
            capture,
        };
        let deadline = permit_deadline(effect, deadline)?;
        self.run_step(
            &owner,
            Cancel::Permit(&effect.stop_handle()),
            step,
            deadline,
        )
        .map(|captured| captured.output)
    }

    /// Runs in an already admitted directory, with or without a code capsule.
    /// Cancelled or expired permits prevent launch; cleanup completes before return.
    pub fn run_owned_step(
        &self,
        effect: &PreparedEffect,
        scope: &Scope,
        step: OwnedStep<'_>,
        deadline: Instant,
    ) -> Result<Captured, String> {
        let (owner, _) = self.session_owner(effect, scope, None)?;
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
            mut environment,
            current_dir,
            capture,
        } = step;
        let mut scratch = None;
        let (executable_id, role) = match (program, &cancel) {
            (OwnedProgram::Git, Cancel::Permit(_)) => ("git", "coding-git"),
            (OwnedProgram::Git, Cancel::Lifecycle(_)) => ("git", "lifecycle-git"),
            (OwnedProgram::Ssh, Cancel::Lifecycle(_)) => ("ssh", "lifecycle-ssh"),
            (OwnedProgram::Nix, Cancel::Permit(_)) => {
                // No session worker writes a fetcher cache another reads.
                let cache = Scratch(
                    self.state_root
                        .join(format!("scoped-test-{}", uuid::Uuid::new_v4())),
                );
                crate::eval_daemon::create_private_dir(&cache.0)?;
                environment.push(("XDG_CACHE_HOME".into(), cache.0.display().to_string()));
                scratch = Some(cache);
                ("nix", "coding-nix")
            }
            (OwnedProgram::Ssh, Cancel::Permit(_)) => {
                return Err("an admitted coding step runs Git or Nix only".to_owned())
            }
            (OwnedProgram::Nix, Cancel::Lifecycle(_)) => {
                return Err("a lifecycle step runs Git or SSH only".to_owned())
            }
        };
        let output = owner.run(
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
        );
        drop(scratch);
        output
    }

    /// The admitted session's owner of its workers and its registered
    /// capsule, when the permit and scope name this registration — and, for a
    /// test run, its frozen `input` names the registered Git capsule.
    fn session_owner(
        &self,
        effect: &PreparedEffect,
        scope: &Scope,
        input: Option<&ScopedTestInput<'_>>,
    ) -> Result<(Arc<ScopedTests>, std::path::PathBuf), String> {
        let session = scope
            .session
            .as_ref()
            .ok_or("scoped tests require a session")?;
        let capsule_id = odin_omp::host_tools::operations::session_capsule_id(session)
            .map_err(|error| error.to_string())?;
        if &capsule_id != effect.capsule_id() {
            return Err("scoped test capsule differs from permit".to_owned());
        }
        let (owner, capsule) = {
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
            )
        };
        Ok((owner, capsule))
    }

    /// Runs only the admitted session's selected pytest files on the frozen
    /// snapshot `input` pins; shell setup is interpreted inside the capsule
    /// sandbox, never by the daemon's shell.
    pub fn run_scoped_tests(
        &self,
        effect: &PreparedEffect,
        scope: &Scope,
        input: &ScopedTestInput<'_>,
        paths: &[String],
    ) -> Result<NixLog, String> {
        let (owner, capsule) = self.session_owner(effect, scope, Some(input))?;
        let started = Instant::now();
        let deadline = permit_deadline(effect, started + Duration::from_millis(1_200_000))?;
        let scratch = Scratch(
            self.state_root
                .join(format!("scoped-test-{}", uuid::Uuid::new_v4())),
        );
        crate::eval_daemon::create_private_dir(&scratch.0)?;
        // Both Nix steps resolve the snapshot commit through its own ref.
        let flake = snapshot_flake(&capsule, input);
        let stop = effect.stop_handle();
        let nix = |role: &'static str, verb: &[&str]| {
            owner
                .run(
                    self,
                    Cancel::Permit(&stop),
                    WorkerLaunchSpec {
                        parent_broker: None,
                        executable_id: "nix",
                        role,
                        args: nix_args(verb, flake.clone()),
                        environment: vec![(
                            "XDG_CACHE_HOME".into(),
                            scratch.0.display().to_string(),
                        )],
                        current_dir: &capsule,
                        runtime_max: deadline.saturating_duration_since(Instant::now()),
                    },
                    Capture::default(),
                )
                .map(|captured| captured.output)
        };
        let metadata = nix("test-source", &["flake", "metadata", "--json"])?;
        if !metadata.status.success() {
            return Ok(NixLog {
                ok: false,
                log: String::from_utf8_lossy(&metadata.stderr).into_owned(),
                seconds: started.elapsed().as_secs(),
            });
        }
        let source = locked_source(&metadata.stdout, input.revision)?;
        let environment = nix("test-environment", &["print-dev-env"])?;
        if !environment.status.success() {
            return Ok(NixLog {
                ok: false,
                log: String::from_utf8_lossy(&environment.stderr).into_owned(),
                seconds: started.elapsed().as_secs(),
            });
        }
        let setup = scratch.0.join("environment");
        std::fs::write(&setup, environment.stdout).map_err(|error| error.to_string())?;
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
        args.extend(["--ro-bind".into(), setup.display().to_string(), "/tmp/environment".into(),
            "--chdir".into(), "/workspace/project".into(), "--".into(), bash.path.display().to_string(),
            "--noprofile".into(), "--norc".into(), "-c".into(),
            "export HOME=/tmp TMPDIR=/tmp PYTHONDONTWRITEBYTECODE=1; \"$1\" /tmp/project && \"$2\" -a /workspace/project/. /tmp/project/ && \"$3\" -R u+w /tmp/project && cd /tmp/project || exit; shift 3; source /tmp/environment; exec pytest --color=no -p no:cacheprovider -- \"$@\"".into(), "scoped-test".into()]);
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
        args.extend(paths.iter().cloned());
        let output = owner
            .run(
                self,
                Cancel::Permit(&stop),
                WorkerLaunchSpec {
                    parent_broker: None,
                    executable_id: "bwrap",
                    role: "pytest",
                    args,
                    environment: Vec::new(),
                    current_dir: &capsule,
                    runtime_max: deadline.saturating_duration_since(Instant::now()),
                },
                Capture::default(),
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
