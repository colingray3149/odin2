use std::os::unix::process::ExitStatusExt;
use std::path::PathBuf;
use std::process::{ChildStderr, ChildStdout, ExitStatus};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::thread;
use std::time::{Duration, Instant};

use odin_domain::{StopResidue, StopVerdict};
use odin_types::{CorrelationId, WorkerId};
use rustix::fs::{fcntl_getfl, fcntl_setfl, OFlags};

use crate::identity::read_process_identity;
use crate::output::OutputCollector;
use crate::{
    mint_worker_id, AllowlistedEnvironment, CapturedOutput, EnvironmentBuilder, FrozenArgv,
    IdentitySnapshot, ScanCriteria, ScopeLifetime, ScopeLimits, SurvivorScanner, WorkerError,
    WorkerErrorCode, WorkerIdentity, WorkerNaming,
};

#[cfg(test)]
use std::collections::BTreeMap;

#[cfg(test)]
use std::sync::Mutex;

#[cfg(test)]
use crate::{WorkerAuthority, WorkerChannel};

#[derive(Clone, Debug)]
pub struct CommandSpec {
    pub argv: FrozenArgv,
    pub environment: AllowlistedEnvironment,
    pub current_dir: PathBuf,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProcessLimits {
    pub timeout: Duration,
    pub termination_grace: Duration,
    pub poll_interval: Duration,
    pub max_stdout_bytes: usize,
    pub max_stderr_bytes: usize,
}

impl ProcessLimits {
    pub fn validate(self) -> Result<Self, crate::ProcessError> {
        if self.timeout.is_zero()
            || self.termination_grace.is_zero()
            || self.poll_interval.is_zero()
            || self.max_stdout_bytes == 0
            || self.max_stderr_bytes == 0
        {
            return Err(crate::ProcessError::new(
                crate::ProcessErrorCode::InvalidLimits,
                "timeouts, polling interval, and output ceilings must be nonzero",
            ));
        }
        Ok(self)
    }
}

impl Default for ProcessLimits {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(30),
            termination_grace: Duration::from_secs(2),
            poll_interval: Duration::from_millis(5),
            max_stdout_bytes: 256 * 1_024,
            max_stderr_bytes: 256 * 1_024,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ExitDisposition {
    Exited(i32),
    Signaled(i32),
    TimedOut { escalated: bool },
    Interrupted { escalated: bool },
    OutputLimit { escalated: bool },
}

/// Capture truncation does not turn a completed exit into a stop.
pub(crate) fn unstopped_disposition(status: ExitStatus) -> ExitDisposition {
    status
        .code()
        .map(ExitDisposition::Exited)
        .or_else(|| status.signal().map(ExitDisposition::Signaled))
        .unwrap_or(ExitDisposition::Signaled(0))
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProcessOutcome {
    pub disposition: ExitDisposition,
    pub stdout: CapturedOutput,
    pub stderr: CapturedOutput,
    pub identity: crate::ProcessIdentity,
    /// `None` means the payload exited without a stop request.
    pub stop: Option<ProcessStopEvidence>,
}

/// `kill_sent` records a systemd control-group stop; `identities` is a supplemental `/proc` scan.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct TeardownReport {
    pub term_sent: bool,
    pub kill_sent: bool,
    pub stopped: bool,
    pub scan_complete: bool,
    pub identities: IdentitySnapshot,
    pub residue: Option<StopResidue>,
}

#[derive(Clone, Debug, Default)]
pub struct CancellationToken(Arc<AtomicBool>);

impl CancellationToken {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn cancel(&self) {
        self.0.store(true, Ordering::SeqCst);
    }

    pub fn is_cancelled(&self) -> bool {
        self.0.load(Ordering::SeqCst)
    }
}

/// Launch, wait, and stop use the transport so the supervisor cannot bypass kernel authorization.
pub struct ProcessSupervisor {
    limits: ProcessLimits,
    transport: Arc<dyn ProcessTransport>,
    active: Option<WorkerId>,
    torn_down: bool,
    attempt: u32,
}

impl std::fmt::Debug for ProcessSupervisor {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ProcessSupervisor")
            .field("limits", &self.limits)
            .field("active", &self.active)
            .field("torn_down", &self.torn_down)
            .field("attempt", &self.attempt)
            .finish_non_exhaustive()
    }
}

/// Admission is complete before transport launch; the transport adds no policy.
#[derive(Clone, Debug)]
pub struct ProcessLaunchRequest {
    pub worker_id: WorkerId,
    pub correlation: CorrelationId,
    pub naming: WorkerNaming,
    pub spec: CommandSpec,
    pub scope_limits: ScopeLimits,
}

/// Only identity and output pipes cross this interface; wait and stop use WorkerId.
#[derive(Debug)]
pub struct ProcessLaunchResult {
    pub identity: WorkerIdentity,
    pub stdout: ChildStdout,
    pub stderr: ChildStderr,
}

pub trait ProcessLaunch {
    fn launch(&self, request: ProcessLaunchRequest) -> Result<ProcessLaunchResult, WorkerError>;
}

pub trait ProcessControl {
    fn try_wait(&self, worker_id: &WorkerId) -> Result<Option<ExitStatus>, WorkerError>;

    fn stop(&self, worker_id: &WorkerId) -> Result<ProcessStopEvidence, WorkerError>;
}

/// A single adapter can provide launch and control through one trait object.
pub trait ProcessTransport: ProcessLaunch + ProcessControl {}

impl<T: ProcessLaunch + ProcessControl + ?Sized> ProcessTransport for T {}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProcessStopEvidence {
    pub worker_id: WorkerId,
    pub verdict: StopVerdict,
    pub replay: bool,
    pub term_sent: bool,
    pub cgroup_kill: bool,
}

impl ProcessStopEvidence {
    /// Only a `Stopped` verdict counts as a clean teardown.
    pub fn stopped(&self) -> bool {
        matches!(self.verdict, StopVerdict::Stopped)
    }

    pub fn residue(&self) -> Option<StopResidue> {
        match &self.verdict {
            StopVerdict::Failed(residue) => Some(residue.clone()),
            _ => None,
        }
    }
}

impl ProcessSupervisor {
    pub fn new(
        limits: ProcessLimits,
        transport: Arc<dyn ProcessTransport>,
    ) -> Result<Self, crate::ProcessError> {
        Ok(Self {
            limits: limits.validate()?,
            transport,
            active: None,
            torn_down: false,
            attempt: 0,
        })
    }

    pub fn limits(&self) -> ProcessLimits {
        self.limits
    }

    /// Errors after launch must stop the worker before returning.
    pub fn run(
        &mut self,
        spec: &CommandSpec,
        cancellation: &CancellationToken,
    ) -> Result<ProcessOutcome, WorkerError> {
        if !spec.current_dir.is_absolute() {
            return Err(WorkerError::new(
                WorkerErrorCode::Spawn,
                "worker current_dir must be absolute",
            ));
        }
        if self.active.is_some() {
            return Err(WorkerError::new(
                WorkerErrorCode::Spawn,
                "a ProcessSupervisor may own only one live worker",
            ));
        }
        self.attempt = self.attempt.checked_add(1).ok_or_else(|| {
            WorkerError::new(WorkerErrorCode::Spawn, "worker attempt counter overflow")
        })?;
        let worker_id = mint_worker_id()?;
        // Use a fresh worker-derived token when the caller supplied no valid correlation.
        let caller_correlation = spec
            .environment
            .get(crate::CORRELATION_ENV)
            .and_then(|value| value.to_str())
            .and_then(|value| CorrelationId::new(value).ok());
        let correlation = caller_correlation.clone().unwrap_or_else(|| {
            CorrelationId::new(worker_id.as_str())
                .expect("minted worker id hex is a valid correlation token")
        });
        let tx_id = spec
            .environment
            .get(crate::CORRELATION_ENV)
            .map(|value| value.to_string_lossy().into_owned())
            .filter(|value| !value.is_empty())
            .unwrap_or_else(|| {
                format!(
                    "internal{}",
                    worker_id.as_str().chars().take(16).collect::<String>()
                )
            });
        let naming = WorkerNaming::new(tx_id, "process", self.attempt, worker_id.clone())?;
        let scope_limits = ScopeLimits {
            lifetime: ScopeLifetime::Bounded(self.limits.timeout),
            timeout_stop: self.limits.termination_grace,
            memory_high: None,
            memory_max: None,
            tasks_max: None,
        };
        // The payload environment must carry the same correlation as its durable record.
        let spec = match caller_correlation {
            Some(_) => spec.clone(),
            None => admitted_spec_with_correlation(spec, &correlation)?,
        };
        let request = ProcessLaunchRequest {
            worker_id: worker_id.clone(),
            correlation,
            naming,
            spec,
            scope_limits,
        };
        let launched = self.transport.launch(request)?;
        if launched.identity.worker_id != worker_id {
            let _ = self.transport.stop(&launched.identity.worker_id);
            return Err(WorkerError::new(
                WorkerErrorCode::IdentityProof,
                "transport launched a foreign worker identity",
            ));
        }
        let correlation_token_present = caller_correlation.is_some();
        match self.supervise(
            &worker_id,
            launched,
            correlation_token_present,
            cancellation,
        ) {
            Ok(outcome) => {
                self.active = Some(worker_id);
                self.torn_down = false;
                Ok(outcome)
            }
            Err(error) => {
                // A supervision error must not leave a live worker.
                let _ = self.transport.stop(&worker_id);
                Err(error)
            }
        }
    }

    fn supervise(
        &mut self,
        worker_id: &WorkerId,
        launched: ProcessLaunchResult,
        correlation_token_present: bool,
        cancellation: &CancellationToken,
    ) -> Result<ProcessOutcome, WorkerError> {
        let leader_pid = launched.identity.leader_pid;
        let mut identity = read_process_identity(leader_pid).ok_or_else(|| {
            WorkerError::new(
                WorkerErrorCode::IdentityProof,
                format!("cannot read kernel identity for worker leader {leader_pid}"),
            )
        })?;
        identity.correlation_token_present = correlation_token_present;
        identity.fixture_root_referenced = true;

        let mut stdout = launched.stdout;
        let mut stderr = launched.stderr;
        set_nonblocking(&stdout)?;
        set_nonblocking(&stderr)?;
        let mut stdout_collector = OutputCollector::new(self.limits.max_stdout_bytes);
        let mut stderr_collector = OutputCollector::new(self.limits.max_stderr_bytes);
        let deadline = Instant::now() + self.limits.timeout;

        let (normal_status, stop) = loop {
            stdout_collector.drain(&mut stdout).map_err(io_error)?;
            stderr_collector.drain(&mut stderr).map_err(io_error)?;
            if let Some(status) = self.transport.try_wait(worker_id)? {
                break (Some(status), None);
            }
            let reason = if cancellation.is_cancelled() {
                Some(StopReason::Interrupted)
            } else if stdout_collector.exceeded() || stderr_collector.exceeded() {
                Some(StopReason::OutputLimit)
            } else if Instant::now() >= deadline {
                Some(StopReason::TimedOut)
            } else {
                None
            };
            if let Some(reason) = reason {
                let evidence = self.transport.stop(worker_id)?;
                break (None, Some((reason, evidence)));
            }
            sleep_until_next_check(deadline, self.limits.poll_interval);
        };

        stdout_collector.drain(&mut stdout).map_err(io_error)?;
        stderr_collector.drain(&mut stderr).map_err(io_error)?;
        // Truncation after exit is a capture property, not a stop.
        let (disposition, stop_evidence) = match stop {
            Some((reason, evidence)) => {
                let escalated = evidence.cgroup_kill;
                let disposition = match reason {
                    StopReason::TimedOut => ExitDisposition::TimedOut { escalated },
                    StopReason::Interrupted => ExitDisposition::Interrupted { escalated },
                    StopReason::OutputLimit => ExitDisposition::OutputLimit { escalated },
                };
                (disposition, Some(evidence))
            }
            None => {
                let status = normal_status.ok_or_else(|| {
                    WorkerError::new(
                        WorkerErrorCode::Reap,
                        "worker exited without an observable status",
                    )
                })?;
                (unstopped_disposition(status), None)
            }
        };
        Ok(ProcessOutcome {
            disposition,
            stdout: stdout_collector.finish(),
            stderr: stderr_collector.finish(),
            identity,
            stop: stop_evidence,
        })
    }

    pub fn cleanup(
        &mut self,
        criteria: &ScanCriteria,
        scanner: &SurvivorScanner,
    ) -> Result<TeardownReport, WorkerError> {
        let evidence = match self.active.as_ref() {
            Some(worker_id) if !self.torn_down => Some(self.transport.stop(worker_id)?),
            _ => None,
        };
        if evidence.is_some() {
            self.torn_down = true;
        }
        let identities = scanner.scan(criteria).map_err(WorkerError::from)?;
        match evidence {
            Some(evidence) => Ok(TeardownReport {
                term_sent: evidence.term_sent,
                kill_sent: evidence.cgroup_kill,
                stopped: evidence.stopped(),
                scan_complete: true,
                identities,
                residue: evidence.residue(),
            }),
            None => Ok(TeardownReport {
                stopped: true,
                scan_complete: true,
                identities,
                ..TeardownReport::default()
            }),
        }
    }
}

impl Drop for ProcessSupervisor {
    fn drop(&mut self) {
        // Drop must attempt to stop a live worker even though it cannot return an error.
        if let Some(worker_id) = self.active.as_ref() {
            if !self.torn_down {
                let _ = self.transport.stop(worker_id);
            }
        }
    }
}

#[derive(Clone, Copy, Debug)]
enum StopReason {
    TimedOut,
    Interrupted,
    OutputLimit,
}

pub(crate) fn set_nonblocking(fd: &impl std::os::fd::AsFd) -> Result<(), WorkerError> {
    let flags = fcntl_getfl(fd).map_err(|error| {
        WorkerError::new(
            WorkerErrorCode::Io,
            format!("cannot read pipe flags: {error}"),
        )
    })?;
    fcntl_setfl(fd, flags | OFlags::NONBLOCK).map_err(|error| {
        WorkerError::new(
            WorkerErrorCode::Io,
            format!("cannot set nonblocking pipe: {error}"),
        )
    })
}

fn sleep_until_next_check(deadline: Instant, poll_interval: Duration) {
    let remaining = deadline.saturating_duration_since(Instant::now());
    if !remaining.is_zero() {
        thread::sleep(poll_interval.min(remaining));
    }
}

fn io_error(error: std::io::Error) -> WorkerError {
    WorkerError::new(WorkerErrorCode::Io, error.to_string())
}

fn admitted_spec_with_correlation(
    spec: &CommandSpec,
    correlation: &CorrelationId,
) -> Result<CommandSpec, WorkerError> {
    let mut builder = EnvironmentBuilder::new(
        spec.environment
            .iter()
            .map(|(key, _)| key.to_os_string())
            .chain([std::ffi::OsStr::new(crate::CORRELATION_ENV).to_os_string()]),
    )
    .map_err(|error| WorkerError::new(WorkerErrorCode::Spawn, error.to_string()))?;
    for (key, value) in spec.environment.iter() {
        builder = builder
            .set(key, value)
            .map_err(|error| WorkerError::new(WorkerErrorCode::Spawn, error.to_string()))?;
    }
    let environment = builder
        .set(crate::CORRELATION_ENV, correlation.as_str())
        .map_err(|error| WorkerError::new(WorkerErrorCode::Spawn, error.to_string()))?
        .build();
    Ok(CommandSpec {
        argv: spec.argv.clone(),
        environment,
        current_dir: spec.current_dir.clone(),
    })
}

#[cfg(test)]
pub(crate) fn channel_transport(channel: WorkerChannel) -> Arc<dyn ProcessTransport> {
    Arc::new(ChannelTransport {
        channel,
        workers: Mutex::new(BTreeMap::new()),
    })
}

/// Test adapter using WorkerAuthority over an explicit channel;
/// production uses the parent-aware authority adapter.
#[cfg(test)]
struct ChannelTransport {
    channel: WorkerChannel,
    workers: Mutex<BTreeMap<String, WorkerAuthority>>,
}

#[cfg(test)]
impl ProcessLaunch for ChannelTransport {
    fn launch(&self, request: ProcessLaunchRequest) -> Result<ProcessLaunchResult, WorkerError> {
        let mut authority = WorkerAuthority::spawn(
            &self.channel,
            request.naming,
            &request.spec,
            request.scope_limits,
        )?;
        let identity = authority.identity().clone();
        if identity.worker_id != request.worker_id {
            let _ = authority.stop();
            return Err(WorkerError::new(
                WorkerErrorCode::IdentityProof,
                "channel transport launched a foreign worker identity",
            ));
        }
        let stdout = authority.take_stdout()?;
        let stderr = authority.take_stderr()?;
        self.workers
            .lock()
            .expect("channel transport worker registry")
            .insert(request.worker_id.as_str().to_owned(), authority);
        Ok(ProcessLaunchResult {
            identity,
            stdout,
            stderr,
        })
    }
}

#[cfg(test)]
impl ProcessControl for ChannelTransport {
    fn try_wait(&self, worker_id: &WorkerId) -> Result<Option<ExitStatus>, WorkerError> {
        self.workers
            .lock()
            .expect("channel transport worker registry")
            .get_mut(worker_id.as_str())
            .ok_or_else(|| unknown_worker(worker_id))?
            .try_wait()
    }

    fn stop(&self, worker_id: &WorkerId) -> Result<ProcessStopEvidence, WorkerError> {
        let report = self
            .workers
            .lock()
            .expect("channel transport worker registry")
            .get_mut(worker_id.as_str())
            .ok_or_else(|| unknown_worker(worker_id))?
            .stop()?;
        let residue = report.residual.map(|residue| StopResidue {
            unit_active: residue.unit_active,
            cgroup_present: residue.cgroup_present,
            processes: residue
                .processes
                .iter()
                .map(|process| odin_domain::StopResidueProcess {
                    pid: process.pid,
                    start_time_ticks: process.start_time_ticks,
                })
                .collect(),
        });
        Ok(ProcessStopEvidence {
            worker_id: worker_id.clone(),
            verdict: StopVerdict::classify(report.stopped, residue, None),
            replay: false,
            term_sent: report.term_sent,
            cgroup_kill: report.cgroup_kill,
        })
    }
}

#[cfg(test)]
fn unknown_worker(worker_id: &WorkerId) -> WorkerError {
    WorkerError::new(
        WorkerErrorCode::Stop,
        format!("unknown channel transport worker {}", worker_id.as_str()),
    )
}
