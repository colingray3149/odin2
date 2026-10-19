//! Stop workers by cgroup because session changes and double forks can escape process groups.

use std::os::fd::OwnedFd;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::Child;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use rustix::process::{pidfd_open, Pid, PidfdFlags};

use crate::identity::read_process_identity;
use crate::systemd::BusError;
use crate::{ProcessError, ProcessErrorCode, ProcessIdentity};

mod bootstrap;
mod identity;
mod io;
mod launch;
mod stop;

#[cfg(any(test, feature = "test-support"))]
pub(crate) use bootstrap::BOOTSTRAP_ACTIVE_VAR;
pub use bootstrap::{
    bootstrap_run, strip_bus_authority, BOOTSTRAP_VAR, BUS_ADDRESS_VAR, BUS_AUTHORITY_ENV_VARS,
    UNSHARE_VAR,
};
pub use io::{WorkerStdinWriter, STDIN_WRITE_TIMEOUT};
pub use launch::{
    mint_worker_id, RegisteredServiceBinding, ScopeLifetime, ScopeLimits, WorkerChannel,
    WorkerIdentity, WorkerNaming,
};
pub use stop::{
    RecoveryAnchors, UnitIdentityProof, WorkerInspection, WorkerResidue, WorkerStopReport,
};

pub use identity::{process_cgroup_line, scan_cgroup_residue};
use stop::REAP_POLL;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WorkerErrorCode {
    ChannelInvalid,
    Spawn,
    ScopeRejected,
    BusQuery,
    IdentityProof,
    PayloadGate,
    Stop,
    ResidualUnit,
    Reap,
    Io,
    /// The message includes the partial byte count delivered before the timeout.
    WriteTimeout,
}

#[derive(Debug)]
pub struct WorkerError {
    code: WorkerErrorCode,
    message: String,
}

impl WorkerError {
    pub(crate) fn new(code: WorkerErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }

    pub fn from_authority(code: WorkerErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }

    pub fn code(&self) -> WorkerErrorCode {
        self.code
    }
}

impl std::fmt::Display for WorkerError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{:?}: {}", self.code, self.message)
    }
}

impl std::error::Error for WorkerError {}

impl From<ProcessError> for WorkerError {
    fn from(error: ProcessError) -> Self {
        let code = match error.code() {
            ProcessErrorCode::Spawn => WorkerErrorCode::Spawn,
            ProcessErrorCode::Identity => WorkerErrorCode::IdentityProof,
            _ => WorkerErrorCode::Io,
        };
        Self::new(code, error.to_string())
    }
}

impl From<BusError> for WorkerError {
    fn from(error: BusError) -> Self {
        let code = if error.is_transport() {
            WorkerErrorCode::BusQuery
        } else {
            WorkerErrorCode::ScopeRejected
        };
        Self::new(code, error.to_string())
    }
}

/// Recovered workers have no child handle; systemd reaps them after identity checks.
#[derive(Debug)]
pub struct WorkerAuthority {
    channel: WorkerChannel,
    identity: WorkerIdentity,
    correlation: Option<String>,
    leader: Option<Child>,
    leader_pidfd: Option<OwnedFd>,
    payload_gate: Option<UnixStream>,
    stdin_serial: Arc<Mutex<()>>,
    payload_released: bool,
    recovered: bool,
    exited: bool,
    stopped: bool,
    abandoned: bool,
    abandonment: Option<Arc<std::sync::atomic::AtomicBool>>,
}

impl WorkerAuthority {
    /// Leave the scope for process-exit recovery after reporting incomplete shutdown.
    pub fn abandon(&mut self) {
        self.abandoned = true;
    }

    /// Install the shutdown signal before publication so error-path workers also observe it.
    pub fn bind_abandonment(&mut self, signal: Arc<std::sync::atomic::AtomicBool>) {
        self.abandonment = Some(signal);
    }

    pub fn identity(&self) -> &WorkerIdentity {
        &self.identity
    }

    pub fn correlation(&self) -> Option<&str> {
        self.correlation.as_deref()
    }

    pub fn channel(&self) -> &WorkerChannel {
        &self.channel
    }

    pub fn is_recovered(&self) -> bool {
        self.recovered
    }

    fn held_leader_mut(&mut self) -> Result<&mut Child, WorkerError> {
        self.leader.as_mut().ok_or_else(|| {
            WorkerError::new(
                WorkerErrorCode::Reap,
                "a recovered worker has no inherited child handle",
            )
        })
    }
}

#[cfg(test)]
mod tests;
