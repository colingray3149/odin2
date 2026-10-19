//! Hosts without bus access use a parent broker that checks peer credentials and worker cgroup identity.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::io::{IoSlice, IoSliceMut, Read, Write};
use std::net::Shutdown;
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::{ChildStderr, ChildStdout, ExitStatus};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use dashmap::DashMap;
use odin_domain::{
    InvocationId, StopEvidence, StopMissing, StopState, StopTraceRow, StopVerdict, WorkerPhase,
    STOP_AUTHORITY_TRACE_SCHEMA,
};
use odin_ledger::{Ledger, LedgerError};
use odin_process::{
    CommandSpec, EnvironmentBuilder, FrozenArgv, ManagerClient, RecoveryAnchors,
    RegisteredServiceBinding, ScopeLifetime, ScopeLimits, WorkerAuthority, WorkerChannel,
    WorkerIdentity, WorkerNaming, CORRELATION_ENV, STDIN_WRITE_TIMEOUT,
};
use odin_types::{CorrelationId, WorkerId};
use rustix::cmsg_space;
use rustix::event::{poll, PollFd, PollFlags, Timespec};
use rustix::net::sockopt::socket_peercred;
use rustix::net::{
    recvmsg, sendmsg, RecvAncillaryBuffer, RecvAncillaryMessage, RecvFlags, SendAncillaryBuffer,
    SendAncillaryMessage, SendFlags,
};
use rustix::process::geteuid;
use serde::{Deserialize, Serialize};

use crate::stop::{
    StopAuthority, StopAuthorityError, StopEvidenceRecord, StopOutcome, WorkerLaunch,
};

mod client;
mod dispatch;
mod prepare;
mod protocol;
mod scope;
mod server;
mod transport;

#[cfg(test)]
mod tests;

pub use client::{
    remote_close_stdin, remote_identity, remote_launch_registered_service, remote_launch_worker,
    remote_recover_pending, remote_stop_record, remote_stop_worker, remote_stop_worker_bounded,
    remote_try_wait, remote_wait, remote_wait_timeout, remote_write_stdin,
    remote_write_stdin_timeout, ParentAuthorityClient, ParentAuthorityDescriptor,
};
pub use server::{ParentBrokerServer, ParentBrokerShutdown};

pub use protocol::{
    BrokerEnvironmentEntry, BrokerIdentity, BrokerLaunchProfile, BrokerLimits, BrokerNaming,
    BrokerRejectionCode, BrokerRequest, BrokerResponse, BrokerSpec, BrokerStopOutcome,
    BrokerStopRecord, ParentAuthorityError, MAX_BROKER_HANDOFF_QUIESCE_TIMEOUT,
    MAX_BROKER_NESTING_DEPTH, MAX_BROKER_STDIN_WRITE_TIMEOUT, MAX_BROKER_STOP_TIMEOUT,
    MAX_BROKER_SUBTREE_SETTLE_TIMEOUT, MAX_BROKER_WAIT_TIMEOUT, MAX_FRAME_BYTES,
    PARENT_AUTHORITY_ENV, SCOPE_LEDGER_NAME,
};

use dispatch::{release_remote_unit, reserve_reassign_target, ReservedReassignment};
use prepare::*;
use protocol::*;
use scope::*;
use server::set_runtime_error;
use transport::*;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ParentExecutableProfile {
    Isolated,
    /// Only registered services may retain host networking.
    RegisteredService,
}

/// Preserve invocation paths verbatim so symlink and multicall entry points remain distinct.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ParentExecutableBinding {
    executable: PathBuf,
    compiled_binding_blake3: String,
    profile: ParentExecutableProfile,
    broker_host: bool,
}

impl ParentExecutableBinding {
    pub fn isolated(
        executable: PathBuf,
        compiled_binding_blake3: String,
    ) -> Result<Self, ParentAuthorityError> {
        Self::new(
            executable,
            compiled_binding_blake3,
            ParentExecutableProfile::Isolated,
        )
    }

    pub fn registered_service(
        executable: PathBuf,
        compiled_binding_blake3: String,
    ) -> Result<Self, ParentAuthorityError> {
        Self::new(
            executable,
            compiled_binding_blake3,
            ParentExecutableProfile::RegisteredService,
        )
    }

    fn new(
        executable: PathBuf,
        compiled_binding_blake3: String,
        profile: ParentExecutableProfile,
    ) -> Result<Self, ParentAuthorityError> {
        if !executable.is_absolute() {
            return Err(ParentAuthorityError::Forbidden(format!(
                "binding executable {} must be absolute",
                executable.display()
            )));
        }
        let canonical = std::fs::canonicalize(&executable).map_err(|error| {
            ParentAuthorityError::Forbidden(format!(
                "binding executable {} is unreadable: {error}",
                executable.display()
            ))
        })?;
        if !canonical.is_file() {
            return Err(ParentAuthorityError::Forbidden(format!(
                "binding executable {} does not resolve to a regular file",
                executable.display()
            )));
        }
        if compiled_binding_blake3.len() != 64
            || !compiled_binding_blake3
                .bytes()
                .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
        {
            return Err(ParentAuthorityError::Forbidden(format!(
                "binding digest for {} must be 64 lowercase hex characters",
                executable.display()
            )));
        }
        let metadata = std::fs::metadata(&executable)?;
        if !metadata.is_file() {
            return Err(ParentAuthorityError::Forbidden(format!(
                "binding executable {} is not a regular file",
                executable.display()
            )));
        }
        Ok(Self {
            executable,
            compiled_binding_blake3,
            profile,
            broker_host: false,
        })
    }

    pub fn with_parent_authority(mut self) -> Result<Self, ParentAuthorityError> {
        self.broker_host = true;
        Ok(self)
    }

    pub fn executable(&self) -> &Path {
        &self.executable
    }

    pub fn compiled_binding_blake3(&self) -> &str {
        &self.compiled_binding_blake3
    }

    pub fn profile(&self) -> ParentExecutableProfile {
        self.profile
    }

    pub fn is_broker_host(&self) -> bool {
        self.broker_host
    }
}

/// Match catalog paths verbatim and honor requested isolation even for registered services.
#[derive(Clone, Debug, Default)]
pub struct AllowedParentBindings {
    entries: BTreeMap<PathBuf, ParentExecutableBinding>,
}

impl AllowedParentBindings {
    pub fn new(
        entries: impl IntoIterator<Item = ParentExecutableBinding>,
    ) -> Result<Self, ParentAuthorityError> {
        let mut validated = BTreeMap::new();
        for binding in entries {
            let path = binding.executable.clone();
            if validated.contains_key(&path) {
                return Err(ParentAuthorityError::Forbidden(format!(
                    "duplicate parent binding for {}",
                    path.display()
                )));
            }
            validated.insert(path, binding);
        }
        Ok(Self { entries: validated })
    }

    pub fn binding_for(&self, executable: &Path) -> Option<&ParentExecutableBinding> {
        self.entries.get(executable)
    }
}
