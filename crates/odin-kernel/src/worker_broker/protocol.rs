//! Strict broker frames carry descriptors with their launch response to preserve stream identity.

use super::*;
pub const PARENT_AUTHORITY_ENV: &str = "ODIN_PARENT_AUTHORITY";

pub const SCOPE_LEDGER_NAME: &str = "ledger.sqlite3";

pub const MAX_FRAME_BYTES: usize = 1 << 20;
pub(super) const FAST_OP_READ_TIMEOUT: Duration = Duration::from_secs(60);

pub const MAX_BROKER_WAIT_TIMEOUT: Duration = Duration::from_secs(30);

pub const MAX_BROKER_NESTING_DEPTH: u8 = 8;

/// Check this subtree deadline between individual scope settlements.
pub const MAX_BROKER_SUBTREE_SETTLE_TIMEOUT: Duration = Duration::from_secs(60);

/// Wait for admitted launch effects before recording handoff so they cannot be orphaned.
pub const MAX_BROKER_HANDOFF_QUIESCE_TIMEOUT: Duration = Duration::from_secs(30);

/// StopAuthority's concrete ladder is bounded below this transport budget.
pub(super) const BROKER_STOP_READ_TIMEOUT: Duration = Duration::from_secs(30);

/// Limit stdin writes so remote callers cannot hold the authority lock indefinitely.
pub const MAX_BROKER_STDIN_WRITE_TIMEOUT: Duration = Duration::from_secs(60);

/// Clamp caller shutdown budgets so remote stops cannot monopolize the parent.
pub const MAX_BROKER_STOP_TIMEOUT: Duration = Duration::from_secs(60);

/// Match the effector argv limit so its sandbox preamble fits before user arguments.
const MAX_ARGV_ITEMS: usize = 128;
const MAX_ARGV_BYTES: usize = 16 * 1024;
const MAX_ENV_ENTRIES: usize = 128;
const MAX_ENV_VALUE_BYTES: usize = 8 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum ParentAuthorityError {
    #[error("parent authority descriptor is invalid: {0}")]
    Descriptor(String),
    #[error("parent authority transport failed: {0}")]
    Transport(String),
    #[error("parent authority protocol violation: {0}")]
    Protocol(String),
    #[error("parent authority scope violation: {0}")]
    Scope(String),
    #[error("parent authority rejected the request: {0}")]
    Forbidden(String),
    #[error("parent authority store io failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("parent authority frame codec failed: {0}")]
    Json(#[from] serde_json::Error),
}

/// Typed rejection codes avoid parsing human-readable error messages.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BrokerRejectionCode {
    UnknownWorker,
    Scope,
    Forbidden,
    Protocol,
    Ledger,
    Worker,
    State,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BrokerNaming {
    pub tx_id: String,
    pub wp_id: String,
    pub attempt: u32,
    pub worker_id: String,
}

/// Preserve environment values as bytes; reject NUL rather than converting lossily.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BrokerEnvironmentEntry {
    pub key: String,
    pub value: Vec<u8>,
}

/// The executable must be absolute; only the parent selects its isolation profile.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BrokerSpec {
    pub argv: Vec<Vec<u8>>,
    pub current_dir: String,
    pub environment: Vec<BrokerEnvironmentEntry>,
}

/// Remote jobs require a finite budget; a client cannot borrow the broker's lifetime.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BrokerLimits {
    pub runtime_max_millis: std::num::NonZeroU64,
    pub timeout_stop_millis: u64,
    pub memory_high: Option<u64>,
    pub memory_max: Option<u64>,
    pub tasks_max: Option<u64>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BrokerIdentity {
    pub worker_id: String,
    pub unit: String,
    pub invocation_id: String,
    pub cgroup_path: String,
    pub cgroup_inode: u64,
    pub leader_pid: u32,
    pub leader_start_ticks: u64,
}

/// Forward the recorded stop outcome without recomputing or upgrading it.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BrokerStopOutcome {
    pub worker_id: String,
    pub verdict: StopVerdict,
    pub evidence: StopEvidence,
    pub trace: Vec<StopTraceRow>,
    pub replay: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BrokerStopRecord {
    pub worker_id: String,
    pub correlation_id: String,
    pub state: StopState,
    pub audit: odin_domain::StopAudit,
    pub attempts: u64,
    pub requested_at: String,
    pub updated_at: String,
    pub settled_at: Option<String>,
}

/// Requests may require isolation but cannot grant themselves registered-service privileges.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BrokerLaunchProfile {
    /// Mandatory network namespace; the only mode for untrusted payloads.
    Isolated,
    /// Host networking is granted only by an exact parent catalog match; the bus stays masked.
    RegisteredService,
}

/// Requests name logical workers, never raw units, PIDs, or caller-selected stop verdicts.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub enum BrokerRequest {
    Launch {
        correlation_id: String,
        naming: BrokerNaming,
        spec: BrokerSpec,
        limits: BrokerLimits,
        /// The parent always honors isolation; registered execution requires its catalog match.
        profile: BrokerLaunchProfile,
    },
    WriteStdin {
        worker_id: String,
        bytes: Vec<u8>,
        timeout_millis: u64,
    },
    CloseStdin {
        worker_id: String,
    },
    TryWait {
        worker_id: String,
    },
    Wait {
        worker_id: String,
        timeout_millis: u64,
    },
    Identity {
        worker_id: String,
    },
    Stop {
        worker_id: String,
    },
    /// Clamp stop grace windows to the caller budget; surviving workers are not reported stopped.
    StopBounded {
        worker_id: String,
        timeout_millis: u64,
    },
    RecoverPending {
        correlation_id: Option<String>,
    },
    StopRecord {
        worker_id: String,
    },
    /// Preserve these payloads for root-run adoption instead of ordinary shutdown cleanup.
    HandoffScope {},
}

/// Launch success carries exactly two SCM_RIGHTS descriptors: stdout, then stderr.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub enum BrokerResponse {
    Launched {
        identity: BrokerIdentity,
    },
    Written {
        count: u64,
    },
    Closed {},
    Tried {
        status: Option<i32>,
    },
    Waited {
        status: Option<i32>,
    },
    Identity {
        identity: Option<BrokerIdentity>,
    },
    Stopped {
        outcome: BrokerStopOutcome,
    },
    Recovered {
        outcomes: Vec<BrokerStopOutcome>,
    },
    Record {
        record: Option<BrokerStopRecord>,
    },
    HandedOff {},
    Rejected {
        code: BrokerRejectionCode,
        reason: String,
    },
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct BrokerEnvelope {
    pub(super) scope_worker: String,
    pub(super) store_root: String,
    pub(super) request: BrokerRequest,
}

/// Attach descriptors to the same sendmsg as the length-prefixed frame.
pub(super) fn write_frame(
    stream: &mut UnixStream,
    payload: &[u8],
    descriptors: Option<&[BorrowedFd<'_>]>,
) -> Result<(), ParentAuthorityError> {
    let length = u32::try_from(payload.len())
        .map_err(|_| ParentAuthorityError::Protocol("frame exceeds u32 length".to_owned()))?;
    let header = length.to_be_bytes();
    match descriptors {
        None => {
            stream.write_all(&header)?;
            stream.write_all(payload)?;
            stream.flush()?;
        }
        Some(descriptors) => {
            let mut space = [std::mem::MaybeUninit::uninit(); cmsg_space!(ScmRights(2))];
            let mut control = SendAncillaryBuffer::new(&mut space);
            if !control.push(SendAncillaryMessage::ScmRights(descriptors)) {
                return Err(ParentAuthorityError::Transport(
                    "could not stage output descriptors".to_owned(),
                ));
            }
            let sent = sendmsg(
                stream.as_fd(),
                &[IoSlice::new(&header), IoSlice::new(payload)],
                &mut control,
                SendFlags::empty(),
            )
            .map_err(|error| ParentAuthorityError::Transport(error.to_string()))?;
            if sent != header.len() + payload.len() {
                return Err(ParentAuthorityError::Transport(
                    "frame write was short".to_owned(),
                ));
            }
        }
    }
    Ok(())
}

pub(super) fn identity_to_wire(identity: &WorkerIdentity) -> BrokerIdentity {
    BrokerIdentity {
        worker_id: identity.worker_id.as_str().to_owned(),
        unit: identity.unit.clone(),
        invocation_id: identity.invocation_id.to_hex(),
        cgroup_path: identity.cgroup_path.clone(),
        cgroup_inode: identity.cgroup_inode,
        leader_pid: identity.leader_pid,
        leader_start_ticks: identity.leader_start_ticks,
    }
}

/// Capture descriptors on the first receive before assembling a potentially fragmented header.
pub(super) fn read_frame(
    stream: &mut UnixStream,
) -> Result<(Vec<u8>, Vec<OwnedFd>), ParentAuthorityError> {
    let mut first = vec![0_u8; 4 + 8192];
    let mut space = [std::mem::MaybeUninit::<u8>::uninit(); cmsg_space![ScmRights(2)]];
    let mut control = RecvAncillaryBuffer::new(&mut space);
    let received = recvmsg(
        stream.as_fd(),
        &mut [IoSliceMut::new(&mut first)],
        &mut control,
        // Received output descriptors must never leak into children.
        RecvFlags::CMSG_CLOEXEC,
    )
    .map_err(|error| ParentAuthorityError::Transport(error.to_string()))?
    .bytes;
    if received == 0 {
        return Err(ParentAuthorityError::Transport(
            "connection closed before the frame header".to_owned(),
        ));
    }
    // Drain ancillary data before ordinary reads can overwrite the first receive state.
    let mut descriptors = Vec::new();
    for message in control.drain() {
        if let RecvAncillaryMessage::ScmRights(iterated) = message {
            descriptors.extend(iterated);
        }
    }
    let mut received = received;
    if received < 4 {
        stream
            .read_exact(&mut first[received..4])
            .map_err(|error| ParentAuthorityError::Transport(error.to_string()))?;
        received = 4;
    }
    let length = usize::try_from(u32::from_be_bytes([first[0], first[1], first[2], first[3]]))
        .map_err(|_| {
            ParentAuthorityError::Protocol("frame length is not representable".to_owned())
        })?;
    if length > MAX_FRAME_BYTES {
        return Err(ParentAuthorityError::Protocol(format!(
            "frame is {length} bytes; ceiling is {MAX_FRAME_BYTES}"
        )));
    }
    let carried = received - 4;
    if carried > length {
        return Err(ParentAuthorityError::Protocol(
            "frame carried more payload than its header declared".to_owned(),
        ));
    }
    let mut payload = Vec::with_capacity(length);
    payload.extend_from_slice(&first[4..received]);
    if payload.len() < length {
        let mut rest = vec![0_u8; length - payload.len()];
        stream
            .read_exact(&mut rest)
            .map_err(|error| ParentAuthorityError::Transport(error.to_string()))?;
        payload.extend_from_slice(&rest);
    }
    Ok((payload, descriptors))
}

pub(super) fn identity_from_wire(
    wire: &BrokerIdentity,
) -> Result<WorkerIdentity, ParentAuthorityError> {
    Ok(WorkerIdentity {
        worker_id: WorkerId::new(&wire.worker_id)
            .map_err(|error| ParentAuthorityError::Protocol(format!("worker id: {error}")))?,
        unit: wire.unit.clone(),
        invocation_id: InvocationId::from_hex(&wire.invocation_id)
            .map_err(|error| ParentAuthorityError::Protocol(format!("invocation id: {error}")))?,
        cgroup_path: wire.cgroup_path.clone(),
        cgroup_inode: wire.cgroup_inode,
        leader_pid: wire.leader_pid,
        leader_start_ticks: wire.leader_start_ticks,
    })
}

pub(super) fn naming_to_wire(naming: &WorkerNaming) -> BrokerNaming {
    BrokerNaming {
        tx_id: naming.tx_id.clone(),
        wp_id: naming.wp_id.clone(),
        attempt: naming.attempt,
        worker_id: naming.worker_id.as_str().to_owned(),
    }
}

pub(super) fn naming_from_wire(wire: &BrokerNaming) -> Result<WorkerNaming, ParentAuthorityError> {
    let worker = WorkerId::new(&wire.worker_id)
        .map_err(|error| ParentAuthorityError::Protocol(format!("worker id: {error}")))?;
    WorkerNaming::new(wire.tx_id.clone(), wire.wp_id.clone(), wire.attempt, worker)
        .map_err(|error| ParentAuthorityError::Protocol(error.to_string()))
}

pub(super) fn spec_to_wire(spec: &CommandSpec) -> BrokerSpec {
    BrokerSpec {
        argv: spec
            .argv
            .items()
            .iter()
            .map(|argument| argument.as_bytes().to_vec())
            .collect(),
        current_dir: spec.current_dir.display().to_string(),
        environment: spec
            .environment
            .iter()
            .map(|(key, value)| BrokerEnvironmentEntry {
                key: key.to_string_lossy().into_owned(),
                value: value.as_bytes().to_vec(),
            })
            .collect(),
    }
}

pub(super) fn spec_from_wire(wire: &BrokerSpec) -> Result<CommandSpec, ParentAuthorityError> {
    if wire.argv.len() > MAX_ARGV_ITEMS {
        return Err(ParentAuthorityError::Protocol(format!(
            "argv has {} items; ceiling is {MAX_ARGV_ITEMS}",
            wire.argv.len()
        )));
    }
    if wire.environment.len() > MAX_ENV_ENTRIES {
        return Err(ParentAuthorityError::Protocol(format!(
            "environment has {} entries; ceiling is {MAX_ENV_ENTRIES}",
            wire.environment.len()
        )));
    }
    let argv: Vec<OsString> = wire
        .argv
        .iter()
        .map(|item| {
            if item.len() > MAX_ARGV_BYTES {
                return Err(ParentAuthorityError::Protocol(
                    "argv item exceeds byte ceiling".to_owned(),
                ));
            }
            Ok(OsStringExt::from_vec(item.clone()))
        })
        .collect::<Result<_, _>>()?;
    let frozen = FrozenArgv::new(argv, MAX_ARGV_ITEMS, MAX_ARGV_BYTES)
        .map_err(|error| ParentAuthorityError::Protocol(error.to_string()))?;
    let keys: Vec<String> = wire
        .environment
        .iter()
        .map(|entry| entry.key.clone())
        .collect();
    let mut builder = EnvironmentBuilder::new(keys)
        .map_err(|error| ParentAuthorityError::Protocol(error.to_string()))?;
    for entry in &wire.environment {
        if entry.value.len() > MAX_ENV_VALUE_BYTES {
            return Err(ParentAuthorityError::Protocol(
                "environment value exceeds byte ceiling".to_owned(),
            ));
        }
        builder = builder
            .set(entry.key.clone(), OsString::from_vec(entry.value.clone()))
            .map_err(|error| ParentAuthorityError::Protocol(error.to_string()))?;
    }
    let current_dir = PathBuf::from(&wire.current_dir);
    if !current_dir.is_absolute() {
        return Err(ParentAuthorityError::Protocol(
            "current_dir must be absolute".to_owned(),
        ));
    }
    Ok(CommandSpec {
        argv: frozen,
        environment: builder.build(),
        current_dir,
    })
}

pub(super) fn apply_parent_descriptor(
    spec: CommandSpec,
    descriptor: Option<&ParentAuthorityDescriptor>,
) -> Result<CommandSpec, ParentAuthorityError> {
    let mut entries = Vec::<(OsString, OsString)>::new();
    for (key, value) in spec.environment.iter() {
        if key.as_bytes() == PARENT_AUTHORITY_ENV.as_bytes() {
            continue;
        }
        entries.push((key.to_os_string(), value.to_os_string()));
    }
    let mut allowed: Vec<OsString> = entries.iter().map(|(key, _)| key.clone()).collect();
    if descriptor.is_some() {
        allowed.push(OsString::from(PARENT_AUTHORITY_ENV));
    }
    let mut environment = EnvironmentBuilder::new(allowed)
        .map_err(|error| ParentAuthorityError::Protocol(error.to_string()))?;
    for (key, value) in entries {
        environment = environment
            .set(key, value)
            .map_err(|error| ParentAuthorityError::Protocol(error.to_string()))?;
    }
    if let Some(descriptor) = descriptor {
        environment = environment
            .set(PARENT_AUTHORITY_ENV, descriptor.to_environment_value())
            .map_err(|error| ParentAuthorityError::Protocol(error.to_string()))?;
    }
    Ok(CommandSpec {
        argv: spec.argv,
        environment: environment.build(),
        current_dir: spec.current_dir,
    })
}

pub(super) fn limits_to_wire(limits: &ScopeLimits) -> Result<BrokerLimits, StopAuthorityError> {
    let runtime_max_millis = match limits.lifetime {
        ScopeLifetime::Bounded(runtime_max) => {
            let millis = u64::try_from(runtime_max.as_millis()).map_err(|_| {
                StopAuthorityError::InvalidWorker(
                    "bounded runtime_max is not representable on the broker wire".to_owned(),
                )
            })?;
            std::num::NonZeroU64::new(millis).ok_or_else(|| {
                StopAuthorityError::InvalidWorker(
                    "a bounded scope runtime ceiling must be at least one millisecond".to_owned(),
                )
            })?
        }
        ScopeLifetime::OwnerUnit => {
            return Err(StopAuthorityError::InvalidWorker(
                "owner-bound lifetime requires local controller ownership".to_owned(),
            ))
        }
    };
    let timeout_stop_millis = u64::try_from(limits.timeout_stop.as_millis()).map_err(|_| {
        StopAuthorityError::InvalidWorker(
            "timeout_stop is not representable on the broker wire".to_owned(),
        )
    })?;
    Ok(BrokerLimits {
        runtime_max_millis,
        timeout_stop_millis,
        memory_high: limits.memory_high,
        memory_max: limits.memory_max,
        tasks_max: limits.tasks_max,
    })
}

pub(super) fn limits_from_wire(wire: &BrokerLimits) -> Result<ScopeLimits, StopAuthorityError> {
    if wire.runtime_max_millis.get().checked_mul(1_000).is_none() {
        return Err(StopAuthorityError::InvalidWorker(
            "bounded runtime exceeds systemd's microsecond ceiling".to_owned(),
        ));
    }
    Ok(ScopeLimits {
        lifetime: ScopeLifetime::Bounded(Duration::from_millis(wire.runtime_max_millis.get())),
        timeout_stop: Duration::from_millis(wire.timeout_stop_millis),
        memory_high: wire.memory_high,
        memory_max: wire.memory_max,
        tasks_max: wire.tasks_max,
    })
}

pub(super) fn outcome_to_wire(outcome: &StopOutcome) -> BrokerStopOutcome {
    BrokerStopOutcome {
        worker_id: outcome.worker_id.as_str().to_owned(),
        verdict: outcome.verdict.clone(),
        evidence: outcome.evidence.clone(),
        trace: outcome.trace.clone(),
        replay: outcome.replay,
    }
}

pub(super) fn outcome_from_wire(
    wire: BrokerStopOutcome,
) -> Result<StopOutcome, StopAuthorityError> {
    let worker_id = WorkerId::new(&wire.worker_id).map_err(|error| {
        StopAuthorityError::InvalidWorker(format!("worker id {:?}: {error}", wire.worker_id))
    })?;
    Ok(StopOutcome {
        worker_id,
        verdict: wire.verdict,
        replay: wire.replay,
        evidence: wire.evidence,
        trace: wire.trace,
    })
}

pub(super) fn record_to_wire(record: &StopEvidenceRecord) -> BrokerStopRecord {
    BrokerStopRecord {
        worker_id: record.worker_id.as_str().to_owned(),
        correlation_id: record.correlation_id.as_str().to_owned(),
        state: record.state,
        audit: record.evidence.clone(),
        attempts: record.attempts,
        requested_at: record.requested_at.clone(),
        updated_at: record.updated_at.clone(),
        settled_at: record.settled_at.clone(),
    }
}

pub(super) fn record_from_wire(
    wire: BrokerStopRecord,
) -> Result<StopEvidenceRecord, StopAuthorityError> {
    let worker_id = WorkerId::new(&wire.worker_id).map_err(|error| {
        StopAuthorityError::InvalidWorker(format!("worker id {:?}: {error}", wire.worker_id))
    })?;
    let correlation_id = CorrelationId::new(&wire.correlation_id).map_err(|error| {
        StopAuthorityError::InvalidWorker(format!(
            "worker {} correlation {:?}: {error}",
            wire.worker_id, wire.correlation_id
        ))
    })?;
    wire.audit.stop_verdict().map_err(|error| {
        StopAuthorityError::InvalidWorker(format!(
            "stop audit for {} is invalid: {error}",
            wire.worker_id
        ))
    })?;
    Ok(StopEvidenceRecord {
        worker_id,
        correlation_id,
        state: wire.state,
        evidence: wire.audit,
        attempts: wire.attempts,
        requested_at: wire.requested_at,
        updated_at: wire.updated_at,
        settled_at: wire.settled_at,
    })
}
