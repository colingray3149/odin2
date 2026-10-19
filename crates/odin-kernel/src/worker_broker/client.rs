//! Hosts without bus access forward logical worker operations to their parent broker.

use super::*;

/// Restrict the host to its parent-issued worker ID, socket, and ledger root.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ParentAuthorityDescriptor {
    worker: WorkerId,
    socket: PathBuf,
    store_root: PathBuf,
}

impl ParentAuthorityDescriptor {
    pub fn new(
        worker: WorkerId,
        socket: PathBuf,
        store_root: PathBuf,
    ) -> Result<Self, ParentAuthorityError> {
        for (role, path) in [("socket", &socket), ("store_root", &store_root)] {
            if path.as_os_str().is_empty() {
                return Err(ParentAuthorityError::Descriptor(format!(
                    "{role} path must not be empty"
                )));
            }
            if !path.is_absolute() {
                return Err(ParentAuthorityError::Descriptor(format!(
                    "{role} path {} must be absolute",
                    path.display()
                )));
            }
            let encoded = path.to_str().ok_or_else(|| {
                ParentAuthorityError::Descriptor(format!("{role} path must be valid UTF-8"))
            })?;
            if encoded.contains(';') {
                return Err(ParentAuthorityError::Descriptor(format!(
                    "{role} path must not contain `;`"
                )));
            }
        }
        Ok(Self {
            worker,
            socket,
            store_root,
        })
    }

    /// Require `worker=<WorkerId>;socket=<abs>;store_root=<abs>` in that order.
    pub fn parse(raw: &str) -> Result<Self, ParentAuthorityError> {
        let segments: Vec<&str> = raw.split(';').collect();
        if segments.len() != 3 {
            return Err(ParentAuthorityError::Descriptor(format!(
                "expected 3 `key=value` segments, found {}",
                segments.len()
            )));
        }
        fn field<'a>(segment: &'a str, expected: &str) -> Result<&'a str, ParentAuthorityError> {
            let Some(rest) = segment.strip_prefix(expected) else {
                return Err(ParentAuthorityError::Descriptor(format!(
                    "segment {segment:?} must start with {expected:?}"
                )));
            };
            let Some(value) = rest.strip_prefix('=') else {
                return Err(ParentAuthorityError::Descriptor(format!(
                    "segment {segment:?} must be {expected:?}=<value>"
                )));
            };
            if value.is_empty() {
                return Err(ParentAuthorityError::Descriptor(format!(
                    "{expected:?} value must not be empty"
                )));
            }
            Ok(value)
        }
        let worker = WorkerId::new(field(segments[0], "worker")?)
            .map_err(|error| ParentAuthorityError::Descriptor(format!("worker id: {error}")))?;
        let socket = PathBuf::from(field(segments[1], "socket")?);
        let store_root = PathBuf::from(field(segments[2], "store_root")?);
        Self::new(worker, socket, store_root)
    }

    /// Absence selects root-local execution; malformed values must not fall back to it.
    pub fn from_env() -> Result<Option<Self>, ParentAuthorityError> {
        match std::env::var(PARENT_AUTHORITY_ENV) {
            Ok(raw) => Self::parse(&raw).map(Some),
            Err(std::env::VarError::NotPresent) => Ok(None),
            Err(error) => Err(ParentAuthorityError::Descriptor(format!(
                "environment value is unreadable: {error}"
            ))),
        }
    }

    pub fn worker_id(&self) -> &WorkerId {
        &self.worker
    }

    pub fn socket_path(&self) -> &Path {
        &self.socket
    }

    pub fn store_root(&self) -> &Path {
        &self.store_root
    }

    pub fn store_path(&self) -> PathBuf {
        self.store_root.join(SCOPE_LEDGER_NAME)
    }

    pub fn to_environment_value(&self) -> String {
        format!(
            "worker={};socket={};store_root={}",
            self.worker.as_str(),
            self.socket.display(),
            self.store_root.display()
        )
    }
}

/// Remote clients never touch the bus; RootLocal uses the local StopAuthority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ParentAuthorityClient {
    RootLocal,
    Remote(ParentAuthorityDescriptor),
}

impl ParentAuthorityClient {
    /// Only an absent descriptor permits root-local execution.
    pub fn from_env() -> Result<Self, ParentAuthorityError> {
        let Some(descriptor) = ParentAuthorityDescriptor::from_env()? else {
            return Ok(Self::RootLocal);
        };
        let canonical_store = validate_private_root("descriptor storage", descriptor.store_root())?;
        if canonical_store != descriptor.store_root() {
            return Err(ParentAuthorityError::Descriptor(
                "descriptor storage root is not canonical".to_owned(),
            ));
        }
        let stream = connect_verified(&descriptor)?;
        let _ = stream.shutdown(Shutdown::Both);
        Ok(Self::Remote(descriptor))
    }

    pub fn root_local() -> Self {
        Self::RootLocal
    }

    pub fn remote(descriptor: ParentAuthorityDescriptor) -> Self {
        Self::Remote(descriptor)
    }

    pub fn is_remote(&self) -> bool {
        matches!(self, Self::Remote(_))
    }

    pub fn descriptor(&self) -> Option<&ParentAuthorityDescriptor> {
        match self {
            Self::RootLocal => None,
            Self::Remote(descriptor) => Some(descriptor),
        }
    }

    /// Remote hosts must use this ledger path; root-local hosts choose their own.
    pub fn expected_store_path(&self) -> Result<PathBuf, ParentAuthorityError> {
        match self {
            Self::RootLocal => Err(ParentAuthorityError::Descriptor(
                "root-local authority has no broker store root".to_owned(),
            )),
            Self::Remote(descriptor) => Ok(descriptor.store_path()),
        }
    }

    /// Preserve the scope through parent shutdown for root-run adoption.
    pub fn request_scope_handoff(&self) -> Result<(), ParentAuthorityError> {
        match self.exchange(BrokerRequest::HandoffScope {})? {
            (BrokerResponse::HandedOff {}, _) => Ok(()),
            (other, _) => Err(unexpected(other)),
        }
    }

    /// Only stop dispatch may convert transport loss into an Indeterminate verdict.
    pub fn call(&self, request: BrokerRequest) -> Result<BrokerResponse, ParentAuthorityError> {
        let (response, descriptors) = self.exchange(request)?;
        if !descriptors.is_empty() {
            return Err(ParentAuthorityError::Protocol(
                "response carried unexpected descriptors".to_owned(),
            ));
        }
        Ok(response)
    }

    /// Launch dispatch also consumes the stdout and stderr descriptors attached to its response.
    fn exchange(
        &self,
        request: BrokerRequest,
    ) -> Result<(BrokerResponse, Vec<OwnedFd>), ParentAuthorityError> {
        let descriptor = match self {
            Self::RootLocal => {
                return Err(ParentAuthorityError::Scope(
                    "root-local authority does not use the broker channel".to_owned(),
                ));
            }
            Self::Remote(descriptor) => descriptor,
        };
        let read_timeout = match &request {
            BrokerRequest::Wait { timeout_millis, .. } => {
                Some(Duration::from_millis(*timeout_millis).saturating_add(Duration::from_secs(5)))
            }
            BrokerRequest::Stop { .. } => Some(BROKER_STOP_READ_TIMEOUT),
            BrokerRequest::StopBounded { timeout_millis, .. } => {
                // Do not add headroom: this stop shares the caller's shutdown deadline.
                Some(Duration::from_millis(*timeout_millis))
            }
            BrokerRequest::WriteStdin { timeout_millis, .. } => {
                Some(Duration::from_millis(*timeout_millis).saturating_add(Duration::from_secs(5)))
            }
            _ => Some(FAST_OP_READ_TIMEOUT),
        };
        let envelope = BrokerEnvelope {
            scope_worker: descriptor.worker_id().as_str().to_owned(),
            store_root: descriptor
                .store_root()
                .to_str()
                .ok_or_else(|| {
                    ParentAuthorityError::Protocol(
                        "descriptor store root is not valid UTF-8".to_owned(),
                    )
                })?
                .to_owned(),
            request,
        };
        let payload = serde_json::to_vec(&envelope)?;
        if payload.len() > MAX_FRAME_BYTES {
            return Err(ParentAuthorityError::Protocol(format!(
                "request frame is {} bytes; ceiling is {MAX_FRAME_BYTES}",
                payload.len()
            )));
        }
        let mut stream = connect_verified(descriptor)?;
        stream.set_read_timeout(read_timeout)?;
        if matches!(envelope.request, BrokerRequest::StopBounded { .. }) {
            stream.set_write_timeout(read_timeout)?;
        }
        write_frame(&mut stream, &payload, None)?;
        let (response_payload, descriptors) = read_frame(&mut stream)?;
        let response: BrokerResponse = serde_json::from_slice(&response_payload)?;
        Ok((response, descriptors))
    }
}

fn unexpected(response: BrokerResponse) -> ParentAuthorityError {
    ParentAuthorityError::Protocol(format!("unexpected broker response {response:?}"))
}

fn rejection_to_error(code: BrokerRejectionCode, reason: &str) -> StopAuthorityError {
    let owned = reason.to_owned();
    match code {
        BrokerRejectionCode::UnknownWorker => StopAuthorityError::UnknownWorker(owned),
        BrokerRejectionCode::State | BrokerRejectionCode::Worker => {
            StopAuthorityError::InvalidWorker(owned)
        }
        BrokerRejectionCode::Scope | BrokerRejectionCode::Forbidden => {
            StopAuthorityError::InvalidWorker(format!("parent authority rejected: {owned}"))
        }
        BrokerRejectionCode::Protocol => StopAuthorityError::InvalidChannel(owned),
        BrokerRejectionCode::Ledger => StopAuthorityError::Ledger(LedgerError::invalid_data(owned)),
    }
}

/// Map typed rejection codes rather than parsing reason strings.
fn require(response: BrokerResponse) -> Result<BrokerResponse, StopAuthorityError> {
    match response {
        BrokerResponse::Rejected { code, reason } => Err(rejection_to_error(code, &reason)),
        other => Ok(other),
    }
}

fn call_error(error: ParentAuthorityError) -> StopAuthorityError {
    match error {
        ParentAuthorityError::Json(error) => error.into(),
        other => StopAuthorityError::InvalidChannel(other.to_string()),
    }
}

fn connect_verified(
    descriptor: &ParentAuthorityDescriptor,
) -> Result<UnixStream, ParentAuthorityError> {
    let metadata = std::fs::symlink_metadata(descriptor.socket_path())?;
    if !metadata.file_type().is_socket()
        || metadata.permissions().mode() & 0o077 != 0
        || metadata.uid() != geteuid().as_raw()
    {
        return Err(ParentAuthorityError::Protocol(format!(
            "capability endpoint {} is not a private socket",
            descriptor.socket_path().display()
        )));
    }
    let stream = UnixStream::connect(descriptor.socket_path())?;
    let peer = socket_peercred(&stream)
        .map_err(|error| ParentAuthorityError::Protocol(error.to_string()))?;
    if peer.uid != geteuid() {
        return Err(ParentAuthorityError::Protocol(
            "capability endpoint peer is not the owning uid".to_owned(),
        ));
    }
    Ok(stream)
}

fn local_worker_row(
    store: &Arc<Mutex<Ledger>>,
    worker_id: &WorkerId,
) -> Result<odin_ledger::worker::WorkerRow, StopAuthorityError> {
    let ledger = store.lock().map_err(|_| StopAuthorityError::LedgerLock)?;
    odin_ledger::worker::worker_row(ledger.connection(), worker_id.as_str())?
        .ok_or_else(|| StopAuthorityError::UnknownWorker(worker_id.as_str().to_owned()))
}

/// Transport loss cannot establish a stop; report Indeterminate from the durable row for later recovery.
fn transport_loss_outcome(
    worker_id: &WorkerId,
    row: &odin_ledger::worker::WorkerRow,
    reason: String,
) -> StopOutcome {
    StopOutcome {
        worker_id: worker_id.clone(),
        verdict: StopVerdict::Indeterminate(StopMissing {
            reason: format!(
                "parent authority transport lost while stopping; stop intent stays recoverable: \
                 {reason}"
            ),
        }),
        replay: false,
        evidence: StopEvidence::new(
            row.worker_id.clone(),
            row.unit.clone(),
            row.cgroup_path.clone().unwrap_or_default(),
        ),
        trace: vec![StopTraceRow {
            schema: STOP_AUTHORITY_TRACE_SCHEMA.to_owned(),
            seq: 1,
            event: odin_domain::StopTraceEvent::Resolve,
            worker_id: row.worker_id.clone(),
            path: None,
        }],
    }
}

/// Request isolation even for registered hosts, without a parent descriptor.
pub fn remote_launch_worker(
    client: &ParentAuthorityClient,
    naming: WorkerNaming,
    correlation_id: &CorrelationId,
    spec: &CommandSpec,
    limits: ScopeLimits,
) -> Result<WorkerLaunch, StopAuthorityError> {
    remote_launch(
        client,
        naming,
        correlation_id,
        spec,
        limits,
        BrokerLaunchProfile::Isolated,
    )
}

/// Only the parent catalog grants registered execution; caller bindings are assertions, not permission.
pub fn remote_launch_registered_service(
    client: &ParentAuthorityClient,
    naming: WorkerNaming,
    correlation_id: &CorrelationId,
    spec: &CommandSpec,
    limits: ScopeLimits,
    _binding: &RegisteredServiceBinding,
) -> Result<WorkerLaunch, StopAuthorityError> {
    remote_launch(
        client,
        naming,
        correlation_id,
        spec,
        limits,
        BrokerLaunchProfile::RegisteredService,
    )
}

fn remote_launch(
    client: &ParentAuthorityClient,
    naming: WorkerNaming,
    correlation_id: &CorrelationId,
    spec: &CommandSpec,
    limits: ScopeLimits,
    profile: BrokerLaunchProfile,
) -> Result<WorkerLaunch, StopAuthorityError> {
    let payload_correlation = spec
        .environment
        .get(CORRELATION_ENV)
        .map(|value| value.to_string_lossy().into_owned());
    if payload_correlation.as_deref() != Some(correlation_id.as_str()) {
        return Err(StopAuthorityError::InvalidWorker(format!(
            "worker {} payload correlation does not match durable correlation {}",
            naming.worker_id.as_str(),
            correlation_id.as_str()
        )));
    }
    let (response, mut descriptors) = client
        .exchange(BrokerRequest::Launch {
            correlation_id: correlation_id.as_str().to_owned(),
            naming: naming_to_wire(&naming),
            spec: spec_to_wire(spec),
            limits: limits_to_wire(&limits)?,
            profile,
        })
        .map_err(call_error)?;
    let identity = match require(response)? {
        BrokerResponse::Launched { identity } => identity,
        other => return Err(call_error(unexpected(other))),
    };
    if descriptors.len() != 2 {
        return Err(StopAuthorityError::InvalidChannel(format!(
            "launch response carried {} descriptors; exactly two are required",
            descriptors.len()
        )));
    }
    let stderr = descriptors.pop().expect("checked length");
    let stdout = descriptors.pop().expect("checked length");
    Ok(WorkerLaunch {
        identity: identity_from_wire(&identity)
            .map_err(|error| StopAuthorityError::InvalidChannel(error.to_string()))?,
        stdout: ChildStdout::from(stdout),
        stderr: ChildStderr::from(stderr),
    })
}

pub fn remote_write_stdin(
    client: &ParentAuthorityClient,
    worker_id: &WorkerId,
    bytes: &[u8],
) -> Result<(), StopAuthorityError> {
    remote_write_stdin_timeout(client, worker_id, bytes, STDIN_WRITE_TIMEOUT).map(|_| ())
}

pub fn remote_write_stdin_timeout(
    client: &ParentAuthorityClient,
    worker_id: &WorkerId,
    bytes: &[u8],
    timeout: Duration,
) -> Result<usize, StopAuthorityError> {
    if timeout > MAX_BROKER_STDIN_WRITE_TIMEOUT {
        return Err(StopAuthorityError::InvalidChannel(format!(
            "parent authority stdin timeout exceeds {} seconds",
            MAX_BROKER_STDIN_WRITE_TIMEOUT.as_secs()
        )));
    }
    let timeout_millis = u64::try_from(timeout.as_millis()).map_err(|_| {
        StopAuthorityError::InvalidChannel(
            "parent authority stdin timeout is not representable".to_owned(),
        )
    })?;
    let response = client
        .call(BrokerRequest::WriteStdin {
            worker_id: worker_id.as_str().to_owned(),
            bytes: bytes.to_vec(),
            timeout_millis,
        })
        .map_err(call_error)?;
    match require(response)? {
        BrokerResponse::Written { count } => {
            let count = usize::try_from(count).map_err(|_| {
                StopAuthorityError::InvalidChannel(
                    "parent authority stdin count is not representable".to_owned(),
                )
            })?;
            if count != bytes.len() {
                return Err(StopAuthorityError::InvalidChannel(format!(
                    "parent authority reported a short stdin write: {count}/{}",
                    bytes.len()
                )));
            }
            Ok(count)
        }
        other => Err(call_error(unexpected(other))),
    }
}

pub fn remote_close_stdin(
    client: &ParentAuthorityClient,
    worker_id: &WorkerId,
) -> Result<(), StopAuthorityError> {
    let response = client
        .call(BrokerRequest::CloseStdin {
            worker_id: worker_id.as_str().to_owned(),
        })
        .map_err(call_error)?;
    match require(response)? {
        BrokerResponse::Closed {} => Ok(()),
        other => Err(call_error(unexpected(other))),
    }
}

pub fn remote_try_wait(
    client: &ParentAuthorityClient,
    worker_id: &WorkerId,
) -> Result<Option<ExitStatus>, StopAuthorityError> {
    let response = client
        .call(BrokerRequest::TryWait {
            worker_id: worker_id.as_str().to_owned(),
        })
        .map_err(call_error)?;
    match require(response)? {
        BrokerResponse::Tried { status } => Ok(status.map(ExitStatus::from_raw)),
        other => Err(call_error(unexpected(other))),
    }
}

pub fn remote_wait(
    client: &ParentAuthorityClient,
    worker_id: &WorkerId,
) -> Result<ExitStatus, StopAuthorityError> {
    remote_wait_timeout(client, worker_id, MAX_BROKER_WAIT_TIMEOUT)?.ok_or_else(|| {
        StopAuthorityError::InvalidWorker(format!(
            "worker {} did not exit before the parent authority wait deadline",
            worker_id.as_str()
        ))
    })
}

pub fn remote_wait_timeout(
    client: &ParentAuthorityClient,
    worker_id: &WorkerId,
    timeout: Duration,
) -> Result<Option<ExitStatus>, StopAuthorityError> {
    if timeout > MAX_BROKER_WAIT_TIMEOUT {
        return Err(StopAuthorityError::InvalidChannel(format!(
            "parent authority wait timeout exceeds {} seconds",
            MAX_BROKER_WAIT_TIMEOUT.as_secs()
        )));
    }
    let timeout_millis = u64::try_from(timeout.as_millis()).map_err(|_| {
        StopAuthorityError::InvalidChannel(
            "parent authority wait timeout is not representable".to_owned(),
        )
    })?;
    let response = client
        .call(BrokerRequest::Wait {
            worker_id: worker_id.as_str().to_owned(),
            timeout_millis,
        })
        .map_err(call_error)?;
    match require(response)? {
        BrokerResponse::Waited { status } => Ok(status.map(ExitStatus::from_raw)),
        other => Err(call_error(unexpected(other))),
    }
}

pub fn remote_identity(
    client: &ParentAuthorityClient,
    worker_id: &WorkerId,
) -> Result<Option<WorkerIdentity>, StopAuthorityError> {
    let response = client
        .call(BrokerRequest::Identity {
            worker_id: worker_id.as_str().to_owned(),
        })
        .map_err(call_error)?;
    match require(response)? {
        BrokerResponse::Identity { identity } => identity
            .map(|wire| {
                identity_from_wire(&wire)
                    .map_err(|error| StopAuthorityError::InvalidChannel(error.to_string()))
            })
            .transpose(),
        other => Err(call_error(unexpected(other))),
    }
}

/// A lost stop response is Indeterminate, never Stopped, even when its intent was persisted.
pub fn remote_stop_worker(
    client: &ParentAuthorityClient,
    store: &Arc<Mutex<Ledger>>,
    worker_id: &WorkerId,
) -> Result<StopOutcome, StopAuthorityError> {
    let row = local_worker_row(store, worker_id)?;
    match client.call(BrokerRequest::Stop {
        worker_id: worker_id.as_str().to_owned(),
    }) {
        Ok(response) => match require(response)? {
            BrokerResponse::Stopped { outcome } => outcome_from_wire(outcome),
            other => Err(call_error(unexpected(other))),
        },
        Err(error @ ParentAuthorityError::Transport(_))
        | Err(error @ ParentAuthorityError::Io(_)) => {
            Ok(transport_loss_outcome(worker_id, &row, error.to_string()))
        }
        Err(error) => Err(call_error(error)),
    }
}

/// Use the remaining shutdown budget; expiry must not issue a request or fall back to an unbounded stop.
pub fn remote_stop_worker_bounded(
    client: &ParentAuthorityClient,
    store: &Arc<Mutex<Ledger>>,
    worker_id: &WorkerId,
    deadline: Instant,
) -> Result<StopOutcome, StopAuthorityError> {
    let row = local_worker_row(store, worker_id)?;
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        return Ok(transport_loss_outcome(
            worker_id,
            &row,
            "stop deadline elapsed before the parent authority stop was issued".to_owned(),
        ));
    }
    if remaining > MAX_BROKER_STOP_TIMEOUT {
        return Err(StopAuthorityError::InvalidChannel(format!(
            "parent authority stop budget exceeds {} seconds",
            MAX_BROKER_STOP_TIMEOUT.as_secs()
        )));
    }
    let timeout_millis = u64::try_from(remaining.as_millis()).map_err(|_| {
        StopAuthorityError::InvalidChannel(
            "parent authority stop budget is not representable on the broker wire".to_owned(),
        )
    })?;
    match client.call(BrokerRequest::StopBounded {
        worker_id: worker_id.as_str().to_owned(),
        timeout_millis,
    }) {
        Ok(response) => match require(response)? {
            BrokerResponse::Stopped { outcome } => outcome_from_wire(outcome),
            other => Err(call_error(unexpected(other))),
        },
        Err(error @ ParentAuthorityError::Transport(_))
        | Err(error @ ParentAuthorityError::Io(_)) => {
            Ok(transport_loss_outcome(worker_id, &row, error.to_string()))
        }
        Err(error) => Err(call_error(error)),
    }
}

pub fn remote_recover_pending(
    client: &ParentAuthorityClient,
    correlation_id: Option<&CorrelationId>,
) -> Result<Vec<StopOutcome>, StopAuthorityError> {
    let response = client
        .call(BrokerRequest::RecoverPending {
            correlation_id: correlation_id.map(CorrelationId::as_str).map(str::to_owned),
        })
        .map_err(call_error)?;
    match require(response)? {
        BrokerResponse::Recovered { outcomes } => {
            outcomes.into_iter().map(outcome_from_wire).collect()
        }
        other => Err(call_error(unexpected(other))),
    }
}

pub fn remote_stop_record(
    client: &ParentAuthorityClient,
    worker_id: &WorkerId,
) -> Result<Option<StopEvidenceRecord>, StopAuthorityError> {
    let response = client
        .call(BrokerRequest::StopRecord {
            worker_id: worker_id.as_str().to_owned(),
        })
        .map_err(call_error)?;
    match require(response)? {
        BrokerResponse::Record { record } => record.map(record_from_wire).transpose(),
        other => Err(call_error(unexpected(other))),
    }
}
