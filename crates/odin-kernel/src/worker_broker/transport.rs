//! Authenticate peers against activated worker cgroups before exposing broker operations.

use super::dispatch::dispatch;
use super::*;

#[allow(clippy::too_many_arguments)]
pub(super) fn accept_loop(
    listener: UnixListener,
    scopes: SharedScopes,
    unit_claims: SharedUnitClaims,
    worker_reservations: SharedWorkerReservations,
    allowed: Arc<AllowedParentBindings>,
    channel: WorkerChannel,
    storage_root: PathBuf,
    socket_path: PathBuf,
    stopping: Arc<AtomicBool>,
    next_connection: Arc<AtomicU64>,
    connections: SharedConnections,
    handlers: SharedHandlers,
    runtime_error: Arc<Mutex<Option<String>>>,
) {
    while !stopping.load(Ordering::Acquire) {
        let mut fds = [PollFd::new(&listener, PollFlags::IN)];
        let timeout = Timespec::try_from(Duration::from_millis(50)).expect("50ms is representable");
        let ready = match poll(&mut fds, Some(&timeout)) {
            Ok(ready) => ready,
            Err(error) => {
                set_runtime_error(
                    &runtime_error,
                    format!("broker listener poll failed: {error}"),
                );
                break;
            }
        };
        if ready == 0 || !fds[0].revents().contains(PollFlags::IN) {
            continue;
        }
        let (stream, _) = match listener.accept() {
            Ok(stream) => stream,
            Err(error) => {
                set_runtime_error(&runtime_error, format!("broker accept failed: {error}"));
                break;
            }
        };
        if stopping.load(Ordering::Acquire) {
            let _ = stream.shutdown(Shutdown::Both);
            break;
        }
        let connection_id = next_connection.fetch_add(1, Ordering::Relaxed);
        let tracked = match stream.try_clone() {
            Ok(stream) => stream,
            Err(error) => {
                set_runtime_error(
                    &runtime_error,
                    format!("cannot track broker connection: {error}"),
                );
                let _ = stream.shutdown(Shutdown::Both);
                continue;
            }
        };
        connections.insert(connection_id, tracked);
        let handler_connections = Arc::clone(&connections);
        let handler = std::thread::Builder::new()
            .name(format!("odin-parent-broker-{connection_id}"))
            .spawn({
                let scopes = Arc::clone(&scopes);
                let unit_claims = Arc::clone(&unit_claims);
                let worker_reservations = Arc::clone(&worker_reservations);
                let allowed = Arc::clone(&allowed);
                let channel = channel.clone();
                let storage_root = storage_root.clone();
                let socket_path = socket_path.clone();
                let stopping = Arc::clone(&stopping);
                move || {
                    serve_connection(
                        ConnectionContext {
                            scopes,
                            unit_claims,
                            worker_reservations,
                            allowed,
                            channel,
                            storage_root,
                            socket_path,
                            stopping,
                        },
                        stream,
                    );
                    handler_connections.remove(&connection_id);
                }
            });
        match handler {
            Ok(handler) => {
                if let Ok(mut tracked) = handlers.lock() {
                    tracked.push(handler);
                } else {
                    stopping.store(true, Ordering::Release);
                    if let Some(stream) = connections.get(&connection_id) {
                        let _ = stream.shutdown(Shutdown::Both);
                    }
                    let _ = handler.join();
                    set_runtime_error(
                        &runtime_error,
                        "broker handler registry lock is poisoned".to_owned(),
                    );
                    break;
                }
            }
            Err(error) => {
                connections.remove(&connection_id);
                set_runtime_error(
                    &runtime_error,
                    format!("cannot spawn broker handler: {error}"),
                );
            }
        }
    }
}

fn write_response(
    stream: &mut UnixStream,
    response: &BrokerResponse,
    descriptors: Option<(&OwnedFd, &OwnedFd)>,
) -> Result<(), ParentAuthorityError> {
    let body = serde_json::to_vec(response)?;
    match descriptors {
        Some((stdout, stderr)) => {
            write_frame(stream, &body, Some(&[stdout.as_fd(), stderr.as_fd()]))
        }
        None => write_frame(stream, &body, None),
    }
}

pub(super) struct ConnectionContext {
    pub(super) scopes: SharedScopes,
    pub(super) unit_claims: SharedUnitClaims,
    pub(super) worker_reservations: SharedWorkerReservations,
    pub(super) allowed: Arc<AllowedParentBindings>,
    pub(super) channel: WorkerChannel,
    pub(super) storage_root: PathBuf,
    pub(super) socket_path: PathBuf,
    pub(super) stopping: Arc<AtomicBool>,
}

fn serve_connection(context: ConnectionContext, stream: UnixStream) {
    let (scope_worker, authority) = match bind_connection_until_active(
        &context.scopes,
        &context.channel,
        &stream,
        &context.stopping,
    ) {
        Ok(binding) => binding,
        // Close without a response so unauthenticated peers learn nothing.
        Err(_) => return,
    };
    serve_bound_connection(context, stream, scope_worker, authority);
}

#[cfg(test)]
std::thread_local! {
    pub(super) static BEFORE_DISPATCH: std::cell::RefCell<Option<Box<dyn FnOnce()>>> =
        std::cell::RefCell::new(None);
}

pub(super) fn serve_bound_connection(
    context: ConnectionContext,
    mut stream: UnixStream,
    scope_worker: String,
    authority: Arc<StopAuthority>,
) {
    let ConnectionContext {
        scopes,
        unit_claims,
        worker_reservations,
        allowed,
        channel,
        storage_root,
        socket_path,
        stopping,
    } = context;
    loop {
        if stopping.load(Ordering::Acquire) {
            return;
        }
        let (payload, descriptors) = match read_frame(&mut stream) {
            Ok(frame) => frame,
            Err(_) => return,
        };
        if !descriptors.is_empty() {
            let _ = write_response(
                &mut stream,
                &BrokerResponse::Rejected {
                    code: BrokerRejectionCode::Protocol,
                    reason: "requests never carry descriptors".to_owned(),
                },
                None,
            );
            return;
        }
        let envelope: BrokerEnvelope = match serde_json::from_slice(&payload) {
            Ok(envelope) => envelope,
            Err(error) => {
                let _ = write_response(
                    &mut stream,
                    &BrokerResponse::Rejected {
                        code: BrokerRejectionCode::Protocol,
                        reason: error.to_string(),
                    },
                    None,
                );
                return;
            }
        };
        let expected_store_root = scopes.lock().ok().and_then(|table| {
            table
                .get(&scope_worker)
                .map(|entry| entry.store_root.clone())
        });
        if envelope.scope_worker != scope_worker
            || expected_store_root.as_deref() != Some(Path::new(&envelope.store_root))
        {
            let _ = write_response(
                &mut stream,
                &BrokerResponse::Rejected {
                    code: BrokerRejectionCode::Scope,
                    reason: "descriptor scope/store binding does not match the peer cgroup"
                        .to_owned(),
                },
                None,
            );
            return;
        }
        let request = envelope.request;
        #[cfg(test)]
        BEFORE_DISPATCH.with(|hook| {
            if let Some(hook) = hook.borrow_mut().take() {
                hook();
            }
        });
        match dispatch(
            &scopes,
            &unit_claims,
            &worker_reservations,
            &allowed,
            &channel,
            &storage_root,
            &socket_path,
            &scope_worker,
            &authority,
            &stopping,
            request,
        ) {
            Ok((response, descriptors)) => {
                // Attach output descriptors to their launch response, never another frame.
                let sent = match (&response, descriptors.as_ref()) {
                    (BrokerResponse::Launched { .. }, Some((stdout, stderr))) => {
                        write_response(&mut stream, &response, Some((stdout, stderr)))
                    }
                    (BrokerResponse::Launched { .. }, None) | (_, Some(_)) => {
                        Err(ParentAuthorityError::Protocol(
                            "launch descriptors missing or misplaced".to_owned(),
                        ))
                    }
                    _ => write_response(&mut stream, &response, None),
                };
                if sent.is_err() {
                    return;
                }
            }
            Err((code, error)) => {
                let protocol = code == BrokerRejectionCode::Protocol;
                let _ = write_response(
                    &mut stream,
                    &BrokerResponse::Rejected {
                        code,
                        reason: error.to_string(),
                    },
                    None,
                );
                if protocol {
                    return;
                }
            }
        }
    }
}

/// Require exactly one unified cgroup-v2 entry to identify the peer.
pub(super) fn process_cgroup_v2_path(pid: u32) -> Result<String, ParentAuthorityError> {
    let raw = std::fs::read_to_string(format!("/proc/{pid}/cgroup"))?;
    let mut matches = raw.lines().filter_map(|line| line.strip_prefix("0::"));
    let path = matches
        .next()
        .ok_or_else(|| ParentAuthorityError::Scope("peer has no cgroup-v2 entry".to_owned()))?
        .trim()
        .to_owned();
    if matches.next().is_some() {
        return Err(ParentAuthorityError::Scope(
            "peer reported multiple cgroup-v2 entries".to_owned(),
        ));
    }
    Ok(path)
}
/// Require an activated scope with matching UID, cgroup, and inode before accepting the peer.
pub(super) fn bind_connection(
    scopes: &SharedScopes,
    channel: &WorkerChannel,
    stream: &UnixStream,
) -> Result<(String, Arc<StopAuthority>), ParentAuthorityError> {
    let peer =
        socket_peercred(stream).map_err(|error| ParentAuthorityError::Scope(error.to_string()))?;
    if peer.uid != geteuid() {
        return Err(ParentAuthorityError::Forbidden(
            "peer uid is not the broker owner".to_owned(),
        ));
    }
    let peer_pid = u32::try_from(peer.pid.as_raw_pid())
        .map_err(|_| ParentAuthorityError::Scope("peer pid is invalid".to_owned()))?;
    let peer_cgroup = process_cgroup_v2_path(peer_pid)?;

    // UID or a claimed WorkerId is insufficient; select an activated scope by its verified cgroup.
    let (worker, anchors, store_root) = {
        let scopes = scopes.lock().map_err(|_| poisoned_scopes())?;
        let mut selected = None;
        for (worker, entry) in scopes.iter() {
            let Some(anchors) = &entry.anchors else {
                continue;
            };
            if anchors.cgroup_path != peer_cgroup {
                continue;
            }
            if selected.is_some() {
                return Err(ParentAuthorityError::Scope(
                    "peer cgroup ambiguously matches multiple scopes".to_owned(),
                ));
            }
            if entry.handoff {
                return Err(ParentAuthorityError::Scope(format!(
                    "scope {worker} was explicitly handed off"
                )));
            }
            if entry.settling {
                return Err(ParentAuthorityError::Scope(format!(
                    "scope {worker} is being settled"
                )));
            }
            // Stop intent prevents new connections even before worker identity is rechecked.
            {
                let ledger = entry.owner_store.lock().map_err(|_| {
                    ParentAuthorityError::Scope("scope owner ledger lock is poisoned".to_owned())
                })?;
                if odin_ledger::stop::stop_row(ledger.connection(), worker)
                    .map_err(|error| {
                        ParentAuthorityError::Scope(format!(
                            "cannot read the stop state of scope {worker}: {error}"
                        ))
                    })?
                    .is_some()
                {
                    return Err(ParentAuthorityError::Scope(format!(
                        "scope {worker} has a durable stop intent; admission refused"
                    )));
                }
            }
            selected = Some((worker.clone(), anchors.clone(), entry.store_root.clone()));
        }
        selected.ok_or_else(|| {
            ParentAuthorityError::Forbidden(
                "peer cgroup matches no activated broker scope".to_owned(),
            )
        })?
    };

    // Recheck manager and process identity on every connection; failed queries must deny admission.
    let invocation = InvocationId::from_hex(&anchors.invocation_hex).map_err(|error| {
        ParentAuthorityError::Scope(format!(
            "scope {worker} has an invalid durable InvocationID: {error}"
        ))
    })?;
    let recovery = RecoveryAnchors {
        cgroup_path: anchors.cgroup_path.clone(),
        cgroup_inode: anchors.cgroup_inode,
        leader_pid: anchors.leader_pid,
        leader_start_ticks: anchors.leader_start_ticks,
    };
    let inspection =
        WorkerAuthority::inspect_recorded(channel, &anchors.unit, &invocation, &recovery).map_err(
            |error| {
                ParentAuthorityError::Scope(format!(
                    "manager proof for broker scope {worker} failed: {error}"
                ))
            },
        )?;
    let leader_matches = inspection.leader.as_ref().is_some_and(|leader| {
        leader.pid == anchors.leader_pid && leader.start_time_ticks == anchors.leader_start_ticks
    });
    if !inspection.unit_identity_verified
        || !inspection.unit_active
        || !inspection.cgroup_present
        || inspection.leader_reaped
        || !leader_matches
    {
        return Err(ParentAuthorityError::Scope(format!(
            "broker scope {worker} is not the exact active manager-proven worker"
        )));
    }

    // Reusing an authority still requires checking stop intent under the admission lock.
    let ledger = Ledger::open(store_root.join(SCOPE_LEDGER_NAME))
        .map_err(|error| ParentAuthorityError::Io(std::io::Error::other(error.to_string())))?;
    let created = Arc::new(StopAuthority::new(
        Arc::new(Mutex::new(ledger)),
        channel.clone(),
    ));
    let authority = {
        let mut scopes = scopes.lock().map_err(|_| poisoned_scopes())?;
        let entry = scopes.get_mut(&worker).ok_or_else(|| {
            ParentAuthorityError::Scope(format!("scope {worker} vanished during admission"))
        })?;
        if entry.handoff || entry.settling || entry.anchors.as_ref() != Some(&anchors) {
            return Err(ParentAuthorityError::Scope(format!(
                "scope {worker} changed during admission"
            )));
        }
        // Recheck stop intent under lock because it may have arrived during identity verification.
        {
            let ledger = entry.owner_store.lock().map_err(|_| {
                ParentAuthorityError::Scope("scope owner ledger lock is poisoned".to_owned())
            })?;
            if odin_ledger::stop::stop_row(ledger.connection(), &worker)
                .map_err(|error| {
                    ParentAuthorityError::Scope(format!(
                        "cannot read the stop state of scope {worker}: {error}"
                    ))
                })?
                .is_some()
            {
                return Err(ParentAuthorityError::Scope(format!(
                    "scope {worker} has a durable stop intent; admission refused"
                )));
            }
        }
        match &entry.authority {
            Some(authority) => Arc::clone(authority),
            None => {
                entry.authority = Some(Arc::clone(&created));
                created
            }
        }
    };
    Ok((worker, authority))
}

pub(super) fn bind_connection_until_active(
    scopes: &SharedScopes,
    channel: &WorkerChannel,
    stream: &UnixStream,
    stopping: &AtomicBool,
) -> Result<(String, Arc<StopAuthority>), ParentAuthorityError> {
    let deadline = Instant::now()
        .checked_add(Duration::from_secs(5))
        .unwrap_or_else(Instant::now);
    loop {
        if stopping.load(Ordering::Acquire) {
            return Err(ParentAuthorityError::Transport(
                "broker is shutting down".to_owned(),
            ));
        }
        match bind_connection(scopes, channel, stream) {
            Ok(binding) => return Ok(binding),
            Err(error) if Instant::now() >= deadline => return Err(error),
            Err(_) => {}
        }
        std::thread::sleep(Duration::from_millis(5));
    }
}
