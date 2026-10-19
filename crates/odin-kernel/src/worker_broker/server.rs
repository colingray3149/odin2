//! Track broker handlers and scope cleanup so shutdown can distinguish completion from timeout.

use super::*;

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ParentBrokerShutdown {
    pub connections_joined: u64,
    pub scopes_stopped: u64,
    pub scopes_handed_off: u64,
}

/// Require explicit private runtime and storage roots rather than inferring them from the environment.
pub struct ParentBrokerServer {
    listener: UnixListener,
    pub(super) socket_path: PathBuf,
    socket_dir: PathBuf,
    runtime_root: PathBuf,
    storage_root: PathBuf,
    pub(super) scopes: SharedScopes,
    unit_claims: SharedUnitClaims,
    pub(super) worker_reservations: SharedWorkerReservations,
    channel: WorkerChannel,
    allowed: Arc<AllowedParentBindings>,
    owner_store: Arc<Mutex<Ledger>>,
    stopping: Arc<AtomicBool>,
    next_connection: Arc<AtomicU64>,
    connections: SharedConnections,
    handlers: SharedHandlers,
    accept_thread: Arc<Mutex<Option<JoinHandle<()>>>>,
    runtime_error: Arc<Mutex<Option<String>>>,
    pub(super) shutdown_complete: Arc<AtomicBool>,
    abandoned: AtomicBool,
    shutdown_failed: AtomicBool,
    shutdown_result: Mutex<Option<ShutdownReceiver>>,
}

impl ParentBrokerServer {
    /// Both roots must already exist, belong to this UID, and deny group and other access.
    pub fn bind(
        runtime_root: &Path,
        storage_root: &Path,
        channel: WorkerChannel,
        allowed: AllowedParentBindings,
        owner_store: Arc<Mutex<Ledger>>,
    ) -> Result<Self, ParentAuthorityError> {
        let runtime_root = validate_private_root("runtime", runtime_root)?;
        let storage_root = validate_private_root("storage", storage_root)?;
        let socket_dir = runtime_root.join("broker");
        std::fs::create_dir(&socket_dir)?;
        std::fs::set_permissions(&socket_dir, std::fs::Permissions::from_mode(0o700))?;
        let socket_path = socket_dir.join("authority.sock");
        if socket_path.as_os_str().as_bytes().len() >= 108 {
            return Err(ParentAuthorityError::Scope(format!(
                "capability socket path is too long: {} bytes",
                socket_path.as_os_str().as_bytes().len()
            )));
        }
        let listener = UnixListener::bind(&socket_path)?;
        std::fs::set_permissions(&socket_path, std::fs::Permissions::from_mode(0o600))?;
        let metadata = std::fs::symlink_metadata(&socket_path)?;
        if !metadata.file_type().is_socket()
            || metadata.permissions().mode() & 0o077 != 0
            || metadata.uid() != geteuid().as_raw()
        {
            let _ = std::fs::remove_file(&socket_path);
            return Err(ParentAuthorityError::Protocol(
                "bound capability endpoint is not an owner-private socket".to_owned(),
            ));
        }
        Ok(Self {
            listener,
            socket_path,
            socket_dir,
            runtime_root,
            storage_root,
            scopes: Arc::new(Mutex::new(BTreeMap::new())),
            unit_claims: Arc::new(Mutex::new(BTreeMap::new())),
            worker_reservations: Arc::new(Mutex::new(BTreeMap::new())),
            channel,
            allowed: Arc::new(allowed),
            owner_store,
            stopping: Arc::new(AtomicBool::new(false)),
            next_connection: Arc::new(AtomicU64::new(1)),
            connections: Arc::new(DashMap::new()),
            handlers: Arc::new(Mutex::new(Vec::new())),
            accept_thread: Arc::new(Mutex::new(None)),
            runtime_error: Arc::new(Mutex::new(None)),
            shutdown_complete: Arc::new(AtomicBool::new(false)),
            shutdown_failed: AtomicBool::new(false),
            abandoned: AtomicBool::new(false),
            shutdown_result: Mutex::new(None),
        })
    }

    /// Create a unique private store so later worker IDs cannot reuse it.
    pub fn prepare_scope(
        &self,
        worker_id: &WorkerId,
    ) -> Result<ParentAuthorityDescriptor, ParentAuthorityError> {
        if self.stopping.load(Ordering::Acquire) {
            return Err(ParentAuthorityError::Transport(
                "parent broker is shutting down; no scope may be prepared".to_owned(),
            ));
        }
        prepare_scope_entry(
            &self.scopes,
            &self.storage_root,
            &self.socket_path,
            worker_id,
            Arc::clone(&self.owner_store),
            None,
            1,
        )
    }

    /// Reject requests until the recorded running identity activates the prepared scope.
    pub fn activate_scope(
        &self,
        worker_id: &WorkerId,
        identity: &WorkerIdentity,
    ) -> Result<(), ParentAuthorityError> {
        if self.stopping.load(Ordering::Acquire) {
            return Err(ParentAuthorityError::Transport(
                "parent broker is shutting down; no scope may be activated".to_owned(),
            ));
        }
        activate_scope_entry(&self.scopes, worker_id, identity)
    }

    /// Transfer only a stopped, drained, handed-off subtree; activate the replacement before accepting requests.
    pub fn reassign_handed_off_scope(
        &self,
        from: &WorkerId,
        to: &WorkerId,
        drain: Duration,
    ) -> Result<ParentAuthorityDescriptor, ParentAuthorityError> {
        if self.stopping.load(Ordering::Acquire) {
            return Err(ParentAuthorityError::Transport(
                "parent broker is shutting down".to_owned(),
            ));
        }
        if from == to {
            return Err(ParentAuthorityError::Scope(
                "handed-off scope cannot be reassigned to itself".to_owned(),
            ));
        }
        // Reserve under locks ordered reservations, scopes, owner ledger so concurrent transfers cannot reuse IDs.
        let ReservedReassignment {
            reservation,
            store_root,
            owner_store,
            anchors,
        } = reserve_reassign_target(&self.worker_reservations, &self.scopes, from, to)?;
        // Failed stops may leave residue; require Stopped or a complete clean inspection before transfer.
        {
            let stopped = {
                let ledger = owner_store.lock().map_err(|_| poisoned_scopes())?;
                odin_ledger::stop::stop_row(ledger.connection(), from.as_str())
                    .map_err(|error| ParentAuthorityError::Scope(error.to_string()))?
                    .is_some_and(|row| row.state == StopState::Stopped)
            };
            if !stopped {
                let Some(anchors) = &anchors else {
                    return Err(ParentAuthorityError::Scope(format!(
                        "scope {} has neither a durable Stopped stop record nor a manager proof to inspect",
                        from.as_str()
                    )));
                };
                let invocation =
                    InvocationId::from_hex(&anchors.invocation_hex).map_err(|error| {
                        ParentAuthorityError::Scope(format!(
                            "scope {} has an invalid durable InvocationID: {error}",
                            from.as_str()
                        ))
                    })?;
                let inspection = WorkerAuthority::inspect_recorded(
                    &self.channel,
                    &anchors.unit,
                    &invocation,
                    &RecoveryAnchors {
                        cgroup_path: anchors.cgroup_path.clone(),
                        cgroup_inode: anchors.cgroup_inode,
                        leader_pid: anchors.leader_pid,
                        leader_start_ticks: anchors.leader_start_ticks,
                    },
                )
                .map_err(|error| {
                    ParentAuthorityError::Scope(format!(
                        "cannot prove handed-off scope {} stopped: {error}",
                        from.as_str()
                    ))
                })?;
                let clean = !inspection.unit_active
                    && !inspection.cgroup_present
                    && inspection.processes.is_empty()
                    && inspection.leader_reaped;
                if !clean {
                    return Err(ParentAuthorityError::Scope(format!(
                        "handed-off scope {} still holds live residue; \
                         a clean stop is required before reassignment",
                        from.as_str()
                    )));
                }
            }
        }
        // Drain descendant requests before moving the subtree under one lock.
        let deadline = Instant::now()
            .checked_add(drain)
            .unwrap_or_else(Instant::now);
        loop {
            let moved = {
                let mut table = self.scopes.lock().map_err(|_| poisoned_scopes())?;
                let lineage = scope_subtree_locked(&table, from.as_str());
                let mut busy = false;
                for worker in &lineage {
                    let entry = table
                        .get(worker)
                        .expect("subtree member from the locked lineage");
                    if !entry.handoff {
                        return Err(ParentAuthorityError::Scope(format!(
                            "scope {} has a non-handed-off subtree member {}",
                            from.as_str(),
                            worker
                        )));
                    }
                    if entry.settling {
                        return Err(ParentAuthorityError::Scope(format!(
                            "scope {} subtree member {} is being settled",
                            from.as_str(),
                            worker
                        )));
                    }
                    busy |= entry.in_flight.load(Ordering::Acquire) != 0;
                }
                if busy {
                    None
                } else if table.contains_key(to.as_str()) {
                    return Err(ParentAuthorityError::Scope(format!(
                        "reassignment target {} already owns a scope",
                        to.as_str()
                    )));
                } else {
                    let mut entry = table.remove(from.as_str()).expect("scope re-checked");
                    entry.handoff = false;
                    entry.settling = false;
                    entry.anchors = None;
                    table.insert(to.as_str().to_owned(), entry);
                    for other in table.values_mut() {
                        if other.parent_scope.as_deref() == Some(from.as_str()) {
                            other.parent_scope = Some(to.as_str().to_owned());
                        }
                    }
                    Some(())
                }
            };
            if moved.is_some() {
                break;
            }
            if Instant::now() >= deadline {
                return Err(ParentAuthorityError::Scope(format!(
                    "handed-off scope {} subtree still drains in-flight requests; \
                     reassignment timed out",
                    from.as_str()
                )));
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        {
            let mut claims = self.unit_claims.lock().map_err(|_| poisoned_scopes())?;
            for owner in claims.values_mut() {
                if owner.0 == from.as_str() {
                    owner.0 = to.as_str().to_owned();
                }
            }
        }
        // Keep the reservation after transfer so the worker ID cannot be reused.
        reservation.disarm();
        ParentAuthorityDescriptor::new(to.clone(), self.socket_path.clone(), store_root)
    }

    /// Explicit shutdown joins tracked handlers; Drop only starts best-effort cleanup.
    pub fn start(&self) -> Result<(), ParentAuthorityError> {
        if self.shutdown_complete.load(Ordering::Acquire) || self.stopping.load(Ordering::Acquire) {
            return Err(ParentAuthorityError::Transport(
                "parent broker was already shut down".to_owned(),
            ));
        }
        let mut slot = self.accept_thread.lock().map_err(|_| {
            ParentAuthorityError::Transport("accept-thread lock is poisoned".to_owned())
        })?;
        if slot.is_some() {
            return Err(ParentAuthorityError::Transport(
                "parent broker is already started".to_owned(),
            ));
        }
        let listener = self.listener.try_clone()?;
        let handle = std::thread::Builder::new()
            .name("odin-parent-broker-accept".to_owned())
            .spawn({
                let scopes = Arc::clone(&self.scopes);
                let unit_claims = Arc::clone(&self.unit_claims);
                let worker_reservations = Arc::clone(&self.worker_reservations);
                let allowed = Arc::clone(&self.allowed);
                let channel = self.channel.clone();
                let storage_root = self.storage_root.clone();
                let socket_path = self.socket_path.clone();
                let stopping = Arc::clone(&self.stopping);
                let next_connection = Arc::clone(&self.next_connection);
                let connections = Arc::clone(&self.connections);
                let handlers = Arc::clone(&self.handlers);
                let runtime_error = Arc::clone(&self.runtime_error);
                move || {
                    accept_loop(
                        listener,
                        scopes,
                        unit_claims,
                        worker_reservations,
                        allowed,
                        channel,
                        storage_root,
                        socket_path,
                        stopping,
                        next_connection,
                        connections,
                        handlers,
                        runtime_error,
                    )
                }
            })
            .map_err(|error| ParentAuthorityError::Transport(error.to_string()))?;
        *slot = Some(handle);
        Ok(())
    }

    /// Freeze admission without joining existing work; preserve durable state for recovery after process exit.
    pub fn abandon(&self) {
        self.stopping.store(true, Ordering::Release);
        // Socket shutdown cannot reject requests already decoded; freeze under the dispatch lock.
        let authorities = {
            let mut scopes = self
                .scopes
                .lock()
                .unwrap_or_else(|error| error.into_inner());
            scopes
                .values_mut()
                .filter_map(|entry| {
                    entry.settling = true;
                    entry.authority.as_ref().map(Arc::clone)
                })
                .collect::<Vec<_>>()
        };
        // Release the scope lock before waiting for an admitted operation's authority lock.
        for authority in authorities {
            authority.abandon();
        }
        if let Ok(stream) = UnixStream::connect(&self.socket_path) {
            let _ = stream.shutdown(Shutdown::Both);
        }
        let _ = close_connections(&self.connections);
        self.abandoned.store(true, Ordering::Release);
    }

    pub fn shutdown(
        &self,
        timeout: Duration,
    ) -> Result<ParentBrokerShutdown, ParentAuthorityError> {
        let deadline = Instant::now()
            .checked_add(timeout)
            .ok_or_else(shutdown_deadline_error)?;
        self.shutdown_until(deadline)
    }

    /// A timeout remains incomplete even if detached cleanup later finishes.
    pub fn shutdown_until(
        &self,
        deadline: Instant,
    ) -> Result<ParentBrokerShutdown, ParentAuthorityError> {
        self.stopping.store(true, Ordering::Release);
        if self.abandoned.load(Ordering::Acquire) {
            return Err(ParentAuthorityError::Transport(
                "parent broker was abandoned; stop proof unavailable".to_owned(),
            ));
        }
        if self.shutdown_failed.load(Ordering::Acquire) || Instant::now() >= deadline {
            self.shutdown_failed.store(true, Ordering::Release);
            return Err(shutdown_deadline_error());
        }
        let mut slot = self.shutdown_result.try_lock().map_err(|_| {
            self.shutdown_failed.store(true, Ordering::Release);
            shutdown_deadline_error()
        })?;
        if self.shutdown_complete.load(Ordering::Acquire) {
            return Ok(ParentBrokerShutdown::default());
        }
        if slot.is_none() {
            *slot = Some(self.spawn_shutdown(deadline)?);
        }
        let result = slot
            .as_ref()
            .expect("shutdown worker installed")
            .recv_timeout(deadline.saturating_duration_since(Instant::now()));
        match result {
            Ok(result)
                if Instant::now() < deadline && !self.shutdown_failed.load(Ordering::Acquire) =>
            {
                *slot = None;
                result
            }
            _ => {
                self.shutdown_failed.store(true, Ordering::Release);
                Err(shutdown_deadline_error())
            }
        }
    }

    fn spawn_shutdown(&self, deadline: Instant) -> Result<ShutdownReceiver, ParentAuthorityError> {
        let state = BrokerShutdownState {
            socket_path: self.socket_path.clone(),
            socket_dir: self.socket_dir.clone(),
            scopes: Arc::clone(&self.scopes),
            channel: self.channel.clone(),
            connections: Arc::clone(&self.connections),
            handlers: Arc::clone(&self.handlers),
            accept_thread: Arc::clone(&self.accept_thread),
            runtime_error: Arc::clone(&self.runtime_error),
            shutdown_complete: Arc::clone(&self.shutdown_complete),
        };
        let (sender, receiver) = std::sync::mpsc::channel();
        std::thread::Builder::new()
            .name("odin-broker-shutdown".to_owned())
            .spawn(move || {
                let result = managed_shutdown(&state, deadline);
                let _ = sender.send(result);
            })
            .map_err(|error| ParentAuthorityError::Transport(error.to_string()))?;
        Ok(receiver)
    }

    pub fn socket_path(&self) -> &Path {
        &self.socket_path
    }

    pub fn runtime_root(&self) -> &Path {
        &self.runtime_root
    }

    pub fn storage_root(&self) -> &Path {
        &self.storage_root
    }
}

type ShutdownReceiver =
    std::sync::mpsc::Receiver<Result<ParentBrokerShutdown, ParentAuthorityError>>;

struct BrokerShutdownState {
    socket_path: PathBuf,
    socket_dir: PathBuf,
    scopes: SharedScopes,
    channel: WorkerChannel,
    connections: SharedConnections,
    handlers: SharedHandlers,
    accept_thread: Arc<Mutex<Option<JoinHandle<()>>>>,
    runtime_error: Arc<Mutex<Option<String>>>,
    shutdown_complete: Arc<AtomicBool>,
}

fn shutdown_deadline_error() -> ParentAuthorityError {
    ParentAuthorityError::Transport(
        "broker shutdown deadline elapsed; stop proof unavailable".to_owned(),
    )
}

pub(super) fn set_runtime_error(target: &Arc<Mutex<Option<String>>>, detail: String) {
    if let Ok(mut slot) = target.lock() {
        if slot.is_none() {
            *slot = Some(detail);
        }
    }
}
pub(super) fn wait_until(
    predicate: impl Fn() -> bool,
    deadline: Instant,
) -> Result<(), ParentAuthorityError> {
    while !predicate() {
        if Instant::now() >= deadline {
            return Err(shutdown_deadline_error());
        }
        std::thread::sleep(
            Duration::from_millis(5).min(deadline.saturating_duration_since(Instant::now())),
        );
    }
    Ok(())
}

pub(super) fn close_connections(
    connections: &SharedConnections,
) -> Result<(), ParentAuthorityError> {
    for entry in connections.iter() {
        let _ = entry.value().shutdown(Shutdown::Both);
    }
    connections.clear();
    Ok(())
}

fn managed_shutdown(
    server: &BrokerShutdownState,
    deadline: Instant,
) -> Result<ParentBrokerShutdown, ParentAuthorityError> {
    if server.shutdown_complete.load(Ordering::Acquire) {
        return Ok(ParentBrokerShutdown::default());
    }
    close_connections(&server.connections)?;

    {
        let slot = server.accept_thread.lock().map_err(|_| {
            ParentAuthorityError::Transport("accept-thread lock is poisoned".to_owned())
        })?;
        if let Some(handle) = slot.as_ref() {
            wait_until(|| handle.is_finished(), deadline)?;
        }
    }
    if let Some(handle) = server
        .accept_thread
        .lock()
        .map_err(|_| ParentAuthorityError::Transport("accept-thread lock is poisoned".to_owned()))?
        .take()
    {
        handle.join().map_err(|_| {
            ParentAuthorityError::Transport("broker accept thread panicked".to_owned())
        })?;
    }

    // No new handlers can appear after the accept thread joins.
    close_connections(&server.connections)?;
    wait_until(
        || {
            server
                .handlers
                .lock()
                .map(|handlers| handlers.iter().all(JoinHandle::is_finished))
                .unwrap_or(false)
        },
        deadline,
    )?;
    let handlers = {
        let mut handlers = server.handlers.lock().map_err(|_| {
            ParentAuthorityError::Transport("handler registry lock is poisoned".to_owned())
        })?;
        std::mem::take(&mut *handlers)
    };
    let mut joined = 0_u64;
    for handler in handlers {
        handler.join().map_err(|_| {
            ParentAuthorityError::Transport("broker connection handler panicked".to_owned())
        })?;
        joined = joined.saturating_add(1);
    }

    // Keep handed-off entries visible because ancestor recovery uses them as exclusions.
    let mut entries = {
        let scopes = server.scopes.lock().map_err(|_| poisoned_scopes())?;
        scopes
            .iter()
            .filter(|(_, entry)| !entry.handoff)
            .map(|(worker, entry)| (worker.clone(), entry.depth))
            .collect::<Vec<_>>()
    };
    entries.sort_by_key(|(_, depth)| std::cmp::Reverse(*depth));
    let mut summary = ParentBrokerShutdown {
        connections_joined: joined,
        ..ParentBrokerShutdown::default()
    };
    let mut failures = Vec::new();
    for (worker, _) in entries {
        if Instant::now() >= deadline {
            failures.push(format!(
                "broker shutdown deadline elapsed before scope {worker} settled"
            ));
            continue;
        }
        let mut entry = server
            .scopes
            .lock()
            .map_err(|_| poisoned_scopes())?
            .remove(&worker)
            .ok_or_else(|| {
                ParentAuthorityError::Scope(format!("scope {worker} vanished during shutdown"))
            })?;
        entry.settling = true;
        match settle_scope_entry(
            &server.scopes,
            &worker,
            &mut entry,
            &server.channel,
            Some(deadline),
        ) {
            Ok(()) => summary.scopes_stopped = summary.scopes_stopped.saturating_add(1),
            Err(error) => {
                // Retain the authority and ledger so failed child cleanup can retry.
                server
                    .scopes
                    .lock()
                    .map_err(|_| poisoned_scopes())?
                    .insert(worker, entry);
                failures.push(error);
            }
        }
    }

    if let Some(error) = server
        .runtime_error
        .lock()
        .map_err(|_| ParentAuthorityError::Transport("runtime-error lock is poisoned".to_owned()))?
        .take()
    {
        failures.push(error);
    }
    if failures.is_empty() {
        for path in [&server.socket_path, &server.socket_dir] {
            let removed = if path == &server.socket_path {
                std::fs::remove_file(path)
            } else {
                std::fs::remove_dir(path)
            };
            if let Err(error) = removed {
                if error.kind() != std::io::ErrorKind::NotFound {
                    return Err(error.into());
                }
            }
        }
        let handed_off = {
            let mut scopes = server.scopes.lock().map_err(|_| poisoned_scopes())?;
            if scopes.values().any(|entry| !entry.handoff) {
                return Err(ParentAuthorityError::Scope(
                    "ordinary scopes remain after shutdown".to_owned(),
                ));
            }
            std::mem::take(&mut *scopes)
        };
        for (_, entry) in handed_off {
            if let Some(authority) = entry.authority {
                std::mem::forget(authority);
            }
            summary.scopes_handed_off = summary.scopes_handed_off.saturating_add(1);
        }
        server.shutdown_complete.store(true, Ordering::Release);
        Ok(summary)
    } else {
        Err(ParentAuthorityError::Scope(failures.join("; ")))
    }
}

impl Drop for ParentBrokerServer {
    fn drop(&mut self) {
        let already_stopping = self.stopping.swap(true, Ordering::AcqRel);
        if !self.shutdown_complete.load(Ordering::Acquire) {
            // Retain unresolved authorities so their destructors cannot stop workers on the caller.
            std::mem::forget(Arc::clone(&self.scopes));
        }
        if self.abandoned.load(Ordering::Acquire) {
            // Admission is frozen; do not retry cleanup beneath surviving work.
            return;
        }
        if !self.shutdown_complete.load(Ordering::Acquire) && !already_stopping {
            // Drop cannot wait for writers; only explicit shutdown establishes completion.
            if self
                .shutdown_result
                .get_mut()
                .is_ok_and(|slot| slot.is_none())
            {
                let _ = self.spawn_shutdown(Instant::now() + Duration::from_secs(5));
            }
        }
    }
}
