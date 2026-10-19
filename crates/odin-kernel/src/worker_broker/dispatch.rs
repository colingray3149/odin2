//! Reserve worker IDs and launch effects before dispatch so concurrent scopes cannot reuse them.

use super::*;

enum LaunchPlan {
    /// Isolated launches never receive a parent descriptor.
    Isolated,
    /// Host networking keeps the bus masked; only broker hosts receive descriptors.
    RegisteredService { nested_host: bool },
}

/// Honor requested isolation; registered execution requires the parent catalog, not caller assertions.
fn plan_launch(
    binding: &ParentExecutableBinding,
    requested: BrokerLaunchProfile,
) -> Result<LaunchPlan, DispatchError> {
    match requested {
        BrokerLaunchProfile::Isolated => Ok(LaunchPlan::Isolated),
        BrokerLaunchProfile::RegisteredService => match binding.profile() {
            ParentExecutableProfile::RegisteredService => Ok(LaunchPlan::RegisteredService {
                nested_host: binding.is_broker_host(),
            }),
            ParentExecutableProfile::Isolated => Err((
                BrokerRejectionCode::Forbidden,
                StopAuthorityError::InvalidWorker(format!(
                    "executable {} has no registered-service binding; \
                     the parent refuses the isolation upgrade",
                    binding.executable().display()
                )),
            )),
        },
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) fn dispatch(
    scopes: &SharedScopes,
    unit_claims: &SharedUnitClaims,
    worker_reservations: &SharedWorkerReservations,
    allowed: &AllowedParentBindings,
    channel: &WorkerChannel,
    storage_root: &Path,
    socket_path: &Path,
    scope_worker: &str,
    authority: &Arc<StopAuthority>,
    stopping: &AtomicBool,
    request: BrokerRequest,
) -> Result<(BrokerResponse, Option<(OwnedFd, OwnedFd)>), DispatchError> {
    let _in_flight = {
        let table = scopes
            .lock()
            .map_err(|_| (BrokerRejectionCode::Scope, StopAuthorityError::LedgerLock))?;
        let entry = table
            .get(scope_worker)
            .filter(|entry| !entry.handoff && !entry.settling)
            .ok_or_else(|| {
                (
                    BrokerRejectionCode::Scope,
                    StopAuthorityError::InvalidWorker(format!(
                        "scope {scope_worker} is handed off, being settled, or vanished"
                    )),
                )
            })?;
        entry.in_flight.fetch_add(1, Ordering::AcqRel);
        ScopeInFlight(Arc::clone(&entry.in_flight))
    };
    let worker_id_of = |raw: &str| -> Result<WorkerId, DispatchError> {
        WorkerId::new(raw).map_err(|error| {
            (
                BrokerRejectionCode::Protocol,
                StopAuthorityError::InvalidWorker(format!("worker id {raw:?}: {error}")),
            )
        })
    };
    match request {
        BrokerRequest::Launch {
            correlation_id,
            naming,
            spec,
            limits,
            profile,
        } => {
            let correlation = CorrelationId::new(&correlation_id).map_err(|error| {
                (
                    BrokerRejectionCode::Protocol,
                    StopAuthorityError::InvalidWorker(format!("correlation id: {error}")),
                )
            })?;
            let owner = scope_owner_row(scopes, scope_worker)
                .map_err(|error| (classify_authority_error(&error), error))?;
            let requested = naming_from_wire(&naming).map_err(|error| {
                (
                    BrokerRejectionCode::Protocol,
                    StopAuthorityError::InvalidChannel(error.to_string()),
                )
            })?;
            let (anchors, _) = scope_anchors(scopes, scope_worker)
                .map_err(|error| (BrokerRejectionCode::Scope, error))?;
            let naming = normalize_remote_naming(&owner, &anchors, requested)
                .map_err(|error| (BrokerRejectionCode::Scope, error))?;
            reserve_launch_worker_id(
                worker_reservations,
                scopes,
                scope_worker,
                &authority.store(),
                &naming.worker_id,
            )
            .map_err(|error| (BrokerRejectionCode::State, error))?;
            let spec = spec_from_wire(&spec).map_err(|error| {
                (
                    BrokerRejectionCode::Protocol,
                    StopAuthorityError::InvalidChannel(error.to_string()),
                )
            })?;
            let limits = limits_from_wire(&limits)
                .map_err(|error: StopAuthorityError| (BrokerRejectionCode::Protocol, error))?;
            let executable = PathBuf::from(spec.argv.executable());
            let binding = allowed.binding_for(&executable).ok_or_else(|| {
                (
                    BrokerRejectionCode::Forbidden,
                    StopAuthorityError::InvalidWorker(format!(
                        "executable {} is not in the parent allow-catalog",
                        executable.display()
                    )),
                )
            })?;
            let plan = plan_launch(binding, profile)?;
            let unit = naming.unit();
            claim_remote_unit(unit_claims, &unit, scope_worker, &naming.worker_id)
                .map_err(|error| (BrokerRejectionCode::State, error))?;

            let child_worker = naming.worker_id.clone();
            // Roll back claims and scopes on failure, but retain the ID reservation for its durable row.
            let rollback =
                LaunchRollback::new(scopes, unit_claims, unit.clone(), child_worker.clone());
            let committed = (|| {
                // Hold the reservation through launch bookkeeping so handoff and settlement must wait.
                let _reservation = revalidate_and_reserve(scopes, scope_worker)?;
                let nested_descriptor = match &plan {
                    LaunchPlan::RegisteredService { nested_host: true } => Some(
                        prepare_nested_scope(
                            scopes,
                            storage_root,
                            socket_path,
                            scope_worker,
                            &child_worker,
                            authority.store(),
                        )
                        .map_err(|error| {
                            (
                                BrokerRejectionCode::Scope,
                                StopAuthorityError::InvalidWorker(error.to_string()),
                            )
                        })?,
                    ),
                    _ => None,
                };
                let spec =
                    apply_parent_descriptor(spec, nested_descriptor.as_ref()).map_err(|error| {
                        (
                            BrokerRejectionCode::Protocol,
                            StopAuthorityError::InvalidChannel(error.to_string()),
                        )
                    })?;
                let mut manager = ManagerClient::connect(channel.bus()).map_err(|error| {
                    (
                        BrokerRejectionCode::Worker,
                        StopAuthorityError::Worker(error.into()),
                    )
                })?;
                if manager
                    .get_unit(&unit)
                    .map_err(|error| {
                        (
                            BrokerRejectionCode::Worker,
                            StopAuthorityError::Worker(error.into()),
                        )
                    })?
                    .is_some()
                {
                    return Err((
                        BrokerRejectionCode::State,
                        StopAuthorityError::InvalidWorker(format!(
                            "unit {unit} already exists; refusing to target or clean up the collision"
                        )),
                    ));
                }
                let launch = match &plan {
                    LaunchPlan::Isolated => {
                        authority.launch_worker(naming, &correlation, &spec, limits)
                    }
                    LaunchPlan::RegisteredService { .. } => {
                        let binding = RegisteredServiceBinding::new(
                            binding.executable().to_path_buf(),
                            binding.compiled_binding_blake3().to_owned(),
                        )
                        .map_err(|error| {
                            (
                                BrokerRejectionCode::Worker,
                                StopAuthorityError::Worker(error),
                            )
                        })?;
                        authority.launch_registered_service(
                            naming,
                            &correlation,
                            &spec,
                            limits,
                            &binding,
                        )
                    }
                };
                let launch = launch.map_err(|error| (BrokerRejectionCode::Worker, error))?;
                if nested_descriptor.is_some() {
                    if let Err(activation) =
                        activate_scope_entry(scopes, &child_worker, &launch.identity)
                    {
                        // Stop the worker before discarding its failed scope and releasing its claim.
                        let worker_cleanup = authority.stop_worker(&child_worker);
                        return Err((
                            BrokerRejectionCode::Scope,
                            StopAuthorityError::InvalidWorker(format!(
                                "nested scope activation failed: {activation}; \
                                 worker cleanup: {worker_cleanup:?}"
                            )),
                        ));
                    }
                }
                Ok(launch)
            })();
            match committed {
                Ok(launch) => {
                    rollback.disarm();
                    let identity = identity_to_wire(&launch.identity);
                    let stdout = OwnedFd::from(launch.stdout);
                    let stderr = OwnedFd::from(launch.stderr);
                    Ok((
                        BrokerResponse::Launched { identity },
                        Some((stdout, stderr)),
                    ))
                }
                Err(error) => Err(rollback.rollback(error)),
            }
        }
        BrokerRequest::WriteStdin {
            worker_id,
            bytes,
            timeout_millis,
        } => {
            if timeout_millis > MAX_BROKER_STDIN_WRITE_TIMEOUT.as_millis() as u64 {
                return Err((
                    BrokerRejectionCode::Protocol,
                    StopAuthorityError::InvalidChannel(
                        "stdin write timeout exceeds the broker ceiling".to_owned(),
                    ),
                ));
            }
            let worker_id = worker_id_of(&worker_id)?;
            let count = authority
                .write_worker_stdin_timeout(
                    &worker_id,
                    &bytes,
                    Duration::from_millis(timeout_millis),
                )
                .map_err(|error| (classify_authority_error(&error), error))?;
            let count = u64::try_from(count).map_err(|_| {
                (
                    BrokerRejectionCode::Protocol,
                    StopAuthorityError::InvalidChannel(
                        "stdin write count is not representable".to_owned(),
                    ),
                )
            })?;
            Ok((BrokerResponse::Written { count }, None))
        }
        BrokerRequest::CloseStdin { worker_id } => {
            let worker_id = worker_id_of(&worker_id)?;
            authority
                .close_worker_stdin(&worker_id)
                .map(|_| (BrokerResponse::Closed {}, None))
                .map_err(|error| (classify_authority_error(&error), error))
        }
        BrokerRequest::TryWait { worker_id } => {
            let worker_id = worker_id_of(&worker_id)?;
            authority
                .try_wait_worker(&worker_id)
                .map(|status| {
                    (
                        BrokerResponse::Tried {
                            status: status.map(|status| status.into_raw()),
                        },
                        None,
                    )
                })
                .map_err(|error| (classify_authority_error(&error), error))
        }
        BrokerRequest::Wait {
            worker_id,
            timeout_millis,
        } => {
            if timeout_millis > MAX_BROKER_WAIT_TIMEOUT.as_millis() as u64 {
                return Err((
                    BrokerRejectionCode::Protocol,
                    StopAuthorityError::InvalidChannel(
                        "wait timeout exceeds the broker ceiling".to_owned(),
                    ),
                ));
            }
            let worker_id = worker_id_of(&worker_id)?;
            let deadline = Instant::now()
                .checked_add(Duration::from_millis(timeout_millis))
                .unwrap_or_else(Instant::now);
            loop {
                if stopping.load(Ordering::Acquire) {
                    return Err((
                        BrokerRejectionCode::State,
                        StopAuthorityError::InvalidWorker(
                            "parent broker is shutting down".to_owned(),
                        ),
                    ));
                }
                let status = authority
                    .try_wait_worker(&worker_id)
                    .map_err(|error| (classify_authority_error(&error), error))?;
                if status.is_some() || Instant::now() >= deadline {
                    break Ok((
                        BrokerResponse::Waited {
                            status: status.map(|status| status.into_raw()),
                        },
                        None,
                    ));
                }
                std::thread::sleep(Duration::from_millis(5));
            }
        }
        BrokerRequest::Identity { worker_id } => {
            let worker_id = worker_id_of(&worker_id)?;
            authority
                .worker_identity(&worker_id)
                .map(|identity| {
                    (
                        BrokerResponse::Identity {
                            identity: identity.as_ref().map(identity_to_wire),
                        },
                        None,
                    )
                })
                .map_err(|error| (classify_authority_error(&error), error))
        }
        BrokerRequest::Stop { worker_id } => {
            let worker_id = worker_id_of(&worker_id)?;
            let outcome = authority
                .stop_worker(&worker_id)
                .map_err(|error| (classify_authority_error(&error), error))?;
            // Settle descendant scopes before reporting a complete stop, even if the owner stopped successfully.
            settle_scope_subtree(scopes, worker_id.as_str(), true, channel, stopping, None)
                .map_err(|error| (BrokerRejectionCode::Scope, error))?;
            Ok((
                BrokerResponse::Stopped {
                    outcome: outcome_to_wire(&outcome),
                },
                None,
            ))
        }
        BrokerRequest::StopBounded {
            worker_id,
            timeout_millis,
        } => {
            if timeout_millis > MAX_BROKER_STOP_TIMEOUT.as_millis() as u64 {
                return Err((
                    BrokerRejectionCode::Protocol,
                    StopAuthorityError::InvalidChannel(
                        "stop budget exceeds the broker ceiling".to_owned(),
                    ),
                ));
            }
            let worker_id = worker_id_of(&worker_id)?;
            let deadline = Instant::now()
                .checked_add(Duration::from_millis(timeout_millis))
                .unwrap_or_else(Instant::now);
            let outcome = authority
                .stop_worker_bounded(&worker_id, deadline)
                .map_err(|error| (classify_authority_error(&error), error))?;
            // Descendant cleanup shares the remaining deadline rather than starting unbounded stops.
            settle_scope_subtree(
                scopes,
                worker_id.as_str(),
                true,
                channel,
                stopping,
                Some(deadline),
            )
            .map_err(|error| (BrokerRejectionCode::Scope, error))?;
            Ok((
                BrokerResponse::Stopped {
                    outcome: outcome_to_wire(&outcome),
                },
                None,
            ))
        }
        BrokerRequest::RecoverPending { correlation_id } => {
            let correlation = correlation_id
                .map(|raw| {
                    CorrelationId::new(&raw).map_err(|error| {
                        (
                            BrokerRejectionCode::Protocol,
                            StopAuthorityError::InvalidWorker(format!("correlation id: {error}")),
                        )
                    })
                })
                .transpose()?;
            let outcomes = authority
                .recover_pending(correlation.as_ref())
                .map_err(|error| (classify_authority_error(&error), error))?;
            // Recovery may stop broker hosts; settle their descendant scopes before reporting completion.
            let mut failures = Vec::new();
            for outcome in &outcomes {
                if let Err(error) = settle_scope_subtree(
                    scopes,
                    outcome.worker_id.as_str(),
                    true,
                    channel,
                    stopping,
                    None,
                ) {
                    failures.push(error.to_string());
                }
            }
            if failures.is_empty() {
                Ok((
                    BrokerResponse::Recovered {
                        outcomes: outcomes.iter().map(outcome_to_wire).collect(),
                    },
                    None,
                ))
            } else {
                Err((
                    BrokerRejectionCode::Scope,
                    StopAuthorityError::InvalidWorker(failures.join("; ")),
                ))
            }
        }
        BrokerRequest::StopRecord { worker_id } => {
            let worker_id = worker_id_of(&worker_id)?;
            authority
                .stop_record(&worker_id)
                .map(|record| {
                    (
                        BrokerResponse::Record {
                            record: record.as_ref().map(record_to_wire),
                        },
                        None,
                    )
                })
                .map_err(|error| (classify_authority_error(&error), error))
        }
        BrokerRequest::HandoffScope {} => {
            // Mark handoff only when this request is alone; launches hold an additional count until registered.
            let deadline = Instant::now()
                .checked_add(MAX_BROKER_HANDOFF_QUIESCE_TIMEOUT)
                .unwrap_or_else(Instant::now);
            loop {
                if stopping.load(Ordering::Acquire) {
                    return Err((
                        BrokerRejectionCode::State,
                        StopAuthorityError::InvalidWorker(
                            "parent broker is shutting down; handoff refused".to_owned(),
                        ),
                    ));
                }
                let marked = {
                    let mut table = scopes.lock().map_err(|_| {
                        (BrokerRejectionCode::Scope, StopAuthorityError::LedgerLock)
                    })?;
                    if !table.contains_key(scope_worker) {
                        return Err((
                            BrokerRejectionCode::Scope,
                            StopAuthorityError::InvalidWorker(format!(
                                "scope {scope_worker} vanished during handoff"
                            )),
                        ));
                    }
                    let count = table
                        .get(scope_worker)
                        .expect("scope re-checked")
                        .in_flight
                        .load(Ordering::Acquire);
                    if count <= 1 {
                        for worker in scope_subtree_locked(&table, scope_worker) {
                            if let Some(entry) = table.get_mut(&worker) {
                                entry.handoff = true;
                            }
                        }
                        true
                    } else {
                        false
                    }
                };
                if marked {
                    break;
                }
                if Instant::now() >= deadline {
                    return Err((
                        BrokerRejectionCode::Scope,
                        StopAuthorityError::InvalidWorker(format!(
                            "scope {scope_worker} still has in-flight requests; \
                             handoff quiesce timed out"
                        )),
                    ));
                }
                std::thread::sleep(Duration::from_millis(5));
            }
            Ok((BrokerResponse::HandedOff {}, None))
        }
    }
}

fn classify_authority_error(error: &StopAuthorityError) -> BrokerRejectionCode {
    match error {
        StopAuthorityError::UnknownWorker(_) => BrokerRejectionCode::UnknownWorker,
        StopAuthorityError::Ledger(_) => BrokerRejectionCode::Ledger,
        StopAuthorityError::LedgerLock
        | StopAuthorityError::WorkerRegistryLock
        | StopAuthorityError::JobBackendLock
        | StopAuthorityError::PodAuthorityLock => BrokerRejectionCode::State,
        StopAuthorityError::Worker(_) => BrokerRejectionCode::Worker,
        StopAuthorityError::JobBackend(_) | StopAuthorityError::PodBackend(_) => {
            BrokerRejectionCode::State
        }
        StopAuthorityError::Json(_) => BrokerRejectionCode::Protocol,
        StopAuthorityError::InvalidWorker(_) | StopAuthorityError::InvalidChannel(_) => {
            BrokerRejectionCode::State
        }
    }
}

pub(super) fn scope_owner_row(
    scopes: &SharedScopes,
    scope_worker: &str,
) -> Result<odin_ledger::worker::WorkerRow, StopAuthorityError> {
    let owner_store = {
        let table = scopes.lock().map_err(|_| StopAuthorityError::LedgerLock)?;
        let entry = table.get(scope_worker).ok_or_else(|| {
            StopAuthorityError::InvalidWorker(format!("scope {scope_worker} vanished"))
        })?;
        Arc::clone(&entry.owner_store)
    };
    let ledger = owner_store
        .lock()
        .map_err(|_| StopAuthorityError::LedgerLock)?;
    let owner =
        odin_ledger::worker::worker_row(ledger.connection(), scope_worker)?.ok_or_else(|| {
            StopAuthorityError::InvalidWorker(format!(
                "scope worker {scope_worker} has no durable owner row"
            ))
        })?;
    // Stop intent prevents the scope from admitting fresh effects.
    if odin_ledger::stop::stop_row(ledger.connection(), scope_worker)?.is_some() {
        return Err(StopAuthorityError::InvalidWorker(format!(
            "scope worker {scope_worker} has a durable stop intent; new effects refused"
        )));
    }
    Ok(owner)
}

pub(super) fn scope_anchors(
    scopes: &SharedScopes,
    scope_worker: &str,
) -> Result<(ScopeAnchors, PathBuf), StopAuthorityError> {
    let table = scopes.lock().map_err(|_| StopAuthorityError::LedgerLock)?;
    let entry = table.get(scope_worker).ok_or_else(|| {
        StopAuthorityError::InvalidWorker(format!("scope {scope_worker} vanished"))
    })?;
    let anchors = entry.anchors.clone().ok_or_else(|| {
        StopAuthorityError::InvalidWorker(format!("scope {scope_worker} has no manager proof"))
    })?;
    Ok((anchors, entry.store_root.clone()))
}

pub(super) fn normalize_remote_naming(
    owner: &odin_ledger::worker::WorkerRow,
    anchors: &ScopeAnchors,
    requested: WorkerNaming,
) -> Result<WorkerNaming, StopAuthorityError> {
    // Use the durable parent transaction and InvocationID; request metadata cannot select another namespace.
    let wp_id = format!("pa{}-{}", anchors.invocation_hex, requested.wp_id);
    let normalized = WorkerNaming::new(
        owner.tx_id.clone(),
        wp_id,
        requested.attempt,
        requested.worker_id,
    )
    .map_err(StopAuthorityError::Worker)?;
    if normalized.unit().len() > 255 {
        return Err(StopAuthorityError::InvalidWorker(
            "parent-owned remote unit name exceeds the systemd unit-name ceiling".to_owned(),
        ));
    }
    Ok(normalized)
}

/// Reserve IDs atomically across scopes and ancestor ledgers so duplicate IDs cannot revoke unrelated workers.
pub(super) fn reserve_launch_worker_id(
    reservations: &SharedWorkerReservations,
    scopes: &SharedScopes,
    scope_worker: &str,
    own_store: &Arc<Mutex<Ledger>>,
    worker_id: &WorkerId,
) -> Result<(), StopAuthorityError> {
    let mut registry = reservations
        .lock()
        .map_err(|_| StopAuthorityError::WorkerRegistryLock)?;
    if registry.contains_key(worker_id.as_str()) {
        return Err(StopAuthorityError::InvalidWorker(format!(
            "worker {} is already reserved by a launch or reassignment on this broker",
            worker_id.as_str()
        )));
    }
    let mut ledgers: Vec<Arc<Mutex<Ledger>>> = vec![Arc::clone(own_store)];
    {
        let table = scopes.lock().map_err(|_| StopAuthorityError::LedgerLock)?;
        if table.contains_key(worker_id.as_str()) {
            return Err(StopAuthorityError::InvalidWorker(format!(
                "worker {} collides with an existing broker scope",
                worker_id.as_str()
            )));
        }
        let mut current = Some(scope_worker.to_owned());
        while let Some(name) = current {
            let entry = table.get(&name).ok_or_else(|| {
                StopAuthorityError::InvalidWorker(format!("scope {name} vanished"))
            })?;
            let owner = Arc::clone(&entry.owner_store);
            if !ledgers.iter().any(|known| Arc::ptr_eq(known, &owner)) {
                ledgers.push(owner);
            }
            current = entry.parent_scope.clone();
        }
    }
    for ledger in &ledgers {
        let ledger = ledger.lock().map_err(|_| StopAuthorityError::LedgerLock)?;
        if odin_ledger::worker::worker_row(ledger.connection(), worker_id.as_str())?.is_some() {
            return Err(StopAuthorityError::InvalidWorker(format!(
                "worker {} collides with an existing identity in a scope ledger",
                worker_id.as_str()
            )));
        }
    }
    registry.insert(worker_id.as_str().to_owned(), scope_worker.to_owned());
    Ok(())
}

pub(super) fn claim_remote_unit(
    claims: &SharedUnitClaims,
    unit: &str,
    scope_worker: &str,
    child_worker: &WorkerId,
) -> Result<(), StopAuthorityError> {
    let mut claims = claims
        .lock()
        .map_err(|_| StopAuthorityError::WorkerRegistryLock)?;
    if let Some((claimed_scope, claimed_worker)) = claims.get(unit) {
        return Err(StopAuthorityError::InvalidWorker(format!(
            "unit {unit} is already claimed by worker {claimed_worker} in scope {claimed_scope}"
        )));
    }
    claims.insert(
        unit.to_owned(),
        (scope_worker.to_owned(), child_worker.as_str().to_owned()),
    );
    Ok(())
}

/// Release failed transfer reservations; keep committed IDs reserved against reuse.
pub(super) struct ReassignReservation<'a> {
    pub(super) registry: &'a SharedWorkerReservations,
    pub(super) worker: String,
    pub(super) armed: bool,
}

impl ReassignReservation<'_> {
    pub(super) fn disarm(mut self) {
        self.armed = false;
    }
}

impl Drop for ReassignReservation<'_> {
    fn drop(&mut self) {
        if self.armed {
            if let Ok(mut registry) = self.registry.lock() {
                registry.remove(self.worker.as_str());
            }
        }
    }
}

pub(super) struct ReservedReassignment<'a> {
    pub(super) reservation: ReassignReservation<'a>,
    pub(super) store_root: PathBuf,
    pub(super) owner_store: Arc<Mutex<Ledger>>,
    pub(super) anchors: Option<ScopeAnchors>,
}

/// Check the source owner ledger, not the root ledger, when reserving a nested handoff target.
pub(super) fn reserve_reassign_target<'a>(
    reservations: &'a SharedWorkerReservations,
    scopes: &SharedScopes,
    from: &WorkerId,
    to: &WorkerId,
) -> Result<ReservedReassignment<'a>, ParentAuthorityError> {
    let mut registry = reservations.lock().map_err(|_| poisoned_scopes())?;
    if registry.contains_key(to.as_str()) {
        return Err(ParentAuthorityError::Scope(format!(
            "reassignment target {} is already reserved by a launch or \
             reassignment on this broker",
            to.as_str()
        )));
    }
    let (store_root, owner_store, anchors) = {
        let table = scopes.lock().map_err(|_| poisoned_scopes())?;
        if table.contains_key(to.as_str()) {
            return Err(ParentAuthorityError::Scope(format!(
                "reassignment target {} already owns a scope",
                to.as_str()
            )));
        }
        let entry = table.get(from.as_str()).ok_or_else(|| {
            ParentAuthorityError::Scope(format!(
                "handed-off scope {} does not exist",
                from.as_str()
            ))
        })?;
        if !entry.handoff {
            return Err(ParentAuthorityError::Scope(format!(
                "scope {} was never explicitly handed off",
                from.as_str()
            )));
        }
        (
            entry.store_root.clone(),
            Arc::clone(&entry.owner_store),
            entry.anchors.clone(),
        )
    };
    {
        let ledger = owner_store.lock().map_err(|_| poisoned_scopes())?;
        if odin_ledger::worker::worker_row(ledger.connection(), to.as_str())
            .map_err(|error| ParentAuthorityError::Scope(error.to_string()))?
            .is_some()
        {
            return Err(ParentAuthorityError::Scope(format!(
                "reassignment target {} already has a durable owner row in its scope owner ledger",
                to.as_str()
            )));
        }
    }
    registry.insert(
        to.as_str().to_owned(),
        format!("reassignment of {}", from.as_str()),
    );
    Ok(ReservedReassignment {
        reservation: ReassignReservation {
            registry: reservations,
            worker: to.as_str().to_owned(),
            armed: true,
        },
        store_root,
        owner_store,
        anchors,
    })
}

/// Failed launches release unit claims for retry; successful launches retain them for the unit lifetime.
pub(super) fn release_remote_unit(
    claims: &SharedUnitClaims,
    unit: &str,
) -> Result<(), StopAuthorityError> {
    let mut claims = claims
        .lock()
        .map_err(|_| StopAuthorityError::WorkerRegistryLock)?;
    claims.remove(unit);
    Ok(())
}
