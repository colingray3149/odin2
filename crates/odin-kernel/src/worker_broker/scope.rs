//! Freeze and drain scopes before reassignment or settlement to avoid racing admitted effects.

use super::*;

/// Retain the cgroup inode so a recreated path cannot impersonate a worker.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct ScopeAnchors {
    pub(super) unit: String,
    pub(super) invocation_hex: String,
    pub(super) cgroup_path: String,
    pub(super) cgroup_inode: u64,
    pub(super) leader_pid: u32,
    pub(super) leader_start_ticks: u64,
}

pub(super) struct ScopeEntry {
    pub(super) store_root: PathBuf,
    pub(super) owner_store: Arc<Mutex<Ledger>>,
    pub(super) parent_scope: Option<String>,
    pub(super) depth: u8,
    pub(super) anchors: Option<ScopeAnchors>,
    pub(super) authority: Option<Arc<StopAuthority>>,
    pub(super) handoff: bool,
    /// Freeze admission during subtree settlement or abandonment.
    pub(super) settling: bool,
    /// Count requests and launch effects under the scope lock so a frozen scope can drain safely.
    pub(super) in_flight: Arc<AtomicU64>,
}

pub(super) type SharedScopes = Arc<Mutex<BTreeMap<String, ScopeEntry>>>;
pub(super) type SharedUnitClaims = Arc<Mutex<BTreeMap<String, (String, String)>>>;
/// Reserve IDs under locks ordered reservations, scopes, ledgers to prevent concurrent reuse.
pub(super) type SharedWorkerReservations = Arc<Mutex<BTreeMap<String, String>>>;
pub(super) type SharedConnections = Arc<DashMap<u64, UnixStream>>;
pub(super) type SharedHandlers = Arc<Mutex<Vec<JoinHandle<()>>>>;

/// Preserve handed-off children and retain failed settlements for later cleanup.
pub(super) fn settle_scope_entry(
    scopes: &SharedScopes,
    worker: &str,
    entry: &mut ScopeEntry,
    channel: &WorkerChannel,
    budget: Option<Instant>,
) -> Result<(), String> {
    let excluded: BTreeSet<String> = {
        let table = scopes
            .lock()
            .map_err(|_| "scope table lock is poisoned".to_owned())?;
        table
            .iter()
            .filter(|(_, scoped)| scoped.handoff && scoped.parent_scope.as_deref() == Some(worker))
            .map(|(id, _)| id.clone())
            .collect()
    };
    if entry.authority.is_none() {
        let ledger = Ledger::open(entry.store_root.join(SCOPE_LEDGER_NAME)).map_err(|error| {
            format!(
                "scope {worker} ledger open failed (parent {:?}): {error}",
                entry.parent_scope
            )
        })?;
        let store = Arc::new(Mutex::new(ledger));
        entry.authority = Some(Arc::new(StopAuthority::new(store, channel.clone())));
    }
    let authority = entry
        .authority
        .as_ref()
        .expect("scope authority initialized");
    let store = authority.store();
    let (pending, residual) = {
        let ledger = store
            .lock()
            .map_err(|_| format!("scope {worker} ledger lock is poisoned"))?;
        (
            odin_ledger::worker::nonterminal_rows(ledger.connection(), None)
                .map_err(|error| format!("scope {worker} recovery queue unreadable: {error}"))?,
            odin_ledger::worker::residual_rows(ledger.connection()).map_err(|error| {
                format!("scope {worker} residual inventory unreadable: {error}")
            })?,
        )
    };
    let mut failures = residual
        .into_iter()
        .filter(|(row, _)| !excluded.contains(&row.worker_id))
        .map(|(row, _)| {
            format!(
                "scope {worker} retains worker residue for {}",
                row.worker_id
            )
        })
        .collect::<Vec<_>>();
    for row in pending {
        if excluded.contains(&row.worker_id) {
            continue;
        }
        let pending_worker = WorkerId::new(&row.worker_id).map_err(|error| {
            format!(
                "scope {worker} recovery row {:?} is invalid: {error}",
                row.worker_id
            )
        })?;
        let settled = match budget {
            // Refuse expired budgets before entering a blocking stop.
            Some(deadline) if Instant::now() >= deadline => Err(String::from(
                "settlement budget elapsed before the stop was issued",
            )),
            Some(deadline) => authority
                .stop_worker_bounded(&pending_worker, deadline)
                .map_err(|error| error.to_string()),
            None => authority
                .stop_worker(&pending_worker)
                .map_err(|error| error.to_string()),
        };
        match settled {
            Ok(outcome) if outcome.verdict == StopVerdict::Stopped => {}
            Ok(outcome) => failures.push(format!(
                "scope {worker} worker {pending_worker} settlement verdict was {:?}",
                outcome.verdict
            )),
            Err(error) => failures.push(format!(
                "scope {worker} settlement failed at {pending_worker}: {error}"
            )),
        }
    }
    if !failures.is_empty() {
        return Err(failures.join("; "));
    }
    if !excluded.is_empty() {
        // Dropping the parent would stop children deliberately preserved by handoff.
        if let Some(authority) = entry.authority.take() {
            std::mem::forget(authority);
        }
    }
    Ok(())
}

/// Share subtree traversal so handoff, revocation, draining, and reassignment include the same descendants.
pub(super) fn scope_subtree_locked(
    table: &BTreeMap<String, ScopeEntry>,
    root: &str,
) -> Vec<String> {
    let mut lineage = vec![root.to_owned()];
    loop {
        let descendants = table
            .iter()
            .filter_map(|(worker, entry)| {
                entry
                    .parent_scope
                    .as_ref()
                    .filter(|parent| lineage.contains(parent) && !lineage.contains(worker))
                    .map(|_| worker.clone())
            })
            .collect::<Vec<_>>();
        if descendants.is_empty() {
            break;
        }
        lineage.extend(descendants);
    }
    lineage
}

/// Exclude handed-off entries and settle deepest-first so children stop before their parents.
pub(super) fn revoke_scope_subtree(
    scopes: &SharedScopes,
    root: &str,
    include_root: bool,
) -> Result<Vec<(String, ScopeEntry)>, StopAuthorityError> {
    let mut table = scopes.lock().map_err(|_| StopAuthorityError::LedgerLock)?;
    let lineage = scope_subtree_locked(&table, root);
    let mut doomed = table
        .iter()
        .filter(|(worker, entry)| {
            !entry.handoff && lineage.contains(*worker) && (include_root || worker.as_str() != root)
        })
        .map(|(worker, entry)| (worker.clone(), entry.depth))
        .collect::<Vec<_>>();
    doomed.sort_by_key(|(_, depth)| std::cmp::Reverse(*depth));
    Ok(doomed
        .into_iter()
        .filter_map(|(worker, _)| table.remove(&worker).map(|entry| (worker, entry)))
        .collect())
}

/// Retain the admission freeze after failed cleanup so stopped hosts cannot start new effects.
pub(super) fn freeze_scope_subtree(
    scopes: &SharedScopes,
    root: &str,
    include_root: bool,
) -> Result<Vec<(String, Arc<AtomicU64>)>, StopAuthorityError> {
    let mut table = scopes.lock().map_err(|_| StopAuthorityError::LedgerLock)?;
    let mut frozen = Vec::new();
    for worker in scope_subtree_locked(&table, root) {
        if !include_root && worker == root {
            continue;
        }
        if let Some(entry) = table.get_mut(&worker) {
            if entry.handoff {
                continue;
            }
            entry.settling = true;
            frozen.push((worker, Arc::clone(&entry.in_flight)));
        }
    }
    Ok(frozen)
}

/// Drain before revoking; retain failed entries frozen so cleanup can retry without admitting effects.
pub(super) fn settle_scope_subtree(
    scopes: &SharedScopes,
    root: &str,
    include_root: bool,
    channel: &WorkerChannel,
    stopping: &AtomicBool,
    budget: Option<Instant>,
) -> Result<(), StopAuthorityError> {
    // Caller budgets can only shorten the subtree deadline; None leaves per-entry stops unbounded.
    let ceiling = Instant::now()
        .checked_add(MAX_BROKER_SUBTREE_SETTLE_TIMEOUT)
        .unwrap_or_else(Instant::now);
    let effective = budget.map(|budget| budget.min(ceiling));
    let deadline = effective.unwrap_or(ceiling);
    let mut failures = Vec::new();
    let frozen = freeze_scope_subtree(scopes, root, include_root)?;
    let mut drained = true;
    'drain: for (worker, count) in &frozen {
        loop {
            if stopping.load(Ordering::Acquire) {
                failures.push(format!(
                    "parent broker is shutting down; scope {root} subtree settlement \
                     aborted before {worker} drained"
                ));
                drained = false;
                break 'drain;
            }
            if count.load(Ordering::Acquire) == 0 {
                break;
            }
            if Instant::now() >= deadline {
                failures.push(format!(
                    "scope {root} subtree drain ceiling elapsed before scope {worker}"
                ));
                drained = false;
                break 'drain;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
    }
    if drained {
        let batch = revoke_scope_subtree(scopes, root, include_root)?;
        for (worker, mut entry) in batch {
            let result = if stopping.load(Ordering::Acquire) {
                Err(format!(
                    "parent broker is shutting down; scope {worker} settlement deferred"
                ))
            } else if Instant::now() >= deadline {
                Err(format!(
                    "scope {root} subtree settlement ceiling elapsed before scope {worker}"
                ))
            } else {
                settle_scope_entry(scopes, &worker, &mut entry, channel, effective)
            };
            if let Err(error) = result {
                scopes
                    .lock()
                    .map_err(|_| StopAuthorityError::LedgerLock)?
                    .insert(worker, entry);
                failures.push(error);
            }
        }
    }
    if failures.is_empty() {
        Ok(())
    } else {
        Err(StopAuthorityError::InvalidWorker(failures.join("; ")))
    }
}

/// Count requests through completion so reassignment cannot overtake admitted work.
pub(super) struct ScopeInFlight(pub(super) Arc<AtomicU64>);

impl Drop for ScopeInFlight {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

/// Reserve effects under the scope lock so handoff and settlement cannot overtake a launch.
pub(super) fn revalidate_and_reserve(
    scopes: &SharedScopes,
    scope_worker: &str,
) -> Result<ScopeInFlight, DispatchError> {
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
                    "scope {scope_worker} was handed off, revoked, or is being settled; \
                     effect refused"
                )),
            )
        })?;
    entry.in_flight.fetch_add(1, Ordering::AcqRel);
    Ok(ScopeInFlight(Arc::clone(&entry.in_flight)))
}

/// Roll back claims and prepared scopes on failure; disarm only after launch commits.
pub(super) struct LaunchRollback<'a> {
    pub(super) scopes: &'a SharedScopes,
    pub(super) claims: &'a SharedUnitClaims,
    pub(super) unit: String,
    pub(super) child_worker: WorkerId,
    pub(super) armed: bool,
}

impl<'a> LaunchRollback<'a> {
    pub(super) fn new(
        scopes: &'a SharedScopes,
        claims: &'a SharedUnitClaims,
        unit: String,
        child_worker: WorkerId,
    ) -> Self {
        Self {
            scopes,
            claims,
            unit,
            child_worker,
            armed: true,
        }
    }

    pub(super) fn disarm(mut self) {
        self.armed = false;
    }

    pub(super) fn rollback(mut self, error: DispatchError) -> DispatchError {
        self.armed = false;
        let (code, error) = error;
        let mut failures = Vec::new();
        if let Err(cleanup) = discard_prepared_scope(self.scopes, &self.child_worker) {
            failures.push(format!("prepared-scope cleanup failed: {cleanup}"));
        }
        if let Err(cleanup) = release_remote_unit(self.claims, &self.unit) {
            failures.push(format!("unit-claim release failed: {cleanup}"));
        }
        if failures.is_empty() {
            (code, error)
        } else {
            (
                code,
                StopAuthorityError::InvalidWorker(format!(
                    "{error}; launch rollback: {}",
                    failures.join("; ")
                )),
            )
        }
    }
}

impl Drop for LaunchRollback<'_> {
    fn drop(&mut self) {
        if self.armed {
            let _ = discard_prepared_scope(self.scopes, &self.child_worker);
            let _ = release_remote_unit(self.claims, &self.unit);
        }
    }
}

pub(super) fn poisoned_scopes() -> ParentAuthorityError {
    ParentAuthorityError::Scope("scope table lock is poisoned".to_owned())
}

pub(super) type DispatchError = (BrokerRejectionCode, StopAuthorityError);
