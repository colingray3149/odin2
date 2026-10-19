//! Prepare private stores before launch and activate scopes only after recording the running worker.

use super::*;

pub(super) fn prepare_scope_entry(
    scopes: &SharedScopes,
    storage_root: &Path,
    socket_path: &Path,
    worker_id: &WorkerId,
    owner_store: Arc<Mutex<Ledger>>,
    parent_scope: Option<String>,
    depth: u8,
) -> Result<ParentAuthorityDescriptor, ParentAuthorityError> {
    let mut table = scopes.lock().map_err(|_| poisoned_scopes())?;
    prepare_scope_entry_locked(
        &mut table,
        storage_root,
        socket_path,
        worker_id,
        owner_store,
        parent_scope,
        depth,
    )
}

/// Check the parent and reserve the child under one lock so settlement cannot strand a prepared scope.
pub(super) fn prepare_scope_entry_locked(
    table: &mut BTreeMap<String, ScopeEntry>,
    storage_root: &Path,
    socket_path: &Path,
    worker_id: &WorkerId,
    owner_store: Arc<Mutex<Ledger>>,
    parent_scope: Option<String>,
    depth: u8,
) -> Result<ParentAuthorityDescriptor, ParentAuthorityError> {
    if depth == 0 || depth > MAX_BROKER_NESTING_DEPTH {
        return Err(ParentAuthorityError::Scope(format!(
            "broker nesting depth {depth} exceeds the configured ceiling"
        )));
    }
    let store_root = storage_root.join(worker_id.as_str());
    if table.contains_key(worker_id.as_str()) || store_root.exists() {
        return Err(ParentAuthorityError::Scope(format!(
            "scope for worker {} already exists",
            worker_id.as_str()
        )));
    }
    std::fs::create_dir(&store_root)?;
    if let Err(error) =
        std::fs::set_permissions(&store_root, std::fs::Permissions::from_mode(0o700))
    {
        let _ = std::fs::remove_dir(&store_root);
        return Err(error.into());
    }
    let descriptor = match ParentAuthorityDescriptor::new(
        worker_id.clone(),
        socket_path.to_path_buf(),
        store_root.clone(),
    ) {
        Ok(descriptor) => descriptor,
        Err(error) => {
            let _ = std::fs::remove_dir(&store_root);
            return Err(error);
        }
    };
    table.insert(
        worker_id.as_str().to_owned(),
        ScopeEntry {
            store_root,
            owner_store,
            parent_scope,
            depth,
            anchors: None,
            handoff: false,
            settling: false,
            authority: None,
            in_flight: Arc::new(AtomicU64::new(0)),
        },
    );
    Ok(descriptor)
}

pub(super) fn prepare_nested_scope(
    scopes: &SharedScopes,
    storage_root: &Path,
    socket_path: &Path,
    parent_scope: &str,
    worker_id: &WorkerId,
    owner_store: Arc<Mutex<Ledger>>,
) -> Result<ParentAuthorityDescriptor, ParentAuthorityError> {
    let mut table = scopes.lock().map_err(|_| poisoned_scopes())?;
    let depth = {
        let parent = table.get(parent_scope).ok_or_else(|| {
            ParentAuthorityError::Scope(format!("parent scope {parent_scope} vanished"))
        })?;
        if parent.handoff {
            return Err(ParentAuthorityError::Scope(format!(
                "parent scope {parent_scope} was handed off"
            )));
        }
        if parent.settling {
            return Err(ParentAuthorityError::Scope(format!(
                "parent scope {parent_scope} is being settled"
            )));
        }
        parent.depth.checked_add(1).ok_or_else(|| {
            ParentAuthorityError::Scope("broker nesting depth overflow".to_owned())
        })?
    };
    prepare_scope_entry_locked(
        &mut table,
        storage_root,
        socket_path,
        worker_id,
        owner_store,
        Some(parent_scope.to_owned()),
        depth,
    )
}

pub(super) fn discard_prepared_scope(
    scopes: &SharedScopes,
    worker_id: &WorkerId,
) -> Result<(), ParentAuthorityError> {
    let store_root = {
        let mut table = scopes.lock().map_err(|_| poisoned_scopes())?;
        let Some(entry) = table.get(worker_id.as_str()) else {
            return Ok(());
        };
        if entry.anchors.is_some() || entry.authority.is_some() {
            return Err(ParentAuthorityError::Scope(format!(
                "activated scope {} cannot be discarded",
                worker_id.as_str()
            )));
        }
        let store_root = entry.store_root.clone();
        table.remove(worker_id.as_str());
        store_root
    };
    std::fs::remove_dir(&store_root).map_err(ParentAuthorityError::Io)
}

pub(super) fn activate_scope_entry(
    scopes: &SharedScopes,
    worker_id: &WorkerId,
    identity: &WorkerIdentity,
) -> Result<(), ParentAuthorityError> {
    if identity.worker_id != *worker_id {
        return Err(ParentAuthorityError::Scope(format!(
            "identity for worker {} cannot activate scope {}",
            identity.worker_id.as_str(),
            worker_id.as_str()
        )));
    }
    let invocation_hex = identity.invocation_id.to_hex();
    // Publish anchors under the owner ledger lock so stop intent cannot race activation.
    let mut table = scopes.lock().map_err(|_| poisoned_scopes())?;
    let entry = table.get_mut(worker_id.as_str()).ok_or_else(|| {
        ParentAuthorityError::Scope(format!(
            "worker {} has no prepared scope",
            worker_id.as_str()
        ))
    })?;
    if entry.anchors.is_some() {
        return Err(ParentAuthorityError::Scope(format!(
            "worker {} scope is already activated",
            worker_id.as_str()
        )));
    }
    if entry.handoff {
        return Err(ParentAuthorityError::Scope(format!(
            "scope {} was handed off before activation",
            worker_id.as_str()
        )));
    }
    let owner_store = Arc::clone(&entry.owner_store);
    {
        let ledger = owner_store.lock().map_err(|_| {
            ParentAuthorityError::Scope("scope owner ledger lock is poisoned".to_owned())
        })?;
        let owner_row = odin_ledger::worker::worker_row(ledger.connection(), worker_id.as_str())
            .map_err(|error| {
                ParentAuthorityError::Scope(format!(
                    "cannot resolve durable scope worker {}: {error}",
                    worker_id.as_str()
                ))
            })?
            .ok_or_else(|| {
                ParentAuthorityError::Scope(format!(
                    "scope worker {} has no durable owner row",
                    worker_id.as_str()
                ))
            })?;
        if owner_row.phase != WorkerPhase::PayloadRunning
            || owner_row.unit != identity.unit
            || owner_row.invocation_id.as_deref() != Some(invocation_hex.as_str())
            || owner_row.cgroup_path.as_deref() != Some(identity.cgroup_path.as_str())
            || owner_row.cgroup_inode != Some(identity.cgroup_inode)
            || owner_row.leader_pid != Some(identity.leader_pid)
            || owner_row.leader_start_ticks != Some(identity.leader_start_ticks)
        {
            return Err(ParentAuthorityError::Scope(format!(
                "manager identity for worker {} does not match its durable payload-running proof",
                worker_id.as_str()
            )));
        }
        // Even a completed stop must prevent stale launches from reopening this identity.
        if odin_ledger::stop::stop_row(ledger.connection(), worker_id.as_str())
            .map_err(|error| {
                ParentAuthorityError::Scope(format!(
                    "cannot read the stop state of scope worker {}: {error}",
                    worker_id.as_str()
                ))
            })?
            .is_some()
        {
            return Err(ParentAuthorityError::Scope(format!(
                "scope worker {} has a durable stop intent; activation refused",
                worker_id.as_str()
            )));
        }
    }
    entry.anchors = Some(ScopeAnchors {
        unit: identity.unit.clone(),
        invocation_hex,
        cgroup_path: identity.cgroup_path.clone(),
        cgroup_inode: identity.cgroup_inode,
        leader_pid: identity.leader_pid,
        leader_start_ticks: identity.leader_start_ticks,
    });
    Ok(())
}

pub(super) fn validate_private_root(
    role: &str,
    path: &Path,
) -> Result<PathBuf, ParentAuthorityError> {
    if !path.is_absolute() {
        return Err(ParentAuthorityError::Scope(format!(
            "{role} root {} must be absolute",
            path.display()
        )));
    }
    let canonical = std::fs::canonicalize(path)?;
    let metadata = std::fs::symlink_metadata(&canonical)?;
    if !metadata.is_dir()
        || metadata.permissions().mode() & 0o077 != 0
        || metadata.uid() != geteuid().as_raw()
    {
        return Err(ParentAuthorityError::Scope(format!(
            "{role} root {} must be an owner-private directory",
            canonical.display()
        )));
    }
    Ok(canonical)
}
