use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use odin_domain::NodeId;
use odin_kernel::authority_transition::{
    AuthorityState, AuthorityTransitionController, AuthorityTransitionError,
};
use odin_ledger::{encode_utc, Ledger, LedgerError};
use odin_registry::{Snapshot, SnapshotStore};
use rusqlite::{params, OptionalExtension};
use serde_json::{Map, Value};
use time::OffsetDateTime;

use super::registry::node_exists;
use super::types::{CheckReport, ControllerError};

const CHECK_SCHEMA: &str = "odin.controller-check.v1";
const CONTROLLER_KIND: &str = "controller";
const CONTROLLER_ID: &str = "odind";

pub(crate) struct Controller {
    kernel: AuthorityTransitionController,
    state_root: PathBuf,
    node: String,
    ledger_path: PathBuf,
    ledger: Ledger,
    authority: AuthorityState,
    restart_count: u64,
    materialized_rows: u64,
}

impl Controller {
    /// Production route: the store must prove it is the exact installed
    /// publication (immutable revision file plus binding receipt) or startup
    /// fails closed; raw, hand-written, or unreceipted snapshots are rejected
    /// inside the kernel controller.
    pub(crate) fn open_published(
        state_root: &Path,
        registry_snapshot: &Path,
        node: &str,
    ) -> Result<Self, ControllerError> {
        let store = SnapshotStore::new(registry_snapshot);
        let snapshot = Arc::new(
            store
                .load_verified()
                .map_err(|error| ControllerError::Registry(error.to_string()))?,
        );
        let kernel =
            AuthorityTransitionController::open_published(state_root, store, typed_node(node)?)
                .map_err(map_kernel)?;
        Self::assemble(state_root, kernel, snapshot, node)
    }

    /// Production route over the exact immutable snapshot Arc the daemon
    /// already pinned for runtime composition.
    pub(crate) fn open_snapshot(
        state_root: &Path,
        snapshot: Arc<Snapshot>,
        node: &str,
    ) -> Result<Self, ControllerError> {
        let kernel = AuthorityTransitionController::open_snapshot(
            state_root,
            Arc::clone(&snapshot),
            typed_node(node)?,
        )
        .map_err(map_kernel)?;
        Self::assemble(state_root, kernel, snapshot, node)
    }

    /// Production follower route over the exact immutable snapshot Arc the
    /// daemon pinned: opens only when the kernel-verified snapshot names a
    /// different authoritative node, and every kernel authority mutation
    /// is then refused before any audit write.
    pub(crate) fn open_snapshot_follower(
        state_root: &Path,
        snapshot: Arc<Snapshot>,
        node: &str,
    ) -> Result<Self, ControllerError> {
        let kernel = AuthorityTransitionController::open_snapshot_follower(
            state_root,
            Arc::clone(&snapshot),
            typed_node(node)?,
        )
        .map_err(map_kernel)?;
        Self::assemble(state_root, kernel, snapshot, node)
    }

    fn assemble(
        state_root: &Path,
        mut kernel: AuthorityTransitionController,
        snapshot: Arc<Snapshot>,
        node: &str,
    ) -> Result<Self, ControllerError> {
        if !node_exists(&snapshot, node) {
            return Err(ControllerError::InvalidData(format!(
                "validated registry omitted requested node {node:?}"
            )));
        }
        let authority = kernel.startup().map_err(map_kernel)?;
        ensure_not_stopped(state_root)?;
        fs::create_dir_all(state_root)?;
        ensure_not_stopped(state_root)?;
        let ledger_path = state_root.join("ledger.sqlite3");
        let mut ledger = Ledger::open(&ledger_path)?;
        ensure_not_stopped(state_root)?;
        let rebuilt = ledger.rebuild_materialized_status()?;
        let materialized_rows = u64::try_from(rebuilt).map_err(|error| {
            ControllerError::InvalidData(format!(
                "materialized row count {rebuilt} exceeds u64: {error}"
            ))
        })?;
        Ok(Self {
            kernel,
            state_root: state_root.to_path_buf(),
            node: node.to_owned(),
            ledger_path,
            ledger,
            authority,
            restart_count: 0,
            materialized_rows,
        })
    }

    pub(crate) fn startup(&mut self) -> Result<CheckReport, ControllerError> {
        ensure_not_stopped(&self.state_root)?;
        let authority = self.kernel.startup().map_err(map_kernel)?;
        let restart_count = self.bump_restart_counter(&authority.authoritative_node)?;
        self.authority = authority;
        self.restart_count = restart_count;
        Ok(CheckReport {
            schema: CHECK_SCHEMA.to_owned(),
            node: self.node.clone(),
            authoritative_node: self.authority.authoritative_node.to_string(),
            authoritative: self.kernel.is_authoritative(),
            restart_count,
            materialized_rows: self.materialized_rows,
            ledger_path: self.ledger_path.clone(),
        })
    }

    /// Durable controller telemetry: one monotonic restart counter under the
    /// well-known controller identity. Authority decisions stay in the
    /// kernel; this only records how often this wrapper started.
    fn bump_restart_counter(&mut self, authoritative: &NodeId) -> Result<u64, ControllerError> {
        let state_root = self.state_root.clone();
        let restart_count = self.ledger.with_tx(|transaction| {
            ensure_not_stopped_ledger(&state_root)?;
            let existing = transaction
                .query_row(
                    "SELECT revision, status_json FROM materialized_status
                     WHERE object_kind = ?1 AND object_id = ?2",
                    params![CONTROLLER_KIND, CONTROLLER_ID],
                    |row| Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?)),
                )
                .optional()?;
            let (revision, mut status) = match existing {
                Some((revision, encoded)) => {
                    if revision < 0 {
                        return Err(LedgerError::invalid_data(
                            "controller metadata has a negative revision".into(),
                        ));
                    }
                    let value: Value = serde_json::from_str(&encoded)?;
                    let object = value.as_object().cloned().ok_or_else(|| {
                        LedgerError::invalid_data(
                            "controller metadata status_json is not an object".into(),
                        )
                    })?;
                    (revision, object)
                }
                None => (0, Map::new()),
            };
            let previous = match status.get("restart_count") {
                Some(value) => value.as_u64().ok_or_else(|| {
                    LedgerError::invalid_data(
                        "controller metadata restart_count is not an unsigned integer".into(),
                    )
                })?,
                None => 0,
            };
            let next = previous.checked_add(1).ok_or_else(|| {
                LedgerError::invalid_data("controller restart_count overflowed".into())
            })?;
            let next_revision = revision.checked_add(1).ok_or_else(|| {
                LedgerError::invalid_data("controller metadata revision overflowed".into())
            })?;
            status.insert("restart_count".into(), Value::from(next));
            status.insert(
                "final_authority".into(),
                Value::String(authoritative.to_string()),
            );
            let status_json = serde_json::to_string(&status)?;
            transaction.execute(
                "INSERT INTO materialized_status (
                     object_kind, object_id, revision, status_json,
                     source_event_id, updated_at, stale_after
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, NULL)
                 ON CONFLICT(object_kind, object_id) DO UPDATE SET
                     revision = excluded.revision,
                     status_json = excluded.status_json,
                     source_event_id = excluded.source_event_id,
                     updated_at = excluded.updated_at,
                     stale_after = NULL",
                params![
                    CONTROLLER_KIND,
                    CONTROLLER_ID,
                    next_revision,
                    status_json,
                    format!("controller-start:{next}"),
                    encode_utc(OffsetDateTime::now_utc())?
                ],
            )?;
            Ok(next)
        })?;
        Ok(restart_count)
    }
}

fn typed_node(node: &str) -> Result<NodeId, ControllerError> {
    NodeId::new(node.to_owned()).map_err(|error| ControllerError::InvalidData(error.to_string()))
}

fn map_kernel(error: AuthorityTransitionError) -> ControllerError {
    match error {
        AuthorityTransitionError::AuthorityMismatch {
            local,
            authoritative,
            ..
        } => ControllerError::AuthorityMismatch {
            local: local.to_string(),
            authoritative: authoritative.to_string(),
        },
        AuthorityTransitionError::FollowerRefusal {
            local,
            authoritative,
            operation,
        } => ControllerError::FollowerRefusal {
            local: local.to_string(),
            authoritative: authoritative.to_string(),
            operation,
        },
        AuthorityTransitionError::Ledger(inner) => ControllerError::Ledger(inner),
        AuthorityTransitionError::Snapshot(inner) => ControllerError::Registry(inner.to_string()),
        AuthorityTransitionError::Io(inner) => ControllerError::Io(inner),
        other => ControllerError::InvalidData(other.to_string()),
    }
}

fn ensure_not_stopped(state_root: &Path) -> Result<(), ControllerError> {
    let stop = state_root.join("STOP");
    if stop.try_exists()? {
        return Err(ControllerError::Stopped(stop));
    }
    Ok(())
}

fn ensure_not_stopped_ledger(state_root: &Path) -> Result<(), LedgerError> {
    let stop = state_root.join("STOP");
    if stop.try_exists()? {
        return Err(LedgerError::Conflict(format!(
            "controller STOP requested at {}",
            stop.display()
        )));
    }
    Ok(())
}
