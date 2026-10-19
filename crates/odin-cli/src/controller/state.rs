use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

#[cfg(test)]
use odin_domain::Digest;
use odin_domain::NodeId;
#[cfg(test)]
use odin_kernel::authority_transition::{AuthorityDispatchReceipt, AuthorityDispatchRequest};
use odin_kernel::authority_transition::{
    AuthorityState, AuthorityTransitionController, AuthorityTransitionError,
};
use odin_ledger::{encode_utc, Ledger, LedgerError};
use odin_registry::{Snapshot, SnapshotStore};
use rusqlite::{params, OptionalExtension};
use serde_json::{Map, Value};
use time::OffsetDateTime;

use super::registry::{fixture_snapshot, node_exists};
#[cfg(test)]
use super::types::DispatchReceipt;
use super::types::{CheckReport, ControllerError};

const CHECK_SCHEMA: &str = "odin.controller-check.v1";
const CONTROLLER_KIND: &str = "controller";
const CONTROLLER_ID: &str = "odind";

pub(crate) struct Controller {
    kernel: AuthorityTransitionController,
    state_root: PathBuf,
    node: String,
    fixture_root: Option<PathBuf>,
    ledger_path: PathBuf,
    ledger: Ledger,
    authority: AuthorityState,
    restart_count: u64,
    materialized_rows: u64,
}

impl Controller {
    /// Rehearsal fixture route: a validated fixture registry directory
    /// becomes one pinned desired-state snapshot inside the kernel
    /// controller. No raw-TOML authority decision happens here.
    #[cfg(test)]
    pub(crate) fn open(
        state_root: &Path,
        registry_root: &Path,
        node: &str,
    ) -> Result<Self, ControllerError> {
        let snapshot = fixture_snapshot(registry_root, 1)?;
        Self::open_snapshot_inner(
            state_root,
            snapshot,
            node,
            Some(registry_root.to_path_buf()),
        )
    }

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
        Self::assemble(state_root, kernel, snapshot, node, None)
    }

    /// Production route over the exact immutable snapshot Arc the daemon
    /// already pinned for runtime composition.
    pub(crate) fn open_snapshot(
        state_root: &Path,
        snapshot: Arc<Snapshot>,
        node: &str,
    ) -> Result<Self, ControllerError> {
        Self::open_snapshot_inner(state_root, snapshot, node, None)
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
        Self::assemble(state_root, kernel, snapshot, node, None)
    }

    fn open_snapshot_inner(
        state_root: &Path,
        snapshot: Arc<Snapshot>,
        node: &str,
        fixture_root: Option<PathBuf>,
    ) -> Result<Self, ControllerError> {
        let kernel = AuthorityTransitionController::open_snapshot(
            state_root,
            Arc::clone(&snapshot),
            typed_node(node)?,
        )
        .map_err(map_kernel)?;
        Self::assemble(state_root, kernel, snapshot, node, fixture_root)
    }

    fn assemble(
        state_root: &Path,
        mut kernel: AuthorityTransitionController,
        snapshot: Arc<Snapshot>,
        node: &str,
        fixture_root: Option<PathBuf>,
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
        let materialized_rows =
            u64::try_from(ledger.rebuild_materialized_status()?).map_err(|_| {
                ControllerError::InvalidData("materialized row count exceeds u64".into())
            })?;
        Ok(Self {
            kernel,
            state_root: state_root.to_path_buf(),
            node: node.to_owned(),
            fixture_root,
            ledger_path,
            ledger,
            authority,
            restart_count: 0,
            materialized_rows,
        })
    }

    pub(crate) fn startup(&mut self) -> Result<CheckReport, ControllerError> {
        ensure_not_stopped(&self.state_root)?;
        if let Some(fixture_root) = self.fixture_root.clone() {
            let snapshot = fixture_snapshot(&fixture_root, self.kernel_snapshot_revision())?;
            self.kernel.refresh_pinned(snapshot).map_err(map_kernel)?;
        }
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
            stopped: false,
            ledger_path: self.ledger_path.clone(),
        })
    }

    #[cfg(test)]
    pub(crate) fn guard_dispatch(
        &mut self,
        idempotency_key: &str,
    ) -> Result<DispatchReceipt, ControllerError> {
        ensure_not_stopped(&self.state_root)?;
        if let Some(fixture_root) = self.fixture_root.clone() {
            let snapshot = fixture_snapshot(&fixture_root, self.kernel_snapshot_revision())?;
            self.kernel.refresh_pinned(snapshot).map_err(map_kernel)?;
        }
        let request = AuthorityDispatchRequest {
            idempotency_key: idempotency_key.to_owned(),
            command_digest: Digest::hash(idempotency_key.as_bytes()),
            observed_at: OffsetDateTime::now_utc(),
        };
        let receipt: AuthorityDispatchReceipt = match self.kernel.guard_dispatch(&request) {
            Ok(receipt) => receipt,
            Err(AuthorityTransitionError::AuthorityMismatch {
                local,
                authoritative,
                ..
            }) => {
                return Err(ControllerError::AuthorityMismatch {
                    local: local.to_string(),
                    authoritative: authoritative.to_string(),
                });
            }
            Err(AuthorityTransitionError::DispatchConflict {
                key,
                expected_digest,
                actual_digest,
            }) => {
                return Err(ControllerError::InvalidData(format!(
                    "dispatch {key:?} already binds digest {expected_digest}, not {actual_digest}"
                )));
            }
            Err(error) => return Err(map_kernel(error)),
        };
        self.authority = AuthorityState {
            local_node: receipt.authority_node.clone(),
            authoritative_node: receipt.authority_node.clone(),
            authoritative_host: self.authority.authoritative_host.clone(),
            snapshot_revision: receipt.snapshot_revision,
            snapshot_hash: receipt.snapshot_hash.clone(),
        };
        Ok(DispatchReceipt {
            command_id: receipt.command_id,
            inserted: receipt.inserted,
            audit_sequence: receipt.audit_sequence,
        })
    }

    #[cfg(test)]
    pub(crate) fn ledger_path(&self) -> &Path {
        &self.ledger_path
    }

    fn kernel_snapshot_revision(&self) -> u64 {
        self.authority.snapshot_revision
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

#[cfg(test)]
mod tests {
    use std::fs;

    use odin_registry::RegistryKind;
    use rusqlite::Connection;
    use tempfile::TempDir;

    use super::*;

    #[test]
    fn stop_prevents_claim_and_audit() {
        let fixture = Fixture::new("old");
        let mut controller = fixture.controller("old");
        controller.startup().expect("startup");
        fs::write(fixture.state.path().join("STOP"), b"stop\n").expect("write STOP");
        assert!(matches!(
            controller.guard_dispatch("stopped-command"),
            Err(ControllerError::Stopped(_))
        ));
        assert_eq!(counts(controller.ledger_path()), (0, 0));
    }

    #[test]
    fn stale_authority_prevents_claim_and_audit() {
        let fixture = Fixture::new("old");
        let mut controller = fixture.controller("old");
        controller.startup().expect("startup");
        fixture.write_registry("new");
        assert!(matches!(
            controller.guard_dispatch("stale-command"),
            Err(ControllerError::AuthorityMismatch { .. })
        ));
        // The kernel durably audits the stale denial; no claim is recorded.
        assert_eq!(counts(controller.ledger_path()), (0, 1));
    }

    #[test]
    fn duplicate_claim_has_one_acceptance() {
        let fixture = Fixture::new("node");
        let mut controller = fixture.controller("node");
        controller.startup().expect("startup");
        let first = controller.guard_dispatch("same-command").expect("first");
        let second = controller
            .guard_dispatch("same-command")
            .expect("duplicate");
        assert!(first.inserted);
        assert!(!second.inserted);
        assert_eq!(first.command_id, second.command_id);
        assert!(first.audit_sequence.is_some());
        assert_eq!(second.audit_sequence, None);
        assert_eq!(counts(controller.ledger_path()), (1, 1));
    }

    #[test]
    fn reopen_increments_restart_metadata() {
        let fixture = Fixture::new("node");
        {
            let mut controller = fixture.controller("node");
            assert_eq!(
                controller.startup().expect("first startup").restart_count,
                1
            );
        }
        let mut reopened = fixture.controller("node");
        assert_eq!(reopened.startup().expect("second startup").restart_count, 2);
    }

    struct Fixture {
        registry: TempDir,
        state: TempDir,
    }

    impl Fixture {
        fn new(authority: &str) -> Self {
            let fixture = Self {
                registry: tempfile::tempdir().expect("registry tempdir"),
                state: tempfile::tempdir().expect("state tempdir"),
            };
            fixture.write_registry(authority);
            fixture
        }

        fn controller(&self, node: &str) -> Controller {
            Controller::open(self.state.path(), self.registry.path(), node)
                .expect("open controller")
        }

        fn write_registry(&self, authority: &str) {
            let root = self.registry.path();
            let nodes = root.join("nodes");
            if nodes.exists() {
                fs::remove_dir_all(&nodes).expect("replace nodes");
            }
            for kind in RegistryKind::ALL {
                fs::create_dir_all(root.join(kind.directory()))
                    .expect("create registry kind directory");
            }
            for node in ["old", "new", "node"] {
                let host = root.join("hosts").join(format!("{node}-host"));
                fs::create_dir_all(&host).expect("create host directory");
                fs::write(
                    host.join("host.toml"),
                    format!(
                        "schema = \"odin.registry.v1\"\nkind = \"host\"\nenabled = true\ndescription = \"test host\"\nhardware = \"fixture\"\nrole = \"control\"\ntailscale = \"{node}-host\"\nenrolled = true\n"
                    ),
                )
                .expect("write host registry");
                let directory = nodes.join(node);
                fs::create_dir_all(&directory).expect("create node directory");
                fs::write(
                    directory.join("node.toml"),
                    format!(
                        "schema = \"odin.registry.v1\"\nkind = \"node\"\nenabled = true\ndescription = \"test node\"\nhost = \"{node}-host\"\nrole = \"control\"\ncapabilities = []\nallow_workloads = true\ngateway_endpoint = \"http://{node}-host:14000/v1\"\nauthoritative_state = {}\n",
                        node == authority
                    ),
                )
                .expect("write node registry");
            }
        }
    }

    fn counts(path: &Path) -> (i64, i64) {
        let connection = Connection::open(path).expect("open ledger for assertion");
        let claims = connection
            .query_row("SELECT COUNT(*) FROM idempotency_keys", [], |row| {
                row.get(0)
            })
            .expect("count claims");
        let audits = connection
            .query_row("SELECT COUNT(*) FROM audit_events", [], |row| row.get(0))
            .expect("count audits");
        (claims, audits)
    }
}
