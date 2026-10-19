//! Assemble the kernel executor and durable ledger before accepting requests.

use super::projection::{projection_catalog, projection_schemas};
use super::store::{verified_effect_receipt, EffectReceiptStore};
use super::{
    now_utc, system_clock, EffectReceipt, EffectorExecutor, Provisioning, Sidecar,
    TransportProjection,
};
use crate::lifecycle::LifecycleLock;
use crate::storage;
use crate::{SidecarError, SidecarErrorCode};
use odin_domain::operation::{EffectState, Limits};
use odin_kernel::stop::StopAuthority;
use odin_kernel::{OperationAuthority, OperationExecutor, ParentAuthorityClient};
use odin_ledger::operation as ledger_op;
use odin_ledger::Ledger;
use odin_types::CorrelationId;
use std::collections::BTreeMap;
use std::path::Path;
use std::sync::{Arc, Mutex};

/// Keep nested worker ledgers under the state root so they survive individual exchanges.
const BROKER_SCOPE_STORES_DIR: &str = "worker-scopes";

pub struct AuthorityConfig {
    limits: Limits,
    max_state_bytes: usize,
    executor: Arc<EffectorExecutor>,
}

impl AuthorityConfig {
    pub fn new(
        limits: Limits,
        max_state_bytes: usize,
        executor: EffectorExecutor,
    ) -> Result<Self, SidecarError> {
        if max_state_bytes == 0 {
            return Err(SidecarError::new(
                SidecarErrorCode::State,
                "legacy state byte ceiling must be nonzero",
            ));
        }
        Ok(Self {
            limits,
            max_state_bytes,
            executor: Arc::new(executor),
        })
    }

    pub const fn limits(&self) -> Limits {
        self.limits
    }

    pub const fn max_state_bytes(&self) -> usize {
        self.max_state_bytes
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthoritySnapshot {
    pub nonterminal: BTreeMap<String, EffectState>,
    pub legacy_imported: bool,
}

impl Sidecar {
    /// Recover unfinished operations and import legacy state before accepting requests.
    pub fn create_or_open(
        state_root: &Path,
        config: AuthorityConfig,
        projection: TransportProjection,
        provisioning: Provisioning,
    ) -> Result<Self, SidecarError> {
        let lifecycle = Arc::new(LifecycleLock::acquire(state_root, true)?);
        let ledger_path = state_root.join(super::LEDGER_FILE);
        let ledger = Arc::new(Mutex::new(
            Ledger::open(&ledger_path).map_err(SidecarError::from)?,
        ));
        let clock = system_clock();

        let state_path = state_root.join(super::LEGACY_STATE_FILE);
        if state_path.exists() {
            let bytes = storage::read_bounded(&state_path, config.max_state_bytes)?;
            let now_ms = clock();
            let imported_at = now_utc(now_ms)?;
            let mut guard = ledger.lock().map_err(|_| SidecarError::poisoned())?;
            guard
                .with_tx(|tx| ledger_op::import_legacy_authority(tx, &bytes, imported_at))
                .map_err(|error| {
                    SidecarError::new(
                        SidecarErrorCode::LegacyImport,
                        format!("legacy authority state import failed: {error}"),
                    )
                })?;
            storage::archive(&state_path, super::LEGACY_ARCHIVE_SUFFIX)?;
        }

        // Nested sidecars use the parent's broker and ledger instead of opening a local manager channel.
        let (stop, scope_store_root) = if let Some(channel) = config.executor.worker_channel() {
            let scope_store_root = state_root.join(BROKER_SCOPE_STORES_DIR);
            storage::create_private_directory(&scope_store_root)?;
            (
                Arc::new(StopAuthority::new(Arc::clone(&ledger), channel.clone())),
                Some(scope_store_root),
            )
        } else {
            let parent = ParentAuthorityClient::from_env().map_err(|error| {
                SidecarError::new(
                    SidecarErrorCode::Authority,
                    format!("parent authority descriptor rejected: {error}"),
                )
            })?;
            if !parent.is_remote() {
                return Err(SidecarError::new(
                    SidecarErrorCode::Authority,
                    "nested sidecar has no ODIN_PARENT_AUTHORITY capability",
                ));
            }
            let parent_store_path = parent.expected_store_path().map_err(|error| {
                SidecarError::new(
                    SidecarErrorCode::Authority,
                    format!("parent authority store path rejected: {error}"),
                )
            })?;
            let parent_store = Arc::new(Mutex::new(
                Ledger::open(&parent_store_path).map_err(SidecarError::from)?,
            ));
            (
                Arc::new(
                    StopAuthority::from_parent(parent_store, parent).map_err(|error| {
                        SidecarError::new(
                            SidecarErrorCode::Authority,
                            format!("parent StopAuthority rejected: {error}"),
                        )
                    })?,
                ),
                None,
            )
        };
        if provisioning.post_effect_uncertainty_once() {
            config.executor.arm_post_effect_uncertainty_once();
        }
        config
            .executor
            .bind_stop_authority(Arc::clone(&stop), scope_store_root)?;
        stop.recover_pending(None).map_err(|error| {
            SidecarError::new(
                SidecarErrorCode::Authority,
                format!("effector worker recovery failed: {error}"),
            )
        })?;
        let receipt_store = Arc::new(EffectReceiptStore::new(Arc::clone(&ledger)));
        config.executor.bind_receipt_store(receipt_store)?;

        let projection = Arc::new(projection);
        let authority = OperationAuthority::new(
            projection_catalog(&projection),
            projection_schemas(&projection),
            Arc::clone(&config.executor) as Arc<dyn OperationExecutor>,
            config.limits,
            Arc::clone(&clock),
            Arc::clone(&ledger),
        );
        let host = Self {
            authority,
            executor: Arc::clone(&config.executor),
            ledger,
            signing_key: provisioning.signing_key().to_vec(),
            token: provisioning.seat_token,
            projection,
            clock,
            _lifecycle: lifecycle,
        };
        host.authority.recover().map_err(SidecarError::from)?;
        Ok(host)
    }

    pub fn now(&self) -> u64 {
        (self.clock)()
    }

    pub fn snapshot(&self) -> Result<AuthoritySnapshot, SidecarError> {
        let ledger = self.ledger.lock().map_err(|_| SidecarError::poisoned())?;
        let nonterminal = ledger_op::nonterminal_rows(ledger.connection(), None)?
            .into_iter()
            .map(|row| (row.correlation_id, row.effect_state))
            .collect();
        let legacy_imported = ledger_op::import_receipt_present(ledger.connection())?;
        Ok(AuthoritySnapshot {
            nonterminal,
            legacy_imported,
        })
    }

    /// Verify the persisted receipt against the journal before returning it to the host.
    pub fn effect_receipt(
        &self,
        correlation_id: &CorrelationId,
    ) -> Result<EffectReceipt, SidecarError> {
        let ledger = self.ledger.lock().map_err(|_| SidecarError::poisoned())?;
        verified_effect_receipt(&ledger, correlation_id)
    }
}
