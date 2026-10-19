//! Journal effects before dispatch and reconcile recorded outcomes instead of replaying effects.

mod admission;
mod child;
mod dispatch;
mod model;
mod settlement;

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, MutexGuard};

use odin_domain::operation::Limits;
use odin_ledger::{Ledger, LedgerError};

use crate::capability::SchemaCatalog;
use crate::token::SeatAuthority;

use model::AuthorityResult;

pub use admission::{AdmittedCapability, OperationCatalog};
pub use child::{ChildEffectGrant, ChildEffectRequest};
pub use model::{
    validate_input_arguments, CapsuleOutcome, Clock, CloseMode, EffectOutcome, ExecutorFault,
    InvokeRequest, OperationDecision, OperationExecutor, OperationRejection, Payload, PreWorld,
    PreWorldRecord, PreparedBinding, PreparedEffect, ProcessIdentity, ReconcileOutcome,
    Reconciliation, RecordedBinding, StopHandle, StopIntentOutcome, StopOutcome, Target,
};

pub struct OperationAuthority {
    catalog: Arc<dyn OperationCatalog>,
    schemas: Arc<dyn SchemaCatalog + Send + Sync>,
    executor: Arc<dyn OperationExecutor>,
    limits: Limits,
    clock: Clock,
    store: Arc<Mutex<Ledger>>,
    in_flight: Mutex<BTreeMap<String, Arc<StopHandle>>>,
}

impl OperationAuthority {
    pub fn new(
        catalog: Arc<dyn OperationCatalog>,
        schemas: Arc<dyn SchemaCatalog + Send + Sync>,
        executor: Arc<dyn OperationExecutor>,
        limits: Limits,
        clock: Clock,
        store: Arc<Mutex<Ledger>>,
    ) -> Self {
        Self {
            catalog,
            schemas,
            executor,
            limits,
            clock,
            store,
            in_flight: Mutex::new(BTreeMap::new()),
        }
    }

    pub(super) fn now_ms(&self) -> u64 {
        (self.clock)()
    }

    pub(super) fn check_authority(
        &self,
        authority: &SeatAuthority,
        now_ms: u64,
    ) -> AuthorityResult<()> {
        if authority.expires_at_ms() <= now_ms {
            return Err(OperationRejection::IdentityExpired {
                expires_at_ms: authority.expires_at_ms(),
            });
        }
        Ok(())
    }

    pub(super) fn lock_store(&self) -> AuthorityResult<MutexGuard<'_, Ledger>> {
        self.store.lock().map_err(|_| {
            OperationRejection::Durable(LedgerError::Publish(
                "operation authority store lock was poisoned".to_owned(),
            ))
        })
    }
}

#[cfg(test)]
mod tests;
