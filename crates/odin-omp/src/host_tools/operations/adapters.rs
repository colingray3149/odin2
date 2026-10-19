//! Ready-only adapter health for capability listing and authorization.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use odin_adapter_core::status::{AdapterHealthState, AdapterStatusSnapshot};
use odin_kernel::AdapterHealth;
use time::OffsetDateTime;

use super::HostToolOperationError;

/// Refreshes through a registered supervised transport, with one deadline-limited attempt.
/// Waiting on the dispatching executor deadlocks; failures must leave the adapter unavailable.
pub trait HostAdapterStatusTransport: Send + Sync {
    fn refresh_status(
        &self,
        adapter: &str,
    ) -> Result<AdapterStatusSnapshot, HostToolOperationError>;
}

/// Adapter status over no supervised transport. Every refresh fails
/// closed; combined with an empty identity set it serves stacks that admit
/// no adapter-bound capability.
pub struct UnsupervisedAdapterStatus;

impl HostAdapterStatusTransport for UnsupervisedAdapterStatus {
    fn refresh_status(
        &self,
        adapter: &str,
    ) -> Result<AdapterStatusSnapshot, HostToolOperationError> {
        Err(HostToolOperationError::AdapterStatus {
            adapter: adapter.to_owned(),
            detail: "no supervised adapter transport is composed".to_owned(),
        })
    }
}

/// The host's live Ready-only adapter-health projection, read at both
/// listing and authorization. Implementations never enable a capability
/// from unknown, stale, unavailable, or foreign-identity state, and a
/// failure is cleared only by a real later refresh.
pub trait HostAdapterStatus: Send + Sync {
    fn current_health(&self, adapters: &BTreeSet<String>, now_ms: u64) -> AdapterHealth;

    /// Records that an authorized dispatch against one adapter did not
    /// settle. The next health query refreshes for real; only a fresh
    /// Ready snapshot re-enables the adapter.
    fn record_dispatch_failure(&self, adapter: &str);
}

/// Credential taint is recorded separately and does not make a Ready adapter unavailable.
#[derive(Default)]
struct AdapterStatusEntry {
    snapshot: Option<AdapterStatusSnapshot>,
    refresh_failed: bool,
}

/// Only configured adapters with fresh Ready snapshots are healthy.
/// The transport validates snapshot identity; stale or failed entries refresh once per query.
pub struct SupervisedAdapterStatus {
    transport: Arc<dyn HostAdapterStatusTransport>,
    configured: BTreeSet<String>,
    ttl: Duration,
    entries: Mutex<BTreeMap<String, AdapterStatusEntry>>,
}

impl SupervisedAdapterStatus {
    pub fn new(
        transport: Arc<dyn HostAdapterStatusTransport>,
        configured: BTreeSet<String>,
        ttl: Duration,
    ) -> Self {
        Self {
            transport,
            configured,
            ttl,
            entries: Mutex::new(BTreeMap::new()),
        }
    }

    /// Whether the snapshot is within the freshness bound and not
    /// future-dated. A pre-epoch stamp fails closed.
    fn is_fresh(snapshot: &AdapterStatusSnapshot, ttl: Duration, now_ms: u64) -> bool {
        let observed_ms =
            (snapshot.observed_at() - OffsetDateTime::UNIX_EPOCH).whole_milliseconds();
        let Ok(observed_ms) = u64::try_from(observed_ms) else {
            return false;
        };
        now_ms >= observed_ms
            && now_ms - observed_ms <= ttl.as_millis().min(u64::MAX as u128) as u64
    }

    /// Performs the one real refresh for this query. The entry fails closed
    /// through the attempt; only a snapshot under the admitted identity
    /// with a fresh Ready verdict is healthy.
    fn refresh(&self, adapter: &str, entry: &mut AdapterStatusEntry, now_ms: u64) -> bool {
        let was_ready = entry
            .snapshot
            .as_ref()
            .is_some_and(|snapshot| matches!(snapshot.health(), AdapterHealthState::Ready))
            && !entry.refresh_failed;
        entry.refresh_failed = true;
        let snapshot = match self.transport.refresh_status(adapter) {
            Ok(snapshot) => snapshot,
            Err(error) => {
                if was_ready || entry.snapshot.is_none() {
                    tracing::warn!(
                        "odind: adapter health id={adapter} state=unavailable error={error}"
                    );
                }
                entry.snapshot = None;
                return false;
            }
        };
        entry.refresh_failed = false;
        let ready = matches!(snapshot.health(), AdapterHealthState::Ready);
        if ready != was_ready {
            tracing::info!(
                "odind: adapter health id={adapter} state={:?} failure={:?}",
                snapshot.health(),
                snapshot.last_failure().map(|failure| failure.code.as_str())
            );
        }
        entry.snapshot = Some(snapshot);
        ready
            && Self::is_fresh_from_refresh(
                entry.snapshot.as_ref().expect("just stored"),
                self.ttl,
                now_ms,
            )
    }

    /// The query clock precedes the probe, so allow timestamps up to one TTL after it.
    fn is_fresh_from_refresh(snapshot: &AdapterStatusSnapshot, ttl: Duration, now_ms: u64) -> bool {
        let observed_ms =
            (snapshot.observed_at() - OffsetDateTime::UNIX_EPOCH).whole_milliseconds();
        let Ok(observed_ms) = u64::try_from(observed_ms) else {
            return false;
        };
        let ttl_ms = ttl.as_millis().min(u128::from(u64::MAX)) as u64;
        observed_ms <= now_ms.saturating_add(ttl_ms) && now_ms.saturating_sub(observed_ms) <= ttl_ms
    }
}

impl HostAdapterStatus for SupervisedAdapterStatus {
    fn current_health(&self, adapters: &BTreeSet<String>, now_ms: u64) -> AdapterHealth {
        let mut entries = self
            .entries
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        AdapterHealth::new(
            adapters
                .iter()
                .map(|adapter| {
                    let healthy = match self.configured.contains(adapter) {
                        false => false,
                        true => {
                            let entry = entries.entry(adapter.clone()).or_default();
                            match &entry.snapshot {
                                Some(snapshot)
                                    if matches!(snapshot.health(), AdapterHealthState::Ready)
                                        && !entry.refresh_failed
                                        && Self::is_fresh(snapshot, self.ttl, now_ms) =>
                                {
                                    true
                                }
                                _ => self.refresh(adapter, entry, now_ms),
                            }
                        }
                    };
                    (adapter.clone(), healthy)
                })
                .collect(),
        )
    }

    fn record_dispatch_failure(&self, adapter: &str) {
        if let Ok(mut entries) = self.entries.lock() {
            entries
                .entry(adapter.to_owned())
                .or_default()
                .refresh_failed = true;
        }
    }
}
