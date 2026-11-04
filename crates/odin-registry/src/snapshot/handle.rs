use std::sync::{Arc, RwLock};

use super::contract::{Snapshot, SnapshotError};
use super::store::SnapshotStore;

/// Swap whole snapshots atomically so requests retain an immutable revision across reloads.
pub struct SnapshotHandle {
    store: SnapshotStore,
    current: RwLock<Arc<Snapshot>>,
    revision_events: tokio::sync::watch::Sender<u64>,
}

impl SnapshotHandle {
    /// Refuse startup when the published snapshot or its receipt cannot be verified.
    pub fn open(store: SnapshotStore) -> Result<Self, SnapshotError> {
        let snapshot = store.load_verified()?;
        let (revision_events, _) = tokio::sync::watch::channel(snapshot.revision);
        Ok(Self {
            store,
            current: RwLock::new(Arc::new(snapshot)),
            revision_events,
        })
    }

    /// Keep the pinned snapshot alive across later reloads.
    pub fn current(&self) -> Arc<Snapshot> {
        self.current
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }

    pub fn subscribe(&self) -> tokio::sync::watch::Receiver<u64> {
        self.revision_events.subscribe()
    }

    /// Reject regressed or changed same-number revisions; equal bytes retain the current pin.
    pub fn reload(&self) -> Result<Arc<Snapshot>, SnapshotError> {
        let snapshot = self.store.load_verified()?;
        let mut guard = self
            .current
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if snapshot.revision < guard.revision {
            return Err(SnapshotError::Invalid(format!(
                "published snapshot regressed from revision {} to {}",
                guard.revision, snapshot.revision
            )));
        }
        if snapshot.revision == guard.revision {
            if snapshot.hash != guard.hash {
                return Err(SnapshotError::Invalid(format!(
                    "published snapshot revision {} changed content; revisions are immutable",
                    guard.revision
                )));
            }
            return Ok(Arc::clone(&guard));
        }
        let pinned = Arc::new(snapshot);
        *guard = Arc::clone(&pinned);
        self.revision_events.send_replace(pinned.revision);
        Ok(pinned)
    }
}
