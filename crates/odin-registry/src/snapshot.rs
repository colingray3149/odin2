//! Registry snapshot validation, publication, and runtime access.

mod atomic;
mod composition;
mod contract;
mod handle;
mod provenance;
mod publication;
mod store;

#[cfg(test)]
mod tests;

pub use composition::CompositionDigest;
pub use contract::{
    ObjectIndex, Snapshot, SnapshotError, Tombstone, WorkloadProfileRef, SNAPSHOT_SCHEMA,
};
pub use handle::SnapshotHandle;
pub use provenance::ValidatedSnapshotCandidate;
pub use store::{
    PublicationOutcome, PublicationReceipt, PublicationResult, RuntimeProjection, SnapshotBase,
    SnapshotStore, PUBLICATION_RECEIPT_SCHEMA,
};

pub(crate) use atomic::{atomic_write, read_regular_file};
