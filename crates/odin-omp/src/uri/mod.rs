//! Read-only scoped URI routing for the OMP bridge.
//!
//! The registered schemes are exactly `atlas:// brain:// odin-artifact:// incident:// run:// lane://
//! approval://`. Parsing rejects every non-canonical input — unknown schemes, credentials,
//! fragments, queries, percent-encoding, traversal, control bytes, and malformed identifiers —
//! before any resolver or storage runs. Ledger resolvers check the caller's scope before
//! returning immutable snapshots; `atlas://` is the deployment-wide allowed snapshot. Brain
//! reads check Atlas node provenance and pin the service policy digest and index generation.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use odin_atlas::AtlasScope;
use odin_brain::service::BrainService;
use odin_confined_fs::Capability;
use odin_domain::SeatId;
use odin_ledger::Ledger;

use crate::host_tools::atlas_query::SharedAtlas;

mod artifact;
mod atlas;
mod brain;
mod brain_ids;
mod brain_page;
mod contract;
mod resolvers;
mod router;

#[cfg(test)]
mod tests;

pub use contract::{
    ExecutionBinding, UriBody, UriContext, UriError, UriRequest, UriResult, UriScheme,
    ARTIFACT_CONTENT_TYPE, JSON_CONTENT_TYPE, MAX_ARTIFACT_READ_BOUND, OMP_CHUNK_PAYLOAD_BYTES,
};

/// Route-and-resolve entry over the injected ledger, atlas, allowed atlas scope, and sealed
/// artifact root. Brain services are per served seat: a deployment without a brain service
/// — or a session whose seat serves none — resolves every other scheme while `brain://`
/// fails typed-unavailable.
#[derive(Clone)]
pub struct ScopedUriRouter {
    ledger: Arc<Mutex<Ledger>>,
    atlas: SharedAtlas,
    allowed_atlas_scope: Arc<AtlasScope>,
    artifact_root: Arc<Capability>,
    /// The declared artifact root name the capability was sealed from. Every
    /// filesystem effect re-proves this name against the sealed descriptor,
    /// so a root replaced after construction is a typed refusal instead of a
    /// silent answer from the orphaned tree.
    artifact_root_path: Arc<PathBuf>,
    max_artifact_bytes: u64,
    brains: Arc<BTreeMap<SeatId, Arc<BrainService>>>,
}
