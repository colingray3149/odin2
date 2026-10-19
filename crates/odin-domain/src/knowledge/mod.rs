pub mod archive;
pub mod context;
pub mod ids;
pub mod privacy;
pub mod retrieval;

/// Requires a JSON key to be present while accepting an explicit `null`.
pub(crate) fn required_nullable<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: serde::Deserialize<'de>,
{
    <Option<T> as serde::Deserialize>::deserialize(deserializer)
}

/// Brain source-id namespaces: one immutable Atlas tree (`atlas.<subtree>`)
/// or one read-only external archive export (`archive.<export>`). A wired
/// `brain.sources` key, a seat's `brain_scope` entry, and a
/// `knowledge.atlas_sources` entry are all [`AtlasId`]s in one of these
/// namespaces; the namespace names the source class that serves it. Project
/// `memory_namespaces` stay Atlas-only: an archive export is served memory,
/// never another project's writable memory identity.
pub const ATLAS_SOURCE_NAMESPACE: &str = "atlas.";
/// The read-only external archive export namespace; see
/// [`ATLAS_SOURCE_NAMESPACE`].
pub const ARCHIVE_SOURCE_NAMESPACE: &str = "archive.";

pub use archive::*;
pub use context::*;
pub use ids::*;
pub use privacy::*;
pub use retrieval::*;
