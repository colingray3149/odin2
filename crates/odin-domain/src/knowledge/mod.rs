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

/// The read-only external archive export namespace: a source id `archive.<export>`
/// is served memory, never another project's writable memory identity.
pub const ARCHIVE_SOURCE_NAMESPACE: &str = "archive.";

pub use archive::*;
pub use context::*;
pub use ids::*;
pub use privacy::*;
pub use retrieval::*;
