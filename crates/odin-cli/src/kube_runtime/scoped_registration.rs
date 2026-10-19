//! Generated models and extension-policy artifacts are readable only by their
//! launching run, never through shared seat, project, or lane grants.
//! Registering identical bytes and run references is idempotent.

use std::sync::Mutex;

use odin_domain::RunId;
use odin_kube::artifacts::ArtifactStore;
use odin_ledger::Ledger;
use odin_omp::host_tools::HostToolError;

use super::admission::storage_error;

/// Attaches only a run reference, preventing access from other runs in the same seat.
pub(super) fn register_scoped_bytes(
    tool: &'static str,
    store: &ArtifactStore,
    ledger: &Mutex<Ledger>,
    bytes: &[u8],
    storage_path: &str,
    run_id: &RunId,
) -> Result<odin_ledger::artifact::ArtifactMetadata, HostToolError> {
    let metadata = store
        .register_bytes(bytes, storage_path)
        .map_err(|error| storage_error(tool, error.to_string()))?;
    let mut ledger = ledger
        .lock()
        .map_err(|_| storage_error(tool, "artifact ledger lock poisoned"))?;
    ledger
        .attach_artifact_reference(
            &metadata.artifact_id,
            metadata.revision,
            odin_ledger::artifact::NewArtifactReference {
                object_kind: "run",
                object_id: run_id.as_str(),
                relation: "kube-content",
                created_at: time::OffsetDateTime::now_utc(),
            },
        )
        .map_err(|error| storage_error(tool, error.to_string()))?;
    Ok(metadata)
}
