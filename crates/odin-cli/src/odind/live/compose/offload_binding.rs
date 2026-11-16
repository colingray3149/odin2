//! Compose optional remote offload from manifest executables.

use std::path::Path;
use std::sync::Arc;

use odin_huginn::{OdindConfig, RuntimeManifest};
use odin_registry::SnapshotHandle;

use super::super::offload;

pub(super) fn compose(
    config: &OdindConfig,
    manifest: &RuntimeManifest,
    huginn_root: &Path,
    snapshot_handle: &Arc<SnapshotHandle>,
) -> Result<Option<Arc<offload::Offload>>, String> {
    // A manifest without rsync leaves offload profiles refusing typed.
    match manifest.executable("rsync") {
        Ok(rsync) => Ok(Some(Arc::new(offload::Offload::open(
            config.paths.state_root.join("offload"),
            huginn_root.to_path_buf(),
            offload::Transport::Ssh {
                ssh: manifest
                    .executable("ssh")
                    .map_err(|error| format!("runtime manifest ssh: {error}"))?
                    .path
                    .clone(),
                rsync: rsync.path.clone(),
            },
            {
                let handle = Arc::clone(snapshot_handle);
                Arc::new(move || handle.current())
            },
        )?))),
        Err(error) => {
            tracing::warn!("offload is not configured: runtime manifest rsync: {error}");
            Ok(None)
        }
    }
}
