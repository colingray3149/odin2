use std::path::Path;
use std::sync::Arc;

use odin_registry::{parse_objects, walk, RegistryFinding, Snapshot};

use super::ControllerError;

/// Builds one validated desired-state snapshot from a fixture registry
/// directory. This helper exists only for rehearsal; every
/// production controller consumes the published `SnapshotStore` through the
/// kernel authority-transition controller, never raw TOML.
pub(super) fn fixture_snapshot(
    registry_root: &Path,
    revision: u64,
) -> Result<Arc<Snapshot>, ControllerError> {
    let discovery = walk(registry_root);
    let parsed = parse_objects(&discovery.objects);
    let mut failures: Vec<_> = discovery
        .findings
        .into_iter()
        .chain(parsed.findings)
        .filter(RegistryFinding::is_failure)
        .collect();
    failures.sort();
    if !failures.is_empty() {
        let details = failures
            .iter()
            .take(4)
            .map(|finding| {
                format!(
                    "{} at {}: {}",
                    finding.code,
                    finding.path.display(),
                    finding.message
                )
            })
            .collect::<Vec<_>>()
            .join("; ");
        return Err(ControllerError::Registry(format!(
            "fixture registry validation failed: {details}"
        )));
    }
    let snapshot = Snapshot::build(revision, parsed.objects)
        .map_err(|error| ControllerError::Registry(error.to_string()))?;
    snapshot
        .verify()
        .map_err(|error| ControllerError::Registry(error.to_string()))?;
    Ok(Arc::new(snapshot))
}

/// Disabled nodes are treated as absent.
pub(super) fn node_exists(snapshot: &Snapshot, node: &str) -> bool {
    snapshot.objects.iter().any(|object| {
        object.id == node
            && matches!(&object.config, odin_registry::ObjectConfig::Node(value) if value.enabled)
    })
}
