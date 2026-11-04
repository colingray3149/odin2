use odin_registry::Snapshot;

/// Disabled nodes are treated as absent.
pub(super) fn node_exists(snapshot: &Snapshot, node: &str) -> bool {
    snapshot.objects.iter().any(|object| {
        object.id == node
            && matches!(&object.config, odin_registry::ObjectConfig::Node(value) if value.enabled)
    })
}
