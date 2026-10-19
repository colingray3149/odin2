//! Atlas narrowing invariants: narrowing can only shrink the allowed scope.

use super::*;

#[test]
fn atlas_queries_only_narrow_allowed_scope() {
    let router = test_router(seeded_ledger(), artifact_root("atlas-narrowing"));
    let global = UriContext::new(Scope::default());

    let one_node = AtlasNarrowing {
        node_prefixes: vec!["odin:alpha:one".to_owned()],
        ..AtlasNarrowing::default()
    };
    let narrowed = router
        .resolve_atlas(&global, "atlas://", &one_node)
        .unwrap();
    let narrowed_nodes = spot_json(&narrowed)["nodes"].as_array().unwrap();
    assert_eq!(narrowed_nodes.len(), 1);
    assert_eq!(narrowed_nodes[0]["id"], json!("odin:alpha:one"));

    let outside_path = AtlasNarrowing {
        path_prefixes: vec!["crates/beta".to_owned()],
        ..AtlasNarrowing::default()
    };
    assert!(matches!(
        router.resolve_atlas(&global, "atlas://", &outside_path),
        Err(UriError::ScopeDenied { .. })
    ));
    let outside_class = AtlasNarrowing {
        source_classes: BTreeSet::from([SourceClass::Registry]),
        ..AtlasNarrowing::default()
    };
    assert!(matches!(
        router.resolve_atlas(&global, "atlas://", &outside_class),
        Err(UriError::ScopeDenied { .. })
    ));
    let traversal_prefix = AtlasNarrowing {
        path_prefixes: vec!["crates/../beta".to_owned()],
        ..AtlasNarrowing::default()
    };
    assert!(matches!(
        router.resolve_atlas(&global, "atlas://", &traversal_prefix),
        Err(UriError::TraversalRejected { .. })
    ));
}
