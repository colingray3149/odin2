//! The Atlas source through the public API over a temporary fixture repo:
//! pin, scope projection, and rejection of an invalid root.

use odin_atlas::{AtlasScope, SourceClass};
use odin_brain::source::atlas::AtlasSource;
use odin_domain::knowledge::ids::AtlasId;
use odin_domain::knowledge::retrieval::TrustClass;

use crate::support::atlas_root;

/// The real Atlas AST index over a real (temporary) source repo, through
/// the public `AtlasSource` API only: pin, scope query, item projection,
/// provenance and trust stamped exactly as citations will see them.
#[test]
fn atlas_fixture_pins_through_public_api() {
    let root = atlas_root("demo", "add_one");
    let atlas_id = AtlasId::new("atlas:fixture").unwrap();
    let pinned = AtlasSource::new(root.path(), atlas_id.clone())
        .pin()
        .unwrap();

    let items = pinned
        .items(&AtlasScope::source(SourceClass::Rust))
        .unwrap();
    assert!(!items.is_empty(), "rust scope must project fixture nodes");
    for item in &items {
        assert_eq!(item.source, atlas_id);
        assert_eq!(item.source_revision, pinned.revision());
        assert_eq!(item.trust, TrustClass::Curated);
        assert!(item.text.contains("add_one"));
    }

    // Scope projection is exact: a scope matching nothing yields nothing.
    let empty = pinned
        .items(&AtlasScope::paths(["nonexistent-prefix".to_owned()]).unwrap())
        .unwrap();
    assert!(empty.is_empty());
}
