/// Per-item source provenance recorded at index build time.
///
/// For Atlas items this names the exact node the item was projected from, so
/// `brain://` scope enforcement can prove the node lies inside an operator's
/// allowed [`AtlasScope`](odin_atlas::AtlasScope). Absent for sources without
/// Atlas node identity (e.g. SilverBullet pages, which are confined by page
/// allowlists at the source layer instead).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ItemProvenance {
    /// Exact Atlas node identifier (e.g. `crate:demo:fn:add_one`).
    pub node_id: String,
    /// Repository-relative source path the node was parsed from.
    pub path: String,
    /// Atlas source class the node belongs to.
    pub source_class: odin_atlas::SourceClass,
    /// Scope tags declared on the node (empty when untagged).
    pub scope_tags: Vec<String>,
}
