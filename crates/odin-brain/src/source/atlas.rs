//! Pinned Atlas source access for the brain index.
//!
//! The current authority is the `odin-atlas` crate: [`odin_atlas::build`]
//! produces the deterministic `odin.atlas.v1` AST index over four source
//! classes — Rust (parsed with `syn`), TypeScript and TSX (parsed with
//! `tree-sitter`/`tree-sitter-typescript`, not SWC), registry TOML, and
//! skeleton catalogs. This module pins one Atlas revision per index
//! generation, projects [`AtlasScope`] scope queries ([`Subtree`]) into
//! indexable [`SourceItem`]s, and records exact provenance: the Atlas
//! revision digest is the source revision stamped into every citation.
//!
//! Atlas remains the immutable knowledge authority; nothing here mutates or
//! reinterprets it. The index built on top is exact and disposable.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use odin_atlas::{Atlas, AtlasScope, AtlasSources, Subtree};
use odin_domain::knowledge::ids::AtlasId;
use odin_domain::knowledge::retrieval::TrustClass;
use odin_domain::Digest;

use crate::error::{BrainError, BrainResult};
use crate::source::SourceItem;

/// A pinned build of the real Atlas index over one source root.
#[derive(Clone, Debug)]
pub struct AtlasSource {
    root: PathBuf,
    atlas_id: AtlasId,
    /// The last build, keyed by the stat fingerprint of every entry under
    /// the source-class directories: an unchanged tree is never re-parsed.
    memo: Arc<Mutex<Option<(blake3::Hash, PinnedAtlas)>>>,
}

impl AtlasSource {
    /// Targets one repository root; `atlas_id` names the knowledge source in
    /// citations and retrieval queries (e.g. `atlas:odin`).
    pub fn new(root: impl Into<PathBuf>, atlas_id: AtlasId) -> Self {
        Self {
            root: root.into(),
            atlas_id,
            memo: Arc::default(),
        }
    }

    pub const fn atlas_id(&self) -> &AtlasId {
        &self.atlas_id
    }

    /// Builds the real Atlas AST index for the pinned root.
    ///
    /// The root is validated up front ([`validate_root`]: it must be an
    /// existing directory), then Atlas itself fails honestly when the root
    /// is not a valid Atlas source root ([`BrainError::Atlas`]); there is
    /// no text-only substitute.
    ///
    /// The build is memoized under a stat fingerprint taken BEFORE it runs
    /// (path, type, size, inode, mtime and ctime in nanoseconds of every
    /// entry): any write after the fingerprint changes the next one, so a
    /// memo hit is exactly the tree the build read.
    pub fn pin(&self) -> BrainResult<PinnedAtlas> {
        validate_root(&self.root)?;
        let fingerprint = tree_fingerprint(&self.root);
        let mut memo = self.memo.lock().map_err(|_| BrainError::Corrupt {
            component: "atlas",
            reason: "atlas memo mutex is poisoned".to_owned(),
        })?;
        if let Some((key, pinned)) = memo.as_ref() {
            if *key == fingerprint && pinned.atlas_id == self.atlas_id {
                return Ok(pinned.clone());
            }
        }
        let atlas = odin_atlas::build(AtlasSources::new(&self.root))?;
        let revision = atlas_revision(&atlas)?;
        let pinned = PinnedAtlas {
            atlas_id: self.atlas_id.clone(),
            revision,
            atlas: Arc::new(atlas),
        };
        *memo = Some((fingerprint, pinned.clone()));
        Ok(pinned)
    }
}

/// Stat fingerprint of every entry under the Atlas source-class directories
/// (symlinks not followed). Unreadable entries hash their error kind, so
/// they too invalidate the memo when they change.
fn tree_fingerprint(root: &Path) -> blake3::Hash {
    use std::os::unix::fs::MetadataExt;
    let sources = AtlasSources::new(root);
    let mut hasher = blake3::Hasher::new();
    let mut stack: Vec<PathBuf> = [
        &sources.rust,
        &sources.typescript,
        &sources.registry,
        &sources.skeletons,
    ]
    .into_iter()
    .map(|class| root.join(class))
    .collect();
    while let Some(path) = stack.pop() {
        hasher.update(path.as_os_str().as_encoded_bytes());
        hasher.update(&[0]);
        let metadata = match std::fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) => {
                hasher.update(format!("!{:?}", error.kind()).as_bytes());
                continue;
            }
        };
        for field in [
            metadata.mode().into(),
            metadata.len(),
            metadata.ino(),
            metadata.mtime() as u64,
            metadata.mtime_nsec() as u64,
            metadata.ctime() as u64,
            metadata.ctime_nsec() as u64,
        ] {
            hasher.update(&field.to_le_bytes());
        }
        if metadata.is_dir() {
            match std::fs::read_dir(&path) {
                Ok(entries) => {
                    let mut children: Vec<PathBuf> = entries
                        .filter_map(|entry| entry.ok().map(|e| e.path()))
                        .collect();
                    children.sort();
                    stack.extend(children.into_iter().rev());
                }
                Err(error) => {
                    hasher.update(format!("!{:?}", error.kind()).as_bytes());
                }
            }
        }
    }
    hasher.finalize()
}

/// One immutable Atlas revision, pinned for indexing and citation.
#[derive(Clone, Debug)]
pub struct PinnedAtlas {
    atlas_id: AtlasId,
    revision: Digest,
    atlas: Arc<Atlas>,
}

impl PinnedAtlas {
    /// The pinned revision digest (the Atlas generation hash).
    pub const fn revision(&self) -> Digest {
        self.revision
    }

    pub const fn atlas_id(&self) -> &AtlasId {
        &self.atlas_id
    }

    /// The underlying Atlas record (read-only authority view).
    pub fn atlas(&self) -> &Atlas {
        &self.atlas
    }

    /// Runs a real Atlas scope query, producing a subtree projection.
    pub fn subtree(&self, scope: &AtlasScope) -> Subtree {
        self.atlas.query(scope)
    }

    /// Projects the scope subtree into indexable items: one item per Atlas
    /// node, with text composed deterministically from the node's path, kind,
    /// name, signature, and summary. Trust is [`TrustClass::Curated`] —
    /// Atlas nodes derive from authored repository content, not runtime
    /// observation.
    pub fn items(&self, scope: &AtlasScope) -> BrainResult<Vec<SourceItem>> {
        let subtree = self.subtree(scope);
        let mut items = Vec::with_capacity(subtree.nodes.len());
        for node in &subtree.nodes {
            let text = node_text(node);
            if text.trim().is_empty() {
                continue;
            }
            let provenance = crate::index::model::ItemProvenance {
                node_id: node.id.clone(),
                path: node.path.clone(),
                source_class: node.source_class,
                scope_tags: scope_tags(node),
            };
            items.push(
                SourceItem::new(
                    self.atlas_id.clone(),
                    self.revision,
                    node.id.as_bytes(),
                    TrustClass::Curated,
                    text,
                )?
                .with_provenance(provenance),
            );
        }
        items.sort_by_key(|item| item.item_id);
        Ok(items)
    }
}

/// Extracts the node's declared scope tags for provenance.
pub(crate) fn scope_tags(node: &odin_atlas::AtlasNode) -> Vec<String> {
    node.properties
        .get("scope_tags")
        .and_then(|value| value.as_array())
        .map(|tags| {
            tags.iter()
                .filter_map(|tag| tag.as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default()
}

/// Converts the Atlas generation hash into a domain revision digest.
fn atlas_revision(atlas: &Atlas) -> BrainResult<Digest> {
    Digest::parse(&format!("blake3:{}", atlas.generation)).map_err(BrainError::Domain)
}

/// Composes the deterministic indexable text for one Atlas node.
pub(crate) fn node_text(node: &odin_atlas::AtlasNode) -> String {
    let mut text = String::with_capacity(160);
    text.push_str(node.path.as_str());
    text.push('\n');
    text.push_str(node.kind.as_str());
    text.push(':');
    text.push_str(node.name.as_str());
    if let Some(signature) = &node.signature {
        text.push('\n');
        text.push_str(signature);
    }
    if let Some(summary) = &node.summary {
        text.push('\n');
        text.push_str(summary);
    }
    text
}

/// Validates a caller-supplied root before handing it to Atlas.
pub fn validate_root(root: &Path) -> BrainResult<()> {
    if !root.is_dir() {
        return Err(BrainError::InvalidRequest(format!(
            "atlas source root {} is not a directory",
            root.display()
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use odin_atlas::SourceClass;

    fn fixture_root() -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("odin-brain-atlas-fixture-{}", std::process::id()));
        let src = dir.join("crates").join("demo").join("src");
        std::fs::create_dir_all(&src).unwrap();
        // The real odin-atlas root layout: every source-class directory the
        // resolver canonicalizes must exist (crates, extension, registry,
        // skeletons); empty ones simply contribute no nodes.
        std::fs::create_dir_all(dir.join("extension")).unwrap();
        std::fs::create_dir_all(dir.join("registry")).unwrap();
        std::fs::create_dir_all(dir.join("skeletons")).unwrap();
        std::fs::write(
            src.join("lib.rs"),
            "//! Demo crate.\n\n/// Adds one.\npub fn add_one(value: u64) -> u64 { value + 1 }\n",
        )
        .unwrap();
        dir
    }

    #[test]
    fn pins_real_atlas_revision_and_projects_items() {
        let root = fixture_root();
        let source = AtlasSource::new(&root, AtlasId::new("atlas:fixture").unwrap());
        let pinned = source.pin().unwrap();
        let scope = AtlasScope::source(SourceClass::Rust);
        let items = pinned.items(&scope).unwrap();
        assert!(!items.is_empty());
        for item in &items {
            assert_eq!(item.source, AtlasId::new("atlas:fixture").unwrap());
            assert_eq!(item.source_revision, pinned.revision());
            assert_eq!(item.trust, TrustClass::Curated);
            assert!(item.text.contains("add_one"));
        }
        // Scope projection is real: an empty scope matches nothing.
        let empty = pinned
            .items(&AtlasScope::paths(["nonexistent-prefix".to_owned()]).unwrap())
            .unwrap();
        assert!(empty.is_empty());
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn unchanged_tree_reuses_the_build_and_any_change_rebuilds() {
        let root = std::env::temp_dir()
            .join(format!("odin-brain-atlas-memo-{}", std::process::id()))
            .join("memo");
        let src = root.join("crates").join("demo").join("src");
        std::fs::create_dir_all(&src).unwrap();
        for class in ["extension", "registry", "skeletons"] {
            std::fs::create_dir_all(root.join(class)).unwrap();
        }
        std::fs::write(src.join("lib.rs"), "pub fn one() -> u64 { 1 }\n").unwrap();
        let source = AtlasSource::new(&root, AtlasId::new("atlas:fixture").unwrap());
        let first = source.pin().unwrap();
        let again = source.pin().unwrap();
        assert!(
            Arc::ptr_eq(&first.atlas, &again.atlas),
            "unchanged tree was re-parsed"
        );
        std::fs::write(src.join("lib.rs"), "pub fn two() -> u64 { 2 }\n").unwrap();
        let changed = source.pin().unwrap();
        assert_ne!(changed.revision(), first.revision());
        std::fs::write(src.join("extra.rs"), "pub fn three() {}\n").unwrap();
        let added = source.pin().unwrap();
        assert!(
            !Arc::ptr_eq(&added.atlas, &changed.atlas),
            "a new file did not rebuild"
        );
        std::fs::remove_dir_all(root.parent().unwrap()).ok();
    }
}
