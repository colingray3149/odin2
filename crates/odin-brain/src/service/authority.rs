//! Exact source and index authority: pinning composed sources per serving
//! operation and the wired-source-set
//! validation against the resolved knowledge policy.

use std::collections::BTreeMap;

use odin_atlas::AtlasScope;
use odin_domain::knowledge::AtlasId;
use odin_domain::Digest;

use crate::archive::ArchiveStore;
use crate::error::{BrainError, BrainResult};
use crate::source;

use super::BrainSourceConfig;

/// One composed knowledge source: an immutable Atlas root, a loopback
/// SilverBullet vault, a seat's memory vault, a state projection, or a
/// governed archive export, pinned to its authority per serving operation.
pub(super) enum KnowledgeSource {
    Atlas(source::atlas::AtlasSource),
    Vault(source::silverbullet::SilverBulletSource),
    /// One seat's reserved memory namespace: the same confined vault
    /// source class, distinguished so the serving side can address the
    /// seat's memory source exactly (startup memory brief, post-write
    /// refresh) without widening any other vault's scope.
    Memory(source::silverbullet::SilverBulletSource),
    Registry(source::state::registry::RegistrySource),
    Live(source::state::live::LiveSource),
    Tasks(source::state::tasks::TasksSource),
    Repos(source::state::repos::ReposSource),
    History(source::ops::HistorySource),
    /// An archive source holds no live handle: its servable state is the
    /// persisted approved revision in the archive store, and pin time reads
    /// nothing from the raw export.
    Archive {
        id: AtlasId,
    },
    /// A source declared `APL_RESTRICTED`/`SECRET`: nothing is read; it pins
    /// one refusal item.
    Withheld {
        id: AtlasId,
        class: odin_domain::knowledge::PrivacyClass,
    },
}

/// One pinned source revision with its exact projected items.
#[derive(Clone)]
pub(super) struct PinnedSource {
    pub(super) id: AtlasId,
    pub(super) revision: Digest,
    /// Archive sources pin the publication's EXACT generation: serving
    /// never resolves by (source, revision) timestamp, so an unpublished
    /// restamp twin can never win the pin. `Some` marks exactly the archive
    /// class — the raw export is never read at pin time and archive items
    /// are empty because the served chunks come from the published
    /// generation.
    pub(super) generation: Option<odin_domain::knowledge::ids::IndexGenerationId>,
    pub(super) items: Vec<source::SourceItem>,
}

impl KnowledgeSource {
    /// Whether the state rebuild pump owns this source's builds.
    pub(super) fn is_state(&self) -> bool {
        matches!(
            self,
            Self::Registry(_) | Self::Live(_) | Self::Tasks(_) | Self::Repos(_) | Self::History(_)
        )
    }

    /// Pins the source's live revision and projects its exact items. Atlas
    /// items carry node provenance; vault pages are observed content without
    /// node identity; archive sources pin the persisted approved revision
    /// and carry no items — serving reads the published generation.
    pub(super) fn pin(&self, archives: Option<&ArchiveStore>) -> BrainResult<Option<PinnedSource>> {
        match self {
            Self::Atlas(atlas) => {
                let pinned = atlas.pin()?;
                let revision = pinned.revision();
                Ok(Some(PinnedSource {
                    id: atlas.atlas_id().clone(),
                    revision,
                    generation: None,
                    items: pinned.items(&AtlasScope::all())?,
                }))
            }
            Self::Vault(vault) | Self::Memory(vault) => {
                // The scoped pin is the only vault pin: eligible names are
                // admitted from the listing before any content read, and
                // read_page refuses out-of-scope names itself — excluded
                // segments cannot enter the pin even through the explicit
                // page primitives.
                let pinned = vault.pin_scoped()?;
                let revision = pinned.revision();
                let id = pinned.atlas_id().clone();
                Ok(Some(PinnedSource {
                    id,
                    revision,
                    generation: None,
                    items: pinned.items()?,
                }))
            }
            Self::Registry(source) => {
                let (revision, items) = source.pin()?;
                Ok(Some(PinnedSource {
                    id: source.atlas_id().clone(),
                    revision,
                    generation: None,
                    items,
                }))
            }
            Self::Live(source) => {
                let (revision, items) = source.pin()?;
                Ok(Some(PinnedSource {
                    id: source.atlas_id().clone(),
                    revision,
                    generation: None,
                    items,
                }))
            }
            Self::Tasks(source) => {
                let (revision, items) = source.pin()?;
                Ok(Some(PinnedSource {
                    id: source.atlas_id().clone(),
                    revision,
                    generation: None,
                    items,
                }))
            }
            Self::Repos(source) => {
                let (revision, items) = source.pin()?;
                Ok(Some(PinnedSource {
                    id: source.atlas_id().clone(),
                    revision,
                    generation: None,
                    items,
                }))
            }
            Self::History(source) => {
                let (revision, items) = source.pin()?;
                Ok(Some(PinnedSource {
                    id: source.atlas_id().clone(),
                    revision,
                    generation: None,
                    items,
                }))
            }
            Self::Withheld { id, class } => {
                let refusal = odin_domain::knowledge::PrivacyRefusal {
                    class: *class,
                    subject: format!("knowledge source {}", id.as_str()),
                };
                let mut material = b"odin-brain:withheld-source:v1\x00".to_vec();
                material.extend_from_slice(id.as_str().as_bytes());
                material.push(0);
                material.extend_from_slice(class.protocol_name().as_bytes());
                let revision = Digest::hash(&material);
                let item = source::SourceItem::new(
                    id.clone(),
                    revision,
                    b"withheld",
                    odin_domain::knowledge::TrustClass::Observed,
                    refusal.sentence(),
                )?;
                Ok(Some(PinnedSource {
                    id: id.clone(),
                    revision,
                    generation: None,
                    items: vec![item],
                }))
            }
            Self::Archive { id } => {
                // Only a published, approved revision ever pins; an archive
                // source that was never ingested contributes nothing, so a
                // wired-but-unapproved source degrades no other source's
                // retrieval. There is no auto-ingest at pin time: nothing
                // here reads the raw export.
                let Some(published) = archives
                    .map(|store| store.publication(id))
                    .transpose()?
                    .flatten()
                else {
                    return Ok(None);
                };
                Ok(Some(PinnedSource {
                    id: id.clone(),
                    revision: published.revision,
                    generation: Some(published.generation_id),
                    items: Vec::new(),
                }))
            }
        }
    }
}

/// Pins every composed source, sorted by source identity. A source that
/// cannot be pinned (unreadable root, vault unreachable) is explicit
/// operation unavailability — never a partial, silently reduced pool.
pub(super) fn pin_all(
    sources: &BTreeMap<AtlasId, KnowledgeSource>,
    archives: Option<&ArchiveStore>,
) -> BrainResult<Vec<PinnedSource>> {
    let mut pinned = Vec::with_capacity(sources.len());
    for source in sources.values() {
        if let Some(pinned_source) = source.pin(archives)? {
            pinned.push(pinned_source);
        }
    }
    pinned.sort_by(|left, right| left.id.cmp(&right.id));
    Ok(pinned)
}

/// Validate immutable Atlas sources at open; live vault availability is
/// checked on each serving operation instead.
pub(super) fn pin_atlas(
    sources: &BTreeMap<AtlasId, KnowledgeSource>,
) -> BrainResult<Vec<PinnedSource>> {
    let mut pinned = Vec::new();
    for source in sources.values() {
        if matches!(source, KnowledgeSource::Atlas(_)) {
            if let Some(pinned_source) = source.pin(None)? {
                pinned.push(pinned_source);
            }
        }
    }
    pinned.sort_by(|left, right| left.id.cmp(&right.id));
    Ok(pinned)
}

/// The wired source set must equal the knowledge policy's authorized set
/// exactly. A wired source outside the policy would exceed the delegation;
/// an authorized source without a wired binding is a missing declared
/// source — invalid composition, refused at the boundary, and distinct
/// from runtime unavailability (a wired vault that is down stays
/// typed-unavailable per serving operation). Both sides are sorted by
/// source identity, so equality is a length check plus one sorted walk.
/// An absent knowledge policy composes no serving surface and therefore
/// accepts no wired sources at all.
pub(super) fn validate_source_set(
    knowledge: Option<&odin_domain::knowledge::EffectiveKnowledgePolicy>,
    sources: &BTreeMap<AtlasId, BrainSourceConfig>,
) -> BrainResult<()> {
    let Some(knowledge) = knowledge else {
        if sources.is_empty() {
            return Ok(());
        }
        let wired = sources
            .keys()
            .map(|id| id.to_string())
            .collect::<Vec<_>>()
            .join(", ");
        return Err(BrainError::InvalidPolicy(format!(
            "no knowledge policy is resolved, so no source may be wired; \
             wired sources: [{wired}]"
        )));
    };
    let authorized = &knowledge.atlas_sources;
    if authorized.len() == sources.len()
        && authorized
            .iter()
            .zip(sources.keys())
            .all(|(authorized_id, wired_id)| authorized_id == wired_id)
    {
        return Ok(());
    }
    let missing = authorized
        .iter()
        .filter(|authorized_id| !sources.contains_key(*authorized_id))
        .map(|id| id.to_string())
        .collect::<Vec<_>>()
        .join(", ");
    let extra = sources
        .keys()
        .filter(|wired_id| !authorized.contains(*wired_id))
        .map(|id| id.to_string())
        .collect::<Vec<_>>()
        .join(", ");
    Err(BrainError::InvalidPolicy(format!(
        "the wired source set must equal the knowledge policy's authorized \
         source set exactly; authorized but unwired: [{missing}]; \
         wired but unauthorized: [{extra}]"
    )))
}

#[cfg(test)]
mod privacy_tests {
    use super::*;
    use odin_domain::knowledge::PrivacyClass;

    #[test]
    fn a_withheld_source_pins_one_refusal_item_and_reads_nothing() {
        let id = AtlasId::new("atlas.apl").unwrap();
        let source = KnowledgeSource::Withheld {
            id: id.clone(),
            class: PrivacyClass::AplRestricted,
        };
        let pinned = source.pin(None).unwrap().expect("withheld sources pin");
        assert_eq!(pinned.id, id);
        assert_eq!(pinned.items.len(), 1);
        assert!(pinned.items[0]
            .text
            .contains("\"knowledge source atlas.apl\" is marked APL_RESTRICTED"));
        // Deterministic revision: the same declaration reuses its generation.
        let again = source.pin(None).unwrap().unwrap();
        assert_eq!(again.revision, pinned.revision);
    }
}
