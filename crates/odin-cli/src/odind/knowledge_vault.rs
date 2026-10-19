//! Generated knowledge is a presentation of the existing brain projections.
//! The vault singleton owns every write; no additional store or source exists.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use odin_brain::error::{BrainError, BrainResult};
use odin_brain::service::{BrainService, KnowledgeProjectionSink};
use odin_brain::source::silverbullet::RESERVED_KNOWLEDGE_SEGMENT;
use odin_domain::knowledge::AtlasId;
use odin_domain::{Digest, SeatId};
use odin_hermes::vault::{VaultBridge, VaultWriteGeneratedInput};

/// Each seat can project a different authorized view of the same source.
/// A stable seat subtree keeps those views from overwriting each other.
struct VaultProjectionSink {
    vault: VaultBridge,
    seat: SeatId,
}

impl VaultProjectionSink {
    fn prefix(&self, source: &AtlasId) -> String {
        format!(
            "{}/{RESERVED_KNOWLEDGE_SEGMENT}/{source}/{}/",
            self.vault.config().generated_namespace,
            self.seat,
        )
    }
}

impl VaultProjectionSink {
    fn write(&self, page_name: String, content: &str) -> BrainResult<()> {
        self.vault
            .write_generated(&VaultWriteGeneratedInput {
                page_name,
                content: content.to_owned(),
            })
            .map(|_| ())
            .map_err(|error| BrainError::Unavailable {
                component: "knowledge_projection",
                reason: error.to_string(),
            })
    }
}

impl KnowledgeProjectionSink for VaultProjectionSink {
    fn max_page_bytes(&self) -> usize {
        self.vault.config().max_page_bytes as usize
    }

    fn write_page(&self, source: &AtlasId, relative_page: &str, content: &str) -> BrainResult<()> {
        self.write(format!("{}{relative_page}", self.prefix(source)), content)
    }

    fn write_shared_page(
        &self,
        source: &AtlasId,
        relative_page: &str,
        content: &str,
    ) -> BrainResult<()> {
        // Seat-independent bytes: every seat with the view writes the same
        // page, and the vault skips the identical rewrites.
        self.write(
            format!(
                "{}/{RESERVED_KNOWLEDGE_SEGMENT}/{source}/{relative_page}",
                self.vault.config().generated_namespace,
            ),
            content,
        )
    }

    fn stored_pages(&self, source: &AtlasId) -> BrainResult<Vec<String>> {
        let prefix = self.prefix(source);
        Ok(self
            .vault
            .generated_page_names()?
            .into_iter()
            .filter_map(|page| page.strip_prefix(&prefix).map(str::to_owned))
            .collect())
    }

    fn remove_page(
        &self,
        source: &AtlasId,
        relative_page: &str,
        _superseded_by: &Digest,
    ) -> BrainResult<()> {
        // Delete through the confined knowledge-tree remover to avoid persistent stale listings.
        let page_name = format!("{}{relative_page}", self.prefix(source));
        self.vault
            .remove_generated_knowledge(&page_name)
            .map_err(|error| BrainError::Unavailable {
                component: "knowledge_projection",
                reason: error.to_string(),
            })
    }
}

/// Remove orphan seat trees and shared pages absent from every live projected view.
/// Per-seat retirement only covers that seat's subtree. Returns the removal count.
pub(super) fn prune_knowledge_tree(
    vault: &VaultBridge,
    views: &BTreeMap<SeatId, BTreeMap<AtlasId, BTreeSet<String>>>,
) -> BrainResult<usize> {
    let mut seat_views: BTreeSet<(&str, &str)> = BTreeSet::new();
    let mut shared: BTreeSet<(&str, &str)> = BTreeSet::new();
    for (seat, sources) in views {
        for (source, pages) in sources {
            seat_views.insert((source.as_str(), seat.as_str()));
            shared.extend(pages.iter().map(|page| (source.as_str(), page.as_str())));
        }
    }
    let tree = format!(
        "{}/{RESERVED_KNOWLEDGE_SEGMENT}/",
        vault.config().generated_namespace
    );
    let mut removed = 0;
    for page in vault.generated_page_names()? {
        let Some(rest) = page.strip_prefix(&tree) else {
            continue;
        };
        // Atlas ids carry no '/', so the source is always the first segment.
        let segments: Vec<&str> = rest.split('/').collect();
        let live = match segments.as_slice() {
            [source, name] => shared.contains(&(*source, *name)),
            [source, seat, _, ..] => seat_views.contains(&(*source, *seat)),
            _ => true,
        };
        if live {
            continue;
        }
        vault
            .remove_generated_knowledge(&page)
            .map_err(|error| BrainError::Unavailable {
                component: "knowledge_projection",
                reason: error.to_string(),
            })?;
        removed += 1;
    }
    Ok(removed)
}

pub(super) fn attach(brain: &BrainService, seat: &SeatId, vault: &VaultBridge) -> BrainResult<()> {
    brain.set_projection_sink(Arc::new(VaultProjectionSink {
        vault: vault.clone(),
        seat: seat.clone(),
    }))
}

#[cfg(test)]
#[path = "tests/knowledge_vault.rs"]
mod tests;
