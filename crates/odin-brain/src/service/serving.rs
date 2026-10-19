//! Index serving: one exact generation per composed source, rebuilt only
//! from the pinned revision, plus the live serving state and immutable
//! item resolution.

use std::collections::{BTreeMap, BTreeSet};

use odin_domain::knowledge::{IndexGeneration, KnowledgeItemId};
use odin_domain::ProjectId;

use crate::audit::{BrainAuditEvent, AUDIT_KIND_INDEX_REBUILT};
use crate::error::{BrainError, BrainResult};
use crate::index;

use super::authority::pin_all;
use super::{BrainService, BrainStatus, KnowledgeItem};

impl BrainService {
    /// Item ownership is source truth, narrowed by the published seat and
    /// the caller's bound project. Projectless reads never inherit ownership.
    pub(super) fn item_visible(
        &self,
        item: &crate::source::SourceItem,
        project: Option<&ProjectId>,
    ) -> bool {
        item.project.as_ref().is_none_or(|owner| {
            project == Some(owner) && self.policy.project_memory.contains_key(owner)
        })
    }

    /// Serves one generation per composed source, rebuilding any source whose
    /// head moved past its stored generation. Index only: the turn path never
    /// writes vault pages (the state pump and post-write refresh project).
    pub fn ensure_generation(&self) -> BrainResult<Vec<IndexGeneration>> {
        self.build_generations(&pin_all(&self.sources, self.archives.as_ref())?)
    }

    /// Refreshes exactly one composed source: pins its live head and
    /// returns — building only if the head moved — the generation covering
    /// it. The post-write surface calls this after a durable generated
    /// write so the seat's own memory source serves the new page without
    /// rebuilding unrelated sources. An unknown source id refuses: a
    /// caller may never cause a build for a source this service does not
    /// serve.
    pub fn ensure_source_generation(
        &self,
        source_id: &odin_domain::knowledge::AtlasId,
    ) -> BrainResult<Vec<IndexGeneration>> {
        let source = self.sources.get(source_id).ok_or_else(|| {
            BrainError::InvalidRequest(format!(
                "source {source_id} is not a composed source of this service"
            ))
        })?;
        // An unpublished archive has no generation to build.
        let Some(pinned) = source.pin(self.archives.as_ref())? else {
            return Ok(Vec::new());
        };
        self.build_and_project(std::slice::from_ref(&pinned))
    }

    /// Refreshes control-plane projections without reading unrelated vaults
    /// or rebuilding Atlas during a high-frequency runtime state event.
    pub fn ensure_state_generations(&self) -> BrainResult<Vec<IndexGeneration>> {
        let pinned = self
            .sources
            .values()
            .filter(|source| source.is_state())
            .filter_map(|source| source.pin(self.archives.as_ref()).transpose())
            .collect::<BrainResult<Vec<_>>>()?;
        self.build_and_project(&pinned)
    }

    /// Projects pages off the turn path so vault writes cannot delay a response.
    fn build_and_project(
        &self,
        pinned_sources: &[super::authority::PinnedSource],
    ) -> BrainResult<Vec<IndexGeneration>> {
        let generations = self.build_generations(pinned_sources)?;
        // A sink or vault failure propagates after the generation is
        // durable; the next pass retries the idempotent emission.
        self.project_generated(pinned_sources)?;
        Ok(generations)
    }

    pub(super) fn build_generations(
        &self,
        pinned_sources: &[super::authority::PinnedSource],
    ) -> BrainResult<Vec<IndexGeneration>> {
        let knowledge = self
            .policy
            .knowledge
            .as_ref()
            .ok_or_else(|| BrainError::Unavailable {
                component: "knowledge_policy",
                reason: "index builds require a resolved knowledge policy".to_owned(),
            })?;
        let chunker =
            index::build::Chunker::new(knowledge.chunk_tokens, knowledge.chunk_overlap_tokens)?;
        let mut generations = BTreeMap::new();
        for pinned in pinned_sources {
            if let Some(generation_id) = &pinned.generation {
                // Archive sources pin the publication's EXACT generation
                // (never a newest-by-timestamp lookup: an unpublished
                // restamp twin must not win) and never rebuild from items
                // (there are none). A missing generation means the
                // publication points at nothing — corruption, never a
                // silent empty rebuild that would shadow approved memory.
                let existing = self
                    .index
                    .load_pinned(generation_id, &pinned.id, &pinned.revision)
                    .map_err(|error| match error {
                        BrainError::NotFound { .. } => BrainError::Corrupt {
                            component: "brain-index-store",
                            reason: format!(
                                "archive source {} publishes revision {} but its generation {} is missing",
                                pinned.id.as_str(),
                                pinned.revision,
                                generation_id
                            ),
                        },
                        other => other,
                    })?;
                generations.insert(pinned.id.clone(), existing);
                continue;
            }
            if let Some(existing) = self.index.current_for_model(
                &pinned.id,
                &pinned.revision,
                self.config.embedding_model.as_ref(),
            )? {
                generations.insert(pinned.id.clone(), existing);
                continue;
            }
            let build = match self.config.embedding_model.as_ref() {
                Some(model) => index::build::build_index_with_embedding_model(
                    pinned.id.clone(),
                    pinned.revision,
                    &pinned.items,
                    &chunker,
                    model.clone(),
                )?,
                None => index::build::build_index(
                    pinned.id.clone(),
                    pinned.revision,
                    &pinned.items,
                    &chunker,
                )?,
            };
            let created_epoch = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_err(|_| {
                    BrainError::InvalidRequest("index clock before the Unix epoch".to_owned())
                })?
                .as_secs();
            self.index.store(&build, created_epoch)?;
            self.audit.record(BrainAuditEvent {
                kind: AUDIT_KIND_INDEX_REBUILT,
                actor: odin_domain::Actor::System {
                    name: "odin-brain".to_owned(),
                },
                scope: odin_domain::Scope::default(),
                payload: serde_json::json!({
                    "generationId": build.generation.generation_id.to_string(),
                    "atlasId": pinned.id.as_str(),
                    "atlasRevision": pinned.revision.to_string(),
                    "chunkerVersion": build.generation.chunker_version,
                    "embeddingModel": build.generation.embedding_model.as_str(),
                    "chunks": build.chunks.len(),
                }),
                evidence: Vec::new(),
                binding: Some(self.policy.policy_digest),
            })?;
            generations.insert(pinned.id.clone(), build.generation);
        }
        Ok(generations.into_values().collect())
    }

    /// The current serving state against the live pinned heads.
    pub fn status(&self) -> BrainResult<BrainStatus> {
        let mut pinned = BTreeMap::new();
        let mut generations = BTreeMap::new();
        for source in pin_all(&self.sources, self.archives.as_ref())? {
            match &source.generation {
                Some(generation_id) => {
                    let generation =
                        self.index
                            .load_pinned(generation_id, &source.id, &source.revision)?;
                    generations.insert(source.id.clone(), generation);
                }
                None => {
                    if let Some(generation) = self.index.current_for_model(
                        &source.id,
                        &source.revision,
                        self.config.embedding_model.as_ref(),
                    )? {
                        generations.insert(source.id.clone(), generation);
                    }
                }
            }
            pinned.insert(source.id, source.revision);
        }
        Ok(BrainStatus {
            policy_digest: self.policy.policy_digest,
            registry_revision: self.policy.registry_revision,
            pinned,
            generations,
        })
    }

    /// Serves one immutable knowledge item from the generation pinned to the
    /// live head of the source that holds it. A stale generation is rejected,
    /// never served.
    ///
    /// `project` is the caller's bound project, declared — never inferred.
    /// The item is resolved only against the project's serving scope: a
    /// source carrying project memory that the project does not declare is
    /// a typed miss for that caller, exactly as if it did not exist, and a
    /// projectless caller resolves general knowledge only. Published
    /// archive sources carry no per-item visibility (their items are the
    /// published generation's chunks), so inside the serving scope they
    /// resolve from that exact generation — the same exemption the
    /// retrieval chunk filter applies.
    pub fn knowledge_item(
        &self,
        item_id: &KnowledgeItemId,
        project: Option<&ProjectId>,
    ) -> BrainResult<KnowledgeItem> {
        if self.policy.knowledge.is_none() {
            return Err(BrainError::Unavailable {
                component: "knowledge_policy",
                reason: "the resolved policy does not enable knowledge retrieval".to_owned(),
            });
        }
        let serving_scope = self.policy.project_serving_scope(project);
        for pinned in pin_all(&self.sources, self.archives.as_ref())? {
            if !serving_scope.contains(&pinned.id) {
                continue;
            }
            // Archive pins have no live items; serve_item checks the published generation instead.
            if pinned.generation.is_none()
                && !pinned
                    .items
                    .iter()
                    .any(|item| &item.item_id == item_id && self.item_visible(item, project))
            {
                continue;
            }
            if let Some(item) = self.serve_item(&pinned, item_id)? {
                return Ok(item);
            }
        }
        Err(BrainError::NotFound {
            kind: "knowledge item",
            id: item_id.to_string(),
        })
    }

    /// Serves the published archive record addressed by its content-addressed
    /// `record_key`: the record is looked up in the CURRENT published
    /// revision of every in-scope pinned archive source, and its item is
    /// served through the exact same pinned-generation path as
    /// [`BrainService::knowledge_item`] — same serving scope, same stale
    /// generation discipline, same archive citation. The returned item id is
    /// the record row's own stored identity, never inferred from chunks; an
    /// unknown key is a typed miss for exactly the record asked for, never
    /// a fuzzy fallback.
    pub fn knowledge_record(
        &self,
        record_key: &odin_domain::Digest,
        project: Option<&ProjectId>,
    ) -> BrainResult<super::KnowledgeRecord> {
        if self.policy.knowledge.is_none() {
            return Err(BrainError::Unavailable {
                component: "knowledge_policy",
                reason: "the resolved policy does not enable knowledge retrieval".to_owned(),
            });
        }
        let serving_scope = self.policy.project_serving_scope(project);
        let Some(store) = self.archives.as_ref() else {
            return Err(BrainError::NotFound {
                kind: "knowledge record",
                id: record_key.to_string(),
            });
        };
        for pinned in pin_all(&self.sources, self.archives.as_ref())? {
            if !serving_scope.contains(&pinned.id) {
                continue;
            }
            // Record selectors exist only for published archive sources: an
            // exact published generation is the record key's authority.
            let Some(generation_id) = &pinned.generation else {
                continue;
            };
            // A stale pinned generation is a typed miss for this record,
            // exactly as for an item; every other load failure propagates.
            match self
                .index
                .load_pinned(generation_id, &pinned.id, &pinned.revision)
            {
                Ok(_) => {}
                Err(BrainError::StaleAuthority { .. }) => continue,
                Err(error) => return Err(error),
            }
            let Some(item_id) = store.item_for_record(&pinned.id, &pinned.revision, record_key)?
            else {
                continue;
            };
            let item = self
                .serve_item(&pinned, &item_id)?
                .ok_or_else(|| BrainError::Corrupt {
                    component: "archive_store",
                    reason: format!(
                        "source {} publishes record {} as item {} but the pinned \
                         generation does not contain that item",
                        pinned.id.as_str(),
                        record_key,
                        item_id
                    ),
                })?;
            return Ok(super::KnowledgeRecord { item_id, item });
        }
        Err(BrainError::NotFound {
            kind: "knowledge record",
            id: record_key.to_string(),
        })
    }

    /// Serves one item from one pinned source's current generation:
    /// `Ok(None)` is an exact miss (the generation does not contain the
    /// item, or its pinned generation is stale authority), so callers keep
    /// scanning their own source list. This is the single item-serving path
    /// for both item-id and record-key resolution.
    pub(super) fn serve_item(
        &self,
        pinned: &super::authority::PinnedSource,
        item_id: &KnowledgeItemId,
    ) -> BrainResult<Option<KnowledgeItem>> {
        let generation = match &pinned.generation {
            // Stale or absent pinned generations are a typed miss for
            // this item, exactly as before; archive citations resolve
            // only from the exact published generation.
            Some(generation_id) => {
                match self
                    .index
                    .load_pinned(generation_id, &pinned.id, &pinned.revision)
                {
                    Ok(generation) => generation,
                    Err(BrainError::StaleAuthority { .. }) => return Ok(None),
                    Err(error) => return Err(error),
                }
            }
            None => {
                let Some(generation) = self.serving_generation(pinned)? else {
                    return Ok(None);
                };
                generation
            }
        };
        // A generation another seat's store built and sealed has no rows in
        // this store's SQLite file: read the item through the sealed-aware path.
        let ordinals = self
            .index
            .ordinals_for_items(&generation.generation_id, &BTreeSet::from([*item_id]))?;
        if ordinals.is_empty() {
            return Ok(None);
        }
        let item_chunks = self.index.chunks_at(&generation.generation_id, &ordinals)?;
        // `None` is exact for sources without Atlas node identity; a
        // missing provenance row for an item that has chunks is store
        // corruption and propagates typed from the index store.
        let provenance = self.index.provenance(&generation.generation_id, item_id)?;
        // Archive items carry their structured export provenance, when
        // this item is one of the published revision's records.
        let archive = match &pinned.generation {
            Some(_) => self.archive_citation(&pinned.id, &pinned.revision, item_id)?,
            None => None,
        };
        Ok(Some(KnowledgeItem {
            generation,
            provenance,
            chunks: item_chunks,
            archive,
        }))
    }
}
