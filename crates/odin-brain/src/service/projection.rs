//! Generated-knowledge projection with a once-set sink and publication lock.
//!
//! Emission happens on the existing generation path — after a fresh build or
//! the first sighting of a (source, revision) pair on a cache hit — so
//! startup renders without a separate pump and head movement replaces pages.
//! All emission runs under one per-service publication lock that also
//! re-pins the source (the freshness fence): a concurrent older pin can
//! never overwrite a newer page, because whichever emitter holds the lock
//! projects the pin that is freshest at emit time. The sink is the source of
//! truth for what currently exists under a source's subtree; its listing
//! failures propagate so a stale tail can never be silently left behind
//! across restarts. The sink MUST NOT call back into this service
//! synchronously: the publication lock is not reentrant.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use odin_domain::knowledge::AtlasId;
use odin_domain::Digest;

use crate::error::{BrainError, BrainResult};
use crate::projection::{self, KnowledgeProjectionSink};

use super::authority::{KnowledgeSource, PinnedSource};
use super::BrainService;

/// Publication state: the last emitted revision per source. Guarded by the
/// service's publication mutex, which serializes every pin-fenced render and
/// emit.
#[derive(Default)]
pub(super) struct PublicationState {
    pub(super) emitted: BTreeMap<AtlasId, Digest>,
}

impl BrainService {
    /// Wires the one knowledge projection sink: called once by the daemon
    /// after factory composition, before the first ensure. A second set is
    /// refused — the projection surface is composed, not swapped at runtime.
    pub fn set_projection_sink(&self, sink: Arc<dyn KnowledgeProjectionSink>) -> BrainResult<()> {
        self.projection_sink.set(sink).map_err(|_| {
            BrainError::InvalidPolicy(
                "a knowledge projection sink is already wired for this service".to_owned(),
            )
        })
    }

    /// What this seat's service projects into generated knowledge: each
    /// projected source with the shared pages it owns (state.repos: one
    /// `<project>.md` per project in the seat's view; empty for sources
    /// that only write the seat subtree). The daemon unions these over all
    /// seats to prune views nobody projects any more.
    pub fn projected_views(&self) -> BTreeMap<AtlasId, BTreeSet<String>> {
        self.sources
            .iter()
            .filter(|(_, source)| projects(source))
            .map(|(id, source)| {
                let shared = match source {
                    KnowledgeSource::Repos(repos) => repos
                        .projects()
                        .keys()
                        .map(|project| format!("{project}.md"))
                        .collect(),
                    _ => BTreeSet::new(),
                };
                (id.clone(), shared)
            })
            .collect()
    }

    /// Emits pending projections for the given pinned sources: the first
    /// emission per (source, revision) per process. Sink and vault failures
    /// propagate typed; emission is idempotent (full-replace writes plus
    /// stale-tail retirement), so the next ensure retries cleanly.
    pub(super) fn project_generated(&self, pinned: &[PinnedSource]) -> BrainResult<()> {
        let Some(sink) = self.projection_sink.get() else {
            return Ok(());
        };
        for source in pinned {
            let Some(composed) = self.sources.get(&source.id) else {
                continue;
            };
            if !projects(composed) {
                continue;
            }
            self.project_one(sink, composed, &source.id)?;
        }
        Ok(())
    }

    /// One source's emission under the publication lock: re-pin (freshness
    /// fence), dedup per revision, render with the sink's page bound, write
    /// the current page set in order, then retire exactly the stale tail
    /// (stored minus current). A head that moved during the build re-projects
    /// the FRESHER pin — the latest event is never silently skipped, and an
    /// older pin can never overwrite a newer page.
    fn project_one(
        &self,
        sink: &Arc<dyn KnowledgeProjectionSink>,
        source: &KnowledgeSource,
        id: &AtlasId,
    ) -> BrainResult<()> {
        let mut state = self
            .projection
            .lock()
            .map_err(|_| BrainError::Unavailable {
                component: "knowledge_projection",
                reason: "publication lock poisoned by a failed emitter".to_owned(),
            })?;
        // An unpublished archive has no projection.
        let Some(fresh) = source.pin(self.archives.as_ref())? else {
            return Ok(());
        };
        if state.emitted.get(id) == Some(&fresh.revision) {
            return Ok(());
        }
        // Repositories project shared per-project summary pages (no seat
        // pages: the seat subtree's stored pages are all stale and retired
        // below); operations history projects one seat page per UTC day;
        // every other source one index page. Graph facts are gated by the
        // composed source VARIANT, never by item text: only the registry
        // carries seat→capability edges and only tasks carry delegation
        // lineage.
        let bound = sink.max_page_bytes();
        let (pages, shared) = match source {
            KnowledgeSource::Repos(_) => (
                Vec::new(),
                projection::render_summary_pages(id, &fresh.revision, &fresh.items, bound)?,
            ),
            KnowledgeSource::History(_) => (
                projection::render_summary_pages(id, &fresh.revision, &fresh.items, bound)?,
                Vec::new(),
            ),
            _ => {
                let kind = match source {
                    KnowledgeSource::Registry(_) => projection::ProjectionKind::Registry,
                    KnowledgeSource::Tasks(_) => projection::ProjectionKind::Tasks,
                    _ => projection::ProjectionKind::Other,
                };
                (
                    vec![projection::render_source_index(
                        id,
                        &fresh.revision,
                        &fresh.items,
                        kind,
                        bound,
                    )?],
                    Vec::new(),
                )
            }
        };
        // The sink's own listing is the retirement oracle: stored names
        // outside the rendered set are stale tails (this run, or left by an
        // interrupted run before this process), retired through the same
        // writer. Listing failures propagate — never a silent fallback.
        let stored = sink.stored_pages(id)?;
        for page in &pages {
            sink.write_page(id, &page.relative_page, &page.content)?;
        }
        for page in &shared {
            sink.write_shared_page(id, &page.relative_page, &page.content)?;
        }
        let current: BTreeSet<&str> = pages
            .iter()
            .map(|page| page.relative_page.as_str())
            .collect();
        let mut stale: Vec<&String> = stored
            .iter()
            .filter(|name| !current.contains(name.as_str()))
            .collect();
        stale.sort();
        for name in stale {
            sink.remove_page(id, name, &fresh.revision)?;
        }
        state.emitted.insert(id.clone(), fresh.revision);
        Ok(())
    }
}

/// Atlas sources exceed page limits; rendering vault or memory sources back
/// into the vault would be circular.
fn projects(source: &KnowledgeSource) -> bool {
    matches!(
        source,
        KnowledgeSource::Registry(_)
            | KnowledgeSource::Live(_)
            | KnowledgeSource::Tasks(_)
            | KnowledgeSource::Repos(_)
            | KnowledgeSource::History(_)
    )
}
