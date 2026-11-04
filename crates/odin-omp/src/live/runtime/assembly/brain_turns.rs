//! A session's turn context from its seat's brain: live memory and brain
//! excerpts at each context epoch's start, record cards on every turn.

use std::collections::BTreeSet;
use std::sync::Arc;

use odin_brain::service::BrainService;
use odin_domain::huginn::{LiveError, LiveSessionId};
use odin_domain::{ProjectId, SessionId};

use crate::host_tools::operations::{HostToolOperations, LiveSessionBindings};
use crate::live::context_trace::{self, Block, Kind};
use crate::live::control::BrainTurnContext;

/// The per-session memory source: one seat's composed brain service and the
/// session's bound project. The publication check keeps a session bound to
/// another composition from reading this brain.
pub(super) struct SessionBrainTurns {
    pub(super) brain: Arc<BrainService>,
    pub(super) operations: HostToolOperations,
    pub(super) session_bindings: Arc<LiveSessionBindings>,
    pub(super) session: SessionId,
    pub(super) session_id: LiveSessionId,
    pub(super) project: ProjectId,
    /// The session lane's query embedder: excerpts fuse keyword and meaning
    /// when it serves.
    pub(super) embedder: Option<Arc<odin_brain::retrieval::QueryEmbedder>>,
    pub(super) core_tokens: u32,
    pub(super) prefetch_tokens: u32,
    pub(super) per_turn_tokens: u32,
    pub(super) live_tokens: u32,
    /// The records this context epoch already carries.
    pub(super) named: std::sync::Mutex<BTreeSet<String>>,
    /// Where injected-context traces go; `None` records nothing.
    pub(super) trace_root: Option<std::path::PathBuf>,
}

/// One built block: its text and the record ids it carries.
type Built = (String, Vec<String>);

impl SessionBrainTurns {
    /// One block of the turn's context; a failure is logged with its cause
    /// and leaves the other blocks standing.
    fn block(
        &self,
        part: &str,
        built: Result<Option<Built>, odin_brain::error::BrainError>,
    ) -> Option<Block> {
        built
            .unwrap_or_else(|error| {
                tracing::warn!(
                    "odind: turn context session={} {part} unavailable: {error}",
                    self.session_id
                );
                None
            })
            .map(|(text, sources)| Block::new(part, &text, sources))
    }
}

impl BrainTurnContext for SessionBrainTurns {
    /// At a context epoch's start: live memory, then the brain's best
    /// matches for the owner's authenticated text, never clock/model lines
    /// or a synthetic wake/report. On every owner turn: cards for the
    /// records his own text names that this epoch does not carry yet.
    fn prefetch(
        &self,
        text: &str,
        owner_text: Option<&str>,
        epoch_start: bool,
    ) -> Result<Option<String>, LiveError> {
        let started = std::time::Instant::now();
        let binding = self
            .session_bindings
            .binding_for(&self.session)
            .ok_or_else(|| {
                LiveError::unavailable("brain_turn_binding_missing", "the session has no binding")
            })?;
        if !self.operations.same_composition(
            binding.served_revision,
            self.brain.policy().registry_revision,
        ) {
            return Err(LiveError::unavailable(
                "brain_turn_publication_mismatch",
                "the binding and the brain serve different registry revisions",
            ));
        }
        let mut named = self
            .named
            .lock()
            .map_err(|error| LiveError::unavailable("brain_turn_named_poisoned", error))?;
        let mut blocks: Vec<Block> = Vec::new();
        if epoch_start {
            named.clear();
            if self.live_tokens > 0 {
                let now_ms = time::OffsetDateTime::now_utc().unix_timestamp_nanos() / 1_000_000;
                let now_ms = u64::try_from(now_ms).unwrap_or(0);
                let jobs = self
                    .operations
                    .jobs()
                    .map(|board| board.live_entries(now_ms))
                    .unwrap_or_default();
                let live = self
                    .brain
                    .live_memory(Some(&self.project), jobs, now_ms, self.live_tokens)
                    .map(|block| block.map(|text| (text, Vec::new())));
                blocks.extend(self.block("live memory", live));
            }
            if let Some(owner_text) = owner_text.filter(|text| !text.trim().is_empty()) {
                let excerpts = self
                    .brain
                    .epoch_excerpts(owner_text, Some(&self.project), self.embedder.as_ref())
                    .and_then(|(hits, _)| {
                        let rendered =
                            odin_brain::service::render_prefetch(&hits, self.prefetch_tokens)?;
                        Ok(rendered.map(|(text, _)| {
                            // Only the hits the rendered block shows are sources.
                            let sources = hits
                                .iter()
                                .map(|hit| hit.item_id.to_string())
                                .filter(|id| text.contains(&format!("brain://{id}")))
                                .collect();
                            (text, sources)
                        }))
                    });
                blocks.extend(self.block("brain excerpts", excerpts));
            }
        }
        if self.per_turn_tokens > 0 {
            // Cards fire only on the owner's own words: a rendered turn, a
            // wake or a report names nothing.
            let cards = owner_text
                .map(|owner| {
                    self.brain
                        .named_records(owner, Some(&self.project), &named, true)
                })
                .transpose()
                .map(|cards| cards.unwrap_or_default())
                .and_then(|cards| {
                    let texts: Vec<String> = cards.iter().map(|(_, card)| card.clone()).collect();
                    let (shown, block) =
                        odin_brain::service::render_named(&texts, self.per_turn_tokens)?;
                    let ids: Vec<String> =
                        cards.iter().take(shown).map(|(id, _)| id.clone()).collect();
                    named.extend(ids.iter().cloned());
                    Ok(block.map(|(text, _)| (text, ids)))
                });
            blocks.extend(self.block("named records", cards));
        }
        tracing::info!(
            "odind: turn context session={} epoch_start={} core_tokens={} blocks={} ms={} prompt_digest=blake3:{}",
            self.session_id,
            epoch_start,
            self.core_tokens,
            blocks.len(),
            started.elapsed().as_millis(),
            blake3::hash(text.as_bytes()).to_hex()
        );
        if let Some(root) = self.trace_root.as_ref().filter(|_| !blocks.is_empty()) {
            let kind = if epoch_start { Kind::Epoch } else { Kind::Turn };
            if let Err(error) = context_trace::record(root, self.session_id, kind, None, &blocks) {
                tracing::warn!(
                    "odind: turn context session={} not traced: {error}",
                    self.session_id
                );
            }
        }
        Ok((!blocks.is_empty()).then(|| {
            blocks
                .into_iter()
                .map(|block| block.text)
                .collect::<Vec<_>>()
                .join("\n\n")
        }))
    }
}
