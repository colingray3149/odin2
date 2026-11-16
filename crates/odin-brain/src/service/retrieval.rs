//! Scoped retrieval over the newest sealed generation of every source in the
//! request's authorized serving scope, and the background warm round that
//! builds, seals, embeds and retires those generations.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use odin_domain::knowledge::{
    AtlasId, IndexGeneration, KnowledgeItemId, RetrievalHit, RetrievalMode, RetrievalQuery,
};
use odin_domain::ProjectId;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

use crate::archive::store::{ArchiveIdentity, MAX_IDENTITY_PAGES, MAX_IDENTITY_RECORDS};
use crate::error::{BrainError, BrainResult};
use crate::retrieval::identity::identity_literals;
use crate::retrieval::query::validate_embedding_binding;
use crate::retrieval::{QueryEmbedder, RetrievalPlan};
use crate::source::archive::ArchiveRecordKind;

use super::authority::{pin_all, PinnedSource};
use super::BrainService;

mod postgres;
pub(super) use postgres::embed_round;

/// One published archive record a turn's exact identity constraints address.
/// A segmented record is ONE logical record carried by several part items, so
/// the addressed content is the union of their chunks.
#[derive(Clone, Debug)]
struct AddressedRecord {
    source: AtlasId,
    item_ids: BTreeSet<KnowledgeItemId>,
}

/// The logical record one identity row belongs to: a segmented part's key is
/// its record's natural key with the `:part:<n>` suffix removed, so every part
/// of one logical record groups together; any other record is its own item,
/// since distinct records may share an export natural key.
fn logical_key(identity: &ArchiveIdentity) -> String {
    match identity.part_index {
        Some(_) => identity
            .natural_key
            .rsplit_once(":part:")
            .map_or(identity.natural_key.as_str(), |(key, _)| key)
            .to_owned(),
        None => identity.item_id.to_string(),
    }
}

/// How one turn's exact identity constraints resolved.
#[derive(Clone, Debug)]
enum AddressResolution {
    /// The query names no published record: the ordinary pool serves.
    None,
    /// The query names exactly one published record coherently.
    Addressed(AddressedRecord),
    /// The query names a record incoherently — several candidates, a
    /// contradicted conversation or instant, or a lookup too saturated to
    /// decide. Nothing may be served as if it were the record asked for.
    Unresolved,
}

/// How long a source stays unwired before its store releases what it held.
const UNWIRED_GRACE: std::time::Duration = std::time::Duration::from_secs(3 * 24 * 3600);

/// The provider name typed vector-leg failures carry.
const EMBEDDING_LEG: &str = "odin.retrieval.embedding";

/// The posture one retrieval actually served under. The lexical-only
/// promise is explicit: a typed lane unavailability degrades ONLY Hybrid
/// plans to their lexical leg, reported here — never silently, never for
/// Vector plans, and never for any other failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RetrievalPosture {
    /// The plan ran complete: a lexical plan, or a hybrid/vector plan with
    /// a usable pool or lane.
    Full,
    /// The vector leg did not run: lexical candidates were served instead
    /// and the unserved chunks await embedding through the declared
    /// gateway lane (observable via `archive_status` for archive sources).
    /// Produced only for Hybrid plans under a typed
    /// [`BrainError::EmbeddingUnavailable`], or for a lexical-only archive
    /// generation; Vector plans and every other error stay
    /// typed-unavailable.
    LexicalOnly {
        /// Why the vector leg did not run.
        reason: String,
    },
    /// The reranker did not run: the fused (BM25 and vector) order served.
    FusedOnly {
        /// Why the rerank was skipped.
        reason: String,
    },
}

/// The outcome of one posture-aware retrieval.
#[derive(Clone, Debug)]
pub struct RetrievalResponse {
    pub hits: Vec<RetrievalHit>,
    pub posture: RetrievalPosture,
}

impl BrainService {
    /// Runs retrieval for one query under the resolved knowledge policy. The
    /// candidate pool merges, for every requested source the bound project's
    /// serving scope authorizes, the generation of its current head when
    /// sealed, else the newest sealed one; a source with none serves nothing
    /// this turn. `embedder` is the caller's session-bound kernel executor;
    /// it is required only when the resolved plan executes embeddings.
    ///
    /// A query that exactly addresses one published archive record — quoting
    /// its message id, thread id, or natural key, with any conversation and
    /// timestamp it also quotes agreeing — serves that record's content
    /// (`resolve_addressed_record`); every other query serves the ordinary
    /// merged pool.
    ///
    /// The posture is never silent: a Hybrid plan under a typed
    /// [`BrainError::EmbeddingUnavailable`] (or a Hybrid plan over a
    /// lexical-only archive generation) serves its lexical leg as
    /// [`RetrievalPosture::LexicalOnly`] with the reason; Vector plans and
    /// every other failure stay typed-unavailable and propagate. Every
    /// consumer receives the posture — there is no posture-dropping
    /// variant.
    pub fn retrieve(
        &self,
        query: &RetrievalQuery,
        project: Option<&ProjectId>,
        embedder: Option<&Arc<QueryEmbedder>>,
    ) -> BrainResult<RetrievalResponse> {
        let (hits, posture) = self.retrieve_scoped(query, project, None, embedder, None)?;
        Ok(RetrievalResponse { hits, posture })
    }

    /// [`BrainService::retrieve`] with an explicit serving scope:
    /// `Some(sources)` restricts served chunks to that set; `None` falls
    /// back to the query's own source set. Either is intersected with the
    /// bound project's serving authority before anything is pinned.
    pub(crate) fn retrieve_scoped(
        &self,
        query: &RetrievalQuery,
        project: Option<&ProjectId>,
        scope: Option<&BTreeSet<AtlasId>>,
        embedder: Option<&Arc<QueryEmbedder>>,
        mode: Option<RetrievalMode>,
    ) -> BrainResult<(Vec<RetrievalHit>, RetrievalPosture)> {
        let knowledge = self
            .policy
            .knowledge
            .as_ref()
            .ok_or_else(|| BrainError::Unavailable {
                component: "retrieval",
                reason: "the resolved policy does not enable knowledge retrieval".to_owned(),
            })?;
        // The serving scope rules EVERY surface of this request, and it is
        // decided before any source is pinned or built: the request (or the
        // caller's explicit scope) intersected with the policy's serving
        // authority for the bound project. A project-bound session serves
        // only general knowledge plus exactly its declared project memory; a
        // projectless one never serves project memory; a query naming its
        // own sources serves at most those. A source outside the scope is
        // never pinned, so its outage cannot fail this request, while a
        // requested, authorized source that cannot be pinned still fails it
        // typed.
        let authorized = self.policy.project_serving_scope(project);
        let serving_scope: BTreeSet<AtlasId> = scope
            .unwrap_or(&query.sources)
            .intersection(&authorized)
            .cloned()
            .collect();
        let pinned_sources = self.pin_scoped(&serving_scope)?;
        let mut generations: Vec<IndexGeneration> = Vec::with_capacity(pinned_sources.len());
        let mut visible_items = BTreeSet::new();
        for pinned in &pinned_sources {
            visible_items.extend(
                pinned
                    .items
                    .iter()
                    .filter(|item| self.item_visible(item, project))
                    .map(|item| item.item_id),
            );
            // Archive sources pin the publication's exact generation.
            let generation = match &pinned.generation {
                Some(generation_id) => {
                    self.index
                        .load_pinned(generation_id, &pinned.id, &pinned.revision)?
                }
                None => match self.serving_generation(pinned)? {
                    Some(generation) => generation,
                    None => {
                        tracing::debug!(
                            source = pinned.id.as_str(),
                            "brain-retrieval source has no sealed generation yet"
                        );
                        continue;
                    }
                },
            };
            generations.push(generation);
        }
        // The plan derives from the knowledge policy (retrieval mode plus the
        // policy-resolved query); the chunks come from the generations pinned
        // above. Nothing of a turn is kept across requests.
        let resolved = knowledge.retrieval_query(query.text.clone())?;
        let mode = mode.unwrap_or(knowledge.retrieval_mode);
        let plan = RetrievalPlan::new(resolved, mode);
        // Defense in depth: the open-time and replace-time rejections hold
        // here too, before any executor call. A partial
        // binding never reaches embedding execution, and a vector/hybrid
        // query can never resolve to an empty success or a hybrid downgrade
        // through it.
        validate_embedding_binding(
            Some(mode),
            embedder.is_some(),
            self.config.embedding_model.is_some(),
        )?;
        // A query can ADDRESS a record instead of describing content: the
        // identity it quotes matches no indexed body text (identity lives in
        // the record's own columns), so resolving it here is the only path
        // from such a question to the content it asks about.
        let addressed =
            match self.resolve_addressed_record(&query.text, &pinned_sources, &serving_scope)? {
                AddressResolution::Addressed(record) => Some(record),
                AddressResolution::None => None,
                AddressResolution::Unresolved => {
                    // An explicitly named record that cannot be resolved
                    // coherently serves NOTHING: unrelated memory must never be
                    // served as if it were the record asked for. The renderer
                    // states the empty result.
                    return Ok((Vec::new(), RetrievalPosture::Full));
                }
            };
        // Sources pinned to an exact published generation are archives;
        // the lexical-only archive posture applies only to them. Every
        // other source keeps the existing vector contract untouched.
        let archive_sources: BTreeSet<AtlasId> = pinned_sources
            .iter()
            .filter(|pinned| pinned.generation.is_some())
            .map(|pinned| pinned.id.clone())
            .collect();
        let mut turn = postgres::PostgresTurn {
            plan,
            generations,
            pinned: &pinned_sources,
            project,
            visible_items: &visible_items,
            archive_sources: &archive_sources,
            serving_scope: &serving_scope,
            addressed: addressed.as_ref(),
            embedder,
        };
        turn.generations
            .retain(|generation| serving_scope.contains(&generation.atlas_id));
        if let Some(record) = turn.addressed {
            turn.generations
                .retain(|generation| generation.atlas_id == record.source);
        }
        self.retrieve_postgres(&turn)
    }

    /// The generation a turn serves for one live source: the one built for
    /// its current head when sealed, else the newest sealed one the pumps
    /// built — a turn never builds for a moved head.
    pub(super) fn serving_generation(
        &self,
        pinned: &PinnedSource,
    ) -> BrainResult<Option<IndexGeneration>> {
        let model = self.config.embedding_model.as_ref();
        if let Some(generation) =
            self.index
                .current_for_model(&pinned.id, &pinned.revision, model)?
        {
            if self.index.servable(&generation.generation_id)? {
                return Ok(Some(generation));
            }
        }
        self.index.newest(&pinned.id, model)
    }

    /// Pins exactly the composed sources of `scope`, sorted by source
    /// identity. A source in scope that cannot be pinned (unreadable root,
    /// vault unreachable) fails the request typed; an id this service does
    /// not compose, or an archive with no approved publication, pins nothing.
    pub(super) fn pin_scoped(&self, scope: &BTreeSet<AtlasId>) -> BrainResult<Vec<PinnedSource>> {
        let mut pinned = Vec::with_capacity(scope.len());
        for id in scope {
            let Some(source) = self.sources.get(id) else {
                continue;
            };
            if let Some(head) = source.pin(self.archives.as_ref())? {
                pinned.push(head);
            }
        }
        Ok(pinned)
    }

    /// One background warm round over one pin of every source: builds the
    /// moved heads of the sources the state pump does not own, seals and
    /// embeds them, then retires old generations. Returns how many generations
    /// still await sealing or vectors.
    pub fn warm(&self, embedder: &QueryEmbedder, budget: usize) -> BrainResult<usize> {
        let pinned = pin_all(&self.sources, self.archives.as_ref())?;
        let unowned: Vec<PinnedSource> = pinned
            .iter()
            .filter(|pinned| {
                pinned.generation.is_none()
                    && self
                        .sources
                        .get(&pinned.id)
                        .is_some_and(|source| !source.is_state())
            })
            .cloned()
            .collect();
        self.build_generations(&unowned)?;
        let pending = self.warm_postgres(&pinned, embedder, budget)?;
        self.retain(&pinned)?;
        Ok(pending)
    }

    /// Why this brain's PostgreSQL store cannot serve while a schema
    /// migration runs (or after it failed); `None` once the schema is
    /// current. The warm pump reports this as an expected wait, not a
    /// per-seat alarm on every round.
    pub fn pending_migration(&self) -> Option<String> {
        self.config.postgres.pending_migration()
    }

    /// Keeps, per source, the serving generation (an archive's published
    /// one, else the newest servable and the one before it, so a head that
    /// returns to its previous generation finds it rather than sealing it
    /// again) and anything newer, and a source this store no longer wires for
    /// [`UNWIRED_GRACE`] (a wiring slip costs no archive); retires the rest,
    /// sweeps copies that never sealed, and frees their space.
    fn retain(&self, pinned_sources: &[PinnedSource]) -> BrainResult<()> {
        let mut retired = 0;
        for pinned in pinned_sources {
            let serving = match &pinned.generation {
                Some(published) => Some(*published),
                None => {
                    let held = self.index.list(Some(&pinned.id))?;
                    held.get(1)
                        .or(held.first())
                        .map(|generation| generation.generation_id)
                }
            };
            if let Some(serving) = serving {
                retired += self.index.retire_older(&pinned.id, &serving)?;
            }
        }
        let unwired: Vec<_> = self
            .index
            .list(None)?
            .into_iter()
            .filter(|generation| !self.sources.contains_key(&generation.atlas_id))
            .map(|generation| generation.generation_id)
            .collect();
        for generation in self.index.unwired_for(&unwired, UNWIRED_GRACE)? {
            if self.index.retire(&generation)? {
                retired += 1;
            }
        }
        retired += self.index.sweep_stale_claims()?;
        if retired > 0 {
            tracing::info!(retired, "brain retention retired old generations");
        }
        Ok(())
    }

    /// One turn's exact identity constraints, resolved to the published
    /// logical record the turn addresses.
    ///
    /// The query's opaque literals ([`identity_literals`]) are compared
    /// exactly against the published records of the serving scope's pinned
    /// archive sources, one lookup per literal and source. Only a
    /// message-class match on the record's OWN identity (natural key, message
    /// id, or thread id) selects content; a conversation id only confirms.
    /// Resolution is coherent or explicitly unresolved:
    ///
    /// - different logical records (or sources) carrying the same literal, a
    ///   literal whose matches exhaust the page budget, or a segmented record
    ///   missing a part its own metadata declares, is
    ///   [`AddressResolution::Unresolved`];
    /// - a segmented record's part items are ONE logical record: every part
    ///   seen is served, never treated as ambiguity;
    /// - an instant literal must equal the selected record's own instant to
    ///   the precision the query carries, and a record without one cannot
    ///   satisfy it; another message sharing that instant is irrelevant;
    /// - a conversation the selected record does not belong to is
    ///   [`AddressResolution::Unresolved`];
    /// - no candidate at all is [`AddressResolution::None`]: most queries
    ///   address no record, and each of them costs no lookup.
    fn resolve_addressed_record(
        &self,
        text: &str,
        pinned_sources: &[PinnedSource],
        serving_scope: &BTreeSet<AtlasId>,
    ) -> BrainResult<AddressResolution> {
        let literals = identity_literals(text);
        if literals.is_empty() {
            return Ok(AddressResolution::None);
        }
        let Some(store) = self.archives.as_ref() else {
            return Ok(AddressResolution::None);
        };
        let archives: Vec<&PinnedSource> = pinned_sources
            .iter()
            .filter(|pinned| pinned.generation.is_some() && serving_scope.contains(&pinned.id))
            .collect();
        let mut addressed: BTreeMap<(AtlasId, String), BTreeSet<KnowledgeItemId>> = BTreeMap::new();
        let mut own_rows: BTreeMap<(AtlasId, String), Vec<ArchiveIdentity>> = BTreeMap::new();
        let mut conversations: BTreeSet<(AtlasId, String)> = BTreeSet::new();
        let mut unresolved = false;
        for pinned in &archives {
            for literal in &literals {
                // A literal's matches are paged to exhaustion: uniqueness is
                // never concluded from a truncated page, and a page budget
                // that runs out is explicitly unresolvable instead of a
                // silently partial answer.
                let mut page = store.identity_records(
                    &pinned.id,
                    &pinned.revision,
                    literal,
                    ArchiveRecordKind::Message,
                )?;
                let mut pages = 1_usize;
                loop {
                    let full = page.len() >= MAX_IDENTITY_RECORDS;
                    let mut last_item = None;
                    for identity in page {
                        last_item = Some(identity.item_id);
                        let owns = literal == &identity.natural_key
                            || identity.message_id.as_deref() == Some(literal.as_str())
                            || identity.thread_id.as_deref() == Some(literal.as_str());
                        if !owns {
                            // Matched by the record's own conversation: a
                            // confirmation for the addressed record, never a
                            // selector.
                            conversations.insert((pinned.id.clone(), literal.clone()));
                            continue;
                        }
                        let key = (pinned.id.clone(), logical_key(&identity));
                        addressed
                            .entry(key.clone())
                            .or_default()
                            .insert(identity.item_id);
                        own_rows.entry(key).or_default().push(identity);
                    }
                    if !full {
                        break;
                    }
                    let Some(last_item) = last_item else { break };
                    if pages >= MAX_IDENTITY_PAGES {
                        unresolved = true;
                        break;
                    }
                    page = store.identity_records_after(
                        &pinned.id,
                        &pinned.revision,
                        literal,
                        ArchiveRecordKind::Message,
                        &last_item,
                    )?;
                    pages += 1;
                }
            }
        }
        if unresolved {
            return Ok(AddressResolution::Unresolved);
        }
        if addressed.is_empty() {
            return Ok(AddressResolution::None);
        }
        // Twin records sharing a quoted id are told apart by the conversation
        // and instant the query also quotes; exactly one must stay coherent.
        let mut coherent = addressed.into_iter().filter_map(|(key, item_ids)| {
            let rows = own_rows.remove(&key)?;
            record_agrees(&key.0, &rows, &conversations, &literals).then_some(AddressedRecord {
                source: key.0,
                item_ids,
            })
        });
        Ok(match (coherent.next(), coherent.next()) {
            (Some(record), None) => AddressResolution::Addressed(record),
            _ => AddressResolution::Unresolved,
        })
    }
}

/// Whether one addressed logical record is complete and agrees with the
/// conversation and instant the query quotes.
fn record_agrees(
    source: &AtlasId,
    rows: &[ArchiveIdentity],
    conversations: &BTreeSet<(AtlasId, String)>,
    literals: &[String],
) -> bool {
    // A segmented logical record is complete only when every part its own
    // metadata declares is present: an incomplete logical message is never
    // served as if it were the whole record.
    if let Some(declared) = rows.iter().filter_map(|identity| identity.part_count).max() {
        let seen: BTreeSet<u32> = rows
            .iter()
            .filter_map(|identity| identity.part_index)
            .collect();
        if !(1..=declared).eq(seen.iter().copied()) {
            return false;
        }
    }
    let Some(own) = rows.first() else {
        return false;
    };
    if conversations.iter().any(|(candidate, conversation)| {
        candidate == source && own.conversation_id.as_deref() != Some(conversation.as_str())
    }) {
        return false;
    }
    let instants = literals
        .iter()
        .filter_map(|literal| Some((literal, OffsetDateTime::parse(literal, &Rfc3339).ok()?)));
    instants.into_iter().all(|(literal, instant)| {
        own.created_at
            .is_some_and(|created_at| instant_matches(literal, instant, created_at))
    })
}

/// Whether one query instant matches a record's own instant at the precision
/// the query carries: a fractional query must match exactly, while a
/// whole-second query matches any instant inside that second.
fn instant_matches(literal: &str, instant: OffsetDateTime, created_at: OffsetDateTime) -> bool {
    if literal.contains('.') {
        instant.unix_timestamp_nanos() == created_at.unix_timestamp_nanos()
    } else {
        instant.unix_timestamp() == created_at.unix_timestamp()
    }
}
