//! Governed archive ingestion and embedding backfill: the operator-approved
//! path that turns one declared archive export into durable normalized
//! memory, and the bounded lane-driven fill that moves a published
//! generation from lexical-only to model-bound vectors.
//!
//! Invariants enforced here:
//! - Ingest never runs at open or retrieval; it runs only through
//!   [`BrainService::ingest_archive`] with approval evidence binding the
//!   exact declaration digest and content revision.
//! - The wired declaration is the only declaration: a request carrying a
//!   different declaration is refused before any mutation, so a swapped
//!   declaration can never reuse an approval.
//! - Records are content-addressed; staging batches commit durably and
//!   re-staging is exact dedupe, so an interrupted run resumes cheaply and
//!   a re-run of unchanged content adds zero rows.
//! - Publication is atomic with the job's terminal state, binds a stored,
//!   verified generation, and never revives or overwrites a terminal
//!   approval; changed content is a new revision the old approval cannot
//!   publish.
//! - The embedding lane's typed unavailability completes the run
//!   lexical-only with durable staged progress; every other failure
//!   surfaces. Partial vector pools are never stored or served.

use std::collections::BTreeMap;

use odin_domain::knowledge::archive::{ArchivePrivacyClass, ArchiveSourceDeclaration};
use odin_domain::knowledge::ids::{AtlasId, EmbeddingModelId, IndexGenerationId, KnowledgeItemId};
use odin_domain::knowledge::retrieval::{IndexGeneration, IndexedChunk, TrustClass};
use odin_domain::Digest;

use crate::archive::{
    declaration_digest, record_key, ArchiveJobState, ArchiveStore, PreparedArchiveRecord,
    RevisionHasher, MAX_ARCHIVE_RECORD_BYTES, STAGE_BATCH_RECORDS,
};
use crate::audit::{BrainAuditEvent, AUDIT_KIND_ARCHIVE_EMBEDDED, AUDIT_KIND_ARCHIVE_INGESTED};
use crate::error::{BrainError, BrainResult};
use crate::index::{self, Chunker};
use crate::retrieval::embedding::EmbeddingVector;
use crate::source::archive::{stream_archive, ArchiveRecord};
use crate::source::SourceItem;

use super::BrainService;

/// The canonical digest binding one archive declaration; identical to the
/// digest governance computes for approval binding.
pub fn archive_declaration_digest(declaration: &ArchiveSourceDeclaration) -> BrainResult<Digest> {
    declaration_digest(declaration)
}

/// Operator approval evidence for one archive ingest, verified — never
/// minted — by the brain. The demand, approval, and command identifiers
/// name rows in the durable kernel ledger; the composed
/// [`ArchiveIngestGate`] proves they exist, are bound to this source,
/// declaration digest, and content revision, and were consumed by exactly
/// this command. Strings alone authorize nothing: without a passing gate
/// verification, ingest is typed-unavailable and no durable state mutates.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArchiveIngestAuthority {
    /// The governed demand this approval answers.
    pub demand_id: String,
    /// The exact approval granted against the demand.
    pub approval_id: String,
    /// The journaled command whose execution this ingest performs; the
    /// approval must have been consumed by exactly this command.
    pub command_id: String,
    /// Bound declaration digest (canonical serde JSON of the declaration).
    pub declaration_digest: Digest,
    /// Bound content revision: the digest the prepare pass observed.
    pub content_revision: Digest,
}

/// The kernel-approval verification seam for archive ingest: runtime wiring
/// implements this over the durable ledger (the approval row exists, its
/// scope structurally matches this source, declaration digest, and content
/// revision, its status shows consumption by exactly
/// `authority.command_id`, and the journaled command's arguments match).
/// Verification is read-only — it never consumes, revives, or journals
/// anything — so it is safe on every path including crash-resume re-entry
/// and the already-published idempotent no-op.
pub trait ArchiveIngestGate: Send + Sync {
    /// Verifies the authority AND the idempotency key against the durable
    /// kernel ledger: the approval row exists, its scope structurally
    /// matches this source, declaration digest, and content revision, its
    /// status shows consumption by exactly `authority.command_id` under
    /// exactly this idempotency key, and the journaled command's
    /// arguments match. Binding the key closes evidence reuse under a
    /// fresh key. Read-only; never consumes or revives anything.
    fn verify(
        &self,
        authority: &ArchiveIngestAuthority,
        source: &AtlasId,
        idempotency_key: &str,
    ) -> BrainResult<()>;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArchiveIngestRequest {
    /// The wired archive source; must be configured as
    /// [`super::BrainSourceConfig::Archive`].
    pub source: AtlasId,
    /// The declaration exactly as wired; verified digest-for-digest against
    /// the declared source before anything else.
    pub declaration: ArchiveSourceDeclaration,
    /// Verified approval evidence binding this declaration and content
    /// revision; verified through the composed [`ArchiveIngestGate`].
    pub approval: ArchiveIngestAuthority,
    /// Single-use idempotency key for this governed run.
    pub idempotency_key: String,
    /// Wall-clock deadline for this run: the declared capability ceiling the
    /// operator command enforces. Reaching it aborts the stream typed, and
    /// every batch already staged stays durable so an identical rerun
    /// resumes from the staged state; `None` runs without a ceiling.
    pub deadline: Option<time::OffsetDateTime>,
}

/// The read-only outcome of one prepare pass: both binding digests and
/// stream accounting, with nothing written anywhere.
#[derive(Clone, Debug)]
pub struct ArchiveIngestPlan {
    pub source: AtlasId,
    pub declaration_digest: Digest,
    pub content_revision: Digest,
    /// Source messages the prepare pass classified (see
    /// [`crate::source::archive::ArchiveStreamSummary::messages_parsed`]).
    pub messages_parsed: u64,
    pub records: u64,
    pub bytes: u64,
    /// Parser-declared skip accounting (policy exclusions, malformed
    /// records, truncations); nothing is silently lost.
    pub skip_reasons: BTreeMap<String, u64>,
}

/// The outcome of one governed ingest.
#[derive(Clone, Debug)]
pub struct ArchiveIngestReport {
    pub source: AtlasId,
    pub content_revision: Digest,
    pub generation: IndexGeneration,
    /// Records observed in the parser stream.
    pub records_seen: u64,
    /// Records newly staged by this run.
    pub records_staged: u64,
    /// Records already staged by an earlier run (resume dedupe).
    pub records_duplicate: u64,
    pub chunks: u64,
    /// True when this call published nothing: the same content revision was
    /// already approved and published, so the call was an idempotent no-op.
    pub resumed: bool,
    pub skip_reasons: BTreeMap<String, u64>,
}

/// Durable embedding posture of one published archive generation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ArchiveEmbeddingView {
    /// Lexical-only is complete and servable; every unserved chunk awaits
    /// embedding through the declared gateway lane.
    LexicalOnly {
        /// Chunks without a stored vector.
        pending_chunks: u64,
        /// Vectors staged by an interrupted backfill (resumable progress).
        staged_vectors: u64,
    },
    Embedded {
        model: EmbeddingModelId,
    },
}

/// The published, servable state of one archive source.
#[derive(Clone, Debug)]
pub struct ArchivePublicationView {
    pub revision: Digest,
    pub generation_id: IndexGenerationId,
    pub embedding: ArchiveEmbeddingView,
    pub records: u64,
    pub chunks: u64,
    pub published_epoch: u64,
}

/// The last governed ingest job of one archive source (metadata only).
#[derive(Clone, Debug)]
pub struct ArchiveJobView {
    pub job_id: String,
    pub approval_demand: String,
    pub approval_id: String,
    pub approval_command: String,
    pub state: ArchiveJobState,
    pub records_seen: u64,
    pub records_staged: u64,
    pub records_duplicate: u64,
    pub skip_reasons: BTreeMap<String, u64>,
}

/// The full durable status of one archive source.
#[derive(Clone, Debug)]
pub struct ArchiveSourceStatus {
    pub source: AtlasId,
    pub memory_namespace: String,
    pub privacy_class: ArchivePrivacyClass,
    pub published: Option<ArchivePublicationView>,
    pub last_job: Option<ArchiveJobView>,
}

/// The exact provenance of one indexed archive item, for citations: the
/// structured identity of the export record a hit's byte range addresses.
/// Provenance is served from these columns, never re-parsed from text.
#[derive(Clone, Debug)]
pub struct ArchiveCitation {
    pub record_key: Digest,
    pub natural_key: String,
    pub kind: crate::source::archive::ArchiveRecordKind,
    pub namespace: String,
    pub privacy_class: ArchivePrivacyClass,
    pub export_account: Option<String>,
    /// 1-based part index and total parts for segmented records; `None`
    /// for whole records.
    pub part_index: Option<u32>,
    pub part_count: Option<u32>,
    pub export_id: Option<String>,
    pub conversation_id: Option<String>,
    pub message_id: Option<String>,
    pub thread_id: Option<String>,
    pub created_at: Option<time::OffsetDateTime>,
    pub sent_by_user: bool,
    pub labels: Vec<String>,
    pub rule_flags: Vec<String>,
    /// Format-specific export metadata carried verbatim (ChatGPT branch
    /// ancestry and conversation flags, Gemini/NotebookLM source names).
    /// Untrusted observed metadata, never authority; empty for formats
    /// that declare none.
    pub export_metadata: BTreeMap<String, serde_json::Value>,
    /// The exact declared export root path — operator-declared at source
    /// composition, read from the persisted declaration, never hardcoded
    /// and never inferred. An origin `member`/`declared_in` resolves
    /// against this root; the parent message id on the same citation
    /// completes the message locator.
    pub origin: Option<crate::source::archive::ArchiveAssetOrigin>,
    /// The declared export root the origin locator is relative to.
    pub export_root: Option<String>,
}

#[derive(Clone, Debug)]
pub struct ArchiveEmbeddingBackfillRequest {
    pub source: AtlasId,
    /// The declared embedding model the backfill binds; the model enters
    /// the new generation's manifest, so a different model is a different
    /// generation, never a silent rebind.
    pub embedding_model: EmbeddingModelId,
    /// Texts per lane batch (1..=256).
    pub batch_size: usize,
    /// Optional batch budget: the run stops after this many lane calls
    /// with the pool still partial, reporting resumable lexical-only
    /// progress.
    pub max_batches: Option<usize>,
}

/// The declared gateway lane the backfill embeds through. Runtime wiring
/// implements this over the kernel-lease-governed batch embedding
/// execution; the brain never calls a provider directly.
pub trait EmbeddingBatchLane {
    /// Embeds one batch of chunk texts; the result aligns with the input
    /// order. [`BrainError::EmbeddingUnavailable`] is the only error that
    /// completes lexical-only; everything else surfaces.
    fn embed_batch(&mut self, texts: &[String]) -> BrainResult<Vec<EmbeddingVector>>;
}

/// How one backfill run ended.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ArchiveBackfillOutcome {
    /// The full pool is stored and the publication now binds the
    /// model-stamped generation.
    Embedded,
    /// The lane was typed-unavailable (or the batch budget was exhausted);
    /// staged progress is durable and a later run resumes it.
    LexicalOnly { reason: String, pending: u64 },
}

#[derive(Clone, Debug)]
pub struct ArchiveEmbeddingBackfillReport {
    pub source: AtlasId,
    pub generation: IndexGeneration,
    pub embedding_model: EmbeddingModelId,
    pub vectors_staged: u64,
    pub outcome: ArchiveBackfillOutcome,
}

/// The typed refusal a run reports once its declared ceiling has passed.
fn ceiling_error() -> BrainError {
    BrainError::Unavailable {
        component: "archive_ingest",
        reason: "the declared ingest ceiling passed while building the generation; nothing was \
                 published and the durable staged state resumes on an identical rerun"
            .to_owned(),
    }
}

/// One run's declared ceiling, measured monotonically: the request's
/// wall-clock deadline (the operator command's own lifecycle value) is
/// converted to an elapsed bound exactly once, so every later check is a
/// monotonic comparison that a clock step can neither shorten nor extend.
/// `None` runs unbounded.
struct RunCeiling {
    deadline: Option<std::time::Instant>,
}

impl RunCeiling {
    fn from_deadline(deadline: Option<time::OffsetDateTime>) -> Self {
        Self {
            deadline: deadline.map(|deadline| {
                let remaining = deadline - time::OffsetDateTime::now_utc();
                std::time::Instant::now()
                    + std::time::Duration::try_from(remaining).unwrap_or(std::time::Duration::ZERO)
            }),
        }
    }

    /// Whether the declared ceiling has passed.
    fn passed(&self) -> bool {
        self.deadline
            .is_some_and(|deadline| std::time::Instant::now() >= deadline)
    }
}

const MIN_BACKFILL_BATCH: usize = 1;
const MAX_BACKFILL_BATCH: usize = 256;

fn epoch_secs() -> BrainResult<u64> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| BrainError::InvalidRequest("brain clock before the Unix epoch".to_owned()))
}

fn validate_record(record: &ArchiveRecord) -> BrainResult<()> {
    if record.natural_key.is_empty() {
        return Err(BrainError::InvalidRequest(
            "archive record natural key must not be empty".to_owned(),
        ));
    }
    if record.text.is_empty() {
        return Err(BrainError::InvalidRequest(format!(
            "archive record {} carries empty text",
            record.natural_key
        )));
    }
    if record.text.len() > MAX_ARCHIVE_RECORD_BYTES {
        return Err(BrainError::InvalidRequest(format!(
            "archive record {} exceeds the {MAX_ARCHIVE_RECORD_BYTES} byte bound",
            record.natural_key
        )));
    }
    if record.provenance.part_count.is_some() != record.provenance.part_index.is_some() {
        return Err(BrainError::InvalidRequest(format!(
            "archive record {} carries a partial part identity",
            record.natural_key
        )));
    }
    Ok(())
}

impl BrainService {
    fn archive_store(&self) -> BrainResult<&ArchiveStore> {
        self.archives
            .as_ref()
            .ok_or_else(|| BrainError::Unavailable {
                component: "archive_store",
                reason: "no archive source is wired on this service".to_owned(),
            })
    }

    /// The wired declaration of one archive source, verified present.
    fn declared_archive(
        &self,
        source: &AtlasId,
    ) -> BrainResult<(ArchiveSourceDeclaration, Digest, &ArchiveStore)> {
        let store = self.archive_store()?;
        let declared = store.declared(source)?.ok_or_else(|| {
            BrainError::InvalidRequest(format!(
                "source {} is not a declared archive source on this service",
                source.as_str()
            ))
        })?;
        Ok((declared.declaration, declared.declaration_digest, store))
    }

    /// Streams the export without writes to compute the declaration digest and
    /// content revision required by approval and [`Self::ingest_archive`].
    pub fn prepare_archive_ingest(&self, source: &AtlasId) -> BrainResult<ArchiveIngestPlan> {
        let (declaration, declaration_digest, _) = self.declared_archive(source)?;
        declaration.validate()?;
        let mut revision = RevisionHasher::new(source, &declaration_digest);
        let mut records = 0_u64;
        let mut bytes = 0_u64;
        let summary = stream_archive(&declaration, &mut |record| {
            validate_record(&record)?;
            let key = record_key(source, &declaration_digest, &record)?;
            revision.push_record(&key);
            records += 1;
            bytes += record.text.len() as u64;
            Ok(())
        })?;
        Ok(ArchiveIngestPlan {
            source: source.clone(),
            declaration_digest,
            content_revision: revision.finish(),
            messages_parsed: summary.messages_parsed,
            records: summary.records_emitted.max(records),
            bytes,
            skip_reasons: summary.skip_reasons,
        })
    }

    /// Governed archive ingest: verifies the approval binding, stages
    /// records durably (content-addressed dedupe), builds the lexical
    /// generation incrementally from staged state, and publishes the
    /// approved revision atomically. Re-running the identical approved
    /// revision is an idempotent no-op; changed content fails typed before
    /// any mutation of the serving state.
    pub fn ingest_archive(
        &self,
        request: &ArchiveIngestRequest,
    ) -> BrainResult<ArchiveIngestReport> {
        let (declaration, declared_digest, store) = self.declared_archive(&request.source)?;
        request.declaration.validate()?;
        if declaration_digest(&request.declaration)? != declared_digest {
            return Err(BrainError::InvalidRequest(format!(
                "request declaration for {} does not digest-match the wired declaration; \
                 a swapped declaration can never reuse an approval",
                request.source.as_str()
            )));
        }
        if request.approval.declaration_digest != declared_digest {
            return Err(BrainError::InvalidRequest(
                "approval binds a different declaration digest than the wired source".to_owned(),
            ));
        }
        // Authority first, before even the idempotent no-op path: only the
        // verified binding may learn publication state, and nothing mutates
        // without it. Verification is read-only and idempotent, so
        // crash-resume re-entry with the same consumed approval passes.
        let gate = self
            .config
            .archive_ingest_gate
            .as_ref()
            .ok_or_else(|| BrainError::Unavailable {
                component: "archive_ingest_gate",
                reason: "archive ingest requires the kernel approval gate;                          this service was opened without one"
                    .to_owned(),
            })?;
        gate.verify(&request.approval, &request.source, &request.idempotency_key)?;
        if let Some(publication) = store.publication(&request.source)? {
            if publication.revision == request.approval.content_revision {
                // Identical approved content already published: nothing to
                // do, nothing re-written. Terminal approvals are never
                // revived and publications are never overwritten.
                let generation = self
                    .index
                    .load_pinned(
                        &publication.generation_id,
                        &request.source,
                        &publication.revision,
                    )
                    .map_err(|error| match error {
                        BrainError::NotFound { .. } => BrainError::StaleAuthority {
                            authority: "archive_publication",
                            detail: format!(
                                "source {} publishes generation {} but its rows are missing",
                                request.source.as_str(),
                                publication.generation_id
                            ),
                        },
                        other => other,
                    })?;
                return Ok(ArchiveIngestReport {
                    source: request.source.clone(),
                    content_revision: publication.revision,
                    generation,
                    records_seen: publication.records,
                    records_staged: 0,
                    records_duplicate: publication.records,
                    chunks: publication.chunks,
                    resumed: true,
                    skip_reasons: BTreeMap::new(),
                });
            }
        }
        // The declared ceiling is checked before any mutation: an expired
        // run stages and publishes nothing, so a rerun starts clean.
        let ceiling = RunCeiling::from_deadline(request.deadline);
        if ceiling.passed() {
            return Err(BrainError::Unavailable {
                component: "archive_ingest",
                reason: "the declared ingest ceiling had already passed; nothing was staged or \
                         published"
                    .to_owned(),
            });
        }
        store.create_job(
            &request.idempotency_key,
            &request.source,
            &request.approval.demand_id,
            &request.approval.approval_id,
            &request.approval.command_id,
            epoch_secs()?,
        )?;
        // Staging failures leave the job non-terminal and the staged rows
        // durable: a re-run with a fresh key resumes by dedupe. Nothing is
        // published on failure, ever.
        self.stage_archive_records(request, &declaration, declared_digest, store, &ceiling)
    }

    /// The staging + publication core of one ingest. Stage rows are labeled
    /// with the approval's bound revision; the recomputed revision is
    /// verified before anything publishes, so a moved export fails typed
    /// and its revision rows are discarded.
    fn stage_archive_records(
        &self,
        request: &ArchiveIngestRequest,
        declaration: &ArchiveSourceDeclaration,
        declared_digest: Digest,
        store: &ArchiveStore,
        ceiling: &RunCeiling,
    ) -> BrainResult<ArchiveIngestReport> {
        let knowledge = self
            .policy
            .knowledge
            .as_ref()
            .ok_or_else(|| BrainError::Unavailable {
                component: "knowledge_policy",
                reason: "archive ingest requires a resolved knowledge policy".to_owned(),
            })?;
        let chunker = Chunker::new(knowledge.chunk_tokens, knowledge.chunk_overlap_tokens)?;
        let staging_revision = request.approval.content_revision;
        let mut revision = RevisionHasher::new(&request.source, &declared_digest);
        let mut batch: Vec<(Digest, PreparedArchiveRecord)> =
            Vec::with_capacity(STAGE_BATCH_RECORDS);
        let mut ordinal = 0_u64;
        let mut seen = 0_u64;
        let mut staged = 0_u64;
        let mut duplicates = 0_u64;
        // Emit errors propagate directly: the parser aborts the stream on
        // an emit error, so a staging failure stops the parse immediately
        // instead of masking the failure while the rest of the archive
        // streams through.
        let stream = stream_archive(declaration, &mut |record| {
            validate_record(&record)?;
            let key = record_key(&request.source, &declared_digest, &record)?;
            revision.push_record(&key);
            // Item identity is the CONTENT-ADDRESSED record key, never the
            // export's natural key alone: two differing records may share one
            // natural key (a duplicated message uuid, two same-named
            // attachments in one message), and they must stay distinct items
            // so each citation resolves to exactly one record.
            let item_id = SourceItem::identity(&request.source, key.as_bytes())?;
            batch.push((
                key,
                PreparedArchiveRecord {
                    ordinal,
                    item_id,
                    natural_key: record.natural_key.clone(),
                    kind: record.kind,
                    namespace: declaration.memory_namespace.clone(),
                    privacy_class: declaration.privacy_class,
                    export_account: record.provenance.export_account.clone(),
                    part_index: record.provenance.part_index,
                    part_count: record.provenance.part_count,
                    export_id: record.provenance.export_id.clone(),
                    conversation_id: record.provenance.conversation_id.clone(),
                    message_id: record.provenance.message_id.clone(),
                    thread_id: record.provenance.thread_id.clone(),
                    created_at: record.provenance.created_at,
                    sent_by_user: record.provenance.sent_by_user,
                    labels: record.provenance.labels.clone(),
                    rule_flags: record.provenance.rule_flags.clone(),
                    export_metadata: record.provenance.export_metadata.clone(),
                    origin: record.provenance.origin.clone(),
                    text_digest: Digest::hash(record.text.as_bytes()),
                    text: record.text,
                },
            ));
            ordinal += 1;
            seen += 1;
            if batch.len() >= STAGE_BATCH_RECORDS {
                // The declared ceiling is enforced between batches, so a run
                // that overruns stops with every staged batch durable: the
                // job stays non-terminal and an identical rerun resumes.
                if ceiling.passed() {
                    return Err(BrainError::Unavailable {
                        component: "archive_ingest",
                        reason: format!(
                            "the declared ingest ceiling passed after {seen} records; every                              staged batch is durable and an identical rerun resumes from it"
                        ),
                    });
                }
                let drained = std::mem::take(&mut batch);
                let refs: Vec<(&Digest, &PreparedArchiveRecord)> =
                    drained.iter().map(|(key, record)| (key, record)).collect();
                let outcome = store.stage_records(
                    &request.source,
                    &staging_revision,
                    &refs,
                    epoch_secs()?,
                )?;
                staged += outcome.inserted;
                duplicates += outcome.duplicates;
                store.update_job_progress(
                    &request.idempotency_key,
                    seen,
                    staged,
                    duplicates,
                    epoch_secs()?,
                )?;
            }
            Ok(())
        });
        let summary = stream?;
        let content_revision = revision.finish();
        if content_revision != staging_revision {
            store.discard_revision(&request.source, &staging_revision)?;
            store.finish_job(
                &request.idempotency_key,
                &content_revision,
                ArchiveJobState::Failed,
                epoch_secs()?,
            )?;
            return Err(BrainError::InvalidRequest(format!(
                "archive content revision {content_revision} does not match the approved \
                 revision {staging_revision}; the export changed after approval — re-run \
                 prepare and re-approve"
            )));
        }
        if !batch.is_empty() {
            let refs: Vec<(&Digest, &PreparedArchiveRecord)> =
                batch.iter().map(|(key, record)| (key, record)).collect();
            let outcome =
                store.stage_records(&request.source, &content_revision, &refs, epoch_secs()?)?;
            staged += outcome.inserted;
            duplicates += outcome.duplicates;
        }
        store.update_job_progress(
            &request.idempotency_key,
            seen,
            staged,
            duplicates,
            epoch_secs()?,
        )?;
        // Build the lexical generation incrementally from staged records —
        // one item's chunks in memory at a time — then publish the revision
        // and the job's terminal state in one transaction.
        // The declared ceiling bounds the whole run, never only staging: an
        // overrun must not build or publish. Staged rows stay durable, so the
        // command resumes instead of publishing past its ceiling.
        if ceiling.passed() {
            return Err(BrainError::Unavailable {
                component: "archive_ingest",
                reason: format!(
                    "the declared ingest ceiling passed after staging {staged} records; the \
                     index was not built, nothing was published, and an identical rerun \
                     resumes from the durable staged state"
                ),
            });
        }
        let lexical_model = EmbeddingModelId::new(index::build::NO_EMBEDDING_MODEL)?;
        let (generation, _) = self.build_archive_generation(
            store,
            &request.source,
            &content_revision,
            chunker,
            lexical_model,
            ceiling,
        )?;
        let chunks = self
            .index
            .chunk_count(&generation.generation_id)?
            .ok_or_else(|| BrainError::Corrupt {
                component: "brain-index-store",
                reason: "the generation just stored has no chunk rows".to_owned(),
            })?;
        // Last gate before the publication transaction: a run that crossed
        // its ceiling while building the index publishes nothing.
        if ceiling.passed() {
            return Err(BrainError::Unavailable {
                component: "archive_ingest",
                reason: format!(
                    "the declared ingest ceiling passed after building generation {}; nothing \
                     was published and an identical rerun resumes from the durable staged \
                     state",
                    generation.generation_id
                ),
            });
        }
        store.publish(
            &request.source,
            &content_revision,
            &generation.generation_id,
            seen,
            chunks,
            None,
            &request.idempotency_key,
            epoch_secs()?,
        )?;
        self.audit.record(BrainAuditEvent {
            kind: AUDIT_KIND_ARCHIVE_INGESTED,
            actor: odin_domain::Actor::System {
                name: "odin-brain".to_owned(),
            },
            scope: odin_domain::Scope::default(),
            payload: serde_json::json!({
                "source": request.source.as_str(),
                "contentRevision": content_revision.to_string(),
                "generationId": generation.generation_id.to_string(),
                "recordsSeen": seen,
                "recordsStaged": staged,
                "recordsDuplicate": duplicates,
                "chunks": chunks,
                "approvalDemand": request.approval.demand_id,
                "approvalId": request.approval.approval_id,
            }),
            evidence: Vec::new(),
            binding: Some(self.policy.policy_digest),
        })?;
        Ok(ArchiveIngestReport {
            source: request.source.clone(),
            content_revision,
            generation,
            records_seen: seen,
            records_staged: staged,
            records_duplicate: duplicates,
            chunks,
            resumed: false,
            skip_reasons: summary.skip_reasons,
        })
    }

    /// Builds one generation over a staged revision by streaming records
    /// from the archive store through the deterministic chunker into the
    /// index store. A scoped producer thread reads and chunks one record at
    /// a time into a bounded channel, so build memory stays at one item's
    /// chunks plus the channel window.
    fn build_archive_generation(
        &self,
        store: &ArchiveStore,
        source: &AtlasId,
        revision: &Digest,
        chunker: Chunker,
        embedding_model: EmbeddingModelId,
        ceiling: &RunCeiling,
    ) -> BrainResult<(IndexGeneration, index::StoreOutcome)> {
        const CHANNEL_WINDOW: usize = 64;
        let (sender, receiver) =
            std::sync::mpsc::sync_channel::<BrainResult<IndexedChunk>>(CHANNEL_WINDOW);
        // `move` is load-bearing: the sender must be owned (and dropped) by
        // the producer thread, or the receiver's end-of-stream never
        // arrives and the consumer waits forever.
        let created_epoch = epoch_secs()?;
        let (built, feed_error) = std::thread::scope(|scope| {
            let producer = scope.spawn(move || {
                let result = store.for_each_revision_record(source, revision, &mut |record| {
                    // The same ceiling bounds the streaming build: an
                    // overrun ends the feed at bounded progress, so the
                    // consumer stops and nothing publishes.
                    if ceiling.passed() {
                        return Err(ceiling_error());
                    }
                    // The same content-addressed identity the staging pass
                    // stored, derived from the record key the store holds.
                    let item = SourceItem::new(
                        source.clone(),
                        *revision,
                        record.record_key.as_bytes(),
                        TrustClass::Observed,
                        record.text,
                    )?;
                    for chunk in chunker.chunk_item(&item)? {
                        if ceiling.passed() {
                            return Err(ceiling_error());
                        }
                        if sender.send(Ok(chunk)).is_err() {
                            // The consumer stopped (store failure); end the
                            // feed so the producer thread can join.
                            return Err(BrainError::Unavailable {
                                component: "archive_generation_build",
                                reason: "chunk consumer stopped before the stream ended".to_owned(),
                            });
                        }
                    }
                    Ok(())
                });
                if let Err(error) = result {
                    let _ = sender.send(Err(error));
                }
            });
            let mut chunks = receiver.into_iter();
            let built = self.index.store_streaming(
                source.clone(),
                *revision,
                &embedding_model,
                created_epoch,
                &mut chunks,
                &BTreeMap::new(),
            );
            if built.is_err() {
                // The producer blocks once the bounded channel fills; drain
                // it to completion so the thread always joins. Its own
                // error, if any, was already forwarded into the stream.
                for _ in chunks.by_ref() {}
            }
            let panic = match producer.join() {
                Ok(()) => None,
                Err(_) => Some(BrainError::Corrupt {
                    component: "archive_generation_build",
                    reason: "chunk producer thread panicked".to_owned(),
                }),
            };
            (built, panic)
        });
        // A producer-side failure after a successful store is still a
        // failure: the generation would be incomplete by definition.
        match feed_error {
            Some(error) if built.is_ok() => Err(error),
            _ => built,
        }
    }

    /// Durable status of one archive source: declaration, publication
    /// (including the observable lexical-only embedding backlog), and the
    /// last governed job.
    pub fn archive_status(&self, source: &AtlasId) -> BrainResult<ArchiveSourceStatus> {
        let store = self.archive_store()?;
        let declared = store.declared(source)?.ok_or_else(|| {
            BrainError::InvalidRequest(format!(
                "source {} is not a declared archive source on this service",
                source.as_str()
            ))
        })?;
        let published = store
            .publication(source)?
            .map(|publication| -> BrainResult<ArchivePublicationView> {
                let embedding = match publication.embedding_model.clone() {
                    Some(model) => ArchiveEmbeddingView::Embedded { model },
                    None => {
                        // Interrupted backfills stage against the pending
                        // twin; progress is durable and observable here.
                        let staged = match &publication.pending_generation {
                            Some(twin) => store.staged_vector_count(twin)?,
                            None => 0,
                        };
                        ArchiveEmbeddingView::LexicalOnly {
                            pending_chunks: publication.chunks.saturating_sub(staged),
                            staged_vectors: staged,
                        }
                    }
                };
                Ok(ArchivePublicationView {
                    revision: publication.revision,
                    generation_id: publication.generation_id,
                    embedding,
                    records: publication.records,
                    chunks: publication.chunks,
                    published_epoch: publication.published_epoch,
                })
            })
            .transpose()?;
        let last_job = store.last_job(source)?.map(|job| ArchiveJobView {
            job_id: job.job_id,
            approval_demand: job.approval_demand,
            approval_id: job.approval_id,
            approval_command: job.approval_command,
            state: job.state,
            records_seen: job.records_seen,
            records_staged: job.records_staged,
            records_duplicate: job.records_duplicate,
            skip_reasons: job.skip_reasons,
        });
        Ok(ArchiveSourceStatus {
            source: source.clone(),
            memory_namespace: declared.declaration.memory_namespace,
            privacy_class: declared.declaration.privacy_class,
            published,
            last_job,
        })
    }

    /// Expands one archive hit's citation into exact export provenance
    /// (export account, conversation/message/thread identity, timestamp).
    /// Retrieval reads only persisted approved state; the raw archive is
    /// never re-opened on the serving path.
    pub fn archive_citation(
        &self,
        source: &AtlasId,
        revision: &Digest,
        item_id: &KnowledgeItemId,
    ) -> BrainResult<Option<ArchiveCitation>> {
        let store = self.archive_store()?;
        // The root is the operator's own persisted declaration, in its
        // exact declared form: an exact checked string (typed refusal for
        // a non-UTF-8 path), never a display()-style lossy rewrite, never
        // a hardcode. It is data about the export, never read authority.
        let export_root = store
            .declared(source)?
            .map(|declared| {
                declared
                    .declaration
                    .path
                    .to_str()
                    .map(str::to_owned)
                    .ok_or_else(|| {
                        BrainError::InvalidRequest(format!(
                            "declared archive path {} is not UTF-8",
                            declared.declaration.path.display()
                        ))
                    })
            })
            .transpose()?;
        Ok(store
            .record_for_item(source, revision, item_id)?
            .map(|record| ArchiveCitation {
                record_key: record.record_key,
                natural_key: record.natural_key,
                kind: record.kind,
                namespace: record.namespace,
                privacy_class: record.privacy_class,
                export_account: record.export_account,
                part_index: record.part_index,
                part_count: record.part_count,
                export_id: record.export_id,
                conversation_id: record.conversation_id,
                message_id: record.message_id,
                thread_id: record.thread_id,
                created_at: record.created_at,
                sent_by_user: record.sent_by_user,
                labels: record.labels,
                rule_flags: record.rule_flags,
                export_metadata: record.export_metadata,
                origin: record.origin,
                export_root,
            }))
    }

    /// Bounded, resumable embedding backfill for one published archive
    /// generation. Chunks embed through the declared lane in bounded
    /// batches, vectors stage durably, and only a complete pool moves —
    /// verified — into the model-stamped twin generation, which the
    /// publication then rebinds in one transaction. Lane unavailability (or
    /// an exhausted batch budget) completes lexical-only with durable
    /// progress; any other failure surfaces.
    pub fn backfill_archive_embeddings(
        &self,
        request: &ArchiveEmbeddingBackfillRequest,
        lane: &mut dyn EmbeddingBatchLane,
    ) -> BrainResult<ArchiveEmbeddingBackfillReport> {
        if request.batch_size < MIN_BACKFILL_BATCH || request.batch_size > MAX_BACKFILL_BATCH {
            return Err(BrainError::InvalidRequest(format!(
                "backfill batch_size must be within {MIN_BACKFILL_BATCH}..={MAX_BACKFILL_BATCH}"
            )));
        }
        let store = self.archive_store()?;
        let publication =
            store
                .publication(&request.source)?
                .ok_or_else(|| BrainError::NotFound {
                    kind: "archive publication",
                    id: request.source.as_str().to_owned(),
                })?;
        // Header-only: backfill never materializes chunk text; chunk
        // integrity is verified on full loads at serving time.
        let published_generation = || {
            self.index
                .load_pinned(
                    &publication.generation_id,
                    &request.source,
                    &publication.revision,
                )
                .map_err(|error| match error {
                    BrainError::NotFound { .. } => BrainError::StaleAuthority {
                        authority: "archive_publication",
                        detail: format!(
                            "source {} publishes generation {} but its rows are missing",
                            request.source.as_str(),
                            publication.generation_id
                        ),
                    },
                    other => other,
                })
        };
        if publication.embedding_model.as_ref() == Some(&request.embedding_model) {
            return Ok(ArchiveEmbeddingBackfillReport {
                source: request.source.clone(),
                generation: published_generation()?,
                embedding_model: request.embedding_model.clone(),
                vectors_staged: 0,
                outcome: ArchiveBackfillOutcome::Embedded,
            });
        }
        let lexical_generation = published_generation()?;
        // A backfill interrupted mid-flight leaves its twin durable in the
        // publication marker: resume stages against that twin instead of
        // restamping, so progress and pool identity survive the crash.
        let twin = match publication.pending_generation {
            Some(twin) => self
                .index
                .load_pinned(&twin, &request.source, &publication.revision)?,
            None => {
                let (twin, _) = self.index.restamp_generation(
                    &lexical_generation.generation_id,
                    &request.embedding_model,
                    epoch_secs()?,
                )?;
                store.set_pending_generation(
                    &request.source,
                    &publication.revision,
                    &twin.generation_id,
                )?;
                twin
            }
        };
        if twin.embedding_model != request.embedding_model {
            return Err(BrainError::StaleAuthority {
                authority: "embedding_model",
                detail: format!(
                    "a pending backfill for source {} already binds model {}; a different                      model is a different job, never a silent rebind",
                    request.source.as_str(),
                    twin.embedding_model.as_str()
                ),
            });
        }
        let total = self
            .index
            .chunk_count(&twin.generation_id)?
            .ok_or_else(|| BrainError::Corrupt {
                component: "brain-index-store",
                reason: "the restamped generation has no chunk rows".to_owned(),
            })?;
        let mut staged = store.staged_vector_count(&twin.generation_id)?;
        let mut batches = 0_u64;
        let mut unavailable: Option<String> = None;
        while staged < total {
            if request
                .max_batches
                .is_some_and(|budget| batches >= budget as u64)
            {
                break;
            }
            let from = staged;
            let to = (from + request.batch_size as u64).min(total);
            let chunk_texts = self
                .index
                .chunk_texts_in_range(&twin.generation_id, from, to)?;
            let texts: Vec<String> = chunk_texts
                .iter()
                .map(|(_, _, text)| text.clone())
                .collect();
            match lane.embed_batch(&texts) {
                Ok(vectors) => {
                    if vectors.len() != chunk_texts.len() {
                        return Err(BrainError::InvalidRequest(format!(
                            "embedding lane returned {} vectors for {} texts",
                            vectors.len(),
                            chunk_texts.len()
                        )));
                    }
                    let staged_rows: Vec<(u64, String, Vec<u8>)> = chunk_texts
                        .iter()
                        .zip(vectors.iter())
                        .map(|((ordinal, chunk_id, _), vector)| {
                            let dims: Vec<u8> = vector
                                .dims()
                                .iter()
                                .copied()
                                .flat_map(f32::to_le_bytes)
                                .collect();
                            (*ordinal, chunk_id.clone(), dims)
                        })
                        .collect();
                    store.stage_vectors(&twin.generation_id, &staged_rows)?;
                    staged = to;
                }
                Err(BrainError::EmbeddingUnavailable { reason, .. }) => {
                    unavailable = Some(reason);
                    break;
                }
                Err(error) => return Err(error),
            }
            batches += 1;
        }
        if staged < total {
            let reason = unavailable.unwrap_or_else(|| {
                format!(
                    "backfill batch budget exhausted after {batches} batches; \
                     staged {staged} of {total} chunks"
                )
            });
            return Ok(ArchiveEmbeddingBackfillReport {
                source: request.source.clone(),
                generation: twin,
                embedding_model: request.embedding_model.clone(),
                vectors_staged: staged,
                outcome: ArchiveBackfillOutcome::LexicalOnly {
                    reason,
                    pending: total - staged,
                },
            });
        }
        // The pool is complete: move it into the model-stamped generation in
        // one verified transaction, then rebind the publication and clear
        // the staging rows. A crash between the pool move and the rebind
        // leaves the pool stored and staged rows intact, so the retry sees
        // a complete pool and only rebinds; the publication still serves
        // the lexical generation until then.
        let mut staged_vectors = store.staged_vector_cursor(&twin.generation_id);
        self.index.store_vectors_stream(
            &twin.generation_id,
            &request.embedding_model,
            &mut staged_vectors,
        )?;
        // Rebind first (guarded by the expected revision), clear staging
        // after: a crash between the two leaves the pool stored and staged
        // rows intact, so the retry observes a complete pool and only
        // rebinds — durable progress survives, exactly as documented.
        store.rebind_publication(
            &request.source,
            &publication.revision,
            &twin.generation_id,
            &request.embedding_model,
            total,
            epoch_secs()?,
        )?;
        store.clear_staged_vectors(&twin.generation_id)?;
        self.audit.record(BrainAuditEvent {
            kind: AUDIT_KIND_ARCHIVE_EMBEDDED,
            actor: odin_domain::Actor::System {
                name: "odin-brain".to_owned(),
            },
            scope: odin_domain::Scope::default(),
            payload: serde_json::json!({
                "source": request.source.as_str(),
                "generationId": twin.generation_id.to_string(),
                "embeddingModel": request.embedding_model.as_str(),
                "vectors": total,
            }),
            evidence: Vec::new(),
            binding: Some(self.policy.policy_digest),
        })?;
        Ok(ArchiveEmbeddingBackfillReport {
            source: request.source.clone(),
            generation: twin,
            embedding_model: request.embedding_model.clone(),
            vectors_staged: staged,
            outcome: ArchiveBackfillOutcome::Embedded,
        })
    }
}
