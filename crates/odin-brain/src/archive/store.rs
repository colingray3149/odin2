//! The archive store: one SQLite database of declared sources, staged
//! normalized records, revision manifests, publications, and vector staging.
//!
//! Durable progress is the staging contract: batches commit as they land
//! and record rows are `INSERT OR IGNORE`, so an interrupted ingest resumes
//! by re-streaming (duplicates are counted, never re-inserted) and a
//! finished ingest re-run against unchanged content adds zero rows.
//! Publication — the only point where a revision becomes servable — flips
//! in one transaction with the job's terminal state and only after the
//! index generation it names is stored and verified.

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::{Mutex, MutexGuard};

use odin_domain::knowledge::archive::{ArchivePrivacyClass, ArchiveSourceDeclaration};
use odin_domain::knowledge::ids::{AtlasId, EmbeddingModelId, IndexGenerationId, KnowledgeItemId};
use odin_domain::Digest;
use rusqlite::{params, Connection, OptionalExtension};
use time::format_description::well_known::Rfc3339;

use crate::error::{BrainError, BrainResult};
use crate::source::archive::ArchiveRecordKind;

use super::{kind_token, parse_kind, parse_privacy, privacy_token};

/// Bound on one identity lookup. A full page is reported to the caller,
/// which must not pick from it: parts of one logical record are legitimate
/// (a segmented message shares its message id), several logical records are
/// ambiguity.
pub const MAX_IDENTITY_RECORDS: usize = 64;

/// Bound on how many identity pages one literal may be paged through before
/// the caller must treat it as unresolvable: uniqueness is never concluded
/// from a truncated page.
pub const MAX_IDENTITY_PAGES: usize = 8;

/// The identity metadata of one published record, without its text.
#[derive(Clone, Debug)]
pub struct ArchiveIdentity {
    pub item_id: KnowledgeItemId,
    pub natural_key: String,
    pub message_id: Option<String>,
    pub thread_id: Option<String>,
    pub conversation_id: Option<String>,
    pub created_at: Option<time::OffsetDateTime>,
    /// 1-based ordinals of a segmented record, `None` on whole records.
    pub part_index: Option<u32>,
    pub part_count: Option<u32>,
}

/// One declared archive source as persisted at open.
#[derive(Clone, Debug)]
pub struct DeclaredArchiveSource {
    /// The operator declaration exactly as wired (canonical JSON round-trip).
    pub declaration: ArchiveSourceDeclaration,
    /// Canonical digest of the declaration; approvals bind this value.
    pub declaration_digest: Digest,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ArchiveJobState {
    /// Records are being staged; progress counters advance durably.
    Staging,
    /// The revision was published atomically with this terminal state.
    Published,
    /// Nothing was published; retry requires a new approved operation.
    Failed,
}

impl ArchiveJobState {
    fn token(self) -> &'static str {
        match self {
            Self::Staging => "staging",
            Self::Published => "published",
            Self::Failed => "failed",
        }
    }

    fn parse(token: &str) -> BrainResult<Self> {
        match token {
            "staging" => Ok(Self::Staging),
            "published" => Ok(Self::Published),
            "failed" => Ok(Self::Failed),
            _ => Err(corrupt(format!("stored job state {token} is unknown"))),
        }
    }
}

/// One durable ingest job row (metadata and counters only, never content).
#[derive(Clone, Debug)]
pub struct ArchiveJobRow {
    pub job_id: String,
    pub source: AtlasId,
    pub approval_demand: String,
    pub approval_id: String,
    pub approval_command: String,
    pub content_revision: Option<Digest>,
    pub state: ArchiveJobState,
    pub records_seen: u64,
    pub records_staged: u64,
    pub records_duplicate: u64,
    pub skip_reasons: BTreeMap<String, u64>,
    pub updated_epoch: u64,
}

/// The published, servable state of one archive source.
#[derive(Clone, Debug)]
pub struct ArchivePublicationRow {
    pub source: AtlasId,
    pub revision: Digest,
    pub generation_id: IndexGenerationId,
    /// `None` is the lexical-only posture: complete and servable, with
    /// every chunk pending embedding until a backfill flips it.
    pub embedding_model: Option<EmbeddingModelId>,
    /// The model-stamped twin a backfill is currently filling; `None` when
    /// no backfill is in flight. Durable progress observable while lexical.
    pub pending_generation: Option<IndexGenerationId>,
    pub records: u64,
    pub chunks: u64,
    pub published_epoch: u64,
}

/// One normalized record exactly as staged (text included; callers stream
/// one at a time and must not accumulate).
#[derive(Clone, Debug)]
pub struct StoredArchiveRecord {
    pub record_key: Digest,
    pub item_id: KnowledgeItemId,
    pub natural_key: String,
    pub kind: ArchiveRecordKind,
    pub namespace: String,
    pub privacy_class: ArchivePrivacyClass,
    /// Export/account owner when the export names one; `None` for formats
    /// without account identity (mbox). Never invented.
    pub export_account: Option<String>,
    /// Segmentation identity for oversized records split into parts:
    /// 1-based index and total part count; `None` for whole records.
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
    /// Format-specific export metadata carried verbatim; empty for
    /// formats that declare none and for rows staged before the column
    /// existed.
    pub export_metadata: BTreeMap<String, serde_json::Value>,
    /// Original asset locator, when the record carries one. `None` for
    /// records without a locator and for rows staged before the column
    /// existed.
    pub origin: Option<crate::source::archive::ArchiveAssetOrigin>,
    pub text_digest: Digest,
    pub text: String,
}

/// Outcome of staging one batch.
#[derive(Clone, Copy, Debug, Default)]
pub struct ArchiveStageOutcome {
    /// Records newly persisted (new content addressing).
    pub inserted: u64,
    /// Records already staged by an earlier run (resume dedupe).
    pub duplicates: u64,
}

/// Durable normalized archive record store over one SQLite database.
pub struct ArchiveStore {
    connection: Mutex<Connection>,
}

/// One page of a literal's identity matches in one source revision.
const IDENTITY_RECORDS_SQL: &str =
    "SELECT DISTINCT r.item_id, r.natural_key, r.message_id, r.thread_id,
                    r.conversation_id, r.created_at, r.part_index, r.part_count
             FROM archive_record r CROSS JOIN archive_revision_record v
             WHERE ((r.source_id = ?2 AND r.natural_key = ?4)
                    OR (r.source_id = ?2 AND r.message_id = ?4)
                    OR (r.source_id = ?2 AND r.thread_id = ?4)
                    OR (r.source_id = ?2 AND r.conversation_id = ?4))
               AND r.kind = ?3
               AND v.source_id = r.source_id AND v.record_key = r.record_key
               AND v.revision = ?1
             ORDER BY r.item_id
             LIMIT ?5";

impl ArchiveStore {
    const SCHEMA: &'static str = "
        CREATE TABLE IF NOT EXISTS archive_source (
            source_id          TEXT PRIMARY KEY,
            memory_namespace   TEXT NOT NULL,
            privacy_class      TEXT NOT NULL,
            declaration_digest TEXT NOT NULL,
            declaration_json   TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS archive_ingest_job (
            job_id            TEXT PRIMARY KEY,
            source_id         TEXT NOT NULL,
            approval_demand   TEXT NOT NULL,
            approval_id       TEXT NOT NULL,
            approval_command  TEXT NOT NULL DEFAULT '',
            content_revision  TEXT,
            state             TEXT NOT NULL,
            records_seen      INTEGER NOT NULL DEFAULT 0,
            records_staged    INTEGER NOT NULL DEFAULT 0,
            records_duplicate INTEGER NOT NULL DEFAULT 0,
            skip_reasons      TEXT NOT NULL DEFAULT '{}',
            created_epoch     INTEGER NOT NULL,
            updated_epoch     INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS archive_record (
            source_id       TEXT NOT NULL,
            record_key      TEXT NOT NULL,
            item_id         TEXT NOT NULL,
            natural_key     TEXT NOT NULL,
            kind            TEXT NOT NULL,
            namespace       TEXT NOT NULL,
            privacy_class   TEXT NOT NULL,
            export_account  TEXT,
            part_index      INTEGER,
            part_count      INTEGER,
            export_id       TEXT,
            conversation_id TEXT,
            message_id      TEXT,
            thread_id       TEXT,
            export_metadata TEXT,
            created_at      TEXT,
            sent_by_user    INTEGER NOT NULL,
            labels          TEXT NOT NULL,
            rule_flags      TEXT NOT NULL,
            origin          TEXT,
            text_digest     TEXT NOT NULL,
            text            TEXT NOT NULL,
            first_seen_epoch INTEGER NOT NULL,
            PRIMARY KEY (source_id, record_key)
        );
        CREATE TABLE IF NOT EXISTS archive_revision_record (
            revision   TEXT NOT NULL,
            source_id  TEXT NOT NULL,
            ordinal    INTEGER NOT NULL,
            record_key TEXT NOT NULL,
            PRIMARY KEY (revision, ordinal)
        );
        -- Identity lookups probe one index per identity column and prove
        -- revision membership from a covering index: an addressed recall
        -- costs the same for a hundred records or a whole history.
        CREATE INDEX IF NOT EXISTS archive_record_natural_key
            ON archive_record(source_id, natural_key);
        CREATE INDEX IF NOT EXISTS archive_record_message_id
            ON archive_record(source_id, message_id);
        CREATE INDEX IF NOT EXISTS archive_record_thread_id
            ON archive_record(source_id, thread_id);
        CREATE INDEX IF NOT EXISTS archive_record_conversation_id
            ON archive_record(source_id, conversation_id);
        CREATE INDEX IF NOT EXISTS archive_revision_member
            ON archive_revision_record(source_id, record_key, revision);
        CREATE TABLE IF NOT EXISTS archive_publication (
            source_id       TEXT PRIMARY KEY,
            revision        TEXT NOT NULL,
            generation_id   TEXT NOT NULL,
            embedding_state TEXT NOT NULL,
            embedding_model TEXT,
            pending_generation TEXT,
            records         INTEGER NOT NULL,
            chunks          INTEGER NOT NULL,
            published_epoch INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS archive_vector_stage (
            generation_id TEXT NOT NULL,
            ordinal       INTEGER NOT NULL,
            chunk_id      TEXT NOT NULL,
            dims          BLOB NOT NULL,
            PRIMARY KEY (generation_id, ordinal)
        );
    ";

    /// Opens (creating if needed) the archive database at
    /// `<root>/brain-archive.sqlite3`.
    pub fn open(root: &Path) -> BrainResult<Self> {
        std::fs::create_dir_all(root).map_err(|error| BrainError::Unavailable {
            component: "brain-archive-store",
            reason: format!("cannot create archive root {}: {error}", root.display()),
        })?;
        let connection = crate::sqlite::open(&root.join("brain-archive.sqlite3"))?;
        connection.execute_batch(Self::SCHEMA)?;
        // Column migration for stores opened before the backfill-progress
        // marker existed; fresh stores already have the column.
        let has_pending: Option<String> = connection
            .query_row(
                "SELECT name FROM pragma_table_info('archive_publication') WHERE name = 'pending_generation'",
                [],
                |row| row.get(0),
            )
            .optional()?;
        if has_pending.is_none() {
            connection.execute_batch(
                "ALTER TABLE archive_publication ADD COLUMN pending_generation TEXT",
            )?;
        }
        // Column migration for stores opened before asset origin locators
        // existed; fresh stores already have the column. Old rows read
        // back as `None` — their identities are untouched.
        let has_origin: Option<String> = connection
            .query_row(
                "SELECT name FROM pragma_table_info('archive_record') WHERE name = 'origin'",
                [],
                |row| row.get(0),
            )
            .optional()?;
        if has_origin.is_none() {
            connection.execute_batch("ALTER TABLE archive_record ADD COLUMN origin TEXT")?;
        }
        // Column migration for stores opened before format export
        // metadata existed; fresh stores already have the column. Old
        // rows read back as an empty map — their identities are untouched.
        let has_export_metadata: Option<String> = connection
            .query_row(
                "SELECT name FROM pragma_table_info('archive_record') WHERE name = 'export_metadata'",
                [],
                |row| row.get(0),
            )
            .optional()?;
        if has_export_metadata.is_none() {
            connection
                .execute_batch("ALTER TABLE archive_record ADD COLUMN export_metadata TEXT")?;
        }
        Ok(Self {
            connection: Mutex::new(connection),
        })
    }

    fn lock_connection(&self) -> BrainResult<MutexGuard<'_, Connection>> {
        self.connection
            .lock()
            .map_err(|_| corrupt("archive store connection mutex is poisoned"))
    }

    /// Persists one source's declaration at open. The memory namespace is
    /// unique across every declared archive source — the namespace↔source
    /// mapping is enforced. A re-declared source may move or change format;
    /// changing its namespace or privacy class is refused.
    pub fn declare_source(
        &self,
        source: &AtlasId,
        declaration: &ArchiveSourceDeclaration,
        declaration_digest: &Digest,
    ) -> BrainResult<()> {
        let connection = self.lock_connection()?;
        let existing_namespace: Option<String> = connection
            .query_row(
                "SELECT source_id FROM archive_source WHERE memory_namespace = ?1",
                params![declaration.memory_namespace.as_str()],
                |row| row.get(0),
            )
            .optional()?;
        if let Some(other) = existing_namespace {
            if other != source.as_str() {
                return Err(BrainError::InvalidPolicy(format!(
                    "archive memory namespace {} is already declared for source {other}",
                    declaration.memory_namespace
                )));
            }
        }
        let stored: Option<(String, String)> = connection
            .query_row(
                "SELECT declaration_digest, declaration_json FROM archive_source
                 WHERE source_id = ?1",
                params![source.as_str()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        let encoded = serde_json::to_string(declaration)?;
        if let Some((digest, json)) = stored {
            if digest == declaration_digest.to_string() && json == encoded {
                return Ok(());
            }
            // A moved or re-exported archive is the same source; its namespace and privacy class are not.
            let previous: ArchiveSourceDeclaration = serde_json::from_str(&json)?;
            if previous.memory_namespace != declaration.memory_namespace
                || previous.privacy_class != declaration.privacy_class
            {
                return Err(BrainError::InvalidPolicy(format!(
                    "archive source {} changed its memory namespace or privacy class; declare it as a new source",
                    source.as_str()
                )));
            }
            connection.execute(
                "UPDATE archive_source SET declaration_digest = ?2, declaration_json = ?3 WHERE source_id = ?1",
                params![source.as_str(), declaration_digest.to_string(), encoded],
            )?;
            tracing::info!(source = source.as_str(), path = %declaration.path.display(), "archive source declaration updated");
            return Ok(());
        }
        connection.execute(
            "INSERT INTO archive_source
                (source_id, memory_namespace, privacy_class, declaration_digest, declaration_json)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                source.as_str(),
                declaration.memory_namespace.as_str(),
                privacy_token(declaration.privacy_class),
                declaration_digest.to_string(),
                encoded,
            ],
        )?;
        Ok(())
    }

    pub fn declared(&self, source: &AtlasId) -> BrainResult<Option<DeclaredArchiveSource>> {
        let connection = self.lock_connection()?;
        let stored: Option<(String, String)> = connection
            .query_row(
                "SELECT declaration_digest, declaration_json FROM archive_source
                 WHERE source_id = ?1",
                params![source.as_str()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        let Some((digest, json)) = stored else {
            return Ok(None);
        };
        let declaration: ArchiveSourceDeclaration = serde_json::from_str(&json)?;
        Ok(Some(DeclaredArchiveSource {
            declaration,
            declaration_digest: Digest::parse(&digest)
                .map_err(|_| corrupt("stored declaration digest is not canonical"))?,
        }))
    }

    /// Resumes staging only with identical approval evidence; terminal jobs
    /// and keys reused with different evidence are rejected.
    pub fn create_job(
        &self,
        job_id: &str,
        source: &AtlasId,
        approval_demand: &str,
        approval_id: &str,
        approval_command: &str,
        epoch: u64,
    ) -> BrainResult<()> {
        let connection = self.lock_connection()?;
        let existing: Option<(String, String, String, String, String)> = connection
            .query_row(
                "SELECT source_id, approval_demand, approval_id, approval_command, state
                 FROM archive_ingest_job WHERE job_id = ?1",
                params![job_id],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                    ))
                },
            )
            .optional()?;
        if let Some((existing_source, demand, approval, command, state)) = existing {
            let same_binding = existing_source == source.as_str()
                && demand == approval_demand
                && approval == approval_id
                && command == approval_command;
            if !same_binding {
                return Err(BrainError::InvalidRequest(format!(
                    "archive ingest idempotency key {job_id} was already used with \
                     different approval evidence"
                )));
            }
            // Terminal jobs are terminal forever. A published job reaches
            // this point only when the publication has since MOVED past its
            // revision (otherwise the caller's idempotent no-op path
            // returned first): the job is superseded and can never
            // republish its old revision. A failed job is over; even a
            // byte-restored export requires a new approved operation. Only
            // a still-staging job resumes in place.
            return match ArchiveJobState::parse(&state)? {
                ArchiveJobState::Staging => Ok(()),
                ArchiveJobState::Published => Err(BrainError::InvalidRequest(format!(
                    "archive ingest job {job_id} is a terminal published run whose revision \
                     was superseded; a terminal job can never republish — run prepare and \
                     approve a new operation for the current content"
                ))),
                ArchiveJobState::Failed => Err(BrainError::InvalidRequest(format!(
                    "archive ingest job {job_id} is a terminal failed run; even a restored \
                     export requires a new approved operation, never a revival"
                ))),
            };
        }
        connection
            .execute(
                "INSERT INTO archive_ingest_job
                (job_id, source_id, approval_demand, approval_id, approval_command,
                 state, created_epoch, updated_epoch)
             VALUES (?1, ?2, ?3, ?4, ?5, 'staging', ?6, ?6)",
                params![
                    job_id,
                    source.as_str(),
                    approval_demand,
                    approval_id,
                    approval_command,
                    epoch as i64
                ],
            )
            .map_err(|error| match error {
                rusqlite::Error::SqliteFailure(error, _)
                    if error.code == rusqlite::ErrorCode::ConstraintViolation =>
                {
                    BrainError::InvalidRequest(format!(
                        "archive ingest idempotency key {job_id} was already used"
                    ))
                }
                other => BrainError::Storage(other),
            })?;
        Ok(())
    }

    /// Durable progress update for one staging run (counts only; the
    /// authoritative skip accounting is the parser summary in the ingest
    /// report).
    pub fn update_job_progress(
        &self,
        job_id: &str,
        records_seen: u64,
        records_staged: u64,
        records_duplicate: u64,
        epoch: u64,
    ) -> BrainResult<()> {
        let connection = self.lock_connection()?;
        connection.execute(
            "UPDATE archive_ingest_job
             SET records_seen = ?2, records_staged = ?3, records_duplicate = ?4,
                 updated_epoch = ?5
             WHERE job_id = ?1",
            params![
                job_id,
                records_seen as i64,
                records_staged as i64,
                records_duplicate as i64,
                epoch as i64,
            ],
        )?;
        Ok(())
    }

    /// Transitions one job to its terminal state, binding the observed
    /// content revision. Terminal states are never revived: this is only
    /// reachable while the job is staging, enforced by the caller.
    pub fn finish_job(
        &self,
        job_id: &str,
        content_revision: &Digest,
        state: ArchiveJobState,
        epoch: u64,
    ) -> BrainResult<()> {
        let connection = self.lock_connection()?;
        connection.execute(
            "UPDATE archive_ingest_job
             SET content_revision = ?2, state = ?3, updated_epoch = ?4
             WHERE job_id = ?1",
            params![
                job_id,
                content_revision.to_string(),
                state.token(),
                epoch as i64
            ],
        )?;
        Ok(())
    }

    /// The most recent job for one source, newest first by creation.
    pub fn last_job(&self, source: &AtlasId) -> BrainResult<Option<ArchiveJobRow>> {
        let connection = self.lock_connection()?;
        let row = connection
            .query_row(
                "SELECT job_id, approval_demand, approval_id, approval_command,
                        content_revision, state,
                        records_seen, records_staged, records_duplicate, skip_reasons,
                        updated_epoch
                 FROM archive_ingest_job WHERE source_id = ?1
                 ORDER BY created_epoch DESC, job_id DESC LIMIT 1",
                params![source.as_str()],
                job_from_row,
            )
            .optional()?;
        row.map(|row| parse_job_row(row, source)).transpose()
    }

    /// Stages one batch of records in a single transaction: record rows are
    /// `INSERT OR IGNORE` (content-addressed resume dedupe) and EVERY
    /// record joins the revision manifest at its stream ordinal — the
    /// membership insert is unconditional and independently idempotent, so
    /// a new revision whose records were already cached (unchanged content
    /// from an earlier revision or a failed attempt) still gains complete
    /// membership. `inserted` counts records newly added to THIS revision's
    /// membership; `duplicates` counts records the revision already had.
    pub fn stage_records(
        &self,
        source: &AtlasId,
        revision: &Digest,
        records: &[(&Digest, &crate::archive::PreparedArchiveRecord)],
        epoch: u64,
    ) -> BrainResult<ArchiveStageOutcome> {
        let connection = self.lock_connection()?;
        let tx = crate::sqlite::write_transaction(&connection)?;
        let mut outcome = ArchiveStageOutcome::default();
        for (record_key, record) in records {
            // The record row is content-addressed; its row count is not the
            // accounting key (membership below is). `INSERT OR IGNORE` makes
            // a rerun of identical content a zero-row write.
            tx.execute(
                "INSERT OR IGNORE INTO archive_record
                    (source_id, record_key, item_id, natural_key, kind, namespace,
                     privacy_class, export_account, part_index, part_count,
                     export_id, conversation_id,
                     message_id, thread_id, created_at, sent_by_user, labels,
                     rule_flags, export_metadata, origin, text_digest, text, first_seen_epoch)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13,
                         ?14, ?15, ?16, ?17, ?18, ?19, ?20, ?21, ?22, ?23)",
                params![
                    source.as_str(),
                    record_key.to_string(),
                    record.item_id.to_string(),
                    record.natural_key.as_str(),
                    kind_token(record.kind),
                    record.namespace.as_str(),
                    privacy_token(record.privacy_class),
                    record.export_account.as_deref(),
                    record.part_index.map(|part| part as i64),
                    record.part_count.map(|count| count as i64),
                    record.export_id.as_deref(),
                    record.conversation_id.as_deref(),
                    record.message_id.as_deref(),
                    record.thread_id.as_deref(),
                    record
                        .created_at
                        .map(|at| at.format(&Rfc3339))
                        .transpose()
                        .map_err(|error| {
                            BrainError::InvalidRequest(format!(
                                "record timestamp cannot format: {error}"
                            ))
                        })?
                        .as_deref(),
                    record.sent_by_user as i64,
                    record.labels.join("\0"),
                    record.rule_flags.join("\0"),
                    // NULL for an empty map: rows without format metadata
                    // keep the exact legacy row shape, and a NULL decodes
                    // back to the empty map below.
                    if record.export_metadata.is_empty() {
                        None
                    } else {
                        Some(
                            serde_json::to_string(&record.export_metadata).map_err(|error| {
                                BrainError::InvalidRequest(format!(
                                    "record export metadata cannot serialize: {error}"
                                ))
                            })?,
                        )
                    },
                    record
                        .origin
                        .as_ref()
                        .map(serde_json::to_string)
                        .transpose()
                        .map_err(|error| {
                            BrainError::InvalidRequest(format!(
                                "record origin cannot serialize: {error}"
                            ))
                        })?
                        .as_deref(),
                    record.text_digest.to_string(),
                    record.text.as_str(),
                    epoch as i64,
                ],
            )?;
            // Membership is unconditional: even a fully cached record joins
            // THIS revision at its ordinal, so a new revision over partly
            // unchanged content gains complete membership. The insert is
            // idempotent per (revision, ordinal) — a retried run replays
            // identical rows and counts them as duplicates.
            let joined = tx.execute(
                "INSERT OR IGNORE INTO archive_revision_record
                    (revision, source_id, ordinal, record_key)
                 VALUES (?1, ?2, ?3, ?4)",
                params![
                    revision.to_string(),
                    source.as_str(),
                    record.ordinal as i64,
                    record_key.to_string(),
                ],
            )?;
            if joined > 0 {
                outcome.inserted += 1;
            } else {
                outcome.duplicates += 1;
            }
        }
        tx.commit()?;
        Ok(outcome)
    }

    /// The published serving state of one source, if a revision was ever
    /// approved and published.
    pub fn publication(&self, source: &AtlasId) -> BrainResult<Option<ArchivePublicationRow>> {
        let connection = self.lock_connection()?;
        let row = connection
            .query_row(
                "SELECT revision, generation_id, embedding_state, embedding_model,
                        pending_generation, records, chunks, published_epoch
                 FROM archive_publication WHERE source_id = ?1",
                params![source.as_str()],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, Option<String>>(3)?,
                        row.get::<_, Option<String>>(4)?,
                        row.get::<_, i64>(5)?,
                        row.get::<_, i64>(6)?,
                        row.get::<_, i64>(7)?,
                    ))
                },
            )
            .optional()?;
        let Some((revision, generation, state, model, pending, records, chunks, epoch)) = row
        else {
            return Ok(None);
        };
        let embedding_model = match (state.as_str(), model) {
            ("embedded", Some(model)) => Some(
                EmbeddingModelId::new(&model)
                    .map_err(|_| corrupt("stored embedding model id is invalid"))?,
            ),
            ("lexical", None) => None,
            _ => {
                return Err(corrupt(
                    "stored publication embedding state is inconsistent",
                ))
            }
        };
        Ok(Some(ArchivePublicationRow {
            source: source.clone(),
            revision: Digest::parse(&revision)
                .map_err(|_| corrupt("stored publication revision is not canonical"))?,
            generation_id: IndexGenerationId::parse(&generation)
                .map_err(|_| corrupt("stored publication generation id is not canonical"))?,
            embedding_model,
            pending_generation: pending
                .map(|pending| {
                    IndexGenerationId::parse(&pending)
                        .map_err(|_| corrupt("stored pending generation id is not canonical"))
                })
                .transpose()?,
            records: records as u64,
            chunks: chunks as u64,
            published_epoch: epoch as u64,
        }))
    }

    /// Atomically publishes one approved revision: the publication pointer
    /// and the job's terminal state commit or roll back together, and a
    /// publication can never point at an unpublished generation (the caller
    /// stores and verifies the generation first). A later ingest under a
    /// new approval replaces the pointer — the new approval is exactly what
    /// authorizes moving the served revision; a re-run of the identical
    /// revision is filtered out by the caller long before this point.
    #[allow(clippy::too_many_arguments)]
    pub fn publish(
        &self,
        source: &AtlasId,
        revision: &Digest,
        generation_id: &IndexGenerationId,
        records: u64,
        chunks: u64,
        embedding_model: Option<&EmbeddingModelId>,
        job_id: &str,
        epoch: u64,
    ) -> BrainResult<()> {
        let connection = self.lock_connection()?;
        let tx = crate::sqlite::write_transaction(&connection)?;
        let (state, model) = match embedding_model {
            Some(model) => ("embedded", Some(model.as_str())),
            None => ("lexical", None),
        };
        tx.execute(
            "INSERT INTO archive_publication
                (source_id, revision, generation_id, embedding_state, embedding_model,
                 records, chunks, published_epoch)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
             ON CONFLICT(source_id) DO UPDATE SET
                revision = excluded.revision,
                generation_id = excluded.generation_id,
                embedding_state = excluded.embedding_state,
                embedding_model = excluded.embedding_model,
                records = excluded.records,
                chunks = excluded.chunks,
                published_epoch = excluded.published_epoch",
            params![
                source.as_str(),
                revision.to_string(),
                generation_id.to_string(),
                state,
                model,
                records as i64,
                chunks as i64,
                epoch as i64,
            ],
        )?;
        let terminal = tx.execute(
            "UPDATE archive_ingest_job
             SET content_revision = ?2, state = 'published', updated_epoch = ?3
             WHERE job_id = ?1",
            params![job_id, revision.to_string(), epoch as i64],
        )?;
        if terminal == 0 {
            // A publication and its job's terminal state commit together or
            // not at all: naming a job that has no durable ingest row would
            // publish without the terminal state that makes the run
            // replayable, so it refuses typed instead.
            return Err(BrainError::InvalidRequest(format!(
                "archive publication for {} names ingest job {job_id}, which has no durable row",
                source.as_str()
            )));
        }
        tx.commit()?;
        Ok(())
    }

    /// Marks the model-stamped twin a backfill is filling, guarded by the
    /// expected revision: the publication stays bound to the lexical
    /// generation while vectors stage, and a concurrent ingest that moved
    /// the revision refuses this marker typed.
    pub fn set_pending_generation(
        &self,
        source: &AtlasId,
        expected_revision: &Digest,
        generation_id: &IndexGenerationId,
    ) -> BrainResult<()> {
        let connection = self.lock_connection()?;
        let updated = connection.execute(
            "UPDATE archive_publication
             SET pending_generation = ?2
             WHERE source_id = ?1 AND revision = ?3",
            params![
                source.as_str(),
                generation_id.to_string(),
                expected_revision.to_string(),
            ],
        )?;
        if updated == 0 {
            return Err(BrainError::StaleAuthority {
                authority: "archive_publication",
                detail: format!(
                    "source {} publication moved past revision {}; a concurrent ingest                      superseded this backfill",
                    source.as_str(),
                    expected_revision
                ),
            });
        }
        Ok(())
    }

    /// Rebinds an existing publication to a new generation (the embedding
    /// backfill's model-stamped twin), one transaction, same revision.
    /// The update is guarded by the expected revision: a concurrent ingest
    /// that moved the publication meanwhile leaves zero rows matched, which
    /// is a typed stale-authority failure — a backfill can never overwrite
    /// a newer approved revision's pointer.
    pub fn rebind_publication(
        &self,
        source: &AtlasId,
        expected_revision: &Digest,
        generation_id: &IndexGenerationId,
        embedding_model: &EmbeddingModelId,
        chunks: u64,
        epoch: u64,
    ) -> BrainResult<()> {
        let connection = self.lock_connection()?;
        let updated = connection.execute(
            "UPDATE archive_publication
             SET generation_id = ?2, embedding_state = 'embedded',
                 embedding_model = ?3, chunks = ?4, published_epoch = ?5,
                 pending_generation = NULL
             WHERE source_id = ?1 AND revision = ?6",
            params![
                source.as_str(),
                generation_id.to_string(),
                embedding_model.as_str(),
                chunks as i64,
                epoch as i64,
                expected_revision.to_string(),
            ],
        )?;
        if updated == 0 {
            return Err(BrainError::StaleAuthority {
                authority: "archive_publication",
                detail: format!(
                    "source {} publication moved past revision {}; a concurrent ingest                      superseded this backfill",
                    source.as_str(),
                    expected_revision
                ),
            });
        }
        Ok(())
    }
    /// Streams the exact records of one revision in ordinal order; the
    /// callback consumes one record at a time and must not accumulate.
    pub fn for_each_revision_record(
        &self,
        source: &AtlasId,
        revision: &Digest,
        visit: &mut dyn FnMut(StoredArchiveRecord) -> BrainResult<()>,
    ) -> BrainResult<()> {
        let connection = self.lock_connection()?;
        let mut statement = connection.prepare(
            "SELECT r.record_key, r.item_id, r.natural_key, r.kind, r.namespace,
                    r.privacy_class, r.export_account, r.part_index, r.part_count,
                    r.export_id, r.conversation_id,
                    r.message_id, r.thread_id, r.created_at, r.sent_by_user,
                    r.labels, r.rule_flags, r.text_digest, r.text, r.origin,
                    r.export_metadata
             FROM archive_revision_record v
             JOIN archive_record r ON r.source_id = v.source_id
                                  AND r.record_key = v.record_key
             WHERE v.revision = ?1 AND v.source_id = ?2
             ORDER BY v.ordinal",
        )?;
        let rows = statement.query_map(params![revision.to_string(), source.as_str()], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, String>(5)?,
                row.get::<_, Option<String>>(6)?,
                row.get::<_, Option<i64>>(7)?,
                row.get::<_, Option<i64>>(8)?,
                row.get::<_, Option<String>>(9)?,
                row.get::<_, Option<String>>(10)?,
                row.get::<_, Option<String>>(11)?,
                row.get::<_, Option<String>>(12)?,
                row.get::<_, Option<String>>(13)?,
                row.get::<_, i64>(14)?,
                row.get::<_, String>(15)?,
                row.get::<_, String>(16)?,
                row.get::<_, String>(17)?,
                row.get::<_, String>(18)?,
                row.get::<_, Option<String>>(19)?,
                row.get::<_, Option<String>>(20)?,
            ))
        })?;
        for row in rows {
            let row = row?;
            visit(record_from_row(row)?)?;
        }
        Ok(())
    }

    /// The exact staged record for one item of one revision — the citation
    /// expansion path. `Ok(None)` means the revision has no such item.
    pub fn record_for_item(
        &self,
        source: &AtlasId,
        revision: &Digest,
        item_id: &KnowledgeItemId,
    ) -> BrainResult<Option<StoredArchiveRecord>> {
        let connection = self.lock_connection()?;
        let row = connection
            .query_row(
                "SELECT r.record_key, r.item_id, r.natural_key, r.kind, r.namespace,
                        r.privacy_class, r.export_account, r.part_index, r.part_count,
                        r.export_id,
                        r.conversation_id, r.message_id, r.thread_id, r.created_at,
                        r.sent_by_user, r.labels, r.rule_flags, r.text_digest, r.text,
                        r.origin, r.export_metadata
                 FROM archive_revision_record v
                 JOIN archive_record r ON r.source_id = v.source_id
                                      AND r.record_key = v.record_key
                 WHERE v.revision = ?1 AND v.source_id = ?2 AND r.item_id = ?3
                 LIMIT 1",
                params![revision.to_string(), source.as_str(), item_id.to_string()],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, String>(4)?,
                        row.get::<_, String>(5)?,
                        row.get::<_, Option<String>>(6)?,
                        row.get::<_, Option<i64>>(7)?,
                        row.get::<_, Option<i64>>(8)?,
                        row.get::<_, Option<String>>(9)?,
                        row.get::<_, Option<String>>(10)?,
                        row.get::<_, Option<String>>(11)?,
                        row.get::<_, Option<String>>(12)?,
                        row.get::<_, Option<String>>(13)?,
                        row.get::<_, i64>(14)?,
                        row.get::<_, String>(15)?,
                        row.get::<_, String>(16)?,
                        row.get::<_, String>(17)?,
                        row.get::<_, String>(18)?,
                        row.get::<_, Option<String>>(19)?,
                        row.get::<_, Option<String>>(20)?,
                    ))
                },
            )
            .optional()?;
        row.map(record_from_row).transpose()
    }

    /// The exact item identity of one published record of one revision — the
    /// record-selector resolution path (`brain://record.blake3:<hex>`). The
    /// item id is the record's own stored identity column, never derived
    /// from chunk content. `Ok(None)` means the revision does not publish a
    /// record under this key.
    pub fn item_for_record(
        &self,
        source: &AtlasId,
        revision: &Digest,
        record_key: &Digest,
    ) -> BrainResult<Option<KnowledgeItemId>> {
        let connection = self.lock_connection()?;
        let row = connection
            .query_row(
                "SELECT r.item_id
                 FROM archive_revision_record v
                 JOIN archive_record r ON r.source_id = v.source_id
                                      AND r.record_key = v.record_key
                 WHERE v.revision = ?1 AND v.source_id = ?2 AND v.record_key = ?3
                 LIMIT 1",
                params![
                    revision.to_string(),
                    source.as_str(),
                    record_key.to_string()
                ],
                |row| row.get::<_, String>(0),
            )
            .optional()?;
        row.map(|item_id| {
            KnowledgeItemId::parse(&item_id).map_err(|_| corrupt("stored item id is not canonical"))
        })
        .transpose()
    }

    /// The distinct published records of one revision whose own identity or
    /// conversation equals `literal` exactly, restricted to one record class.
    ///
    /// Identity-addressed retrieval resolves here instead of through lexical
    /// scoring, which cannot see identity that lives only in these columns.
    /// Only identity metadata is projected — never record text — one closed
    /// predicate covers every identity column, and the comparison is exact
    /// and case-preserving: each format's ingest normalization (bracket
    /// stripping, case, timestamp precision) is the authority, so a literal
    /// still carrying transport punctuation or different case is a miss,
    /// never a fuzzy match. Rows are distinct identities ordered by item id;
    /// a full page ([`MAX_IDENTITY_RECORDS`]) is reported as such.
    pub fn identity_records(
        &self,
        source: &AtlasId,
        revision: &Digest,
        literal: &str,
        kind: ArchiveRecordKind,
    ) -> BrainResult<Vec<ArchiveIdentity>> {
        let connection = self.lock_connection()?;
        let mut statement = connection.prepare_cached(IDENTITY_RECORDS_SQL)?;
        let rows = statement.query_map(
            params![
                revision.to_string(),
                source.as_str(),
                kind_token(kind),
                literal,
                MAX_IDENTITY_RECORDS as i64,
            ],
            identity_row,
        )?;
        let mut records = Vec::new();
        for row in rows {
            records.push(decode_identity(row?)?);
        }
        Ok(records)
    }

    /// [`ArchiveStore::identity_records`] continued after `after`: the next
    /// distinct identities in item-id order. Keyset paging, so a caller can
    /// exhaust one literal's matches instead of trusting a truncated page.
    pub fn identity_records_after(
        &self,
        source: &AtlasId,
        revision: &Digest,
        literal: &str,
        kind: ArchiveRecordKind,
        after: &KnowledgeItemId,
    ) -> BrainResult<Vec<ArchiveIdentity>> {
        let connection = self.lock_connection()?;
        let mut statement = connection.prepare_cached(
            "SELECT DISTINCT r.item_id, r.natural_key, r.message_id, r.thread_id,
                    r.conversation_id, r.created_at, r.part_index, r.part_count
             FROM archive_record r CROSS JOIN archive_revision_record v
             WHERE ((r.source_id = ?2 AND r.natural_key = ?4)
                    OR (r.source_id = ?2 AND r.message_id = ?4)
                    OR (r.source_id = ?2 AND r.thread_id = ?4)
                    OR (r.source_id = ?2 AND r.conversation_id = ?4))
               AND r.kind = ?3
               AND v.source_id = r.source_id AND v.record_key = r.record_key
               AND v.revision = ?1
               AND r.item_id > ?6
             ORDER BY r.item_id
             LIMIT ?5",
        )?;
        let rows = statement.query_map(
            params![
                revision.to_string(),
                source.as_str(),
                kind_token(kind),
                literal,
                MAX_IDENTITY_RECORDS as i64,
                after.to_string(),
            ],
            identity_row,
        )?;
        let mut records = Vec::new();
        for row in rows {
            records.push(decode_identity(row?)?);
        }
        Ok(records)
    }

    /// Stages one batch of embedding vectors (resumable, idempotent per
    /// ordinal) in a single transaction.
    pub fn stage_vectors(
        &self,
        generation_id: &IndexGenerationId,
        vectors: &[(u64, String, Vec<u8>)],
    ) -> BrainResult<()> {
        let connection = self.lock_connection()?;
        let tx = crate::sqlite::write_transaction(&connection)?;
        for (ordinal, chunk_id, dims) in vectors {
            tx.execute(
                "INSERT OR REPLACE INTO archive_vector_stage
                    (generation_id, ordinal, chunk_id, dims)
                 VALUES (?1, ?2, ?3, ?4)",
                params![generation_id.to_string(), *ordinal as i64, chunk_id, dims],
            )?;
        }
        tx.commit()?;
        Ok(())
    }

    pub fn staged_vector_count(&self, generation_id: &IndexGenerationId) -> BrainResult<u64> {
        let connection = self.lock_connection()?;
        let count = connection.query_row(
            "SELECT COUNT(*) FROM archive_vector_stage WHERE generation_id = ?1",
            params![generation_id.to_string()],
            |row| row.get::<_, i64>(0),
        )?;
        Ok(count as u64)
    }

    /// Drops one revision's membership rows after a failed ingest attempt
    /// (e.g. content moved after approval). Record rows stay: they are the
    /// content-addressed dedupe cache, keyed by record identity, not by
    /// revision.
    pub fn discard_revision(&self, source: &AtlasId, revision: &Digest) -> BrainResult<()> {
        let connection = self.lock_connection()?;
        connection.execute(
            "DELETE FROM archive_revision_record WHERE revision = ?1 AND source_id = ?2",
            params![revision.to_string(), source.as_str()],
        )?;
        Ok(())
    }

    /// Staged vectors for one half-open ordinal range, in ordinal order;
    /// the pool move pulls pages through this so the full pool never
    /// materializes in RAM.
    pub fn staged_vectors_range(
        &self,
        generation_id: &IndexGenerationId,
        from: u64,
        to: u64,
    ) -> BrainResult<Vec<(u64, String, Vec<f32>)>> {
        let connection = self.lock_connection()?;
        let mut statement = connection.prepare(
            "SELECT ordinal, chunk_id, dims FROM archive_vector_stage
             WHERE generation_id = ?1 AND ordinal >= ?2 AND ordinal < ?3
             ORDER BY ordinal",
        )?;
        let rows = statement.query_map(
            params![generation_id.to_string(), from as i64, to as i64],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                ))
            },
        )?;
        let mut vectors = Vec::new();
        for row in rows {
            let (ordinal, chunk_id, dims) = row?;
            if dims.len() % 4 != 0 {
                return Err(corrupt("staged vector dims are not a f32 run"));
            }
            let floats = dims
                .chunks_exact(4)
                .map(|chunk| f32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]))
                .collect();
            vectors.push((ordinal as u64, chunk_id, floats));
        }
        Ok(vectors)
    }

    /// A paged, bounded pull cursor over one generation's staged vectors:
    /// each page is read on demand, so the pool move streams without
    /// materializing every vector in RAM.
    pub fn staged_vector_cursor(
        &self,
        generation_id: &IndexGenerationId,
    ) -> StagedVectorCursor<'_> {
        StagedVectorCursor {
            store: self,
            generation_id: *generation_id,
            next_ordinal: 0,
            buffered: std::collections::VecDeque::new(),
            exhausted: false,
        }
    }

    /// Drops staged vectors after a completed pool move.
    pub fn clear_staged_vectors(&self, generation_id: &IndexGenerationId) -> BrainResult<()> {
        let connection = self.lock_connection()?;
        connection.execute(
            "DELETE FROM archive_vector_stage WHERE generation_id = ?1",
            params![generation_id.to_string()],
        )?;
        Ok(())
    }
}

type RawJobRow = (
    String,
    String,
    String,
    String,
    Option<String>,
    String,
    i64,
    i64,
    i64,
    String,
    i64,
);

fn job_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<RawJobRow> {
    Ok((
        row.get(0)?,
        row.get(1)?,
        row.get(2)?,
        row.get(3)?,
        row.get(4)?,
        row.get(5)?,
        row.get(6)?,
        row.get(7)?,
        row.get(8)?,
        row.get(9)?,
        row.get(10)?,
    ))
}

fn parse_job_row(row: RawJobRow, source: &AtlasId) -> BrainResult<ArchiveJobRow> {
    let (
        job_id,
        demand,
        approval,
        command,
        revision,
        state,
        seen,
        staged,
        duplicates,
        skips,
        epoch,
    ) = row;
    Ok(ArchiveJobRow {
        job_id,
        source: source.clone(),
        approval_demand: demand,
        approval_id: approval,
        approval_command: command,
        content_revision: revision
            .map(|value| Digest::parse(&value))
            .transpose()
            .map_err(|_| corrupt("stored job revision is not canonical"))?,
        state: ArchiveJobState::parse(&state)?,
        records_seen: seen as u64,
        records_staged: staged as u64,
        records_duplicate: duplicates as u64,
        skip_reasons: serde_json::from_str(&skips)?,
        updated_epoch: epoch as u64,
    })
}

type RawRecordRow = (
    String,
    String,
    String,
    String,
    String,
    String,
    Option<String>,
    Option<i64>,
    Option<i64>,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
    i64,
    String,
    String,
    String,
    String,
    Option<String>,
    Option<String>,
);

/// The identity projection's row shape, shared by every identity lookup.
type IdentityRow = (
    String,
    String,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<i64>,
    Option<i64>,
);

fn identity_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<IdentityRow> {
    Ok((
        row.get(0)?,
        row.get(1)?,
        row.get(2)?,
        row.get(3)?,
        row.get(4)?,
        row.get(5)?,
        row.get(6)?,
        row.get(7)?,
    ))
}

/// One decoded identity row: canonical ids and instants, part ordinals
/// bounded to their column type.
fn decode_identity(row: IdentityRow) -> BrainResult<ArchiveIdentity> {
    let (
        item_id,
        natural_key,
        message_id,
        thread_id,
        conversation_id,
        created_at,
        part_index,
        part_count,
    ) = row;
    let part = |value: Option<i64>, what: &str| -> BrainResult<Option<u32>> {
        value
            .map(|value| {
                u32::try_from(value)
                    .map_err(|_| corrupt(format!("stored part {what} is out of range")))
            })
            .transpose()
    };
    Ok(ArchiveIdentity {
        item_id: KnowledgeItemId::parse(&item_id)
            .map_err(|_| corrupt("stored item id is not canonical"))?,
        natural_key,
        message_id,
        thread_id,
        conversation_id,
        created_at: parse_instant(created_at)?,
        part_index: part(part_index, "index")?,
        part_count: part(part_count, "count")?,
    })
}

/// The one RFC 3339 decoder for stored instants, shared by whole-record and
/// identity-metadata reads so both reject a malformed value identically.
fn parse_instant(value: Option<String>) -> BrainResult<Option<time::OffsetDateTime>> {
    value
        .map(|value| time::OffsetDateTime::parse(&value, &Rfc3339))
        .transpose()
        .map_err(|_| corrupt("stored record timestamp is not RFC 3339"))
}

fn record_from_row(row: RawRecordRow) -> BrainResult<StoredArchiveRecord> {
    let (
        record_key,
        item_id,
        natural_key,
        kind,
        namespace,
        privacy,
        export_account,
        part_index,
        part_count,
        export_id,
        conversation_id,
        message_id,
        thread_id,
        created_at,
        sent_by_user,
        labels,
        rule_flags,
        text_digest,
        text,
        origin,
        export_metadata,
    ) = row;
    let created_at = parse_instant(created_at)?;
    Ok(StoredArchiveRecord {
        record_key: Digest::parse(&record_key)
            .map_err(|_| corrupt("stored record key is not canonical"))?,
        item_id: KnowledgeItemId::parse(&item_id)
            .map_err(|_| corrupt("stored item id is not canonical"))?,
        natural_key,
        kind: parse_kind(&kind)?,
        namespace,
        privacy_class: parse_privacy(&privacy)?,
        export_account,
        part_index: part_index.map(|part| part as u32),
        part_count: part_count.map(|count| count as u32),
        export_id,
        conversation_id,
        message_id,
        thread_id,
        created_at,
        sent_by_user: sent_by_user != 0,
        labels: if labels.is_empty() {
            Vec::new()
        } else {
            labels.split('\0').map(str::to_owned).collect()
        },
        rule_flags: if rule_flags.is_empty() {
            Vec::new()
        } else {
            rule_flags.split('\0').map(str::to_owned).collect()
        },
        // Old rows and metadata-free formats carry no map: NULL decodes
        // to the empty map and the record keeps its exact stored identity.
        export_metadata: export_metadata
            .map(|encoded| serde_json::from_str(&encoded))
            .transpose()
            .map_err(|_| corrupt("stored record export metadata is not canonical JSON"))?
            .unwrap_or_default(),
        text_digest: Digest::parse(&text_digest)
            .map_err(|_| corrupt("stored text digest is not canonical"))?,
        text,
        // Old rows carry no locator: NULL deserializes to `None` and the
        // record keeps its exact stored identity.
        origin: origin
            .map(|origin| serde_json::from_str(&origin))
            .transpose()
            .map_err(|_| corrupt("stored record origin is not canonical JSON"))?,
    })
}

fn corrupt(reason: impl Into<String>) -> BrainError {
    BrainError::Corrupt {
        component: "brain-archive-store",
        reason: reason.into(),
    }
}

/// A paged, bounded pull cursor over one generation's staged vectors: each
/// page is read from the archive store on demand, so the pool move into
/// the index store streams without materializing every vector in RAM.
pub struct StagedVectorCursor<'a> {
    store: &'a ArchiveStore,
    generation_id: IndexGenerationId,
    next_ordinal: u64,
    buffered: std::collections::VecDeque<(u64, String, Vec<f32>)>,
    exhausted: bool,
}

impl Iterator for StagedVectorCursor<'_> {
    type Item = BrainResult<(u64, String, Vec<f32>)>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.buffered.is_empty() {
            if self.exhausted {
                return None;
            }
            const PAGE: u64 = 4096;
            match self.store.staged_vectors_range(
                &self.generation_id,
                self.next_ordinal,
                self.next_ordinal + PAGE,
            ) {
                Ok(rows) => {
                    if rows.is_empty() {
                        self.exhausted = true;
                        return None;
                    }
                    self.next_ordinal = rows
                        .last()
                        .map(|(ordinal, _, _)| *ordinal + 1)
                        .unwrap_or(self.next_ordinal);
                    self.buffered.extend(rows);
                }
                Err(error) => {
                    self.exhausted = true;
                    return Some(Err(error));
                }
            }
        }
        self.buffered.pop_front().map(Ok)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::archive::PreparedArchiveRecord;
    use crate::source::archive::{ArchiveProvenance, ArchiveRecord, ArchiveRecordKind};
    use odin_domain::knowledge::archive::{
        ArchiveDedupeKey, ArchiveFormat, ArchiveSelectionPolicy,
    };

    fn source() -> AtlasId {
        AtlasId::new("archive:store-test").unwrap()
    }

    fn durable_record_count(store: &ArchiveStore, source: &AtlasId) -> u64 {
        let connection = store.lock_connection().unwrap();
        connection
            .query_row(
                "SELECT COUNT(*) FROM archive_record WHERE source_id = ?1",
                params![source.as_str()],
                |row| row.get::<_, i64>(0),
            )
            .unwrap() as u64
    }

    /// Revision membership uses a covering index rather than a source scan.
    #[test]
    fn identity_lookups_probe_indexes_instead_of_scanning_a_source() {
        let directory = tempfile::tempdir().unwrap();
        let store = ArchiveStore::open(directory.path()).unwrap();
        let connection = store.lock_connection().unwrap();
        let mut statement = connection
            .prepare(&format!("EXPLAIN QUERY PLAN {IDENTITY_RECORDS_SQL}"))
            .unwrap();
        let plan: Vec<String> = statement
            .query_map(params!["rev", "src", "message", "lit", 8], |row| {
                row.get::<_, String>(3)
            })
            .unwrap()
            .map(Result::unwrap)
            .collect();
        let plan = plan.join("\n");
        assert!(plan.contains("MULTI-INDEX OR"), "{plan}");
        for index in [
            "archive_record_natural_key",
            "archive_record_message_id",
            "archive_record_thread_id",
            "archive_record_conversation_id",
            "COVERING INDEX archive_revision_member",
        ] {
            assert!(plan.contains(index), "{index} missing from\n{plan}");
        }
    }

    fn declaration(namespace: &str) -> ArchiveSourceDeclaration {
        ArchiveSourceDeclaration {
            format: ArchiveFormat::ClaudeExport,
            path: std::path::PathBuf::from("/tmp/store-test-export"),
            memory_namespace: namespace.to_owned(),
            privacy_class: ArchivePrivacyClass::Private,
            dedupe_key: ArchiveDedupeKey::ContentDigest,
            selection: ArchiveSelectionPolicy {
                since: None,
                exclude_labels: Vec::new(),
                exclude_if_header: Vec::new(),
                keep_if_participant: false,
                participant_emails: Vec::new(),
                suspicious_rules: Vec::new(),
                exclude_do_not_remember: None,
            },
        }
    }

    fn record(ordinal: u64, key: &str, text: &str) -> (Digest, PreparedArchiveRecord) {
        let archive_record = ArchiveRecord {
            natural_key: key.to_owned(),
            kind: ArchiveRecordKind::Message,
            text: text.to_owned(),
            provenance: ArchiveProvenance {
                export_account: Some("test-account".to_owned()),
                conversation_id: Some(format!("conv-{key}")),
                message_id: Some(key.to_owned()),
                ..ArchiveProvenance::default()
            },
        };
        let digest = crate::archive::declaration_digest(&declaration("memory.test")).unwrap();
        let record_key = crate::archive::record_key(&source(), &digest, &archive_record).unwrap();
        (
            record_key,
            PreparedArchiveRecord {
                ordinal,
                item_id: crate::source::SourceItem::identity(&source(), key.as_bytes()).unwrap(),
                natural_key: key.to_owned(),
                kind: ArchiveRecordKind::Message,
                namespace: "memory.test".to_owned(),
                privacy_class: ArchivePrivacyClass::Private,
                export_account: Some("test-account".to_owned()),
                part_index: None,
                part_count: None,
                export_id: None,
                conversation_id: Some(format!("conv-{key}")),
                message_id: Some(key.to_owned()),
                thread_id: None,
                created_at: None,
                sent_by_user: false,
                labels: Vec::new(),
                rule_flags: Vec::new(),
                export_metadata: BTreeMap::new(),
                origin: None,
                text_digest: Digest::hash(text.as_bytes()),
                text: text.to_owned(),
            },
        )
    }

    fn open(tag: &str) -> ArchiveStore {
        let root = std::env::temp_dir().join(format!(
            "odin-brain-archive-store-test-{tag}-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        ArchiveStore::open(&root).unwrap()
    }

    #[test]
    fn restaging_is_exact_dedupe_and_rebuilds_membership() {
        // The interrupted/retry invariant: a run that staged part of a
        // revision and was retried must insert zero duplicate rows and
        // stream the identical membership in ordinal order.
        let store = open("dedupe");
        let digest = crate::archive::declaration_digest(&declaration("memory.test")).unwrap();
        store
            .declare_source(&source(), &declaration("memory.test"), &digest)
            .unwrap();
        let revision = Digest::hash(b"revision-1");
        let first = vec![record(0, "m-1", "one"), record(1, "m-2", "two")];
        let outcome = store
            .stage_records(
                &source(),
                &revision,
                &first.iter().map(|(k, r)| (k, r)).collect::<Vec<_>>(),
                1,
            )
            .unwrap();
        assert_eq!(outcome.inserted, 2);
        assert_eq!(outcome.duplicates, 0);
        // "Interruption": the retry re-offers the same records plus the
        // rest of the stream.
        let mut retry = first.clone();
        retry.push(record(2, "m-3", "three"));
        let outcome = store
            .stage_records(
                &source(),
                &revision,
                &retry.iter().map(|(k, r)| (k, r)).collect::<Vec<_>>(),
                2,
            )
            .unwrap();
        assert_eq!(outcome.inserted, 1, "only the new record inserts");
        assert_eq!(outcome.duplicates, 2, "the retried records dedupe");
        assert_eq!(durable_record_count(&store, &source()), 3);
        let mut natural_keys = Vec::new();
        store
            .for_each_revision_record(&source(), &revision, &mut |record| {
                natural_keys.push(record.natural_key);
                Ok(())
            })
            .unwrap();
        assert_eq!(natural_keys, vec!["m-1", "m-2", "m-3"]);
    }

    #[test]
    fn namespace_mapping_is_enforced_not_decorative() {
        let store = open("namespace");
        let digest_alpha =
            crate::archive::declaration_digest(&declaration("memory.alpha")).unwrap();
        let digest_beta = crate::archive::declaration_digest(&declaration("memory.beta")).unwrap();
        store
            .declare_source(&source(), &declaration("memory.alpha"), &digest_alpha)
            .unwrap();
        let other = AtlasId::new("archive:store-test-other").unwrap();
        let conflict = store.declare_source(&other, &declaration("memory.alpha"), &digest_alpha);
        assert!(
            matches!(&conflict, Err(BrainError::InvalidPolicy(_))),
            "one namespace must map to exactly one source, got {conflict:?}"
        );
        // The same source re-declared identically is an idempotent no-op.
        store
            .declare_source(&source(), &declaration("memory.alpha"), &digest_alpha)
            .unwrap();
        // A changed namespace for the same source is refused.
        let changed = store.declare_source(&source(), &declaration("memory.beta"), &digest_beta);
        assert!(matches!(&changed, Err(BrainError::InvalidPolicy(_))));
        // A moved export is the same source: the new declaration is stored.
        let mut moved = declaration("memory.alpha");
        moved.path = std::path::PathBuf::from("/moved/export");
        let moved_digest = crate::archive::declaration_digest(&moved).unwrap();
        store
            .declare_source(&source(), &moved, &moved_digest)
            .unwrap();
        store
            .declare_source(&source(), &moved, &moved_digest)
            .unwrap();
    }

    #[test]
    fn publication_replaces_only_through_a_new_revision() {
        let store = open("publish");
        let digest = crate::archive::declaration_digest(&declaration("memory.test")).unwrap();
        store
            .declare_source(&source(), &declaration("memory.test"), &digest)
            .unwrap();
        let generation = || {
            IndexGenerationId::new(Digest::hash(
                format!("generation-{}", std::process::id()).as_bytes(),
            ))
        };
        let revision_one = Digest::hash(b"revision-1");
        store
            .create_job("job-1", &source(), "demand-1", "approval-1", "command-1", 1)
            .unwrap();
        store
            .publish(
                &source(),
                &revision_one,
                &generation(),
                2,
                4,
                None,
                "job-1",
                1,
            )
            .unwrap();
        // A rebind guarded by the wrong revision is refused typed.
        let model = EmbeddingModelId::new("embedding.test.v1").unwrap();
        let stale = store.rebind_publication(
            &source(),
            &Digest::hash(b"other-revision"),
            &generation(),
            &model,
            4,
            3,
        );
        assert!(matches!(&stale, Err(BrainError::StaleAuthority { .. })));
        let published = store.publication(&source()).unwrap().unwrap();
        assert_eq!(published.revision, revision_one);
        assert_eq!(published.embedding_model, None, "lexical-only posture");
        // A new approved revision moves the pointer; the job terminal state
        // commits with it.
        let revision_two = Digest::hash(b"revision-2");
        store
            .create_job("job-2", &source(), "demand-2", "approval-2", "command-2", 2)
            .unwrap();
        store
            .publish(
                &source(),
                &revision_two,
                &generation(),
                3,
                5,
                None,
                "job-2",
                2,
            )
            .unwrap();
        let published = store.publication(&source()).unwrap().unwrap();
        assert_eq!(published.revision, revision_two);
        assert_eq!(published.records, 3);
        let job = store.last_job(&source()).unwrap().unwrap();
        assert_eq!(job.state, ArchiveJobState::Published);
        assert_eq!(job.content_revision, Some(revision_two));
    }

    #[test]
    fn terminal_jobs_never_reopen() {
        // Superseded and failed jobs cannot republish, even if their export bytes are restored.
        let store = open("terminal");
        let digest = crate::archive::declaration_digest(&declaration("memory.test")).unwrap();
        store
            .declare_source(&source(), &declaration("memory.test"), &digest)
            .unwrap();
        let generation = IndexGenerationId::new(Digest::hash(b"terminal-generation"));
        let revision_a = Digest::hash(b"revision-a");
        let revision_b = Digest::hash(b"revision-b");
        store
            .create_job("job-a", &source(), "demand-a", "approval-a", "command-a", 1)
            .unwrap();
        store
            .publish(&source(), &revision_a, &generation, 1, 1, None, "job-a", 2)
            .unwrap();
        // A is current: the no-op path handles it before create_job, but
        // create_job must also be safe (it is only reachable past the
        // no-op when superseded).
        store
            .create_job("job-b", &source(), "demand-b", "approval-b", "command-b", 3)
            .unwrap();
        store
            .publish(&source(), &revision_b, &generation, 1, 1, None, "job-b", 4)
            .unwrap();
        let superseded =
            store.create_job("job-a", &source(), "demand-a", "approval-a", "command-a", 5);
        assert!(
            matches!(&superseded, Err(BrainError::InvalidRequest(_))),
            "a superseded published job must never republish, got {superseded:?}"
        );
        assert_eq!(
            store.publication(&source()).unwrap().unwrap().revision,
            revision_b,
            "the publication must still point at B"
        );
        // Failed jobs stay failed.
        store
            .create_job("job-c", &source(), "demand-c", "approval-c", "command-c", 6)
            .unwrap();
        store
            .finish_job("job-c", &revision_a, ArchiveJobState::Failed, 7)
            .unwrap();
        let failed = store.create_job("job-c", &source(), "demand-c", "approval-c", "command-c", 8);
        assert!(matches!(&failed, Err(BrainError::InvalidRequest(_))));
        // A still-staging job resumes in place.
        store
            .create_job("job-d", &source(), "demand-d", "approval-d", "command-d", 9)
            .unwrap();
        store
            .create_job(
                "job-d",
                &source(),
                "demand-d",
                "approval-d",
                "command-d",
                10,
            )
            .unwrap();
    }

    #[test]
    fn staged_vectors_persist_and_clear() {
        let store = open("vectors");
        let generation = IndexGenerationId::new(Digest::hash(b"generation-vectors"));
        let rows: Vec<(u64, String, Vec<u8>)> = (0..3)
            .map(|ordinal| {
                let dims: Vec<u8> = [0.5_f32, 1.5]
                    .iter()
                    .copied()
                    .flat_map(f32::to_le_bytes)
                    .collect();
                (ordinal, format!("chunk-{ordinal}"), dims)
            })
            .collect();
        store.stage_vectors(&generation, &rows).unwrap();
        assert_eq!(store.staged_vector_count(&generation).unwrap(), 3);
        let paged = store.staged_vectors_range(&generation, 1, 3).unwrap();
        assert_eq!(paged.len(), 2);
        assert_eq!(paged[0].0, 1);
        assert_eq!(paged[0].2, vec![0.5_f32, 1.5]);
        store.clear_staged_vectors(&generation).unwrap();
        assert_eq!(store.staged_vector_count(&generation).unwrap(), 0);
    }

    #[test]
    fn new_revision_gains_complete_membership_over_cached_records() {
        let store = open("membership");
        let digest = crate::archive::declaration_digest(&declaration("memory.test")).unwrap();
        store
            .declare_source(&source(), &declaration("memory.test"), &digest)
            .unwrap();
        let revision_one = Digest::hash(b"revision-1");
        let revision_two = Digest::hash(b"revision-2");
        let batch = || vec![record(0, "m-1", "one"), record(1, "m-2", "two")];
        let outcome = store
            .stage_records(
                &source(),
                &revision_one,
                &batch().iter().map(|(k, r)| (k, r)).collect::<Vec<_>>(),
                1,
            )
            .unwrap();
        assert_eq!(outcome.inserted, 2);
        // The export changed elsewhere: a NEW revision over the same
        // records must still gain complete membership even though every
        // record row is already cached (zero record inserts).
        let outcome = store
            .stage_records(
                &source(),
                &revision_two,
                &batch().iter().map(|(k, r)| (k, r)).collect::<Vec<_>>(),
                2,
            )
            .unwrap();
        assert_eq!(
            outcome.inserted, 2,
            "membership inserts are independent of record dedupe"
        );
        assert_eq!(outcome.duplicates, 0);
        assert_eq!(
            durable_record_count(&store, &source()),
            2,
            "no record rows duplicated"
        );
        let mut keys = Vec::new();
        store
            .for_each_revision_record(&source(), &revision_two, &mut |record| {
                keys.push(record.natural_key);
                Ok(())
            })
            .unwrap();
        assert_eq!(keys, vec!["m-1".to_owned(), "m-2".to_owned()]);
    }

    #[test]
    fn discard_then_retry_restores_membership() {
        let store = open("discard-retry");
        let digest = crate::archive::declaration_digest(&declaration("memory.test")).unwrap();
        store
            .declare_source(&source(), &declaration("memory.test"), &digest)
            .unwrap();
        let revision = Digest::hash(b"revision-1");
        let batch = || vec![record(0, "m-1", "one")];
        store
            .stage_records(
                &source(),
                &revision,
                &batch().iter().map(|(k, r)| (k, r)).collect::<Vec<_>>(),
                1,
            )
            .unwrap();
        store.discard_revision(&source(), &revision).unwrap();
        // Retry after the failed-attempt cleanup: cached record rows must
        // rejoin the revision at their ordinals.
        let outcome = store
            .stage_records(
                &source(),
                &revision,
                &batch().iter().map(|(k, r)| (k, r)).collect::<Vec<_>>(),
                2,
            )
            .unwrap();
        assert_eq!(outcome.inserted, 1);
        let count = durable_record_count(&store, &source());
        assert_eq!(count, 1);
    }
}
