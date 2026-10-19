//! Durable normalized archive records: declared sources, staged records
//! with structured provenance, revision manifests, atomic publication, and
//! resumable vector staging for the embedding backfill.
//!
//! Archives are personal exports ingested as memory, never authority: every
//! record stays `TrustClass::Observed`, carries its declared confidentiality
//! class separately, and retains provenance as structured columns (export
//! account, conversation/message/thread identity, timestamps, format export
//! metadata, asset locators) so retrieval can cite the exact export record
//! without interpolating provenance into text.
//!
//! Record identity is content addressing: a record key binds the source,
//! the declaration digest, the export's natural key, the normalized text
//! digest, and the canonical provenance fields. A re-export that changes one
//! byte of one message under a stable UUID is a different record, and the
//! revision manifest over ordered record keys changes with it — stable
//! export identity alone is never treated as content addressing.
//!
//! Progress is durable and resume is dedupe: staging batches commit as they
//! land, `INSERT OR IGNORE` makes re-staging a no-op, and only the final
//! publication flip (one transaction with the job's terminal state) makes a
//! revision servable. Nothing here ever reads the raw archive; the parser
//! streams records in and this store serves persisted approved state.

pub mod store;

pub use store::{
    ArchiveJobRow, ArchiveJobState, ArchivePublicationRow, ArchiveStageOutcome, ArchiveStore,
    DeclaredArchiveSource, StoredArchiveRecord,
};

use odin_domain::knowledge::archive::{ArchivePrivacyClass, ArchiveSourceDeclaration};
use odin_domain::knowledge::ids::AtlasId;
use odin_domain::Digest;
use std::collections::BTreeMap;

use crate::error::{BrainError, BrainResult};
use crate::source::archive::ArchiveRecord;

/// Enforce the parser's per-part size limit again before storage.
pub const MAX_ARCHIVE_RECORD_BYTES: usize = 1024 * 1024;

/// One batch of staged records within one staging transaction.
pub(crate) const STAGE_BATCH_RECORDS: usize = 512;

/// The domain tag prefixing the export-metadata field inside
/// [`record_key`] material: metadata must never alias the origin
/// locator's untagged canonical-JSON field.
const EXPORT_METADATA_TAG: &[u8] = b"odin-brain:archive-record:export-metadata\0";

pub(crate) fn kind_token(kind: crate::source::archive::ArchiveRecordKind) -> &'static str {
    use crate::source::archive::ArchiveRecordKind;
    match kind {
        ArchiveRecordKind::Conversation => "conversation",
        ArchiveRecordKind::ConversationSummary => "conversation_summary",
        ArchiveRecordKind::Message => "message",
        ArchiveRecordKind::Memory => "memory",
        ArchiveRecordKind::AssetMetadata => "asset_metadata",
    }
}

pub(crate) fn parse_kind(token: &str) -> BrainResult<crate::source::archive::ArchiveRecordKind> {
    use crate::source::archive::ArchiveRecordKind;
    match token {
        "conversation" => Ok(ArchiveRecordKind::Conversation),
        "conversation_summary" => Ok(ArchiveRecordKind::ConversationSummary),
        "message" => Ok(ArchiveRecordKind::Message),
        "memory" => Ok(ArchiveRecordKind::Memory),
        "asset_metadata" => Ok(ArchiveRecordKind::AssetMetadata),
        _ => Err(BrainError::Corrupt {
            component: "brain-archive-store",
            reason: format!("stored archive record kind {token} is not a known kind"),
        }),
    }
}

pub(crate) fn privacy_token(class: ArchivePrivacyClass) -> &'static str {
    match class {
        ArchivePrivacyClass::Private => "private",
        ArchivePrivacyClass::Shared => "shared",
    }
}

pub(crate) fn parse_privacy(token: &str) -> BrainResult<ArchivePrivacyClass> {
    match token {
        "private" => Ok(ArchivePrivacyClass::Private),
        "shared" => Ok(ArchivePrivacyClass::Shared),
        _ => Err(BrainError::Corrupt {
            component: "brain-archive-store",
            reason: format!("stored archive privacy class {token} is not a known class"),
        }),
    }
}

/// Appends one length-prefixed field to canonical record material so no
/// field-boundary ambiguity can ever alias two records.
fn push_field(material: &mut Vec<u8>, field: &[u8]) {
    material.extend_from_slice(&(field.len() as u64).to_be_bytes());
    material.extend_from_slice(field);
}

/// The content-addressed identity of one normalized archive record.
///
/// The material binds the source, the whole declaration digest (selection
/// policy included), the export's natural key, the normalized text digest,
/// and every structured provenance field. Export UUIDs and RFC 822
/// Message-Ids remain the record's natural key — they are identity
/// material, never a dedupe mode: changed content under a stable natural
/// key changes this digest.
///
/// Version the hash domain when identity semantics change so existing
/// records and terminal jobs retain their immutable identifiers.
pub fn record_key(
    source: &AtlasId,
    declaration_digest: &Digest,
    record: &ArchiveRecord,
) -> BrainResult<Digest> {
    let text_len = record.text.len();
    if text_len > MAX_ARCHIVE_RECORD_BYTES {
        return Err(BrainError::InvalidRequest(format!(
            "archive record {} exceeds the {MAX_ARCHIVE_RECORD_BYTES} byte bound ({text_len} bytes)",
            record.natural_key
        )));
    }
    let mut material = b"odin-brain:archive-record:v2\0".to_vec();
    push_field(&mut material, source.as_str().as_bytes());
    push_field(&mut material, declaration_digest.as_bytes());
    push_field(&mut material, record.natural_key.as_bytes());
    let text_digest = Digest::hash(record.text.as_bytes());
    push_field(&mut material, text_digest.as_bytes());
    let provenance = &record.provenance;
    push_field(
        &mut material,
        provenance
            .export_account
            .as_deref()
            .unwrap_or("")
            .as_bytes(),
    );
    push_field(
        &mut material,
        &provenance
            .part_index
            .map(|part| part.to_string())
            .unwrap_or_default()
            .into_bytes(),
    );
    push_field(
        &mut material,
        &provenance
            .part_count
            .map(|count| count.to_string())
            .unwrap_or_default()
            .into_bytes(),
    );
    push_field(
        &mut material,
        provenance.export_id.as_deref().unwrap_or("").as_bytes(),
    );
    push_field(
        &mut material,
        provenance
            .conversation_id
            .as_deref()
            .unwrap_or("")
            .as_bytes(),
    );
    push_field(
        &mut material,
        provenance.message_id.as_deref().unwrap_or("").as_bytes(),
    );
    push_field(
        &mut material,
        provenance.thread_id.as_deref().unwrap_or("").as_bytes(),
    );
    let created = provenance
        .created_at
        .map(|at| at.format(&time::format_description::well_known::Rfc3339))
        .transpose()
        .map_err(|error| {
            BrainError::InvalidRequest(format!("record timestamp cannot format: {error}"))
        })?;
    push_field(&mut material, created.as_deref().unwrap_or("").as_bytes());
    push_field(
        &mut material,
        if provenance.sent_by_user { b"1" } else { b"0" },
    );
    push_field(&mut material, &provenance.labels.join("\0").into_bytes());
    push_field(
        &mut material,
        &provenance.rule_flags.join("\0").into_bytes(),
    );
    // Nonempty metadata only, under its own domain tag: it must never
    // alias the origin locator's untagged JSON field. Empty metadata
    // adds nothing, so records without it keep their exact prior keys.
    if !provenance.export_metadata.is_empty() {
        let canonical = serde_json::to_vec(&provenance.export_metadata).map_err(|error| {
            BrainError::InvalidRequest(format!("record export metadata cannot serialize: {error}"))
        })?;
        push_field(&mut material, EXPORT_METADATA_TAG);
        push_field(&mut material, &canonical);
    }
    // The origin locator joins the material only when present: records
    // without one keep their exact prior keys (old rows stay put), and a
    // provenance upgrade on re-ingest is an honest new record version,
    // never a mutation of an old one.
    if let Some(origin) = &provenance.origin {
        let canonical = serde_json::to_vec(origin).map_err(|error| {
            BrainError::InvalidRequest(format!("record origin cannot serialize: {error}"))
        })?;
        push_field(&mut material, &canonical);
    }
    Ok(Digest::hash(&material))
}

/// One record validated and projected for staging: identity fields are
/// already derived (record key, item id, text digest); `ordinal` is the
/// record's position in the parser stream and becomes the revision
/// manifest's canonical order.
#[derive(Clone)]
pub struct PreparedArchiveRecord {
    pub ordinal: u64,
    pub item_id: odin_domain::knowledge::ids::KnowledgeItemId,
    pub natural_key: String,
    pub kind: crate::source::archive::ArchiveRecordKind,
    pub namespace: String,
    pub privacy_class: ArchivePrivacyClass,
    /// Export/account owner when the export names one; `None` when the
    /// format carries no account identity (mbox). Never invented.
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
    /// Empty for formats that declare none; those records keep their
    /// exact prior identity.
    pub export_metadata: BTreeMap<String, serde_json::Value>,
    /// Original asset locator when the record carries one; `None`
    /// preserves the identity of records without a locator.
    pub origin: Option<crate::source::archive::ArchiveAssetOrigin>,
    pub text_digest: Digest,
    pub text: String,
}

/// Incremental builder for one source revision: the digest over the
/// declaration-bound header and every staged record key in parser stream
/// order. The same export under the same declaration always rebuilds the
/// same revision; any content, provenance, or policy change moves it.
pub struct RevisionHasher {
    hasher: blake3::Hasher,
}

impl RevisionHasher {
    pub fn new(source: &AtlasId, declaration_digest: &Digest) -> Self {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"odin-brain:archive-revision:v1\0");
        hasher.update(source.as_str().as_bytes());
        hasher.update(&[0]);
        hasher.update(declaration_digest.as_bytes());
        Self { hasher }
    }

    /// Feeds one staged record's key in stream order.
    pub fn push_record(&mut self, record_key: &Digest) {
        self.hasher.update(record_key.as_bytes());
    }

    pub fn finish(self) -> Digest {
        Digest::from_bytes(*self.hasher.finalize().as_bytes())
    }
}

/// The canonical digest binding one operator declaration: the stable
/// serde JSON encoding hashed whole. Approvals bind this digest, so a
/// swapped declaration can never reuse an approval.
pub fn declaration_digest(declaration: &ArchiveSourceDeclaration) -> BrainResult<Digest> {
    let encoded = serde_json::to_string(declaration)?;
    Ok(Digest::hash(encoded.as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::source::archive::{ArchiveProvenance, ArchiveRecordKind};
    use std::collections::BTreeMap;

    fn record(text: &str, key: &str) -> ArchiveRecord {
        ArchiveRecord {
            natural_key: key.to_owned(),
            kind: ArchiveRecordKind::Message,
            text: text.to_owned(),
            provenance: ArchiveProvenance {
                export_account: Some("colin".to_owned()),
                part_index: None,
                part_count: None,
                export_id: None,
                conversation_id: Some("conv-1".to_owned()),
                message_id: Some(key.to_owned()),
                thread_id: None,
                created_at: None,
                sent_by_user: false,
                labels: Vec::new(),
                rule_flags: Vec::new(),
                export_metadata: BTreeMap::new(),
                origin: None,
            },
        }
    }

    fn source() -> AtlasId {
        AtlasId::new("archive:test").unwrap()
    }

    fn digest() -> Digest {
        Digest::hash(b"declaration")
    }

    #[test]
    fn changed_content_under_stable_natural_key_is_a_new_record() {
        // A stable export UUID must never double as content addressing:
        // one edited byte under the same message UUID is a different record.
        let original = record_key(&source(), &digest(), &record("hello", "m-1")).unwrap();
        let edited = record_key(&source(), &digest(), &record("hello!", "m-1")).unwrap();
        assert_ne!(original, edited);
    }

    #[test]
    fn provenance_participates_in_record_identity() {
        let mut flagged = record("hello", "m-1");
        flagged.provenance.rule_flags = vec!["suspicious_sender".to_owned()];
        let plain = record_key(&source(), &digest(), &record("hello", "m-1")).unwrap();
        let flagged = record_key(&source(), &digest(), &flagged).unwrap();
        assert_ne!(plain, flagged);
    }

    #[test]
    fn export_metadata_participates_in_record_identity() {
        let mut tagged = record("hello", "m-1");
        tagged.provenance.export_metadata.insert(
            "library_file_id".to_owned(),
            serde_json::Value::from("file-1"),
        );
        let plain = record_key(&source(), &digest(), &record("hello", "m-1")).unwrap();
        let tagged = record_key(&source(), &digest(), &tagged).unwrap();
        assert_ne!(
            plain, tagged,
            "declared format metadata is identity material"
        );
    }

    #[test]
    fn empty_export_metadata_keeps_the_parent_record_key() {
        // Persisted keys from before metadata support must remain addressable.
        let key = record_key(&source(), &digest(), &record("hello", "m-1")).unwrap();
        assert_eq!(
            key,
            Digest::parse(
                "blake3:986b3d24f18c59ad2713d48b2470aace0fe8ddf4348835b091fe1d39311178c2"
            )
            .unwrap()
        );
    }

    #[test]
    fn export_metadata_cannot_alias_an_origin_locator() {
        // The origin locator is an untagged canonical-JSON field (its
        // historical contract); metadata is tagged. An origin that
        // serializes to exactly the bytes of a metadata map must never
        // produce the same key — drop the tag and this fixture collides.
        let origin = crate::source::archive::ArchiveAssetOrigin {
            position: Some(7),
            ..Default::default()
        };
        let mut origin_only = record("hello", "m-1");
        origin_only.provenance.origin = Some(origin);
        let mut metadata_only = record("hello", "m-1");
        metadata_only.provenance.export_metadata = serde_json::from_value(
            serde_json::to_value(origin_only.provenance.origin.as_ref().unwrap()).unwrap(),
        )
        .unwrap();
        assert_eq!(
            serde_json::to_vec(origin_only.provenance.origin.as_ref().unwrap()).unwrap(),
            serde_json::to_vec(&metadata_only.provenance.export_metadata).unwrap(),
            "fixture must serialize both fields to identical JSON bytes"
        );
        assert_ne!(
            record_key(&source(), &digest(), &origin_only).unwrap(),
            record_key(&source(), &digest(), &metadata_only).unwrap(),
        );
    }

    #[test]
    fn namespace_and_source_isolate_identity() {
        let record = record("hello", "m-1");
        let base = record_key(&source(), &digest(), &record).unwrap();
        let other_source =
            record_key(&AtlasId::new("archive:other").unwrap(), &digest(), &record).unwrap();
        let other_declaration = record_key(&source(), &Digest::hash(b"other"), &record).unwrap();
        assert_ne!(base, other_source);
        assert_ne!(base, other_declaration);
    }

    #[test]
    fn oversize_record_fails_typed() {
        let big = record(&"x".repeat(MAX_ARCHIVE_RECORD_BYTES + 1), "m-1");
        assert!(matches!(
            record_key(&source(), &digest(), &big),
            Err(BrainError::InvalidRequest(_))
        ));
    }

    #[test]
    fn revision_reproduces_in_stream_order() {
        let records = [
            record("one", "m-1"),
            record("two", "m-2"),
            record("three", "m-3"),
        ];
        let keys: Vec<Digest> = records
            .iter()
            .map(|r| record_key(&source(), &digest(), r).unwrap())
            .collect();
        let mut hasher = RevisionHasher::new(&source(), &digest());
        for key in &keys {
            hasher.push_record(key);
        }
        let revision = hasher.finish();
        let mut again = RevisionHasher::new(&source(), &digest());
        for key in &keys {
            again.push_record(key);
        }
        assert_eq!(revision, again.finish());
        // A dropped record moves the revision even when every remaining
        // record key is unchanged.
        let mut shorter = RevisionHasher::new(&source(), &digest());
        for key in &keys[..2] {
            shorter.push_record(key);
        }
        assert_ne!(revision, shorter.finish());
    }
}
