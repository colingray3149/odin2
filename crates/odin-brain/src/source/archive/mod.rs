//! Streaming parsers for operator-declared external archives.
//!
//! One generic path turns a declared [`ArchiveSourceDeclaration`] into a
//! stream of bounded, provenance-carrying [`ArchiveRecord`]s; the brain
//! store persists, content-addresses, and dedupes them, so parsers never
//! hold a whole export in memory and never decide trust. Supported
//! formats:
//!
//! - Claude export: a `conversations.json` array streamed with a serde
//!   visitor (one conversation at a time — a `StreamDeserializer` cannot
//!   stream *inside* an array), plus the `memories/*.json` records beside
//!   it. Attachments contribute metadata-only asset records;
//!   `extracted_content` bodies never enter a record. Keep-all: no record
//!   is truncated; oversized normalized text is segmented into ordered
//!   parts with stable identity, and a malformed memory file fails the
//!   stream typed rather than dropping content.
//! - Grok export: a zip archive read in place (never extracted to disk)
//!   whose `prod-grok-backend.json` streams the same way; asset-server
//!   entries contribute metadata only.
//! - ChatGPT export: a zip archive read in place whose split
//!   `conversations-*.json` arrays stream one conversation at a time.
//!   Each conversation is a parent-linked message tree with a declared
//!   `current_node`; the current_node ancestor chain is the canonical
//!   thread, alternate branches are provenance (never duplicated), and
//!   broken ancestry (missing node, cycle) truncates the chain and is
//!   counted, never healed by guessing. `*.dat` asset entries and
//!   `library_files.json` contribute filename/size metadata only.
//! - Gemini in Workspace and NotebookLM Takeout roots: transcript and
//!   notebook-source notes streamed from the extracted Takeout tree with
//!   notebook/source names as structured provenance metadata.
//! - Mbox: a zipped or plain mbox read as a stream of messages split on
//!
//! Records are data, never authority: every record is untrusted observed
//! memory, carries structured export provenance (never interpolated into
//! text), and gets no invented values — an absent export summary becomes
//! a deterministic derived summary built only from record counts,
//! timestamps, and message text.
//!
//! Nothing is dropped silently: every exclusion, malformed record, and
//! segmentation increments one counter in [`ArchiveStreamSummary`].

use std::collections::{BTreeMap, HashMap};

use odin_domain::knowledge::archive::{ArchiveFormat, ArchiveSourceDeclaration};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::error::{BrainError, BrainResult};

/// A zip member's name; a name the reader cannot decode fails typed.
fn member_name<R: std::io::Read + ?Sized>(
    entry: &zip::read::ZipFile<'_, R>,
) -> BrainResult<String> {
    entry
        .name()
        .map(std::borrow::Cow::into_owned)
        .map_err(|err| BrainError::Unavailable {
            component: "archive",
            reason: format!("cannot decode a zip member name: {err}"),
        })
}

mod chatgpt;
mod claude;
mod gemini_workspace;
mod grok;
mod mbox;
mod notebooklm;

#[cfg(test)]
mod tests;

/// Hard bound on one record part's normalized text, in bytes. Keep-all
/// formats never truncate: a record whose normalized text exceeds this
/// bound is emitted as ordered parts (see `segment_and_deliver`), each
/// individually bounded. The store may re-enforce the same bound per part
/// typed as a backstop.
pub const MAX_RECORD_BYTES: usize = 1024 * 1024;

/// The kind of one normalized archive record.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArchiveRecordKind {
    /// Conversation identity record: title (or a deterministic derivation
    /// from message text when the export has no title). Chat exports only;
    /// mail threads are implicit through [`ArchiveProvenance::thread_id`].
    Conversation,
    /// Per-conversation summary, export-supplied or deterministically
    /// derived when the export summary is absent.
    ConversationSummary,
    /// One normalized conversation or mail message.
    Message,
    /// A memory record from the export (Claude `memories/*.json`).
    Memory,
    /// Uploaded asset metadata only; asset bodies never enter records.
    AssetMetadata,
}

/// Structured export provenance attached to every record. Every field is
/// exactly what the export declared (or derivable by a deterministic rule
/// documented on the field); parsers never invent values and never
/// interpolate provenance into record text.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct ArchiveProvenance {
    /// The export/account owner when the export names one (Claude/Grok
    /// account uuid). `None` when the export carries no account identity
    /// (mbox) — identity is never invented. The archive itself is
    /// identified by the source `AtlasId` plus content revision attached
    /// by the store.
    pub export_account: Option<String>,
    /// Export bundle identity when the export names one (Grok export
    /// directory uuid).
    pub export_id: Option<String>,
    /// Conversation uuid (Claude/Grok) when the export has one.
    pub conversation_id: Option<String>,
    /// Stable message identity inside the export: chat message uuid, Grok
    /// response id, or RFC822 Message-ID. This is the record natural key
    /// material, never the dedupe key by itself — dedupe is content
    /// addressing, owned by the store.
    pub message_id: Option<String>,
    /// Gmail thread identity (canonical component Message-ID), `None` for
    /// chat exports.
    pub thread_id: Option<String>,
    /// Source timestamp, parsed. `None` when the export timestamp is
    /// absent or unparseable (counted under `unparseable_timestamp`);
    /// never fabricated.
    pub created_at: Option<OffsetDateTime>,
    /// 1-based ordinal of this part when one export record was segmented
    /// (see `segment_and_deliver`); `None` on unsegmented records.
    pub part_index: Option<u32>,
    /// Total part count for a segmented record; `None` on unsegmented
    /// records.
    pub part_count: Option<u32>,
    /// `true` only when the export itself marks the record as authored by
    /// the operator: chat sender, or mail whose `Sent` label or sender
    /// address matches a declared participant identity. Receiving mail alone
    /// does not mark the record as authored by the operator.
    pub sent_by_user: bool,
    /// Declared labels on the record (Gmail `X-Gmail-Labels`), split on
    /// commas; empty for chat exports.
    pub labels: Vec<String>,
    /// Names of declared suspicious rules with the `flag` action that
    /// matched this record. Rules with the `exclude` action never produce
    /// a record; they appear in [`ArchiveStreamSummary::skip_reasons`].
    pub rule_flags: Vec<String>,
    /// Format-specific export metadata carried verbatim (ChatGPT branch
    /// ancestry and conversation flags, Gemini/NotebookLM notebook and
    /// source names). Structured provenance — never interpolated into
    /// record text, and empty (skipped on the wire) when a format declares
    /// none, keeping old serialized identities byte-identical.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub export_metadata: BTreeMap<String, serde_json::Value>,
    /// The original locator of one media/attachment metadata record:
    /// where the export declares the asset and — only when the export
    /// actually ships the bytes — the exact archive member holding them.
    /// `None` for records with no asset identity (conversations, plain
    /// messages, memories) and skipped on the wire when absent, keeping
    /// old serialized identities byte-identical.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub origin: Option<ArchiveAssetOrigin>,
}

/// Where one media/attachment metadata record's asset actually lives in
/// the declared export. Two distinct facts, never conflated: the
/// metadata *declaration* location (the export document the attachment
/// row was read from) and the *original binary* locator (the one zip
/// member or export-tree file the central directory or declared tree
/// uniquely identifies). A declared filename is never claimed as a
/// member: `member` is `None` whenever no unique byte member was
/// identified — the export does not carry the bytes, or an id/name is
/// ambiguous — and the declaration location plus the parent message id
/// (already on the provenance) and the export's own asset id or
/// attachment position are the locator. Provenance is data, never read
/// authority. Every field is optional and skipped on the wire when
/// absent: provenance upgraded by re-ingest is a new honest record
/// version, never a mutation of an old one.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct ArchiveAssetOrigin {
    /// Export-tree-relative path (or exact zip member name) of the
    /// metadata document that declares this asset — `conversations.json`
    /// for a Claude attachment, the export's backend JSON member for a
    /// Grok asset, the declaring `conversations-*.json` member for a
    /// ChatGPT attachment.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub declared_in: Option<String>,
    /// The exact zip member name (zip formats) or export-tree-relative
    /// path (extracted-tree formats) holding the original bytes — only
    /// when the central directory or classified declared tree identifies
    /// exactly ONE such location. `None` means no unique exported byte
    /// member was identified: the format does not export the bytes, or a
    /// member id/name is ambiguous (counted `ambiguous_asset_member`) —
    /// it never asserts the bytes do not exist, and a declared filename
    /// is never promoted to a member. Identical-name duplicates are a
    /// documented reader limitation: the maintained zip reader's index
    /// coalesces same-named entries to one before any parser sees them,
    /// so only distinct-name ambiguity is observable and typed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub member: Option<String>,
    pub asset_id: Option<String>,
    /// 1-based position of the asset within its parent record's declared
    /// collection, for exports that give no per-asset id (Claude
    /// attachments, Grok cards, mbox attachments). Widest integer form:
    /// a source position never wraps.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub position: Option<u64>,
}

/// One bounded, normalized record from a declared archive.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ArchiveRecord {
    /// Stable identity inside this export: export-supplied
    /// uuid/Message-ID, or a deterministic synthetic key for exports that
    /// lack one. Segmented records suffix `:part:<n>`. Keys may repeat
    /// within one stream (overlapping entries, changed content under a
    /// stable id): repeats are emitted unchanged and accounted —
    /// content-addressed identity and dedupe are the store's job.
    pub natural_key: String,
    pub kind: ArchiveRecordKind,
    /// Normalized record text; non-empty, bounded per part at
    /// [`MAX_RECORD_BYTES`] (larger content is segmented, never cut).
    pub text: String,
    pub provenance: ArchiveProvenance,
}

/// Accounting for one archive stream. `skip_reasons` counts exclusions (declared policy,
/// suspicious rules with the `exclude` action), malformed records,
/// duplicate collapses, declared out-of-scope material, segmentations
/// (`record_segmented` — the record IS emitted, in full, as parts), and
/// metadata-only admissions (`empty_body` — an eligible message with no
/// decoded body is emitted as its declared identity and attachment
/// metadata, never dropped for lacking text).
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct ArchiveStreamSummary {
    /// Records successfully delivered to the emit callback: messages plus
    /// every derived record (conversations, summaries, memories, asset
    /// metadata, and segmented parts).
    pub records_emitted: u64,
    /// Source messages the reader classified. Every parsed message is either
    /// represented by at least one emitted record or counted in exactly one
    /// exclusion reason, so `messages_parsed` is the audit total the derived
    /// records and events are checked against.
    pub messages_parsed: u64,
    /// Per-reason counters. Exclusion reasons (`before_since`,
    /// `excluded_label`, `excluded_bulk`, `suspicious_rule_excluded:*`, and
    /// `unparseable_timestamp` under a declared cutoff) each count one
    /// message that was NOT admitted. Event reasons are not exclusions and
    /// never mean content loss: `empty_body` counts an admitted message
    /// whose export body was empty (its identity and attachment metadata are
    /// stored), `record_segmented` counts a record emitted in full as
    /// ordered parts, `duplicate_record` counts an exact repeat collapsed by
    /// content address, and `natural_key_reused` counts a differing record
    /// emitted under a natural key an earlier record already used.
    pub skip_reasons: BTreeMap<String, u64>,
}

impl ArchiveStreamSummary {
    /// Increments one accounting reason.
    pub(crate) fn skip(&mut self, reason: impl Into<String>) {
        *self.skip_reasons.entry(reason.into()).or_default() += 1;
    }

    /// Delivers one record. Natural keys may legitimately repeat across
    /// one stream (overlapping mbox entries, changed content under a
    /// stable export uuid); the store owns content-addressed identity and
    /// dedupe, so repeats are never mangled and never fail the stream —
    /// they are accounted: an exact repeat (same key, kind, text, and
    /// provenance) collapses into one counted `duplicate_record`; a key
    /// reused with different content is emitted unchanged and counted
    /// `natural_key_reused`. Accounting order never changes what is
    /// emitted.
    pub(crate) fn deliver(
        &mut self,
        seen: &mut HashMap<String, String>,
        record: ArchiveRecord,
        emit: &mut dyn FnMut(ArchiveRecord) -> BrainResult<()>,
    ) -> BrainResult<()> {
        let tag = record_tag(&record);
        match seen.get(&record.natural_key) {
            Some(previous) if previous == &tag => {
                self.skip("duplicate_record");
                return Ok(());
            }
            Some(_) => {
                self.skip("natural_key_reused");
            }
            None => {
                seen.insert(record.natural_key.clone(), tag);
            }
        }
        emit(record)?;
        self.records_emitted += 1;
        Ok(())
    }
}

/// Deterministic record-equality tag over the full normalized record —
/// kind, text, and canonical provenance (serde field order is stable) —
/// so identical text under the same key but a different conversation,
/// timestamp, or rule flag set is a different record, not a duplicate.
fn record_tag(record: &ArchiveRecord) -> String {
    let provenance = serde_json::to_string(&record.provenance).unwrap_or_default();
    let kind = serde_json::to_string(&record.kind).unwrap_or_default();
    let mut material = String::with_capacity(kind.len() + record.text.len() + provenance.len() + 2);
    material.push_str(&kind);
    material.push('\0');
    material.push_str(&record.text);
    material.push('\0');
    material.push_str(&provenance);
    blake3::hash(material.as_bytes()).to_hex()[..32].to_owned()
}

/// Delivers one record, segmenting its text when it exceeds
/// [`MAX_RECORD_BYTES`]: the full normalized content is preserved as
/// ordered parts, each individually bounded, sharing the record's
/// provenance with `part_index`/`part_count` set and stable part natural
/// keys (`<key>:part:<n>`, 1-based). Content is never truncated.
pub(crate) fn segment_and_deliver(
    summary: &mut ArchiveStreamSummary,
    seen: &mut HashMap<String, String>,
    mut record: ArchiveRecord,
    emit: &mut dyn FnMut(ArchiveRecord) -> BrainResult<()>,
) -> BrainResult<()> {
    if record.text.len() <= MAX_RECORD_BYTES {
        return summary.deliver(seen, record, emit);
    }
    let text = std::mem::take(&mut record.text);
    let chunks: Vec<&str> = {
        let mut boundaries = vec![0];
        let mut start = 0;
        while text.len() - start > MAX_RECORD_BYTES {
            let mut end = start + MAX_RECORD_BYTES;
            while !text.is_char_boundary(end) {
                end -= 1;
            }
            boundaries.push(end);
            start = end;
        }
        boundaries.push(text.len());
        boundaries
            .windows(2)
            .map(|window| &text[window[0]..window[1]])
            .collect()
    };
    let count = chunks.len() as u32;
    for (index, chunk) in chunks.iter().enumerate() {
        let mut part = record.clone();
        part.text = chunk.to_string();
        part.natural_key = format!("{}:part:{}", record.natural_key, index + 1);
        part.provenance.part_index = Some(index as u32 + 1);
        part.provenance.part_count = Some(count);
        summary.deliver(seen, part, emit)?;
    }
    summary.skip("record_segmented");
    Ok(())
}

/// Parses one export timestamp string into the typed provenance form.
/// `None` marks an absent or unparseable value (callers count it); the
/// raw string is never fabricated into a date.
pub(crate) fn parse_timestamp(raw: &str) -> Option<OffsetDateTime> {
    let raw = raw.trim();
    OffsetDateTime::parse(raw, &time::format_description::well_known::Rfc3339).ok()
}

/// The declared `since` cutoff for keep-all chat records — a hard
/// cutoff: with a cutoff declared, a record without a usable timestamp
/// cannot be admitted (`Some` skip reason, counted); records with
/// parseable timestamps must be on or after the cutoff. Without a
/// cutoff, everything keeps (`None`) and the caller preserves whatever
/// timestamp state the export carried (counting unparseable raws).
/// Mail fails closed at its own seam instead — see the mbox module.
pub(crate) fn since_skip_reason(
    since: Option<time::Date>,
    created_at: Option<OffsetDateTime>,
    raw_present: bool,
) -> Option<&'static str> {
    let cutoff = since?;
    match created_at {
        Some(at) if at.date() >= cutoff => None,
        Some(_) => Some("before_since"),
        None => Some(if raw_present {
            "unparseable_timestamp"
        } else {
            "date_missing"
        }),
    }
}

/// Streams one declared archive as bounded, provenance-carrying records.
///
/// The declaration is re-validated before any byte moves; format/selection
/// mismatches are refused by the domain `validate()` exactly as the
/// registry pipeline refuses them. Records are delivered in export order
/// through `emit`; an emit error or an unreadable source aborts the
/// stream typed, while individual excluded records are counted and
/// skipped.
pub fn stream_archive(
    declaration: &ArchiveSourceDeclaration,
    emit: &mut dyn FnMut(ArchiveRecord) -> BrainResult<()>,
) -> BrainResult<ArchiveStreamSummary> {
    declaration.validate()?;
    let mut summary = ArchiveStreamSummary::default();
    let mut seen = HashMap::new();
    match declaration.format {
        ArchiveFormat::ClaudeExport => {
            claude::stream(declaration, &mut seen, &mut summary, emit)?;
        }
        ArchiveFormat::GrokExport => {
            grok::stream(declaration, &mut seen, &mut summary, emit)?;
        }
        ArchiveFormat::Mbox => {
            mbox::stream(declaration, &mut seen, &mut summary, emit)?;
        }
        ArchiveFormat::ChatGptExport => {
            chatgpt::stream(declaration, &mut seen, &mut summary, emit)?;
        }
        ArchiveFormat::GeminiWorkspace => {
            gemini_workspace::stream(declaration, &mut seen, &mut summary, emit)?;
        }
        ArchiveFormat::NotebookLm => {
            notebooklm::stream(declaration, &mut seen, &mut summary, emit)?;
        }
    }
    Ok(summary)
}
