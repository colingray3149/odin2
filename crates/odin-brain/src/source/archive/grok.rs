//! Grok export parser: a zip archive read in place, never extracted.
//!
//! The export bundle is a zip whose `ttl/30d/export_data/<export-uuid>/
//! prod-grok-backend.json` holds `{"conversations": [{"conversation":
//! {...}, "responses": [{"response": {...}}]}], ...}`. The conversations
//! array is streamed with a serde visitor through the zip entry's
//! decompressor, so the JSON is never fully materialized and nothing is
//! written to disk. `prod-mc-asset-server/<uuid>/content` entries are
//! metadata only (uuid + size from the zip central directory); their
//! bodies are never read.

use std::collections::HashMap;
use std::fs::File;
use std::io::{BufReader, Read};

use odin_domain::knowledge::archive::ArchiveSourceDeclaration;
use serde::de::{DeserializeSeed, IgnoredAny, MapAccess, SeqAccess, Visitor};
use serde::Deserialize;
use serde::Deserializer as _;
use time::OffsetDateTime;

use crate::error::{BrainError, BrainResult};
use crate::source::archive::{
    parse_timestamp, segment_and_deliver, since_skip_reason, ArchiveAssetOrigin, ArchiveProvenance,
    ArchiveRecord, ArchiveRecordKind, ArchiveStreamSummary,
};

/// Limit uncompressed entry bytes to reject decompression bombs.
const MAX_ENTRY_BYTES: u64 = 256 * 1024 * 1024;

const BACKEND_JSON_SUFFIX: &str = "prod-grok-backend.json";
const ASSET_SERVER_MARKER: &str = "prod-mc-asset-server/";
const EXPORT_DATA_MARKER: &str = "export_data/";

#[derive(Deserialize)]
struct GrokConversation {
    conversation: GrokConvMeta,
    responses: Vec<GrokResponseEntry>,
}

#[derive(Deserialize)]
struct GrokConvMeta {
    id: String,
    user_id: Option<String>,
    title: Option<String>,
    summary: Option<String>,
    create_time: Option<String>,
    modify_time: Option<String>,
    asset_ids: Option<Vec<String>>,
}

#[derive(Deserialize)]
struct GrokResponseEntry {
    response: GrokResponse,
}

#[derive(Deserialize)]
struct GrokResponse {
    #[serde(rename = "_id")]
    id: String,
    #[serde(default)]
    message: Option<String>,
    sender: Option<String>,
    create_time: Option<GrokDate>,
    model: Option<String>,
    file_attachments: Option<Vec<String>>,
    card_attachments_json: Option<Vec<String>>,
}

/// Grok timestamps appear both as ISO strings and as MongoDB extended JSON
/// (`{"$date": {"$numberLong": "<millis>"}}`); both are real export forms.
#[derive(Deserialize)]
#[serde(untagged)]
enum GrokDate {
    Iso(String),
    Mongo {
        #[serde(rename = "$date")]
        date: MongoDate,
    },
}

#[derive(Deserialize)]
struct MongoDate {
    #[serde(rename = "$numberLong")]
    millis: String,
}

impl GrokDate {
    fn parse(&self) -> Option<OffsetDateTime> {
        match self {
            GrokDate::Iso(raw) => parse_timestamp(raw),
            GrokDate::Mongo { date } => date.millis.trim().parse::<i64>().ok().and_then(|millis| {
                // time 0.3 has no from_unix_timestamp_ms; split into
                // seconds and subsecond remainder (euclidean, so pre-1970
                // values stay exact).
                let seconds = millis.div_euclid(1000);
                let sub_millis = millis.rem_euclid(1000);
                OffsetDateTime::from_unix_timestamp(seconds)
                    .ok()
                    .map(|at| at + time::Duration::milliseconds(sub_millis))
            }),
        }
    }
}

pub(super) fn stream(
    declaration: &ArchiveSourceDeclaration,
    seen: &mut HashMap<String, String>,
    summary: &mut ArchiveStreamSummary,
    emit: &mut dyn FnMut(ArchiveRecord) -> BrainResult<()>,
) -> BrainResult<()> {
    let file = File::open(&declaration.path).map_err(|err| BrainError::Unavailable {
        component: "archive",
        reason: format!("cannot open {}: {err}", declaration.path.display()),
    })?;
    let mut archive =
        zip::ZipArchive::new(BufReader::new(file)).map_err(|err| BrainError::Unavailable {
            component: "archive",
            reason: format!(
                "{} is not a readable zip archive: {err}",
                declaration.path.display()
            ),
        })?;

    // Locate the conversation JSON entry and index asset entries from the
    // central directory (metadata only; asset bodies never move). The
    // exact member name is the locator fact — and only an UNAMBIGUOUS
    // one: a second central-directory entry claiming an already-claimed
    // asset id marks the id ambiguous (counted), no member is claimed and
    // no inferred size kept; no bytes are read or hashed to disambiguate.
    // (Identical-name duplicates are a documented reader limitation: the
    // maintained zip reader coalesces same-named entries to one — last
    // physical entry — before any parser sees them.)
    let mut backend_index = None;
    let mut backend_member = None;
    let mut export_id = None;
    let mut assets: HashMap<String, GrokAsset> = HashMap::new();
    for index in 0..archive.len() {
        let entry = archive
            .by_index(index)
            .map_err(|err| BrainError::Unavailable {
                component: "archive",
                reason: format!("cannot read zip entry {index}: {err}"),
            })?;
        let name = super::member_name(&entry)?;
        if name.ends_with(BACKEND_JSON_SUFFIX) && backend_index.is_none() {
            backend_index = Some(index);
            backend_member = Some(name.clone());
            export_id = export_uuid(&name);
        }
        if let Some(asset_uuid) = asset_uuid(&name) {
            match assets.get_mut(&asset_uuid) {
                None => {
                    assets.insert(
                        asset_uuid,
                        GrokAsset {
                            member: Some(name.clone()),
                            size: Some(entry.size()),
                        },
                    );
                }
                Some(existing) => {
                    existing.member = None;
                    existing.size = None;
                    summary.skip("ambiguous_asset_member");
                }
            }
        }
    }
    let Some(backend_index) = backend_index else {
        return Err(BrainError::Unavailable {
            component: "archive",
            reason: format!(
                "no {BACKEND_JSON_SUFFIX} entry found in {}",
                declaration.path.display()
            ),
        });
    };

    let entry = archive
        .by_index(backend_index)
        .map_err(|err| BrainError::Unavailable {
            component: "archive",
            reason: format!("cannot open zip entry {backend_index}: {err}"),
        })?;
    if entry.size() > MAX_ENTRY_BYTES {
        return Err(BrainError::Unavailable {
            component: "archive",
            reason: format!(
                "zip entry {} is {} bytes, exceeding the {MAX_ENTRY_BYTES} bound",
                super::member_name(&entry)?,
                entry.size()
            ),
        });
    }
    let reader = BufReader::new(entry.take(MAX_ENTRY_BYTES));
    let mut deserializer = serde_json::Deserializer::from_reader(reader);
    let visitor = ExportVisitor {
        seen,
        summary,
        emit,
        export_id,
        backend_member: backend_member.unwrap_or_default(),
        assets: &assets,
        since: declaration.selection.since,
    };
    deserializer
        .deserialize_map(visitor)
        .map_err(BrainError::Serialization)
}

/// Extracts the export bundle uuid from `.../export_data/<uuid>/...`.
fn export_uuid(name: &str) -> Option<String> {
    name.split(EXPORT_DATA_MARKER)
        .nth(1)?
        .split('/')
        .next()
        .filter(|part| !part.is_empty())
        .map(str::to_owned)
}

/// Extracts the asset uuid from `.../prod-mc-asset-server//<uuid>/content`
/// (the export writes a doubled separator; `trim_start_matches` covers it).
fn asset_uuid(name: &str) -> Option<String> {
    let tail = name.split(ASSET_SERVER_MARKER).nth(1)?;
    tail.trim_start_matches('/')
        .split('/')
        .next()
        .filter(|part| !part.is_empty())
        .map(str::to_owned)
}
/// One asset id's central-directory facts. `member`/`size` are `None`
/// exactly when a second DISTINCT-name central-directory entry claims
/// the id (counted ambiguity, declared metadata stays the only
/// fallback); identical-name duplicates never reach this parser — the
/// maintained zip reader's index coalesces them to one entry. No bytes
/// are read or hashed to disambiguate.
struct GrokAsset {
    member: Option<String>,
    size: Option<u64>,
}

/// Streams the top-level export object, descending only into the
/// `conversations` array; every other key is skipped without buffering.
struct ExportVisitor<'a> {
    seen: &'a mut HashMap<String, String>,
    summary: &'a mut ArchiveStreamSummary,
    emit: &'a mut dyn FnMut(ArchiveRecord) -> BrainResult<()>,
    export_id: Option<String>,
    backend_member: String,
    assets: &'a HashMap<String, GrokAsset>,
    since: Option<time::Date>,
}

impl<'a, 'de> Visitor<'de> for ExportVisitor<'a> {
    type Value = ();

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str("the Grok export JSON object")
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        while let Some(key) = map.next_key::<String>()? {
            if key == "conversations" {
                map.next_value_seed(ConversationsVisitor {
                    seen: self.seen,
                    summary: self.summary,
                    emit: self.emit,
                    export_id: &self.export_id,
                    assets: self.assets,
                    backend_member: self.backend_member.clone(),
                    since: self.since,
                })?;
            } else {
                map.next_value::<IgnoredAny>()?;
            }
        }
        Ok(())
    }
}

struct ConversationsVisitor<'a> {
    seen: &'a mut HashMap<String, String>,
    summary: &'a mut ArchiveStreamSummary,
    emit: &'a mut dyn FnMut(ArchiveRecord) -> BrainResult<()>,
    export_id: &'a Option<String>,
    assets: &'a HashMap<String, GrokAsset>,
    backend_member: String,
    since: Option<time::Date>,
}

impl<'de> DeserializeSeed<'de> for ConversationsVisitor<'_> {
    type Value = ();

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_seq(self)
    }
}

impl<'a, 'de> Visitor<'de> for ConversationsVisitor<'a> {
    type Value = ();

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str("a JSON array of Grok conversations")
    }

    fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        while let Some(conversation) = seq.next_element::<GrokConversation>()? {
            emit_conversation(
                self.seen,
                self.summary,
                self.emit,
                conversation,
                self.export_id,
                self.assets,
                &self.backend_member,
                self.since,
            )
            .map_err(serde::de::Error::custom)?;
        }
        Ok(())
    }
}

#[allow(clippy::too_many_arguments)]
fn emit_conversation(
    seen: &mut HashMap<String, String>,
    summary: &mut ArchiveStreamSummary,
    emit: &mut dyn FnMut(ArchiveRecord) -> BrainResult<()>,
    conversation: GrokConversation,
    export_id: &Option<String>,
    assets: &HashMap<String, GrokAsset>,
    backend_member: &str,
    since: Option<time::Date>,
) -> BrainResult<()> {
    let meta = &conversation.conversation;
    let export_account = meta.user_id.clone();
    let (created_at, created_unparseable) = match meta.create_time.as_deref() {
        Some(raw) => {
            let parsed = parse_timestamp(raw);
            (parsed, parsed.is_none())
        }
        None => (None, false),
    };
    if created_unparseable {
        summary.skip("unparseable_timestamp");
    }
    let base = ArchiveProvenance {
        export_account,
        export_id: export_id.clone(),
        conversation_id: Some(meta.id.clone()),
        created_at,
        ..ArchiveProvenance::default()
    };

    // Conversation identity record: title or a deterministic derivation
    // from the first human message.
    let title = meta
        .title
        .as_deref()
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .map(str::to_owned)
        .unwrap_or_else(|| first_human_message_preview(&conversation));
    segment_and_deliver(
        summary,
        seen,
        ArchiveRecord {
            natural_key: meta.id.clone(),
            kind: ArchiveRecordKind::Conversation,
            text: title,
            provenance: base.clone(),
        },
        emit,
    )?;

    // Summary record: Grok exports ship empty summaries in practice, so
    // the deterministic derived form is the norm, built only from counts,
    // timestamps, and message text — never model-invented facts.
    let export_summary = meta
        .summary
        .as_deref()
        .map(str::trim)
        .filter(|text| !text.is_empty());
    let summary_text = match export_summary {
        Some(export_summary) => export_summary.to_owned(),
        None => derived_summary(meta, &conversation),
    };
    segment_and_deliver(
        summary,
        seen,
        ArchiveRecord {
            natural_key: format!("{}:summary", meta.id),
            kind: ArchiveRecordKind::ConversationSummary,
            text: summary_text,
            provenance: base.clone(),
        },
        emit,
    )?;

    for entry in &conversation.responses {
        summary.messages_parsed += 1;
        let response = &entry.response;
        let body = response.message.as_deref().map(str::trim).unwrap_or("");
        let body = if body.is_empty() {
            // Keep-all: a response whose export text is empty still carries
            // real identity (id, sender, timestamp), so it is admitted as a
            // metadata record with a deterministic absence marker —
            // counted, never dropped, never invented.
            summary.skip("empty_body");
            "[no text content]"
        } else {
            body
        };
        let text = match (response.sender.as_deref(), response.model.as_deref()) {
            (Some("assistant"), Some(model)) if !model.is_empty() => {
                format!("[model {model}]\n{body}")
            }
            _ => body.to_owned(),
        };
        let (created_at, created_unparseable) = match response.create_time.as_ref() {
            Some(date) => {
                let parsed = date.parse();
                (parsed, parsed.is_none())
            }
            None => (None, false),
        };
        // Hard cutoff when declared: records without a usable timestamp
        // cannot be admitted under a declared cutoff. Without one,
        // keep-all preserves the record (an unparseable raw is counted
        // below and `created_at` stays `None`).
        if let Some(reason) = since_skip_reason(since, created_at, response.create_time.is_some()) {
            summary.skip(reason);
            continue;
        }
        if created_unparseable {
            summary.skip("unparseable_timestamp");
        }
        segment_and_deliver(
            summary,
            seen,
            ArchiveRecord {
                natural_key: response.id.clone(),
                kind: ArchiveRecordKind::Message,
                text,
                provenance: ArchiveProvenance {
                    message_id: Some(response.id.clone()),
                    created_at,
                    sent_by_user: response.sender.as_deref() == Some("human"),
                    ..base.clone()
                },
            },
            emit,
        )?;

        for asset_id in response.file_attachments.iter().flatten() {
            let asset = assets.get(asset_id);
            deliver_asset(
                seen,
                summary,
                emit,
                &base,
                &response.id,
                asset_id,
                asset.and_then(|asset| asset.size),
                "unknown",
                Some(ArchiveAssetOrigin {
                    declared_in: Some(backend_member.to_owned()),
                    member: asset.and_then(|asset| asset.member.clone()),
                    asset_id: Some(asset_id.clone()),
                    ..ArchiveAssetOrigin::default()
                }),
            )?;
        }
        for (index, card) in response.card_attachments_json.iter().flatten().enumerate() {
            // Cards are serialized JSON strings; only their citation URL
            // is metadata worth keeping, never the fetched content.
            let url = serde_json::from_str::<serde_json::Value>(card)
                .ok()
                .and_then(|value| {
                    value
                        .get("url")
                        .and_then(|url| url.as_str())
                        .map(str::to_owned)
                });
            let name = url.unwrap_or_else(|| format!("card-{index}"));
            deliver_asset(
                seen,
                summary,
                emit,
                &base,
                &response.id,
                &name,
                None,
                "application/x-grok-card",
                Some(ArchiveAssetOrigin {
                    declared_in: Some(backend_member.to_owned()),
                    position: Some(index as u64 + 1),
                    ..ArchiveAssetOrigin::default()
                }),
            )?;
        }
    }

    // Conversation-level asset references carry the same metadata treatment.
    for asset_id in meta.asset_ids.iter().flatten() {
        let asset = assets.get(asset_id);
        deliver_asset(
            seen,
            summary,
            emit,
            &base,
            &meta.id,
            asset_id,
            asset.and_then(|asset| asset.size),
            "unknown",
            Some(ArchiveAssetOrigin {
                declared_in: Some(backend_member.to_owned()),
                member: asset.and_then(|asset| asset.member.clone()),
                asset_id: Some(asset_id.clone()),
                ..ArchiveAssetOrigin::default()
            }),
        )?;
    }
    Ok(())
}
#[allow(clippy::too_many_arguments)]
fn deliver_asset(
    seen: &mut HashMap<String, String>,
    summary: &mut ArchiveStreamSummary,
    emit: &mut dyn FnMut(ArchiveRecord) -> BrainResult<()>,
    base: &ArchiveProvenance,
    owner_id: &str,
    asset_id: &str,
    size_bytes: Option<u64>,
    media_type: &str,
    origin: Option<ArchiveAssetOrigin>,
) -> BrainResult<()> {
    let key = format!(
        "{}:asset:{asset_id}",
        base.conversation_id.as_deref().unwrap_or(owner_id)
    );
    let size_label = size_bytes
        .map(|size| size.to_string())
        .unwrap_or_else(|| "unknown".to_owned());
    summary.deliver(
        seen,
        ArchiveRecord {
            natural_key: key,
            kind: ArchiveRecordKind::AssetMetadata,
            text: format!(
                "uploaded asset: name={asset_id} size_bytes={size_label} media_type={media_type}"
            ),
            provenance: ArchiveProvenance {
                message_id: Some(owner_id.to_owned()),
                origin,
                ..base.clone()
            },
        },
        emit,
    )
}

/// Deterministic derivation for a conversation with no export title: a
/// preview of the first human message.
fn first_human_message_preview(conversation: &GrokConversation) -> String {
    conversation
        .responses
        .iter()
        .find(|entry| entry.response.sender.as_deref() == Some("human"))
        .map(|entry| {
            let body = entry.response.message.as_deref().unwrap_or("");
            let mut preview: String = body.chars().take(240).collect();
            if body.chars().count() > 240 {
                preview.push('…');
            }
            preview
        })
        .unwrap_or_else(|| "untitled conversation".to_owned())
}

/// Deterministic summary built only from title, counts, timestamps, and
/// the first human message — never model-invented facts.
fn derived_summary(meta: &GrokConvMeta, conversation: &GrokConversation) -> String {
    let title = meta
        .title
        .as_deref()
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .unwrap_or("untitled");
    let range = match (meta.create_time.as_deref(), meta.modify_time.as_deref()) {
        (Some(first), Some(last)) => format!("{first} .. {last}"),
        (Some(first), None) => first.to_owned(),
        _ => "unknown dates".to_owned(),
    };
    format!(
        "Export summary absent. Conversation '{title}': {} messages, {range}. First human message: {}",
        conversation.responses.len(),
        first_human_message_preview(conversation)
    )
}
