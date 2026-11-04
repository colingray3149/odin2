//! Grok export parser: the export unpacked into a directory.
//!
//! The export bundle is a directory tree whose `ttl/30d/export_data/<export-uuid>/
//! prod-grok-backend.json` holds `{"conversations": [{"conversation":
//! {...}, "responses": [{"response": {...}}]}], ...}`. The conversations
//! array is streamed with a serde visitor from the file, so the JSON is
//! never fully materialized. `prod-mc-asset-server/<uuid>/content` files
//! are metadata only (uuid + file size); their bodies are never read.

use std::collections::HashMap;

use odin_domain::knowledge::archive::ArchiveSourceDeclaration;
use serde::de::{DeserializeSeed, IgnoredAny, MapAccess, SeqAccess, Visitor};
use serde::Deserialize;
use serde::Deserializer as _;
use time::OffsetDateTime;

use crate::error::{BrainError, BrainResult};
use crate::source::archive::{
    date_range, first_text_preview, parse_timestamp, segment_and_deliver, since_skip_reason,
    ArchiveAssetOrigin, ArchiveProvenance, ArchiveRecord, ArchiveRecordKind, ArchiveStreamSummary,
    AssetMetadata, SeenRecords, EMPTY_BODY_MARKER,
};

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
    seen: &mut SeenRecords,
    summary: &mut ArchiveStreamSummary,
    emit: &mut dyn FnMut(ArchiveRecord) -> BrainResult<()>,
) -> BrainResult<()> {
    // Locate the conversation JSON file and index asset files from the
    // directory listing (metadata only; asset bodies never move). The
    // exact member name is the locator fact — and only an UNAMBIGUOUS
    // one: a second file claiming an already-claimed asset id marks the
    // id ambiguous (counted), no member is claimed and no inferred size
    // kept; no bytes are read or hashed to disambiguate.
    let members = super::export_members(&declaration.path)?;
    let mut backend = None;
    let mut assets: HashMap<String, GrokAsset> = HashMap::new();
    for member in &members {
        let name = &member.name;
        if name.ends_with(BACKEND_JSON_SUFFIX) && backend.is_none() {
            backend = Some(member);
        }
        if let Some(asset_uuid) = asset_uuid(name) {
            match assets.get_mut(&asset_uuid) {
                None => {
                    assets.insert(
                        asset_uuid,
                        GrokAsset {
                            member: Some(name.clone()),
                            size: Some(member.size),
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
    let Some(backend) = backend else {
        return Err(BrainError::Unavailable {
            component: "archive",
            reason: format!(
                "no {BACKEND_JSON_SUFFIX} file found in {}",
                declaration.path.display()
            ),
        });
    };

    let mut deserializer = serde_json::Deserializer::from_reader(super::open_member(backend)?);
    let visitor = ExportVisitor {
        seen,
        summary,
        emit,
        export_id: export_uuid(&backend.name),
        backend_member: backend.name.clone(),
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

/// One asset id's file facts. `member`/`size` are `None` exactly when a
/// second file claims the id (counted ambiguity, declared metadata stays
/// the only fallback). No bytes are read or hashed to disambiguate.
struct GrokAsset {
    member: Option<String>,
    size: Option<u64>,
}

/// Streams the top-level export object, descending only into the
/// `conversations` array; every other key is skipped without buffering.
struct ExportVisitor<'a> {
    seen: &'a mut SeenRecords,
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
    seen: &'a mut SeenRecords,
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
            emit_conversation(EmitConversation {
                seen: self.seen,
                summary: self.summary,
                emit: self.emit,
                conversation,
                export_id: self.export_id,
                assets: self.assets,
                backend_member: &self.backend_member,
                since: self.since,
            })
            .map_err(serde::de::Error::custom)?;
        }
        Ok(())
    }
}

struct EmitConversation<'a> {
    seen: &'a mut SeenRecords,
    summary: &'a mut ArchiveStreamSummary,
    emit: &'a mut dyn FnMut(ArchiveRecord) -> BrainResult<()>,
    conversation: GrokConversation,
    export_id: &'a Option<String>,
    assets: &'a HashMap<String, GrokAsset>,
    backend_member: &'a str,
    since: Option<time::Date>,
}

fn emit_conversation(input: EmitConversation<'_>) -> BrainResult<()> {
    let EmitConversation {
        seen,
        summary,
        emit,
        conversation,
        export_id,
        assets,
        backend_member,
        since,
    } = input;
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
        .unwrap_or_else(|| first_text_preview(human_bodies(&conversation)));
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
            EMPTY_BODY_MARKER
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
            let record = AssetMetadata {
                scope: &meta.id,
                key: asset_id,
                message_id: &response.id,
                name: asset_id,
                size_bytes: asset.and_then(|asset| asset.size),
                media_type: "unknown",
                origin: ArchiveAssetOrigin {
                    declared_in: Some(backend_member.to_owned()),
                    member: asset.and_then(|asset| asset.member.clone()),
                    asset_id: Some(asset_id.clone()),
                    ..ArchiveAssetOrigin::default()
                },
            };
            summary.deliver(seen, record.record(&base), emit)?;
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
            let record = AssetMetadata {
                scope: &meta.id,
                key: &name,
                message_id: &response.id,
                name: &name,
                size_bytes: None,
                media_type: "application/x-grok-card",
                origin: ArchiveAssetOrigin {
                    declared_in: Some(backend_member.to_owned()),
                    position: Some(index as u64 + 1),
                    ..ArchiveAssetOrigin::default()
                },
            };
            summary.deliver(seen, record.record(&base), emit)?;
        }
    }

    // Conversation-level asset references carry the same metadata treatment.
    for asset_id in meta.asset_ids.iter().flatten() {
        let asset = assets.get(asset_id);
        let record = AssetMetadata {
            scope: &meta.id,
            key: asset_id,
            message_id: &meta.id,
            name: asset_id,
            size_bytes: asset.and_then(|asset| asset.size),
            media_type: "unknown",
            origin: ArchiveAssetOrigin {
                declared_in: Some(backend_member.to_owned()),
                member: asset.and_then(|asset| asset.member.clone()),
                asset_id: Some(asset_id.clone()),
                ..ArchiveAssetOrigin::default()
            },
        };
        summary.deliver(seen, record.record(&base), emit)?;
    }
    Ok(())
}

/// One conversation's human message bodies, in order.
fn human_bodies(conversation: &GrokConversation) -> impl Iterator<Item = &str> {
    conversation
        .responses
        .iter()
        .filter(|entry| entry.response.sender.as_deref() == Some("human"))
        .map(|entry| entry.response.message.as_deref().unwrap_or(""))
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
    let range = date_range(meta.create_time.as_deref(), meta.modify_time.as_deref());
    format!(
        "Export summary absent. Conversation '{title}': {} messages, {range}. First human message: {}",
        conversation.responses.len(),
        first_text_preview(human_bodies(conversation))
    )
}
