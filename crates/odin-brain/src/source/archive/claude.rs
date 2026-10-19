//! Claude export parser: `conversations.json` + `memories/*.json`.
//!
//! `conversations.json` is one giant JSON array; it is streamed with a serde
//! visitor so at most one conversation is in memory at a time (a
//! `StreamDeserializer` iterates top-level values and cannot stream
//! *inside* an array). Memory records come from the `memories/` directory
//! beside the export, keyed by their stable file uuid. Attachments and
//! files contribute metadata-only asset records: `extracted_content`
//! bodies never enter a record. `projects/*.json` are prompt templates,
//! declared out of scope for this format, and counted as skipped; the
//! `*.zip` siblings (artifact archives) are not part of this format.
//!
//! Chats are keep-all: no record is truncated (oversized normalized text
//! is segmented with stable part identity), and a malformed memory file
//! fails the stream typed instead of dropping content. The declared
//! `since` cutoff applies to records with parseable timestamps; records
//! without one are kept with `created_at: None` and counted.

use std::collections::HashMap;
use std::fs::File;
use std::io::BufReader;

use odin_domain::knowledge::archive::ArchiveSourceDeclaration;
use serde::de::{SeqAccess, Visitor};
use serde::Deserialize;
use serde::Deserializer as _;

use crate::error::{BrainError, BrainResult};
use crate::source::archive::{
    parse_timestamp, segment_and_deliver, since_skip_reason, ArchiveAssetOrigin, ArchiveProvenance,
    ArchiveRecord, ArchiveRecordKind, ArchiveStreamSummary,
};

const CONVERSATIONS_FILE: &str = "conversations.json";
const MEMORIES_DIR: &str = "memories";
const PROJECTS_DIR: &str = "projects";

#[derive(Deserialize)]
struct Conversation {
    uuid: String,
    name: Option<String>,
    summary: Option<String>,
    created_at: Option<String>,
    updated_at: Option<String>,
    account: Option<Account>,
    chat_messages: Vec<ChatMessage>,
}

#[derive(Deserialize)]
struct Account {
    uuid: String,
}

#[derive(Deserialize)]
struct ChatMessage {
    uuid: String,
    sender: Option<String>,
    text: Option<String>,
    content: Option<Vec<ContentBlock>>,
    created_at: Option<String>,
    attachments: Option<Vec<Attachment>>,
    files: Option<Vec<ChatFile>>,
}

#[derive(Deserialize)]
struct ContentBlock {
    #[serde(rename = "type")]
    block_type: String,
    text: Option<String>,
    thinking: Option<String>,
    name: Option<String>,
    input: Option<serde_json::Value>,
    content: Option<serde_json::Value>,
}

/// Attachment metadata. `extracted_content` is deliberately absent: bodies
/// of uploaded assets never enter a record.
#[derive(Deserialize)]
struct Attachment {
    file_name: Option<String>,
    #[serde(default, deserialize_with = "declared_size")]
    file_size: Option<String>,
    file_type: Option<String>,
}

/// One `files` entry of a message: the same asset identity the attachment
/// records carry.
#[derive(Deserialize)]
struct ChatFile {
    file_uuid: Option<String>,
    file_name: Option<String>,
    #[serde(default, deserialize_with = "declared_size")]
    file_size: Option<String>,
    file_type: Option<String>,
}

/// Export builds declare an asset size either as a JSON number or as a
/// quoted number; both are the export's own value and are carried verbatim as
/// text. Every other shape stays absent — a size is never invented.
fn declared_size<'de, D>(deserializer: D) -> Result<Option<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::Deserialize as _;
    Ok(
        match Option::<serde_json::Value>::deserialize(deserializer)? {
            Some(serde_json::Value::Number(size)) => Some(size.to_string()),
            Some(serde_json::Value::String(size)) => Some(size),
            _ => None,
        },
    )
}

#[derive(Deserialize)]
struct MemoryFile {
    account_uuid: Option<String>,
    conversations_memory: Option<String>,
    memory_files: Option<Vec<MemoryFileEntry>>,
    project_memories: Option<std::collections::BTreeMap<String, String>>,
}

#[derive(Deserialize)]
struct MemoryFileEntry {
    path: String,
    content: String,
}

pub(super) fn stream(
    declaration: &ArchiveSourceDeclaration,
    seen: &mut HashMap<String, String>,
    summary: &mut ArchiveStreamSummary,
    emit: &mut dyn FnMut(ArchiveRecord) -> BrainResult<()>,
) -> BrainResult<()> {
    stream_conversations(declaration, seen, summary, emit)?;
    stream_memories(declaration, seen, summary, emit)?;
    if declaration.path.join(PROJECTS_DIR).is_dir() {
        summary.skip("project_records_out_of_scope");
    }
    Ok(())
}

fn stream_conversations(
    declaration: &ArchiveSourceDeclaration,
    seen: &mut HashMap<String, String>,
    summary: &mut ArchiveStreamSummary,
    emit: &mut dyn FnMut(ArchiveRecord) -> BrainResult<()>,
) -> BrainResult<()> {
    let path = declaration.path.join(CONVERSATIONS_FILE);
    let file = File::open(&path).map_err(|err| BrainError::Unavailable {
        component: "archive",
        reason: format!("cannot open {}: {err}", path.display()),
    })?;
    let reader = BufReader::new(file);
    let mut deserializer = serde_json::Deserializer::from_reader(reader);
    let visitor = ConversationStream {
        seen,
        summary,
        emit,
        since: declaration.selection.since,
    };
    deserializer
        .deserialize_seq(visitor)
        .map_err(BrainError::Serialization)
}

/// Streams the top-level `conversations.json` array one conversation at a
/// time.
struct ConversationStream<'a> {
    seen: &'a mut HashMap<String, String>,
    summary: &'a mut ArchiveStreamSummary,
    emit: &'a mut dyn FnMut(ArchiveRecord) -> BrainResult<()>,
    /// Declared hard date cutoff for message records, if any.
    since: Option<time::Date>,
}

impl<'a, 'de> Visitor<'de> for ConversationStream<'a> {
    type Value = ();

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str("a JSON array of Claude export conversations")
    }

    fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        while let Some(conversation) = seq.next_element::<Conversation>()? {
            emit_conversation(self.seen, self.summary, self.emit, self.since, conversation)
                .map_err(serde::de::Error::custom)?;
        }
        Ok(())
    }
}

fn emit_conversation(
    seen: &mut HashMap<String, String>,
    summary: &mut ArchiveStreamSummary,
    emit: &mut dyn FnMut(ArchiveRecord) -> BrainResult<()>,
    since: Option<time::Date>,
    conversation: Conversation,
) -> BrainResult<()> {
    let export_account = conversation
        .account
        .as_ref()
        .map(|account| account.uuid.clone());
    let (created_at, created_raw) = match conversation.created_at.as_deref() {
        Some(raw) => (parse_timestamp(raw), Some(raw)),
        None => (None, None),
    };
    if created_raw.is_some() && created_at.is_none() {
        summary.skip("unparseable_timestamp");
    }
    let base = ArchiveProvenance {
        export_account,
        conversation_id: Some(conversation.uuid.clone()),
        created_at,
        ..ArchiveProvenance::default()
    };

    // Conversation identity record: the export title, or a deterministic
    // derivation from the first user message when the export has no name.
    let title = conversation
        .name
        .as_deref()
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .map(str::to_owned)
        .unwrap_or_else(|| first_user_message_preview(&conversation));
    segment_and_deliver(
        summary,
        seen,
        ArchiveRecord {
            natural_key: conversation.uuid.clone(),
            kind: ArchiveRecordKind::Conversation,
            text: title,
            provenance: base.clone(),
        },
        emit,
    )?;

    // One summary record per conversation. An absent export summary
    // becomes a deterministic derived summary built only from counts,
    // timestamps, and message text — never model-invented facts.
    let export_summary = conversation
        .summary
        .as_deref()
        .map(str::trim)
        .filter(|text| !text.is_empty());
    let summary_text = match export_summary {
        Some(export_summary) => export_summary.to_owned(),
        None => derived_summary(&conversation),
    };
    segment_and_deliver(
        summary,
        seen,
        ArchiveRecord {
            natural_key: format!("{}:summary", conversation.uuid),
            kind: ArchiveRecordKind::ConversationSummary,
            text: summary_text,
            provenance: base.clone(),
        },
        emit,
    )?;

    for message in &conversation.chat_messages {
        summary.messages_parsed += 1;
        let body = message_body(message);
        let body = if body.trim().is_empty() {
            // Keep-all: a message whose export text is empty still carries
            // real identity (uuid, sender, timestamp) and its declared
            // attachment metadata, so it is admitted as a metadata record —
            // counted, never dropped, never invented.
            summary.skip("empty_body");
            message_metadata_text(message)
        } else {
            body
        };
        let (message_created, message_created_raw) = match message.created_at.as_deref() {
            Some(raw) => (parse_timestamp(raw), Some(raw)),
            None => (None, None),
        };
        // Hard cutoff when declared: records without a usable timestamp
        // cannot be admitted under a declared cutoff. Without one,
        // keep-all preserves the record (an unparseable raw is counted
        // below and `created_at` stays `None`).
        if let Some(reason) =
            since_skip_reason(since, message_created, message_created_raw.is_some())
        {
            summary.skip(reason);
            continue;
        }
        if message_created_raw.is_some() && message_created.is_none() {
            summary.skip("unparseable_timestamp");
        }
        segment_and_deliver(
            summary,
            seen,
            ArchiveRecord {
                natural_key: message.uuid.clone(),
                kind: ArchiveRecordKind::Message,
                text: body,
                provenance: ArchiveProvenance {
                    message_id: Some(message.uuid.clone()),
                    created_at: message_created,
                    sent_by_user: message.sender.as_deref() == Some("user"),
                    ..base.clone()
                },
            },
            emit,
        )?;

        for (index, attachment) in message.attachments.iter().flatten().enumerate() {
            let name = attachment
                .file_name
                .clone()
                .unwrap_or_else(|| format!("attachment-{index}"));
            deliver_asset(
                seen,
                summary,
                emit,
                &message.uuid,
                &base,
                name,
                attachment.file_size.clone(),
                attachment.file_type.clone(),
                // The export ships attachment metadata only: the locator
                // is the declaration site plus the 1-based position — the
                // declared filename is never claimed as an existing member.
                Some(ArchiveAssetOrigin {
                    declared_in: Some(CONVERSATIONS_FILE.to_owned()),
                    position: Some(index as u64 + 1),
                    ..ArchiveAssetOrigin::default()
                }),
            )?;
        }
        for (index, file) in message.files.iter().flatten().enumerate() {
            let name = file
                .file_name
                .clone()
                .or_else(|| file.file_uuid.clone())
                .unwrap_or_else(|| "file".to_owned());
            deliver_asset(
                seen,
                summary,
                emit,
                &message.uuid,
                &base,
                name,
                file.file_size.clone(),
                file.file_type.clone(),
                Some(ArchiveAssetOrigin {
                    declared_in: Some(CONVERSATIONS_FILE.to_owned()),
                    asset_id: file.file_uuid.clone(),
                    position: Some(index as u64 + 1),
                    ..ArchiveAssetOrigin::default()
                }),
            )?;
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn deliver_asset(
    seen: &mut HashMap<String, String>,
    summary: &mut ArchiveStreamSummary,
    emit: &mut dyn FnMut(ArchiveRecord) -> BrainResult<()>,
    message_uuid: &str,
    base: &ArchiveProvenance,
    name: String,
    size: Option<String>,
    media_type: Option<String>,
    origin: Option<ArchiveAssetOrigin>,
) -> BrainResult<()> {
    let size_label = size
        .as_deref()
        .and_then(|value| value.parse::<u64>().ok())
        .map(|size| size.to_string())
        .unwrap_or_else(|| "unknown".to_owned());
    let media_label = media_type.as_deref().unwrap_or("unknown");
    segment_and_deliver(
        summary,
        seen,
        ArchiveRecord {
            natural_key: format!("{message_uuid}:asset:{name}"),
            kind: ArchiveRecordKind::AssetMetadata,
            text: format!(
                "uploaded asset: name={name} size_bytes={size_label} media_type={media_label}"
            ),
            provenance: ArchiveProvenance {
                message_id: Some(message_uuid.to_owned()),
                origin,
                ..base.clone()
            },
        },
        emit,
    )
}

/// Normalizes one chat message: text and thinking blocks in full, tool
/// calls with their full declared payloads (keep-all — no truncation).
/// The declared identity text of one message whose export body is empty: a
/// deterministic absence marker plus the export's own attachment metadata
/// (name, declared size, media type). Nothing is decoded and nothing is
/// invented — an absent field stays `unknown`.
fn message_metadata_text(message: &ChatMessage) -> String {
    let mut text = "[no text content]".to_owned();
    for attachment in message.attachments.iter().flatten() {
        let name = attachment.file_name.as_deref().unwrap_or("unnamed");
        let size = attachment.file_size.as_deref().unwrap_or("unknown");
        let media = attachment.file_type.as_deref().unwrap_or("unknown");
        text.push_str(&format!(
            "\n[attachment name={name} size_bytes={size} media_type={media}]"
        ));
    }
    for file in message.files.iter().flatten() {
        let name = file
            .file_name
            .as_deref()
            .or(file.file_uuid.as_deref())
            .unwrap_or("unnamed");
        let size = file.file_size.as_deref().unwrap_or("unknown");
        let media = file.file_type.as_deref().unwrap_or("unknown");
        text.push_str(&format!(
            "\n[attachment name={name} size_bytes={size} media_type={media}]"
        ));
    }
    text
}

fn message_body(message: &ChatMessage) -> String {
    let mut body = String::new();
    match &message.content {
        Some(blocks) => {
            for block in blocks {
                match block.block_type.as_str() {
                    "text" => push_opt(&mut body, block.text.as_deref()),
                    "thinking" => push_opt(&mut body, block.thinking.as_deref()),
                    "tool_use" => {
                        let name = block.name.as_deref().unwrap_or("unknown");
                        body.push_str(&format!("[tool_use {name}] "));
                        push_json(&mut body, block.input.as_ref());
                    }
                    "tool_result" => {
                        body.push_str("[tool_result] ");
                        push_json(&mut body, block.content.as_ref());
                    }
                    other => body.push_str(&format!("[unsupported block type: {other}]")),
                }
            }
        }
        None => push_opt(&mut body, message.text.as_deref()),
    }
    body
}

fn push_opt(body: &mut String, text: Option<&str>) {
    if let Some(text) = text {
        if !text.is_empty() {
            if !body.is_empty() {
                body.push('\n');
            }
            body.push_str(text);
        }
    }
}

/// Flattens a tool-call JSON payload into the normalized body: raw
/// strings pass through, tool-result content arrays concatenate their
/// text fields, anything else serializes compactly.
fn push_json(body: &mut String, value: Option<&serde_json::Value>) {
    let Some(value) = value else {
        return;
    };
    match value {
        serde_json::Value::String(text) => body.push_str(text),
        serde_json::Value::Array(items) => {
            let flat = items
                .iter()
                .filter_map(|item| match item {
                    serde_json::Value::Object(fields) => fields
                        .get("text")
                        .and_then(|text| text.as_str())
                        .map(str::to_owned),
                    _ => None,
                })
                .collect::<Vec<_>>()
                .join("\n");
            body.push_str(&flat);
        }
        other => body.push_str(&other.to_string()),
    }
}

/// Deterministic derivation for a conversation with no export title:
/// a preview of the first user message.
fn first_user_message_preview(conversation: &Conversation) -> String {
    conversation
        .chat_messages
        .iter()
        .find(|message| message.sender.as_deref() == Some("user"))
        .map(|message| {
            let body = message_body(message);
            let mut preview: String = body.chars().take(240).collect();
            if body.chars().count() > 240 {
                preview.push('…');
            }
            preview
        })
        .unwrap_or_else(|| "untitled conversation".to_owned())
}

/// Deterministic summary for a conversation whose export summary is
/// absent: built only from the title, message counts, timestamps, and a
/// preview of the first user message.
fn derived_summary(conversation: &Conversation) -> String {
    let title = conversation
        .name
        .as_deref()
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .unwrap_or("untitled");
    let range = match (
        conversation.created_at.as_deref(),
        conversation.updated_at.as_deref(),
    ) {
        (Some(first), Some(last)) => format!("{first} .. {last}"),
        (Some(first), None) => first.to_owned(),
        _ => "unknown dates".to_owned(),
    };
    format!(
        "Export summary absent. Conversation '{title}': {} messages, {range}. First user message: {}",
        conversation.chat_messages.len(),
        first_user_message_preview(conversation)
    )
}

/// Emits the `memories/*.json` records beside the export: the account's
/// conversation memory, per-file memory records, and per-project memory
/// records, all keyed by the stable memory file uuid. Keep-all: a
/// malformed memory file fails the stream typed rather than dropping it.
fn stream_memories(
    declaration: &ArchiveSourceDeclaration,
    seen: &mut HashMap<String, String>,
    summary: &mut ArchiveStreamSummary,
    emit: &mut dyn FnMut(ArchiveRecord) -> BrainResult<()>,
) -> BrainResult<()> {
    let memories_dir = declaration.path.join(MEMORIES_DIR);
    let entries = match std::fs::read_dir(&memories_dir) {
        Ok(entries) => entries,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(err) => {
            return Err(BrainError::Unavailable {
                component: "archive",
                reason: format!("cannot read {}: {err}", memories_dir.display()),
            });
        }
    };
    for entry in entries {
        let entry = entry.map_err(|err| BrainError::Unavailable {
            component: "archive",
            reason: format!("cannot read {}: {err}", memories_dir.display()),
        })?;
        let path = entry.path();
        if path.extension().and_then(|ext| ext.to_str()) != Some("json") {
            continue;
        }
        let Some(stem) = path
            .file_stem()
            .and_then(|stem| stem.to_str())
            .map(str::to_owned)
        else {
            summary.skip("memory_without_stable_uuid");
            continue;
        };
        let file = File::open(&path).map_err(|err| BrainError::Unavailable {
            component: "archive",
            reason: format!("cannot open {}: {err}", path.display()),
        })?;
        let memory: MemoryFile =
            serde_json::from_reader(file).map_err(BrainError::Serialization)?;
        let base = ArchiveProvenance {
            export_account: memory.account_uuid.clone(),
            ..ArchiveProvenance::default()
        };
        if let Some(text) = memory
            .conversations_memory
            .as_deref()
            .map(str::trim)
            .filter(|text| !text.is_empty())
        {
            deliver_memory(seen, summary, emit, &stem, "conversations", text, &base)?;
        }
        for file in memory.memory_files.iter().flatten() {
            if file.content.trim().is_empty() {
                summary.skip("empty_memory");
                continue;
            }
            deliver_memory(
                seen,
                summary,
                emit,
                &stem,
                &format!("file:{}", file.path),
                &file.content,
                &base,
            )?;
        }
        for (project_uuid, text) in memory.project_memories.iter().flatten() {
            if text.trim().is_empty() {
                summary.skip("empty_memory");
                continue;
            }
            deliver_memory(
                seen,
                summary,
                emit,
                &stem,
                &format!("project:{project_uuid}"),
                text,
                &base,
            )?;
        }
    }
    Ok(())
}

fn deliver_memory(
    seen: &mut HashMap<String, String>,
    summary: &mut ArchiveStreamSummary,
    emit: &mut dyn FnMut(ArchiveRecord) -> BrainResult<()>,
    stem: &str,
    scope: &str,
    text: &str,
    base: &ArchiveProvenance,
) -> BrainResult<()> {
    segment_and_deliver(
        summary,
        seen,
        ArchiveRecord {
            natural_key: format!("{stem}:{scope}"),
            kind: ArchiveRecordKind::Memory,
            text: text.to_owned(),
            provenance: base.clone(),
        },
        emit,
    )
}
