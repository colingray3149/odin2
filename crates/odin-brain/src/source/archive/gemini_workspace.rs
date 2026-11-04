//! Gemini in Workspace Takeout parser: an extracted Takeout root.
//!
//! The declaration path is the extracted Takeout root (the directory that
//! also holds `Mail/`, `NotebookLM/`, …). Exactly two relative layouts are
//! read, nothing else:
//!
//! - `Gemini in Workspace/Conversation History/*.txt` — one JSON file per
//!   conversation (despite the `.txt` suffix) with `title`,
//!   `creation_time`, `last_modification_time`, and `conversation_turns[]`
//!   where each turn entry carries either a `user_turn` (one prompt) or a
//!   `system_turn` (one response with `text` blocks, optional
//!   `model_thoughts` and `citations`). A malformed file fails the stream
//!   typed — an unrecognized export is never repackaged as a fake message.
//! - `Gemini/*.html` — the gems and scheduled-actions metadata documents.
//!   They are metadata-only: each document contributes a `Memory` record
//!   carrying its source-relative path and declared line count — never
//!   the rendered document text, which for gems and scheduled actions is
//!   prompt bodies. URLs are never fetched. When the directory is absent
//!   the stream simply has no metadata records; a present but empty
//!   document is counted, not invented into content.
//!
//! The export carries no account identity, no conversation uuid, and no
//! summary field: identity comes from the stable source file stem, and
//! every summary record is the deterministic derivation from counts,
//! timestamps, and a first-prompt preview. Response content is normalized
//! through a generic JSON walk, so a future export shape adds content
//! instead of silently dropping it. Keep-all: oversized text is segmented
//! with stable part identity, never truncated.
use std::collections::BTreeMap;
use std::fs::File;

use odin_domain::knowledge::archive::ArchiveSourceDeclaration;
use serde::Deserialize;
use serde_json::Value;

use crate::error::{BrainError, BrainResult};
use crate::source::archive::{
    date_range, first_text_preview, parse_timestamp, push_opt, segment_and_deliver,
    since_skip_reason, ArchiveAssetOrigin, ArchiveProvenance, ArchiveRecord, ArchiveRecordKind,
    ArchiveStreamSummary, SeenRecords, EMPTY_BODY_MARKER, HTML_TEXT_WIDTH,
};

const GEMINI_WORKSPACE_DIR: &str = "Gemini in Workspace";
const CONVERSATION_HISTORY_DIR: &str = "Conversation History";
const GEMINI_METADATA_DIR: &str = "Gemini";

pub(super) fn stream(
    declaration: &ArchiveSourceDeclaration,
    seen: &mut SeenRecords,
    summary: &mut ArchiveStreamSummary,
    emit: &mut dyn FnMut(ArchiveRecord) -> BrainResult<()>,
) -> BrainResult<()> {
    stream_conversations(declaration, seen, summary, emit)?;
    stream_metadata(declaration, seen, summary, emit)
}

// ---------------------------------------------------------------------------
// Conversation History/*.txt
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct GeminiConversation {
    #[serde(default)]
    title: Option<String>,
    #[serde(default)]
    creation_time: Option<String>,
    #[serde(default)]
    last_modification_time: Option<String>,
    #[serde(default)]
    conversation_turns: Vec<GeminiTurn>,
}

/// One export turn entry: either the operator's prompt or the model's
/// response — never both, never neither in observed exports.
#[derive(Deserialize)]
struct GeminiTurn {
    #[serde(default)]
    user_turn: Option<GeminiUserTurn>,
    #[serde(default)]
    system_turn: Option<GeminiSystemTurn>,
}

#[derive(Deserialize)]
struct GeminiUserTurn {
    #[serde(default)]
    prompt: Option<String>,
    #[serde(default)]
    turn_index: Option<u64>,
    #[serde(default)]
    turn_last_modified: Option<String>,
}

#[derive(Deserialize)]
struct GeminiSystemTurn {
    /// Response content blocks: observed shapes are `{"data": …}` and
    /// research-style `{"title", "description", "execution_plan"}`, held
    /// generically so any future shape still normalizes in full.
    #[serde(default)]
    text: Vec<Value>,
    #[serde(default)]
    model_thoughts: Vec<GeminiThought>,
    #[serde(default)]
    citations: Vec<GeminiCitation>,
    #[serde(default)]
    turn_index: Option<u64>,
    #[serde(default)]
    turn_last_modified: Option<String>,
}

#[derive(Deserialize)]
struct GeminiThought {
    #[serde(default)]
    headline: Option<String>,
    #[serde(default)]
    description: Option<String>,
}

#[derive(Deserialize)]
struct GeminiCitation {
    #[serde(default)]
    display_text: Option<String>,
    #[serde(default)]
    url: Option<String>,
}

fn stream_conversations(
    declaration: &ArchiveSourceDeclaration,
    seen: &mut SeenRecords,
    summary: &mut ArchiveStreamSummary,
    emit: &mut dyn FnMut(ArchiveRecord) -> BrainResult<()>,
) -> BrainResult<()> {
    let workspace_dir = declaration.path.join(GEMINI_WORKSPACE_DIR);
    let history_dir = workspace_dir.join(CONVERSATION_HISTORY_DIR);
    // read_dir follows a symlinked directory, so every joined directory
    // is classified before traversal: symlinks and non-directories are
    // refused typed, and absence on the required path is a declaration
    // error naming exactly which join is missing.
    if !real_directory(&workspace_dir)? {
        return Err(missing_required(&workspace_dir));
    }
    if !real_directory(&history_dir)? {
        return Err(missing_required(&history_dir));
    }
    for (name, path) in sorted_files(&history_dir, summary)? {
        if !name.ends_with(".txt") {
            summary.skip("non_transcript_file");
            continue;
        }
        let file = File::open(&path).map_err(|err| BrainError::Unavailable {
            component: "archive",
            reason: format!("cannot open {}: {err}", path.display()),
        })?;
        let conversation: GeminiConversation =
            serde_json::from_reader(file).map_err(BrainError::Serialization)?;
        emit_conversation(
            seen,
            summary,
            emit,
            declaration.selection.since,
            &name,
            conversation,
        )?;
    }
    Ok(())
}

/// Lists the regular files of one already-classified directory as
/// `(file name, path)` pairs sorted by name, so the stream order is
/// deterministic across re-reads. Entries are never followed through
/// symlinks — `file_type` does not traverse, so a symlinked file or
/// directory is counted and skipped, and nothing outside the declared
/// root is ever read through one. Names must be UTF-8 to become
/// provenance; anything else is counted.
fn sorted_files(
    dir: &std::path::Path,
    summary: &mut ArchiveStreamSummary,
) -> BrainResult<Vec<(String, std::path::PathBuf)>> {
    let entries = match std::fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(err) => return Err(unreadable(dir, err)),
    };
    let mut files = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|err| unreadable(dir, err))?;
        let file_type = entry.file_type().map_err(|err| unreadable(dir, err))?;
        if !file_type.is_file() {
            // A symlink or subdirectory: never traversed, only counted.
            summary.skip("entry_not_regular_file");
            continue;
        }
        let path = entry.path();
        let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
            summary.skip("file_without_stable_name");
            continue;
        };
        files.push((name.to_owned(), path));
    }
    files.sort_by(|first, second| first.0.cmp(&second.0));
    Ok(files)
}

/// Classifies one below-root joined directory without following symlinks:
/// `symlink_metadata` stats the link itself, where `read_dir` would
/// traverse its target. `Ok(false)` marks an absent path; every present
/// path must be a real directory, else the stream fails typed.
fn real_directory(dir: &std::path::Path) -> BrainResult<bool> {
    let meta = match std::fs::symlink_metadata(dir) {
        Ok(meta) => meta,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(err) => return Err(unreadable(dir, err)),
    };
    if meta.is_symlink() || !meta.is_dir() {
        let reason = if meta.is_symlink() {
            "symlinked directory (never followed)"
        } else {
            "not a directory"
        };
        return Err(BrainError::Unavailable {
            component: "archive",
            reason: format!("cannot read {}: {reason}", dir.display()),
        });
    }
    Ok(true)
}

fn missing_required(dir: &std::path::Path) -> BrainError {
    BrainError::Unavailable {
        component: "archive",
        reason: format!("cannot read {}: missing required directory", dir.display()),
    }
}

fn unreadable(dir: &std::path::Path, err: std::io::Error) -> BrainError {
    BrainError::Unavailable {
        component: "archive",
        reason: format!("cannot read {}: {err}", dir.display()),
    }
}

fn emit_conversation(
    seen: &mut SeenRecords,
    summary: &mut ArchiveStreamSummary,
    emit: &mut dyn FnMut(ArchiveRecord) -> BrainResult<()>,
    since: Option<time::Date>,
    name: &str,
    conversation: GeminiConversation,
) -> BrainResult<()> {
    // The export has no conversation uuid: the stable source file stem is
    // the export's own conversation identity and the record key material.
    let stem = name.strip_suffix(".txt").unwrap_or(name);
    let source_file = format!("{GEMINI_WORKSPACE_DIR}/{CONVERSATION_HISTORY_DIR}/{name}");
    let export_metadata: BTreeMap<String, Value> =
        BTreeMap::from([("source_file".to_owned(), Value::from(source_file))]);

    let (created_at, created_raw) = match conversation.creation_time.as_deref() {
        Some(raw) => (parse_timestamp(raw), Some(raw)),
        None => (None, None),
    };
    if created_raw.is_some() && created_at.is_none() {
        summary.skip("unparseable_timestamp");
    }
    let base = ArchiveProvenance {
        conversation_id: Some(stem.to_owned()),
        created_at,
        export_metadata: export_metadata.clone(),
        ..ArchiveProvenance::default()
    };

    // Conversation identity record: the export title, or a deterministic
    // derivation from the first prompt when the export has no title.
    let title = conversation
        .title
        .as_deref()
        .map(str::trim)
        .filter(|title| !title.is_empty())
        .map(str::to_owned)
        .unwrap_or_else(|| {
            first_text_preview(
                conversation
                    .conversation_turns
                    .iter()
                    .filter_map(|turn| turn.user_turn.as_ref())
                    .filter_map(|user| user.prompt.as_deref()),
            )
        });
    segment_and_deliver(
        summary,
        seen,
        ArchiveRecord {
            natural_key: stem.to_owned(),
            kind: ArchiveRecordKind::Conversation,
            text: title.clone(),
            provenance: base.clone(),
        },
        emit,
    )?;

    // One summary record per conversation. The format has no summary
    // field, so this is always the deterministic derivation from counts,
    // timestamps, and the first prompt — never model-invented facts.
    let prompts = conversation
        .conversation_turns
        .iter()
        .filter(|turn| turn.user_turn.is_some())
        .count();
    let responses = conversation
        .conversation_turns
        .iter()
        .filter(|turn| turn.system_turn.is_some())
        .count();
    let range = date_range(
        conversation.creation_time.as_deref(),
        conversation.last_modification_time.as_deref(),
    );
    segment_and_deliver(
        summary,
        seen,
        ArchiveRecord {
            natural_key: format!("{stem}:summary"),
            kind: ArchiveRecordKind::ConversationSummary,
            text: format!(
                "Conversation '{title}': {prompts} user prompts, {responses} system \
                 responses, {range}. First user prompt: {}",
                first_text_preview(
                    conversation
                        .conversation_turns
                        .iter()
                        .filter_map(|turn| turn.user_turn.as_ref())
                        .filter_map(|user| user.prompt.as_deref()),
                )
            ),
            provenance: base.clone(),
        },
        emit,
    )?;

    for (ordinal, turn) in conversation.conversation_turns.iter().enumerate() {
        let (role, body, turn_index, last_modified) = match (&turn.user_turn, &turn.system_turn) {
            (Some(user), None) => {
                summary.messages_parsed += 1;
                let prompt = user.prompt.as_deref().unwrap_or_default();
                let body = if prompt.trim().is_empty() {
                    // Keep-all: an empty prompt still carries real identity
                    // (turn index, timestamp), so it is admitted as a
                    // metadata record — counted, never dropped.
                    summary.skip("empty_body");
                    EMPTY_BODY_MARKER.to_owned()
                } else {
                    prompt.to_owned()
                };
                (
                    "user",
                    body,
                    user.turn_index,
                    user.turn_last_modified.as_deref(),
                )
            }
            (None, Some(system)) => {
                summary.messages_parsed += 1;
                let mut body = String::new();
                for block in &system.text {
                    push_value(&mut body, None, block);
                }
                for thought in &system.model_thoughts {
                    push_marker(&mut body, "model thought");
                    if let Some(headline) = thought.headline.as_deref() {
                        push_field(&mut body, "headline", headline);
                    }
                    if let Some(description) = thought.description.as_deref() {
                        push_field(&mut body, "description", description);
                    }
                }
                for citation in &system.citations {
                    push_marker(&mut body, "citation");
                    if let Some(display_text) = citation.display_text.as_deref() {
                        push_field(&mut body, "display_text", display_text);
                    }
                    // Recorded as the export's own text; never fetched.
                    if let Some(url) = citation.url.as_deref() {
                        push_field(&mut body, "url", url);
                    }
                }
                let body = if body.trim().is_empty() {
                    summary.skip("empty_body");
                    EMPTY_BODY_MARKER.to_owned()
                } else {
                    body
                };
                (
                    "system",
                    body,
                    system.turn_index,
                    system.turn_last_modified.as_deref(),
                )
            }
            (None, None) => {
                summary.skip("malformed_turn");
                continue;
            }
            (Some(_), Some(_)) => {
                summary.skip("malformed_turn");
                continue;
            }
        };

        let (created_at, created_raw) = match last_modified {
            Some(raw) => (parse_timestamp(raw), Some(raw)),
            None => (None, None),
        };
        // Hard cutoff when declared: records without a usable timestamp
        // cannot be admitted under a declared cutoff. Without one,
        // keep-all preserves the record (an unparseable raw is counted
        // below and `created_at` stays `None`).
        if let Some(reason) = since_skip_reason(since, created_at, created_raw.is_some()) {
            summary.skip(reason);
            continue;
        }
        if created_raw.is_some() && created_at.is_none() {
            summary.skip("unparseable_timestamp");
        }
        // The export numbers turns in one shared monotonic space; the
        // role-qualified key stays unique even if a future export numbers
        // each role separately. A turn without an export index falls back
        // to its array ordinal.
        let index = turn_index.unwrap_or(ordinal as u64);
        segment_and_deliver(
            summary,
            seen,
            ArchiveRecord {
                natural_key: format!("{stem}:turn:{index}:{role}"),
                kind: ArchiveRecordKind::Message,
                text: body,
                provenance: ArchiveProvenance {
                    message_id: Some(format!("{stem}:turn:{index}:{role}")),
                    created_at,
                    sent_by_user: role == "user",
                    ..base.clone()
                },
            },
            emit,
        )?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Response-content normalization
// ---------------------------------------------------------------------------

/// Renders one response-content JSON value into the normalized body.
/// `data` strings are the response prose and render plain; every other
/// string renders under its own field-name marker, so a future export
/// shape adds content instead of silently dropping it.
fn push_value(body: &mut String, marker: Option<&str>, value: &Value) {
    match value {
        Value::String(text) => match marker {
            Some(marker) => push_field(body, marker, text),
            None => push_opt(body, Some(text)),
        },
        Value::Array(items) => {
            for item in items {
                push_value(body, marker, item);
            }
        }
        Value::Object(fields) => {
            for (field, value) in fields {
                if field == "data" {
                    push_value(body, None, value);
                } else {
                    push_value(body, Some(field), value);
                }
            }
        }
        other => {
            if let Some(marker) = marker {
                push_marker(body, marker);
            }
            push_opt(body, Some(&other.to_string()));
        }
    }
}

/// Appends one `[marker] text` line: the readable form of a marked
/// string value.
fn push_field(body: &mut String, marker: &str, text: &str) {
    if !text.is_empty() {
        if !body.is_empty() {
            body.push('\n');
        }
        body.push_str(&format!("[{marker}] {text}"));
    }
}

/// Appends a bare structural marker line: the content rendered beneath
/// it belongs to this field.
fn push_marker(body: &mut String, marker: &str) {
    if !body.is_empty() {
        body.push('\n');
    }
    body.push_str(&format!("[{marker}]"));
}

// ---------------------------------------------------------------------------
// Gemini/*.html metadata documents
// ---------------------------------------------------------------------------

/// Streams the gems and scheduled-actions metadata documents beside the
/// conversation history. Each document becomes at most one `Memory`
/// record keyed by its source-relative path, carrying the declared line
/// count only — the rendered document text (gem and scheduled-action
/// prompt bodies) never enters a record — and a document with no
/// rendered text is counted, not invented.
fn stream_metadata(
    declaration: &ArchiveSourceDeclaration,
    seen: &mut SeenRecords,
    summary: &mut ArchiveStreamSummary,
    emit: &mut dyn FnMut(ArchiveRecord) -> BrainResult<()>,
) -> BrainResult<()> {
    let metadata_dir = declaration.path.join(GEMINI_METADATA_DIR);
    // The optional join gets the same classification: a symlinked or
    // non-directory Gemini path is refused typed, never traversed and
    // never silently treated as absent.
    if !real_directory(&metadata_dir)? {
        // The metadata documents are optional: without them the stream
        // simply has no metadata records.
        return Ok(());
    }
    for (name, path) in sorted_files(&metadata_dir, summary)? {
        if !name.ends_with(".html") {
            summary.skip("non_metadata_file");
            continue;
        }
        let html = std::fs::read(&path).map_err(|err| unreadable(&path, err))?;
        let rendered = html2text::from_read(html.as_slice(), HTML_TEXT_WIDTH).map_err(|err| {
            BrainError::Unavailable {
                component: "archive",
                reason: format!("cannot render {}: {err}", path.display()),
            }
        })?;
        let line_count = rendered
            .lines()
            .filter(|line| !line.trim().is_empty())
            .count();
        if line_count == 0 {
            summary.skip("empty_metadata_file");
            continue;
        }
        let source_file = format!("{GEMINI_METADATA_DIR}/{name}");
        segment_and_deliver(
            summary,
            seen,
            ArchiveRecord {
                natural_key: source_file.clone(),
                kind: ArchiveRecordKind::Memory,
                // Metadata only: the document's identity and declared line
                // count. Its rendered text — gem and scheduled-action
                // prompt bodies — is never ingested.
                text: format!("{source_file}: {line_count} declared metadata lines"),
                provenance: ArchiveProvenance {
                    export_metadata: BTreeMap::from([(
                        "source_file".to_owned(),
                        Value::from(source_file.clone()),
                    )]),
                    // The metadata document is its own original: the
                    // locator is the exact source-relative path, never a
                    // basename or a re-rendered location.
                    origin: Some(ArchiveAssetOrigin {
                        member: Some(source_file),
                        ..ArchiveAssetOrigin::default()
                    }),
                    ..ArchiveProvenance::default()
                },
            },
            emit,
        )?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::BrainError;
    use crate::source::archive::{stream_archive, ArchiveStreamSummary};
    use odin_domain::knowledge::archive::ArchiveSourceDeclaration;
    use std::path::{Path, PathBuf};
    use time::macros::datetime;

    /// Synthetic extracted-Takeout fixture: the real export layout (JSON
    /// conversation transcripts in `.txt` files, HTML metadata documents,
    /// unrelated Takeout siblings) with invented content only.
    fn takeout_fixture(dir: &tempfile::TempDir) -> PathBuf {
        let root = dir.path().to_path_buf();
        let history = root
            .join(GEMINI_WORKSPACE_DIR)
            .join(CONVERSATION_HISTORY_DIR);
        std::fs::create_dir_all(&history).unwrap();
        std::fs::create_dir_all(root.join(GEMINI_METADATA_DIR)).unwrap();

        let conversation_a = serde_json::json!({
            "title": "Register review",
            "creation_time": "2026-04-26T18:33:19.123456+00:00",
            "last_modification_time": "2026-04-26T19:00:00.000000+00:00",
            "conversation_turns": [
                {"user_turn": {
                    "prompt": "First prompt line one\nline two é✓\nline three",
                    "turn_index": 0,
                    "turn_last_modified": "2026-04-26T18:33:19.123456+00:00"
                }},
                {"system_turn": {
                    "text": [{"data": "Response part one.\nResponse part two."}],
                    "turn_index": 1,
                    "turn_last_modified": "2026-04-26T18:33:45.000000+00:00"
                }},
                {"user_turn": {
                    "prompt": "Deep question",
                    "turn_index": 2,
                    "turn_last_modified": "2026-04-26T18:40:00.000000+00:00"
                }},
                {"system_turn": {
                    "text": [
                        {"title": "Research plan", "description": "Plan description.",
                         "execution_plan": {"steps": [
                             {"description": "Step one.",
                              "sub_steps": [{"description": "Sub one."}]},
                             {"description": "Step two."}
                         ]}},
                        {"data": "Final answer paragraph."}
                    ],
                    "model_thoughts": [
                        {"headline": "Reading the sources", "description": "Thought body."}
                    ],
                    "citations": [
                        {"display_text": "Cited snippet", "url": "https://example.test/source"}
                    ],
                    "turn_index": 3,
                    "turn_last_modified": "2026-04-26T18:41:00.000000+00:00"
                }}
            ]
        });
        std::fs::write(
            history.join("conversation_1000000001.txt"),
            conversation_a.to_string(),
        )
        .unwrap();

        // No title, an empty prompt, and a single creation date: every
        // derived-identity path in one conversation.
        let conversation_b = serde_json::json!({
            "creation_time": "2026-05-02T09:00:00.000000+00:00",
            "conversation_turns": [
                {"user_turn": {
                    "prompt": "",
                    "turn_index": 0,
                    "turn_last_modified": "2026-05-02T09:00:00.000000+00:00"
                }},
                {"system_turn": {
                    "text": [{"data": "Answer to the empty prompt."}],
                    "turn_index": 1,
                    "turn_last_modified": "2026-05-02T09:00:05.000000+00:00"
                }},
                {"user_turn": {
                    "prompt": "Second question for the preview.",
                    "turn_index": 2,
                    "turn_last_modified": "2026-05-02T09:05:00.000000+00:00"
                }},
                {"system_turn": {
                    "text": [{"data": "Answer to the second question."}],
                    "turn_index": 3,
                    "turn_last_modified": "2026-05-02T09:05:05.000000+00:00"
                }}
            ]
        });
        std::fs::write(
            history.join("conversation_1000000002.txt"),
            conversation_b.to_string(),
        )
        .unwrap();

        // A non-transcript file is counted, never parsed as a chat body.
        std::fs::write(history.join("notes.md"), "not a transcript").unwrap();

        // Metadata documents: one with declared entries, one empty (the
        // shape the real export carries), one non-HTML.
        std::fs::write(
            root.join(GEMINI_METADATA_DIR).join("gemini_gems_data.html"),
            "<html><body><div><h2>Launch calculator</h2>\
             <p>Estimates rocket deltas.</p><h2>Standup notes</h2>\
             <p>Summarizes daily standup.</p></div></body></html>",
        )
        .unwrap();
        std::fs::write(
            root.join(GEMINI_METADATA_DIR)
                .join("gemini_scheduled_actions_data.html"),
            "<html><body><div></div></body></html>",
        )
        .unwrap();
        std::fs::write(
            root.join(GEMINI_METADATA_DIR).join("readme.txt"),
            "not metadata html",
        )
        .unwrap();

        // An unrelated Takeout sibling: never discovered, never counted.
        std::fs::create_dir_all(root.join("NotebookLM").join("nb").join("Sources")).unwrap();
        std::fs::write(
            root.join("NotebookLM")
                .join("nb")
                .join("Sources")
                .join("source.html"),
            "<html><body><div>notebook source body</div></body></html>",
        )
        .unwrap();

        root
    }

    /// Builds the declaration the way an operator TOML would: through the
    /// domain serde vocabulary, so the test never pins Rust-side struct
    /// construction.
    fn declaration(root: &Path, since: Option<&str>) -> ArchiveSourceDeclaration {
        let selection = match since {
            Some(day) => format!(r#"{{"since":"{day}"}}"#),
            None => "{}".to_owned(),
        };
        let path = serde_json::to_string(root.to_str().unwrap()).unwrap();
        serde_json::from_str(&format!(
            r#"{{"format":"gemini-workspace","path":{path},"memory_namespace":"archive-test",
                "privacy_class":"private","dedupe_key":"content_digest","selection":{selection}}}"#
        ))
        .unwrap()
    }

    fn collect(
        declaration: &ArchiveSourceDeclaration,
    ) -> (BrainResult<ArchiveStreamSummary>, Vec<ArchiveRecord>) {
        let mut records = Vec::new();
        let summary = {
            let mut emit = |record: ArchiveRecord| -> BrainResult<()> {
                records.push(record);
                Ok(())
            };
            stream_archive(declaration, &mut emit)
        };
        (summary, records)
    }

    fn record<'a>(records: &'a [ArchiveRecord], natural_key: &str) -> &'a ArchiveRecord {
        records
            .iter()
            .find(|record| record.natural_key == natural_key)
            .unwrap_or_else(|| panic!("no record {natural_key}"))
    }

    #[test]
    fn preserves_roles_boundaries_and_multiline_content() {
        let dir = tempfile::tempdir().unwrap();
        let root = takeout_fixture(&dir);
        let (summary, records) = collect(&declaration(&root, None));
        let summary = summary.unwrap();

        // Every source turn is represented: 8 messages plus 2 conversation
        // identity and 2 summary records plus 1 gems metadata record.
        assert_eq!(summary.messages_parsed, 8);
        assert_eq!(summary.records_emitted, 13);
        assert_eq!(records.len(), 13);

        // Export order is preserved: identity, summary, then each turn's
        // prompt and response in turn-index order.
        let stem = "conversation_1000000001";
        let keys: Vec<&str> = records[..6]
            .iter()
            .map(|record| record.natural_key.as_str())
            .collect();
        assert_eq!(
            keys,
            vec![
                stem,
                &format!("{stem}:summary"),
                &format!("{stem}:turn:0:user"),
                &format!("{stem}:turn:1:system"),
                &format!("{stem}:turn:2:user"),
                &format!("{stem}:turn:3:system"),
            ]
        );

        // The multiline prompt crosses the boundary byte-for-byte.
        let prompt = record(&records, "conversation_1000000001:turn:0:user");
        assert_eq!(prompt.kind, ArchiveRecordKind::Message);
        assert!(prompt.provenance.sent_by_user);
        assert_eq!(
            prompt.text,
            "First prompt line one\nline two é✓\nline three"
        );
        assert_eq!(
            prompt.provenance.created_at,
            Some(datetime!(2026-04-26 18:33:19.123456 +00:00))
        );

        // The plain response keeps its internal line structure.
        let response = record(&records, "conversation_1000000001:turn:1:system");
        assert!(!response.provenance.sent_by_user);
        assert!(response
            .text
            .contains("Response part one.\nResponse part two."));

        // The research-style response keeps every declared piece: title,
        // description, plan steps and sub-steps, thoughts, citations.
        let research = record(&records, "conversation_1000000001:turn:3:system");
        for expected in [
            "Final answer paragraph.",
            "[title] Research plan",
            "[description] Plan description.",
            "[description] Step one.",
            "[description] Sub one.",
            "[description] Step two.",
            "[model thought]",
            "[headline] Reading the sources",
            "[description] Thought body.",
            "[citation]",
            "[display_text] Cited snippet",
            "[url] https://example.test/source",
        ] {
            assert!(research.text.contains(expected), "missing {expected:?}");
        }
    }

    #[test]
    fn provenance_is_exact_and_rereads_are_stable() {
        let dir = tempfile::tempdir().unwrap();
        let root = takeout_fixture(&dir);
        let declaration = declaration(&root, None);
        let (first_summary, first) = collect(&declaration);
        let (second_summary, second) = collect(&declaration);
        first_summary.unwrap();
        second_summary.unwrap();

        // A re-read produces identical records — the store-side guarantee
        // that a second ingest adds zero rows.
        assert_eq!(first, second);

        let source_file = "Gemini in Workspace/Conversation History/conversation_1000000001.txt";
        for record in first.iter() {
            if record.natural_key.starts_with("conversation_1000000001") {
                assert_eq!(
                    record.provenance.conversation_id.as_deref(),
                    Some("conversation_1000000001")
                );
                assert_eq!(
                    record.provenance.export_metadata.get("source_file"),
                    Some(&Value::from(source_file))
                );
            }
        }
        let message = record(&first, "conversation_1000000001:turn:2:user");
        assert_eq!(
            message.provenance.message_id.as_deref(),
            Some("conversation_1000000001:turn:2:user")
        );
        // No account or export identity is invented for this format.
        assert_eq!(message.provenance.export_account, None);
        assert_eq!(message.provenance.export_id, None);
    }

    #[test]
    fn symlinked_and_non_directory_joins_refuse_typed() {
        // A symlinked required ancestor: read_dir would traverse the
        // target, so the join is classified first and refused typed.
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let outside = root.join("outside");
        std::fs::create_dir_all(outside.join(CONVERSATION_HISTORY_DIR)).unwrap();
        std::os::unix::fs::symlink(&outside, root.join(GEMINI_WORKSPACE_DIR)).unwrap();
        let (summary, records) = collect(&declaration(root, None));
        let err = summary.unwrap_err();
        assert!(matches!(err, BrainError::Unavailable { .. }));
        assert!(err.to_string().contains("symlinked directory"));
        assert!(records.is_empty());

        // A symlinked conversation-history leaf: same refusal.
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let workspace = root.join(GEMINI_WORKSPACE_DIR);
        std::fs::create_dir_all(&workspace).unwrap();
        let outside = root.join("outside");
        std::fs::create_dir_all(&outside).unwrap();
        std::os::unix::fs::symlink(&outside, workspace.join(CONVERSATION_HISTORY_DIR)).unwrap();
        let (summary, records) = collect(&declaration(root, None));
        let err = summary.unwrap_err();
        assert!(matches!(err, BrainError::Unavailable { .. }));
        assert!(err.to_string().contains("symlinked directory"));
        assert!(records.is_empty());

        // The optional Gemini join present as a file is refused typed,
        // never silently treated as absent.
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let history = root
            .join(GEMINI_WORKSPACE_DIR)
            .join(CONVERSATION_HISTORY_DIR);
        std::fs::create_dir_all(&history).unwrap();
        std::fs::write(root.join(GEMINI_METADATA_DIR), "not a directory").unwrap();
        let (summary, _records) = collect(&declaration(root, None));
        let err = summary.unwrap_err();
        assert!(matches!(err, BrainError::Unavailable { .. }));
        assert!(err.to_string().contains("not a directory"));
    }

    #[test]
    fn malformed_transcript_fails_typed() {
        let dir = tempfile::tempdir().unwrap();
        let history = dir
            .path()
            .join(GEMINI_WORKSPACE_DIR)
            .join(CONVERSATION_HISTORY_DIR);
        std::fs::create_dir_all(&history).unwrap();
        std::fs::write(history.join("conversation_bad.txt"), "{not json").unwrap();
        let (summary, records) = collect(&declaration(dir.path(), None));
        assert!(matches!(summary.unwrap_err(), BrainError::Serialization(_)));
        assert!(records.is_empty());
    }
}
