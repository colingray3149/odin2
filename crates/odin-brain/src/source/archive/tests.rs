//! Synthetic archive fixtures stay in temporary directories, with no bodies in diagnostics.

use odin_domain::knowledge::archive::{
    ArchiveDedupeKey, ArchiveFormat, ArchivePrivacyClass, ArchiveSelectionPolicy,
    ArchiveSourceDeclaration,
};
use time::macros::date;

use crate::error::BrainResult;
use crate::source::archive::{stream_archive, ArchiveRecord, ArchiveRecordKind};

fn declaration(
    format: ArchiveFormat,
    path: std::path::PathBuf,
    mut selection: ArchiveSelectionPolicy,
) -> ArchiveSourceDeclaration {
        // Label and thread rules belong to the mbox declaration; a chat
        // export carries none of them.
        selection.exclude_labels.clear();
        selection.exclude_if_header.clear();
        selection.keep_if_participant = false;
        selection.participant_emails.clear();
    ArchiveSourceDeclaration {
        format,
        path,
        memory_namespace: "archive-test".to_owned(),
        privacy_class: ArchivePrivacyClass::Private,
        dedupe_key: ArchiveDedupeKey::ContentDigest,
        selection,
    }
}

fn mbox_selection() -> ArchiveSelectionPolicy {
    ArchiveSelectionPolicy {
        since: Some(date!(2021 - 01 - 01)),
        exclude_labels: vec!["Spam".to_owned(), "Trash".to_owned()],
        exclude_if_header: Vec::new(),
        keep_if_participant: false,
        participant_emails: Vec::new(),
        suspicious_rules: Vec::new(),
        exclude_do_not_remember: None,
        people_registry: None,
    }
}

fn collect(
    declaration: &ArchiveSourceDeclaration,
) -> (
    BrainResult<crate::source::archive::ArchiveStreamSummary>,
    Vec<ArchiveRecord>,
) {
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

fn kinds(records: &[ArchiveRecord]) -> std::collections::HashMap<ArchiveRecordKind, usize> {
    let mut counts = std::collections::HashMap::new();
    for record in records {
        *counts.entry(record.kind).or_default() += 1;
    }
    counts
}

#[test]
fn a_reused_key_counts_once_and_an_exact_repeat_of_either_record_collapses() {
    let record = |text: &str| ArchiveRecord {
        natural_key: "key".to_owned(),
        kind: ArchiveRecordKind::Message,
        text: text.to_owned(),
        provenance: Default::default(),
    };
    let mut summary = crate::source::archive::ArchiveStreamSummary::default();
    let mut seen = crate::source::archive::SeenRecords::new();
    let mut emitted = Vec::new();
    for text in ["one", "two", "two", "one"] {
        summary
            .deliver(&mut seen, record(text), &mut |record| {
                emitted.push(record.text);
                Ok(())
            })
            .unwrap();
    }
    assert_eq!(emitted, ["one", "two"]);
    assert_eq!(summary.skip_reasons["duplicate_record"], 2);
    assert_eq!(summary.skip_reasons["natural_key_reused"], 1);
    assert_eq!(summary.records_emitted, 2);
}

// ---------------------------------------------------------------------------
// Claude export
// ---------------------------------------------------------------------------

fn claude_fixture(dir: &tempfile::TempDir) {
    let conversations = serde_json::json!([
        {
            "uuid": "conv-1",
            "name": "Work chat",
            "summary": "Export-supplied summary.",
            "created_at": "2026-09-01T10:00:00.000000Z",
            "updated_at": "2026-09-01T11:00:00.000000Z",
            "account": {"uuid": "acc-1"},
            "chat_messages": [
                {
                    "uuid": "msg-1",
                    "sender": "user",
                    "created_at": "2026-09-01T10:00:01.000000Z",
                    "text": "Please review the register.",
                    "content": [{"type": "text", "text": "Please review the register."}],
                    "attachments": [{
                        "file_name": "REGISTER.md",
                        "file_size": "11558",
                        "file_type": "text/markdown",
                        "extracted_content": "SECRET ASSET BODY MUST NEVER APPEAR"
                    }],
                    "files": []
                },
                {
                    "uuid": "msg-2",
                    "sender": "assistant",
                    "created_at": "2026-09-01T10:05:00.000000Z",
                    "text": null,
                    "content": [
                        {"type": "thinking", "thinking": "let me think"},
                        {"type": "tool_use", "name": "Read", "input": {"file_path": "/x.rs"}},
                        {"type": "tool_result", "content": [{"type": "text", "text": "file contents here"}]}
                    ],
                    "attachments": [],
                    "files": [{"file_uuid": "f-1", "file_name": "shot.png"}]
                }
            ]
        },
        {
            "uuid": "conv-2",
            "name": null,
            "summary": null,
            "created_at": "2026-09-02T09:00:00.000000Z",
            "updated_at": "2026-09-02T09:30:00.000000Z",
            "account": {"uuid": "acc-1"},
            "chat_messages": [
                {
                    "uuid": "msg-3",
                    "sender": "user",
                    "created_at": "2026-09-02T09:00:01.000000Z",
                    "text": "What is an RDE?",
                    "content": null,
                    "attachments": [],
                    "files": []
                }
            ]
        }
    ]);
    std::fs::write(
        dir.path().join("conversations.json"),
        serde_json::to_string(&conversations).unwrap(),
    )
    .unwrap();
    std::fs::create_dir(dir.path().join("memories")).unwrap();
    let memory = serde_json::json!({
        "account_uuid": "acc-1",
        "conversations_memory": "The owner works on a thesis.",
        "memory_files": [{"path": "/areas/engines.md", "content": "RDE notes"}],
        "project_memories": {"proj-1": "Rig project context"}
    });
    std::fs::write(
        dir.path().join("memories").join("acc-1.json"),
        serde_json::to_string(&memory).unwrap(),
    )
    .unwrap();
    std::fs::create_dir(dir.path().join("projects")).unwrap();
}

#[test]
fn claude_streams_array_with_summaries_memories_and_asset_metadata() {
    let dir = tempfile::tempdir().unwrap();
    claude_fixture(&dir);

    let declaration = declaration(
        ArchiveFormat::ClaudeExport,
        dir.path().to_path_buf(),
        mbox_selection(),
    );
    let (summary, records) = collect(&declaration);
    let summary = summary.unwrap();

    let counts = kinds(&records);
    assert_eq!(counts[&ArchiveRecordKind::Conversation], 2);
    assert_eq!(counts[&ArchiveRecordKind::ConversationSummary], 2);
    assert_eq!(counts[&ArchiveRecordKind::Message], 3);
    assert_eq!(counts[&ArchiveRecordKind::Memory], 3);
    // REGISTER.md attachment + shot.png file.
    assert_eq!(counts[&ArchiveRecordKind::AssetMetadata], 2);

    // Export summary is used verbatim when present.
    let summary_record = records
        .iter()
        .find(|record| record.natural_key == "conv-1:summary")
        .unwrap();
    assert_eq!(summary_record.text, "Export-supplied summary.");

    // An absent summary is derived deterministically from record facts,
    // never invented.
    let derived = records
        .iter()
        .find(|record| record.natural_key == "conv-2:summary")
        .unwrap();
    assert!(derived.text.contains("Export summary absent."));
    assert!(derived.text.contains("What is an RDE?"));

    // Tool calls normalize to bounded descriptors inside message text.
    let tool_message = records
        .iter()
        .find(|record| record.natural_key == "msg-2")
        .unwrap();
    assert!(tool_message.text.contains("[tool_use Read]"));
    assert!(tool_message
        .text
        .contains("[tool_result] file contents here"));
    assert!(tool_message.text.contains("let me think"));

    // Message provenance: sender is explicit export truth.
    let user_message = records
        .iter()
        .find(|record| record.natural_key == "msg-1")
        .unwrap();
    assert!(user_message.provenance.sent_by_user);
    assert!(!tool_message.provenance.sent_by_user);
    assert_eq!(
        user_message.provenance.created_at.unwrap().unix_timestamp(),
        1788256801
    );

    // Uploaded assets contribute metadata only: the extracted_content
    // body must appear in no record text.
    let asset = records
        .iter()
        .find(|record| record.natural_key == "msg-1:asset:REGISTER.md")
        .unwrap();
    assert_eq!(asset.kind, ArchiveRecordKind::AssetMetadata);
    assert!(asset.text.contains("size_bytes=11558"));
    assert!(records
        .iter()
        .all(|record| !record.text.contains("SECRET ASSET BODY MUST NEVER APPEAR")));

    // Memory records keep stable uuid keys.
    let keys: std::collections::BTreeSet<&str> = records
        .iter()
        .filter(|record| record.kind == ArchiveRecordKind::Memory)
        .map(|record| record.natural_key.as_str())
        .collect();
    assert_eq!(
        keys,
        [
            "acc-1:conversations",
            "acc-1:file:/areas/engines.md",
            "acc-1:project:proj-1"
        ]
        .into_iter()
        .collect()
    );

    // Project prompt templates are declared out of scope, counted.
    assert_eq!(summary.skip_reasons["project_records_out_of_scope"], 1);
    assert_eq!(summary.records_emitted, records.len() as u64);
}

// ---------------------------------------------------------------------------
// Grok export
// ---------------------------------------------------------------------------

fn grok_fixture(path: &std::path::Path) {
    let backend = serde_json::json!({
        "conversations": [{
            "conversation": {
                "id": "conv-1",
                "user_id": "user-1",
                "title": "Cheap laptop hunt",
                "summary": "",
                "create_time": "2026-09-10T02:27:35.874494Z",
                "modify_time": "2026-09-10T02:34:52.641Z",
                "asset_ids": []
            },
            "responses": [
                {"response": {
                    "_id": "r1",
                    "message": "Is there a cheap laptop?",
                    "sender": "human",
                    "create_time": {"$date": {"$numberLong": "1789007315864"}},
                    "model": "",
                    "file_attachments": ["asset-uuid-1"]
                }},
                {"response": {
                    "_id": "r2",
                    "message": "Yes, a used one.",
                    "sender": "assistant",
                    "create_time": {"$date": {"$numberLong": "1789007400000"}},
                    "model": "grok-4",
                    "file_attachments": []
                }}
            ]
        }],
        "projects": [],
        "tasks": []
    });
    write_export_files(
        path,
        &[
            (
                "ttl/30d/export_data/export-uuid-1/prod-grok-backend.json",
                serde_json::to_string(&backend).unwrap().as_bytes(),
            ),
            (
                "ttl/30d/export_data/export-uuid-1/prod-mc-asset-server/asset-uuid-1/content",
                b"fake asset bytes",
            ),
        ],
    );
}

/// Writes files (named by their path under the export directory) into an
/// unpacked export directory.
fn write_export_files(root: &std::path::Path, files: &[(&str, &[u8])]) {
    for (name, bytes) in files {
        let file = root.join(name);
        std::fs::create_dir_all(file.parent().unwrap()).unwrap();
        std::fs::write(file, bytes).unwrap();
    }
}

#[test]
fn grok_directory_streams_conversations_and_asset_sizes() {
    let dir = tempfile::tempdir().unwrap();
    let export_path = dir.path().join("grokdata");
    grok_fixture(&export_path);

    let declaration = declaration(ArchiveFormat::GrokExport, export_path, mbox_selection());
    let (summary, records) = collect(&declaration);
    let summary = summary.unwrap();

    let conversation = records
        .iter()
        .find(|record| record.natural_key == "conv-1")
        .unwrap();
    assert_eq!(conversation.kind, ArchiveRecordKind::Conversation);
    assert_eq!(conversation.text, "Cheap laptop hunt");
    assert_eq!(
        conversation.provenance.export_account.as_deref(),
        Some("user-1")
    );
    assert_eq!(
        conversation.provenance.export_id.as_deref(),
        Some("export-uuid-1")
    );

    // Grok ships empty summaries: the derived deterministic form applies.
    let summary_record = records
        .iter()
        .find(|record| record.natural_key == "conv-1:summary")
        .unwrap();
    assert!(summary_record.text.contains("Export summary absent."));
    assert!(summary_record.text.contains("Is there a cheap laptop?"));

    let human = records
        .iter()
        .find(|record| record.natural_key == "r1")
        .unwrap();
    assert!(human.provenance.sent_by_user);
    assert_eq!(
        human.provenance.created_at.unwrap(),
        time::OffsetDateTime::from_unix_timestamp(1789007315).unwrap()
            + time::Duration::milliseconds(864)
    );

    let assistant = records
        .iter()
        .find(|record| record.natural_key == "r2")
        .unwrap();
    assert!(!assistant.provenance.sent_by_user);
    assert!(assistant.text.starts_with("[model grok-4]"));

    // Asset metadata only, size taken from the file.
    let asset = records
        .iter()
        .find(|record| record.kind == ArchiveRecordKind::AssetMetadata)
        .unwrap();
    assert_eq!(asset.natural_key, "conv-1:asset:asset-uuid-1");
    assert!(asset.text.contains("size_bytes=16"));

    assert_eq!(summary.records_emitted, records.len() as u64);
    assert!(summary.skip_reasons.is_empty());
}

// ---------------------------------------------------------------------------
// Mbox: thread override, since hard cutoff, MIME
// ---------------------------------------------------------------------------









#[test]
fn an_oversized_record_segments_into_bounded_parts_with_stable_identity() {
    use crate::source::archive::{segment_and_deliver, SeenRecords, MAX_RECORD_BYTES};
    // A two-byte character straddles the bound, so the cut snaps back.
    let big = format!("{}é{}", "x".repeat(MAX_RECORD_BYTES - 1), "y".repeat(16));
    let record = ArchiveRecord {
        natural_key: "big@x".to_owned(),
        kind: ArchiveRecordKind::Message,
        text: big.clone(),
        provenance: Default::default(),
    };
    let mut summary = crate::source::archive::ArchiveStreamSummary::default();
    let mut parts = Vec::new();
    segment_and_deliver(&mut summary, &mut SeenRecords::new(), record, &mut |part| {
        parts.push(part);
        Ok(())
    })
    .unwrap();

    assert_eq!(parts.len(), 2);
    assert_eq!(parts[0].natural_key, "big@x:part:1");
    assert_eq!(parts[1].natural_key, "big@x:part:2");
    assert!(parts.iter().all(|part| part.text.len() <= MAX_RECORD_BYTES));
    let reassembled: String = parts.iter().map(|part| part.text.as_str()).collect();
    assert_eq!(reassembled, big, "nothing is cut or lost");
    assert_eq!(parts[0].text.len(), MAX_RECORD_BYTES - 1);
    assert_eq!(
        parts
            .iter()
            .map(|part| (part.provenance.part_index, part.provenance.part_count))
            .collect::<Vec<_>>(),
        [(Some(1), Some(2)), (Some(2), Some(2))]
    );
    assert_eq!(summary.skip_reasons["record_segmented"], 1);
}


#[test]
fn malformed_memory_file_fails_typed_under_keep_all() {
    let dir = tempfile::tempdir().unwrap();
    claude_fixture(&dir);
    std::fs::write(
        dir.path().join("memories").join("broken.json"),
        "{ not valid json",
    )
    .unwrap();

    let declaration = declaration(
        ArchiveFormat::ClaudeExport,
        dir.path().to_path_buf(),
        mbox_selection(),
    );
    let (summary, _) = collect(&declaration);
    // Keep-all: malformed memory content fails the stream typed instead
    // of being silently dropped.
    assert!(matches!(
        summary.unwrap_err(),
        crate::error::BrainError::Serialization(_)
    ));
}



// ---------------------------------------------------------------------------
// Asset origin locators: the declaration site vs the original binary
// ---------------------------------------------------------------------------


// ---------------------------------------------------------------------------
// Chat JSONL, text tree, private people
// ---------------------------------------------------------------------------






#[test]
fn text_tree_reads_documents_with_title_and_date() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(dir.path().join("journal")).unwrap();
    std::fs::write(
        dir.path().join("journal/2019.md"),
        "date: 2019-05-04\n\n# Year in review\nbody\n",
    )
    .unwrap();
    std::fs::write(dir.path().join("notes.txt"), "plain words").unwrap();
    std::fs::write(dir.path().join(".hidden.md"), "never read").unwrap();
    std::fs::write(dir.path().join("image.png"), "not text").unwrap();
    let mut selection = mbox_selection();
    selection.since = None;
    let tree = declaration(ArchiveFormat::TextTree, dir.path().to_path_buf(), selection);
    let (summary, records) = collect(&tree);
    summary.unwrap();

    assert_eq!(records.len(), 2);
    let dated = records
        .iter()
        .find(|r| r.natural_key == "journal/2019.md")
        .unwrap();
    assert_eq!(dated.provenance.export_metadata["title"], "Year in review");
    assert_eq!(
        dated.provenance.created_at,
        Some(datetime!(2019-05-04 0:00 UTC))
    );
    let plain = records
        .iter()
        .find(|r| r.natural_key == "notes.txt")
        .unwrap();
    assert_eq!(plain.provenance.export_metadata["title"], "notes");
    // An undated document has no timestamp, however old its file is.
    assert_eq!(plain.provenance.created_at, None);

    // A declared cutoff cannot place it, and says so.
    let mut selection = mbox_selection();
    selection.since = Some(date!(2019 - 01 - 01));
    let (summary, records) = collect(&declaration(
        ArchiveFormat::TextTree,
        dir.path().to_path_buf(),
        selection,
    ));
    assert_eq!(summary.unwrap().skip_reasons["date_missing"], 1);
    assert_eq!(records.len(), 1);
}

