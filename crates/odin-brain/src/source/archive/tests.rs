//! Synthetic archive fixtures stay in temporary directories, with no bodies in diagnostics.

use std::io::Write;

use odin_domain::knowledge::archive::{
    ArchiveDedupeKey, ArchiveFormat, ArchivePrivacyClass, ArchiveSelectionPolicy,
    ArchiveSourceDeclaration, ArchiveSuspiciousAction, ArchiveSuspiciousRule,
};
use time::macros::{date, datetime};

use crate::error::BrainResult;
use crate::source::archive::{stream_archive, ArchiveRecord, ArchiveRecordKind};

fn declaration(
    format: ArchiveFormat,
    path: std::path::PathBuf,
    mut selection: ArchiveSelectionPolicy,
) -> ArchiveSourceDeclaration {
    if matches!(format, ArchiveFormat::Mbox) {
        selection.exclude_if_header =
            vec!["List-Unsubscribe".to_owned(), "Precedence: bulk".to_owned()];
        // Use explicit Sent metadata for participation without inferring an operator address.
        selection.keep_if_participant = true;
        selection.participant_emails = Vec::new();
    } else {
        // Label and thread rules belong to the mbox declaration; a chat
        // export carries none of them.
        selection.exclude_labels.clear();
        selection.exclude_if_header.clear();
        selection.keep_if_participant = false;
        selection.participant_emails.clear();
    }
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
        "conversations_memory": "Colin works on PARSEC.",
        "memory_files": [{"path": "/areas/engines.md", "content": "RDE notes"}],
        "project_memories": {"proj-1": "Surtr project context"}
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
    let mut zip = zip::ZipWriter::new(std::fs::File::create(path).unwrap());
    let options = zip::write::SimpleFileOptions::default()
        .compression_method(zip::CompressionMethod::Deflated);
    zip.start_file(
        "ttl/30d/export_data/export-uuid-1/prod-grok-backend.json",
        options,
    )
    .unwrap();
    zip.write_all(serde_json::to_string(&backend).unwrap().as_bytes())
        .unwrap();
    zip.start_file(
        "ttl/30d/export_data/export-uuid-1/prod-mc-asset-server//asset-uuid-1/content",
        options,
    )
    .unwrap();
    zip.write_all(b"fake asset bytes").unwrap();
    zip.finish().unwrap();
}

#[test]
fn grok_zip_streams_conversations_and_asset_sizes() {
    let dir = tempfile::tempdir().unwrap();
    let zip_path = dir.path().join("grokdata.zip");
    grok_fixture(&zip_path);

    let declaration = declaration(ArchiveFormat::GrokExport, zip_path, mbox_selection());
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

    // Asset metadata only, size taken from the zip central directory.
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

/// Three-message thread fixture: Colin's `Sent` message anchors a thread
/// a bulk newsletter reply belongs to (override keeps it), a lone bulk
/// message is excluded, and everything dated before `since` is a hard
/// cut even when Colin sent it. Also exercises `>From ` body escaping
/// and a quoted-printable multipart body.
const MBOX_FIXTURE: &str = "\
From colin@example.com Mon Jan  4 10:00:00 2021
Message-ID: <c1@x>
Date: Mon, 04 Jan 2021 10:00:00 +0000
From: Colin <colin@example.com>
To: list@example.com
Subject: Thread start
X-Gmail-Labels: Sent
Content-Type: multipart/alternative; boundary=\"bnd\"

--bnd
Content-Type: text/plain; charset=utf-8
Content-Transfer-Encoding: quoted-printable

Hello=20world
--bnd
Content-Type: text/html; charset=utf-8

<p>Hello world</p>
--bnd--

From bounce@example.com Mon Jan  4 11:00:00 2021
Message-ID: <a1@x>
Date: Mon, 04 Jan 2021 11:00:00 +0000
From: news@example.com
To: colin@example.com
Subject: Re: Thread start
In-Reply-To: <c1@x>
X-Gmail-Labels: Inbox
List-Unsubscribe: <https://example.com/unsub>

>From the quoted depths
bulk body one

From bounce@example.com Mon Jan  4 11:30:00 2021
Message-ID: <b1@x>
Date: Mon, 04 Jan 2021 11:30:00 +0000
From: news@example.com
To: colin@example.com
Subject: Lone bulk
X-Gmail-Labels: Inbox
Precedence: bulk
List-Unsubscribe: <https://example.com/other>

lone bulk body

From colin@example.com Sat Jan  4 10:00:00 2020
Message-ID: <d1@x>
Date: Sat, 04 Jan 2020 10:00:00 +0000
From: Colin <colin@example.com>
To: someone@example.com
Subject: Old sent
X-Gmail-Labels: Sent

old body

From spam@example.com Mon Jan  4 12:00:00 2021
Message-ID: <e1@x>
Date: Mon, 04 Jan 2021 12:00:00 +0000
From: spam@example.com
To: colin@example.com
Subject: Junk
X-Gmail-Labels: Spam

junk body

From spam@example.com Mon Jan  4 12:30:00 2021
Message-ID: <f1@x>
Date: Mon, 04 Jan 2021 12:30:00 +0000
From: spam@example.com
To: colin@example.com
Subject: Junk in Colins thread
References: <c1@x>
X-Gmail-Labels: Spam

junk in kept thread

";

#[test]
fn mbox_thread_override_keeps_sent_threads_and_hard_cutoffs() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("test.mbox"), MBOX_FIXTURE).unwrap();

    let declaration = declaration(
        ArchiveFormat::Mbox,
        dir.path().join("test.mbox"),
        mbox_selection(),
    );
    let (stream_summary, records) = collect(&declaration);
    let stream_summary = stream_summary.unwrap();

    let keys: std::collections::BTreeSet<&str> = records
        .iter()
        .map(|record| record.natural_key.as_str())
        .collect();
    // c1: Colin's sent message. a1: bulk-labelled but in Colin's thread —
    // the declared override keeps it. b1: lone bulk, excluded. d1: Colin
    // sent it but 2020 is a hard cutoff. e1: Spam label on a thread Colin
    // never sent to, excluded. f1: Spam label, but inside Colin's sent
    // thread — the participant override keeps it too.
    assert_eq!(keys, ["a1@x", "c1@x", "f1@x"].into_iter().collect());

    assert_eq!(stream_summary.skip_reasons["excluded_bulk"], 1);
    assert_eq!(stream_summary.skip_reasons["before_since"], 1);
    assert_eq!(stream_summary.skip_reasons["excluded_label"], 1);

    let sent = records
        .iter()
        .find(|record| record.natural_key == "c1@x")
        .unwrap();
    assert!(sent.provenance.sent_by_user);
    // Mbox exports carry no account identity; it is never invented.
    assert!(sent.provenance.export_account.is_none());

    let kept_bulk = records
        .iter()
        .find(|record| record.natural_key == "a1@x")
        .unwrap();
    // Receiving mail does not imply authorship.
    assert!(!kept_bulk.provenance.sent_by_user);
    // Thread membership survives: the bulk reply shares Colin's thread;
    // the canonical thread id is the component's smallest Message-ID.
    assert_eq!(kept_bulk.provenance.thread_id.as_deref(), Some("a1@x"));
    assert_eq!(sent.provenance.thread_id.as_deref(), Some("a1@x"));
    assert_eq!(kept_bulk.provenance.labels, vec!["Inbox".to_owned()]);

    // MIME boundaries: the quoted-printable text/plain part decodes, the
    // html alternative loses to text, and the >From quoted line stayed
    // inside the message instead of splitting it.
    assert!(kept_bulk.text.contains("bulk body one"));
    assert!(kept_bulk.text.contains("From the quoted depths"));
    assert!(!kept_bulk.text.contains("From bounce@example.com Mon"));
    let sent_body = sent.text.replace('\r', "");
    assert!(sent_body.contains("Hello world"));
    assert!(!sent_body.contains("=20"));
}

#[test]
fn mbox_html_only_body_gets_deterministic_text_fallback() {
    let dir = tempfile::tempdir().unwrap();
    let mbox = "\
From a@example.com Mon Jan  4 10:00:00 2021
Message-ID: <h1@x>
Date: Mon, 04 Jan 2021 10:00:00 +0000
From: a@example.com
To: colin@example.com
Subject: Html only
X-Gmail-Labels: Inbox
Content-Type: text/html; charset=utf-8

<html><body><p>Hi &amp; bye</p><script>var x=1;</script></body></html>

";
    std::fs::write(dir.path().join("test.mbox"), mbox).unwrap();
    let declaration = declaration(
        ArchiveFormat::Mbox,
        dir.path().join("test.mbox"),
        mbox_selection(),
    );
    let (stream_summary, records) = collect(&declaration);
    stream_summary.unwrap();
    let record = records
        .iter()
        .find(|record| record.natural_key == "h1@x")
        .unwrap();
    assert!(record.text.contains("Hi & bye"));
    assert!(!record.text.contains("var x=1"));
}

/// A reference the message declares is content even when the renderer never
/// shows it: the renderer drops `<style>`/`<script>`/`<link>`/`<meta>`/
/// `<head>` whole and renders `<img>` as its alt text alone, so a web font,
/// a stylesheet image or a `style`-attribute target exists only in the
/// source. Each must reach record text as the value the message declared
/// while CSS prose around it never becomes memory text.
#[test]
fn mbox_html_body_keeps_declared_references_the_renderer_drops() {
    let dir = tempfile::tempdir().unwrap();
    let mbox = "\
From a@example.com Mon Jan  4 10:00:00 2021
Message-ID: <ref1@x>
Date: Mon, 04 Jan 2021 10:00:00 +0000
From: a@example.com
To: colin@example.com
Subject: Declared references
X-Gmail-Labels: Inbox
Content-Type: text/html; charset=utf-8

<html><head><style type=\"text/css\">
@font-face{font-family:Colfax;src:url(https://fonts.example.test/beta/fonts/ColfaxAIRegular.woff2) format(\"woff2\");}
.cta{background-image:url('https://tiles.example.test/tile.png');}
.cta-again{background-image:url('https://tiles.example.test/tile.png');}
</style></head><body>
<p>Hello</p>
<img src=\"https://images.example.test/chart.png\" alt=\"A chart\">
<table style=\"background-image:url('https://attr.example.test/bg.png')\"><tr><td>x</td></tr></table>
</body></html>

";
    std::fs::write(dir.path().join("test.mbox"), mbox).unwrap();
    let declaration = declaration(
        ArchiveFormat::Mbox,
        dir.path().join("test.mbox"),
        mbox_selection(),
    );
    let (stream_summary, records) = collect(&declaration);
    stream_summary.unwrap();
    let record = records
        .iter()
        .find(|record| record.natural_key == "ref1@x")
        .unwrap();

    // A web font declared only inside `<style>`, a stylesheet image, an
    // `<img>` target and a `style`-attribute target: all absent from what
    // the renderer produces, all preserved as the message declared them.
    for declared in [
        "https://fonts.example.test/beta/fonts/ColfaxAIRegular.woff2",
        "https://tiles.example.test/tile.png",
        "https://images.example.test/chart.png",
        "https://attr.example.test/bg.png",
    ] {
        assert!(
            record.text.contains(declared),
            "{declared} is declared by the message and must survive"
        );
    }
    // A repeated declaration is recorded once.
    assert_eq!(
        record
            .text
            .matches("https://tiles.example.test/tile.png")
            .count(),
        1
    );
    // The body still renders; the CSS around those references does not.
    assert!(record.text.contains("Hello"));
    assert!(!record.text.contains("@font-face"));
    assert!(!record.text.contains("background-image"));
    // The appended references change no provenance.
    assert_eq!(record.provenance.message_id.as_deref(), Some("ref1@x"));
    assert_eq!(
        record.provenance.created_at,
        Some(datetime!(2021-01-04 10:00:00 UTC))
    );
    assert_eq!(record.provenance.labels, vec!["Inbox".to_owned()]);
}

/// Declared values keep their own boundaries and escapes: HTML character
/// references and CSS escapes are resolved by the maintained parsers, a
/// quoted value keeps parentheses and punctuation verbatim, and neither
/// prose nor `<script>` text is ever read as a declared reference.
#[test]
fn mbox_html_body_decodes_declared_reference_escapes_and_boundaries() {
    let dir = tempfile::tempdir().unwrap();
    let mbox = "\
From a@example.com Mon Jan  4 10:00:00 2021
Message-ID: <ref2@x>
Date: Mon, 04 Jan 2021 10:00:00 +0000
From: a@example.com
To: colin@example.com
Subject: Escaped references
X-Gmail-Labels: Inbox
Content-Type: text/html; charset=utf-8

<html><body>
<p>See https://prose.example.test/plain for details.</p>
<p><a href=\"https://links.example.test/report?token=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa&amp;page=1&#38;sort=asc&#x26;next=final\">Report</a></p>
<img src=\"https://images.example.test/v2_(final).png\" alt=\"A chart\">
<table style=\"background-image:url(https://attr.example.test/a\\)b.png);border-image:url(https://attr.example.test/x\\26 y.png)\"><tr><td>x</td></tr></table>
<script>var endpoint = \"https://script.example.test/collect\";</script>
</body></html>

";
    std::fs::write(dir.path().join("test.mbox"), mbox).unwrap();
    let declaration = declaration(
        ArchiveFormat::Mbox,
        dir.path().join("test.mbox"),
        mbox_selection(),
    );
    let (stream_summary, records) = collect(&declaration);
    stream_summary.unwrap();
    let record = records
        .iter()
        .find(|record| record.natural_key == "ref2@x")
        .unwrap();

    // Named, decimal and hexadecimal character references all resolve to the
    // reference the message declares (this target is long enough that the
    // renderer's own wrapped link footnote cannot carry it whole).
    assert!(record.text.contains(
        "https://links.example.test/report?token=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa&page=1&sort=asc&next=final"
    ));
    // A quoted attribute value keeps its parentheses and punctuation.
    assert!(record
        .text
        .contains("https://images.example.test/v2_(final).png"));
    // CSS escapes decode: `\)` is a literal parenthesis, `\26 ` is `&`.
    assert!(record.text.contains("https://attr.example.test/a)b.png"));
    assert!(record.text.contains("https://attr.example.test/x&y.png"));
    // Prose stays prose (one rendering, not a declared reference too), and
    // script text never becomes a reference.
    assert_eq!(
        record
            .text
            .matches("https://prose.example.test/plain")
            .count(),
        1
    );
    assert!(!record.text.contains("https://script.example.test/collect"));
}

/// A resource-limit truncation is never silent: CSS nested past the
/// maintained parser's block-nesting limit holds references this walk cannot
/// reach, so the message fails the stream typed instead of being ingested
/// with a partial read.
#[test]
fn mbox_html_body_css_nested_past_the_parser_limit_fails_typed() {
    let dir = tempfile::tempdir().unwrap();
    // Two blocks per repetition, well past the parser's nesting limit.
    let nested_css = format!(
        "{}{}{}",
        "x{background-image:image-set(".repeat(80),
        "url(https://deep.example.test/a.png)",
        ")}".repeat(80)
    );
    let mbox = format!(
        "\
From a@example.com Mon Jan  4 10:00:00 2021
Message-ID: <ref3@x>
Date: Mon, 04 Jan 2021 10:00:00 +0000
From: a@example.com
To: colin@example.com
Subject: Nested references
X-Gmail-Labels: Inbox
Content-Type: text/html; charset=utf-8

<html><head><style>{nested_css}</style></head><body><p>Hello</p></body></html>

"
    );
    std::fs::write(dir.path().join("test.mbox"), mbox).unwrap();
    let declaration = declaration(
        ArchiveFormat::Mbox,
        dir.path().join("test.mbox"),
        mbox_selection(),
    );
    let (stream_summary, records) = collect(&declaration);
    let error = stream_summary.expect_err("nesting past the parser limit must fail typed");
    assert!(matches!(
        error,
        crate::error::BrainError::Corrupt {
            component: "archive",
            ..
        }
    ));
    // Nothing was admitted: a partial read is never a successful record.
    assert!(records.is_empty());
}

#[test]
fn mbox_suspicious_rules_exclude_and_flag_deterministically() {
    let dir = tempfile::tempdir().unwrap();
    let mbox = "\
From a@example.com Mon Jan  4 10:00:00 2021
Message-ID: <s1@x>
Date: Mon, 04 Jan 2021 10:00:00 +0000
From: evil@phish.example
To: colin@example.com
Subject: Flag me
X-Gmail-Labels: Inbox,Category Promotions

flag body

From b@example.com Mon Jan  4 10:05:00 2021
Message-ID: <s2@x>
Date: Mon, 04 Jan 2021 10:05:00 +0000
From: b@example.com
To: colin@example.com
Subject: Drop me
X-Phish: yes
X-Gmail-Labels: Inbox

drop body

";
    std::fs::write(dir.path().join("test.mbox"), mbox).unwrap();
    let mut selection = mbox_selection();
    selection.suspicious_rules = vec![
        ArchiveSuspiciousRule {
            name: "promotions_watched".to_owned(),
            action: ArchiveSuspiciousAction::Flag,
            match_label: Some("Category Promotions".to_owned()),
            match_header: None,
            sender_domain: None,
        },
        ArchiveSuspiciousRule {
            name: "phish_header".to_owned(),
            action: ArchiveSuspiciousAction::Exclude,
            match_label: None,
            match_header: Some("X-Phish".to_owned()),
            sender_domain: None,
        },
        ArchiveSuspiciousRule {
            name: "external_sender".to_owned(),
            action: ArchiveSuspiciousAction::Flag,
            match_label: None,
            match_header: None,
            sender_domain: Some("example".to_owned()),
        },
    ];
    let declaration = declaration(ArchiveFormat::Mbox, dir.path().join("test.mbox"), selection);
    let (stream_summary, records) = collect(&declaration);
    let stream_summary = stream_summary.unwrap();

    let kept = records
        .iter()
        .find(|record| record.natural_key == "s1@x")
        .unwrap();
    // Both flag rules match s1: the promotions label and the external
    // sender domain (phish.example is a subdomain of example).
    assert_eq!(
        kept.provenance.rule_flags,
        vec![
            "promotions_watched".to_owned(),
            "external_sender".to_owned()
        ]
    );

    assert!(!records.iter().any(|record| record.natural_key == "s2@x"));
    assert_eq!(
        stream_summary.skip_reasons["suspicious_rule_excluded:phish_header"],
        1
    );
}

#[test]
fn duplicate_natural_keys_collapse_or_account_without_rekeying() {
    let dir = tempfile::tempdir().unwrap();
    // The same message appears twice (e.g. overlapping mbox entries):
    // an exact repeat collapses into one counted duplicate.
    let repeated = "\
From a@example.com Mon Jan  4 10:00:00 2021
Message-ID: <dup@x>
Date: Mon, 04 Jan 2021 10:00:00 +0000
From: a@example.com
To: colin@example.com
Subject: One
X-Gmail-Labels: Inbox

same body

";
    let mut mbox = String::new();
    mbox.push_str(repeated);
    mbox.push('\n');
    mbox.push_str(repeated);
    // A different message reusing the same Message-ID is NOT re-keyed:
    // identity is store-owned and content-addressed; the parser emits it
    // unchanged and accounts the reuse.
    mbox.push_str(
        "\
From b@example.com Mon Jan  4 10:05:00 2021
Message-ID: <dup@x>
Date: Mon, 04 Jan 2021 10:05:00 +0000
From: b@example.com
To: colin@example.com
Subject: Two
X-Gmail-Labels: Inbox

changed body

",
    );
    std::fs::write(dir.path().join("test.mbox"), mbox).unwrap();
    let declaration = declaration(
        ArchiveFormat::Mbox,
        dir.path().join("test.mbox"),
        mbox_selection(),
    );
    let (stream_summary, records) = collect(&declaration);
    let stream_summary = stream_summary.unwrap();
    let keys: Vec<&str> = records
        .iter()
        .map(|record| record.natural_key.as_str())
        .collect();
    // Natural keys are never mangled; exact repeat collapsed.
    assert_eq!(keys, vec!["dup@x", "dup@x"]);
    assert!(records[1].text.contains("changed body"));
    assert_eq!(stream_summary.skip_reasons["duplicate_record"], 1);
    assert_eq!(stream_summary.skip_reasons["natural_key_reused"], 1);
}

#[test]
fn oversized_records_segment_with_stable_part_identity() {
    let dir = tempfile::tempdir().unwrap();
    let big = "x".repeat(crate::source::archive::MAX_RECORD_BYTES + 16);
    let mbox = format!(
        "\
From a@example.com Mon Jan  4 10:00:00 2021
Message-ID: <big@x>
Date: Mon, 04 Jan 2021 10:00:00 +0000
From: a@example.com
To: colin@example.com
Subject: Big
X-Gmail-Labels: Inbox
Content-Type: text/plain; charset=utf-8

{big}
"
    );
    std::fs::write(dir.path().join("test.mbox"), mbox).unwrap();
    let declaration = declaration(
        ArchiveFormat::Mbox,
        dir.path().join("test.mbox"),
        mbox_selection(),
    );
    let (stream_summary, records) = collect(&declaration);
    let stream_summary = stream_summary.unwrap();

    // Keep-all: the full content survives as ordered parts, each
    // individually bounded, with stable identity and shared provenance.
    let parts: Vec<&ArchiveRecord> = records
        .iter()
        .filter(|record| record.natural_key.starts_with("big@x:part:"))
        .collect();
    assert_eq!(parts.len(), 2);
    assert_eq!(parts[0].natural_key, "big@x:part:1");
    assert_eq!(parts[1].natural_key, "big@x:part:2");
    assert!(parts
        .iter()
        .all(|part| part.text.len() <= crate::source::archive::MAX_RECORD_BYTES));
    // The parts are the record's exact text split at the bound — nothing is
    // trimmed away except the framing newline the splitter normalizes: the
    // content-header prefix stays on the first part and the body arrives
    // whole on the last.
    let reassembled: String = parts.iter().map(|part| part.text.as_str()).collect();
    assert!(reassembled.starts_with("From: a@example.com\nTo: colin@example.com\nSubject: Big\n\n"));
    assert!(reassembled.ends_with(big.as_str()));
    assert_eq!(
        parts[0].text.len(),
        crate::source::archive::MAX_RECORD_BYTES,
        "the first part fills the bound exactly"
    );
    assert_eq!(parts[0].provenance.part_index, Some(1));
    assert_eq!(parts[0].provenance.part_count, Some(2));
    assert_eq!(parts[1].provenance.part_index, Some(2));
    assert_eq!(parts[0].provenance.message_id.as_deref(), Some("big@x"));
    // Segmentation is counted, not silent; nothing is truncated.
    assert_eq!(stream_summary.skip_reasons["record_segmented"], 1);
    assert!(!stream_summary.skip_reasons.contains_key("record_truncated"));
}

#[test]
fn zipped_mbox_reads_in_place() {
    let dir = tempfile::tempdir().unwrap();
    let zip_path = dir.path().join("takeout.zip");
    let mut zip = zip::ZipWriter::new(std::fs::File::create(&zip_path).unwrap());
    let options = zip::write::SimpleFileOptions::default()
        .compression_method(zip::CompressionMethod::Deflated);
    zip.start_file("Takeout/Mail/Test mail.mbox", options)
        .unwrap();
    zip.write_all(MBOX_FIXTURE.as_bytes()).unwrap();
    zip.finish().unwrap();

    let declaration = declaration(ArchiveFormat::Mbox, zip_path, mbox_selection());
    let (stream_summary, records) = collect(&declaration);
    let stream_summary = stream_summary.unwrap();
    let keys: std::collections::BTreeSet<&str> = records
        .iter()
        .map(|record| record.natural_key.as_str())
        .collect();
    assert_eq!(keys, ["a1@x", "c1@x", "f1@x"].into_iter().collect());
    assert_eq!(stream_summary.skip_reasons["excluded_bulk"], 1);
    // Mbox exports carry no account identity; it is never invented.
    let kept = records
        .iter()
        .find(|record| record.natural_key == "c1@x")
        .unwrap();
    assert!(kept.provenance.export_account.is_none());
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
    assert!(summary.is_err());
}

#[test]
fn participant_sender_identity_marks_sent_threads() {
    let dir = tempfile::tempdir().unwrap();
    // No Sent label anywhere: declared participant sender identity is
    // what marks Colin's thread, so the override still applies.
    let mbox = "\
From colin@example.com Mon Jan  4 10:00:00 2021
Message-ID: <p1@x>
Date: Mon, 04 Jan 2021 10:00:00 +0000
From: colin@example.com
To: list@example.com
Subject: Mine
X-Gmail-Labels: Inbox

my thread start

From bounce@example.com Mon Jan  4 11:00:00 2021
Message-ID: <p2@x>
Date: Mon, 04 Jan 2021 11:00:00 +0000
From: news@example.com
To: colin@example.com
Subject: Re: Mine
In-Reply-To: <p1@x>
X-Gmail-Labels: Inbox
List-Unsubscribe: <https://example.com/unsub>

bulk reply

";
    std::fs::write(dir.path().join("test.mbox"), mbox).unwrap();
    let mut declaration = declaration(
        ArchiveFormat::Mbox,
        dir.path().join("test.mbox"),
        mbox_selection(),
    );
    // The declared operator identity is the only place an address may come
    // from; it is what marks this thread here.
    declaration.selection.participant_emails = vec!["colin@example.com".to_owned()];
    let (stream_summary, records) = collect(&declaration);
    stream_summary.unwrap();
    let sent = records
        .iter()
        .find(|record| record.natural_key == "p1@x")
        .unwrap();
    assert!(sent.provenance.sent_by_user);
    assert!(records.iter().any(|record| record.natural_key == "p2@x"));
}

#[test]
fn declared_since_is_a_hard_cutoff_for_undated_chat_records() {
    let dir = tempfile::tempdir().unwrap();
    let conversations = serde_json::json!([
        {
            "uuid": "conv-old",
            "name": "Dated",
            "summary": null,
            "created_at": "2020-06-01T10:00:00.000000Z",
            "chat_messages": [
                {
                    "uuid": "msg-old",
                    "sender": "user",
                    "created_at": "2020-06-01T10:00:01.000000Z",
                    "text": "before the cutoff",
                    "content": null
                }
            ]
        },
        {
            "uuid": "conv-undated",
            "name": "Undated",
            "summary": null,
            "created_at": null,
            "chat_messages": [
                {
                    "uuid": "msg-undated",
                    "sender": "user",
                    "created_at": "not a timestamp",
                    "text": "no usable date",
                    "content": null
                }
            ]
        }
    ]);
    std::fs::write(
        dir.path().join("conversations.json"),
        serde_json::to_string(&conversations).unwrap(),
    )
    .unwrap();

    let mut selection = mbox_selection();
    selection.since = Some(time::macros::date!(2021 - 01 - 01));
    let declaration = declaration(
        ArchiveFormat::ClaudeExport,
        dir.path().to_path_buf(),
        selection,
    );
    let (stream_summary, records) = collect(&declaration);
    let stream_summary = stream_summary.unwrap();
    let keys: std::collections::BTreeSet<&str> = records
        .iter()
        .filter(|record| record.kind == ArchiveRecordKind::Message)
        .map(|record| record.natural_key.as_str())
        .collect();
    // A declared cutoff is hard: neither pre-cutoff nor undated/unparseable
    // chat records are admitted.
    assert!(keys.is_empty());
    assert_eq!(stream_summary.skip_reasons["before_since"], 1);
    assert_eq!(stream_summary.skip_reasons["unparseable_timestamp"], 1);
}

/// Policy correctness: a message with no decoded body is still admitted as a
/// metadata record — its Message-ID, headers, date, and labels survive — and
/// is only counted (`empty_body`). Excluding mail for lacking text would be
/// undeclared selection, so attachment-only/empty-body mail is never dropped.
#[test]
fn empty_body_messages_are_admitted_as_metadata_records() {
    let dir = tempfile::tempdir().unwrap();
    let mbox = "\
From a@example.com Mon Jan  4 10:00:00 2021
Message-ID: <meta@x>
Date: Mon, 04 Jan 2021 10:00:00 +0000
From: a@example.com
To: colin@example.com
X-Gmail-Labels: Inbox
Content-Type: text/plain; charset=utf-8

";
    std::fs::write(dir.path().join("test.mbox"), mbox).unwrap();
    let declaration = declaration(
        ArchiveFormat::Mbox,
        dir.path().join("test.mbox"),
        mbox_selection(),
    );
    let (stream_summary, records) = collect(&declaration);
    let stream_summary = stream_summary.unwrap();
    let record = records
        .iter()
        .find(|record| record.natural_key == "meta@x")
        .expect("an empty-body message is admitted, never dropped");
    assert_eq!(record.kind, ArchiveRecordKind::Message);
    // The record is the export's own header block: no fabricated content.
    assert!(record.text.contains("From: a@example.com"));
    assert!(record.text.contains("To: colin@example.com"));
    assert_eq!(record.provenance.message_id.as_deref(), Some("meta@x"));
    assert!(record.provenance.created_at.is_some());
    assert_eq!(record.provenance.labels, vec!["Inbox".to_owned()]);
    assert_eq!(stream_summary.skip_reasons.get("empty_body"), Some(&1));
    assert_eq!(stream_summary.skip_reasons.get("no_body"), None);
}

// ---------------------------------------------------------------------------
// Asset origin locators: the declaration site vs the original binary
// ---------------------------------------------------------------------------

#[test]
fn claude_asset_origin_declares_site_without_claiming_bytes() {
    let dir = tempfile::tempdir().unwrap();
    claude_fixture(&dir);
    let declaration = declaration(
        ArchiveFormat::ClaudeExport,
        dir.path().to_path_buf(),
        mbox_selection(),
    );
    let (_, records) = collect(&declaration);

    // Attachments carry no id in this export: the locator is the
    // declaration site plus the 1-based position. The bytes are not
    // exported, so no member is ever claimed — `REGISTER.md` is a
    // declared filename, not a member.
    let attachment = records
        .iter()
        .find(|record| record.natural_key == "msg-1:asset:REGISTER.md")
        .unwrap();
    let origin = attachment.provenance.origin.as_ref().unwrap();
    assert_eq!(origin.declared_in.as_deref(), Some("conversations.json"));
    assert_eq!(origin.member, None);
    assert_eq!(origin.asset_id, None);
    assert_eq!(origin.position, Some(1));

    // `files` entries carry the export's own file uuid as the asset id.
    let file = records
        .iter()
        .find(|record| record.natural_key == "msg-2:asset:shot.png")
        .unwrap();
    let origin = file.provenance.origin.as_ref().unwrap();
    assert_eq!(origin.declared_in.as_deref(), Some("conversations.json"));
    assert_eq!(origin.member, None);
    assert_eq!(origin.asset_id.as_deref(), Some("f-1"));
    assert_eq!(origin.position, Some(1));

    // Records without asset identity carry no locator at all.
    let conversation = records
        .iter()
        .find(|record| record.natural_key == "conv-1")
        .unwrap();
    assert!(conversation.provenance.origin.is_none());
    let message = records
        .iter()
        .find(|record| record.natural_key == "msg-1")
        .unwrap();
    assert!(message.provenance.origin.is_none());
}

#[test]
fn grok_asset_origin_is_the_exact_central_directory_member() {
    let dir = tempfile::tempdir().unwrap();
    let zip_path = dir.path().join("grokdata.zip");
    grok_fixture(&zip_path);

    let declaration = declaration(ArchiveFormat::GrokExport, zip_path, mbox_selection());
    let (_, records) = collect(&declaration);
    let asset = records
        .iter()
        .find(|record| record.natural_key == "conv-1:asset:asset-uuid-1")
        .unwrap();
    let origin = asset.provenance.origin.as_ref().unwrap();
    // The locator is the exact member the central directory carries —
    // doubled separator included — never a name derived from metadata.
    assert_eq!(
        origin.member.as_deref(),
        Some("ttl/30d/export_data/export-uuid-1/prod-mc-asset-server//asset-uuid-1/content")
    );
    assert_eq!(
        origin.declared_in.as_deref(),
        Some("ttl/30d/export_data/export-uuid-1/prod-grok-backend.json")
    );
    assert_eq!(origin.asset_id.as_deref(), Some("asset-uuid-1"));
    assert_eq!(origin.position, None);
}

#[test]
fn mbox_attachments_keep_names_and_media_and_locate_member_position() {
    let dir = tempfile::tempdir().unwrap();
    let zip_path = dir.path().join("takeout-attachment.zip");
    let raw = "\
From alice@example.com Tue Jun  7 10:00:00 2022
Message-ID: <att-1@x>
Date: Tue, 07 Jun 2022 10:00:00 +0000
From: Alice <alice@example.com>
To: colin@example.com
Subject: Report attached
Content-Type: multipart/mixed; boundary=\"bnd\"

--bnd
Content-Type: text/plain; charset=utf-8

See the report.
--bnd
Content-Type: application/pdf; name=\"report.pdf\"
Content-Disposition: attachment; filename=\"report.pdf\"
Content-Transfer-Encoding: base64

UERGLUlHTk9SRUQ=
--bnd--

";
    let mut zip = zip::ZipWriter::new(std::fs::File::create(&zip_path).unwrap());
    let options = zip::write::SimpleFileOptions::default()
        .compression_method(zip::CompressionMethod::Deflated);
    zip.start_file("Takeout/Mail/My mail.mbox", options)
        .unwrap();
    zip.write_all(raw.as_bytes()).unwrap();
    zip.finish().unwrap();

    let zip_declaration = declaration(ArchiveFormat::Mbox, zip_path, mbox_selection());
    let (_, records) = collect(&zip_declaration);
    let message = records
        .iter()
        .find(|record| record.natural_key == "att-1@x")
        .unwrap();

    // The export's own attachment metadata survives in the record text:
    // declared file name and media type, body bytes never touched.
    assert!(message
        .text
        .contains("[attachment name=report.pdf media_type=application/pdf]"));
    assert!(!message.text.contains("UERGLUlHTk9SRUQ="));

    // The locator: the mbox zip member plus the deterministic 1-based
    // source position; the Message-ID above stays the identity.
    let origin = message.provenance.origin.as_ref().unwrap();
    assert_eq!(origin.member.as_deref(), Some("Takeout/Mail/My mail.mbox"));
    assert_eq!(origin.position, Some(1));
    assert_eq!(origin.asset_id, None);

    // A message without attachments carries no locator.
    let plain_dir = tempfile::tempdir().unwrap();
    let plain_path = plain_dir.path().join("plain.mbox");
    std::fs::write(
        &plain_path,
        "From alice@example.com Tue Jun  7 10:00:00 2022\nMessage-ID: <plain-1@x>\nDate: Tue, 07 Jun 2022 10:00:00 +0000\nFrom: Alice <alice@example.com>\nTo: colin@example.com\nSubject: Plain\n\nno attachments\n\n",
    )
    .unwrap();
    let plain_declaration = declaration(ArchiveFormat::Mbox, plain_path, mbox_selection());
    let (_, plain_records) = collect(&plain_declaration);
    let plain = plain_records
        .iter()
        .find(|record| record.natural_key == "plain-1@x")
        .unwrap();
    assert!(plain.provenance.origin.is_none());
    assert!(!plain.text.contains("[attachment"));
}

#[test]
fn grok_ambiguous_asset_id_claims_no_member() {
    let dir = tempfile::tempdir().unwrap();
    let zip_path = dir.path().join("grokdata.zip");
    let backend = serde_json::json!({
        "conversations": [{
            "conversation": {
                "id": "conv-1",
                "user_id": "user-1",
                "title": "Ambiguous asset",
                "asset_ids": ["asset-1"]
            },
            "responses": [{"response": {
                "_id": "r1",
                "message": "one asset, two members",
                "sender": "human",
                "file_attachments": ["asset-1"]
            }}]
        }]
    });
    // TWO distinct members claim one asset id: neither is the original —
    // no member may be chosen, and no size either. (IDENTICAL-name
    // duplicates are a documented reader limitation: the maintained zip
    // reader's index coalesces same-named entries to one — last physical
    // entry — before any parser sees them, so identical-name ambiguity is
    // not observable here and is never claimed. No bytes are read or
    // hashed to disambiguate anything.)
    let mut zip = zip::ZipWriter::new(std::fs::File::create(&zip_path).unwrap());
    let options = zip::write::SimpleFileOptions::default()
        .compression_method(zip::CompressionMethod::Deflated);
    zip.start_file(
        "ttl/30d/export_data/export-uuid-1/prod-grok-backend.json",
        options,
    )
    .unwrap();
    zip.write_all(serde_json::to_string(&backend).unwrap().as_bytes())
        .unwrap();
    zip.start_file(
        "ttl/30d/export_data/export-uuid-1/prod-mc-asset-server//asset-1/content",
        options,
    )
    .unwrap();
    zip.write_all(b"which bytes are these?").unwrap();
    zip.start_file(
        "ttl/30d/export_data/export-uuid-1/prod-mc-asset-server/asset-1/content",
        options,
    )
    .unwrap();
    zip.write_all(b"which bytes are these?").unwrap();
    zip.finish().unwrap();
    let declaration = declaration(ArchiveFormat::GrokExport, zip_path, mbox_selection());
    let (summary, records) = collect(&declaration);
    let summary = summary.unwrap();
    let asset = records
        .iter()
        .find(|record| record.natural_key == "conv-1:asset:asset-1")
        .unwrap();
    let origin = asset.provenance.origin.as_ref().unwrap();
    // The ambiguous id claims NO member and NO central-directory size;
    // the declaration site and the export's own asset id remain the
    // locator. Never an invented choice between members.
    assert_eq!(origin.member, None);
    assert_eq!(
        origin.declared_in.as_deref(),
        Some("ttl/30d/export_data/export-uuid-1/prod-grok-backend.json")
    );
    assert_eq!(origin.asset_id.as_deref(), Some("asset-1"));
    assert!(asset.text.contains("size_bytes=unknown"));
    assert_eq!(summary.skip_reasons["ambiguous_asset_member"], 1);
}
