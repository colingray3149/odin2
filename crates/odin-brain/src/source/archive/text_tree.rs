//! Text tree parser: every `*.md` / `*.txt` file under the declared
//! directory is one document record (extracted document text, transcripts,
//! life summaries, curated pages). The title is the first `# ` heading or
//! the file stem; the timestamp is a leading `date: YYYY-MM-DD` line, and a
//! document without one has none (a copy or restore resets modification
//! times, which would re-key every record). Oversized files segment as usual.

use odin_domain::knowledge::archive::ArchiveSourceDeclaration;
use serde_json::json;
use time::Date;

use crate::error::{BrainError, BrainResult};
use crate::source::archive::{
    segment_and_deliver, since_skip_reason, tree_files, ArchiveProvenance, ArchiveRecord,
    ArchiveRecordKind, ArchiveStreamSummary, SeenRecords,
};

pub(super) fn stream(
    declaration: &ArchiveSourceDeclaration,
    seen: &mut SeenRecords,
    summary: &mut ArchiveStreamSummary,
    emit: &mut dyn FnMut(ArchiveRecord) -> BrainResult<()>,
) -> BrainResult<()> {
    for path in tree_files(&declaration.path, &["md", "txt"])? {
        let rel = path
            .strip_prefix(&declaration.path)
            .unwrap_or(&path)
            .to_string_lossy()
            .into_owned();
        let unreadable = |err: std::io::Error| BrainError::Unavailable {
            component: "archive",
            reason: format!("cannot read {rel}: {err}"),
        };
        summary.messages_parsed += 1;
        let Ok(text) = String::from_utf8(std::fs::read(&path).map_err(unreadable)?) else {
            summary.skip(format!("not_utf8:{rel}"));
            continue;
        };
        if text.trim().is_empty() {
            summary.skip("empty_document");
            continue;
        }
        let created_at = leading_date(&text).map(|date| date.midnight().assume_utc());
        if let Some(reason) = since_skip_reason(declaration.selection.since, created_at, false) {
            summary.skip(reason);
            continue;
        }
        let stem = path
            .file_stem()
            .map(|stem| stem.to_string_lossy().into_owned())
            .unwrap_or_else(|| rel.clone());
        let title = text
            .lines()
            .find_map(|line| line.strip_prefix("# "))
            .map(str::trim)
            .filter(|title| !title.is_empty())
            .map(str::to_owned)
            .unwrap_or(stem);
        let mut provenance = ArchiveProvenance {
            message_id: Some(rel.clone()),
            created_at,
            ..ArchiveProvenance::default()
        };
        provenance
            .export_metadata
            .insert("path".to_owned(), json!(rel));
        provenance
            .export_metadata
            .insert("title".to_owned(), json!(title));
        segment_and_deliver(
            summary,
            seen,
            ArchiveRecord {
                natural_key: rel,
                kind: ArchiveRecordKind::Memory,
                text,
                provenance,
            },
            emit,
        )?;
    }
    Ok(())
}

/// The day of a `date: YYYY-MM-DD` line among the first few non-blank lines
/// (a `---` front-matter fence may precede it).
fn leading_date(text: &str) -> Option<Date> {
    text.lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && *line != "---")
        .take(5)
        .find_map(|line| {
            line.get(..5)
                .filter(|prefix| prefix.eq_ignore_ascii_case("date:"))?;
            Date::parse(
                line[5..].trim(),
                &time::macros::format_description!("[year]-[month]-[day]"),
            )
            .ok()
        })
}
