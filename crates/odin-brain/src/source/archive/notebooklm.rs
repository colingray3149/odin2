//! NotebookLM Takeout parser: `<notebook>/Sources/*` + `<notebook> metadata.json`.
//!
//! The declared root is the `NotebookLM/` directory of an extracted Google
//! Takeout. Every subdirectory is one notebook, identified by its directory
//! name, with a `<name> metadata.json` beside a `Sources/` directory of
//! per-source files. The export carries no account, notebook, or source
//! uuids, so identity is the export's own naming: notebook directory and
//! source file name, and natural keys are the deterministic
//! `<notebook>:<file>` pairs. Each `.html` source is the exported snapshot
//! of one notebook source, rendered to normalized note text through the
//! same maintained `html2text` renderer the mbox parser uses — styles,
//! scripts, and link plumbing never become prose, and nothing is ever
//! fetched from the declared link targets. Sources the export shipped as
//! uploads keep their file as-is and contribute metadata-only asset
//! records; bodies never move.
//!
//! The Takeout declares no per-source timestamp, so source notes keep
//! `created_at: None` and a declared `since` cutoff fails closed: every
//! source is skipped `date_missing`, exactly like undated chat records.
//! Keep-all: a note longer than [`MAX_RECORD_BYTES`] is segmented with
//! stable part identity, and a source whose HTML renders to no text is
//! admitted as its declared identity (`empty_body`), never dropped — a
//! render failure is not emptiness and fails the stream typed. The
//! `<name> metadata.json` file is required structure: a notebook without
//! it fails the stream typed instead of losing the notebook silently.
//! Only real directories and regular files of the declared tree are ever
//! read: every enumerated entry and every fixed-name join is classified
//! through `symlink_metadata`, so symlinks and non-regular entries are
//! refused typed and their targets are never followed.

use std::collections::{BTreeMap, HashMap};
use std::ffi::OsString;
use std::fs::File;
use std::io::BufReader;
use std::path::Path;

use odin_domain::knowledge::archive::ArchiveSourceDeclaration;
use serde::Deserialize;
use serde_json::Value;

use crate::error::{BrainError, BrainResult};
use crate::source::archive::{
    parse_timestamp, segment_and_deliver, since_skip_reason, ArchiveAssetOrigin, ArchiveProvenance,
    ArchiveRecord, ArchiveRecordKind, ArchiveStreamSummary,
};

/// Text width used when rendering source HTML to normalized note text
/// (the mbox renderer width; one normalization across formats).
const HTML_TEXT_WIDTH: usize = 120;

/// Hard bound on one source file read by this parser (bomb guard,
/// mirroring the grok entry bound). Source snapshots are small; the bound
/// fails an absurd export typed instead of materializing it.
const MAX_SOURCE_BYTES: u64 = 256 * 1024 * 1024;

const SOURCES_DIR: &str = "Sources";
const METADATA_SUFFIX: &str = " metadata.json";
const HTML_EXTENSION: &str = "html";

/// Exported notebook metadata: `<name> metadata.json`. Fields the export
/// omits stay absent — nothing is invented, unknown fields are ignored.
#[derive(Deserialize)]
struct NotebookMetadata {
    #[serde(default)]
    title: Option<String>,
    #[serde(default)]
    emoji: Option<String>,
    #[serde(default, rename = "metadata")]
    times: Option<NotebookTimes>,
}

#[derive(Deserialize)]
struct NotebookTimes {
    #[serde(default, rename = "createTime")]
    create_time: Option<String>,
    #[serde(default, rename = "isShared")]
    is_shared: Option<bool>,
    #[serde(default, rename = "lastViewed")]
    last_viewed: Option<String>,
}

pub(super) fn stream(
    declaration: &ArchiveSourceDeclaration,
    seen: &mut HashMap<String, String>,
    summary: &mut ArchiveStreamSummary,
    emit: &mut dyn FnMut(ArchiveRecord) -> BrainResult<()>,
) -> BrainResult<()> {
    let Some(entries) = sorted_entries(&declaration.path)? else {
        return Err(BrainError::Unavailable {
            component: "archive",
            reason: format!(
                "declared NotebookLM root {} not found",
                declaration.path.display()
            ),
        });
    };
    for (name, kind) in entries {
        match kind {
            // Stray regular files beside the notebook directories
            // (Takeout leftovers) are not part of this format.
            DeclaredKind::File => continue,
            // Symlinks and non-regular entries are never followed.
            DeclaredKind::Other => {
                return Err(BrainError::Unavailable {
                    component: "archive",
                    reason: format!(
                        "{} is not a regular directory; refusing a non-regular entry in the declared export",
                        declaration.path.join(&name).display()
                    ),
                });
            }
            // Vanished between listing and classification.
            DeclaredKind::Absent => summary.skip("notebook_entry_absent"),
            DeclaredKind::Dir => {
                let Some(notebook) = name.to_str() else {
                    summary.skip("notebook_without_stable_name");
                    continue;
                };
                stream_notebook(declaration, seen, summary, emit, notebook)?;
            }
        }
    }
    Ok(())
}

/// Streams one notebook: its required metadata record, then every source
/// file in `Sources/`, in deterministic name order, one file in memory at
/// a time.
fn stream_notebook(
    declaration: &ArchiveSourceDeclaration,
    seen: &mut HashMap<String, String>,
    summary: &mut ArchiveStreamSummary,
    emit: &mut dyn FnMut(ArchiveRecord) -> BrainResult<()>,
    notebook: &str,
) -> BrainResult<()> {
    let dir = declaration.path.join(notebook);
    let metadata_path = dir.join(format!("{notebook}{METADATA_SUFFIX}"));
    // The metadata file is opened by a fixed name, so it is checked
    // itself: a symlink is refused typed, never followed.
    match declared_kind(&metadata_path)? {
        DeclaredKind::File => {}
        DeclaredKind::Absent => {
            return Err(BrainError::Unavailable {
                component: "archive",
                reason: format!("required {} not found", metadata_path.display()),
            });
        }
        DeclaredKind::Dir | DeclaredKind::Other => {
            return Err(BrainError::Unavailable {
                component: "archive",
                reason: format!(
                    "{} is not a regular file; refusing a non-regular entry in the declared export",
                    metadata_path.display()
                ),
            });
        }
    }
    let metadata: NotebookMetadata =
        serde_json::from_reader(File::open(&metadata_path).map_err(|err| {
            BrainError::Unavailable {
                component: "archive",
                reason: format!("cannot open {}: {err}", metadata_path.display()),
            }
        })?)
        .map_err(BrainError::Serialization)?;

    // The export's title when it declares one; the directory name is the
    // export's own identity otherwise. Never invented.
    let title = metadata
        .title
        .as_deref()
        .map(str::trim)
        .filter(|title| !title.is_empty())
        .unwrap_or(notebook);
    let created = metadata
        .times
        .as_ref()
        .and_then(|times| times.create_time.as_deref());
    let (created_at, created_raw) = match created {
        Some(raw) => (parse_timestamp(raw), Some(raw)),
        None => (None, None),
    };
    if created_raw.is_some() && created_at.is_none() {
        summary.skip("unparseable_timestamp");
    }

    // Notebook-level structured provenance: the export's declared
    // notebook metadata, carried verbatim (raw timestamp strings, never
    // reformatted) and shared by every record of this notebook.
    let mut base = ArchiveProvenance::default();
    let mut notebook_meta = BTreeMap::new();
    notebook_meta.insert("notebook".to_owned(), Value::String(title.to_owned()));
    if let Some(emoji) = metadata.emoji.as_deref() {
        notebook_meta.insert("notebook_emoji".to_owned(), Value::String(emoji.to_owned()));
    }
    if let Some(times) = metadata.times.as_ref() {
        if let Some(raw) = times.create_time.as_deref() {
            notebook_meta.insert(
                "notebook_created_at".to_owned(),
                Value::String(raw.to_owned()),
            );
        }
        if let Some(shared) = times.is_shared {
            notebook_meta.insert("notebook_is_shared".to_owned(), Value::Bool(shared));
        }
        if let Some(raw) = times.last_viewed.as_deref() {
            notebook_meta.insert(
                "notebook_last_viewed".to_owned(),
                Value::String(raw.to_owned()),
            );
        }
    }
    base.export_metadata = notebook_meta;

    let sources_dir = dir.join(SOURCES_DIR);
    // `Sources/` is read by a fixed name, so it is checked itself: a
    // symlinked directory is refused typed instead of walking an
    // undeclared target.
    let sources = match declared_kind(&sources_dir)? {
        DeclaredKind::Dir => sorted_entries(&sources_dir)?
            .unwrap_or_default()
            .into_iter()
            .map(|(name, kind)| match name.to_str() {
                Some(name) => (name.to_owned(), kind),
                None => (String::new(), kind),
            })
            .collect::<Vec<_>>(),
        // A notebook without a `Sources/` directory has zero sources; the
        // metadata record below still accounts for the notebook.
        DeclaredKind::Absent => Vec::new(),
        DeclaredKind::File | DeclaredKind::Other => {
            return Err(BrainError::Unavailable {
                component: "archive",
                reason: format!(
                    "{} is not a regular directory; refusing a non-regular entry in the declared export",
                    sources_dir.display()
                ),
            });
        }
    };
    let named_sources = sources
        .iter()
        .filter(|(name, kind)| !name.is_empty() && matches!(kind, DeclaredKind::File))
        .count();

    // Notebook identity record: deterministic text over export-declared
    // fields only (title, source count, declared creation).
    let mut text = format!("Notebook '{title}'\nsources: {named_sources}");
    // The declared creation enters derived text only when it parsed; an
    // unparseable raw is counted and stays in provenance, never
    // fabricated into record text.
    if created_at.is_some() {
        if let Some(raw) = created_raw {
            text.push_str(&format!("\ncreated: {raw}"));
        }
    }
    let mut provenance = base.clone();
    provenance.created_at = created_at;
    segment_and_deliver(
        summary,
        seen,
        ArchiveRecord {
            natural_key: format!("{notebook}:metadata"),
            kind: ArchiveRecordKind::Memory,
            text,
            provenance,
        },
        emit,
    )?;

    for (file_name, kind) in sources {
        summary.messages_parsed += 1;
        if file_name.is_empty() {
            // A source file name outside UTF-8 has no stable identity to
            // key or carry in provenance; counted, never silent.
            summary.skip("source_without_stable_name");
            continue;
        }
        match kind {
            // Symlinks and non-regular entries are never followed.
            DeclaredKind::Other => {
                return Err(BrainError::Unavailable {
                    component: "archive",
                    reason: format!(
                        "{} is not a regular file; refusing a non-regular entry in the declared export",
                        sources_dir.join(&file_name).display()
                    ),
                });
            }
            DeclaredKind::Dir => {
                summary.skip("unexpected_sources_entry");
                continue;
            }
            // Vanished between listing and classification.
            DeclaredKind::Absent => {
                summary.skip("source_entry_absent");
                continue;
            }
            DeclaredKind::File => {}
        }
        // Source files are undated; a declared cutoff excludes them all,
        // fail-closed, before any content is read.
        if let Some(reason) = since_skip_reason(declaration.selection.since, None, false) {
            summary.skip(reason);
            continue;
        }
        let path = sources_dir.join(&file_name);
        if is_html(&file_name) {
            deliver_html_source(seen, summary, emit, notebook, &path, &file_name, &base)?;
        } else {
            deliver_upload_asset(seen, summary, emit, notebook, &path, &file_name, &base)?;
        }
    }
    Ok(())
}

/// Normalizes one exported HTML source through the maintained renderer and
/// delivers it as a Memory note. A render failure is not emptiness and
/// fails the stream typed; a source that successfully renders to no text
/// is admitted as its declared identity — counted, never dropped.
fn deliver_html_source(
    seen: &mut HashMap<String, String>,
    summary: &mut ArchiveStreamSummary,
    emit: &mut dyn FnMut(ArchiveRecord) -> BrainResult<()>,
    notebook: &str,
    path: &Path,
    file_name: &str,
    base: &ArchiveProvenance,
) -> BrainResult<()> {
    check_source_size(path)?;
    let file = File::open(path).map_err(|err| BrainError::Unavailable {
        component: "archive",
        reason: format!("cannot open {}: {err}", path.display()),
    })?;
    let rendered = html2text::from_read(BufReader::new(file), HTML_TEXT_WIDTH).map_err(|err| {
        BrainError::Unavailable {
            component: "archive",
            reason: format!("cannot render {}: {err}", path.display()),
        }
    })?;
    let text = if rendered.trim().is_empty() {
        summary.skip("empty_body");
        format!("[no text content]\n[source file={file_name}]")
    } else {
        rendered
    };
    deliver_source(
        seen,
        summary,
        emit,
        notebook,
        file_name,
        text,
        ArchiveRecordKind::Memory,
        base,
    )
}

/// Delivers one uploaded source file as metadata only: the file body is
/// never read; identity, declared size, and the type its own name declares
/// live in the record.
fn deliver_upload_asset(
    seen: &mut HashMap<String, String>,
    summary: &mut ArchiveStreamSummary,
    emit: &mut dyn FnMut(ArchiveRecord) -> BrainResult<()>,
    notebook: &str,
    path: &Path,
    file_name: &str,
    base: &ArchiveProvenance,
) -> BrainResult<()> {
    let size = check_source_size(path)?;
    let text = format!("uploaded source: name={file_name} size_bytes={size}");
    deliver_source(
        seen,
        summary,
        emit,
        notebook,
        file_name,
        text,
        ArchiveRecordKind::AssetMetadata,
        base,
    )
}

#[allow(clippy::too_many_arguments)]
fn deliver_source(
    seen: &mut HashMap<String, String>,
    summary: &mut ArchiveStreamSummary,
    emit: &mut dyn FnMut(ArchiveRecord) -> BrainResult<()>,
    notebook: &str,
    file_name: &str,
    text: String,
    kind: ArchiveRecordKind,
    base: &ArchiveProvenance,
) -> BrainResult<()> {
    let mut provenance = base.clone();
    provenance.export_metadata.insert(
        "source_file".to_owned(),
        Value::String(file_name.to_owned()),
    );
    if let Some(source_type) = source_type(file_name) {
        provenance
            .export_metadata
            .insert("source_type".to_owned(), Value::String(source_type));
    }
    // The locator is the notebook-relative path of the actual source
    // file (classified a regular file by the caller before delivery) —
    // never the ambiguous basename alone, which collides across
    // notebooks of the same Takeout.
    provenance.origin = Some(ArchiveAssetOrigin {
        member: Some(format!("{notebook}/{SOURCES_DIR}/{file_name}")),
        ..ArchiveAssetOrigin::default()
    });
    segment_and_deliver(
        summary,
        seen,
        ArchiveRecord {
            natural_key: format!("{notebook}:{file_name}"),
            kind,
            text,
            provenance,
        },
        emit,
    )
}

/// A source is HTML when the export named it `.html`.
fn is_html(file_name: &str) -> bool {
    Path::new(file_name)
        .extension()
        .is_some_and(|ext| ext.eq_ignore_ascii_case(HTML_EXTENSION))
}

/// The upload type the export's own file naming declares: an uploaded
/// source is rendered to `<name>.<type>.html`, so the extension before
/// `.html` is the declared type (`guide.pdf.html` declares `pdf`); a file
/// kept as-is declares its plain extension (`notes.txt` declares `txt`).
/// Derived from the export's names only, never guessed.
fn source_type(file_name: &str) -> Option<String> {
    let path = Path::new(file_name);
    let outer = path.extension()?.to_str()?;
    let typed = if outer.eq_ignore_ascii_case(HTML_EXTENSION) {
        Path::new(path.file_stem()?.to_str()?)
    } else {
        path
    };
    let source_type = typed.extension()?.to_str()?;
    Some(source_type.to_owned()).filter(|source_type| !source_type.is_empty())
}

/// Stats one source file without following symlinks, enforcing
/// [`MAX_SOURCE_BYTES`]; returns its size.
fn check_source_size(path: &Path) -> BrainResult<u64> {
    let size = std::fs::symlink_metadata(path)
        .map_err(|err| BrainError::Unavailable {
            component: "archive",
            reason: format!("cannot stat {}: {err}", path.display()),
        })?
        .len();
    if size > MAX_SOURCE_BYTES {
        return Err(BrainError::Unavailable {
            component: "archive",
            reason: format!(
                "source {} is {size} bytes, exceeding the {MAX_SOURCE_BYTES} bound",
                path.display()
            ),
        });
    }
    Ok(size)
}

/// The classification of one path in the declared export tree, taken
/// through `symlink_metadata`: symlinks are their own kind and are never
/// followed, so only real directories and regular files of the declared
/// tree are ever opened.
enum DeclaredKind {
    /// The path is absent (never existed, or vanished between listing
    /// and classification).
    Absent,
    Dir,
    File,
    /// Anything else: a symlink, or a non-regular file. Refused typed by
    /// every caller; its target is never read.
    Other,
}

/// Classifies one path without following symlinks. Read-only.
fn declared_kind(path: &Path) -> BrainResult<DeclaredKind> {
    match std::fs::symlink_metadata(path) {
        Ok(meta) if meta.is_dir() => Ok(DeclaredKind::Dir),
        Ok(meta) if meta.is_file() => Ok(DeclaredKind::File),
        Ok(_) => Ok(DeclaredKind::Other),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(DeclaredKind::Absent),
        Err(err) => Err(BrainError::Unavailable {
            component: "archive",
            reason: format!("cannot stat {}: {err}", path.display()),
        }),
    }
}

/// Deterministically sorted `(name, kind)` entries of one directory,
/// each classified through [`declared_kind`]. `Ok(None)` when the
/// directory does not exist; required roots are enforced by the caller,
/// absence elsewhere is an empty collection.
fn sorted_entries(dir: &Path) -> BrainResult<Option<Vec<(OsString, DeclaredKind)>>> {
    let listed = match std::fs::read_dir(dir) {
        Ok(listed) => listed,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(err) => {
            return Err(BrainError::Unavailable {
                component: "archive",
                reason: format!("cannot read {}: {err}", dir.display()),
            });
        }
    };
    let mut classified = Vec::new();
    for entry in listed {
        let entry = entry.map_err(|err| BrainError::Unavailable {
            component: "archive",
            reason: format!("cannot read {}: {err}", dir.display()),
        })?;
        let name = entry.file_name();
        let kind = declared_kind(&dir.join(&name))?;
        classified.push((name, kind));
    }
    classified.sort_by(|left, right| left.0.cmp(&right.0));
    Ok(Some(classified))
}

#[cfg(test)]
mod tests {
    use std::fs;

    use odin_domain::knowledge::archive::{
        ArchiveDedupeKey, ArchiveFormat, ArchivePrivacyClass, ArchiveSelectionPolicy,
        ArchiveSourceDeclaration,
    };
    use serde_json::Value;
    use time::macros::{date, datetime};

    use crate::error::{BrainError, BrainResult};
    use crate::source::archive::{stream_archive, ArchiveRecord, ArchiveStreamSummary};

    use super::*;

    /// Two synthetic notebooks, no real notebook, person, or thesis
    /// content. `Beta Notebook` is created first on disk to prove name
    /// ordering, declares an empty title (directory-name fallback), and
    /// carries one empty source.
    fn notebook_fixture(dir: &std::path::Path) {
        let beta = dir.join("Beta Notebook");
        fs::create_dir_all(beta.join("Sources")).unwrap();
        fs::write(beta.join("Beta Notebook metadata.json"), r#"{"title":""}"#).unwrap();
        fs::write(beta.join("Sources").join("empty.html"), "<p></p>").unwrap();
        fs::write(beta.join("Sources").join("zeta.html"), "<p>beta note</p>").unwrap();

        let alpha = dir.join("Alpha Notes");
        fs::create_dir_all(alpha.join("Sources")).unwrap();
        fs::write(
            alpha.join("Alpha Notes metadata.json"),
            r#"{"title":"Alpha Notes","emoji":"N","metadata":{"createTime":"2025-01-02T03:04:05Z","isShared":false,"lastViewed":"2025-06-01T10:00:00Z"}}"#,
        )
        .unwrap();
        fs::write(
            alpha.join("Sources").join("long plan.html"),
            "<h1>Plan</h1><p>first &amp; foremost</p><script>never()</script><ul><li>step one</li><li>step two</li></ul>",
        )
        .unwrap();
        fs::write(alpha.join("Sources").join("paper.pdf"), b"%PDF-synthetic").unwrap();
        fs::write(
            alpha.join("Sources").join("slide.pdf.html"),
            "<p>slides text</p>",
        )
        .unwrap();
    }

    fn selection() -> ArchiveSelectionPolicy {
        ArchiveSelectionPolicy {
            since: None,
            exclude_labels: Vec::new(),
            exclude_if_header: Vec::new(),
            keep_if_participant: false,
            participant_emails: Vec::new(),
            suspicious_rules: Vec::new(),
            exclude_do_not_remember: None,
        }
    }

    fn declaration(path: std::path::PathBuf) -> ArchiveSourceDeclaration {
        ArchiveSourceDeclaration {
            format: ArchiveFormat::NotebookLm,
            path,
            memory_namespace: "archive-test".to_owned(),
            privacy_class: ArchivePrivacyClass::Private,
            dedupe_key: ArchiveDedupeKey::ContentDigest,
            selection: selection(),
        }
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

    fn record<'records>(
        records: &'records [ArchiveRecord],
        natural_key: &str,
    ) -> &'records ArchiveRecord {
        records
            .iter()
            .find(|record| record.natural_key == natural_key)
            .unwrap_or_else(|| panic!("no record {natural_key}"))
    }

    fn meta(record: &ArchiveRecord, key: &str) -> Value {
        record.provenance.export_metadata[key].clone()
    }

    #[test]
    fn sources_become_memory_notes_with_notebook_provenance() {
        let dir = tempfile::tempdir().unwrap();
        notebook_fixture(dir.path());

        let (summary, records) = collect(&declaration(dir.path().to_path_buf()));
        let summary = summary.unwrap();

        let note = record(&records, "Alpha Notes:long plan.html");
        assert_eq!(note.kind, ArchiveRecordKind::Memory);
        let text = &note.text;
        assert!(text.contains("Plan"));
        assert!(text.contains("first & foremost"));
        assert!(text.contains("step one") && text.contains("step two"));
        assert!(!text.contains("never()"));
        assert_eq!(meta(note, "notebook"), Value::from("Alpha Notes"));
        assert_eq!(meta(note, "source_file"), Value::from("long plan.html"));
        assert!(!note.provenance.export_metadata.contains_key("source_type"));

        // Uploads: rendered snapshots stay notes, raw files stay
        // metadata-only assets; both carry the declared type.
        let asset = record(&records, "Alpha Notes:paper.pdf");
        assert_eq!(asset.kind, ArchiveRecordKind::AssetMetadata);
        assert!(asset.text.contains("name=paper.pdf"));
        assert_eq!(meta(asset, "source_type"), Value::from("pdf"));
        let rendered = record(&records, "Alpha Notes:slide.pdf.html");
        assert_eq!(rendered.kind, ArchiveRecordKind::Memory);
        assert!(rendered.text.contains("slides text"));
        assert_eq!(meta(rendered, "source_type"), Value::from("pdf"));

        // Notebook identity record: deterministic export-declared text and
        // the full declared notebook metadata as structured provenance.
        let notebook = record(&records, "Alpha Notes:metadata");
        assert_eq!(notebook.kind, ArchiveRecordKind::Memory);
        assert!(notebook.text.contains("Notebook 'Alpha Notes'"));
        assert!(notebook.text.contains("sources: 3"));
        assert!(notebook.text.contains("created: 2025-01-02T03:04:05Z"));
        assert_eq!(
            notebook.provenance.created_at,
            Some(datetime!(2025-01-02 03:04:05 UTC))
        );
        assert_eq!(meta(notebook, "notebook"), Value::from("Alpha Notes"));
        assert_eq!(meta(notebook, "notebook_emoji"), Value::from("N"));
        assert_eq!(
            meta(notebook, "notebook_created_at"),
            Value::from("2025-01-02T03:04:05Z")
        );
        assert_eq!(meta(notebook, "notebook_is_shared"), Value::from(false));
        assert_eq!(
            meta(notebook, "notebook_last_viewed"),
            Value::from("2025-06-01T10:00:00Z")
        );

        // Empty title falls back to the export's own directory identity.
        assert_eq!(
            meta(record(&records, "Beta Notebook:metadata"), "notebook"),
            Value::from("Beta Notebook")
        );

        // A source with no text is admitted as its identity, never dropped.
        assert_eq!(summary.skip_reasons["empty_body"], 1);
        let empty = record(&records, "Beta Notebook:empty.html");
        assert!(empty.text.contains("[no text content]"));
        assert!(empty.text.contains("empty.html"));

        // Every source is classified: five sources, all emitted or counted.
        assert_eq!(summary.messages_parsed, 5);
        assert_eq!(summary.records_emitted, 7);
    }

    #[test]
    fn repeat_streams_yield_identical_natural_keys() {
        let dir = tempfile::tempdir().unwrap();
        notebook_fixture(dir.path());
        let declaration = declaration(dir.path().to_path_buf());

        let keys = |records: &[ArchiveRecord]| -> Vec<String> {
            records
                .iter()
                .map(|record| record.natural_key.clone())
                .collect()
        };
        let (_, first) = collect(&declaration);
        let (_, second) = collect(&declaration);
        assert!(!first.is_empty());
        assert_eq!(keys(&first), keys(&second));
    }

    #[test]
    fn oversized_note_segments_with_stable_part_identity() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("Big Notes");
        fs::create_dir_all(root.join("Sources")).unwrap();
        fs::write(
            root.join("Big Notes metadata.json"),
            r#"{"title":"Big Notes"}"#,
        )
        .unwrap();
        let oversized = format!(
            "<p>HEADMARKER</p><p>{}</p><p>TAILMARKER</p>",
            "x".repeat(crate::source::archive::MAX_RECORD_BYTES + 17)
        );
        fs::write(root.join("Sources").join("big.html"), oversized).unwrap();

        let (summary, records) = collect(&declaration(dir.path().to_path_buf()));
        let summary = summary.unwrap();

        let parts: Vec<&ArchiveRecord> = records
            .iter()
            .filter(|record| record.natural_key.starts_with("Big Notes:big.html:part:"))
            .collect();
        assert!(parts.len() >= 2);
        for (index, part) in parts.iter().enumerate() {
            assert!(part.text.len() <= crate::source::archive::MAX_RECORD_BYTES);
            assert_eq!(part.provenance.part_index, Some(index as u32 + 1));
            assert_eq!(part.provenance.part_count, Some(parts.len() as u32));
        }
        assert!(parts[0].text.contains("HEADMARKER"));
        assert!(parts[parts.len() - 1].text.contains("TAILMARKER"));
        assert_eq!(summary.skip_reasons["record_segmented"], 1);
    }

    #[test]
    fn required_metadata_is_enforced_typed() {
        // Missing `<name> metadata.json`: the notebook's structure is
        // broken; the stream fails typed instead of losing the notebook.
        let dir = tempfile::tempdir().unwrap();
        let ghost = dir.path().join("Ghost Notebook");
        fs::create_dir_all(ghost.join("Sources")).unwrap();
        fs::write(ghost.join("Sources").join("x.html"), "<p>lost</p>").unwrap();
        let (summary, _) = collect(&declaration(dir.path().to_path_buf()));
        assert!(matches!(
            summary.unwrap_err(),
            BrainError::Unavailable { .. }
        ));

        // Malformed metadata: a malformed memory-like file fails the
        // stream typed rather than dropping content.
        let dir = tempfile::tempdir().unwrap();
        let broken = dir.path().join("Broken");
        fs::create_dir_all(&broken).unwrap();
        fs::write(broken.join("Broken metadata.json"), "{not json").unwrap();
        let (summary, _) = collect(&declaration(dir.path().to_path_buf()));
        assert!(matches!(summary.unwrap_err(), BrainError::Serialization(_)));
    }

    #[test]
    fn unparseable_notebook_timestamp_is_counted_not_invented() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("Undated");
        fs::create_dir_all(&root).unwrap();
        fs::write(
            root.join("Undated metadata.json"),
            r#"{"title":"Undated","metadata":{"createTime":"not-a-date"}}"#,
        )
        .unwrap();

        let (summary, records) = collect(&declaration(dir.path().to_path_buf()));
        let summary = summary.unwrap();
        let notebook = record(&records, "Undated:metadata");
        assert_eq!(notebook.provenance.created_at, None);
        assert!(!notebook.text.contains("created:"));
        assert_eq!(
            meta(notebook, "notebook_created_at"),
            Value::from("not-a-date")
        );
        assert_eq!(summary.skip_reasons["unparseable_timestamp"], 1);
    }

    #[test]
    fn symlinked_export_entries_are_refused_typed_never_followed() {
        // The link targets live outside the declared root; every escape
        // fails typed and no target content is ever read.
        let outside = tempfile::tempdir().unwrap();
        std::fs::write(outside.path().join("target.html"), "<p>ESCAPED</p>").unwrap();
        std::fs::create_dir_all(outside.path().join("target-dir")).unwrap();

        // A symlinked source entry inside `Sources/`.
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("Linked");
        fs::create_dir_all(root.join("Sources")).unwrap();
        fs::write(root.join("Linked metadata.json"), r#"{"title":"Linked"}"#).unwrap();
        std::os::unix::fs::symlink(
            outside.path().join("target.html"),
            root.join("Sources").join("linked.html"),
        )
        .unwrap();
        let (summary, _) = collect(&declaration(dir.path().to_path_buf()));
        assert!(matches!(
            summary.unwrap_err(),
            BrainError::Unavailable { .. }
        ));

        // A symlinked `Sources/` directory itself: the fixed-name join
        // must not walk into an undeclared target.
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("Linked Sources");
        fs::create_dir_all(&root).unwrap();
        fs::write(
            root.join("Linked Sources metadata.json"),
            r#"{"title":"L"}"#,
        )
        .unwrap();
        std::os::unix::fs::symlink(outside.path().join("target-dir"), root.join("Sources"))
            .unwrap();
        let (summary, _) = collect(&declaration(dir.path().to_path_buf()));
        assert!(matches!(
            summary.unwrap_err(),
            BrainError::Unavailable { .. }
        ));

        // A symlinked `<name> metadata.json` itself.
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("Linked Meta");
        fs::create_dir_all(root.join("Sources")).unwrap();
        std::os::unix::fs::symlink(
            outside.path().join("target.html"),
            root.join("Linked Meta metadata.json"),
        )
        .unwrap();
        let (summary, _) = collect(&declaration(dir.path().to_path_buf()));
        assert!(matches!(
            summary.unwrap_err(),
            BrainError::Unavailable { .. }
        ));
    }

    #[test]
    fn declared_since_is_a_hard_cutoff_for_undated_sources() {
        let dir = tempfile::tempdir().unwrap();
        notebook_fixture(dir.path());
        let mut declaration = declaration(dir.path().to_path_buf());
        declaration.selection.since = Some(date!(2025 - 01 - 01));

        // Through the parser seam directly: sources carry no export
        // timestamp, so the cutoff excludes every one of them while the
        // notebook identity records (which are dated by the export) keep.
        let mut records = Vec::new();
        let mut summary = ArchiveStreamSummary::default();
        let mut seen = HashMap::new();
        {
            let mut emit = |record: ArchiveRecord| -> BrainResult<()> {
                records.push(record);
                Ok(())
            };
            stream(&declaration, &mut seen, &mut summary, &mut emit).unwrap();
        }
        assert_eq!(summary.messages_parsed, 5);
        assert_eq!(summary.skip_reasons["date_missing"], 5);
        assert_eq!(summary.records_emitted, 2);
        assert!(records
            .iter()
            .all(|record| record.natural_key.ends_with(":metadata")));
    }

    #[test]
    fn notebooks_stream_in_deterministic_name_order() {
        let dir = tempfile::tempdir().unwrap();
        notebook_fixture(dir.path());

        let (_, records) = collect(&declaration(dir.path().to_path_buf()));
        assert_eq!(records[0].natural_key, "Alpha Notes:metadata");
        let metadata_position = records
            .iter()
            .position(|record| record.natural_key == "Beta Notebook:metadata")
            .unwrap();
        let first_beta_source = records
            .iter()
            .position(|record| record.natural_key == "Beta Notebook:empty.html")
            .unwrap();
        assert!(metadata_position < first_beta_source);
    }

    #[test]
    fn same_basename_sources_keep_notebook_relative_locators() {
        let dir = tempfile::tempdir().unwrap();
        // Two notebooks shipping a source with the SAME basename: the
        // basename alone is ambiguous, so the locator must be the
        // notebook-relative path of the actual file.
        for notebook in ["One Notebook", "Two Notebook"] {
            let root = dir.path().join(notebook);
            fs::create_dir_all(root.join("Sources")).unwrap();
            fs::write(
                root.join(format!("{notebook} metadata.json")),
                format!(r#"{{"title":"{notebook}"}}"#),
            )
            .unwrap();
            fs::write(root.join("Sources").join("guide.pdf"), b"%PDF-synthetic").unwrap();
        }

        let (_, records) = collect(&declaration(dir.path().to_path_buf()));
        let one = record(&records, "One Notebook:guide.pdf");
        let two = record(&records, "Two Notebook:guide.pdf");
        let one_origin = one.provenance.origin.as_ref().unwrap();
        let two_origin = two.provenance.origin.as_ref().unwrap();
        assert_eq!(
            one_origin.member.as_deref(),
            Some("One Notebook/Sources/guide.pdf")
        );
        assert_eq!(
            two_origin.member.as_deref(),
            Some("Two Notebook/Sources/guide.pdf")
        );
        assert_ne!(one_origin.member, two_origin.member);
    }
}
