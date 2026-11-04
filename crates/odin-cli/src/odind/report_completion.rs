//! The report contract a research run owes: exactly one polished PDF beside
//! its markdown, identified by the renderer's receipt. Supporting PDFs are
//! evidence. Markdown is parsed by pulldown-cmark and emitted as Typst content
//! with every text run a string literal, so page and tool output cannot become
//! markup. A figure the export cannot satisfy is named on the page, never
//! silently dropped. The authority compiles that source with docs.render's
//! research template; this module does not run Typst.

use std::{fmt::Write as _, time::Duration};

use odin_domain::RunId;
use odin_omp::host_tools::pod_exec::{ExportedFile, PodWorkerExec, WorkerExecFault};
use pulldown_cmark::{CodeBlockKind, Event, Options, Parser, Tag, TagEnd};
use serde_json::Value;

const TOOL_WAIT: Duration = Duration::from_secs(120);
/// Stdout the settle loop asks a pod tool to keep.
const TOOL_TAIL: usize = 4 * 1024;
/// The renderer's own source bound; a longer answer is a named failure.
const MAX_SOURCE_BYTES: usize = 256 * 1024;

/// The one PDF the renderer receipt names.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ReportIdentity {
    pub pdf_relative: String,
    pub pdf_absolute: String,
    pub source: String,
    pub bytes: u64,
    pub page_count: u64,
    pub content: String,
    pub body: String,
    pub pdf: String,
    pub captured_at: String,
}

/// What completing the report contract found, for the pod report wake.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum ReportCompletion {
    /// A validated renderer receipt names the one report PDF.
    Met(ReportIdentity),
    /// No validated receipt. The authority can still render the report body.
    Owed,
    /// No receipt and nothing to complete from. The message names why.
    Unmet(String),
}

/// Decides the run's report contract from its settled export.
///
/// The report is the PDF named by a validated `report-render.json`. Other
/// PDFs stay evidence. Paths in the export listing are relative to `export_dir`.
pub(crate) fn report_contract(
    files: &[ExportedFile],
    export_dir: &str,
    failed: bool,
    answer_is_empty: bool,
) -> ReportCompletion {
    match report_identity(files, export_dir) {
        Ok(Some(identity)) => ReportCompletion::Met(identity),
        Ok(None) if failed || answer_is_empty => ReportCompletion::Unmet(
            "This profile's runs owe one PDF beside the answer; this run ended before a \
             report existed, so none was rendered. Its saved evidence still stands."
                .to_owned(),
        ),
        Ok(None) => ReportCompletion::Owed,
        Err(reason) if failed || answer_is_empty => ReportCompletion::Unmet(format!(
            "This profile's runs owe one PDF beside the answer; the render receipt could not \
             be validated ({reason}), and this run ended before a report existed."
        )),
        Err(_) => ReportCompletion::Owed,
    }
}

/// The report PDF named by a validated renderer receipt, if the export has one.
pub(crate) fn report_identity(
    files: &[ExportedFile],
    export_dir: &str,
) -> Result<Option<ReportIdentity>, String> {
    let Some(file) = find_named(files, "report-render.json") else {
        return Ok(None);
    };
    let bytes = file
        .content
        .as_ref()
        .map_err(|error| format!("the render receipt could not be read: {error}"))?;
    let parsed: Value = serde_json::from_slice(bytes)
        .map_err(|error| format!("the render receipt is not JSON: {error}"))?;
    let source = required_str(&parsed, "source")?;
    let output = required_str(&parsed, "output")?;
    let captured_at = required_str(&parsed, "capturedAt")?;
    let page_count = parsed["page_count"]
        .as_u64()
        .ok_or_else(|| "the render receipt has no page_count".to_owned())?;
    if page_count == 0 {
        return Err("the render receipt names a PDF with no pages".to_owned());
    }
    let pdf_bytes = parsed["bytes"]
        .as_u64()
        .ok_or_else(|| "the render receipt has no byte count".to_owned())?;
    if pdf_bytes == 0 {
        return Err("the render receipt names an empty PDF".to_owned());
    }
    let content = required_str(&parsed, "content")?;
    let body = required_str(&parsed, "body")?;
    let pdf = required_str(&parsed, "pdf")?;
    if !(source.starts_with("/export/") || source.starts_with("/state/"))
        || !output.starts_with("/export/")
    {
        return Err(format!(
            "the render receipt paths are not pod paths: source {source}, output {output}"
        ));
    }
    let relative = relative_export(export_dir, &output);
    let listed = files
        .iter()
        .find(|file| file.path == relative)
        .ok_or_else(|| format!("the render receipt names {output}, which is not in the export"))?;
    if listed.bytes != pdf_bytes {
        return Err(format!(
            "the render receipt says {output} is {pdf_bytes} bytes, but the export has {}",
            listed.bytes
        ));
    }
    let listed_bytes = listed.content.as_ref().map_err(|error| {
        format!("the render receipt names {output}, which could not be read: {error}")
    })?;
    if odin_domain::Digest::hash(listed_bytes).to_string() != pdf {
        return Err(format!(
            "the render receipt names {output}, but its bytes are not that PDF"
        ));
    }
    Ok(Some(ReportIdentity {
        pdf_relative: relative,
        pdf_absolute: output,
        source,
        bytes: pdf_bytes,
        page_count,
        content,
        body,
        pdf,
        captured_at,
    }))
}

fn required_str(value: &Value, field: &str) -> Result<String, String> {
    value[field]
        .as_str()
        .filter(|text| !text.is_empty())
        .map(str::to_owned)
        .ok_or_else(|| format!("the render receipt has no {field}"))
}

pub(crate) fn find_named<'a>(files: &'a [ExportedFile], name: &str) -> Option<&'a ExportedFile> {
    files
        .iter()
        .find(|file| file.path == name || file.path.ends_with(&format!("/{name}")))
}

pub(crate) fn relative_export(export_dir: &str, path: &str) -> String {
    let export = export_dir.trim_end_matches('/');
    path.strip_prefix(export)
        .unwrap_or(path)
        .trim_start_matches('/')
        .to_owned()
}

pub(crate) fn absolute_export(export_dir: &str, path: &str) -> String {
    if path.starts_with('/') {
        path.to_owned()
    } else {
        format!("{}/{}", export_dir.trim_end_matches('/'), path)
    }
}

/// Structural floors that ask the pod to finish the report from the export.
/// They never establish a complete report: acceptance is the model's review
/// of the rendered pages, not these checks. This never invents missing text.
pub(crate) fn content_gaps(
    body: &str,
    source: &str,
    files: &[ExportedFile],
    report_pdf: Option<&str>,
) -> Vec<String> {
    let mut gaps = Vec::new();
    if body.trim().is_empty() {
        gaps.push("the report body is empty".to_owned());
    }
    if !contacts_table(body) {
        gaps.push(
            "the report has no contacts table under a Contacts heading; complete it from the \
             export, and state an absence only when the evidence shows none"
                .to_owned(),
        );
    }
    let figures: Vec<&str> = files
        .iter()
        .filter(|file| is_figure(file, files) && !source_embeds(source, &file.path))
        .map(|file| file.path.as_str())
        .collect();
    if !figures.is_empty() {
        gaps.push(format!(
            "these exported figures are not embedded by the report source: {}",
            figures.join(", ")
        ));
    }
    let evidence: Vec<&str> = files
        .iter()
        .filter(|file| is_evidence(file, files, report_pdf) && !body.contains(&file.path))
        .map(|file| file.path.as_str())
        .collect();
    if !evidence.is_empty() {
        gaps.push(format!(
            "these evidence files are not described in the report; say what each is and what it \
             shows: {}",
            evidence.join(", ")
        ));
    }
    gaps
}

/// The most unmet items one answer is read for, and the longest one.
const MAX_UNMET: usize = 12;
const UNMET_CHARS: usize = 300;
/// The most words of an item that name it.
const UNMET_NAME_WORDS: usize = 8;

/// The launch-input items a final answer says it did not do: what follows its last `Unmet items`
/// lead, a line (heading, bold or plain) reading `Unmet items` or `Unmet launch-input items`, with
/// or without a colon. The items are the text after a colon and the lines below, one per bullet or
/// line, up to the next heading. `Unmet items: none` is every item done. Each item carries the
/// methods the pod says it tried, in its own words.
pub(crate) fn unmet_items(answer: &str) -> Vec<String> {
    let lines: Vec<&str> = answer.lines().collect();
    let Some((at, first)) = lines
        .iter()
        .enumerate()
        .rev()
        .find_map(|(at, line)| unmet_lead(line).map(|rest| (at, rest)))
    else {
        return Vec::new();
    };
    let mut items = Vec::new();
    let mut take = |text: &str| {
        let item = list_text(text);
        if !item.is_empty() {
            items.push(item.chars().take(UNMET_CHARS).collect::<String>());
        }
    };
    take(first);
    for line in &lines[at + 1..] {
        if line.trim_start().starts_with('#') {
            break;
        }
        take(line);
    }
    if items.len() == 1 && items[0].trim_end_matches('.').eq_ignore_ascii_case("none") {
        return Vec::new();
    }
    items.truncate(MAX_UNMET);
    items
}

/// The words an unmet item leads with, to tell items apart across answers that reword the
/// methods tried on them: the text before its first colon (its first words when it has none),
/// lower-cased, without emphasis marks.
pub(crate) fn unmet_name(item: &str) -> String {
    let lead = item.split(':').next().unwrap_or(item);
    let words: Vec<&str> = lead.split_whitespace().take(UNMET_NAME_WORDS).collect();
    words.join(" ").replace(['*', '`'], "").to_lowercase()
}

/// What follows the `Unmet items` lead on `line`, when it is one.
fn unmet_lead(line: &str) -> Option<&str> {
    fn strip<'a>(text: &'a str, word: &str) -> Option<&'a str> {
        let head = text.get(..word.len())?;
        head.eq_ignore_ascii_case(word)
            .then(|| text[word.len()..].trim_start())
    }
    let line = line.trim().trim_start_matches(['#', '*', '_', '-', ' ']);
    let mut rest = strip(line, "unmet")?;
    rest = strip(rest, "launch-input")
        .or_else(|| strip(rest, "launch input"))
        .unwrap_or(rest);
    rest = strip(rest, "items")
        .or_else(|| strip(rest, "item"))
        .unwrap_or(rest);
    let rest = rest.trim_start_matches(['*', '_', ' ']);
    if !rest.is_empty() && !rest.starts_with(':') {
        return None;
    }
    Some(rest.trim_start_matches([':', '*', '_', ' ']))
}

/// One list line's text, without its bullet or number.
fn list_text(line: &str) -> &str {
    let line = line.trim();
    let digits = line.bytes().take_while(u8::is_ascii_digit).count();
    let numbered = matches!(line.as_bytes().get(digits), Some(b'.' | b')')) && digits > 0;
    let rest = match numbered {
        true => &line[digits + 1..],
        false => line
            .strip_prefix(['-', '*', '+', '\u{2022}'])
            .unwrap_or(line),
    };
    match rest.starts_with(char::is_whitespace) {
        true => rest.trim(),
        false => line,
    }
}

/// A markdown table whose heading names contacts (for example "Contacts" or
/// "Public contacts"), parsed as a table — a stray pipe is not a table.
fn contacts_table(body: &str) -> bool {
    let mut heading = String::new();
    let mut collecting = None::<String>;
    for event in markdown(body) {
        match event {
            Event::Start(Tag::Heading { .. }) => collecting = Some(String::new()),
            Event::Text(text) => {
                if let Some(pending) = collecting.as_mut() {
                    pending.push_str(&text);
                }
            }
            Event::End(TagEnd::Heading(_)) => {
                heading = collecting.take().unwrap_or_default().trim().to_lowercase();
            }
            Event::Start(Tag::Table(_))
                if heading.split_whitespace().any(|word| {
                    matches!(
                        word.trim_matches(|c: char| !c.is_alphanumeric()),
                        "contact" | "contacts"
                    )
                }) =>
            {
                return true;
            }
            _ => {}
        }
    }
    false
}

/// Whether the Typst source embeds one exported file in an `image(…)` call.
/// A filename in prose is not an embed.
fn source_embeds(source: &str, path: &str) -> bool {
    let relative = job_relative(path);
    source.match_indices("image(").any(|(at, _)| {
        let rest = source[at + "image(".len()..].trim_start();
        serde_json::Deserializer::from_str(rest)
            .into_iter::<String>()
            .next()
            .is_some_and(|target| target.is_ok_and(|target| job_relative(&target) == relative))
    })
}

/// A page of the report's own PDF, rasterised by `report.pages` into whatever directory the pod
/// chose: `page-<number>.<ext>` beside the `pages.json` receipt that run wrote. An inspection aid,
/// neither a figure nor evidence.
pub(crate) fn is_page_raster(file: &ExportedFile, files: &[ExportedFile]) -> bool {
    let numbered = file_name(&file.path)
        .strip_prefix("page-")
        .and_then(|rest| rest.rsplit_once('.'))
        .is_some_and(|(number, _)| {
            !number.is_empty() && number.bytes().all(|byte| byte.is_ascii_digit())
        });
    let receipt = match file.path.rsplit_once('/') {
        Some((directory, _)) => format!("{directory}/pages.json"),
        None => "pages.json".to_owned(),
    };
    numbered && files.iter().any(|other| other.path == receipt)
}

fn is_figure(file: &ExportedFile, files: &[ExportedFile]) -> bool {
    let name = file_name(&file.path);
    file.bytes > 0
        && !is_page_raster(file, files)
        && name.rsplit('.').next().is_some_and(|extension| {
            ["png", "jpg", "jpeg", "webp", "gif", "svg"]
                .iter()
                .any(|kind| extension.eq_ignore_ascii_case(kind))
        })
}

fn is_evidence(file: &ExportedFile, files: &[ExportedFile], report_pdf: Option<&str>) -> bool {
    if file.bytes == 0 || is_figure(file, files) {
        return false;
    }
    let name = file_name(&file.path);
    if matches!(
        name,
        "run-stats.json"
            | "report-render.json"
            | "report-review.json"
            | "report-delivered.json"
            | "report-copies.json"
            | "report-settlement.json"
            | "pages.json"
            | "report.md"
    ) || name.ends_with(".typ")
        || name.starts_with("page-")
    {
        return false;
    }
    report_pdf != Some(file.path.as_str()) && report_pdf != Some(name)
}

fn file_name(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

/// Stages the settled answer as Typst content the research template wraps.
/// Figures resolve against the run's export; one that does not is named on
/// the page. The caller compiles this with `docs::render::research`.
pub(crate) fn complete_fallback_source(
    answer: &str,
    files: &[ExportedFile],
) -> Result<String, String> {
    let source = fallback_typst(answer, files);
    if source.len() > MAX_SOURCE_BYTES {
        return Err(format!(
            "the settled answer is {} bytes of Typst, over the {MAX_SOURCE_BYTES}-byte source \
             bound",
            source.len()
        ));
    }
    Ok(source)
}

/// The export-relative figure files the settled source embeds by name.
pub(crate) fn embedded_figures<'a>(
    source: &str,
    files: &'a [ExportedFile],
) -> Vec<&'a ExportedFile> {
    files
        .iter()
        .filter(|file| is_figure(file, files) && source_embeds(source, &file.path))
        .collect()
}

pub(crate) fn run_tool(
    exec: &dyn PodWorkerExec,
    run: &RunId,
    argv: &[&str],
    stdin: Option<&[u8]>,
    what: &str,
) -> Result<(), String> {
    run_tool_output(exec, run, argv, stdin, TOOL_TAIL, what).map(|_| ())
}

/// The same in-pod call, keeping the stdout the caller asked for. A short
/// read is a failure: a truncated page is not a viewed page.
pub(crate) fn run_tool_output(
    exec: &dyn PodWorkerExec,
    run: &RunId,
    argv: &[&str],
    stdin: Option<&[u8]>,
    tail: usize,
    what: &str,
) -> Result<odin_omp::host_tools::pod_exec::WorkerOutput, String> {
    let argv: Vec<String> = argv.iter().copied().map(str::to_owned).collect();
    let output = exec
        .exec(run, &argv, stdin, TOOL_WAIT, tail)
        .map_err(|fault| match fault {
            WorkerExecFault::NotStarted(reason) | WorkerExecFault::Unknown(reason) => reason,
        })?;
    if output.exit_code != 0 {
        return Err(format!(
            "{what} exited {}: {}",
            output.exit_code,
            String::from_utf8_lossy(&output.stderr_tail).trim()
        ));
    }
    Ok(output)
}

fn markdown(markdown: &str) -> Parser<'_> {
    let mut options = Options::empty();
    options.insert(Options::ENABLE_TABLES);
    options.insert(Options::ENABLE_STRIKETHROUGH);
    options.insert(Options::ENABLE_FOOTNOTES);
    options.insert(Options::ENABLE_TASKLISTS);
    Parser::new_ext(markdown, options)
}

/// The Typst content for the settled answer. The research template supplies
/// the phone page, type and footer; this body never sets its own page.
pub(crate) fn fallback_typst(answer: &str, files: &[ExportedFile]) -> String {
    let mut document = String::from(
        "// Completed by Odin from the run's settled answer; the pod rendered no PDF.\n",
    );
    let events = markdown(answer);
    emit_blocks(&mut events.peekable(), &mut document, files, 0, None);
    document
}

/// Emits block events until `stop` (or the end). Every text run passes through
/// [`string`] so the answer's content is never markup.
fn emit_blocks(
    events: &mut std::iter::Peekable<Parser<'_>>,
    document: &mut String,
    files: &[ExportedFile],
    depth: usize,
    stop: Option<TagEnd>,
) {
    while let Some(event) = events.next() {
        match event {
            Event::Start(Tag::Paragraph) => {
                inline_into(events, document, files, TagEnd::Paragraph);
                document.push_str("\n\n");
            }
            Event::Start(Tag::Heading { level, .. }) => {
                let marks = "=".repeat(heading_depth(level));
                document.push_str(&marks);
                document.push(' ');
                inline_into(events, document, files, TagEnd::Heading(level));
                document.push_str("\n\n");
            }
            Event::Start(Tag::BlockQuote(kind)) => {
                document.push_str("#quote(block: true)[");
                emit_blocks(
                    events,
                    document,
                    files,
                    depth,
                    Some(TagEnd::BlockQuote(kind)),
                );
                document.push_str("]\n\n");
            }
            Event::Start(Tag::CodeBlock(kind)) => {
                code_block(events, document, kind);
            }
            Event::Start(Tag::HtmlBlock) => {
                html_block(events, document);
            }
            Event::Start(Tag::List(start)) => {
                list(events, document, files, depth, start.is_some());
            }
            Event::Start(Tag::Table(_)) => {
                table(events, document, files);
            }
            Event::Rule => document.push_str("#line(length: 100%)\n\n"),
            Event::Start(
                tag @ (Tag::Emphasis | Tag::Strong | Tag::Strikethrough | Tag::Link { .. }),
            ) => {
                stray_inline(events, document, files, tag);
                document.push_str("\n\n");
            }
            Event::Start(Tag::Image { dest_url, .. }) => {
                let alt = plain_alt(events, TagEnd::Image);
                document.push_str(&figure(dest_url.as_ref(), &alt, files));
                document.push_str("\n\n");
            }
            Event::Start(Tag::FootnoteDefinition(label)) => {
                document.push_str(&format!("#text({}) ", string(&format!("[{label}]"))));
                emit_blocks(
                    events,
                    document,
                    files,
                    depth,
                    Some(TagEnd::FootnoteDefinition),
                );
            }
            Event::Start(Tag::MetadataBlock(_)) => skip_metadata(events),
            Event::Start(tag) => {
                emit_blocks(events, document, files, depth, Some(tag.to_end()));
                document.push_str("\n\n");
            }
            Event::End(end) if Some(end) == stop => return,
            Event::End(_) => {}
            Event::Text(_)
            | Event::Code(_)
            | Event::InlineHtml(_)
            | Event::Html(_)
            | Event::InlineMath(_)
            | Event::DisplayMath(_)
            | Event::FootnoteReference(_)
            | Event::SoftBreak
            | Event::HardBreak
            | Event::TaskListMarker(_) => {
                let mut paragraph = String::new();
                render_inline(events, &event, &mut paragraph, files);
                while events.peek().is_some_and(is_scalar_inline) {
                    if let Some(next) = events.next() {
                        render_inline(events, &next, &mut paragraph, files);
                    }
                }
                document.push_str(&paragraph);
                document.push_str("\n\n");
            }
        }
    }
}

fn skip_until(events: &mut std::iter::Peekable<Parser<'_>>, end: TagEnd) {
    let mut depth = 1u32;
    for event in events.by_ref() {
        match event {
            Event::Start(_) => depth += 1,
            Event::End(ended) if ended == end => {
                depth -= 1;
                if depth == 0 {
                    return;
                }
            }
            Event::End(_) => depth = depth.saturating_sub(1),
            _ => {}
        }
    }
}

fn skip_metadata(events: &mut std::iter::Peekable<Parser<'_>>) {
    let mut depth = 1u32;
    for event in events.by_ref() {
        match event {
            Event::Start(Tag::MetadataBlock(_)) => depth += 1,
            Event::End(TagEnd::MetadataBlock(_)) if depth == 1 => return,
            Event::End(TagEnd::MetadataBlock(_)) => depth -= 1,
            _ => {}
        }
    }
}

fn is_scalar_inline(event: &Event<'_>) -> bool {
    matches!(
        event,
        Event::Text(_)
            | Event::Code(_)
            | Event::InlineHtml(_)
            | Event::Html(_)
            | Event::InlineMath(_)
            | Event::DisplayMath(_)
            | Event::FootnoteReference(_)
            | Event::SoftBreak
            | Event::HardBreak
            | Event::TaskListMarker(_)
    )
}

/// Renders one scalar inline event, then any inline starts it introduces.
fn render_inline(
    events: &mut std::iter::Peekable<Parser<'_>>,
    event: &Event<'_>,
    out: &mut String,
    files: &[ExportedFile],
) {
    match event {
        Event::Text(text) => out.push_str(&text_call(text)),
        Event::Code(code) => out.push_str(&format!("#raw({})", string(code))),
        Event::InlineMath(math) | Event::DisplayMath(math) => {
            out.push_str(&text_call(&format!("${math}$")))
        }
        Event::FootnoteReference(label) => out.push_str(&text_call(&format!("[{label}]"))),
        Event::SoftBreak => out.push(' '),
        Event::HardBreak => out.push_str("#linebreak() "),
        Event::Html(text) | Event::InlineHtml(text) => out.push_str(&text_call(text)),
        Event::TaskListMarker(checked) => out.push_str(if *checked {
            "#text(\"[x] \")"
        } else {
            "#text(\"[ ] \")"
        }),
        Event::Start(Tag::Emphasis) => wrap(events, out, files, TagEnd::Emphasis, "#emph"),
        Event::Start(Tag::Strong) => wrap(events, out, files, TagEnd::Strong, "#strong"),
        Event::Start(Tag::Strikethrough) => {
            wrap(events, out, files, TagEnd::Strikethrough, "#strike")
        }
        Event::Start(Tag::Link { dest_url, .. }) => {
            out.push_str(&format!("#link({})[", string(dest_url)));
            inline_into(events, out, files, TagEnd::Link);
            out.push(']');
        }
        Event::Start(Tag::Image { dest_url, .. }) => {
            let alt = plain_alt(events, TagEnd::Image);
            out.push_str(&figure(dest_url.as_ref(), &alt, files));
        }
        _ => {}
    }
}

/// One inline span: its inner content, as a content argument of `op`.
fn wrap(
    events: &mut std::iter::Peekable<Parser<'_>>,
    out: &mut String,
    files: &[ExportedFile],
    end: TagEnd,
    op: &str,
) {
    out.push_str(op);
    out.push('[');
    inline_into(events, out, files, end);
    out.push(']');
}

fn inline_into(
    events: &mut std::iter::Peekable<Parser<'_>>,
    out: &mut String,
    files: &[ExportedFile],
    end: TagEnd,
) {
    while let Some(event) = events.next() {
        match event {
            Event::End(ended) if ended == end => return,
            Event::End(_) => {}
            Event::Start(
                Tag::Emphasis
                | Tag::Strong
                | Tag::Strikethrough
                | Tag::Link { .. }
                | Tag::Image { .. },
            )
            | Event::Text(_)
            | Event::Code(_)
            | Event::InlineHtml(_)
            | Event::Html(_)
            | Event::InlineMath(_)
            | Event::DisplayMath(_)
            | Event::FootnoteReference(_)
            | Event::SoftBreak
            | Event::HardBreak
            | Event::TaskListMarker(_) => render_inline(events, &event, out, files),
            Event::Start(other) => inline_into(events, out, files, other.to_end()),
            Event::Rule => out.push_str("#line(length: 100%)"),
        }
    }
}

/// An image's plain alt text: its inner text runs only.
fn plain_alt(events: &mut std::iter::Peekable<Parser<'_>>, end: TagEnd) -> String {
    let mut alt = String::new();
    for event in events.by_ref() {
        match event {
            Event::Text(text) => alt.push_str(&text),
            Event::End(ended) if ended == end => break,
            _ => {}
        }
    }
    alt
}

/// One figure: the exported file when the run saved it, otherwise a named
/// placeholder on the page. Never silence, never a guessed local path.
fn figure(target: &str, alt: &str, files: &[ExportedFile]) -> String {
    match resolve_figure(files, target) {
        Ok(Some(path)) => format!(
            "#figure(image({}, width: 100%), caption: [#text({})])",
            string(&path),
            string(alt)
        ),
        Ok(None) => named_missing(target, alt),
        Err(reason) => named_missing(&format!("{target} ({reason})"), alt),
    }
}

fn named_missing(target: &str, alt: &str) -> String {
    format!(
        "#figure(rect(width: 100%, inset: 6pt, stroke: 0.5pt + link-ink)[#text(\
         fill: link-ink, size: 0.85em, {})], caption: [#text({})])",
        string(&format!(
            "Figure not embedded: {target}. The file is not in this run's export; see the \
             evidence appendix."
        )),
        string(alt)
    )
}

/// The job-relative path of a saved figure. An exact export path keeps its
/// directories. A bare name matches only when one export file has that name.
fn resolve_figure(files: &[ExportedFile], target: &str) -> Result<Option<String>, String> {
    let relative = target.strip_prefix("/export/").unwrap_or(target);
    if !safe_relative(relative) {
        return Err("the figure path leaves the export".to_owned());
    }
    if files
        .iter()
        .any(|file| is_figure(file, files) && file.path == relative)
    {
        return Ok(Some(relative.to_owned()));
    }
    if relative.contains('/') {
        return Ok(None);
    }
    let named: Vec<&ExportedFile> = files
        .iter()
        .filter(|file| is_figure(file, files) && file_name(&file.path) == relative)
        .collect();
    match named.as_slice() {
        [only] => Ok(Some(only.path.clone())),
        [] => Ok(None),
        _ => Err(format!("more than one export file is named {relative}")),
    }
}

pub(crate) fn job_relative(path: &str) -> String {
    path.strip_prefix("/export/").unwrap_or(path).to_owned()
}

pub(crate) fn safe_relative(path: &str) -> bool {
    !path.is_empty()
        && !path.starts_with('/')
        && !path.contains('\0')
        && !path
            .split('/')
            .any(|part| part.is_empty() || matches!(part, "." | ".."))
}

/// A stray inline start outside any block: render it as its own paragraph.
fn stray_inline(
    events: &mut std::iter::Peekable<Parser<'_>>,
    document: &mut String,
    files: &[ExportedFile],
    tag: Tag<'_>,
) {
    match tag {
        Tag::Emphasis => wrap(events, document, files, TagEnd::Emphasis, "#emph"),
        Tag::Strong => wrap(events, document, files, TagEnd::Strong, "#strong"),
        Tag::Strikethrough => wrap(events, document, files, TagEnd::Strikethrough, "#strike"),
        Tag::Link { dest_url, .. } => {
            document.push_str(&format!("#link({})[", string(&dest_url)));
            inline_into(events, document, files, TagEnd::Link);
            document.push(']');
        }
        _ => {}
    }
}

/// One HTML block stays literal text: the renderer draws it, it never runs.
fn html_block(events: &mut std::iter::Peekable<Parser<'_>>, document: &mut String) {
    for event in events.by_ref() {
        match event {
            Event::Html(text) | Event::InlineHtml(text) | Event::Text(text) => {
                document.push_str(&text_call(&text));
                document.push('\n');
            }
            Event::End(TagEnd::HtmlBlock) => break,
            _ => {}
        }
    }
    document.push('\n');
}

fn code_block(
    events: &mut std::iter::Peekable<Parser<'_>>,
    document: &mut String,
    kind: CodeBlockKind<'_>,
) {
    let mut code = String::new();
    for event in events.by_ref() {
        match event {
            Event::Text(text) => code.push_str(&text),
            Event::End(TagEnd::CodeBlock) => break,
            _ => {}
        }
    }
    let marker = "`".repeat(code.chars().filter(|c| *c == '`').count().max(1) + 2);
    let tag = match &kind {
        CodeBlockKind::Fenced(info) => info.split_whitespace().next().unwrap_or_default(),
        CodeBlockKind::Indented => "",
    };
    let safe = if tag
        .chars()
        .all(|character| character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '+'))
    {
        tag
    } else {
        ""
    };
    document.push_str(&marker);
    document.push_str(safe);
    document.push('\n');
    document.push_str(code.trim_end_matches('\n'));
    document.push('\n');
    document.push_str(&marker);
    document.push_str("\n\n");
}

fn list(
    events: &mut std::iter::Peekable<Parser<'_>>,
    document: &mut String,
    files: &[ExportedFile],
    depth: usize,
    ordered: bool,
) {
    let marker = if ordered { "+" } else { "-" };
    let indent = "  ".repeat(depth);
    while let Some(event) = events.next() {
        match event {
            Event::Start(Tag::Item) => {
                document.push_str(&indent);
                document.push_str(marker);
                document.push(' ');
                item(events, document, files, depth);
                document.push('\n');
            }
            Event::End(TagEnd::List(_)) => return,
            _ => {}
        }
    }
}

/// One list item: its inline content, and any nested list under it.
fn item(
    events: &mut std::iter::Peekable<Parser<'_>>,
    document: &mut String,
    files: &[ExportedFile],
    depth: usize,
) {
    while let Some(event) = events.next() {
        match event {
            Event::Start(Tag::Paragraph) => {
                inline_into(events, document, files, TagEnd::Paragraph);
            }
            Event::Start(Tag::List(start)) => {
                document.push('\n');
                list(events, document, files, depth + 1, start.is_some());
            }
            Event::End(TagEnd::Item) => return,
            Event::Text(_)
            | Event::Code(_)
            | Event::InlineHtml(_)
            | Event::Html(_)
            | Event::InlineMath(_)
            | Event::DisplayMath(_)
            | Event::FootnoteReference(_)
            | Event::SoftBreak
            | Event::HardBreak
            | Event::TaskListMarker(_)
            | Event::Start(
                Tag::Emphasis
                | Tag::Strong
                | Tag::Strikethrough
                | Tag::Link { .. }
                | Tag::Image { .. },
            ) => render_inline(events, &event, document, files),
            Event::Start(other) => skip_until(events, other.to_end()),
            Event::Rule => document.push_str("#line(length: 100%)"),
            Event::End(_) => {}
        }
    }
}

fn table(
    events: &mut std::iter::Peekable<Parser<'_>>,
    document: &mut String,
    files: &[ExportedFile],
) {
    let mut rows: Vec<Vec<String>> = Vec::new();
    while let Some(event) = events.next() {
        match event {
            Event::Start(tag @ (Tag::TableHead | Tag::TableRow)) => {
                rows.push(table_row(events, files, tag.to_end()));
            }
            Event::End(TagEnd::Table) => break,
            _ => {}
        }
    }
    let columns = rows.iter().map(Vec::len).max().unwrap_or(0);
    if columns == 0 {
        return;
    }
    writeln!(document, "#table(columns: {columns},").expect("String formatting");
    for cells in &rows {
        for column in 0..columns {
            let cell = cells.get(column).map(String::as_str).unwrap_or_default();
            writeln!(document, "  [{cell}],").expect("String formatting");
        }
    }
    document.push_str(")\n\n");
}

fn table_row(
    events: &mut std::iter::Peekable<Parser<'_>>,
    files: &[ExportedFile],
    end: TagEnd,
) -> Vec<String> {
    let mut cells = Vec::new();
    while let Some(event) = events.next() {
        match event {
            Event::Start(Tag::TableCell) => {
                let mut cell = String::new();
                inline_into(events, &mut cell, files, TagEnd::TableCell);
                cells.push(cell);
            }
            Event::End(finished) if finished == end => return cells,
            _ => {}
        }
    }
    cells
}

fn heading_depth(level: pulldown_cmark::HeadingLevel) -> usize {
    match level {
        pulldown_cmark::HeadingLevel::H1 => 1,
        pulldown_cmark::HeadingLevel::H2 => 2,
        pulldown_cmark::HeadingLevel::H3 => 3,
        pulldown_cmark::HeadingLevel::H4 => 4,
        pulldown_cmark::HeadingLevel::H5 => 5,
        pulldown_cmark::HeadingLevel::H6 => 6,
    }
}

fn text_call(text: &str) -> String {
    format!("#text({})", string(text))
}

/// A Typst string literal: `\\`, `\"` and control characters escaped, so any
/// page or tool output renders as text and never as markup.
fn string(text: &str) -> String {
    let mut out = String::with_capacity(text.len() + 2);
    out.push('"');
    for character in text.chars() {
        match character {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            control if (control as u32) < 0x20 || control as u32 == 0x7f => {
                out.push_str(&format!("\\u{{{:x}}}", control as u32));
            }
            other => out.push(other),
        }
    }
    out.push('"');
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn exported(path: &str, bytes: u64) -> ExportedFile {
        ExportedFile {
            path: path.to_owned(),
            bytes,
            content: Ok(Vec::new()),
        }
    }

    #[test]
    fn the_contract_uses_the_receipt_and_refuses_tampered_pdf_bytes() {
        assert!(matches!(
            report_contract(&[], "/export", true, false),
            ReportCompletion::Unmet(_)
        ));
        assert!(matches!(
            report_contract(&[], "/export", false, true),
            ReportCompletion::Unmet(_)
        ));
        let receipt = serde_json::json!({
            "source": "/export/report.typ",
            "output": "/export/custom-final.pdf",
            "page_count": 1,
            "bytes": 10,
            "content": odin_domain::Digest::hash(b"source").to_string(),
            "body": odin_domain::Digest::hash(b"").to_string(),
            "pdf": odin_domain::Digest::hash(b"0123456789").to_string(),
            "capturedAt": "2026-10-28T00:00:00Z",
            "stats": "/export/run-stats.json",
        });
        let mut files = vec![
            ExportedFile {
                path: "report-render.json".to_owned(),
                bytes: 80,
                content: Ok(serde_json::to_vec(&receipt).expect("receipt")),
            },
            ExportedFile {
                path: "custom-final.pdf".to_owned(),
                bytes: 10,
                content: Ok(b"0123456789".to_vec()),
            },
            exported("annual-report.pdf", 40),
        ];
        assert!(matches!(
            report_contract(&files, "/export", false, false),
            ReportCompletion::Met(identity) if identity.pdf_relative == "custom-final.pdf"
        ));
        files[1].content = Ok(b"9876543210".to_vec());
        assert_eq!(
            report_contract(&files, "/export", false, false),
            ReportCompletion::Owed
        );
        assert!(matches!(
            report_contract(&files, "/export", true, false),
            ReportCompletion::Unmet(_)
        ));
        assert_eq!(
            report_contract(
                &[exported("annual-report.pdf", 40)],
                "/export",
                false,
                false
            ),
            ReportCompletion::Owed
        );
    }

    #[test]
    fn a_final_answer_names_what_it_left_unmet() {
        let answer = "## Findings\n\nAcecare lists a 6.8 L cylinder.\n\n## Unmet items\n\n\
                      - Nine manufacturers: read, browser and Wayback all answered 403\n\
                      2. DOT-SP 21259 grantee: the PHMSA PDF is blocked, no archive copy\n\n\
                      ## Sources\n\n- https://example.com";
        assert_eq!(
            unmet_items(answer),
            [
                "Nine manufacturers: read, browser and Wayback all answered 403",
                "DOT-SP 21259 grantee: the PHMSA PDF is blocked, no archive copy"
            ]
        );
        assert_eq!(
            unmet_items("Done.\n\n**Unmet items:** the price table, the contact email"),
            ["the price table, the contact email"]
        );
        assert!(unmet_items("Done.\nUnmet items: none").is_empty());
        assert!(
            unmet_items("## Unmet items\n- a price\n\nMore work.\n\n## Unmet items\nNone.")
                .is_empty()
        );
        assert!(
            unmet_items("Unmet demand for aerogel is high.\nUnmet needs differ.").is_empty(),
            "a sentence about unmet demand is no list of unmet items"
        );
    }
}
