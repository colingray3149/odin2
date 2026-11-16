//! Documents: render Markdown or Typst to a PDF with page images, convert between
//! formats, show any document's pages, and make scans searchable. Each call works
//! in its own scratch folder; the PDFs and files it lists become shared artifacts.
mod convert;
mod ocr;
mod preview;
pub mod render;
#[cfg(test)]
mod tests;

use std::path::{Path, PathBuf};
use std::time::Duration;

use serde_json::Value;

use crate::sandbox::{Net, Sandbox};
use crate::{args, cause, Call, Ctx, Failure, Workflow, MAX_PREVIEWS, SCRATCH_ROOT};

/// The declared root holding `theme.typ`, the palette the templates print in.
const THEME_ROOT: &str = "docs-theme";

pub const WORKFLOWS: &[Workflow] = &[
    Workflow {
        capability: "docs.convert",
        run: convert::run,
        plan: None,
        executables: &["pandoc", "soffice", "typst", "pdfinfo", "file"],
        roots: &[SCRATCH_ROOT, THEME_ROOT],
        secrets: &[],
        endpoints: &[],
    },
    Workflow {
        capability: "docs.ocr",
        run: ocr::run,
        plan: None,
        executables: &["ocrmypdf", "pdfinfo", "file"],
        roots: &[SCRATCH_ROOT],
        secrets: &[],
        endpoints: &[],
    },
    Workflow {
        capability: "docs.preview",
        run: preview::run,
        plan: None,
        executables: &["pdftoppm", "pdfinfo", "soffice", "file"],
        roots: &[SCRATCH_ROOT],
        secrets: &[],
        endpoints: &[],
    },
    Workflow {
        capability: "docs.render",
        run: render::run,
        plan: None,
        executables: &["typst", "pandoc", "pdfinfo", "pdftoppm"],
        roots: &[SCRATCH_ROOT, THEME_ROOT],
        secrets: &[],
        endpoints: &[],
    },
];

const POPPLER_LIMIT: Duration = Duration::from_secs(60);
const OFFICE_LIMIT: Duration = Duration::from_secs(180);
/// One pandoc run, whether it converts a document or feeds the typst template.
const PANDOC_LIMIT: Duration = Duration::from_secs(120);
/// Page images are drawn at this resolution: readable text at a small size.
const PREVIEW_PPI: &str = "110";
/// The longest output file name stem.
const MAX_NAME_CHARS: usize = 60;
/// LibreOffice logs every internal warning on stderr unless told otherwise.
const OFFICE_QUIET: (&str, &str) = ("SAL_LOG", "-WARN-INFO");

/// pandoc's exit codes (pandoc(1), "EXIT CODES", 3.7).
pub(super) const PANDOC_CODES: &[(i32, &str)] = &[
    (1, "pandoc could not read or write a file"),
    (
        5,
        "pandoc's template failed; this is an Odin bug in pandoc.typst",
    ),
    (21, "pandoc does not know the input format"),
    (22, "pandoc does not know the output format"),
    (
        24,
        "a citation could not be resolved; check the key exists in refs.bib",
    ),
    (25, "the bibliography could not be read"),
    (64, "pandoc could not parse the input"),
    (92, "the input is not valid UTF-8 text"),
    (93, "the notebook is not valid ipynb JSON"),
    (
        99,
        "a referenced image or file was not found; pass it in artifacts",
    ),
];

/// LibreOffice exits 1 even when it converted; the output file is the proof.
const OFFICE_CAUSES: &[(&str, &str)] = &[
    (
        "source file could not be loaded",
        "LibreOffice could not open the file (damaged, password-protected or not an office document)",
    ),
    ("impl_store", "LibreOffice could not write the converted file"),
    ("filter for", "LibreOffice has no converter from this file to that format"),
];

/// pdftoppm(1) "EXIT CODES".
const POPPLER_CODES: &[(i32, &str)] = &[
    (1, "the PDF could not be opened (damaged or not a PDF)"),
    (2, "the page image could not be written"),
    (3, "the PDF is password-protected"),
    (99, "pdftoppm failed"),
];

/// Formats by MIME type, for files whose name carries no known extension.
const MIME_KINDS: &[(&str, &str)] = &[
    ("application/pdf", "pdf"),
    ("text/html", "html"),
    ("text/plain", "md"),
    ("text/markdown", "md"),
    ("application/json", "ipynb"),
    ("application/epub+zip", "epub"),
    ("application/rtf", "rtf"),
    ("text/rtf", "rtf"),
    ("application/msword", "doc"),
    ("application/vnd.ms-excel", "xls"),
    ("application/vnd.ms-powerpoint", "ppt"),
    (
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        "docx",
    ),
    (
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        "xlsx",
    ),
    (
        "application/vnd.openxmlformats-officedocument.presentationml.presentation",
        "pptx",
    ),
    ("application/vnd.oasis.opendocument.text", "odt"),
    ("application/vnd.oasis.opendocument.spreadsheet", "ods"),
    ("application/vnd.oasis.opendocument.presentation", "odp"),
    ("image/png", "png"),
    ("image/jpeg", "jpg"),
    ("image/tiff", "tiff"),
];

/// Extensions taken at their word.
const KNOWN_KINDS: &[&str] = &[
    "md", "markdown", "txt", "typ", "html", "htm", "pdf", "docx", "odt", "doc", "rtf", "pptx",
    "ppt", "xlsx", "xls", "ods", "odp", "ipynb", "epub", "png", "jpg", "jpeg", "tif", "tiff",
];

/// Office formats LibreOffice opens.
pub(super) const OFFICE_KINDS: &[&str] = &[
    "docx", "odt", "doc", "rtf", "pptx", "ppt", "xlsx", "xls", "ods", "odp",
];

/// Whether `name` is an office document LibreOffice renders to PDF.
pub fn is_office(name: &str) -> bool {
    Path::new(name).extension().is_some_and(|extension| {
        OFFICE_KINDS.contains(&extension.to_string_lossy().to_ascii_lowercase().as_str())
    })
}

/// A PDF of an office document, made the way docs.convert makes one, for a send
/// that carries both (files send, files drop): written into `out`, with its page count.
pub fn office_pdf(ctx: &Ctx, input: &Path, out: &Path) -> Result<(PathBuf, u32), Failure> {
    std::fs::create_dir_all(out).map_err(|error| {
        Failure::unavailable(format!("could not create {}: {error}", out.display()))
    })?;
    let pdf = office(ctx, input, "pdf", out)?;
    let pages = page_count(ctx, &pdf)?;
    Ok((pdf, pages))
}

/// Refuses bytes that are not the file `name` says they are, before a send
/// (files send, files drop): a spilled tool result (a JSON object carrying
/// `artifact`) under any name, or an office, PDF or image extension whose magic
/// bytes do not match. `what` names the source in the cause. Unknown extensions pass.
pub fn check_send(what: &str, name: &str, bytes: &[u8]) -> Result<(), String> {
    let extension = Path::new(name)
        .extension()
        .map(|extension| extension.to_string_lossy().to_ascii_lowercase())
        .unwrap_or_default();
    if bytes.trim_ascii_start().starts_with(b"{") {
        let result = serde_json::from_slice::<Value>(bytes).ok();
        if result.is_some_and(|value| value.get("artifact").is_some()) {
            let kind = if extension.is_empty() {
                "file".to_owned()
            } else {
                format!(".{extension} file")
            };
            return Err(format!(
                "{what} is a tool result (JSON), not a {kind}; send the result's `artifact` field"
            ));
        }
    }
    let fits = match extension.as_str() {
        "docx" | "xlsx" | "pptx" | "odt" | "ods" | "odp" => bytes.starts_with(b"PK\x03\x04"),
        "doc" | "xls" | "ppt" => bytes.starts_with(&[0xd0, 0xcf, 0x11, 0xe0]),
        "pdf" => bytes.starts_with(b"%PDF"),
        "png" => bytes.starts_with(b"\x89PNG"),
        "jpg" | "jpeg" => bytes.starts_with(&[0xff, 0xd8, 0xff]),
        "gif" => bytes.starts_with(b"GIF8"),
        "webp" => bytes.starts_with(b"RIFF") && bytes.get(8..12) == Some(b"WEBP"),
        _ => true,
    };
    if fits {
        Ok(())
    } else {
        Err(format!(
            "{what} is not a .{extension} file: its bytes do not start like one"
        ))
    }
}

/// [`check_send`] for a file on disk: reads its head, and all of it only when it
/// may be a JSON tool result.
pub fn check_send_file(what: &str, name: &str, path: &Path) -> Result<(), String> {
    use std::io::Read;
    let mut head = Vec::new();
    std::fs::File::open(path)
        .and_then(|file| file.take(16).read_to_end(&mut head))
        .map_err(|error| format!("{what} is unreadable: {error}"))?;
    if head.trim_ascii_start().starts_with(b"{") {
        head = std::fs::read(path).map_err(|error| format!("{what} is unreadable: {error}"))?;
    }
    check_send(what, name, &head)
}

/// The one document a call names.
pub(super) enum Doc {
    /// Inline `source` text.
    Text(String),
    /// The staged `artifact` or `intake` file.
    File(PathBuf),
}

/// The document and the staged `artifacts`, read back from `call.files`. Glue
/// stages artifact, artifacts, intake, asset, then `reference` last. `reference`
/// is counted so the lengths match, and it is never the source. `fields` are the
/// document fields the op takes, for the message when not exactly one is given.
pub(super) fn inputs<'a>(
    call: &'a Call,
    args: &Value,
    fields: &[&str],
) -> Result<(Doc, &'a [PathBuf]), Failure> {
    let given = |field: &str| args::opt_str(args, field).is_some();
    let (artifact, intake) = (given("artifact"), given("intake"));
    let source = args::opt_str(args, "source");
    if fields.iter().filter(|field| given(field)).count() != 1 {
        return Err(Failure::arguments(format!(
            "give exactly one of {}",
            fields.join(", ")
        )));
    }
    let extra = args::strs(args, "artifacts").len();
    let reference = usize::from(given("reference"));
    let expected = usize::from(artifact) + extra + usize::from(intake) + reference;
    if call.files.len() != expected {
        return Err(Failure::unavailable(format!(
            "the call names {expected} input files but {} were staged",
            call.files.len()
        )));
    }
    let body = &call.files[..call.files.len() - reference];
    let first = usize::from(artifact);
    let doc = match source {
        Some(text) => Doc::Text(text.to_owned()),
        None if artifact => Doc::File(body[0].clone()),
        None => Doc::File(body[body.len() - 1].clone()),
    };
    Ok((doc, &body[first..first + extra]))
}

/// The file's format: its extension when known, else what `file` says it is.
pub(super) fn kind(ctx: &Ctx, path: &Path) -> Result<String, Failure> {
    let extension = path
        .extension()
        .map(|extension| extension.to_string_lossy().to_ascii_lowercase())
        .unwrap_or_default();
    if KNOWN_KINDS.contains(&extension.as_str()) {
        return Ok(match extension.as_str() {
            "markdown" | "txt" => "md".to_owned(),
            "htm" => "html".to_owned(),
            "jpeg" => "jpg".to_owned(),
            "tif" => "tiff".to_owned(),
            _ => extension,
        });
    }
    let mime = crate::quarantine::sniff_mime(ctx, path)?;
    MIME_KINDS
        .iter()
        .find(|(known, _)| *known == mime)
        .map(|(_, kind)| (*kind).to_owned())
        .ok_or_else(|| {
            Failure::arguments(format!(
                "{} is {mime}, which is not a document format docs reads",
                file_name(path)
            ))
        })
}

/// `path` when its extension is `kind`; otherwise a copy in `job` that carries it,
/// since LibreOffice and pandoc pick their reader by extension.
pub(super) fn with_extension(path: &Path, kind: &str, job: &Path) -> Result<PathBuf, Failure> {
    if path.extension().is_some_and(|extension| extension == kind) {
        return Ok(path.to_path_buf());
    }
    let stem = path
        .file_stem()
        .map_or_else(|| "input".into(), |stem| stem.to_string_lossy());
    let copy = job.join(format!("{stem}.{kind}"));
    render::copy_into(path, &copy).map_err(|error| {
        Failure::unavailable(format!("could not copy {}: {error}", file_name(path)))
    })?;
    Ok(copy)
}

/// An output file name: `base` lowercased to letters, digits and dashes, at most
/// 60 characters, never empty, plus `.ext`.
pub(super) fn output_name(base: &str, ext: &str) -> String {
    let mut stem = String::new();
    for c in base.chars().flat_map(char::to_lowercase) {
        if c.is_ascii_alphanumeric() {
            stem.push(c);
        } else if !stem.ends_with('-') && !stem.is_empty() {
            stem.push('-');
        }
    }
    let stem: String = stem.chars().take(MAX_NAME_CHARS).collect();
    let stem = stem.trim_end_matches('-');
    format!("{}.{ext}", if stem.is_empty() { "document" } else { stem })
}

pub(super) use crate::paths::file_name;

pub(super) fn file_stem(path: &Path) -> String {
    path.file_stem()
        .map_or_else(String::new, |stem| stem.to_string_lossy().into_owned())
}

pub(super) fn bytes(path: &Path) -> u64 {
    std::fs::metadata(path).map_or(0, |meta| meta.len())
}

/// "412 KB" or "1.3 MB".
pub(super) fn size(bytes: u64) -> String {
    const KB: u64 = 1024;
    if bytes < KB * KB {
        format!("{} KB", bytes.div_ceil(KB))
    } else {
        format!("{:.1} MB", bytes as f64 / (KB * KB) as f64)
    }
}

/// The PDF's page count, from `pdfinfo`.
pub(super) fn page_count(ctx: &Ctx, pdf: &Path) -> Result<u32, Failure> {
    let spec = Sandbox::new(ctx, "pdfinfo")?
        .arg(pdf)
        .ro(pdf)
        .net(Net::None)
        .timeout(POPPLER_LIMIT)
        .build();
    let out = ctx.run(&spec)?;
    if let Some(failure) = cause::failure("pdfinfo", &[], POPPLER_CODES, &out, POPPLER_LIMIT) {
        return Err(failure);
    }
    out.stdout_text()
        .lines()
        .find_map(|line| line.strip_prefix("Pages:"))
        .and_then(|count| count.trim().parse().ok())
        .ok_or_else(|| Failure::upstream("pdfinfo found no page count; the PDF may be damaged"))
}

/// The requested pages (1-based; `[1]` by default) that exist, at most four, and a
/// note naming the ones that do not.
pub(super) fn pick_pages(args: &Value, count: u32) -> (Vec<u32>, Option<String>) {
    let mut wanted: Vec<u32> = args
        .get("pages")
        .and_then(Value::as_array)
        .map(|pages| {
            pages
                .iter()
                .filter_map(Value::as_u64)
                .filter_map(|page| u32::try_from(page).ok())
                .collect()
        })
        .unwrap_or_default();
    if wanted.is_empty() {
        wanted.push(1);
    }
    wanted.sort_unstable();
    wanted.dedup();
    let (kept, missing): (Vec<u32>, Vec<u32>) = wanted
        .into_iter()
        .partition(|page| (1..=count).contains(page));
    let note = (!missing.is_empty()).then(|| {
        let names: Vec<String> = missing.iter().map(u32::to_string).collect();
        format!(
            "page {} does not exist; the document has {count} pages",
            names.join(", ")
        )
    });
    (kept.into_iter().take(MAX_PREVIEWS).collect(), note)
}

/// Draws each page as `<out>/page-<n>.png`.
pub(super) fn previews(
    ctx: &Ctx,
    pdf: &Path,
    out: &Path,
    pages: &[u32],
) -> Result<Vec<PathBuf>, Failure> {
    let mut images = Vec::new();
    for page in pages {
        let page = page.to_string();
        let target = out.join(format!("page-{page}"));
        let spec = Sandbox::new(ctx, "pdftoppm")?
            .args([
                "-png",
                "-r",
                PREVIEW_PPI,
                "-f",
                &page,
                "-l",
                &page,
                "-singlefile",
            ])
            .arg(pdf)
            .arg(&target)
            .ro(pdf)
            .rw(out)
            .net(Net::None)
            .timeout(POPPLER_LIMIT)
            .build();
        let run = ctx.run(&spec)?;
        if let Some(failure) = cause::failure("pdftoppm", &[], POPPLER_CODES, &run, POPPLER_LIMIT) {
            return Err(failure);
        }
        images.push(target.with_extension("png"));
    }
    Ok(images)
}

/// LibreOffice converts `input` to `filter` (pdf, csv, docx) in `job`; returns the file
/// it wrote. Its profile lives in the sandbox's private /tmp, so no lock outlives it.
pub(super) fn office(
    ctx: &Ctx,
    input: &Path,
    filter: &str,
    job: &Path,
) -> Result<PathBuf, Failure> {
    let spec = Sandbox::new(ctx, "soffice")?
        .args([
            "--headless",
            "--norestore",
            "--nolockcheck",
            "--nodefault",
            "--nofirststartwizard",
            "-env:UserInstallation=file:///tmp/lo-profile",
            "--convert-to",
            filter,
            "--outdir",
        ])
        .arg(job)
        .arg(input)
        .ro(Path::new("/etc/fonts"))
        .rw(job)
        .ro(input)
        .cwd(job)
        .env(OFFICE_QUIET.0, OFFICE_QUIET.1)
        .net(Net::None)
        .timeout(OFFICE_LIMIT)
        .build();
    let out = ctx.run(&spec)?;
    let written = job.join(format!("{}.{filter}", file_stem(input)));
    if bytes(&written) > 0 {
        return Ok(written);
    }
    if out.timed_out {
        return Err(Failure::upstream(cause::timed_out(
            "LibreOffice",
            OFFICE_LIMIT,
        )));
    }
    Err(Failure::upstream(
        match cause::marked(OFFICE_CAUSES, &out) {
            Some(why) => why.to_owned(),
            None => format!(
            "LibreOffice produced no {filter} file; the input may be password-protected or empty"
        ),
        },
    ))
}
