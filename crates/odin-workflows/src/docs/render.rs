//! docs.render: Markdown (through pandoc) or Typst to a PDF with the Odin templates,
//! plus page images so the caller can look and render again. The only Typst path.

use std::path::{Path, PathBuf};
use std::time::Duration;

use serde_json::{json, Value};

use super::{inputs, Doc, PANDOC_CODES, PANDOC_LIMIT};
use crate::sandbox::{Net, Sandbox};
use crate::{args, cause, Call, Ctx, Failure};

pub(super) const RENDER_LIMIT: Duration = Duration::from_secs(60);
/// Inline or staged source text above this is refused.
const MAX_SOURCE_BYTES: u64 = 400 * 1024;
/// Compile errors quoted in a failure, and warnings kept in a result.
const QUOTED_ERRORS: usize = 3;
const KEPT_WARNINGS: usize = 5;
/// The optional root holding the reference library, read only with `cite`.
const BIB_ROOT: &str = "bib";
const BIB_FILE: &str = "zotero.bib";

/// The template files every job folder gets; the binary carries them, so template
/// and code always match.
const TEMPLATES: &[(&str, &str)] = &[
    ("odin.typ", include_str!("templates/odin.typ")),
    ("slides.typ", include_str!("templates/slides.typ")),
    ("pandoc.typst", include_str!("templates/pandoc.typst")),
];

const TEMPLATE_NAMES: &[&str] = &["report", "research", "slides", "letter", "plain"];

/// Hints for compile errors whose fix is not obvious from Typst's own line.
const TYPST_CAUSES: &[(&str, &str)] = &[
    (
        "failed to download package",
        "a Typst package is not in the offline bundle; use one the templates import",
    ),
    (
        "package not found",
        "a Typst package is not in the offline bundle; use one the templates import",
    ),
    (
        "file not found",
        "the source names a file that was not given; pass it in artifacts and name it by its artifact id",
    ),
    (
        "outside of project root",
        "the source reads a path outside the document folder; pass the file in artifacts",
    ),
];

/// How a document should look. `template` is report, research, slides, letter or plain.
pub(super) struct Look<'a> {
    pub template: &'a str,
    pub title: Option<&'a str>,
    pub phone: bool,
    pub cite: bool,
}

impl<'a> Look<'a> {
    pub fn of(args: &'a Value) -> Result<Self, Failure> {
        let template = args::opt_str(args, "template").unwrap_or("report");
        if !TEMPLATE_NAMES.contains(&template) {
            return Err(Failure::arguments(format!(
                "template must be one of {}",
                TEMPLATE_NAMES.join(", ")
            )));
        }
        Ok(Self {
            template,
            title: args::opt_str(args, "title"),
            phone: args::opt_bool(args, "phone").unwrap_or(false),
            cite: args::opt_bool(args, "cite").unwrap_or(false),
        })
    }
}

/// A compiled PDF and its count, matching the tool's `page_count` field.
pub struct Compiled {
    pub pdf: PathBuf,
    pub page_count: u32,
    pub warnings: Vec<String>,
}

/// Same `compile`, template research, phone true, cite false. `job` already
/// exists and holds figures under the names `text` uses. `meta` values are
/// strings the caller labelled. `typst` true skips pandoc.
pub fn research(
    ctx: &Ctx,
    job: &Path,
    text: &str,
    typst: bool,
    title: Option<&str>,
    meta: &Value,
    name: &str,
) -> Result<Compiled, Failure> {
    let look = Look {
        template: "research",
        title,
        phone: true,
        cite: false,
    };
    compile(ctx, job, text, typst, &look, meta, name)
}

pub(super) fn run(ctx: &Ctx, call: &Call, args: &Value) -> Result<Value, Failure> {
    let (doc, assets) = inputs(call, args, &["source", "artifact", "intake"])?;
    let look = Look::of(args)?;
    let job = ctx.scratch(call)?;
    let (text, inferred, stem) = read(&doc)?;
    let typst = source_is_typst(args, inferred)?;
    let text = place_assets(&text, &args::strs(args, "artifacts"), assets, &job)?;
    let stem = args::opt_str(args, "name").or(look.title).unwrap_or(&stem);
    let name = super::output_name(stem, "pdf");
    let meta = args.get("meta").cloned().unwrap_or_else(|| json!({}));
    ctx.progress("preparing the document");
    let compiled = compile(ctx, &job, &text, typst, &look, &meta, &name)?;
    ctx.progress("rendered; drawing page images");
    let (pages, note) = super::pick_pages(args, compiled.page_count);
    let images = super::previews(ctx, &compiled.pdf, &job, &pages)?;
    let bytes = super::bytes(&compiled.pdf);
    let shown: Vec<String> = pages.iter().map(u32::to_string).collect();
    let mut out = json!({
        "done": format!(
            "Rendered {name}: {} page(s), {}; page {} attached.",
            compiled.page_count,
            super::size(bytes),
            shown.join(", ")
        ),
        "page_count": compiled.page_count,
        "bytes": bytes,
        "artifacts": [compiled.pdf],
        "preview": images,
        "warnings": compiled.warnings,
    });
    if let Some(note) = note {
        out["note"] = json!(note);
    }
    Ok(out)
}

/// The source text, whether it looks like Typst, and a name stem for the output.
pub(super) fn read(doc: &Doc) -> Result<(String, bool, String), Failure> {
    let size = match doc {
        Doc::Text(text) => text.len() as u64,
        Doc::File(path) => super::bytes(path),
    };
    if size > MAX_SOURCE_BYTES {
        return Err(Failure::arguments(format!(
            "the source is {} KiB; split it below {}",
            size / 1024,
            cause::limit_text(MAX_SOURCE_BYTES)
        )));
    }
    let (text, extension, stem) = match doc {
        Doc::Text(text) => (text.clone(), String::new(), "document".to_owned()),
        Doc::File(path) => {
            let text = crate::paths::read_text(path, "give Markdown or Typst source")?;
            let extension = path
                .extension()
                .map(|extension| extension.to_string_lossy().to_ascii_lowercase())
                .unwrap_or_default();
            (text, extension, super::file_stem(path))
        }
    };
    let typst = inferred_typst(&extension, &text);
    Ok((text, typst, stem))
}

/// Typst when `format` says so; otherwise the extension and source-line inference.
fn source_is_typst(args: &Value, inferred: bool) -> Result<bool, Failure> {
    match args::opt_str(args, "format") {
        Some("typst") => Ok(true),
        Some("markdown") => Ok(false),
        Some(format) => Err(Failure::arguments(format!(
            "format must be markdown or typst, not {format}"
        ))),
        None => Ok(inferred),
    }
}

pub(super) fn inferred_typst(extension: &str, text: &str) -> bool {
    match extension {
        "typ" => true,
        "md" | "markdown" | "txt" => false,
        _ => text.lines().any(|line| {
            ["#set ", "#import ", "#let ", "#show"]
                .iter()
                .any(|start| line.starts_with(start))
        }),
    }
}

/// Copies each staged asset into the job folder and replaces its artifact id in the
/// source with the file name it now has there.
fn place_assets(
    text: &str,
    ids: &[&str],
    assets: &[PathBuf],
    job: &Path,
) -> Result<String, Failure> {
    let mut text = text.to_owned();
    for (id, path) in ids.iter().zip(assets) {
        let name = super::file_name(path);
        copy_into(path, &job.join(&name)).map_err(|error| {
            Failure::unavailable(format!("could not copy asset {name}: {error}"))
        })?;
        text = text.replace(id, &name);
    }
    Ok(text)
}

/// Research Typst bodies use the same template and footer as Markdown reports.
fn research_body(text: &str, look: &Look) -> String {
    if look.template != "research" {
        return text.to_owned();
    }
    let title = look.title.map_or_else(
        || "none".to_owned(),
        |title| serde_json::to_string(title).unwrap_or_else(|_| "none".to_owned()),
    );
    let phone = if look.phone { "true" } else { "false" };
    format!(
        "#import \"odin.typ\": *\n#show: research.with(title: {title}, phone: {phone})\n{text}\n"
    )
}

/// Writes the templates, theme, meta and source into `job`, turns Markdown into
/// Typst with pandoc, and compiles `job/<name>`. `job` must already exist.
pub(super) fn compile(
    ctx: &Ctx,
    job: &Path,
    text: &str,
    typst: bool,
    look: &Look,
    meta: &Value,
    name: &str,
) -> Result<Compiled, Failure> {
    for (file, body) in TEMPLATES {
        write(job, file, body)?;
    }
    let theme = ctx.root(super::THEME_ROOT)?.path.join("theme.typ");
    copy_into(&theme, &job.join("theme.typ")).map_err(|error| {
        Failure::unavailable(format!(
            "the theme {} was not copied: {error}",
            theme.display()
        ))
    })?;
    write(job, "meta.json", &meta.to_string())?;
    if look.cite {
        let bib = ctx.config.roots.get(BIB_ROOT).ok_or_else(|| {
            Failure::unavailable("no reference library is declared (services.odin.tools.roots.bib)")
        })?;
        let library = bib.path.join(BIB_FILE);
        copy_into(&library, &job.join("refs.bib")).map_err(|error| {
            Failure::unavailable(format!(
                "the reference library {} was not copied: {error}",
                library.display()
            ))
        })?;
    }
    let text = &named_by_content(job, text);
    if typst {
        write(job, "main.typ", &research_body(text, look))?;
    } else {
        write(job, "in.md", text)?;
        pandoc_to_typst(ctx, job, look)?;
    }
    let spec = Sandbox::new(ctx, "typst")?
        .arg("compile")
        .arg("--root")
        .arg(job)
        .args(["--diagnostic-format", "short", "main.typ", name])
        .rw(job)
        .cwd(job)
        .net(Net::None)
        .timeout(RENDER_LIMIT)
        .build();
    let out = ctx.run(&spec)?;
    let lines = |kind: &str| -> Vec<String> {
        out.stderr_tail
            .lines()
            .map(str::trim)
            .filter(|line| line.starts_with(kind) || line.contains(&format!(": {kind}")))
            .map(str::to_owned)
            .collect()
    };
    if out.timed_out {
        return Err(Failure::upstream(cause::timed_out("typst", RENDER_LIMIT)));
    }
    if !out.success() {
        let errors = lines("error:");
        if errors.is_empty() {
            return Err(Failure::upstream(cause::explain("typst", &[], &[], &out)));
        }
        let quoted = errors[..errors.len().min(QUOTED_ERRORS)].join("; ");
        let hint = TYPST_CAUSES
            .iter()
            .find(|(marker, _)| quoted.contains(marker))
            .map_or(String::new(), |(_, hint)| format!(" ({hint})"));
        return Err(Failure::arguments(format!(
            "the document did not compile: {quoted}{hint}"
        )));
    }
    let pdf = job.join(name);
    let pages = super::page_count(ctx, &pdf)?;
    let mut warnings = lines("warning:");
    warnings.truncate(KEPT_WARNINGS);
    Ok(Compiled {
        pdf,
        page_count: pages,
        warnings,
    })
}

/// Typst reads a picture by its extension, and a saved page often names a WebP or PNG `.jpg`:
/// each image in `job` whose bytes say otherwise gets a copy named for what it is, and `text`
/// points at that copy.
pub(super) fn named_by_content(job: &Path, text: &str) -> String {
    let mut text = text.to_owned();
    let mut folders = vec![job.to_path_buf()];
    while let Some(folder) = folders.pop() {
        let Ok(entries) = std::fs::read_dir(&folder) else {
            continue;
        };
        for path in entries.flatten().map(|entry| entry.path()) {
            if path.is_dir() {
                folders.push(path);
                continue;
            }
            let Some(named) = path.extension().and_then(|ext| ext.to_str()) else {
                continue;
            };
            let named = named.to_ascii_lowercase();
            if !matches!(named.as_str(), "jpg" | "jpeg" | "png" | "gif" | "webp") {
                continue;
            }
            let Some(real) = image_kind(&path) else {
                continue;
            };
            if real == named || (real == "jpg" && named == "jpeg") {
                continue;
            }
            let renamed = path.with_extension(real);
            let (Ok(from), Ok(to)) = (path.strip_prefix(job), renamed.strip_prefix(job)) else {
                continue;
            };
            if copy_into(&path, &renamed).is_ok() {
                text = text.replace(&*from.to_string_lossy(), &to.to_string_lossy());
            }
        }
    }
    text
}

/// What an image file is, by its first bytes.
fn image_kind(path: &Path) -> Option<&'static str> {
    let mut head = [0u8; 12];
    let read = std::io::Read::read(&mut std::fs::File::open(path).ok()?, &mut head).ok()?;
    let head = &head[..read];
    if head.starts_with(b"\x89PNG") {
        Some("png")
    } else if head.starts_with(&[0xff, 0xd8, 0xff]) {
        Some("jpg")
    } else if head.starts_with(b"GIF8") {
        Some("gif")
    } else if head.len() == 12 && head.starts_with(b"RIFF") && &head[8..] == b"WEBP" {
        Some("webp")
    } else {
        None
    }
}

/// `job/in.md` to `job/main.typ` through the template library.
fn pandoc_to_typst(ctx: &Ctx, job: &Path, look: &Look) -> Result<(), Failure> {
    // Citations only with a library, so a stray @name stays text.
    let reader = if look.cite {
        "--from=markdown+autolink_bare_uris"
    } else {
        "--from=markdown-citations+autolink_bare_uris"
    };
    let mut spec = Sandbox::new(ctx, "pandoc")?
        .args(["--sandbox", reader, "--to=typst", "--template=pandoc.typst"])
        .args(["-M".to_owned(), format!("look={}", look.template)])
        .args(["-M".to_owned(), format!("phone={}", look.phone)]);
    if let Some(title) = look.title {
        spec = spec.args(["-M".to_owned(), format!("title={title}")]);
    }
    if look.cite {
        spec = spec.args(["-M", "bibliography=refs.bib"]);
    }
    let spec = spec
        .args(["--output=main.typ", "in.md"])
        .rw(job)
        .cwd(job)
        .env("LANG", "C.UTF-8")
        .net(Net::None)
        .timeout(PANDOC_LIMIT)
        .build();
    let out = ctx.run(&spec)?;
    match cause::failure("pandoc", &[], PANDOC_CODES, &out, PANDOC_LIMIT) {
        Some(failure) => Err(failure),
        None => Ok(()),
    }
}

/// The bytes of `from` written to `to`. Unlike `fs::copy` this never carries a read-only mode
/// over from the Nix store, so a second render in the same job folder can replace the file.
pub(super) fn copy_into(from: &Path, to: &Path) -> std::io::Result<()> {
    std::fs::write(to, std::fs::read(from)?)
}

fn write(job: &Path, file: &str, body: &str) -> Result<(), Failure> {
    std::fs::write(job.join(file), body)
        .map_err(|error| Failure::unavailable(format!("could not write {file}: {error}")))
}
