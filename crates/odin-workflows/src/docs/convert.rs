//! docs.convert: pandoc for text formats, LibreOffice for office formats, and the
//! render templates for Markdown or Typst to PDF, so every PDF Odin makes looks alike.

use std::path::Path;

use serde_json::{json, Value};

use super::render::{self, Look};
use super::{inputs, Doc, OFFICE_KINDS, PANDOC_CODES, PANDOC_LIMIT};
use crate::sandbox::{Net, Sandbox};
use crate::{args, cause, Call, Ctx, Failure};

/// How one conversion is made.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Route {
    /// pandoc with this reader.
    Pandoc(&'static str),
    /// LibreOffice.
    Office,
    /// The render templates.
    Render,
}

/// Every conversion docs.convert makes: (from, to, how).
const ROUTES: &[(&[&str], &[&str], Route)] = &[
    (&["md"], &["pdf"], Route::Render),
    (&["typ"], &["pdf"], Route::Render),
    (
        &["md"],
        &["docx", "odt", "html", "epub", "typst", "txt", "rst", "org"],
        Route::Pandoc("markdown"),
    ),
    (
        &["html"],
        &["md", "docx", "odt", "epub", "txt"],
        Route::Pandoc("html"),
    ),
    (
        &["docx"],
        &["md", "html", "txt", "epub", "typst"],
        Route::Pandoc("docx"),
    ),
    (
        &["odt"],
        &["md", "html", "txt", "epub", "typst", "docx"],
        Route::Pandoc("odt"),
    ),
    (&["ipynb"], &["md", "html", "docx"], Route::Pandoc("ipynb")),
    (&["epub"], &["md", "html", "txt"], Route::Pandoc("epub")),
    (OFFICE_KINDS, &["pdf"], Route::Office),
    (&["xlsx", "xls", "ods"], &["csv"], Route::Office),
    (&["doc", "rtf"], &["docx"], Route::Office),
];

/// pandoc writer names and the extension each output carries.
const WRITERS: &[(&str, &str, &str)] = &[
    ("docx", "docx", "docx"),
    ("odt", "odt", "odt"),
    ("html", "html5", "html"),
    ("epub", "epub3", "epub"),
    ("md", "gfm", "md"),
    ("txt", "plain", "txt"),
    ("typst", "typst", "typ"),
    ("rst", "rst", "rst"),
    ("org", "org", "org"),
];

fn route(from: &str, to: &str) -> Option<Route> {
    ROUTES
        .iter()
        .find(|(sources, tos, _)| sources.contains(&from) && tos.contains(&to))
        .map(|(_, _, route)| *route)
}

/// "md to docx, odt, …; html to …", for a refused pair.
fn table() -> String {
    ROUTES
        .iter()
        .map(|(sources, tos, _)| format!("{} to {}", sources.join("/"), tos.join(", ")))
        .collect::<Vec<_>>()
        .join("; ")
}

pub(super) fn run(ctx: &Ctx, call: &Call, args: &Value) -> Result<Value, Failure> {
    let (doc, _) = inputs(call, args, &["source", "artifact", "intake"])?;
    let to = args::str(args, "to")?;
    let reference = reference_doc(call, args)?;
    let job = ctx.scratch(call)?;
    let (input, from, stem) = match &doc {
        Doc::Text(text) => {
            let from = if text.trim_start().starts_with('<') {
                "html"
            } else if render::inferred_typst("", text) {
                "typ"
            } else {
                "md"
            };
            let input = job.join(format!("in.{from}"));
            std::fs::write(&input, text).map_err(|error| {
                Failure::unavailable(format!("could not write the source: {error}"))
            })?;
            (input, from.to_owned(), "document".to_owned())
        }
        Doc::File(path) => (
            path.clone(),
            super::kind(ctx, path)?,
            super::file_stem(path),
        ),
    };
    let Some(how) = route(&from, to) else {
        return Err(Failure::arguments(format!(
            "{from} to {to} is not a conversion docs.convert makes; it converts {}",
            table()
        )));
    };
    ctx.progress(format!("converting {from} to {to}"));
    let input = super::with_extension(&input, &from, &job)?;
    let (written, pages) = match how {
        Route::Render => {
            let (text, typst, _) = render::read(&Doc::File(input.clone()))?;
            let look = Look {
                template: "report",
                title: None,
                phone: false,
                cite: false,
            };
            let name = super::output_name(named_stem(args, &stem), "pdf");
            let compiled = render::compile(ctx, &job, &text, typst, &look, &json!({}), &name)?;
            (compiled.pdf, Some(compiled.page_count))
        }
        Route::Office => {
            if to == "docx" && reference.is_some() {
                let stage = job.join("office");
                std::fs::create_dir_all(&stage).map_err(|error| {
                    Failure::unavailable(format!("could not create the office stage: {error}"))
                })?;
                let converted = super::office(ctx, &input, to, &stage)?;
                (
                    pandoc(
                        ctx,
                        &converted,
                        "docx",
                        to,
                        named_stem(args, &stem),
                        &job,
                        reference.as_deref(),
                    )?,
                    None,
                )
            } else {
                let converted = super::office(ctx, &input, to, &job)?;
                let named = job.join(super::output_name(named_stem(args, &stem), to));
                rename(&converted, &named)?;
                let pages = (to == "pdf")
                    .then(|| super::page_count(ctx, &named))
                    .transpose()?;
                (named, pages)
            }
        }
        Route::Pandoc(reader) => (
            pandoc(
                ctx,
                &input,
                reader,
                to,
                named_stem(args, &stem),
                &job,
                reference.as_deref(),
            )?,
            None,
        ),
    };
    let bytes = super::bytes(&written);
    let name = super::file_name(&written);
    let pages_said = pages.map_or(String::new(), |pages| format!("{pages} page(s), "));
    let mut out = json!({
        "done": format!("Converted to {name} ({pages_said}{}).", super::size(bytes)),
        "bytes": bytes,
        "artifacts": [written],
    });
    if let Some(pages) = pages {
        out["page_count"] = json!(pages);
    }
    Ok(out)
}

fn named_stem<'a>(args: &'a Value, fallback: &'a str) -> &'a str {
    args::opt_str(args, "name").unwrap_or(fallback)
}

/// The staged `.docx` whose styles a docx conversion copies. Glue stages `reference`
/// last, after artifact, artifacts, intake and asset.
fn reference_doc(call: &Call, args: &Value) -> Result<Option<std::path::PathBuf>, Failure> {
    let Some(_) = args::opt_str(args, "reference") else {
        return Ok(None);
    };
    if args::opt_str(args, "to") != Some("docx") {
        return Err(Failure::arguments(
            "reference styles a docx; convert to docx or omit reference",
        ));
    }
    let index = call
        .files
        .len()
        .checked_sub(1)
        .ok_or_else(|| Failure::unavailable("the reference document was not staged"))?;
    Ok(Some(call.files[index].clone()))
}

fn pandoc(
    ctx: &Ctx,
    input: &Path,
    reader: &str,
    to: &str,
    stem: &str,
    job: &Path,
    reference: Option<&Path>,
) -> Result<std::path::PathBuf, Failure> {
    let (writer, extension) = WRITERS
        .iter()
        .find(|(name, _, _)| *name == to)
        .map(|(_, writer, extension)| (*writer, *extension))
        .ok_or_else(|| {
            Failure::arguments(format!("{to} is not a pandoc output docs.convert makes"))
        })?;
    let output = job.join(super::output_name(stem, extension));
    let mut spec = Sandbox::new(ctx, "pandoc")?.args([
        "--sandbox",
        &format!("--from={reader}"),
        &format!("--to={writer}"),
    ]);
    if let Some(reference) = reference {
        spec = spec.arg(format!("--reference-doc={}", reference.display()));
    }
    if matches!(to, "html" | "typst") {
        spec = spec.arg("--standalone");
    }
    let mut spec = spec
        .arg(format!("--output={}", output.display()))
        .arg(input)
        .ro(input)
        .rw(job);
    if let Some(reference) = reference {
        spec = spec.ro(reference);
    }
    let spec = spec
        .cwd(job)
        .env("LANG", "C.UTF-8")
        .net(Net::None)
        .timeout(PANDOC_LIMIT)
        .build();
    let out = ctx.run(&spec)?;
    if let Some(failure) = cause::failure("pandoc", &[], PANDOC_CODES, &out, PANDOC_LIMIT) {
        return Err(failure);
    }
    if super::bytes(&output) == 0 {
        return Err(Failure::upstream(format!(
            "pandoc wrote no {to} file for {}",
            super::file_name(input)
        )));
    }
    Ok(output)
}

fn rename(from: &Path, to: &Path) -> Result<(), Failure> {
    if from == to {
        return Ok(());
    }
    std::fs::rename(from, to).map_err(|error| {
        Failure::unavailable(format!(
            "could not name the output {}: {error}",
            to.display()
        ))
    })
}
