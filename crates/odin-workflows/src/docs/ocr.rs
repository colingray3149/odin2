//! docs.ocr: OCRmyPDF adds a searchable text layer to a scanned PDF or a photo of a
//! page, keeps its look, and writes the text beside it.

use std::time::Duration;

use serde_json::{json, Value};

use super::{inputs, Doc};
use crate::sandbox::{Net, Sandbox};
use crate::{args, cause, Call, Ctx, Failure};

const OCR_LIMIT: Duration = Duration::from_secs(1500);
/// The text a result carries inline; the full text is the .txt artifact.
const INLINE_TEXT_CHARS: usize = 6000;
/// Photos carry no reliable resolution; OCR assumes a phone photo of a page.
const IMAGE_DPI: &str = "300";
/// Pages OCR'd at once.
const JOBS: &str = "4";

/// OCRmyPDF's `ExitCode` (ocrmypdf/exceptions.py, 17.13).
const OCR_CODES: &[(i32, &str)] = &[
    (
        1,
        "OCRmyPDF refused its arguments; check the language codes",
    ),
    (2, "the input is not a PDF or image OCRmyPDF can read"),
    (3, "a helper OCRmyPDF needs is missing from its package"),
    (4, "OCRmyPDF produced an invalid PDF; try redo"),
    (6, "the PDF already has text; use redo to replace it"),
    (
        7,
        "a helper (tesseract or Ghostscript) failed on this document",
    ),
    (8, "the PDF is encrypted; send an unlocked copy"),
];

const OCR_CAUSES: &[(&str, &str)] = &[
    (
        "is not installed",
        "a tesseract language pack is missing for the requested language",
    ),
    (
        "DigitalSignatureError",
        "the PDF is digitally signed; OCR would break the signature",
    ),
];

pub(super) fn run(ctx: &Ctx, call: &Call, args: &Value) -> Result<Value, Failure> {
    let (Doc::File(path), _) = inputs(call, args, &["artifact", "intake"])? else {
        return Err(Failure::arguments("give artifact or intake"));
    };
    let job = ctx.scratch(call)?;
    let kind = super::kind(ctx, &path)?;
    let image = matches!(kind.as_str(), "png" | "jpg" | "tiff");
    if kind != "pdf" && !image {
        return Err(Failure::arguments(format!(
            "{} is {kind}; ocr reads scanned PDFs and photos of pages",
            super::file_name(&path)
        )));
    }
    let pages = if image {
        1
    } else {
        super::page_count(ctx, &path)?
    };
    ctx.progress(format!("reading {pages} page(s)"));
    let name = super::output_name(&super::file_stem(&path), "pdf");
    let pdf = job.join(&name);
    let text = pdf.with_extension("txt");
    let languages = args::opt_str(args, "languages").unwrap_or("eng");
    let mode = if args::opt_bool(args, "redo").unwrap_or(false) {
        "--force-ocr"
    } else {
        "--skip-text"
    };
    let mut spec = Sandbox::new(ctx, "ocrmypdf")?
        .args([
            "--output-type",
            "pdf",
            "--rotate-pages",
            "--deskew",
            "--jobs",
            JOBS,
        ])
        .args(["-l", languages, mode, "--sidecar"])
        .arg(&text);
    if image {
        spec = spec.args(["--image-dpi", IMAGE_DPI]);
    }
    let spec = spec
        .arg(&path)
        .arg(&pdf)
        .ro(&path)
        .rw(&job)
        .cwd(&job)
        .net(Net::None)
        .timeout(OCR_LIMIT)
        .build();
    let out = ctx.run(&spec)?;
    if let Some(failure) = cause::failure("ocrmypdf", OCR_CAUSES, OCR_CODES, &out, OCR_LIMIT) {
        return Err(failure);
    }
    let full = std::fs::read_to_string(&text).map_err(|error| {
        Failure::upstream(format!(
            "ocrmypdf finished but its text file {} is unreadable: {error}",
            super::file_name(&text)
        ))
    })?;
    let truncated = full.chars().count() > INLINE_TEXT_CHARS;
    let inline: String = full.chars().take(INLINE_TEXT_CHARS).collect();
    let bytes = super::bytes(&pdf);
    Ok(json!({
        "done": format!("Made {name} searchable: {pages} page(s); its text is attached."),
        "page_count": pages,
        "bytes": bytes,
        "text": inline,
        "text_truncated": truncated,
        "artifacts": [pdf, text],
    }))
}
