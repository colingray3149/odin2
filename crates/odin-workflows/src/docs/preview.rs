//! docs.preview: a PDF's pages, or an office file's pages the way LibreOffice (and so
//! Word or PowerPoint) lays them out, as images. Nothing becomes an artifact.

use serde_json::{json, Value};

use super::{inputs, Doc, OFFICE_KINDS};
use crate::{Call, Ctx, Failure};

pub(super) fn run(ctx: &Ctx, call: &Call, args: &Value) -> Result<Value, Failure> {
    let (Doc::File(path), _) = inputs(call, args, &["artifact", "intake"])? else {
        return Err(Failure::arguments("give artifact or intake"));
    };
    let job = ctx.scratch(call)?;
    let kind = super::kind(ctx, &path)?;
    let pdf = if kind == "pdf" {
        path.clone()
    } else if OFFICE_KINDS.contains(&kind.as_str()) {
        ctx.progress(format!("laying out the {kind} file"));
        let input = super::with_extension(&path, &kind, &job)?;
        super::office(ctx, &input, "pdf", &job)?
    } else {
        return Err(Failure::arguments(format!(
            "{} is {kind}; preview shows PDFs and office files (convert or render it first)",
            super::file_name(&path)
        )));
    };
    let count = super::page_count(ctx, &pdf)?;
    let (pages, note) = super::pick_pages(args, count);
    let images = super::previews(ctx, &pdf, &job, &pages)?;
    let shown: Vec<String> = pages.iter().map(u32::to_string).collect();
    let mut out = json!({
        "done": format!(
            "Page {} of {count} of {}.",
            shown.join(", "),
            super::file_name(&path)
        ),
        "page_count": count,
        "preview": images,
    });
    if let Some(note) = note {
        out["note"] = json!(note);
    }
    Ok(out)
}
