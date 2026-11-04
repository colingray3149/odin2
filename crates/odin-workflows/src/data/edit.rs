//! data.edit: one yq expression applied to a copy of a YAML, JSON, XML or TOML file,
//! keeping comments and order. Returns the new file and a unified diff; the original
//! is never touched.

use std::path::Path;
use std::time::Duration;

use serde_json::{json, Value};

use crate::paths::file_name;
use crate::sandbox::{Net, Sandbox};
use crate::{args, cause, Call, Ctx, Failure};

const EDIT_LIMIT: Duration = Duration::from_secs(30);
/// The diff a result carries inline.
const INLINE_DIFF_CHARS: usize = 8000;
const FORMATS: &[&str] = &["yaml", "json", "xml", "toml"];

/// yq prints `Error: <message>` and exits 1.
const YQ_CAUSES: &[(&str, &str)] = &[
    (
        "bad expression",
        "the yq expression is not valid; check its syntax",
    ),
    (
        "parsing expression",
        "the yq expression is not valid; check its syntax",
    ),
    ("lexer", "the yq expression is not valid; check its syntax"),
    ("yaml: line", "the file is not valid YAML at the line named"),
    ("invalid character", "the file is not valid JSON"),
    (
        "disabled",
        "the expression reads files or the environment, which data.edit leaves out",
    ),
];

/// diff(1): 0 same, 1 different, 2 trouble.
const DIFF_CODES: &[(i32, &str)] = &[(2, "diff could not compare the files")];

pub(super) fn run(ctx: &Ctx, call: &Call, args: &Value) -> Result<Value, Failure> {
    let expr = args::str(args, "expr")?;
    let text = args::opt_str(args, "text");
    let staged = call.files.first();
    let (body, name) = match (text, staged) {
        (Some(text), None) => (text.to_owned(), None),
        (None, Some(path)) => (
            crate::paths::read_text(path, "data.edit reads YAML, JSON, XML or TOML")?,
            Some(path.as_path()),
        ),
        _ => {
            return Err(Failure::arguments(
                "give exactly one of text, artifact, intake",
            ))
        }
    };
    let format = match args::opt_str(args, "format") {
        Some(format) if FORMATS.contains(&format) => format,
        Some(_) => {
            return Err(Failure::arguments(format!(
                "format must be one of {}",
                FORMATS.join(", ")
            )))
        }
        None => format_of(name, &body),
    };
    let job = ctx.scratch(call)?;
    let file = match name {
        Some(path) if extension(path).is_some_and(|ext| format_by_extension(&ext).is_some()) => {
            file_name(path)
        }
        Some(path) => format!("{}.{format}", stem(path)),
        None => format!("edited.{format}"),
    };
    let original = job.join("orig");
    let edited = job.join(&file);
    for target in [&original, &edited] {
        std::fs::write(target, &body).map_err(|error| {
            Failure::unavailable(format!("could not copy the file to edit: {error}"))
        })?;
    }
    let spec = Sandbox::new(ctx, "yq")?
        .args([
            "--security-disable-env-ops",
            "--security-disable-file-ops",
            "-p",
            format,
            "-o",
            format,
            "-i",
            expr,
        ])
        .arg(&edited)
        .rw(&job)
        .cwd(&job)
        .net(Net::None)
        .timeout(EDIT_LIMIT)
        .build();
    let out = ctx.run(&spec)?;
    if out.timed_out {
        return Err(Failure::upstream(cause::timed_out("yq", EDIT_LIMIT)));
    }
    if !out.success() {
        return Err(Failure::arguments(cause::explain(
            "yq",
            YQ_CAUSES,
            &[],
            &out,
        )));
    }
    let spec = Sandbox::new(ctx, "diff")?
        .args(["-u", "--label", "before", "--label", "after"])
        .arg(&original)
        .arg(&edited)
        .ro(&job)
        .net(Net::None)
        .timeout(EDIT_LIMIT)
        .build();
    let out = ctx.run(&spec)?;
    match out.code {
        Some(0) if !out.timed_out => {
            return Ok(
                json!({"done": format!("The expression changed nothing in {file}."), "diff": ""}),
            );
        }
        Some(1) if !out.timed_out => {}
        _ => {
            return Err(Failure::upstream(if out.timed_out {
                cause::timed_out("diff", EDIT_LIMIT)
            } else {
                cause::explain("diff", &[], DIFF_CODES, &out)
            }))
        }
    }
    let diff = out.stdout_text();
    let changed = diff
        .lines()
        .filter(|line| line.starts_with('+') && !line.starts_with("+++"))
        .count();
    Ok(json!({
        "done": format!("Edited {file}; {changed} line(s) changed."),
        "diff": diff.chars().take(INLINE_DIFF_CHARS).collect::<String>(),
        "artifacts": [edited],
    }))
}

/// The format a file's extension names, else a guess from its text: `<` is XML, a
/// bare `[table]` or `key =` line is TOML, `{` or `[` is JSON, anything else YAML.
fn format_of(path: Option<&Path>, body: &str) -> &'static str {
    if let Some(format) = path
        .and_then(extension)
        .and_then(|ext| format_by_extension(&ext))
    {
        return format;
    }
    let bare = |key: &str| {
        !key.is_empty()
            && key
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || "_.-\"".contains(c))
    };
    let toml = body.lines().map(str::trim).any(|line| {
        line.strip_prefix('[')
            .and_then(|inner| inner.strip_suffix(']'))
            .is_some_and(bare)
            || line
                .split_once('=')
                .is_some_and(|(key, _)| bare(key.trim()))
    });
    match body.trim_start().chars().next() {
        Some('<') => "xml",
        _ if toml => "toml",
        Some('{' | '[') => "json",
        _ => "yaml",
    }
}

fn format_by_extension(extension: &str) -> Option<&'static str> {
    match extension {
        "yaml" | "yml" => Some("yaml"),
        "json" => Some("json"),
        "xml" => Some("xml"),
        "toml" => Some("toml"),
        _ => None,
    }
}

fn extension(path: &Path) -> Option<String> {
    path.extension()
        .map(|extension| extension.to_string_lossy().to_ascii_lowercase())
}

fn stem(path: &Path) -> String {
    path.file_stem().map_or_else(
        || "edited".to_owned(),
        |stem| stem.to_string_lossy().into_owned(),
    )
}
