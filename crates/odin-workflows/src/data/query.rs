//! data.query: DuckDB runs one SQL query over the given files. Each file is a
//! view named from its file stem; pasted CSV keeps the name given. Rows come back
//! inline (the first 200); `save_as` also returns the whole result as a file.

use std::fmt::Write as _;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde_json::{json, Map, Value};

use crate::paths::{self, file_name};
use crate::sandbox::{Net, Sandbox, MAX_STDOUT};
use crate::{args, cause, Call, Ctx, Failure};

const QUERY_LIMIT: Duration = Duration::from_secs(120);
/// Rows a result carries inline.
const INLINE_ROWS: usize = 200;
/// The longest pasted table name.
const MAX_TABLE_NAME: usize = 41;
const SAVE_FORMATS: &[&str] = &["csv", "parquet", "json"];

/// DuckDB failures that are not a mistake in the SQL.
const DUCKDB_CAUSES: &[(&str, &str)] = &[
    (
        "Out of Memory Error",
        "the query needs more memory than allowed; aggregate or filter first",
    ),
    (
        "Permission Error",
        "the query tried to read outside the given files",
    ),
    (
        "IO Error: No files found",
        "a table's file was not staged; pass it in artifacts",
    ),
];

pub(super) fn run(ctx: &Ctx, call: &Call, args: &Value) -> Result<Value, Failure> {
    let sql = args::str(args, "sql")?.trim().trim_end_matches(';').trim();
    let save_as = args::opt_str(args, "save_as");
    if save_as.is_some_and(|format| !SAVE_FORMATS.contains(&format)) {
        return Err(Failure::arguments(format!(
            "save_as must be one of {}",
            SAVE_FORMATS.join(", ")
        )));
    }
    let job = ctx.scratch(call)?;
    let mut tables: Vec<(String, PathBuf)> = call
        .files
        .iter()
        .map(|path| (view_name(path), path.clone()))
        .collect();
    if let Some(pasted) = args.get("tables").and_then(Value::as_object) {
        tables.extend(paste(pasted, &job)?);
    }
    if tables.is_empty() {
        return Err(Failure::arguments(
            "give the data as artifacts, intake or pasted tables",
        ));
    }
    let saved = save_as.map(|format| paths::unique(&job, &format!("{}.{format}", save_stem(args))));
    let inputs = ctx.inputs(call)?;
    let script = job.join("q.sql");
    std::fs::write(
        &script,
        script_text(&tables, sql, &inputs, &job, saved.as_deref())?,
    )
    .map_err(|error| Failure::unavailable(format!("could not write the query: {error}")))?;
    let spec = Sandbox::new(ctx, "duckdb")?
        .args(["-json", "-no-stdin", "-init", "/dev/null", ":memory:", "-c"])
        .arg(format!(".read {}", script.display()))
        .ro(&inputs)
        .rw(&job)
        .cwd(&job)
        .net(Net::None)
        .timeout(QUERY_LIMIT)
        .build();
    let out = ctx.run(&spec)?;
    if out.timed_out {
        return Err(Failure::upstream(cause::timed_out("duckdb", QUERY_LIMIT)));
    }
    if !out.success() {
        return Err(failure(
            &out.stderr_tail,
            &cause::explain("duckdb", &[], &[], &out),
        ));
    }
    let rows = last_rows(&out.stdout_text())?;
    let columns: Vec<String> = rows
        .first()
        .and_then(Value::as_object)
        .map(|row| row.keys().cloned().collect())
        .unwrap_or_default();
    let names: Vec<&str> = tables.iter().map(|(name, _)| name.as_str()).collect();
    let mut done = format!("{} rows from {}", rows.len(), names.join(", "));
    let mut out = json!({
        "columns": columns,
        "row_count": rows.len(),
        "truncated": rows.len() > INLINE_ROWS,
        "rows": rows.iter().take(INLINE_ROWS).collect::<Vec<_>>(),
    });
    if let Some(saved) = saved {
        let _ = write!(done, "; saved {}", file_name(&saved));
        out["artifacts"] = json!([saved]);
    }
    out["done"] = json!(format!("{done}."));
    Ok(out)
}

/// Pasted CSV tables, written into the job folder under their names.
fn paste(pasted: &Map<String, Value>, job: &Path) -> Result<Vec<(String, PathBuf)>, Failure> {
    let mut tables = Vec::new();
    for (name, text) in pasted {
        let plain = name.len() <= MAX_TABLE_NAME
            && name.starts_with(|c: char| c.is_ascii_lowercase() || c == '_')
            && name
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_');
        if !plain {
            return Err(Failure::arguments(format!(
                "table name {name:?} is not usable; table names are lowercase letters, digits and _"
            )));
        }
        let path = job.join(format!("{name}.csv"));
        let csv = text.as_str().ok_or_else(|| {
            Failure::arguments(format!(
                "table {name} must be CSV text, not another JSON type"
            ))
        })?;
        std::fs::write(&path, csv).map_err(|error| {
            Failure::unavailable(format!("could not write table {name}: {error}"))
        })?;
        tables.push((name.clone(), path));
    }
    Ok(tables)
}

/// A view name from the staged file stem. Staging preserves intake names and names artifacts by ID.
fn view_name(path: &Path) -> String {
    path.file_stem().map_or_else(
        || "table".to_owned(),
        |stem| sanitize(&stem.to_string_lossy(), "table"),
    )
}

/// The saved file stem: `name` when given, otherwise `result`.
fn save_stem(args: &Value) -> String {
    args::opt_str(args, "name").map_or_else(|| "result".to_owned(), |name| sanitize(name, "result"))
}

fn sanitize(raw: &str, empty: &str) -> String {
    let mut name = String::new();
    for c in raw.chars().flat_map(char::to_lowercase) {
        if c.is_ascii_alphanumeric() {
            name.push(c);
        } else if !name.ends_with('_') && !name.is_empty() {
            name.push('_');
        }
    }
    if name.ends_with('_') {
        name.pop();
    }
    if name.is_empty() {
        empty.to_owned()
    } else {
        name
    }
}

/// The script: DuckDB locked to the given files, one view per table, the optional
/// COPY, then the query itself last, so its rows are the last JSON array printed.
fn script_text(
    tables: &[(String, PathBuf)],
    sql: &str,
    inputs: &Path,
    job: &Path,
    saved: Option<&Path>,
) -> Result<String, Failure> {
    let mut script = format!(
        "SET autoinstall_known_extensions = false;\n\
         SET autoload_known_extensions = false;\n\
         SET allowed_directories = [{}, {}];\n\
         SET enable_external_access = false;\n\
         SET lock_configuration = true;\n",
        quote(inputs),
        quote(job)
    );
    for (name, path) in tables {
        let reader = match reader(path)? {
            "parquet" => format!("read_parquet({})", quote(path)),
            "json" => format!("read_json_auto({})", quote(path)),
            _ => format!("read_csv({}, auto_detect = true)", quote(path)),
        };
        let _ = writeln!(script, "CREATE VIEW \"{name}\" AS SELECT * FROM {reader};");
    }
    if let Some(saved) = saved {
        let format = saved
            .extension()
            .map_or("csv".into(), |extension| extension.to_string_lossy());
        let header = if format == "csv" { ", HEADER" } else { "" };
        let _ = writeln!(
            script,
            "COPY ({sql}) TO {} (FORMAT {format}{header});",
            quote(saved)
        );
    }
    let _ = writeln!(script, "{sql};");
    Ok(script)
}

/// A file's reader: by extension, else by its first bytes.
fn reader(path: &Path) -> Result<&'static str, Failure> {
    let extension = path
        .extension()
        .map(|extension| extension.to_string_lossy().to_ascii_lowercase())
        .unwrap_or_default();
    match extension.as_str() {
        "csv" | "tsv" | "txt" => return Ok("csv"),
        "json" | "ndjson" | "jsonl" => return Ok("json"),
        "parquet" => return Ok("parquet"),
        _ => {}
    }
    let mut head = [0u8; 4];
    let read = std::fs::File::open(path)
        .and_then(|mut file| file.read(&mut head))
        .map_err(|error| {
            Failure::unavailable(format!("could not read {}: {error}", path.display()))
        })?;
    Ok(match &head[..read] {
        b"PAR1" => "parquet",
        [b'[' | b'{', ..] => "json",
        _ => "csv",
    })
}

/// A SQL string literal.
fn quote(path: &Path) -> String {
    format!("'{}'", path.display().to_string().replace('\'', "''"))
}

/// The rows of the last result DuckDB printed (one JSON array per statement with rows).
fn last_rows(stdout: &str) -> Result<Vec<Value>, Failure> {
    let mut last = None;
    for value in serde_json::Deserializer::from_str(stdout).into_iter::<Value>() {
        match value {
            Ok(Value::Array(rows)) => last = Some(rows),
            Ok(_) => {}
            Err(_) if stdout.len() >= MAX_STDOUT => {
                return Err(Failure::upstream(format!(
                    "the result did not fit in {} of output; aggregate or filter, or use save_as",
                    cause::limit_text(MAX_STDOUT as u64)
                )))
            }
            Err(error) => {
                return Err(Failure::upstream(format!(
                    "duckdb printed output that is not JSON: {error}"
                )))
            }
        }
    }
    Ok(last.unwrap_or_default())
}

/// DuckDB's first `<Kind> Error:` line: the SQL's own mistake unless it is one of
/// the causes outside the query.
fn failure(stderr: &str, fallback: &str) -> Failure {
    if let Some((_, why)) = DUCKDB_CAUSES
        .iter()
        .find(|(marker, _)| stderr.contains(marker))
    {
        return Failure::upstream(*why);
    }
    match stderr
        .lines()
        .map(str::trim)
        .find(|line| line.contains(" Error: "))
    {
        Some(line) => Failure::arguments(format!("the query failed: {line}")),
        None => Failure::upstream(fallback),
    }
}
