//! code.rewrite's result: ast-grep's stream JSON (preview) or its apply summary, projected for the seat.

use std::collections::BTreeSet;
use std::io::Read;
use std::path::Path;

use odin_confined_fs::Capability;
use odin_omp::host_tools::HostToolError;
use serde_json::{json, Value};

use super::receipts::Captured;

const TOOL: &str = "odin_code.rewrite";
const DEFAULT_MAX_MATCHES: u64 = 100;
const SNIPPET_CHARS: usize = 400;
const MAX_PREVIEW_BYTES: u64 = 4 * 1024 * 1024;
/// Scratch that is never part of a change.
const SCRATCH: &str = ".odin-eval/";

/// ast-grep's stderr marker → the cause in the seat's terms (first match wins).
const CAUSES: &[(&str, &str)] = &[
    (
        "Multiple AST nodes",
        "the pattern parses to several nodes; wrap it so it is one expression or statement",
    ),
    (
        "No AST root",
        "the pattern is empty once parsed; write a complete expression or statement",
    ),
    (
        "Cannot parse query",
        "the pattern is not valid code in that language; write it as a complete expression or statement",
    ),
    ("is not supported", "ast-grep does not know that language name"),
    (
        "No such file or directory",
        "a path in paths does not exist in the capsule",
    ),
    (
        "Permission denied",
        "a path in paths is not readable in the capsule",
    ),
];

pub(super) fn project(
    run: &Captured,
    arguments: &Value,
    capsule_root: &Path,
) -> Result<Value, HostToolError> {
    let reported = applied_count(&run.stdout).or_else(|| applied_count(&run.stderr));
    let apply = arguments
        .get("apply")
        .or_else(|| arguments.pointer("/output/applied"))
        .and_then(Value::as_bool)
        == Some(true)
        || reported.is_some();
    let preview;
    let stdout = if apply {
        run.stdout.as_str()
    } else {
        preview = preview_stdout(run, capsule_root)?;
        preview.as_str()
    };
    // ast-grep exits non-zero with nothing to say when nothing matched.
    let quiet_miss = stdout.trim().is_empty() && run.stderr.trim().is_empty();
    if run.exit_code != Some(0) && !quiet_miss {
        let detail = CAUSES
            .iter()
            .find(|(marker, _)| run.stderr.contains(marker))
            .map(|(_, cause)| (*cause).to_owned())
            .unwrap_or_else(|| {
                let last = run
                    .stderr
                    .lines()
                    .rev()
                    .find(|line| !line.trim().is_empty());
                let code = run
                    .exit_code
                    .map_or_else(|| "without a code".to_owned(), |code| code.to_string());
                format!("ast-grep exited {code}: {}", clip(last.unwrap_or(""), 200))
            });
        return Err(HostToolError::Arguments { tool: TOOL, detail });
    }
    if apply {
        let applied = match reported {
            Some(count) if !run.stdout_truncated => count,
            None if quiet_miss => 0,
            _ => {
                return Err(HostToolError::Unavailable {
                    tool: TOOL,
                    reason: "ast-grep did not return a complete replacement count".to_owned(),
                })
            }
        };
        let changed: Vec<String> = run
            .changed
            .iter()
            .filter_map(|path| Path::new(path).strip_prefix(capsule_root).ok())
            .map(|path| path.display().to_string())
            .filter(|path| !path.starts_with(SCRATCH))
            .collect();
        return Ok(json!({
            "done": format!(
                "Applied {applied} replacement{}; {} file{} in the capsule now differ from its base. Build or test next.",
                plural(applied),
                changed.len(),
                plural(changed.len() as u64),
            ),
            "total": applied,
            "applied": true,
            "changed_files": changed,
        }));
    }
    let keep = arguments
        .get("max_matches")
        .and_then(Value::as_u64)
        .unwrap_or(DEFAULT_MAX_MATCHES) as usize;
    let mut total = 0u64;
    let mut files = BTreeSet::new();
    let mut matches = Vec::new();
    for line in stdout.lines() {
        let found =
            serde_json::from_str::<Value>(line).map_err(|error| HostToolError::Unavailable {
                tool: TOOL,
                reason: format!("ast-grep returned an invalid preview row: {error}"),
            })?;
        if !found.is_object() {
            return Err(HostToolError::Unavailable {
                tool: TOOL,
                reason: "ast-grep returned a preview row that is not an object".to_owned(),
            });
        }
        total += 1;
        if let Some(file) = found.get("file").and_then(Value::as_str) {
            if !files.contains(file) {
                files.insert(file.to_owned());
            }
        }
        if matches.len() < keep {
            matches.push(entry(&found));
        }
    }
    let mut done = if total == 0 {
        "No matches; nothing was written.".to_owned()
    } else {
        format!(
            "Previewed {total} match{} in {} file{}; apply=true writes them.",
            if total == 1 { "" } else { "es" },
            files.len(),
            plural(files.len() as u64),
        )
    };
    if let Some(warning) = run.stderr.lines().find(|line| !line.trim().is_empty()) {
        done.push_str(&format!(" ast-grep: {}", clip(warning, 200)));
    }
    Ok(json!({ "done": done, "total": total, "applied": false, "matches": matches }))
}

/// The complete preview stays in capsule scratch, beyond the effector receipt's 64 KiB retention.
fn preview_stdout(run: &Captured, capsule_root: &Path) -> Result<String, HostToolError> {
    let unavailable = |reason| HostToolError::Unavailable { tool: TOOL, reason };
    if run.stdout_truncated {
        return Err(unavailable(
            "ast-grep's preview receipt was truncated".to_owned(),
        ));
    }
    if run.stdout.trim().is_empty() {
        return Ok(String::new());
    }
    let report: Value = serde_json::from_str(&run.stdout)
        .map_err(|error| unavailable(format!("ast-grep's preview receipt is invalid: {error}")))?;
    let path = report["stdout_path"].as_str().unwrap_or_default();
    let relative = Path::new(path);
    if relative.parent() != Some(Path::new(".odin-eval"))
        || !relative
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.starts_with("rewrite-") && name.ends_with(".jsonl"))
    {
        return Err(unavailable(format!(
            "preview path {path:?} is not capsule scratch"
        )));
    }
    let root = Capability::seal(capsule_root)
        .map_err(|error| unavailable(format!("capsule is not a confined root: {error}")))?;
    let file = root
        .open_read(relative)
        .map_err(|error| unavailable(format!("preview {path} is unreadable: {error}")))?;
    let mut stdout = String::new();
    file.take(MAX_PREVIEW_BYTES + 1)
        .read_to_string(&mut stdout)
        .map_err(|error| unavailable(format!("preview {path} is unreadable: {error}")))?;
    if stdout.len() as u64 > MAX_PREVIEW_BYTES {
        return Err(unavailable(
            format!("ast-grep preview exceeded {MAX_PREVIEW_BYTES} bytes; narrow paths for a complete count"),
        ));
    }
    Ok(stdout)
}

/// `Applied N changes` is what `--update-all` prints; preview prints JSON lines.
fn applied_count(stdout: &str) -> Option<u64> {
    stdout.lines().find_map(|line| {
        let rest = line.trim().strip_prefix("Applied ")?;
        rest.split_whitespace().next()?.parse().ok()
    })
}

fn entry(found: &Value) -> Value {
    let text = |key: &str| {
        found
            .get(key)
            .and_then(Value::as_str)
            .map(|text| clip(text, SNIPPET_CHARS))
    };
    let line = found
        .pointer("/range/start/line")
        .and_then(Value::as_u64)
        .map_or(0, |line| line + 1);
    let mut entry = json!({ "file": text("file"), "line": line, "text": text("text") });
    if let Some(replacement) = text("replacement") {
        entry["replacement"] = json!(replacement);
    }
    entry
}

fn clip(text: &str, limit: usize) -> String {
    let mut characters = text.char_indices();
    match characters.nth(limit.saturating_sub(1)) {
        Some((at, _)) if characters.next().is_some() => format!("{}…", &text[..at]),
        _ => text.to_owned(),
    }
}

fn plural(count: u64) -> &'static str {
    if count == 1 {
        ""
    } else {
        "s"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Two matches from `ast-grep run --pattern 'helper($A)' --rewrite 'assist($A)' --lang rust --json=stream`
    /// (0.51.0) and a third from another file, trimmed of fields the projection ignores.
    const STREAM: &str = r#"{"text":"helper(1)","range":{"byteOffset":{"start":51,"end":60},"start":{"line":1,"column":20},"end":{"line":1,"column":29}},"file":"a.rs","lines":"fn main() { let x = helper(1); helper(2); }","replacement":"assist(1)","language":"Rust"}
{"text":"helper(2)","range":{"byteOffset":{"start":62,"end":71},"start":{"line":1,"column":31},"end":{"line":1,"column":40}},"file":"a.rs","lines":"fn main() { let x = helper(1); helper(2); }","replacement":"assist(2)","language":"Rust"}
{"text":"helper(3)","range":{"byteOffset":{"start":4,"end":13},"start":{"line":0,"column":4},"end":{"line":0,"column":13}},"file":"src/b.rs","lines":"let helper(3);","replacement":"assist(3)","language":"Rust"}
"#;

    fn run(exit_code: i64, stdout: &str, stderr: &str) -> Captured {
        Captured {
            exit_code: Some(exit_code),
            stdout: stdout.to_owned(),
            stderr: stderr.to_owned(),
            stdout_truncated: false,
            changed: vec![
                "/capsule/a.rs".to_owned(),
                "/capsule/.odin-eval/x".to_owned(),
            ],
        }
    }

    fn spooled(stdout: &str) -> (tempfile::TempDir, Captured) {
        let root = tempfile::tempdir().unwrap();
        std::fs::create_dir(root.path().join(".odin-eval")).unwrap();
        let path = ".odin-eval/rewrite-op.jsonl";
        std::fs::write(root.path().join(path), stdout).unwrap();
        let captured = run(0, &json!({"stdout_path": path}).to_string(), "");
        (root, captured)
    }

    #[test]
    fn projects_stream_json_into_matches_and_total() {
        let (root, captured) = spooled(STREAM);
        let result = project(&captured, &json!({"max_matches": 2}), root.path()).unwrap();
        assert_eq!(result["total"], 3);
        assert_eq!(result["matches"].as_array().unwrap().len(), 2);
        assert_eq!(
            result["matches"][0],
            json!({"file": "a.rs", "line": 2, "text": "helper(1)", "replacement": "assist(1)"})
        );
        assert!(result["done"]
            .as_str()
            .unwrap()
            .starts_with("Previewed 3 matches in 2 files"));

        let applied = project(
            &run(0, "", "Applied 3 changes\n"),
            &json!({"apply": true}),
            Path::new("/capsule"),
        )
        .unwrap();
        assert_eq!(applied["total"], 3);
        assert_eq!(applied["changed_files"], json!(["a.rs"]));
    }

    #[test]
    fn preview_refuses_a_symlink_spool_and_incomplete_rows() {
        let (root, captured) = spooled(STREAM);
        let spool = root.path().join(".odin-eval/rewrite-op.jsonl");
        let outside = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(outside.path(), STREAM).unwrap();
        std::fs::remove_file(&spool).unwrap();
        std::os::unix::fs::symlink(outside.path(), &spool).unwrap();
        assert!(matches!(
            project(&captured, &json!({}), root.path()),
            Err(HostToolError::Unavailable { reason, .. }) if reason.contains("unreadable")
        ));
        std::fs::remove_file(&spool).unwrap();
        std::fs::write(&spool, "{\"file\":").unwrap();
        assert!(matches!(
            project(&captured, &json!({}), root.path()),
            Err(HostToolError::Unavailable { reason, .. }) if reason.contains("invalid preview row")
        ));
    }

    #[test]
    fn empty_stdout_with_exit_one_is_zero_matches() {
        let result = project(&run(1, "", ""), &json!({}), Path::new("/capsule")).unwrap();
        assert_eq!(result["total"], 0);
        assert_eq!(result["done"], "No matches; nothing was written.");
    }
}
