//! local.models: lists, loads, unloads, swaps and pulls local models and switches a host's GPU mode
//! by running the declared `local-models` CLI. A failed run answers with the CLI's own stderr.
//! Names, sizes and loaded state only: the CLI takes no paths, and no argument can name one here.

use std::path::Path;
use std::process::Command;

use serde_json::{json, Map, Value};

use crate::{Ctx, Failure};

/// The key of the declared `local-models` executable.
const EXECUTABLE: &str = "local-models";
/// What a model row carries out of the CLI: names, sizes and state, never a path.
const ROW_FIELDS: [&str; 8] = [
    "id", "kind", "size", "vram_gib", "context", "loaded", "resident", "mode",
];

/// Wraps the CLI's words in the ssh argv that runs them on another fleet host.
pub type Remote = fn(&str, &[String]) -> Vec<String>;

/// Runs one local.models call. `host` absent, or the host this process runs on, runs the declared
/// executable here; any other host runs `local-models` by name through `remote`.
pub fn run(ctx: &Ctx, remote: Remote, input: &Value) -> Result<Value, Failure> {
    let exe = ctx.exe(EXECUTABLE)?;
    let host = field(input, "host")
        .map(|host| bare(host, "host"))
        .transpose()?;
    let host = host.filter(|host| *host != here());
    let cli = |args: &[&str]| invoke(exe, host, remote, args);
    let op = field(input, "op").unwrap_or_default();
    match op {
        "list" => {
            let models = rows(&cli(&["list", "--json"])?)?;
            Ok(json!({
                "ok": true,
                "text": format!("{} local models", models.len()),
                "models": models,
            }))
        }
        "load" => done(cli(&["load", id(input, op)?])?),
        "unload" => done(cli(&["unload", id(input, op)?])?),
        "swap" => {
            cli(&["unload", "all"])?;
            done(cli(&["load", id(input, op)?])?)
        }
        "pull" => {
            let source = needed(input, op, "source")?;
            if source.starts_with(['/', '.', '~', '-']) {
                return Err(Failure::arguments(format!(
                    "local.models pull takes a Hugging Face repo, a link or a model name, not {source}"
                )));
            }
            let mut args = vec!["pull", source];
            if let Some(file) = field(input, "file") {
                args.extend(["--file", bare(file, "file")?]);
            }
            done(cli(&args)?)
        }
        "mode" => match field(input, "mode") {
            Some(mode) => done(cli(&["mode", bare(mode, "mode")?])?),
            None => done(cli(&["mode"])?),
        },
        other => Err(Failure::arguments(format!(
            "local.models has no op {other}; use list, load, unload, swap, pull or mode"
        ))),
    }
}

/// Runs the CLI and returns its trimmed stdout, or its stderr as the failure; a Python traceback
/// is cut to the line that names its cause. A pull may run as long as the capability's declared
/// timeout allows, so this call takes no limit of its own.
fn invoke(
    exe: &Path,
    host: Option<&str>,
    remote: Remote,
    args: &[&str],
) -> Result<String, Failure> {
    let argv: Vec<String> = match host {
        Some(host) => {
            let mut words = vec![EXECUTABLE.to_owned()];
            words.extend(args.iter().map(|arg| (*arg).to_owned()));
            remote(host, &words)
        }
        None => std::iter::once(exe.display().to_string())
            .chain(args.iter().map(|arg| (*arg).to_owned()))
            .collect(),
    };
    let output = Command::new(&argv[0])
        .args(&argv[1..])
        .output()
        .map_err(|error| Failure::unavailable(format!("{} could not start: {error}", argv[0])))?;
    if output.status.success() {
        return Ok(String::from_utf8_lossy(&output.stdout).trim().to_owned());
    }
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stderr = stderr.trim_end();
    let cause = if stderr.starts_with("Traceback") {
        stderr.lines().next_back().unwrap_or(stderr)
    } else {
        stderr
    };
    Err(Failure::upstream(if cause.is_empty() {
        format!("{EXECUTABLE} {} exited with {}", args[0], output.status)
    } else {
        cause.to_owned()
    }))
}

/// The CLI's `list --json` array, projected to the fields a model row carries.
fn rows(stdout: &str) -> Result<Vec<Value>, Failure> {
    let parsed: Value = serde_json::from_str(stdout).map_err(|error| {
        Failure::upstream(format!("local-models list --json printed no JSON: {error}"))
    })?;
    let rows = parsed.as_array().ok_or_else(|| {
        Failure::upstream("local-models list --json printed JSON that is not an array")
    })?;
    Ok(rows
        .iter()
        .map(|row| {
            let kept: Map<String, Value> = ROW_FIELDS
                .iter()
                .filter_map(|key| {
                    row.get(*key)
                        .map(|value| ((*key).to_owned(), value.clone()))
                })
                .collect();
            Value::Object(kept)
        })
        .collect())
}

fn done(text: String) -> Result<Value, Failure> {
    Ok(json!({ "ok": true, "text": text }))
}

fn id<'a>(input: &'a Value, op: &str) -> Result<&'a str, Failure> {
    bare(needed(input, op, "id")?, "id")
}

fn needed<'a>(input: &'a Value, op: &str, key: &str) -> Result<&'a str, Failure> {
    field(input, key).ok_or_else(|| Failure::arguments(format!("local.models {op} needs {key}")))
}

fn field<'a>(input: &'a Value, key: &str) -> Option<&'a str> {
    input
        .get(key)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|text| !text.is_empty())
}

/// A name the CLI reads as one word: never an option, never a path.
fn bare<'a>(text: &'a str, key: &str) -> Result<&'a str, Failure> {
    if text.starts_with('-') || text.contains('/') {
        return Err(Failure::arguments(format!(
            "local.models {key} is a name, not a path or an option: {text}"
        )));
    }
    Ok(text)
}

/// The host this process runs on; `host` names it to run locally.
fn here() -> String {
    std::fs::read_to_string("/proc/sys/kernel/hostname")
        .map(|name| name.trim().to_owned())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::testing::{ctx_for, recorded_args, FakeExe};

    fn no_remote(_: &str, _: &[String]) -> Vec<String> {
        Vec::new()
    }

    #[test]
    fn local_models_list_returns_the_cli_rows() {
        let dir = tempfile::tempdir().expect("dir");
        let row = r#"[{"id":"lfm","kind":"chat","size":18.5,"vram_gib":19.1,"context":131072,"loaded":true,"resident":true,"mode":"odin","path":"/srv/secret"}]"#;
        let exe = FakeExe::new(dir.path(), EXECUTABLE).stdout(row).install();
        let ctx = ctx_for(dir.path(), &[(EXECUTABLE, exe.as_path())], &[], &[], &[]);
        let out = run(&ctx, no_remote, &json!({"op": "list"})).expect("list");
        assert_eq!(out["models"][0]["id"], "lfm");
        assert_eq!(out["models"][0]["loaded"], true);
        assert!(
            out["models"][0].get("path").is_none(),
            "a row carries no path"
        );
        assert_eq!(recorded_args(&exe), ["list", "--json"]);
    }

    /// Stands in for ssh: runs the words locally, printing the host first.
    fn echo_remote(host: &str, words: &[String]) -> Vec<String> {
        let mut argv: Vec<String> = ["/bin/sh", "-c", r#"echo "$@""#, "remote", host]
            .map(str::to_owned)
            .into();
        argv.extend(words.iter().cloned());
        argv
    }

    #[test]
    fn another_host_runs_the_cli_by_name_through_remote_and_swap_unloads_before_it_loads() {
        let dir = tempfile::tempdir().expect("dir");
        let exe = FakeExe::new(dir.path(), EXECUTABLE).install();
        let ctx = ctx_for(dir.path(), &[(EXECUTABLE, exe.as_path())], &[], &[], &[]);
        let out = run(
            &ctx,
            echo_remote,
            &json!({"op": "load", "id": "lfm", "host": "elsewhere"}),
        )
        .expect("remote load");
        assert!(
            out["text"]
                .as_str()
                .unwrap()
                .contains("elsewhere local-models load lfm"),
            "{out}"
        );
        assert!(
            recorded_args(&exe).is_empty(),
            "the declared executable is not run for another host"
        );

        run(&ctx, no_remote, &json!({"op": "swap", "id": "lfm"})).expect("swap");
        assert_eq!(
            recorded_args(&exe),
            ["load", "lfm"],
            "the fake records its last run"
        );
        let refused = run(
            &ctx,
            no_remote,
            &json!({"op": "pull", "source": "/etc/passwd"}),
        )
        .expect_err("a path is not a source");
        assert_eq!(refused.kind, crate::FailureKind::Arguments);
    }

    #[test]
    fn local_models_failed_load_returns_the_cli_stderr() {
        let dir = tempfile::tempdir().expect("dir");
        let cause = "local model qwen3.6-35b is not loaded on mini (loaded: lfm); local.models load qwen3.6-35b";
        let exe = FakeExe::new(dir.path(), EXECUTABLE)
            .stderr(format!("{cause}\n"))
            .exit(1)
            .install();
        let ctx = ctx_for(dir.path(), &[(EXECUTABLE, exe.as_path())], &[], &[], &[]);
        let failure = run(&ctx, no_remote, &json!({"op": "load", "id": "qwen3.6-35b"}))
            .expect_err("load fails");
        assert_eq!(failure.cause, cause);
        assert_eq!(recorded_args(&exe), ["load", "qwen3.6-35b"]);
    }
}
