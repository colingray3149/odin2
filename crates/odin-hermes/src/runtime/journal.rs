//! `journal_read` — the odind journal on the authority host.
//!
//! The tool runs inside odind, so a local `journalctl --user -u odind` read
//! is the authority host's journal; nothing is followed, paged or written.
//! Every line passes the shared `odin_omp` redaction before it leaves the
//! tool, and a journal that cannot answer names its cause.

use std::path::Path;
use std::process::Command;
use std::sync::Arc;

use odin_domain::Scope;
use odin_omp::capability_parameters;
use odin_omp::host_tools::{HostTool, HostToolError, RpcHostToolDefinition, ToolLoadMode};
use odin_omp::redact::redact_text;
use serde_json::{json, Value};

use super::tools::CapabilityTool;
use super::HermesRuntime;

const TOOL: &str = "journal_read";
/// The authority daemon's user unit; the read is fixed to it.
const UNIT: &str = "odind";
const DEFAULT_LINES: i64 = 100;
const MAX_LINES: i64 = 200;
const MAX_SINCE_CHARS: usize = 128;
/// odind's own tracing levels, most severe first. odind writes every line
/// to stderr, so journald files them all at priority info and `-p` cannot
/// tell an ERROR from an INFO; the level is matched in the line instead.
const LEVELS: &[&str] = &["error", "warn", "info"];

/// The `journalctl --grep` pattern keeping tracing lines at `level` or
/// worse: the message starts with the tracing timestamp, then the level.
fn level_pattern(level: &str) -> &'static str {
    match level {
        "error" => "^[0-9T:.-]+Z +ERROR ",
        "warn" => "^[0-9T:.-]+Z +(ERROR|WARN) ",
        _ => "^[0-9T:.-]+Z +(ERROR|WARN|INFO) ",
    }
}

fn read(lines: i64, since: Option<&str>, level: Option<&str>) -> Result<Value, HostToolError> {
    read_with(lines, since, level, None)
}

/// `program` overrides the `journalctl` binary. Production always passes
/// `None` (PATH lookup). Tests pass their own executable so parallel
/// `cargo test` does not share process environment.
fn read_with(
    lines: i64,
    since: Option<&str>,
    level: Option<&str>,
    program: Option<&Path>,
) -> Result<Value, HostToolError> {
    let mut command = match program {
        Some(program) => Command::new(program),
        None => Command::new("journalctl"),
    };
    command
        .args(["--user", "-u", UNIT, "--no-pager", "-o", "short-iso", "-n"])
        .arg(lines.to_string());
    if let Some(since) = since {
        command.args(["--since", since]);
    }
    if let Some(level) = level {
        command.args(["--case-sensitive=true", "--grep", level_pattern(level)]);
    }
    let output = command.output().map_err(|error| {
        HostToolError::unavailable(TOOL, format!("the {UNIT} journal is unreadable: {error}"))
    })?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stdout = stdout.trim_end();
    let no_entries = stdout.is_empty() || stdout == "-- No entries --";
    // `journalctl --grep` exits 1, silently, when nothing matches.
    let no_match = level.is_some()
        && no_entries
        && output.status.code() == Some(1)
        && output.stderr.iter().all(u8::is_ascii_whitespace);
    if !output.status.success() && !no_match {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_owned();
        let code = output.status.code().unwrap_or(-1);
        return Err(HostToolError::unavailable(
            TOOL,
            if stderr.is_empty() {
                format!("the {UNIT} journal is unreadable: journalctl exited with {code}")
            } else {
                format!("the {UNIT} journal is unreadable: journalctl: {stderr}")
            },
        ));
    }
    if no_entries {
        // A filtered read that matches nothing is a real answer (no errors
        // since …); an unfiltered one means this host's user journal holds
        // nothing from the unit at all.
        if since.is_none() && level.is_none() {
            return Err(HostToolError::unavailable(TOOL, format!(
                "this host's user journal has no {UNIT} entries: the {UNIT} unit is unknown here or has not logged"
            )));
        }
        return Ok(json!({ "lines": [] }));
    }
    let lines: Vec<String> = redact_text(stdout).lines().map(str::to_owned).collect();
    Ok(json!({ "lines": lines }))
}

fn parse_read(arguments: &Value) -> Result<(i64, Option<String>, Option<String>), HostToolError> {
    let lines = match arguments.get("lines") {
        None | Some(Value::Null) => DEFAULT_LINES,
        Some(value) => value
            .as_i64()
            .filter(|lines| (1..=MAX_LINES).contains(lines))
            .ok_or_else(|| HostToolError::Arguments {
                tool: TOOL,
                detail: format!("lines must be an integer from 1 to {MAX_LINES}"),
            })?,
    };
    let since = match arguments.get("since") {
        None | Some(Value::Null) => None,
        Some(Value::String(since)) => {
            let trimmed = since.trim();
            if trimmed.is_empty() || trimmed.len() > MAX_SINCE_CHARS {
                return Err(HostToolError::Arguments {
                    tool: TOOL,
                    detail: format!(
                        "since must be 1 to {MAX_SINCE_CHARS} characters, e.g. 1 hour ago"
                    ),
                });
            }
            Some(trimmed.to_owned())
        }
        Some(_) => {
            return Err(HostToolError::Arguments {
                tool: TOOL,
                detail: "since must be a string".to_owned(),
            })
        }
    };
    let level = match arguments.get("level") {
        None | Some(Value::Null) => None,
        Some(Value::String(level)) => {
            if LEVELS.contains(&level.as_str()) {
                Some(level.to_owned())
            } else {
                return Err(HostToolError::Arguments {
                    tool: TOOL,
                    detail: format!("level must be one of {}", LEVELS.join(", ")),
                });
            }
        }
        Some(_) => {
            return Err(HostToolError::Arguments {
                tool: TOOL,
                detail: "level must be a string".to_owned(),
            })
        }
    };
    Ok((lines, since, level))
}

pub(super) fn journal_tools(_runtime: &Arc<HermesRuntime>, tools: &mut Vec<Arc<dyn HostTool>>) {
    let handler = move |_scope: Scope, arguments: Value| {
        let (lines, since, level) = parse_read(&arguments)?;
        read(lines, since.as_deref(), level.as_deref())
    };
    tools.push(Arc::new(CapabilityTool::plain_without_prerequisites(
        RpcHostToolDefinition {
            name: TOOL.into(),
            label: "Read the odind journal".into(),
            description: "The last lines of the odind journal on the authority host, with \
                timestamps, secrets withheld: use it when the owner asks to check odind's logs or \
                whether Odin is healthy. lines is how many to keep (default 100, at most 200); \
                since is an optional journalctl time such as 1 hour ago; level keeps only \
                odind's own lines at that severity or worse (error, warn, info), and lines \
                then counts the newest matches."
                .into(),
            parameters: capability_parameters!("journal.read"),
            hidden: false,
            load_mode: ToolLoadMode::Discoverable,
        },
        Box::new(handler),
    )));
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;

    /// A private fake `journalctl`. Each install writes its own executable
    /// that records argv next to itself; nothing is put on PATH or in the
    /// process environment, so parallel tests cannot clobber each other.
    struct FakeJournalctl {
        _root: tempfile::TempDir,
        program: PathBuf,
        argv: PathBuf,
    }

    /// Shell single quotes, so a temp path with quotes still round-trips.
    fn shell_single_quote(value: &str) -> String {
        format!("'{}'", value.replace('\'', "'\\''"))
    }

    impl FakeJournalctl {
        fn install(body: &str) -> Self {
            let root = tempfile::tempdir().expect("temp dir");
            let program = root.path().join("journalctl");
            let argv = root.path().join("argv");
            let script = format!(
                "#!/bin/sh\nargv={}\n{body}",
                shell_single_quote(&argv.display().to_string())
            );
            std::fs::write(&program, script).expect("fake journalctl");
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&program, std::fs::Permissions::from_mode(0o755))
                .expect("chmod");
            Self {
                _root: root,
                program,
                argv,
            }
        }

        fn program(&self) -> &Path {
            &self.program
        }

        fn argv(&self) -> String {
            std::fs::read_to_string(&self.argv).expect("recorded argv")
        }
    }

    fn read_fake(
        fake: &FakeJournalctl,
        lines: i64,
        since: Option<&str>,
        level: Option<&str>,
    ) -> Result<Value, HostToolError> {
        read_with(lines, since, level, Some(fake.program()))
    }

    /// The real read path: exact argv to journalctl, redacted lines back.
    #[test]
    fn the_tail_reads_redacts_and_names_the_query() {
        let fake = FakeJournalctl::install(
            "printf '%s\\n' \"$@\" > \"$argv\"\nprintf '%s\\n' \
             '2026-10-20T19:53:02-07:00 mini odind[421]: ERROR odind::pumps: brain warm for seat sinmara failed: postgres timed out' \
             '2026-10-20T19:53:03-07:00 mini odind[421]: WARN odin_hermes::runtime: retry token=sk-live-abc123 soon'\n",
        );
        let result = read_fake(&fake, 100, None, None).expect("default tail");
        assert_eq!(
            fake.argv(),
            "--user\n-u\nodind\n--no-pager\n-o\nshort-iso\n-n\n100\n"
        );
        let lines = result["lines"].as_array().expect("lines");
        assert_eq!(lines.len(), 2);
        assert!(lines[0]
            .as_str()
            .unwrap()
            .contains("ERROR odind::pumps: brain warm"));
        let second = lines[1].as_str().unwrap();
        assert!(second.contains("[withheld]"), "{second}");
        assert!(!second.contains("sk-live-abc123"), "{second}");

        let result =
            read_fake(&fake, 200, Some("1 hour ago"), Some("warn")).expect("filtered tail");
        assert_eq!(
            fake.argv(),
            "--user\n-u\nodind\n--no-pager\n-o\nshort-iso\n-n\n200\n--since\n1 hour ago\n\
             --case-sensitive=true\n--grep\n^[0-9T:.-]+Z +(ERROR|WARN) \n"
        );
        assert_eq!(result["lines"].as_array().expect("lines").len(), 2);
    }

    /// A journalctl that cannot answer names its cause.
    #[test]
    fn a_failing_journalctl_names_its_cause() {
        let fake = FakeJournalctl::install("echo 'Failed to parse timestamp: zz' >&2\nexit 1\n");
        let error = read_fake(&fake, 100, Some("zz"), None).expect_err("journalctl failed");
        assert!(
            error.to_string().contains("Failed to parse timestamp: zz"),
            "{error}"
        );
        // A filtered read that fails is still a failure, not "no matches".
        let error = read_fake(&fake, 100, Some("zz"), Some("error"))
            .expect_err("filtered journalctl failed");
        assert!(
            error.to_string().contains("Failed to parse timestamp: zz"),
            "{error}"
        );
    }
}
