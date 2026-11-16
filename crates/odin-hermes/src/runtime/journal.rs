//! `journal_read` — a user unit's journal on the authority host.
//!
//! The tool runs inside odind, so a local `journalctl --user -u <unit>` read
//! is the authority host's journal; nothing is followed, paged or written.
//! The readable units are the `unit` enum of the declared input schema
//! (odind by default). Every line passes the shared `odin_omp` redaction
//! before it leaves the tool, and a journal that cannot answer names its cause.

use std::path::Path;
use std::process::Command;
use std::sync::{Arc, LazyLock};

use odin_domain::Scope;
use odin_omp::capability_parameters;
use odin_omp::host_tools::{HostTool, HostToolError, RpcHostToolDefinition, ToolLoadMode};
use odin_omp::redact::redact_text;
use serde_json::{json, Value};

use super::tools::CapabilityTool;
use super::HermesRuntime;

const TOOL: &str = "journal_read";
/// The authority daemon's user unit, read when no unit is named.
const UNIT: &str = "odind";
/// The user units a read may name: the declared schema's `unit` enum.
static UNITS: LazyLock<Vec<String>> = LazyLock::new(|| {
    let schema: Value = serde_json::from_str(include_str!(
        "../../../../schemas/capability/journal.read.input.json"
    ))
    .expect("the journal.read input schema is JSON");
    serde_json::from_value(schema["properties"]["unit"]["enum"].clone())
        .expect("the journal.read input schema declares its unit enum")
});
const DEFAULT_LINES: i64 = 100;
const MAX_LINES: i64 = 200;
const MAX_SINCE_CHARS: usize = 128;
/// The levels a read may keep, most severe first. odind writes every line
/// to stderr, so journald files them all at priority info and `-p` cannot
/// tell an ERROR from an INFO; for odind the level is matched in the line
/// instead, and for every other unit it is journald's priority.
const LEVELS: &[&str] = &["error", "warn", "info"];

/// journald's priority for `level`, for units other than odind.
fn level_priority(level: &str) -> &'static str {
    match level {
        "error" => "err",
        "warn" => "warning",
        _ => "info",
    }
}

/// The `journalctl --grep` pattern keeping tracing lines at `level` or
/// worse: the message starts with the tracing timestamp, then the level.
fn level_pattern(level: &str) -> &'static str {
    match level {
        "error" => "^[0-9T:.-]+Z +ERROR ",
        "warn" => "^[0-9T:.-]+Z +(ERROR|WARN) ",
        _ => "^[0-9T:.-]+Z +(ERROR|WARN|INFO) ",
    }
}

/// One read's arguments: the unit and the tail it keeps.
struct Query {
    unit: String,
    lines: i64,
    since: Option<String>,
    level: Option<String>,
}

/// `program` overrides the `journalctl` binary. Production always passes
/// `None` (PATH lookup). Tests pass their own executable so parallel
/// `cargo test` does not share process environment.
fn read_with(query: &Query, program: Option<&Path>) -> Result<Value, HostToolError> {
    let Query {
        unit,
        lines,
        since,
        level,
    } = query;
    let (since, level) = (since.as_deref(), level.as_deref());
    let mut command = match program {
        Some(program) => Command::new(program),
        None => Command::new("journalctl"),
    };
    command
        .args([
            "--user",
            "-u",
            unit.as_str(),
            "--no-pager",
            "-o",
            "short-iso",
            "-n",
        ])
        .arg(lines.to_string());
    if let Some(since) = since {
        command.args(["--since", since]);
    }
    match level {
        Some(level) if unit == UNIT => {
            command.args(["--case-sensitive=true", "--grep", level_pattern(level)]);
        }
        Some(level) => {
            command.args(["-p", level_priority(level)]);
        }
        None => {}
    }
    let output = command.output().map_err(|error| {
        HostToolError::unavailable(TOOL, format!("the {unit} journal is unreadable: {error}"))
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
                format!("the {unit} journal is unreadable: journalctl exited with {code}")
            } else {
                format!("the {unit} journal is unreadable: journalctl: {stderr}")
            },
        ));
    }
    if no_entries {
        // A filtered read that matches nothing is a real answer (no errors
        // since …); an unfiltered one means this host's user journal holds
        // nothing from the unit at all.
        if since.is_none() && level.is_none() {
            return Err(HostToolError::unavailable(TOOL, format!(
                "this host's user journal has no {unit} entries: the {unit} unit is unknown here or has not logged"
            )));
        }
        return Ok(json!({ "lines": [] }));
    }
    let lines: Vec<String> = redact_text(stdout).lines().map(str::to_owned).collect();
    Ok(json!({ "lines": lines }))
}

fn parse_read(arguments: &Value) -> Result<Query, HostToolError> {
    let unit = match arguments.get("unit") {
        None | Some(Value::Null) => UNIT.to_owned(),
        Some(Value::String(unit)) if UNITS.contains(unit) => unit.to_owned(),
        Some(_) => {
            return Err(HostToolError::Arguments {
                tool: TOOL,
                detail: format!("unit must be one of {}", UNITS.join(", ")),
            })
        }
    };
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
    Ok(Query {
        unit,
        lines,
        since,
        level,
    })
}

pub(super) fn journal_tools(_runtime: &Arc<HermesRuntime>, tools: &mut Vec<Arc<dyn HostTool>>) {
    let handler = move |_scope: Scope, arguments: Value| read_with(&parse_read(&arguments)?, None);
    tools.push(Arc::new(CapabilityTool::plain_without_prerequisites(
        RpcHostToolDefinition {
            name: TOOL.into(),
            label: "Read a unit's journal".into(),
            description: "The last lines of a user unit's journal on the authority host \
                (unit, default odind: the brain, model and gateway units too), with \
                timestamps, secrets withheld: use it to see why a unit failed. lines is how \
                many to keep (default 100, at most 200); since is an optional journalctl time \
                such as 1 hour ago; level keeps lines at that severity or worse (error, warn, \
                info), and lines then counts the newest matches."
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
        let query = Query {
            unit: UNIT.to_owned(),
            lines,
            since: since.map(str::to_owned),
            level: level.map(str::to_owned),
        };
        read_with(&query, Some(fake.program()))
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

        // A declared unit reads its own journal, its level as journald's priority.
        let query = parse_read(&json!({"unit": "brain-load", "level": "error"})).expect("unit");
        read_with(&query, Some(fake.program())).expect("unit tail");
        assert_eq!(
            fake.argv(),
            "--user\n-u\nbrain-load\n--no-pager\n-o\nshort-iso\n-n\n100\n-p\nerr\n"
        );
        assert!(parse_read(&json!({"unit": "sshd"})).is_err());
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
