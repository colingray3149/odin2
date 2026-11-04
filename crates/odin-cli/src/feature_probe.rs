//! `odin feature-probe`: evaluate this host's `unit:` and `file:` probes, then exit.
//!
//! odind calls [`probe`] in-process for the local host and runs this command over SSH for
//! remote hosts. Probes are routed by host by the caller; this module reads only the local
//! systemd manager and the local filesystem. The other probe kinds are not evaluated here.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::io::{self, Write};
use std::path::PathBuf;
use std::time::Duration;

use clap::Args;
use odin_process::ManagerScope;
use odin_registry::schema::{Probe, UnitManager};
use serde::{Deserialize, Serialize};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

#[derive(Debug, Args)]
pub struct FeatureProbeArgs {
    /// JSON array of check strings, for example `["unit:pc user sinmara-desk 6h"]`.
    #[arg(long)]
    checks: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ProbeState {
    Pass,
    Fail,
    Unknown,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ProbeResult {
    pub check: String,
    pub state: ProbeState,
    pub detail: String,
    /// The evaluation time, RFC 3339.
    pub at: String,
}

pub fn feature_probe(arguments: FeatureProbeArgs, output: &mut impl Write) -> Result<(), String> {
    let texts: Vec<String> = serde_json::from_str(&arguments.checks)
        .map_err(|error| format!("--checks must be a JSON array of strings: {error}"))?;
    let checks = texts
        .iter()
        .map(|text| Probe::parse(text))
        .collect::<Result<Vec<_>, _>>()?;
    let results = probe(&checks, OffsetDateTime::now_utc());
    serde_json::to_writer(&mut *output, &results).map_err(|error| error.to_string())?;
    writeln!(output).map_err(|error| error.to_string())
}

/// Evaluate the `unit:` and `file:` checks against this host at `now`. Every other kind
/// answers unknown, and a failed read answers unknown with its cause; nothing here panics.
pub fn probe(checks: &[Probe], now: OffsetDateTime) -> Vec<ProbeResult> {
    let at = rfc3339(now);
    checks
        .iter()
        .map(|check| {
            let (state, detail) = match check {
                Probe::Unit {
                    manager,
                    unit,
                    max_age,
                    ..
                } => match odin_process::unit_state(manager_scope(*manager), unit) {
                    Ok(properties) => judge_unit(&properties, *max_age, now),
                    Err(error) => (ProbeState::Unknown, error),
                },
                Probe::File { path, max_age, .. } => file_state(path, *max_age, now),
                _ => (ProbeState::Unknown, "not a host check".to_owned()),
            };
            ProbeResult {
                check: describe(check),
                state,
                detail,
                at: at.clone(),
            }
        })
        .collect()
}

/// The systemd manager a check names. `system` and `user` are never mixed.
fn manager_scope(manager: UnitManager) -> ManagerScope {
    match manager {
        UnitManager::System => ManagerScope::System,
        UnitManager::User => ManagerScope::User,
    }
}

/// Judge one unit from its `systemctl show` properties, as read over D-Bus.
fn judge_unit(
    properties: &BTreeMap<String, String>,
    max_age: Option<Duration>,
    now: OffsetDateTime,
) -> (ProbeState, String) {
    let property = |key: &str| properties.get(key).map(String::as_str).unwrap_or_default();
    let result = property("Result");
    match max_age {
        None => match property("ActiveState") {
            "active" => (
                ProbeState::Pass,
                match unix_time(property("ActiveEnterTimestamp")) {
                    Some(since) => format!("active since {}", rfc3339(since)),
                    None => "active".to_owned(),
                },
            ),
            "failed" => (ProbeState::Fail, format!("failed ({result})")),
            "inactive" => (ProbeState::Fail, "inactive".to_owned()),
            "activating" | "reloading" => (ProbeState::Unknown, "starting".to_owned()),
            other => (ProbeState::Unknown, format!("state {other}")),
        },
        Some(max_age) => {
            // Systemd reports 0 for an exit it has not recorded since this boot.
            if matches!(property("ExecMainExitTimestampMonotonic"), "" | "0") {
                return (ProbeState::Unknown, "no run since boot".to_owned());
            }
            let Some(exit) = unix_time(property("ExecMainExitTimestamp")) else {
                return (ProbeState::Unknown, "no exit timestamp".to_owned());
            };
            if result != "success" {
                return (ProbeState::Fail, format!("failed ({result})"));
            }
            let status = property("ExecMainStatus");
            if status != "0" {
                return (ProbeState::Fail, format!("exit status {status}"));
            }
            let ago = elapsed(now, exit);
            if ago < max_age {
                (ProbeState::Pass, format!("last run {} ago", span(ago)))
            } else {
                (ProbeState::Fail, format!("last run {} ago", span(ago)))
            }
        }
    }
}

/// `@<seconds>` as written by `--timestamp=unix`; an empty or other value is absent.
fn unix_time(value: &str) -> Option<OffsetDateTime> {
    let seconds: i64 = value.strip_prefix('@')?.parse().ok()?;
    OffsetDateTime::from_unix_timestamp(seconds).ok()
}

fn file_state(path: &str, max_age: Option<Duration>, now: OffsetDateTime) -> (ProbeState, String) {
    let path = match expand_home(path, std::env::var_os("HOME")) {
        Ok(path) => path,
        Err(error) => return (ProbeState::Unknown, error),
    };
    let metadata = match std::fs::metadata(&path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return (ProbeState::Fail, "missing".to_owned())
        }
        Err(error) => return (ProbeState::Unknown, format!("unreadable: {error}")),
    };
    if metadata.len() == 0 {
        return (ProbeState::Fail, "empty".to_owned());
    }
    let modified = match metadata.modified() {
        Ok(modified) => OffsetDateTime::from(modified),
        Err(error) => return (ProbeState::Unknown, format!("no mtime: {error}")),
    };
    match max_age {
        Some(max_age) if elapsed(now, modified) >= max_age => (
            ProbeState::Fail,
            format!("stale {}", span(elapsed(now, modified))),
        ),
        _ => (ProbeState::Pass, format!("updated {}", rfc3339(modified))),
    }
}

/// `~/…` resolves under `$HOME`; any other path is used as written.
fn expand_home(path: &str, home: Option<OsString>) -> Result<PathBuf, String> {
    match path.strip_prefix("~/") {
        Some(rest) => home
            .map(|home| PathBuf::from(home).join(rest))
            .ok_or_else(|| "HOME is unset, so ~ cannot expand".to_owned()),
        None => Ok(PathBuf::from(path)),
    }
}

/// Time since `then`, never negative: a timestamp in the future counts as fresh.
fn elapsed(now: OffsetDateTime, then: OffsetDateTime) -> Duration {
    Duration::try_from(now - then).unwrap_or_default()
}

/// Whole hours from one hour up, otherwise whole minutes.
fn span(age: Duration) -> String {
    let hours = age.as_secs() / 3_600;
    if hours >= 1 {
        format!("{hours}h")
    } else {
        format!("{}m", age.as_secs() / 60)
    }
}

fn rfc3339(at: OffsetDateTime) -> String {
    at.format(&Rfc3339)
        .unwrap_or_else(|_| at.unix_timestamp().to_string())
}

/// The canonical check text, used as the result's `check` field.
fn describe(check: &Probe) -> String {
    match check {
        Probe::Http { url } => format!("http:{url}"),
        Probe::Unit {
            host,
            manager,
            unit,
            max_age,
        } => {
            let manager = match manager {
                UnitManager::System => "system",
                UnitManager::User => "user",
            };
            with_age(format!("unit:{host} {manager} {unit}"), *max_age)
        }
        Probe::File {
            host,
            path,
            max_age,
        } => with_age(format!("file:{host} {path}"), *max_age),
        Probe::Models { lane } => format!("models:{lane}"),
    }
}

fn with_age(text: String, max_age: Option<Duration>) -> String {
    let Some(age) = max_age else {
        return text;
    };
    let seconds = age.as_secs();
    let age = if seconds % 86_400 == 0 {
        format!("{}d", seconds / 86_400)
    } else if seconds % 3_600 == 0 {
        format!("{}h", seconds / 3_600)
    } else {
        format!("{}m", seconds / 60)
    };
    format!("{text} {age}")
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: i64 = 1_790_000_000;

    fn now() -> OffsetDateTime {
        OffsetDateTime::from_unix_timestamp(NOW).expect("fixed test time")
    }

    fn show(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(key, value)| ((*key).to_owned(), (*value).to_owned()))
            .collect()
    }

    /// Judge one `unit:` check against the properties its manager reports.
    fn judge(check: &str, pairs: &[(&str, &str)]) -> (ProbeState, String) {
        let Probe::Unit { max_age, .. } = Probe::parse(check).expect("check parses") else {
            panic!("{check} is not a unit check");
        };
        judge_unit(&show(pairs), max_age, now())
    }

    fn run_check(check: &str) -> ProbeResult {
        run_check_at(check, now())
    }

    fn run_check_at(check: &str, at: OffsetDateTime) -> ProbeResult {
        let parsed = Probe::parse(check).expect("check parses");
        probe(&[parsed], at).into_iter().next().expect("one result")
    }

    #[test]
    fn feature_probe_unit_failed_names_its_result() {
        let (state, detail) = judge(
            "unit:pc user sinmara-desk",
            &[("ActiveState", "failed"), ("Result", "exit-code")],
        );
        assert_eq!(state, ProbeState::Fail);
        assert_eq!(detail, "failed (exit-code)");
    }

    #[test]
    fn feature_probe_unit_with_age_passes_when_fresh_and_fails_when_stale() {
        let check = "unit:mini system backup.service 6h";
        let (state, detail) = judge(
            check,
            &[
                ("Result", "success"),
                ("ExecMainStatus", "0"),
                ("ExecMainExitTimestampMonotonic", "123456"),
                ("ExecMainExitTimestamp", "@1789996400"),
            ],
        );
        assert_eq!(state, ProbeState::Pass, "{detail}");
        assert_eq!(detail, "last run 1h ago");

        let (state, detail) = judge(
            "unit:mini system backup.service 1d",
            &[
                ("Result", "success"),
                ("ExecMainStatus", "0"),
                ("ExecMainExitTimestampMonotonic", "123456"),
                ("ExecMainExitTimestamp", "@1789740000"),
            ],
        );
        assert_eq!(state, ProbeState::Fail);
        assert_eq!(detail, "last run 72h ago");
    }

    #[test]
    fn feature_probe_file_present_missing_and_empty() {
        let dir = tempfile::tempdir().expect("tempdir");
        let present = dir.path().join("present");
        std::fs::write(&present, "data").expect("write");
        let present_path = present.display();
        let result = run_check(&format!("file:mini {present_path}"));
        assert_eq!(result.state, ProbeState::Pass);
        assert!(result.detail.starts_with("updated "), "{}", result.detail);

        let missing = dir.path().join("missing");
        let result = run_check(&format!("file:mini {}", missing.display()));
        assert_eq!(result.state, ProbeState::Fail);
        assert_eq!(result.detail, "missing");

        let empty = dir.path().join("empty");
        std::fs::write(&empty, "").expect("write");
        let result = run_check(&format!("file:mini {}", empty.display()));
        assert_eq!(result.state, ProbeState::Fail);
        assert_eq!(result.detail, "empty");
    }
}
