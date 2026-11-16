//! Failed systemd user units on this host become Info incidents: the card
//! shows in `odin view` and in live working memory, nobody is paged, and it
//! resolves only once a later invocation of the unit runs clean. Leaving the
//! failed set is not enough: a deploy's `reset-failed` and the next start both
//! do that, so the pump remembers the failed InvocationID and asks systemd.
//! The journal's failure records rebuild that memory when odind restarts.
//! A long-running daemon that comes back up never exits 0, so a new active
//! invocation with `Result=success` also resolves the card.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::Duration as StdDuration;

use odin_huginn::incidents::IncidentSeverityView;
use odin_process::ManagerScope;

use crate::incidents::{IncidentDesk, RaisedIncident};

const POLL: StdDuration = StdDuration::from_secs(60);
/// systemd's "Failed with result" journal record (SD_MESSAGE_UNIT_FAILURE_RESULT).
const UNIT_FAILURE_RESULT: &str = "d9b373ed55a64feb8242e02dbe79a49c";

pub(super) fn arm_unit_failure_pump(
    pumps: &mut tokio::task::JoinSet<Result<(), String>>,
    desk: Arc<IncidentDesk>,
) {
    pumps.spawn(async move {
        // Unit -> the InvocationID that failed.
        let mut open = BTreeMap::new();
        match journal_failures().await {
            Ok(failures) => {
                for (unit, failure) in failures {
                    match state_of(&unit).await {
                        Ok(state)
                            if state.loaded && !state.ran_clean_since(&failure.invocation) =>
                        {
                            desk.restate(incident(&unit, failure.detail));
                            open.insert(unit, failure.invocation);
                        }
                        // A transient scope or a removed unit cannot run again.
                        Ok(state) if !state.loaded => {
                            desk.clear(&signature(&unit), GONE);
                        }
                        Ok(_) => {}
                        Err(error) => tracing::warn!("failed-unit recall: {error}"),
                    }
                }
            }
            Err(error) => tracing::warn!("failed-unit recall: {error}"),
        }
        let mut ticker = tokio::time::interval(POLL);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            ticker.tick().await;
            let failed = match failed_units().await {
                Ok(failed) => failed,
                Err(error) => {
                    tracing::warn!("failed-unit poll: {error}");
                    continue;
                }
            };
            for unit in &failed {
                let state = match state_of(unit).await {
                    Ok(state) => state,
                    Err(error) => {
                        tracing::warn!("failed-unit poll: {error}");
                        continue;
                    }
                };
                if open.get(unit) != Some(&state.invocation) {
                    desk.raise(incident(unit, state.detail(unit)));
                    open.insert(unit.clone(), state.invocation);
                }
            }
            let recovered = open.iter().filter(|(unit, _)| !failed.contains(*unit));
            let mut cleared = Vec::new();
            for (unit, invocation) in recovered {
                match state_of(unit).await {
                    Ok(state) if state.ran_clean_since(invocation) => {
                        desk.clear(&signature(unit), "a later invocation ran clean");
                        cleared.push(unit.clone());
                    }
                    Ok(state) if !state.loaded => {
                        desk.clear(&signature(unit), GONE);
                        cleared.push(unit.clone());
                    }
                    Ok(state) if running_again(&state, invocation) => {
                        let reason = format!("running again since {}", when(&state.active_entered));
                        desk.clear(&signature(unit), &reason);
                        cleared.push(unit.clone());
                    }
                    Ok(_) => {}
                    Err(error) => tracing::warn!("failed-unit poll: {error}"),
                }
            }
            for unit in cleared {
                open.remove(&unit);
            }
        }
    });
}

const GONE: &str = "the unit no longer exists";

fn incident(unit: &str, detail: String) -> RaisedIncident {
    RaisedIncident {
        source: format!("systemd:{unit}"),
        severity: IncidentSeverityView::Info,
        summary: format!("{unit} failed"),
        detail,
        affected: vec![unit.to_owned()],
        signature: signature(unit),
    }
}

fn signature(unit: &str) -> String {
    format!("unit-failed:{unit}")
}

async fn command(program: &str, args: &[&str]) -> Result<String, String> {
    let output = tokio::process::Command::new(program)
        .arg("--user")
        .args(args)
        .output()
        .await
        .map_err(|error| format!("{program} --user {}: {error}", args.join(" ")))?;
    if !output.status.success() {
        return Err(format!(
            "{program} --user {} exited {}: {}",
            args.join(" "),
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

async fn failed_units() -> Result<BTreeSet<String>, String> {
    let names = tokio::task::spawn_blocking(|| odin_process::failed_units(ManagerScope::User))
        .await
        .map_err(|error| format!("failed-unit list stopped: {error}"))?;
    Ok(names?.into_iter().collect())
}

/// A daemon that failed earlier is running again: a different invocation is
/// active and its last result is success. Long-running units never exit 0.
fn running_again(state: &UnitState, failed_invocation: &str) -> bool {
    state.invocation != failed_invocation && state.active == "active" && state.result == "success"
}

/// What systemd says about a unit's latest invocation.
#[derive(Debug, Default, PartialEq)]
struct UnitState {
    loaded: bool,
    invocation: String,
    active: String,
    result: String,
    exit_status: String,
    exit_kind: String,
    started_monotonic: u64,
    exited_monotonic: u64,
    queued: bool,
    changed: String,
    active_entered: String,
}

impl UnitState {
    /// A different invocation actually exited normally with status 0.
    /// Queued/running work, reset-failed and a clean start are not recovery.
    fn ran_clean_since(&self, failed: &str) -> bool {
        !self.invocation.is_empty()
            && self.invocation != failed
            && self.result == "success"
            && self.exit_status == "0"
            && self.exit_kind == "1"
            && self.started_monotonic > 0
            && self.exited_monotonic >= self.started_monotonic
            && !self.queued
            && matches!(self.active.as_str(), "inactive" | "active")
    }

    /// Why and when, from systemd's own fields; the journal says the rest.
    fn detail(&self, unit: &str) -> String {
        format!(
            "Result={} ExecMainStatus={} at {}; journalctl --user -u {unit} has its log",
            self.result,
            self.exit_status,
            when(&self.changed)
        )
    }
}

/// The user manager's view of one unit, read over D-Bus.
async fn state_of(unit: &str) -> Result<UnitState, String> {
    let unit = unit.to_owned();
    let read =
        tokio::task::spawn_blocking(move || odin_process::unit_state(ManagerScope::User, &unit))
            .await
            .map_err(|error| format!("unit read stopped: {error}"))?;
    Ok(parse_state(&read?))
}

/// The time a `@<unix seconds>` stamp from `unit_state` names.
fn when(stamp: &str) -> String {
    stamp
        .strip_prefix('@')
        .and_then(|seconds| seconds.parse::<i64>().ok())
        .and_then(|seconds| time::OffsetDateTime::from_unix_timestamp(seconds).ok())
        .map_or_else(|| "an unrecorded time".to_owned(), |at| at.to_string())
}

fn parse_state(shown: &BTreeMap<String, String>) -> UnitState {
    let mut state = UnitState::default();
    for (key, value) in shown {
        let value = value.to_owned();
        match key.as_str() {
            "LoadState" => state.loaded = value == "loaded",
            "InvocationID" => state.invocation = value,
            "ActiveState" => state.active = value,
            "Result" => state.result = value,
            "ExecMainStatus" => state.exit_status = value,
            "ExecMainCode" => state.exit_kind = value,
            "ExecMainStartTimestampMonotonic" => {
                state.started_monotonic = value.parse().unwrap_or(0)
            }
            "ExecMainExitTimestampMonotonic" => state.exited_monotonic = value.parse().unwrap_or(0),
            "Job" => {
                state.queued = value
                    .split_whitespace()
                    .next()
                    .is_some_and(|job| job != "0")
            }
            "StateChangeTimestamp" => state.changed = value,
            "ActiveEnterTimestamp" => state.active_entered = value,
            _ => {}
        }
    }
    state
}

/// One unit's last failure the journal recorded.
#[derive(Debug, PartialEq)]
struct JournalFailure {
    invocation: String,
    detail: String,
}

async fn journal_failures() -> Result<BTreeMap<String, JournalFailure>, String> {
    let records = command(
        "journalctl",
        &[
            "--output=json",
            "--no-pager",
            "--output-fields=USER_UNIT,USER_INVOCATION_ID,UNIT_RESULT",
            &format!("MESSAGE_ID={UNIT_FAILURE_RESULT}"),
        ],
    )
    .await?;
    Ok(parse_journal_failures(&records))
}

/// Records come oldest first, so each unit keeps its latest failure.
fn parse_journal_failures(records: &str) -> BTreeMap<String, JournalFailure> {
    let mut failures = BTreeMap::new();
    for record in records.lines() {
        let Ok(record) = serde_json::from_str::<serde_json::Value>(record) else {
            continue;
        };
        let field = |name: &str| record.get(name).and_then(serde_json::Value::as_str);
        let (Some(unit), Some(invocation)) = (field("USER_UNIT"), field("USER_INVOCATION_ID"))
        else {
            continue;
        };
        let at = field("__REALTIME_TIMESTAMP")
            .and_then(|micros| micros.parse::<i128>().ok())
            .and_then(|micros| time::OffsetDateTime::from_unix_timestamp_nanos(micros * 1000).ok())
            .map_or_else(|| "an unrecorded time".to_owned(), |at| at.to_string());
        failures.insert(
            unit.to_owned(),
            JournalFailure {
                invocation: invocation.to_owned(),
                detail: format!(
                    "Result={} at {at}; journalctl --user -u {unit} has its log",
                    field("UNIT_RESULT").unwrap_or("unrecorded")
                ),
            },
        );
    }
    failures
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `unit_state` text, as the properties map the poll reads.
    fn state_of(text: String) -> UnitState {
        let shown = text
            .lines()
            .filter_map(|line| line.split_once('='))
            .map(|(key, value)| (key.to_owned(), value.to_owned()))
            .collect();
        parse_state(&shown)
    }

    /// A deploy's reset-failed keeps the failed InvocationID: still open.
    /// Only a later invocation that exited 0 resolves the card.
    #[test]
    fn only_a_later_clean_invocation_resolves() {
        let state = |invocation: &str, active: &str, status: &str| {
            state_of(format!(
                "LoadState=loaded\nInvocationID={invocation}\nActiveState={active}\n\
                 Result=success\nExecMainStatus={status}\nExecMainCode=1\n\
                 ExecMainStartTimestampMonotonic=100\nExecMainExitTimestampMonotonic=200\nJob=0\n"
            ))
        };
        assert!(!state("a1", "inactive", "1").ran_clean_since("a1"));
        assert!(!state("b2", "activating", "0").ran_clean_since("a1"));
        assert!(state("b2", "inactive", "0").ran_clean_since("a1"));
        let mut running = state("b2", "active", "0");
        running.exit_kind = "0".to_owned();
        running.exited_monotonic = 0;
        assert!(!running.ran_clean_since("a1"));
        let mut queued = state("b2", "inactive", "0");
        queued.queued = true;
        assert!(!queued.ran_clean_since("a1"));
        assert!(!state("b2", "inactive", "1").ran_clean_since("a1"));
    }

    /// A transient scope that is gone reads as not loaded, which clears its card.
    #[test]
    fn a_vanished_unit_reads_as_not_loaded() {
        assert!(!state_of("LoadState=not-found\nInvocationID=\n".to_owned()).loaded);
        assert!(state_of("LoadState=loaded\n".to_owned()).loaded);
    }
}
