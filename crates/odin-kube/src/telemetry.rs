//! Pods emit `ODIN-STATUS {json}` on stdout; status is read through the
//! Kubernetes log API rather than host paths. Watchdogs evaluate new reports,
//! while status queries compare the two newest reports.

use std::collections::BTreeMap;

use serde_json::{Map, Value};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

pub const STATUS_PREFIX: &str = "ODIN-STATUS ";

pub const STATUS_TAIL_LINES: i64 = 200;

/// Longest string status value shown in a delta line.
const STATUS_VALUE_CHARS: usize = 40;

fn status_object(line: &str) -> Option<Map<String, Value>> {
    serde_json::from_str(line.trim().strip_prefix(STATUS_PREFIX)?).ok()
}

/// The status reports of a timestamped log (`timestamps=true`), newest first: when the pod
/// printed each, and its JSON object.
fn reports(log: &str) -> impl Iterator<Item = (OffsetDateTime, Map<String, Value>)> + '_ {
    log.lines().rev().filter_map(|line| {
        let (stamp, text) = line.split_once(' ')?;
        let at = OffsetDateTime::parse(stamp, &Rfc3339).ok()?;
        Some((at, status_object(text)?))
    })
}

/// The newest status report of a timestamped log: when the pod printed it, and its JSON object.
pub fn latest_report(log: &str) -> Option<(OffsetDateTime, Map<String, Value>)> {
    reports(log).next()
}

/// The status reports of a timestamped log printed after `after` (all of them when `None`),
/// oldest first, so a monitor sees every sample between two reads, not just the newest.
pub fn reports_since(
    log: &str,
    after: Option<OffsetDateTime>,
) -> Vec<(OffsetDateTime, Map<String, Value>)> {
    let mut fresh: Vec<_> = reports(log)
        .take_while(|(at, _)| after.is_none_or(|after| *at > after))
        .collect();
    fresh.reverse();
    fresh
}

/// The numeric fields of one status report.
pub fn numeric_counters(object: &Map<String, Value>) -> BTreeMap<String, f64> {
    object
        .iter()
        .filter_map(|(key, value)| Some((key.clone(), value.as_f64()?)))
        .collect()
}

/// The `summary` text of the newest status line in `log`, when it has one.
pub fn latest_summary(log: &str) -> Option<String> {
    let newest = log.lines().rev().find_map(status_object)?;
    newest.get("summary")?.as_str().map(str::to_owned)
}

/// A number short enough for a one-line delta.
fn compact(number: f64) -> String {
    let magnitude = number.abs();
    if number.fract() == 0.0 && magnitude < 1e15 {
        format!("{number:.0}")
    } else if magnitude != 0.0 && !(1e-3..1e6).contains(&magnitude) {
        format!("{number:.2e}")
    } else {
        let fixed = format!("{number:.4}");
        fixed.trim_end_matches('0').trim_end_matches('.').to_owned()
    }
}

fn scalar(value: &Value) -> Option<String> {
    match value {
        Value::Number(number) => number.as_f64().map(compact),
        Value::String(text) => Some(text.chars().take(STATUS_VALUE_CHARS).collect()),
        Value::Bool(flag) => Some(flag.to_string()),
        _ => None,
    }
}

/// One delta line from a timestamped log (`timestamps=true`: every line is
/// `<RFC 3339> <text>`): each field of the newest status, with its value in
/// the status before when it changed, and how long ago the newest was
/// printed. `None` when the pod has printed no status.
pub fn status_delta(log: &str, now: OffsetDateTime) -> Option<String> {
    let mut reports = reports(log);
    let (at, newest) = reports.next()?;
    let previous = reports.next().map(|(_, object)| object);
    let mut fields: Vec<String> = newest
        .iter()
        .filter_map(|(key, value)| {
            let now_value = scalar(value)?;
            let was = previous
                .as_ref()
                .and_then(|previous| previous.get(key))
                .and_then(scalar)
                .filter(|was| *was != now_value);
            Some(match was {
                Some(was) => format!("{key}={now_value} (was {was})"),
                None => format!("{key}={now_value}"),
            })
        })
        .collect();
    let age = (now - at).whole_seconds().max(0);
    fields.push(format!("reported {age}s ago"));
    Some(fields.join(" | "))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_summary_is_the_newest_status_lines_even_behind_noise() {
        let log = "ODIN-STATUS {\"summary\": \"meshing\"}\n\
                   ODIN-STATUS {\"summary\": \"solving, 40% done\", \"iteration\": 5}\n\
                   solver chatter\n";
        assert_eq!(latest_summary(log).as_deref(), Some("solving, 40% done"));
        assert_eq!(latest_summary("ODIN-STATUS {\"iteration\": 5}\n"), None);
        assert_eq!(latest_summary("only noise\n"), None);
    }
}
