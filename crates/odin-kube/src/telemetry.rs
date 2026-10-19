//! Pods emit `ODIN-STATUS {json}` on stdout; status is read through the
//! Kubernetes log API rather than host paths. Watchdogs use the latest
//! counters, while status queries compare the two newest reports.

use std::collections::BTreeMap;

use serde_json::Value;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

pub const STATUS_PREFIX: &str = "ODIN-STATUS ";

pub const STATUS_TAIL_LINES: i64 = 200;

fn status_object(line: &str) -> Option<serde_json::Map<String, Value>> {
    serde_json::from_str(line.trim().strip_prefix(STATUS_PREFIX)?).ok()
}

/// The numeric counters of the newest status line in `log`.
pub fn latest_status(log: &str) -> Option<BTreeMap<String, f64>> {
    log.lines().rev().find_map(|line| {
        Some(
            status_object(line)?
                .into_iter()
                .filter_map(|(key, value)| value.as_f64().map(|number| (key, number)))
                .collect(),
        )
    })
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
        Value::String(text) => Some(text.chars().take(40).collect()),
        Value::Bool(flag) => Some(flag.to_string()),
        _ => None,
    }
}

/// One delta line from a timestamped log (`timestamps=true`: every line is
/// `<RFC 3339> <text>`): each field of the newest status, with its value in
/// the status before when it changed, and how long ago the newest was
/// printed. `None` when the pod has printed no status.
pub fn status_delta(log: &str, now: OffsetDateTime) -> Option<String> {
    let mut reports = log.lines().rev().filter_map(|line| {
        let (stamp, text) = line.split_once(' ')?;
        let at = OffsetDateTime::parse(stamp, &Rfc3339).ok()?;
        Some((at, status_object(text)?))
    });
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
    fn the_delta_compares_the_newest_status_with_the_one_before() {
        let log = "2026-10-02T11:00:00Z starting\n\
                   2026-10-02T11:00:10Z ODIN-STATUS {\"iteration\": 8100, \"residual\": 0.0000123, \"phase\": \"solve\"}\n\
                   2026-10-02T11:00:15Z ODIN-STATUS {broken\n\
                   2026-10-02T11:00:20Z ODIN-STATUS {\"iteration\": 8200, \"residual\": 0.0000084, \"phase\": \"solve\", \"courant\": 0.74}\n\
                   2026-10-02T11:00:21Z noise\n";
        let now = OffsetDateTime::parse("2026-10-02T11:00:32Z", &Rfc3339).unwrap();
        assert_eq!(
            status_delta(log, now).as_deref(),
            Some(
                "courant=0.74 | iteration=8200 (was 8100) | phase=solve | \
                 residual=8.40e-6 (was 1.23e-5) | reported 12s ago"
            )
        );
        assert_eq!(status_delta("2026-10-02T11:00:00Z hello\n", now), None);
    }
}
