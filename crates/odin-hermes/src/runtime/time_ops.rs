//! `time.get_current_time` and `time.convert_time`: the native in-process
//! clock surface. Both operations resolve IANA zones and convert wall-clock
//! times with `jiff` inside the daemon and return one text block carrying the
//! JSON plus the same fields under `structuredContent`.

use jiff::tz::{Dst, TimeZone};
use jiff::{civil, Timestamp, Zoned};
use std::sync::Arc;

use odin_domain::Scope;
use odin_omp::capability_parameters;
use odin_omp::host_tools::{HostTool, HostToolError, RpcHostToolDefinition, ToolLoadMode};
use serde_json::{json, Value};

use super::tools::{parse_string, CapabilityTool};
use super::HermesRuntime;

/// The host tool names; the model's tool listing is keyed by them.
const GET_CURRENT_TIME: &str = "time_get_current_time";
const CONVERT_TIME: &str = "time_convert_time";

/// One IANA zone by its exact key, or a typed argument failure naming it.
fn zone(tool: &'static str, field: &str, name: &str) -> Result<TimeZone, HostToolError> {
    TimeZone::get(name).map_err(|error| HostToolError::Arguments {
        tool,
        detail: format!(
            "Invalid timezone: {field} {name:?} is not a known IANA time zone name: {error}"
        ),
    })
}

/// Whether `moment` sits in daylight saving time in its zone.
fn is_dst(moment: &Zoned) -> bool {
    moment.time_zone().to_offset_info(moment.timestamp()).dst() == Dst::Yes
}

/// `Monday`, `Tuesday`, ... in English.
fn day_of_week(date: civil::Date) -> &'static str {
    match date.weekday() {
        civil::Weekday::Monday => "Monday",
        civil::Weekday::Tuesday => "Tuesday",
        civil::Weekday::Wednesday => "Wednesday",
        civil::Weekday::Thursday => "Thursday",
        civil::Weekday::Friday => "Friday",
        civil::Weekday::Saturday => "Saturday",
        civil::Weekday::Sunday => "Sunday",
    }
}

/// One zone snapshot: ISO-8601 datetime to seconds precision, the zone's
/// own name, the weekday and its DST state.
fn zone_result(name: &str, moment: &Zoned) -> Value {
    json!({
        "timezone": name,
        "datetime": moment.strftime("%Y-%m-%dT%H:%M:%S%:z").to_string(),
        "day_of_week": day_of_week(moment.date()),
        "is_dst": is_dst(moment),
    })
}

/// The one result the host returns: the fields both as `structuredContent`
/// and as the JSON text block.
fn mcp_result(fields: Value) -> Value {
    json!({
        "content": [{"type": "text", "text": fields.to_string()}],
        "structuredContent": fields,
    })
}

/// `time.get_current_time`: `now` in one named zone.
fn current_time(timezone: &str, now: Timestamp) -> Result<Value, HostToolError> {
    let tz = zone(GET_CURRENT_TIME, "timezone", timezone)?;
    Ok(mcp_result(zone_result(timezone, &now.to_zoned(tz))))
}

/// `time.convert_time`: one wall-clock time on `now`'s date in a source zone,
/// mapped to a target zone. A time a clock change skips is rejected, an
/// ambiguous time resolves to its earlier offset, and the offset difference
/// is reported in hours.
fn convert_time(
    source: &str,
    time: &str,
    target: &str,
    now: Timestamp,
) -> Result<Value, HostToolError> {
    let invalid = |detail: String| HostToolError::Arguments {
        tool: CONVERT_TIME,
        detail,
    };
    let source_tz = zone(CONVERT_TIME, "source_timezone", source)?;
    let target_tz = zone(CONVERT_TIME, "target_timezone", target)?;
    let (hours, minutes) = time.split_once(':').ok_or_else(|| {
        invalid("Invalid time format. Expected HH:MM [24-hour format]".to_owned())
    })?;
    let (hours, minutes): (i8, i8) = match (hours.parse(), minutes.parse()) {
        (Ok(hours), Ok(minutes)) if (0..24).contains(&hours) && (0..60).contains(&minutes) => {
            (hours, minutes)
        }
        _ => {
            return Err(invalid(
                "Invalid time format. Expected HH:MM [24-hour format]".to_owned(),
            ))
        }
    };
    let today = now
        .to_zoned(source_tz.clone())
        .datetime()
        .with()
        .hour(hours)
        .minute(minutes)
        .second(0)
        .subsec_nanosecond(0)
        .build()
        .map_err(|error| invalid(format!("today in {source:?} is not representable: {error}")))?;
    let source_moment = source_tz
        .to_ambiguous_zoned(today)
        .earlier()
        .map_err(|error| invalid(format!("today in {source:?} is not representable: {error}")))?;
    // A wall-clock time skipped by a clock change (e.g. 02:30 on a DST
    // spring-forward day) does not survive a round trip through its own
    // zone; report it instead of silently shifting it.
    if source_moment.datetime() != today {
        return Err(invalid(format!(
            "Invalid time: {time} does not exist in {source} on {} (skipped by a clock change)",
            today.date()
        )));
    }
    let target_moment = source_moment.with_time_zone(target_tz);
    let difference_hours = target_moment
        .offset()
        .duration_since(source_moment.offset())
        .as_secs_f64()
        / 3600.0;
    let time_difference = if difference_hours.fract() == 0.0 {
        format!("{difference_hours:+.1}h")
    } else {
        format!("{difference_hours:+.2}",)
            .trim_end_matches('0')
            .trim_end_matches('.')
            .to_owned()
            + "h"
    };
    Ok(mcp_result(json!({
        "source": zone_result(source, &source_moment),
        "target": zone_result(target, &target_moment),
        "time_difference": time_difference,
    })))
}

/// Builds the two native time tools: read-only clock operations served
/// wholly in-process. Without a `timezone` the clock reads in the owner's.
pub(super) fn time_tools(runtime: &Arc<HermesRuntime>, tools: &mut Vec<Arc<dyn HostTool>>) {
    let runtime = Arc::clone(runtime);
    tools.push(Arc::new(CapabilityTool::plain_without_prerequisites(
        RpcHostToolDefinition {
            name: GET_CURRENT_TIME.into(),
            label: "Current time in a time zone".into(),
            description: "Get current time in a specific timezone, the owner's by default".into(),
            parameters: capability_parameters!("time.get_current_time"),
            hidden: false,
            load_mode: ToolLoadMode::Discoverable,
        },
        Box::new(move |_scope: Scope, arguments: Value| {
            let timezone = match arguments.get("timezone").filter(|zone| !zone.is_null()) {
                Some(_) => parse_string(&arguments, "timezone", 64)?,
                None => runtime.owner_time_zone(),
            };
            current_time(&timezone, Timestamp::now())
        }),
    )));
    tools.push(Arc::new(CapabilityTool::plain_without_prerequisites(
        RpcHostToolDefinition {
            name: CONVERT_TIME.into(),
            label: "Convert a time between zones".into(),
            description: "Convert time between timezones".into(),
            parameters: capability_parameters!("time.convert_time"),
            hidden: false,
            load_mode: ToolLoadMode::Discoverable,
        },
        Box::new(|_scope: Scope, arguments: Value| {
            let source = parse_string(&arguments, "source_timezone", 64)?;
            let time = parse_string(&arguments, "time", 32)?;
            let target = parse_string(&arguments, "target_timezone", 64)?;
            convert_time(&source, &time, &target, Timestamp::now())
        }),
    )));
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(instant: &str) -> Timestamp {
        instant.parse().expect("a fixed instant")
    }

    #[test]
    fn current_time_reports_the_named_zone_at_the_instant() {
        let result = current_time("Asia/Tokyo", at("2026-10-27T03:34:56Z")).unwrap();
        let fields = &result["structuredContent"];
        assert_eq!(fields["timezone"], "Asia/Tokyo");
        assert_eq!(fields["datetime"], "2026-10-27T12:34:56+09:00");
        assert_eq!(fields["day_of_week"], "Tuesday");
        assert_eq!(fields["is_dst"], false);
        assert_eq!(
            result["content"][0]["text"].as_str().expect("text block"),
            fields.to_string(),
            "the text block carries the same JSON"
        );
        let summer = current_time("America/New_York", at("2026-07-01T12:00:00Z")).unwrap();
        assert_eq!(
            summer["structuredContent"]["datetime"],
            "2026-07-01T08:00:00-04:00"
        );
        assert_eq!(summer["structuredContent"]["is_dst"], true);
    }

    #[test]
    fn convert_time_moves_a_wall_clock_across_zones() {
        let now = at("2026-10-27T10:00:00Z");
        let result = convert_time("UTC", "15:30", "Asia/Tokyo", now).unwrap();
        let fields = &result["structuredContent"];
        assert_eq!(fields["source"]["datetime"], "2026-10-27T15:30:00+00:00");
        assert_eq!(fields["target"]["datetime"], "2026-10-28T00:30:00+09:00");
        assert_eq!(fields["time_difference"], "+9.0h");
        // Kathmandu is UTC+5:45.
        let result = convert_time("UTC", "12:00", "Asia/Kathmandu", now).unwrap();
        assert_eq!(result["structuredContent"]["time_difference"], "+5.75h");
    }

    #[test]
    fn convert_time_refuses_a_skipped_time_and_takes_the_earlier_of_an_ambiguous_one() {
        let error = convert_time(
            "America/New_York",
            "02:30",
            "UTC",
            at("2026-03-08T12:00:00Z"),
        )
        .expect_err("02:30 does not exist on the spring-forward day");
        assert!(error.to_string().contains("skipped"), "{error}");
        let result = convert_time(
            "America/New_York",
            "01:30",
            "UTC",
            at("2026-11-01T12:00:00Z"),
        )
        .unwrap();
        assert_eq!(
            result["structuredContent"]["source"]["datetime"],
            "2026-11-01T01:30:00-04:00"
        );
    }
}
