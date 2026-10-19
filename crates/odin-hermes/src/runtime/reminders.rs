//! `reminder.*` and `time.zone.set`: the model surface over the durable
//! schedule, and the reconcile step that fires due rows.

use std::sync::Arc;

use jiff::{SignedDuration, Timestamp};
use odin_domain::Scope;
use odin_omp::host_tools::{HostTool, HostToolError, RpcHostToolDefinition, ToolLoadMode};
use serde_json::{json, Value};

use super::recovery::bridge_route;
use super::tools::{object_schema, parse_string, CapabilityTool};
use super::{ApprovedIntentExecution, HermesRuntime, IntentFailure};
use crate::schedule::{
    first_timed_event, ScheduleKind, ScheduleStatus, ScheduledItem, MAX_TEXT_CHARS,
};

fn unavailable(tool: &'static str) -> impl Fn(String) -> HostToolError {
    move |reason| HostToolError::Unavailable { tool, reason }
}

fn optional_str<'a>(arguments: &'a Value, key: &str) -> Result<Option<&'a str>, HostToolError> {
    match arguments.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(value)) if !value.trim().is_empty() => Ok(Some(value.trim())),
        Some(_) => Err(HostToolError::Arguments {
            tool: "reminder_set",
            detail: format!("{key} must be a non-empty string"),
        }),
    }
}

fn optional_minutes(
    arguments: &Value,
    key: &str,
    min: i64,
    max: i64,
) -> Result<Option<i64>, HostToolError> {
    match arguments.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(value) => value
            .as_i64()
            .filter(|value| (min..=max).contains(value))
            .map(Some)
            .ok_or_else(|| HostToolError::Arguments {
                tool: "reminder_set",
                detail: format!("{key} must be an integer in {min}..={max}"),
            }),
    }
}

fn repeat_arguments(arguments: &Value) -> Result<Option<(i64, u32)>, HostToolError> {
    let every = optional_minutes(arguments, "repeat_every_minutes", 1, 1440)?;
    let times = optional_minutes(arguments, "repeat_times", 1, 500)?;
    match (every, times) {
        (None, None) => Ok(None),
        (Some(every), Some(times)) => Ok(Some((every, times as u32))),
        _ => Err(HostToolError::Arguments {
            tool: "reminder_set",
            detail: "repeat_every_minutes and repeat_times must be supplied together; repeat_times counts additional firings after the first".to_owned(),
        }),
    }
}

impl HermesRuntime {
    fn resolve_reminder_time(
        &self,
        arguments: &Value,
        now: Timestamp,
    ) -> Result<(Timestamp, Option<String>), HostToolError> {
        let invalid = |detail: &str| HostToolError::Arguments {
            tool: "reminder_set",
            detail: detail.to_owned(),
        };
        let at = optional_str(arguments, "at")?;
        let in_minutes = optional_minutes(arguments, "in_minutes", 1, 576_000)?;
        let anchor_date = optional_str(arguments, "anchor_date")?;
        let account = optional_str(arguments, "anchor_account")?;
        let title_match = optional_str(arguments, "anchor_match")?;
        let lead = optional_minutes(arguments, "lead_minutes", 0, 720)?;
        if anchor_date.is_none() {
            for field in ["anchor_account", "anchor_match", "lead_minutes"] {
                if arguments.get(field).is_some_and(|value| !value.is_null()) {
                    return Err(invalid(&format!("{field} requires anchor_date")));
                }
            }
        }
        match (at, in_minutes, anchor_date) {
            (Some(at), None, None) => Ok((
                self.clock
                    .resolve_local(at)
                    .map_err(|error| invalid(&format!("at: {error}")))?,
                None,
            )),
            (None, Some(minutes), None) => Ok((now + SignedDuration::from_mins(minutes), None)),
            (None, None, Some(date)) => {
                let account = account
                    .ok_or_else(|| invalid("anchor_account names the calendar to anchor on"))?;
                let lead = lead.unwrap_or(30);
                let calendar = self.calendar.as_ref().ok_or_else(|| {
                    unavailable("reminder_set")("no calendar is configured".to_owned())
                })?;
                let (start, end) = self
                    .clock
                    .day_window(date)
                    .map_err(|error| invalid(&format!("anchor_date: {error}")))?;
                let events = calendar
                    .read_window(
                        &crate::calendar::CalendarWindow {
                            account: account.to_owned(),
                            start,
                            end,
                        },
                        super::now_utc(),
                    )
                    .map_err(|error| unavailable("reminder_set")(error.to_string()))?;
                let (event_at, title) = first_timed_event(
                    events
                        .iter()
                        .map(|event| (event.title.as_deref(), event.start.as_str())),
                    title_match,
                )
                .ok_or_else(|| {
                    unavailable("reminder_set")(format!(
                        "no timed event on {date} in {account}'s calendar matches"
                    ))
                })?;
                Ok((
                    event_at - SignedDuration::from_mins(lead),
                    Some(format!(
                        "{lead} min before {title} at {}",
                        self.clock.render(event_at.as_millisecond())
                    )),
                ))
            }
            _ => Err(invalid(
                "give exactly one of: at (local time), in_minutes, or anchor_date",
            )),
        }
    }

    /// How long until the next schedule row comes due (zero when one is),
    /// for the reconcile loop to sleep exactly that long.
    pub fn schedule_due_in(&self) -> Option<std::time::Duration> {
        let due = self.schedule.next_due_ms().ok()??;
        let wait = due.saturating_sub(Timestamp::now().as_millisecond()).max(0);
        Some(std::time::Duration::from_millis(
            u64::try_from(wait).unwrap_or(0),
        ))
    }

    /// Queues one unprompted conversation turn for an observed event (a
    /// delegated child finished, a monitor raised an anomaly), once per id.
    pub fn wake_once(&self, id: &str, text: &str) -> Result<bool, String> {
        let queued = self.schedule.wake_once(id, text, Timestamp::now())?;
        if queued {
            self.reconcile_wake.notify_one();
        }
        Ok(queued)
    }

    fn render_item(&self, item: &ScheduledItem) -> Value {
        json!({
            "id": item.id,
            "text": bounded_text(&item.text),
            "kind": item.kind,
            "fireAt": self.clock.render(item.fire_at_ms),
            "status": item.status,
            "anchor": item.anchor,
            "repeat": item.every_minutes.map(|every| json!({ "everyMinutes": every, "timesLeft": item.repeats_left })),
        })
    }

    fn owner_intents_queued(&self) -> bool {
        self.admitted.lock().is_ok_and(|queue| !queue.is_empty())
    }

    /// A wake the vehicle cannot run yet: back off without counting an attempt.
    fn defer_wake(&self, item: &ScheduledItem, detail: &str) -> Result<(), String> {
        self.schedule.hold_unresolved(&item.id, Timestamp::now())?;
        tracing::warn!(
            "odin-hermes: wake {} waiting for the vehicle (attempt unchanged): {detail}",
            item.id
        );
        Ok(())
    }

    /// Fires every due schedule row. Notifies go to the owner as a plain DM;
    /// wakes run as an unprompted turn of the bound conversation route. Repeating
    /// wakes bind their row and planned fire time, which survives retries and
    /// reopen; one-shot wakes retain their row identity. Failed delivery backs off
    /// and settles failed after [`crate::schedule::MAX_DELIVERY_ATTEMPTS`] attempts.
    ///
    /// A routine row is checked against its current declaration and its
    /// handoff recorded immediately before delivery: that is the boundary.
    /// A delivery already handed off finishes and records its outcome even
    /// if the declaration changes meanwhile.
    pub fn reconcile_schedule(&self) -> Result<usize, String> {
        let now = Timestamp::now();
        let mut fired = 0;
        for item in self.schedule.take_due(now)? {
            // Owner intents take priority; wakes stay queued until the route is available.
            let route = match item.kind {
                ScheduleKind::Notify => None,
                ScheduleKind::Wake if self.owner_intents_queued() => continue,
                ScheduleKind::Wake => {
                    let route = self
                        .approved_route
                        .lock()
                        .ok()
                        .and_then(|cell| cell.clone());
                    let Some(route) = route else { continue };
                    Some(route)
                }
            };
            let started_before = match routine_of(&item) {
                None => false,
                Some(routine) => {
                    if !self.routine_dispatchable(routine, &item)? {
                        continue;
                    }
                    match self.schedule.start_dispatch(&item.id)? {
                        Some(started) => started,
                        None => continue,
                    }
                }
            };
            let delivered = match item.kind {
                // One message per occurrence, its bytes frozen by the first
                // attempt (the late suffix included); a replay or retry sends
                // those bytes and an unknown outcome is never sent again.
                ScheduleKind::Notify => self
                    .notify_scheduled(&schedule_key(&item), || {
                        if is_routine(&item) {
                            // Routine DMs use the owner's text without a late suffix.
                            return item.text.clone();
                        }
                        let late = now.as_millisecond() - item.fire_at_ms > 10 * 60 * 1000;
                        let suffix = if late {
                            format!(" (was due {})", self.clock.render(item.fire_at_ms))
                        } else {
                            String::new()
                        };
                        format!("⏰ Reminder: {}{suffix}", item.text)
                    })
                    .map(drop)
                    .map_err(|error| Undelivered {
                        outcome_unknown: error.may_have_posted(),
                        detail: error.to_string(),
                    }),
                ScheduleKind::Wake => {
                    let Some(route) = route else { continue };
                    let key = schedule_key(&item);
                    let intent = ApprovedIntentExecution {
                        unprompted: true,
                        command_id: key.clone(),
                        idempotency_key: key,
                        content: if let Some(routine) = routine_of(&item) {
                            format!(
                                "[Routine {routine} from Odin — not a message from Colin. He set \
                                 this routine; it fires now: \"{}\". Act on it with your \
                                 governed tools. Your reply is the message Colin receives — \
                                 do not also send it with a messaging tool — so put only what \
                                 he needs in it, or answer exactly [quiet] if nothing does.]",
                                item.text
                            )
                        } else if item.event {
                            // Include event age because delivery may wait; verify current state before relaying.
                            format!(
                                "[Odin event observed {} ({} min ago) — not a message from \
                                 Colin: {}\nIt may be out of date: check the current state \
                                 with your governed reads before telling Colin anything, and \
                                 tell him only what he needs to know; if nothing here needs \
                                 him, answer exactly [quiet].]",
                                self.clock.render(item.created_at_ms),
                                (now.as_millisecond() - item.created_at_ms) / 60_000,
                                item.text
                            )
                        } else {
                            format!(
                                "[Scheduled wake from Odin — not a message from Colin. At {} \
                                 you set this for now: \"{}\". Act on it; tell Colin only what \
                                 he needs to know, or answer exactly [quiet] if nothing does.]",
                                self.clock.render(item.created_at_ms),
                                item.text
                            )
                        },
                    };
                    match bridge_route(route.execute(intent)) {
                        Ok(Ok(_)) => Ok(()),
                        // The vehicle is mid-turn, mid-rollover, or gone:
                        // the wake runs when it is back. None of these is a
                        // failed attempt, and the handoff had no effect.
                        Ok(Err(failure)) if wake_waits_for_vehicle(&failure) => {
                            if is_routine(&item) && !started_before {
                                self.schedule.undo_dispatch(&item.id)?;
                            }
                            self.defer_wake(&item, &failure.to_string())?;
                            continue;
                        }
                        Ok(Err(failure)) => Err(Undelivered {
                            detail: failure.to_string(),
                            outcome_unknown: false,
                        }),
                        Err(error) => Err(Undelivered {
                            detail: error.to_string(),
                            outcome_unknown: false,
                        }),
                    }
                }
            };
            match delivered {
                Ok(()) => {
                    let now = Timestamp::now();
                    self.schedule.mark_fired(&item.id, now)?;
                    if let Some(routine) = routine_of(&item) {
                        if let Err(error) = self.note_routine_fired(routine, &item, now) {
                            tracing::error!(
                                routine = %routine,
                                error = %error,
                                "odind: routine fired-record failed id={routine} error={error}"
                            );
                        }
                    }
                    fired += 1;
                }
                // The original send may have landed. Seal it so a later pass
                // cannot post it again, warn once under its own occurrence
                // key, and never send the original again. A warning that
                // provably did not go out waits; one that may have does not,
                // or a crash would send it twice. An acknowledged send whose
                // receipt write failed is not unknown: only that write is owed.
                Err(Undelivered {
                    detail,
                    outcome_unknown: true,
                }) => {
                    let key = schedule_key(&item);
                    if self.seal_scheduled(&key).map_err(|error| {
                        format!("cannot seal reminder {} delivery: {error}", item.id)
                    })? == crate::conversation::delivery::ScheduledSeal::Acknowledged
                    {
                        self.schedule.hold_unresolved(&item.id, Timestamp::now())?;
                        tracing::warn!(
                            "odin-hermes: reminder {} posted but its receipt is uncommitted",
                            item.id
                        );
                        continue;
                    }
                    let when = self.clock.render(item.fire_at_ms);
                    let notice = format!(
                        "I may have missed sending {} at {when}",
                        missed_label(&item)
                    );
                    let warning = format!("{key}:missed");
                    match self.notify_scheduled(&warning, || notice) {
                        Ok(_) => {
                            self.schedule.settle_uncertain(&item.id, Timestamp::now())?;
                        }
                        Err(error) if !error.may_have_posted() => {
                            self.schedule.hold_unresolved(&item.id, Timestamp::now())?;
                            tracing::warn!(
                                "odin-hermes: reminder {} uncertain notice not sent, will retry: {error}",
                                item.id
                            );
                        }
                        Err(error) => {
                            self.schedule.settle_uncertain(&item.id, Timestamp::now())?;
                            tracing::warn!(
                                "odin-hermes: reminder {} uncertain notice may have been sent: {error}",
                                item.id
                            );
                        }
                    }
                    tracing::warn!(
                        "odin-hermes: reminder {} outcome unknown, original not resent: {detail}",
                        item.id
                    );
                }
                Err(Undelivered { detail, .. }) => {
                    let gave_up = self.schedule.mark_failed(&item.id, Timestamp::now())?;
                    tracing::error!(
                        "odin-hermes: {} {} not delivered (attempt {}{}): {detail}",
                        if item.kind == ScheduleKind::Wake {
                            "wake"
                        } else {
                            "reminder"
                        },
                        item.id,
                        item.attempts + 1,
                        if gave_up { ", giving up" } else { "" },
                    );
                }
            }
        }
        Ok(fired)
    }
}

/// A delivery that did not complete, and whether its message may exist.
struct Undelivered {
    detail: String,
    outcome_unknown: bool,
}

/// A wake the vehicle cannot run yet: mid-turn, mid-rollover, lost, or the
/// model unavailable. Not a delivery that failed.
fn wake_waits_for_vehicle(failure: &IntentFailure) -> bool {
    match failure {
        IntentFailure::ConversationBusy
        | IntentFailure::VehicleLost
        | IntentFailure::ModelUnavailable { .. }
        | IntentFailure::SuccessorStartBackoff { .. }
        | IntentFailure::SuccessorStartExhausted { .. } => true,
        IntentFailure::Other(detail) => detail.contains("transition stays pending"),
        _ => false,
    }
}

fn missed_label(item: &ScheduledItem) -> String {
    match item.kind {
        ScheduleKind::Notify => format!("reminder \"{}\"", item.text),
        ScheduleKind::Wake if item.event => format!("report \"{}\"", item.text),
        ScheduleKind::Wake => format!("wake \"{}\"", item.text),
    }
}

/// The stable identity of one delivery of a row: a repeating row's
/// occurrence is its row and planned fire time, which survive retries and
/// reopen; a one-shot row is its id.
fn schedule_key(item: &ScheduledItem) -> String {
    if item.every_minutes.is_some() {
        format!("schedule-occurrence:{}:{}", item.id, item.fire_at_ms)
    } else {
        format!("schedule:{}", item.id)
    }
}

fn routine_of(item: &ScheduledItem) -> Option<&str> {
    item.anchor.as_deref()?.strip_prefix("routine:")
}

fn is_routine(item: &ScheduledItem) -> bool {
    routine_of(item).is_some()
}

pub(super) fn schedule_tools(runtime: &Arc<HermesRuntime>, tools: &mut Vec<Arc<dyn HostTool>>) {
    let settings = runtime.settings();
    let text_max = MAX_TEXT_CHARS as u64;
    {
        let runtime = Arc::clone(runtime);
        let handler = move |_scope: Scope, arguments: Value| {
            let text = parse_string(&arguments, "text", 4 * MAX_TEXT_CHARS)?;
            let repeat = repeat_arguments(&arguments)?;
            let kind = match optional_str(&arguments, "kind")? {
                None | Some("notify") => ScheduleKind::Notify,
                Some("wake") => ScheduleKind::Wake,
                Some(other) => {
                    return Err(HostToolError::Arguments {
                        tool: "reminder_set",
                        detail: format!("kind {other:?} is not notify or wake"),
                    })
                }
            };
            let now = Timestamp::now();
            let (fire_at, anchor) = runtime.resolve_reminder_time(&arguments, now)?;
            let mut item = runtime
                .schedule
                .add(kind, &text, fire_at, anchor, now)
                .map_err(unavailable("reminder_set"))?;
            if let Some((every, times)) = repeat {
                runtime
                    .schedule
                    .set_repeat(&item.id, every, times, now)
                    .map_err(|detail| HostToolError::Arguments {
                        tool: "reminder_set",
                        detail,
                    })?;
                item.every_minutes = Some(every);
                item.repeats_left = times;
            }
            runtime.reconcile_wake.notify_one();
            Ok(runtime.render_item(&item))
        };
        tools.push(Arc::new(CapabilityTool::plain_without_prerequisites(
            RpcHostToolDefinition {
                name: "reminder_set".into(),
                label: "Set a reminder".into(),
                description: "Schedules a reminder: notify sends the text; wake starts a turn. \
                 Give exactly one time: at (local YYYY-MM-DDTHH:MM), in_minutes, or \
                 anchor_date with anchor_account for the first timed calendar event that day. \
                 anchor_match filters its title; lead_minutes defaults to 30 before the event. \
                 Repetition requires both repeat_every_minutes and repeat_times; repeat_times \
                 counts additional firings after the first."
                    .into(),
                parameters: {
                    let mut schema = object_schema(
                    "reminder_set",
                    json!({
                        "text": { "type": "string", "minLength": 1, "maxLength": text_max },
                        "kind": { "type": "string", "enum": ["notify", "wake"] },
                        "at": { "type": "string", "minLength": 16, "maxLength": 19 },
                        "in_minutes": { "type": "integer", "minimum": 1, "maximum": 576000 },
                        "anchor_date": { "type": "string", "minLength": 10, "maxLength": 10 },
                        "anchor_account": super::adapters::account_schema(settings, true),
                        "anchor_match": { "type": "string", "minLength": 1, "maxLength": 100 },
                        "lead_minutes": { "type": "integer", "minimum": 0, "maximum": 720 },
                        "repeat_every_minutes": { "type": "integer", "minimum": 1, "maximum": 1440 },
                        "repeat_times": { "type": "integer", "minimum": 1, "maximum": 500, "description": "Additional firings after the first; required with repeat_every_minutes." }
                    }),
                    &["text"],
                    );
                    schema["dependencies"] = json!({
                        "repeat_every_minutes": ["repeat_times"],
                        "repeat_times": ["repeat_every_minutes"]
                    });
                    schema
                },
                hidden: false,
                load_mode: ToolLoadMode::Discoverable,
            },
            Box::new(handler),
        )));
    }
    {
        let runtime = Arc::clone(runtime);
        let handler = move |_scope: Scope, _arguments: Value| {
            let items = runtime
                .schedule
                .list()
                .map_err(unavailable("reminder_list"))?;
            let (listed, omitted) = compact_listing(&items);
            Ok(json!({
                "now": runtime.clock.line(Timestamp::now()),
                "reminders": listed.into_iter().map(|item| runtime.render_item(item)).collect::<Vec<_>>(),
                "olderSettledOmitted": omitted,
            }))
        };
        tools.push(Arc::new(CapabilityTool::plain_without_prerequisites(
            RpcHostToolDefinition {
                name: "reminder_list".into(),
                label: "List reminders".into(),
                description: "Lists pending reminders and wakes plus the few most recently \
                 fired or cancelled reminders, in Colin's local time."
                    .into(),
                parameters: object_schema("reminder_list", json!({}), &[]),
                hidden: false,
                load_mode: ToolLoadMode::Discoverable,
            },
            Box::new(handler),
        )));
    }
    {
        let runtime = Arc::clone(runtime);
        let handler = move |_scope: Scope, arguments: Value| {
            let id = parse_string(&arguments, "id", 32)?;
            let item = runtime
                .schedule
                .cancel(&id, Timestamp::now())
                .map_err(unavailable("reminder_cancel"))?;
            Ok(runtime.render_item(&item))
        };
        tools.push(Arc::new(CapabilityTool::plain_without_prerequisites(
            RpcHostToolDefinition {
                name: "reminder_cancel".into(),
                label: "Cancel a reminder".into(),
                description: "Cancels one pending reminder or wake by id.".into(),
                parameters: object_schema(
                    "reminder_cancel",
                    json!({ "id": { "type": "string", "minLength": 1, "maxLength": 32 } }),
                    &["id"],
                ),
                hidden: false,
                load_mode: ToolLoadMode::Discoverable,
            },
            Box::new(handler),
        )));
    }
    {
        let runtime = Arc::clone(runtime);
        let handler = move |_scope: Scope, arguments: Value| {
            let zone = parse_string(&arguments, "zone", 64)?;
            let until = match arguments.get("until") {
                None | Some(Value::Null) => None,
                Some(Value::String(until)) if until.len() <= 32 => Some(until.clone()),
                Some(_) => {
                    return Err(HostToolError::Arguments {
                        tool: "time_zone_set",
                        detail: "until must be a local time like 2026-10-04T23:59".to_owned(),
                    })
                }
            };
            let change = runtime
                .clock
                .set_zone(&zone, until.as_deref())
                .map_err(|detail| HostToolError::Arguments {
                    tool: "time_zone_set",
                    detail,
                })?;
            let mut output = json!({
                "zone": change.zone,
                "now": runtime.clock.line(Timestamp::now()),
            });
            if let Some(until) = change.until {
                output["until"] = json!(until);
            }
            Ok(output)
        };
        tools.push(Arc::new(CapabilityTool::plain_without_prerequisites(
            RpcHostToolDefinition {
                name: "time_zone_set".into(),
                label: "Set Colin's time zone".into(),
                description: "Records the IANA time zone Colin is in now (travel), e.g. \
                 America/New_York. Every clock line and reminder time follows it. When he \
                 says when the trip ends (\"until Sunday\"), pass until: the local end time \
                 in the new zone (YYYY-MM-DDTHH:MM); his home zone returns by itself then."
                    .into(),
                parameters: object_schema(
                    "time_zone_set",
                    json!({
                        "zone": { "type": "string", "minLength": 1, "maxLength": 64 },
                        "until": { "type": "string", "minLength": 10, "maxLength": 32 },
                    }),
                    &["zone"],
                ),
                hidden: false,
                load_mode: ToolLoadMode::Discoverable,
            },
            Box::new(handler),
        )));
    }
}

/// How many settled (fired, cancelled, failed) reminders the listing keeps.
const RECENT_SETTLED: usize = 5;
/// Per-item text bound in the listing; the schedule keeps the full text.
const LISTED_TEXT_CHARS: usize = 240;

// Include open rows and recent settled reminders, excluding settled internal wakes.
fn compact_listing(items: &[ScheduledItem]) -> (Vec<&ScheduledItem>, usize) {
    let open = |item: &&ScheduledItem| {
        matches!(
            item.status,
            ScheduleStatus::Pending | ScheduleStatus::Firing
        )
    };
    let mut listed: Vec<&ScheduledItem> = items.iter().filter(open).collect();
    let mut settled: Vec<&ScheduledItem> = items
        .iter()
        .filter(|item| !open(item) && item.kind == ScheduleKind::Notify)
        .collect();
    settled.sort_by_key(|item| std::cmp::Reverse(item.fired_at_ms.unwrap_or(item.fire_at_ms)));
    settled.truncate(RECENT_SETTLED);
    listed.extend(settled);
    let omitted = items.len() - listed.len();
    (listed, omitted)
}

fn bounded_text(text: &str) -> String {
    if text.chars().count() <= LISTED_TEXT_CHARS {
        return text.to_owned();
    }
    let mut bounded: String = text.chars().take(LISTED_TEXT_CHARS).collect();
    bounded.push('…');
    bounded
}

#[cfg(test)]
mod listing_tests {
    use super::*;

    #[test]
    fn repetition_requires_explicit_additional_firings() {
        assert_eq!(repeat_arguments(&json!({})).unwrap(), None);
        assert_eq!(
            repeat_arguments(&json!({"repeat_every_minutes":5, "repeat_times":2})).unwrap(),
            Some((5, 2))
        );
        for arguments in [
            json!({"repeat_every_minutes":5}),
            json!({"repeat_every_minutes":5, "repeat_times":null}),
            json!({"repeat_times":2}),
            json!({"repeat_every_minutes":5, "repeat_times":0}),
            json!({"repeat_every_minutes":5, "repeat_times":"2"}),
        ] {
            let error = repeat_arguments(&arguments).unwrap_err();
            assert!(error.to_string().contains("repeat_times"), "{error}");
        }
    }

    #[test]
    fn optional_reminder_fields_reject_invalid_values() {
        for value in [json!(""), json!(false), json!(20)] {
            let error = optional_str(&json!({"at":value}), "at").unwrap_err();
            assert!(error.to_string().contains("at"), "{error}");
        }
        for value in [json!(""), json!("30"), json!(-1), json!(721)] {
            let error = optional_minutes(&json!({"lead_minutes":value}), "lead_minutes", 0, 720)
                .unwrap_err();
            assert!(error.to_string().contains("lead_minutes"), "{error}");
        }
    }

    fn item(id: &str, kind: ScheduleKind, status: ScheduleStatus, at: i64) -> ScheduledItem {
        ScheduledItem {
            id: id.to_owned(),
            kind,
            text: "x".repeat(1_000),
            fire_at_ms: at,
            anchor: None,
            created_at_ms: 0,
            status,
            fired_at_ms: None,
            every_minutes: None,
            repeats_left: 0,
            attempts: 0,
            retry_at_ms: None,
            event: false,
            routine_digest: None,
            dispatch_started: false,
        }
    }

    #[test]
    fn the_listing_keeps_every_open_row_and_only_the_recent_settled_reminders() {
        let mut items = vec![
            item(
                "pending-wake",
                ScheduleKind::Wake,
                ScheduleStatus::Pending,
                50,
            ),
            item("pending", ScheduleKind::Notify, ScheduleStatus::Pending, 40),
        ];
        for at in 0..30 {
            items.push(item(
                &format!("wake-{at}"),
                ScheduleKind::Wake,
                ScheduleStatus::Fired,
                at,
            ));
            items.push(item(
                &format!("fired-{at}"),
                ScheduleKind::Notify,
                ScheduleStatus::Fired,
                at,
            ));
        }
        let (listed, omitted) = compact_listing(&items);
        let ids: Vec<&str> = listed.iter().map(|item| item.id.as_str()).collect();
        assert_eq!(
            ids,
            [
                "pending-wake",
                "pending",
                "fired-29",
                "fired-28",
                "fired-27",
                "fired-26",
                "fired-25"
            ]
        );
        assert_eq!(omitted, items.len() - 7);
        assert_eq!(
            bounded_text(&items[0].text).chars().count(),
            LISTED_TEXT_CHARS + 1
        );
    }

    #[test]
    fn a_vehicle_that_is_down_does_not_count_as_a_failed_wake() {
        assert!(wake_waits_for_vehicle(&IntentFailure::VehicleLost));
        assert!(wake_waits_for_vehicle(&IntentFailure::ModelUnavailable {
            reason: "provider quota".to_owned(),
        }));
        assert!(wake_waits_for_vehicle(&IntentFailure::Other(
            "the predecessor is not provably Ended; the transition stays pending".to_owned(),
        )));
        assert!(!wake_waits_for_vehicle(&IntentFailure::TurnRefused {
            reason: "the prompt was refused".to_owned(),
        }));
    }
}
