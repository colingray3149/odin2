//! `reminder.*` and `time.zone.set`: the model surface over the durable
//! schedule, and the reconcile step that fires due rows.

use std::sync::Arc;

use crate::conversation::QUIET_REPLY;
use jiff::{SignedDuration, Timestamp};
use odin_domain::Scope;
use odin_omp::capability_parameters;
use odin_omp::host_tools::{HostTool, HostToolError, RpcHostToolDefinition, ToolLoadMode};
use serde_json::{json, Value};

use super::follow_through::ask_of_wake;
use super::recovery::bridge_route;
use super::tools::{parse_string, CapabilityTool};
use super::{ApprovedIntentExecution, HarnessRide, HermesRuntime, IntentFailure};
use crate::schedule::EventWake;
use crate::schedule::{
    ScheduleKind, ScheduleStatus, ScheduledItem, JOB_ROW_PREFIX, MAX_TEXT_CHARS, REPEAT_MINUTES,
    REPEAT_TIMES, ROUTINE_ROW_PREFIX,
};

const TOOL: &str = "reminder_set";
/// Farthest `in_minutes` accepts (400 days).
const MAX_IN_MINUTES: i64 = 576_000;
/// Minutes before the anchoring event a reminder fires unless told otherwise.
const DEFAULT_LEAD_MINUTES: i64 = 30;
/// A notify or wake that fires this long after it was due says so.
const LATE_AFTER_MS: i64 = 10 * 60 * 1000;
/// A job report that waited this many minutes tells the model the conversation may have moved on.
const REPORT_STALE_MINUTES: i64 = 2;

/// Characters of event text one owner turn carries behind his message.
const HARNESS_RIDE_CHARS: usize = 6_000;

fn optional_str<'a>(arguments: &'a Value, key: &str) -> Result<Option<&'a str>, HostToolError> {
    match arguments.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(value)) if !value.trim().is_empty() => Ok(Some(value.trim())),
        Some(_) => Err(HostToolError::Arguments {
            tool: TOOL,
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
                tool: TOOL,
                detail: format!("{key} must be an integer in {min}..={max}"),
            }),
    }
}

fn repeat_arguments(arguments: &Value) -> Result<Option<(i64, u32)>, HostToolError> {
    let every = optional_minutes(
        arguments,
        "repeat_every_minutes",
        *REPEAT_MINUTES.start(),
        *REPEAT_MINUTES.end(),
    )?;
    let times = optional_minutes(
        arguments,
        "repeat_times",
        i64::from(*REPEAT_TIMES.start()),
        i64::from(*REPEAT_TIMES.end()),
    )?;
    match (every, times) {
        (None, None) => Ok(None),
        (Some(every), Some(times)) => Ok(Some((every, times as u32))),
        _ => Err(HostToolError::Arguments {
            tool: TOOL,
            detail: "repeat_every_minutes and repeat_times must be supplied together; repeat_times counts additional firings after the first".to_owned(),
        }),
    }
}

/// When a reminder fires, what it was resolved from, and the calendar event
/// it counts down to (a repeat stops there).
struct ReminderTime {
    fire_at: Timestamp,
    anchor: Option<String>,
    event_start: Option<Timestamp>,
}

impl ReminderTime {
    fn at(fire_at: Timestamp) -> Self {
        Self {
            fire_at,
            anchor: None,
            event_start: None,
        }
    }
}

/// How many of the `times` firings after the first still land before the
/// anchoring event starts (all of them for a reminder with no event).
fn repeats_before(
    fire_at: Timestamp,
    event_start: Option<Timestamp>,
    every_minutes: i64,
    times: u32,
) -> u32 {
    let Some(start) = event_start else {
        return times;
    };
    let before_start = start.as_millisecond() - fire_at.as_millisecond() - 1;
    let room = before_start.div_euclid(every_minutes * 60_000).max(0);
    u32::try_from(room).map_or(times, |room| room.min(times))
}

impl HermesRuntime {
    fn resolve_reminder_time(
        &self,
        arguments: &Value,
        now: Timestamp,
    ) -> Result<ReminderTime, HostToolError> {
        let invalid = |detail: &str| HostToolError::Arguments {
            tool: TOOL,
            detail: detail.to_owned(),
        };
        let at = optional_str(arguments, "at")?;
        let in_minutes = optional_minutes(arguments, "in_minutes", 1, MAX_IN_MINUTES)?;
        let anchor_date = optional_str(arguments, "anchor_date")?;
        if anchor_date.is_none() {
            for field in ["anchor_account", "anchor_match", "lead_minutes"] {
                if arguments.get(field).is_some_and(|value| !value.is_null()) {
                    return Err(invalid(&format!("{field} requires anchor_date")));
                }
            }
        }
        match (at, in_minutes, anchor_date) {
            (Some(at), None, None) => Ok(ReminderTime::at(
                self.clock
                    .resolve_local(at)
                    .map_err(|error| invalid(&format!("at: {error}")))?,
            )),
            (None, Some(minutes), None) => {
                Ok(ReminderTime::at(now + SignedDuration::from_mins(minutes)))
            }
            _ => Err(invalid(
                "give exactly one of: at (local time or RFC 3339 with an offset), in_minutes, or anchor_date",
            )),
        }
    }

    /// How long until the next schedule row comes due (zero when one is),
    /// for the reconcile loop to sleep exactly that long.
    pub fn schedule_due_in(&self) -> Option<std::time::Duration> {
        let due = match self.schedule.next_due_ms() {
            Ok(due) => due?,
            Err(error) => {
                tracing::warn!("odin-hermes: next schedule deadline unreadable, ticking: {error}");
                return None;
            }
        };
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

    /// Whether the wake `id` was already queued, fired or not.
    pub fn wake_queued(&self, id: &str) -> Result<bool, String> {
        self.schedule.has(id)
    }

    /// [`Self::wake_once`] for an event about `job` for `cause`: the same
    /// cause about the same job inside the declared quiet window of its last
    /// wake queues nothing, so a seat that keeps reporting one trouble wakes
    /// the conversation once. The first repeat is pinned to `job` as a task
    /// note, so the one wake's memory says it kept happening.
    pub fn wake_event(
        &self,
        id: &str,
        text: &str,
        job: &str,
        cause: &str,
    ) -> Result<EventWake, String> {
        self.wake_event_at(Timestamp::now(), id, text, (job, cause))
    }

    /// [`Self::wake_event`] as of `now`.
    pub fn wake_event_at(
        &self,
        now: Timestamp,
        id: &str,
        text: &str,
        stream: (&str, &str),
    ) -> Result<EventWake, String> {
        let window = i64::from(self.settings.quiet_wake_minutes) * 60_000;
        let woke = self
            .schedule
            .wake_event_once(id, text, stream, window, now)?;
        match woke {
            EventWake::Queued => self.reconcile_wake.notify_one(),
            EventWake::Quiet { first: true } => self.note_repeat(stream.0, stream.1),
            _ => {}
        }
        Ok(woke)
    }

    /// The wake that last woke the conversation about `job`.
    pub fn quiet_wake_id(&self, job: &str) -> Result<Option<String>, String> {
        self.schedule.quiet_wake_id(job)
    }

    /// Pins "same cause again" to `job` in the authority ledger, where the
    /// conversation seat's live memory shows task notes.
    fn note_repeat(&self, job: &str, cause: &str) {
        let Some(discord) = self.settings.discord.as_ref() else {
            return;
        };
        let note = format!("same cause again: {cause}");
        let ledger = match self.purchase_ledger.lock() {
            Ok(ledger) => ledger,
            Err(error) => return tracing::error!("odin-hermes: repeat note not written: {error}"),
        };
        if let Err(error) = odin_ledger::task_note::add(
            ledger.connection(),
            job,
            discord.seat.as_str(),
            Some(discord.project.as_str()),
            &note
                .chars()
                .take(odin_ledger::task_note::MAX_NOTE_CHARS - 1)
                .collect::<String>(),
            time::OffsetDateTime::now_utc(),
        ) {
            tracing::error!("odin-hermes: repeat note for {job} not written: {error}");
        }
    }

    /// The events waiting when the owner's message runs, oldest first, as many as
    /// [`HARNESS_RIDE_CHARS`] hold: they ride his turn instead of taking
    /// turns of their own ahead of the next message of his. One that does not
    /// fit keeps its own turn.
    pub(super) fn harness_waiting(&self, now: Timestamp) -> Result<Vec<ScheduledItem>, String> {
        let mut due = self.schedule.due_events(now)?;
        self.settle_moot_wakes(&mut due, now)?;
        let mut used = 0;
        let fits = due
            .iter()
            .take_while(|item| {
                used += item.text.len();
                used <= HARNESS_RIDE_CHARS
            })
            .count();
        due.truncate(fits);
        Ok(due)
    }

    /// One event as the line that rides the owner's turn.
    pub(super) fn harness_line(&self, item: &ScheduledItem) -> String {
        format!(
            "- {}: {}",
            self.clock.render(item.created_at_ms),
            item.text.trim().replace('\n', "\n  ")
        )
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

    /// ` (was due <time>)` when a row fires well after its time, so a late
    /// repeat or catch-up is not taken for something that just came due.
    fn late_note(&self, item: &ScheduledItem, now: Timestamp) -> String {
        if now.as_millisecond() - item.fire_at_ms > LATE_AFTER_MS {
            format!(" (was due {})", self.clock.render(item.fire_at_ms))
        } else {
            String::new()
        }
    }

    fn owner_intents_queued(&self) -> bool {
        self.admitted.lock().is_ok_and(|queue| !queue.is_empty())
    }

    /// A wake the vehicle cannot run yet: back off without counting an attempt.
    /// A busy or restarting conversation is back within seconds; a model or
    /// successor outage gets the long hold.
    fn defer_wake(&self, item: &ScheduledItem, failure: &IntentFailure) -> Result<(), String> {
        let now = Timestamp::now();
        if matches!(
            failure,
            IntentFailure::ConversationBusy | IntentFailure::VehicleLost
        ) {
            self.schedule
                .hold_for(&item.id, now, crate::schedule::VEHICLE_BUSY_WAIT_MS)?;
            tracing::info!(
                "odin-hermes: wake {} waits for the conversation (attempt unchanged): {failure}",
                item.id
            );
        } else {
            self.schedule.hold_unresolved(&item.id, now)?;
            tracing::warn!(
                "odin-hermes: wake {} waiting for the vehicle (attempt unchanged): {failure}",
                item.id
            );
        }
        Ok(())
    }

    /// Settles the due wakes that would only wake the model for nothing and
    /// removes them from `due`: a pod launch's receipt (the pod reports
    /// itself), a delegated child's finished turn that the child has since
    /// moved past (the seat steered it, or a later turn answered), and an open
    /// ask's wake once the ask is delivered or dropped.
    fn settle_moot_wakes(
        &self,
        due: &mut Vec<ScheduledItem>,
        now: Timestamp,
    ) -> Result<(), String> {
        let mut moot = Vec::new();
        let mut failure = None;
        due.retain(|item| {
            let is_moot = if item.kind == ScheduleKind::Wake && ask_of_wake(&item.id).is_some() {
                // The ask was delivered or dropped while its wake waited.
                self.ask_wake_is_moot(&item.id).unwrap_or_else(|error| {
                    failure = Some(error);
                    false
                })
            } else if is_job_report(item) {
                odin_domain::job_report::launch_receipt(&item.text)
            } else {
                item.kind == ScheduleKind::Wake
                    && child_turn_of(&item.id).is_some_and(|(child, key)| {
                        self.delegator
                            .as_ref()
                            .is_some_and(|delegator| delegator.child_moved_past(child, key))
                    })
            };
            if is_moot {
                moot.push(item.id.clone());
            }
            !is_moot
        });
        for id in moot {
            tracing::info!("odin-hermes: wake {id} is moot; settled without a turn");
            self.schedule.mark_fired(&id, now)?;
        }
        failure.map_or(Ok(()), Err)
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
        self.reconcile_schedule_at(Timestamp::now())
    }

    /// [`Self::reconcile_schedule`] as of `now`.
    pub fn reconcile_schedule_at(&self, now: Timestamp) -> Result<usize, String> {
        let mut fired = 0;
        self.wake_open_asks(now)?;
        let mut due = self.schedule.take_due(now)?;
        self.settle_moot_wakes(&mut due, now)?;
        let held = match due.iter().any(is_job_report) {
            true => self.schedule.held_job_reports(now)?,
            false => Vec::new(),
        };
        let riders = gather_job_reports(&mut due, held);
        for item in due {
            // The job reports that ride this one's turn settle with it.
            let riders: &[ScheduledItem] = if is_job_report(&item) { &riders } else { &[] };
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
                        format!("⏰ Reminder: {}{}", item.text, self.late_note(&item, now))
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
                        harness: HarnessRide::default(),
                        unprompted: true,
                        command_id: key.clone(),
                        idempotency_key: key,
                        content: if let Some(routine) = routine_of(&item) {
                            format!(
                                "[Routine {routine} from the harness. The owner scheduled it \
                                 for now: \"{}\"{}. The governed tools carry it out. The reply \
                                 reaches the owner with the result. A reply of exactly \
                                 {QUIET_REPLY} sends nothing.]",
                                item.text,
                                self.late_note(&item, now)
                            )
                        } else if item.id.starts_with(JOB_ROW_PREFIX) {
                            let age = (now.as_millisecond() - item.created_at_ms) / 60_000;
                            let late = if age >= REPORT_STALE_MINUTES {
                                format!(
                                    "\nThis report waited {age} min while you were busy: the \
                                     conversation may have moved on or covered the result."
                                )
                            } else {
                                String::new()
                            };
                            format!(
                                "{} \u{2014} a harness report: {}{late}\n\
                                 The reply tells the owner what completed or what failed, \
                                 why, and what happens next. A reply of exactly \
                                 {QUIET_REPLY} sends nothing.]",
                                odin_domain::job_report::REPORT_TURN,
                                item.text
                            )
                        } else if item.event {
                            // Include event age because delivery may wait; verify current state before relaying.
                            format!(
                                "[Harness event observed {} ({} min ago): {}\n\
                                 It may be out of date; the governed reads show the current \
                                 state. The reply reaches the owner with what matters now. \
                                 A reply of exactly {QUIET_REPLY} sends nothing.]",
                                self.clock.render(item.created_at_ms),
                                (now.as_millisecond() - item.created_at_ms) / 60_000,
                                item.text
                            )
                        } else {
                            format!(
                                "[Scheduled harness wake. At {} you set this for now: \"{}\"{}. \
                                 The reply reaches the owner with what matters now. \
                                 A reply of exactly {QUIET_REPLY} sends nothing.]",
                                self.clock.render(item.created_at_ms),
                                item.text,
                                self.late_note(&item, now)
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
                            for wake in std::iter::once(&item).chain(riders) {
                                self.defer_wake(wake, &failure)?;
                            }
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
                    for wake in std::iter::once(&item).chain(riders) {
                        self.schedule.mark_fired(&wake.id, now)?;
                    }
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
                    for rider in riders {
                        self.schedule.mark_failed(&rider.id, Timestamp::now())?;
                    }
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
    matches!(
        failure,
        IntentFailure::ConversationBusy
            | IntentFailure::VehicleLost
            | IntentFailure::ModelUnavailable { .. }
            | IntentFailure::SuccessorStartBackoff { .. }
            | IntentFailure::SuccessorStartExhausted { .. }
    )
}

fn missed_label(item: &ScheduledItem) -> String {
    match item.kind {
        ScheduleKind::Notify => format!("reminder \"{}\"", item.text),
        ScheduleKind::Wake if item.event => format!("report \"{}\"", item.text),
        ScheduleKind::Wake => format!("wake \"{}\"", item.text),
    }
}

/// A background job's report (`JobBoard` wakes them as `job:…`).
fn is_job_report(item: &ScheduledItem) -> bool {
    item.kind == ScheduleKind::Wake && item.id.starts_with(JOB_ROW_PREFIX)
}

/// Job reports wake one turn together, not one each: most come back while
/// she is busy and need no reply (W5: 116 of 253 report turns in a day and a
/// half answered only the quiet token). The first due report carries the text of
/// every other due report and every `held` one (waiting out a busy turn),
/// each on its own line, and the age of the oldest; the rest are taken out
/// of `due` and returned, to settle with it.
fn gather_job_reports(
    due: &mut Vec<ScheduledItem>,
    held: Vec<ScheduledItem>,
) -> Vec<ScheduledItem> {
    let Some(first) = due.iter().position(is_job_report) else {
        return Vec::new();
    };
    let mut riders = Vec::new();
    let mut index = first + 1;
    while index < due.len() {
        if is_job_report(&due[index]) {
            riders.push(due.remove(index));
        } else {
            index += 1;
        }
    }
    riders.extend(held);
    for rider in &riders {
        due[first].text.push_str("\n\n");
        due[first].text.push_str(&rider.text);
        due[first].created_at_ms = due[first].created_at_ms.min(rider.created_at_ms);
    }
    riders
}

/// The wake id of one settled turn of a delegated child: odind queues it once
/// per answer, so a repeated observation of the same answer wakes nothing.
pub fn child_turn_wake_id(child: impl std::fmt::Display, key: &str) -> String {
    format!("child-{child}-{key}")
}

/// The child session and turn key a [`child_turn_wake_id`] names.
fn child_turn_of(id: &str) -> Option<(&str, &str)> {
    /// A hyphenated session uuid.
    const SESSION_LEN: usize = 36;
    let (child, key) = id.strip_prefix("child-")?.split_at_checked(SESSION_LEN)?;
    Some((child, key.strip_prefix('-')?))
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
    item.anchor.as_deref()?.strip_prefix(ROUTINE_ROW_PREFIX)
}

fn is_routine(item: &ScheduledItem) -> bool {
    routine_of(item).is_some()
}

pub(super) fn schedule_tools(runtime: &Arc<HermesRuntime>, tools: &mut Vec<Arc<dyn HostTool>>) {
    let settings = runtime.settings();
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
                        tool: TOOL,
                        detail: format!("kind {other:?} is not notify or wake"),
                    })
                }
            };
            let now = Timestamp::now();
            let when = runtime.resolve_reminder_time(&arguments, now)?;
            let mut item = runtime
                .schedule
                .add(kind, &text, when.fire_at, when.anchor, now)
                .map_err(|reason| HostToolError::unavailable(TOOL, reason))?;
            let mut stopped_at_event = false;
            if let Some((every, asked)) = repeat {
                let times = repeats_before(when.fire_at, when.event_start, every, asked);
                stopped_at_event = times < asked;
                if times > 0 {
                    runtime
                        .schedule
                        .set_repeat(&item.id, every, times)
                        .map_err(|detail| HostToolError::Arguments { tool: TOOL, detail })?;
                    item.every_minutes = Some(every);
                    item.repeats_left = times;
                }
            }
            runtime.reconcile_wake.notify_one();
            let mut rendered = runtime.render_item(&item);
            if stopped_at_event {
                rendered["note"] = json!("the repeats stop when the event starts");
            }
            Ok(rendered)
        };
        tools.push(Arc::new(CapabilityTool::plain_without_prerequisites(
            RpcHostToolDefinition {
                name: TOOL.into(),
                label: "Set a reminder".into(),
                description: format!("Schedules a reminder: notify sends the text; wake starts a turn. \
                 Give exactly one time: at (local YYYY-MM-DDTHH:MM, or RFC 3339 with its offset), in_minutes, or \
                 anchor_date with anchor_account for the first timed calendar event that day. \
                 anchor_match filters its title; lead_minutes defaults to {DEFAULT_LEAD_MINUTES} before the event. \
                 Repetition requires both repeat_every_minutes and repeat_times; repeat_times \
                 counts additional firings after the first; an anchored reminder stops repeating \
                 when its event starts."
                )
                .into(),
                parameters: odin_omp::host_tools::schema_compat::resolve_ids(
                    capability_parameters!("reminder.set"),
                    "/properties/anchor_account",
                    settings.account_names(true),
                ),
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
                .map_err(|reason| HostToolError::unavailable("reminder_list", reason))?;
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
                 fired or cancelled reminders, in the owner's local time."
                    .into(),
                parameters: capability_parameters!("reminder.list"),
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
            if let Some(ask) = runtime
                .drop_ask(&id)
                .map_err(|reason| HostToolError::unavailable("reminder_cancel", reason))?
            {
                return Ok(ask);
            }
            let item = runtime
                .schedule
                .cancel(&id, Timestamp::now())
                .map_err(|reason| HostToolError::unavailable("reminder_cancel", reason))?;
            Ok(runtime.render_item(&item))
        };
        tools.push(Arc::new(CapabilityTool::plain_without_prerequisites(
            RpcHostToolDefinition {
                name: "reminder_cancel".into(),
                label: "Cancel a reminder".into(),
                description: "Cancels one pending reminder or wake by id, or drops the open ask \
                 an ask wake names."
                    .into(),
                parameters: capability_parameters!("reminder.cancel"),
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
                label: "Set the owner's time zone".into(),
                description: "Records the IANA time zone the owner is in now (travel), e.g. \
                 America/New_York. Every clock line and reminder time follows it. When he \
                 says when the trip ends (\"until Sunday\"), pass until: the local end time \
                 in the new zone (YYYY-MM-DDTHH:MM); his home zone returns by itself then."
                    .into(),
                parameters: capability_parameters!("time.zone.set"),
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

/// A note or incident line as its cause: the words without ids and numbers,
/// so the same trouble reads the same each time it recurs.
pub fn cause_of(text: &str) -> String {
    text.split_whitespace()
        .filter(|word| !word.bytes().any(|byte| byte.is_ascii_digit()))
        .collect::<Vec<_>>()
        .join(" ")
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
    fn a_repeat_stops_before_the_event_it_counts_down_to() {
        let first = Timestamp::from_second(1_790_000_000).unwrap();
        let starts = first + SignedDuration::from_mins(35);
        // Every 10 minutes from 35 minutes out: firings at +10, +20, +30 fit.
        assert_eq!(repeats_before(first, Some(starts), 10, 50), 3);
        assert_eq!(repeats_before(first, Some(starts), 10, 2), 2);
        // A firing at the very start is not before it.
        let on_the_dot = first + SignedDuration::from_mins(30);
        assert_eq!(repeats_before(first, Some(on_the_dot), 10, 50), 2);
        // The event starts before a second firing: no repeat at all.
        assert_eq!(repeats_before(first, Some(starts), 60, 50), 0);
        // Nothing to count down to: the repeat is as asked.
        assert_eq!(repeats_before(first, None, 10, 50), 50);
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
}
