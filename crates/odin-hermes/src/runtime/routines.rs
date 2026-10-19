//! Published routines queue schedule rows for timed or event-triggered delivery.

use std::collections::BTreeMap;
use std::sync::Arc;

use jiff::Timestamp;
use odin_registry::schema::{
    RoutineActionKind, RoutineEvent, RoutineSchedule, RoutineToml, RoutineTriggerToml,
};
use odin_registry::ObjectConfig;

use odin_domain::Scope;
use odin_omp::host_tools::{HostTool, HostToolError, RpcHostToolDefinition, ToolLoadMode};
use serde_json::{json, Map, Value};

use super::tools::{object_schema, parse_string, CapabilityTool};
use super::HermesRuntime;
use crate::schedule::{latest_occurrence, ScheduleKind, ScheduledItem};

const SET_TOOL: &str = "routine_set";
const REMOVE_TOOL: &str = "routine_remove";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RoutineSetRequest {
    pub id: String,
    pub description: String,
    pub schedule: Option<String>,
    pub event: Option<String>,
    pub profile: Option<String>,
    /// Mail search text, title or file-name words, or a project id.
    pub matches: Option<String>,
    /// Minutes before a calendar event.
    pub lead_minutes: Option<u16>,
    /// The one mail or calendar account to watch.
    pub account: Option<String>,
    /// `brief` or `dm`.
    pub action: String,
    pub text: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RoutineChange {
    pub routine: String,
    /// `declared`, `replaced` or `removed`.
    pub outcome: String,
    pub published_revision: u64,
    pub commit: String,
}

/// The daemon's routine authoring route: commit onto odin main and
/// publish. `caller` is the kernel-admitted seat, never a model argument.
pub trait RoutineRoute: Send + Sync {
    fn set(
        &self,
        caller: &odin_domain::SeatId,
        request: RoutineSetRequest,
    ) -> Result<RoutineChange, String>;
    fn remove(&self, caller: &odin_domain::SeatId, id: &str) -> Result<RoutineChange, String>;
}

fn optional(arguments: &Value, field: &str, max: usize) -> Result<Option<String>, HostToolError> {
    match arguments.get(field) {
        None | Some(Value::Null) => Ok(None),
        Some(_) => parse_string(arguments, field, max).map(Some),
    }
}

fn lead_minutes(arguments: &Value) -> Result<Option<u16>, HostToolError> {
    let Some(value) = arguments
        .get("lead_minutes")
        .filter(|value| !value.is_null())
    else {
        return Ok(None);
    };
    if arguments.get("event").and_then(Value::as_str) != Some("calendar_event") {
        return Err(HostToolError::Arguments {
            tool: SET_TOOL,
            detail: "lead_minutes requires event=calendar_event".to_owned(),
        });
    }
    let minutes = value
        .as_u64()
        .filter(|value| (1..=1440).contains(value))
        .ok_or_else(|| HostToolError::Arguments {
            tool: SET_TOOL,
            detail: "lead_minutes must be an integer in 1..=1440".to_owned(),
        })?;
    Ok(Some(minutes as u16))
}

fn change_json(change: RoutineChange) -> Value {
    json!({
        "routine": change.routine,
        "outcome": change.outcome,
        "publishedRevision": change.published_revision,
        "commit": change.commit,
    })
}

pub(super) fn routine_tools(runtime: &Arc<HermesRuntime>, tools: &mut Vec<Arc<dyn HostTool>>) {
    let set_runtime = Arc::clone(runtime);
    let handler = move |scope: Scope, arguments: Value| {
        let unavailable = |reason: String| HostToolError::Unavailable {
            tool: SET_TOOL,
            reason,
        };
        let caller = scope
            .seat
            .ok_or_else(|| unavailable("the dispatch carries no admitted seat".to_owned()))?;
        let route = set_runtime.routine_route().ok_or_else(|| {
            unavailable("routine authoring is not composed on this host".to_owned())
        })?;
        let request = RoutineSetRequest {
            id: parse_string(&arguments, "id", 63)?,
            description: parse_string(&arguments, "description", 300)?,
            schedule: optional(&arguments, "schedule", 64)?,
            event: optional(&arguments, "event", 32)?,
            profile: optional(&arguments, "profile", 64)?,
            matches: optional(&arguments, "match", 200)?,
            lead_minutes: lead_minutes(&arguments)?,
            account: optional(&arguments, "account", 254)?,
            action: parse_string(&arguments, "action", 8)?,
            text: parse_string(&arguments, "text", 2_000)?,
        };
        let change = route.set(&caller, request).map_err(unavailable)?;
        set_runtime
            .note_routine_declared(&change.routine)
            .map_err(unavailable)?;
        Ok(change_json(change))
    };
    tools.push(Arc::new(CapabilityTool::plain_without_prerequisites(
        RpcHostToolDefinition {
            name: SET_TOOL.into(),
            label: "Set a routine".into(),
            description: "Declares (or replaces, by id) a routine that runs without Colin \
                 asking. Trigger: exactly one of `schedule` in his zone — \"weekdays 07:30\", \
                 \"daily 21:00\", \"mon,wed,fri 16:00\", \"monthly 1 09:00\", \"every 2 hours\" — \
                 or `event`: workload_succeeded / workload_failed (optionally one pod \
                 `profile`), watchdog, incident; mail_arrived (`match` is the mail search, e.g. \
                 a sender address or subject words; optional `account`); calendar_event \
                 (`lead_minutes` before an event, optional `match` on its title and `account`) \
                 — e.g. 30 minutes before any class; file_received (he sends a file; optional \
                 `match` on its name); repo_push (any push to a project repository; optional \
                 `match` = the project); ring_gesture (Colin's smart ring: optional `match` = the \
                 gesture name). Action: brief starts a turn with text as its instruction; \
                 dm sends text as written. Routines use the seat's existing authority. \
                 Use reminder_set for one-shot requests."
                .into(),
            parameters: object_schema(
                SET_TOOL,
                json!({
                    "id": { "type": "string", "pattern": "^[a-z][a-z0-9-]{1,62}$" },
                    "description": { "type": "string", "minLength": 1, "maxLength": 300 },
                    "schedule": { "type": "string", "minLength": 5, "maxLength": 64 },
                    "event": { "enum": [
                        "workload_succeeded", "workload_failed", "watchdog", "incident",
                        "mail_arrived", "calendar_event", "file_received", "repo_push",
                        "ring_gesture"
                    ] },
                    "profile": { "type": "string", "minLength": 1, "maxLength": 64 },
                    "match": { "type": "string", "minLength": 1, "maxLength": 200 },
                    "lead_minutes": { "type": "integer", "minimum": 1, "maximum": 1440 },
                    "account": { "type": "string", "minLength": 3, "maxLength": 254 },
                    "action": { "enum": ["brief", "dm"] },
                    "text": { "type": "string", "minLength": 1, "maxLength": 2000 },
                }),
                &["id", "description", "action", "text"],
            ),
            hidden: false,
            load_mode: ToolLoadMode::Discoverable,
        },
        Box::new(handler),
    )));
    let remove_runtime = Arc::clone(runtime);
    let handler = move |scope: Scope, arguments: Value| {
        let unavailable = |reason: String| HostToolError::Unavailable {
            tool: REMOVE_TOOL,
            reason,
        };
        let caller = scope
            .seat
            .ok_or_else(|| unavailable("the dispatch carries no admitted seat".to_owned()))?;
        let route = remove_runtime.routine_route().ok_or_else(|| {
            unavailable("routine authoring is not composed on this host".to_owned())
        })?;
        let id = parse_string(&arguments, "id", 63)?;
        route
            .remove(&caller, &id)
            .map(change_json)
            .map_err(unavailable)
    };
    tools.push(Arc::new(CapabilityTool::plain_without_prerequisites(
        RpcHostToolDefinition {
            name: REMOVE_TOOL.into(),
            label: "Remove a routine".into(),
            description: "Removes one of your routines by id; it never fires again. List them \
                 with registry_read kind=routine."
                .into(),
            parameters: object_schema(
                REMOVE_TOOL,
                json!({ "id": { "type": "string", "pattern": "^[a-z][a-z0-9-]{1,62}$" } }),
                &["id"],
            ),
            hidden: false,
            load_mode: ToolLoadMode::Discoverable,
        },
        Box::new(handler),
    )));
}

// Skip occurrences older than the catch-up window.
const CATCH_UP_MS: i64 = 30 * 60 * 1000;

/// One poll of the routine sources: the reads that failed, and the
/// earliest calendar lead time the poll saw still ahead.
#[derive(Debug, Default)]
pub struct RoutineSourcePoll {
    pub failures: Vec<String>,
    pub next_lead: Option<NextLead>,
}

/// A calendar routine's next lead time: the sources are polled again then,
/// so the routine fires when it comes due, not at the next regular poll.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NextLead {
    pub due: time::OffsetDateTime,
    pub routine: String,
    pub occurrence: String,
}

/// Where an event stands against a calendar routine's lead time.
#[derive(Debug, PartialEq, Eq)]
enum LeadTime {
    Due,
    Ahead(time::OffsetDateTime),
    Outside,
}

/// An event `lead` before its `start` is due from then until it starts;
/// a lead time before the routine was first seen never fires.
fn lead_time(
    start: time::OffsetDateTime,
    lead: time::Duration,
    now: time::OffsetDateTime,
    first_seen_ms: i64,
) -> LeadTime {
    let due = start - lead;
    let due_ms = i64::try_from(due.unix_timestamp_nanos() / 1_000_000).unwrap_or(i64::MAX);
    if start <= now || due_ms < first_seen_ms {
        LeadTime::Outside
    } else if due > now {
        LeadTime::Ahead(due)
    } else {
        LeadTime::Due
    }
}

/// The source reads the last routine poll could not make, per routine.
#[derive(Default)]
pub(crate) struct RoutineState {
    problems: parking_lot::Mutex<BTreeMap<String, String>>,
}

fn trigger_name(trigger: &RoutineTriggerToml) -> &'static str {
    match (&trigger.schedule, trigger.event) {
        (Some(_), _) => "schedule",
        (None, Some(event)) => event.as_str(),
        (None, None) => "none",
    }
}

impl HermesRuntime {
    /// The enabled routines this runtime's conversation seat speaks for.
    fn own_routines(&self) -> Vec<(String, RoutineToml)> {
        let (Some(pin), Some(discord)) = (self.registry_pin(), self.settings().discord.as_ref())
        else {
            return Vec::new();
        };
        pin.current()
            .objects
            .iter()
            .filter_map(|object| match &object.config {
                ObjectConfig::Routine(routine)
                    if routine.enabled && routine.seat == discord.seat =>
                {
                    Some((object.id.clone(), routine.as_ref().clone()))
                }
                _ => None,
            })
            .collect()
    }

    /// Fires every routine schedule occurrence that came due since the
    /// routine was first seen, within the catch-up window. Returns how
    /// many rows it queued.
    pub fn reconcile_routines(&self) -> Result<usize, String> {
        let routines = self.own_routines();
        let now = Timestamp::now();
        let declared = |id: &String| routines.iter().any(|(routine, _)| routine == id);
        let (seen, ()) = self.schedule.update_routines(|seen| {
            seen.first_seen.retain(|id, _| declared(id));
            seen.fired.retain(|id, _| declared(id));
            for (id, _) in &routines {
                seen.first_seen
                    .entry(id.clone())
                    .or_insert(now.as_millisecond());
            }
        })?;
        let zone = self.clock.zone();
        let mut queued = 0;
        for (id, routine) in &routines {
            let Some(schedule) = &routine.trigger.schedule else {
                continue;
            };
            let schedule = match RoutineSchedule::parse(schedule) {
                Ok(schedule) => schedule,
                Err(reason) => {
                    tracing::warn!(routine = %id, reason = %reason, "odin-hermes: routine id={id} skipped: {reason}");
                    continue;
                }
            };
            let Some(occurrence) = latest_occurrence(&schedule, &zone, now) else {
                continue;
            };
            let first_seen = seen.first_seen.get(id).copied().unwrap_or(i64::MAX);
            let at = occurrence.as_millisecond();
            if at < first_seen || now.as_millisecond() - at > CATCH_UP_MS {
                continue;
            }
            if self.queue_routine(id, routine, &at.to_string(), None, now)? {
                queued += 1;
            }
        }
        Ok(queued)
    }

    /// Feeds one observed event to the routines that follow it. `key`
    /// identifies the occurrence (a job uid, an incident id) so a replayed
    /// event fires nothing new; `profile` is the pod it concerns; an event
    /// that `occurred` before a routine was first seen never fires it (a
    /// pod that finished yesterday does not start today's chain).
    /// `occurred_at_ms` is Unix milliseconds.
    pub fn routine_event(
        &self,
        event: RoutineEvent,
        profile: Option<&str>,
        key: &str,
        detail: &str,
        occurred_at_ms: i64,
    ) -> Result<usize, String> {
        let now = Timestamp::now();
        let seen = self.schedule.routines()?;
        let mut queued = 0;
        for (id, routine) in self.own_routines() {
            let trigger = &routine.trigger;
            let narrowed = match event {
                pod if pod.concerns_a_pod() => trigger
                    .profile
                    .as_deref()
                    .is_none_or(|wanted| profile == Some(wanted)),
                RoutineEvent::FileReceived => trigger
                    .matches
                    .as_deref()
                    .is_none_or(|words| profile.is_some_and(|name| contains_words(name, words))),
                RoutineEvent::RepoPush => trigger
                    .matches
                    .as_deref()
                    .is_none_or(|project| profile == Some(project.trim())),
                RoutineEvent::RingGesture => {
                    profile.is_some_and(|made| trigger.follows_gesture(made))
                }
                _ => true,
            };
            let matches = trigger.event == Some(event)
                && narrowed
                && seen
                    .first_seen
                    .get(&id)
                    .is_some_and(|first| occurred_at_ms >= *first);
            if matches && self.queue_routine(&id, &routine, key, Some(detail), now)? {
                queued += 1;
            }
        }
        Ok(queued)
    }

    /// Whether any of this seat's routines follows `event` (a source with
    /// a cost, like a repository poll, runs only when one does).
    pub fn follows(&self, event: RoutineEvent) -> bool {
        self.own_routines()
            .iter()
            .any(|(_, routine)| routine.trigger.event == Some(event))
    }

    /// Polls mail matches and upcoming calendar events through the same adapters
    /// and credential leases as the seat's tools.
    /// Each occurrence is queued once (keyed by message or event); nothing
    /// that happened before the routine existed fires. Returns the reads
    /// that failed, for the caller to log, and the earliest lead time still
    /// ahead, which the caller polls again at.
    pub fn poll_routine_sources(&self) -> RoutineSourcePoll {
        let mut poll = RoutineSourcePoll::default();
        let mut problems = BTreeMap::new();
        let seen = match self.schedule.routines() {
            Ok(seen) => seen,
            Err(error) => {
                poll.failures.push(error);
                return poll;
            }
        };
        let now = Timestamp::now();
        let now_utc = time::OffsetDateTime::now_utc();
        let accounts: Vec<String> = self
            .settings()
            .accounts
            .iter()
            .map(|account| account.account.clone())
            .collect();
        for (id, routine) in self.own_routines() {
            let trigger = &routine.trigger;
            let Some(first_seen) = seen.first_seen.get(&id).copied() else {
                continue;
            };
            let watched: Vec<&String> = accounts
                .iter()
                .filter(|account| {
                    trigger
                        .account
                        .as_ref()
                        .is_none_or(|wanted| wanted == *account)
                })
                .collect();
            match trigger.event {
                Some(RoutineEvent::MailArrived) => {
                    let (Some(adapter), Some(text)) = (self.email.as_ref(), &trigger.matches)
                    else {
                        continue;
                    };
                    for account in watched {
                        let query = crate::email::EmailSearchQuery {
                            account: account.clone(),
                            text: text.clone(),
                            limit: 10,
                        };
                        let hits = match adapter.search(&query, now_utc) {
                            Ok(hits) => hits,
                            Err(error) => {
                                let problem = format!("mail search on {account} failed: {error}");
                                poll.failures.push(format!("routine {id}: {problem}"));
                                problems.insert(id.clone(), problem);
                                continue;
                            }
                        };
                        for hit in hits {
                            let Some(received) = hit.received_at.as_deref().and_then(|at| {
                                time::OffsetDateTime::parse(
                                    at,
                                    &time::format_description::well_known::Rfc3339,
                                )
                                .ok()
                            }) else {
                                continue;
                            };
                            let received_ms =
                                i64::try_from(received.unix_timestamp_nanos() / 1_000_000)
                                    .unwrap_or(i64::MAX);
                            if received_ms < first_seen
                                || now.as_millisecond() - received_ms > MAIL_WINDOW_MS
                            {
                                continue;
                            }
                            let detail = format!(
                                "mail on {account} from {}: \"{}\" (message {})",
                                hit.from.as_deref().unwrap_or("an unknown sender"),
                                hit.subject.as_deref().unwrap_or("(no subject)"),
                                hit.id
                            );
                            let occurrence = format!("mail:{account}:{}", hit.id);
                            if let Err(error) =
                                self.queue_routine(&id, &routine, &occurrence, Some(&detail), now)
                            {
                                poll.failures.push(error);
                            }
                        }
                    }
                }
                Some(RoutineEvent::CalendarEvent) => {
                    let (Some(adapter), Some(lead)) =
                        (self.calendar.as_ref(), trigger.lead_minutes)
                    else {
                        continue;
                    };
                    let lead = time::Duration::minutes(i64::from(lead));
                    let window = |at: time::OffsetDateTime| {
                        at.format(&time::format_description::well_known::Rfc3339)
                            .unwrap_or_default()
                    };
                    for account in watched {
                        let events = match adapter.read_window(
                            &crate::calendar::CalendarWindow {
                                account: account.clone(),
                                start: window(now_utc),
                                end: window(now_utc + lead + time::Duration::minutes(15)),
                            },
                            now_utc,
                        ) {
                            Ok(events) => events,
                            Err(error) => {
                                let problem = format!("calendar read on {account} failed: {error}");
                                poll.failures.push(format!("routine {id}: {problem}"));
                                problems.insert(id.clone(), problem);
                                continue;
                            }
                        };
                        for event in events {
                            let title = event.title.as_deref().unwrap_or("(untitled)");
                            if trigger
                                .matches
                                .as_deref()
                                .is_some_and(|words| !contains_words(title, words))
                            {
                                continue;
                            }
                            let Ok(start) = time::OffsetDateTime::parse(
                                &event.start,
                                &time::format_description::well_known::Rfc3339,
                            ) else {
                                continue;
                            };
                            let occurrence =
                                format!("calendar:{account}:{}:{}", event.id, event.start);
                            match lead_time(start, lead, now_utc, first_seen) {
                                LeadTime::Outside => continue,
                                LeadTime::Ahead(due) => {
                                    if poll.next_lead.as_ref().is_none_or(|next| due < next.due) {
                                        poll.next_lead = Some(NextLead {
                                            due,
                                            routine: id.clone(),
                                            occurrence,
                                        });
                                    }
                                    continue;
                                }
                                LeadTime::Due => {}
                            }
                            let minutes = (start - now_utc).whole_minutes();
                            let detail = format!(
                                "\"{title}\" on {account} starts at {} (in {minutes} min)",
                                self.clock.render(
                                    i64::try_from(start.unix_timestamp_nanos() / 1_000_000)
                                        .unwrap_or(i64::MAX)
                                )
                            );
                            if let Err(error) =
                                self.queue_routine(&id, &routine, &occurrence, Some(&detail), now)
                            {
                                poll.failures.push(error);
                            }
                        }
                    }
                }
                _ => {}
            }
        }
        *self.routine_state.problems.lock() = problems;
        poll
    }

    /// Record declaration time immediately: work started in the same turn may finish before reconciliation.
    fn note_routine_declared(&self, id: &str) -> Result<(), String> {
        let now = Timestamp::now().as_millisecond();
        let (_, added) = self.schedule.update_routines(|seen| {
            if seen.first_seen.contains_key(id) {
                return false;
            }
            seen.first_seen.insert(id.to_owned(), now);
            true
        })?;
        if added {
            tracing::info!(routine = %id, first_seen_ms = now, "odin-hermes: routine id={id} first_seen_ms={now} source=declared");
        }
        Ok(())
    }

    /// Records a delivered routine row as its routine's newest firing.
    pub(super) fn note_routine_fired(
        &self,
        routine: &str,
        item: &ScheduledItem,
        now: Timestamp,
    ) -> Result<(), String> {
        let occurrence = item
            .id
            .strip_prefix(&format!("routine:{routine}:"))
            .unwrap_or(&item.id)
            .to_owned();
        let trigger = self
            .own_routines()
            .iter()
            .find(|(id, _)| id == routine)
            .map_or("undeclared", |(_, declared)| {
                trigger_name(&declared.trigger)
            });
        let at_ms = now.as_millisecond();
        tracing::info!(
            routine = %routine,
            trigger = %trigger,
            occurrence = %occurrence,
            "odind: routine fired id={routine} trigger={trigger} occurrence={occurrence} kind={:?} late_ms={}",
            item.kind,
            at_ms - item.fire_at_ms
        );
        self.schedule
            .update_routines(|seen| {
                if seen.first_seen.contains_key(routine) {
                    seen.fired.insert(routine.to_owned(), (at_ms, occurrence));
                }
            })
            .map(drop)
    }

    /// What `registry_read` shows beside each routine declaration: when it
    /// last fired (or that it never has since Odin first saw it), and the
    /// source read its last poll could not make. The schedule is read once
    /// per call, however many routines are shown.
    pub(super) fn routine_statuses(
        &self,
    ) -> Result<impl Fn(&str) -> Map<String, Value> + '_, String> {
        // The record and the delivered rows are written apart: the newer
        // of the two wins (a stop between them, or a failed record write).
        let activity = self.schedule.routine_activity()?;
        Ok(move |id: &str| {
            let seen = activity.get(id);
            let fired = seen.and_then(|seen| seen.recorded.max(seen.delivered));
            let mut status = Map::new();
            status.insert(
                "lastFired".to_owned(),
                match (fired, seen.and_then(|seen| seen.first_seen)) {
                    (Some(at), _) => json!(self.clock.render(at)),
                    (None, Some(first)) => json!(format!(
                        "never since Odin first saw it {}",
                        self.clock.render(first)
                    )),
                    (None, None) => json!("never"),
                },
            );
            if let Some(problem) = self.routine_state.problems.lock().get(id) {
                status.insert("sourceProblem".to_owned(), json!(problem));
            }
            status
        })
    }

    fn queue_routine(
        &self,
        id: &str,
        routine: &RoutineToml,
        occurrence: &str,
        detail: Option<&str>,
        now: Timestamp,
    ) -> Result<bool, String> {
        let text = match detail {
            Some(detail) => format!("{}\nWhat happened: {detail}", routine.action.text.trim()),
            None => routine.action.text.trim().to_owned(),
        };
        let kind = match routine.action.kind {
            RoutineActionKind::Brief => ScheduleKind::Wake,
            RoutineActionKind::Dm => ScheduleKind::Notify,
        };
        let row = format!("routine:{id}:{occurrence}");
        let digest = declaration_digest(routine)?;
        let queued =
            self.schedule
                .enqueue_once(&row, kind, &text, Some((id, digest)), false, now)?;
        if queued {
            tracing::info!(
                routine = %id,
                occurrence = %occurrence,
                "odin-hermes: routine id={id} occurrence={occurrence} action={:?} queued",
                routine.action.kind
            );
            self.reconcile_wake.notify_one();
        }
        Ok(queued)
    }

    /// Whether a due routine row may be handed to delivery now, checked
    /// against the declaration current at this moment — per row, since an
    /// earlier delivery in the same pass can change it. With no registry
    /// pin or conversation seat bound it waits, neither cancelled nor sent.
    /// When the declaration that queued it is no longer current (removed,
    /// disabled, replaced, or a row from before rows were bound to one), a
    /// row never handed off is cancelled; one whose handoff may have reached
    /// Colin keeps its evidence and is held, never relabelled or re-sent.
    pub(super) fn routine_dispatchable(
        &self,
        routine: &str,
        item: &ScheduledItem,
    ) -> Result<bool, String> {
        let (Some(pin), Some(discord)) = (self.registry_pin(), self.settings().discord.as_ref())
        else {
            return Ok(false);
        };
        let snapshot = pin.current();
        let current = snapshot
            .objects
            .iter()
            .find(|object| object.id == routine)
            .and_then(|object| match &object.config {
                ObjectConfig::Routine(declared)
                    if declared.enabled && declared.seat == discord.seat =>
                {
                    Some(declared.as_ref())
                }
                _ => None,
            })
            .map(declaration_digest)
            .transpose()?;
        if current.is_some() && current == item.routine_digest {
            return Ok(true);
        }
        let now = Timestamp::now();
        if !item.dispatch_started && self.schedule.cancel_undispatched(&item.id, now)? {
            tracing::info!(
                routine = %routine,
                "odin-hermes: routine id={routine} row={} cancelled before dispatch: the \
                 declaration that queued it is no longer current",
                item.id
            );
        } else {
            self.schedule.hold_unresolved(&item.id, now)?;
            tracing::warn!(
                routine = %routine,
                "odin-hermes: routine id={routine} row={} held: it was handed to delivery \
                 under a declaration no longer current, outcome unknown",
                item.id
            );
        }
        Ok(false)
    }
}

/// The digest a routine row binds: the complete declaration (trigger,
/// action, seat, enabled), so a replacement under the same id differs.
fn declaration_digest(routine: &RoutineToml) -> Result<String, String> {
    serde_json::to_vec(routine)
        .map(|bytes| odin_domain::Digest::hash(&bytes).to_string())
        .map_err(|error| format!("routine declaration could not be serialized: {error}"))
}

/// How old a matching mail may be and still fire a routine.
const MAIL_WINDOW_MS: i64 = 24 * 3600 * 1000;

/// Whether every word of `words` appears in `text`, case-insensitively.
fn contains_words(text: &str, words: &str) -> bool {
    let text = text.to_lowercase();
    words
        .split_whitespace()
        .all(|word| text.contains(&word.to_lowercase()))
}

#[cfg(test)]
mod tests {
    use super::{lead_time, LeadTime};
    use time::macros::datetime;
    use time::Duration;

    #[test]
    fn lead_minutes_requires_calendar_event_and_valid_minutes() {
        use serde_json::json;

        for arguments in [
            json!({"schedule":"daily 08:00", "lead_minutes":30}),
            json!({"event":"mail_arrived", "lead_minutes":0}),
            json!({"event":"calendar_event", "lead_minutes":0}),
            json!({"event":"calendar_event", "lead_minutes":1441}),
            json!({"event":"calendar_event", "lead_minutes":"30"}),
        ] {
            let error = super::lead_minutes(&arguments).unwrap_err();
            assert!(error.to_string().contains("lead_minutes"), "{error}");
        }
        assert_eq!(
            super::lead_minutes(&json!({"event":"calendar_event", "lead_minutes":30})).unwrap(),
            Some(30)
        );
        assert_eq!(
            super::lead_minutes(&json!({"schedule":"daily 08:00", "lead_minutes":null})).unwrap(),
            None
        );
    }

    #[test]
    fn a_lead_time_is_ahead_then_due_until_the_event_starts() {
        let start = datetime!(2026-10-04 13:35 -7);
        let lead = Duration::minutes(20);
        let first_seen = datetime!(2026-10-04 13:07:40 -7).unix_timestamp() * 1_000;
        let at = |now| lead_time(start, lead, now, first_seen);
        assert_eq!(
            at(datetime!(2026-10-04 13:13:40 -7)),
            LeadTime::Ahead(datetime!(2026-10-04 13:15 -7))
        );
        assert_eq!(at(datetime!(2026-10-04 13:15 -7)), LeadTime::Due);
        assert_eq!(at(datetime!(2026-10-04 13:34:59 -7)), LeadTime::Due);
        assert_eq!(at(datetime!(2026-10-04 13:35 -7)), LeadTime::Outside);
        let later = datetime!(2026-10-04 13:16 -7).unix_timestamp() * 1_000;
        assert_eq!(
            lead_time(start, lead, datetime!(2026-10-04 13:17 -7), later),
            LeadTime::Outside
        );
    }
}
