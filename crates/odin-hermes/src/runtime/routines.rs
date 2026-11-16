//! Published routines queue schedule rows for timed or event-triggered delivery.

use std::collections::BTreeMap;
use std::sync::Arc;

use jiff::Timestamp;
use odin_registry::schema::{
    dm_placeholders, fill_dm, DmFacts, RoutineActionKind, RoutineEvent, RoutineSchedule,
    RoutineToml, RoutineTriggerToml,
};
use odin_registry::ObjectConfig;

use odin_domain::Scope;
use odin_omp::capability_parameters;
use odin_omp::host_tools::{HostTool, HostToolError, RpcHostToolDefinition, ToolLoadMode};
use serde_json::{json, Map, Value};

use super::tools::{parse_string, CapabilityTool};
use super::HermesRuntime;
use crate::schedule::{latest_occurrence, ScheduleKind, ScheduledItem, ROUTINE_ROW_PREFIX};

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
    /// The project a `project_event` routine follows.
    pub project: Option<String>,
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
        let unavailable = |reason: String| HostToolError::unavailable(SET_TOOL, reason);
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
            project: optional(&arguments, "project", 128)?,
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
            description: "Declares (or replaces, by id) a routine that runs without the owner \
                 asking. Trigger: exactly one of `schedule` in the owner's zone — \"weekdays 07:30\", \
                 \"daily 21:00\", \"mon,wed,fri 16:00\", \"monthly 1 09:00\", \"every 2 hours\" — \
                 or `event`: workload_succeeded / workload_failed (optionally one pod \
                 `profile`), watchdog, incident; mail_arrived (`match` is the mail search, e.g. \
                 a sender address or subject words; optional `account`); calendar_event \
                 (`lead_minutes` before an event, optional `match` on its title and `account`) \
                 — e.g. 30 minutes before any class; file_received (he sends a file; optional \
                 `match` on its name); repo_push (any push to a project repository; optional \
                 `match` = the project); ring_gesture (the owner's smart ring: optional `match` = the \
                 gesture name); project_event (a project's tooling reports an event, e.g. a job \
                 done: `project` names the project, optional `match` = event kinds). Action: brief starts a turn with text as its instruction; \
                 dm sends text as written; on workload_succeeded or workload_failed it may \
                 name {label}, {outcome}, {summary} (the run's status summary) or {profile}. \
                 Routines use the seat's existing authority. \
                 Use reminder_set for one-shot requests."
                .into(),
            parameters: capability_parameters!("routine.set"),
            hidden: false,
            load_mode: ToolLoadMode::Discoverable,
        },
        Box::new(handler),
    )));
    let remove_runtime = Arc::clone(runtime);
    let handler = move |scope: Scope, arguments: Value| {
        let unavailable = |reason: String| HostToolError::unavailable(REMOVE_TOOL, reason);
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
            parameters: capability_parameters!("routine.remove"),
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

/// What a finished run says about itself for a routine dm: the label its launch named and its newest status summary.
#[derive(Clone, Copy, Debug, Default)]
pub struct RunFacts<'a> {
    pub label: Option<&'a str>,
    pub summary: &'a str,
}

impl HermesRuntime {
    /// Enabled seats whose `[live] watches` names `watch`, unqualified or as
    /// `watch:<project>` for the event's `project`.
    pub fn seats_watching(&self, watch: &str, project: Option<&str>) -> Vec<odin_domain::SeatId> {
        let Some(pin) = self.registry_pin() else {
            return Vec::new();
        };
        pin.current()
            .objects
            .iter()
            .filter_map(|object| match &object.config {
                ObjectConfig::Seat(seat)
                    if seat.enabled
                        && seat.live.as_ref().is_some_and(|live| {
                            live.watches
                                .iter()
                                .any(|declared| watch_matches(declared, watch, project))
                        }) =>
                {
                    object.id.parse().ok()
                }
                _ => None,
            })
            .collect()
    }

    /// Whether any enabled seat watches `watch`, for any project.
    pub fn any_seat_watches(&self, watch: &str) -> bool {
        self.registry_pin().is_some_and(|pin| {
            pin.current()
                .objects
                .iter()
                .any(|object| match &object.config {
                    ObjectConfig::Seat(seat) if seat.enabled => {
                        seat.live.as_ref().is_some_and(|live| {
                            live.watches.iter().any(|declared| {
                                declared
                                    .split_once(':')
                                    .map_or(declared.as_str(), |(name, _)| name)
                                    == watch
                            })
                        })
                    }
                    _ => false,
                })
        })
    }

    /// The project of `lane`, and the seat of that project's enabled
    /// `owns_workloads` lane when one is declared.
    pub fn workload_owner(
        &self,
        lane: &odin_domain::LaneId,
    ) -> (Option<odin_domain::ProjectId>, Option<odin_domain::SeatId>) {
        let Some(pin) = self.registry_pin() else {
            return (None, None);
        };
        let snapshot = pin.current();
        let lanes = || {
            snapshot
                .objects
                .iter()
                .filter_map(|object| match &object.config {
                    ObjectConfig::Lane(declared) if declared.enabled => Some((object, declared)),
                    _ => None,
                })
        };
        let Some(project) = lanes()
            .find(|(object, _)| object.id == lane.as_str())
            .map(|(_, declared)| declared.project.clone())
        else {
            return (None, None);
        };
        let owner = lanes()
            .find(|(_, declared)| declared.owns_workloads && declared.project == project)
            .map(|(_, declared)| declared.default_seat.clone());
        (Some(project), owner)
    }

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
            if self.queue_routine(id, routine, &at.to_string(), None, now, None)? {
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
        self.route_event(
            event,
            profile,
            RunFacts::default(),
            key,
            detail,
            occurred_at_ms,
        )
    }

    /// As [`Self::routine_event`] for an event a project's tooling reported:
    /// it fires the routines whose `trigger.project` is `project` and whose
    /// `match`, when present, names `kind`.
    pub fn routine_project_event(
        &self,
        project: &str,
        kind: &str,
        key: &str,
        detail: &str,
        occurred_at_ms: i64,
    ) -> Result<usize, String> {
        self.routine_event(
            RoutineEvent::ProjectEvent,
            Some(&format!("{project} {kind}")),
            key,
            detail,
            occurred_at_ms,
        )
    }

    /// As [`Self::routine_event`] for a finished workload run: a dm's
    /// `{label}` is the run's label (its profile when the launch named none)
    /// and `{summary}` its status summary, empty when it printed none.
    pub fn routine_workload_event(
        &self,
        event: RoutineEvent,
        profile: Option<&str>,
        run: RunFacts<'_>,
        key: &str,
        detail: &str,
        occurred_at_ms: i64,
    ) -> Result<usize, String> {
        self.route_event(event, profile, run, key, detail, occurred_at_ms)
    }

    fn route_event(
        &self,
        event: RoutineEvent,
        profile: Option<&str>,
        run: RunFacts<'_>,
        key: &str,
        detail: &str,
        occurred_at_ms: i64,
    ) -> Result<usize, String> {
        let now = Timestamp::now();
        let seen = self.schedule.routines()?;
        let outcome = match event {
            RoutineEvent::WorkloadSucceeded => Some("succeeded"),
            RoutineEvent::WorkloadFailed => Some("failed"),
            _ => None,
        };
        let facts = outcome.map(|outcome| DmFacts {
            label: run.label.or(profile).unwrap_or_default(),
            outcome,
            summary: run.summary,
            profile: profile.unwrap_or_default(),
        });
        let mut queued = 0;
        for (id, routine) in self.own_routines() {
            let trigger = &routine.trigger;
            let matches = trigger.event == Some(event)
                && narrows(trigger, event, profile)
                && seen
                    .first_seen
                    .get(&id)
                    .is_some_and(|first| occurred_at_ms >= *first);
            if matches
                && self.queue_routine(&id, &routine, key, Some(detail), now, facts.as_ref())?
            {
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
            .strip_prefix(&format!("{ROUTINE_ROW_PREFIX}{routine}:"))
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

    /// Queues one occurrence of `routine`. A dm that names placeholders is
    /// the owner's message as filled from `facts`; any other text gets the
    /// event's detail after it, as before.
    fn queue_routine(
        &self,
        id: &str,
        routine: &RoutineToml,
        occurrence: &str,
        detail: Option<&str>,
        now: Timestamp,
        facts: Option<&DmFacts<'_>>,
    ) -> Result<bool, String> {
        let action = routine.action.text.trim();
        let filled = match (routine.action.kind, facts) {
            (RoutineActionKind::Dm, Some(facts))
                if dm_placeholders(action).is_ok_and(|used| !used.is_empty()) =>
            {
                Some(fill_dm(action, *facts))
            }
            _ => None,
        };
        let text = match (filled, detail) {
            (Some(filled), _) => filled,
            (None, Some(detail)) => format!("{action}\nWhat happened: {detail}"),
            (None, None) => action.to_owned(),
        };
        let kind = match routine.action.kind {
            RoutineActionKind::Brief => ScheduleKind::Wake,
            RoutineActionKind::Dm => ScheduleKind::Notify,
        };
        let row = format!("{ROUTINE_ROW_PREFIX}{id}:{occurrence}");
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
    /// the owner keeps its evidence and is held, never relabelled or re-sent.
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


/// Whether every word of `words` appears in `text`, case-insensitively.
fn contains_words(text: &str, words: &str) -> bool {
    let text = text.to_lowercase();
    words
        .split_whitespace()
        .all(|word| text.contains(&word.to_lowercase()))
}

/// Whether `trigger`'s narrowing (`profile` or `matches`) accepts this occurrence of `event`.
fn narrows(trigger: &RoutineTriggerToml, event: RoutineEvent, profile: Option<&str>) -> bool {
    match event {
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
        // Neither a project id nor a kind holds a space: the subject is `<project> <kind>`.
        RoutineEvent::ProjectEvent => profile
            .and_then(|subject| subject.split_once(' '))
            .is_some_and(|(project, kind)| {
                trigger.project.as_deref().map(str::trim) == Some(project)
                    && trigger
                        .matches
                        .as_deref()
                        .is_none_or(|kinds| kinds.split_whitespace().any(|want| want == kind))
            }),
        _ => true,
    }
}

/// A declared watch entry `name` or `name:<project>` against an event of
/// `watch` in `project`; an unqualified entry matches every project.
fn watch_matches(declared: &str, watch: &str, project: Option<&str>) -> bool {
    match declared.split_once(':') {
        None => declared == watch,
        Some((name, scoped)) => name == watch && project == Some(scoped),
    }
}

#[cfg(test)]
mod tests {
    use super::watch_matches;

    #[test]
    fn a_project_watch_wakes_only_for_its_project() {
        assert!(watch_matches(
            "workload_watch:project-alpha",
            "workload_watch",
            Some("project-alpha")
        ));
        assert!(!watch_matches(
            "workload_watch:project-alpha",
            "workload_watch",
            Some("odin")
        ));
        assert!(!watch_matches(
            "workload_watch:project-alpha",
            "workload_watch",
            None
        ));
        assert!(!watch_matches(
            "workload_watch:project-alpha",
            "child_report",
            Some("project-alpha")
        ));
        assert!(watch_matches(
            "workload_watch",
            "workload_watch",
            Some("odin")
        ));
        assert!(watch_matches("workload_watch", "workload_watch", None));
        assert!(watch_matches(
            "simulation:project-alpha",
            "simulation",
            Some("project-alpha")
        ));
        assert!(!watch_matches(
            "simulation:project-alpha",
            "simulation",
            Some("odin")
        ));
        assert!(!watch_matches(
            "simulation:project-alpha",
            "simulation",
            None
        ));
        assert!(watch_matches("simulation", "simulation", Some("odin")));
    }



}
