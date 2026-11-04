//! Follow-through on delegated work. A job (a pod or a child seat) that ends
//! without its result leaves the owner's ask open: the wake names what is
//! undone, what was tried and what was not, and the ask wakes the seat again
//! every [`HermesSettings::open_ask_minutes`] until a result is delivered, the
//! seat relaunches it (a running pod holds the wake back) or drops it with
//! `reminder_cancel`. Live memory lists the pods and the ask under the job that
//! launched them, so the notes pinned to that job show beside them.
//!
//! [`HermesSettings::open_ask_minutes`]: crate::config::HermesSettings::open_ask_minutes

use jiff::Timestamp;
use odin_brain::service::LiveEntry;
use serde_json::{json, Value};

use super::HermesRuntime;
use crate::schedule::OpenAsk;

/// The longest subject or unmet line an ask keeps, in characters.
const MAX_LINE_CHARS: usize = 300;

/// A delegated job the daemon sees running now.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RunningJob {
    /// The id notes pin to.
    pub id: String,
    pub title: String,
    pub started_ms: u64,
}

/// What a delegated job that ended without its result left behind.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Unmet<'a> {
    /// What the ask is about: the same for a job and its relaunch.
    pub subject: &'a str,
    /// The job that ended; notes pinned to it show in live memory.
    pub job: &'a str,
    /// What the job left undone.
    pub items: &'a [String],
    /// The methods the job tried, then the ones its profile offered that it
    /// never called; `None` when nothing recorded them.
    pub methods: Option<(&'a [String], &'a [String])>,
}

/// Opens the id of an ask and of each of its wakes.
const ASK_PREFIX: &str = "follow-";
/// Hex digits of the subject's digest in an ask's id.
const ASK_DIGITS: usize = 8;

/// The id `reminder_cancel` takes to drop the ask about `subject`.
fn ask_id(subject: &str) -> String {
    let digest = odin_domain::Digest::hash(subject.as_bytes()).to_string();
    format!("{ASK_PREFIX}{}", &digest[digest.len() - ASK_DIGITS..])
}

/// The ask a wake id of [`HermesRuntime::wake_open_asks`] belongs to.
pub(super) fn ask_of_wake(wake_id: &str) -> Option<&str> {
    let (ask, due) = wake_id.split_at_checked(ASK_PREFIX.len() + ASK_DIGITS)?;
    (ask.starts_with(ASK_PREFIX) && due.strip_prefix('-')?.parse::<i64>().is_ok()).then_some(ask)
}

fn bounded(text: &str) -> String {
    let flat = text.split_whitespace().collect::<Vec<_>>().join(" ");
    match flat.char_indices().nth(MAX_LINE_CHARS) {
        Some((cut, _)) => format!("{}…", &flat[..cut]),
        None => flat,
    }
}

fn listing(names: &[String]) -> String {
    if names.is_empty() {
        "none".to_owned()
    } else {
        names.join(", ")
    }
}

fn minutes_between(from_ms: i64, to_ms: i64) -> i64 {
    (to_ms - from_ms).max(0) / 60_000
}

impl HermesRuntime {
    /// Queues the wake for a job that ended without its result, `lead` being
    /// the account of how it ended, and keeps the ask about `unmet.subject`
    /// open. The same report observed again opens nothing new and moves no
    /// wake.
    pub fn report_unmet(
        &self,
        wake_id: &str,
        lead: &str,
        unmet: &Unmet<'_>,
    ) -> Result<bool, String> {
        let now = Timestamp::now();
        let now_ms = now.as_millisecond();
        let id = ask_id(unmet.subject);
        self.schedule.open_ask(&OpenAsk {
            id: id.clone(),
            subject: bounded(unmet.subject),
            job: unmet.job.to_owned(),
            unmet: bounded(&unmet.items.join("; ")),
            opened_ms: now_ms,
            next_wake_ms: now_ms + self.open_ask_interval_ms(),
        })?;
        let items = if unmet.items.is_empty() {
            "- the job did not say".to_owned()
        } else {
            unmet
                .items
                .iter()
                .map(|item| format!("- {}", bounded(item)))
                .collect::<Vec<_>>()
                .join("\n")
        };
        let methods = unmet.methods.map_or_else(String::new, |(tried, untried)| {
            format!(
                "Methods already tried: {}\nMethods not yet tried: {}\n",
                listing(tried),
                listing(untried)
            )
        });
        let owner = self.owner_name();
        let text = format!(
            "{lead}\n{owner}'s ask \"{}\" is still open and stays open until its result is \
             delivered, you relaunch it, or {owner} drops it.\nUnmet:\n{items}\n{methods}This \
             wakes you again every {} minutes while nothing runs for it. If you tell {owner} it \
             cannot be done, or it is dropped, call reminder_cancel with id \"{id}\".",
            bounded(unmet.subject),
            self.settings.open_ask_minutes,
        );
        self.wake_once(wake_id, &text)
    }

    /// The ask about `subject` is delivered: its wakes stop.
    pub fn ask_delivered(&self, subject: &str) -> Result<bool, String> {
        self.schedule.close_ask(&ask_id(subject))
    }

    /// Drops the open ask `id` names (`reminder_cancel`), as the reminder it
    /// reads as; `None` when `id` is no ask.
    pub(super) fn drop_ask(&self, id: &str) -> Result<Option<Value>, String> {
        let Some(ask) = self
            .schedule
            .open_asks()?
            .into_iter()
            .find(|ask| ask.id == id)
        else {
            return Ok(None);
        };
        self.schedule.close_ask(id)?;
        Ok(Some(json!({
            "id": ask.id,
            "text": format!("open ask \"{}\"", ask.subject),
            "kind": "wake",
            "fireAt": self.clock.render(ask.next_wake_ms),
            "status": "cancelled",
            "anchor": null,
            "repeat": null,
        })))
    }

    /// The pods running now, as the daemon reads them: an ask whose job is
    /// running again waits for it.
    pub fn set_running_jobs(&self, jobs: Vec<RunningJob>) {
        *self
            .delegated
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = jobs;
    }

    /// The methods a pod's `profile` offers split by whether its journal shows
    /// the pod calling them: `(tried, not yet tried)`. A pod whose journal or
    /// profile cannot be read says so instead of guessing.
    pub fn pod_methods(
        &self,
        session: &str,
        profile: &str,
    ) -> Result<(Vec<String>, Vec<String>), String> {
        let called = self
            .run_stats_route()
            .ok_or("the run stats route is not bound, so the pod's calls are unread")?
            .tools_called(session)?;
        let pin = self.registry_pin().ok_or("no registry is pinned")?;
        let offered: Vec<String> = pin
            .current()
            .objects
            .iter()
            .find_map(|object| match &object.config {
                odin_registry::ObjectConfig::Workload(workload) if object.id == profile => {
                    Some(workload.tools.iter().map(ToString::to_string).collect())
                }
                _ => None,
            })
            .ok_or_else(|| format!("no workload profile {profile} is published"))?;
        let untried = offered
            .into_iter()
            .filter(|tool| !called.contains(tool))
            .collect();
        Ok((called.into_iter().collect(), untried))
    }

    /// The background job whose accepted receipt names the pod run `run`: the
    /// launch she made. Notes pinned to that job belong to the pod.
    fn launching_job(&self, run: &str) -> Option<String> {
        let board = self.jobs.lock().ok()?.clone()?;
        board.list()["jobs"].as_array()?.iter().find_map(|job| {
            job["outcome"]
                .as_str()
                .is_some_and(|outcome| outcome.contains(run))
                .then(|| job["job"].as_str().map(str::to_owned))
                .flatten()
        })
    }

    /// Live memory's entries for delegated work, under the background job that
    /// launched each pod when it has one (they replace that job's own line, so
    /// the notes pinned to the job show beside the pod): each running pod, and
    /// each open ask.
    pub(super) fn follow_through_entries(&self, now_ms: u64) -> Vec<LiveEntry> {
        let running = self
            .delegated
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        let asks = self.schedule.open_asks().unwrap_or_else(|error| {
            tracing::error!("odin-hermes: open asks unreadable for live memory: {error}");
            Vec::new()
        });
        let now = i64::try_from(now_ms).unwrap_or(i64::MAX);
        let owner = self.owner_name();
        running
            .into_iter()
            .map(|job| LiveEntry {
                line: format!(
                    "pod {}: running for {} min",
                    job.title,
                    now_ms.saturating_sub(job.started_ms) / 60_000
                ),
                id: self.launching_job(&job.id).unwrap_or(job.id),
                open: true,
                at_ms: job.started_ms,
            })
            .chain(asks.into_iter().map(|ask| LiveEntry {
                line: format!(
                    "{owner}'s ask \"{}\" open {} min, its jobs ended without a delivered \
                     result: {}",
                    ask.subject,
                    minutes_between(ask.opened_ms, now),
                    ask.unmet
                ),
                id: self.launching_job(&ask.job).unwrap_or(ask.id),
                open: true,
                at_ms: u64::try_from(ask.opened_ms).unwrap_or(0),
            }))
            .collect()
    }

    fn open_ask_interval_ms(&self) -> i64 {
        i64::from(self.settings.open_ask_minutes) * 60_000
    }

    /// Whether `id` names a wake of an ask that is no longer open.
    pub(super) fn ask_wake_is_moot(&self, id: &str) -> Result<bool, String> {
        let Some(ask) = ask_of_wake(id) else {
            return Ok(false);
        };
        Ok(!self.schedule.open_asks()?.iter().any(|open| open.id == ask))
    }

    /// Wakes the seat for every open ask whose interval has passed, unless a
    /// pod is running: that look moves one interval on either way. The wake
    /// shows how long the ask has been open.
    pub(super) fn wake_open_asks(&self, now: Timestamp) -> Result<(), String> {
        let now_ms = now.as_millisecond();
        for ask in self.schedule.open_asks()? {
            if ask.next_wake_ms > now_ms {
                continue;
            }
            self.schedule
                .wake_ask_at(&ask.id, now_ms + self.open_ask_interval_ms())?;
            let running = !self
                .delegated
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .is_empty();
            if running {
                continue;
            }
            let owner = self.owner_name();
            let text = format!(
                "{owner}'s ask \"{}\" has been open {} min and nothing is running for it: its \
                 last job ({}) ended without a delivered result. Unmet: {}\nRelaunch it with a \
                 method not yet tried, deliver what you have, or tell {owner} it cannot be done. \
                 After you tell {owner} it cannot be done, or it is dropped, call reminder_cancel \
                 with id \"{}\".",
                ask.subject,
                minutes_between(ask.opened_ms, now_ms),
                ask.job,
                ask.unmet,
                ask.id
            );
            self.schedule
                .wake_once(&format!("{}-{}", ask.id, ask.next_wake_ms), &text, now)?;
        }
        Ok(())
    }
}
