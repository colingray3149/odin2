//! Background jobs. A host tool call that is still running after the
//! seat's declared `[limits] inline_seconds` becomes a job: the model is
//! answered at once with the job's id, and the call keeps running under
//! its capability's declared timeout. When it finishes, fails or passes
//! that deadline, a job report wakes the conversation, so she tells the owner
//! what happened. `jobs_list` shows her what is running.
//!
//! A seat may have `limits.max_background_jobs` running (default 4). The
//! slot is reserved only when the call actually detaches at the inline
//! deadline: a call that finishes inline never takes one, and a full board
//! at the deadline keeps the call running inline instead of refusing it —
//! its answer arrives late in the same turn, never not at all. Detached
//! jobs are a snapshot. A restart does not replay them: one report says
//! they ended when Odin stopped, then the snapshot is dropped. A failed
//! report leaves it, so the next start retries the same wake.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use odin_domain::job_report::{self, STARTED};
use odin_domain::SeatId;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

/// The deadline of a job whose tool declares no timeout.
pub const DEFAULT_DEADLINE: Duration = Duration::from_secs(600);
/// The shortest job deadline. Declared timeouts were never enforced on
/// builtin tools and some are tight (a 10 MB Discord upload declares 60 s
/// against its own 120 s request deadline, whose error names the cause
/// better); a job gets at least this long.
pub const MIN_DEADLINE: Duration = Duration::from_secs(180);
/// Tools that always answer in the foreground: an image result cannot ride a
/// job report, and the job list must answer at once.
const FOREGROUND: &[&str] = &["media_view", "jobs_list"];
/// Finished jobs `jobs_list` still shows.
const KEEP_FINISHED: usize = 20;
/// The most of a job's result a report carries.
const REPORT_CHARS: usize = 6_000;

/// Delivers one report: a wake id unique to the job, and its text.
pub type JobReport = Arc<dyn Fn(&str, &str) -> Result<(), String> + Send + Sync>;

/// More live-memory entries the seat's runtime keeps for the board's jobs
/// (delegated work: its pods and the asks still open), as of `now_ms`.
pub type LiveSource = Arc<dyn Fn(u64) -> Vec<odin_brain::service::LiveEntry> + Send + Sync>;

/// A slot held while a call detaches at its inline deadline. Pass it to
/// [`JobBoard::start`] to record the detached call.
#[derive(Debug)]
pub struct Reservation {
    id: u64,
}

/// Running jobs the previous process left. `cutoff` is stable so a retried
/// report is the same wake.
#[derive(Clone, Debug, Deserialize, Serialize)]
struct Snapshot {
    cutoff: u64,
    jobs: Vec<SnapshotJob>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct SnapshotJob {
    id: String,
    tool: String,
    about: String,
}

pub struct JobBoard {
    seat: SeatId,
    report: JobReport,
    /// Makes wake ids unique across daemon restarts.
    boot: u64,
    /// The seat's `[limits] inline_seconds`: how long a call runs in the
    /// foreground before it may detach into a job.
    inline: Duration,
    max_background: u16,
    /// Absent when a restart has nothing to record.
    store: Option<PathBuf>,
    live_source: Mutex<Option<LiveSource>>,
    state: Mutex<State>,
    /// One snapshot write at a time: they share the temporary file.
    saving: Mutex<()>,
}

struct State {
    next: u64,
    held: std::collections::BTreeSet<u64>,
    jobs: Vec<Job>,
}

struct Job {
    id: String,
    tool: String,
    about: String,
    started: Instant,
    deadline: Duration,
    /// The call's latest progress line, set while it runs.
    progress: odin_domain::progress::Slot,
    /// Whether it went through, what came of it, and when it ended.
    outcome: Option<(bool, String, Duration)>,
}

impl Job {
    fn title(&self) -> String {
        if self.about.is_empty() {
            self.tool.clone()
        } else {
            format!("{}: {}", self.tool, self.about)
        }
    }
}

impl JobBoard {
    /// `inline` is the seat's `limits.inline_seconds` and `max_background`
    /// its `limits.max_background_jobs`. `store` is the snapshot of
    /// detached jobs. Jobs it names are reported once and not replayed. A
    /// snapshot that cannot be read is left in place and not replaced, so
    /// the next start can still report it.
    pub fn open(
        seat: SeatId,
        report: JobReport,
        inline: Duration,
        max_background: u16,
        store: Option<PathBuf>,
    ) -> Self {
        let boot = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |since| since.as_secs());
        let store = store.filter(|path| match report_cutoff(path, &report) {
            Ok(()) => true,
            Err(error) => {
                tracing::error!("odin-omp: job snapshot not reported or not removed: {error}");
                false
            }
        });
        Self {
            seat,
            report,
            boot,
            inline,
            max_background,
            store,
            live_source: Mutex::new(None),
            state: Mutex::new(State {
                next: 0,
                held: std::collections::BTreeSet::new(),
                jobs: Vec::new(),
            }),
            saving: Mutex::new(()),
        }
    }

    /// Whether a call of `tool` by a session of `seat` may become a job.
    pub fn runs_in_background(&self, seat: Option<&SeatId>, tool: &str) -> bool {
        seat == Some(&self.seat) && !FOREGROUND.contains(&tool)
    }

    /// How long a call runs in the foreground before it may detach.
    pub fn inline(&self) -> Duration {
        self.inline
    }

    /// Jobs still running, held detach slots included.
    pub fn running(&self) -> usize {
        let state = self.state();
        state
            .jobs
            .iter()
            .filter(|job| job.outcome.is_none())
            .count()
            + state.held.len()
    }

    fn state(&self) -> std::sync::MutexGuard<'_, State> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Takes a background slot when a call detaches at its inline deadline.
    /// `Err` names the cap; the caller keeps the call running inline.
    pub fn try_reserve(&self) -> Result<Reservation, String> {
        let mut state = self.state();
        let running = state
            .jobs
            .iter()
            .filter(|job| job.outcome.is_none())
            .count();
        let cap = usize::from(self.max_background);
        if running + state.held.len() >= cap {
            return Err(format!(
                "{cap} jobs already running (limits.max_background_jobs); \
                 wait for a report or jobs_list"
            ));
        }
        state.next += 1;
        let id = state.next;
        state.held.insert(id);
        Ok(Reservation { id })
    }

    /// Detaches a reserved call at its inline deadline. The slot stays
    /// taken. `started` is the call's one real start time, so the job's
    /// run time and deadline are measured from when the call began, not
    /// from when it detached.
    pub fn start(
        &self,
        reservation: Reservation,
        tool: &str,
        arguments: &Value,
        deadline: Duration,
        started: Instant,
        progress: odin_domain::progress::Slot,
    ) -> Result<(String, Value), String> {
        let (id, result) = {
            let mut state = self.state();
            if !state.held.remove(&reservation.id) {
                return Err(
                    "the background slot was already released, so the call was not detached"
                        .to_owned(),
                );
            }
            let id = format!("j{}", reservation.id);
            let about = arguments
                .as_object()
                .and_then(|fields| fields.values().find_map(Value::as_str))
                .map(|text| text.chars().take(80).collect())
                .unwrap_or_default();
            state.jobs.push(Job {
                id: id.clone(),
                tool: tool.to_owned(),
                about,
                started,
                deadline,
                progress,
                outcome: None,
            });
            let text = format!(
                "Still running after {} s, so it continues {STARTED}{id} \
                 (deadline {} s). No result is available yet. Its completion report \
                 will carry the evidence and outcome; jobs_list shows its progress meanwhile.",
                self.inline.as_secs(),
                deadline.as_secs()
            );
            let result = json!({
                "content": [{ "type": "text", "text": text }],
                "details": { "job": &id, "state": "running", "tool": tool },
                "isError": false,
            });
            (id, result)
        };
        if let Err(error) = self.save() {
            self.state().jobs.retain(|job| job.id != id);
            return Err(format!(
                "could not record background job {id}, so it was not detached: {error}"
            ));
        }
        Ok((id, result))
    }

    /// Records how job `id` ended (its result text, or the cause it failed)
    /// and reports it to the conversation. The snapshot drops it.
    pub fn finish(&self, id: &str, outcome: Result<String, String>) {
        let text = {
            let mut state = self.state();
            let Some(job) = state.jobs.iter_mut().find(|job| job.id == id) else {
                return;
            };
            let elapsed = job.started.elapsed();
            let (ok, detail) = match outcome {
                Ok(result) => (true, result),
                Err(cause) => (false, cause),
            };
            let detail: String = detail.chars().take(REPORT_CHARS).collect();
            let text = job_report::report(
                &job.id,
                &job.title(),
                elapsed.as_secs(),
                if ok { Ok(&detail) } else { Err(&detail) },
            );
            job.outcome = Some((ok, detail, elapsed));
            let finished = state
                .jobs
                .iter()
                .filter(|job| job.outcome.is_some())
                .count();
            if finished > KEEP_FINISHED {
                if let Some(oldest) = state.jobs.iter().position(|job| job.outcome.is_some()) {
                    state.jobs.remove(oldest);
                }
            }
            text
        };
        if let Err(error) = self.save() {
            tracing::error!("odin-omp: job snapshot update failed job={id} error={error}");
        }
        let wake = format!("job:{}:{id}", self.boot);
        if let Err(error) = (self.report)(&wake, &text) {
            tracing::error!("odin-omp: job report failed job={id} error={error}");
        }
    }

    /// Every running job and the recently finished ones, newest last.
    pub fn list(&self) -> Value {
        let jobs: Vec<Value> = self
            .state()
            .jobs
            .iter()
            .map(|job| {
                let mut entry = json!({
                    "job": job.id,
                    "tool": job.tool,
                    "about": job.about,
                    "deadlineSeconds": job.deadline.as_secs(),
                });
                match &job.outcome {
                    None => {
                        entry["state"] = json!("running");
                        entry["elapsedSeconds"] = json!(job.started.elapsed().as_secs());
                        if let Some(line) = job.progress.get() {
                            entry["progress"] = json!(line);
                        }
                    }
                    Some((ok, detail, elapsed)) => {
                        entry["state"] = json!(if *ok { "done" } else { "failed" });
                        entry["elapsedSeconds"] = json!(elapsed.as_secs());
                        entry["outcome"] = json!(detail.chars().take(300).collect::<String>());
                    }
                }
                entry
            })
            .collect();
        json!({ "jobs": jobs })
    }

    /// Adds the runtime's own entries to [`Self::live_entries`].
    pub fn set_live_source(&self, source: LiveSource) {
        *self
            .live_source
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(source);
    }

    /// Live memory's view of the board: each job, open while it runs, then
    /// the runtime's own entries, which replace the board's line for a job
    /// they name.
    pub fn live_entries(&self, now_ms: u64) -> Vec<odin_brain::service::LiveEntry> {
        let more = self
            .live_source
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
            .map(|source| source(now_ms))
            .unwrap_or_default();
        let mut entries: Vec<_> = self
            .state()
            .jobs
            .iter()
            .map(|job| {
                let started = job.started.elapsed();
                let state = match &job.outcome {
                    None => format!("running for {}", minutes(started)),
                    Some((true, detail, _)) => format!("done: {}", excerpt(detail)),
                    Some((false, detail, _)) => format!("failed: {}", excerpt(detail)),
                };
                odin_brain::service::LiveEntry {
                    id: job.id.clone(),
                    line: format!("job {}: {state}", job.title()),
                    open: job.outcome.is_none(),
                    at_ms: now_ms.saturating_sub(started.as_millis() as u64),
                }
            })
            .collect();
        entries.retain(|entry| more.iter().all(|other| other.id != entry.id));
        entries.extend(more);
        entries
    }

    fn save(&self) -> Result<(), String> {
        let Some(path) = &self.store else {
            return Ok(());
        };
        let _saving = self
            .saving
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let jobs: Vec<SnapshotJob> = self
            .state()
            .jobs
            .iter()
            .filter(|job| job.outcome.is_none())
            .map(|job| SnapshotJob {
                id: job.id.clone(),
                tool: job.tool.clone(),
                about: job.about.clone(),
            })
            .collect();
        if jobs.is_empty() {
            return remove_snapshot(path);
        }
        // Keep the cutoff of a snapshot a restart has not yet reported.
        let cutoff = read_snapshot(path)?
            .map(|shot| shot.cutoff)
            .unwrap_or(self.boot);
        write_snapshot(path, &Snapshot { cutoff, jobs })
    }
}

fn remove_snapshot(path: &Path) -> Result<(), String> {
    match std::fs::remove_file(path) {
        Err(error) if error.kind() != std::io::ErrorKind::NotFound => {
            Err(format!("could not remove {}: {error}", path.display()))
        }
        _ => Ok(()),
    }
}

fn read_snapshot(path: &Path) -> Result<Option<Snapshot>, String> {
    match std::fs::read(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.to_string()),
        Ok(bytes) => serde_json::from_slice(&bytes)
            .map(Some)
            .map_err(|error| format!("could not read {}: {error}", path.display())),
    }
}

fn write_snapshot(path: &Path, snapshot: &Snapshot) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|error| format!("could not create {}: {error}", parent.display()))?;
    }
    let tmp = path.with_extension("json.tmp");
    std::fs::write(
        &tmp,
        serde_json::to_vec(snapshot).map_err(|error| error.to_string())?,
    )
    .map_err(|error| format!("could not write {}: {error}", tmp.display()))?;
    std::fs::rename(&tmp, path)
        .map_err(|error| format!("could not rename {} into place: {error}", tmp.display()))
}

/// One report for the snapshot, then the file goes. A failed report leaves it.
fn report_cutoff(path: &Path, report: &JobReport) -> Result<(), String> {
    let Some(snapshot) = read_snapshot(path)? else {
        return Ok(());
    };
    if snapshot.jobs.is_empty() {
        return remove_snapshot(path);
    }
    let listed = snapshot
        .jobs
        .iter()
        .map(|job| match job.about.is_empty() {
            true => format!("{} ({})", job.id, job.tool),
            false => format!("{} ({}: {})", job.id, job.tool, job.about),
        })
        .collect::<Vec<_>>()
        .join(", ");
    let count = snapshot.jobs.len();
    let noun = if count == 1 { "job" } else { "jobs" };
    report(
        &format!("job:cutoff:{}", snapshot.cutoff),
        &format!("{count} background {noun} ended when Odin stopped: {listed}"),
    )?;
    remove_snapshot(path)
}

fn minutes(elapsed: Duration) -> String {
    match elapsed.as_secs() / 60 {
        0 => "under a minute".to_owned(),
        1 => "1 min".to_owned(),
        minutes => format!("{minutes} min"),
    }
}

/// A job outcome as live memory quotes it.
fn excerpt(detail: &str) -> String {
    const CHARS: usize = 160;
    let flat = detail.split_whitespace().collect::<Vec<_>>().join(" ");
    match flat.char_indices().nth(CHARS) {
        Some((cut, _)) => format!("{}…", &flat[..cut]),
        None => flat,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    type Reports = Arc<Mutex<Vec<(String, String)>>>;

    fn board(max_background: u16, store: Option<PathBuf>) -> (JobBoard, Reports) {
        let reports = Arc::new(Mutex::new(Vec::new()));
        let sink = Arc::clone(&reports);
        let jobs = JobBoard::open(
            SeatId::new("sinmara").expect("seat"),
            Arc::new(move |id, text| {
                sink.lock()
                    .expect("reports")
                    .push((id.to_owned(), text.to_owned()));
                Ok(())
            }),
            Duration::from_secs(3),
            max_background,
            store,
        );
        (jobs, reports)
    }

    #[test]
    fn a_job_reports_the_calls_run_time_from_its_real_start() {
        let (jobs, reports) = board(4, None);
        let (id, _) = jobs
            .start(
                jobs.try_reserve().expect("slot"),
                "knowledge_search",
                &json!({ "query": "CS295 class notes" }),
                Duration::from_secs(180),
                Instant::now()
                    .checked_sub(Duration::from_secs(3))
                    .unwrap_or_else(Instant::now),
                odin_domain::progress::Slot::default(),
            )
            .expect("detaches");
        jobs.finish(&id, Ok("3 results".to_owned()));
        let listed = jobs.list();
        assert_eq!(listed["jobs"][0]["state"], "done");
        assert_eq!(listed["jobs"][0]["elapsedSeconds"], 3);
        assert_eq!(reports.lock().expect("reports").len(), 1);
    }

    #[test]
    fn calls_detaching_at_once_each_record_their_job() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (jobs, _) = board(64, Some(dir.path().join("jobs.json")));
        let jobs = Arc::new(jobs);
        let barrier = Arc::new(std::sync::Barrier::new(16));
        let starts: Vec<_> = (0..16)
            .map(|_| {
                let (jobs, barrier) = (Arc::clone(&jobs), Arc::clone(&barrier));
                std::thread::spawn(move || {
                    let reservation = jobs.try_reserve().expect("slot");
                    barrier.wait();
                    jobs.start(
                        reservation,
                        "knowledge_search",
                        &json!({ "query": "notes" }),
                        Duration::from_secs(180),
                        Instant::now(),
                        odin_domain::progress::Slot::default(),
                    )
                })
            })
            .collect();
        for start in starts {
            start.join().expect("thread").expect("each job is recorded");
        }
        assert_eq!(jobs.list()["jobs"].as_array().expect("jobs").len(), 16);
        let saved = read_snapshot(&dir.path().join("jobs.json"))
            .expect("snapshot reads")
            .expect("snapshot written");
        assert_eq!(
            saved.jobs.len(),
            16,
            "every detached job is in the snapshot"
        );
    }

    #[test]
    fn a_full_board_declines_detachment_until_a_running_job_finishes() {
        let (jobs, _) = board(4, None);
        for _ in 0..4 {
            let reservation = jobs.try_reserve().expect("under the cap");
            jobs.start(
                reservation,
                "discord_file_send",
                &json!({}),
                Duration::from_secs(60),
                Instant::now(),
                odin_domain::progress::Slot::default(),
            )
            .expect("reserved slot detaches");
        }
        let reason = jobs.try_reserve().expect_err("the fifth call stays inline");
        assert!(
            reason.contains("limits.max_background_jobs") && reason.contains("4 jobs"),
            "{reason}"
        );
        assert_eq!(jobs.list()["jobs"].as_array().expect("jobs").len(), 4);
        jobs.finish("j1", Ok("sent".to_owned()));
        jobs.try_reserve().expect("a finished job frees its slot");
    }

    #[test]
    fn a_restart_reports_cut_off_jobs_once_and_does_not_replay_them() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("jobs.json");
        let reports: Reports = Arc::new(Mutex::new(Vec::new()));
        let sink = Arc::clone(&reports);
        let report: JobReport = Arc::new(move |id, text| {
            sink.lock()
                .expect("reports")
                .push((id.to_owned(), text.to_owned()));
            Ok(())
        });
        let jobs = JobBoard::open(
            SeatId::new("sinmara").expect("seat"),
            Arc::clone(&report),
            Duration::from_secs(3),
            4,
            Some(path.clone()),
        );
        let (id, _) = jobs
            .start(
                jobs.try_reserve().expect("slot"),
                "discord_file_send",
                &json!({ "file_name": "draft.pdf" }),
                Duration::from_secs(60),
                Instant::now(),
                odin_domain::progress::Slot::default(),
            )
            .expect("start");
        assert!(path.is_file(), "detached job is snapshotted");
        drop(jobs);

        let restarted = JobBoard::open(
            SeatId::new("sinmara").expect("seat"),
            Arc::clone(&report),
            Duration::from_secs(3),
            4,
            Some(path.clone()),
        );
        let seen = reports.lock().expect("reports").clone();
        assert_eq!(seen.len(), 1, "{seen:?}");
        assert!(seen[0].0.starts_with("job:cutoff:"), "{}", seen[0].0);
        assert!(
            seen[0]
                .1
                .contains("1 background job ended when Odin stopped")
                && seen[0].1.contains(&id)
                && seen[0].1.contains("discord_file_send"),
            "{}",
            seen[0].1
        );
        assert!(restarted.list()["jobs"]
            .as_array()
            .expect("jobs")
            .is_empty());
        assert!(!path.exists(), "snapshot cleared after the report");
        drop(restarted);
        let _ = JobBoard::open(
            SeatId::new("sinmara").expect("seat"),
            report,
            Duration::from_secs(3),
            4,
            Some(path),
        );
        assert_eq!(
            reports.lock().expect("reports").len(),
            1,
            "not reported again"
        );
    }
}
