//! The conversation seat's background jobs: the board the bridge runs slow
//! calls on, whose reports wake the conversation, and `jobs_list`, which
//! shows Sinmara what is running and how her recent jobs ended.

use std::sync::{Arc, Weak};

use odin_domain::Scope;
use odin_omp::host_tools::jobs::JobBoard;
use odin_omp::host_tools::{HostTool, RpcHostToolDefinition, ToolLoadMode};
use odin_registry::schema::{
    ObjectConfig, RegistryKind, DEFAULT_INLINE_SECONDS, DEFAULT_MAX_BACKGROUND_JOBS,
};
use serde_json::{json, Value};

use super::HermesRuntime;

impl HermesRuntime {
    /// Running detached calls that a publication reload must preserve.
    pub fn running_jobs(&self) -> usize {
        self.jobs
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .as_ref()
            .map_or(0, |board| board.running())
    }

    /// What runs in the background, each with how long it has run: the
    /// calls on the job board, then the agent pods the daemon reports. A
    /// delegated worker is a live session, not a pod, so none is listed twice.
    pub(crate) fn background_jobs(&self) -> Vec<crate::conversation::BackgroundWork> {
        let board = self.jobs.lock().ok().and_then(|cell| cell.clone());
        let mut work: Vec<_> = board
            .iter()
            .flat_map(|board| board.list()["jobs"].as_array().cloned().unwrap_or_default())
            .filter(|job| job["state"] == "running")
            .map(|job| {
                let tool = job["tool"].as_str().unwrap_or_default();
                let what = match job["about"].as_str().filter(|about| !about.is_empty()) {
                    Some(about) => format!("{tool}: {about}"),
                    None => tool.to_owned(),
                };
                crate::conversation::BackgroundWork {
                    what,
                    seconds: job["elapsedSeconds"].as_u64().unwrap_or_default(),
                }
            })
            .collect();
        let now = u64::try_from(time::OffsetDateTime::now_utc().unix_timestamp_nanos() / 1_000_000)
            .unwrap_or(0);
        let pods = self
            .delegated
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        work.extend(pods.iter().map(|pod| crate::conversation::BackgroundWork {
            what: pod.title.clone(),
            seconds: now.saturating_sub(pod.started_ms) / 1000,
        }));
        work
    }

    /// The job board of the Discord conversation seat, made on first use;
    /// `None` without a Discord surface (no conversation to report to).
    pub fn job_board(self: &Arc<Self>) -> Option<Arc<JobBoard>> {
        let seat = self.settings.discord.as_ref()?.seat.clone();
        let mut cell = self.jobs.lock().ok()?;
        if let Some(board) = cell.as_ref() {
            return Some(Arc::clone(board));
        }
        let runtime: Weak<Self> = Arc::downgrade(self);
        let max_background = seat_max_background(self, &seat);
        let inline = std::time::Duration::from_secs(u64::from(seat_inline_seconds(self, &seat)));
        let store = self
            .settings
            .state_dir
            .join("background-jobs")
            .join(format!("{}.json", seat.as_str()));
        let board = Arc::new(JobBoard::open(
            seat,
            Arc::new(move |id: &str, text: &str| {
                let runtime = runtime
                    .upgrade()
                    .ok_or_else(|| "the Hermes runtime has stopped".to_owned())?;
                runtime.wake_once(id, text).map(drop)
            }),
            inline,
            max_background,
            Some(store),
        ));
        let entries: Weak<Self> = Arc::downgrade(self);
        board.set_live_source(Arc::new(move |now_ms| {
            entries
                .upgrade()
                .map(|runtime| runtime.follow_through_entries(now_ms))
                .unwrap_or_default()
        }));
        *cell = Some(Arc::clone(&board));
        Some(board)
    }
}

/// One of the seat's declared `limits` from the pinned registry, or `default` when the pin is
/// absent or this seat is not in it.
fn seat_limit(
    runtime: &HermesRuntime,
    seat: &odin_domain::SeatId,
    read: impl Fn(&odin_registry::schema::SeatLimitsToml) -> u16,
    default: u16,
) -> u16 {
    runtime
        .registry_pin()
        .and_then(|pin| {
            pin.current()
                .objects
                .iter()
                .find_map(|object| match &object.config {
                    ObjectConfig::Seat(config)
                        if object.kind() == RegistryKind::Seat && object.id == seat.as_str() =>
                    {
                        Some(read(&config.limits))
                    }
                    _ => None,
                })
        })
        .unwrap_or(default)
}

fn seat_max_background(runtime: &HermesRuntime, seat: &odin_domain::SeatId) -> u16 {
    seat_limit(
        runtime,
        seat,
        |limits| limits.max_background_jobs,
        DEFAULT_MAX_BACKGROUND_JOBS,
    )
}

pub(crate) fn seat_inline_seconds(runtime: &HermesRuntime, seat: &odin_domain::SeatId) -> u16 {
    seat_limit(
        runtime,
        seat,
        |limits| limits.inline_seconds,
        DEFAULT_INLINE_SECONDS,
    )
}

pub(super) fn jobs_tools(runtime: &Arc<HermesRuntime>, tools: &mut Vec<Arc<dyn HostTool>>) {
    let runtime = Arc::clone(runtime);
    tools.push(Arc::new(
        super::tools::CapabilityTool::plain_without_prerequisites(
            RpcHostToolDefinition {
                name: "jobs_list".into(),
                label: "List background jobs".into(),
                description: "Lists your background jobs: every call still running (with how \
                    long it has run and its deadline) and how recent ones ended. A call still \
                    running past your inline limit becomes a job on its own; its outcome comes \
                    back to you as a report. Use this when the owner asks how something is going."
                    .into(),
                parameters: odin_omp::capability_parameters!("jobs.list"),
                hidden: false,
                load_mode: ToolLoadMode::Discoverable,
            },
            Box::new(move |_scope: Scope, _arguments: Value| {
                let board = runtime
                    .jobs
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                Ok(board
                    .as_ref()
                    .map_or_else(|| json!({ "jobs": [] }), |board| board.list()))
            }),
        ),
    ));
}

#[cfg(test)]
mod tests {
    use super::super::follow_through::RunningJob;
    use super::*;

    #[test]
    fn a_running_agent_pod_is_background_work_with_its_age() {
        let state = tempfile::tempdir().expect("hermes state");
        let settings = crate::config::HermesSettings::new(
            state.path().join("state"),
            None,
            None,
            Vec::new(),
        )
        .expect("hermes settings");
        let ledgers = crate::runtime::HermesLedgers {
            conversation: odin_ledger::Ledger::open_in_memory().expect("conversation ledger"),
            adapter: Arc::new(parking_lot::Mutex::new(
                odin_ledger::Ledger::open_in_memory().expect("adapter ledger"),
            )),
            purchase: Arc::new(std::sync::Mutex::new(
                odin_ledger::Ledger::open_in_memory().expect("purchase ledger"),
            )),
        };
        let runtime = HermesRuntime::open(
            settings,
            ledgers,
            &std::collections::BTreeMap::new(),
            None,
            8_192,
            std::collections::BTreeMap::new(),
            None,
        )
        .expect("hermes runtime");
        assert!(runtime.background_jobs().is_empty());
        let started = u64::try_from(time::OffsetDateTime::now_utc().unix_timestamp() - 90)
            .expect("after 1970");
        runtime.set_running_jobs(vec![RunningJob {
            id: "run:pod:1".to_owned(),
            title: "heat-sim".to_owned(),
            started_ms: started * 1000,
        }]);
        let work = runtime.background_jobs();
        assert_eq!(work.len(), 1);
        assert_eq!(work[0].what, "heat-sim");
        assert!((90..=95).contains(&work[0].seconds), "{}", work[0].seconds);
    }
}
