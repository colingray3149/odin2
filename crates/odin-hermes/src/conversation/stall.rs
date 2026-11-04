//! The lane watchdog. A running turn whose journal stands still for the seat's declared
//! `stall_seconds` is not waited out: the turn is cancelled and the conversation moves to the
//! seat's next declared lane, where the caller that can sends the turn once more.

use std::collections::BTreeSet;
use std::time::Duration;

use odin_domain::huginn::{
    AbortScope, EventSeq, HistoryQuery, LiveCommand, LiveCommandBody, LiveEventBody,
    LiveSessionState, LiveSessionSummary, ModelName, ProviderName,
};
use odin_omp::host_tools::delegation::{next_switchable_lane, WorkerLane};
use tokio::time::Instant;

use super::history::page_limit;
use super::identity::bounded_command;
use super::ConversationRoot;
use crate::runtime::IntentFailure;

/// How long one wait has watched a session's journal stand still.
pub(super) struct Quiet {
    head: Option<EventSeq>,
    since: Instant,
}

impl Quiet {
    pub(super) fn new() -> Self {
        Self {
            head: None,
            since: Instant::now(),
        }
    }

    fn restart(&mut self, head: EventSeq) {
        self.head = Some(head);
        self.since = Instant::now();
    }
}

impl ConversationRoot {
    /// When a journal standing still from here reaches the declared stall time.
    pub(super) fn stall_due(&self, quiet: &Quiet) -> Option<Instant> {
        self.stall_bound.map(|bound| quiet.since + bound)
    }

    /// Moves a running turn off its lane once the journal has stood still for the declared
    /// stall time. A tool call still open is the tool's wait, not the lane's. The failure
    /// returned names the lane left and the one taken.
    pub(super) async fn stalled_lane(
        &self,
        quiet: &mut Quiet,
        summary: &LiveSessionSummary,
    ) -> Option<IntentFailure> {
        let bound = self.stall_bound?;
        if quiet.head != Some(summary.event_head) || summary.state != LiveSessionState::Running {
            quiet.restart(summary.event_head);
            return None;
        }
        let silence = quiet.since.elapsed();
        if silence < bound {
            return None;
        }
        // Events can land between the read that showed silence and now.
        let current = match self.find_session(summary.session_id, true).await {
            Ok(Some(current))
                if current.event_head == summary.event_head
                    && current.state == LiveSessionState::Running =>
            {
                current
            }
            _ => {
                quiet.restart(summary.event_head);
                return None;
            }
        };
        if self.tool_open(&current).await {
            quiet.restart(current.event_head);
            return None;
        }
        Some(self.leave_lane(&current, silence).await)
    }

    /// Whether a tool call is still running at the journal's head.
    async fn tool_open(&self, summary: &LiveSessionSummary) -> bool {
        let tail = EventSeq::new(
            summary
                .event_head
                .get()
                .saturating_sub(u64::from(page_limit().get())),
        );
        let Ok(page) = self
            .plane
            .history(HistoryQuery {
                session_id: summary.session_id,
                after: tail,
                limit: page_limit(),
            })
            .await
        else {
            // Unreadable: do not cancel a turn that may be mid-tool.
            return true;
        };
        let mut open = BTreeSet::new();
        for event in page.events {
            match event.body {
                // A settled or cancelled turn leaves nothing running.
                LiveEventBody::SessionStateChanged(change)
                    if change.current == LiveSessionState::Idle =>
                {
                    open.clear();
                }
                LiveEventBody::ToolStarted(started) => {
                    open.insert(started.tool.tool_use_id);
                }
                LiveEventBody::ToolFinished(finished) => {
                    open.remove(&finished.result.tool_use_id);
                }
                _ => {}
            }
        }
        !open.is_empty()
    }

    /// Cancels the quiet turn and puts the conversation on the seat's next declared lane.
    async fn leave_lane(&self, summary: &LiveSessionSummary, silence: Duration) -> IntentFailure {
        let from = summary.model.to_string();
        let seconds = silence.as_secs();
        let current = WorkerLane {
            provider: summary.provider.to_string(),
            model: from.clone(),
        };
        // A family entry (`local/*`) names no model to switch to.
        let lanes: Vec<_> = (self.binding.launch_options.iter())
            .filter(|option| !option.model.as_str().ends_with("/*"))
            .cloned()
            .collect();
        let next = next_switchable_lane(&lanes, &current);
        let moved = async {
            let abort = self.lane_control(
                summary,
                "abort",
                LiveCommandBody::Abort {
                    scope: AbortScope::CurrentTurn,
                },
            )?;
            self.apply_control(summary, abort).await?;
            if let Some(next) = &next {
                let set = self.lane_control(
                    summary,
                    "set-model",
                    LiveCommandBody::SetModel {
                        provider: ProviderName::new(next.provider.clone())
                            .map_err(|error| error.to_string())?,
                        model: ModelName::new(next.model.clone())
                            .map_err(|error| error.to_string())?,
                        route: None,
                    },
                )?;
                self.apply_control(summary, set).await?;
            }
            Ok::<(), String>(())
        }
        .await;
        match moved {
            Ok(()) => {
                tracing::warn!(
                    session = %summary.session_id,
                    "odin-hermes: lane stalled session={} lane={from} quiet_s={seconds} to={}",
                    summary.session_id,
                    next.as_ref().map_or("none", |lane| lane.model.as_str())
                );
                IntentFailure::LaneStalled {
                    from,
                    to: next.map(|lane| lane.model),
                    seconds,
                }
            }
            Err(error) => IntentFailure::Other(format!(
                "lane {from} went quiet for {seconds}s and the turn could not be cancelled \
                 or moved: {error}"
            )),
        }
    }

    fn lane_control(
        &self,
        summary: &LiveSessionSummary,
        step: &str,
        body: LiveCommandBody,
    ) -> Result<LiveCommand, String> {
        Ok(LiveCommand {
            command_id: bounded_command(
                "lane-stall",
                &[
                    &summary.session_id.to_string(),
                    &summary.event_head.get().to_string(),
                    step,
                ],
            )?,
            session_id: summary.session_id,
            expected_epoch: summary.epoch,
            expected_event_head: None,
            body,
        })
    }

    /// the owner's one line when a quiet lane's turn is sent again on the next; the key is the turn's.
    pub(super) fn tell_lane_move(&self, key: &str, from: &str, to: &str, seconds: u64) {
        let line = crate::natural::lane_moved_line(from, to, seconds);
        if let Err(error) = self.deliver_final(&format!("lane:{key}"), &line, None) {
            tracing::warn!(
                key = %key,
                error = %error,
                "odind: lane-move notice failed key={key} error={error}"
            );
        }
    }
}
