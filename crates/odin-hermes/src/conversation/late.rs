//! The late answer: a turn handed off past the answer bound is awaited here, without the
//! conversation lock, and its answer delivered when it settles.

use std::time::Duration as StdDuration;

use odin_domain::huginn::{EventSeq, LiveSessionId, LiveSessionState};

use crate::runtime::IntentFailure;

use super::decisions::{WakeProgress, LATE_ANSWER_BOUND};
use super::history::AnswerWait;
use super::stall::Quiet;
use super::stream::TurnStatus;
use super::{ConversationRoot, PendingWake};

impl ConversationRoot {
    /// Waits — WITHOUT the conversation lock, so the owner can keep talking —
    /// until the long turn stops running, then takes the lock to collect
    /// and deliver its answer through the durable reply path. Bounded by
    /// [`LATE_ANSWER_BOUND`]; a pending question is relayed by the normal
    /// answer wait and its decision path owns the continuation.
    pub(super) async fn run_late_answer(
        &self,
        requested: &PendingWake,
    ) -> Result<WakeProgress, String> {
        let session_id = LiveSessionId::parse(&requested.session_id)
            .map_err(|error| format!("wake session invalid: {error}"))?;
        let deadline = tokio::time::Instant::now() + LATE_ANSWER_BOUND;
        let mut quiet = Quiet::new();
        let mut stalled = None;
        let mut status = TurnStatus::new(self.egress.clone(), tokio::time::Instant::now());
        let mut seen = EventSeq::new(requested.decision_cursor);
        loop {
            let summary = self
                .find_session(session_id, true)
                .await
                .map_err(|error| error.to_string())?
                .ok_or_else(|| "the late-answer session vanished".to_owned())?;
            match summary.state {
                LiveSessionState::Running | LiveSessionState::Starting
                    if tokio::time::Instant::now() < deadline =>
                {
                    // A lane gone quiet is left now, not waited out for the full bound.
                    stalled = self.stalled_lane(&mut quiet, &summary).await;
                    if stalled.is_some() {
                        break;
                    }
                    self.wait_following(
                        &summary,
                        &mut seen,
                        &mut status,
                        self.poll_interval.max(StdDuration::from_secs(5)),
                    )
                    .await;
                }
                LiveSessionState::Running | LiveSessionState::Starting => {
                    return Err("the turn is still running past the late-answer bound".to_owned())
                }
                LiveSessionState::Ended | LiveSessionState::Failed => {
                    // the owner was told it is coming: say it is not.
                    let _guard = self.lock.lock().await;
                    let mut record = self.load_record()?;
                    let Some(mut wake) = record
                        .wakes
                        .iter()
                        .find(|wake| wake.command_id == requested.command_id)
                        .cloned()
                    else {
                        return Ok(WakeProgress::Complete);
                    };
                    tracing::warn!(
                        session = %session_id,
                        "odin-hermes: late answer lost session={session_id} state={:?}",
                        summary.state
                    );
                    return self.deliver_wake_reply(
                        &mut record,
                        &mut wake,
                        Some(super::prompt::LATE_ANSWER_LOST.to_owned()),
                    );
                }
                _ => break,
            }
        }
        status.finish();
        let _guard = self.lock.lock().await;
        let mut record = self.load_record()?;
        let Some(mut wake) = record
            .wakes
            .iter()
            .find(|wake| wake.command_id == requested.command_id)
            .cloned()
        else {
            return Ok(WakeProgress::Complete);
        };
        if wake.reply.is_some() {
            return self.deliver_wake_reply(&mut record, &mut wake, None);
        }
        let waited = match stalled {
            Some(stalled) => Err(stalled),
            None => {
                self.await_answer(session_id, EventSeq::new(wake.decision_cursor), None)
                    .await
            }
        };
        let waited = match waited {
            Err(stalled @ IntentFailure::LaneStalled { .. }) => {
                return self.deliver_stalled_lane(&mut wake, &stalled);
            }
            other => other.map_err(|error| error.to_string())?,
        };
        match waited {
            AnswerWait::Answer(answer) => {
                record = self.load_record()?;
                self.deliver_wake_reply(&mut record, &mut wake, Some(answer))
            }
            AnswerWait::NeedsOwner(asked) => {
                self.hold_reply(None, &asked)?;
                Ok(WakeProgress::Complete)
            }
            // Its last round thought and said nothing: the owner hears that
            // plainly instead of a progress line standing as the answer.
            AnswerWait::Silent => {
                record = self.load_record()?;
                self.deliver_wake_reply(
                    &mut record,
                    &mut wake,
                    Some(crate::natural::natural_intent_failure(
                        &IntentFailure::SilentTurn,
                    )),
                )
            }
            AnswerWait::VehicleDown => Err(IntentFailure::VehicleLost.to_string()),
        }
    }
}
