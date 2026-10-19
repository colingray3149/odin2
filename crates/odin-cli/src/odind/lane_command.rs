//! Huginn `LaneCommand`: one control verb for a whole lane —
//! pause, resume, restart, checkpoint, abort or rehome every live session the
//! lane runs. A lane's live sessions are its `run:live:<session>` runs in the
//! ledger; each becomes one ordinary session command through the live plane,
//! retaining session epochs, journaling, and refusals.

use std::sync::{Arc, Mutex};

use odin_domain::huginn as live;
use odin_domain::huginn::{OmpLivePlane, SessionListQuery};
use odin_domain::{CommandId, LaneId, RunId};
use odin_ledger::lane_run::{live_runs_for_lane, read_lane};
use odin_ledger::Ledger;

/// The session commands one lane command becomes: one per live session of
/// the lane, in run order, each with its own command id derived from the
/// lane command's. Refused when the lane moved past the client's revision.
pub(super) fn plan(
    command: &live::LaneCommand,
    lane_revision: i64,
    lane_runs: &[RunId],
    live_sessions: &[live::LiveSessionSummary],
) -> Result<Vec<live::LiveCommand>, live::HuginnProtocolError> {
    let actual = u64::try_from(lane_revision).unwrap_or(0);
    if command.expected_revision != actual {
        return Err(live::HuginnProtocolError::RevisionMismatch {
            expected: live::Revision::new(command.expected_revision),
            actual: live::Revision::new(actual),
        });
    }
    let body = match &command.body {
        live::LaneCommandBody::Pause => live::LiveCommandBody::Pause,
        live::LaneCommandBody::Resume => live::LiveCommandBody::Resume,
        live::LaneCommandBody::Restart => live::LiveCommandBody::Restart,
        live::LaneCommandBody::Checkpoint => live::LiveCommandBody::Checkpoint,
        live::LaneCommandBody::Abort => live::LiveCommandBody::Abort {
            scope: live::AbortScope::Session,
        },
        live::LaneCommandBody::Rehome(node) => live::LiveCommandBody::Rehome {
            target_node: node.clone(),
        },
    };
    lane_runs
        .iter()
        .filter_map(|run| run.as_str().strip_prefix("run:live:"))
        .filter_map(|session| {
            live_sessions
                .iter()
                .find(|summary| summary.session_id.to_string() == session)
        })
        .map(|summary| {
            let command_id =
                CommandId::new(format!("{}:{}", command.command_id, summary.session_id)).map_err(
                    |error| live::HuginnProtocolError::InvalidRequest {
                        code: "laneCommandId".to_owned(),
                        message: error.to_string(),
                    },
                )?;
            Ok(live::LiveCommand {
                command_id,
                session_id: summary.session_id,
                expected_epoch: summary.epoch,
                expected_event_head: None,
                body: body.clone(),
            })
        })
        .collect()
}

/// Runs one lane command against the live plane: reads the lane and its
/// live runs under the ledger lock, lists the seat's live sessions, sends
/// each planned session command and logs every receipt. A lane with no live
/// session acknowledges with nothing sent.
pub(super) async fn execute(
    ledger: &Arc<Mutex<Ledger>>,
    plane: &Arc<dyn OmpLivePlane>,
    command: live::LaneCommand,
) -> Result<live::HuginnResponse, live::HuginnProtocolError> {
    let (lane, runs) = {
        let guard = ledger
            .lock()
            .map_err(|_| unavailable("laneLedgerUnavailable"))?;
        let lane = read_lane(guard.connection(), &command.lane_id)
            .map_err(|error| unavailable(&format!("laneLedgerUnavailable: {error}")))?
            .ok_or_else(|| not_found(&command.lane_id))?;
        let runs = live_runs_for_lane(guard.connection(), &command.lane_id)
            .map_err(|error| unavailable(&format!("laneLedgerUnavailable: {error}")))?;
        (lane, runs)
    };
    let sessions = plane
        .sessions(SessionListQuery {
            seat_id: Some(lane.seat_id.clone()),
            include_ended: false,
            cursor: None,
            limit: std::num::NonZeroU16::new(200).expect("non-zero"),
        })
        .await
        .map_err(odin_huginn::state::live_error_into_protocol)?
        .sessions;
    let planned = plan(&command, lane.revision, &runs, &sessions)?;
    let count = planned.len();
    let mut parked = 0usize;
    for session_command in planned {
        let session = session_command.session_id;
        match plane.command(session_command).await {
            Ok(receipt) => tracing::info!(
                "lane command lane={} session={session} receipt={receipt:?}",
                command.lane_id
            ),
            Err(error) if is_parked(&error) => {
                parked += 1;
                tracing::warn!(
                    "lane command lane={} session={session} skipped reason=parked",
                    command.lane_id
                );
            }
            Err(error) => {
                tracing::error!(
                    "lane command lane={} session={session} refused: {error}",
                    command.lane_id
                );
                return Err(odin_huginn::state::live_error_into_protocol(error));
            }
        }
    }
    tracing::warn!(
        "lane command lane={} body={:?} sessions={count} parked={parked}",
        command.lane_id,
        command.body
    );
    Ok(live::HuginnResponse::Ack)
}

/// Parked sessions have no process to pause or checkpoint, so lane commands skip them.
fn is_parked(error: &live::LiveError) -> bool {
    matches!(error, live::LiveError::Conflict { code, .. } if code == "session_parked")
}

fn unavailable(code: &str) -> live::HuginnProtocolError {
    live::HuginnProtocolError::Unavailable {
        code: code.to_owned(),
    }
}

fn not_found(lane: &LaneId) -> live::HuginnProtocolError {
    live::HuginnProtocolError::NotFound {
        object_kind: "lane".to_owned(),
        object_id: lane.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use odin_domain::NodeId;

    fn session(id: &str, epoch: u64) -> live::LiveSessionSummary {
        live::LiveSessionSummary {
            session_id: live::LiveSessionId::parse(id).expect("session"),
            epoch: live::SessionEpoch::new(epoch),
            seat_id: odin_domain::SeatId::new("gungnir").expect("seat"),
            provider: live::ProviderName::new("gateway").expect("provider"),
            model: live::ModelName::new("glm-flash").expect("model"),
            title: None,
            state: live::LiveSessionState::Running,
            started_at: time::OffsetDateTime::UNIX_EPOCH,
            updated_at: time::OffsetDateTime::UNIX_EPOCH,
            failed_at: None,
            event_head: live::EventSeq::new(1),
            terminal_head: live::TerminalSeq::new(0),
            pending_permission_count: 0,
        }
    }

    fn lane_command(revision: u64, body: live::LaneCommandBody) -> live::LaneCommand {
        live::LaneCommand {
            command_id: CommandId::new("lane-cmd-1").expect("id"),
            lane_id: LaneId::new("gungnir-surtr").expect("lane"),
            expected_revision: revision,
            body,
        }
    }

    #[test]
    fn a_parked_session_is_skipped_not_fatal() {
        assert!(is_parked(&live::LiveError::Conflict {
            code: "session_parked".to_owned(),
            message: "the session is parked after a daemon restart".to_owned(),
        }));
        assert!(!is_parked(&live::LiveError::Conflict {
            code: "session_ended".to_owned(),
            message: "ended".to_owned(),
        }));
        assert!(!is_parked(&live::LiveError::Unauthorized));
    }

    const A: &str = "11111111-1111-4111-8111-111111111111";
    const B: &str = "22222222-2222-4222-8222-222222222222";
    const ENDED: &str = "33333333-3333-4333-8333-333333333333";

    /// Every live session of the lane gets the verb, at its own epoch, under
    /// its own command id; runs of ended sessions and other lanes' sessions
    /// get nothing.
    #[test]
    fn a_lane_command_reaches_each_live_session_of_the_lane() {
        let runs: Vec<RunId> = [A, ENDED, B]
            .iter()
            .map(|id| RunId::new(format!("run:live:{id}")).expect("run"))
            .collect();
        let other = "44444444-4444-4444-8444-444444444444";
        let live = [session(B, 3), session(A, 1), session(other, 1)];
        let planned = plan(
            &lane_command(7, live::LaneCommandBody::Pause),
            7,
            &runs,
            &live,
        )
        .expect("planned");
        let targets: Vec<(String, u64)> = planned
            .iter()
            .map(|command| (command.session_id.to_string(), command.expected_epoch.get()))
            .collect();
        assert_eq!(targets, [(A.to_owned(), 1), (B.to_owned(), 3)]);
        assert!(planned
            .iter()
            .all(|command| command.body == live::LiveCommandBody::Pause));
        assert_eq!(planned[0].command_id.as_str(), format!("lane-cmd-1:{A}"));
    }

    #[test]
    fn a_stale_lane_revision_is_refused_before_anything_is_sent() {
        let refused =
            plan(&lane_command(6, live::LaneCommandBody::Abort), 7, &[], &[]).expect_err("stale");
        assert!(matches!(
            refused,
            live::HuginnProtocolError::RevisionMismatch { .. }
        ));
    }

    #[test]
    fn abort_ends_the_session_and_rehome_names_the_node() {
        let runs = [RunId::new(format!("run:live:{A}")).expect("run")];
        let live = [session(A, 2)];
        let abort = plan(
            &lane_command(1, live::LaneCommandBody::Abort),
            1,
            &runs,
            &live,
        )
        .expect("abort");
        assert_eq!(
            abort[0].body,
            live::LiveCommandBody::Abort {
                scope: live::AbortScope::Session
            }
        );
        let node = NodeId::new("pc").expect("node");
        let rehome = plan(
            &lane_command(1, live::LaneCommandBody::Rehome(node.clone())),
            1,
            &runs,
            &live,
        )
        .expect("rehome");
        assert_eq!(
            rehome[0].body,
            live::LiveCommandBody::Rehome { target_node: node }
        );
    }
}
