use odin_domain::huginn::{
    Freshness, FreshnessState, HuginnMessage, HuginnProtocolError, LiveSessionId,
    LiveSessionSummary, LiveStreamKind, ObjectKind, ObjectRef, OmpLivePlane, QueryScope, Revision,
    RevisionSource, Sequence, SessionEpoch, StreamFrame, StreamId, TerminalSeq, TerminalSnapshot,
};
use serde::Serialize;
use time::OffsetDateTime;

use super::SessionEventFeed;
use crate::read_model::{project_object, MaterializedReadModel, ProjectionMetadata};
use crate::streams::MultiplexedItem;

pub(super) fn stream_id(session: LiveSessionId, epoch: SessionEpoch) -> StreamId {
    let mut hash = blake3::Hasher::new();
    hash.update(b"odin.huginn.terminal.v1");
    hash.update(session.as_uuid().as_bytes());
    hash.update(&epoch.get().to_le_bytes());
    let mut bytes = [0; 16];
    bytes.copy_from_slice(&hash.finalize().as_bytes()[..16]);
    bytes[6] = (bytes[6] & 0x0f) | 0x80;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    StreamId::new(uuid::Uuid::from_bytes(bytes)).expect("non-nil terminal stream identity")
}
/// Rotation visits skipped after an unchanged capture, so an idle screen is captured half as often.
pub(super) const TERMINAL_SKIP_VISITS: u8 = 1;
/// How long one terminal capture may take before its session is reported failed.
const TERMINAL_CAPTURE_BOUND: std::time::Duration = std::time::Duration::from_secs(5);

/// A session whose process can be captured: never a Detached one, which
/// is how a session without a live process (parked after a restart) lists.
pub(super) fn eligible(session: &LiveSessionSummary) -> bool {
    use odin_domain::huginn::LiveSessionState;
    session.terminal_head.get() > 0
        && !matches!(
            session.state,
            LiveSessionState::Detached | LiveSessionState::Ended
        )
}
/// Capture pacing state for one eligible session.
pub(super) struct TerminalPace {
    /// The incarnation the paced sequence belongs to; a new epoch resets.
    epoch: SessionEpoch,
    /// The last captured screen sequence; 0 before the first capture.
    sequence: TerminalSeq,
    /// Visits left to skip because the last capture came back unchanged.
    skips_left: u8,
}

impl Default for TerminalPace {
    fn default() -> Self {
        Self {
            epoch: SessionEpoch::new(0),
            sequence: TerminalSeq::new(0),
            skips_left: 0,
        }
    }
}

fn invalid(message: impl ToString) -> HuginnProtocolError {
    HuginnProtocolError::InvalidRequest {
        code: "terminalFeedBinding".to_owned(),
        message: message.to_string(),
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct TerminalView<'a> {
    stream_id: StreamId,
    #[serde(flatten)]
    snapshot: &'a TerminalSnapshot,
}

impl SessionEventFeed {
    pub(super) async fn terminal(
        &mut self,
        plane: &dyn OmpLivePlane,
        read_model: &MaterializedReadModel,
        session: &LiveSessionSummary,
    ) -> Result<(), HuginnProtocolError> {
        if !eligible(session) {
            return Ok(());
        }
        if let Some(pace) = self.terminal_pace.get_mut(&session.session_id) {
            if pace.skips_left > 0 {
                pace.skips_left -= 1;
                return Ok(());
            }
        }
        let snapshot = tokio::time::timeout(
            TERMINAL_CAPTURE_BOUND,
            plane.terminal_snapshot(session.session_id),
        )
        .await
        .map_err(|error| invalid(format!("terminal capture timed out: {error}")))?
        .map_err(crate::state::live_error_into_protocol)?;
        let incarnation = (session.epoch, snapshot.sequence);
        let unchanged = self
            .terminal_pace
            .get(&session.session_id)
            .is_some_and(|pace| (pace.epoch, pace.sequence) == incarnation);
        let published = self.publish_terminal(read_model, session, snapshot).await;
        if published.is_ok() {
            let pace = self.terminal_pace.entry(session.session_id).or_default();
            if !unchanged {
                pace.epoch = incarnation.0;
                pace.sequence = incarnation.1;
            }
            pace.skips_left = if unchanged { TERMINAL_SKIP_VISITS } else { 0 };
        }
        published
    }

    /// Drops pacing for sessions that are no longer capture-eligible.
    pub(super) fn prune_terminal_pace(&mut self, sessions: &[LiveSessionSummary]) {
        self.terminal_pace.retain(|id, _| {
            sessions
                .iter()
                .any(|session| &session.session_id == id && eligible(session))
        });
    }

    pub(super) async fn publish_terminal(
        &self,
        read_model: &MaterializedReadModel,
        session: &LiveSessionSummary,
        snapshot: TerminalSnapshot,
    ) -> Result<(), HuginnProtocolError> {
        snapshot.validate().map_err(invalid)?;
        if !eligible(session)
            || snapshot.session_id != session.session_id
            || snapshot.epoch != session.epoch
            || snapshot.sequence < session.terminal_head
        {
            return Err(invalid(
                "snapshot does not match the live session incarnation",
            ));
        }
        let object = ObjectRef {
            kind: ObjectKind::Terminal,
            id: session.session_id.to_string(),
        };
        let stream_id = stream_id(snapshot.session_id, snapshot.epoch);
        let view = TerminalView {
            stream_id,
            snapshot: &snapshot,
        };
        let metadata = ProjectionMetadata::new(
            session
                .title
                .clone()
                .unwrap_or_else(|| session.session_id.to_string()),
            "Live terminal",
        )
        .in_scope(QueryScope::Session(session.session_id))
        .in_scope(QueryScope::Seat(session.seat_id.clone()))
        .with_evidence(ObjectRef {
            kind: ObjectKind::Session,
            id: session.session_id.to_string(),
        });
        let previous = read_model.get(&object)?;
        let published = previous.as_ref().map(|old| {
            let at = |pointer: &str| {
                old.value
                    .pointer(pointer)
                    .and_then(serde_json::Value::as_u64)
            };
            (at("/data/epoch"), at("/data/sequence"))
        });
        if let Some((old_epoch, old_sequence)) = published {
            if old_epoch.is_some_and(|epoch| epoch > snapshot.epoch.get())
                || (old_epoch == Some(snapshot.epoch.get())
                    && old_sequence.is_some_and(|sequence| sequence > snapshot.sequence.get()))
            {
                return Err(invalid(
                    "terminal snapshot regressed behind the published screen",
                ));
            }
        }
        let revision = Revision::new(previous.as_ref().map_or(Ok(1), |old| {
            old.revision
                .get()
                .checked_add(1)
                .ok_or_else(|| invalid("terminal revision exhausted"))
        })?);
        let projected = project_object(
            object,
            revision,
            RevisionSource::Omp,
            Freshness {
                state: FreshnessState::Fresh,
                observed_at: snapshot.recorded_at,
                source_updated_at: Some(snapshot.recorded_at),
                stale_after_seconds: None,
            },
            &view,
            &metadata,
        )?;
        if previous
            .as_ref()
            .is_some_and(|old| old.value == projected.value)
        {
            return Ok(());
        }
        if published == Some((Some(snapshot.epoch.get()), Some(snapshot.sequence.get()))) {
            return Err(invalid("terminal snapshot changed at the same sequence"));
        }
        let bytes = serde_json::to_vec(&snapshot).map_err(invalid)?;
        if bytes.len() as u64 > self.max_payload_bytes {
            return Err(HuginnProtocolError::ResourceLimit {
                limit: "maxStreamFrameBytes".to_owned(),
            });
        }
        let sequence = self
            .streams
            .durable_head(&stream_id)?
            .get()
            .checked_add(1)
            .ok_or_else(|| invalid("terminal stream sequence exhausted"))?;
        let content = self
            .artifacts
            .publish_feed_payload(
                session.session_id,
                &format!(
                    "terminal-{}-{}",
                    snapshot.epoch.get(),
                    snapshot.sequence.get()
                ),
                &bytes,
            )
            .await?;
        let frame = StreamFrame {
            stream_id,
            kind: LiveStreamKind::Terminal,
            sequence: Sequence::new(sequence),
            control_revision: snapshot.epoch.get(),
            produced_at: snapshot.recorded_at,
            key_frame: true,
            content,
        };
        self.streams.publish(
            MultiplexedItem::new(frame, HuginnMessage::TerminalReset(snapshot)),
            OffsetDateTime::now_utc(),
        )?;
        read_model.upsert_indexed(projected, metadata)?;
        Ok(())
    }
}
