use std::collections::BTreeMap;
use std::num::NonZeroU16;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use async_trait::async_trait;
use futures_core::Stream;
use odin_domain::huginn::{
    ArtifactReadRequest, ArtifactReadStream, ArtifactRef, CommandReceipt, DeviceId, EventSeq,
    HistoryPage, HistoryQuery, LiveCommand, LiveError, LiveEvent, LiveEventStream, LiveSessionId,
    LiveSessionSummary, OmpLivePlane, OpenSessionRequest, SeatRoster, SessionListPage,
    SessionListQuery, SubscribeRequest, TerminalControlLeaseId, TerminalControlRequest,
    TerminalControlStatus, TerminalInput, TerminalResize, TerminalTargetStatus, TransferChunk,
    TransferId, TransferStatus, UploadManifest,
};
use odin_domain::CommandId;

#[derive(Clone)]
pub struct SessionAdapters<P> {
    plane: Arc<P>,
    max_history_page: NonZeroU16,
    max_list_page: NonZeroU16,
}

impl<P> SessionAdapters<P> {
    pub fn new(plane: Arc<P>, max_history_page: NonZeroU16, max_list_page: NonZeroU16) -> Self {
        Self {
            plane,
            max_history_page,
            max_list_page,
        }
    }

    pub fn plane(&self) -> &Arc<P> {
        &self.plane
    }
}

#[async_trait]
impl<P: OmpLivePlane> OmpLivePlane for SessionAdapters<P> {
    async fn terminal_snapshot(
        &self,
        session: LiveSessionId,
    ) -> Result<odin_domain::huginn::TerminalSnapshot, LiveError> {
        self.plane.terminal_snapshot(session).await
    }

    async fn roster(&self) -> Result<SeatRoster, LiveError> {
        let mut roster = self.plane.roster().await?;
        roster.canonicalize();
        let mut seen = BTreeMap::new();
        for seat in &roster.seats {
            for session in &seat.active_sessions {
                if session.seat_id != seat.seat_id || seen.insert(session.session_id, ()).is_some()
                {
                    return Err(invalid_live(
                        "roster",
                        "roster contains a cross-seat or duplicate session",
                    ));
                }
            }
        }
        Ok(roster)
    }

    async fn sessions(&self, query: SessionListQuery) -> Result<SessionListPage, LiveError> {
        if query.limit > self.max_list_page {
            return Err(LiveError::ResourceLimit {
                limit: "session-list-page".to_owned(),
            });
        }
        let requested_seat = query.seat_id.clone();
        let page = self.plane.sessions(query).await?;
        if page.sessions.iter().any(|session| {
            requested_seat
                .as_ref()
                .is_some_and(|seat| &session.seat_id != seat)
        }) {
            return Err(invalid_live(
                "session-list",
                "session page contains a session from another seat",
            ));
        }
        Ok(SessionListPage::new(page.sessions, page.next_cursor))
    }

    async fn history(&self, query: HistoryQuery) -> Result<HistoryPage, LiveError> {
        if query.limit > self.max_history_page {
            return Err(LiveError::ResourceLimit {
                limit: "session-history-page".to_owned(),
            });
        }
        let requested_session = query.session_id;
        let requested_after = query.after;
        let page = self.plane.history(query).await?;
        if page.head < requested_after || page.next_after > page.head {
            return Err(invalid_live(
                "history",
                "history page has invalid cursor bounds",
            ));
        }
        let mut expected = requested_after.get();
        for event in &page.events {
            expected = expected
                .checked_add(1)
                .ok_or_else(|| invalid_live("history", "event sequence overflow"))?;
            if event.session_id != requested_session || event.sequence.get() != expected {
                return Err(invalid_live(
                    "history",
                    "history page contains a cross-session, duplicate, or missing event",
                ));
            }
        }
        let expected_next = page
            .events
            .last()
            .map(|event| event.sequence)
            .unwrap_or(requested_after);
        if page.next_after != expected_next {
            return Err(invalid_live(
                "history",
                "history next cursor is not the delivered tail",
            ));
        }
        Ok(page)
    }

    async fn subscribe(&self, request: SubscribeRequest) -> Result<LiveEventStream, LiveError> {
        let mut cursors = BTreeMap::new();
        for subscription in &request.subscriptions {
            if cursors
                .insert(subscription.session_id, subscription.event_after)
                .is_some()
            {
                return Err(invalid_live(
                    "subscribe",
                    "subscription contains a duplicate session",
                ));
            }
        }
        if cursors.is_empty() {
            return Err(invalid_live("subscribe", "subscription set is empty"));
        }
        let source = self.plane.subscribe(request).await?;
        Ok(Box::pin(SessionIsolationStream {
            source,
            cursors,
            failed: false,
        }))
    }

    async fn open_session(
        &self,
        request: OpenSessionRequest,
    ) -> Result<LiveSessionSummary, LiveError> {
        let expected_seat = request.seat_id.clone();
        let expected_provider = request.provider.clone();
        let expected_model = request.model.clone();
        let summary = self.plane.open_session(request).await?;
        if summary.seat_id != expected_seat
            || summary.provider != expected_provider
            || summary.model != expected_model
        {
            return Err(invalid_live(
                "open-session",
                "opened session does not match its immutable request",
            ));
        }
        Ok(summary)
    }

    async fn command(&self, command: LiveCommand) -> Result<CommandReceipt, LiveError> {
        self.plane.command(command).await
    }

    async fn begin_upload(&self, manifest: UploadManifest) -> Result<TransferStatus, LiveError> {
        self.plane.begin_upload(manifest).await
    }

    async fn upload_chunk(
        &self,
        transfer: TransferId,
        chunk: TransferChunk,
    ) -> Result<(), LiveError> {
        self.plane.upload_chunk(transfer, chunk).await
    }

    async fn commit_upload(&self, transfer: TransferId) -> Result<ArtifactRef, LiveError> {
        self.plane.commit_upload(transfer).await
    }

    async fn cancel_transfer(
        &self,
        command_id: CommandId,
        transfer: TransferId,
    ) -> Result<TransferStatus, LiveError> {
        self.plane.cancel_transfer(command_id, transfer).await
    }

    async fn grant_download_credit(
        &self,
        command_id: CommandId,
        transfer: TransferId,
        chunks: NonZeroU16,
    ) -> Result<(), LiveError> {
        self.plane
            .grant_download_credit(command_id, transfer, chunks)
            .await
    }

    async fn read_artifact(
        &self,
        request: ArtifactReadRequest,
    ) -> Result<(ArtifactRef, ArtifactReadStream), LiveError> {
        self.plane.read_artifact(request).await
    }

    async fn acquire_terminal_control(
        &self,
        command_id: CommandId,
        device: DeviceId,
        request: TerminalControlRequest,
    ) -> Result<TerminalControlStatus, LiveError> {
        self.plane
            .acquire_terminal_control(command_id, device, request)
            .await
    }

    async fn write_terminal(
        &self,
        command_id: CommandId,
        session: LiveSessionId,
        input: TerminalInput,
    ) -> Result<(), LiveError> {
        self.plane.write_terminal(command_id, session, input).await
    }

    async fn resize_terminal(
        &self,
        command_id: CommandId,
        session: LiveSessionId,
        resize: TerminalResize,
    ) -> Result<(), LiveError> {
        self.plane
            .resize_terminal(command_id, session, resize)
            .await
    }

    async fn release_terminal_control(
        &self,
        command_id: CommandId,
        session: LiveSessionId,
        lease: TerminalControlLeaseId,
    ) -> Result<TerminalControlStatus, LiveError> {
        self.plane
            .release_terminal_control(command_id, session, lease)
            .await
    }

    async fn bind_terminal_target(
        &self,
        zellij_session: String,
    ) -> Result<TerminalTargetStatus, LiveError> {
        self.plane.bind_terminal_target(zellij_session).await
    }

    async fn unbind_terminal_target(&self) -> Result<TerminalTargetStatus, LiveError> {
        self.plane.unbind_terminal_target().await
    }

    async fn terminal_target_status(&self) -> Result<TerminalTargetStatus, LiveError> {
        self.plane.terminal_target_status().await
    }
}

struct SessionIsolationStream {
    source: LiveEventStream,
    cursors: BTreeMap<odin_domain::huginn::LiveSessionId, EventSeq>,
    failed: bool,
}

impl Stream for SessionIsolationStream {
    type Item = Result<LiveEvent, LiveError>;

    fn poll_next(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        if self.failed {
            return Poll::Ready(None);
        }
        match self.source.as_mut().poll_next(context) {
            Poll::Ready(Some(Ok(event))) => {
                let Some(cursor) = self.cursors.get_mut(&event.session_id) else {
                    self.failed = true;
                    return Poll::Ready(Some(Err(invalid_live(
                        "cross-session-event",
                        "event source emitted an unsubscribed session",
                    ))));
                };
                let Some(expected) = cursor.get().checked_add(1) else {
                    self.failed = true;
                    return Poll::Ready(Some(Err(invalid_live(
                        "event-sequence",
                        "event sequence overflow",
                    ))));
                };
                if event.sequence.get() != expected {
                    self.failed = true;
                    return Poll::Ready(Some(Err(invalid_live(
                        "event-sequence",
                        "event source emitted a duplicate or gap",
                    ))));
                }
                *cursor = event.sequence;
                Poll::Ready(Some(Ok(event)))
            }
            Poll::Ready(Some(Err(error))) => Poll::Ready(Some(Err(error))),
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
        }
    }
}

fn invalid_live(code: &str, message: &str) -> LiveError {
    LiveError::InvalidRequest {
        code: code.to_owned(),
        message: message.to_owned(),
    }
}
