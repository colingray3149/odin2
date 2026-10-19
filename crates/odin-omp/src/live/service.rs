use std::num::NonZeroU16;
use std::sync::Arc;

use async_trait::async_trait;
use futures_util::stream;
use odin_domain::huginn::{
    ArtifactReadRequest, ArtifactReadStream, ArtifactRef, CommandReceipt, DeviceId, EventSeq,
    HistoryPage, HistoryQuery, LiveCommand, LiveError, LiveEventBody, LiveEventStream,
    LiveSessionId, LiveSessionState, LiveSessionSummary, OmpLivePlane, OpenSessionRequest,
    RosterRevision, SeatLiveState, SeatRoster, SeatRosterEntry, SessionListCursor, SessionListPage,
    SessionListQuery, SubscribeRequest, TerminalControlLeaseId, TerminalControlRequest,
    TerminalControlStatus, TerminalInput, TerminalResize, TerminalTargetSource as WireTargetSource,
    TerminalTargetStatus as WireTargetStatus, TransferChunk, TransferId, TransferStatus,
    UploadManifest,
};
use odin_domain::{ArtifactId, CommandId, SeatId};
use time::OffsetDateTime;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;

use crate::live::lane_artifacts::LaneArtifact;

use super::ledger::{live_error, LiveLedger};
use super::supervisor::{LiveSupervisor, PARK_IDLE_LIMIT};
use super::transfer::TransferManager;

pub struct OmpLiveService {
    ledger: Arc<dyn LiveLedger>,
    supervisor: Arc<LiveSupervisor>,
    transfers: Arc<TransferManager>,
}

impl OmpLiveService {
    /// Returns the exact admitted command, or `None` when safe to admit it.
    /// Existing entries are observed on replay, never re-executed.
    pub async fn command_entry(
        &self,
        command: &LiveCommand,
    ) -> Result<Option<super::ledger::CommandJournalEntry>, LiveError> {
        self.ledger.command(command).await.map_err(live_error)
    }

    /// Whether a durable session manifest exists for this id: initialize
    /// distinguishes an absent manifest (idempotent original open) from a
    /// present-but-parked session (recovery path).
    pub async fn session_manifest_present(
        &self,
        session_id: LiveSessionId,
    ) -> Result<bool, LiveError> {
        match self.ledger.session(session_id).await {
            Ok(_) => Ok(true),
            Err(super::ledger::LedgerError::SessionMissing(_)) => Ok(false),
            Err(error) => Err(live_error(error)),
        }
    }

    pub fn new(
        ledger: Arc<dyn LiveLedger>,
        supervisor: Arc<LiveSupervisor>,
        transfers: Arc<TransferManager>,
    ) -> Self {
        Self {
            ledger,
            supervisor,
            transfers,
        }
    }

    pub fn supervisor(&self) -> &Arc<LiveSupervisor> {
        &self.supervisor
    }

    pub async fn acquire_terminal_control(
        &self,
        operation_id: CommandId,
        device: DeviceId,
        request: TerminalControlRequest,
    ) -> Result<TerminalControlStatus, LiveError> {
        self.terminal(request.session_id)
            .await?
            .acquire_control(operation_id, device, request)
            .await
    }

    pub async fn write_terminal(
        &self,
        operation_id: CommandId,
        session: LiveSessionId,
        input: TerminalInput,
    ) -> Result<(), LiveError> {
        self.terminal(session)
            .await?
            .write_input(operation_id, input)
            .await
    }

    pub async fn resize_terminal(
        &self,
        operation_id: CommandId,
        session: LiveSessionId,
        resize: TerminalResize,
    ) -> Result<(), LiveError> {
        self.terminal(session)
            .await?
            .resize(operation_id, resize)
            .await
    }

    pub async fn release_terminal_control(
        &self,
        operation_id: CommandId,
        session: LiveSessionId,
        lease: TerminalControlLeaseId,
    ) -> Result<TerminalControlStatus, LiveError> {
        self.terminal(session)
            .await?
            .release_control(operation_id, lease)
            .await
    }

    pub async fn register_egress(&self, artifact: LaneArtifact) -> Result<ArtifactRef, LiveError> {
        let artifact = self.transfers.register_egress(artifact).await?;
        if !artifact_published(&*self.ledger, artifact.session_id, &artifact.artifact_id).await? {
            self.supervisor
                .actor(artifact.session_id)
                .await?
                .append(LiveEventBody::ArtifactPublished(artifact.clone()))
                .await?;
        }
        Ok(artifact)
    }
    async fn terminal(
        &self,
        session: LiveSessionId,
    ) -> Result<Arc<super::zellij::ZellijLiveAdapter>, LiveError> {
        self.supervisor
            .actor(session)
            .await?
            .terminal()
            .cloned()
            .ok_or_else(|| LiveError::Unsupported {
                operation: "terminal_unavailable_for_headless_session".to_owned(),
            })
    }
}

#[async_trait]
impl OmpLivePlane for OmpLiveService {
    async fn terminal_snapshot(
        &self,
        session: LiveSessionId,
    ) -> Result<odin_domain::huginn::TerminalSnapshot, LiveError> {
        let actor = self.supervisor.actor(session).await?;
        let summary = actor.summary()?;
        // Failed still has a process until the actor exits. Ended, and a
        // process already stopping, are gone.
        if actor.stopping() || summary.state == LiveSessionState::Ended {
            return Err(LiveError::Unavailable {
                code: "terminal_session_closed".to_owned(),
            });
        }
        let terminal = actor.terminal().ok_or_else(|| LiveError::Unsupported {
            operation: "terminal_unavailable_for_headless_session".to_owned(),
        })?;
        let snapshot = terminal.snapshot().await?;
        if actor.stopping() {
            return Err(LiveError::Unavailable {
                code: "terminal_session_closed".to_owned(),
            });
        }
        Ok(snapshot)
    }

    async fn roster(&self) -> Result<SeatRoster, LiveError> {
        let summaries = self.supervisor.summaries().await?;
        let now = OffsetDateTime::now_utc();
        let mut revision_bytes = Vec::new();
        let mut seats = Vec::new();
        for binding in self.supervisor.bindings().await {
            let active_sessions = current_sessions(&summaries, &binding.seat_id, now);
            revision_bytes.extend_from_slice(binding.seat_id.as_str().as_bytes());
            for session in &active_sessions {
                revision_bytes.extend_from_slice(&session.event_head.get().to_le_bytes());
                revision_bytes.extend_from_slice(&session.epoch.get().to_le_bytes());
            }
            let state = seat_state(&active_sessions);
            seats.push(SeatRosterEntry {
                seat_id: binding.seat_id,
                slice_id: binding.slice_id,
                display_name: binding.display_name,
                state,
                active_sessions,
                launch_options: binding.launch_options,
                diagnostic: None,
            });
        }
        let digest = blake3::hash(&revision_bytes);
        let mut revision = [0u8; 8];
        revision.copy_from_slice(&digest.as_bytes()[..8]);
        Ok(SeatRoster::new(
            RosterRevision::new(u64::from_le_bytes(revision)),
            now,
            seats,
        ))
    }

    async fn sessions(&self, query: SessionListQuery) -> Result<SessionListPage, LiveError> {
        // One bounded unified durable page from the supervisor: every
        // session has a durable row, the ledger scan is source-bounded to
        // limit+1 metadata rows, and the returned cursor is the last
        // scanned id whenever more rows exist — no skipped or duplicated
        // history.
        let after = match &query.cursor {
            Some(cursor) => Some(LiveSessionId::parse(cursor.as_str()).map_err(|_| {
                LiveError::InvalidRequest {
                    code: "invalid_session_list_cursor".to_owned(),
                    message: "session list cursor is not a session id".to_owned(),
                }
            })?),
            None => None,
        };
        let (mut sessions, next_after) = self
            .supervisor
            .session_summaries_page(
                query.seat_id.as_ref(),
                query.include_ended,
                after,
                usize::from(query.limit.get()),
            )
            .await?;
        sessions.sort_by_key(|summary| summary.session_id);
        // Preserve scan progress even when filters leave the page empty.
        let next_cursor = next_after
            .map(|session_id| SessionListCursor::new(session_id.to_string()))
            .transpose()
            .map_err(|_| unavailable())?;
        Ok(SessionListPage::new(sessions, next_cursor))
    }

    async fn history(&self, query: HistoryQuery) -> Result<HistoryPage, LiveError> {
        self.ledger.history(query).await.map_err(live_error)
    }

    async fn subscribe(&self, request: SubscribeRequest) -> Result<LiveEventStream, LiveError> {
        if request.subscriptions.is_empty() {
            return Err(LiveError::InvalidRequest {
                code: "empty_subscription".to_owned(),
                message: "at least one session subscription is required".to_owned(),
            });
        }
        let mut streams = Vec::with_capacity(request.subscriptions.len());
        for subscription in request.subscriptions {
            match self.supervisor.actor(subscription.session_id).await {
                Ok(actor) => streams.push(actor.subscribe(subscription.event_after).await?),
                Err(LiveError::NotFound { .. }) => streams.push(
                    finite_replay(
                        Arc::clone(&self.ledger),
                        subscription.session_id,
                        subscription.event_after,
                    )
                    .await?,
                ),
                Err(error) => return Err(error),
            }
        }
        Ok(Box::pin(stream::select_all(streams)))
    }

    async fn open_session(
        &self,
        request: OpenSessionRequest,
    ) -> Result<odin_domain::huginn::LiveSessionSummary, LiveError> {
        self.supervisor.open(request).await
    }

    async fn open_session_owned(
        &self,
        request: OpenSessionRequest,
        cancellation: tokio::sync::watch::Receiver<bool>,
    ) -> (Result<LiveSessionSummary, LiveError>, bool) {
        self.supervisor.open_owned(request, cancellation).await
    }

    async fn command(&self, command: LiveCommand) -> Result<CommandReceipt, LiveError> {
        let actor = match self.supervisor.actor(command.session_id).await {
            Ok(actor) => actor,
            Err(LiveError::NotFound { .. }) => {
                // The supervisor owns parked-session admission and recovery
                // under one gate: exact replay first, then full validation,
                // journaling, capacity, and the single reclaim effect.
                return self.supervisor.recover_parked_command(command).await;
            }
            Err(error) => return Err(error),
        };
        actor.command(command).await
    }

    /// Shared recovery surface: rehydrates one durable session in place
    /// under the same session identity (fresh authority-verified child,
    /// durable transcript resumed). Works whether or not a previous actor
    /// existed; a truthfully Ended session refuses typed.
    async fn reclaim_session(
        &self,
        session_id: LiveSessionId,
    ) -> Result<LiveSessionSummary, LiveError> {
        self.supervisor.reclaim(session_id).await
    }

    async fn begin_upload(&self, manifest: UploadManifest) -> Result<TransferStatus, LiveError> {
        self.transfers.begin(manifest).await
    }

    async fn upload_chunk(
        &self,
        transfer: TransferId,
        chunk: TransferChunk,
    ) -> Result<(), LiveError> {
        self.transfers.write_chunk(transfer, chunk).await
    }

    async fn commit_upload(&self, transfer: TransferId) -> Result<ArtifactRef, LiveError> {
        let artifact = self.transfers.commit(transfer).await?;
        self.supervisor
            .actor(artifact.session_id)
            .await?
            .append(LiveEventBody::ArtifactPublished(artifact.clone()))
            .await?;
        Ok(artifact)
    }

    async fn cancel_transfer(
        &self,
        command_id: CommandId,
        transfer: TransferId,
    ) -> Result<TransferStatus, LiveError> {
        self.transfers.cancel(command_id, transfer).await
    }

    async fn grant_download_credit(
        &self,
        command_id: CommandId,
        transfer: TransferId,
        chunks: NonZeroU16,
    ) -> Result<(), LiveError> {
        self.transfers
            .grant_download_credit(command_id, transfer, chunks)
            .await
    }

    async fn read_artifact(
        &self,
        request: ArtifactReadRequest,
    ) -> Result<(ArtifactRef, ArtifactReadStream), LiveError> {
        self.transfers.read(request).await
    }

    async fn acquire_terminal_control(
        &self,
        command_id: CommandId,
        device: DeviceId,
        request: TerminalControlRequest,
    ) -> Result<TerminalControlStatus, LiveError> {
        OmpLiveService::acquire_terminal_control(self, command_id, device, request).await
    }

    async fn write_terminal(
        &self,
        command_id: CommandId,
        session: LiveSessionId,
        input: TerminalInput,
    ) -> Result<(), LiveError> {
        OmpLiveService::write_terminal(self, command_id, session, input).await
    }

    async fn resize_terminal(
        &self,
        command_id: CommandId,
        session: LiveSessionId,
        resize: TerminalResize,
    ) -> Result<(), LiveError> {
        OmpLiveService::resize_terminal(self, command_id, session, resize).await
    }

    async fn release_terminal_control(
        &self,
        command_id: CommandId,
        session: LiveSessionId,
        lease: TerminalControlLeaseId,
    ) -> Result<TerminalControlStatus, LiveError> {
        OmpLiveService::release_terminal_control(self, command_id, session, lease).await
    }

    async fn bind_terminal_target(
        &self,
        zellij_session: String,
    ) -> Result<WireTargetStatus, LiveError> {
        self.supervisor
            .bind_terminal_target(zellij_session)
            .await
            .map(wire_terminal_target_status)
    }

    async fn unbind_terminal_target(&self) -> Result<WireTargetStatus, LiveError> {
        self.supervisor
            .clear_terminal_target()
            .await
            .map(wire_terminal_target_status)
    }

    async fn terminal_target_status(&self) -> Result<WireTargetStatus, LiveError> {
        self.supervisor
            .terminal_target_status()
            .await
            .map(wire_terminal_target_status)
    }
}

/// `seat`'s current sessions, the only ones its roster entry and health
/// reflect: every tracked session except a failed or processless one that is
/// superseded (the seat started a later session) or idle past
/// [`PARK_IDLE_LIMIT`]. Those stay durable history (`sessions`).
fn current_sessions(
    summaries: &[LiveSessionSummary],
    seat: &SeatId,
    now: OffsetDateTime,
) -> Vec<LiveSessionSummary> {
    let seat_sessions: Vec<_> = summaries
        .iter()
        .filter(|summary| summary.seat_id == *seat)
        .collect();
    seat_sessions
        .iter()
        .filter(|summary| {
            !matches!(
                summary.state,
                LiveSessionState::Failed | LiveSessionState::Detached
            ) || (now - summary.updated_at <= PARK_IDLE_LIMIT
                && seat_sessions
                    .iter()
                    .all(|other| other.started_at <= summary.started_at))
        })
        .map(|summary| (*summary).clone())
        .collect()
}

/// A seat's health: the highest-priority state of its current sessions.
fn seat_state(sessions: &[LiveSessionSummary]) -> SeatLiveState {
    SeatLiveState::highest_priority(sessions.iter().map(|summary| match summary.state {
        LiveSessionState::RequiresAction => SeatLiveState::RequiresAction,
        LiveSessionState::Starting | LiveSessionState::Running | LiveSessionState::Aborting => {
            SeatLiveState::Running
        }
        LiveSessionState::Idle | LiveSessionState::Detached => SeatLiveState::Idle,
        LiveSessionState::Failed => SeatLiveState::Degraded,
        LiveSessionState::Ended => SeatLiveState::Offline,
    }))
}

/// Converts the supervisor's terminal target status into the shared wire
/// type. The conversion is total and lossless: the wire struct mirrors the
/// supervisor struct field for field.
fn wire_terminal_target_status(status: super::target::TerminalTargetStatus) -> WireTargetStatus {
    WireTargetStatus {
        bound: status.bound,
        zellij_session: status.zellij_session,
        source: status.source.map(|source| match source {
            super::target::TerminalTargetSource::Declared => WireTargetSource::Declared,
            super::target::TerminalTargetSource::ChatRegistration => {
                WireTargetSource::ChatRegistration
            }
        }),
        registered_at: status.registered_at,
        replaced: status.replaced,
    }
}

async fn artifact_published(
    ledger: &dyn LiveLedger,
    session: LiveSessionId,
    artifact: &ArtifactId,
) -> Result<bool, LiveError> {
    let limit = NonZeroU16::new(1024).ok_or_else(unavailable)?;
    let mut after = EventSeq::new(0);
    loop {
        let page = ledger
            .history(HistoryQuery {
                session_id: session,
                after,
                limit,
            })
            .await
            .map_err(live_error)?;
        if page.events.iter().any(|event| {
            matches!(
                &event.body,
                LiveEventBody::ArtifactPublished(published)
                    if &published.artifact_id == artifact
            )
        }) {
            return Ok(true);
        }
        if page.events.is_empty() || page.next_after >= page.head {
            return Ok(false);
        }
        after = page.next_after;
    }
}

async fn finite_replay(
    ledger: Arc<dyn LiveLedger>,
    session: LiveSessionId,
    after: EventSeq,
) -> Result<LiveEventStream, LiveError> {
    let limit = NonZeroU16::new(1024).ok_or_else(unavailable)?;
    let (sender, receiver) = mpsc::channel(64);
    tokio::spawn(async move {
        let mut cursor = after;
        loop {
            let page = match ledger
                .history(HistoryQuery {
                    session_id: session,
                    after: cursor,
                    limit,
                })
                .await
            {
                Ok(page) => page,
                Err(error) => {
                    let _ = sender.send(Err(live_error(error))).await;
                    return;
                }
            };
            if page.events.is_empty() {
                return;
            }
            cursor = page.next_after;
            for event in page.events {
                if sender.send(Ok(event)).await.is_err() {
                    return;
                }
            }
            if cursor >= page.head {
                return;
            }
        }
    });
    Ok(Box::pin(ReceiverStream::new(receiver)))
}

fn unavailable() -> LiveError {
    LiveError::Unavailable {
        code: "omp_live_service".to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use odin_domain::huginn::{ModelName, ProviderName, SessionEpoch, TerminalSeq};

    #[test]
    fn superseded_and_old_failures_never_keep_a_seat_degraded() {
        let now = OffsetDateTime::now_utc();
        let session = |n: u128, seat: &str, state, started_hours_ago: i64| LiveSessionSummary {
            session_id: LiveSessionId::new(uuid::Uuid::from_u128(n)).expect("session"),
            epoch: SessionEpoch::new(1),
            seat_id: SeatId::new(seat).expect("seat"),
            provider: ProviderName::new("gateway").expect("provider"),
            model: ModelName::new("glm-flash").expect("model"),
            title: None,
            state,
            started_at: now - time::Duration::hours(started_hours_ago),
            updated_at: now - time::Duration::hours(started_hours_ago),
            failed_at: Some(now - time::Duration::hours(started_hours_ago)),
            event_head: EventSeq::new(1),
            terminal_head: TerminalSeq::new(0),
            pending_permission_count: 0,
        };
        let summaries = [
            // Kubert: one failure four days old.
            session(1, "kubert", LiveSessionState::Failed, 96),
            // Architect: a failure the seat moved past with a new session.
            session(2, "architect", LiveSessionState::Failed, 3),
            session(3, "architect", LiveSessionState::Running, 1),
            // Gungnir: two recent failures; only the latest is current.
            session(4, "gungnir", LiveSessionState::Failed, 3),
            session(5, "gungnir", LiveSessionState::Failed, 1),
        ];
        let health = |seat: &str| {
            let current = current_sessions(&summaries, &SeatId::new(seat).unwrap(), now);
            let ids: Vec<u128> = current
                .iter()
                .map(|summary| summary.session_id.as_uuid().as_u128())
                .collect();
            (ids, seat_state(&current))
        };
        assert_eq!(health("kubert"), (vec![], SeatLiveState::Offline));
        assert_eq!(health("architect"), (vec![3], SeatLiveState::Running));
        assert_eq!(health("gungnir"), (vec![5], SeatLiveState::Degraded));
    }

    #[test]
    fn a_processless_session_ages_out_of_its_seat() {
        let now = OffsetDateTime::now_utc();
        let session = |n: u128, hours_ago: i64| LiveSessionSummary {
            session_id: LiveSessionId::new(uuid::Uuid::from_u128(n)).expect("session"),
            epoch: SessionEpoch::new(1),
            seat_id: SeatId::new("architect").expect("seat"),
            provider: ProviderName::new("gateway").expect("provider"),
            model: ModelName::new("glm-flash").expect("model"),
            title: None,
            state: LiveSessionState::Detached,
            started_at: now - time::Duration::hours(hours_ago),
            updated_at: now - time::Duration::hours(hours_ago),
            failed_at: None,
            event_head: EventSeq::new(1),
            terminal_head: TerminalSeq::new(0),
            pending_permission_count: 0,
        };
        let seat = SeatId::new("architect").expect("seat");
        assert!(current_sessions(&[session(1, 30)], &seat, now).is_empty());
        assert_eq!(current_sessions(&[session(2, 2)], &seat, now).len(), 1);
    }
}
