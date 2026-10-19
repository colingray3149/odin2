//! Bounded general/live dispatch: per-request admission (stop guard and
//! follower posture), exact request routing, and subscription replacement
//! semantics over the connection-local stream slots.

use odin_domain::huginn::{
    ArtifactReadRequest, ContentTicket, ContentTicketRequest, DeviceId, EventSeq, HistoryQuery,
    HuginnMessage, HuginnProtocolError, HuginnReadModel, HuginnRequest, HuginnResponse,
    HuginnStreamSource, LiveClientRequest, LiveProtocolError, LiveResponse, LiveServerMessage,
    LiveSessionId, OmpLivePlane, OpenSessionRequest, RequestId, SessionListQuery, SubscribeRequest,
};
use std::num::NonZeroU16;

use uuid::Uuid;

/// Frame bytes reserved for the response envelope around a `Deltas` page.
pub(super) const DELTA_FRAME_HEADROOM: usize = 16 * 1024;

use super::command::AuthenticatedCommandPort;
use super::live::{protocol_to_live, ConnectionStreams, LiveDispatcher, ObjectWatch, Standing};

/// The snapshot answer that handed out `revision` is still on its way out:
/// the same retryable refusal an in-flight object batch gets.
fn resume_point_in_flight(revision: odin_domain::huginn::Revision) -> HuginnProtocolError {
    HuginnProtocolError::Conflict {
        code: "objectAckPending".to_owned(),
        message: format!("the answer handing out revision {revision} is still in flight"),
    }
}

/// Exhaustive follower classification of the general protocol surface:
/// only health, status, and read-model observations are read-only. This is
/// a total match with no wildcard arm on purpose: a new `HuginnRequest`
/// variant fails to compile until it is classified, so the follower
/// posture can never silently admit an unknown request kind.
fn huginn_request_is_read_only(request: &HuginnRequest) -> bool {
    match request {
        HuginnRequest::Snapshot(_)
        | HuginnRequest::Deltas(_)
        | HuginnRequest::Search(_)
        | HuginnRequest::Subscribe(_)
        | HuginnRequest::SubscribeObjects(_)
        | HuginnRequest::ConversationStatus
        | HuginnRequest::ConversationThread(_)
        | HuginnRequest::ConversationReply(_) => true,
        HuginnRequest::OpenSession(_)
        | HuginnRequest::SessionCommand(_)
        | HuginnRequest::LaneCommand(_)
        | HuginnRequest::KubeCommand(_)
        | HuginnRequest::ApprovalDecision(_)
        | HuginnRequest::ListFiles(_)
        | HuginnRequest::ReadFile(_)
        | HuginnRequest::WatchFiles(_)
        | HuginnRequest::BeginTransfer(_)
        | HuginnRequest::TransferChunk(_)
        | HuginnRequest::CommitTransfer(_)
        | HuginnRequest::CancelTransfer(_)
        | HuginnRequest::GrantDownloadCredit(_)
        | HuginnRequest::RequestRender(_)
        | HuginnRequest::RenderStatus(_)
        | HuginnRequest::WatchRender(_)
        | HuginnRequest::IssueContentTicket(_)
        | HuginnRequest::BrowserCommand(_)
        | HuginnRequest::BrowserObserve(_)
        | HuginnRequest::SimulationCommand(_)
        // A ring gesture fires the authority's routines.
        | HuginnRequest::RingGesture(_)
        | HuginnRequest::AcquireTerminalControl(_)
        | HuginnRequest::WriteTerminal(_)
        | HuginnRequest::ResizeTerminal(_)
        | HuginnRequest::ReleaseTerminalControl(_)
        | HuginnRequest::ConversationSay(_)
        | HuginnRequest::EmergencyStop(_)
        // The spend lives in the authority's gateway; a follower has none.
        | HuginnRequest::Spend(_) => false,
    }
}

/// Exhaustive classification keeps new request kinds from bypassing device authentication.
fn huginn_request_needs_device(request: &HuginnRequest) -> bool {
    match request {
        HuginnRequest::BrowserCommand(_)
        | HuginnRequest::BrowserObserve(_)
        | HuginnRequest::ApprovalDecision(_)
        | HuginnRequest::ConversationStatus
        | HuginnRequest::ConversationThread(_)
        | HuginnRequest::ConversationSay(_)
        | HuginnRequest::ConversationReply(_)
        | HuginnRequest::Spend(_)
        | HuginnRequest::LaneCommand(_)
        | HuginnRequest::KubeCommand(_)
        | HuginnRequest::SimulationCommand(_)
        | HuginnRequest::RingGesture(_)
        | HuginnRequest::EmergencyStop(_)
        // Session tokens must be associated with the calling device.
        | HuginnRequest::OpenSession(_) => true,
        HuginnRequest::Snapshot(_)
        | HuginnRequest::Deltas(_)
        | HuginnRequest::Search(_)
        | HuginnRequest::Subscribe(_)
        | HuginnRequest::SubscribeObjects(_)
        | HuginnRequest::SessionCommand(_)
        | HuginnRequest::ListFiles(_)
        | HuginnRequest::ReadFile(_)
        | HuginnRequest::WatchFiles(_)
        | HuginnRequest::BeginTransfer(_)
        | HuginnRequest::TransferChunk(_)
        | HuginnRequest::CommitTransfer(_)
        | HuginnRequest::CancelTransfer(_)
        | HuginnRequest::GrantDownloadCredit(_)
        | HuginnRequest::RequestRender(_)
        | HuginnRequest::RenderStatus(_)
        | HuginnRequest::WatchRender(_)
        | HuginnRequest::IssueContentTicket(_)
        | HuginnRequest::AcquireTerminalControl(_)
        | HuginnRequest::WriteTerminal(_)
        | HuginnRequest::ResizeTerminal(_)
        | HuginnRequest::ReleaseTerminalControl(_) => false,
    }
}

/// Live-plane counterpart of [`huginn_request_is_read_only`]: roster,
/// session list, history, event subscriptions, and the connection-local
/// unsubscribe. Every session, command, transfer, ticket, and terminal
/// operation mutates and is refused on a follower.
fn live_request_is_read_only(request: &LiveClientRequest) -> bool {
    match request {
        LiveClientRequest::GetRoster { .. }
        | LiveClientRequest::ListSessions { .. }
        | LiveClientRequest::GetHistory { .. }
        | LiveClientRequest::GetTerminalTarget { .. }
        | LiveClientRequest::Subscribe { .. }
        | LiveClientRequest::Unsubscribe { .. } => true,
        LiveClientRequest::OpenSession { .. }
        | LiveClientRequest::Control { .. }
        | LiveClientRequest::BeginUpload { .. }
        | LiveClientRequest::UploadChunk { .. }
        | LiveClientRequest::CommitUpload { .. }
        | LiveClientRequest::CancelTransfer { .. }
        | LiveClientRequest::FetchArtifact { .. }
        | LiveClientRequest::GrantDownloadCredit { .. }
        | LiveClientRequest::BrowseFiles { .. }
        | LiveClientRequest::ReadFile { .. }
        | LiveClientRequest::WatchFiles { .. }
        | LiveClientRequest::RequestRender { .. }
        | LiveClientRequest::RenderStatus { .. }
        | LiveClientRequest::WatchRender { .. }
        | LiveClientRequest::IssueContentTicket { .. }
        | LiveClientRequest::AcquireTerminalControl { .. }
        | LiveClientRequest::WriteTerminal { .. }
        | LiveClientRequest::ResizeTerminal { .. }
        | LiveClientRequest::BindTerminalTarget { .. }
        | LiveClientRequest::UnbindTerminalTarget { .. }
        | LiveClientRequest::ReleaseTerminalControl { .. } => false,
    }
}

impl<R, C, S> LiveDispatcher<R, C, S>
where
    R: HuginnReadModel + 'static,
    C: AuthenticatedCommandPort + OmpLivePlane + 'static,
    S: HuginnStreamSource + 'static,
{
    pub(super) async fn dispatch_general(
        &self,
        request: HuginnRequest,
        device: DeviceId,
        streams: &mut ConnectionStreams,
    ) -> Option<HuginnMessage> {
        if let Err(error) = self.guard.check_stop().await {
            return Some(HuginnMessage::ProtocolError(error));
        }
        if !self.posture.admits(huginn_request_is_read_only(&request)) {
            return Some(HuginnMessage::ProtocolError(
                HuginnProtocolError::Unauthorized,
            ));
        }
        let result = match request {
            HuginnRequest::Snapshot(mut query) => {
                // "Unchanged" is an answer only against a baseline this
                // connection holds; any other revision — perhaps an
                // earlier daemon's, equal to this head — gets the state.
                // Each served page may extend this connection's chain.
                if !streams.resume.honours_if_revision(&query) {
                    query.if_revision = None;
                }
                match self.read_model.snapshot(query.clone()).await {
                    Ok(page) => {
                        streams.resume.stage_snapshot(&query, &page);
                        Ok(HuginnResponse::Snapshot(page))
                    }
                    Err(error) => Err(error),
                }
            }
            HuginnRequest::Search(query) => self
                .read_model
                .search(query)
                .await
                .map(HuginnResponse::Search),
            // The page budget is the connection's own frame bound less the
            // response envelope, so a large window pages instead of
            // overflowing the frame and dropping the connection.
            // The cursor names its model, which refuses another's typed, so
            // raw sync resumes on any connection to the same model.
            HuginnRequest::Deltas(query) => self
                .read_model
                .deltas(
                    query,
                    self.codec_limits
                        .max_frame_bytes
                        .saturating_sub(DELTA_FRAME_HEADROOM),
                )
                .await
                .map(HuginnResponse::Deltas),
            HuginnRequest::Subscribe(subscriptions) => {
                if !subscriptions.is_valid()
                    || subscriptions.subscriptions.len() > self.max_subscriptions
                {
                    Err(HuginnProtocolError::ResourceLimit {
                        limit: "subscriptionsPerConnection".to_owned(),
                    })
                } else {
                    match self.streams.subscribe(subscriptions).await {
                        Ok(subscription) => {
                            streams.general = Some(subscription);
                            Ok(HuginnResponse::Subscribed)
                        }
                        Err(error) => Err(error),
                    }
                }
            }
            HuginnRequest::SubscribeObjects(subscription) => match streams
                .resume
                .subscription(&subscription, streams.objects.as_ref())
            {
                // A point this connection was never handed — perhaps an
                // earlier daemon's, equal to this head — resumes nothing:
                // the client takes a fresh snapshot. The previous
                // subscription stays untouched, as for any cursor failure.
                Standing::Unknown => Err(HuginnProtocolError::CursorExpired),
                Standing::InFlight => Err(resume_point_in_flight(subscription.after)),
                Standing::Handed => match self
                    .read_model
                    .object_deltas_page(
                        subscription.after,
                        &subscription.kinds,
                        &subscription.scope,
                        1,
                        self.object_page_budget(),
                    )
                    .await
                {
                    // The requested point must still be served: a typed
                    // cursor failure answers the request and leaves the
                    // previous subscription — its outstanding page
                    // included — untouched.
                    Err(error) => Err(error),
                    Ok(_) => {
                        // While a batch is still in flight nothing is freed
                        // and nothing is replaced: the previous subscription
                        // keeps its page, and whichever SubscribeObjects this
                        // is (the ack at its checkpoint, or a re-baseline) is
                        // retried once the batch is on the wire. A consumer
                        // that discarded a stale batch resyncs instead of
                        // stalling behind a page it will never acknowledge.
                        let pending = streams
                            .objects
                            .as_ref()
                            .and_then(|state| state.unacked_checkpoint());
                        match pending {
                            Some(checkpoint) => Err(HuginnProtocolError::Conflict {
                                code: "objectAckPending".to_owned(),
                                message: format!(
                                    "the previous object batch (checkpoint {checkpoint}) \
                                     is still in flight"
                                ),
                            }),
                            None => {
                                // Any delivered page is superseded by this
                                // ack or re-baseline.
                                if let Some(state) = streams.objects.as_mut() {
                                    state.clear_unacked();
                                }
                                streams.objects = Some(ObjectWatch::new(&subscription));
                                Ok(HuginnResponse::Subscribed)
                            }
                        }
                    }
                },
            },
            HuginnRequest::ListFiles(request) => match &self.files {
                Some(files) => files.list(request).await.map(HuginnResponse::Files),
                None => Err(HuginnProtocolError::Unavailable {
                    code: "fileGateway".to_owned(),
                }),
            },
            HuginnRequest::ReadFile(request) => match &self.files {
                Some(files) => match files.read(request).await {
                    Ok(chunks) => {
                        streams.file = Some(chunks);
                        Ok(HuginnResponse::Ack)
                    }
                    Err(error) => Err(error),
                },
                None => Err(HuginnProtocolError::Unavailable {
                    code: "fileGateway".to_owned(),
                }),
            },
            HuginnRequest::WatchFiles(request) => match &self.files {
                Some(files) => match files.watch(request).await {
                    Ok(deltas) => {
                        streams.file_watch = Some(deltas);
                        Ok(HuginnResponse::Subscribed)
                    }
                    Err(error) => Err(error),
                },
                None => Err(HuginnProtocolError::Unavailable {
                    code: "fileGateway".to_owned(),
                }),
            },
            HuginnRequest::BeginTransfer(manifest) => self
                .commands
                .begin_upload(odin_domain::huginn::UploadManifest {
                    manifest,
                    source_device: device,
                })
                .await
                .map(HuginnResponse::Transfer)
                .map_err(crate::state::live_error_into_protocol),
            HuginnRequest::TransferChunk(request) => self
                .commands
                .upload_chunk(request.transfer_id, request.chunk)
                .await
                .map(|()| HuginnResponse::Ack)
                .map_err(crate::state::live_error_into_protocol),
            HuginnRequest::CommitTransfer(transfer) => self
                .commands
                .commit_upload(transfer)
                .await
                .map(HuginnResponse::Artifact)
                .map_err(crate::state::live_error_into_protocol),
            HuginnRequest::CancelTransfer(request) => self
                .commands
                .cancel_transfer(request.command_id, request.transfer_id)
                .await
                .map(HuginnResponse::Transfer)
                .map_err(crate::state::live_error_into_protocol),
            HuginnRequest::GrantDownloadCredit(request) => self
                .commands
                .grant_download_credit(request.command_id, request.transfer_id, request.chunks)
                .await
                .map(|()| HuginnResponse::Ack)
                .map_err(crate::state::live_error_into_protocol),
            HuginnRequest::RequestRender(request) => match &self.renders {
                Some(renders) => renders
                    .request_render(request)
                    .await
                    .map(HuginnResponse::Render),
                None => Err(HuginnProtocolError::Unavailable {
                    code: "renderGateway".to_owned(),
                }),
            },
            HuginnRequest::RenderStatus(request) => match &self.renders {
                Some(renders) => renders
                    .render_status(request.render_id)
                    .await
                    .map(HuginnResponse::Render),
                None => Err(HuginnProtocolError::Unavailable {
                    code: "renderGateway".to_owned(),
                }),
            },
            HuginnRequest::WatchRender(request) => match &self.renders {
                Some(renders) => match renders.watch_render(request.render_id).await {
                    Ok(statuses) => {
                        streams.render = Some(statuses);
                        Ok(HuginnResponse::Subscribed)
                    }
                    Err(error) => Err(error),
                },
                None => Err(HuginnProtocolError::Unavailable {
                    code: "renderGateway".to_owned(),
                }),
            },
            HuginnRequest::AcquireTerminalControl(request) => self
                .commands
                .acquire_terminal_control(request.command_id, device, request.request)
                .await
                .map(HuginnResponse::TerminalControl)
                .map_err(crate::state::live_error_into_protocol),
            HuginnRequest::WriteTerminal(request) => self
                .commands
                .write_terminal(request.command_id, request.session_id, request.input)
                .await
                .map(|()| HuginnResponse::Ack)
                .map_err(crate::state::live_error_into_protocol),
            HuginnRequest::ResizeTerminal(request) => self
                .commands
                .resize_terminal(request.command_id, request.session_id, request.resize)
                .await
                .map(|()| HuginnResponse::Ack)
                .map_err(crate::state::live_error_into_protocol),
            HuginnRequest::ReleaseTerminalControl(request) => self
                .commands
                .release_terminal_control(request.command_id, request.session_id, request.lease_id)
                .await
                .map(HuginnResponse::TerminalControl)
                .map_err(crate::state::live_error_into_protocol),
            HuginnRequest::IssueContentTicket(request) => self
                .issue_content_ticket(device, request)
                .await
                .map(HuginnResponse::ContentTicket),
            request if huginn_request_needs_device(&request) => {
                self.commands.execute_authenticated(device, request).await
            }
            request => self.commands.execute(request).await,
        };
        Some(match result {
            Ok(result) => HuginnMessage::Response {
                request_id: request_id(),
                result,
            },
            Err(error) => HuginnMessage::ProtocolError(error),
        })
    }

    /// Each subscribed session's replay boundary `(session, requested_after,
    /// head)`. Read after the event stream opened, so the stream is bound to
    /// deliver every event up to each head (replay, then tail).
    async fn replay_heads(
        &self,
        cursors: Vec<(LiveSessionId, EventSeq)>,
    ) -> Result<Vec<(LiveSessionId, EventSeq, EventSeq)>, LiveProtocolError> {
        let mut heads = Vec::with_capacity(cursors.len());
        for (session_id, after) in cursors {
            let page = self
                .commands
                .history(HistoryQuery {
                    session_id,
                    after,
                    limit: NonZeroU16::MIN,
                })
                .await?;
            heads.push((session_id, after, page.head));
        }
        Ok(heads)
    }

    pub(super) async fn dispatch_live(
        &self,
        request: LiveClientRequest,
        device: DeviceId,
        streams: &mut ConnectionStreams,
    ) -> Option<LiveServerMessage> {
        if let Err(error) = self.guard.check_stop().await {
            return Some(LiveServerMessage::ProtocolError(protocol_to_live(error)));
        }
        if !self.posture.admits(live_request_is_read_only(&request)) {
            return Some(LiveServerMessage::ProtocolError(
                LiveProtocolError::Unauthorized,
            ));
        }
        let response = match request {
            LiveClientRequest::GetRoster {
                request_id,
                if_revision,
            } => self.commands.roster().await.map(|roster| {
                response(
                    request_id,
                    LiveResponse::Roster(if if_revision == Some(roster.revision) {
                        None
                    } else {
                        Some(roster)
                    }),
                )
            }),
            LiveClientRequest::ListSessions {
                request_id,
                seat_id,
                include_ended,
                cursor,
                limit,
            } => self
                .commands
                .sessions(SessionListQuery {
                    seat_id,
                    include_ended,
                    cursor,
                    limit,
                })
                .await
                .map(|sessions| response(request_id, LiveResponse::Sessions(sessions))),
            LiveClientRequest::GetHistory {
                request_id,
                session_id,
                after,
                limit,
            } => self
                .commands
                .history(HistoryQuery {
                    session_id,
                    after,
                    limit,
                })
                .await
                .map(|history| response(request_id, LiveResponse::History(history))),
            LiveClientRequest::Subscribe {
                request_id,
                subscriptions,
            } => {
                if subscriptions.is_empty() || subscriptions.len() > self.max_subscriptions {
                    Err(LiveProtocolError::ResourceLimit {
                        limit: "subscriptionsPerConnection".to_owned(),
                    })
                } else {
                    let cursors: Vec<_> = subscriptions
                        .iter()
                        .map(|subscription| (subscription.session_id, subscription.event_after))
                        .collect();
                    match self
                        .commands
                        .subscribe(SubscribeRequest { subscriptions })
                        .await
                    {
                        Ok(subscription) => match self.replay_heads(cursors).await {
                            Ok(heads) => {
                                streams.live = Some(subscription);
                                streams.live_replay.begin(heads);
                                Ok(response(request_id, LiveResponse::Subscribed))
                            }
                            Err(error) => Err(error),
                        },
                        Err(error) => Err(error),
                    }
                }
            }
            LiveClientRequest::Unsubscribe {
                request_id,
                session_ids,
            } => {
                if session_ids.is_empty() {
                    Err(LiveProtocolError::InvalidRequest {
                        code: "emptyUnsubscribe".to_owned(),
                        message: "at least one session id is required".to_owned(),
                    })
                } else {
                    streams.live = None;
                    streams.live_replay.clear();
                    Ok(response(request_id, LiveResponse::Ack))
                }
            }
            LiveClientRequest::OpenSession {
                request_id,
                command_id,
                seat_id,
                project_id,
                slice_id,
                provider,
                model,
                title,
                target_node,
                open_tab,
                initial_prompt,
                served_revision,
            } => self
                .commands
                .execute_authenticated(
                    device,
                    HuginnRequest::OpenSession(OpenSessionRequest {
                        command_id,
                        seat_id,
                        project_id,
                        slice_id,
                        provider,
                        model,
                        title,
                        target_node,
                        open_tab,
                        initial_prompt,
                        // Command transports never carry a workload binding:
                        // only the kube launch port opens workload sessions.
                        workload: None,
                        served_revision,
                    }),
                )
                .await
                .map_err(protocol_to_live)
                .and_then(|answered| match answered {
                    HuginnResponse::SessionOpened(session) => {
                        Ok(response(request_id, LiveResponse::SessionOpened(session)))
                    }
                    _ => Err(LiveProtocolError::InvalidRequest {
                        code: "openSessionResponse".to_owned(),
                        message: "the authenticated open did not answer a session".to_owned(),
                    }),
                }),
            LiveClientRequest::Control {
                request_id,
                command,
            } => self
                .commands
                .command(command)
                .await
                .map(|receipt| response(request_id, LiveResponse::Command(receipt))),
            LiveClientRequest::BeginUpload {
                request_id,
                manifest,
            } => self
                .commands
                .begin_upload(manifest)
                .await
                .map(|status| response(request_id, LiveResponse::Transfer(status))),
            LiveClientRequest::UploadChunk { request } => {
                match self
                    .commands
                    .upload_chunk(request.transfer_id, request.chunk)
                    .await
                {
                    Ok(()) => return None,
                    Err(error) => Err(error),
                }
            }
            LiveClientRequest::CommitUpload {
                request_id,
                transfer_id,
            } => self
                .commands
                .commit_upload(transfer_id)
                .await
                .map(|artifact| response(request_id, LiveResponse::Artifact(artifact))),
            LiveClientRequest::CancelTransfer {
                request_id,
                request,
            } => self
                .commands
                .cancel_transfer(request.command_id, request.transfer_id)
                .await
                .map(|status| response(request_id, LiveResponse::Transfer(status))),
            LiveClientRequest::FetchArtifact {
                request_id,
                artifact_id,
                first_chunk,
            } => match self
                .commands
                .read_artifact(ArtifactReadRequest {
                    artifact_id,
                    first_chunk,
                    initial_credit: self.initial_download_credit,
                })
                .await
            {
                Ok((artifact, chunks)) => {
                    streams.artifact = Some(chunks);
                    Ok(response(request_id, LiveResponse::Artifact(artifact)))
                }
                Err(error) => Err(error),
            },
            LiveClientRequest::GrantDownloadCredit { request } => {
                match self
                    .commands
                    .grant_download_credit(request.command_id, request.transfer_id, request.chunks)
                    .await
                {
                    Ok(()) => return None,
                    Err(error) => Err(error),
                }
            }
            LiveClientRequest::BrowseFiles { request_id, query } => match &self.files {
                Some(files) => files
                    .list(query)
                    .await
                    .map(|files| response(request_id, LiveResponse::Files(files)))
                    .map_err(protocol_to_live),
                None => Err(LiveProtocolError::Unavailable {
                    code: "fileGateway".to_owned(),
                }),
            },
            LiveClientRequest::ReadFile {
                request_id,
                request,
            } => match &self.files {
                Some(files) => match files.read(request).await {
                    Ok(chunks) => {
                        streams.file = Some(chunks);
                        Ok(response(request_id, LiveResponse::Ack))
                    }
                    Err(error) => Err(protocol_to_live(error)),
                },
                None => Err(LiveProtocolError::Unavailable {
                    code: "fileGateway".to_owned(),
                }),
            },
            LiveClientRequest::WatchFiles {
                request_id,
                request,
            } => match &self.files {
                Some(files) => match files.watch(request).await {
                    Ok(deltas) => {
                        streams.file_watch = Some(deltas);
                        Ok(response(request_id, LiveResponse::Subscribed))
                    }
                    Err(error) => Err(protocol_to_live(error)),
                },
                None => Err(LiveProtocolError::Unavailable {
                    code: "fileGateway".to_owned(),
                }),
            },
            LiveClientRequest::RequestRender {
                request_id,
                request,
            } => match &self.renders {
                Some(renders) => renders
                    .request_render(request)
                    .await
                    .map(|status| response(request_id, LiveResponse::Render(status)))
                    .map_err(protocol_to_live),
                None => Err(LiveProtocolError::Unavailable {
                    code: "renderGateway".to_owned(),
                }),
            },
            LiveClientRequest::RenderStatus {
                request_id,
                request,
            } => match &self.renders {
                Some(renders) => renders
                    .render_status(request.render_id)
                    .await
                    .map(|status| response(request_id, LiveResponse::Render(status)))
                    .map_err(protocol_to_live),
                None => Err(LiveProtocolError::Unavailable {
                    code: "renderGateway".to_owned(),
                }),
            },
            LiveClientRequest::WatchRender {
                request_id,
                request,
            } => match &self.renders {
                Some(renders) => match renders.watch_render(request.render_id).await {
                    Ok(statuses) => {
                        streams.render = Some(statuses);
                        Ok(response(request_id, LiveResponse::Subscribed))
                    }
                    Err(error) => Err(protocol_to_live(error)),
                },
                None => Err(LiveProtocolError::Unavailable {
                    code: "renderGateway".to_owned(),
                }),
            },
            LiveClientRequest::IssueContentTicket {
                request_id,
                request,
            } => self
                .issue_content_ticket(device, request)
                .await
                .map(|ticket| response(request_id, LiveResponse::ContentTicket(ticket)))
                .map_err(protocol_to_live),
            LiveClientRequest::AcquireTerminalControl {
                request_id,
                request,
            } => self
                .commands
                .acquire_terminal_control(request.command_id, device, request.request)
                .await
                .map(|status| response(request_id, LiveResponse::TerminalControl(status))),
            LiveClientRequest::WriteTerminal {
                request_id,
                request,
            } => self
                .commands
                .write_terminal(request.command_id, request.session_id, request.input)
                .await
                .map(|()| response(request_id, LiveResponse::Ack)),
            LiveClientRequest::ResizeTerminal {
                request_id,
                request,
            } => self
                .commands
                .resize_terminal(request.command_id, request.session_id, request.resize)
                .await
                .map(|()| response(request_id, LiveResponse::Ack)),
            LiveClientRequest::ReleaseTerminalControl {
                request_id,
                request,
            } => self
                .commands
                .release_terminal_control(request.command_id, request.session_id, request.lease_id)
                .await
                .map(|status| response(request_id, LiveResponse::TerminalControl(status))),
            LiveClientRequest::BindTerminalTarget {
                request_id,
                zellij_session,
            } => self
                .commands
                .bind_terminal_target(zellij_session)
                .await
                .map(|status| response(request_id, LiveResponse::TerminalTarget(status))),
            LiveClientRequest::UnbindTerminalTarget { request_id } => self
                .commands
                .unbind_terminal_target()
                .await
                .map(|status| response(request_id, LiveResponse::TerminalTarget(status))),
            LiveClientRequest::GetTerminalTarget { request_id } => self
                .commands
                .terminal_target_status()
                .await
                .map(|status| response(request_id, LiveResponse::TerminalTarget(status))),
        };

        Some(match response {
            Ok(message) => message,
            Err(error) => LiveServerMessage::ProtocolError(error),
        })
    }

    async fn issue_content_ticket(
        &self,
        device: DeviceId,
        request: ContentTicketRequest,
    ) -> Result<ContentTicket, HuginnProtocolError> {
        let source = request.source.clone();
        let max_bytes = request.max_bytes.get();
        let ticket = self.tickets.issue(device, request).await?;
        if ticket.source != source
            || ticket.byte_len > max_bytes
            || ticket.expires_at <= time::OffsetDateTime::now_utc()
            || ticket.validate().is_err()
        {
            return Err(HuginnProtocolError::Conflict {
                code: "contentTicketBinding".to_owned(),
                message:
                    "issued content ticket violates its source, size, freshness, or token binding"
                        .to_owned(),
            });
        }
        Ok(ticket)
    }
}

fn request_id() -> RequestId {
    RequestId::new(Uuid::new_v4()).expect("random UUID is non-nil")
}

fn response(request_id: RequestId, result: LiveResponse) -> LiveServerMessage {
    LiveServerMessage::Response { request_id, result }
}

#[cfg(test)]
mod device_routing_tests {
    use super::*;
    use odin_domain::huginn::{LaneCommand, LaneCommandBody};
    use odin_domain::{CommandId, LaneId};

    #[test]
    fn lane_and_kube_commands_carry_the_device() {
        let lane = HuginnRequest::LaneCommand(LaneCommand {
            command_id: CommandId::new("lane-cmd").unwrap(),
            lane_id: LaneId::new("gungnir-odin").unwrap(),
            expected_revision: 1,
            body: LaneCommandBody::Pause,
        });
        assert!(huginn_request_needs_device(&lane));
        assert!(huginn_request_needs_device(
            &HuginnRequest::ConversationStatus
        ));
        // Emergency stop requires a device and cannot run on a follower.
        let stop = HuginnRequest::EmergencyStop(odin_domain::huginn::EmergencyStopRequest {
            command_id: CommandId::new("stop-cmd").unwrap(),
        });
        assert!(huginn_request_needs_device(&stop));
        assert!(!huginn_request_is_read_only(&stop));
    }

    /// Simulation pause, resume, and abort use the per-device approval path.
    #[test]
    fn simulation_commands_carry_the_device() {
        let command = odin_domain::huginn::SimulationCommand::Pause {
            context: odin_domain::huginn::SimulationCommandContext {
                command_id: CommandId::new("sim-cmd").unwrap(),
                run_id: odin_domain::RunId::new("run-1").unwrap(),
                expected_revision: 1,
                arguments_digest: odin_domain::Digest::hash(b"pause"),
                approval_id: None,
            },
        };
        assert!(huginn_request_needs_device(
            &HuginnRequest::SimulationCommand(command)
        ));
        let gesture = HuginnRequest::RingGesture(odin_domain::huginn::RingGestureReport {
            gesture_id: "g-1".to_owned(),
            gesture: "double-tap".to_owned(),
        });
        assert!(huginn_request_needs_device(&gesture));
        assert!(!huginn_request_is_read_only(&gesture));
    }

    #[test]
    fn open_session_needs_the_device() {
        let open = HuginnRequest::OpenSession(OpenSessionRequest {
            command_id: CommandId::new("open-cmd").unwrap(),
            seat_id: odin_domain::SeatId::new("gungnir").unwrap(),
            project_id: odin_domain::ProjectId::new("research").unwrap(),
            slice_id: odin_domain::SliceId::new("slice:research").unwrap(),
            provider: odin_domain::huginn::ProviderName::new("fixture").unwrap(),
            model: odin_domain::huginn::ModelName::new("fixture-model").unwrap(),
            title: None,
            target_node: odin_domain::NodeId::new("laptop").unwrap(),
            open_tab: false,
            initial_prompt: None,
            workload: None,
            served_revision: None,
        });
        assert!(huginn_request_needs_device(&open));
        assert!(!huginn_request_is_read_only(&open));
    }
}
