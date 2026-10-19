//! Reuse CLI composition and prompt acceptance so ACP does not introduce a separate session path.

use std::num::NonZeroU16;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use futures_util::future::BoxFuture;
use odin_cli::authority_provision::{self, SessionComposition, DEFAULT_TOKEN_TTL_SECONDS};
use odin_domain::huginn as live;
use odin_domain::{CommandId, NodeId};
use odin_huginn::client::{
    ClientError, ColinRemoteClient, EndpointTransport, FileCredentialStore, HuginnTransport,
    LiveConnection,
};
use odin_huginn::DeviceCredentialStore;
use odin_huginn::OdindConfig;
use tokio::sync::mpsc;

use crate::frontend::{
    FirstPromptGate, KernelApprovalView, OpenedSession, PendingSession, PreparedPrompt,
    SessionOpener,
};

#[derive(Debug, Clone)]
pub(crate) struct SessionFacts {
    pub live_session: live::LiveSessionId,
    pub seat: String,
    pub project: String,
    pub provider: live::ProviderName,
    pub model: live::ModelName,
    /// The composed project root; the ACP `cwd` must match it exactly.
    pub project_root: PathBuf,
}

impl SessionFacts {
    pub(crate) fn from_composition(composition: &SessionComposition) -> Self {
        Self {
            live_session: composition.live_session,
            seat: composition.seat.to_string(),
            project: composition.project.to_string(),
            provider: composition.provider.clone(),
            model: composition.model.clone(),
            project_root: composition.project_root.clone(),
        }
    }
}

/// Plain HTTP is allowed only on loopback; remote listeners require configured TLS.
pub(crate) fn endpoint_for(config: &OdindConfig) -> Result<url::Url, String> {
    let scheme = match (
        config.listener.tls_cert.is_some(),
        config.listener.tls_key.is_some(),
    ) {
        (true, true) => "https",
        (false, false) => "http",
        _ => return Err("the controller listener is only half configured for TLS".to_owned()),
    };
    url::Url::parse(&format!("{scheme}://{}", config.listener.address))
        .map_err(|error| format!("invalid controller listener endpoint: {error}"))
}

pub(crate) fn live_request_id() -> Result<live::RequestId, String> {
    let command = authority_provision::random_command_uuid()?;
    live::RequestId::parse(&command.to_string()).map_err(|error| error.to_string())
}

pub(crate) fn command_id() -> Result<CommandId, String> {
    authority_provision::random_command_uuid()
}

pub(crate) async fn send_session_command<T, K>(
    client: &ColinRemoteClient<T, K>,
    command: live::LiveCommand,
) -> Result<live::CommandReceipt, String>
where
    T: HuginnTransport,
    K: DeviceCredentialStore,
{
    match client
        .request(live::HuginnRequest::SessionCommand(command))
        .await
    {
        Ok(live::HuginnResponse::Command(receipt)) => Ok(receipt),
        Ok(other) => Err(format!(
            "the controller answered the command with {other:?}"
        )),
        Err(error) => Err(error.to_string()),
    }
}
pub(crate) async fn find_live_session<T, K>(
    client: &ColinRemoteClient<T, K>,
    session_id: live::LiveSessionId,
) -> Result<live::LiveSessionSummary, String>
where
    T: HuginnTransport,
    K: DeviceCredentialStore,
{
    // Loaded sessions must already exist, so one paginated lookup is sufficient.
    walk_session_list(client, session_id).await?.ok_or_else(|| {
        format!(
            "session {session_id} is not live on the controller; load requires an \
                 existing live session"
        )
    })
}

async fn walk_session_list<T, K>(
    client: &ColinRemoteClient<T, K>,
    session_id: live::LiveSessionId,
) -> Result<Option<live::LiveSessionSummary>, String>
where
    T: HuginnTransport,
    K: DeviceCredentialStore,
{
    let mut connection = client.connect().await.map_err(|error| error.to_string())?;
    let mut cursor: Option<live::SessionListCursor> = None;
    loop {
        let request_id = live_request_id()?;
        let response = tokio::time::timeout(
            Duration::from_secs(10),
            connection.request_live(live::LiveClientRequest::ListSessions {
                request_id,
                seat_id: None,
                include_ended: false,
                cursor,
                limit: NonZeroU16::new(128).expect("positive"),
            }),
        )
        .await
        .map_err(|_| "the session list request timed out".to_owned())?
        .map_err(|error| error.to_string())?;
        let live::LiveResponse::Sessions(page) = response else {
            return Err("unexpected session list response".to_owned());
        };
        if let Some(summary) = page
            .sessions
            .into_iter()
            .find(|summary| summary.session_id == session_id)
        {
            return Ok(Some(summary));
        }
        match page.next_cursor {
            Some(next) => cursor = Some(next),
            None => return Ok(None),
        }
    }
}

/// Preserve per-session wire order so replay and live events fold consistently.
#[derive(Debug)]
pub(crate) enum PlaneEvent {
    Subscribed {
        session: live::LiveSessionId,
    },
    SubscribeFailed {
        session: live::LiveSessionId,
        error: String,
    },
    /// Remaining sessions are re-announced because detaching replaces the whole stream.
    Unsubscribed,
    ReplayBegin {
        session: live::LiveSessionId,
    },
    Event(Box<live::LiveEvent>),
    ReplayComplete {
        session: live::LiveSessionId,
    },
    /// Retain subscription cursors so reconnect can resume delivery.
    Disconnected,
    /// Backoff has elapsed; the frontend may reorder this subscription.
    Unreachable {
        session: live::LiveSessionId,
    },
    /// Revocation and unrecoverable protocol errors require the frontend to stop.
    Failed(String),
}

/// Send replies on the event channel so waiting for an order cannot deadlock event delivery.
#[derive(Debug)]
pub(crate) enum PlaneOrder {
    Subscribe {
        session: live::LiveSessionId,
        after: live::EventSeq,
    },
    Unsubscribe {
        session: live::LiveSessionId,
    },
}

#[derive(Clone)]
pub(crate) struct PlaneHandle {
    orders: mpsc::Sender<PlaneOrder>,
}

impl PlaneHandle {
    pub(crate) fn orders(&self) -> mpsc::Sender<PlaneOrder> {
        self.orders.clone()
    }
}

pub(crate) fn spawn_plane<T, K>(
    client: Arc<ColinRemoteClient<T, K>>,
) -> (PlaneHandle, mpsc::Receiver<PlaneEvent>)
where
    T: HuginnTransport,
    K: DeviceCredentialStore,
{
    let (orders, order_receiver) = mpsc::channel::<PlaneOrder>(32);
    let (events, event_receiver) = mpsc::channel::<PlaneEvent>(1024);
    tokio::spawn(async move {
        plane_actor(client, order_receiver, events).await;
    });
    (PlaneHandle { orders }, event_receiver)
}

/// Subscription changes replace the whole stream, so every request needs all remaining cursors.
async fn plane_actor<T, K>(
    client: Arc<ColinRemoteClient<T, K>>,
    mut orders: mpsc::Receiver<PlaneOrder>,
    events: mpsc::Sender<PlaneEvent>,
) where
    T: HuginnTransport,
    K: DeviceCredentialStore,
{
    let mut subscriptions: Vec<live::SessionSubscription> = Vec::new();
    let mut connection: Option<Box<LiveConnection<T::Socket, T>>> = None;
    let mut reconnect = RECONNECT_FIRST;
    loop {
        // Connect only for an order so idle actors do not hold unused connections.
        if connection.is_none() {
            let Some(order) = orders.recv().await else {
                return;
            };
            match establish(&client, &events, order, &mut subscriptions, &mut reconnect).await {
                Some(conn) => connection = Some(Box::new(conn)),
                None => continue,
            }
        }
        let Some(conn) = connection.as_mut() else {
            unreachable!("connection was just established");
        };
        tokio::select! {
            biased;
            order = orders.recv() => {
                let Some(order) = order else { return };
                match order {
                    PlaneOrder::Subscribe { session, after } => {
                        let confirmed = subscriptions.clone();
                        upsert_subscription(&mut subscriptions, session, after);
                        let subscribe = live::LiveClientRequest::Subscribe {
                            request_id: match live_request_id() {
                                Ok(id) => id,
                                Err(error) => {
                                    let _ = events.send(PlaneEvent::Failed(error)).await;
                                    return;
                                }
                            },
                            subscriptions: subscriptions.clone(),
                        };
                        let outcome = tokio::time::timeout(
                            Duration::from_secs(10),
                            conn.request_live(subscribe),
                        )
                        .await;
                        match outcome {
                            Ok(Ok(live::LiveResponse::Subscribed)) => {
                                let _ = events
                                    .send(PlaneEvent::Subscribed { session })
                                    .await;
                            }
                            // Restore the confirmed set because the controller refused this replacement.
                            Ok(Ok(other)) => {
                                subscriptions = confirmed;
                                let _ = events
                                    .send(PlaneEvent::SubscribeFailed {
                                        session,
                                        error: format!("unexpected subscribe answer {other:?}"),
                                    })
                                    .await;
                            }
                            Ok(Err(error)) if is_fatal_stream_error(&error) => {
                                let _ = events.send(PlaneEvent::Failed(error.to_string())).await;
                                return;
                            }
                            // Keep desired subscriptions and cursors for reconnect.
                            Ok(Err(error)) if is_transport_error(&error) => {
                                connection = None;
                                let _ = events.send(PlaneEvent::Disconnected).await;
                            }
                            // A protocol refusal does not necessarily invalidate the connection.
                            Ok(Err(error)) => {
                                subscriptions = confirmed;
                                let _ = events
                                    .send(PlaneEvent::SubscribeFailed {
                                        session,
                                        error: error.to_string(),
                                    })
                                    .await;
                            }
                            // An unanswered replacement leaves stream state unknown; reconnect to resume.
                            Err(_) => {
                                connection = None;
                                let _ = events.send(PlaneEvent::Disconnected).await;
                            }
                        }
                    }
                    PlaneOrder::Unsubscribe { session } => {
                        subscriptions.retain(|sub| sub.session_id != session);
                        if subscriptions.is_empty() {
                            // No subscriptions remain, so detach and release the idle connection.
                            match detach(conn, vec![session]).await {
                                Detach::Acked => {
                                    connection = None;
                                    let _ = events.send(PlaneEvent::Unsubscribed).await;
                                }
                                Detach::Lost => {
                                    connection = None;
                                    let _ = events.send(PlaneEvent::Disconnected).await;
                                }
                                Detach::Fatal(error) => {
                                    let _ = events.send(PlaneEvent::Failed(error)).await;
                                    return;
                                }
                            }
                            continue;
                        }
                        // Unsubscribe drops the whole stream; resubscribe to preserve other sessions.
                        let remaining = subscriptions.clone();
                        let subscribe = live::LiveClientRequest::Subscribe {
                            request_id: match live_request_id() {
                                Ok(id) => id,
                                Err(error) => {
                                    let _ = events.send(PlaneEvent::Failed(error)).await;
                                    return;
                                }
                            },
                            subscriptions: remaining.clone(),
                        };
                        let outcome = tokio::time::timeout(
                            Duration::from_secs(10),
                            conn.request_live(subscribe),
                        )
                        .await;
                        match outcome {
                            Ok(Ok(live::LiveResponse::Subscribed)) => {
                                let _ = events.send(PlaneEvent::Unsubscribed).await;
                                for sub in remaining {
                                    let _ = events
                                        .send(PlaneEvent::Subscribed {
                                            session: sub.session_id,
                                        })
                                        .await;
                                }
                            }
                            Ok(Err(error)) if is_fatal_stream_error(&error) => {
                                let _ = events.send(PlaneEvent::Failed(error.to_string())).await;
                                return;
                            }
                            // Preserve the desired set when transport loss ends the stream.
                            Ok(Err(error)) if is_transport_error(&error) => {
                                connection = None;
                                let _ = events.send(PlaneEvent::Disconnected).await;
                            }
                            // A refused replacement leaves the existing stream intact; only detach failed.
                            Ok(Err(error)) => {
                                let _ = events
                                    .send(PlaneEvent::SubscribeFailed {
                                        session,
                                        error: error.to_string(),
                                    })
                                    .await;
                            }
                            Ok(Ok(other)) => {
                                let _ = events
                                    .send(PlaneEvent::SubscribeFailed {
                                        session,
                                        error: format!("unexpected subscribe answer {other:?}"),
                                    })
                                    .await;
                            }
                            // Drop the uncertain stream but retain the desired set for reconnect.
                            Err(_) => {
                                connection = None;
                                let _ = events.send(PlaneEvent::Disconnected).await;
                            }
                        }
                    }
                }
            }
            message = conn.next_live() => {
                match message {
                    Some(Ok(live::LiveServerMessage::Event(event))) => {
                        advance_cursor(&mut subscriptions, &event);
                        if events.send(PlaneEvent::Event(Box::new(event))).await.is_err() {
                            return;
                        }
                    }
                    Some(Ok(live::LiveServerMessage::ReplayBegin { session_id, .. })) => {
                        if events
                            .send(PlaneEvent::ReplayBegin { session: session_id })
                            .await
                            .is_err()
                        {
                            return;
                        }
                    }
                    Some(Ok(live::LiveServerMessage::ReplayComplete { session_id, .. })) => {
                        if events
                            .send(PlaneEvent::ReplayComplete { session: session_id })
                            .await
                            .is_err()
                        {
                            return;
                        }
                    }
                    Some(Ok(live::LiveServerMessage::DeviceRevoked)) => {
                        let _ = events
                            .send(PlaneEvent::Failed("the device credential was revoked".to_owned()))
                            .await;
                        return;
                    }
                    Some(Ok(live::LiveServerMessage::ProtocolError(error))) => {
                        let _ = events.send(PlaneEvent::Failed(error.to_string())).await;
                        return;
                    }
                    Some(Ok(_)) => {
                        // Ignore non-session frames rather than exposing them as session events.
                    }
                    // Transport loss does not stop durable sessions; retain cursors for reconnect.
                    Some(Err(error)) if is_transport_error(&error) => {
                        connection = None;
                        if events.send(PlaneEvent::Disconnected).await.is_err() {
                            return;
                        }
                    }
                    Some(Err(error)) => {
                        let _ = events.send(PlaneEvent::Failed(error.to_string())).await;
                        return;
                    }
                    None => {
                        connection = None;
                        if events.send(PlaneEvent::Disconnected).await.is_err() {
                            return;
                        }
                    }
                }
            }
        }
    }
}

/// Transport damage permits reconnect without changing session identity or cursors.
fn is_transport_error(error: &ClientError) -> bool {
    matches!(
        error,
        ClientError::ConnectionClosed | ClientError::Transport(_) | ClientError::Io(_)
    )
}

/// Revocation and protocol failures cannot be repaired by reconnecting.
fn is_fatal_stream_error(error: &ClientError) -> bool {
    matches!(
        error,
        ClientError::DeviceRevoked
            | ClientError::CredentialUnavailable
            | ClientError::Protocol(_)
            | ClientError::Codec(_)
    )
}

enum Detach {
    /// The connection has no remaining subscriptions.
    Acked,
    /// Stream state is unknown without an acknowledgement.
    Lost,
    /// Revocation or protocol failure prevents reconnect.
    Fatal(String),
}

/// Only a controller acknowledgement establishes that unsubscribe completed.
async fn detach<T: HuginnTransport>(
    conn: &mut LiveConnection<T::Socket, T>,
    session_ids: Vec<live::LiveSessionId>,
) -> Detach {
    let request_id = match live_request_id() {
        Ok(id) => id,
        Err(error) => return Detach::Fatal(error),
    };
    let unsubscribe = live::LiveClientRequest::Unsubscribe {
        request_id,
        session_ids,
    };
    match tokio::time::timeout(Duration::from_secs(10), conn.request_live(unsubscribe)).await {
        Ok(Ok(live::LiveResponse::Ack)) => Detach::Acked,
        Ok(Ok(_)) => Detach::Lost,
        Ok(Err(error)) if is_fatal_stream_error(&error) => Detach::Fatal(error.to_string()),
        Ok(Err(_)) | Err(_) => Detach::Lost,
    }
}

const RECONNECT_FIRST: Duration = Duration::from_millis(250);
const RECONNECT_CEILING: Duration = Duration::from_secs(10);

/// `None` means the event channel answered the order and the actor should wait for another.
async fn establish<T, K>(
    client: &ColinRemoteClient<T, K>,
    events: &mpsc::Sender<PlaneEvent>,
    order: PlaneOrder,
    subscriptions: &mut Vec<live::SessionSubscription>,
    reconnect: &mut Duration,
) -> Option<LiveConnection<T::Socket, T>>
where
    T: HuginnTransport,
    K: DeviceCredentialStore,
{
    let (session, after) = match order {
        PlaneOrder::Subscribe { session, after } => (session, after),
        // Without a connection there is no stream to detach from.
        PlaneOrder::Unsubscribe { session } => {
            subscriptions.retain(|sub| sub.session_id != session);
            let _ = events.send(PlaneEvent::Unsubscribed).await;
            return None;
        }
    };
    let confirmed = subscriptions.clone();
    let mut connection = match client.connect().await {
        Ok(connection) => connection,
        Err(error) if is_transport_error(&error) => {
            unreachable_after_backoff(events, session, reconnect).await;
            return None;
        }
        Err(error) => {
            let _ = events.send(PlaneEvent::Failed(error.to_string())).await;
            return None;
        }
    };
    upsert_subscription(subscriptions, session, after);
    let subscribe = live::LiveClientRequest::Subscribe {
        request_id: match live_request_id() {
            Ok(id) => id,
            Err(error) => {
                let _ = events.send(PlaneEvent::Failed(error)).await;
                return None;
            }
        },
        // Restore every desired subscription at its current cursor after reconnect.
        subscriptions: subscriptions.clone(),
    };
    let outcome =
        tokio::time::timeout(Duration::from_secs(10), connection.request_live(subscribe)).await;
    match outcome {
        Ok(Ok(live::LiveResponse::Subscribed)) => {
            *reconnect = RECONNECT_FIRST;
            let _ = events.send(PlaneEvent::Subscribed { session }).await;
            Some(connection)
        }
        // Restore the confirmed set after refusal; the connection itself remains usable.
        Ok(Ok(other)) => {
            *subscriptions = confirmed;
            let _ = events
                .send(PlaneEvent::SubscribeFailed {
                    session,
                    error: format!("unexpected subscribe answer {other:?}"),
                })
                .await;
            Some(connection)
        }
        Ok(Err(error)) if is_fatal_stream_error(&error) => {
            let _ = events.send(PlaneEvent::Failed(error.to_string())).await;
            None
        }
        // Retain the desired set and cursors after transport failure.
        Ok(Err(error)) if is_transport_error(&error) => {
            unreachable_after_backoff(events, session, reconnect).await;
            None
        }
        Ok(Err(error)) => {
            *subscriptions = confirmed;
            let _ = events
                .send(PlaneEvent::SubscribeFailed {
                    session,
                    error: error.to_string(),
                })
                .await;
            Some(connection)
        }
        Err(_) => {
            unreachable_after_backoff(events, session, reconnect).await;
            None
        }
    }
}

async fn unreachable_after_backoff(
    events: &mpsc::Sender<PlaneEvent>,
    session: live::LiveSessionId,
    reconnect: &mut Duration,
) {
    tokio::select! {
        () = tokio::time::sleep(*reconnect) => {}
        () = events.closed() => return,
    }
    *reconnect = (*reconnect * 2).min(RECONNECT_CEILING);
    let _ = events.send(PlaneEvent::Unreachable { session }).await;
}

fn upsert_subscription(
    subscriptions: &mut Vec<live::SessionSubscription>,
    session: live::LiveSessionId,
    after: live::EventSeq,
) {
    if let Some(existing) = subscriptions
        .iter_mut()
        .find(|sub| sub.session_id == session)
    {
        // Rewinding would deliver events the frontend already applied.
        if after > existing.event_after {
            existing.event_after = after;
        }
    } else {
        subscriptions.push(live::SessionSubscription {
            session_id: session,
            event_after: after,
            terminal_after: None,
        });
    }
}

fn advance_cursor(subscriptions: &mut [live::SessionSubscription], event: &live::LiveEvent) {
    if let Some(subscription) = subscriptions
        .iter_mut()
        .find(|sub| sub.session_id == event.session_id)
    {
        subscription.event_after = event.sequence;
    }
}

/// Preparation uses shared composition; only `commit()` performs session actions.
pub(crate) struct GovernedOpener {
    pub config: OdindConfig,
    pub seat: String,
    pub project: String,
    /// Fresh sessions use this declaration; loaded sessions keep their persisted provider and model.
    pub provider: String,
    pub model: String,
    pub client: Arc<ColinRemoteClient<EndpointTransport, FileCredentialStore>>,
    pub device: live::DeviceId,
}

impl SessionOpener for GovernedOpener {
    fn prepare_new(&self) -> BoxFuture<'static, Result<PendingSession, String>> {
        let config = self.config.clone();
        let seat = self.seat.clone();
        let project = self.project.clone();
        let provider = self.provider.clone();
        let model = self.model.clone();
        let client = self.client.clone();
        let device = self.device;
        Box::pin(async move {
            let command = command_id()?;
            let composition = authority_provision::compose(
                &config,
                &seat,
                &project,
                &command,
                authority_provision::LaunchSelection::new(&provider, &model),
            )?;
            let facts = SessionFacts::from_composition(&composition);
            let commit = move || -> BoxFuture<'static, Result<OpenedSession, String>> {
                let config = config.clone();
                let composition = composition.clone();
                let client = client.clone();
                Box::pin(async move {
                    // Reuse only a token that still authenticates through the shared CLI policy.
                    let mint = authority_provision::ensure_session_token(
                        &config,
                        &composition,
                        DEFAULT_TOKEN_TTL_SECONDS,
                        authority_provision::TokenRenewalPolicy::OperatorOnly,
                    )
                    .map_err(|error| {
                        format!(
                            "session {} (command {}) has no usable authority: {error}",
                            composition.live_session, composition.command_id
                        )
                    })?;
                    tracing::info!(
                        action = if mint.reused_existing { "reused" } else { "minted" },
                        token = %mint.token_id,
                        ttl_s = mint.ttl_seconds,
                        path = %mint.token_path.display(),
                        "authority bounded token"
                    );
                    let summary = open_idle(&client, &config, &composition).await?;
                    let gate = OperatorPromptGate::opened(config, composition.clone(), device);
                    Ok(OpenedSession {
                        facts: SessionFacts::from_composition(&composition),
                        gate: Box::new(gate),
                        epoch: summary.epoch,
                        state: summary.state,
                        // Fresh sessions need first-prompt acceptance.
                        gate_accepted: false,
                    })
                })
            };
            Ok(PendingSession::new(facts.project_root.clone(), commit))
        })
    }
    fn prepare_load(
        &self,
        live_session: live::LiveSessionId,
    ) -> BoxFuture<'static, Result<PendingSession, String>> {
        let config = self.config.clone();
        let seat = self.seat.clone();
        let project = self.project.clone();
        let client = self.client.clone();
        let device = self.device;
        Box::pin(async move {
            // Use the controller's session list rather than a potentially stale local cache.
            let summary = find_live_session(&client, live_session).await?;
            if summary.seat_id.as_str() != seat {
                return Err(format!(
                    "session {} belongs to seat {}, but this frontend is bound to seat {seat}",
                    summary.session_id, summary.seat_id
                ));
            }
            // Preserve the session's provider and model rather than selecting from declaration order.
            let command = command_id()?;
            let composition = authority_provision::compose_for_session(
                &config,
                &seat,
                &project,
                &command,
                live_session,
                authority_provision::LaunchSelection::new(
                    summary.provider.as_str(),
                    summary.model.as_str(),
                ),
            )?;
            let facts = SessionFacts::from_composition(&composition);
            let commit = move || -> BoxFuture<'static, Result<OpenedSession, String>> {
                Box::pin(async move {
                    // Check the durable run's project and acceptance before exposing a loaded session.
                    let gate_accepted =
                        odin_cli::operator_prompt::has_accepted_plan(&config, &composition)?;
                    let gate = OperatorPromptGate::loaded(
                        config,
                        seat,
                        project,
                        live_session,
                        summary.provider.as_str().to_owned(),
                        summary.model.as_str().to_owned(),
                        device,
                    );
                    Ok(OpenedSession {
                        facts: SessionFacts::from_composition(&composition),
                        gate: Box::new(gate),
                        epoch: summary.epoch,
                        state: summary.state,
                        gate_accepted,
                    })
                })
            };
            Ok(PendingSession::new(facts.project_root.clone(), commit))
        })
    }
}

/// Open idle so the first prompt cannot precede durable plan acceptance.
async fn open_idle(
    client: &ColinRemoteClient<EndpointTransport, FileCredentialStore>,
    config: &OdindConfig,
    composition: &SessionComposition,
) -> Result<live::LiveSessionSummary, String> {
    // The controller's declared node selects placement, not the ACP frontend.
    let node = NodeId::parse(&config.identity.node).map_err(|error| {
        format!(
            "invalid controller node id {:?}: {error}",
            config.identity.node
        )
    })?;
    let request = live::OpenSessionRequest {
        command_id: composition.command_id.clone(),
        seat_id: composition.seat.clone(),
        project_id: composition.project.clone(),
        slice_id: composition.slice.clone(),
        provider: composition.provider.clone(),
        model: composition.model.clone(),
        title: None,
        target_node: node,
        open_tab: false,
        initial_prompt: None,
        workload: None,
        served_revision: Some(composition.snapshot_revision),
    };
    let summary = match client
        .request(live::HuginnRequest::OpenSession(request))
        .await
    {
        Ok(live::HuginnResponse::SessionOpened(summary)) => summary,
        Ok(other) => {
            return Err(format!(
                "the controller answered the session open with {other:?}"
            ))
        }
        Err(error) => return Err(error.to_string()),
    };
    // Reject a controller response naming a different session or seat.
    if summary.session_id != composition.live_session {
        return Err(format!(
            "the controller returned session {}, but command {} provisioned {}",
            summary.session_id, composition.command_id, composition.live_session
        ));
    }
    if summary.seat_id != composition.seat {
        return Err(format!(
            "the controller opened session {} on seat {}, but command {} provisioned \
             seat {}",
            summary.session_id, summary.seat_id, composition.command_id, composition.seat
        ));
    }
    Ok(summary)
}

pub(crate) struct OperatorPromptGate {
    config: OdindConfig,
    binding: GateBinding,
    device: live::DeviceId,
}

enum GateBinding {
    Opened(Box<SessionComposition>),
    /// Recompose loaded sessions using their persisted provider and model.
    Loaded {
        seat: String,
        project: String,
        live_session: live::LiveSessionId,
        /// Preserve the controller's stored launch selection instead of deriving a replacement.
        provider: String,
        model: String,
    },
}

impl OperatorPromptGate {
    pub(crate) fn opened(
        config: OdindConfig,
        composition: SessionComposition,
        device: live::DeviceId,
    ) -> Self {
        Self {
            config,
            binding: GateBinding::Opened(Box::new(composition)),
            device,
        }
    }

    pub(crate) fn loaded(
        config: OdindConfig,
        seat: String,
        project: String,
        live_session: live::LiveSessionId,
        provider: String,
        model: String,
        device: live::DeviceId,
    ) -> Self {
        Self {
            config,
            binding: GateBinding::Loaded {
                seat,
                project,
                live_session,
                provider,
                model,
            },
            device,
        }
    }
}

impl FirstPromptGate for OperatorPromptGate {
    fn prepare<'a>(
        &'a mut self,
        prompt: &'a str,
        epoch: live::SessionEpoch,
    ) -> BoxFuture<'a, Result<PreparedPrompt, String>> {
        Box::pin(async move {
            let loaded;
            let composition = match &self.binding {
                GateBinding::Opened(composition) => composition.as_ref(),
                GateBinding::Loaded {
                    seat,
                    project,
                    live_session,
                    provider,
                    model,
                } => {
                    // Command IDs identify actions, not durable sessions.
                    let command = command_id()?;
                    loaded = authority_provision::compose_for_session(
                        &self.config,
                        seat,
                        project,
                        &command,
                        *live_session,
                        authority_provision::LaunchSelection::new(provider, model),
                    )?;
                    &loaded
                }
            };
            let prepared = odin_cli::operator_prompt::prepare(
                &self.config,
                composition,
                self.device,
                prompt,
                epoch,
            )?;
            let (command, receipt) = prepared.into_parts();
            Ok(PreparedPrompt { command, receipt })
        })
    }
}

/// Query approvals for the requested session only; unreadable ledgers are errors, not empty results.
pub(crate) fn kernel_approvals_reader(
    state_root: PathBuf,
) -> Arc<dyn Fn(live::LiveSessionId) -> Result<Vec<KernelApprovalView>, String> + Send + Sync> {
    Arc::new(move |session: live::LiveSessionId| {
        let ledger = odin_ledger::Ledger::open(state_root.join("ledger.sqlite3"))
            .map_err(|error| format!("could not open the shared session ledger: {error}"))?;
        // Use the shared run-ID convention and scoped SQL to exclude other sessions' approvals.
        let run = odin_cli::operator_prompt::session_run_id(&session)?;
        let approvals = ledger
            .requested_approvals_for_target("run", run.as_str())
            .map_err(|error| format!("could not read the durable approvals: {error}"))?;
        let now = time::OffsetDateTime::now_utc();
        Ok(approvals
            .into_iter()
            .filter(|approval| approval.expires_at > now)
            .map(|approval| KernelApprovalView {
                approval_id: approval.approval_id.to_string(),
                revision: approval.revision,
                capability_id: approval.scope.capability_id.as_str().to_owned(),
                target_kind: approval.scope.target_kind,
                target_id: approval.scope.target_id,
                arguments_digest: approval.scope.arguments_digest.to_string(),
            })
            .collect())
    })
}

#[cfg(test)]
mod tests;
