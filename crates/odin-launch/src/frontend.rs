//! Poll network tasks alongside input so a stalled controller cannot block cancellation or EOF.

mod events;
mod permissions;
mod setup;

use std::collections::{BTreeSet, HashMap, VecDeque};
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use futures_util::future::BoxFuture;
use futures_util::stream::{FuturesUnordered, StreamExt};
use odin_cli::operator_prompt::OperatorPlanReceipt;
use odin_domain::huginn as live;
use odin_domain::{ApprovalId, CommandId};
use odin_huginn::client::{ColinRemoteClient, HuginnTransport};
use odin_huginn::DeviceCredentialStore;
use serde_json::{json, Value};
use tokio::sync::mpsc;

use crate::acp::{
    self, DecidedPermission, Framing, Message, PromptResult, RequestPermissionResult, RpcError,
    ACP_PROTOCOL_VERSION, AGENT_NAME, AGENT_TITLE,
};
use crate::backend::{
    command_id, send_session_command, PlaneEvent, PlaneHandle, PlaneOrder, SessionFacts,
};

type SessionCommit = dyn FnOnce() -> BoxFuture<'static, Result<OpenedSession, String>> + Send;

/// Preparation has no effects; `commit()` ensures the token and opens a new session if needed.
pub(crate) struct PendingSession {
    project_root: PathBuf,
    commit: Box<SessionCommit>,
}

impl PendingSession {
    pub(crate) fn new(
        project_root: PathBuf,
        commit: impl FnOnce() -> BoxFuture<'static, Result<OpenedSession, String>> + Send + 'static,
    ) -> Self {
        Self {
            project_root,
            commit: Box::new(commit),
        }
    }

    pub(crate) fn project_root(&self) -> &Path {
        &self.project_root
    }

    pub(crate) async fn commit(self) -> Result<OpenedSession, String> {
        (self.commit)().await
    }
}

pub(crate) struct OpenedSession {
    pub facts: SessionFacts,
    pub gate: Box<dyn FirstPromptGate>,
    pub epoch: live::SessionEpoch,
    pub state: live::LiveSessionState,
    /// Loaded sessions retain durable plan acceptance; fresh sessions need the first-prompt gate.
    pub gate_accepted: bool,
}

/// Use the shared operator-prompt path so ACP cannot bypass plan acceptance.
pub(crate) trait FirstPromptGate: Send + Sync {
    fn prepare<'a>(
        &'a mut self,
        prompt: &'a str,
        epoch: live::SessionEpoch,
    ) -> BoxFuture<'a, Result<PreparedPrompt, String>>;
}

/// Keep the acceptance receipt with the prompt command so sending cannot rerun acceptance.
pub(crate) struct PreparedPrompt {
    pub command: live::LiveCommand,
    pub receipt: OperatorPlanReceipt,
}

pub(crate) trait SessionOpener: Send + Sync {
    /// Resolve the project root before performing any session action.
    fn prepare_new(&self) -> BoxFuture<'static, Result<PendingSession, String>>;
    /// Check the controller's session list without performing any session action.
    fn prepare_load(
        &self,
        live_session: live::LiveSessionId,
    ) -> BoxFuture<'static, Result<PendingSession, String>>;
}

#[derive(Debug, Clone)]
pub(crate) struct KernelApprovalView {
    pub approval_id: String,
    pub revision: i64,
    pub capability_id: String,
    pub target_kind: String,
    pub target_id: String,
    pub arguments_digest: String,
}

/// Return only undecided approvals for the requested session; decisions use backend commands.
pub(crate) type ApprovalsReader =
    Arc<dyn Fn(live::LiveSessionId) -> Result<Vec<KernelApprovalView>, String> + Send + Sync>;

#[derive(Debug, Clone)]
enum SetupKind {
    New,
    Load,
}

#[derive(Debug, Clone)]
struct SetupWaiter {
    acp_request_id: Value,
    kind: SetupKind,
}

struct Turn {
    acp_request_id: Value,
    /// Reconnect resends the same command identity so the journal can deduplicate it.
    command_id: CommandId,
    cancel_requested: bool,
    /// Retain the abort identity to prevent multiple aborts for one turn.
    abort_command: Option<CommandId>,
    /// Admission alone does not establish that an abort took effect.
    abort_outcome: Option<bool>,
    /// Failed or cancelled decisions must resolve the pending turn rather than leave it waiting.
    decision_commands: Vec<CommandId>,
}

#[derive(Debug, Clone)]
struct LivePermission {
    request_id: live::PermissionRequestId,
    epoch: live::SessionEpoch,
}

#[derive(Debug, Clone)]
struct KernelApproval {
    approval_id: ApprovalId,
    revision: i64,
    epoch: live::SessionEpoch,
}

struct Session {
    facts: SessionFacts,
    epoch: live::SessionEpoch,
    state: live::LiveSessionState,
    /// Monotonic cursors prevent reconnect from replaying already-applied events.
    cursor: live::EventSeq,
    subscribed: bool,
    /// Reorder subscriptions until the daemon confirms the stream.
    stream_owed: bool,
    gate_accepted: bool,
    streaming_text: bool,
    /// Suppress a Result that repeats the assistant message already displayed.
    last_answer: Option<String>,
    gate: Box<dyn FirstPromptGate>,
    turn: Option<Turn>,
    /// Replay reconciles uncertain commands using their original identities, not new commands.
    unconfirmed: Vec<live::LiveCommand>,
    /// Track restart until receipt, outcome, or transfer to `unconfirmed` prevents duplicate sends.
    restart_inflight: Option<CommandId>,
    /// Replay removes resolved permissions before any surviving requests are displayed.
    pending_permissions: HashMap<live::PermissionRequestId, live::PermissionRequest>,
    permission_out: HashMap<u64, LivePermission>,
    approval_out: HashMap<u64, KernelApproval>,
    shown_kernel: BTreeSet<String>,
    setup: Option<SetupWaiter>,
    manifest: Option<live::SessionManifest>,
    /// Hide content and reject actions until the manifest matches the configured seat and project.
    manifest_ok: bool,
    in_replay: bool,
    ended: bool,
}

impl Session {
    fn from_opened(opened: OpenedSession, setup: SetupWaiter) -> Self {
        Self {
            facts: opened.facts,
            epoch: opened.epoch,
            state: opened.state,
            cursor: live::EventSeq::new(0),
            subscribed: false,
            stream_owed: false,
            gate_accepted: opened.gate_accepted,
            streaming_text: false,
            last_answer: None,
            gate: opened.gate,
            turn: None,
            unconfirmed: Vec::new(),
            restart_inflight: None,
            pending_permissions: HashMap::new(),
            permission_out: HashMap::new(),
            approval_out: HashMap::new(),
            shown_kernel: BTreeSet::new(),
            setup: Some(setup),
            manifest: None,
            manifest_ok: false,
            in_replay: false,
            ended: false,
        }
    }

    fn apply_receipt(&mut self, receipt: &live::CommandReceipt) -> Option<Message> {
        let id = match receipt {
            live::CommandReceipt::Accepted { command_id }
            | live::CommandReceipt::Duplicate { command_id, .. }
            | live::CommandReceipt::Rejected { command_id, .. } => command_id,
        };
        self.unconfirmed.retain(|command| &command.command_id != id);
        if self.restart_inflight.as_ref() == Some(id) {
            self.restart_inflight = None;
        }
        match receipt {
            live::CommandReceipt::Rejected { reason, .. } => {
                let turn = self.turn.as_mut()?;
                if turn.abort_command.as_ref() == Some(id) {
                    turn.abort_outcome = Some(false);
                    return self.take_idle_reply();
                }
                if &turn.command_id == id || turn.decision_commands.contains(id) {
                    return Some(finish_turn(
                        self.turn.take()?,
                        TurnOutcome::Failed(governed(format!(
                            "the controller refused the command: {reason}"
                        ))),
                    ));
                }
                None
            }
            live::CommandReceipt::Duplicate {
                prior_outcome: Some(outcome),
                ..
            } => self.apply_outcome(outcome),
            _ => None,
        }
    }

    fn apply_outcome(&mut self, outcome: &live::CommandOutcome) -> Option<Message> {
        let id = match outcome {
            live::CommandOutcome::Applied { command_id }
            | live::CommandOutcome::Cancelled { command_id, .. }
            | live::CommandOutcome::Failed { command_id, .. }
            | live::CommandOutcome::ToolDenied { command_id, .. } => command_id,
        };
        self.unconfirmed.retain(|command| &command.command_id != id);
        if self.restart_inflight.as_ref() == Some(id) {
            self.restart_inflight = None;
        }
        let turn = self.turn.as_mut()?;
        if turn.abort_command.as_ref() == Some(id) {
            turn.abort_outcome = Some(matches!(outcome, live::CommandOutcome::Applied { .. }));
            return self.take_idle_reply();
        }
        if &turn.command_id != id && !turn.decision_commands.contains(id) {
            return None;
        }
        turn.decision_commands.retain(|pending| pending != id);
        turn_outcome_for(outcome)
            .map(|outcome| finish_turn(self.turn.take().expect("matched active turn"), outcome))
    }

    fn take_idle_reply(&mut self) -> Option<Message> {
        if self.state != live::LiveSessionState::Idle || !self.approval_out.is_empty() {
            return None;
        }
        let turn = self.turn.as_ref()?;
        if !turn.decision_commands.is_empty()
            || (turn.abort_command.is_some() && turn.abort_outcome.is_none())
        {
            return None;
        }
        let reason = if turn.abort_outcome == Some(true) {
            acp::STOP_CANCELLED
        } else {
            acp::STOP_END_TURN
        };
        Some(finish_turn(self.turn.take()?, TurnOutcome::Stopped(reason)))
    }

    fn bind_manifest(&mut self, manifest: &live::SessionManifest) {
        self.manifest = Some(manifest.clone());
        self.manifest_ok = manifest.seat_id.as_str() == self.facts.seat
            && manifest.project_id.as_str() == self.facts.project;
    }

    /// Replay cannot expose content before the manifest's seat and project are checked.
    fn exposure_allowed(&self) -> bool {
        self.manifest_ok
    }
}

enum Completion {
    SetupReady {
        request_id: Value,
        kind: SetupKind,
        opened: Result<OpenedSession, RpcError>,
    },
    CommandSent {
        session: live::LiveSessionId,
        command: live::LiveCommand,
        outcome: Result<live::CommandReceipt, String>,
    },
    OrdersDrained,
}

enum TurnOutcome {
    Stopped(&'static str),
    Failed(RpcError),
}

fn finish_turn(turn: Turn, outcome: TurnOutcome) -> Message {
    match outcome {
        TurnOutcome::Stopped(stop_reason) => Message::success(
            turn.acp_request_id,
            serde_json::to_value(PromptResult { stop_reason }).expect("prompt result serializes"),
        ),
        TurnOutcome::Failed(error) => Message::failure(turn.acp_request_id, error),
    }
}

/// Applied commands do not end a turn; completion waits for the session state change.
fn turn_outcome_for(outcome: &live::CommandOutcome) -> Option<TurnOutcome> {
    match outcome {
        live::CommandOutcome::Failed { error, .. } => Some(TurnOutcome::Failed(governed(format!(
            "the turn failed durably: {} [{}]",
            error.message, error.code
        )))),
        live::CommandOutcome::Cancelled { .. } => Some(TurnOutcome::Stopped(acp::STOP_CANCELLED)),
        live::CommandOutcome::Applied { .. } | live::CommandOutcome::ToolDenied { .. } => None,
    }
}

pub(crate) struct Frontend<T: HuginnTransport, K: DeviceCredentialStore> {
    client: Arc<ColinRemoteClient<T, K>>,
    opener: Arc<dyn SessionOpener>,
    approvals: ApprovalsReader,
    plane: PlaneHandle,
    plane_events: mpsc::Receiver<PlaneEvent>,
    outbound: mpsc::Sender<Message>,
    /// Pause producers until overflow drains so backpressure cannot create an unbounded queue.
    overflow: VecDeque<Message>,
    sessions: HashMap<String, Session>,
    initialized: bool,
    next_outgoing_id: u64,
    tasks: FuturesUnordered<BoxFuture<'static, Completion>>,
}

impl<T: HuginnTransport, K: DeviceCredentialStore> Frontend<T, K> {
    pub(crate) fn new(
        client: Arc<ColinRemoteClient<T, K>>,
        opener: Arc<dyn SessionOpener>,
        approvals: ApprovalsReader,
        plane: PlaneHandle,
        plane_events: mpsc::Receiver<PlaneEvent>,
        outbound: mpsc::Sender<Message>,
    ) -> Self {
        Self {
            client,
            opener,
            approvals,
            plane,
            plane_events,
            outbound,
            overflow: VecDeque::new(),
            sessions: HashMap::new(),
            initialized: false,
            next_outgoing_id: 0,
            tasks: FuturesUnordered::new(),
        }
    }

    /// EOF detaches without aborting durable sessions.
    pub(crate) async fn run<R: tokio::io::AsyncRead + Unpin>(
        mut self,
        input: R,
    ) -> Result<(), RpcError> {
        let mut reader = tokio::io::BufReader::new(input);
        // Keep partial bytes outside the read future so select! cancellation cannot discard them.
        let mut line = Vec::new();
        let outbound = self.outbound.clone();
        let mut input_failure = None;
        loop {
            let accepting = self.overflow.is_empty();
            tokio::select! {
                event = self.plane_events.recv(), if accepting => {
                    match event {
                        Some(event) => self.on_plane_event(event)?,
                        None => return Err(governed("the backend event stream closed")),
                    }
                }
                Some(completion) = self.tasks.next(), if accepting && !self.tasks.is_empty() => {
                    self.on_completion(completion);
                }
                permit = outbound.reserve(), if !self.overflow.is_empty() => {
                    match permit {
                        Ok(permit) => {
                            if let Some(message) = self.overflow.pop_front() {
                                permit.send(message);
                            }
                        }
                        Err(_) => break,
                    }
                }
                framed = acp::read_message(&mut reader, &mut line, acp::MAX_FRAME_BYTES), if accepting => {
                    match framed {
                        Ok(Framing::Eof) => break,
                        Ok(Framing::Message(message)) => {
                            if self.on_message(message).await.is_err() {
                                break;
                            }
                        }
                        Err(error) if error.kind() == io::ErrorKind::InvalidData => {
                            // Stop after framing errors because the remaining stream is not trustworthy.
                            self.queue_message(Message::failure(
                                Value::Null,
                                acp::framing_error(error),
                            ));
                            break;
                        }
                        Err(error) => {
                            input_failure = Some(error);
                            break;
                        }
                    }
                }
            }
        }
        // Responses queued before the input closed still leave.
        while let Some(message) = self.overflow.pop_front() {
            if self.outbound.send(message).await.is_err() {
                break;
            }
        }
        match input_failure {
            Some(error) => Err(governed(format!("the editor's input failed: {error}"))),
            None => Ok(()),
        }
    }

    async fn on_message(&mut self, message: Message) -> Result<(), ()> {
        if message.method.is_none() && message.id.is_some() {
            return self.on_client_response(message).await;
        }
        let Some(method) = message.method.clone() else {
            self.queue_message(Message::failure(
                message.id.unwrap_or(Value::Null),
                RpcError::new(
                    RpcError::INVALID_REQUEST,
                    "message carries neither method nor response",
                ),
            ));
            return Ok(());
        };
        let params = message.params.clone();
        if message.is_notification() {
            self.on_notification(&method, params.as_ref());
            return Ok(());
        }
        let id = message.id.clone().unwrap_or(Value::Null);
        let outcome: Result<Handled, RpcError> = match method.as_str() {
            "initialize" => self
                .handle_initialize(params.as_ref())
                .await
                .map(Handled::Now),
            "session/new" => self.handle_session_new(&id, params.as_ref()).await,
            "session/load" => self.handle_session_load(&id, params.as_ref()).await,
            "session/prompt" => self.handle_prompt(&id, params.as_ref()).await,
            "session/close" => self.handle_session_close(params.as_ref()).map(Handled::Now),
            "authenticate"
            | "session/list"
            | "session/resume"
            | "session/fork"
            | "session/set_mode"
            | "session/set_config_option" => Err(RpcError::new(
                RpcError::METHOD_NOT_FOUND,
                format!("{method} is not implemented and not advertised"),
            )),
            "$/cancel_request" => Ok(Handled::Now(json!({}))),
            _ => Err(RpcError::new(
                RpcError::METHOD_NOT_FOUND,
                format!("unknown method {method:?}"),
            )),
        };
        match outcome {
            Ok(Handled::Now(result)) => {
                self.queue_message(Message::success(id, result));
            }
            // Setup waits for replay; prompts wait for a turn outcome.
            Ok(Handled::Deferred) => {}
            Err(error) => {
                self.queue_message(Message::failure(id, error));
            }
        }
        Ok(())
    }

    async fn handle_prompt(
        &mut self,
        id: &Value,
        params: Option<&Value>,
    ) -> Result<Handled, RpcError> {
        self.require_initialized()?;
        let params: acp::PromptParams = acp::decode_params(params, "session/prompt")?;
        let texts = acp::prompt_blocks_to_text(&params.prompt)?;
        let message = live::LiveMessage::new(
            texts
                .into_iter()
                .map(live::LiveContentBlock::Text)
                .collect::<Vec<_>>(),
        )
        .map_err(|error| {
            RpcError::new(
                RpcError::INVALID_PARAMS,
                format!("the prompt is not a valid governed message: {error}"),
            )
        })?;

        // Finish local checks before sending; only the network operation needs a tracked task.
        let (live_session, command) = {
            let session = self.session_mut(&params.session_id)?;
            if session.ended {
                return Err(RpcError::new(
                    RpcError::GOVERNED_REFUSAL,
                    format!("session {} has ended", params.session_id),
                ));
            }
            if session.setup.is_some() {
                return Err(RpcError::new(
                    RpcError::GOVERNED_REFUSAL,
                    "the session setup has not completed; its binding proof is pending",
                ));
            }
            if !session.subscribed {
                return Err(RpcError::new(
                    RpcError::GOVERNED_REFUSAL,
                    "the backend connection is not streaming yet",
                ));
            }
            if session.turn.is_some() {
                return Err(RpcError::new(
                    RpcError::INVALID_REQUEST,
                    "this session already has a prompt in flight; cancel it first",
                ));
            }
            let text = message
                .content
                .iter()
                .filter_map(|block| match block {
                    live::LiveContentBlock::Text(text) => Some(text.as_str()),
                    _ => None,
                })
                .collect::<Vec<_>>()
                .join("\n");
            let command = if session.gate_accepted {
                // Follow-up prompts must not replace the accepted plan or rerun acceptance.
                let body = if matches!(
                    session.state,
                    live::LiveSessionState::Running | live::LiveSessionState::RequiresAction
                ) {
                    live::LiveCommandBody::FollowUp {
                        message: message.clone(),
                    }
                } else {
                    live::LiveCommandBody::Prompt {
                        message: message.clone(),
                    }
                };
                live::LiveCommand {
                    command_id: command_id().map_err(governed)?,
                    session_id: session.facts.live_session,
                    expected_epoch: session.epoch,
                    expected_event_head: None,
                    body,
                }
            } else {
                // Acceptance replaces the durable plan, so only ungated idle sessions may use it.
                if !matches!(session.state, live::LiveSessionState::Idle) {
                    return Err(RpcError::new(
                        RpcError::GOVERNED_REFUSAL,
                        "the first prompt of an ungated session requires an idle session",
                    ));
                }
                let prepared = session
                    .gate
                    .prepare(&text, session.epoch)
                    .await
                    .map_err(governed)?;
                let command = prepared.command;
                if command.session_id != session.facts.live_session {
                    return Err(RpcError::new(
                        RpcError::INTERNAL_ERROR,
                        "the prepared prompt command names a different session",
                    ));
                }
                tracing::info!(
                    run = %prepared.receipt.run,
                    revision = %prepared.receipt.revision,
                    fingerprint = %prepared.receipt.fingerprint,
                    actor = %prepared.receipt.actor,
                    label = %prepared.receipt.label,
                    prompt_command = %prepared.receipt.prompt_command_id,
                    "plan accepted"
                );
                // Acceptance is durable; an uncertain send must not rerun the gate.
                session.gate_accepted = true;
                command
            };
            (session.facts.live_session, command)
        };
        // Track before sending so cancellation races and uncertain delivery retain this identity.
        let session_key = live_session.to_string();
        let session = self
            .sessions
            .get_mut(&session_key)
            .ok_or_else(|| governed("session vanished before the prompt send"))?;
        session.turn = Some(Turn {
            acp_request_id: id.clone(),
            command_id: command.command_id.clone(),
            cancel_requested: false,
            abort_command: None,
            abort_outcome: None,
            decision_commands: Vec::new(),
        });
        self.send_tracked(live_session, command);
        Ok(Handled::Deferred)
    }

    fn handle_session_close(&mut self, params: Option<&Value>) -> Result<Value, RpcError> {
        self.require_initialized()?;
        let session_id = params
            .and_then(|params| params.get("sessionId"))
            .and_then(Value::as_str)
            .ok_or_else(|| RpcError::new(RpcError::INVALID_PARAMS, "sessionId is required"))?
            .to_owned();
        if let Some(mut session) = self.sessions.remove(&session_id) {
            if let Some(turn) = session.turn.take() {
                self.queue_message(finish_turn(turn, TurnOutcome::Stopped(acp::STOP_CANCELLED)));
            }
            // Detach, never kill: the durable session keeps running.
            self.order_plane(PlaneOrder::Unsubscribe {
                session: session.facts.live_session,
            });
        }
        Ok(json!({}))
    }

    fn on_notification(&mut self, method: &str, params: Option<&Value>) {
        if method == "session/cancel" {
            let session_id = params
                .and_then(|params| params.get("sessionId"))
                .and_then(Value::as_str);
            if let Some(session_id) = session_id {
                if let Err(error) = self.handle_cancel(session_id) {
                    tracing::error!(%error, "cancel failed");
                }
            }
        }
        // Unknown notifications are ignored: notifications are never answered.
    }

    /// Retain cancellation until the running-state event allows exactly one abort to be sent.
    fn handle_cancel(&mut self, session_id: &str) -> Result<(), String> {
        let abort = {
            let Some(session) = self.sessions.get_mut(session_id) else {
                return Err(format!("session {session_id} is not attached"));
            };
            if let Some(turn) = session.turn.as_mut() {
                turn.cancel_requested = true;
            }
            let abort_in_flight = session
                .turn
                .as_ref()
                .is_some_and(|turn| turn.abort_command.is_some());
            let running = matches!(
                session.state,
                live::LiveSessionState::Running | live::LiveSessionState::RequiresAction
            );
            if !running || abort_in_flight {
                // Retain intent until work starts, without sending a duplicate abort.
                None
            } else {
                let abort_id = command_id()?;
                if let Some(turn) = session.turn.as_mut() {
                    turn.abort_command = Some(abort_id.clone());
                }
                Some(live::LiveCommand {
                    command_id: abort_id,
                    session_id: session.facts.live_session,
                    expected_epoch: session.epoch,
                    expected_event_head: None,
                    body: live::LiveCommandBody::Abort {
                        scope: live::AbortScope::CurrentTurn,
                    },
                })
            }
        };
        if let Some(abort) = abort {
            let live_session = abort.session_id;
            self.send_tracked(live_session, abort);
        }
        Ok(())
    }

    /// Preserve command identity so replay can reconcile transport failures without new effects.
    fn send_tracked(&mut self, session: live::LiveSessionId, command: live::LiveCommand) {
        if matches!(command.body, live::LiveCommandBody::Restart) {
            if let Some(tracked) = self.sessions.get_mut(&session.to_string()) {
                tracked.restart_inflight = Some(command.command_id.clone());
            }
        }
        let client = Arc::clone(&self.client);
        self.tasks.push(Box::pin(async move {
            let outcome = send_session_command(&client, command.clone()).await;
            Completion::CommandSent {
                session,
                command,
                outcome,
            }
        }));
    }

    /// A full order channel must not block the frontend loop.
    fn order_plane(&mut self, order: PlaneOrder) {
        if let Err(error) = self.plane.orders().try_send(order) {
            let orders = self.plane.orders();
            let order = error.into_inner();
            self.tasks.push(Box::pin(async move {
                let _ = orders.send(order).await;
                Completion::OrdersDrained
            }));
        }
    }

    fn on_completion(&mut self, completion: Completion) {
        match completion {
            Completion::SetupReady {
                request_id,
                kind,
                opened,
            } => self.on_setup_ready(request_id, kind, opened),
            Completion::CommandSent {
                session,
                command,
                outcome,
            } => self.on_command_sent(session, command, outcome),
            Completion::OrdersDrained => {}
        }
    }

    fn on_command_sent(
        &mut self,
        session: live::LiveSessionId,
        command: live::LiveCommand,
        outcome: Result<live::CommandReceipt, String>,
    ) {
        let Some(session) = self.sessions.get_mut(&session.to_string()) else {
            return;
        };
        match outcome {
            Ok(receipt) => {
                if matches!(receipt, live::CommandReceipt::Rejected { .. }) {
                    if let live::LiveCommandBody::DecideApproval { approval_id, .. } = &command.body
                    {
                        session.shown_kernel.remove(approval_id.as_str());
                    }
                }
                if let Some(reply) = session.apply_receipt(&receipt) {
                    self.queue_message(reply);
                }
            }
            Err(error) => {
                tracing::warn!(
                    command = %command.command_id,
                    %error,
                    "command fate unknown; kept pending for replay reconciliation"
                );
                if session.restart_inflight.as_ref() == Some(&command.command_id) {
                    session.restart_inflight = None;
                }
                if !session
                    .unconfirmed
                    .iter()
                    .any(|tracked| tracked.command_id == command.command_id)
                {
                    session.unconfirmed.push(command);
                }
            }
        }
    }

    /// Preserve message order in overflow when the output channel is full.
    fn queue_message(&mut self, message: Message) {
        let message = if self.overflow.is_empty() {
            match self.outbound.try_send(message) {
                Ok(()) => return,
                Err(error) => error.into_inner(),
            }
        } else {
            message
        };
        self.overflow.push_back(message);
    }

    fn require_initialized(&self) -> Result<(), RpcError> {
        if self.initialized {
            Ok(())
        } else {
            Err(RpcError::new(
                RpcError::GOVERNED_REFUSAL,
                "initialize must succeed before any session method",
            ))
        }
    }

    fn reject_unsupported_setup(
        &self,
        mcp_servers: usize,
        additional_directories: usize,
    ) -> Result<(), RpcError> {
        if mcp_servers > 0 {
            return Err(RpcError::new(
                RpcError::GOVERNED_REFUSAL,
                "mcpServers are not supported: the governed session runs only its declared \
                 capsule tools and accepts no host tool injection",
            ));
        }
        if additional_directories > 0 {
            return Err(RpcError::new(
                RpcError::GOVERNED_REFUSAL,
                "additionalDirectories are not supported: the session is bound to exactly \
                 its composed project root",
            ));
        }
        Ok(())
    }

    fn session_mut(&mut self, session_id: &str) -> Result<&mut Session, RpcError> {
        self.sessions.get_mut(session_id).ok_or_else(|| {
            RpcError::new(
                RpcError::INVALID_REQUEST,
                format!("session {session_id} is not attached to this frontend"),
            )
        })
    }

    fn session_by_live_mut(&mut self, live_session: live::LiveSessionId) -> Option<&mut Session> {
        let key = live_session.to_string();
        self.sessions.get_mut(&key)
    }
}

enum Handled {
    Now(Value),
    Deferred,
}

/// Model/tool text is untrusted: escape sequences are never interpreted.
fn safe_text(text: &str) -> String {
    text.chars()
        .filter(|c| !c.is_control() || *c == '\n' || *c == '\t')
        .collect()
}

fn governed(message: impl Into<String>) -> RpcError {
    RpcError::new(RpcError::GOVERNED_REFUSAL, message.into())
}

// Tests drive the real loop over a duplex stream.
#[cfg(test)]
mod tests;
