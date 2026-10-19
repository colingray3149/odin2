//! ACP frontend state machine tests.
//!
//! The scripted daemon here is a controlled external boundary only: it sits
//! behind the actual memory transport, decodes and encodes the real framed
//! Huginn protocol with the shared codec, and records every frame the
//! frontend sends. Nothing in the frontend is mocked; the governance seams
//! (opener, gate, approvals) are scripted because their production bodies
//! live in `odin-cli` and are covered by that crate's own suite.

use std::collections::VecDeque;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;

use parking_lot::Mutex;
use std::time::Duration;

use futures_util::future::BoxFuture;
use odin_cli::operator_prompt::OperatorPlanReceipt;
use odin_domain::huginn as live;
use odin_domain::CommandId;
use odin_huginn::client::{
    memory_transport, ColinRemoteClient, DeviceCredential, MemoryCredentialStore, MemoryServerEnd,
    TransportFrame as _,
};
use odin_huginn::protocol::{decode_frame, encode_frame, ClientFrame, CodecLimits, ServerFrame};
use serde_json::{json, Value};
use tokio::sync::mpsc;

use super::{
    ApprovalsReader, FirstPromptGate, Frontend, KernelApprovalView, OpenedSession, PendingSession,
    PreparedPrompt, SessionFacts, SessionOpener,
};
use crate::acp::{Message, RpcError, ACP_PROTOCOL_VERSION};

const SESSION: &str = "00000000-0000-4000-8000-0000000000a1";
const OTHER_SESSION: &str = "00000000-0000-4000-8000-0000000000b2";
const SEAT: &str = "seat.atlas";
const PROJECT: &str = "odin";
const OTHER_PROJECT: &str = "dotfiles";
const SLICE: &str = "slice.session";
const PROVIDER: &str = "omp";
const MODEL: &str = "glm-5.3";
const NODE: &str = "node.controller";
const TS: time::OffsetDateTime = time::OffsetDateTime::UNIX_EPOCH;
const DIGEST: &str = "blake3:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

type Push = Option<ServerFrame>;

struct DaemonState {
    received: Mutex<Vec<ClientFrame>>,
    /// Refuse the next command with this typed, pre-journal rejection.
    reject_next: Mutex<Option<live::CommandRejection>>,
    /// Answer the next command with this durable prior outcome.
    duplicate_outcome: Mutex<Option<live::CommandOutcome>>,
    /// Withhold the next command's receipt entirely: its fate stays unknown.
    stall_next_command: AtomicBool,
    drop_next_command: AtomicBool,
    drop_stream_after_replay: AtomicBool,
    /// Break the connection on the next Subscribe, before any answer.
    drop_next_subscribe: AtomicBool,
    /// Connections closed on arrival, as while the daemon restarts.
    refuse_connections: AtomicUsize,
    replay: Mutex<Vec<Value>>,
    pending: Mutex<VecDeque<Push>>,
    subscribes: Mutex<Vec<u64>>,
    session_epoch: Arc<AtomicU64>,
}

type Ctx = Arc<DaemonState>;

impl DaemonState {
    fn record(&self, frame: ClientFrame) {
        self.received.lock().push(frame);
    }
}

enum Reaction {
    Frames(Vec<ServerFrame>),
    FramesThenDrop(Vec<ServerFrame>),
    Drop,
    Nothing,
}

fn fixture_session() -> live::LiveSessionId {
    live::LiveSessionId::parse(SESSION).expect("fixture session id")
}

fn fixture_request_id() -> live::RequestId {
    live::RequestId::parse("00000000-0000-4000-8000-0000000000f0").expect("fixture request id")
}

fn handler(ctx: &Ctx, frame: &ClientFrame) -> Reaction {
    match frame {
        ClientFrame::General(live::HuginnRequest::SessionCommand(command)) => {
            if ctx.stall_next_command.swap(false, Ordering::SeqCst) {
                // The receipt never returns: the command's fate is unknown.
                return Reaction::Nothing;
            }
            if ctx.drop_next_command.swap(false, Ordering::SeqCst) {
                return Reaction::Drop;
            }
            let receipt = if let Some(reason) = ctx.reject_next.lock().take() {
                live::CommandReceipt::Rejected {
                    command_id: command.command_id.clone(),
                    reason,
                }
            } else if let Some(outcome) = ctx.duplicate_outcome.lock().take() {
                live::CommandReceipt::Duplicate {
                    command_id: command.command_id.clone(),
                    prior_outcome: Some(Box::new(outcome)),
                }
            } else {
                live::CommandReceipt::Accepted {
                    command_id: command.command_id.clone(),
                }
            };
            Reaction::Frames(vec![ServerFrame::General(live::HuginnMessage::Response {
                request_id: fixture_request_id(),
                result: live::HuginnResponse::Command(receipt),
            })])
        }
        ClientFrame::Live(live::LiveClientRequest::Subscribe {
            request_id,
            subscriptions,
        }) => {
            if ctx.drop_next_subscribe.swap(false, Ordering::SeqCst) {
                return Reaction::Drop;
            }
            let after = subscriptions
                .first()
                .map(|subscription| subscription.event_after.get())
                .unwrap_or(0);
            ctx.subscribes.lock().push(after);
            let session_id = subscriptions
                .first()
                .map(|subscription| subscription.session_id)
                .unwrap_or_else(fixture_session);
            let replay = ctx.replay.lock().clone();
            let head = live::EventSeq::new(replay.len() as u64);
            let mut frames = vec![
                ServerFrame::Live(live::LiveServerMessage::Response {
                    request_id: *request_id,
                    result: live::LiveResponse::Subscribed,
                }),
                ServerFrame::Live(live::LiveServerMessage::ReplayBegin {
                    session_id,
                    requested_after: live::EventSeq::new(after),
                    head,
                }),
            ];
            let epoch = 1; // These retained fixture events predate any reclaim.
            for (index, body) in replay.iter().enumerate() {
                frames.push(event_frame(
                    &session_id.to_string(),
                    (index + 1) as u64,
                    epoch,
                    body.clone(),
                ));
            }
            frames.push(ServerFrame::Live(live::LiveServerMessage::ReplayComplete {
                session_id,
                head,
            }));
            if ctx.drop_stream_after_replay.swap(false, Ordering::SeqCst) {
                Reaction::FramesThenDrop(frames)
            } else {
                Reaction::Frames(frames)
            }
        }
        ClientFrame::Live(live::LiveClientRequest::ListSessions { request_id, .. }) => {
            let epoch = ctx.session_epoch.load(Ordering::SeqCst);
            let value = json!({
                "channel": "live",
                "value": { "kind": "response", "value": {
                    "requestId": request_id.to_string(),
                    "result": { "kind": "sessions", "value": {
                        "sessions": [summary_json(epoch)],
                        "nextCursor": Value::Null,
                    } }
                }}
            });
            let frame: ServerFrame = serde_json::from_value(value).expect("sessions frame");
            Reaction::Frames(vec![frame])
        }
        ClientFrame::Live(live::LiveClientRequest::Unsubscribe { request_id, .. }) => {
            Reaction::Frames(vec![ServerFrame::Live(live::LiveServerMessage::Response {
                request_id: *request_id,
                result: live::LiveResponse::Subscribed,
            })])
        }
        _ => Reaction::Nothing,
    }
}

async fn serve(ctx: Ctx, mut end: MemoryServerEnd) {
    let limits = CodecLimits::default();
    // Only the subscription connection drains pushed frames, so a command
    // connection can never swallow a live event.
    let stream = Arc::new(AtomicBool::new(false));
    loop {
        let stream_for_push = stream.clone();
        let ctx_for_push = ctx.clone();
        let push = async move {
            if !stream_for_push.load(Ordering::SeqCst) {
                std::future::pending::<()>().await;
            }
            loop {
                let item = ctx_for_push.pending.lock().pop_front();
                if let Some(item) = item {
                    return Some(item);
                }
                tokio::time::sleep(Duration::from_millis(2)).await;
            }
        };
        tokio::select! {
            biased;
            item = push => match item {
                Some(Some(frame)) => {
                    let Ok(bytes) = encode_frame(&frame, &limits) else { break };
                    if end.send_frame(bytes).await.is_err() {
                        break;
                    }
                }
                Some(None) => {
                    let _ = end.close().await;
                    break;
                }
                None => {}
            },
            incoming = end.next_frame() => {
                let Ok(Some(bytes)) = incoming else { break };
                let Ok(decoded) = decode_frame::<ClientFrame>(&bytes, &limits) else { break };
                ctx.record(decoded.value.clone());
                if matches!(
                    decoded.value,
                    ClientFrame::Live(live::LiveClientRequest::Subscribe { .. })
                ) {
                    stream.store(true, Ordering::SeqCst);
                }
                match handler(&ctx, &decoded.value) {
                    Reaction::Frames(frames) => {
                        for frame in frames {
                            let Ok(bytes) = encode_frame(&frame, &limits) else { break };
                            if end.send_frame(bytes).await.is_err() {
                                break;
                            }
                        }
                    }
                    Reaction::FramesThenDrop(frames) => {
                        for frame in frames {
                            if let Ok(bytes) = encode_frame(&frame, &limits) {
                                let _ = end.send_frame(bytes).await;
                            }
                        }
                        break;
                    }
                    Reaction::Drop => break,
                    Reaction::Nothing => {}
                }
            }
        }
    }
}

async fn daemon(mut hub: odin_huginn::client::MemoryServerHub, ctx: Ctx) {
    while let Some(end) = hub.accept().await {
        let refused = ctx
            .refuse_connections
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |left| {
                left.checked_sub(1)
            })
            .is_ok();
        if refused {
            continue;
        }
        tokio::spawn(serve(ctx.clone(), end));
    }
}

fn project_root(tag: &str) -> PathBuf {
    let dir =
        std::env::temp_dir().join(format!("odin-acp-regression-{tag}-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("project root directory");
    dir
}

fn facts_for(root: PathBuf, session: live::LiveSessionId) -> SessionFacts {
    SessionFacts {
        live_session: session,
        seat: SEAT.to_owned(),
        project: PROJECT.to_owned(),
        provider: live::ProviderName::parse(PROVIDER).expect("provider"),
        model: live::ModelName::parse(MODEL).expect("model"),
        project_root: root,
    }
}

fn summary_json(epoch: u64) -> Value {
    json!({
        "sessionId": SESSION,
        "epoch": epoch,
        "seatId": SEAT,
        "provider": PROVIDER,
        "model": MODEL,
        "title": Value::Null,
        "state": "idle",
        "startedAt": TS,
        "updatedAt": TS,
        "eventHead": 0,
        "terminalHead": 0,
        "pendingPermissionCount": 0,
    })
}

fn event_frame(session: &str, sequence: u64, epoch: u64, body: Value) -> ServerFrame {
    serde_json::from_value(json!({
        "channel": "live",
        "value": { "kind": "event", "value": {
            "schemaVersion": 1,
            "eventId": format!("event:s{sequence}"),
            "sessionId": session,
            "epoch": epoch,
            "sequence": sequence,
            "occurredAt": TS,
            "body": body,
        }}
    }))
    .expect("event frame")
}

fn state_body(previous: &str, current: &str) -> Value {
    json!({
        "kind": "sessionStateChanged",
        "payload": { "previous": previous, "current": current, "reason": Value::Null }
    })
}

fn opened_body(session: &str, project: &str) -> Value {
    json!({
        "kind": "sessionOpened",
        "payload": { "manifest": {
            "sessionId": session,
            "seatId": SEAT,
            "sliceId": SLICE,
            "projectId": project,
            "provider": PROVIDER,
            "model": MODEL,
            "title": Value::Null,
            "targetNode": NODE,
            "openTab": false,
        }}
    })
}

fn permission_body(request: &str, tool: &str) -> Value {
    json!({
        "kind": "permissionRequested",
        "payload": {
            "requestId": request,
            "toolUseId": tool,
            "capabilityId": "seat.shell",
            "argumentsDigest": DIGEST,
            "prompt": "run the declared shell tool?",
            "expiresAt": time::OffsetDateTime::now_utc() + time::Duration::hours(1),
        }
    })
}

fn failed_tool_body() -> Value {
    json!({
        "kind": "toolFinished",
        "payload": { "turnId": "turn:1", "result": {
            "toolUseId": "tool-7",
            "content": [{ "kind": "text", "value": "kernel r3 rejected the operation" }],
            "isError": true
        }}
    })
}

fn control_completed_failed(command_id: &CommandId) -> Value {
    json!({
        "kind": "controlCompleted",
        "payload": {
            "status": "failed",
            "commandId": command_id.to_string(),
            "error": {
                "code": "control_failed",
                "message": "the bridge refused the prompt",
                "retryable": false,
            }
        }
    })
}

fn control_completed_decision_failed(command_id: &CommandId) -> Value {
    json!({
        "kind": "controlCompleted",
        "payload": {
            "status": "failed",
            "commandId": command_id.to_string(),
            "error": {
                "code": "control_failed",
                "message": "the ledger refused the decision",
                "retryable": false,
            }
        }
    })
}

fn control_completed_applied(command_id: &CommandId) -> Value {
    json!({
        "kind": "controlCompleted",
        "payload": {
            "status": "applied",
            "commandId": command_id.to_string(),
        }
    })
}
fn resolved_body(request: &str) -> Value {
    json!({
        "kind": "permissionResolved",
        "payload": {
            "requestId": request,
            "commandId": "command:resolved",
            "decision": "allowOnce",
        }
    })
}

fn delta_body(text: &str) -> Value {
    json!({
        "kind": "assistantDelta",
        "payload": { "turnId": "turn:1", "text": text }
    })
}

fn message_body(text: &str) -> Value {
    json!({
        "kind": "assistantMessage",
        "payload": { "content": [{ "kind": "text", "value": text }] }
    })
}

struct ScriptedGate {
    calls: Arc<AtomicUsize>,
    session: live::LiveSessionId,
    fail: Arc<AtomicBool>,
}

impl FirstPromptGate for ScriptedGate {
    fn prepare<'a>(
        &'a mut self,
        _prompt: &'a str,
        epoch: live::SessionEpoch,
    ) -> BoxFuture<'a, Result<PreparedPrompt, String>> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if self.fail.load(Ordering::SeqCst) {
            return Box::pin(async { Err("no durable bridge run".to_owned()) });
        }
        let command = live::LiveCommand {
            command_id: CommandId::new("command:first-prompt").expect("command id"),
            session_id: self.session,
            expected_epoch: epoch,
            expected_event_head: None,
            body: live::LiveCommandBody::Prompt {
                message: live::LiveMessage::new(vec![live::LiveContentBlock::Text(
                    "first".to_owned(),
                )])
                .expect("message"),
            },
        };
        let receipt = OperatorPlanReceipt {
            run: "run:acp-fixture".to_owned(),
            revision: 1,
            fingerprint: "fingerprint-acp".to_owned(),
            actor: "device:00000000-0000-4000-8000-0000000000d1".to_owned(),
            label: "fixture".to_owned(),
            prompt_command_id: "command:first-prompt".to_owned(),
        };
        Box::pin(async move { Ok(PreparedPrompt { command, receipt }) })
    }
}

struct ScriptedOpener {
    root: PathBuf,
    session: live::LiveSessionId,
    epoch: Arc<AtomicU64>,
    gate_calls: Arc<AtomicUsize>,
    gate_fail: Arc<AtomicBool>,
    gate_accepted: bool,
}

impl ScriptedOpener {
    fn pending(&self, session: live::LiveSessionId) -> PendingSession {
        let root = self.root.clone();
        let epoch = live::SessionEpoch::new(self.epoch.load(Ordering::SeqCst));
        let calls = self.gate_calls.clone();
        let fail = self.gate_fail.clone();
        let gate_accepted = self.gate_accepted;
        PendingSession::new(root.clone(), move || {
            let gate = ScriptedGate {
                calls: calls.clone(),
                session,
                fail: fail.clone(),
            };
            let opened = OpenedSession {
                facts: facts_for(root, session),
                gate: Box::new(gate),
                epoch,
                state: live::LiveSessionState::Idle,
                gate_accepted,
            };
            Box::pin(async move { Ok(opened) }) as BoxFuture<'static, Result<OpenedSession, String>>
        })
    }
}

impl SessionOpener for ScriptedOpener {
    fn prepare_new(&self) -> BoxFuture<'static, Result<PendingSession, String>> {
        let pending = self.pending(self.session);
        Box::pin(async move { Ok(pending) })
    }

    fn prepare_load(
        &self,
        live_session: live::LiveSessionId,
    ) -> BoxFuture<'static, Result<PendingSession, String>> {
        if live_session != self.session {
            return Box::pin(async {
                Err(
                    "session is not live on the controller; load requires an existing live \
                     session"
                        .to_owned(),
                )
            });
        }
        let pending = self.pending(live_session);
        Box::pin(async move { Ok(pending) })
    }
}

struct Rig {
    ctx: Ctx,
    root: PathBuf,
    /// The live session identity as the frontend reported it.
    session: String,
    feeder: tokio::io::DuplexStream,
    outbound: mpsc::Receiver<Message>,
    gate_calls: Arc<AtomicUsize>,
    gate_fail: Arc<AtomicBool>,
    approvals: Arc<Mutex<Vec<KernelApprovalView>>>,
}

async fn make_raw_rig_capacity(
    tag: &str,
    replay: Vec<Value>,
    approvals: Vec<KernelApprovalView>,
    capacity: usize,
    gate_accepted: bool,
) -> Rig {
    let root = project_root(tag);
    let (transport, hub) = memory_transport(64);
    let ctx = Arc::new(DaemonState {
        received: Mutex::new(Vec::new()),
        reject_next: Mutex::new(None),
        duplicate_outcome: Mutex::new(None),
        stall_next_command: AtomicBool::new(false),
        drop_next_command: AtomicBool::new(false),
        drop_stream_after_replay: AtomicBool::new(false),
        drop_next_subscribe: AtomicBool::new(false),
        refuse_connections: AtomicUsize::new(0),
        replay: Mutex::new(replay),
        pending: Mutex::new(VecDeque::new()),
        subscribes: Mutex::new(Vec::new()),
        session_epoch: Arc::new(AtomicU64::new(1)),
    });
    tokio::spawn(daemon(hub, ctx.clone()));
    let credential = DeviceCredential::new(vec![1_u8; 48]).expect("credential");
    let store = MemoryCredentialStore::new(credential);
    let client = Arc::new(ColinRemoteClient::with_limits(
        transport,
        store,
        CodecLimits::default(),
    ));
    let (plane, plane_events) = crate::backend::spawn_plane(client.clone());
    let (outbound, receiver) = mpsc::channel(capacity);
    let (frontend_input, feeder) = tokio::io::duplex(65_536);
    let gate_calls = Arc::new(AtomicUsize::new(0));
    let gate_fail = Arc::new(AtomicBool::new(false));
    let opener = ScriptedOpener {
        root: root.clone(),
        session: fixture_session(),
        epoch: Arc::clone(&ctx.session_epoch),
        gate_calls: gate_calls.clone(),
        gate_fail: gate_fail.clone(),
        gate_accepted,
    };
    let approvals = Arc::new(Mutex::new(approvals));
    let reader_rows = Arc::clone(&approvals);
    let reader: ApprovalsReader = Arc::new(move |_| Ok(reader_rows.lock().clone()));
    let frontend = Frontend::new(
        client,
        Arc::new(opener),
        reader,
        plane,
        plane_events,
        outbound,
    );
    tokio::spawn(frontend.run(frontend_input));
    Rig {
        ctx,
        root,
        session: SESSION.to_owned(),
        feeder,
        outbound: receiver,
        gate_calls,
        gate_fail,
        approvals,
    }
}

async fn make_raw_rig(tag: &str, replay: Vec<Value>, approvals: Vec<KernelApprovalView>) -> Rig {
    make_raw_rig_capacity(tag, replay, approvals, 128, false).await
}

/// A fully initialized rig: the real protocol setup runs before any
/// lifecycle method can.
async fn make_rig(tag: &str, replay: Vec<Value>, approvals: Vec<KernelApprovalView>) -> Rig {
    let mut rig = make_raw_rig(tag, replay, approvals).await;
    send_message(
        Message::request(
            json!(0),
            "initialize",
            json!({ "protocolVersion": ACP_PROTOCOL_VERSION, "clientCapabilities": {} }),
        ),
        &mut rig,
    )
    .await;
    let response = next_message(&mut rig).await;
    assert_eq!(response.id, Some(json!(0)));
    assert!(response.error.is_none(), "initialize failed");
    rig
}

async fn send_message(message: Message, rig: &mut Rig) {
    use tokio::io::AsyncWriteExt as _;
    let mut line = serde_json::to_string(&message).expect("message serializes");
    line.push('\n');
    rig.feeder.write_all(line.as_bytes()).await.expect("write");
    rig.feeder.flush().await.expect("flush");
}

async fn next_message(rig: &mut Rig) -> Message {
    tokio::time::timeout(Duration::from_secs(5), rig.outbound.recv())
        .await
        .expect("timed out waiting for an ACP message")
        .expect("outbound channel closed")
}

async fn expect_silence(rig: &mut Rig) {
    let surprise = tokio::time::timeout(Duration::from_millis(150), rig.outbound.recv()).await;
    assert!(
        surprise.is_err(),
        "unexpected outbound message: {surprise:?}"
    );
}

async fn commands(ctx: &Ctx, count: usize) -> Vec<live::LiveCommand> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        let found: Vec<live::LiveCommand> = ctx
            .received
            .lock()
            .iter()
            .filter_map(|frame| match frame {
                ClientFrame::General(live::HuginnRequest::SessionCommand(command)) => {
                    Some(command.clone())
                }
                _ => None,
            })
            .collect();
        if found.len() >= count {
            return found;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "timed out waiting for {count} session commands"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

fn push_event(rig: &Rig, sequence: u64, body: Value) {
    let epoch = rig.ctx.session_epoch.load(Ordering::SeqCst);
    let frame = event_frame(&rig.session, sequence, epoch, body);
    rig.ctx.pending.lock().push_back(Some(frame));
}
fn push_live(rig: &Rig, message: live::LiveServerMessage) {
    rig.ctx
        .pending
        .lock()
        .push_back(Some(ServerFrame::Live(message)));
}

/// Opens a new session through the real protocol and derives the session
/// identity from the actual `session/new` response.
async fn open_session(rig: &mut Rig) {
    // A new session proves its own durable manifest, so the fixture
    // journals the SessionOpened event before the subscription replays.
    rig.ctx
        .replay
        .lock()
        .push(opened_body(&rig.session, PROJECT));
    send_message(
        Message::request(
            json!(1),
            "session/new",
            json!({ "cwd": rig.root.display().to_string(), "mcpServers": [] }),
        ),
        rig,
    )
    .await;
    let response = next_message(rig).await;
    assert_eq!(response.id, Some(json!(1)));
    assert!(response.error.is_none(), "session/new failed");
    let session = response.result.expect("session/new result")["sessionId"]
        .as_str()
        .expect("sessionId")
        .to_owned();
    live::LiveSessionId::parse(&session).expect("a governed session identity");
    rig.session = session;
}

/// Drives one first prompt through the gate to a completed turn.
async fn complete_first_turn(rig: &mut Rig, sequence: &mut u64) {
    send_message(
        Message::request(
            json!(2),
            "session/prompt",
            json!({ "sessionId": rig.session, "prompt": [{ "type": "text", "text": "hello" }] }),
        ),
        rig,
    )
    .await;
    let _ = commands(&rig.ctx, 1).await;
    *sequence += 1;
    push_event(rig, *sequence, state_body("idle", "running"));
    *sequence += 1;
    push_event(rig, *sequence, state_body("running", "idle"));
    let response = next_message(rig).await;
    assert_eq!(response.id, Some(json!(2)));
    assert_eq!(
        response.result.as_ref().expect("result")["stopReason"],
        "end_turn"
    );
}

mod permissions;
mod sessions;
mod turns;

#[test]
fn tool_denial_completion_does_not_complete_a_prompt_turn() {
    let outcome: live::CommandOutcome = serde_json::from_value(json!({
        "status": "toolDenied",
        "commandId": "probe:pod:create:1",
        "receipt": {
            "requestId": "probe:pod:create:1",
            "toolName": "kube_workload_create",
            "denial": {"kind": "unknownTool"},
            "error": "host admission refused"
        }
    }))
    .unwrap();
    assert!(super::turn_outcome_for(&outcome).is_none());
}
