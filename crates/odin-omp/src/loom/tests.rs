use std::collections::VecDeque;
use std::sync::Arc;

use odin_domain::huginn::{LiveContentBlock, LiveEventBody, LiveMessage, LiveSessionState};
use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::broadcast;

use super::journal::{Call, Entry};
use super::render::{self, Durable, Estimator, Exchange};
use super::*;
use crate::host_tools::lane_status::LaneStatusTool;
use crate::live::control::LiveControlBackend;
use crate::live::rollover::{RolloverChildState, RolloverPendingApproval};
use crate::probe::{
    CaseContext, ConformanceCaseId, FaultFixtureRuntime, OmpLaunchTemplate, ProbeConfig,
};

// ---- the scripted gateway -------------------------------------------------

enum Script {
    Events(Vec<Value>),
    /// Answers nothing while the connection lives.
    Hold,
    /// Refuses with this HTTP status.
    Status(u16),
}

/// A reply with no usage report, so the request estimate stays bytes / 4.
fn plain(text: &str) -> Script {
    Script::Events(vec![
        json!({"choices": [{"index": 0, "delta": {"role": "assistant", "content": text}, "finish_reason": "stop"}]}),
    ])
}

fn usage() -> Value {
    json!({"choices": [], "usage": {"prompt_tokens": 40, "completion_tokens": 2,
        "prompt_tokens_details": {"cached_tokens": 30}}})
}

fn says(text: &str) -> Script {
    Script::Events(vec![
        json!({"model": "served", "choices": [{"index": 0, "delta": {"role": "assistant", "content": text}}]}),
        json!({"choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}]}),
        usage(),
    ])
}

fn calls(id: &str, arguments: &Value) -> Script {
    Script::Events(vec![
        json!({"choices": [{"index": 0, "delta": {"tool_calls": [{"index": 0, "id": id,
            "function": {"name": LaneStatusTool::NAME, "arguments": ""},
            "provider_specific_fields": {"thought_signature": "sig"}}]}}]}),
        json!({"choices": [{"index": 0, "delta": {"tool_calls": [{"index": 0,
            "function": {"arguments": arguments.to_string()}}]}, "finish_reason": "tool_calls"}]}),
        usage(),
    ])
}

/// Every request the gateway received: its header block and body.
#[derive(Clone, Default)]
struct Seen(Arc<std::sync::Mutex<Vec<(String, Value)>>>);

impl Seen {
    fn bodies(&self) -> Vec<Value> {
        self.0
            .lock()
            .unwrap()
            .iter()
            .map(|(_, body)| body.clone())
            .collect()
    }
}

async fn gateway(script: Vec<Script>) -> (Gateway, Seen) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let seen = Seen::default();
    let record = seen.clone();
    let mut script = VecDeque::from(script);
    tokio::spawn(async move {
        loop {
            let Ok((mut socket, _)) = listener.accept().await else {
                return;
            };
            let mut buffer = Vec::new();
            let (head, length) = loop {
                let mut chunk = [0u8; 4096];
                let read = socket.read(&mut chunk).await.unwrap();
                buffer.extend_from_slice(&chunk[..read]);
                if let Some(end) = buffer.windows(4).position(|window| window == b"\r\n\r\n") {
                    let head = String::from_utf8_lossy(&buffer[..end]).to_lowercase();
                    let length = head
                        .lines()
                        .find_map(|line| line.strip_prefix("content-length:"))
                        .map(|value| value.trim().parse::<usize>().unwrap())
                        .unwrap_or(0);
                    buffer.drain(..end + 4);
                    break (head, length);
                }
            };
            while buffer.len() < length {
                let mut chunk = [0u8; 65536];
                let read = socket.read(&mut chunk).await.unwrap();
                buffer.extend_from_slice(&chunk[..read]);
            }
            let body = serde_json::from_slice(&buffer[..length]).unwrap();
            record.0.lock().unwrap().push((head, body));
            match script.pop_front().unwrap_or_else(|| says("done")) {
                Script::Status(code) => {
                    let body = r#"{"error":{"message":"refused by the fixture"}}"#;
                    let out = format!(
                        "HTTP/1.1 {code} Refused\r\ncontent-type: application/json\r\n\
                         content-length: {}\r\nconnection: close\r\n\r\n{body}",
                        body.len()
                    );
                    let _ = socket.write_all(out.as_bytes()).await;
                    let _ = socket.shutdown().await;
                }
                Script::Hold => {
                    tokio::spawn(async move {
                        let _held = socket;
                        std::future::pending::<()>().await;
                    });
                }
                Script::Events(events) => {
                    let mut out = String::from(
                        "HTTP/1.1 200 OK\r\ncontent-type: text/event-stream\r\nconnection: close\r\n\r\n",
                    );
                    for event in events {
                        out.push_str(&format!("data: {event}\n\n"));
                    }
                    out.push_str("data: [DONE]\n\n");
                    let _ = socket.write_all(out.as_bytes()).await;
                    let _ = socket.shutdown().await;
                }
            }
        }
    });
    (
        Gateway {
            url,
            key: "test-key".to_owned(),
        },
        seen,
    )
}

// ---- a session over the probe's real operation surface ---------------------

struct Hooks;

#[async_trait]
impl LiveControlHooks for Hooks {
    async fn pause(&self) -> Result<(), LiveError> {
        Ok(())
    }
    async fn resume(&self) -> Result<(), LiveError> {
        Ok(())
    }
    async fn rehome(&self, _target_node: &odin_domain::NodeId) -> Result<(), LiveError> {
        Ok(())
    }
    async fn decide_approval(
        &self,
        _approval_id: &odin_domain::ApprovalId,
        _expected_revision: u64,
        _decision: odin_domain::huginn::ApprovalDecision,
    ) -> Result<(), LiveError> {
        Ok(())
    }
}

struct Children;

#[async_trait]
impl RolloverChildrenSource for Children {
    async fn children(
        &self,
        _parent: &odin_domain::SessionId,
        _cap: usize,
    ) -> Result<Vec<RolloverChildState>, String> {
        Ok(vec![child()])
    }
    async fn assignment(
        &self,
        _session: &odin_domain::SessionId,
    ) -> Result<Option<String>, String> {
        Ok(None)
    }
}

fn child() -> RolloverChildState {
    RolloverChildState {
        child_session: "child-session-7".to_owned(),
        phase: "running".to_owned(),
        project: "odin".to_owned(),
        provider: "gateway".to_owned(),
        model: "terra".to_owned(),
        depth: 1,
        prompt_digest: "d".to_owned(),
        created_at_ms: 0,
        epoch: None,
        event_head: None,
    }
}

struct Source {
    context: CaseContext,
    gated: bool,
}

#[async_trait]
impl LoomSource for Source {
    async fn loom_parts(
        &self,
        _manifest: &SessionManifest,
        _epoch: SessionEpoch,
    ) -> Result<LoomParts, LiveError> {
        let descriptor = self.context.session_descriptor();
        let config = self
            .context
            .bridge_config_gated(descriptor.clone(), self.gated)
            .unwrap();
        let mut bridge = config.binding;
        {
            let mut ledger = config.ledger.lock().unwrap();
            let row = odin_ledger::live::NewLiveSession {
                session_id: bridge.session_id.clone(),
                seat_id: self.context.ids().seat.to_string(),
                project_id: self.context.ids().project.to_string(),
                slice_id: descriptor.slice_id,
                lane_id: bridge.lane_id.to_string(),
                target_node_id: descriptor.target_node_id,
                provider: descriptor.provider,
                model: descriptor.model,
                title: None,
                manifest: descriptor.manifest,
                open_tab: false,
                state: "ready".to_owned(),
                created_at: time::OffsetDateTime::now_utc(),
            };
            bridge.epoch = match ledger.live_session(&bridge.session_id) {
                Ok(existing) => existing.epoch,
                Err(_) => ledger.create_live_session_at(&row, 1).unwrap().epoch,
            };
        }
        Ok(LoomParts {
            operations: config.operations,
            binding: config.operation_binding,
            admitted: config.admitted_host_tools,
            bridge,
            ledger: config.ledger,
            uri_router: config.uri_router,
            artifact_root: config.artifact_root,
            context_trace_root: None,
            system: "You are a test seat.".to_owned(),
            brain: None,
            images: None,
            children: Arc::new(Children),
            hooks: Arc::new(Hooks),
            terminal: None,
        })
    }
}

struct NoInner;

#[async_trait]
impl LiveSessionLauncher for NoInner {
    async fn open(
        &self,
        _: &SessionManifest,
        _: SessionEpoch,
        _: bool,
    ) -> Result<SessionRuntime, LiveError> {
        panic!("a loom seat's own session never reaches the inner launcher")
    }
    fn harness_turns(&self) -> Option<Arc<crate::live::harness::HarnessTurns>> {
        None
    }
}

fn case(root: &std::path::Path) -> CaseContext {
    use std::os::unix::fs::PermissionsExt;
    let executable = root.join("omp");
    std::fs::write(&executable, "#!/bin/sh\nexit 0\n").unwrap();
    std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o755)).unwrap();
    let atlas_root = root.join("atlas");
    for directory in ["crates", "extension", "registry", "skeletons"] {
        std::fs::create_dir_all(atlas_root.join(directory)).unwrap();
    }
    let atlas = Arc::new(odin_atlas::build(odin_atlas::AtlasSources::new(&atlas_root)).unwrap());
    let worker = crate::process::launch_for_fixture(&executable);
    let config = Arc::new(ProbeConfig::new(
        OmpLaunchTemplate {
            executable: executable.clone(),
            explicit_args: Vec::new(),
            explicit_env: Vec::new(),
            expected_source_revision: crate::probe::PINNED_OMP_SOURCE_REVISION.to_owned(),
            startup_timeout: Duration::from_secs(10),
            drain_timeout: Duration::from_secs(10),
            kill_timeout: Duration::from_secs(10),
            worker: worker.clone(),
        },
        FaultFixtureRuntime {
            bun: executable,
            explicit_env: Vec::new(),
            worker,
        },
        root.join("work"),
        atlas,
    ));
    let context = CaseContext::for_case(&config, ConformanceCaseId::new(1), "loom").unwrap();
    crate::probe::cases::subagents_tools::host_tool::seed_bound_lane(&context).unwrap();
    context
}

fn manifest() -> SessionManifest {
    serde_json::from_value(json!({
        "sessionId": "4f6c2a10-0000-4000-8000-0000000000aa",
        "seatId": "kubert",
        "sliceId": "odin-probe",
        "projectId": "odin",
        "provider": "gateway",
        "model": "terra",
        "targetNode": "mini",
        "title": null,
        "openTab": false,
    }))
    .unwrap()
}

struct Fixture {
    _root: tempfile::TempDir,
    launcher: LoomLauncher,
    seen: Seen,
}

/// A loom seat over the probe's real operation surface (its one tool,
/// gated when asked) and a gateway answering `script(lane)` in order.
async fn fixture(
    script: impl FnOnce(&Value) -> Vec<Script>,
    config: SeatLoomToml,
    gated: bool,
) -> Fixture {
    let root = tempfile::tempdir().unwrap();
    let context = case(root.path());
    let arguments = json!({"laneId": context.ids().lane.to_string()});
    let (gateway, seen) = gateway(script(&arguments)).await;
    let launcher = LoomLauncher::new(
        Arc::new(NoInner),
        Arc::new(Source { context, gated }),
        BTreeMap::from([(SeatId::new("kubert").unwrap(), config)]),
        Ok(gateway),
        BTreeMap::new(),
        root.path().join("loom"),
    );
    Fixture {
        _root: root,
        launcher,
        seen,
    }
}

type Frames = broadcast::Receiver<crate::bridge::ObservedFrame>;

async fn open(fixture: &Fixture) -> (Arc<dyn LiveControlBackend>, Frames) {
    let runtime = fixture
        .launcher
        .open(&manifest(), SessionEpoch::new(1), false)
        .await
        .unwrap();
    (runtime.control, runtime.observations.unwrap())
}

fn message(text: &str) -> LiveMessage {
    LiveMessage::new(vec![LiveContentBlock::Text(text.to_owned())]).unwrap()
}

/// What the journal records for these frames of a running session.
fn normalized(before: &[Value], turn: &[Value]) -> Vec<LiveEventBody> {
    let root = tempfile::tempdir().unwrap();
    let normalizer = crate::live::normalize::EventNormalizer::new(
        manifest().session_id,
        SessionEpoch::new(1),
        LiveSessionState::Running,
        Arc::new(crate::live::ledger::fs::FsLiveLedger::open(root.path()).unwrap()),
    );
    before
        .iter()
        .chain(turn)
        .flat_map(|frame| {
            normalizer
                .normalize_omp(&crate::bridge::ObservedFrame::harness_event(frame.clone()))
                .unwrap()
        })
        .collect()
}

/// Every frame up to and including the turn's `agent_end`.
async fn until_end(frames: &mut Frames) -> Vec<Value> {
    let mut seen = Vec::new();
    loop {
        let frame = frames.recv().await.unwrap();
        let value = frame.value().unwrap().clone();
        let end = value["type"] == "agent_end";
        seen.push(value);
        if end {
            return seen;
        }
    }
}

async fn owner_turn(
    control: &Arc<dyn LiveControlBackend>,
    frames: &mut Frames,
    text: &str,
) -> Vec<Value> {
    control.prompt(&message(text), Some(text)).await.unwrap();
    until_end(frames).await
}

fn last_message_text(body: &Value) -> String {
    let message = body["messages"].as_array().unwrap().last().unwrap();
    message["content"].as_str().unwrap_or_default().to_owned()
}

/// Every call in a request is followed directly by exactly its results.
fn calls_meet_results(messages: &[Value]) {
    for (index, message) in messages.iter().enumerate() {
        for (offset, call) in message["tool_calls"]
            .as_array()
            .into_iter()
            .flatten()
            .enumerate()
        {
            let result = &messages[index + 1 + offset];
            assert_eq!(result["role"], "tool", "{messages:?}");
            assert_eq!(result["tool_call_id"], call["id"], "{messages:?}");
        }
    }
}

fn tool_text(body: &Value) -> String {
    body["messages"]
        .as_array()
        .unwrap()
        .iter()
        .find(|message| message["role"] == "tool")
        .unwrap()["content"]
        .as_str()
        .unwrap()
        .to_owned()
}

// ---- end to end -------------------------------------------------------------

#[tokio::test]
async fn an_owner_turn_calls_a_tool_answers_and_later_sees_a_digest() {
    // A result over the configured digest size is a digest in later turns.
    let config = SeatLoomToml {
        digest_bytes: 16,
        ..SeatLoomToml::default()
    };
    let fixture = fixture(
        |arguments| {
            vec![
                calls("call-1", arguments),
                says("the lane is fine"),
                says("second answer"),
            ]
        },
        config,
        false,
    )
    .await;
    let (control, mut frames) = open(&fixture).await;
    let turn = owner_turn(&control, &mut frames, "how is the lane?").await;
    let end = turn
        .iter()
        .find(|frame| frame["type"] == "tool_execution_end")
        .unwrap();
    assert_eq!(end["isError"], false, "{end}");
    let last = turn.last().unwrap();
    assert_eq!(last["stopReason"], "stop");
    assert_eq!(
        last["messages"][0]["content"][0]["text"],
        "the lane is fine"
    );
    assert!(turn
        .iter()
        .any(|frame| frame["type"] == "message_end"
            && frame["message"]["usage"]["cacheRead"].is_u64()));
    owner_turn(&control, &mut frames, "and now?").await;

    let bodies = fixture.seen.bodies();
    assert_eq!(bodies.len(), 3);
    for body in &bodies {
        calls_meet_results(body["messages"].as_array().unwrap());
        assert!(!body.to_string().contains("cache_control"));
        // The prefix is byte-identical across the epoch's requests.
        assert_eq!(body["tools"].to_string(), bodies[0]["tools"].to_string());
        assert_eq!(body["messages"][0], bodies[0]["messages"][0]);
        assert_eq!(body["prompt_cache_key"], bodies[0]["prompt_cache_key"]);
    }
    // The opaque signature went back with its call.
    let replayed = bodies[1]["messages"].to_string();
    assert!(replayed.contains("thought_signature"), "{replayed}");
    // Whole in its own turn; a digest naming its artifact afterwards.
    assert!(!tool_text(&bodies[1]).contains("artifact "));
    assert!(
        tool_text(&bodies[2]).contains("artifact "),
        "{}",
        tool_text(&bodies[2])
    );
    // The new message is last, after the window.
    assert_eq!(last_message_text(&bodies[0]), "how is the lane?");
    assert_eq!(last_message_text(&bodies[2]), "and now?");
    let (head, _) = fixture.seen.0.lock().unwrap()[0].clone();
    assert!(
        head.contains("x-litellm-tags: seat:kubert,session:"),
        "{head}"
    );
    control.shutdown().await.unwrap();
}

#[tokio::test]
async fn an_approval_required_call_answers_the_model_and_rides_the_summary() {
    let fixture = fixture(
        |arguments| {
            vec![
                calls("call-1", arguments),
                says("asked the owner"),
                says("still waiting"),
            ]
        },
        SeatLoomToml::default(),
        true,
    )
    .await;
    let (control, mut frames) = open(&fixture).await;
    let turn = owner_turn(&control, &mut frames, "check the lane").await;
    let end = turn
        .iter()
        .find(|frame| frame["type"] == "tool_execution_end")
        .unwrap();
    assert_eq!(end["isError"], true, "{end}");
    owner_turn(&control, &mut frames, "anything?").await;
    let bodies = fixture.seen.bodies();
    // The pending approval is a durable row of every later request's summary.
    let summary = bodies[2]["messages"][1]["content"].as_str().unwrap();
    assert!(
        summary
            .lines()
            .any(|row| row.starts_with("- approval:") && row.ends_with(" for odin.lane_status")),
        "{summary}"
    );
    assert!(summary.contains("child-session-7"), "{summary}");
    control.shutdown().await.unwrap();
}

#[tokio::test]
async fn abort_stops_the_running_turn_and_names_why() {
    let fixture = fixture(|_| vec![Script::Hold], SeatLoomToml::default(), false).await;
    let (control, mut frames) = open(&fixture).await;
    control
        .prompt(&message("take your time"), Some("take your time"))
        .await
        .unwrap();
    let start = frames.recv().await.unwrap();
    assert_eq!(start.value().unwrap()["type"], "agent_start");
    control.abort_turn().await.unwrap();
    let turn = until_end(&mut frames).await;
    assert!(turn.last().unwrap()["errorMessage"]
        .as_str()
        .is_some_and(|why| !why.is_empty()));
    // However its frames arrive, an aborted turn never fails the session.
    let journaled = normalized(&[start.value().unwrap().clone()], &turn);
    assert!(
        !journaled.iter().any(|body| matches!(body,
            LiveEventBody::SessionStateChanged(change) if change.current == LiveSessionState::Failed)
            || matches!(body, LiveEventBody::Error(_))),
        "{journaled:?}"
    );
    control.shutdown().await.unwrap();
    assert!(control
        .prompt(&message("more"), Some("more"))
        .await
        .is_err());
}

#[tokio::test]
async fn a_reopened_session_resumes_from_its_journal_in_a_fresh_epoch() {
    let fixture = fixture(
        |_| vec![says("first answer"), says("second answer")],
        SeatLoomToml::default(),
        false,
    )
    .await;
    let (control, mut frames) = open(&fixture).await;
    owner_turn(&control, &mut frames, "first question").await;
    control.shutdown().await.unwrap();
    drop(control);
    let (control, mut frames) = open(&fixture).await;
    owner_turn(&control, &mut frames, "second question").await;
    let bodies = fixture.seen.bodies();
    let window = bodies[1]["messages"].to_string();
    assert!(
        window.contains("first question") && window.contains("first answer"),
        "{window}"
    );
    assert_ne!(bodies[0]["prompt_cache_key"], bodies[1]["prompt_cache_key"]);
    control.shutdown().await.unwrap();
}

#[tokio::test]
async fn a_render_over_the_turn_budget_is_refused_and_never_sent() {
    let config = SeatLoomToml::default();
    let budget = usize::try_from(config.turn_budget_tokens).unwrap();
    let fixture = fixture(|_| Vec::new(), config, false).await;
    let (control, mut frames) = open(&fixture).await;
    let turn = owner_turn(&control, &mut frames, &"x".repeat(budget * 8)).await;
    let last = turn.last().unwrap();
    assert_eq!(last["stopReason"], "error");
    assert!(
        last["errorMessage"]
            .as_str()
            .unwrap()
            .contains("turn_budget_tokens"),
        "{last}"
    );
    assert!(fixture.seen.bodies().is_empty());
    // The refused turn left nothing behind that refuses the next one.
    let next = owner_turn(&control, &mut frames, "short").await;
    assert_eq!(next.last().unwrap()["stopReason"], "stop");
    assert!(fixture.seen.bodies()[0].to_string().len() < budget * 4);
    control.shutdown().await.unwrap();
}

#[tokio::test]
async fn a_side_turn_adds_only_its_posted_reply_to_the_main_window() {
    let fixture = fixture(
        |arguments| {
            vec![
                says("hello back"),
                calls("side-call", arguments),
                says("the pod finished"),
                says(odin_domain::huginn::QUIET_REPLY),
                says("continuing"),
                says("noted"),
            ]
        },
        SeatLoomToml::default(),
        false,
    )
    .await;
    let (control, mut frames) = open(&fixture).await;
    owner_turn(&control, &mut frames, "hello").await;
    for wake in ["[wake] the pod reported", "[wake] nothing new"] {
        control
            .prompt_wake(&message(wake), None, false)
            .await
            .unwrap();
        until_end(&mut frames).await;
    }
    // An owner-less message that is not a wake (an approval continuation)
    // is a main turn: it sees the window.
    control
        .prompt(&message("[host] continue"), None)
        .await
        .unwrap();
    until_end(&mut frames).await;
    owner_turn(&control, &mut frames, "what happened?").await;
    let bodies = fixture.seen.bodies();
    // The side turn rendered only its own item after the summary.
    assert!(!bodies[1]["messages"].to_string().contains("hello back"));
    assert!(bodies[4]["messages"].to_string().contains("hello back"));
    let main = bodies[5]["messages"].as_array().unwrap();
    let text = serde_json::to_string(main).unwrap();
    assert!(
        text.contains("hello back") && text.contains("the pod finished"),
        "{text}"
    );
    assert!(
        !text.contains("[wake]") && !text.contains(odin_domain::huginn::QUIET_REPLY),
        "{text}"
    );
    assert!(
        main.iter().all(|message| message["role"] != "tool"),
        "{text}"
    );
    assert!(text.contains("[host] continue"), "{text}");
    control.shutdown().await.unwrap();
}

#[tokio::test]
async fn a_gateway_refusal_ends_the_turn_as_omp_reports_a_provider_error() {
    let status = 429;
    let fixture = fixture(
        |_| vec![Script::Status(status)],
        SeatLoomToml::default(),
        false,
    )
    .await;
    let (control, mut frames) = open(&fixture).await;
    let turn = owner_turn(&control, &mut frames, "anyone there?").await;
    let journaled = normalized(&[], &turn);
    assert!(
        journaled.iter().any(|body| matches!(body,
            LiveEventBody::Error(error) if error.code == "provider_turn_error"
                && error.error_status == Some(status))),
        "{journaled:?}"
    );
    control.shutdown().await.unwrap();
}

#[tokio::test]
async fn a_fold_measures_the_whole_request_prefix_included() {
    // Measure the request a first turn renders with no window behind it.
    let probe = fixture(
        |_| vec![plain("first answer")],
        SeatLoomToml::default(),
        false,
    )
    .await;
    let (control, mut frames) = open(&probe).await;
    owner_turn(&control, &mut frames, "first question").await;
    control.shutdown().await.unwrap();
    let alone = Estimator::default().tokens(probe.seen.bodies()[0].to_string().len());
    // The prefix alone nearly fills compact_at; a short window passes it.
    let config = SeatLoomToml {
        compact_at_tokens: alone,
        compact_to_tokens: 0,
        ..SeatLoomToml::default()
    };
    let fixture = fixture(
        |_| {
            vec![
                plain("first answer"),
                plain("- asked a first question"),
                plain("second answer"),
            ]
        },
        config.clone(),
        false,
    )
    .await;
    let (control, mut frames) = open(&fixture).await;
    owner_turn(&control, &mut frames, "first question").await;
    owner_turn(&control, &mut frames, "second question").await;
    let bodies = fixture.seen.bodies();
    let lane = config.summary_model.strip_prefix("gateway/").unwrap();
    assert_eq!(bodies[1]["model"], lane, "the second turn folded first");
    let folded = bodies[2]["messages"].to_string();
    assert!(folded.contains("- asked a first question"), "{folded}");
    assert!(!folded.contains("first answer"), "{folded}");
    control.shutdown().await.unwrap();
}

#[test]
fn a_torn_last_journal_line_is_dropped_and_the_session_resumes() {
    let root = tempfile::tempdir().unwrap();
    let mut journal = journal::Journal::open(root.path(), "s").unwrap();
    journal
        .append(Entry::Epoch {
            epoch: 1,
            model: "terra".to_owned(),
        })
        .unwrap();
    let path = root.path().join("s.jsonl");
    let mut file = std::fs::OpenOptions::new()
        .append(true)
        .open(&path)
        .unwrap();
    std::io::Write::write_all(&mut file, br#"{"kind":"user","turn":1,"si"#).unwrap();
    let reopened = journal::Journal::open(root.path(), "s").unwrap();
    assert_eq!(reopened.entries, journal.entries);
    let mut reopened = reopened;
    reopened.append(Entry::Truncated { upto: 0 }).unwrap();
    assert_eq!(
        journal::Journal::open(root.path(), "s")
            .unwrap()
            .entries
            .len(),
        2
    );
}

// ---- render ---------------------------------------------------------------

#[test]
fn an_interrupted_call_still_meets_a_result() {
    let call = |id: &str| Call {
        id: id.to_owned(),
        name: "t".to_owned(),
        arguments: "{}".to_owned(),
        opaque: None,
    };
    let entries = [
        Entry::User {
            turn: 1,
            side: false,
            text: "go".to_owned(),
        },
        Entry::Assistant {
            turn: 1,
            side: false,
            text: String::new(),
            reasoning: None,
            calls: vec![call("a"), call("b")],
            opaque: None,
        },
        Entry::Result {
            turn: 1,
            side: false,
            call_id: "b".to_owned(),
            tool: "t".to_owned(),
            text: "fine".to_owned(),
            digest: None,
            is_error: false,
        },
    ];
    let refs: Vec<&Entry> = entries.iter().collect();
    calls_meet_results(&render::turn_messages(&refs, true, true));
}

#[test]
fn a_fold_leaves_the_rest_within_its_target() {
    let mut seed = 0x9e37_79b9_u64;
    let mut next = move || {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        seed
    };
    for _ in 0..200 {
        let exchanges: Vec<Exchange> = (0..next() % 30)
            .map(|turn| Exchange {
                turn,
                messages: Vec::new(),
                bytes: (next() % 5_000) as usize,
            })
            .collect();
        let summary = (next() % 2_000) as usize;
        let target = next() % 40_000;
        let estimate = Estimator {
            tokens: next() % 3,
            bytes: next() % 10,
        };
        let count = render::fold_count(&exchanges, summary, estimate, target);
        let rest: usize = exchanges[count..]
            .iter()
            .map(|exchange| exchange.bytes)
            .sum();
        assert!(count == exchanges.len() || estimate.tokens(summary + rest) <= target);
    }
}

#[test]
fn the_durable_summary_always_carries_the_request_approvals_and_children() {
    let durable = Durable {
        unanswered: Some("please book the flight".to_owned()),
        plan: None,
        approvals: vec![RolloverPendingApproval {
            approval_id: "approval-42".to_owned(),
            capability_id: "travel.book".to_owned(),
            target_kind: "run".to_owned(),
            target_id: "run:live:x".to_owned(),
            issuer: "kernel".to_owned(),
            requested_at_ms: 0,
            expires_at_ms: 0,
        }],
        children: vec![child()],
        failures: (0..50)
            .map(|n| format!("turn {n}: {}", "x".repeat(200)))
            .collect(),
    };
    let config = SeatLoomToml::default();
    for max in [
        config.summary_max_bytes / 16,
        config.summary_max_bytes / 4,
        config.summary_max_bytes,
    ] {
        let summary = render::summary(&durable, "", max);
        for needle in ["please book the flight", "approval-42", "child-session-7"] {
            assert!(summary.contains(needle), "{max}: {summary}");
        }
    }
}

#[test]
fn a_fold_larger_than_its_input_is_rejected() {
    let max = SeatLoomToml::default().summary_max_bytes;
    let (notes, folded) = ("- a", "user: b");
    assert!(session::accepted_fold("- a, b", notes, folded, max));
    assert!(!session::accepted_fold(
        &"z".repeat(notes.len() + folded.len()),
        notes,
        folded,
        max
    ));
    assert!(!session::accepted_fold(
        &"z".repeat(max + 1),
        &"n".repeat(max * 2),
        folded,
        max
    ));
    assert!(!session::accepted_fold("  ", notes, folded, max));
}

#[test]
fn a_digest_stays_within_the_size_it_is_given() {
    let text: String = (0..2_000)
        .map(|n| format!("line {n}{}\n", if n == 999 { " error: boom" } else { "" }))
        .collect();
    let config = SeatLoomToml::default();
    for budget in [
        config.digest_bytes / 2,
        config.digest_bytes,
        config.digest_bytes * 4,
    ] {
        let digest = render::digest("web_read", "{\"url\":\"x\"}", &text, "artifact-1", budget);
        assert!(digest.contains("artifact-1"));
        // The header names the artifact; the rest is bounded by the size.
        let body = digest.split_once('\n').unwrap().1;
        assert!(body.len() <= budget, "{budget}: {}", body.len());
        assert!(
            body.contains("line 0") && body.contains("line 1999"),
            "{body}"
        );
    }
}
