//! `odin view`: the terminal frontend. The screen is a Bun app built from
//! OMP's own TUI files (`view/` in this repo); this command starts it, and
//! the app starts `odin view --bridge` as its data source. The bridge holds
//! one authenticated Huginn link and speaks JSON lines on stdin/stdout:
//! seats with their live sessions and the session carrying Sinmara's
//! conversation, the watched session's events, today's spend, and the owner's
//! says and model changes. The overview page adds the waiting approvals,
//! Odin's pods, the Claude Code sessions running on this device, and one
//! CI line per declared repo (the authority's cached read; with the authority unreachable the view
//! shows no new spend or CI). The bridge's stderr is the app's log.

use std::collections::BTreeMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use super::compute_sample::{compute_loop, read_commands, sample_compute};
use clap::Args;
use odin_cli::authority_provision;
use odin_domain::huginn as live;
use odin_domain::ApprovalStatus;
use odin_huginn::approvals::ApprovalView;
use odin_huginn::client::{ClientError, RemoteClient, EndpointTransport, FileCredentialStore};
use serde_json::{json, Value};

#[derive(Debug, Args)]
pub(crate) struct ViewArgs {
    /// Serve the view's data as JSON lines on stdin/stdout (the view starts this itself).
    #[arg(long, hide = true)]
    bridge: bool,
    /// Huginn endpoint (HTTPS, or loopback HTTP on the authority).
    #[arg(long, env = "ODIN_HUGINN_ENDPOINT")]
    endpoint: Option<String>,
    /// Holds `huginn/device.credential`, this host's pairing.
    #[arg(long, env = "ODIN_HUGINN_STATE_ROOT", default_value = "state")]
    state_root: PathBuf,
}

mod context;
mod features;

pub(super) type Client = RemoteClient<EndpointTransport, FileCredentialStore>;
type Connection = odin_huginn::client::LiveConnection<
    <EndpointTransport as odin_huginn::client::HuginnTransport>::Socket,
    EndpointTransport,
>;

/// How long one ordinary request may take before the link counts as lost.
const REQUEST_BOUND: Duration = Duration::from_secs(20);
/// A model change commits, pushes and publishes the registry, then switches
/// the live session.
const MODEL_BOUND: Duration = Duration::from_secs(120);
const SEATS_EVERY: Duration = Duration::from_secs(2);
/// The slow tick: the Status snapshot (incidents, today's spend, CI), approvals, pods and this device's
/// Claude sessions. Spend and CI are the authority's cached objects, so a tick makes no gateway or gh read.
const SLOW_EVERY: Duration = Duration::from_secs(60);
const RETRY_EVERY: Duration = Duration::from_secs(2);
/// How many recent events a newly watched session replays; halved while
/// Huginn refuses the replay as too large.
const REPLAY_WINDOW: u64 = 400;

pub(crate) fn run(arguments: ViewArgs) -> Result<(), String> {
    if arguments.bridge {
        return bridge(arguments);
    }
    launch()
}

/// The view's exit status when a deploy replaced the installed odin. The
/// launcher execs that odin in its place, so the new view is this process,
/// not a child of the old one.
const UPDATED_EXIT: i32 = 75;

/// What the installed odin's wrapper sets only when unset. A relaunch drops
/// every store-path value of these: the new wrapper then sets its own, and a
/// value the owner set (outside the store) stays.
const WRAPPER_DEFAULTS: [&str; 2] = ["ODIN_CONFIG", "ODIN_ROOT"];

/// Runs the view, `bun <entry>`, told how to start its bridge. When it exits
/// because Odin was redeployed, the installed `odin view` replaces this process.
fn launch() -> Result<(), String> {
    use std::os::unix::process::CommandExt;
    let entry = std::env::var("ODIN_VIEW_ENTRY").map_err(|_| {
        "odin view: ODIN_VIEW_ENTRY is not set (the installed odin sets it; a dev build needs ODIN_VIEW_ENTRY=<repo>/view/main.ts)"
    })?;
    let bun = std::env::var("ODIN_VIEW_BUN").unwrap_or_else(|_| "bun".to_owned());
    let odin = std::env::current_exe()
        .map_err(|error| format!("odin view: cannot find this odin binary: {error}"))?;
    let bridge = json!([odin, "view", "--bridge"]).to_string();
    let status = std::process::Command::new(&bun)
        .arg(&entry)
        .env("ODIN_VIEW_BRIDGE", bridge)
        .status()
        .map_err(|error| format!("odin view: could not start {bun} {entry}: {error}"))?;
    if status.code() != Some(UPDATED_EXIT) {
        std::process::exit(status.code().unwrap_or(1));
    }
    let mut relaunch = std::process::Command::new("odin");
    relaunch.arg("view");
    for (name, value) in std::env::vars_os() {
        if WRAPPER_DEFAULTS.contains(&name.to_str().unwrap_or_default())
            && Path::new(&value).starts_with(NIX_STORE)
        {
            relaunch.env_remove(&name);
        }
    }
    let error = relaunch.exec();
    Err(format!(
        "odin view: Odin was redeployed, but the installed odin view could not start: {error}"
    ))
}

const NIX_STORE: &str = "/nix/store";

/// The installed odin: the first `odin` on `path`, resolved to the store
/// path a deploy replaces (the wrapper script, or the binary a profile
/// links to).
fn installed_odin(path: &std::ffi::OsStr) -> Option<PathBuf> {
    std::env::split_paths(path)
        .map(|dir| dir.join("odin"))
        .find(|candidate| candidate.is_file())?
        .canonicalize()
        .ok()
}

fn bridge(arguments: ViewArgs) -> Result<(), String> {
    let endpoint = arguments
        .endpoint
        .ok_or("odin view: no Huginn endpoint (set ODIN_HUGINN_ENDPOINT or pass --endpoint)")?;
    let url = url::Url::parse(&endpoint)
        .map_err(|error| format!("odin view: invalid Huginn endpoint {endpoint}: {error}"))?;
    let transport = EndpointTransport::new(url).map_err(|error| error.to_string())?;
    let credentials = FileCredentialStore::open(arguments.state_root.join("huginn"))
        .map_err(|error| format!("odin view: this host is not paired with Huginn: {error}"))?;
    let client = Arc::new(RemoteClient::new(transport, credentials));
    let runtime = tokio::runtime::Runtime::new()
        .map_err(|error| format!("odin view: could not start the runtime: {error}"))?;
    runtime.block_on(serve(client, endpoint, arguments.state_root))
}

/// One JSON line to the view. The view is gone when stdout is, and so is the bridge.
fn emit(value: &Value) {
    let mut out = std::io::stdout().lock();
    if writeln!(out, "{value}").and_then(|()| out.flush()).is_err() {
        std::process::exit(0);
    }
}

/// The installed odin this view started under, when it runs a deployed
/// build: a cargo build is never swapped for the installed one.
fn started_under() -> Option<PathBuf> {
    std::env::current_exe()
        .ok()
        .filter(|own| own.starts_with(NIX_STORE))?;
    installed_odin(&std::env::var_os("PATH")?)
}

/// Tells the view, on every slow tick, that a deploy replaced the odin it
/// started under and which status to exit with; it does once its composer
/// is empty and no message is in flight.
fn updated(started: Option<&PathBuf>) {
    let Some(started) = started else {
        return;
    };
    let now = std::env::var_os("PATH").and_then(|path| installed_odin(&path));
    if now.is_some_and(|now| &now != started) {
        emit(&json!({ "t": "updated", "exit": UPDATED_EXIT }));
    }
}

fn done(id: &Value, ok: bool, text: impl Into<String>) {
    emit(&json!({ "t": "done", "id": id, "ok": ok, "text": text.into() }));
}

/// Why the link to Huginn is down, in words.
pub(super) fn cause(error: &ClientError) -> String {
    match error {
        ClientError::DeviceRevoked => {
            "this host was unpaired from Huginn; pair it again".to_owned()
        }
        other => other.to_string(),
    }
}

/// The link is gone (or odind is restarting), so reconnect. The conversation's
/// own trouble (`conversationUnavailable`, `conversationVehicle`, …) comes on a
/// live link.
fn lost(error: &ClientError) -> bool {
    match error {
        ClientError::ConnectionClosed | ClientError::Transport(_) | ClientError::Io(_) => true,
        ClientError::Protocol(live::HuginnProtocolError::Unavailable { code, .. }) => {
            !code.starts_with("conversation")
        }
        _ => false,
    }
}

struct Bridge {
    client: Arc<Client>,
    endpoint: String,
    /// This host's state root: the injected-context traces the authority wrote.
    state_root: PathBuf,
    connection: Option<Connection>,
    link: Option<(bool, String)>,
    seats: String,
    /// The session carrying Sinmara's conversation, as last seen; it changes
    /// when the conversation rolls over to a successor session.
    conversation: Option<String>,
    /// The session the conversation rolled over from, replayed ahead of the
    /// current one so what was said there stays on screen.
    previous: Option<live::PreviousVehicle>,
    /// Each live session's event head, from the last seat poll.
    heads: BTreeMap<String, u64>,
    watch: Option<tokio::task::JoinHandle<()>>,
    /// The last emitted line per overview poll: a slow poll repeats
    /// verbatim until its data changes (ages are the view's to compute).
    approvals: String,
    incidents: String,
    pods: String,
    local: String,
    ci: String,
    /// The Capabilities object, last sent; a poll repeats it only when it changes.
    features: String,
    /// How far each live local transcript has been scanned for compaction.
    transcripts: BTreeMap<PathBuf, TranscriptScan>,
    say_retry: SayRetry,
}

/// A say that got no answer keeps its command id, so saying the same line
/// again is the daemon's to dedupe instead of a second admission.
#[derive(Default)]
struct SayRetry(Option<(String, odin_domain::CommandId)>);

impl SayRetry {
    fn command_id(&mut self, text: &str) -> Result<odin_domain::CommandId, String> {
        match self.0.take() {
            Some((previous, command_id)) if previous == text => Ok(command_id),
            _ => authority_provision::random_command_uuid(),
        }
    }

    fn unanswered(&mut self, text: &str, command_id: odin_domain::CommandId) {
        self.0 = Some((text.to_owned(), command_id));
    }
}

async fn serve(client: Arc<Client>, endpoint: String, state_root: PathBuf) -> Result<(), String> {
    let started = started_under();
    let (compute_active, compute_state) = tokio::sync::watch::channel(false);
    let mut commands = read_commands(compute_active);
    let compute_client = Arc::clone(&client);
    let compute = tokio::spawn(compute_loop(
        compute_state,
        move || sample_compute(Arc::clone(&compute_client)),
        |line| emit(&line),
    ));
    let mut bridge = Bridge {
        client,
        endpoint,
        state_root,
        connection: None,
        link: None,
        seats: String::new(),
        conversation: None,
        previous: None,
        heads: BTreeMap::new(),
        watch: None,
        approvals: String::new(),
        incidents: String::new(),
        pods: String::new(),
        local: String::new(),
        ci: String::new(),
        features: String::new(),
        transcripts: BTreeMap::new(),
        say_retry: SayRetry::default(),
    };
    // Every connect polls seats, status, approvals and pods at once; the
    // ticks keep them fresh after.
    let start = tokio::time::Instant::now();
    let mut seats = tokio::time::interval_at(start + SEATS_EVERY, SEATS_EVERY);
    let mut slow = tokio::time::interval_at(start + SLOW_EVERY, SLOW_EVERY);
    for tick in [&mut seats, &mut slow] {
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    }
    // The overview's local reads need no Huginn link, so they run now and
    // then on the slow tick even while the link is down.
    bridge.poll_local().await;
    loop {
        if bridge.connection.is_none() {
            bridge.connect().await;
        }
        if bridge.connection.is_none() {
            tokio::select! {
                () = tokio::time::sleep(RETRY_EVERY) => {}
                _ = slow.tick() => {
                    updated(started.as_ref());
                    bridge.poll_local().await;
                }
                command = commands.recv() => match command {
                    Some(command) => bridge.command(command).await,
                    None => break,
                },
            }
            continue;
        }
        tokio::select! {
            _ = seats.tick() => bridge.poll_seats().await,
            _ = slow.tick() => {
                updated(started.as_ref());
                bridge.poll_models().await;
                bridge.poll_approvals().await;
                bridge.poll_status().await;
                bridge.poll_pods().await;
                bridge.poll_local().await;
            }
            command = commands.recv() => match command {
                Some(command) => bridge.command(command).await,
                None => break,
            },
        }
    }
    compute.abort();
    if let Some(watch) = bridge.watch.take() {
        watch.abort();
    }
    Ok(())
}

impl Bridge {
    fn set_link(&mut self, ok: bool, text: String) {
        if self.link.as_ref() != Some(&(ok, text.clone())) {
            emit(&json!({ "t": "link", "ok": ok, "text": text }));
            self.link = Some((ok, text));
        }
    }

    async fn connect(&mut self) {
        match tokio::time::timeout(REQUEST_BOUND, self.client.connect()).await {
            Ok(Ok(connection)) => {
                self.connection = Some(connection);
                let text = format!("connected to {}", self.endpoint);
                self.set_link(true, text);
                // A fresh link re-sends the whole seat list, and reads the
                // overview's approvals and pods now rather than saying
                // "none" until the slow tick.
                self.seats.clear();
                self.poll_seats().await;
                self.poll_models().await;
                self.poll_approvals().await;
                self.poll_status().await;
                self.poll_pods().await;
            }
            Ok(Err(error)) => {
                let text = format!(
                    "Huginn at {} is unreachable: {}",
                    self.endpoint,
                    cause(&error)
                );
                self.set_link(false, text);
            }
            Err(_) => {
                let text = format!(
                    "Huginn at {} did not answer within {} s",
                    self.endpoint,
                    REQUEST_BOUND.as_secs()
                );
                self.set_link(false, text);
            }
        }
    }

    /// One request on the link; a lost link is dropped (and said) so the
    /// loop reconnects.
    async fn request(
        &mut self,
        request: live::HuginnRequest,
        bound: Duration,
    ) -> Result<live::HuginnResponse, String> {
        let connection = self
            .connection
            .as_mut()
            .ok_or_else(|| "not connected to Huginn".to_owned())?;
        let error = match tokio::time::timeout(bound, connection.request(request)).await {
            Ok(Ok(response)) => return Ok(response),
            Ok(Err(error)) if !lost(&error) => return Err(cause(&error)),
            Ok(Err(error)) => cause(&error),
            Err(_) => format!("no answer within {} s", bound.as_secs()),
        };
        self.connection = None;
        let text = format!("lost Huginn at {}: {error}", self.endpoint);
        self.set_link(false, text);
        Err(error)
    }

    async fn poll_seats(&mut self) {
        let query = live::HuginnRequest::Snapshot(live::SnapshotQuery {
            scope: live::QueryScope::All,
            kinds: vec![live::ObjectKind::Seat, live::ObjectKind::Session],
            if_revision: None,
            cursor: None,
            limit: std::num::NonZeroU16::new(128).expect("128 is non-zero"),
            include_stale: true,
        });
        let page = match self.request(query, REQUEST_BOUND).await {
            Ok(live::HuginnResponse::Snapshot(page)) => page,
            Ok(other) => {
                tracing::warn!("seat snapshot answered {other:?}");
                return;
            }
            Err(error) => {
                tracing::warn!("seat snapshot failed: {error}");
                return;
            }
        };
        let mut heads = BTreeMap::new();
        let mut seats = Vec::new();
        let mut claude = Vec::new();
        for object in page.objects {
            if object.object.kind == live::ObjectKind::Session {
                if let Some(line) = claude_line(&object) {
                    claude.push(line);
                }
                continue;
            }
            let entry = match serde_json::from_value::<live::SeatRosterEntry>(
                object.value.get("data").cloned().unwrap_or(Value::Null),
            ) {
                Ok(entry) => entry,
                Err(error) => {
                    tracing::warn!("seat {} is not a roster entry: {error}", object.object.id);
                    continue;
                }
            };
            for session in &entry.active_sessions {
                heads.insert(session.session_id.to_string(), session.event_head.get());
            }
            seats.push(seat_line(&entry));
        }
        self.heads = heads;
        self.poll_conversation().await;
        let line = json!({
            "t": "seats",
            "seats": seats,
            "claude": claude,
            "conversation": self.conversation
        });
        emit_once(&mut self.seats, &line);
    }

    /// Between a rollover's retirement and its successor's opening there is
    /// no vehicle; the last one stays named until the next appears.
    async fn poll_conversation(&mut self) {
        match self
            .request(live::HuginnRequest::ConversationStatus, REQUEST_BOUND)
            .await
        {
            Ok(live::HuginnResponse::Conversation(view)) => {
                if let Some(session) = view.vehicle_session {
                    self.conversation = Some(session.to_string());
                    self.previous = view.previous_vehicle;
                }
            }
            Ok(other) => tracing::warn!("conversation status answered {other:?}"),
            Err(error) => tracing::warn!("conversation status failed: {error}"),
        }
    }

    /// The pane uses the same board and renderer as `odin models` and `quota`.
    async fn poll_models(&mut self) {
        let result = match self
            .request(live::HuginnRequest::Models, REQUEST_BOUND)
            .await
        {
            Ok(live::HuginnResponse::Models(board)) => {
                let mut rendered = Vec::new();
                super::huginn::write_models(&mut rendered, &board).map(|()| {
                    String::from_utf8_lossy(&rendered)
                        .lines()
                        .map(str::to_owned)
                        .collect::<Vec<_>>()
                })
            }
            Ok(other) => Err(format!("model book answered {other:?}")),
            Err(error) => Err(format!("model book unreadable: {error}")),
        };
        match result {
            Ok(rows) => emit(&json!({ "t": "modelRows", "rows": rows })),
            Err(error) => emit(&json!({ "t": "modelRows", "error": error })),
        }
    }

    /// Every object of one kind, page by page; `None` (logged) when a page
    /// fails, so the last line shown stays up.
    async fn snapshot_all(&mut self, kind: live::ObjectKind) -> Option<Vec<live::ObjectSnapshot>> {
        let mut objects = Vec::new();
        let mut cursor = None;
        loop {
            let query = live::HuginnRequest::Snapshot(live::SnapshotQuery {
                scope: live::QueryScope::All,
                kinds: vec![kind],
                if_revision: None,
                cursor: cursor.take(),
                limit: std::num::NonZeroU16::new(1000).expect("1000 is non-zero"),
                include_stale: false,
            });
            let page = match self.request(query, REQUEST_BOUND).await {
                Ok(live::HuginnResponse::Snapshot(page)) => page,
                Ok(other) => {
                    tracing::warn!("{kind:?} snapshot answered {other:?}");
                    return None;
                }
                Err(error) => {
                    tracing::warn!("{kind:?} snapshot failed: {error}");
                    return None;
                }
            };
            objects.extend(page.objects);
            match page.next_cursor {
                Some(next) => cursor = Some(next),
                None => return Some(objects),
            }
        }
    }

    /// Approvals waiting, for the overview: the read model's requested ones.
    /// The live model holds only pending approvals and those settled within
    /// the last day, so this is one small page.
    async fn poll_approvals(&mut self) {
        let Some(objects) = self.snapshot_all(live::ObjectKind::Approval).await else {
            return;
        };
        let rows: Vec<Value> = objects.iter().filter_map(approval_row).collect();
        let line = json!({ "t": "approvals", "rows": rows });
        emit_once(&mut self.approvals, &line);
    }

    /// One Status snapshot feeds four lines: open incidents for the overview, newest first (resolved
    /// cards stay in the read model but leave the view), the Capabilities object, and the authority's
    /// cached spend and CI objects. A stale spend object is not in the snapshot, so a figure the
    /// gateway stopped confirming sends no line and goes dim.
    async fn poll_status(&mut self) {
        let Some(objects) = self.snapshot_all(live::ObjectKind::Status).await else {
            return;
        };
        let line = json!({ "t": "incidents", "rows": incident_rows(&objects) });
        emit_once(&mut self.incidents, &line);
        if let Some(line) = features::features_line(&objects) {
            emit_once(&mut self.features, &line);
        }
        if let Some(line) = spend_line(&objects) {
            emit(&line);
        }
        emit_once(&mut self.ci, &ci_line(&objects));
    }

    /// Odin's pods for the overview: every live one, then the ones that
    /// ended within the last day, newest first.
    async fn poll_pods(&mut self) {
        let Some(objects) = self.snapshot_all(live::ObjectKind::KubeResource).await else {
            return;
        };
        let line =
            json!({ "t": "pods", "rows": pod_rows(&objects, time::OffsetDateTime::now_utc()) });
        emit_once(&mut self.pods, &line);
    }

    /// The Claude Code sessions running on this device (`~/.claude/sessions`),
    /// each with its git branch and whether its transcript has compacted.
    async fn poll_local(&mut self) {
        let Some(home) = std::env::var_os("HOME").map(PathBuf::from) else {
            return;
        };
        let sessions = match std::fs::read_dir(home.join(".claude/sessions")) {
            Ok(sessions) => sessions,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                let line = json!({ "t": "claudeLocal", "device": device(), "rows": [] });
                emit_once(&mut self.local, &line);
                return;
            }
            Err(error) => {
                tracing::warn!("reading ~/.claude/sessions failed: {error}");
                return;
            }
        };
        let mut files: Vec<_> = sessions.filter_map(Result::ok).collect();
        files.sort_by_key(|entry| entry.file_name());
        // Only live sessions' scans are kept.
        let mut scans = std::mem::take(&mut self.transcripts);
        let mut rows = Vec::new();
        for entry in files {
            let path = entry.path();
            if path.extension().and_then(|ext| ext.to_str()) != Some("json") {
                continue;
            }
            let Ok(text) = std::fs::read_to_string(&path) else {
                continue;
            };
            let Ok(value) = serde_json::from_str::<Value>(&text) else {
                tracing::warn!("{} is not a JSON session file", path.display());
                continue;
            };
            let (Some(pid), Some(session), Some(cwd)) = (
                value.get("pid").and_then(Value::as_u64),
                value.get("sessionId").and_then(Value::as_str),
                value.get("cwd").and_then(Value::as_str),
            ) else {
                continue;
            };
            // A dead daemon leaves its file behind; only live sessions show.
            if !Path::new(&format!("/proc/{pid}")).exists() {
                continue;
            }
            let name = value
                .get("name")
                .and_then(Value::as_str)
                .unwrap_or("claude");
            let transcript = transcript_path(&home, cwd, session);
            let mut scan = scans.remove(&transcript).unwrap_or_default();
            let compacted = compacted(&transcript, &mut scan);
            self.transcripts.insert(transcript, scan);
            rows.push((
                name.to_owned(),
                json!({
                    "id": session,
                    "name": name,
                    "status": value.get("status").and_then(Value::as_str).unwrap_or(""),
                    "cwd": cwd,
                    "branch": git_branch(cwd).await,
                    "compacted": compacted,
                }),
            ));
        }
        rows.sort_by(|a, b| a.0.cmp(&b.0));
        let line = json!({
            "t": "claudeLocal",
            "device": device(),
            "rows": rows.into_iter().map(|(_, row)| row).collect::<Vec<_>>(),
        });
        emit_once(&mut self.local, &line);
    }

    async fn command(&mut self, command: Value) {
        let id = command.get("id").cloned().unwrap_or(Value::Null);
        let text = |key: &str| command.get(key).and_then(Value::as_str).unwrap_or_default();
        match text("t") {
            "watch" => self.watch(text("session")),
            "say" => self.say(&id, text("text")).await,
            "model" => self.model(&id, text("seat"), text("model")).await,
            "catalog" => self.catalog(&id, text("seat")).await,
            "claude" => {
                self.claude(
                    text("session"),
                    command.get("since").and_then(Value::as_u64),
                    text("request"),
                )
                .await
            }
            "models" => self.models().await,
            "context" => self.context(text("session")),
            "features" => self.refresh_features().await,
            other => tracing::warn!("view sent an unknown command {other:?}"),
        }
    }

    fn watch(&mut self, session: &str) {
        if let Some(previous) = self.watch.take() {
            previous.abort();
        }
        let Ok(session_id) = session.parse::<live::LiveSessionId>() else {
            emit(&json!({ "t": "event", "session": session, "kind": "error",
                "text": format!("{session:?} is not a session id") }));
            return;
        };
        let head = self.heads.get(session).copied().unwrap_or(0);
        let earlier = if self.conversation.as_deref() == Some(session) {
            self.previous.clone()
        } else {
            None
        };
        emit(&json!({ "t": "reset", "session": session,
            "previous": earlier.as_ref().map(|previous| previous.session.to_string()) }));
        let client = Arc::clone(&self.client);
        self.watch = Some(tokio::spawn(async move {
            if let Some(previous) = earlier {
                follow(
                    Arc::clone(&client),
                    previous.session,
                    previous.event_head,
                    true,
                )
                .await;
                let short: String = session_id.to_string().chars().take(8).collect();
                note(
                    &session_id,
                    format!("the conversation continues in a new session ({short})"),
                );
            }
            follow(client, session_id, head, false).await;
        }));
    }

    async fn say(&mut self, id: &Value, text: &str) {
        let text = text.trim();
        if text.is_empty() {
            return done(id, false, "an empty line is not sent");
        }
        let command_id = match self.say_retry.command_id(text) {
            Ok(command_id) => command_id,
            Err(error) => return done(id, false, error),
        };
        let request = live::HuginnRequest::ConversationSay(live::ConversationSayRequest {
            command_id: command_id.clone(),
            text: text.to_owned(),
            terminal: true,
        });
        match self.request(request, REQUEST_BOUND).await {
            Ok(live::HuginnResponse::Conversation(view)) => {
                let intake = view.intake.unwrap_or_else(|| "sent".to_owned());
                done(id, true, format!("sent ({intake})"));
            }
            Ok(other) => done(id, false, format!("Huginn answered the say with {other:?}")),
            Err(error) => {
                self.say_retry.unanswered(text, command_id);
                done(
                    id,
                    false,
                    format!(
                        "no answer: {error}; saying the same line again will not send it twice"
                    ),
                );
            }
        }
    }

    async fn model(&mut self, id: &Value, seat: &str, choice: &str) {
        let Some((provider, model)) = choice.split_once('/') else {
            return done(id, false, format!("{choice:?} is not provider/model"));
        };
        let command_id = match authority_provision::random_command_uuid() {
            Ok(command_id) => command_id,
            Err(error) => return done(id, false, error),
        };
        let request = live::HuginnRequest::SeatModelSet(live::SeatModelSetRequest {
            command_id,
            seat: seat.to_owned(),
            provider: provider.to_owned(),
            model: model.to_owned(),
        });
        match self.request(request, MODEL_BOUND).await {
            Ok(live::HuginnResponse::SeatModel(change)) => {
                done(id, true, format!("{}; {}", change.declared, change.live));
            }
            Ok(other) => done(
                id,
                false,
                format!("Huginn answered the model change with {other:?}"),
            ),
            Err(error) => done(id, false, format!("model not changed: {error}")),
        }
    }

    async fn catalog(&mut self, id: &Value, seat: &str) {
        let failed = |note: String| {
            emit(&json!({
                "t": "catalog",
                "id": id,
                "seat": seat,
                "note": note,
                "rows": [],
            }));
        };
        match self
            .request(live::HuginnRequest::ModelCatalog, REQUEST_BOUND)
            .await
        {
            Ok(live::HuginnResponse::ModelCatalog(view)) => {
                let mut line = serde_json::to_value(&view).unwrap_or_else(|_| json!({}));
                if let Some(object) = line.as_object_mut() {
                    object.insert("t".into(), json!("catalog"));
                    object.insert("id".into(), id.clone());
                    object.insert("seat".into(), json!(seat));
                }
                emit(&line);
            }
            Ok(other) => failed(format!("Huginn answered the catalog with {other:?}")),
            Err(error) => failed(error),
        }
    }

    /// One bounded page of a Claude session, read on its owning host only because the view asked.
    async fn claude(&mut self, session: &str, since: Option<u64>, correlation: &str) {
        let note = |text: String| {
            emit(&json!({
                "t": "claudeTranscript",
                "session": session,
                "request": correlation,
                "events": [],
                "nextCursor": since.unwrap_or(0),
                "hasMore": false,
                "note": text,
            }));
        };
        if session.is_empty() {
            return note("a Claude transcript needs its session".to_owned());
        }
        let id = claude_id(session);
        if id.is_empty() {
            return note("a Claude transcript needs its session".to_owned());
        }
        let request = live::HuginnRequest::ClaudeTranscript(live::ClaudeTranscriptRequest {
            session: id.to_owned(),
            since,
        });
        match self.request(request, REQUEST_BOUND).await {
            Ok(live::HuginnResponse::ClaudeTranscript(page)) => {
                let mut line = claude_page(session, &page);
                line["request"] = json!(correlation);
                emit(&line);
            }
            Ok(other) => note(format!("Huginn answered the transcript with {other:?}")),
            Err(error) => note(error),
        }
    }

    /// The one model book. The view asks when its pane is open; this is not a second reading.
    async fn models(&mut self) {
        match self
            .request(live::HuginnRequest::Models, REQUEST_BOUND)
            .await
        {
            Ok(live::HuginnResponse::Models(board)) => {
                emit(&json!({ "t": "models", "board": board }))
            }
            Ok(other) => emit(
                &json!({ "t": "models", "note": format!("Huginn answered the model book with {other:?}") }),
            ),
            Err(error) => emit(&json!({ "t": "models", "note": error })),
        }
    }
}

/// The view's tab id is `claude:<uuid>`; the transcript request wants the uuid.
fn claude_id(session: &str) -> &str {
    session.strip_prefix("claude:").unwrap_or(session)
}

/// The existing ClaudeReadReply, named for the view. `has_more` is the host backlog, not a local guess.
fn claude_page(session: &str, page: &Value) -> Value {
    let next = page.get("next_cursor").and_then(Value::as_u64).unwrap_or(0);
    let mut line = json!({
        "t": "claudeTranscript",
        "session": session,
        "events": page.get("events").cloned().unwrap_or_else(|| json!([])),
        "nextCursor": next,
        "hasMore": page.get("has_more") == Some(&Value::Bool(true)),
    });
    if let Some(error) = page.get("error") {
        let cursor = error.get("cursor").and_then(Value::as_u64).unwrap_or(next);
        line["error"] = json!(format!("the line at cursor {cursor} is too large to show"));
    }
    line
}

/// A waiting approval's overview row; `None` once it is decided. An
/// approval's snapshot value is its `ApprovalView` itself, not `{data}`.
fn approval_row(object: &live::ObjectSnapshot) -> Option<Value> {
    let view = match serde_json::from_value::<ApprovalView>(object.value.clone()) {
        Ok(view) => view,
        Err(error) => {
            tracing::warn!("{} is not an approval view: {error}", object.object.id);
            return None;
        }
    };
    (view.status == ApprovalStatus::Requested).then(|| {
        json!({
            "id": view.approval_id.to_string(),
            "issuer": view.issuer,
            "capability": view.capability_id.to_string(),
            "target": format!("{} {}", view.target_kind, view.target_id),
            "requestedAt": rfc3339(view.requested_at),
        })
    })
}

/// Open incidents as overview rows, newest first. Status objects that are
/// not incident cards (roster, daemon status) are skipped.
fn incident_rows(objects: &[live::ObjectSnapshot]) -> Vec<Value> {
    use odin_huginn::incidents::{IncidentStatusView, IncidentView};
    let mut open: Vec<IncidentView> = objects
        .iter()
        .filter(|object| object.value.get("incidentId").is_some())
        .filter_map(
            |object| match serde_json::from_value::<IncidentView>(object.value.clone()) {
                Ok(view) => Some(view),
                Err(error) => {
                    tracing::warn!("{} is not an incident view: {error}", object.object.id);
                    None
                }
            },
        )
        .filter(|view| view.status != IncidentStatusView::Resolved)
        .collect();
    open.sort_by_key(|view| std::cmp::Reverse(view.last_observed_at));
    open.iter()
        .map(|view| {
            json!({
                "id": view.incident_id.to_string(),
                "severity": view.severity,
                "summary": view.deviation,
                "since": rfc3339(view.first_observed_at),
            })
        })
        .collect()
}

/// The most ended pods the overview lists.
const ENDED_PODS: usize = 5;

/// Odin's workloads as overview rows: live ones first, then those that
/// ended within the last day, each group newest first. Foreign objects and
/// non-workload views (nodes, events) are not pods.
fn pod_rows(objects: &[live::ObjectSnapshot], now: time::OffsetDateTime) -> Vec<Value> {
    use live::KubeWorkloadState as State;
    let mut workloads: Vec<live::KubeWorkloadView> = objects
        .iter()
        .filter_map(|object| serde_json::from_value(object.value.clone()).ok())
        .collect();
    workloads.sort_by_key(|workload| std::cmp::Reverse(workload.started_at));
    let ended = |workload: &live::KubeWorkloadView| {
        matches!(workload.state, State::Succeeded | State::Failed)
    };
    let recent = |workload: &&live::KubeWorkloadView| {
        workload
            .finished_at
            .is_some_and(|at| now - at < time::Duration::days(1))
    };
    let live = workloads.iter().filter(|workload| !ended(workload));
    let finished = workloads
        .iter()
        .filter(|workload| ended(workload))
        .filter(recent)
        .take(ENDED_PODS);
    live.chain(finished)
        .filter_map(|workload| {
            let live::KubeResourceOwnership::Odin { seat_id, .. } = &workload.ownership else {
                return None;
            };
            Some(json!({
                "name": workload
                    .label
                    .as_deref()
                    .or(workload.profile.as_deref())
                    .unwrap_or(&workload.resource.name),
                "state": workload.state,
                "seat": seat_id.as_str(),
                "node": workload.node_id.as_ref().map(ToString::to_string),
                "startedAt": workload.started_at.map(rfc3339),
                "finishedAt": workload.finished_at.map(rfc3339),
                "status": workload.status.as_ref().map(|status| json!({
                    "at": rfc3339(status.at),
                    "progress": status.progress,
                    "summary": status.summary,
                })),
            }))
        })
        .collect()
}

fn seat_line(entry: &live::SeatRosterEntry) -> Value {
    let mut models: Vec<String> = entry
        .launch_options
        .iter()
        .map(|option| format!("{}/{}", option.provider, option.model))
        .collect();
    models.dedup();
    let mut sessions: Vec<&live::LiveSessionSummary> = entry.active_sessions.iter().collect();
    sessions.sort_by_key(|session| std::cmp::Reverse(session.updated_at));
    let sessions: Vec<Value> = sessions
        .into_iter()
        .map(|session| {
            json!({
                "id": session.session_id.to_string(),
                "state": session.state,
                "model": format!("{}/{}", session.provider, session.model),
                "title": session.title,
                "updatedAt": rfc3339(session.updated_at),
                "quietSeconds": session.quiet_seconds,
                "pendingPermissionCount": session.pending_permission_count,
            })
        })
        .collect();
    json!({
        "id": entry.seat_id.as_str(),
        "name": entry.display_name,
        "state": entry.state,
        "models": models,
        "sessions": sessions,
    })
}

/// A live Claude session. The badge is age versus `updatedAt`, same as a seat row.
fn claude_line(object: &live::ObjectSnapshot) -> Option<Value> {
    if !object.object.id.starts_with("claude:") {
        return None;
    }
    let data = object.value.get("data")?;
    let state = data.pointer("/session/state")?.as_str()?;
    if !matches!(state, "opening" | "running" | "prompting" | "stopping") {
        return None;
    }
    let title = data
        .pointer("/session/request/name")
        .and_then(Value::as_str)
        .filter(|name| !name.is_empty())
        .unwrap_or("Claude");
    // `running` is the tab open between Odin's prompts: Odin does not see
    // Claude Code's own turns, so it reads as open, not as a turn going quiet.
    let state = if state == "running" { "open" } else { state };
    Some(json!({
        "id": object.object.id,
        "state": state,
        "model": "claude",
        "title": title,
        "updatedAt": rfc3339(object.freshness.observed_at),
        "quietSeconds": data.get("quietSeconds").and_then(Value::as_u64).unwrap_or(600),
        "pendingPermissionCount": data.get("pendingPermissionCount").and_then(Value::as_u64).unwrap_or(0),
        "compacted": compacted_events(data.get("events").and_then(Value::as_array)),
    }))
}

/// Whether the projected transcript window holds Claude Code's own
/// compaction: the `system`/`compact_boundary` frame, or the summary it
/// replays (`isCompactSummary`). Local transcripts carry the same markers.
fn compacted_events(events: Option<&Vec<Value>>) -> bool {
    events.is_some_and(|events| {
        events.iter().any(|event| {
            let Some(payload) = event.get("payload") else {
                return false;
            };
            payload.get("isCompactSummary") == Some(&Value::Bool(true))
                || (payload.get("type").and_then(Value::as_str) == Some("system")
                    && payload.get("subtype").and_then(Value::as_str) == Some("compact_boundary"))
        })
    })
}

fn rfc3339(at: time::OffsetDateTime) -> String {
    at.format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_default()
}

/// A slow poll's line goes out only when it changed; ages are computed in
/// the view, so an unchanged line would repeat verbatim.
fn emit_once(last: &mut String, line: &Value) {
    let text = line.to_string();
    if text != *last {
        emit(line);
        *last = text;
    }
}

/// This device's name, labelling the overview's local rows.
fn device() -> String {
    std::fs::read_to_string("/etc/hostname")
        .unwrap_or_default()
        .trim()
        .to_owned()
}

/// The cwd's git branch, or `None` when it is not a checkout.
async fn git_branch(cwd: &str) -> Option<String> {
    let read = tokio::process::Command::new("git")
        .arg("-C")
        .arg(cwd)
        .args(["rev-parse", "--abbrev-ref", "HEAD"])
        .output();
    let output = tokio::time::timeout(Duration::from_secs(10), read)
        .await
        .ok()?
        .ok()?;
    let branch = String::from_utf8_lossy(&output.stdout).trim().to_owned();
    (!branch.is_empty()).then_some(branch)
}

/// How far one transcript has been scanned for a compaction record: the
/// file can be tens of megabytes, so each slow tick reads only what was
/// appended since, and a found marker is permanent.
#[derive(Default)]
struct TranscriptScan {
    read: u64,
    compacted: bool,
}

/// Claude Code munges the cwd into the project directory the way
/// `odin-hub move` already relies on.
fn transcript_path(home: &Path, cwd: &str, session: &str) -> PathBuf {
    let project: String = cwd
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
        .collect();
    home.join(format!(".claude/projects/{project}/{session}.jsonl"))
}

/// Whether the transcript holds a compaction record, reading the complete
/// lines past `scan.read` (the marker is one line).
fn compacted(path: &Path, scan: &mut TranscriptScan) -> bool {
    if scan.compacted {
        return true;
    }
    let Ok(file) = std::fs::File::open(path) else {
        return false;
    };
    if file.metadata().is_ok_and(|meta| meta.len() < scan.read) {
        scan.read = 0;
    }
    let mut reader = std::io::BufReader::new(file);
    if std::io::Seek::seek(&mut reader, std::io::SeekFrom::Start(scan.read)).is_err() {
        return false;
    }
    let mut line = Vec::new();
    loop {
        line.clear();
        match std::io::BufRead::read_until(&mut reader, b'\n', &mut line) {
            Ok(0) | Err(_) => return false,
            // A line still being written is read whole on a later tick.
            Ok(_) if line.last() != Some(&b'\n') => return false,
            Ok(read) => scan.read += read as u64,
        }
        if [
            "\"subtype\":\"compact_boundary\"".as_bytes(),
            "\"isCompactSummary\":true".as_bytes(),
        ]
        .iter()
        .any(|needle| line.windows(needle.len()).any(|window| window == *needle))
        {
            scan.compacted = true;
            return true;
        }
    }
}

/// The Status ids odind publishes the cached spend and CI under.
const SPEND_STATUS: &str = "spend";
const CI_STATUS: &str = "ci";

fn status_value<'a>(objects: &'a [live::ObjectSnapshot], id: &str) -> Option<&'a Value> {
    objects
        .iter()
        .find(|object| object.object.kind == live::ObjectKind::Status && object.object.id == id)
        .map(|object| &object.value)
}

/// Today's spend as the `spend` line: the authority's cached Status object, never a gateway read of the view's own.
fn spend_line(objects: &[live::ObjectSnapshot]) -> Option<Value> {
    let view = match serde_json::from_value::<live::SpendView>(
        status_value(objects, SPEND_STATUS)?.clone(),
    ) {
        Ok(view) => view,
        Err(error) => {
            tracing::warn!("the spend object is not a spend view: {error}");
            return None;
        }
    };
    let seats: serde_json::Map<String, Value> = view
        .seats
        .iter()
        .map(|line| {
            (
                line.label.clone(),
                json!({
                    "usdCents": line.usd_cents,
                    "includedCents": line.included_cents,
                    "tokens": line.tokens,
                }),
            )
        })
        .collect();
    Some(json!({
        "t": "spend",
        "day": view.to,
        "usdCents": view.total.usd_cents,
        "includedCents": view.total.included_cents,
        "tokens": view.total.tokens,
        "seats": seats,
    }))
}

/// The CI rows the authority last read, or why there are none yet.
fn ci_line(objects: &[live::ObjectSnapshot]) -> Value {
    match status_value(objects, CI_STATUS) {
        Some(value) => json!({ "t": "ci", "rows": value["rows"] }),
        None => json!({ "t": "ci", "rows": [], "note": "the authority has not read CI yet" }),
    }
}

/// Follows one session's agent events until aborted: a recent replay, then
/// live (or only the replay, for a session that has ended). A dropped stream
/// resumes after the last event it delivered.
async fn follow(client: Arc<Client>, session: live::LiveSessionId, head: u64, replay_only: bool) {
    let stream_id = odin_huginn::feed::agent_event_stream(session);
    let mut window = REPLAY_WINDOW;
    let mut after = head.saturating_sub(window);
    let mut told_unavailable = false;
    loop {
        let set = subscription(stream_id, after);
        let mut stream = match client.subscribe(set).await {
            Ok(stream) => stream,
            Err(ClientError::Protocol(
                live::HuginnProtocolError::ResourceLimit { .. }
                | live::HuginnProtocolError::CursorExpired,
            )) if after < head => {
                // Too much history to replay at once: ask for less.
                window /= 2;
                after = head.saturating_sub(window);
                continue;
            }
            Err(error) => {
                tracing::warn!("watch {session} failed: {error}");
                if !lost(&error) {
                    note(
                        &session,
                        format!("cannot follow this session: {}", cause(&error)),
                    );
                    return;
                }
                // Huginn answers `unavailable` while its copy of the stream
                // is behind the cursor asked for; say so once, keep retrying.
                if !told_unavailable
                    && matches!(
                        error,
                        ClientError::Protocol(live::HuginnProtocolError::Unavailable { .. })
                    )
                {
                    told_unavailable = true;
                    note(
                        &session,
                        format!(
                            "Huginn cannot replay this session's events yet ({}); retrying",
                            cause(&error)
                        ),
                    );
                }
                tokio::time::sleep(RETRY_EVERY).await;
                continue;
            }
        };
        loop {
            match stream.next().await {
                Some(Ok(live::HuginnMessage::Event(event))) => {
                    after = after.max(event.sequence.get());
                    if let Some(line) = event_line(&event) {
                        emit(&line);
                    }
                }
                Some(Ok(live::HuginnMessage::ReplayComplete { .. })) if replay_only => return,
                Some(Ok(live::HuginnMessage::StreamStatus(status)))
                    if matches!(
                        status.lifecycle,
                        live::StreamLifecycle::Closed | live::StreamLifecycle::Failed
                    ) =>
                {
                    note(&session, "this session's event stream ended".to_owned());
                    return;
                }
                Some(Ok(_)) => {}
                Some(Err(error)) => {
                    tracing::warn!("watch {session} lost: {error}");
                    break;
                }
                None => break,
            }
        }
        tokio::time::sleep(RETRY_EVERY).await;
    }
}

fn subscription(stream_id: live::StreamId, after: u64) -> live::SubscriptionSet {
    let positive32 = |value: u32| std::num::NonZeroU32::new(value).expect("positive");
    let positive64 = |value: u64| std::num::NonZeroU64::new(value).expect("positive");
    live::SubscriptionSet {
        subscriptions: vec![live::StreamSubscription {
            kind: live::LiveStreamKind::AgentEvents,
            cursor: live::StreamCursor::Durable {
                stream_id,
                after: Some(live::Sequence::new(after)),
            },
            credit: live::StreamCredit {
                items: positive32(64),
                bytes: positive64(1 << 20),
            },
            limits: live::StreamBackpressureLimits {
                // The replay is one batch of at most this many items.
                max_buffered_items: positive32(512),
                max_buffered_bytes: positive64(8 << 20),
                max_item_bytes: positive64(2 << 20),
                max_items_per_second: positive32(60),
                max_in_flight_bytes: positive64(8 << 20),
            },
        }],
    }
}

fn note(session: &live::LiveSessionId, text: String) {
    emit(&json!({ "t": "event", "session": session.to_string(), "kind": "note", "text": text }));
}

fn message_text(message: &live::LiveMessage) -> String {
    message
        .content
        .iter()
        .filter_map(|block| match block {
            live::LiveContentBlock::Text(text) => Some(text.as_str()),
            _ => None,
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// One live event as the view's line, or `None` for what the view does not show.
fn event_line(event: &live::LiveEvent) -> Option<Value> {
    let fields = match &event.body {
        live::LiveEventBody::UserMessage(message) => {
            let text = message_text(message);
            let jobs: Vec<Value> = odin_domain::job_report::reported_jobs(&text)
                .into_iter()
                .map(|report| {
                    json!({
                        "job": report.job,
                        "ok": report.ok,
                        "seconds": report.seconds,
                        "line": report.line,
                    })
                })
                .collect();
            if jobs.is_empty() {
                json!({ "kind": "user", "text": text })
            } else {
                json!({ "kind": "user", "text": text, "jobs": jobs })
            }
        }
        live::LiveEventBody::AssistantDelta(delta) => reply_fields("delta", &delta.text),
        live::LiveEventBody::AssistantMessage(message) => {
            reply_fields("assistant", &message_text(message))
        }
        live::LiveEventBody::Thinking(thinking) => {
            json!({ "kind": "thinking", "text": thinking.text })
        }
        live::LiveEventBody::Usage(usage) => json!({
            "kind": "usage",
            "model": format!("{}/{}", usage.provider, usage.model),
            "input": usage.input,
            "output": usage.output,
            "cacheRead": usage.cache_read,
            "cacheWrite": usage.cache_write,
            "contextTokens": usage.context_tokens,
            "contextWindow": usage.context_window,
        }),
        live::LiveEventBody::ToolStarted(started) => json!({
            "kind": "toolStart",
            "id": started.tool.tool_use_id,
            "name": started.tool.capability_id.as_str(),
            "args": started.tool.arguments,
        }),
        live::LiveEventBody::ToolFinished(finished) => {
            let text = finished
                .result
                .content
                .iter()
                .filter_map(|block| match block {
                    live::LiveContentBlock::Text(text) => Some(text.as_str()),
                    _ => None,
                })
                .collect::<Vec<_>>()
                .join("\n");
            // A call that became a background job names it.
            let job = odin_domain::job_report::started_job(&text).map(str::to_owned);
            json!({
                "kind": "toolEnd",
                "id": finished.result.tool_use_id,
                "text": text,
                "isError": finished.result.is_error,
                "job": job,
            })
        }
        live::LiveEventBody::ModelRouted(route) => json!({
            "kind": "note",
            "text": match &route.decision.refusal {
                Some(reason) => format!("class escalation refused: {reason} (warrant: {})",
                    route.decision.warrant.as_deref().unwrap_or("none")),
                None => format!("class {} → {}: {}/{} (warrant: {})",
                    route.decision.from_class, route.decision.to_class, route.provider, route.model,
                    route.decision.warrant.as_deref().unwrap_or("window/photo routing")),
            },
        }),
        live::LiveEventBody::SessionStateChanged(change) => {
            json!({ "kind": "state", "state": change.current, "reason": change.reason })
        }
        live::LiveEventBody::Error(error) => {
            json!({ "kind": "error", "text": format!("{} ({})", error.message, error.code) })
        }
        live::LiveEventBody::PermissionRequested(request) => json!({
            "kind": "note",
            "text": format!("asks permission for {}: {}", request.capability_id.as_str(), request.prompt),
        }),
        live::LiveEventBody::SessionOpened(_) => {
            json!({ "kind": "note", "text": "session opened" })
        }
        live::LiveEventBody::SessionClosed(closed) => json!({
            "kind": "note",
            "text": format!("session closed ({})", serde_json::to_value(&closed.reason)
                .ok().and_then(|reason| reason.as_str().map(str::to_owned)).unwrap_or_default()),
        }),
        _ => return None,
    };
    let mut line = json!({
        "t": "event",
        "session": event.session_id.to_string(),
        "seq": event.sequence.get(),
        "at": rfc3339(event.occurred_at),
    });
    if let (Some(line), Value::Object(fields)) = (line.as_object_mut(), fields) {
        line.extend(fields);
    }
    Some(line)
}

/// Preserve delta boundaries and whitespace; the renderer filters the assembled reply.
fn reply_fields(kind: &str, text: &str) -> Value {
    json!({ "kind": kind, "text": text, "quiet": odin_hermes::conversation::QUIET_REPLY })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_say_without_an_answer_is_retried_under_its_own_command_id() {
        let mut retry = SayRetry::default();
        let first = retry.command_id("book tea").expect("id");
        retry.unanswered("book tea", first.clone());
        assert_eq!(retry.command_id("book tea").expect("id"), first);

        retry.unanswered("book tea", first.clone());
        let other = retry.command_id("book coffee").expect("id");
        assert_ne!(other, first, "a different line is a different command");
        assert_ne!(
            retry.command_id("book tea").expect("id"),
            first,
            "an answered or replaced say keeps nothing"
        );
    }

    /// An approval's snapshot value is the approval itself: a requested one
    /// is a row, a decided one is not. The shape is the live read model's.
    #[test]
    fn a_requested_approval_is_a_row_and_a_decided_one_is_not() {
        let approval = |status: &str| -> live::ObjectSnapshot {
            serde_json::from_value(json!({
                "contentDigest": "blake3:8d98b5c54b284d14c4ef90f1fb1f112ea7c19ec55a8ed04720900eb7b5139fb6",
                "freshness": {
                    "observedAt": [2026, 294, 14, 8, 2, 0, 0, 0, 0],
                    "sourceUpdatedAt": [2026, 294, 14, 8, 2, 0, 0, 0, 0],
                    "staleAfterSeconds": null,
                    "state": "fresh"
                },
                "object": { "id": "approval:email-send:0021c839", "kind": "approval" },
                "revision": 1,
                "revisionSource": { "kind": "ledger" },
                "value": {
                    "approvalId": "approval:email-send:0021c839",
                    "argumentsDigest": "blake3:d783ee75c3e244ed77f463a29031e6dd79a0160be351ef3e10cfeca058fc50d1",
                    "capabilityId": "email.send",
                    "consumedByCommandId": null,
                    "decidedAt": null,
                    "decidedBy": null,
                    "decisionEvidenceRef": null,
                    "expiresAt": [2026, 294, 15, 8, 2, 0, 0, 0, 0],
                    "issuer": "sinmara",
                    "requestedAt": [2026, 294, 14, 8, 2, 0, 0, 0, 0],
                    "revision": 1,
                    "status": status,
                    "targetId": "sinmara",
                    "targetKind": "seat"
                }
            }))
            .expect("an approval snapshot")
        };
        let row = approval_row(&approval("requested")).expect("a requested approval is a row");
        assert_eq!(row["issuer"], json!("sinmara"));
        assert_eq!(row["capability"], json!("email.send"));
        assert_eq!(row["target"], json!("seat sinmara"));
        assert_eq!(row["requestedAt"], json!("2026-10-21T14:08:02Z"));
        assert!(approval_row(&approval("consumed")).is_none());
    }

    /// Live pods first, then those that ended within the day, newest first;
    /// an older run and a foreign object are not listed. Shapes are the
    /// live read model's.
    #[test]
    fn pods_are_the_live_ones_then_the_days_ended_ones() {
        let at = |day: u16, hour: u8, minute: u8| json!([2026, day, hour, minute, 0, 0, 0, 0, 0]);
        let pod = |profile: &str,
                   state: &str,
                   started: Value,
                   finished: Value,
                   odin: bool|
         -> live::ObjectSnapshot {
            let ownership = if odin {
                json!({ "odin": {
                    "attemptId": "workload-attempt-3a754d07eb89b4e050d4ad32dfa6484e",
                    "laneId": "kubert-odin",
                    "runId": format!("run:live:aef10d41-28d4-4dc7-a56a-36b719630c1e:pod:{profile}"),
                    "seatId": "kubert"
                } })
            } else {
                json!("foreign")
            };
            let resources = json!({ "cpuMillis": 2000, "ephemeralStorageBytes": 4294967296_u64, "gpuCount": 0, "memoryBytes": 2147483648_u64 });
            serde_json::from_value(json!({
                "contentDigest": "blake3:42f9088f2572c6e67fbe44fe91b34ed83065108bb2f351220d2ee99d8f7d7f30",
                "freshness": { "observedAt": at(294, 15, 44), "sourceUpdatedAt": at(294, 15, 44), "staleAfterSeconds": null, "state": "fresh" },
                "object": { "id": format!("default:Job:default:odin-{profile}"), "kind": "kubeResource" },
                "revision": 13,
                "revisionSource": { "kind": "kube" },
                "value": {
                    "containers": [], "finishedAt": finished, "limit": resources, "nodeId": null,
                    "observedAt": at(294, 15, 44), "ownership": ownership, "profile": profile,
                    "requested": resources,
                    "resource": { "apiVersion": "batch/v1", "cluster": "default", "kind": "Job",
                        "name": format!("odin-{profile}"), "namespace": "default", "uid": "a2515e85" },
                    "revision": 13, "stale": false, "startedAt": started, "state": state,
                    "usage": { "cpuMillis": 0, "ephemeralStorageBytes": 0, "gpuCount": 0, "memoryBytes": 0 },
                    "usageStale": true
                }
            }))
            .expect("a workload snapshot")
        };
        let objects = [
            pod(
                "acceptance-sweep-counter",
                "failed",
                at(289, 21, 8),
                at(289, 22, 8),
                true,
            ),
            pod(
                "floyds-times",
                "succeeded",
                at(294, 8, 58),
                at(294, 8, 59),
                true,
            ),
            pod("heat-sim", "running", at(294, 15, 56), Value::Null, true),
            pod(
                "someone-elses",
                "running",
                at(294, 15, 50),
                Value::Null,
                false,
            ),
        ];
        let now = time::Date::from_ordinal_date(2026, 294)
            .and_then(|day| day.with_hms(16, 0, 0))
            .expect("a time")
            .assume_utc();
        let rows = pod_rows(&objects, now);
        let names: Vec<&str> = rows.iter().filter_map(|row| row["name"].as_str()).collect();
        assert_eq!(names, ["heat-sim", "floyds-times"]);
        assert_eq!(rows[0]["state"], json!("running"));
        assert_eq!(rows[0]["seat"], json!("kubert"));
        assert_eq!(rows[0]["startedAt"], json!("2026-10-21T15:56:00Z"));
        assert_eq!(rows[1]["finishedAt"], json!("2026-10-21T08:59:00Z"));
    }

    /// Compaction is the `system`/`compact_boundary` record or the summary it
    /// replays, in the transcript's tail; the excerpt is a real session's.
    #[test]
    fn compaction_is_detected_in_the_transcript_tail() {
        let dir = tempfile::tempdir().expect("tempdir");
        let home = dir.path();
        let cwd = "/home/owner/wt/glm-overview";
        let session = "9a4a5c6e-1f2e-4c31-9d2a-3b2c1a0b9c8d";
        let projects = home.join(".claude/projects/-home-colin-wt-glm-overview");
        std::fs::create_dir_all(&projects).expect("projects directory");
        let transcript = projects.join(format!("{session}.jsonl"));
        std::fs::write(
            &transcript,
            concat!(
                "{\"type\":\"user\",\"message\":{\"role\":\"user\",\"content\":\"earlier turn\"}}\n",
                "{\"type\":\"system\",\"subtype\":\"turn_duration\",\"content\":\"2.1s\"}\n",
            ),
        )
        .expect("write the un-compacted tail");
        let path = transcript_path(home, cwd, session);
        assert_eq!(path, transcript);
        let mut scan = TranscriptScan::default();
        assert!(!compacted(&path, &mut scan));
        let read = scan.read;
        assert_eq!(read, std::fs::metadata(&path).expect("transcript").len());
        // A line still being written is not consumed.
        let mut file = std::fs::OpenOptions::new()
            .append(true)
            .open(&transcript)
            .expect("open the transcript");
        file.write_all(b"{\"type\":\"system\",\"subtype\":\"compact_")
            .expect("write a partial line");
        assert!(!compacted(&path, &mut scan));
        assert_eq!(scan.read, read);
        file.write_all(
            concat!(
                "boundary\",\"parentUuid\":null,\"isSidechain\":false,",
                "\"content\":\"Conversation compacted\",\"level\":\"info\",",
                "\"compactMetadata\":{\"trigger\":\"manual\",\"preTokens\":672144,\"postTokens\":17004}}\n",
                "{\"parentUuid\":\"85b48eb4\",\"isSidechain\":false,\"type\":\"user\",\"isCompactSummary\":true,",
                "\"message\":{\"role\":\"user\",\"content\":\"This session is being continued from a previous conversation.\"}}\n",
            )
            .as_bytes(),
        )
        .expect("write the compacted tail");
        assert!(compacted(&path, &mut scan));
        // A session with no transcript on this device is simply not compacted.
        assert!(!compacted(
            &transcript_path(home, "/home/owner", "00000000-0000-4000-8000-000000000000"),
            &mut TranscriptScan::default()
        ));
    }
}
