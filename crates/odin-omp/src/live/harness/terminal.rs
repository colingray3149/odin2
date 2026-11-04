//! The `terminal` harness protocol: the agent's real
//! interactive TUI program runs for the whole session in a terminal inside
//! the declared sandbox, and Odin drives it the way a person would. The
//! sandbox is a confined transient user unit whose main process is a tmux
//! server (`tmux -D`): everything the server starts runs inside the unit's
//! confinement, and stopping the unit stops all of it. Odin types prompts
//! into the agent (bracketed paste, then Enter), reads its screen
//! (`capture-pane`), and follows its transcript files for what it did — a
//! turn ends when the agent's last assistant record ends its turn. The
//! session's Zellij tab attaches to the same terminal, so the owner can watch
//! it or type into it from any paired device. Governance is `observed`:
//! the agent runs its own tools; the unit is the boundary.

use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};

use odin_domain::StopVerdict;
use odin_kernel::StopAuthority;
use odin_types::{CorrelationId, WorkerId};

use odin_domain::huginn::{LiveError, LiveMessage, SessionManifest};
use odin_registry::{AccountKind, DEFAULT_ACCOUNT};
use serde_json::{json, Value};
use tokio::io::AsyncWriteExt;
use tokio::process::Command;
use tokio::sync::{broadcast, watch};

use super::decode::{agent_end, assistant, prompt_result, OutputDecoder};
use super::driver::hand_back_note;
use super::watchdogs::{HarnessIncidentSink, Watchdogs};
use super::{fleet_host_argv, message_text, HarnessRoute, HarnessWorkspace};
use crate::bridge::ObservedFrame;
use crate::live::kernel_mcp::McpRegistration;
use crate::live::rollover::{ROLLOVER_ABSORB_INSTRUCTION, ROLLOVER_PROMPT_MARKER};

/// The tmux session (and window) the agent runs in.
const SESSION: &str = "main";
/// The terminal size the agent starts at (the tab resizes it on attach).
const COLUMNS: &str = "200";
const ROWS: &str = "50";
/// How often the followed transcript is read.
const POLL: Duration = Duration::from_millis(1_000);
/// `tmux has-session` is forked this many poll ticks apart. A dead server
/// is noticed within that interval; the transcript is still read every `POLL`.
const LIVENESS_TICKS: u32 = 4;
/// How long the unit's tmux socket is awaited, and how often it is looked for.
const SOCKET_WAIT: Duration = Duration::from_secs(5);
const SOCKET_POLL: Duration = Duration::from_millis(100);
/// Capture failures the startup watch rides out before it gives up answering questions.
const STARTUP_CAPTURE_FAILURES: u32 = 5;
/// Where Remote Control's phone link points when Claude recorded no session URL.
const CLAUDE_CODE_URL: &str = "https://claude.ai/code";

/// Timeout leaves an unfinished stop available for recovery, never reported as done.
const STOP_TIMEOUT: Duration = Duration::from_secs(20);

/// The waits a terminal session keeps: how long the TUI is given to take a paste before its submit
/// and to redraw after a slash command, and how often the transcript and the startup screen are
/// read. Tests shorten them all.
#[derive(Clone, Copy)]
struct Pacing {
    paste: Duration,
    slash: Duration,
    poll: Duration,
    startup: Duration,
}

impl Pacing {
    const LIVE: Self = Self {
        paste: Duration::from_millis(300),
        slash: Duration::from_millis(1_500),
        poll: POLL,
        startup: STARTUP_POLL,
    };
    #[cfg(test)]
    const QUICK: Self = Self {
        paste: Duration::ZERO,
        slash: Duration::ZERO,
        poll: Duration::from_millis(10),
        startup: Duration::from_millis(10),
    };
}

/// How long the startup screen is watched for a one-time question (long
/// enough for the owner to sign a fresh account in).
const STARTUP_WATCH: Duration = Duration::from_secs(30 * 60);
const STARTUP_POLL: Duration = Duration::from_secs(2);

/// The agent's input prompt is showing: startup is over.
pub fn screen_ready(screen: &str) -> bool {
    let lower = screen.to_ascii_lowercase();
    lower.contains("? for shortcuts") || lower.contains("bypass permissions on")
}

/// The workspace path as Claude Code names its project directory: every
/// character but ASCII letters and digits becomes `-`.
pub fn workspace_slug(workspace: &Path) -> String {
    workspace
        .to_string_lossy()
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() {
                character
            } else {
                '-'
            }
        })
        .collect()
}

/// What a declared command or path template's tokens expand to for one session: `{home}`,
/// `{workspace}`, `{workspace_slug}`, `{session}`, `{account_dir}`, `{mcp_config}` and `{bwrap}`.
/// A token with no value stays in the text, so a launch that still carries one refuses.
struct Tokens<'a> {
    home: &'a Path,
    workspace: &'a Path,
    session: &'a SessionManifest,
    /// The resolved login directory; the default account's when none was selected.
    account_dir: Option<&'a Path>,
    /// The kernel MCP file bound into the bubble.
    mcp_config: Option<&'a Path>,
    /// The runtime manifest's bubblewrap (`ODIN_BWRAP`).
    bwrap: Option<&'a str>,
}

fn expand(template: &str, tokens: &Tokens) -> String {
    let account = tokens
        .account_dir
        .map(Path::to_path_buf)
        .unwrap_or_else(|| default_claude_dir(tokens.home));
    let mut text = template
        .replace("{home}", &tokens.home.to_string_lossy())
        .replace("{workspace_slug}", &workspace_slug(tokens.workspace))
        .replace("{workspace}", &tokens.workspace.to_string_lossy())
        .replace("{session}", &tokens.session.session_id.to_string())
        .replace("{account_dir}", &account.to_string_lossy());
    if let Some(config) = tokens.mcp_config {
        text = text.replace("{mcp_config}", &config.to_string_lossy());
    }
    if let Some(bwrap) = tokens.bwrap {
        text = text.replace("{bwrap}", bwrap);
    }
    text
}

fn default_claude_dir(home: &Path) -> PathBuf {
    home.join(AccountKind::ClaudeCode.layout(DEFAULT_ACCOUNT).dir)
}

/// The command the agent runs: the declared one with its tokens expanded, plus the MCP config and
/// model flags the declaration names. A token left unexpanded (no `ODIN_BWRAP`, no kernel MCP
/// config) refuses: a governed harness never starts unconfined.
fn agent_command(route: &HarnessRoute, tokens: &Tokens) -> Result<Vec<String>, LiveError> {
    let harness = &route.harness;
    let mut agent: Vec<String> = harness
        .command
        .iter()
        .map(|argument| expand(argument, tokens))
        .collect();
    if agent
        .iter()
        .any(|argument| argument.contains("{bwrap}") || argument.contains("{mcp_config}"))
    {
        return Err(LiveError::unavailable(
            "terminal_bwrap_undeclared",
            "ODIN_BWRAP or the kernel MCP config is unset; a governed harness cannot start unconfined",
        ));
    }
    // The declared command may already name `--mcp-config`; the flag is appended only when it
    // does not, so the file is never missing.
    if let (Some(flag), Some(config)) = (&harness.mcp_config_arg, tokens.mcp_config) {
        let config = config.display().to_string();
        if !agent.contains(&config) {
            agent.push(flag.clone());
            agent.push(config);
        }
    }
    if let Some(flag) = &harness.model_arg {
        agent.push(flag.clone());
        agent.push(tokens.session.model.as_str().to_owned());
    }
    Ok(agent)
}

/// What the screen asks before the agent can work, and the keys that
/// answer it. A folder-trust question is answered yes (the workspace is
/// Odin's own clone for this session); a sign-in screen is the owner's to
/// answer, so it is reported, never typed into.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ScreenGate {
    /// A fresh account's first screen (pick a text style): the default.
    Theme,
    TrustFolder,
    /// The one-time consent to run without permission prompts, which the
    /// harness declares (`--dangerously-skip-permissions`) and the sandbox
    /// bounds: the second option ("Yes, I accept") is taken.
    BypassConsent,
    SignIn,
}

/// The question the screen is asking. A sign-in phrase counts only while the agent's input prompt
/// is not showing: a signed-in agent that quotes one on its screen is not signed out.
pub fn screen_gate(screen: &str) -> Option<ScreenGate> {
    let lower = screen.to_ascii_lowercase();
    if (lower.contains("select login method")
        || lower.contains("sign in with")
        || lower.contains("paste code here"))
        && !screen_ready(screen)
    {
        Some(ScreenGate::SignIn)
    } else if lower.contains("choose the text style") {
        Some(ScreenGate::Theme)
    } else if lower.contains("bypass permissions mode") && lower.contains("yes, i accept") {
        Some(ScreenGate::BypassConsent)
    } else if lower.contains("do you trust the files in this folder")
        || (lower.contains("trust") && lower.contains("yes, proceed"))
    {
        Some(ScreenGate::TrustFolder)
    } else {
        None
    }
}

/// A slash command (`/clear`, `/model opus`): typed, never awaited as a
/// turn — it ends no assistant turn in the transcript.
pub fn is_slash_command(text: &str) -> bool {
    let text = text.trim();
    text.starts_with('/') && !text.contains('\n') && text.len() > 1
}

struct TermState {
    turns: u64,
    /// The running turn's id; `None` between turns.
    running: Option<String>,
    /// The agent has had the declared brief.
    briefed: bool,
    closed: bool,
}

pub(super) struct TerminalControl {
    manifest: SessionManifest,
    route: HarnessRoute,
    workspace: PathBuf,
    /// The selected account's Claude directory. Named accounts live under
    /// `~/.claude-accounts/<name>`; default is `~/.claude`. Never inferred
    /// as the home default when a named directory was selected.
    claude_dir: PathBuf,
    /// The tmux server this session started: pid and `/proc` start ticks.
    /// Registration evidence must belong to a live descendant of this process.
    session_process: Option<ProcessStamp>,
    registration_since: SystemTime,
    transport: TerminalTransport,
    pacing: Pacing,
    frames: broadcast::Sender<ObservedFrame>,
    failed: watch::Sender<Option<String>>,
    state: Arc<Mutex<TermState>>,
    stop_follow: watch::Sender<bool>,
    stopped: tokio::sync::Mutex<bool>,
    incidents: Option<Arc<dyn HarnessIncidentSink>>,
    /// The session's kernel MCP endpoint; dropped with the control.
    _kernel: Option<McpRegistration>,
    rollover: super::terminal_rollover::TerminalRollover,
}

/// A terminal control over a scripted tmux client, with what a test watches of it.
#[cfg(test)]
pub(super) struct Scripted {
    pub control: Arc<TerminalControl>,
    pub frames: broadcast::Receiver<ObservedFrame>,
    pub failed: watch::Receiver<Option<String>>,
    pub follow_stopped: watch::Receiver<bool>,
}

#[cfg(test)]
impl TerminalControl {
    /// A control over a scripted tmux client (its argv): no unit to stop, no kernel bridge, no pauses.
    pub(super) fn scripted(
        manifest: &SessionManifest,
        route: HarnessRoute,
        workspace: PathBuf,
        exec: Vec<String>,
    ) -> Scripted {
        let (frames, received) = broadcast::channel(64);
        let (failed, failed_rx) = watch::channel(None);
        let (stop_follow, follow_stopped) = watch::channel(false);
        let control = Arc::new(Self {
            manifest: manifest.clone(),
            route,
            claude_dir: workspace.join(".claude"),
            workspace,
            session_process: None,
            registration_since: SystemTime::now(),
            transport: TerminalTransport::Scripted { exec },
            pacing: Pacing::QUICK,
            frames,
            failed,
            state: Arc::new(Mutex::new(TermState {
                turns: 0,
                running: None,
                briefed: false,
                closed: false,
            })),
            stop_follow,
            stopped: tokio::sync::Mutex::new(false),
            incidents: None,
            _kernel: None,
            rollover: super::terminal_rollover::TerminalRollover::new(),
        });
        Scripted {
            control,
            frames: received,
            failed: failed_rx,
            follow_stopped,
        }
    }
}

/// One process as the kernel sees it: pid plus start ticks, so a reused pid is not this process.
#[derive(Clone, Copy, Debug)]
pub(super) struct ProcessStamp {
    pid: u32,
    start_ticks: u64,
}

/// The session's own runtime directory, bound into its sandbox: the tmux
/// socket and the MCP config live here.
pub(super) fn runtime_dir(session: &str) -> PathBuf {
    super::session_runtime_dir("odin-term", session)
}

/// The Claude Code MCP config of a terminal session.
pub(super) fn terminal_mcp_config(session: &str) -> PathBuf {
    runtime_dir(session).join("mcp.json")
}

/// The terminal stop row's correlation, derived from the session id's hex
/// so a restarted daemon re-derives the same correlation and scopes
/// recovery to exactly this session's rows.
fn terminal_correlation(session: &str) -> Result<CorrelationId, LiveError> {
    CorrelationId::new(&session.replace('-', ""))
        .map_err(|error| LiveError::unavailable("terminal_session_correlation", error))
}

pub(super) fn unsupported(operation: &str, harness: &str) -> LiveError {
    LiveError::Unsupported {
        operation: format!("{operation} is not available under the {harness} harness"),
    }
}

/// Stops through the registered worker; errors leave the row nonterminal for recovery.
async fn stop_registered_terminal(
    stops: &Arc<StopAuthority>,
    worker_id: &WorkerId,
) -> Result<(), LiveError> {
    let worker = worker_id.as_str().to_owned();
    let stops = Arc::clone(stops);
    let worker_id = worker_id.clone();
    match tokio::time::timeout(
        STOP_TIMEOUT,
        tokio::task::spawn_blocking(move || stops.stop_worker(&worker_id)),
    )
    .await
    {
        Ok(Ok(Ok(outcome))) => {
            if !matches!(outcome.verdict, StopVerdict::Stopped) {
                tracing::error!(
                    "odind: terminal stop worker={} verdict={:?} left recoverable",
                    outcome.worker_id.as_str(),
                    outcome.verdict
                );
                return Err(LiveError::unavailable(
                    "terminal_unit_stop_unconfirmed",
                    format!("{worker} stopped with verdict {:?}", outcome.verdict),
                ));
            }
        }
        Ok(Ok(Err(error))) => {
            tracing::error!("odind: terminal stop worker={worker} error={error} left recoverable");
            return Err(LiveError::unavailable("terminal_unit_stop", error));
        }
        Ok(Err(error)) => {
            return Err(LiveError::unavailable("terminal_unit_stop_join", error));
        }
        Err(_) => {
            tracing::error!("odind: terminal stop exceeded its bound; the row stays recoverable");
            return Err(LiveError::unavailable(
                "terminal_unit_stop_timeout",
                format!("{worker} did not stop within its bound"),
            ));
        }
    }
    Ok(())
}

/// Transport for tmux commands; typing, observation, and hand-back are shared.
pub(super) enum TerminalTransport {
    /// Local tmux socket in a registered unit; its name alone cannot authorize signals.
    Unit {
        tmux: PathBuf,
        socket: PathBuf,
        unit: String,
        path: String,
        stops: Arc<StopAuthority>,
        worker_id: WorkerId,
    },
    /// Tests: a scripted tmux client (its argv), with nothing to stop.
    #[cfg(test)]
    Scripted { exec: Vec<String> },
}

impl TerminalTransport {
    /// A tmux client command, ready for its arguments.
    fn tmux(&self) -> Command {
        match self {
            Self::Unit {
                tmux, socket, path, ..
            } => tmux_command(tmux, socket, path),
            #[cfg(test)]
            Self::Scripted { exec } => {
                let mut command = Command::new(&exec[0]);
                command
                    .args(&exec[1..])
                    .stdin(Stdio::null())
                    .stdout(Stdio::piped())
                    .stderr(Stdio::piped())
                    .kill_on_drop(true);
                command
            }
        }
    }

    /// The argv the session's tab runs to attach to the same terminal.
    fn attach(&self) -> Vec<String> {
        match self {
            Self::Unit { tmux, socket, .. } => vec![
                tmux.to_string_lossy().into_owned(),
                "-S".to_owned(),
                socket.to_string_lossy().into_owned(),
                "attach-session".to_owned(),
                "-t".to_owned(),
                SESSION.to_owned(),
            ],
            #[cfg(test)]
            Self::Scripted { .. } => Vec::new(),
        }
    }

    fn describe(&self) -> String {
        match self {
            Self::Unit { unit, socket, .. } => {
                format!("unit={unit} socket={}", socket.display())
            }
            #[cfg(test)]
            Self::Scripted { .. } => "scripted".to_owned(),
        }
    }

    /// The tmux server this session proved, when the unit path captured one.
    fn session_process(&self) -> Option<ProcessStamp> {
        match self {
            Self::Unit {
                stops, worker_id, ..
            } => session_process(stops, worker_id),
            #[cfg(test)]
            Self::Scripted { .. } => None,
        }
    }

    /// Stops the terminal's unit through its durable identity row — never
    /// by name.
    async fn stop(&self) -> Result<(), LiveError> {
        match self {
            Self::Unit {
                stops, worker_id, ..
            } => {
                stop_registered_terminal(stops, worker_id).await?;
            }
            #[cfg(test)]
            Self::Scripted { .. } => {}
        }
        Ok(())
    }
}

/// Everything one opened terminal session needs to start.
pub(super) struct TerminalStart<'a> {
    /// The daemon's home: programs, accounts and transcripts resolve under it.
    pub home: &'a Path,
    pub manifest: &'a SessionManifest,
    pub route: HarnessRoute,
    pub workspace: PathBuf,
    /// The resolved account directory under home, when the harness signs in.
    pub account_dir: Option<PathBuf>,
    pub hand_back: Arc<dyn HarnessWorkspace>,
    pub frames: broadcast::Sender<ObservedFrame>,
    pub failed: watch::Sender<Option<String>>,
    pub incidents: Option<Arc<dyn HarnessIncidentSink>>,
    /// The kernel MCP bridge registration and the config it was written to.
    pub kernel: Option<(McpRegistration, PathBuf)>,
    /// Required for registering and stopping a unit terminal.
    pub stops: Option<Arc<StopAuthority>>,
}

impl TerminalControl {
    fn tmux(&self) -> Command {
        self.transport.tmux()
    }

    /// Runs one tmux client action in its own process group and collects
    /// its output; a cancellation or drop takes the group with it.
    async fn tmux_output(
        &self,
        code: &str,
        arguments: &[&str],
    ) -> Result<std::process::Output, LiveError> {
        let mut client = self.tmux();
        client.args(arguments);
        let group = GroupChild::spawn(&mut client)
            .map_err(|error| LiveError::unavailable(format!("{code}_spawn"), error))?;
        group
            .output()
            .await
            .map_err(|error| LiveError::unavailable(code, error))
    }

    /// Starts the sandboxed terminal and the agent in it, the transcript
    /// follower and the startup watch. Returns the control and the argv
    /// the session's tab runs to attach to the same terminal.
    pub(super) async fn start(
        start: TerminalStart<'_>,
    ) -> Result<(Arc<Self>, Vec<String>), LiveError> {
        let home = start.home;
        let bwrap = std::env::var("ODIN_BWRAP").ok();
        let tokens = Tokens {
            home,
            workspace: &start.workspace,
            session: start.manifest,
            account_dir: start.account_dir.as_deref(),
            mcp_config: start.kernel.as_ref().map(|(_, config)| config.as_path()),
            bwrap: bwrap.as_deref(),
        };
        let agent = agent_command(&start.route, &tokens)?;
        let transport = Self::start_unit(&start, home).await?;
        // The one client that legitimately starts the server: a normal
        // completion never signals its group (the daemonized server leaves
        // it), but an aborted start takes client and half-started server
        // with it before the unit stop below.
        let registration_since = SystemTime::now();
        let mut client = transport.tmux();
        client
            .args([
                "new-session",
                "-d",
                "-s",
                SESSION,
                "-x",
                COLUMNS,
                "-y",
                ROWS,
                "-c",
            ])
            .arg(&start.workspace)
            .arg("--")
            .args(&agent);
        let group = GroupChild::spawn(&mut client)
            .map_err(|error| LiveError::unavailable("terminal_agent_spawn", error))?;
        let output = group
            .output()
            .await
            .map_err(|error| LiveError::unavailable("terminal_agent_spawn", error))?;
        if !output.status.success() {
            transport.stop().await?;
            return Err(LiveError::unavailable(
                "terminal_agent_start",
                String::from_utf8_lossy(&output.stderr).trim(),
            ));
        }
        let transcripts = PathBuf::from(expand(
            start
                .route
                .harness
                .transcripts
                .as_deref()
                .unwrap_or_default(),
            &tokens,
        ));
        tracing::info!(
            "odind: terminal open session={} seat={} harness={} {} transcripts={} \
             governance=observed",
            start.manifest.session_id,
            start.manifest.seat_id,
            start.route.harness_id,
            transport.describe(),
            transcripts.display()
        );
        let (stop_follow, follow_stopped) = watch::channel(false);
        let session_process = transport.session_process();
        let control = Arc::new(Self {
            manifest: start.manifest.clone(),
            route: start.route,
            workspace: start.workspace,
            claude_dir: start
                .account_dir
                .clone()
                .unwrap_or_else(|| default_claude_dir(home)),
            session_process,
            registration_since,
            frames: start.frames,
            failed: start.failed,
            state: Arc::new(Mutex::new(TermState {
                turns: 0,
                running: None,
                briefed: false,
                closed: false,
            })),
            stop_follow,
            stopped: tokio::sync::Mutex::new(false),
            incidents: start.incidents,
            _kernel: start.kernel.map(|(registration, _)| registration),
            transport,
            pacing: Pacing::LIVE,
            rollover: super::terminal_rollover::TerminalRollover::new(),
        });
        tokio::spawn(Arc::clone(&control).watch_startup());
        tokio::spawn(Arc::clone(&control).follow(transcripts, start.hand_back, follow_stopped));
        let attach = control.transport.attach();
        Ok((control, attach))
    }

    /// Binds the selected card window and the seat's rollover policy.
    pub(super) fn bind_rollover(
        &self,
        policy: crate::live::rollover::RolloverPolicy,
        window: u64,
        ceiling: u64,
        completed: u32,
        store: Option<std::path::PathBuf>,
    ) {
        self.rollover
            .bind(policy, window, ceiling, completed, store);
    }

    /// `/clear` starts a new Claude transcript. The continuity brief is the
    /// next turn. The caller commits the count only after both writes succeed.
    pub(super) async fn roll_context(&self) -> Result<(), LiveError> {
        self.type_line("/clear").await?;
        tokio::time::sleep(self.pacing.slash).await;
        let brief = format!(
            "{ROLLOVER_PROMPT_MARKER} session={} trigger=threshold] {ROLLOVER_ABSORB_INSTRUCTION}",
            self.manifest.session_id
        );
        self.type_line(&brief).await
    }

    /// Starts the session's sandboxed unit running the tmux server.
    async fn start_unit(
        start: &TerminalStart<'_>,
        home: &Path,
    ) -> Result<TerminalTransport, LiveError> {
        let home = home.to_path_buf();
        let path = path_env(&home);
        let tmux = find_program("tmux", &home).ok_or_else(|| {
            LiveError::unavailable(
                "terminal_tmux_missing",
                "tmux is on none of the session's program paths",
            )
        })?;
        let short = super::short_session(&start.manifest.session_id.to_string());
        let unit = format!("odin-term-{short}");
        let unit_service = format!("{unit}.service");
        // The stop authority is not optional on the unit path: the durable
        // row is the only thing that makes this unit ours.
        let Some(stops) = start.stops.as_ref() else {
            return Err(LiveError::unavailable(
                "terminal_stop_authority_missing",
                "the unit path has no stop authority",
            ));
        };
        let correlation = terminal_correlation(&start.manifest.session_id.to_string())?;
        // Persist intent before launch so failed starts remain available for recovery.
        let worker_id = {
            let stops = Arc::clone(stops);
            let unit_service = unit_service.clone();
            tokio::task::spawn_blocking(move || {
                stops.register_terminal_intent(&unit_service, &correlation)
            })
            .await
            .map_err(|error| LiveError::unavailable("terminal_intent", error))?
            .map_err(|error| LiveError::unavailable("terminal_intent", error))?
        };
        // The socket lives in a directory of this session's own, bound into
        // the sandbox: a private home hides /run/user, and another session's
        // sandbox must not reach this terminal.
        let runtime = runtime_dir(&start.manifest.session_id.to_string());
        tokio::fs::create_dir_all(&runtime)
            .await
            .map_err(|error| LiveError::unavailable("terminal_runtime_dir", error))?;
        let socket = runtime.join("tmux.sock");
        let _ = tokio::fs::remove_file(&socket).await;
        // The unit's main process is the tmux server: its confinement is
        // the declared environment's, plus the socket's directory.
        let server = vec![
            tmux.to_string_lossy().into_owned(),
            "-S".to_owned(),
            socket.to_string_lossy().into_owned(),
            "-f".to_owned(),
            "/dev/null".to_owned(),
            "-D".to_owned(),
        ];
        let mut argv = fleet_host_argv(&unit, &home, &start.workspace, &start.route, &server);
        argv.retain(|argument| argument != "--pipe");
        if let Some(split) = argv.iter().position(|argument| argument == "--") {
            argv.splice(
                split..split,
                ["-p".to_owned(), format!("BindPaths={}", runtime.display())],
            );
        }
        let status = Command::new(&argv[0])
            .args(&argv[1..])
            .env("PATH", &path)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .output()
            .await
            .map_err(|error| LiveError::unavailable("terminal_unit_spawn", error))?;
        if !status.status.success() {
            // The launch failed: no unit exists, and the journaled stop
            // settles the intent row as honestly absent.
            stop_registered_terminal(stops, &worker_id).await?;
            return Err(LiveError::unavailable(
                "terminal_unit_start",
                String::from_utf8_lossy(&status.stderr).trim(),
            ));
        }
        // Validate the unit and tmux process identities before allowing agent activity.
        {
            // Keep the outer handles available to stop the worker if validation fails.
            let proof_stops = Arc::clone(stops);
            let proof_worker = worker_id.clone();
            let proof_unit = unit_service.clone();
            match tokio::task::spawn_blocking(move || {
                proof_stops.prove_terminal_unit(&proof_worker, &proof_unit)
            })
            .await
            {
                Ok(Ok(_identity)) => {}
                Ok(Err(error)) => {
                    tracing::error!(
                        "odind: terminal unit unproven session={} unit={unit_service} \
                         reason={error}; the intent row stays for recovery",
                        start.manifest.session_id
                    );
                    stop_registered_terminal(stops, &worker_id).await?;
                    return Err(LiveError::unavailable("terminal_unit_identity", error));
                }
                Err(error) => {
                    stop_registered_terminal(stops, &worker_id).await?;
                    return Err(LiveError::unavailable("terminal_unit_identity", error));
                }
            }
        }
        // Require the unit's socket: otherwise tmux may start an unconfined server.
        let mut up = false;
        let give_up = Instant::now() + SOCKET_WAIT;
        while Instant::now() < give_up {
            if tokio::fs::metadata(&socket).await.is_ok() {
                up = true;
                break;
            }
            tokio::time::sleep(SOCKET_POLL).await;
        }
        // Unit activity was checked above; the socket establishes client readiness.
        if !up {
            tracing::error!(
                "odind: terminal sandbox-failed session={} unit={unit} worker={} \
                 socket_up=false",
                start.manifest.session_id,
                worker_id.as_str()
            );
            stop_registered_terminal(stops, &worker_id).await?;
            return Err(LiveError::unavailable(
                "terminal_sandbox_failed",
                format!("unit {unit} did not come up"),
            ));
        }
        Ok(TerminalTransport::Unit {
            tmux,
            socket,
            unit,
            path,
            stops: Arc::clone(stops),
            worker_id,
        })
    }

    fn emit(&self, frame: Value) {
        let _ = self.frames.send(ObservedFrame::harness_event(frame));
    }

    /// The agent's current screen (the visible pane).
    pub(super) async fn screen(&self) -> Result<String, LiveError> {
        let output = self
            .tmux_output("terminal_capture", &["capture-pane", "-p", "-t", SESSION])
            .await?;
        if !output.status.success() {
            return Err(LiveError::unavailable(
                "terminal_closed",
                "tmux refused the capture",
            ));
        }
        Ok(String::from_utf8_lossy(&output.stdout)
            .trim_end()
            .to_owned())
    }

    async fn keys(&self, keys: &[&str]) -> Result<(), LiveError> {
        let mut arguments = vec!["send-keys", "-t", SESSION];
        arguments.extend_from_slice(keys);
        let output = self.tmux_output("terminal_keys", &arguments).await?;
        if output.status.success() {
            Ok(())
        } else {
            Err(LiveError::unavailable(
                "terminal_closed",
                "tmux refused the keys",
            ))
        }
    }

    /// Types `text` as one paste (newlines stay inside the prompt), then
    /// Enter.
    pub(super) async fn type_line(&self, text: &str) -> Result<(), LiveError> {
        // The paste load keeps its stdin open while writing; the guard
        // owns the child the whole time, so a cancelled paste never leaks
        // the load client.
        let mut client = self.tmux();
        client
            .args(["load-buffer", "-b", "odin", "-"])
            .stdin(Stdio::piped());
        let mut load = GroupChild::spawn(&mut client)
            .map_err(|error| LiveError::unavailable("terminal_paste", error))?;
        {
            let child = load.child.as_mut().expect("load client present");
            if let Some(mut stdin) = child.stdin.take() {
                stdin
                    .write_all(text.as_bytes())
                    .await
                    .map_err(|error| LiveError::unavailable("terminal_paste", error))?;
            }
            let loaded = child
                .wait()
                .await
                .map_err(|error| LiveError::unavailable("terminal_paste", error))?;
            // Reaped: the guard goes inert and never signals the group.
            load.child = None;
            if !loaded.success() {
                return Err(LiveError::unavailable(
                    "terminal_closed",
                    "tmux refused the paste load",
                ));
            }
        }
        let pasted = self
            .tmux_output(
                "terminal_paste",
                &["paste-buffer", "-p", "-d", "-b", "odin", "-t", SESSION],
            )
            .await?;
        if !pasted.status.success() {
            return Err(LiveError::unavailable(
                "terminal_closed",
                "tmux refused the paste",
            ));
        }
        // The TUI takes the paste before the submit key.
        tokio::time::sleep(self.pacing.paste).await;
        self.keys(&["Enter"]).await
    }

    /// A one-time question on the startup screen: folder trust is answered,
    /// a sign-in screen is reported for the owner.
    async fn watch_startup(self: Arc<Self>) {
        let deadline = tokio::time::Instant::now() + STARTUP_WATCH;
        let mut sign_in_reported = false;
        let mut capture_failures = 0;
        while tokio::time::Instant::now() < deadline {
            tokio::time::sleep(self.pacing.startup).await;
            let screen = match self.screen().await {
                Ok(screen) => screen,
                Err(error) => {
                    capture_failures += 1;
                    tracing::warn!(
                        "odind: terminal startup capture failed session={} failures={capture_failures} error={error}",
                        self.manifest.session_id
                    );
                    if capture_failures >= STARTUP_CAPTURE_FAILURES {
                        return;
                    }
                    continue;
                }
            };
            capture_failures = 0;
            let gate = screen_gate(&screen);
            if gate.is_none() && screen_ready(&screen) {
                tracing::info!(
                    "odind: terminal ready session={} harness={}",
                    self.manifest.session_id,
                    self.route.harness_id
                );
                self.note_remote_control(BridgeRegistration::Requested);
                tokio::spawn(Arc::clone(&self).watch_remote_control());
                return;
            }
            match gate {
                Some(ScreenGate::Theme) => {
                    let _ = self.keys(&["Enter"]).await;
                }
                Some(ScreenGate::TrustFolder) => {
                    tracing::info!(
                        "odind: terminal trust-folder answered session={} harness={}",
                        self.manifest.session_id,
                        self.route.harness_id
                    );
                    let _ = self.keys(&["Enter"]).await;
                }
                Some(ScreenGate::BypassConsent) => {
                    tracing::info!(
                        "odind: terminal bypass-consent answered session={} harness={} \
                         (declared by the harness, bounded by the sandbox)",
                        self.manifest.session_id,
                        self.route.harness_id
                    );
                    let _ = self.keys(&["Down"]).await;
                    let _ = self.keys(&["Enter"]).await;
                }
                Some(ScreenGate::SignIn) if sign_in_reported => {}
                Some(ScreenGate::SignIn) => {
                    sign_in_reported = true;
                    tracing::warn!(
                        "odind: terminal needs-sign-in session={} harness={}",
                        self.manifest.session_id,
                        self.route.harness_id
                    );
                    self.emit(assistant(
                        "[this agent's account is signed out: the owner signs in once in its terminal tab]",
                    ));
                }
                None => {}
            }
        }
    }

    /// Whether the declared command asked Claude to enable Remote Control.
    /// Argv is a request, not proof the bridge registered.
    fn remote_control_requested(&self) -> bool {
        self.route
            .harness
            .command
            .iter()
            .any(|argument| argument == "--remote-control")
    }

    /// Reports Remote Control only from a confirmed bridge registration.
    /// Until Claude records one, the note says requested; a rejected or
    /// unreadable registration is a failure, never "on".
    fn note_remote_control(&self, registration: BridgeRegistration) {
        if !self.remote_control_requested() && registration == BridgeRegistration::Unknown {
            return;
        }
        let name = self
            .manifest
            .title
            .clone()
            .filter(|title| !title.is_empty())
            .unwrap_or_else(|| self.manifest.seat_id.to_string());
        let text = match &registration {
            BridgeRegistration::Active { session_url: Some(session_url) } => format!(
                "Remote Control is on for {name}. The hub tab is this session; the phone joins at {session_url}."
            ),
            BridgeRegistration::Active { session_url: None } => format!(
                "Remote Control is on for {name}. The hub tab is this session; the phone joins at {CLAUDE_CODE_URL}."
            ),
            BridgeRegistration::Requested => format!(
                "Remote Control was requested for {name}. It is not on until Claude records the bridge."
            ),
            BridgeRegistration::Unknown => format!(
                "Remote Control for {name} is unknown: Claude has not recorded a bridge session."
            ),
            BridgeRegistration::Failed { reason } => format!(
                "Remote Control failed for {name}: {reason}"
            ),
        };
        self.emit(assistant(&text));
    }

    /// Polls Claude's own session record for this seat. "On" requires the
    /// bridge session id Claude writes after registration. A control error
    /// in that record is a failure. The screen becoming ready is not proof.
    async fn watch_remote_control(self: Arc<Self>) {
        if !self.remote_control_requested() {
            return;
        }
        let deadline = tokio::time::Instant::now() + STARTUP_WATCH;
        while tokio::time::Instant::now() < deadline {
            if self.stop_in_flight() || self.state.lock().map(|state| state.closed).unwrap_or(true)
            {
                return;
            }
            match claude_bridge_registration(
                &self.claude_dir,
                &self.workspace,
                &self.manifest.session_id.to_string(),
                self.session_process,
                self.registration_since,
            )
            .await
            {
                BridgeRegistration::Active { session_url } => {
                    self.note_remote_control(BridgeRegistration::Active { session_url });
                    return;
                }
                BridgeRegistration::Failed { reason } => {
                    self.note_remote_control(BridgeRegistration::Failed { reason });
                    return;
                }
                BridgeRegistration::Requested | BridgeRegistration::Unknown => {}
            }
            tokio::time::sleep(self.pacing.startup).await;
        }
        self.note_remote_control(BridgeRegistration::Unknown);
    }

    fn signed_out_error(&self) -> LiveError {
        LiveError::unavailable(
            "terminal_signed_out",
            format!(
                "the {} account needs a sign-in in its terminal",
                self.route.harness_id
            ),
        )
    }

    pub(super) async fn start_turn(&self, message: &LiveMessage) -> Result<(), LiveError> {
        let prompt = message_text(message);
        if prompt.trim().is_empty() {
            return Err(LiveError::InvalidRequest {
                code: "harness_prompt_empty".to_owned(),
                message: "the prompt carries no text".to_owned(),
            });
        }
        if screen_gate(&self.screen().await?) == Some(ScreenGate::SignIn) {
            return Err(self.signed_out_error());
        }
        let slash = is_slash_command(&prompt);
        let (turn_id, text, briefing) = {
            let mut state = self
                .state
                .lock()
                .map_err(|error| LiveError::unavailable("terminal_state", error))?;
            if state.closed {
                return Err(LiveError::Conflict {
                    code: "harness_session_closed".to_owned(),
                    message: "the session was stopped".to_owned(),
                });
            }
            if state.running.is_some() {
                return Err(LiveError::Conflict {
                    code: "harness_turn_running".to_owned(),
                    message: format!(
                        "{} is still working on the last prompt; steer to add to it",
                        self.route.harness_id
                    ),
                });
            }
            state.turns += 1;
            let turn_id = format!("{}-turn-{}", self.route.harness_id, state.turns);
            let briefing = !state.briefed && !slash;
            let text = match (&self.route.harness.brief, briefing) {
                (Some(brief), true) => format!("{}\n\n{prompt}", brief.trim()),
                _ => prompt.clone(),
            };
            if !slash {
                state.running = Some(turn_id.clone());
            }
            (turn_id, text, briefing)
        };
        tracing::info!(
            "odind: terminal turn session={} harness={} turn={turn_id} slash={slash}",
            self.manifest.session_id,
            self.route.harness_id
        );
        self.emit(json!({"type": "agent_start", "turnId": turn_id}));
        if let Err(error) = self.type_line(&text).await {
            if let Ok(mut state) = self.state.lock() {
                state.running = None;
            }
            return Err(error);
        }
        if briefing {
            if let Ok(mut state) = self.state.lock() {
                state.briefed = true;
            }
        }
        if slash {
            // A slash command ends no turn in the transcript: its answer
            // is what the screen shows once it has redrawn.
            tokio::time::sleep(self.pacing.slash).await;
            let screen = self.screen().await.unwrap_or_default();
            let summary = format!("Typed {}. The screen now shows:\n{screen}", text.trim());
            self.emit(agent_end(Some(&turn_id), None, None));
            self.emit(prompt_result(Some(&turn_id), &summary));
        }
        Ok(())
    }

    /// A hand-back may finish after an interrupt and a new prompt. Retire
    /// only its original turn, keeping emission ordered with that retirement.
    fn end_matching_turn(&self, expected: &str, text: String, usage: Option<&Value>) {
        let Ok(mut state) = self.state.lock() else {
            return;
        };
        // The hand-back awaited while a session stop may have begun settling:
        // a stopping session never emits a synthetic answer.
        if state.running.as_deref() != Some(expected) || self.stop_in_flight() {
            return;
        }
        let turn_id = state.running.take().expect("matching running turn");
        drop(state);
        self.emit(agent_end(Some(&turn_id), None, usage));
        self.emit(prompt_result(Some(&turn_id), &text));
    }

    async fn finish_turn(
        &self,
        turn_id: &str,
        mut summary: String,
        hand_back: &dyn HarnessWorkspace,
        usage: Option<&Value>,
    ) {
        let note = hand_back_note(
            hand_back
                .hand_back(&self.manifest, &self.route, &self.workspace)
                .await,
        );
        if let Some(note) = note {
            if !summary.is_empty() {
                summary.push_str("\n\n");
            }
            summary.push_str(&note);
        }
        tracing::info!(
            "odind: terminal turn_end session={} harness={}",
            self.manifest.session_id,
            self.route.harness_id
        );
        self.end_matching_turn(turn_id, summary, usage);
    }

    /// Intentional control settlement belongs to the actor's ControlEffect,
    /// not an asynchronous provider failure or a fabricated task answer.
    pub(super) async fn interrupt_turn(&self) -> Result<(), LiveError> {
        self.keys(&["Escape"]).await?;
        self.state
            .lock()
            .map_err(|error| LiveError::unavailable("terminal_state", error))?
            .running = None;
        Ok(())
    }

    /// `usage` is the provider's own object from the transcript. Absent, the
    /// frame carries no usage and rollover treats the turn as unmeasured.
    fn end_turn_with(&self, text: String, failure: Option<&str>, usage: Option<&Value>) {
        let turn = self
            .state
            .lock()
            .ok()
            .and_then(|mut state| state.running.take());
        let Some(turn_id) = turn else { return };
        self.emit(agent_end(Some(&turn_id), failure, usage));
        self.emit(prompt_result(Some(&turn_id), &text));
    }

    /// Suppresses failure and turn completion observations during deliberate stop.
    fn stop_in_flight(&self) -> bool {
        self.stopped
            .try_lock()
            .map(|stopped| *stopped)
            .unwrap_or(true)
    }

    pub(super) async fn close(&self) -> Result<(), LiveError> {
        let mut stopped = self.stopped.lock().await;
        if *stopped {
            return Ok(());
        }
        tracing::info!(
            "odind: terminal stop session={} harness={} {}",
            self.manifest.session_id,
            self.route.harness_id,
            self.transport.describe()
        );
        self.transport.stop().await?;
        // Retire the turn even if input closed, preventing stale hand-back after stop.
        {
            let mut state = self
                .state
                .lock()
                .map_err(|error| LiveError::unavailable("terminal_state", error))?;
            state.closed = true;
            state.running = None;
        }
        let _ = self.stop_follow.send(true);
        *stopped = true;
        let _ = tokio::fs::remove_dir_all(runtime_dir(&self.manifest.session_id.to_string())).await;
        Ok(())
    }

    /// Follows the newest transcript file in `dir` (a cleared context
    /// starts a new one), turns its records into frames, ends the running
    /// turn on the agent's end of turn (handing the work back), and notices
    /// the agent's terminal closing.
    async fn follow(
        self: Arc<Self>,
        dir: PathBuf,
        hand_back: Arc<dyn HarnessWorkspace>,
        mut stopped: watch::Receiver<bool>,
    ) {
        // A transcript older than the session is history.
        let opened = self.registration_since;
        let mut current: Option<PathBuf> = None;
        let mut offset: u64 = 0;
        let mut partial = String::new();
        let mut decoder = OutputDecoder::new(self.route.harness.output, &self.route.harness_id);
        let mut last_text = String::new();
        let mut poll = tokio::time::interval(self.pacing.poll);
        let mut tick = 0u32;
        let mut dir_mtime: Option<SystemTime> = None;
        let mut watchdogs = Watchdogs::new(&self.route);
        loop {
            tokio::select! {
                _ = stopped.changed() => if *stopped.borrow() { break },
                _ = poll.tick() => {}
            }
            // The agent's terminal is gone: the session cannot go on.
            // Checked every few seconds, not every transcript poll.
            if tick.is_multiple_of(LIVENESS_TICKS) {
                // A probe that could not run says nothing about the terminal; only a completed
                // `has-session` that fails means it is gone.
                let alive = match self
                    .tmux_output("terminal_liveness", &["has-session", "-t", SESSION])
                    .await
                {
                    Ok(output) => output.status.success(),
                    Err(error) => {
                        tracing::warn!(
                            "odind: terminal liveness probe failed session={} error={error}",
                            self.manifest.session_id
                        );
                        true
                    }
                };
                if !alive && !self.stop_in_flight() {
                    tracing::info!(
                        "odind: terminal closed session={} harness={}",
                        self.manifest.session_id,
                        self.route.harness_id
                    );
                    let _ = self
                        .failed
                        .send(Some("the agent's terminal closed".to_owned()));
                    self.end_turn_with(
                        last_text.clone(),
                        Some("the agent's terminal closed"),
                        decoder.usage(),
                    );
                    if let Ok(mut state) = self.state.lock() {
                        state.closed = true;
                    }
                    break;
                }
            }
            tick = tick.wrapping_add(1);
            let followed_exists = match &current {
                Some(path) => tokio::fs::try_exists(path).await.unwrap_or(false),
                None => false,
            };
            let mtime = tokio::fs::metadata(&dir)
                .await
                .ok()
                .and_then(|meta| meta.modified().ok());
            let dir_changed = match (dir_mtime, mtime) {
                (Some(previous), Some(now)) => previous != now,
                _ => true,
            };
            if !followed_exists || dir_changed {
                if let Some(newest) = newest_transcript(&dir).await {
                    if current.as_deref() != Some(newest.as_path()) {
                        // A file older than the session is history: start at
                        // its end. A new one is read from its start.
                        offset = match tokio::fs::metadata(&newest).await {
                            Ok(meta) if meta.modified().is_ok_and(|at| at < opened) => meta.len(),
                            _ => 0,
                        };
                        tracing::info!(
                            "odind: terminal following session={} transcript={} offset={offset}",
                            self.manifest.session_id,
                            newest.display()
                        );
                        tracing::info!(
                            "odind: terminal transcript live environment={} session={} following={}",
                            self.route.environment_id,
                            self.manifest.session_id,
                            newest.display()
                        );
                        watchdogs.reset_transcript();
                        partial.clear();
                        decoder =
                            OutputDecoder::new(self.route.harness.output, &self.route.harness_id);
                        current = Some(newest);
                    }
                }
                dir_mtime = mtime;
            }
            let Some(file) = &current else { continue };
            watchdogs.tick(&self.incidents, &self.route, file.to_str());
            let Ok(chunk) = read_from(file, &mut offset).await else {
                continue;
            };
            partial.push_str(&chunk);
            // A read cursor instead of a per-line drain: catch-up reads
            // with many lines memmove the buffer once, not once per line.
            let mut consumed = 0usize;
            while let Some(offset) = partial[consumed..].find('\n') {
                let end = consumed + offset;
                let line = partial[consumed..end].trim();
                let decoded = if line.is_empty() {
                    None
                } else {
                    Some(decoder.line(line))
                };
                consumed = end + 1;
                let Some(decoded) = decoded else {
                    continue;
                };
                for frame in decoded.frames {
                    watchdogs.frame(&frame, true, &self.incidents, &self.route, file.to_str());
                    if frame.get("type").and_then(Value::as_str) == Some("message_end") {
                        if let Some(text) = frame
                            .pointer("/message/content/0/text")
                            .and_then(Value::as_str)
                        {
                            last_text = text.to_owned();
                        }
                    }
                    self.emit(frame);
                }
                let ended = decoded.ends_turn;
                let running = self
                    .state
                    .lock()
                    .ok()
                    .and_then(|state| state.running.clone());
                if let Some(turn_id) = running.filter(|_| ended && !self.stop_in_flight()) {
                    self.finish_turn(
                        &turn_id,
                        last_text.clone(),
                        hand_back.as_ref(),
                        decoder.usage(),
                    )
                    .await;
                }
            }
            if consumed > 0 {
                partial.drain(..consumed);
            }
        }
    }
}

mod group;
use group::*;

mod registration;
use registration::*;

mod support;
use support::*;

mod control;
#[cfg(test)]
#[path = "terminal_interrupt_tests.rs"]
mod interrupt_tests;

#[cfg(test)]
mod tests {
    use super::super::tests::TempWorkspace;
    use super::super::tests::{reginn_manifest, terminal_fixture};
    use super::interrupt_tests::route;
    use super::*;

    /// A route whose declared command is `command`.
    fn route_running(manifest: &SessionManifest, command: &[&str]) -> HarnessRoute {
        let mut route = route(manifest);
        route.harness = terminal_fixture();
        route.harness.command = command.iter().map(|word| (*word).to_owned()).collect();
        route
    }

    /// The declared command's tokens expand to this session's values, the MCP and model flags the
    /// declaration names follow, and a command still holding `{bwrap}` or `{mcp_config}` refuses.
    #[test]
    fn a_declared_command_expands_its_tokens_and_refuses_while_one_is_unset() {
        let manifest = reginn_manifest();
        let (home, workspace) = (Path::new("/home/owner"), Path::new("/home/owner/ws/seat"));
        let account = home.join(".claude-accounts/school");
        let mcp = Path::new("/run/user/1000/odin-term/abcd/mcp.json");
        let mut route = route_running(
            &manifest,
            &[
                "{bwrap}",
                "--bind",
                "{workspace}",
                "{workspace}",
                "--bind",
                "{account_dir}",
                "{account_dir}",
                "--remote-control",
                "{session}",
            ],
        );
        route.harness.mcp_config_arg = Some("--mcp-config".to_owned());
        route.harness.model_arg = Some("--model".to_owned());
        let tokens = |bwrap, mcp_config| Tokens {
            home,
            workspace,
            session: &manifest,
            account_dir: Some(account.as_path()),
            mcp_config,
            bwrap,
        };

        let argv = agent_command(&route, &tokens(Some("/nix/store/bwrap"), Some(mcp))).unwrap();
        assert_eq!(
            argv,
            [
                "/nix/store/bwrap",
                "--bind",
                "/home/owner/ws/seat",
                "/home/owner/ws/seat",
                "--bind",
                "/home/owner/.claude-accounts/school",
                "/home/owner/.claude-accounts/school",
                "--remote-control",
                manifest.session_id.to_string().as_str(),
                "--mcp-config",
                "/run/user/1000/odin-term/abcd/mcp.json",
                "--model",
                "sonnet",
            ]
        );
        // The declared command that already names the config is not given the flag twice.
        route.harness.command.push("{mcp_config}".to_owned());
        let named = agent_command(&route, &tokens(Some("/nix/store/bwrap"), Some(mcp))).unwrap();
        assert_eq!(
            named
                .iter()
                .filter(|word| *word == &mcp.display().to_string())
                .count(),
            1
        );

        for (bwrap, mcp_config) in [(None, Some(mcp)), (Some("/nix/store/bwrap"), None)] {
            assert!(matches!(
                agent_command(&route, &tokens(bwrap, mcp_config)),
                Err(LiveError::Unavailable { code, .. }) if code == "terminal_bwrap_undeclared"
            ));
        }
    }

    #[test]
    fn remote_control_is_on_only_after_a_confirmed_bridge_registration() {
        assert_eq!(
            registration_from_record(&json!({"cwd": "/w", "pid": 1})),
            BridgeRegistration::Requested
        );
        assert_eq!(
            registration_from_record(&json!({"bridgeSessionId": ""})),
            BridgeRegistration::Requested
        );
        assert_eq!(
            registration_from_record(&json!({"bridgeSessionId": "session_01abc"})),
            BridgeRegistration::Active { session_url: None },
            "a bridge id is not a session URL"
        );
        assert_eq!(
            registration_from_record(&json!({
                "bridgeSessionId": "session_01abc",
                "sessionUrl": "https://claude.ai/code/session_01abc"
            })),
            BridgeRegistration::Active {
                session_url: Some("https://claude.ai/code/session_01abc".to_owned()),
            }
        );
        assert_eq!(
            registration_from_record(&json!({
                "type": "control_response",
                "subtype": "success",
                "response": {
                    "session_url": "https://claude.ai/code/bridge-42",
                    "bridge_session_id": "bridge-42"
                }
            })),
            BridgeRegistration::Active {
                session_url: Some("https://claude.ai/code/bridge-42".to_owned()),
            }
        );
        // A success URL without a bridge id is not a registration.
        assert_eq!(
            registration_from_record(&json!({
                "type": "control_response",
                "subtype": "success",
                "response": {"session_url": "https://claude.ai/code/"}
            })),
            BridgeRegistration::Requested
        );
        assert_eq!(
            registration_from_record(&json!({"remoteControlError": "bridge refused"})),
            BridgeRegistration::Failed {
                reason: "bridge refused".to_owned(),
            }
        );
        assert_eq!(
            registration_from_record(&json!({
                "type": "control_response",
                "subtype": "error",
                "request": {"subtype": "remote_control"},
                "error": "not entitled"
            })),
            BridgeRegistration::Failed {
                reason: "not entitled".to_owned(),
            }
        );
        // A path-shaped id cannot rewrite the phone URL.
        assert_eq!(
            registration_from_record(&json!({"bridgeSessionId": "../secret"})),
            BridgeRegistration::Requested
        );
        assert!(registration_from_line(r#"{"bridgeSessionId":"session_01abc"}"#).is_some());
        assert!(registration_from_line(r#"{"type":"assistant"}"#).is_none());
    }

    #[tokio::test]
    async fn a_session_record_confirms_remote_control_only_for_this_account_and_process() {
        let root = tempfile::tempdir().unwrap();
        let (home, workspace, other) = (
            root.path().join("home"),
            root.path().join("ws"),
            root.path().join("other"),
        );
        let named = home.join(".claude-accounts/school");
        let default_dir = home.join(".claude");
        for dir in [&named, &default_dir] {
            std::fs::create_dir_all(dir.join("sessions")).unwrap();
        }
        std::fs::create_dir_all(&workspace).unwrap();
        let session = "seat-1";
        let stamp = ProcessStamp {
            pid: std::process::id(),
            start_ticks: start_ticks(
                &std::fs::read_to_string(format!("/proc/{}/stat", std::process::id())).unwrap(),
            )
            .unwrap(),
        };
        let registered =
            |stamp, since| claude_bridge_registration(&named, &workspace, session, stamp, since);
        let record = named.join("sessions/9.json");
        let write = |at: &Path, value: Value| std::fs::write(at, value.to_string()).unwrap();
        let epoch = SystemTime::UNIX_EPOCH;
        let active = BridgeRegistration::Active { session_url: None };
        let requested = BridgeRegistration::Requested;

        assert_eq!(registered(Some(stamp), epoch).await, requested);
        write(
            &default_dir.join("sessions/9.json"),
            json!({"cwd": workspace, "pid": stamp.pid, "bridgeSessionId": "default-bridge"}),
        );
        assert_eq!(
            registered(Some(stamp), epoch).await,
            requested,
            "the default ~/.claude record is not the named account's registration"
        );
        write(
            &record,
            json!({"cwd": other, "pid": stamp.pid, "bridgeSessionId": "other-bridge"}),
        );
        assert_eq!(
            registered(Some(stamp), epoch).await,
            requested,
            "another workspace's bridge must not be reported as this session"
        );
        write(
            &record,
            json!({"cwd": workspace, "bridgeSessionId": "session_01abc"}),
        );
        assert_eq!(
            registered(Some(stamp), epoch).await,
            requested,
            "a record with no pid is not this session's process"
        );
        write(
            &record,
            json!({"cwd": workspace, "pid": 1, "bridgeSessionId": "stale"}),
        );
        assert_eq!(
            registered(Some(stamp), epoch).await,
            requested,
            "a pid that is not this session's process is a stale record"
        );
        write(
            &record,
            json!({"cwd": workspace, "pid": stamp.pid, "bridgeSessionId": "session_01abc"}),
        );
        assert_eq!(registered(Some(stamp), epoch).await, active);
        assert_eq!(
            registered(None, epoch).await,
            requested,
            "without a captured session process the record is not evidence"
        );
        assert_eq!(
            registered(Some(stamp), SystemTime::now() + Duration::from_secs(60)).await,
            requested,
            "a record predating the session is not evidence even if its pid matches"
        );
        let reused = ProcessStamp {
            start_ticks: stamp.start_ticks.wrapping_add(1),
            ..stamp
        };
        assert_eq!(
            registered(Some(reused), epoch).await,
            requested,
            "a reused session leader pid is not the captured process"
        );
    }

    /// A cancelled tmux client takes its whole process group with it: the
    /// fake tmux forks a grandchild that survives the direct child's
    /// kill_on_drop, so only the group kill can prove the cleanup.
    #[tokio::test]
    async fn cancelling_tmux_output_takes_its_process_group_with_it() {
        let root = tempfile::tempdir().unwrap();
        let grandchild_record = root.path().join("grandchild");
        let tmux = root.path().join("tmux");
        std::fs::write(
            &tmux,
            format!(
                "#!/bin/sh\nsleep 61 & printf '%s\\n' \"$!\" > {}\nexec sleep 61\n",
                grandchild_record.display()
            ),
        )
        .unwrap();
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&tmux, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        // The fake client's `sleep` must resolve: a minimal PATH like
        // "/bin" holds only the shell on this fleet (NixOS), and a
        // grandchild that dies of exec failure would fake the very
        // liveness this precondition asserts.
        let client_path = std::env::var("PATH").expect("the test harness PATH");
        let mut client = tmux_command(&tmux, &root.path().join("tmux.sock"), &client_path);
        client.args(["capture-pane", "-p", "-t", SESSION]);
        let group = GroupChild::spawn(&mut client).expect("fake tmux client");
        let group_id = group.group;
        let mut output = Box::pin(group.output());
        // Poll output collection before dropping it so cancellation exercises active I/O.
        std::future::poll_fn(|cx| {
            use std::future::Future;
            assert!(output.as_mut().poll(cx).is_pending());
            std::task::Poll::Ready(())
        })
        .await;
        let grandchild = loop {
            if let Ok(text) = std::fs::read_to_string(&grandchild_record) {
                if let Ok(pid) = text.trim().parse::<u32>() {
                    break pid;
                }
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        };
        let exists = |pid: u32| Path::new(&format!("/proc/{pid}")).exists();
        assert!(exists(grandchild), "the grandchild runs under the client");

        // Cancel the pending output future, not merely the unstarted guard.
        drop(output);
        let gone = |pid: u32| {
            let deadline = Instant::now() + Duration::from_secs(10);
            while Instant::now() < deadline {
                if !exists(pid) {
                    return true;
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            !exists(pid)
        };
        assert!(gone(group_id), "the direct client must be gone");
        assert!(
            gone(grandchild),
            "the forked grandchild must die with the client's group"
        );
    }

    /// A tmux that logs every call and types what it is pasted. The screen is the file `screen`
    /// beside the log when there is one, else the ready prompt; `has-session` fails while `dead`
    /// exists and `load-buffer` while `refuse` does.
    struct Tmux {
        dir: tempfile::TempDir,
    }

    impl Tmux {
        fn new() -> Self {
            let dir = tempfile::tempdir().unwrap();
            let tmux = Self { dir };
            tmux.install(
                r#"dir=$1
shift
printf '%s\n' "$*" >> "$dir/calls"
case "$1" in
 capture-pane) if [ -x "$dir/screen" ]; then "$dir/screen"; else printf '%s\n' '? for shortcuts'; fi ;;
 load-buffer) cat >> "$dir/typed"; printf '\n--\n' >> "$dir/typed"; [ -e "$dir/refuse" ] && exit 1 ;;
 has-session) [ -e "$dir/dead" ] && exit 1 ;;
 paste-buffer|send-keys) ;;
 *) exit 2 ;;
esac
exit 0
"#,
            );
            tmux
        }

        /// The tmux client: an executable script, so removing it makes the client fail to spawn.
        fn install(&self, script: &str) {
            use std::os::unix::fs::PermissionsExt;
            let path = self.dir.path().join("tmux");
            std::fs::write(&path, format!("#!/bin/sh\n{script}")).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        }

        fn exec(&self) -> Vec<String> {
            vec![
                self.dir.path().join("tmux").display().to_string(),
                self.dir.path().display().to_string(),
            ]
        }

        fn calls(&self) -> Vec<String> {
            std::fs::read_to_string(self.dir.path().join("calls"))
                .unwrap_or_default()
                .lines()
                .map(str::to_owned)
                .collect()
        }

        /// What was pasted, one entry per paste.
        fn typed(&self) -> Vec<String> {
            std::fs::read_to_string(self.dir.path().join("typed"))
                .unwrap_or_default()
                .split("\n--\n")
                .filter(|text| !text.is_empty())
                .map(str::to_owned)
                .collect()
        }
    }

    fn scripted(tmux: &Tmux, command: &[&str]) -> Scripted {
        let manifest = reginn_manifest();
        let route = route_running(&manifest, command);
        TerminalControl::scripted(&manifest, route, tmux.dir.path().to_path_buf(), tmux.exec())
    }

    fn message(text: &str) -> LiveMessage {
        LiveMessage::new(vec![odin_domain::huginn::LiveContentBlock::Text(
            text.to_owned(),
        )])
        .unwrap()
    }

    fn value_of(frame: &ObservedFrame) -> Value {
        frame.value().cloned().expect("a decoded frame")
    }

    fn frames_of(received: &mut broadcast::Receiver<ObservedFrame>) -> Vec<Value> {
        let mut frames = Vec::new();
        while let Ok(frame) = received.try_recv() {
            frames.push(value_of(&frame));
        }
        frames
    }

    fn texts(frames: &[Value]) -> Vec<String> {
        frames
            .iter()
            .filter_map(|frame| {
                frame
                    .pointer("/message/content/0/text")
                    .or_else(|| frame.get("text"))
                    .and_then(Value::as_str)
                    .map(str::to_owned)
            })
            .collect()
    }

    /// A rollover clears the context, then types the continuity brief under the shared marker.
    #[tokio::test]
    async fn a_rollover_clears_the_context_and_types_the_continuity_brief() {
        let tmux = Tmux::new();
        let session = scripted(&tmux, &["claude"]);
        session.control.roll_context().await.unwrap();
        let typed = tmux.typed();
        assert_eq!(typed[0], "/clear");
        assert!(
            typed[1].starts_with(&format!(
                "{ROLLOVER_PROMPT_MARKER} session={} trigger=threshold]",
                session.control.manifest.session_id
            )) && typed[1].ends_with(ROLLOVER_ABSORB_INSTRUCTION),
            "{}",
            typed[1]
        );
    }

    fn append(file: &Path, line: &Value) {
        use std::io::Write;
        let mut handle = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(file)
            .unwrap();
        writeln!(handle, "{line}").unwrap();
    }

    fn assistant_record(stop_reason: &str, content: Value) -> Value {
        json!({"type": "assistant", "message": {"role": "assistant", "stop_reason": stop_reason, "content": content}})
    }

    /// The next frame of `kind`, within a safety bound that only a hung follower reaches.
    async fn next_frame(received: &mut broadcast::Receiver<ObservedFrame>, kind: &str) -> Value {
        let mut seen = Vec::new();
        tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                let frame = value_of(&received.recv().await.expect("frames stay open"));
                if frame["type"] == kind {
                    return frame;
                }
                seen.push(frame);
            }
        })
        .await
        .unwrap_or_else(|_| panic!("no {kind} frame arrived; saw {seen:?}"))
    }

    fn spawn_follower(session: &Scripted, transcripts: &Path) -> tokio::task::JoinHandle<()> {
        tokio::spawn(Arc::clone(&session.control).follow(
            transcripts.to_path_buf(),
            Arc::new(TempWorkspace {
                prepared: Default::default(),
            }),
            session.follow_stopped.clone(),
        ))
    }

    /// Starts the follower and returns once it has looked at the transcript directory: the
    /// second `has-session` probe comes a whole poll cycle after the first scan.
    async fn follow(
        session: &Scripted,
        tmux: &Tmux,
        transcripts: &Path,
    ) -> tokio::task::JoinHandle<()> {
        let probes = || {
            tmux.calls()
                .iter()
                .filter(|call| call.starts_with("has-session"))
                .count()
        };
        let before = probes();
        let follower = spawn_follower(session, transcripts);
        while probes() < before + 2 {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        follower
    }

    /// The follower reads what the agent writes after the session opened: a tool round yields tool
    /// frames and no end, the end-of-turn record ends the running turn with its text, and a
    /// transcript from before the session is history that ends nothing.
    #[tokio::test]
    async fn the_follower_ends_the_turn_on_the_end_turn_record_and_skips_history() {
        let tmux = Tmux::new();
        let transcripts = tmux.dir.path().join("projects");
        std::fs::create_dir(&transcripts).unwrap();
        let file = transcripts.join("s.jsonl");
        append(
            &file,
            &assistant_record("end_turn", json!([{"type": "text", "text": "old news"}])),
        );
        let mut session = scripted(&tmux, &["claude"]);
        session.control.start_turn(&message("go")).await.unwrap();
        let follower = follow(&session, &tmux, &transcripts).await;

        append(
            &file,
            &assistant_record(
                "tool_use",
                json!([{"type": "tool_use", "id": "t1", "name": "Bash", "input": {}}]),
            ),
        );
        next_frame(&mut session.frames, "tool_execution_start").await;
        assert!(
            running_turn(&session.control).is_some(),
            "a tool round does not end the turn"
        );
        append(
            &file,
            &json!({"type": "user", "message": {"role": "user", "content": [{"type": "tool_result", "tool_use_id": "t1", "content": "ok"}]}}),
        );
        append(
            &file,
            &assistant_record("end_turn", json!([{"type": "text", "text": "Done."}])),
        );
        let result = next_frame(&mut session.frames, "prompt_result").await;
        assert_eq!(result["text"], "Done.");
        assert!(running_turn(&session.control).is_none());
        let later = texts(&frames_of(&mut session.frames));
        assert!(
            !later.iter().any(|text| text.contains("old news")),
            "{later:?}"
        );
        follower.abort();
    }

    fn running_turn(control: &TerminalControl) -> Option<String> {
        control.state.lock().unwrap().running.clone()
    }

    /// A dead tmux fails the session and ends its running turn; a probe that could not run is not
    /// a death.
    #[tokio::test]
    async fn a_closed_terminal_fails_the_session_but_a_failed_probe_does_not() {
        let tmux = Tmux::new();
        let mut session = scripted(&tmux, &["claude"]);
        let transcripts = tmux.dir.path().join("projects");
        std::fs::create_dir(&transcripts).unwrap();
        let file = transcripts.join("s.jsonl");
        session.control.start_turn(&message("go")).await.unwrap();
        let follower = follow(&session, &tmux, &transcripts).await;

        // With the tmux client gone, `has-session` cannot even run; the transcript still flows
        // across several liveness ticks.
        std::fs::remove_file(tmux.dir.path().join("tmux")).unwrap();
        for round in 0..=LIVENESS_TICKS {
            let text = format!("note {round}");
            append(
                &file,
                &assistant_record("tool_use", json!([{"type": "text", "text": text}])),
            );
            next_frame(&mut session.frames, "message_end").await;
        }
        assert!(session.failed.borrow().is_none());
        assert!(running_turn(&session.control).is_some());
        follower.abort();

        tmux.install("case \"$2\" in has-session) exit 1 ;; esac\n");
        let follower = spawn_follower(&session, &transcripts);
        let end = next_frame(&mut session.frames, "agent_end").await;
        assert_eq!(end["stopReason"], "error");
        assert_eq!(
            session.failed.borrow().as_deref(),
            Some("the agent's terminal closed")
        );
        assert!(running_turn(&session.control).is_none());
        follower.await.unwrap();
    }
}
