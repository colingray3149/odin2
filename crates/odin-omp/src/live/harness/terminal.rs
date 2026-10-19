//! The `terminal` harness protocol: the agent's real
//! interactive TUI program runs for the whole session in a terminal inside
//! the declared sandbox, and Odin drives it the way a person would. The
//! sandbox is a confined transient user unit whose main process is a tmux
//! server (`tmux -D`): everything the server starts runs inside the unit's
//! confinement, and stopping the unit stops all of it. Odin types prompts
//! into the agent (bracketed paste, then Enter), reads its screen
//! (`capture-pane`), and follows its transcript files for what it did — a
//! turn ends when the agent's last assistant record ends its turn. The
//! session's Zellij tab attaches to the same terminal, so Colin can watch
//! it or type into it from any paired device. Governance is `observed`:
//! the agent runs its own tools; the unit is the boundary.

use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};

use odin_domain::StopVerdict;
use odin_kernel::StopAuthority;
use odin_types::{CorrelationId, WorkerId};
use rustix::process::{kill_process_group, Pid, Signal};

use async_trait::async_trait;
use odin_domain::huginn::{
    ApprovalDecision, LiveError, LiveMessage, ModelName, PermissionDecision, PermissionRequestId,
    ProviderName, SessionManifest,
};
use odin_domain::{ApprovalId, NodeId};
use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};
use tokio::process::Command;
use tokio::sync::{broadcast, watch};

use super::decode::OutputDecoder;
use super::observe::{HarnessIncidentSink, Watchdogs};
use super::{fleet_host_argv, message_text, HarnessRoute, HarnessWorkspace};
use crate::bridge::ObservedFrame;
use crate::live::control::LiveControlBackend;
use crate::live::kernel_mcp::McpRegistration;

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
/// Timeout leaves an unfinished stop available for recovery, never reported as done.
const STOP_TIMEOUT: Duration = Duration::from_secs(20);

/// How long a slash command is given to redraw before the screen is read.
const SLASH_SETTLE: Duration = Duration::from_millis(1_500);
/// How long a cancelled client's drop waits to reap the group-killed
/// child before surfacing that it could not.
const GROUP_REAP_WINDOW: Duration = Duration::from_millis(500);
/// The reap poll inside [`GROUP_REAP_WINDOW`].
const GROUP_REAP_POLL: Duration = Duration::from_millis(5);

/// How long the startup screen is watched for a one-time question (long
/// enough for Colin to sign a fresh account in).
const STARTUP_WATCH: Duration = Duration::from_secs(30 * 60);

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

/// `{home}` and `{workspace_slug}` substituted into a declared template.
pub fn expand(template: &str, home: &Path, workspace: &Path) -> String {
    template
        .replace("{home}", &home.to_string_lossy())
        .replace("{workspace_slug}", &workspace_slug(workspace))
}

/// The directories a confined unit and odind look for programs in.
pub fn program_path(home: &Path) -> Vec<PathBuf> {
    let user = home
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_default();
    vec![
        home.join(".local/state/nix/profile/bin"),
        PathBuf::from(format!("/etc/profiles/per-user/{user}/bin")),
        PathBuf::from("/run/current-system/sw/bin"),
    ]
}

/// What the screen asks before the agent can work, and the keys that
/// answer it. A folder-trust question is answered yes (the workspace is
/// Odin's own clone for this session); a sign-in screen is Colin's to
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

pub fn screen_gate(screen: &str) -> Option<ScreenGate> {
    let lower = screen.to_ascii_lowercase();
    if lower.contains("select login method")
        || lower.contains("sign in with")
        || lower.contains("paste code here")
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

/// Whether this poll tick should fork `tmux has-session`.
pub(super) fn liveness_due(tick: u32) -> bool {
    tick.is_multiple_of(LIVENESS_TICKS)
}

/// Rescan the transcript directory when the followed file is gone, or when
/// the directory mtime moved (a cleared context starts a new file beside
/// the old one). A steady follow does not list the directory.
pub(super) fn transcript_rescan(followed_exists: bool, dir_mtime_changed: bool) -> bool {
    !followed_exists || dir_mtime_changed
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
    transport: TerminalTransport,
    frames: broadcast::Sender<ObservedFrame>,
    failed: watch::Sender<Option<String>>,
    state: Arc<Mutex<TermState>>,
    stop_follow: watch::Sender<bool>,
    stopped: tokio::sync::Mutex<bool>,
    incidents: Option<Arc<dyn HarnessIncidentSink>>,
    /// The session's kernel MCP endpoint; dropped with the control.
    _kernel: Option<McpRegistration>,
}

/// The session's own runtime directory, bound into its sandbox: the tmux
/// socket and the MCP config live here.
pub(super) fn runtime_dir(session: &str) -> PathBuf {
    super::session_runtime_dir("odin-term", session)
}

/// The Claude Code MCP config of a terminal session.
pub(super) fn mcp_config_path(session: &str) -> PathBuf {
    runtime_dir(session).join("mcp.json")
}

/// The terminal stop row's correlation, derived from the session id's hex
/// so a restarted daemon re-derives the same correlation and scopes
/// recovery to exactly this session's rows.
fn terminal_correlation(session: &str) -> Result<CorrelationId, LiveError> {
    CorrelationId::new(&session.replace('-', "")).map_err(|error| LiveError::Unavailable {
        code: format!("terminal_session_correlation ({error:?})"),
    })
}

fn lock_failed() -> LiveError {
    LiveError::Unavailable {
        code: "terminal_state".to_owned(),
    }
}

fn unsupported(operation: &str, harness: &str) -> LiveError {
    LiveError::Unsupported {
        operation: format!("{operation} is not available under the {harness} harness"),
    }
}

/// The tmux client command against the session's socket.
fn tmux_command(tmux: &Path, socket: &Path, path: &str) -> Command {
    let mut command = Command::new(tmux);
    command
        .arg("-S")
        .arg(socket)
        .env("PATH", path)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    command
}

/// A tmux client child in its own process group. `process_group(0)` is
/// set before spawn, so the child's PID is its group's: a cancellation or
/// drop takes the whole group down (`tmux` may have forked while
/// connecting to the server), and the builder's `kill_on_drop` stays as
/// the direct-child backstop. Output is drained before reaping, keeping
/// the group leader's PID reserved until group cleanup is disarmed.
struct GroupChild {
    child: Option<tokio::process::Child>,
    group: u32,
}

impl GroupChild {
    fn spawn(client: &mut Command) -> Result<Self, std::io::Error> {
        client.process_group(0);
        let child = client.spawn()?;
        let group = child
            .id()
            .ok_or_else(|| std::io::Error::other("client exited before its group was known"))?;
        Ok(Self {
            child: Some(child),
            group,
        })
    }

    /// Waits for exit and collects the output. Normal completion never
    /// signals the group: the child was reaped, and the pid may belong to
    /// an unrelated group by now.
    async fn output(mut self) -> std::io::Result<std::process::Output> {
        let child = self
            .child
            .as_mut()
            .expect("client present until completion");
        // Do not transfer the child into wait_with_output: cancellation
        // would drop it outside this guard and leave its descendants alive.
        // Drain both pipes before waiting so even an exited leader stays
        // unreaped (and its group id cannot be reused) while reads are pending.
        drop(child.stdin.take());
        let mut stdout = child.stdout.take();
        let mut stderr = child.stderr.take();
        let mut stdout_bytes = Vec::new();
        let mut stderr_bytes = Vec::new();
        tokio::try_join!(
            async {
                if let Some(pipe) = stdout.as_mut() {
                    pipe.read_to_end(&mut stdout_bytes).await?;
                }
                Ok::<_, std::io::Error>(())
            },
            async {
                if let Some(pipe) = stderr.as_mut() {
                    pipe.read_to_end(&mut stderr_bytes).await?;
                }
                Ok::<_, std::io::Error>(())
            }
        )?;
        let status = child.wait().await?;
        // No await between the reap and disarming the group cleanup.
        self.child = None;
        Ok(std::process::Output {
            status,
            stdout: stdout_bytes,
            stderr: stderr_bytes,
        })
    }
}

impl Drop for GroupChild {
    fn drop(&mut self) {
        let Some(mut child) = self.child.take() else {
            return;
        };
        // The child owns this group (it was grouped before spawn), so the
        // kill reaches every process tmux forked and cannot reach ours.
        if let Some(group) = i32::try_from(self.group).ok().and_then(Pid::from_raw) {
            let _ = kill_process_group(group, Signal::KILL);
        }
        // Bounded reap: the cancellation must produce evidence, not hand
        // a killed group to the orphan queue unseen. A SIGKILL'd client is
        // reaped here unless the kernel holds it uninterruptibly.
        let deadline = Instant::now() + GROUP_REAP_WINDOW;
        loop {
            match child.try_wait() {
                Ok(Some(_status)) => return,
                Ok(None) if Instant::now() < deadline => std::thread::sleep(GROUP_REAP_POLL),
                Ok(None) => break,
                Err(_error) => break,
            }
        }
        tracing::error!(
            "odind: terminal client group={} was killed but not reaped within its bound",
            self.group
        );
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
                return Err(LiveError::Unavailable {
                    code: format!("terminal_unit_stop_unconfirmed: {worker}"),
                });
            }
        }
        Ok(Ok(Err(error))) => {
            tracing::error!("odind: terminal stop worker={worker} error={error} left recoverable");
            return Err(LiveError::Unavailable {
                code: format!("terminal_unit_stop: {error}"),
            });
        }
        Ok(Err(error)) => {
            return Err(LiveError::Unavailable {
                code: format!("terminal_unit_stop_join: {error}"),
            });
        }
        Err(_) => {
            tracing::error!("odind: terminal stop exceeded its bound; the row stays recoverable");
            return Err(LiveError::Unavailable {
                code: format!("terminal_unit_stop_timeout: {worker}"),
            });
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
    /// A k3s pod: the same tmux client run through `kubectl exec`.
    Pod {
        terminal: super::PodTerminal,
        pods: Arc<dyn super::PodTerminals>,
        session: String,
    },
}

/// The host a terminal session starts on.
pub(super) enum TerminalHost {
    /// Start a transient unit on this host.
    Unit,
    /// A pod already running its tmux server.
    Pod {
        terminal: super::PodTerminal,
        pods: Arc<dyn super::PodTerminals>,
    },
}

impl TerminalTransport {
    /// A tmux client command, ready for its arguments.
    fn tmux(&self) -> Command {
        match self {
            Self::Unit {
                tmux, socket, path, ..
            } => tmux_command(tmux, socket, path),
            Self::Pod { terminal, .. } => {
                let mut command = Command::new(&terminal.exec[0]);
                command
                    .args(&terminal.exec[1..])
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
            Self::Pod { terminal, .. } => terminal.attach.clone(),
        }
    }

    fn describe(&self) -> String {
        match self {
            Self::Unit { unit, socket, .. } => {
                format!("unit={unit} socket={}", socket.display())
            }
            Self::Pod { terminal, .. } => format!("pod={}", terminal.pod),
        }
    }

    /// Stops the terminal's host: the unit through its durable identity
    /// row — never by name — or the pod.
    async fn stop(&self) -> Result<(), LiveError> {
        match self {
            Self::Unit {
                stops, worker_id, ..
            } => {
                stop_registered_terminal(stops, worker_id).await?;
            }
            Self::Pod {
                pods,
                session,
                terminal,
            } => {
                if let Err(error) = pods.stop(session).await {
                    tracing::error!(
                        "odind: terminal stop pod={} did not confirm: {error}",
                        terminal.pod
                    );
                    return Err(error);
                }
            }
        }
        Ok(())
    }
}

/// Everything one opened terminal session needs to start.
pub(super) struct TerminalStart<'a> {
    pub manifest: &'a SessionManifest,
    pub route: HarnessRoute,
    pub workspace: PathBuf,
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
        let group = GroupChild::spawn(&mut client).map_err(|error| LiveError::Unavailable {
            code: format!("{code}_spawn ({error})"),
        })?;
        group
            .output()
            .await
            .map_err(|error| LiveError::Unavailable {
                code: format!("{code} ({error})"),
            })
    }

    /// Starts the sandboxed terminal and the agent in it, the transcript
    /// follower and the startup watch. Returns the control and the argv
    /// the session's tab runs to attach to the same terminal.
    pub(super) async fn start(
        start: TerminalStart<'_>,
        host: TerminalHost,
    ) -> Result<(Arc<Self>, Vec<String>), LiveError> {
        let home = home();
        let transport = match host {
            TerminalHost::Unit => Self::start_unit(&start, &home).await?,
            TerminalHost::Pod { terminal, pods } => TerminalTransport::Pod {
                terminal,
                pods,
                session: start.manifest.session_id.to_string(),
            },
        };
        let mut agent: Vec<String> = start
            .route
            .harness
            .command
            .iter()
            .map(|argument| expand(argument, &home, &start.workspace))
            .collect();
        // Before the model flag: `--mcp-config` takes several values.
        if let (Some(flag), Some((_, config))) =
            (&start.route.harness.mcp_config_arg, &start.kernel)
        {
            agent.push(flag.clone());
            agent.push(config.display().to_string());
        }
        if let Some(flag) = &start.route.harness.model_arg {
            agent.push(flag.clone());
            agent.push(start.manifest.model.as_str().to_owned());
        }
        // The one client that legitimately starts the server: a normal
        // completion never signals its group (the daemonized server leaves
        // it), but an aborted start takes client and half-started server
        // with it before the unit stop below.
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
        let group = GroupChild::spawn(&mut client).map_err(|error| LiveError::Unavailable {
            code: format!("terminal_agent_spawn ({error})"),
        })?;
        let output = group
            .output()
            .await
            .map_err(|error| LiveError::Unavailable {
                code: format!("terminal_agent_spawn ({error})"),
            })?;
        if !output.status.success() {
            transport.stop().await?;
            return Err(LiveError::Unavailable {
                code: format!(
                    "terminal_agent_start: {}",
                    String::from_utf8_lossy(&output.stderr).trim()
                ),
            });
        }
        let transcripts = PathBuf::from(expand(
            start
                .route
                .harness
                .transcripts
                .as_deref()
                .unwrap_or_default(),
            &home,
            &start.workspace,
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
        let control = Arc::new(Self {
            manifest: start.manifest.clone(),
            route: start.route,
            workspace: start.workspace,
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
        });
        tokio::spawn(Arc::clone(&control).watch_startup());
        tokio::spawn(Arc::clone(&control).follow(transcripts, start.hand_back, follow_stopped));
        let attach = control.transport.attach();
        Ok((control, attach))
    }

    /// Starts the session's sandboxed unit running the tmux server.
    async fn start_unit(
        start: &TerminalStart<'_>,
        home: &Path,
    ) -> Result<TerminalTransport, LiveError> {
        let home = home.to_path_buf();
        let path = path_env(&home);
        let tmux = find_program("tmux", &home).ok_or_else(|| LiveError::Unavailable {
            code: "terminal_tmux_missing".to_owned(),
        })?;
        let short: String = start
            .manifest
            .session_id
            .to_string()
            .chars()
            .take(8)
            .collect();
        let unit = format!("odin-term-{short}");
        let unit_service = format!("{unit}.service");
        // The stop authority is not optional on the unit path: the durable
        // row is the only thing that makes this unit ours.
        let Some(stops) = start.stops.as_ref() else {
            return Err(LiveError::Unavailable {
                code: "terminal_stop_authority_missing".to_owned(),
            });
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
            .map_err(|error| LiveError::Unavailable {
                code: format!("terminal_intent ({error})"),
            })?
            .map_err(|error| LiveError::Unavailable {
                code: format!("terminal_intent: {error}"),
            })?
        };
        // The socket lives in a directory of this session's own, bound into
        // the sandbox: a private home hides /run/user, and another session's
        // sandbox must not reach this terminal.
        let runtime = runtime_dir(&start.manifest.session_id.to_string());
        tokio::fs::create_dir_all(&runtime)
            .await
            .map_err(|error| LiveError::Unavailable {
                code: format!("terminal_runtime_dir ({error})"),
            })?;
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
            .map_err(|error| LiveError::Unavailable {
                code: format!("terminal_unit_spawn ({error})"),
            })?;
        if !status.status.success() {
            // The launch failed: no unit exists, and the journaled stop
            // settles the intent row as honestly absent.
            stop_registered_terminal(stops, &worker_id).await?;
            return Err(LiveError::Unavailable {
                code: format!(
                    "terminal_unit_start: {}",
                    String::from_utf8_lossy(&status.stderr).trim()
                ),
            });
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
                    return Err(LiveError::Unavailable {
                        code: format!("terminal_unit_identity: {error}"),
                    });
                }
                Err(error) => {
                    return Err(LiveError::Unavailable {
                        code: format!("terminal_unit_identity ({error})"),
                    });
                }
            }
        }
        // Require the unit's socket: otherwise tmux may start an unconfined server.
        let mut up = false;
        for _ in 0..50 {
            if tokio::fs::metadata(&socket).await.is_ok() {
                up = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
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
            return Err(LiveError::Unavailable {
                code: format!("terminal_sandbox_failed: unit {unit} did not come up"),
            });
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
            return Err(LiveError::Unavailable {
                code: "terminal_closed".to_owned(),
            });
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
            Err(LiveError::Unavailable {
                code: "terminal_closed".to_owned(),
            })
        }
    }

    /// Types `text` as one paste (newlines stay inside the prompt), then
    /// Enter.
    async fn type_line(&self, text: &str) -> Result<(), LiveError> {
        // The paste load keeps its stdin open while writing; the guard
        // owns the child the whole time, so a cancelled paste never leaks
        // the load client.
        let mut client = self.tmux();
        client
            .args(["load-buffer", "-b", "odin", "-"])
            .stdin(Stdio::piped());
        let mut load = GroupChild::spawn(&mut client).map_err(|error| LiveError::Unavailable {
            code: format!("terminal_paste ({error})"),
        })?;
        {
            let child = load.child.as_mut().expect("load client present");
            if let Some(mut stdin) = child.stdin.take() {
                stdin
                    .write_all(text.as_bytes())
                    .await
                    .map_err(|error| LiveError::Unavailable {
                        code: format!("terminal_paste ({error})"),
                    })?;
            }
            let loaded = child.wait().await.map_err(|error| LiveError::Unavailable {
                code: format!("terminal_paste ({error})"),
            })?;
            // Reaped: the guard goes inert and never signals the group.
            load.child = None;
            if !loaded.success() {
                return Err(LiveError::Unavailable {
                    code: "terminal_closed".to_owned(),
                });
            }
        }
        let pasted = self
            .tmux_output(
                "terminal_paste",
                &["paste-buffer", "-p", "-d", "-b", "odin", "-t", SESSION],
            )
            .await?;
        if !pasted.status.success() {
            return Err(LiveError::Unavailable {
                code: "terminal_closed".to_owned(),
            });
        }
        // The TUI takes the paste before the submit key.
        tokio::time::sleep(Duration::from_millis(300)).await;
        self.keys(&["Enter"]).await
    }

    /// A one-time question on the startup screen: folder trust is answered,
    /// a sign-in screen is reported for Colin.
    async fn watch_startup(self: Arc<Self>) {
        let deadline = tokio::time::Instant::now() + STARTUP_WATCH;
        let mut sign_in_reported = false;
        while tokio::time::Instant::now() < deadline {
            tokio::time::sleep(Duration::from_secs(2)).await;
            let Ok(screen) = self.screen().await else {
                return;
            };
            let gate = screen_gate(&screen);
            if gate.is_none() && screen_ready(&screen) {
                tracing::info!(
                    "odind: terminal ready session={} harness={}",
                    self.manifest.session_id,
                    self.route.harness_id
                );
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
                    self.emit(json!({
                        "type": "message_end",
                        "message": {"role": "assistant", "content": [{"type": "text", "text":
                            "[this agent's account is signed out: Colin signs in once in its terminal tab]"}]},
                    }));
                }
                None => {}
            }
        }
    }

    fn signed_out_error(&self) -> LiveError {
        LiveError::Unavailable {
            code: format!(
                "terminal_signed_out: the {} account needs Colin's sign-in in its terminal",
                self.route.harness_id
            ),
        }
    }

    async fn start_turn(&self, message: &LiveMessage) -> Result<(), LiveError> {
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
        let (turn_id, text) = {
            let mut state = self.state.lock().map_err(|_| lock_failed())?;
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
            let text = match (&self.route.harness.brief, state.briefed, slash) {
                (Some(brief), false, false) => {
                    state.briefed = true;
                    format!("{}\n\n{prompt}", brief.trim())
                }
                _ => prompt.clone(),
            };
            if !slash {
                state.running = Some(turn_id.clone());
            }
            (turn_id, text)
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
        if slash {
            // A slash command ends no turn in the transcript: its answer
            // is what the screen shows once it has redrawn.
            tokio::time::sleep(SLASH_SETTLE).await;
            let screen = self.screen().await.unwrap_or_default();
            let summary = format!("Typed {}. The screen now shows:\n{screen}", text.trim());
            self.emit(json!({"type": "agent_end", "turnId": turn_id, "stopReason": "stop"}));
            self.emit(json!({"type": "prompt_result", "turnId": turn_id, "text": summary}));
        }
        Ok(())
    }

    /// A hand-back may finish after an interrupt and a new prompt. Retire
    /// only its original turn, keeping emission ordered with that retirement.
    fn end_matching_turn(&self, expected: &str, text: String) {
        let Ok(mut state) = self.state.lock() else {
            return;
        };
        // The hand-back awaited while a session stop may have begun settling:
        // a stopping session never emits a synthetic answer.
        if state.running.as_deref() != Some(expected) || self.stop_in_flight() {
            return;
        }
        let turn_id = state.running.take().expect("matching running turn");
        self.emit(json!({"type": "agent_end", "turnId": turn_id, "stopReason": "stop"}));
        self.emit(json!({"type": "prompt_result", "turnId": turn_id, "text": text}));
    }

    async fn finish_turn(
        &self,
        turn_id: &str,
        mut summary: String,
        hand_back: &dyn HarnessWorkspace,
    ) {
        let note = match hand_back
            .hand_back(&self.manifest, &self.route, &self.workspace)
            .await
        {
            Ok(note) => note,
            Err(error) => Some(format!("The work could not be handed back: {error:?}")),
        };
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
        self.end_matching_turn(turn_id, summary);
    }

    /// Intentional control settlement belongs to the actor's ControlEffect,
    /// not an asynchronous provider failure or a fabricated task answer.
    async fn interrupt_turn(&self) -> Result<(), LiveError> {
        self.keys(&["Escape"]).await?;
        self.state.lock().map_err(|_| lock_failed())?.running = None;
        Ok(())
    }

    /// Ends the running turn after genuine terminal completion or failure.
    fn end_turn(&self, text: String, failure: Option<&str>) {
        let turn = self
            .state
            .lock()
            .ok()
            .and_then(|mut state| state.running.take());
        let Some(turn_id) = turn else { return };
        match failure {
            None => self.emit(json!({"type": "agent_end", "turnId": turn_id, "stopReason": "stop"})),
            Some(reason) => self.emit(json!({
                "type": "agent_end", "turnId": turn_id, "stopReason": "error", "errorMessage": reason
            })),
        }
        self.emit(json!({"type": "prompt_result", "turnId": turn_id, "text": text}));
    }

    /// Suppresses failure and turn completion observations during deliberate stop.
    fn stop_in_flight(&self) -> bool {
        self.stopped
            .try_lock()
            .map(|stopped| *stopped)
            .unwrap_or(true)
    }

    async fn close(&self) -> Result<(), LiveError> {
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
            let mut state = self.state.lock().map_err(|_| lock_failed())?;
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
        let opened = SystemTime::now();
        let mut current: Option<PathBuf> = None;
        let mut offset: u64 = 0;
        let mut partial = String::new();
        let mut decoder = OutputDecoder::new(self.route.harness.output, &self.route.harness_id);
        let mut last_text = String::new();
        let mut poll = tokio::time::interval(POLL);
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
            if liveness_due(tick) {
                let alive = self
                    .tmux_output("terminal_liveness", &["has-session", "-t", SESSION])
                    .await
                    .map(|output| output.status.success())
                    .unwrap_or(false);
                if !alive && !self.stop_in_flight() {
                    tracing::info!(
                        "odind: terminal closed session={} harness={}",
                        self.manifest.session_id,
                        self.route.harness_id
                    );
                    let _ = self
                        .failed
                        .send(Some("the agent's terminal closed".to_owned()));
                    self.end_turn(last_text.clone(), Some("the agent's terminal closed"));
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
            if transcript_rescan(followed_exists, dir_changed) {
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
                            "odind: observe live environment={} session={} following={}",
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
            while let Some(end) = partial.find('\n') {
                let line: String = partial.drain(..=end).collect();
                let line = line.trim();
                if line.is_empty() {
                    continue;
                }
                let decoded = decoder.line(line);
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
                    self.finish_turn(&turn_id, last_text.clone(), hand_back.as_ref())
                        .await;
                }
            }
        }
    }
}

fn home() -> PathBuf {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_default()
}

fn path_env(home: &Path) -> String {
    program_path(home)
        .iter()
        .map(|dir| dir.to_string_lossy().into_owned())
        .collect::<Vec<_>>()
        .join(":")
}

fn find_program(name: &str, home: &Path) -> Option<PathBuf> {
    program_path(home)
        .into_iter()
        .map(|dir| dir.join(name))
        .find(|candidate| candidate.is_file())
}

/// The most recently modified `*.jsonl` in `dir`.
async fn newest_transcript(dir: &Path) -> Option<PathBuf> {
    let mut entries = tokio::fs::read_dir(dir).await.ok()?;
    let mut newest: Option<(SystemTime, PathBuf)> = None;
    while let Ok(Some(entry)) = entries.next_entry().await {
        let path = entry.path();
        if path.extension().and_then(|ext| ext.to_str()) != Some("jsonl") {
            continue;
        }
        let Ok(modified) = entry.metadata().await.and_then(|meta| meta.modified()) else {
            continue;
        };
        if newest.as_ref().is_none_or(|(at, _)| modified > *at) {
            newest = Some((modified, path));
        }
    }
    newest.map(|(_, path)| path)
}

/// The bytes written to `file` after `offset` (advanced past them).
async fn read_from(file: &Path, offset: &mut u64) -> std::io::Result<String> {
    let mut handle = tokio::fs::File::open(file).await?;
    let length = handle.metadata().await?.len();
    if length < *offset {
        *offset = 0;
    }
    if length == *offset {
        return Ok(String::new());
    }
    handle.seek(std::io::SeekFrom::Start(*offset)).await?;
    let mut bytes = Vec::with_capacity(usize::try_from(length - *offset).unwrap_or(0));
    handle.read_to_end(&mut bytes).await?;
    // Only whole lines' worth of valid UTF-8 is consumed; a cut character
    // waits for the next read.
    let valid = match std::str::from_utf8(&bytes) {
        Ok(_) => bytes.len(),
        Err(error) => error.valid_up_to(),
    };
    *offset += valid as u64;
    Ok(String::from_utf8_lossy(&bytes[..valid]).into_owned())
}

#[async_trait]
impl LiveControlBackend for TerminalControl {
    async fn prompt(&self, message: &LiveMessage) -> Result<(), LiveError> {
        self.start_turn(message).await
    }
    async fn follow_up(&self, message: &LiveMessage) -> Result<(), LiveError> {
        self.start_turn(message).await
    }
    /// Typed into the running turn: the agent queues it as a person's
    /// message would be.
    async fn steer(&self, message: &LiveMessage) -> Result<(), LiveError> {
        let text = message_text(message);
        if text.trim().is_empty() {
            return Err(LiveError::InvalidRequest {
                code: "harness_prompt_empty".to_owned(),
                message: "the steer carries no text".to_owned(),
            });
        }
        self.type_line(&text).await
    }
    /// Escape interrupts the agent's turn; its conversation stays.
    async fn pause(&self) -> Result<(), LiveError> {
        self.interrupt_turn().await
    }
    async fn resume(&self) -> Result<(), LiveError> {
        Ok(())
    }
    async fn checkpoint(&self) -> Result<(), LiveError> {
        Err(unsupported("checkpoint", &self.route.harness_id))
    }
    async fn restart(&self) -> Result<(), LiveError> {
        self.pause().await
    }
    async fn rehome(&self, _target_node: &NodeId) -> Result<(), LiveError> {
        Err(unsupported("rehome", &self.route.harness_id))
    }
    /// The agent's own model command, typed.
    async fn set_model(
        &self,
        _provider: &ProviderName,
        model: &ModelName,
    ) -> Result<(), LiveError> {
        self.type_line(&format!("/model {model}")).await
    }
    async fn abort_turn(&self) -> Result<(), LiveError> {
        self.pause().await
    }
    async fn abort_session(&self) -> Result<(), LiveError> {
        self.close().await
    }
    async fn shutdown(&self) -> Result<(), LiveError> {
        self.close().await
    }
    async fn decide_permission(
        &self,
        _request_id: &PermissionRequestId,
        _decision: PermissionDecision,
    ) -> Result<(), LiveError> {
        Err(unsupported("permission decisions", &self.route.harness_id))
    }
    async fn decide_approval(
        &self,
        _approval_id: &ApprovalId,
        _expected_revision: u64,
        _decision: ApprovalDecision,
    ) -> Result<(), LiveError> {
        Err(unsupported("approval decisions", &self.route.harness_id))
    }
    async fn bridge_ready(&self) -> bool {
        self.failed.borrow().is_none()
            && self
                .state
                .lock()
                .map(|state| !state.closed)
                .unwrap_or(false)
    }
}

#[cfg(test)]
#[path = "terminal_interrupt_tests.rs"]
mod interrupt_tests;

#[cfg(test)]
mod tests {
    use super::super::decode::ends_turn;
    use super::*;

    struct NoPods;

    #[async_trait]
    impl super::super::PodTerminals for NoPods {
        async fn start(
            &self,
            _request: super::super::PodTerminalRequest,
        ) -> Result<super::super::PodTerminal, LiveError> {
            unreachable!("the pod is already up")
        }

        async fn stop(&self, _session: &str) -> Result<(), LiveError> {
            Ok(())
        }
    }

    #[tokio::test]
    async fn unconfirmed_unit_stop_propagates_and_keeps_durable_recovery() {
        let store = Arc::new(Mutex::new(odin_ledger::Ledger::open_in_memory().unwrap()));
        let channel = odin_kernel::recovery_worker_channel(
            "unix:path=/tmp/odin-terminal-stop-test-absent-bus.sock",
        )
        .expect("recovery channel");
        let authority = Arc::new(StopAuthority::new(Arc::clone(&store), channel));
        let correlation = CorrelationId::new("44444444444444444444444444444444").unwrap();
        let worker = authority
            .register_terminal_intent("odin-term-b2c3d4e5.service", &correlation)
            .expect("register unproved terminal intent");
        assert!(matches!(
            stop_registered_terminal(&authority, &worker).await,
            Err(LiveError::Unavailable { code })
                if code == format!("terminal_unit_stop_unconfirmed: {}", worker.as_str())
        ));
        assert!(authority.stop_record(&worker).unwrap().is_some());
    }

    #[tokio::test]
    async fn unconfirmed_pod_stop_propagates_without_closing_and_can_be_retried() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        struct Pods(AtomicUsize);
        #[async_trait]
        impl super::super::PodTerminals for Pods {
            async fn start(
                &self,
                _: super::super::PodTerminalRequest,
            ) -> Result<super::super::PodTerminal, LiveError> {
                unreachable!("no pod is launched by this regression")
            }
            async fn stop(&self, _: &str) -> Result<(), LiveError> {
                if self.0.fetch_add(1, Ordering::SeqCst) == 0 {
                    Err(LiveError::Unavailable {
                        code: "authority_stop_unproven".to_owned(),
                    })
                } else {
                    Ok(())
                }
            }
        }
        let pods = Arc::new(Pods(AtomicUsize::new(0)));
        let session = odin_domain::huginn::LiveSessionId::new(uuid::Uuid::new_v4()).unwrap();
        let (frames, mut observed) = broadcast::channel(8);
        let (failed, _) = watch::channel(None);
        let (stop_follow, follow_stopped) = watch::channel(false);
        let control = TerminalControl {
            manifest: SessionManifest {
                session_id: session,
                seat_id: odin_domain::SeatId::new("reginn").unwrap(),
                slice_id: odin_domain::SliceId::new("gungnir-build").unwrap(),
                project_id: odin_domain::ProjectId::new("surtr").unwrap(),
                provider: ProviderName::new("fixture-terminal").unwrap(),
                model: ModelName::new("fixture-model").unwrap(),
                target_node: NodeId::new("mini").unwrap(),
                title: None,
                open_tab: false,
                workload: None,
                served_revision: None,
                harness: None,
            },
            route: HarnessRoute {
                harness_id: "fixture-terminal".to_owned(),
                harness: toml::from_str(
                    r#"
schema = "odin.registry.v1"
kind = "harness"
enabled = true
description = "Generic terminal stop fixture"
protocol = "terminal"
governance = "observed"
command = ["fixture-terminal"]
prompt = "keys"
output = "text"
[stop]
signal = "SIGTERM"
grace_seconds = 10
"#,
                )
                .unwrap(),
                environment_id: "pod-authority".to_owned(),
                environment: toml::from_str(include_str!(
                    "../../../../../registry/environments/pod-authority/environment.toml"
                ))
                .unwrap(),
                account: None,
            },
            workspace: PathBuf::new(),
            transport: TerminalTransport::Pod {
                terminal: super::super::PodTerminal {
                    pod: "owned-pod".to_owned(),
                    exec: Vec::new(),
                    attach: Vec::new(),
                },
                pods: pods.clone(),
                session: session.to_string(),
            },
            frames,
            failed,
            state: Arc::new(Mutex::new(TermState {
                turns: 1,
                running: Some("turn-1".to_owned()),
                briefed: true,
                closed: false,
            })),
            stop_follow,
            stopped: tokio::sync::Mutex::new(false),
            incidents: None,
            _kernel: None,
        };
        assert!(
            matches!(control.shutdown().await, Err(LiveError::Unavailable { code }) if code == "authority_stop_unproven")
        );
        assert!(!control.state.lock().expect("state").closed);
        assert!(control.state.lock().expect("state").running.is_some());
        assert!(!*follow_stopped.borrow());
        assert!(
            observed.try_recv().is_err(),
            "failed custody stop must emit no stopped turn"
        );
        // Closed input must not suppress stop retries.
        control.state.lock().expect("state").closed = true;
        control.abort_session().await.unwrap();
        assert!(*follow_stopped.borrow());
        assert!(control.state.lock().expect("state").running.is_none());
        assert!(
            observed.try_recv().is_err(),
            "confirmed custody stop emits no synthetic turn under the turn fence"
        );
        control.shutdown().await.unwrap();
        assert_eq!(
            pods.0.load(Ordering::SeqCst),
            2,
            "confirmed stop is idempotent"
        );
    }

    #[test]
    fn a_pod_terminal_runs_the_same_tmux_client_through_exec() {
        let exec: Vec<String> = [
            "kubectl",
            "exec",
            "-i",
            "odin-term-1",
            "-c",
            "agent",
            "--",
            "/odin/bin/tmux",
            "-S",
            "/run/odin-term/tmux.sock",
        ]
        .map(str::to_owned)
        .to_vec();
        let transport = TerminalTransport::Pod {
            terminal: super::super::PodTerminal {
                pod: "odin-term-1".to_owned(),
                exec: exec.clone(),
                attach: vec!["kubectl".to_owned(), "attach-it".to_owned()],
            },
            pods: Arc::new(NoPods),
            session: "s".to_owned(),
        };
        let mut command = transport.tmux();
        command.args(["send-keys", "-t", SESSION, "Enter"]);
        let command = command.as_std();
        assert_eq!(command.get_program(), "kubectl");
        let args: Vec<String> = command
            .get_args()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect();
        let mut expected = exec[1..].to_vec();
        expected.extend(["send-keys", "-t", SESSION, "Enter"].map(str::to_owned));
        assert_eq!(args, expected);
        assert_eq!(transport.attach(), ["kubectl", "attach-it"]);
        assert_eq!(transport.describe(), "pod=odin-term-1");
    }

    /// ProtectHome makes the home read-only; runtime files need the writable runtime directory.
    #[test]
    fn session_runtime_files_live_in_the_user_runtime_directory() {
        std::env::set_var("XDG_RUNTIME_DIR", "/run/user/1000");
        let session = "e60ff7b2-1111-4222-8333-444455556666";
        assert_eq!(
            runtime_dir(session),
            Path::new("/run/user/1000/odin-term/e60ff7b2")
        );
        assert_eq!(
            mcp_config_path(session),
            Path::new("/run/user/1000/odin-term/e60ff7b2/mcp.json")
        );
        assert_eq!(
            super::super::mcp_config_path(session).as_deref(),
            Some(Path::new("/run/user/1000/odin-mcp/e60ff7b2/mcp.json"))
        );
    }

    #[test]
    fn the_workspace_slug_is_claude_codes_project_directory() {
        assert_eq!(
            workspace_slug(Path::new("/home/colin/.local/state/odin/ws/a_b")),
            "-home-colin--local-state-odin-ws-a-b"
        );
        assert_eq!(
            expand(
                "{home}/.claude/projects/{workspace_slug}",
                Path::new("/home/colin"),
                Path::new("/w/x")
            ),
            "/home/colin/.claude/projects/-w-x"
        );
    }

    #[test]
    fn slash_commands_are_typed_not_awaited() {
        assert!(is_slash_command("/clear"));
        assert!(is_slash_command("  /model opus "));
        assert!(!is_slash_command("/"));
        assert!(!is_slash_command("fix /etc paths\nplease"));
        assert!(!is_slash_command("run the tests"));
    }

    #[test]
    fn only_an_end_turn_assistant_record_ends_the_turn() {
        let tool: Value = serde_json::from_str(
            r#"{"type":"assistant","message":{"role":"assistant","stop_reason":"tool_use","content":[{"type":"tool_use","id":"t","name":"Bash","input":{}}]}}"#,
        )
        .unwrap();
        let done: Value = serde_json::from_str(
            r#"{"type":"assistant","message":{"role":"assistant","stop_reason":"end_turn","content":[{"type":"text","text":"Done."}]}}"#,
        )
        .unwrap();
        let user: Value =
            serde_json::from_str(r#"{"type":"user","message":{"role":"user","content":"hi"}}"#)
                .unwrap();
        assert!(!ends_turn(&tool));
        assert!(ends_turn(&done));
        assert!(!ends_turn(&user));
    }

    #[test]
    fn tmux_liveness_is_not_checked_on_every_poll() {
        assert!(liveness_due(0));
        assert!(!liveness_due(1));
        assert!(!liveness_due(LIVENESS_TICKS - 1));
        assert!(liveness_due(LIVENESS_TICKS));
    }

    #[test]
    fn the_transcript_directory_is_listed_only_when_the_follow_changes() {
        assert!(transcript_rescan(false, false));
        assert!(transcript_rescan(false, true));
        assert!(transcript_rescan(true, true));
        assert!(!transcript_rescan(true, false));
    }

    #[test]
    fn startup_questions_are_recognised() {
        assert_eq!(
            screen_gate(
                " Do you trust the files in this folder?\n ❯ 1. Yes, proceed\n   2. No, exit"
            ),
            Some(ScreenGate::TrustFolder)
        );
        assert_eq!(
            screen_gate(" Select login method:\n ❯ 1. Claude account with subscription"),
            Some(ScreenGate::SignIn)
        );
        assert_eq!(
            screen_gate(
                " Let's get started.\n Choose the text style that looks best with your terminal"
            ),
            Some(ScreenGate::Theme)
        );
        assert_eq!(
            screen_gate(
                "WARNING: Claude Code running in Bypass Permissions mode\n ❯ 1. No, exit\n   2. Yes, I accept"
            ),
            Some(ScreenGate::BypassConsent)
        );
        assert_eq!(screen_gate("> try \"fix lint errors\""), None);
    }

    /// The follower reads only whole characters and never re-reads.
    #[tokio::test]
    async fn the_transcript_reader_resumes_where_it_stopped() {
        let dir = std::env::temp_dir().join(format!("odin-term-test-{}", std::process::id()));
        tokio::fs::create_dir_all(&dir).await.unwrap();
        let file = dir.join("s.jsonl");
        tokio::fs::write(&file, "{\"a\":1}\n{\"b\":\"\u{e9}")
            .await
            .unwrap();
        let mut offset = 0;
        let first = read_from(&file, &mut offset).await.unwrap();
        assert_eq!(first, "{\"a\":1}\n{\"b\":\"\u{e9}");
        let mut append = tokio::fs::OpenOptions::new()
            .append(true)
            .open(&file)
            .await
            .unwrap();
        append.write_all(b"\"}\n").await.unwrap();
        let second = read_from(&file, &mut offset).await.unwrap();
        assert_eq!(second, "\"}\n");
        assert_eq!(
            newest_transcript(&dir).await.as_deref(),
            Some(file.as_path())
        );
        let _ = tokio::fs::remove_dir_all(&dir).await;
    }

    /// A cancelled tmux client takes its whole process group with it: the
    /// fake tmux forks a grandchild that survives the direct child's
    /// kill_on_drop, so only the group kill can prove the cleanup.
    #[tokio::test]
    async fn cancelling_tmux_output_takes_its_process_group_with_it() {
        let root = std::env::temp_dir().join(format!("odin-term-group-{}", std::process::id()));
        tokio::fs::create_dir_all(&root).await.unwrap();
        let grandchild_record = root.join("grandchild");
        let tmux = root.join("tmux");
        tokio::fs::write(
            &tmux,
            format!(
                "#!/bin/sh\nsleep 61 & printf '%s\\n' \"$!\" > {}\nexec sleep 61\n",
                grandchild_record.display()
            ),
        )
        .await
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
        let mut client = tmux_command(&tmux, &root.join("tmux.sock"), &client_path);
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
        let mut grandchild_text = String::new();
        let mut reader = tokio::fs::File::open(&grandchild_record).await;
        for _ in 0..100 {
            if let Ok(file) = &mut reader {
                if file.read_to_string(&mut grandchild_text).await.is_ok()
                    && !grandchild_text.trim().is_empty()
                {
                    break;
                }
            } else {
                reader = tokio::fs::File::open(&grandchild_record).await;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        let grandchild: u32 = grandchild_text.trim().parse().expect("grandchild pid");
        let exists = |pid: u32| std::path::Path::new(&format!("/proc/{pid}")).exists();
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
        let _ = tokio::fs::remove_dir_all(&root).await;
    }

    /// A completed client is reaped, not group-signaled: the guard goes
    /// inert after a wait, so the output arrives and nothing else is
    /// signaled.
    #[tokio::test]
    async fn a_completed_tmux_client_is_reaped_without_a_group_kill() {
        let root = std::env::temp_dir().join(format!("odin-term-done-{}", std::process::id()));
        tokio::fs::create_dir_all(&root).await.unwrap();
        let tmux = root.join("tmux");
        tokio::fs::write(&tmux, "#!/bin/sh\necho ok\n")
            .await
            .unwrap();
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&tmux, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        let mut client = tmux_command(&tmux, &root.join("tmux.sock"), "/bin");
        let group = GroupChild::spawn(&mut client).expect("fake tmux client");
        let output = group.output().await.expect("completed client");
        assert!(output.status.success());
        assert_eq!(String::from_utf8_lossy(&output.stdout).trim(), "ok");
        let _ = tokio::fs::remove_dir_all(&root).await;
    }

    /// The terminal stop row's correlation is the session id's hex: the
    /// same session re-derives the same correlation after a restart.
    #[test]
    fn terminal_rows_derive_their_correlation_from_the_session() {
        assert_eq!(
            terminal_correlation("e60ff7b2-1111-4222-8333-444455556666")
                .expect("correlation")
                .as_str(),
            "e60ff7b2111142228333444455556666"
        );
    }
}
