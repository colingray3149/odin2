//! Non-OMP harnesses: a seat whose declared launch
//! option names a `process` harness runs that CLI agent (Codex, any
//! line-speaking agent) instead of the pinned OMP — one process per
//! prompt, in the session's own workspace, inside the declared environment
//! (a confined transient user unit on a fleet host, or a process on an ssh
//! machine). Its output is decoded into the canonical session-event frames,
//! so the journal, Huginn, the session's Zellij tab, delegated-task
//! completion and stop all work exactly as for OMP. Governance is honest:
//! the agent's own tools are not mediated by the kernel (`observed`). An
//! `acp` harness runs the same way, its turn spoken over the Agent Client
//! Protocol instead of decoded from lines (`acp.rs`). Claude Code is not a
//! seat harness anywhere: it is driven only by the `claude.*` workload
//! driver, and a route claiming a Claude account is refused below.

mod account;
mod acp;
mod decode;
mod driver;
mod followers;
mod observe;
mod terminal;
mod transports;
mod turns;

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use odin_domain::huginn::{
    ApprovalDecision, LiveContentBlock, LiveError, LiveMessage, ModelName, PermissionDecision,
    PermissionRequestId, SessionEpoch, SessionManifest,
};
use odin_domain::{ApprovalId, NodeId};
use odin_registry::{
    AccountKind, EnvironmentToml, EnvironmentTransport, HarnessPrompt, HarnessProtocol,
    HarnessToml, DEFAULT_ACCOUNT,
};
use serde_json::{json, Value};
use tokio::process::{Child, Command};
use tokio::sync::{broadcast, watch};

use super::control::LiveControlBackend;
use super::supervisor::{LaunchEffects, LiveSessionLauncher, SessionRuntime};
use super::target::TerminalTargetAdmin;
use super::zellij::ZellijLiveAdapter;
use crate::bridge::ObservedFrame;
use crate::live::kernel_mcp::{KernelMcpServer, McpEndpoint, McpRegistration};
use driver::{AcpPrompt, Teardown, TurnDriver, TEARDOWN};

pub use account::{AccountRefusal, ProjectAccounts};
pub use decode::{Decoded, OutputDecoder};
pub use followers::ObserverFollowers;
pub use observe::HarnessIncidentSink;
pub use transports::{fleet_host_argv, ssh_host_argv, SSH_OPTIONS};
pub use turns::HarnessTurns;

/// One declared harness with the environment a launch option pairs it with.
#[derive(Clone, Debug)]
pub struct HarnessRoute {
    pub harness_id: String,
    pub harness: HarnessToml,
    pub environment_id: String,
    pub environment: EnvironmentToml,
    /// The account the session runs on, once resolved at launch.
    pub account: Option<String>,
}

/// Where a session's agent works and how its work is handed back. The daemon
/// implements it over the declared project roots (a fresh clone on
/// `seat/<seat>/<session>`; the branch is pushed into the project's own
/// repository after each turn — or the exact seat branch the agent moved
/// the workspace to, how a task naming its branch reaches the publish step).
#[async_trait]
pub trait HarnessWorkspace: Send + Sync {
    /// The session's workspace directory, prepared on first use (idempotent
    /// per session), on the environment's machine.
    async fn prepare(
        &self,
        manifest: &SessionManifest,
        route: &HarnessRoute,
    ) -> Result<PathBuf, LiveError>;

    /// Commits whatever the turn changed and pushes the session's seat
    /// branch — the exact seat branch the workspace was moved to, when it
    /// was; returns one plain sentence for the result, or `None` when
    /// nothing changed.
    async fn hand_back(
        &self,
        manifest: &SessionManifest,
        route: &HarnessRoute,
        workspace: &Path,
    ) -> Result<Option<String>, LiveError>;
}

/// The session's Zellij tab for a harness session (the production factory
/// opens it on the declared terminal surface).
#[async_trait]
pub trait HarnessTerminals: Send + Sync {
    async fn open(
        &self,
        manifest: &SessionManifest,
        cwd: &Path,
    ) -> Result<Option<Arc<ZellijLiveAdapter>>, LiveError>;

    /// The tab running `attach` (the agent's own terminal, a `terminal`
    /// harness) in place of the journal-following client.
    async fn open_attached(
        &self,
        manifest: &SessionManifest,
        cwd: &Path,
        attach: Vec<String>,
    ) -> Result<Option<Arc<ZellijLiveAdapter>>, LiveError> {
        let _ = attach;
        self.open(manifest, cwd).await
    }
}

/// Starts and stops a terminal harness's pod; terminal commands use `exec`.
#[async_trait]
pub trait PodTerminals: Send + Sync {
    /// Starts (or, on reclaim, adopts) the session's pod with its tmux
    /// server running, and says how to reach that server.
    async fn start(&self, request: PodTerminalRequest) -> Result<PodTerminal, LiveError>;

    /// Stops the session's pod (gone already is success).
    async fn stop(&self, session: &str) -> Result<(), LiveError>;
}

/// What one terminal pod is started with. Every path is host-side and is
/// mounted at the same path in the pod.
#[derive(Clone, Debug)]
pub struct PodTerminalRequest {
    pub manifest: SessionManifest,
    pub home: PathBuf,
    pub workspace: PathBuf,
    /// The session's runtime directory (its MCP config), read-only.
    pub runtime: Option<PathBuf>,
    /// The declared credential directories the harness's state needs.
    pub credentials: Vec<PathBuf>,
    pub allow_hosts: Vec<String>,
    /// The kernel MCP bridge URL the agent is configured with.
    pub bridge: Option<String>,
    /// The environment's declared git mirror host.
    pub git_mirror: Option<String>,
}

/// How Odin reaches one pod's tmux server.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PodTerminal {
    pub pod: String,
    /// The argv of a non-interactive tmux client in the pod, up to and
    /// including `tmux -S <socket>` (its arguments follow).
    pub exec: Vec<String>,
    /// The interactive argv the session's tab runs to attach.
    pub attach: Vec<String>,
}

/// Why a terminal harness was refused a pod, before any pod exists.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum TerminalPodRefusal {
    #[error("this odind composes no terminal pods (no cluster)")]
    NoCluster,
    #[error("environment {environment} declares no [pod] for its pods")]
    NoPodDeclaration { environment: String },
    #[error(
        "environment {environment} does not admit the {kind} account the {harness} harness \
         signs in with; Colin decides which accounts ride into a pod: add \"{kind}\" to [pod] \
         accounts in registry/environments/{environment}/environment.toml"
    )]
    AccountNotAdmitted {
        environment: String,
        harness: String,
        kind: &'static str,
    },
}

impl TerminalPodRefusal {
    pub const fn code(&self) -> &'static str {
        match self {
            Self::NoCluster => "terminal_pod_no_cluster",
            Self::NoPodDeclaration { .. } => "terminal_pod_undeclared",
            Self::AccountNotAdmitted { .. } => "terminal_pod_account_not_admitted",
        }
    }
}

impl From<TerminalPodRefusal> for LiveError {
    fn from(refusal: TerminalPodRefusal) -> Self {
        LiveError::Conflict {
            code: refusal.code().to_owned(),
            message: refusal.to_string(),
        }
    }
}

/// Mounts only the session account's login when the pod admits that account kind.
pub fn pod_credentials(
    route: &HarnessRoute,
    home: &Path,
) -> Result<Vec<PathBuf>, TerminalPodRefusal> {
    let pod =
        route
            .environment
            .pod
            .as_ref()
            .ok_or_else(|| TerminalPodRefusal::NoPodDeclaration {
                environment: route.environment_id.clone(),
            })?;
    let Some(kind) = route.harness.account else {
        return Ok(Vec::new());
    };
    if !pod.accounts.contains(&kind) {
        return Err(TerminalPodRefusal::AccountNotAdmitted {
            environment: route.environment_id.clone(),
            harness: route.harness_id.clone(),
            kind: kind.as_str(),
        });
    }
    Ok(kind
        .layout(route.account.as_deref().unwrap_or(DEFAULT_ACCOUNT))
        .paths
        .iter()
        .map(|path| home.join(path))
        .collect())
}

/// The supervisor's launcher: OMP manifests go to the pinned OMP launcher;
/// a manifest whose option names a declared process harness runs it here.
pub struct HarnessLauncher {
    omp: Arc<dyn LiveSessionLauncher>,
    routes: BTreeMap<(String, String), HarnessRoute>,
    workspace: Arc<dyn HarnessWorkspace>,
    terminals: Option<Arc<dyn HarnessTerminals>>,
    incidents: Option<Arc<dyn HarnessIncidentSink>>,
    kernel: Option<Arc<KernelMcpServer>>,
    pods: Option<Arc<dyn PodTerminals>>,
    stops: Option<Arc<odin_kernel::StopAuthority>>,
    accounts: ProjectAccounts,
    /// odind's home: accounts, state paths and the workspace roots live under it.
    home: PathBuf,
    followers: Arc<ObserverFollowers>,
    turns: Arc<HarnessTurns>,
}

impl HarnessLauncher {
    pub fn with_kernel_mcp(mut self, server: Arc<KernelMcpServer>) -> Self {
        self.kernel = Some(server);
        self
    }

    /// The cluster a `k3s-pod` terminal harness runs its pods on.
    pub fn with_pod_terminals(mut self, pods: Arc<dyn PodTerminals>) -> Self {
        self.pods = Some(pods);
        self
    }

    pub fn with_stops(mut self, stops: Arc<odin_kernel::StopAuthority>) -> Self {
        self.stops = Some(stops);
        self
    }

    /// The account each project's agents sign in with, by kind.
    pub fn with_project_accounts(mut self, accounts: ProjectAccounts) -> Self {
        self.accounts = accounts;
        self
    }

    /// Where observed sessions' watchdog hits go.
    pub fn with_incidents(mut self, sink: Arc<dyn HarnessIncidentSink>) -> Self {
        self.incidents = Some(sink);
        self
    }

    pub fn new(
        omp: Arc<dyn LiveSessionLauncher>,
        routes: Vec<HarnessRoute>,
        workspace: Arc<dyn HarnessWorkspace>,
        terminals: Option<Arc<dyn HarnessTerminals>>,
    ) -> Self {
        Self {
            omp,
            routes: routes
                .into_iter()
                .map(|route| {
                    (
                        (route.harness_id.clone(), route.environment_id.clone()),
                        route,
                    )
                })
                .collect(),
            workspace,
            terminals,
            incidents: None,
            kernel: None,
            pods: None,
            stops: None,
            accounts: ProjectAccounts::new(),
            home: std::env::var_os("HOME")
                .map(PathBuf::from)
                .unwrap_or_default(),
            followers: Arc::new(ObserverFollowers::new()),
            turns: HarnessTurns::new(),
        }
    }
}

#[async_trait]
impl LiveSessionLauncher for HarnessLauncher {
    async fn open(
        &self,
        manifest: &SessionManifest,
        epoch: SessionEpoch,
        reclaim: bool,
    ) -> Result<SessionRuntime, LiveError> {
        self.open_owned(manifest, epoch, reclaim, LaunchEffects::default())
            .await
    }

    async fn open_owned(
        &self,
        manifest: &SessionManifest,
        epoch: SessionEpoch,
        reclaim: bool,
        effects: LaunchEffects,
    ) -> Result<SessionRuntime, LiveError> {
        let Some(binding) = manifest.harness.as_ref() else {
            return self.omp.open_owned(manifest, epoch, reclaim, effects).await;
        };
        let route = self
            .routes
            .get(&(binding.harness.clone(), binding.environment.clone()))
            .cloned()
            .ok_or_else(|| LiveError::NotFound {
                object_kind: "harnessRoute".to_owned(),
                object_id: format!("{}@{}", binding.harness, binding.environment),
            })?;
        if !route.environment.seats.contains(&manifest.seat_id) {
            tracing::error!(
                "odind: harness refused session={} seat={} environment={} reason=\"the \
                 environment does not admit this seat\"",
                manifest.session_id,
                manifest.seat_id,
                route.environment_id
            );
            return Err(LiveError::Unauthorized);
        }
        let observing = route.harness.protocol == HarnessProtocol::Observe;
        if observing != (route.environment.transport == EnvironmentTransport::RemoteSession)
            || (observing
                && (!route.harness.check().is_empty()
                    || binding.account.is_some()
                    || route.account.is_some()
                    || !matches!(
                        route.environment.observation.format.as_deref(),
                        Some("claude-stream-json" | "codex-json" | "text")
                    )))
        {
            return Err(unsupported("observe requires a passive remote-session route without an account and with a declared transcript format", &route.harness_id));
        }
        if route.harness.protocol == HarnessProtocol::Omp {
            return Err(LiveError::Unsupported {
                operation: format!(
                    "harness {} speaks {:?}; the pinned OMP is launched by the OMP runtime",
                    route.harness_id, route.harness.protocol
                ),
            });
        }
        // Attach clients and delegated children require the durable run before opening.
        // Track driving opens so shutdown rejects new ones and joins pending ones.
        let _admission = if observing {
            None
        } else {
            Some(self.turns.admit()?)
        };
        effects.mark_started();
        self.omp.ensure_session_run(manifest).await?;
        if observing {
            return self.open_observed(manifest, route).await;
        }
        let route = self.resolve_account(manifest, route)?;
        let workspace = self.workspace.prepare(manifest, &route).await?;
        if route.harness.protocol == HarnessProtocol::Terminal {
            return self.open_terminal(manifest, route, workspace).await;
        }
        // The tab follows the session journal; it shows on the authority
        // whichever machine the agent runs on.
        let terminal = match &self.terminals {
            Some(terminals) => terminals.open(manifest, &workspace).await?,
            None => None,
        };
        // A process harness reads its MCP config from a file of its own; an
        // ACP agent is handed the server in `session/new`.
        let config = (route.harness.mcp_config_arg.is_some()
            && route.harness.protocol == HarnessProtocol::Process)
            .then(|| mcp_config_path(&manifest.session_id.to_string()))
            .flatten();
        let kernel = self
            .kernel_bridge(manifest, &route, &workspace, config.as_deref())
            .await;
        let (frames, observations) = broadcast::channel(1024);
        let (failed_tx, failed_notices) = watch::channel(None);
        tracing::info!(
            "odind: harness open session={} seat={} harness={} protocol={:?} environment={} \
             transport={} governance=observed workspace={}",
            manifest.session_id,
            manifest.seat_id,
            route.harness_id,
            route.harness.protocol,
            route.environment_id,
            route.environment.transport.as_str(),
            workspace.display()
        );
        let mcp_config = kernel.as_ref().and(config);
        let control = Arc::new(ProcessHarnessControl {
            manifest: manifest.clone(),
            route,
            workspace,
            kernel,
            mcp_config,
            hand_back: Arc::clone(&self.workspace),
            frames,
            failed: failed_tx,
            state: Arc::new(Mutex::new(TurnState {
                model: manifest.model.clone(),
                agent_session: None,
                running: None,
                turns: 0,
                closed: false,
            })),
            teardown: TEARDOWN,
            turns: Arc::clone(&self.turns),
        });
        Ok(SessionRuntime {
            control,
            terminal,
            observations: Some(observations),
            failed_notices: Some(failed_notices),
        })
    }

    fn terminal_target_admin(&self) -> Option<Arc<dyn TerminalTargetAdmin>> {
        self.omp.terminal_target_admin()
    }

    fn observer_followers(&self) -> Option<Arc<ObserverFollowers>> {
        Some(Arc::clone(&self.followers))
    }

    fn harness_turns(&self) -> Option<Arc<HarnessTurns>> {
        Some(Arc::clone(&self.turns))
    }
}

impl HarnessLauncher {
    /// The route on the session's account, refused before anything starts
    /// when that account is not signed in on the host the agent runs on.
    fn resolve_account(
        &self,
        manifest: &SessionManifest,
        route: HarnessRoute,
    ) -> Result<HarnessRoute, LiveError> {
        let Some(kind) = route.harness.account else {
            return Ok(route);
        };
        // Reject stale Claude harness routes before touching credentials or workspaces.
        if kind == AccountKind::ClaudeCode {
            tracing::error!(
                "odind: harness refused session={} seat={} harness={} environment={} \
                 reason=harness_claude_account_driver_only",
                manifest.session_id,
                manifest.seat_id,
                route.harness_id,
                route.environment_id
            );
            return Err(LiveError::Conflict {
                code: "harness_claude_account_driver_only".to_owned(),
                message: format!(
                    "harness {} cannot sign Claude Code in: Claude Code is driven only by \
                     the claude.* workload driver (claude.open/prompt/read/stop)",
                    route.harness_id
                ),
            });
        }
        let name = account::session_account(manifest, kind, &self.accounts);
        let local = matches!(
            route.environment.transport,
            EnvironmentTransport::FleetHost | EnvironmentTransport::K3sPod
        );
        let (harness, environment) = (route.harness_id.clone(), route.environment_id.clone());
        match account::with_account(route, name.clone(), &self.home, local) {
            Ok(route) => {
                tracing::info!(
                    "odind: harness account session={} seat={} harness={harness} \
                     environment={environment} account={}:{name}",
                    manifest.session_id,
                    manifest.seat_id,
                    kind.as_str()
                );
                Ok(route)
            }
            Err(refusal) => {
                tracing::error!(
                    "odind: harness refused session={} seat={} harness={harness} \
                     environment={environment} reason={} detail=\"{refusal}\"",
                    manifest.session_id,
                    manifest.seat_id,
                    refusal.code()
                );
                Err(refusal.into())
            }
        }
    }

    /// Runs the interactive agent in a sandboxed terminal that the tab attaches to.
    async fn open_terminal(
        &self,
        manifest: &SessionManifest,
        route: HarnessRoute,
        workspace: PathBuf,
    ) -> Result<SessionRuntime, LiveError> {
        let in_pod = match route.environment.transport {
            EnvironmentTransport::FleetHost => false,
            EnvironmentTransport::K3sPod => true,
            other => {
                return Err(LiveError::Unsupported {
                    operation: format!(
                        "a terminal harness runs in a fleet-host or k3s-pod environment, not {}",
                        other.as_str()
                    ),
                })
            }
        };
        let home = self.home.clone();
        // A pod is refused before anything exists unless the cluster is
        // composed and every credential its harness needs is declared.
        let pod_plan = if in_pod {
            let refused = |refusal: TerminalPodRefusal| {
                tracing::error!(
                    "odind: terminal pod refused session={} seat={} harness={} environment={} \
                     reason={} detail=\"{refusal}\"",
                    manifest.session_id,
                    manifest.seat_id,
                    route.harness_id,
                    route.environment_id,
                    refusal.code()
                );
                LiveError::from(refusal)
            };
            let pods = self
                .pods
                .clone()
                .ok_or_else(|| refused(TerminalPodRefusal::NoCluster))?;
            let credentials = pod_credentials(&route, &home).map_err(refused)?;
            Some((pods, credentials))
        } else {
            None
        };
        // A state directory bound into a private home must exist to be
        // bound (a file such as `.claude.json` is bound only if it exists).
        for path in &route.harness.state_paths {
            let path = home.join(path);
            if path.extension().is_none() {
                let _ = tokio::fs::create_dir_all(&path).await;
            }
        }
        let config = terminal::mcp_config_path(&manifest.session_id.to_string());
        let kernel = match route.harness.mcp_config_arg {
            Some(_) => self
                .kernel_bridge(manifest, &route, &workspace, Some(&config))
                .await
                .map(|registration| (registration, config)),
            None => None,
        };
        let host = match pod_plan {
            None => terminal::TerminalHost::Unit,
            Some((pods, credentials)) => {
                let terminal = pods
                    .start(PodTerminalRequest {
                        manifest: manifest.clone(),
                        home: home.clone(),
                        workspace: workspace.clone(),
                        runtime: kernel
                            .as_ref()
                            .and_then(|(_, config)| config.parent().map(Path::to_path_buf)),
                        credentials,
                        allow_hosts: route
                            .environment
                            .pod
                            .as_ref()
                            .map(|pod| pod.allow_hosts.clone())
                            .unwrap_or_default(),
                        bridge: kernel
                            .as_ref()
                            .map(|(registration, _)| registration.endpoint.url.clone()),
                        git_mirror: route.environment.git_mirror.clone(),
                    })
                    .await?;
                terminal::TerminalHost::Pod { terminal, pods }
            }
        };
        let (frames, observations) = broadcast::channel(1024);
        let (failed_tx, failed_notices) = watch::channel(None);
        let (control, attach) = terminal::TerminalControl::start(
            terminal::TerminalStart {
                manifest,
                route,
                workspace: workspace.clone(),
                hand_back: Arc::clone(&self.workspace),
                frames,
                failed: failed_tx,
                incidents: self.incidents.clone(),
                kernel,
                stops: self.stops.clone(),
            },
            host,
        )
        .await?;
        let terminal = match &self.terminals {
            Some(terminals) => {
                terminals
                    .open_attached(manifest, &workspace, attach)
                    .await?
            }
            None => None,
        };
        Ok(SessionRuntime {
            control,
            terminal,
            observations: Some(observations),
            failed_notices: Some(failed_notices),
        })
    }

    /// Tracks the transcript follower so shutdown refuses new opens and joins it.
    async fn open_observed(
        &self,
        manifest: &SessionManifest,
        route: HarnessRoute,
    ) -> Result<SessionRuntime, LiveError> {
        if self.followers.stopped() {
            return Err(LiveError::Unavailable {
                code: "observer_stopping".to_owned(),
            });
        }
        let home = self.home.clone();
        let terminal = match &self.terminals {
            Some(terminals) => terminals.open(manifest, &home).await?,
            None => None,
        };
        let (frames, observations) = broadcast::channel(1024);
        let (stopped, stopped_rx) = watch::channel(false);
        let (_failed, failed_notices) = watch::channel(None);
        tracing::info!(
            "odind: observe open session={} seat={} environment={} host={} posture={:?}",
            manifest.session_id,
            manifest.seat_id,
            route.environment_id,
            route.environment.host.as_deref().unwrap_or("?"),
            route.environment.posture()
        );
        let control = Arc::new(observe::ObserveControl {
            environment: route.environment_id.clone(),
            stopped: stopped.clone(),
        });
        if !self.followers.spawn(
            stopped,
            observe::follow(
                manifest.clone(),
                route,
                frames,
                self.incidents.clone(),
                stopped_rx,
            ),
        ) {
            return Err(LiveError::Unavailable {
                code: "observer_stopping".to_owned(),
            });
        }
        Ok(SessionRuntime {
            control,
            terminal,
            observations: Some(observations),
            failed_notices: Some(failed_notices),
        })
    }
}

struct TurnState {
    model: ModelName,
    agent_session: Option<String>,
    running: Option<RunningTurn>,
    turns: u64,
    closed: bool,
}

/// Retained until teardown completes, preventing overlapping prompts.
struct RunningTurn {
    turn: u64,
    /// Taken by the first stop; its driver stops on it.
    stop: Option<tokio::sync::oneshot::Sender<()>>,
    /// `Ok` only after the driver's teardown completes.
    done: watch::Receiver<Option<Result<(), String>>>,
}

struct Reserved {
    turn: u64,
    model: ModelName,
    agent_session: Option<String>,
    stop: tokio::sync::oneshot::Receiver<()>,
    done: watch::Sender<Option<Result<(), String>>>,
    /// The launcher's admission of this turn: a daemon stop joins it until
    /// its driver registers or the reservation is released.
    admission: turns::Admission,
}

/// Releases only the matching turn, leaving a newer turn untouched.
fn retire(state: &Mutex<TurnState>, turn: u64) {
    if let Ok(mut state) = state.lock() {
        if state
            .running
            .as_ref()
            .is_some_and(|running| running.turn == turn)
        {
            state.running = None;
        }
    }
}

struct ProcessHarnessControl {
    manifest: SessionManifest,
    route: HarnessRoute,
    workspace: PathBuf,
    /// The session's kernel MCP endpoint; dropped with the control.
    kernel: Option<McpRegistration>,
    /// The Claude Code MCP config the agent is started with.
    mcp_config: Option<PathBuf>,
    hand_back: Arc<dyn HarnessWorkspace>,
    frames: broadcast::Sender<ObservedFrame>,
    failed: watch::Sender<Option<String>>,
    state: Arc<Mutex<TurnState>>,
    teardown: Teardown,
    turns: Arc<HarnessTurns>,
}

fn lock_failed() -> LiveError {
    LiveError::Unavailable {
        code: "harness_state".to_owned(),
    }
}

fn unsupported(operation: &str, harness: &str) -> LiveError {
    LiveError::Unsupported {
        operation: format!("{operation} is not available under the {harness} harness"),
    }
}

/// The prompt text of one live message.
fn message_text(message: &LiveMessage) -> String {
    message
        .content
        .iter()
        .filter_map(|block| match block {
            LiveContentBlock::Text(text) => Some(text.as_str()),
            _ => None,
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// The prompt one turn sends: a fresh agent conversation (nothing to
/// resume) gets the harness's declared brief first; a resumed one already
/// holds it.
pub fn turn_prompt(harness: &HarnessToml, fresh: bool, prompt: &str) -> String {
    match (&harness.brief, fresh) {
        (Some(brief), true) => format!("{}\n\n{prompt}", brief.trim()),
        _ => prompt.to_owned(),
    }
}

/// The agent's argv for one turn: command, model, resume, prompt.
pub fn agent_argv(
    harness: &HarnessToml,
    model: &str,
    agent_session: Option<&str>,
    prompt: &str,
    mcp_config: Option<&Path>,
) -> Vec<String> {
    let mut argv = harness.command.clone();
    // Right after the declared command, before the model flag: Claude
    // Code's `--mcp-config` takes several values, so a following option —
    // never the prompt — must end it.
    if let (Some(flag), Some(config)) = (&harness.mcp_config_arg, mcp_config) {
        argv.push(flag.clone());
        argv.push(config.display().to_string());
    }
    if let Some(flag) = &harness.model_arg {
        argv.push(flag.clone());
        argv.push(model.to_owned());
    }
    if let Some(session) = agent_session {
        argv.extend(
            harness
                .resume_args
                .iter()
                .map(|argument| argument.replace("{agent_session}", session)),
        );
    }
    if harness.prompt == HarnessPrompt::Argv {
        argv.push(prompt.to_owned());
    }
    argv
}

/// Where a process harness session's MCP config lives, bound read-only
/// into the session's unit (a private home hides everything else).
fn mcp_config_path(session: &str) -> Option<PathBuf> {
    Some(session_runtime_dir("odin-mcp", session).join("mcp.json"))
}

/// Runtime files must live under writable `$XDG_RUNTIME_DIR`, not the read-only home.
pub(crate) fn session_runtime_dir(kind: &str, session: &str) -> PathBuf {
    let short: String = session.chars().take(8).collect();
    std::env::var_os("XDG_RUNTIME_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            PathBuf::from(format!("/run/user/{}", rustix::process::getuid().as_raw()))
        })
        .join(kind)
        .join(short)
}

/// Adds one unit property just before the `--` that starts the agent.
pub(crate) fn bind_before_agent(argv: &mut Vec<String>, property: &str) {
    if let Some(split) = argv.iter().position(|argument| argument == "--") {
        argv.splice(split..split, ["-p".to_owned(), property.to_owned()]);
    }
}

impl HarnessLauncher {
    /// Registers local sessions with the kernel MCP bridge using the OMP surface.
    /// Unsupported surfaces run without it; config writes reuse any existing token.
    async fn kernel_bridge(
        &self,
        manifest: &SessionManifest,
        route: &HarnessRoute,
        workspace: &Path,
        config: Option<&Path>,
    ) -> Option<McpRegistration> {
        let server = self.kernel.as_ref()?;
        let session = manifest.session_id.to_string();
        let in_pod = match route.environment.transport {
            EnvironmentTransport::FleetHost => false,
            EnvironmentTransport::K3sPod => true,
            _ => {
                tracing::warn!(
                    "odind: mcp skipped session={session} seat={} reason=remote_environment \
                     environment={}",
                    manifest.seat_id,
                    route.environment_id
                );
                return None;
            }
        };
        // A pod cannot reach the host's loopback: it gets the node-reachable
        // listener's URL, bearer-protected the same way.
        let url = if in_pod {
            let Some(url) = server.node_url_for(&session) else {
                tracing::warn!(
                    "odind: mcp skipped session={session} seat={} reason=no_node_listener \
                     environment={}",
                    manifest.seat_id,
                    route.environment_id
                );
                return None;
            };
            url
        } else {
            server.url_for(&session)
        };
        let kernel = match self.omp.kernel_session(manifest, workspace).await {
            Ok(kernel) => kernel,
            Err(error) => {
                tracing::warn!(
                    "odind: mcp unavailable session={session} seat={} error=\"{error}\"",
                    manifest.seat_id
                );
                return None;
            }
        };
        let bearer = config.and_then(|path| McpEndpoint::persisted_bearer(path, &url));
        let registration = if in_pod {
            server.register_for_pod(&session, manifest.seat_id.as_str(), kernel, bearer)?
        } else {
            server.register(&session, manifest.seat_id.as_str(), kernel, bearer)
        };
        if let Some(path) = config {
            let written = match path.parent() {
                Some(directory) => tokio::fs::create_dir_all(directory)
                    .await
                    .and_then(|()| registration.endpoint.write_config(path)),
                None => Err(std::io::Error::other("the config path has no directory")),
            };
            if let Err(error) = written {
                tracing::warn!(
                    "odind: mcp unavailable session={session} seat={} reason=config_write \
                     path={} error=\"{error}\"",
                    manifest.seat_id,
                    path.display()
                );
                return None;
            }
        }
        Some(registration)
    }
}

impl ProcessHarnessControl {
    fn emit(&self, frame: Value) {
        // A send fails only when no observer is subscribed (the pump ended
        // with the session); the frame then has nobody to reach.
        let _ = self.frames.send(ObservedFrame::harness_event(frame));
    }

    fn start_turn(&self, message: &LiveMessage) -> Result<(), LiveError> {
        let prompt = message_text(message);
        if prompt.trim().is_empty() {
            return Err(LiveError::InvalidRequest {
                code: "harness_prompt_empty".to_owned(),
                message: "the prompt carries no text".to_owned(),
            });
        }
        let reserved = self.reserve()?;
        match self.spawn_agent(&reserved, prompt) {
            Ok((child, unit, acp, stdin_prompt)) => {
                self.drive(reserved, child, unit, acp, stdin_prompt);
                Ok(())
            }
            Err(error) => {
                self.release(reserved);
                Err(error)
            }
        }
    }

    /// Reserves the next turn in the same lock that finds none held, so two
    /// prompts never both start an agent. The launcher admits it first (a
    /// stopping daemon starts no turn), outside the session's lock.
    fn reserve(&self) -> Result<Reserved, LiveError> {
        let admission = self.turns.admit()?;
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
                    "a {} turn is still running; a process harness takes one prompt at a time",
                    self.route.harness_id
                ),
            });
        }
        state.turns += 1;
        let (stop_tx, stop) = tokio::sync::oneshot::channel();
        let (done, done_rx) = watch::channel(None);
        state.running = Some(RunningTurn {
            turn: state.turns,
            stop: Some(stop_tx),
            done: done_rx,
        });
        Ok(Reserved {
            turn: state.turns,
            model: state.model.clone(),
            agent_session: state.agent_session.clone(),
            stop,
            done,
            admission,
        })
    }

    /// Ends a reservation that started no agent: nothing is left to tear down.
    fn release(&self, reserved: Reserved) {
        retire(&self.state, reserved.turn);
        let _ = reserved.done.send_replace(Some(Ok(())));
    }

    /// Starts the reserved turn's agent on the route's transport: the child,
    /// its transient unit (fleet host), for ACP the turn's prompt, and for a
    /// stdin-prompted agent the prompt its driver writes.
    #[allow(clippy::type_complexity)]
    fn spawn_agent(
        &self,
        reserved: &Reserved,
        prompt: String,
    ) -> Result<(Child, Option<String>, Option<AcpPrompt>, Option<String>), LiveError> {
        let (model, agent_session, turn) =
            (&reserved.model, &reserved.agent_session, reserved.turn);
        let acp = self.route.harness.protocol == HarnessProtocol::Acp;
        // An ACP agent gets its brief inside the conversation, once it is
        // known whether the agent's own session was loaded.
        let prompt = if acp {
            prompt
        } else {
            turn_prompt(&self.route.harness, agent_session.is_none(), &prompt)
        };
        let agent = agent_argv(
            &self.route.harness,
            model.as_str(),
            if acp { None } else { agent_session.as_deref() },
            &prompt,
            self.mcp_config.as_deref(),
        );
        let short: String = self
            .manifest
            .session_id
            .to_string()
            .chars()
            .take(8)
            .collect();
        let (argv, unit) = match self.route.environment.transport {
            EnvironmentTransport::FleetHost => {
                let unit = format!("odin-harness-{short}-{turn}");
                let home = std::env::var_os("HOME").map(PathBuf::from).ok_or_else(|| {
                    LiveError::Unavailable {
                        code: "harness_home".to_owned(),
                    }
                })?;
                let mut argv = fleet_host_argv(&unit, &home, &self.workspace, &self.route, &agent);
                if let Some(directory) = self.mcp_config.as_deref().and_then(Path::parent) {
                    bind_before_agent(
                        &mut argv,
                        &format!("BindReadOnlyPaths={}", directory.display()),
                    );
                }
                (argv, Some(unit))
            }
            EnvironmentTransport::SshHost => {
                let destination = self.route.environment.host.clone().unwrap_or_default();
                // A protocol stream must not pass a tty (echo, CR/LF): an
                // ACP agent ends on its stdin closing instead of a hang-up.
                (
                    ssh_host_argv(&destination, &self.workspace, &agent, !acp),
                    None,
                )
            }
            transport => {
                return Err(LiveError::Unsupported {
                    operation: format!(
                        "a {} environment does not start a harness",
                        transport.as_str()
                    ),
                })
            }
        };
        let mut command = Command::new(&argv[0]);
        command
            .args(&argv[1..])
            .stdin(
                if acp || self.route.harness.prompt == HarnessPrompt::Stdin {
                    Stdio::piped()
                } else {
                    Stdio::null()
                },
            )
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        let child = command.spawn().map_err(|error| LiveError::Unavailable {
            code: format!("harness_spawn: {} ({error})", argv[0]),
        })?;
        // The driver writes a stdin prompt itself, owned with the turn.
        let stdin_prompt =
            (!acp && self.route.harness.prompt == HarnessPrompt::Stdin).then(|| prompt.clone());
        let acp = acp.then(|| AcpPrompt {
            prompt,
            agent_session: agent_session.clone(),
            mcp_servers: self
                .kernel
                .as_ref()
                .map(|kernel| vec![kernel.endpoint.acp_server()])
                .unwrap_or_default(),
        });
        Ok((child, unit, acp, stdin_prompt))
    }

    /// Tracks the driver until shutdown joins it; the driver releases the turn after teardown.
    fn drive(
        &self,
        slot: Reserved,
        child: Child,
        unit: Option<String>,
        acp: Option<AcpPrompt>,
        stdin_prompt: Option<String>,
    ) {
        let turn = slot.turn;
        tracing::info!(
            "odind: harness turn session={} harness={} turn={turn} model={} resume={} unit={}",
            self.manifest.session_id,
            self.route.harness_id,
            slot.model,
            slot.agent_session.is_some(),
            unit.as_deref().unwrap_or("ssh")
        );
        let turn_id = format!("{}-turn-{turn}", self.route.harness_id);
        self.emit(json!({"type": "agent_start", "turnId": turn_id}));
        let Reserved {
            stop,
            done,
            admission,
            ..
        } = slot;
        let verdict = done.subscribe();
        let driver = TurnDriver {
            manifest: self.manifest.clone(),
            route: self.route.clone(),
            workspace: self.workspace.clone(),
            hand_back: Arc::clone(&self.hand_back),
            frames: self.frames.clone(),
            state: Arc::clone(&self.state),
            turn,
            done,
            teardown: self.teardown,
            turn_id,
            unit,
            acp,
            stdin_prompt,
        };
        let task = tokio::spawn(driver.run(child, stop));
        self.turns
            .register(admission, Arc::clone(&self.state), turn, verdict, task);
    }

    /// Signals before awaiting; cancellation or timeout leaves the driver finishing teardown.
    async fn stop_running(&self, close: bool) -> Result<(), LiveError> {
        let stop_by = tokio::time::Instant::now() + self.teardown.stop_within(&self.route);
        let mut signalled = false;
        let (mut done, turn) = {
            let mut state = self.state.lock().map_err(|_| lock_failed())?;
            if close {
                state.closed = true;
            }
            let Some(running) = state.running.as_mut() else {
                return Ok(());
            };
            if let Some(stop) = running.stop.take() {
                signalled = true;
                tracing::info!(
                    "odind: harness stop session={} harness={} turn={}",
                    self.manifest.session_id,
                    self.route.harness_id,
                    running.turn
                );
                let _ = stop.send(());
            }
            (running.done.clone(), running.turn)
        };
        let end = tokio::time::timeout_at(stop_by, done.wait_for(Option::is_some))
            .await
            .map(|end| end.map(|end| end.clone()));
        let reason = match end {
            Ok(Ok(Some(Ok(())))) => return Ok(()),
            Ok(Ok(Some(Err(reason)))) => {
                let ssh = self.route.environment.transport == EnvironmentTransport::SshHost;
                // Session close retains an unresolved turn so repeated close retries teardown.
                if ssh && signalled && !close {
                    retire(&self.state, turn);
                    return Ok(());
                }
                reason
            }
            Err(_elapsed) => {
                tracing::warn!(
                    "odind: harness stop pending session={} harness={}",
                    self.manifest.session_id,
                    self.route.harness_id
                );
                return Err(LiveError::Unavailable {
                    code: "harness_stop_pending".to_owned(),
                });
            }
            _ => "the turn's driver ended without a verdict".to_owned(),
        };
        tracing::error!(
            "odind: harness stop unproven session={} harness={} reason=\"{reason}\"",
            self.manifest.session_id,
            self.route.harness_id
        );
        Err(LiveError::Unavailable {
            code: "harness_stop_unproven".to_owned(),
        })
    }
}

#[async_trait]
impl LiveControlBackend for ProcessHarnessControl {
    async fn prompt(&self, message: &LiveMessage) -> Result<(), LiveError> {
        self.start_turn(message)
    }
    async fn follow_up(&self, message: &LiveMessage) -> Result<(), LiveError> {
        self.start_turn(message)
    }
    async fn steer(&self, _message: &LiveMessage) -> Result<(), LiveError> {
        Err(unsupported(
            "steering a running turn",
            &self.route.harness_id,
        ))
    }
    /// Pausing stops the turn while preserving workspace changes and resumable conversation.
    async fn pause(&self) -> Result<(), LiveError> {
        self.stop_running(false).await
    }
    /// Nothing runs between turns, so there is nothing to wake: the next
    /// prompt starts the agent again where its conversation stopped.
    async fn resume(&self) -> Result<(), LiveError> {
        Ok(())
    }
    async fn checkpoint(&self) -> Result<(), LiveError> {
        Err(unsupported("checkpoint", &self.route.harness_id))
    }
    async fn restart(&self) -> Result<(), LiveError> {
        // The next prompt starts a fresh process that resumes the agent's
        // own conversation; a restart only needs the current turn gone.
        self.stop_running(false).await
    }
    async fn rehome(&self, _target_node: &NodeId) -> Result<(), LiveError> {
        Err(unsupported("rehome", &self.route.harness_id))
    }
    async fn set_model(
        &self,
        _provider: &odin_domain::huginn::ProviderName,
        model: &ModelName,
    ) -> Result<(), LiveError> {
        if self.route.harness.model_arg.is_none() {
            return Err(unsupported("choosing a model", &self.route.harness_id));
        }
        self.state.lock().map_err(|_| lock_failed())?.model = model.clone();
        Ok(())
    }
    async fn abort_turn(&self) -> Result<(), LiveError> {
        self.stop_running(false).await
    }
    async fn abort_session(&self) -> Result<(), LiveError> {
        // The session is over (the actor's terminal stop or a whole-session
        // abort): the turn teardown is the same close, and the session's
        // MCP config goes with it exactly as in `shutdown` — an ended
        // session must not keep private configuration behind.
        self.stop_running(true).await?;
        if let Some(directory) = self.mcp_config.as_deref().and_then(Path::parent) {
            let _ = tokio::fs::remove_dir_all(directory).await;
        }
        Ok(())
    }
    /// Remove MCP config only after the turn's teardown completes.
    async fn shutdown(&self) -> Result<(), LiveError> {
        self.stop_running(true).await?;
        if let Some(directory) = self.mcp_config.as_deref().and_then(Path::parent) {
            let _ = tokio::fs::remove_dir_all(directory).await;
        }
        Ok(())
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
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    use odin_domain::huginn::{HarnessBinding, LiveSessionId, ProviderName};
    use odin_domain::{ProjectId, SeatId, SliceId};

    use super::*;

    /// The inner (OMP) launcher: records the run it is asked to create and
    /// refuses to launch anything itself.
    pub(super) struct RunRecorder {
        pub(super) runs: AtomicUsize,
        pub(super) refuse: bool,
    }

    #[async_trait]
    impl LiveSessionLauncher for RunRecorder {
        fn harness_turns(&self) -> Option<Arc<HarnessTurns>> {
            None
        }

        async fn open(
            &self,
            _manifest: &SessionManifest,
            _epoch: SessionEpoch,
            _reclaim: bool,
        ) -> Result<SessionRuntime, LiveError> {
            Err(LiveError::Unsupported {
                operation: "the fixture launches no OMP session".to_owned(),
            })
        }

        async fn ensure_session_run(&self, _manifest: &SessionManifest) -> Result<(), LiveError> {
            self.runs.fetch_add(1, Ordering::SeqCst);
            if self.refuse {
                return Err(LiveError::Unavailable {
                    code: "bridge_ledger_run".to_owned(),
                });
            }
            Ok(())
        }
    }

    pub(super) struct TempWorkspace {
        pub(super) prepared: AtomicUsize,
    }

    #[async_trait]
    impl HarnessWorkspace for TempWorkspace {
        async fn prepare(
            &self,
            _manifest: &SessionManifest,
            _route: &HarnessRoute,
        ) -> Result<PathBuf, LiveError> {
            self.prepared.fetch_add(1, Ordering::SeqCst);
            Ok(std::env::temp_dir())
        }

        async fn hand_back(
            &self,
            _manifest: &SessionManifest,
            _route: &HarnessRoute,
            _workspace: &Path,
        ) -> Result<Option<String>, LiveError> {
            Ok(None)
        }
    }

    pub(super) fn process_fixture() -> HarnessToml {
        toml::from_str(
            r#"
schema = "odin.registry.v1"
kind = "harness"
enabled = true
description = "Generic process transport fixture."
protocol = "process"
governance = "observed"
command = ["fixture-agent", "--allowedTools", "Read,mcp__odin"]
prompt = "argv"
output = "claude-stream-json"
model_arg = "--model"
mcp_config_arg = "--mcp-config"
resume_args = ["--resume", "{agent_session}"]
state_paths = [".cache/fixture-agent"]
account = "codex"
brief = "Use the declared tools."
[stop]
signal = "SIGINT"
grace_seconds = 10
"#,
        )
        .expect("generic process fixture")
    }

    pub(super) fn terminal_fixture() -> HarnessToml {
        let mut harness = process_fixture();
        harness.protocol = HarnessProtocol::Terminal;
        harness.prompt = HarnessPrompt::Keys;
        harness.command = vec!["fixture-agent".to_owned()];
        harness.resume_args.clear();
        harness.state_paths.clear();
        harness.transcripts = Some("{account}/projects/{workspace_slug}".to_owned());
        harness.stop.signal = "SIGTERM".to_owned();
        harness
    }

    pub(super) fn observe_fixture() -> HarnessToml {
        toml::from_str(include_str!(
            "../../../../registry/harnesses/observe/harness.toml"
        ))
        .expect("observe declaration")
    }
    fn process_on_the_authority() -> HarnessRoute {
        HarnessRoute {
            harness_id: "fixture-process".to_owned(),
            harness: process_fixture(),
            environment_id: "fleet-authority".to_owned(),
            environment: toml::from_str(include_str!(
                "../../../../registry/environments/fleet-authority/environment.toml"
            ))
            .expect("declared fleet-authority environment parses"),
            account: None,
        }
    }

    pub(super) fn reginn_manifest() -> SessionManifest {
        SessionManifest {
            session_id: LiveSessionId::new(uuid::Uuid::new_v4()).expect("session id"),
            seat_id: SeatId::new("reginn").expect("seat id"),
            slice_id: SliceId::new("gungnir-build").expect("slice id"),
            project_id: ProjectId::new("surtr").expect("project id"),
            provider: ProviderName::new("fixture-process").expect("provider"),
            model: ModelName::new("sonnet").expect("model"),
            title: None,
            target_node: NodeId::new("mini").expect("node id"),
            open_tab: false,
            workload: None,
            served_revision: None,
            harness: Some(HarnessBinding {
                harness: "fixture-process".to_owned(),
                environment: "fleet-authority".to_owned(),
                account: None,
            }),
        }
    }

    /// MCP config precedes `--model`; multi-value flags must not consume the prompt.
    #[test]
    fn a_process_agent_is_started_with_the_kernel_bridge_config() {
        let route = process_on_the_authority();
        let config = Path::new("/run/user/1000/odin-mcp/0f1e2d3c/mcp.json");
        let argv = agent_argv(&route.harness, "sonnet", None, "do it", Some(config));
        let flag = argv
            .iter()
            .position(|argument| argument == "--mcp-config")
            .expect("the config flag");
        assert_eq!(argv[flag + 1], config.display().to_string());
        assert_eq!(argv[flag + 2], "--model");
        assert!(argv[flag - 1].ends_with(",mcp__odin"), "{argv:?}");
        assert_eq!(argv.last().map(String::as_str), Some("do it"));
        let plain = agent_argv(&route.harness, "sonnet", None, "do it", None);
        assert!(!plain.iter().any(|argument| argument == "--mcp-config"));
    }

    fn terminal_in_a_pod(accounts: &[odin_registry::AccountKind]) -> HarnessRoute {
        let mut environment: odin_registry::EnvironmentToml = toml::from_str(include_str!(
            "../../../../registry/environments/pod-authority/environment.toml"
        ))
        .expect("declared pod-authority environment parses");
        environment.pod.as_mut().expect("[pod]").accounts = accounts.to_vec();
        HarnessRoute {
            harness_id: "fixture-terminal".to_owned(),
            harness: terminal_fixture(),
            environment_id: "pod-authority".to_owned(),
            environment,
            account: None,
        }
    }

    /// A home where the default codex account and `school` are signed in.
    fn signed_in_home() -> tempfile::TempDir {
        let home = tempfile::tempdir().expect("home");
        for dir in [".codex", ".codex-accounts/school"] {
            std::fs::create_dir_all(home.path().join(dir)).expect("account dir");
            std::fs::write(home.path().join(dir).join("auth.json"), "{}").expect("sign-in");
        }
        home
    }

    #[derive(Default)]
    struct RecordingPods {
        starts: std::sync::Mutex<Vec<PodTerminalRequest>>,
    }

    #[async_trait]
    impl PodTerminals for RecordingPods {
        async fn start(&self, request: PodTerminalRequest) -> Result<PodTerminal, LiveError> {
            self.starts.lock().expect("starts").push(request);
            Err(LiveError::Unavailable {
                code: "test_pod".to_owned(),
            })
        }

        async fn stop(&self, _session: &str) -> Result<(), LiveError> {
            Ok(())
        }
    }

    /// Account admission precedes pod creation; only the selected login is mounted.
    #[test]
    fn a_terminal_pod_carries_only_the_session_account() {
        let home = Path::new("/home/colin");
        let refused = pod_credentials(&terminal_in_a_pod(&[]), home).expect_err("refused");
        assert_eq!(refused.code(), "terminal_pod_account_not_admitted");
        assert!(refused.to_string().contains("codex"));
        assert_eq!(
            pod_credentials(
                &terminal_in_a_pod(&[odin_registry::AccountKind::ClaudeCode]),
                home
            )
            .expect_err("another kind does not admit it")
            .code(),
            "terminal_pod_account_not_admitted"
        );
        let mut school = terminal_in_a_pod(&[odin_registry::AccountKind::Codex]);
        assert_eq!(
            pod_credentials(&school, home).expect("default"),
            [PathBuf::from("/home/colin/.codex")]
        );
        school.account = Some("school".to_owned());
        assert_eq!(
            pod_credentials(&school, home).expect("school"),
            [PathBuf::from("/home/colin/.codex-accounts/school")],
            "only the session account rides in"
        );
        let mut undeclared = terminal_in_a_pod(&[]);
        undeclared.environment.pod = None;
        assert_eq!(
            pod_credentials(&undeclared, home)
                .expect_err("no [pod]")
                .code(),
            "terminal_pod_undeclared"
        );
    }

    #[tokio::test]
    async fn an_unadmitted_or_signed_out_account_refuses_the_launch_before_any_pod() {
        let home = signed_in_home();
        let pods = Arc::new(RecordingPods::default());
        let launcher = |accounts: &[odin_registry::AccountKind]| {
            let mut launcher = HarnessLauncher::new(
                Arc::new(RunRecorder {
                    runs: AtomicUsize::new(0),
                    refuse: false,
                }),
                vec![terminal_in_a_pod(accounts)],
                Arc::new(TempWorkspace {
                    prepared: AtomicUsize::new(0),
                }),
                None,
            )
            .with_pod_terminals(pods.clone())
            .with_project_accounts(ProjectAccounts::from([(
                "surtr".to_owned(),
                BTreeMap::from([(odin_registry::AccountKind::Codex, "school".to_owned())]),
            )]));
            launcher.home = home.path().to_path_buf();
            launcher
        };
        let mut manifest = reginn_manifest();
        manifest.harness = Some(HarnessBinding {
            harness: "fixture-terminal".to_owned(),
            environment: "pod-authority".to_owned(),
            account: None,
        });
        let refusal = |result: Result<SessionRuntime, LiveError>| match result {
            Err(LiveError::Conflict { code, .. }) => code,
            Err(other) => panic!("a typed refusal, not {other:?}"),
            Ok(_) => panic!("the launch must refuse"),
        };
        assert_eq!(
            refusal(
                launcher(&[])
                    .open(&manifest, SessionEpoch::new(1), false)
                    .await
            ),
            "terminal_pod_account_not_admitted"
        );
        let admitting = launcher(&[odin_registry::AccountKind::Codex]);
        manifest.harness.as_mut().expect("binding").account = Some("club".to_owned());
        assert_eq!(
            refusal(admitting.open(&manifest, SessionEpoch::new(1), false).await),
            "harness_account_signed_out"
        );
        assert!(pods.starts.lock().expect("starts").is_empty(), "no pod");
        // Admitted and signed in: the pod is asked for with the project's account and the egress.
        manifest.harness.as_mut().expect("binding").account = None;
        let _ = admitting.open(&manifest, SessionEpoch::new(1), false).await;
        let starts = pods.starts.lock().expect("starts");
        assert_eq!(starts.len(), 1);
        assert_eq!(
            starts[0].credentials,
            [home.path().join(".codex-accounts/school")]
        );
        assert_eq!(
            starts[0].allow_hosts,
            ["api.anthropic.com", "platform.claude.com"]
        );
    }

    #[test]
    fn the_declared_brief_leads_a_fresh_agent_conversation_only() {
        let route = process_on_the_authority();
        let brief = route
            .harness
            .brief
            .clone()
            .expect("the harness declares a brief");
        let fresh = turn_prompt(&route.harness, true, "Assigned task: x");
        assert!(fresh.starts_with(brief.trim()) && fresh.ends_with("Assigned task: x"));
        assert_eq!(turn_prompt(&route.harness, false, "next"), "next");
    }

    #[tokio::test]
    async fn a_process_harness_session_gets_its_run_before_it_opens() {
        let inner = Arc::new(RunRecorder {
            runs: AtomicUsize::new(0),
            refuse: false,
        });
        let workspace = Arc::new(TempWorkspace {
            prepared: AtomicUsize::new(0),
        });
        let home = signed_in_home();
        let mut launcher = HarnessLauncher::new(
            inner.clone(),
            vec![process_on_the_authority()],
            workspace.clone(),
            None,
        );
        launcher.home = home.path().to_path_buf();
        let runtime = launcher
            .open(&reginn_manifest(), SessionEpoch::new(1), false)
            .await;
        assert!(runtime.is_ok(), "the harness session opens");
        assert_eq!(inner.runs.load(Ordering::SeqCst), 1, "its run was ensured");
    }

    #[tokio::test]
    async fn an_observed_session_gets_its_run_before_its_tab() {
        let inner = Arc::new(RunRecorder {
            runs: AtomicUsize::new(0),
            refuse: true,
        });
        let route = HarnessRoute {
            harness_id: "observe".to_owned(),
            harness: observe_fixture(),
            environment_id: "pc-claude-session".to_owned(),
            environment: toml::from_str(include_str!(
                "../../../../registry/environments/pc-claude-session/environment.toml"
            ))
            .expect("declared pc-claude-session environment parses"),
            ..process_on_the_authority()
        };
        assert_eq!(
            route.environment.transport,
            EnvironmentTransport::RemoteSession
        );
        let launcher = HarnessLauncher::new(
            inner.clone(),
            vec![route],
            Arc::new(TempWorkspace {
                prepared: AtomicUsize::new(0),
            }),
            None,
        );
        let mut manifest = reginn_manifest();
        manifest.seat_id = SeatId::new("kubert").expect("seat id");
        manifest.harness = Some(HarnessBinding {
            harness: "observe".to_owned(),
            environment: "pc-claude-session".to_owned(),
            account: None,
        });
        let refused = launcher
            .open(&manifest, SessionEpoch::new(1), false)
            .await
            .err()
            .expect("no observed session without its run");
        assert!(
            matches!(&refused, LiveError::Unavailable { code } if code == "bridge_ledger_run"),
            "{refused:?}"
        );
        assert_eq!(inner.runs.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn an_acp_harness_session_opens() {
        let mut harness = process_fixture();
        harness.protocol = HarnessProtocol::Acp;
        harness.prompt = HarnessPrompt::Rpc;
        harness.output = odin_registry::HarnessOutput::Acp;
        harness.mcp_config_arg = None;
        let route = HarnessRoute {
            harness_id: "fixture-acp".to_owned(),
            harness,
            ..process_on_the_authority()
        };
        assert_eq!(route.harness.protocol, HarnessProtocol::Acp);
        let home = signed_in_home();
        let mut launcher = HarnessLauncher::new(
            Arc::new(RunRecorder {
                runs: AtomicUsize::new(0),
                refuse: false,
            }),
            vec![route],
            Arc::new(TempWorkspace {
                prepared: AtomicUsize::new(0),
            }),
            None,
        );
        launcher.home = home.path().to_path_buf();
        let mut manifest = reginn_manifest();
        manifest.harness = Some(HarnessBinding {
            harness: "fixture-acp".to_owned(),
            environment: "fleet-authority".to_owned(),
            account: None,
        });
        let runtime = launcher.open(&manifest, SessionEpoch::new(1), false).await;
        assert!(runtime.is_ok(), "the acp harness session opens");
    }

    /// The private home contains only the workspace and account state.
    #[test]
    fn the_terminal_harness_runs_in_a_private_home() {
        let route = HarnessRoute {
            harness_id: "fixture-terminal".to_owned(),
            harness: terminal_fixture(),
            environment_id: "sandbox-authority".to_owned(),
            environment: toml::from_str(include_str!(
                "../../../../registry/environments/sandbox-authority/environment.toml"
            ))
            .expect("declared sandbox-authority environment parses"),
            account: None,
        };
        assert_eq!(route.harness.check(), Vec::<String>::new());
        assert_eq!(route.harness.protocol, HarnessProtocol::Terminal);
        let route =
            account::with_account(route, "school".to_owned(), Path::new("/home/colin"), false)
                .expect("school");
        let argv = fleet_host_argv(
            "odin-term-x",
            Path::new("/home/colin"),
            Path::new("/home/colin/valhalla/.odin-workspaces/s"),
            &route,
            &["tmux".to_owned()],
        );
        let properties: Vec<&str> = argv
            .windows(2)
            .filter(|pair| pair[0] == "-p")
            .map(|pair| pair[1].as_str())
            .collect();
        for wanted in [
            "ProtectHome=tmpfs",
            "BindPaths=/home/colin/valhalla/.odin-workspaces/s",
            "BindPaths=-/home/colin/.codex-accounts/school",
            "ProtectSystem=strict",
            "NoNewPrivileges=yes",
        ] {
            assert!(properties.contains(&wanted), "{wanted} in {properties:?}");
        }
        assert!(!properties.contains(&"ProtectHome=read-only"));
        assert!(
            !properties
                .iter()
                .any(|property| property.ends_with("/.claude")
                    || property.ends_with("/.claude.json")),
            "another account's login stays out: {properties:?}"
        );
    }

    #[test]
    fn a_shared_home_hides_every_account_but_the_sessions_own() {
        let home = tempfile::tempdir().expect("home");
        for dir in [
            ".claude-accounts/school",
            ".claude-accounts/club",
            ".codex-accounts/astra",
        ] {
            std::fs::create_dir_all(home.path().join(dir)).expect("account dir");
        }
        let route = HarnessRoute {
            harness_id: "fixture-process".to_owned(),
            harness: process_fixture(),
            environment_id: "fleet-authority".to_owned(),
            environment: toml::from_str(include_str!(
                "../../../../registry/environments/fleet-authority/environment.toml"
            ))
            .expect("declared fleet-authority environment parses"),
            account: None,
        };
        let route =
            account::with_account(route, "school".to_owned(), home.path(), false).expect("school");
        let argv = fleet_host_argv(
            "odin-term-x",
            home.path(),
            &home.path().join("valhalla/.odin-workspaces/s"),
            &route,
            &["fixture-agent".to_owned()],
        );
        let root = home.path().display();
        let hidden: Vec<String> = argv
            .windows(2)
            .filter(|pair| pair[0] == "-p")
            .filter_map(|pair| pair[1].strip_prefix("InaccessiblePaths=-"))
            .map(str::to_owned)
            .collect();
        for foreign in [
            ".claude",
            ".claude.json",
            ".claude-accounts/school",
            ".claude-accounts/club",
            ".codex",
            ".codex-accounts/astra",
        ] {
            assert!(
                hidden.contains(&format!("{root}/{foreign}")),
                "{foreign} in {hidden:?}"
            );
        }
        assert!(
            !hidden
                .iter()
                .any(|path| path.ends_with(".codex-accounts/school")),
            "its own account stays: {hidden:?}"
        );
        assert!(argv.contains(&format!("ReadWritePaths=-{root}/.codex-accounts/school")));
    }

    #[tokio::test]
    async fn a_process_agent_pauses_and_resumes() {
        let home = signed_in_home();
        let mut launcher = HarnessLauncher::new(
            Arc::new(RunRecorder {
                runs: AtomicUsize::new(0),
                refuse: false,
            }),
            vec![process_on_the_authority()],
            Arc::new(TempWorkspace {
                prepared: AtomicUsize::new(0),
            }),
            None,
        );
        launcher.home = home.path().to_path_buf();
        let runtime = launcher
            .open(&reginn_manifest(), SessionEpoch::new(1), false)
            .await
            .expect("opens");
        runtime.control.pause().await.expect("pause stops the turn");
        runtime.control.resume().await.expect("resume");
    }

    #[tokio::test]
    async fn an_unknown_harness_route_refuses_before_launch_effects() {
        let inner = Arc::new(RunRecorder {
            runs: AtomicUsize::new(0),
            refuse: false,
        });
        let workspace = Arc::new(TempWorkspace {
            prepared: AtomicUsize::new(0),
        });
        let launcher = HarnessLauncher::new(inner.clone(), vec![], workspace.clone(), None);
        let effects = LaunchEffects::default();
        let refused = launcher
            .open_owned(
                &reginn_manifest(),
                SessionEpoch::new(1),
                false,
                effects.clone(),
            )
            .await;
        assert!(
            matches!(refused, Err(LiveError::NotFound { ref object_kind, .. })
            if object_kind == "harnessRoute")
        );
        assert!(!effects.started(), "route validation has no launch effects");
        assert_eq!(inner.runs.load(Ordering::SeqCst), 0);
        assert_eq!(workspace.prepared.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn observer_refuses_driving_routes_before_any_launch_effect() {
        for account in [None, Some("missing-login".to_owned())] {
            let inner = Arc::new(RunRecorder {
                runs: AtomicUsize::new(0),
                refuse: false,
            });
            let workspace = Arc::new(TempWorkspace {
                prepared: AtomicUsize::new(0),
            });
            let mut route = process_on_the_authority();
            route.harness = observe_fixture();
            let mut manifest = reginn_manifest();
            manifest.harness.as_mut().unwrap().account = account;
            let launcher =
                HarnessLauncher::new(inner.clone(), vec![route], workspace.clone(), None);
            let effects = LaunchEffects::default();
            assert!(matches!(
                launcher
                    .open_owned(&manifest, SessionEpoch::new(1), false, effects.clone())
                    .await,
                Err(LiveError::Unsupported { .. })
            ));
            assert!(!effects.started());
            assert_eq!(inner.runs.load(Ordering::SeqCst), 0);
            assert_eq!(workspace.prepared.load(Ordering::SeqCst), 0);
        }
    }

    #[tokio::test]
    async fn a_session_whose_run_cannot_be_recorded_does_not_open() {
        let inner = Arc::new(RunRecorder {
            runs: AtomicUsize::new(0),
            refuse: true,
        });
        let workspace = Arc::new(TempWorkspace {
            prepared: AtomicUsize::new(0),
        });
        let launcher = HarnessLauncher::new(
            inner,
            vec![process_on_the_authority()],
            workspace.clone(),
            None,
        );
        let refused = launcher
            .open(&reginn_manifest(), SessionEpoch::new(1), false)
            .await;
        assert!(
            matches!(refused, Err(LiveError::Unavailable { ref code }) if code == "bridge_ledger_run"),
            "the open fails typed with the run's error"
        );
        assert_eq!(workspace.prepared.load(Ordering::SeqCst), 0);
    }

    /// Stale Claude harness routes must be refused before account or workspace access.
    #[tokio::test]
    async fn a_claude_account_harness_route_is_refused_driver_only() {
        let mut harness = process_fixture();
        harness.account = Some(odin_registry::AccountKind::ClaudeCode);
        let route = HarnessRoute {
            harness,
            ..process_on_the_authority()
        };
        let inner = Arc::new(RunRecorder {
            runs: AtomicUsize::new(0),
            refuse: false,
        });
        let workspace = Arc::new(TempWorkspace {
            prepared: AtomicUsize::new(0),
        });
        let home = signed_in_home();
        let mut launcher =
            HarnessLauncher::new(inner.clone(), vec![route], workspace.clone(), None);
        launcher.home = home.path().to_path_buf();
        let refused = launcher
            .open(&reginn_manifest(), SessionEpoch::new(1), false)
            .await;
        match refused {
            Err(LiveError::Conflict { code, message }) => {
                assert_eq!(code, "harness_claude_account_driver_only");
                assert!(message.contains("claude.*"), "{message}");
            }
            Err(other) => panic!("a typed driver-only refusal, not {other:?}"),
            Ok(_) => panic!("the launch must refuse"),
        }
        assert_eq!(workspace.prepared.load(Ordering::SeqCst), 0);
    }

    /// A hand-back held until the test releases it: while it waits, the
    /// turn's owned teardown is provably unfinished.
    struct GatedHandBack {
        entered: tokio::sync::mpsc::UnboundedSender<()>,
        release: tokio::sync::Semaphore,
    }

    #[async_trait]
    impl HarnessWorkspace for GatedHandBack {
        async fn prepare(
            &self,
            _manifest: &SessionManifest,
            _route: &HarnessRoute,
        ) -> Result<PathBuf, LiveError> {
            Ok(std::env::temp_dir())
        }

        async fn hand_back(
            &self,
            _manifest: &SessionManifest,
            _route: &HarnessRoute,
            _workspace: &Path,
        ) -> Result<Option<String>, LiveError> {
            let _ = self.entered.send(());
            self.release.acquire().await.expect("gate").forget();
            Ok(None)
        }
    }

    /// A process control as `open` builds it, on a transport `start_turn`
    /// refuses before spawning: an admitted prompt shows as that refusal
    /// and never starts a unit.
    fn local_control(
        hand_back: Arc<dyn HarnessWorkspace>,
        teardown: Teardown,
    ) -> (ProcessHarnessControl, broadcast::Receiver<ObservedFrame>) {
        let mut route = process_on_the_authority();
        route.environment.transport = EnvironmentTransport::K3sPod;
        let (frames, observations) = broadcast::channel(64);
        let manifest = reginn_manifest();
        let control = ProcessHarnessControl {
            state: Arc::new(Mutex::new(TurnState {
                model: manifest.model.clone(),
                agent_session: None,
                running: None,
                turns: 0,
                closed: false,
            })),
            manifest,
            route,
            workspace: std::env::temp_dir(),
            kernel: None,
            mcp_config: None,
            hand_back,
            frames,
            failed: watch::channel(None).0,
            teardown,
            turns: HarnessTurns::new(),
        };
        (control, observations)
    }

    /// The fixture agent prints one stream-json line, then waits on stdin.
    const WAITS: &str = r#"printf '%s\n' "$1"; read -r _"#;

    /// Reserves and drives a turn through the production path past the
    /// transport, on a real local child running `script` (`unit` names the
    /// unit the teardown's manager is asked to stop).
    fn drive_local_turn(control: &ProcessHarnessControl, script: &str, unit: Option<&str>) -> u32 {
        let line =
            r#"{"type":"assistant","message":{"content":[{"type":"text","text":"working"}]}}"#;
        let slot = control.reserve().expect("a turn is reserved");
        let child = Command::new("sh")
            .args(["-c", script, "fixture-agent", line])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .expect("the fixture agent starts");
        let pid = child.id().expect("a running agent");
        control.drive(slot, child, unit.map(str::to_owned), None, None);
        pid
    }

    /// The next frame of `kind`, bounded so a broken driver fails, not hangs.
    async fn next_frame(
        observations: &mut broadcast::Receiver<ObservedFrame>,
        kind: &str,
    ) -> Value {
        let next = async {
            loop {
                let frame = observations.recv().await.expect("frames");
                let value = frame.decoded.expect("decoded").value().clone();
                if value["type"] == kind {
                    return value;
                }
            }
        };
        tokio::time::timeout(Duration::from_secs(10), next)
            .await
            .expect("the frame arrives")
    }

    fn reaped(pid: u32) -> bool {
        !Path::new(&format!("/proc/{pid}")).exists()
    }

    fn plain_workspace() -> Arc<dyn HarnessWorkspace> {
        Arc::new(TempWorkspace {
            prepared: AtomicUsize::new(0),
        })
    }

    fn next_message() -> LiveMessage {
        LiveMessage::new(vec![LiveContentBlock::Text("next".to_owned())]).expect("message")
    }

    fn stop_unproven(result: Result<(), LiveError>) -> bool {
        matches!(result, Err(LiveError::Unavailable { code }) if code == "harness_stop_unproven")
    }

    /// A hand-back held shut, and the channel that tells when one began.
    fn gated() -> (Arc<GatedHandBack>, tokio::sync::mpsc::UnboundedReceiver<()>) {
        let (entered, handing) = tokio::sync::mpsc::unbounded_channel();
        let release = tokio::sync::Semaphore::new(0);
        (Arc::new(GatedHandBack { entered, release }), handing)
    }

    /// A stop reports success only once the turn's owned agent is reaped and
    /// its driver has ended the turn; it used to signal the driver and
    /// return while the agent still ran.
    #[tokio::test]
    async fn a_process_stop_succeeds_only_after_the_turns_owned_teardown() {
        let (control, mut observations) = local_control(plain_workspace(), TEARDOWN);
        let pid = drive_local_turn(&control, WAITS, None);
        next_frame(&mut observations, "message_end").await;
        control.pause().await.expect("the turn stops");
        assert!(
            reaped(pid),
            "the agent was reaped before the stop succeeded"
        );
        let ended: Vec<Value> = std::iter::from_fn(|| observations.try_recv().ok())
            .filter_map(|frame| frame.decoded.map(|frame| frame.value().clone()))
            .collect();
        let kinds: Vec<&Value> = ended.iter().map(|frame| &frame["type"]).collect();
        assert!(
            kinds.ends_with(&[&json!("agent_end"), &json!("prompt_result")]),
            "the turn's terminal frames precede the stop's success: {ended:?}"
        );
        assert!(ended
            .iter()
            .all(|frame| frame["turnId"] == "fixture-process-turn-1"));
        assert!(control.state.lock().expect("state").running.is_none());
    }

    /// A generic process turn that fails is not an OMP provider failure:
    /// through the real driver and session actor its exact failure is typed,
    /// the session settles Failed, and the turn's own report — the failure
    /// and where its work was handed back — still journals, once.
    #[tokio::test]
    async fn a_failed_process_turn_keeps_its_failure_and_its_hand_back_report() {
        use crate::live::ledger::LiveLedger as _;
        use crate::live::session_actor::tests::spawn_fixture_with_control;
        use odin_domain::huginn::{EventSeq, HistoryQuery, LiveEventBody, LiveSessionState};

        struct NotedHandBack;

        #[async_trait]
        impl HarnessWorkspace for NotedHandBack {
            async fn prepare(
                &self,
                _manifest: &SessionManifest,
                _route: &HarnessRoute,
            ) -> Result<PathBuf, LiveError> {
                Ok(std::env::temp_dir())
            }

            async fn hand_back(
                &self,
                _manifest: &SessionManifest,
                _route: &HarnessRoute,
                _workspace: &Path,
            ) -> Result<Option<String>, LiveError> {
                Ok(Some("The work is on branch odin/fixture.".to_owned()))
            }
        }

        let (control, mut observations) = local_control(Arc::new(NotedHandBack), TEARDOWN);
        let control = Arc::new(control);
        let backend = Arc::clone(&control);
        let fixture = spawn_fixture_with_control(move |_, _| backend).await;
        drive_local_turn(
            &control,
            r#"printf '%s\n' "$1"; echo 'the fixture agent failed' >&2; exit 3"#,
            None,
        );
        let mut reason = None;
        let report = loop {
            let frame = tokio::time::timeout(Duration::from_secs(10), observations.recv())
                .await
                .expect("the turn ends")
                .expect("frames");
            let value = frame.decoded.as_ref().expect("decoded").value().clone();
            fixture
                .handle
                .ingest_omp(frame.clone())
                .await
                .expect("the frame journals");
            if value["type"] == "agent_end" {
                reason = value["errorMessage"].as_str().map(str::to_owned);
            }
            if value["type"] == "prompt_result" {
                break frame;
            }
        };
        // The same report arriving again is no second result.
        fixture
            .handle
            .ingest_omp(report.clone())
            .await
            .expect("the late frame is ingested");

        let reason = reason.expect("the driver reports its failure");
        let report = report.decoded.expect("decoded").value().clone();
        let text = report["text"].as_str().expect("the report text");
        assert!(text.contains("The work is on branch odin/fixture."));
        assert!(text.contains(&reason), "{text}");
        let bodies: Vec<LiveEventBody> = fixture
            .ledger
            .history(HistoryQuery {
                session_id: fixture.session_id,
                after: EventSeq::new(0),
                limit: std::num::NonZeroU16::new(64).expect("limit"),
            })
            .await
            .expect("history")
            .events
            .into_iter()
            .map(|event| event.body)
            .collect();
        match &bodies[bodies.len().saturating_sub(3)..] {
            [LiveEventBody::Error(error), LiveEventBody::SessionStateChanged(failed), LiveEventBody::Result(result)] =>
            {
                assert_eq!(error.code, "turn_stopped_error");
                assert_eq!(error.message, reason);
                assert_eq!(failed.current, LiveSessionState::Failed);
                assert_eq!(result.summary.as_deref(), Some(text));
            }
            other => panic!("the failure, Failed, then the report: {other:?}"),
        }
        assert_eq!(
            bodies
                .iter()
                .filter(|body| matches!(body, LiveEventBody::Result(_)))
                .count(),
            1
        );
        assert_eq!(
            fixture.handle.summary().expect("summary").state,
            LiveSessionState::Failed
        );
        fixture.handle.stop().await.expect("the actor stops");
        let _ = tokio::fs::remove_dir_all(fixture.root).await;
    }

    /// Canceling stop must not admit another prompt before teardown and hand-back finish.
    #[tokio::test]
    async fn a_canceled_stop_keeps_custody_until_the_teardown_completes() {
        let (gate, mut handing) = gated();
        let (control, mut observations) = local_control(gate.clone(), TEARDOWN);
        let pid = drive_local_turn(&control, WAITS, None);
        next_frame(&mut observations, "message_end").await;
        let _ = futures_util::FutureExt::now_or_never(control.pause());
        tokio::time::timeout(Duration::from_secs(10), handing.recv())
            .await
            .expect("the teardown goes on without its caller");
        assert!(reaped(pid), "the canceled stop still reached the agent");
        let refused = control.prompt(&next_message()).await;
        assert!(
            matches!(&refused, Err(LiveError::Conflict { code, .. }) if code == "harness_turn_running"),
            "no prompt over an unfinished teardown: {refused:?}"
        );
        let (stopped, ()) = tokio::join!(control.pause(), async { gate.release.add_permits(1) });
        stopped.expect("the stop succeeds once the teardown completed");
        assert!(control.state.lock().expect("state").running.is_none());
        let admitted = control.prompt(&next_message()).await;
        assert!(
            matches!(&admitted, Err(LiveError::Unsupported { .. })),
            "admitted to the transport: {admitted:?}"
        );
    }

    /// Late completion must not release a newer turn.
    #[tokio::test]
    async fn turn_custody_is_exact_to_its_turn() {
        let (control, mut observations) = local_control(plain_workspace(), TEARDOWN);
        let first = drive_local_turn(&control, WAITS, None);
        next_frame(&mut observations, "message_end").await;
        let refused = control.reserve();
        assert!(
            matches!(refused, Err(LiveError::Conflict { .. })),
            "one turn at a time"
        );
        // Retain the first record while allowing a second reservation to test late completion.
        let stale = control
            .state
            .lock()
            .expect("state")
            .running
            .take()
            .expect("turn 1");
        let second = control.reserve().expect("turn 2");
        let pid = i32::try_from(first)
            .ok()
            .and_then(rustix::process::Pid::from_raw);
        rustix::process::kill_process(pid.expect("pid"), rustix::process::Signal::KILL)
            .expect("the first agent ends");
        let mut done = stale.done.clone();
        tokio::time::timeout(Duration::from_secs(10), done.wait_for(Option::is_some))
            .await
            .expect("turn 1 ends")
            .expect("with a verdict");
        let state = control.state.lock().expect("state");
        assert_eq!(
            state.running.as_ref().map(|running| running.turn),
            Some(second.turn)
        );
        drop(state);
        control.release(second);
    }

    /// Failed unit stop prevents hand-back and further prompts even after the local client exits.
    #[tokio::test]
    async fn an_unconfirmed_unit_stop_keeps_the_turn_in_custody() {
        let refusing = Teardown {
            stop_unit: &["sh", "-c", "exit 1", "manager"],
            ..TEARDOWN
        };
        let (gate, mut handing) = gated();
        let (control, mut observations) = local_control(gate, refusing);
        let pid = drive_local_turn(&control, WAITS, Some("odin-harness-fixture-1"));
        next_frame(&mut observations, "message_end").await;
        assert!(stop_unproven(control.pause().await));
        assert!(reaped(pid), "its own client is reaped all the same");
        assert!(
            handing.try_recv().is_err(),
            "nothing is published past an unproven stop"
        );
        assert!(matches!(
            control.prompt(&next_message()).await,
            Err(LiveError::Conflict { .. })
        ));
        assert!(stop_unproven(control.shutdown().await));
        assert!(control.state.lock().expect("state").running.is_some());
    }

    /// Output EOF alone cannot release the turn; the driver must still reap the agent.
    #[tokio::test]
    async fn an_unreaped_agent_stays_owned_and_unpublished() {
        let impatient = Teardown {
            reap_within: Duration::from_millis(100),
            ..TEARDOWN
        };
        let (gate, mut handing) = gated();
        let (control, mut observations) = local_control(gate, impatient);
        let pid = drive_local_turn(
            &control,
            r#"printf '%s\n' "$1"; exec >&-; exec sleep 30"#,
            None,
        );
        next_frame(&mut observations, "prompt_result").await;
        assert!(!reaped(pid), "the agent still runs");
        assert!(
            handing.try_recv().is_err(),
            "no hand-back while the agent may write"
        );
        assert!(matches!(
            control.prompt(&next_message()).await,
            Err(LiveError::Conflict { .. })
        ));
        assert!(stop_unproven(control.pause().await));
        let mut polls = 0;
        while !reaped(pid) && polls < 500 {
            tokio::time::sleep(Duration::from_millis(10)).await;
            polls += 1;
        }
        assert!(
            reaped(pid),
            "its owning driver killed and reaped it on the stop"
        );
        assert!(
            handing.try_recv().is_err(),
            "nor after: its end was not proven in time"
        );
        assert!(control.state.lock().expect("state").running.is_some());
    }

    fn stop_pending(result: Result<(), LiveError>) -> bool {
        matches!(result, Err(LiveError::Unavailable { code }) if code == "harness_stop_pending")
    }

    /// Whether `pid` still runs: neither gone nor a zombie awaiting its reap.
    fn running(pid: u32) -> bool {
        std::fs::read_to_string(format!("/proc/{pid}/stat"))
            .ok()
            .and_then(|stat| {
                stat.rsplit_once(") ")
                    .map(|(_, rest)| !rest.starts_with('Z'))
            })
            .unwrap_or(false)
    }

    /// Polls `done` for up to five seconds.
    async fn eventually(done: impl Fn() -> bool) -> bool {
        for _ in 0..500 {
            if done() {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        done()
    }

    /// Stop returns by its deadline while uninterruptible hand-back continues in the driver.
    #[tokio::test]
    async fn a_stop_is_answered_by_its_deadline_while_the_hand_back_runs() {
        let brief = Teardown {
            reap_within: Duration::from_secs(1),
            ..TEARDOWN
        };
        let (gate, mut handing) = gated();
        let (control, mut observations) = local_control(gate.clone(), brief);
        let pid = drive_local_turn(&control, WAITS, None);
        next_frame(&mut observations, "message_end").await;
        let answered = tokio::time::timeout(Duration::from_secs(10), control.pause())
            .await
            .expect("answered by the stop's deadline");
        assert!(stop_pending(answered));
        assert!(reaped(pid));
        assert!(handing.try_recv().is_ok(), "the hand-back had begun");
        assert!(matches!(control.reserve(), Err(LiveError::Conflict { .. })));
        gate.release.add_permits(1);
        let proven = tokio::time::timeout(Duration::from_secs(10), control.pause()).await;
        proven
            .expect("bounded")
            .expect("proven once the hand-back ended");
        assert!(control.state.lock().expect("state").running.is_none());
    }

    /// Stop timeout kills the hung manager but retains the turn while the agent is reaped.
    #[tokio::test]
    async fn a_hung_unit_manager_is_bounded_and_not_left_running() {
        let scratch = tempfile::tempdir().expect("scratch");
        let pidfile = scratch.path().join("manager.pid");
        let pidfile: &'static str = Box::leak(pidfile.display().to_string().into_boxed_str());
        let hung = Teardown {
            stop_unit: Box::leak(Box::new([
                "sh",
                "-c",
                r#"echo $$ > "$0"; exec sleep 30"#,
                pidfile,
            ])),
            reap_within: Duration::from_millis(500),
        };
        let (gate, mut handing) = gated();
        let (control, mut observations) = local_control(gate, hung);
        let pid = drive_local_turn(&control, WAITS, Some("odin-harness-fixture-1"));
        next_frame(&mut observations, "message_end").await;
        let answered = tokio::time::timeout(Duration::from_secs(10), control.pause())
            .await
            .expect("answered by the stop's deadline");
        let code = match answered {
            Err(LiveError::Unavailable { code }) => code,
            other => panic!("an uncertain stop, not {other:?}"),
        };
        assert!(["harness_stop_unproven", "harness_stop_pending"].contains(&code.as_str()));
        let manager: u32 = std::fs::read_to_string(pidfile)
            .expect("the manager ran")
            .trim()
            .parse()
            .expect("its pid");
        assert!(
            eventually(|| !running(manager)).await,
            "the manager was killed"
        );
        assert!(
            eventually(|| reaped(pid)).await,
            "the agent's driver reaped it"
        );
        assert!(handing.try_recv().is_err());
        assert!(matches!(control.reserve(), Err(LiveError::Conflict { .. })));
    }

    /// Interactive SSH stop releases the turn; natural SSH failure also preserves its error.
    #[tokio::test]
    async fn a_stopped_ssh_turn_releases_custody_and_keeps_a_natural_failure() {
        let (gate, mut handing) = gated();
        let (mut control, mut observations) = local_control(gate, TEARDOWN);
        control.route.environment.transport = EnvironmentTransport::SshHost;
        let pid = drive_local_turn(&control, WAITS, None);
        next_frame(&mut observations, "message_end").await;
        control
            .pause()
            .await
            .expect("an explicit ssh stop settles stopped");
        assert!(reaped(pid), "the local client is reaped");
        assert!(
            handing.try_recv().is_err(),
            "unproven remote work is not handed back"
        );
        assert!(control.state.lock().expect("state").running.is_none());
        let reserved = control
            .reserve()
            .expect("the session accepts another prompt");
        control.release(reserved);

        let (mut control, mut observations) = local_control(plain_workspace(), TEARDOWN);
        control.route.environment.transport = EnvironmentTransport::SshHost;
        let pid = drive_local_turn(&control, r#"printf '%s\n' "$1"; exit 255"#, None);
        let ended = next_frame(&mut observations, "agent_end").await;
        assert_eq!(
            ended["stopReason"], "error",
            "a natural ssh failure stays a failure"
        );
        assert!(reaped(pid));
        assert!(
            eventually(|| control.state.lock().expect("state").running.is_none()).await,
            "custody released after the failure"
        );
        control
            .reserve()
            .expect("the session accepts another prompt after the failure");
        let later: Vec<Value> = std::iter::from_fn(|| observations.try_recv().ok())
            .filter_map(|frame| frame.decoded.map(|frame| frame.value().clone()))
            .collect();
        assert!(
            later.iter().all(|frame| frame["stopReason"] != "stop"),
            "the failure is not rewritten as a successful stop: {later:?}"
        );
    }

    fn stopping(result: Result<impl Sized, LiveError>) -> bool {
        matches!(result, Err(LiveError::Unavailable { code }) if code == "harness_stopping")
    }

    /// The daemon's stop of the launcher's turns stops a running turn
    /// through its owned teardown and counts it drained only once that is
    /// proven and its driver ended; from the stop on no turn is admitted.
    #[tokio::test]
    async fn a_daemon_stop_drains_a_proven_turn_and_admits_no_other() {
        let (control, mut observations) = local_control(plain_workspace(), TEARDOWN);
        let pid = drive_local_turn(&control, WAITS, None);
        next_frame(&mut observations, "message_end").await;
        control.turns.stop();
        let joined = tokio::time::timeout(
            Duration::from_secs(20),
            control
                .turns
                .join(tokio::time::Instant::now() + Duration::from_secs(10)),
        )
        .await
        .expect("the join is bounded by its deadline");
        assert_eq!(joined, (1, 0), "the proven turn drained");
        assert!(reaped(pid), "the stop reached and reaped the agent");
        assert!(control.state.lock().expect("state").running.is_none());
        assert!(stopping(control.reserve()), "no turn after the stop");
        assert!(stopping(control.prompt(&next_message()).await));
    }

    /// Unconfirmed unit or remote stops remain stragglers across repeated session close.
    #[tokio::test]
    async fn a_daemon_stop_keeps_an_unproven_unit_and_an_unproven_ssh_stop() {
        let refusing = Teardown {
            stop_unit: &["sh", "-c", "exit 1", "manager"],
            ..TEARDOWN
        };
        let (gate, mut handing) = gated();
        let (control, mut observations) = local_control(gate, refusing);
        let pid = drive_local_turn(&control, WAITS, Some("odin-harness-fixture-1"));
        next_frame(&mut observations, "message_end").await;
        control.turns.stop();
        let joined = control
            .turns
            .join(tokio::time::Instant::now() + Duration::from_secs(10))
            .await;
        assert_eq!(joined, (0, 1), "an unproven unit stop is a straggler");
        assert!(reaped(pid));
        assert!(handing.try_recv().is_err());
        assert!(control.state.lock().expect("state").running.is_some());
        assert!(stop_unproven(control.shutdown().await));

        let (gate, mut handing) = gated();
        let (mut control, mut observations) = local_control(gate, TEARDOWN);
        control.route.environment.transport = EnvironmentTransport::SshHost;
        let pid = drive_local_turn(&control, WAITS, None);
        next_frame(&mut observations, "message_end").await;
        control.turns.stop();
        let joined = control
            .turns
            .join(tokio::time::Instant::now() + Duration::from_secs(10))
            .await;
        assert_eq!(joined, (0, 1), "an explicit ssh stop is not a proven drain");
        assert!(reaped(pid));
        assert!(
            handing.try_recv().is_err(),
            "remote work is not handed back"
        );
        assert!(control.state.lock().expect("state").running.is_some());
        assert!(stop_unproven(control.shutdown().await));
        assert!(
            control.state.lock().expect("state").running.is_some(),
            "a close does not retire an unproven ssh turn"
        );
        assert!(stop_unproven(control.shutdown().await));
        assert!(
            control.state.lock().expect("state").running.is_some(),
            "a repeated close still has the unproven turn to report"
        );
        assert!(stopping(control.reserve()));
    }

    /// Repeated stop must not restart teardown that is still running after its deadline.
    #[tokio::test]
    async fn a_teardown_running_at_the_deadline_is_a_straggler() {
        let (gate, mut handing) = gated();
        let (control, mut observations) = local_control(gate.clone(), TEARDOWN);
        let pid = drive_local_turn(&control, WAITS, None);
        next_frame(&mut observations, "message_end").await;
        control.turns.stop();
        tokio::time::timeout(Duration::from_secs(10), handing.recv())
            .await
            .expect("the stopped turn reaches its hand-back");
        control.turns.stop();
        let joined = control
            .turns
            .join(tokio::time::Instant::now() + Duration::from_millis(300))
            .await;
        assert_eq!(joined, (0, 1), "a teardown in progress is counted");
        assert!(reaped(pid));
        assert!(control.state.lock().expect("state").running.is_some());
        gate.release.add_permits(1);
        assert!(
            eventually(|| control.state.lock().expect("state").running.is_none()).await,
            "the teardown completed once released"
        );
        assert!(handing.try_recv().is_err(), "one hand-back, never a second");
    }

    /// A workspace whose `prepare` is held shut: an open on its way.
    struct GatedPrepare {
        entered: tokio::sync::mpsc::UnboundedSender<()>,
        release: tokio::sync::Semaphore,
    }

    #[async_trait]
    impl HarnessWorkspace for GatedPrepare {
        async fn prepare(
            &self,
            _manifest: &SessionManifest,
            _route: &HarnessRoute,
        ) -> Result<PathBuf, LiveError> {
            let _ = self.entered.send(());
            self.release.acquire().await.expect("gate").forget();
            Ok(std::env::temp_dir())
        }

        async fn hand_back(
            &self,
            _manifest: &SessionManifest,
            _route: &HarnessRoute,
            _workspace: &Path,
        ) -> Result<Option<String>, LiveError> {
            Ok(None)
        }
    }

    /// An open already on its way when the daemon stops is owned: the stop
    /// refuses any new open before its first effect, a join at the deadline
    /// counts the open in progress as a straggler, and once it ends a join
    /// finds nothing left.
    #[tokio::test]
    async fn an_open_on_its_way_at_the_stop_is_owned_and_counted() {
        let (entered, mut opening) = tokio::sync::mpsc::unbounded_channel();
        let workspace = Arc::new(GatedPrepare {
            entered,
            release: tokio::sync::Semaphore::new(0),
        });
        let inner = Arc::new(RunRecorder {
            runs: AtomicUsize::new(0),
            refuse: false,
        });
        let home = signed_in_home();
        let mut launcher = HarnessLauncher::new(
            inner.clone(),
            vec![process_on_the_authority()],
            workspace.clone(),
            None,
        );
        launcher.home = home.path().to_path_buf();
        let launcher = Arc::new(launcher);
        let turns = launcher
            .harness_turns()
            .expect("the launcher owns its turns");
        let first = reginn_manifest();
        let opening_launcher = Arc::clone(&launcher);
        let open = tokio::spawn(async move {
            opening_launcher
                .open(&first, SessionEpoch::new(1), false)
                .await
                .map(|_| ())
        });
        tokio::time::timeout(Duration::from_secs(10), opening.recv())
            .await
            .expect("the open reached its workspace");
        turns.stop();
        let refused = launcher
            .open(&reginn_manifest(), SessionEpoch::new(1), false)
            .await;
        assert!(stopping(refused.map(|_| ())), "no open after the stop");
        assert_eq!(
            inner.runs.load(Ordering::SeqCst),
            1,
            "the refused open ran nothing"
        );
        let joined = turns
            .join(tokio::time::Instant::now() + Duration::from_millis(300))
            .await;
        assert_eq!(joined, (0, 1), "the open on its way is counted");
        // Release: the owned open ends, and nothing remains to join.
        workspace.release.add_permits(1);
        tokio::time::timeout(Duration::from_secs(10), open)
            .await
            .expect("the released open ends")
            .expect("joined")
            .expect("the open completed");
        let joined = turns
            .join(tokio::time::Instant::now() + Duration::from_secs(5))
            .await;
        assert_eq!(joined, (0, 0));
    }
}
