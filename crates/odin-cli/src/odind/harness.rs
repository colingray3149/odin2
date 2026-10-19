//! The daemon half of non-OMP harnesses: the routes
//! every declared harness launch option resolves to (harness + environment
//! from the published registry), the session workspace (a fresh clone of
//! the project on `seat/<seat>/<session>`, on the environment's machine)
//! and its hand-back (each turn's changes committed and the branch pushed
//! into the project's own repository — the session's seat branch, or the
//! exact seat branch the agent moved the workspace to), and the session's
//! Zellij tab.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use odin_domain::huginn::{LiveError, SessionManifest};
use odin_omp::live::harness::{HarnessRoute, HarnessTerminals, ProjectAccounts};
use odin_omp::live::runtime::ProductionBridgeRuntimeFactory;
use odin_omp::live::zellij::ZellijLiveAdapter;
use odin_registry::{EnvironmentTransport, ObjectConfig, RegistryObject};

#[path = "harness/workspace.rs"]
pub(crate) mod workspace;

/// Every harness route the seats' declared launch options name, resolved
/// against the published registry. A launch option naming an undeclared or
/// disabled harness or environment fails composition: the seat would
/// otherwise be offered a launch that can never open.
pub(crate) fn harness_routes(
    seats: &[odin_huginn::config::OdindSeatBinding],
    objects: &[RegistryObject],
) -> Result<Vec<HarnessRoute>, String> {
    let wanted: BTreeSet<(String, String)> = seats
        .iter()
        .flat_map(|seat| seat.launch_options.iter())
        .filter_map(|option| option.harness.as_ref())
        .map(|binding| (binding.harness.clone(), binding.environment.clone()))
        .collect();
    let mut harnesses = BTreeMap::new();
    let mut environments = BTreeMap::new();
    for object in objects {
        match &object.config {
            ObjectConfig::Harness(harness) if harness.enabled => {
                harnesses.insert(object.id.clone(), harness.as_ref().clone());
            }
            ObjectConfig::Environment(environment) if environment.enabled => {
                environments.insert(object.id.clone(), environment.as_ref().clone());
            }
            _ => {}
        }
    }
    wanted
        .into_iter()
        .map(|(harness_id, environment_id)| {
            let harness = harnesses.get(&harness_id).cloned().ok_or_else(|| {
                format!("launch harness {harness_id} is not an enabled registry harness")
            })?;
            let environment = environments.get(&environment_id).cloned().ok_or_else(|| {
                format!(
                    "launch environment {environment_id} is not an enabled registry environment"
                )
            })?;
            Ok(HarnessRoute {
                harness_id,
                harness,
                environment_id,
                environment,
                account: None,
            })
        })
        .collect()
}

/// The account each enabled registry project's agents sign in with, by kind.
pub(crate) fn project_accounts(objects: &[RegistryObject]) -> ProjectAccounts {
    objects
        .iter()
        .filter_map(|object| match &object.config {
            ObjectConfig::Project(project) if project.enabled && !project.accounts.is_empty() => {
                Some((object.id.clone(), project.accounts.clone()))
            }
            _ => None,
        })
        .collect()
}

pub(crate) struct FactoryHarnessTerminals(pub(crate) Arc<ProductionBridgeRuntimeFactory>);

#[async_trait]
impl HarnessTerminals for FactoryHarnessTerminals {
    async fn open(
        &self,
        manifest: &SessionManifest,
        cwd: &Path,
    ) -> Result<Option<Arc<ZellijLiveAdapter>>, LiveError> {
        // A remote workspace path does not exist here: the tab opens in the
        // project root instead (it shows the session journal either way).
        let local = if cwd.is_absolute() && cwd.is_dir() {
            cwd.to_path_buf()
        } else {
            std::env::var_os("HOME")
                .map(PathBuf::from)
                .unwrap_or_default()
        };
        self.0.open_session_terminal(manifest, &local).await
    }

    async fn open_attached(
        &self,
        manifest: &SessionManifest,
        cwd: &Path,
        attach: Vec<String>,
    ) -> Result<Option<Arc<ZellijLiveAdapter>>, LiveError> {
        self.0
            .open_session_terminal_attached(manifest, cwd, Some(attach))
            .await
    }
}

/// Watchdog hits on observed sessions raise incidents through the desk.
pub(crate) struct DeskIncidentSink(pub(crate) Arc<crate::incidents::IncidentDesk>);

impl odin_omp::live::harness::HarnessIncidentSink for DeskIncidentSink {
    fn raise(&self, environment: &str, watchdog: &str, summary: &str, detail: &str) {
        let receipt = self.0.raise(crate::incidents::RaisedIncident {
            source: format!("observe:{environment}/{watchdog}"),
            severity: odin_huginn::incidents::IncidentSeverityView::Warning,
            summary: summary.to_owned(),
            detail: detail.chars().take(1_000).collect(),
            affected: vec![format!("environment:{environment}")],
            signature: format!("observe:{environment}:{watchdog}"),
        });
        tracing::info!(
            "observe incident environment={environment} watchdog={watchdog} \
             incident={} published={} phone={} woken={} summary={summary:?}",
            receipt.incident_id,
            receipt.published,
            receipt.phone_alerted,
            receipt.conversation_woken
        );
    }
}

/// Reload never waits for observe-only sessions: Odin cannot stop the agents they mirror.
pub(crate) fn observer_titles(routes: &[HarnessRoute]) -> std::collections::BTreeSet<String> {
    routes
        .iter()
        .filter(|route| route.environment.transport == EnvironmentTransport::RemoteSession)
        .map(|route| observer_title(&route.environment_id))
        .collect()
}

fn observer_title(environment: &impl std::fmt::Display) -> String {
    format!("watch-{environment}")
}

/// Stop admission before awaiting shutdown, then join the opener, blocking mints,
/// and followers under one deadline. Blocking mints remain tracked after caller cancellation.
pub(crate) struct ObservedSessions {
    supervisor: Arc<odin_omp::live::supervisor::LiveSupervisor>,
    config: odin_huginn::config::OdindConfig,
    routes: Vec<HarnessRoute>,
    /// The launcher's follower tracker; `None` when this daemon's launcher
    /// opens no observe-only sessions. Every follower `open_observed`
    /// spawns registers there from birth.
    followers: Option<Arc<odin_omp::live::harness::ObserverFollowers>>,
    /// Retained until each blocking mint exits.
    mints: Mutex<Vec<tokio::task::JoinHandle<()>>>,
    /// Set once shutdown stopped admission: no further route is minted or
    /// opened.
    stopping: AtomicBool,
    /// Retained so shutdown can join the opener.
    opener: Mutex<Option<tokio::task::JoinHandle<()>>>,
}

impl ObservedSessions {
    /// Owns one daemon's observer admission. The follower tracker comes
    /// from the same launcher the supervisor launches through, so the
    /// opener's opens and any later reopen of an observer session register
    /// their followers in the very tracker this handle joins.
    pub(crate) fn own(
        supervisor: Arc<odin_omp::live::supervisor::LiveSupervisor>,
        config: odin_huginn::config::OdindConfig,
        routes: Vec<HarnessRoute>,
    ) -> Arc<Self> {
        Arc::new(Self {
            followers: supervisor.observer_followers(),
            supervisor,
            config,
            routes,
            mints: Mutex::new(Vec::new()),
            stopping: AtomicBool::new(false),
            opener: Mutex::new(None),
        })
    }

    /// Spawns the opener. A second call refuses: one opener owns the
    /// admission.
    pub(crate) fn spawn(self: &Arc<Self>) {
        let mut opener = self.opener.lock().expect("observer opener");
        if opener.is_some() {
            tracing::warn!("observe opener already running");
            return;
        }
        let sessions = Arc::clone(self);
        *opener = Some(tokio::spawn(async move {
            open_observed_sessions(&sessions).await;
        }));
    }

    /// Stops: no new observer admission starts, and every live follower is
    /// signaled. Sync and idempotent: the shutdown calls it before its
    /// first await.
    pub(crate) fn stop(&self) {
        if self.stopping.swap(true, Ordering::SeqCst) {
            return;
        }
        if let Some(followers) = &self.followers {
            followers.stop();
        }
        tracing::info!("observe admission stopped");
    }

    fn stopping(&self) -> bool {
        self.stopping.load(Ordering::SeqCst)
    }

    /// Track the blocking mint until it exits, even if the requesting opener is cancelled.
    fn provision(
        &self,
        request: odin_domain::huginn::OpenSessionRequest,
    ) -> tokio::sync::oneshot::Receiver<Result<(), String>> {
        let config = self.config.clone();
        let (reply, receive) = tokio::sync::oneshot::channel();
        let mint = tokio::task::spawn_blocking(move || {
            let _ = reply.send(provision_observer(&config, &request));
        });
        let mut mints = self.mints.lock().expect("observer mints");
        mints.retain(|mint| !mint.is_finished());
        mints.push(mint);
        receive
    }

    /// Join under one shutdown deadline, returning `(drained, stragglers)`.
    /// Blocking mints cannot be aborted and remain tracked after missing the deadline.
    pub(crate) async fn join(&self, deadline: tokio::time::Instant) -> (usize, usize) {
        let mut drained = 0;
        let mut stragglers = 0;
        let opener = self.opener.lock().expect("observer opener").take();
        if let Some(mut opener) = opener {
            match tokio::time::timeout_at(deadline, &mut opener).await {
                Ok(Ok(())) => drained += 1,
                Ok(Err(error)) => {
                    drained += 1;
                    tracing::error!("observe opener ended abnormally: {error}");
                }
                Err(_elapsed) => {
                    opener.abort();
                    stragglers += 1;
                    tracing::error!(
                        "observe opener outlived the shutdown deadline; aborted and \
                         counted"
                    );
                }
            }
        }
        // The opener has exited, so no mint can register from here on.
        let mints = self
            .mints
            .lock()
            .expect("observer mints")
            .drain(..)
            .collect::<Vec<_>>();
        for mut mint in mints {
            match tokio::time::timeout_at(deadline, &mut mint).await {
                Ok(Ok(())) => drained += 1,
                Ok(Err(error)) => {
                    drained += 1;
                    tracing::error!("observe mint closure ended abnormally: {error}");
                }
                Err(_elapsed) => {
                    stragglers += 1;
                    tracing::error!("observe mint closure outlived the shutdown deadline; counted");
                }
            }
        }
        if let Some(followers) = &self.followers {
            let (followed, missed) = followers.join(deadline).await;
            drained += followed;
            stragglers += missed;
        }
        (drained, stragglers)
    }
}

/// Opens one observe-only session per remote-session route at start for
/// the seat that declares the route watches it. Once
/// [`ObservedSessions::stop`] ran, no further route is minted or opened.
pub(crate) async fn open_observed_sessions(sessions: &ObservedSessions) {
    for route in sessions
        .routes
        .iter()
        .filter(|route| route.environment.transport == EnvironmentTransport::RemoteSession)
    {
        if sessions.stopping() {
            tracing::info!(
                "observe admission stopped environment={}",
                route.environment_id
            );
            return;
        }
        let supervisor = &sessions.supervisor;
        let config = &sessions.config;
        let Some((seat, option)) = config.seats.iter().find_map(|seat| {
            seat.launch_options
                .iter()
                .find(|option| {
                    option
                        .harness
                        .as_ref()
                        .is_some_and(|binding| binding.environment == route.environment_id)
                })
                .map(|option| (seat, option))
        }) else {
            continue;
        };
        let Some(project) = config
            .lane_bindings
            .iter()
            .find(|binding| binding.seat == seat.seat)
            .map(|binding| binding.project.clone())
        else {
            tracing::warn!(
                "observe environment={} seat={} has no project lane; not watched",
                route.environment_id,
                seat.seat
            );
            continue;
        };
        let request = odin_domain::huginn::OpenSessionRequest {
            command_id: match odin_domain::CommandId::new(format!(
                "observe-{}-{}",
                route.environment_id,
                uuid::Uuid::new_v4().simple()
            )) {
                Ok(id) => id,
                Err(error) => {
                    tracing::error!("observe command id: {error}");
                    continue;
                }
            },
            seat_id: seat.seat.clone(),
            project_id: project,
            slice_id: seat.slice.clone(),
            provider: option.provider.clone(),
            model: option.model.clone(),
            title: Some(observer_title(&route.environment_id)),
            target_node: match odin_domain::NodeId::new(&config.identity.node) {
                Ok(node) => node,
                Err(error) => {
                    tracing::error!("observe node id: {error}");
                    continue;
                }
            },
            open_tab: true,
            initial_prompt: None,
            workload: None,
            served_revision: None,
        };
        let minted = sessions.provision(request.clone());
        match minted.await {
            Ok(Ok(())) => {}
            Ok(Err(error)) => {
                tracing::error!(
                    "observe session refused environment={} error={error}",
                    route.environment_id
                );
                continue;
            }
            Err(receive) => {
                tracing::error!(
                    "observe provisioning failed environment={} error={receive:?}",
                    route.environment_id
                );
                continue;
            }
        }
        match supervisor
            .settle_superseded_observers(
                &seat.seat,
                &route.environment_id,
                time::OffsetDateTime::now_utc(),
            )
            .await
        {
            Ok(ended) if ended.is_empty() => {}
            Ok(ended) => tracing::info!(
                "observe superseded environment={} sessions={ended:?}",
                route.environment_id
            ),
            Err(error) => tracing::error!(
                "observe supersede failed environment={} error={error:?}",
                route.environment_id
            ),
        }
        match supervisor.open(request).await {
            Ok(summary) => tracing::info!(
                "observe session opened environment={} session={}",
                route.environment_id,
                summary.session_id
            ),
            Err(error) => tracing::error!(
                "observe session refused environment={} error={error:?}",
                route.environment_id
            ),
        }
    }
}

/// Mint the observer's seat token before opening so the bridge can record its run.
pub(crate) fn provision_observer(
    config: &odin_huginn::config::OdindConfig,
    request: &odin_domain::huginn::OpenSessionRequest,
) -> Result<(), String> {
    let composition = odin_cli::authority_provision::compose(
        config,
        request.seat_id.as_str(),
        request.project_id.as_str(),
        &request.command_id,
        odin_cli::authority_provision::LaunchSelection::new(
            request.provider.as_str(),
            request.model.as_str(),
        ),
    )?;
    odin_cli::authority_provision::ensure_session_token(
        config,
        &composition,
        odin_cli::authority_provision::DEFAULT_TOKEN_TTL_SECONDS,
        odin_cli::authority_provision::TokenRenewalPolicy::OperatorOnly,
    )
    .map_err(|error| {
        format!(
            "observer {} has no usable authority: {error}",
            composition.live_session
        )
    })?;
    Ok(())
}

/// Terminal pods attach through `kubectl exec`. Credentials use hostPath mounts
/// because Claude refreshes tokens and writes transcripts that odind follows on the host.
pub(crate) struct KubePodTerminals {
    pub(crate) cell: Arc<crate::kube::KubeRuntimeCell>,
    pub(crate) argv: PodTerminalsArgv,
    /// The node odind serves from: the workspace and credentials live here.
    pub(crate) node: String,
    /// The deployed platform workload image.
    pub(crate) image: String,
}

const POD_TMUX: &str = "/odin/bin/tmux";
const POD_SESSION: &str = "main";

/// The `kubectl exec` argv of a terminal pod.
pub(crate) struct PodTerminalsArgv {
    /// `kubectl` (or `k3s kubectl`) with the kubeconfig and namespace.
    pub(crate) kubectl: Vec<String>,
}

impl PodTerminalsArgv {
    /// `kubectl` from PATH, or k3s's own, against the cell's cluster.
    pub(crate) fn for_cluster(config: &odin_kube::config::KubeConfig) -> Self {
        let found = |name: &str| {
            std::env::var_os("PATH").and_then(|path| {
                std::env::split_paths(&path)
                    .map(|dir| dir.join(name))
                    .find(|candidate| candidate.is_file())
            })
        };
        let mut argv = match (found("kubectl"), found("k3s")) {
            (Some(kubectl), _) => vec![kubectl.display().to_string()],
            (None, Some(k3s)) => vec![k3s.display().to_string(), "kubectl".to_owned()],
            (None, None) => vec!["kubectl".to_owned()],
        };
        argv.extend([
            "--kubeconfig".to_owned(),
            config.kubeconfig.display().to_string(),
            "-n".to_owned(),
            config.namespace.clone(),
        ]);
        Self { kubectl: argv }
    }

    fn exec_argv(&self, pod: &str, interactive: bool) -> Vec<String> {
        let mut argv = self.kubectl.clone();
        argv.extend([
            "exec".to_owned(),
            if interactive { "-it" } else { "-i" }.to_owned(),
            pod.to_owned(),
            "-c".to_owned(),
            odin_kube::terminal_pod::TERMINAL_CONTAINER.to_owned(),
            "--".to_owned(),
            POD_TMUX.to_owned(),
            "-S".to_owned(),
            odin_kube::terminal_pod::TERMINAL_SOCKET.to_owned(),
        ]);
        argv
    }

    /// How Odin and the session's tab reach one pod's tmux server.
    pub(crate) fn terminal(&self, pod: &str) -> odin_omp::live::harness::PodTerminal {
        let mut attach = self.exec_argv(pod, true);
        attach.extend([
            "attach-session".to_owned(),
            "-t".to_owned(),
            POD_SESSION.to_owned(),
        ]);
        odin_omp::live::harness::PodTerminal {
            pod: pod.to_owned(),
            exec: self.exec_argv(pod, false),
            attach,
        }
    }
}

/// The host and port of the kernel bridge URL a pod is configured with.
fn bridge_target(url: &str) -> Option<odin_kube::workload::WorkloadGatewayTarget> {
    let authority = url.strip_prefix("http://")?.split('/').next()?;
    let (host, port) = authority.rsplit_once(':')?;
    Some(odin_kube::workload::WorkloadGatewayTarget {
        host: host.to_owned(),
        port: port.parse().ok()?,
    })
}

fn run_of(session: &str) -> Result<odin_domain::RunId, LiveError> {
    odin_domain::RunId::new(format!("run:live:{session}")).map_err(|error| LiveError::Unavailable {
        code: format!("terminal_pod_run ({error})"),
    })
}

#[async_trait]
impl odin_omp::live::harness::PodTerminals for KubePodTerminals {
    async fn start(
        &self,
        request: odin_omp::live::harness::PodTerminalRequest,
    ) -> Result<odin_omp::live::harness::PodTerminal, LiveError> {
        use std::os::unix::fs::MetadataExt as _;
        let session = request.manifest.session_id.to_string();
        let unavailable = |stage: &str, error: String| {
            tracing::error!(
                "terminal pod failed session={session} stage={stage} error=\"{error}\""
            );
            LiveError::Unavailable {
                code: format!("terminal_pod_{stage}: {error}"),
            }
        };
        // The pod runs as the owner of the directories it mounts.
        let owner = std::fs::metadata(&request.workspace)
            .map_err(|error| unavailable("workspace", error.to_string()))?;
        let bridge = match request.bridge.as_deref() {
            Some(url) => Some(bridge_target(url).ok_or_else(|| {
                unavailable("bridge", format!("{url} is not http://host:port/…"))
            })?),
            None => None,
        };
        let plan = odin_kube::terminal_pod::TerminalPodPlan {
            run_id: run_of(&session)?,
            session: session.clone(),
            image: self.image.clone(),
            node: self.node.clone(),
            uid: i64::from(owner.uid()),
            gid: i64::from(owner.gid()),
            home: request.home.display().to_string(),
            workspace: request.workspace.display().to_string(),
            runtime: request.runtime.map(|path| path.display().to_string()),
            credentials: request
                .credentials
                .iter()
                .map(|path| path.display().to_string())
                .collect(),
            tmux: POD_TMUX.to_owned(),
            allow_hosts: request.allow_hosts.clone(),
            bridge,
            git_mirror: request.git_mirror.clone().map(|host| {
                odin_kube::workload::WorkloadGatewayTarget {
                    host,
                    port: odin_registry::GIT_MIRROR_PORT,
                }
            }),
        };
        let client = self
            .cell
            .client()
            .await
            .map_err(|error| unavailable("cluster", error.to_string()))?;
        let _lifecycle = self
            .cell
            .terminal_lifecycle()
            .await
            .map_err(|error| unavailable("recovery", error.to_string()))?;
        let stops = self.cell.stop_authority();
        let config = self.cell.kube_config();
        let pod = odin_kube::terminal_pod::ensure_terminal_pod(
            &client,
            &stops,
            &config.cluster,
            &config.namespace,
            &plan,
        )
        .await
        .map_err(|error| unavailable("start", error.to_string()))?;
        tracing::info!(
            "terminal pod up session={session} pod={pod} node={} image={} credentials={} \
             allow_hosts={} bridge={} git_mirror={}",
            self.node,
            self.image,
            plan.credentials.join(","),
            plan.allow_hosts.join(","),
            request.bridge.as_deref().unwrap_or("none"),
            request.git_mirror.as_deref().unwrap_or("none")
        );
        Ok(self.argv.terminal(&pod))
    }

    async fn stop(&self, session: &str) -> Result<(), LiveError> {
        self.cell
            .client()
            .await
            .map_err(|error| LiveError::Unavailable {
                code: format!("terminal_pod_cluster: {error}"),
            })?;
        let _lifecycle = self
            .cell
            .terminal_lifecycle()
            .await
            .map_err(|error| workspace::harness_failure("terminal_pod_recovery", error))?;
        let correlation = odin_kube::terminal_pod::terminal_correlation(session)
            .map_err(|error| workspace::harness_failure("terminal_pod_correlation", error))?;
        let stops = self.cell.stop_authority();
        let (worker, _, _) = stops
            .pod_worker_for_correlation(&correlation)
            .map_err(|error| workspace::harness_failure("terminal_pod_stop", error))?
            .ok_or_else(|| {
                workspace::harness_failure(
                    "terminal_pod_stop",
                    "no registered pod worker for session",
                )
            })?;
        let outcome = stops
            .stop_pod_worker(&worker)
            .map_err(|error| workspace::harness_failure("terminal_pod_stop", error))?;
        if outcome.verdict != odin_domain::StopVerdictTag::Stopped {
            return Err(workspace::harness_failure(
                "terminal_pod_stop",
                format!(
                    "worker {worker} stop failed: {:?}",
                    outcome.evidence.missing
                ),
            ));
        }
        tracing::info!("terminal pod stopped session={session}");
        Ok(())
    }
}

#[cfg(test)]
mod pod_terminal_tests {
    /// The tmux client in the pod and the tab's attach go through kubectl
    /// exec into the one agent container, at the pod's own socket.
    #[test]
    fn the_pod_terminal_is_reached_through_kubectl_exec() {
        let argv = |terminal: &odin_omp::live::harness::PodTerminal| terminal.exec.clone();
        let kubectl = vec![
            "/bin/kubectl".to_owned(),
            "--kubeconfig".to_owned(),
            "/k.yaml".to_owned(),
            "-n".to_owned(),
            "odin".to_owned(),
        ];
        let exec = |pod: &str, interactive: bool| {
            let mut expected = kubectl.clone();
            expected.extend(
                [
                    "exec",
                    if interactive { "-it" } else { "-i" },
                    pod,
                    "-c",
                    "agent",
                    "--",
                    "/odin/bin/tmux",
                    "-S",
                    "/run/odin-term/tmux.sock",
                ]
                .map(str::to_owned),
            );
            expected
        };
        let terminal = super::PodTerminalsArgv {
            kubectl: kubectl.clone(),
        }
        .terminal("odin-term-1");
        assert_eq!(argv(&terminal), exec("odin-term-1", false));
        let mut attach = exec("odin-term-1", true);
        attach.extend(["attach-session", "-t", "main"].map(str::to_owned));
        assert_eq!(terminal.attach, attach);
        assert_eq!(
            super::bridge_target("http://100.64.0.11:18430/mcp/s"),
            Some(odin_kube::workload::WorkloadGatewayTarget {
                host: "100.64.0.11".to_owned(),
                port: 18430
            })
        );
        assert_eq!(super::bridge_target("https://x/mcp"), None);
    }
}

#[cfg(test)]
mod observer_tests {
    use std::sync::atomic::Ordering;
    use std::sync::Arc;

    use odin_domain::huginn::{HarnessBinding, LiveError};
    use odin_omp::live::harness::HarnessRoute;

    #[tokio::test]
    async fn an_observer_is_opened_with_its_seat_token() {
        let mut fixture = crate::live::hermes_routes::tests::gate_fixture().await;
        fixture.config.seats[0].launch_options[0].provider =
            odin_domain::huginn::ProviderName::new("observed").expect("provider");
        fixture.config.seats[0].launch_options[0].model =
            odin_domain::huginn::ModelName::new("transcript").expect("model");
        fixture.config.seats[0].launch_options[0].harness = Some(HarnessBinding {
            harness: "observe".to_owned(),
            environment: "pc-claude-session".to_owned(),
            account: None,
        });
        let route = HarnessRoute {
            harness_id: "observe".to_owned(),
            harness: toml::from_str(include_str!(
                "../../../../registry/harnesses/observe/harness.toml"
            ))
            .expect("declared observe harness parses"),
            environment_id: "pc-claude-session".to_owned(),
            environment: toml::from_str(include_str!(
                "../../../../registry/environments/pc-claude-session/environment.toml"
            ))
            .expect("declared pc-claude-session environment parses"),
            account: None,
        };
        let tokens = |root: &std::path::Path| {
            std::fs::read_dir(root).map_or(0, |entries| {
                entries
                    .filter_map(Result::ok)
                    .filter(|entry| entry.path().extension().is_some_and(|ext| ext == "json"))
                    .count()
            })
        };
        let root = fixture.config.paths.authority_token_root.clone();
        let sessions = super::ObservedSessions::own(
            Arc::clone(&fixture.supervisor),
            fixture.config.clone(),
            vec![route],
        );
        super::open_observed_sessions(&sessions).await;
        assert_eq!(tokens(&root), 1, "the observer's seat token was minted");
    }

    /// An opener parked inside an open when the shutdown stops must be
    /// joined, must not mint or open the NEXT route, and a bounded join
    /// must report the still-running work as a straggler — never claim it
    /// drained.
    struct ParkedObserverLauncher {
        entered: Arc<std::sync::atomic::AtomicUsize>,
        release: Arc<tokio::sync::Notify>,
        park_forever: bool,
    }

    #[async_trait::async_trait]
    impl odin_omp::live::supervisor::LiveSessionLauncher for ParkedObserverLauncher {
        fn harness_turns(&self) -> Option<Arc<odin_omp::live::harness::HarnessTurns>> {
            None
        }

        async fn open(
            &self,
            _manifest: &odin_domain::huginn::SessionManifest,
            _epoch: odin_domain::huginn::SessionEpoch,
            _reclaim: bool,
        ) -> Result<odin_omp::live::supervisor::SessionRuntime, LiveError> {
            self.entered.fetch_add(1, Ordering::SeqCst);
            if self.park_forever {
                tokio::time::sleep(std::time::Duration::from_secs(3600)).await;
                return Err(LiveError::Unavailable {
                    code: "observer_fixture".to_owned(),
                });
            }
            self.release.notified().await;
            Err(LiveError::Unavailable {
                code: "observer_fixture".to_owned(),
            })
        }
    }

    fn observed_routes() -> Vec<HarnessRoute> {
        let environment: odin_registry::EnvironmentToml = toml::from_str(include_str!(
            "../../../../registry/environments/pc-claude-session/environment.toml"
        ))
        .expect("declared pc-claude-session environment parses");
        ["pc-claude-session", "second-watch"]
            .into_iter()
            .map(|environment_id| HarnessRoute {
                harness_id: "observe".to_owned(),
                harness: toml::from_str(include_str!(
                    "../../../../registry/harnesses/observe/harness.toml"
                ))
                .expect("declared observe harness parses"),
                environment_id: environment_id.to_owned(),
                environment: environment.clone(),
                account: None,
            })
            .collect()
    }

    fn two_observer_options(fixture: &mut crate::live::hermes_routes::tests::GateFixture) {
        fixture.config.seats[0].launch_options[0].provider =
            odin_domain::huginn::ProviderName::new("observed").expect("provider");
        fixture.config.seats[0].launch_options[0].model =
            odin_domain::huginn::ModelName::new("transcript").expect("model");
        fixture.config.seats[0].launch_options[0].harness = Some(HarnessBinding {
            harness: "observe".to_owned(),
            environment: "pc-claude-session".to_owned(),
            account: None,
        });
        let mut second = fixture.config.seats[0].launch_options[0].clone();
        second.harness = Some(HarnessBinding {
            harness: "observe".to_owned(),
            environment: "second-watch".to_owned(),
            account: None,
        });
        fixture.config.seats[0].launch_options.push(second);
    }

    /// Admission requires a bound seat: this is the exact declared
    /// coordinator binding the fixture's config derives, so the open
    /// reaches the parked launcher.
    async fn bind_coordinator(fixture: &crate::live::hermes_routes::tests::GateFixture) {
        fixture
            .supervisor
            .bind(odin_omp::live::supervisor::LiveSeatBinding {
                seat_id: odin_domain::SeatId::new("coordinator").expect("seat"),
                slice_id: odin_domain::SliceId::new("coordinator-work").expect("slice"),
                display_name: "Coordinator".to_owned(),
                launch_options: fixture.config.seats[0].launch_options.clone(),
                allowed_nodes: vec![odin_domain::NodeId::new("laptop").expect("node")],
                max_sessions: 8,
                turn_budget: None,
            })
            .await
            .expect("fixture seat binding");
    }

    /// A stop while the first observer's open is parked: the parked open is
    /// joined, the second route is never minted nor opened, and the opener
    /// drains.
    #[tokio::test]
    async fn a_stop_during_a_parked_open_joins_and_refuses_the_next_route() {
        let entered = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let release = Arc::new(tokio::sync::Notify::new());
        let mut fixture = crate::live::hermes_routes::tests::gate_fixture_with(
            256,
            Arc::new(ParkedObserverLauncher {
                entered: Arc::clone(&entered),
                release: Arc::clone(&release),
                park_forever: false,
            }),
            true,
        )
        .await;
        two_observer_options(&mut fixture);
        bind_coordinator(&fixture).await;
        let sessions = super::ObservedSessions::own(
            Arc::clone(&fixture.supervisor),
            fixture.config.clone(),
            observed_routes(),
        );
        sessions.spawn();
        tokio::time::timeout(std::time::Duration::from_secs(10), async {
            while entered.load(Ordering::SeqCst) == 0 {
                tokio::time::sleep(std::time::Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("the opener parked inside the first open");
        sessions.stop();
        release.notify_one();
        let (drained, stragglers) = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            sessions.join(tokio::time::Instant::now() + std::time::Duration::from_secs(5)),
        )
        .await
        .expect("the join is bounded");
        assert_eq!(
            (drained, stragglers),
            (2, 0),
            "the opener and its mint closure drained with no stragglers"
        );
        assert_eq!(entered.load(Ordering::SeqCst), 1, "no late open");
        let root = fixture.config.paths.authority_token_root.clone();
        let minted = std::fs::read_dir(&root).map_or(0, |entries| {
            entries
                .filter_map(Result::ok)
                .filter(|entry| entry.path().extension().is_some_and(|ext| ext == "json"))
                .count()
        });
        assert_eq!(minted, 1, "the second route was never minted");
    }

    /// A join under a deadline the parked opener cannot meet reports the
    /// straggler and returns bounded — the daemon never waits unbounded on
    /// observer work.
    #[tokio::test]
    async fn an_opener_missing_the_deadline_is_counted_not_claimed() {
        let entered = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let mut fixture = crate::live::hermes_routes::tests::gate_fixture_with(
            256,
            Arc::new(ParkedObserverLauncher {
                entered: Arc::clone(&entered),
                release: Arc::new(tokio::sync::Notify::new()),
                park_forever: true,
            }),
            true,
        )
        .await;
        two_observer_options(&mut fixture);
        bind_coordinator(&fixture).await;
        let sessions = super::ObservedSessions::own(
            Arc::clone(&fixture.supervisor),
            fixture.config.clone(),
            observed_routes()[..1].to_vec(),
        );
        sessions.spawn();
        tokio::time::timeout(std::time::Duration::from_secs(10), async {
            while entered.load(Ordering::SeqCst) == 0 {
                tokio::time::sleep(std::time::Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("the opener parked inside the open");
        sessions.stop();
        let (drained, stragglers) = sessions
            .join(tokio::time::Instant::now() + std::time::Duration::from_millis(200))
            .await;
        assert_eq!(
            (drained, stragglers),
            (1, 1),
            "the parked opener is a straggler, its finished mint drained"
        );
    }
}
