//! Declared Hermes route binding: the conversation root composed from the
//! declared transport binding, and the daemon-bound read seams (terminal
//! capture and Huginn session projection).

use odin_huginn::OdindConfig;
use odin_ledger::Ledger;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration as StdDuration;

use crate::authority::{DeclaredConversationAuthority, DeclaredConversationBinding};
use crate::hermes::{DaemonHuginnReadRoute, DaemonModelCommandRoute, DaemonTerminalReadRoute};

/// The composition product the vehicle-open lane owns: the runtime holds
/// the route cells, the root holds the governed durable identity.
pub(super) struct VehicleRouteBinding {
    pub(super) runtime: Arc<odin_hermes::runtime::HermesRuntime>,
    pub(super) root: Arc<odin_hermes::conversation::ConversationRoot>,
}

pub(super) struct HermesBind<'a> {
    pub(super) hermes_runtime: &'a Option<Arc<odin_hermes::runtime::HermesRuntime>>,
    pub(super) hermes_route: Option<DeclaredConversationBinding>,
    pub(super) omp: &'a Arc<odin_omp::live::service::OmpLiveService>,
    pub(super) supervisor: &'a Arc<odin_omp::live::supervisor::LiveSupervisor>,
    pub(super) config: &'a OdindConfig,
    pub(super) manifest: &'a odin_huginn::RuntimeManifest,
    pub(super) conversation_ledger_path: &'a Path,
    pub(super) pin: &'a Arc<odin_registry::SnapshotHandle>,
    pub(super) read_model: &'a Arc<odin_huginn::read_model::MaterializedReadModel>,
    pub(super) kube_cell: &'a Option<Arc<crate::kube::KubeRuntimeCell>>,
    pub(super) rollover_seats: &'a std::collections::BTreeMap<
        odin_domain::SeatId,
        odin_omp::live::rollover::RolloverRuntimeConfig,
    >,
    pub(super) delegation_links: &'a odin_omp::host_tools::delegation::DelegationLinkLedger,
    pub(super) incidents: Option<&'a Arc<crate::incidents::IncidentDesk>>,
    pub(super) operation_store: Arc<std::sync::Mutex<Ledger>>,
    pub(super) operation_clock: odin_kernel::operation::Clock,
    pub(super) session_capsule_authority: &'a Arc<odin_cli::live_authority::SessionAuthorityPool>,
    /// The daemon's pinned gateway projection, when readable.
    pub(super) gateway: Option<&'a odin_registry::GatewayProjectionManifest>,
}

pub(super) async fn bind(parts: HermesBind<'_>) -> Result<Option<VehicleRouteBinding>, String> {
    let HermesBind {
        hermes_runtime,
        hermes_route,
        omp,
        supervisor,
        config,
        manifest,
        conversation_ledger_path,
        pin,
        read_model,
        kube_cell,
        rollover_seats,
        delegation_links,
        incidents,
        operation_store,
        operation_clock,
        session_capsule_authority,
        gateway,
    } = parts;
    // Missing credentials disarm both the gateway listener and conversation startup.
    let surface_disarmed = hermes_runtime.as_ref().is_some_and(|runtime| {
        runtime
            .gateway()
            .as_ref()
            .is_some_and(|gateway| gateway.credential_absent())
    });
    let mut declared_vehicle: Option<(
        odin_domain::SeatId,
        Arc<odin_hermes::conversation::ConversationRoot>,
    )> = None;
    let conversation_root = if surface_disarmed {
        None
    } else if let (
        Some(runtime),
        Some(DeclaredConversationBinding {
            declaration,
            vehicle: Some((binding, lane)),
            ..
        }),
    ) = (hermes_runtime, hermes_route)
    {
        let discord = runtime
            .settings()
            .discord
            .as_ref()
            .ok_or_else(|| "conversation composition lost its declared transport".to_owned())?;
        // Carry the seat identity with the root so model changes target this surface only.
        let vehicle_seat = binding.seat_id.clone();
        // The seat's declared model: the first of its registry `models`.
        let launch = binding
            .launch_options
            .first()
            .ok_or_else(|| format!("seat {} declares no model launch", binding.seat_id))?
            .clone();
        let target_node = odin_domain::NodeId::new(&config.identity.node)
            .map_err(|error| format!("conversation serving node is invalid: {error}"))?;
        if !binding.allowed_nodes.contains(&target_node) {
            return Err(format!(
                "seat {} does not allow the declared serving node",
                binding.seat_id
            ));
        }
        let authority = Arc::new(DeclaredConversationAuthority {
            config: config.clone(),
            seat: binding.seat_id.clone(),
            project: declaration.project.clone(),
            slice: binding.slice_id.clone(),
            lane: lane.clone(),
            provider: launch.provider.clone(),
            model: launch.model.clone(),
            incidents: incidents.cloned(),
        });
        let state_path = runtime
            .settings()
            .state_dir
            .join("conversations")
            .join(binding.seat_id.as_str())
            .join("root.json");
        let class_route = if let Some(class) = declaration.class {
            let gateway = runtime.model_gateway().ok_or_else(|| {
                format!(
                    "seat {} declares class {} without hermes.model_gateway",
                    binding.seat_id,
                    class.as_str()
                )
            })?;
            let launches: Vec<String> = binding
                .launch_options
                .iter()
                .map(|option| option.model.to_string())
                .collect();
            let endpoint = gateway.clone();
            tokio::task::spawn_blocking(move || {
                odin_hermes::runtime::validate_model_launches(&endpoint, &launches)
            })
            .await
            .map_err(|error| format!("class launch declaration validation stopped: {error}"))?
            .map_err(|error| {
                format!(
                    "seat {} class launch declaration refused: {error}",
                    binding.seat_id
                )
            })?;
            Some(odin_hermes::conversation::ClassRoute {
                class: class.as_str(),
                gateway,
            })
        } else {
            None
        };
        let approval_ledger = Ledger::open(conversation_ledger_path)
            .map_err(|error| format!("conversation approval ledger unavailable: {error}"))?;
        let route = odin_hermes::conversation::ConversationRoot::open(
            odin_hermes::conversation::ConversationRootConfig {
                binding,
                project: declaration.project,
                lane,
                provider: launch.provider,
                model: launch.model,
                target_node,
                owner: odin_hermes::conversation::OwnerSurface {
                    owner_user_id: discord.owner_user_id.clone(),
                    channel_id: discord.notify_channel_id.clone(),
                    actor: format!("discord-owner:{}", discord.owner_user_id),
                },
                answer_bound: StdDuration::from_secs(declaration.answer_timeout_seconds.get()),
                stall_bound: declaration
                    .stall_seconds
                    .map(|seconds| StdDuration::from_secs(seconds.get())),
                poll_interval: StdDuration::from_secs(2),
                plane: omp.clone(),
                authority,
                egress: Arc::new(Arc::downgrade(runtime)),
                approvals: Arc::new(odin_hermes::conversation::DaemonKernelApprovals {
                    runtime: Arc::downgrade(runtime),
                    ledger: Arc::new(parking_lot::Mutex::new(approval_ledger)),
                    delegation_links: Some(delegation_links.clone()),
                }),
                ledger_path: conversation_ledger_path.to_path_buf(),
                state_path,
                rollover: rollover_seats
                    .get(&vehicle_seat)
                    .map(odin_omp::live::rollover::RolloverRuntimeConfig::policy)
                    .unwrap_or_default(),
                clock: Some(odin_hermes::schedule::OwnerClock::new(
                    &runtime.settings().state_dir,
                )),
                delegation_links: Some(delegation_links.clone()),
                class_route,
            },
        )?;
        // The initialize itself is the lane's, not the composition's: a
        // failed vehicle open is a typed Huginn incident plus a bounded
        // retry of the SAME governed open — never a daemon exit. Until the
        // lane's initialize succeeds, the approved-intent and
        // owner-decision cells stay unset, so approved intents remain
        // stashed fail-closed and the vehicle's unavailability stays
        // explicit while every other surface serves. The composed root
        // travels to the model route: its durable record names the
        // surface's unambiguous vehicle session.
        declared_vehicle = Some((vehicle_seat, Arc::clone(&route)));
        Some(VehicleRouteBinding {
            runtime: Arc::clone(runtime),
            root: route,
        })
    } else {
        None
    };

    // The daemon-bound read seams: `terminal.read` rides the REAL supervisor
    // screen capture of the resolved governed target; `huginn.read` rides
    // the real live plane and supervisor facts. Both bridge the sync seams
    // through dedicated threads on the composition runtime, bounded under
    // their capability timeouts; a seam left unbound (hermes absent) keeps
    // dispatch typed-unavailable, never stubbed.
    if let Some(runtime) = &hermes_runtime {
        runtime.set_terminal_read_route(Arc::new(DaemonTerminalReadRoute {
            supervisor: Arc::clone(supervisor),
            handle: tokio::runtime::Handle::current(),
        }));
        runtime.set_huginn_read_route(Arc::new(DaemonHuginnReadRoute {
            plane: Arc::clone(omp),
            supervisor: Arc::clone(supervisor),
            node: config.identity.node.clone(),
            handle: tokio::runtime::Handle::current(),
        }));
        // The `workspace.connect` resolver rides the SAME pinned snapshot
        // and shared read model every fleet pump and brain source reads:
        // session names, host liveness, and project roots are one
        // authority's data, never a per-dispatch re-derivation.
        let ssh = manifest
            .executable("ssh")
            .map_err(|error| format!("runtime manifest ssh: {error}"))?;
        runtime.set_workspace_connect_route(Arc::new(crate::hermes::DaemonWorkspaceConnectRoute {
            pin: Arc::clone(pin),
            read_model: Arc::clone(read_model),
            project_roots: config.projects.clone(),
            ssh: ssh.path.clone(),
        }));
        runtime.set_desktop_route(Arc::new(crate::desk::DeskChannel::new(
            Arc::clone(pin),
            ssh.path.clone(),
        )));
        let pod = Arc::new(crate::claude_pod_backend::ClaudePodBackend::new(
            Arc::clone(pin),
            config,
            kube_cell.clone(),
            tokio::runtime::Handle::current(),
            operation_store,
            operation_clock,
        ));
        if let Err(error) = pod.recover_workers() {
            tracing::error!(
                "Claude publication worker recovery refused; existing pods retained error={error}"
            );
        }
        let transport = crate::claude_host_transport::ClaudeHostTransport::from_config(
            config,
            manifest,
            "claude-host-authority",
            "Claude host",
        )?;
        let host = Arc::new(crate::claude_host::ClaudeHostBackend::new(
            Arc::clone(pin),
            Arc::clone(read_model),
            transport,
        ));
        let claude = Arc::new(
            crate::claude_sessions::DaemonClaudeSessionRoute::new(
                &config.paths.state_root,
                pod,
                host,
                Arc::clone(read_model),
                Arc::clone(pin),
                incidents.cloned(),
            )
            .map_err(|error| format!("Claude session store unavailable: {error}"))?,
        );
        claude.start_projection_pump();
        runtime.set_claude_session_route(claude);
    }

    // Share the active snapshot pin so published profiles are launchable without restart.
    if let Some(runtime) = &hermes_runtime {
        // The live model-switch route: the real `OmpLiveService::command`
        // seam plus the surface's declared vehicle, so `seat.model.set`
        // dispatches exactly where the supervisor and the conversation
        // vehicle lawfully live — never at the bridge backend.
        // The fleet drain/restore surface rides the same pinned snapshot
        // and read model, plus the composed kube cell (`None` keeps every
        // cluster-touching dispatch typed-unavailable): one route, two
        // model tools, the authority move forever operator-run.
        runtime.set_fleet_drain_route(Arc::new(crate::hermes::DaemonFleetDrainRoute {
            pin: Arc::clone(pin),
            read_model: Arc::clone(read_model),
            kube_cell: kube_cell.clone(),
            handle: tokio::runtime::Handle::current(),
            state_root: config.paths.state_root.clone(),
        }));
    }
    if let Some(runtime) = &hermes_runtime {
        // A deployed authority authors in its private linked worktree of the
        // declared repository; without one, the registry root's parent (a
        // development checkout) is the worktree.
        let worktree = match &config.paths.authoring_worktree {
            Some(worktree) => worktree.clone(),
            None => config
                .paths
                .registry_root
                .parent()
                .ok_or_else(|| "registry root has no Odin repository parent".to_owned())?
                .to_path_buf(),
        };
        let sync = config
            .paths
            .authoring_repository
            .clone()
            .map(|repository| crate::workload_authoring::AuthoringSync { repository });
        // Coding seats build, check and hand back work from their session
        // capsules under the declared project roots (runtime-created ones
        // included: `OdindConfig::load` adopted them).
        let coding = Arc::new(crate::coding_route::DaemonCodingRoute {
            state_root: config.paths.state_root.clone(),
            session_pool: Some(Arc::clone(session_capsule_authority)),
            supervisor: Arc::downgrade(supervisor),
            projects: config
                .projects
                .iter()
                .map(|(project, entry)| (project.clone(), entry.root.clone()))
                .collect(),
            registry: Some(Arc::clone(pin)),
            manifest: Some(manifest.clone()),
            merge_lock_bound: crate::coding_route::MERGE_LOCK_BOUND,
        });
        let coding_route: Arc<dyn odin_hermes::runtime::coding::CodingRoute> = coding;
        runtime.set_coding_route(Arc::clone(&coding_route));
        let bwrap = manifest
            .executable("bwrap")
            .map_err(|error| format!("runtime manifest bwrap: {error}"))?
            .path
            .clone();
        runtime.set_claude_review_route(Arc::new(crate::claude_review::DaemonClaudeReviewRoute {
            pin: Arc::clone(pin),
            state_root: config.paths.state_root.clone(),
            brain_root: config
                .hermes
                .as_ref()
                .and_then(|hermes| hermes.brain_raw_root.clone()),
            bwrap,
            coding: coding_route,
        }));
        // The official-client consult drivers (Opus 5.5 through Claude
        // Code, Antigravity through agy) compose from the same pinned
        // snapshot; absent agy config leaves consult its gateway frontier
        // cards and the Claude Code card.
        runtime.set_consult_route(Arc::new(crate::consult_official::DaemonConsultRoute {
            pin: Arc::clone(pin),
            state_root: config.paths.state_root.clone(),
            agy: config
                .hermes
                .as_ref()
                .and_then(|hermes| hermes.consult.as_ref())
                .and_then(|consult| consult.agy.clone()),
        }));
        // Declared folders on fleet hosts (`files.list`, `files.share`).
        if !config.file_roots.is_empty() {
            let here = pin
                .current()
                .listed_objects(odin_registry::RegistryKind::Node)
                .into_iter()
                .find_map(|object| match &object.config {
                    odin_registry::ObjectConfig::Node(node)
                        if object.id == config.identity.node =>
                    {
                        Some(node.host.clone())
                    }
                    _ => None,
                });
            let host_files = Arc::new(crate::host_files::DaemonHostFiles {
                roots: config.file_roots.clone(),
                here,
                pin: Arc::clone(pin),
                state_dir: config.paths.state_root.join("host-file-saves"),
                queue_gate: std::sync::Mutex::new(()),
                transport: crate::claude_host_transport::ClaudeHostTransport::from_config(
                    config,
                    manifest,
                    "host-files-authority",
                    "host files",
                )?,
            });
            host_files.start_queue()?;
            runtime.set_host_file_route(host_files);
        }
        let mut declare = None;
        if let Some(sync) = &sync {
            // One authoring route: projects, seats, routines and seat models share its
            // commit-and-publish transaction.
            let route = Arc::new(crate::project_authoring::DaemonProjectRoute {
                pin: Arc::clone(pin),
                admission_config: config.clone(),
                caller_slices: config
                    .seats
                    .iter()
                    .map(|binding| (binding.seat.to_string(), binding.slice.to_string()))
                    .collect(),
                harness_environments: config
                    .seats
                    .iter()
                    .flat_map(|binding| {
                        binding.launch_options.iter().filter_map(|option| {
                            option.harness.as_ref().map(|harness| {
                                (harness.environment.clone(), binding.seat.to_string())
                            })
                        })
                    })
                    .fold(
                        std::collections::BTreeMap::new(),
                        |mut environments, (environment, seat)| {
                            environments.entry(environment).or_default().insert(seat);
                            environments
                        },
                    ),
                snapshot_store: config.paths.registry_snapshot.clone(),
                worktree: worktree.clone(),
                sync: sync.clone(),
            });
            runtime.set_project_route(route.clone());
            runtime.set_routine_route(route.clone());
            runtime.set_registry_author_route(route.clone());
            declare = Some(route);
        }
        runtime.set_model_command_route(Arc::new(DaemonModelCommandRoute {
            plane: Arc::clone(omp),
            vehicle: declared_vehicle,
            handle: tokio::runtime::Handle::current(),
            declare,
        }));
        let authoring = crate::workload_authoring::DaemonWorkloadAuthoring::new(
            Arc::clone(pin),
            worktree,
            config.paths.registry_snapshot.clone(),
            conversation_ledger_path.to_path_buf(),
            config.paths.state_root.clone(),
            kube_cell
                .as_ref()
                .map(|cell| cell.workload_identity().deployment.clone()),
            sync,
        )
        .map_err(|error| error.to_string())?
        .with_gateway(gateway.cloned())
        .with_seat_lanes(
            config
                .seats
                .iter()
                .map(|binding| {
                    let lanes = binding
                        .launch_options
                        .iter()
                        .filter(|option| option.provider.as_str() == "gateway")
                        .map(|option| option.model.as_str().to_owned())
                        .collect();
                    (binding.seat.to_string(), lanes)
                })
                .collect(),
        );
        runtime.set_workload_authoring_route(Arc::new(authoring));
    }
    Ok(conversation_root)
}

#[cfg(test)]
#[path = "../tests/hermes_routes.rs"]
pub(crate) mod tests;
