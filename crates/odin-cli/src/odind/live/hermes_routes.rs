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

#[allow(clippy::too_many_arguments)]
pub(super) async fn bind(
    hermes_runtime: &Option<Arc<odin_hermes::runtime::HermesRuntime>>,
    hermes_route: Option<DeclaredConversationBinding>,
    omp: &Arc<odin_omp::live::service::OmpLiveService>,
    supervisor: &Arc<odin_omp::live::supervisor::LiveSupervisor>,
    config: &OdindConfig,
    manifest: &odin_huginn::RuntimeManifest,
    conversation_ledger_path: &Path,
    pin: &Arc<odin_registry::SnapshotHandle>,
    read_model: &Arc<odin_huginn::read_model::MaterializedReadModel>,
    kube_cell: &Option<Arc<crate::kube::KubeRuntimeCell>>,
    rollover_seats: &std::collections::BTreeMap<
        odin_domain::SeatId,
        odin_omp::live::rollover::RolloverRuntimeConfig,
    >,
    delegation_links: &odin_omp::host_tools::delegation::DelegationLinkLedger,
    incidents: Option<&Arc<crate::incidents::IncidentDesk>>,
    operation_store: Arc<std::sync::Mutex<Ledger>>,
    operation_clock: odin_kernel::operation::Clock,
    session_capsule_authority: &Arc<odin_cli::live_authority::SessionAuthorityPool>,
) -> Result<Option<VehicleRouteBinding>, String> {
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
        // The seat's chosen launch (set from a DM, kept
        // across restarts), else its first declared option.
        let launch = odin_omp::live::seat_launch::SeatLaunchStore::new(&config.paths.state_root)
            .select(binding.seat_id.as_str(), &binding.launch_options)
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
        runtime.set_workspace_connect_route(Arc::new(crate::hermes::DaemonWorkspaceConnectRoute {
            pin: Arc::clone(pin),
            read_model: Arc::clone(read_model),
            project_roots: config.projects.clone(),
        }));
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
                "Claude publication custody recovery refused; existing pods retained error={error}"
            );
        }
        let transport =
            crate::claude_host_transport::ClaudeHostTransport::from_config(config, manifest)?;
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
        runtime.set_model_command_route(Arc::new(DaemonModelCommandRoute {
            plane: Arc::clone(omp),
            vehicle: declared_vehicle,
            handle: tokio::runtime::Handle::current(),
            seat_launch: odin_omp::live::seat_launch::SeatLaunchStore::new(
                &config.paths.state_root,
            ),
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
        runtime.set_coding_route(Arc::new(crate::coding_route::DaemonCodingRoute {
            state_root: config.paths.state_root.clone(),
            session_pool: Some(Arc::clone(session_capsule_authority)),
            supervisor: Arc::downgrade(supervisor),
            projects: config
                .projects
                .iter()
                .map(|(project, entry)| (project.clone(), entry.root.clone()))
                .collect(),
            registry: Some(Arc::clone(pin)),
        }));
        if let Some(sync) = &sync {
            // One authoring route: projects, seats and routines share its
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
            runtime.set_registry_author_route(route);
        }
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
