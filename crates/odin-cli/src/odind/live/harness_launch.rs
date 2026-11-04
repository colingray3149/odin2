//! The session launcher every seat runs through: OMP's bridge launcher wrapped by the harness launcher with its
//! routes and the kernel MCP bridge.

use std::sync::Arc;

use odin_huginn::OdindConfig;
use odin_omp::live::harness::ProjectAccounts;
use odin_omp::live::runtime::ProductionBridgeRuntimeFactory;
use odin_omp::live::supervisor::{LiveBridgeLauncher, LiveSessionLauncher};
use tokio::sync::watch;

use crate::incidents::IncidentDesk;
use crate::kernel_mcp::{KernelDispatches, KernelMcpBridge};

pub(super) struct HarnessLaunchInputs<'a> {
    pub config: &'a OdindConfig,
    pub launcher: LiveBridgeLauncher,
    pub production_factory: &'a Arc<ProductionBridgeRuntimeFactory>,
    pub incident_desk: &'a Arc<IncidentDesk>,
    pub stops: Arc<odin_kernel::StopAuthority>,
    pub supervisor: crate::live_authority::SupervisorHandle,
    /// The session pool whose lifecycle owner runs every generic harness
    /// hand-back step; the daemon closes it at its stop.
    pub pool: crate::live_authority::SessionPoolHandle,
    // The owning daemon's stop token: the MCP listener serves until it
    // resolves, then hand their serve tasks back for the bounded join —
    // and the dispatch ledger back to close and drain.
    pub stopping: watch::Receiver<bool>,
    /// The runtime manifest's bubblewrap. A Claude Code seat harness refuses to start without it.
    pub bwrap: Option<std::path::PathBuf>,
}

pub(super) async fn compose(
    inputs: HarnessLaunchInputs<'_>,
) -> Result<(Arc<dyn LiveSessionLauncher>, KernelMcpBridge), String> {
    let HarnessLaunchInputs {
        config,
        launcher,
        production_factory,
        incident_desk,
        stops,
        supervisor,
        pool,
        stopping,
        bwrap,
    } = inputs;
    if let Some(bwrap) = bwrap.as_ref().filter(|path| path.is_absolute()) {
        // The terminal harness expands `{bwrap}` from this variable. The manifest
        // path is the only source; an unset variable refuses the launch.
        std::env::set_var("ODIN_BWRAP", bwrap);
    }
    // Only launch options naming a harness bypass OMP.
    let names_a_harness = config
        .seats
        .iter()
        .flat_map(|seat| seat.launch_options.iter())
        .any(|option| option.harness.is_some());
    let (harness_routes, project_accounts) = if !names_a_harness {
        (Vec::new(), ProjectAccounts::new())
    } else {
        let objects = odin_registry::SnapshotStore::new(&config.paths.registry_snapshot)
            .load_verified()
            .map(|snapshot| snapshot.objects)
            .map_err(|error| format!("registry snapshot for harness routes: {error}"))?;
        (
            crate::harness::harness_routes(&config.seats, &objects)?,
            crate::harness::project_accounts(&objects),
        )
    };
    for route in &harness_routes {
        tracing::info!(
            "harness route harness={} environment={} transport={} posture={:?}",
            route.harness_id,
            route.environment_id,
            route.environment.transport.as_str(),
            route.environment.posture()
        );
    }
    let mut mcp_handles = Vec::new();
    let dispatches = KernelDispatches::new();
    let kernel_mcp = match crate::kernel_mcp::KERNEL_MCP_ADDRESS.parse() {
        Ok(address) => {
            let server = odin_omp::live::kernel_mcp::KernelMcpServer::new(
                crate::kernel_mcp::base_url(address),
            );
            match crate::kernel_mcp::serve(
                address,
                Arc::clone(&server),
                dispatches.clone(),
                stopping.clone(),
            )
            .await
            {
                Ok((_, handle)) => {
                    mcp_handles.push(handle);
                    Some(server)
                }
                Err(error) => {
                    tracing::warn!(
                        "mcp unavailable address={address} error=\"{error}\"; harness \
                         sessions run without Odin's functions"
                    );
                    None
                }
            }
        }
        Err(error) => {
            tracing::warn!("mcp unavailable error=\"{error}\"");
            None
        }
    };
    let harness_launcher = odin_omp::live::harness::HarnessLauncher::new(
        Arc::new(launcher),
        harness_routes,
        Arc::new(crate::harness::workspace::DaemonHarnessWorkspace {
            projects: config
                .projects
                .iter()
                .map(|(id, project)| (id.clone(), project.root.clone()))
                .collect(),
            authority_host: config.identity.node.clone(),
            state_root: config.paths.state_root.clone(),
            supervisor,
            pool,
        }),
        Some(Arc::new(crate::harness::FactoryHarnessTerminals(
            production_factory.clone(),
        ))),
    );
    let (rollover_seats, card_windows) = production_factory.terminal_rollover();
    let harness_launcher = harness_launcher
        .with_terminal_rollover(
            rollover_seats,
            card_windows,
            config.paths.state_root.join("rollover-counts"),
        )
        .with_incidents(Arc::new(crate::harness::DeskIncidentSink(Arc::clone(
            incident_desk,
        ))))
        .with_stops(stops)
        .with_project_accounts(project_accounts);
    let harness_launcher = match kernel_mcp {
        Some(server) => harness_launcher.with_kernel_mcp(server),
        None => harness_launcher,
    };
    Ok((
        Arc::new(harness_launcher),
        KernelMcpBridge {
            listeners: mcp_handles,
            dispatches,
        },
    ))
}
