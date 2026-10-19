//! The session launcher every seat runs through: OMP's bridge launcher wrapped by the harness launcher with its
//! routes, the kernel MCP bridge and the cluster's pod terminals.

use std::sync::Arc;

use odin_huginn::OdindConfig;
use odin_omp::live::harness::{HarnessRoute, ProjectAccounts};
use odin_omp::live::runtime::ProductionBridgeRuntimeFactory;
use odin_omp::live::supervisor::{LiveBridgeLauncher, LiveSessionLauncher};
use odin_registry::Snapshot;
use tokio::sync::watch;

use crate::incidents::IncidentDesk;
use crate::kernel_mcp::{KernelDispatches, KernelMcpBridge};
use crate::kube::KubeRuntimeCell;

pub(super) struct HarnessLaunchInputs<'a> {
    pub config: &'a OdindConfig,
    pub snapshot: &'a Snapshot,
    pub launcher: LiveBridgeLauncher,
    pub production_factory: &'a Arc<ProductionBridgeRuntimeFactory>,
    pub incident_desk: &'a Arc<IncidentDesk>,
    pub kube_cell: &'a Option<Arc<KubeRuntimeCell>>,
    pub stops: Arc<odin_kernel::StopAuthority>,
    pub supervisor: crate::live_authority::SupervisorHandle,
    /// The session pool whose lifecycle owner runs every generic harness
    /// hand-back step; the daemon closes it at its stop.
    pub pool: crate::live_authority::SessionPoolHandle,
    // The owning daemon's stop token: both MCP listeners serve until it
    // resolves, then hand their serve tasks back for the bounded join —
    // and the dispatch ledger back to close and drain.
    pub stopping: watch::Receiver<bool>,
}

pub(super) async fn compose(
    inputs: HarnessLaunchInputs<'_>,
) -> Result<
    (
        Arc<dyn LiveSessionLauncher>,
        Vec<HarnessRoute>,
        KernelMcpBridge,
    ),
    String,
> {
    let HarnessLaunchInputs {
        config,
        snapshot,
        launcher,
        production_factory,
        incident_desk,
        kube_cell,
        stops,
        supervisor,
        pool,
        stopping,
    } = inputs;
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
    // Host harnesses use loopback MCP; terminal pods need the declared pod-facing address.
    let node_address: Option<std::net::IpAddr> = snapshot
        .objects
        .iter()
        .find_map(|object| match &object.config {
            odin_registry::ObjectConfig::Node(node) if object.id == config.identity.node => {
                node.gateway_endpoint.clone()
            }
            _ => None,
        })
        .and_then(|endpoint| odin_registry::schema::NodeGatewayEndpoint::parse(&endpoint).ok())
        .and_then(|endpoint| endpoint.host().parse().ok());
    let mut mcp_handles = Vec::new();
    let dispatches = KernelDispatches::new();
    let kernel_mcp = match crate::kernel_mcp::KERNEL_MCP_ADDRESS.parse() {
        Ok(address) => {
            let node = node_address
                .map(|ip| std::net::SocketAddr::new(ip, crate::kernel_mcp::KERNEL_MCP_PORT));
            let server = odin_omp::live::kernel_mcp::KernelMcpServer::with_node(
                crate::kernel_mcp::base_url(address),
                node.map(crate::kernel_mcp::base_url),
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
                    if let Some(node) = node {
                        match crate::kernel_mcp::serve_node(
                            node,
                            Arc::clone(&server),
                            dispatches.clone(),
                            stopping.clone(),
                        )
                        .await
                        {
                            Ok((_, handle)) => mcp_handles.push(handle),
                            Err(error) => {
                                tracing::warn!(
                                    "mcp node listener unavailable address={node} \
                                     error=\"{error}\"; terminal pods run without Odin's functions"
                                );
                            }
                        }
                    }
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
        harness_routes.clone(),
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
    // A `k3s-pod` terminal harness runs its pod on this node's cluster.
    let harness_launcher = match kube_cell {
        Some(cell) => {
            harness_launcher.with_pod_terminals(Arc::new(crate::harness::KubePodTerminals {
                cell: Arc::clone(cell),
                argv: crate::harness::PodTerminalsArgv::for_cluster(cell.kube_config()),
                node: config.identity.node.clone(),
                image: cell.workload_identity().deployment.image_reference.clone(),
            }))
        }
        None => harness_launcher,
    };
    Ok((
        Arc::new(harness_launcher),
        harness_routes,
        KernelMcpBridge {
            listeners: mcp_handles,
            dispatches,
        },
    ))
}
