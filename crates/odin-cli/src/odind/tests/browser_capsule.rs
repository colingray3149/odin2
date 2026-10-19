// Browser termination must not stop Huginn or Hermes serving.

use std::future::Future;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration as StdDuration;

use odin_domain::huginn::{ContentTicketIssuer, DeviceId, TailnetNodeId};
use odin_hermes::discord::DiscordMessage;
use odin_huginn::auth::DeviceCredential;
use odin_huginn::browser::BrowserProjectionError;
use odin_huginn::devices::{NewDeviceRecord, SqliteDeviceTrustStore};
use odin_huginn::dispatch::{AuthenticatedCommandPort, DispatchGuard as _};
use odin_huginn::files::RootCatalog;
use odin_huginn::private_network::InterfaceTailnetVerifier;
use odin_huginn::read_model::MaterializedReadModel;
use odin_huginn::renders::{FileRenderSource, RenderPublisher};
use odin_huginn::router::ContentTicketStore;
use odin_huginn::service::{
    FsExternalContentIndex, FsPublishedArtifactStore, HuginnCommandPlane, HuginnContentTicketIssuer,
};
use odin_huginn::state::{FsDispatchGuard, HuginnPorts};
use odin_huginn::streams::{BoundedMultiplexer, DurableReplayStore};
use odin_huginn::{ConnectionRegistry, DeviceTrustStore as _};
use odin_huginn::{HuginnConfig, HuginnLiveState, HuginnService, NodePosture};
use odin_ledger::Ledger;
use time::OffsetDateTime;

use crate::composition::renderer_registry;
use crate::huginn_conformance::stream_backpressure_limits;
use crate::kube::RuntimeCommandPort;
use crate::live::hermes_routes::tests::{gate_fixture, GateFixture};
use crate::live::orchestrate_serving;
use crate::live::serving::{ServingShutdown, ShutdownOutcome, SHUTDOWN_GRACE};
use odin_cli::runtime_bindings::RuntimeInputs;

fn event_stream_ended_failure() -> BrowserProjectionError {
    BrowserProjectionError::Stage {
        stage: "browser event delivery",
        detail: "event stream ended while the session was active".to_owned(),
    }
}

/// Return the recorded terminal result, or `Closed` if its sender disappears.
async fn watch_terminal(
    mut terminal: tokio::sync::watch::Receiver<Option<Result<(), BrowserProjectionError>>>,
) -> Result<(), BrowserProjectionError> {
    loop {
        if let Some(result) = terminal.borrow().clone() {
            return result;
        }
        if terminal.changed().await.is_err() {
            return Err(BrowserProjectionError::Closed);
        }
    }
}

/// Compose Huginn as `serve_huginn_async` does, with a provisioned fixture device.
pub(crate) async fn arm_real_huginn_service(
    fixture: &GateFixture,
    address: std::net::SocketAddr,
) -> (impl Future<Output = std::io::Result<()>>, String) {
    let config = fixture.config.clone();
    let snapshot = fixture.pin.current();
    let validated = HuginnConfig {
        bind: odin_huginn::config::HuginnBindConfig { address },
        limits: config.capacity.clone(),
        state_root: config.paths.state_root.join("huginn"),
    }
    .validate()
    .expect("fixture huginn configuration validates");
    let runtime_inputs =
        RuntimeInputs::parse(&config, &snapshot.objects).expect("fixture runtime inputs parse");
    let limits = validated.limits().clone();
    let huginn_root = validated.state().root().to_path_buf();
    let guard: Arc<dyn odin_huginn::dispatch::DispatchGuard> = {
        let guard = FsDispatchGuard::new(&config.paths.state_root).expect("STOP guard composes");
        guard.check_stop().await.expect("STOP guard check");
        Arc::new(guard)
    };
    std::fs::create_dir_all(validated.state().streams_dir()).expect("streams root");

    let bridge_ledger = Arc::new(Mutex::new(
        Ledger::open(config.paths.state_root.join("ledger.sqlite3"))
            .expect("controller ledger opens"),
    ));
    let max_objects = snapshot
        .objects
        .len()
        .saturating_add(runtime_inputs.file_roots.len())
        .saturating_add(65_536);
    let read_model = Arc::new(MaterializedReadModel::with_limits(
        max_objects,
        max_objects.saturating_mul(2),
        OffsetDateTime::now_utc(),
    ));
    let replay = DurableReplayStore::open(
        validated.state().streams_dir().join("replay.sqlite3"),
        limits.streams.replay_buffer_events.get(),
        u64::try_from(limits.streams.max_stream_frame_bytes.get())
            .expect("stream frame limit fits u64"),
    )
    .expect("replay store opens");
    let streams = Arc::new(BoundedMultiplexer::new(
        replay,
        limits.streams.frame_queue_depth.get(),
        limits.connections.max_subscriptions_per_connection.get(),
    ));
    let devices = Arc::new(
        SqliteDeviceTrustStore::open(validated.state().devices_db()).expect("devices db opens"),
    );
    let credential = DeviceCredential::generate(
        DeviceId::parse("0189d6b3-d316-7c3e-8b1e-2f9c4a7b8c9d").expect("device id"),
    );
    devices
        .insert(NewDeviceRecord {
            device_id: credential.device_id(),
            tailnet_node_id: TailnetNodeId::parse("fixture-node.tailnet").expect("tailnet node id"),
            label: "browser-capsule-liveness".to_owned(),
            credential_digest: credential.digest(),
            created_at: OffsetDateTime::now_utc(),
        })
        .await
        .expect("fixture device is provisioned");
    let tailnet = Arc::new(InterfaceTailnetVerifier::new(
        runtime_inputs.tailnet_peers.clone(),
    ));
    let connections = ConnectionRegistry::with_limit(limits.connections.max_connections.get());
    let external_content = Arc::new(
        FsExternalContentIndex::open(huginn_root.join("content-aliases"))
            .expect("external content index opens"),
    );
    let published = Arc::new(
        FsPublishedArtifactStore::open(
            huginn_root.join("published"),
            runtime_inputs.render_session,
            runtime_inputs.file_publish_lane,
            runtime_inputs.render_publish_lane,
        )
        .expect("published store opens"),
    );
    let files = Arc::new(odin_huginn::HuginnFileService::new(
        RootCatalog::new(runtime_inputs.file_roots.clone()).expect("file catalog"),
        limits.files.clone(),
    ));
    let render_source: Arc<dyn odin_huginn::renders::RenderSourceResolver> =
        Arc::new(FileRenderSource::new(files.browse_engine().clone()));
    let render_publisher: Arc<dyn RenderPublisher> = published.clone();
    let renders = Arc::new(
        odin_huginn::HuginnRenderService::new(
            validated.state().renders_dir(),
            limits.renders.clone(),
            renderer_registry().expect("renderer registry"),
            render_source,
            render_publisher,
        )
        .expect("render service opens"),
    );
    let ticket_ttl = StdDuration::from_secs(
        u64::try_from(limits.transfers.ticket_ttl.whole_seconds()).expect("ticket ttl fits u64"),
    );
    let ticket_store = ContentTicketStore::new(
        limits.transfers.queue_depth.get(),
        limits.transfers.max_transfer_bytes.get(),
        ticket_ttl,
    );
    let live_plane = fixture.omp.clone();
    let ticket_issuer: Arc<dyn ContentTicketIssuer> = Arc::new(
        HuginnContentTicketIssuer::new(
            ticket_store.clone(),
            live_plane.clone(),
            Arc::clone(&files),
            Arc::clone(&published),
            external_content.as_ref().clone(),
            ticket_ttl,
            limits.transfers.queue_depth.get(),
        )
        .map_err(|error| error.to_string())
        .expect("ticket issuer composes"),
    );
    let general: Arc<dyn AuthenticatedCommandPort> = Arc::new(RuntimeCommandPort::new(
        bridge_ledger,
        Arc::clone(&read_model),
        None,
        Arc::clone(&streams),
        None,
        stream_backpressure_limits(&limits).expect("stream backpressure limits"),
    ));
    let commands = Arc::new(HuginnCommandPlane::new(general, live_plane));
    let state = HuginnLiveState::new(HuginnPorts {
        read_model,
        commands,
        streams,
        files,
        renders,
        devices,
        tailnet,
        connections,
        guard,
        posture: NodePosture::Authoritative,
        tickets: ticket_issuer,
    });
    let service = HuginnService::new(validated, state, ticket_store);
    (service.serve(), credential.encode())
}

/// One real authenticated bootstrap request against the REAL Huginn API
/// handler over real loopback TCP. Connection failures are returned, not
/// panicked, so the caller decides what a refusal means.
pub(crate) async fn authenticated_bootstrap(
    address: std::net::SocketAddr,
    bearer: &str,
) -> std::io::Result<(u16, String)> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut stream = tokio::net::TcpStream::connect(address).await?;
    let request = format!(
        "GET /colinremote/v1/bootstrap HTTP/1.1\r\nHost: {address}\r\n\
         Authorization: Bearer {bearer}\r\nConnection: close\r\n\r\n"
    );
    stream
        .write_all(request.as_bytes())
        .await
        .expect("bootstrap request written");
    let mut response = String::new();
    stream
        .read_to_string(&mut response)
        .await
        .expect("bootstrap response read");
    let status: u16 = response
        .split_whitespace()
        .nth(1)
        .and_then(|code| code.parse().ok())
        .unwrap_or(0);
    Ok((status, response))
}

/// The FIRST bootstrap waits for the real service to finish binding its
/// listener: a refused connection before the first success is startup
/// timing, never a liveness verdict.
pub(crate) async fn first_authenticated_bootstrap(
    address: std::net::SocketAddr,
    bearer: &str,
) -> (u16, String) {
    let deadline = tokio::time::Instant::now() + StdDuration::from_secs(10);
    loop {
        match tokio::time::timeout(
            StdDuration::from_secs(2),
            authenticated_bootstrap(address, bearer),
        )
        .await
        {
            Ok(Ok(outcome)) => return outcome,
            Ok(Err(_)) | Err(_) => assert!(
                tokio::time::Instant::now() < deadline,
                "the real Huginn service never began serving"
            ),
        }
        tokio::time::sleep(StdDuration::from_millis(10)).await;
    }
}

/// One real Hermes ingress admission through the runtime's sanctioned
/// non-gateway entry: the paired owner's DM. Returns the typed intake
/// projection's status field.
async fn hermes_ingest(runtime: &Arc<odin_hermes::runtime::HermesRuntime>, id: u64) -> String {
    let message = DiscordMessage {
        id: format!("1000000000000000{id:04}"),
        channel_id: "1000000000000000002".to_owned(),
        author_id: "1000000000000000001".to_owned(),
        guild_id: None,
        content: "please inspect the repository".to_owned(),
        attachments: Vec::new(),
    };
    let projection = runtime
        .admit_message(&message)
        .expect("hermes ingress must answer with a typed intake projection");
    projection
        .get("status")
        .and_then(|status| status.as_str())
        .map(str::to_owned)
        .expect("the intake projection carries a typed status")
}

async fn wait_for(counter: &AtomicU64, target: u64, case: &str) {
    let deadline = tokio::time::Instant::now() + StdDuration::from_secs(10);
    while counter.load(Ordering::Relaxed) < target {
        assert!(
            tokio::time::Instant::now() < deadline,
            "{case}: capsule retirement never ran"
        );
        tokio::time::sleep(StdDuration::from_millis(5)).await;
    }
}

async fn browser_terminal_keeps_huginn_and_hermes_serving(
    terminal: Result<(), BrowserProjectionError>,
    case: &'static str,
) {
    let fixture = gate_fixture().await;

    // Reserve an ephemeral serving port for the real Huginn service.
    let probe_listener = std::net::TcpListener::bind("127.0.0.1:0").expect("free port");
    let address = probe_listener.local_addr().expect("serving address");
    drop(probe_listener);
    let (serve, bearer) = arm_real_huginn_service(&fixture, address).await;

    // The pump set: the immortal pump-task shape the daemon arms (the
    // Hermes egress and kube watch pumps live exactly here in production).
    let ticks = Arc::new(AtomicU64::new(0));
    let mut pumps = tokio::task::JoinSet::new();
    let pump_ticks = Arc::clone(&ticks);
    pumps.spawn(async move {
        loop {
            tokio::time::sleep(StdDuration::from_millis(5)).await;
            pump_ticks.fetch_add(1, Ordering::Relaxed);
        }
        #[allow(unreachable_code)]
        Ok::<(), String>(())
    });

    // Exercise the same supervisor and serving select used by `serve_huginn_async`.
    let (terminal_signal, terminal_watch) = tokio::sync::watch::channel(None);
    let retirements = Arc::new(AtomicU64::new(0));
    let capsule = {
        let retirements = Arc::clone(&retirements);
        Some((watch_terminal(terminal_watch), move || {
            let retirements = Arc::clone(&retirements);
            async move {
                retirements.fetch_add(1, Ordering::Relaxed);
                Vec::new()
            }
        }))
    };

    let (stop_signal, signal_stop) = tokio::sync::oneshot::channel::<()>();
    let signal_stop = async move {
        let _ = signal_stop.await;
    };
    let node = tokio::spawn(orchestrate_serving(
        Ok(serve),
        pumps,
        signal_stop,
        capsule,
        ServingShutdown::detached(),
    ));

    // Before: both real surfaces answer usefully.
    let (status, body) = first_authenticated_bootstrap(address, &bearer).await;
    assert_eq!(
        status, 200,
        "{case}: Huginn must serve an authenticated bootstrap before the terminal: {body}"
    );
    assert!(
        body.contains("maxFrameBytes"),
        "{case}: bootstrap must carry its typed payload: {body}"
    );
    let hermes_before = hermes_ingest(&fixture.runtime, 1).await;
    assert!(
        !hermes_before.is_empty(),
        "{case}: hermes ingress must project a typed status before the terminal"
    );

    // Mid-session the browser capsule reaches terminal.
    terminal_signal.send_replace(Some(terminal));

    wait_for(&retirements, 1, case).await;
    let (status, body) = authenticated_bootstrap(address, &bearer)
        .await
        .unwrap_or_else(|error| {
            panic!(
                "{case}: after the capsule reached terminal the daemon must still \
                 accept and answer connections (the pre-fix outage dropped them \
                 instead): {error}"
            )
        });
    assert_eq!(
        status, 200,
        "{case}: Huginn must STILL serve an authenticated, useful bootstrap \
         after the browser capsule reached terminal: {body}"
    );
    assert!(
        body.contains("maxFrameBytes"),
        "{case}: post-terminal bootstrap must still carry its typed payload: {body}"
    );
    let hermes_after = hermes_ingest(&fixture.runtime, 2).await;
    assert!(
        !hermes_after.is_empty(),
        "{case}: hermes ingress must still project a typed status after the terminal"
    );

    // The pump arm is still alive too.
    let ticks_before = ticks.load(Ordering::Relaxed);
    tokio::time::sleep(StdDuration::from_millis(40)).await;
    assert!(
        ticks.load(Ordering::Relaxed) > ticks_before,
        "{case}: the pump set must keep ticking after the capsule retired"
    );

    // A real stop lands cleanly: the seam's own retirement owner joins (the
    // capsule retired itself long before stop), the select exits on the
    // stop flag only, and nothing retried the retired capsule.
    stop_signal
        .send(())
        .expect("the serving select waits for the stop");
    let (result, accounting) = tokio::time::timeout(StdDuration::from_secs(10), node)
        .await
        .expect("{case}: the serving select returns on stop")
        .expect("{case}: the serving select task joins");
    assert_eq!(
        accounting.outcome,
        ShutdownOutcome::Drained { tracked: 2 },
        "{case}: the pump and the joined capsule ladder are the two tracked ends"
    );
    assert!(
        result.is_ok(),
        "{case}: the stop path stays clean: {result:?}"
    );
    assert_eq!(
        retirements.load(Ordering::Relaxed),
        1,
        "{case}: exactly one capsule retirement must ever run"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn browser_failure_keeps_huginn_and_hermes_actually_serving() {
    browser_terminal_keeps_huginn_and_hermes_serving(
        Err(event_stream_ended_failure()),
        "browser failure",
    )
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn clean_browser_terminal_keeps_huginn_and_hermes_actually_serving() {
    browser_terminal_keeps_huginn_and_hermes_serving(Ok(()), "clean browser terminal").await;
}

/// An undrainable browser is reported as a straggler under the serving deadline, with the
/// original stop time returned for the caller's publication budget rather than a fresh clock.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn browser_retirement_is_bounded_by_the_shared_shutdown_deadline() {
    let capsule = Some((
        std::future::pending::<Result<(), BrowserProjectionError>>(),
        || std::future::pending::<Vec<String>>(),
    ));
    let before_stop = std::time::Instant::now();
    let (result, accounting) = tokio::time::timeout(
        SHUTDOWN_GRACE + StdDuration::from_secs(2),
        orchestrate_serving(
            Ok(async { Ok::<(), std::io::Error>(()) }),
            tokio::task::JoinSet::new(),
            std::future::pending::<()>(),
            capsule,
            ServingShutdown::detached(),
        ),
    )
    .await
    .expect("browser retirement must not hold shutdown past the serving deadline");
    let finished = std::time::Instant::now();

    assert!(result.is_ok(), "the caller owns the straggler verdict");
    assert_eq!(
        accounting.outcome,
        ShutdownOutcome::Stragglers {
            tracked: 0,
            stragglers: 1,
        },
        "the unfinished browser must refuse clean shutdown and publication"
    );
    assert!(accounting.capsule_failures.is_empty());
    assert!(accounting.started >= before_stop);
    assert!(
        finished.duration_since(accounting.started) >= SHUTDOWN_GRACE,
        "the publication clock must include browser retirement, not restart after it"
    );
    assert!(accounting.deadline <= finished);
    assert!(
        accounting.deadline.duration_since(accounting.started)
            <= SHUTDOWN_GRACE + StdDuration::from_millis(100),
        "the shared serving deadline must retain main's eight-second bound"
    );
}
