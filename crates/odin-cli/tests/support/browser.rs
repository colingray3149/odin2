//! Real browser session/projection with a scripted page-mechanics relay.
//! Approval and command outcomes remain the production coordinator's work.
use std::collections::BTreeMap;
use std::num::NonZeroUsize;
use std::os::unix::fs::PermissionsExt as _;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use odin_browser::relay::{RelayedStreams, RelayedWorkerLaunch, RelayedWorkerPaths, WorkerRelay};
use odin_browser::safety::{BrowserSafetyGate, ProtectedValue, ProtectedValues};
use odin_browser::session::{BrowserSession, FrameWiring, SessionLimits};
use odin_browser::{
    ActionRule, BrowserPolicySnapshot, BrowserStopHost, ExecutableMalwareScanner, StructuralAction,
};
use odin_cli::browser_runtime::BrowserCommandCoordinator;
use odin_domain::huginn as live;
use odin_domain::{CapabilityId, EffectClass, LaneId};
use odin_huginn::browser::{BrowserProjection, BrowserProjectionConfig};
use odin_huginn::read_model::MaterializedReadModel;
use odin_huginn::service::{FsExternalContentIndex, FsPublishedArtifactStore};
use odin_huginn::streams::{BoundedMultiplexer, DurableReplayStore};
use odin_ledger::Ledger;
use serde_json::{json, Value};
use tokio::io::{AsyncBufReadExt as _, AsyncWriteExt as _, BufReader};

pub(crate) const BROWSER: &str = "00000000-0000-4000-8000-0000000000b2";
const VEHICLE: &str = "00000000-0000-4000-8000-0000000000b0";

/// The relayed worker's page mechanics for one form page: it answers the
/// closed JSONL worker protocol and records every dispatched mutation. It
/// never sees an approval; the coordinator and session decide what reaches
/// it.
struct ScriptedWorker(Option<RelayedStreams>);

impl WorkerRelay for ScriptedWorker {
    fn split(self: Box<Self>) -> RelayedStreams {
        self.0.expect("the relay is split exactly once")
    }
}

fn scripted_worker(dispatched: Arc<Mutex<Vec<Value>>>) -> Box<dyn WorkerRelay> {
    let (host_in, worker_in) = tokio::io::duplex(1 << 20);
    let (mut worker_out, host_out) = tokio::io::duplex(1 << 20);
    let worker = tokio::spawn(async move {
        let ready = b"{\"v\":1,\"ready\":\"odin-playwright-worker\"}\n";
        if worker_out.write_all(ready).await.is_err() {
            return;
        }
        let document = "d".repeat(64);
        let mut lines = BufReader::new(worker_in).lines();
        while let Ok(Some(line)) = lines.next_line().await {
            let request: Value = serde_json::from_str(&line).expect("worker request line");
            let Some(id) = request["id"].as_str() else {
                continue;
            };
            let params = &request["params"];
            let result = match request["method"].as_str().unwrap_or_default() {
                "Launch" => Some(json!({"browserLaunched": true, "frameProducerStarted": true})),
                "Preflight" => Some(json!({
                    "bindingId": format!("binding-{id}"),
                    "documentToken": document,
                    "target": params["selector"]
                        .is_string()
                        .then(|| json!({"tag": "button", "inputType": "submit", "inForm": true})),
                })),
                "Dispatch" => {
                    dispatched.lock().unwrap().push(params["action"].clone());
                    Some(
                        json!({"navigation": null, "screenshotBase64": null, "targetClosed": false}),
                    )
                }
                "ReleaseBinding" | "StopFrames" | "CloseBrowser" | "Shutdown" => {
                    Some(json!({"acknowledged": true}))
                }
                // No page facts exist in this fixture: observation refuses.
                _ => None,
            };
            let envelope = match result {
                Some(result) => json!({"v": 1, "id": id, "ok": true, "result": result}),
                None => json!({"v": 1, "id": id, "ok": false,
                    "error": {"code": "operationFailed", "uncertain": false, "fatal": false}}),
            };
            if worker_out
                .write_all(format!("{envelope}\n").as_bytes())
                .await
                .is_err()
            {
                return;
            }
            if request["method"] == "Shutdown" {
                break;
            }
        }
    });
    Box::new(ScriptedWorker(Some(RelayedStreams {
        stdin: Box::new(host_in),
        stdout: Box::new(host_out),
        exit: Box::pin(async move {
            Some(match worker.await {
                Ok(()) => "fixture relay task joined".to_owned(),
                Err(error) => format!("fixture relay task failed: {error}"),
            })
        }),
        stderr: Box::new(tokio::io::empty()),
    })))
}

/// Opens the real session, projection and coordinator. Only the page
/// mechanics are scripted; `submitForm` is consequential and needs approval.
pub(crate) async fn open_browser(
    root: &Path,
    ledger: Arc<Mutex<Ledger>>,
    dispatched: Arc<Mutex<Vec<Value>>>,
    read_model: Arc<MaterializedReadModel>,
) -> (BrowserProjection, BrowserCommandCoordinator) {
    let session = live::BrowserSessionId::parse(BROWSER).unwrap();
    let scanner = root.join("scanner");
    std::fs::write(&scanner, "#!/bin/sh\nexit 0\n").unwrap();
    std::fs::set_permissions(&scanner, std::fs::Permissions::from_mode(0o700)).unwrap();
    let staging = root.join("staging");
    std::fs::create_dir(&staging).unwrap();
    std::fs::set_permissions(&staging, std::fs::Permissions::from_mode(0o700)).unwrap();
    let bus = odin_process::BusAddress::unix_socket(root.join("stop.sock")).unwrap();
    let stop_host = BrowserStopHost {
        authority: Arc::new(odin_kernel::StopAuthority::new(
            Arc::clone(&ledger),
            odin_process::WorkerChannel::for_recovery(bus).unwrap(),
        )),
        tx_id: "odintx".to_owned(),
        wp_id: "browser".to_owned(),
        attempt: 1,
        worker_binding: odin_process::RegisteredServiceBinding::new(
            scanner.clone(),
            blake3::hash(&std::fs::read(&scanner).unwrap())
                .to_hex()
                .to_string(),
        )
        .unwrap(),
    };
    let gate = Arc::new(BrowserSafetyGate::new(
        ProtectedValues::new(vec![ProtectedValue::new(
            "fixture",
            b"never-typed-fixture-secret".to_vec(),
        )])
        .unwrap(),
        Box::new(
            ExecutableMalwareScanner::new(scanner, Vec::<String>::new(), stop_host.clone())
                .unwrap(),
        ),
    ));
    let policy = BrowserPolicySnapshot::initial(
        session,
        BTreeMap::from([(
            StructuralAction::SubmitForm,
            ActionRule {
                capability_id: CapabilityId::new("browser.consequential").unwrap(),
                capability_version: 1,
                effect_class: EffectClass::R3,
                approval_required: true,
            },
        )]),
    )
    .unwrap();
    let artifacts = Arc::new(
        FsPublishedArtifactStore::open(
            root.join("published"),
            live::LiveSessionId::parse(VEHICLE).unwrap(),
            LaneId::new("file.out").unwrap(),
            LaneId::new("render.out").unwrap(),
        )
        .unwrap(),
    );
    let publisher: Arc<dyn odin_browser::ArtifactPublisher> = artifacts.clone();
    let opened = BrowserSession::open_relayed(
        RelayedWorkerLaunch {
            relay: scripted_worker(dispatched),
            paths: RelayedWorkerPaths::for_session(
                Path::new("/state"),
                &session,
                "/odin/lib/playwright-core".to_owned(),
                "/odin/bin/chromium".to_owned(),
            ),
            viewport: odin_browser::config::Viewport::default(),
            limits: odin_browser::config::ResourceLimits::default(),
            startup: Duration::from_secs(10),
            command: Duration::from_secs(10),
            shutdown: Duration::from_secs(5),
            takeover_lease: Duration::from_secs(60),
            download_staging_root: staging.canonicalize().unwrap(),
            identity: "pod:browser-batch".to_owned(),
            navigate_hosts: None,
        },
        stop_host,
        policy,
        gate,
        FrameWiring {
            stream_id: live::pod_browser_stream_id(&session),
            limits: odin_browser::config::FrameLimits::default(),
            publisher,
            stream: false,
        },
        SessionLimits {
            read: Duration::from_secs(10),
            preflight: Duration::from_secs(10),
            dispatch: Duration::from_secs(10),
            max_screenshot_bytes: 1 << 20,
        },
        Arc::clone(&ledger),
    )
    .await
    .expect("the relayed browser session opens");
    let replay = DurableReplayStore::open(root.join("replay.sqlite3"), 256, 1 << 20).unwrap();
    let projection = BrowserProjection::spawn(
        opened,
        Arc::clone(&read_model),
        Arc::new(BoundedMultiplexer::new(replay, 64, 64)),
        artifacts,
        Arc::new(FsExternalContentIndex::open(root.join("content")).unwrap()),
        BrowserProjectionConfig {
            command_capacity: NonZeroUsize::new(16).unwrap(),
            max_timeline_records: NonZeroUsize::new(64).unwrap(),
            max_timeline_bytes: NonZeroUsize::new(1 << 20).unwrap(),
        },
    );
    let coordinator = BrowserCommandCoordinator::new(
        ledger,
        read_model,
        projection.handle(),
        NonZeroUsize::new(8).unwrap(),
    );
    (projection, coordinator)
}
