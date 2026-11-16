//! Service pump arming: the artifact egress lane pumps and the
//! long-running Hermes, kube watch, and fleet host-liveness pumps armed
//! before the serving loop selects.

use std::sync::Arc;
use std::time::Duration as StdDuration;

use futures_util::StreamExt as _;

use odin_domain::IncidentId;
use odin_huginn::incidents::{
    IncidentProjection, IncidentSeverityView, IncidentStatusView, IncidentView,
};
use odin_huginn::NodePosture;
use serde_json::json;

use odin_registry::{ObjectConfig, RegistryKind, SnapshotHandle};

use crate::kube::{kube_reconcile_tick, KubeRuntimeCell};

/// How often the status, gateway, device and render pumps look again.
const POLL_TICK: StdDuration = StdDuration::from_secs(5);
/// How often the kube watch and durable feed pumps look again.
const WATCH_TICK: StdDuration = StdDuration::from_secs(2);
/// How often a healthy Job watch sweeps finished-run residue. Watch events mark and reap runs as
/// they finish; the sweep only deletes Jobs past their day of grace and day-old stray policies.
const RESIDUE_SWEEP: StdDuration = StdDuration::from_secs(600);
/// The brain warm pump's next look while stores still have rows to warm, and once all are warm.
const BRAIN_WARM_BUSY: StdDuration = StdDuration::from_secs(1);
const BRAIN_WARM_IDLE: StdDuration = StdDuration::from_secs(60);

/// An interval that waits out a slow pass instead of bursting to catch up.
fn delayed_ticker(period: StdDuration) -> tokio::time::Interval {
    let mut ticker = tokio::time::interval(period);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    ticker
}

/// Arms the fleet host-liveness pump: on startup, on every
/// [`odin_huginn::fleet::FLEET_REFRESH_INTERVAL`] tick, and on every registry
/// revision watch fire, it pins the registry snapshot, captures the shared
/// read model (kube node/workload facts and live sessions), probes every
/// enabled+enrolled declared host CONCURRENTLY (each probe individually
/// timeout-bounded: the tailnet TCP dial and the zellij session listing run
/// as one concurrent fan-out), projects the fleet objects through
/// `project_fleet`, and lands each changed object via `upsert_indexed`.
/// Never panics on probe failure: every probe failure is a typed
/// `Reachability` or `ZellijSessions`, and a failed pass logs and retries
/// on the next trigger.
pub(super) fn arm_fleet(
    pumps: &mut tokio::task::JoinSet<Result<(), String>>,
    snapshot_handle: Arc<SnapshotHandle>,
    read_model: Arc<odin_huginn::read_model::MaterializedReadModel>,
    probe: Arc<dyn odin_huginn::fleet::FleetProbe>,
    zellij: Arc<dyn odin_huginn::fleet::FleetZellijProbe>,
) {
    pumps.spawn(async move {
        let mut ticker = delayed_ticker(odin_huginn::fleet::FLEET_REFRESH_INTERVAL);
        let mut registry_revisions = snapshot_handle.subscribe();
        // Cross-pass memory owned by this pump: last-seen stamps advance
        // only while a host proves alive and are preserved across offline
        // passes (daemon restarts restart the memory with the daemon).
        let mut last_seen = std::collections::BTreeMap::new();
        loop {
            tokio::select! {
                _ = ticker.tick() => {}
                _ = registry_revisions.changed() => {}
            }
            if let Err(error) = fleet_tick(
                &snapshot_handle,
                &read_model,
                probe.as_ref(),
                zellij.as_ref(),
                &mut last_seen,
            )
            .await
            {
                tracing::error!("fleet pump pass failed: {error}");
            }
        }
    });
}

/// One fleet observation pass: registry pin, read-model capture, concurrent
/// bounded probes, projection, and per-object indexed upserts. An object
/// whose payload did not change is skipped by the producer (no revision
/// movement, no downstream rebuild wake); a typed upsert failure is logged
/// with its object id and never takes the pass or the daemon down.
async fn fleet_tick(
    snapshot_handle: &SnapshotHandle,
    read_model: &Arc<odin_huginn::read_model::MaterializedReadModel>,
    probe: &dyn odin_huginn::fleet::FleetProbe,
    zellij: &dyn odin_huginn::fleet::FleetZellijProbe,
    last_seen: &mut std::collections::BTreeMap<String, time::OffsetDateTime>,
) -> Result<(), String> {
    use odin_domain::huginn::ObjectKind;
    use odin_huginn::fleet::{
        probe_hosts, probe_zellij_sessions, project_fleet, FleetKubeState, FleetSessionCounts,
    };

    let registry = snapshot_handle.current();
    let capture = read_model
        .capture_kinds(&[
            ObjectKind::Node,
            ObjectKind::KubeResource,
            ObjectKind::Session,
            ObjectKind::FleetHost,
            ObjectKind::FleetPlacement,
        ])
        .map_err(|error| format!("read-model capture failed: {error}"))?;
    let kube = FleetKubeState::from_capture(&capture);
    let sessions = FleetSessionCounts::from_capture(&capture);
    let mut current = std::collections::BTreeMap::new();
    for object in &capture.objects {
        if matches!(
            object.object.kind,
            ObjectKind::FleetHost | ObjectKind::FleetPlacement
        ) {
            current.insert(object.object.id.clone(), object.clone());
        }
    }
    // Probe inputs derive ONLY from the declarations: one entry per
    // enabled+enrolled host, with its declared tailscale name and the first
    // declared gateway endpoint of its enabled nodes.
    let inputs: Vec<_> = registry
        .listed_objects(RegistryKind::Host)
        .filter_map(|object| {
            let ObjectConfig::Host(host) = &object.config else {
                return None;
            };
            if !(host.enabled && host.enrolled) {
                return None;
            }
            let endpoint = registry
                .listed_objects(RegistryKind::Node)
                .filter_map(|node| match &node.config {
                    ObjectConfig::Node(node) => Some(node),
                    _ => None,
                })
                .find(|node| node.enabled && node.host == object.id)
                .and_then(|node| node.gateway_endpoint.clone());
            Some((object.id.clone(), host.tailscale.clone(), endpoint))
        })
        .collect();
    // The tailnet TCP dial and the zellij session listing are one
    // concurrent fan-out over the same declared inputs — never two serial
    // passes and never a serial wait per host.
    let (mut probes, zellij_sessions) = tokio::join!(
        probe_hosts(probe, inputs.clone()),
        probe_zellij_sessions(
            zellij,
            inputs
                .into_iter()
                .map(|(host, tailscale, _endpoint)| (host, tailscale)),
        )
    );
    answered_over_ssh(&mut probes, &zellij_sessions);
    let observed_at = time::OffsetDateTime::now_utc();
    for projection in project_fleet(
        &registry,
        odin_huginn::fleet::FleetObservation {
            probes: &probes,
            zellij: &zellij_sessions,
            kube: &kube,
            sessions: sessions.as_ref(),
            observed_at,
        },
        last_seen,
        &current,
    ) {
        if let Err(error) = read_model.upsert_indexed(projection.snapshot, projection.metadata) {
            tracing::error!("fleet projection rejected: {error}");
        }
    }
    Ok(())
}

/// Successful SSH proves reachability even when the gateway firewall admits only pods.
pub(super) fn answered_over_ssh(
    probes: &mut std::collections::BTreeMap<String, odin_huginn::fleet::Reachability>,
    zellij: &std::collections::BTreeMap<String, odin_huginn::fleet::ZellijSessions>,
) {
    for (host, sessions) in zellij {
        if matches!(sessions, odin_huginn::fleet::ZellijSessions::Live(_)) {
            probes.insert(host.clone(), odin_huginn::fleet::Reachability::Reachable);
        }
    }
}

/// Arms the artifact egress lane pumps for the enabled runtime lanes. Every
/// lane artifact is consumed by a MUTATING pump: `OmpLiveService::register_egress`
/// writes durable transfer records and appends `ArtifactPublished` to the
/// session actor log. A demoted node arms nothing — egress lanes derive
/// from config-bound seats' live contracts, and the follower design keeps
/// every authority surface absent — so the follower logs one disarm line
/// and returns; no lane stream is opened and no durable live-transfer
/// state can be written here.
pub(super) async fn arm_egress_lane_pumps(
    pumps: &mut tokio::task::JoinSet<Result<(), String>>,
    lane_artifacts: &odin_omp::live::lane_artifacts::LaneTransferBridge,
    omp: &Arc<odin_omp::live::service::OmpLiveService>,
    lanes: std::collections::BTreeSet<odin_domain::LaneId>,
    posture: NodePosture,
) -> Result<(), String> {
    if posture == NodePosture::Follower {
        tracing::warn!(
            "follower posture: artifact egress lanes stay disarmed; no egress \
             registration or ArtifactPublished from this node"
        );
        return Ok(());
    }
    for lane in lanes {
        let mut stream = lane_artifacts
            .subscribe_egress(&lane)
            .await
            .map_err(|error| error.to_string())?;
        let service = Arc::clone(omp);
        pumps.spawn(async move {
            while let Some(artifact) = stream.next().await {
                service
                    .register_egress(artifact.map_err(|error| error.to_string())?)
                    .await
                    .map_err(|error| error.to_string())?;
            }
            Err::<(), String>(format!("artifact egress lane {lane} closed"))
        });
    }
    Ok(())
}
/// Arms the Hermes gateway/egress/reconcile pumps and the kube watch pump
/// after artifact egress registration succeeds, before the serving loop selects.
pub(super) fn arm_service_pumps(
    pumps: &mut tokio::task::JoinSet<Result<(), String>>,
    posture: NodePosture,
    hermes_runtime: &Option<Arc<odin_hermes::runtime::HermesRuntime>>,
    kube_cell: &Option<Arc<KubeRuntimeCell>>,
    read_model: &Arc<odin_huginn::read_model::MaterializedReadModel>,
) {
    let hermes_armed = match (hermes_runtime, posture) {
        (Some(runtime), NodePosture::Authoritative) => Some(Arc::clone(runtime)),
        (Some(_), NodePosture::Follower) => {
            tracing::warn!(
                "follower posture: hermes gateway/egress/reconcile pumps stay \
                     disarmed; no external intake"
            );
            None
        }
        (None, _) => None,
    };
    if let Some(runtime) = &hermes_armed {
        // The status pump also delivers durable owner questions; sending can block.
        if let Some(discord) = runtime.settings().discord.as_ref() {
            let capacity = discord.egress_capacity;
            let runtime = Arc::clone(runtime);
            pumps.spawn(async move {
                let mut ticker = delayed_ticker(POLL_TICK);
                loop {
                    ticker.tick().await;
                    match tokio::task::spawn_blocking({
                        let runtime = Arc::clone(&runtime);
                        move || runtime.pump_status_egress(capacity)
                    })
                    .await
                    {
                        Ok(Ok(_)) => {}
                        Ok(Err(error)) => {
                            tracing::error!("odin-hermes egress pump failed: {error}")
                        }
                        Err(error) => {
                            tracing::error!("odin-hermes egress pump task failed: {error}")
                        }
                    }
                }
            });
        } else {
            // Without `[hermes.discord]` the runtime composes no notify
            // bridge; the typed absence would only repeat forever.
            tracing::warn!("hermes discord surface not configured: status egress pump disarmed");
        }
        // Intent reconcilers: the gated (R3) leg settles terminal
        // kernel decisions exactly once through the ingress gate, and
        // the admitted (R1) leg drives every owner DM through the
        // bound conversation route to its natural answer. Admission
        // wakes this worker immediately; the periodic tick remains only
        // the durable crash-recovery sweep. Both routes may block on the
        // answer bound, so they run on the blocking pool — never a
        // runtime worker.
        {
            let runtime = Arc::clone(runtime);
            pumps.spawn(async move {
                let mut ticker = delayed_ticker(odin_hermes::runtime::RECONCILE_TICK);
                // One DM catch-up pass when the conversation vehicle first
                // becomes ready (the approved-intent route binds): a DM
                // fetched while the vehicle was still opening admits
                // durably either way, and this pass closes any remaining
                // fetch gap before the reconciler drains.
                let mut caught_up_on_vehicle_ready = false;
                loop {
                    // A due reminder fires when it comes due, not at the
                    // next tick.
                    let due_in = tokio::task::spawn_blocking({
                        let runtime = Arc::clone(&runtime);
                        move || runtime.schedule_due_in()
                    })
                    .await
                    .ok()
                    .flatten()
                    .unwrap_or(odin_hermes::runtime::RECONCILE_TICK);
                    tokio::select! {
                        _ = ticker.tick() => {}
                        _ = runtime.wait_for_reconcile_wake() => {}
                        _ = tokio::time::sleep(due_in) => {}
                    }
                    if !caught_up_on_vehicle_ready && runtime.approved_route_bound() {
                        if let Err(error) = runtime.catch_up_owner_dms().await {
                            tracing::error!("odin-hermes DM catch-up failed: {error}");
                        } else {
                            caught_up_on_vehicle_ready = true;
                        }
                    }
                    let gated = tokio::task::spawn_blocking({
                        let runtime = Arc::clone(&runtime);
                        move || runtime.reconcile_gated_tasks()
                    })
                    .await
                    .map_err(|error| error.to_string())
                    .and_then(|result| result.map_err(|error| error.to_string()));
                    if let Err(error) = gated {
                        tracing::error!("odin-hermes gated reconcile failed: {error}");
                    }
                    let admitted = tokio::task::spawn_blocking({
                        let runtime = Arc::clone(&runtime);
                        move || runtime.reconcile_admitted_intents()
                    })
                    .await
                    .map_err(|error| error.to_string())
                    .and_then(|result| result.map_err(|error| error.to_string()));
                    if let Err(error) = admitted {
                        tracing::error!("odin-hermes admitted reconcile failed: {error}");
                    }
                    // Due reminders and wakes fire after the owner's own
                    // intents, on the same serialized loop.
                    let scheduled = tokio::task::spawn_blocking({
                        let runtime = Arc::clone(&runtime);
                        move || runtime.reconcile_schedule()
                    })
                    .await
                    .map_err(|error| error.to_string())
                    .and_then(|result| result);
                    if let Err(error) = scheduled {
                        tracing::error!("odin-hermes schedule reconcile failed: {error}");
                    }
                    // Due routines queue their rows for the next pass.
                    let routines = tokio::task::spawn_blocking({
                        let runtime = Arc::clone(&runtime);
                        move || runtime.reconcile_routines()
                    })
                    .await
                    .map_err(|error| error.to_string())
                    .and_then(|result| result);
                    if let Err(error) = routines {
                        tracing::error!("odin-hermes routine reconcile failed: {error}");
                    }
                }
            });
        }
        // Keep one Discord gateway consumer per token; retry terminal failures on later ticks.
        if let Some(gateway) = runtime.gateway().clone() {
            if gateway.credential_absent() {
                // Declared absence is composed, typed state, not a
                // transient failure: the listener stays disarmed (one
                // line, like the status egress pump) and the daemon keeps
                // serving every other surface.
                tracing::warn!(
                    "odin-hermes discord surface declared absent: gateway listener disarmed; restart after credentials are provisioned"
                );
            } else {
                // Fatal close: one Huginn incident alert, then the park
                // — the listener never retries.
                let intake = Arc::new(odin_hermes::runtime::GatewayIntake::new(Arc::clone(
                    runtime,
                )));
                let runtime_for_pump = Arc::clone(runtime);
                let read_model = Arc::clone(read_model);
                pumps.spawn(gateway_listener_pump(
                    intake,
                    runtime_for_pump,
                    read_model,
                    gateway,
                    POLL_TICK,
                ));
            }
        }
    }
    if let Some(cell) = kube_cell.as_ref() {
        let cell = Arc::clone(cell);
        let read_model = Arc::clone(read_model);
        pumps.spawn(async move {
            let mut ticker = delayed_ticker(KUBE_INVENTORY_EVERY);
            let mut log = WatchLog::default();
            loop {
                ticker.tick().await;
                match cell.parts().await {
                    Ok((control, client)) => {
                        let ended =
                            kube_inventory_watch(&control, client, &read_model, &mut log).await;
                        log.note(format!("inventory watch closed: {ended}"));
                    }
                    Err(error) => log.note(format!("cluster unreachable: {error}")),
                }
            }
        });
    }
    if let Some(cell) = kube_cell.as_ref() {
        let cell = Arc::clone(cell);
        let read_model = Arc::clone(read_model);
        pumps.spawn(async move {
            // Watched-observation loop over the real Api watch: typed
            // Job observations flow through the shared ordinal ingest
            // and the same replace-delta route as every other surface.
            // A stream that ends (relist expiry) or fails re-opens a
            // fresh watch on the next bounded tick; an unavailable API
            // server retries without ever taking the daemon down.
            let mut ticker = delayed_ticker(WATCH_TICK);
            let mut sweep = delayed_ticker(RESIDUE_SWEEP);
            let mut log = WatchLog::default();
            loop {
                ticker.tick().await;
                let (control, client) = match cell.parts().await {
                    Ok(parts) => parts,
                    Err(error) => {
                        log.note(format!("cluster unreachable: {error}"));
                        continue;
                    }
                };
                // One posture-gated reconcile pass: journal recovery
                // (cluster-mutating replay) runs only on the snapshot
                // authority; observation stays live everywhere.
                kube_reconcile_tick(posture, &control, &mut log).await;
                pod_recovery_tick(posture, &cell, &mut log).await;
                let mut stream = match odin_kube::watch::job_observations(client, cell.job_cache().clone()).await {
                    Ok(stream) => stream,
                    Err(error) => {
                        log.note(format!("watch not opened: {error}"));
                        continue;
                    }
                };
                tracing::info!("kube watch opened");
                let mut events = 0_u64;
                let mut ended = "the stream ended".to_owned();
                loop {
                    let item = tokio::select! {
                        item = stream.next() => match item {
                            Some(item) => item,
                            None => break,
                        },
                        _ = ticker.tick() => {
                            pod_recovery_tick(posture, &cell, &mut log).await;
                            continue;
                        }
                        _ = sweep.tick() => {
                            // A healthy watch never returns to the pre-watch sweep.
                            if posture == NodePosture::Authoritative {
                                if let Err(error) =
                                    control.reconciler().reap_marked_residue(time::OffsetDateTime::now_utc()).await
                                {
                                    log.note(format!("finished-run cleanup failed: {error}"));
                                }
                            }
                            continue;
                        }
                    };
                    events += 1;
                    match item {
                        Ok(odin_kube::watch::KubeJobWatchEvent::Applied(observation)) => {
                            let seen = (*observation).clone();
                            if posture == NodePosture::Authoritative {
                                if let Err(error) =
                                    control.reconciler().note_watched_job(&seen).await
                                {
                                    log.note(format!("finished mark failed: {error}"));
                                }
                            }
                            match control.observe(vec![*observation]).await {
                                Ok(deltas) => log.apply(&read_model, &control, deltas).await,
                                Err(error) => {
                                    log.refused_observation(posture, &control, &seen, &error)
                                        .await;
                                }
                            }
                        }
                        Ok(odin_kube::watch::KubeJobWatchEvent::Deleted(deleted)) => {
                            // The Job object leaving the API never proves pods
                            // are gone — that stays behind StopAuthority. The
                            // claim, policy, and maps are this run's residue
                            // and follow the deletion event.
                            let label = deleted.run_label.clone();
                            match control.retire(deleted.resource).await {
                                Ok(delta) => log.apply(&read_model, &control, delta).await,
                                Err(error) => log.note(format!("retirement refused: {error}")),
                            }
                            if posture == NodePosture::Authoritative {
                                if let Err(error) = control
                                    .reconciler()
                                    .reap_watched_deletion(label.as_deref())
                                    .await
                                {
                                    log.note(format!("residue cleanup failed: {error}"));
                                }
                            }
                        }
                        Ok(odin_kube::watch::KubeJobWatchEvent::Listed(listed)) => {
                            match control.retire_unlisted(&listed).await {
                                Ok(deltas) => log.apply(&read_model, &control, deltas).await,
                                Err(error) => log.note(format!("retirement refused: {error}")),
                            }
                        }
                        // A Job whose binding fails validation is one bad
                        // object, not a broken watch: note it and go on.
                        Err(odin_kube::KubeError::Rejected { reason }) => {
                            log.note(format!("observation rejected: {reason}"));
                        }
                        // Dropped watch or unavailable server: the outer
                        // loop reconciles via an authoritative relist and
                        // re-opens a fresh watch.
                        Err(error) => {
                            ended = error.to_string();
                            break;
                        }
                    }
                }
                tracing::info!("kube watch closed events={events} reason={ended}");
            }
        });
    }
}

async fn pod_recovery_tick(posture: NodePosture, cell: &KubeRuntimeCell, log: &mut WatchLog) {
    if posture != NodePosture::Authoritative {
        return;
    }
    let _lifecycle = match cell.pod_lifecycle().await {
        Ok(guard) => guard,
        Err(error) => {
            log.note(format!("pod worker startup recovery failed: {error}"));
            return;
        }
    };
    match cell.stop_authority().recover_pending_pod_stops() {
        Ok(outcomes) => {
            for outcome in outcomes {
                if outcome.verdict != odin_domain::StopVerdictTag::Stopped {
                    log.note(format!(
                        "pod worker cleanup pending worker={} missing={}",
                        outcome.worker_id,
                        outcome
                            .evidence
                            .missing
                            .as_deref()
                            .unwrap_or("absence unproven")
                    ));
                }
            }
        }
        Err(error) => log.note(format!("pod worker recovery failed: {error}")),
    }
}

/// Watch inventory changes without waiting for relists; return why either watch ended.
async fn kube_inventory_watch(
    control: &odin_huginn::kube::KubeControl,
    client: odin_kube::KubeClient,
    read_model: &Arc<odin_huginn::read_model::MaterializedReadModel>,
    log: &mut WatchLog,
) -> String {
    let mut nodes = match odin_kube::watch::node_inventory(client.clone()).await {
        Ok(stream) => stream,
        Err(error) => return format!("node watch not opened: {error}"),
    };
    let mut foreign = match odin_kube::watch::foreign_inventory(client).await {
        Ok(stream) => stream,
        Err(error) => return format!("foreign watch not opened: {error}"),
    };
    tracing::info!("kube inventory watch opened");
    loop {
        tokio::select! {
            item = nodes.next() => match item {
                Some(Ok(views)) => match control.observe_nodes(views).await {
                    Ok(deltas) => log.apply(read_model, control, deltas).await,
                    Err(error) => log.note(format!("node observation refused: {error}")),
                },
                Some(Err(error)) => return format!("node watch: {error}"),
                None => return "the node watch ended".to_owned(),
            },
            item = foreign.next() => match item {
                Some(Ok(event)) => match control.apply_foreign(event).await {
                    Ok(deltas) => log.apply(read_model, control, deltas).await,
                    Err(error) => log.note(format!("foreign observation refused: {error}")),
                },
                Some(Err(error)) => return format!("foreign watch: {error}"),
                None => return "the foreign watch ended".to_owned(),
            },
        }
    }
}

/// The kube observation pump's diagnostics: a failure is logged when it
/// first appears or changes, never once per two-second tick, and never
/// swallowed.
#[derive(Default)]
pub(super) struct WatchLog {
    last: Option<String>,
    /// Jobs whose observation this authority refused, with the reason: a
    /// Job it never registered (a disposable integration-suite Job, residue
    /// from an earlier authority's ledger) is refused on every relist and
    /// every status event, so it is said once per Job and reason.
    refused: std::collections::BTreeMap<String, String>,
    /// Orphan Jobs this daemon already deleted (their deletion event and
    /// relists may still show them once).
    collected: std::collections::BTreeSet<String>,
}

impl WatchLog {
    pub(super) fn refused(&mut self, job: &str, reason: &str) {
        if self.refused.get(job).map(String::as_str) != Some(reason) {
            tracing::error!("kube watch observation of {job} refused: {reason}");
            self.refused.insert(job.to_owned(), reason.to_owned());
        }
    }

    /// A refused observation: an abandoned orphan Job (Odin-labelled, run
    /// unknown to this authority) is collected once by the authority with
    /// one line; anything else is said once per Job and reason.
    pub(super) async fn refused_observation(
        &mut self,
        posture: NodePosture,
        control: &odin_huginn::kube::KubeControl,
        observation: &odin_kube::JobObservation,
        error: &odin_domain::huginn::HuginnProtocolError,
    ) {
        let job = observation.workload.resource.name.as_str();
        if self.collected.contains(job) {
            return;
        }
        if posture != NodePosture::Authoritative {
            self.refused(job, &error.to_string());
            return;
        }
        match control.collect_orphan(observation).await {
            Ok(odin_kube::OrphanVerdict::Collect) => {
                tracing::info!(
                    "kube orphan job={job} run={} state={:?} collected: an Odin Job this authority never registered, abandoned",
                    observation.projection.labels.run_id, observation.workload.state
                );
                self.refused.remove(job);
                self.collected.insert(job.to_owned());
            }
            Ok(odin_kube::OrphanVerdict::NotDue) => self.refused(
                job,
                &format!("{error} (orphan: collected once ended 1 h or started 24 h ago)"),
            ),
            Ok(odin_kube::OrphanVerdict::Registered) => self.refused(job, &error.to_string()),
            Err(collect) => {
                self.refused(
                    job,
                    &format!("{error} (orphan collection failed: {collect})"),
                );
            }
        }
    }

    pub(super) fn note(&mut self, failure: String) {
        if self.last.as_deref() != Some(failure.as_str()) {
            tracing::info!("kube watch {failure}");
            self.last = Some(failure);
        }
    }

    /// Publishes observation deltas to the read model behind every delta
    /// the control buffered (create, summarize, operate). A revision gap
    /// resyncs that object from the catalog and says so once; a refusal no
    /// resync repairs is noted.
    pub(super) async fn apply(
        &mut self,
        read_model: &odin_huginn::read_model::MaterializedReadModel,
        control: &odin_huginn::kube::KubeControl,
        deltas: impl IntoIterator<Item = odin_domain::huginn::ObjectDelta>,
    ) {
        for note in control.publish(read_model, deltas).await {
            match note {
                odin_huginn::kube::DeltaPublication::Resynced {
                    object_id,
                    from,
                    delta_from,
                    to,
                } => tracing::info!(
                    "kube watch resynced object={object_id} from={} delta_from={} to={}",
                    from.map_or_else(|| "none".to_owned(), |revision| revision.to_string()),
                    delta_from,
                    to
                ),
                odin_huginn::kube::DeltaPublication::Refused { object_id, reason } => self.note(
                    format!("read model refused a delta for {object_id}: {reason}"),
                ),
            }
        }
    }
}

/// The Hermes gateway listener pump: one bounded dial per tick. A fatal
/// close (reconnect=false) is the one terminal outcome — one Huginn
/// incident alert, then this task parks forever (a completed pump is the
/// serving select's own terminal, so the park keeps every other surface
/// serving) and stays cancellable by the owning shutdown.
async fn gateway_listener_pump(
    intake: Arc<dyn odin_hermes::discord::DiscordIngressSink>,
    runtime: Arc<odin_hermes::runtime::HermesRuntime>,
    read_model: Arc<odin_huginn::read_model::MaterializedReadModel>,
    gateway: Arc<odin_hermes::discord::DiscordGateway>,
    period: StdDuration,
) -> Result<(), String> {
    let mut ticker = delayed_ticker(period);
    loop {
        ticker.tick().await;
        // Reconnect catch-up BEFORE each dial (startup and every reconnect
        // after a session ends): Discord's gateway never replays the
        // MESSAGE_CREATE events a down or starting authority missed, so
        // the bounded history backfill since the durable intake cursor is
        // the only recovery path. The fetch admits through the same
        // intake path as live messages; idempotency makes it replay-safe.
        if let Err(error) = runtime.catch_up_owner_dms().await {
            tracing::error!("odin-hermes DM catch-up failed: {error}");
        }
        if let Err(error) = gateway
            .run(
                Arc::clone(&intake),
                odin_hermes::discord::ReconnectPolicy::bounded(),
            )
            .await
        {
            if let odin_hermes::discord::DiscordSendError::GatewayFatalClose { code, reason } =
                &error
            {
                tracing::error!("odin-hermes gateway closed fatally: {error}");
                tracing::warn!(
                    "odin-hermes: fatal Discord gateway close — fix the \
                     declared gateway configuration indicated by the cause, \
                     then restart odind; the gateway listener stays down \
                     without retrying"
                );
                if let Err(alert_error) =
                    publish_gateway_fatal_close_incident(&read_model, *code, reason)
                {
                    tracing::error!(
                        "odin-hermes: the fatal-close Huginn incident could not be \
                         published: {alert_error}"
                    );
                }
                // The park: forever-pending, cancellable at each await by
                // the owning shutdown, never resolving back into this loop.
                loop {
                    std::future::pending::<()>().await;
                }
            }
            tracing::warn!("odin-hermes gateway listener ended: {error}; retrying");
        }
    }
}

/// The typed failures of the fatal-close owner alert.
#[derive(Debug, thiserror::Error)]
enum FatalCloseAlertError {
    #[error("the fatal-close incident identity is invalid: {0}")]
    IncidentIdentity(#[from] odin_domain::DomainError),
    #[error("the incident projection refused the fatal-close card: {0}")]
    Projection(#[from] odin_domain::huginn::HuginnProtocolError),
}

/// Composes the fatal-close incident card and projects it onto the
/// served read model. The identity is scoped to this gateway incarnation
/// (fresh identity prevents reopening prior incidents) and the arm parks after
/// one publish, so no prior card is ever consulted and a terminal card
/// is never reopened. The typed wire cause travels verbatim in the
/// deviation and observed state; the escalation target is the recovery
/// driver's operator identity (`seat:operator`).
fn publish_gateway_fatal_close_incident(
    read_model: &Arc<odin_huginn::read_model::MaterializedReadModel>,
    code: u16,
    reason: &str,
) -> Result<(), FatalCloseAlertError> {
    let observed_at = time::OffsetDateTime::now_utc();
    let incident_id = IncidentId::from_parts(
        "incident",
        crate::incidents::unix_ms(observed_at),
        uuid::Uuid::new_v4(),
    )?;
    let view = IncidentView {
        incident_id,
        run_id: None,
        severity: IncidentSeverityView::Critical,
        confidence_micros: 1_000_000,
        deviation: format!(
            "The Discord gateway closed fatally with close code {code}: {reason}. \
             The gateway listener is down and will not retry."
        ),
        failure_signature: "hermes.discord.gateway.fatal-close".to_owned(),
        expected_state: json!({ "gateway": "serving" }),
        observed_state: json!({
            "close": { "code": code, "reason": reason },
            "reconnect": false,
        }),
        affected_objects: vec!["hermes.discord.gateway".to_owned()],
        evidence_refs: vec!["odind:hermes-gateway-listener".to_owned()],
        allowed_capabilities: Vec::new(),
        attempt_ids: Vec::new(),
        recommended_next_action: "Fix the declared gateway configuration the close code \
             names, then restart odind; every other surface keeps serving."
            .to_owned(),
        escalation_target: crate::incidents::OPERATOR_ESCALATION.to_owned(),
        first_observed_at: observed_at,
        last_observed_at: observed_at,
        last_useful_progress_at: None,
        status: IncidentStatusView::Open,
        revision: 1,
    };
    IncidentProjection::new(Arc::clone(read_model))
        .publish(view, [], [])
        .map(|_| ())
        .map_err(FatalCloseAlertError::from)
}

/// Per-device activity and revocation redrive: every 5 s the paired
/// devices' last authentication and open-connection count are re-published
/// into the read model (`odin huginn devices list`), revocations a crash
/// interrupted are finished (grants ledger-revoked, record finalized,
/// live streams closed), and already-revoked devices this process still
/// serves are cut. An unchanged device is a no-op.
pub(super) fn arm_device_activity_pump(
    pumps: &mut tokio::task::JoinSet<Result<(), String>>,
    (devices, connections): (
        Arc<odin_huginn::devices::SqliteDeviceTrustStore>,
        odin_huginn::ConnectionRegistry,
    ),
    read_model: Arc<odin_huginn::read_model::MaterializedReadModel>,
    admin: Arc<odin_huginn::devices::DeviceAdmin<odin_huginn::devices::SqliteDeviceTrustStore>>,
    ledger: Arc<std::sync::Mutex<odin_ledger::Ledger>>,
) {
    pumps.spawn(async move {
        let mut ticker = delayed_ticker(POLL_TICK);
        loop {
            ticker.tick().await;
            if let Err(error) = odin_huginn::devices::publish_device_activity(
                devices.as_ref(),
                &connections,
                &read_model,
                time::OffsetDateTime::now_utc(),
            )
            .await
            {
                tracing::error!("device activity publication failed: {error}");
            }
            odin_cli::authority_provision::redrive_device_revocations(
                admin.as_ref(),
                devices.as_ref(),
                &connections,
                Arc::clone(&ledger),
            )
            .await;
        }
    });
}

/// Render metadata: every 5 s each render job's status,
/// renderer and output manifest is re-published into the read model
/// (`odin huginn render list`); an unchanged job is a no-op.
pub(super) fn arm_render_pump(
    pumps: &mut tokio::task::JoinSet<Result<(), String>>,
    renders: Arc<odin_huginn::HuginnRenderService>,
    read_model: Arc<odin_huginn::read_model::MaterializedReadModel>,
) {
    pumps.spawn(async move {
        let mut ticker = delayed_ticker(POLL_TICK);
        loop {
            ticker.tick().await;
            if let Err(error) = renders.publish_jobs(&read_model, time::OffsetDateTime::now_utc()) {
                tracing::error!("render publication failed: {error}");
            }
        }
    });
}

/// Arms the durable-feeds pump: the bounded roster/session projection, the
/// per-session durable agent-events producer, and the durable approval
/// cursor consumer. Authoritative posture only — a follower serves no seats
/// and its read model stays registry-seeded. The pump's tick performs only
/// bounded source reads: one roster snapshot, at most one history page per
/// live session, and at most one approval-feed page.
pub(super) fn arm_durable_feed_pump(
    pumps: &mut tokio::task::JoinSet<Result<(), String>>,
    posture: NodePosture,
    feed: Arc<odin_huginn::feed::DurableFeedPump>,
) {
    if posture == NodePosture::Follower {
        tracing::warn!("follower posture: durable feed pump stays disarmed; no live projection");
        return;
    }
    pumps.spawn(async move {
        let mut ticker = delayed_ticker(WATCH_TICK);
        loop {
            ticker.tick().await;
            feed.tick().await;
        }
    });
}

/// How long a durable stream may stay quiet before the replay store keeps only its head frame.
const QUIET_STREAM_RETENTION: time::Duration = time::Duration::days(7);

/// Expires quiet replay streams at startup and then daily; each dropped frame's feed payload goes
/// with it (the published store is the replay store's content retirement).
pub(super) fn arm_stream_expiry_pump(
    pumps: &mut tokio::task::JoinSet<Result<(), String>>,
    streams: Arc<odin_huginn::streams::BoundedMultiplexer>,
) {
    pumps.spawn(async move {
        let mut ticker = delayed_ticker(crate::retention::RETENTION_EVERY);
        loop {
            ticker.tick().await;
            let streams = Arc::clone(&streams);
            let cutoff = time::OffsetDateTime::now_utc() - QUIET_STREAM_RETENTION;
            match tokio::task::spawn_blocking(move || streams.expire_quiet_streams(cutoff)).await {
                Ok(Ok((0, _))) => {}
                Ok(Ok((streams, frames))) => tracing::info!(
                    streams,
                    frames,
                    "replay store expired quiet streams down to their head frames"
                ),
                Ok(Err(error)) => tracing::error!("replay stream expiry failed: {error}"),
                Err(error) => tracing::error!("replay stream expiry did not finish: {error}"),
            }
        }
    });
}


/// The pause before node inventory and the foreign mirror re-open their watches.
const KUBE_INVENTORY_EVERY: StdDuration = StdDuration::from_secs(30);

/// Uncached chunks one warm round embeds per seat brain: one request, one
/// text per embedder slot. The CPU embedder runs ~60 tokens/s per slot, so
/// 128 texts took ~70 s against the gateway's 20 s embedding timeout; every
/// round timed out, was retried, and stored nothing.
const BRAIN_WARM_BUDGET: usize = 8;

/// How one seat's failed warm round is reported. A store migration in
/// flight is the expected state while it runs — a warning naming its
/// reason once, then quiet while the reason is unchanged — while every
/// other failure alarms each time it happens.
enum WarmReport {
    /// The seat's store is migrating; `String` is the reason to name once.
    Migrating(String),
    /// The same migration reason was already reported: stay quiet.
    Quiet,
    /// A failure nothing expected explains: an alarm, every time.
    Alarm,
}

fn warm_report(pending: Option<&str>, last_reported: Option<&str>) -> WarmReport {
    match pending {
        Some(reason) if last_reported == Some(reason) => WarmReport::Quiet,
        Some(reason) => WarmReport::Migrating(reason.to_owned()),
        None => WarmReport::Alarm,
    }
}

/// Background brain warm, off every turn path: each round builds moved
/// non-state sources, seals and embeds new generations and retires old
/// ones, each seat through its own declared session lane. Rounds run back
/// to back while anything is pending, then idle to a slow cadence.
pub(super) fn arm_brain_warm_pump(
    pumps: &mut tokio::task::JoinSet<Result<(), String>>,
    targets: Vec<(
        odin_domain::SeatId,
        Arc<odin_brain::service::BrainService>,
        Arc<odin_brain::retrieval::QueryEmbedder>,
    )>,
) {
    if targets.is_empty() {
        return;
    }
    pumps.spawn(async move {
        // Each seat's last reported migration reason: an unchanged reason
        // stays quiet instead of alarming on every round.
        let mut waiting: std::collections::BTreeMap<odin_domain::SeatId, String> =
            std::collections::BTreeMap::new();
        loop {
            let mut pending = 0;
            for (seat, brain, embedder) in &targets {
                let (round, embedder) = (Arc::clone(brain), Arc::clone(embedder));
                match tokio::task::spawn_blocking(move || {
                    round.warm(embedder.as_ref(), BRAIN_WARM_BUDGET)
                })
                .await
                {
                    Ok(Ok(remaining)) => {
                        pending += remaining;
                        waiting.remove(seat);
                    }
                    Ok(Err(error)) => match warm_report(
                        brain.pending_migration().as_deref(),
                        waiting.get(seat).map(String::as_str),
                    ) {
                        WarmReport::Migrating(reason) => {
                            tracing::warn!(
                                "brain warm for seat {seat} waits out a store migration: {reason}"
                            );
                            waiting.insert(seat.clone(), reason);
                        }
                        WarmReport::Quiet => {}
                        WarmReport::Alarm => {
                            waiting.remove(seat);
                            tracing::error!("brain warm for seat {seat} failed: {error}")
                        }
                    },
                    Err(error) => {
                        waiting.remove(seat);
                        tracing::error!("brain warm for seat {seat} did not finish: {error}")
                    }
                }
            }
            tokio::time::sleep(if pending > 0 {
                BRAIN_WARM_BUSY
            } else {
                BRAIN_WARM_IDLE
            })
            .await;
        }
    });
}

#[cfg(test)]
#[path = "tests/pumps.rs"]
mod tests;
