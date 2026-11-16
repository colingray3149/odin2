mod support;

use super::*;

use async_trait::async_trait;
use futures_util::FutureExt;
use odin_domain::huginn::{
    AbortScope, ApprovalDecision, CommandOutcome, CommandReceipt, EventSeq, HistoryQuery,
    LiveCommand, LiveCommandBody, LiveError, LiveEventBody, LiveLaunchOption, LiveMessage,
    LiveSessionState, ModelName, OmpLivePlane, OpenSessionRequest, PermissionDecision,
    PermissionRequestId, ProviderName, SessionEpoch, SessionManifest, SessionStateChanged,
};
use odin_domain::{ApprovalId, EventId, NodeId, SeatId};
use std::num::NonZeroU16;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use tokio::sync::watch;

use self::support::{NullBackend, RecordingLaunch};
use super::admission::unavailable;
use crate::live::control::LiveControlBackend;
use crate::live::lane_artifacts::LaneTransferBridge;
use crate::live::ledger::fs::FsLiveLedger;
use crate::live::ledger::NewLiveEvent;
use crate::live::service::OmpLiveService;
use crate::live::transfer::TransferManager;

struct RejectLaunch(AtomicUsize);
#[async_trait]
impl LiveSessionLauncher for RejectLaunch {
    fn harness_turns(&self) -> Option<std::sync::Arc<crate::live::harness::HarnessTurns>> {
        None
    }

    async fn open(
        &self,
        _: &SessionManifest,
        _: odin_domain::huginn::SessionEpoch,
        _: bool,
    ) -> Result<SessionRuntime, LiveError> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Err(unavailable("the fixture refuses this"))
    }
}

struct SucceedLaunch;

#[async_trait]
impl LiveSessionLauncher for SucceedLaunch {
    fn harness_turns(&self) -> Option<std::sync::Arc<crate::live::harness::HarnessTurns>> {
        None
    }

    async fn open(
        &self,
        _: &SessionManifest,
        _: odin_domain::huginn::SessionEpoch,
        _: bool,
    ) -> Result<SessionRuntime, LiveError> {
        Ok(SessionRuntime {
            control: Arc::new(NullBackend),
            terminal: None,
            observations: None,
            failed_notices: None,
        })
    }
}

/// Parks its first launch until released, like a bridge whose child takes
/// its time to hand-shake; every later launch succeeds at once.
#[derive(Default)]
struct GatedLaunch {
    calls: AtomicUsize,
    entered: tokio::sync::Notify,
    release: tokio::sync::Notify,
}

#[async_trait]
impl LiveSessionLauncher for GatedLaunch {
    fn harness_turns(&self) -> Option<std::sync::Arc<crate::live::harness::HarnessTurns>> {
        None
    }

    async fn open(
        &self,
        _: &SessionManifest,
        _: odin_domain::huginn::SessionEpoch,
        _: bool,
    ) -> Result<SessionRuntime, LiveError> {
        if self.calls.fetch_add(1, Ordering::SeqCst) == 0 {
            self.entered.notify_one();
            self.release.notified().await;
        }
        Ok(SessionRuntime {
            control: Arc::new(NullBackend),
            terminal: None,
            observations: None,
            failed_notices: None,
        })
    }
}

/// Launch runs outside the admission gate while retaining its seat slot.
#[tokio::test]
async fn a_slow_launch_holds_its_slot_but_not_the_gate() {
    let root = tempfile::tempdir().expect("tempdir");
    let ledger: Arc<dyn LiveLedger> =
        Arc::new(super::super::ledger::fs::FsLiveLedger::open(root.path()).expect("ledger"));
    let launch = Arc::new(GatedLaunch::default());
    let supervisor = LiveSupervisor::new(Arc::clone(&ledger), launch.clone(), 256, None);
    let request = bound_seat(&supervisor, 2).await;
    let with_id = |id: &str| {
        let mut request = request.clone();
        request.command_id = odin_domain::CommandId::new(id).expect("command id");
        request
    };
    let first = tokio::spawn({
        let supervisor = Arc::clone(&supervisor);
        let request = with_id("slow-launch");
        async move { supervisor.open(request).await }
    });
    launch.entered.notified().await;
    tokio::time::timeout(
        std::time::Duration::from_secs(5),
        supervisor.open(with_id("second")),
    )
    .await
    .expect("the second open does not wait for the first launch")
    .expect("second opens");
    let refused = supervisor.open(with_id("third")).await;
    assert!(
        matches!(refused, Err(LiveError::ResourceLimit { .. })),
        "the starting session holds its seat slot: {refused:?}"
    );
    let starting = supervisor.open(with_id("slow-launch")).await;
    assert!(
        matches!(&starting, Err(LiveError::Unavailable { code, .. }) if code == "session_starting"),
        "{starting:?}"
    );
    launch.release.notify_one();
    first.await.expect("first task").expect("first opens");
    assert_eq!(supervisor.summaries().await.expect("summaries").len(), 2);
}

struct Watched(std::sync::Mutex<String>);

impl crate::live::service::HeartbeatWatched for Watched {
    fn digest(&self, seat: &odin_domain::SeatId) -> String {
        format!("{seat}:{}", self.0.lock().expect("watched"))
    }
}

#[tokio::test]
async fn an_unchanged_digest_skips_the_heartbeat() {
    let root = tempfile::tempdir().expect("tempdir");
    let ledger: Arc<dyn LiveLedger> =
        Arc::new(super::super::ledger::fs::FsLiveLedger::open(root.path()).expect("ledger"));
    let supervisor = LiveSupervisor::new(ledger, Arc::new(SucceedLaunch), 256, None);
    let watched = Arc::new(Watched(std::sync::Mutex::new(
        "workload a Running".to_owned(),
    )));
    supervisor.set_heartbeat_watched(watched.clone());
    let (changed, always) = (
        SeatId::new("supervisor").unwrap(),
        SeatId::new("kubert").unwrap(),
    );
    supervisor.set_heartbeat_when(&changed, crate::live::rollover::HeartbeatWhen::Changed);
    let session = LiveSessionId::new(uuid::Uuid::new_v4()).expect("session");

    assert!(
        supervisor.heartbeat_changed(&changed, session).await,
        "the first fires"
    );
    assert!(
        !supervisor.heartbeat_changed(&changed, session).await,
        "nothing moved"
    );
    assert!(
        supervisor.heartbeat_changed(&always, session).await,
        "always fires"
    );
    *watched.0.lock().expect("watched") = "workload a Succeeded".to_owned();
    assert!(
        supervisor.heartbeat_changed(&changed, session).await,
        "a workload moved"
    );
    supervisor.clear_heartbeat(session);
    assert!(
        supervisor.heartbeat_changed(&changed, session).await,
        "a cleared fire is due again"
    );
}

#[derive(Default)]
struct CancellationWitnessLaunch {
    entered: tokio::sync::Notify,
    terminated: AtomicBool,
}

#[async_trait]
impl LiveSessionLauncher for CancellationWitnessLaunch {
    fn harness_turns(&self) -> Option<std::sync::Arc<crate::live::harness::HarnessTurns>> {
        None
    }

    fn cancellation_joins_resources(&self) -> bool {
        // The blocked future owns only the synchronous Drop witness below.
        true
    }

    async fn open(
        &self,
        _: &SessionManifest,
        _: odin_domain::huginn::SessionEpoch,
        _: bool,
    ) -> Result<SessionRuntime, LiveError> {
        struct Witness<'a>(&'a AtomicBool);
        impl Drop for Witness<'_> {
            fn drop(&mut self) {
                self.0.store(true, Ordering::SeqCst);
            }
        }
        let _witness = Witness(&self.terminated);
        self.entered.notify_one();
        std::future::pending().await
    }
}

#[tokio::test]
async fn owned_open_cancellation_joins_real_launcher_before_returning() {
    let root = tempfile::tempdir().expect("tempdir");
    let ledger: Arc<dyn LiveLedger> =
        Arc::new(super::super::ledger::fs::FsLiveLedger::open(root.path()).expect("ledger"));
    let launch = Arc::new(CancellationWitnessLaunch::default());
    let supervisor = LiveSupervisor::new(ledger, launch.clone(), 256, None);
    let request = bound_seat(&supervisor, 2).await;
    let (cancel, cancellation) = watch::channel(false);
    let open = tokio::spawn({
        let supervisor = Arc::clone(&supervisor);
        async move { supervisor.open_owned(request, cancellation).await }
    });
    launch.entered.notified().await;
    assert!(!launch.terminated.load(Ordering::SeqCst));
    cancel.send_replace(true);
    let (result, committed) = tokio::time::timeout(std::time::Duration::from_secs(5), open)
        .await
        .expect("cancellation joins launcher")
        .expect("open task");
    assert!(matches!(result, Err(LiveError::Unavailable { code, .. }) if code == "open_cancelled"));
    assert!(!committed);
    assert!(
        launch.terminated.load(Ordering::SeqCst),
        "real launcher terminated before reply"
    );
    assert!(supervisor.actors.read().await.is_empty());
    assert!(supervisor.starting.lock().expect("starting").is_empty());
}

/// One bound, open session parked by a daemon restart: `launcher` owns
/// the fresh supervisor's launches, the seat is re-bound, and `parked` is
/// the session's exact durable summary.
async fn parked_session(
    root: &std::path::Path,
    launcher: Arc<dyn LiveSessionLauncher>,
    max_sessions: usize,
) -> (
    Arc<LiveSupervisor>,
    Arc<dyn LiveLedger>,
    LiveSessionSummary,
    LiveSessionId,
) {
    let ledger: Arc<dyn LiveLedger> =
        Arc::new(super::super::ledger::fs::FsLiveLedger::open(root).expect("ledger"));
    let supervisor = LiveSupervisor::new(Arc::clone(&ledger), Arc::new(SucceedLaunch), 256, None);
    let request = bound_seat(&supervisor, 4).await;
    let opened = supervisor.open(request).await.expect("open");
    drop(supervisor);
    let reopened: Arc<dyn LiveLedger> =
        Arc::new(super::super::ledger::fs::FsLiveLedger::open(root).expect("reopen ledger"));
    let recovered = LiveSupervisor::discover(reopened.clone(), launcher, max_sessions, None)
        .await
        .expect("discover");
    bound_seat(&recovered, 4).await;
    let parked = recovered
        .parked(opened.session_id)
        .await
        .expect("parked lookup")
        .expect("the session is parked");
    (recovered, reopened, parked, opened.session_id)
}

/// A whole-session abort bound to a summary's exact durable identity.
fn abort_session(
    session_id: LiveSessionId,
    parked: &LiveSessionSummary,
    label: &'static str,
) -> LiveCommand {
    LiveCommand {
        command_id: odin_domain::CommandId::new(format!("{label:0<128}")).expect("command id"),
        session_id,
        expected_epoch: parked.epoch,
        expected_event_head: Some(parked.event_head),
        body: LiveCommandBody::Abort {
            scope: AbortScope::Session,
        },
    }
}

/// A prompt bound to a summary's exact durable identity.
fn parked_prompt(session_id: LiveSessionId, parked: &LiveSessionSummary) -> LiveCommand {
    LiveCommand {
        command_id: odin_domain::CommandId::new(format!("{:0<128}", "parked-prompt"))
            .expect("command id"),
        session_id,
        expected_epoch: parked.epoch,
        expected_event_head: Some(parked.event_head),
        body: LiveCommandBody::Prompt {
            message: LiveMessage::new(vec![odin_domain::huginn::LiveContentBlock::Text(
                "still there?".to_owned(),
            )])
            .expect("message"),
            owner_text: None,
            wake: false,
        },
    }
}

fn control_id(prefix: &str, command: &LiveCommand) -> EventId {
    super::reclaim::control_event_id(command, prefix).expect("event id")
}

/// Transfer-side stubs: the public command route never touches transfers,
/// so every lane call fails typed.
struct UnresolvedTransferLanes;

#[async_trait]
impl crate::live::transfer::TransferLaneResolver for UnresolvedTransferLanes {
    async fn lane_for(
        &self,
        _: &odin_domain::huginn::TransferManifest,
    ) -> Result<odin_domain::LaneId, LiveError> {
        Err(unavailable("the fixture refuses this"))
    }
}

struct UnreachableLanePort;

#[async_trait]
impl crate::live::lane_artifacts::LaneArtifactPort for UnreachableLanePort {
    async fn publish(&self, _: crate::live::lane_artifacts::LaneArtifact) -> Result<(), LiveError> {
        Err(unavailable("the fixture refuses this"))
    }
    async fn subscribe(
        &self,
        _: &odin_domain::LaneId,
    ) -> Result<crate::live::lane_artifacts::LaneEgressStream, LiveError> {
        Err(unavailable("the fixture refuses this"))
    }
}

/// A wired public command route: the same dispatcher every operator
/// surface hits.
fn command_service(
    root: &std::path::Path,
    ledger: &Arc<dyn LiveLedger>,
    supervisor: &Arc<LiveSupervisor>,
) -> OmpLiveService {
    let transfers = TransferManager::open(
        root.join("transfers"),
        Arc::clone(ledger),
        Arc::new(UnresolvedTransferLanes),
        Arc::new(LaneTransferBridge::new(Arc::new(UnreachableLanePort))),
    )
    .expect("transfers");
    OmpLiveService::new(
        Arc::clone(ledger),
        Arc::clone(supervisor),
        Arc::new(transfers),
    )
}

#[tokio::test]
async fn discover_restores_exactly_and_explicit_reclaim_publishes_the_epoch_at_the_head() {
    let root = tempfile::tempdir().expect("tempdir");
    let launcher = Arc::new(SucceedLaunch);
    let ledger: Arc<dyn LiveLedger> =
        Arc::new(super::super::ledger::fs::FsLiveLedger::open(root.path()).expect("ledger"));
    let supervisor = LiveSupervisor::new(Arc::clone(&ledger), launcher.clone(), 256, None);
    let request = bound_seat(&supervisor, 4).await;
    supervisor.open(request).await.expect("open");
    let opened = supervisor.summaries().await.expect("summaries")[0].clone();
    assert_eq!(opened.epoch.get(), 1);
    assert_eq!(opened.state, LiveSessionState::Idle);

    // The daemon restarts: a fresh supervisor DISCOVERS the durable
    // ledger. Discovery is load-only — the session's summary is
    // restored exactly as the journal left it (same epoch, same
    // state), no child spawns, and no authority is consulted, so a
    // stale seat token can never prevent startup.
    drop(supervisor);
    let reopened: Arc<dyn LiveLedger> =
        Arc::new(super::super::ledger::fs::FsLiveLedger::open(root.path()).expect("reopen ledger"));
    let recording = Arc::new(RecordingLaunch::new());
    let recovered = LiveSupervisor::discover(Arc::clone(&reopened), recording.clone(), 256, None)
        .await
        .expect("discover");
    let missing = recovered
        .reclaim(opened.session_id)
        .await
        .expect_err("unbound seat refuses");
    assert!(matches!(missing, LiveError::NotFound { .. }));
    assert_eq!(
        reopened
            .session(opened.session_id)
            .await
            .expect("session")
            .epoch
            .get(),
        1
    );
    bound_seat(&recovered, 4).await;
    assert!(
        recording.opens().is_empty(),
        "load-only discovery must never launch a bridge"
    );
    let summary = recovered.summaries().await.expect("summaries")[0].clone();
    assert_eq!(
        summary.epoch.get(),
        1,
        "discovery restores the exact durable epoch"
    );
    assert_eq!(summary.state, LiveSessionState::Detached);

    // The explicit reclaim advances the epoch and that advance is
    // always published at the journal head: a client replaying history
    // to the head adopts the authoritative current epoch, never a
    // stale pre-reclaim one.
    let reclaimed = recovered
        .reclaim(summary.session_id)
        .await
        .expect("reclaim");
    assert_eq!(
        reclaimed.epoch.get(),
        2,
        "reclaim advances exactly one epoch"
    );
    assert_eq!(
        recording.opens().len(),
        1,
        "the reclaim launched exactly one fresh bridge incarnation"
    );
    let page = reopened
        .history(HistoryQuery {
            session_id: summary.session_id,
            after: EventSeq::new(0),
            limit: NonZeroU16::new(1024).expect("positive"),
        })
        .await
        .expect("history");
    let head = page.events.last().expect("journal head");
    assert_eq!(
        head.epoch, reclaimed.epoch,
        "the journal head must carry the session's current epoch after a reclaim"
    );
}

#[tokio::test]
async fn reclaim_uses_current_declared_lead_instead_of_persisted_launch() {
    let root = tempfile::tempdir().expect("tempdir");
    let ledger: Arc<dyn LiveLedger> =
        Arc::new(super::super::ledger::fs::FsLiveLedger::open(root.path()).expect("ledger"));
    let supervisor = LiveSupervisor::new(Arc::clone(&ledger), Arc::new(SucceedLaunch), 256, None);
    let request = bound_seat(&supervisor, 4).await;
    let slice_id = request.slice_id.clone();
    let opened = supervisor.open(request).await.expect("open");
    let original_provider = opened.provider.clone();
    let original_model = opened.model.clone();
    let new_model = ModelName::new("fixture-new-lead").expect("fixture model");
    assert_ne!(original_model, new_model);

    // The daemon restarts with a different lead, while the former model
    // remains declared as an alternative. The same durable transcript must
    // resume under the current lead, not the saved launch pair.
    drop(supervisor);
    let reopened: Arc<dyn LiveLedger> =
        Arc::new(super::super::ledger::fs::FsLiveLedger::open(root.path()).expect("reopen ledger"));
    let recording = Arc::new(RecordingLaunch::new());
    let recovered = LiveSupervisor::discover(Arc::clone(&reopened), recording.clone(), 256, None)
        .await
        .expect("discover");
    let persisted = reopened
        .session(opened.session_id)
        .await
        .expect("persisted session");
    assert_eq!(persisted.manifest.provider, original_provider);
    assert_eq!(persisted.manifest.model, original_model);
    let rebound: LiveLaunchOption = serde_json::from_value(serde_json::json!({
        "provider": original_provider.as_str(), "model": new_model.as_str(),
        "skeletonRef":"omp", "containerId":"omp"
    }))
    .expect("rebound launch option");
    let former: LiveLaunchOption = serde_json::from_value(serde_json::json!({
        "provider": original_provider.as_str(), "model": original_model.as_str(),
        "skeletonRef":"omp", "containerId":"omp"
    }))
    .expect("former launch option");
    recovered
        .bind(LiveSeatBinding {
            seat_id: opened.seat_id.clone(),
            slice_id,
            display_name: "Architect".to_owned(),
            launch_options: vec![rebound, former],
            allowed_nodes: vec![NodeId::new("laptop").expect("node id")],
            max_sessions: 4,
            turn_budget: None,
            quiet_seconds: 600,
        })
        .await
        .expect("rebind");
    let summary = recovered.reclaim(opened.session_id).await.expect("reclaim");
    assert_eq!(summary.provider, original_provider);
    assert_eq!(summary.model, new_model);
    let launches = recording.opens();
    assert_eq!(launches.len(), 1, "the reclaim launches exactly one bridge");
    let (session_id, epoch, reclaim, provider, model) = &launches[0];
    assert_eq!(
        epoch.get(),
        2,
        "the launch records the durable admission epoch the reclaim produced"
    );
    assert_eq!(*session_id, opened.session_id);
    assert!(
        *reclaim,
        "the parked recovery reclaims with a fresh incarnation"
    );
    assert_eq!(
        provider, &original_provider,
        "the provider remains unchanged"
    );
    assert_eq!(model, &new_model, "the current declared lead wins");
    let durable = recovered
        .durable_summary(opened.session_id)
        .await
        .expect("summary")
        .expect("session");
    assert_eq!(durable.provider, original_provider);
    assert_eq!(durable.model, new_model);
    drop(recovered);
    drop(reopened);
    let ledger: Arc<dyn LiveLedger> = Arc::new(
        super::super::ledger::fs::FsLiveLedger::open(root.path()).expect("reopen after reclaim"),
    );
    let rediscovered = LiveSupervisor::discover(ledger, Arc::new(SucceedLaunch), 256, None)
        .await
        .expect("rediscover");
    let summary = rediscovered
        .durable_summary(opened.session_id)
        .await
        .expect("summary")
        .expect("session");
    assert_eq!(summary.provider, original_provider);
    assert_eq!(summary.model, new_model);
}

#[tokio::test]
async fn durable_summary_replays_applied_switches_after_reclaim_but_not_failures() {
    let root = tempfile::tempdir().expect("tempdir");
    let ledger: Arc<dyn LiveLedger> = Arc::new(FsLiveLedger::open(root.path()).expect("ledger"));
    let supervisor = LiveSupervisor::new(Arc::clone(&ledger), Arc::new(SucceedLaunch), 256, None);
    let request = bound_seat(&supervisor, 4).await;
    let opened = supervisor.open(request).await.expect("open");
    let reclaimed_provider = ProviderName::new("reclaimed-provider").unwrap();
    let reclaimed_model = ModelName::new("reclaimed-model").unwrap();
    ledger
        .append(
            opened.epoch,
            NewLiveEvent {
                session_id: opened.session_id,
                event_id: EventId::new("replay-reclaim").unwrap(),
                occurred_at: time::OffsetDateTime::now_utc(),
                body: LiveEventBody::ModelReclaimed(odin_domain::huginn::ModelReclaimed {
                    provider: reclaimed_provider.clone(),
                    model: reclaimed_model.clone(),
                }),
            },
        )
        .await
        .unwrap();
    let durable = supervisor
        .durable_summary(opened.session_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        (durable.provider, durable.model),
        (reclaimed_provider, reclaimed_model)
    );

    let selected_provider = ProviderName::new("selected-provider").unwrap();
    let selected_model = ModelName::new("selected-model").unwrap();
    for (id, provider, model, applied) in [
        (
            "switch-applied",
            selected_provider.clone(),
            selected_model.clone(),
            true,
        ),
        (
            "switch-failed",
            ProviderName::new("failed-provider").unwrap(),
            ModelName::new("failed-model").unwrap(),
            false,
        ),
    ] {
        let command = LiveCommand {
            command_id: odin_domain::CommandId::new(id).unwrap(),
            session_id: opened.session_id,
            expected_epoch: opened.epoch,
            expected_event_head: None,
            body: LiveCommandBody::SetModel {
                provider,
                model,
                route: None,
            },
        };
        ledger.append_command(&command).await.unwrap();
        let outcome = if applied {
            CommandOutcome::Applied {
                command_id: command.command_id.clone(),
            }
        } else {
            CommandOutcome::Failed {
                command_id: command.command_id.clone(),
                error: odin_domain::huginn::CommandFailure {
                    code: "control_failed".to_owned(),
                    message: "refused".to_owned(),
                    retryable: false,
                },
            }
        };
        ledger
            .complete_command(command.command_id.clone(), outcome.clone())
            .await
            .unwrap();
        ledger
            .append(
                opened.epoch,
                NewLiveEvent {
                    session_id: opened.session_id,
                    event_id: EventId::new(id).unwrap(),
                    occurred_at: time::OffsetDateTime::now_utc(),
                    body: LiveEventBody::ControlCompleted(outcome),
                },
            )
            .await
            .unwrap();
    }
    drop(supervisor);
    drop(ledger);
    let reopened: Arc<dyn LiveLedger> = Arc::new(FsLiveLedger::open(root.path()).unwrap());
    let rediscovered = LiveSupervisor::discover(reopened, Arc::new(SucceedLaunch), 256, None)
        .await
        .unwrap();
    let summary = rediscovered
        .durable_summary(opened.session_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        (summary.provider, summary.model),
        (selected_provider, selected_model)
    );
}

#[tokio::test]
async fn a_truthfully_ended_session_is_never_reclaimed() {
    let root = tempfile::tempdir().expect("tempdir");
    let ledger: Arc<dyn LiveLedger> =
        Arc::new(super::super::ledger::fs::FsLiveLedger::open(root.path()).expect("ledger"));
    let supervisor = LiveSupervisor::new(Arc::clone(&ledger), Arc::new(SucceedLaunch), 256, None);
    let request = bound_seat(&supervisor, 1).await;
    let first = supervisor.open(request).await.expect("first session opens");

    // The operator ends the conversation; the journal settles Ended.
    let actor = supervisor.actor(first.session_id).await.expect("actor");
    let snapshot = actor.summary().expect("actor summary");
    let abort = LiveCommand {
        command_id: odin_domain::CommandId::new("odin-omp:cmd:end-for-refusal")
            .expect("command id"),
        session_id: first.session_id,
        expected_epoch: snapshot.epoch,
        expected_event_head: None,
        body: odin_domain::huginn::LiveCommandBody::Abort {
            scope: odin_domain::huginn::AbortScope::Session,
        },
    };
    actor.command(abort).await.expect("abort command");

    // Recovery refuses a terminal session BEFORE any effect: no fresh
    // epoch, no child, and the durable summary stays truthfully Ended.
    let error = supervisor
        .reclaim(first.session_id)
        .await
        .expect_err("ended refuses");
    assert!(
        matches!(error, LiveError::Conflict { ref code, .. } if code == "session_ended"),
        "expected the typed terminal refusal, got {error}"
    );
    // Terminal history is read from the journal, not retained in the roster.
    assert!(
        !supervisor
            .summaries()
            .await
            .expect("summaries")
            .iter()
            .any(|summary| summary.session_id == first.session_id),
        "a truthfully ended session must leave the live roster"
    );
    let ended = supervisor
        .terminal_summary(first.session_id)
        .await
        .expect("terminal read-back")
        .expect("the terminal session's durable summary");
    assert_eq!(ended.state, LiveSessionState::Ended);
    assert_eq!(
        ended.epoch.get(),
        snapshot.epoch.get(),
        "the refusal must not advance the epoch"
    );
    assert!(
        supervisor
            .parked(first.session_id)
            .await
            .expect("parked lookup")
            .is_none(),
        "a terminal session is not parked anywhere — it is ledger history"
    );
}

/// A backend whose readiness models the ACTUAL bridge lifecycle: ready
/// while the incarnation carries traffic, not-ready once its pump proves
/// the child gone, ready again after a recovery replaces it. Counts its
/// in-place restarts.
struct GatedBackend {
    ready: Arc<AtomicBool>,
    restarts: Arc<AtomicU64>,
    /// Signalled on every readiness probe, so a test waits for the actor to have judged a notice.
    probed: Arc<tokio::sync::Notify>,
}

#[async_trait]
impl LiveControlBackend for GatedBackend {
    async fn bridge_ready(&self) -> bool {
        self.probed.notify_one();
        self.ready.load(Ordering::SeqCst)
    }
    async fn restart(&self) -> Result<(), LiveError> {
        self.restarts.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
    async fn prompt(&self, _: &LiveMessage, _owner_text: Option<&str>) -> Result<(), LiveError> {
        Ok(())
    }
    async fn follow_up(&self, _: &LiveMessage, _owner_text: Option<&str>) -> Result<(), LiveError> {
        Ok(())
    }
    async fn steer(&self, _: &LiveMessage) -> Result<(), LiveError> {
        Ok(())
    }
    async fn pause(&self) -> Result<(), LiveError> {
        Ok(())
    }
    async fn resume(&self) -> Result<(), LiveError> {
        Ok(())
    }
    async fn checkpoint(&self) -> Result<(), LiveError> {
        Ok(())
    }
    async fn rehome(&self, _: &NodeId) -> Result<(), LiveError> {
        Ok(())
    }
    async fn set_model(&self, _: &ProviderName, _: &ModelName) -> Result<(), LiveError> {
        Ok(())
    }
    async fn abort_turn(&self) -> Result<(), LiveError> {
        Ok(())
    }
    async fn abort_session(&self) -> Result<(), LiveError> {
        Ok(())
    }
    async fn shutdown(&self) -> Result<(), LiveError> {
        Ok(())
    }
    async fn decide_permission(
        &self,
        _: &PermissionRequestId,
        _: PermissionDecision,
    ) -> Result<(), LiveError> {
        Ok(())
    }
    async fn decide_approval(
        &self,
        _: &ApprovalId,
        _: u64,
        _: ApprovalDecision,
    ) -> Result<(), LiveError> {
        Ok(())
    }
}

/// A launcher that hands the session's typed failure-notice receiver to
/// the test and a gated backend modeling the failed/ready transition, so
/// an ACTUAL backend failure (production: the bridge pump proving the
/// child gone) can be injected without any command.
struct WatchedLaunch {
    failures: watch::Sender<Option<String>>,
    ready: Arc<AtomicBool>,
    restarts: Arc<AtomicU64>,
    probed: Arc<tokio::sync::Notify>,
    opens: AtomicUsize,
}

impl WatchedLaunch {
    fn new(
        failures: watch::Sender<Option<String>>,
        ready: Arc<AtomicBool>,
        restarts: Arc<AtomicU64>,
    ) -> Arc<Self> {
        Arc::new(Self {
            failures,
            ready,
            restarts,
            probed: Arc::default(),
            opens: AtomicUsize::new(0),
        })
    }
}

#[async_trait]
impl LiveSessionLauncher for WatchedLaunch {
    fn harness_turns(&self) -> Option<std::sync::Arc<crate::live::harness::HarnessTurns>> {
        None
    }

    async fn open(
        &self,
        _manifest: &SessionManifest,
        _epoch: odin_domain::huginn::SessionEpoch,
        reclaim: bool,
    ) -> Result<SessionRuntime, LiveError> {
        self.opens.fetch_add(1, Ordering::SeqCst);
        let _ = reclaim;
        Ok(SessionRuntime {
            control: Arc::new(GatedBackend {
                ready: Arc::clone(&self.ready),
                restarts: Arc::clone(&self.restarts),
                probed: Arc::clone(&self.probed),
            }),
            terminal: None,
            observations: None,
            failed_notices: Some(self.failures.subscribe()),
        })
    }
}

/// A round trip through the session's actor: it returns only after every message queued before it.
async fn barrier(supervisor: &LiveSupervisor, session_id: LiveSessionId) {
    supervisor
        .actor(session_id)
        .await
        .expect("actor")
        .bridge_ready()
        .await;
}

async fn summaries_state_of(
    supervisor: &LiveSupervisor,
    session_id: LiveSessionId,
) -> LiveSessionState {
    supervisor
        .summaries()
        .await
        .expect("summaries")
        .into_iter()
        .find(|summary| summary.session_id == session_id)
        .expect("session summary")
        .state
}

#[tokio::test]
async fn an_actual_backend_failure_becomes_durable_failed_recovers_in_place_and_ignores_a_late_stale_notice(
) {
    let root = tempfile::tempdir().expect("tempdir");
    let ledger: Arc<dyn LiveLedger> =
        Arc::new(super::super::ledger::fs::FsLiveLedger::open(root.path()).expect("ledger"));
    let (failure_tx, _) = watch::channel(None);
    let ready = Arc::new(AtomicBool::new(true));
    let restarts = Arc::new(AtomicU64::new(0));
    let launcher = WatchedLaunch::new(
        failure_tx.clone(),
        Arc::clone(&ready),
        Arc::clone(&restarts),
    );
    let supervisor = LiveSupervisor::new(Arc::clone(&ledger), launcher.clone(), 256, None);
    let request = bound_seat(&supervisor, 4).await;
    let opened = supervisor.open(request).await.expect("open");
    let epoch_before = opened.epoch;
    assert_eq!(
        summaries_state_of(&supervisor, opened.session_id).await,
        LiveSessionState::Idle
    );

    // ACTUAL FAILURE, no command, no stop: the incarnation's backend
    // stops carrying traffic (production: the pump proves the child
    // gone) and the typed notice is published.
    // The actor judges each notice with a readiness probe first, then journals, so a summary read
    // after the probe is serialized behind the whole judgement.
    ready.store(false, Ordering::SeqCst);
    let _ = launcher.probed.notified().now_or_never();
    failure_tx
        .send(Some("OMP stdout closed; the child exited".to_owned()))
        .expect("failure notice");
    launcher.probed.notified().await;
    barrier(&supervisor, opened.session_id).await;
    assert_eq!(
        summaries_state_of(&supervisor, opened.session_id).await,
        LiveSessionState::Failed,
        "an actual backend failure must reach the public session summary"
    );

    // The SHARED recovery recovers the SAME session id IN PLACE: no new
    // launch (the bridge restarts under the same actor), epoch +1, and
    // the fresh incarnation is ready again.
    ready.store(true, Ordering::SeqCst);
    let recovered = supervisor
        .reclaim(opened.session_id)
        .await
        .expect("recover");
    assert_eq!(recovered.state, LiveSessionState::Idle);
    assert_eq!(
        recovered.epoch,
        epoch_before.checked_increment().expect("epoch advances")
    );
    assert_eq!(restarts.load(Ordering::SeqCst), 1, "one in-place restart");
    assert_eq!(
        launcher.opens.load(Ordering::SeqCst),
        1,
        "only the original open ever launched a bridge"
    );

    // A LATE STALE NOTICE (queued before the recovery, delivered after
    // it) must be ignored: the freshly recovered incarnation proves
    // ready, the summary stays Idle, and the journal head is unchanged.
    let _ = launcher.probed.notified().now_or_never();
    failure_tx
        .send(Some("OMP stdout closed; the child exited".to_owned()))
        .expect("stale notice");
    launcher.probed.notified().await;
    barrier(&supervisor, opened.session_id).await;
    assert_eq!(
        summaries_state_of(&supervisor, opened.session_id).await,
        LiveSessionState::Idle,
        "a stale notice must never fail a recovered incarnation"
    );
    let head_after_stale = supervisor
        .actor(opened.session_id)
        .await
        .expect("actor")
        .summary()
        .expect("summary")
        .event_head;
    assert_eq!(
        head_after_stale, recovered.event_head,
        "the stale notice must not journal anything"
    );
}

#[tokio::test]
async fn a_parked_session_aborts_to_durable_terminal_and_frees_the_roster() {
    let root = tempfile::tempdir().expect("tempdir");
    let recording = Arc::new(RecordingLaunch::new());
    let (recovered, reopened, parked, session_id) =
        parked_session(root.path(), recording.clone(), 1).await;
    assert_eq!(parked.epoch.get(), 1);
    assert_eq!(parked.state, LiveSessionState::Idle);

    // The parked entry IS the roster: a genuinely new open refuses with
    // the declared-roster limit.
    let follower: OpenSessionRequest = serde_json::from_value(serde_json::json!({
        "commandId":"parked-abort-follower", "seatId":"architect", "sliceId":"architect-engine",
        "projectId":"odin", "provider":"openai-codex", "model":"gpt-6-astra",
        "title":null, "targetNode":"laptop", "openTab":false, "initialPrompt":null
    }))
    .expect("follower request");
    let refused = recovered
        .open(follower.clone())
        .await
        .expect_err("the full roster refuses a genuinely new open");
    assert!(matches!(refused, LiveError::ResourceLimit { .. }));

    // Admission stays exclusive: conversation refuses; only the
    // whole-session abort settles.
    let prompt_refused = recovered
        .recover_parked_command(parked_prompt(session_id, &parked))
        .await
        .expect_err("a parked session refuses conversation");
    assert!(matches!(
        &prompt_refused,
        LiveError::Conflict { code, .. } if code == "session_parked"
    ));

    recovered
        .recover_parked_command(abort_session(session_id, &parked, "parked-abort-one"))
        .await
        .expect("the parked abort settles terminal");
    assert!(
        recording.opens().is_empty(),
        "the abort composed no authority and launched nothing"
    );
    let terminal = recovered
        .terminal_summary(session_id)
        .await
        .expect("terminal lookup")
        .expect("terminal");
    assert_eq!(terminal.state, LiveSessionState::Ended);
    assert_eq!(terminal.epoch.get(), parked.epoch.get(), "no epoch advance");
    assert!(recovered
        .parked(session_id)
        .await
        .expect("parked")
        .is_none());

    // The freed slot admits the refused open; its launch is the only one.
    recovered.open(follower).await.expect("admitted");
    let launches = recording.opens();
    assert_eq!(launches.len(), 1);
    assert!(!launches[0].2, "the only launch is the fresh open");

    // Exactly the live abort's journal transition, at the same epoch.
    let page = reopened
        .history(HistoryQuery {
            session_id,
            after: parked.event_head,
            limit: NonZeroU16::new(1024).expect("positive"),
        })
        .await
        .expect("history");
    assert_eq!(page.events.len(), 3);
    assert!(page.events.iter().all(|event| event.epoch == parked.epoch));
    assert!(matches!(
        &page.events[0].body,
        LiveEventBody::ControlAccepted(CommandReceipt::Accepted { .. })
    ));
    match &page.events[1].body {
        LiveEventBody::SessionStateChanged(change) => {
            assert_eq!(change.previous, LiveSessionState::Idle);
            assert_eq!(change.current, LiveSessionState::Ended);
            assert_eq!(change.reason.as_deref(), Some("control:AbortSession"));
        }
        other => panic!("expected the terminal transition, got {other:?}"),
    }
    assert!(matches!(
        &page.events[2].body,
        LiveEventBody::ControlCompleted(CommandOutcome::Applied { .. })
    ));

    // Replay keeps the stored outcome; terminal stays terminal; neither
    // journals anything.
    let head = page.events[2].sequence;
    let replayed = recovered
        .recover_parked_command(abort_session(session_id, &parked, "parked-abort-one"))
        .await
        .expect("replay");
    assert!(matches!(
        &replayed,
        CommandReceipt::Duplicate {
            prior_outcome: Some(_),
            ..
        }
    ));
    let second = recovered
        .recover_parked_command(abort_session(session_id, &parked, "parked-abort-two"))
        .await
        .expect_err("terminal is terminal");
    assert!(matches!(
        &second,
        LiveError::Conflict { code, .. } if code == "session_ended"
    ));
    let after = reopened
        .history(HistoryQuery {
            session_id,
            after: head,
            limit: NonZeroU16::new(1024).expect("positive"),
        })
        .await
        .expect("history");
    assert!(
        after.events.is_empty(),
        "replay and refusals journal nothing"
    );
}

#[tokio::test]
async fn an_interrupted_parked_abort_reconciles_without_replaying_effects() {
    let root = tempfile::tempdir().expect("tempdir");
    let recording = Arc::new(RecordingLaunch::new());
    let (recovered, reopened, parked, session_id) =
        parked_session(root.path(), recording.clone(), 1).await;
    let service = command_service(root.path(), &reopened, &recovered);

    // Journals one crash window of a whole-session abort at the parked
    // identity: accepted, optionally terminal and optionally completed —
    // whatever the daemon's death interrupted.
    async fn journal_window(
        ledger: &dyn LiveLedger,
        command: &LiveCommand,
        epoch: odin_domain::huginn::SessionEpoch,
        terminal: bool,
        completed: bool,
    ) {
        ledger.append_command(command).await.expect("accepted");
        for (prefix, body) in [
            (
                "control",
                LiveEventBody::ControlAccepted(CommandReceipt::Accepted {
                    command_id: command.command_id.clone(),
                }),
            ),
            (
                "control-state",
                LiveEventBody::SessionStateChanged(SessionStateChanged {
                    previous: LiveSessionState::Idle,
                    current: LiveSessionState::Ended,
                    reason: Some("control:AbortSession".to_owned()),
                }),
            ),
        ] {
            if prefix == "control-state" && !terminal {
                continue;
            }
            ledger
                .append(
                    epoch,
                    NewLiveEvent {
                        session_id: command.session_id,
                        event_id: control_id(prefix, command),
                        occurred_at: time::OffsetDateTime::now_utc(),
                        body,
                    },
                )
                .await
                .expect("crash window journaled");
        }
        if completed {
            ledger
                .complete_command(
                    command.command_id.clone(),
                    CommandOutcome::Applied {
                        command_id: command.command_id.clone(),
                    },
                )
                .await
                .expect("completed");
        }
    }

    // Window one — crashed between the parked admission marker and the
    // terminal event: the settlement never landed and nothing may be
    // invented, so the id keeps its stored unresolved receipt and the
    // session stays parked. A fresh distinct abort still terminalizes —
    // window two is that fresh abort.
    let stranded = abort_session(session_id, &parked, "interrupted-abort-one");
    journal_window(reopened.as_ref(), &stranded, parked.epoch, false, false).await;
    let head_after_strand = reopened.head(session_id).await.expect("head");
    let resolved = service
        .command(abort_session(session_id, &parked, "interrupted-abort-one"))
        .await
        .expect("reconciled");
    assert!(matches!(
        &resolved,
        CommandReceipt::Duplicate {
            prior_outcome: None,
            ..
        }
    ));
    assert!(recording.opens().is_empty());
    assert_eq!(
        reopened.head(session_id).await.expect("head"),
        head_after_strand,
        "no invented cancellation is journaled"
    );
    let still_parked = recovered
        .parked(session_id)
        .await
        .expect("parked lookup")
        .expect("the session stays parked");
    assert_eq!(still_parked.state, LiveSessionState::Idle);

    // Window two — crashed after the terminal event, before the outcome:
    // THIS command's settlement event is durable, so the public route
    // adopts Applied, journals the one missing completion, and frees the
    // roster slot.
    let settled = abort_session(session_id, &parked, "interrupted-abort-two");
    journal_window(reopened.as_ref(), &settled, parked.epoch, true, false).await;
    let adopted = service
        .command(abort_session(session_id, &parked, "interrupted-abort-two"))
        .await
        .expect("adopted");
    assert!(matches!(
        &adopted,
        CommandReceipt::Duplicate { prior_outcome, .. }
            if matches!(prior_outcome.as_deref(), Some(CommandOutcome::Applied { .. }))
    ));
    // A LIVE incarnation's interrupted abort: its terminal event carries
    // the actor's random id, so no parked marker is durable and the
    // reconciliation must not invent an outcome for it. The receipt
    // stays exactly as journaled, the session stays Ended, and the
    // journal is untouched.
    let live_owned = abort_session(session_id, &parked, "live-owned-abort");
    reopened
        .append_command(&live_owned)
        .await
        .expect("accepted");
    for (seed, body) in [
        (
            uuid::Uuid::new_v4().to_string(),
            LiveEventBody::ControlAccepted(CommandReceipt::Accepted {
                command_id: live_owned.command_id.clone(),
            }),
        ),
        (
            uuid::Uuid::new_v4().to_string(),
            LiveEventBody::SessionStateChanged(SessionStateChanged {
                previous: LiveSessionState::Idle,
                current: LiveSessionState::Ended,
                reason: Some("control:AbortSession".to_owned()),
            }),
        ),
    ] {
        reopened
            .append(
                parked.epoch,
                NewLiveEvent {
                    session_id,
                    event_id: EventId::new(format!("event:{seed}")).expect("event id"),
                    occurred_at: time::OffsetDateTime::now_utc(),
                    body,
                },
            )
            .await
            .expect("live crash window journaled");
    }
    let head_before_live = reopened.head(session_id).await.expect("head");
    let preserved = service
        .command(abort_session(session_id, &parked, "live-owned-abort"))
        .await
        .expect("replayed");
    assert!(matches!(
        &preserved,
        CommandReceipt::Duplicate {
            prior_outcome: None,
            ..
        }
    ));
    assert_eq!(
        reopened.head(session_id).await.expect("head"),
        head_before_live,
        "a live-owned incomplete receipt is never mutated"
    );
    assert!(recording.opens().is_empty());
    let live_terminal = recovered
        .terminal_summary(session_id)
        .await
        .expect("terminal lookup")
        .expect("terminal");
    assert_eq!(live_terminal.state, LiveSessionState::Ended);
    assert!(recovered
        .parked(session_id)
        .await
        .expect("parked")
        .is_none());

    // Window three — the outcome completed but the daemon died before the
    // completion event and the eviction: replay on the SAME live
    // supervisor finishes both, idempotently.
    let finished = abort_session(session_id, &parked, "interrupted-abort-three");
    journal_window(reopened.as_ref(), &finished, parked.epoch, true, true).await;
    let head_before = reopened.head(session_id).await.expect("head");
    let replayed = service
        .command(abort_session(
            session_id,
            &parked,
            "interrupted-abort-three",
        ))
        .await
        .expect("reconciled");
    assert!(matches!(
        &replayed,
        CommandReceipt::Duplicate { prior_outcome, .. }
            if matches!(prior_outcome.as_deref(), Some(CommandOutcome::Applied { .. }))
    ));
    assert_eq!(
        reopened.head(session_id).await.expect("head").get(),
        head_before.get() + 1,
        "exactly the missing completion event is added"
    );
    assert!(recording.opens().iter().all(|launch| !launch.2));

    // Reopen: a fresh daemon discovers the terminal journal — never
    // parked, no actor — and its public route still reaches the
    // reconciler, adopting Applied without any launch; the freed roster
    // then admits a genuinely new session.
    drop(service);
    drop(recovered);
    let late_recording = Arc::new(RecordingLaunch::new());
    let reopened_again: Arc<dyn LiveLedger> = Arc::new(
        super::super::ledger::fs::FsLiveLedger::open(root.path()).expect("reopen ledger again"),
    );
    let rediscovered =
        LiveSupervisor::discover(Arc::clone(&reopened_again), late_recording.clone(), 1, None)
            .await
            .expect("rediscover");
    bound_seat(&rediscovered, 4).await;
    assert!(matches!(
        rediscovered.actor(session_id).await,
        Err(LiveError::NotFound { .. })
    ));
    let late_service = command_service(root.path(), &reopened_again, &rediscovered);
    let replayed_again = late_service
        .command(abort_session(
            session_id,
            &parked,
            "interrupted-abort-three",
        ))
        .await
        .expect("adopted after reopen");
    assert!(matches!(
        &replayed_again,
        CommandReceipt::Duplicate { prior_outcome, .. }
            if matches!(prior_outcome.as_deref(), Some(CommandOutcome::Applied { .. }))
    ));

    // The reconciled slot admits a genuinely new session.
    let fresh: OpenSessionRequest = serde_json::from_value(serde_json::json!({
        "commandId":"reconciled-follower", "seatId":"architect", "sliceId":"architect-engine",
        "projectId":"odin", "provider":"openai-codex", "model":"gpt-6-astra",
        "title":null, "targetNode":"laptop", "openTab":false, "initialPrompt":null
    }))
    .expect("fresh request");
    rediscovered.open(fresh).await.expect("admitted");
    assert!(late_recording.opens().iter().all(|launch| !launch.2));
}

/// Kill the actual actor runtime after durable admission, rather than
/// manufacturing an Accepted receipt. The backend holds the three bridge
/// dispatch states independently of the live journal across daemon death.
fn parked_message_crash_window(follow_up: bool, stage: u8) {
    use self::support::{InterruptedDispatch, InterruptedDispatchLaunch};

    let root = tempfile::tempdir().expect("tempdir");
    let backend = InterruptedDispatch::new(stage);
    let daemon = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("daemon runtime");
    let command = daemon.block_on(async {
        let ledger: Arc<dyn LiveLedger> =
            Arc::new(super::super::ledger::fs::FsLiveLedger::open(root.path()).expect("ledger"));
        let supervisor = LiveSupervisor::new(
            ledger.clone(),
            Arc::new(InterruptedDispatchLaunch(backend.clone())),
            256,
            None,
        );
        let request = bound_seat(&supervisor, 4).await;
        let opened = supervisor.open(request).await.expect("open");
        let actor = supervisor.actor(opened.session_id).await.expect("actor");
        let mut command = parked_prompt(opened.session_id, &opened);
        if follow_up {
            // FollowUp is admitted only while a turn is active. Publish that
            // fixture state through the actor so its summary and journal agree,
            // then bind the command to the resulting head before admission.
            let running = actor
                .append(LiveEventBody::SessionStateChanged(SessionStateChanged {
                    previous: opened.state,
                    current: LiveSessionState::Running,
                    reason: Some("fixture turn in progress".to_owned()),
                }))
                .await
                .expect("journal the running turn");
            command.expected_event_head = Some(running.sequence);
            let LiveCommandBody::Prompt { message, .. } = command.body else {
                unreachable!()
            };
            command.body = LiveCommandBody::FollowUp {
                message,
                owner_text: None,
                wake: false,
            };
        }
        let submitted = command.clone();
        tokio::spawn(async move { actor.command(submitted).await });
        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            backend.entered.notified(),
        )
        .await
        .expect("actor reaches dispatch boundary");
        let entry = ledger
            .command(&command)
            .await
            .expect("lookup")
            .expect("admitted");
        assert_eq!(entry.command, command);
        assert_eq!(entry.dispatch_identity, Some(1));
        command
    });
    // Dropping the runtime cancels the blocked actor without completing its
    // control command, exactly where the backend dispatch boundary stopped it.
    drop(daemon);
    backend.recovering.store(true, Ordering::SeqCst);
    let recovered_runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("recovery runtime");
    recovered_runtime.block_on(async {
        let ledger: Arc<dyn LiveLedger> = Arc::new(
            super::super::ledger::fs::FsLiveLedger::open(root.path()).expect("reopen ledger"),
        );
        let supervisor = LiveSupervisor::discover(
            ledger.clone(),
            Arc::new(InterruptedDispatchLaunch(backend.clone())),
            256,
            None,
        )
        .await
        .expect("discover");
        bound_seat(&supervisor, 4).await;
        assert!(supervisor.parked(command.session_id).await.expect("parked").is_some());
        let service = command_service(root.path(), &ledger, &supervisor);
        let receipt = service.command(command.clone()).await.expect("recover original command");
        let expected = if stage == 1 {
            None
        } else {
            Some(CommandOutcome::Applied { command_id: command.command_id.clone() })
        };
        assert!(matches!(receipt, CommandReceipt::Duplicate { prior_outcome, .. } if prior_outcome.as_deref() == expected.as_ref()));
        let entry = ledger.command(&command).await.expect("lookup").expect("original admission");
        assert_eq!(entry.command, command, "reclaim must never rebind the admitted epoch or head");
        assert!(ledger.session(command.session_id).await.expect("session").epoch > command.expected_epoch);
        let again = service.command(command.clone()).await.expect("retry after recovery");
        assert!(matches!(again, CommandReceipt::Duplicate { prior_outcome, .. } if prior_outcome.as_deref() == expected.as_ref()));
        assert_eq!(backend.sends.load(Ordering::SeqCst), 1, "recovery must not send a fresh identity");
        let calls = backend.calls.lock().expect("calls");
        assert!(calls.len() >= 2, "the parked recovery must reach the backend, not replay a fake receipt");
        assert!(calls.iter().all(|(id, actual_follow_up)| id == &command.command_id && *actual_follow_up == follow_up));
    });
}

#[test]
fn parked_prompt_recovers_original_admission_across_dispatch_crash_windows() {
    for stage in 0..=2 {
        parked_message_crash_window(false, stage);
    }
}

/// One bound seat and its open request, mirroring the existing launch
/// fixtures.
async fn bound_seat(supervisor: &LiveSupervisor, max_sessions: usize) -> OpenSessionRequest {
    let request: OpenSessionRequest = serde_json::from_value(serde_json::json!({
        "commandId":"reclaim-publishes-epoch", "seatId":"architect", "sliceId":"architect-engine",
        "projectId":"odin", "provider":"openai-codex", "model":"gpt-6-astra",
        "title":null, "targetNode":"laptop", "openTab":false, "initialPrompt":null
    }))
    .expect("request");
    let option: LiveLaunchOption = serde_json::from_value(serde_json::json!({
        "provider":"openai-codex", "model":"gpt-6-astra", "skeletonRef":"omp", "containerId":"omp"
    }))
    .expect("launch option");
    supervisor
        .bind(LiveSeatBinding {
            seat_id: request.seat_id.clone(),
            slice_id: request.slice_id.clone(),
            display_name: "Architect".to_owned(),
            launch_options: vec![option],
            allowed_nodes: vec![request.target_node.clone()],
            max_sessions,
            turn_budget: None,
            quiet_seconds: 600,
        })
        .await
        .expect("bind");
    request
}

#[tokio::test]
async fn bounded_seat_refusal_names_the_live_sessions_to_attach_to() {
    let root = tempfile::tempdir().expect("tempdir");
    let ledger: Arc<dyn LiveLedger> =
        Arc::new(super::super::ledger::fs::FsLiveLedger::open(root.path()).expect("ledger"));
    let supervisor = LiveSupervisor::new(ledger, Arc::new(SucceedLaunch), 256, None);
    let request = bound_seat(&supervisor, 1).await;
    supervisor
        .open(request.clone())
        .await
        .expect("first session opens");
    let second: OpenSessionRequest = serde_json::from_value(serde_json::json!({
        "commandId":"bounded-seat-second", "seatId":"architect", "sliceId":"architect-engine",
        "projectId":"odin", "provider":"openai-codex", "model":"gpt-6-astra",
        "title":null, "targetNode":"laptop", "openTab":false, "initialPrompt":null
    }))
    .expect("second request");
    // Bind the seat at a maximum of ONE session: the bounded-session
    // requirement itself stays; only the refusal becomes actionable.
    let error = supervisor
        .open(second)
        .await
        .expect_err("bounded seat refuses");
    let LiveError::ResourceLimit { limit } = error else {
        panic!("expected the bounded-seat resource limit, got {error}");
    };
    let live = supervisor
        .summaries()
        .await
        .expect("summaries")
        .iter()
        .map(|summary| summary.session_id.to_string())
        .collect::<Vec<_>>()
        .join("");
    assert!(
        limit.contains(&live),
        "the refusal must name the live session blocking the seat: {limit}"
    );
    assert!(
        limit.contains("attach"),
        "the refusal must point at attach: {limit}"
    );
}

/// A pod's agent session runs its harness in the pod: it neither takes nor
/// waits for one of the seat's interactive slots.
#[tokio::test]
async fn a_pod_agent_session_neither_takes_nor_waits_for_an_interactive_slot() {
    let root = tempfile::tempdir().expect("tempdir");
    let ledger: Arc<dyn LiveLedger> =
        Arc::new(super::super::ledger::fs::FsLiveLedger::open(root.path()).expect("ledger"));
    let supervisor = LiveSupervisor::new(ledger, Arc::new(SucceedLaunch), 256, None);
    let request = bound_seat(&supervisor, 1).await;
    supervisor
        .open(request)
        .await
        .expect("the interactive session takes the seat's one slot");
    let pod: OpenSessionRequest = serde_json::from_value(serde_json::json!({
        "commandId":"pod-agent-attach", "seatId":"architect", "sliceId":"architect-engine",
        "projectId":"odin", "provider":"openai-codex", "model":"gpt-6-astra",
        "title":"tool-probe", "targetNode":"laptop", "openTab":false, "initialPrompt":null
    }))
    .expect("pod request");
    let binding = odin_domain::huginn::WorkloadSessionBinding {
        profile: "tool-probe".to_owned(),
        snapshot_revision: 1,
        operation: "operation:pod-agent-attach".to_owned(),
        inputs: Vec::new(),
        launching_run: None,
        unresolved_hosts: Default::default(),
        limits: None,
        seeds: Vec::new(),
    };
    let pod = supervisor
        .open_workload(pod, binding)
        .await
        .expect("the pod's agent attaches while the seat's slot is held");
    let second: OpenSessionRequest = serde_json::from_value(serde_json::json!({
        "commandId":"interactive-second", "seatId":"architect", "sliceId":"architect-engine",
        "projectId":"odin", "provider":"openai-codex", "model":"gpt-6-astra",
        "title":null, "targetNode":"laptop", "openTab":false, "initialPrompt":null
    }))
    .expect("second request");
    let LiveError::ResourceLimit { limit } = supervisor
        .open(second)
        .await
        .expect_err("the interactive bound still holds")
    else {
        panic!("expected the bounded-seat resource limit");
    };
    assert!(limit.contains("maximum of 1"), "{limit}");
    assert!(
        !limit.contains(&pod.session_id.to_string()),
        "the pod session holds no interactive slot: {limit}"
    );
}

#[tokio::test]
async fn failed_explicit_launch_is_not_recovered_after_restart() {
    let root = tempfile::tempdir().expect("tempdir");
    let launcher = Arc::new(RejectLaunch(AtomicUsize::new(0)));
    let ledger: Arc<dyn LiveLedger> =
        Arc::new(super::super::ledger::fs::FsLiveLedger::open(root.path()).expect("ledger"));
    let supervisor = LiveSupervisor::new(ledger, launcher.clone(), 256, None);
    let request: OpenSessionRequest = serde_json::from_value(serde_json::json!({
        "commandId":"failed-visible-launch", "seatId":"architect", "sliceId":"architect-engine",
        "projectId":"odin", "provider":"openai-codex", "model":"gpt-6-astra",
        "title":null, "targetNode":"laptop", "openTab":false, "initialPrompt":null
    }))
    .expect("request");
    let option: LiveLaunchOption = serde_json::from_value(serde_json::json!({
        "provider":"openai-codex", "model":"gpt-6-astra", "skeletonRef":"omp", "containerId":"omp"
    }))
    .expect("launch option");
    supervisor
        .bind(LiveSeatBinding {
            seat_id: request.seat_id.clone(),
            slice_id: request.slice_id.clone(),
            display_name: "Architect".to_owned(),
            launch_options: vec![option],
            allowed_nodes: vec![request.target_node.clone()],
            max_sessions: 4,
            turn_budget: None,
            quiet_seconds: 600,
        })
        .await
        .expect("bind");
    assert!(supervisor.open(request).await.is_err());
    assert_eq!(launcher.0.load(Ordering::SeqCst), 1);
    let failed_id =
        session_id_for(&odin_domain::CommandId::new("failed-visible-launch").expect("command id"))
            .expect("session id");
    assert!(supervisor.reclaim(failed_id).await.is_err());
    assert_eq!(launcher.0.load(Ordering::SeqCst), 2);
    drop(supervisor);
    let reopened: Arc<dyn LiveLedger> =
        Arc::new(super::super::ledger::fs::FsLiveLedger::open(root.path()).expect("reopen ledger"));
    let recovered = LiveSupervisor::discover(reopened, launcher.clone(), 256, None)
        .await
        .expect("discover");
    assert_eq!(
        launcher.0.load(Ordering::SeqCst),
        2,
        "failed launch or reclaim must never respawn"
    );
    // Discover's bounded fill still re-parks the failed row (at most
    // max_sessions entries), and it projects its authoritative failed
    // label — but it occupies no capacity (the canonical read path
    // re-derives its terminal state before the count).
    let summaries = recovered.summaries().await.expect("summaries");
    assert_eq!(summaries.len(), 1);
    assert_eq!(summaries[0].state, LiveSessionState::Failed);
    let counted = recovered
        .session_summaries_page(None, true, None, 64)
        .await
        .expect("page")
        .0
        .len();
    assert_eq!(counted, 1);
    // Terminal rows use no capacity, so the new request reaches the failing launcher.
    bound_seat(&recovered, 4).await;
    let fresh = recovered
        .open(cycle_request("failed-visible-launch-2"))
        .await
        .expect_err("the new open reaches the failing launch seam");
    assert!(
        !matches!(fresh, LiveError::ResourceLimit { .. }),
        "the open passes the capacity law (the terminal row holds no slot)          and fails at the launch seam: {fresh:?}"
    );
}

/// One fresh open request on the shared bounded seat, with a unique
/// command id per label.
fn cycle_request(label: &str) -> OpenSessionRequest {
    serde_json::from_value(serde_json::json!({
        "commandId": label, "seatId":"architect", "sliceId":"architect-engine",
        "projectId":"odin", "provider":"openai-codex", "model":"gpt-6-astra",
        "title":null, "targetNode":"laptop", "openTab":false, "initialPrompt":null
    }))
    .expect("cycle request")
}

/// Ends the session through its actor the way the operator surface does:
/// an Abort over the whole session settles the journal `Ended`.
async fn end_session(supervisor: &LiveSupervisor, session_id: LiveSessionId, label: &str) {
    let actor = supervisor.actor(session_id).await.expect("actor");
    let snapshot = actor.summary().expect("actor summary");
    actor
        .command(LiveCommand {
            command_id: odin_domain::CommandId::new(label).expect("command id"),
            session_id,
            expected_epoch: snapshot.epoch,
            expected_event_head: None,
            body: LiveCommandBody::Abort {
                scope: odin_domain::huginn::AbortScope::Session,
            },
        })
        .await
        .expect("abort command");
}

/// The declared `limits.sessions.max_sessions` bounds the live roster
/// across ALL seats — per-seat bounds alone cannot express the process
/// memory budget, and the refusal names the declared limit.
#[tokio::test]
async fn the_declared_session_cap_bounds_live_sessions_across_seats() {
    let root = tempfile::tempdir().expect("tempdir");
    let ledger: Arc<dyn LiveLedger> =
        Arc::new(super::super::ledger::fs::FsLiveLedger::open(root.path()).expect("ledger"));
    // The DECLARED cap is two; each seat individually allows four.
    let supervisor = LiveSupervisor::new(Arc::clone(&ledger), Arc::new(SucceedLaunch), 2, None);
    let first = bound_seat(&supervisor, 4).await;
    let second: OpenSessionRequest = serde_json::from_value(serde_json::json!({
        "commandId":"declared-cap-second", "seatId":"builder", "sliceId":"architect-engine",
        "projectId":"odin", "provider":"openai-codex", "model":"gpt-6-astra",
        "title":null, "targetNode":"laptop", "openTab":false, "initialPrompt":null
    }))
    .expect("second seat request");
    let option: LiveLaunchOption = serde_json::from_value(serde_json::json!({
        "provider":"openai-codex", "model":"gpt-6-astra", "skeletonRef":"omp", "containerId":"omp"
    }))
    .expect("launch option");
    supervisor
        .bind(LiveSeatBinding {
            seat_id: second.seat_id.clone(),
            slice_id: second.slice_id.clone(),
            display_name: "Builder".to_owned(),
            launch_options: vec![option],
            allowed_nodes: vec![second.target_node.clone()],
            max_sessions: 4,
            turn_budget: None,
            quiet_seconds: 600,
        })
        .await
        .expect("bind second seat");

    supervisor.open(first).await.expect("first live session");
    supervisor.open(second).await.expect("second live session");
    let third = cycle_request("odin-omp:cmd:declared-cap-third");
    let error = supervisor
        .open(third)
        .await
        .expect_err("the declared cap refuses the third live session");
    let LiveError::ResourceLimit { limit } = &error else {
        panic!("expected the declared-cap resource limit, got {error}");
    };
    assert!(
        limit.contains("max_sessions is 2") && limit.contains("2 session(s)"),
        "the refusal names the declared limit and the tracked roster: {limit}"
    );

    // Ending one session and reclaiming it frees declared capacity: the
    // next open proceeds without touching the limit.
    let live = supervisor.summaries().await.expect("summaries");
    assert_eq!(live.len(), 2);
    end_session(
        &supervisor,
        live[0].session_id,
        "odin-omp:cmd:declared-cap-end",
    )
    .await;
    // The next read performs the terminal eviction through the real
    // reclaim path.
    let _ = supervisor.summaries().await.expect("summaries");
    assert_eq!(supervisor.summaries().await.expect("summaries").len(), 1);
    supervisor
        .open(cycle_request("odin-omp:cmd:declared-cap-replacement"))
        .await
        .expect("freed capacity admits another session");
}

/// The unified durable listing, traced end to end: one source-bounded
/// scan overlays exact in-memory truth and restores the rest — active
/// first page, filtered gaps, no duplicates and no missed terminal rows,
/// and cursor progress even when a filtered page comes back empty.
#[tokio::test]
async fn the_unified_session_page_traces_active_gap_and_cursor_cases() {
    let root = tempfile::tempdir().expect("tempdir");
    let ledger: Arc<dyn LiveLedger> =
        Arc::new(super::super::ledger::fs::FsLiveLedger::open(root.path()).expect("ledger"));
    let supervisor = LiveSupervisor::new(Arc::clone(&ledger), Arc::new(SucceedLaunch), 256, None);
    let _ = bound_seat(&supervisor, 4).await;
    let a = supervisor
        .open(cycle_request("odin-omp:cmd:page-a"))
        .await
        .expect("open a");
    let b = supervisor
        .open(cycle_request("odin-omp:cmd:page-b"))
        .await
        .expect("open b");
    let c = supervisor
        .open(cycle_request("odin-omp:cmd:page-c"))
        .await
        .expect("open c");
    end_session(&supervisor, b.session_id, "odin-omp:cmd:page-end-b").await;

    // FIRST PAGE: exactly `limit` rows — the (limit+1)th source row is
    // only the has-more lookahead — and the cursor proves a next page.
    let (mut page, mut next) = supervisor
        .session_summaries_page(None, true, None, 2)
        .await
        .expect("first page");
    assert_eq!(page.len(), 2);
    assert!(next.is_some(), "the lookahead must report a next page");
    // Follow the cursor to exhaustion; the union must cover every session
    // exactly once with exactly one Ended row — b's.
    let mut seen: Vec<(LiveSessionId, LiveSessionState)> = Vec::new();
    let mut guard = 0;
    loop {
        seen.extend(
            page.iter()
                .map(|summary| (summary.session_id, summary.state)),
        );
        let Some(after) = next else {
            break;
        };
        guard += 1;
        assert!(guard <= 4, "pagination must terminate: {guard}");
        let response = supervisor
            .session_summaries_page(None, true, Some(after), 2)
            .await
            .expect("following page");
        page = response.0;
        next = response.1;
    }
    let mut ids: Vec<LiveSessionId> = seen.iter().map(|(id, _)| *id).collect();
    ids.sort();
    // Three source rows, three seen rows: the lookahead row is never
    // consumed by the page that discovered it.
    assert_eq!(seen.len(), 3);
    assert_eq!(
        ids.len(),
        ids.iter().collect::<std::collections::BTreeSet<_>>().len(),
        "no duplicate rows across pages"
    );
    for expected in [a.session_id, b.session_id, c.session_id] {
        assert!(
            ids.contains(&expected),
            "no session may be missed: {expected}"
        );
    }
    assert_eq!(
        seen.iter()
            .filter(|(_, state)| *state == LiveSessionState::Ended)
            .count(),
        1,
        "exactly the ended session carries the terminal state"
    );
    assert!(seen
        .iter()
        .any(|(id, state)| *id == b.session_id && *state == LiveSessionState::Ended));

    // FILTERED GAP: an unbound seat empties the page, but the cursor still
    // reports progress and eventually exhausts.
    let stranger = SeatId::new("unbound-seat").expect("seat id");
    let (empty_page, empty_next) = supervisor
        .session_summaries_page(Some(&stranger), true, None, 2)
        .await
        .expect("empty filtered page");
    assert!(empty_page.is_empty());
    assert!(
        empty_next.is_some(),
        "an empty filtered page must still advance the cursor"
    );
    let (empty_page_two, exhausted) = supervisor
        .session_summaries_page(Some(&stranger), true, empty_next, 2)
        .await
        .expect("following empty page");
    assert!(empty_page_two.is_empty() && exhausted.is_none());
}

/// Terminal rows are capacity-free and the projection serves the
/// canonical governed state: EIGHT governed-closed or failed rows — half
/// settled Ended through the governed online close, half failed at the
/// launch seam — never count toward the declared bound, stale cache
/// labels (failed OR idle) never shadow the durable ended marker, and a
/// failed-open burst leaves the physically bounded cache clean while
/// every burst row stays exactly durable.
#[tokio::test]
async fn terminal_rows_are_capacity_free_and_the_projection_stays_authoritative() {
    let root = tempfile::tempdir().expect("tempdir");
    let ledger: Arc<dyn LiveLedger> =
        Arc::new(super::super::ledger::fs::FsLiveLedger::open(root.path()).expect("ledger"));

    // The prior incarnation leaves FOUR governed-closed sessions (Idle
    // opens settled through the whole-session Abort) and FOUR failed
    // opens — eight terminal rows in total.
    let prior = LiveSupervisor::new(Arc::clone(&ledger), Arc::new(SucceedLaunch), 256, None);
    let _template = bound_seat(&prior, 256).await;
    let mut ended = Vec::new();
    for label in [
        "sr-eight-ended-a",
        "sr-eight-ended-b",
        "sr-eight-ended-c",
        "sr-eight-ended-d",
    ] {
        let summary = prior.open(cycle_request(label)).await.expect("open");
        end_session(&prior, summary.session_id, &format!("{label}-close")).await;
        ended.push(summary.session_id);
    }
    drop(prior);
    let failing = LiveSupervisor::new(
        Arc::clone(&ledger),
        Arc::new(RejectLaunch(AtomicUsize::new(0))),
        256,
        None,
    );
    bound_seat(&failing, 256).await;
    let mut failed = Vec::new();
    for label in [
        "sr-eight-failed-a",
        "sr-eight-failed-b",
        "sr-eight-failed-c",
        "sr-eight-failed-d",
    ] {
        assert!(failing.open(cycle_request(label)).await.is_err());
        failed.push(
            session_id_for(&odin_domain::CommandId::new(label).expect("command id"))
                .expect("session id"),
        );
    }
    drop(failing);

    // Failed burst launches leave durable rows but no cached terminal summaries.
    let burst_ids: Vec<LiveSessionId> = (0..6)
        .map(|index| {
            session_id_for(
                &odin_domain::CommandId::new(format!("sr-eight-burst-{index}"))
                    .expect("command id"),
            )
            .expect("session id")
        })
        .collect();
    let supervisor = LiveSupervisor::new(
        reopened_or(root.path()),
        Arc::new(FailSetLaunch::new(std::collections::BTreeSet::from_iter(
            burst_ids.iter().copied(),
        ))),
        3,
        None,
    );
    let _template = bound_seat(&supervisor, 3).await;
    let live_a = supervisor
        .open(cycle_request("sr-eight-live-a"))
        .await
        .expect("live open a")
        .session_id;
    supervisor
        .open(cycle_request("sr-eight-live-b"))
        .await
        .expect("live open b");

    // Failed launches must not consume cache capacity.
    for index in 0..6 {
        assert!(
            supervisor
                .open(cycle_request(&format!("sr-eight-burst-{index}")))
                .await
                .is_err(),
            "burst open {index} fails at the launch seam"
        );
    }
    let summaries_after_burst = supervisor.summaries().await.expect("summaries");
    for (burst_index, burst_id) in burst_ids.iter().enumerate() {
        assert!(
            !summaries_after_burst
                .iter()
                .any(|summary| summary.session_id == *burst_id),
            "terminal burst rows are never cached: burst {burst_index}"
        );
    }

    // Stale cache labels are canonicalized: an IDLE label over one
    // durably ended journal and a FAILED label over another both project
    // the durable ended marker and leave the cache entirely.
    let summaries_now = supervisor.summaries().await.expect("summaries");
    let mut idle_label = summaries_now
        .iter()
        .find(|summary| summary.session_id == live_a)
        .expect("the live label source")
        .clone();
    idle_label.session_id = ended[0];
    let failed_label = supervisor
        .session_summaries_page(None, true, None, 64)
        .await
        .expect("page")
        .0
        .into_iter()
        .find(|summary| summary.session_id == failed[0])
        .expect("the failed row projects under include-stale");
    supervisor.park(ended[0], idle_label).await.expect("park");
    supervisor.park(ended[1], failed_label).await.expect("park");

    // The projection serves the CANONICAL governed state for the whole
    // terminal set: every ended row projects Ended and every failed row
    // projects Failed, and no terminal row is cached.
    let projected = supervisor
        .session_summaries_page(None, true, None, 64)
        .await
        .expect("page")
        .0;
    for session_id in &ended {
        let row = projected
            .iter()
            .find(|summary| summary.session_id == *session_id)
            .expect("the ended row is still listed under include-stale");
        assert_eq!(
            row.state,
            LiveSessionState::Ended,
            "the canonical ended marker is served for {session_id}"
        );
        assert!(supervisor
            .parked(*session_id)
            .await
            .expect("parked")
            .is_none());
    }
    for session_id in &failed {
        let row = projected
            .iter()
            .find(|summary| summary.session_id == *session_id)
            .expect("the failed row is still listed under include-stale");
        assert_eq!(
            row.state,
            LiveSessionState::Failed,
            "the authoritative failed label is served for {session_id}"
        );
    }

    // Capacity: the eight terminal rows and the six burst rows never
    // held a slot, so the two live actors leave room for exactly one
    // more session before the all-actor bound refuses.
    supervisor
        .open(cycle_request("sr-eight-live-c"))
        .await
        .expect("the free slot admits a live session");
    let refused = supervisor.open(cycle_request("sr-eight-live-d")).await;
    assert!(
        matches!(&refused, Err(LiveError::ResourceLimit { .. })),
        "the all-actor bound still refuses: {refused:?}"
    );
    let durable = reopened_or(root.path())
        .sessions()
        .await
        .expect("durable sessions");
    assert_eq!(
        durable.len(),
        17,
        "four governed closes, four failed opens, six burst rows, three live          sessions are all retained durably"
    );
}

fn reopened_or(root: &std::path::Path) -> Arc<dyn LiveLedger> {
    Arc::new(super::super::ledger::fs::FsLiveLedger::open(root).expect("reopen ledger"))
}

/// A launcher that fails exactly the listed session identities: the burst
/// opens fail at the real launch seam while every other open composes a
/// live incarnation.
struct FailSetLaunch {
    fail: std::sync::Mutex<std::collections::BTreeSet<LiveSessionId>>,
}

impl FailSetLaunch {
    fn new(fail: std::collections::BTreeSet<LiveSessionId>) -> Self {
        Self {
            fail: std::sync::Mutex::new(fail),
        }
    }
}

#[async_trait::async_trait]
impl LiveSessionLauncher for FailSetLaunch {
    fn harness_turns(&self) -> Option<std::sync::Arc<crate::live::harness::HarnessTurns>> {
        None
    }

    async fn open(
        &self,
        manifest: &SessionManifest,
        _: odin_domain::huginn::SessionEpoch,
        _: bool,
    ) -> Result<SessionRuntime, LiveError> {
        if self
            .fail
            .lock()
            .expect("fail set")
            .contains(&manifest.session_id)
        {
            return Err(unavailable("the fixture refuses this"));
        }
        Ok(SessionRuntime {
            control: Arc::new(NullBackend),
            terminal: None,
            observations: None,
            failed_notices: None,
        })
    }
}

#[tokio::test]
async fn ambiguous_workload_start_failure_never_authorizes_carrier_release() {
    struct LateResourceLimit;
    #[async_trait]
    impl LiveSessionLauncher for LateResourceLimit {
        fn harness_turns(&self) -> Option<Arc<crate::live::harness::HarnessTurns>> {
            None
        }
        async fn open(
            &self,
            _: &SessionManifest,
            _: odin_domain::huginn::SessionEpoch,
            _: bool,
        ) -> Result<SessionRuntime, LiveError> {
            Err(LiveError::ResourceLimit {
                limit: "late launcher failure".to_owned(),
            })
        }
    }
    let root = tempfile::tempdir().expect("tempdir");
    let ledger = reopened_or(root.path());
    let supervisor = LiveSupervisor::new(ledger.clone(), Arc::new(LateResourceLimit), 8, None);
    let request = bound_seat(&supervisor, 1).await;
    let failure = supervisor
        .open_workload(
            request,
            odin_domain::huginn::WorkloadSessionBinding {
                profile: "tool-probe".to_owned(),
                snapshot_revision: 1,
                operation: "op-ambiguous".to_owned(),
                inputs: Vec::new(),
                launching_run: None,
                unresolved_hosts: Default::default(),
                limits: None,
                seeds: Vec::new(),
            },
        )
        .await
        .expect_err("launcher fails after session creation");
    assert!(!failure.refused_before_open);
    assert!(matches!(failure.error, LiveError::ResourceLimit { .. }));
    assert!(supervisor
        .ended_workload_sessions()
        .await
        .unwrap()
        .is_empty());
    drop(supervisor);
    let restored = LiveSupervisor::discover(ledger, Arc::new(LateResourceLimit), 8, None)
        .await
        .expect("restore failed row");
    assert!(restored.ended_workload_sessions().await.unwrap().is_empty());
}

/// A slot-holding session idle over a day, or an ended one, is not parked.
#[test]
fn discovery_parks_only_recently_active_sessions() {
    let now = time::OffsetDateTime::now_utc();
    let summary = |state, idle: time::Duration| LiveSessionSummary {
        session_id: LiveSessionId::new(uuid::Uuid::from_u128(7)).expect("session"),
        epoch: odin_domain::huginn::SessionEpoch::new(1),
        seat_id: odin_domain::SeatId::new("kubert").expect("seat"),
        provider: odin_domain::huginn::ProviderName::new("gateway").expect("provider"),
        model: odin_domain::huginn::ModelName::new("kubert-mini").expect("model"),
        title: None,
        state,
        started_at: now - idle,
        updated_at: now - idle,
        failed_at: None,
        event_head: odin_domain::huginn::EventSeq::new(3),
        terminal_head: odin_domain::huginn::TerminalSeq::new(0),
        pending_permission_count: 0,
        quiet_seconds: 600,
    };
    let parks = |state, idle| super::admission::parks_on_discovery(&summary(state, idle), now);
    assert!(parks(LiveSessionState::Idle, time::Duration::hours(1)));
    assert!(
        !parks(LiveSessionState::Idle, time::Duration::days(23)),
        "a stale session"
    );
    assert!(!parks(LiveSessionState::Ended, time::Duration::minutes(1)));
    // A recent failed row parks for its label; an old one is history.
    assert!(parks(LiveSessionState::Failed, time::Duration::hours(1)));
    assert!(!parks(LiveSessionState::Failed, time::Duration::days(4)));
}

/// At start a session idle past the park limit that no owner names is
/// journaled `Ended` once with its reason; an owned one, or a terminal one,
/// is left alone.
#[tokio::test]
async fn start_settlement_ends_only_unowned_stale_sessions() {
    let root = tempfile::tempdir().expect("tempdir");
    let ledger: Arc<dyn LiveLedger> =
        Arc::new(super::super::ledger::fs::FsLiveLedger::open(root.path()).expect("ledger"));
    let long_ago = time::OffsetDateTime::now_utc() - time::Duration::days(3);
    let mut sessions = Vec::new();
    for label in ["stale", "owned"] {
        let session_id = LiveSessionId::new(uuid::Uuid::new_v4()).expect("session id");
        let manifest: SessionManifest = serde_json::from_value(serde_json::json!({
            "sessionId": session_id, "seatId": "architect", "sliceId": "architect-engine",
            "projectId": "odin", "provider": "openai-codex", "model": "gpt-6-astra",
            "title": null, "targetNode": "laptop", "openTab": false
        }))
        .expect("manifest");
        ledger
            .create_session(manifest.clone())
            .await
            .expect("create");
        let epoch = odin_domain::huginn::SessionEpoch::new(1);
        for (index, body) in [
            LiveEventBody::SessionOpened(odin_domain::huginn::SessionOpened {
                manifest: Box::new(manifest),
            }),
            LiveEventBody::SessionStateChanged(SessionStateChanged {
                previous: LiveSessionState::Starting,
                current: LiveSessionState::Idle,
                reason: None,
            }),
        ]
        .into_iter()
        .enumerate()
        {
            ledger
                .append(
                    epoch,
                    NewLiveEvent {
                        session_id,
                        event_id: EventId::new(format!("{label}-{index}")).expect("event id"),
                        occurred_at: long_ago,
                        body,
                    },
                )
                .await
                .expect("append");
        }
        sessions.push(session_id);
    }
    let supervisor =
        LiveSupervisor::discover(Arc::clone(&ledger), Arc::new(SucceedLaunch), 8, None)
            .await
            .expect("discover");
    let now = time::OffsetDateTime::now_utc();
    let (stale, owned) = (sessions[0], sessions[1]);

    let outcome = supervisor
        .settle_at_start(stale, false, now)
        .await
        .expect("settle");
    assert!(
        matches!(
            outcome,
            StartSettlement::Settled {
                previous: LiveSessionState::Idle,
                ..
            }
        ),
        "{outcome:?}"
    );
    let history = ledger
        .history(HistoryQuery {
            session_id: stale,
            after: EventSeq::new(0),
            limit: NonZeroU16::new(16).unwrap(),
        })
        .await
        .expect("history");
    let ended = history.events.iter().filter(|event| {
        matches!(&event.body, LiveEventBody::SessionStateChanged(change)
            if change.current == LiveSessionState::Ended
                && change.reason.as_deref().is_some_and(|reason| reason.contains("no conversation or task owns it")))
    });
    assert_eq!(ended.count(), 1);
    assert_eq!(
        supervisor
            .settle_at_start(stale, false, now)
            .await
            .expect("again"),
        StartSettlement::Terminal(LiveSessionState::Ended),
        "a settled session is terminal, never settled twice"
    );
    assert_eq!(
        supervisor
            .settle_at_start(owned, true, now)
            .await
            .expect("owned"),
        StartSettlement::Resumable,
        "a conversation's vehicle is never ended by settlement"
    );
}

/// A backend whose stop fails closed, as the OMP bridge does when the
/// pump returns an exit record without an observed root status.
struct UnprovenStopBackend;

#[async_trait]
impl LiveControlBackend for UnprovenStopBackend {
    async fn bridge_ready(&self) -> bool {
        true
    }
    async fn prompt(
        &self,
        message: &LiveMessage,
        owner_text: Option<&str>,
    ) -> Result<(), LiveError> {
        NullBackend.prompt(message, owner_text).await
    }
    async fn follow_up(
        &self,
        message: &LiveMessage,
        owner_text: Option<&str>,
    ) -> Result<(), LiveError> {
        NullBackend.follow_up(message, owner_text).await
    }
    async fn steer(&self, message: &LiveMessage) -> Result<(), LiveError> {
        NullBackend.steer(message).await
    }
    async fn pause(&self) -> Result<(), LiveError> {
        Ok(())
    }
    async fn resume(&self) -> Result<(), LiveError> {
        Ok(())
    }
    async fn checkpoint(&self) -> Result<(), LiveError> {
        Ok(())
    }
    async fn restart(&self) -> Result<(), LiveError> {
        Ok(())
    }
    async fn rehome(&self, _: &NodeId) -> Result<(), LiveError> {
        Ok(())
    }
    async fn set_model(&self, _: &ProviderName, _: &ModelName) -> Result<(), LiveError> {
        Ok(())
    }
    async fn abort_turn(&self) -> Result<(), LiveError> {
        Ok(())
    }
    async fn abort_session(&self) -> Result<(), LiveError> {
        Err(LiveError::unavailable(
            "omp_bridge",
            "the fixture bridge is down",
        ))
    }
    async fn shutdown(&self) -> Result<(), LiveError> {
        Err(LiveError::unavailable(
            "omp_bridge",
            "the fixture bridge is down",
        ))
    }
    async fn decide_permission(
        &self,
        _: &PermissionRequestId,
        _: PermissionDecision,
    ) -> Result<(), LiveError> {
        Ok(())
    }
    async fn decide_approval(
        &self,
        _: &ApprovalId,
        _: u64,
        _: ApprovalDecision,
    ) -> Result<(), LiveError> {
        Ok(())
    }
}

struct UnprovenStopLaunch;

#[async_trait]
impl LiveSessionLauncher for UnprovenStopLaunch {
    fn harness_turns(&self) -> Option<std::sync::Arc<crate::live::harness::HarnessTurns>> {
        None
    }

    async fn open(
        &self,
        _: &SessionManifest,
        _: odin_domain::huginn::SessionEpoch,
        _: bool,
    ) -> Result<SessionRuntime, LiveError> {
        Ok(SessionRuntime {
            control: Arc::new(UnprovenStopBackend),
            terminal: None,
            observations: None,
            failed_notices: None,
        })
    }
}

/// The failed end still journals `Ended`, and the exited actor leaves the
/// live roster.
#[tokio::test]
async fn a_failed_end_still_ends_the_session_and_its_exited_actor_leaves_the_roster() {
    let root = tempfile::tempdir().expect("tempdir");
    let ledger: Arc<dyn LiveLedger> =
        Arc::new(super::super::ledger::fs::FsLiveLedger::open(root.path()).expect("ledger"));
    let supervisor =
        LiveSupervisor::new(Arc::clone(&ledger), Arc::new(UnprovenStopLaunch), 256, None);
    let request = bound_seat(&supervisor, 4).await;
    let opened = supervisor.open(request).await.expect("open");
    let actor = supervisor.actor(opened.session_id).await.expect("actor");

    assert!(
        actor.end().await.is_err(),
        "the unproven teardown is reported"
    );

    assert!(
        matches!(
            supervisor.actor(opened.session_id).await,
            Err(LiveError::NotFound { .. })
        ),
        "an exited actor must not read as a live session"
    );
    let journaled = supervisor
        .terminal_summary(opened.session_id)
        .await
        .expect("journal")
        .expect("terminal summary");
    assert_eq!(journaled.state, LiveSessionState::Ended);
    assert!(
        !supervisor
            .summaries()
            .await
            .expect("summaries")
            .iter()
            .any(|summary| summary.session_id == opened.session_id
                && summary.state != LiveSessionState::Ended),
        "the roster no longer lists it as live"
    );
}

#[tokio::test]
async fn parked_report_missing_admission_refuses_old_intent_then_delivers_fresh_once() {
    let root = tempfile::tempdir().expect("tempdir");
    let ledger: Arc<dyn LiveLedger> =
        Arc::new(super::super::ledger::fs::FsLiveLedger::open(root.path()).expect("ledger"));
    let supervisor = LiveSupervisor::new(Arc::clone(&ledger), Arc::new(SucceedLaunch), 256, None);
    let request = bound_seat(&supervisor, 4).await;
    let opened = supervisor.open(request).await.expect("open");
    // The owner has persisted this exact intent, but has NOT admitted it
    // into the FS command journal when the daemon dies.
    let pending = parked_prompt(opened.session_id, &opened);
    assert!(ledger.command(&pending).await.expect("lookup").is_none());
    drop(supervisor);
    drop(ledger);

    let ledger: Arc<dyn LiveLedger> =
        Arc::new(super::super::ledger::fs::FsLiveLedger::open(root.path()).expect("reopen"));
    let backend = support::InterruptedDispatch::new(0);
    backend.recovering.store(true, Ordering::SeqCst);
    let recovered = LiveSupervisor::discover(
        Arc::clone(&ledger),
        Arc::new(support::InterruptedDispatchLaunch(backend.clone())),
        256,
        None,
    )
    .await
    .expect("discover");
    bound_seat(&recovered, 4).await;
    assert!(recovered
        .parked(opened.session_id)
        .await
        .expect("lookup")
        .is_some());
    assert!(ledger
        .command(&pending)
        .await
        .expect("durable absence")
        .is_none());
    assert!(
        matches!(
            recovered.recover_parked_command(pending.clone()).await,
            Err(LiveError::Conflict { code, .. }) if code == "session_parked"
        ),
        "ordinary parked prompts retain their public refusal"
    );
    let receipt = recovered
        .recover_parked_report_command(pending.clone())
        .await
        .expect("recover missing report admission");
    assert!(
        matches!(receipt, CommandReceipt::Rejected { .. }),
        "{receipt:?}"
    );
    assert_eq!(backend.sends.load(Ordering::SeqCst), 0);
    assert!(ledger
        .command(&pending)
        .await
        .expect("old intent remains unadmitted")
        .is_none());

    let actor = recovered
        .actor(opened.session_id)
        .await
        .expect("recovered actor");
    let summary = actor.summary().expect("summary");
    assert_eq!(
        summary.epoch,
        opened.epoch.checked_increment().expect("next epoch")
    );
    // Only after observing Refused may the owner persist a new command id
    // at the fresh target. It never rebinds the original durable intent.
    let mut fresh = parked_prompt(opened.session_id, &summary);
    fresh.command_id =
        odin_domain::CommandId::new(format!("{:0<128}", "fresh-report")).expect("fresh id");
    assert!(matches!(
        actor.command(fresh.clone()).await.expect("deliver"),
        CommandReceipt::Accepted { .. }
    ));
    assert!(matches!(
        actor.command(fresh).await.expect("replay"),
        CommandReceipt::Duplicate { .. }
    ));
    assert!(matches!(
        recovered
            .recover_parked_report_command(pending)
            .await
            .expect("old retry"),
        CommandReceipt::Rejected { .. }
    ));
    assert_eq!(
        backend.sends.load(Ordering::SeqCst),
        1,
        "exactly one delivery"
    );
    assert_eq!(
        actor.summary().expect("summary").epoch,
        summary.epoch,
        "a late recovery retry never reclaims the live actor"
    );
}

#[tokio::test]
async fn failed_fresh_launch_can_resume_the_original_command_after_restart() {
    use crate::live::rollover::{FreshBriefSources, RolloverPolicy};
    use crate::live::supervisor::FreshPlacement;
    use odin_domain::huginn::LiveContentBlock;

    struct FailSuccessorOnce(AtomicUsize);
    #[async_trait]
    impl LiveSessionLauncher for FailSuccessorOnce {
        fn harness_turns(&self) -> Option<Arc<crate::live::harness::HarnessTurns>> {
            None
        }
        async fn open(
            &self,
            _: &SessionManifest,
            _: SessionEpoch,
            _: bool,
        ) -> Result<SessionRuntime, LiveError> {
            if self.0.fetch_add(1, Ordering::SeqCst) == 1 {
                return Err(unavailable("successor launch failed once"));
            }
            Ok(SessionRuntime {
                control: Arc::new(NullBackend),
                terminal: None,
                observations: None,
                failed_notices: None,
            })
        }
    }

    let root = tempfile::tempdir().unwrap();
    let launcher = Arc::new(FailSuccessorOnce(AtomicUsize::new(0)));
    let ledger: Arc<dyn LiveLedger> = Arc::new(FsLiveLedger::open(root.path()).unwrap());
    let supervisor = LiveSupervisor::new(Arc::clone(&ledger), launcher.clone(), 256, None);
    let request = bound_seat(&supervisor, 4).await;
    let placed = FreshPlacement {
        project_id: request.project_id.clone(),
        slice_id: request.slice_id.clone(),
        target_node: request.target_node.clone(),
        open_tab: request.open_tab,
        served_revision: request.served_revision,
    };
    let opened = supervisor.open(request).await.unwrap();
    let summary = supervisor
        .actor(opened.session_id)
        .await
        .unwrap()
        .summary()
        .unwrap();
    let owner = "retain exact information across restart";
    let command = LiveCommand {
        command_id: odin_domain::CommandId::new("fresh-restart-owner").unwrap(),
        session_id: opened.session_id,
        expected_epoch: summary.epoch,
        expected_event_head: Some(summary.event_head),
        body: LiveCommandBody::Prompt {
            message: LiveMessage::new(vec![LiveContentBlock::Text(owner.to_owned())]).unwrap(),
            owner_text: Some(owner.to_owned()),
            wake: false,
        },
    };
    let policy = RolloverPolicy {
        fresh_on_new_information: true,
        ..RolloverPolicy::default()
    };
    let sources = FreshBriefSources {
        owner_text: owner.to_owned(),
        ..FreshBriefSources::default()
    };
    assert!(supervisor
        .refuse_injection_when_fresh(
            opened.session_id,
            &policy,
            true,
            command.clone(),
            sources,
            placed,
        )
        .await
        .is_err());
    assert!(ledger.has_pending_fresh(opened.session_id).await.unwrap());
    drop(supervisor);
    drop(ledger);

    let reopened: Arc<dyn LiveLedger> = Arc::new(FsLiveLedger::open(root.path()).unwrap());
    let recovered = LiveSupervisor::discover(Arc::clone(&reopened), launcher, 256, None)
        .await
        .unwrap();
    bound_seat(&recovered, 4).await;
    let receipt = recovered
        .resume_fresh_command(&command)
        .await
        .unwrap()
        .unwrap();
    assert!(
        matches!(receipt, CommandReceipt::Duplicate { ref command_id, prior_outcome: Some(_), .. }
        if *command_id == command.command_id)
    );
    assert!(!reopened.has_pending_fresh(opened.session_id).await.unwrap());
}
