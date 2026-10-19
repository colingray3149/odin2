//! Durable actor transitions, control outcomes and recovery invariants.

use std::num::NonZeroU16;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use odin_domain::huginn::{
    AbortScope, ApprovalDecision, CommandFailure, CommandOutcome, CommandReceipt, EventSeq,
    HistoryQuery, LiveCommand, LiveCommandBody, LiveError, LiveEventBody, LiveMessage,
    LiveSessionId, LiveSessionState, LiveSessionSummary, ModelName, PermissionDecision,
    PermissionRequestId, ProviderName, SessionEpoch, SessionManifest, SessionOpened,
    SessionStateChanged, TerminalSeq,
};
use odin_domain::{ApprovalId, CommandId, EventId, NodeId, ProjectId, SeatId, SliceId};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::live::control::{ControlExecutor, LiveControlBackend};
use crate::live::ledger::fs::FsLiveLedger;
use crate::live::ledger::{LiveLedger, NewLiveEvent};
use crate::live::zellij::{CapturedTerminal, ZellijLiveAdapter, ZellijPane};

use super::{unavailable, SessionActor, SessionActorHandle};

/// One recorded `rollover_fresh` call: the refusing event alongside the
/// journaled model selection the rollover carried (`None` when the fresh
/// incarnation composes from the launch pair).
type RecordedRollover = (u64, Option<(ProviderName, ModelName)>);

#[derive(Default)]
struct FakeBackend {
    abort_session_calls: AtomicU64,
    abort_turn_calls: AtomicU64,
    shutdown_calls: AtomicU64,
    prompt_calls: AtomicU64,
    restart_calls: AtomicU64,
    /// Every applied set_model in call order, so recovery re-asserts are
    /// observable alongside operator commands.
    set_models: Mutex<Vec<(ProviderName, ModelName)>>,
    /// When set, abort_turn refuses like a backend whose cancellation is
    /// rejected — the give-up must journal the typed failure.
    fail_abort_turn: AtomicBool,
    /// When set, steer parks until `steer_release` fires, like a backend
    /// that never answers the correlated RPC reply.
    steer_blocked: AtomicBool,
    steer_release: tokio::sync::Notify,
    steer_calls: AtomicU64,
    /// When set, the backend reads not-ready: a queued failure notice
    /// against a ready backend is deliberately ignored, so proving the
    /// Failed route needs the ready flag down, like a dead pinned child.
    backend_not_ready: AtomicBool,
    /// When set, prompt parks until `prompt_release` fires, like a backend
    /// that never acknowledges the initial journaled dispatch.
    prompt_blocked: AtomicBool,
    prompt_release: tokio::sync::Notify,
    /// Records model selection at rollover, before any reinjection turn.
    rollovers: Mutex<Vec<RecordedRollover>>,
    /// Reclaims handed back per rollover, tracking the journal's epoch
    /// (the fixture session opens at 1, so the Nth rollover reclaims to
    /// N+1).
    rollover_epoch: AtomicU64,
    identified: Mutex<std::collections::BTreeMap<CommandId, bool>>,
    identified_sends: AtomicU64,
}
#[async_trait]
impl LiveControlBackend for FakeBackend {
    fn supports_identity_safe_dispatch(&self) -> bool {
        true
    }

    async fn message_outcome(&self, command_id: &CommandId) -> Result<Option<bool>, LiveError> {
        Ok(self
            .identified
            .lock()
            .map_err(|_| unavailable())?
            .get(command_id)
            .copied())
    }

    async fn dispatch_message(
        &self,
        command_id: &CommandId,
        message: &LiveMessage,
        follow_up: bool,
    ) -> Result<bool, LiveError> {
        if let Some(delivered) = self
            .identified
            .lock()
            .map_err(|_| unavailable())?
            .get(command_id)
            .copied()
        {
            return Ok(delivered);
        }
        self.identified_sends.fetch_add(1, Ordering::SeqCst);
        if follow_up {
            self.follow_up(message).await?;
        } else {
            self.prompt(message).await?;
        }
        self.identified
            .lock()
            .map_err(|_| unavailable())?
            .insert(command_id.clone(), true);
        Ok(true)
    }

    async fn bridge_ready(&self) -> bool {
        !self.backend_not_ready.load(Ordering::SeqCst)
    }

    async fn prompt(&self, _message: &LiveMessage) -> Result<(), LiveError> {
        self.prompt_calls.fetch_add(1, Ordering::SeqCst);
        if self.prompt_blocked.load(Ordering::SeqCst) {
            // Park like a backend that never acknowledges the dispatch;
            // the declared turn budget — never this task — must end the
            // initial dispatch wait.
            self.prompt_release.notified().await;
        }
        Ok(())
    }

    async fn follow_up(&self, _message: &LiveMessage) -> Result<(), LiveError> {
        Ok(())
    }

    async fn steer(&self, _message: &LiveMessage) -> Result<(), LiveError> {
        self.steer_calls.fetch_add(1, Ordering::SeqCst);
        if self.steer_blocked.load(Ordering::SeqCst) {
            // Park like a backend that never answers; the declared turn
            // budget — never this task — must end the wait.
            self.steer_release.notified().await;
        }
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

    async fn restart(&self) -> Result<(), LiveError> {
        self.restart_calls.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }

    async fn rollover_fresh(
        &self,
        refusal_event: u64,
        selected_model: Option<(&ProviderName, &ModelName)>,
    ) -> Result<i64, LiveError> {
        self.rollovers.lock().map_err(|_| unavailable())?.push((
            refusal_event,
            selected_model.map(|(provider, model)| (provider.clone(), model.clone())),
        ));
        Ok(i64::try_from(self.rollover_epoch.fetch_add(1, Ordering::SeqCst) + 2).unwrap_or(2))
    }

    async fn rehome(&self, _target_node: &NodeId) -> Result<(), LiveError> {
        Ok(())
    }

    async fn abort_turn(&self) -> Result<(), LiveError> {
        self.abort_turn_calls.fetch_add(1, Ordering::SeqCst);
        if self.fail_abort_turn.load(Ordering::SeqCst) {
            return Err(LiveError::Unavailable {
                code: "fixture-abort-refused".to_owned(),
            });
        }
        Ok(())
    }

    async fn abort_session(&self) -> Result<(), LiveError> {
        self.abort_session_calls.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }

    async fn shutdown(&self) -> Result<(), LiveError> {
        self.shutdown_calls.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }

    async fn set_model(&self, provider: &ProviderName, model: &ModelName) -> Result<(), LiveError> {
        self.set_models
            .lock()
            .map_err(|_| unavailable())?
            .push((provider.clone(), model.clone()));
        Ok(())
    }

    async fn decide_permission(
        &self,
        _request_id: &PermissionRequestId,
        _decision: PermissionDecision,
    ) -> Result<(), LiveError> {
        Ok(())
    }

    async fn decide_approval(
        &self,
        _approval_id: &ApprovalId,
        _expected_revision: u64,
        _decision: ApprovalDecision,
    ) -> Result<(), LiveError> {
        Ok(())
    }
}

/// Deliberately inherits the trait's identity-blind dispatch adapter, just
/// like process and terminal controls. Count effects before losing the reply.
#[derive(Default)]
struct NonIdentityBackend {
    calls: AtomicU64,
    lose_reply: AtomicBool,
    controls: FakeBackend,
}

#[async_trait]
impl LiveControlBackend for NonIdentityBackend {
    async fn prompt(&self, _: &LiveMessage) -> Result<(), LiveError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if self.lose_reply.load(Ordering::SeqCst) {
            return Err(LiveError::Unavailable {
                code: "reply_lost_after_effect".to_owned(),
            });
        }
        Ok(())
    }
    async fn follow_up(&self, message: &LiveMessage) -> Result<(), LiveError> {
        self.prompt(message).await
    }
    async fn steer(&self, message: &LiveMessage) -> Result<(), LiveError> {
        self.controls.steer(message).await
    }
    async fn pause(&self) -> Result<(), LiveError> {
        self.controls.pause().await
    }
    async fn resume(&self) -> Result<(), LiveError> {
        self.controls.resume().await
    }
    async fn checkpoint(&self) -> Result<(), LiveError> {
        self.controls.checkpoint().await
    }
    async fn restart(&self) -> Result<(), LiveError> {
        self.controls.restart().await
    }
    async fn rehome(&self, node: &NodeId) -> Result<(), LiveError> {
        self.controls.rehome(node).await
    }
    async fn set_model(&self, provider: &ProviderName, model: &ModelName) -> Result<(), LiveError> {
        self.controls.set_model(provider, model).await
    }
    async fn abort_turn(&self) -> Result<(), LiveError> {
        self.controls.abort_turn().await
    }
    async fn abort_session(&self) -> Result<(), LiveError> {
        self.controls.abort_session().await
    }
    async fn shutdown(&self) -> Result<(), LiveError> {
        self.controls.shutdown().await
    }
    async fn decide_permission(
        &self,
        id: &PermissionRequestId,
        decision: PermissionDecision,
    ) -> Result<(), LiveError> {
        self.controls.decide_permission(id, decision).await
    }
    async fn decide_approval(
        &self,
        id: &ApprovalId,
        revision: u64,
        decision: ApprovalDecision,
    ) -> Result<(), LiveError> {
        self.controls.decide_approval(id, revision, decision).await
    }
    async fn bridge_ready(&self) -> bool {
        self.controls.bridge_ready().await
    }
}

#[tokio::test]
async fn identity_blind_backend_dispatches_initial_messages_but_never_replays_incomplete_effects() {
    for follow_up in [false, true] {
        for lose_reply in [false, true] {
            let backend = Arc::new(NonIdentityBackend::default());
            backend.lose_reply.store(lose_reply, Ordering::SeqCst);
            let fixture = spawn_fixture_with_backend(None, None, Some(backend.clone())).await;
            if follow_up {
                fixture
                    .handle
                    .append(LiveEventBody::SessionStateChanged(SessionStateChanged {
                        previous: LiveSessionState::Idle,
                        current: LiveSessionState::Running,
                        reason: None,
                    }))
                    .await
                    .unwrap();
            }
            let message = LiveMessage::new(vec![odin_domain::huginn::LiveContentBlock::Text(
                "answer".to_owned(),
            )])
            .unwrap();
            let command = LiveCommand {
                command_id: CommandId::new("command:identity-blind").unwrap(),
                session_id: fixture.session_id,
                expected_epoch: fixture.epoch,
                expected_event_head: None,
                body: if follow_up {
                    LiveCommandBody::FollowUp { message }
                } else {
                    LiveCommandBody::Prompt { message }
                },
            };
            let initial = fixture.handle.command(command.clone()).await;
            if lose_reply {
                assert!(
                    matches!(initial, Err(LiveError::Unavailable { code }) if code == "reply_lost_after_effect")
                );
            } else {
                assert!(matches!(initial.unwrap(), CommandReceipt::Accepted { .. }));
            }
            assert_eq!(backend.calls.load(Ordering::SeqCst), 1);
            // Even a now-responsive backend cannot safely repeat an effect
            // whose initial reply was lost; leave its admission unresolved.
            backend.lose_reply.store(false, Ordering::SeqCst);
            for _ in 0..2 {
                let replay = fixture.handle.command(command.clone()).await.unwrap();
                match replay {
                    CommandReceipt::Duplicate { prior_outcome, .. } => {
                        if lose_reply {
                            assert!(prior_outcome.is_none());
                        } else {
                            assert!(matches!(
                                prior_outcome.as_deref(),
                                Some(CommandOutcome::Applied { .. })
                            ));
                        }
                    }
                    other => panic!("expected duplicate, got {other:?}"),
                }
            }
            assert_eq!(backend.calls.load(Ordering::SeqCst), 1);
            let admission = fixture.ledger.command(&command).await.unwrap().unwrap();
            assert!(
                matches!(admission.receipt, CommandReceipt::Duplicate { prior_outcome, .. } if prior_outcome.is_none() == lose_reply)
            );
            fixture.handle.stop().await.unwrap();
        }
    }
}

#[derive(Default)]
struct FakePane {
    terminate_calls: AtomicU64,
    fail_terminate: AtomicBool,
}

#[async_trait]
impl ZellijPane for FakePane {
    async fn capture(&self) -> Result<CapturedTerminal, LiveError> {
        Err(unavailable())
    }

    async fn write_input(&self, _operation_id: &CommandId, _bytes: &[u8]) -> Result<(), LiveError> {
        Err(unavailable())
    }

    async fn resize(
        &self,
        _operation_id: &CommandId,
        _columns: NonZeroU16,
        _rows: NonZeroU16,
    ) -> Result<(), LiveError> {
        Err(unavailable())
    }

    async fn terminate(&self) -> Result<(), LiveError> {
        self.terminate_calls.fetch_add(1, Ordering::SeqCst);
        if self.fail_terminate.load(Ordering::SeqCst) {
            Err(unavailable())
        } else {
            Ok(())
        }
    }
}

pub(crate) struct Fixture {
    pub(crate) handle: SessionActorHandle,
    pub(crate) session_id: LiveSessionId,
    pub(crate) epoch: SessionEpoch,
    pub(crate) ledger: Arc<FsLiveLedger>,
    backend: Arc<FakeBackend>,
    pane: Option<Arc<FakePane>>,
    pub(crate) root: std::path::PathBuf,
}

impl Fixture {
    /// The capture directory `ZellijLiveAdapter::open` created.
    fn capture_dir(&self) -> std::path::PathBuf {
        self.root.join("terminal").join(self.session_id.to_string())
    }
}

static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(0);

async fn spawn_fixture(pane: Option<Arc<FakePane>>) -> Fixture {
    spawn_fixture_with_budget(pane, None).await
}

async fn spawn_fixture_with_budget(
    pane: Option<Arc<FakePane>>,
    turn_budget: Option<std::time::Duration>,
) -> Fixture {
    spawn_fixture_with_backend(pane, turn_budget, None).await
}

/// Share the real actor and filesystem ledger with terminal process tests;
/// the backend is constructed with this actor's actual manifest and root.
pub(crate) async fn spawn_fixture_with_control(
    make_backend: impl FnOnce(&SessionManifest, &std::path::Path) -> Arc<dyn LiveControlBackend>,
) -> Fixture {
    spawn_fixture_with_backend_factory(None, None, |manifest, root| {
        Some(make_backend(manifest, root))
    })
    .await
}

async fn spawn_fixture_with_backend(
    pane: Option<Arc<FakePane>>,
    turn_budget: Option<std::time::Duration>,
    override_backend: Option<Arc<dyn LiveControlBackend>>,
) -> Fixture {
    spawn_fixture_with_backend_factory(pane, turn_budget, |_, _| override_backend).await
}

async fn spawn_fixture_with_backend_factory(
    pane: Option<Arc<FakePane>>,
    turn_budget: Option<std::time::Duration>,
    make_backend: impl FnOnce(&SessionManifest, &std::path::Path) -> Option<Arc<dyn LiveControlBackend>>,
) -> Fixture {
    let root = std::env::temp_dir().join(format!(
        "odin-omp-session-actor-{}-{}",
        std::process::id(),
        NEXT_FIXTURE.fetch_add(1, Ordering::SeqCst),
    ));
    let ledger = Arc::new(FsLiveLedger::open(&root).expect("live ledger opens"));
    let session_id = LiveSessionId::new(Uuid::new_v4()).expect("session id");
    let manifest = SessionManifest {
        session_id,
        seat_id: SeatId::new("seat:fixture").expect("seat id"),
        slice_id: SliceId::new("slice:fixture").expect("slice id"),
        project_id: ProjectId::new("project:fixture").expect("project id"),
        provider: ProviderName::new("fixture").expect("provider name"),
        model: ModelName::new("fixture-model").expect("model name"),
        title: None,
        target_node: NodeId::new("node:fixture").expect("node id"),
        open_tab: false,
        workload: None,
        served_revision: None,
        harness: None,
    };
    ledger
        .create_session(manifest.clone())
        .await
        .expect("session created");
    let epoch = SessionEpoch::new(1);
    let opened = ledger
        .append(
            epoch,
            NewLiveEvent {
                session_id,
                event_id: EventId::new(format!("opened:{session_id}")).expect("event id"),
                occurred_at: OffsetDateTime::now_utc(),
                body: LiveEventBody::SessionOpened(SessionOpened {
                    manifest: Box::new(manifest.clone()),
                }),
            },
        )
        .await
        .expect("opened event");
    let summary = LiveSessionSummary {
        session_id,
        epoch,
        seat_id: manifest.seat_id.clone(),
        provider: manifest.provider.clone(),
        model: manifest.model.clone(),
        title: None,
        state: LiveSessionState::Idle,
        started_at: opened.occurred_at,
        updated_at: opened.occurred_at,
        failed_at: None,
        event_head: opened.sequence,
        terminal_head: TerminalSeq::new(0),
        pending_permission_count: 0,
    };
    let terminal = pane.as_ref().map(|pane| {
        Arc::new(
            ZellijLiveAdapter::open(
                root.join("terminal"),
                session_id,
                epoch,
                TerminalSeq::new(0),
                Arc::clone(pane) as Arc<dyn ZellijPane>,
            )
            .expect("terminal adapter opens"),
        )
    });
    let backend = Arc::new(FakeBackend::default());
    let override_backend = make_backend(&manifest, &root);
    let handle = SessionActor::spawn(
        summary,
        Arc::clone(&ledger) as Arc<dyn LiveLedger>,
        ControlExecutor::new(
            override_backend.unwrap_or_else(|| Arc::clone(&backend) as Arc<dyn LiveControlBackend>),
        ),
        terminal,
        tokio::runtime::Handle::current(),
        None,
        turn_budget,
    )
    .expect("session actor spawns");
    Fixture {
        handle,
        session_id,
        epoch,
        ledger,
        backend,
        pane,
        root,
    }
}

fn abort_session_command(fixture: &Fixture, command_id: &str) -> LiveCommand {
    LiveCommand {
        command_id: CommandId::new(command_id).expect("command id"),
        session_id: fixture.session_id,
        expected_epoch: fixture.epoch,
        expected_event_head: None,
        body: LiveCommandBody::Abort {
            scope: AbortScope::Session,
        },
    }
}
#[tokio::test]
async fn admitted_messages_recover_before_dispatch_and_settle_exact_identity_once() {
    for follow_up in [false, true] {
        let fixture = spawn_fixture(None).await;
        let message = LiveMessage::new(vec![odin_domain::huginn::LiveContentBlock::Text(
            "answer".to_owned(),
        )])
        .unwrap();
        let command = LiveCommand {
            command_id: CommandId::new("command:recover-before-dispatch").unwrap(),
            session_id: fixture.session_id,
            expected_epoch: fixture.epoch,
            expected_event_head: None,
            body: if follow_up {
                LiveCommandBody::FollowUp { message }
            } else {
                LiveCommandBody::Prompt { message }
            },
        };
        fixture.ledger.append_command(&command).await.unwrap();
        for _ in 0..2 {
            assert!(
                matches!(fixture.handle.command(command.clone()).await.unwrap(),
                CommandReceipt::Duplicate { prior_outcome: Some(outcome), .. }
                    if matches!(*outcome, CommandOutcome::Applied { .. }))
            );
        }
        assert_eq!(fixture.backend.identified_sends.load(Ordering::SeqCst), 1);
        fixture.handle.stop().await.unwrap();
    }
}

#[tokio::test]
async fn admitted_messages_reconcile_postdispatch_without_resending() {
    for follow_up in [false, true] {
        let fixture = spawn_fixture(None).await;
        let message = LiveMessage::new(vec![odin_domain::huginn::LiveContentBlock::Text(
            "answer".to_owned(),
        )])
        .unwrap();
        let command = LiveCommand {
            command_id: CommandId::new("command:recover-after-dispatch").unwrap(),
            session_id: fixture.session_id,
            expected_epoch: fixture.epoch,
            expected_event_head: None,
            body: if follow_up {
                LiveCommandBody::FollowUp { message }
            } else {
                LiveCommandBody::Prompt { message }
            },
        };
        fixture.ledger.append_command(&command).await.unwrap();
        fixture
            .backend
            .identified
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .insert(command.command_id.clone(), false);
        assert!(matches!(
            fixture.handle.command(command.clone()).await.unwrap(),
            CommandReceipt::Duplicate {
                prior_outcome: None,
                ..
            }
        ));
        fixture
            .backend
            .identified
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .insert(command.command_id.clone(), true);
        assert!(
            matches!(fixture.handle.command(command.clone()).await.unwrap(),
            CommandReceipt::Duplicate { prior_outcome: Some(outcome), .. }
                if matches!(*outcome, CommandOutcome::Applied { .. }))
        );
        assert_eq!(fixture.backend.identified_sends.load(Ordering::SeqCst), 0);
        assert_eq!(
            fixture.handle.summary().unwrap().state,
            LiveSessionState::Idle
        );
        fixture.handle.stop().await.unwrap();
    }
}

#[tokio::test]
async fn durable_command_replays_identity_before_epoch_validation() {
    let fixture = spawn_fixture(None).await;
    let message = LiveMessage::new(vec![odin_domain::huginn::LiveContentBlock::Text(
        "durable".to_owned(),
    )])
    .unwrap();
    let command = LiveCommand {
        command_id: CommandId::new("command:durable-prompt").unwrap(),
        session_id: fixture.session_id,
        expected_epoch: fixture.epoch,
        expected_event_head: None,
        body: LiveCommandBody::Prompt { message },
    };
    fixture.ledger.append_command(&command).await.unwrap();
    let outcome = CommandOutcome::Applied {
        command_id: command.command_id.clone(),
    };
    fixture
        .ledger
        .complete_command(command.command_id.clone(), outcome.clone())
        .await
        .unwrap();
    fixture.handle.recover().await.unwrap();
    assert_ne!(
        fixture.handle.summary().unwrap().epoch,
        command.expected_epoch
    );
    assert!(matches!(
        fixture.handle.command(command.clone()).await.unwrap(),
        CommandReceipt::Duplicate { prior_outcome: Some(prior), .. } if *prior == outcome
    ));

    let mut conflict = command.clone();
    conflict.body = LiveCommandBody::Prompt {
        message: LiveMessage::new(vec![odin_domain::huginn::LiveContentBlock::Text(
            "different".to_owned(),
        )])
        .unwrap(),
    };
    assert!(fixture.handle.command(conflict).await.is_err());
    let mut conflict = command.clone();
    conflict.expected_epoch = fixture.handle.summary().unwrap().epoch;
    assert!(fixture.handle.command(conflict).await.is_err());
    let mut conflict = command.clone();
    conflict.expected_event_head = Some(EventSeq::new(1));
    assert!(fixture.handle.command(conflict).await.is_err());

    let stale = LiveCommand {
        command_id: CommandId::new("command:stale-prompt").unwrap(),
        session_id: fixture.session_id,
        expected_epoch: fixture.epoch,
        expected_event_head: None,
        body: LiveCommandBody::Prompt {
            message: LiveMessage::new(vec![odin_domain::huginn::LiveContentBlock::Text(
                "stale".to_owned(),
            )])
            .unwrap(),
        },
    };
    assert!(matches!(
        fixture.handle.command(stale).await.unwrap(),
        CommandReceipt::Rejected { .. }
    ));
}

/// A journaled model choice rides INTO the rollover operation and is
/// re-asserted by the bridge after the respawn, BEFORE the reinjection
/// turn: the backend receives the selection with the rollover, and no
/// post-turn SetModel competes after it.
#[tokio::test]
async fn a_rollover_carries_the_journaled_model_selection_before_its_reinjection() {
    let fixture = spawn_fixture(None).await;
    let applied_set_models = || {
        fixture
            .backend
            .set_models
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .clone()
    };
    let recorded_rollovers = || {
        fixture
            .backend
            .rollovers
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .clone()
    };
    let switched = fixture
        .handle
        .command(LiveCommand {
            command_id: CommandId::new("odin.fixture:set-model").unwrap(),
            session_id: fixture.session_id,
            expected_epoch: fixture.epoch,
            expected_event_head: None,
            body: LiveCommandBody::SetModel {
                provider: ProviderName::new("gateway").unwrap(),
                model: ModelName::new("kimi-k28").unwrap(),
            },
        })
        .await
        .unwrap();
    assert!(matches!(switched, CommandReceipt::Accepted { .. }));
    assert_eq!(applied_set_models().len(), 1);

    let rolled = fixture.handle.rollover_fresh(31).await.unwrap();
    assert_eq!(rolled.epoch.get(), 2);
    assert_eq!(
        recorded_rollovers(),
        vec![(
            31,
            Some((
                ProviderName::new("gateway").unwrap(),
                ModelName::new("kimi-k28").unwrap()
            ))
        )],
        "the journaled selection rides into the rollover operation"
    );
    assert_eq!(
        applied_set_models().len(),
        1,
        "only the operator switch: no post-rollover SetModel competes after the reinjection"
    );

    // A session back on its launch pair carries no selection: the fresh
    // incarnation composes from the launch manifest as-is.
    fixture
        .handle
        .command(LiveCommand {
            command_id: CommandId::new("odin.fixture:set-model-back").unwrap(),
            session_id: fixture.session_id,
            expected_epoch: rolled.epoch,
            expected_event_head: None,
            body: LiveCommandBody::SetModel {
                provider: ProviderName::new("fixture").unwrap(),
                model: ModelName::new("fixture-model").unwrap(),
            },
        })
        .await
        .unwrap();
    fixture.handle.rollover_fresh(32).await.unwrap();
    assert_eq!(
        recorded_rollovers()[1],
        (32, None),
        "the launch pair needs no re-assert"
    );
}

#[tokio::test]
async fn confirmation_resolution_is_durable_and_old_waits_do_not_cross_recovery() {
    async fn question(handle: &SessionActorHandle, id: &str) {
        let raw = format!(
            "{{\"type\":\"extension_ui_request\",\"id\":\"{id}\",\"method\":\"confirm\",\"title\":\"Confirm\"}}\n"
        );
        let decoded = crate::frames::RpcFrameDecoder::default()
            .push_physical_line(raw.as_bytes())
            .unwrap()
            .unwrap();
        handle
            .ingest_omp(crate::bridge::ObservedFrame {
                class: crate::bridge::classify_frame(decoded.value()),
                decoded: Some(decoded),
                rejection: None,
                active_command: None,
                journal_failure: None,
            })
            .await
            .unwrap();
    }
    let fixture = spawn_fixture(None).await;
    question(&fixture.handle, "confirmation-1").await;
    let waiting = fixture.handle.summary().unwrap();
    assert_eq!(waiting.state, LiveSessionState::RequiresAction);
    assert_eq!(waiting.pending_permission_count, 1);
    let command_id = CommandId::new("command:confirmation-answer").unwrap();
    let receipt = fixture
        .handle
        .command(LiveCommand {
            command_id: command_id.clone(),
            session_id: fixture.session_id,
            expected_epoch: fixture.epoch,
            expected_event_head: None,
            body: LiveCommandBody::DecidePermission {
                request_id: PermissionRequestId::new("confirmation-1").unwrap(),
                decision: PermissionDecision::AllowOnce,
            },
        })
        .await
        .unwrap();
    assert!(matches!(receipt, CommandReceipt::Accepted { .. }));
    let settled = fixture.handle.summary().unwrap();
    assert_eq!(settled.state, LiveSessionState::Running);
    assert_eq!(settled.pending_permission_count, 0);
    assert!(journaled_bodies(&fixture).await.iter().any(|body| matches!(
        body, LiveEventBody::PermissionResolved(resolution)
            if resolution.command_id == command_id
                && resolution.request_id.as_str() == "confirmation-1"
    )));
    question(&fixture.handle, "confirmation-2").await;
    assert_eq!(
        fixture.handle.summary().unwrap().pending_permission_count,
        1
    );
    fixture.handle.recover().await.unwrap();
    assert_eq!(
        fixture.handle.summary().unwrap().pending_permission_count,
        0
    );
    fixture.handle.stop().await.unwrap();
}

async fn journaled_bodies(fixture: &Fixture) -> Vec<LiveEventBody> {
    let head = fixture
        .ledger
        .head(fixture.session_id)
        .await
        .expect("journal head");
    let page = fixture
        .ledger
        .history(HistoryQuery {
            session_id: fixture.session_id,
            after: EventSeq::new(0),
            limit: NonZeroU16::new(64).expect("history limit"),
        })
        .await
        .expect("journal history");
    assert_eq!(page.next_after, head);
    page.events.into_iter().map(|event| event.body).collect()
}

fn pane_terminate_calls(fixture: &Fixture) -> u64 {
    fixture
        .pane
        .as_ref()
        .map(|pane| pane.terminate_calls.load(Ordering::SeqCst))
        .unwrap_or(0)
}

/// The 120 s failed-pod grace anchors at the failure's own transition: a
/// late journaled event behind an already-failed session advances
/// `updated_at` but never moves `failed_at` (live 2026-10: a failed pod
/// that kept journaling was never released, only its Job deadline ended
/// it).
#[tokio::test]
async fn the_failed_instant_is_the_transition_not_the_newest_event() {
    use odin_domain::huginn::TextDelta;
    use odin_domain::TurnId;
    let fixture = spawn_fixture(Some(Arc::new(FakePane::default()))).await;
    fixture
        .backend
        .backend_not_ready
        .store(true, Ordering::SeqCst);
    fixture
        .handle
        .backend_failed("the pinned child is gone".to_owned())
        .await
        .expect("backend failure settles failed");
    let failed = fixture.handle.summary().expect("summary");
    assert_eq!(failed.state, LiveSessionState::Failed);
    let failed_at = failed.failed_at.expect("the failure instant is recorded");
    // The journal pins the failure event's own instant.
    let head = fixture
        .ledger
        .head(fixture.session_id)
        .await
        .expect("journal head");
    let page = fixture
        .ledger
        .history(HistoryQuery {
            session_id: fixture.session_id,
            after: EventSeq::new(0),
            limit: NonZeroU16::new(64).expect("history limit"),
        })
        .await
        .expect("journal history");
    let error_at = page
        .events
        .iter()
        .find(|event| event.sequence == head)
        .map(|event| event.occurred_at)
        .expect("the failure event");
    assert_eq!(Some(error_at), failed.failed_at);

    // A late frame behind the failed session journals on and advances
    // `updated_at`; the failure instant stays put.
    fixture
        .handle
        .append(LiveEventBody::AssistantDelta(TextDelta {
            turn_id: TurnId::new("turn:late").expect("turn id"),
            text: "a late annotated frame".to_owned(),
        }))
        .await
        .expect("late frame journals");
    let later = fixture.handle.summary().expect("summary");
    assert_eq!(later.state, LiveSessionState::Failed);
    assert_eq!(later.failed_at, Some(failed_at));
    assert!(later.updated_at >= failed.updated_at);
}

/// The failed-pod grace anchors the continuous `Failed` interval: leaving
/// `Failed` clears the instant, a re-failure anchors its own transition, and
/// later journaled frames keep it (live 2026-10: any traffic behind a failed
/// pod postponed its release indefinitely).
#[tokio::test]
async fn the_failed_instant_tracks_the_continuous_failed_interval() {
    use odin_domain::huginn::TextDelta;
    use odin_domain::TurnId;
    let fixture = spawn_fixture(Some(Arc::new(FakePane::default()))).await;
    fixture
        .backend
        .backend_not_ready
        .store(true, Ordering::SeqCst);
    fixture
        .handle
        .backend_failed("the pinned child is gone".to_owned())
        .await
        .expect("backend failure settles failed");
    assert!(
        fixture
            .handle
            .summary()
            .expect("summary")
            .failed_at
            .is_some(),
        "the failure instant is recorded"
    );

    // Recovery leaves `Failed`: the instant must not survive the interval.
    fixture
        .handle
        .append(LiveEventBody::SessionStateChanged(SessionStateChanged {
            previous: LiveSessionState::Failed,
            current: LiveSessionState::Idle,
            reason: Some("incarnation recovered in place".to_owned()),
        }))
        .await
        .expect("recovery journals");
    let recovered = fixture.handle.summary().expect("summary");
    assert_eq!(recovered.state, LiveSessionState::Idle);
    assert_eq!(
        recovered.failed_at, None,
        "leaving Failed clears the failed instant"
    );

    // A re-failure anchors at its own transition, never the stale instant.
    fixture
        .handle
        .backend_failed("the recovered child is gone".to_owned())
        .await
        .expect("re-failure settles failed");
    let refailed = fixture.handle.summary().expect("summary");
    assert_eq!(refailed.state, LiveSessionState::Failed);
    let refailed_at = refailed
        .failed_at
        .expect("the re-failure instant is recorded");

    // Later frames behind the re-failed session keep the new anchor.
    fixture
        .handle
        .append(LiveEventBody::AssistantDelta(TextDelta {
            turn_id: TurnId::new("turn:late").expect("turn id"),
            text: "a late annotated frame".to_owned(),
        }))
        .await
        .expect("late frame journals");
    let later = fixture.handle.summary().expect("summary");
    assert_eq!(later.state, LiveSessionState::Failed);
    assert_eq!(later.failed_at, Some(refailed_at));
    assert!(later.updated_at >= refailed.updated_at);
}

#[tokio::test]
async fn abort_session_journals_once_terminates_once_and_stop_is_idempotent() {
    let fixture = spawn_fixture(Some(Arc::new(FakePane::default()))).await;
    let command = abort_session_command(&fixture, "odin-omp:cmd:abort-once");
    let receipt = fixture
        .handle
        .command(command.clone())
        .await
        .expect("abort command");
    assert_eq!(
        receipt,
        CommandReceipt::Accepted {
            command_id: command.command_id.clone(),
        }
    );
    assert_eq!(
        fixture.handle.summary().expect("summary").state,
        LiveSessionState::Ended
    );
    let bodies = journaled_bodies(&fixture).await;
    assert_eq!(bodies.len(), 4);
    assert!(matches!(bodies[0], LiveEventBody::SessionOpened(_)));
    assert!(matches!(
        bodies[1],
        LiveEventBody::ControlAccepted(CommandReceipt::Accepted { .. })
    ));
    assert!(matches!(
        bodies[2],
        LiveEventBody::SessionStateChanged(SessionStateChanged {
            previous: LiveSessionState::Idle,
            current: LiveSessionState::Ended,
            ..
        })
    ));
    assert!(matches!(
        bodies[3],
        LiveEventBody::ControlCompleted(CommandOutcome::Applied { .. })
    ));
    assert_eq!(
        fixture.backend.abort_session_calls.load(Ordering::SeqCst),
        1
    );
    assert_eq!(fixture.backend.shutdown_calls.load(Ordering::SeqCst), 0);
    assert_eq!(pane_terminate_calls(&fixture), 1);

    fixture.handle.stop().await.expect("stop after abort");
    assert_eq!(
        fixture.backend.abort_session_calls.load(Ordering::SeqCst),
        1
    );
    assert_eq!(fixture.backend.shutdown_calls.load(Ordering::SeqCst), 0);
    assert_eq!(pane_terminate_calls(&fixture), 1);
}

#[tokio::test]
async fn duplicate_abort_replays_the_recorded_outcome_without_new_teardown() {
    let fixture = spawn_fixture(Some(Arc::new(FakePane::default()))).await;
    let command = abort_session_command(&fixture, "odin-omp:cmd:abort-duplicate");
    let first = fixture
        .handle
        .command(command.clone())
        .await
        .expect("first command");
    assert_eq!(
        first,
        CommandReceipt::Accepted {
            command_id: command.command_id.clone(),
        }
    );
    let second = fixture
        .handle
        .command(command.clone())
        .await
        .expect("duplicate command");
    assert_eq!(
        second,
        CommandReceipt::Duplicate {
            command_id: command.command_id.clone(),
            prior_outcome: Some(Box::new(CommandOutcome::Applied {
                command_id: command.command_id.clone(),
            })),
        }
    );
    assert_eq!(
        fixture.backend.abort_session_calls.load(Ordering::SeqCst),
        1
    );
    assert_eq!(pane_terminate_calls(&fixture), 1);
    fixture.handle.stop().await.expect("stop after duplicate");
    assert_eq!(pane_terminate_calls(&fixture), 1);
}

#[tokio::test]
async fn live_stop_still_shuts_down_bridge_and_pane() {
    let fixture = spawn_fixture(Some(Arc::new(FakePane::default()))).await;
    fixture.handle.stop().await.expect("live stop");
    assert_eq!(fixture.backend.shutdown_calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        fixture.backend.abort_session_calls.load(Ordering::SeqCst),
        0
    );
    assert_eq!(pane_terminate_calls(&fixture), 1);
}

/// Ending retires the session; ordinary daemon shutdown preserves resumability.
#[tokio::test]
async fn ending_a_session_journals_ended_while_a_plain_stop_keeps_it_resumable() {
    let ended = spawn_fixture(Some(Arc::new(FakePane::default()))).await;
    let before = ended.handle.summary().expect("summary").state;
    ended.handle.end().await.expect("end");
    assert_eq!(
        ended.handle.summary().expect("summary").state,
        LiveSessionState::Ended
    );
    assert!(journaled_bodies(&ended).await.iter().any(|body| matches!(
        body,
        LiveEventBody::SessionStateChanged(SessionStateChanged {
            previous,
            current: LiveSessionState::Ended,
            ..
        }) if *previous == before
    )));

    let stopped = spawn_fixture(Some(Arc::new(FakePane::default()))).await;
    stopped.handle.stop().await.expect("stop");
    assert_eq!(stopped.handle.summary().expect("summary").state, before);
}

#[tokio::test]
async fn ending_a_session_removes_its_capture_dir_while_a_plain_stop_keeps_it() {
    let aborted = spawn_fixture(Some(Arc::new(FakePane::default()))).await;
    let capture = aborted.capture_dir();
    assert!(capture.is_dir(), "the adapter creates the capture dir");
    aborted
        .handle
        .command(abort_session_command(
            &aborted,
            "odin-omp:cmd:abort-capture",
        ))
        .await
        .expect("abort command");
    assert_eq!(
        aborted.handle.summary().expect("summary").state,
        LiveSessionState::Ended
    );
    assert!(!capture.exists(), "the abort removes the capture dir");

    let ended = spawn_fixture(Some(Arc::new(FakePane::default()))).await;
    let capture = ended.capture_dir();
    assert!(capture.is_dir());
    ended.handle.end().await.expect("end");
    assert!(
        !capture.exists(),
        "the delegator's end removes the capture dir"
    );

    let torn = spawn_fixture(Some(Arc::new(FakePane {
        fail_terminate: AtomicBool::new(true),
        ..FakePane::default()
    })))
    .await;
    let capture = torn.capture_dir();
    assert!(capture.is_dir());
    torn.handle
        .command(abort_session_command(
            &torn,
            "odin-omp:cmd:abort-capture-torn",
        ))
        .await
        .expect("abort command with a failing pane");
    assert_eq!(
        torn.handle.summary().expect("summary").state,
        LiveSessionState::Ended
    );
    assert!(
        !capture.exists(),
        "an unproven teardown still removes the capture dir"
    );

    let stopped = spawn_fixture(Some(Arc::new(FakePane::default()))).await;
    let capture = stopped.capture_dir();
    assert!(capture.is_dir());
    stopped.handle.stop().await.expect("stop");
    assert!(
        capture.is_dir(),
        "a plain stop keeps the resumable session's capture dir"
    );
}

#[tokio::test]
async fn failed_pane_teardown_records_failed_and_stop_surfaces_the_failure() {
    let pane = Arc::new(FakePane {
        fail_terminate: AtomicBool::new(true),
        ..FakePane::default()
    });
    let fixture = spawn_fixture(Some(pane)).await;
    let command = abort_session_command(&fixture, "odin-omp:cmd:abort-pane-failure");
    let receipt = fixture
        .handle
        .command(command.clone())
        .await
        .expect("abort command");
    assert_eq!(
        receipt,
        CommandReceipt::Accepted {
            command_id: command.command_id.clone(),
        }
    );
    assert_eq!(
        fixture.handle.summary().expect("summary").state,
        LiveSessionState::Ended
    );
    let bodies = journaled_bodies(&fixture).await;
    assert_eq!(bodies.len(), 4);
    assert!(matches!(
        &bodies[3],
        LiveEventBody::ControlCompleted(CommandOutcome::Failed { error, .. })
        if error.code == "terminate_failed"
    ));
    assert_eq!(fixture.backend.shutdown_calls.load(Ordering::SeqCst), 0);
    assert_eq!(pane_terminate_calls(&fixture), 1);

    fixture
        .handle
        .stop()
        .await
        .expect_err("pane failure must surface");
    assert_eq!(fixture.backend.shutdown_calls.load(Ordering::SeqCst), 0);
    assert_eq!(pane_terminate_calls(&fixture), 2);
}

#[tokio::test]
async fn idle_kernel_decision_starts_one_continuation_even_on_replay() {
    let fixture = spawn_fixture(None).await;
    let command = LiveCommand {
        command_id: CommandId::new("command:approval-continuation").unwrap(),
        session_id: fixture.session_id,
        expected_epoch: fixture.epoch,
        expected_event_head: None,
        body: LiveCommandBody::DecideApproval {
            approval_id: ApprovalId::new("approval:pending-tool").unwrap(),
            expected_revision: 1,
            decision: ApprovalDecision::Approve,
        },
    };
    assert!(matches!(
        fixture.handle.command(command.clone()).await.unwrap(),
        CommandReceipt::Accepted { .. }
    ));
    assert_eq!(
        fixture.handle.summary().unwrap().state,
        LiveSessionState::Running
    );
    assert_eq!(fixture.backend.prompt_calls.load(Ordering::SeqCst), 1);
    assert!(matches!(
        fixture.handle.command(command).await.unwrap(),
        CommandReceipt::Duplicate { .. }
    ));
    assert_eq!(fixture.backend.prompt_calls.load(Ordering::SeqCst), 1);
    fixture.handle.stop().await.unwrap();
}

#[tokio::test]
async fn ended_session_refuses_operator_and_internal_restart() {
    let fixture = spawn_fixture(None).await;
    fixture
        .handle
        .command(abort_session_command(
            &fixture,
            "command:end-before-recovery",
        ))
        .await
        .unwrap();
    let ended = fixture.handle.summary().unwrap();
    assert!(fixture.handle.recover().await.is_err());
    assert_eq!(fixture.backend.restart_calls.load(Ordering::SeqCst), 0);
    assert!(matches!(
        fixture
            .handle
            .command(LiveCommand {
                command_id: CommandId::new("command:restart-after-end").unwrap(),
                session_id: fixture.session_id,
                expected_epoch: ended.epoch,
                expected_event_head: None,
                body: LiveCommandBody::Restart,
            })
            .await
            .unwrap(),
        CommandReceipt::Rejected { .. }
    ));
    let observed = fixture.handle.summary().unwrap();
    assert_eq!(observed.state, LiveSessionState::Ended);
    assert_eq!(observed.epoch, ended.epoch);
    assert_eq!(fixture.backend.restart_calls.load(Ordering::SeqCst), 0);
    fixture.handle.stop().await.unwrap();
}

async fn ingest_lifecycle_frame(fixture: &Fixture, raw: &[u8]) {
    let decoded = crate::frames::RpcFrameDecoder::default()
        .push_physical_line(raw)
        .unwrap()
        .unwrap();
    fixture
        .handle
        .ingest_omp(crate::bridge::ObservedFrame {
            class: crate::bridge::classify_frame(decoded.value()),
            decoded: Some(decoded),
            rejection: None,
            active_command: None,
            journal_failure: None,
        })
        .await
        .unwrap();
}

// This is the actor/control ordering contract, not a simulation of terminal
// cancellation output. The terminal process tests exercise that producer.
#[tokio::test]
async fn applied_turn_abort_settles_idle_before_a_head_checked_prompt() {
    let fixture = spawn_fixture(None).await;
    let mut prompt = LiveCommand {
        command_id: CommandId::new("command:before-intentional-abort").unwrap(),
        session_id: fixture.session_id,
        expected_epoch: fixture.epoch,
        expected_event_head: None,
        body: LiveCommandBody::Prompt {
            message: LiveMessage::new(vec![odin_domain::huginn::LiveContentBlock::Text(
                "start a turn".to_owned(),
            )])
            .unwrap(),
        },
    };
    assert!(matches!(
        fixture.handle.command(prompt.clone()).await.unwrap(),
        CommandReceipt::Accepted { .. }
    ));
    let abort_id = CommandId::new("command:intentional-turn-abort").unwrap();
    assert!(matches!(
        fixture
            .handle
            .command(LiveCommand {
                command_id: abort_id.clone(),
                session_id: fixture.session_id,
                expected_epoch: fixture.epoch,
                expected_event_head: Some(fixture.handle.summary().unwrap().event_head),
                body: LiveCommandBody::Abort {
                    scope: AbortScope::CurrentTurn,
                },
            })
            .await
            .unwrap(),
        CommandReceipt::Accepted { .. }
    ));
    let settled = fixture.handle.summary().unwrap();
    assert_eq!(settled.state, LiveSessionState::Idle);
    assert_eq!(fixture.backend.abort_turn_calls.load(Ordering::SeqCst), 1);
    let bodies = journaled_bodies(&fixture).await;
    let applied = bodies
        .iter()
        .position(|body| {
            matches!(
                body,
                LiveEventBody::ControlCompleted(CommandOutcome::Applied { command_id })
                    if *command_id == abort_id
            )
        })
        .expect("abort Applied is durable");
    let idle = bodies
        .iter()
        .position(|body| {
            matches!(
                body,
                LiveEventBody::SessionStateChanged(change)
                    if change.previous == LiveSessionState::Running
                        && change.current == LiveSessionState::Idle
            )
        })
        .expect("abort settles Idle");
    assert!(
        idle < applied,
        "state is durable before the completion is published"
    );
    assert!(!bodies
        .iter()
        .any(|body| matches!(body, LiveEventBody::Error(_) | LiveEventBody::Result(_))));

    prompt.command_id = CommandId::new("command:after-intentional-abort").unwrap();
    prompt.expected_event_head = Some(settled.event_head);
    assert!(matches!(
        fixture.handle.command(prompt).await.unwrap(),
        CommandReceipt::Accepted { .. }
    ));
    assert_eq!(fixture.backend.prompt_calls.load(Ordering::SeqCst), 2);
    assert_eq!(
        fixture.handle.summary().unwrap().state,
        LiveSessionState::Running
    );
    fixture.handle.stop().await.unwrap();
}

#[tokio::test]
async fn terminal_provider_error_stays_failed_and_refuses_a_new_prompt() {
    let fixture = spawn_fixture(None).await;
    ingest_lifecycle_frame(&fixture, b"{\"type\":\"agent_start\"}\n").await;
    ingest_lifecycle_frame(
        &fixture,
        b"{\"type\":\"agent_end\",\"stopReason\":\"error\"}\n",
    )
    .await;
    let failed = fixture.handle.summary().unwrap();
    assert_eq!(failed.state, LiveSessionState::Failed);
    assert!(failed.failed_at.is_some());
    // A genuine provider failure is not an intentional cancellation. A later
    // success-shaped settle cannot erase it or publish a fabricated answer.
    ingest_lifecycle_frame(
        &fixture,
        b"{\"type\":\"agent_end\",\"stopReason\":\"stop\",\"messages\":[{\"role\":\"assistant\",\"content\":\"late answer\"}]}\n",
    )
    .await;
    let bodies = journaled_bodies(&fixture).await;
    assert_eq!(
        bodies
            .iter()
            .filter(|body| matches!(
                body, LiveEventBody::Error(error) if error.code == "turn_stopped_error"
            ))
            .count(),
        1
    );
    assert!(!bodies
        .iter()
        .any(|body| matches!(body, LiveEventBody::Result(_))));
    assert!(!bodies.iter().any(|body| matches!(
        body, LiveEventBody::SessionStateChanged(change)
            if change.current == LiveSessionState::Idle
    )));
    assert!(matches!(
        fixture
            .handle
            .command(LiveCommand {
                command_id: CommandId::new("command:prompt-after-terminal-error").unwrap(),
                session_id: fixture.session_id,
                expected_epoch: fixture.epoch,
                expected_event_head: Some(fixture.handle.summary().unwrap().event_head),
                body: LiveCommandBody::Prompt {
                    message: LiveMessage::new(vec![odin_domain::huginn::LiveContentBlock::Text(
                        "must not reach the backend".to_owned(),
                    )])
                    .unwrap(),
                },
            })
            .await
            .unwrap(),
        CommandReceipt::Rejected { .. }
    ));
    assert_eq!(fixture.backend.prompt_calls.load(Ordering::SeqCst), 0);
    let observed = fixture.handle.summary().unwrap();
    assert_eq!(observed.state, LiveSessionState::Failed);
    assert_eq!(observed.failed_at, failed.failed_at);
    fixture.handle.stop().await.unwrap();
}

#[tokio::test]
async fn session_abort_wins_over_a_late_successful_turn_settle() {
    let fixture = spawn_fixture(None).await;
    ingest_lifecycle_frame(&fixture, b"{\"type\":\"agent_start\"}\n").await;
    fixture
        .handle
        .command(abort_session_command(
            &fixture,
            "command:end-before-late-settle",
        ))
        .await
        .unwrap();
    let ended = fixture.handle.summary().unwrap();
    assert_eq!(ended.state, LiveSessionState::Ended);
    ingest_lifecycle_frame(
        &fixture,
        b"{\"type\":\"agent_end\",\"stopReason\":\"stop\",\"messages\":[{\"role\":\"assistant\",\"content\":\"late answer\"}]}\n",
    )
    .await;
    let observed = fixture.handle.summary().unwrap();
    assert_eq!(observed.state, LiveSessionState::Ended);
    assert_eq!(observed.event_head, ended.event_head);
    assert!(!journaled_bodies(&fixture)
        .await
        .iter()
        .any(|body| matches!(body, LiveEventBody::Result(_) | LiveEventBody::Error(_))));
    fixture.handle.stop().await.unwrap();
    assert_eq!(
        fixture.handle.summary().unwrap().state,
        LiveSessionState::Ended
    );
    assert_eq!(
        fixture.backend.abort_session_calls.load(Ordering::SeqCst),
        1
    );
    assert_eq!(fixture.backend.shutdown_calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn provider_round_end_does_not_finish_the_agent_loop() {
    let fixture = spawn_fixture(None).await;
    let mut decoder = crate::frames::RpcFrameDecoder::default();
    for kind in ["agent_start", "turn_start", "turn_end", "agent_end"] {
        let raw = format!("{{\"type\":\"{kind}\"}}\n");
        let decoded = decoder.push_physical_line(raw.as_bytes()).unwrap().unwrap();
        fixture
            .handle
            .ingest_omp(crate::bridge::ObservedFrame {
                class: crate::bridge::classify_frame(decoded.value()),
                decoded: Some(decoded),
                rejection: None,
                active_command: None,
                journal_failure: None,
            })
            .await
            .unwrap();
        assert_eq!(
            fixture.handle.summary().unwrap().state,
            if kind == "agent_end" {
                LiveSessionState::Idle
            } else {
                LiveSessionState::Running
            }
        );
    }
    fixture.handle.stop().await.unwrap();
}

#[tokio::test]
async fn provider_turn_error_is_durable_typed_failure_not_a_silent_empty_turn() {
    let fixture = spawn_fixture(None).await;

    async fn ingest(fixture: &Fixture, raw: &str) {
        let decoded = crate::frames::RpcFrameDecoder::default()
            .push_physical_line(raw.as_bytes())
            .unwrap()
            .unwrap();
        fixture
            .handle
            .ingest_omp(crate::bridge::ObservedFrame {
                class: crate::bridge::classify_frame(decoded.value()),
                decoded: Some(decoded),
                rejection: None,
                active_command: None,
                journal_failure: None,
            })
            .await
            .unwrap();
    }

    // Non-error turn settlement (a tool/control round, an operator abort)
    // carries no failure signal and must not classify: only the typed
    // `stopReason` discriminant does.
    ingest(&fixture, "{\"type\":\"agent_start\"}\n").await;
    ingest(&fixture, "{\"type\":\"turn_start\"}\n").await;
    ingest(&fixture, "{\"type\":\"turn_end\"}\n").await;
    ingest(&fixture, "{\"type\":\"turn_start\"}\n").await;
    ingest(
        &fixture,
        "{\"type\":\"turn_end\",\"message\":{\"role\":\"assistant\",\"stopReason\":\"aborted\",\"content\":[{\"type\":\"text\",\"text\":\"\"}]}}\n",
    )
    .await;
    assert!(
        !journaled_bodies(&fixture)
            .await
            .iter()
            .any(|body| matches!(body, LiveEventBody::Error(_))),
        "non-error turn_end frames must never classify as failure"
    );

    // Representative captured upstream provider failure (gateway HTTP 400
    // detail, secret-free): the pinned child emits an empty-text error
    // `message_end` and a `turn_end` carrying `stopReason: "error"` plus
    // `errorMessage`. The closing `agent_end` journals the durable typed
    // Error event the contract names for such a turn, then Failed.
    const UPSTREAM_400: &str = "litellm.BadRequestError: OpenAIException - Request is missing x-opencode-session and cannot be routed efficiently. Please see https://opencode.ai/docs/go/#where-can-i-use-it. Received Model Group=go-kimi\nAvailable Model Group Fallbacks=None";
    let error_message = format!(
        "{{\"role\":\"assistant\",\"provider\":\"litellm-gateway\",\"model\":\"go-kimi\",\
         \"content\":[{{\"type\":\"text\",\"text\":\"\"}}],\"stopReason\":\"error\",\
         \"errorMessage\":{}}}",
        serde_json::to_string(UPSTREAM_400).unwrap()
    );
    ingest(&fixture, "{\"type\":\"turn_start\"}\n").await;
    ingest(
        &fixture,
        &format!("{{\"type\":\"message_end\",\"message\":{error_message}}}\n"),
    )
    .await;
    ingest(
        &fixture,
        &format!("{{\"type\":\"turn_end\",\"message\":{error_message},\"toolResults\":[]}}\n"),
    )
    .await;
    ingest(&fixture, "{\"type\":\"agent_end\"}\n").await;

    let bodies = journaled_bodies(&fixture).await;
    assert!(
        !bodies
            .iter()
            .any(|body| matches!(body, LiveEventBody::AssistantMessage(_))),
        "the empty error message_end must not surface as an assistant message"
    );
    assert_provider_failure_stays_terminal(&fixture, &bodies, UPSTREAM_400);
    fixture.handle.stop().await.unwrap();
}

fn provider_failure_frames() -> (serde_json::Value, serde_json::Value, serde_json::Value) {
    let turn_end = serde_json::json!({
        "type": "turn_end",
        "message": {
            "role": "assistant",
            "stopReason": "error",
            "errorStatus": 500,
            "errorMessage": "upstream API connection failed",
            "content": [{"type": "text", "text": "Partial answer from a failed request."}]
        }
    });
    let agent_end = serde_json::json!({
        "type": "agent_end",
        "isTerminal": true,
        "yielded": true,
        "messages": [
            {"role": "user", "content": [{"type": "text", "text": "Perform one bounded task."}]},
            {
                "role": "assistant",
                "stopReason": "error",
                "errorStatus": 500,
                "errorMessage": "upstream API connection failed",
                "content": [{"type": "text", "text": "Partial answer from a failed request."}]
            }
        ]
    });
    let late_success = serde_json::json!({
        "type": "agent_end",
        "isTerminal": true,
        "messages": [{
            "role": "assistant",
            "stopReason": "stop",
            "content": [{"type": "text", "text": "late answer"}]
        }]
    });
    (turn_end, agent_end, late_success)
}

async fn ingest_json(fixture: &Fixture, frame: &serde_json::Value) {
    ingest_lifecycle_frame(fixture, format!("{frame}\n").as_bytes()).await;
}

/// The cross-crate failure contract consumers classify on: exactly one
/// `provider_turn_error` carrying the provider's own diagnostic, not
/// retryable as is, immediately followed by the explicit `Failed` transition.
fn assert_provider_failure_stays_terminal(
    fixture: &Fixture,
    bodies: &[LiveEventBody],
    diagnostic: &str,
) {
    let summary = fixture.handle.summary().unwrap();
    assert_eq!(summary.state, LiveSessionState::Failed);
    assert!(summary.failed_at.is_some());
    let errors: Vec<_> = bodies
        .iter()
        .enumerate()
        .filter_map(|(index, body)| match body {
            LiveEventBody::Error(error) => Some((index, error)),
            _ => None,
        })
        .collect();
    let [(at, error)] = errors.as_slice() else {
        panic!("exactly one typed failure diagnostic: {bodies:?}");
    };
    assert_eq!(error.code, "provider_turn_error");
    assert_eq!(error.message, diagnostic);
    assert!(!error.retryable, "{error:?}");
    assert!(
        matches!(
            bodies.get(at + 1),
            Some(LiveEventBody::SessionStateChanged(change))
                if change.current == LiveSessionState::Failed
        ),
        "the explicit Failed transition follows the error: {bodies:?}"
    );
    assert_eq!(
        bodies
            .iter()
            .filter(|body| matches!(
                body,
                LiveEventBody::SessionStateChanged(change)
                    if change.current == LiveSessionState::Failed
            ))
            .count(),
        1,
        "failed once: {bodies:?}"
    );
    assert!(
        !bodies
            .iter()
            .any(|body| matches!(body, LiveEventBody::Result(_))),
        "a failed provider turn never publishes its partial text as a result: {bodies:?}"
    );
    assert!(
        !bodies.iter().any(|body| matches!(
            body, LiveEventBody::SessionStateChanged(change)
                if change.current == LiveSessionState::Idle
        )),
        "a failed provider turn never settles Idle: {bodies:?}"
    );
}

#[tokio::test]
async fn nested_provider_failure_after_turn_end_error_stays_failed_against_late_completions() {
    let fixture = spawn_fixture(None).await;
    let (turn_end, agent_end, late_success) = provider_failure_frames();
    ingest_json(&fixture, &serde_json::json!({"type": "agent_start"})).await;
    ingest_json(&fixture, &turn_end).await;
    ingest_json(&fixture, &agent_end).await;
    let failed_at = fixture.handle.summary().unwrap().failed_at;

    ingest_json(&fixture, &agent_end).await;
    ingest_json(&fixture, &late_success).await;
    ingest_json(
        &fixture,
        &serde_json::json!({"type": "prompt_result", "text": "late answer"}),
    )
    .await;
    ingest_json(
        &fixture,
        &serde_json::json!({"type": "prompt_result", "agentInvoked": false, "text": "local"}),
    )
    .await;

    assert_provider_failure_stays_terminal(
        &fixture,
        &journaled_bodies(&fixture).await,
        "upstream API connection failed",
    );
    assert_eq!(fixture.handle.summary().unwrap().failed_at, failed_at);
    fixture.handle.stop().await.unwrap();
}

#[tokio::test]
async fn nested_provider_failure_without_turn_end_is_typed_and_stays_failed() {
    let fixture = spawn_fixture(None).await;
    let (_, agent_end, late_success) = provider_failure_frames();
    ingest_json(&fixture, &serde_json::json!({"type": "agent_start"})).await;
    ingest_json(&fixture, &agent_end).await;
    let failed_at = fixture.handle.summary().unwrap().failed_at;

    ingest_json(&fixture, &late_success).await;
    ingest_json(
        &fixture,
        &serde_json::json!({"type": "prompt_result", "text": "late answer"}),
    )
    .await;

    assert_provider_failure_stays_terminal(
        &fixture,
        &journaled_bodies(&fixture).await,
        "upstream API connection failed",
    );
    assert_eq!(fixture.handle.summary().unwrap().failed_at, failed_at);
    fixture.handle.stop().await.unwrap();
}

#[tokio::test]
async fn nonterminal_error_round_does_not_fail_a_loop_that_then_succeeds() {
    let fixture = spawn_fixture(None).await;
    let (_, mut failed_round_end, _) = provider_failure_frames();
    failed_round_end["isTerminal"] = serde_json::json!(false);
    failed_round_end["willContinue"] = serde_json::json!(true);
    ingest_json(&fixture, &serde_json::json!({"type": "agent_start"})).await;
    ingest_json(
        &fixture,
        &serde_json::json!({
            "type": "turn_end",
            "message": {"role": "assistant", "stopReason": "toolUse", "content": []}
        }),
    )
    .await;
    ingest_json(&fixture, &failed_round_end).await;
    assert_ne!(
        fixture.handle.summary().unwrap().state,
        LiveSessionState::Failed
    );

    ingest_json(&fixture, &serde_json::json!({"type": "agent_start"})).await;
    ingest_json(
        &fixture,
        &serde_json::json!({
            "type": "agent_end",
            "isTerminal": true,
            "yielded": true,
            "messages": [
                {"role": "user", "content": [{"type": "text", "text": "Perform one bounded task."}]},
                {
                    "role": "assistant",
                    "stopReason": "stop",
                    "content": [{"type": "text", "text": "Final answer."}]
                }
            ]
        }),
    )
    .await;

    let bodies = journaled_bodies(&fixture).await;
    assert!(!bodies
        .iter()
        .any(|body| matches!(body, LiveEventBody::Error(_))));
    let results: Vec<_> = bodies
        .iter()
        .filter_map(|body| match body {
            LiveEventBody::Result(result) => Some(result.summary.as_deref()),
            _ => None,
        })
        .collect();
    assert_eq!(results, [Some("Final answer.")]);
    let summary = fixture.handle.summary().unwrap();
    assert_eq!(summary.state, LiveSessionState::Idle);
    assert!(summary.failed_at.is_none());
    fixture.handle.stop().await.unwrap();
}

/// A provider round the loop retries in place is not the turn: while it
/// retries, nothing durable says Failed (no typed error, no failed instant),
/// and the retried round's answer settles once.
#[tokio::test]
async fn provider_round_retried_in_place_never_publishes_a_failed_window() {
    let fixture = spawn_fixture(None).await;
    let (failed_round, _, _) = provider_failure_frames();
    ingest_json(&fixture, &serde_json::json!({"type": "agent_start"})).await;
    ingest_json(&fixture, &failed_round).await;
    let retrying = fixture.handle.summary().unwrap();
    assert_eq!(retrying.state, LiveSessionState::Running);
    assert!(retrying.failed_at.is_none());

    let answer = serde_json::json!({
        "role": "assistant",
        "stopReason": "stop",
        "content": [{"type": "text", "text": "Retried answer."}]
    });
    ingest_json(
        &fixture,
        &serde_json::json!({"type": "turn_end", "message": answer}),
    )
    .await;
    ingest_json(
        &fixture,
        &serde_json::json!({"type": "agent_end", "isTerminal": true, "messages": [answer]}),
    )
    .await;

    let bodies = journaled_bodies(&fixture).await;
    assert!(!bodies
        .iter()
        .any(|body| matches!(body, LiveEventBody::Error(_))));
    assert!(!bodies.iter().any(|body| matches!(
        body, LiveEventBody::SessionStateChanged(change)
            if change.current == LiveSessionState::Failed
    )));
    let results: Vec<_> = bodies
        .iter()
        .filter_map(|body| match body {
            LiveEventBody::Result(result) => Some(result.summary.as_deref()),
            _ => None,
        })
        .collect();
    assert_eq!(results, [Some("Retried answer.")]);
    let summary = fixture.handle.summary().unwrap();
    assert_eq!(summary.state, LiveSessionState::Idle);
    assert!(summary.failed_at.is_none());
    fixture.handle.stop().await.unwrap();
}

/// A terminal provider failure leaves Failed only through the actual
/// admitted recovery. The fresh incarnation forgets the failed turn: the old
/// incarnation's late terminal cannot fail it again, and its own result
/// journals.
#[tokio::test]
async fn recovery_after_a_provider_failure_starts_the_fresh_incarnation_clean() {
    let fixture = spawn_fixture(None).await;
    let (failed_round, agent_end, _) = provider_failure_frames();
    ingest_json(&fixture, &serde_json::json!({"type": "agent_start"})).await;
    ingest_json(&fixture, &failed_round).await;
    ingest_json(&fixture, &agent_end).await;
    assert_eq!(
        fixture.handle.summary().unwrap().state,
        LiveSessionState::Failed
    );

    let recovered = fixture.handle.recover().await.unwrap();
    assert_eq!(recovered.state, LiveSessionState::Idle);
    assert_eq!(fixture.backend.restart_calls.load(Ordering::SeqCst), 1);
    ingest_json(&fixture, &agent_end).await;
    ingest_json(
        &fixture,
        &serde_json::json!({"type": "prompt_result", "text": "fresh incarnation answer"}),
    )
    .await;

    let bodies = journaled_bodies(&fixture).await;
    assert_eq!(
        bodies
            .iter()
            .filter(|body| matches!(body, LiveEventBody::Error(_)))
            .count(),
        1,
        "{bodies:?}"
    );
    assert!(bodies.iter().any(|body| matches!(
        body, LiveEventBody::Result(result)
            if result.summary.as_deref() == Some("fresh incarnation answer")
    )));
    let summary = fixture.handle.summary().unwrap();
    assert_eq!(summary.state, LiveSessionState::Idle);
    assert!(summary.failed_at.is_none());
    fixture.handle.stop().await.unwrap();
}

/// An intentional turn abort wins even over a failed provider round still
/// pending in the loop it cancelled: the aborted turn's settle is neither a
/// provider failure nor a reopening.
#[tokio::test]
async fn operator_turn_abort_with_an_aborted_settle_is_not_a_provider_failure() {
    let fixture = spawn_fixture(None).await;
    assert!(matches!(
        fixture
            .handle
            .command(LiveCommand {
                command_id: CommandId::new("command:prompt-before-operator-abort").unwrap(),
                session_id: fixture.session_id,
                expected_epoch: fixture.epoch,
                expected_event_head: None,
                body: LiveCommandBody::Prompt {
                    message: LiveMessage::new(vec![odin_domain::huginn::LiveContentBlock::Text(
                        "start a turn".to_owned(),
                    )])
                    .unwrap(),
                },
            })
            .await
            .unwrap(),
        CommandReceipt::Accepted { .. }
    ));
    ingest_json(&fixture, &provider_failure_frames().0).await;
    assert!(matches!(
        fixture
            .handle
            .command(LiveCommand {
                command_id: CommandId::new("command:operator-turn-abort").unwrap(),
                session_id: fixture.session_id,
                expected_epoch: fixture.epoch,
                expected_event_head: None,
                body: LiveCommandBody::Abort {
                    scope: AbortScope::CurrentTurn,
                },
            })
            .await
            .unwrap(),
        CommandReceipt::Accepted { .. }
    ));
    ingest_json(
        &fixture,
        &serde_json::json!({
            "type": "agent_end",
            "isTerminal": true,
            "messages": [{
                "role": "assistant",
                "stopReason": "aborted",
                "content": [{"type": "text", "text": "partial"}]
            }]
        }),
    )
    .await;

    assert!(!journaled_bodies(&fixture)
        .await
        .iter()
        .any(|body| matches!(body, LiveEventBody::Error(_))));
    let summary = fixture.handle.summary().unwrap();
    assert_eq!(summary.state, LiveSessionState::Idle);
    assert!(summary.failed_at.is_none());
    fixture.handle.stop().await.unwrap();
}

#[tokio::test]
async fn local_only_prompt_result_releases_the_turn_without_agent_end() {
    let fixture = spawn_fixture(None).await;
    let mut command = LiveCommand {
        command_id: CommandId::new("command:local-only").unwrap(),
        session_id: fixture.session_id,
        expected_epoch: fixture.epoch,
        expected_event_head: None,
        body: LiveCommandBody::Prompt {
            message: LiveMessage::new(vec![odin_domain::huginn::LiveContentBlock::Text(
                "/local-command".to_owned(),
            )])
            .unwrap(),
        },
    };
    fixture.handle.command(command.clone()).await.unwrap();
    let decoded = crate::frames::RpcFrameDecoder::default()
        .push_physical_line(b"{\"type\":\"prompt_result\",\"agentInvoked\":false}\n")
        .unwrap()
        .unwrap();
    fixture
        .handle
        .ingest_omp(crate::bridge::ObservedFrame {
            class: crate::bridge::classify_frame(decoded.value()),
            decoded: Some(decoded),
            rejection: None,
            active_command: None,
            journal_failure: None,
        })
        .await
        .unwrap();
    assert_eq!(
        fixture.handle.summary().unwrap().state,
        LiveSessionState::Idle
    );
    command.command_id = CommandId::new("command:after-local-only").unwrap();
    assert!(matches!(
        fixture.handle.command(command).await.unwrap(),
        CommandReceipt::Accepted { .. }
    ));
    fixture.handle.stop().await.unwrap();
}

#[tokio::test]
async fn in_place_recovery_re_asserts_the_recorded_effective_model() {
    let fixture = spawn_fixture(None).await;

    // The operator switches the model mid-session through the ordinary
    // journaled command: the summary records the effective launch.
    let snapshot = fixture.handle.summary().expect("summary");
    let set_model = LiveCommand {
        command_id: CommandId::new("odin-omp:cmd:set-model-recovery").expect("command id"),
        session_id: fixture.session_id,
        expected_epoch: snapshot.epoch,
        expected_event_head: None,
        body: LiveCommandBody::SetModel {
            provider: ProviderName::new("fixture").expect("provider"),
            model: ModelName::new("switched-model").expect("model"),
        },
    };
    fixture
        .handle
        .command(set_model)
        .await
        .expect("set model command");
    let switched = fixture.handle.summary().expect("summary");
    assert_eq!(switched.model.as_str(), "switched-model");

    // The incarnation dies and the supervisor recovers in place: the
    // fresh bridge respawns from the launch manifest, so recovery must
    // re-assert the recorded effective model — the summary must never
    // describe a model the recovered incarnation does not run.
    fixture.handle.recover().await.expect("in-place recovery");
    let set_models = fixture
        .backend
        .set_models
        .lock()
        .map(|calls| calls.clone())
        .expect("set model calls");
    assert_eq!(
        set_models,
        vec![
            (
                ProviderName::new("fixture").expect("provider"),
                ModelName::new("switched-model").expect("model")
            ),
            (
                ProviderName::new("fixture").expect("provider"),
                ModelName::new("switched-model").expect("model")
            ),
        ],
        "the operator switch and its recovery re-assert must both reach the backend"
    );
    let recovered = fixture.handle.summary().expect("summary");
    assert_eq!(recovered.model.as_str(), "switched-model");
    assert_eq!(
        recovered.epoch.get(),
        fixture.epoch.get() + 1,
        "in-place recovery advances exactly one epoch"
    );
    fixture.handle.stop().await.expect("stop after recovery");
}

#[tokio::test]
async fn recovery_of_an_unswitched_session_re_asserts_nothing() {
    let fixture = spawn_fixture(None).await;
    fixture.handle.recover().await.expect("in-place recovery");
    let set_models = fixture
        .backend
        .set_models
        .lock()
        .map(|calls| calls.clone())
        .expect("set model calls");
    assert!(
        set_models.is_empty(),
        "a recovery that matches the launch manifest must not touch the backend model"
    );
    fixture.handle.stop().await.expect("stop after recovery");
}

#[tokio::test(start_paused = true)]
async fn turn_budget_give_up_cancels_once_and_journals_the_honest_terminal() {
    let fixture =
        spawn_fixture_with_budget(None, Some(std::time::Duration::from_millis(150))).await;
    let receipt = fixture
        .handle
        .command(LiveCommand {
            command_id: CommandId::new("command:budget-turn").unwrap(),
            session_id: fixture.session_id,
            expected_epoch: fixture.epoch,
            expected_event_head: None,
            body: LiveCommandBody::Prompt {
                message: LiveMessage::new(vec![odin_domain::huginn::LiveContentBlock::Text(
                    "answer without settling".to_owned(),
                )])
                .unwrap(),
            },
        })
        .await
        .unwrap();
    assert!(matches!(receipt, CommandReceipt::Accepted { .. }));
    assert_eq!(
        fixture.handle.summary().unwrap().state,
        LiveSessionState::Running
    );
    // The backend never settles the turn; the declared budget must end it.
    tokio::time::sleep(std::time::Duration::from_millis(600)).await;
    assert_eq!(
        fixture.backend.abort_turn_calls.load(Ordering::SeqCst),
        1,
        "the give-up cancels the turn exactly once through the shared abort seam"
    );
    let bodies = journaled_bodies(&fixture).await;
    assert!(
        bodies.iter().any(|body| {
            matches!(
                body,
                LiveEventBody::Error(error)
                    if error.code == "turn_budget_exceeded"
            )
        }),
        "the journal carries a typed error, not a fabricated answer: {bodies:?}"
    );
    assert!(
        bodies.iter().any(|body| {
            matches!(
                body,
                LiveEventBody::SessionStateChanged(change)
                    if change.previous == LiveSessionState::Running
                        && change.current == LiveSessionState::Failed
                        && change.reason.as_deref() == Some("turn budget elapsed")
            )
        }),
        "the give-up settles Failed, not a misleading idle success: {bodies:?}"
    );
    assert!(
        bodies
            .iter()
            .all(|body| !matches!(body, LiveEventBody::Result(_))),
        "budget expiry is not a task result: {bodies:?}"
    );
    assert_eq!(
        fixture.handle.summary().unwrap().state,
        LiveSessionState::Failed
    );
    // No repeated cancellation after the turn settled: the budget is per-turn.
    tokio::time::sleep(std::time::Duration::from_millis(400)).await;
    assert_eq!(
        fixture.backend.abort_turn_calls.load(Ordering::SeqCst),
        1,
        "a settled turn is never cancelled again"
    );
    fixture.handle.stop().await.unwrap();
}

#[tokio::test(start_paused = true)]
async fn turn_budget_does_not_fire_for_a_turn_that_settles_in_time() {
    let fixture =
        spawn_fixture_with_budget(None, Some(std::time::Duration::from_millis(400))).await;
    fixture
        .handle
        .command(LiveCommand {
            command_id: CommandId::new("command:fast-turn").unwrap(),
            session_id: fixture.session_id,
            expected_epoch: fixture.epoch,
            expected_event_head: None,
            body: LiveCommandBody::Prompt {
                message: LiveMessage::new(vec![odin_domain::huginn::LiveContentBlock::Text(
                    "settle quickly".to_owned(),
                )])
                .unwrap(),
            },
        })
        .await
        .unwrap();
    for raw in ["{\"type\":\"agent_start\"}\n", "{\"type\":\"agent_end\"}\n"] {
        let decoded = crate::frames::RpcFrameDecoder::default()
            .push_physical_line(raw.as_bytes())
            .unwrap()
            .unwrap();
        fixture
            .handle
            .ingest_omp(crate::bridge::ObservedFrame {
                class: crate::bridge::classify_frame(decoded.value()),
                decoded: Some(decoded),
                rejection: None,
                active_command: None,
                journal_failure: None,
            })
            .await
            .unwrap();
    }
    assert_eq!(
        fixture.handle.summary().unwrap().state,
        LiveSessionState::Idle
    );
    tokio::time::sleep(std::time::Duration::from_millis(600)).await;
    assert_eq!(
        fixture.backend.abort_turn_calls.load(Ordering::SeqCst),
        0,
        "a turn that settles inside the budget is never cancelled"
    );
    assert!(
        !journaled_bodies(&fixture)
            .await
            .iter()
            .any(|body| matches!(body, LiveEventBody::Result(_))),
        "no host-minted terminal exists when the turn settles honestly"
    );
    fixture.handle.stop().await.unwrap();
}

#[tokio::test(start_paused = true)]
async fn turn_budget_due_while_waiting_fires_on_the_running_resume_without_reopening() {
    let fixture =
        spawn_fixture_with_budget(None, Some(std::time::Duration::from_millis(200))).await;
    fixture
        .handle
        .command(LiveCommand {
            command_id: CommandId::new("command:waiting-turn").unwrap(),
            session_id: fixture.session_id,
            expected_epoch: fixture.epoch,
            expected_event_head: None,
            body: LiveCommandBody::Prompt {
                message: LiveMessage::new(vec![odin_domain::huginn::LiveContentBlock::Text(
                    "wait for permission".to_owned(),
                )])
                .unwrap(),
            },
        })
        .await
        .unwrap();
    let raw = "{\"type\":\"extension_ui_request\",\"id\":\"confirmation-budget\",\"method\":\"confirm\",\"title\":\"Confirm\"}\n";
    let decoded = crate::frames::RpcFrameDecoder::default()
        .push_physical_line(raw.as_bytes())
        .unwrap()
        .unwrap();
    fixture
        .handle
        .ingest_omp(crate::bridge::ObservedFrame {
            class: crate::bridge::classify_frame(decoded.value()),
            decoded: Some(decoded),
            rejection: None,
            active_command: None,
            journal_failure: None,
        })
        .await
        .unwrap();
    assert_eq!(
        fixture.handle.summary().unwrap().state,
        LiveSessionState::RequiresAction
    );
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    assert_eq!(
        fixture.backend.abort_turn_calls.load(Ordering::SeqCst),
        0,
        "a waiting turn is not cancelled in RequiresAction"
    );
    // The permission resolves; generation resumes with an already-expired
    // budget and the give-up fires immediately — the state goes forward
    // (Running -> Failed), never back to a live turn.
    fixture
        .handle
        .command(LiveCommand {
            command_id: CommandId::new("command:budget-answer").unwrap(),
            session_id: fixture.session_id,
            expected_epoch: fixture.epoch,
            expected_event_head: None,
            body: LiveCommandBody::DecidePermission {
                request_id: PermissionRequestId::new("confirmation-budget").unwrap(),
                decision: PermissionDecision::AllowOnce,
            },
        })
        .await
        .unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(400)).await;
    assert_eq!(
        fixture.backend.abort_turn_calls.load(Ordering::SeqCst),
        1,
        "the due give-up fires exactly once when the turn resumes"
    );
    assert_eq!(
        fixture.handle.summary().unwrap().state,
        LiveSessionState::Failed
    );
    fixture.handle.stop().await.unwrap();
}

/// While an expired budget waits OUTSIDE `Running`, the actor stays
/// responsive to mailbox traffic — the overdue deadline holds (the
/// declaration is elapsed time) but the timer must not spin wakeups that
/// observe `due == false` forever — and the eventual `Running` transition
/// still cancels the ORIGINAL overdue turn exactly once, promptly, never
/// after a fresh budget window.
#[tokio::test(start_paused = true)]
async fn overdue_budget_waits_responsibly_and_cancels_once_on_running_resume() {
    let fixture =
        spawn_fixture_with_budget(None, Some(std::time::Duration::from_millis(150))).await;
    fixture
        .handle
        .command(LiveCommand {
            command_id: CommandId::new("command:overdue-wait").unwrap(),
            session_id: fixture.session_id,
            expected_epoch: fixture.epoch,
            expected_event_head: None,
            body: LiveCommandBody::Prompt {
                message: LiveMessage::new(vec![odin_domain::huginn::LiveContentBlock::Text(
                    "wait overdue".to_owned(),
                )])
                .unwrap(),
            },
        })
        .await
        .unwrap();
    let raw = "{\"type\":\"extension_ui_request\",\"id\":\"confirmation-overdue\",\"method\":\"confirm\",\"title\":\"Confirm\"}\n";
    let decoded = crate::frames::RpcFrameDecoder::default()
        .push_physical_line(raw.as_bytes())
        .unwrap()
        .unwrap();
    fixture
        .handle
        .ingest_omp(crate::bridge::ObservedFrame {
            class: crate::bridge::classify_frame(decoded.value()),
            decoded: Some(decoded),
            rejection: None,
            active_command: None,
            journal_failure: None,
        })
        .await
        .unwrap();
    assert_eq!(
        fixture.handle.summary().unwrap().state,
        LiveSessionState::RequiresAction
    );
    // The budget elapses while the owner decision is pending.
    tokio::time::sleep(std::time::Duration::from_millis(400)).await;
    assert_eq!(
        fixture.backend.abort_turn_calls.load(Ordering::SeqCst),
        0,
        "the overdue wait never cancels outside Running"
    );
    // Responsiveness while overdue: mailbox work completes promptly even
    // though no timer may fire outside Running.
    let _events = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        fixture.handle.subscribe(EventSeq::new(0)),
    )
    .await
    .expect("the actor answers while an overdue budget waits")
    .expect("subscribe succeeds while overdue");
    // The owner resolves; the ORIGINAL overdue deadline cancels once and
    // promptly — never after a fresh budget window.
    fixture
        .handle
        .command(LiveCommand {
            command_id: CommandId::new("command:overdue-answer").unwrap(),
            session_id: fixture.session_id,
            expected_epoch: fixture.epoch,
            expected_event_head: None,
            body: LiveCommandBody::DecidePermission {
                request_id: PermissionRequestId::new("confirmation-overdue").unwrap(),
                decision: PermissionDecision::AllowOnce,
            },
        })
        .await
        .unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        while fixture.backend.abort_turn_calls.load(Ordering::SeqCst) == 0 {
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("the resumed Running state cancels the overdue turn promptly");
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    assert_eq!(
        fixture.backend.abort_turn_calls.load(Ordering::SeqCst),
        1,
        "the overdue give-up runs exactly once"
    );
    assert_eq!(
        fixture.handle.summary().unwrap().state,
        LiveSessionState::Failed
    );
    assert!(
        journaled_bodies(&fixture).await.iter().any(|body| {
            matches!(
                body,
                LiveEventBody::Error(error)
                    if error.code == "turn_budget_exceeded"
            )
        }),
        "the cancelled overdue turn journals the honest terminal"
    );
    fixture.handle.stop().await.unwrap();
}

#[tokio::test(start_paused = true)]
async fn turn_budget_abort_failure_is_journaled_once_and_never_marks_idle() {
    let fixture =
        spawn_fixture_with_budget(None, Some(std::time::Duration::from_millis(150))).await;
    fixture
        .backend
        .fail_abort_turn
        .store(true, Ordering::SeqCst);
    fixture
        .handle
        .command(LiveCommand {
            command_id: CommandId::new("command:abort-fail-turn").unwrap(),
            session_id: fixture.session_id,
            expected_epoch: fixture.epoch,
            expected_event_head: None,
            body: LiveCommandBody::Prompt {
                message: LiveMessage::new(vec![odin_domain::huginn::LiveContentBlock::Text(
                    "outlive the budget".to_owned(),
                )])
                .unwrap(),
            },
        })
        .await
        .unwrap();
    assert_eq!(
        fixture.handle.summary().unwrap().state,
        LiveSessionState::Running
    );
    // The budget expires; the shared abort seam refuses the cancellation.
    tokio::time::sleep(std::time::Duration::from_millis(600)).await;
    assert_eq!(
        fixture.backend.abort_turn_calls.load(Ordering::SeqCst),
        1,
        "the give-up cancels the turn exactly once"
    );
    let bodies = journaled_bodies(&fixture).await;
    assert!(
        bodies.iter().any(|body| {
            matches!(
                body,
                LiveEventBody::Error(error) if error.code == "turn_budget_abort_failed"
            )
        }),
        "the refusal is journaled as a typed error — the append is awaited, \
         never dropped unawaited: {bodies:?}"
    );
    assert!(
        !bodies.iter().any(|body| {
            matches!(
                body,
                LiveEventBody::SessionStateChanged(change)
                    if change.current == LiveSessionState::Idle
            )
        }),
        "a failed cancellation never claims Idle: {bodies:?}"
    );
    assert_eq!(
        fixture.handle.summary().unwrap().state,
        LiveSessionState::Failed,
        "the honest terminal of a refused cancellation is Failed"
    );
    // The once-per-turn expiry holds even though the summary is still
    // Running-shaped: the episode is spent, never re-armed.
    tokio::time::sleep(std::time::Duration::from_millis(400)).await;
    assert_eq!(
        fixture.backend.abort_turn_calls.load(Ordering::SeqCst),
        1,
        "a failed give-up is never retried on the same turn"
    );
    // A late successful frame of the original turn cannot reopen the
    // failure: the normalizer followed the journal to Failed.
    let decoded = crate::frames::RpcFrameDecoder::default()
        .push_physical_line(b"{\"type\":\"agent_end\",\"stopReason\":\"stop\"}\n")
        .unwrap()
        .unwrap();
    fixture
        .handle
        .ingest_omp(crate::bridge::ObservedFrame {
            class: crate::bridge::classify_frame(decoded.value()),
            decoded: Some(decoded),
            rejection: None,
            active_command: None,
            journal_failure: None,
        })
        .await
        .unwrap();
    assert_eq!(
        fixture.handle.summary().unwrap().state,
        LiveSessionState::Failed,
        "a late successful agent_end never reopens a cancellation failure"
    );
    // The session is honestly Failed: new work is refused, not dispatched.
    let receipt = fixture
        .handle
        .command(LiveCommand {
            command_id: CommandId::new("command:after-abort-failure").unwrap(),
            session_id: fixture.session_id,
            expected_epoch: fixture.epoch,
            expected_event_head: None,
            body: LiveCommandBody::Prompt {
                message: LiveMessage::new(vec![odin_domain::huginn::LiveContentBlock::Text(
                    "try again".to_owned(),
                )])
                .unwrap(),
            },
        })
        .await
        .unwrap();
    assert!(
        matches!(receipt, CommandReceipt::Rejected { .. }),
        "a Failed session refuses new turns: {receipt:?}"
    );
    fixture.handle.stop().await.unwrap();
}

#[tokio::test(start_paused = true)]
async fn turn_budget_bounds_a_running_command_awaiting_a_reply_that_never_arrives() {
    let fixture =
        spawn_fixture_with_budget(None, Some(std::time::Duration::from_millis(150))).await;
    fixture.backend.steer_blocked.store(true, Ordering::SeqCst);
    fixture
        .handle
        .command(LiveCommand {
            command_id: CommandId::new("command:starved-turn").unwrap(),
            session_id: fixture.session_id,
            expected_epoch: fixture.epoch,
            expected_event_head: None,
            body: LiveCommandBody::Prompt {
                message: LiveMessage::new(vec![odin_domain::huginn::LiveContentBlock::Text(
                    "start a turn".to_owned(),
                )])
                .unwrap(),
            },
        })
        .await
        .unwrap();
    // A running-state steer whose correlated RPC reply never arrives must
    // not park the actor beyond the declared budget: the deadline ends the
    // wait and the turn's give-up settles it.
    let steer = fixture.handle.command(LiveCommand {
        command_id: CommandId::new("command:starved-steer").unwrap(),
        session_id: fixture.session_id,
        expected_epoch: fixture.epoch,
        expected_event_head: None,
        body: LiveCommandBody::Steer {
            message: LiveMessage::new(vec![odin_domain::huginn::LiveContentBlock::Text(
                "redirect the turn".to_owned(),
            )])
            .unwrap(),
        },
    });
    let receipt = tokio::time::timeout(std::time::Duration::from_secs(5), steer)
        .await
        .expect("the declared deadline ends the starved command wait");
    assert!(
        matches!(
            receipt.expect("command result"),
            CommandReceipt::Accepted { .. }
        ),
        "the command keeps its journaled identity"
    );
    // The budget's own give-up then cancels the turn through the shared
    // abort seam and journals the honest terminal.
    tokio::time::sleep(std::time::Duration::from_millis(400)).await;
    assert_eq!(
        fixture.backend.abort_turn_calls.load(Ordering::SeqCst),
        1,
        "the deadline-elapsed turn is cancelled exactly once"
    );
    let bodies = journaled_bodies(&fixture).await;
    assert!(
        bodies.iter().any(|body| {
            matches!(
                body,
                LiveEventBody::ControlCompleted(CommandOutcome::Failed {
                    error: CommandFailure { code, message, .. },
                    ..
                }) if code == "control_failed" && message.contains("turn_budget_expired")
            )
        }),
        "the expired command wait journals a typed retryable failure — the \
         wait is cancelled, never the dispatched command: {bodies:?}"
    );
    assert!(
        bodies.iter().any(|body| {
            matches!(
                body,
                LiveEventBody::Error(error)
                    if error.code == "turn_budget_exceeded"
            )
        }),
        "the give-up still journals the honest terminal: {bodies:?}"
    );
    assert_eq!(
        fixture.handle.summary().unwrap().state,
        LiveSessionState::Failed
    );
    // The parked backend wait was owned by the command future the deadline
    // dropped; releasing it must change nothing.
    fixture.backend.steer_release.notify_waiters();
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    assert_eq!(
        fixture.handle.summary().unwrap().state,
        LiveSessionState::Failed,
        "a late steer reply never reopens the settled turn"
    );
    fixture.handle.stop().await.unwrap();
}

#[tokio::test]
async fn orphaned_correlated_response_failure_settles_failed_and_stays_failed() {
    let fixture = spawn_fixture(None).await;
    fixture
        .handle
        .command(LiveCommand {
            command_id: CommandId::new("command:orphan-turn").unwrap(),
            session_id: fixture.session_id,
            expected_epoch: fixture.epoch,
            expected_event_head: None,
            body: LiveCommandBody::Prompt {
                message: LiveMessage::new(vec![odin_domain::huginn::LiveContentBlock::Text(
                    "answer with a mismatched response".to_owned(),
                )])
                .unwrap(),
            },
        })
        .await
        .unwrap();
    // The bridge-annotated frame: the open-loop prompt's correlated
    // response mismatched the pending command and its waiter was dropped
    // at the write-acknowledged dispatch, so the typed failure rode the
    // frame — without the annotation it would be silently lost.
    let decoded = crate::frames::RpcFrameDecoder::default()
        .push_physical_line(
            b"{\"type\":\"response\",\"id\":\"wire-orphan\",\"command\":\"steer\",\"success\":true,\"data\":{}}\n",
        )
        .unwrap()
        .unwrap();
    fixture
        .handle
        .ingest_omp(crate::bridge::ObservedFrame {
            class: crate::bridge::classify_frame(decoded.value()),
            decoded: Some(decoded),
            rejection: None,
            active_command: None,
            journal_failure: Some(crate::bridge::TypedFrameFailure {
                code: "response_mismatch".to_owned(),
                detail: "response/command mismatch: expected `prompt`, got `steer`".to_owned(),
                epoch: Some(fixture.epoch),
            }),
        })
        .await
        .unwrap();
    let bodies = journaled_bodies(&fixture).await;
    assert!(
        bodies.iter().any(|body| {
            matches!(
                body,
                LiveEventBody::Error(error) if error.code == "response_mismatch"
            )
        }),
        "the orphaned correlated failure lands in the session journal: {bodies:?}"
    );
    assert_eq!(
        fixture.handle.summary().unwrap().state,
        LiveSessionState::Failed
    );
    // A late successful agent_end of the original turn cannot reopen the
    // failure with an Idle transition.
    let decoded = crate::frames::RpcFrameDecoder::default()
        .push_physical_line(b"{\"type\":\"agent_end\",\"stopReason\":\"stop\"}\n")
        .unwrap()
        .unwrap();
    fixture
        .handle
        .ingest_omp(crate::bridge::ObservedFrame {
            class: crate::bridge::classify_frame(decoded.value()),
            decoded: Some(decoded),
            rejection: None,
            active_command: None,
            journal_failure: None,
        })
        .await
        .unwrap();
    assert_eq!(
        fixture.handle.summary().unwrap().state,
        LiveSessionState::Failed,
        "a late successful agent_end never reopens the correlated failure"
    );
    assert!(
        !journaled_bodies(&fixture).await.iter().any(|body| {
            matches!(
                body,
                LiveEventBody::SessionStateChanged(change)
                    if change.current == LiveSessionState::Idle
            )
        }),
        "no Idle transition is ever journaled after the typed failure"
    );
    fixture.handle.stop().await.unwrap();
}

#[tokio::test(start_paused = true)]
async fn turn_budget_expired_initial_dispatch_reconciles_once_and_blocks_late_turns() {
    let fixture =
        spawn_fixture_with_budget(None, Some(std::time::Duration::from_millis(150))).await;
    fixture.backend.prompt_blocked.store(true, Ordering::SeqCst);
    // A starting-turn prompt whose initial journaled dispatch is never
    // acknowledged must not park the actor past the declared budget. The
    // wire write may already have been accepted when the wait times out,
    // so the child can start the turn late — the reconciliation must model
    // that uncertainty, not assume a never-started turn.
    let prompt = fixture.handle.command(LiveCommand {
        command_id: CommandId::new("command:starved-initial-dispatch").unwrap(),
        session_id: fixture.session_id,
        expected_epoch: fixture.epoch,
        expected_event_head: None,
        body: LiveCommandBody::Prompt {
            message: LiveMessage::new(vec![odin_domain::huginn::LiveContentBlock::Text(
                "start a turn".to_owned(),
            )])
            .unwrap(),
        },
    });
    let receipt = tokio::time::timeout(std::time::Duration::from_secs(5), prompt)
        .await
        .expect("the declared deadline ends the starved initial dispatch wait");
    assert!(
        matches!(
            receipt.expect("command result"),
            CommandReceipt::Accepted { .. }
        ),
        "the command keeps its journaled identity"
    );
    // The failure is journaled exactly once: a typed retryable command
    // failure, one bounded cancellation through the shared abort seam, and
    // the fail-closed Failed terminal — never an Idle claim for a dispatch
    // whose outcome is unknown.
    let bodies = journaled_bodies(&fixture).await;
    assert!(
        bodies.iter().any(|body| {
            matches!(
                body,
                LiveEventBody::ControlCompleted(CommandOutcome::Failed {
                    error: CommandFailure { code, message, .. },
                    ..
                }) if code == "control_failed" && message.contains("turn_budget_expired")
            )
        }),
        "the expired initial dispatch journals a typed retryable failure: {bodies:?}"
    );
    assert!(
        bodies.iter().any(|body| {
            matches!(
                body,
                LiveEventBody::Error(error) if error.code == "turn_budget_expired"
            )
        }),
        "the uncertain dispatch settles a typed failure terminal: {bodies:?}"
    );
    assert_eq!(
        fixture.backend.abort_turn_calls.load(Ordering::SeqCst),
        1,
        "the uncertain dispatch is cancelled exactly once through the shared abort seam"
    );
    assert_eq!(
        fixture.handle.summary().unwrap().state,
        LiveSessionState::Failed,
        "the honest terminal of an unknown-outcome dispatch is Failed, never Idle"
    );
    // The child now starts the turn late, exactly as it may: the frames
    // arrive after the failure terminal and must not reopen a live turn.
    for raw in [
        "{\"type\":\"agent_start\"}\n",
        "{\"type\":\"agent_end\",\"stopReason\":\"stop\"}\n",
    ] {
        let decoded = crate::frames::RpcFrameDecoder::default()
            .push_physical_line(raw.as_bytes())
            .unwrap()
            .unwrap();
        fixture
            .handle
            .ingest_omp(crate::bridge::ObservedFrame {
                class: crate::bridge::classify_frame(decoded.value()),
                decoded: Some(decoded),
                rejection: None,
                active_command: None,
                journal_failure: None,
            })
            .await
            .unwrap();
    }
    assert_eq!(
        fixture.handle.summary().unwrap().state,
        LiveSessionState::Failed,
        "a late-started turn never reopens the failure terminal"
    );
    assert!(
        !journaled_bodies(&fixture).await.iter().any(|body| {
            matches!(
                body,
                LiveEventBody::SessionStateChanged(change)
                    if change.current == LiveSessionState::Running
                        || change.current == LiveSessionState::Idle
            )
        }),
        "no live-turn transition is ever journaled after the failure terminal"
    );
    // No re-arm behind the failure: another whole budget fires nothing.
    tokio::time::sleep(std::time::Duration::from_millis(400)).await;
    assert_eq!(
        fixture.backend.abort_turn_calls.load(Ordering::SeqCst),
        1,
        "the failed dispatch leaves no armed deadline behind"
    );
    // The retryable failure never blindly allows a duplicate consequential
    // effect: new work is refused while the session is Failed; the
    // sanctioned retry is recovery, which advances the epoch.
    let retry = fixture
        .handle
        .command(LiveCommand {
            command_id: CommandId::new("command:blind-retry").unwrap(),
            session_id: fixture.session_id,
            expected_epoch: fixture.epoch,
            expected_event_head: None,
            body: LiveCommandBody::Prompt {
                message: LiveMessage::new(vec![odin_domain::huginn::LiveContentBlock::Text(
                    "retry the turn".to_owned(),
                )])
                .unwrap(),
            },
        })
        .await
        .unwrap();
    assert!(
        matches!(retry, CommandReceipt::Rejected { .. }),
        "a Failed session refuses blind retries: {retry:?}"
    );
    fixture.handle.stop().await.unwrap();
}

#[tokio::test]
async fn authenticated_context_refusal_settles_failed_and_the_abort_settle_cannot_reopen() {
    let fixture = spawn_fixture(None).await;
    fixture
        .handle
        .command(LiveCommand {
            command_id: CommandId::new("command:refusal-turn").unwrap(),
            session_id: fixture.session_id,
            expected_epoch: fixture.epoch,
            expected_event_head: None,
            body: LiveCommandBody::Prompt {
                message: LiveMessage::new(vec![odin_domain::huginn::LiveContentBlock::Text(
                    "run an oversized turn".to_owned(),
                )])
                .unwrap(),
            },
        })
        .await
        .unwrap();
    // The bridge authenticated the trusted extension's refusal host-side
    // (exact trusted artifact, pinned event, strict marker schema, live
    // turn anchor of this binding) and annotated the frame; the marker
    // error string below is the wire evidence, the annotation is the
    // trust.
    let raw = concat!(
        "{\"type\":\"extension_error\",\"extensionPath\":\"/ext/odin.ts\",",
        "\"event\":\"before_provider_request\",\"error\":\"odin.context_refusal.v1|",
        "{\\\"code\\\":\\\"window_exceeded\\\",\\\"reason\\\":\\\"measured 9000 + input 2500 + reserve 500 = 12000 exceeds the declared window 10000\\\"}\"}",
        "\n"
    );
    let decoded = crate::frames::RpcFrameDecoder::default()
        .push_physical_line(raw.as_bytes())
        .unwrap()
        .unwrap();
    fixture
        .handle
        .ingest_omp(crate::bridge::ObservedFrame {
            class: crate::bridge::classify_frame(decoded.value()),
            decoded: Some(decoded),
            rejection: None,
            active_command: None,
            journal_failure: Some(crate::bridge::TypedFrameFailure {
                code: "context_refusal.window_exceeded".to_owned(),
                detail: "measured 9000 + input 2500 + reserve 500 = 12000 exceeds the declared window 10000".to_owned(),
                epoch: Some(fixture.epoch),
            }),
        })
        .await
        .unwrap();
    let bodies = journaled_bodies(&fixture).await;
    assert!(
        bodies.iter().any(|body| {
            matches!(
                body,
                LiveEventBody::Error(error) if error.code == "context_refusal.window_exceeded"
            )
        }),
        "the authenticated refusal lands in the session journal: {bodies:?}"
    );
    assert_eq!(
        fixture.handle.summary().unwrap().state,
        LiveSessionState::Failed
    );
    // The generic abort settle of the SAME turn arrives late and must not
    // overwrite the refusal terminal with a misleading Idle transition.
    let decoded = crate::frames::RpcFrameDecoder::default()
        .push_physical_line(b"{\"type\":\"agent_end\",\"stopReason\":\"stop\"}\n")
        .unwrap()
        .unwrap();
    fixture
        .handle
        .ingest_omp(crate::bridge::ObservedFrame {
            class: crate::bridge::classify_frame(decoded.value()),
            decoded: Some(decoded),
            rejection: None,
            active_command: None,
            journal_failure: None,
        })
        .await
        .unwrap();
    assert_eq!(
        fixture.handle.summary().unwrap().state,
        LiveSessionState::Failed,
        "the USER_INTERRUPT settle of the refused turn never reopens the failure"
    );
    fixture.handle.stop().await.unwrap();
}

#[tokio::test]
async fn unauthenticated_marker_extension_error_stays_generic_uncertain() {
    let fixture = spawn_fixture(None).await;
    fixture
        .handle
        .command(LiveCommand {
            command_id: CommandId::new("command:spoof-turn").unwrap(),
            session_id: fixture.session_id,
            expected_epoch: fixture.epoch,
            expected_event_head: None,
            body: LiveCommandBody::Prompt {
                message: LiveMessage::new(vec![odin_domain::huginn::LiveContentBlock::Text(
                    "run a turn".to_owned(),
                )])
                .unwrap(),
            },
        })
        .await
        .unwrap();
    // A marker-looking extension_error the bridge did NOT authenticate
    // (here: no annotation reaches the actor) stays the generic honest
    // Uncertain — never a typed context refusal.
    let raw = concat!(
        "{\"type\":\"extension_error\",\"extensionPath\":\"/evil/plugin.ts\",",
        "\"event\":\"before_provider_request\",\"error\":\"odin.context_refusal.v1|",
        "{\\\"code\\\":\\\"window_exceeded\\\",\\\"reason\\\":\\\"spoofed\\\"}\"}",
        "\n"
    );
    let decoded = crate::frames::RpcFrameDecoder::default()
        .push_physical_line(raw.as_bytes())
        .unwrap()
        .unwrap();
    fixture
        .handle
        .ingest_omp(crate::bridge::ObservedFrame {
            class: crate::bridge::classify_frame(decoded.value()),
            decoded: Some(decoded),
            rejection: None,
            active_command: None,
            journal_failure: None,
        })
        .await
        .unwrap();
    let bodies = journaled_bodies(&fixture).await;
    assert!(
        bodies.iter().any(|body| {
            matches!(
                body,
                LiveEventBody::Error(error) if error.code == "omp_extension"
            )
        }),
        "an unauthenticated marker journals a generic extension error: {bodies:?}"
    );
    assert!(
        !bodies.iter().any(|body| {
            matches!(
                body,
                LiveEventBody::Error(error) if error.code.starts_with("context_refusal.")
            )
        }),
        "an unauthenticated marker never types a context refusal: {bodies:?}"
    );
    assert_eq!(
        fixture.handle.summary().unwrap().state,
        LiveSessionState::Failed
    );
    fixture.handle.stop().await.unwrap();
}

/// Stop interrupts a waiting backend and prevents queued commands from reaching it.
#[tokio::test(start_paused = true)]
async fn a_stop_preempts_a_command_waiting_on_its_backend() {
    let fixture = spawn_fixture_with_budget(None, None).await;
    fixture.backend.steer_blocked.store(true, Ordering::SeqCst);
    let text = |words: &str| {
        LiveMessage::new(vec![odin_domain::huginn::LiveContentBlock::Text(
            words.to_owned(),
        )])
        .unwrap()
    };
    fixture
        .handle
        .command(LiveCommand {
            command_id: CommandId::new("command:stoppable-turn").unwrap(),
            session_id: fixture.session_id,
            expected_epoch: fixture.epoch,
            expected_event_head: None,
            body: LiveCommandBody::Prompt {
                message: text("start a turn"),
            },
        })
        .await
        .unwrap();
    let steer = |id: &'static str| {
        let handle = fixture.handle.clone();
        let (session_id, epoch) = (fixture.session_id, fixture.epoch);
        tokio::spawn(async move {
            handle
                .command(LiveCommand {
                    command_id: CommandId::new(id).unwrap(),
                    session_id,
                    expected_epoch: epoch,
                    expected_event_head: None,
                    body: LiveCommandBody::Steer {
                        message: text("redirect the turn"),
                    },
                })
                .await
        })
    };
    let first = steer("command:starved-steer");
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    let second = steer("command:queued-steer");
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    tokio::time::timeout(std::time::Duration::from_secs(5), fixture.handle.stop())
        .await
        .expect("the stop does not wait for the starved reply")
        .expect("stopped");
    assert_eq!(fixture.backend.shutdown_calls.load(Ordering::SeqCst), 1);
    assert!(first.await.expect("steer task").is_ok());
    assert!(second.await.expect("steer task").is_ok());
    assert_eq!(fixture.backend.steer_calls.load(Ordering::SeqCst), 1);
    let bodies = journaled_bodies(&fixture).await;
    assert!(
        bodies.iter().any(|body| matches!(
            body,
            LiveEventBody::ControlCompleted(CommandOutcome::Failed {
                error: CommandFailure { message, .. },
                ..
            }) if message.contains("session_stopping")
        )),
        "the yielded wait is journaled: {bodies:?}"
    );
}
