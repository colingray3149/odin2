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
            .map_err(unavailable)?
            .get(command_id)
            .copied())
    }

    async fn dispatch_message(
        &self,
        command_id: &CommandId,
        message: &LiveMessage,
        owner_text: Option<&str>,
        follow_up: bool,
    ) -> Result<bool, LiveError> {
        if let Some(delivered) = self
            .identified
            .lock()
            .map_err(unavailable)?
            .get(command_id)
            .copied()
        {
            return Ok(delivered);
        }
        self.identified_sends.fetch_add(1, Ordering::SeqCst);
        if follow_up {
            self.follow_up(message, owner_text).await?;
        } else {
            self.prompt(message, owner_text).await?;
        }
        self.identified
            .lock()
            .map_err(unavailable)?
            .insert(command_id.clone(), true);
        Ok(true)
    }

    async fn bridge_ready(&self) -> bool {
        !self.backend_not_ready.load(Ordering::SeqCst)
    }

    async fn prompt(
        &self,
        _message: &LiveMessage,
        _owner_text: Option<&str>,
    ) -> Result<(), LiveError> {
        self.prompt_calls.fetch_add(1, Ordering::SeqCst);
        if self.prompt_blocked.load(Ordering::SeqCst) {
            // Park like a backend that never acknowledges the dispatch;
            // the declared turn budget — never this task — must end the
            // initial dispatch wait.
            self.prompt_release.notified().await;
        }
        Ok(())
    }

    async fn follow_up(
        &self,
        _message: &LiveMessage,
        _owner_text: Option<&str>,
    ) -> Result<(), LiveError> {
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
        self.rollovers.lock().map_err(unavailable)?.push((
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
            return Err(LiveError::unavailable(
                "fixture-abort-refused",
                "the fixture refuses the abort",
            ));
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
            .map_err(unavailable)?
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
    async fn prompt(&self, _: &LiveMessage, _owner_text: Option<&str>) -> Result<(), LiveError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if self.lose_reply.load(Ordering::SeqCst) {
            return Err(LiveError::unavailable(
                "reply_lost_after_effect",
                "the fixture loses the reply",
            ));
        }
        Ok(())
    }
    async fn follow_up(
        &self,
        message: &LiveMessage,
        owner_text: Option<&str>,
    ) -> Result<(), LiveError> {
        self.prompt(message, owner_text).await
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
            let message = text_message("answer");
            let command = LiveCommand {
                command_id: CommandId::new("command:identity-blind").unwrap(),
                session_id: fixture.session_id,
                expected_epoch: fixture.epoch,
                expected_event_head: None,
                body: if follow_up {
                    LiveCommandBody::FollowUp {
                        message,
                        owner_text: None,
                    }
                } else {
                    LiveCommandBody::Prompt {
                        message,
                        owner_text: None,
                    }
                },
            };
            let initial = fixture.handle.command(command.clone()).await;
            if lose_reply {
                assert!(
                    matches!(initial, Err(LiveError::Unavailable { code, .. }) if code == "reply_lost_after_effect")
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
        Err(unavailable("the fixture pane does not support this"))
    }

    async fn write_input(&self, _operation_id: &CommandId, _bytes: &[u8]) -> Result<(), LiveError> {
        Err(unavailable("the fixture pane does not support this"))
    }

    async fn resize(
        &self,
        _operation_id: &CommandId,
        _columns: NonZeroU16,
        _rows: NonZeroU16,
    ) -> Result<(), LiveError> {
        Err(unavailable("the fixture pane does not support this"))
    }

    async fn terminate(&self) -> Result<(), LiveError> {
        self.terminate_calls.fetch_add(1, Ordering::SeqCst);
        if self.fail_terminate.load(Ordering::SeqCst) {
            Err(unavailable("the fixture pane does not support this"))
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
    _scratch: tempfile::TempDir,
}

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
    spawn_fixture_with_backend_factory(None, None, false, |manifest, root| {
        Some(make_backend(manifest, root))
    })
    .await
}

async fn spawn_fixture_with_backend(
    pane: Option<Arc<FakePane>>,
    turn_budget: Option<std::time::Duration>,
    override_backend: Option<Arc<dyn LiveControlBackend>>,
) -> Fixture {
    spawn_fixture_with_backend_factory(pane, turn_budget, false, |_, _| override_backend).await
}

/// `degraded` latches the ledger's journal-degraded gate before the actor starts, so every
/// ledger read the actor makes fails.
async fn spawn_fixture_with_backend_factory(
    pane: Option<Arc<FakePane>>,
    turn_budget: Option<std::time::Duration>,
    degraded: bool,
    make_backend: impl FnOnce(&SessionManifest, &std::path::Path) -> Option<Arc<dyn LiveControlBackend>>,
) -> Fixture {
    let scratch = tempfile::tempdir().expect("tempdir");
    let root = scratch.path().to_path_buf();
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
    if degraded {
        // A directory where the command segment belongs makes the next command commit fail,
        // which latches the ledger degraded.
        std::fs::create_dir_all(
            root.join("sessions")
                .join(session_id.to_string())
                .join("commands")
                .join("commands-00000000.seg"),
        )
        .expect("obstacle stands");
        ledger
            .append_command(&LiveCommand {
                command_id: CommandId::new("command:degrade").expect("command id"),
                session_id,
                expected_epoch: epoch,
                expected_event_head: None,
                body: LiveCommandBody::Pause,
            })
            .await
            .expect_err("the commit fails on the obstacle");
    }
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
        quiet_seconds: 600,
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
        _scratch: scratch,
    }
}

fn text_message(text: &str) -> LiveMessage {
    LiveMessage::new(vec![odin_domain::huginn::LiveContentBlock::Text(
        text.to_owned(),
    )])
    .unwrap()
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
        let message = text_message("answer");
        let command = LiveCommand {
            command_id: CommandId::new("command:recover-before-dispatch").unwrap(),
            session_id: fixture.session_id,
            expected_epoch: fixture.epoch,
            expected_event_head: None,
            body: if follow_up {
                LiveCommandBody::FollowUp {
                    message,
                    owner_text: None,
                }
            } else {
                LiveCommandBody::Prompt {
                    message,
                    owner_text: None,
                }
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
        let message = text_message("answer");
        let command = LiveCommand {
            command_id: CommandId::new("command:recover-after-dispatch").unwrap(),
            session_id: fixture.session_id,
            expected_epoch: fixture.epoch,
            expected_event_head: None,
            body: if follow_up {
                LiveCommandBody::FollowUp {
                    message,
                    owner_text: None,
                }
            } else {
                LiveCommandBody::Prompt {
                    message,
                    owner_text: None,
                }
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
    let message = text_message("durable");
    let command = LiveCommand {
        command_id: CommandId::new("command:durable-prompt").unwrap(),
        session_id: fixture.session_id,
        expected_epoch: fixture.epoch,
        expected_event_head: None,
        body: LiveCommandBody::Prompt {
            message,
            owner_text: None,
        },
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
        message: text_message("different"),
        owner_text: None,
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
            message: text_message("stale"),
            owner_text: None,
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
                model: ModelName::new("kimi-k31").unwrap(),
                route: Some(odin_domain::huginn::ClassRouteDecision {
                    from_class: "fast".into(),
                    to_class: "standard".into(),
                    warrant: Some(
                        "repeated typed tool/schema failure: test.run (arguments)".into(),
                    ),
                    through: EventSeq::new(1),
                    owner_message: None,
                    refusal: None,
                }),
            },
        })
        .await
        .unwrap();
    assert!(matches!(switched, CommandReceipt::Accepted { .. }));
    assert_eq!(applied_set_models().len(), 1);
    let history = fixture
        .ledger
        .history(HistoryQuery {
            session_id: fixture.session_id,
            after: EventSeq::new(0),
            limit: NonZeroU16::new(64).unwrap(),
        })
        .await
        .unwrap();
    assert!(history.events.iter().any(|event| matches!(&event.body,
        LiveEventBody::ModelRouted(route)
            if route.applied
                && route.model == "kimi-k31"
                && route.decision.to_class == "standard"
                && route.decision.warrant.as_deref().is_some_and(|warrant| warrant.contains("arguments"))
    )), "the applied switch and its warrant share the existing turn journal");

    let rolled = fixture.handle.rollover_fresh(31).await.unwrap();
    assert_eq!(rolled.epoch.get(), 2);
    assert_eq!(
        recorded_rollovers(),
        vec![(
            31,
            Some((
                ProviderName::new("gateway").unwrap(),
                ModelName::new("kimi-k31").unwrap()
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
                route: None,
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

    // A duplicate replays the recorded outcome without another teardown.
    let duplicate = fixture
        .handle
        .command(command.clone())
        .await
        .expect("duplicate command");
    assert_eq!(
        duplicate,
        CommandReceipt::Duplicate {
            command_id: command.command_id.clone(),
            prior_outcome: Some(Box::new(CommandOutcome::Applied {
                command_id: command.command_id.clone(),
            })),
        }
    );

    fixture.handle.stop().await.expect("stop after abort");
    assert_eq!(
        fixture.backend.abort_session_calls.load(Ordering::SeqCst),
        1
    );
    assert_eq!(fixture.backend.shutdown_calls.load(Ordering::SeqCst), 0);
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
            message: text_message("start a turn"),
            owner_text: None,
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
                    message: text_message("must not reach the backend"),
                    owner_text: None,
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
                message: text_message("answer without settling"),
                owner_text: None,
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
            message: text_message("start a turn"),
            owner_text: None,
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
                message: text_message("retry the turn"),
                owner_text: None,
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
                owner_text: None,
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
