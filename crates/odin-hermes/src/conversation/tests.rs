//! Invariant test support: the real FsLiveLedger journal and shared
//! session-state ledger with a scripted child actor, the fake egress,
//! authority, and approval seams, and the composition harness.

use super::*;
use crate::egress::EgressError;
use crate::natural::OwnerDecision;
use crate::runtime::{
    ApprovedIntentExecution, AuthenticatedOwnerMessage, DecisionRefusal, DeliveredApproval,
    IntentFailure,
};
use async_trait::async_trait;
use odin_domain::huginn::{
    AbortScope, CommandReceipt, CommandRejection, EventSeq, HistoryPage, HistoryQuery, LiveCommand,
    LiveCommandBody, LiveContentBlock, LiveError, LiveEventBody, LiveLaunchOption, LiveMessage,
    LiveSessionId, LiveSessionState, LiveSessionSummary, OpenSessionRequest, PermissionRequest,
    PermissionRequestId, PermissionResolution, SessionEpoch, SessionListPage, SessionListQuery,
    SessionManifest, TerminalSeq,
};
use odin_domain::{
    ApprovalId, CapabilityId, CommandId, ContainerId, Digest, EventId, LaneId, NodeId, ProjectId,
    RunId, SeatId, SliceId,
};
use odin_ledger::Ledger;
use odin_omp::bridge::ObservedFrame;
use odin_omp::live::ledger::{fs::FsLiveLedger, LiveLedger, NewLiveEvent};
use odin_omp::live::normalize::EventNormalizer;
use odin_omp::live::supervisor::LiveSeatBinding;
use parking_lot::Mutex;
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration as StdDuration;
use tempfile::{tempdir, TempDir};
use time::OffsetDateTime;

mod invariants;
mod queue;

mod delivery_regressions;
mod prompt_provenance;

pub(super) async fn delivery_test_root(
    egress: Arc<dyn ConversationEgress>,
) -> (TempDir, Arc<ConversationRoot>) {
    let dir = tempdir().expect("tempdir");
    let plane = Arc::new(FakePlane::new(dir.path()).await);
    let root = root_in(dir.path(), plane, egress, Arc::new(FakeApprovals::empty()));
    (dir, root)
}
const SEAT: &str = "gateway";
const PROJECT: &str = "proj";
/// The paired owner surface every admitted intent belongs to.
const OWNER: &str = "owner-1";
/// The paired DM channel the owner writes from.
const CHANNEL: &str = "chan-1";
const ANSWER_BOUND: StdDuration = StdDuration::from_secs(30);

const SESSION_LANE: &str = "lane-main";

/// The shared session-state ledger file: the one durable ledger the
/// production bridge runtime binds every live run into and the
/// conversation plan gate verifies acceptance against.
fn state_ledger_path(root: &std::path::Path) -> std::path::PathBuf {
    root.join("ledger.sqlite3")
}

#[derive(Clone, Copy)]
struct FakeLive {
    state: LiveSessionState,
    epoch: u64,
    live: bool,
}

/// The journal, history, command admission (epoch-checked, exactly
/// once by id), manifest presence, and the supervisor's durable
/// bridge-run binding are REAL (FsLiveLedger plus the shared
/// session-state ledger); only the child actor (auto-reply, pending
/// requests) is scripted.
struct FakePlane {
    ledger: FsLiveLedger,
    /// The shared session-state ledger the supervisor binds runs into.
    bridge_ledger: PathBuf,
    /// The seat's declared session lane; every live run binds to it.
    lane: LaneId,
    sessions: Mutex<BTreeMap<String, FakeLive>>,
    opens: Mutex<Vec<String>>,
    commands: Mutex<Vec<(String, String)>>,
    recoveries: Mutex<Vec<String>>,
    /// Whole-session retirements observed by the rollover: the session
    /// ids governed Ended through the canonical abort surface.
    retirements: Mutex<Vec<String>>,
    /// The next N whole-session aborts are journaled Rejected and do not
    /// end the session. A later abort of the same session is a new command
    /// and ends it.
    fail_retirements: AtomicUsize,
    /// The initial prompts of every open, in order.
    initial_prompts: Mutex<Vec<String>>,
    /// plane refusal — the production bridge/launch failure class.
    reclaim_failure: Mutex<Option<LiveError>>,
    auto_reply: AtomicBool,
    /// A prompt leaves the session Running with no answer (a long turn).
    hold_running: AtomicBool,
    /// When >0, the next rollover-brief prompts are RECORDED in the real
    /// journal without an applied outcome and without processing — the
    /// production wedge shape (the successor never came up; its accepting
    /// run is gone).
    record_only_briefs: AtomicUsize,
    /// When >0, the next rollover-brief prompts are journaled and settle
    /// with a durable retryable Failed outcome — the production shape where
    /// the continuity turn's brain compile refused.
    fail_briefs: AtomicUsize,
    /// When >0, the next owner prompts are journaled and settle Failed —
    /// the turn compile refused before the model ran.
    fail_prompts: AtomicUsize,
    /// Owner prompts the bridge refuses for the context window
    /// (`context_refusal.window_exceeded`, then Failed), in order.
    refuse_context: AtomicUsize,
    /// Turns the model provider refuses (usage limit): an error, then Failed.
    refuse_provider: AtomicUsize,
    /// Provider-turn frame scripts, one per owner prompt in order: the
    /// production EventNormalizer turns each script into the journal events
    /// and session states, so the consumer sees what the producer writes.
    normalized_turns: Mutex<std::collections::VecDeque<Vec<serde_json::Value>>>,
    /// The normalizer's blob ledger; provider-turn frames never store a blob.
    normalizer_ledger: Arc<dyn LiveLedger>,
    /// The previous turn is still running when the next command is
    /// accepted: its own question lands between the acceptance and the
    /// new turn's user message.
    previous_turn_trails: AtomicBool,
    /// Post-tool requests refused with `context_refusal.envelope_invalid`, followed by idle recovery.
    refuse_envelope: AtomicUsize,
    /// Turns that run and settle Idle with no reply text (the model ended
    /// on a tool call).
    silent_turns: AtomicUsize,
    /// Turns that answer only the quiet token.
    quiet_turns: AtomicUsize,
    /// When positive, opens create a session then fail, leaving it ended.
    fail_opens: AtomicUsize,
    resolve_permissions: AtomicBool,
    pause_next_prompt: AtomicBool,
    /// The next prompt is admitted and runs, but its receipt is lost on the
    /// way back, and the journal lookup right after it fails once.
    lose_receipt: AtomicBool,
    fail_next_entry: AtomicBool,
    prompt_paused: tokio::sync::Notify,
    history_changed: tokio::sync::Notify,
    answer: Mutex<String>,
    pending_requests: Mutex<Vec<String>>,
}

impl FakePlane {
    async fn new(root: &std::path::Path) -> Self {
        let ledger = FsLiveLedger::open(root.join("live")).expect("live ledger opens");
        let normalizer_ledger: Arc<dyn LiveLedger> = Arc::new(
            FsLiveLedger::open(root.join("normalizer-live")).expect("normalizer ledger opens"),
        );
        let plane = Self {
            ledger,
            normalized_turns: Mutex::new(std::collections::VecDeque::new()),
            normalizer_ledger,
            bridge_ledger: state_ledger_path(root),
            lane: LaneId::new(SESSION_LANE).expect("lane id"),
            pause_next_prompt: AtomicBool::new(false),
            lose_receipt: AtomicBool::new(false),
            fail_next_entry: AtomicBool::new(false),
            prompt_paused: tokio::sync::Notify::new(),
            history_changed: tokio::sync::Notify::new(),
            sessions: Mutex::new(BTreeMap::new()),
            opens: Mutex::new(Vec::new()),
            commands: Mutex::new(Vec::new()),
            recoveries: Mutex::new(Vec::new()),
            retirements: Mutex::new(Vec::new()),
            fail_retirements: AtomicUsize::new(0),
            initial_prompts: Mutex::new(Vec::new()),
            reclaim_failure: Mutex::new(None),
            auto_reply: AtomicBool::new(true),
            hold_running: AtomicBool::new(false),
            record_only_briefs: AtomicUsize::new(0),
            fail_briefs: AtomicUsize::new(0),
            fail_prompts: AtomicUsize::new(0),
            refuse_context: AtomicUsize::new(0),
            refuse_provider: AtomicUsize::new(0),
            previous_turn_trails: AtomicBool::new(false),
            refuse_envelope: AtomicUsize::new(0),
            silent_turns: AtomicUsize::new(0),
            quiet_turns: AtomicUsize::new(0),
            fail_opens: AtomicUsize::new(0),
            resolve_permissions: AtomicBool::new(true),
            answer: Mutex::new("A plain answer.".to_owned()),
            pending_requests: Mutex::new(vec!["perm-a".to_owned()]),
        };
        plane.reload_discovered().await;
        plane
    }

    /// A fresh daemon over the same live root discovers the durable
    /// sessions parked: no live actor anywhere.
    async fn reload_discovered(&self) {
        let discovered = self
            .ledger
            .sessions()
            .await
            .expect("durable sessions readable");
        let mut sessions = self.sessions.lock();
        for session in discovered {
            sessions
                .entry(session.manifest.session_id.to_string())
                .or_insert(FakeLive {
                    state: LiveSessionState::Idle,
                    epoch: session.epoch.get(),
                    live: false,
                });
        }
    }

    fn vehicle_session(command: &CommandId) -> LiveSessionId {
        odin_omp::live::supervisor::session_id_for(command).expect("vehicle session")
    }

    fn manifest(&self, session: LiveSessionId) -> SessionManifest {
        SessionManifest {
            session_id: session,
            seat_id: SeatId::new(SEAT).expect("seat id"),
            slice_id: SliceId::new("slice-main").expect("slice id"),
            project_id: ProjectId::new(PROJECT).expect("project id"),
            provider: ProviderName::new("prov").expect("provider"),
            model: ModelName::new("model").expect("model"),
            title: None,
            target_node: NodeId::new("node-a").expect("node id"),
            open_tab: false,
            workload: None,
            served_revision: None,
            harness: None,
        }
    }

    /// The production supervisor's first durable act for a live
    /// session, mirrored exactly: the `run:live:<session>` row is
    /// bound to the session lane under its lane parent in the shared
    /// session-state ledger before any open summary is returned; the
    /// conversation plan gate later verifies acceptance against this
    /// same run.
    fn ensure_bridge_run(&self, session: LiveSessionId) {
        let manifest = self.manifest(session);
        let input_hash =
            Digest::hash(&serde_json::to_vec(&manifest).expect("manifest serializes")).to_string();
        let ledger = Ledger::open(&self.bridge_ledger).expect("session-state ledger opens");
        let connection = ledger.connection();
        if odin_ledger::lane_run::read_lane(connection, &self.lane)
            .expect("session lane readable")
            .is_none()
        {
            odin_ledger::lane_run::create_lane(
                connection,
                &odin_ledger::lane_run::NewLane {
                    lane_id: self.lane.clone(),
                    seat_id: manifest.seat_id.clone(),
                    project_id: Some(manifest.project_id.clone()),
                    template_id: "default".to_owned(),
                    backend: "local_omp".to_owned(),
                    created_by: "live-session".to_owned(),
                    created_at: OffsetDateTime::UNIX_EPOCH,
                    retained: false,
                },
            )
            .expect("session lane created");
        }
        let run_id = RunId::new(format!("run:live:{session}")).expect("run id");
        if let Some(existing) =
            odin_ledger::lane_run::read_run(connection, &run_id).expect("session run readable")
        {
            assert_eq!(
                existing.lane_id, self.lane,
                "the live run rides the session lane"
            );
            return;
        }
        let attempt_number: i64 = connection
            .query_row(
                "SELECT COALESCE(MAX(attempt_number), 0) + 1 FROM runs WHERE lane_id = ?1",
                [self.lane.to_string()],
                |row| row.get(0),
            )
            .expect("run attempt number readable");
        odin_ledger::lane_run::create_run(
            connection,
            &odin_ledger::lane_run::NewRun {
                run_id,
                lane_id: self.lane.clone(),
                attempt_number,
                workflow_id: Some(format!("live:{}", manifest.slice_id)),
                workflow_version: Some(1),
                input_hash,
                accepted_capability_revision: None,
                lease_id: None,
                absolute_deadline: None,
                retry_budget: 0,
                created_at: OffsetDateTime::UNIX_EPOCH,
            },
        )
        .expect("session run created");
    }

    async fn seed(
        &self,
        command: &CommandId,
        state: LiveSessionState,
        live: bool,
    ) -> LiveSessionId {
        let session = Self::vehicle_session(command);
        self.ledger
            .create_session(self.manifest(session))
            .await
            .expect("manifest created");
        self.ensure_bridge_run(session);
        self.sessions.lock().insert(
            session.to_string(),
            FakeLive {
                state,
                epoch: 1,
                live,
            },
        );
        session
    }

    async fn push_event(&self, session: &LiveSessionId, body: LiveEventBody) {
        let epoch = {
            let sessions = self.sessions.lock();
            sessions.get(&session.to_string()).expect("seeded").epoch
        };
        let sequence = self.ledger.head(*session).await.expect("head").get() + 1;
        self.ledger
            .append(
                SessionEpoch::new(epoch),
                NewLiveEvent {
                    session_id: *session,
                    event_id: EventId::new(format!("event-{session}-{sequence}"))
                        .expect("event id"),
                    occurred_at: time::OffsetDateTime::UNIX_EPOCH,
                    body,
                },
            )
            .await
            .expect("event appended");
        self.history_changed.notify_waiters();
    }

    async fn push_state_change(&self, session: &LiveSessionId, current: LiveSessionState) {
        self.push_event(
            session,
            LiveEventBody::SessionStateChanged(odin_domain::huginn::SessionStateChanged {
                previous: LiveSessionState::Running,
                current,
                reason: None,
            }),
        )
        .await;
        self.set_state(session, current);
    }

    /// Journals what the production normalizer writes for `frames` and
    /// follows the session state the way the journal folds it.
    async fn push_normalized_frames(
        &self,
        session: &LiveSessionId,
        frames: Vec<serde_json::Value>,
    ) {
        let epoch = {
            let sessions = self.sessions.lock();
            sessions.get(&session.to_string()).expect("seeded").epoch
        };
        let normalizer = EventNormalizer::new(
            *session,
            SessionEpoch::new(epoch),
            LiveSessionState::Idle,
            Arc::clone(&self.normalizer_ledger),
        );
        let mut state = LiveSessionState::Idle;
        for frame in frames {
            let bodies = normalizer
                .normalize_omp(&ObservedFrame::harness_event(frame))
                .expect("frame normalizes");
            for body in bodies {
                state = odin_omp::live::ledger::state_after(state, &body);
                self.push_event(session, body).await;
                self.set_state(session, state);
            }
        }
    }

    fn set_state_public(&self, session: &LiveSessionId, state: LiveSessionState) {
        let mut sessions = self.sessions.lock();
        let fake = sessions.entry(session.to_string()).or_insert(FakeLive {
            state,
            epoch: 1,
            live: false,
        });
        fake.state = state;
    }

    /// Ends a held long turn with `answer`.
    async fn finish_turn(&self, session: &LiveSessionId, answer: &str) {
        self.push_event(
            session,
            LiveEventBody::AssistantMessage(text_message(answer)),
        )
        .await;
        self.push_state_change(session, LiveSessionState::Idle)
            .await;
    }

    fn set_state(&self, session: &LiveSessionId, state: LiveSessionState) {
        self.sessions
            .lock()
            .get_mut(&session.to_string())
            .expect("seeded session")
            .state = state;
    }

    fn state_of(&self, session: &LiveSessionId) -> Option<LiveSessionState> {
        self.sessions
            .lock()
            .get(&session.to_string())
            .map(|fake| fake.state)
    }

    fn command_entries(&self, needle: &str) -> Vec<String> {
        self.commands
            .lock()
            .iter()
            .filter(|(id, _)| id.contains(needle))
            .map(|(_, kind)| kind.clone())
            .collect()
    }

    fn prompt_count(&self, needle: &str) -> usize {
        self.command_entries(needle)
            .iter()
            .filter(|kind| kind.as_str() == "prompt" || kind.as_str() == "follow_up")
            .count()
    }

    fn decide_count(&self) -> usize {
        self.command_entries("command:permission:").len()
    }
}

fn text_message(text: &str) -> LiveMessage {
    LiveMessage::new(vec![LiveContentBlock::Text(text.to_owned())]).expect("message")
}

fn permission_request(request_id: &str, prompt: &str) -> PermissionRequest {
    PermissionRequest {
        request_id: PermissionRequestId::new(request_id).expect("request id"),
        tool_use_id: "tool-1".to_owned(),
        capability_id: CapabilityId::new("email.send").expect("capability id"),
        arguments_digest: Digest::hash(b"arguments"),
        prompt: prompt.to_owned(),
        expires_at: time::OffsetDateTime::now_utc() + time::Duration::hours(1),
    }
}

fn fake_summary(session: &LiveSessionId, fake: &FakeLive, head: EventSeq) -> LiveSessionSummary {
    LiveSessionSummary {
        session_id: *session,
        epoch: SessionEpoch::new(fake.epoch),
        seat_id: SeatId::new(SEAT).expect("seat id"),
        provider: ProviderName::new("prov").expect("provider"),
        model: ModelName::new("model").expect("model"),
        title: None,
        state: fake.state,
        started_at: time::OffsetDateTime::UNIX_EPOCH,
        updated_at: time::OffsetDateTime::UNIX_EPOCH,
        failed_at: None,
        event_head: head,
        terminal_head: TerminalSeq::new(0),
        pending_permission_count: 0,
    }
}

#[async_trait]
impl ConversationPlane for FakePlane {
    async fn sessions(&self, query: SessionListQuery) -> Result<SessionListPage, LiveError> {
        let sessions: Vec<_> = self
            .sessions
            .lock()
            .iter()
            .map(|(id, state)| (id.clone(), *state))
            .collect();
        let mut listed = Vec::new();
        for (id, fake) in sessions.iter() {
            if !query.include_ended
                && matches!(
                    fake.state,
                    LiveSessionState::Ended | LiveSessionState::Failed
                )
            {
                continue;
            }
            let session = LiveSessionId::parse(id).expect("session id");
            let head = self.ledger.head(session).await.expect("head");
            listed.push(fake_summary(&session, fake, head));
        }
        Ok(SessionListPage::new(listed, None))
    }

    async fn open_session(
        &self,
        request: OpenSessionRequest,
    ) -> Result<LiveSessionSummary, LiveError> {
        self.opens.lock().push(request.command_id.to_string());
        if let Some(prompt) = &request.initial_prompt {
            self.initial_prompts
                .lock()
                .push(history::assistant_text(prompt));
        }
        let session = odin_omp::live::supervisor::session_id_for(&request.command_id)?;
        self.ledger
            .create_session(self.manifest(session))
            .await
            .ok();
        self.ensure_bridge_run(session);
        if self
            .fail_opens
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |left| {
                left.checked_sub(1)
            })
            .is_ok()
        {
            self.sessions.lock().insert(
                session.to_string(),
                FakeLive {
                    state: LiveSessionState::Ended,
                    epoch: 1,
                    live: false,
                },
            );
            return Err(LiveError::Unavailable {
                code: "omp_bridge_start: Host URI scheme is reserved by OMP: artifact://"
                    .to_owned(),
            });
        }
        let head = self
            .ledger
            .head(session)
            .await
            .map_err(odin_omp::live::ledger::live_error)?;
        let summary = {
            let mut sessions = self.sessions.lock();
            let fake = sessions
                .entry(session.to_string())
                .or_insert_with(|| FakeLive {
                    state: LiveSessionState::Idle,
                    epoch: 1,
                    live: true,
                });
            fake.state = LiveSessionState::Idle;
            fake.live = true;
            fake_summary(&session, fake, head)
        };
        Ok(summary)
    }

    async fn command(&self, command: LiveCommand) -> Result<CommandReceipt, LiveError> {
        if matches!(&command.body, LiveCommandBody::Prompt { .. })
            && self.lose_receipt.swap(false, Ordering::SeqCst)
        {
            let _ = self.command(command).await;
            self.fail_next_entry.store(true, Ordering::SeqCst);
            return Err(LiveError::Unavailable {
                code: "connection reset".to_owned(),
            });
        }
        if matches!(&command.body, LiveCommandBody::Prompt { .. })
            && self.pause_next_prompt.swap(false, Ordering::SeqCst)
        {
            // Deterministic crash window before durable command admission.
            self.prompt_paused.notify_one();
            std::future::pending::<()>().await;
        }
        let kind = match &command.body {
            LiveCommandBody::Prompt { .. } => "prompt",
            LiveCommandBody::FollowUp { .. } => "follow_up",
            LiveCommandBody::DecidePermission { .. } => "decide_permission",
            _ => "other",
        };
        if matches!(
            &command.body,
            LiveCommandBody::Abort {
                scope: AbortScope::Session,
            }
        ) {
            if self.fail_retirements.load(Ordering::SeqCst) > 0 {
                self.fail_retirements.fetch_sub(1, Ordering::SeqCst);
                self.ledger
                    .append_command(&command)
                    .await
                    .map_err(odin_omp::live::ledger::live_error)?;
                return Ok(CommandReceipt::Rejected {
                    command_id: command.command_id.clone(),
                    reason: CommandRejection::InvalidState {
                        command: odin_domain::huginn::LiveCommandKind::AbortSession,
                        state: LiveSessionState::Running,
                    },
                });
            }
            self.retirements.lock().push(command.session_id.to_string());
            self.set_state_public(&command.session_id, LiveSessionState::Ended);
            return Ok(CommandReceipt::Accepted {
                command_id: command.command_id.clone(),
            });
        }
        // REAL journal lookup first: an admitted id replays its
        // stored receipt and never re-executes.
        if let Some(entry) = self
            .ledger
            .command(&command)
            .await
            .map_err(odin_omp::live::ledger::live_error)?
        {
            self.commands
                .lock()
                .push((command.command_id.to_string(), format!("{kind}:replayed")));
            return Ok(entry.receipt);
        }
        let parked = !self
            .sessions
            .lock()
            .get(&command.session_id.to_string())
            .map(|fake| fake.live)
            .unwrap_or(false);
        if parked {
            return Err(LiveError::Conflict {
                code: "session_parked".to_owned(),
                message: "the session is parked after a daemon restart".to_owned(),
            });
        }
        // The production wedge window: the journal RECORDS the brief
        // command, but the successor that would apply it never comes up —
        // no outcome is ever written and nothing can write one.
        let brief_failure = self.fail_briefs.load(Ordering::SeqCst) > 0;
        if (brief_failure || self.record_only_briefs.load(Ordering::SeqCst) > 0)
            && matches!(
                &command.body,
                LiveCommandBody::Prompt { message }
                    if message.content.iter().any(|block| matches!(
                        block,
                        LiveContentBlock::Text(text)
                            if text.starts_with(
                                odin_omp::live::rollover::ROLLOVER_PROMPT_MARKER
                            )
                    ))
            )
        {
            self.ledger
                .append_command(&command)
                .await
                .map_err(odin_omp::live::ledger::live_error)?;
            if brief_failure {
                self.fail_briefs.fetch_sub(1, Ordering::SeqCst);
                self.ledger
                    .complete_command(
                        command.command_id.clone(),
                        odin_domain::huginn::CommandOutcome::Failed {
                            command_id: command.command_id.clone(),
                            error: odin_domain::huginn::CommandFailure {
                                code: "control_failed".to_owned(),
                                message: "live service unavailable: brain_turn_compile: stale brain authority".to_owned(),
                                retryable: true,
                            },
                        },
                    )
                    .await
                    .map_err(odin_omp::live::ledger::live_error)?;
                self.commands
                    .lock()
                    .push((command.command_id.to_string(), "brief:failed".to_owned()));
            } else {
                self.record_only_briefs.fetch_sub(1, Ordering::SeqCst);
                self.commands.lock().push((
                    command.command_id.to_string(),
                    "brief:recorded-only".to_owned(),
                ));
            }
            return Ok(CommandReceipt::Accepted {
                command_id: command.command_id.clone(),
            });
        }
        if matches!(&command.body, LiveCommandBody::Prompt { .. })
            && self.fail_prompts.load(Ordering::SeqCst) > 0
        {
            // The production shape: the actor journals the command, settles
            // it Failed, and emits its ControlAccepted/ControlCompleted.
            self.fail_prompts.fetch_sub(1, Ordering::SeqCst);
            self.ledger
                .append_command(&command)
                .await
                .map_err(odin_omp::live::ledger::live_error)?;
            let outcome = odin_domain::huginn::CommandOutcome::Failed {
                command_id: command.command_id.clone(),
                error: odin_domain::huginn::CommandFailure {
                    code: "control_failed".to_owned(),
                    message: "live service unavailable: brain_turn_compile: brain store \
                              brain-index-store is corrupt"
                        .to_owned(),
                    retryable: true,
                },
            };
            self.ledger
                .complete_command(command.command_id.clone(), outcome.clone())
                .await
                .map_err(odin_omp::live::ledger::live_error)?;
            self.push_event(
                &command.session_id,
                LiveEventBody::ControlAccepted(CommandReceipt::Accepted {
                    command_id: command.command_id.clone(),
                }),
            )
            .await;
            self.push_event(
                &command.session_id,
                LiveEventBody::ControlCompleted(outcome),
            )
            .await;
            return Ok(CommandReceipt::Accepted {
                command_id: command.command_id.clone(),
            });
        }
        let current_epoch = self
            .sessions
            .lock()
            .get(&command.session_id.to_string())
            .map(|fake| fake.epoch)
            .unwrap_or(1);
        if command.expected_epoch.get() != current_epoch {
            return Ok(CommandReceipt::Rejected {
                command_id: command.command_id.clone(),
                reason: CommandRejection::EpochMismatch {
                    expected: command.expected_epoch,
                    actual: SessionEpoch::new(current_epoch),
                },
            });
        }
        self.ledger
            .append_command(&command)
            .await
            .map_err(odin_omp::live::ledger::live_error)?;
        // The session actor journals every admitted command's acceptance
        // into the session history before its turn runs.
        self.push_event(
            &command.session_id,
            LiveEventBody::ControlAccepted(CommandReceipt::Accepted {
                command_id: command.command_id.clone(),
            }),
        )
        .await;
        self.commands
            .lock()
            .push((command.command_id.to_string(), kind.to_owned()));
        match command.body {
            LiveCommandBody::Prompt { message } | LiveCommandBody::FollowUp { message } => {
                let brief = message.content.iter().any(|block| {
                    matches!(
                        block,
                        LiveContentBlock::Text(text)
                            if text.starts_with(odin_omp::live::rollover::ROLLOVER_PROMPT_MARKER)
                    )
                });
                if brief {
                    self.initial_prompts
                        .lock()
                        .push(history::assistant_text(&message));
                }
                if !brief && self.previous_turn_trails.swap(false, Ordering::SeqCst) {
                    self.push_event(
                        &command.session_id,
                        LiveEventBody::AssistantMessage(text_message(
                            "Create \u{201c}tea\u{201d} on your calendar at 3?",
                        )),
                    )
                    .await;
                    self.push_state_change(&command.session_id, LiveSessionState::Idle)
                        .await;
                    self.push_state_change(&command.session_id, LiveSessionState::Running)
                        .await;
                }
                self.push_event(&command.session_id, LiveEventBody::UserMessage(message))
                    .await;
                if !brief
                    && self
                        .refuse_context
                        .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |left| {
                            left.checked_sub(1)
                        })
                        .is_ok()
                {
                    self.push_event(
                        &command.session_id,
                        LiveEventBody::Error(odin_domain::huginn::SessionError {
                            code: "context_refusal.window_exceeded".to_owned(),
                            message: "request requires 486994 byte tokens, exceeding the \
                                      declared window 272000"
                                .to_owned(),
                            retryable: true,
                            error_status: None,
                        }),
                    )
                    .await;
                    self.push_state_change(&command.session_id, LiveSessionState::Failed)
                        .await;
                    return Ok(CommandReceipt::Accepted {
                        command_id: command.command_id.clone(),
                    });
                }
                if !brief
                    && self
                        .refuse_provider
                        .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |left| {
                            left.checked_sub(1)
                        })
                        .is_ok()
                {
                    self.push_event(
                        &command.session_id,
                        LiveEventBody::Error(odin_domain::huginn::SessionError {
                            code: "provider_turn_error".to_owned(),
                            message: "429 {\"error\":{\"message\":\"You exceeded your current \
                                      quota\",\"type\":\"insufficient_quota\"}}"
                                .to_owned(),
                            retryable: false,
                            error_status: Some(429),
                        }),
                    )
                    .await;
                    self.push_state_change(&command.session_id, LiveSessionState::Failed)
                        .await;
                    return Ok(CommandReceipt::Accepted {
                        command_id: command.command_id.clone(),
                    });
                }
                let scripted = if brief {
                    None
                } else {
                    self.normalized_turns.lock().pop_front()
                };
                if let Some(frames) = scripted {
                    self.push_normalized_frames(&command.session_id, frames)
                        .await;
                    return Ok(CommandReceipt::Accepted {
                        command_id: command.command_id.clone(),
                    });
                }
                if !brief
                    && self
                        .refuse_envelope
                        .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |left| {
                            left.checked_sub(1)
                        })
                        .is_ok()
                {
                    self.push_state_change(&command.session_id, LiveSessionState::Running)
                        .await;
                    self.push_event(
                        &command.session_id,
                        LiveEventBody::Error(odin_domain::huginn::SessionError {
                            code: "context_refusal.envelope_invalid".to_owned(),
                            message: "registered retrieval block is missing or ambiguous in \
                                      the provider user payload"
                                .to_owned(),
                            retryable: true,
                            error_status: None,
                        }),
                    )
                    .await;
                    self.push_state_change(&command.session_id, LiveSessionState::Failed)
                        .await;
                    self.push_state_change(&command.session_id, LiveSessionState::Idle)
                        .await;
                    return Ok(CommandReceipt::Accepted {
                        command_id: command.command_id.clone(),
                    });
                }
                if !brief
                    && self
                        .silent_turns
                        .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |left| {
                            left.checked_sub(1)
                        })
                        .is_ok()
                {
                    self.push_state_change(&command.session_id, LiveSessionState::Running)
                        .await;
                    self.push_state_change(&command.session_id, LiveSessionState::Idle)
                        .await;
                } else if self.hold_running.load(Ordering::SeqCst) {
                    self.push_state_change(&command.session_id, LiveSessionState::Running)
                        .await;
                } else if self.auto_reply.load(Ordering::SeqCst) {
                    let quiet = !brief
                        && self
                            .quiet_turns
                            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |left| {
                                left.checked_sub(1)
                            })
                            .is_ok();
                    let answer = if quiet {
                        super::prompt::QUIET_REPLY.to_owned()
                    } else {
                        self.answer.lock().clone()
                    };
                    self.push_event(
                        &command.session_id,
                        LiveEventBody::AssistantMessage(text_message(&answer)),
                    )
                    .await;
                    self.push_state_change(&command.session_id, LiveSessionState::Idle)
                        .await;
                } else {
                    let requests = self.pending_requests.lock().clone();
                    for request in requests {
                        self.push_event(
                            &command.session_id,
                            LiveEventBody::PermissionRequested(permission_request(
                                &request,
                                "Send the drafted message?",
                            )),
                        )
                        .await;
                    }
                    self.push_state_change(&command.session_id, LiveSessionState::RequiresAction)
                        .await;
                }
            }
            LiveCommandBody::DecidePermission {
                request_id,
                decision,
            } => {
                if !self.resolve_permissions.load(Ordering::SeqCst) {
                    return Ok(CommandReceipt::Accepted {
                        command_id: command.command_id.clone(),
                    });
                }
                self.push_event(
                    &command.session_id,
                    LiveEventBody::PermissionResolved(PermissionResolution {
                        request_id,
                        command_id: command.command_id.clone(),
                        decision,
                    }),
                )
                .await;
                if self.auto_reply.load(Ordering::SeqCst) {
                    let answer = self.answer.lock().clone();
                    self.push_event(
                        &command.session_id,
                        LiveEventBody::AssistantMessage(text_message(&answer)),
                    )
                    .await;
                }
                self.push_state_change(&command.session_id, LiveSessionState::Idle)
                    .await;
            }
            _ => {}
        }
        self.ledger
            .complete_command(
                command.command_id.clone(),
                odin_domain::huginn::CommandOutcome::Applied {
                    command_id: command.command_id.clone(),
                },
            )
            .await
            .map_err(odin_omp::live::ledger::live_error)?;
        Ok(CommandReceipt::Accepted {
            command_id: command.command_id.clone(),
        })
    }

    async fn history(&self, query: HistoryQuery) -> Result<HistoryPage, LiveError> {
        self.ledger
            .history(query)
            .await
            .map_err(odin_omp::live::ledger::live_error)
    }

    async fn wait_for_history(
        &self,
        session_id: LiveSessionId,
        after: EventSeq,
    ) -> Result<(), LiveError> {
        loop {
            let notified = self.history_changed.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if self
                .ledger
                .head(session_id)
                .await
                .map_err(odin_omp::live::ledger::live_error)?
                > after
            {
                return Ok(());
            }
            notified.await;
        }
    }

    async fn recover_session(
        &self,
        session_id: LiveSessionId,
    ) -> Result<LiveSessionSummary, LiveError> {
        self.recoveries.lock().push(session_id.to_string());
        let ended = self
            .sessions
            .lock()
            .get(&session_id.to_string())
            .map(|fake| fake.state == LiveSessionState::Ended)
            .unwrap_or(false);
        if ended {
            return Err(LiveError::Conflict {
                code: "session_ended".to_owned(),
                message: "the session is truthfully ended".to_owned(),
            });
        }
        if let Some(failure) = self.reclaim_failure.lock().clone() {
            return Err(failure);
        }
        let epoch = self
            .ledger
            .reclaim(session_id)
            .await
            .map_err(odin_omp::live::ledger::live_error)?;
        let head = self
            .ledger
            .head(session_id)
            .await
            .unwrap_or(EventSeq::new(0));
        let summary = {
            let mut sessions = self.sessions.lock();
            let fake = sessions.entry(session_id.to_string()).or_insert(FakeLive {
                state: LiveSessionState::Idle,
                epoch: epoch.get(),
                live: true,
            });
            fake.epoch = epoch.get();
            fake.state = LiveSessionState::Idle;
            fake.live = true;
            fake_summary(&session_id, fake, head)
        };
        Ok(summary)
    }

    async fn command_entry(
        &self,
        command: &LiveCommand,
    ) -> Result<Option<odin_omp::live::ledger::CommandJournalEntry>, LiveError> {
        if self.fail_next_entry.swap(false, Ordering::SeqCst) {
            return Err(LiveError::Unavailable {
                code: "journal busy".to_owned(),
            });
        }
        self.ledger
            .command(command)
            .await
            .map_err(odin_omp::live::ledger::live_error)
    }

    async fn session_manifest_present(&self, session_id: LiveSessionId) -> Result<bool, LiveError> {
        Ok(self.ledger.session(session_id).await.is_ok())
    }
}

struct FakeEgress {
    sends: Mutex<Vec<String>>,
    fail: AtomicBool,
    reviews: Mutex<Vec<crate::runtime::review::Exchange>>,
    delivery_failure: Mutex<Option<(usize, crate::discord::DiscordSendError)>>,
}

impl FakeEgress {
    fn new() -> Self {
        Self {
            sends: Mutex::new(Vec::new()),
            fail: AtomicBool::new(false),
            reviews: Mutex::new(Vec::new()),
            delivery_failure: Mutex::new(None),
        }
    }

    fn sends(&self) -> Vec<String> {
        self.sends.lock().clone()
    }

    fn post(&self, content: &str) -> crate::discord::DiscordMessageRef {
        let mut sends = self.sends.lock();
        sends.push(content.to_owned());
        crate::discord::DiscordMessageRef {
            message_id: ((1_000 + sends.len() as u64) << 22).to_string(),
            channel_id: CHANNEL.to_owned(),
        }
    }
}

impl ConversationEgress for FakeEgress {
    fn deliver(
        &self,
        content: &str,
        checkpoint: Arc<dyn crate::egress::DeliveryCheckpoint>,
    ) -> Result<crate::egress::ReplyChunks, EgressError> {
        use crate::egress::{DeliveryOperation, OutboundMessage, ReplyChunks};
        let plan = checkpoint.prepare(&OutboundMessage {
            channel_id: CHANNEL.to_owned(),
            content: content.to_owned(),
        })?;
        let mut held: Vec<_> = plan
            .ownership
            .as_ref()
            .map(|reply| reply.refs().cloned().collect())
            .unwrap_or_default();
        for (applied, operation) in plan.operations.iter().enumerate() {
            let reservation = checkpoint.reserve(operation)?;
            let failure = {
                let mut failure = self.delivery_failure.lock();
                if failure.as_ref().is_some_and(|(index, _)| *index == applied) {
                    failure.take().map(|(_, error)| error)
                } else if self.fail.load(Ordering::SeqCst) {
                    Some(crate::discord::DiscordSendError::Unreachable)
                } else {
                    None
                }
            };
            if let Some(error) = failure {
                checkpoint.failed(&reservation, &error)?;
                return Err(if held.is_empty() {
                    EgressError::Transport(error)
                } else {
                    EgressError::Partial {
                        ownership: Box::new(ReplyChunks {
                            anchor: held[0].clone(),
                            tails: held[1..].to_vec(),
                        }),
                        applied,
                        total: plan.operations.len(),
                        post_outcome_unknown: matches!(operation, DeliveryOperation::Post { .. })
                            && EgressError::Transport(error.clone()).post_outcome_unknown(),
                        source: error,
                    }
                });
            }
            let reference = match operation {
                DeliveryOperation::Post { content, .. } => Some(self.post(content)),
                DeliveryOperation::Patch {
                    reference, content, ..
                } => {
                    self.sends
                        .lock()
                        .push(format!("[edit {}] {content}", reference.message_id));
                    Some(reference.clone())
                }
                DeliveryOperation::Delete { reference } => {
                    self.sends
                        .lock()
                        .push(format!("[delete {}]", reference.message_id));
                    None
                }
            };
            checkpoint.acknowledge(&reservation, reference.as_ref())?;
            match operation {
                DeliveryOperation::Post { .. } => held.push(reference.unwrap()),
                DeliveryOperation::Patch { index, .. } => held[*index] = reference.unwrap(),
                DeliveryOperation::Delete { reference } => held.retain(|item| item != reference),
            }
        }
        checkpoint.complete()?;
        let mut held = held.into_iter();
        let anchor = held
            .next()
            .ok_or(EgressError::InvalidState("fake delivery has no messages"))?;
        Ok(ReplyChunks {
            anchor,
            tails: held.collect(),
        })
    }

    fn typing(&self) -> Result<(), String> {
        Ok(())
    }

    fn turn_answered(&self, exchange: crate::runtime::review::Exchange) {
        self.reviews.lock().push(exchange);
    }
}

struct FakeAuthority {
    calls: Mutex<Vec<String>>,
    /// The ensured token's own generation versus the per-call current
    /// pin: the fresh-generation trigger facts.
    bound: u64,
    current: u64,
    /// Per-command generation overrides consulted before the static
    /// pair: the staged publication drift of a scripted scenario. An
    /// ensure for an unscripted command reports the static pair.
    script: Mutex<BTreeMap<String, EnsuredGeneration>>,
    /// The host's pending-reload gate ([`ConversationAuthority::rollover_deferred`]).
    deferred: std::sync::atomic::AtomicBool,
    /// What the successor transition reported to the host's desk.
    troubles: Mutex<Vec<crate::conversation::SuccessorTrouble>>,
}

#[async_trait]
impl ConversationAuthority for FakeAuthority {
    async fn ensure(
        &self,
        command_id: &CommandId,
        session_id: LiveSessionId,
    ) -> Result<crate::conversation::EnsuredGeneration, String> {
        self.calls
            .lock()
            .push(format!("{command_id} -> {session_id}"));
        Ok(self
            .script
            .lock()
            .get(&command_id.to_string())
            .copied()
            .unwrap_or(EnsuredGeneration {
                bound: self.bound,
                current: self.current,
                composition: None,
            }))
    }

    fn rollover_deferred(&self) -> bool {
        self.deferred.load(Ordering::SeqCst)
    }

    fn successor_trouble(
        &self,
        _conversation_id: &str,
        trouble: crate::conversation::SuccessorTrouble,
    ) {
        self.troubles.lock().push(trouble);
    }
}

struct FakeApprovals {
    pending: Mutex<Vec<DeliveredApproval>>,
    probe_once: Mutex<Vec<DeliveredApproval>>,
    decisions: Mutex<Vec<(String, OwnerDecision)>>,
    followed: Mutex<Vec<(String, String)>>,
    /// The approval store cannot be read.
    status_unavailable: AtomicBool,
    /// One status read pauses after observing the row, while its caller
    /// still owns the conversation lock. Two rendezvous release it.
    status_barrier: Mutex<Option<Arc<tokio::sync::Barrier>>>,
}

impl FakeApprovals {
    fn empty() -> Self {
        Self {
            pending: Mutex::new(Vec::new()),
            probe_once: Mutex::new(Vec::new()),
            decisions: Mutex::new(Vec::new()),
            followed: Mutex::new(Vec::new()),
            status_unavailable: AtomicBool::new(false),
            status_barrier: Mutex::new(None),
        }
    }

    fn request_labeled(
        &self,
        approval_id: &str,
        session: LiveSessionId,
        capability: &str,
        label: &str,
        detail: &str,
    ) {
        let approval = DeliveredApproval {
            approval_id: ApprovalId::new(approval_id).expect("approval id"),
            revision: 3,
            capability_id: CapabilityId::new(capability).expect("capability id"),
            session: format!("run:live:{session}"),
            label: label.to_owned(),
            detail: Some(detail.to_owned()),
        };
        self.pending.lock().push(approval.clone());
        self.probe_once.lock().push(approval);
    }

    fn request(&self, approval_id: &str, session: LiveSessionId) {
        let approval = DeliveredApproval {
            approval_id: ApprovalId::new(approval_id).expect("approval id"),
            revision: 3,
            capability_id: CapabilityId::new("email.send").expect("capability id"),
            session: format!("run:live:{session}"),
            label: "send an email".to_owned(),
            detail: Some("\u{201c}approval test\u{201d} to colin@example.com".to_owned()),
        };
        self.pending.lock().push(approval.clone());
        self.probe_once.lock().push(approval);
    }

    fn decide_count(&self) -> usize {
        self.decisions.lock().len()
    }
}

#[async_trait]
impl KernelApprovals for FakeApprovals {
    async fn delivered_pending(
        &self,
        _channel_id: &str,
        _owner_user_id: &str,
        _now: OffsetDateTime,
    ) -> Result<Vec<DeliveredApproval>, DecisionRefusal> {
        Ok(self.pending.lock().clone())
    }

    async fn deliver_session_questions(
        &self,
        _session: &LiveSessionId,
        _channel_id: &str,
        _owner_user_id: &str,
        _now: OffsetDateTime,
    ) -> Result<Vec<DeliveredApproval>, String> {
        Ok(std::mem::take(&mut *self.probe_once.lock()))
    }

    async fn decide_delivered(
        &self,
        _message: &AuthenticatedOwnerMessage,
        approval: &DeliveredApproval,
        decision: OwnerDecision,
        _now: OffsetDateTime,
    ) -> Result<Option<KernelDecisionOutcome>, DecisionRefusal> {
        self.decisions
            .lock()
            .push((approval.approval_id.to_string(), decision));
        self.pending
            .lock()
            .retain(|pending| pending.approval_id != approval.approval_id);
        // A decided ledger row cannot be delivered again as a pending question.
        self.probe_once
            .lock()
            .retain(|pending| pending.approval_id != approval.approval_id);
        Ok(Some(match decision {
            OwnerDecision::AllowOnce => KernelDecisionOutcome::Approved,
            OwnerDecision::Deny => KernelDecisionOutcome::Denied,
        }))
    }

    async fn follow_vehicle(
        &self,
        predecessor: &LiveSessionId,
        successor: &LiveSessionId,
    ) -> Result<usize, String> {
        self.followed
            .lock()
            .push((predecessor.to_string(), successor.to_string()));
        Ok(0)
    }

    async fn approval_status(
        &self,
        approval_id: &str,
    ) -> Result<Option<odin_domain::ApprovalStatus>, String> {
        if self.status_unavailable.load(Ordering::SeqCst) {
            return Err("the approval store is unavailable".to_owned());
        }
        let decided = self
            .decisions
            .lock()
            .iter()
            .rev()
            .find(|(id, _)| id == approval_id)
            .map(|(_, decision)| match decision {
                OwnerDecision::AllowOnce => odin_domain::ApprovalStatus::Approved,
                OwnerDecision::Deny => odin_domain::ApprovalStatus::Denied,
            });
        let status = decided.or_else(|| {
            self.pending
                .lock()
                .iter()
                .any(|pending| pending.approval_id.as_str() == approval_id)
                .then_some(odin_domain::ApprovalStatus::Requested)
        });
        let barrier = self.status_barrier.lock().take();
        if let Some(barrier) = barrier {
            barrier.wait().await;
            barrier.wait().await;
        }
        Ok(status)
    }
}

async fn harness() -> (
    TempDir,
    Arc<FakePlane>,
    Arc<FakeEgress>,
    Arc<FakeApprovals>,
    Arc<ConversationRoot>,
) {
    let dir = tempdir().expect("tempdir");
    let plane = Arc::new(FakePlane::new(dir.path()).await);
    let egress = Arc::new(FakeEgress::new());
    let approvals = Arc::new(FakeApprovals::empty());
    let root = root_in(
        dir.path(),
        Arc::clone(&plane) as Arc<dyn ConversationPlane>,
        egress.clone(),
        approvals.clone(),
    );
    (dir, plane, egress, approvals, root)
}

fn root_in(
    dir: &std::path::Path,
    plane: Arc<dyn ConversationPlane>,
    egress: Arc<dyn ConversationEgress>,
    approvals: Arc<dyn KernelApprovals>,
) -> Arc<ConversationRoot> {
    root_in_generations(dir, plane, egress, approvals, 1, 1)
}

fn root_in_generations(
    dir: &std::path::Path,
    plane: Arc<dyn ConversationPlane>,
    egress: Arc<dyn ConversationEgress>,
    approvals: Arc<dyn KernelApprovals>,
    bound: u64,
    current: u64,
) -> Arc<ConversationRoot> {
    root_in_authority(
        dir,
        plane,
        egress,
        approvals,
        Arc::new(FakeAuthority {
            calls: Mutex::new(Vec::new()),
            bound,
            current,
            script: Mutex::new(BTreeMap::new()),
            deferred: std::sync::atomic::AtomicBool::new(false),
            troubles: Mutex::new(Vec::new()),
        }),
    )
}

/// Composes a root over a caller-owned authority, so a scenario can
/// script per-command generations and mutate them between phases.
fn root_in_authority(
    dir: &std::path::Path,
    plane: Arc<dyn ConversationPlane>,
    egress: Arc<dyn ConversationEgress>,
    approvals: Arc<dyn KernelApprovals>,
    authority: Arc<FakeAuthority>,
) -> Arc<ConversationRoot> {
    root_with_rollover(dir, plane, egress, approvals, authority, Default::default())
}

/// [`root_in_authority`] under an explicitly declared seat rollover policy.
fn root_with_rollover(
    dir: &std::path::Path,
    plane: Arc<dyn ConversationPlane>,
    egress: Arc<dyn ConversationEgress>,
    approvals: Arc<dyn KernelApprovals>,
    authority: Arc<FakeAuthority>,
    rollover: odin_omp::live::rollover::RolloverPolicy,
) -> Arc<ConversationRoot> {
    root_with_links(dir, plane, egress, approvals, authority, rollover, None)
}

/// [`root_with_rollover`] over the daemon's delegation links.
fn root_with_links(
    dir: &std::path::Path,
    plane: Arc<dyn ConversationPlane>,
    egress: Arc<dyn ConversationEgress>,
    approvals: Arc<dyn KernelApprovals>,
    authority: Arc<FakeAuthority>,
    rollover: odin_omp::live::rollover::RolloverPolicy,
    delegation_links: Option<odin_omp::host_tools::delegation::DelegationLinkLedger>,
) -> Arc<ConversationRoot> {
    let binding = LiveSeatBinding {
        seat_id: SeatId::new(SEAT).expect("seat id"),
        slice_id: SliceId::new("slice-main").expect("slice id"),
        display_name: "Test seat".to_owned(),
        launch_options: vec![LiveLaunchOption {
            provider: ProviderName::new("prov").expect("provider"),
            model: ModelName::new("model").expect("model"),
            skeleton_ref: "skeleton".to_owned(),
            container_id: ContainerId::new("container").expect("container id"),
            harness: None,
        }],
        allowed_nodes: vec![NodeId::new("node-a").expect("node id")],
        max_sessions: 1,
        turn_budget: None,
    };
    ConversationRoot::open(ConversationRootConfig {
        binding,
        project: ProjectId::new(PROJECT).expect("project id"),
        lane: LaneId::new(SESSION_LANE).expect("lane id"),
        provider: ProviderName::new("prov").expect("provider"),
        model: ModelName::new("model").expect("model"),
        target_node: NodeId::new("node-a").expect("node id"),
        owner: OwnerSurface {
            owner_user_id: OWNER.to_owned(),
            channel_id: CHANNEL.to_owned(),
            actor: format!("discord-owner:{OWNER}"),
        },
        answer_bound: ANSWER_BOUND,
        poll_interval: StdDuration::from_millis(50),
        plane,
        authority,
        egress,
        approvals,
        ledger_path: state_ledger_path(dir),
        state_path: dir.join("conversations/gateway/root.json"),
        rollover,
        clock: None,
        delegation_links,
    })
    .expect("root composes")
}

fn intent(key: &str) -> ApprovedIntentExecution {
    ApprovedIntentExecution {
        command_id: format!("cmd-{key}"),
        idempotency_key: key.to_owned(),
        content: format!("intent {key}"),
        unprompted: false,
    }
}

fn owner_message(content: &str) -> AuthenticatedOwnerMessage {
    AuthenticatedOwnerMessage {
        owner_user_id: OWNER.to_owned(),
        channel_id: CHANNEL.to_owned(),
        message_id: (10_000_u64 << 22).to_string(),
        seat: SeatId::new(SEAT).expect("seat id"),
        project: ProjectId::new(PROJECT).expect("project id"),
        content: content.to_owned(),
    }
}

/// A turn that outlives the answer bound is never lost: Colin gets one
/// holding line, can keep talking, and the real answer arrives when the
/// turn settles.
#[tokio::test(start_paused = true)]
async fn a_turn_past_the_answer_bound_is_delivered_late_not_lost() {
    use crate::runtime::ApprovedIntentRoute as _;
    let (dir, plane, egress, approvals, root) = harness().await;
    root.initialize().await.expect("initialize");
    plane.hold_running.store(true, Ordering::SeqCst);
    let projection = root.execute(intent("slow")).await.expect("handed off");
    assert_eq!(projection["lateAnswer"], true);
    assert_eq!(
        egress.sends(),
        vec![super::prompt::LATE_ANSWER_HOLDING.to_owned()]
    );
    plane.hold_running.store(false, Ordering::SeqCst);
    let session = root
        .current_vehicle_session()
        .await
        .expect("vehicle")
        .expect("vehicle");
    plane
        .finish_turn(&session, "Your ChE63a notes cover the Rankine cycle.")
        .await;
    for _ in 0..600 {
        if egress.sends().len() == 2 {
            break;
        }
        tokio::time::sleep(StdDuration::from_millis(100)).await;
    }
    assert_eq!(
        egress.sends(),
        [
            super::prompt::LATE_ANSWER_HOLDING.to_owned(),
            "[edit 4198498304] Your ChE63a notes cover the Rankine cycle.".to_owned()
        ]
    );
    root.join_background(StdDuration::from_secs(600)).await;
    let before = egress.sends();
    let reopened = root_in(dir.path(), plane.clone(), egress.clone(), approvals.clone());
    let replay = reopened
        .execute(intent("slow"))
        .await
        .expect("late original-key receipt");
    assert_eq!(replay["replySent"], true);
    assert_eq!(egress.sends(), before);
    let _ = (dir, approvals);
}

#[tokio::test(start_paused = true)]
async fn each_recent_turn_keeps_its_own_answer() {
    use crate::runtime::ApprovedIntentRoute as _;
    let (dir, plane, _egress, approvals, root) = harness().await;
    root.initialize().await.expect("initialize");
    for turn in 0..=RECENT_ANSWERS {
        *plane.answer.lock() = format!("Answer {turn}.");
        root.execute(intent(&format!("turn-{turn}")))
            .await
            .expect("settled");
    }
    let record = root.load_record().expect("record");
    let answer = |key: &str| {
        record
            .recent_answers
            .iter()
            .find(|recent| recent.idempotency_key == key)
            .map(|recent| recent.answer.clone())
    };
    assert_eq!(answer("turn-1").as_deref(), Some("Answer 1."));
    assert_eq!(
        answer(&format!("turn-{RECENT_ANSWERS}")).as_deref(),
        Some(format!("Answer {RECENT_ANSWERS}.").as_str())
    );
    assert_eq!(answer("turn-0"), None);
    assert_eq!(record.recent_answers.len(), RECENT_ANSWERS);
    let _ = (dir, approvals);
}

#[tokio::test(start_paused = true)]
async fn a_recovered_turn_past_the_answer_bound_is_delivered_late() {
    use crate::runtime::ApprovedIntentRoute as _;
    let (dir, plane, egress, approvals, root) = harness().await;
    root.initialize().await.expect("initialize");
    plane.hold_running.store(true, Ordering::SeqCst);
    let session = root
        .current_vehicle_session()
        .await
        .expect("vehicle")
        .expect("vehicle");
    let turn = tokio::spawn({
        let root = Arc::clone(&root);
        async move { root.execute(intent("slow")).await }
    });
    tokio::time::sleep(StdDuration::from_secs(1)).await;
    plane
        .push_state_change(&session, LiveSessionState::Failed)
        .await;
    for _ in 0..100 {
        if !plane.recoveries.lock().is_empty() {
            break;
        }
        tokio::time::sleep(StdDuration::from_millis(50)).await;
    }
    assert!(!plane.recoveries.lock().is_empty(), "recovered in place");
    plane
        .push_state_change(&session, LiveSessionState::Running)
        .await;
    let projection = turn
        .await
        .expect("join")
        .expect("handed off, not a timeout");
    assert_eq!(projection["lateAnswer"], true);
    plane.finish_turn(&session, "Recovered answer.").await;
    sends_reach(&egress, 2).await;
    assert_eq!(
        egress.sends(),
        vec![
            super::prompt::LATE_ANSWER_HOLDING.to_owned(),
            "[edit 4198498304] Recovered answer.".to_owned()
        ]
    );
    let _ = (dir, approvals);
}

/// A handed-off turn whose session dies never leaves Colin with only the
/// holding line.
#[tokio::test(start_paused = true)]
async fn a_late_turn_whose_session_dies_says_so() {
    use crate::runtime::ApprovedIntentRoute as _;
    let (dir, plane, egress, approvals, root) = harness().await;
    root.initialize().await.expect("initialize");
    plane.hold_running.store(true, Ordering::SeqCst);
    let projection = root.execute(intent("slow")).await.expect("handed off");
    assert_eq!(projection["lateAnswer"], true);
    let session = root
        .current_vehicle_session()
        .await
        .expect("vehicle")
        .expect("vehicle");
    plane
        .push_state_change(&session, LiveSessionState::Failed)
        .await;
    sends_reach(&egress, 2).await;
    assert_eq!(
        egress.sends(),
        [
            super::prompt::LATE_ANSWER_HOLDING.to_owned(),
            format!("[edit 4198498304] {}", super::prompt::LATE_ANSWER_LOST)
        ]
    );
    let _ = (dir, approvals);
}

#[tokio::test(start_paused = true)]
async fn a_refused_prompt_fails_the_turn_at_once() {
    use crate::runtime::ApprovedIntentRoute as _;
    let (dir, plane, _egress, approvals, root) = harness().await;
    root.initialize().await.expect("initialize");
    plane.fail_prompts.store(1, Ordering::SeqCst);
    let started = tokio::time::Instant::now();
    let failure = root.execute(intent("refused")).await.expect_err("refused");
    assert!(
        matches!(&failure, IntentFailure::TurnRefused { reason } if reason.contains("brain_turn_compile")),
        "{failure:?}"
    );
    assert!(
        started.elapsed() < ANSWER_BOUND,
        "it failed at once, not at the bound"
    );
    let _ = (dir, approvals);
}

/// Provider failures reach the owner without raw provider response text.
#[tokio::test(start_paused = true)]
async fn a_provider_refusal_is_one_plain_sentence_at_once() {
    use crate::runtime::ApprovedIntentRoute as _;
    let (dir, plane, _egress, approvals, root) = harness().await;
    root.initialize().await.expect("initialize");
    plane.refuse_provider.store(1, Ordering::SeqCst);
    let started = tokio::time::Instant::now();
    let failure = root.execute(intent("quota")).await.expect_err("refused");
    assert!(
        matches!(&failure, IntentFailure::ModelUnavailable { reason } if reason.contains("quota")),
        "{failure:?}"
    );
    assert!(
        started.elapsed() < ANSWER_BOUND,
        "at once, not at the bound"
    );
    let sentence = crate::natural::natural_intent_failure(&failure);
    assert!(
        !sentence.contains("insufficient_quota"),
        "no raw provider body"
    );
    let _ = (dir, approvals);
}

const PARTIAL_TEXT: &str = "Partial answer from a failed request.";

fn failed_assistant(text: &str) -> serde_json::Value {
    serde_json::json!({
        "role": "assistant",
        "stopReason": "error",
        "errorStatus": 500,
        "errorMessage": "upstream API connection failed",
        "content": [{"type": "text", "text": text}],
    })
}

fn bounded_user_turn() -> serde_json::Value {
    serde_json::json!({
        "role": "user",
        "content": [{"type": "text", "text": "Perform one bounded task."}],
    })
}

/// Partial text followed by failed-round and terminal frames carrying the provider error.
fn failed_provider_turn_frames() -> Vec<serde_json::Value> {
    vec![
        serde_json::json!({"type": "agent_start"}),
        serde_json::json!({"type": "message_end", "message": failed_assistant(PARTIAL_TEXT)}),
        serde_json::json!({"type": "turn_end", "message": failed_assistant(PARTIAL_TEXT)}),
        serde_json::json!({
            "type": "agent_end",
            "isTerminal": true,
            "yielded": true,
            "messages": [bounded_user_turn(), failed_assistant(PARTIAL_TEXT)],
        }),
    ]
}

/// The nested failure shape: the terminal agent_end alone names the failure.
fn nested_failed_provider_turn_frames() -> Vec<serde_json::Value> {
    let mut frames = failed_provider_turn_frames();
    frames.retain(|frame| frame["type"] != "turn_end");
    frames
}

/// A failed round that the loop retries in place and answers.
fn retried_provider_turn_frames() -> Vec<serde_json::Value> {
    let answered = serde_json::json!({
        "role": "assistant",
        "stopReason": "stop",
        "content": [{"type": "text", "text": "Retried answer."}],
    });
    vec![
        serde_json::json!({"type": "agent_start"}),
        serde_json::json!({"type": "message_end", "message": failed_assistant(PARTIAL_TEXT)}),
        serde_json::json!({"type": "turn_end", "message": failed_assistant(PARTIAL_TEXT)}),
        serde_json::json!({"type": "message_end", "message": answered}),
        serde_json::json!({"type": "turn_end", "message": answered}),
        serde_json::json!({
            "type": "agent_end",
            "isTerminal": true,
            "messages": [bounded_user_turn(), answered],
        }),
    ]
}

async fn direct_provider_failure_is_model_unavailable(frames: Vec<serde_json::Value>, key: &str) {
    use crate::runtime::ApprovedIntentRoute as _;
    let (dir, plane, egress, approvals, root) = harness().await;
    root.initialize().await.expect("initialize");
    let vehicle = root.load_record().expect("record").session_id;
    let prompts = plane.prompt_count("");
    plane.normalized_turns.lock().push_back(frames);
    let started = tokio::time::Instant::now();
    let failure = root
        .execute(intent(key))
        .await
        .expect_err("provider failed");
    assert!(
        matches!(&failure, IntentFailure::ModelUnavailable { .. }),
        "{failure:?}"
    );
    assert!(
        started.elapsed() < ANSWER_BOUND,
        "at once, not at the bound"
    );
    assert!(
        plane.recoveries.lock().is_empty(),
        "a terminal provider error is not a lost vehicle"
    );
    assert_eq!(plane.prompt_count(""), prompts + 1, "no extra model prompt");
    assert!(
        egress.sends().is_empty(),
        "the failed turn's partial text is never a reply: {:?}",
        egress.sends()
    );
    assert_eq!(root.load_record().expect("record").session_id, vehicle);
    let _ = (dir, approvals);
}

#[tokio::test(start_paused = true)]
async fn a_normalized_provider_failure_after_partial_text_is_model_unavailable() {
    direct_provider_failure_is_model_unavailable(
        failed_provider_turn_frames(),
        "normalized-failed",
    )
    .await;
}

/// The nested failure (terminal agent_end without a preceding failed
/// turn_end) is the same typed provider failure.
#[tokio::test(start_paused = true)]
async fn a_nested_normalized_provider_failure_is_model_unavailable() {
    direct_provider_failure_is_model_unavailable(
        nested_failed_provider_turn_frames(),
        "normalized-nested",
    )
    .await;
}

/// A failed round that the loop retries in place and answers stays the
/// turn's answer; the failed round's partial text never is.
#[tokio::test(start_paused = true)]
async fn a_normalized_retried_provider_round_that_answers_is_the_answer() {
    use crate::runtime::ApprovedIntentRoute as _;
    let (dir, plane, egress, approvals, root) = harness().await;
    root.initialize().await.expect("initialize");
    plane
        .normalized_turns
        .lock()
        .push_back(retried_provider_turn_frames());
    let projection = root
        .execute(intent("normalized-retried"))
        .await
        .expect("answers");
    assert_eq!(projection["answer"], "Retried answer.");
    assert_eq!(egress.sends(), vec!["Retried answer.".to_owned()]);
    assert!(plane.recoveries.lock().is_empty());
    let _ = (dir, approvals);
}

/// A terminal provider error invalidates the partial answer of the same
/// turn for every reader of the journal, including one that reads after the
/// session later settles Idle.
#[tokio::test(start_paused = true)]
async fn a_failed_turns_partial_text_never_settles_as_an_answer() {
    use crate::runtime::ApprovedIntentRoute as _;
    let (dir, plane, _egress, approvals, root) = harness().await;
    root.initialize().await.expect("initialize");
    plane
        .normalized_turns
        .lock()
        .push_back(failed_provider_turn_frames());
    root.execute(intent("normalized-observed"))
        .await
        .expect_err("provider failed");
    let session = root
        .current_vehicle_session()
        .await
        .expect("vehicle")
        .expect("vehicle");
    plane
        .push_state_change(&session, LiveSessionState::Idle)
        .await;
    let observed = root
        .observe_since(session, EventSeq::new(0), None)
        .await
        .expect("observed");
    assert_eq!(observed, None, "the partial text is not an answer");
    let _ = (dir, approvals);
}

#[tokio::test(start_paused = true)]
async fn a_follow_up_is_answered_by_its_own_turn_not_the_one_before() {
    use crate::runtime::ApprovedIntentRoute as _;
    let (dir, plane, egress, approvals, root) = harness().await;
    root.initialize().await.expect("initialize");
    plane.previous_turn_trails.store(true, Ordering::SeqCst);
    let projection = root.execute(intent("routine")).await.expect("answers");
    assert_eq!(projection["answer"], "A plain answer.");
    assert_eq!(egress.sends(), vec!["A plain answer.".to_owned()]);
    let _ = (dir, approvals);
}

#[tokio::test(start_paused = true)]
async fn a_silent_turn_is_reprompted_once_and_answers_at_once() {
    use crate::runtime::ApprovedIntentRoute as _;
    let (dir, plane, egress, approvals, root) = harness().await;
    root.initialize().await.expect("initialize");
    let vehicle = root.load_record().expect("record").session_id;
    plane.silent_turns.store(1, Ordering::SeqCst);
    let started = tokio::time::Instant::now();
    let projection = root.execute(intent("silent")).await.expect("answers");
    assert!(
        started.elapsed() < ANSWER_BOUND,
        "at once, not at the bound"
    );
    assert_eq!(projection["answer"], "A plain answer.");
    assert_eq!(egress.sends(), vec!["A plain answer.".to_owned()]);
    assert_eq!(
        root.load_record().expect("record").session_id,
        vehicle,
        "the same session answered"
    );
    let commands = plane.commands.lock().clone();
    let reprompts = commands
        .iter()
        .filter(|(id, _)| id.starts_with("command:silent:"))
        .count();
    assert_eq!(reprompts, 1, "exactly one reprompt: {commands:?}");
    assert!(root.load_record().expect("record").in_flight.is_none());
    let _ = (dir, approvals);
}

/// A reprompt that is silent too fails as one typed outcome at once.
#[tokio::test(start_paused = true)]
async fn a_twice_silent_turn_fails_honestly_at_once() {
    use crate::runtime::ApprovedIntentRoute as _;
    let (dir, plane, egress, approvals, root) = harness().await;
    root.initialize().await.expect("initialize");
    plane.silent_turns.store(2, Ordering::SeqCst);
    let started = tokio::time::Instant::now();
    let failure = root.execute(intent("mute")).await.expect_err("silent");
    assert_eq!(failure, IntentFailure::SilentTurn);
    assert!(
        started.elapsed() < ANSWER_BOUND,
        "at once, not at the bound"
    );
    assert!(egress.sends().is_empty(), "no invented reply");
    assert!(root.load_record().expect("record").in_flight.is_none());
    let _ = (dir, approvals);
}

#[tokio::test(start_paused = true)]
async fn an_over_window_envelope_refusal_rolls_and_answers() {
    use crate::runtime::ApprovedIntentRoute as _;
    let (dir, plane, _egress, approvals, root) = harness().await;
    root.initialize().await.expect("initialize");
    let vehicle = root.load_record().expect("record").session_id;
    plane.refuse_envelope.store(1, Ordering::SeqCst);
    let started = tokio::time::Instant::now();
    let projection = root.execute(intent("envelope")).await.expect("answers");
    assert!(
        started.elapsed() < ANSWER_BOUND,
        "at once, not at the bound"
    );
    assert_eq!(projection["answer"], "A plain answer.");
    assert_ne!(
        root.load_record().expect("record").session_id,
        vehicle,
        "the conversation rolled"
    );
    let _ = (dir, approvals);
}

async fn sends_reach(egress: &FakeEgress, count: usize) {
    for _ in 0..600 {
        if egress.sends().len() >= count {
            return;
        }
        tokio::time::sleep(StdDuration::from_millis(100)).await;
    }
}

#[tokio::test(start_paused = true)]
async fn an_unprompted_wake_never_folds_into_a_running_turn() {
    use crate::runtime::ApprovedIntentRoute as _;
    let (dir, plane, egress, approvals, root) = harness().await;
    root.initialize().await.expect("initialize");
    plane.hold_running.store(true, Ordering::SeqCst);
    root.execute(intent("slow")).await.expect("handed off");
    let mut wake = intent("wake");
    wake.unprompted = true;
    assert_eq!(
        root.execute(wake.clone()).await.expect_err("busy"),
        IntentFailure::ConversationBusy
    );
    plane.hold_running.store(false, Ordering::SeqCst);
    let session = root.current_vehicle_session().await.unwrap().unwrap();
    plane.finish_turn(&session, "The GPU test passed.").await;
    sends_reach(&egress, 2).await;
    root.execute(wake)
        .await
        .expect("the wake runs as its own turn");
    let sends = egress.sends();
    assert_eq!(sends[1], "[edit 4198498304] The GPU test passed.");
    assert_eq!(sends.len(), 3, "{sends:?}");
    assert_eq!(sends[2], "A plain answer.");
    let _ = (dir, approvals);
}

#[tokio::test(start_paused = true)]
async fn an_answered_owner_turn_is_reviewed_and_a_wake_is_not() {
    use crate::runtime::ApprovedIntentRoute as _;
    let (dir, plane, egress, approvals, root) = harness().await;
    root.initialize().await.expect("initialize");
    *plane.answer.lock() = "Noted: black coffee.".to_owned();
    root.execute(intent("owner")).await.expect("settled");
    let mut wake = intent("wake");
    wake.unprompted = true;
    root.execute(wake).await.expect("settled");
    let reviews = egress.reviews.lock().clone();
    assert_eq!(reviews.len(), 1, "{reviews:?}");
    assert_eq!(reviews[0].trigger, "turn");
    assert_eq!(reviews[0].answered, "Noted: black coffee.");
    assert_eq!(reviews[0].asked, intent("owner").content);
    let _ = (dir, plane, approvals);
}

/// A late answer is the NEXT settled answer after its cursor: a second
/// turn that settles before the observer reads never stands in for it.
#[tokio::test(start_paused = true)]
async fn a_late_answer_is_the_first_settled_answer_not_the_last() {
    use crate::runtime::ApprovedIntentRoute as _;
    let (dir, plane, egress, approvals, root) = harness().await;
    root.initialize().await.expect("initialize");
    plane.hold_running.store(true, Ordering::SeqCst);
    root.execute(intent("slow")).await.expect("handed off");
    plane.hold_running.store(false, Ordering::SeqCst);
    let session = root.current_vehicle_session().await.unwrap().unwrap();
    plane.finish_turn(&session, "First answer.").await;
    plane
        .push_state_change(&session, LiveSessionState::Running)
        .await;
    plane.finish_turn(&session, "Second answer.").await;
    sends_reach(&egress, 2).await;
    assert_eq!(
        egress.sends(),
        [
            super::prompt::LATE_ANSWER_HOLDING.to_owned(),
            "[edit 4198498304] First answer.".to_owned()
        ]
    );
    let _ = (dir, approvals);
}

#[tokio::test(start_paused = true)]
async fn a_quiet_unprompted_turn_sends_nothing() {
    use crate::runtime::ApprovedIntentRoute as _;
    let (dir, plane, egress, approvals, root) = harness().await;
    root.initialize().await.expect("initialize");
    *plane.answer.lock() = super::prompt::QUIET_REPLY.to_owned();
    let mut wake = intent("report");
    wake.unprompted = true;
    let projection = root.execute(wake).await.expect("settles");
    assert_eq!(projection["quiet"], true);
    assert!(egress.sends().is_empty(), "{:?}", egress.sends());
    let reopened = root_in(dir.path(), plane.clone(), egress.clone(), approvals.clone());
    let mut retry = intent("report");
    retry.unprompted = true;
    assert_eq!(
        reopened.execute(retry).await.expect("quiet wake receipt"),
        projection
    );
    assert!(egress.sends().is_empty());
    // Owner turns that remain quiet after reprompt fail without exposing the control token.
    let owner = root.execute(intent("owner")).await.expect_err("unanswered");
    assert_eq!(owner, IntentFailure::SilentTurn);
    assert!(
        egress.sends().iter().all(|sent| !sent.contains("[quiet]")),
        "{:?}",
        egress.sends()
    );
    let _ = (dir, approvals);
}

#[tokio::test(start_paused = true)]
async fn a_quiet_owner_turn_is_reprompted_and_answers() {
    use crate::runtime::ApprovedIntentRoute as _;
    let (dir, plane, egress, approvals, root) = harness().await;
    root.initialize().await.expect("initialize");
    let vehicle = root.load_record().expect("record").session_id;
    plane.quiet_turns.store(1, Ordering::SeqCst);
    let started = tokio::time::Instant::now();
    let projection = root.execute(intent("chain")).await.expect("answers");
    assert!(
        started.elapsed() < ANSWER_BOUND,
        "at once, not at the bound"
    );
    assert_eq!(projection["answer"], "A plain answer.");
    assert_eq!(egress.sends(), vec!["A plain answer.".to_owned()]);
    assert_eq!(
        root.load_record().expect("record").session_id,
        vehicle,
        "the same session answered"
    );
    let commands = plane.commands.lock().clone();
    let reprompts: Vec<_> = commands
        .iter()
        .filter(|(id, _)| id.starts_with("command:silent:"))
        .collect();
    assert_eq!(reprompts.len(), 1, "exactly one reprompt: {commands:?}");
    assert!(root.load_record().expect("record").in_flight.is_none());
    let _ = (dir, approvals);
}

#[test]
fn the_quiet_token_is_stripped_and_never_spoken() {
    use super::prompt::without_quiet_token;
    assert_eq!(without_quiet_token("[quiet]"), "");
    assert_eq!(without_quiet_token("  [quiet]\n"), "");
    assert_eq!(
        without_quiet_token("[quiet] — actually, one thing worth a word: the docs worker stalled."),
        "actually, one thing worth a word: the docs worker stalled."
    );
    assert_eq!(without_quiet_token("All done. [quiet]"), "All done.");
    assert_eq!(without_quiet_token("Branch is up."), "Branch is up.");
}

#[tokio::test(start_paused = true)]
async fn an_owner_reply_streams_into_the_one_message_that_becomes_the_answer() {
    use crate::runtime::ApprovedIntentRoute as _;
    let (dir, plane, egress, approvals, root) = harness().await;
    root.initialize().await.expect("initialize");
    plane.hold_running.store(true, Ordering::SeqCst);
    let delta = |text: &str| {
        LiveEventBody::AssistantDelta(odin_domain::huginn::TextDelta {
            turn_id: odin_domain::TurnId::new("turn-stream").expect("turn id"),
            text: text.to_owned(),
        })
    };
    let seat = async {
        tokio::time::sleep(StdDuration::from_secs(1)).await;
        let session = root.current_vehicle_session().await.unwrap().unwrap();
        plane.push_event(&session, delta("Oolong")).await;
        tokio::time::sleep(StdDuration::from_secs(2)).await;
        plane.push_event(&session, delta(" is a tea")).await;
        tokio::time::sleep(StdDuration::from_secs(2)).await;
        plane.finish_turn(&session, "Oolong is a tea.").await;
    };
    let (settled, ()) = tokio::join!(root.execute(intent("owner")), seat);
    let projection = settled.expect("settled");
    assert_eq!(projection["replySent"], true, "{projection}");
    let sends = egress.sends();
    let posted = ((1_000 + 1_u64) << 22).to_string();
    assert_eq!(
        sends,
        [
            "Oolong".to_owned(),
            format!("[edit {posted}] Oolong is a tea"),
            format!("[edit {posted}] Oolong is a tea."),
        ],
    );
    let _ = (dir, approvals);
}

/// A failed tail must retain the acknowledged prefix across record reloads.
#[tokio::test]
async fn permission_question_partial_delivery_reconciles_or_stops_on_unknown_post() {
    for unknown in [false, true] {
        let (_dir, _plane, egress, _approvals, root) = harness().await;
        root.initialize().await.unwrap();
        let mut record = root.load_record().unwrap();
        record.questions.push(DeliveredQuestion {
            request_id: "partial-question".to_owned(),
            session_id: "session".to_owned(),
            session_epoch: Some(1),
            prompt: "permission detail ".repeat(200),
            expires_at_unix_ms: u64::MAX,
            owner_user_id: root.owner.owner_user_id.clone(),
            channel_id: "chan-1".to_owned(),
            delivered_message_id: None,
            delivery_chunks: Vec::new(),
            delivery_pending: false,
            decision_command_id: None,
            delivery_error: None,
            settled: false,
        });
        let index = record.questions.len() - 1;
        *egress.delivery_failure.lock() = Some((
            1,
            if unknown {
                crate::discord::DiscordSendError::ServiceUnavailable
            } else {
                crate::discord::DiscordSendError::Unreachable
            },
        ));
        let before = egress.sends().len();
        root.relay_question(&mut record, index).unwrap();
        let mut record = root.load_record().unwrap();
        let acknowledged_prefix = ((1_000 + 1_u64) << 22).to_string();
        assert_eq!(egress.sends().len(), before + 1);
        assert!(record.questions[index].delivered_message_id.is_none());
        assert!(record.questions[index].delivery_error.is_some());
        assert!(!root.is_decidable_receipt(&record.questions[index]));
        root.relay_question(&mut record, index).unwrap();
        let record = root.load_record().unwrap();
        let sends = egress.sends();
        if unknown {
            assert_eq!(sends.len(), before + 1, "no blind resend or edit");
            assert!(record.questions[index].delivered_message_id.is_none());
            assert!(record.questions[index].delivery_error.is_some());
        } else {
            assert_eq!(sends.len(), before + 2);
            assert_eq!(sends[before..].concat(), record.questions[index].prompt);
            assert_eq!(
                record.questions[index].delivered_message_id.as_deref(),
                Some(acknowledged_prefix.as_str())
            );
            assert!(record.questions[index].delivery_chunks.is_empty());
            assert!(!record.questions[index].delivery_pending);
            let mut lost_cache = root.load_record().unwrap();
            lost_cache.questions[index].delivered_message_id = None;
            root.store_record(&mut lost_cache).unwrap();
            root.relay_question(&mut lost_cache, index).unwrap();
            assert_eq!(
                lost_cache.questions[index].delivered_message_id.as_deref(),
                Some(acknowledged_prefix.as_str())
            );
            assert_eq!(
                egress.sends(),
                sends,
                "committed ownership repairs the cache without HTTP"
            );
        }
        // A crash after reservation but before recording transport's result
        // is equally unsafe to replay, including before an anchor is known.
        let mut record = root.load_record().unwrap();
        record.questions[index].delivered_message_id = None;
        record.questions[index].delivery_chunks.clear();
        // A distinct legacy question has no new ledger receipt to override
        // its uncertain pre-cutover dispatch.
        record.questions[index].request_id = "legacy-reserved-question".to_owned();
        record.questions[index].delivery_pending = true;
        root.store_record(&mut record).unwrap();
        let mut record = root.load_record().unwrap();
        let before = egress.sends().len();
        root.relay_question(&mut record, index).unwrap();
        assert_eq!(egress.sends().len(), before);
    }
}
