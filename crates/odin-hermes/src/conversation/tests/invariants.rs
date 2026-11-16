//! Conversation identity, replay, delivery causality, wake and terminal-state invariants.

use super::*;
use crate::conversation::identity::{
    bounded_command, conversation_root_identity, successor_vehicle_command,
};
use crate::correlation::identity_from_key;
use crate::ingress::{INTENT_COMMAND_PREFIX, INTENT_ISSUER};
use crate::runtime::{ApprovedIntentRoute as _, OwnerDecisionRoute as _};
use odin_ledger::command::{CommandOutcome, CommandSpec, CommandTerminalStatus, RecordCommand};

/// One intent rides the one vehicle; a replayed idempotency key
/// returns the recorded projection verbatim with no duplicate prompt
/// and no duplicate reply.
#[tokio::test(start_paused = true)]
async fn replay_returns_recorded_projection_without_duplicate_prompt() {
    let (_dir, plane, egress, _approvals, root) = harness().await;
    root.initialize().await.expect("initialize");
    let first = root
        .execute(intent("k1"))
        .await
        .expect("first execution settles");
    assert_eq!(first["answer"], "A plain answer.");
    assert_eq!(first["replySent"], true);
    assert_eq!(plane.prompt_count("command:intent:"), 1);
    assert_eq!(egress.sends().len(), 1);

    let replay = root
        .execute(intent("k1"))
        .await
        .expect("replay settles from the record");
    assert_eq!(replay, first);
    assert_eq!(plane.prompt_count("command:intent:"), 1, "no re-prompt");
    assert_eq!(egress.sends().len(), 1, "no duplicate reply");
}

/// The Hermes runtime the daemon composes over `route`, its schedule under
/// `dir/hermes`.
fn schedule_runtime(
    dir: &std::path::Path,
    route: &Arc<ConversationRoot>,
) -> Arc<crate::runtime::HermesRuntime> {
    let runtime = crate::runtime::HermesRuntime::open(
        crate::config::HermesSettings::new(
            dir.join("hermes"),
            None,
            None,
            vec![],
        )
        .expect("settings"),
        crate::runtime::HermesLedgers {
            conversation: Ledger::open_in_memory().expect("ledger"),
            adapter: Arc::new(Mutex::new(Ledger::open_in_memory().expect("ledger"))),
            purchase: Arc::new(std::sync::Mutex::new(
                Ledger::open_in_memory().expect("ledger"),
            )),
        },
        &BTreeMap::new(),
        None,
        8_192,
        BTreeMap::new(),
        None,
    )
    .expect("runtime");
    let route: Arc<dyn crate::runtime::ApprovedIntentRoute> = route.clone();
    runtime.set_approved_intent_route(route);
    runtime
}

/// One reconcile pass, off the async workers as the daemon's loop runs it.
async fn schedule_pass(runtime: &Arc<crate::runtime::HermesRuntime>) -> usize {
    let runtime = Arc::clone(runtime);
    tokio::task::spawn_blocking(move || runtime.reconcile_schedule())
        .await
        .expect("pass joins")
        .expect("schedule pass")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn each_recurring_wake_occurrence_runs_its_own_turn_and_a_retry_reuses_it() {
    let (dir, plane, egress, approvals, root) = harness().await;
    root.initialize().await.expect("initialize");
    // Ten minutes overdue, every minute, once more after this: two
    // occurrences, as `reminder_set` with a repeat stores them.
    let state = dir.path().join("hermes");
    std::fs::create_dir_all(&state).expect("state dir");
    let now = jiff::Timestamp::now().as_millisecond();
    drop(crate::schedule::ScheduleStore::open(&state).expect("schedule store"));
    rusqlite::Connection::open(state.join("schedule.sqlite3"))
        .expect("schedule db")
        .execute(
            "INSERT INTO schedule_items (id, kind, text, fire_at_ms, created_at_ms, status, every_minutes, repeats_left) VALUES ('rcycle', 'wake', 'check the pod', ?1, ?2, 'pending', 1, 1)",
            rusqlite::params![now - 10 * 60_000, now - 20 * 60_000],
        )
        .expect("seed");
    let schedule = state.join("schedule.sqlite3");
    let sql = |statement: &str| {
        rusqlite::Connection::open(&schedule)
            .expect("schedule db")
            .execute(statement, [])
            .expect("schedule fixture");
    };
    let status = || -> String {
        rusqlite::Connection::open(&schedule)
            .expect("schedule db")
            .query_row(
                "SELECT status FROM schedule_items WHERE id = 'rcycle'",
                [],
                |row| row.get(0),
            )
            .expect("row")
    };
    let runtime = schedule_runtime(dir.path(), &root);

    *plane.answer.lock() = "First occurrence: pod healthy.".to_owned();
    assert_eq!(schedule_pass(&runtime).await, 1);
    assert_eq!(plane.prompt_count("command:intent:"), 1);
    assert_eq!(egress.sends(), ["First occurrence: pod healthy."]);
    assert_eq!(status(), "pending", "re-armed for the next occurrence");
    // Nothing due: a pass prompts no model.
    assert_eq!(schedule_pass(&runtime).await, 0);
    assert_eq!(plane.prompt_count("command:intent:"), 1, "idle pass");

    // The next occurrence comes due: two cadence steps back stays on the
    // row's grid and is later than the first occurrence.
    sql("UPDATE schedule_items SET fire_at_ms = fire_at_ms - 120000 WHERE id = 'rcycle'");
    *plane.answer.lock() = "Second occurrence: pod restarted.".to_owned();
    assert_eq!(schedule_pass(&runtime).await, 1);
    assert_eq!(
        plane.prompt_count("command:intent:"),
        2,
        "the second occurrence runs its own turn, not the first one's replay"
    );
    assert_eq!(
        egress.sends(),
        [
            "First occurrence: pod healthy.",
            "Second occurrence: pod restarted."
        ]
    );
    assert_eq!(status(), "fired", "count spent");

    // A stop after the turn settled but before the row did: the store
    // still holds the second occurrence leased, and a fresh daemon re-fires
    // it. Its recorded result is reused; the model is never asked again.
    sql("UPDATE schedule_items SET status = 'firing' WHERE id = 'rcycle'");
    drop(runtime);
    drop(root);
    let reopened = root_in(dir.path(), plane.clone(), egress.clone(), approvals.clone());
    let runtime = schedule_runtime(dir.path(), &reopened);
    *plane.answer.lock() = "Never asked.".to_owned();
    assert_eq!(schedule_pass(&runtime).await, 1);
    assert_eq!(
        plane.prompt_count("command:intent:"),
        2,
        "the same occurrence never prompts again"
    );
    assert_eq!(
        egress.sends(),
        [
            "First occurrence: pod healthy.",
            "Second occurrence: pod restarted."
        ],
        "its reply is not sent again"
    );
    assert_eq!(status(), "fired");
    assert_eq!(schedule_pass(&runtime).await, 0);
}

/// After a restart the recorded vehicle that retired as failed
/// recovers IN PLACE through the real reclaim (same session id, epoch
/// bump, no second open), and the next intent rides it.
#[tokio::test(start_paused = true)]
async fn restart_recovers_the_failed_vehicle_in_place() {
    let dir = scratch_dir();
    let vehicle_command = {
        let plane = Arc::new(FakePlane::new(dir.path()).await);
        let root = root_in(
            dir.path(),
            Arc::clone(&plane) as Arc<dyn ConversationPlane>,
            Arc::new(FakeEgress::new()),
            Arc::new(FakeApprovals::empty()),
        );
        root.initialize().await.expect("initialize");
        root.vehicle_command_id().expect("vehicle command")
    };
    // The fresh daemon discovers the session FAILED (child exited).
    let plane_b = Arc::new(FakePlane::new(dir.path()).await);
    let session = plane_b
        .seed(&vehicle_command, LiveSessionState::Failed, false)
        .await;
    let root_b = root_in(
        dir.path(),
        Arc::clone(&plane_b) as Arc<dyn ConversationPlane>,
        Arc::new(FakeEgress::new()),
        Arc::new(FakeApprovals::empty()),
    );
    let projection = root_b
        .execute(intent("after-restart"))
        .await
        .expect("settles on the recovered vehicle");
    assert_eq!(projection["session"], session.to_string());
    assert_eq!(
        plane_b.recoveries.lock().as_slice(),
        [session.to_string()],
        "the SAME session recovered in place"
    );
    assert!(plane_b.opens.lock().is_empty(), "no replacement open");
    assert_eq!(plane_b.prompt_count("command:intent:"), 1);
}

/// A crash after send before projection replays by OBSERVING the
/// recorded cursor through the real journal: the prompt is never
/// admitted twice.
#[tokio::test(start_paused = true)]
async fn crash_after_send_replays_by_observation_only() {
    let (_dir, plane, _egress, _approvals, root) = harness().await;
    root.initialize().await.expect("initialize");
    root.execute(intent("k1")).await.expect("first settles");
    let session = root
        .current_vehicle_session()
        .await
        .expect("vehicle")
        .expect("vehicle");

    let mut record = root.load_record().expect("record");
    let head = plane.ledger.head(session).await.expect("head").get();
    let k2_command = bounded_command("intent", &["k2"]).expect("command id");
    record.in_flight = Some(InFlightPrompt {
        harness: Default::default(),
        idempotency_key: "k2".to_owned(),
        content: "intent k2".to_owned(),
        command_id: k2_command.to_string(),
        session_id: session.to_string(),
        kind: InFlightKind::Prompt,
        expected_epoch: 1,
        event_cursor: head,
        phase: InFlightPhase::Sent,
        clock: None,
        brief: None,
        asks: Vec::new(),
        owner: false,
        unprompted: false,
    });
    record.last_idempotency_key = None;
    record.last_projection = None;
    root.store_record(&mut record).expect("record stored");
    plane
        .push_event(
            &session,
            LiveEventBody::AssistantMessage(text_message("The second answer.")),
        )
        .await;
    plane
        .push_state_change(&session, LiveSessionState::Idle)
        .await;

    let projection = root.execute(intent("k2")).await.expect("observed settle");
    assert_eq!(projection["answer"], "The second answer.");
    assert_eq!(
        plane.prompt_count("command:intent:"),
        1,
        "the k1 prompt only: observation, never a resend"
    );
    assert!(
        plane.command_entries(&k2_command.to_string()).is_empty(),
        "the k2 command never touched the journal"
    );
}

/// A yes to a question that never reached him authorizes nothing; the question is sent again,
/// and his yes to that one decides.
#[tokio::test(start_paused = true)]
async fn a_yes_to_an_undelivered_question_sends_it_again() {
    let (_dir, plane, egress, _approvals, root) = harness().await;
    egress.fail.store(true, Ordering::SeqCst);
    plane.auto_reply.store(false, Ordering::SeqCst);
    root.initialize().await.expect("initialize");
    let failure = root.execute(intent("gated")).await.expect_err("bounds out");
    assert_eq!(failure, IntentFailure::AnswerTimeout);
    egress.fail.store(false, Ordering::SeqCst);
    let sent_before = egress.sends().len();
    root.try_decision(owner_message("yes"))
        .await
        .expect("decision handled")
        .expect("the yes is answered");
    assert_eq!(plane.decide_count(), 0, "nothing was authorized");
    assert!(
        egress.sends().len() > sent_before,
        "the question reaches him now"
    );
    let record = root.load_record().expect("record");
    assert!(record
        .questions
        .iter()
        .all(|question| question.delivered_message_id.is_some()));
}

#[tokio::test(start_paused = true)]
async fn a_delivered_question_cannot_authorize_a_reused_id_after_recovery() {
    let (_dir, plane, _egress, _approvals, root) = harness().await;
    plane.auto_reply.store(false, Ordering::SeqCst);
    root.initialize().await.unwrap();
    root.execute(intent("gated")).await.unwrap();
    assert!(
        root.load_record()
            .unwrap()
            .questions
            .iter()
            .any(|question| question.delivered_message_id.is_some()),
        "the first question reached him"
    );
    let session = root.current_vehicle_session().await.unwrap().unwrap();
    plane.recover_session(session).await.unwrap();
    plane
        .push_event(
            &session,
            LiveEventBody::PermissionRequested(permission_request("perm-a", "A new question")),
        )
        .await;
    plane
        .push_state_change(&session, LiveSessionState::RequiresAction)
        .await;
    let answered = root.try_decision(owner_message("yes")).await.unwrap();
    assert!(
        answered.is_some(),
        "the yes is refused aloud, not read as chat"
    );
    assert_eq!(plane.decide_count(), 0);
}

#[tokio::test(start_paused = true)]
async fn a_denial_carries_its_instruction() {
    let dir = scratch_dir();
    let plane = Arc::new(FakePlane::new(dir.path()).await);
    plane.auto_reply.store(false, Ordering::SeqCst);
    plane.pending_requests.lock().clear();
    let egress = Arc::new(FakeEgress::new());
    let approvals = Arc::new(FakeApprovals::empty());
    let root = root_in(
        dir.path(),
        Arc::clone(&plane) as Arc<dyn ConversationPlane>,
        egress.clone(),
        approvals.clone(),
    );
    root.initialize().await.expect("initialize");
    let session = root
        .current_vehicle_session()
        .await
        .expect("vehicle")
        .expect("session");
    approvals.request("approval:r3:email.send:detail", session);
    let _ = root.execute(intent("gated")).await;
    assert!(
        root.try_decision(owner_message("no worries"))
            .await
            .expect("handled")
            .is_none(),
        "a pleasantry is chat, not a decision"
    );
    assert_eq!(approvals.decide_count(), 0);
    root.try_decision(owner_message("no — send it to my school address instead"))
        .await
        .expect("handled")
        .expect("decided");
    assert_eq!(approvals.decide_count(), 1);
    let record = root.load_record().expect("record");
    let wake = record
        .wakes
        .iter()
        .find(|wake| wake.approval_id.as_deref() == Some("approval:r3:email.send:detail"))
        .expect("declined wake");
    assert!(!wake.approved);
    assert_eq!(
        wake.owner_note.as_deref(),
        Some("send it to my school address instead")
    );
}

#[tokio::test(start_paused = true)]
async fn a_question_decided_on_another_surface_resumes_the_conversation() {
    let dir = scratch_dir();
    let plane = Arc::new(FakePlane::new(dir.path()).await);
    plane.auto_reply.store(false, Ordering::SeqCst);
    plane.pending_requests.lock().clear();
    *plane.answer.lock() = "Sent it.".to_owned();
    let egress = Arc::new(FakeEgress::new());
    let approvals = Arc::new(FakeApprovals::empty());
    let root = root_in(
        dir.path(),
        Arc::clone(&plane) as Arc<dyn ConversationPlane>,
        egress.clone(),
        approvals.clone(),
    );
    root.initialize().await.expect("initialize");
    let session = root
        .current_vehicle_session()
        .await
        .expect("vehicle")
        .expect("session");
    approvals.request("approval:r3:email.send:huginn", session);
    let projection = root.execute(intent("gated")).await.expect("waits");
    assert_eq!(projection["waitingOnApproval"], true);
    let wakes = root.load_record().expect("record").wakes.len();
    root.decide_external("approval:r3:email.send:other", true, async {})
        .await
        .expect("an unrelated decision stands alone");
    assert_eq!(root.load_record().expect("record").wakes.len(), wakes);

    root.decide_external("approval:r3:email.send:huginn", true, async {
        // The Huginn surface records the decision in the ledger.
        approvals.decisions.lock().push((
            "approval:r3:email.send:huginn".to_owned(),
            OwnerDecision::AllowOnce,
        ));
        approvals
            .pending
            .lock()
            .retain(|pending| pending.approval_id.as_str() != "approval:r3:email.send:huginn");
        plane.auto_reply.store(true, Ordering::SeqCst);
        plane
            .push_state_change(&session, LiveSessionState::Idle)
            .await;
    })
    .await
    .expect("this conversation's question is owned");
    root.join_background(StdDuration::from_secs(30)).await;
    assert_eq!(
        *approvals.ran.lock(),
        ["approval:r3:email.send:huginn"],
        "a device's yes runs the held call, as a DM yes does"
    );
    assert!(
        egress.sends().iter().any(|sent| sent == "Sent it."),
        "the continuation answered: {:?}",
        egress.sends()
    );
}

#[tokio::test(start_paused = true)]
async fn a_device_yes_runs_the_call_another_seat_parked() {
    let dir = scratch_dir();
    let plane = Arc::new(FakePlane::new(dir.path()).await);
    let egress = Arc::new(FakeEgress::new());
    let approvals = Arc::new(FakeApprovals::empty());
    let root = root_in(
        dir.path(),
        Arc::clone(&plane) as Arc<dyn ConversationPlane>,
        egress,
        approvals.clone(),
    );
    root.initialize().await.expect("initialize");
    let parked = "approval:r1:project.campaign_approve:planner";
    root.decide_external(parked, true, async {
        approvals
            .decisions
            .lock()
            .push((parked.to_owned(), OwnerDecision::AllowOnce));
    })
    .await
    .expect("another seat's approval stands alone");
    assert_eq!(*approvals.ran.lock(), [parked]);
}

/// A settled kernel decision's continuation uses the same durable
/// vehicle and command identity when its wake plan is resumed.
#[tokio::test(start_paused = true)]
async fn kernel_decision_continuation_survives_durable_wake_resume() {
    let long_approval = format!("approval:r3-{}", "x".repeat(90));
    let dir = scratch_dir();
    let plane = Arc::new(FakePlane::new(dir.path()).await);
    plane.auto_reply.store(false, Ordering::SeqCst);
    plane.pending_requests.lock().clear();
    *plane.answer.lock() = "The report went out.".to_owned();
    let egress = Arc::new(FakeEgress::new());
    let approvals = Arc::new(FakeApprovals::empty());
    let root = root_in(
        dir.path(),
        Arc::clone(&plane) as Arc<dyn ConversationPlane>,
        egress.clone(),
        approvals.clone(),
    );
    root.initialize().await.expect("initialize");
    let session = root
        .current_vehicle_session()
        .await
        .expect("vehicle")
        .expect("session");
    approvals.request(&long_approval, session);
    let projection = root
        .execute(intent("gated"))
        .await
        .expect("settles waiting");
    assert_eq!(projection["waitingOnApproval"], true);

    // The owner decides; the wake observes the continuation window.
    plane.auto_reply.store(true, Ordering::SeqCst);
    plane
        .push_state_change(&session, LiveSessionState::Idle)
        .await;
    plane.pause_next_prompt.store(true, Ordering::SeqCst);
    root.try_decision(owner_message("yes"))
        .await
        .expect("decision handled")
        .expect("consumed as a decision");
    assert_eq!(approvals.decide_count(), 1);
    tokio::time::timeout(ANSWER_BOUND, plane.prompt_paused.notified())
        .await
        .expect("continuation reaches the pre-admission crash window");
    root.join_background(StdDuration::ZERO).await;
    assert!(
        root.initialize().await.is_err(),
        "a stopped runtime cannot re-arm"
    );
    let record = root.load_record().expect("durable interrupted wake");
    let wake_id = record
        .wakes
        .iter()
        .find(|wake| wake.approval_id.as_deref() == Some(long_approval.as_str()))
        .expect("settled decision retains its wake")
        .command_id
        .clone();
    assert_eq!(plane.prompt_count(&wake_id), 0, "crash preceded admission");
    let restarted = root_in(
        dir.path(),
        Arc::clone(&plane) as Arc<dyn ConversationPlane>,
        egress.clone(),
        approvals.clone(),
    );
    restarted
        .initialize()
        .await
        .expect("fresh owner resumes wakes");
    restarted.join_background(StdDuration::from_secs(30)).await;
    assert_eq!(
        plane.prompt_count(&wake_id),
        1,
        "the wake never repeats its prompt"
    );
    assert_eq!(
        egress
            .sends()
            .iter()
            .filter(|sent| sent.as_str() == "The report went out.")
            .count(),
        1,
        "the resumed continuation reaches the owner exactly once"
    );
    let record = restarted.load_record().expect("record");
    assert!(
        record.wakes.iter().all(|wake| wake.command_id != wake_id),
        "the ran wake plan cleared"
    );
}

/// The wedge escape (GAP 5): a vehicle whose in-place recovery keeps
/// failing refused every turn forever. The first failures stay typed
/// refusals on the SAME session; at the bound the conversation rolls to a
/// governed successor and the turn runs there.
#[tokio::test(start_paused = true)]
async fn a_vehicle_whose_recovery_keeps_failing_rolls_to_a_successor() {
    let dir = scratch_dir();
    let vehicle_command = {
        let plane = Arc::new(FakePlane::new(dir.path()).await);
        let root = root_in(
            dir.path(),
            Arc::clone(&plane) as Arc<dyn ConversationPlane>,
            Arc::new(FakeEgress::new()),
            Arc::new(FakeApprovals::empty()),
        );
        root.initialize().await.expect("initialize");
        root.vehicle_command_id().expect("vehicle command")
    };
    let plane_b = Arc::new(FakePlane::new(dir.path()).await);
    let session = plane_b
        .seed(&vehicle_command, LiveSessionState::Failed, false)
        .await;
    *plane_b.reclaim_failure.lock() = Some(LiveError::unavailable(
        "bridge_launch_refused",
        "scripted launch refusal",
    ));
    let root_b = root_in(
        dir.path(),
        Arc::clone(&plane_b) as Arc<dyn ConversationPlane>,
        Arc::new(FakeEgress::new()),
        Arc::new(FakeApprovals::empty()),
    );
    for attempt in 1..crate::conversation::vehicle::WEDGE_ESCAPE_AFTER {
        let failure = root_b
            .execute(intent(&format!("wedged-{attempt}")))
            .await
            .expect_err("a failed reclaim refuses typed");
        assert!(
            matches!(failure, IntentFailure::VehicleRecoveryFailed { .. }),
            "{failure:?}"
        );
        assert!(plane_b.opens.lock().is_empty(), "no successor yet");
    }
    assert_eq!(root_b.previous_vehicle().await.expect("previous"), None);
    let _ = root_b.execute(intent("escape")).await;
    let record = root_b.load_record().expect("record");
    let current = record.session_id.clone().expect("vehicle");
    assert_ne!(
        current,
        session.to_string(),
        "the conversation left the wedge"
    );
    let previous = root_b
        .previous_vehicle()
        .await
        .expect("previous")
        .expect("clients can find the session it rolled over from");
    assert_eq!(previous.session, session);
    assert_eq!(
        plane_b.opens.lock().len(),
        1,
        "exactly one successor opened"
    );
    assert_eq!(record.recovery_failures, 0);
}

/// Backoff survives restarts; a new daemon executable resets it.
#[tokio::test(start_paused = true)]
async fn a_successor_that_never_starts_backs_off_instead_of_minting_sessions() {
    use crate::conversation::rollover::ended_successor_backoff_ms;
    let dir = scratch_dir();
    let vehicle_command = {
        let plane = Arc::new(FakePlane::new(dir.path()).await);
        let root = root_in(
            dir.path(),
            Arc::clone(&plane) as Arc<dyn ConversationPlane>,
            Arc::new(FakeEgress::new()),
            Arc::new(FakeApprovals::empty()),
        );
        root.initialize().await.expect("initialize");
        root.vehicle_command_id().expect("vehicle command")
    };
    let plane = Arc::new(FakePlane::new(dir.path()).await);
    plane
        .seed(&vehicle_command, LiveSessionState::Failed, false)
        .await;
    *plane.reclaim_failure.lock() = Some(LiveError::unavailable(
        "bridge_launch_refused",
        "scripted launch refusal",
    ));
    plane.fail_opens.store(usize::MAX, Ordering::SeqCst);
    let authority = Arc::new(FakeAuthority {
        calls: Mutex::new(Vec::new()),
        bound: 1,
        current: 1,
        script: Mutex::new(BTreeMap::new()),
        deferred: std::sync::atomic::AtomicBool::new(false),
        troubles: Mutex::new(Vec::new()),
    });
    let root = root_in_authority(
        dir.path(),
        Arc::clone(&plane) as Arc<dyn ConversationPlane>,
        Arc::new(FakeEgress::new()),
        Arc::new(FakeApprovals::empty()),
        Arc::clone(&authority),
    );
    for _ in 0..crate::conversation::vehicle::WEDGE_ESCAPE_AFTER {
        assert!(root.initialize().await.is_err());
    }
    *plane.reclaim_failure.lock() = None;
    for _ in 0..10 {
        assert!(root.initialize().await.is_err());
    }
    assert_eq!(
        plane.opens.lock().len(),
        2,
        "the ended successor is replaced once; later retries wait out the backoff"
    );
    match root.initialize().await {
        Err(crate::conversation::InitializeError::SuccessorBackoff {
            attempts: 1,
            retry_at_unix_ms,
        }) => assert!(retry_at_unix_ms > crate::conversation::identity::now_unix_ms()),
        other => panic!("expected the typed successor backoff, got {other:?}"),
    }
    let rewind =
        |root: &ConversationRoot,
         edit: &dyn Fn(&mut crate::conversation::rollover::EndedSuccessors)| {
            let mut record = root.load_record().expect("record");
            edit(
                record
                    .rollover
                    .as_mut()
                    .and_then(|slot| slot.ended.as_mut())
                    .expect("ended successors are durable"),
            );
            root.store_record(&mut record).expect("store");
        };
    rewind(&root, &|ended| {
        ended.last_at_unix_ms -= ended_successor_backoff_ms(ended.count);
    });
    assert!(root.initialize().await.is_err());
    assert_eq!(plane.opens.lock().len(), 3, "one more after the backoff");
    assert!(matches!(
        root.initialize().await,
        Err(crate::conversation::InitializeError::SuccessorBackoff { attempts: 2, .. })
    ));
    rewind(&root, &|ended| {
        ended.executable = "/nix/store/new-odind".to_owned()
    });
    assert!(root.initialize().await.is_err());
    assert_eq!(plane.opens.lock().len(), 4, "a new build retries at once");
    let record = root.load_record().expect("record");
    assert_eq!(
        record
            .rollover
            .and_then(|slot| slot.ended)
            .map(|ended| ended.count),
        Some(1)
    );

    use crate::conversation::rollover::MAX_ENDED_SUCCESSORS;
    for count in 1..MAX_ENDED_SUCCESSORS {
        rewind(&root, &|ended| {
            ended.last_at_unix_ms -= ended_successor_backoff_ms(ended.count);
        });
        assert!(root.initialize().await.is_err());
        assert_eq!(
            root.load_record()
                .expect("record")
                .rollover
                .and_then(|slot| slot.ended)
                .map(|ended| ended.count),
            Some(count + 1)
        );
    }
    let minted = plane.opens.lock().len();
    let successor = root
        .load_record()
        .expect("record")
        .rollover
        .expect("slot")
        .successor_session;
    for _ in 0..3 {
        rewind(&root, &|ended| ended.last_at_unix_ms = 0);
        assert!(matches!(
            root.initialize().await,
            Err(crate::conversation::InitializeError::SuccessorExhausted { attempts })
                if attempts == MAX_ENDED_SUCCESSORS
        ));
    }
    assert_eq!(plane.opens.lock().len(), minted, "the cap stops minting");
    use crate::conversation::SuccessorTrouble;
    let troubles = authority.troubles.lock().clone();
    assert!(matches!(
        troubles[0],
        SuccessorTrouble::Backoff { attempts: 1, .. }
    ));
    let exhausted: Vec<_> = troubles
        .iter()
        .filter_map(|trouble| match trouble {
            SuccessorTrouble::Exhausted { attempts, newly } => Some((*attempts, *newly)),
            _ => None,
        })
        .collect();
    assert_eq!(
        exhausted,
        vec![
            (MAX_ENDED_SUCCESSORS, true),
            (MAX_ENDED_SUCCESSORS, false),
            (MAX_ENDED_SUCCESSORS, false)
        ],
        "the desk hears the exhaustion once as news, then as a restatement"
    );
    assert_eq!(
        root.load_record()
            .expect("record")
            .rollover
            .expect("slot")
            .successor_session,
        successor,
        "the identity stops advancing"
    );
}

/// A coherent bound/current pair recovers in place: no successor, no
/// retirement, no slot.
#[tokio::test(start_paused = true)]
async fn coherent_generations_recover_in_place_without_a_rollover() {
    let dir = scratch_dir();
    let vehicle_command = {
        let plane = Arc::new(FakePlane::new(dir.path()).await);
        let root = root_in(
            dir.path(),
            Arc::clone(&plane) as Arc<dyn ConversationPlane>,
            Arc::new(FakeEgress::new()),
            Arc::new(FakeApprovals::empty()),
        );
        root.initialize().await.expect("initialize");
        root.vehicle_command_id().expect("vehicle command")
    };
    let plane_b = Arc::new(FakePlane::new(dir.path()).await);
    let session = plane_b
        .seed(&vehicle_command, LiveSessionState::Failed, false)
        .await;
    let root_b = root_in_generations(
        dir.path(),
        Arc::clone(&plane_b) as Arc<dyn ConversationPlane>,
        Arc::new(FakeEgress::new()),
        Arc::new(FakeApprovals::empty()),
        1,
        1,
    );
    root_b.initialize().await.expect("plain recovery");
    let record = root_b.load_record().expect("record");
    assert!(record.rollover.is_none(), "no successor was armed");
    assert!(record.session_id.as_deref() == Some(session.to_string().as_str()));
    assert_eq!(
        plane_b.recoveries.lock().as_slice(),
        [session.to_string()],
        "the SAME session recovered in place"
    );
}

/// Derives the bounded successor identity of one predecessor, the same
/// derivation the rollover performs.
fn successor_of(
    conversation_id: &str,
    predecessor_session: &LiveSessionId,
) -> (CommandId, LiveSessionId) {
    let command = successor_vehicle_command(conversation_id, &predecessor_session.to_string())
        .expect("successor command");
    let session = odin_omp::live::supervisor::session_id_for(&command).expect("successor session");
    (command, session)
}

/// How the runtime settled one owner-DM turn. Only a completed,
/// executed, delivered outcome is continuity-eligible.
#[derive(Clone, Copy)]
enum TurnSettlement {
    Delivered,
    Undelivered,
    Failed,
}

/// One owner-DM conversation command as the production intake records
/// it and the runtime settles it into the root ledger.
struct OwnerTurn {
    message_id: u64,
    author_id: String,
    channel_id: String,
    guild_id: Option<String>,
    request: String,
    target_seat: String,
    project: String,
    session: String,
    answer: String,
    settlement: TurnSettlement,
    /// Corrupt causal identity: the outcome names another command.
    forged_command_id: bool,
    /// Corrupt causal identity: the outcome names another key.
    forged_idempotency_key: bool,
}

impl OwnerTurn {
    /// The canonical delivered turn of the paired owner on the current
    /// seat, delivered by one of the conversation's bygone vehicles.
    fn delivered(message_id: u64, request: &str, answer: &str, session: &str) -> Self {
        Self {
            message_id,
            author_id: OWNER.to_owned(),
            channel_id: CHANNEL.to_owned(),
            guild_id: None,
            request: request.to_owned(),
            target_seat: SEAT.to_owned(),
            project: PROJECT.to_owned(),
            session: session.to_owned(),
            answer: answer.to_owned(),
            settlement: TurnSettlement::Delivered,
            forged_command_id: false,
            forged_idempotency_key: false,
        }
    }
}

/// Records one owner-DM turn in the root ledger through the typed
/// command state machine — record, accept, complete — with the exact
/// argument and executed-outcome shapes production writes.
fn record_owner_turn(ledger: &mut Ledger, turn: &OwnerTurn, turn_at: OffsetDateTime) {
    let idempotency_key = format!("discord:v1:{}:{}", turn.channel_id, turn.message_id);
    let command_id = CommandId::new(format!(
        "{INTENT_COMMAND_PREFIX}{}",
        identity_from_key(&idempotency_key)
    ))
    .expect("intent command id");
    let arguments = serde_json::json!({
        "request": turn.request,
        "channel_id": turn.channel_id,
        "message_id": turn.message_id.to_string(),
        "author_id": turn.author_id,
        "guild_id": turn.guild_id,
    });
    let spec = CommandSpec {
        id: command_id.clone(),
        idempotency_key: idempotency_key.clone(),
        correlation_id: idempotency_key.clone(),
        causation_id: Some(format!("discord:message:{}", turn.message_id)),
        issuer: INTENT_ISSUER.to_owned(),
        approval_id: None,
        target_kind: "seat".to_owned(),
        target_id: turn.target_seat.clone(),
        capability_id: CapabilityId::new("discord.intake").expect("capability id"),
        capability_version: 1,
        arguments_hash: Digest::hash(arguments.to_string().as_bytes()),
        arguments,
        expected_desired_revision: None,
        issued_at: turn_at,
        expires_at: turn_at + time::Duration::hours(1),
    };
    let recorded = match ledger.record_command(&spec).expect("intent recorded") {
        RecordCommand::Inserted(recorded) => recorded,
        RecordCommand::Existing(_) => panic!("fixture message ids must be unique"),
    };
    let accepted = ledger
        .accept_command(&recorded, recorded.command().revision, turn_at)
        .expect("intent accepted");
    let outcome = serde_json::json!({
        "conversationId": format!(
            "conversation:{}",
            conversation_root_identity(SEAT, PROJECT)
        ),
        "session": turn.session,
        "seat": turn.target_seat,
        "project": turn.project,
        "commandId": if turn.forged_command_id {
            "command:discord-intent:forged-identity".to_owned()
        } else {
            command_id.to_string()
        },
        "idempotencyKey": if turn.forged_idempotency_key {
            "discord:v1:forged:1".to_owned()
        } else {
            idempotency_key
        },
        "answer": turn.answer,
        "waitingOnApproval": false,
        "replySent": matches!(turn.settlement, TurnSettlement::Delivered),
    });
    let settle = |status| CommandOutcome {
        status,
        result: match status {
            CommandTerminalStatus::Completed => {
                serde_json::json!({ "status": "executed", "outcome": outcome })
            }
            _ => serde_json::json!({
                "status": "failed",
                "reason": "the execution route refused the settled intent",
            }),
        },
    };
    ledger
        .complete_command(
            &accepted,
            &settle(match turn.settlement {
                TurnSettlement::Failed => CommandTerminalStatus::Failed,
                _ => CommandTerminalStatus::Completed,
            }),
            accepted.command().revision,
            turn_at + time::Duration::seconds(1),
        )
        .expect("turn settled");
}

/// A bygone vehicle session of this logical conversation, minted
/// through the same bounded rollover derivation every real vehicle
/// identity follows. Durable turns name these: the logical identity
/// survives vehicle changes, so the history source cannot filter by
/// session id.
fn bygone_vehicle_session(conversation_id: &str, generation: u64) -> LiveSessionId {
    let command = bounded_command(
        "conversation-vehicle-rollover",
        &[conversation_id, &format!("generation-{generation}")],
    )
    .expect("bygone vehicle command");
    odin_omp::live::supervisor::session_id_for(&command).expect("bygone vehicle session")
}

/// Writes `count` canonical delivered turns at one-minute spacing,
/// each delivered by a rotating bygone vehicle. Turn `index` carries
/// the texts REQUEST-{index:03} and ANSWER-{index:03}.
fn write_delivered_turns(
    ledger: &mut Ledger,
    conversation_id: &str,
    count: usize,
    base: OffsetDateTime,
) {
    for index in 0..count {
        let session = bygone_vehicle_session(conversation_id, (index % 3) as u64).to_string();
        record_owner_turn(
            ledger,
            &OwnerTurn::delivered(
                1_100_000_000_000_000_000 + index as u64,
                &format!("REQUEST-{index:03}"),
                &format!("ANSWER-{index:03}"),
                &session,
            ),
            base + time::Duration::minutes(index as i64),
        );
    }
}

/// The failed-vehicle recovery scenario pieces: the fresh daemon over
/// the retired vehicle, the retired identity, and the derived
/// successor command the rollover mints at the current generation.
struct FailedVehicle {
    plane: Arc<FakePlane>,
    vehicle_command: CommandId,
    predecessor: LiveSessionId,
    successor_command: CommandId,
}

/// A current vehicle that went down mid-turn: its journal holds only
/// `state_events` lifecycle state changes and never a message.
/// Lifecycle events enough that the newest are not on the journal's first history page.
fn more_than_a_page() -> usize {
    2 * usize::from(crate::conversation::history::page_limit().get()) + 2
}

async fn failed_vehicle_fixture(dir: &std::path::Path, state_events: usize) -> FailedVehicle {
    let vehicle_command = {
        let plane = Arc::new(FakePlane::new(dir).await);
        let root = root_in(
            dir,
            Arc::clone(&plane) as Arc<dyn ConversationPlane>,
            Arc::new(FakeEgress::new()),
            Arc::new(FakeApprovals::empty()),
        );
        root.initialize().await.expect("initialize");
        root.vehicle_command_id().expect("vehicle command")
    };
    let predecessor =
        odin_omp::live::supervisor::session_id_for(&vehicle_command).expect("predecessor");
    let plane_b = Arc::new(FakePlane::new(dir).await);
    let session = plane_b
        .seed(&vehicle_command, LiveSessionState::Failed, false)
        .await;
    for index in 0..state_events {
        plane_b
            .push_event(
                &session,
                LiveEventBody::SessionStateChanged(odin_domain::huginn::SessionStateChanged {
                    previous: if index % 2 == 0 {
                        LiveSessionState::Idle
                    } else {
                        LiveSessionState::Running
                    },
                    current: if index % 2 == 0 {
                        LiveSessionState::Running
                    } else {
                        LiveSessionState::Idle
                    },
                    reason: None,
                }),
            )
            .await;
    }
    let conversation_id = format!("conversation:{}", conversation_root_identity(SEAT, PROJECT));
    let (successor_command, _) = successor_of(&conversation_id, &predecessor);
    FailedVehicle {
        plane: plane_b,
        vehicle_command,
        predecessor,
        successor_command,
    }
}

/// Rolls the failed vehicle over at a lagging generation and settles
/// the in-flight intent on the successor. Returns the successor's
/// first prompt (the continuity brief), the fresh session, and the
/// settled projection.
async fn roll_failed_vehicle(
    fx: &FailedVehicle,
    dir: &std::path::Path,
) -> (String, LiveSessionId, serde_json::Value) {
    roll_failed_vehicle_under(fx, dir, Default::default()).await
}

async fn roll_failed_vehicle_under(
    fx: &FailedVehicle,
    dir: &std::path::Path,
    rollover: odin_omp::live::rollover::RolloverPolicy,
) -> (String, LiveSessionId, serde_json::Value) {
    let mut script = BTreeMap::new();
    script.insert(
        fx.vehicle_command.to_string(),
        EnsuredGeneration {
            bound: 9,
            current: 12,
            composition: None,
        },
    );
    script.insert(
        fx.successor_command.to_string(),
        EnsuredGeneration {
            bound: 12,
            current: 12,
            composition: None,
        },
    );
    let root_b = root_with_rollover(
        dir,
        Arc::clone(&fx.plane) as Arc<dyn ConversationPlane>,
        Arc::new(FakeEgress::new()),
        Arc::new(FakeApprovals::empty()),
        Arc::new(FakeAuthority {
            calls: Mutex::new(Vec::new()),
            bound: 12,
            current: 12,
            script: Mutex::new(script),
            deferred: std::sync::atomic::AtomicBool::new(false),
            troubles: Mutex::new(Vec::new()),
        }),
        rollover,
    );
    let projection = root_b
        .execute(intent("after-restart"))
        .await
        .expect("the rollover completes and the intent settles");
    let successor = root_b
        .current_vehicle_session()
        .await
        .expect("vehicle readable")
        .expect("successor recorded");
    let prompts = fx.plane.initial_prompts.lock();
    assert_eq!(prompts.len(), 1, "the brief rode the successor open");
    (prompts[0].clone(), successor, projection)
}

/// The brief's conversation tail: the bounded transcript the successor
/// opens with.
fn brief_conversation_tail(prompt: &str) -> Vec<serde_json::Value> {
    let brief_json = prompt
        .lines()
        .nth(1)
        .expect("rollover prompt carries the brief json");
    let brief: serde_json::Value = serde_json::from_str(brief_json).expect("brief parses");
    brief["conversation_tail"]
        .as_array()
        .expect("conversation tail")
        .clone()
}

/// A retired vehicle whose journal is lifecycle state only (more than a
/// page of events, never a message) still rolls with the RECENT delivered
/// owner-DM tail: the durable conversation ledger is the history
/// source, carrying the newest 64 settled turns in chronological
/// order across bygone vehicle identities, and the oldest page never
/// replaces the tail.
#[tokio::test(start_paused = true)]
async fn recovery_carries_the_recent_journal_tail_not_the_oldest_page() {
    let dir = scratch_dir();
    let fx = failed_vehicle_fixture(dir.path(), more_than_a_page()).await;
    let conversation_id = format!("conversation:{}", conversation_root_identity(SEAT, PROJECT));
    // 66 delivered turns: two more than the newest-64 pair window.
    let mut ledger = Ledger::open(state_ledger_path(dir.path())).expect("root ledger opens");
    write_delivered_turns(
        &mut ledger,
        &conversation_id,
        66,
        OffsetDateTime::now_utc() - time::Duration::hours(2),
    );
    drop(ledger);
    let (prompt, successor, projection) = roll_failed_vehicle(&fx, dir.path()).await;
    assert_ne!(successor, fx.predecessor, "a FRESH session identity");
    assert_eq!(projection["session"], successor.to_string());
    assert_eq!(
        fx.plane.retirements.lock().as_slice(),
        [fx.predecessor.to_string()],
        "the failed predecessor governed Ended exactly once"
    );
    let tail = brief_conversation_tail(&prompt);
    // The budget chooses how many newest pairs fit; they must remain contiguous and chronological.
    let pairs = tail.len() / 2;
    assert!(pairs >= 2, "the newest turns ride the brief");
    let first_index = 66 - pairs;
    for (position, index) in (first_index..66).enumerate() {
        let user = &tail[position * 2];
        let assistant = &tail[position * 2 + 1];
        assert_eq!(user["role"], "user", "turn {index} rides the brief");
        assert_eq!(user["text"], format!("REQUEST-{index:03}"));
        assert_eq!(assistant["role"], "assistant");
        assert_eq!(assistant["text"], format!("ANSWER-{index:03}"));
    }
}

/// Newer rows that are not this owner's delivered DM turns — foreign
/// author, channel, seat, or project; forged causal identity;
/// undelivered; failed — neither poison the brief nor crowd eligible
/// turns out of the newest-64 window.
#[tokio::test(start_paused = true)]
async fn ineligible_ledger_rows_never_poison_or_crowd_out_eligible_turns() {
    let dir = scratch_dir();
    let fx = failed_vehicle_fixture(dir.path(), more_than_a_page()).await;
    let conversation_id = format!("conversation:{}", conversation_root_identity(SEAT, PROJECT));
    let base = OffsetDateTime::now_utc() - time::Duration::hours(2);
    let ineligible_session = bygone_vehicle_session(&conversation_id, 7).to_string();
    {
        let mut ledger = Ledger::open(state_ledger_path(dir.path())).expect("root ledger opens");
        write_delivered_turns(&mut ledger, &conversation_id, 65, base);
        let foreign_author = OwnerTurn {
            author_id: "other-owner".to_owned(),
            ..OwnerTurn::delivered(
                2_000_000_000_000_000_000,
                "FOREIGN-AUTHOR",
                "FOREIGN-REPLY-A",
                &ineligible_session,
            )
        };
        let foreign_channel = OwnerTurn {
            channel_id: "99998888777766655001".to_owned(),
            ..OwnerTurn::delivered(
                2_000_000_000_000_000_001,
                "FOREIGN-CHANNEL",
                "FOREIGN-REPLY-B",
                &ineligible_session,
            )
        };
        let guild_message = OwnerTurn {
            guild_id: Some("555000111222333".to_owned()),
            ..OwnerTurn::delivered(
                2_000_000_000_000_000_002,
                "FOREIGN-GUILD",
                "FOREIGN-REPLY-C",
                &ineligible_session,
            )
        };
        let foreign_seat = OwnerTurn {
            target_seat: "satellite".to_owned(),
            ..OwnerTurn::delivered(
                2_000_000_000_000_000_003,
                "FOREIGN-SEAT",
                "FOREIGN-REPLY-D",
                &ineligible_session,
            )
        };
        let foreign_project = OwnerTurn {
            project: "satellite-project".to_owned(),
            ..OwnerTurn::delivered(
                2_000_000_000_000_000_004,
                "FOREIGN-PROJECT",
                "FOREIGN-REPLY-E",
                &ineligible_session,
            )
        };
        let forged_command = OwnerTurn {
            forged_command_id: true,
            ..OwnerTurn::delivered(
                2_000_000_000_000_000_005,
                "FORGED-COMMAND",
                "FORGED-REPLY-A",
                &ineligible_session,
            )
        };
        let forged_key = OwnerTurn {
            forged_idempotency_key: true,
            ..OwnerTurn::delivered(
                2_000_000_000_000_000_006,
                "FORGED-KEY",
                "FORGED-REPLY-B",
                &ineligible_session,
            )
        };
        let undelivered = OwnerTurn {
            settlement: TurnSettlement::Undelivered,
            ..OwnerTurn::delivered(
                2_000_000_000_000_000_007,
                "UNDELIVERED",
                "UNDELIVERED-REPLY",
                &ineligible_session,
            )
        };
        let failed = OwnerTurn {
            settlement: TurnSettlement::Failed,
            ..OwnerTurn::delivered(
                2_000_000_000_000_000_008,
                "FAILED-TURN",
                "FAILED-REPLY",
                &ineligible_session,
            )
        };
        for (position, turn) in [
            foreign_author,
            foreign_channel,
            guild_message,
            foreign_seat,
            foreign_project,
            forged_command,
            forged_key,
            undelivered,
            failed,
        ]
        .into_iter()
        .enumerate()
        {
            record_owner_turn(
                &mut ledger,
                &turn,
                base + time::Duration::minutes(100 + position as i64),
            );
        }
    }
    let (prompt, _successor, _projection) = roll_failed_vehicle(&fx, dir.path()).await;
    let tail = brief_conversation_tail(&prompt);
    // The byte-bounded brief rides the NEWEST ELIGIBLE pairs (the exact
    // count is whatever fits the current budget); ineligible rows never
    // crowd them out.
    let pairs = tail.len() / 2;
    assert!(pairs >= 2, "eligible turns ride the brief");
    let first_index = 65 - pairs;
    for (position, index) in (first_index..65).enumerate() {
        assert_eq!(
            tail[position * 2]["text"],
            format!("REQUEST-{index:03}"),
            "eligible turn {index} keeps its slot"
        );
        assert_eq!(tail[position * 2 + 1]["text"], format!("ANSWER-{index:03}"));
    }
    for token in [
        "FOREIGN-AUTHOR",
        "FOREIGN-CHANNEL",
        "FOREIGN-GUILD",
        "FOREIGN-SEAT",
        "FOREIGN-PROJECT",
        "FORGED-COMMAND",
        "FORGED-KEY",
        "UNDELIVERED",
    ] {
        assert!(
            !prompt.contains(token),
            "{token} must never poison the brief"
        );
    }
    // His newest message failed: it is no exchange in the tail, but the
    // successor is told it was never answered.
    let tail_text = serde_json::to_string(&tail).expect("tail json");
    assert!(!tail_text.contains("FAILED"), "no failed turn in the tail");
    let brief: serde_json::Value =
        serde_json::from_str(prompt.lines().nth(1).expect("brief json")).expect("brief parses");
    assert_eq!(
        brief["continuity_notes"]["unanswered_request"], "FAILED-TURN",
        "{brief}"
    );
}

#[tokio::test(start_paused = true)]
async fn never_applied_in_flight_flight_is_retired_and_the_next_dm_answers() {
    let (_dir, plane, _egress, _approvals, root) = harness().await;
    root.initialize().await.expect("initialize");
    root.execute(intent("k1")).await.expect("first settles");
    let session = root
        .current_vehicle_session()
        .await
        .expect("vehicle")
        .expect("vehicle");

    // The cached phase says sent, but the journal has no admission for this command.
    let mut record = root.load_record().expect("record");
    let head = plane.ledger.head(session).await.expect("head").get();
    let wedged_command = bounded_command("intent", &["wedged"]).expect("command id");
    record.in_flight = Some(InFlightPrompt {
        harness: Default::default(),
        idempotency_key: "wedged".to_owned(),
        content: "ok you there now?".to_owned(),
        command_id: wedged_command.to_string(),
        session_id: session.to_string(),
        kind: InFlightKind::Prompt,
        expected_epoch: 1,
        event_cursor: head,
        phase: InFlightPhase::Sent,
        clock: None,
        brief: None,
        asks: Vec::new(),
        owner: false,
        unprompted: false,
    });
    root.store_record(&mut record).expect("record stored");

    // The next DM proceeds and is answered — the wedge is gone.
    let projection = root.execute(intent("k2")).await.expect("second DM answers");
    assert_eq!(projection["answer"], "A plain answer.");
    assert!(
        plane
            .command_entries(&wedged_command.to_string())
            .is_empty(),
        "the wedged command stays never-admitted"
    );
    let cleared = root.load_record().expect("record");
    assert!(cleared.in_flight.is_none(), "the flight is retired");
    assert!(cleared.last_idempotency_key.as_deref() != Some("wedged"));
}

/// The predecessor delegated to Kubert, whose session answered: its link
/// ledger, and the child.
async fn delegated_child(
    dir: &std::path::Path,
    plane: &FakePlane,
    vehicle: LiveSessionId,
) -> (
    odin_omp::host_tools::delegation::DelegationLinkLedger,
    LiveSessionId,
) {
    use odin_omp::host_tools::delegation::{
        DelegationLink, DelegationLinkLedger, DelegationPhase, DELEGATION_LINK_SCHEMA,
    };
    let child_command = bounded_command("intent", &["delegated-child"]).expect("command");
    let child = plane
        .open_session(OpenSessionRequest {
            command_id: child_command.clone(),
            seat_id: SeatId::new("kubert").expect("seat"),
            project_id: ProjectId::new(PROJECT).expect("project"),
            slice_id: SliceId::new("kubert-ops").expect("slice"),
            provider: ProviderName::new("prov").expect("provider"),
            model: ModelName::new("model").expect("model"),
            title: Some("Launch the arXiv pod".to_owned()),
            target_node: NodeId::new("node-a").expect("node"),
            open_tab: false,
            workload: None,
            initial_prompt: None,
            served_revision: None,
        })
        .await
        .expect("child opens")
        .session_id;
    plane
        .finish_turn(
            &child,
            "Digest delivered: 17 new flu-dyn papers, none on RDEs.",
        )
        .await;
    let links = DelegationLinkLedger::open(dir.join("links")).expect("links");
    links
        .persist(&DelegationLink {
            schema: DELEGATION_LINK_SCHEMA.to_owned(),
            child,
            parent: odin_domain::SessionId::new(vehicle.to_string()).expect("parent"),
            parent_seat: Some(SeatId::new(SEAT).expect("seat")),
            parent_run: odin_domain::RunId::new(format!("run:live:{vehicle}")).expect("run"),
            child_run: odin_domain::RunId::new(format!("run:live:{child}")).expect("run"),
            command: child_command,
            project: ProjectId::new(PROJECT).expect("project"),
            lane: None,
            budget_raises: Vec::new(),
            provider: "prov".to_owned(),
            model: "model".to_owned(),
            prompt_digest: odin_domain::Digest::hash(b"prompt"),
            depth: 1,
            phase: DelegationPhase::Running,
            created_at_ms: 1,
            learning_capture_sequence: None,
            escalated_to: None,
            escalation_open: false,
            learning_result_sequence: None,
            learning_proposal_id: None,
            stall_retries: 0,
            stalls: Vec::new(),
            switched_to: None,
            handled_stall_event: None,
            refusals: Vec::new(),
            gateway_fallbacks: Vec::new(),
            reported_answer: None,
            assignment: String::new(),
            rollover_admissions: 0,
            pending_report: None,
        })
        .expect("link persists");
    (links, child)
}

#[tokio::test]
async fn rollover_brief_carries_live_delegated_children() {
    let dir = scratch_dir();
    let plane = Arc::new(FakePlane::new(dir.path()).await);
    let root = root_in(
        dir.path(),
        Arc::clone(&plane) as Arc<dyn ConversationPlane>,
        Arc::new(FakeEgress::new()),
        Arc::new(FakeApprovals::empty()),
    );
    root.initialize().await.expect("initialize");
    let vehicle = root
        .current_vehicle_session()
        .await
        .expect("vehicle readable")
        .expect("vehicle");
    let (links, child) = delegated_child(dir.path(), &plane, vehicle).await;

    // Force a rollover the same way production does: the predecessor bound
    // lags the pin.
    let vehicle_command = root.vehicle_command_id().expect("vehicle command");
    let successor_command = successor_vehicle_command(
        &format!("conversation:{}", conversation_root_identity(SEAT, PROJECT)),
        &vehicle.to_string(),
    )
    .expect("successor");
    let mut script = BTreeMap::new();
    script.insert(
        vehicle_command.to_string(),
        EnsuredGeneration {
            bound: 5,
            current: 7,
            composition: None,
        },
    );
    script.insert(
        successor_command.to_string(),
        EnsuredGeneration {
            bound: 7,
            current: 7,
            composition: None,
        },
    );
    let authority = Arc::new(FakeAuthority {
        calls: Mutex::new(Vec::new()),
        bound: 7,
        current: 7,
        script: Mutex::new(script),
        deferred: std::sync::atomic::AtomicBool::new(false),
        troubles: Mutex::new(Vec::new()),
    });
    let plane_b = Arc::new(FakePlane::new(dir.path()).await);
    plane_b.reload_discovered().await;
    let approvals_b = Arc::new(FakeApprovals::empty());
    let root_b = root_with_links(
        dir.path(),
        Arc::clone(&plane_b) as Arc<dyn ConversationPlane>,
        Arc::new(FakeEgress::new()),
        Arc::clone(&approvals_b) as Arc<dyn KernelApprovals>,
        authority,
        Default::default(),
        Some(links),
    );
    root_b.initialize().await.expect("the rollover completes");

    let record = root_b.load_record().expect("record");
    let slot = record.rollover.expect("transition slot");
    assert_eq!(
        approvals_b.followed.lock().as_slice(),
        &[(vehicle.to_string(), slot.successor_session.clone())]
    );
    let brief_text = slot.brief.as_deref().unwrap_or_default();
    assert!(
        brief_text.contains(odin_omp::live::rollover::ROLLOVER_CARRY_INSTRUCTION),
        "{brief_text}"
    );
    let json_text = &brief_text[brief_text.find('{').expect("brief json")..];
    let brief: serde_json::Value = serde_json::from_str(json_text).expect("brief json");
    let children = brief["continuity_notes"]["delegated_children"].clone();
    let array = children.as_array().expect("children is an array");
    assert_eq!(array.len(), 1, "exactly the delegated child: {children}");
    assert_eq!(array[0]["session"], child.to_string());
    // (The fake plane reports every session under its one fixture seat.)
    assert!(array[0]["seat"].is_string(), "the child's seat is carried");
    assert_eq!(
        array[0]["answer"], "Digest delivered: 17 new flu-dyn papers, none on RDEs.",
        "the child's answer reaches the successor"
    );
}

#[tokio::test(start_paused = true)]
async fn a_dm_during_a_pending_reload_answers_on_the_current_vehicle() {
    let (dir, plane, _egress, _approvals, _root) = harness().await;
    let authority = Arc::new(FakeAuthority {
        calls: Mutex::new(Vec::new()),
        bound: 1,
        current: 1,
        script: Mutex::new(BTreeMap::new()),
        deferred: std::sync::atomic::AtomicBool::new(false),
        troubles: Mutex::new(Vec::new()),
    });
    let root = root_in_authority(
        dir.path(),
        Arc::clone(&plane) as Arc<dyn ConversationPlane>,
        Arc::new(FakeEgress::new()),
        Arc::new(FakeApprovals::empty()),
        Arc::clone(&authority),
    );
    root.initialize().await.expect("initialize");
    let vehicle = root.load_record().expect("record").session_id;
    // A runtime publication advanced the pin; odind has not reloaded yet.
    authority.script.lock().insert(
        root.vehicle_command_id()
            .expect("vehicle command")
            .to_string(),
        EnsuredGeneration {
            bound: 1,
            current: 2,
            composition: None,
        },
    );
    authority.deferred.store(true, Ordering::SeqCst);
    let projection = root
        .execute(intent("during-reload"))
        .await
        .expect("the DM answers while the reload is pending");
    assert_eq!(projection["answer"], "A plain answer.");
    let record = root.load_record().expect("record");
    assert!(record.rollover.is_none(), "no successor was armed");
    assert_eq!(record.session_id, vehicle, "the same vehicle answered");
    // The reload happened: the next DM rolls to the fresh generation.
    authority.deferred.store(false, Ordering::SeqCst);
    root.execute(intent("after-reload"))
        .await
        .expect("the DM after the reload answers");
    assert_ne!(
        root.load_record().expect("record").session_id,
        vehicle,
        "the vehicle rolled once the reload was done"
    );
}

#[tokio::test(start_paused = true)]
async fn a_routine_publication_keeps_the_vehicle_and_a_seat_change_still_rolls() {
    let (dir, plane, _egress, _approvals, _root) = harness().await;
    let authority = Arc::new(FakeAuthority {
        calls: Mutex::new(Vec::new()),
        bound: 1,
        current: 1,
        script: Mutex::new(BTreeMap::new()),
        deferred: std::sync::atomic::AtomicBool::new(false),
        troubles: Mutex::new(Vec::new()),
    });
    let root = root_in_authority(
        dir.path(),
        Arc::clone(&plane) as Arc<dyn ConversationPlane>,
        Arc::new(FakeEgress::new()),
        Arc::new(FakeApprovals::empty()),
        Arc::clone(&authority),
    );
    root.initialize().await.expect("initialize");
    let vehicle = root.load_record().expect("record").session_id;
    let command = root
        .vehicle_command_id()
        .expect("vehicle command")
        .to_string();
    let composed = odin_registry::CompositionDigest::from_bytes([1; 32]);
    // A routine publication: revision 2, the same composition.
    authority.script.lock().insert(
        command.clone(),
        EnsuredGeneration {
            bound: 1,
            current: 2,
            composition: Some(crate::conversation::CompositionPair {
                bound: composed,
                current: composed,
            }),
        },
    );
    let projection = root
        .execute(intent("after-routine"))
        .await
        .expect("the DM after a routine publication answers");
    assert_eq!(projection["answer"], "A plain answer.");
    let record = root.load_record().expect("record");
    assert!(record.rollover.is_none(), "no successor was armed");
    assert_eq!(record.session_id, vehicle, "the same vehicle answered");
    assert!(
        plane.retirements.lock().is_empty(),
        "nothing was retired by a routine publication"
    );
    // A seat-tool change: revision 3 composes her differently and rolls.
    authority.script.lock().insert(
        command,
        EnsuredGeneration {
            bound: 1,
            current: 3,
            composition: Some(crate::conversation::CompositionPair {
                bound: composed,
                current: odin_registry::CompositionDigest::from_bytes([2; 32]),
            }),
        },
    );
    root.execute(intent("after-seat-change"))
        .await
        .expect("the DM after a seat change answers");
    assert_ne!(
        root.load_record().expect("record").session_id,
        vehicle,
        "a composition change rolls the vehicle"
    );
}

#[tokio::test(start_paused = true)]
async fn a_context_window_refusal_rolls_to_a_successor_and_answers() {
    let (_dir, plane, _egress, _approvals, root) = harness().await;
    root.initialize().await.expect("initialize");
    let vehicle = root.load_record().expect("record").session_id;
    plane.refuse_context.store(1, Ordering::SeqCst);
    let projection = root
        .execute(intent("too-big"))
        .await
        .expect("the DM answers on the successor");
    assert_eq!(projection["answer"], "A plain answer.");
    let record = root.load_record().expect("record");
    assert_ne!(record.session_id, vehicle, "the conversation rolled");
    assert_eq!(
        plane.retirements.lock().as_slice(),
        [vehicle.expect("vehicle")],
        "the refused vehicle was retired"
    );
}

/// A turn held behind the approval card for an email send.
async fn held_behind_card() -> (
    TempDir,
    Arc<FakePlane>,
    Arc<FakeEgress>,
    Arc<FakeApprovals>,
    Arc<ConversationRoot>,
) {
    let dir = scratch_dir();
    let plane = Arc::new(FakePlane::new(dir.path()).await);
    plane.auto_reply.store(false, Ordering::SeqCst);
    plane.pending_requests.lock().clear();
    let egress = Arc::new(FakeEgress::new());
    let approvals = Arc::new(FakeApprovals::empty());
    let root = root_in(
        dir.path(),
        Arc::clone(&plane) as Arc<dyn ConversationPlane>,
        egress.clone(),
        approvals.clone(),
    );
    root.initialize().await.expect("initialize");
    let session = root
        .current_vehicle_session()
        .await
        .expect("vehicle")
        .expect("session");
    approvals.request("approval:r3:email.send:held", session);
    let projection = root.execute(intent("held")).await.expect("settles waiting");
    assert_eq!(projection["waitingOnApproval"], true);
    (dir, plane, egress, approvals, root)
}

fn open_replies(dir: &std::path::Path) -> Vec<String> {
    crate::conversation::delivery::inspect(&state_ledger_path(dir))
        .expect("inspect")
        .as_array()
        .expect("rows")
        .iter()
        .filter(|row| row["phase"] == "open")
        .map(|row| row["key"].as_str().expect("key").to_owned())
        .collect()
}

/// An approval that expires unanswered closes the reply it held, and
/// the owner hears in one line that the request lapsed and nothing was done.
#[tokio::test(start_paused = true)]
async fn an_expired_approval_closes_its_held_reply_and_says_it_lapsed() {
    let (dir, _plane, egress, approvals, root) = held_behind_card().await;
    assert_eq!(open_replies(dir.path()), ["held"], "the reply is held");
    let before = egress.sends();
    approvals.expire("approval:r3:email.send:held");
    root.settle_held_replies().await.expect("settled");
    let said = &egress.sends()[before.len()..];
    assert_eq!(said.len(), 1, "{said:?}");
    assert!(
        said[0].contains("send an email") && said[0].contains("lapsed"),
        "{said:?}"
    );
    assert!(open_replies(dir.path()).is_empty(), "no reply stays open");
    root.settle_held_replies().await.expect("settled again");
    assert_eq!(egress.sends().len(), before.len() + 1, "said once");
    assert!(root.load_record().expect("record").held.is_empty());
}
