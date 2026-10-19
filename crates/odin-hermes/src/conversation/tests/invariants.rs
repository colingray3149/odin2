//! Conversation identity, replay, delivery causality, wake and terminal-state invariants.

use super::*;
use crate::conversation::identity::{
    bounded_command, conversation_root_identity, successor_vehicle_command,
};
use crate::correlation::identity_from_key;
use crate::ingress::{INTENT_COMMAND_PREFIX, INTENT_ISSUER};
use crate::runtime::{ApprovedIntentRoute as _, OwnerDecisionRoute as _};
use odin_domain::huginn::PermissionDecision;
use odin_ledger::command::{CommandOutcome, CommandSpec, CommandTerminalStatus, RecordCommand};

/// Closing admission is synchronous even while another owner holds the registry.
#[tokio::test(start_paused = true)]
async fn close_background_refuses_new_wakes_without_waiting_for_registry() {
    let (_dir, _plane, _egress, _approvals, root) = harness().await;
    let background = root.background.lock().await;
    root.close_background();
    let started = tokio::time::Instant::now();
    tokio::time::timeout(
        StdDuration::from_secs(1),
        root.spawn_wake_task(PendingWake {
            command_id: "closed-wake".to_owned(),
            owner_keys: Vec::new(),
            kind: WakeKind::LiveContinuation,
            approved: true,
            label: "closed admission".to_owned(),
            session_id: String::new(),
            decision_cursor: 0,
            approval_id: None,
            prompt: None,
            reply: None,
            completion: None,
            owner_note: None,
            rolled: false,
        }),
    )
    .await
    .expect("closed admission must not wait for the background mutex");
    assert_eq!(tokio::time::Instant::now(), started);
    assert!(background.is_empty(), "no wake was admitted after close");
}

/// A registry owner cannot turn the daemon's bounded drain into an unbounded wait.
#[tokio::test(start_paused = true)]
async fn join_background_until_bounds_registry_lock_and_reports_incomplete() {
    let (_dir, _plane, _egress, _approvals, root) = harness().await;
    let (release, released) = tokio::sync::oneshot::channel::<()>();
    let mut background = root.background.lock().await;
    background.insert(
        "held-wake".to_owned(),
        tokio::spawn(async move {
            let _ = released.await;
        }),
    );
    let deadline = tokio::time::Instant::now() + StdDuration::from_secs(2);
    let outcome = tokio::time::timeout_at(
        deadline + StdDuration::from_secs(1),
        root.join_background_until(deadline),
    )
    .await
    .expect("the registry lock wait must obey the shared deadline");
    let finished = tokio::time::Instant::now();
    // The timed-out drain did not acquire ownership: release and join the
    // fixture ourselves rather than detaching the task with its registry.
    let handle = background.remove("held-wake").expect("fixture still owned");
    drop(background);
    release.send(()).expect("fixture was not cancelled");
    handle.await.expect("fixture joined");
    assert_eq!(outcome, (0, 1));
    assert_eq!(finished, deadline);
    assert!(root.closing.load(Ordering::Acquire));
}

/// An earlier shutdown phase may consume all grace; a later drain gets none anew.
#[tokio::test(start_paused = true)]
async fn join_background_until_expired_shared_deadline_grants_no_fresh_grace() {
    let (_dir, _plane, _egress, _approvals, root) = harness().await;
    let (owned, dropped) = tokio::sync::oneshot::channel::<()>();
    root.background.lock().await.insert(
        "expired-wake".to_owned(),
        tokio::spawn(async move {
            let _owned = owned;
            std::future::pending::<()>().await;
        }),
    );
    let deadline = tokio::time::Instant::now() + StdDuration::from_secs(2);
    tokio::time::advance(StdDuration::from_secs(3)).await;
    let started = tokio::time::Instant::now();
    let outcome = tokio::time::timeout(
        StdDuration::from_secs(1),
        root.join_background_until(deadline),
    )
    .await
    .expect("an expired shared deadline must not start a fresh grace period");
    let finished = tokio::time::Instant::now();
    // Observe destruction after abort before releasing the fixture's owners.
    assert!(dropped.await.is_err(), "the straggler was cancelled");
    assert_eq!(outcome, (0, 1));
    assert_eq!(finished, started);
    assert!(root.background.lock().await.is_empty());
}

/// Bounded, domain-separated identities: separator characters cannot
/// collide, a ~100-char real approval id still yields a wake command
/// below the wire ceiling, and the digest is deterministic.
#[test]
fn identities_are_bounded_collision_free_and_deterministic() {
    let collision_a = conversation_root_identity("a:b", "c");
    let collision_b = conversation_root_identity("a", "b:c");
    assert_ne!(collision_a, collision_b);
    assert_eq!(collision_a, conversation_root_identity("a:b", "c"));
    let long_approval = format!("approval:r3-{}", "x".repeat(90));
    let wake =
        bounded_command("conversation-wake", &[&long_approval, "approve"]).expect("wake identity");
    assert!(wake.to_string().len() < 128);
    let long_key = "k".repeat(120);
    let intent_id = bounded_command("intent", &[&long_key]).expect("intent identity");
    assert!(intent_id.to_string().len() < 128);
    assert_eq!(
        bounded_command("intent", &[&long_key]).expect("intent identity"),
        intent_id
    );
}

/// Startup opens the vehicle headless IDLE and persists the durable
/// identity BEFORE any prompt; a fresh daemon over the same state
/// re-derives the SAME root and vehicle.
#[tokio::test(start_paused = true)]
async fn initialize_persists_identity_before_any_prompt() {
    let dir = tempdir().expect("tempdir");
    let plane = Arc::new(FakePlane::new(dir.path()).await);
    let root = root_in(
        dir.path(),
        Arc::clone(&plane) as Arc<dyn ConversationPlane>,
        Arc::new(FakeEgress::new()),
        Arc::new(FakeApprovals::empty()),
    );
    root.initialize().await.expect("initialize");
    assert_eq!(plane.opens.lock().len(), 1, "one headless open");
    assert!(plane.commands.lock().is_empty(), "no prompt rode the open");
    let record = std::fs::read(dir.path().join("conversations/gateway/root.json"))
        .expect("record persisted");
    let record: ConversationRecord = serde_json::from_slice(&record).expect("record parses");
    assert_eq!(record.seat, SEAT);
    assert_eq!(record.project, PROJECT);
    assert!(record.session_id.is_some());

    // Restart: the fresh plane discovers the durable manifest parked.
    let plane_b = Arc::new(FakePlane::new(dir.path()).await);
    let root_b = root_in(
        dir.path(),
        Arc::clone(&plane_b) as Arc<dyn ConversationPlane>,
        Arc::new(FakeEgress::new()),
        Arc::new(FakeApprovals::empty()),
    );
    assert_eq!(root_b.conversation_id(), root.conversation_id());
    let vehicle = root_b
        .current_vehicle_session()
        .await
        .expect("vehicle readable")
        .expect("vehicle recorded before any prompt");
    assert!(
        plane_b
            .session_manifest_present(vehicle)
            .await
            .expect("manifest lookup"),
        "the durable manifest exists"
    );
}

/// One intent rides the one vehicle; a replayed idempotency key
/// returns the recorded projection verbatim with no duplicate prompt
/// and no duplicate reply.
#[tokio::test(start_paused = true)]
async fn replay_returns_recorded_projection_without_duplicate_prompt() {
    let (dir, plane, egress, approvals, root) = harness().await;
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
    let _ = (dir, approvals);
}

/// The Hermes runtime the daemon composes over `route`, its schedule under
/// `dir/hermes`.
fn schedule_runtime(
    dir: &std::path::Path,
    route: &Arc<ConversationRoot>,
) -> Arc<crate::runtime::HermesRuntime> {
    let runtime = crate::runtime::HermesRuntime::open(
        crate::config::HermesSettings::new(dir.join("hermes"), None, None, None, vec![])
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
    let rows = serde_json::json!([{
        "id": "rcycle", "kind": "wake", "text": "check the pod",
        "fireAtMs": now - 10 * 60_000, "createdAtMs": now - 20 * 60_000,
        "status": "pending", "everyMinutes": 1, "repeatsLeft": 1,
    }]);
    std::fs::write(state.join("schedule.json"), rows.to_string()).expect("seed");
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

/// A durable assistant-history event wakes answer projection immediately;
/// the configured 50 ms poll cadence is deliberately longer than the
/// scripted model delay, so this fails if answer detection returns to polling.
#[tokio::test(start_paused = true)]
async fn durable_history_wakes_first_token_and_reply_without_poll_latency() {
    let (_dir, plane, egress, _approvals, root) = harness().await;
    plane.auto_reply.store(false, Ordering::SeqCst);
    plane.pending_requests.lock().clear();
    root.initialize().await.expect("initialize");

    let admitted_at = tokio::time::Instant::now();
    let execution = {
        let root = Arc::clone(&root);
        tokio::spawn(async move { root.execute(intent("latency")).await })
    };
    while plane.prompt_count("command:intent:") == 0 {
        tokio::task::yield_now().await;
    }
    tokio::time::sleep(StdDuration::from_millis(25)).await;
    let first_model_token = admitted_at.elapsed();
    let session = root
        .current_vehicle_session()
        .await
        .expect("vehicle readable")
        .expect("vehicle exists");
    plane
        .push_event(
            &session,
            LiveEventBody::AssistantMessage(text_message("Fast answer.")),
        )
        .await;
    plane
        .push_state_change(&session, LiveSessionState::Idle)
        .await;

    let projection = execution
        .await
        .expect("execution task")
        .expect("answer settles");
    let reply_sent = admitted_at.elapsed();
    assert_eq!(projection["answer"], "Fast answer.");
    assert_eq!(projection["replySent"], true);
    assert_eq!(egress.sends(), vec!["Fast answer."]);
    eprintln!(
        "history-feed DM->first-model-token={first_model_token:?} \
         DM->reply-sent={reply_sent:?}"
    );
    assert_eq!(first_model_token, StdDuration::from_millis(25));
    assert!(
        reply_sent < StdDuration::from_millis(50),
        "reply must not wait for the 50 ms test poll cadence: {reply_sent:?}"
    );
}

/// After a restart the recorded vehicle that retired as failed
/// recovers IN PLACE through the real reclaim (same session id, epoch
/// bump, no second open), and the next intent rides it.
#[tokio::test(start_paused = true)]
async fn restart_recovers_the_failed_vehicle_in_place() {
    let dir = tempdir().expect("tempdir");
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
    let (dir, plane, egress, approvals, root) = harness().await;
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
        idempotency_key: "k2".to_owned(),
        content: "intent k2".to_owned(),
        command_id: k2_command.to_string(),
        session_id: session.to_string(),
        kind: InFlightKind::Prompt,
        expected_epoch: 1,
        event_cursor: head,
        phase: InFlightPhase::Sent,
        clock: None,
        asks: Vec::new(),
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
    let _ = (dir, egress, approvals);
}

/// A crash before send with a STALE epoch: the journal proves the
/// command was never admitted, so the SAME id refreshes its epoch to
/// the live target and is admitted exactly once.
#[tokio::test(start_paused = true)]
async fn crash_before_send_refreshes_epoch_for_a_never_admitted_command() {
    let (dir, plane, egress, approvals, root) = harness().await;
    root.initialize().await.expect("initialize");
    let session = root
        .current_vehicle_session()
        .await
        .expect("vehicle")
        .expect("vehicle");
    // The vehicle recovered once in between: the epoch moved on.
    plane.recover_session(session).await.expect("epoch bump");

    let mut record = root.load_record().expect("record");
    let k3_command = bounded_command("intent", &["k3"]).expect("command id");
    record.in_flight = Some(InFlightPrompt {
        idempotency_key: "k3".to_owned(),
        content: "intent k3".to_owned(),
        command_id: k3_command.to_string(),
        session_id: session.to_string(),
        kind: InFlightKind::Prompt,
        expected_epoch: 1,
        event_cursor: 0,
        phase: InFlightPhase::Prepared,
        clock: None,
        asks: Vec::new(),
    });
    root.store_record(&mut record).expect("record stored");

    let projection = root.execute(intent("k3")).await.expect("settles once");
    assert_eq!(projection["answer"], "A plain answer.");
    let entries = plane.command_entries(&k3_command.to_string());
    assert_eq!(entries.len(), 1, "admitted exactly once");
    assert_eq!(entries[0], "prompt", "no replayed duplicate");
    assert_eq!(egress.sends().len(), 1);
    let _ = (dir, approvals);
}

#[tokio::test(start_paused = true)]
async fn a_carried_turn_never_delivers_the_brief_turns_reply() {
    let (dir, plane, egress, approvals, root) = harness().await;
    root.initialize().await.expect("initialize");
    let session = root
        .current_vehicle_session()
        .await
        .expect("vehicle")
        .expect("vehicle");
    let mut record = root.load_record().expect("record");
    let carried = bounded_command("intent", &["carried"]).expect("command id");
    record.in_flight = Some(InFlightPrompt {
        idempotency_key: "carried".to_owned(),
        content: "intent carried".to_owned(),
        command_id: carried.to_string(),
        session_id: session.to_string(),
        kind: InFlightKind::Prompt,
        expected_epoch: 1,
        event_cursor: 0,
        phase: InFlightPhase::Prepared,
        clock: None,
        asks: Vec::new(),
    });
    root.store_record(&mut record).expect("record stored");
    // The brief turn settles on the session before the carried turn runs.
    plane
        .push_event(
            &session,
            LiveEventBody::AssistantMessage(text_message("ready")),
        )
        .await;
    plane
        .push_state_change(&session, LiveSessionState::Idle)
        .await;

    let projection = root.execute(intent("carried")).await.expect("settles");
    assert_eq!(projection["answer"], "A plain answer.");
    assert_eq!(egress.sends(), vec!["A plain answer."]);
    let _ = (dir, approvals);
}

/// A question whose delivery FAILED never becomes a decision
/// receipt: the intent answer-bounds out, and a later yes refuses
/// with one plain sentence and authorizes nothing.
#[tokio::test(start_paused = true)]
async fn failed_delivery_denies_the_decision() {
    let (dir, plane, egress, approvals, root) = harness().await;
    egress.fail.store(true, Ordering::SeqCst);
    plane.auto_reply.store(false, Ordering::SeqCst);
    root.initialize().await.expect("initialize");
    let failure = root.execute(intent("gated")).await.expect_err("bounds out");
    assert_eq!(failure, IntentFailure::AnswerTimeout);
    egress.fail.store(false, Ordering::SeqCst);
    root.try_decision(owner_message("yes"))
        .await
        .expect("decision handled")
        .expect("a bare yes to an undelivered question is refused");
    assert_eq!(plane.decide_count(), 0, "nothing was authorized");
    let record = root.load_record().expect("record");
    assert!(
        record
            .questions
            .iter()
            .any(|question| question.delivered_message_id.is_none()),
        "the undelivered receipt stays, so the question is asked again"
    );
    let _ = (dir, approvals);
}

#[tokio::test(start_paused = true)]
async fn a_delivered_question_cannot_authorize_a_reused_id_after_recovery() {
    let (_dir, plane, _egress, _approvals, root) = harness().await;
    plane.auto_reply.store(false, Ordering::SeqCst);
    root.initialize().await.unwrap();
    root.execute(intent("gated")).await.unwrap();
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
    root.try_decision(owner_message("yes")).await.unwrap();
    assert_eq!(plane.decide_count(), 0);
}

#[tokio::test(start_paused = true)]
async fn a_reply_predating_the_actual_native_question_cannot_authorize_it() {
    let (_dir, plane, _egress, _approvals, root) = harness().await;
    plane.auto_reply.store(false, Ordering::SeqCst);
    root.initialize().await.unwrap();
    root.execute(intent("gated")).await.unwrap();
    let mut reply = owner_message("yes");
    reply.message_id = "1".to_owned();
    root.try_decision(reply).await.unwrap();
    assert_eq!(plane.decide_count(), 0);
}

#[tokio::test(start_paused = true)]
async fn a_native_decision_admission_is_not_acknowledged_as_resolution() {
    let (_dir, plane, _egress, _approvals, root) = harness().await;
    plane.auto_reply.store(false, Ordering::SeqCst);
    plane.resolve_permissions.store(false, Ordering::SeqCst);
    root.initialize().await.unwrap();
    root.execute(intent("gated")).await.unwrap();
    assert!(root.try_decision(owner_message("yes")).await.is_err());
    let mut retry = owner_message("yes");
    retry.message_id = (10_001_u64 << 22).to_string();
    assert!(root.try_decision(retry).await.is_err());
    assert_eq!(
        plane
            .commands
            .lock()
            .iter()
            .filter(|(_, kind)| kind == "decide_permission")
            .count(),
        1,
        "the durable journal admits one decision; later sends only replay it"
    );
}

/// A yes arriving after the delivered question already settled (the
/// unseen-replacement shape) refuses; nothing is authorized.
#[tokio::test(start_paused = true)]
async fn unseen_replacement_denies_the_decision() {
    let (dir, plane, egress, approvals, root) = harness().await;
    plane.auto_reply.store(false, Ordering::SeqCst);
    root.initialize().await.expect("initialize");
    let projection = root
        .execute(intent("gated"))
        .await
        .expect("settles waiting");
    assert_eq!(projection["waitingOnApproval"], true);
    let session = root
        .current_vehicle_session()
        .await
        .expect("vehicle")
        .expect("vehicle");
    plane
        .push_event(
            &session,
            LiveEventBody::PermissionResolved(PermissionResolution {
                request_id: PermissionRequestId::new("perm-a").expect("request id"),
                command_id: bounded_command("permission", &["perm-a"]).expect("command id"),
                decision: PermissionDecision::Deny,
            }),
        )
        .await;
    plane.set_state(&session, LiveSessionState::Idle);
    root.try_decision(owner_message("yes"))
        .await
        .expect("decision handled")
        .expect("a yes to a settled question is refused");
    assert_eq!(plane.decide_count(), 0, "nothing was authorized");
    let _ = (dir, egress, approvals);
}

/// A delivered live permission decides once; the wake is
/// OBSERVE-ONLY — it never injects a prompt, so an operation that
/// already continued can never be re-issued — and the continuation
/// answer reaches the owner.
#[tokio::test(start_paused = true)]
async fn live_decision_wake_is_observe_only() {
    let (dir, plane, egress, approvals, root) = harness().await;
    plane.auto_reply.store(false, Ordering::SeqCst);
    *plane.answer.lock() = "Done, the message is on its way.".to_owned();
    root.initialize().await.expect("initialize");
    let projection = root
        .execute(intent("gated"))
        .await
        .expect("settles waiting");
    assert_eq!(projection["waitingOnApproval"], true);
    // The gate resolves and the vehicle continues on its own.
    plane.auto_reply.store(true, Ordering::SeqCst);
    plane.pending_requests.lock().clear();
    root.try_decision(owner_message("yes"))
        .await
        .expect("decision handled")
        .expect("consumed as a decision");
    assert_eq!(plane.decide_count(), 1);
    root.join_background(StdDuration::from_secs(30)).await;
    assert!(
        egress
            .sends()
            .iter()
            .any(|sent| sent.contains("on its way")),
        "the continuation answer reached the owner"
    );
    assert_eq!(
        plane
            .command_entries("")
            .iter()
            .filter(|kind| matches!(kind.as_str(), "prompt" | "follow_up"))
            .count(),
        1,
        "only the original intent may prompt the child"
    );
    let _ = (dir, approvals);
}

#[tokio::test(start_paused = true)]
async fn an_undecided_reply_re_asks_with_detail_and_a_denial_carries_its_instruction() {
    let dir = tempdir().expect("tempdir");
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
    let re_ask = root
        .try_decision(owner_message("no worries"))
        .await
        .expect("handled")
        .expect("re-asked");
    assert!(re_ask.contains("colin@example.com"), "{re_ask}");
    assert_eq!(approvals.decide_count(), 0, "no worries never decides");
    root.try_decision(owner_message("no — send it to my caltech address instead"))
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
        Some("send it to my caltech address instead")
    );
    let _ = (dir, egress);
}

#[tokio::test(start_paused = true)]
async fn a_question_decided_on_another_surface_resumes_the_conversation() {
    let dir = tempdir().expect("tempdir");
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
    assert!(
        egress.sends().iter().any(|sent| sent == "Sent it."),
        "the continuation answered: {:?}",
        egress.sends()
    );
    let _ = dir;
}

/// A cancelled pre-commit intake leaves its question open, not a durable
/// continuation that a later rollover could rebind without a running owner.
#[tokio::test(start_paused = true)]
async fn a_cancelled_external_decision_retires_its_uncommitted_wake() {
    let (_dir, plane, egress, approvals, root) = harness().await;
    root.initialize().await.expect("initialize");
    let session = root
        .current_vehicle_session()
        .await
        .expect("vehicle")
        .expect("session");
    let approval = "approval:r3:email.send:cancelled-intake";
    approvals.request(approval, session);
    let delivered = egress.sends();
    let (entered, observed) = tokio::sync::oneshot::channel();
    let mut intake = Box::pin(root.decide_external(approval, true, async move {
        entered.send(()).expect("intake observer");
        std::future::pending::<()>().await;
    }));
    tokio::select! {
        result = &mut intake => panic!("the uncommitted intake finished: {result:?}"),
        result = observed => result.expect("the decision future was entered"),
    }
    let record = root.load_record().expect("owned pre-commit plan");
    let wake = record
        .wakes
        .iter()
        .find(|wake| wake.approval_id.as_deref() == Some(approval))
        .expect("the continuation is owned before the decision");
    let command = wake.command_id.clone();
    drop(intake);
    root.join_background(StdDuration::from_secs(30)).await;
    assert!(root.load_record().expect("settled record").wakes.is_empty());
    assert_eq!(approvals.decide_count(), 0);
    assert_eq!(
        approvals.approval_status(approval).await.expect("approval"),
        Some(odin_domain::ApprovalStatus::Requested)
    );
    assert_eq!(
        plane.prompt_count(&command),
        0,
        "no model continuation before a decision"
    );
    assert_eq!(egress.sends(), delivered, "no invented answer");
}

/// A DM queued behind a Requested status read wins the FIFO conversation
/// lock before the old tracker can settle. Its committed plan must survive.
#[tokio::test(start_paused = true)]
async fn a_dm_decision_outlives_the_previous_requested_tracker() {
    let (_dir, plane, egress, approvals, root) = harness().await;
    plane.pending_requests.lock().clear();
    *plane.answer.lock() = "Sent after the DM decision.".to_owned();
    root.initialize().await.expect("initialize");
    let session = root
        .current_vehicle_session()
        .await
        .expect("vehicle")
        .expect("session");
    let approval = "approval:r3:email.send:mixed-surfaces";
    approvals.request(approval, session);
    let barrier = Arc::new(tokio::sync::Barrier::new(2));
    *approvals.status_barrier.lock() = Some(Arc::clone(&barrier));
    let refused = root
        .decide_external(approval, true, async {
            Err::<(), _>("refused before commit")
        })
        .await
        .expect("continuation owned");
    assert!(refused.is_err());
    barrier.wait().await;
    let record = root.load_record().expect("old plan");
    let command = record
        .wakes
        .iter()
        .find(|wake| wake.approval_id.as_deref() == Some(approval))
        .expect("the old tracker is still settling")
        .command_id
        .clone();

    // Poll exactly once to enqueue the real DM route behind the held lock.
    let mut dm = Box::pin(root.try_decision(owner_message("yes")));
    tokio::select! {
        biased;
        result = &mut dm => panic!("DM passed a held conversation lock: {result:?}"),
        () = std::future::ready(()) => {}
    }
    barrier.wait().await;
    dm.await
        .expect("the DM route succeeds")
        .expect("the DM commits its decision");
    root.join_background(StdDuration::from_secs(30)).await;
    assert_eq!(approvals.decide_count(), 1);
    assert_eq!(
        plane.prompt_count(&command),
        1,
        "the committed DM continuation was lost"
    );
    assert_eq!(
        egress
            .sends()
            .iter()
            .filter(|sent| sent.as_str() == "Sent after the DM decision.")
            .count(),
        1,
        "actual owner deliveries: {:?}",
        egress.sends()
    );
    assert!(root.load_record().expect("settled record").wakes.is_empty());
}

/// A rollover queued behind the Requested read must not rename an unused
/// plan before its old tracker drops it by the predecessor's command id.
#[tokio::test(start_paused = true)]
async fn a_rollover_cannot_rebind_a_refused_decisions_retiring_wake() {
    let (_dir, plane, _egress, approvals, root) = harness().await;
    plane.pending_requests.lock().clear();
    root.initialize().await.expect("initialize");
    let predecessor = root
        .current_vehicle_session()
        .await
        .expect("vehicle")
        .expect("session");
    let approval = "approval:r3:email.send:refused-before-rollover";
    approvals.request(approval, predecessor);
    let barrier = Arc::new(tokio::sync::Barrier::new(2));
    *approvals.status_barrier.lock() = Some(Arc::clone(&barrier));
    let refused = root
        .decide_external(approval, true, async {
            Err::<(), _>("refused before commit")
        })
        .await
        .expect("continuation owned");
    assert!(refused.is_err());
    barrier.wait().await;
    let record = root.load_record().expect("old plan");
    let command = record
        .wakes
        .iter()
        .find(|wake| wake.approval_id.as_deref() == Some(approval))
        .expect("the Requested tracker is settling")
        .command_id
        .clone();
    let mut rollover = Box::pin(async {
        let _guard = root.lock.lock().await;
        let mut record = root.load_record().expect("predecessor record");
        root.begin_successor(&mut record, None, None).await
    });
    tokio::select! {
        biased;
        result = &mut rollover => panic!("rollover passed a held conversation lock: {result:?}"),
        () = std::future::ready(()) => {}
    }
    barrier.wait().await;
    let successor = rollover.await.expect("the actual successor opens");
    assert_ne!(successor, predecessor);
    root.join_background(StdDuration::from_secs(30)).await;
    let settled = root.load_record().expect("successor record");
    assert!(
        !settled
            .wakes
            .iter()
            .any(|wake| wake.approval_id.as_deref() == Some(approval)),
        "rollover rebound the refused wake without an owner"
    );
    assert_eq!(approvals.decide_count(), 0);
    assert_eq!(plane.prompt_count(&command), 0);
}

/// Ambiguous replies leave both questions open; naming one decides only that question.
#[tokio::test(start_paused = true)]
async fn a_reply_naming_one_of_two_questions_decides_that_one() {
    let (dir, plane, egress, approvals, root) = harness().await;
    root.initialize().await.expect("initialize");
    let session = root
        .current_vehicle_session()
        .await
        .expect("vehicle")
        .expect("session");
    approvals.request_labeled(
        "approval:r3:calendar.propose:one",
        session,
        "calendar.propose",
        "Book this calendar event",
        "add “standup” at 2026-10-04 09:00 on the personal calendar",
    );
    approvals.request_labeled(
        "approval:r3:email.send:two",
        session,
        "email.send",
        "Send this email draft",
        "“weekly notes” to colin@example.com",
    );
    let ambiguous = root
        .try_decision(owner_message("no"))
        .await
        .expect("handled")
        .expect("asks which");
    assert!(ambiguous.starts_with("More than one thing"), "{ambiguous}");
    let both = root
        .try_decision(owner_message("yes to the calendar event and the email"))
        .await
        .expect("handled")
        .expect("asks which");
    assert!(both.starts_with("More than one thing"), "{both}");
    assert_eq!(approvals.decide_count(), 0);

    root.try_decision(owner_message("no to the calendar one"))
        .await
        .expect("handled")
        .expect("decided");
    assert_eq!(
        approvals.decisions.lock().clone(),
        vec![(
            "approval:r3:calendar.propose:one".to_owned(),
            OwnerDecision::Deny
        )]
    );
    assert!(approvals
        .pending
        .lock()
        .iter()
        .any(|pending| pending.approval_id.as_str() == "approval:r3:email.send:two"));
    let _ = (dir, plane, egress);
}

/// "no to both" declines every open question; a yes never covers several.
#[tokio::test(start_paused = true)]
async fn no_to_both_declines_every_open_question() {
    let (dir, plane, egress, approvals, root) = harness().await;
    root.initialize().await.expect("initialize");
    let session = root
        .current_vehicle_session()
        .await
        .expect("vehicle")
        .expect("session");
    for (id, capability, label) in [
        (
            "approval:r3:calendar.propose:a",
            "calendar.propose",
            "Book this calendar event",
        ),
        (
            "approval:r3:email.send:b",
            "email.send",
            "Send this email draft",
        ),
    ] {
        approvals.request_labeled(id, session, capability, label, "detail");
    }
    let yes_all = root
        .try_decision(owner_message("yes to both"))
        .await
        .expect("handled")
        .expect("asks which");
    assert!(yes_all.starts_with("More than one thing"), "{yes_all}");
    assert_eq!(approvals.decide_count(), 0);
    root.try_decision(owner_message("no to both"))
        .await
        .expect("handled")
        .expect("declined");
    let decided = approvals.decisions.lock().clone();
    assert_eq!(decided.len(), 2, "{decided:?}");
    assert!(decided
        .iter()
        .all(|(_, decision)| *decision == OwnerDecision::Deny));
    let record = root.load_record().expect("record");
    assert_eq!(
        record.wakes.iter().filter(|wake| !wake.approved).count(),
        2,
        "each declined question tells its turn"
    );
    let _ = (dir, plane, egress);
}

/// A settled kernel decision's continuation uses the same durable
/// vehicle and command identity when its wake plan is resumed.
#[tokio::test(start_paused = true)]
async fn kernel_decision_continuation_survives_durable_wake_resume() {
    let long_approval = format!("approval:r3-{}", "x".repeat(90));
    let dir = tempdir().expect("tempdir");
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

/// A truthfully closed vehicle refuses everywhere: no reclaim, no
/// commands, no silent replacement, and startup propagates the
/// refusal instead of re-arming.
#[tokio::test(start_paused = true)]
async fn terminal_closed_vehicle_refuses_everything() {
    let (dir, plane, egress, approvals, root) = harness().await;
    root.initialize().await.expect("initialize");
    let session = root
        .current_vehicle_session()
        .await
        .expect("vehicle")
        .expect("vehicle");
    plane.set_state(&session, LiveSessionState::Ended);
    let failure = root
        .execute(intent("after-close"))
        .await
        .expect_err("refused");
    assert_eq!(failure, IntentFailure::ConversationClosed);
    assert!(plane.recoveries.lock().is_empty(), "never reclaimed");
    assert_eq!(plane.opens.lock().len(), 1, "never replaced");
    assert!(
        plane.commands.lock().is_empty(),
        "no prompt rode a closed vehicle"
    );
    assert!(
        root.initialize().await.is_err(),
        "startup propagates the terminal refusal"
    );
    assert_eq!(plane.opens.lock().len(), 1, "no silent re-arm");
    let _ = (dir, egress, approvals);
}

/// Two delivered, still-open questions require clarification: a bare
/// yes decides neither.
#[tokio::test(start_paused = true)]
async fn multiple_pending_questions_require_clarification() {
    let (dir, plane, egress, approvals, root) = harness().await;
    plane.auto_reply.store(false, Ordering::SeqCst);
    *plane.pending_requests.lock() = vec!["perm-a".to_owned(), "perm-b".to_owned()];
    root.initialize().await.expect("initialize");
    let projection = root
        .execute(intent("gated"))
        .await
        .expect("settles waiting");
    assert_eq!(projection["waitingOnApproval"], true);
    root.try_decision(owner_message("yes"))
        .await
        .expect("decision handled")
        .expect("consumed as ambiguity");
    assert_eq!(plane.decide_count(), 0);
    let _ = (dir, egress, approvals);
}

/// A refused reclaim preserves the plane's typed refusal through the
/// shared failure boundary — exact session, the epoch the listing
/// actually observed, the recovery step, and the source error — to
/// what the daemon logs and settles, while the owner's sentence stays
/// generic; a truthfully ended session still refuses ConversationClosed.
#[tokio::test(start_paused = true)]
async fn failed_recovery_preserves_the_typed_plane_refusal() {
    let dir = tempdir().expect("tempdir");
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
    // The fresh daemon finds the session FAILED; the plane refuses the
    // reclaim with a typed bridge failure.
    let plane_b = Arc::new(FakePlane::new(dir.path()).await);
    let session = plane_b
        .seed(&vehicle_command, LiveSessionState::Failed, false)
        .await;
    let injected = LiveError::Unavailable {
        code: "bridge_launch_refused".to_owned(),
    };
    *plane_b.reclaim_failure.lock() = Some(injected.clone());
    let root_b = root_in(
        dir.path(),
        Arc::clone(&plane_b) as Arc<dyn ConversationPlane>,
        Arc::new(FakeEgress::new()),
        Arc::new(FakeApprovals::empty()),
    );
    let failure = root_b
        .execute(intent("after-restart"))
        .await
        .expect_err("the refused reclaim surfaces typed");
    // The daemon diagnostic names the cause and the vehicle.
    let diagnostic = failure.to_string();
    assert!(
        diagnostic.contains("bridge_launch_refused")
            && diagnostic.contains(session.to_string().as_str()),
        "the daemon diagnostic must name the cause and session: {diagnostic}"
    );
    // The owner's rendered sentence stays free of the typed detail.
    let notice = crate::natural::natural_intent_failure(&failure);
    assert!(
        !notice.contains("bridge_launch_refused") && !notice.contains(&session.to_string()),
        "typed detail never reaches the owner sentence: {notice}"
    );
    let (reported, epoch, step, source) = match &failure {
        IntentFailure::VehicleRecoveryFailed {
            session,
            epoch,
            step,
            source,
        } => (session, *epoch, *step, source),
        other => panic!("expected the structured recovery failure, got: {other:?}"),
    };
    assert_eq!(reported, &session, "the exact vehicle session");
    // The epoch the Failed listing observed right before the reclaim.
    assert_eq!(epoch, Some(1), "the observed epoch, never an invention");
    assert_eq!(step, "vehicle reclaim");
    assert_eq!(source, &injected, "the typed source stays accessible");
    assert_eq!(
        plane_b.recoveries.lock().as_slice(),
        [session.to_string()],
        "the SAME session attempted once"
    );
    assert!(plane_b.opens.lock().is_empty(), "no replacement open");

    // The canonical terminal gate inside recover_vehicle refuses before
    // any reclaim surface is touched.
    *plane_b.reclaim_failure.lock() = None;
    plane_b.set_state(&session, LiveSessionState::Ended);
    let mut record = root_b.load_record().expect("record");
    let failure = root_b
        .recover_vehicle(&mut record, None)
        .await
        .expect_err("a truthfully ended session refuses typed");
    assert_eq!(failure, IntentFailure::ConversationClosed);
}

/// The wedge escape (GAP 5): a vehicle whose in-place recovery keeps
/// failing refused every turn forever. The first failures stay typed
/// refusals on the SAME session; at the bound the conversation rolls to a
/// governed successor and the turn runs there.
#[tokio::test(start_paused = true)]
async fn a_vehicle_whose_recovery_keeps_failing_rolls_to_a_successor() {
    let dir = tempdir().expect("tempdir");
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
    *plane_b.reclaim_failure.lock() = Some(LiveError::Unavailable {
        code: "bridge_launch_refused".to_owned(),
    });
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
    let _ = root_b.execute(intent("escape")).await;
    let record = root_b.load_record().expect("record");
    let current = record.session_id.clone().expect("vehicle");
    assert_ne!(
        current,
        session.to_string(),
        "the conversation left the wedge"
    );
    assert_eq!(
        plane_b.opens.lock().len(),
        1,
        "exactly one successor opened"
    );
    assert_eq!(record.recovery_failures, 0);
}

#[tokio::test(start_paused = true)]
async fn a_served_vehicle_whose_successors_never_start_reports_exhaustion_once() {
    use crate::conversation::rollover::MAX_ENDED_SUCCESSORS;
    use crate::conversation::SuccessorTrouble;
    let dir = tempdir().expect("tempdir");
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
    *plane.reclaim_failure.lock() = Some(LiveError::Unavailable {
        code: "bridge_launch_refused".to_owned(),
    });
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
    let mut last = None;
    for turn in 0..64 {
        let mut record = root.load_record().expect("record");
        if let Some(ended) = record
            .rollover
            .as_mut()
            .and_then(|slot| slot.ended.as_mut())
        {
            ended.last_at_unix_ms = 0;
            root.store_record(&mut record).expect("store");
        }
        let failure = root
            .execute(intent(&format!("turn-{turn}")))
            .await
            .expect_err("the vehicle never serves");
        let done = matches!(failure, IntentFailure::SuccessorStartExhausted { .. });
        last = Some(failure);
        if done {
            break;
        }
    }
    assert!(
        matches!(
            last,
            Some(IntentFailure::SuccessorStartExhausted { attempts }) if attempts == MAX_ENDED_SUCCESSORS
        ),
        "{last:?}"
    );
    let _ = root.execute(intent("after-the-cap")).await;
    let newly = authority
        .troubles
        .lock()
        .iter()
        .filter(|trouble| matches!(trouble, SuccessorTrouble::Exhausted { newly: true, .. }))
        .count();
    assert_eq!(newly, 1);
}

/// The wedge escape covers startup too: odind's open lane retries
/// `initialize`, and before the escape reached it a vehicle whose startup
/// reclaim kept failing left the conversation closed forever (no intent
/// ever routed, so the intent-side escape never ran). Two failed opens
/// stay typed; the third rolls to a successor and the vehicle opens.
#[tokio::test(start_paused = true)]
async fn a_vehicle_whose_startup_reclaim_keeps_failing_opens_a_successor() {
    let dir = tempdir().expect("tempdir");
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
    *plane_b.reclaim_failure.lock() = Some(LiveError::Unavailable {
        code: "bridge_launch_refused".to_owned(),
    });
    let root_b = root_in(
        dir.path(),
        Arc::clone(&plane_b) as Arc<dyn ConversationPlane>,
        Arc::new(FakeEgress::new()),
        Arc::new(FakeApprovals::empty()),
    );
    for _ in 1..crate::conversation::vehicle::WEDGE_ESCAPE_AFTER {
        assert!(
            root_b.initialize().await.is_err(),
            "a failed reclaim stays typed"
        );
        assert!(plane_b.opens.lock().is_empty(), "no successor yet");
    }
    root_b
        .initialize()
        .await
        .expect("the third failed reclaim opens a successor");
    let record = root_b.load_record().expect("record");
    assert_ne!(
        record.session_id.clone().expect("vehicle"),
        session.to_string(),
        "the conversation left the wedge"
    );
    assert_eq!(plane_b.opens.lock().len(), 1, "exactly one successor");
    assert_eq!(record.recovery_failures, 0);
}

#[tokio::test(start_paused = true)]
async fn an_ended_pending_successor_is_superseded_by_a_fresh_one() {
    let dir = tempdir().expect("tempdir");
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
    plane_b
        .seed(&vehicle_command, LiveSessionState::Failed, false)
        .await;
    *plane_b.reclaim_failure.lock() = Some(LiveError::Unavailable {
        code: "bridge_launch_refused".to_owned(),
    });
    plane_b.fail_opens.store(1, Ordering::SeqCst);
    let root_b = root_in(
        dir.path(),
        Arc::clone(&plane_b) as Arc<dyn ConversationPlane>,
        Arc::new(FakeEgress::new()),
        Arc::new(FakeApprovals::empty()),
    );
    for _ in 0..crate::conversation::vehicle::WEDGE_ESCAPE_AFTER {
        assert!(
            root_b.initialize().await.is_err(),
            "the successor open failed"
        );
    }
    assert_eq!(plane_b.opens.lock().len(), 1, "one successor tried");
    let ended = plane_b.opens.lock()[0].clone();
    *plane_b.reclaim_failure.lock() = None;
    let mut opened = false;
    for _ in 0..3 {
        if root_b.initialize().await.is_ok() {
            opened = true;
            break;
        }
    }
    assert!(
        opened,
        "a fresh successor opens instead of re-driving the ended one"
    );
    let opens = plane_b.opens.lock().clone();
    assert_eq!(opens.len(), 2, "exactly one fresh successor: {opens:?}");
    assert_ne!(opens[1], ended);
    let record = root_b.load_record().expect("record");
    assert_eq!(
        record.session_id.clone().expect("vehicle"),
        odin_omp::live::supervisor::session_id_for(&CommandId::new(&opens[1]).unwrap())
            .unwrap()
            .to_string()
    );
}

/// Backoff survives restarts; a new daemon executable resets it.
#[tokio::test(start_paused = true)]
async fn a_successor_that_never_starts_backs_off_instead_of_minting_sessions() {
    use crate::conversation::rollover::ended_successor_backoff_ms;
    let dir = tempdir().expect("tempdir");
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
    *plane.reclaim_failure.lock() = Some(LiveError::Unavailable {
        code: "bridge_launch_refused".to_owned(),
    });
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

/// A lagging ensured bound arms the governed fresh-generation successor
/// at startup: the SAME logical conversation opens a NEW session at the
/// current pin, the predecessor is governed Ended through the canonical
/// abort surface, the bounded brief rides the successor's first prompt,
/// and the durable slot records the completed transition.
#[tokio::test(start_paused = true)]
async fn startup_rolls_a_lagging_vehicle_to_a_fresh_current_generation() {
    let dir = tempdir().expect("tempdir");
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
    let predecessor =
        odin_omp::live::supervisor::session_id_for(&vehicle_command).expect("predecessor session");
    let plane_b = Arc::new(FakePlane::new(dir.path()).await);
    plane_b
        .seed(&vehicle_command, LiveSessionState::Failed, false)
        .await;
    let (successor_command, expected_successor) = successor_of(
        &format!("conversation:{}", conversation_root_identity(SEAT, PROJECT)),
        &predecessor,
    );
    // The predecessor's token is frozen below the pin; the freshly
    // derived successor mints AT the current pin, so the transition
    // converges on the first derived identity.
    let mut script = BTreeMap::new();
    script.insert(
        vehicle_command.to_string(),
        EnsuredGeneration {
            bound: 55,
            current: 81,
            composition: None,
        },
    );
    script.insert(
        successor_command.to_string(),
        EnsuredGeneration {
            bound: 81,
            current: 81,
            composition: None,
        },
    );
    let root_b = root_in_authority(
        dir.path(),
        Arc::clone(&plane_b) as Arc<dyn ConversationPlane>,
        Arc::new(FakeEgress::new()),
        Arc::new(FakeApprovals::empty()),
        Arc::new(FakeAuthority {
            calls: Mutex::new(Vec::new()),
            bound: 81,
            current: 81,
            script: Mutex::new(script),
            deferred: std::sync::atomic::AtomicBool::new(false),
            troubles: Mutex::new(Vec::new()),
        }),
    );
    root_b.initialize().await.expect("the rollover completes");
    let successor = root_b
        .current_vehicle_session()
        .await
        .expect("vehicle readable")
        .expect("successor recorded");
    assert_eq!(successor, expected_successor, "the derived successor");
    assert_ne!(successor, predecessor, "a FRESH session identity");
    assert_eq!(
        plane_b.retirements.lock().as_slice(),
        [predecessor.to_string()],
        "the predecessor governed Ended exactly once"
    );
    assert_eq!(plane_b.retirements.lock().len(), 1);
    let prompts = plane_b.initial_prompts.lock();
    assert_eq!(prompts.len(), 1, "the brief rides the successor open");
    assert!(
        prompts[0].contains("odin.rollover-brief.v1"),
        "the bounded brief is the continuity carrier"
    );
    let record = root_b.load_record().expect("record");
    let slot = record.rollover.expect("the transition slot");
    assert_eq!(slot.phase, rollover::SuccessorPhase::Open);
    assert_eq!(slot.predecessor_session, predecessor.to_string());
    assert_eq!(slot.successor_session, successor.to_string());
}

/// A rejected retirement is journaled under its command id. The next
/// attempt uses a different id, so the stop re-runs and the successor opens.
#[tokio::test(start_paused = true)]
async fn a_rejected_retirement_is_driven_again_and_the_successor_opens() {
    let dir = tempdir().expect("tempdir");
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
    let predecessor =
        odin_omp::live::supervisor::session_id_for(&vehicle_command).expect("predecessor session");
    let plane_b = Arc::new(FakePlane::new(dir.path()).await);
    plane_b
        .seed(&vehicle_command, LiveSessionState::Running, true)
        .await;
    plane_b.fail_retirements.store(1, Ordering::SeqCst);
    let (successor_command, expected_successor) = successor_of(
        &format!("conversation:{}", conversation_root_identity(SEAT, PROJECT)),
        &predecessor,
    );
    let mut script = BTreeMap::new();
    script.insert(
        vehicle_command.to_string(),
        EnsuredGeneration {
            bound: 55,
            current: 81,
            composition: None,
        },
    );
    script.insert(
        successor_command.to_string(),
        EnsuredGeneration {
            bound: 81,
            current: 81,
            composition: None,
        },
    );
    let root_b = root_in_authority(
        dir.path(),
        Arc::clone(&plane_b) as Arc<dyn ConversationPlane>,
        Arc::new(FakeEgress::new()),
        Arc::new(FakeApprovals::empty()),
        Arc::new(FakeAuthority {
            calls: Mutex::new(Vec::new()),
            bound: 81,
            current: 81,
            script: Mutex::new(script),
            deferred: AtomicBool::new(false),
            troubles: Mutex::new(Vec::new()),
        }),
    );
    root_b
        .initialize()
        .await
        .expect("a rejected first retirement does not wedge the conversation");
    let successor = root_b
        .current_vehicle_session()
        .await
        .expect("vehicle readable")
        .expect("successor recorded");
    assert_eq!(successor, expected_successor);
    assert_eq!(
        plane_b.retirements.lock().as_slice(),
        [predecessor.to_string()],
        "the later attempt ended the predecessor"
    );
    assert_eq!(
        plane_b.fail_retirements.load(Ordering::SeqCst),
        0,
        "the rejected attempt was consumed"
    );
    let record = root_b.load_record().expect("record");
    assert_eq!(
        record.rollover.expect("slot").phase,
        rollover::SuccessorPhase::Open
    );
}

/// Retirement that never ends does not hold every later turn. The successor
/// opens and the predecessor is left running.
#[tokio::test(start_paused = true)]
async fn an_unfinished_retirement_opens_the_successor_anyway() {
    let dir = tempdir().expect("tempdir");
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
    let predecessor =
        odin_omp::live::supervisor::session_id_for(&vehicle_command).expect("predecessor session");
    let plane_b = Arc::new(FakePlane::new(dir.path()).await);
    plane_b
        .seed(&vehicle_command, LiveSessionState::Running, true)
        .await;
    plane_b.fail_retirements.store(8, Ordering::SeqCst);
    let (successor_command, expected_successor) = successor_of(
        &format!("conversation:{}", conversation_root_identity(SEAT, PROJECT)),
        &predecessor,
    );
    let mut script = BTreeMap::new();
    script.insert(
        vehicle_command.to_string(),
        EnsuredGeneration {
            bound: 55,
            current: 81,
            composition: None,
        },
    );
    script.insert(
        successor_command.to_string(),
        EnsuredGeneration {
            bound: 81,
            current: 81,
            composition: None,
        },
    );
    let root_b = root_with_links(
        dir.path(),
        Arc::clone(&plane_b) as Arc<dyn ConversationPlane>,
        Arc::new(FakeEgress::new()),
        Arc::new(FakeApprovals::empty()),
        Arc::new(FakeAuthority {
            calls: Mutex::new(Vec::new()),
            bound: 81,
            current: 81,
            script: Mutex::new(script),
            deferred: AtomicBool::new(false),
            troubles: Mutex::new(Vec::new()),
        }),
        Default::default(),
        Some(
            odin_omp::host_tools::delegation::DelegationLinkLedger::open(dir.path().join("links"))
                .expect("delegation links"),
        ),
    );
    root_b
        .initialize()
        .await
        .expect("an unfinished retirement does not wedge the conversation");
    let successor = root_b
        .current_vehicle_session()
        .await
        .expect("vehicle readable")
        .expect("successor recorded");
    assert_eq!(successor, expected_successor);
    assert!(
        plane_b.retirements.lock().is_empty(),
        "no attempt ended the predecessor"
    );
    let still = plane_b
        .state_of(&predecessor)
        .expect("predecessor still listed");
    assert_ne!(still, LiveSessionState::Ended);
    let links = root_b.delegation_links.as_ref().expect("delegation links");
    let parent = odin_domain::SessionId::new(predecessor.to_string()).expect("parent");
    let expected = odin_domain::SessionId::new(expected_successor.to_string()).expect("successor");
    assert_eq!(
        links.armed_successor(&parent).expect("handoff arm"),
        Some(expected.clone()),
        "late children must follow the successor while retirement remains unfinished"
    );
    let mut record = root_b.load_record().expect("successor record");
    root_b
        .resume_successor(&mut record)
        .await
        .expect("resume unfinished retirement");
    assert_eq!(
        links.armed_successor(&parent).expect("resumed handoff arm"),
        Some(expected),
        "resuming from the successor must retain the late-child handoff"
    );
    plane_b.set_state_public(&predecessor, LiveSessionState::Ended);
    root_b
        .resume_successor(&mut record)
        .await
        .expect("resume ended predecessor");
    assert_eq!(links.armed_successor(&parent).expect("cleared arm"), None);
}

/// A coherent bound/current pair recovers in place: no successor, no
/// retirement, no slot.
#[tokio::test(start_paused = true)]
async fn coherent_generations_recover_in_place_without_a_rollover() {
    let dir = tempdir().expect("tempdir");
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

/// A truthfully closed vehicle never rolls: terminality precedes arming.
#[tokio::test(start_paused = true)]
async fn closed_vehicle_never_rolls_even_when_lagging() {
    let (_dir, plane, egress, approvals, root) = harness().await;
    let _ = (&plane, &egress, &approvals);
    root.initialize().await.expect("initialize");
    let session = root
        .current_vehicle_session()
        .await
        .expect("vehicle")
        .expect("vehicle");
    plane.set_state(&session, LiveSessionState::Ended);
    let failure = root
        .execute(intent("after-close"))
        .await
        .expect_err("refused");
    assert_eq!(failure, IntentFailure::ConversationClosed);
    let record = root.load_record().expect("record");
    assert!(record.rollover.is_none(), "a closed vehicle never rolls");
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

/// A pending successor whose OWN ensured bound lags a newer publication
/// is superseded before anything opens: the stale identity never opens,
/// a never-opened stale identity leaves nothing to retire, the brief
/// survives verbatim, and the transition converges on the fresh
/// identity derived one generation forward — no frozen token rebound.
#[tokio::test(start_paused = true)]
async fn a_new_pin_supersedes_a_pending_successor_before_anything_opens() {
    let dir = tempdir().expect("tempdir");
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
    let predecessor =
        odin_omp::live::supervisor::session_id_for(&vehicle_command).expect("predecessor");
    let conversation_id = format!("conversation:{}", conversation_root_identity(SEAT, PROJECT));
    let (stale_command, stale_session) = successor_of(&conversation_id, &predecessor);
    let (fresh_command, fresh_session) = successor_of(&conversation_id, &stale_session);
    let plane_b = Arc::new(FakePlane::new(dir.path()).await);
    plane_b
        .seed(&vehicle_command, LiveSessionState::Failed, false)
        .await;
    let mut script = BTreeMap::new();
    // The predecessor's bound lags the pin (arming), the stale
    // successor's own mint lags a newer publication (superseding), and
    // only the next identity is current (convergence).
    script.insert(
        vehicle_command.to_string(),
        EnsuredGeneration {
            bound: 5,
            current: 7,
            composition: None,
        },
    );
    script.insert(
        stale_command.to_string(),
        EnsuredGeneration {
            bound: 5,
            current: 7,
            composition: None,
        },
    );
    script.insert(
        fresh_command.to_string(),
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
    let root_b = root_in_authority(
        dir.path(),
        Arc::clone(&plane_b) as Arc<dyn ConversationPlane>,
        Arc::new(FakeEgress::new()),
        Arc::new(FakeApprovals::empty()),
        authority,
    );
    root_b
        .initialize()
        .await
        .expect("the governed supersede completes");
    let successor = root_b
        .current_vehicle_session()
        .await
        .expect("vehicle readable")
        .expect("successor recorded");
    assert_eq!(
        successor, fresh_session,
        "the transition converged one generation forward"
    );
    assert_eq!(
        plane_b.opens.lock().as_slice(),
        [fresh_command.to_string()],
        "the stale successor never opened"
    );
    assert_eq!(
        plane_b.retirements.lock().as_slice(),
        [predecessor.to_string()],
        "only the predecessor retired; a never-opened stale identity \
         leaves nothing to retire"
    );
    assert!(
        plane_b.recoveries.lock().is_empty(),
        "no reclaim rode the supersede"
    );
    let prompts = plane_b.initial_prompts.lock();
    assert_eq!(prompts.len(), 1, "one open, carrying the preserved brief");
    assert!(
        prompts[0].contains("odin.rollover-brief.v1"),
        "the bounded brief is the continuity carrier"
    );
    drop(prompts);
    let record = root_b.load_record().expect("record");
    let slot = record.rollover.expect("the transition slot");
    assert_eq!(slot.phase, rollover::SuccessorPhase::Open);
    assert_eq!(slot.predecessor_session, stale_session.to_string());
    assert_eq!(slot.successor_session, successor.to_string());
}

/// The crash window AFTER the successor opened but BEFORE the slot was
/// proven durable, with a new publication landing meanwhile: the resume
/// supersedes the already-opened stale successor through the canonical
/// retirement surface, preserves the brief byte-for-byte, and opens the
/// next derived identity.
#[tokio::test(start_paused = true)]
async fn a_publication_during_a_pending_open_supersedes_the_opened_successor() {
    let dir = tempdir().expect("tempdir");
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
    let predecessor =
        odin_omp::live::supervisor::session_id_for(&vehicle_command).expect("predecessor");
    let conversation_id = format!("conversation:{}", conversation_root_identity(SEAT, PROJECT));
    let (stale_command, stale_session) = successor_of(&conversation_id, &predecessor);
    let (fresh_command, fresh_session) = successor_of(&conversation_id, &stale_session);
    let mut script = BTreeMap::new();
    script.insert(
        stale_command.to_string(),
        EnsuredGeneration {
            bound: 1,
            current: 1,
            composition: None,
        },
    );
    script.insert(
        fresh_command.to_string(),
        EnsuredGeneration {
            bound: 2,
            current: 2,
            composition: None,
        },
    );
    let authority = Arc::new(FakeAuthority {
        calls: Mutex::new(Vec::new()),
        bound: 1,
        current: 1,
        script: Mutex::new(script),
        deferred: std::sync::atomic::AtomicBool::new(false),
        troubles: Mutex::new(Vec::new()),
    });
    let plane_b = Arc::new(FakePlane::new(dir.path()).await);
    let root_b = root_in_authority(
        dir.path(),
        Arc::clone(&plane_b) as Arc<dyn ConversationPlane>,
        Arc::new(FakeEgress::new()),
        Arc::new(FakeApprovals::empty()),
        Arc::clone(&authority),
    );
    // The first leg runs the governed transition to completion at the
    // then-current pin: the predecessor retires Ended, the successor
    // opens at its coherent generation.
    let mut record = root_b.load_record().expect("record");
    root_b
        .begin_successor(&mut record, Some(1), Some(0))
        .await
        .expect("the first leg opens the successor");
    assert_eq!(
        plane_b.retirements.lock().as_slice(),
        [predecessor.to_string()]
    );
    // The crash window: the durable open happened, the slot was never
    // marked Open.
    let mut record = root_b.load_record().expect("record");
    let slot = record.rollover.as_mut().expect("the transition slot");
    assert_eq!(slot.phase, rollover::SuccessorPhase::Open);
    slot.phase = rollover::SuccessorPhase::Pending;
    root_b.store_record(&mut record).expect("record stored");
    // A new publication lands: the opened successor's ensured bound now
    // lags the pin.
    authority.script.lock().insert(
        stale_command.to_string(),
        EnsuredGeneration {
            bound: 1,
            current: 2,
            composition: None,
        },
    );
    root_b
        .initialize()
        .await
        .expect("the resume supersedes the stale successor");
    let successor = root_b
        .current_vehicle_session()
        .await
        .expect("vehicle readable")
        .expect("successor recorded");
    assert_eq!(successor, fresh_session);
    assert_eq!(
        plane_b.opens.lock().as_slice(),
        [stale_command.to_string(), fresh_command.to_string()],
        "exactly the first-leg open and the fresh open"
    );
    assert_eq!(
        plane_b.retirements.lock().as_slice(),
        [predecessor.to_string(), stale_session.to_string()],
        "the opened stale successor retired through the canonical surface"
    );
    let prompts = plane_b.initial_prompts.lock();
    assert_eq!(prompts.len(), 2, "the brief rode both opens");
    assert!(
        prompts[1].contains("odin.rollover-brief.v1"),
        "the fresh open carries the continuity carrier"
    );
    assert_eq!(
        prompts[1], prompts[0],
        "the preserved brief is byte-identical across the supersede"
    );
    drop(prompts);
    let record = root_b.load_record().expect("record");
    let slot = record.rollover.expect("the transition slot");
    assert_eq!(slot.phase, rollover::SuccessorPhase::Open);
    assert_eq!(slot.predecessor_session, stale_session.to_string());
    assert_eq!(slot.successor_session, successor.to_string());
}

/// The observe-recovery entry: a vehicle that went down mid-turn and is
/// canonically Ended by recover time refuses typed — the closed
/// lifecycle is never reclaimed and never superseded, whatever the
/// ensured generation reports.
#[tokio::test(start_paused = true)]
async fn an_ended_vehicle_refuses_observe_recovery_even_when_lagging() {
    let dir = tempdir().expect("tempdir");
    let plane = Arc::new(FakePlane::new(dir.path()).await);
    let root = root_in(
        dir.path(),
        Arc::clone(&plane) as Arc<dyn ConversationPlane>,
        Arc::new(FakeEgress::new()),
        Arc::new(FakeApprovals::empty()),
    );
    root.initialize().await.expect("initialize");
    let session = root
        .current_vehicle_session()
        .await
        .expect("vehicle")
        .expect("vehicle");
    // The fresh daemon ensures at a lagging generation, and the plane
    // reports the session canonically Ended.
    let plane_b = Arc::new(FakePlane::new(dir.path()).await);
    plane_b.set_state(&session, LiveSessionState::Ended);
    let root_b = root_in_generations(
        dir.path(),
        Arc::clone(&plane_b) as Arc<dyn ConversationPlane>,
        Arc::new(FakeEgress::new()),
        Arc::new(FakeApprovals::empty()),
        3,
        4,
    );
    let mut record = root_b.load_record().expect("record");
    let failure = root_b
        .recover_vehicle(&mut record, None)
        .await
        .expect_err("the closed lifecycle refuses typed");
    assert_eq!(failure, IntentFailure::ConversationClosed);
    let record = root_b.load_record().expect("record");
    assert!(
        record.rollover.is_none(),
        "a closed lifecycle is never superseded"
    );
    assert!(
        plane_b.retirements.lock().is_empty(),
        "no retirement rode the refusal"
    );
    assert!(
        plane_b.opens.lock().is_empty(),
        "no fresh session replaced the closed vehicle"
    );
    assert!(
        plane_b.recoveries.lock().is_empty(),
        "no reclaim touched the closed vehicle"
    );
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
    let (_, brief_json) = prompt
        .split_once('\n')
        .expect("rollover prompt carries the brief json");
    let brief: serde_json::Value = serde_json::from_str(brief_json).expect("brief parses");
    brief["conversation_tail"]
        .as_array()
        .expect("conversation tail")
        .clone()
}

/// A retired vehicle whose journal is lifecycle state only (402
/// events, never a message) still rolls with the RECENT delivered
/// owner-DM tail: the durable conversation ledger is the history
/// source, carrying the newest 64 settled turns in chronological
/// order across bygone vehicle identities, and the oldest page never
/// replaces the tail.
#[tokio::test(start_paused = true)]
async fn recovery_carries_the_recent_journal_tail_not_the_oldest_page() {
    let dir = tempdir().expect("tempdir");
    let fx = failed_vehicle_fixture(dir.path(), 402).await;
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
/// turns out of the newest-64 window: with 65 eligible turns the cap
/// excludes exactly the oldest one.
#[tokio::test(start_paused = true)]
async fn ineligible_ledger_rows_never_poison_or_crowd_out_eligible_turns() {
    let dir = tempdir().expect("tempdir");
    let fx = failed_vehicle_fixture(dir.path(), 402).await;
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
        "FAILED-TURN",
    ] {
        assert!(
            !prompt.contains(token),
            "{token} must never poison the brief"
        );
    }
}

#[tokio::test(start_paused = true)]
async fn never_applied_in_flight_flight_is_retired_and_the_next_dm_answers() {
    let (dir, plane, egress, approvals, root) = harness().await;
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
        idempotency_key: "wedged".to_owned(),
        content: "ok you there now?".to_owned(),
        command_id: wedged_command.to_string(),
        session_id: session.to_string(),
        kind: InFlightKind::Prompt,
        expected_epoch: 1,
        event_cursor: head,
        phase: InFlightPhase::Sent,
        clock: None,
        asks: Vec::new(),
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
    let _ = (dir, egress, approvals);
}

/// The unknown-fate branch: the stale flight's command WAS admitted but
/// no answer ever settled and the accepting run is gone. The owner gets
/// exactly ONE plain sentence, the flight clears, and the new DM is
/// answered afterwards.
#[tokio::test(start_paused = true)]
async fn unknown_fate_in_flight_flight_notifies_once_and_the_next_dm_answers() {
    let (dir, plane, egress, approvals, root) = harness().await;
    root.initialize().await.expect("initialize");
    let session = root
        .current_vehicle_session()
        .await
        .expect("vehicle")
        .expect("vehicle");

    // Admit the stale command WITHOUT any answer event: auto_reply off,
    // direct journal admission through the real plane command path.
    plane.auto_reply.store(false, Ordering::SeqCst);
    let stale_command = bounded_command("intent", &["stale"]).expect("command id");
    let admitted = plane
        .command(LiveCommand {
            command_id: stale_command.clone(),
            session_id: session,
            expected_epoch: SessionEpoch::new(1),
            expected_event_head: None,
            body: LiveCommandBody::Prompt {
                message: LiveMessage::new(vec![LiveContentBlock::Text(
                    "ok you there now?".to_owned(),
                )])
                .expect("message"),
            },
        })
        .await
        .expect("journal admits the stale prompt");
    // Its accepting run died with the turn: the session is idle again.
    plane
        .push_state_change(&session, LiveSessionState::Idle)
        .await;

    let mut record = root.load_record().expect("record");
    let head = plane.ledger.head(session).await.expect("head").get();
    record.in_flight = Some(InFlightPrompt {
        idempotency_key: "stale".to_owned(),
        content: "ok you there now?".to_owned(),
        command_id: stale_command.to_string(),
        session_id: session.to_string(),
        kind: InFlightKind::Prompt,
        expected_epoch: 1,
        event_cursor: head,
        phase: InFlightPhase::Sent,
        clock: None,
        asks: Vec::new(),
    });
    root.store_record(&mut record).expect("record stored");

    plane.auto_reply.store(true, Ordering::SeqCst);
    let projection = root.execute(intent("k2")).await.expect("second DM answers");
    assert_eq!(projection["answer"], "A plain answer.");
    // Exactly ONE unknown-fate notice reached the owner, quoting a
    // bounded prefix of the lost content.
    let sends = egress.sends();
    let notices: Vec<_> = sends
        .iter()
        .filter(|send| send.starts_with("I lost track of your message"))
        .collect();
    assert_eq!(notices.len(), 1, "one plain sentence, sends: {sends:?}");
    assert!(
        notices[0].contains("ok you there now?"),
        "the notice quotes the lost content"
    );
    assert!(
        notices[0].contains("can you send it again?"),
        "the notice asks for a resend"
    );
    let cleared = root.load_record().expect("record");
    assert!(cleared.in_flight.is_none(), "the flight is retired");
    // k2 settled afterwards and owns the final projection; the retire is
    // proven by the ONE notice, the cleared flight, and k2's answer.
    assert_eq!(cleared.last_idempotency_key.as_deref(), Some("k2"));
    let _ = (dir, approvals, admitted);
}

#[tokio::test(start_paused = true)]
async fn a_turn_whose_session_ended_under_it_is_retired_plainly() {
    let (dir, plane, egress, approvals, root) = harness().await;
    root.initialize().await.expect("initialize");
    let old = plane
        .seed(
            &CommandId::new("cmd-crashed-vehicle").expect("command id"),
            LiveSessionState::Idle,
            true,
        )
        .await;
    plane.auto_reply.store(false, Ordering::SeqCst);
    let stale_command = bounded_command("intent", &["crashed"]).expect("command id");
    plane
        .command(LiveCommand {
            command_id: stale_command.clone(),
            session_id: old,
            expected_epoch: SessionEpoch::new(1),
            expected_event_head: None,
            body: LiveCommandBody::Prompt {
                message: LiveMessage::new(vec![LiveContentBlock::Text(
                    "make me a tiny agent pod".to_owned(),
                )])
                .expect("message"),
            },
        })
        .await
        .expect("journal admits the prompt");
    plane.push_state_change(&old, LiveSessionState::Ended).await;
    plane.set_state_public(&old, LiveSessionState::Ended);
    plane.auto_reply.store(true, Ordering::SeqCst);
    let mut record = root.load_record().expect("record");
    let head = plane.ledger.head(old).await.expect("head").get();
    record.in_flight = Some(InFlightPrompt {
        idempotency_key: "crashed".to_owned(),
        content: "make me a tiny agent pod".to_owned(),
        command_id: stale_command.to_string(),
        session_id: old.to_string(),
        kind: InFlightKind::Prompt,
        expected_epoch: 1,
        event_cursor: head,
        phase: InFlightPhase::Sent,
        clock: None,
        asks: Vec::new(),
    });
    root.store_record(&mut record).expect("record stored");

    root.execute(intent("crashed"))
        .await
        .expect("retired plainly, not 'conversation closed'");
    let sends = egress.sends();
    assert_eq!(
        sends,
        vec![
            "I lost track of your message 'make me a tiny agent pod' — can you send it again?"
                .to_owned()
        ]
    );
    assert!(root.load_record().expect("record").in_flight.is_none());
    let _ = (dir, approvals);
}

/// A recorded brief with no applied outcome needs a new successor identity, not another replay.
#[tokio::test(start_paused = true)]
async fn a_recorded_never_applied_brief_supersedes_the_successor_instead_of_looping() {
    unapplied_brief_supersedes_the_successor(false).await;
}

/// A settled failure cannot become applied under the same command id.
#[tokio::test(start_paused = true)]
async fn a_failed_brief_supersedes_the_successor_instead_of_looping() {
    unapplied_brief_supersedes_the_successor(true).await;
}

async fn unapplied_brief_supersedes_the_successor(failed: bool) {
    let dir = tempdir().expect("tempdir");
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
    let predecessor =
        odin_omp::live::supervisor::session_id_for(&vehicle_command).expect("predecessor");
    let conversation_id = format!("conversation:{}", conversation_root_identity(SEAT, PROJECT));
    let (stale_command, stale_session) = successor_of(&conversation_id, &predecessor);
    let (fresh_command, fresh_session) = successor_of(&conversation_id, &stale_session);
    let plane_b = Arc::new(FakePlane::new(dir.path()).await);
    plane_b
        .seed(&vehicle_command, LiveSessionState::Failed, false)
        .await;
    let mut script = BTreeMap::new();
    // The predecessor's bound lags the pin (arming the transition); both
    // successor identities are current, so the ONLY failure mode is the
    // never-applied brief command.
    script.insert(
        vehicle_command.to_string(),
        EnsuredGeneration {
            bound: 5,
            current: 7,
            composition: None,
        },
    );
    for current_command in [&stale_command, &fresh_command] {
        script.insert(
            current_command.to_string(),
            EnsuredGeneration {
                bound: 7,
                current: 7,
                composition: None,
            },
        );
    }
    let authority = Arc::new(FakeAuthority {
        calls: Mutex::new(Vec::new()),
        bound: 7,
        current: 7,
        script: Mutex::new(script),
        deferred: std::sync::atomic::AtomicBool::new(false),
        troubles: Mutex::new(Vec::new()),
    });
    let root_b = root_in_authority(
        dir.path(),
        Arc::clone(&plane_b) as Arc<dyn ConversationPlane>,
        Arc::new(FakeEgress::new()),
        Arc::new(FakeApprovals::empty()),
        authority,
    );
    // The first brief delivery records the command without an outcome —
    // the capsule-refused production window.
    if failed {
        plane_b.fail_briefs.store(1, Ordering::SeqCst);
    } else {
        plane_b.record_only_briefs.store(1, Ordering::SeqCst);
    }

    root_b
        .initialize()
        .await
        .expect("the never-applied brief is superseded, not looped");
    let successor = root_b
        .current_vehicle_session()
        .await
        .expect("vehicle readable")
        .expect("successor recorded");
    assert_eq!(
        successor, fresh_session,
        "the transition converged on the next derived identity"
    );
    assert_eq!(
        plane_b.opens.lock().as_slice(),
        [stale_command.to_string(), fresh_command.to_string()],
        "the stale successor opened, then the fresh one"
    );
    assert_eq!(
        plane_b.retirements.lock().as_slice(),
        [predecessor.to_string(), stale_session.to_string()],
        "the predecessor and the stale successor both retired canonically"
    );
    let record = root_b.load_record().expect("record");
    let slot = record.rollover.expect("the transition slot");
    assert_eq!(slot.phase, rollover::SuccessorPhase::Open);
    assert_eq!(slot.successor_session, fresh_session.to_string());
    // The stale brief keeps its journal entry (no outcome, or its settled
    // failure) — the fix never fabricates an applied one; it moves forward.
    assert!(
        plane_b
            .commands
            .lock()
            .iter()
            .any(|(id, kind)| id == &stale_command.to_string()
                && kind
                    == if failed {
                        "brief:failed"
                    } else {
                        "brief:recorded-only"
                    }),
        "the stale brief kept its recorded (or failed) journal entry"
    );
    let prompts = plane_b.initial_prompts.lock();
    assert!(
        prompts
            .iter()
            .any(|prompt| prompt.contains("odin.rollover-brief.v1")),
        "the preserved brief opened the fresh successor"
    );
}

#[tokio::test]
async fn rollover_brief_carries_live_delegated_children() {
    use odin_omp::host_tools::delegation::{
        DelegationLink, DelegationLinkLedger, DelegationPhase, DELEGATION_LINK_SCHEMA,
    };
    let dir = tempdir().expect("tempdir");
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

    // The predecessor delegated to Kubert, whose session answered.
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
    let links = DelegationLinkLedger::open(dir.path().join("links")).expect("links");
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
        brief_text.contains(odin_omp::live::rollover::ROLLOVER_ABSORB_INSTRUCTION),
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
async fn forty_turn_rollover_carries_a_continuity_sized_tail() {
    let dir = tempdir().expect("tempdir");
    let fx = failed_vehicle_fixture(dir.path(), 12).await;
    let conversation_id = format!("conversation:{}", conversation_root_identity(SEAT, PROJECT));
    let mut ledger = Ledger::open(state_ledger_path(dir.path())).expect("root ledger opens");
    write_delivered_turns(
        &mut ledger,
        &conversation_id,
        40,
        OffsetDateTime::now_utc() - time::Duration::hours(1),
    );
    drop(ledger);
    let (prompt, _successor, _projection) = roll_failed_vehicle(&fx, dir.path()).await;
    let tail = brief_conversation_tail(&prompt);
    let pairs = tail.len() / 2;
    assert!(
        pairs >= 16,
        "the brief carries a continuity-sized recent tail (got {pairs} pairs)"
    );
    // Newest, contiguous, chronological: the final pair is turn 39.
    let last_user = &tail[(pairs - 1) * 2];
    let last_assistant = &tail[(pairs - 1) * 2 + 1];
    assert_eq!(last_user["text"], "REQUEST-039");
    assert_eq!(last_assistant["text"], "ANSWER-039");
}

/// The seat's DECLARED `[live.rollover]` budget bounds the vehicle brief:
/// a declared 16 KB carries more of a long tail than the 8 KB default and
/// never exceeds its own bound (before, the vehicle ignored the declaration
/// and always rendered under the compiled default).
#[tokio::test(start_paused = true)]
async fn the_vehicle_brief_is_bounded_by_the_declared_seat_policy() {
    let mut sizes = Vec::new();
    for declared in [None, Some(16_000)] {
        let dir = tempdir().expect("tempdir");
        let fx = failed_vehicle_fixture(dir.path(), 12).await;
        let conversation_id = format!("conversation:{}", conversation_root_identity(SEAT, PROJECT));
        let mut ledger = Ledger::open(state_ledger_path(dir.path())).expect("root ledger opens");
        let base = OffsetDateTime::now_utc() - time::Duration::hours(1);
        for index in 0..40_u64 {
            let session = bygone_vehicle_session(&conversation_id, index % 3).to_string();
            record_owner_turn(
                &mut ledger,
                &OwnerTurn::delivered(
                    1_100_000_000_000_000_000 + index,
                    &format!("REQUEST-{index:03} {}", "detail ".repeat(40)),
                    &format!("ANSWER-{index:03} {}", "context ".repeat(40)),
                    &session,
                ),
                base + time::Duration::minutes(index as i64),
            );
        }
        drop(ledger);
        let policy = odin_omp::live::rollover::RolloverPolicy {
            max_brief_bytes: declared
                .unwrap_or(odin_omp::live::rollover::ROLLOVER_BRIEF_BYTES_DEFAULT),
            ..Default::default()
        };
        let bound = policy.max_brief_bytes;
        let (prompt, _, _) = roll_failed_vehicle_under(&fx, dir.path(), policy).await;
        let (_, brief) = prompt.split_once('\n').expect("brief json");
        assert!(
            brief.len() <= bound,
            "brief {} exceeds its bound {bound}",
            brief.len()
        );
        sizes.push(brief_conversation_tail(&prompt).len());
    }
    assert!(
        sizes[1] > sizes[0],
        "the declared 16 KB budget carries more tail than the default ({sizes:?})"
    );
}

#[tokio::test(start_paused = true)]
async fn stale_wake_rebinds_at_rollover_and_the_next_dm_answers() {
    let dir = tempdir().expect("tempdir");
    let fx = failed_vehicle_fixture(dir.path(), 8).await;
    // The stale wake: approved kernelRetry pinned to the PREDECESSOR.
    let stale_command = bounded_command("conversation-wake", &["predecessor-approval"])
        .expect("wake command")
        .to_string();
    {
        let edit_root = root_in(
            dir.path(),
            Arc::clone(&fx.plane) as Arc<dyn ConversationPlane>,
            Arc::new(FakeEgress::new()),
            Arc::new(FakeApprovals::empty()),
        );
        let mut record = edit_root.load_record().expect("record");
        record.wakes.push(PendingWake {
            command_id: stale_command.clone(),
            owner_keys: Vec::new(),
            kind: WakeKind::KernelRetry,
            approved: true,
            label: "Ask Gungnir to help implement this task".to_owned(),
            session_id: fx.predecessor.to_string(),
            decision_cursor: 7,
            approval_id: Some("approval:r3:seat.ask.gungnir:blake3:abc".to_owned()),
            prompt: Some(InFlightPrompt {
                idempotency_key: stale_command.clone(),
                content: "[host] The owner approved your request.".to_owned(),
                command_id: stale_command.clone(),
                session_id: fx.predecessor.to_string(),
                kind: InFlightKind::Prompt,
                expected_epoch: 2,
                event_cursor: 7,
                phase: InFlightPhase::Sent,
                clock: None,
                asks: Vec::new(),
            }),
            reply: None,
            completion: None,
            owner_note: None,
            rolled: false,
        });
        edit_root.store_record(&mut record).expect("record stored");
    }
    // Rollover + a DM right after.
    let (prompt, successor, _projection) = roll_failed_vehicle(&fx, dir.path()).await;
    assert!(prompt.contains("odin.rollover-brief"), "the rollover ran");
    assert_ne!(successor, fx.predecessor, "a fresh successor");
    let root_c = root_in(
        dir.path(),
        Arc::clone(&fx.plane) as Arc<dyn ConversationPlane>,
        Arc::new(FakeEgress::new()),
        Arc::new(FakeApprovals::empty()),
    );
    let record = root_c.load_record().expect("record");
    let wake = record
        .wakes
        .iter()
        .find(|wake| wake.kind == WakeKind::KernelRetry)
        .expect("the wake survived the rollover");
    assert_ne!(
        wake.command_id, stale_command,
        "the wake carries a FRESH command identity"
    );
    assert_eq!(
        wake.session_id,
        successor.to_string(),
        "the wake is bound to the successor"
    );
    let rebound = wake.prompt.as_ref().expect("prompt kept");
    assert_eq!(rebound.session_id, successor.to_string());
    assert_ne!(rebound.command_id, stale_command);
    assert_eq!(rebound.phase, InFlightPhase::Prepared);
    // And the DM after the rollover answers: the route is not wedged.
    let projection = root_c
        .execute(intent("after-rollover"))
        .await
        .expect("the DM answers after the rollover");
    assert_eq!(projection["answer"], "A plain answer.");
}

/// Admission freezes the command; retrying at a different epoch requires a new id.
#[tokio::test(start_paused = true)]
async fn a_retry_after_an_admitted_failure_is_a_new_command() {
    let (dir, plane, egress, approvals, root) = harness().await;
    root.initialize().await.expect("initialize");
    plane.fail_prompts.store(1, Ordering::SeqCst);
    let failure = root
        .execute(intent("wake"))
        .await
        .expect_err("first admitted attempt fails before final selection");
    assert!(
        matches!(failure, IntentFailure::TurnRefused { .. }),
        "{failure:?}"
    );
    let session = root.current_vehicle_session().await.unwrap().unwrap();
    let admitted = |history: HistoryPage| {
        history
            .events
            .into_iter()
            .filter_map(|event| match event.body {
                LiveEventBody::ControlAccepted(CommandReceipt::Accepted { command_id })
                    if command_id.as_str().starts_with("command:intent:") =>
                {
                    Some(command_id)
                }
                _ => None,
            })
            .collect::<Vec<_>>()
    };
    let before = admitted(
        plane
            .history(HistoryQuery {
                session_id: session,
                after: EventSeq::new(0),
                limit: std::num::NonZeroU16::new(500).unwrap(),
            })
            .await
            .expect("durable failed admission history"),
    );
    assert_eq!(before.len(), 1, "failed attempt was durably admitted");
    assert!(
        root.replay_delivery("wake").unwrap().is_none(),
        "no final answer was selected"
    );
    assert!(egress.sends().is_empty());
    // The admitted command stays journaled, but no terminal delivery exists.
    // The retry on the moved epoch must use a fresh command, not replay it.
    plane.recover_session(session).await.expect("epoch bump");
    let projection = root
        .execute(intent("wake"))
        .await
        .expect("the retry settles");
    assert_eq!(projection["answer"], "A plain answer.");
    let after = admitted(
        plane
            .history(HistoryQuery {
                session_id: session,
                after: EventSeq::new(0),
                limit: std::num::NonZeroU16::new(500).unwrap(),
            })
            .await
            .expect("durable retry admission history"),
    );
    assert_eq!(after.len(), 2, "one journaled admission per attempt");
    assert_eq!(
        after[0], before[0],
        "the original admission remains journaled"
    );
    assert_ne!(
        after[0], after[1],
        "moved-epoch retry has a fresh command identity"
    );
    // Admission is not success: the failed attempt may have run tools, so
    // the retry's receipt owns it beside the attempt that answered.
    assert_eq!(
        projection["promptCommands"],
        serde_json::json!([
            { "session": session.to_string(), "commandId": after[0].as_str() },
            { "session": session.to_string(), "commandId": after[1].as_str() },
        ])
    );
    assert_eq!(
        egress.sends(),
        ["A plain answer."],
        "only the successful retry delivers"
    );
    let _ = (dir, egress, approvals);
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

/// Equal revisions never lag; changed revisions need matching composition digests to avoid rollover.
#[test]
fn the_generation_lags_only_on_a_composition_change() {
    let a = odin_registry::CompositionDigest::from_bytes([1; 32]);
    let b = odin_registry::CompositionDigest::from_bytes([2; 32]);
    let generation = |bound, current, composition| EnsuredGeneration {
        bound,
        current,
        composition,
    };
    let pair = |bound, current| Some(crate::conversation::CompositionPair { bound, current });
    assert!(!generation(4, 4, None).lags());
    assert!(!generation(4, 4, pair(a, b)).lags());
    assert!(generation(4, 5, None).lags());
    assert!(generation(4, 5, pair(a, b)).lags());
    assert!(!generation(4, 5, pair(a, a)).lags());
    assert_eq!(generation(4, 5, pair(a, a)).kept_composition(), Some(a));
    assert_eq!(generation(4, 4, pair(a, a)).kept_composition(), None);
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

#[tokio::test(start_paused = true)]
async fn a_context_refusal_during_reload_preserves_the_owner_request() {
    let (dir, plane, egress, _approvals, _root) = harness().await;
    let authority = Arc::new(FakeAuthority {
        calls: Mutex::new(Vec::new()),
        bound: 2,
        current: 2,
        script: Mutex::new(BTreeMap::new()),
        deferred: std::sync::atomic::AtomicBool::new(false),
        troubles: Mutex::new(Vec::new()),
    });
    let root = root_in_authority(
        dir.path(),
        Arc::clone(&plane) as Arc<dyn ConversationPlane>,
        Arc::clone(&egress) as Arc<dyn ConversationEgress>,
        Arc::new(FakeApprovals::empty()),
        Arc::clone(&authority),
    );
    root.initialize().await.expect("initialize");
    let vehicle = root.load_record().expect("record").session_id;
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
    plane.refuse_context.store(1, Ordering::SeqCst);
    assert_eq!(
        root.execute(intent("reload-context")).await.unwrap_err(),
        IntentFailure::ConversationBusy
    );
    let record = root.load_record().expect("pending record");
    assert_eq!(record.session_id, vehicle);
    assert_eq!(
        record.rollover.as_ref().expect("pending successor").phase,
        rollover::SuccessorPhase::Pending
    );
    assert!(plane.retirements.lock().is_empty());
    assert_eq!(
        root.execute(intent("reload-context")).await.unwrap_err(),
        IntentFailure::ConversationBusy
    );
    assert!(plane.retirements.lock().is_empty());
    authority.deferred.store(false, Ordering::SeqCst);
    let answer = root
        .execute(intent("reload-context"))
        .await
        .expect("answer after reload");
    assert_eq!(answer["answer"], "A plain answer.");
    assert_eq!(
        plane.retirements.lock().as_slice(),
        &[vehicle.expect("predecessor")]
    );
    assert!(egress
        .sends()
        .iter()
        .any(|reply| reply.contains("A plain answer.")));
}

/// A request that does not fit even a fresh successor fails honestly at
/// once, never a timeout.
#[tokio::test(start_paused = true)]
async fn a_request_that_never_fits_fails_at_once() {
    let (_dir, plane, _egress, _approvals, root) = harness().await;
    root.initialize().await.expect("initialize");
    plane.refuse_context.store(2, Ordering::SeqCst);
    assert_eq!(
        root.execute(intent("way-too-big")).await.unwrap_err(),
        IntentFailure::ContextExhausted
    );
}
