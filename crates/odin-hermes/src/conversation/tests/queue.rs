//! Queued owner messages, rapid repeats and new requests while questions remain open.

use super::*;
use crate::runtime::ApprovedIntentRoute as _;

/// A known failed send releases its reservation but retains a finalizing ledger
/// row. The sequence proves a dispatch was attempted; the lifecycle cache does
/// not grant either completion or resend permission.
fn queued_delivery_failed(root: &ConversationRoot, wake: &PendingWake) -> bool {
    if wake.kind != WakeKind::QueuedAsks || wake.reply.is_none() {
        return false;
    }
    let id = crate::conversation::identity::bounded_command(
        "conversation-delivery",
        &[&root.conversation_id, &wake.command_id],
    )
    .expect("delivery identity");
    let ledger = odin_ledger::Ledger::open(&root.ledger_path).expect("delivery ledger");
    let Some(row) = ledger
        .conversation_delivery(&id.to_string())
        .expect("delivery row")
    else {
        return false;
    };
    let state: serde_json::Value = serde_json::from_str(&row.state_json).expect("delivery state");
    let failed = state["phase"] == "finalizing"
        && state["sequence"]
            .as_u64()
            .is_some_and(|sequence| sequence > 0)
        && state["pending"].is_null();
    if failed {
        assert!(wake.completion.is_none());
        assert_ne!(wake.reply.as_ref().unwrap().delivered, Some(true));
    }
    failed
}

/// The production turn-log lines, with the tests' own `queue-test:` marks between them, captured
/// in this process for as long as the value lives.
struct TurnLog {
    lines: Arc<parking_lot::Mutex<Vec<u8>>>,
    _guard: tracing::subscriber::DefaultGuard,
}

struct LogWriter(Arc<parking_lot::Mutex<Vec<u8>>>);

impl std::io::Write for LogWriter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.lock().extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl TurnLog {
    fn capture() -> Self {
        let lines = Arc::new(parking_lot::Mutex::new(Vec::new()));
        let sink = Arc::clone(&lines);
        let subscriber = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::INFO)
            .with_ansi(false)
            .with_target(false)
            .with_level(false)
            .without_time()
            .with_writer(move || LogWriter(Arc::clone(&sink)))
            .finish();
        Self {
            lines,
            _guard: tracing::subscriber::set_default(subscriber),
        }
    }

    /// Each key's one terminal line carries `outcome` and follows the delivery; a replay emits
    /// none, or with `retained_replay` the same line again from the retained receipt. `blocked`
    /// delivery emits no terminal at all.
    fn assert_terminals(&self, keys: &[&str], outcome: &str, retained_replay: bool) {
        let log = String::from_utf8_lossy(&self.lines.lock()).into_owned();
        if outcome == "blocked" {
            assert!(
                log.contains("queue-test: blocked retries complete\n"),
                "{log}"
            );
            assert!(log.contains("conversation-wake delivery_blocked"), "{log}");
            for key in keys {
                assert!(
                    !log.contains(&format!("odind: conversation-turn key={key} ")),
                    "blocked delivery emitted a terminal: {log}"
                );
            }
            return;
        }
        let (before, after) = log
            .split_once("queue-test: delivery-enabled\n")
            .expect("reached the delivery boundary");
        let (delivering, replay) = after
            .split_once("queue-test: delivered\n")
            .expect("reached durable completion");
        for key in keys {
            let prefix = format!("odind: conversation-turn key={key} ");
            assert!(!before.contains(&prefix), "premature terminal: {log}");
            if let Some((uncommitted, _)) = delivering.split_once("queue-test: committed\n") {
                assert!(
                    !uncommitted.contains(&prefix),
                    "terminal before commit: {log}"
                );
            }
            let terminals: Vec<_> = delivering
                .lines()
                .filter(|line| line.starts_with(&prefix))
                .collect();
            assert_eq!(terminals.len(), 1, "one terminal per admitted key: {log}");
            assert!(
                terminals[0].contains(&format!("queued=true outcome={outcome}")),
                "{log}"
            );
            let repeated: Vec<_> = replay
                .lines()
                .filter(|line| line.starts_with(&prefix))
                .collect();
            if retained_replay {
                assert_eq!(
                    repeated, terminals,
                    "the retained receipt preserves the exact outcome: {log}"
                );
            } else {
                assert!(
                    repeated.is_empty(),
                    "replay emitted another terminal: {log}"
                );
            }
        }
    }
}

#[tokio::test(start_paused = true)]
async fn queued_question_terminal_waits_for_durable_owner_handoff() {
    let log = TurnLog::capture();
    let (_dir, plane, egress, _approvals, root) = harness().await;
    root.initialize().await.expect("initialize");
    plane.auto_reply.store(false, Ordering::SeqCst);
    egress.fail.store(true, Ordering::SeqCst);
    for outcome in root
        .execute_batch(vec![
            said("question-a", "first thing"),
            said("question-b", "second thing"),
        ])
        .await
    {
        assert_eq!(outcome.expect("admitted")["queued"], true);
    }
    tokio::time::timeout(ANSWER_BOUND, async {
        loop {
            let record = root.load_record().expect("record");
            if record
                .questions
                .iter()
                .any(|question| question.delivery_error.is_some())
            {
                assert!(record
                    .questions
                    .iter()
                    .all(|question| question.delivered_message_id.is_none()));
                assert!(record
                    .wakes
                    .iter()
                    .any(|wake| wake.kind == WakeKind::QueuedAsks));
                assert!(record.wakes.iter().all(|wake| wake.completion.is_none()));
                break;
            }
            tokio::time::sleep(StdDuration::from_millis(100)).await;
        }
    })
    .await
    .expect("failed question delivery persisted");
    assert!(egress.sends().is_empty());
    tracing::info!("queue-test: delivery-enabled");
    egress.fail.store(false, Ordering::SeqCst);
    sends_reach(&egress, 1).await;
    root.join_background(StdDuration::from_secs(600)).await;
    let record = root.load_record().expect("durable question");
    assert_eq!(record.questions.len(), 1);
    let question = &record.questions[0];
    assert!(question.delivered_message_id.is_some());
    assert!(question.delivery_error.is_none());
    assert!(!question.settled, "handoff must not decide the question");
    assert!(record.wakes.is_empty());
    assert!(record.queued.is_empty());
    assert_eq!(plane.decide_count(), 0);
    assert_eq!(egress.sends().len(), 1);
    assert!(egress.sends()[0].contains("Send the drafted message?"));
    tracing::info!("queue-test: delivered");
    for key in ["question-a", "question-b"] {
        assert_eq!(
            root.execute(said(key, "ignored replay"))
                .await
                .expect("replay")["queued"],
            true
        );
    }
    assert_eq!(egress.sends().len(), 1);
    assert_eq!(plane.prompt_count("command:queued-turn:"), 1);
    log.assert_terminals(&["question-a", "question-b"], "needs_owner", false);
}

#[tokio::test(start_paused = true)]
async fn queued_model_failure_survives_delivery_retry_and_retained_receipt() {
    let log = TurnLog::capture();
    let (dir, plane, egress, approvals, root) = harness().await;
    root.initialize().await.expect("initialize");
    plane.refuse_provider.store(1, Ordering::SeqCst);
    egress.fail.store(true, Ordering::SeqCst);
    for outcome in root
        .execute_batch(vec![
            said("failure-a", "first thing"),
            said("failure-b", "second thing"),
        ])
        .await
    {
        assert_eq!(outcome.expect("admitted")["queued"], true);
    }
    let mut retained = tokio::time::timeout(ANSWER_BOUND, async {
        loop {
            let record = root.load_record().expect("record");
            if let Some(wake) = record
                .wakes
                .iter()
                .find(|wake| queued_delivery_failed(&root, wake))
            {
                assert_eq!(wake.prompt.as_ref().expect("owned asks").asks.len(), 2);
                break wake.clone();
            }
            tokio::time::sleep(StdDuration::from_millis(100)).await;
        }
    })
    .await
    .expect("failed error delivery persisted");
    assert!(egress.sends().is_empty());
    tracing::info!("queue-test: delivery-enabled");
    egress.fail.store(false, Ordering::SeqCst);
    sends_reach(&egress, 1).await;
    root.join_background(StdDuration::from_secs(600)).await;
    assert_eq!(egress.sends().len(), 1);
    let mut record = root.load_record().expect("durable completion");
    assert!(record.wakes.is_empty());
    assert!(record.queued.is_empty());
    // Recreate the crash window after the receipt write but before wake retirement,
    // preserving the real prompt, response, and typed failure from execution.
    retained.reply.as_mut().unwrap().delivered = Some(true);
    record.wakes.push(retained);
    root.store_record(&mut record)
        .expect("retained delivered receipt");
    tracing::info!("queue-test: delivered");
    let restarted = root_in(
        dir.path(),
        Arc::clone(&plane) as Arc<dyn ConversationPlane>,
        egress.clone(),
        approvals.clone(),
    );
    restarted.initialize().await.expect("restart");
    restarted.join_background(StdDuration::from_secs(600)).await;
    assert!(restarted
        .load_record()
        .expect("replayed receipt")
        .wakes
        .is_empty());
    assert_eq!(egress.sends().len(), 1, "delivered failure must not resend");
    assert_eq!(plane.prompt_count("command:queued-turn:"), 1);
    log.assert_terminals(&["failure-a", "failure-b"], "ModelUnavailable", true);
}

/// 12:01 "what's 17 times 23?" arrived while another turn ran: it was
/// folded into that turn as an OMP follow-up, never answered on its own,
/// and the owner got "Still working on that one" after 240 s. Now it waits in
/// the queue, he hears it is coming, and when the running turn ends it is
/// sent as its own prompt and answered under a quote of it.
#[tokio::test(start_paused = true)]
async fn a_message_during_a_running_turn_is_answered_after_it_never_folded() {
    let log = TurnLog::capture();
    let (_dir, plane, egress, _approvals, root) = harness().await;
    root.initialize().await.expect("initialize");
    plane.hold_running.store(true, Ordering::SeqCst);
    root.execute(said("slow", "count the rain"))
        .await
        .expect("handed off");
    let projection = root
        .execute(said("math", "what's 17 times 23?"))
        .await
        .expect("queued");
    assert_eq!(projection["queued"], true);
    assert!(
        plane
            .commands
            .lock()
            .iter()
            .all(|(_, kind)| kind != "follow_up"),
        "never folded into the running turn"
    );
    assert_eq!(
        egress.sends(),
        vec![
            super::super::prompt::LATE_ANSWER_HOLDING.to_owned(),
            super::super::queue::QUEUED_BEHIND_TURN.to_owned(),
        ]
    );
    tracing::info!("queue-test: delivery-enabled");
    plane.hold_running.store(false, Ordering::SeqCst);
    *plane.answer.lock() = "391.".to_owned();
    let session = root.current_vehicle_session().await.unwrap().unwrap();
    plane.finish_turn(&session, "Seven rains.").await;
    sends_reach(&egress, 4).await;
    let sends = egress.sends();
    assert_eq!(
        sends.len(),
        4,
        "holding, queue notice, anchor edit, queued answer; no duplicate POST"
    );
    assert_eq!(
        sends[2],
        edited(1, "Seven rains."),
        "the running turn edits its holding anchor first"
    );
    assert_eq!(
        sends[3],
        edited(2, "> what's 17 times 23?\n391."),
        "queued final edits its own notice anchor"
    );
    let prompts = user_messages(&plane, session).await;
    assert!(
        prompts
            .last()
            .is_some_and(|last| last.ends_with("what's 17 times 23?")),
        "{prompts:?}"
    );
    root.join_background(StdDuration::from_secs(600)).await;
    let record = root.load_record().expect("record");
    assert!(record.queued.is_empty());
    assert!(record
        .recent_answers
        .iter()
        .any(|recent| recent.idempotency_key == "math" && recent.answer == "391."));
    assert!(
        record.wakes.is_empty(),
        "delivered wake was durably retired"
    );
    tracing::info!("queue-test: delivered");
    // A replay of the queued message never prompts again.
    let before = plane.commands.lock().len();
    let replay = root
        .execute(said("math", "what's 17 times 23?"))
        .await
        .expect("replays");
    assert_eq!(replay["replySent"], true);
    assert_eq!(replay["idempotencyKey"], "math");
    assert_eq!(replay["answer"], "> what's 17 times 23?\n391.");
    assert_eq!(egress.sends(), sends, "final replay never sends again");
    assert_eq!(plane.commands.lock().len(), before);
    log.assert_terminals(&["math"], "settled", false);
}

/// The events that waited behind a queued message are in the turn that
/// answers it, and settle once the queue holds them.
#[tokio::test(start_paused = true)]
async fn events_behind_a_queued_message_ride_its_turn_and_settle_once() {
    let (_dir, plane, egress, _approvals, root) = harness().await;
    root.initialize().await.expect("initialize");
    let state = tempfile::tempdir().expect("state");
    let store = Arc::new(crate::schedule::ScheduleStore::open(state.path()).expect("store"));
    let due = jiff::Timestamp::from_millisecond(1_790_000_000_000).unwrap();
    assert!(store.wake_once("ev1", "disk is full", due).unwrap());
    let later = jiff::Timestamp::from_millisecond(due.as_millisecond() + 1).unwrap();
    assert_eq!(store.due_events(later).unwrap().len(), 1);
    let mut ask = said("p2", "ping again");
    ask.harness = crate::runtime::HarnessRide::new(
        vec!["- Mon 10:00: disk is full".to_owned()],
        &store,
        vec!["ev1".to_owned()],
    );
    for outcome in root.execute_batch(vec![said("p1", "ping"), ask]).await {
        assert_eq!(outcome.expect("queued")["queued"], true);
    }
    sends_reach(&egress, 1).await;
    assert!(store.due_events(later).unwrap().is_empty(), "settled");
    let session = root.current_vehicle_session().await.unwrap().unwrap();
    let prompts = user_messages(&plane, session).await;
    let prompt = prompts.last().expect("prompt");
    let (words, digest) = prompt.split_once("harness event(s)").expect("digest");
    assert!(
        words.contains("ping") && !words.contains("disk is full"),
        "{prompt}"
    );
    assert!(digest.contains("disk is full"), "{prompt}");
}

/// the owner's first messages queued behind nothing but each other: the flush is
/// the session's first prompt, and it must run as his own turn. His tools
/// need the accepted plan, his desktop knows it is his ask, and his words
/// (not the harness's rendering of them) reach the brain.
#[tokio::test(start_paused = true)]
async fn a_queued_owner_message_runs_as_his_turn_without_being_resent() {
    let (dir, plane, egress, _approvals, root) = harness().await;
    root.initialize().await.expect("initialize");
    let session = root.current_vehicle_session().await.unwrap().unwrap();
    let batch = vec![
        said("p1", "put the game on the tv"),
        said("p2", "Ask Varun"),
    ];
    for outcome in root.execute_batch(batch).await {
        assert_eq!(outcome.expect("queued")["queued"], true);
    }
    sends_reach(&egress, 1).await;
    root.join_background(StdDuration::from_secs(600)).await;

    let run = RunId::new(format!("run:live:{session}")).expect("run id");
    let ledger = Ledger::open(state_ledger_path(dir.path())).expect("ledger");
    assert!(
        ledger.plan_is_accepted(&run).expect("plan"),
        "the queued turn's tools run under an accepted plan"
    );
    assert_eq!(
        *egress.opened.lock(),
        [(Provenance::Owner, "p2".to_owned())],
        "his latest queued message is the desktop's ask"
    );
    assert_eq!(
        *plane.owner_texts.lock(),
        [Some("put the game on the tv\nAsk Varun".to_owned())]
    );
}

#[tokio::test(start_paused = true)]
async fn queued_messages_survive_a_crash_before_their_prompt_is_admitted() {
    let (dir, plane, egress, approvals, root) = harness().await;
    root.initialize().await.expect("initialize");
    *plane.answer.lock() = "Both done.".to_owned();
    plane.pause_next_prompt.store(true, Ordering::SeqCst);
    root.execute_batch(vec![said("a", "first thing"), said("b", "second thing")])
        .await;
    tokio::time::timeout(ANSWER_BOUND, plane.prompt_paused.notified())
        .await
        .expect("the queue's prompt reaches the pre-admission crash window");
    root.join_background(StdDuration::ZERO).await;
    assert_eq!(
        plane.prompt_count("command:queued-turn:"),
        0,
        "crash preceded admission"
    );
    let restarted = root_in(
        dir.path(),
        Arc::clone(&plane) as Arc<dyn ConversationPlane>,
        egress.clone(),
        approvals.clone(),
    );
    restarted.initialize().await.expect("restart");
    sends_reach(&egress, 1).await;
    assert_eq!(
        egress.sends(),
        vec!["> first thing\n> second thing\nBoth done.".to_owned()]
    );
    assert_eq!(plane.prompt_count("command:queued-turn:"), 1);
    let record = restarted.load_record().expect("record");
    assert!(record.queued.is_empty());
    assert!(record.wakes.is_empty(), "{:?}", record.wakes);
}

#[tokio::test(start_paused = true)]
async fn a_queued_turn_too_big_for_its_vehicle_rolls_and_is_answered() {
    let (_dir, plane, egress, _approvals, root) = harness().await;
    root.initialize().await.expect("initialize");
    let vehicle = root.load_record().expect("record").session_id;
    plane.refuse_context.store(1, Ordering::SeqCst);
    *plane.answer.lock() = "Both done.".to_owned();
    let outcomes = root
        .execute_batch(vec![said("a", "first thing"), said("b", "second thing")])
        .await;
    assert!(outcomes.iter().all(Result::is_ok));
    sends_reach(&egress, 1).await;
    root.join_background(StdDuration::from_secs(600)).await;
    assert_eq!(
        egress.sends(),
        vec!["> first thing\n> second thing\nBoth done.".to_owned()]
    );
    let record = root.load_record().expect("record");
    assert_ne!(record.session_id, vehicle, "the conversation rolled");
    assert!(record.wakes.is_empty(), "{:?}", record.wakes);
    assert!(record.queued.is_empty());
}

#[tokio::test(start_paused = true)]
async fn a_failing_continuation_is_settled_before_the_queue_overtakes_it() {
    let (_dir, plane, egress, approvals, root) = harness().await;
    root.initialize().await.expect("initialize");
    let session = root.current_vehicle_session().await.unwrap().unwrap();
    approvals.status_unavailable.store(true, Ordering::SeqCst);
    let wake = email_retry_wake(&session, "stuck");
    let mut record = root.load_record().expect("record");
    record.wakes.push(wake.clone());
    root.store_record(&mut record).expect("stored");
    root.spawn_wake_task(wake).await;
    *plane.answer.lock() = "Both done.".to_owned();
    root.execute_batch(vec![said("a", "first thing"), said("b", "second thing")])
        .await;
    root.join_background(StdDuration::from_secs(3600)).await;
    let sends = egress.sends();
    assert_eq!(sends.len(), 2, "{sends:?}");
    assert!(
        sends[0].starts_with("I couldn't carry on after your answer about Send this email draft"),
        "{sends:?}"
    );
    assert_eq!(sends[1], "> first thing\n> second thing\nBoth done.");
    assert!(root.load_record().expect("record").wakes.is_empty());
}
