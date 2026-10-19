//! Queued owner messages, rapid repeats and new requests while questions remain open.

use super::*;
use crate::runtime::{ApprovedIntentRoute as _, OwnerDecisionRoute as _};

fn said(key: &str, content: &str) -> ApprovedIntentExecution {
    ApprovedIntentExecution {
        content: content.to_owned(),
        ..intent(key)
    }
}

async fn user_messages(plane: &FakePlane, session: LiveSessionId) -> Vec<String> {
    plane
        .history(HistoryQuery {
            session_id: session,
            after: EventSeq::new(0),
            limit: std::num::NonZeroU16::new(500).expect("limit"),
        })
        .await
        .expect("history")
        .events
        .into_iter()
        .filter_map(|event| match event.body {
            LiveEventBody::UserMessage(message) => Some(history::assistant_text(&message)),
            _ => None,
        })
        .collect()
}

/// Capture the real eprintln! boundary without installing a production observer.
fn capture_queued_terminals(test: &str, keys: &[&str]) -> bool {
    capture_queued_outcomes(test, keys, "settled", false)
}

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

fn capture_queued_outcomes(
    test: &str,
    keys: &[&str],
    outcome: &str,
    retained_replay: bool,
) -> bool {
    const CHILD: &str = "ODIN_HERMES_QUEUE_TERMINAL_CHILD";
    if std::env::var(CHILD).as_deref() == Ok(test) {
        // Production terminals are tracing events. Print the message alone
        // so this child still observes them on stderr.
        let filter = tracing_subscriber::EnvFilter::new("info");
        tracing_subscriber::fmt()
            .with_env_filter(filter)
            .with_ansi(false)
            .with_target(false)
            .with_level(false)
            .without_time()
            .with_writer(std::io::stderr)
            .init();
        return false;
    }
    let path = format!("{}::{test}", module_path!());
    // libtest names omit the crate name from module_path!().
    let path = path.split_once("::").expect("test module").1;
    let output = std::process::Command::new(std::env::current_exe().expect("test harness"))
        .args(["--exact", path, "--test-threads", "1", "--nocapture"])
        .env(CHILD, test)
        .output()
        .expect("queue lifecycle child");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "child failed: {}\n{stderr}",
        String::from_utf8_lossy(&output.stdout)
    );
    if outcome == "blocked" {
        assert!(
            stderr.contains("queue-test: blocked retries complete\n"),
            "{stderr}"
        );
        assert!(
            stderr.contains("conversation-wake delivery_blocked"),
            "{stderr}"
        );
        for key in keys {
            assert!(
                !stderr.contains(&format!("odind: conversation-turn key={key} ")),
                "blocked delivery emitted a terminal: {stderr}"
            );
        }
        return true;
    }
    let (before, after) = stderr
        .split_once("queue-test: delivery-enabled\n")
        .expect("child reached delivery boundary");
    let (delivering, replay) = after
        .split_once("queue-test: delivered\n")
        .expect("child reached durable completion");
    for key in keys {
        let prefix = format!("odind: conversation-turn key={key} ");
        assert!(!before.contains(&prefix), "premature terminal: {stderr}");
        if let Some((uncommitted, _)) = delivering.split_once("queue-test: committed\n") {
            assert!(
                !uncommitted.contains(&prefix),
                "terminal before commit: {stderr}"
            );
        }
        let terminals: Vec<_> = delivering
            .lines()
            .filter(|line| line.starts_with(&prefix))
            .collect();
        assert_eq!(
            terminals.len(),
            1,
            "one terminal per admitted key: {stderr}"
        );
        assert!(
            terminals[0].contains(&format!("queued=true outcome={outcome}")),
            "{stderr}"
        );
        if outcome != "settled" {
            assert!(!terminals[0].contains("outcome=settled"), "{stderr}");
        }
        let repeated: Vec<_> = replay
            .lines()
            .filter(|line| line.starts_with(&prefix))
            .collect();
        if retained_replay {
            assert_eq!(
                repeated, terminals,
                "retained receipt preserves the exact outcome: {stderr}"
            );
        } else {
            assert!(
                repeated.is_empty(),
                "replay emitted another terminal: {stderr}"
            );
        }
    }
    true
}

#[tokio::test(start_paused = true)]
async fn queued_question_terminal_waits_for_durable_owner_handoff() {
    if capture_queued_outcomes(
        "queued_question_terminal_waits_for_durable_owner_handoff",
        &["question-a", "question-b"],
        "needs_owner",
        false,
    ) {
        return;
    }
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
    eprintln!("queue-test: delivery-enabled");
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
    eprintln!("queue-test: delivered");
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
}

#[tokio::test(start_paused = true)]
async fn retained_owner_handoff_survives_a_decided_question() {
    if capture_queued_outcomes(
        "retained_owner_handoff_survives_a_decided_question",
        &["decided-a", "decided-b"],
        "needs_owner",
        true,
    ) {
        return;
    }
    retained_owner_handoff_after_question_changes(["decided-a", "decided-b"], true, false).await;
}

#[tokio::test(start_paused = true)]
async fn retained_owner_handoff_survives_an_expired_question() {
    if capture_queued_outcomes(
        "retained_owner_handoff_survives_an_expired_question",
        &["expired-a", "expired-b"],
        "needs_owner",
        true,
    ) {
        return;
    }
    retained_owner_handoff_after_question_changes(["expired-a", "expired-b"], false, false).await;
}

#[tokio::test(start_paused = true)]
async fn retained_owner_handoff_retires_before_invalid_session_refusal() {
    if capture_queued_outcomes(
        "retained_owner_handoff_retires_before_invalid_session_refusal",
        &["invalid-session-a", "invalid-session-b"],
        "needs_owner",
        true,
    ) {
        return;
    }
    retained_owner_handoff_after_question_changes(
        ["invalid-session-a", "invalid-session-b"],
        false,
        true,
    )
    .await;
}

async fn retained_owner_handoff_after_question_changes(
    keys: [&str; 2],
    decided: bool,
    invalid_session: bool,
) {
    let (dir, plane, egress, approvals, root) = harness().await;
    root.initialize().await.expect("initialize");
    plane.auto_reply.store(false, Ordering::SeqCst);
    egress.fail.store(true, Ordering::SeqCst);
    for outcome in root
        .execute_batch(vec![
            said(keys[0], "first thing"),
            said(keys[1], "second thing"),
        ])
        .await
    {
        assert_eq!(outcome.expect("admitted")["queued"], true);
    }
    let pending = tokio::time::timeout(ANSWER_BOUND, async {
        loop {
            let record = root.load_record().expect("record");
            if record
                .questions
                .iter()
                .any(|question| question.delivery_error.is_some())
            {
                let wake = record
                    .wakes
                    .iter()
                    .find(|wake| wake.kind == WakeKind::QueuedAsks)
                    .expect("failed handoff retains wake");
                assert!(wake.completion.is_none());
                assert!(wake.reply.is_none());
                assert_eq!(wake.prompt.as_ref().expect("owned asks").asks.len(), 2);
                break wake.clone();
            }
            tokio::time::sleep(StdDuration::from_millis(100)).await;
        }
    })
    .await
    .expect("failed delivery persisted");
    assert!(egress.sends().is_empty());
    // Stop the retry driver without closing the root. Run the actual handoff
    // directly so its persisted receipt remains available before task retirement.
    let handles = std::mem::take(&mut *root.background.lock().await);
    for handle in handles.values() {
        handle.abort();
    }
    for handle in handles.into_values() {
        let _ = handle.await;
    }
    eprintln!("queue-test: delivery-enabled");
    egress.fail.store(false, Ordering::SeqCst);
    assert!(matches!(
        root.run_queued(&pending).await.expect("successful handoff"),
        super::super::decisions::WakeProgress::Complete
    ));
    let mut record = root
        .load_record()
        .expect("durable handoff before retirement");
    assert_eq!(record.wakes.len(), 1);
    let mut retained = record.wakes[0].clone();
    assert_eq!(retained.completion, Some(WakeCompletion::NeedsOwner));
    assert!(retained.reply.is_none());
    assert_eq!(egress.sends().len(), 1);
    assert!(record.queued.is_empty());
    assert_eq!(record.questions.len(), 1);
    assert!(record.questions[0].delivered_message_id.is_some());
    assert!(!record.questions[0].settled);
    assert_eq!(plane.decide_count(), 0);
    assert_eq!(plane.prompt_count("command:queued-turn:"), 1);
    record.wakes.clear();
    root.store_record(&mut record)
        .expect("retire completed handoff");
    if decided {
        plane.auto_reply.store(true, Ordering::SeqCst);
        root.try_decision(owner_message("yes"))
            .await
            .expect("decision handled")
            .expect("question decided");
        root.join_background(StdDuration::from_secs(600)).await;
        assert_eq!(plane.decide_count(), 1);
    }
    let mut record = root.load_record().expect("changed question");
    if decided {
        assert!(record.questions[0].settled);
    } else {
        record.questions[0].expires_at_unix_ms = 0;
        assert!(!record.questions[0].settled);
    }
    // Recreate the crash window between durable handoff receipt and retirement.
    // The delivered question is no longer actionable when the wake resumes.
    assert!(retained.reply.is_none());
    if invalid_session {
        record.session_id = Some("not-a-session-id".to_owned());
        retained.session_id = "not-a-session-id".to_owned();
        retained.prompt.as_mut().expect("owned asks").session_id = "not-a-session-id".to_owned();
    }
    record.wakes.push(retained);
    root.store_record(&mut record)
        .expect("retained handoff receipt");
    let sends = egress.sends();
    let decisions = plane.decide_count();
    let commands = plane.command_entries("command:").len();
    eprintln!("queue-test: delivered");
    let restarted = root_in(
        dir.path(),
        Arc::clone(&plane) as Arc<dyn ConversationPlane>,
        egress.clone(),
        approvals.clone(),
    );
    if invalid_session {
        let failure = restarted
            .initialize()
            .await
            .expect_err("invalid vehicle still refused");
        assert!(
            failure.to_string().contains("recorded session is invalid"),
            "{failure}"
        );
        assert!(restarted
            .load_record()
            .expect("receipt retired before refusal")
            .wakes
            .is_empty());
        assert_eq!(egress.sends(), sends);
        assert_eq!(plane.decide_count(), decisions);
        assert_eq!(approvals.decide_count(), 0);
        assert_eq!(plane.command_entries("command:").len(), commands);
        return;
    }
    restarted.initialize().await.expect("restart");
    restarted.join_background(StdDuration::from_secs(600)).await;
    let record = restarted.load_record().expect("retired receipt");
    assert!(record.wakes.is_empty());
    assert!(record.queued.is_empty());
    for key in keys {
        assert_eq!(
            restarted
                .execute(said(key, "ignored replay"))
                .await
                .expect("replay")["queued"],
            true
        );
    }
    restarted.join_background(StdDuration::from_secs(600)).await;
    assert_eq!(egress.sends(), sends, "handoff replay sends nothing");
    assert_eq!(
        plane.decide_count(),
        decisions,
        "handoff replay decides nothing"
    );
    assert_eq!(approvals.decide_count(), 0);
    assert_eq!(
        plane.command_entries("command:").len(),
        commands,
        "handoff replay submits no command"
    );
    assert_eq!(plane.prompt_count("command:queued-turn:"), 1);
}

#[tokio::test(start_paused = true)]
async fn queued_model_failure_survives_delivery_retry_and_retained_receipt() {
    if capture_queued_outcomes(
        "queued_model_failure_survives_delivery_retry_and_retained_receipt",
        &["failure-a", "failure-b"],
        "ModelUnavailable",
        true,
    ) {
        return;
    }
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
    eprintln!("queue-test: delivery-enabled");
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
    eprintln!("queue-test: delivered");
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
}

#[tokio::test(start_paused = true)]
async fn queued_normalized_provider_failure_is_model_unavailable_not_a_lost_vehicle() {
    let (_dir, plane, egress, _approvals, root) = harness().await;
    root.initialize().await.expect("initialize");
    plane
        .normalized_turns
        .lock()
        .push_back(failed_provider_turn_frames());
    egress.fail.store(true, Ordering::SeqCst);
    for outcome in root
        .execute_batch(vec![
            said("normalized-a", "first thing"),
            said("normalized-b", "second thing"),
        ])
        .await
    {
        assert_eq!(outcome.expect("admitted")["queued"], true);
    }
    let retained = tokio::time::timeout(ANSWER_BOUND, async {
        loop {
            let record = root.load_record().expect("record");
            if let Some(wake) = record
                .wakes
                .iter()
                .find(|wake| queued_delivery_failed(&root, wake))
            {
                break wake.clone();
            }
            tokio::time::sleep(StdDuration::from_millis(100)).await;
        }
    })
    .await
    .expect("failed error delivery persisted");
    assert_eq!(retained.prompt.as_ref().expect("owned asks").asks.len(), 2);
    assert!(egress.sends().is_empty());
    egress.fail.store(false, Ordering::SeqCst);
    sends_reach(&egress, 1).await;
    root.join_background(StdDuration::from_secs(600)).await;
    let sends = egress.sends();
    let failure = IntentFailure::ModelUnavailable {
        reason: failed_assistant(PARTIAL_TEXT)["errorMessage"]
            .as_str()
            .expect("provider diagnostic")
            .to_owned(),
    };
    assert_eq!(sends.len(), 1);
    assert!(
        sends[0].ends_with(&crate::natural::natural_intent_failure(&failure)),
        "the owner receives the provider-unavailable reply after the queued asks, not a silent-turn fallback"
    );
    assert_ne!(sends[0], super::super::prompt::LATE_ANSWER_LOST);
    assert!(!sends[0].contains(PARTIAL_TEXT), "{sends:?}");
    assert!(
        plane.recoveries.lock().is_empty(),
        "a terminal provider error is not a lost vehicle"
    );
    assert_eq!(plane.prompt_count("command:queued-turn:"), 1);
    let record = root.load_record().expect("durable completion");
    assert!(record.wakes.is_empty());
    assert!(record.queued.is_empty());
}

#[tokio::test(start_paused = true)]
async fn batch_terminals_wait_for_failed_delivery_to_be_retried() {
    if capture_queued_terminals(
        "batch_terminals_wait_for_failed_delivery_to_be_retried",
        &["terminal-a", "terminal-b"],
    ) {
        return;
    }
    let (_dir, plane, egress, _approvals, root) = harness().await;
    root.initialize().await.expect("initialize");
    egress.fail.store(true, Ordering::SeqCst);
    *plane.answer.lock() = "Both done.".to_owned();
    let outcomes = root
        .execute_batch(vec![
            said("terminal-a", "first thing"),
            said("terminal-b", "second thing"),
        ])
        .await;
    assert_eq!(outcomes.len(), 2);
    for outcome in outcomes {
        let projection = outcome.expect("admitted");
        assert_eq!(projection["queued"], true);
        assert_eq!(projection["replySent"], false);
    }
    // Wait for a real failed dispatch in the durable ledger, not merely an
    // observed answer or the non-authoritative lifecycle delivery cache.
    tokio::time::timeout(ANSWER_BOUND, async {
        loop {
            let record = root.load_record().expect("record");
            if record
                .wakes
                .iter()
                .any(|wake| queued_delivery_failed(&root, wake))
            {
                let wake = record
                    .wakes
                    .iter()
                    .find(|wake| wake.kind == WakeKind::QueuedAsks)
                    .unwrap();
                let asks = &wake.prompt.as_ref().expect("owned prompt").asks;
                assert_eq!(asks.len(), 2);
                assert!(asks.iter().any(|ask| ask.idempotency_key == "terminal-a"));
                assert!(asks.iter().any(|ask| ask.idempotency_key == "terminal-b"));
                break;
            }
            tokio::time::sleep(StdDuration::from_millis(100)).await;
        }
    })
    .await
    .expect("failed delivery persisted");
    assert!(egress.sends().is_empty());
    assert_eq!(plane.prompt_count("command:queued-turn:"), 1);
    eprintln!("queue-test: delivery-enabled");
    egress.fail.store(false, Ordering::SeqCst);
    sends_reach(&egress, 1).await;
    root.join_background(StdDuration::from_secs(600)).await;
    assert_eq!(
        egress.sends(),
        vec!["> first thing\n> second thing\nBoth done.".to_owned()]
    );
    let record = root.load_record().expect("durable completion");
    assert!(record.queued.is_empty());
    assert!(
        record.wakes.is_empty(),
        "delivered wake was durably retired"
    );
    eprintln!("queue-test: delivered");
    for key in ["terminal-a", "terminal-b"] {
        let replay = root
            .execute(said(key, "ignored replay"))
            .await
            .expect("replay");
        assert_eq!(replay["queued"], true);
    }
    assert_eq!(plane.prompt_count("command:queued-turn:"), 1);
    assert_eq!(egress.sends().len(), 1);
}

/// The marker follows the real checkpoint complete, not merely the last POST.
struct QueueCommitEgress(Arc<FakeEgress>);

impl ConversationEgress for QueueCommitEgress {
    fn deliver(
        &self,
        content: &str,
        checkpoint: Arc<dyn crate::egress::DeliveryCheckpoint>,
    ) -> Result<crate::egress::ReplyChunks, EgressError> {
        let chunks = self.0.deliver(content, checkpoint)?;
        eprintln!("queue-test: committed");
        Ok(chunks)
    }

    fn typing(&self) -> Result<(), String> {
        Ok(())
    }
}

#[tokio::test(start_paused = true)]
async fn queued_chunk_terminals_follow_commit_without_resending_prefix() {
    if capture_queued_terminals(
        "queued_chunk_terminals_follow_commit_without_resending_prefix",
        &["chunk-a", "chunk-b"],
    ) {
        return;
    }
    let (dir, plane, egress, approvals, _root) = harness().await;
    let root = root_in(
        dir.path(),
        plane.clone(),
        Arc::new(QueueCommitEgress(egress.clone())),
        approvals,
    );
    root.initialize().await.expect("initialize");
    let answer = "chunk boundary text ".repeat(250);
    *plane.answer.lock() = answer.clone();
    *egress.delivery_failure.lock() = Some((1, crate::discord::DiscordSendError::Unreachable));
    eprintln!("queue-test: delivery-enabled");
    for outcome in root
        .execute_batch(vec![said("chunk-a", "first"), said("chunk-b", "second")])
        .await
    {
        assert_eq!(outcome.expect("admitted")["queued"], true);
    }
    root.join_background(StdDuration::from_secs(600)).await;
    let record = root.load_record().expect("durable completion");
    assert!(record.wakes.is_empty());
    assert!(record.queued.is_empty());
    let sent = egress.sends();
    assert!(sent.len() > 1);
    // Queue settlement trims the model text before quoting and chunking it.
    assert_eq!(
        sent.concat(),
        format!("> first\n> second\n{}", answer.trim())
    );
    eprintln!("queue-test: delivered");
    for key in ["chunk-a", "chunk-b"] {
        root.execute(said(key, "ignored replay"))
            .await
            .expect("replay");
    }
    assert_eq!(egress.sends(), sent);
    assert_eq!(plane.prompt_count("command:queued-turn:"), 1);
}

#[tokio::test(start_paused = true)]
async fn queued_unknown_chunk_retains_wake_without_terminal_or_resend() {
    if capture_queued_outcomes(
        "queued_unknown_chunk_retains_wake_without_terminal_or_resend",
        &["unknown-a", "unknown-b"],
        "blocked",
        false,
    ) {
        return;
    }
    let (dir, plane, egress, approvals, root) = harness().await;
    root.initialize().await.expect("initialize");
    *plane.answer.lock() = "chunk boundary text ".repeat(250);
    *egress.delivery_failure.lock() =
        Some((1, crate::discord::DiscordSendError::ServiceUnavailable));
    for outcome in root
        .execute_batch(vec![
            said("unknown-a", "first"),
            said("unknown-b", "second"),
        ])
        .await
    {
        assert_eq!(outcome.expect("admitted")["queued"], true);
    }
    sends_reach(&egress, 1).await;
    // The scripted transport failure is consumed once. Subsequent attempts must
    // remain blocked by the durable reservation even though transport is healthy.
    assert!(egress.delivery_failure.lock().is_none());
    let sent = egress.sends();
    assert_eq!(sent.len(), 1);
    let restarted = root_in(dir.path(), plane.clone(), egress.clone(), approvals);
    for attempt in [&root, &restarted] {
        let mut record = attempt.load_record().expect("retained wake");
        let mut wake = record
            .wakes
            .iter()
            .find(|wake| wake.kind == WakeKind::QueuedAsks)
            .expect("queued wake retained")
            .clone();
        assert_eq!(wake.prompt.as_ref().expect("owned asks").asks.len(), 2);
        assert!(wake.completion.is_none());
        assert_ne!(
            wake.reply.as_ref().expect("stored answer").delivered,
            Some(true)
        );
        for _ in 0..2 {
            assert!(attempt
                .deliver_wake_reply(&mut record, &mut wake, None)
                .is_err());
            assert_eq!(egress.sends(), sent, "unknown tail must never be retried");
        }
        let persisted = attempt.load_record().expect("wake still durable");
        assert_eq!(persisted.wakes.len(), 1);
        assert!(persisted.wakes[0].completion.is_none());
        assert_ne!(
            persisted.wakes[0].reply.as_ref().unwrap().delivered,
            Some(true)
        );
    }
    assert_eq!(plane.prompt_count("command:queued-turn:"), 1);
    eprintln!("queue-test: blocked retries complete");
}

/// 12:01 "what's 17 times 23?" arrived while another turn ran: it was
/// folded into that turn as an OMP follow-up, never answered on its own,
/// and Colin got "Still working on that one" after 240 s. Now it waits in
/// the queue, he hears it is coming, and when the running turn ends it is
/// sent as its own prompt and answered under a quote of it.
#[tokio::test(start_paused = true)]
async fn a_message_during_a_running_turn_is_answered_after_it_never_folded() {
    if capture_queued_terminals(
        "a_message_during_a_running_turn_is_answered_after_it_never_folded",
        &["math"],
    ) {
        return;
    }
    let (dir, plane, egress, approvals, root) = harness().await;
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
    eprintln!("queue-test: delivery-enabled");
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
        sends[2], "[edit 4198498304] Seven rains.",
        "the running turn edits its holding anchor first"
    );
    assert_eq!(
        sends[3], "[edit 4202692608] > what's 17 times 23?\n391.",
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
    eprintln!("queue-test: delivered");
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
    let _ = (dir, approvals);
}

/// 12:05: five rapid "ping"s and "café 日本語" that waited behind a turn
/// became six turns, answered one by one minutes later between newer
/// asks. Messages that waited together are ONE turn: repeats once, in
/// order, one reply quoting them.
#[tokio::test(start_paused = true)]
async fn messages_that_waited_together_are_one_turn() {
    let (dir, plane, egress, approvals, root) = harness().await;
    root.initialize().await.expect("initialize");
    *plane.answer.lock() = "pong \u{2014} and caf\u{e9} \u{65e5}\u{672c}\u{8a9e}.".to_owned();
    let batch = vec![
        said("p1", "ping"),
        said("p2", "ping"),
        said("p3", "Ping"),
        said("cafe", "café 日本語"),
    ];
    let outcomes = root.execute_batch(batch).await;
    assert_eq!(outcomes.len(), 4);
    for outcome in &outcomes {
        assert_eq!(outcome.as_ref().expect("queued")["queued"], true);
    }
    sends_reach(&egress, 1).await;
    assert_eq!(
        egress.sends(),
        vec![
            "> ping\n> café 日本語\npong \u{2014} and caf\u{e9} \u{65e5}\u{672c}\u{8a9e}."
                .to_owned()
        ]
    );
    assert_eq!(plane.prompt_count("command:queued-turn:"), 1, "one turn");
    assert_eq!(plane.prompt_count("command:intent:"), 0);
    let session = root.current_vehicle_session().await.unwrap().unwrap();
    let prompts = user_messages(&plane, session).await;
    let prompt = prompts.last().expect("prompt");
    assert!(
        prompt.contains("1. [") && prompt.contains("sent 3 times] ping"),
        "{prompt}"
    );
    assert!(
        prompt.contains("2. [") && prompt.ends_with("] café 日本語"),
        "{prompt}"
    );
    // Once settled, every original alias replays the final receipt, not its
    // earlier queued placeholder or a new model turn.
    let before = egress.sends();
    let replayed = root.execute_batch(vec![said("p1", "ping")]).await;
    let replay = replayed[0].as_ref().expect("replay");
    assert_eq!(replay["replySent"], true);
    assert_eq!(replay["idempotencyKey"], "p1");
    assert_eq!(
        replay["answer"],
        "> ping\n> café 日本語\npong — and café 日本語."
    );
    assert_eq!(egress.sends(), before);
    assert_eq!(plane.prompt_count("command:queued-turn:"), 1);
    let _ = (dir, approvals);
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

/// 12:06: a new request while a purchase question was open must not
/// answer it. Only a yes/no (or "no to the laptop", naming it) decides; a
/// request that merely opens with "stop"/"ok"/"yes," is an ordinary message
/// and the question stays open, even when it shares a word with it.
#[tokio::test(start_paused = true)]
async fn a_new_request_leaves_an_open_question_open() {
    let (dir, plane, egress, approvals, root) = harness().await;
    root.initialize().await.expect("initialize");
    let session = root.current_vehicle_session().await.unwrap().unwrap();
    approvals.request_labeled(
        "approval:r3:purchase.buy:laptop",
        session,
        "purchase.buy",
        "Buy this item",
        "a laptop under $1500",
    );
    for request in [
        "stop the bagcore one",
        "stop the deploy",
        "yes, remind me about the laptop later",
        "yes to the laptop sleeve",
        "yes to reminding me about the laptop later",
        "yes to the laptop, but only if it costs under $100",
        "yes to the laptop and a mouse",
        "yes to laptops",
        "yes to the laptop under 15000",
        "ok, open three Claude Code sessions on surtr, bagcore and ringd",
        "open three Claude Code sessions: one on surtr, one on bagcore, one on ringd",
    ] {
        assert_eq!(
            root.try_decision(owner_message(request))
                .await
                .expect("handled"),
            None,
            "{request}"
        );
    }
    assert_eq!(approvals.decide_count(), 0, "nothing decided");
    let re_ask = root
        .try_decision(owner_message("no worries"))
        .await
        .expect("handled")
        .expect("a short undecided reply asks once more");
    assert!(re_ask.contains("laptop"), "{re_ask}");
    root.try_decision(owner_message("no to the laptop"))
        .await
        .expect("handled")
        .expect("decided");
    assert_eq!(
        approvals.decisions.lock().clone(),
        vec![(
            "approval:r3:purchase.buy:laptop".to_owned(),
            OwnerDecision::Deny
        )]
    );
    let _ = (dir, plane, egress);
}

/// Quantities, ordinals and ambiguous uses of "one" must not change the pending request by approving it.
#[tokio::test(start_paused = true)]
async fn a_yes_with_a_quantity_in_words_asks_the_question_again() {
    for (detail, label, reply) in [
        (
            "under ten dollars with five dollars shipping",
            "Buy this laptop",
            "yes to the laptop under five dollars",
        ),
        (
            "with one charger",
            "Buy two laptop computers",
            "yes to one laptop",
        ),
        (
            "the one laptop in stock",
            "Buy two laptop computers",
            "yes to the one laptop",
        ),
        (
            "this one laptop model",
            "Buy two laptop computers",
            "yes to this one laptop",
        ),
        (
            "the laptop, one of two",
            "Buy two laptop computers",
            "yes to the laptop, one",
        ),
        (
            "the laptop; one of two",
            "Buy two laptop computers",
            "yes to the laptop; one",
        ),
        (
            "on the thirteenth of October",
            "Renew the lease",
            "yes to the lease on the thirteenth",
        ),
        (
            "laptop one is the affected serial",
            "Replace the laptop",
            "yes to laptop one, thanks",
        ),
        (
            "only a few seats left",
            "Grab the seats",
            "yes to the few seats",
        ),
    ] {
        let (dir, plane, egress, approvals, root) = harness().await;
        root.initialize().await.expect("initialize");
        let session = root.current_vehicle_session().await.unwrap().unwrap();
        approvals.request_labeled(
            "approval:r3:purchase.buy:laptop",
            session,
            "purchase.buy",
            label,
            detail,
        );
        root.try_decision(owner_message(reply))
            .await
            .expect("handled")
            .expect("asked again");
        assert_eq!(approvals.decide_count(), 0, "{reply}: nothing decided");
        let _ = (dir, plane, egress);
    }
}

/// A selection that repeats the question's own "one" is assent, not a new
/// quantity: "yes to the red one, please" decides instead of asking again.
#[tokio::test(start_paused = true)]
async fn a_yes_repeating_the_questions_own_one_decides() {
    let (dir, plane, egress, approvals, root) = harness().await;
    root.initialize().await.expect("initialize");
    let session = root.current_vehicle_session().await.unwrap().unwrap();
    approvals.request_labeled(
        "approval:r3:purchase.buy:laptop",
        session,
        "purchase.buy",
        "Ship the laptop",
        "the red one from the order",
    );
    root.try_decision(owner_message("yes to the red one, please"))
        .await
        .expect("handled")
        .expect("decided");
    assert_eq!(
        approvals.decisions.lock().clone(),
        vec![(
            "approval:r3:purchase.buy:laptop".to_owned(),
            OwnerDecision::AllowOnce
        )]
    );
    let _ = (dir, plane, egress);
}

/// A message sent while the seat waits on Colin's yes/no queues behind it:
/// he is asked the question once more, nothing is decided, and nothing is
/// folded into the waiting turn.
#[tokio::test(start_paused = true)]
async fn a_message_behind_an_open_question_asks_it_once_more() {
    let (dir, plane, egress, approvals, root) = harness().await;
    plane.auto_reply.store(false, Ordering::SeqCst);
    root.initialize().await.expect("initialize");
    let projection = root.execute(intent("gated")).await.expect("asks");
    assert_eq!(projection["waitingOnApproval"], true);
    let projection = root
        .execute(said("new", "what's on my calendar today?"))
        .await
        .expect("queued");
    assert_eq!(projection["queued"], true);
    let last = egress.sends().last().cloned().unwrap_or_default();
    assert!(
        last.contains("yes or no") && last.contains("Send the drafted message?"),
        "{last}"
    );
    assert_eq!(plane.decide_count(), 0);
    assert_eq!(plane.prompt_count(""), 1, "only the first message prompted");
    let _ = (dir, approvals);
}

#[tokio::test(start_paused = true)]
async fn a_queued_turn_too_big_for_its_vehicle_rolls_and_is_answered() {
    let (dir, plane, egress, approvals, root) = harness().await;
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
    let _ = (dir, approvals);
}

/// A queued turn that does not fit even the fresh successor is told once,
/// plainly, and settled — never retried.
#[tokio::test(start_paused = true)]
async fn a_queued_turn_that_never_fits_is_told_once() {
    let (dir, plane, egress, approvals, root) = harness().await;
    root.initialize().await.expect("initialize");
    plane.refuse_context.store(2, Ordering::SeqCst);
    root.execute_batch(vec![said("a", "first thing"), said("b", "second thing")])
        .await;
    sends_reach(&egress, 1).await;
    root.join_background(StdDuration::from_secs(600)).await;
    assert_eq!(
        egress.sends(),
        vec![format!(
            "> first thing\n> second thing\n{}",
            crate::natural::natural_intent_failure(&IntentFailure::ContextExhausted)
        )]
    );
    assert!(root.load_record().expect("record").wakes.is_empty());
    let _ = (dir, approvals);
}

/// An unreadable journal is not evidence that a prompt was never admitted.
#[tokio::test(start_paused = true)]
async fn an_unreadable_admission_keeps_the_prompt_and_its_id() {
    let (dir, plane, egress, approvals, root) = harness().await;
    root.initialize().await.expect("initialize");
    plane.lose_receipt.store(true, Ordering::SeqCst);
    *plane.answer.lock() = "Both done.".to_owned();
    root.execute_batch(vec![said("a", "first thing"), said("b", "second thing")])
        .await;
    sends_reach(&egress, 1).await;
    root.join_background(StdDuration::from_secs(600)).await;
    assert_eq!(
        egress.sends(),
        vec!["> first thing\n> second thing\nBoth done.".to_owned()]
    );
    assert_eq!(plane.prompt_count("command:queued-turn:"), 1);
    let _ = (dir, approvals);
}

#[tokio::test(start_paused = true)]
async fn a_failing_continuation_is_settled_before_the_queue_overtakes_it() {
    let (dir, plane, egress, approvals, root) = harness().await;
    root.initialize().await.expect("initialize");
    let session = root.current_vehicle_session().await.unwrap().unwrap();
    approvals.status_unavailable.store(true, Ordering::SeqCst);
    let wake = PendingWake {
        command_id: "command:conversation-wake:stuck".to_owned(),
        owner_keys: Vec::new(),
        kind: WakeKind::KernelRetry,
        approved: true,
        label: "Send this email draft".to_owned(),
        session_id: session.to_string(),
        decision_cursor: 0,
        approval_id: Some("approval:r3:email.send:stuck".to_owned()),
        prompt: None,
        reply: None,
        completion: None,
        owner_note: None,
        rolled: false,
    };
    let mut record = root.load_record().expect("record");
    record.wakes.push(wake.clone());
    root.store_record(&mut record).expect("stored");
    root.spawn_wake_task(wake).await;
    *plane.answer.lock() = "Both done.".to_owned();
    root.execute_batch(vec![said("a", "first thing"), said("b", "second thing")])
        .await;
    sends_reach(&egress, 2).await;
    root.join_background(StdDuration::from_secs(3600)).await;
    let sends = egress.sends();
    assert_eq!(sends.len(), 2, "{sends:?}");
    assert!(
        sends[0].starts_with("I couldn't carry on after your answer about Send this email draft"),
        "{sends:?}"
    );
    assert_eq!(sends[1], "> first thing\n> second thing\nBoth done.");
    assert!(root.load_record().expect("record").wakes.is_empty());
    let _ = dir;
}

#[tokio::test(start_paused = true)]
async fn a_queued_turn_the_provider_refused_is_told_once() {
    let (dir, plane, egress, approvals, root) = harness().await;
    root.initialize().await.expect("initialize");
    plane.refuse_provider.store(1, Ordering::SeqCst);
    root.execute_batch(vec![said("a", "first thing"), said("b", "second thing")])
        .await;
    sends_reach(&egress, 1).await;
    root.join_background(StdDuration::from_secs(600)).await;
    let sends = egress.sends();
    assert_eq!(sends.len(), 1, "{sends:?}");
    assert!(
        sends[0].starts_with("> first thing\n> second thing\n"),
        "{sends:?}"
    );
    assert!(root.load_record().expect("record").wakes.is_empty());
    let _ = (dir, approvals);
}

#[tokio::test(start_paused = true)]
async fn a_failed_continuation_reply_is_sent_again_before_the_queue() {
    let (dir, plane, egress, approvals, root) = harness().await;
    root.initialize().await.expect("initialize");
    let session = root.current_vehicle_session().await.unwrap().unwrap();
    let wake = PendingWake {
        command_id: "command:conversation-wake:unsent".to_owned(),
        owner_keys: Vec::new(),
        kind: WakeKind::KernelRetry,
        approved: true,
        label: "Send this email draft".to_owned(),
        session_id: session.to_string(),
        decision_cursor: 0,
        approval_id: Some("approval:r3:email.send:unsent".to_owned()),
        prompt: None,
        reply: Some(super::super::ContinuationReply {
            answer: "Sent it.".to_owned(),
            delivered: Some(false),
            terminal_outcome: None,
        }),
        completion: None,
        owner_note: None,
        rolled: false,
    };
    let mut record = root.load_record().expect("record");
    record.wakes.push(wake.clone());
    root.store_record(&mut record).expect("stored");
    egress.fail.store(true, Ordering::SeqCst);
    root.spawn_wake_task(wake).await;
    *plane.answer.lock() = "Both done.".to_owned();
    root.execute_batch(vec![said("a", "first thing"), said("b", "second thing")])
        .await;
    tokio::time::sleep(StdDuration::from_secs(10)).await;
    egress.fail.store(false, Ordering::SeqCst);
    sends_reach(&egress, 2).await;
    root.join_background(StdDuration::from_secs(3600)).await;
    let sends = egress.sends();
    assert_eq!(
        sends,
        vec![
            "Sent it.".to_owned(),
            "> first thing\n> second thing\nBoth done.".to_owned()
        ]
    );
    assert!(root.load_record().expect("record").wakes.is_empty());
    let _ = (dir, approvals);
}

#[tokio::test(start_paused = true)]
async fn a_queued_turn_on_an_untold_question_never_holds_the_next_message() {
    let (dir, plane, egress, approvals, root) = harness().await;
    root.initialize().await.expect("initialize");
    plane.auto_reply.store(false, Ordering::SeqCst);
    egress.fail.store(true, Ordering::SeqCst);
    root.execute_batch(vec![said("a", "first thing"), said("b", "second thing")])
        .await;
    while plane.prompt_count("command:queued-turn:") == 0 {
        tokio::time::sleep(StdDuration::from_millis(100)).await;
    }
    tokio::time::sleep(StdDuration::from_secs(2)).await;
    let started = tokio::time::Instant::now();
    let projection = root
        .execute(said("c", "third thing"))
        .await
        .expect("queued");
    assert_eq!(projection["queued"], true);
    assert!(
        started.elapsed() < ANSWER_BOUND / 4,
        "waited {:?} for the conversation lock",
        started.elapsed()
    );
    let _ = (dir, approvals);
}

#[tokio::test(start_paused = true)]
async fn an_older_queued_reply_goes_before_a_newer_batch() {
    let (dir, plane, egress, approvals, root) = harness().await;
    root.initialize().await.expect("initialize");
    let session = root.current_vehicle_session().await.unwrap().unwrap();
    let older = PendingWake {
        command_id: "command:queued:older".to_owned(),
        owner_keys: vec!["o1".to_owned()],
        kind: WakeKind::QueuedAsks,
        approved: true,
        label: String::new(),
        session_id: session.to_string(),
        decision_cursor: 0,
        approval_id: None,
        prompt: Some(InFlightPrompt {
            idempotency_key: "command:queued:older".to_owned(),
            content: "older thing".to_owned(),
            command_id: "command:queued-turn:older".to_owned(),
            session_id: session.to_string(),
            kind: InFlightKind::Prompt,
            expected_epoch: 1,
            event_cursor: 0,
            phase: InFlightPhase::Sent,
            clock: None,
            asks: vec![QueuedAsk {
                idempotency_key: "o1".to_owned(),
                content: "older thing".to_owned(),
                at_unix_ms: 0,
            }],
        }),
        reply: Some(super::super::ContinuationReply {
            answer: "> older thing\nOlder done.".to_owned(),
            delivered: Some(false),
            terminal_outcome: Some("settled".to_owned()),
        }),
        completion: None,
        owner_note: None,
        rolled: false,
    };
    let mut record = root.load_record().expect("record");
    record.wakes.push(older.clone());
    root.store_record(&mut record).expect("stored");
    egress.fail.store(true, Ordering::SeqCst);
    root.spawn_wake_task(older).await;
    *plane.answer.lock() = "Both done.".to_owned();
    root.execute_batch(vec![said("a", "first thing"), said("b", "second thing")])
        .await;
    tokio::time::sleep(StdDuration::from_secs(10)).await;
    assert_eq!(
        plane.prompt_count("command:queued-turn:"),
        0,
        "the newer batch waits for the older reply"
    );
    egress.fail.store(false, Ordering::SeqCst);
    sends_reach(&egress, 2).await;
    root.join_background(StdDuration::from_secs(3600)).await;
    assert_eq!(
        egress.sends(),
        vec![
            "> older thing\nOlder done.".to_owned(),
            "> first thing\n> second thing\nBoth done.".to_owned()
        ]
    );
    assert!(root.load_record().expect("record").wakes.is_empty());
    let before = egress.sends();
    let reopened = root_in(dir.path(), plane.clone(), egress.clone(), approvals.clone());
    for key in ["o1", "a", "b"] {
        let replay = reopened
            .execute(said(key, "must not become a new turn"))
            .await
            .expect("covered original-key receipt");
        assert_eq!(replay["replySent"], true, "{key}: {replay}");
    }
    assert_eq!(egress.sends(), before);
    let _ = (dir, approvals);
}

/// A number appearing elsewhere in the question must not authorize a changed quantity or price.
#[tokio::test(start_paused = true)]
async fn a_yes_with_a_number_asks_the_question_again() {
    let (dir, plane, egress, approvals, root) = harness().await;
    root.initialize().await.expect("initialize");
    let session = root.current_vehicle_session().await.unwrap().unwrap();
    approvals.request_labeled(
        "approval:r3:purchase.buy:laptop",
        session,
        "purchase.buy",
        "Buy this laptop",
        "under $1,500 with a $500 deposit",
    );
    let again = root
        .try_decision(owner_message("yes to the laptop under $500"))
        .await
        .expect("handled")
        .expect("asked again");
    assert!(again.contains("$1,500"), "{again}");
    assert_eq!(approvals.decide_count(), 0, "nothing decided");
    root.try_decision(owner_message("yes to the laptop"))
        .await
        .expect("handled")
        .expect("decided");
    assert_eq!(
        approvals.decisions.lock().clone(),
        vec![(
            "approval:r3:purchase.buy:laptop".to_owned(),
            OwnerDecision::AllowOnce
        )]
    );
    let _ = (dir, plane, egress);
}

/// A Failed session is settled without waiting for Idle. The queue is
/// taken, and the original ask keys replay the failure.
#[tokio::test(start_paused = true)]
async fn a_failed_session_settles_the_queue_instead_of_waiting() {
    let (dir, plane, egress, approvals, root) = harness().await;
    root.initialize().await.expect("initialize");
    let session = root.current_vehicle_session().await.unwrap().unwrap();
    plane.set_state(&session, LiveSessionState::Failed);
    let mut record = root.load_record().expect("record");
    record.queued.push(QueuedAsk {
        idempotency_key: "waiting".to_owned(),
        content: "the thing I asked".to_owned(),
        at_unix_ms: 0,
    });
    record.queued.push(QueuedAsk {
        idempotency_key: "waiting-too".to_owned(),
        content: "the other thing".to_owned(),
        at_unix_ms: 1,
    });
    record.wakes.push(PendingWake {
        command_id: "command:queued:failed-session".to_owned(),
        owner_keys: Vec::new(),
        kind: WakeKind::QueuedAsks,
        approved: true,
        label: String::new(),
        session_id: session.to_string(),
        decision_cursor: 0,
        approval_id: None,
        prompt: None,
        reply: None,
        completion: None,
        owner_note: None,
        rolled: false,
    });
    root.store_record(&mut record).expect("stored");
    let wake = record
        .wakes
        .iter()
        .find(|wake| wake.command_id == "command:queued:failed-session")
        .cloned()
        .expect("queued wake");
    let started = tokio::time::Instant::now();
    root.spawn_wake_task(wake).await;
    root.join_background(StdDuration::from_secs(30)).await;
    assert!(
        started.elapsed() < StdDuration::from_secs(1),
        "did not wait for Idle"
    );
    let sends = egress.sends();
    assert_eq!(sends.len(), 1, "{sends:?}");
    assert!(
        sends[0].contains("failed"),
        "the spawned wake delivered the failure: {sends:?}"
    );
    let record = root.load_record().expect("record");
    assert!(record.wakes.is_empty(), "the settled wake does not retry");
    assert!(record.queued.is_empty(), "settlement took the queue");
    assert!(
        plane.commands.lock().is_empty(),
        "nothing was sent to the failed session"
    );
    for key in ["waiting", "waiting-too"] {
        let replay = root
            .replay_delivery(key)
            .expect("replay")
            .expect("failure receipt");
        assert!(
            replay["answer"]
                .as_str()
                .is_some_and(|answer| answer.contains("failed")),
            "original key replays the failure: {replay}"
        );
    }
    assert_eq!(egress.sends().len(), 1, "replay does not send again");
    assert!(
        plane.commands.lock().is_empty(),
        "replay sends nothing to the failed session"
    );
    let _ = (dir, approvals);
}

/// A Failed session settles a continuation that was waiting for Idle.
/// The failure is reported; the wait does not run out the answer bound.
#[tokio::test(start_paused = true)]
async fn a_failed_session_settles_a_waiting_continuation() {
    let (dir, plane, egress, approvals, root) = harness().await;
    root.initialize().await.expect("initialize");
    let session = root.current_vehicle_session().await.unwrap().unwrap();
    plane.set_state(&session, LiveSessionState::Running);
    approvals.decisions.lock().push((
        "approval:r3:email.send:down".to_owned(),
        OwnerDecision::AllowOnce,
    ));
    let wake = PendingWake {
        command_id: "command:conversation-wake:down".to_owned(),
        owner_keys: Vec::new(),
        kind: WakeKind::KernelRetry,
        approved: true,
        label: "Send this email draft".to_owned(),
        session_id: session.to_string(),
        decision_cursor: 0,
        approval_id: Some("approval:r3:email.send:down".to_owned()),
        prompt: None,
        reply: None,
        completion: None,
        owner_note: None,
        rolled: false,
    };
    let mut record = root.load_record().expect("record");
    record.wakes.push(wake.clone());
    root.store_record(&mut record).expect("stored");
    let root = Arc::clone(&root);
    let session_for_fail = session;
    let plane_for_fail = Arc::clone(&plane);
    let waiting = tokio::spawn(async move { root.run_wake(&wake).await });
    tokio::task::yield_now().await;
    plane_for_fail.set_state(&session_for_fail, LiveSessionState::Failed);
    tokio::time::advance(StdDuration::from_millis(100)).await;
    let started = tokio::time::Instant::now();
    let error = match waiting.await.expect("wake task") {
        Err(error) => error,
        Ok(_) => panic!("a failed session is settled, not waited on"),
    };
    assert!(
        error.contains("failed"),
        "the failure is reported plainly: {error}"
    );
    assert!(
        started.elapsed() < StdDuration::from_secs(1),
        "did not wait out the answer bound"
    );
    let _ = (dir, egress, approvals);
}
