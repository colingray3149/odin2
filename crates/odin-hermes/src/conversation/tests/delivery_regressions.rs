use super::*;

#[tokio::test]
async fn independent_roots_choose_one_final_answer_before_sending() {
    let (dir, plane, egress, approvals, first) = harness().await;
    let second = root_in(dir.path(), plane, egress.clone(), approvals);
    let barrier = Arc::new(std::sync::Barrier::new(2));
    let results = std::thread::scope(|scope| {
        let barrier_first = barrier.clone();
        let a = scope.spawn(move || {
            barrier_first.wait();
            first.deliver_final("racing-final", "first answer", None)
        });
        let b = scope.spawn(move || {
            barrier.wait();
            second.deliver_final("racing-final", "second answer", None)
        });
        (a.join().unwrap(), b.join().unwrap())
    });
    assert_ne!(results.0.is_ok(), results.1.is_ok());
    let sent = egress.sends();
    assert_eq!(sent.len(), 1);
    assert_eq!(
        sent[0],
        if results.0.is_ok() {
            "first answer"
        } else {
            "second answer"
        }
    );
}

#[tokio::test(start_paused = true)]
async fn original_key_replays_after_newer_turns_and_root_restart_without_resend() {
    use crate::runtime::ApprovedIntentRoute as _;
    let (dir, plane, egress, approvals, root) = harness().await;
    root.initialize().await.unwrap();
    *plane.answer.lock() = "the original answer".into();
    let original = root.execute(intent("original-replay")).await.unwrap();
    // One more turn than the recent-answers cache holds evicts the original from it.
    for index in 0..=RECENT_ANSWERS {
        *plane.answer.lock() = format!("newer answer {index}");
        root.execute(intent(&format!("newer-{index}")))
            .await
            .unwrap();
    }
    let before = egress.sends();
    let reopened = root_in(dir.path(), plane, egress.clone(), approvals);
    assert_eq!(
        reopened.execute(intent("original-replay")).await.unwrap(),
        original
    );
    assert_eq!(egress.sends(), before);
}

#[tokio::test]
async fn restart_resumes_only_known_missing_tail_and_never_unknown_tail() {
    for unknown in [false, true] {
        let (dir, plane, egress, approvals, root) = harness().await;
        let answer = "chunk boundary text ".repeat(250);
        let projection = serde_json::json!({"answer": answer, "replySent": true});
        *egress.delivery_failure.lock() = Some((
            1,
            if unknown {
                crate::discord::DiscordSendError::ServiceUnavailable
            } else {
                crate::discord::DiscordSendError::Unreachable
            },
        ));
        assert!(root
            .deliver_final("partial-restart", &answer, Some(&projection))
            .is_err());
        let prefix = egress.sends();
        assert_eq!(prefix.len(), 1);
        let reopened = root_in(dir.path(), plane, egress.clone(), approvals);
        let replay = reopened
            .replay_delivery("partial-restart")
            .unwrap()
            .unwrap();
        let after = egress.sends();
        assert_eq!(after[0], prefix[0]);
        if unknown {
            assert_eq!(
                after, prefix,
                "an unresolved reservation cannot grant resend permission"
            );
            assert_eq!(replay["replySent"], false);
            assert!(replay["replyError"].is_string());
        } else {
            assert_eq!(
                after.concat(),
                answer,
                "only the missing physical chunks are posted"
            );
            assert_eq!(replay["replySent"], true);
            assert!(after
                .iter()
                .all(|operation| !operation.starts_with("[edit")));
        }
        let stable = egress.sends();
        reopened.replay_delivery("partial-restart").unwrap();
        assert_eq!(egress.sends(), stable);
    }
}

fn reply_row(dir: &std::path::Path, key: &str) -> serde_json::Value {
    crate::conversation::delivery::inspect(&state_ledger_path(dir))
        .unwrap()
        .as_array()
        .unwrap()
        .iter()
        .find(|reply| reply["key"] == key)
        .cloned()
        .unwrap()
}

/// A settled direct turn whose 3-chunk final stopped at chunk 1 on a known
/// no-dispatch error, with only chunk 0 delivered.
async fn direct_tail_known_unsent(
    key: &str,
) -> (
    TempDir,
    Arc<FakePlane>,
    Arc<FakeEgress>,
    Arc<FakeApprovals>,
    Arc<ConversationRoot>,
    String,
) {
    use crate::runtime::ApprovedIntentRoute as _;
    let (dir, plane, egress, approvals, root) = harness().await;
    root.initialize().await.unwrap();
    let answer = format!("{}end.", "chunk boundary text ".repeat(250));
    *plane.answer.lock() = answer.clone();
    *egress.delivery_failure.lock() = Some((1, crate::discord::DiscordSendError::Unreachable));
    let settled = root.execute(intent(key)).await.unwrap();
    assert_eq!(settled["replySent"], false);
    assert_eq!(egress.sends().len(), 1);
    (dir, plane, egress, approvals, root, answer)
}

/// The background retry itself meets an outcome it cannot know: that
/// reservation stays durable and visible, nothing is resent, and only the
/// direct reply's owner retires, undelivered, so nothing queues behind it.
#[tokio::test(start_paused = true)]
async fn direct_reply_owner_retires_when_its_retry_turns_unknown() {
    use crate::runtime::ApprovedIntentRoute as _;
    let (dir, plane, egress, _approvals, root, _answer) =
        direct_tail_known_unsent("direct-unknown").await;
    let prefix = egress.sends();
    // The retry's first operation is the missing chunk 1.
    *egress.delivery_failure.lock() =
        Some((0, crate::discord::DiscordSendError::ServiceUnavailable));
    tokio::time::sleep(StdDuration::from_secs(60)).await;
    assert_eq!(egress.sends(), prefix);
    let blocked = reply_row(dir.path(), "direct-unknown");
    assert_eq!(blocked["phase"], "finalizing");
    assert_eq!(blocked["pendingKind"], "post");
    assert!(blocked["pendingSequence"].is_u64());
    assert!(root.load_record().unwrap().wakes.is_empty());
    tokio::time::sleep(StdDuration::from_secs(30 * 60)).await;
    assert_eq!(egress.sends(), prefix);
    assert_eq!(reply_row(dir.path(), "direct-unknown"), blocked);
    let replay = root.execute(intent("direct-unknown")).await.unwrap();
    assert_eq!(replay["replySent"], false);
    assert!(replay["replyError"].is_string());
    assert_eq!(egress.sends(), prefix);
    assert_eq!(plane.prompt_count("command:intent:"), 1);
    root.join_background(StdDuration::from_secs(1)).await;
}
