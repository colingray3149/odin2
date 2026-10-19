use super::*;
use crate::egress::{DeliveryCheckpoint, OutboundMessage};

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
    for index in 0..40 {
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

#[tokio::test]
async fn quiet_commit_replays_without_a_physical_message() {
    let (dir, plane, egress, approvals, root) = harness().await;
    let projection = serde_json::json!({"quiet": true, "replySent": false});
    assert!(root
        .deliver_final("quiet-replay", "", Some(&projection))
        .unwrap()
        .is_none());
    let reopened = root_in(dir.path(), plane, egress.clone(), approvals);
    assert_eq!(
        reopened.replay_delivery("quiet-replay").unwrap(),
        Some(projection)
    );
    assert!(egress.sends().is_empty());
}

#[tokio::test]
async fn final_freeze_rejects_a_stale_stream_handle_without_editing() {
    let (_dir, _plane, egress, _approvals, root) = harness().await;
    let stream = root.reply_delivery("frozen-stream", None, None).unwrap();
    egress.deliver("draft", stream.clone()).unwrap();
    let answer = root
        .deliver_final("frozen-stream", "final words", None)
        .unwrap()
        .unwrap();
    assert_eq!(answer.len(), 1);
    let before = egress.sends();
    assert!(stream
        .prepare(&OutboundMessage {
            channel_id: CHANNEL.into(),
            content: "late draft".into(),
        })
        .is_err());
    assert!(egress.deliver("late draft", stream).is_err());
    assert_eq!(egress.sends(), before);
    assert!(root
        .deliver_final("frozen-stream", "different final words", None)
        .is_err());
    assert_eq!(egress.sends(), before);
}

#[tokio::test]
async fn startup_resumes_a_frozen_final_without_a_new_terminal_producer() {
    let (dir, plane, egress, approvals, root) = harness().await;
    let projection = serde_json::json!({"answer": "frozen before dispatch", "replySent": true});
    root.reply_delivery(
        "startup-frozen",
        Some("frozen before dispatch"),
        Some(&projection),
    )
    .unwrap();
    assert!(egress.sends().is_empty());
    drop(root);
    let reopened = root_in(dir.path(), plane, egress.clone(), approvals);
    reopened.resume_deliveries().unwrap();
    assert_eq!(egress.sends(), ["frozen before dispatch"]);
    assert_eq!(
        reopened.replay_delivery("startup-frozen").unwrap(),
        Some(projection)
    );
    reopened.resume_deliveries().unwrap();
    assert_eq!(egress.sends(), ["frozen before dispatch"]);
}

#[tokio::test]
async fn startup_commits_last_ack_without_repeating_the_physical_operation() {
    let (dir, plane, egress, approvals, root) = harness().await;
    let projection = serde_json::json!({"answer": "acknowledged final", "replySent": true});
    let delivery = root
        .reply_delivery(
            "startup-last-ack",
            Some("acknowledged final"),
            Some(&projection),
        )
        .unwrap();
    let plan = delivery
        .prepare(&OutboundMessage {
            channel_id: CHANNEL.to_owned(),
            content: "acknowledged final".to_owned(),
        })
        .unwrap();
    assert_eq!(plan.operations.len(), 1);
    let reservation = delivery.reserve(&plan.operations[0]).unwrap();
    // Model process loss after the real fake POST acknowledgement but before complete.
    let sent = egress.post("acknowledged final");
    delivery.acknowledge(&reservation, Some(&sent)).unwrap();
    drop(delivery);
    drop(root);
    let reopened = root_in(dir.path(), plane, egress.clone(), approvals);
    reopened.resume_deliveries().unwrap();
    assert_eq!(egress.sends(), ["acknowledged final"]);
    assert_eq!(
        reopened.replay_delivery("startup-last-ack").unwrap(),
        Some(projection)
    );
    reopened.resume_deliveries().unwrap();
    assert_eq!(egress.sends(), ["acknowledged final"]);
}

/// A direct turn whose final delivery stopped on a known no-dispatch error
/// still owes Colin only its frozen missing tail: the root's own background
/// ownership delivers it on its normal cadence — no restart, no owner
/// resubmission, no second model turn. A reservation whose outcome is
/// unknown is never resent and stays visible.
#[tokio::test(start_paused = true)]
async fn direct_turn_known_unsent_tail_continues_without_restart_or_replay() {
    use crate::runtime::ApprovedIntentRoute as _;
    for unknown in [false, true] {
        let (dir, plane, egress, _approvals, root) = harness().await;
        root.initialize().await.unwrap();
        let answer = format!("{}end.", "chunk boundary text ".repeat(250));
        *plane.answer.lock() = answer.clone();
        *egress.delivery_failure.lock() = Some((
            1,
            if unknown {
                crate::discord::DiscordSendError::ServiceUnavailable
            } else {
                crate::discord::DiscordSendError::Unreachable
            },
        ));
        let settled = root.execute(intent("direct-tail")).await.unwrap();
        assert_eq!(settled["replySent"], false);
        assert!(settled["replyError"].is_string());
        let prefix = egress.sends();
        assert_eq!(prefix.len(), 1);
        let row = || {
            crate::conversation::delivery::inspect(&state_ledger_path(dir.path()))
                .unwrap()
                .as_array()
                .unwrap()
                .iter()
                .find(|reply| reply["key"] == "direct-tail")
                .cloned()
                .unwrap()
        };
        if unknown {
            tokio::time::sleep(StdDuration::from_secs(30 * 60)).await;
            assert_eq!(
                egress.sends(),
                prefix,
                "an unresolved reservation cannot grant resend permission"
            );
            let blocked = row();
            assert_eq!(blocked["phase"], "finalizing");
            assert_eq!(blocked["pendingKind"], "post");
            assert!(blocked["pendingSequence"].is_u64());
            let replay = root.execute(intent("direct-tail")).await.unwrap();
            assert_eq!(replay["replySent"], false);
            assert!(replay["replyError"].is_string());
            assert_eq!(egress.sends(), prefix);
            assert_eq!(row()["pendingSequence"], blocked["pendingSequence"]);
        } else {
            // The transport stays down through background attempts: each is
            // a known no-dispatch failure, never a dispatch or a guess.
            egress.fail.store(true, Ordering::SeqCst);
            tokio::time::sleep(StdDuration::from_secs(5 * 60)).await;
            assert_eq!(egress.sends(), prefix);
            assert!(row()["pendingSequence"].is_null());
            egress.fail.store(false, Ordering::SeqCst);
            for _ in 0..15 * 60 {
                if egress.sends().len() >= 3 {
                    break;
                }
                tokio::time::sleep(StdDuration::from_secs(1)).await;
            }
            let sent = egress.sends();
            assert_eq!(sent[0], prefix[0]);
            assert_eq!(
                sent.concat(),
                answer,
                "only the known missing frozen chunks are posted"
            );
            assert!(sent.iter().all(|operation| !operation.starts_with('[')));
            assert_eq!(row()["phase"], "committed");
            tokio::time::sleep(StdDuration::from_secs(30 * 60)).await;
            assert_eq!(egress.sends(), sent);
            let replay = root.execute(intent("direct-tail")).await.unwrap();
            assert_eq!(replay["replySent"], true);
            assert_eq!(egress.sends(), sent);
        }
        assert_eq!(plane.prompt_count("command:intent:"), 1);
        assert!(plane.command_entries("command:silent:").is_empty());
        root.join_background(StdDuration::from_secs(1)).await;
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

/// Shutdown aborts the tracked owner but not the debt: the durable plan and
/// frozen row survive, and a restart delivers only the missing tail and
/// reports the canonical delivered result without a second model turn.
#[tokio::test(start_paused = true)]
async fn owned_shutdown_keeps_a_direct_reply_owed_until_restart() {
    use crate::runtime::ApprovedIntentRoute as _;
    let (dir, plane, egress, approvals, root, answer) =
        direct_tail_known_unsent("direct-shutdown").await;
    let prefix = egress.sends();
    egress.fail.store(true, Ordering::SeqCst);
    root.join_background(StdDuration::ZERO).await;
    let record = root.load_record().unwrap();
    assert_eq!(record.wakes.len(), 1);
    assert_eq!(record.wakes[0].owner_keys, ["direct-shutdown"]);
    assert_eq!(record.wakes[0].reply.as_ref().unwrap().delivered, None);
    let owed = reply_row(dir.path(), "direct-shutdown");
    assert_eq!(owed["phase"], "finalizing");
    assert!(owed["pendingSequence"].is_null());
    assert_eq!(egress.sends(), prefix);
    egress.fail.store(false, Ordering::SeqCst);
    let restarted = root_in(
        dir.path(),
        Arc::clone(&plane) as Arc<dyn ConversationPlane>,
        egress.clone(),
        approvals.clone(),
    );
    restarted.initialize().await.expect("restart");
    sends_reach(&egress, 3).await;
    restarted.join_background(StdDuration::from_secs(600)).await;
    let sent = egress.sends();
    assert_eq!(sent[0], prefix[0]);
    assert_eq!(sent.concat(), answer);
    let record = restarted.load_record().unwrap();
    assert!(record.wakes.is_empty(), "{:?}", record.wakes);
    let cached = record.last_projection.unwrap();
    assert_eq!(cached["replySent"], true);
    assert!(cached.get("replyError").is_none());
    let replay = restarted.execute(intent("direct-shutdown")).await.unwrap();
    assert_eq!(replay["replySent"], true);
    assert_eq!(egress.sends(), sent);
    assert_eq!(plane.prompt_count("command:intent:"), 1);
}
