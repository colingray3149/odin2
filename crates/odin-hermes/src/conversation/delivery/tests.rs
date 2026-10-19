use super::*;
use std::sync::Barrier;

struct Fixture {
    directory: tempfile::TempDir,
    id: String,
}

impl Fixture {
    fn new() -> Self {
        let directory = tempfile::tempdir().expect("ledger directory");
        let id = delivery_id("conversation-test", "turn-test").expect("delivery identity");
        let state = State {
            conversation: "conversation-test".into(),
            key: "turn-test".into(),
            channel: "channel-test".into(),
            phase: Phase::Open,
            alias: None,
            prompts: Vec::new(),
            legacy_unknown: false,
            final_answer: None,
            projection: None,
            target: Vec::new(),
            final_rendered: false,
            chunks: Vec::new(),
            generation: 0,
            sequence: 0,
            pending: None,
        };
        Ledger::open(directory.path().join("ledger.sqlite3"))
            .expect("ledger")
            .open_conversation_delivery(
                &id,
                &serde_json::to_string(&state).expect("state JSON"),
                OffsetDateTime::now_utc(),
            )
            .expect("initial durable state");
        Self { directory, id }
    }

    fn handle(&self, answer: Option<&str>) -> ReplyDelivery {
        ReplyDelivery {
            ledger_path: self.directory.path().join("ledger.sqlite3"),
            id: self.id.clone(),
            final_answer: answer.map(str::to_owned),
            generation: Mutex::new(None),
            scheduled: false,
        }
    }

    fn state(&self) -> State {
        let handle = self.handle(None);
        handle
            .load(&handle.ledger().expect("reopen ledger"))
            .expect("load state")
            .1
    }

    fn freeze(&self, answer: &str) -> Arc<ReplyDelivery> {
        ReplyDelivery::open(
            &self.directory.path().join("ledger.sqlite3"),
            "conversation-test",
            "channel-test",
            "turn-test",
            Some(answer),
            Some(&serde_json::json!({"replySent": false, "replyError": "old error"})),
        )
        .expect("freeze final answer")
    }
}

fn message(content: &str) -> OutboundMessage {
    OutboundMessage {
        channel_id: "channel-test".into(),
        content: content.into(),
    }
}

fn reference(id: &str) -> DiscordMessageRef {
    DiscordMessageRef {
        channel_id: "channel-test".into(),
        message_id: id.into(),
    }
}

#[test]
fn separate_handles_race_for_one_durable_reservation() {
    let fixture = Fixture::new();
    let first = fixture.handle(None);
    let second = fixture.handle(None);
    let operation = first
        .prepare(&message("stream"))
        .expect("first plan")
        .operations
        .remove(0);
    assert_eq!(
        second
            .prepare(&message("stream"))
            .expect("second plan")
            .operations,
        vec![operation.clone()]
    );
    let barrier = Barrier::new(2);
    let (left, right) = std::thread::scope(|scope| {
        let left = scope.spawn(|| {
            barrier.wait();
            first.reserve(&operation)
        });
        let right = scope.spawn(|| {
            barrier.wait();
            second.reserve(&operation)
        });
        (
            left.join().expect("first thread"),
            right.join().expect("second thread"),
        )
    });
    assert_eq!(usize::from(left.is_ok()) + usize::from(right.is_ok()), 1);
    let winner = left.or(right).expect("one winner");
    let state = fixture.state();
    assert_eq!(state.sequence, winner.sequence);
    assert_eq!(
        state.pending.expect("durable reservation").operation,
        operation
    );
}

#[test]
fn reopening_a_reserved_operation_does_not_grant_dispatch_permission() {
    let fixture = Fixture::new();
    let handle = fixture.handle(None);
    let operation = handle
        .prepare(&message("stream"))
        .expect("plan")
        .operations
        .remove(0);
    let reservation = handle.reserve(&operation).expect("reserve");
    drop(handle);
    let reopened = fixture.handle(None);
    assert!(reopened.prepare(&message("stream")).is_err());
    assert!(reopened.reserve(&operation).is_err());
    assert!(reopened.complete().is_err());
    assert_eq!(
        fixture.state().pending.expect("still reserved").sequence,
        reservation.sequence
    );
}

#[test]
fn every_chunk_is_acknowledged_before_the_next_reservation() {
    let fixture = Fixture::new();
    let handle = fixture.freeze("answer");
    let content = "a".repeat(MAX_MESSAGE_CODEPOINTS * 2 + 1);
    let plan = handle.prepare(&message(&content)).expect("plan");
    assert!(plan.operations.len() >= 3);
    for (index, operation) in plan.operations.iter().enumerate() {
        let reservation = handle.reserve(operation).expect("reserve next chunk");
        assert!(handle.complete().is_err());
        if let Some(next) = plan.operations.get(index + 1) {
            assert!(handle.reserve(next).is_err());
        }
        assert_eq!(fixture.state().chunks.len(), index);
        handle
            .acknowledge(&reservation, Some(&reference(&format!("message-{index}"))))
            .expect("ack chunk");
        let state = fixture.state();
        assert!(state.pending.is_none());
        assert_eq!(state.chunks.len(), index + 1);
        assert_eq!(state.chunks[index].content, plan.chunks[index]);
    }
    handle.complete().expect("commit");
    let result = handle
        .result()
        .expect("committed result")
        .expect("visible reply");
    assert_eq!(result.anchor, reference("message-0"));
    assert_eq!(result.tails.len(), plan.chunks.len() - 1);
}

#[test]
fn unknown_outcome_stops_before_the_next_chunk_and_survives_reopen() {
    let fixture = Fixture::new();
    let handle = fixture.freeze("answer");
    let content = "x".repeat(MAX_MESSAGE_CODEPOINTS + 1);
    let plan = handle.prepare(&message(&content)).expect("plan");
    let reservation = handle
        .reserve(&plan.operations[0])
        .expect("first reservation");
    handle
        .failed(&reservation, &DiscordSendError::Encoding)
        .expect("record unknown outcome");
    assert!(handle.reserve(&plan.operations[1]).is_err());
    assert!(handle.complete().is_err());
    let reopened = fixture.handle(Some("answer"));
    assert!(reopened.prepare(&message(&content)).is_err());
    let state = fixture.state();
    assert!(state.chunks.is_empty());
    assert_eq!(
        state.pending.expect("unknown retained").sequence,
        reservation.sequence
    );
}

#[test]
fn final_rendered_bytes_are_immutable_across_reopen() {
    let fixture = Fixture::new();
    let handle = fixture.freeze("unscrubbed answer");
    let rendered = "sanitized é\n```rust\nlet x = 1;\n```";
    let plan = handle.prepare(&message(rendered)).expect("first rendering");
    drop(handle);
    let reopened = fixture.handle(Some("unscrubbed answer"));
    let replay = reopened
        .prepare(&message("different sanitizer output"))
        .expect("replay frozen rendering");
    assert_eq!(replay.chunks, plan.chunks);
    assert_eq!(replay.operations, plan.operations);
    assert_eq!(fixture.state().target, vec![rendered.to_owned()]);
}

#[test]
fn prepared_stream_handle_cannot_reserve_after_final_freeze() {
    let fixture = Fixture::new();
    let stream = fixture.handle(None);
    let operation = stream
        .prepare(&message("same bytes"))
        .expect("stream plan")
        .operations
        .remove(0);
    let final_handle = fixture.freeze("same bytes");
    let final_plan = final_handle
        .prepare(&message("same bytes"))
        .expect("final plan");
    assert_eq!(final_plan.operations, vec![operation.clone()]);
    assert!(
        stream.reserve(&operation).is_err(),
        "final freeze must revoke even a prepared stream generation"
    );
    assert!(stream.prepare(&message("late stream")).is_err());
    assert!(fixture.state().pending.is_none());
    final_handle
        .reserve(&operation)
        .expect("final owner retains permission");
}

#[test]
fn quiet_final_commits_without_message_references() {
    let fixture = Fixture::new();
    let handle = fixture.freeze("");
    handle.quiet().expect("quiet commit");
    let reopened = fixture.handle(Some(""));
    reopened.quiet().expect("idempotent quiet commit");
    assert!(reopened.result().expect("committed result").is_none());
    let state = fixture.state();
    assert_eq!(state.phase, Phase::Committed);
    assert!(state.chunks.is_empty());
    assert!(state.pending.is_none());
}

#[test]
fn final_commit_recovers_from_last_ack_without_more_physical_operations() {
    let fixture = Fixture::new();
    let handle = fixture.freeze("answer");
    let plan = handle.prepare(&message("rendered answer")).expect("plan");
    let reservation = handle.reserve(&plan.operations[0]).expect("reserve");
    handle
        .acknowledge(&reservation, Some(&reference("final-message")))
        .expect("last ack");
    assert_eq!(fixture.state().phase, Phase::Finalizing);
    drop(handle);
    let reopened = fixture.handle(Some("answer"));
    let recovery = reopened
        .prepare(&message("changed rendering"))
        .expect("recovery plan");
    assert!(recovery.operations.is_empty());
    assert_eq!(recovery.chunks, plan.chunks);
    reopened.complete().expect("recover commit");
    reopened.complete().expect("idempotent commit");
    let state = fixture.state();
    assert_eq!(state.phase, Phase::Committed);
    assert_eq!(
        state.projection,
        Some(serde_json::json!({"replySent": true}))
    );
    assert_eq!(
        reopened.result().expect("result").expect("visible").anchor,
        reference("final-message")
    );
    assert!(fixture
        .handle(Some("answer"))
        .prepare(&message("third rendering"))
        .expect("committed replay")
        .operations
        .is_empty());
}

#[test]
fn definite_no_effect_failure_allows_fresh_reservation_not_stale_ack() {
    for error in [
        DiscordSendError::CredentialsUnavailable,
        DiscordSendError::GatewayNotOwned,
        DiscordSendError::Unreachable,
        DiscordSendError::RateLimited { retry_after_ms: 50 },
        DiscordSendError::Rejected {
            code: 50013,
            message: "missing permission".into(),
        },
    ] {
        let fixture = Fixture::new();
        let handle = fixture.freeze("answer");
        let operation = handle
            .prepare(&message("answer"))
            .expect("plan")
            .operations
            .remove(0);
        let first = handle.reserve(&operation).expect("first reservation");
        handle.failed(&first, &error).expect("definite no effect");
        assert!(fixture.state().pending.is_none());
        let reopened = fixture.handle(Some("answer"));
        let retry = reopened.prepare(&message("answer")).expect("retry plan");
        assert_eq!(retry.operations, vec![operation.clone()]);
        let second = reopened.reserve(&operation).expect("fresh reservation");
        assert!(second.sequence > first.sequence);
        assert!(handle
            .acknowledge(&first, Some(&reference("stale")))
            .is_err());
        reopened
            .acknowledge(&second, Some(&reference("retried")))
            .expect("fresh ack");
        reopened.complete().expect("commit retry");
        assert_eq!(
            reopened.result().expect("result").expect("visible").anchor,
            reference("retried")
        );
    }
}
