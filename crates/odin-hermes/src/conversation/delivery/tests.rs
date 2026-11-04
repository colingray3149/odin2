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
            sealed_unknown: false,
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

/// A send left by a daemon that died mid-send goes out again on the first
/// try (it used to fail "stale revision" and wait for the 30 s retry); a row
/// sealed unknown is never resent.
#[test]
fn a_dead_daemons_send_resends_at_once_and_a_sealed_one_never() {
    let fixture = Fixture::new();
    let handle = fixture.handle(None);
    let operation = handle
        .prepare(&message("stream"))
        .expect("plan")
        .operations
        .remove(0);
    handle.reserve(&operation).expect("reserve");
    drop(handle);
    let reopened = fixture.handle(None);
    let mut ledger = reopened.ledger().expect("ledger");
    let (row, mut state) = reopened.load(&ledger).expect("state");
    state.pending.as_mut().expect("reserved").dispatcher_pid = u32::MAX;
    persist(&mut ledger, &row, &state).expect("a dead dispatcher's send");
    let plan = reopened
        .prepare(&message("stream, longer"))
        .expect("resent on the first try");
    assert_eq!(plan.chunks, ["stream, longer"]);

    let (row, mut state) = reopened.load(&ledger).expect("state");
    state.sealed_unknown = true;
    persist(&mut ledger, &row, &state).expect("sealed unknown");
    assert!(reopened.prepare(&message("stream")).is_err());
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
        .failed(
            &reservation,
            &DiscordSendError::Encoding("scripted unreadable reply".to_owned()),
        )
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
