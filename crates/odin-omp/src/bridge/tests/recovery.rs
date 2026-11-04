use super::*;

/// An in-memory ledger holding one idle live session.
pub(super) fn journal(session: &str) -> (Ledger, SessionId) {
    let mut ledger = Ledger::open_in_memory().unwrap();
    ledger
        .connection()
        .execute(
            "INSERT INTO lanes(lane_id,seat_id,template_id,backend,status,created_by,created_at,updated_at) \
             VALUES('lane:test','seat:test','template:test','local_omp','ready','test',\
             '2026-09-29T12:00:00Z','2026-09-29T12:00:00Z')",
            [],
        )
        .unwrap();
    let session_id = SessionId::new(session).unwrap();
    ledger
        .create_live_session(&NewLiveSession {
            session_id: session_id.clone(),
            seat_id: "seat:test".into(),
            project_id: "project:test".into(),
            slice_id: "slice:test".into(),
            lane_id: "lane:test".into(),
            target_node_id: "node:test".into(),
            provider: "provider".into(),
            model: "model".into(),
            title: None,
            manifest: json!({}),
            open_tab: false,
            state: "idle".into(),
            created_at: OffsetDateTime::now_utc(),
        })
        .unwrap();
    (ledger, session_id)
}

pub(super) fn append(ledger: &mut Ledger, session_id: &SessionId, index: usize, body: Value) {
    ledger
        .append_live_event_after_blobs(&NewLiveEvent {
            event_id: EventId::from_parts("test:ev", 1, format!("{index}")).unwrap(),
            session_id: session_id.clone(),
            expected_epoch: 1,
            occurred_at: OffsetDateTime::now_utc(),
            body,
            blob_refs: json!([]),
        })
        .unwrap();
}

/// Reconciliation and the rollover brief read only what they need, so a
/// journal past the full-scan ceiling stays recoverable.
#[test]
fn a_journal_past_the_scan_ceiling_stays_reconcilable_and_briefable() {
    let ceiling = ScanCeiling {
        events: 1_000,
        bytes: 4 * 1024,
    };
    let (mut ledger, session_id) = journal("session:oversized");
    append(
        &mut ledger,
        &session_id,
        0,
        json!({ "kind": "command_issued", "command_id": "command:test:early", "command": "prompt" }),
    );
    let pad = "x".repeat(1024);
    for index in 1..=10 {
        append(
            &mut ledger,
            &session_id,
            index,
            json!({ "kind": "session", "frame": { "type": "turn_end", "pad": pad } }),
        );
    }
    append(
        &mut ledger,
        &session_id,
        11,
        json!({ "kind": "command_response", "command_id": "command:test:early", "command": "prompt", "success": true }),
    );
    assert!(bounded_live_history(&ledger, &session_id, ceiling).is_err());
    let early = CommandId::new("command:test:early").unwrap();
    let never = CommandId::new("command:test:never").unwrap();
    let pending = BTreeSet::from([early.clone(), never.clone()]);
    let (issued, answered) = pending_command_evidence(&ledger, &session_id, &pending).unwrap();
    assert_eq!(issued, BTreeSet::from([early.clone()]));
    assert_eq!(answered.len(), 1);
    assert_eq!(answered[&early]["success"], json!(true));
    let tail = live_history_tail(&ledger, &session_id, 4, ceiling).unwrap();
    let sequences: Vec<i64> = tail.iter().map(|event| event.sequence).collect();
    assert_eq!(sequences, vec![9, 10, 11, 12]);
    let budgeted = live_history_tail(&ledger, &session_id, 1024, ceiling).unwrap();
    assert!(budgeted.len() < 12 && budgeted.last().unwrap().sequence == 12);
}

/// Covered token deletes leave sequence gaps. The history read returns the
/// retained rows by their original sequences and does not treat the gap as
/// corruption. `event_head` stays where the appends left it.
#[test]
fn bounded_history_reads_retained_sequences_without_assuming_density() {
    let (mut ledger, session_id) = journal("session:sparse");
    for index in 1..=5 {
        append(
            &mut ledger,
            &session_id,
            index,
            json!({ "kind": "session", "frame": { "type": "turn_end", "n": index } }),
        );
    }
    let sequences = |ledger: &Ledger| -> Vec<i64> {
        bounded_live_history(ledger, &session_id, DURABLE_HISTORY)
            .unwrap()
            .iter()
            .map(|event| event.sequence)
            .collect()
    };
    assert_eq!(sequences(&ledger), vec![1, 2, 3, 4, 5]);

    let guard: String = ledger
        .connection()
        .query_row(
            "SELECT sql FROM sqlite_master WHERE type='trigger' \
             AND name='live_events_immutable_delete'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    ledger
        .connection()
        .execute_batch("DROP TRIGGER live_events_immutable_delete")
        .unwrap();
    let deleted = ledger
        .connection()
        .execute(
            "DELETE FROM live_events WHERE session_id=?1 AND sequence IN (2, 3)",
            [session_id.to_string()],
        )
        .unwrap();
    assert_eq!(deleted, 2);
    ledger.connection().execute_batch(&guard).unwrap();

    assert_eq!(sequences(&ledger), vec![1, 4, 5]);
    assert_eq!(ledger.reconnect_head(&session_id).unwrap(), 5);
}

/// Rollovers journaled before a crash still count after the counter write was lost.
#[test]
fn the_rollover_count_survives_a_lost_counter_write() {
    let (mut ledger, session) = journal("session:rollover-count");
    for (index, kind) in [
        "rollover_completed",
        "rollover_failed",
        "rollover_completed",
    ]
    .into_iter()
    .enumerate()
    {
        append(&mut ledger, &session, index, json!({ "kind": kind }));
    }
    assert_eq!(restored_rollover_count(&ledger, &session).unwrap(), 2);
}
