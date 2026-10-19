use super::{retain_events, sessions_with_covered_token_rows};

fn rfc3339(at: time::OffsetDateTime) -> String {
    at.format(&time::format_description::well_known::Rfc3339)
        .unwrap()
}

/// A covered token row drops as soon as a later `message_end` exists, including
/// a recent or still-live session. The immutability guard is back afterwards.
#[test]
fn covered_token_rows_drop_when_the_message_ends() {
    let dir = tempfile::tempdir().unwrap();
    let ledger = dir.path().join("ledger.sqlite3");
    drop(odin_ledger::Ledger::open(&ledger).expect("ledger schema"));
    let now = time::OffsetDateTime::now_utc();
    let at = |days: i64| rfc3339(now - time::Duration::days(days));
    let db = rusqlite::Connection::open(&ledger).unwrap();
    db.execute(
        "INSERT INTO lanes(lane_id,seat_id,project_id,template_id,backend,created_by,created_at,updated_at) \
         VALUES('gungnir-odin','gungnir','odin','fixture','local_omp','fixture',?1,?1)",
        [at(60)],
    )
    .unwrap();
    for (session, state, age) in [
        ("old", "ended", 40),
        ("recent", "ended", 5),
        ("live", "ready", 40),
    ] {
        db.execute(
            "INSERT INTO live_sessions (session_id,seat_id,project_id,slice_id,lane_id,\
             target_node_id,provider,model,open_tab,state,created_at,updated_at) \
             VALUES (?1,'gungnir','odin','gungnir-build','gungnir-odin','mini','gateway',\
             'glm-flash',0,?2,?3,?3)",
            rusqlite::params![session, state, at(age)],
        )
        .unwrap();
        for (sequence, frame) in [
            (1, "message_update"),
            (2, "message_update"),
            (3, "message_end"),
        ] {
            db.execute(
                "INSERT INTO live_events (event_id,session_id,epoch,sequence,occurred_at,body_json) \
                 VALUES (?1,?2,1,?3,?4,?5)",
                rusqlite::params![
                    format!("{session}-{sequence}"),
                    session,
                    sequence,
                    at(age),
                    format!(r#"{{"kind":"session","frame":{{"type":"{frame}"}}}}"#),
                ],
            )
            .unwrap();
        }
    }
    drop(db);

    let covered = sessions_with_covered_token_rows(&ledger).unwrap();
    assert_eq!(covered, vec!["live", "old", "recent"]);
    assert_eq!(
        retain_events(&covered, &ledger).unwrap(),
        6,
        "each covered token row goes; each final message stays"
    );
    let db = rusqlite::Connection::open(&ledger).unwrap();
    let count = |session: &str| -> i64 {
        db.query_row(
            "SELECT COUNT(*) FROM live_events WHERE session_id=?1",
            [session],
            |row| row.get(0),
        )
        .unwrap()
    };
    assert_eq!(count("old"), 1, "the final message stays");
    assert_eq!(
        count("recent"),
        1,
        "a recent finished message is not kept as tokens"
    );
    assert_eq!(
        count("live"),
        1,
        "a live session drops tokens its message_end already covers"
    );
    let deleted = db.execute("DELETE FROM live_events WHERE session_id='recent'", []);
    assert!(deleted.is_err(), "the journal is immutable again");
    drop(db);
    assert_eq!(
        retain_events(&covered, &ledger).unwrap(),
        0,
        "a second pass has nothing left to drop"
    );
}

/// Covered token rows drop. The finished message, tools, errors, and an
/// update with no later `message_end` in that epoch stay. Sequences and
/// `event_head` are not rewritten, so the existing history read still
/// returns the retained rows.
#[test]
fn retention_keeps_complete_frames_and_unfinished_updates_without_renumbering() {
    let dir = tempfile::tempdir().unwrap();
    let ledger_path = dir.path().join("ledger.sqlite3");
    drop(odin_ledger::Ledger::open(&ledger_path).expect("ledger schema"));
    let now = time::OffsetDateTime::now_utc();
    let at = rfc3339(now - time::Duration::days(40));
    let db = rusqlite::Connection::open(&ledger_path).unwrap();
    db.execute(
        "INSERT INTO lanes(lane_id,seat_id,project_id,template_id,backend,created_by,created_at,updated_at) \
         VALUES('gungnir-odin','gungnir','odin','fixture','local_omp','fixture',?1,?1)",
        [&at],
    )
    .unwrap();
    db.execute(
        "INSERT INTO live_sessions (session_id,seat_id,project_id,slice_id,lane_id,\
         target_node_id,provider,model,epoch,event_head,terminal_head,open_tab,state,\
         created_at,updated_at) \
         VALUES ('session:retained','gungnir','odin','gungnir-build','gungnir-odin','mini',\
         'gateway','glm-flash',2,10,0,0,'ended',?1,?1)",
        [&at],
    )
    .unwrap();
    db.execute(
        "INSERT INTO live_commands (command_id,session_id,expected_epoch,expected_event_head,\
         body_json,issued_at) VALUES ('command:retained','session:retained',2,10,?1,?2)",
        (r#"{"command":"prompt"}"#, &at),
    )
    .unwrap();
    let rows = [
        (
            1,
            1,
            serde_json::json!({"kind":"session","frame":{"type":"tool_execution_end","toolName":"read"}}),
        ),
        (
            2,
            1,
            serde_json::json!({"kind":"session","frame":{"type":"message_update","delta":"tok"}}),
        ),
        (
            3,
            1,
            serde_json::json!({"kind":"session","frame":{"type":"message_update","delta":"en"}}),
        ),
        (
            4,
            1,
            serde_json::json!({"kind":"session","frame":{"type":"message_end","message":{"role":"assistant","content":[{"type":"text","text":"the finished answer"}]}}}),
        ),
        (
            5,
            2,
            serde_json::json!({"kind":"session","frame":{"type":"tool_execution_update","toolName":"read"}}),
        ),
        (
            6,
            1,
            serde_json::json!({"kind":"session","frame":{"type":"message_update","delta":"epoch-one-unfinished"}}),
        ),
        (
            7,
            2,
            serde_json::json!({"kind":"extension_error","error":"child failed"}),
        ),
        (
            8,
            2,
            serde_json::json!({"kind":"session","frame":{"type":"message_update","delta":"covered-later"}}),
        ),
        (
            9,
            2,
            serde_json::json!({"kind":"session","frame":{"type":"message_end","message":{"role":"assistant","content":[{"type":"text","text":"epoch two answer"}]}}}),
        ),
        (
            10,
            2,
            serde_json::json!({"kind":"session","frame":{"type":"message_update","delta":"still streaming"}}),
        ),
    ];
    for (sequence, epoch, body) in rows {
        db.execute(
            "INSERT INTO live_events (event_id,session_id,epoch,sequence,occurred_at,body_json) \
             VALUES (?1,'session:retained',?2,?3,?4,?5)",
            rusqlite::params![
                format!("retained-{sequence}"),
                epoch,
                sequence,
                &at,
                body.to_string(),
            ],
        )
        .unwrap();
    }
    drop(db);

    assert_eq!(
        retain_events(&["session:retained".to_owned()], &ledger_path).unwrap(),
        3,
        "only token rows covered in the same epoch drop"
    );

    let ledger = odin_ledger::Ledger::open(&ledger_path).unwrap();
    let session = odin_domain::SessionId::new("session:retained").unwrap();
    let history = ledger
        .live_event_history(&session, 0, 10)
        .expect("sparse history still reads");
    let sequences: Vec<i64> = history.iter().map(|event| event.sequence).collect();
    assert_eq!(
        sequences,
        vec![1, 4, 5, 6, 7, 9, 10],
        "retained rows keep their original sequences"
    );
    assert_eq!(
        history
            .iter()
            .find(|event| event.sequence == 4)
            .unwrap()
            .body["frame"]["message"]["content"][0]["text"],
        "the finished answer"
    );
    assert_eq!(
        history
            .iter()
            .find(|event| event.sequence == 9)
            .unwrap()
            .body["frame"]["message"]["content"][0]["text"],
        "epoch two answer"
    );
    assert_eq!(
        history
            .iter()
            .find(|event| event.sequence == 6)
            .unwrap()
            .body["frame"]["delta"],
        "epoch-one-unfinished",
        "a later end in another epoch does not cover it"
    );
    assert_eq!(
        history
            .iter()
            .find(|event| event.sequence == 10)
            .unwrap()
            .body["frame"]["delta"],
        "still streaming"
    );
    assert_eq!(
        history
            .iter()
            .find(|event| event.sequence == 7)
            .unwrap()
            .body["kind"],
        "extension_error"
    );
    assert_eq!(ledger.reconnect_head(&session).unwrap(), 10);
    drop(ledger);

    let db = rusqlite::Connection::open(&ledger_path).unwrap();
    let head: i64 = db
        .query_row(
            "SELECT event_head FROM live_sessions WHERE session_id='session:retained'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(head, 10, "event_head is not lowered");
    let command_head: i64 = db
        .query_row(
            "SELECT expected_event_head FROM live_commands WHERE command_id='command:retained'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(
        command_head, 10,
        "command identity still names the original head"
    );
    let deleted = db.execute(
        "DELETE FROM live_events WHERE session_id='session:retained'",
        [],
    );
    assert!(deleted.is_err(), "the journal is immutable again");
    drop(db);
    assert_eq!(
        retain_events(&["session:retained".to_owned()], &ledger_path).unwrap(),
        0
    );
}
