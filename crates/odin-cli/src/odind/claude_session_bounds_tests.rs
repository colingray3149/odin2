use super::*;

fn stored(count: usize, payload: Value) -> StoredSession {
    let request = serde_json::from_value(json!({"account":"test","project":"test"})).unwrap();
    StoredSession {
        session: ClaudeSessionRecord {
            session: "00000000-0000-4000-8000-000000000001".into(),
            request,
            owner_run: "run.test".into(),
            state: ClaudeSessionState::Stopped,
            resource: None,
            claude_session_id: None,
            remote_control: None,
            cursor: count as u64,
            last_error: None,
            last_driver_cursor: None,
            last_publication_cursor: None,
        },
        events: (1..=count)
            .map(|cursor| ClaudeSessionEvent {
                cursor: cursor as u64,
                kind: "backend".into(),
                payload: payload.clone(),
            })
            .collect(),
        observed_at: time::OffsetDateTime::UNIX_EPOCH,
        needs_persist: false,
    }
}

#[test]
fn projection_is_newest_window_and_read_pages_are_oldest_first() {
    let stored = stored(600, json!({"text":"evidence"}));
    let projection = transcript_projection(&stored).unwrap();
    assert_eq!(projection.events.len(), TRANSCRIPT_MAX_EVENTS);
    assert_eq!(projection.event_start, Some(345));
    assert_eq!(projection.event_end, Some(600));
    assert!(projection.has_more);
    assert!(serde_json::to_vec(&projection).unwrap().len() <= TRANSCRIPT_MAX_BYTES);
    let mut cursor = 0;
    let mut seen = Vec::new();
    loop {
        let page = transcript_page(&stored, cursor).unwrap();
        assert!(page.events.len() <= TRANSCRIPT_MAX_EVENTS);
        assert!(page.error.is_none());
        assert!(serde_json::to_vec(&page).unwrap().len() <= TRANSCRIPT_MAX_BYTES);
        seen.extend(page.events.iter().map(|event| event.cursor));
        cursor = page.next_cursor;
        if !page.has_more {
            break;
        }
    }
    assert_eq!(seen, (1..=600).collect::<Vec<u64>>());
    assert_eq!(stored.events.len(), 600);
    let empty = transcript_page(&stored, cursor).unwrap();
    assert!(empty.events.is_empty());
    assert_eq!(empty.next_cursor, 600);
    assert!(!empty.has_more);
}

#[test]
fn byte_budget_bounds_both_windows_without_changing_durable_events() {
    let stored = stored(20, json!({"text":"x".repeat(100_000)}));
    let projection = transcript_projection(&stored).unwrap();
    assert!(projection.events.len() < 20);
    assert_eq!(projection.event_end, Some(20));
    assert!(serde_json::to_vec(&projection).unwrap().len() <= TRANSCRIPT_MAX_BYTES);
    let page = transcript_page(&stored, 0).unwrap();
    assert_eq!(page.events.first().unwrap().cursor, 1);
    assert!(page.events.len() < 20);
    assert!(page.has_more);
    assert!(serde_json::to_vec(&page).unwrap().len() <= TRANSCRIPT_MAX_BYTES);
    assert_eq!(stored.events.len(), 20);
}

#[test]
fn huge_event_returns_typed_error_without_advancing_or_erasing_evidence() {
    let stored = stored(1, json!({"text":"x".repeat(TRANSCRIPT_MAX_BYTES)}));
    let before = serde_json::to_vec(&stored).unwrap();
    let page = transcript_page(&stored, 0).unwrap();
    assert!(page.events.is_empty());
    assert_eq!(page.next_cursor, 0);
    assert!(page.has_more);
    assert!(matches!(
        page.error,
        Some(ClaudeReadError::EventTooLarge { cursor: 1, .. })
    ));
    assert!(serde_json::to_vec(&page).unwrap().len() <= TRANSCRIPT_MAX_BYTES);
    let projection = transcript_projection(&stored).unwrap();
    assert!(projection.events.is_empty());
    assert_eq!(projection.event_start, None);
    assert_eq!(projection.event_end, None);
    assert!(projection.has_more);
    assert_eq!(before, serde_json::to_vec(&stored).unwrap());
}

#[test]
fn codec_container_limit_is_not_hidden_by_small_json_bytes() {
    let stored = stored(1, Value::Array(vec![json!(0); 65_537]));
    let page = transcript_page(&stored, 0).unwrap();
    assert!(matches!(
        page.error,
        Some(ClaudeReadError::EventTooLarge { cursor: 1, .. })
    ));
    assert_eq!(page.next_cursor, 0);
    assert!(transcript_projection(&stored).unwrap().events.is_empty());
}

#[test]
fn oversized_metadata_refuses_instead_of_emitting_an_oversized_reply() {
    let mut stored = stored(0, Value::Null);
    stored.session.last_error = Some("x".repeat(TRANSCRIPT_MAX_BYTES));
    assert!(matches!(
        transcript_page(&stored, 0),
        Err(HostToolError::Arguments { .. })
    ));
    assert!(matches!(
        transcript_projection(&stored),
        Err(HostToolError::Arguments { .. })
    ));
}

#[test]
fn oversized_event_after_a_page_is_reported_on_the_next_page() {
    let mut stored = stored(2, json!({}));
    stored.events[1].payload = json!({"text":"x".repeat(TRANSCRIPT_MAX_BYTES)});
    let page = transcript_page(&stored, 0).unwrap();
    assert_eq!(page.next_cursor, 1);
    assert!(page.error.is_none());
    assert!(page.has_more);
    let blocked = transcript_page(&stored, page.next_cursor).unwrap();
    assert_eq!(blocked.next_cursor, 1);
    assert!(matches!(
        blocked.error,
        Some(ClaudeReadError::EventTooLarge { cursor: 2, .. })
    ));
}
