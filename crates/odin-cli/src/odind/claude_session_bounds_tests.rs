use super::*;

fn stored(count: usize, payload: Value) -> StoredSession {
    let request = serde_json::from_value(json!({"account":"test","project":"test"})).unwrap();
    StoredSession {
        session: ClaudeSessionRecord {
            session: "00000000-0000-4000-8000-000000000001".into(),
            request,
            owner_run: "run.test".into(),
            seat: None,
            lane: None,
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
        ended_at: None,
        needs_persist: false,
    }
}

#[test]
fn projection_is_newest_window_and_read_pages_are_oldest_first() {
    let stored = stored(600, json!({"text":"evidence"}));
    let projection = transcript_projection(&stored, 600).unwrap();
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
    let projection = transcript_projection(&stored, 600).unwrap();
    assert!(projection.events.is_empty());
    assert_eq!(projection.event_start, None);
    assert_eq!(projection.event_end, None);
    assert!(projection.has_more);
    assert_eq!(before, serde_json::to_vec(&stored).unwrap());
}
