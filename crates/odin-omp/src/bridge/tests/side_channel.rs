use super::*;

#[test]
fn side_table_history_is_bounded_and_counted() {
    let mut table = SideTable::default();
    for index in 0..SIDE_CHANNEL_HISTORY_CAP + 5 {
        table.remember(outcome(&format!("req-{index}")));
    }
    assert_eq!(table.history.len(), SIDE_CHANNEL_HISTORY_CAP);
    assert_eq!(table.dropped, 5);
    assert_eq!(
        table.history.front().expect("oldest retained").request_id,
        "req-5"
    );
}

#[test]
fn side_flood_hits_count_and_byte_bounds_without_retained_growth() {
    let mut table = SideTable::default();
    for index in 0..DISPATCH_PERMITS {
        assert!(table.admission_rejection(1).is_none());
        table.active_bytes += 1;
        let previous = table.active.insert(
            format!("req-{index}"),
            SideEntry {
                kind: SideChannelKind::Tool,
                name: "tool".to_owned(),
                retained_bytes: 1,
                disposition: SideDisposition::Running,
            },
        );
        assert!(previous.is_none());
    }
    let count = table.active.len();
    let bytes = table.active_bytes;
    assert_eq!(
        table.admission_rejection(1),
        Some("side-channel active-count ceiling reached")
    );
    let terminal = side_result_frame(
        "over-count",
        SideChannelKind::Tool,
        &side_error_result(
            SideChannelKind::Tool,
            "side-channel active-count ceiling reached",
        ),
    );
    assert_eq!(terminal["id"], "over-count");
    assert_eq!(terminal["isError"], true);
    assert_eq!(table.active.len(), count);
    assert_eq!(table.active_bytes, bytes);

    table.active.clear();
    table.active_bytes = SIDE_CHANNEL_ACTIVE_BYTE_BUDGET;
    assert_eq!(
        table.admission_rejection(1),
        Some("side-channel active-byte ceiling reached")
    );
    assert!(table.active.is_empty(), "byte rejection retains no waiter");
}

#[test]
fn cancellation_preserves_reservation_and_suppresses_late_authorization() {
    let mut table = SideTable::default();
    table.active.insert(
        "req-cancel".to_owned(),
        SideEntry {
            kind: SideChannelKind::Uri,
            name: "atlas://node".to_owned(),
            retained_bytes: 128,
            disposition: SideDisposition::Running,
        },
    );
    table.active_bytes = 128;
    assert!(!table.cancel("req-cancel", SideChannelKind::Tool));
    assert!(table.cancel("req-cancel", SideChannelKind::Uri));
    let entry = table
        .active
        .get("req-cancel")
        .expect("reservation retained");
    assert_eq!(entry.disposition, SideDisposition::Cancelled);
    assert_eq!(table.active_bytes, 128);
    let removed = table.remove_active("req-cancel").expect("settles once");
    assert_eq!(removed.disposition, SideDisposition::Cancelled);
    assert_eq!(table.active_bytes, 0);
    assert!(table.remove_active("req-cancel").is_none());
}

fn uri_result(content_type: &str, body: UriBody) -> UriResult {
    UriResult {
        request: UriRequest {
            url: "atlas://node".to_owned(),
            operation: UriOperation::Read,
            scheme: UriScheme::Atlas,
            id: Some("node".to_owned()),
            content_type: content_type.to_owned(),
            immutable: true,
        },
        content_type: content_type.to_owned(),
        immutable: true,
        notes: Vec::new(),
        body,
    }
}

#[test]
fn uri_result_value_never_leaks_wire_keys_and_maps_bodies() {
    let json_value = uri_result_value(&uri_result(
        "application/json",
        UriBody::Json(json!({ "a": 1 })),
    ));
    assert_eq!(json_value["contentType"], "application/json");
    assert_eq!(json_value["content"], "{\"a\":1}", "canonical compact JSON");
    assert!(json_value.get("type").is_none() && json_value.get("id").is_none());

    let bytes = uri_result_value(&uri_result(
        "application/octet-stream",
        UriBody::Bytes(b"hi".to_vec()),
    ));
    assert_eq!(bytes["contentType"], "text/plain");
    assert_eq!(bytes["content"], "hi");
    assert_eq!(bytes["immutable"], true);

    let binary = uri_result_value(&uri_result(
        "application/octet-stream",
        UriBody::Bytes(vec![0xff, 0x00]),
    ));
    assert_eq!(binary["contentType"], "application/json");
    let encoded: Value = serde_json::from_str(binary["content"].as_str().expect("binary envelope"))
        .expect("binary envelope is json");
    assert_eq!(encoded, json!({ "encoding": "base64", "bytes": "/wA=" }));
}

#[test]
fn side_result_frames_match_the_pinned_schema() {
    let tool = side_result_frame(
        "req-1",
        SideChannelKind::Tool,
        &json!({ "content": [{ "type": "text", "text": "ok" }] }),
    );
    assert_eq!(
        tool,
        json!({
            "type": "host_tool_result",
            "id": "req-1",
            "result": { "content": [{ "type": "text", "text": "ok" }] },
            "isError": false,
        })
    );

    let uri = side_result_frame(
        "req-2",
        SideChannelKind::Uri,
        &json!({
            "content": "body",
            "contentType": "text/markdown",
            "immutable": true,
            "type": "poison",
            "id": "poison",
        }),
    );
    assert_eq!(
        uri,
        json!({
            "type": "host_uri_result",
            "id": "req-2",
            "content": "body",
            "contentType": "text/markdown",
            "immutable": true,
        }),
        "payload can never override the envelope's type or id"
    );

    assert_eq!(
        side_error_result(SideChannelKind::Uri, "denied"),
        json!({ "isError": true, "error": "denied" })
    );
    let tool_error = side_error_result(SideChannelKind::Tool, "boom");
    assert_eq!(tool_error["isError"], true);
    assert_eq!(tool_error["content"][0]["type"], "text");
}
