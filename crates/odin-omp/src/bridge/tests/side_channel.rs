use super::*;

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
            None,
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
fn a_cancelled_call_keeps_its_byte_reservation_until_it_settles() {
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

#[test]
fn handler_images_leave_the_text_and_details_and_are_journaled_without_data() {
    let image = json!({ "type": "image", "mimeType": "image/jpeg", "data": "QUJD" });
    let (rest, images) = split_images(json!({ "viewed": "IMG_1.jpg", "images": [image] }));
    assert_eq!(rest, json!({ "viewed": "IMG_1.jpg" }));
    assert_eq!(images, vec![image.clone()]);
    // Anything that is not a list of image blocks stays ordinary data.
    let plain = json!({ "images": ["IMG_1.jpg"] });
    assert_eq!(split_images(plain.clone()), (plain, Vec::new()));
    let journaled = without_image_data(&json!({
        "content": [{ "type": "text", "text": "{}" }, image],
        "details": rest,
    }));
    assert_eq!(
        journaled["content"][1],
        json!({ "type": "image", "mimeType": "image/jpeg", "data": "<4 base64 bytes>" })
    );
    assert_eq!(journaled["content"][0]["text"], "{}");
}

#[cfg(unix)]
#[tokio::test]
async fn calls_take_no_slot_during_grace_and_a_full_board_keeps_them_inline() {
    use crate::host_tools::jobs::JobBoard;
    let root = tempfile::tempdir().expect("fixture root");
    let context = super::fixture::fixture_context(root.path(), 1, "job-inline").await;
    let config = context
        .bridge_config(context.session_descriptor())
        .expect("bridge config");
    let bridge = OmpBridge::start(config).await.expect("bridge");
    let jobs = Arc::new(JobBoard::open(
        "sinmara".parse().expect("seat"),
        Arc::new(|_, _| Ok(())),
        Duration::from_secs(60),
        1,
        None,
    ));
    let shared = Arc::clone(bridge.shared_for_test());
    let board = Arc::clone(&jobs);
    let (started, began) = std::sync::mpsc::channel();
    let (release, released) = std::sync::mpsc::channel();
    let call = tokio::spawn(async move {
        shared
            .timed_call_for_test("inside-grace", board, move || {
                started.send(()).expect("started");
                released.recv().expect("release");
                Ok(json!({"content":[{"type":"text","text":"found current version"}]}))
            })
            .await;
    });
    tokio::task::spawn_blocking(move || began.recv().expect("effect started"))
        .await
        .expect("start observation");
    assert_eq!(jobs.running(), 0, "inline work reserves no job slot");
    release.send(()).expect("finish inline");
    call.await.expect("inline call");
    assert!(jobs.list()["jobs"].as_array().expect("jobs").is_empty());
    let jobs = Arc::new(JobBoard::open(
        "sinmara".parse().expect("seat"),
        Arc::new(|_, _| Ok(())),
        Duration::from_millis(5),
        1,
        None,
    ));
    jobs.start(
        jobs.try_reserve().expect("one detach slot"),
        "brain_search",
        &json!({}),
        Duration::from_secs(180),
        std::time::Instant::now(),
        odin_domain::progress::Slot::default(),
    )
    .expect("fill board");
    bridge
        .shared_for_test()
        .timed_call_for_test("full-board", Arc::clone(&jobs), || {
            std::thread::sleep(Duration::from_millis(80));
            Ok(json!({"content":[{"type":"text","text":"full board still found version"}]}))
        })
        .await;
    let (outcomes, _) = bridge.side_channel_evidence().expect("outcomes");
    let result = outcomes
        .iter()
        .find(|outcome| outcome.request_id == "full-board")
        .expect("inline outcome");
    assert!(
        matches!(&result.status, SideChannelStatus::Completed { result, .. }
        if result["content"][0]["text"] == "full board still found version")
    );
    assert_eq!(jobs.running(), 1, "no second call detached");
    jobs.finish("j1", Ok("finished".to_owned()));
    bridge.stop().await.expect("stop fixture");
}
