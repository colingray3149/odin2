//! Scheduled notifications on the real consumer path: a due Notify row goes
//! through the notify worker and the production Discord sink to a loopback
//! server, with the schedule and delivery state on disk and the daemon
//! reopened between attempts. A scheduled message is one physical message per
//! occurrence. An outcome nobody can know is not sent again and is not called
//! not-delivered: the row settles uncertain after one distinct notice.

use crate::fixtures::{gate_runtime, INTENT_DM_CHANNEL};
use crate::loopback_discord::{Fuse, GatedSink, Helper, LoopbackDiscord, PostReply};
use crate::schedule::{call, fire, published_registry, routine_acting};
use odin_hermes::runtime::HermesRuntime;
use odin_registry::schema::RoutineEvent;
use serde_json::json;
use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Arc;

const HONOLULU: &str = "Pacific/Honolulu";
const TOKYO: &str = "Asia/Tokyo";

/// A daemon over `dir` whose owner channel is the loopback. The sink is
/// bound before anything can be sent.
fn open(dir: &Path, server: &LoopbackDiscord) -> Arc<HermesRuntime> {
    let runtime = gate_runtime(dir);
    runtime.bind_notify_sink(server.sink()).unwrap();
    runtime
}

fn set_zone(runtime: &Arc<HermesRuntime>, zone: &str) {
    call(runtime, "time_zone_set", json!({ "zone": zone }));
}

/// Seeds a due reminder through the schedule JSON import path.
fn seed(dir: &Path, id: &str, text: &str, ms_ago: i64, repeat: Option<(i64, u32)>) {
    let now = jiff::Timestamp::now().as_millisecond();
    let mut row = json!({
        "id": id, "kind": "notify", "text": text,
        "fireAtMs": now - ms_ago, "createdAtMs": now - 86_400_000,
        "status": "pending"
    });
    if let Some((every, times)) = repeat {
        row["everyMinutes"] = json!(every);
        row["repeatsLeft"] = json!(times);
    }
    let state = dir.join("state");
    std::fs::create_dir_all(&state).unwrap();
    std::fs::write(state.join("schedule.json"), json!([row]).to_string()).unwrap();
}

fn schedule_db(dir: &Path) -> rusqlite::Connection {
    rusqlite::Connection::open(dir.join("state/schedule.sqlite3")).unwrap()
}

struct RowState {
    status: String,
    dispatch_started: bool,
    fire_at_ms: i64,
}

fn row(dir: &Path, id: &str) -> RowState {
    schedule_db(dir)
        .query_row(
            "SELECT status, dispatch_started, fire_at_ms FROM schedule_items WHERE id = ?1",
            [id],
            |row| {
                Ok(RowState {
                    status: row.get(0)?,
                    dispatch_started: row.get(1)?,
                    fire_at_ms: row.get(2)?,
                })
            },
        )
        .unwrap()
}

/// A routine DM row's id, found by what happened rather than by occurrence.
fn dm_row_id(dir: &Path, detail: &str) -> String {
    schedule_db(dir)
        .query_row(
            "SELECT id FROM schedule_items WHERE anchor = 'routine:pod-dm' \
             AND instr(text, ?1) > 0",
            [format!("What happened: {detail}")],
            |row| row.get(0),
        )
        .unwrap()
}

/// The elapsed retry delay of every open row, as a daemon that waited it out.
fn make_retry_due(dir: &Path) {
    schedule_db(dir)
        .execute(
            "UPDATE schedule_items SET retry_at_ms = NULL WHERE status = 'firing'",
            [],
        )
        .unwrap();
}

/// The daemon died after the row was handed off (and the message accepted)
/// but before the row recorded it fired: the row is leased and handed off
/// again at the same occurrence.
fn crash_before_fired(dir: &Path, id: &str, fire_at_ms: i64) {
    let changed = schedule_db(dir)
        .execute(
            "UPDATE schedule_items SET status = 'firing', fired_at_ms = NULL, attempts = 0, \
             retry_at_ms = NULL, dispatch_started = 1, fire_at_ms = ?2 WHERE id = ?1",
            rusqlite::params![id, fire_at_ms],
        )
        .unwrap();
    assert_eq!(changed, 1, "the crash window needs the row to exist");
}

fn pin_pod_dm(runtime: &Arc<HermesRuntime>, dir: &Path, root: &str) {
    runtime.set_registry_pin(published_registry(
        &dir.join(root),
        vec![routine_acting(
            "pod-dm",
            "event = \"incident\"",
            "dm",
            "Pod news.",
        )],
    ));
}

fn assert_never_reworded(server: &LoopbackDiscord) {
    let (patches, deletes) = server.rewrites();
    assert!(
        patches.is_empty() && deletes.is_empty(),
        "a scheduled message is posted once and never edited or deleted: \
         patches {patches:?}, deletes {deletes:?}"
    );
}

/// Delivery bytes by operation key; an unrendered sealed row has no target.
fn delivery_payloads(dir: &Path) -> BTreeMap<String, Option<Vec<String>>> {
    #[derive(serde::Deserialize)]
    struct Payload {
        key: String,
        target: Option<Vec<String>>,
    }

    let db = rusqlite::Connection::open(dir.join("gate-conversation.db")).unwrap();
    let mut statement = db
        .prepare(
            "SELECT status_json FROM materialized_status \
             WHERE object_kind = 'conversation_delivery' ORDER BY object_id",
        )
        .unwrap();
    statement
        .query_map([], |row| row.get::<_, String>(0))
        .unwrap()
        .map(|state| {
            let state: Payload = serde_json::from_str(&state.unwrap()).unwrap();
            (state.key, state.target)
        })
        .collect()
}

fn times_posted(posted: &[String], chunks: &[String]) -> usize {
    posted
        .iter()
        .filter(|item| chunks.iter().any(|chunk| chunk == *item))
        .count()
}

/// The occurrence key and its notice key each froze one distinct payload.
fn unknown_pair(dir: &Path, occurrence_key: &str) -> (Vec<String>, Vec<String>) {
    let mut payloads = delivery_payloads(dir);
    let occurrence = payloads
        .remove(occurrence_key)
        .unwrap_or_else(|| panic!("missing occurrence delivery {occurrence_key}"))
        .expect("the occurrence has frozen delivery bytes");
    let notice_key = format!("{occurrence_key}:missed");
    let notice = payloads
        .remove(&notice_key)
        .unwrap_or_else(|| panic!("missing notice delivery {notice_key}"))
        .expect("the notice has frozen delivery bytes");
    assert_eq!(occurrence.len(), 1, "{occurrence:?}");
    assert_eq!(notice.len(), 1, "{notice:?}");
    assert_ne!(
        occurrence, notice,
        "the notice is a different delivery from the occurrence"
    );
    (occurrence, notice)
}

/// An accepted reminder is one message to the owner. The daemon dying
/// between the accepted post and the row recording it fired replays the row
/// after reopen — in another zone, so a fresh render would read differently —
/// and the replay finds the message already delivered.
#[test]
fn an_accepted_reminder_is_one_message_and_a_replay_after_a_crash_never_repeats_it() {
    let dir = tempfile::tempdir().unwrap();
    let server = LoopbackDiscord::start();
    seed(
        dir.path(),
        "rglasses",
        "get your glasses",
        30 * 60_000,
        None,
    );
    let runtime = open(dir.path(), &server);
    set_zone(&runtime, HONOLULU);
    assert_eq!(runtime.reconcile_schedule().unwrap(), 1);
    let first = server.posted();
    assert_eq!(first.len(), 1, "{first:?}");
    assert!(first[0].contains("get your glasses"), "{first:?}");
    assert_eq!(server.attempts()[0].channel_id, INTENT_DM_CHANNEL);
    let occurrence = row(dir.path(), "rglasses").fire_at_ms;
    drop(runtime);

    crash_before_fired(dir.path(), "rglasses", occurrence);
    let reopened = open(dir.path(), &server);
    set_zone(&reopened, TOKYO);
    reopened.reconcile_schedule().unwrap();
    assert_eq!(
        server.posted(),
        first,
        "the replay of an accepted occurrence posts nothing and rewrites nothing"
    );
    assert_eq!(row(dir.path(), "rglasses").status, "fired");
    assert_never_reworded(&server);
}

/// A reply lost after the server posted the message is an outcome nobody
/// can know. The occurrence is posted once, one uncertainty notice follows,
/// and reopen neither posts the occurrence again nor repeats the notice.
#[test]
fn a_reminder_whose_reply_was_lost_is_never_posted_twice_and_stays_held() {
    let dir = tempfile::tempdir().unwrap();
    let server = LoopbackDiscord::start();
    server.script(&[PostReply::LoseReply]);
    seed(
        dir.path(),
        "rglasses",
        "get your glasses",
        30 * 60_000,
        None,
    );
    let runtime = open(dir.path(), &server);
    set_zone(&runtime, HONOLULU);
    assert_eq!(runtime.reconcile_schedule().unwrap(), 0);
    let first = server.posted();
    let (occurrence, notice) = unknown_pair(dir.path(), "schedule:rglasses");
    assert_eq!(
        times_posted(&first, &occurrence),
        1,
        "the lost reply posted the occurrence once: {first:?}"
    );
    assert_eq!(
        times_posted(&first, &notice),
        1,
        "one uncertainty notice: {first:?}"
    );
    assert_eq!(first.len(), 2, "no other posts: {first:?}");
    drop(runtime);

    for round in 0..2 {
        make_retry_due(dir.path());
        let reopened = open(dir.path(), &server);
        set_zone(&reopened, TOKYO);
        for _ in 0..2 {
            assert_eq!(reopened.reconcile_schedule().unwrap(), 0, "round {round}");
        }
        assert_eq!(
            server.posted(),
            first,
            "round {round}: an unknown outcome is never sent again"
        );
        assert_eq!(
            row(dir.path(), "rglasses").status,
            "uncertain",
            "round {round}: settled unknown, neither fired nor failed"
        );
        drop(reopened);
    }
    assert_never_reworded(&server);
}

/// A refused post is known unsent, so the retry may send — but the message
/// is the one the first attempt rendered, late suffix and zone included,
/// even though the owner's zone changed before the retry and the daemon
/// reopened.
#[test]
fn a_refused_reminder_retries_with_the_bytes_its_first_attempt_rendered() {
    let dir = tempfile::tempdir().unwrap();
    let server = LoopbackDiscord::start();
    server.script(&[PostReply::Refuse]);
    seed(
        dir.path(),
        "rglasses",
        "get your glasses",
        30 * 60_000,
        None,
    );
    let runtime = open(dir.path(), &server);
    set_zone(&runtime, HONOLULU);
    assert_eq!(runtime.reconcile_schedule().unwrap(), 0);
    assert!(
        server.posted().is_empty(),
        "a refused post is not a message"
    );
    let refused = server.attempts();
    assert_eq!(refused.len(), 1);
    drop(runtime);

    make_retry_due(dir.path());
    let reopened = open(dir.path(), &server);
    set_zone(&reopened, TOKYO);
    assert_eq!(reopened.reconcile_schedule().unwrap(), 1);
    let posted = server.posted();
    assert_eq!(posted.len(), 1, "{posted:?}");
    assert_eq!(
        posted[0], refused[0].content,
        "the retry sends the first attempt's exact bytes"
    );
    assert_eq!(row(dir.path(), "rglasses").status, "fired");
    assert_never_reworded(&server);
}

/// Retrying an outcome nobody can know never runs out and never resends the
/// occurrence. The row settles unknown once its notice has been attempted,
/// never as failed, and the occurrence plus that notice are the only posts.
#[test]
fn unknown_delivery_outcomes_stay_held_past_the_retry_limit() {
    let dir = tempfile::tempdir().unwrap();
    let server = LoopbackDiscord::start();
    server.answer_all(PostReply::LoseReply);
    seed(
        dir.path(),
        "rglasses",
        "get your glasses",
        30 * 60_000,
        None,
    );
    let mut runtime = open(dir.path(), &server);
    let passes = odin_hermes::schedule::MAX_DELIVERY_ATTEMPTS + 4;
    for pass in 0..passes {
        if pass == passes / 2 {
            drop(runtime);
            runtime = open(dir.path(), &server);
        }
        make_retry_due(dir.path());
        assert_eq!(runtime.reconcile_schedule().unwrap(), 0);
    }
    assert_eq!(
        row(dir.path(), "rglasses").status,
        "uncertain",
        "settled unknown, never failed"
    );
    let posted = server.posted();
    let (occurrence, notice) = unknown_pair(dir.path(), "schedule:rglasses");
    assert_eq!(
        times_posted(&posted, &occurrence),
        1,
        "the occurrence is posted once: {posted:?}"
    );
    assert_eq!(
        times_posted(&posted, &notice),
        1,
        "the uncertainty notice is posted once: {posted:?}"
    );
    assert_eq!(posted.len(), 2, "no other posts: {posted:?}");
    assert_never_reworded(&server);
}

/// A repeating reminder's occurrences are distinct messages even when their
/// bytes are identical; a replay of the latest occurrence after a crash is
/// still not a new message.
#[test]
fn each_recurring_reminder_occurrence_is_its_own_message_and_a_replay_repeats_none() {
    let dir = tempfile::tempdir().unwrap();
    let server = LoopbackDiscord::start();
    seed(dir.path(), "rstand", "stand up", 90_000, Some((1, 3)));
    let runtime = open(dir.path(), &server);
    assert_eq!(runtime.reconcile_schedule().unwrap(), 1);
    assert_eq!(row(dir.path(), "rstand").status, "pending");

    let second = jiff::Timestamp::now().as_millisecond() - 30_000;
    schedule_db(dir.path())
        .execute(
            "UPDATE schedule_items SET fire_at_ms = ?2 WHERE id = ?1 AND status = 'pending'",
            rusqlite::params!["rstand", second],
        )
        .unwrap();
    assert_eq!(runtime.reconcile_schedule().unwrap(), 1);
    let posted = server.posted();
    assert_eq!(posted.len(), 2, "one message per occurrence: {posted:?}");
    assert_eq!(
        posted[0], posted[1],
        "identical bytes, distinct occurrences"
    );
    drop(runtime);

    crash_before_fired(dir.path(), "rstand", second);
    let reopened = open(dir.path(), &server);
    reopened.reconcile_schedule().unwrap();
    assert_eq!(
        server.posted().len(),
        2,
        "replaying the second occurrence posts no third message"
    );
    assert_eq!(row(dir.path(), "rstand").status, "pending");
    assert_never_reworded(&server);
}

/// A routine's DM goes through the same delivery: a reply lost after the
/// post leaves one message plus one uncertainty notice, and reopen posts
/// neither again.
#[test]
fn a_routine_dm_whose_reply_was_lost_is_never_posted_twice_and_stays_held() {
    let dir = tempfile::tempdir().unwrap();
    let server = LoopbackDiscord::start();
    server.script(&[PostReply::LoseReply]);
    let runtime = open(dir.path(), &server);
    pin_pod_dm(&runtime, dir.path(), "registry");
    runtime.reconcile_routines().unwrap();
    assert_eq!(
        fire(&runtime, RoutineEvent::Incident, "inc-1", "first incident"),
        1
    );
    assert_eq!(runtime.reconcile_schedule().unwrap(), 0);
    let id = dm_row_id(dir.path(), "first incident");
    let first = server.posted();
    let (occurrence, notice) = unknown_pair(dir.path(), &format!("schedule:{id}"));
    assert_eq!(times_posted(&first, &occurrence), 1, "{first:?}");
    assert_eq!(times_posted(&first, &notice), 1, "{first:?}");
    assert_eq!(first.len(), 2, "no other posts: {first:?}");
    assert!(row(dir.path(), &id).dispatch_started);
    drop(runtime);

    for round in 0..2 {
        make_retry_due(dir.path());
        let reopened = open(dir.path(), &server);
        pin_pod_dm(&reopened, dir.path(), &format!("registry-reopened-{round}"));
        for _ in 0..2 {
            assert_eq!(reopened.reconcile_schedule().unwrap(), 0, "round {round}");
        }
        assert_eq!(
            server.posted(),
            first,
            "round {round}: a handed-off DM of unknown outcome is not sent again"
        );
        assert_eq!(row(dir.path(), &id).status, "uncertain", "round {round}");
        drop(reopened);
    }
    assert_never_reworded(&server);
}

/// The routine DM accepted before a crash is not posted again when the row
/// is replayed after reopen.
#[test]
fn an_accepted_routine_dm_replayed_after_a_crash_is_not_posted_again() {
    let dir = tempfile::tempdir().unwrap();
    let server = LoopbackDiscord::start();
    let runtime = open(dir.path(), &server);
    pin_pod_dm(&runtime, dir.path(), "registry");
    runtime.reconcile_routines().unwrap();
    assert_eq!(
        fire(&runtime, RoutineEvent::Incident, "inc-1", "first incident"),
        1
    );
    assert_eq!(runtime.reconcile_schedule().unwrap(), 1);
    let first = server.posted();
    assert_eq!(first.len(), 1, "{first:?}");
    let id = dm_row_id(dir.path(), "first incident");
    let occurrence = row(dir.path(), &id).fire_at_ms;
    drop(runtime);

    crash_before_fired(dir.path(), &id, occurrence);
    let reopened = open(dir.path(), &server);
    pin_pod_dm(&reopened, dir.path(), "registry-reopened");
    reopened.reconcile_schedule().unwrap();
    assert_eq!(server.posted(), first, "the accepted DM is not repeated");
    assert_eq!(row(dir.path(), &id).status, "fired");
    assert_never_reworded(&server);
}

/// While the sink holds a delivery the handoff is already durable, so an
/// observer sees a row that may have been sent and a wire that has nothing;
/// once the sink answers, the message goes out once and the row settles.
/// The fuse and the joined helper keep this from outliving a failure.
#[test]
fn a_notify_inside_the_sink_is_a_durable_handoff_that_finishes_exactly_once() {
    let dir = tempfile::tempdir().unwrap();
    let server = LoopbackDiscord::start();
    let fuse = Fuse::default();
    let gated = GatedSink::new(server.sink(), &fuse);
    let runtime = gate_runtime(dir.path());
    runtime.bind_notify_sink(gated.clone()).unwrap();
    pin_pod_dm(&runtime, dir.path(), "registry");
    runtime.reconcile_routines().unwrap();
    assert_eq!(
        fire(&runtime, RoutineEvent::Incident, "inc-1", "first incident"),
        1
    );
    let id = dm_row_id(dir.path(), "first incident");
    let pass = {
        let runtime = Arc::clone(&runtime);
        Helper::spawn(&fuse, move || runtime.reconcile_schedule())
    };
    assert!(gated.wait_entered(1), "the delivery never reached the sink");
    let inside = row(dir.path(), &id);
    assert_eq!(inside.status, "firing");
    assert!(
        inside.dispatch_started,
        "handed off: it may have been sent, so it is never cancelled"
    );
    assert!(server.attempts().is_empty(), "nothing has reached the wire");
    fuse.release();
    assert_eq!(pass.finish().unwrap(), 1);
    assert_eq!(server.posted().len(), 1);
    assert_eq!(row(dir.path(), &id).status, "fired");
}

/// Drains the notify worker on a private runtime, as the daemon's shutdown
/// does against its one deadline.
fn drain(runtime: &HermesRuntime, within: std::time::Duration) -> Result<(), String> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(runtime.drain_notifications_until(tokio::time::Instant::now() + within))
}

/// Shutdown closes admission before anything else: a reminder that comes due
/// after the close is refused unsent — nothing reaches the wire, the row is
/// retried rather than lost — and the daemon that reopens sends it once.
#[test]
fn a_reminder_due_after_notifications_close_is_never_sent_and_goes_out_after_reopen() {
    let dir = tempfile::tempdir().unwrap();
    let server = LoopbackDiscord::start();
    seed(
        dir.path(),
        "rglasses",
        "get your glasses",
        30 * 60_000,
        None,
    );
    let runtime = open(dir.path(), &server);
    runtime.close_notifications();
    runtime.close_notifications();
    assert_eq!(runtime.reconcile_schedule().unwrap(), 0);
    assert!(
        server.attempts().is_empty(),
        "a closed notifier puts nothing on the wire"
    );
    assert_eq!(row(dir.path(), "rglasses").status, "firing");
    drain(&runtime, std::time::Duration::from_secs(10)).expect("an idle worker stops");
    drop(runtime);

    make_retry_due(dir.path());
    let reopened = open(dir.path(), &server);
    assert_eq!(reopened.reconcile_schedule().unwrap(), 1);
    let posted = server.posted();
    assert_eq!(posted.len(), 1, "{posted:?}");
    assert!(posted[0].contains("get your glasses"), "{posted:?}");
    assert_eq!(row(dir.path(), "rglasses").status, "fired");
    assert_never_reworded(&server);
}

/// A delivery already inside the sink when shutdown begins is waited for:
/// the drain returns once it lands, the caller sees it delivered, and the
/// row settles fired with the one message out.
#[test]
fn a_notify_inside_the_sink_finishes_within_the_shutdown_drain() {
    let dir = tempfile::tempdir().unwrap();
    let server = LoopbackDiscord::start();
    let fuse = Fuse::default();
    let gated = GatedSink::new(server.sink(), &fuse);
    seed(
        dir.path(),
        "rglasses",
        "get your glasses",
        30 * 60_000,
        None,
    );
    let runtime = gate_runtime(dir.path());
    runtime.bind_notify_sink(gated.clone()).unwrap();
    let pass = {
        let runtime = Arc::clone(&runtime);
        Helper::spawn(&fuse, move || runtime.reconcile_schedule())
    };
    assert!(gated.wait_entered(1), "the delivery never reached the sink");
    runtime.close_notifications();
    fuse.release();
    drain(&runtime, std::time::Duration::from_secs(20)).expect("the in-flight delivery lands");
    assert_eq!(pass.finish().unwrap(), 1);
    assert_eq!(server.posted().len(), 1, "{:?}", server.posted());
    assert_eq!(row(dir.path(), "rglasses").status, "fired");
}

/// A sink that cannot be cancelled outlives the shutdown deadline: the drain
/// reports it instead of calling it stopped. The occurrence is posted at most
/// once, and a reopened daemon sends the uncertainty notice once rather than
/// the occurrence again.
#[test]
fn a_notify_stuck_in_the_sink_at_the_deadline_is_reported_held_and_never_resent() {
    let dir = tempfile::tempdir().unwrap();
    let server = LoopbackDiscord::start();
    let fuse = Fuse::default();
    let gated = GatedSink::new(server.sink(), &fuse);
    seed(
        dir.path(),
        "rglasses",
        "get your glasses",
        30 * 60_000,
        None,
    );
    let runtime = gate_runtime(dir.path());
    runtime.bind_notify_sink(gated.clone()).unwrap();
    let pass = {
        let runtime = Arc::clone(&runtime);
        Helper::spawn(&fuse, move || runtime.reconcile_schedule())
    };
    assert!(gated.wait_entered(1), "the delivery never reached the sink");
    runtime.close_notifications();
    drain(&runtime, std::time::Duration::from_millis(150))
        .expect_err("a worker still inside its sink has not stopped");
    assert!(server.attempts().is_empty(), "nothing has reached the wire");

    assert_eq!(
        pass.finish().unwrap(),
        0,
        "the caller stopped waiting at the shared deadline"
    );
    drain(&runtime, std::time::Duration::from_secs(10)).expect("the answered sink lets it join");
    let occurrence = delivery_payloads(dir.path())
        .remove("schedule:rglasses")
        .expect("the occurrence delivery was recorded");
    let initial_posts = server.posted();
    let landed = match &occurrence {
        Some(chunks) => times_posted(&initial_posts, chunks),
        None => {
            assert!(
                initial_posts.is_empty(),
                "an unrendered occurrence cannot have posted"
            );
            0
        }
    };
    assert!(landed <= 1, "{:?}", server.posted());
    assert_eq!(
        row(dir.path(), "rglasses").status,
        "firing",
        "held: its outcome was not observed, so it is neither fired nor failed"
    );
    drop(runtime);

    make_retry_due(dir.path());
    let reopened = open(dir.path(), &server);
    reopened.reconcile_schedule().unwrap();
    let posted = server.posted();
    let mut payloads = delivery_payloads(dir.path());
    let notice = payloads
        .remove("schedule:rglasses:missed")
        .flatten()
        .expect("the uncertainty notice has frozen delivery bytes");
    assert_eq!(notice.len(), 1, "{notice:?}");
    if let Some(chunks) = &occurrence {
        assert_eq!(
            times_posted(&posted, chunks),
            landed,
            "a reopened daemon never sends the occurrence a second time: {posted:?}"
        );
    }
    assert_eq!(
        times_posted(&posted, &notice),
        1,
        "one uncertainty notice: {posted:?}"
    );
    assert_eq!(posted.len(), landed + 1, "no other posts: {posted:?}");
    assert_eq!(row(dir.path(), "rglasses").status, "uncertain");
    assert_never_reworded(&server);
}

/// Two queued occurrences of one routine, the first inside the sink. The
/// declaration is removed meanwhile: the handed-off first finishes, and the
/// second — never handed off, so provably unsent — is cancelled and never
/// reaches the wire. Uncertain-after-dispatch and undispatched are different
/// outcomes of the same change.
#[test]
fn a_removed_routine_cancels_the_undispatched_dm_but_not_the_one_in_the_sink() {
    let dir = tempfile::tempdir().unwrap();
    let server = LoopbackDiscord::start();
    let fuse = Fuse::default();
    let gated = GatedSink::new(server.sink(), &fuse);
    let runtime = gate_runtime(dir.path());
    runtime.bind_notify_sink(gated.clone()).unwrap();
    pin_pod_dm(&runtime, dir.path(), "registry");
    runtime.reconcile_routines().unwrap();
    for (key, detail) in [("inc-1", "first incident"), ("inc-2", "second incident")] {
        assert_eq!(fire(&runtime, RoutineEvent::Incident, key, detail), 1);
    }
    let first = dm_row_id(dir.path(), "first incident");
    let second = dm_row_id(dir.path(), "second incident");
    let pass = {
        let runtime = Arc::clone(&runtime);
        Helper::spawn(&fuse, move || runtime.reconcile_schedule())
    };
    assert!(gated.wait_entered(1), "the delivery never reached the sink");
    let (sent, waiting) = if row(dir.path(), &first).dispatch_started {
        ("first incident", "second incident")
    } else {
        ("second incident", "first incident")
    };
    let (sent_id, waiting_id) = if sent == "first incident" {
        (first.clone(), second.clone())
    } else {
        (second.clone(), first.clone())
    };
    assert_eq!(row(dir.path(), &sent_id).status, "firing");
    let held = row(dir.path(), &waiting_id);
    assert_eq!(
        (held.status.as_str(), held.dispatch_started),
        ("firing", false)
    );

    runtime.set_registry_pin(published_registry(
        &dir.path().join("registry-removed"),
        vec![routine_acting(
            "other",
            "event = \"workload_failed\"",
            "dm",
            "Other news.",
        )],
    ));
    fuse.release();
    assert_eq!(pass.finish().unwrap(), 1);
    let posted = server.posted();
    assert_eq!(posted.len(), 1, "{posted:?}");
    assert!(posted[0].contains(sent), "{posted:?}");
    assert!(!posted[0].contains(waiting), "{posted:?}");
    assert_eq!(row(dir.path(), &sent_id).status, "fired");
    assert_eq!(row(dir.path(), &waiting_id).status, "cancelled");
}

#[test]
fn an_unknown_occurrence_stays_held_when_notification_admission_closes() {
    let dir = tempfile::tempdir().unwrap();
    let server = LoopbackDiscord::start();
    server.script(&[PostReply::LoseReply]);
    seed(
        dir.path(),
        "rclosed",
        "keep this outcome honest",
        60_000,
        None,
    );
    let runtime = open(dir.path(), &server);
    assert_eq!(runtime.reconcile_schedule().unwrap(), 0);
    let posted = server.posted();
    let (occurrence, notice) = unknown_pair(dir.path(), "schedule:rclosed");
    assert_eq!(times_posted(&posted, &occurrence), 1, "{posted:?}");
    assert_eq!(times_posted(&posted, &notice), 1, "{posted:?}");
    assert_eq!(posted.len(), 2, "no other posts: {posted:?}");
    assert_eq!(row(dir.path(), "rclosed").status, "uncertain");
    runtime.close_notifications();
    for _ in 0..10 {
        make_retry_due(dir.path());
        assert_eq!(runtime.reconcile_schedule().unwrap(), 0);
    }
    assert_eq!(row(dir.path(), "rclosed").status, "uncertain");
    assert_eq!(server.posted(), posted);
    drain(&runtime, std::time::Duration::from_secs(10)).unwrap();
}

#[test]
fn an_already_delivered_occurrence_settles_even_after_notification_admission_closes() {
    let dir = tempfile::tempdir().unwrap();
    let server = LoopbackDiscord::start();
    seed(
        dir.path(),
        "rdelivered",
        "one physical reminder",
        60_000,
        None,
    );
    let runtime = open(dir.path(), &server);
    assert_eq!(runtime.reconcile_schedule().unwrap(), 1);
    let posted = server.posted();
    assert_eq!(posted.len(), 1);
    let occurrence = row(dir.path(), "rdelivered").fire_at_ms;
    drop(runtime);
    crash_before_fired(dir.path(), "rdelivered", occurrence);
    let reopened = open(dir.path(), &server);
    reopened.close_notifications();
    assert_eq!(reopened.reconcile_schedule().unwrap(), 1);
    assert_eq!(row(dir.path(), "rdelivered").status, "fired");
    assert_eq!(server.posted(), posted);
    drain(&reopened, std::time::Duration::from_secs(10)).unwrap();
}

#[test]
fn the_last_ack_survives_a_failed_final_commit_and_closed_notification_admission() {
    let dir = tempfile::tempdir().unwrap();
    let server = LoopbackDiscord::start();
    seed(
        dir.path(),
        "rlastack",
        "one acknowledged reminder",
        60_000,
        None,
    );
    let runtime = open(dir.path(), &server);
    let db = rusqlite::Connection::open(dir.path().join("gate-conversation.db")).unwrap();
    db.execute_batch(
        "CREATE TRIGGER refuse_final_delivery BEFORE UPDATE OF status_json ON materialized_status
         WHEN NEW.object_kind = 'conversation_delivery'
         AND json_extract(NEW.status_json, '$.phase') = 'committed'
         BEGIN SELECT RAISE(ABORT, 'private final-commit fault'); END;",
    )
    .unwrap();
    assert_eq!(runtime.reconcile_schedule().unwrap(), 0);
    let posted = server.posted();
    assert_eq!(posted.len(), 1);
    db.execute_batch("DROP TRIGGER refuse_final_delivery")
        .unwrap();
    drain(&runtime, std::time::Duration::from_secs(10)).unwrap();
    drop(runtime);

    make_retry_due(dir.path());
    let reopened = open(dir.path(), &server);
    reopened.close_notifications();
    assert_eq!(reopened.reconcile_schedule().unwrap(), 1);
    assert_eq!(row(dir.path(), "rlastack").status, "fired");
    assert_eq!(server.posted(), posted);
    drain(&reopened, std::time::Duration::from_secs(10)).unwrap();
}
