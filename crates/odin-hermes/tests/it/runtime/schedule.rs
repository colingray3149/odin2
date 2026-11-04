//! Deterministic reminders: the model-facing tools store code-resolved rows,
//! and the reconcile loop fires each due row exactly once — a notify as a
//! plain owner DM, a wake as an unprompted conversation turn — including
//! rows that came due while the daemon was down.

use crate::runtime::fixtures::{
    call, discord_runtime, gate_runtime, owner_dm, tool_named as tool, FakeRoute,
    RecordingNotifySink,
};
use odin_domain::Scope;
use odin_omp::host_tools::HostInvocation;
use serde_json::json;
use std::sync::Arc;

/// Seeds a due row in the current schedule store.
fn seed_due_row(state: &std::path::Path, id: &str, kind: &str, text: &str, minutes_ago: i64) {
    let now = jiff::Timestamp::now().as_millisecond();
    std::fs::create_dir_all(state).unwrap();
    drop(odin_hermes::schedule::ScheduleStore::open(state).unwrap());
    rusqlite::Connection::open(state.join("schedule.sqlite3")).unwrap().execute(
        "INSERT INTO schedule_items (id, kind, text, fire_at_ms, created_at_ms, status) VALUES (?1, ?2, ?3, ?4, ?5, 'pending')",
        rusqlite::params![id, kind, text, now - minutes_ago * 60_000, now - 86_400_000],
    ).unwrap();
}

#[test]
fn reminders_are_set_listed_and_cancelled_in_the_owner_zone() {
    let dir = tempfile::tempdir().unwrap();
    let runtime = gate_runtime(dir.path());
    let zone = call(
        &runtime,
        "time_zone_set",
        json!({ "zone": "America/Los_Angeles" }),
    );
    assert!(zone["now"]
        .as_str()
        .unwrap()
        .contains("America/Los_Angeles"));
    let day = jiff::Zoned::now()
        .with_time_zone(jiff::tz::TimeZone::get("America/Los_Angeles").unwrap())
        .date()
        .checked_add(jiff::Span::new().days(2))
        .unwrap();
    let set = call(
        &runtime,
        "reminder_set",
        json!({ "text": "CS 11 midterm tomorrow — review", "at": format!("{day}T20:00") }),
    );
    let fire_at = set["fireAt"].as_str().unwrap();
    assert!(
        fire_at.contains(&format!(" {} 20:00 P", day.day())),
        "{fire_at}"
    );
    assert_eq!(set["status"], "pending");
    let listed = call(&runtime, "reminder_list", json!({}));
    assert_eq!(listed["reminders"].as_array().unwrap().len(), 1);
    let cancelled = call(&runtime, "reminder_cancel", json!({ "id": set["id"] }));
    assert_eq!(cancelled["status"], "cancelled");
    // A time in the past and an ambiguous time are refusals, never guesses.
    for (arguments, cause) in [
        (
            json!({ "text": "x", "at": "2000-01-01T08:00" }),
            "already passed",
        ),
        (
            json!({ "text": "x", "at": format!("{day}T08:00"), "in_minutes": 5 }),
            "exactly one",
        ),
        (json!({ "text": "x" }), "exactly one"),
        (json!({ "text": "x", "at": "tomorrow at eight" }), "at: "),
    ] {
        let error = tool(&runtime, "reminder_set")
            .invoke(HostInvocation {
                scope: Scope::default(),
                arguments,
            })
            .unwrap_err();
        assert!(error.to_string().contains(cause), "{error}");
    }
}

#[test]
fn a_due_notify_fires_once_as_a_plain_dm_even_after_downtime() {
    let dir = tempfile::tempdir().unwrap();
    seed_due_row(
        &dir.path().join("state"),
        "rglasses",
        "notify",
        "get your glasses",
        30,
    );
    let runtime = gate_runtime(dir.path());
    let sink = Arc::new(RecordingNotifySink::default());
    runtime.bind_notify_sink(sink.clone()).unwrap();
    assert_eq!(runtime.reconcile_schedule().unwrap(), 1);
    assert_eq!(
        runtime.reconcile_schedule().unwrap(),
        0,
        "a fired row never re-fires"
    );
    let calls = sink.calls.lock().clone();
    assert_eq!(calls.len(), 1);
    assert!(
        calls[0].starts_with("⏰ Reminder: get your glasses (was due "),
        "{calls:?}"
    );
}

#[test]
fn a_due_wake_runs_one_unprompted_turn_of_the_conversation() {
    let dir = tempfile::tempdir().unwrap();
    seed_due_row(
        &dir.path().join("state"),
        "rwatch",
        "wake",
        "close the hinge pod",
        1,
    );
    let runtime = gate_runtime(dir.path());
    let route = FakeRoute::answering();
    runtime.set_approved_intent_route(route.clone());
    assert_eq!(runtime.reconcile_schedule().unwrap(), 1);
    assert_eq!(runtime.reconcile_schedule().unwrap(), 0);
    let execution = route.sole_execution();
    assert_eq!(execution.idempotency_key, "schedule:rwatch");
    assert!(execution.content.contains("close the hinge pod"));
    assert!(
        !execution.content.contains("was due"),
        "{}",
        execution.content
    );
}

#[test]
fn a_queued_owner_dm_goes_before_a_due_wake() {
    let dir = tempfile::tempdir().unwrap();
    seed_due_row(
        &dir.path().join("state"),
        "rreport",
        "wake",
        "child finished",
        1,
    );
    let runtime = discord_runtime(
        dir.path(),
        odin_ledger::Ledger::open_in_memory().unwrap(),
        odin_domain::EffectClass::R1,
    );
    let route = FakeRoute::answering();
    runtime.set_approved_intent_route(route.clone());
    runtime
        .admit_message(&owner_dm("1000000000000000077", "what time is it?"))
        .unwrap();
    assert_eq!(runtime.reconcile_schedule().unwrap(), 0, "the wake yields");
    assert_eq!(route.count(), 0);
    assert_eq!(runtime.reconcile_admitted_intents().unwrap(), 1);
    assert_eq!(runtime.reconcile_schedule().unwrap(), 1);
    assert_eq!(route.count(), 2);
}

/// Queues `count` events of `text_len` bytes, a minute old, each about its own job.
fn queue_events(runtime: &odin_hermes::runtime::HermesRuntime, count: usize, text_len: usize) {
    let then = jiff::Timestamp::now()
        .checked_sub(jiff::SignedDuration::from_mins(1))
        .unwrap();
    for index in 0..count {
        let text = format!("event {index} {}", "x".repeat(text_len));
        let woke = runtime
            .wake_event_at(
                then,
                &format!("ev{index}"),
                &text,
                (&format!("job{index}"), "stuck"),
            )
            .unwrap();
        assert_eq!(woke, odin_hermes::runtime::EventWake::Queued);
    }
}

fn owner_runtime(
    dir: &std::path::Path,
) -> (Arc<odin_hermes::runtime::HermesRuntime>, Arc<FakeRoute>) {
    let runtime = discord_runtime(
        dir,
        odin_ledger::Ledger::open_in_memory().unwrap(),
        odin_domain::EffectClass::R1,
    );
    let route = FakeRoute::answering();
    runtime.set_approved_intent_route(route.clone());
    (runtime, route)
}

fn still_waiting(dir: &std::path::Path) -> usize {
    let store = odin_hermes::schedule::ScheduleStore::open(&dir.join("state")).unwrap();
    store.due_events(jiff::Timestamp::now()).unwrap().len()
}

#[test]
fn colins_message_is_answered_first_with_the_waiting_events_behind_it() {
    let dir = tempfile::tempdir().unwrap();
    let (runtime, route) = owner_runtime(dir.path());
    queue_events(&runtime, 3, 20);
    runtime
        .admit_message(&owner_dm("1000000000000000081", "what time is it?"))
        .unwrap();
    assert_eq!(runtime.reconcile_admitted_intents().unwrap(), 1);
    assert_eq!(route.count(), 1);
    let execution = route.sole_execution();
    assert_eq!(execution.content, "what time is it?");
    assert_eq!(execution.harness.lines.len(), 3);
    assert!(execution.harness.lines[0].contains("event 0"));
    // The turn holds them: no turn of their own follows.
    assert_eq!(
        runtime
            .reconcile_schedule_at(jiff::Timestamp::now())
            .unwrap(),
        0
    );
    assert_eq!(route.count(), 1);
}

#[test]
fn events_past_the_ride_limit_and_reports_keep_their_own_turns() {
    let dir = tempfile::tempdir().unwrap();
    let (runtime, route) = owner_runtime(dir.path());
    // Two 4000-byte events: only the first fits behind his message.
    queue_events(&runtime, 2, 4_000);
    assert!(runtime.wake_once("job:j1", "job j1 finished").unwrap());
    runtime
        .admit_message(&owner_dm("1000000000000000082", "hello"))
        .unwrap();
    assert_eq!(runtime.reconcile_admitted_intents().unwrap(), 1);
    let ridden = route.sole_execution().harness.lines;
    assert_eq!(ridden.len(), 1);
    assert!(ridden[0].contains("event 0"));
    assert_eq!(
        runtime
            .reconcile_schedule_at(jiff::Timestamp::now())
            .unwrap(),
        2
    );
    let contents = route.execution_contents();
    assert!(contents[1..].iter().any(|text| text.contains("event 1")));
    assert!(contents[1..].iter().any(|text| text.contains("job j1")));
}

#[test]
fn events_a_failed_turn_never_held_wait_for_their_own_turn() {
    let dir = tempfile::tempdir().unwrap();
    let runtime = discord_runtime(
        dir.path(),
        odin_ledger::Ledger::open_in_memory().unwrap(),
        odin_domain::EffectClass::R1,
    );
    runtime.set_approved_intent_route(FakeRoute::failing("route down"));
    queue_events(&runtime, 2, 10);
    runtime
        .admit_message(&owner_dm("1000000000000000083", "hello"))
        .unwrap();
    runtime.reconcile_admitted_intents().unwrap();
    assert_eq!(still_waiting(dir.path()), 2);
}

#[test]
fn an_event_reconcile_is_delivering_does_not_ride_his_message() {
    let dir = tempfile::tempdir().unwrap();
    let (runtime, route) = owner_runtime(dir.path());
    queue_events(&runtime, 2, 10);
    // Reconcile has leased both; the first is held for a retry, the second is mid-delivery.
    let now = jiff::Timestamp::now().as_millisecond();
    let db = rusqlite::Connection::open(dir.path().join("state/schedule.sqlite3")).unwrap();
    db.execute(
        "UPDATE schedule_items SET status = 'firing', retry_at_ms = ?1 WHERE id = 'ev0'",
        [now + 600_000],
    )
    .unwrap();
    db.execute(
        "UPDATE schedule_items SET status = 'firing' WHERE id = 'ev1'",
        [],
    )
    .unwrap();
    runtime
        .admit_message(&owner_dm("1000000000000000084", "hello"))
        .unwrap();
    assert_eq!(runtime.reconcile_admitted_intents().unwrap(), 1);
    let ridden = route.sole_execution().harness.lines;
    assert_eq!(ridden.len(), 1);
    assert!(ridden[0].contains("event 0"));
}

/// Publishes `objects` as the verified active snapshot under `root`.
pub(crate) fn published_registry(
    root: &std::path::Path,
    objects: Vec<odin_registry::RegistryObject>,
) -> Arc<odin_registry::SnapshotHandle> {
    let snapshot = odin_registry::Snapshot::build(1, objects).unwrap();
    let mut bytes = serde_json::to_vec_pretty(&snapshot).unwrap();
    bytes.push(b'\n');
    let revisions = root.join("revisions");
    std::fs::create_dir_all(&revisions).unwrap();
    std::fs::write(root.join("snapshot.json"), &bytes).unwrap();
    std::fs::write(revisions.join(format!("{:020}.snapshot.json", 1)), &bytes).unwrap();
    let receipt = json!({
        "schema": odin_registry::PUBLICATION_RECEIPT_SCHEMA,
        "outcome": "published",
        "revision": 1,
        "previous_revision": null,
        "commit": "commit-1",
        "tree": "tree-1",
        "snapshot_hash": snapshot.hash.clone(),
    });
    std::fs::write(
        revisions.join(format!("{:020}.receipt.json", 1)),
        serde_json::to_vec_pretty(&receipt).unwrap(),
    )
    .unwrap();
    let store = odin_registry::SnapshotStore::new(root.join("snapshot.json"));
    Arc::new(odin_registry::SnapshotHandle::open(store).unwrap())
}

/// The daemon's authoring route, already published: the routine is in the
/// pinned snapshot by the time `routine_set` returns.
struct PublishedRoutine;

impl odin_hermes::runtime::routines::RoutineRoute for PublishedRoutine {
    fn set(
        &self,
        _: &odin_domain::SeatId,
        request: odin_hermes::runtime::routines::RoutineSetRequest,
    ) -> Result<odin_hermes::runtime::routines::RoutineChange, String> {
        Ok(odin_hermes::runtime::routines::RoutineChange {
            routine: request.id,
            outcome: "declared".to_owned(),
            published_revision: 1,
            commit: "commit-1".to_owned(),
        })
    }

    fn remove(
        &self,
        _: &odin_domain::SeatId,
        _: &str,
    ) -> Result<odin_hermes::runtime::routines::RoutineChange, String> {
        Err("not in this test".to_owned())
    }
}

/// Eligibility starts at declaration time, not the first routine poll.
#[test]
fn a_pod_that_finishes_during_the_declaring_turn_fires_its_routine() {
    use odin_registry::schema::{parse_object_toml, RegistryKind, RoutineEvent};
    let dir = tempfile::tempdir().unwrap();
    let runtime = gate_runtime(dir.path());
    let routine = parse_object_toml(
        RegistryKind::Routine,
        "chain-check",
        "registry/routines/chain-check/routine.toml",
        r#"schema = "odin.registry.v1"
kind = "routine"
enabled = true
description = "heat-sim success launches heat-check."
seat = "sinmara"

[trigger]
event = "workload_succeeded"
profile = "heat-sim"

[action]
kind = "brief"
text = "Ask Kubert to launch heat-check."
"#,
    )
    .unwrap();
    runtime.set_registry_pin(published_registry(
        &dir.path().join("registry"),
        vec![routine],
    ));
    runtime.set_routine_route(Arc::new(PublishedRoutine));
    let set = tool(&runtime, "routine_set")
        .invoke(HostInvocation {
            scope: Scope {
                seat: Some(odin_domain::SeatId::new("sinmara").unwrap()),
                ..Scope::default()
            },
            arguments: json!({
                "id": "chain-check", "description": "heat-sim success launches heat-check.",
                "event": "workload_succeeded", "profile": "heat-sim",
                "action": "brief", "text": "Ask Kubert to launch heat-check.",
            }),
        })
        .unwrap();
    assert_eq!(set["outcome"], "declared");
    let finished = jiff::Timestamp::now().as_millisecond() + 1;
    let queued = runtime
        .routine_event(
            RoutineEvent::WorkloadSucceeded,
            Some("heat-sim"),
            "uid-heat-sim",
            "pod heat-sim finished successfully",
            finished,
        )
        .unwrap();
    assert_eq!(
        queued, 1,
        "the success after the declaration fires the chain"
    );
    let before = runtime
        .routine_event(
            RoutineEvent::WorkloadSucceeded,
            Some("heat-sim"),
            "uid-yesterday",
            "pod heat-sim finished successfully",
            finished - 86_400_000,
        )
        .unwrap();
    assert_eq!(
        before, 0,
        "a pod that finished before the routine never fires it"
    );
}

fn routine_object(id: &str, trigger: &str) -> odin_registry::RegistryObject {
    routine_acting(id, trigger, "brief", &format!("Run {id}."))
}

pub(crate) fn routine_acting(
    id: &str,
    trigger: &str,
    action: &str,
    text: &str,
) -> odin_registry::RegistryObject {
    use odin_registry::schema::{parse_object_toml, RegistryKind};
    parse_object_toml(
        RegistryKind::Routine,
        id,
        format!("registry/routines/{id}/routine.toml"),
        &format!(
            "schema = \"odin.registry.v1\"\nkind = \"routine\"\nenabled = true\n\
             description = \"{id}\"\nseat = \"sinmara\"\n\n[trigger]\n{trigger}\n\n\
             [action]\nkind = \"{action}\"\ntext = \"{text}\"\n"
        ),
    )
    .unwrap()
}


#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_received_csv_wakes_its_routine_once_with_exact_reader_guidance() {
    let dir = tempfile::tempdir().unwrap();
    let runtime = gate_runtime(dir.path());
    runtime.set_registry_pin(published_registry(
        &dir.path().join("registry"),
        vec![routine_object(
            "csv-data-row-count",
            "event = \"file_received\"",
        )],
    ));
    runtime.reconcile_routines().unwrap();
    let route = FakeRoute::answering();
    runtime.set_approved_intent_route(route.clone());
    let csv = "name,value\nalpha,1\nbeta,2\ngamma,3\ndelta,4\nepsilon,5\nzeta,6\neta,7\ntheta,8\niota,9\n";
    let app =
        axum::Router::new().route("/life.csv", axum::routing::get(move || async move { csv }));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        axum::serve(listener, app.into_make_service())
            .await
            .unwrap();
    });
    let mut message = owner_dm("1000000000000000099", "");
    message
        .attachments
        .push(odin_hermes::discord::DiscordAttachment {
            filename: "life.csv".to_owned(),
            id: "1557195830124089346".to_owned(),
            url: format!("http://{address}/life.csv"),
            content_type: Some("text/csv".to_owned()),
            size: csv.len() as u64,
        });
    let worker_runtime = runtime.clone();
    tokio::task::spawn_blocking(move || {
        assert_eq!(
            worker_runtime.admit_message(&message).unwrap()["status"],
            "queued"
        );
        assert_eq!(worker_runtime.reconcile_admitted_intents().unwrap(), 1);
        assert_eq!(worker_runtime.reconcile_schedule().unwrap(), 1);
        assert_eq!(
            worker_runtime.admit_message(&message).unwrap()["status"],
            "duplicate"
        );
        assert_eq!(worker_runtime.reconcile_admitted_intents().unwrap(), 0);
        assert_eq!(worker_runtime.reconcile_schedule().unwrap(), 0);
    })
    .await
    .unwrap();
    server.abort();
    let contents = route.execution_contents();
    assert_eq!(
        contents.len(),
        2,
        "one owner intake turn and one routine wake"
    );
    let wakes: Vec<_> = contents
        .iter()
        .filter(|text| text.contains("Run csv-data-row-count."))
        .collect();
    assert_eq!(
        wakes.len(),
        1,
        "replaying an intake cannot repeat its routine occurrence"
    );
    for text in [&contents[0], wakes[0]] {
        assert!(text.contains("life.csv"), "{text}");
        assert!(text.contains("1000000000000000099/1"), "{text}");
        assert!(text.contains("intake_read"), "{text}");
        assert!(
            !text.contains(dir.path().to_str().unwrap()),
            "no ambient path: {text}"
        );
    }
    assert_eq!(
        std::fs::read_to_string(dir.path().join("state/intake/1000000000000000099/1.txt")).unwrap(),
        csv,
    );
}

/// Status includes delivered firings and the first-observed time for routines that never fired.
#[test]
fn a_fired_routine_shows_when_it_last_fired_in_the_registry_read() {
    use odin_registry::schema::RoutineEvent;
    let dir = tempfile::tempdir().unwrap();
    let runtime = gate_runtime(dir.path());
    runtime.set_registry_pin(published_registry(
        &dir.path().join("registry"),
        vec![
            routine_object("chain-check", "event = \"workload_succeeded\""),
            routine_object("weekly-review", "schedule = \"sun 18:00\""),
        ],
    ));
    runtime.set_approved_intent_route(FakeRoute::answering());
    runtime.reconcile_routines().unwrap();
    let queued = runtime
        .routine_event(
            RoutineEvent::WorkloadSucceeded,
            None,
            "uid-1",
            "pod finished",
            jiff::Timestamp::now().as_millisecond() + 1,
        )
        .unwrap();
    assert_eq!(queued, 1);
    let before = jiff::Timestamp::now().as_millisecond();
    assert_eq!(runtime.reconcile_schedule().unwrap(), 1);
    let after = jiff::Timestamp::now().as_millisecond();
    let listed = call(&runtime, "registry_read", json!({ "kind": "routine" }));
    let entry = |id: &str| {
        listed["objects"]
            .as_array()
            .unwrap()
            .iter()
            .find(|entry| entry["id"] == id)
            .unwrap()
            .clone()
    };
    let fired = entry("chain-check")["lastFired"]
        .as_str()
        .unwrap()
        .to_owned();
    let clock = odin_hermes::schedule::OwnerClock::new(&dir.path().join("state"));
    assert!(
        [clock.render(before), clock.render(after)].contains(&fired),
        "last fired is the moment of the firing, in the owner zone: {fired}"
    );
    let never = entry("weekly-review")["lastFired"]
        .as_str()
        .unwrap()
        .to_owned();
    assert!(
        never.starts_with("never since Odin first saw it "),
        "{never}"
    );
    let single = call(
        &runtime,
        "registry_read",
        json!({ "kind": "routine", "id": "chain-check" }),
    );
    assert_eq!(single["lastFired"], fired.as_str());
    drop(runtime);
    let reopened = gate_runtime(dir.path());
    reopened.set_registry_pin(published_registry(
        &dir.path().join("registry-reopened"),
        vec![routine_object(
            "chain-check",
            "event = \"workload_succeeded\"",
        )],
    ));
    let again = call(
        &reopened,
        "registry_read",
        json!({ "kind": "routine", "id": "chain-check" }),
    );
    assert_eq!(again["lastFired"], fired.as_str(), "the firing is durable");
    // A stop between the delivered row and the routine record leaves the
    // record older: the delivered row still wins.
    rusqlite::Connection::open(dir.path().join("state/schedule.sqlite3"))
        .unwrap()
        .execute(
            "UPDATE routine_state SET fired_at_ms = 0 WHERE routine = 'chain-check'",
            [],
        )
        .unwrap();
    let stale = call(
        &reopened,
        "registry_read",
        json!({ "kind": "routine", "id": "chain-check" }),
    );
    assert_eq!(stale["lastFired"], fired.as_str(), "the newer firing wins");

    // The newer-wins merge is symmetric: a record written after the
    // delivered row (the next pass records the firing) wins too.
    let raw = rusqlite::Connection::open(dir.path().join("state/schedule.sqlite3")).unwrap();
    let delivered_ms: i64 = raw
        .query_row(
            "SELECT max(fired_at_ms) FROM schedule_items WHERE anchor = 'routine:chain-check'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    raw.execute(
        "UPDATE routine_state SET fired_at_ms = ?1 WHERE routine = 'chain-check'",
        [delivered_ms + 3_600_000],
    )
    .unwrap();
    let newer = call(
        &reopened,
        "registry_read",
        json!({ "kind": "routine", "id": "chain-check" }),
    );
    assert_ne!(newer["lastFired"], fired.as_str(), "the newer record wins");
}

/// Feeds one routine event observed just now; returns the rows queued.
pub(crate) fn fire(
    runtime: &odin_hermes::runtime::HermesRuntime,
    event: odin_registry::schema::RoutineEvent,
    key: &str,
    detail: &str,
) -> usize {
    let after = jiff::Timestamp::now().as_millisecond() + 1;
    runtime
        .routine_event(event, None, key, detail, after)
        .unwrap()
}

/// A routine row's status, found by its routine and what happened, not by
/// the occurrence id.
fn routine_row_status(dir: &std::path::Path, routine: &str, detail: &str) -> String {
    rusqlite::Connection::open(dir.join("state/schedule.sqlite3"))
        .unwrap()
        .query_row(
            "SELECT status FROM schedule_items WHERE anchor = ?1 AND instr(text, ?2) > 0",
            [
                format!("routine:{routine}"),
                format!("What happened: {detail}"),
            ],
            |row| row.get(0),
        )
        .unwrap()
}

/// Removing or replacing a routine publishes its declaration, but an occurrence it queued before the change and never
/// dispatched — leased behind the owner's queued DM, or still pending, then
/// carried across a restart — never fires afterward. What already went out
/// stays fired, and work the change does not touch still runs.
#[test]
fn a_removed_or_replaced_routine_never_fires_its_queued_occurrences() {
    use odin_registry::schema::RoutineEvent;
    let dir = tempfile::tempdir().unwrap();
    let status = |routine: &str, detail: &str| routine_row_status(dir.path(), routine, detail);
    let runtime = gate_runtime(dir.path());
    runtime.set_registry_pin(published_registry(
        &dir.path().join("registry"),
        vec![
            routine_acting("pod-dm", "event = \"incident\"", "dm", "Pod news."),
            routine_object("pod-brief", "event = \"workload_succeeded\""),
            routine_object("keep-brief", "event = \"workload_succeeded\""),
        ],
    ));
    runtime.set_approved_intent_route(FakeRoute::answering());
    runtime
        .bind_notify_sink(Arc::new(RecordingNotifySink::default()))
        .unwrap();
    runtime.reconcile_routines().unwrap();
    // Delivered before the change: each routine's first occurrence.
    assert_eq!(
        fire(
            &runtime,
            RoutineEvent::WorkloadSucceeded,
            "uid-1",
            "first run"
        ),
        2
    );
    assert_eq!(
        fire(&runtime, RoutineEvent::Incident, "inc-1", "first incident"),
        1
    );
    assert_eq!(runtime.reconcile_schedule().unwrap(), 3);
    // the owner's DM is queued: the next occurrences are leased and wait.
    runtime
        .admit_message(&owner_dm("1000000000000000077", "what time is it?"))
        .unwrap();
    assert_eq!(
        fire(
            &runtime,
            RoutineEvent::WorkloadSucceeded,
            "uid-2",
            "second run"
        ),
        2
    );
    assert!(runtime.wake_once("child-report", "child finished").unwrap());
    assert_eq!(runtime.reconcile_schedule().unwrap(), 0, "the wakes yield");
    assert_eq!(runtime.reconcile_admitted_intents().unwrap(), 1);
    assert_eq!(
        fire(&runtime, RoutineEvent::Incident, "inc-2", "second incident"),
        1
    );
    assert_eq!(status("pod-brief", "second run"), "firing");
    assert_eq!(status("pod-dm", "second incident"), "pending");
    drop(runtime);

    // Published: pod-dm removed, pod-brief replaced (another trigger, the
    // same instruction), keep-brief untouched. Then the daemon restarts.
    let reopened = gate_runtime(dir.path());
    reopened.set_registry_pin(published_registry(
        &dir.path().join("registry-changed"),
        vec![
            routine_object("pod-brief", "event = \"workload_failed\""),
            routine_object("keep-brief", "event = \"workload_succeeded\""),
        ],
    ));
    let route = FakeRoute::answering();
    reopened.set_approved_intent_route(route.clone());
    let sink = Arc::new(RecordingNotifySink::default());
    reopened.bind_notify_sink(sink.clone()).unwrap();
    // The daemon's pass order: the schedule first, then the routines.
    reopened.reconcile_schedule().unwrap();
    reopened.reconcile_routines().unwrap();
    assert_eq!(
        fire(
            &reopened,
            RoutineEvent::WorkloadFailed,
            "uid-3",
            "third run failed"
        ),
        1
    );
    reopened.reconcile_schedule().unwrap();

    let contents = route.execution_contents();
    let woke = |text: &str, detail: &str| {
        contents
            .iter()
            .any(|content| content.contains(text) && content.contains(detail))
    };
    assert!(
        woke("Run keep-brief.", "second run"),
        "untouched routine work still runs: {contents:?}"
    );
    assert!(
        contents
            .iter()
            .any(|content| content.contains("child finished")),
        "a plain wake still runs: {contents:?}"
    );
    assert!(
        woke("Run pod-brief.", "third run failed"),
        "the replacement fires: {contents:?}"
    );
    assert!(
        !woke("Run pod-brief.", "second run"),
        "the replaced routine's queued occurrence never fires: {contents:?}"
    );
    let sent = sink.calls.lock().clone();
    assert!(
        sent.iter().all(|text| !text.contains("second incident")),
        "the removed routine's queued DM never goes out: {sent:?}"
    );
    // Delivered truth is kept; the obsolete rows settle, never deleted.
    for (routine, detail) in [
        ("pod-dm", "first incident"),
        ("pod-brief", "first run"),
        ("keep-brief", "second run"),
    ] {
        assert_eq!(status(routine, detail), "fired", "{routine}: {detail}");
    }
    for (routine, detail) in [("pod-dm", "second incident"), ("pod-brief", "second run")] {
        assert_eq!(status(routine, detail), "cancelled", "{routine}: {detail}");
    }
}

/// The schedule store's inventory before routine provenance: the first two
/// registered migrations, which the ledger runner proves against their SQL.
const V2_SCHEDULE: &[odin_ledger::migration::Migration<'_>] = &[
    odin_ledger::migration::Migration::register(
        1,
        "schemas/hermes/0001_schedule.sql",
        "a896e7f301fb17d53467add5d3d2af80b0c3e741dc176824e13a6e44f53e5c71",
        include_str!("../../../../../schemas/hermes/0001_schedule.sql"),
    ),
    odin_ledger::migration::Migration::register(
        2,
        "schemas/hermes/0002_settled_deadline.sql",
        "bb70ebb884b867d23fc6aa2b1860fa080f4033a2a7a832b81e261557c75889c5",
        include_str!("../../../../../schemas/hermes/0002_settled_deadline.sql"),
    ),
];

/// Migration 3 on a real v2 `schedule.sqlite3` — the upgrade path, not the
/// JSON import. Every original field survives. A routine row the old
/// release left firing may have reached the owner: it is held, never sent and
/// never relabelled, even when its hold lapses after a reopen. A pending
/// one cannot be proven the current declaration's and is cancelled unsent.
/// Settled and plain work are untouched, and plain work still runs.
#[test]
fn a_v2_schedule_store_upgrades_with_its_firing_routine_rows_held() {
    let dir = tempfile::tempdir().unwrap();
    let state = dir.path().join("state");
    std::fs::create_dir_all(&state).unwrap();
    let db = state.join("schedule.sqlite3");
    let now = jiff::Timestamp::now().as_millisecond();
    let columns = |db: &rusqlite::Connection| -> Vec<String> {
        db.prepare("SELECT name FROM pragma_table_info('schedule_items')")
            .unwrap()
            .query_map([], |row| row.get(0))
            .unwrap()
            .collect::<rusqlite::Result<_>>()
            .unwrap()
    };
    let routine = Some("routine:pod-brief");
    // id, kind, text, fire_at_ms, anchor, status, fired_at_ms, attempts
    let seeded = [
        (
            "routine:pod-brief:legacy-firing",
            "wake",
            "Run pod-brief.\nWhat happened: firing",
            now - 60_000,
            routine,
            "firing",
            None,
            2,
        ),
        (
            "routine:pod-brief:legacy-pending",
            "wake",
            "Run pod-brief.\nWhat happened: pending",
            now - 60_000,
            routine,
            "pending",
            None,
            0,
        ),
        (
            "routine:pod-brief:legacy-fired",
            "wake",
            "Run pod-brief.\nWhat happened: fired",
            now - 3_600_000,
            routine,
            "fired",
            Some(now - 3_590_000),
            0,
        ),
        (
            "rplain",
            "wake",
            "check the hinge pod",
            now - 60_000,
            None,
            "pending",
            None,
            0,
        ),
        (
            "rlater",
            "notify",
            "stand up",
            now + 3_600_000,
            None,
            "pending",
            None,
            0,
        ),
    ];
    let created = now - 7_200_000;
    let v2 = odin_ledger::open_database(&db, V2_SCHEDULE).unwrap();
    assert!(
        !columns(&v2).iter().any(|name| name == "dispatch_started"),
        "the store is the old schema"
    );
    for (id, kind, text, fire_at, anchor, status, fired, attempts) in seeded {
        v2.execute(
            "INSERT INTO schedule_items (id, kind, text, fire_at_ms, anchor, created_at_ms, \
             status, fired_at_ms, attempts) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            rusqlite::params![id, kind, text, fire_at, anchor, created, status, fired, attempts],
        )
        .unwrap();
    }
    v2.execute(
        "INSERT INTO routine_state (routine, first_seen_ms) VALUES ('pod-brief', ?1)",
        [now - 86_400_000],
    )
    .unwrap();
    drop(v2);

    // The original fields, then (status, dispatch_started, routine_digest,
    // retry_at_ms) as the current store keeps them.
    let original = |id: &str| {
        rusqlite::Connection::open(&db)
            .unwrap()
            .query_row(
                "SELECT kind, text, fire_at_ms, anchor, created_at_ms, fired_at_ms, attempts \
                 FROM schedule_items WHERE id = ?1",
                [id],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, i64>(2)?,
                        row.get::<_, Option<String>>(3)?,
                        row.get::<_, i64>(4)?,
                        row.get::<_, Option<i64>>(5)?,
                        row.get::<_, i64>(6)?,
                    ))
                },
            )
            .unwrap()
    };
    let current = |id: &str| {
        rusqlite::Connection::open(&db)
            .unwrap()
            .query_row(
                "SELECT status, dispatch_started, routine_digest, retry_at_ms \
                 FROM schedule_items WHERE id = ?1",
                [id],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, bool>(1)?,
                        row.get::<_, Option<String>>(2)?,
                        row.get::<_, Option<i64>>(3)?,
                    ))
                },
            )
            .unwrap()
    };
    let unchanged = |settled: &[&str]| {
        for (id, kind, text, fire_at, anchor, _, fired_at, attempts) in seeded {
            if settled.contains(&id) {
                continue;
            }
            assert_eq!(
                original(id),
                (
                    kind.to_owned(),
                    text.to_owned(),
                    fire_at,
                    anchor.map(str::to_owned),
                    created,
                    fired_at,
                    attempts
                ),
                "{id}"
            );
        }
    };
    let declared = || {
        vec![routine_object(
            "pod-brief",
            "event = \"workload_succeeded\"",
        )]
    };

    let runtime = gate_runtime(dir.path());
    unchanged(&[]);
    for (id, _, _, _, _, status, _, _) in seeded {
        assert_eq!(
            current(id),
            (status.to_owned(), status == "firing", None, None),
            "{id}: only a firing row carries the uncertainty"
        );
    }
    runtime.set_registry_pin(published_registry(&dir.path().join("registry"), declared()));
    let route = FakeRoute::answering();
    runtime.set_approved_intent_route(route.clone());
    assert_eq!(
        runtime.reconcile_schedule().unwrap(),
        1,
        "the plain wake runs"
    );
    let contents = route.execution_contents();
    assert_eq!(contents.len(), 1, "{contents:?}");
    assert!(contents[0].contains("check the hinge pod"), "{contents:?}");
    let (status, started, digest, held) = current("routine:pod-brief:legacy-firing");
    assert_eq!((status.as_str(), started, digest), ("firing", true, None));
    assert!(
        held.is_some_and(|until| until > now),
        "held, not retried each pass"
    );
    assert_eq!(
        current("routine:pod-brief:legacy-pending"),
        ("cancelled".to_owned(), false, None, None)
    );
    assert_eq!(current("routine:pod-brief:legacy-fired").0, "fired");
    assert_eq!(current("rplain").0, "fired");
    assert_eq!(current("rlater").0, "pending");
    drop(runtime);

    // The hold lapses while the daemon is down; the reopened store looks
    // at the row again and still neither sends nor cancels it.
    rusqlite::Connection::open(&db)
        .unwrap()
        .execute(
            "UPDATE schedule_items SET retry_at_ms = ?1 WHERE id = ?2",
            rusqlite::params![now - 1, "routine:pod-brief:legacy-firing"],
        )
        .unwrap();
    let reopened = gate_runtime(dir.path());
    reopened.set_registry_pin(published_registry(
        &dir.path().join("registry-reopened"),
        declared(),
    ));
    let route = FakeRoute::answering();
    reopened.set_approved_intent_route(route.clone());
    assert_eq!(reopened.reconcile_schedule().unwrap(), 0);
    assert_eq!(route.count(), 0, "nothing from the old release is sent");
    let (status, started, _, held) = current("routine:pod-brief:legacy-firing");
    assert_eq!((status.as_str(), started), ("firing", true));
    assert!(held.is_some_and(|until| until > now), "held again");
    assert_eq!(current("routine:pod-brief:legacy-pending").0, "cancelled");
    assert_eq!(current("rlater").0, "pending");
    // Rows the passes did not settle keep every original field, the held
    // row's attempt count included.
    unchanged(&["rplain", "routine:pod-brief:legacy-pending"]);
}

/// A restart before the registry is pinned: routine work waits, neither
/// cancelled nor sent, while other work runs; once pinned, it fires.
#[test]
fn routine_work_waits_for_the_registry_pin_while_other_work_runs() {
    use odin_registry::schema::RoutineEvent;
    let dir = tempfile::tempdir().unwrap();
    let declared = || {
        vec![routine_object(
            "pod-brief",
            "event = \"workload_succeeded\"",
        )]
    };
    let runtime = gate_runtime(dir.path());
    runtime.set_registry_pin(published_registry(&dir.path().join("registry"), declared()));
    runtime.reconcile_routines().unwrap();
    assert_eq!(
        fire(
            &runtime,
            RoutineEvent::WorkloadSucceeded,
            "uid-1",
            "first run"
        ),
        1
    );
    drop(runtime);
    let reopened = gate_runtime(dir.path());
    let route = FakeRoute::answering();
    reopened.set_approved_intent_route(route.clone());
    assert!(reopened
        .wake_once("child-report", "child finished")
        .unwrap());
    assert_eq!(
        reopened.reconcile_schedule().unwrap(),
        1,
        "the plain wake runs"
    );
    assert_eq!(
        routine_row_status(dir.path(), "pod-brief", "first run"),
        "firing",
        "the routine waits"
    );
    reopened.set_registry_pin(published_registry(
        &dir.path().join("registry-reopened"),
        declared(),
    ));
    assert_eq!(reopened.reconcile_schedule().unwrap(), 1);
    let contents = route.execution_contents();
    assert_eq!(contents.len(), 2, "{contents:?}");
    assert!(contents[0].contains("child finished"), "{contents:?}");
    assert!(contents[1].contains("Run pod-brief."), "{contents:?}");
    assert!(contents[1].contains("first run"), "{contents:?}");
    assert_eq!(
        routine_row_status(dir.path(), "pod-brief", "first run"),
        "fired"
    );
}

