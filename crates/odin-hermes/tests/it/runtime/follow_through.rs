//! Follow-through on delegated work: a job that ends without its result
//! leaves the owner's ask open. The wake names what is unmet and which methods
//! were and were not tried, and the ask wakes the seat again every declared
//! interval until a result is delivered, a relaunch is running or the ask is
//! dropped.

use std::path::Path;
use std::sync::Arc;

use jiff::{SignedDuration, Timestamp};
use odin_hermes::runtime::{HermesRuntime, RunningJob, Unmet};

use crate::runtime::fixtures::{gate_runtime, FakeRoute};

const SUBJECT: &str = "Acme Aerogel";
const JOB: &str = "run:live:1:pod:research-deep:ab12";
const FIRST_WAKE: &str = "pod-1-a";

fn report(runtime: &HermesRuntime) -> bool {
    let items = ["lead times of nine manufacturers are unverified".to_owned()];
    let tried = ["web.read".to_owned()];
    let untried = ["browser.interact".to_owned(), "browser.observe".to_owned()];
    runtime
        .report_unmet(
            FIRST_WAKE,
            "A pod you launched stopped before finishing.",
            &Unmet {
                subject: SUBJECT,
                job: JOB,
                items: &items,
                methods: Some((&tried, &untried)),
            },
        )
        .unwrap()
}

/// A pod for `SUBJECT` ended partial and its wake has run: the ask is open
/// from `opened` on.
fn open_ask(dir: &Path) -> (Arc<HermesRuntime>, Arc<FakeRoute>, Timestamp) {
    let runtime = gate_runtime(dir);
    let route = FakeRoute::answering();
    runtime.set_approved_intent_route(route.clone());
    assert!(report(&runtime));
    assert_eq!(runtime.reconcile_schedule().unwrap(), 1);
    (runtime, route, Timestamp::now())
}

fn after(opened: Timestamp, minutes: i64) -> Timestamp {
    opened + SignedDuration::from_mins(minutes)
}

fn every(runtime: &HermesRuntime) -> i64 {
    i64::from(runtime.settings().open_ask_minutes)
}

fn latest_wake(route: &FakeRoute) -> String {
    route.execution_contents().pop().expect("a wake ran")
}

#[test]
fn a_partial_report_wake_names_what_is_unmet_tried_and_untried_and_keeps_the_ask_open() {
    let dir = tempfile::tempdir().unwrap();
    let (_, route, _) = open_ask(dir.path());
    let wake = latest_wake(&route);
    assert!(wake.contains("stopped before finishing"), "{wake}");
    assert!(
        wake.contains(SUBJECT) && wake.contains("still open"),
        "{wake}"
    );
    assert!(
        wake.contains("lead times of nine manufacturers are unverified"),
        "{wake}"
    );
    let line_with = |needle: &str| wake.lines().find(|line| line.contains(needle)).unwrap();
    assert!(!line_with("web.read").contains("browser.observe"), "{wake}");
    assert!(
        line_with("browser.interact").contains("browser.observe"),
        "{wake}"
    );
}

#[test]
fn an_open_ask_wakes_again_every_interval_and_shows_how_long_it_has_been_open() {
    let dir = tempfile::tempdir().unwrap();
    let (runtime, route, opened) = open_ask(dir.path());
    let every = every(&runtime);
    assert_eq!(
        runtime
            .reconcile_schedule_at(after(opened, every - 1))
            .unwrap(),
        0,
        "the interval has not passed"
    );
    assert_eq!(
        runtime.reconcile_schedule_at(after(opened, every)).unwrap(),
        1
    );
    assert!(
        latest_wake(&route).contains(&format!("open {every} min")),
        "{}",
        latest_wake(&route)
    );
    // The pump seeing the same unmet report again opens nothing and moves no wake.
    assert!(!report(&runtime));
    assert_eq!(
        runtime
            .reconcile_schedule_at(after(opened, every + 1))
            .unwrap(),
        0
    );
    assert_eq!(
        runtime
            .reconcile_schedule_at(after(opened, 2 * every))
            .unwrap(),
        1
    );
    assert!(
        latest_wake(&route).contains(&format!("open {} min", 2 * every)),
        "{}",
        latest_wake(&route)
    );
}

#[test]
fn a_delivered_result_stops_the_wakes() {
    let dir = tempfile::tempdir().unwrap();
    let (runtime, route, opened) = open_ask(dir.path());
    assert!(runtime.ask_delivered(SUBJECT).unwrap());
    assert_eq!(
        runtime
            .reconcile_schedule_at(after(opened, every(&runtime)))
            .unwrap(),
        0
    );
    assert_eq!(route.count(), 1, "only the report itself woke her");
}

#[test]
fn an_open_ask_survives_a_restart() {
    let dir = tempfile::tempdir().unwrap();
    let (runtime, _, opened) = open_ask(dir.path());
    let every = every(&runtime);
    drop(runtime);
    let runtime = gate_runtime(dir.path());
    let route = FakeRoute::answering();
    runtime.set_approved_intent_route(route.clone());
    assert_eq!(
        runtime.reconcile_schedule_at(after(opened, every)).unwrap(),
        1
    );
    assert!(latest_wake(&route).contains(SUBJECT));
}

/// A pod that runs shows in live memory while it does.
#[test]
fn a_running_pod_shows_in_live_memory() {
    let dir = tempfile::tempdir().unwrap();
    let runtime = gate_runtime(dir.path());
    runtime.set_running_jobs(vec![RunningJob {
        id: JOB.to_owned(),
        title: "Beta Foams".to_owned(),
        started_ms: 0,
    }]);
    let entries = runtime.job_board().unwrap().live_entries(0);
    assert!(
        entries
            .iter()
            .any(|entry| entry.open && entry.id == JOB && entry.line.contains("Beta Foams")),
        "{entries:?}"
    );
}
