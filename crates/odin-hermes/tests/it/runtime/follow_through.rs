//! Follow-through on delegated work: a job that ends without its result
//! leaves the owner's ask open. The wake names what is unmet and which methods
//! were and were not tried. Each job keeps its own ask, which wakes the seat
//! once after the declared interval, until a result is delivered, a relaunch is
//! running or the ask is dropped.

use std::path::Path;
use std::sync::Arc;

use jiff::{SignedDuration, Timestamp};
use odin_hermes::runtime::{HermesRuntime, RunningJob, Unmet};

use crate::runtime::fixtures::{gate_runtime, FakeRoute};

const SUBJECT: &str = "Acme Aerogel";
const JOB: &str = "run:live:1:pod:research-deep:ab12";
const LATER_JOB: &str = "run:live:1:pod:research-deep:cd34";
const FIRST_WAKE: &str = "pod-1-a";

fn report_job(runtime: &HermesRuntime, wake: &str, job: &str) -> bool {
    let items = ["lead times of nine manufacturers are unverified".to_owned()];
    let tried = ["web.read".to_owned()];
    let untried = ["browser.interact".to_owned(), "browser.observe".to_owned()];
    runtime
        .report_unmet(
            wake,
            "A pod you launched stopped before finishing.",
            &Unmet {
                subject: SUBJECT,
                job,
                items: &items,
                methods: Some((&tried, &untried)),
            },
        )
        .unwrap()
}

fn report(runtime: &HermesRuntime) -> bool {
    report_job(runtime, FIRST_WAKE, JOB)
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
fn an_open_ask_wakes_once_per_job_and_shows_how_long_it_has_been_open() {
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
    // The same unmet job observed again opens nothing, and its state woke the seat already.
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
        0,
        "an unchanged job wakes the seat once"
    );
    // A relaunch that ends unmet is a new job: its ask wakes the seat once more.
    assert!(report_job(&runtime, "pod-2-a", LATER_JOB));
    assert_eq!(
        runtime.reconcile_schedule().unwrap(),
        1,
        "its report wakes once"
    );
    let relaunched = Timestamp::now();
    assert_eq!(
        runtime
            .reconcile_schedule_at(after(relaunched, every))
            .unwrap(),
        1
    );
    assert!(
        latest_wake(&route).contains(LATER_JOB),
        "{}",
        latest_wake(&route)
    );
}

/// Two jobs for one subject keep two asks: delivering one leaves the other open.
#[test]
fn two_jobs_for_one_subject_are_two_asks() {
    let dir = tempfile::tempdir().unwrap();
    let runtime = gate_runtime(dir.path());
    let route = FakeRoute::answering();
    runtime.set_approved_intent_route(route.clone());
    assert!(report_job(&runtime, FIRST_WAKE, JOB));
    assert!(report_job(&runtime, "pod-2-a", LATER_JOB));
    assert_eq!(runtime.reconcile_schedule().unwrap(), 2);
    assert!(runtime.ask_delivered(JOB).unwrap());
    let opened = Timestamp::now();
    assert_eq!(
        runtime
            .reconcile_schedule_at(after(opened, every(&runtime)))
            .unwrap(),
        1
    );
    assert!(
        latest_wake(&route).contains(LATER_JOB),
        "{}",
        latest_wake(&route)
    );
}

/// A cancelled job's ask follows the run that serves its subject: the
/// replacement's delivery closes it, and the dead job never wakes the seat.
#[test]
fn a_rekeyed_ask_follows_the_replacement_and_closes_when_it_delivers() {
    let dir = tempfile::tempdir().unwrap();
    let (runtime, route, opened) = open_ask(dir.path());
    assert!(runtime.rekey_ask(JOB, LATER_JOB).unwrap());
    // The old key is gone: delivering the dead job closes nothing.
    assert!(!runtime.ask_delivered(JOB).unwrap());
    let every = every(&runtime);
    assert_eq!(
        runtime.reconcile_schedule_at(after(opened, every)).unwrap(),
        1
    );
    assert!(
        latest_wake(&route).contains(LATER_JOB),
        "{}",
        latest_wake(&route)
    );
    assert!(runtime.ask_delivered(LATER_JOB).unwrap());
    assert_eq!(route.count(), 2, "the report and one interval wake only");
    // With no ask under the old key left, rekeying moves nothing.
    assert!(!runtime
        .rekey_ask(JOB, "run:live:1:pod:research-deep:ef56")
        .unwrap());
}

#[test]
fn a_delivered_result_stops_the_wakes() {
    let dir = tempfile::tempdir().unwrap();
    let (runtime, route, opened) = open_ask(dir.path());
    assert!(runtime.ask_delivered(JOB).unwrap());
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
