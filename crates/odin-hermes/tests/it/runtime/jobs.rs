//! A background job's outcome wakes the conversation: Sinmara gets one job
//! report turn naming the job and how it ended, and `jobs_list` shows it.

use std::time::{Duration, Instant};

use crate::runtime::fixtures::{
    call, discord_runtime, discord_runtime_owning, discord_settings, FakeRoute,
};
use odin_domain::job_report::{reported_jobs, started_job};
use serde_json::json;

#[test]
fn a_finished_job_wakes_the_conversation_with_its_report() {
    let dir = tempfile::tempdir().unwrap();
    let runtime = discord_runtime(
        dir.path(),
        odin_ledger::Ledger::open_in_memory().unwrap(),
        odin_domain::EffectClass::R1,
    );
    let route = FakeRoute::answering();
    runtime.set_approved_intent_route(route.clone());
    let board = runtime
        .job_board()
        .expect("a Discord conversation has a job board");
    let reserved = board.try_reserve().expect("a free background slot");
    let (id, started) = board
        .start(
            reserved,
            "discord_file_send",
            &json!({ "file_name": "Neev-De-Novo-GPCR-draft.pdf" }),
            Duration::from_secs(60),
            Instant::now() - Duration::from_secs(3),
            odin_domain::progress::Slot::default(),
        )
        .expect("reserved slot detaches");
    let told = started["content"][0]["text"].as_str().unwrap();
    assert_eq!(started_job(told), Some(id.as_str()), "{told}");
    assert_eq!(
        call(&runtime, "jobs_list", json!({}))["jobs"][0]["state"],
        "running"
    );

    board.finish(
        &id,
        Ok(r#"{"sent":"Neev-De-Novo-GPCR-draft.pdf"}"#.to_owned()),
    );
    assert_eq!(runtime.reconcile_schedule().unwrap(), 1);
    assert_eq!(runtime.reconcile_schedule().unwrap(), 0, "reported once");
    let execution = route.sole_execution();
    assert!(execution.unprompted);
    assert!(
        execution.content.contains(&format!(
            "Background job {id} (discord_file_send: Neev-De-Novo-GPCR-draft.pdf) finished after"
        )),
        "{}",
        execution.content
    );
    let reported: Vec<_> = reported_jobs(&execution.content)
        .into_iter()
        .map(|report| (report.job, report.ok, report.seconds))
        .collect();
    assert_eq!(
        reported,
        [(id.as_str(), true, Some(3))],
        "its own run time, counting the 3 s it ran before it went to the background"
    );
    let listed = call(&runtime, "jobs_list", json!({}));
    assert_eq!(listed["jobs"][0]["state"], "done", "{listed}");
}

#[test]
fn reports_due_together_wake_one_turn() {
    let dir = tempfile::tempdir().unwrap();
    let runtime = discord_runtime(
        dir.path(),
        odin_ledger::Ledger::open_in_memory().unwrap(),
        odin_domain::EffectClass::R1,
    );
    let route = FakeRoute::answering();
    runtime.set_approved_intent_route(route.clone());
    let board = runtime.job_board().expect("a job board");
    // Three parallel reads detach together and come back while she is busy.
    let ids: Vec<String> = ["notes", "docs", "code"]
        .into_iter()
        .map(|query| {
            let reserved = board.try_reserve().expect("a free background slot");
            board
                .start(
                    reserved,
                    "brain_search",
                    &json!({ "query": query }),
                    Duration::from_secs(180),
                    Instant::now(),
                    odin_domain::progress::Slot::default(),
                )
                .expect("detaches")
                .0
        })
        .collect();
    board.finish(&ids[0], Ok("three notes".to_owned()));
    board.finish(&ids[1], Ok("nothing".to_owned()));
    board.finish(&ids[2], Err("search timed out".to_owned()));
    assert_eq!(runtime.reconcile_schedule().unwrap(), 1);
    assert_eq!(
        runtime.reconcile_schedule().unwrap(),
        0,
        "all three settled"
    );
    assert_eq!(route.count(), 1, "{:#?}", route.execution_contents());
    let turn = route.sole_execution().content;
    let reported: Vec<_> = reported_jobs(&turn)
        .into_iter()
        .map(|report| (report.job.to_owned(), report.ok))
        .collect();
    assert_eq!(
        reported,
        [
            (ids[0].clone(), true),
            (ids[1].clone(), true),
            (ids[2].clone(), false)
        ],
        "{turn}"
    );
}

/// A task owner whose delegated child has gone on past the turn `.0`.
struct MovedOn(&'static str);

impl odin_omp::host_tools::delegation::TaskOwner for MovedOn {
    fn create_task(
        &self,
        _: odin_omp::host_tools::delegation::TaskCreateRequest,
    ) -> Result<
        odin_omp::host_tools::delegation::TaskCreateReceipt,
        odin_omp::host_tools::delegation::TaskToolFailure,
    > {
        unreachable!("the wakes under test only ask whether the child moved on")
    }

    fn read_task(
        &self,
        _: odin_omp::host_tools::delegation::TaskReadRequest,
    ) -> Result<
        odin_omp::host_tools::delegation::TaskReadReport,
        odin_omp::host_tools::delegation::TaskToolFailure,
    > {
        unreachable!("the wakes under test only ask whether the child moved on")
    }

    fn acknowledge_inline_answer(
        &self,
        _: odin_domain::huginn::LiveSessionId,
        _: &str,
    ) -> Result<(), String> {
        Ok(())
    }

    fn preflight_task(
        &self,
        _: &odin_omp::host_tools::delegation::TaskCreateRequest,
    ) -> Result<(), odin_omp::host_tools::delegation::TaskToolFailure> {
        unreachable!("the wakes under test only ask whether the child moved on")
    }

    fn child_moved_past(&self, _: odin_domain::huginn::LiveSessionId, key: &str) -> bool {
        key == self.0
    }
}

/// A pod launch's receipt and a delegated child's turn it has moved past tell
/// the seat nothing new: they settle without a turn, while a real report and
/// the child's current turn still wake her.
#[test]
fn wakes_that_would_only_wake_the_model_for_nothing_are_dropped() {
    let dir = tempfile::tempdir().unwrap();
    let settings = odin_hermes::config::HermesSettings::new(
        dir.path().join("state"),
        Some(discord_settings()),
        None,
        Vec::new(),
    )
    .unwrap();
    let runtime = discord_runtime_owning(
        settings,
        odin_ledger::Ledger::open_in_memory().unwrap(),
        odin_domain::EffectClass::R1,
        Some(std::sync::Arc::new(MovedOn("turn-one"))),
    );
    let route = FakeRoute::answering();
    runtime.set_approved_intent_route(route.clone());
    let child = "00000000-0000-4000-8000-000000000001";
    for (key, answer) in [
        ("turn-one", "before the steer"),
        ("turn-two", "after the steer"),
    ] {
        runtime
            .wake_once(
                &odin_hermes::runtime::child_turn_wake_id(child, key),
                &format!("Work you delegated just finished a turn. Its answer:\n{answer}"),
            )
            .unwrap();
    }
    let board = runtime.job_board().expect("a job board");
    let start = |tool: &str| {
        let reserved = board.try_reserve().expect("a free background slot");
        board
            .start(
                reserved,
                tool,
                &json!({}),
                Duration::from_secs(180),
                Instant::now(),
                odin_domain::progress::Slot::default(),
            )
            .expect("detaches")
            .0
    };
    let launched = start("kube_workload_create");
    let searched = start("brain_search");
    board.finish(
        &launched,
        Ok(r#"{"status":"accepted","runId":"run:1738000000000:pod"}"#.to_owned()),
    );
    board.finish(&searched, Ok("three notes".to_owned()));

    assert_eq!(runtime.reconcile_schedule().unwrap(), 2);
    let turns = route.execution_contents();
    assert_eq!(turns.len(), 2, "{turns:#?}");
    assert!(turns.iter().any(|turn| turn.contains("after the steer")));
    assert!(turns.iter().any(|turn| turn.contains("three notes")));
    assert_eq!(runtime.reconcile_schedule().unwrap(), 0, "nothing is owed");
    assert_eq!(route.count(), 2);
}
