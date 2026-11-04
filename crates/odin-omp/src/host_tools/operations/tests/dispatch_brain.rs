//! Real kernel-governed knowledge dispatch, including caller-proof failures.

use std::sync::Arc;

use super::fixture::{
    BrainEmbedding, Fixture, BRAIN_ATLAS_SOURCE, BRAIN_READ_TOOL, BRAIN_RECORDS_TOOL,
    BRAIN_SEARCH_TOOL,
};
use crate::host_tools::operations::HostToolOperationError;
use odin_brain::error::BrainError;
use odin_brain::retrieval::QueryEmbedder;
use odin_domain::knowledge::RetrievalMode;
use odin_kernel::{ExecutorFault, OperationRejection};
use serde_json::{json, Value};

fn assert_rejected(error: HostToolOperationError) {
    assert!(
        matches!(
            error,
            HostToolOperationError::Authority(OperationRejection::Executor(
                ExecutorFault::Rejected { .. }
            ))
        ),
        "expected governed pre-effect rejection, got {error:?}"
    );
}

fn arguments() -> serde_json::Value {
    json!({"query":"fixture_brain_marker"})
}

fn failing_lane(error: fn() -> BrainError) -> Arc<QueryEmbedder> {
    Arc::new(move |_query| Err(error()))
}

fn lane_unavailable() -> BrainError {
    BrainError::EmbeddingUnavailable {
        provider: "fixture-gateway".to_owned(),
        reason: "the fixture lane is down".to_owned(),
    }
}

fn lane_corrupt() -> BrainError {
    BrainError::Corrupt {
        component: "fixture-gateway",
        reason: "the fixture lane answered a malformed vector".to_owned(),
    }
}

fn search(fixture: &Fixture, request: &str) -> Result<Value, HostToolOperationError> {
    fixture.dispatch_execution(
        BRAIN_SEARCH_TOOL,
        Some(fixture.resource.clone()),
        arguments(),
        request,
        Some(&fixture.execution()),
    )
}

/// The search output must satisfy the real declared `brain.search` output
/// schema the production catalog binds, not only the permissive fixture one.
fn assert_declared_output(search: &Value) {
    let schema: Value = serde_json::from_str(include_str!(
        "../../../../../../schemas/capability/brain.search.output.json"
    ))
    .expect("real brain.search output schema");
    let validator = jsonschema::validator_for(&schema).expect("output schema compiles");
    let errors: Vec<String> = validator
        .iter_errors(search)
        .map(|error| error.to_string())
        .collect();
    assert!(errors.is_empty(), "{errors:?}: {search}");
}

#[test]
fn a_typed_embedding_outage_serves_a_lexical_only_search_that_says_so() {
    let fixture = Fixture::for_brain_embedding(BrainEmbedding {
        mode: RetrievalMode::Hybrid,
        embedder: failing_lane(lane_unavailable),
    });
    let degraded = search(&fixture, "brain-search-lexical-only").unwrap();
    assert!(
        degraded["results"]
            .as_array()
            .unwrap()
            .iter()
            .any(|result| {
                result["source"] == BRAIN_ATLAS_SOURCE
                    && result["content"]
                        .as_str()
                        .is_some_and(|text| text.contains("fixture_brain_marker"))
            }),
        "the lexical leg still serves the declared source: {degraded}"
    );
    let posture = &degraded["posture"];
    assert_eq!(posture["mode"], "lexicalOnly", "{degraded}");
    assert!(
        posture["reason"]
            .as_str()
            .is_some_and(|reason| !reason.trim().is_empty()),
        "a lexical-only posture carries why the vector leg did not run: {degraded}"
    );
    assert_declared_output(&degraded);
    let model: Value =
        serde_json::from_str(&crate::bridge::model_tool_text(&degraded).unwrap()).unwrap();
    assert_eq!(&model["posture"], posture, "the model reads the posture");

    let healthy = Fixture::for_brain();
    let full = search(&healthy, "brain-search-full").unwrap();
    assert_eq!(full["posture"], json!({"mode": "full"}), "{full}");
    assert_declared_output(&full);
}

/// Only a typed lane outage under a hybrid plan permits a lexical-only answer.
#[test]
fn vector_and_integrity_embedding_failures_still_refuse_the_search() {
    for (name, mode, embedder) in [
        (
            "vector-lane-unavailable",
            RetrievalMode::Vector,
            failing_lane(lane_unavailable),
        ),
        (
            "hybrid-lane-corrupt",
            RetrievalMode::Hybrid,
            failing_lane(lane_corrupt),
        ),
    ] {
        let fixture = Fixture::for_brain_embedding(BrainEmbedding { mode, embedder });
        let refused = search(&fixture, name)
            .expect_err(&format!("{name}: the search must refuse, not degrade"));
        assert!(
            refused.to_string().contains("fixture-gateway"),
            "{name}: the refusal names the lane: {refused}"
        );
    }
}

#[test]
fn governed_brain_search_and_read_dispatch_with_active_proof() {
    let mut fixture = Fixture::for_brain();
    let execution = fixture.execution();
    let search = fixture
        .dispatch_execution(
            BRAIN_SEARCH_TOOL,
            Some(fixture.resource.clone()),
            arguments(),
            "brain-search-live",
            Some(&execution),
        )
        .unwrap();
    let hit = search["results"]
        .as_array()
        .unwrap()
        .iter()
        .find(|result| {
            result["content"]
                .as_str()
                .is_some_and(|text| text.contains("fixture_brain_marker"))
        })
        .expect("the declared source's marker is retrievable");
    let url = hit["url"].as_str().unwrap();
    let read = fixture
        .dispatch_execution(
            BRAIN_READ_TOOL,
            Some(fixture.resource.clone()),
            json!({"url":url}),
            "brain-read-live",
            Some(&execution),
        )
        .unwrap();
    let full = read["body"]["page"]["text"].as_str().unwrap();
    assert!(full.contains("fixture_brain_marker"));
    assert_eq!(
        format!("brain://{}", read["body"]["itemId"].as_str().unwrap()),
        url
    );
    let mut next = Some(format!("{url}/bytes/0/16"));
    let mut reconstructed = String::new();
    let mut count = 0;
    while let Some(url) = next {
        let page = fixture
            .dispatch_execution(
                BRAIN_READ_TOOL,
                Some(fixture.resource.clone()),
                json!({"url":url}),
                &format!("brain-page-{count}"),
                Some(&execution),
            )
            .unwrap();
        let page = &page["body"]["page"];
        assert_eq!(
            page["byteStart"].as_u64().unwrap() as usize,
            reconstructed.len()
        );
        reconstructed.push_str(page["text"].as_str().unwrap());
        next = page["continuation"].as_str().map(str::to_owned);
        count += 1;
        assert!(
            count < 100,
            "continuations must make bounded forward progress"
        );
    }
    assert_eq!(reconstructed, full);
    assert_rejected(
        fixture
            .dispatch_execution(
                BRAIN_READ_TOOL,
                Some(fixture.resource.clone()),
                json!({"url":url}),
                "brain-read-unbound",
                None,
            )
            .unwrap_err(),
    );
    fixture.scope.node = Some("foreign-node".parse().unwrap());
    assert_rejected(
        fixture
            .dispatch_execution(
                BRAIN_READ_TOOL,
                Some(fixture.resource.clone()),
                json!({"url":url}),
                "brain-read-foreign-node",
                Some(&execution),
            )
            .unwrap_err(),
    );
    fixture.scope.node = None;
    std::fs::write(
        fixture.root.join("brain-atlas-src/crates/demo/src/lib.rs"),
        "//! Changed source.\npub fn fixture_brain_marker() -> u64 { 2 }\n",
    )
    .unwrap();
    // A moved head keeps serving the last built generation until the
    // background pump rebuilds; a read never builds.
    fixture
        .dispatch_execution(
            BRAIN_READ_TOOL,
            Some(fixture.resource.clone()),
            json!({"url":url}),
            "brain-read-moved-head",
            Some(&execution),
        )
        .expect("the last built generation serves the cited item");
    drop(fixture._brain_slot.take());
    assert!(
        fixture
            .dispatch_execution(
                BRAIN_SEARCH_TOOL,
                Some(fixture.resource.clone()),
                arguments(),
                "brain-runtime-stopped",
                Some(&execution),
            )
            .is_err(),
        "a stopped runtime cannot keep serving through an ownership cycle"
    );
}

#[test]
fn brain_dispatch_refuses_invalid_execution() {
    let mut fixture = Fixture::for_brain();
    let live = fixture.execution();
    for (name, execution) in [
        ("missing", None),
        ("stale", Some(fixture.execution_at_epoch(2))),
    ] {
        assert_rejected(
            fixture
                .dispatch_execution(
                    BRAIN_SEARCH_TOOL,
                    Some(fixture.resource.clone()),
                    arguments(),
                    name,
                    execution.as_ref(),
                )
                .unwrap_err(),
        );
    }
    for (name, sql, reset) in [
        (
            "terminal-run",
            "UPDATE runs SET status='succeeded' WHERE run_id='run.fixture'",
            "UPDATE runs SET status='pending' WHERE run_id='run.fixture'",
        ),
        (
            "ended-session",
            "UPDATE live_sessions SET state='ended'",
            "UPDATE live_sessions SET state='ready'",
        ),
        (
            "failed-session",
            "UPDATE live_sessions SET state='failed'",
            "UPDATE live_sessions SET state='ready'",
        ),
        (
            "foreign-project",
            "UPDATE live_sessions SET project_id='foreign'",
            "UPDATE live_sessions SET project_id='project.fixture'",
        ),
    ] {
        fixture
            .ledger
            .lock()
            .unwrap()
            .connection()
            .execute(sql, [])
            .unwrap();
        assert_rejected(
            fixture
                .dispatch_execution(
                    BRAIN_SEARCH_TOOL,
                    Some(fixture.resource.clone()),
                    arguments(),
                    name,
                    Some(&live),
                )
                .unwrap_err(),
        );
        fixture
            .ledger
            .lock()
            .unwrap()
            .connection()
            .execute(reset, [])
            .unwrap();
    }
    let bound = fixture.scope.clone();
    for dimension in ["seat", "project", "lane", "run", "session", "attempt"] {
        let mut scope = bound.clone();
        match dimension {
            "seat" => scope.seat = Some("foreign".parse().unwrap()),
            "project" => scope.project = Some("foreign".parse().unwrap()),
            "lane" => scope.lane = Some("foreign".parse().unwrap()),
            "run" => scope.run = Some("foreign".parse().unwrap()),
            "session" => scope.session = Some("foreign".parse().unwrap()),
            "attempt" => scope.attempt = Some("foreign".parse().unwrap()),
            _ => unreachable!(),
        }
        fixture.scope = scope;
        fixture
            .dispatch_execution(
                BRAIN_SEARCH_TOOL,
                Some(fixture.resource.clone()),
                arguments(),
                &format!("foreign-{dimension}"),
                Some(&live),
            )
            .expect_err(&format!("the caller cannot change its bound {dimension}"));
    }
    fixture.scope = bound;
    let ungranted = Fixture::new();
    assert!(matches!(
        ungranted.dispatch_execution(
            BRAIN_SEARCH_TOOL,
            None,
            arguments(),
            "brain-without-grant",
            None,
        ),
        Err(HostToolOperationError::UnknownTool { .. })
    ));
}

/// A code-only seat cannot read global curated records or learn whether a
/// named person exists through the record API.
#[test]
fn code_only_seat_is_refused_curated_record_operations() {
    let fixture = Fixture::for_brain();
    let execution = fixture.execution();
    for op in ["person", "status"] {
        let refused = fixture
            .dispatch_execution(
                BRAIN_RECORDS_TOOL,
                Some(fixture.resource.clone()),
                json!({"op": op, "id": "Known Person"}),
                &format!("brain-records-code-only-{op}"),
                Some(&execution),
            )
            .unwrap_err();
        let message = format!("{refused:?}");
        assert!(
            message.contains("atlas.personal") && message.contains("archive.curated"),
            "the refusal names the missing scope, not the record: {refused:?}"
        );
        assert!(!message.contains("no person matches"), "{refused:?}");
    }
}
