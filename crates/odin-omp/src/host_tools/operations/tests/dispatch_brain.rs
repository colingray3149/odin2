//! Real kernel-governed knowledge dispatch, including caller-proof failures.

use std::sync::Arc;

use super::fixture::{
    BrainEmbedding, Fixture, BRAIN_ATLAS_SOURCE, BRAIN_READ_TOOL, BRAIN_SEARCH_TOOL,
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
                result["hit"]["source"] == BRAIN_ATLAS_SOURCE
                    && result["hit"]["content"]
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

#[test]
fn a_lexical_only_reason_cannot_exceed_the_search_response_bound() {
    let fixture = Fixture::for_brain_embedding(BrainEmbedding {
        mode: RetrievalMode::Hybrid,
        // Build the real vector pool first; failing a chunk embed would
        // select the separate bounded "pool unavailable" posture instead.
        embedder: Arc::new(|texts: &[String]| {
            if texts.iter().any(|text| text == "fixture_brain_marker") {
                Err(BrainError::EmbeddingUnavailable {
                    provider: "fixture-gateway".to_owned(),
                    reason: "\n".repeat(crate::host_tools::brain::MAX_RESPONSE_BYTES),
                })
            } else {
                texts
                    .iter()
                    .map(|_| {
                        odin_brain::retrieval::embedding::EmbeddingVector::from_dims(vec![1.0; 512])
                    })
                    .collect()
            }
        }),
    });
    assert!(
        search(&fixture, "brain-search-oversized-posture").is_err(),
        "an oversized posture must not escape the search response bound"
    );
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
        let refused = search(&fixture, name);
        assert!(
            refused.is_err(),
            "{name}: the search must refuse, not degrade: {refused:?}"
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
            result["hit"]["content"]
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
    println!("governed brain search/read PASS citation {url}; {count} exact continuation pages");
}

#[test]
fn brain_dispatch_refuses_invalid_execution_before_building_an_index() {
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
        assert!(
            fixture
                .dispatch_execution(
                    BRAIN_SEARCH_TOOL,
                    Some(fixture.resource.clone()),
                    arguments(),
                    &format!("foreign-{dimension}"),
                    Some(&live),
                )
                .is_err(),
            "the caller cannot change its bound {dimension}"
        );
    }
    fixture.scope = bound;
    let builds: i64 = fixture
        .ledger
        .lock()
        .unwrap()
        .connection()
        .query_row(
            "SELECT COUNT(*) FROM audit_events WHERE kind='knowledge.index.rebuilt'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(
        builds, 0,
        "invalid execution must be refused before knowledge materialization"
    );
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

/// A question that names a source searches that declared source alone; an
/// undeclared one is refused with the session's own source list.
#[test]
fn brain_search_can_name_one_declared_source() {
    let fixture = Fixture::for_brain();
    let execution = fixture.execution();
    let found = fixture
        .dispatch_execution(
            BRAIN_SEARCH_TOOL,
            Some(fixture.resource.clone()),
            json!({"query": "fixture_brain_marker", "source": BRAIN_ATLAS_SOURCE}),
            "brain-search-source",
            Some(&execution),
        )
        .unwrap();
    assert!(!found["results"].as_array().unwrap().is_empty());
    let refused = fixture
        .dispatch_execution(
            BRAIN_SEARCH_TOOL,
            Some(fixture.resource.clone()),
            json!({"query": "fixture_brain_marker", "source": "archive.nowhere"}),
            "brain-search-undeclared",
            Some(&execution),
        )
        .unwrap_err();
    assert!(
        format!("{refused:?}").contains(BRAIN_ATLAS_SOURCE),
        "the refusal names the declared sources: {refused:?}"
    );
}
