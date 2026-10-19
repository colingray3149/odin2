//! Test-only parent for the scoped URI router invariants: shared ledger, atlas, brain,
//! and artifact fixtures. Per-domain invariant tests live in the child modules.
use super::*;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use odin_atlas::SourceClass;
use odin_atlas::{AtlasCounts, AtlasNode, ATLAS_SCHEMA, ATLAS_VERSION};
use odin_brain::config::EffectiveBrainPolicy;
use odin_brain::service::{BrainServiceConfig, BrainSourceConfig};
use odin_domain::huginn::ids::ModelName;
use odin_domain::knowledge::ids::TokenizerId;
use odin_domain::knowledge::retrieval::ModelDescriptor;
use odin_domain::knowledge::{AtlasId, ToolName};
use odin_domain::{Digest, Scope};
use odin_ledger::approval::{ApprovalScope, NewApproval};
use odin_ledger::artifact::{
    ArtifactMetadata, ArtifactRegistration, NewArtifactReference, RetentionClass,
};
use odin_ledger::incident::{
    ConfidenceMicros, EvidenceRefs, IncidentObservation, IncidentSeverity,
};
use odin_ledger::lane_run;
use odin_ledger::lane_run::{NewAttempt, NewLane, NewRun};
use odin_ledger::{decode_utc, Ledger};
use odin_registry::schema::{
    AccountingWindowToml, ApprovalDefaultToml, ApprovalDefaultsToml, BudgetPolicyToml,
    RegistryKind, SeatContextToml, SeatKnowledgeToml, SeatLimitsToml, SeatToml,
    SeatToolRedirectsToml, SeatToolsToml, SliceContextToml, SliceKnowledgeToml, SliceRedirectsToml,
    SliceToml, SliceToolRedirectsToml, SliceToolsToml, REGISTRY_SCHEMA,
};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::num::{NonZeroU16, NonZeroU32, NonZeroU64};

const MAX_TEST_ARTIFACT_BYTES: u64 = 4096;

fn seeded_ledger() -> Arc<Mutex<Ledger>> {
    let mut ledger = Ledger::open_in_memory().unwrap();
    {
        let connection = ledger.connection();
        let created = decode_utc("2026-01-01T00:00:00Z").unwrap();
        lane_run::create_lane(
            connection,
            &NewLane {
                lane_id: "lane-alpha".parse().unwrap(),
                seat_id: "seat-alpha".parse().unwrap(),
                project_id: Some("project-alpha".parse().unwrap()),
                template_id: "seat-template".to_owned(),
                backend: "local_omp".to_owned(),
                created_by: "operator".to_owned(),
                created_at: created,
                retained: false,
            },
        )
        .unwrap();
        lane_run::create_run(
            connection,
            &NewRun {
                run_id: "run-alpha".parse().unwrap(),
                lane_id: "lane-alpha".parse().unwrap(),
                attempt_number: 1,
                workflow_id: None,
                workflow_version: None,
                input_hash: "input-alpha".to_owned(),
                accepted_capability_revision: None,
                lease_id: None,
                absolute_deadline: None,
                retry_budget: 3,
                created_at: created,
            },
        )
        .unwrap();
        lane_run::create_attempt(
            connection,
            &NewAttempt {
                attempt_id: "attempt-alpha".parse().unwrap(),
                run_id: "run-alpha".parse().unwrap(),
                attempt_number: 1,
                executor_id: None,
                created_at: created,
            },
        )
        .unwrap();
    }
    let requested = decode_utc("2026-01-01T00:00:00Z").unwrap();
    let expires = decode_utc("2026-01-01T00:01:00Z").unwrap();
    ledger
        .request_approval(NewApproval {
            approval_id: "approval-alpha".parse().unwrap(),
            issuer: "operator".to_owned(),
            scope: ApprovalScope {
                target_kind: "run".to_owned(),
                target_id: "run-alpha".to_owned(),
                capability_id: "capability.alpha".parse().unwrap(),
                arguments_digest: Digest::hash(b"arguments"),
            },
            requested_at: requested,
            expires_at: expires,
        })
        .unwrap();
    ledger
        .upsert_incident(
            IncidentObservation {
                incident_id: "incident-alpha".parse().unwrap(),
                run_id: Some("run-alpha".parse().unwrap()),
                severity: IncidentSeverity::Warning,
                confidence: ConfidenceMicros::new(500_000).unwrap(),
                deviation: "stalled progress".to_owned(),
                failure_signature: "signature-alpha".to_owned(),
                expected_state: json!({"status": "running"}),
                observed_state: json!({"status": "paused"}),
                affected_objects: vec!["run-alpha".to_owned()],
                evidence_refs: EvidenceRefs::new(["ledger://incidents/signature-alpha".to_owned()])
                    .unwrap(),
                allowed_capabilities: vec!["capability.alpha".parse().unwrap()],
                attempt_ids: vec!["attempt-alpha".parse().unwrap()],
                recommended_next_action: "resume the lane".to_owned(),
                escalation_target: "operator".to_owned(),
                observed_at: requested,
                last_useful_progress_at: None,
            },
            0,
        )
        .unwrap();
    ledger
        .upsert_incident(
            IncidentObservation {
                incident_id: "incident-global".parse().unwrap(),
                run_id: None,
                severity: IncidentSeverity::Info,
                confidence: ConfidenceMicros::new(100_000).unwrap(),
                deviation: "unscheduled deviation".to_owned(),
                failure_signature: "signature-global".to_owned(),
                expected_state: json!({"status": "idle"}),
                observed_state: json!({"status": "busy"}),
                affected_objects: Vec::new(),
                evidence_refs: EvidenceRefs::new(Vec::<String>::new()).unwrap(),
                allowed_capabilities: Vec::new(),
                attempt_ids: Vec::new(),
                recommended_next_action: "triage".to_owned(),
                escalation_target: "operator".to_owned(),
                observed_at: requested,
                last_useful_progress_at: None,
            },
            0,
        )
        .unwrap();
    Arc::new(Mutex::new(ledger))
}

fn atlas_node(id: &str, path: &str, tags: &[&str]) -> AtlasNode {
    AtlasNode {
        id: id.to_owned(),
        source_class: SourceClass::Rust,
        path: path.to_owned(),
        source_blake3: "0".repeat(64),
        name: id.to_owned(),
        kind: "function".to_owned(),
        signature: None,
        summary: None,
        properties: [(
            "scope_tags".to_owned(),
            Value::Array(
                tags.iter()
                    .map(|tag| Value::String(tag.to_string()))
                    .collect(),
            ),
        )]
        .into_iter()
        .collect(),
    }
}

fn test_atlas() -> Atlas {
    let nodes = vec![
        atlas_node(
            "odin:alpha:one",
            "crates/alpha/src/lib.rs",
            &["engineering"],
        ),
        atlas_node("odin:alpha:two", "crates/alpha/src/extra.rs", &[]),
        atlas_node("odin:beta:one", "crates/beta/src/lib.rs", &["operations"]),
    ];
    Atlas {
        schema: ATLAS_SCHEMA.to_owned(),
        version: ATLAS_VERSION,
        generation: "uri-test-generation".to_owned(),
        source_paths: BTreeMap::new(),
        source_hashes: BTreeMap::new(),
        counts: AtlasCounts {
            files: 0,
            nodes: nodes.len(),
            parse_errors: 0,
            by_source: BTreeMap::new(),
        },
        files: Vec::new(),
        parse_errors: Vec::new(),
        nodes,
    }
}

fn allowed_atlas_scope() -> AtlasScope {
    AtlasScope {
        source_classes: BTreeSet::from([SourceClass::Rust]),
        path_prefixes: vec!["crates/alpha".to_owned()],
        node_prefixes: Vec::new(),
        seat_categories: None,
    }
}

fn artifact_root(name: &str) -> PathBuf {
    let root = std::env::temp_dir().join("odin-omp-uri-tests").join(name);
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).unwrap();
    root
}

fn nz16(value: u16) -> NonZeroU16 {
    NonZeroU16::new(value).unwrap()
}

fn nz32(value: u32) -> NonZeroU32 {
    NonZeroU32::new(value).unwrap()
}

fn atlas_ids(values: &[&str]) -> BTreeSet<AtlasId> {
    values
        .iter()
        .map(|value| AtlasId::new(*value).unwrap())
        .collect()
}

fn tool_names(values: &[&str]) -> BTreeSet<ToolName> {
    values
        .iter()
        .map(|value| ToolName::new(*value).unwrap())
        .collect()
}

/// The registry slice for the test policy, mirroring the odin-brain policy fixture.
fn test_slice() -> SliceToml {
    SliceToml {
        schema: REGISTRY_SCHEMA.to_owned(),
        kind: RegistryKind::Slice,
        enabled: true,
        description: "policy fixture slice".to_owned(),
        capabilities: BTreeSet::new(),
        variables: BTreeMap::new(),
        redirects: SliceRedirectsToml {
            out_of_scope: "NeedsPlan".to_owned(),
        },
        knowledge: Some(SliceKnowledgeToml {
            required: false,
            atlas_sources: atlas_ids(&["atlas:uri-test"]),
            retrieval_mode: odin_domain::knowledge::RetrievalMode::Hybrid,
            candidate_limit: nz16(128),
            top_k: nz16(16),
            min_score_micros: 100_000,
            chunk_tokens: nz32(512),
            chunk_overlap_tokens: 64,
            embedding_backend: odin_domain::knowledge::EmbeddingBackend::Local,
        }),
        context: Some(SliceContextToml {
            max_bundle_tokens: nz32(32768),
            reserve_output_tokens: nz32(8192),
            control_tokens: nz32(4096),
            history_tokens: nz32(12288),
            core_tokens: nz32(2048),
            prefetch_tokens: nz32(6144),
            tool_result_tokens: nz32(4096),
            tool_schema_tokens: nz32(4096),
            max_item_tokens: nz32(2048),
        }),
        tools: Some(SliceToolsToml {
            allow: tool_names(&["read_one", "search_one"]),
            deny: tool_names(&["secret_read_raw"]),
            redirects: SliceToolRedirectsToml {
                max_http_hops: 2,
                allow_cross_origin: false,
                allow_https_downgrade: false,
            },
            alias_redirect: BTreeSet::new(),
        }),
        live: None,
        budget: None,
    }
}

/// The registry seat for the test policy, mirroring the odin-brain policy fixture.
fn test_seat() -> SeatToml {
    SeatToml {
        schema: REGISTRY_SCHEMA.to_owned(),
        kind: RegistryKind::Seat,
        enabled: true,
        description: "policy fixture seat".to_owned(),
        categories: BTreeSet::new(),
        tool_refs: BTreeSet::new(),
        project_scope: BTreeSet::new(),
        read_project_scope: BTreeSet::new(),
        models: Vec::new(),
        approval_defaults: ApprovalDefaultsToml {
            r0: ApprovalDefaultToml::Auto,
            r1: ApprovalDefaultToml::Auto,
            r2: ApprovalDefaultToml::Auto,
            r3: ApprovalDefaultToml::Approval,
        },
        brain_scope: atlas_ids(&["atlas:uri-test"]),
        limits: SeatLimitsToml {
            max_parallel_runs: 4,
            max_sessions: 4,
            budget: Some(BudgetPolicyToml {
                usd_micros: 30_000_000,
                window: AccountingWindowToml {
                    duration_seconds: NonZeroU64::new(2_592_000).unwrap(),
                },
            }),
        },
        live: None,
        knowledge: Some(SeatKnowledgeToml {
            atlas_sources: atlas_ids(&["atlas:uri-test"]),
            required_tags: BTreeSet::new(),
            denied_tags: BTreeSet::new(),
            top_k: nz16(8),
        }),
        context: Some(SeatContextToml {
            max_bundle_tokens: nz32(24576),
            profile: "sized".into(),
            review_lane: None,
        }),
        tools: Some(SeatToolsToml {
            deny: tool_names(&["search_one"]),
            redirects: SeatToolRedirectsToml {
                max_http_hops: 2,
                allow_cross_origin: false,
                disabled_aliases: BTreeSet::new(),
            },
            always: BTreeSet::new(),
        }),
        guidance: None,
        conversation: None,
        profile_namespace: None,
        ephemeral: None,
        sandbox: odin_registry::schema::SeatSandboxToml::default(),
    }
}

/// Builds the pinned brain authority for a test router: a real Atlas source tree, a
/// registry-resolved policy, and empty stores. Mirrors the odin-brain test fixtures.
fn test_brain(ledger: &Arc<Mutex<Ledger>>, root: &Path) -> Arc<BrainService> {
    let src = root.join("atlas-src/crates/demo/src");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::write(
        src.join("lib.rs"),
        "//! Demo crate.\n\n/// Adds one.\npub fn add_one(value: u64) -> u64 { value + 1 }\n",
    )
    .unwrap();
    // The real Atlas build resolves all four source classes under the
    // fixture root; the three non-Rust classes exist empty and
    // contribute no nodes.
    let atlas_root = root.join("atlas-src");
    std::fs::create_dir_all(atlas_root.join("extension")).unwrap();
    std::fs::create_dir_all(atlas_root.join("registry")).unwrap();
    std::fs::create_dir_all(atlas_root.join("skeletons")).unwrap();
    let model = ModelDescriptor {
        name: ModelName::new("model.uri-test").unwrap(),
        tokenizer: TokenizerId::new("odin.tokenizer.utf8-bytes.v1").unwrap(),
        context_window_tokens: nz32(8192),
    };
    let policy = EffectiveBrainPolicy::resolve(
        74,
        &test_slice(),
        &test_seat(),
        &BTreeMap::new(),
        &std::collections::BTreeMap::from([(
            "sized",
            &odin_registry::ContextProfileToml::sized(nz32(2048), nz32(6144)),
        )]),
        &model,
    )
    .unwrap();
    let config = BrainServiceConfig {
        store_root: root.join("brain-store"),
        sources: BTreeMap::from([(
            AtlasId::new("atlas:uri-test").unwrap(),
            BrainSourceConfig::Atlas {
                root: root.join("atlas-src"),
            },
        )]),
        embedding_available: false,
        embedding_model: None,
        archive_ingest_gate: None,
        postgres: None,
    };
    Arc::new(BrainService::open(config, policy, ledger.clone()).unwrap())
}

fn test_router(ledger: Arc<Mutex<Ledger>>, root: PathBuf) -> ScopedUriRouter {
    let brain = test_brain(&ledger, &root);
    ScopedUriRouter::new(
        ledger,
        Arc::new(test_atlas()),
        allowed_atlas_scope(),
        root,
        MAX_TEST_ARTIFACT_BYTES,
        BTreeMap::from([(SeatId::new("seat-alpha").unwrap(), brain)]),
    )
    .unwrap()
}

fn set_alpha_lane_session_ref(ledger: &Arc<Mutex<Ledger>>, session_ref: &str) {
    let guard = ledger.lock().unwrap();
    guard
        .connection()
        .execute(
            "UPDATE lanes SET session_ref=?1 WHERE lane_id=?2",
            [session_ref, "lane-alpha"],
        )
        .unwrap();
}

fn seed_artifact(ledger: &mut Ledger, root: &Path) -> (ArtifactMetadata, Vec<u8>) {
    let payload: &[u8] = b"artifact payload for uri routing";
    std::fs::write(root.join("report.txt"), payload).unwrap();
    let created = decode_utc("2026-01-01T00:00:00Z").unwrap();
    let metadata = ledger
        .register_artifact(ArtifactRegistration {
            bytes: payload,
            media_type: "text/plain",
            storage_path: "report.txt",
            retention: RetentionClass::Pinned,
            created_at: created,
        })
        .unwrap();
    ledger
        .attach_artifact_reference(
            &metadata.artifact_id,
            1,
            NewArtifactReference {
                object_kind: "run",
                object_id: "run-alpha",
                relation: "output",
                created_at: created,
            },
        )
        .unwrap();
    (metadata, payload.to_vec())
}

fn spot_json(result: &UriResult) -> &Value {
    let UriBody::Json(value) = &result.body else {
        panic!("expected canonical JSON body");
    };
    value
}

fn scoped_of_seat(seat: &str) -> UriContext {
    UriContext::new(Scope {
        seat: Some(seat.parse().unwrap()),
        ..Scope::default()
    })
}

mod artifact;
mod atlas;
mod brain;
mod ledger;
mod router;
