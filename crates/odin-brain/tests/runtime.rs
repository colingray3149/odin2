//! `BrainService` runtime composition contracts.
//!
//! Defends the observable serving behavior of the composed service over a
//! real Atlas fixture and the real loopback vault source contract:
//! - An absent knowledge policy composes no serving surface; the affected
//!   operations fail typed-unavailable and nothing else degrades.
//! - The wired source set must equal the policy's authorized set exactly.
//! - One generation per Atlas source, merged candidate pools across sources,
//!   and `brain://`-shaped item resolution with real node provenance.
//! - A wired vault that is not serving fails typed (`Unavailable`, named
//!   component) — never silently partial results.

use std::collections::{BTreeMap, BTreeSet};
use std::num::{NonZeroU16, NonZeroU32, NonZeroU64};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use odin_brain::config::EffectiveBrainPolicy;
use odin_brain::context::PinnedTokenizer;
use odin_brain::error::{BrainError, BrainResult};
use odin_brain::index::postgres::BrainPostgres;
use odin_brain::service::{BrainService, BrainServiceConfig, BrainSourceConfig};
use odin_domain::huginn::ids::ModelName;
use odin_domain::knowledge::{AtlasId, EmbeddingBackend, RetrievalMode};
use odin_domain::{Digest, SeatId};
use odin_ledger::Ledger;
use odin_registry::schema::{
    AccountingWindowToml, ApprovalDefaultToml, ApprovalDefaultsToml, BudgetPolicyToml,
    RegistryKind, SeatKnowledgeToml, SeatLimitsToml, SeatToml, SliceKnowledgeToml,
    SliceRedirectsToml, SliceToml, REGISTRY_SCHEMA,
};

use odin_domain::knowledge::ids::EmbeddingModelId;
use odin_domain::knowledge::retrieval::ModelDescriptor;

#[path = "support/postgres.rs"]
mod postgres_cluster;
#[path = "runtime/project_sources.rs"]
mod project_sources;

const ATLAS_FIXTURE_ID: &str = "atlas:runtime-fixture";
const VAULT_FIXTURE_ID: &str = "vault:silverbullet";
/// A loopback port no test server listens on: the vault source must fail
/// typed instead of hanging or faking content.
const DEAD_VAULT_PORT: u16 = 1;

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

/// Writes a real, buildable crate so the fixture pins through the actual
/// `odin-atlas` build (no text-only substitute exists).
fn fixture_root(tag: &str, crate_name: &str, fn_name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "odin-brain-runtime-{tag}-{}-{}",
        crate_name,
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    let src = dir.join("crates").join(crate_name).join("src");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::write(
        src.join("lib.rs"),
        format!(
            "//! Fixture crate {crate_name}.\n\n/// Adds one to the input.\n\
             pub fn {fn_name}(value: u64) -> u64 {{ value + 1 }}\n"
        ),
    )
    .unwrap();
    // The real Atlas build resolves all four source classes under the root
    // and fails on the first missing one; the three non-Rust classes exist
    // empty here and contribute no nodes.
    std::fs::create_dir_all(dir.join("extension")).unwrap();
    std::fs::create_dir_all(dir.join("registry")).unwrap();
    std::fs::create_dir_all(dir.join("skeletons")).unwrap();
    dir
}

fn slice(atlas_sources: &[&str]) -> SliceToml {
    let knowledge = (!atlas_sources.is_empty()).then(|| SliceKnowledgeToml {
        required: false,
        atlas_sources: atlas_ids(atlas_sources),
        retrieval_mode: RetrievalMode::Lexical,
        candidate_limit: nz16(64),
        top_k: nz16(8),
        min_score_micros: 0,
        chunk_tokens: nz32(512),
        chunk_overlap_tokens: 64,
        embedding_backend: EmbeddingBackend::Local,
    });
    SliceToml {
        schema: REGISTRY_SCHEMA.to_owned(),
        kind: RegistryKind::Slice,
        enabled: true,
        description: "runtime fixture slice".to_owned(),
        capabilities: BTreeSet::new(),
        variables: BTreeMap::new(),
        redirects: SliceRedirectsToml {
            out_of_scope: "NeedsPlan".to_owned(),
        },
        knowledge,
        context: None,
        tools: None,
        live: None,
        budget: None,
    }
}

fn seat(atlas_sources: &[&str]) -> SeatToml {
    let knowledge = (!atlas_sources.is_empty()).then(|| SeatKnowledgeToml {
        atlas_sources: atlas_ids(atlas_sources),
        required_tags: BTreeSet::new(),
        denied_tags: BTreeSet::new(),
        top_k: nz16(8),
    });
    SeatToml {
        schema: REGISTRY_SCHEMA.to_owned(),
        kind: RegistryKind::Seat,
        enabled: true,
        description: "runtime fixture seat".to_owned(),
        categories: BTreeSet::new(),
        project_scope: BTreeSet::new(),
        read_project_scope: BTreeSet::new(),
        models: Vec::new(),
        tool_refs: BTreeSet::new(),
        approval_defaults: ApprovalDefaultsToml {
            r0: ApprovalDefaultToml::Auto,
            r1: ApprovalDefaultToml::Auto,
            r2: ApprovalDefaultToml::Auto,
            r3: ApprovalDefaultToml::Auto,
        },
        brain_scope: atlas_ids(&[
            "atlas:runtime-fixture",
            "atlas:runtime-second",
            "vault:silverbullet",
        ]),
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
        guidance: None,
        conversation: None,
        profile_namespace: None,
        knowledge,
        context: None,
        tools: None,
        ephemeral: None,
        sandbox: odin_registry::schema::SeatSandboxToml::default(),
    }
}

fn model() -> ModelDescriptor {
    ModelDescriptor {
        name: ModelName::new("model.runtime").unwrap(),
        tokenizer: PinnedTokenizer::id().unwrap(),
        context_window_tokens: nz32(8192),
    }
}

fn resolve(atlas_sources: &[&str]) -> EffectiveBrainPolicy {
    EffectiveBrainPolicy::resolve(
        74,
        &slice(atlas_sources),
        &seat(atlas_sources),
        &BTreeMap::new(),
        &std::collections::BTreeMap::new(),
        &model(),
    )
    .unwrap()
}

fn ledger() -> Arc<Mutex<Ledger>> {
    Arc::new(Mutex::new(Ledger::open_in_memory().unwrap()))
}

fn config(tag: &str, sources: BTreeMap<AtlasId, BrainSourceConfig>) -> BrainServiceConfig {
    BrainServiceConfig {
        // Per-test store tags keep the durable atlas-content baselines from
        // colliding across tests that share one process.
        store_root: std::env::temp_dir().join(format!(
            "odin-brain-runtime-store-{tag}-{}",
            std::process::id()
        )),
        sources,
        embedding_available: false,
        embedding_model: None,
        archive_ingest_gate: None,
        postgres: None,
    }
}

fn atlas_source(id: &str, root: &std::path::Path) -> (AtlasId, BrainSourceConfig) {
    (
        AtlasId::new(id).unwrap(),
        BrainSourceConfig::Atlas {
            root: root.to_path_buf(),
        },
    )
}

fn dead_vault() -> (AtlasId, BrainSourceConfig) {
    (
        AtlasId::new(VAULT_FIXTURE_ID).unwrap(),
        BrainSourceConfig::SilverBullet {
            port: DEAD_VAULT_PORT,
            expected_space_root: Some("/home/colin/vault".to_owned()),
            general_namespaces: vec!["knowledge".to_owned()],
            generated_namespace: "generated".to_owned(),
            excluded_namespaces: vec!["finance".to_owned()],
            max_pages: 100,
        },
    )
}

/// Unwraps an `open` failure without requiring `Debug` on the service:
/// the error side carries the typed contract under test.
fn open_err(result: BrainResult<BrainService>) -> BrainError {
    match result {
        Err(error) => error,
        Ok(_) => panic!("brain service open must fail for this configuration"),
    }
}

/// Absent knowledge authority: the service composes no serving surface, the
/// affected operations fail typed-unavailable, and status stays honest about
/// serving nothing.
#[test]
fn absent_knowledge_policy_composes_no_serving_surface() {
    let policy = resolve(&[]);
    assert!(policy.knowledge.is_none());
    let service = BrainService::open(config("absent", BTreeMap::new()), policy, ledger()).unwrap();

    let error = service.ensure_generation().unwrap_err();
    assert!(
        matches!(
            error,
            BrainError::Unavailable {
                component: "knowledge_policy",
                ..
            }
        ),
        "index builds without a knowledge policy must be typed-unavailable: {error:?}"
    );
    let error = service
        .knowledge_item(
            &odin_domain::knowledge::KnowledgeItemId::new(odin_domain::Digest::hash(b"absent")),
            None,
        )
        .unwrap_err();
    assert!(
        matches!(
            error,
            BrainError::Unavailable {
                component: "knowledge_policy",
                ..
            }
        ),
        "item resolution without a knowledge policy must be typed-unavailable: {error:?}"
    );
    let status = service.status().unwrap();
    assert!(
        status.pinned.is_empty() && status.generations.is_empty(),
        "a service with no knowledge source serves nothing: {status:?}"
    );
}

/// The wired source set must equal the authorized set exactly: an authorized
/// source without a wired binding and a wired source outside the policy are
/// both open failures, never silent narrowing or silent excess.
#[test]
fn open_rejects_source_set_mismatch() {
    let policy = resolve(&[ATLAS_FIXTURE_ID]);

    let error = open_err(BrainService::open(
        config("reject-empty", BTreeMap::new()),
        policy.clone(),
        ledger(),
    ));
    assert!(
        matches!(error, BrainError::InvalidPolicy(_)),
        "an authorized source without a wired binding must fail open: {error:?}"
    );

    let root = fixture_root("extra", "extra", "extra_fn");
    let error = open_err(BrainService::open(
        config(
            "reject-extra",
            BTreeMap::from([
                atlas_source(ATLAS_FIXTURE_ID, &root),
                atlas_source("atlas:runtime-second", &root),
            ]),
        ),
        policy,
        ledger(),
    ));
    assert!(
        matches!(error, BrainError::InvalidPolicy(_)),
        "a wired source outside the authorized set must fail open: {error:?}"
    );
}

/// An absent knowledge policy composes no sources: wiring a source without
/// any resolved knowledge authority is invalid composition, refused at open
/// with a typed policy error — never a silently ignored source behind a
/// service that serves nothing.
#[test]
fn open_refuses_wired_source_without_knowledge_policy() {
    let policy = resolve(&[]);
    assert!(policy.knowledge.is_none());

    let root = fixture_root("unwired", "unwired", "unwired_fn");
    let error = open_err(BrainService::open(
        config(
            "unwired",
            BTreeMap::from([atlas_source(ATLAS_FIXTURE_ID, &root)]),
        ),
        policy,
        ledger(),
    ));
    assert!(
        matches!(error, BrainError::InvalidPolicy(_)),
        "wiring a source without a knowledge policy must fail open: {error:?}"
    );
}

/// The single-Atlas smoke: real Atlas build, per-head generation, lexical
/// retrieval over the merged pool, and brain://-shaped item resolution with
/// real node provenance.
#[test]
fn atlas_service_serves_generation_retrieval_and_item() {
    let root = fixture_root("single", "demo", "alpha_add");
    let policy = resolve(&[ATLAS_FIXTURE_ID]);
    let sources = BTreeMap::from([atlas_source(ATLAS_FIXTURE_ID, &root)]);
    let service = BrainService::open(config("single", sources), policy.clone(), ledger()).unwrap();

    let generations = service.ensure_generation().unwrap();
    assert_eq!(generations.len(), 1, "one generation per composed source");
    assert_eq!(generations[0].atlas_id.as_str(), ATLAS_FIXTURE_ID);

    let status = service.status().unwrap();
    let fixture_id = AtlasId::new(ATLAS_FIXTURE_ID).unwrap();
    assert!(
        status.pinned.contains_key(&fixture_id),
        "status pins the live source head"
    );
    assert!(
        status.generations.contains_key(&fixture_id),
        "status serves the generation built for the live head"
    );

    let knowledge = policy.knowledge.as_ref().unwrap();
    let query = knowledge.retrieval_query("alpha_add".to_owned()).unwrap();
    let hits = service.retrieve(&query, None, None).unwrap().hits;
    assert!(!hits.is_empty(), "the fixture function must be retrievable");
    assert!(
        hits.iter()
            .all(|hit| hit.source.as_str() == ATLAS_FIXTURE_ID),
        "every hit cites its composing source"
    );

    let item = service.knowledge_item(&hits[0].item_id, None).unwrap();
    assert_eq!(&item.generation, &generations[0]);
    let provenance = item.provenance.expect("Atlas items carry node provenance");
    assert!(
        provenance.path.contains("demo"),
        "provenance names the fixture source path: {:?}",
        provenance.path
    );
    assert!(!item.chunks.is_empty());
}

/// Two Atlas sources: both generations build, the candidate pool merges, and
/// each source's content is retrievable through the one shared service.
#[test]
fn two_atlas_sources_merge_into_one_retrieval_pool() {
    let alpha_root = fixture_root("alpha", "alpha", "alpha_add");
    let beta_root = fixture_root("beta", "beta", "beta_mul");
    let policy = resolve(&["atlas:runtime-fixture", "atlas:runtime-second"]);
    let sources = BTreeMap::from([
        atlas_source("atlas:runtime-fixture", &alpha_root),
        atlas_source("atlas:runtime-second", &beta_root),
    ]);
    let service = BrainService::open(config("merge", sources), policy.clone(), ledger()).unwrap();

    let generations = service.ensure_generation().unwrap();
    assert_eq!(generations.len(), 2, "one generation per composed source");

    let knowledge = policy.knowledge.as_ref().unwrap();
    for (needle, source_id) in [
        ("alpha_add", "atlas:runtime-fixture"),
        ("beta_mul", "atlas:runtime-second"),
    ] {
        let query = knowledge.retrieval_query(needle.to_owned()).unwrap();
        let hits = service.retrieve(&query, None, None).unwrap().hits;
        assert!(
            hits.iter().any(|hit| hit.source.as_str() == source_id),
            "query {needle:?} must reach the {source_id} generation through the merged pool"
        );
    }
}

/// The fused PostgreSQL query must return the same results as the SQLite path.
#[test]
fn a_turn_serves_from_the_postgres_store_once_its_generations_are_mirrored() {
    let cluster = postgres_cluster::TestCluster::start();
    let postgres = Arc::new(BrainPostgres::connect(&cluster.conninfo).unwrap());
    let ids = ["atlas:runtime-fixture", "atlas:runtime-second"];
    let policy = resolve(&ids);
    let sources = BTreeMap::from([
        atlas_source(ids[0], &fixture_root("pg-alpha", "alpha", "alpha_add")),
        atlas_source(ids[1], &fixture_root("pg-beta", "beta", "beta_mul")),
    ]);
    let sqlite = BrainService::open(
        config("pg-sqlite", sources.clone()),
        policy.clone(),
        ledger(),
    )
    .unwrap();
    let served = BrainService::open(
        BrainServiceConfig {
            postgres: Some(postgres),
            ..config("pg", sources)
        },
        policy.clone(),
        ledger(),
    )
    .unwrap();
    assert_eq!(served.warm(dead_lane().as_ref(), 4_096).unwrap(), 0);
    let knowledge = policy.knowledge.as_ref().unwrap();
    for (needle, source) in [("alpha_add", ids[0]), ("beta_mul", ids[1])] {
        let query = knowledge.retrieval_query(needle.to_owned()).unwrap();
        let expected = sqlite.retrieve(&query, None, None).unwrap().hits;
        let hits = served.retrieve(&query, None, None).unwrap().hits;
        assert_eq!(hits[0].source.as_str(), source, "{needle}: {hits:?}");
        assert_eq!(hits[0].item_id, expected[0].item_id, "{needle}");
    }
    let held = std::process::Command::new("psql")
        .args([
            &cluster.conninfo,
            "-tAc",
            "SELECT count(*) FROM brain_generation",
        ])
        .output()
        .unwrap();
    assert_eq!(String::from_utf8_lossy(&held.stdout).trim(), "2");
}

/// With the PostgreSQL store unreachable a turn fails typed; it never
/// serves the SQLite index instead.
#[test]
fn a_turn_fails_while_the_postgres_store_is_down() {
    let cluster = postgres_cluster::TestCluster::start();
    let postgres = Arc::new(BrainPostgres::connect(&cluster.conninfo).unwrap());
    let ids = ["atlas:runtime-fixture"];
    let policy = resolve(&ids);
    let sources = BTreeMap::from([atlas_source(
        ids[0],
        &fixture_root("pg-down", "alpha", "alpha_add"),
    )]);
    let served = BrainService::open(
        BrainServiceConfig {
            postgres: Some(Arc::clone(&postgres)),
            ..config("pg-down", sources)
        },
        policy.clone(),
        ledger(),
    )
    .unwrap();
    assert_eq!(served.warm(dead_lane().as_ref(), 4_096).unwrap(), 0);
    let knowledge = policy.knowledge.as_ref().unwrap();
    let query = knowledge.retrieval_query("alpha_add".to_owned()).unwrap();
    let hits = served.retrieve(&query, None, None).unwrap().hits;
    assert_eq!(hits[0].source.as_str(), ids[0]);

    // Stop the throwaway cluster for real: the conninfo's host is its
    // private socket directory, the data dir sits under it.
    let socket_dir = cluster
        .conninfo
        .split_once("host=")
        .and_then(|(_, rest)| rest.split_whitespace().next())
        .unwrap();
    let stopped = std::process::Command::new("pg_ctl")
        .args(["--mode=immediate", "--pgdata"])
        .arg(format!("{socket_dir}/data"))
        .arg("stop")
        .output()
        .unwrap();
    assert!(
        stopped.status.success(),
        "{}",
        String::from_utf8_lossy(&stopped.stderr)
    );
    assert!(served.retrieve(&query, None, None).is_err());
}

/// A wired vault that is not serving: open still succeeds (vault sources are
/// live services, proven per operation), every serving operation fails typed
/// with the named silverbullet component.
#[test]
fn unreachable_vault_fails_typed() {
    let root = fixture_root("vaultless", "demo", "alpha_add");
    let policy = resolve(&[ATLAS_FIXTURE_ID, VAULT_FIXTURE_ID]);
    let sources = BTreeMap::from([atlas_source(ATLAS_FIXTURE_ID, &root), dead_vault()]);
    let service = BrainService::open(config("vaultdown", sources), policy, ledger()).unwrap();

    let error = service.status().unwrap_err();
    assert!(
        matches!(
            &error,
            BrainError::Unavailable {
                component: "silverbullet",
                ..
            }
        ),
        "an unreachable vault must be typed-unavailable: {error:?}"
    );

    let error = service.ensure_generation().unwrap_err();
    assert!(
        matches!(
            &error,
            BrainError::Unavailable {
                component: "silverbullet",
                ..
            }
        ),
        "generation rebuilds must not silently skip the dead vault: {error:?}"
    );
}

/// Unrequested sources are neither pinned nor built, so their outages cannot fail a search.
#[test]
fn a_scoped_search_serves_its_source_while_an_unrequested_vault_is_down() {
    let root = fixture_root("scoped-vaultdown", "demo", "alpha_add");
    let policy = resolve(&[ATLAS_FIXTURE_ID, VAULT_FIXTURE_ID]);
    let sources = BTreeMap::from([atlas_source(ATLAS_FIXTURE_ID, &root), dead_vault()]);
    let service = BrainService::open(
        config("scoped-vaultdown", sources),
        policy.clone(),
        ledger(),
    )
    .unwrap();
    let knowledge = policy.knowledge.as_ref().unwrap();
    let mut query = knowledge.retrieval_query("alpha_add".to_owned()).unwrap();

    query.sources = atlas_ids(&[ATLAS_FIXTURE_ID]);
    let served = service.retrieve(&query, None, None).unwrap();
    assert!(
        served
            .hits
            .iter()
            .any(|hit| hit.content.contains("alpha_add")),
        "the requested source serves: {:?}",
        served.hits
    );
    assert!(
        served
            .hits
            .iter()
            .all(|hit| hit.source.as_str() == ATLAS_FIXTURE_ID),
        "only the requested source serves: {:?}",
        served.hits
    );

    query.sources = atlas_ids(&[VAULT_FIXTURE_ID]);
    let error = service.retrieve(&query, None, None).unwrap_err();
    assert!(
        matches!(
            &error,
            BrainError::Unavailable {
                component: "silverbullet",
                ..
            }
        ),
        "a requested source that is down refuses typed: {error:?}"
    );
}

/// A vault-only policy: retrieval-class operations stay wired behind the
/// live vault.
#[test]
fn vault_only_policy_serves_through_the_live_vault() {
    let policy = resolve(&[VAULT_FIXTURE_ID]);
    let sources = BTreeMap::from([dead_vault()]);
    let service = BrainService::open(config("vaultonly", sources), policy, ledger()).unwrap();

    let error = service.status().unwrap_err();
    assert!(
        matches!(
            &error,
            BrainError::Unavailable {
                component: "silverbullet",
                ..
            }
        ),
        "the live vault is still the serving surface and fails typed when down: {error:?}"
    );
}

/// The vault namespace scope is mandatory configuration, validated at
/// open: a scope whose allowlist intersects its exclusions is an authority
/// violation — `InvalidPolicy` with the offending field named — never a
/// deferred per-serving failure and never a permissive fallback. The check
/// runs before any network I/O, so this test is deterministic offline.
#[test]
fn open_rejects_invalid_vault_scope() {
    let policy = resolve(&[VAULT_FIXTURE_ID]);
    let sources = BTreeMap::from([(
        AtlasId::new(VAULT_FIXTURE_ID).unwrap(),
        BrainSourceConfig::SilverBullet {
            port: DEAD_VAULT_PORT,
            expected_space_root: None,
            general_namespaces: vec!["knowledge".to_owned(), "finance".to_owned()],
            generated_namespace: "generated".to_owned(),
            excluded_namespaces: vec!["finance".to_owned()],
            max_pages: 100,
        },
    )]);
    let error = open_err(BrainService::open(
        config("vaultscope", sources),
        policy,
        ledger(),
    ));
    assert!(
        matches!(&error, BrainError::InvalidPolicy(reason)
            if reason.contains("excluded_namespaces") && reason.contains("finance")),
        "a vault scope violating the namespace law must fail open typed: {error:?}"
    );
}

fn slice_with_mode(atlas_sources: &[&str], mode: RetrievalMode) -> SliceToml {
    let mut slice = slice(atlas_sources);
    if let Some(knowledge) = slice.knowledge.as_mut() {
        knowledge.retrieval_mode = mode;
    }
    slice
}

fn resolve_mode(atlas_sources: &[&str], mode: RetrievalMode) -> EffectiveBrainPolicy {
    EffectiveBrainPolicy::resolve(
        74,
        &slice_with_mode(atlas_sources, mode),
        &seat(atlas_sources),
        &BTreeMap::new(),
        &std::collections::BTreeMap::new(),
        &model(),
    )
    .unwrap()
}

/// A partial embedding binding (an available backend without its declared
/// model, or the reverse) fails typed at service open before any embedding
/// execution: no session-bound embedder can be supplied to a service whose
/// open rejected the binding.
#[test]
fn partial_embedding_binding_fails_typed_before_any_execution() {
    let root = fixture_root("binding", "bind_demo", "bind_fn");
    let sources = BTreeMap::from([atlas_source(ATLAS_FIXTURE_ID, &root)]);
    let policy = resolve_mode(&[ATLAS_FIXTURE_ID], RetrievalMode::Vector);

    let mut backend_only = config("binding-backend-only", sources.clone());
    backend_only.embedding_available = true;
    let error = open_err(BrainService::open(backend_only, policy.clone(), ledger()));
    assert!(
        matches!(error, BrainError::InvalidPolicy(_)),
        "an available backend without its declared model must fail open: {error:?}"
    );

    let mut model_only = config("binding-model-only", sources);
    model_only.embedding_model =
        Some(EmbeddingModelId::new("test:fixture-model-v1").expect("model id"));
    let error = open_err(BrainService::open(model_only, policy, ledger()));
    assert!(
        matches!(error, BrainError::InvalidPolicy(_)),
        "a declared model without an available backend must fail open: {error:?}"
    );
}

#[test]
fn a_live_head_change_serves_the_last_built_generation_until_the_pump_rebuilds() {
    use odin_brain::source::state::live::LiveSource;
    use odin_domain::huginn::{
        Freshness, FreshnessState, ObjectKind, ObjectRef, ObjectSnapshot, Revision, RevisionSource,
    };
    use odin_huginn::read_model::MaterializedReadModel;

    let now = time::OffsetDateTime::UNIX_EPOCH;
    let read_model = MaterializedReadModel::new(16, now);
    let snapshot = |revision, status: &str| {
        let value = serde_json::json!({
            "sessionId": "session-k1",
            "seatId": "sinmara",
            "projectId": "life",
            "state": status,
        });
        ObjectSnapshot {
            object: ObjectRef {
                kind: ObjectKind::Session,
                id: "session-k1".into(),
            },
            revision: Revision::new(revision),
            revision_source: RevisionSource::Omp,
            freshness: Freshness {
                state: FreshnessState::Fresh,
                observed_at: now,
                source_updated_at: Some(now),
                stale_after_seconds: None,
            },
            content_digest: Digest::hash(&serde_json::to_vec(&value).unwrap()),
            value,
        }
    };
    read_model.upsert(snapshot(1, "running")).unwrap();
    let id = AtlasId::new("state.live").unwrap();
    let source = LiveSource::new(id.clone(), read_model.clone());
    let (old_head, items) = source.pin().unwrap();
    let item_id = items
        .iter()
        .find(|item| item.text.contains("session-k1"))
        .unwrap()
        .item_id;
    let mut declared_seat = seat(&["state.live"]);
    declared_seat.brain_scope = atlas_ids(&["state.live"]);
    let policy = EffectiveBrainPolicy::resolve(
        74,
        &slice(&["state.live"]),
        &declared_seat,
        &BTreeMap::new(),
        &std::collections::BTreeMap::new(),
        &model(),
    )
    .unwrap();
    let directory = tempfile::tempdir().unwrap();
    let mut configuration = config(
        "state-live",
        BTreeMap::from([(id.clone(), BrainSourceConfig::StateLive { source })]),
    );
    configuration.store_root = directory.path().to_path_buf();
    let service = BrainService::open(configuration, policy, ledger()).unwrap();
    service.ensure_state_generations().unwrap();
    let query = service
        .policy()
        .knowledge
        .as_ref()
        .unwrap()
        .retrieval_query("session sinmara running".to_owned())
        .unwrap();
    let response = service.retrieve(&query, None, None).unwrap();
    assert!(response.hits.iter().any(|hit| hit.item_id == item_id
        && hit.content.contains("running")
        && hit.citation.source_revision == old_head));
    let old = service.knowledge_item(&item_id, None).unwrap();
    assert!(old
        .chunks
        .iter()
        .any(|chunk| chunk.text.contains("running")));
    assert!(old
        .chunks
        .iter()
        .all(|chunk| chunk.citation.source_revision == old_head));

    // The turn never builds: until the pump rebuilds, the last built
    // generation serves, and the item it cites still resolves.
    read_model.upsert(snapshot(2, "ended")).unwrap();
    let raced = service.retrieve(&query, None, None).unwrap();
    assert!(raced
        .hits
        .iter()
        .any(|hit| hit.item_id == item_id && hit.citation.source_revision == old_head));
    assert!(service
        .knowledge_item(&item_id, None)
        .unwrap()
        .chunks
        .iter()
        .any(|chunk| chunk.text.contains("running")));
    service.ensure_state_generations().unwrap();
    let current = service.knowledge_item(&item_id, None).unwrap();
    assert_ne!(current.generation.atlas_revision, old_head);
    assert!(current
        .chunks
        .iter()
        .any(|chunk| chunk.text.contains("ended")));
    assert!(!current
        .chunks
        .iter()
        .any(|chunk| chunk.text.contains("running")));
    let refreshed = service.retrieve(&query, None, None).unwrap();
    assert!(refreshed
        .hits
        .iter()
        .any(|hit| hit.item_id == item_id && hit.content.contains("ended")));
    assert!(refreshed
        .hits
        .iter()
        .all(|hit| hit.citation.source_revision != old_head));

    // A restarted read model can reuse a numeric revision, but never an old
    // generation whose authoritative content was different.
    let restarted = MaterializedReadModel::new(16, now);
    restarted.upsert(snapshot(1, "failed")).unwrap();
    let restarted_source = LiveSource::new(id, restarted);
    assert_ne!(restarted_source.pin().unwrap().0, old_head);
}

#[test]
fn fleet_live_objects_surface_as_citable_items() {
    use odin_brain::source::state::live::LiveSource;
    use odin_domain::huginn::{
        FleetHostView, FleetPlacementView, FleetTailnetState, Freshness, FreshnessState,
        KubeNodeState, ObjectKind, ObjectRef, ObjectSnapshot, Revision, RevisionSource,
    };
    use odin_huginn::read_model::MaterializedReadModel;

    let now = time::OffsetDateTime::UNIX_EPOCH;
    let read_model = MaterializedReadModel::new(16, now);
    let fleet_snapshot = |kind, id: &str, value: serde_json::Value| ObjectSnapshot {
        object: ObjectRef {
            kind,
            id: id.to_owned(),
        },
        revision: Revision::new(1),
        revision_source: RevisionSource::Fleet,
        freshness: Freshness {
            state: FreshnessState::Fresh,
            observed_at: now,
            source_updated_at: Some(now),
            stale_after_seconds: None,
        },
        content_digest: Digest::hash(&serde_json::to_vec(&value).unwrap()),
        value,
    };
    let host = FleetHostView {
        host: "mini".to_owned(),
        tailscale: "mini".to_owned(),
        hardware: "mini-pc".to_owned(),
        role: "control".to_owned(),
        capabilities: vec!["operator".to_owned()],
        allow_workloads: true,
        authoritative_state: true,
        gateway_endpoint: None,
        tailnet: FleetTailnetState::Unreachable,
        k3s_node_state: Some(KubeNodeState::NotReady),
        online: false,
        last_seen: Some(now),
        pods_scheduled: 0,
        zellij_live: None,
    };
    let authority = FleetPlacementView {
        thing: "odind-authority".to_owned(),
        node: Some("mini".to_owned()),
        host: Some("mini".to_owned()),
        endpoint: None,
        count: None,
        names: Vec::new(),
        active_count: None,
        live: None,
    };
    read_model
        .upsert(fleet_snapshot(
            ObjectKind::FleetHost,
            "mini",
            serde_json::to_value(&host).unwrap(),
        ))
        .unwrap();
    read_model
        .upsert(fleet_snapshot(
            ObjectKind::FleetPlacement,
            "fleet:placement:authority",
            serde_json::to_value(&authority).unwrap(),
        ))
        .unwrap();

    let id = AtlasId::new("state.live").unwrap();
    let source = LiveSource::new(id.clone(), read_model.clone());
    let (head, items) = source.pin().unwrap();
    let host_key = format!("fleet-hosts/{}", host.host);
    let expected_host_id =
        odin_brain::source::SourceItem::identity(&id, host_key.as_bytes()).unwrap();
    let host_item = items
        .iter()
        .find(|item| item.item_id == expected_host_id)
        .unwrap_or_else(|| panic!("no {host_key} item pinned: {items:?}"));
    let placement_key = "fleet-placement/fleet:placement:authority";
    let expected_placement_id =
        odin_brain::source::SourceItem::identity(&id, placement_key.as_bytes()).unwrap();
    let placement_item = items
        .iter()
        .find(|item| item.item_id == expected_placement_id)
        .unwrap_or_else(|| panic!("no {placement_key} item pinned: {items:?}"));
    assert!(host_item.text.contains("offline"), "{}", host_item.text);
    assert!(placement_item.text.contains("odind-authority"));
    let mut declared_seat = seat(&["state.live"]);
    declared_seat.brain_scope = atlas_ids(&["state.live"]);
    let policy = EffectiveBrainPolicy::resolve(
        74,
        &slice(&["state.live"]),
        &declared_seat,
        &BTreeMap::new(),
        &std::collections::BTreeMap::new(),
        &model(),
    )
    .unwrap();
    let directory = tempfile::tempdir().unwrap();
    let mut configuration = config(
        "fleet-live",
        BTreeMap::from([(id, BrainSourceConfig::StateLive { source })]),
    );
    configuration.store_root = directory.path().to_path_buf();
    let service = BrainService::open(configuration, policy, ledger()).unwrap();
    service.ensure_state_generations().unwrap();
    let query = service
        .policy()
        .knowledge
        .as_ref()
        .unwrap()
        .retrieval_query("fleet host mini offline".to_owned())
        .unwrap();
    let hits = service.retrieve(&query, None, None).unwrap();
    assert!(hits.hits.iter().any(|hit| hit.item_id == host_item.item_id
        && hit.content.contains("offline")
        && hit.citation.source_revision == head));
    let knowledge = service
        .knowledge_item(&placement_item.item_id, None)
        .unwrap();
    assert!(knowledge
        .chunks
        .iter()
        .all(|chunk| chunk.citation.source_revision == head));
}

#[test]
fn state_source_cannot_be_wired_under_an_authorized_alias() {
    let mut declared_seat = seat(&["state.live"]);
    declared_seat.brain_scope = atlas_ids(&["state.live"]);
    let policy = EffectiveBrainPolicy::resolve(
        74,
        &slice(&["state.live"]),
        &declared_seat,
        &BTreeMap::new(),
        &std::collections::BTreeMap::new(),
        &model(),
    )
    .unwrap();
    let source = odin_brain::source::state::live::LiveSource::new(
        AtlasId::new("private.live").unwrap(),
        odin_huginn::read_model::MaterializedReadModel::new(16, time::OffsetDateTime::UNIX_EPOCH),
    );
    let configuration = config(
        "state-alias",
        BTreeMap::from([(
            AtlasId::new("state.live").unwrap(),
            BrainSourceConfig::StateLive { source },
        )]),
    );
    assert!(matches!(
        open_err(BrainService::open(configuration, policy, ledger())),
        BrainError::InvalidPolicy(_)
    ));
}

#[test]
fn memory_source_cannot_alias_another_seats_subtree() {
    use odin_brain::source::silverbullet::{SilverBulletSource, VaultScope};
    let id = AtlasId::new("memory.sinmara").unwrap();
    let mut declared = seat(&["memory.sinmara"]);
    declared.brain_scope = [id.clone()].into();
    let policy = EffectiveBrainPolicy::resolve(
        74,
        &slice(&["memory.sinmara"]),
        &declared,
        &BTreeMap::new(),
        &std::collections::BTreeMap::new(),
        &model(),
    )
    .unwrap();
    let source = SilverBulletSource::new(
        id.clone(),
        DEAD_VAULT_PORT,
        VaultScope::generated_only("generated/memories/kubert", &[]).unwrap(),
    );
    let error = open_err(BrainService::open(
        config(
            "memory-alias",
            BTreeMap::from([(id, BrainSourceConfig::Memory { source })]),
        ),
        policy,
        ledger(),
    ));
    assert!(matches!(error, BrainError::InvalidPolicy(_)));
}

/// A turn neither builds nor seals: an unsealed generation serves nothing
/// until the warm round seals it, and the next turn then serves it.
#[test]
fn an_unsealed_generation_serves_nothing_until_the_warm_round_seals_it() {
    let cluster = postgres_cluster::TestCluster::start();
    let postgres = Arc::new(BrainPostgres::connect(&cluster.conninfo).unwrap());
    let ids = [ATLAS_FIXTURE_ID];
    let policy = resolve(&ids);
    let sources = BTreeMap::from([atlas_source(
        ids[0],
        &fixture_root("pg-unsealed", "alpha", "alpha_add"),
    )]);
    // Staged under a store without PostgreSQL: the generation exists in
    // SQLite and nothing is mirrored.
    let staged = BrainService::open(
        config("pg-unsealed", sources.clone()),
        policy.clone(),
        ledger(),
    )
    .unwrap();
    staged.ensure_generation().unwrap();
    let fixture_id = AtlasId::new(ids[0]).unwrap();
    let generation = staged.status().unwrap().generations[&fixture_id].clone();
    let id = generation.generation_id.to_string();
    drop(staged);

    let served = BrainService::open(
        BrainServiceConfig {
            postgres: Some(postgres),
            ..config("pg-unsealed", sources)
        },
        policy.clone(),
        ledger(),
    )
    .unwrap();
    let psql = |sql: &str| {
        let output = std::process::Command::new("psql")
            .args([&cluster.conninfo, "-tAc", sql])
            .output()
            .unwrap();
        String::from_utf8_lossy(&output.stdout).trim().to_owned()
    };

    let knowledge = policy.knowledge.as_ref().unwrap();
    let query = knowledge.retrieval_query("alpha_add".to_owned()).unwrap();
    assert!(served.retrieve(&query, None, None).unwrap().hits.is_empty());
    assert_eq!(
        psql(&format!(
            "SELECT count(*) FROM brain_generation_header WHERE generation_id = '{id}'"
        )),
        "0",
        "the turn must not seal"
    );
    assert_eq!(
        psql(&format!(
            "SELECT count(*) FROM brain_chunk WHERE generation_id = '{id}'"
        )),
        "0",
        "the turn must not copy"
    );

    assert_eq!(served.warm(dead_lane().as_ref(), 4_096).unwrap(), 0);
    assert_eq!(
        psql(&format!(
            "SELECT count(*) FROM brain_generation_header WHERE generation_id = '{id}'"
        )),
        "1",
        "the warm round seals the unheld generation"
    );

    let served_hits = served.retrieve(&query, None, None).unwrap().hits;
    assert_eq!(served_hits[0].source.as_str(), ids[0]);
}

/// An embedding lane that is down: warm rounds seal without embedding.
fn dead_lane() -> Arc<odin_brain::retrieval::QueryEmbedder> {
    Arc::new(|_texts| {
        Err(BrainError::EmbeddingUnavailable {
            provider: "fixture-gateway".to_owned(),
            reason: "the lexical fixture warms no embedding leg".to_owned(),
        })
    })
}
