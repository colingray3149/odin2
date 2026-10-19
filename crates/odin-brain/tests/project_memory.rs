//! Project-scoped source refresh: one shared seat, two declared projects, and
//! four indexed Atlas sources; a scoped refresh builds exactly the named
//! sources the service composes.

use std::collections::{BTreeMap, BTreeSet};
use std::num::{NonZeroU16, NonZeroU32, NonZeroU64};
use std::sync::{Arc, Mutex};

use odin_brain::config::EffectiveBrainPolicy;
use odin_brain::service::{BrainService, BrainServiceConfig, BrainSourceConfig};
use odin_domain::huginn::ids::ModelName;
use odin_domain::knowledge::ids::{AtlasId, TokenizerId};
use odin_domain::knowledge::retrieval::ModelDescriptor;
use odin_domain::knowledge::{EmbeddingBackend, RetrievalMode};
use odin_domain::{ProjectId, SeatId};
use odin_ledger::Ledger;
use odin_registry::schema::{
    AccountingWindowToml, ApprovalDefaultToml, ApprovalDefaultsToml, BudgetPolicyToml, ProjectToml,
    RegistryKind, SeatContextToml, SeatKnowledgeToml, SeatLimitsToml, SeatToml, SliceContextToml,
    SliceKnowledgeToml, SliceRedirectsToml, SliceToml, REGISTRY_SCHEMA,
};

const ALPHA_SOURCE: &str = "atlas:pm-alpha";
const BETA_SOURCE: &str = "atlas:pm-beta";
const SHARED_SOURCE: &str = "atlas:pm-shared";
/// Declared by NO project: ordinary seat-general reference knowledge.
const GENERAL_SOURCE: &str = "atlas:pm-general";

fn nz16(value: u16) -> NonZeroU16 {
    NonZeroU16::new(value).unwrap()
}

fn nz32(value: u32) -> NonZeroU32 {
    NonZeroU32::new(value).unwrap()
}

fn atlas_ids(values: &[&str]) -> BTreeSet<AtlasId> {
    values.iter().map(|v| AtlasId::new(*v).unwrap()).collect()
}

/// Writes a real, buildable crate so every declared source pins through the
/// actual `odin-atlas` build.
fn fixture_root(tag: &str, crate_name: &str, fn_name: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "odin-brain-project-memory-{tag}-{}-{crate_name}",
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
    std::fs::create_dir_all(dir.join("extension")).unwrap();
    std::fs::create_dir_all(dir.join("registry")).unwrap();
    std::fs::create_dir_all(dir.join("skeletons")).unwrap();
    dir
}

fn slice(atlas_sources: &[&str]) -> SliceToml {
    SliceToml {
        schema: REGISTRY_SCHEMA.to_owned(),
        kind: RegistryKind::Slice,
        enabled: true,
        description: "project memory fixture slice".to_owned(),
        capabilities: BTreeSet::new(),
        variables: BTreeMap::new(),
        redirects: SliceRedirectsToml {
            out_of_scope: "NeedsPlan".to_owned(),
        },
        knowledge: Some(SliceKnowledgeToml {
            required: false,
            atlas_sources: atlas_ids(atlas_sources),
            retrieval_mode: RetrievalMode::Lexical,
            candidate_limit: nz16(64),
            top_k: nz16(8),
            min_score_micros: 0,
            chunk_tokens: nz32(512),
            chunk_overlap_tokens: 64,
            embedding_backend: EmbeddingBackend::Local,
        }),
        context: Some(SliceContextToml {
            max_bundle_tokens: nz32(8192),
            reserve_output_tokens: nz32(1024),
            control_tokens: nz32(2048),
            history_tokens: nz32(256),
            core_tokens: nz32(2048),
            prefetch_tokens: nz32(2048),
            tool_result_tokens: nz32(256),
            tool_schema_tokens: nz32(512),
            max_item_tokens: nz32(1024),
        }),
        tools: None,
        live: None,
        budget: None,
    }
}

fn seat(atlas_sources: &[&str], projects: &[&str]) -> SeatToml {
    SeatToml {
        schema: REGISTRY_SCHEMA.to_owned(),
        kind: RegistryKind::Seat,
        enabled: true,
        description: "project memory fixture seat".to_owned(),
        categories: BTreeSet::new(),
        project_scope: projects
            .iter()
            .map(|p| ProjectId::new(*p).unwrap())
            .collect(),
        read_project_scope: BTreeSet::new(),
        models: Vec::new(),
        tool_refs: BTreeSet::new(),
        approval_defaults: ApprovalDefaultsToml {
            r0: ApprovalDefaultToml::Auto,
            r1: ApprovalDefaultToml::Auto,
            r2: ApprovalDefaultToml::Auto,
            r3: ApprovalDefaultToml::Auto,
        },
        brain_scope: atlas_ids(atlas_sources),
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
        knowledge: Some(SeatKnowledgeToml {
            atlas_sources: atlas_ids(atlas_sources),
            required_tags: BTreeSet::new(),
            denied_tags: BTreeSet::new(),
            top_k: nz16(8),
        }),
        context: Some(SeatContextToml {
            max_bundle_tokens: nz32(8192),
            profile: "sized".into(),
            review_lane: None,
        }),
        tools: None,
        ephemeral: None,
        sandbox: odin_registry::schema::SeatSandboxToml::default(),
    }
}

fn project(_id: &str, namespaces: &[&str]) -> ProjectToml {
    ProjectToml {
        schema: REGISTRY_SCHEMA.to_owned(),
        kind: RegistryKind::Project,
        enabled: true,
        description: "project memory fixture project".to_owned(),
        source_root: String::new(),
        default_seat: SeatId::new("pm-seat").unwrap(),
        memory_namespaces: atlas_ids(namespaces),
        artifact_policy: "standard".to_owned(),
        privacy: None,
        accounts: Default::default(),
        review_verdict: None,
    }
}

fn model() -> ModelDescriptor {
    ModelDescriptor {
        name: ModelName::new("model.pm").unwrap(),
        tokenizer: TokenizerId::new("odin.tokenizer.utf8-bytes.v1").unwrap(),
        context_window_tokens: nz32(8192),
    }
}

fn policy() -> EffectiveBrainPolicy {
    let sources = [ALPHA_SOURCE, BETA_SOURCE, SHARED_SOURCE, GENERAL_SOURCE];
    let alpha = project("alpha", &[ALPHA_SOURCE, SHARED_SOURCE]);
    let beta = project("beta", &[BETA_SOURCE, SHARED_SOURCE]);
    EffectiveBrainPolicy::resolve(
        74,
        &slice(&sources),
        &seat(&sources, &["alpha", "beta"]),
        &BTreeMap::from([("alpha", &alpha), ("beta", &beta)]),
        &std::collections::BTreeMap::from([(
            "sized",
            &odin_registry::ContextProfileToml::sized(nz32(2048), nz32(2048)),
        )]),
        &model(),
    )
    .unwrap()
}

fn ledger() -> Arc<Mutex<Ledger>> {
    Arc::new(Mutex::new(Ledger::open_in_memory().unwrap()))
}
/// One BrainServiceConfig over a per-test store root: the durable index
/// store pins atlas baselines, so concurrent tests sharing one
/// directory collide on generation ids and pinned revisions. The tag keeps
/// every test's durable state isolated, exactly as the runtime tests do.
fn config(tag: &str, sources: BTreeMap<AtlasId, BrainSourceConfig>) -> BrainServiceConfig {
    BrainServiceConfig {
        store_root: std::env::temp_dir().join(format!(
            "odin-brain-project-memory-store-{tag}-{}",
            std::process::id()
        )),
        sources,
        embedding_available: false,
        embedding_model: None,
        archive_ingest_gate: None,
        postgres: None,
    }
}

/// The four indexed fixture sources for one test, under per-test root
/// directories: concurrent tests must never share (or concurrently
/// recreate) the bytes another test's generation is pinned to.
fn fixture_sources(prefix: &str) -> BTreeMap<AtlasId, BrainSourceConfig> {
    let alpha_root = fixture_root(&format!("{prefix}-alpha"), "pm_alpha_demo", "alpha_fn");
    let beta_root = fixture_root(&format!("{prefix}-beta"), "pm_beta_demo", "beta_fn");
    let shared_root = fixture_root(&format!("{prefix}-shared"), "pm_shared_demo", "shared_fn");
    let general_root = fixture_root(
        &format!("{prefix}-general"),
        "pm_general_demo",
        "general_fn",
    );
    BTreeMap::from([
        atlas_source(ALPHA_SOURCE, &alpha_root),
        atlas_source(BETA_SOURCE, &beta_root),
        atlas_source(SHARED_SOURCE, &shared_root),
        atlas_source(GENERAL_SOURCE, &general_root),
    ])
}

fn atlas_source(id: &str, root: &std::path::Path) -> (AtlasId, BrainSourceConfig) {
    (
        AtlasId::new(id).unwrap(),
        BrainSourceConfig::Atlas {
            root: root.to_path_buf(),
        },
    )
}
/// Intersect project scope before pinning so another project's outage stays isolated.
#[test]
fn a_project_bound_search_never_pins_another_projects_broken_source() {
    let sources = fixture_sources("scoped-project");
    let Some(BrainSourceConfig::Atlas { root: beta_root }) =
        sources.get(&AtlasId::new(BETA_SOURCE).unwrap()).cloned()
    else {
        panic!("beta is an atlas fixture source");
    };
    let service =
        BrainService::open(config("scoped-project", sources), policy(), ledger()).unwrap();
    std::fs::remove_dir_all(&beta_root).unwrap();

    let alpha = ProjectId::new("alpha").unwrap();
    let declared = service.policy().project_serving_scope(Some(&alpha));
    assert!(!declared.contains(&AtlasId::new(BETA_SOURCE).unwrap()));
    let mut query = service
        .policy()
        .knowledge
        .as_ref()
        .unwrap()
        .retrieval_query("alpha_fn beta_fn".to_owned())
        .unwrap();
    for requested in [declared, atlas_ids(&[ALPHA_SOURCE, BETA_SOURCE])] {
        query.sources = requested;
        let hits = service.retrieve(&query, Some(&alpha), None).unwrap().hits;
        assert!(
            hits.iter()
                .any(|hit| hit.source.as_str() == ALPHA_SOURCE && hit.content.contains("alpha_fn")),
            "{:?}: alpha's memory serves: {hits:?}",
            query.sources
        );
        assert!(
            hits.iter().all(|hit| hit.source.as_str() != BETA_SOURCE),
            "{:?}: beta never serves to alpha: {hits:?}",
            query.sources
        );
    }
}
