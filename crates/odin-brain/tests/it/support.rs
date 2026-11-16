//! Fixtures the integration suites share: a registry slice and seat over
//! declared sources, a throwaway Atlas root, the approval gate and ingest
//! request of archive tests, and the service configuration over a cluster.

use std::collections::{BTreeMap, BTreeSet};
use std::num::{NonZeroU16, NonZeroU32, NonZeroU64};
use std::sync::{Arc, Mutex};

use odin_brain::error::BrainError;
use odin_brain::service::{
    archive_declaration_digest, ArchiveIngestAuthority, ArchiveIngestGate, ArchiveIngestRequest,
    BrainServiceConfig, BrainSourceConfig,
};
use odin_brain::test_cluster::TestCluster;
use odin_domain::knowledge::archive::{ArchiveSelectionPolicy, ArchiveSourceDeclaration};
use odin_domain::knowledge::ids::RelevanceScore;
use odin_domain::knowledge::retrieval::{RetrievalQuery, TrustClass};
use odin_domain::knowledge::{AtlasId, EmbeddingBackend, RetrievalMode};
use odin_domain::{Digest, ProjectId, SeatId};
use odin_ledger::Ledger;
use odin_registry::schema::{
    AccountingWindowToml, BudgetPolicyToml, ProjectToml, RegistryKind, SeatContextToml,
    SeatKnowledgeToml, SeatLimitsToml, SeatToml, SliceContextToml, SliceKnowledgeToml,
    SliceRedirectsToml, SliceToml, REGISTRY_SCHEMA,
};

pub fn nz16(value: u16) -> NonZeroU16 {
    NonZeroU16::new(value).unwrap()
}

pub fn nz32(value: u32) -> NonZeroU32 {
    NonZeroU32::new(value).unwrap()
}

pub fn atlas_ids(values: &[&str]) -> BTreeSet<AtlasId> {
    values
        .iter()
        .map(|value| AtlasId::new(*value).unwrap())
        .collect()
}

pub fn ledger() -> Arc<Mutex<Ledger>> {
    Arc::new(Mutex::new(Ledger::open_in_memory().unwrap()))
}

/// A slice that authorizes `sources` for knowledge under `mode`.
pub fn slice(sources: &[&str], mode: RetrievalMode, backend: EmbeddingBackend) -> SliceToml {
    SliceToml {
        schema: REGISTRY_SCHEMA.to_owned(),
        inherit_seat_grants: false,
        kind: RegistryKind::Slice,
        enabled: true,
        description: "integration fixture slice".to_owned(),
        capabilities: BTreeSet::new(),
        variables: BTreeMap::new(),
        redirects: SliceRedirectsToml {
            out_of_scope: "NeedsPlan".to_owned(),
        },
        knowledge: Some(SliceKnowledgeToml {
            required: false,
            atlas_sources: atlas_ids(sources),
            retrieval_mode: mode,
            candidate_limit: nz16(64),
            top_k: nz16(8),
            min_score_micros: 0,
            chunk_tokens: nz32(512),
            chunk_overlap_tokens: 64,
            embedding_backend: backend,
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

/// A seat that reads `sources` and works on `projects`.
pub fn seat(sources: &[&str], projects: &[&str]) -> SeatToml {
    SeatToml {
        schema: REGISTRY_SCHEMA.to_owned(),
        kind: RegistryKind::Seat,
        enabled: true,
        description: "integration fixture seat".to_owned(),
        categories: BTreeSet::new(),
        project_scope: projects
            .iter()
            .map(|project| ProjectId::new(*project).unwrap())
            .collect(),
        read_project_scope: BTreeSet::new(),
        models: Vec::new(),
        tool_refs: BTreeSet::new(),
        slice: None,
        brain_scope: atlas_ids(sources),
        limits: SeatLimitsToml {
            max_parallel_runs: 4,
            max_sessions: 4,
            max_background_jobs: 4,
            max_batch_launches: 256,
            max_batch_inputs: 16,
            inline_seconds: 4,
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
            atlas_sources: atlas_ids(sources),
            required_tags: BTreeSet::new(),
            denied_tags: BTreeSet::new(),
            top_k: nz16(8),
        }),
        context: Some(SeatContextToml {
            max_bundle_tokens: nz32(8192),
            profile: "sized".into(),
            review_lane: None,
            consult: None,
        }),
        tools: None,
        ephemeral: None,
        sandbox: odin_registry::schema::SeatSandboxToml::default(),
    }
}

/// A project whose declared memory is `namespaces`.
pub fn project(namespaces: &[&str]) -> ProjectToml {
    ProjectToml {
        schema: REGISTRY_SCHEMA.to_owned(),
        kind: RegistryKind::Project,
        enabled: true,
        description: "integration fixture project".to_owned(),
        source_root: String::new(),
        default_seat: SeatId::new("fixture-seat").unwrap(),
        memory_namespaces: atlas_ids(namespaces),
        privacy: None,
        accounts: Default::default(),
        review_verdict: None,
        repo: None,
        hub_refresh_seconds: None,
        deploy: None,
        sphere: None,
        agents: Default::default(),
    }
}

/// An archive selection that declares nothing.
pub fn selection() -> ArchiveSelectionPolicy {
    ArchiveSelectionPolicy {
        since: None,
        exclude_labels: Vec::new(),
        exclude_if_header: Vec::new(),
        keep_if_participant: false,
        participant_emails: Vec::new(),
        suspicious_rules: Vec::new(),
        exclude_do_not_remember: None,
        people_registry: None,
    }
}

/// A Rust source tree in the Atlas root layout, so the root pins through the
/// real `odin-atlas` build.
pub fn atlas_root(crate_name: &str, fn_name: &str) -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    write_atlas_tree(dir.path(), crate_name, fn_name);
    dir
}

/// Writes the Atlas root layout under `root`: one Rust crate holding `fn_name`,
/// and the three other source classes empty.
pub fn write_atlas_tree(root: &std::path::Path, crate_name: &str, fn_name: &str) {
    let src = root.join("crates").join(crate_name).join("src");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::write(
        src.join("lib.rs"),
        format!(
            "//! Fixture crate {crate_name}.\n\n/// Adds one to the input.\n\
             pub fn {fn_name}(value: u64) -> u64 {{ value + 1 }}\n"
        ),
    )
    .unwrap();
    for directory in ["extension", "registry", "skeletons"] {
        std::fs::create_dir_all(root.join(directory)).unwrap();
    }
}

pub fn atlas_source(id: &str, root: &std::path::Path) -> (AtlasId, BrainSourceConfig) {
    (
        AtlasId::new(id).unwrap(),
        BrainSourceConfig::Atlas {
            root: root.to_path_buf(),
        },
    )
}

/// The service configuration over a fresh cluster.
pub fn config_with(
    sources: BTreeMap<AtlasId, BrainSourceConfig>,
    archive_ingest_gate: Option<Arc<dyn ArchiveIngestGate>>,
) -> (TestCluster, BrainServiceConfig) {
    let cluster = TestCluster::start();
    let config = BrainServiceConfig {
        store_root: cluster.path(),
        sources,
        embedding_available: false,
        embedding_model: None,
        archive_ingest_gate,
        postgres: cluster.store(),
        rerank: None,
    };
    (cluster, config)
}

/// The approval gate of archive tests: every approval verifies unless its
/// id ends in `denied`.
pub struct TestGate;

impl ArchiveIngestGate for TestGate {
    fn verify(
        &self,
        authority: &ArchiveIngestAuthority,
        source: &AtlasId,
        _idempotency_key: &str,
    ) -> Result<(), BrainError> {
        if source.as_str().is_empty() {
            return Err(BrainError::InvalidRequest("empty source".to_owned()));
        }
        if authority.approval_id.ends_with("denied") {
            return Err(BrainError::Unavailable {
                component: "archive_ingest_gate",
                reason: "approval is not in an approved-and-consumed state".to_owned(),
            });
        }
        Ok(())
    }
}

pub fn test_gate() -> Option<Arc<dyn ArchiveIngestGate>> {
    Some(Arc::new(TestGate))
}

pub fn ingest_request(
    source: &AtlasId,
    declaration: &ArchiveSourceDeclaration,
    content_revision: Digest,
    key: &str,
) -> ArchiveIngestRequest {
    ArchiveIngestRequest {
        source: source.clone(),
        declaration: declaration.clone(),
        approval: ArchiveIngestAuthority {
            demand_id: format!("demand-{key}"),
            approval_id: format!("approval-{key}"),
            command_id: format!("command-{key}"),
            declaration_digest: archive_declaration_digest(declaration).unwrap(),
            content_revision,
        },
        idempotency_key: key.to_owned(),
        deadline: None,
    }
}

/// A query for `text` over `sources`, every trust class admitted.
pub fn query(sources: BTreeSet<AtlasId>, text: &str) -> RetrievalQuery {
    RetrievalQuery::new(odin_domain::knowledge::retrieval::RetrievalQueryInit {
        text: text.to_owned(),
        sources,
        required_tags: BTreeSet::new(),
        denied_tags: BTreeSet::new(),
        allowed_trust: [
            TrustClass::Curated,
            TrustClass::Observed,
            TrustClass::Untrusted,
        ]
        .into_iter()
        .collect(),
        candidate_limit: nz16(64),
        top_k: nz16(8),
        min_score: RelevanceScore::new(0).unwrap(),
    })
    .unwrap()
}
