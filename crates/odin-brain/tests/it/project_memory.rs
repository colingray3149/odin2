//! Project-scoped source refresh: one shared seat, two declared projects, and
//! four indexed Atlas sources; a scoped refresh builds exactly the named
//! sources the service composes.

use std::collections::BTreeMap;

use odin_brain::config::EffectiveBrainPolicy;
use odin_brain::service::{BrainService, BrainSourceConfig};
use odin_domain::huginn::ids::ModelName;
use odin_domain::knowledge::ids::{AtlasId, TokenizerId};
use odin_domain::knowledge::retrieval::ModelDescriptor;
use odin_domain::knowledge::{EmbeddingBackend, RetrievalMode};
use odin_domain::ProjectId;

use crate::support::{
    atlas_ids, atlas_root, atlas_source, config_with, ledger, nz32, project, seat, slice,
};

const ALPHA_SOURCE: &str = "atlas:pm-alpha";
const BETA_SOURCE: &str = "atlas:pm-beta";
const SHARED_SOURCE: &str = "atlas:pm-shared";
/// Declared by NO project: ordinary seat-general reference knowledge.
const GENERAL_SOURCE: &str = "atlas:pm-general";

fn model() -> ModelDescriptor {
    ModelDescriptor {
        name: ModelName::new("model.pm").unwrap(),
        tokenizer: TokenizerId::new("odin.tokenizer.utf8-bytes.v1").unwrap(),
        context_window_tokens: nz32(8192),
    }
}

fn policy() -> EffectiveBrainPolicy {
    let sources = [ALPHA_SOURCE, BETA_SOURCE, SHARED_SOURCE, GENERAL_SOURCE];
    let alpha = project(&[ALPHA_SOURCE, SHARED_SOURCE]);
    let beta = project(&[BETA_SOURCE, SHARED_SOURCE]);
    EffectiveBrainPolicy::resolve(
        74,
        &slice(&sources, RetrievalMode::Lexical, EmbeddingBackend::Local),
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

/// The four indexed fixture sources for one test. Concurrent tests must never
/// share the bytes another test's generation is pinned to.
fn fixture_sources() -> (Vec<tempfile::TempDir>, BTreeMap<AtlasId, BrainSourceConfig>) {
    let alpha = atlas_root("pm_alpha_demo", "alpha_fn");
    let beta = atlas_root("pm_beta_demo", "beta_fn");
    let shared = atlas_root("pm_shared_demo", "shared_fn");
    let general = atlas_root("pm_general_demo", "general_fn");
    let sources = BTreeMap::from([
        atlas_source(ALPHA_SOURCE, alpha.path()),
        atlas_source(BETA_SOURCE, beta.path()),
        atlas_source(SHARED_SOURCE, shared.path()),
        atlas_source(GENERAL_SOURCE, general.path()),
    ]);
    (vec![alpha, beta, shared, general], sources)
}

/// Intersect project scope before pinning so another project's outage stays isolated.
#[test]
fn a_project_bound_search_never_pins_another_projects_broken_source() {
    let (_dirs, sources) = fixture_sources();
    let Some(BrainSourceConfig::Atlas { root: beta_root }) =
        sources.get(&AtlasId::new(BETA_SOURCE).unwrap()).cloned()
    else {
        panic!("beta is an atlas fixture source");
    };
    let (_store, cfg) = config_with(sources, None);
    let service = BrainService::open(cfg, policy(), ledger()).unwrap();
    service.ensure_generation().unwrap();
    std::fs::remove_dir_all(&beta_root).unwrap();

    let alpha = ProjectId::new("alpha").unwrap();
    let declared = service.policy().project_serving_scope(Some(&alpha));
    assert!(!declared.contains(&AtlasId::new(BETA_SOURCE).unwrap()));
    // Reading an item by id pins the project's scope only: beta's outage is no one's.
    let query = service
        .policy()
        .knowledge
        .as_ref()
        .unwrap()
        .retrieval_query("alpha_fn".to_owned())
        .unwrap();
    let item = service.retrieve(&query, Some(&alpha), None).unwrap().hits[0].item_id;
    assert!(service.knowledge_item(&item, Some(&alpha)).is_ok());
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
