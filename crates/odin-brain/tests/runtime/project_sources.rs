use super::*;
use odin_brain::source::state::repos::ReposSource;
use odin_domain::ProjectId;
use odin_registry::schema::ProjectToml;
use std::path::Path;
use std::process::Command;

fn git(root: &Path, args: &[&str]) {
    let output = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(args)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_AUTHOR_NAME", "Fixture")
        .env("GIT_AUTHOR_EMAIL", "fixture@example.invalid")
        .env("GIT_COMMITTER_NAME", "Fixture")
        .env("GIT_COMMITTER_EMAIL", "fixture@example.invalid")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "git {args:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn repository(root: &Path, marker: &str) {
    std::fs::create_dir_all(root.join("crates/demo/src")).unwrap();
    for directory in ["extension", "registry", "skeletons"] {
        std::fs::create_dir_all(root.join(directory)).unwrap();
    }
    std::fs::write(
        root.join("crates/demo/src/lib.rs"),
        format!("pub fn {marker}() -> u64 {{ 1 }}\n"),
    )
    .unwrap();
    git(root, &["init", "--quiet"]);
    git(root, &["add", "."]);
    git(root, &["commit", "--quiet", "-m", "initial"]);
}

fn scoped_policy(ids: &[&str], projects: &[&str]) -> EffectiveBrainPolicy {
    let mut declared = seat(ids);
    declared.brain_scope = atlas_ids(ids);
    declared.project_scope = projects
        .iter()
        .map(|id| ProjectId::new(*id).unwrap())
        .collect();
    let objects: BTreeMap<_, _> = projects
        .iter()
        .map(|id| {
            (
                *id,
                ProjectToml {
                    schema: REGISTRY_SCHEMA.into(),
                    kind: RegistryKind::Project,
                    enabled: true,
                    description: "project source fixture".into(),
                    source_root: String::new(),
                    default_seat: SeatId::new("fixture").unwrap(),
                    memory_namespaces: BTreeSet::new(),
                    artifact_policy: "standard".into(),
                    privacy: None,
                    accounts: Default::default(),
                    review_verdict: None,
                },
            )
        })
        .collect();
    EffectiveBrainPolicy::resolve(
        74,
        &slice(ids),
        &declared,
        &objects.iter().map(|(id, project)| (*id, project)).collect(),
        &std::collections::BTreeMap::new(),
        &model(),
    )
    .unwrap()
}

#[test]
fn repository_sources_refuse_cross_project_reads_and_follow_rebuilt_heads() {
    let root = tempfile::tempdir().unwrap();
    let alpha_root = root.path().join("alpha");
    let beta_root = root.path().join("beta");
    repository(&alpha_root, "alpha_committed_marker");
    repository(&beta_root, "beta_committed_marker");
    let alpha = ProjectId::new("alpha").unwrap();
    let beta = ProjectId::new("beta").unwrap();
    let id = AtlasId::new("state.repos").unwrap();
    let source = ReposSource::new(
        id.clone(),
        BTreeMap::from([
            (alpha.clone(), alpha_root.clone()),
            (beta.clone(), beta_root),
        ]),
    )
    .unwrap();
    let mut configuration = config(
        "project-repos",
        BTreeMap::from([(
            id.clone(),
            BrainSourceConfig::StateRepos {
                source: source.clone(),
            },
        )]),
    );
    configuration.store_root = root.path().join("index");
    let service = BrainService::open(
        configuration,
        scoped_policy(&["state.repos"], &["alpha", "beta"]),
        ledger(),
    )
    .unwrap();
    service.ensure_generation().unwrap();
    let query = service
        .policy()
        .knowledge
        .as_ref()
        .unwrap()
        .retrieval_query("alpha_committed_marker".into())
        .unwrap();
    let hits = service.retrieve(&query, Some(&alpha), None).unwrap().hits;
    let hit = hits
        .iter()
        .find(|hit| hit.content.contains("alpha_committed_marker"))
        .unwrap();
    let item_id = hit.item_id;
    assert!(service.knowledge_item(&item_id, Some(&alpha)).is_ok());
    assert!(matches!(
        service.knowledge_item(&item_id, Some(&beta)),
        Err(BrainError::NotFound { .. })
    ));
    assert!(matches!(
        service.knowledge_item(&item_id, None),
        Err(BrainError::NotFound { .. })
    ));
    assert!(!service
        .retrieve(&query, Some(&beta), None)
        .unwrap()
        .hits
        .iter()
        .any(|hit| hit.content.contains("alpha_committed_marker")));
    assert!(service
        .retrieve(&query, None, None)
        .unwrap()
        .hits
        .is_empty());
    let old_revision = hit.source_revision;
    git(
        &alpha_root,
        &["commit", "--quiet", "--allow-empty", "-m", "head-only move"],
    );
    // Until the pump rebuilds, the last built generation still serves it.
    let served = service.knowledge_item(&item_id, Some(&alpha)).unwrap();
    assert_eq!(served.generation.atlas_revision, old_revision);
    service.ensure_generation().unwrap();
    let current = service.knowledge_item(&item_id, Some(&alpha)).unwrap();
    assert_ne!(current.generation.atlas_revision, old_revision);
}

#[test]
fn seat_project_restriction_prevents_even_pinning_a_foreign_repository() {
    let root = tempfile::tempdir().unwrap();
    let own_root = root.path().join("own");
    let foreign_root = root.path().join("foreign");
    repository(&own_root, "own_marker");
    repository(&foreign_root, "foreign_marker");
    let source = ReposSource::new(
        AtlasId::new("state.repos").unwrap(),
        BTreeMap::from([
            (ProjectId::new("own").unwrap(), own_root),
            (ProjectId::new("foreign").unwrap(), foreign_root.clone()),
        ]),
    )
    .unwrap();
    let mut configuration = config(
        "seat-repos",
        BTreeMap::from([(
            AtlasId::new("state.repos").unwrap(),
            BrainSourceConfig::StateRepos { source },
        )]),
    );
    configuration.store_root = root.path().join("index");
    let service = BrainService::open(
        configuration,
        scoped_policy(&["state.repos"], &["own"]),
        ledger(),
    )
    .unwrap();
    std::fs::remove_dir_all(foreign_root).unwrap();
    service.ensure_generation().unwrap();
    let query = service
        .policy()
        .knowledge
        .as_ref()
        .unwrap()
        .retrieval_query("own_marker".into())
        .unwrap();
    assert!(service
        .retrieve(&query, Some(&ProjectId::new("own").unwrap()), None)
        .unwrap()
        .hits
        .iter()
        .any(|hit| hit.content.contains("own_marker")));
}
