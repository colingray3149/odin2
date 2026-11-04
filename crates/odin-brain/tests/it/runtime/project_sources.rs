use super::*;
use crate::support::{project, write_atlas_tree};
use odin_brain::source::state::repos::ReposSource;
use odin_domain::ProjectId;
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
    write_atlas_tree(root, "demo", marker);
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
    let objects: BTreeMap<_, _> = projects.iter().map(|id| (*id, project(&[]))).collect();
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
    let cluster = TestCluster::start();
    let configuration = config_at(
        &root.path().join("index"),
        cluster.store(),
        BTreeMap::from([(
            id.clone(),
            BrainSourceConfig::StateRepos {
                source: source.clone(),
            },
        )]),
    );
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
