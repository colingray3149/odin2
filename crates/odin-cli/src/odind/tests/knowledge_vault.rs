use super::*;
use std::collections::{BTreeMap, BTreeSet};
use std::num::NonZeroU32;

use odin_brain::config::EffectiveBrainPolicy;
use odin_brain::service::{BrainServiceConfig, BrainSourceConfig};
use odin_brain::source::state::repos::ReposSource;
use odin_domain::knowledge::{EmbeddingBackend, RetrievalMode};
use odin_domain::ProjectId;
use odin_hermes::vault::{SilverBulletConfig, VaultConfig};
use odin_registry::schema::{ProjectToml, SeatToml, SliceToml};

fn commit(root: &std::path::Path, message: &str) {
    for args in [
        vec!["add", "."],
        vec![
            "-c",
            "user.name=Fixture",
            "-c",
            "user.email=fixture@example.invalid",
            "commit",
            "--quiet",
            "-m",
            message,
        ],
    ] {
        assert!(std::process::Command::new("git")
            .arg("-C")
            .arg(root)
            .args(args)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .status()
            .unwrap()
            .success());
    }
}

/// A seat whose brain projects exactly `source` for project `demo`, the
/// loopback vault it projects into, and its brain configuration.
struct Fixture {
    vault: crate::test_vault::LoopbackVault,
    bridge: VaultBridge,
    policy: EffectiveBrainPolicy,
    seat: SeatId,
}

fn fixture(label: &str, source: &AtlasId) -> Fixture {
    let vault = crate::test_vault::LoopbackVault::open(label);
    let project = ProjectId::new("demo").unwrap();
    let mut seat_decl: SeatToml = toml::from_str(include_str!(
        "../../../../../registry/seats/sinmara/seat.toml"
    ))
    .unwrap();
    let mut slice: SliceToml = toml::from_str(include_str!(
        "../../../../../registry/slices/sinmara-life/slice.toml"
    ))
    .unwrap();
    let mut project_decl: ProjectToml = toml::from_str(include_str!(
        "../../../../../registry/projects/odin/project.toml"
    ))
    .unwrap();
    project_decl.memory_namespaces.clear();
    seat_decl.project_scope = BTreeSet::from([project]);
    seat_decl.brain_scope = BTreeSet::from([source.clone()]);
    seat_decl.knowledge.as_mut().unwrap().atlas_sources = BTreeSet::from([source.clone()]);
    seat_decl.context = None;
    slice.context = None;
    let knowledge = slice.knowledge.as_mut().unwrap();
    knowledge.atlas_sources = BTreeSet::from([source.clone()]);
    knowledge.retrieval_mode = RetrievalMode::Lexical;
    knowledge.embedding_backend = EmbeddingBackend::Disabled;
    let policy = EffectiveBrainPolicy::resolve(
        1,
        &slice,
        &seat_decl,
        &BTreeMap::from([("demo", &project_decl)]),
        &std::collections::BTreeMap::new(),
        &odin_domain::knowledge::retrieval::ModelDescriptor {
            name: odin_domain::huginn::ids::ModelName::new("projection-proof").unwrap(),
            tokenizer: odin_brain::context::PinnedTokenizer::id().unwrap(),
            context_window_tokens: NonZeroU32::new(32768).unwrap(),
        },
    )
    .unwrap();
    let bridge = VaultBridge::new(VaultConfig {
        vault_root: vault.root().to_path_buf(),
        source_id: "vault.proof".into(),
        silverbullet: Some(SilverBulletConfig {
            port: vault.port(),
            expected_space_root: Some(vault.expected_space_root()),
        }),
        general_namespaces: vec!["knowledge".into()],
        generated_namespace: "generated".into(),
        excluded_namespaces: vec![],
        max_pages: 1024,
        max_page_bytes: 2048,
        timeout_ms: 5000,
    })
    .unwrap();
    Fixture {
        vault,
        bridge,
        policy,
        seat: SeatId::new("renderer-proof").unwrap(),
    }
}

/// Every generated knowledge page by path below the knowledge tree, each
/// within the page bound.
fn snapshot(bridge: &VaultBridge) -> BTreeMap<String, String> {
    fn walk(dir: &std::path::Path, files: &mut Vec<std::path::PathBuf>) {
        for entry in std::fs::read_dir(dir).into_iter().flatten().flatten() {
            let path = entry.path();
            if path.is_dir() {
                walk(&path, files);
            } else {
                files.push(path);
            }
        }
    }
    let tree = bridge.config().vault_root.join("generated/knowledge");
    let mut files = Vec::new();
    walk(&tree, &mut files);
    files
        .into_iter()
        .map(|path| {
            let text = std::fs::read_to_string(&path).unwrap();
            assert!(text.len() <= bridge.config().max_page_bytes as usize);
            (
                path.strip_prefix(&tree).unwrap().display().to_string(),
                text,
            )
        })
        .collect()
}

#[test]
fn repos_project_one_shared_summary_page_per_project_and_retire_the_mirror() {
    let root = tempfile::tempdir().unwrap();
    let repo = root.path().join("repo");
    std::fs::create_dir_all(repo.join("crates/demo/src")).unwrap();
    assert!(std::process::Command::new("git")
        .arg("init")
        .arg("--quiet")
        .arg(&repo)
        .status()
        .unwrap()
        .success());
    let first_code: String = (0..40)
        .map(|index| format!("pub fn obsolete_projection_fact_{index}() {{}}\n"))
        .collect();
    std::fs::write(repo.join("crates/demo/src/lib.rs"), first_code).unwrap();
    commit(&repo, "initial");

    let source = AtlasId::new("state.repos").unwrap();
    let project = ProjectId::new("demo").unwrap();
    let Fixture {
        vault: _vault,
        bridge,
        policy,
        seat,
    } = fixture("knowledge-replacement", &source);
    let config = BrainServiceConfig {
        store_root: root.path().join("brain"),
        sources: BTreeMap::from([(
            source.clone(),
            BrainSourceConfig::StateRepos {
                source: ReposSource::new(source.clone(), BTreeMap::from([(project, repo.clone())]))
                    .unwrap(),
            },
        )]),
        embedding_available: false,
        embedding_model: None,
        archive_ingest_gate: None,
        postgres: None,
    };
    let ledger = Arc::new(std::sync::Mutex::new(
        odin_ledger::Ledger::open_in_memory().unwrap(),
    ));
    let sink = VaultProjectionSink {
        vault: bridge.clone(),
        seat: seat.clone(),
    };
    let root_dir = bridge.config().vault_root.clone();
    let tree = root_dir.join("generated/knowledge");
    let snapshot = || snapshot(&bridge);
    // A per-node mirror page left by the old renderer in the seat subtree.
    let legacy = format!("generated/knowledge/{source}/{seat}/items/legacy-node.md");
    bridge
        .write_generated(&odin_hermes::vault::VaultWriteGeneratedInput {
            page_name: legacy.clone(),
            content: "old per-node mirror page\n".into(),
        })
        .unwrap();

    let brain = BrainService::open(config.clone(), policy.clone(), Arc::clone(&ledger)).unwrap();
    attach(&brain, &seat, &bridge).unwrap();
    brain.ensure_state_generations().unwrap();
    // One shared summary page per project; no seat pages, no per-node
    // source mirror, and the legacy mirror page is retired.
    let first = snapshot();
    assert_eq!(
        first.keys().collect::<Vec<_>>(),
        [&format!("{source}/demo.md")]
    );
    let summary = &first[&format!("{source}/demo.md")];
    assert!(summary.contains("# state.repos demo") && summary.contains("subject initial"));
    assert!(!summary.contains("obsolete_projection_fact"));
    assert!(sink.stored_pages(&source).unwrap().is_empty());
    assert!(!root_dir.join(&legacy).exists());
    brain.ensure_state_generations().unwrap();
    assert_eq!(
        snapshot(),
        first,
        "unchanged source renders identical bytes"
    );
    drop(brain);

    // A second seat with the same view shares the page: identical bytes,
    // not rewritten (mtime kept), and no seat subtree of its own.
    let page_path = tree.join(format!("{source}/demo.md"));
    let mtime = std::fs::metadata(&page_path).unwrap().modified().unwrap();
    let other_seat = SeatId::new("renderer-proof-2").unwrap();
    let other_root = tempfile::tempdir().unwrap();
    let other = BrainService::open(
        BrainServiceConfig {
            store_root: other_root.path().join("brain"),
            ..config.clone()
        },
        policy.clone(),
        Arc::clone(&ledger),
    )
    .unwrap();
    attach(&other, &other_seat, &bridge).unwrap();
    other.ensure_state_generations().unwrap();
    assert_eq!(snapshot(), first);
    assert_eq!(
        std::fs::metadata(&page_path).unwrap().modified().unwrap(),
        mtime
    );
    drop(other);

    std::fs::write(
        repo.join("crates/demo/src/lib.rs"),
        "pub fn current_projection_fact() {}\n",
    )
    .unwrap();
    commit(&repo, "updated");
    // Restart drops the renderer's in-memory bookkeeping.
    let reopened = BrainService::open(config, policy, ledger).unwrap();
    attach(&reopened, &seat, &bridge).unwrap();
    // Vault writes wait for the background state pump to avoid delaying turns.
    reopened.ensure_generation().unwrap();
    assert_eq!(snapshot(), first);
    reopened.ensure_state_generations().unwrap();
    // A new commit rewrites only the project's summary page.
    let updated = snapshot();
    let changed = updated
        .iter()
        .filter(|(name, text)| first.get(*name) != Some(*text))
        .count();
    assert_eq!(changed, 1, "{:?}", updated.keys().collect::<Vec<_>>());
    assert_eq!(updated.len(), 1);
    assert!(updated[&format!("{source}/demo.md")].contains("subject updated"));

    // The startup prune removes what no live seat projects: a retired
    // seat's view, a live seat's view of a source it no longer projects,
    // and a disabled project's shared summary; live views, shared pages a
    // seat owns, and non-knowledge generated pages stay. The remover
    // refuses anything outside the generated knowledge tree.
    let ghosts = [
        format!("generated/knowledge/{source}/retired-seat/index.md"),
        format!("generated/knowledge/state.live/{seat}/index.md"),
        format!("generated/knowledge/{source}/disabled-project.md"),
    ];
    let kept = format!("generated/knowledge/state.registry/{seat}/index.md");
    for page in ghosts
        .iter()
        .chain([&kept, &"generated/notes/keep.md".to_owned()])
    {
        bridge
            .write_generated(&odin_hermes::vault::VaultWriteGeneratedInput {
                page_name: page.clone(),
                content: "fixture page\n".into(),
            })
            .unwrap();
    }
    let mut views = BTreeMap::from([(seat.clone(), reopened.projected_views())]);
    assert_eq!(
        views[&seat].get(&source),
        Some(&BTreeSet::from(["demo.md".to_owned()]))
    );
    views
        .get_mut(&seat)
        .unwrap()
        .insert(AtlasId::new("state.registry").unwrap(), BTreeSet::new());
    assert_eq!(prune_knowledge_tree(&bridge, &views).unwrap(), 3);
    for ghost in &ghosts {
        assert!(!root_dir.join(ghost).exists(), "{ghost} must be pruned");
    }
    assert!(root_dir.join(&kept).exists());
    assert!(page_path.exists(), "an owned shared page stays");
    assert!(bridge
        .remove_generated_knowledge("generated/notes/keep.md")
        .is_err());
    assert!(bridge
        .generated_page_names()
        .unwrap()
        .iter()
        .any(|name| name == "generated/notes/keep.md"));
}

#[test]
fn history_projects_one_page_per_day_and_a_new_record_rewrites_one_page() {
    use odin_ledger::audit::{NewAuditEvent, RedactedPayload};

    let source = AtlasId::new("ops.history").unwrap();
    let fixture = fixture("knowledge-history", &source);
    let seat = &fixture.seat;
    let root = tempfile::tempdir().unwrap();
    let ledger = Arc::new(std::sync::Mutex::new(
        odin_ledger::Ledger::open_in_memory().unwrap(),
    ));
    let record = |id: &str, at: time::OffsetDateTime| {
        ledger
            .lock()
            .unwrap()
            .append_audit_event(NewAuditEvent {
                event_id: odin_domain::EventId::new(id).unwrap(),
                kind: "lane.observed".into(),
                actor: odin_domain::Actor::Seat {
                    seat: seat.clone(),
                    session: None,
                },
                scope: odin_domain::Scope {
                    project: Some(ProjectId::new("demo").unwrap()),
                    ..odin_domain::Scope::default()
                },
                evidence: Vec::new(),
                payload: RedactedPayload::new(
                    serde_json::json!({"detail": "metadata-only"}),
                    odin_domain::Redaction::None,
                )
                .unwrap(),
                occurred_at: at,
            })
            .unwrap();
    };
    let day_one = time::macros::datetime!(2026-10-03 10:00 UTC);
    let day_two = time::macros::datetime!(2026-10-04 10:00 UTC);
    record("event-1", day_one);
    record("event-2", day_one);
    record("event-3", day_two);
    // The old renderer's per-record page and paginated index.
    for page in ["items/legacy-record.md", "index-2.md"] {
        fixture
            .bridge
            .write_generated(&odin_hermes::vault::VaultWriteGeneratedInput {
                page_name: format!("generated/knowledge/{source}/{seat}/{page}"),
                content: "old per-record page\n".into(),
            })
            .unwrap();
    }

    let brain = BrainService::open(
        BrainServiceConfig {
            store_root: root.path().join("brain"),
            sources: BTreeMap::from([(
                source.clone(),
                BrainSourceConfig::OpsHistory {
                    source: odin_brain::source::ops::HistorySource::new(
                        source.clone(),
                        Arc::clone(&ledger),
                    ),
                },
            )]),
            embedding_available: false,
            embedding_model: None,
            archive_ingest_gate: None,
            postgres: None,
        },
        fixture.policy.clone(),
        Arc::clone(&ledger),
    )
    .unwrap();
    attach(&brain, seat, &fixture.bridge).unwrap();
    brain.ensure_state_generations().unwrap();
    let first = snapshot(&fixture.bridge);
    let day_page = |day: &str| format!("{source}/{seat}/{day}.md");
    assert_eq!(
        first.keys().cloned().collect::<Vec<_>>(),
        [day_page("2026-10-03"), day_page("2026-10-04")],
        "one page per day; no record pages, the old ones retired"
    );
    assert!(first[&day_page("2026-10-03")].contains("audit events: 2"));
    assert!(!first
        .values()
        .any(|page| page.contains("audit event event-")));

    record("event-4", day_two);
    brain.ensure_state_generations().unwrap();
    let second = snapshot(&fixture.bridge);
    let changed: Vec<_> = second
        .iter()
        .filter(|(name, text)| first.get(*name) != Some(*text))
        .map(|(name, _)| name.clone())
        .collect();
    assert_eq!(changed, [day_page("2026-10-04")]);
    assert_eq!(second.len(), first.len());
    assert!(second[&day_page("2026-10-04")].contains("audit events: 2"));
}
