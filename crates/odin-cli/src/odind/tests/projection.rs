use super::*;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;

/// Only policies of served seats may authorize configured sources.
#[test]
fn brain_sources_refuse_wiring_outside_the_served_policy() {
    let policy = |knowledge| odin_brain::config::EffectiveBrainPolicy {
        registry_revision: 7,
        knowledge,
        context: None,
        tools: None,
        model: odin_domain::knowledge::retrieval::ModelDescriptor {
            name: odin_domain::huginn::ids::ModelName::new("glm-flash").expect("model name"),
            tokenizer: odin_brain::context::PinnedTokenizer::id().expect("pinned tokenizer"),
            context_window_tokens: std::num::NonZeroU32::new(200_000).expect("window"),
        },
        project_memory: BTreeMap::new(),
        seat_global_sources: BTreeSet::new(),
        review_lane: None,
        profile_namespace: None,
        writes_profile: false,
        policy_digest: Digest::hash(b"brain-source-confinement-fixture"),
    };
    let knowledge_for = |sources: &[&str]| {
        let authorized = sources
            .iter()
            .map(|id| odin_domain::knowledge::AtlasId::new(*id).expect("source id"))
            .collect::<BTreeSet<_>>();
        odin_domain::knowledge::EffectiveKnowledgePolicy {
            required: false,
            atlas_sources: authorized,
            required_tags: BTreeSet::new(),
            denied_tags: BTreeSet::new(),
            allowed_trust: BTreeSet::from([odin_domain::knowledge::TrustClass::Curated]),
            retrieval_mode: odin_domain::knowledge::RetrievalMode::Lexical,
            candidate_limit: std::num::NonZeroU16::new(8).expect("candidate limit"),
            top_k: std::num::NonZeroU16::new(4).expect("top k"),
            min_score: odin_domain::knowledge::RelevanceScore::new(100_000).expect("min score"),
            chunk_tokens: std::num::NonZeroU32::new(256).expect("chunk tokens"),
            chunk_overlap_tokens: 32,
            embedding_backend: odin_domain::knowledge::EmbeddingBackend::Disabled,
        }
    };
    let policies = |entries: &[(
        &str,
        Option<odin_domain::knowledge::EffectiveKnowledgePolicy>,
    )]| {
        entries
            .iter()
            .map(|(seat, knowledge)| {
                (
                    odin_domain::SeatId::new(*seat).expect("seat id"),
                    policy(knowledge.clone()),
                )
            })
            .collect::<BTreeMap<odin_domain::SeatId, odin_brain::config::EffectiveBrainPolicy>>()
    };
    // The composition proves every wired atlas root is a real directory
    // (and distinct per source), so the fixture materializes one per key.
    let atlas_fixture = tempfile::tempdir().expect("atlas fixture root");
    let materialize = |key: &str| {
        let root = atlas_fixture.path().join(key);
        fs::create_dir_all(&root).expect("atlas fixture source directory");
        root
    };
    let wired = |keys: &[&str]| {
        keys.iter()
            .map(|&key| {
                (
                    key.to_owned(),
                    odin_huginn::config::OdindBrainSourceConfig {
                        kind: "atlas".to_owned(),
                        privacy: None,
                        root: Some(materialize(key)),
                        port: None,
                        expected_space_root: None,
                        general_namespaces: Vec::new(),
                        generated_namespace: None,
                        excluded_namespaces: Vec::new(),
                        max_pages: None,
                        format: None,
                        export_path: None,
                        memory_namespace: None,
                        privacy_class: None,
                        dedupe_key: None,
                        selection: None,
                    },
                )
            })
            .collect::<BTreeMap<String, odin_huginn::config::OdindBrainSourceConfig>>()
    };
    let personal = Some(knowledge_for(&["atlas.personal"]));
    let code = Some(knowledge_for(&["atlas.code"]));

    // Composition needs a shared reader; adapter behavior is tested separately.
    let registry_fixture = tempfile::tempdir().expect("registry fixture root");
    publish_snapshot_fixture(registry_fixture.path());
    let registry_handle = Arc::new(
        odin_registry::SnapshotHandle::open(odin_registry::SnapshotStore::new(
            registry_fixture.path().join("snapshot.json"),
        ))
        .expect("snapshot handle opens"),
    );
    let read_model = odin_huginn::read_model::MaterializedReadModel::with_limits(
        16,
        32,
        time::OffsetDateTime::now_utc(),
    );
    let task_reader: Arc<dyn odin_brain::source::state::tasks::TaskStateReader> =
        Arc::new(EmptyTaskReader);
    let history_ledger = Arc::new(std::sync::Mutex::new(
        odin_ledger::Ledger::open_in_memory().unwrap(),
    ));
    let compose =
        |policies: &BTreeMap<odin_domain::SeatId, odin_brain::config::EffectiveBrainPolicy>,
         wired: &BTreeMap<String, odin_huginn::config::OdindBrainSourceConfig>| {
            brain_sources(
                policies,
                &crate::projection::DeclaredBrainSources {
                    sources: wired,
                    project_roots: &BTreeMap::new(),
                },
                &registry_handle,
                &read_model,
                &task_reader,
                None,
                &history_ledger,
            )
        };

    // A single served seat composes exactly its authorized sources.
    let composed = compose(
        &policies(&[("sinmara", personal.clone())]),
        &wired(&["atlas.personal"]),
    )
    .expect("the authorized source is the one wired source");
    assert_eq!(composed.len(), 1);
    assert!(matches!(
        composed.values().next(),
        Some(odin_brain::service::BrainSourceConfig::Atlas { .. })
    ));

    // Restricted sources must remain unread even when configured.
    let mut restricted = wired(&["atlas.personal"]);
    restricted.get_mut("atlas.personal").unwrap().privacy =
        Some(odin_domain::knowledge::PrivacyClass::AplRestricted);
    let composed = compose(&policies(&[("sinmara", personal.clone())]), &restricted)
        .expect("a withheld source still composes");
    assert!(matches!(
        composed.values().next(),
        Some(odin_brain::service::BrainSourceConfig::Withheld {
            class: odin_domain::knowledge::PrivacyClass::AplRestricted
        })
    ));
    let mut school = wired(&["atlas.personal"]);
    school.get_mut("atlas.personal").unwrap().privacy =
        Some(odin_domain::knowledge::PrivacyClass::School);
    let composed = compose(&policies(&[("sinmara", personal.clone())]), &school)
        .expect("a school source composes");
    assert!(matches!(
        composed.values().next(),
        Some(odin_brain::service::BrainSourceConfig::Atlas { .. })
    ));

    // Two seats with DISTINCT published scopes compose the union of
    // their authorized sets: per-seat filtering to each seat's own set
    // happens in the factory assembly, never by narrowing this map.
    let composed = compose(
        &policies(&[("sinmara", personal.clone()), ("architect", code.clone())]),
        &wired(&["atlas.personal", "atlas.code"]),
    )
    .expect("each seat's authorized set stays wired");
    assert_eq!(composed.len(), 2);

    let error = compose(
        &policies(&[("sinmara", personal.clone()), ("architect", code)]),
        &wired(&["atlas.personal", "atlas.code", "atlas.hosts"]),
    )
    .expect_err("unauthorized wiring must refuse");
    assert!(
        error.contains("no served seat's published policy"),
        "typed unauthorized-wiring error: {error}"
    );

    let error = compose(&policies(&[("sinmara", None)]), &wired(&["atlas.personal"]))
        .expect_err("wiring without any knowledge authority must refuse");
    assert!(
        error.contains("no served seat's published policy"),
        "typed unauthorized-wiring error: {error}"
    );

    let state_policies = policies(&[(
        "sinmara",
        Some(knowledge_for(&[
            "atlas.personal",
            "state.registry",
            "state.live",
            "state.tasks",
        ])),
    )]);
    let state_wired = |keys: &[&str]| {
        keys.iter()
            .map(|&key| {
                (
                    key.to_owned(),
                    odin_huginn::config::OdindBrainSourceConfig {
                        kind: key.to_owned(),
                        privacy: None,
                        root: None,
                        port: None,
                        expected_space_root: None,
                        general_namespaces: Vec::new(),
                        generated_namespace: None,
                        excluded_namespaces: Vec::new(),
                        max_pages: None,
                        format: None,
                        export_path: None,
                        memory_namespace: None,
                        privacy_class: None,
                        dedupe_key: None,
                        selection: None,
                    },
                )
            })
            .collect::<BTreeMap<String, odin_huginn::config::OdindBrainSourceConfig>>()
    };
    let composed = compose(
        &state_policies,
        &state_wired(&["state.registry", "state.live", "state.tasks"]),
    )
    .expect("authorized state sources compose their real authorities");
    assert_eq!(composed.len(), 3);
    let id = |key: &str| odin_domain::knowledge::AtlasId::new(key).expect("state source id");
    assert!(matches!(
        composed.get(&id("state.registry")),
        Some(odin_brain::service::BrainSourceConfig::StateRegistry { .. })
    ));
    assert!(matches!(
        composed.get(&id("state.live")),
        Some(odin_brain::service::BrainSourceConfig::StateLive { .. })
    ));
    assert!(matches!(
        composed.get(&id("state.tasks")),
        Some(odin_brain::service::BrainSourceConfig::StateTasks { .. })
    ));
    let error = compose(
        &policies(&[("sinmara", personal.clone())]),
        &state_wired(&["state.registry"]),
    )
    .expect_err("unauthorized state wiring must refuse");
    assert!(
        error.contains("no served seat's published policy"),
        "typed unauthorized state wiring error: {error}"
    );

    // Memory namespaces come from the vault configuration and cannot alias ordinary sources.
    let vault = odin_hermes::vault::VaultConfig {
        vault_root: std::path::PathBuf::from("/tmp/fabric-k2-memory-fixture"),
        source_id: "atlas.personal".to_owned(),
        silverbullet: Some(odin_hermes::vault::SilverBulletConfig {
            port: 3117,
            expected_space_root: Some("/tmp/fabric-k2-memory-fixture".to_owned()),
        }),
        general_namespaces: vec!["knowledge".to_owned()],
        generated_namespace: "generated".to_owned(),
        excluded_namespaces: vec!["credentials".to_owned()],
        max_pages: 100,
        max_page_bytes: 4096,
        timeout_ms: 1_000,
    };
    let compose_with_vault =
        |policies: &BTreeMap<odin_domain::SeatId, odin_brain::config::EffectiveBrainPolicy>,
         wired: &BTreeMap<String, odin_huginn::config::OdindBrainSourceConfig>| {
            brain_sources(
                policies,
                &crate::projection::DeclaredBrainSources {
                    sources: wired,
                    project_roots: &BTreeMap::new(),
                },
                &registry_handle,
                &read_model,
                &task_reader,
                Some(&vault),
                &history_ledger,
            )
        };
    let memory_policies = policies(&[(
        "sinmara",
        Some(knowledge_for(&["atlas.personal", "memory.sinmara"])),
    )]);
    let memory_wired = |keys: &[&str]| {
        keys.iter()
            .map(|&key| {
                let kind = if key.starts_with("memory.") {
                    "memory".to_owned()
                } else {
                    "atlas".to_owned()
                };
                (
                    key.to_owned(),
                    odin_huginn::config::OdindBrainSourceConfig {
                        kind,
                        privacy: None,
                        root: if key.starts_with("memory.") {
                            None
                        } else {
                            Some(materialize(key))
                        },
                        port: None,
                        expected_space_root: None,
                        general_namespaces: Vec::new(),
                        generated_namespace: None,
                        excluded_namespaces: Vec::new(),
                        max_pages: None,
                        format: None,
                        export_path: None,
                        memory_namespace: None,
                        privacy_class: None,
                        dedupe_key: None,
                        selection: None,
                    },
                )
            })
            .collect::<BTreeMap<String, odin_huginn::config::OdindBrainSourceConfig>>()
    };
    // Authorized memory namespaces are derived without operator source entries.
    let derived = compose_with_vault(&memory_policies, &memory_wired(&["atlas.personal"]))
        .expect("an authorized memory namespace composes undeclared");
    assert!(matches!(
        derived.get(&id("memory.sinmara")),
        Some(odin_brain::service::BrainSourceConfig::Memory { .. })
    ));
    let composed = compose_with_vault(
        &memory_policies,
        &memory_wired(&["atlas.personal", "memory.sinmara"]),
    )
    .expect("the seat's own memory source composes from the vault singleton");
    let Some(odin_brain::service::BrainSourceConfig::Memory { source }) =
        composed.get(&id("memory.sinmara"))
    else {
        panic!("memory.sinmara must compose as the Memory variant");
    };
    // Exactly the seat's own reserved subtree serves: sibling seat,
    // general, and traversal names are refused by the composed scope.
    assert!(source.admits("memory/sinmara/preferences.md"));
    assert!(!source.admits("memory/architect/preferences.md"));
    assert!(!source.admits("memory/preferences.md"));
    assert!(!source.admits("knowledge/preferences.md"));
    assert!(!source.admits("memory/sinmara/../architect/x.md"));

    // Without the vault singleton a declared memory source has no
    // authority at all and refuses startup.
    let error = compose(
        &memory_policies,
        &memory_wired(&["atlas.personal", "memory.sinmara"]),
    )
    .expect_err("memory wiring without the vault singleton must refuse");
    assert!(
        error.contains("no [hermes.vault]"),
        "typed missing-vault error: {error}"
    );

    // A general allowlist must not expose the reserved memory tree.
    let silverbullet_wired = |general: &[&str], generated: &str| {
        let mut wired = memory_wired(&["atlas.personal", "memory.sinmara"]);
        wired.insert(
            "vault.broad".to_owned(),
            odin_huginn::config::OdindBrainSourceConfig {
                kind: "silverbullet".to_owned(),
                privacy: None,
                root: None,
                port: Some(3000),
                expected_space_root: None,
                general_namespaces: general.iter().map(|name| name.to_string()).collect(),
                generated_namespace: Some(generated.to_owned()),
                excluded_namespaces: Vec::new(),
                max_pages: Some(100),
                format: None,
                export_path: None,
                memory_namespace: None,
                privacy_class: None,
                dedupe_key: None,
                selection: None,
            },
        );
        wired
    };
    compose_with_vault(
        &policies(&[(
            "sinmara",
            Some(knowledge_for(&[
                "atlas.personal",
                "memory.sinmara",
                "vault.broad",
            ])),
        )]),
        &silverbullet_wired(&["generated"], "generated/other"),
    )
    .expect_err("a general arm over the reserved root must refuse");

    // A generated namespace reaching INTO the reserved tree refuses too —
    // including the seat tree itself, whose own /memory carve-out
    // would not cover the seat's own notes.
    compose_with_vault(
        &policies(&[(
            "sinmara",
            Some(knowledge_for(&[
                "atlas.personal",
                "memory.sinmara",
                "vault.broad",
            ])),
        )]),
        &silverbullet_wired(&["knowledge"], "memory/sinmara"),
    )
    .expect_err("a generated arm inside the reserved tree must refuse");

    // A projection must never ingest its own generated output, including
    // through an independently declared namespace nested below the renderer.
    compose_with_vault(
        &policies(&[(
            "sinmara",
            Some(knowledge_for(&[
                "atlas.personal",
                "memory.sinmara",
                "vault.broad",
            ])),
        )]),
        &silverbullet_wired(&["knowledge"], "generated/knowledge/state.registry"),
    )
    .expect_err("a generated arm inside the projection output must refuse");

    // Disjoint general and generated namespaces may share the vault.
    let composed = compose_with_vault(
        &policies(&[(
            "sinmara",
            Some(knowledge_for(&[
                "atlas.personal",
                "memory.sinmara",
                "vault.broad",
            ])),
        )]),
        &silverbullet_wired(&["knowledge"], "generated"),
    )
    .expect("the vault's own broad source composes");
    assert_eq!(composed.len(), 3);
    let composed = compose_with_vault(
        &policies(&[(
            "sinmara",
            Some(knowledge_for(&[
                "atlas.personal",
                "memory.sinmara",
                "vault.broad",
            ])),
        )]),
        &silverbullet_wired(&["knowledge"], "generated/other"),
    )
    .expect("a disjoint generated namespace composes");
    assert_eq!(composed.len(), 3);
}


fn gateway_route(
    lane: &str,
    model: &str,
    endpoint: &str,
    eligible: bool,
) -> odin_registry::GatewayProjectionRoute {
    odin_registry::GatewayProjectionRoute {
        gateway_lane_id: lane.to_owned(),
        gateway_model_id: model.to_owned(),
        account_handle: "account".to_owned(),
        endpoint: endpoint.to_owned(),
        credential_handle: "credential".to_owned(),
        role: "worker".to_owned(),
        affinity_key: "affinity".to_owned(),
        eligible,
    }
}

fn gateway_projection(
    routes: Vec<odin_registry::GatewayProjectionRoute>,
) -> GatewayProjectionManifest {
    GatewayProjectionManifest::build(routes).expect("projection builds")
}

/// Include the versioned snapshot and receipt required by `load_verified`.
fn publish_snapshot_fixture(root: &std::path::Path) {
    let snapshot = odin_registry::Snapshot::build(1, Vec::new()).expect("fixture snapshot");
    let mut bytes = serde_json::to_vec_pretty(&snapshot).expect("serialize snapshot");
    bytes.push(b'\n');
    fs::write(root.join("snapshot.json"), &bytes).expect("write active snapshot");
    let revisions = root.join("revisions");
    fs::create_dir_all(&revisions).expect("create revisions directory");
    fs::write(
        revisions.join(format!("{:020}.snapshot.json", snapshot.revision)),
        &bytes,
    )
    .expect("write versioned snapshot");
    let receipt = serde_json::json!({
        "schema": odin_registry::PUBLICATION_RECEIPT_SCHEMA,
        "outcome": "published",
        "revision": snapshot.revision,
        "previous_revision": serde_json::Value::Null,
        "commit": format!("commit-{}", snapshot.revision),
        "tree": format!("tree-{}", snapshot.revision),
        "snapshot_hash": snapshot.hash.clone(),
    });
    fs::write(
        revisions.join(format!("{:020}.receipt.json", snapshot.revision)),
        serde_json::to_vec_pretty(&receipt).expect("serialize receipt"),
    )
    .expect("write receipt");
}

/// Composition only needs to attach the shared reader; adapter behavior is tested separately.
struct EmptyTaskReader;

impl odin_brain::source::state::tasks::TaskStateReader for EmptyTaskReader {
    fn snapshot(
        &self,
    ) -> odin_brain::error::BrainResult<odin_brain::source::state::tasks::TaskStateSnapshot> {
        Ok(odin_brain::source::state::tasks::TaskStateSnapshot {
            delegations: Vec::new(),
            runs: Vec::new(),
        })
    }
}





