use super::*;
use odin_brain::retrieval::LaneEmbeddingProvider as _;
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
    assert!(source.admits("generated/memories/sinmara/preferences.md"));
    assert!(!source.admits("generated/memories/architect/preferences.md"));
    assert!(!source.admits("generated/memories/preferences.md"));
    assert!(!source.admits("knowledge/preferences.md"));
    assert!(!source.admits("generated/memories/sinmara/../architect/x.md"));

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
    // including the seat tree itself, whose own nested /memories carve-out
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
        &silverbullet_wired(&["knowledge"], "generated/memories/sinmara"),
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

/// Gateway budgets enforce spending; native providers cannot enforce a declared budget here.
#[test]
fn served_embedding_refuses_native_and_composes_gateway_budgets() {
    use crate::test_fixture::PublishedStore;
    use crate::test_support::commit_all;
    use odin_domain::knowledge::retrieval::RetrievalQuery;
    use odin_registry::{GatewayProjectionManifest, GatewayProjectionRoute};
    use std::fs;
    use std::net::TcpListener;
    use std::num::NonZeroU16;
    use std::sync::atomic::{AtomicUsize, Ordering};

    const BRAIN_TOML: &str = r#"schema = "odin.registry.v1"
kind = "provider"
enabled = true
description = "budget boundary fixture"
adapter = "brain-embedding"
[policy]
routes = []
[budget]
usd_micros = 30_000_000
[budget.window]
duration_seconds = 2_592_000
[recovery]
allowed_rungs = ["retry", "escalate"]
blocked_missing_decision = "operator decides"
[recovery.max_attempts]
retry = 1
restart_worker = 0
checkpoint = 0
rehome = 0
escalate = 1
[recovery.cooldown_seconds]
retry = 30
restart_worker = 0
checkpoint = 0
rehome = 0
escalate = 0
"#;
    const GATEWAY_TOML: &str = r#"schema = "odin.registry.v1"
kind = "provider"
enabled = true
description = "budget boundary fixture"
adapter = "litellm-gateway"
[policy]
routes = [{ gateway_lane_id = "embed-lane", gateway_model_id = "embed-model-1" }]
[budget]
usd_micros = 30_000_000
[budget.window]
duration_seconds = 2_592_000
[recovery]
allowed_rungs = ["retry", "escalate"]
blocked_missing_decision = "operator decides"
[recovery.max_attempts]
retry = 1
restart_worker = 0
checkpoint = 0
rehome = 0
escalate = 1
[recovery.cooldown_seconds]
retry = 30
restart_worker = 0
checkpoint = 0
rehome = 0
escalate = 0
"#;

    let listener = TcpListener::bind("127.0.0.1:0").expect("bind gateway stand-in");
    let port = listener.local_addr().expect("listener addr").port();
    let probe_listener = listener.try_clone().expect("clone probe listener");
    let attempts = std::sync::Arc::new(AtomicUsize::new(0));
    let accepted = attempts.clone();
    // Inspect the wire header rather than just the configured credential.
    let seen_authorization = std::sync::Arc::new(std::sync::Mutex::new(None::<String>));
    let recorded = std::sync::Arc::clone(&seen_authorization);
    // Deterministic gateway stand-in: drain each request, then answer once.
    // Draining first removes the ECONNRESET race a reply-to-half-read close
    // creates under parallel-suite scheduling. The accept loop survives the
    // probe's transient non-blocking window instead of ending on WouldBlock.
    std::thread::spawn(move || {
        use std::io::{BufRead as _, BufReader, Read as _, Write as _};
        const MAX_STANDIN_REQUEST_BYTES: u64 = 64 * 1024;
        loop {
            match listener.accept() {
                Ok((stream, _)) => {
                    accepted.fetch_add(1, Ordering::Relaxed);
                    if stream
                        .set_read_timeout(Some(std::time::Duration::from_secs(5)))
                        .is_err()
                    {
                        continue;
                    }
                    let mut reader = BufReader::with_capacity(8192, stream);
                    let mut content_length: Option<usize> = None;
                    let mut head_remaining = MAX_STANDIN_REQUEST_BYTES;
                    let mut head_complete = false;
                    // `take` bounds only what is read; bytes the BufReader
                    // already buffered for the body stay intact.
                    while head_remaining > 0 {
                        let mut line = String::new();
                        let mut limited = (&mut reader).take(head_remaining);
                        let read = limited.read_line(&mut line).unwrap_or(0);
                        head_remaining -= read as u64;
                        if read == 0 {
                            break;
                        }
                        if line == "\r\n" {
                            head_complete = true;
                            break;
                        }
                        if let Some((name, value)) = line.split_once(':') {
                            if name.trim().eq_ignore_ascii_case("authorization") {
                                if let Ok(mut slot) = recorded.lock() {
                                    *slot = Some(value.trim().to_owned());
                                }
                            }
                            if name.trim().eq_ignore_ascii_case("content-length") {
                                content_length = value.trim().parse::<usize>().ok();
                            }
                        }
                    }
                    // A broken or oversized fixture request is refused, never
                    // answered with a guessed body boundary.
                    let body_bytes = match head_complete {
                        true => content_length.unwrap_or(0),
                        false => continue,
                    };
                    if body_bytes as u64 > MAX_STANDIN_REQUEST_BYTES {
                        continue;
                    }
                    let mut remaining = body_bytes;
                    let mut drained = true;
                    while remaining > 0 {
                        let available = match reader.fill_buf() {
                            Ok(buffer) => buffer.len(),
                            Err(_) => {
                                drained = false;
                                break;
                            }
                        };
                        if available == 0 {
                            drained = false;
                            break;
                        }
                        let take = available.min(remaining);
                        reader.consume(take);
                        remaining -= take;
                    }
                    if !drained {
                        continue;
                    }
                    let mut stream = reader.into_inner();
                    let _ =
                        stream.write_all(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n");
                    let _ = stream.flush();
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => continue,
                Err(_) => break,
            }
        }
    });

    let store = PublishedStore::new("laptop", true);
    let providers = store.worktree.join("registry").join("providers");
    fs::create_dir_all(providers.join("brain-embedding")).expect("brain dir");
    fs::create_dir_all(providers.join("gateway")).expect("gateway dir");
    fs::write(
        providers.join("brain-embedding").join("provider.toml"),
        BRAIN_TOML,
    )
    .expect("write brain provider");
    fs::write(
        providers.join("gateway").join("provider.toml"),
        GATEWAY_TOML,
    )
    .expect("write gateway provider");
    let commit = commit_all(&store.worktree, "budget boundary fixture");
    let candidate = odin_registry::ValidatedSnapshotCandidate::from_committed_worktree(
        &store.worktree,
        &commit,
        Vec::<odin_registry::relational::AdmittedBinding>::new(),
    )
    .expect("fixture candidate validates");
    let snapshot_path = store.temporary.path().join("snapshot.json");
    odin_registry::SnapshotStore::new(&snapshot_path)
        .publish_committed(&candidate, 1)
        .expect("publish fixture snapshot");
    let snapshot =
        odin_registry::SnapshotHandle::open(odin_registry::SnapshotStore::new(&snapshot_path))
            .expect("snapshot handle")
            .current();

    let manifest = GatewayProjectionManifest::build(vec![GatewayProjectionRoute {
        gateway_lane_id: "embed-lane".to_owned(),
        gateway_model_id: "embed-model-1".to_owned(),
        account_handle: "fixture-account".to_owned(),
        endpoint: format!("http://127.0.0.1:{port}"),
        credential_handle: "gateway/key".to_owned(),
        role: "embed".to_owned(),
        affinity_key: "embed".to_owned(),
        eligible: true,
    }])
    .expect("fixture projection builds");
    let manifest_bytes = serde_json::to_vec(&manifest).expect("serialize projection");
    let manifest_path = store.temporary.path().join("projection.json");
    fs::write(&manifest_path, &manifest_bytes).expect("write projection");

    fn composed_config(
        root: &std::path::Path,
        snapshot: &std::path::Path,
        projection: &std::path::Path,
        digest: &str,
        provider: &str,
        port: u16,
    ) -> odin_huginn::OdindConfig {
        let mut config: odin_huginn::OdindConfig = odin_huginn::OdindConfig::parse(
            &crate::test_fixture::fixture_config_text(root, snapshot),
        )
        .expect("fixture config parses");
        let state_root = root.join("state");
        fs::create_dir_all(&state_root).expect("state root");
        config.paths.state_root = state_root;
        config.catalogs.gateway_projection = odin_huginn::PathDigestRef {
            path: projection.to_path_buf(),
            digest: digest.to_owned(),
        };
        config.brain = Some(odin_huginn::OdindBrainConfig {
            lane_windows: Default::default(),
            serving_model: odin_huginn::OdindServingModelConfig {
                name: "test-model".to_owned(),
                context_window_tokens: std::num::NonZeroU32::new(8_192).expect("nonzero window"),
                tokenizer: None,
            },
            sources: BTreeMap::new(),
            embedding: Some(odin_huginn::OdindBrainEmbeddingConfig {
                provider: provider.to_owned(),
                endpoint: format!("http://127.0.0.1:{port}"),
            }),
            postgres: None,
        });
        config.gateway_host_credentials.insert(
            "gateway/key".to_owned(),
            odin_huginn::OdindGatewayHostCredential::new("FIXTURE_EMBEDDING_KEY")
                .expect("fixture custody parses"),
        );
        config
    }

    let mut allowed_trust = BTreeSet::new();
    allowed_trust.insert(odin_domain::knowledge::retrieval::TrustClass::Curated);
    allowed_trust.insert(odin_domain::knowledge::retrieval::TrustClass::Observed);
    let query = RetrievalQuery::new(
        "thesis advisor meeting".to_owned(),
        BTreeSet::from([odin_domain::knowledge::AtlasId::new("atlas.personal").expect("atlas id")]),
        BTreeSet::new(),
        BTreeSet::new(),
        allowed_trust,
        NonZeroU16::new(24).expect("candidate limit"),
        NonZeroU16::new(8).expect("top k"),
        odin_domain::knowledge::ids::RelevanceScore::new(100_000).expect("min score"),
    )
    .expect("retrieval query");

    let local_root = store.temporary.path().join("native");
    let local_config = composed_config(
        &local_root,
        &snapshot_path,
        &manifest_path,
        &odin_domain::Digest::hash(&manifest_bytes).to_string(),
        "brain-embedding",
        port,
    );
    let binding =
        served_embedding(&local_config, &snapshot).expect("native provider resolves without error");
    assert!(
        binding.is_none(),
        "a native provider must never bind an embedding executor"
    );
    probe_listener
        .set_nonblocking(true)
        .expect("nonblocking probe");
    let probe = probe_listener.accept();
    assert!(
        matches!(&probe, Err(error) if error.kind() == std::io::ErrorKind::WouldBlock),
        "no HTTP request may reach the gateway for a native provider"
    );
    probe_listener
        .set_nonblocking(false)
        .expect("restore the blocking stand-in after the probe");
    assert!(
        !local_config
            .paths
            .state_root
            .join("ledger.sqlite3")
            .exists(),
        "the unbound native path must not touch the provider ledger"
    );

    // GATEWAY-ROUTED: same declared budget, gateway-owned enforcement — the
    // real executor composes, reaches for the gateway, and surfaces the
    // transport-level failure instead of a budget refusal.
    let gateway_root = store.temporary.path().join("gateway");
    let gateway_config = composed_config(
        &gateway_root,
        &snapshot_path,
        &manifest_path,
        &odin_domain::Digest::hash(&manifest_bytes).to_string(),
        "gateway",
        port,
    );
    // Leases use the requesting session lane, not the gateway route; materialize it before first use.
    let runtime_lane = odin_domain::LaneId::new("sinmara-life").expect("runtime lane id");
    let mut gateway_config = gateway_config;
    gateway_config
        .lane_bindings
        .push(odin_huginn::OdindLaneBinding {
            seat: odin_domain::SeatId::new("sinmara").expect("seat id"),
            project: odin_domain::ProjectId::new("life").expect("project id"),
            lane: runtime_lane.clone(),
            runtime: false,
        });
    // Inject credential resolution to avoid mutating the process environment.
    let mut custody_source =
        |name: &str| (name == "FIXTURE_EMBEDDING_KEY").then(|| "fixture-embedding-key".to_owned());
    // Backfill leases also require the session lane's ledger row.
    {
        let mut parts = served_embedding_parts(
            &gateway_config,
            &snapshot,
            &runtime_lane,
            &mut custody_source,
        )
        .expect("backfill parts compose")
        .expect("backfill parts bind");
        assert_eq!(parts.coordinator.lane(), &runtime_lane);
        let lease = parts
            .coordinator
            .begin_request(
                &mut parts.ledger,
                "backfill-lease-probe",
                time::OffsetDateTime::now_utc(),
            )
            .expect("the backfill lease starts under the registered session lane");
        drop(lease);
    }
    let binding = compose_embedding(&gateway_config, &snapshot, &mut custody_source)
        .expect("gateway-routed budget composes the real executor")
        .expect("gateway-routed budget binds an executor");
    // The session context binds its runtime lane ONCE; the bound embedder
    // serves every retrieval of that context.
    let embedder = binding
        .executor
        .bind_lane(&runtime_lane)
        .expect("the runtime lane binds to the executor");
    let error = (embedder)(std::slice::from_ref(&query.text))
        .expect_err("offline fixture gateway surfaces its own transport failure");
    assert!(
        matches!(
            &error,
            odin_brain::error::BrainError::EmbeddingUnavailable { reason, .. }
                if reason.contains("HTTP 400") && !reason.contains("budget")
        ),
        "gateway path attempts the served gateway and reports its reply, never a budget \
         refusal: {error:?}"
    );
    // The observed lease is owned by the REQUESTING runtime lane, not the
    // projected route lane.
    {
        let ledger =
            odin_ledger::Ledger::open(gateway_config.paths.state_root.join("ledger.sqlite3"))
                .expect("observe ledger opens");
        let lease = ledger
            .active_provider_lease_for_lane(&runtime_lane)
            .expect("lease row readable");
        assert!(
            lease.is_some(),
            "the kernel provider lease must be minted under the requesting runtime lane"
        );
        assert!(
            ledger
                .active_provider_lease_for_lane(
                    &odin_domain::LaneId::new("embed-lane").expect("route lane id")
                )
                .expect("route-lane lease readable")
                .is_none(),
            "the projected route lane must never own a lease"
        );
    }
    // The composed credential reached the wire: the stand-in recorded the
    // exact Authorization header of the request it answered.
    assert_eq!(
        seen_authorization
            .lock()
            .expect("authorization slot")
            .as_deref(),
        Some("Bearer fixture-embedding-key"),
        "the resolved custody value must be presented as the gateway bearer"
    );
    // The stand-in incremented before writing the reply the transport just
    // consumed, so exactly one served attempt is deterministic here.
    assert_eq!(
        attempts.load(Ordering::Relaxed),
        1,
        "the gateway-routed executor must have attempted the gateway exactly once"
    );
    assert!(
        gateway_config
            .paths
            .state_root
            .join("ledger.sqlite3")
            .exists(),
        "the gateway-routed executor runs under a kernel provider lease"
    );

    // Credential failures must name the handle, never its value, before any network request.
    let mut unrelated_source = |_: &str| Some("unrelated-value".to_owned());
    let mut undeclared = gateway_config.clone();
    undeclared.gateway_host_credentials.clear();
    let error = match compose_embedding(&undeclared, &snapshot, &mut unrelated_source) {
        Ok(_) => panic!("an undeclared credential handle must refuse composition"),
        Err(error) => error,
    };
    assert!(
        error.contains("gateway/key") && !error.contains("unrelated-value"),
        "undeclared-handle refusal names the handle, never the unrelated value: {error}"
    );
    // A declared source holding no value refuses: unset, and present but
    // empty, are the same typed boundary.
    let mut empty_source = |_: &str| None::<String>;
    let error = match compose_embedding(&gateway_config, &snapshot, &mut empty_source) {
        Ok(_) => panic!("a custody source holding no value must refuse composition"),
        Err(error) => error,
    };
    assert!(
        error.contains("gateway/key"),
        "missing-value refusal names the handle: {error}"
    );
    let mut empty_string_source = |_: &str| Some(String::new());
    let error = match compose_embedding(&gateway_config, &snapshot, &mut empty_string_source) {
        Ok(_) => panic!("an empty credential value must refuse composition"),
        Err(error) => error,
    };
    assert!(
        error.contains("gateway/key"),
        "empty-value refusal names the handle: {error}"
    );
    // A resolved value carrying CR/LF is not a valid bearer and refuses at
    // composition without the error ever quoting it.
    let mut crlf_source = |_: &str| Some("fixture-embedding-key\r\n".to_owned());
    let error = match compose_embedding(&gateway_config, &snapshot, &mut crlf_source) {
        Ok(_) => panic!("a CR/LF-bearing credential value must refuse composition"),
        Err(error) => error,
    };
    assert!(
        error.contains("gateway/key") && !error.contains("fixture-embedding-key"),
        "bearer refusal names the handle, never the value: {error}"
    );
    assert_eq!(
        attempts.load(Ordering::Relaxed),
        1,
        "custody refusals happen before any gateway connection"
    );
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

/// The served credential handle is the ONE eligible route naming the exact
/// admitted (lane, model) pair: a different lane's route never leaks in, and
/// no host or endpoint travels with it — the pod's address is the explicitly
/// selected target node's declared gateway endpoint.
#[test]
fn served_workload_gateway_credential_resolves_the_exact_lane_route() {
    let mut exact = gateway_route(
        "lane.model",
        "model.x",
        "https://gateway.internal:4000/v1",
        true,
    );
    exact.credential_handle = "credential-exact".to_owned();
    let mut other = gateway_route("lane.other", "model.y", "http://10.0.0.8:4000/v1", true);
    other.credential_handle = "credential-other".to_owned();
    let manifest = gateway_projection(vec![exact, other]);
    let handle = served_workload_gateway_credential(&manifest, "lane.model", "model.x")
        .expect("the exact eligible route resolves");
    assert_eq!(handle, "credential-exact");
}

/// A lane the projection carries but marks ineligible is a DEAD route, and
/// a lane the projection never carried is MISSING — both refuse typed with
/// the distinct reason, never a fallback to another route.
#[test]
fn served_workload_gateway_credential_refuses_dead_and_missing_routes_typed() {
    let dead = gateway_projection(vec![gateway_route(
        "lane.model",
        "model.x",
        "https://gateway.internal:4000/v1",
        false,
    )]);
    let dead = served_workload_gateway_credential(&dead, "lane.model", "model.x");
    assert!(dead.is_err(), "an ineligible route is dead");

    let missing = gateway_projection(vec![gateway_route(
        "lane.other",
        "model.y",
        "https://gateway.internal:4000/v1",
        true,
    )]);
    let missing = served_workload_gateway_credential(&missing, "lane.model", "model.x");
    assert!(missing.is_err(), "an unprojected lane is missing");
}

/// A daemon-local (loopback) route endpoint is a lawful declaration for the
/// local clients that consume that route: the workload credential resolves
/// without reading the route's address at all, because the pod's address is
/// the selected node's declared gateway endpoint (which refuses loopback
/// where the node declaration is parsed).
#[test]
fn served_workload_gateway_credential_ignores_the_route_endpoint_address() {
    let manifest = gateway_projection(vec![gateway_route(
        "lane.model",
        "model.x",
        "http://127.0.0.1:4000/v1",
        true,
    )]);
    assert_eq!(
        served_workload_gateway_credential(&manifest, "lane.model", "model.x")
            .expect("the local route still serves workload credentials"),
        "credential"
    );
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

/// The archive projection arm: one declared archive source composes the
/// strict domain declaration (re-validated at the projection seam), and two
/// sources over the SAME export path refuse — one physical root is one
/// source identity, for archives exactly as for atlas roots.
#[test]
fn brain_sources_compose_archive_declarations_fail_closed() {
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
        policy_digest: Digest::hash(b"archive-source-confinement-fixture"),
    };
    let authorized =
        BTreeSet::from([odin_domain::knowledge::AtlasId::new("archive.mail").expect("source id")]);
    let knowledge = Some(odin_domain::knowledge::EffectiveKnowledgePolicy {
        required: false,
        atlas_sources: authorized,
        required_tags: BTreeSet::new(),
        denied_tags: BTreeSet::new(),
        allowed_trust: BTreeSet::from([odin_domain::knowledge::TrustClass::Observed]),
        retrieval_mode: odin_domain::knowledge::RetrievalMode::Lexical,
        candidate_limit: std::num::NonZeroU16::new(8).expect("candidate limit"),
        top_k: std::num::NonZeroU16::new(4).expect("top k"),
        min_score: odin_domain::knowledge::RelevanceScore::new(0).expect("min score"),
        chunk_tokens: std::num::NonZeroU32::new(256).expect("chunk tokens"),
        chunk_overlap_tokens: 32,
        embedding_backend: odin_domain::knowledge::EmbeddingBackend::Disabled,
    });
    let export = tempfile::NamedTempFile::new().expect("archive export fixture");
    let archive_source = |key: &str, namespace: &str| {
        (
            key.to_owned(),
            odin_huginn::config::OdindBrainSourceConfig {
                kind: "archive".to_owned(),
                privacy: None,
                root: None,
                port: None,
                expected_space_root: None,
                general_namespaces: Vec::new(),
                generated_namespace: None,
                excluded_namespaces: Vec::new(),
                max_pages: None,
                format: Some(odin_domain::knowledge::ArchiveFormat::Mbox),
                export_path: Some(export.path().to_path_buf()),
                memory_namespace: Some(namespace.to_owned()),
                privacy_class: Some(odin_domain::knowledge::ArchivePrivacyClass::Private),
                dedupe_key: Some(odin_domain::knowledge::ArchiveDedupeKey::ContentDigest),
                selection: Some(odin_domain::knowledge::ArchiveSelectionPolicy {
                    since: None,
                    exclude_labels: Vec::new(),
                    exclude_if_header: Vec::new(),
                    keep_if_participant: false,
                    participant_emails: Vec::new(),
                    suspicious_rules: Vec::new(),
                    exclude_do_not_remember: None,
                }),
            },
        )
    };
    let policies = BTreeMap::from([(
        odin_domain::SeatId::new("sinmara").expect("seat id"),
        policy(knowledge.clone()),
    )]);
    // The state-source authorities: the same real handles every other
    // composition test binds; the archive arm never touches them.
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
    let ledger = Arc::new(std::sync::Mutex::new(
        odin_ledger::Ledger::open_in_memory().unwrap(),
    ));
    let composed = brain_sources(
        &policies,
        &crate::projection::DeclaredBrainSources {
            sources: &BTreeMap::from([archive_source("archive.mail", "mail")]),
            project_roots: &BTreeMap::new(),
        },
        &registry_handle,
        &read_model,
        &task_reader,
        None,
        &ledger,
    )
    .expect("the authorized archive source composes");
    match composed.get(&odin_domain::knowledge::AtlasId::new("archive.mail").expect("source id")) {
        Some(odin_brain::service::BrainSourceConfig::Archive { declaration }) => {
            assert_eq!(declaration.memory_namespace, "mail");
            assert_eq!(
                declaration.format,
                odin_domain::knowledge::ArchiveFormat::Mbox
            );
        }
        other => panic!("expected the archive source config, got {other:?}"),
    }
    // Authorize both ids to isolate physical-root aliasing from authorization refusal.
    let mut alias_knowledge = knowledge;
    alias_knowledge
        .as_mut()
        .expect("knowledge policy fixture")
        .atlas_sources = BTreeSet::from([
        odin_domain::knowledge::AtlasId::new("archive.mail").expect("source id"),
        odin_domain::knowledge::AtlasId::new("archive.mail_copy").expect("source id"),
    ]);
    let alias_policies = BTreeMap::from([(
        odin_domain::SeatId::new("sinmara").expect("seat id"),
        policy(alias_knowledge),
    )]);
    let wired = BTreeMap::from([
        archive_source("archive.mail", "mail"),
        archive_source("archive.mail_copy", "mail-alias"),
    ]);
    let error = brain_sources(
        &alias_policies,
        &crate::projection::DeclaredBrainSources {
            sources: &wired,
            project_roots: &BTreeMap::new(),
        },
        &registry_handle,
        &read_model,
        &task_reader,
        None,
        &ledger,
    )
    .expect_err("aliased export roots must refuse");
    assert!(
        error.contains("one root is one source identity"),
        "unexpected error: {error}"
    );
}

/// The projection is the strict seam for the declared brain context
/// tokenizer: absent keeps the conservative byte-count default, the
/// declared qwen3 identity selects the pinned Qwen3 counter, and any other
/// declared value refuses startup pointing at the owning declaration.
#[test]
fn seat_model_descriptor_resolves_declared_tokenizer_strictly() {
    let serving = |tokenizer: Option<&str>| odin_huginn::OdindServingModelConfig {
        name: "test-model".to_owned(),
        context_window_tokens: std::num::NonZeroU32::new(8_192).expect("nonzero window"),
        tokenizer: tokenizer.map(str::to_owned),
    };

    let descriptor = seat_model_descriptor(&serving(None), "colin").expect("absent resolves");
    assert_eq!(
        descriptor.tokenizer,
        odin_brain::context::PinnedTokenizer::id().expect("pinned tokenizer")
    );

    let descriptor = seat_model_descriptor(
        &serving(Some(odin_brain::context::QWEN3_TOKENIZER_ID)),
        "colin",
    )
    .expect("the declared qwen3 identity resolves");
    assert_eq!(
        descriptor.tokenizer.as_str(),
        odin_brain::context::QWEN3_TOKENIZER_ID
    );

    let error = seat_model_descriptor(&serving(Some("other.vendor.model")), "colin")
        .expect_err("an unsupported declared tokenizer must refuse startup");
    assert!(
        error.contains("brain.serving_model.tokenizer"),
        "the error must point at the owning declaration seam: {error}"
    );

    let error = seat_model_descriptor(&serving(Some("not an id")), "colin")
        .expect_err("a malformed tokenizer identity must refuse startup");
    assert!(
        error.contains("not a valid tokenizer identity"),
        "unexpected error: {error}"
    );
}

/// Protocol changes must produce distinct embedding identities and invalidate existing generations.
#[test]
fn effective_embedding_model_composes_the_protocol_suffix() {
    use odin_registry::{EmbeddingFramingToml, EmbeddingProtocolToml, ResolvedProviderRoute};

    fn route(model: &str, protocol: Option<EmbeddingProtocolToml>) -> ResolvedProviderRoute {
        ResolvedProviderRoute {
            gateway_lane_id: "wemm-embedding".to_owned(),
            gateway_model_id: model.to_owned(),
            account_handle: "account".to_owned(),
            endpoint: "http://127.0.0.1:4000".to_owned(),
            credential_handle: "litellm-master-key".to_owned(),
            role: "embedding".to_owned(),
            affinity_key: "skuld".to_owned(),
            priority: 0,
            protocol,
        }
    }

    fn protocol() -> EmbeddingProtocolToml {
        EmbeddingProtocolToml {
            id: "wemm-im-user-v1".to_owned(),
            framing: EmbeddingFramingToml::ImUserV1,
            truncate_tokens: 256,
            l2_normalize: true,
        }
    }

    let model = effective_embedding_model(&route("wemm-embedding", Some(protocol())))
        .expect("the declared protocol composes");
    assert_eq!(
        model.as_str(),
        "wemm-embedding:wemm-im-user-v1",
        "the effective identity is wire model + protocol suffix"
    );

    let raw = effective_embedding_model(&route("wemm-embedding", None))
        .expect("the undeclared protocol keeps the raw wire model");
    assert_eq!(
        raw.as_str(),
        "wemm-embedding",
        "absent a declaration the identity is unsuffixed"
    );

    let error = effective_embedding_model(&route("openai/test-embedding", Some(protocol())))
        .expect_err("a composition outside the embedding model charset must refuse");
    assert!(
        error.contains("is not a valid embedding model id"),
        "the composition refusal must be typed: {error}"
    );
}

/// Watch only enabled, in-scope repositories at their host-provisioned roots.
#[test]
fn repository_state_watches_the_provisioned_project_root_never_a_registry_path() {
    let project = |id: &str, enabled: bool| {
        odin_registry::schema::parse_object_toml(
            odin_registry::RegistryKind::Project,
            id,
            format!("projects/{id}/project.toml"),
            &format!(
                "schema = \"odin.registry.v1\"\nkind = \"project\"\nenabled = {enabled}\n\
                 description = \"fixture\"\nsource_root = \"/home/colin/retired-checkout\"\n\
                 default_seat = \"gungnir\"\nmemory_namespaces = []\n\
                 artifact_policy = \"standard\"\n"
            ),
        )
        .expect("project declaration parses")
    };
    let objects = vec![
        project("odin", true),
        project("dotfiles", true),
        project("skuld", false),
        project("research", true),
    ];
    let objects = [objects, vec![project("life", true)]].concat();
    let in_scope: BTreeSet<odin_domain::ProjectId> = ["odin", "dotfiles", "skuld", "life"]
        .into_iter()
        .map(|id| odin_domain::ProjectId::new(id).expect("project id"))
        .collect();
    let roots = tempfile::tempdir().expect("roots");
    let dir = |name: &str, repository: bool| {
        let path = roots.path().join(name);
        fs::create_dir_all(if repository {
            path.join(".git")
        } else {
            path.clone()
        })
        .expect("root");
        odin_huginn::config::OdindProjectConfig {
            root: path,
            runtime: false,
        }
    };
    let project_roots = BTreeMap::from([
        ("odin".to_owned(), dir("odin", true)),
        ("skuld".to_owned(), dir("skuld", true)),
        ("research".to_owned(), dir("research", true)),
        ("life".to_owned(), dir("vault", false)),
    ]);
    let watched = crate::projection::declared_repo_roots(&objects, &in_scope, &project_roots)
        .expect("roots derive");
    assert_eq!(
        watched,
        BTreeMap::from([(
            odin_domain::ProjectId::new("odin").expect("project id"),
            roots.path().join("odin"),
        )])
    );
}

#[test]
fn an_unservable_workload_is_skipped_by_the_daemon_and_refused_by_check() {
    use crate::live::workload::{
        retain_servable_with, validate_workload_routes, WorkloadComposition, WorkloadModelPolicy,
    };
    let config = odin_huginn::OdindConfig::parse(&format!(
        "schema = 'odin.odind-config.v1'\nrevision = 1\nworker_bus = 'unix:/tmp/bus.sock'\n[identity]\nnode = 'mini'\n[paths]\nregistry_root = '/'\nstate_root = '/'\nregistry_snapshot = '/'\nauthority_token_root = '/'\nauthority_verification_key_file = '/'\n[listener]\naddress = '127.0.0.1:18420'\n[executables]\nomp_bin = '/omp'\nomp_revision = '{}'\nextension = '/ext.ts'\nzellij_bin = '/zellij'\nzellij_session = 'odin'\n[catalogs.gateway_projection]\npath = '/p.json'\ndigest = 'blake3:{}'\n[publish]\nrender_session = '00000000-0000-4000-8000-0000000000aa'\nfile_lane = 'f'\nrender_lane = 'r'\n[capacity]\n",
        "a".repeat(40),
        "c".repeat(64)
    ))
    .expect("minimal config");
    let projection = gateway_projection(vec![gateway_route(
        "lane.other",
        "model.y",
        "https://gateway.internal:4000/v1",
        true,
    )]);
    let lane = odin_domain::LaneId::new("gungnir-skuld").unwrap();
    let mut composition = WorkloadComposition {
        laws: Default::default(),
        models: [(
            "digest".to_owned(),
            WorkloadModelPolicy::Exact {
                provider: "gateway".to_owned(),
                model: "glm-flash".to_owned(),
            },
        )]
        .into(),
        bindings: [(
            "digest".to_owned(),
            (
                odin_domain::SliceId::new("gungnir-build").unwrap(),
                lane,
                odin_domain::NodeId::new("mini").unwrap(),
            ),
        )]
        .into(),
        skipped: Default::default(),
    };
    assert!(validate_workload_routes(&config, &projection, &composition).is_err());
    retain_servable_with(&config, &projection, &mut composition);
    assert!(composition.models.is_empty() && composition.bindings.is_empty());
    let reason = composition
        .skipped
        .get("digest")
        .expect("skipped with its reason");
    assert!(reason.contains("carries no route"), "{reason}");
}

#[test]
fn a_runtime_lane_workload_derives_its_credential_from_the_pinned_carrier() {
    use super::workload_gateway_credential;
    let mut carrier = gateway_route("glm-flash", "glm-flash", "http://127.0.0.1:4000/v1", true);
    carrier.credential_handle = "litellm-master-key".to_owned();
    let projection = gateway_projection(vec![carrier]);
    assert_eq!(
        workload_gateway_credential(&projection, "gungnir-skuld", "glm-flash").unwrap(),
        "litellm-master-key"
    );
    assert!(workload_gateway_credential(&projection, "gungnir-skuld", "zai-glm").is_err());
    let mut dead = gateway_route("glm-flash", "glm-flash", "http://127.0.0.1:4000/v1", false);
    dead.credential_handle = "x".to_owned();
    let projection = gateway_projection(vec![dead]);
    assert!(workload_gateway_credential(&projection, "gungnir-skuld", "glm-flash").is_err());
}

#[test]
fn a_restricted_project_withholds_every_memory_namespace_it_declares() {
    use odin_domain::knowledge::{AtlasId, PrivacyClass};
    let project =
        |id: &str, namespace: &str, privacy: Option<PrivacyClass>| odin_registry::RegistryObject {
            id: id.to_owned(),
            relative_config: format!("projects/{id}/project.toml").into(),
            config: odin_registry::ObjectConfig::Project(Box::new(
                odin_registry::schema::ProjectToml {
                    schema: odin_registry::schema::REGISTRY_SCHEMA.to_owned(),
                    kind: odin_registry::schema::RegistryKind::Project,
                    enabled: true,
                    description: "fixture".to_owned(),
                    source_root: "/tmp".to_owned(),
                    default_seat: odin_domain::SeatId::new("sinmara").unwrap(),
                    memory_namespaces: [AtlasId::new(namespace).unwrap()].into(),
                    artifact_policy: "standard".to_owned(),
                    privacy,
                    accounts: Default::default(),
                    review_verdict: None,
                },
            )),
        };
    let objects = vec![
        project("apl", "atlas.apl", Some(PrivacyClass::AplRestricted)),
        project("life", "atlas.personal", Some(PrivacyClass::Personal)),
    ];
    let apl = AtlasId::new("atlas.apl").unwrap();
    let personal = AtlasId::new("atlas.personal").unwrap();
    assert_eq!(
        crate::projection::withheld_class(&apl, None, &objects),
        Some(PrivacyClass::AplRestricted)
    );
    assert_eq!(
        crate::projection::withheld_class(&personal, None, &objects),
        None
    );
    // The strictest declaration wins: a SECRET source under a personal
    // project is withheld.
    assert_eq!(
        crate::projection::withheld_class(&personal, Some(PrivacyClass::Secret), &objects),
        Some(PrivacyClass::Secret)
    );
}
