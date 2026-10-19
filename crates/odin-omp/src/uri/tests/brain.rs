//! Brain authority invariants: per-seat policies, typed unavailability, pinned snapshots.

use super::*;

fn brain_context(ledger: &Arc<Mutex<Ledger>>, seat: &str, project: &str) -> UriContext {
    let session = format!("brain-{seat}-{project}");
    let lane = format!("lane-{session}");
    let run = format!("run-{session}");
    let now = time::OffsetDateTime::UNIX_EPOCH;
    let mut ledger = ledger.lock().unwrap();
    lane_run::create_lane(
        ledger.connection(),
        &NewLane {
            lane_id: lane.parse().unwrap(),
            seat_id: seat.parse().unwrap(),
            project_id: Some(project.parse().unwrap()),
            template_id: "fixture".into(),
            backend: "local_omp".into(),
            created_by: "fixture".into(),
            created_at: now,
            retained: false,
        },
    )
    .unwrap();
    lane_run::create_run(
        ledger.connection(),
        &NewRun {
            run_id: run.parse().unwrap(),
            lane_id: lane.parse().unwrap(),
            attempt_number: 1,
            workflow_id: None,
            workflow_version: None,
            input_hash: "fixture".into(),
            accepted_capability_revision: None,
            lease_id: None,
            absolute_deadline: None,
            retry_budget: 0,
            created_at: now,
        },
    )
    .unwrap();
    let record = ledger
        .create_live_session(&odin_ledger::live::NewLiveSession {
            session_id: session.parse().unwrap(),
            seat_id: seat.into(),
            project_id: project.into(),
            slice_id: "slice-fixture".into(),
            lane_id: lane.clone(),
            target_node_id: "node-fixture".into(),
            provider: "fixture".into(),
            model: "fixture".into(),
            title: None,
            manifest: json!({}),
            open_tab: false,
            state: "ready".into(),
            created_at: now,
        })
        .unwrap();
    let scope = Scope {
        seat: Some(seat.parse().unwrap()),
        project: Some(project.parse().unwrap()),
        session: Some(session.parse().unwrap()),
        lane: Some(lane.parse().unwrap()),
        run: Some(run.parse().unwrap()),
        ..Scope::default()
    };
    let mut binding = crate::bridge::BridgeBinding::new(
        scope.clone(),
        session.parse().unwrap(),
        run.parse().unwrap(),
        lane.parse().unwrap(),
        "fixture",
    );
    binding.epoch = record.epoch;
    UriContext::with_execution(scope, ExecutionBinding::from_binding(&binding))
}

#[test]
fn brain_resolves_through_injected_service() {
    let ledger = seeded_ledger();
    let seated = brain_context(&ledger, "seat-alpha", "project-alpha");
    let router = test_router(ledger, artifact_root("brain-resolution"));
    // brain:// selects the service by the authenticated session scope's
    // seat, so the context carries the served seat explicitly.
    // The bare URI pins the live brain authority snapshot.
    let snapshot = router.resolve(&seated, "brain://").unwrap();
    assert_eq!(snapshot.content_type, JSON_CONTENT_TYPE);
    assert!(snapshot.immutable);
    let value = spot_json(&snapshot);
    assert_eq!(value["authority"], "brain");
    assert!(value["policyDigest"].is_string());
    assert!(value["registryRevision"].is_u64());
    assert!(value["pinned"].is_object());
    assert!(value["pinned"]["atlas:uri-test"].is_string());
    // A non-canonical identifier is rejected by the grammar before any
    // resolver or storage runs.
    let miss = router
        .resolve(&seated, "brain://context-bundle-alpha")
        .unwrap_err();
    assert!(
        matches!(miss, UriError::Malformed { .. }),
        "non-canonical brain ids must fail grammar validation: {miss:?}"
    );
    // With empty stores a canonical, well-formed identifier is a typed miss:
    // no current generation serves it, and stale data is never substituted.
    let miss = router
        .resolve(
            &seated,
            "brain://blake3:0000000000000000000000000000000000000000000000000000000000000000",
        )
        .unwrap_err();
    assert!(
        matches!(miss, UriError::UnknownResource { .. }),
        "a well-formed absent item must be a typed miss: {miss:?}"
    );
    // Escaped and non-canonical identifiers never reach the service.
    assert!(matches!(
        ScopedUriRouter::parse("brain://-bundle"),
        Err(UriError::Malformed { .. })
    ));
    assert_eq!(
        ScopedUriRouter::parse("brain://item%41").unwrap_err(),
        UriError::EncodedBytesRejected {
            url: "brain://item%41".to_owned(),
        }
    );
}
/// Seat policies isolate wired sources; lexical retrieval needs no embeddings backend.
#[test]
fn brain_serves_each_seat_its_own_policy_and_sources_only() {
    let ledger = seeded_ledger();
    let root = artifact_root("brain-per-seat");
    let source_tree = |name: &str| {
        let src = root.join(name).join("atlas-src/crates/demo/src");
        std::fs::create_dir_all(&src).unwrap();
        std::fs::write(src.join("lib.rs"), "//! Demo.\npub fn demo() {}\n").unwrap();
        for class in ["extension", "registry", "skeletons"] {
            std::fs::create_dir_all(root.join(name).join("atlas-src").join(class)).unwrap();
        }
        root.join(name).join("atlas-src")
    };
    let personal_root = source_tree("personal");
    let code_root = source_tree("code");
    let model = ModelDescriptor {
        name: ModelName::new("model.uri-test").unwrap(),
        tokenizer: TokenizerId::new("odin.tokenizer.utf8-bytes.v1").unwrap(),
        context_window_tokens: nz32(8192),
    };
    // The slice is the delegation ceiling: it delegates the sources a
    // seat may narrow to, and each seat narrows that delegation with
    // its own brain_scope and seat knowledge. The personal/code
    // delegates are disjoint, so the two published policies must
    // differ; a scope naming ids the slice never delegates would
    // collapse to the empty set, not widen.
    let slice_delegating = |sources: &[&str]| {
        let mut slice = test_slice();
        if let Some(knowledge) = slice.knowledge.as_mut() {
            knowledge.atlas_sources = atlas_ids(sources);
        }
        slice
    };
    let seat_with_scope = |sources: &[&str]| {
        let mut seat = test_seat();
        seat.brain_scope = atlas_ids(sources);
        if let Some(knowledge) = seat.knowledge.as_mut() {
            knowledge.atlas_sources = atlas_ids(sources);
        }
        seat
    };
    let personal_id = AtlasId::new("atlas:personal").unwrap();
    let code_id = AtlasId::new("atlas:code").unwrap();
    // Each seat authorizes exactly the disjoint source set its slice
    // delegates and its real roots serve: the composition validator
    // refuses authorizing-unwired identities, so published policies
    // and wired sources match exactly.
    let sinmara_policy = EffectiveBrainPolicy::resolve(
        74,
        &slice_delegating(&["atlas:personal"]),
        &seat_with_scope(&["atlas:personal"]),
        &BTreeMap::new(),
        &std::collections::BTreeMap::from([(
            "sized",
            &odin_registry::ContextProfileToml::sized(
                std::num::NonZeroU32::new(2048).unwrap(),
                std::num::NonZeroU32::new(6144).unwrap(),
            ),
        )]),
        &model,
    )
    .unwrap();
    let architect_policy = EffectiveBrainPolicy::resolve(
        74,
        &slice_delegating(&["atlas:code"]),
        &seat_with_scope(&["atlas:code"]),
        &BTreeMap::new(),
        &std::collections::BTreeMap::from([(
            "sized",
            &odin_registry::ContextProfileToml::sized(
                std::num::NonZeroU32::new(2048).unwrap(),
                std::num::NonZeroU32::new(6144).unwrap(),
            ),
        )]),
        &model,
    )
    .unwrap();
    assert_ne!(
        sinmara_policy.policy_digest, architect_policy.policy_digest,
        "distinct seat scopes must yield distinct published policies"
    );
    let personal_service = {
        let config = BrainServiceConfig {
            store_root: root.join("brain-store-sinmara"),
            sources: BTreeMap::from([(
                personal_id.clone(),
                BrainSourceConfig::Atlas {
                    root: personal_root,
                },
            )]),
            embedding_available: false,
            embedding_model: None,
            archive_ingest_gate: None,
            postgres: None,
        };
        Arc::new(BrainService::open(config, sinmara_policy.clone(), ledger.clone()).unwrap())
    };
    let code_service = {
        let config = BrainServiceConfig {
            store_root: root.join("brain-store-architect"),
            sources: BTreeMap::from([(
                code_id.clone(),
                BrainSourceConfig::Atlas { root: code_root },
            )]),
            embedding_available: false,
            embedding_model: None,
            archive_ingest_gate: None,
            postgres: None,
        };
        Arc::new(BrainService::open(config, architect_policy, ledger.clone()).unwrap())
    };
    let router = ScopedUriRouter::new(
        Arc::clone(&ledger),
        Arc::new(test_atlas()),
        allowed_atlas_scope(),
        root,
        MAX_TEST_ARTIFACT_BYTES,
        BTreeMap::from([
            (SeatId::new("sinmara").unwrap(), personal_service),
            (SeatId::new("architect").unwrap(), code_service),
        ]),
    )
    .unwrap();
    let pinned = |seat: &str| {
        let snapshot = router
            .resolve(&brain_context(&ledger, seat, "project-alpha"), "brain://")
            .expect("seat-served brain authority snapshot");
        let value = spot_json(&snapshot);
        value["pinned"].as_object().expect("pinned map").clone()
    };
    // Sinmara pins exactly its authorized-and-wired source; the
    // disjoint delegation keeps research absent — never widened,
    // never a phantom root.
    let sinmara_pinned = pinned("sinmara");
    assert!(sinmara_pinned.contains_key("atlas:personal"));
    assert!(!sinmara_pinned.contains_key("atlas:research"));
    // Cross-seat isolation: architect never sees sinmara's source.
    let architect_pinned = pinned("architect");
    assert!(architect_pinned.contains_key("atlas:code"));
    assert!(!architect_pinned.contains_key("atlas:personal"));
    // A seat that serves no brain fails typed while the served seats
    // keep resolving, and so does a scope that binds no seat at all.
    for seat in [None, Some("kubert")] {
        let context = match seat {
            Some(seat) => brain_context(&ledger, seat, "project-alpha"),
            None => UriContext::new(Scope::default()),
        };
        let error = router.resolve(&context, "brain://").unwrap_err();
        assert!(
            matches!(
                error,
                UriError::ConfigurationRejected { .. } | UriError::ExecutionProof { .. }
            ),
            "unserved seat brain:// must be typed-unavailable: {error:?}"
        );
    }
}

/// A deployment without a brain service still resolves every unrelated
/// scheme; `brain://` alone fails typed-unavailable instead of hitting a
/// fabricated service.
#[test]
fn router_without_brain_serves_other_schemes_and_rejects_brain_typed() {
    let ledger = seeded_ledger();
    let root = artifact_root("brain-unconfigured");
    let router = ScopedUriRouter::new(
        Arc::clone(&ledger),
        Arc::new(test_atlas()),
        allowed_atlas_scope(),
        root,
        MAX_TEST_ARTIFACT_BYTES,
        BTreeMap::new(),
    )
    .unwrap();
    let global = UriContext::new(Scope::default());

    let context = brain_context(&ledger, "seat-alpha", "project-alpha");
    let error = router.resolve(&context, "brain://").unwrap_err();
    assert!(
        matches!(error, UriError::ConfigurationRejected { .. }),
        "brain:// without a brain service must be typed-unavailable: {error:?}"
    );

    // Unrelated schemes keep their full resolver surface.
    let atlas_snapshot = router.resolve(&global, "atlas://").unwrap();
    assert_eq!(atlas_snapshot.content_type, JSON_CONTENT_TYPE);
}

/// Project intersection on the URI leg of D2: one seat, two declared
/// projects with disjoint private namespaces, and one seat-general
/// source no project declares. The same indexed item resolves through
/// `brain://` only under a scope bound to the declaring project — the
/// other project's scope and a projectless scope get the typed miss,
/// exactly as if the item did not exist — while the general item
/// resolves under every scope. No default project exists anywhere on
/// this path.
#[test]
fn brain_item_resolution_stays_inside_the_bound_projects_memory() {
    let ledger = seeded_ledger();
    let root = artifact_root("brain-project-scope");
    let source_tree = |name: &str, marker_fn: &str| {
        let atlas_root = root.join(name).join("atlas-src");
        let src = atlas_root.join("crates/demo/src");
        std::fs::create_dir_all(&src).unwrap();
        std::fs::write(
            src.join("lib.rs"),
            format!("//! Demo crate.\n\n/// Marker.\npub fn {marker_fn}() -> u64 {{ 1 }}\n"),
        )
        .unwrap();
        for class in ["extension", "registry", "skeletons"] {
            std::fs::create_dir_all(atlas_root.join(class)).unwrap();
        }
        atlas_root
    };
    let alpha_root = source_tree("alpha", "alpha_scope_fn");
    let beta_root = source_tree("beta", "beta_scope_fn");
    let general_root = source_tree("general", "general_scope_fn");
    let (alpha_id, beta_id, general_id) = (
        AtlasId::new("atlas:scope-alpha").unwrap(),
        AtlasId::new("atlas:scope-beta").unwrap(),
        AtlasId::new("atlas:scope-general").unwrap(),
    );
    let sources = atlas_ids(&[alpha_id.as_str(), beta_id.as_str(), general_id.as_str()]);
    let model = ModelDescriptor {
        name: ModelName::new("model.uri-test").unwrap(),
        tokenizer: TokenizerId::new("odin.tokenizer.utf8-bytes.v1").unwrap(),
        context_window_tokens: nz32(8192),
    };
    let mut slice = test_slice();
    let slice_knowledge = slice.knowledge.as_mut().unwrap();
    slice_knowledge.atlas_sources = sources.clone();
    slice_knowledge.retrieval_mode = odin_domain::knowledge::RetrievalMode::Lexical;
    let mut seat = test_seat();
    seat.brain_scope = sources.clone();
    seat.knowledge.as_mut().unwrap().atlas_sources = sources.clone();
    seat.project_scope = BTreeSet::from([
        odin_domain::ProjectId::new("alpha").unwrap(),
        odin_domain::ProjectId::new("beta").unwrap(),
    ]);
    let project = |namespaces: &[AtlasId]| odin_registry::schema::ProjectToml {
        schema: REGISTRY_SCHEMA.to_owned(),
        kind: RegistryKind::Project,
        enabled: true,
        description: "uri scope fixture project".to_owned(),
        source_root: String::new(),
        default_seat: odin_domain::SeatId::new("sinmara").unwrap(),
        memory_namespaces: namespaces.iter().cloned().collect(),
        artifact_policy: "standard".to_owned(),
        privacy: None,
        accounts: Default::default(),
        review_verdict: None,
    };
    let alpha = project(std::slice::from_ref(&alpha_id));
    let beta = project(std::slice::from_ref(&beta_id));
    let policy = EffectiveBrainPolicy::resolve(
        74,
        &slice,
        &seat,
        &BTreeMap::from([("alpha", &alpha), ("beta", &beta)]),
        &std::collections::BTreeMap::from([(
            "sized",
            &odin_registry::ContextProfileToml::sized(
                std::num::NonZeroU32::new(2048).unwrap(),
                std::num::NonZeroU32::new(6144).unwrap(),
            ),
        )]),
        &model,
    )
    .unwrap();
    assert_eq!(
        policy.seat_global_sources,
        atlas_ids(&[general_id.as_str()]),
        "only the undeclared source stays seat-general"
    );
    let service = {
        let config = BrainServiceConfig {
            store_root: root.join("brain-store"),
            sources: BTreeMap::from([
                (
                    alpha_id.clone(),
                    BrainSourceConfig::Atlas { root: alpha_root },
                ),
                (
                    beta_id.clone(),
                    BrainSourceConfig::Atlas { root: beta_root },
                ),
                (
                    general_id.clone(),
                    BrainSourceConfig::Atlas { root: general_root },
                ),
            ]),
            embedding_available: false,
            embedding_model: None,
            archive_ingest_gate: None,
            postgres: None,
        };
        let service = BrainService::open(config, policy, ledger.clone()).unwrap();
        service.ensure_generation().unwrap();
        service
    };
    let service = Arc::new(service);
    let router = ScopedUriRouter::new(
        Arc::clone(&ledger),
        Arc::new(test_atlas()),
        allowed_atlas_scope(),
        root,
        MAX_TEST_ARTIFACT_BYTES,
        BTreeMap::from([(SeatId::new("sinmara").unwrap(), Arc::clone(&service))]),
    )
    .unwrap();
    let item_id_of = |marker: &str,
                      needle_sources: &BTreeSet<AtlasId>,
                      project: Option<&odin_domain::ProjectId>| {
        service
            .retrieve(
                &odin_domain::knowledge::retrieval::RetrievalQuery::new(
                    marker.to_owned(),
                    needle_sources.clone(),
                    BTreeSet::new(),
                    BTreeSet::new(),
                    [
                        odin_domain::knowledge::retrieval::TrustClass::Curated,
                        odin_domain::knowledge::retrieval::TrustClass::Observed,
                        odin_domain::knowledge::retrieval::TrustClass::Untrusted,
                    ]
                    .into_iter()
                    .collect(),
                    nz16(64),
                    nz16(8),
                    odin_domain::knowledge::RelevanceScore::new(0).unwrap(),
                )
                .unwrap(),
                project,
                None,
            )
            .unwrap()
            .hits
            .into_iter()
            .find(|hit| hit.content.contains(marker))
            .map(|hit| hit.item_id)
            .unwrap_or_else(|| panic!("the {marker} fixture must index and retrieve"))
    };
    let alpha_item = item_id_of(
        "alpha_scope_fn",
        &sources,
        Some(&odin_domain::ProjectId::new("alpha").unwrap()),
    );
    let beta_item = item_id_of(
        "beta_scope_fn",
        &sources,
        Some(&odin_domain::ProjectId::new("beta").unwrap()),
    );
    let general_item = item_id_of("general_scope_fn", &sources, None);
    let scope_of = |project: &str| brain_context(&ledger, "sinmara", project);
    let resolves = |context: &UriContext, item: &odin_domain::knowledge::KnowledgeItemId| {
        router
            .resolve(context, &format!("brain://{item}"))
            .map(|snapshot| spot_json(&snapshot).clone())
    };
    let alpha_scope = scope_of("alpha");
    let beta_scope = scope_of("beta");
    let projectless = UriContext::new(Scope {
        seat: Some("sinmara".parse().unwrap()),
        ..Scope::default()
    });
    assert!(
        resolves(&alpha_scope, &alpha_item).is_ok() && resolves(&beta_scope, &beta_item).is_ok(),
        "each project resolves its own declared memory"
    );
    let error = resolves(&beta_scope, &alpha_item).unwrap_err();
    assert!(
        matches!(error, UriError::UnknownResource { .. }),
        "alpha's item must be a typed miss under beta scope: {error:?}"
    );
    let error = resolves(&alpha_scope, &beta_item).unwrap_err();
    assert!(
        matches!(error, UriError::UnknownResource { .. }),
        "beta's item must be a typed miss under alpha scope: {error:?}"
    );
    for (context, label) in [(&alpha_scope, "alpha"), (&beta_scope, "beta")] {
        assert!(
            resolves(context, &general_item).is_ok(),
            "seat-general knowledge serves every session of the seat ({label})"
        );
    }
    assert!(matches!(
        resolves(&projectless, &general_item),
        Err(UriError::ExecutionProof { .. })
    ));
}

/// A brain URI read is BOUNDED and PAGEABLE end to end: one indexed item
/// larger than the default page is read across pages whose concatenation is
/// exactly the item's bytes — dense multi-byte scalars included — with
/// explicit continuation selectors, and every non-canonical window is refused
/// rather than clamped or silently shortened.
#[test]
fn brain_item_reads_are_paged_and_exact() {
    use odin_brain::service::{
        archive_declaration_digest, ArchiveIngestAuthority, ArchiveIngestGate, ArchiveIngestRequest,
    };
    use odin_domain::knowledge::archive::{
        ArchiveDedupeKey, ArchiveFormat, ArchivePrivacyClass, ArchiveSelectionPolicy,
        ArchiveSourceDeclaration,
    };
    use odin_domain::knowledge::retrieval::{RetrievalQuery, TrustClass};

    /// The fixture gate: this test exercises the read path, not admission.
    struct TestGate;
    impl ArchiveIngestGate for TestGate {
        fn verify(
            &self,
            _authority: &ArchiveIngestAuthority,
            source: &AtlasId,
            _idempotency_key: &str,
        ) -> odin_brain::error::BrainResult<()> {
            assert!(!source.as_str().is_empty());
            Ok(())
        }
    }

    let unit = "漢字🙂é";
    // One archive message far past the default page; the marker scalar
    // sequence makes any lost or duplicated byte between pages visible.
    let message = format!("{}{}", unit.repeat(6_000), "PAGE-TAIL-MARKER");
    let root = artifact_root("brain-pages");
    let export_dir = root.join("export");
    std::fs::create_dir_all(&export_dir).unwrap();
    let export = serde_json::json!([{
        "uuid": "conv-pages",
        "name": "Paged fixture",
        "account": { "uuid": "account-pages" },
        "created_at": "2026-01-01T00:00:00Z",
        "chat_messages": [{
            "uuid": "msg-pages",
            "sender": "assistant",
            "text": message,
            "created_at": "2026-01-02T00:00:00Z",
            // Metadata only — the export ships no asset bytes, so the
            // locator must name the declaration site and position while
            // claiming no member.
            "attachments": [{
                "file_name": "pages-origin.md",
                "file_size": "7",
                "file_type": "text/markdown"
            }],
        }],
    }]);
    std::fs::write(
        export_dir.join("conversations.json"),
        serde_json::to_string(&export).unwrap(),
    )
    .unwrap();
    let source = AtlasId::new("archive:pages").unwrap();
    let declaration = ArchiveSourceDeclaration {
        format: ArchiveFormat::ClaudeExport,
        path: export_dir.clone(),
        memory_namespace: "memory.pages".to_owned(),
        privacy_class: ArchivePrivacyClass::Private,
        dedupe_key: ArchiveDedupeKey::ContentDigest,
        selection: ArchiveSelectionPolicy {
            since: None,
            exclude_labels: Vec::new(),
            exclude_if_header: Vec::new(),
            keep_if_participant: false,
            participant_emails: Vec::new(),
            suspicious_rules: Vec::new(),
            exclude_do_not_remember: None,
        },
    };
    let sources = atlas_ids(&[source.as_str()]);
    let model = ModelDescriptor {
        name: ModelName::new("model.uri-pages").unwrap(),
        tokenizer: TokenizerId::new("odin.tokenizer.utf8-bytes.v1").unwrap(),
        context_window_tokens: nz32(8192),
    };
    let mut slice = test_slice();
    let slice_knowledge = slice.knowledge.as_mut().unwrap();
    slice_knowledge.atlas_sources = sources.clone();
    slice_knowledge.retrieval_mode = odin_domain::knowledge::RetrievalMode::Lexical;
    slice_knowledge.embedding_backend = odin_domain::knowledge::EmbeddingBackend::Disabled;
    let mut seat = test_seat();
    seat.brain_scope = sources.clone();
    seat.knowledge.as_mut().unwrap().atlas_sources = sources.clone();
    let policy = EffectiveBrainPolicy::resolve(
        74,
        &slice,
        &seat,
        &BTreeMap::new(),
        &std::collections::BTreeMap::from([(
            "sized",
            &odin_registry::ContextProfileToml::sized(
                std::num::NonZeroU32::new(2048).unwrap(),
                std::num::NonZeroU32::new(6144).unwrap(),
            ),
        )]),
        &model,
    )
    .unwrap();
    let ledger = seeded_ledger();
    let router_ledger = Arc::clone(&ledger);
    let service = Arc::new(
        BrainService::open(
            BrainServiceConfig {
                store_root: root.join("brain-store"),
                sources: BTreeMap::from([(
                    source.clone(),
                    BrainSourceConfig::Archive {
                        declaration: declaration.clone(),
                    },
                )]),
                embedding_available: false,
                embedding_model: None,
                archive_ingest_gate: Some(Arc::new(TestGate)),
                postgres: None,
            },
            policy,
            ledger.clone(),
        )
        .unwrap(),
    );
    let plan = service.prepare_archive_ingest(&source).unwrap();
    service
        .ingest_archive(&ArchiveIngestRequest {
            source: source.clone(),
            declaration: declaration.clone(),
            approval: ArchiveIngestAuthority {
                demand_id: "demand-pages".to_owned(),
                approval_id: "approval-pages".to_owned(),
                command_id: "command-pages".to_owned(),
                declaration_digest: archive_declaration_digest(&declaration).unwrap(),
                content_revision: plan.content_revision,
            },
            idempotency_key: "pages".to_owned(),
            deadline: None,
        })
        .unwrap();
    let hits = service
        .retrieve(
            &RetrievalQuery::new(
                "PAGE-TAIL-MARKER".to_owned(),
                sources.clone(),
                BTreeSet::new(),
                BTreeSet::new(),
                [
                    TrustClass::Curated,
                    TrustClass::Observed,
                    TrustClass::Untrusted,
                ]
                .into_iter()
                .collect(),
                nz16(64),
                nz16(64),
                odin_domain::knowledge::RelevanceScore::new(0).unwrap(),
            )
            .unwrap(),
            None,
            None,
        )
        .unwrap()
        .hits;
    // The MESSAGE record, not the derived conversation summary the parser
    // also emits for the same fixture.
    let item_id = hits
        .iter()
        .find(|hit| {
            service
                .archive_citation(
                    &hit.citation.source,
                    &hit.citation.source_revision,
                    &hit.citation.item_id,
                )
                .unwrap()
                .is_some_and(|citation| citation.message_id.as_deref() == Some("msg-pages"))
        })
        .map(|hit| hit.item_id)
        .expect("the archived pageable message must serve");
    let router = ScopedUriRouter::new(
        router_ledger,
        Arc::new(test_atlas()),
        allowed_atlas_scope(),
        root,
        MAX_TEST_ARTIFACT_BYTES,
        BTreeMap::from([(SeatId::new("seat-alpha").unwrap(), Arc::clone(&service))]),
    )
    .unwrap();
    // Seed session, lane, and run through the same ledger paths as the bridge.
    let proof_lane: odin_domain::LaneId = "lane-proof".parse().unwrap();
    let proof_run: odin_domain::RunId = "run-proof".parse().unwrap();
    let proof_session: odin_domain::SessionId =
        "7b1f2c3d-4e5f-4a6b-8c9d-0e1f2a3b4c5d".parse().unwrap();
    {
        let guard = ledger.lock().unwrap();
        let conn = guard.connection();
        odin_ledger::lane_run::create_lane(
            conn,
            &odin_ledger::lane_run::NewLane {
                lane_id: proof_lane.clone(),
                seat_id: "seat-alpha".parse().unwrap(),
                project_id: Some("project-alpha".parse().unwrap()),
                template_id: "default".to_owned(),
                backend: "local_omp".to_owned(),
                created_by: "uri-test".to_owned(),
                created_at: time::OffsetDateTime::UNIX_EPOCH,
                retained: false,
            },
        )
        .unwrap();
        odin_ledger::lane_run::create_run(
            conn,
            &odin_ledger::lane_run::NewRun {
                run_id: proof_run.clone(),
                lane_id: proof_lane.clone(),
                attempt_number: 1,
                workflow_id: Some("uri-test".to_owned()),
                workflow_version: Some(1),
                input_hash: Digest::hash(b"uri-test-manifest").to_string(),
                accepted_capability_revision: None,
                lease_id: None,
                absolute_deadline: None,
                retry_budget: 0,
                created_at: time::OffsetDateTime::UNIX_EPOCH,
            },
        )
        .unwrap();
    }
    // The live session row is written last: its lane is a foreign key.
    ledger
        .lock()
        .unwrap()
        .create_live_session(&odin_ledger::live::NewLiveSession {
            session_id: proof_session.clone(),
            seat_id: "seat-alpha".to_owned(),
            project_id: "project-alpha".to_owned(),
            slice_id: "sinmara-life".to_owned(),
            lane_id: proof_lane.to_string(),
            target_node_id: "laptop".to_owned(),
            provider: "gateway".to_owned(),
            model: "deepseek-chat".to_owned(),
            title: None,
            manifest: serde_json::json!({}),
            open_tab: false,
            state: "ready".to_owned(),
            created_at: time::OffsetDateTime::UNIX_EPOCH,
        })
        .unwrap();
    let proof_epoch = ledger
        .lock()
        .unwrap()
        .live_session(&proof_session)
        .unwrap()
        .epoch;
    let proof_scope = odin_domain::Scope {
        seat: Some("seat-alpha".parse().unwrap()),
        project: Some("project-alpha".parse().unwrap()),
        lane: Some(proof_lane.clone()),
        run: Some(proof_run.clone()),
        session: Some(proof_session.clone()),
        ..odin_domain::Scope::default()
    };
    let proof_for = |scope: &odin_domain::Scope,
                     session: odin_domain::SessionId,
                     run: odin_domain::RunId,
                     lane: odin_domain::LaneId,
                     epoch: i64| {
        let mut binding =
            crate::bridge::BridgeBinding::new(scope.clone(), session, run, lane, "uri-test");
        binding.epoch = epoch;
        UriContext::with_execution(
            scope.clone(),
            crate::uri::ExecutionBinding::from_binding(&binding),
        )
    };
    let authorized = proof_for(
        &proof_scope,
        proof_session.clone(),
        proof_run.clone(),
        proof_lane.clone(),
        proof_epoch,
    );
    let page = router
        .resolve(&authorized, &format!("brain://{item_id}"))
        .unwrap();
    let value = spot_json(&page);
    assert_eq!(value["itemId"], item_id.to_string());
    assert_eq!(
        value["page"]["byteStart"], 0,
        "the authenticated execution proof must not change which page is served"
    );
    // The consumer seam — the served wire payload itself, not just the
    // service struct: the message window carries the declared export
    // root and stays origin-less (its record has no asset identity).
    assert_eq!(
        value["archive"]["exportRoot"].as_str(),
        export_dir.to_str(),
        "exportRoot is the persisted declaration's exact path"
    );
    assert!(value["archive"]["origin"].is_null());
    assert!(
        value["archive"]["naturalKey"].is_string(),
        "the payload names its record's natural key"
    );

    // The attachment's own record page carries the locator on the wire:
    // declaration site + position, member=null (bytes not exported),
    // against the same root — resolved through the real record selector.
    let asset_hits = service
        .retrieve(
            &RetrievalQuery::new(
                "pages-origin markdown".to_owned(),
                sources.clone(),
                BTreeSet::new(),
                BTreeSet::new(),
                [
                    TrustClass::Curated,
                    TrustClass::Observed,
                    TrustClass::Untrusted,
                ]
                .into_iter()
                .collect(),
                nz16(64),
                nz16(64),
                odin_domain::knowledge::RelevanceScore::new(0).unwrap(),
            )
            .unwrap(),
            None,
            None,
        )
        .unwrap()
        .hits;
    let asset_item_id = asset_hits
        .iter()
        .find_map(|hit| {
            let citation = service
                .archive_citation(
                    &hit.citation.source,
                    &hit.citation.source_revision,
                    &hit.citation.item_id,
                )
                .unwrap()?;
            (citation.kind == odin_brain::source::archive::ArchiveRecordKind::AssetMetadata)
                .then_some(hit.item_id)
        })
        .expect("the attachment metadata record must serve");
    let record_page = router
        .resolve(&authorized, &format!("brain://{asset_item_id}"))
        .unwrap();
    let record_value = spot_json(&record_page);
    let origin = &record_value["archive"]["origin"];
    assert_eq!(origin["declaredIn"].as_str(), Some("conversations.json"));
    assert!(
        origin["member"].is_null(),
        "the bytes are not exported: no member is ever claimed"
    );
    assert_eq!(origin["position"], 1);
    assert_eq!(
        record_value["archive"]["exportRoot"].as_str(),
        export_dir.to_str()
    );
    let refusal = |context: &UriContext| {
        router
            .resolve(context, &format!("brain://{item_id}"))
            .unwrap_err()
    };
    // A stale binding epoch is not the session's current incarnation.
    assert!(matches!(
        refusal(&proof_for(
            &proof_scope,
            proof_session.clone(),
            proof_run.clone(),
            proof_lane.clone(),
            proof_epoch + 1,
        )),
        UriError::ExecutionProof { .. }
    ));
    // Match scope to the absent session so the ledger lookup is the failing check.
    let missing_session: odin_domain::SessionId = "session-missing".parse().unwrap();
    let missing_scope = odin_domain::Scope {
        session: Some(missing_session.clone()),
        ..proof_scope.clone()
    };
    assert!(matches!(
        refusal(&proof_for(
            &missing_scope,
            missing_session,
            proof_run.clone(),
            proof_lane.clone(),
            proof_epoch,
        )),
        UriError::Storage { .. }
    ));
    // A run the ledger does not know is never an execution binding.
    assert!(matches!(
        refusal(&proof_for(
            &proof_scope,
            proof_session.clone(),
            "run-ghost".parse().unwrap(),
            proof_lane.clone(),
            proof_epoch,
        )),
        UriError::ExecutionProof { .. }
    ));
    let wrong_lane_scope = odin_domain::Scope {
        lane: Some("lane-beta".parse().unwrap()),
        ..proof_scope.clone()
    };
    assert!(matches!(
        refusal(&proof_for(
            &wrong_lane_scope,
            proof_session.clone(),
            proof_run.clone(),
            proof_lane.clone(),
            proof_epoch,
        )),
        UriError::ExecutionProof { .. }
    ));
    // A node-bound session cannot read an item that proves no node identity.
    let node_bound_scope = odin_domain::Scope {
        node: Some("node-alpha".parse().unwrap()),
        ..proof_scope.clone()
    };
    assert!(matches!(
        refusal(&proof_for(
            &node_bound_scope,
            proof_session.clone(),
            proof_run.clone(),
            proof_lane.clone(),
            proof_epoch,
        )),
        UriError::ScopeDenied { .. }
    ));
    // Scope alone is insufficient without captured execution context.
    assert!(matches!(
        refusal(&UriContext::new(proof_scope.clone())),
        UriError::ExecutionProof { .. }
    ));

    let first_page = router
        .resolve(&authorized, &format!("brain://{item_id}"))
        .unwrap();
    let first = spot_json(&first_page);
    assert_eq!(first["kind"], "knowledge item window");
    assert_eq!(first["itemId"], item_id.to_string());
    assert_eq!(first["page"]["byteStart"], 0);
    let total = first["page"]["totalBytes"].as_u64().unwrap();
    assert!(
        total > 16 * 1024,
        "the indexed item must really be larger than one default page, got {total} bytes"
    );
    let mut assembled = String::new();
    // Page one is the bare item URI; every later page is the continuation
    // the previous one named.
    let mut next = Some(format!("brain://{item_id}"));
    let mut cursor = 0_u64;
    while cursor < total {
        let url = next
            .clone()
            .expect("every unfinished page names its continuation");
        let page = router.resolve(&authorized, &url).unwrap();
        let value = spot_json(&page);
        assert_eq!(
            value["page"]["byteStart"].as_u64().unwrap(),
            cursor,
            "a page starts exactly where the previous one ended"
        );
        let end = value["page"]["byteEnd"].as_u64().unwrap();
        assert!(end > cursor && end <= total);
        let text = value["page"]["text"].as_str().unwrap().to_owned();
        assembled.push_str(&text);
        assert_eq!(
            assembled.len() as u64,
            end,
            "pages concatenate exactly once, with no duplicated overlap"
        );
        cursor = end;
        next = value["page"]["continuation"].as_str().map(str::to_owned);
    }
    assert!(next.is_none(), "the last page ends the item");
    assert_eq!(
        assembled.len() as u64,
        total,
        "pages cover the item exactly"
    );
    assert!(
        assembled.ends_with("PAGE-TAIL-MARKER"),
        "the item's own tail is reachable through pages"
    );
    assert_eq!(
        assembled.matches(unit).count(),
        6_000,
        "no multi-byte scalar is lost or duplicated across page boundaries"
    );

    // Refusals: an edge inside a scalar, a past-end window, an oversized
    // window, and a malformed selector are all typed, never clamped.
    let inside_scalar = assembled.find(unit).unwrap() as u64 + 1;
    for url in [
        format!(
            "brain://{item_id}/bytes/{inside_scalar}/{}",
            inside_scalar + 3
        ),
        format!("brain://{item_id}/bytes/0/{}", total + 1),
        format!("brain://{item_id}/bytes/0/{}", 64 * 1024 + 1),
        format!("brain://{item_id}/bytes/0/notanumber"),
    ] {
        assert!(
            router.resolve(&authorized, &url).is_err(),
            "{url} must be refused"
        );
    }

    // Bare snapshots require active sessions just like item reads.
    ledger
        .lock()
        .unwrap()
        .finish_live_session(
            &proof_session,
            proof_epoch,
            odin_ledger::live::LiveSessionExit::Ended,
            time::OffsetDateTime::UNIX_EPOCH,
        )
        .unwrap();
    assert!(matches!(
        refusal(&authorized),
        UriError::ExecutionProof { .. }
    ));
    assert!(matches!(
        router.resolve(&authorized, "brain://"),
        Err(UriError::ExecutionProof { .. })
    ));
}

/// Emitted identifiers must round-trip through the scoped router and refuse unauthorized sources.
#[test]
fn brain_emitted_identifiers_round_trip_and_bad_scope_refuses() {
    use odin_brain::service::{
        archive_declaration_digest, ArchiveIngestAuthority, ArchiveIngestGate, ArchiveIngestRequest,
    };
    use odin_domain::knowledge::archive::{
        ArchiveDedupeKey, ArchiveFormat, ArchivePrivacyClass, ArchiveSelectionPolicy,
        ArchiveSourceDeclaration,
    };
    use odin_domain::knowledge::retrieval::{RetrievalQuery, TrustClass};
    use odin_registry::schema::{ProjectToml, RegistryKind, REGISTRY_SCHEMA};

    struct TestGate;
    impl ArchiveIngestGate for TestGate {
        fn verify(
            &self,
            _authority: &ArchiveIngestAuthority,
            source: &AtlasId,
            _idempotency_key: &str,
        ) -> odin_brain::error::BrainResult<()> {
            assert!(!source.as_str().is_empty());
            Ok(())
        }
    }

    // One archive message past the default page, so the record read's
    // continuation selector is exercised too.
    let message = format!("{}{}", "IDENTITY-MARKER-é".repeat(2_000), "RECORD-TAIL");
    let root = artifact_root("brain-identifier-roundtrip");
    let export_dir = root.join("export");
    std::fs::create_dir_all(&export_dir).unwrap();
    let export = serde_json::json!([{
        "uuid": "conv-identity",
        "name": "Identity fixture",
        "account": { "uuid": "account-identity" },
        "created_at": "2026-01-01T00:00:00Z",
        "chat_messages": [{
            "uuid": "msg-identity",
            "sender": "assistant",
            "text": message,
            "created_at": "2026-01-02T00:00:00Z",
        }],
    }]);
    std::fs::write(
        export_dir.join("conversations.json"),
        serde_json::to_string(&export).unwrap(),
    )
    .unwrap();
    let source = AtlasId::new("archive:identity").unwrap();
    let declaration = ArchiveSourceDeclaration {
        format: ArchiveFormat::ClaudeExport,
        path: export_dir,
        memory_namespace: "memory.identity".to_owned(),
        // Shared so the fixture source can be declared as project memory;
        // the scope mechanic under test is the project's declared memory,
        // not privacy admission (real private exports stay Private and
        // seat-scoped).
        privacy_class: ArchivePrivacyClass::Shared,
        dedupe_key: ArchiveDedupeKey::ContentDigest,
        selection: ArchiveSelectionPolicy {
            since: None,
            exclude_labels: Vec::new(),
            exclude_if_header: Vec::new(),
            keep_if_participant: false,
            participant_emails: Vec::new(),
            suspicious_rules: Vec::new(),
            exclude_do_not_remember: None,
        },
    };
    let sources = atlas_ids(&[source.as_str()]);
    let model = ModelDescriptor {
        name: ModelName::new("model.uri-identity").unwrap(),
        tokenizer: TokenizerId::new("odin.tokenizer.utf8-bytes.v1").unwrap(),
        context_window_tokens: nz32(8192),
    };
    let mut slice = test_slice();
    let slice_knowledge = slice.knowledge.as_mut().unwrap();
    slice_knowledge.atlas_sources = sources.clone();
    slice_knowledge.retrieval_mode = odin_domain::knowledge::RetrievalMode::Lexical;
    slice_knowledge.embedding_backend = odin_domain::knowledge::EmbeddingBackend::Disabled;
    let mut seat = test_seat();
    seat.brain_scope = sources.clone();
    seat.knowledge.as_mut().unwrap().atlas_sources = sources.clone();
    seat.project_scope = BTreeSet::from([odin_domain::ProjectId::new("identity").unwrap()]);
    let project = ProjectToml {
        schema: REGISTRY_SCHEMA.to_owned(),
        kind: RegistryKind::Project,
        enabled: true,
        description: "uri identifier fixture project".to_owned(),
        source_root: String::new(),
        default_seat: SeatId::new("sinmara").unwrap(),
        memory_namespaces: sources.clone(),
        artifact_policy: "standard".to_owned(),
        privacy: None,
        accounts: Default::default(),
        review_verdict: None,
    };
    let policy = EffectiveBrainPolicy::resolve(
        74,
        &slice,
        &seat,
        &BTreeMap::from([("identity", &project)]),
        &std::collections::BTreeMap::from([(
            "sized",
            &odin_registry::ContextProfileToml::sized(
                std::num::NonZeroU32::new(2048).unwrap(),
                std::num::NonZeroU32::new(6144).unwrap(),
            ),
        )]),
        &model,
    )
    .unwrap();
    assert!(
        policy
            .project_memory
            .contains_key(&odin_domain::ProjectId::new("identity").unwrap()),
        "the archive source is the identity project's declared memory"
    );
    let ledger = seeded_ledger();
    let service = Arc::new(
        BrainService::open(
            BrainServiceConfig {
                store_root: root.join("brain-store"),
                sources: BTreeMap::from([(
                    source.clone(),
                    BrainSourceConfig::Archive {
                        declaration: declaration.clone(),
                    },
                )]),
                embedding_available: false,
                embedding_model: None,
                archive_ingest_gate: Some(Arc::new(TestGate)),
                postgres: None,
            },
            policy,
            ledger.clone(),
        )
        .unwrap(),
    );
    let plan = service.prepare_archive_ingest(&source).unwrap();
    service
        .ingest_archive(&ArchiveIngestRequest {
            source: source.clone(),
            declaration: declaration.clone(),
            approval: ArchiveIngestAuthority {
                demand_id: "demand-identity".to_owned(),
                approval_id: "approval-identity".to_owned(),
                command_id: "command-identity".to_owned(),
                declaration_digest: archive_declaration_digest(&declaration).unwrap(),
                content_revision: plan.content_revision,
            },
            idempotency_key: "identity".to_owned(),
            deadline: None,
        })
        .unwrap();
    let hits = service
        .retrieve(
            &RetrievalQuery::new(
                "RECORD-TAIL".to_owned(),
                sources.clone(),
                BTreeSet::new(),
                BTreeSet::new(),
                [
                    TrustClass::Curated,
                    TrustClass::Observed,
                    TrustClass::Untrusted,
                ]
                .into_iter()
                .collect(),
                nz16(64),
                nz16(64),
                odin_domain::knowledge::RelevanceScore::new(0).unwrap(),
            )
            .unwrap(),
            // Project memory serves only its declared project.
            Some(&odin_domain::ProjectId::new("identity").unwrap()),
            None,
        )
        .unwrap()
        .hits;
    let item_id = hits
        .iter()
        .find(|hit| {
            service
                .archive_citation(
                    &hit.citation.source,
                    &hit.citation.source_revision,
                    &hit.item_id,
                )
                .unwrap()
                .is_some_and(|citation| citation.message_id.as_deref() == Some("msg-identity"))
        })
        .map(|hit| hit.item_id)
        .expect("the archived identity message must serve");
    let router = ScopedUriRouter::new(
        ledger.clone(),
        Arc::new(test_atlas()),
        allowed_atlas_scope(),
        root,
        MAX_TEST_ARTIFACT_BYTES,
        BTreeMap::from([(SeatId::new("sinmara").unwrap(), Arc::clone(&service))]),
    )
    .unwrap();
    // Both scopes have live sessions; only project authorization differs.
    let identity = brain_context(&ledger, "sinmara", "identity");
    let foreign_project = brain_context(&ledger, "sinmara", "elsewhere");
    let resolve = |context: &UriContext, url: &str| {
        ScopedUriRouter::parse(url).unwrap_or_else(|error| panic!("{url} must parse: {error}"));
        router
            .resolve(context, url)
            .map(|snapshot| spot_json(&snapshot).clone())
    };

    // The bundle surface hands out exactly one identifier: the item's
    // canonical page URI. It must parse through the one shared grammar and
    // resolve through this router; the record key rides along only as
    // payload attribution for citation reads, never as a second address.
    let item_url = format!("brain://{item_id}");
    let page = resolve(&identity, &item_url).unwrap();
    assert_eq!(page["kind"], "knowledge item window");
    assert_eq!(page["itemId"], item_id.to_string());
    assert_eq!(
        page["archive"]["naturalKey"].as_str(),
        Some("msg-identity"),
        "the payload names its record's natural key"
    );
    assert!(
        page["archive"]["recordKey"].is_string(),
        "the payload names its record key for citation reads"
    );

    // One exact window reads back its leading bytes exactly.
    let window_bytes = &message[..8];
    let item_window = resolve(&identity, &format!("{item_url}/bytes/0/8")).unwrap();
    assert_eq!(
        item_window["page"]["text"].as_str(),
        Some(window_bytes),
        "the window selector serves the item's exact leading bytes"
    );

    // Bad scope: outside the identity project's declared memory, the item
    // address is a typed miss — existence is never leaked across projects.
    let error = router.resolve(&foreign_project, &item_url).unwrap_err();
    assert!(
        matches!(error, UriError::UnknownResource { .. }),
        "{item_url} must be a typed miss outside the serving project: {error:?}"
    );
}

/// The serialized brain:// item and record payloads carry the format's
/// export metadata when a record declares any — branch-free here: the
/// Gemini Workspace fixture's every record carries its declared
/// `source_file`, read from the persisted structured column.
#[test]
fn brain_archive_reads_carry_format_export_metadata() {
    use odin_brain::service::{
        archive_declaration_digest, ArchiveIngestAuthority, ArchiveIngestGate, ArchiveIngestRequest,
    };
    use odin_domain::knowledge::archive::{
        ArchiveDedupeKey, ArchiveFormat, ArchivePrivacyClass, ArchiveSelectionPolicy,
        ArchiveSourceDeclaration,
    };
    use odin_domain::knowledge::retrieval::{RetrievalQuery, TrustClass};

    struct TestGate;
    impl ArchiveIngestGate for TestGate {
        fn verify(
            &self,
            _authority: &ArchiveIngestAuthority,
            source: &AtlasId,
            _idempotency_key: &str,
        ) -> odin_brain::error::BrainResult<()> {
            assert!(!source.as_str().is_empty());
            Ok(())
        }
    }

    let root = artifact_root("brain-meta");
    let history = root
        .join("Gemini in Workspace")
        .join("Conversation History");
    std::fs::create_dir_all(&history).unwrap();
    let conversation = serde_json::json!({
        "title": "Urn seal",
        "creation_time": "2026-01-01T00:00:00Z",
        "conversation_turns": [
            {"user_turn": {"prompt": "META-BRONZE: the bronze urn seal", "turn_index": 0}}
        ]
    });
    std::fs::write(
        history.join("urn-seal.txt"),
        serde_json::to_vec(&conversation).unwrap(),
    )
    .unwrap();
    let source = AtlasId::new("archive:meta-urn").unwrap();
    let declaration = ArchiveSourceDeclaration {
        format: ArchiveFormat::GeminiWorkspace,
        path: root.clone(),
        memory_namespace: "memory.meta-urn".to_owned(),
        privacy_class: ArchivePrivacyClass::Private,
        dedupe_key: ArchiveDedupeKey::ContentDigest,
        selection: ArchiveSelectionPolicy {
            since: None,
            exclude_labels: Vec::new(),
            exclude_if_header: Vec::new(),
            keep_if_participant: false,
            participant_emails: Vec::new(),
            suspicious_rules: Vec::new(),
            exclude_do_not_remember: None,
        },
    };
    let sources = atlas_ids(&[source.as_str()]);
    let model = ModelDescriptor {
        name: ModelName::new("model.uri-meta").unwrap(),
        tokenizer: TokenizerId::new("odin.tokenizer.utf8-bytes.v1").unwrap(),
        context_window_tokens: nz32(8192),
    };
    let mut slice = test_slice();
    let slice_knowledge = slice.knowledge.as_mut().unwrap();
    slice_knowledge.atlas_sources = sources.clone();
    slice_knowledge.retrieval_mode = odin_domain::knowledge::RetrievalMode::Lexical;
    slice_knowledge.embedding_backend = odin_domain::knowledge::EmbeddingBackend::Disabled;
    // Match the positive FTS5 score floor shipped in source declarations.
    slice_knowledge.min_score_micros = 1;
    let mut seat = test_seat();
    seat.brain_scope = sources.clone();
    seat.knowledge.as_mut().unwrap().atlas_sources = sources.clone();
    let policy = EffectiveBrainPolicy::resolve(
        74,
        &slice,
        &seat,
        &BTreeMap::new(),
        &std::collections::BTreeMap::from([(
            "sized",
            &odin_registry::ContextProfileToml::sized(
                std::num::NonZeroU32::new(2048).unwrap(),
                std::num::NonZeroU32::new(6144).unwrap(),
            ),
        )]),
        &model,
    )
    .unwrap();
    let service = Arc::new(
        BrainService::open(
            BrainServiceConfig {
                store_root: root.join("brain-store"),
                sources: BTreeMap::from([(
                    source.clone(),
                    BrainSourceConfig::Archive {
                        declaration: declaration.clone(),
                    },
                )]),
                embedding_available: false,
                embedding_model: None,
                archive_ingest_gate: Some(Arc::new(TestGate)),
                postgres: None,
            },
            policy,
            seeded_ledger(),
        )
        .unwrap(),
    );
    let plan = service.prepare_archive_ingest(&source).unwrap();
    service
        .ingest_archive(&ArchiveIngestRequest {
            source: source.clone(),
            declaration: declaration.clone(),
            approval: ArchiveIngestAuthority {
                demand_id: "demand-meta".to_owned(),
                approval_id: "approval-meta".to_owned(),
                command_id: "command-meta".to_owned(),
                declaration_digest: archive_declaration_digest(&declaration).unwrap(),
                content_revision: plan.content_revision,
            },
            idempotency_key: "meta-urn".to_owned(),
            deadline: None,
        })
        .unwrap();

    let query_text = |text: &str| {
        RetrievalQuery::new(
            text.to_owned(),
            sources.clone(),
            BTreeSet::new(),
            BTreeSet::new(),
            [
                TrustClass::Curated,
                TrustClass::Observed,
                TrustClass::Untrusted,
            ]
            .into_iter()
            .collect(),
            nz16(64),
            nz16(64),
            odin_domain::knowledge::RelevanceScore::new(0).unwrap(),
        )
        .unwrap()
    };
    let find = |natural_key: &str, text: &str| {
        service
            .retrieve(&query_text(text), None, None)
            .unwrap()
            .hits
            .into_iter()
            .find_map(|hit| {
                let citation = service
                    .archive_citation(
                        &hit.citation.source,
                        &hit.citation.source_revision,
                        &hit.citation.item_id,
                    )
                    .unwrap()?;
                (citation.natural_key == natural_key).then_some((hit.item_id, citation))
            })
            .expect("the addressed record must serve and cite itself")
    };
    let (message_item, _) = find("urn-seal:turn:0:user", "META-BRONZE urn seal");

    let ledger = seeded_ledger();
    let router = ScopedUriRouter::new(
        ledger.clone(),
        Arc::new(test_atlas()),
        allowed_atlas_scope(),
        root,
        MAX_TEST_ARTIFACT_BYTES,
        BTreeMap::from([(SeatId::new("seat-alpha").unwrap(), Arc::clone(&service))]),
    )
    .unwrap();
    let seated = brain_context(&ledger, "seat-alpha", "project-alpha");
    let page = router
        .resolve(&seated, &format!("brain://{message_item}"))
        .unwrap();
    assert_eq!(
        spot_json(&page)["archive"]["exportMetadata"]["source_file"].as_str(),
        Some("Gemini in Workspace/Conversation History/urn-seal.txt"),
    );
}
