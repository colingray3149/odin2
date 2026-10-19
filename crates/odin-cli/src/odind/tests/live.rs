use std::collections::BTreeMap;
use std::fs;
use std::sync::{Arc, Mutex};

use odin_registry::{SnapshotHandle, SnapshotStore};

use crate::controller;
use crate::test_fixture::{odind_host_toml, odind_node_toml, PublishedStore};
use crate::test_support::commit_all;

#[test]
fn odind_snapshot_only_rejects_missing_raw_and_unversioned_sources() {
    let fixture = PublishedStore::new("alpha", true);

    // Missing store.
    let missing = SnapshotHandle::open(SnapshotStore::new(
        fixture.temporary.path().join("absent/snapshot.json"),
    ));
    assert!(missing.is_err(), "missing store must fail startup");

    // A directory is not an active snapshot file.
    let directory =
        SnapshotHandle::open(SnapshotStore::new(fixture.temporary.path().to_path_buf()));
    assert!(directory.is_err(), "directory source must fail startup");

    // The exact active bytes without the immutable revision file and
    // receipt are a raw source, never a publication.
    let raw_directory = fixture.temporary.path().join("raw");
    fs::create_dir(&raw_directory).expect("create raw directory");
    fs::copy(&fixture.snapshot_path, raw_directory.join("snapshot.json"))
        .expect("copy active bytes");
    let raw = SnapshotHandle::open(SnapshotStore::new(raw_directory.join("snapshot.json")));
    assert!(raw.is_err(), "unversioned copy must fail startup");

    let error = controller::check(&controller::CheckRequest {
        registry_snapshot: raw_directory.join("snapshot.json"),
        state_root: fixture.temporary.path().join("state-raw"),
        node: "alpha".to_owned(),
    })
    .expect_err("raw source must fail controller startup");
    assert!(matches!(error, controller::ControllerError::Registry(_)));
}

#[test]
fn odind_snapshot_only_check_binds_authority_to_the_published_revision() {
    let fixture = PublishedStore::new("alpha", true);
    let handle = SnapshotHandle::open(fixture.store()).expect("open verified store");
    let pinned = handle.current();
    assert_eq!(pinned.revision, 1);

    let report = fixture.check("alpha").expect("startup with authority");
    assert_eq!(report.authoritative_node, "alpha");
    assert_eq!(report.restart_count, 1);

    // Move the authority to beta in a committed revision and publish it.
    let alpha = fixture.worktree.join("registry/nodes/alpha/node.toml");
    fs::write(&alpha, odind_node_toml("alpha", false)).expect("demote alpha");
    let beta = fixture.worktree.join("registry/nodes/beta");
    fs::create_dir_all(&beta).expect("create beta directory");
    fs::write(beta.join("node.toml"), odind_node_toml("beta", true)).expect("write beta config");
    let beta_host = fixture.worktree.join("registry/hosts/beta-host");
    fs::create_dir_all(&beta_host).expect("create beta host directory");
    fs::write(beta_host.join("host.toml"), odind_host_toml("beta"))
        .expect("write beta host config");
    let second_commit = commit_all(&fixture.worktree, "odind authority promotion fixture");
    let candidate = odin_registry::ValidatedSnapshotCandidate::from_committed_worktree(
        &fixture.worktree,
        &second_commit,
        Vec::<odin_registry::relational::AdmittedBinding>::new(),
    )
    .expect("second committed candidate");
    fixture
        .store()
        .publish_committed(&candidate, 2)
        .expect("publish revision 2");

    // Even if publication advances after the daemon pins revision 1,
    // controller startup validates that exact Arc before the same Arc is
    // passed into runtime composition.
    let pinned_report = controller::check_snapshot(
        &fixture.temporary.path().join("state-pinned-alpha"),
        Arc::clone(&pinned),
        "alpha",
    )
    .expect("validate exact pinned startup revision");
    assert_eq!(pinned_report.authoritative_node, "alpha");
    assert_eq!(pinned.revision, 1);

    // The pinned revision from before the publish is untouched, and the
    // store re-verifies onto revision 2.
    assert_eq!(handle.current().revision, 1);
    assert_eq!(handle.reload().expect("reload").revision, 2);
    assert_eq!(handle.current().revision, 2);

    // The new authority starts; the old one is refused even though its
    // raw worktree file still exists on disk with valid syntax.
    let beta_report = fixture.check("beta").expect("startup with new authority");
    assert_eq!(beta_report.authoritative_node, "beta");
    let error = fixture
        .check("alpha")
        .expect_err("non-authoritative node must be refused");
    assert!(
        error.contains("not authoritative"),
        "unexpected error: {error}"
    );

    // Editing the raw worktree TOML cannot resurrect authority: the
    // published snapshot is the only source the controller reads.
    fs::write(&alpha, odind_node_toml("alpha", true)).expect("tamper raw source");
    let error = fixture
        .check("alpha")
        .expect_err("raw worktree edits must not bind authority");
    assert!(
        error.contains("not authoritative"),
        "unexpected error: {error}"
    );
}

/// Check the bridge's actual destination before IO, not just the session's memory grant.
#[test]
fn vault_write_gate_refuses_a_mismatched_destination_before_io() {
    use std::collections::BTreeSet;
    use std::num::{NonZeroU16, NonZeroU32};

    use odin_brain::config::EffectiveBrainPolicy;
    use odin_brain::service::{BrainService, BrainServiceConfig, BrainSourceConfig};
    use odin_domain::huginn::ids::{LiveSessionId, ModelName};
    use odin_domain::knowledge::ids::TokenizerId;
    use odin_domain::knowledge::{AtlasId, EmbeddingBackend, RetrievalMode};
    use odin_domain::{ProjectId, SeatId};
    use odin_hermes::vault::{VaultBridge, VaultConfig, VaultWriteGate};
    use odin_ledger::Ledger;
    use odin_omp::live::ledger::{fs::FsLiveLedger, LiveLedger};
    use odin_registry::schema::{
        AccountingWindowToml, ApprovalDefaultToml, ApprovalDefaultsToml, BudgetPolicyToml,
        ProjectToml, RegistryKind, SeatKnowledgeToml, SeatLimitsToml, SeatToml, SliceKnowledgeToml,
        SliceRedirectsToml, SliceToml, REGISTRY_SCHEMA,
    };

    fn nz16(value: u16) -> NonZeroU16 {
        NonZeroU16::new(value).unwrap()
    }

    fn nz32(value: u32) -> NonZeroU32 {
        NonZeroU32::new(value).unwrap()
    }

    fn model() -> odin_domain::knowledge::retrieval::ModelDescriptor {
        odin_domain::knowledge::retrieval::ModelDescriptor {
            name: odin_domain::huginn::ids::ModelName::new("model.gate").unwrap(),
            tokenizer: TokenizerId::new("odin.tokenizer.utf8-bytes.v1").unwrap(),
            context_window_tokens: nz32(8192),
        }
    }

    // A real, buildable crate so the composed source pins through the
    // actual Atlas build.
    let root = tempfile::tempdir().expect("fixture root");
    let crate_root = root.path().join("crate");
    let src = crate_root.join("crates").join("pm_gate_demo").join("src");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::write(
        src.join("lib.rs"),
        "//! Fixture crate.\n\n/// Adds one.\npub fn gate_fn(v: u64) -> u64 { v + 1 }\n",
    )
    .unwrap();
    for directory in ["extension", "registry", "skeletons"] {
        std::fs::create_dir_all(crate_root.join(directory)).unwrap();
    }

    let source = "atlas:pm-alpha";
    let seat_id = SeatId::new("gate-seat").unwrap();
    let slice = SliceToml {
        schema: REGISTRY_SCHEMA.to_owned(),
        kind: RegistryKind::Slice,
        enabled: true,
        description: "gate fixture slice".to_owned(),
        capabilities: BTreeSet::new(),
        variables: BTreeMap::new(),
        redirects: SliceRedirectsToml {
            out_of_scope: "NeedsPlan".to_owned(),
        },
        knowledge: Some(SliceKnowledgeToml {
            required: false,
            atlas_sources: BTreeSet::from([AtlasId::new(source).unwrap()]),
            retrieval_mode: RetrievalMode::Lexical,
            candidate_limit: nz16(64),
            top_k: nz16(8),
            min_score_micros: 0,
            chunk_tokens: nz32(512),
            chunk_overlap_tokens: 64,
            embedding_backend: EmbeddingBackend::Local,
        }),
        context: None,
        tools: None,
        live: None,
        budget: None,
    };
    let seat = SeatToml {
        schema: REGISTRY_SCHEMA.to_owned(),
        kind: RegistryKind::Seat,
        enabled: true,
        description: "gate fixture seat".to_owned(),
        categories: BTreeSet::new(),
        project_scope: BTreeSet::from([ProjectId::new("alpha").unwrap()]),
        read_project_scope: BTreeSet::new(),
        models: Vec::new(),
        tool_refs: BTreeSet::new(),
        approval_defaults: ApprovalDefaultsToml {
            r0: ApprovalDefaultToml::Auto,
            r1: ApprovalDefaultToml::Auto,
            r2: ApprovalDefaultToml::Auto,
            r3: ApprovalDefaultToml::Auto,
        },
        brain_scope: BTreeSet::from([AtlasId::new(source).unwrap()]),
        limits: SeatLimitsToml {
            max_parallel_runs: 1,
            max_sessions: 1,
            budget: Some(BudgetPolicyToml {
                usd_micros: 30_000_000,
                window: AccountingWindowToml {
                    duration_seconds: std::num::NonZeroU64::new(2_592_000).unwrap(),
                },
            }),
        },
        live: None,
        guidance: None,
        conversation: None,
        profile_namespace: None,
        knowledge: Some(SeatKnowledgeToml {
            atlas_sources: BTreeSet::from([AtlasId::new(source).unwrap()]),
            required_tags: BTreeSet::new(),
            denied_tags: BTreeSet::new(),
            top_k: nz16(8),
        }),
        context: None,
        tools: None,
        ephemeral: None,
        sandbox: odin_registry::schema::SeatSandboxToml::default(),
    };
    let alpha = ProjectToml {
        schema: REGISTRY_SCHEMA.to_owned(),
        kind: RegistryKind::Project,
        enabled: true,
        description: "vault gate fixture project".to_owned(),
        source_root: String::new(),
        default_seat: seat_id.clone(),
        memory_namespaces: BTreeSet::from([AtlasId::new(source).unwrap()]),
        artifact_policy: "standard".to_owned(),
        privacy: None,
        accounts: Default::default(),
        review_verdict: None,
    };
    let projects = BTreeMap::from([("alpha", &alpha)]);
    let policy = EffectiveBrainPolicy::resolve(
        1,
        &slice,
        &seat,
        &projects,
        &std::collections::BTreeMap::new(),
        &model(),
    )
    .unwrap();

    let service = BrainService::open(
        BrainServiceConfig {
            store_root: root.path().join("brain-store"),
            sources: BTreeMap::from([(
                AtlasId::new(source).unwrap(),
                BrainSourceConfig::Atlas {
                    root: crate_root.clone(),
                },
            )]),
            embedding_available: false,
            embedding_model: None,
            archive_ingest_gate: None,
            postgres: None,
        },
        policy.clone(),
        Arc::new(Mutex::new(Ledger::open_in_memory().unwrap())),
    )
    .unwrap();

    // The durable session manifest binds the session to project alpha.
    let live_root = tempfile::tempdir().expect("live root");
    let live_ledger: Arc<dyn LiveLedger> =
        Arc::new(FsLiveLedger::open(live_root.path()).expect("live ledger opens"));
    let live_session = LiveSessionId::parse("00000000-0000-4000-8000-0000000000aa").unwrap();
    {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime
            .block_on(
                live_ledger.create_session(odin_domain::huginn::SessionManifest {
                    session_id: live_session,
                    seat_id: seat_id.clone(),
                    slice_id: odin_domain::SliceId::new("slice.gate").unwrap(),
                    project_id: ProjectId::new("alpha").unwrap(),
                    provider: odin_domain::huginn::ProviderName::new("provider.gate").unwrap(),
                    model: ModelName::new("model.gate").unwrap(),
                    title: None,
                    target_node: odin_domain::NodeId::new("node.gate").unwrap(),
                    open_tab: false,
                    workload: None,
                    served_revision: Some(1),
                    harness: None,
                }),
            )
            .expect("session row");
    }
    let bridge_session =
        odin_domain::SessionId::new(live_session.to_string()).expect("bridge session id");

    let gate = super::FactoryVaultWriteGate {
        brains: BTreeMap::from([(seat_id.clone(), Arc::new(service))]),
        live_ledger: Arc::clone(&live_ledger),
        generated_namespace: Some("generated".into()),
    };

    // The mismatched destination: the bridge is configured for a global
    // vault source the project never declared. The gate refuses typed
    // BEFORE any IO, so the mismatched vault root stays empty.
    let mismatched_root = tempfile::tempdir().expect("mismatched vault root");
    let mismatched_bridge = VaultBridge::new(VaultConfig {
        vault_root: mismatched_root.path().join("vault"),
        source_id: "vault:global".to_owned(),
        silverbullet: None,
        general_namespaces: vec!["knowledge".to_owned()],
        generated_namespace: "generated".to_owned(),
        excluded_namespaces: vec![],
        max_pages: 64,
        max_page_bytes: 65_536,
        timeout_ms: 1_000,
    })
    .expect("mismatched bridge composes");
    let refusal = gate.gate_generated_write(
        &seat_id,
        &bridge_session,
        "vault:global",
        "generated/note.md",
    );
    assert!(
        refusal.is_err(),
        "a destination the project never declared must refuse: {refusal:?}"
    );
    assert!(!mismatched_root
        .path()
        .join("vault")
        .join("generated")
        .exists());

    // The matching destination: the declared namespace IS the write source,
    // so the gate admits it — destination-exact, never vacuous.
    let matched_root = tempfile::tempdir().expect("matched vault root");
    let matched_bridge = VaultBridge::new(VaultConfig {
        vault_root: matched_root.path().join("vault"),
        source_id: source.to_owned(),
        silverbullet: None,
        general_namespaces: vec!["knowledge".to_owned()],
        generated_namespace: "generated".to_owned(),
        excluded_namespaces: vec![],
        max_pages: 64,
        max_page_bytes: 65_536,
        timeout_ms: 1_000,
    })
    .expect("matched bridge composes");
    gate.gate_generated_write(&seat_id, &bridge_session, source, "generated/note.md")
        .expect("the declared destination is admitted");
    // The knowledge-projection tree is daemon-rendered, never model-
    // written: a generated write naming a knowledge path refuses typed
    // before any IO, exactly like a mismatched destination — the bridge
    // cannot be tricked into forging brain projection pages.
    assert!(
        gate.gate_generated_write(
            &seat_id,
            &bridge_session,
            source,
            "generated/knowledge/state.registry/index.md",
        )
        .is_err(),
        "a generated write cannot land inside the knowledge projection tree"
    );
    assert!(
        gate.gate_generated_write(
            &seat_id,
            &bridge_session,
            source,
            "generated/memories/gate-seat/private.md",
        )
        .is_err(),
        "project vault authority alone cannot grant reserved seat memory"
    );

    let memory_id = AtlasId::new("memory.gate-seat").unwrap();
    let mut memory_seat = seat.clone();
    memory_seat.brain_scope = [memory_id.clone()].into();
    memory_seat.knowledge.as_mut().unwrap().atlas_sources = [memory_id.clone()].into();
    let mut memory_slice = slice.clone();
    memory_slice.knowledge.as_mut().unwrap().atlas_sources = [memory_id.clone()].into();
    let memory_policy = EffectiveBrainPolicy::resolve(
        1,
        &memory_slice,
        &memory_seat,
        &projects,
        &std::collections::BTreeMap::new(),
        &model(),
    )
    .unwrap();
    let memory_source = odin_brain::source::silverbullet::SilverBulletSource::new(
        memory_id.clone(),
        1,
        odin_brain::source::silverbullet::VaultScope::generated_only(
            "generated/memories/gate-seat",
            &[],
        )
        .unwrap(),
    );
    let memory_brain = Arc::new(
        BrainService::open(
            BrainServiceConfig {
                store_root: root.path().join("memory-brain"),
                sources: BTreeMap::from([(
                    memory_id,
                    BrainSourceConfig::Memory {
                        source: memory_source,
                    },
                )]),
                embedding_available: false,
                embedding_model: None,
                archive_ingest_gate: None,
                postgres: None,
            },
            memory_policy,
            Arc::new(Mutex::new(Ledger::open_in_memory().unwrap())),
        )
        .unwrap(),
    );
    let foreign = SeatId::new("foreign-seat").unwrap();
    let memory_gate = super::FactoryVaultWriteGate {
        brains: BTreeMap::from([
            (seat_id.clone(), Arc::clone(&memory_brain)),
            (foreign.clone(), memory_brain),
        ]),
        live_ledger: Arc::clone(&live_ledger),
        generated_namespace: Some("generated".into()),
    };
    memory_gate
        .gate_generated_write(
            &seat_id,
            &bridge_session,
            source,
            "generated/memories/gate-seat/note.md",
        )
        .unwrap();
    assert!(memory_gate
        .gate_generated_write(
            &seat_id,
            &bridge_session,
            source,
            "generated/memories/foreign-seat/note.md",
        )
        .is_err());
    assert!(
        memory_gate
            .gate_generated_write(
                &foreign,
                &bridge_session,
                source,
                "generated/memories/foreign-seat/note.md",
            )
            .is_err(),
        "the durable session seat must match even when a brain is wired"
    );
    let mut vault_config = matched_bridge.config().clone();
    vault_config.vault_root = matched_root.path().to_path_buf();
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(
            &vault_config.vault_root,
            std::fs::Permissions::from_mode(0o700),
        )
        .unwrap();
    }
    let runtime = odin_hermes::runtime::HermesRuntime::open(
        odin_hermes::config::HermesSettings::new(
            root.path().join("hermes"),
            None,
            Some(vault_config),
            None,
            vec![],
        )
        .unwrap(),
        odin_hermes::runtime::HermesLedgers {
            conversation: Ledger::open_in_memory().unwrap(),
            adapter: Arc::new(parking_lot::Mutex::new(Ledger::open_in_memory().unwrap())),
            purchase: Arc::new(Mutex::new(Ledger::open_in_memory().unwrap())),
        },
        &BTreeMap::new(),
        None,
        8192,
        BTreeMap::new(),
        None,
    )
    .unwrap();
    runtime.set_vault_write_gate(Arc::new(memory_gate));
    let tools = odin_hermes::runtime::hermes_host_tools(&runtime);
    let remember = tools
        .iter()
        .find(|tool| tool.definition().name == "memory_remember")
        .unwrap();
    let scope = odin_domain::Scope {
        seat: Some(seat_id.clone()),
        session: Some(bridge_session.clone()),
        project: Some(ProjectId::new("alpha").unwrap()),
        ..Default::default()
    };
    let content = "Remember the measured solver convergence criterion.";
    let receipt = remember
        .invoke(odin_omp::host_tools::HostInvocation {
            scope: scope.clone(),
            arguments: serde_json::json!({"content":content}),
        })
        .unwrap();
    let written = receipt["page"].as_str().unwrap();
    assert!(written.starts_with("gate-seat/memory-"), "{receipt}");
    assert!(
        std::fs::read_to_string(matched_root.path().join("generated/memories").join(written))
            .unwrap()
            .contains(content)
    );
    assert!(
        receipt["knowledgeRefreshUnavailable"].is_string(),
        "the durable write stays successful when the read-only projection endpoint is down"
    );
    assert!(remember.invoke(odin_omp::host_tools::HostInvocation {
        scope: scope.clone(),
        arguments: serde_json::json!({"content":content,"page_name":"generated/memories/foreign-seat/stolen.md"}),
    }).is_err(), "model arguments cannot choose a memory destination");
    let ordinary = tools
        .iter()
        .find(|tool| tool.definition().name == "vault_write_generated")
        .unwrap();
    assert!(ordinary.invoke(odin_omp::host_tools::HostInvocation {
        scope, arguments: serde_json::json!({"content":content,"page_name":"generated/memories/foreign-seat/stolen.md"}),
    }).is_err(), "ordinary generated writes cannot bypass the reserved memory gate");
    assert!(!matched_root
        .path()
        .join("generated/memories/foreign-seat")
        .exists());

    // Declared project memory overrides the seat default without exposing undeclared namespaces.
    let project_memory_id = AtlasId::new("memory.project.alpha").unwrap();
    let mut alpha_with_memory = alpha.clone();
    alpha_with_memory
        .memory_namespaces
        .insert(project_memory_id.clone());
    let project_memory_projects = BTreeMap::from([("alpha", &alpha_with_memory)]);
    let mut project_seat = memory_seat.clone();
    project_seat.brain_scope.insert(project_memory_id.clone());
    project_seat
        .knowledge
        .as_mut()
        .unwrap()
        .atlas_sources
        .insert(project_memory_id.clone());
    let mut project_slice = memory_slice.clone();
    project_slice
        .knowledge
        .as_mut()
        .unwrap()
        .atlas_sources
        .insert(project_memory_id.clone());
    let project_policy = EffectiveBrainPolicy::resolve(
        1,
        &project_slice,
        &project_seat,
        &project_memory_projects,
        &std::collections::BTreeMap::new(),
        &model(),
    )
    .unwrap();
    let memory_at = |id: &AtlasId, namespace: &str| {
        (
            id.clone(),
            BrainSourceConfig::Memory {
                source: odin_brain::source::silverbullet::SilverBulletSource::new(
                    id.clone(),
                    1,
                    odin_brain::source::silverbullet::VaultScope::generated_only(namespace, &[])
                        .unwrap(),
                ),
            },
        )
    };
    let project_brain = Arc::new(
        BrainService::open(
            BrainServiceConfig {
                store_root: root.path().join("project-memory-brain"),
                sources: BTreeMap::from([
                    memory_at(
                        &AtlasId::new("memory.gate-seat").unwrap(),
                        "generated/memories/gate-seat",
                    ),
                    memory_at(&project_memory_id, "generated/memories/project.alpha"),
                ]),
                embedding_available: false,
                embedding_model: None,
                archive_ingest_gate: None,
                postgres: None,
            },
            project_policy,
            Arc::new(Mutex::new(Ledger::open_in_memory().unwrap())),
        )
        .unwrap(),
    );
    let project_gate = super::FactoryVaultWriteGate {
        brains: BTreeMap::from([(seat_id.clone(), project_brain)]),
        live_ledger: Arc::clone(&live_ledger),
        generated_namespace: Some("generated".into()),
    };
    project_gate
        .gate_generated_write(
            &seat_id,
            &bridge_session,
            source,
            "generated/memories/project.alpha/note.md",
        )
        .expect("the session project's declared memory is writable");
    assert!(
        project_gate
            .gate_generated_write(
                &seat_id,
                &bridge_session,
                source,
                "generated/memories/project.beta/note.md",
            )
            .is_err(),
        "another project's memory is never writable"
    );
    runtime.set_vault_write_gate(Arc::new(project_gate));
    runtime.set_project_memory(BTreeMap::from([(
        (seat_id.clone(), ProjectId::new("alpha").unwrap()),
        "project.alpha".to_owned(),
    )]));
    let receipt = remember
        .invoke(odin_omp::host_tools::HostInvocation {
            scope: odin_domain::Scope {
                seat: Some(seat_id.clone()),
                session: Some(bridge_session.clone()),
                project: Some(ProjectId::new("alpha").unwrap()),
                ..Default::default()
            },
            arguments: serde_json::json!({"content": "alpha-only note"}),
        })
        .unwrap();
    assert!(receipt["page"]
        .as_str()
        .unwrap()
        .starts_with("project.alpha/"));
    let _ = &matched_bridge;
    let _ = &mismatched_bridge;
}
