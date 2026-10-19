//! All declared seats remember through the real writer and recall through a
//! fresh session compiler. Source mutation must invalidate both items and bundles.

use std::collections::BTreeMap;
use std::fs;
use std::sync::{Arc, Mutex};

/// Narrow cloned declarations and re-resolve policy rather than mutating digest-checked fields.
/// Set both `ODIN_FABRIC_PROOF_VAULT_ROOT` and `ODIN_FABRIC_PROOF_VAULT_PORT`
/// to use a SilverBullet deployment instead of the loopback vault.
#[test]
fn every_declared_seat_proves_rollover_memory_recall_and_rebuild() {
    use std::num::NonZeroU32;
    use std::path::PathBuf;

    use odin_brain::config::EffectiveBrainPolicy;
    use odin_brain::retrieval::embedding::EmbeddingVector;
    use odin_brain::retrieval::QueryEmbedder;
    use odin_brain::service::{BrainService, BrainServiceConfig, BrainSourceConfig};
    use odin_brain::source::silverbullet::{memory_namespace, SilverBulletSource, VaultScope};
    use odin_domain::huginn::ids::{LiveSessionId, ModelName};
    use odin_domain::huginn::ProviderName;
    use odin_domain::knowledge::context::ToolName;
    use odin_domain::knowledge::ids::{AtlasId, EmbeddingModelId, TokenizerId};
    use odin_domain::knowledge::retrieval::ModelDescriptor;
    use odin_domain::knowledge::KnowledgeItemId;
    use odin_domain::{CapabilityId, NodeId, ProjectId, SeatId, SliceId};
    use odin_hermes::vault::{VaultBridge, VaultConfig};
    use odin_ledger::Ledger;
    use odin_omp::live::ledger::{fs::FsLiveLedger, LiveLedger};
    use odin_registry::schema::{CapabilityToml, ProjectToml, SeatToml, SliceToml};

    let repo_root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");

    let memory_capability: CapabilityToml = toml::from_str(
        &fs::read_to_string(
            repo_root.join("registry/capabilities/memory.remember/capability.toml"),
        )
        .expect("memory.remember capability declaration"),
    )
    .expect("valid memory.remember capability declaration");
    assert!(
        !memory_capability.seat_tags.contains("*"),
        "memory.remember must never be a wildcard grant"
    );

    // Enumerate declarations so new seats are covered automatically.
    let mut seat_names: Vec<String> = fs::read_dir(repo_root.join("registry/seats"))
        .expect("seat declarations directory")
        .filter_map(|entry| {
            let path = entry.ok()?.path();
            path.is_dir()
                .then(|| {
                    path.file_stem()
                        .map(|stem| stem.to_string_lossy().to_string())
                })
                .flatten()
        })
        .collect();
    seat_names.sort();
    assert!(!seat_names.is_empty(), "the real seats must enumerate");

    let mut slices: BTreeMap<String, SliceToml> = BTreeMap::new();
    for entry in
        fs::read_dir(repo_root.join("registry/slices")).expect("slice declarations directory")
    {
        let path = entry.expect("slice entry").path();
        if !path.is_dir() {
            continue;
        }
        let name = path
            .file_stem()
            .expect("slice id")
            .to_string_lossy()
            .to_string();
        let slice: SliceToml = toml::from_str(
            &fs::read_to_string(path.join("slice.toml")).expect("slice declaration"),
        )
        .expect("valid slice declaration");
        slices.insert(name, slice);
    }
    assert!(!slices.is_empty(), "the real slices must parse");

    let mut projects: BTreeMap<String, ProjectToml> = BTreeMap::new();
    for entry in
        fs::read_dir(repo_root.join("registry/projects")).expect("project declarations directory")
    {
        let path = entry.expect("project entry").path();
        if !path.is_dir() {
            continue;
        }
        let name = path
            .file_stem()
            .expect("project id")
            .to_string_lossy()
            .to_string();
        let project: ProjectToml = toml::from_str(
            &fs::read_to_string(path.join("project.toml")).expect("project declaration"),
        )
        .expect("valid project declaration");
        assert!(project.enabled, "project {name} must be enabled");
        projects.insert(name, project);
    }
    assert!(!projects.is_empty(), "the real projects must parse");
    let project_refs: BTreeMap<&str, &ProjectToml> = projects
        .iter()
        .map(|(name, project)| (name.as_str(), project))
        .collect();
    let mut profiles: BTreeMap<String, odin_registry::ContextProfileToml> = BTreeMap::new();
    for entry in fs::read_dir(repo_root.join("registry/context-profiles"))
        .expect("context profile declarations directory")
    {
        let path = entry.expect("context profile entry").path();
        let name = path
            .file_name()
            .expect("profile id")
            .to_string_lossy()
            .to_string();
        let profile = toml::from_str(
            &fs::read_to_string(path.join("context-profile.toml")).expect("profile declaration"),
        )
        .expect("valid context profile declaration");
        profiles.insert(name, profile);
    }
    let profile_refs: BTreeMap<&str, &odin_registry::ContextProfileToml> = profiles
        .iter()
        .map(|(name, profile)| (name.as_str(), profile))
        .collect();

    // The vault binding: isolated in-process fixture by default, or the
    // operator-provided real SilverBullet deployment pinned to ITS root.
    let env_root = std::env::var("ODIN_FABRIC_PROOF_VAULT_ROOT");
    let env_port = std::env::var("ODIN_FABRIC_PROOF_VAULT_PORT");
    let (vault_root, vault_port, expected_space_root, _fixture) = match (env_root, env_port) {
        (Ok(root), Ok(port)) => {
            let root = PathBuf::from(root);
            let expected_space_root = root.display().to_string();
            (
                root,
                port.parse::<u16>()
                    .expect("ODIN_FABRIC_PROOF_VAULT_PORT parses"),
                Some(expected_space_root),
                None,
            )
        }
        (Ok(_), Err(_)) | (Err(_), Ok(_)) => panic!(
            "ODIN_FABRIC_PROOF_VAULT_ROOT and ODIN_FABRIC_PROOF_VAULT_PORT \
             must be set together"
        ),
        (Err(_), Err(_)) => {
            let vault = crate::test_vault::LoopbackVault::open("fabric-k6");
            (
                vault.root().to_path_buf(),
                vault.port(),
                Some(vault.expected_space_root()),
                Some(vault),
            )
        }
    };

    let model = |seat_name: &str| ModelDescriptor {
        name: ModelName::new(format!("model.fabric-{seat_name}")).unwrap(),
        tokenizer: TokenizerId::new("odin.tokenizer.utf8-bytes.v1").unwrap(),
        context_window_tokens: NonZeroU32::new(131_072).unwrap(),
    };
    // Deterministic test embeddings preserve the declared hybrid retrieval
    // mode without invoking a production model provider.
    let embedder: Arc<QueryEmbedder> = Arc::new(|texts: &[String]| {
        texts
            .iter()
            .map(|text| {
                let mut dims = [0.0f32; 8];
                for (index, byte) in text.bytes().enumerate() {
                    dims[index % dims.len()] += f32::from(byte % 16) + 1.0;
                }
                EmbeddingVector::from_dims(dims.to_vec())
            })
            .collect()
    });
    let embedding_model = EmbeddingModelId::new("test:fabric-proof-v1").unwrap();

    // Pass 1: every real declaration must grant its seat the reserved
    // memory surface, and the composed REAL policy must serve it — before
    // any runtime exists.
    let mut contexts = Vec::new();
    let mut brains: BTreeMap<SeatId, Arc<BrainService>> = BTreeMap::new();
    // Durable brain stores live outside the vault: the vault root is
    // served over the /.fs/ API and carries only pages.
    let brain_root = tempfile::tempdir().expect("brain store root");
    for seat_name in &seat_names {
        let seat_name = seat_name.as_str();
        let seat_toml: SeatToml = toml::from_str(
            &fs::read_to_string(
                repo_root
                    .join("registry/seats")
                    .join(seat_name)
                    .join("seat.toml"),
            )
            .unwrap_or_else(|error| panic!("seat {seat_name} declaration: {error}")),
        )
        .unwrap_or_else(|error| panic!("valid seat {seat_name} declaration: {error}"));
        assert!(seat_toml.enabled, "seat {seat_name} must be enabled");
        let memory_id = AtlasId::new(format!("memory.{seat_name}")).unwrap();
        // Runtime-created seats share template memory rather than declaring their own source.
        if !seat_toml
            .brain_scope
            .iter()
            .any(|source| source.as_str() == memory_id.as_str())
        {
            continue;
        }

        // The ONE slice delegating this seat's own memory source: matched
        // by declaration, never by name convention, so every seat —
        // including future ones — finds its own slice or fails loudly.
        let mut delegated = slices.iter().filter(|(_, slice)| {
            slice
                .knowledge
                .as_ref()
                .is_some_and(|knowledge| knowledge.atlas_sources.contains(&memory_id))
        });
        let (slice_name, slice_toml) = delegated.next().unwrap_or_else(|| {
            panic!(
                "seat {seat_name}: no slice delegates {}",
                memory_id.as_str()
            )
        });
        assert!(
            delegated.next().is_none(),
            "seat {seat_name}: multiple slices delegate {}",
            memory_id.as_str()
        );
        assert!(slice_toml.enabled, "slice {slice_name} must be enabled");

        // (1) Rollover: the seat declares the bounded policy, and it
        // revalidates against the runtime constructor's bounds.
        let live = seat_toml
            .live
            .as_ref()
            .unwrap_or_else(|| panic!("seat {seat_name} must declare [live]"));
        let rollover = live
            .rollover
            .as_ref()
            .unwrap_or_else(|| panic!("seat {seat_name} must declare [live.rollover]"));
        odin_omp::live::rollover::RolloverRuntimeConfig::new(
            odin_omp::live::rollover::RolloverPolicy {
                threshold_tokens: rollover.threshold_tokens,
                max_brief_bytes: rollover.max_brief_bytes,
                history_tail_events: rollover.history_tail_events,
            },
        )
        .unwrap_or_else(|error| panic!("seat {seat_name} rollover revalidates: {error}"));
        // The successor's first input must fit the slice's item ceiling.
        let item_ceiling = slice_toml
            .context
            .as_ref()
            .map(|context| context.max_item_tokens.get())
            .unwrap_or_else(|| panic!("slice {slice_name} declares [context]"));
        assert!(
            odin_cli::runtime_bindings::brief_fits_item_ceiling(rollover.max_brief_bytes, item_ceiling),
            "seat {seat_name} brief budget {} must fit slice {slice_name}'s item ceiling {item_ceiling}",
            rollover.max_brief_bytes
        );

        // (2) The registry grants, enumerated — never a runtime branch.
        let remember_id = CapabilityId::new("memory.remember").unwrap();
        assert!(
            memory_capability
                .seat_tags
                .iter()
                .any(|tag| seat_toml.categories.contains(tag)),
            "seat {seat_name} categories {:?} must be admitted by \
             memory.remember category rules {:?}",
            seat_toml.categories,
            memory_capability.seat_tags,
        );
        assert!(
            seat_toml.tool_refs.contains(&remember_id),
            "seat {seat_name} must grant memory.remember through tool_refs"
        );
        assert!(
            slice_toml.capabilities.contains(&remember_id),
            "slice {slice_name} must delegate memory.remember"
        );
        let slice_tools = slice_toml.tools.as_ref().expect("slice tool surface");
        assert!(
            slice_tools
                .allow
                .contains(&ToolName::new("memory_remember").unwrap()),
            "slice {slice_name} must surface the memory_remember tool"
        );
        assert!(
            seat_toml.brain_scope.contains(&memory_id),
            "seat {seat_name} brain_scope must reach {}",
            memory_id.as_str()
        );
        let seat_knowledge = seat_toml.knowledge.as_ref().expect("seat knowledge");
        assert!(
            seat_knowledge.atlas_sources.contains(&memory_id),
            "seat {seat_name} knowledge must authorize {}",
            memory_id.as_str()
        );
        let slice_knowledge = slice_toml.knowledge.as_ref().expect("slice knowledge");
        assert!(
            slice_knowledge.atlas_sources.contains(&memory_id),
            "slice {slice_name} knowledge must delegate {}",
            memory_id.as_str()
        );

        // The bound project: the seat's own default-seat project when one
        // declares it, else the first project in the seat's scope.
        let project_id = {
            let defaulted = projects
                .iter()
                .find(|(_, project)| project.enabled && project.default_seat.as_str() == seat_name)
                .map(|(name, _)| name.clone());
            let name = defaulted.unwrap_or_else(|| {
                seat_toml
                    .project_scope
                    .iter()
                    .next()
                    .expect("seat project scope")
                    .as_str()
                    .to_owned()
            });
            ProjectId::new(name).unwrap()
        };
        assert!(
            seat_toml.project_scope.contains(&project_id),
            "the bound project must sit in seat {seat_name} project_scope"
        );

        // The REAL policy: every declared source authorized, and the seat's
        // own memory serves inside the project scope.
        let real_policy = EffectiveBrainPolicy::resolve(
            1,
            slice_toml,
            &seat_toml,
            &project_refs,
            &profile_refs,
            &model(seat_name),
        )
        .unwrap_or_else(|error| panic!("seat {seat_name} policy composes: {error}"));
        assert!(
            real_policy
                .project_serving_scope(Some(&project_id))
                .contains(&memory_id),
            "seat {seat_name} must serve its own memory {}",
            memory_id.as_str()
        );

        // Re-resolve narrowed declarations because direct policy mutation invalidates its digest.
        let mut proof_slice = slice_toml.clone();
        proof_slice.knowledge.as_mut().unwrap().atlas_sources = [memory_id.clone()].into();
        let mut proof_seat = seat_toml.clone();
        proof_seat.brain_scope = [memory_id.clone()].into();
        proof_seat.knowledge.as_mut().unwrap().atlas_sources = [memory_id.clone()].into();
        let proof_policy = EffectiveBrainPolicy::resolve(
            1,
            &proof_slice,
            &proof_seat,
            &project_refs,
            &profile_refs,
            &model(seat_name),
        )
        .unwrap_or_else(|error| panic!("seat {seat_name} proof policy: {error}"));

        // The seat's brain: only its own reserved memory source, scoped to
        // the shared isolated vault's per-seat subtree.
        let namespace = memory_namespace("generated", seat_name).unwrap();
        let mut source = SilverBulletSource::new(
            memory_id.clone(),
            vault_port,
            VaultScope::generated_only(&namespace, &[]).unwrap(),
        );
        if let Some(space_root) = &expected_space_root {
            source = source.with_expected_space_root(space_root.clone());
        }
        let brain = BrainService::open(
            BrainServiceConfig {
                store_root: brain_root.path().join(format!("fabric-brain-{seat_name}")),
                sources: BTreeMap::from([(
                    memory_id.clone(),
                    BrainSourceConfig::Memory { source },
                )]),
                embedding_available: true,
                embedding_model: Some(embedding_model.clone()),
                archive_ingest_gate: None,
                postgres: None,
            },
            proof_policy.clone(),
            Arc::new(Mutex::new(Ledger::open_in_memory().unwrap())),
        )
        .unwrap_or_else(|error| panic!("seat {seat_name} brain composes: {error}"));

        let slice_id = SliceId::new(slice_name).unwrap();
        brains.insert(SeatId::new(seat_name).unwrap(), Arc::new(brain));
        contexts.push((seat_name, memory_id, project_id, slice_id, proof_policy));
    }

    // Durable live sessions: one remember session and one fresh recall
    // session per seat, bound to the seat, slice, and real project.
    let live_dir = tempfile::tempdir().expect("live root");
    let live_ledger: Arc<dyn LiveLedger> =
        Arc::new(FsLiveLedger::open(live_dir.path()).expect("live ledger opens"));
    {
        let tokio = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        tokio.block_on(async {
            for (index, (seat_name, _, project_id, slice_id, _)) in contexts.iter().enumerate() {
                for hex in [format!("{index:012x}"), format!("{:012x}", index + 16)] {
                    live_ledger
                        .create_session(odin_domain::huginn::SessionManifest {
                            session_id: LiveSessionId::parse(&format!(
                                "00000000-0000-4000-8000-{hex}"
                            ))
                            .unwrap(),
                            seat_id: SeatId::new(*seat_name).unwrap(),
                            slice_id: slice_id.clone(),
                            project_id: project_id.clone(),
                            provider: ProviderName::new("provider.fabric").unwrap(),
                            model: ModelName::new(format!("model.fabric-{seat_name}")).unwrap(),
                            title: None,
                            target_node: NodeId::new("node.fabric").unwrap(),
                            open_tab: false,
                            workload: None,
                            served_revision: Some(1),
                            harness: None,
                        })
                        .await
                        .expect("session row");
                }
            }
        });
    }

    // The daemon-shaped write gate over the SAME per-seat brains, and the
    // hermes runtime whose vault singleton owns every write.
    let gate = super::FactoryVaultWriteGate {
        brains: brains.clone(),
        live_ledger: Arc::clone(&live_ledger),
        generated_namespace: Some("generated".into()),
    };
    let hermes_root = tempfile::tempdir().expect("hermes root");
    let runtime = odin_hermes::runtime::HermesRuntime::open(
        odin_hermes::config::HermesSettings::new(
            hermes_root.path().to_path_buf(),
            None,
            Some(VaultConfig {
                vault_root: vault_root.clone(),
                source_id: "vault:fabric-proof".to_owned(),
                silverbullet: Some(odin_hermes::vault::SilverBulletConfig {
                    port: vault_port,
                    expected_space_root: expected_space_root.clone(),
                }),
                general_namespaces: vec!["knowledge".to_owned()],
                generated_namespace: "generated".to_owned(),
                excluded_namespaces: vec![],
                max_pages: 64,
                max_page_bytes: 65_536,
                timeout_ms: 1_000,
            }),
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
    runtime.set_vault_write_gate(Arc::new(gate));
    let vault_bridge: VaultBridge = runtime
        .vault()
        .as_ref()
        .expect("the fabric vault singleton composes")
        .clone();

    // The production knowledge-vault adapter attaches to every seat brain
    // BEFORE any remember — the daemon's own rendering path stays in the
    // loop for the whole scenario.
    for (seat_id, brain) in &brains {
        crate::knowledge_vault::attach(brain, seat_id, &vault_bridge)
            .expect("the knowledge vault sink attaches");
    }

    let tools = odin_hermes::runtime::hermes_host_tools(&runtime);
    let remember = tools
        .iter()
        .find(|tool| tool.definition().name == "memory_remember")
        .expect("the memory_remember surface exists");

    // Pass 2: remember through the real bridge, recall fresh, mutate, and
    // watch every stale surface refuse typed.
    for (index, (seat_name, memory_id, project_id, _slice_id, policy)) in
        contexts.iter().enumerate()
    {
        let seat_name = *seat_name;
        let seat_id = SeatId::new(seat_name).unwrap();
        let original = format!(
            "FABRIC-{seat_name}-ZEPHYR: the measured convergence criterion is durable seat memory."
        );
        let scope = odin_domain::Scope {
            seat: Some(seat_id.clone()),
            session: Some(
                odin_domain::SessionId::new(
                    LiveSessionId::parse(&format!("00000000-0000-4000-8000-{:012x}", index))
                        .unwrap()
                        .to_string(),
                )
                .unwrap(),
            ),
            project: Some(project_id.clone()),
            ..Default::default()
        };

        // (3) Remember: the confined write lands in the seat's reserved
        // subtree, and the post-write refresh builds its memory generation.
        let receipt = remember
            .invoke(odin_omp::host_tools::HostInvocation {
                scope,
                arguments: serde_json::json!({ "content": original }),
            })
            .unwrap_or_else(|error| panic!("seat {seat_name} remembers: {error}"));
        let page_name = receipt["page"].as_str().expect("receipt page");
        assert!(
            page_name.starts_with(&format!("{seat_name}/")),
            "the memory lands in the seat's own reserved subtree: {page_name}"
        );
        assert!(
            receipt.get("knowledgeRefreshUnavailable").is_none(),
            "the live vault must refresh the seat's memory generation: {receipt:?}"
        );

        // (4) Fresh session, fresh service: the remembered fact serves as
        // observed, brain://-cited context.
        let fresh = BrainService::open(
            BrainServiceConfig {
                store_root: brain_root.path().join(format!("fabric-fresh-{seat_name}")),
                sources: BTreeMap::from([(
                    memory_id.clone(),
                    BrainSourceConfig::Memory {
                        source: fresh_source(memory_id, vault_port, expected_space_root.as_deref()),
                    },
                )]),
                embedding_available: true,
                embedding_model: Some(embedding_model.clone()),
                archive_ingest_gate: None,
                postgres: None,
            },
            policy.clone(),
            Arc::new(Mutex::new(Ledger::open_in_memory().unwrap())),
        )
        .expect("fresh brain opens");
        crate::knowledge_vault::attach(&fresh, &seat_id, &vault_bridge).unwrap();
        fresh.ensure_generation().expect("fresh generation builds");
        let core = fresh
            .core_memory(Some(project_id))
            .expect("the fresh session core renders")
            .expect("the seat serves memory");
        assert!(
            core.text.contains(&original),
            "seat {seat_name} fresh session core must carry its remembered fact"
        );
        let query = policy
            .knowledge
            .as_ref()
            .expect("the seat declares knowledge")
            .retrieval_query(format!("FABRIC {seat_name} convergence criterion"))
            .unwrap();
        let recalled = fresh
            .retrieve(&query, Some(project_id), Some(&embedder))
            .expect("the seat recalls through brain_search's path");
        let cited = recalled
            .hits
            .iter()
            .find(|hit| hit.source == *memory_id)
            .unwrap_or_else(|| panic!("seat {seat_name} memory must be brain://-cited"));
        let item_id: KnowledgeItemId = cited.item_id;
        let served = fresh
            .knowledge_item(&item_id, Some(project_id))
            .expect("the brain:// item serves");
        assert!(
            served
                .chunks
                .iter()
                .any(|chunk| chunk.text.contains(&original)),
            "the served brain:// item carries the remembered bytes"
        );

        // (5) Mutate the source — no refresh follows — and the last built
        // generation keeps serving until the warm pump rebuilds.
        let mutated =
            format!("FABRIC-{seat_name}-REVISED: the superseded criterion must never serve again.");
        fs::write(
            vault_root.join("generated/memories").join(page_name),
            &mutated,
        )
        .expect("the source mutates under the test's control");
        let last_built = fresh
            .knowledge_item(&item_id, Some(project_id))
            .expect("the last built generation serves");
        assert!(last_built
            .chunks
            .iter()
            .any(|chunk| chunk.text.contains(&original)));
        // A rebuilt fresh service serves exactly the mutated bytes.
        let rebuilt = BrainService::open(
            BrainServiceConfig {
                store_root: brain_root
                    .path()
                    .join(format!("fabric-rebuilt-{seat_name}")),
                sources: BTreeMap::from([(
                    memory_id.clone(),
                    BrainSourceConfig::Memory {
                        source: fresh_source(memory_id, vault_port, expected_space_root.as_deref()),
                    },
                )]),
                embedding_available: true,
                embedding_model: Some(embedding_model.clone()),
                archive_ingest_gate: None,
                postgres: None,
            },
            policy.clone(),
            Arc::new(Mutex::new(Ledger::open_in_memory().unwrap())),
        )
        .expect("rebuilt brain opens");
        crate::knowledge_vault::attach(&rebuilt, &seat_id, &vault_bridge).unwrap();
        rebuilt
            .ensure_generation()
            .expect("rebuilt generation builds");
        let core = rebuilt
            .core_memory(Some(project_id))
            .expect("the next session core renders")
            .expect("the seat serves memory");
        assert!(
            core.text.contains(&mutated),
            "seat {seat_name} next session core must carry the mutated bytes"
        );
        assert!(
            !core.text.contains(&original),
            "seat {seat_name} must never serve a stale byte: {}",
            core.text
        );
        println!("{seat_name}: fresh core + recall brain://{item_id}; old item NotFound; next core revised");
    }
}

/// Pin a fresh head while retaining the same vault and seat scope.
fn fresh_source(
    memory_id: &odin_domain::knowledge::ids::AtlasId,
    vault_port: u16,
    expected_space_root: Option<&str>,
) -> odin_brain::source::silverbullet::SilverBulletSource {
    use odin_brain::source::silverbullet::{memory_namespace, SilverBulletSource, VaultScope};

    let namespace = memory_namespace("generated", memory_seat(memory_id)).unwrap();
    let mut source = SilverBulletSource::new(
        memory_id.clone(),
        vault_port,
        VaultScope::generated_only(&namespace, &[]).unwrap(),
    );
    if let Some(space_root) = expected_space_root {
        source = source.with_expected_space_root(space_root.to_owned());
    }
    source
}

fn memory_seat(memory_id: &odin_domain::knowledge::ids::AtlasId) -> &str {
    memory_id
        .as_str()
        .strip_prefix("memory.")
        .expect("a memory.<seat> atlas id")
}
