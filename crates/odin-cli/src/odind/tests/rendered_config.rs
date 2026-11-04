//! The renderer's shapes, loaded the way odind loads them, against the
//! shipped registry published through the production path: `[models]` keyed
//! by bare lanes (`odin-architect.nix`), bare seat launch options, and the
//! fleet projection with bare `gateway_lane_id`s (`odin-fleet.nix`).

use super::*;
use std::fs;
use std::path::PathBuf;

use odin_registry::{GatewayProjectionRoute, ObjectConfig, ValidatedSnapshotCandidate};

use crate::test_fixture::copy_tree;
use crate::test_support::{commit_all, git};

/// Publish the working tree's registry as revision 1 of a fresh store.
fn publish_shipped(root: &Path) -> (PathBuf, Arc<odin_registry::Snapshot>) {
    let repository = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let worktree = root.join("authoring");
    fs::create_dir_all(&worktree).expect("create authoring worktree");
    git(&worktree, &["-c", "init.defaultBranch=main", "init", "-q"]);
    for directory in ["registry", "schemas"] {
        copy_tree(&repository.join(directory), &worktree.join(directory));
    }
    let commit = commit_all(&worktree, "shipped registry");
    let candidate = ValidatedSnapshotCandidate::from_committed_worktree(
        &worktree,
        &commit,
        odin_cli::runtime_bindings::admitted_registry_bindings(),
    )
    .expect("the shipped registry is a valid candidate");
    let snapshot = root.join("state/registry/snapshot.json");
    SnapshotStore::new(&snapshot)
        .publish_committed(&candidate, 1)
        .expect("publish the shipped registry");
    let pinned = SnapshotHandle::open(SnapshotStore::new(&snapshot))
        .expect("open the published store")
        .current();
    (snapshot, pinned)
}

/// The gateway model cards as the renderer projects them: bare lane, card.
fn gateway_cards(
    snapshot: &odin_registry::Snapshot,
) -> Vec<(String, odin_registry::ModelCardToml)> {
    snapshot
        .objects
        .iter()
        .filter_map(|object| match &object.config {
            ObjectConfig::Model(card) if card.enabled => {
                card.lane().map(|lane| (lane.to_owned(), (**card).clone()))
            }
            _ => None,
        })
        .collect()
}

#[test]
fn renderer_shaped_config_and_projection_load_with_bare_lanes() {
    let fixture = tempfile::TempDir::new().expect("temporary directory");
    let root = fixture.path();
    let (snapshot_path, snapshot) = publish_shipped(root);
    let cards = gateway_cards(&snapshot);

    let mut config = OdindConfig::parse(&crate::test_fixture::fixture_config_text(
        root,
        &snapshot_path,
    ))
    .expect("fixture config");
    config.paths.authoring_repository = Some(root.join("projects/odin"));
    config.paths.authoring_worktree = Some(root.join("state/authoring/odin"));
    for (lane, card) in &cards {
        config.models.lanes.insert(
            lane.clone(),
            odin_huginn::OdindModelLaneConfig {
                seats: card.seats,
                strengths: card.strengths.clone(),
                tier: card.tier.clone(),
                display_name: card.description.clone(),
                context_window: 200_000,
                cost: odin_huginn::OdindModelCost {
                    input: "0".to_owned(),
                    output: "0".to_owned(),
                },
                billing: "subscription".to_owned(),
            },
        );
    }
    config.seats.push(odin_huginn::OdindSeatBinding {
        seat: "architect".parse().expect("seat id"),
        slice: "architect-engine".parse().expect("slice id"),
        display_name: "Architect".to_owned(),
        max_sessions: 4,
        launch_options: vec![live::LiveLaunchOption {
            provider: "gateway".parse().expect("provider"),
            model: "zai-glm".parse().expect("model"),
            skeleton_ref: "architect-native".to_owned(),
            container_id: "architect-native".parse().expect("container id"),
            harness: None,
        }],
        allowed_nodes: vec!["laptop".parse().expect("node id")],
        runtime: false,
    });
    let path = root.join("odind.toml");
    fs::write(&path, toml::to_string(&config).expect("render config")).expect("write config");
    let loaded = OdindConfig::load(&path).expect("the bare-lane config loads");
    let architect = loaded
        .seats
        .iter()
        .find(|seat| seat.seat.as_str() == "architect")
        .expect("architect seat");
    assert!(architect.launch_options.len() > 1);
    for option in &architect.launch_options {
        assert!(
            loaded.models.lanes.contains_key(option.model.as_str()),
            "architect launch model {} is a declared bare lane",
            option.model
        );
    }

    // Lanes keyed by card id are refused by name.
    let mut card_keyed = config.clone();
    card_keyed.models.lanes = config
        .models
        .lanes
        .iter()
        .map(|(lane, declared)| (format!("gateway/{lane}"), declared.clone()))
        .collect();
    fs::write(&path, toml::to_string(&card_keyed).expect("render config")).expect("write config");
    let error = OdindConfig::load(&path).expect_err("card-id keys are not lanes");
    assert!(
        error.to_string().contains("not a declared model lane"),
        "{error}"
    );

    // The fleet projection: every seat lane and the embedding lane, keyed bare.
    let routes = cards
        .iter()
        .filter(|(_, card)| card.seats || card.capability == "embedding")
        .map(|(lane, card)| {
            let embedding = card.capability == "embedding";
            GatewayProjectionRoute {
                gateway_lane_id: lane.clone(),
                gateway_model_id: if embedding {
                    lane.clone()
                } else {
                    // A local card serves its lane at the host endpoint.
                    card.served
                        .clone()
                        .unwrap_or_else(|| format!("openai/{lane}"))
                },
                account_handle: "litellm-loopback".to_owned(),
                endpoint: "http://127.0.0.1:4000/v1".to_owned(),
                credential_handle: "litellm-master-key".to_owned(),
                role: if embedding { "embedding" } else { "coding" }.to_owned(),
                affinity_key: lane.clone(),
                eligible: true,
            }
        })
        .collect();
    let manifest = odin_registry::GatewayProjectionManifest::build(routes)
        .expect("bare lane ids are stable ids");
    let bytes = serde_json::to_vec(&manifest).expect("projection bytes");
    let projection_path = root.join("projection.json");
    fs::write(&projection_path, &bytes).expect("write projection");
    let mut config = loaded;
    config.catalogs.gateway_projection = odin_huginn::PathDigestRef {
        path: projection_path,
        digest: Digest::hash(&bytes).to_string(),
    };
    let projection = load_gateway_projection(&config).expect("the fleet projection loads");

    // The embedding route the registry declares is the one the fleet
    // projects; the wire model is the bare lane (LiteLLM's model_name), the
    // protocol suffix only the index identity.
    let policy = odin_registry::resolve_provider_policy(
        &snapshot,
        &ProviderId::new("brain-embedding").expect("provider id"),
        &projection,
    )
    .expect("brain-embedding resolves against the fleet projection");
    let [route] = policy.routes.as_slice() else {
        panic!("one embedding route");
    };
    assert_eq!(route.gateway_model_id, "wemm-embedding");
    assert_eq!(
        effective_embedding_model(route).expect("model id").as_str(),
        "wemm-embedding:wemm-im-user-v2"
    );

    // A workload row keyed by a session lane derives from the bare carrier.
    assert_eq!(
        workload_gateway_credential(&projection, "gungnir-odin", "zai-glm"),
        Ok("litellm-master-key".to_owned())
    );
}
