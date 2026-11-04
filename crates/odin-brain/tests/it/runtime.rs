//! `BrainService` runtime composition contracts.
//!
//! Defends the observable serving behavior of the composed service over a
//! real Atlas fixture and the real loopback vault source contract:
//! - An absent knowledge policy composes no serving surface; the affected
//!   operations fail typed-unavailable and nothing else degrades.
//! - The wired source set must equal the policy's authorized set exactly.
//! - One generation per Atlas source, merged candidate pools across sources,
//!   and `brain://`-shaped item resolution with real node provenance.
//! - A wired vault that is not serving fails typed (`Unavailable`, named
//!   component) — never silently partial results.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};

use odin_brain::config::EffectiveBrainPolicy;
use odin_brain::context::PinnedTokenizer;
use odin_brain::error::{BrainError, BrainResult};
use odin_brain::index::postgres::BrainPostgres;
use odin_brain::service::{BrainService, BrainServiceConfig, BrainSourceConfig};
use odin_brain::test_cluster::TestCluster;
use odin_domain::huginn::ids::ModelName;
use odin_domain::knowledge::retrieval::ModelDescriptor;
use odin_domain::knowledge::{AtlasId, EmbeddingBackend, RetrievalMode};
use odin_domain::Digest;
use odin_registry::schema::{SeatToml, SliceToml};

use crate::support::{self, atlas_ids, atlas_root, atlas_source, config_with, ledger, nz32};

#[path = "runtime/live_memory.rs"]
mod live_memory;
#[path = "runtime/project_sources.rs"]
mod project_sources;

const ATLAS_FIXTURE_ID: &str = "atlas:runtime-fixture";
const VAULT_FIXTURE_ID: &str = "vault:silverbullet";
/// A loopback port no test server listens on: the vault source must fail
/// typed instead of hanging or faking content.
const DEAD_VAULT_PORT: u16 = 1;

/// The fixture slice: no context block, and no knowledge when it names no source.
fn slice(sources: &[&str]) -> SliceToml {
    let mut slice = support::slice(sources, RetrievalMode::Lexical, EmbeddingBackend::Local);
    slice.context = None;
    if sources.is_empty() {
        slice.knowledge = None;
    }
    slice
}

/// The fixture seat: it may read the fixture and vault sources, with no
/// context block, and no knowledge when `sources` is empty.
fn seat(sources: &[&str]) -> SeatToml {
    let mut seat = support::seat(sources, &[]);
    seat.brain_scope = atlas_ids(&[ATLAS_FIXTURE_ID, "atlas:runtime-second", VAULT_FIXTURE_ID]);
    seat.context = None;
    if sources.is_empty() {
        seat.knowledge = None;
    }
    seat
}

fn config(sources: BTreeMap<AtlasId, BrainSourceConfig>) -> (TestCluster, BrainServiceConfig) {
    config_with(sources, None)
}

fn model() -> ModelDescriptor {
    ModelDescriptor {
        name: ModelName::new("model.runtime").unwrap(),
        tokenizer: PinnedTokenizer::id().unwrap(),
        context_window_tokens: nz32(8192),
    }
}

fn resolve(atlas_sources: &[&str]) -> EffectiveBrainPolicy {
    EffectiveBrainPolicy::resolve(
        74,
        &slice(atlas_sources),
        &seat(atlas_sources),
        &BTreeMap::new(),
        &std::collections::BTreeMap::new(),
        &model(),
    )
    .unwrap()
}

fn config_at(
    store_root: &std::path::Path,
    postgres: Arc<BrainPostgres>,
    sources: BTreeMap<AtlasId, BrainSourceConfig>,
) -> BrainServiceConfig {
    BrainServiceConfig {
        store_root: store_root.to_path_buf(),
        sources,
        embedding_available: false,
        embedding_model: None,
        archive_ingest_gate: None,
        postgres,
        rerank: None,
    }
}

fn dead_vault() -> (AtlasId, BrainSourceConfig) {
    (
        AtlasId::new(VAULT_FIXTURE_ID).unwrap(),
        BrainSourceConfig::SilverBullet {
            port: DEAD_VAULT_PORT,
            expected_space_root: Some("/srv/vault".to_owned()),
            general_namespaces: vec!["knowledge".to_owned()],
            generated_namespace: "generated".to_owned(),
            excluded_namespaces: vec!["finance".to_owned()],
            max_pages: 100,
        },
    )
}

/// Unwraps an `open` failure without requiring `Debug` on the service:
/// the error side carries the typed contract under test.
fn open_err(result: BrainResult<BrainService>) -> BrainError {
    match result {
        Err(error) => error,
        Ok(_) => panic!("brain service open must fail for this configuration"),
    }
}

/// Seats that reach the curated sources get a card for each record a turn names:
/// not the owner's own, not past the per-turn cap, none on harness text.
#[test]
fn named_cards_follow_the_owners_words_and_skip_the_owner_and_the_held() {
    let personal = atlas_root("personal", "personal_fn");
    let curated = atlas_root("curated", "curated_fn");
    let ids = ["atlas.personal", "archive.curated"];
    let mut declared_seat = seat(&ids);
    declared_seat.brain_scope = atlas_ids(&ids);
    declared_seat.profile_namespace = Some(AtlasId::new("memory.owner").unwrap());
    let policy = EffectiveBrainPolicy::resolve(
        74,
        &slice(&ids),
        &declared_seat,
        &BTreeMap::new(),
        &BTreeMap::new(),
        &model(),
    )
    .unwrap();
    let (cluster, cfg) = config(BTreeMap::from([
        atlas_source(ids[0], personal.path()),
        atlas_source(ids[1], curated.path()),
    ]));
    let service = BrainService::open(cfg, policy, ledger()).unwrap();
    cluster.sql(
        "INSERT INTO brain_person (slug, name, record, source_path, local_only, doc) VALUES \
           ('varun', 'Varun Rodriguez', '{}', 'people.toml', false, 'Varun Rodriguez'), \
           ('priya', 'Priya', '{}', 'people.toml', false, 'Priya'), \
           ('sam', 'Sam', '{}', 'people.toml', false, 'Sam'), \
           ('lee', 'Lee', '{}', 'people.toml', false, 'Lee'), \
           ('colin-g', 'the owner Gray', '{}', 'people.toml', false, 'the owner Gray'); \
         INSERT INTO brain_person_handle VALUES \
           ('varun', 'name', '', 'Varun Rodriguez'), ('priya', 'name', '', 'Priya'), \
           ('sam', 'name', '', 'Sam'), ('lee', 'name', '', 'Lee'), \
           ('colin-g', 'name', '', 'the owner'); \
         INSERT INTO brain_channel (channel_id, server_id, server, name, kind) VALUES \
           ('dm', NULL, 'Direct', 'dm', 'DM');",
    );
    let names = |text: &str, skip: &[&str], owner: bool| -> Vec<String> {
        let skip = skip.iter().map(|id| (*id).to_owned()).collect();
        service
            .named_records(text, None, &skip, owner)
            .unwrap()
            .into_iter()
            .map(|(id, _)| id)
            .collect()
    };

    let said = "ask Varun Rodriguez, Priya, Sam and Lee about the owner";
    assert_eq!(
        names(said, &[], true),
        ["person:varun", "person:priya", "person:sam"]
    );
    assert_eq!(
        names(said, &["person:varun"], true),
        ["person:priya", "person:sam", "person:lee"]
    );
    assert!(
        names(said, &[], false).is_empty(),
        "harness text names nothing"
    );
    let cards = service
        .named_records("ask Varun Rodriguez", None, &BTreeSet::new(), true)
        .unwrap();
    assert!(cards[0].1.starts_with("person varun: ") && cards[0].1.contains("Varun Rodriguez"));
}

/// The single-Atlas smoke: real Atlas build, per-head generation, lexical
/// retrieval over the merged pool, and brain://-shaped item resolution with
/// real node provenance.
#[test]
fn atlas_service_serves_generation_retrieval_and_item() {
    let root = atlas_root("demo", "alpha_add");
    let policy = resolve(&[ATLAS_FIXTURE_ID]);
    let sources = BTreeMap::from([atlas_source(ATLAS_FIXTURE_ID, root.path())]);
    let (_store, cfg) = config(sources);
    let service = BrainService::open(cfg, policy.clone(), ledger()).unwrap();

    let generations = service.ensure_generation().unwrap();
    assert_eq!(generations.len(), 1, "one generation per composed source");
    assert_eq!(generations[0].atlas_id.as_str(), ATLAS_FIXTURE_ID);

    let status = service.status().unwrap();
    let fixture_id = AtlasId::new(ATLAS_FIXTURE_ID).unwrap();
    assert!(
        status.pinned.contains_key(&fixture_id),
        "status pins the live source head"
    );
    assert!(
        status.generations.contains_key(&fixture_id),
        "status serves the generation built for the live head"
    );

    let knowledge = policy.knowledge.as_ref().unwrap();
    let query = knowledge.retrieval_query("alpha_add".to_owned()).unwrap();
    let hits = service.retrieve(&query, None, None).unwrap().hits;
    assert!(!hits.is_empty(), "the fixture function must be retrievable");
    assert!(
        hits.iter()
            .all(|hit| hit.source.as_str() == ATLAS_FIXTURE_ID),
        "every hit cites its composing source"
    );

    let item = service.knowledge_item(&hits[0].item_id, None).unwrap();
    assert_eq!(&item.generation, &generations[0]);
    let provenance = item.provenance.expect("Atlas items carry node provenance");
    assert!(
        provenance.path.contains("demo"),
        "provenance names the fixture source path: {:?}",
        provenance.path
    );
    assert!(!item.chunks.is_empty());
}

/// A warmed turn serves every source's generation from the PostgreSQL store.
#[test]
fn a_turn_serves_from_the_postgres_store_once_its_generations_are_sealed() {
    let ids = [ATLAS_FIXTURE_ID, "atlas:runtime-second"];
    let policy = resolve(&ids);
    let alpha = atlas_root("alpha", "alpha_add");
    let beta = atlas_root("beta", "beta_mul");
    let sources = BTreeMap::from([
        atlas_source(ids[0], alpha.path()),
        atlas_source(ids[1], beta.path()),
    ]);
    let (cluster, served_cfg) = config(sources);
    let served = BrainService::open(served_cfg, policy.clone(), ledger()).unwrap();
    assert_eq!(served.warm(dead_lane().as_ref(), 4_096).unwrap(), 0);
    let knowledge = policy.knowledge.as_ref().unwrap();
    for (needle, source) in [("alpha_add", ids[0]), ("beta_mul", ids[1])] {
        let query = knowledge.retrieval_query(needle.to_owned()).unwrap();
        let hits = served.retrieve(&query, None, None).unwrap().hits;
        assert_eq!(hits[0].source.as_str(), source, "{needle}: {hits:?}");
    }
    assert_eq!(cluster.sql("SELECT count(*) FROM brain_generation"), "2");
}

/// With the PostgreSQL store unreachable a turn fails typed.
#[test]
fn a_turn_fails_while_the_postgres_store_is_down() {
    let ids = [ATLAS_FIXTURE_ID];
    let policy = resolve(&ids);
    let alpha = atlas_root("alpha", "alpha_add");
    let sources = BTreeMap::from([atlas_source(ids[0], alpha.path())]);
    let (cluster, cfg) = config(sources);
    let served = BrainService::open(cfg, policy.clone(), ledger()).unwrap();
    assert_eq!(served.warm(dead_lane().as_ref(), 4_096).unwrap(), 0);
    let knowledge = policy.knowledge.as_ref().unwrap();
    let query = knowledge.retrieval_query("alpha_add".to_owned()).unwrap();
    let hits = served.retrieve(&query, None, None).unwrap().hits;
    assert_eq!(hits[0].source.as_str(), ids[0]);

    // Stop the throwaway cluster for real: the conninfo's host is its
    // private socket directory, the data dir sits under it.
    let socket_dir = cluster
        .conninfo
        .split_once("host=")
        .and_then(|(_, rest)| rest.split_whitespace().next())
        .unwrap();
    let stopped = std::process::Command::new("pg_ctl")
        .args(["--mode=immediate", "--pgdata"])
        .arg(format!("{socket_dir}/data"))
        .arg("stop")
        .output()
        .unwrap();
    assert!(
        stopped.status.success(),
        "{}",
        String::from_utf8_lossy(&stopped.stderr)
    );
    assert!(
        matches!(
            served.retrieve(&query, None, None),
            Err(BrainError::Unavailable { .. })
        ),
        "a down store is the typed outage, not a policy or authority refusal"
    );
}

/// Unrequested sources are neither pinned nor built, so their outages cannot fail a search.
#[test]
fn a_scoped_search_serves_its_source_while_an_unrequested_vault_is_down() {
    let root = atlas_root("demo", "alpha_add");
    let policy = resolve(&[ATLAS_FIXTURE_ID, VAULT_FIXTURE_ID]);
    let sources = BTreeMap::from([atlas_source(ATLAS_FIXTURE_ID, root.path()), dead_vault()]);
    let (_store, cfg) = config(sources);
    let service = BrainService::open(cfg, policy.clone(), ledger()).unwrap();
    service
        .ensure_source_generation(&AtlasId::new(ATLAS_FIXTURE_ID).unwrap())
        .unwrap();
    let knowledge = policy.knowledge.as_ref().unwrap();
    let mut query = knowledge.retrieval_query("alpha_add".to_owned()).unwrap();

    query.sources = atlas_ids(&[ATLAS_FIXTURE_ID]);
    let served = service.retrieve(&query, None, None).unwrap();
    assert!(
        served
            .hits
            .iter()
            .any(|hit| hit.content.contains("alpha_add")),
        "the requested source serves: {:?}",
        served.hits
    );
    assert!(
        served
            .hits
            .iter()
            .all(|hit| hit.source.as_str() == ATLAS_FIXTURE_ID),
        "only the requested source serves: {:?}",
        served.hits
    );

    query.sources = atlas_ids(&[VAULT_FIXTURE_ID]);
    let error = service.retrieve(&query, None, None).unwrap_err();
    assert!(
        matches!(
            &error,
            BrainError::Unavailable {
                component: "silverbullet",
                ..
            }
        ),
        "a requested source that is down refuses typed: {error:?}"
    );
}

#[test]
fn a_live_head_change_serves_the_last_built_generation_until_the_pump_rebuilds() {
    use odin_brain::source::state::live::LiveSource;
    use odin_domain::huginn::{
        Freshness, FreshnessState, ObjectKind, ObjectRef, Revision, RevisionSource,
    };
    use odin_huginn::read_model::MaterializedReadModel;

    let now = time::OffsetDateTime::UNIX_EPOCH;
    let read_model = MaterializedReadModel::new(16, now);
    // A session as odind stores it, through project_object.
    let snapshot = |revision, status: &str| {
        let at = serde_json::to_value(now).unwrap();
        let summary = serde_json::json!({
            "sessionId": "00000000-0000-4000-8000-000000000001", "epoch": 1,
            "seatId": "sinmara", "provider": "zai", "model": "glm-5", "title": null,
            "state": status, "startedAt": at, "updatedAt": at, "eventHead": 0,
            "terminalHead": 0, "pendingPermissionCount": 0,
        });
        odin_huginn::read_model::project_object(
            ObjectRef {
                kind: ObjectKind::Session,
                id: "session-k1".into(),
            },
            Revision::new(revision),
            RevisionSource::Omp,
            Freshness {
                state: FreshnessState::Fresh,
                observed_at: now,
                source_updated_at: Some(now),
                stale_after_seconds: None,
            },
            &summary,
            &odin_huginn::read_model::ProjectionMetadata::new("session-k1", "session"),
        )
        .unwrap()
    };
    read_model.upsert(snapshot(1, "running")).unwrap();
    let id = AtlasId::new("state.live").unwrap();
    let source = LiveSource::new(id.clone(), read_model.clone());
    let (old_head, items) = source.pin().unwrap();
    let item_id = items
        .iter()
        .find(|item| item.text.contains("session-k1"))
        .unwrap()
        .item_id;
    let mut declared_seat = seat(&["state.live"]);
    declared_seat.brain_scope = atlas_ids(&["state.live"]);
    let policy = EffectiveBrainPolicy::resolve(
        74,
        &slice(&["state.live"]),
        &declared_seat,
        &BTreeMap::new(),
        &std::collections::BTreeMap::new(),
        &model(),
    )
    .unwrap();
    let directory = TestCluster::start();
    let configuration = config_at(
        &directory.path(),
        directory.store(),
        BTreeMap::from([(id.clone(), BrainSourceConfig::StateLive { source })]),
    );
    let service = BrainService::open(configuration, policy, ledger()).unwrap();
    service.ensure_state_generations().unwrap();
    let query = service
        .policy()
        .knowledge
        .as_ref()
        .unwrap()
        .retrieval_query("session sinmara running".to_owned())
        .unwrap();
    let response = service.retrieve(&query, None, None).unwrap();
    assert!(response.hits.iter().any(|hit| hit.item_id == item_id
        && hit.content.contains("running")
        && hit.citation.source_revision == old_head));
    let old = service.knowledge_item(&item_id, None).unwrap();
    assert!(old
        .chunks
        .iter()
        .any(|chunk| chunk.text.contains("running")));
    assert!(old
        .chunks
        .iter()
        .all(|chunk| chunk.citation.source_revision == old_head));

    // The turn never builds: until the pump rebuilds, the last built
    // generation serves, and the item it cites still resolves.
    read_model.upsert(snapshot(2, "ended")).unwrap();
    let raced = service.retrieve(&query, None, None).unwrap();
    assert!(raced
        .hits
        .iter()
        .any(|hit| hit.item_id == item_id && hit.citation.source_revision == old_head));
    assert!(service
        .knowledge_item(&item_id, None)
        .unwrap()
        .chunks
        .iter()
        .any(|chunk| chunk.text.contains("running")));
    service.ensure_state_generations().unwrap();
    let current = service.knowledge_item(&item_id, None).unwrap();
    assert_ne!(current.generation.atlas_revision, old_head);
    assert!(current
        .chunks
        .iter()
        .any(|chunk| chunk.text.contains("ended")));
    assert!(!current
        .chunks
        .iter()
        .any(|chunk| chunk.text.contains("running")));
    let refreshed = service.retrieve(&query, None, None).unwrap();
    assert!(refreshed
        .hits
        .iter()
        .any(|hit| hit.item_id == item_id && hit.content.contains("ended")));
    assert!(refreshed
        .hits
        .iter()
        .all(|hit| hit.citation.source_revision != old_head));

    // A restarted read model can reuse a numeric revision, but never an old
    // generation whose authoritative content was different.
    let restarted = MaterializedReadModel::new(16, now);
    restarted.upsert(snapshot(1, "failed")).unwrap();
    let restarted_source = LiveSource::new(id, restarted);
    assert_ne!(restarted_source.pin().unwrap().0, old_head);
}

#[test]
fn fleet_live_objects_surface_as_citable_items() {
    use odin_brain::source::state::live::LiveSource;
    use odin_domain::huginn::{
        FleetHostView, FleetPlacementView, FleetTailnetState, Freshness, FreshnessState,
        KubeNodeState, ObjectKind, ObjectRef, ObjectSnapshot, Revision, RevisionSource,
    };
    use odin_huginn::read_model::MaterializedReadModel;

    let now = time::OffsetDateTime::UNIX_EPOCH;
    let read_model = MaterializedReadModel::new(16, now);
    let fleet_snapshot = |kind, id: &str, value: serde_json::Value| ObjectSnapshot {
        object: ObjectRef {
            kind,
            id: id.to_owned(),
        },
        revision: Revision::new(1),
        revision_source: RevisionSource::Fleet,
        freshness: Freshness {
            state: FreshnessState::Fresh,
            observed_at: now,
            source_updated_at: Some(now),
            stale_after_seconds: None,
        },
        content_digest: Digest::hash(&serde_json::to_vec(&value).unwrap()),
        value,
    };
    let host = FleetHostView {
        host: "mini".to_owned(),
        tailscale: "mini".to_owned(),
        hardware: "mini-pc".to_owned(),
        role: "control".to_owned(),
        capabilities: vec!["operator".to_owned()],
        allow_workloads: true,
        authoritative_state: true,
        gateway_endpoint: None,
        tailnet: FleetTailnetState::Unreachable,
        k3s_node_state: Some(KubeNodeState::NotReady),
        online: false,
        last_seen: Some(now),
        pods_scheduled: 0,
        zellij_live: None,
    };
    let authority = FleetPlacementView {
        thing: "odind-authority".to_owned(),
        node: Some("mini".to_owned()),
        host: Some("mini".to_owned()),
        endpoint: None,
        count: None,
        names: Vec::new(),
        active_count: None,
        live: None,
    };
    read_model
        .upsert(fleet_snapshot(
            ObjectKind::FleetHost,
            "mini",
            serde_json::to_value(&host).unwrap(),
        ))
        .unwrap();
    read_model
        .upsert(fleet_snapshot(
            ObjectKind::FleetPlacement,
            "fleet:placement:authority",
            serde_json::to_value(&authority).unwrap(),
        ))
        .unwrap();

    let id = AtlasId::new("state.live").unwrap();
    let source = LiveSource::new(id.clone(), read_model.clone());
    let (head, items) = source.pin().unwrap();
    let host_key = format!("fleet-hosts/{}", host.host);
    let expected_host_id =
        odin_brain::source::SourceItem::identity(&id, host_key.as_bytes()).unwrap();
    let host_item = items
        .iter()
        .find(|item| item.item_id == expected_host_id)
        .unwrap_or_else(|| panic!("no {host_key} item pinned: {items:?}"));
    let placement_key = "fleet-placement/fleet:placement:authority";
    let expected_placement_id =
        odin_brain::source::SourceItem::identity(&id, placement_key.as_bytes()).unwrap();
    let placement_item = items
        .iter()
        .find(|item| item.item_id == expected_placement_id)
        .unwrap_or_else(|| panic!("no {placement_key} item pinned: {items:?}"));
    assert!(host_item.text.contains("offline"), "{}", host_item.text);
    assert!(placement_item.text.contains("odind-authority"));
    let mut declared_seat = seat(&["state.live"]);
    declared_seat.brain_scope = atlas_ids(&["state.live"]);
    let policy = EffectiveBrainPolicy::resolve(
        74,
        &slice(&["state.live"]),
        &declared_seat,
        &BTreeMap::new(),
        &std::collections::BTreeMap::new(),
        &model(),
    )
    .unwrap();
    let directory = TestCluster::start();
    let configuration = config_at(
        &directory.path(),
        directory.store(),
        BTreeMap::from([(id, BrainSourceConfig::StateLive { source })]),
    );
    let service = BrainService::open(configuration, policy, ledger()).unwrap();
    service.ensure_state_generations().unwrap();
    let query = service
        .policy()
        .knowledge
        .as_ref()
        .unwrap()
        .retrieval_query("fleet host mini offline".to_owned())
        .unwrap();
    let hits = service.retrieve(&query, None, None).unwrap();
    assert!(hits.hits.iter().any(|hit| hit.item_id == host_item.item_id
        && hit.content.contains("offline")
        && hit.citation.source_revision == head));
    let knowledge = service
        .knowledge_item(&placement_item.item_id, None)
        .unwrap();
    assert!(knowledge
        .chunks
        .iter()
        .all(|chunk| chunk.citation.source_revision == head));
}

#[test]
fn state_source_cannot_be_wired_under_an_authorized_alias() {
    let mut declared_seat = seat(&["state.live"]);
    declared_seat.brain_scope = atlas_ids(&["state.live"]);
    let policy = EffectiveBrainPolicy::resolve(
        74,
        &slice(&["state.live"]),
        &declared_seat,
        &BTreeMap::new(),
        &std::collections::BTreeMap::new(),
        &model(),
    )
    .unwrap();
    let source = odin_brain::source::state::live::LiveSource::new(
        AtlasId::new("private.live").unwrap(),
        odin_huginn::read_model::MaterializedReadModel::new(16, time::OffsetDateTime::UNIX_EPOCH),
    );
    let (_store, configuration) = config(BTreeMap::from([(
        AtlasId::new("state.live").unwrap(),
        BrainSourceConfig::StateLive { source },
    )]));
    assert!(matches!(
        open_err(BrainService::open(configuration, policy, ledger())),
        BrainError::InvalidPolicy(_)
    ));
}

#[test]
fn memory_source_cannot_alias_another_seats_subtree() {
    use odin_brain::source::silverbullet::{SilverBulletSource, VaultScope};
    let id = AtlasId::new("memory.sinmara").unwrap();
    let mut declared = seat(&["memory.sinmara"]);
    declared.brain_scope = [id.clone()].into();
    let policy = EffectiveBrainPolicy::resolve(
        74,
        &slice(&["memory.sinmara"]),
        &declared,
        &BTreeMap::new(),
        &std::collections::BTreeMap::new(),
        &model(),
    )
    .unwrap();
    let source = SilverBulletSource::new(
        id.clone(),
        DEAD_VAULT_PORT,
        VaultScope::generated_only("memory/kubert", &[]).unwrap(),
    );
    let (_store, cfg) = config(BTreeMap::from([(id, BrainSourceConfig::Memory { source })]));
    let error = open_err(BrainService::open(cfg, policy, ledger()));
    assert!(matches!(error, BrainError::InvalidPolicy(_)));
}

/// A turn neither builds nor seals: an unsealed generation serves nothing
/// until the warm round seals it, and the next turn then serves it.
#[test]
fn an_unsealed_generation_serves_nothing_until_the_warm_round_seals_it() {
    let ids = [ATLAS_FIXTURE_ID];
    let policy = resolve(&ids);
    let alpha = atlas_root("alpha", "alpha_add");
    let sources = BTreeMap::from([atlas_source(ids[0], alpha.path())]);
    let (cluster, cfg) = config(sources);
    let served = BrainService::open(cfg, policy.clone(), ledger()).unwrap();

    let knowledge = policy.knowledge.as_ref().unwrap();
    let query = knowledge.retrieval_query("alpha_add".to_owned()).unwrap();
    assert!(served.retrieve(&query, None, None).unwrap().hits.is_empty());
    assert_eq!(
        cluster.sql("SELECT count(*) FROM brain_generation_header"),
        "0",
        "the turn must not seal"
    );

    assert_eq!(served.warm(dead_lane().as_ref(), 4_096).unwrap(), 0);
    assert_eq!(
        cluster.sql("SELECT count(*) FROM brain_generation_header"),
        "1",
        "the warm round seals the generation"
    );

    let served_hits = served.retrieve(&query, None, None).unwrap().hits;
    assert_eq!(served_hits[0].source.as_str(), ids[0]);
}

/// An embedding lane that is down: warm rounds seal without embedding.
fn dead_lane() -> Arc<odin_brain::retrieval::QueryEmbedder> {
    Arc::new(|_texts| {
        Err(BrainError::EmbeddingUnavailable {
            provider: "fixture-gateway".to_owned(),
            reason: "the lexical fixture warms no embedding leg".to_owned(),
        })
    })
}

/// A reranker on a loopback port that records every document it is sent
/// and answers in reverse order.
fn recording_reranker() -> (
    odin_brain::retrieval::rerank::Reranker,
    Arc<Mutex<Vec<String>>>,
) {
    use std::io::{Read, Write};
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let recorded = Arc::clone(&seen);
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let mut stream = stream.unwrap();
            let mut request = Vec::new();
            let mut chunk = [0u8; 65536];
            let body = loop {
                let read = stream.read(&mut chunk).unwrap();
                assert!(read > 0, "the client closed before its request was whole");
                request.extend_from_slice(&chunk[..read]);
                let text = String::from_utf8_lossy(&request).into_owned();
                if let Some((head, body)) = text.split_once("\r\n\r\n") {
                    let length: usize = head
                        .lines()
                        .find_map(|line| line.strip_prefix("Content-Length: "))
                        .unwrap()
                        .parse()
                        .unwrap();
                    if body.len() >= length {
                        break body.to_owned();
                    }
                }
            };
            let request: serde_json::Value = serde_json::from_str(&body).unwrap();
            let documents: Vec<String> = request["documents"]
                .as_array()
                .unwrap()
                .iter()
                .map(|document| document.as_str().unwrap().to_owned())
                .collect();
            let results: Vec<_> = (0..documents.len())
                .map(|index| serde_json::json!({"index": index, "relevance_score": index as f64}))
                .collect();
            recorded.lock().unwrap().extend(documents);
            let body = serde_json::json!({ "results": results }).to_string();
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            )
            .unwrap();
        }
    });
    (
        odin_brain::retrieval::rerank::Reranker {
            address,
            candidates: 32,
        },
        seen,
    )
}

/// A seat whose policy lacks a source never gets its chunks: not through
/// the BM25 leg, though another seat sealed them into the same store, not
/// by naming the source in its query, and the reranker never sees them.
/// The reranker reorders what the seat may read.
#[test]
fn a_seat_without_a_source_gets_none_of_its_chunks_through_bm25_or_the_reranker() {
    let ids = [ATLAS_FIXTURE_ID, "atlas:runtime-second"];
    let alpha = atlas_root("alpha", "alpha_secret_marker");
    let beta = atlas_root("beta", "beta_open_marker");
    std::fs::write(
        beta.path().join("crates/beta/src/lib.rs"),
        "//! Fixture crate beta.\n\n/// Adds one: beta_open_marker.\npub fn beta_open_marker(value: u64) -> u64 { value + 1 }\n\n\
         /// Adds two, after beta_open_marker.\npub fn beta_twice(value: u64) -> u64 { value + 2 }\n",
    )
    .unwrap();
    let cluster = TestCluster::start();
    let both = BrainService::open(
        config_at(
            &cluster.path().join("both"),
            cluster.store(),
            BTreeMap::from([
                atlas_source(ids[0], alpha.path()),
                atlas_source(ids[1], beta.path()),
            ]),
        ),
        resolve(&ids),
        ledger(),
    )
    .unwrap();
    assert_eq!(both.warm(dead_lane().as_ref(), 4_096).unwrap(), 0);
    let knowledge = resolve(&ids).knowledge.unwrap();
    let secret = knowledge
        .retrieval_query("alpha_secret_marker".to_owned())
        .unwrap();
    assert_eq!(
        both.retrieve(&secret, None, None).unwrap().hits[0]
            .source
            .as_str(),
        ids[0],
        "the sealed chunk serves a seat that holds its source"
    );

    let (reranker, seen) = recording_reranker();
    let scoped_policy = resolve(&ids[1..]);
    let scoped = BrainService::open(
        BrainServiceConfig {
            rerank: Some(reranker),
            ..config_at(
                &cluster.path().join("scoped"),
                cluster.store(),
                BTreeMap::from([atlas_source(ids[1], beta.path())]),
            )
        },
        scoped_policy.clone(),
        ledger(),
    )
    .unwrap();
    assert_eq!(scoped.warm(dead_lane().as_ref(), 4_096).unwrap(), 0);
    let scoped_knowledge = scoped_policy.knowledge.unwrap();
    let mut query = scoped_knowledge
        .retrieval_query("alpha_secret_marker beta_open_marker".to_owned())
        .unwrap();
    query.sources = atlas_ids(&ids);
    let hits = scoped.retrieve(&query, None, None).unwrap().hits;
    assert!(!hits.is_empty(), "the seat's own source serves");
    assert!(
        hits.iter().all(
            |hit| hit.source.as_str() == ids[1] && !hit.content.contains("alpha_secret_marker")
        ),
        "{hits:?}"
    );
    let seen = seen.lock().unwrap();
    assert!(!seen.is_empty(), "the reranker reordered the turn");
    assert!(
        seen.iter()
            .all(|text| !text.contains("alpha_secret_marker")),
        "the reranker saw another source's chunk: {seen:?}"
    );
}
