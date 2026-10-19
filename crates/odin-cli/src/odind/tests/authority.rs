use super::*;

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::num::NonZeroU64;
use std::path::Path;

use odin_domain::CapabilityId;
use odin_registry::{ObjectConfig, RegistryKind};

use crate::test_fixture::{fixture_config_text, manifest_identity_fixture, PublishedStore};

#[test]
fn conversation_transport_uses_exact_declared_project_not_lane_order() {
    let mut object = odin_registry::schema::parse_object_toml(
        RegistryKind::Seat,
        "coordinator",
        "seats/coordinator/seat.toml",
        include_str!("../../../../../registry/seats/sinmara/seat.toml"),
    )
    .expect("seat declaration");
    let ObjectConfig::Seat(seat) = &mut object.config else {
        panic!("seat declaration");
    };
    let ask_id = CapabilityId::new("coord.assist").expect("ask capability");
    seat.project_scope = BTreeSet::from([ProjectId::new("research").expect("project")]);
    seat.conversation = Some(odin_registry::schema::SeatConversationToml {
        project: ProjectId::new("research").expect("project"),
        ask_capability: ask_id.clone(),
        guidance: "Use plain language.".to_owned(),
        answer_timeout_seconds: NonZeroU64::new(240).expect("bound"),
    });
    let seat_id = odin_domain::SeatId::new("coordinator").expect("seat");
    let mut ask_object = odin_registry::schema::parse_object_toml(
        RegistryKind::Capability,
        ask_id.as_str(),
        "capabilities/coord.assist/capability.toml",
        include_str!("../../../../../registry/capabilities/seat.ask.sinmara/capability.toml"),
    )
    .expect("generic ask declaration");
    let ObjectConfig::Capability(ask) = &mut ask_object.config else {
        panic!("capability declaration");
    };
    ask.delegate_to = Some(seat_id.clone());
    let admitted =
        odin_registry::relational::declared_admitted_binding(ask).expect("declared native binding");
    let contract = odin_kernel::CapabilityContract::try_from_registry(&ask_object, &admitted)
        .expect("admitted arbitrary capability name");
    let mut contracts = BTreeMap::from([(ask_id.clone(), contract)]);
    let binding = odin_omp::live::supervisor::LiveSeatBinding {
        seat_id: seat_id.clone(),
        slice_id: odin_domain::SliceId::new("coordinator-work").expect("slice"),
        display_name: "Coordinator".to_owned(),
        launch_options: Vec::new(),
        allowed_nodes: Vec::new(),
        max_sessions: 1,
        turn_budget: None,
    };
    let transport = odin_hermes::config::DiscordSettings {
        seat: seat_id.clone(),
        project: ProjectId::new("research").expect("project"),
        owner_user_id: "owner".to_owned(),
        notify_channel_id: "paired-channel".to_owned(),
        capability: CapabilityId::new("discord.intake").expect("capability"),
        egress_capacity: 8,
        gateway_intents: 1,
        bot_token_handle: "cred:discord.bot".to_owned(),
        scrub_tokens: BTreeSet::new(),
        ttl_seconds: 300,
    };
    let target_lane = odin_domain::LaneId::new("coordinator-research").expect("lane");
    let mut lanes = BTreeMap::from([
        (
            (
                seat_id.clone(),
                ProjectId::new("aaa-unrelated").expect("project"),
            ),
            odin_domain::LaneId::new("first-but-wrong").expect("lane"),
        ),
        (
            (seat_id.clone(), transport.project.clone()),
            target_lane.clone(),
        ),
    ]);
    let objects = vec![object];
    let bindings = vec![binding];
    let resolved = declared_conversation_binding(
        &objects,
        &contracts,
        &bindings,
        &lanes,
        &transport,
        NodePosture::Authoritative,
    )
    .expect("exact declared owner and capability");
    assert_eq!(resolved.vehicle.expect("served vehicle").1, target_lane);

    contracts.get_mut(&ask_id).expect("ask").delegate_to =
        Some(odin_domain::SeatId::new("another-worker").expect("seat"));
    assert!(
        declared_conversation_binding(
            &objects,
            &contracts,
            &bindings,
            &lanes,
            &transport,
            NodePosture::Authoritative,
        )
        .is_err(),
        "an admitted ask for another target cannot own this conversation"
    );
    contracts.get_mut(&ask_id).expect("ask").delegate_to = Some(seat_id.clone());
    assert!(
        declared_conversation_binding(
            &objects,
            &BTreeMap::new(),
            &bindings,
            &lanes,
            &transport,
            NodePosture::Authoritative,
        )
        .is_err(),
        "a missing ask capability cannot silently select a default"
    );
    let follower = declared_conversation_binding(
        &objects,
        &contracts,
        &[],
        &BTreeMap::new(),
        &transport,
        NodePosture::Follower,
    )
    .expect("published ownership does not arm a follower");
    assert!(follower.vehicle.is_none());

    lanes.remove(&(seat_id, transport.project.clone()));
    assert!(declared_conversation_binding(
        &objects,
        &contracts,
        &bindings,
        &lanes,
        &transport,
        NodePosture::Authoritative,
    )
    .is_err());
    let mut wrong_project = transport;
    wrong_project.project = ProjectId::new("aaa-unrelated").expect("project");
    assert!(declared_conversation_binding(
        &objects,
        &contracts,
        &bindings,
        &lanes,
        &wrong_project,
        NodePosture::Authoritative,
    )
    .is_err());
}

/// HMAC verification also permits minting, so followers must never load the key.
#[test]
fn authority_composition_reads_minting_secret_only_on_authority() {
    let fixture = PublishedStore::new("laptop", true);
    let root = fixture.temporary.path();
    fs::create_dir_all(root.join("state")).expect("state root");
    let text = fixture_config_text(root, &fixture.snapshot_path);
    let config = OdindConfig::parse(&text).expect("fixture config parses");
    let manifest = manifest_identity_fixture("omp", Path::new("/tmp/odind-omp"));

    let key_file = config.paths.authority_verification_key_file.clone();
    assert!(
        !key_file.exists(),
        "the fixture must not provision an authority key"
    );
    let (_provider, _pool) = compose_operation_authority(NodePosture::Follower, &config, &manifest)
        .expect("follower composes with no authority key present");

    let error = compose_operation_authority(NodePosture::Authoritative, &config, &manifest)
        .err()
        .expect("authority must fail without the minting secret");
    assert!(
        error.contains("could not read authority verification key file"),
        "typed missing-key failure required: {error}"
    );

    fs::create_dir_all(config.paths.authority_token_root.clone()).expect("provision token root");
    fs::create_dir_all(
        config
            .paths
            .authority_verification_key_file
            .parent()
            .expect("verification key has a parent directory"),
    )
    .expect("provision verification key directory");
    fs::write(&key_file, vec![b'k'; 64]).expect("provision authority key");
    let (_provider, _pool) =
        compose_operation_authority(NodePosture::Authoritative, &config, &manifest)
            .expect("authority composes with the provisioned secret");
}

/// Use the installed token's generation, not the caller's pinned revision.
#[tokio::test]
async fn conversation_ensure_binds_the_ensured_tokens_own_claim_across_a_publication() {
    use crate::authority_fixture::{command, fixture, write_object, SEAT_TOML};
    use crate::test_support::commit_all;
    use odin_cli::authority_provision::{compose, init, LaunchSelection};
    use odin_hermes::conversation::ConversationAuthority as _;
    use odin_registry::SnapshotStore;

    let fixture = fixture();
    init(&fixture.config).expect("authority initialized");
    let command_id = command("command:conversation-seam");
    let composition = compose(
        &fixture.config,
        "architect",
        "odin",
        &command_id,
        LaunchSelection::new("gateway", "zai-glm"),
    )
    .expect("composition");
    assert_eq!(composition.snapshot_revision, 1);
    let authority = super::DeclaredConversationAuthority {
        config: fixture.config.clone(),
        seat: composition.seat.clone(),
        project: composition.project.clone(),
        slice: composition.slice.clone(),
        lane: composition.lane.clone(),
        provider: composition.provider.clone(),
        model: composition.model.clone(),
        incidents: None,
    };
    let token_path = fixture
        .config
        .paths
        .authority_token_root
        .join(format!("{}.json", composition.session.as_str()));

    let ensured = authority
        .ensure(&command_id, composition.live_session)
        .await
        .expect("the vehicle authority ensures");
    let installed: odin_domain::SeatToken =
        serde_json::from_slice(&fs::read(&token_path).expect("token readable"))
            .expect("token parses");
    assert_eq!(installed.served_revision, Some(1));
    assert_eq!(
        ensured.bound,
        installed.served_revision.unwrap(),
        "the recorded binding is the installed token's own claim"
    );
    assert_eq!(ensured.current, 1);

    let worktree = fixture._temporary.path().join("authoring");
    write_object(
        &worktree,
        "seats",
        "architect",
        "seat.toml",
        &SEAT_TOML.replace(
            "categories = [\"builder\", \"coordinator\"]",
            "categories = [\"builder\", \"coordinator\", \"reviewer\"]",
        ),
    );
    let commit = commit_all(&worktree, "authority fixture registry roll");
    let candidate = odin_registry::ValidatedSnapshotCandidate::from_committed_worktree(
        &worktree,
        &commit,
        odin_omp::host_tools::PRE_ADMITTED_BINDINGS
            .iter()
            .map(|binding| binding.to_admitted_binding()),
    )
    .expect("rolled authority fixture candidate");
    SnapshotStore::new(&fixture.config.paths.registry_snapshot)
        .publish_committed(&candidate, 2)
        .expect("publish rolled authority fixture snapshot");

    // Reusing a token must retain its generation across publication.
    let ensured_after = authority
        .ensure(&command_id, composition.live_session)
        .await
        .expect("the installed token still authenticates across the publication");
    let installed_after: odin_domain::SeatToken =
        serde_json::from_slice(&fs::read(&token_path).expect("token readable"))
            .expect("token parses");
    assert_eq!(
        installed_after.served_revision,
        Some(1),
        "reuse retains the frozen generation"
    );
    assert_eq!(
        ensured_after.bound,
        installed_after.served_revision.unwrap(),
        "the binding follows the ensured token's ACTUAL claim across a publication"
    );
    assert_eq!(
        ensured_after.bound, 1,
        "a frozen session never silently adopts the new publication"
    );
    assert_eq!(ensured_after.current, 2);

    // A genuinely new session mints at the current publication and
    // reports exactly that.
    let fresh_command = command("command:conversation-seam-fresh");
    let fresh = compose(
        &fixture.config,
        "architect",
        "odin",
        &fresh_command,
        LaunchSelection::new("gateway", "zai-glm"),
    )
    .expect("fresh composition at the rolled publication");
    assert_eq!(fresh.snapshot_revision, 2);
    let ensured_fresh = authority
        .ensure(&fresh_command, fresh.live_session)
        .await
        .expect("the fresh session mints at the current publication");
    assert_eq!(
        ensured_fresh.bound, 2,
        "a fresh session's binding is the current publication"
    );
    assert_eq!(ensured_fresh.current, 2);

    // A legacy claim-less token is REFUSED with the existing remedy,
    // never defaulted to current: the open that follows could not
    // lawfully record any manifest binding the token does not carry.
    let legacy_command = command("command:conversation-seam-legacy");
    let legacy = compose(
        &fixture.config,
        "architect",
        "odin",
        &legacy_command,
        LaunchSelection::new("gateway", "zai-glm"),
    )
    .expect("legacy composition");
    let key =
        odin_cli::authority_provision::load_signing_key(&fixture.config).expect("signing key");
    let issued_at_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| u64::try_from(duration.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(0);
    let legacy_token = odin_kernel::TokenIssuer::new(key)
        .expect("issuer")
        .mint(odin_kernel::MintRequest {
            seat: legacy.seat.clone(),
            slice: legacy.slice.clone(),
            lane: legacy.lane.clone(),
            session: legacy.session.clone(),
            seat_revision: legacy.policy.policy.seat_revision,
            slice_revision: legacy.policy.policy.slice_revision,
            capability_policy_digest: legacy.policy.policy.capability_policy_digest,
            context_policy_digest: legacy.policy.context_policy_digest,
            issued_at_ms,
            expires_at_ms: issued_at_ms + 3_600_000,
            entropy: b"legacy-seam-entropy",
        })
        .expect("legacy token mints");
    let legacy_path = fixture
        .config
        .paths
        .authority_token_root
        .join(format!("{}.json", legacy.session.as_str()));
    fs::write(&legacy_path, serde_json::to_vec(&legacy_token).unwrap())
        .expect("legacy token written");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(&legacy_path, fs::Permissions::from_mode(0o600))
            .expect("token protected");
    }
    authority
        .ensure(&legacy_command, legacy.live_session)
        .await
        .expect_err("a legacy claim-less token is refused, never defaulted to current");
}
