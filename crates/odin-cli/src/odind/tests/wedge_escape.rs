//! Isolated wedge recovery with production composition and loopback model transport.
//! This does not exercise live DM acceptance.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use odin_domain::huginn::LiveSessionId;
use odin_domain::CommandId;
use odin_omp::host_tools::operations::session_capsule_id;
use odin_omp::live::runtime::SessionCapsuleAuthority;
use odin_omp::live::supervisor::session_id_for;

use crate::authority::DeclaredConversationAuthority;
use crate::live::hermes_routes::tests::{gate_fixture_with, GateFixture};
use crate::mismatch_recovery_tests::{
    compose_serving_with, execute_dm, mint_installed_token, stage_predecessor, BoundaryLauncher,
    GenerationFixture, LaunchProbe, DM_PAYLOAD, DM_REPLY,
};

/// The deterministic wedged-vehicle identity: distinct from every other
/// fixture's vehicle command, so the staged session and capsule path are
/// unambiguous.
fn wedged_vehicle_command() -> CommandId {
    CommandId::new("command:conversation-open:wedge-escape-fixture").expect("vehicle command")
}

fn wedged_vehicle_session() -> LiveSessionId {
    session_id_for(&wedged_vehicle_command()).expect("deterministic wedged vehicle session")
}

/// The exact private session state path the REAL pool derives in
/// `register_session` — the path the fault replaces with a file.
fn wedged_capsule_state_path(gate: &GateFixture, session: LiveSessionId) -> PathBuf {
    let bridge_session = odin_domain::SessionId::new(session.to_string())
        .expect("the vehicle session is a valid bridge session id");
    let capsule = session_capsule_id(&bridge_session).expect("capsule identity");
    gate.config
        .paths
        .state_root
        .join("session-authorities")
        .join(format!("capsule-{}", capsule.as_str().replace(':', "-")))
}

/// The retained record exactly as production persists it.
fn durable_record(fixture: &GenerationFixture) -> serde_json::Value {
    serde_json::from_slice(&std::fs::read(&fixture.record_path).expect("retained record"))
        .expect("retained record parses")
}

/// One staged vehicle at revision 1 over the REAL session authority pool:
/// the mismatch staging with ONE composition difference — the factory's
/// capsule authority is production's own pool, so the scratch fault bites
/// through production registration instead of an accepting stub.
async fn stage_wedge_row() -> GenerationFixture {
    let probe = Arc::new(LaunchProbe::default());
    let launcher = Arc::new(BoundaryLauncher::new(probe.clone()));
    let gate = gate_fixture_with(8, launcher.clone(), false).await;
    gate.runtime
        .bind_notify_sink(probe.clone())
        .expect("isolated egress");

    let binding = gate.binding();
    let (seat_binding, lane) = binding
        .vehicle
        .clone()
        .expect("the fixture binds a vehicle");
    let launch = seat_binding
        .launch_options
        .first()
        .expect("the fixture seat declares a launch pair")
        .clone();
    let authority = DeclaredConversationAuthority {
        config: gate.config.clone(),
        seat: binding.ownership.seat.clone(),
        project: binding.ownership.project.clone(),
        slice: seat_binding.slice_id.clone(),
        lane: lane.clone(),
        provider: launch.provider.clone(),
        model: launch.model.clone(),
        incidents: None,
    };

    // The pool production composes on an authoritative node: the manifest
    // only needs to resolve the pinned git, and the key is the fixture's
    // provisioned minting secret.
    let manifest = crate::test_fixture::manifest_identity_fixture("git", Path::new("git"));
    let key = std::fs::read(&gate.config.paths.authority_verification_key_file)
        .expect("read the provisioned authority key");
    let capsules: Arc<dyn SessionCapsuleAuthority> =
        odin_cli::live_authority::SessionAuthorityPool::open(&gate.config, &manifest, key)
            .expect("compose the REAL session authority pool");

    let vehicle_command = wedged_vehicle_command();
    let session = wedged_vehicle_session();
    let ensured = mint_installed_token(&authority, &vehicle_command, &session).await;
    assert_eq!(
        ensured.bound, 1,
        "the installed token binds its mint-time pin"
    );
    assert_eq!(ensured.current, 1, "the staging pin is revision 1");

    stage_predecessor(&gate, &session, Some(1), &vehicle_command, None, None).await;

    let serving = compose_serving_with(
        &gate,
        launcher.clone(),
        gate.ledger.clone(),
        capsules.clone(),
    )
    .await;
    // Path accesses must precede the `gate` move into the fixture.
    let token_file = gate
        .config
        .paths
        .authority_token_root
        .join(format!("{session}.json"));
    let record_path = gate.record_path.clone();
    let mut fixture = GenerationFixture {
        gate,
        probe,
        launcher,
        root: serving.root,
        ledger: serving.ledger,
        capsules,
        authority,
        vehicle_command,
        session,
        token_file,
        record_path,
    };
    assert!(
        fixture.token_file.is_file(),
        "the real authority provisioned the installed token file"
    );
    fixture.reopen().await;
    fixture
}

/// Replace scratch capsule state with a file to force three durable recovery failures.
#[tokio::test]
async fn a_wedged_vehicle_escapes_to_a_served_successor_after_three_failures() {
    let mut fixture = stage_wedge_row().await;
    let predecessor = fixture.session;
    // Isolation guard: the fixture composes entirely inside its scratch
    // root — never the daemon's live state root, never the owner capsule.
    let scratch_root = fixture.gate._root.path();
    assert!(
        fixture.record_path.starts_with(scratch_root)
            && fixture
                .gate
                .config
                .paths
                .state_root
                .starts_with(scratch_root),
        "the wedge fixture's state root must stay inside its scratch root"
    );
    let token_before = std::fs::read(&fixture.token_file).expect("installed token");

    // The already-current vehicle recovers IN PLACE through the REAL pool:
    // the reclaim registers the session and materializes its capsule state.
    fixture
        .root
        .initialize()
        .await
        .expect("the healthy vehicle recovers in place");
    let record = durable_record(&fixture);
    assert_eq!(
        record["sessionId"],
        predecessor.to_string(),
        "in-place recovery keeps the vehicle session"
    );
    let capsule = wedged_capsule_state_path(&fixture.gate, predecessor);
    assert!(
        capsule.is_dir(),
        "the REAL pool materialized the vehicle capsule state"
    );

    // The scratch fault: the vehicle's capsule state directory becomes a
    // file, inside the fixture's own root only.
    std::fs::remove_dir_all(&capsule).expect("drop the scratch capsule state");
    std::fs::write(
        &capsule,
        b"wedge fixture: a file where the capsule state belongs",
    )
    .expect("stage the wedge fault");
    assert!(capsule.is_file(), "the fault is staged");

    // A full reopen — fresh ledger replay, fresh supervisor, fresh plane,
    // fresh pool, fresh root over the SAME retained record: the
    // daemon-restart analogue with the fault in place.
    fixture.reopen().await;

    // The first two failed recoveries refuse: no successor opens, and the
    // durable count climbs.
    for expected in [1u32, 2] {
        fixture
            .root
            .initialize()
            .await
            .expect_err("a failed in-place recovery refuses the open");
        let record = durable_record(&fixture);
        assert_eq!(
            record["recoveryFailures"], expected,
            "the failed attempt is counted durably"
        );
        assert!(
            fixture.probe.opens().is_empty(),
            "no successor opens before the escape bound"
        );
    }

    // The third failure reaches the bound of 3: the conversation rolls to
    // a governed successor and the open SUCCEEDS.
    fixture
        .root
        .initialize()
        .await
        .expect("the third failed recovery rolls to a successor");
    let record = durable_record(&fixture);
    let successor: LiveSessionId = LiveSessionId::parse(
        record["sessionId"]
            .as_str()
            .expect("the record names the vehicle"),
    )
    .expect("successor session id");
    assert_ne!(successor, predecessor, "the conversation left the wedge");
    assert_eq!(
        record["recoveryFailures"], 0,
        "the escape resets the durable failure count"
    );
    assert_eq!(
        record["rollover"]["predecessorSession"],
        predecessor.to_string(),
        "the slot names the wedged predecessor"
    );
    assert_eq!(
        record["rollover"]["phase"], "open",
        "the successor transition settles open"
    );
    let opens = fixture.probe.opens();
    assert_eq!(opens.len(), 1, "exactly one successor open: {opens:?}");
    assert_eq!(
        opens[0].session, successor,
        "the opened session is the durable successor"
    );
    assert!(
        !opens[0].reclaim,
        "the successor opens fresh, never as a reclaim"
    );

    // The wedged predecessor is never rebound and its token is untouched.
    let predecessor_row = fixture
        .ledger
        .session(predecessor)
        .await
        .expect("predecessor row");
    assert_eq!(
        predecessor_row.manifest.served_revision,
        Some(1),
        "the wedged predecessor's manifest binding is never rewritten"
    );
    assert_eq!(
        std::fs::read(&fixture.token_file).expect("installed token"),
        token_before,
        "the wedged vehicle's token is never reminted"
    );

    // The successor's first prompt is the bounded escape brief carrying
    // the predecessor history.
    let prompts = fixture.probe.prompts();
    assert_eq!(
        prompts.len(),
        1,
        "exactly the successor's initial prompt: {prompts:?}"
    );
    let brief: serde_json::Value = serde_json::from_str(
        prompts[0]
            .split_once('\n')
            .expect("brief header and payload")
            .1,
    )
    .expect("the successor's initial prompt carries the rollover brief JSON");
    assert_eq!(
        brief["schema"], "odin.rollover-brief.v1",
        "the escape brief carries the rollover-brief schema"
    );
    assert!(
        prompts[0].contains("PRE-HISTORY"),
        "the brief carries the predecessor history into the fresh harness"
    );

    // The successor SERVES: the next owner turn rides it and comes back
    // answered, exactly once.
    let projection = execute_dm(&fixture, "wedge-post-escape-dm").await;
    assert_eq!(
        projection["answer"], DM_REPLY,
        "the owner gets the message-specific reply from the successor"
    );
    assert_eq!(
        projection["replySent"], true,
        "the reply delivery is recorded"
    );
    assert!(fixture
        .probe
        .delivered
        .lock()
        .expect("deliveries")
        .iter()
        .any(|message| message.content == DM_REPLY));
    assert_eq!(
        fixture.probe.prompt_count(DM_PAYLOAD),
        1,
        "the DM rides the successor exactly once"
    );
}
