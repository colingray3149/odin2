//! Model-visible targets and live-session selection boundaries.
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use odin_domain::huginn::{
    EventSeq, LiveLaunchOption, LiveSessionId, LiveSessionState, LiveSessionSummary, ModelName,
    ProviderName, SessionEpoch, TerminalSeq,
};
use odin_domain::{ContainerId, SeatId, SliceId};
use odin_hermes::runtime::{
    hermes_host_tools, select_target_session, HermesLedgers, HermesRuntime, ModelLaunchDeclaration,
    ModelRouteError, SeatSessionSurvey,
};
use odin_kernel::CapabilityContract;
use odin_ledger::Ledger;
use odin_omp::live::supervisor::LiveSeatBinding;
use time::OffsetDateTime;

fn binding(seat: &str, provider: &str, model: &str) -> LiveSeatBinding {
    LiveSeatBinding {
        seat_id: SeatId::new(seat).unwrap(),
        slice_id: SliceId::new("fixture").unwrap(),
        display_name: seat.to_owned(),
        launch_options: vec![LiveLaunchOption {
            provider: ProviderName::new(provider).unwrap(),
            model: ModelName::new(model).unwrap(),
            skeleton_ref: "fixture".to_owned(),
            container_id: ContainerId::new("fixture").unwrap(),
            harness: None,
        }],
        allowed_nodes: vec![],
        max_sessions: 2,
        turn_budget: None,
    }
}

fn contract() -> CapabilityContract {
    let path = "registry/capabilities/seat.model.set/capability.toml";
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let source = std::fs::read_to_string(root.join(path)).unwrap();
    let object = odin_registry::schema::parse_object_toml(
        odin_registry::RegistryKind::Capability,
        "seat.model.set".to_owned(),
        path,
        &source,
    )
    .unwrap();
    let odin_registry::ObjectConfig::Capability(declaration) = &object.config else {
        panic!("capability")
    };
    CapabilityContract::try_from_registry(
        &object,
        &odin_registry::relational::AdmittedBinding {
            version: declaration.version,
            input_schema: declaration.input_schema.clone().unwrap(),
            output_schema: declaration.output_schema.clone().unwrap(),
            handler: declaration.handler.clone().unwrap(),
            evidence_extractor: declaration.evidence_extractor.clone().unwrap(),
        },
    )
    .unwrap()
}

#[test]
fn model_surface_offers_exact_pairs_for_all_declared_seats() {
    let root = tempfile::tempdir().unwrap();
    let contract = contract();
    let runtime = HermesRuntime::open(
        odin_hermes::config::HermesSettings::new(
            root.path().join("state"),
            None,
            None,
            None,
            vec![],
        )
        .unwrap(),
        HermesLedgers {
            conversation: Ledger::open_in_memory().unwrap(),
            adapter: Arc::new(parking_lot::Mutex::new(Ledger::open_in_memory().unwrap())),
            purchase: Arc::new(std::sync::Mutex::new(Ledger::open_in_memory().unwrap())),
        },
        &BTreeMap::from([(contract.id.clone(), contract)]),
        None,
        8192,
        BTreeMap::new(),
        None,
    )
    .unwrap();
    let mut declarations = [
        binding("alpha", "provider-a", "model-a"),
        binding("beta", "provider-b", "model-b"),
    ];
    let alternate = declarations[1].launch_options[0].clone();
    declarations[0].launch_options.push(alternate);
    runtime.set_model_launch_declaration(ModelLaunchDeclaration::from_bindings(&declarations));
    let tool = hermes_host_tools(&runtime)
        .into_iter()
        .find(|tool| tool.definition().name.as_ref() == "seat_model_set")
        .unwrap();
    let tuples = tool.definition().parameters["allOf"][0]["oneOf"]
        .as_array()
        .unwrap()
        .iter()
        .map(|branch| {
            let props = &branch["properties"];
            (
                props["seat"]["const"].as_str().unwrap(),
                props["provider"]["const"].as_str().unwrap(),
                props["model"]["const"].as_str().unwrap(),
            )
        })
        .collect::<BTreeSet<_>>();
    assert_eq!(
        tuples,
        BTreeSet::from([
            ("alpha", "provider-a", "model-a"),
            ("alpha", "provider-b", "model-b"),
            ("beta", "provider-b", "model-b")
        ])
    );
    assert_eq!(tool.definition().parameters["additionalProperties"], false);
    assert!(tool.definition().parameters["properties"]
        .get("sessionId")
        .is_none());
}

fn summary(id: u128, seat: &str, state: LiveSessionState) -> LiveSessionSummary {
    LiveSessionSummary {
        session_id: LiveSessionId::parse(&format!("{id:08x}-0000-4000-8000-000000000001")).unwrap(),
        epoch: SessionEpoch::new(3),
        seat_id: SeatId::new(seat).unwrap(),
        provider: ProviderName::new("provider").unwrap(),
        model: ModelName::new("model").unwrap(),
        title: None,
        state,
        started_at: OffsetDateTime::UNIX_EPOCH,
        updated_at: OffsetDateTime::UNIX_EPOCH,
        failed_at: None,
        event_head: EventSeq::new(0),
        terminal_head: TerminalSeq::new(0),
        pending_permission_count: 0,
    }
}

#[test]
fn model_target_requires_one_live_session_or_the_exact_declared_vehicle() {
    let seat = SeatId::new("alpha").unwrap();
    let first = summary(1, "alpha", LiveSessionState::Idle);
    let second = summary(2, "alpha", LiveSessionState::Running);
    for sessions in [
        vec![],
        vec![summary(1, "alpha", LiveSessionState::Ended)],
        vec![summary(1, "alpha", LiveSessionState::Failed)],
        vec![summary(1, "beta", LiveSessionState::Idle)],
        vec![first.clone(), second.clone()],
    ] {
        assert!(matches!(
            select_target_session(
                &SeatSessionSurvey {
                    declared_vehicle: None,
                    live_sessions: sessions
                },
                &seat
            ),
            Err(ModelRouteError::Refused(_))
        ));
    }
    let mut survey = SeatSessionSurvey {
        declared_vehicle: Some(second.session_id),
        live_sessions: vec![first.clone(), second.clone()],
    };
    assert_eq!(
        select_target_session(&survey, &seat).unwrap().session_id,
        second.session_id
    );
    survey.live_sessions = vec![first];
    assert!(
        matches!(
            select_target_session(&survey, &seat),
            Err(ModelRouteError::Refused(_))
        ),
        "a missing declared vehicle must not redirect the switch to another session"
    );
    survey.declared_vehicle = None;
    assert_eq!(
        select_target_session(&survey, &seat).unwrap().session_id,
        survey.live_sessions[0].session_id
    );
}
