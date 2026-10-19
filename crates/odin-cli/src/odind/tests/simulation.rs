//! Workload missions, telemetry, checkpoints, and simulation command routing.

use std::collections::BTreeSet;
use std::num::{NonZeroU32, NonZeroU64};
use std::sync::{Arc, Mutex};

use odin_domain::huginn::{
    CommandReceipt, HuginnProtocolError, KubeResourceRef, KubeWorkloadState, ObjectKind, ObjectRef,
    RenderId, RendererId, SimulationCommand, SimulationCommandContext, SimulationIntervention,
    SimulationMissionStage, SimulationMissionView, StreamBackpressureLimits,
};
use odin_domain::{CheckpointId, CommandId, Digest, NodeId, RunId};
use odin_huginn::read_model::MaterializedReadModel;
use odin_huginn::streams::{BoundedMultiplexer, DurableReplayStore};
use odin_ledger::Ledger;
use time::OffsetDateTime;

use super::{ObservedRun, SimulationDesk};

struct Fixture {
    desk: SimulationDesk,
    read_model: Arc<MaterializedReadModel>,
    streams: Arc<BoundedMultiplexer>,
    _dir: tempfile::TempDir,
}

fn fixture() -> Fixture {
    let dir = tempfile::tempdir().expect("tempdir");
    let replay = DurableReplayStore::open(dir.path().join("replay.sqlite3"), 256, 1 << 20)
        .expect("replay store");
    let streams = Arc::new(BoundedMultiplexer::new(replay, 64, 64));
    let read_model = Arc::new(MaterializedReadModel::with_limits(
        4096,
        8192,
        OffsetDateTime::now_utc(),
    ));
    let limits = StreamBackpressureLimits {
        max_buffered_items: NonZeroU32::new(64).unwrap(),
        max_buffered_bytes: NonZeroU64::new(64 << 20).unwrap(),
        max_item_bytes: NonZeroU64::new(1 << 20).unwrap(),
        max_items_per_second: NonZeroU32::new(256).unwrap(),
        max_in_flight_bytes: NonZeroU64::new(64 << 20).unwrap(),
    };
    let desk = SimulationDesk::new(
        Arc::clone(&read_model),
        Arc::clone(&streams),
        limits,
        Arc::new(Mutex::new(Ledger::open_in_memory().expect("ledger"))),
    )
    .expect("desk");
    Fixture {
        desk,
        read_model,
        streams,
        _dir: dir,
    }
}

fn run(state: KubeWorkloadState) -> ObservedRun {
    ObservedRun {
        run_id: RunId::new("kube-run-sim-fixture-1").unwrap(),
        profile: "sim-fixture".to_owned(),
        declaration: serde_json::json!({"description": "toy"}),
        renderers: vec![RendererId::new("field_svg-v1").unwrap()],
        state,
        node_id: Some(NodeId::new("pc").unwrap()),
        workload: KubeResourceRef {
            cluster: "odin".to_owned(),
            api_version: "batch/v1".to_owned(),
            kind: "Job".to_owned(),
            namespace: Some("odin-workloads".to_owned()),
            name: "sim-fixture-1".to_owned(),
            uid: "uid-1".to_owned(),
        },
        started_at: None,
        finished_at: None,
    }
}

fn mission(fixture: &Fixture, run: &ObservedRun) -> SimulationMissionView {
    let snapshot = fixture
        .read_model
        .get(&ObjectRef {
            kind: ObjectKind::Simulation,
            id: run.run_id.to_string(),
        })
        .expect("read model")
        .expect("the mission is published");
    serde_json::from_value(snapshot.value).expect("a mission view")
}

fn context(run: &ObservedRun, id: &str, expected_revision: u64) -> SimulationCommandContext {
    SimulationCommandContext {
        command_id: CommandId::new(id).unwrap(),
        run_id: run.run_id.clone(),
        expected_revision,
        arguments_digest: Digest::hash(id.as_bytes()),
        approval_id: None,
    }
}

const LOG: &str = "2026-10-04T02:00:00.000000001Z starting\n\
2026-10-04T02:00:01Z ODIN-STATUS {\"iteration\": 1, \"residual\": 0.5}\n\
2026-10-04T02:00:02Z ODIN-STATUS {\"iteration\": 2, \"residual\": 0.25}\n\
2026-10-04T02:00:03Z ODIN-CHECKPOINT {\"label\": \"iteration 2\", \"iteration\": 2}\n\
2026-10-04T02:00:03Z ODIN-STATUS not json\n";

/// Re-reading a log must not duplicate telemetry; only newer lines create a batch.
#[test]
fn a_running_job_is_a_mission_with_its_telemetry_and_checkpoint() {
    let fixture = fixture();
    let running = run(KubeWorkloadState::Running);
    let at = OffsetDateTime::now_utc();
    fixture.desk.observe(&running, LOG, at).expect("observe");

    let view = mission(&fixture, &running);
    assert_eq!(view.stage, SimulationMissionStage::Running);
    assert_eq!(view.label, "sim-fixture");
    assert_eq!(view.node_id.as_ref().map(NodeId::as_str), Some("pc"));
    let head = fixture
        .streams
        .durable_head(&view.telemetry_stream_id)
        .expect("telemetry stream");
    assert_eq!(head.get(), 1, "one batch for the two status lines");

    // The pod-reported checkpoint is the mission's current one.
    let checkpoint = view
        .current_checkpoint_id
        .clone()
        .expect("the reported checkpoint is linked");
    let published = fixture
        .read_model
        .get(&ObjectRef {
            kind: ObjectKind::Simulation,
            id: checkpoint.to_string(),
        })
        .unwrap()
        .expect("the checkpoint is published");
    assert_eq!(published.value["label"], "iteration 2");

    // The same tail again: nothing new.
    fixture.desk.observe(&running, LOG, at).expect("observe");
    assert_eq!(
        fixture
            .streams
            .durable_head(&view.telemetry_stream_id)
            .unwrap()
            .get(),
        1
    );
    let more = format!("{LOG}2026-10-04T02:00:04Z ODIN-STATUS {{\"iteration\": 3}}\n");
    fixture.desk.observe(&running, &more, at).expect("observe");
    assert_eq!(
        fixture
            .streams
            .durable_head(&view.telemetry_stream_id)
            .unwrap()
            .get(),
        2
    );
}

/// Queued jobs observed as finished must still pass through the running stage.
#[test]
fn the_stage_follows_the_job_and_a_vanished_job_aborts() {
    let fixture = fixture();
    let at = OffsetDateTime::now_utc();
    fixture
        .desk
        .observe(&run(KubeWorkloadState::Running), "", at)
        .unwrap();
    fixture
        .desk
        .observe(&run(KubeWorkloadState::Suspended), "", at)
        .unwrap();
    assert_eq!(
        mission(&fixture, &run(KubeWorkloadState::Running)).stage,
        SimulationMissionStage::Paused
    );

    let queued = fixture_with(KubeWorkloadState::Pending, "kube-run-two");
    fixture.desk.observe(&queued, "", at).unwrap();
    assert_eq!(
        mission(&fixture, &queued).stage,
        SimulationMissionStage::Queued
    );
    let finished = ObservedRun {
        state: KubeWorkloadState::Succeeded,
        ..queued.clone()
    };
    fixture.desk.observe(&finished, "", at).unwrap();
    assert_eq!(
        mission(&fixture, &queued).stage,
        SimulationMissionStage::Succeeded
    );
    assert!(
        !fixture.desk.wants_log(&queued.run_id),
        "a finished mission"
    );

    // Only the second run is still listed; the paused first one vanished.
    fixture
        .desk
        .retire_missing(&BTreeSet::from([queued.run_id.clone()]), at);
    let first = mission(&fixture, &run(KubeWorkloadState::Running));
    assert_eq!(first.stage, SimulationMissionStage::Aborted);
    assert_eq!(
        mission(&fixture, &queued).stage,
        SimulationMissionStage::Succeeded
    );
}

fn fixture_with(state: KubeWorkloadState, run_id: &str) -> ObservedRun {
    let mut observed = run(state);
    observed.run_id = RunId::new(run_id).unwrap();
    observed.workload.uid = format!("uid-{run_id}");
    observed
}

/// Check the mission revision before routing commands to the corresponding kube revision.
#[test]
fn simulation_commands_are_served() {
    let fixture = fixture();
    let running = run(KubeWorkloadState::Running);
    let at = OffsetDateTime::now_utc();
    fixture.desk.observe(&running, LOG, at).unwrap();
    let revision = mission(&fixture, &running).revision;

    let pause = SimulationCommand::Pause {
        context: context(&running, "pause-1", revision),
    };
    let kube = fixture
        .desk
        .kube_command(&pause, |workload| {
            (workload.name == "sim-fixture-1").then_some(7)
        })
        .expect("pause routes")
        .expect("pause is a kube verb");
    match kube {
        odin_domain::huginn::KubeCommand::SuspendWorkload {
            run_id,
            expected_revision,
            ..
        } => {
            assert_eq!(run_id, running.run_id);
            assert_eq!(expected_revision, 7);
        }
        other => panic!("pause must suspend the Job: {other:?}"),
    }
    let abort = SimulationCommand::Abort {
        context: context(&running, "abort-1", revision),
        reason: "done".to_owned(),
    };
    assert!(matches!(
        fixture.desk.kube_command(&abort, |_| Some(7)).unwrap(),
        Some(odin_domain::huginn::KubeCommand::DeleteWorkload { .. })
    ));
    let stale = SimulationCommand::Resume {
        context: context(&running, "resume-1", revision + 9),
    };
    assert!(matches!(
        fixture.desk.kube_command(&stale, |_| Some(7)),
        Err(HuginnProtocolError::RevisionMismatch { .. })
    ));

    let checkpoint = SimulationCommand::CreateCheckpoint {
        context: context(&running, "checkpoint-1", revision),
        checkpoint_id: CheckpointId::new("operator-checkpoint-1").unwrap(),
        label: "before the change".to_owned(),
    };
    assert!(fixture
        .desk
        .kube_command(&checkpoint, |_| Some(7))
        .unwrap()
        .is_none());
    let receipt = fixture
        .desk
        .execute_board(&checkpoint, at)
        .expect("a checkpoint while running");
    assert!(matches!(receipt, CommandReceipt::Accepted { .. }));
    let after = mission(&fixture, &running);
    assert_eq!(
        after
            .current_checkpoint_id
            .as_ref()
            .map(CheckpointId::as_str),
        Some("operator-checkpoint-1")
    );

    let render = SimulationCommand::RequestRender {
        context: context(&running, "render-1", after.revision),
        render_id: RenderId::new(uuid::Uuid::from_u128(7)).unwrap(),
        renderer_id: RendererId::new("undeclared-v1").unwrap(),
        renderer_version: "1".to_owned(),
        parameters: after.case.clone(),
    };
    assert!(fixture.desk.execute_board(&render, at).is_err());
    let intervene = SimulationCommand::Intervene {
        context: context(&running, "intervene-1", after.revision),
        intervention: SimulationIntervention::AbstainAndEscalate {
            reason: "check".to_owned(),
        },
    };
    assert!(matches!(
        fixture.desk.execute_board(&intervene, at),
        Err(HuginnProtocolError::Conflict { code, .. }) if code == "approvalRequired"
    ));
}
