//! Workload missions, telemetry, checkpoints, and simulation command routing.

use std::collections::BTreeSet;
use std::num::{NonZeroU32, NonZeroU64};
use std::sync::{Arc, Mutex};

use odin_domain::huginn::{
    KubeResourceRef, KubeWorkloadState, ObjectKind, ObjectRef, RendererId, SimulationMissionStage,
    SimulationMissionView, StreamBackpressureLimits,
};
use odin_domain::{NodeId, RunId};
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

/// A restarted daemon re-reads a finished run's log: its telemetry resumes
/// after the durable head an earlier daemon left, never at sequence 1 again.
#[test]
fn a_restarted_desk_resumes_the_durable_telemetry_stream() {
    let first = fixture();
    let finished = run(KubeWorkloadState::Succeeded);
    let at = OffsetDateTime::now_utc();
    first.desk.observe(&finished, LOG, at).expect("observe");
    let stream = mission(&first, &finished).telemetry_stream_id;
    assert_eq!(first.streams.durable_head(&stream).unwrap().get(), 1);

    let restarted = SimulationDesk::new(
        Arc::clone(&first.read_model),
        Arc::clone(&first.streams),
        first.desk.backpressure,
        Arc::new(Mutex::new(Ledger::open_in_memory().expect("ledger"))),
    )
    .expect("desk");
    restarted.observe(&finished, LOG, at).expect("observe");
    assert_eq!(first.streams.durable_head(&stream).unwrap().get(), 2);
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
