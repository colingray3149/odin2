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
use odin_huginn::service::FsPublishedArtifactStore;
use odin_huginn::streams::{BoundedMultiplexer, DurableReplayStore};
use odin_ledger::Ledger;
use odin_registry::schema::WorkloadSimulationToml;
use time::OffsetDateTime;

use super::{
    checked_frame, frame_report, FrameReport, ObservedRun, ObservedWorkload, SimulationDesk,
};

struct Fixture {
    desk: SimulationDesk,
    read_model: Arc<MaterializedReadModel>,
    streams: Arc<BoundedMultiplexer>,
    published: Arc<FsPublishedArtifactStore>,
    _dir: tempfile::TempDir,
}

fn published(dir: &std::path::Path) -> Arc<FsPublishedArtifactStore> {
    let id = |name: &str| odin_domain::LaneId::new(name).unwrap();
    Arc::new(
        FsPublishedArtifactStore::open(
            dir.join("published"),
            odin_domain::huginn::LiveSessionId::new(uuid::Uuid::from_u128(7)).unwrap(),
            id("files"),
            id("renders"),
        )
        .expect("published store"),
    )
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
    let published = published(dir.path());
    let desk = SimulationDesk::new(
        Arc::clone(&read_model),
        Arc::clone(&streams),
        limits,
        Arc::new(Mutex::new(Ledger::open_in_memory().expect("ledger"))),
        Arc::clone(&published),
    )
    .expect("desk");
    Fixture {
        desk,
        read_model,
        streams,
        published,
        _dir: dir,
    }
}
#[test]
fn mission_status_publishes_current_view_settings() {
    let fixture = fixture();
    let object = crate::huginn_spend::status_object("missions");
    fixture
        .desk
        .publish_status(OffsetDateTime::now_utc(), 5, 300);
    let value = fixture.read_model.get(&object).unwrap().unwrap().value;
    assert_eq!(value["viewPollSeconds"], 5);
    assert_eq!(value["viewPreviewMaxSide"], 300);
    fixture
        .desk
        .publish_status(OffsetDateTime::now_utc(), 12, 600);
    let value = fixture.read_model.get(&object).unwrap().unwrap().value;
    assert_eq!(value["viewPollSeconds"], 12);
    assert_eq!(value["viewPreviewMaxSide"], 600);
}

fn run(state: KubeWorkloadState) -> ObservedRun {
    ObservedRun {
        run_id: RunId::new("kube-run-sim-fixture-1").unwrap(),
        lane: Some(odin_domain::LaneId::new("simulation-lane").unwrap()),
        profile: "sim-fixture".to_owned(),
        declaration: serde_json::json!({"description": "toy"}),
        simulation: WorkloadSimulationToml {
            renderers: vec![RendererId::new("field_svg-v1").unwrap()],
            render_command: vec!["/bin/render".to_owned()],
            plot: vec!["residual".to_owned()],
            ..WorkloadSimulationToml::default()
        },
        declared: true,
        state,
        node_id: Some(NodeId::new("pc").unwrap()),
        workload: ObservedWorkload::Kube(KubeResourceRef {
            cluster: "odin".to_owned(),
            api_version: "batch/v1".to_owned(),
            kind: "Job".to_owned(),
            namespace: Some("odin-workloads".to_owned()),
            name: "sim-fixture-1".to_owned(),
            uid: "uid-1".to_owned(),
        }),
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
        Arc::clone(&first.published),
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
    let ObservedWorkload::Kube(resource) = &mut observed.workload else {
        panic!("fixture must be a Kubernetes workload");
    };
    resource.uid = format!("uid-{run_id}");
    observed
}

/// The smallest PNG a frame check accepts: the signature and one byte more.
const PNG: &[u8] = b"\x89PNG\r\n\x1a\n-";

fn render_line(renderer: &str, path: &str) -> String {
    format!(
        "2026-10-04T02:00:05Z ODIN-RENDER {{\"renderer\":\"{renderer}\",\"seq\":17,\"path\":\"{path}\",\"sim_time_us\":153.2}}\n"
    )
}

fn request_render(fixture: &Fixture, observed: &ObservedRun) {
    let view = mission(fixture, observed);
    let command = odin_domain::huginn::SimulationCommand::RequestRender {
        context: odin_domain::huginn::SimulationCommandContext {
            command_id: odin_domain::CommandId::new("cmd-render-1").unwrap(),
            run_id: observed.run_id.clone(),
            expected_revision: view.revision,
            arguments_digest: odin_domain::Digest::hash(b"render"),
            approval_id: None,
        },
        render_id: odin_domain::huginn::RenderId::new(uuid::Uuid::from_u128(9)).unwrap(),
        renderer_id: RendererId::new("field_svg-v1").unwrap(),
        renderer_version: "1".to_owned(),
        parameters: view.case.clone(),
    };
    fixture
        .desk
        .execute_board(&command, OffsetDateTime::now_utc())
        .expect("render requested");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_render_line_completes_the_running_request() {
    let fixture = fixture();
    let running = run(KubeWorkloadState::Running);
    let at = OffsetDateTime::now_utc();
    fixture.desk.observe(&running, LOG, at).expect("observe");
    request_render(&fixture, &running);

    let start = fixture
        .desk
        .start_render(&running.run_id, at)
        .expect("the render starts in the pod");
    assert_eq!(start.argv[0], "/bin/render");
    assert_eq!(start.argv[1], "field_svg-v1");
    assert_eq!(
        start.argv[2], "{}",
        "the case stands for the pod's defaults"
    );

    let line = render_line("field_svg-v1", "frames/field/000017.png");
    let reads = fixture
        .desk
        .observe(&running, &format!("{LOG}{line}"), at)
        .expect("observe");
    let [report] = reads.as_slice() else {
        panic!("one frame to read back: {reads:?}");
    };
    assert_eq!(
        report.read_argv().last().unwrap(),
        "/export/frames/field/000017.png"
    );
    fixture.desk.take_frame(report, Ok(PNG.to_vec()), at).await;

    let render = fixture
        .read_model
        .get(&ObjectRef {
            kind: ObjectKind::Simulation,
            id: start.render_id.to_string(),
        })
        .unwrap()
        .expect("the render is published");
    assert_eq!(render.value["status"], "complete");
    let (_, frame) = fixture
        .desk
        .latest_frame(running.run_id.as_str(), None)
        .expect("the frame is kept");
    assert_eq!(fixture.desk.frame_bytes(&frame).await.unwrap(), PNG);
}

#[test]
fn an_undeclared_renderer_is_refused() {
    let fixture = fixture();
    let running = run(KubeWorkloadState::Running);
    let reads = fixture
        .desk
        .observe(
            &running,
            &render_line("other", "frames/a.png"),
            OffsetDateTime::now_utc(),
        )
        .unwrap();
    assert!(reads.is_empty());
    let value = serde_json::json!({"renderer": "other", "seq": 1, "path": "frames/a.png"});
    let error = frame_report(&running, &value).unwrap_err();
    assert!(
        error.contains("other") && error.contains("not declared"),
        "{error}"
    );
}

#[test]
fn a_frame_path_outside_export_is_refused() {
    let running = run(KubeWorkloadState::Running);
    for path in ["../x.png", "/etc/x.png", "frames//x.png", "frames/x.html"] {
        let value = serde_json::json!({"renderer": "field_svg-v1", "seq": 1, "path": path});
        assert!(frame_report(&running, &value).is_err(), "{path} is refused");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn an_svg_frame_preserves_its_format() {
    let fixture = fixture();
    let running = run(KubeWorkloadState::Running);
    let at = OffsetDateTime::now_utc();
    let svg = br#"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 10 10"><path d="M0 0 L10 10" stroke="red"/></svg>"#;
    let reads = fixture
        .desk
        .observe(&running, &render_line("field_svg-v1", "frames/f.svg"), at)
        .unwrap();
    fixture
        .desk
        .take_frame(&reads[0], Ok(svg.to_vec()), at)
        .await;
    let (_, frame) = fixture
        .desk
        .latest_frame(running.run_id.as_str(), None)
        .unwrap();
    assert_eq!(frame.media_type, "image/svg+xml");
    assert!(frame.display_name.ends_with(".svg"));
    assert_eq!(fixture.desk.frame_bytes(&frame).await.unwrap(), svg);
    let read = fixture.desk.read(Some("sim-fixture")).unwrap();
    assert_eq!(
        read["missions"][0]["frames"][0]["latest"]["mediaType"],
        "image/svg+xml"
    );
}

#[test]
fn svg_frames_reject_active_external_or_malformed_content() {
    let running = run(KubeWorkloadState::Running);
    let report = frame_report(
        &running,
        &serde_json::json!({"renderer":"field_svg-v1", "seq":1, "path":"frames/f.svg"}),
    )
    .unwrap();
    for svg in [
        r#"<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>"#,
        r#"<svg xmlns="http://www.w3.org/2000/svg"><image href="https://example.com/a.png"/></svg>"#,
        r#"<svg xmlns="http://www.w3.org/2000/svg"><path onload="alert(1)"/></svg>"#,
        r#"<svg xmlns="http://www.w3.org/2000/svg"><path fill="url(https://example.com/a)"/></svg>"#,
        r#"<!DOCTYPE svg [<!ENTITY x SYSTEM "file:///etc/passwd">]><svg xmlns="http://www.w3.org/2000/svg">&x;</svg>"#,
        r#"<svg xmlns="http://www.w3.org/2000/svg"><path></svg>"#,
    ] {
        assert!(
            checked_frame(&report, svg.as_bytes().to_vec()).is_err(),
            "{svg}"
        );
    }
    assert!(checked_frame(&report, PNG.to_vec()).is_err());
}

#[test]
fn a_frame_over_the_cap_is_refused_naming_it() {
    let report = FrameReport {
        run_id: RunId::new("kube-run-sim-fixture-1").unwrap(),
        renderer: RendererId::new("field_svg-v1").unwrap(),
        seq: 1,
        path: "frames/big.png".to_owned(),
        sim_time_us: None,
        max_bytes: u64::try_from(PNG.len()).unwrap() - 1,
    };
    let error = checked_frame(&report, PNG.to_vec()).unwrap_err();
    assert!(
        error.contains("frames/big.png") && error.contains("cap"),
        "{error}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_read_names_the_mission_its_last_sample_and_frames() {
    let fixture = fixture();
    let running = run(KubeWorkloadState::Running);
    let at = OffsetDateTime::now_utc();
    let line = render_line("field_svg-v1", "frames/f.png");
    let reads = fixture
        .desk
        .observe(&running, &format!("{LOG}{line}"), at)
        .unwrap();
    fixture
        .desk
        .take_frame(&reads[0], Ok(PNG.to_vec()), at)
        .await;

    let read = fixture.desk.read(Some("sim-fixture")).unwrap();
    let mission = &read["missions"][0];
    assert_eq!(mission["stage"], "running");
    assert_eq!(mission["lastSample"]["status"]["iteration"], 2);
    assert_eq!(mission["plot"][0], "residual");
    assert_eq!(mission["frames"][0]["latest"]["seq"], 17);
    assert!(fixture.desk.read(Some("nothing")).is_err());
}

#[test]
fn a_paused_mission_is_a_stage_event() {
    let fixture = fixture();
    // Just after the log's last sample: not stale yet.
    let at = OffsetDateTime::parse(
        "2026-10-04T02:00:05Z",
        &time::format_description::well_known::Rfc3339,
    )
    .unwrap();
    fixture
        .desk
        .observe(&run(KubeWorkloadState::Running), LOG, at)
        .unwrap();
    assert!(fixture.desk.drain_events().is_empty());
    fixture
        .desk
        .observe(&run(KubeWorkloadState::Suspended), "", at)
        .unwrap();
    let events = fixture.desk.drain_events();
    let [event] = events.as_slice() else {
        panic!("one event: {events:?}");
    };
    assert_eq!(event.kind, "paused");
    assert_eq!(
        event.lane,
        Some(odin_domain::LaneId::new("simulation-lane").unwrap())
    );
    assert!(event.text.contains("sim-fixture") && event.text.contains("iteration"));
}
