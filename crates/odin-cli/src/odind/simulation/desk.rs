use super::*;
use odin_domain::huginn::{
    ArtifactKind, LiveStreamKind, LiveStreamMode, Sequence, SimulationCheckpointView,
    SimulationMissionView, SimulationOutputId, SimulationTelemetryView,
};
use odin_domain::CheckpointId;
use odin_huginn::simulation::{checkpoint_delta, mission_delta, stage_transition_allowed};

impl Desk {
    pub(super) fn observe(
        &mut self,
        run: &ObservedRun,
        log: &str,
        streams: &BoundedMultiplexer,
        backpressure: StreamBackpressureLimits,
        at: OffsetDateTime,
    ) -> Result<Publication, String> {
        let mut publication = Publication::default();
        let before = match self.control.board().mission(&run.run_id) {
            Some(mission) => mission.revision,
            None => {
                self.register(run, at)?;
                tracing::info!(
                    "simulation mission registered run={} profile={} state={:?}",
                    run.run_id,
                    run.profile,
                    run.state
                );
                0
            }
        };
        self.follow(run, at);
        let cursor = self.cursors.entry(run.run_id.clone()).or_default();
        let new = reports(log, cursor.after);
        if let Some(newest) = new
            .iter()
            .map(|report| match report {
                Report::Status(at, _) | Report::Checkpoint(at, _) | Report::Render(at, _) => *at,
            })
            .max()
        {
            cursor.after = Some(newest);
        }
        let mut samples = Vec::new();
        for report in new {
            match report {
                Report::Status(stamp, status) => samples.push((stamp, status)),
                Report::Render(_, line) => match frame_report(run, &line) {
                    Ok(frame) => publication.reads.push(frame),
                    Err(reason) => {
                        tracing::error!(
                            "simulation frame refused run={} reason={reason}",
                            run.run_id
                        );
                        let renderer = line
                            .get("renderer")
                            .and_then(serde_json::Value::as_str)
                            .and_then(|renderer| RendererId::new(renderer).ok());
                        let failed = self.fail_running(&run.run_id, renderer.as_ref(), &reason, at);
                        publication.deltas.extend(failed.deltas);
                    }
                },
                Report::Checkpoint(stamp, checkpoint) => {
                    match self
                        .pod_checkpoint(run, stamp, checkpoint)
                        .and_then(|view| checkpoint_delta(&view, 0))
                    {
                        Ok(delta) => publication.deltas.push(delta),
                        Err(error) => tracing::error!(
                            "simulation checkpoint refused run={} error={error}",
                            run.run_id
                        ),
                    }
                }
            }
        }
        if !samples.is_empty() {
            match self.telemetry(run, samples, streams, backpressure, at) {
                Ok(frame) => publication.frames.push(frame),
                Err(error) => tracing::error!(
                    "simulation telemetry refused run={} error={error}",
                    run.run_id
                ),
            }
        }
        self.watch_staleness(&run.run_id, at);
        if let Some(mission) = self.control.board().mission(&run.run_id) {
            if mission.revision != before {
                // Checkpoint objects precede the mission that links them.
                publication
                    .deltas
                    .push(mission_delta(mission, before).map_err(|error| error.to_string())?);
            }
        }
        self.prune(&run.run_id);
        Ok(publication)
    }

    fn register(&mut self, run: &ObservedRun, at: OffsetDateTime) -> Result<(), String> {
        let cursor = self.cursors.entry(run.run_id.clone()).or_default();
        cursor.profile.clone_from(&run.profile);
        cursor.lane.clone_from(&run.lane);
        cursor.simulation.clone_from(&run.simulation);
        cursor.declared = run.declared;
        let key = run_key(&run.run_id);
        let artifacts = self.control.board_mut().artifacts_mut();
        let mut publish = |name: &str, value: &serde_json::Value| {
            let bytes = serde_json::to_vec(value).map_err(|error| error.to_string())?;
            artifacts
                .publish(
                    ArtifactId::new(format!("sim-{name}-{key}"))
                        .map_err(|error| error.to_string())?,
                    ArtifactKind::File,
                    &format!("{name}.json"),
                    "application/json",
                    &bytes,
                )
                .map_err(|error| error.to_string())
        };
        let case = publish(
            "case",
            &serde_json::json!({"profile": run.profile, "declaration": run.declaration}),
        )?;
        let obligations = publish(
            "obligations",
            &serde_json::json!({"profile": run.profile, "obligations": []}),
        )?;
        let stage = match stage_of(run.state) {
            Some(SimulationMissionStage::Aborted) | None => SimulationMissionStage::Queued,
            Some(stage) => stage,
        };
        let stream = |purpose: &str| {
            StreamId::new(derived_uuid(purpose, &run.run_id)).map_err(|error| error.to_string())
        };
        self.control
            .board_mut()
            .register_mission(SimulationMissionView {
                run_id: run.run_id.clone(),
                revision: 1,
                label: run.profile.clone(),
                stage,
                case,
                geometry: None,
                node_id: run.node_id.clone(),
                workload: Some(run.workload.resource().clone()),
                telemetry_stream_id: stream("telemetry")?,
                frame_stream_id: stream("frames")?,
                current_checkpoint_id: None,
                supported_renderers: run.simulation.renderers.clone(),
                evidence_obligations: obligations,
                started_at: run.started_at,
                finished_at: run.finished_at,
                updated_at: at,
                stale: false,
                failure: None,
            });
        Ok(())
    }

    /// Normalize a Job's queued-to-succeeded jump through the required running stage.
    fn follow(&mut self, run: &ObservedRun, at: OffsetDateTime) {
        let board = self.control.board_mut();
        let Some(mission) = board.mission(&run.run_id) else {
            return;
        };
        let (current, node_changed) = (
            mission.stage,
            run.node_id.is_some() && run.node_id != mission.node_id,
        );
        if node_changed || mission.workload.as_ref() != Some(run.workload.resource()) {
            // A rehome moves the run to another node (and Job object).
            if let Err(error) = board.set_links(
                &run.run_id,
                run.node_id.clone(),
                Some(run.workload.resource().clone()),
                at,
            ) {
                tracing::warn!(
                    "simulation run {} rehome links not recorded: {error}",
                    run.run_id
                );
            }
        }
        let Some(target) = stage_of(run.state) else {
            return;
        };
        if target == current || is_terminal(current) {
            return;
        }
        let result = if target == SimulationMissionStage::Aborted {
            board.abort(&run.run_id, "the workload is terminating", at)
        } else if stage_transition_allowed(current, target) {
            board.transition_stage(&run.run_id, target, at)
        } else if stage_transition_allowed(current, SimulationMissionStage::Running)
            && stage_transition_allowed(SimulationMissionStage::Running, target)
        {
            board
                .transition_stage(&run.run_id, SimulationMissionStage::Running, at)
                .and_then(|_| board.transition_stage(&run.run_id, target, at))
        } else {
            Ok((0, 0))
        };
        match result {
            Err(error) => tracing::error!(
                "simulation stage not followed run={} from={current:?} to={target:?} error={error}",
                run.run_id
            ),
            Ok(_) => {
                let kind = match target {
                    SimulationMissionStage::Failed => Some("failed"),
                    SimulationMissionStage::Aborted => Some("aborted"),
                    SimulationMissionStage::Paused => Some("paused"),
                    _ => None,
                };
                if let Some(kind) = kind {
                    self.stage_event(&run.run_id, kind, None, at);
                }
            }
        }
    }

    /// Records one stage event, told with the mission's stage, node and last sample.
    fn stage_event(
        &mut self,
        run_id: &RunId,
        kind: &'static str,
        reason: Option<&str>,
        at: OffsetDateTime,
    ) {
        let Some(mission) = self.control.board().mission(run_id) else {
            return;
        };
        let cursor = self.cursors.get(run_id);
        if !cursor.is_some_and(|cursor| cursor.declared) {
            return;
        }
        let sample = cursor
            .and_then(|cursor| cursor.latest.as_ref())
            .map_or_else(
                || "no sample yet".to_owned(),
                |(stamp, status)| {
                    let mut text = status.to_string();
                    if text.len() > 300 {
                        text.truncate(text.floor_char_boundary(300));
                        text.push('…');
                    }
                    format!(
                        "last sample {text} at {}",
                        stamp.format(&Rfc3339).unwrap_or_default()
                    )
                },
            );
        let node = mission.node_id.as_ref().map_or("no node", NodeId::as_str);
        let why = reason
            .or(mission.failure.as_deref())
            .map(|why| format!(" ({why})"))
            .unwrap_or_default();
        self.events.push(StageEvent {
            run_id: run_id.clone(),
            lane: cursor.and_then(|cursor| cursor.lane.clone()),
            profile: cursor
                .map(|cursor| cursor.profile.clone())
                .unwrap_or_default(),
            kind,
            key: format!("{run_id}:{kind}:{}", mission.revision),
            text: format!(
                "Mission {} (run {run_id}) is {kind}{why} on {node}; {sample}.",
                mission.label
            ),
            at,
        });
    }

    /// A running mission that stopped reporting is stale once per episode.
    fn watch_staleness(&mut self, run_id: &RunId, at: OffsetDateTime) {
        let running = self
            .control
            .board()
            .mission(run_id)
            .is_some_and(|mission| mission.stage == SimulationMissionStage::Running);
        let Some(cursor) = self.cursors.get_mut(run_id) else {
            return;
        };
        let after = time::Duration::seconds(i64::from(cursor.simulation.stale_seconds()));
        let stale = running
            && cursor
                .latest
                .as_ref()
                .is_some_and(|(stamp, _)| at - *stamp > after);
        if !stale {
            cursor.stale_told = false;
            return;
        }
        if !cursor.stale_told {
            cursor.stale_told = true;
            let why = format!("no status line for {} seconds", after.whole_seconds());
            self.stage_event(run_id, "stale", Some(&why), at);
        }
    }

    /// Publishes a frame's render: completes the running request for its
    /// renderer or records the pod's own, keeps it, and retires the oldest.
    pub(super) fn record_frame(
        &mut self,
        report: &FrameReport,
        artifact: ArtifactRef,
        at: OffsetDateTime,
    ) -> Publication {
        let mut publication = Publication::default();
        let Some(mission) = self.control.board().mission(&report.run_id).cloned() else {
            publication.retired.push(artifact);
            return publication;
        };
        let (renders, _) = self.control.renders_mut();
        let rendered = match renders.running_for(&report.run_id, &report.renderer) {
            Some(render_id) => {
                renders
                    .complete(&render_id, artifact.clone(), at)
                    .and_then(|(from, _)| {
                        let view = renders.render(&render_id).cloned().ok_or_else(|| {
                            invalid("simulationRender", format!("render {render_id} vanished"))
                        })?;
                        Ok((render_id, SimulationRenderBoard::render_delta(&view, from)?))
                    })
            }
            None => RenderId::new(derived_uuid(
                &format!("render-{}-{}", report.seq, at.unix_timestamp_nanos()),
                &report.run_id,
            ))
            .map_err(|error| invalid("simulationRenderIdentity", error.to_string()))
            .and_then(|render_id| {
                let view =
                    renders.record(&mission, render_id, &report.renderer, artifact.clone(), at)?;
                Ok((render_id, SimulationRenderBoard::render_delta(&view, 0)?))
            }),
        };
        let render_id = match rendered {
            Ok((render_id, delta)) => {
                publication.deltas.push(delta);
                render_id
            }
            Err(error) => {
                tracing::error!(
                    "simulation frame not recorded run={} error={error}",
                    report.run_id
                );
                publication.retired.push(artifact);
                return publication;
            }
        };
        let cursor = self.cursors.entry(report.run_id.clone()).or_default();
        cursor.frame_sequence += 1;
        let sequence = cursor.frame_sequence;
        let keep = cursor.simulation.keep_frames();
        let kept = cursor.frames.entry(report.renderer.clone()).or_default();
        kept.push_back(KeptFrame {
            artifact: artifact.clone(),
            render_id,
            seq: report.seq,
            sim_time_us: report.sim_time_us,
            at,
        });
        let mut dropped = Vec::new();
        while kept.len() > keep {
            dropped.extend(kept.pop_front());
        }
        for frame in dropped {
            if let Some(delta) = self.forget_render(&frame.render_id, at) {
                publication.deltas.push(delta);
            }
            publication.retired.push(frame.artifact);
        }
        publication.frames.push(StreamFrameSpec {
            stream_id: mission.frame_stream_id,
            kind: LiveStreamKind::SimulationFrames,
            mode: LiveStreamMode::LatestFrame,
            sequence,
            control_revision: mission.revision,
            content: artifact,
        });
        publication
    }

    /// Drops a finished render from the board and the read model.
    fn forget_render(&mut self, render_id: &RenderId, at: OffsetDateTime) -> Option<ObjectDelta> {
        let (renders, _) = self.control.renders_mut();
        let revision = renders.render(render_id)?.revision;
        renders.forget(render_id);
        Some(remove_delta(render_id.to_string(), revision, at))
    }

    /// Fails the running render of `renderer` (any renderer when `None` names none), with the reason as evidence.
    pub(super) fn fail_running(
        &mut self,
        run_id: &RunId,
        renderer: Option<&RendererId>,
        reason: &str,
        at: OffsetDateTime,
    ) -> Publication {
        match renderer.and_then(|renderer| self.control.renders().running_for(run_id, renderer)) {
            Some(render_id) => self.fail_render(run_id, render_id, reason, at),
            None => Publication::default(),
        }
    }

    pub(super) fn fail_render(
        &mut self,
        run_id: &RunId,
        render_id: RenderId,
        reason: &str,
        at: OffsetDateTime,
    ) -> Publication {
        let mut publication = Publication::default();
        let (renders, board) = self.control.renders_mut();
        let evidence = ArtifactId::new(format!("sim-render-failure-{}", render_id))
            .ok()
            .and_then(|id| {
                board
                    .artifacts_mut()
                    .publish(
                        id,
                        ArtifactKind::File,
                        "render-failure.txt",
                        "text/plain",
                        reason.as_bytes(),
                    )
                    .ok()
            });
        match renders.fail(&render_id, evidence, at) {
            Ok((from, _)) => {
                if let Some(view) = renders.render(&render_id) {
                    match SimulationRenderBoard::render_delta(view, from) {
                        Ok(delta) => publication.deltas.push(delta),
                        Err(error) => {
                            tracing::error!("simulation render delta refused error={error}")
                        }
                    }
                }
                self.stage_event(run_id, "render-failed", Some(reason), at);
            }
            Err(error) => tracing::error!(
                "simulation render {render_id} not failed run={run_id} error={error}"
            ),
        }
        publication
    }

    pub(super) fn start_render(
        &mut self,
        run_id: &RunId,
        at: OffsetDateTime,
    ) -> (Option<RenderStart>, Publication) {
        let Some(mission) = self.control.board().mission(run_id).cloned() else {
            return (None, Publication::default());
        };
        let Some(requested) = self.control.renders().next_requested(run_id).cloned() else {
            return (None, Publication::default());
        };
        if mission.stage != SimulationMissionStage::Running {
            if is_terminal(mission.stage) {
                let reason = format!(
                    "the mission ended {:?} before the render ran",
                    mission.stage
                );
                return (
                    None,
                    self.fail_render(run_id, requested.render_id, &reason, at),
                );
            }
            return (None, Publication::default());
        }
        let cursor = self.cursors.get(run_id);
        let simulation = cursor
            .map(|cursor| cursor.simulation.clone())
            .unwrap_or_default();
        let command = simulation.render_command.clone();
        if command.is_empty() {
            let reason = format!(
                "profile {} declares no simulation.render_command",
                cursor.map(|cursor| cursor.profile.as_str()).unwrap_or("?")
            );
            return (
                None,
                self.fail_render(run_id, requested.render_id, &reason, at),
            );
        }
        // The mission's case stands for the pod's own defaults.
        let parameters = if requested.parameters_digest == mission.case.content_digest {
            "{}".to_owned()
        } else {
            match self
                .control
                .board()
                .artifacts()
                .bytes_by_digest(&requested.parameters_digest)
                .and_then(|bytes| std::str::from_utf8(bytes).ok())
                .filter(|text| {
                    serde_json::from_str::<serde_json::Map<String, serde_json::Value>>(text).is_ok()
                }) {
                Some(text) => text.to_owned(),
                None => {
                    return (
                        None,
                        self.fail_render(
                            run_id,
                            requested.render_id,
                            "the render parameters are not a stored JSON object",
                            at,
                        ),
                    )
                }
            }
        };
        let mut publication = Publication::default();
        let (renders, _) = self.control.renders_mut();
        match renders.transition(&requested.render_id, SimulationRenderStatus::Running, 0, at) {
            Ok((from, _)) => {
                if let Some(view) = renders.render(&requested.render_id) {
                    if let Ok(delta) = SimulationRenderBoard::render_delta(view, from) {
                        publication.deltas.push(delta);
                    }
                }
            }
            Err(error) => {
                tracing::error!("simulation render not started run={run_id} error={error}");
                return (None, publication);
            }
        }
        let mut argv = command;
        argv.push(requested.renderer_id.to_string());
        argv.push(parameters);
        let max_bytes = simulation.max_frame_bytes();
        let wait = StdDuration::from_secs(u64::from(simulation.render_timeout_seconds()));
        (
            Some(RenderStart {
                run_id: run_id.clone(),
                render_id: requested.render_id,
                renderer: requested.renderer_id,
                argv,
                max_bytes,
                wait,
            }),
            publication,
        )
    }

    /// Missions a read names: all, or those whose run id, label or workload is `mission`.
    pub(super) fn matching(
        &self,
        mission: Option<&str>,
    ) -> Result<Vec<SimulationMissionView>, String> {
        let all = self.control.board().missions();
        let Some(wanted) = mission else {
            return Ok(all.cloned().collect());
        };
        let found: Vec<_> = all
            .filter(|view| {
                view.run_id.as_str() == wanted
                    || view.label == wanted
                    || view
                        .workload
                        .as_ref()
                        .is_some_and(|workload| workload.name == wanted)
            })
            .cloned()
            .collect();
        if found.is_empty() {
            return Err(format!("no mission is {wanted:?}"));
        }
        Ok(found)
    }

    /// One mission as a read shows it.
    pub(super) fn describe(&self, view: &SimulationMissionView) -> serde_json::Value {
        let cursor = self.cursors.get(&view.run_id);
        let stamp = |at: OffsetDateTime| at.format(&Rfc3339).unwrap_or_default();
        let renders: Vec<_> = self
            .control
            .renders()
            .of_run(&view.run_id)
            .filter(|render| render.status != SimulationRenderStatus::Complete)
            .map(|render| {
                serde_json::json!({
                    "renderer": render.renderer_id,
                    "status": render.status,
                    "requestedAt": stamp(render.requested_at),
                })
            })
            .collect();
        let checkpoints: Vec<_> = self
            .control
            .board()
            .checkpoints_of(&view.run_id)
            .map(|checkpoint| {
                serde_json::json!({
                    "id": checkpoint.checkpoint_id,
                    "label": checkpoint.label,
                    "at": stamp(checkpoint.created_at),
                })
            })
            .collect();
        serde_json::json!({
            "run": view.run_id,
            "label": view.label,
            "profile": cursor.map(|cursor| cursor.profile.as_str()),
            "stage": view.stage,
            "node": view.node_id,
            "workload": view.workload.as_ref().map(|workload| &workload.name),
            "startedAt": view.started_at.map(stamp),
            "finishedAt": view.finished_at.map(stamp),
            "failure": view.failure,
            "lastSample": cursor.and_then(|cursor| cursor.latest.as_ref()).map(|(at, status)| serde_json::json!({
                "at": stamp(*at),
                "status": status,
            })),
            "plot": cursor.map(|cursor| cursor.simulation.plot.clone()).unwrap_or_default(),
            "renderers": view.supported_renderers,
            "checkpoints": checkpoints,
            "openRenders": renders,
            "frames": cursor.map(|cursor| cursor.frames.iter().map(|(renderer, frames)| serde_json::json!({
                "renderer": renderer,
                "kept": frames.len(),
                "latest": frames.back().map(|frame| serde_json::json!({
                    "artifact": frame.artifact.artifact_id,
                    "mediaType": frame.artifact.media_type,
                    "seq": frame.seq,
                    "simTimeUs": frame.sim_time_us,
                    "bytes": frame.artifact.byte_len,
                    "at": stamp(frame.at),
                })),
            })).collect::<Vec<_>>()).unwrap_or_default(),
        })
    }

    fn telemetry(
        &mut self,
        run: &ObservedRun,
        mut samples: Vec<(OffsetDateTime, serde_json::Value)>,
        streams: &BoundedMultiplexer,
        backpressure: StreamBackpressureLimits,
        at: OffsetDateTime,
    ) -> Result<StreamFrameSpec, String> {
        let truncated = samples.len() > MAX_SAMPLES_PER_BATCH;
        if truncated {
            samples.drain(..samples.len() - MAX_SAMPLES_PER_BATCH);
        }
        let mission = self
            .control
            .board()
            .mission(&run.run_id)
            .cloned()
            .ok_or("mission is not registered")?;
        let cursor = self.cursors.entry(run.run_id.clone()).or_default();
        if cursor.sequence == 0 {
            // The stream is durable and outlives this daemon: resume after
            // what an earlier daemon published for the same run.
            cursor.sequence = streams
                .durable_head(&mission.telemetry_stream_id)
                .map_err(|error| error.to_string())?
                .get();
        }
        cursor.sequence += 1;
        let sequence = cursor.sequence;
        let recorded_at = samples.last().map_or(at, |(stamp, _)| *stamp);
        cursor.latest = samples.last().cloned();
        for key in cursor.simulation.plot.clone() {
            let series = cursor.series.entry(key.clone()).or_default();
            series.extend(
                samples
                    .iter()
                    .filter_map(|(_, status)| status.get(&key).and_then(serde_json::Value::as_f64)),
            );
            let over = series.len().saturating_sub(PLOT_POINTS);
            series.drain(..over);
        }
        let document = serde_json::json!({
            "run": run.run_id,
            "samples": samples
                .iter()
                .map(|(stamp, status)| serde_json::json!({
                    "at": stamp.format(&Rfc3339).unwrap_or_default(),
                    "status": status,
                }))
                .collect::<Vec<_>>(),
        });
        let bytes = serde_json::to_vec(&document).map_err(|error| error.to_string())?;
        let artifact_id =
            ArtifactId::new(format!("sim-telemetry-{}-{sequence}", run_key(&run.run_id)))
                .map_err(|error| error.to_string())?;
        let content = self
            .control
            .board_mut()
            .artifacts_mut()
            .publish(
                artifact_id.clone(),
                ArtifactKind::File,
                "telemetry.json",
                "application/json",
                &bytes,
            )
            .map_err(|error| error.to_string())?;
        let cursor = self.cursors.entry(run.run_id.clone()).or_default();
        cursor.artifacts.push_back(artifact_id);
        let view = SimulationTelemetryView {
            run_id: run.run_id.clone(),
            output_id: SimulationOutputId::new(derived_uuid("output", &run.run_id))
                .map_err(|error| error.to_string())?,
            sequence: Sequence::new(sequence),
            control_revision: mission.revision,
            recorded_at,
            sample_count: u64::try_from(samples.len()).unwrap_or(u64::MAX),
            content,
            truncated,
        };
        let bound = |value: u64| NonZeroU64::new(value).ok_or("zero ring bound");
        self.control
            .telemetry_ring_mut(
                &run.run_id,
                mission.telemetry_stream_id,
                NonZeroUsize::new(16).ok_or("zero ring bound")?,
                bound(4 << 20)?,
                backpressure,
            )
            .push(view, &bytes)
            .map_err(|error| error.to_string())?;
        // The ring is drained at once into the compact frame the stream
        // carries; the raw batch stays a board artifact.
        let frame = self
            .control
            .next_model_frame(&run.run_id, mission.telemetry_stream_id, at)
            .map_err(|error| error.to_string())?
            .ok_or("the telemetry ring yielded no frame")?;
        self.cursors
            .entry(run.run_id.clone())
            .or_default()
            .artifacts
            .push_back(frame.content.artifact_id.clone());
        Ok(StreamFrameSpec {
            stream_id: mission.telemetry_stream_id,
            kind: LiveStreamKind::SimulationTelemetry,
            mode: LiveStreamMode::Durable,
            sequence,
            control_revision: mission.revision,
            content: frame.content,
        })
    }

    /// The state artifact of a checkpoint: what the pod reported (if it
    /// reported the checkpoint itself), its newest status, and the volume
    /// its state lives on.
    pub(super) fn checkpoint_state(
        &mut self,
        run_id: &RunId,
        label: &str,
        reported: Option<&serde_json::Value>,
        at: OffsetDateTime,
    ) -> Result<ArtifactRef, HuginnProtocolError> {
        let mission = self
            .control
            .board()
            .mission(run_id)
            .cloned()
            .ok_or_else(|| HuginnProtocolError::NotFound {
                object_kind: "simulationMission".to_owned(),
                object_id: run_id.to_string(),
            })?;
        let cursor = self.cursors.entry(run_id.clone()).or_default();
        cursor.checkpoints += 1;
        let ordinal = cursor.checkpoints;
        let latest = cursor.latest.clone();
        let document = serde_json::json!({
            "run": run_id,
            "label": label,
            "at": at.format(&Rfc3339).unwrap_or_default(),
            "reported": reported,
            "latestStatus": latest.map(|(stamp, status)| serde_json::json!({
                "at": stamp.format(&Rfc3339).unwrap_or_default(),
                "status": status,
            })),
            "stateVolume": mission.workload.as_ref().map(|workload| workload.name.clone()),
        });
        let bytes = serde_json::to_vec(&document)
            .map_err(|error| invalid("simulationCheckpointState", error.to_string()))?;
        let artifact_id = ArtifactId::new(format!("sim-checkpoint-{}-{ordinal}", run_key(run_id)))
            .map_err(|error| invalid("simulationCheckpointState", error.to_string()))?;
        let reference = self.control.board_mut().artifacts_mut().publish(
            artifact_id.clone(),
            ArtifactKind::File,
            "checkpoint.json",
            "application/json",
            &bytes,
        )?;
        self.cursors
            .entry(run_id.clone())
            .or_default()
            .artifacts
            .push_back(artifact_id);
        Ok(reference)
    }

    /// A checkpoint the pod reported: linked as the mission's current one.
    fn pod_checkpoint(
        &mut self,
        run: &ObservedRun,
        stamp: OffsetDateTime,
        reported: serde_json::Value,
    ) -> Result<SimulationCheckpointView, HuginnProtocolError> {
        let label = reported
            .get("label")
            .and_then(serde_json::Value::as_str)
            .map(|label| label.chars().take(80).collect::<String>());
        let ordinal = self
            .cursors
            .get(&run.run_id)
            .map_or(0, |cursor| cursor.checkpoints)
            + 1;
        let label = label.unwrap_or_else(|| format!("checkpoint {ordinal}"));
        let state = self.checkpoint_state(&run.run_id, &label, Some(&reported), stamp)?;
        let board = self.control.board_mut();
        let parent = board
            .mission(&run.run_id)
            .and_then(|mission| mission.current_checkpoint_id.clone());
        let view = SimulationCheckpointView {
            checkpoint_id: CheckpointId::new(format!(
                "sim-ckpt-{}-{ordinal}",
                run_key(&run.run_id)
            ))
            .map_err(|error| invalid("simulationCheckpointIdentity", error.to_string()))?,
            run_id: run.run_id.clone(),
            revision: 1,
            parent_checkpoint_id: parent,
            label,
            created_at: stamp,
            state_digest: state.content_digest,
            state,
        };
        board.add_checkpoint(view.clone())?;
        board.set_current_checkpoint(&run.run_id, &view.checkpoint_id, stamp)?;
        Ok(view)
    }

    pub(super) fn retire_missing(
        &mut self,
        live_runs: &BTreeSet<RunId>,
        at: OffsetDateTime,
    ) -> Publication {
        let gone: Vec<(RunId, u64)> = self
            .control
            .board()
            .missions()
            .filter(|mission| !is_terminal(mission.stage) && !live_runs.contains(&mission.run_id))
            .map(|mission| (mission.run_id.clone(), mission.revision))
            .collect();
        let mut publication = Publication::default();
        for (run_id, before) in gone {
            let board = self.control.board_mut();
            if board.abort(&run_id, "the workload is gone", at).is_ok() {
                tracing::error!("simulation mission aborted run={run_id} reason=workload gone");
                match board
                    .mission(&run_id)
                    .map(|mission| mission_delta(mission, before))
                {
                    Some(Ok(delta)) => publication.deltas.push(delta),
                    Some(Err(error)) => {
                        tracing::error!(
                            "simulation mission delta refused run={run_id} error={error}"
                        )
                    }
                    None => {}
                }
                self.stage_event(&run_id, "aborted", None, at);
            }
        }
        // A mission whose Job is gone leaves the board a day after it ended.
        let old: Vec<RunId> = self
            .control
            .board()
            .missions()
            .filter(|mission| {
                is_terminal(mission.stage)
                    && !live_runs.contains(&mission.run_id)
                    && at - mission.finished_at.unwrap_or(mission.updated_at)
                        > time::Duration::hours(i64::from(
                            self.cursors
                                .get(&mission.run_id)
                                .map_or_else(WorkloadSimulationToml::default, |cursor| {
                                    cursor.simulation.clone()
                                })
                                .retire_after_hours(),
                        ))
            })
            .map(|mission| mission.run_id.clone())
            .collect();
        for run_id in old {
            self.retire(&run_id, at, &mut publication);
        }
        publication
    }

    /// Drops a mission with its checkpoints, renders, frames and artifacts.
    fn retire(&mut self, run_id: &RunId, at: OffsetDateTime, publication: &mut Publication) {
        let renders: Vec<RenderId> = self
            .control
            .renders()
            .of_run(run_id)
            .map(|render| render.render_id)
            .collect();
        for render_id in renders {
            if let Some(delta) = self.forget_render(&render_id, at) {
                publication.deltas.push(delta);
            }
        }
        if let Some(cursor) = self.cursors.remove(run_id) {
            let artifacts = self.control.board_mut().artifacts_mut();
            for id in cursor.artifacts {
                artifacts.remove(&id);
            }
            publication.retired.extend(
                cursor
                    .frames
                    .into_values()
                    .flatten()
                    .map(|frame| frame.artifact),
            );
        }
        if let Some((mission, checkpoints)) = self.control.board_mut().remove_mission(run_id) {
            for checkpoint in checkpoints {
                self.control
                    .board_mut()
                    .artifacts_mut()
                    .remove(&checkpoint.state.artifact_id);
                publication.deltas.push(remove_delta(
                    checkpoint.checkpoint_id.to_string(),
                    checkpoint.revision,
                    at,
                ));
            }
            for artifact in [&mission.case, &mission.evidence_obligations] {
                self.control
                    .board_mut()
                    .artifacts_mut()
                    .remove(&artifact.artifact_id);
            }
            publication
                .deltas
                .push(remove_delta(run_id.to_string(), mission.revision, at));
            tracing::info!("simulation mission retired run={run_id}");
        }
    }

    fn prune(&mut self, run_id: &RunId) {
        let Some(cursor) = self.cursors.get_mut(run_id) else {
            return;
        };
        let mut dropped = Vec::new();
        while cursor.artifacts.len() > KEPT_ARTIFACTS_PER_RUN {
            if let Some(id) = cursor.artifacts.pop_front() {
                dropped.push(id);
            }
        }
        let artifacts = self.control.board_mut().artifacts_mut();
        for id in dropped {
            artifacts.remove(&id);
        }
    }
}
