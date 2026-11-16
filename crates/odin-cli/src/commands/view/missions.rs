//! The Missions tab's bridge side: the authority's `missions` Status object while the tab is open, the newest
//! frame of the mission the view opened (downloaded once per frame), and its render, pause and resume commands.

use base64::Engine as _;
use odin_domain::huginn as live;
use serde_json::{json, Value};

use super::{done, emit, emit_once, Bridge, REQUEST_BOUND};

/// The Status id odind publishes the simulation board under.
const MISSIONS_STATUS: &str = "missions";

#[derive(Default)]
pub(super) struct Missions {
    /// Whether the tab is showing; nothing is polled while it is not.
    pub(super) open: bool,
    /// Most recently published authority cadence, or the five-second default.
    pub(super) poll_seconds: Option<u64>,
    /// The mission whose frame the view shows.
    selected: Option<String>,
    last: String,
    /// The frame artifact last sent for `selected`.
    frame: Option<String>,
    preview_max_side: Option<u32>,
}

impl Bridge {
    /// `{t: "missions", open, run?}`: the tab opened, closed or moved to another mission.
    pub(super) async fn missions_view(&mut self, command: &Value) {
        self.missions.open = command
            .get("open")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let run = command
            .get("run")
            .and_then(Value::as_str)
            .map(str::to_owned);
        if run != self.missions.selected {
            self.missions.selected = run;
            self.missions.frame = None;
        }
        if self.missions.open {
            self.missions.last.clear();
            self.poll_missions().await;
        }
    }

    pub(super) async fn poll_missions(&mut self) {
        if !self.missions.open {
            return;
        }
        let Some(objects) = self.snapshot_all(live::ObjectKind::Status).await else {
            return;
        };
        let Some(value) = super::status_value(&objects, MISSIONS_STATUS).cloned() else {
            emit_once(
                &mut self.missions.last,
                &json!({ "t": "missions", "value": { "rows": [] } }),
            );
            return;
        };
        self.missions.poll_seconds = value
            .get("viewPollSeconds")
            .and_then(Value::as_u64)
            .filter(|seconds| *seconds > 0);
        let preview_max_side = match value.get("viewPreviewMaxSide") {
            None => 2048,
            Some(value) => match value
                .as_u64()
                .and_then(|side| u32::try_from(side).ok())
                .filter(|side| *side > 0)
            {
                Some(side) => side,
                None => {
                    tracing::warn!("invalid mission preview maximum side");
                    return;
                }
            },
        };
        if self.missions.preview_max_side != Some(preview_max_side) {
            self.missions.preview_max_side = Some(preview_max_side);
            self.missions.frame = None;
        }
        emit_once(
            &mut self.missions.last,
            &json!({ "t": "missions", "value": value }),
        );
        let Some(run) = self.missions.selected.clone() else {
            return;
        };
        let frame = value["rows"]
            .as_array()
            .and_then(|rows| rows.iter().find(|row| row["run"] == run.as_str()))
            .map(|row| &row["frame"]);
        let artifact = frame
            .and_then(|frame| frame["artifact"].as_str())
            .map(str::to_owned);
        let media_type = frame.and_then(|frame| frame["mediaType"].as_str());
        let Some(artifact) =
            artifact.filter(|artifact| self.missions.frame.as_ref() != Some(artifact))
        else {
            return;
        };
        let source = match artifact.parse() {
            Ok(id) => live::ContentSource::Artifact(id),
            Err(error) => {
                tracing::warn!("mission frame {artifact} is not an artifact id: {error}");
                return;
            }
        };
        let command_id = match odin_cli::authority_provision::random_command_uuid() {
            Ok(id) => id,
            Err(error) => {
                emit(&json!({ "t": "frame", "run": run, "artifact": artifact, "error": error }));
                self.missions.frame = Some(artifact);
                return;
            }
        };
        let request = live::ContentTicketRequest {
            command_id,
            source,
            max_bytes: std::num::NonZeroU64::new(odin_registry::schema::MAX_FRAME_BYTES)
                .expect("frame byte limit is nonzero"),
        };
        match self.client.download_ticket(request).await {
            Ok(bytes) => {
                match preview_frame(media_type, bytes, preview_max_side) {
                    Ok((preview_type, bytes)) => {
                        let data = base64::engine::general_purpose::STANDARD.encode(bytes);
                        emit(
                            &json!({ "t": "frame", "run": run, "artifact": artifact, "mediaType": preview_type, "data": data }),
                        );
                    }
                    Err(error) => emit(
                        &json!({ "t": "frame", "run": run, "artifact": artifact, "error": error }),
                    ),
                }
                self.missions.frame = Some(artifact);
            }
            Err(error) => {
                emit(&json!({ "t": "frame", "run": run, "artifact": artifact,
                    "error": super::cause(&error) }));
                self.missions.frame = Some(artifact);
            }
        }
    }

    /// `{t: "render" | "pause" | "resume", run, renderer?}` on the mission's current revision.
    pub(super) async fn mission_command(&mut self, id: &Value, verb: &str, command: &Value) {
        let run = command
            .get("run")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let result = self
            .mission_request(verb, run, command.get("renderer").and_then(Value::as_str))
            .await;
        match result {
            Ok(text) => done(id, true, text),
            Err(text) => done(id, false, text),
        }
    }

    async fn mission_request(
        &mut self,
        verb: &str,
        run: &str,
        renderer: Option<&str>,
    ) -> Result<String, String> {
        let objects = self
            .snapshot_all(live::ObjectKind::Simulation)
            .await
            .ok_or("the board is unreadable")?;
        let mission: live::SimulationMissionView = objects
            .iter()
            .find(|object| object.object.id == run)
            .and_then(|object| serde_json::from_value(object.value.clone()).ok())
            .ok_or_else(|| format!("no mission is {run:?}"))?;
        let context = live::SimulationCommandContext {
            command_id: odin_cli::authority_provision::random_command_uuid()?,
            run_id: mission.run_id.clone(),
            expected_revision: mission.revision,
            arguments_digest: odin_domain::Digest::hash(format!("{verb}:{run}").as_bytes()),
            approval_id: None,
        };
        let request = match verb {
            "render" => {
                let renderer = match renderer {
                    Some(renderer) => {
                        live::RendererId::new(renderer).map_err(|error| error.to_string())?
                    }
                    None => mission
                        .supported_renderers
                        .first()
                        .cloned()
                        .ok_or_else(|| format!("{} declares no renderer", mission.label))?,
                };
                live::SimulationCommand::RequestRender {
                    context,
                    render_id: live::RenderId::new(uuid::Uuid::new_v4())
                        .map_err(|error| error.to_string())?,
                    renderer_id: renderer,
                    renderer_version: "view".to_owned(),
                    // The mission's case stands for the pod's own defaults.
                    parameters: mission.case.clone(),
                }
            }
            "pause" => live::SimulationCommand::Pause { context },
            _ => live::SimulationCommand::Resume { context },
        };
        self.request(
            live::HuginnRequest::SimulationCommand(request),
            REQUEST_BOUND,
        )
        .await
        .map(|_| match verb {
            "render" => format!("render of {} requested", mission.label),
            other => format!("{other} of {} asked", mission.label),
        })
    }
}

/// Produce a bounded terminal preview without altering the published artifact.
fn preview_frame(
    media_type: Option<&str>,
    bytes: Vec<u8>,
    max_side: u32,
) -> Result<(Option<&str>, Vec<u8>), String> {
    if media_type != Some("image/svg+xml") {
        return Ok((media_type, bytes));
    }
    // Reapply the render-plane policy at this boundary; neither filesystem nor network
    // resources are needed for the passive SVG subset accepted for mission frames.
    let max_bytes = usize::try_from(odin_registry::schema::MAX_FRAME_BYTES)
        .map_err(|_| "frame size limit does not fit this platform".to_owned())?;
    let svg =
        odin_huginn::renders::sanitize_svg(&bytes, max_bytes).map_err(|error| error.to_string())?;
    static FONT: std::sync::LazyLock<
        Result<(std::sync::Arc<resvg::usvg::fontdb::Database>, String), String>,
    > = std::sync::LazyLock::new(|| {
        let mut db = resvg::usvg::fontdb::Database::new();
        db.load_font_data(rust_widgets_font::latin::FONT.to_vec());
        let family = db
            .faces()
            .next()
            .and_then(|face| face.families.first())
            .map(|(name, _)| name.clone())
            .ok_or_else(|| "embedded preview font is invalid".to_owned())?;
        db.set_serif_family(family.clone());
        db.set_sans_serif_family(family.clone());
        db.set_monospace_family(family.clone());
        Ok((std::sync::Arc::new(db), family))
    });
    let (db, family) = FONT.as_ref().map_err(Clone::clone)?;
    let options = resvg::usvg::Options {
        fontdb: db.clone(),
        font_family: family.clone(),
        ..Default::default()
    };
    let tree = resvg::usvg::Tree::from_data(&svg, &options).map_err(|error| error.to_string())?;
    // Bound memory even for a tiny SVG declaring enormous dimensions. Preserve aspect ratio.
    let size = tree.size();
    let scale = (max_side as f32 / size.width())
        .min(max_side as f32 / size.height())
        .min(1.0);
    let width = (size.width() * scale).ceil().max(1.0) as u32;
    let height = (size.height() * scale).ceil().max(1.0) as u32;
    let mut pixmap = resvg::tiny_skia::Pixmap::new(width, height)
        .ok_or_else(|| "could not allocate SVG preview".to_owned())?;
    resvg::render(
        &tree,
        resvg::tiny_skia::Transform::from_scale(scale, scale),
        &mut pixmap.as_mut(),
    );
    let png = pixmap.encode_png().map_err(|error| error.to_string())?;
    Ok((Some("image/png"), png))
}

#[cfg(test)]
mod tests {
    use super::preview_frame;

    #[test]
    fn svg_preview_is_rendered_png() {
        let svg = br##"<svg xmlns="http://www.w3.org/2000/svg" width="8" height="8"><rect width="8" height="8" fill="#ff0000"/></svg>"##.to_vec();
        let (media, png) = preview_frame(Some("image/svg+xml"), svg.clone(), 32).unwrap();
        assert_eq!(media, Some("image/png"));
        let image = resvg::tiny_skia::Pixmap::decode_png(&png).unwrap();
        assert_eq!((image.width(), image.height()), (8, 8));
        assert_eq!(image.pixel(4, 4).unwrap().red(), 255);
        assert_eq!(
            png,
            preview_frame(Some("image/svg+xml"), svg, 32).unwrap().1
        );
    }

    #[test]
    fn passive_policy_and_size_bound_apply_to_svg_previews() {
        let active =
            br#"<svg xmlns="http://www.w3.org/2000/svg"><script>bad()</script></svg>"#.to_vec();
        assert!(preview_frame(Some("image/svg+xml"), active, 32).is_err());
        let huge = br#"<svg xmlns="http://www.w3.org/2000/svg" width="100000" height="50000"><rect width="100000" height="50000"/></svg>"#.to_vec();
        let png = preview_frame(Some("image/svg+xml"), huge, 300).unwrap().1;
        let image = resvg::tiny_skia::Pixmap::decode_png(&png).unwrap();
        assert_eq!((image.width(), image.height()), (300, 150));
    }

    #[test]
    fn svg_text_renders_with_bundled_font() {
        let svg = br#"<svg xmlns="http://www.w3.org/2000/svg" width="100" height="30"><text x="1" y="24" font-size="24">Mission</text></svg>"#.to_vec();
        let png = preview_frame(Some("image/svg+xml"), svg, 100).unwrap().1;
        let image = resvg::tiny_skia::Pixmap::decode_png(&png).unwrap();
        assert!(image.pixels().iter().any(|pixel| pixel.alpha() != 0));
    }
}
