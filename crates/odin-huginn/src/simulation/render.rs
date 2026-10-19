//! Typed simulation render jobs with declared-renderer and progress checks.

use std::collections::BTreeMap;
use std::num::NonZeroUsize;

use odin_domain::huginn::read_model as rm;
use odin_domain::huginn::{
    ArtifactRef, HuginnProtocolError, ObjectDelta, ObjectKind, RenderId, RendererId, Revision,
    RevisionSource, SimulationMissionView, SimulationRenderStatus, SimulationRenderView,
};
use time::OffsetDateTime;

pub type Result<T, E = HuginnProtocolError> = std::result::Result<T, E>;

fn is_terminal(status: SimulationRenderStatus) -> bool {
    matches!(
        status,
        SimulationRenderStatus::Complete
            | SimulationRenderStatus::Failed
            | SimulationRenderStatus::Cancelled
    )
}

/// Render job board for simulation surfaces. Requests against undeclared renderers, oversized
/// queues, or malformed progress are rejected before any job is created.
pub struct SimulationRenderBoard {
    renders: BTreeMap<RenderId, SimulationRenderView>,
    max_active: NonZeroUsize,
}

impl SimulationRenderBoard {
    pub fn new(max_active: NonZeroUsize) -> Self {
        Self {
            renders: BTreeMap::new(),
            max_active,
        }
    }

    pub fn render(&self, render_id: &RenderId) -> Option<&SimulationRenderView> {
        self.renders.get(render_id)
    }

    pub fn renders_for_run(&self, run_id: &odin_domain::RunId) -> Vec<&SimulationRenderView> {
        self.renders
            .values()
            .filter(|render| &render.run_id == run_id)
            .collect()
    }

    fn active_count(&self) -> usize {
        self.renders
            .values()
            .filter(|render| !is_terminal(render.status))
            .count()
    }

    /// Declares one render job. The renderer must be declared by the mission surface.
    pub fn request(
        &mut self,
        mission: &SimulationMissionView,
        render_id: RenderId,
        renderer_id: &RendererId,
        renderer_version: &str,
        parameters: ArtifactRef,
        at: OffsetDateTime,
    ) -> Result<SimulationRenderView> {
        if !mission
            .supported_renderers
            .iter()
            .any(|declared| declared == renderer_id)
        {
            return Err(HuginnProtocolError::Unsupported {
                operation: format!("renderer {renderer_id} is not declared by this surface"),
            });
        }
        if renderer_version.is_empty() || renderer_version.as_bytes().contains(&0) {
            return Err(HuginnProtocolError::InvalidRequest {
                code: "simulationRendererVersion".to_string(),
                message: "renderer version must be non-empty and contain no NUL".to_string(),
            });
        }
        if self.active_count() >= self.max_active.get() {
            return Err(HuginnProtocolError::ResourceLimit {
                limit: "simulationRenderQueue".to_string(),
            });
        }
        if self.renders.contains_key(&render_id) {
            return Err(HuginnProtocolError::Conflict {
                code: "renderExists".to_string(),
                message: format!("render {render_id} already exists"),
            });
        }
        let view = SimulationRenderView {
            render_id,
            run_id: mission.run_id.clone(),
            revision: 1,
            renderer_id: renderer_id.clone(),
            renderer_version: renderer_version.to_string(),
            parameters_digest: parameters.content_digest,
            input_digest: mission.case.content_digest,
            status: SimulationRenderStatus::Requested,
            progress_basis_points: 0,
            requested_at: at,
            finished_at: None,
            output: None,
            failure_evidence: None,
        };
        self.renders.insert(view.render_id, view.clone());
        Ok(view)
    }

    fn view_or_not_found(&mut self, render_id: &RenderId) -> Result<&mut SimulationRenderView> {
        self.renders
            .get_mut(render_id)
            .ok_or_else(|| HuginnProtocolError::NotFound {
                object_kind: "simulationRender".to_string(),
                object_id: render_id.to_string(),
            })
    }

    fn check_progress(progress_basis_points: u16) -> Result<()> {
        if progress_basis_points > 10_000 {
            return Err(HuginnProtocolError::InvalidRequest {
                code: "simulationRenderProgress".to_string(),
                message: "progress basis points exceed 10000".to_string(),
            });
        }
        Ok(())
    }

    /// Moves a job to Running (or straight to Failed/Cancelled) with a progress reading.
    pub fn transition(
        &mut self,
        render_id: &RenderId,
        status: SimulationRenderStatus,
        progress_basis_points: u16,
        at: OffsetDateTime,
    ) -> Result<(u64, u64)> {
        Self::check_progress(progress_basis_points)?;
        let view = self.view_or_not_found(render_id)?;
        let allowed = matches!(
            (view.status, status),
            (
                SimulationRenderStatus::Requested,
                SimulationRenderStatus::Running
            ) | (
                SimulationRenderStatus::Requested,
                SimulationRenderStatus::Failed
            ) | (
                SimulationRenderStatus::Requested,
                SimulationRenderStatus::Cancelled
            ) | (
                SimulationRenderStatus::Running,
                SimulationRenderStatus::Running
            ) | (
                SimulationRenderStatus::Running,
                SimulationRenderStatus::Failed
            ) | (
                SimulationRenderStatus::Running,
                SimulationRenderStatus::Cancelled
            )
        );
        if !allowed {
            return Err(HuginnProtocolError::Conflict {
                code: "simulationRenderState".to_string(),
                message: format!(
                    "transition from {:?} to {status:?} is not allowed",
                    view.status
                ),
            });
        }
        let from = view.revision;
        let to = view
            .revision
            .checked_add(1)
            .ok_or_else(|| HuginnProtocolError::Conflict {
                code: "revisionExhausted".to_string(),
                message: "render revision space is exhausted".to_string(),
            })?;
        view.revision = to;
        view.status = status;
        view.progress_basis_points = progress_basis_points;
        if is_terminal(status) {
            view.finished_at = Some(at);
        }
        Ok((from, to))
    }

    /// Completes a Running job with its verified output artifact.
    pub fn complete(
        &mut self,
        render_id: &RenderId,
        output: ArtifactRef,
        at: OffsetDateTime,
    ) -> Result<(u64, u64)> {
        let view = self.view_or_not_found(render_id)?;
        if view.status != SimulationRenderStatus::Running {
            return Err(HuginnProtocolError::Conflict {
                code: "simulationRenderState".to_string(),
                message: "only a running render can complete".to_string(),
            });
        }
        let from = view.revision;
        let to = view
            .revision
            .checked_add(1)
            .ok_or_else(|| HuginnProtocolError::Conflict {
                code: "revisionExhausted".to_string(),
                message: "render revision space is exhausted".to_string(),
            })?;
        view.revision = to;
        view.status = SimulationRenderStatus::Complete;
        view.progress_basis_points = 10_000;
        view.output = Some(output);
        view.finished_at = Some(at);
        Ok((from, to))
    }

    /// Records failure evidence on a terminal Failed job.
    pub fn fail(
        &mut self,
        render_id: &RenderId,
        failure_evidence: Option<ArtifactRef>,
        at: OffsetDateTime,
    ) -> Result<(u64, u64)> {
        let (from, to) = self.transition(render_id, SimulationRenderStatus::Failed, 0, at)?;
        let view = self.view_or_not_found(render_id)?;
        view.failure_evidence = failure_evidence;
        Ok((from, to))
    }

    pub fn render_delta(view: &SimulationRenderView, from_revision: u64) -> ObjectDelta {
        rm::ObjectDelta {
            object: rm::ObjectRef {
                kind: ObjectKind::Simulation,
                id: view.render_id.to_string(),
            },
            from_revision: Revision::new(from_revision),
            to_revision: Revision::new(view.revision),
            revision_source: RevisionSource::Simulation,
            freshness: rm::Freshness {
                state: rm::FreshnessState::Fresh,
                observed_at: view.requested_at,
                source_updated_at: view.finished_at,
                stale_after_seconds: None,
            },
            body: rm::ObjectDeltaBody::Replace(
                serde_json::to_value(view).unwrap_or(serde_json::Value::Null),
            ),
        }
    }
}
