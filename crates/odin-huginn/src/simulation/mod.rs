//! Simulation mission, telemetry, render, checkpoint, and Judge adapters.

pub mod control;
pub mod render;
pub mod telemetry;
pub mod view;

pub use control::{Result as ControlResult, SimulationControl};
pub use render::{Result as RenderResult, SimulationRenderBoard};
pub use telemetry::{CompactTelemetry, Result as TelemetryResult, TelemetryRing};
pub use view::{
    checkpoint_delta, judge_delta, mission_delta, stage_transition_allowed, Result as ViewResult,
    SimulationBoard,
};
