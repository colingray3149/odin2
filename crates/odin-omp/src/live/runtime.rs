mod adapter_stack;
mod assembly;
pub(crate) mod brain_tools;
mod config;
mod errors;
mod hooks;
mod launch_support;
mod tool_index;

#[cfg(test)]
mod bridge_launch_tests;
#[cfg(test)]
mod served_shape_tests;

pub use assembly::{ProductionBridgeRuntimeFactory, SessionCapsuleAuthority};
pub use config::{
    declared_conversation_guidance, declared_seat_memory_max, declared_seat_sandboxes,
    declared_tool_exposure, ContextReadRuntimeConfig, LaneWindow, ProductionBridgeRuntimeConfig,
    WorkloadCarrierPort, WorkloadSessionLaw,
};
pub use hooks::FsControlHooks;
pub use launch_support::live_session_lane;
