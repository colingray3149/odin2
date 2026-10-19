//! The eight disjoint conformance case modules.
//!
//! Each module file owns exactly the case ids declared by
//! [`crate::probe::CaseModule::case_ids`] and exposes the registration slot
//! `pub fn cases() -> Vec<Arc<dyn ConformanceCase>>`. The case bodies are
//! implemented by the per-module waves; [`crate::probe::registered_cases`]
//! refuses the suite until every one of the 21 frozen cases is registered by
//! its owning module exactly once.

pub mod controls_model;
pub mod crash_provider;
pub mod framing_unknown;
pub mod history_persistence;
pub mod prompt_state_todos;
pub mod slash_config_shutdown;
pub mod startup;
pub mod subagents_tools;
