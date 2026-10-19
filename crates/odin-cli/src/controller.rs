//! Controller facade; implementation is split by responsibility below.

#[path = "controller/registry.rs"]
mod registry;
#[path = "controller/rehearsal.rs"]
mod rehearsal;
#[path = "controller/state.rs"]
mod state;
#[path = "controller/types.rs"]
mod types;

#[cfg(test)]
pub use rehearsal::check;
pub use rehearsal::{check_from_config, check_snapshot};
pub use types::ControllerError;
#[cfg(test)]
pub use types::{CheckReport, CheckRequest};
