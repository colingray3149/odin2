//! Controller facade; implementation is split by responsibility below.

#[path = "controller/check.rs"]
mod check;
#[path = "controller/registry.rs"]
mod registry;
#[path = "controller/state.rs"]
mod state;
#[path = "controller/types.rs"]
mod types;

#[cfg(test)]
pub use check::check;
pub use check::{check_from_config, check_snapshot};
#[cfg(test)]
pub use types::{CheckReport, CheckRequest};
