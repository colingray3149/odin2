//! The `odin huginn` operator command, split along its existing command
//! domains:
//!
//! - [`surface`] owns the operator-facing argument grammar, the shared
//!   bounded-read vocabulary (paging, snapshot/search/watch planning, kind
//!   selectors), the [`HuginnPlan`](surface::HuginnPlan) wire, top-level plan dispatch, and plan
//!   execution against the production Huginn client.
//! - One module per subcommand domain: [`approvals`], [`browser`],
//!   [`devices`], [`files`], [`lane`], [`render`], [`session`], [`simulation`],
//!   and [`terminal`].

mod approvals;
mod browser;
mod chat;
mod devices;
mod export;
mod files;
mod lane;
mod render;
mod session;
mod simulation;
mod surface;
mod terminal;

#[cfg(test)]
pub(crate) use surface::HuginnPlan;
pub(crate) use surface::{run_huginn, HuginnArgs};
