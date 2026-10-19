//! Daemon browser runtime composition.
//!
//! The runtime is split along its authority boundaries:
//!
//! - `inputs` declares the operator-supplied policy and protected-value
//!   inputs and validates them against the capability registry before any
//!   browser mechanism is launched.
//! - `launch` owns mechanism configuration, durable session launch, and the
//!   projection that mirrors the live browser session.
//! - `coordinator` owns authenticated command and approval handling over
//!   that session: call admission, idempotent journaling, takeover, fresh
//!   durable approval consumption, and terminal command completion.
//! - `dispatch` decodes governed host-tool capability invocations and
//!   encodes their evidence, keeping model-visible invocation structured.
//!
//! Public paths of this module are the canonical API surface consumed by
//! `odind`; they are preserved verbatim through re-exports.

mod coordinator;
mod dispatch;
mod inputs;
mod launch;
mod pods;

const BROWSER_INTERACT_CAPABILITY: &str = "browser.interact";
const BROWSER_INTERACT_VERSION: u64 = 1;

pub use coordinator::{BrowserCheckoutBackend, BrowserCommandCoordinator};
pub use inputs::{BrowserPolicyInput, BrowserPolicyRuleInput, ProtectedValueInput};
pub use launch::{BrowserRuntimeConfig, BrowserRuntimeError, BrowserRuntimeLaunch};
pub use pods::{BrowserRoutes, PodBrowserLaunch, PodBrowserOpener};
