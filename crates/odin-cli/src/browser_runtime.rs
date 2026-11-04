//! Daemon browser runtime composition.
//!
//! The runtime is split along its authority boundaries:
//!
//! - `inputs` declares the operator-supplied policy and protected-value
//!   inputs and validates them against the capability registry before any
//!   browser mechanism is launched.
//! - `launch` owns mechanism configuration and the validated launch seam;
//!   no session opens there.
//! - `local` owns the governed local browser's on-demand lifecycle: the
//!   first governed call launches, idle closes, dead pages reopen fresh.
//! - `coordinator` owns authenticated command and approval handling over
//!   one session: call admission, idempotent journaling, takeover, fresh
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
mod local;
mod pods;

const BROWSER_INTERACT_CAPABILITY: &str = "browser.interact";
const BROWSER_INTERACT_VERSION: u64 = 1;
const BROWSER_CONSEQUENTIAL_CAPABILITY: &str = "browser.consequential";
/// The wire target kind of an approval scoped to one governed browser session.
const BROWSER_APPROVAL_TARGET_KIND: &str = "browserSession";

pub use coordinator::BrowserCommandCoordinator;
pub use inputs::{BrowserPolicyInput, BrowserPolicyRuleInput, ProtectedValueInput};
pub use launch::{
    BrowserRuntimeConfig, BrowserRuntimeError, LocalSessionLaunch, PreparedBrowserRuntime,
};
pub use local::LocalBrowser;
pub use pods::{BrowserRoutes, PodBrowserLaunch, PodBrowserOpener};
