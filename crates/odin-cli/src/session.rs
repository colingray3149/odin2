//! Opens a declared seat session through Huginn using the configured launch
//! tuple, pinned registry snapshot, seat token, and enrolled device credential.
//!
//! With `--prompt-file`, the session opens idle. The prompt is persisted as the
//! bridge run's plan objective and accepted by the paired operator device
//! before a `Prompt` command can be constructed. An existing but unaccepted
//! plan does not authorize a prompt.

mod interactive;
mod open;
mod plan;
mod transport;

pub(crate) use open::{start, SessionRequest};
pub(crate) use plan::{accept, PlanAcceptRequest};
pub(crate) use transport::{terminal, TerminalCommand, TerminalRequest};
