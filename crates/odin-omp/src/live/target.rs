//! The operator's chat terminal: the Zellij session an interactive client
//! registered, whose screen `terminal read` captures.
//!
//! The supervisor never guesses an operator Zellij session — not the first,
//! not the last, not the inherited `ZELLIJ_SESSION_NAME`, and never a phantom
//! fallback name. The target exists only as an explicit operator registration
//! sent from the interactive client. Resolution is fail-closed: an unbound
//! target, an invalid name, or a bound-but-not-currently-live session is a
//! typed error.

use async_trait::async_trait;
use odin_domain::huginn::{LiveError, LiveSessionId};
use serde::{Deserialize, Serialize};
use std::sync::{Arc, RwLock as StdRwLock};
use time::OffsetDateTime;

/// Domain object kind used in typed `NotFound` errors for a dead selector.
pub const TERMINAL_TARGET_KIND: &str = "zellij_session";

/// The only placeholder an attach-command template may carry; it is replaced
/// with the dispatched live session id at tab creation.
pub const ATTACH_SESSION_PLACEHOLDER: &str = "{session_id}";

const MAX_TARGET_NAME_BYTES: usize = 128;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum TerminalTargetSource {
    /// Explicit operator registration from the interactive client.
    ChatRegistration,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TerminalTargetSnapshot {
    pub zellij_session: String,
    pub source: TerminalTargetSource,
}

/// One bounded read-only capture of the operator's real terminal session
/// screen, taken daemon-side through the resolved live target. `truncated`
/// is explicit: content beyond `max_bytes` is dropped and reported, never
/// silently.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TerminalScreenCapture {
    /// The resolved Zellij session the content was captured from.
    pub zellij_session: String,
    /// Bounded UTF-8 screen content.
    pub content: String,
    /// Whether the capture exceeded the requested byte budget.
    pub truncated: bool,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TerminalTargetStatus {
    pub bound: bool,
    pub zellij_session: Option<String>,
    pub source: Option<TerminalTargetSource>,
    pub registered_at: Option<OffsetDateTime>,
    /// True when this registration replaced an earlier chat registration.
    pub replaced: bool,
}

/// One validated target binding with its origin and registration instant.
#[derive(Clone, Debug, PartialEq, Serialize)]
struct TargetBinding {
    zellij_session: String,
    source: TerminalTargetSource,
    registered_at: OffsetDateTime,
}

#[derive(Default)]
struct TargetState {
    registered: Option<TargetBinding>,
}

/// Shared registry holding at most one explicit chat registration. Clones observe the same state, so the supervisor, the
/// terminal factory, and any admin surface resolve one identical target.
/// State mutation is a tiny cell swap under a sync lock; live-session
/// verification happens in the terminal admin, never inside this lock.
#[derive(Clone, Default)]
pub struct TerminalTargetRegistry {
    state: Arc<StdRwLock<TargetState>>,
}

/// Administration surface for the terminal target: verification against the
/// real Zellij session list happens behind this trait, never in the registry.
#[async_trait]
pub trait TerminalTargetAdmin: Send + Sync {
    /// Explicitly registers the operator chat target after verifying the
    /// session is currently live. Replaces any earlier chat registration.
    async fn register_chat_target(
        &self,
        zellij_session: String,
    ) -> Result<TerminalTargetStatus, LiveError>;

    /// Drops the chat registration, restoring the declared selector (or an
    /// unbound state).
    async fn clear_chat_target(&self) -> Result<TerminalTargetStatus, LiveError>;

    /// Current binding without live verification.
    async fn terminal_target_status(&self) -> TerminalTargetStatus;

    /// Resolves the effective target and verifies it is currently live.
    async fn resolve_target(&self) -> Result<TerminalTargetSnapshot, LiveError>;

    /// Captures one bounded read-only screen dump of the RESOLVED live
    /// target. The default is a typed refusal: an admin that cannot capture
    /// screens never fabricates a transcript. `session` must equal the
    /// resolved governed target — an arbitrary selector is a typed miss, so
    /// the read surface can never wander to another operator session.
    async fn capture_screen(
        &self,
        session: &str,
        max_bytes: usize,
    ) -> Result<TerminalScreenCapture, LiveError> {
        let _ = (session, max_bytes);
        Err(LiveError::unavailable(
            "terminal_screen_capture_unsupported",
            "this terminal admin keeps no screen captures",
        ))
    }

    /// The sessions whose terminal capture (lease, control audit) sits on
    /// disk. An admin that keeps no captures has none.
    async fn captured_sessions(&self) -> Result<Vec<LiveSessionId>, LiveError> {
        Ok(Vec::new())
    }

    /// Removes one session's terminal capture; an absent capture is done.
    async fn remove_session_capture(&self, session: LiveSessionId) -> Result<(), LiveError> {
        let _ = session;
        Ok(())
    }
}

impl TerminalTargetRegistry {
    /// An empty registry: nothing is declared and nothing is registered.
    pub fn new() -> Self {
        Self::default()
    }

    /// Commits an already verified chat registration, replacing any earlier
    /// one. Callers must verify the session is live first (see
    /// [`TerminalTargetAdmin::register_chat_target`]).
    pub fn register_chat(&self, zellij_session: String) -> Result<TerminalTargetStatus, LiveError> {
        validate_target_name(&zellij_session)?;
        Ok(self.mutate(|state| {
            let replaced = state.registered.is_some();
            state.registered = Some(TargetBinding {
                zellij_session,
                source: TerminalTargetSource::ChatRegistration,
                registered_at: OffsetDateTime::now_utc(),
            });
            replaced
        }))
    }

    /// Drops the chat registration. Clearing without one is not an error.
    pub fn clear_chat(&self) -> Result<TerminalTargetStatus, LiveError> {
        Ok(self.mutate(|state| state.registered.take().is_some()))
    }

    /// The chat registration. Unbound is a typed availability error.
    pub fn resolve(&self) -> Result<TerminalTargetSnapshot, LiveError> {
        let state = match self.state.read() {
            Ok(state) => state,
            // A panicked writer leaves the cell structurally valid (two
            // Options); recover the guard rather than fail the daemon.
            Err(poisoned) => poisoned.into_inner(),
        };
        let binding = state.registered.as_ref().ok_or_else(|| {
            LiveError::unavailable("terminal_target_unbound", "no zellij session is registered")
        })?;
        Ok(TerminalTargetSnapshot {
            zellij_session: binding.zellij_session.clone(),
            source: binding.source,
        })
    }

    /// Current binding for display, without resolution or verification.
    pub fn status(&self) -> TerminalTargetStatus {
        self.snapshot()
    }

    fn mutate(&self, apply: impl FnOnce(&mut TargetState) -> bool) -> TerminalTargetStatus {
        let mut state = match self.state.write() {
            Ok(state) => state,
            Err(poisoned) => poisoned.into_inner(),
        };
        let replaced = apply(&mut state);
        TerminalTargetStatus {
            replaced,
            ..Self::status_of(&state)
        }
    }

    fn snapshot(&self) -> TerminalTargetStatus {
        let state = match self.state.read() {
            Ok(state) => state,
            Err(poisoned) => poisoned.into_inner(),
        };
        Self::status_of(&state)
    }

    fn status_of(state: &TargetState) -> TerminalTargetStatus {
        state
            .registered
            .as_ref()
            .map(|binding| TerminalTargetStatus {
                bound: true,
                zellij_session: Some(binding.zellij_session.clone()),
                source: Some(binding.source),
                registered_at: Some(binding.registered_at),
                replaced: false,
            })
            .unwrap_or_default()
    }
}

/// Selectors and registrations require nonblank names of at most 128 bytes without controls.
pub fn validate_target_name(name: &str) -> Result<(), LiveError> {
    let cause = if name.trim().is_empty() {
        "is empty"
    } else if name.len() > MAX_TARGET_NAME_BYTES {
        "is longer than 128 bytes"
    } else if name.chars().any(char::is_control) {
        "contains a control character"
    } else {
        return Ok(());
    };
    Err(LiveError::InvalidRequest {
        code: "terminal_target_invalid".to_owned(),
        message: format!("zellij session target name {cause}"),
    })
}

/// Parses `zellij list-sessions --no-formatting` (zellij 0.45) into the
/// currently live session names. Each non-empty line is
/// `<name> [Created ...]` with `(EXITED - attach to resurrect)` appended for
/// dead sessions; the name ends at the first whitespace.
pub fn parse_live_sessions(output: &str) -> Vec<String> {
    output
        .lines()
        .filter_map(|line| {
            let name = line.split_whitespace().next()?;
            if name.is_empty() || line.contains("(EXITED") {
                None
            } else {
                Some(name.to_owned())
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `zellij list-sessions --no-formatting` output from zellij 0.45.0.
    const OBSERVED: &str = "m89 [Created 4days 2h 8m 14s ago] (EXITED - attach to resurrect)\n\
                            quadratic-pigeon [Created 2days 5h 44m 5s ago] \n\
                            unflappable-orange [Created 1day 23h 26m 3s ago] \n";

    #[test]
    fn parse_keeps_only_live_sessions_from_observed_output() {
        let live = parse_live_sessions(OBSERVED);
        assert_eq!(
            live,
            vec![
                "quadratic-pigeon".to_owned(),
                "unflappable-orange".to_owned()
            ]
        );
    }

    #[test]
    fn chat_registration_replaces_and_clears() {
        let registry = TerminalTargetRegistry::new();
        let status = registry
            .register_chat("quadratic-pigeon".to_owned())
            .expect("register");
        assert!(status.bound);
        assert_eq!(status.source, Some(TerminalTargetSource::ChatRegistration));
        assert!(!status.replaced, "no earlier chat registration existed");

        let replaced = registry
            .register_chat("unflappable-orange".to_owned())
            .expect("re-register");
        assert!(replaced.replaced);

        let snapshot = registry.resolve().expect("registered resolves");
        assert_eq!(snapshot.zellij_session, "unflappable-orange");

        let cleared = registry.clear_chat().expect("clear");
        assert!(cleared.replaced);
        assert!(!cleared.bound);
        assert!(!registry.clear_chat().expect("clear").replaced);
    }
}
