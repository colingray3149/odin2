//! Session capsules and harness launch directories: removed when a
//! session ends, and swept at start for sessions of earlier daemons.

use odin_domain::huginn::{LiveSessionId, LiveSessionState};
use time::OffsetDateTime;

use super::admission::parks_on_discovery;
use super::LiveSupervisor;

impl LiveSupervisor {
    /// Deletes each ended session's capsule and harness directories under
    /// `roots` from now on.
    pub fn remove_capsules_under(&self, roots: crate::live::capsules::SessionRoots) {
        if let Err(ignored) = self.capsule_root.set(roots) {
            tracing::error!(
                "session roots {ignored:?} ignored: this supervisor already removes capsules elsewhere"
            );
        }
    }

    pub(super) fn remove_capsule(&self, session_id: LiveSessionId) {
        if let Some(root) = self.capsule_root.get().cloned() {
            self.runtime.spawn_blocking(move || {
                crate::live::capsules::remove_capsule(&root, session_id);
            });
        }
    }

    /// Deletes the capsule of every session nothing can run again: the
    /// start-time pass for sessions of earlier daemons. An Ended session is
    /// final. A Failed one can be reclaimed, so its capsule stays while the
    /// session is live or parked here, failed within the 24 h park limit, or
    /// is `owned` by a conversation that reclaims its vehicle. Returns how many
    /// capsules are gone; one that could not be deleted is logged and not counted.
    pub async fn remove_finished_capsules(
        &self,
        owned: impl Fn(LiveSessionId) -> bool,
        now: OffsetDateTime,
    ) -> Result<usize, String> {
        let Some(root) = self.capsule_root.get().cloned() else {
            return Ok(0);
        };
        let mut removed = 0;
        for session_id in crate::live::capsules::capsule_sessions(&root)? {
            let Some(summary) = self
                .durable_summary(session_id)
                .await
                .map_err(|error| format!("session {session_id} journal unreadable: {error}"))?
            else {
                continue;
            };
            let finished = match summary.state {
                LiveSessionState::Ended => true,
                LiveSessionState::Failed => {
                    !parks_on_discovery(&summary, now)
                        && !owned(session_id)
                        && !self.actors.read().await.contains_key(&session_id)
                        && !self.inactive.read().await.contains_key(&session_id)
                }
                _ => false,
            };
            if finished {
                let root = root.clone();
                let clean = tokio::task::spawn_blocking(move || {
                    crate::live::capsules::remove_capsule(&root, session_id)
                })
                .await
                .map_err(|error| format!("capsule removal for {session_id} failed: {error}"))?;
                removed += usize::from(clean);
            }
        }
        Ok(removed)
    }
}
