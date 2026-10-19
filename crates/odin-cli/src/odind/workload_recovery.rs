//! Anti-stuck recovery for pods: the kernel's recovery
//! ladder (`odin_kernel::recovery`) walked over a pod's declared progress
//! counter. Useful progress is the counter passing its high-water mark —
//! never a heartbeat, a repeated value, or a restarted pod climbing back to
//! where it stalled — so a pod that stalls again at the same place after
//! its authorized restart is the identical stall, and the finite ladder
//! ends in escalation instead of restarting it forever. The decision is
//! code; the pod's seat applies the one authorized step with its own tools.

use std::collections::BTreeMap;
use std::path::Path;

use odin_domain::{Digest, IncidentId};
use odin_kernel::recovery::{
    RecoveryDecision, RecoveryObservation, RecoveryPolicy, RecoveryRung, RecoverySnapshot,
    RecoveryState,
};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

/// Runs whose last read is older than this are forgotten.
const FORGET_AFTER_MS: i64 = 7 * 24 * 3600 * 1000;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) enum StallStep {
    /// The one authorized step, and which attempt on that rung it is.
    Act { rung: RecoveryRung, attempt: u32 },
    /// The previous step's cooldown has not passed; nothing is done.
    Cooldown,
    /// The ladder is spent: only a decision by Colin moves it.
    Blocked { missing_decision: String },
}

/// One run's progress and ladder, durable across daemon restarts.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub(super) struct StallState {
    high_water: f64,
    last_value: f64,
    last_moved_ms: i64,
    last_read_ms: i64,
    /// A stall already decided; the next decision waits for the pod to move.
    episode_open: bool,
    /// The ladder while recovering; `None` while healthy.
    recovery: Option<RecoverySnapshot>,
}

fn at(ms: i64) -> OffsetDateTime {
    OffsetDateTime::from_unix_timestamp_nanos(i128::from(ms) * 1_000_000)
        .unwrap_or(OffsetDateTime::UNIX_EPOCH)
}

impl StallState {
    pub(super) fn new(value: f64, now_ms: i64) -> Self {
        Self {
            high_water: value,
            last_value: value,
            last_moved_ms: now_ms,
            last_read_ms: now_ms,
            episode_open: false,
            recovery: None,
        }
    }

    pub(super) fn high_water(&self) -> f64 {
        self.high_water
    }

    /// One read of the progress counter. `signature` names the stall (the
    /// same for the same pod and counter, so a repeat is the identical
    /// failure). Returns the ladder's step when this read is a new stall.
    pub(super) fn observe(
        &mut self,
        value: f64,
        now_ms: i64,
        stall_ms: i64,
        policy: &RecoveryPolicy,
        signature: &str,
    ) -> Result<Option<StallStep>, String> {
        self.last_read_ms = now_ms;
        if value > self.high_water {
            self.high_water = value;
            self.last_value = value;
            self.last_moved_ms = now_ms;
            self.episode_open = false;
            if let Some(snapshot) = self.recovery.take() {
                let state =
                    RecoveryState::from_snapshot(snapshot).map_err(|error| format!("{error:?}"))?;
                let cleared = state
                    .observe(RecoveryObservation::UsefulProgress {
                        observed_at: at(now_ms),
                    })
                    .map_err(|error| format!("{error:?}"))?
                    .into_state();
                // A ladder that useful progress did not clear stays.
                let snapshot = cleared.snapshot();
                if snapshot.total_attempts != 0 || snapshot.last_failure_at.is_some() {
                    self.recovery = Some(snapshot);
                }
            }
            return Ok(None);
        }
        if value != self.last_value {
            // Working again (a restarted pod climbing back): not yet useful
            // progress, but the next stall is a new episode.
            self.last_value = value;
            self.last_moved_ms = now_ms;
            self.episode_open = false;
            return Ok(None);
        }
        if self.episode_open || now_ms - self.last_moved_ms < stall_ms {
            return Ok(None);
        }
        self.episode_open = true;
        let state = match self.recovery.take() {
            Some(snapshot) => {
                RecoveryState::from_snapshot(snapshot).map_err(|error| format!("{error:?}"))?
            }
            None => RecoveryState::new(policy.clone()),
        };
        let incident = IncidentId::new(format!(
            "incident:stall:{}",
            Digest::hash(signature.as_bytes())
                .to_string()
                .trim_start_matches("blake3:")
                .get(..16)
                .unwrap_or_default()
        ))
        .map_err(|error| error.to_string())?;
        let observed = state
            .observe(RecoveryObservation::Failure {
                failure_signature: signature.to_owned(),
                incident_ref: incident,
                observed_at: at(now_ms),
            })
            .map_err(|error| format!("{error:?}"))?
            .into_state();
        let decision = observed
            .next(at(now_ms))
            .map_err(|error| format!("{error:?}"))?;
        let step = match &decision {
            RecoveryDecision::Action { action, .. } => Some(StallStep::Act {
                rung: action.rung,
                attempt: action.attempt_on_rung,
            }),
            RecoveryDecision::Cooldown { .. } => Some(StallStep::Cooldown),
            RecoveryDecision::Blocked { state } => Some(StallStep::Blocked {
                missing_decision: match state.snapshot().phase {
                    odin_kernel::recovery::RecoveryPhaseSnapshot::Blocked { missing_decision } => {
                        missing_decision
                    }
                    _ => String::new(),
                },
            }),
            RecoveryDecision::NoAction { .. } => None,
        };
        self.recovery = Some(decision.into_state().snapshot());
        Ok(step)
    }
}

/// Every tracked run, persisted as one JSON file.
#[derive(Debug, Default, Deserialize, Serialize)]
pub(super) struct StallBook {
    runs: BTreeMap<String, StallState>,
}

impl StallBook {
    /// A missing book is a fresh start; an unreadable or corrupt one also
    /// restarts every run's ladder, so it says so (the next store rewrites it).
    pub(super) fn load(path: &Path) -> Self {
        match std::fs::read(path) {
            Ok(bytes) => serde_json::from_slice(&bytes).unwrap_or_else(|error| {
                tracing::error!(
                    "workload-recovery book-reset path={} reason=corrupt: {error}",
                    path.display()
                );
                Self::default()
            }),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Self::default(),
            Err(error) => {
                tracing::error!(
                    "workload-recovery book-reset path={} reason=unreadable: {error}",
                    path.display()
                );
                Self::default()
            }
        }
    }

    pub(super) fn store(&mut self, path: &Path, now_ms: i64) -> Result<(), String> {
        self.runs
            .retain(|_, state| now_ms - state.last_read_ms < FORGET_AFTER_MS);
        let bytes = serde_json::to_vec_pretty(self).map_err(|error| error.to_string())?;
        let staged = path.with_extension("json.odin-tmp");
        std::fs::write(&staged, bytes)
            .and_then(|()| std::fs::rename(&staged, path))
            .map_err(|error| format!("{}: {error}", path.display()))
    }

    pub(super) fn run(&mut self, run: &str, value: f64, now_ms: i64) -> &mut StallState {
        self.runs
            .entry(run.to_owned())
            .or_insert_with(|| StallState::new(value, now_ms))
    }
}

pub(super) fn pod_policy(
    declared: &odin_registry::schema::RecoveryPolicyToml,
) -> Result<RecoveryPolicy, String> {
    let resolved =
        odin_registry::schema::resolve_recovery_policy(0, std::slice::from_ref(declared))
            .map_err(|error| error.to_string())?;
    RecoveryPolicy::from_resolved(&resolved).map_err(|error| format!("{error:?}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use odin_registry::schema::{
        RecoveryAttemptLimitsToml, RecoveryCooldownsToml, RecoveryPolicyToml, RecoveryRungToml,
    };

    fn policy() -> RecoveryPolicy {
        pod_policy(&RecoveryPolicyToml {
            max_attempts: RecoveryAttemptLimitsToml {
                retry: 0,
                restart_worker: 1,
                checkpoint: 0,
                rehome: 0,
                escalate: 1,
            },
            cooldown_seconds: RecoveryCooldownsToml {
                retry: 0,
                restart_worker: 0,
                checkpoint: 0,
                rehome: 0,
                escalate: 0,
            },
            allowed_rungs: [RecoveryRungToml::RestartWorker, RecoveryRungToml::Escalate]
                .into_iter()
                .collect(),
            blocked_missing_decision: "Colin decides whether to abandon or fix the pod".to_owned(),
        })
        .expect("policy")
    }

    /// Only progress beyond the high-water mark resets the ladder, not repeated heartbeats.
    #[test]
    fn a_stuck_pod_is_restarted_once_then_escalated_on_the_identical_stall() {
        let policy = policy();
        let stall = 60_000;
        let signature = "stall:counter-pod:step";
        let mut state = StallState::new(0.0, 0);
        // Healthy climb.
        for (minute, step) in [(1, 10.0), (2, 20.0), (3, 30.0)] {
            assert_eq!(
                state.observe(step, minute * 60_000, stall, &policy, signature),
                Ok(None)
            );
        }
        // Stuck at 30: heartbeats only, no decision inside the window.
        assert_eq!(
            state.observe(30.0, 200_000, stall, &policy, signature),
            Ok(None)
        );
        assert_eq!(
            state.observe(30.0, 241_000, stall, &policy, signature),
            Ok(Some(StallStep::Act {
                rung: RecoveryRung::RestartWorker,
                attempt: 1
            }))
        );
        // One decision per stall.
        assert_eq!(
            state.observe(30.0, 300_000, stall, &policy, signature),
            Ok(None)
        );
        // Restarted: climbs back from zero, stalls again at 30.
        for (second, step) in [(310, 0.0), (330, 15.0), (350, 30.0)] {
            assert_eq!(
                state.observe(step, second * 1000, stall, &policy, signature),
                Ok(None)
            );
        }
        assert_eq!(
            state.observe(30.0, 411_000, stall, &policy, signature),
            Ok(Some(StallStep::Act {
                rung: RecoveryRung::Escalate,
                attempt: 1
            }))
        );
        // The ladder is spent: the pod moves a little, stalls again, and the
        // ladder is blocked on Colin's decision — never another restart.
        assert_eq!(
            state.observe(29.0, 420_000, stall, &policy, signature),
            Ok(None)
        );
        assert_eq!(
            state.observe(29.0, 481_000, stall, &policy, signature),
            Ok(Some(StallStep::Blocked {
                missing_decision: "Colin decides whether to abandon or fix the pod".to_owned()
            }))
        );

        // Progress past the high-water mark clears a recovering ladder.
        let mut fresh = StallState::new(0.0, 0);
        fresh
            .observe(5.0, 60_000, stall, &policy, signature)
            .unwrap();
        assert!(matches!(
            fresh.observe(5.0, 130_000, stall, &policy, signature),
            Ok(Some(StallStep::Act { .. }))
        ));
        fresh
            .observe(6.0, 140_000, stall, &policy, signature)
            .unwrap();
        assert_eq!(fresh.high_water(), 6.0);
        assert_eq!(fresh.recovery, None, "useful progress cleared the ladder");
    }
}
