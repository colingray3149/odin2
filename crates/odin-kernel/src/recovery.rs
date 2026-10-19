//! Finite, pure recovery-ladder transitions.

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt;
use std::str::FromStr;

use odin_domain::{Digest, IncidentId};
use odin_registry::{RecoveryRungToml, ResolvedRecoveryPolicy};
use time::{Duration, OffsetDateTime};

const RUNG_COUNT: usize = 5;

/// Ordered recovery actions. Each rung has a finite configured attempt limit.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum RecoveryRung {
    Retry,
    RestartWorker,
    Checkpoint,
    Rehome,
    Escalate,
}

impl RecoveryRung {
    const ORDER: [Self; RUNG_COUNT] = [
        Self::Retry,
        Self::RestartWorker,
        Self::Checkpoint,
        Self::Rehome,
        Self::Escalate,
    ];
    const fn index(self) -> usize {
        match self {
            Self::Retry => 0,
            Self::RestartWorker => 1,
            Self::Checkpoint => 2,
            Self::Rehome => 3,
            Self::Escalate => 4,
        }
    }

    const fn successor(self) -> Option<Self> {
        match self {
            Self::Retry => Some(Self::RestartWorker),
            Self::RestartWorker => Some(Self::Checkpoint),
            Self::Checkpoint => Some(Self::Rehome),
            Self::Rehome => Some(Self::Escalate),
            Self::Escalate => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RungLimits {
    limits: [u32; RUNG_COUNT],
}

impl RungLimits {
    pub const fn new(
        retry: u32,
        restart_worker: u32,
        checkpoint: u32,
        rehome: u32,
        escalate: u32,
    ) -> Self {
        Self {
            limits: [retry, restart_worker, checkpoint, rehome, escalate],
        }
    }

    pub const fn limit(self, rung: RecoveryRung) -> u32 {
        self.limits[rung.index()]
    }
}

impl Default for RungLimits {
    fn default() -> Self {
        Self::new(2, 1, 1, 1, 1)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RungCooldowns {
    cooldowns: [Duration; RUNG_COUNT],
}

impl RungCooldowns {
    pub const fn new(
        retry: Duration,
        restart_worker: Duration,
        checkpoint: Duration,
        rehome: Duration,
        escalate: Duration,
    ) -> Self {
        Self {
            cooldowns: [retry, restart_worker, checkpoint, rehome, escalate],
        }
    }

    pub const fn uniform(cooldown: Duration) -> Self {
        Self::new(cooldown, cooldown, cooldown, cooldown, cooldown)
    }

    pub const fn cooldown(self, rung: RecoveryRung) -> Duration {
        self.cooldowns[rung.index()]
    }

    fn contains_negative(self) -> bool {
        self.cooldowns
            .into_iter()
            .any(|cooldown| cooldown < Duration::ZERO)
    }
}

impl Default for RungCooldowns {
    fn default() -> Self {
        Self::uniform(Duration::seconds(30))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoveryPolicy {
    limits: RungLimits,
    cooldowns: RungCooldowns,
    blocked_missing_decision: String,
    allowed: BTreeSet<RecoveryRung>,
    registry_revision: u64,
    policy_digest: Digest,
}

impl RecoveryPolicy {
    pub fn new(
        limits: RungLimits,
        cooldowns: RungCooldowns,
        blocked_missing_decision: impl Into<String>,
    ) -> Result<Self, RecoveryError> {
        if cooldowns.contains_negative() {
            return Err(RecoveryError::NegativeCooldown);
        }
        let blocked_missing_decision = blocked_missing_decision.into();
        if blocked_missing_decision.trim().is_empty() {
            return Err(RecoveryError::EmptyMissingDecision);
        }
        Ok(Self {
            limits,
            cooldowns,
            blocked_missing_decision,
            allowed: RecoveryRung::ORDER.into_iter().collect(),
            registry_revision: 0,
            policy_digest: Digest::hash(b"kernel-test-recovery-policy"),
        })
    }

    pub const fn limits(&self) -> RungLimits {
        self.limits
    }

    pub const fn cooldowns(&self) -> RungCooldowns {
        self.cooldowns
    }

    pub fn blocked_missing_decision(&self) -> &str {
        &self.blocked_missing_decision
    }

    pub fn from_resolved(resolved: &ResolvedRecoveryPolicy) -> Result<Self, RecoveryError> {
        let limits = &resolved.policy.max_attempts;
        let cooldowns = &resolved.policy.cooldown_seconds;
        let allowed = resolved
            .filtered_rungs
            .iter()
            .map(|rung| match rung {
                RecoveryRungToml::Retry => RecoveryRung::Retry,
                RecoveryRungToml::RestartWorker => RecoveryRung::RestartWorker,
                RecoveryRungToml::Checkpoint => RecoveryRung::Checkpoint,
                RecoveryRungToml::Rehome => RecoveryRung::Rehome,
                RecoveryRungToml::Escalate => RecoveryRung::Escalate,
            })
            .collect::<BTreeSet<_>>();
        if !allowed.contains(&RecoveryRung::Escalate) {
            return Err(RecoveryError::MissingTerminalRung);
        }
        let mut policy = Self::new(
            RungLimits::new(
                limits.retry,
                limits.restart_worker,
                limits.checkpoint,
                limits.rehome,
                limits.escalate,
            ),
            RungCooldowns::new(
                Duration::seconds(
                    i64::try_from(cooldowns.retry)
                        .map_err(|_| RecoveryError::TimestampOutOfRange)?,
                ),
                Duration::seconds(
                    i64::try_from(cooldowns.restart_worker)
                        .map_err(|_| RecoveryError::TimestampOutOfRange)?,
                ),
                Duration::seconds(
                    i64::try_from(cooldowns.checkpoint)
                        .map_err(|_| RecoveryError::TimestampOutOfRange)?,
                ),
                Duration::seconds(
                    i64::try_from(cooldowns.rehome)
                        .map_err(|_| RecoveryError::TimestampOutOfRange)?,
                ),
                Duration::seconds(
                    i64::try_from(cooldowns.escalate)
                        .map_err(|_| RecoveryError::TimestampOutOfRange)?,
                ),
            ),
            resolved.policy.blocked_missing_decision.clone(),
        )?;
        policy.allowed = allowed;
        policy.registry_revision = resolved.registry_revision;
        policy.policy_digest = resolved.policy_digest;
        Ok(policy)
    }

    pub const fn registry_revision(&self) -> u64 {
        self.registry_revision
    }

    pub const fn policy_digest(&self) -> Digest {
        self.policy_digest
    }

    fn next_allowed(&self, rung: RecoveryRung) -> Option<RecoveryRung> {
        let mut next = Some(rung);
        while let Some(candidate) = next {
            if self.allowed.contains(&candidate) {
                return Some(candidate);
            }
            next = candidate.successor();
        }
        None
    }
}

impl Default for RecoveryPolicy {
    fn default() -> Self {
        Self::new(
            RungLimits::default(),
            RungCooldowns::default(),
            "operator must choose whether to abandon, repair, or resume the workload",
        )
        .expect("compiled test recovery policy is valid")
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RecoveryPhase {
    Idle,
    Recovering { rung: RecoveryRung },
    Blocked { missing_decision: String },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RecoveryObservation {
    Failure {
        failure_signature: String,
        incident_ref: IncidentId,
        observed_at: OffsetDateTime,
    },
    UsefulProgress {
        observed_at: OffsetDateTime,
    },
    Heartbeat {
        observed_at: OffsetDateTime,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ObservationDisposition {
    Activated,
    FailureLinked,
    DuplicateFailure,
    ClearedByUsefulProgress,
    StaleUsefulProgress,
    HeartbeatOnly,
    NoChange,
    TerminalBlocked,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoveryUpdate {
    state: RecoveryState,
    disposition: ObservationDisposition,
}

impl RecoveryUpdate {
    pub const fn state(&self) -> &RecoveryState {
        &self.state
    }

    pub const fn disposition(&self) -> ObservationDisposition {
        self.disposition
    }

    pub fn into_state(self) -> RecoveryState {
        self.state
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoveryState {
    policy: RecoveryPolicy,
    phase: RecoveryPhase,
    attempts: [u32; RUNG_COUNT],
    total_attempts: u64,
    cooldown_until: Option<OffsetDateTime>,
    failure_signatures: BTreeSet<String>,
    incident_refs: BTreeSet<IncidentId>,
    last_failure_at: Option<OffsetDateTime>,
    revision: u64,
}

impl RecoveryState {
    pub fn new(policy: RecoveryPolicy) -> Self {
        Self {
            policy,
            phase: RecoveryPhase::Idle,
            attempts: [0; RUNG_COUNT],
            total_attempts: 0,
            cooldown_until: None,
            failure_signatures: BTreeSet::new(),
            incident_refs: BTreeSet::new(),
            last_failure_at: None,
            revision: 0,
        }
    }

    pub const fn policy(&self) -> &RecoveryPolicy {
        &self.policy
    }

    pub const fn phase(&self) -> &RecoveryPhase {
        &self.phase
    }

    pub const fn revision(&self) -> u64 {
        self.revision
    }

    pub const fn total_attempts(&self) -> u64 {
        self.total_attempts
    }

    pub const fn attempts_on(&self, rung: RecoveryRung) -> u32 {
        self.attempts[rung.index()]
    }

    pub const fn cooldown_until(&self) -> Option<OffsetDateTime> {
        self.cooldown_until
    }

    pub fn failure_signatures(&self) -> impl Iterator<Item = &str> {
        self.failure_signatures.iter().map(String::as_str)
    }

    pub fn incident_refs(&self) -> impl Iterator<Item = &IncidentId> {
        self.incident_refs.iter()
    }

    pub const fn last_failure_at(&self) -> Option<OffsetDateTime> {
        self.last_failure_at
    }

    /// Applies an observation without I/O or hidden mutation.
    pub fn observe(
        self,
        observation: RecoveryObservation,
    ) -> Result<RecoveryUpdate, RecoveryError> {
        match observation {
            RecoveryObservation::Heartbeat { .. } => Ok(RecoveryUpdate {
                state: self,
                disposition: ObservationDisposition::HeartbeatOnly,
            }),
            RecoveryObservation::Failure {
                failure_signature,
                incident_ref,
                observed_at,
            } => self.observe_failure(failure_signature, incident_ref, observed_at),
            RecoveryObservation::UsefulProgress { observed_at } => {
                self.observe_useful_progress(observed_at)
            }
        }
    }

    fn observe_failure(
        mut self,
        failure_signature: String,
        incident_ref: IncidentId,
        observed_at: OffsetDateTime,
    ) -> Result<RecoveryUpdate, RecoveryError> {
        if failure_signature.trim().is_empty() {
            return Err(RecoveryError::EmptyFailureSignature);
        }

        if matches!(&self.phase, RecoveryPhase::Idle) {
            self.attempts = [0; RUNG_COUNT];
            self.total_attempts = 0;
            self.cooldown_until = None;
            self.failure_signatures.clear();
            self.incident_refs.clear();
            self.failure_signatures.insert(failure_signature);
            self.incident_refs.insert(incident_ref);
            self.last_failure_at = Some(observed_at);
            self.phase = RecoveryPhase::Recovering {
                rung: RecoveryRung::Retry,
            };
            self.bump_revision()?;
            return Ok(RecoveryUpdate {
                state: self,
                disposition: ObservationDisposition::Activated,
            });
        }

        let signature_added = self.failure_signatures.insert(failure_signature);
        let incident_added = self.incident_refs.insert(incident_ref);
        if !signature_added && !incident_added {
            let disposition = if matches!(&self.phase, RecoveryPhase::Blocked { .. }) {
                ObservationDisposition::TerminalBlocked
            } else {
                ObservationDisposition::DuplicateFailure
            };
            return Ok(RecoveryUpdate {
                state: self,
                disposition,
            });
        }

        self.last_failure_at = Some(
            self.last_failure_at
                .map_or(observed_at, |current| current.max(observed_at)),
        );
        self.bump_revision()?;
        Ok(RecoveryUpdate {
            state: self,
            disposition: ObservationDisposition::FailureLinked,
        })
    }

    fn observe_useful_progress(
        mut self,
        observed_at: OffsetDateTime,
    ) -> Result<RecoveryUpdate, RecoveryError> {
        match &self.phase {
            RecoveryPhase::Idle => Ok(RecoveryUpdate {
                state: self,
                disposition: ObservationDisposition::NoChange,
            }),
            RecoveryPhase::Blocked { .. } => Ok(RecoveryUpdate {
                state: self,
                disposition: ObservationDisposition::TerminalBlocked,
            }),
            RecoveryPhase::Recovering { .. }
                if self
                    .last_failure_at
                    .is_some_and(|failure_at| observed_at <= failure_at) =>
            {
                Ok(RecoveryUpdate {
                    state: self,
                    disposition: ObservationDisposition::StaleUsefulProgress,
                })
            }
            RecoveryPhase::Recovering { .. } => {
                self.phase = RecoveryPhase::Idle;
                self.attempts = [0; RUNG_COUNT];
                self.total_attempts = 0;
                self.cooldown_until = None;
                self.last_failure_at = None;
                self.bump_revision()?;
                Ok(RecoveryUpdate {
                    state: self,
                    disposition: ObservationDisposition::ClearedByUsefulProgress,
                })
            }
        }
    }

    pub fn next(mut self, now: OffsetDateTime) -> Result<RecoveryDecision, RecoveryError> {
        let rung = match &self.phase {
            RecoveryPhase::Idle => return Ok(RecoveryDecision::NoAction { state: self }),
            RecoveryPhase::Blocked { .. } => {
                return Ok(RecoveryDecision::Blocked { state: self });
            }
            RecoveryPhase::Recovering { rung } => *rung,
        };
        let Some(mut rung) = self.policy.next_allowed(rung) else {
            self.phase = RecoveryPhase::Blocked {
                missing_decision: self.policy.blocked_missing_decision.clone(),
            };
            self.cooldown_until = None;
            self.bump_revision()?;
            return Ok(RecoveryDecision::Blocked { state: self });
        };

        if self
            .cooldown_until
            .is_some_and(|cooldown_until| now < cooldown_until)
        {
            return Ok(RecoveryDecision::Cooldown { state: self });
        }

        loop {
            let index = rung.index();
            let limit = self.policy.limits.limit(rung);
            if self.attempts[index] < limit {
                let attempt_on_rung = self.attempts[index]
                    .checked_add(1)
                    .ok_or(RecoveryError::AttemptCounterExhausted)?;
                let total_attempt = self
                    .total_attempts
                    .checked_add(1)
                    .ok_or(RecoveryError::AttemptCounterExhausted)?;
                let cooldown_until = now
                    .checked_add(self.policy.cooldowns.cooldown(rung))
                    .ok_or(RecoveryError::TimestampOutOfRange)?;

                self.attempts[index] = attempt_on_rung;
                self.total_attempts = total_attempt;
                self.cooldown_until = Some(cooldown_until);
                self.phase = RecoveryPhase::Recovering { rung };
                self.bump_revision()?;
                let action = RecoveryAction {
                    rung,
                    attempt_on_rung,
                    total_attempt,
                    revision: self.revision,
                };
                return Ok(RecoveryDecision::Action {
                    state: self,
                    action,
                });
            }

            let Some(successor) = rung
                .successor()
                .and_then(|candidate| self.policy.next_allowed(candidate))
            else {
                self.phase = RecoveryPhase::Blocked {
                    missing_decision: self.policy.blocked_missing_decision.clone(),
                };
                self.cooldown_until = None;
                self.bump_revision()?;
                return Ok(RecoveryDecision::Blocked { state: self });
            };
            rung = successor;
        }
    }

    fn bump_revision(&mut self) -> Result<(), RecoveryError> {
        self.revision = self
            .revision
            .checked_add(1)
            .ok_or(RecoveryError::RevisionExhausted)?;
        Ok(())
    }
}

impl RecoveryState {
    /// Missing dispatch permission is terminal so the driver cannot silently retry it.
    pub fn block(mut self, missing_decision: impl Into<String>) -> Result<Self, RecoveryError> {
        let missing_decision = missing_decision.into();
        if missing_decision.trim().is_empty() {
            return Err(RecoveryError::EmptyMissingDecision);
        }
        self.phase = RecoveryPhase::Blocked { missing_decision };
        self.cooldown_until = None;
        self.bump_revision()?;
        Ok(self)
    }
}

fn rung_name(rung: RecoveryRung) -> &'static str {
    match rung {
        RecoveryRung::Retry => "retry",
        RecoveryRung::RestartWorker => "restart_worker",
        RecoveryRung::Checkpoint => "checkpoint",
        RecoveryRung::Rehome => "rehome",
        RecoveryRung::Escalate => "escalate",
    }
}

fn rung_from_name(name: &str) -> Option<RecoveryRung> {
    match name {
        "retry" => Some(RecoveryRung::Retry),
        "restart_worker" => Some(RecoveryRung::RestartWorker),
        "checkpoint" => Some(RecoveryRung::Checkpoint),
        "rehome" => Some(RecoveryRung::Rehome),
        "escalate" => Some(RecoveryRung::Escalate),
        _ => None,
    }
}

/// Exact `time::Duration` pair; `time::Duration` itself has no serde form.
#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DurationSnapshot {
    pub seconds: i64,
    pub nanoseconds: i32,
}

impl DurationSnapshot {
    const fn of(duration: Duration) -> Self {
        Self {
            seconds: duration.whole_seconds(),
            nanoseconds: duration.subsec_nanoseconds(),
        }
    }

    const fn to_duration(self) -> Duration {
        Duration::new(self.seconds, self.nanoseconds)
    }
}

/// Validate rung names on restore so persisted state cannot introduce unknown actions.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryPolicySnapshot {
    pub limits: BTreeMap<String, u32>,
    pub cooldowns: BTreeMap<String, DurationSnapshot>,
    pub blocked_missing_decision: String,
    pub allowed: BTreeSet<String>,
    pub registry_revision: u64,
    pub policy_digest: String,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum RecoveryPhaseSnapshot {
    Idle,
    Recovering { rung: String },
    Blocked { missing_decision: String },
}

/// Reject other versions rather than guessing their layout.
pub const RECOVERY_SNAPSHOT_VERSION: u16 = 1;

/// Persist the complete ladder state so reopening does not infer progress.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoverySnapshot {
    pub snapshot_version: u16,
    pub policy: RecoveryPolicySnapshot,
    pub phase: RecoveryPhaseSnapshot,
    pub attempts: BTreeMap<String, u32>,
    pub total_attempts: u64,
    pub cooldown_until: Option<OffsetDateTime>,
    pub failure_signatures: BTreeSet<String>,
    pub incident_refs: Vec<String>,
    pub last_failure_at: Option<OffsetDateTime>,
    pub revision: u64,
}

impl RecoveryPolicy {
    fn to_snapshot(&self) -> RecoveryPolicySnapshot {
        let mut limits = BTreeMap::new();
        let mut cooldowns = BTreeMap::new();
        let mut allowed = BTreeSet::new();
        for rung in RecoveryRung::ORDER {
            limits.insert(rung_name(rung).to_owned(), self.limits.limit(rung));
            cooldowns.insert(
                rung_name(rung).to_owned(),
                DurationSnapshot::of(self.cooldowns.cooldown(rung)),
            );
            if self.allowed.contains(&rung) {
                allowed.insert(rung_name(rung).to_owned());
            }
        }
        RecoveryPolicySnapshot {
            limits,
            cooldowns,
            blocked_missing_decision: self.blocked_missing_decision.clone(),
            allowed,
            registry_revision: self.registry_revision,
            policy_digest: self.policy_digest.to_string(),
        }
    }

    fn from_snapshot(snapshot: RecoveryPolicySnapshot) -> Result<Self, RecoveryError> {
        if snapshot.blocked_missing_decision.trim().is_empty() {
            return Err(RecoveryError::EmptyMissingDecision);
        }
        let mut limits = [0u32; RUNG_COUNT];
        let mut cooldowns = [Duration::ZERO; RUNG_COUNT];
        let mut allowed = BTreeSet::new();
        for rung in RecoveryRung::ORDER {
            let name = rung_name(rung);
            let limit = *snapshot
                .limits
                .get(name)
                .ok_or_else(|| RecoveryError::InvalidSnapshotRung(name.to_owned()))?;
            let cooldown = snapshot
                .cooldowns
                .get(name)
                .ok_or_else(|| RecoveryError::InvalidSnapshotRung(name.to_owned()))?
                .to_duration();
            if cooldown < Duration::ZERO {
                return Err(RecoveryError::NegativeCooldown);
            }
            limits[rung.index()] = limit;
            cooldowns[rung.index()] = cooldown;
            if snapshot.allowed.contains(name) {
                allowed.insert(rung);
            }
        }
        if snapshot
            .allowed
            .iter()
            .any(|name| rung_from_name(name).is_none())
        {
            return Err(RecoveryError::InvalidSnapshotRung("unknown".to_owned()));
        }
        let policy_digest = Digest::from_str(&snapshot.policy_digest)
            .map_err(|_| RecoveryError::InvalidSnapshotDigest)?;
        Ok(Self {
            limits: RungLimits { limits },
            cooldowns: RungCooldowns { cooldowns },
            blocked_missing_decision: snapshot.blocked_missing_decision,
            allowed,
            registry_revision: snapshot.registry_revision,
            policy_digest,
        })
    }
}

impl RecoveryState {
    pub fn snapshot(&self) -> RecoverySnapshot {
        let attempts = RecoveryRung::ORDER
            .into_iter()
            .map(|rung| (rung_name(rung).to_owned(), self.attempts[rung.index()]))
            .collect();
        RecoverySnapshot {
            snapshot_version: RECOVERY_SNAPSHOT_VERSION,
            policy: self.policy.to_snapshot(),
            phase: match &self.phase {
                RecoveryPhase::Idle => RecoveryPhaseSnapshot::Idle,
                RecoveryPhase::Recovering { rung } => RecoveryPhaseSnapshot::Recovering {
                    rung: rung_name(*rung).to_owned(),
                },
                RecoveryPhase::Blocked { missing_decision } => RecoveryPhaseSnapshot::Blocked {
                    missing_decision: missing_decision.clone(),
                },
            },
            attempts,
            total_attempts: self.total_attempts,
            cooldown_until: self.cooldown_until,
            failure_signatures: self.failure_signatures.clone(),
            incident_refs: self.incident_refs.iter().map(ToString::to_string).collect(),
            last_failure_at: self.last_failure_at,
            revision: self.revision,
        }
    }

    /// Reject invalid fields rather than restoring a partially usable ladder.
    pub fn from_snapshot(snapshot: RecoverySnapshot) -> Result<Self, RecoveryError> {
        if snapshot.snapshot_version != RECOVERY_SNAPSHOT_VERSION {
            return Err(RecoveryError::UnsupportedSnapshotVersion(
                snapshot.snapshot_version,
            ));
        }
        let policy = RecoveryPolicy::from_snapshot(snapshot.policy)?;
        if snapshot.attempts.len() != RUNG_COUNT {
            return Err(RecoveryError::InvalidSnapshotRung(
                "attempt-map-shape".to_owned(),
            ));
        }
        let mut attempts = [0u32; RUNG_COUNT];
        for rung in RecoveryRung::ORDER {
            let name = rung_name(rung);
            let value = *snapshot
                .attempts
                .get(name)
                .ok_or_else(|| RecoveryError::InvalidSnapshotRung(name.to_owned()))?;
            attempts[rung.index()] = value;
        }
        let mut incident_refs = BTreeSet::new();
        for reference in snapshot.incident_refs {
            let incident = IncidentId::from_str(&reference)
                .map_err(|_| RecoveryError::InvalidSnapshotIncident(reference))?;
            incident_refs.insert(incident);
        }
        let phase = match snapshot.phase {
            RecoveryPhaseSnapshot::Idle => RecoveryPhase::Idle,
            RecoveryPhaseSnapshot::Recovering { rung } => RecoveryPhase::Recovering {
                rung: rung_from_name(&rung).ok_or(RecoveryError::InvalidSnapshotRung(rung))?,
            },
            RecoveryPhaseSnapshot::Blocked { missing_decision } => {
                if missing_decision.trim().is_empty() {
                    return Err(RecoveryError::EmptyMissingDecision);
                }
                RecoveryPhase::Blocked { missing_decision }
            }
        };
        if snapshot
            .failure_signatures
            .iter()
            .any(|signature| signature.trim().is_empty())
        {
            return Err(RecoveryError::EmptyFailureSignature);
        }
        Ok(Self {
            policy,
            phase,
            attempts,
            total_attempts: snapshot.total_attempts,
            cooldown_until: snapshot.cooldown_until,
            failure_signatures: snapshot.failure_signatures,
            incident_refs,
            last_failure_at: snapshot.last_failure_at,
            revision: snapshot.revision,
        })
    }
}

impl Default for RecoveryState {
    fn default() -> Self {
        Self::new(RecoveryPolicy::default())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RecoveryAction {
    pub rung: RecoveryRung,
    pub attempt_on_rung: u32,
    pub total_attempt: u64,
    pub revision: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RecoveryDecision {
    NoAction {
        state: RecoveryState,
    },
    Cooldown {
        state: RecoveryState,
    },
    Action {
        state: RecoveryState,
        action: RecoveryAction,
    },
    Blocked {
        state: RecoveryState,
    },
}

impl RecoveryDecision {
    pub const fn state(&self) -> &RecoveryState {
        match self {
            Self::NoAction { state }
            | Self::Cooldown { state }
            | Self::Action { state, .. }
            | Self::Blocked { state } => state,
        }
    }

    pub fn into_state(self) -> RecoveryState {
        match self {
            Self::NoAction { state }
            | Self::Cooldown { state }
            | Self::Action { state, .. }
            | Self::Blocked { state } => state,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RecoveryError {
    EmptyFailureSignature,
    EmptyMissingDecision,
    NegativeCooldown,
    RevisionExhausted,
    AttemptCounterExhausted,
    TimestampOutOfRange,
    MissingTerminalRung,
    UnsupportedSnapshotVersion(u16),
    InvalidSnapshotRung(String),
    InvalidSnapshotDigest,
    InvalidSnapshotIncident(String),
}

impl fmt::Display for RecoveryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyFailureSignature => {
                formatter.write_str("failure signature must not be empty")
            }
            Self::EmptyMissingDecision => {
                formatter.write_str("blocked missing decision must not be empty")
            }
            Self::NegativeCooldown => {
                formatter.write_str("recovery cooldowns must not be negative")
            }
            Self::RevisionExhausted => formatter.write_str("recovery revision exhausted"),
            Self::AttemptCounterExhausted => {
                formatter.write_str("recovery attempt counter exhausted")
            }
            Self::TimestampOutOfRange => {
                formatter.write_str("recovery cooldown timestamp is out of range")
            }
            Self::MissingTerminalRung => {
                formatter.write_str("recovery policy must retain terminal escalation")
            }
            Self::UnsupportedSnapshotVersion(version) => {
                write!(
                    formatter,
                    "recovery snapshot version {version} is unsupported"
                )
            }
            Self::InvalidSnapshotRung(name) => {
                write!(formatter, "recovery snapshot names invalid rung {name:?}")
            }
            Self::InvalidSnapshotDigest => {
                formatter.write_str("recovery snapshot policy digest is invalid")
            }
            Self::InvalidSnapshotIncident(reference) => {
                write!(
                    formatter,
                    "recovery snapshot names invalid incident reference {reference:?}"
                )
            }
        }
    }
}

impl Error for RecoveryError {}

#[cfg(test)]
mod tests;
