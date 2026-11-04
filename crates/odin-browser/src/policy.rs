//! Per-session browser policy: the single home of every changeable browser rule.
//!
//! This module is the only place browser rules exist. Rules are supplied per
//! session by the higher API/kernel, serialized canonically, bound to a
//! BLAKE3 digest, and replaced only through an expected-revision compare-and-
//! swap update. Nothing here inspects page content and nothing outside this
//! module may hard-code domains, effect classes, or approval requirements.
//! Adapter-level safety gates (credentials, quarantine, resource bounds) are
//! immutable and live in `safety.rs`, not here.

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use odin_domain::huginn::BrowserSessionId;
use odin_domain::{CapabilityId, Digest, EffectClass};

/// Caps snapshot size without choosing which rules callers supply.
pub const MAX_POLICY_RULES: usize = 128;

/// Revision of the first snapshot supplied for a session.
pub const INITIAL_POLICY_REVISION: u64 = 1;

/// The closed structural action vocabulary of the browser arm.
///
/// Variants name page interaction shapes only. Whether an action may run,
/// which capability it belongs to, and which effect class it carries are
/// decisions recorded in [`ActionRule`] by the higher API; page text can never
/// introduce, select, or reclassify a variant.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum StructuralAction {
    Navigate,
    Back,
    Forward,
    Reload,
    Fill,
    Activate,
    SubmitForm,
    PressKey,
    Scroll,
    Screenshot,
    Close,
}

/// The single changeable rule attached to one [`StructuralAction`] for a
/// session: which capability covers it, at which capability version, with
/// which effect class, and whether the kernel requires an approval before the
/// action may mutate the browser.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ActionRule {
    pub capability_id: CapabilityId,
    pub capability_version: u64,
    pub effect_class: EffectClass,
    pub approval_required: bool,
}

impl ActionRule {
    /// Canonical validation: structural sanity only. Effect class and
    /// approval requirement combinations are the higher API's decision and
    /// are never second-guessed here.
    pub fn validate(&self) -> Result<(), BrowserPolicyError> {
        if self.capability_version < 1 {
            return Err(BrowserPolicyError::InvalidRules {
                reason: "capability_version must be at least 1".to_owned(),
            });
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BrowserPolicyError {
    InvalidRules {
        reason: String,
    },
    SessionMismatch {
        expected: BrowserSessionId,
        actual: BrowserSessionId,
    },
    RevisionConflict {
        expected_revision: u64,
        actual_revision: u64,
    },
    DigestMismatch {
        recorded: Digest,
        computed: Digest,
    },
}

impl fmt::Display for BrowserPolicyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidRules { reason } => write!(formatter, "invalid policy rules: {reason}"),
            Self::SessionMismatch { expected, actual } => write!(
                formatter,
                "policy session mismatch: expected {expected}, got {actual}"
            ),
            Self::RevisionConflict {
                expected_revision,
                actual_revision,
            } => write!(
                formatter,
                "policy revision conflict: expected {expected_revision}, actual {actual_revision}"
            ),
            Self::DigestMismatch { recorded, computed } => write!(
                formatter,
                "policy digest mismatch: recorded {recorded}, computed {computed}"
            ),
        }
    }
}

impl std::error::Error for BrowserPolicyError {}

/// BLAKE3 digest over the canonical serialization (`serde_json`) of the rule
/// map. `BTreeMap` ordering makes the serialization deterministic.
fn rules_digest(rules: &BTreeMap<StructuralAction, ActionRule>) -> Digest {
    let canonical = serde_json::to_vec(rules)
        .expect("BTreeMap<StructuralAction, ActionRule> serialization is infallible");
    Digest::hash(&canonical)
}

/// Validates rule count and structure without supplying defaults.
pub fn validate_rules(
    rules: &BTreeMap<StructuralAction, ActionRule>,
) -> Result<(), BrowserPolicyError> {
    if rules.len() > MAX_POLICY_RULES {
        return Err(BrowserPolicyError::InvalidRules {
            reason: format!(
                "rule map holds {} entries, bound is {MAX_POLICY_RULES}",
                rules.len()
            ),
        });
    }
    for (action, rule) in rules {
        rule.validate().map_err(|error| match error {
            BrowserPolicyError::InvalidRules { reason } => BrowserPolicyError::InvalidRules {
                reason: format!("{action:?}: {reason}"),
            },
            other => other,
        })?;
    }
    Ok(())
}

/// An immutable per-session policy: the complete rule map plus the revision
/// and digest that identify it. Rules can only be replaced through
/// [`BrowserPolicySnapshot::apply`], which enforces the expected-revision CAS
/// and produces the invalidation metadata that retires pending actions bound
/// to the superseded policy.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", try_from = "BrowserPolicySnapshotParts")]
pub struct BrowserPolicySnapshot {
    session_id: BrowserSessionId,
    revision: u64,
    digest: Digest,
    rules: BTreeMap<StructuralAction, ActionRule>,
}

impl BrowserPolicySnapshot {
    /// Seals the initial per-session policy at [`INITIAL_POLICY_REVISION`].
    /// There is no default rule set: whatever the caller supplies is the
    /// whole policy, including the empty map.
    pub fn initial(
        session_id: BrowserSessionId,
        rules: BTreeMap<StructuralAction, ActionRule>,
    ) -> Result<Self, BrowserPolicyError> {
        validate_rules(&rules)?;
        let digest = rules_digest(&rules);
        Ok(Self {
            session_id,
            revision: INITIAL_POLICY_REVISION,
            digest,
            rules,
        })
    }

    fn seal(
        session_id: BrowserSessionId,
        revision: u64,
        rules: BTreeMap<StructuralAction, ActionRule>,
    ) -> Self {
        let digest = rules_digest(&rules);
        Self {
            session_id,
            revision,
            digest,
            rules,
        }
    }

    pub fn session_id(&self) -> BrowserSessionId {
        self.session_id
    }

    pub fn revision(&self) -> u64 {
        self.revision
    }

    pub fn digest(&self) -> Digest {
        self.digest
    }

    pub fn rules(&self) -> &BTreeMap<StructuralAction, ActionRule> {
        &self.rules
    }

    pub fn rule(&self, action: &StructuralAction) -> Option<&ActionRule> {
        self.rules.get(action)
    }

    /// Compare-and-swap policy replacement. The update applies only when its
    /// `expected_revision` equals the current revision and it targets this
    /// session; the new revision is always current + 1 and always carries a
    /// freshly computed digest. The returned [`PolicyInvalidation`] marks
    /// every pending action bound to any other (revision, digest) pair as
    /// stale.
    pub fn apply(
        &self,
        update: &BrowserPolicyUpdate,
    ) -> Result<BrowserPolicyUpdateOutcome, BrowserPolicyError> {
        if update.session_id != self.session_id {
            return Err(BrowserPolicyError::SessionMismatch {
                expected: self.session_id,
                actual: update.session_id,
            });
        }
        if update.expected_revision != self.revision {
            return Err(BrowserPolicyError::RevisionConflict {
                expected_revision: update.expected_revision,
                actual_revision: self.revision,
            });
        }
        validate_rules(&update.rules)?;
        let revision =
            self.revision
                .checked_add(1)
                .ok_or_else(|| BrowserPolicyError::InvalidRules {
                    reason: "policy revision is exhausted".to_owned(),
                })?;
        let snapshot = Self::seal(self.session_id, revision, update.rules.clone());
        let invalidation = PolicyInvalidation {
            superseded_revision: self.revision,
            superseded_digest: self.digest,
            active_revision: snapshot.revision,
            active_digest: snapshot.digest,
        };
        Ok(BrowserPolicyUpdateOutcome {
            snapshot,
            invalidation,
        })
    }

    pub fn binding_is_current(&self, binding: &crate::capability::PolicyBinding) -> bool {
        binding.revision == self.revision && binding.digest == self.digest
    }
}

/// Intermediate shape used to validate a deserialized snapshot: the recorded
/// digest is recomputed from the rules and must match exactly.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct BrowserPolicySnapshotParts {
    session_id: BrowserSessionId,
    revision: u64,
    digest: Digest,
    rules: BTreeMap<StructuralAction, ActionRule>,
}

impl TryFrom<BrowserPolicySnapshotParts> for BrowserPolicySnapshot {
    type Error = BrowserPolicyError;

    fn try_from(parts: BrowserPolicySnapshotParts) -> Result<Self, Self::Error> {
        if parts.revision < INITIAL_POLICY_REVISION {
            return Err(BrowserPolicyError::InvalidRules {
                reason: format!("revision {} precedes the initial revision", parts.revision),
            });
        }
        validate_rules(&parts.rules)?;
        let computed = rules_digest(&parts.rules);
        if computed != parts.digest {
            return Err(BrowserPolicyError::DigestMismatch {
                recorded: parts.digest,
                computed,
            });
        }
        Ok(Self {
            session_id: parts.session_id,
            revision: parts.revision,
            digest: parts.digest,
            rules: parts.rules,
        })
    }
}

/// A caller-supplied replacement rule map for one session, guarded by the
/// policy revision the caller observed. Carries no rules of its own beyond
/// what the higher API put in it.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BrowserPolicyUpdate {
    pub session_id: BrowserSessionId,
    pub expected_revision: u64,
    pub rules: BTreeMap<StructuralAction, ActionRule>,
}

impl BrowserPolicyUpdate {
    pub fn new(
        session_id: BrowserSessionId,
        expected_revision: u64,
        rules: BTreeMap<StructuralAction, ActionRule>,
    ) -> Result<Self, BrowserPolicyError> {
        validate_rules(&rules)?;
        Ok(Self {
            session_id,
            expected_revision,
            rules,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BrowserPolicyUpdateOutcome {
    pub snapshot: BrowserPolicySnapshot,
    pub invalidation: PolicyInvalidation,
}

/// Stale-pending invalidation metadata for one applied policy update.
///
/// Any pending action bound to a (revision, digest) pair that is not the
/// active pair is stale and must be abandoned before it can reach the worker.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PolicyInvalidation {
    pub superseded_revision: u64,
    pub superseded_digest: Digest,
    pub active_revision: u64,
    pub active_digest: Digest,
}

impl PolicyInvalidation {
    pub fn invalidates(&self, policy_revision: u64, policy_digest: Digest) -> bool {
        policy_revision != self.active_revision || policy_digest != self.active_digest
    }
}
