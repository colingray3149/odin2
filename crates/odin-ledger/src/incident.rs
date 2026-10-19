use std::collections::HashSet;
use std::fmt;

use odin_domain::{AttemptId, CapabilityId, Digest, IncidentId, RunId};
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;
use time::OffsetDateTime;

use crate::{decode_utc, encode_utc, parse_id, Ledger, LedgerError, LedgerResult};

pub const INCIDENT_CARD_SCHEMA_VERSION: u16 = 1;

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IncidentSeverity {
    Info,
    Warning,
    Error,
    Critical,
}

impl IncidentSeverity {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Warning => "warning",
            Self::Error => "error",
            Self::Critical => "critical",
        }
    }

    fn parse(value: &str) -> LedgerResult<Self> {
        match value {
            "info" => Ok(Self::Info),
            "warning" => Ok(Self::Warning),
            "error" => Ok(Self::Error),
            "critical" => Ok(Self::Critical),
            other => Err(LedgerError::invalid_data(format!(
                "unknown incident severity {other:?}"
            ))),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IncidentStatus {
    Open,
    Recovering,
    Escalated,
    Resolved,
    Blocked,
}

impl IncidentStatus {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Recovering => "recovering",
            Self::Escalated => "escalated",
            Self::Resolved => "resolved",
            Self::Blocked => "blocked",
        }
    }

    pub const fn can_transition_to(self, next: Self) -> bool {
        match self {
            Self::Open => matches!(
                next,
                Self::Recovering | Self::Escalated | Self::Resolved | Self::Blocked
            ),
            Self::Recovering => matches!(
                next,
                Self::Open | Self::Escalated | Self::Resolved | Self::Blocked
            ),
            Self::Escalated => {
                matches!(next, Self::Recovering | Self::Resolved | Self::Blocked)
            }
            Self::Blocked => {
                matches!(next, Self::Recovering | Self::Escalated | Self::Resolved)
            }
            Self::Resolved => false,
        }
    }

    fn parse(value: &str) -> LedgerResult<Self> {
        match value {
            "open" => Ok(Self::Open),
            "recovering" => Ok(Self::Recovering),
            "escalated" => Ok(Self::Escalated),
            "resolved" => Ok(Self::Resolved),
            "blocked" => Ok(Self::Blocked),
            other => Err(LedgerError::invalid_data(format!(
                "unknown incident status {other:?}"
            ))),
        }
    }
}

/// Fixed-point confidence in millionths.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ConfidenceMicros(i64);

impl ConfidenceMicros {
    pub const MIN: i64 = 0;
    pub const MAX: i64 = 1_000_000;

    pub fn new(value: i64) -> Result<Self, IncidentValidationError> {
        if (Self::MIN..=Self::MAX).contains(&value) {
            Ok(Self(value))
        } else {
            Err(IncidentValidationError::ConfidenceOutOfRange(value))
        }
    }

    pub const fn get(self) -> i64 {
        self.0
    }
}

/// A bounded evidence list. Duplicates and empty strings are rejected.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EvidenceRefs(Vec<String>);

impl EvidenceRefs {
    pub const MAX_LEN: usize = 5;

    pub fn new(values: impl IntoIterator<Item = String>) -> Result<Self, IncidentValidationError> {
        let mut unique = HashSet::new();
        let mut refs = Vec::new();
        for value in values {
            if value.is_empty() {
                return Err(IncidentValidationError::EmptyEvidenceRef);
            }
            if !unique.insert(value.clone()) {
                return Err(IncidentValidationError::DuplicateEvidenceRef(value));
            }
            refs.push(value);
        }
        if refs.len() > Self::MAX_LEN {
            return Err(IncidentValidationError::TooManyEvidenceRefs(refs.len()));
        }
        Ok(Self(refs))
    }

    pub fn as_slice(&self) -> &[String] {
        &self.0
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum IncidentValidationError {
    ConfidenceOutOfRange(i64),
    TooManyEvidenceRefs(usize),
    EmptyEvidenceRef,
    DuplicateEvidenceRef(String),
}

impl fmt::Display for IncidentValidationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ConfidenceOutOfRange(value) => {
                write!(
                    formatter,
                    "confidence micros {value} is outside 0..=1000000"
                )
            }
            Self::TooManyEvidenceRefs(count) => {
                write!(
                    formatter,
                    "incident has {count} evidence refs; maximum is 5"
                )
            }
            Self::EmptyEvidenceRef => {
                write!(
                    formatter,
                    "incident evidence refs must not contain empty strings"
                )
            }
            Self::DuplicateEvidenceRef(value) => {
                write!(
                    formatter,
                    "incident evidence refs must be unique; duplicated {value:?}"
                )
            }
        }
    }
}

impl std::error::Error for IncidentValidationError {}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IncidentRecoveryPolicyPin {
    pub registry_revision: u64,
    pub policy_digest: Digest,
}

/// A fresh observation. `expected_revision == 0` creates a new signature;
/// otherwise the existing signature must have the supplied revision.
#[derive(Clone, Debug, PartialEq)]
pub struct IncidentObservation {
    pub incident_id: IncidentId,
    pub run_id: Option<RunId>,
    pub severity: IncidentSeverity,
    pub confidence: ConfidenceMicros,
    pub deviation: String,
    pub failure_signature: String,
    pub expected_state: Value,
    pub observed_state: Value,
    pub affected_objects: Vec<String>,
    pub evidence_refs: EvidenceRefs,
    pub allowed_capabilities: Vec<CapabilityId>,
    pub attempt_ids: Vec<AttemptId>,
    pub recommended_next_action: String,
    pub escalation_target: String,
    pub observed_at: OffsetDateTime,
    pub last_useful_progress_at: Option<OffsetDateTime>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct IncidentCard {
    pub incident_id: IncidentId,
    pub run_id: Option<RunId>,
    pub severity: IncidentSeverity,
    pub confidence: ConfidenceMicros,
    pub deviation: String,
    pub failure_signature: String,
    pub expected_state: Value,
    pub observed_state: Value,
    pub affected_objects: Vec<String>,
    pub evidence_refs: EvidenceRefs,
    pub allowed_capabilities: Vec<CapabilityId>,
    pub attempt_ids: Vec<AttemptId>,
    pub recommended_next_action: String,
    pub escalation_target: String,
    pub first_observed_at: OffsetDateTime,
    pub last_observed_at: OffsetDateTime,
    pub last_useful_progress_at: Option<OffsetDateTime>,
    pub status: IncidentStatus,
    pub revision: i64,
}

#[derive(Clone, Debug, PartialEq)]
pub enum TransitionIncident {
    Transitioned(IncidentCard),
    NotFound,
    Illegal(IncidentCard),
}

#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct IncidentCardWire {
    pub schema_version: u16,
    pub incident_id: IncidentId,
    pub run_id: Option<RunId>,
    pub severity: IncidentSeverity,
    pub confidence_micros: i64,
    pub deviation: String,
    pub failure_signature: String,
    pub expected_state: Value,
    pub observed_state: Value,
    pub affected_objects: Vec<String>,
    pub evidence_refs: Vec<String>,
    pub allowed_capabilities: Vec<CapabilityId>,
    pub attempt_ids: Vec<AttemptId>,
    pub recommended_next_action: String,
    pub escalation_target: String,
    pub first_observed_at: String,
    pub last_observed_at: String,
    pub last_useful_progress_at: Option<String>,
    pub status: IncidentStatus,
    pub revision: i64,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct IncidentCardWireParts {
    schema_version: u16,
    incident_id: IncidentId,
    #[serde(deserialize_with = "crate::required_nullable")]
    run_id: Option<RunId>,
    severity: IncidentSeverity,
    confidence_micros: i64,
    deviation: String,
    failure_signature: String,
    expected_state: Value,
    observed_state: Value,
    affected_objects: Vec<String>,
    evidence_refs: Vec<String>,
    allowed_capabilities: Vec<CapabilityId>,
    attempt_ids: Vec<AttemptId>,
    recommended_next_action: String,
    escalation_target: String,
    first_observed_at: String,
    last_observed_at: String,
    #[serde(deserialize_with = "crate::required_nullable")]
    last_useful_progress_at: Option<String>,
    status: IncidentStatus,
    revision: i64,
}

impl<'de> Deserialize<'de> for IncidentCardWire {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let parts = IncidentCardWireParts::deserialize(deserializer)?;
        if parts.schema_version != INCIDENT_CARD_SCHEMA_VERSION {
            return Err(serde::de::Error::custom(format!(
                "unsupported incident card schema version {}",
                parts.schema_version
            )));
        }
        ConfidenceMicros::new(parts.confidence_micros)
            .map_err(|error| serde::de::Error::custom(error.to_string()))?;
        EvidenceRefs::new(parts.evidence_refs.iter().cloned())
            .map_err(|error| serde::de::Error::custom(error.to_string()))?;
        validate_incident_fields(
            &parts.deviation,
            &parts.failure_signature,
            &parts.recommended_next_action,
            &parts.escalation_target,
            &parts.affected_objects,
            parts.revision,
        )
        .map_err(serde::de::Error::custom)?;
        decode_utc(&parts.first_observed_at).map_err(serde::de::Error::custom)?;
        decode_utc(&parts.last_observed_at).map_err(serde::de::Error::custom)?;
        if let Some(progress) = parts.last_useful_progress_at.as_deref() {
            decode_utc(progress).map_err(serde::de::Error::custom)?;
        }
        Ok(Self {
            schema_version: parts.schema_version,
            incident_id: parts.incident_id,
            run_id: parts.run_id,
            severity: parts.severity,
            confidence_micros: parts.confidence_micros,
            deviation: parts.deviation,
            failure_signature: parts.failure_signature,
            expected_state: parts.expected_state,
            observed_state: parts.observed_state,
            affected_objects: parts.affected_objects,
            evidence_refs: parts.evidence_refs,
            allowed_capabilities: parts.allowed_capabilities,
            attempt_ids: parts.attempt_ids,
            recommended_next_action: parts.recommended_next_action,
            escalation_target: parts.escalation_target,
            first_observed_at: parts.first_observed_at,
            last_observed_at: parts.last_observed_at,
            last_useful_progress_at: parts.last_useful_progress_at,
            status: parts.status,
            revision: parts.revision,
        })
    }
}

impl TryFrom<&IncidentCard> for IncidentCardWire {
    type Error = LedgerError;

    fn try_from(card: &IncidentCard) -> LedgerResult<Self> {
        validate_incident_card(card)?;
        Ok(Self {
            schema_version: INCIDENT_CARD_SCHEMA_VERSION,
            incident_id: card.incident_id.clone(),
            run_id: card.run_id.clone(),
            severity: card.severity,
            confidence_micros: card.confidence.get(),
            deviation: card.deviation.clone(),
            failure_signature: card.failure_signature.clone(),
            expected_state: card.expected_state.clone(),
            observed_state: card.observed_state.clone(),
            affected_objects: card.affected_objects.clone(),
            evidence_refs: card.evidence_refs.as_slice().to_vec(),
            allowed_capabilities: card.allowed_capabilities.clone(),
            attempt_ids: card.attempt_ids.clone(),
            recommended_next_action: card.recommended_next_action.clone(),
            escalation_target: card.escalation_target.clone(),
            first_observed_at: encode_utc(card.first_observed_at)?,
            last_observed_at: encode_utc(card.last_observed_at)?,
            last_useful_progress_at: card.last_useful_progress_at.map(encode_utc).transpose()?,
            status: card.status,
            revision: card.revision,
        })
    }
}

impl IncidentCardWire {
    pub fn into_card(self) -> LedgerResult<IncidentCard> {
        if self.schema_version != INCIDENT_CARD_SCHEMA_VERSION {
            return Err(LedgerError::invalid_data(format!(
                "unsupported incident card schema version {}",
                self.schema_version
            )));
        }
        let confidence = ConfidenceMicros::new(self.confidence_micros).map_err(|error| {
            LedgerError::invalid_data_caused_by("invalid incident confidence", error)
        })?;
        let evidence_refs = EvidenceRefs::new(self.evidence_refs).map_err(|error| {
            LedgerError::invalid_data_caused_by("invalid incident evidence refs", error)
        })?;
        let card = IncidentCard {
            incident_id: self.incident_id,
            run_id: self.run_id,
            severity: self.severity,
            confidence,
            deviation: self.deviation,
            failure_signature: self.failure_signature,
            expected_state: self.expected_state,
            observed_state: self.observed_state,
            affected_objects: self.affected_objects,
            evidence_refs,
            allowed_capabilities: self.allowed_capabilities,
            attempt_ids: self.attempt_ids,
            recommended_next_action: self.recommended_next_action,
            escalation_target: self.escalation_target,
            first_observed_at: decode_utc(&self.first_observed_at)?,
            last_observed_at: decode_utc(&self.last_observed_at)?,
            last_useful_progress_at: self
                .last_useful_progress_at
                .as_deref()
                .map(decode_utc)
                .transpose()?,
            status: self.status,
            revision: self.revision,
        };
        validate_incident_card(&card)?;
        Ok(card)
    }
}

fn validate_incident_card(card: &IncidentCard) -> LedgerResult<()> {
    validate_incident_fields(
        &card.deviation,
        &card.failure_signature,
        &card.recommended_next_action,
        &card.escalation_target,
        &card.affected_objects,
        card.revision,
    )
}

/// Schema `id` pattern: `^[a-zA-Z0-9][a-zA-Z0-9._:-]{0,127}$`.
fn is_schema_id(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.is_empty() || bytes.len() > 128 {
        return false;
    }
    bytes[0].is_ascii_alphanumeric()
        && bytes[1..]
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-'))
}

fn validate_incident_fields(
    deviation: &str,
    failure_signature: &str,
    recommended_next_action: &str,
    escalation_target: &str,
    affected_objects: &[String],
    revision: i64,
) -> LedgerResult<()> {
    for (field, value) in [
        ("deviation", deviation),
        ("failure signature", failure_signature),
        ("recommended next action", recommended_next_action),
    ] {
        if value.trim().is_empty() {
            return Err(LedgerError::invalid_data(format!(
                "incident {field} must not be empty"
            )));
        }
    }
    if !is_schema_id(escalation_target) {
        return Err(LedgerError::invalid_data(
            "incident escalationTarget must be a schema id".into(),
        ));
    }
    if affected_objects.iter().any(|object| object.is_empty()) {
        return Err(LedgerError::invalid_data(
            "incident affected objects must not contain empty strings".into(),
        ));
    }
    if revision < 1 {
        return Err(LedgerError::invalid_data(
            "incident revision must be positive".into(),
        ));
    }
    Ok(())
}

impl Ledger {
    pub fn incident(&self, incident_id: &IncidentId) -> LedgerResult<Option<IncidentCard>> {
        load_incident_by_id(self.connection(), incident_id)
    }

    pub fn incident_by_signature(
        &self,
        failure_signature: &str,
    ) -> LedgerResult<Option<IncidentCard>> {
        load_incident_by_signature(self.connection(), failure_signature)
    }

    /// Inserts or refreshes the single durable card for a failure signature.
    ///
    /// Refreshes retain the original incident ID, first observation, and
    /// current status. Every successful refresh increments the revision.
    pub fn upsert_incident(
        &mut self,
        observation: IncidentObservation,
        expected_revision: i64,
    ) -> LedgerResult<IncidentCard> {
        validate_incident_fields(
            &observation.deviation,
            &observation.failure_signature,
            &observation.recommended_next_action,
            &observation.escalation_target,
            &observation.affected_objects,
            1,
        )?;
        self.with_tx(|transaction| {
            if let Some(current) =
                load_incident_by_signature(transaction, &observation.failure_signature)?
            {
                require_revision(&current, expected_revision)?;
                let last_observed_at = current.last_observed_at.max(observation.observed_at);
                let changed = transaction.execute(
                    "UPDATE incidents
                     SET run_id = ?1, severity = ?2, confidence_micros = ?3,
                         deviation = ?4, expected_state_json = ?5, observed_state_json = ?6,
                         affected_objects_json = ?7, evidence_refs_json = ?8,
                         allowed_capabilities_json = ?9, attempt_ids_json = ?10,
                         recommended_next_action = ?11, escalation_target = ?12,
                         last_observed_at = ?13, last_useful_progress_at = ?14,
                         revision = revision + 1
                     WHERE incident_id = ?15 AND revision = ?16",
                    params![
                        observation.run_id.as_ref().map(ToString::to_string),
                        observation.severity.as_str(),
                        observation.confidence.get(),
                        observation.deviation,
                        serde_json::to_string(&observation.expected_state)?,
                        serde_json::to_string(&observation.observed_state)?,
                        serde_json::to_string(&observation.affected_objects)?,
                        serde_json::to_string(observation.evidence_refs.as_slice())?,
                        serde_json::to_string(&observation.allowed_capabilities)?,
                        serde_json::to_string(&observation.attempt_ids)?,
                        observation.recommended_next_action,
                        observation.escalation_target,
                        encode_utc(last_observed_at)?,
                        observation
                            .last_useful_progress_at
                            .map(encode_utc)
                            .transpose()?,
                        current.incident_id.to_string(),
                        expected_revision,
                    ],
                )?;
                ensure_guarded_update(
                    transaction,
                    &current.incident_id,
                    expected_revision,
                    changed,
                )?;
                return load_existing_incident(transaction, &current.incident_id);
            }

            if expected_revision != 0 {
                return Err(LedgerError::StaleActor {
                    actor: format!("incident-signature:{}", observation.failure_signature),
                    expected_revision,
                    actual_revision: 0,
                });
            }
            transaction.execute(
                "INSERT INTO incidents (
                    incident_id, run_id, severity, confidence_micros, deviation,
                    failure_signature, expected_state_json, observed_state_json,
                    affected_objects_json, evidence_refs_json, allowed_capabilities_json,
                    attempt_ids_json, recommended_next_action, escalation_target,
                    first_observed_at, last_observed_at, last_useful_progress_at,
                    status, revision
                 ) VALUES (
                    ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13,
                    ?14, ?15, ?15, ?16, 'open', 1
                 )",
                params![
                    observation.incident_id.to_string(),
                    observation.run_id.as_ref().map(ToString::to_string),
                    observation.severity.as_str(),
                    observation.confidence.get(),
                    observation.deviation,
                    observation.failure_signature,
                    serde_json::to_string(&observation.expected_state)?,
                    serde_json::to_string(&observation.observed_state)?,
                    serde_json::to_string(&observation.affected_objects)?,
                    serde_json::to_string(observation.evidence_refs.as_slice())?,
                    serde_json::to_string(&observation.allowed_capabilities)?,
                    serde_json::to_string(&observation.attempt_ids)?,
                    observation.recommended_next_action,
                    observation.escalation_target,
                    encode_utc(observation.observed_at)?,
                    observation
                        .last_useful_progress_at
                        .map(encode_utc)
                        .transpose()?,
                ],
            )?;
            load_existing_incident(transaction, &observation.incident_id)
        })
    }

    pub fn transition_incident_status(
        &mut self,
        incident_id: &IncidentId,
        next: IncidentStatus,
        expected_revision: i64,
    ) -> LedgerResult<TransitionIncident> {
        self.with_tx(|transaction| {
            let Some(current) = load_incident_by_id(transaction, incident_id)? else {
                return Ok(TransitionIncident::NotFound);
            };
            require_revision(&current, expected_revision)?;
            if !current.status.can_transition_to(next) {
                return Ok(TransitionIncident::Illegal(current));
            }
            let changed = transaction.execute(
                "UPDATE incidents
                 SET status = ?1, revision = revision + 1
                 WHERE incident_id = ?2 AND revision = ?3 AND status = ?4",
                params![
                    next.as_str(),
                    incident_id.to_string(),
                    expected_revision,
                    current.status.as_str(),
                ],
            )?;
            ensure_guarded_update(transaction, incident_id, expected_revision, changed)?;
            Ok(TransitionIncident::Transitioned(load_existing_incident(
                transaction,
                incident_id,
            )?))
        })
    }

    /// Pins the resolved recovery policy once. Repeating the exact binding is
    /// idempotent; a changed policy for the same incident is rejected.
    pub fn pin_incident_recovery_policy(
        &mut self,
        incident_id: &IncidentId,
        pin: &IncidentRecoveryPolicyPin,
    ) -> LedgerResult<IncidentRecoveryPolicyPin> {
        if pin.registry_revision == 0 {
            return Err(LedgerError::invalid_data(
                "incident recovery policy revision must be positive".to_owned(),
            ));
        }
        self.with_tx(|transaction| {
            let changed = transaction.execute(
                "UPDATE incidents SET recovery_policy_revision=?1,recovery_policy_digest=?2
                 WHERE incident_id=?3 AND recovery_policy_revision=0",
                params![
                    i64::try_from(pin.registry_revision).map_err(|error| {
                        LedgerError::invalid_data_caused_by(
                            "incident recovery policy revision exceeds SQLite INTEGER",
                            error,
                        )
                    })?,
                    pin.policy_digest.to_string(),
                    incident_id.to_string(),
                ],
            )?;
            if changed == 0 {
                let existing =
                    incident_recovery_policy(transaction, incident_id)?.ok_or_else(|| {
                        LedgerError::NotFound {
                            kind: "incident",
                            id: incident_id.to_string(),
                        }
                    })?;
                if existing != *pin {
                    return Err(LedgerError::Conflict(format!(
                        "incident {incident_id} already pins recovery policy revision {} digest {}",
                        existing.registry_revision, existing.policy_digest
                    )));
                }
            }
            incident_recovery_policy(transaction, incident_id)?.ok_or_else(|| {
                LedgerError::invalid_data(
                    "incident recovery policy pin disappeared after update".to_owned(),
                )
            })
        })
    }

    pub fn incident_recovery_policy(
        &self,
        incident_id: &IncidentId,
    ) -> LedgerResult<Option<IncidentRecoveryPolicyPin>> {
        incident_recovery_policy(self.connection(), incident_id)
    }
}

fn incident_recovery_policy(
    connection: &Connection,
    incident_id: &IncidentId,
) -> LedgerResult<Option<IncidentRecoveryPolicyPin>> {
    let raw: Option<(i64, String)> = connection
        .query_row(
            "SELECT recovery_policy_revision,recovery_policy_digest
             FROM incidents WHERE incident_id=?1",
            [incident_id.to_string()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    raw.and_then(|(revision, digest)| (revision > 0).then_some((revision, digest)))
        .map(|(revision, digest)| {
            Ok(IncidentRecoveryPolicyPin {
                registry_revision: u64::try_from(revision).map_err(|error| {
                    LedgerError::invalid_data_caused_by(
                        "negative incident recovery policy revision",
                        error,
                    )
                })?,
                policy_digest: Digest::parse(&digest).map_err(|error| {
                    LedgerError::invalid_data_caused_by(
                        "invalid incident recovery policy digest",
                        error,
                    )
                })?,
            })
        })
        .transpose()
}

struct RawIncident {
    incident_id: String,
    run_id: Option<String>,
    severity: String,
    confidence_micros: i64,
    deviation: String,
    failure_signature: String,
    expected_state_json: String,
    observed_state_json: String,
    affected_objects_json: String,
    evidence_refs_json: String,
    allowed_capabilities_json: String,
    attempt_ids_json: String,
    recommended_next_action: String,
    escalation_target: String,
    first_observed_at: String,
    last_observed_at: String,
    last_useful_progress_at: Option<String>,
    status: String,
    revision: i64,
}

fn load_incident_by_id(
    connection: &Connection,
    incident_id: &IncidentId,
) -> LedgerResult<Option<IncidentCard>> {
    load_incident(connection, "incident_id", incident_id.as_str())
}

fn load_incident_by_signature(
    connection: &Connection,
    failure_signature: &str,
) -> LedgerResult<Option<IncidentCard>> {
    load_incident(connection, "failure_signature", failure_signature)
}

fn load_incident(
    connection: &Connection,
    column: &'static str,
    value: &str,
) -> LedgerResult<Option<IncidentCard>> {
    let sql = format!(
        "SELECT incident_id, run_id, severity, confidence_micros, deviation,
                failure_signature, expected_state_json, observed_state_json,
                affected_objects_json, evidence_refs_json, allowed_capabilities_json,
                attempt_ids_json, recommended_next_action, escalation_target,
                first_observed_at, last_observed_at, last_useful_progress_at,
                status, revision
         FROM incidents WHERE {column} = ?1"
    );
    let raw = connection
        .query_row(&sql, [value], |row| {
            Ok(RawIncident {
                incident_id: row.get(0)?,
                run_id: row.get(1)?,
                severity: row.get(2)?,
                confidence_micros: row.get(3)?,
                deviation: row.get(4)?,
                failure_signature: row.get(5)?,
                expected_state_json: row.get(6)?,
                observed_state_json: row.get(7)?,
                affected_objects_json: row.get(8)?,
                evidence_refs_json: row.get(9)?,
                allowed_capabilities_json: row.get(10)?,
                attempt_ids_json: row.get(11)?,
                recommended_next_action: row.get(12)?,
                escalation_target: row.get(13)?,
                first_observed_at: row.get(14)?,
                last_observed_at: row.get(15)?,
                last_useful_progress_at: row.get(16)?,
                status: row.get(17)?,
                revision: row.get(18)?,
            })
        })
        .optional()?;
    raw.map(IncidentCard::try_from).transpose()
}

fn load_existing_incident(
    connection: &Connection,
    incident_id: &IncidentId,
) -> LedgerResult<IncidentCard> {
    load_incident_by_id(connection, incident_id)?.ok_or_else(|| {
        LedgerError::invalid_data("incident vanished during guarded mutation".to_owned())
    })
}

impl TryFrom<RawIncident> for IncidentCard {
    type Error = LedgerError;

    fn try_from(raw: RawIncident) -> LedgerResult<Self> {
        let evidence: Vec<String> = serde_json::from_str(&raw.evidence_refs_json)?;
        let evidence_refs = EvidenceRefs::new(evidence).map_err(|error| {
            LedgerError::invalid_data_caused_by("invalid incident evidence refs", error)
        })?;
        let confidence = ConfidenceMicros::new(raw.confidence_micros).map_err(|error| {
            LedgerError::invalid_data_caused_by("invalid incident confidence", error)
        })?;
        let card = Self {
            incident_id: parse_id(&raw.incident_id, 0)?,
            run_id: raw
                .run_id
                .as_deref()
                .map(|value| parse_id(value, 1))
                .transpose()?,
            severity: IncidentSeverity::parse(&raw.severity)?,
            confidence,
            deviation: raw.deviation,
            failure_signature: raw.failure_signature,
            expected_state: serde_json::from_str(&raw.expected_state_json)?,
            observed_state: serde_json::from_str(&raw.observed_state_json)?,
            affected_objects: serde_json::from_str(&raw.affected_objects_json)?,
            evidence_refs,
            allowed_capabilities: serde_json::from_str(&raw.allowed_capabilities_json)?,
            attempt_ids: serde_json::from_str(&raw.attempt_ids_json)?,
            recommended_next_action: raw.recommended_next_action,
            escalation_target: raw.escalation_target,
            first_observed_at: decode_utc(&raw.first_observed_at)?,
            last_observed_at: decode_utc(&raw.last_observed_at)?,
            last_useful_progress_at: raw
                .last_useful_progress_at
                .as_deref()
                .map(decode_utc)
                .transpose()?,
            status: IncidentStatus::parse(&raw.status)?,
            revision: raw.revision,
        };
        validate_incident_card(&card)?;
        Ok(card)
    }
}

fn require_revision(incident: &IncidentCard, expected_revision: i64) -> LedgerResult<()> {
    if incident.revision == expected_revision {
        Ok(())
    } else {
        Err(LedgerError::StaleActor {
            actor: format!("incident:{}", incident.incident_id),
            expected_revision,
            actual_revision: incident.revision,
        })
    }
}

fn ensure_guarded_update(
    connection: &Connection,
    incident_id: &IncidentId,
    expected_revision: i64,
    changed: usize,
) -> LedgerResult<()> {
    if changed == 1 {
        return Ok(());
    }
    let current = load_existing_incident(connection, incident_id)?;
    Err(LedgerError::StaleActor {
        actor: format!("incident:{incident_id}"),
        expected_revision,
        actual_revision: current.revision,
    })
}

#[cfg(test)]
mod tests {
    use odin_domain::{CapabilityId, IncidentId};
    use serde_json::json;
    use time::{Duration, OffsetDateTime};

    use super::{
        ConfidenceMicros, EvidenceRefs, IncidentObservation, IncidentSeverity, IncidentStatus,
        TransitionIncident,
    };
    use crate::Ledger;

    fn now() -> OffsetDateTime {
        OffsetDateTime::from_unix_timestamp(1_800_000_000).unwrap()
    }

    fn observation(id: &str, observed_at: OffsetDateTime) -> IncidentObservation {
        IncidentObservation {
            incident_id: IncidentId::new(id).unwrap(),
            run_id: None,
            severity: IncidentSeverity::Error,
            confidence: ConfidenceMicros::new(850_000).unwrap(),
            deviation: "worker stopped making useful progress".to_owned(),
            failure_signature: "stalled:tool-loop:v1".to_owned(),
            expected_state: json!({"progress": true}),
            observed_state: json!({"heartbeats": true, "progress": false}),
            affected_objects: vec!["lane:one".to_owned()],
            evidence_refs: EvidenceRefs::new(vec!["event:one".to_owned(), "event:two".to_owned()])
                .unwrap(),
            allowed_capabilities: vec![CapabilityId::new("cap:restart").unwrap()],
            attempt_ids: Vec::new(),
            recommended_next_action: "restart once".to_owned(),
            escalation_target: "seat:kubert".to_owned(),
            observed_at,
            last_useful_progress_at: Some(observed_at - Duration::minutes(5)),
        }
    }

    #[test]
    fn evidence_rejects_duplicates_empties_and_is_bounded() {
        assert!(EvidenceRefs::new(vec!["one".to_owned(), "one".to_owned()]).is_err());
        assert!(EvidenceRefs::new(vec!["one".to_owned(), String::new()]).is_err());
        assert!(EvidenceRefs::new((0..6).map(|index| format!("event:{index}"))).is_err());
        assert!(ConfidenceMicros::new(-1).is_err());
        assert!(ConfidenceMicros::new(1_000_001).is_err());
    }

    #[test]
    fn signature_dedup_retains_first_observation_and_increments_revision() {
        let mut ledger = Ledger::open_in_memory().unwrap();
        let first_at = now();
        let first = ledger
            .upsert_incident(observation("incident:first", first_at), 0)
            .unwrap();
        assert_eq!(first.revision, 1);

        let second = ledger
            .upsert_incident(
                observation("incident:duplicate", first_at + Duration::minutes(1)),
                1,
            )
            .unwrap();
        assert_eq!(second.incident_id, first.incident_id);
        assert_eq!(second.first_observed_at, first_at);
        assert_eq!(second.last_observed_at, first_at + Duration::minutes(1));
        assert_eq!(second.revision, 2);
        let count: i64 = ledger
            .connection()
            .query_row(
                "SELECT COUNT(*) FROM incidents WHERE failure_signature = ?1",
                ["stalled:tool-loop:v1"],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count, 1);

        let transitioned = ledger
            .transition_incident_status(&second.incident_id, IncidentStatus::Recovering, 2)
            .unwrap();
        let TransitionIncident::Transitioned(transitioned) = transitioned else {
            panic!("legal incident transition was rejected");
        };
        assert_eq!(transitioned.revision, 3);
        assert_eq!(transitioned.first_observed_at, first_at);
    }
}
