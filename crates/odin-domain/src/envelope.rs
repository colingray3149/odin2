//! Stable event and command envelopes shared by every transport.

use std::collections::BTreeSet;

use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;

use crate::{
    AttemptId, CapabilityId, CommandId, Digest, DomainError, EventId, HostId, LaneId, NodeId,
    ProjectId, RunId, Scope, SeatId, SessionId,
};

pub const EVENT_SCHEMA: &str = "odin.event.v1";
pub const COMMAND_SCHEMA: &str = "odin.command.v1";

const MAX_METADATA_LEN: usize = 256;
const MAX_CAPABILITY_VERSION: u64 = u16::MAX as u64;

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct Correlation {
    pub idempotency_key: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CorrelationWire {
    idempotency_key: String,
}

impl<'de> Deserialize<'de> for Correlation {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = CorrelationWire::deserialize(deserializer)?;
        let correlation = Self {
            idempotency_key: wire.idempotency_key,
        };
        correlation.validate().map_err(serde::de::Error::custom)?;
        Ok(correlation)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum Actor {
    Seat {
        seat: SeatId,
        #[serde(skip_serializing_if = "Option::is_none")]
        session: Option<SessionId>,
    },
    Node {
        node: NodeId,
    },
    System {
        name: String,
    },
}

impl<'de> Deserialize<'de> for Actor {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = Value::deserialize(deserializer)?;
        let object = value
            .as_object()
            .ok_or_else(|| serde::de::Error::custom("actor must be an object"))?;
        let kind = object
            .get("kind")
            .and_then(|kind| kind.as_str())
            .ok_or_else(|| serde::de::Error::custom("actor kind is missing"))?;
        let unknown_field = |allowed: &[&str]| {
            object
                .keys()
                .find(|key| *key != "kind" && !allowed.contains(&key.as_str()))
                .cloned()
        };
        let actor = match kind {
            "seat" => {
                if let Some(key) = unknown_field(&["seat", "session"]) {
                    return Err(serde::de::Error::custom(format!(
                        "unknown seat actor field {key:?}"
                    )));
                }
                let seat = object
                    .get("seat")
                    .cloned()
                    .ok_or_else(|| serde::de::Error::custom("seat actor requires a seat"))?;
                let session = match object.get("session") {
                    None => None,
                    Some(Value::Null) => {
                        return Err(serde::de::Error::custom(
                            "seat actor session must be omitted rather than null",
                        ));
                    }
                    Some(session) => Some(
                        serde_json::from_value::<SessionId>(session.clone())
                            .map_err(serde::de::Error::custom)?,
                    ),
                };
                Self::Seat {
                    seat: serde_json::from_value(seat).map_err(serde::de::Error::custom)?,
                    session,
                }
            }
            "node" => {
                if let Some(key) = unknown_field(&["node"]) {
                    return Err(serde::de::Error::custom(format!(
                        "unknown node actor field {key:?}"
                    )));
                }
                let node = object
                    .get("node")
                    .cloned()
                    .ok_or_else(|| serde::de::Error::custom("node actor requires a node"))?;
                Self::Node {
                    node: serde_json::from_value(node).map_err(serde::de::Error::custom)?,
                }
            }
            "system" => {
                if let Some(key) = unknown_field(&["name"]) {
                    return Err(serde::de::Error::custom(format!(
                        "unknown system actor field {key:?}"
                    )));
                }
                let name = object
                    .get("name")
                    .cloned()
                    .ok_or_else(|| serde::de::Error::custom("system actor requires a name"))?;
                Self::System {
                    name: serde_json::from_value(name).map_err(serde::de::Error::custom)?,
                }
            }
            other => {
                return Err(serde::de::Error::custom(format!(
                    "unknown actor kind {other:?}"
                )))
            }
        };
        actor.validate().map_err(serde::de::Error::custom)?;
        Ok(actor)
    }
}

impl Correlation {
    pub fn new(idempotency_key: impl Into<String>) -> Result<Self, DomainError> {
        let correlation = Self {
            idempotency_key: idempotency_key.into(),
        };
        correlation.validate()?;
        Ok(correlation)
    }

    pub fn validate(&self) -> Result<(), DomainError> {
        validate_metadata("correlation idempotency key", &self.idempotency_key)
    }
}

impl Actor {
    pub fn system(name: impl Into<String>) -> Result<Self, DomainError> {
        let actor = Self::System { name: name.into() };
        actor.validate()?;
        Ok(actor)
    }

    pub fn validate(&self) -> Result<(), DomainError> {
        match self {
            Self::System { name } => validate_metadata("system actor name", name),
            Self::Seat { .. } | Self::Node { .. } => Ok(()),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum Redaction {
    None,
    Payload,
    Fields { json_pointers: BTreeSet<String> },
}

impl<'de> Deserialize<'de> for Redaction {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = Value::deserialize(deserializer)?;
        let object = value
            .as_object()
            .ok_or_else(|| serde::de::Error::custom("redaction must be an object"))?;
        let kind = object
            .get("kind")
            .and_then(|kind| kind.as_str())
            .ok_or_else(|| serde::de::Error::custom("redaction kind is missing"))?;
        let unknown_field = |allowed: &[&str]| {
            object
                .keys()
                .find(|key| *key != "kind" && !allowed.contains(&key.as_str()))
                .cloned()
        };
        let redaction = match kind {
            "none" => {
                if let Some(key) = unknown_field(&[]) {
                    return Err(serde::de::Error::custom(format!(
                        "unknown none redaction field {key:?}"
                    )));
                }
                Self::None
            }
            "payload" => {
                if let Some(key) = unknown_field(&[]) {
                    return Err(serde::de::Error::custom(format!(
                        "unknown payload redaction field {key:?}"
                    )));
                }
                Self::Payload
            }
            "fields" => {
                if let Some(key) = unknown_field(&["json_pointers"]) {
                    return Err(serde::de::Error::custom(format!(
                        "unknown fields redaction field {key:?}"
                    )));
                }
                let json_pointers = object.get("json_pointers").cloned().ok_or_else(|| {
                    serde::de::Error::custom("fields redaction requires json_pointers")
                })?;
                let pointers: Vec<String> =
                    serde_json::from_value(json_pointers).map_err(serde::de::Error::custom)?;
                let mut unique = BTreeSet::new();
                for pointer in pointers {
                    if !unique.insert(pointer.clone()) {
                        return Err(serde::de::Error::custom(format!(
                            "duplicate redaction JSON pointer {pointer:?}"
                        )));
                    }
                }
                Self::Fields {
                    json_pointers: unique,
                }
            }
            other => {
                return Err(serde::de::Error::custom(format!(
                    "unknown redaction kind {other:?}"
                )))
            }
        };
        redaction.validate().map_err(serde::de::Error::custom)?;
        Ok(redaction)
    }
}
impl Redaction {
    pub fn fields(json_pointers: impl IntoIterator<Item = String>) -> Result<Self, DomainError> {
        let pointers: Vec<String> = json_pointers.into_iter().collect();
        let mut unique = BTreeSet::new();
        for pointer in &pointers {
            if !unique.insert(pointer.clone()) {
                return invalid(format!("duplicate redaction JSON pointer {pointer:?}"));
            }
        }
        let redaction = Self::Fields {
            json_pointers: unique,
        };
        redaction.validate()?;
        Ok(redaction)
    }

    pub fn validate(&self) -> Result<(), DomainError> {
        let Self::Fields { json_pointers } = self else {
            return Ok(());
        };
        if json_pointers.is_empty() {
            return invalid("field redaction must contain at least one JSON pointer");
        }
        if let Some(pointer) = json_pointers
            .iter()
            .find(|pointer| !pointer.starts_with('/'))
        {
            return invalid(format!(
                "redaction path {pointer:?} is not an absolute JSON pointer"
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct Producer {
    pub component: String,
    pub version: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub node: Option<NodeId>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProducerWire {
    component: String,
    version: String,
    #[serde(default, deserialize_with = "reject_explicit_null")]
    node: Option<NodeId>,
}

impl<'de> Deserialize<'de> for Producer {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = ProducerWire::deserialize(deserializer)?;
        let producer = Self {
            component: wire.component,
            version: wire.version,
            node: wire.node,
        };
        producer.validate().map_err(serde::de::Error::custom)?;
        Ok(producer)
    }
}

impl Producer {
    pub fn new(
        component: impl Into<String>,
        version: impl Into<String>,
        node: Option<NodeId>,
    ) -> Result<Self, DomainError> {
        let producer = Self {
            component: component.into(),
            version: version.into(),
            node,
        };
        producer.validate()?;
        Ok(producer)
    }

    pub fn validate(&self) -> Result<(), DomainError> {
        validate_metadata("producer component", &self.component)?;
        validate_metadata("producer version", &self.version)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    content = "id",
    rename_all = "camelCase",
    deny_unknown_fields
)]
pub enum CommandTarget {
    Seat(SeatId),
    Project(ProjectId),
    Lane(LaneId),
    Run(RunId),
    Attempt(AttemptId),
    Session(SessionId),
    Node(NodeId),
    Host(HostId),
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct CommandCapability {
    pub id: CapabilityId,
    pub version: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CommandCapabilityWire {
    id: CapabilityId,
    version: u64,
}

impl<'de> Deserialize<'de> for CommandCapability {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = CommandCapabilityWire::deserialize(deserializer)?;
        let capability = Self {
            id: wire.id,
            version: wire.version,
        };
        capability.validate().map_err(serde::de::Error::custom)?;
        Ok(capability)
    }
}

impl CommandCapability {
    pub fn new(id: CapabilityId, version: u64) -> Result<Self, DomainError> {
        let capability = Self { id, version };
        capability.validate()?;
        Ok(capability)
    }

    pub fn validate(&self) -> Result<(), DomainError> {
        validate_capability_id(&self.id)?;
        if !(1..=MAX_CAPABILITY_VERSION).contains(&self.version) {
            return invalid(format!(
                "capability version must be in 1..={MAX_CAPABILITY_VERSION}"
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct EventEnvelope {
    pub schema: String,
    pub id: EventId,
    pub sequence: u64,
    pub revision: u64,
    pub occurred_at_ms: u64,
    pub kind: String,
    pub actor: Actor,
    pub scope: Scope,
    pub correlation: Correlation,
    pub payload: Value,
    pub redaction: Redaction,
    pub producer: Producer,
}

/// Requires a JSON key to be present while accepting an explicit `null`.
fn required_nullable<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(deserializer)
}

/// Allows a missing key (`None`) but rejects an explicit JSON `null`.
fn reject_explicit_null<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    match Option::<T>::deserialize(deserializer)? {
        None => Err(serde::de::Error::custom(
            "optional field must be omitted rather than null",
        )),
        Some(value) => Ok(Some(value)),
    }
}

/// Strict wire form of [`Scope`]: the shared scope type sits outside this file
/// and its own deserialization cannot reject unknown keys.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ScopeWire {
    #[serde(deserialize_with = "required_nullable")]
    seat: Option<SeatId>,
    #[serde(deserialize_with = "required_nullable")]
    project: Option<ProjectId>,
    #[serde(deserialize_with = "required_nullable")]
    lane: Option<LaneId>,
    #[serde(deserialize_with = "required_nullable")]
    run: Option<RunId>,
    #[serde(deserialize_with = "required_nullable")]
    attempt: Option<AttemptId>,
    #[serde(deserialize_with = "required_nullable")]
    session: Option<SessionId>,
    #[serde(deserialize_with = "required_nullable")]
    node: Option<NodeId>,
}

impl From<ScopeWire> for Scope {
    fn from(wire: ScopeWire) -> Self {
        Self {
            seat: wire.seat,
            project: wire.project,
            lane: wire.lane,
            run: wire.run,
            attempt: wire.attempt,
            session: wire.session,
            node: wire.node,
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EventEnvelopeWire {
    schema: String,
    id: EventId,
    sequence: u64,
    revision: u64,
    occurred_at_ms: u64,
    kind: String,
    actor: Actor,
    scope: ScopeWire,
    correlation: Correlation,
    payload: Value,
    redaction: Redaction,
    producer: Producer,
}

impl<'de> Deserialize<'de> for EventEnvelope {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = EventEnvelopeWire::deserialize(deserializer)?;
        let envelope = Self {
            schema: wire.schema,
            id: wire.id,
            sequence: wire.sequence,
            revision: wire.revision,
            occurred_at_ms: wire.occurred_at_ms,
            kind: wire.kind,
            actor: wire.actor,
            scope: wire.scope.into(),
            correlation: wire.correlation,
            payload: wire.payload,
            redaction: wire.redaction,
            producer: wire.producer,
        };
        envelope.validate().map_err(serde::de::Error::custom)?;
        Ok(envelope)
    }
}

#[derive(Clone, Debug)]
pub struct EventEnvelopeInit {
    pub id: EventId,
    pub sequence: u64,
    pub revision: u64,
    pub occurred_at_ms: u64,
    pub kind: String,
    pub actor: Actor,
    pub scope: Scope,
    pub correlation: Correlation,
    pub payload: Value,
    pub redaction: Redaction,
    pub producer: Producer,
}

impl EventEnvelope {
    pub fn new(init: EventEnvelopeInit) -> Result<Self, DomainError> {
        let envelope = Self {
            schema: EVENT_SCHEMA.to_owned(),
            id: init.id,
            sequence: init.sequence,
            revision: init.revision,
            occurred_at_ms: init.occurred_at_ms,
            kind: init.kind,
            actor: init.actor,
            scope: init.scope,
            correlation: init.correlation,
            payload: init.payload,
            redaction: init.redaction,
            producer: init.producer,
        };
        envelope.validate()?;
        Ok(envelope)
    }

    pub fn validate(&self) -> Result<(), DomainError> {
        if self.schema != EVENT_SCHEMA {
            return invalid(format!("unsupported event schema {:?}", self.schema));
        }
        if self.sequence == 0 {
            return invalid("event sequence must start at one");
        }
        validate_kind("event", &self.kind)?;
        self.actor.validate()?;
        self.correlation.validate()?;
        self.redaction.validate()?;
        self.producer.validate()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct CommandEnvelope {
    pub schema: String,
    pub id: CommandId,
    pub sequence: u64,
    pub issued_at_ms: u64,
    pub expires_at_ms: u64,
    pub kind: String,
    pub actor: Actor,
    pub scope: Scope,
    pub correlation: Correlation,
    pub payload: Value,
    pub redaction: Redaction,
    pub producer: Producer,
    pub target: CommandTarget,
    pub capability: CommandCapability,
    pub args_hash: Digest,
    pub expected_revision: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CommandEnvelopeWire {
    schema: String,
    id: CommandId,
    sequence: u64,
    issued_at_ms: u64,
    expires_at_ms: u64,
    kind: String,
    actor: Actor,
    scope: ScopeWire,
    correlation: Correlation,
    payload: Value,
    redaction: Redaction,
    producer: Producer,
    target: CommandTarget,
    capability: CommandCapability,
    args_hash: Digest,
    expected_revision: u64,
}

impl<'de> Deserialize<'de> for CommandEnvelope {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = CommandEnvelopeWire::deserialize(deserializer)?;
        let envelope = Self {
            schema: wire.schema,
            id: wire.id,
            sequence: wire.sequence,
            issued_at_ms: wire.issued_at_ms,
            expires_at_ms: wire.expires_at_ms,
            kind: wire.kind,
            actor: wire.actor,
            scope: wire.scope.into(),
            correlation: wire.correlation,
            payload: wire.payload,
            redaction: wire.redaction,
            producer: wire.producer,
            target: wire.target,
            capability: wire.capability,
            args_hash: wire.args_hash,
            expected_revision: wire.expected_revision,
        };
        envelope.validate().map_err(serde::de::Error::custom)?;
        Ok(envelope)
    }
}

#[derive(Clone, Debug)]
pub struct CommandEnvelopeInit {
    pub id: CommandId,
    pub sequence: u64,
    pub issued_at_ms: u64,
    pub expires_at_ms: u64,
    pub kind: String,
    pub actor: Actor,
    pub scope: Scope,
    pub correlation: Correlation,
    pub payload: Value,
    pub redaction: Redaction,
    pub producer: Producer,
    pub target: CommandTarget,
    pub capability: CommandCapability,
    pub args_hash: Digest,
    pub expected_revision: u64,
}

impl CommandEnvelope {
    pub fn new(init: CommandEnvelopeInit) -> Result<Self, DomainError> {
        let envelope = Self {
            schema: COMMAND_SCHEMA.to_owned(),
            id: init.id,
            sequence: init.sequence,
            issued_at_ms: init.issued_at_ms,
            expires_at_ms: init.expires_at_ms,
            kind: init.kind,
            actor: init.actor,
            scope: init.scope,
            correlation: init.correlation,
            payload: init.payload,
            redaction: init.redaction,
            producer: init.producer,
            target: init.target,
            capability: init.capability,
            args_hash: init.args_hash,
            expected_revision: init.expected_revision,
        };
        envelope.validate()?;
        Ok(envelope)
    }

    /// Checks the self-contained envelope invariants without consulting a clock or ledger.
    pub fn validate(&self) -> Result<(), DomainError> {
        if self.schema != COMMAND_SCHEMA {
            return invalid(format!("unsupported command schema {:?}", self.schema));
        }
        if self.sequence == 0 {
            return invalid("command sequence must start at one");
        }
        if self.expires_at_ms <= self.issued_at_ms {
            return invalid("command expiry must be later than its issue time");
        }
        validate_kind("command", &self.kind)?;
        self.actor.validate()?;
        self.correlation.validate()?;
        self.redaction.validate()?;
        self.producer.validate()?;
        self.capability.validate()
    }

    /// Rejects stale or expired work before a transport dispatches it.
    pub fn validate_at(&self, now_ms: u64, current_revision: u64) -> Result<(), DomainError> {
        self.validate()?;
        if now_ms >= self.expires_at_ms {
            return invalid(format!(
                "command expired at {} (current time {now_ms})",
                self.expires_at_ms
            ));
        }
        if self.expected_revision != current_revision {
            return invalid(format!(
                "command expected revision {}, current revision is {current_revision}",
                self.expected_revision
            ));
        }
        Ok(())
    }
}

fn validate_metadata(field: &str, value: &str) -> Result<(), DomainError> {
    if value.is_empty() {
        return invalid(format!("{field} must not be empty"));
    }
    if value.len() > MAX_METADATA_LEN {
        return invalid(format!("{field} exceeds the {MAX_METADATA_LEN}-byte limit"));
    }
    Ok(())
}

/// Validates the canonical lowercase dotted taxonomy, e.g. `odin.lane.ready`.
fn validate_kind(field: &str, kind: &str) -> Result<(), DomainError> {
    let segment_valid = |segment: &str| {
        !segment.is_empty()
            && segment
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '-')
    };
    let mut segments = kind.split('.');
    let head = segments.next().unwrap_or_default();
    let mut head_chars = head.chars();
    let head_valid = match head_chars.next() {
        Some(first) if first.is_ascii_lowercase() => {
            head_chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '-')
        }
        _ => false,
    };
    let mut saw_tail = false;
    let mut tail_valid = true;
    for segment in segments {
        saw_tail = true;
        tail_valid &= segment_valid(segment);
    }
    if !head_valid || !saw_tail || !tail_valid {
        return invalid(format!(
            "{field} kind must be lowercase dot-separated segments such as \"odin.lane.ready\""
        ));
    }
    Ok(())
}

/// Validates the canonical lowercase dotted capability ID taxonomy, e.g. `lane.start`.
fn validate_capability_id(id: &CapabilityId) -> Result<(), DomainError> {
    validate_kind("capability", id.as_str())
}

fn invalid<T>(message: impl Into<String>) -> Result<T, DomainError> {
    Err(DomainError::InvalidEnvelope(message.into()))
}

#[cfg(test)]
mod tests;
