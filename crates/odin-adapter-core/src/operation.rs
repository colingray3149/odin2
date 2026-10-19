//! `dispatched` and `cancelled` are transport observations with no durable `EffectState` equivalent.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

pub use odin_domain::{Digest, EffectClass, EffectState};

use crate::ids::{
    AdapterTaint, AdapterWireId, OpaqueCredentialHandle, OperationKind, SchemaRef,
    WireAdapterIdentity,
};
use crate::{validate_canonical, AdapterError, ADAPTER_OPERATION_SCHEMA_NAME};

pub const ADAPTER_OPERATION_SCHEMA_JSON: &str =
    include_str!("../../../schemas/control/adapter-operation.schema.json");

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperationRecordState {
    Prepared,
    Dispatched,
    EffectStarted,
    Succeeded,
    Failed,
    Cancelled,
    InDoubt,
}

impl OperationRecordState {
    pub const fn to_effect_state(self) -> Option<EffectState> {
        match self {
            Self::Prepared => Some(EffectState::Prepared),
            Self::EffectStarted => Some(EffectState::EffectStarted),
            Self::Succeeded => Some(EffectState::Committed),
            Self::Failed => Some(EffectState::Aborted),
            Self::InDoubt => Some(EffectState::InDoubt),
            Self::Dispatched | Self::Cancelled => None,
        }
    }
}

/// The schemas' `idempotency_key`: 1..=256 Unicode scalar values.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct IdempotencyKey(String);

impl IdempotencyKey {
    pub fn new(value: impl Into<String>) -> Result<Self, AdapterError> {
        let value = value.into();
        let length = value.chars().count();
        if !(1..=256).contains(&length) {
            return Err(AdapterError::Grammar {
                field: "IdempotencyKey",
                detail: "must contain between 1 and 256 characters".to_owned(),
            });
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for IdempotencyKey {
    type Error = AdapterError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl std::fmt::Display for IdempotencyKey {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl Serialize for IdempotencyKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for IdempotencyKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(serde::de::Error::custom)
    }
}

/// Hand-built records need [`Self::validate`] before persistence to check cross-field constraints.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub struct AdapterOperationRecord {
    /// Validation re-checks this discriminator for hand-built records.
    pub schema: String,
    pub operation_id: AdapterWireId,
    pub adapter: WireAdapterIdentity,
    pub kind: OperationKind,
    pub effect_class: EffectClass,
    pub input_schema: SchemaRef,
    pub input_digest: Digest,
    pub credential_handles: Vec<OpaqueCredentialHandle>,
    pub idempotency_key: IdempotencyKey,
    pub taint: AdapterTaint,
    pub state: OperationRecordState,
    pub output_schema: SchemaRef,
    pub output_digest: Option<Digest>,
    pub evidence_refs: Vec<AdapterWireId>,
}

impl AdapterOperationRecord {
    /// Typed checks report precise uniqueness errors beyond the schema's `uniqueItems` check.
    pub fn from_wire(wire: &serde_json::Value) -> Result<Self, AdapterError> {
        validate_canonical(
            ADAPTER_OPERATION_SCHEMA_NAME,
            ADAPTER_OPERATION_SCHEMA_JSON,
            wire,
        )?;
        let record: Self =
            serde::Deserialize::deserialize(wire).map_err(|error| AdapterError::Grammar {
                field: "operation record",
                detail: error.to_string(),
            })?;
        record.check_semantics()?;
        Ok(record)
    }

    pub fn validate(&self) -> Result<(), AdapterError> {
        validate_canonical(
            ADAPTER_OPERATION_SCHEMA_NAME,
            ADAPTER_OPERATION_SCHEMA_JSON,
            &self.to_wire(),
        )?;
        self.check_semantics()
    }

    fn check_semantics(&self) -> Result<(), AdapterError> {
        if self.schema != ADAPTER_OPERATION_SCHEMA_NAME {
            return Err(AdapterError::Semantic {
                detail: format!(
                    "operation record schema must be {ADAPTER_OPERATION_SCHEMA_NAME}, found {:?}",
                    self.schema
                ),
            });
        }
        let mut refs = BTreeSet::new();
        for reference in &self.evidence_refs {
            if !refs.insert(reference.as_str()) {
                return Err(AdapterError::Semantic {
                    detail: format!(
                        "operation record repeats evidence ref {:?}",
                        reference.as_str()
                    ),
                });
            }
        }
        let mut handles = BTreeSet::new();
        for handle in &self.credential_handles {
            if !handles.insert(handle.as_str()) {
                return Err(AdapterError::Semantic {
                    detail: "operation record repeats a credential handle".to_owned(),
                });
            }
        }
        Ok(())
    }

    pub fn to_wire(&self) -> serde_json::Value {
        serde_json::to_value(self).expect("typed operation record serializes")
    }
}
