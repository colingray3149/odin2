//! Typed timestamps enforce RFC 3339; publication and health decisions remain in the kernel.

use serde::{Deserialize, Serialize};
use serde_json::json;
use time::OffsetDateTime;

use crate::ids::{AdapterTaint, AdapterWireId, WireAdapterIdentity};
use crate::{validate_canonical, AdapterError, ADAPTER_STATUS_SCHEMA_NAME};

pub const ADAPTER_STATUS_SCHEMA_JSON: &str =
    include_str!("../../../schemas/control/adapter-status.schema.json");

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AdapterHealthState {
    Starting,
    Ready,
    Degraded,
    Unavailable,
    Recovering,
    Stopped,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub struct StatusFailure {
    pub code: AdapterWireId,
    pub retryable: bool,
    pub operation_id: Option<AdapterWireId>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case", try_from = "StatusRaw")]
pub struct AdapterStatusSnapshot {
    adapter: WireAdapterIdentity,
    revision: u64,
    health: AdapterHealthState,
    taint: AdapterTaint,
    active_operations: u64,
    #[serde(with = "time::serde::rfc3339")]
    observed_at: OffsetDateTime,
    last_failure: Option<StatusFailure>,
    evidence_refs: Vec<AdapterWireId>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
struct StatusRaw {
    schema: String,
    adapter: WireAdapterIdentity,
    revision: u64,
    health: AdapterHealthState,
    taint: AdapterTaint,
    active_operations: u64,
    #[serde(with = "time::serde::rfc3339")]
    observed_at: OffsetDateTime,
    last_failure: Option<StatusFailure>,
    evidence_refs: Vec<AdapterWireId>,
}

impl TryFrom<StatusRaw> for AdapterStatusSnapshot {
    type Error = AdapterError;

    fn try_from(raw: StatusRaw) -> Result<Self, Self::Error> {
        if raw.schema != ADAPTER_STATUS_SCHEMA_NAME {
            return Err(AdapterError::Semantic {
                detail: format!(
                    "status schema must be {ADAPTER_STATUS_SCHEMA_NAME}, found {:?}",
                    raw.schema
                ),
            });
        }
        if raw.revision == 0 {
            return Err(AdapterError::Semantic {
                detail: "status revision must be at least 1".to_owned(),
            });
        }
        Ok(Self {
            adapter: raw.adapter,
            revision: raw.revision,
            health: raw.health,
            taint: raw.taint,
            active_operations: raw.active_operations,
            observed_at: raw.observed_at,
            last_failure: raw.last_failure,
            evidence_refs: raw.evidence_refs,
        })
    }
}

impl AdapterStatusSnapshot {
    /// The typed timestamp parser enforces the schema's `date-time` format.
    pub fn from_wire(wire: &serde_json::Value) -> Result<Self, AdapterError> {
        validate_canonical(ADAPTER_STATUS_SCHEMA_NAME, ADAPTER_STATUS_SCHEMA_JSON, wire)?;
        serde::Deserialize::deserialize(wire).map_err(|error| AdapterError::Grammar {
            field: "status snapshot",
            detail: error.to_string(),
        })
    }

    pub fn to_wire(&self) -> serde_json::Value {
        let mut wire =
            serde_json::to_value(self).expect("validated status snapshots serialize infallibly");
        wire["schema"] = json!(ADAPTER_STATUS_SCHEMA_NAME);
        wire
    }

    pub fn adapter(&self) -> &WireAdapterIdentity {
        &self.adapter
    }

    pub fn revision(&self) -> u64 {
        self.revision
    }

    pub fn health(&self) -> AdapterHealthState {
        self.health
    }

    pub fn taint(&self) -> AdapterTaint {
        self.taint
    }

    pub fn observed_at(&self) -> OffsetDateTime {
        self.observed_at
    }

    pub fn last_failure(&self) -> Option<&StatusFailure> {
        self.last_failure.as_ref()
    }

    pub fn evidence_refs(&self) -> &[AdapterWireId] {
        &self.evidence_refs
    }
}
