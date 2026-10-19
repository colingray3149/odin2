//! Semantic checks cover operation uniqueness and taint rules that JSON Schema cannot express.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use serde_json::json;

pub use odin_domain::EffectClass;
pub use odin_kernel::IdempotencyPolicy;

use crate::ids::{
    AdapterTaint, AdapterWireId, OpaqueCredentialHandle, OperationKind, SchemaRef,
    WireAdapterIdentity,
};
use crate::{validate_canonical, AdapterError, ADAPTER_DESCRIPTOR_SCHEMA_NAME};

pub const ADAPTER_DESCRIPTOR_SCHEMA_JSON: &str =
    include_str!("../../../schemas/control/adapter-descriptor.schema.json");

pub const ADAPTER_PROTOCOL_VERSION: u16 = 1;

#[derive(Clone, Debug, Eq, PartialEq, Deserialize)]
#[serde(try_from = "DescriptorRaw")]
pub struct AdapterDescriptor {
    adapter: WireAdapterIdentity,
    operations: Vec<OperationContract>,
    credential_handles: Vec<OpaqueCredentialHandle>,
    initial_taint: AdapterTaint,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
struct DescriptorRaw {
    schema: String,
    adapter: WireAdapterIdentity,
    protocol_version: u16,
    operations: Vec<OperationContract>,
    credential_handles: Vec<OpaqueCredentialHandle>,
    initial_taint: AdapterTaint,
}

impl TryFrom<DescriptorRaw> for AdapterDescriptor {
    type Error = AdapterError;

    fn try_from(raw: DescriptorRaw) -> Result<Self, Self::Error> {
        if raw.schema != ADAPTER_DESCRIPTOR_SCHEMA_NAME {
            return Err(AdapterError::Semantic {
                detail: format!(
                    "descriptor schema must be {ADAPTER_DESCRIPTOR_SCHEMA_NAME}, found {:?}",
                    raw.schema
                ),
            });
        }
        if raw.protocol_version != ADAPTER_PROTOCOL_VERSION {
            return Err(AdapterError::Semantic {
                detail: format!(
                    "descriptor protocol_version must be {ADAPTER_PROTOCOL_VERSION}, found {}",
                    raw.protocol_version
                ),
            });
        }
        let mut kinds = BTreeSet::new();
        for operation in &raw.operations {
            if !kinds.insert(operation.kind.as_str()) {
                return Err(AdapterError::Semantic {
                    detail: format!(
                        "descriptor declares duplicate operation kind {:?}",
                        operation.kind.as_str()
                    ),
                });
            }
        }
        for operation in &raw.operations {
            if operation.input_schema == operation.output_schema {
                return Err(AdapterError::Semantic {
                    detail: format!(
                        "operation {} declares identical input and output schema refs",
                        operation.kind.as_str()
                    ),
                });
            }
            if raw.initial_taint == AdapterTaint::CredentialTainted
                && operation.taint_after == AdapterTaint::Clean
            {
                return Err(AdapterError::Semantic {
                    detail: format!(
                        "operation {} decreases taint below the descriptor's credential_tainted initial taint",
                        operation.kind.as_str()
                    ),
                });
            }
        }
        Ok(Self {
            adapter: raw.adapter,
            operations: raw.operations,
            credential_handles: raw.credential_handles,
            initial_taint: raw.initial_taint,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub struct OperationContract {
    pub kind: OperationKind,
    pub input_schema: SchemaRef,
    pub output_schema: SchemaRef,
    pub effect_class: EffectClass,
    pub idempotency: IdempotencyPolicy,
    pub evidence: Vec<EvidenceRequirement>,
    pub credential_handle: Option<OpaqueCredentialHandle>,
    pub taint_after: AdapterTaint,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub struct EvidenceRequirement {
    pub kind: AdapterWireId,
    pub schema: SchemaRef,
    pub required: bool,
}

impl AdapterDescriptor {
    pub fn from_wire(wire: &serde_json::Value) -> Result<Self, AdapterError> {
        validate_canonical(
            ADAPTER_DESCRIPTOR_SCHEMA_NAME,
            ADAPTER_DESCRIPTOR_SCHEMA_JSON,
            wire,
        )?;
        serde::Deserialize::deserialize(wire).map_err(|error| AdapterError::Grammar {
            field: "descriptor",
            detail: error.to_string(),
        })
    }

    pub fn to_wire(&self) -> serde_json::Value {
        json!({
            "schema": ADAPTER_DESCRIPTOR_SCHEMA_NAME,
            "adapter": self.adapter,
            "protocol_version": ADAPTER_PROTOCOL_VERSION,
            "operations": self.operations,
            "credential_handles": self.credential_handles,
            "initial_taint": self.initial_taint,
        })
    }

    pub fn adapter(&self) -> &WireAdapterIdentity {
        &self.adapter
    }

    pub fn protocol_version(&self) -> u16 {
        ADAPTER_PROTOCOL_VERSION
    }

    pub fn operations(&self) -> &[OperationContract] {
        &self.operations
    }

    pub fn credential_handles(&self) -> &[OpaqueCredentialHandle] {
        &self.credential_handles
    }

    pub fn initial_taint(&self) -> AdapterTaint {
        self.initial_taint
    }
}
