//! Embedded schemas and shared domain types keep adapter wire validation consistent.

#![forbid(unsafe_code)]

pub mod config;
pub mod descriptor;
pub mod dispatch;
pub mod evidence;
pub mod ids;
pub mod operation;
pub mod status;
pub mod transport;

pub const ADAPTER_DESCRIPTOR_SCHEMA_NAME: &str = "odin.adapter.descriptor.v1";
pub const ADAPTER_OPERATION_SCHEMA_NAME: &str = "odin.adapter.operation.v1";
pub const ADAPTER_STATUS_SCHEMA_NAME: &str = "odin.adapter.status.v1";

/// Routes declared adapters through their configured backend rather than a HostTool.
pub const ADAPTER_OPERATION_HANDLER: &str = "odin_adapter.operation";

/// Derives receipt evidence from the captured response rather than a backend-supplied summary.
pub const ADAPTER_RECEIPT_EVIDENCE: &str = "odin_adapter.receipt";

pub const ADAPTER_RECEIPT_EVIDENCE_KIND: &str = "adapter.receipt";

pub const ADAPTER_RECEIPT_EVIDENCE_SCHEMA_REF: &str =
    "schemas/control/adapter-receipt-evidence.schema.json";

/// Exit codes of the declared web fetch (`obscura-save`) when the site never answered in time and
/// when it refused with a block status. The bridge's PDF converter and a pod's page fetch both
/// read them as a refusal that another network exit may not repeat.
pub const FETCH_TIMED_OUT: i32 = 124;
pub const FETCH_REFUSED: i32 = 67;

/// Digests the response instead of copying it into the evidence document.
pub fn receipt_evidence(
    adapter: &ids::WireAdapterIdentity,
    kind: &ids::OperationKind,
    taint: ids::AdapterTaint,
    response: &serde_json::Value,
    observed_at: time::OffsetDateTime,
) -> Result<serde_json::Value, AdapterError> {
    let canonical =
        odin_strict_json::canonicalize(response).map_err(|error| AdapterError::Canonical {
            detail: error.to_string(),
        })?;
    let observed_at = observed_at
        .to_offset(time::UtcOffset::UTC)
        .replace_nanosecond(0)
        .map_err(|error| AdapterError::Canonical {
            detail: error.to_string(),
        })?
        .format(&time::format_description::well_known::Rfc3339)
        .map_err(|error| AdapterError::Canonical {
            detail: error.to_string(),
        })?;
    Ok(serde_json::json!({
        "adapter_identity": adapter,
        "kind": kind.as_str(),
        "response_digest": Digest::hash(&canonical),
        "observed_at": observed_at,
        "taint": taint,
    }))
}

pub use ids::{Digest, OpaqueCredentialHandle};

#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum AdapterError {
    #[error("wire data rejected by canonical schema {schema}: {detail}")]
    Schema {
        schema: &'static str,
        detail: String,
    },
    /// Semantic checks cover constraints JSON Schema cannot express.
    #[error("wire data failed semantic admission: {detail}")]
    Semantic { detail: String },
    #[error("invalid {field}: {detail}")]
    Grammar { field: &'static str, detail: String },
    #[error("canonical serialization failed: {detail}")]
    Canonical { detail: String },
    /// Persistence can fail after the effect has occurred.
    #[error("effect receipt persistence failed: {detail}")]
    Receipt { detail: String },
}

/// A broken embedded schema is a build defect, not an invalid input.
pub(crate) fn validate_canonical(
    schema_name: &'static str,
    wire: &serde_json::Value,
) -> Result<(), AdapterError> {
    match odin_kernel::schema::violations(embedded_validator(schema_name), wire) {
        None => Ok(()),
        Some(detail) => Err(AdapterError::Schema {
            schema: schema_name,
            detail,
        }),
    }
}

fn embedded_validator(schema_name: &'static str) -> &'static jsonschema::Validator {
    use std::sync::LazyLock;
    static DESCRIPTOR: LazyLock<jsonschema::Validator> =
        LazyLock::new(|| compile_embedded(descriptor::ADAPTER_DESCRIPTOR_SCHEMA_JSON));
    static OPERATION: LazyLock<jsonschema::Validator> =
        LazyLock::new(|| compile_embedded(operation::ADAPTER_OPERATION_SCHEMA_JSON));
    static STATUS: LazyLock<jsonschema::Validator> =
        LazyLock::new(|| compile_embedded(status::ADAPTER_STATUS_SCHEMA_JSON));
    match schema_name {
        ADAPTER_DESCRIPTOR_SCHEMA_NAME => &DESCRIPTOR,
        ADAPTER_OPERATION_SCHEMA_NAME => &OPERATION,
        ADAPTER_STATUS_SCHEMA_NAME => &STATUS,
        _ => panic!("embedded canonical adapter schema {schema_name} is not one of the three"),
    }
}

fn compile_embedded(schema_json: &'static str) -> jsonschema::Validator {
    let schema: serde_json::Value =
        serde_json::from_str(schema_json).expect("embedded canonical adapter schema parses");
    odin_kernel::schema::compile(&schema).expect("embedded canonical adapter schema compiles")
}
