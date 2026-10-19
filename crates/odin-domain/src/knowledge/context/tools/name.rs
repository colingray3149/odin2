use std::collections::BTreeMap;
use std::fmt;
use std::path::PathBuf;
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::{Map, Value};
use url::Url;

use crate::{CapabilityId, Digest, DomainError};

const MAX_TOOL_NAME_BYTES: usize = 64;

/// Provider-facing tool name, restricted to the portable provider name grammar.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct ToolName(String);

impl ToolName {
    pub fn new(value: impl Into<String>) -> Result<Self, DomainError> {
        let value = value.into();
        let valid = !value.is_empty()
            && value.len() <= MAX_TOOL_NAME_BYTES
            && value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'));
        if !valid {
            return Err(DomainError::InvalidId {
                kind: "ToolName",
                value,
                reason: "must contain 1 to 64 ASCII alphanumeric, '_' or '-' characters",
            });
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ToolName {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl FromStr for ToolName {
    type Err = DomainError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::new(value)
    }
}

impl AsRef<str> for ToolName {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl<'de> Deserialize<'de> for ToolName {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Self::new(String::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}

/// Canonically ordered JSON schema together with the digest of its canonical encoding.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ToolSchema {
    canonical_json: Value,
    digest: Digest,
}

impl ToolSchema {
    pub fn new(canonical_json: Value, expected_digest: Digest) -> Result<Self, DomainError> {
        let schema = Self::from_value(canonical_json)?;
        if schema.digest != expected_digest {
            return Err(invalid_tool("schema digest does not match canonical JSON"));
        }
        Ok(schema)
    }

    pub fn from_value(value: Value) -> Result<Self, DomainError> {
        let canonical_json = canonicalize(value)?;
        let encoded = serde_json::to_vec(&canonical_json)
            .map_err(|error| invalid_tool(format!("schema cannot be encoded: {error}")))?;
        Ok(Self {
            canonical_json,
            digest: Digest::hash(&encoded),
        })
    }

    pub fn canonical_json(&self) -> &Value {
        &self.canonical_json
    }

    pub const fn digest(&self) -> Digest {
        self.digest
    }
}

impl Serialize for ToolSchema {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.canonical_json.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for ToolSchema {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Self::from_value(Value::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}

fn canonicalize(value: Value) -> Result<Value, DomainError> {
    match value {
        Value::Null | Value::Bool(_) | Value::String(_) => Ok(value),
        Value::Number(number) => {
            if number.is_f64() {
                return Err(invalid_tool(
                    "schema canonical JSON cannot contain floating-point numbers",
                ));
            }
            Ok(Value::Number(number))
        }
        Value::Array(values) => values
            .into_iter()
            .map(canonicalize)
            .collect::<Result<Vec<_>, _>>()
            .map(Value::Array),
        Value::Object(values) => {
            let sorted = values
                .into_iter()
                .map(|(key, value)| canonicalize(value).map(|value| (key, value)))
                .collect::<Result<BTreeMap<_, _>, _>>()?;
            Ok(Value::Object(sorted.into_iter().collect::<Map<_, _>>()))
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum ResourceConstraint {
    FilesystemBeneath { root: PathBuf },
    HttpOrigin { origin: Url },
    Named { kind: String, value: String },
}

impl ResourceConstraint {
    pub fn validate(&self) -> Result<(), DomainError> {
        match self {
            Self::FilesystemBeneath { root } => {
                let Some(root_text) = root.to_str() else {
                    return Err(invalid_tool("filesystem resource root must be UTF-8"));
                };
                if !root.is_absolute() || root_text.chars().any(char::is_control) {
                    return Err(invalid_tool(
                        "filesystem resource root must be an absolute control-free path",
                    ));
                }
            }
            Self::HttpOrigin { origin } => {
                if !matches!(origin.scheme(), "http" | "https")
                    || origin.host().is_none()
                    || !origin.username().is_empty()
                    || origin.password().is_some()
                    || origin.query().is_some()
                    || origin.fragment().is_some()
                    || origin.path() != "/"
                {
                    return Err(invalid_tool(
                        "HTTP resource must be an http(s) origin without credentials, path, query, or fragment",
                    ));
                }
            }
            Self::Named { kind, value } => {
                if invalid_named_part(kind) || invalid_named_part(value) {
                    return Err(invalid_tool(
                        "named resource kind and value must be trimmed, nonempty, and control-free",
                    ));
                }
            }
        }
        Ok(())
    }
}

fn invalid_named_part(value: &str) -> bool {
    value.is_empty() || value.trim() != value || value.chars().any(char::is_control)
}

/// One provider-visible tool descriptor bound to a kernel capability.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ToolCapability {
    pub capability_id: CapabilityId,
    pub tool_name: ToolName,
    pub description: String,
    pub input_schema: ToolSchema,
    pub schema_digest: Digest,
    pub resource_constraints: Vec<ResourceConstraint>,
}

pub struct ToolCapabilityInit {
    pub capability_id: CapabilityId,
    pub tool_name: ToolName,
    pub description: String,
    pub input_schema: ToolSchema,
    pub schema_digest: Digest,
    pub resource_constraints: Vec<ResourceConstraint>,
}

impl ToolCapability {
    pub fn new(init: ToolCapabilityInit) -> Result<Self, DomainError> {
        let ToolCapabilityInit {
            capability_id,
            tool_name,
            description,
            input_schema,
            schema_digest,
            mut resource_constraints,
        } = init;
        resource_constraints.sort();
        resource_constraints.dedup();
        let capability = Self {
            capability_id,
            tool_name,
            description,
            input_schema,
            schema_digest,
            resource_constraints,
        };
        capability.validate()?;
        Ok(capability)
    }

    pub fn validate(&self) -> Result<(), DomainError> {
        if self.description.trim().is_empty() || self.description.chars().any(char::is_control) {
            return Err(invalid_tool(
                "tool description must be nonempty and control-free",
            ));
        }
        if self.schema_digest != self.input_schema.digest() {
            return Err(invalid_tool(
                "tool schema digest does not match its canonical schema",
            ));
        }
        if self
            .resource_constraints
            .windows(2)
            .any(|pair| pair[0] >= pair[1])
        {
            return Err(invalid_tool(
                "tool resource constraints must be sorted and unique",
            ));
        }
        self.resource_constraints
            .iter()
            .try_for_each(ResourceConstraint::validate)
    }
}

fn invalid_tool(reason: impl Into<String>) -> DomainError {
    DomainError::InvalidEnvelope(format!("tool capability: {}", reason.into()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn tool_names_are_private_validated_provider_names() {
        assert_eq!(ToolName::new("Read_2").unwrap().as_str(), "Read_2");
        assert!(ToolName::new("").is_err());
        assert!(ToolName::new("read.file").is_err());
        assert!(ToolName::new("read file").is_err());
        assert!(ToolName::new("x".repeat(65)).is_err());
        assert!(serde_json::from_str::<ToolName>("\"bad name\"").is_err());
    }

    #[test]
    fn schemas_are_canonical_and_digest_validated() {
        let expected = Digest::hash(br#"{"a":{"c":3,"d":2},"z":1}"#);
        let schema = ToolSchema::new(json!({"z": 1, "a": {"d": 2, "c": 3}}), expected).unwrap();
        assert_eq!(
            serde_json::to_string(schema.canonical_json()).unwrap(),
            r#"{"a":{"c":3,"d":2},"z":1}"#
        );
        assert_eq!(schema.digest(), expected);
        assert!(ToolSchema::new(json!({"a": 1}), Digest::hash(b"wrong")).is_err());
        assert!(ToolSchema::from_value(json!({"ratio": 0.5})).is_err());
    }

    #[test]
    fn capability_constructor_orders_resources_and_checks_invariants() {
        let schema = ToolSchema::from_value(json!({"type": "object"})).unwrap();
        let digest = schema.digest();
        let named = ResourceConstraint::Named {
            kind: "queue".into(),
            value: "jobs".into(),
        };
        let capability = ToolCapability::new(ToolCapabilityInit {
            capability_id: CapabilityId::new("tool.read").unwrap(),
            tool_name: ToolName::new("Read").unwrap(),
            description: "Read a resource".into(),
            input_schema: schema.clone(),
            schema_digest: digest,
            resource_constraints: vec![named.clone(), named],
        })
        .unwrap();
        assert_eq!(capability.resource_constraints.len(), 1);
        assert!(ToolCapability::new(ToolCapabilityInit {
            capability_id: CapabilityId::new("tool.read").unwrap(),
            tool_name: ToolName::new("Read").unwrap(),
            description: "  ".into(),
            input_schema: schema.clone(),
            schema_digest: digest,
            resource_constraints: vec![],
        })
        .is_err());
        assert!(ToolCapability::new(ToolCapabilityInit {
            capability_id: CapabilityId::new("tool.read").unwrap(),
            tool_name: ToolName::new("Read").unwrap(),
            description: "Read".into(),
            input_schema: schema,
            schema_digest: Digest::hash(b"different"),
            resource_constraints: vec![],
        })
        .is_err());
    }

    #[test]
    fn resource_validation_rejects_ambiguous_named_and_http_values() {
        assert!(ResourceConstraint::Named {
            kind: " queue".into(),
            value: "jobs".into(),
        }
        .validate()
        .is_err());
        assert!(ResourceConstraint::HttpOrigin {
            origin: Url::parse("https://example.test/path").unwrap(),
        }
        .validate()
        .is_err());
    }
}
