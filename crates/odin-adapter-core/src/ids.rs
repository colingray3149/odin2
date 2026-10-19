//! Reuse domain identities so adapter and domain credential, digest, and capability grammars agree.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::AdapterError;

/// `cred:<id>` credential handle, canonical grammar enforced by the domain
/// (dot/colon allowed, up to 191 suffix bytes); redacted Debug.
pub use odin_domain::huginn::OpaqueCredentialHandle;
/// Registry capability identity; adapter operations become admitted
/// capabilities under this stricter 128-byte grammar.
pub use odin_domain::CapabilityId;
/// `blake3:` plus 64 lowercase hex digits (`$defs.digest`).
pub use odin_domain::Digest;

/// The schemas' `$defs.id` bound (`{0,191}` after the first character).
const MAX_WIRE_ID_BYTES: usize = 192;

fn valid_wire_id(value: &str) -> Option<&'static str> {
    if value.is_empty() {
        return Some("must not be empty");
    }
    if value.len() > MAX_WIRE_ID_BYTES {
        return Some("must not exceed 192 bytes");
    }
    let mut bytes = value.bytes();
    if !bytes
        .next()
        .is_some_and(|byte| byte.is_ascii_alphanumeric())
    {
        return Some("must start with an ASCII alphanumeric character");
    }
    if !bytes.all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-'))
    {
        return Some("must contain only ASCII alphanumeric characters or '.', '_', ':', and '-'");
    }
    None
}

fn valid_adapter_version(value: &str) -> Option<&'static str> {
    let parts: Vec<&str> = value.split('.').collect();
    let shaped = parts.len() == 3
        && parts
            .iter()
            .all(|part| !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit()));
    if !shaped {
        return Some("must be three dot-separated numeric components (X.Y.Z)");
    }
    None
}

fn valid_operation_kind(value: &str) -> Option<&'static str> {
    let segments: Vec<&str> = value.split('.').collect();
    if segments.len() < 2 {
        return Some("must contain at least one '.' separator");
    }
    let first = segments[0];
    let first_valid = !first.is_empty()
        && first.as_bytes()[0].is_ascii_lowercase()
        && first.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'_' | b'-')
        });
    if !first_valid {
        return Some("must start with a segment shaped [a-z][a-z0-9_-]*");
    }
    for segment in &segments[1..] {
        let valid = !segment.is_empty()
            && segment.bytes().all(|byte| {
                byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'_' | b'-')
            });
        if !valid {
            return Some("every '.'-separated suffix segment must be nonempty [a-z0-9_-]+");
        }
    }
    None
}

fn valid_schema_ref(value: &str) -> Option<&'static str> {
    let Some(rest) = value.strip_prefix("schemas/") else {
        return Some("must start with 'schemas/'");
    };
    let Some(core) = rest.strip_suffix(".json") else {
        return Some("must end with '.json'");
    };
    if core.is_empty()
        || !core
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'/' | b'-'))
    {
        return Some(
            "must contain only ASCII alphanumeric characters or '.', '_', '/', and '-' between the 'schemas/' prefix and '.json' suffix",
        );
    }
    None
}

macro_rules! define_wire_string {
    ($(#[$docs:meta])* $name:ident, $grammar:ident) => {
        $(#[$docs])*
        #[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name(String);

        impl $name {
            pub fn new(value: impl Into<String>) -> Result<Self, AdapterError> {
                let value = value.into();
                if let Some(reason) = $grammar(&value) {
                    return Err(AdapterError::Grammar {
                        field: stringify!($name),
                        detail: reason.to_owned(),
                    });
                }
                Ok(Self(value))
            }

            pub fn parse(value: &str) -> Result<Self, AdapterError> {
                Self::new(value)
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(&self.0)
            }
        }

        impl FromStr for $name {
            type Err = AdapterError;

            fn from_str(value: &str) -> Result<Self, Self::Err> {
                Self::parse(value)
            }
        }

        impl TryFrom<String> for $name {
            type Error = AdapterError;

            fn try_from(value: String) -> Result<Self, Self::Error> {
                Self::new(value)
            }
        }

        impl Serialize for $name {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                serializer.serialize_str(&self.0)
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                let value = String::deserialize(deserializer)?;
                Self::new(value).map_err(serde::de::Error::custom)
            }
        }
    };
}

define_wire_string!(
    /// Wire IDs allow 192 bytes; registry capability IDs retain the stricter 128-byte limit.
    AdapterWireId,
    valid_wire_id
);

define_wire_string!(
    /// Schema versions require three numeric components (`X.Y.Z`).
    AdapterVersion,
    valid_adapter_version
);

define_wire_string!(
    /// Dotted lowercase kinds must also satisfy [`CapabilityId`] when admitted to the registry.
    OperationKind,
    valid_operation_kind
);

define_wire_string!(
    /// Schema references are repository-relative `schemas/<path>.json` paths.
    SchemaRef,
    valid_schema_ref
);

/// Joining taint cannot turn [`AdapterTaint::CredentialTainted`] back into [`AdapterTaint::Clean`].
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AdapterTaint {
    Clean,
    CredentialTainted,
}

impl AdapterTaint {
    pub const fn join(self, other: Self) -> Self {
        if matches!(self, Self::CredentialTainted) || matches!(other, Self::CredentialTainted) {
            Self::CredentialTainted
        } else {
            Self::Clean
        }
    }
}

/// Uses the domain identity's wire shape while enforcing adapter-schema string grammars.
#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub struct WireAdapterIdentity {
    pub adapter_id: AdapterWireId,
    pub version: AdapterVersion,
    pub binding_digest: Digest,
}
