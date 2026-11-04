//! Validated identifiers, sequences, epochs, and revisions used by Huginn.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use uuid::Uuid;

use odin_types::MAX_ID_BYTES;

use crate::ids::invalid_id_reason;
use crate::DomainError;

fn invalid_id(kind: &'static str, value: String, reason: impl Into<String>) -> DomainError {
    DomainError::InvalidId {
        kind,
        value,
        reason: reason.into(),
    }
}

fn provider_model_name_reason(value: &str) -> Option<String> {
    if value.is_empty() {
        return Some("must not be empty".to_owned());
    }
    if value.len() > MAX_ID_BYTES {
        return Some(format!("must not exceed {MAX_ID_BYTES} bytes"));
    }
    if value.chars().next().is_some_and(char::is_whitespace)
        || value.chars().next_back().is_some_and(char::is_whitespace)
    {
        return Some("must not begin or end with whitespace".to_owned());
    }
    if value.chars().any(char::is_control) {
        return Some("must not contain control characters".to_owned());
    }

    None
}

macro_rules! define_uuid_ids {
    ($($name:ident),+ $(,)?) => {
        $(
            #[doc = concat!("Validated non-nil UUID identifier for ", stringify!($name), ".")]
            #[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
            pub struct $name(Uuid);

            impl $name {
                pub fn new(value: Uuid) -> Result<Self, DomainError> {
                    if value.is_nil() {
                        return Err(invalid_id(
                            stringify!($name),
                            value.to_string(),
                            "must not be the nil UUID",
                        ));
                    }
                    Ok(Self(value))
                }

                pub fn parse(value: &str) -> Result<Self, DomainError> {
                    let parsed = Uuid::parse_str(value).map_err(|error| {
                        invalid_id(
                            stringify!($name),
                            value.to_owned(),
                            format!("must be a valid UUID: {error}"),
                        )
                    })?;
                    if parsed.to_string() != value {
                        return Err(invalid_id(
                            stringify!($name),
                            value.to_owned(),
                            "must be a lowercase hyphenated UUID",
                        ));
                    }
                    Self::new(parsed)
                }

                pub const fn as_uuid(&self) -> &Uuid {
                    &self.0
                }

                pub const fn into_uuid(self) -> Uuid {
                    self.0
                }
            }

            impl fmt::Display for $name {
                fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                    fmt::Display::fmt(&self.0, formatter)
                }
            }

            impl FromStr for $name {
                type Err = DomainError;

                fn from_str(value: &str) -> Result<Self, Self::Err> {
                    Self::parse(value)
                }
            }

            impl Serialize for $name {
                fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
                where
                    S: Serializer,
                {
                    serializer.collect_str(self)
                }
            }

            impl<'de> Deserialize<'de> for $name {
                fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
                where
                    D: Deserializer<'de>,
                {
                    let value = String::deserialize(deserializer)?;
                    Self::parse(&value).map_err(serde::de::Error::custom)
                }
            }
        )+
    };
}

macro_rules! define_u64_counters {
    ($($name:ident),+ $(,)?) => {
        $(
            #[derive(
                Clone,
                Copy,
                Debug,
                Eq,
                Hash,
                Ord,
                PartialEq,
                PartialOrd,
                Serialize,
                Deserialize,
            )]
            #[serde(transparent)]
            pub struct $name(u64);

            impl $name {
                pub const fn new(value: u64) -> Self {
                    Self(value)
                }

                pub const fn get(self) -> u64 {
                    self.0
                }

                pub const fn checked_increment(self) -> Option<Self> {
                    match self.0.checked_add(1) {
                        Some(value) => Some(Self(value)),
                        None => None,
                    }
                }

                pub const fn checked_next(self) -> Option<Self> {
                    self.checked_increment()
                }

                pub fn parse(value: &str) -> Result<Self, DomainError> {
                    value.parse::<u64>().map(Self).map_err(|error| {
                        invalid_id(
                            stringify!($name),
                            value.to_owned(),
                            format!("must be an unsigned 64-bit integer: {error}"),
                        )
                    })
                }
            }

            impl fmt::Display for $name {
                fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                    fmt::Display::fmt(&self.0, formatter)
                }
            }

            impl FromStr for $name {
                type Err = DomainError;

                fn from_str(value: &str) -> Result<Self, Self::Err> {
                    Self::parse(value)
                }
            }
        )+
    };
}

macro_rules! define_string_ids {
    ($validate:ident, $description:literal; $($name:ident),+ $(,)?) => {
        $(
            #[doc = concat!($description, stringify!($name), ".")]
            #[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
            #[serde(transparent)]
            pub struct $name(String);

            impl $name {
                pub fn new(value: impl Into<String>) -> Result<Self, DomainError> {
                    let value = value.into();
                    if let Some(reason) = $validate(&value) {
                        return Err(invalid_id(stringify!($name), value, reason));
                    }
                    Ok(Self(value))
                }

                pub fn parse(value: &str) -> Result<Self, DomainError> {
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
                type Err = DomainError;

                fn from_str(value: &str) -> Result<Self, Self::Err> {
                    Self::parse(value)
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
        )+
    };
}

define_uuid_ids!(
    LiveSessionId,
    DeviceId,
    ConnectionId,
    StreamId,
    RequestId,
    TransferId,
    TerminalControlLeaseId,
    BrowserSessionId,
    DownloadId,
    SimulationOutputId,
    RenderId,
    FileWatchId,
);

define_u64_counters!(
    Sequence,
    EventSeq,
    TerminalSeq,
    SessionEpoch,
    RosterRevision,
);

define_string_ids!(invalid_id_reason, "Validated safe string identifier for ";
    PermissionRequestId,
    TailnetNodeId,
    FileRootId,
    RendererId,
    SessionListCursor,
);

define_string_ids!(provider_model_name_reason, "Validated provider/model name for "; ProviderName, ModelName);

#[cfg(test)]
mod tests {
    use super::{
        DomainError, FileRootId, PermissionRequestId, RendererId, SessionListCursor, TailnetNodeId,
    };

    #[test]
    fn safe_string_ids_match_core_rules() {
        let permission = PermissionRequestId::new("permission.alpha_1:primary-2").unwrap();
        assert_eq!(permission.as_str(), "permission.alpha_1:primary-2");
        assert_eq!(
            serde_json::from_str::<PermissionRequestId>(
                &serde_json::to_string(&permission).unwrap()
            )
            .unwrap(),
            permission
        );

        assert_eq!(
            TailnetNodeId::parse("node-1.tailnet").unwrap().to_string(),
            "node-1.tailnet"
        );
        assert_eq!(
            FileRootId::parse("project:primary").unwrap().to_string(),
            "project:primary"
        );
        assert_eq!(
            RendererId::parse("renderer_svg-v1").unwrap().to_string(),
            "renderer_svg-v1"
        );
        assert_eq!(
            SessionListCursor::parse("cursor:page-2")
                .unwrap()
                .to_string(),
            "cursor:page-2"
        );

        for invalid in ["", "_leading", "has/slash", "has space", "nönascii"] {
            assert!(matches!(
                PermissionRequestId::new(invalid),
                Err(DomainError::InvalidId { .. })
            ));
        }
        assert!(PermissionRequestId::new("a".repeat(129)).is_err());
        assert!(serde_json::from_str::<FileRootId>("\"../escape\"").is_err());
    }
}
