//! Validated identifiers, sequences, epochs, and revisions used by Huginn.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use uuid::Uuid;

use crate::DomainError;

const MAX_ID_BYTES: usize = 128;

fn invalid_id(kind: &'static str, value: String, reason: &'static str) -> DomainError {
    DomainError::InvalidId {
        kind,
        value,
        reason,
    }
}

fn safe_id_reason(value: &str) -> Option<&'static str> {
    if value.is_empty() {
        return Some("must not be empty");
    }
    if value.len() > MAX_ID_BYTES {
        return Some("must not exceed 128 bytes");
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

fn provider_model_name_reason(value: &str) -> Option<&'static str> {
    if value.is_empty() {
        return Some("must not be empty");
    }
    if value.len() > MAX_ID_BYTES {
        return Some("must not exceed 128 bytes");
    }
    if value.chars().next().is_some_and(char::is_whitespace)
        || value.chars().next_back().is_some_and(char::is_whitespace)
    {
        return Some("must not begin or end with whitespace");
    }
    if value.chars().any(char::is_control) {
        return Some("must not contain control characters");
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
                    let parsed = Uuid::parse_str(value).map_err(|_| {
                        invalid_id(
                            stringify!($name),
                            value.to_owned(),
                            "must be a valid UUID",
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
                    value.parse::<u64>().map(Self).map_err(|_| {
                        invalid_id(
                            stringify!($name),
                            value.to_owned(),
                            "must be an unsigned 64-bit integer",
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

define_string_ids!(safe_id_reason, "Validated safe string identifier for ";
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
        BrowserSessionId, ConnectionId, DeviceId, DomainError, DownloadId, EventSeq, FileRootId,
        FileWatchId, LiveSessionId, ModelName, PermissionRequestId, ProviderName, RenderId,
        RendererId, RequestId, RosterRevision, Sequence, SessionEpoch, SessionListCursor,
        SimulationOutputId, StreamId, TailnetNodeId, TerminalControlLeaseId, TerminalSeq,
        TransferId,
    };
    use uuid::Uuid;

    macro_rules! assert_uuid_roundtrip {
        ($name:ident, $text:literal) => {{
            let id = $name::parse($text).unwrap();
            assert_eq!(id.to_string(), $text);
            assert_eq!(*id.as_uuid(), Uuid::parse_str($text).unwrap());
            assert_eq!($name::new(id.into_uuid()).unwrap(), id);
            assert_eq!(id.to_string().parse::<$name>().unwrap(), id);
            assert_eq!(
                serde_json::from_str::<$name>(&serde_json::to_string(&id).unwrap()).unwrap(),
                id
            );
            assert!(matches!(
                $name::new(Uuid::nil()),
                Err(DomainError::InvalidId { .. })
            ));
            assert!(serde_json::from_str::<$name>("\"not-a-uuid\"").is_err());
        }};
    }

    #[test]
    fn uuid_ids_validate_and_roundtrip() {
        assert_uuid_roundtrip!(LiveSessionId, "00000000-0000-4000-8000-000000000001");
        assert_uuid_roundtrip!(DeviceId, "00000000-0000-4000-8000-000000000002");
        assert_uuid_roundtrip!(ConnectionId, "00000000-0000-4000-8000-000000000003");
        assert_uuid_roundtrip!(StreamId, "00000000-0000-4000-8000-000000000004");
        assert_uuid_roundtrip!(RequestId, "00000000-0000-4000-8000-000000000005");
        assert_uuid_roundtrip!(TransferId, "00000000-0000-4000-8000-000000000006");
        assert_uuid_roundtrip!(
            TerminalControlLeaseId,
            "00000000-0000-4000-8000-000000000007"
        );
        assert_uuid_roundtrip!(BrowserSessionId, "00000000-0000-4000-8000-000000000008");
        assert_uuid_roundtrip!(DownloadId, "00000000-0000-4000-8000-000000000009");
        assert_uuid_roundtrip!(SimulationOutputId, "00000000-0000-4000-8000-00000000000a");
        assert_uuid_roundtrip!(RenderId, "00000000-0000-4000-8000-00000000000b");
        assert_uuid_roundtrip!(FileWatchId, "00000000-0000-4000-8000-00000000000c");
    }

    #[test]
    fn uuid_ids_reject_noncanonical_text() {
        let canonical = "8f9c2ee3-85ec-46e9-a43a-a2cd6048c1e9";
        assert!(LiveSessionId::parse(canonical).is_ok());
        assert!(LiveSessionId::parse(&canonical.to_uppercase()).is_err());
        assert!(LiveSessionId::parse(&canonical.replace('-', "")).is_err());
        assert!(LiveSessionId::parse(&format!("urn:uuid:{canonical}")).is_err());
        assert!(LiveSessionId::parse(&format!("{{{canonical}}}")).is_err());
    }

    macro_rules! assert_counter_boundaries {
        ($name:ident) => {{
            let zero = $name::new(0);
            assert_eq!(zero.get(), 0);
            assert_eq!(zero.checked_increment(), Some($name::new(1)));
            assert_eq!(zero.checked_next(), Some($name::new(1)));
            assert_eq!($name::new(u64::MAX).checked_increment(), None);
            assert_eq!(
                u64::MAX.to_string().parse::<$name>().unwrap().get(),
                u64::MAX
            );
            assert!($name::parse("-1").is_err());
            assert!($name::parse("18446744073709551616").is_err());
            assert_eq!(
                serde_json::from_str::<$name>(&serde_json::to_string(&zero).unwrap()).unwrap(),
                zero
            );
        }};
    }

    #[test]
    fn counters_check_overflow_and_roundtrip() {
        assert_counter_boundaries!(Sequence);
        assert_counter_boundaries!(EventSeq);
        assert_counter_boundaries!(TerminalSeq);
        assert_counter_boundaries!(SessionEpoch);
        assert_counter_boundaries!(RosterRevision);
    }

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

    #[test]
    fn provider_and_model_names_allow_punctuation_without_unsafe_edges() {
        let provider = ProviderName::new("openrouter/anthropic@us-east:beta").unwrap();
        let model = ModelName::new("Claude 3.5 (Sonnet) [latest]").unwrap();

        assert_eq!(
            provider.to_string().parse::<ProviderName>().unwrap(),
            provider
        );
        assert_eq!(
            serde_json::from_str::<ModelName>(&serde_json::to_string(&model).unwrap()).unwrap(),
            model
        );

        for invalid in ["", " leading", "trailing ", "line\nbreak", "nul\0byte"] {
            assert!(ProviderName::new(invalid).is_err());
            assert!(ModelName::new(invalid).is_err());
        }
        assert!(ProviderName::new("p".repeat(129)).is_err());
    }
}
