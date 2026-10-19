//! Generated authority wire v2 data types and strict argument validation; do not edit.

use super::*;

pub const PROTOCOL_VERSION: u8 = 2;
pub const ARGUMENT_MAX_DEPTH: usize = 32;
pub const ARGUMENT_MAX_ARRAY_ITEMS: usize = 1024;
pub const ARGUMENT_MAX_OBJECT_PROPERTIES: usize = 256;
pub const ARGUMENT_MAX_KEY_CODE_POINTS: usize = 256;
pub const ARGUMENT_MAX_STRING_CODE_POINTS: usize = 65_536;
pub const ARGUMENT_MAX_INTEGER: i64 = 9_007_199_254_740_991;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Version;

impl Serialize for Version {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_u8(PROTOCOL_VERSION)
    }
}

impl<'de> Deserialize<'de> for Version {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct VersionVisitor;
        impl Visitor<'_> for VersionVisitor {
            type Value = Version;
            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("the integer 2")
            }
            fn visit_u64<E: de::Error>(self, value: u64) -> Result<Self::Value, E> {
                if value == u64::from(PROTOCOL_VERSION) {
                    Ok(Version)
                } else {
                    Err(E::custom("wire version must be integer 2"))
                }
            }
            fn visit_i64<E: de::Error>(self, value: i64) -> Result<Self::Value, E> {
                if value == i64::from(PROTOCOL_VERSION) {
                    Ok(Version)
                } else {
                    Err(E::custom("wire version must be integer 2"))
                }
            }
        }
        deserializer.deserialize_any(VersionVisitor)
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct U64Wire(u64);
impl U64Wire {
    pub const fn new(value: u64) -> Self {
        Self(value)
    }
    pub const fn get(self) -> u64 {
        self.0
    }
}
impl From<u64> for U64Wire {
    fn from(value: u64) -> Self {
        Self::new(value)
    }
}
impl fmt::Display for U64Wire {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}", self.0)
    }
}
impl Serialize for U64Wire {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(&self.0)
    }
}
impl<'de> Deserialize<'de> for U64Wire {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct DecimalVisitor;
        impl Visitor<'_> for DecimalVisitor {
            type Value = U64Wire;
            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a canonical decimal-string u64")
            }
            fn visit_str<E: de::Error>(self, value: &str) -> Result<Self::Value, E> {
                parse_u64_wire(value).map(U64Wire).map_err(E::custom)
            }
        }
        deserializer.deserialize_str(DecimalVisitor)
    }
}
fn parse_u64_wire(value: &str) -> Result<u64, &'static str> {
    if value == "0" {
        return Ok(0);
    }
    let bytes = value.as_bytes();
    if !matches!(bytes.first(), Some(b'1'..=b'9')) || !bytes.iter().all(u8::is_ascii_digit) {
        return Err("u64 must be unsigned canonical decimal without leading zeroes");
    }
    value
        .parse::<u64>()
        .map_err(|_| "u64 decimal exceeds 18446744073709551615")
}

macro_rules! string_newtype {
    ($name:ident, $validator:ident) => {
        #[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
        pub struct $name(String);
        impl $name {
            pub fn new(value: &str) -> Result<Self, &'static str> {
                $validator(value)?;
                Ok(Self(value.to_string()))
            }
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }
        impl TryFrom<String> for $name {
            type Error = &'static str;
            fn try_from(value: String) -> Result<Self, Self::Error> {
                $validator(&value)?;
                Ok(Self(value))
            }
        }
        impl From<$name> for String {
            fn from(value: $name) -> Self {
                value.0
            }
        }
        impl AsRef<str> for $name {
            fn as_ref(&self) -> &str {
                self.as_str()
            }
        }
        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(self.as_str())
            }
        }
        impl Serialize for $name {
            fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                serializer.serialize_str(self.as_str())
            }
        }
        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                let value = String::deserialize(deserializer)?;
                value.try_into().map_err(de::Error::custom)
            }
        }
    };
}

fn validate_unit_name(value: &str) -> Result<(), &'static str> {
    if value.is_empty() || value.chars().count() > 256 {
        return Err("unit_name must be 1..=256 Unicode code points");
    }
    if !value.bytes().all(|byte| {
        byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':' | b'@')
    }) {
        return Err("unit_name contains an invalid character");
    }
    Ok(())
}
fn validate_cgroup_path(value: &str) -> Result<(), &'static str> {
    if value.chars().count() > 4096 || !value.starts_with('/') {
        return Err("cgroup path must be absolute and at most 4096 Unicode code points");
    }
    for segment in value[1..].split('/') {
        if segment.is_empty() || segment == "." || segment == ".." {
            return Err("cgroup path contains an empty, dot, or dot-dot segment");
        }
        if !segment.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':' | b'@')
        }) {
            return Err("cgroup path contains an invalid segment character");
        }
    }
    Ok(())
}
fn validate_rejection_code(value: &str) -> Result<(), &'static str> {
    if value.is_empty() || value.chars().count() > 128 || !value.as_bytes()[0].is_ascii_lowercase()
    {
        return Err(
            "rejection code must begin with lowercase ASCII and be at most 128 Unicode code points",
        );
    }
    if !value.bytes().all(|byte| {
        byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'_' | b'-')
    }) {
        return Err("rejection code contains an invalid character");
    }
    Ok(())
}
fn validate_detail(value: &str) -> Result<(), &'static str> {
    if value.is_empty() || value.chars().count() > 4096 {
        return Err("rejection detail must be 1..=4096 Unicode code points");
    }
    Ok(())
}
string_newtype!(UnitName, validate_unit_name);
string_newtype!(CgroupPath, validate_cgroup_path);
string_newtype!(RejectionCode, validate_rejection_code);
string_newtype!(Detail, validate_detail);

#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(transparent)]
pub struct Arguments(Value);
impl Arguments {
    pub fn new(value: Value) -> Result<Self, &'static str> {
        validate_argument(&value, 0)?;
        Ok(Self(value))
    }
    pub const fn as_value(&self) -> &Value {
        &self.0
    }
}
impl TryFrom<Value> for Arguments {
    type Error = &'static str;
    fn try_from(value: Value) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}
impl<'de> Deserialize<'de> for Arguments {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = Value::deserialize(deserializer)?;
        Self::new(value).map_err(de::Error::custom)
    }
}
fn validate_argument(value: &Value, depth: usize) -> Result<(), &'static str> {
    if depth > ARGUMENT_MAX_DEPTH {
        return Err("arguments exceed depth 32");
    }
    match value {
        Value::Null | Value::Bool(_) => Ok(()),
        Value::Int(value) => {
            if (-ARGUMENT_MAX_INTEGER..=ARGUMENT_MAX_INTEGER).contains(value) {
                Ok(())
            } else {
                Err("argument integer exceeds JavaScript-safe range")
            }
        }
        Value::UInt(value) => {
            if *value <= ARGUMENT_MAX_INTEGER as u64 {
                Ok(())
            } else {
                Err("argument integer exceeds JavaScript-safe range")
            }
        }
        Value::Float(_) => Err("argument numbers must be integers"),
        Value::String(value) => {
            if value.chars().count() <= ARGUMENT_MAX_STRING_CODE_POINTS {
                Ok(())
            } else {
                Err("argument string exceeds 65536 Unicode code points")
            }
        }
        Value::Array(values) => {
            if depth == ARGUMENT_MAX_DEPTH {
                return Err("arguments exceed depth 32");
            }
            if values.len() > ARGUMENT_MAX_ARRAY_ITEMS {
                return Err("argument array exceeds 1024 items");
            }
            for value in values {
                validate_argument(value, depth + 1)?;
            }
            Ok(())
        }
        Value::Object(entries) => {
            if depth == ARGUMENT_MAX_DEPTH {
                return Err("arguments exceed depth 32");
            }
            if entries.len() > ARGUMENT_MAX_OBJECT_PROPERTIES {
                return Err("argument object exceeds 256 properties");
            }
            let mut keys = BTreeSet::new();
            for entry in entries {
                let code_points = entry.key.chars().count();
                if code_points == 0 || code_points > ARGUMENT_MAX_KEY_CODE_POINTS {
                    return Err("argument key must be 1..=256 Unicode code points");
                }
                if !keys.insert(entry.key.as_str()) {
                    return Err("argument object contains a duplicate key");
                }
                validate_argument(&entry.value, depth + 1)?;
            }
            Ok(())
        }
    }
}

pub const FIXTURE_ID: &str = "odin-authority-wire-v2";
pub const MAX_REQUEST_BYTES: usize = 262144;
pub const MAX_FRAME_BYTES: usize = 1048576;
pub const CANONICAL_VECTOR_NAMES: &[&str] = &[
    "invoke-basic",
    "invoke-u64-max",
    "resume-operation",
    "reconcile-durable",
    "reconcile-absent",
    "close-drain",
    "close-abort",
    "stop-process",
    "stop-cgroup",
    "stop-unit",
    "invoked-basic",
    "invoked-replay",
    "operation-resumed",
    "operation-reconciled-durable",
    "operation-reconciled-absent",
    "capsule-closed-drain",
    "capsule-closed-abort",
    "stop-recorded-requested",
    "stop-recorded-stopped",
    "stop-recorded-failed",
    "rejected",
];

pub const V1_REJECTION_NAMES: &[&str] = &[
    "v1-bind-request",
    "v1-prepare-request",
    "v1-decision-request",
    "v1-settle-request",
    "v1-stop-intent-request",
    "v1-stop-outcome-request",
    "v1-bound-response",
    "v1-prepared-response",
    "v1-decision-response",
    "v1-settled-response",
    "v1-stop-recorded-response",
    "v1-rejected-response",
];

pub const EXACT_ECHO_PAIRS: &[(&str, &str)] = &[
    ("invoke-basic", "invoked-basic"),
    ("invoke-u64-max", "invoked-replay"),
    ("resume-operation", "operation-resumed"),
    ("reconcile-durable", "operation-reconciled-durable"),
    ("reconcile-absent", "operation-reconciled-absent"),
    ("close-drain", "capsule-closed-drain"),
    ("close-abort", "capsule-closed-abort"),
    ("stop-process", "stop-recorded-requested"),
    ("stop-cgroup", "stop-recorded-stopped"),
    ("stop-unit", "stop-recorded-failed"),
];

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OperationState {
    Prepared,
    EffectStarted,
    Committed,
    Aborted,
    InDoubt,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StopState {
    Requested,
    Stopped,
    Failed,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CloseMode {
    Drain,
    Abort,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Budget {
    pub requests: U64Wire,
    pub stops: U64Wire,
    pub spend: U64Wire,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Evidence {
    Process {
        pid: i32,
        start_time_ticks: U64Wire,
        process_group: i32,
    },
    Unit {
        unit_name: UnitName,
    },
    Cgroup {
        path: CgroupPath,
        inode: U64Wire,
    },
    Durable {
        digest: PredecessorHash,
    },
    Absent,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Request {
    InvokeCapability {
        wire: Version,
        capsule_id: CapsuleId,
        correlation_id: CorrelationId,
        capability: ToolId,
        budget: Budget,
        arguments: Arguments,
    },
    ResumeOperation {
        wire: Version,
        capsule_id: CapsuleId,
        correlation_id: CorrelationId,
        operation_id: OperationId,
    },
    ReconcileOperation {
        wire: Version,
        capsule_id: CapsuleId,
        correlation_id: CorrelationId,
        operation_id: OperationId,
    },
    CloseCapsule {
        wire: Version,
        capsule_id: CapsuleId,
        correlation_id: CorrelationId,
        mode: CloseMode,
    },
    StopIntent {
        wire: Version,
        capsule_id: CapsuleId,
        correlation_id: CorrelationId,
        operation_id: Option<OperationId>,
    },
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Response {
    CapabilityInvoked {
        wire: Version,
        capsule_id: CapsuleId,
        correlation_id: CorrelationId,
        operation_id: OperationId,
        state: OperationState,
        replay: bool,
    },
    OperationResumed {
        wire: Version,
        capsule_id: CapsuleId,
        correlation_id: CorrelationId,
        operation_id: OperationId,
        state: OperationState,
        replay: bool,
    },
    OperationReconciled {
        wire: Version,
        capsule_id: CapsuleId,
        correlation_id: CorrelationId,
        operation_id: OperationId,
        state: OperationState,
        replay: bool,
        evidence: Evidence,
    },
    CapsuleClosed {
        wire: Version,
        capsule_id: CapsuleId,
        correlation_id: CorrelationId,
        drained: U64Wire,
    },
    StopRecorded {
        wire: Version,
        capsule_id: CapsuleId,
        correlation_id: CorrelationId,
        operation_id: Option<OperationId>,
        state: StopState,
        evidence: Evidence,
    },
    Rejected {
        wire: Version,
        code: RejectionCode,
        detail: Detail,
    },
}
