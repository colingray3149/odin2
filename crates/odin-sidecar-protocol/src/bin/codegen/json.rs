//! Minimal strict-JSON value model shared by every generator stage.

use std::collections::BTreeMap;
use std::ops::Index;

use serde::{Serialize, Serializer};

pub(crate) type JsonMap = BTreeMap<String, JsonValue>;

#[derive(Clone, Debug, PartialEq)]
pub(crate) enum JsonValue {
    Null,
    Bool(bool),
    I64(i64),
    U64(u64),
    String(String),
    Array(Vec<JsonValue>),
    Object(JsonMap),
}

impl Serialize for JsonValue {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            Self::Null => serializer.serialize_unit(),
            Self::Bool(value) => serializer.serialize_bool(*value),
            Self::I64(value) => serializer.serialize_i64(*value),
            Self::U64(value) => serializer.serialize_u64(*value),
            Self::String(value) => serializer.serialize_str(value),
            Self::Array(values) => values.serialize(serializer),
            Self::Object(values) => values.serialize(serializer),
        }
    }
}

impl JsonValue {
    pub(crate) fn as_object(&self) -> Option<&JsonMap> {
        if let Self::Object(value) = self {
            Some(value)
        } else {
            None
        }
    }

    pub(crate) fn as_array(&self) -> Option<&[JsonValue]> {
        if let Self::Array(value) = self {
            Some(value)
        } else {
            None
        }
    }

    pub(crate) fn as_str(&self) -> Option<&str> {
        if let Self::String(value) = self {
            Some(value)
        } else {
            None
        }
    }

    pub(crate) fn as_i64(&self) -> Option<i64> {
        match self {
            Self::I64(value) => Some(*value),
            Self::U64(value) => i64::try_from(*value).ok(),
            _ => None,
        }
    }

    pub(crate) const fn is_boolean(&self) -> bool {
        matches!(self, Self::Bool(_))
    }

    pub(crate) const fn is_null(&self) -> bool {
        matches!(self, Self::Null)
    }
}

impl Index<&str> for JsonValue {
    type Output = JsonValue;

    fn index(&self, key: &str) -> &Self::Output {
        self.as_object()
            .and_then(|object| object.get(key))
            .expect("generator model key exists")
    }
}

pub(crate) trait ToJson {
    fn to_json(&self) -> JsonValue;
}

impl ToJson for JsonValue {
    fn to_json(&self) -> JsonValue {
        self.clone()
    }
}

impl ToJson for str {
    fn to_json(&self) -> JsonValue {
        JsonValue::String(self.to_string())
    }
}

impl ToJson for String {
    fn to_json(&self) -> JsonValue {
        JsonValue::String(self.clone())
    }
}

impl ToJson for bool {
    fn to_json(&self) -> JsonValue {
        JsonValue::Bool(*self)
    }
}

impl ToJson for i32 {
    fn to_json(&self) -> JsonValue {
        JsonValue::I64(i64::from(*self))
    }
}

impl ToJson for i64 {
    fn to_json(&self) -> JsonValue {
        JsonValue::I64(*self)
    }
}

impl ToJson for usize {
    fn to_json(&self) -> JsonValue {
        JsonValue::U64(u64::try_from(*self).expect("generator usize fits u64"))
    }
}

impl<T: ToJson + ?Sized> ToJson for &T {
    fn to_json(&self) -> JsonValue {
        (*self).to_json()
    }
}

impl<T: ToJson> ToJson for Vec<T> {
    fn to_json(&self) -> JsonValue {
        JsonValue::Array(self.iter().map(ToJson::to_json).collect())
    }
}

impl ToJson for JsonMap {
    fn to_json(&self) -> JsonValue {
        JsonValue::Object(self.clone())
    }
}

macro_rules! json {
    (null) => {
        JsonValue::Null
    };
    ([$($value:tt),* $(,)?]) => {
        JsonValue::Array(vec![$(json!($value)),*])
    };
    ({$($key:literal : $value:tt),* $(,)?}) => {{
        let mut object = JsonMap::new();
        $(
            assert!(
                object.insert($key.to_string(), json!($value)).is_none(),
                "duplicate generator object key {}",
                $key
            );
        )*
        JsonValue::Object(object)
    }};
    (($value:expr)) => {
        ToJson::to_json(&$value)
    };
    ($value:expr) => {
        ToJson::to_json(&$value)
    };
}

pub(crate) use json;

pub(crate) fn json_text(value: &impl Serialize) -> Result<String, String> {
    let bytes = odin_strict_json::canonicalize(value)
        .map_err(|error| format!("generated JSON cannot canonicalize: {error}"))?;
    String::from_utf8(bytes)
        .map_err(|error| format!("generated canonical JSON is not UTF-8: {error}"))
}

pub(crate) fn json_file(value: &impl Serialize) -> Result<String, String> {
    let mut text = json_text(value)?;
    text.push('\n');
    Ok(text)
}
