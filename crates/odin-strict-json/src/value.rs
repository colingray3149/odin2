//! Preserve object entries until duplicate checking rather than silently collapsing them.

use std::fmt;

use serde::{Deserialize, Serialize};

/// Preserve insertion order and exact integers without widening through floating point.
#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    Null,
    Bool(bool),
    Int(i64),
    /// Keep integers above i64::MAX exact rather than rounding through f64.
    UInt(u64),
    Float(f64),
    String(String),
    Array(Vec<Value>),
    Object(Vec<ObjectEntry>),
}

#[derive(Debug, Clone, PartialEq)]
pub struct ObjectEntry {
    pub key: String,
    pub value: Value,
}

impl Value {
    pub fn is_null(&self) -> bool {
        matches!(self, Value::Null)
    }

    pub fn kind(&self) -> &'static str {
        match self {
            Value::Null => "null",
            Value::Bool(_) => "bool",
            Value::Int(_) => "int",
            Value::UInt(_) => "uint",
            Value::Float(_) => "float",
            Value::String(_) => "string",
            Value::Array(_) => "array",
            Value::Object(_) => "object",
        }
    }
}

impl fmt::Display for Value {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Value::Null => f.write_str("null"),
            Value::Bool(b) => f.write_str(if *b { "true" } else { "false" }),
            Value::Int(n) => write!(f, "{n}"),
            Value::UInt(n) => write!(f, "{n}"),
            Value::Float(x) => write!(f, "{x}"),
            Value::String(s) => write!(f, "{s:?}"),
            Value::Array(items) => {
                f.write_str("[")?;
                for (i, v) in items.iter().enumerate() {
                    if i > 0 {
                        f.write_str(",")?;
                    }
                    write!(f, "{v}")?;
                }
                f.write_str("]")
            }
            Value::Object(entries) => {
                f.write_str("{")?;
                for (i, e) in entries.iter().enumerate() {
                    if i > 0 {
                        f.write_str(",")?;
                    }
                    write!(f, "{}:{}", e.key, e.value)?;
                }
                f.write_str("}")
            }
        }
    }
}

impl Serialize for Value {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            Value::Null => serializer.serialize_unit(),
            Value::Bool(b) => serializer.serialize_bool(*b),
            Value::Int(n) => serializer.serialize_i64(*n),
            Value::UInt(n) => serializer.serialize_u64(*n),
            Value::Float(x) => serializer.serialize_f64(*x),
            Value::String(s) => serializer.serialize_str(s),
            Value::Array(items) => {
                use serde::ser::SerializeSeq;
                let mut seq = serializer.serialize_seq(Some(items.len()))?;
                for item in items {
                    seq.serialize_element(item)?;
                }
                seq.end()
            }
            Value::Object(entries) => {
                use serde::ser::SerializeMap;
                let mut map = serializer.serialize_map(Some(entries.len()))?;
                for entry in entries {
                    map.serialize_entry(&entry.key, &entry.value)?;
                }
                map.end()
            }
        }
    }
}

impl<'de> Deserialize<'de> for Value {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        // Strict callers validate duplicate keys before reaching serde deserialization.
        let raw = serde_json::Value::deserialize(deserializer)?;
        Ok(value_from_serde(&raw))
    }
}

pub(crate) fn value_from_serde(raw: &serde_json::Value) -> Value {
    match raw {
        serde_json::Value::Null => Value::Null,
        serde_json::Value::Bool(b) => Value::Bool(*b),
        serde_json::Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                Value::Int(i)
            } else if let Some(u) = n.as_u64() {
                Value::UInt(u)
            } else {
                Value::Float(n.as_f64().expect("finite f64"))
            }
        }
        serde_json::Value::String(s) => Value::String(s.clone()),
        serde_json::Value::Array(items) => {
            Value::Array(items.iter().map(value_from_serde).collect())
        }
        serde_json::Value::Object(map) => {
            // Retain serde_json's iteration order, which depends on its preserve_order feature.
            let entries = map
                .iter()
                .map(|(k, v)| ObjectEntry {
                    key: k.clone(),
                    value: value_from_serde(v),
                })
                .collect();
            Value::Object(entries)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::value_from_serde;
    use super::Value;
    use crate::error::{DecodeError, DecodeOptions};
    use crate::parse::parse;

    fn strict(text: &str) -> Value {
        parse(text.as_bytes(), DecodeOptions::default()).expect("valid wire input parses")
    }

    /// Unsigned integers stay exact across parse, the strict `Value`, and
    /// the canonical encoder: the full `u64` range survives, values beyond
    /// `i64::MAX` never touch `f64`, and out-of-range integers are
    /// rejected instead of approximated.
    #[test]
    fn unsigned_boundaries() {
        assert_eq!(strict("0"), Value::Int(0));
        assert_eq!(strict("-1"), Value::Int(-1));
        assert_eq!(strict("-9223372036854775808"), Value::Int(i64::MIN));
        assert_eq!(strict("9223372036854775807"), Value::Int(i64::MAX));
        assert_eq!(
            strict("9223372036854775808"),
            Value::UInt(i64::MAX as u64 + 1)
        );
        assert_eq!(strict("18446744073709551615"), Value::UInt(u64::MAX));

        assert!(matches!(
            parse(b"18446744073709551616", DecodeOptions::default()),
            Err(DecodeError::InvalidNumber { .. })
        ));
        assert!(matches!(
            parse(b"-9223372036854775809", DecodeOptions::default()),
            Err(DecodeError::InvalidNumber { .. })
        ));

        let bytes =
            crate::canonical::canonicalize_value(&Value::UInt(u64::MAX)).expect("canonicalizes");
        assert_eq!(bytes, b"18446744073709551615");
        assert_eq!(
            parse(&bytes, DecodeOptions::default()).expect("reparses"),
            Value::UInt(u64::MAX)
        );

        assert_eq!(
            value_from_serde(&serde_json::json!(u64::MAX)),
            Value::UInt(u64::MAX)
        );
        assert_eq!(
            value_from_serde(&serde_json::json!(i64::MAX)),
            Value::Int(i64::MAX)
        );
        assert_eq!(Value::UInt(u64::MAX).to_string(), "18446744073709551615");

        let decoded: serde_json::Value =
            crate::parse::decode(b"18446744073709551615", 4096).expect("decodes");
        assert_eq!(decoded.as_u64(), Some(u64::MAX));

        assert_eq!(
            crate::canonical::canonicalize(&0i128).expect("i128 zero"),
            b"0"
        );
        assert_eq!(
            crate::canonical::canonicalize(&(i64::MAX as i128)).expect("i128 i64 max"),
            b"9223372036854775807"
        );
        assert_eq!(
            crate::canonical::canonicalize(&(i64::MAX as i128 + 1)).expect("i128 above i64"),
            b"9223372036854775808"
        );
        assert_eq!(
            crate::canonical::canonicalize(&(u64::MAX as i128)).expect("i128 u64 max"),
            b"18446744073709551615"
        );
        assert!(matches!(
            crate::canonical::canonicalize(&(u64::MAX as i128 + 1)),
            Err(crate::CanonicalError::Serialize { .. })
        ));
        assert_eq!(
            crate::canonical::canonicalize(&(i64::MIN as i128)).expect("i128 i64 min"),
            b"-9223372036854775808"
        );
        assert!(matches!(
            crate::canonical::canonicalize(&(i64::MIN as i128 - 1)),
            Err(crate::CanonicalError::Serialize { .. })
        ));
        assert_eq!(
            crate::canonical::canonicalize(&(u64::MAX as u128)).expect("u128 u64 max"),
            b"18446744073709551615"
        );
        assert!(matches!(
            crate::canonical::canonicalize(&(u64::MAX as u128 + 1)),
            Err(crate::CanonicalError::Serialize { .. })
        ));

        assert_eq!(
            strict("1e2"),
            Value::Float(100.0),
            "float syntax still produces floats"
        );
    }
}
