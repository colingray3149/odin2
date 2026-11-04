//! Reading workflow arguments. The kernel already checked them against the
//! declared input schema, so these only read and name what is missing.

use serde_json::Value;

use crate::Failure;

/// A required non-empty string: "{key} is required".
pub fn str<'a>(args: &'a Value, key: &str) -> Result<&'a str, Failure> {
    opt_str(args, key).ok_or_else(|| Failure::arguments(format!("{key} is required")))
}

/// An optional string; empty counts as absent.
pub fn opt_str<'a>(args: &'a Value, key: &str) -> Option<&'a str> {
    args.get(key)
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
}

pub fn opt_u64(args: &Value, key: &str) -> Option<u64> {
    args.get(key).and_then(Value::as_u64)
}

pub fn opt_bool(args: &Value, key: &str) -> Option<bool> {
    args.get(key).and_then(Value::as_bool)
}

/// Every string of an optional array, in order.
pub fn strs<'a>(args: &'a Value, key: &str) -> Vec<&'a str> {
    args.get(key)
        .and_then(Value::as_array)
        .map(|items| items.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default()
}

/// A required string that is one of `allowed`: "{key} must be one of a, b".
pub fn one_of<'a>(args: &'a Value, key: &str, allowed: &[&str]) -> Result<&'a str, Failure> {
    let value = str(args, key)?;
    if allowed.contains(&value) {
        Ok(value)
    } else {
        Err(Failure::arguments(format!(
            "{key} must be one of {}",
            allowed.join(", ")
        )))
    }
}
