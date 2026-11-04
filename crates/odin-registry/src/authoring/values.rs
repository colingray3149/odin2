//! Skeleton variable type parsing and typed TOML fill-value validation.

use std::collections::BTreeSet;
use std::path::{Component, Path};

use crate::schema::{is_handler_shell_syntax, valid_id, valid_media_type};

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) enum VariableType {
    Bool,
    Int {
        min: i64,
        max: i64,
    },
    IntOrEmpty,
    Enum(BTreeSet<String>),
    Id,
    IdOrEmpty,
    IdOrStar,
    String,
    /// Prose that may span lines: nonempty, newlines and tabs allowed.
    Text,
    StringOrEmpty,
    RelativePath,
    RelativePathOrEmpty,
    PathOrEmpty,
    Scalar,
    Url,
    SecretHandle,
    Handler,
    SchemaStem,
    MediaType,
    Expression,
    Handle,
    Table,
    Array(Box<VariableType>),
    Optional(Box<VariableType>),
}

#[derive(Clone, Debug, PartialEq)]
pub(super) enum FilledValue {
    Omitted,
    Value(toml::Value),
}

pub(super) fn parse_variable_type(value: &str) -> Result<VariableType, String> {
    if let Some(inner) = value
        .strip_prefix("array<")
        .and_then(|value| value.strip_suffix('>'))
    {
        if inner.is_empty() {
            return Err("array<T> must declare an element type".to_owned());
        }
        return Ok(VariableType::Array(Box::new(parse_variable_type(inner)?)));
    }
    if let Some(inner) = value
        .strip_prefix("optional<")
        .and_then(|value| value.strip_suffix('>'))
    {
        if inner.is_empty() {
            return Err("optional<T> must declare an inner type".to_owned());
        }
        if inner.starts_with("optional<") {
            return Err("nested optional<optional<T>> has no distinct TOML meaning".to_owned());
        }
        return Ok(VariableType::Optional(Box::new(parse_variable_type(
            inner,
        )?)));
    }
    let simple = match value {
        "bool" => Some(VariableType::Bool),
        "int-or-empty" => Some(VariableType::IntOrEmpty),
        "id" => Some(VariableType::Id),
        "id-or-empty" => Some(VariableType::IdOrEmpty),
        "id-or-star" => Some(VariableType::IdOrStar),
        "string" => Some(VariableType::String),
        "text" => Some(VariableType::Text),
        "string-or-empty" => Some(VariableType::StringOrEmpty),
        "relative-path" => Some(VariableType::RelativePath),
        "relative-path-or-empty" => Some(VariableType::RelativePathOrEmpty),
        "path-or-empty" => Some(VariableType::PathOrEmpty),
        "scalar" => Some(VariableType::Scalar),
        "url" => Some(VariableType::Url),
        "secret-handle" => Some(VariableType::SecretHandle),
        "handler" => Some(VariableType::Handler),
        "schema-stem" => Some(VariableType::SchemaStem),
        "media-type" => Some(VariableType::MediaType),
        "expression" => Some(VariableType::Expression),
        "handle" => Some(VariableType::Handle),
        "table" => Some(VariableType::Table),
        _ => None,
    };
    if let Some(variable_type) = simple {
        return Ok(variable_type);
    }
    if let Some(range) = value.strip_prefix("int:") {
        let mut bounds = range.split(':');
        let min = bounds
            .next()
            .and_then(|bound| bound.parse::<i64>().ok())
            .ok_or_else(|| "integer type has an invalid lower bound".to_owned())?;
        let max = bounds
            .next()
            .and_then(|bound| bound.parse::<i64>().ok())
            .ok_or_else(|| "integer type has an invalid upper bound".to_owned())?;
        if bounds.next().is_some() || min > max {
            return Err("integer type must declare exactly one ordered min:max range".to_owned());
        }
        return Ok(VariableType::Int { min, max });
    }
    if let Some(variants) = value.strip_prefix("enum:") {
        let values: Vec<&str> = variants.split('|').collect();
        if values.iter().any(|variant| variant.is_empty()) {
            return Err("enum type must declare nonempty alternatives".to_owned());
        }
        let alternatives: BTreeSet<String> =
            values.iter().map(|variant| (*variant).to_owned()).collect();
        if alternatives.len() != values.len() {
            return Err("enum type alternatives must be unique".to_owned());
        }
        return Ok(VariableType::Enum(alternatives));
    }
    Err(format!("unsupported skeleton variable type {value:?}"))
}

pub(super) fn parse_filled_value(
    variable_type: &VariableType,
    raw: &toml::Value,
) -> Result<FilledValue, String> {
    let string = || {
        raw.as_str()
            .ok_or_else(|| "value must be a TOML string".to_owned())
    };
    let accepted = match variable_type {
        VariableType::Optional(inner) => return parse_filled_value(inner, raw),
        VariableType::Array(inner) => {
            let values = raw
                .as_array()
                .ok_or_else(|| "value must be a typed TOML array".to_owned())?;
            let mut parsed = Vec::with_capacity(values.len());
            for value in values {
                match parse_filled_value(inner, value)? {
                    FilledValue::Value(value) => parsed.push(value),
                    FilledValue::Omitted => {
                        return Err("array elements cannot use omission sentinels".to_owned());
                    }
                }
            }
            toml::Value::Array(parsed)
        }
        VariableType::Table => {
            validate_typed_toml(raw)?;
            if !raw.is_table() {
                return Err("value must be a typed TOML table".to_owned());
            }
            raw.clone()
        }
        VariableType::Bool => toml::Value::Boolean(
            raw.as_bool()
                .ok_or_else(|| "value must be a TOML boolean".to_owned())?,
        ),
        VariableType::Int { min, max } => {
            let value = raw
                .as_integer()
                .ok_or_else(|| "value must be a TOML integer".to_owned())?;
            if value < *min || value > *max {
                return Err(format!("integer value must be in {min}..={max}"));
            }
            toml::Value::Integer(value)
        }
        VariableType::IntOrEmpty if raw.as_str() == Some("") => return Ok(FilledValue::Omitted),
        VariableType::IntOrEmpty => toml::Value::Integer(
            raw.as_integer()
                .ok_or_else(|| "optional integer must be omitted or a TOML integer".to_owned())?,
        ),
        VariableType::Enum(alternatives) => {
            let value = string()?;
            if !alternatives.contains(value) {
                return Err(format!(
                    "enum value must be one of {}",
                    alternatives.iter().cloned().collect::<Vec<_>>().join("|")
                ));
            }
            raw.clone()
        }
        VariableType::Id => {
            validate_stable_id(string()?)?;
            raw.clone()
        }
        VariableType::IdOrEmpty if raw.as_str() == Some("") => return Ok(FilledValue::Omitted),
        VariableType::IdOrEmpty => {
            validate_stable_id(string()?)?;
            raw.clone()
        }
        VariableType::IdOrStar if raw.as_str() == Some("") => return Ok(FilledValue::Omitted),
        VariableType::IdOrStar => {
            let value = string()?;
            if value != "*" {
                validate_stable_id(value)?;
            }
            raw.clone()
        }
        VariableType::String => {
            validate_text(string()?, false)?;
            raw.clone()
        }
        VariableType::Text => {
            let value = string()?;
            if value.trim().is_empty()
                || value
                    .chars()
                    .any(|character| character.is_control() && !matches!(character, '\n' | '\t'))
            {
                return Err(
                    "text value must be nonempty with no control characters except newline and tab"
                        .to_owned(),
                );
            }
            raw.clone()
        }
        VariableType::StringOrEmpty => {
            validate_text(string()?, true)?;
            raw.clone()
        }
        VariableType::RelativePath => {
            validate_relative_reference(string()?)?;
            raw.clone()
        }
        VariableType::RelativePathOrEmpty if raw.as_str() == Some("") => {
            return Ok(FilledValue::Omitted);
        }
        VariableType::RelativePathOrEmpty => {
            validate_relative_reference(string()?)?;
            raw.clone()
        }
        VariableType::PathOrEmpty => {
            let value = string()?;
            if !value.is_empty() {
                validate_path_reference(value)?;
            }
            raw.clone()
        }
        VariableType::Scalar => {
            if !matches!(
                raw,
                toml::Value::String(_) | toml::Value::Integer(_) | toml::Value::Boolean(_)
            ) {
                return Err("scalar must be a TOML string, integer, or boolean".to_owned());
            }
            raw.clone()
        }
        VariableType::Url => {
            let value = string()?;
            validate_text(value, false)?;
            let authority = value
                .strip_prefix("http://")
                .or_else(|| value.strip_prefix("https://"))
                .ok_or_else(|| "URL must use http:// or https://".to_owned())?;
            if authority.is_empty() || authority.chars().any(char::is_whitespace) {
                return Err("URL must contain a nonempty authority without whitespace".to_owned());
            }
            raw.clone()
        }
        VariableType::SecretHandle | VariableType::SchemaStem => {
            validate_stable_id(string()?)?;
            raw.clone()
        }
        VariableType::Handler => {
            let value = string()?;
            validate_text(value, false)?;
            if value.chars().any(is_handler_shell_syntax) {
                return Err(
                    "handler contains shell syntax; use a typed builtin or exec argv reference"
                        .to_owned(),
                );
            }
            raw.clone()
        }
        VariableType::MediaType => {
            let value = string()?;
            if !valid_media_type(value) || value.chars().any(char::is_whitespace) {
                return Err(
                    "media type must be a nonempty type/subtype without whitespace".to_owned(),
                );
            }
            raw.clone()
        }
        VariableType::Expression => {
            validate_text(string()?, false)?;
            raw.clone()
        }
        VariableType::Handle => {
            let value = string()?;
            validate_text(value, false)?;
            if value.chars().any(is_handler_shell_syntax) {
                return Err("surface handle must not contain shell syntax".to_owned());
            }
            raw.clone()
        }
    };
    Ok(FilledValue::Value(accepted))
}

fn validate_typed_toml(value: &toml::Value) -> Result<(), String> {
    match value {
        toml::Value::Float(_) | toml::Value::Datetime(_) => {
            Err("fill values cannot contain floats or TOML datetimes".to_owned())
        }
        toml::Value::Array(values) => {
            for value in values {
                validate_typed_toml(value)?;
            }
            Ok(())
        }
        toml::Value::Table(values) => {
            for value in values.values() {
                validate_typed_toml(value)?;
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

pub(super) fn validate_stable_id(value: &str) -> Result<(), String> {
    valid_id(value)
        .then_some(())
        .ok_or_else(|| "ID must match [A-Za-z0-9][A-Za-z0-9._-]*".to_owned())
}

fn validate_text(value: &str, allow_empty: bool) -> Result<(), String> {
    if (!allow_empty && value.trim().is_empty()) || value.chars().any(char::is_control) {
        return Err(if allow_empty {
            "string value must not contain control characters".to_owned()
        } else {
            "string value must be nonempty and contain no control characters".to_owned()
        });
    }
    Ok(())
}

fn validate_relative_reference(value: &str) -> Result<(), String> {
    validate_path(value, false)
}

fn validate_path_reference(value: &str) -> Result<(), String> {
    validate_path(value, true)
}

fn validate_path(value: &str, allow_absolute: bool) -> Result<(), String> {
    validate_text(value, false)?;
    let noun = if allow_absolute {
        "path"
    } else {
        "relative path"
    };
    let mut saw_normal = false;
    for component in Path::new(value).components() {
        match component {
            Component::Normal(_) => saw_normal = true,
            Component::CurDir => {}
            Component::ParentDir => {
                return Err(format!("{noun} must not traverse through a parent"));
            }
            Component::RootDir | Component::Prefix(_) if allow_absolute => {}
            Component::RootDir | Component::Prefix(_) => {
                return Err("relative path must not be absolute".to_owned());
            }
        }
    }
    saw_normal.then_some(()).ok_or_else(|| {
        format!(
            "{noun} must name {}",
            if allow_absolute {
                "a filesystem location"
            } else {
                "a descendant"
            }
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn text(value: &str) -> toml::Value {
        toml::Value::String(value.to_owned())
    }

    fn accepted(kind: &str, value: toml::Value) -> bool {
        parse_filled_value(&parse_variable_type(kind).unwrap(), &value).is_ok()
    }

    #[test]
    fn a_filled_value_must_fit_its_declared_type() {
        let cases = [
            ("int:1:10", 5.into(), true),
            ("int:1:10", 11.into(), false),
            ("int:1:10", text("5"), false),
            ("enum:a|b", text("b"), true),
            ("enum:a|b", text("c"), false),
            ("url", text("https://example.org/x"), true),
            ("url", text("ftp://example.org"), false),
            ("url", text("https://"), false),
            ("relative-path", text("a/b.txt"), true),
            ("relative-path", text("../b"), false),
            ("relative-path", text("/etc/passwd"), false),
            ("path-or-empty", text("/srv/data"), true),
            ("path-or-empty", text("/srv/../etc"), false),
            ("handler", text("odin-tool"), true),
            ("handler", text("tool; rm -rf /"), false),
            ("id", text("web.read"), true),
            ("id", text("-leading"), false),
            (
                "array<id>",
                toml::Value::Array(vec![text("a"), text("b")]),
                true,
            ),
            (
                "array<id>",
                toml::Value::Array(vec![text("a"), text("b c")]),
                false,
            ),
            ("table", toml::Value::Table(toml::Table::new()), true),
            (
                "table",
                toml::Value::Table(toml::Table::from_iter([("n".to_owned(), 1.5.into())])),
                false,
            ),
        ];
        for (kind, value, ok) in cases {
            assert_eq!(accepted(kind, value.clone()), ok, "{kind} {value}");
        }
        assert_eq!(
            parse_filled_value(&parse_variable_type("id-or-empty").unwrap(), &text("")),
            Ok(FilledValue::Omitted)
        );
    }
}
