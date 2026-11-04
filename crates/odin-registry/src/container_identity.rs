//! Hash selected typed fields in sorted order so formatting and tunable changes do not alter identity.

use std::collections::BTreeSet;
use std::fmt;

use odin_domain::Digest;
use serde::ser::SerializeStruct;
use serde::{Serialize, Serializer};

use crate::schema::{lookup_toml_path, ContainerToml};

pub const CONTAINER_IDENTITY_ENCODING: &str = "odin.container-identity.fields.v1";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ContainerIdentity {
    digest: Digest,
    canonical_bytes: Vec<u8>,
}

impl ContainerIdentity {
    pub fn calculate(container: &ContainerToml) -> Result<Self, ContainerIdentityError> {
        if container.identity_fields.is_empty() {
            return Err(ContainerIdentityError::EmptyFields);
        }
        let document = toml::Value::try_from(container)
            .map_err(|error| ContainerIdentityError::Serialize(error.to_string()))?;
        let mut canonical_bytes = Vec::new();
        for field in &container.identity_fields {
            validate_declared_path(field)?;
            let value = lookup_toml_path(&document, field).ok_or_else(|| {
                ContainerIdentityError::MissingField {
                    path: field.clone(),
                }
            })?;
            append_identity_record(&mut canonical_bytes, field, value)?;
        }
        Ok(Self {
            digest: Digest::hash(&canonical_bytes),
            canonical_bytes,
        })
    }

    pub const fn digest(&self) -> Digest {
        self.digest
    }

    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical_bytes
    }
}

impl Serialize for ContainerIdentity {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("ContainerIdentity", 3)?;
        state.serialize_field("encoding", CONTAINER_IDENTITY_ENCODING)?;
        state.serialize_field("digest", &self.digest)?;
        state.serialize_field("canonical_bytes", &HexBytes(&self.canonical_bytes))?;
        state.end()
    }
}

struct HexBytes<'a>(&'a [u8]);

impl fmt::Display for HexBytes<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(formatter, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl Serialize for HexBytes<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.collect_str(self)
    }
}

/// Validate before set deserialization can erase duplicate declarations.
pub fn validate_container_identity_fields(fields: &[String]) -> Result<(), ContainerIdentityError> {
    if fields.is_empty() {
        return Err(ContainerIdentityError::EmptyFields);
    }
    let mut seen = BTreeSet::new();
    for field in fields {
        if !seen.insert(field.as_str()) {
            return Err(ContainerIdentityError::DuplicatePath {
                path: field.clone(),
            });
        }
        validate_declared_path(field)?;
    }
    Ok(())
}

#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ContainerIdentityError {
    #[error("identity_fields must contain at least one canonical field path")]
    EmptyFields,
    #[error("identity field {path:?} is declared more than once")]
    DuplicatePath { path: String },
    #[error("identity field {path:?} is not a nonempty dot-separated path")]
    InvalidPath { path: String },
    #[error("identity field {path:?} points into tunables")]
    TunablePath { path: String },
    #[error("identity field {path:?} does not resolve in the container config")]
    MissingField { path: String },
    #[error("identity field {path:?} contains an unsupported {kind} value")]
    UnsupportedValue { path: String, kind: &'static str },
    #[error("identity material serialization failed: {0}")]
    Serialize(String),
}

pub(crate) fn validate_declared_path(path: &str) -> Result<(), ContainerIdentityError> {
    if path.is_empty() || path.split('.').any(str::is_empty) {
        return Err(ContainerIdentityError::InvalidPath {
            path: path.to_owned(),
        });
    }
    if path == "tunables" || path.starts_with("tunables.") {
        return Err(ContainerIdentityError::TunablePath {
            path: path.to_owned(),
        });
    }
    Ok(())
}

fn append_identity_record(
    canonical: &mut Vec<u8>,
    path: &str,
    value: &toml::Value,
) -> Result<(), ContainerIdentityError> {
    serde_json::to_writer(&mut *canonical, path)
        .map_err(|error| ContainerIdentityError::Serialize(error.to_string()))?;
    canonical.push(b':');
    append_canonical_value(canonical, path, value)?;
    canonical.push(b'\n');
    Ok(())
}

fn append_canonical_value(
    canonical: &mut Vec<u8>,
    path: &str,
    value: &toml::Value,
) -> Result<(), ContainerIdentityError> {
    match value {
        toml::Value::String(value) => {
            serde_json::to_writer(&mut *canonical, value)
                .map_err(|error| ContainerIdentityError::Serialize(error.to_string()))?;
        }
        toml::Value::Integer(value) => {
            use std::io::Write as _;
            write!(canonical, "{value}")
                .map_err(|error| ContainerIdentityError::Serialize(error.to_string()))?;
        }
        toml::Value::Boolean(value) => {
            canonical.extend_from_slice(if *value { b"true" as &[u8] } else { b"false" });
        }
        toml::Value::Datetime(value) => {
            serde_json::to_writer(&mut *canonical, &value.to_string())
                .map_err(|error| ContainerIdentityError::Serialize(error.to_string()))?;
        }
        toml::Value::Float(_) => {
            return Err(ContainerIdentityError::UnsupportedValue {
                path: path.to_owned(),
                kind: "float",
            });
        }
        toml::Value::Array(values) => {
            canonical.push(b'[');
            for (index, value) in values.iter().enumerate() {
                if index != 0 {
                    canonical.push(b',');
                }
                append_canonical_value(canonical, path, value)?;
            }
            canonical.push(b']');
        }
        toml::Value::Table(values) => {
            canonical.push(b'{');
            let mut entries = values.iter().collect::<Vec<_>>();
            entries.sort_unstable_by_key(|(key, _)| *key);
            for (index, (key, value)) in entries.into_iter().enumerate() {
                if index != 0 {
                    canonical.push(b',');
                }
                serde_json::to_writer(&mut *canonical, key)
                    .map_err(|error| ContainerIdentityError::Serialize(error.to_string()))?;
                canonical.push(b':');
                append_canonical_value(canonical, path, value)?;
            }
            canonical.push(b'}');
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::ContainerIdentity;
    use crate::schema::{ContainerToml, ContainerTunableValue};

    const EXAMPLE_WORKER: &str = r#"
schema = "odin.registry.v1"
kind = "container"
enabled = true
description = "Monitored local-process fixture proving simulation, identity, slices, and Remote surfaces."
purpose = "sweep-fixture"
base = "local-process"
seats_offered = []
scripts = []
watchdogs = []
identity_fields = ["purpose", "base", "contents.kind", "monitoring.slice"]
tunables = { cycles = 8 }
surface = ["status", "last-result"]

[contents]
kind = "scripts"

[monitoring]
slice = "example-watch"
cadence_seconds = 60
"#;

    fn parse_container(source: &str) -> ContainerToml {
        toml::from_str(source).expect("container fixture must parse")
    }

    #[test]
    fn formatting_and_declaration_order_do_not_change_identity() {
        let identity = ContainerIdentity::calculate(&parse_container(EXAMPLE_WORKER)).unwrap();
        let reformatted = parse_container(
            r#"
description = "Monitored local-process fixture proving simulation, identity, slices, and Remote surfaces."
kind = "container"
purpose = 'sweep-fixture'
identity_fields = ["monitoring.slice", "purpose", "base", "contents.kind"]
schema = "odin.registry.v1"
base = "local-process"
enabled = true
watchdogs = []
scripts = []
seats_offered = []
surface = ["last-result", "status"]
tunables = { cycles = 8 }

[contents]
kind = "scripts"

[monitoring]
cadence_seconds = 60
slice = "example-watch"
"#,
        );
        assert_eq!(
            identity,
            ContainerIdentity::calculate(&reformatted).unwrap()
        );
    }

    #[test]
    fn selected_field_changes_move_identity_and_undeclared_changes_do_not() {
        let container = parse_container(EXAMPLE_WORKER);
        let identity = ContainerIdentity::calculate(&container).unwrap();

        let mut changed = container.clone();
        changed.purpose = "sweep-fixture-2".to_owned();
        assert_ne!(identity, ContainerIdentity::calculate(&changed).unwrap());

        let mut dropped = container.clone();
        dropped.identity_fields.remove("base");
        assert_ne!(identity, ContainerIdentity::calculate(&dropped).unwrap());

        let mut added = container.clone();
        added.identity_fields.insert("monitoring".to_owned());
        let added = ContainerIdentity::calculate(&added).unwrap();
        assert_ne!(identity, added);
        assert!(String::from_utf8_lossy(added.canonical_bytes())
            .contains("\"monitoring\":{\"cadence_seconds\":60,\"slice\":\"example-watch\"}"));

        let mut untouched = container.clone();
        untouched.description = "Unrelated edit.".to_owned();
        untouched.enabled = !untouched.enabled;
        untouched.surface.clear();
        untouched
            .tunables
            .insert("cycles".to_owned(), ContainerTunableValue::Integer(9));
        assert_eq!(identity, ContainerIdentity::calculate(&untouched).unwrap());
    }
}
