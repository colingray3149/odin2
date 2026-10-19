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
    use super::{
        append_canonical_value, append_identity_record, validate_container_identity_fields,
        ContainerIdentity, ContainerIdentityError, CONTAINER_IDENTITY_ENCODING,
    };
    use crate::schema::{ContainerMonitoringToml, ContainerToml, ContainerTunableValue};
    use odin_domain::Digest;

    const EXAMPLE_WORKER: &str = r#"
schema = "odin.registry.v1"
kind = "container"
enabled = true
description = "Monitored local-process fixture proving simulation, identity, slices, and ColinRemote surfaces."
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

    const EXAMPLE_WORKER_DIGEST: &str =
        "blake3:bc1aae686314298ec74de25a35669fa1cd13152ef7ac40a254254532ab706fad";

    const EXAMPLE_WORKER_BYTES: &[u8] = b"\"base\":\"local-process\"\n\"contents.kind\":\"scripts\"\n\"monitoring.slice\":\"example-watch\"\n\"purpose\":\"sweep-fixture\"\n";

    fn parse_container(source: &str) -> ContainerToml {
        toml::from_str(source).expect("container fixture must parse")
    }

    fn fields(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| (*value).to_owned()).collect()
    }

    fn stripped_container(identity_fields: &str) -> ContainerToml {
        parse_container(&format!(
            r#"
schema = "odin.registry.v1"
kind = "container"
enabled = true
description = "Identity fixture."
purpose = "sweep-fixture"
base = "local-process"
seats_offered = []
scripts = []
watchdogs = []
identity_fields = [{identity_fields}]
tunables = {{ cycles = 8 }}
surface = []

[contents]
kind = "scripts"

[monitoring]
slice = "example-watch"
cadence_seconds = 60
"#
        ))
    }

    #[test]
    fn example_worker_identity_matches_frozen_v1_bytes_and_digest() {
        assert_eq!(
            CONTAINER_IDENTITY_ENCODING,
            "odin.container-identity.fields.v1"
        );
        let identity = ContainerIdentity::calculate(&parse_container(EXAMPLE_WORKER)).unwrap();
        assert_eq!(identity.canonical_bytes(), EXAMPLE_WORKER_BYTES);
        assert_eq!(identity.digest().to_string(), EXAMPLE_WORKER_DIGEST);
        assert_eq!(Digest::hash(identity.canonical_bytes()), identity.digest());
        assert_eq!(
            identity,
            ContainerIdentity::calculate(&parse_container(EXAMPLE_WORKER)).unwrap()
        );
    }

    #[test]
    fn formatting_and_declaration_order_do_not_change_identity() {
        let identity = ContainerIdentity::calculate(&parse_container(EXAMPLE_WORKER)).unwrap();
        let reformatted = parse_container(
            r#"
description = "Monitored local-process fixture proving simulation, identity, slices, and ColinRemote surfaces."
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

    #[test]
    fn raw_declarations_reject_empty_duplicate_invalid_and_tunable_paths() {
        assert_eq!(
            validate_container_identity_fields(&fields(&[
                "purpose",
                "base",
                "contents.kind",
                "monitoring.slice"
            ])),
            Ok(())
        );
        let cases: Vec<(Vec<String>, ContainerIdentityError)> = vec![
            (fields(&[]), ContainerIdentityError::EmptyFields),
            (
                fields(&["purpose", "purpose"]),
                ContainerIdentityError::DuplicatePath {
                    path: "purpose".to_owned(),
                },
            ),
            (
                fields(&[""]),
                ContainerIdentityError::InvalidPath {
                    path: String::new(),
                },
            ),
            (
                fields(&["base."]),
                ContainerIdentityError::InvalidPath {
                    path: "base.".to_owned(),
                },
            ),
            (
                fields(&[".base"]),
                ContainerIdentityError::InvalidPath {
                    path: ".base".to_owned(),
                },
            ),
            (
                fields(&["tunables"]),
                ContainerIdentityError::TunablePath {
                    path: "tunables".to_owned(),
                },
            ),
            (
                fields(&["tunables.cycles"]),
                ContainerIdentityError::TunablePath {
                    path: "tunables.cycles".to_owned(),
                },
            ),
            (
                fields(&["tunables", "tunables"]),
                ContainerIdentityError::TunablePath {
                    path: "tunables".to_owned(),
                },
            ),
        ];
        for (declaration, expected) in cases {
            assert_eq!(
                validate_container_identity_fields(&declaration),
                Err(expected)
            );
        }
    }

    #[test]
    fn calculate_rejects_empty_invalid_tunable_and_missing_fields() {
        assert_eq!(
            ContainerIdentity::calculate(&stripped_container("")),
            Err(ContainerIdentityError::EmptyFields)
        );
        assert_eq!(
            ContainerIdentity::calculate(&stripped_container("\"purpose\", \"\"")),
            Err(ContainerIdentityError::InvalidPath {
                path: String::new()
            })
        );
        assert_eq!(
            ContainerIdentity::calculate(&stripped_container("\"purpose\", \"tunables\"")),
            Err(ContainerIdentityError::TunablePath {
                path: "tunables".to_owned(),
            })
        );
        assert_eq!(
            ContainerIdentity::calculate(&stripped_container("\"purpose\", \"tunables.cycles\"")),
            Err(ContainerIdentityError::TunablePath {
                path: "tunables.cycles".to_owned(),
            })
        );
        assert_eq!(
            ContainerIdentity::calculate(&stripped_container("\"purpose\", \"ghost.path\"")),
            Err(ContainerIdentityError::MissingField {
                path: "ghost.path".to_owned(),
            })
        );
        let mut unbound = stripped_container("\"purpose\", \"monitoring.slice\"");
        unbound.monitoring = ContainerMonitoringToml::None("none".to_owned());
        assert_eq!(
            ContainerIdentity::calculate(&unbound),
            Err(ContainerIdentityError::MissingField {
                path: "monitoring.slice".to_owned(),
            })
        );
    }

    #[test]
    fn scalar_encodings_are_frozen_and_floats_are_unsupported() {
        let mut out = Vec::new();
        let float = ContainerIdentityError::UnsupportedValue {
            path: "ratio".to_owned(),
            kind: "float",
        };
        assert_eq!(
            append_canonical_value(&mut out, "ratio", &toml::Value::Float(1.5)),
            Err(float.clone())
        );
        out.clear();
        assert_eq!(
            append_canonical_value(
                &mut out,
                "ratio",
                &toml::Value::Array(vec![toml::Value::Integer(1), toml::Value::Float(0.5)]),
            ),
            Err(float)
        );
        out.clear();
        append_canonical_value(
            &mut out,
            "flags",
            &toml::Value::Array(vec![
                toml::Value::Boolean(true),
                toml::Value::Boolean(false),
            ]),
        )
        .unwrap();
        assert_eq!(out, b"[true,false]");
        out.clear();
        append_canonical_value(&mut out, "debt", &toml::Value::Integer(-3)).unwrap();
        assert_eq!(out, b"-3");
        out.clear();
        let document = toml::from_str::<toml::Value>("a = 1\nb = 2").unwrap();
        append_canonical_value(&mut out, "pair", &document).unwrap();
        assert_eq!(out, b"{\"a\":1,\"b\":2}");
        let document = toml::from_str::<toml::Value>("stamp = 1979-05-27T07:32:00Z").unwrap();
        out.clear();
        append_canonical_value(&mut out, "stamp", document.get("stamp").unwrap()).unwrap();
        assert_eq!(out, b"\"1979-05-27T07:32:00Z\"");
    }

    #[test]
    fn paths_strings_and_table_keys_use_json_escaping() {
        let mut out = Vec::new();
        append_identity_record(
            &mut out,
            "quote\"path",
            &toml::Value::String("slash\\line\n".to_owned()),
        )
        .unwrap();
        assert_eq!(out, b"\"quote\\\"path\":\"slash\\\\line\\n\"\n");

        let mut table = toml::Table::new();
        table.insert("quote\"key".to_owned(), toml::Value::Boolean(true));
        out.clear();
        append_canonical_value(&mut out, "table", &toml::Value::Table(table)).unwrap();
        assert_eq!(out, b"{\"quote\\\"key\":true}");
    }
}
