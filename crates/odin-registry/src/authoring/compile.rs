//! Render skeletons as typed TOML rather than substituting unvalidated text.

use std::collections::{BTreeMap, BTreeSet};
use std::num::NonZeroU16;
use std::path::{Path, PathBuf};

use odin_domain::{ContainerId, SliceId};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use super::contracts::{
    blank_name, issue, AuthoringErrors, AuthoringIssue, FillDocumentSource, FillRequest,
    FillValues, SkeletonCatalog, SkeletonContract, SkeletonKind,
};
use super::values::FilledValue;
use crate::relational::AdmittedBinding;
use crate::schema::{
    valid_id, CapabilityToml, ClaudeCodeToml, ContainerAlertSeverityToml, ContainerAlertToml,
    ContainerSurfaceDefinitionToml, ContainerSurfaceKindToml, ContainerSurfaceToml, ContainerToml,
    ContainerWatchdogToml, HostToml, LaneToml, NodeToml, ObjectConfig, ProjectToml, ProviderToml,
    RegistryKind, SeatToml, SliceToml, WorkloadProfileToml, CLAUDE_CODE_HARNESS,
};

pub const AUTHORING_FILL_SCHEMA: &str = "odin.authoring.fill.v1";

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FillDocument {
    schema: String,
    fill: Vec<FillDocumentEntry>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FillDocumentEntry {
    skeleton: SkeletonKind,
    destination_id: String,
    values: toml::Table,
}

/// Defer cross-file relations to validate_fill_batch so references see all compiled documents.
pub fn compile_fill_documents(
    catalog: &SkeletonCatalog,
    sources: impl IntoIterator<Item = FillDocumentSource>,
    admitted_bindings: &[AdmittedBinding],
) -> Result<Vec<CompiledFill>, AuthoringErrors> {
    let mut issues = Vec::new();
    let mut compiled = Vec::new();
    let mut seen_sources = BTreeSet::new();
    for source in sources {
        if source.relative_path.is_absolute()
            || source
                .relative_path
                .extension()
                .and_then(|value| value.to_str())
                != Some("toml")
            || !source
                .relative_path
                .file_name()
                .and_then(|value| value.to_str())
                .is_some_and(|name| name.ends_with(".fill.toml"))
        {
            issues.push(issue(
                "authoring-fill-path",
                &source.relative_path,
                None::<String>,
                "committed fill path must be relative and end in .fill.toml",
            ));
            continue;
        }
        if !seen_sources.insert(source.relative_path.clone()) {
            issues.push(issue(
                "authoring-fill-duplicate-source",
                &source.relative_path,
                None::<String>,
                "fill source path was supplied more than once",
            ));
            continue;
        }
        let document: FillDocument = match toml::from_str(&source.source) {
            Ok(document) => document,
            Err(error) => {
                issues.push(issue(
                    "authoring-fill-parse",
                    &source.relative_path,
                    None::<String>,
                    format!("strict typed fill TOML rejected: {error}"),
                ));
                continue;
            }
        };
        if document.schema != AUTHORING_FILL_SCHEMA {
            issues.push(issue(
                "authoring-fill-schema",
                &source.relative_path,
                None::<String>,
                format!(
                    "fill schema must be {AUTHORING_FILL_SCHEMA:?}, found {:?}",
                    document.schema
                ),
            ));
            continue;
        }
        if document.fill.is_empty() {
            issues.push(issue(
                "authoring-fill-empty",
                &source.relative_path,
                None::<String>,
                "fill document must contain at least one [[fill]] entry",
            ));
            continue;
        }
        for entry in document.fill {
            match catalog.compile_with_bindings(
                FillRequest {
                    skeleton: entry.skeleton,
                    destination_id: entry.destination_id,
                    values: FillValues(entry.values),
                },
                admitted_bindings,
            ) {
                Ok(fill) => compiled.push(fill),
                Err(error) => issues.extend(error.issues),
            }
        }
    }
    let mut destinations = BTreeMap::<PathBuf, SkeletonKind>::new();
    for fill in &compiled {
        let destination = fill.destination.relative_config().to_path_buf();
        if let Some(first) = destinations.insert(destination.clone(), fill.skeleton) {
            issues.push(issue(
                "authoring-duplicate-destination",
                destination,
                None::<String>,
                format!(
                    "batch destinations collide between {first:?} and {:?}",
                    fill.skeleton
                ),
            ));
        }
    }
    if issues.is_empty() {
        compiled.sort_by(|left, right| {
            left.destination
                .relative_config()
                .cmp(right.destination.relative_config())
        });
        Ok(compiled)
    } else {
        Err(AuthoringErrors::new(issues))
    }
}

/// Derive destination paths in the compiler rather than accepting caller paths.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum AuthoringDestination {
    RegistryObject {
        kind: RegistryKind,
        id: String,
        relative_config: PathBuf,
    },
    ContainerPatch {
        container: ContainerId,
        relative_config: PathBuf,
    },
}

impl AuthoringDestination {
    pub fn relative_config(&self) -> &Path {
        match self {
            Self::RegistryObject {
                relative_config, ..
            }
            | Self::ContainerPatch {
                relative_config, ..
            } => relative_config,
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum ContainerPatch {
    AppendWatchdog(ContainerWatchdogToml),
    AppendSurface(ContainerSurfaceToml),
}

#[derive(Clone, Debug, PartialEq)]
pub enum CompiledDocument {
    Registry(ObjectConfig),
    ContainerPatch(ContainerPatch),
}

#[derive(Clone, Debug, PartialEq)]
pub struct CompiledFill {
    pub skeleton: SkeletonKind,
    pub destination: AuthoringDestination,
    pub document: CompiledDocument,
    pub canonical_toml: Vec<u8>,
}

fn render_template(
    contract: &SkeletonContract,
    filled: &BTreeMap<String, FilledValue>,
) -> Result<toml::Value, AuthoringErrors> {
    let mut issues = Vec::new();
    let rendered = substitute_value(
        &contract.template,
        filled,
        &contract.template_path,
        &mut issues,
    );
    if !issues.is_empty() {
        return Err(AuthoringErrors::new(issues));
    }
    rendered.ok_or_else(|| {
        AuthoringErrors::single(issue(
            "authoring-template-empty",
            &contract.template_path,
            None::<String>,
            "top-level template cannot be omitted",
        ))
    })
}

fn substitute_value(
    value: &toml::Value,
    filled: &BTreeMap<String, FilledValue>,
    path: &Path,
    issues: &mut Vec<AuthoringIssue>,
) -> Option<toml::Value> {
    match value {
        toml::Value::String(value) => substitute_string(value, filled, path, issues),
        toml::Value::Array(values) => {
            let values = values
                .iter()
                .filter_map(|value| substitute_value(value, filled, path, issues))
                .collect();
            Some(toml::Value::Array(values))
        }
        toml::Value::Table(values) => {
            let mut rendered = toml::map::Map::new();
            for (key, value) in values {
                let Some(key) = substitute_key(key, filled, path, issues) else {
                    continue;
                };
                let Some(value) = substitute_value(value, filled, path, issues) else {
                    continue;
                };
                if rendered.insert(key.clone(), value).is_some() {
                    issues.push(issue(
                        "authoring-key-collision",
                        path,
                        Some(key),
                        "dynamic table key collides with another rendered key",
                    ));
                }
            }
            // Omit empty optional sections so they do not declare invalid fieldless configuration.
            if rendered.is_empty() && !values.is_empty() {
                return None;
            }
            Some(toml::Value::Table(rendered))
        }
        value => Some(value.clone()),
    }
}

fn substitute_key(
    key: &str,
    filled: &BTreeMap<String, FilledValue>,
    path: &Path,
    issues: &mut Vec<AuthoringIssue>,
) -> Option<String> {
    let Some(name) = blank_name(key) else {
        return Some(key.to_owned());
    };
    match filled.get(name) {
        Some(FilledValue::Value(toml::Value::String(value))) if valid_id(value) => {
            Some(value.clone())
        }
        Some(FilledValue::Omitted) => {
            issues.push(issue(
                "authoring-key-omitted",
                path,
                Some(name),
                "dynamic table key cannot be omitted",
            ));
            None
        }
        Some(_) => {
            issues.push(issue(
                "authoring-key-invalid",
                path,
                Some(name),
                "dynamic table key must render as a stable ID",
            ));
            None
        }
        None => {
            issues.push(issue(
                "authoring-value-missing",
                path,
                Some(name),
                "dynamic table key has no compiled fill value",
            ));
            None
        }
    }
}

fn substitute_string(
    value: &str,
    filled: &BTreeMap<String, FilledValue>,
    path: &Path,
    issues: &mut Vec<AuthoringIssue>,
) -> Option<toml::Value> {
    if let Some(name) = blank_name(value) {
        return match filled.get(name) {
            Some(FilledValue::Value(value)) => Some(value.clone()),
            Some(FilledValue::Omitted) => None,
            None => {
                issues.push(issue(
                    "authoring-value-missing",
                    path,
                    Some(name),
                    "template blank has no compiled fill value",
                ));
                None
            }
        };
    }

    let mut rendered = String::with_capacity(value.len());
    let mut cursor = 0;
    let mut replaced = false;
    while let Some(open_relative) = value[cursor..].find("__") {
        let open = cursor + open_relative;
        let value_start = open + 2;
        let Some(close_relative) = value[value_start..].find("__") else {
            break;
        };
        let close = value_start + close_relative;
        let name = &value[value_start..close];
        rendered.push_str(&value[cursor..open]);
        match filled.get(name) {
            Some(FilledValue::Value(value)) => match scalar_text(value) {
                Some(value) => rendered.push_str(&value),
                None => issues.push(issue(
                    "authoring-value-invalid",
                    path,
                    Some(name),
                    "embedded blank must render as a scalar",
                )),
            },
            Some(FilledValue::Omitted) => issues.push(issue(
                "authoring-value-invalid",
                path,
                Some(name),
                "embedded blank cannot be omitted",
            )),
            None => issues.push(issue(
                "authoring-value-missing",
                path,
                Some(name),
                "embedded blank has no compiled fill value",
            )),
        }
        cursor = close + 2;
        replaced = true;
    }
    if !replaced {
        return Some(toml::Value::String(value.to_owned()));
    }
    rendered.push_str(&value[cursor..]);
    Some(toml::Value::String(rendered))
}

fn scalar_text(value: &toml::Value) -> Option<String> {
    match value {
        toml::Value::String(value) => Some(value.clone()),
        toml::Value::Integer(value) => Some(value.to_string()),
        toml::Value::Boolean(value) => Some(value.to_string()),
        _ => None,
    }
}

pub(super) fn compile_registry(
    contract: &SkeletonContract,
    destination_id: String,
    filled: &BTreeMap<String, FilledValue>,
    admitted_bindings: &[AdmittedBinding],
) -> Result<CompiledFill, AuthoringErrors> {
    let Some(kind) = contract.registry_kind() else {
        return Err(AuthoringErrors::single(issue(
            "authoring-fill-mismatch",
            &contract.template_path,
            None::<String>,
            "registry compilation received a structured patch skeleton",
        )));
    };
    let document = render_template(contract, filled)?;
    let config = match kind {
        RegistryKind::Seat => ObjectConfig::Seat(Box::new(deserialize_template::<SeatToml>(
            document, contract, kind,
        )?)),
        RegistryKind::Project => {
            ObjectConfig::Project(Box::new(deserialize_template::<ProjectToml>(
                document, contract, kind,
            )?))
        }
        RegistryKind::Lane => ObjectConfig::Lane(Box::new(deserialize_template::<LaneToml>(
            document, contract, kind,
        )?)),
        RegistryKind::Node => ObjectConfig::Node(Box::new(deserialize_template::<NodeToml>(
            document, contract, kind,
        )?)),
        RegistryKind::Provider => {
            ObjectConfig::Provider(Box::new(deserialize_template::<ProviderToml>(
                document, contract, kind,
            )?))
        }
        RegistryKind::Capability => ObjectConfig::Capability(Box::new(
            resolve_capability_template(document, contract, admitted_bindings)?,
        )),
        RegistryKind::Slice => ObjectConfig::Slice(Box::new(deserialize_template::<SliceToml>(
            document, contract, kind,
        )?)),
        RegistryKind::Container => {
            ObjectConfig::Container(Box::new(deserialize_template::<ContainerToml>(
                document, contract, kind,
            )?))
        }
        RegistryKind::Host => ObjectConfig::Host(Box::new(deserialize_template::<HostToml>(
            document, contract, kind,
        )?)),
        RegistryKind::Workload => {
            if document.get("harness").and_then(toml::Value::as_str) == Some(CLAUDE_CODE_HARNESS) {
                ObjectConfig::ClaudeCode(Box::new(deserialize_template::<ClaudeCodeToml>(
                    document, contract, kind,
                )?))
            } else {
                ObjectConfig::Workload(Box::new(deserialize_template::<WorkloadProfileToml>(
                    document, contract, kind,
                )?))
            }
        }
        RegistryKind::Routine => {
            ObjectConfig::Routine(Box::new(
                deserialize_template::<crate::schema::RoutineToml>(document, contract, kind)?,
            ))
        }
        RegistryKind::Harness => {
            ObjectConfig::Harness(Box::new(
                deserialize_template::<crate::schema::HarnessToml>(document, contract, kind)?,
            ))
        }
        RegistryKind::Environment => {
            ObjectConfig::Environment(Box::new(deserialize_template::<
                crate::schema::EnvironmentToml,
            >(document, contract, kind)?))
        }
        RegistryKind::ContextProfile => {
            ObjectConfig::ContextProfile(Box::new(deserialize_template::<
                crate::schema::ContextProfileToml,
            >(document, contract, kind)?))
        }
    };
    let relative_config = canonical_relative_config(kind, &destination_id);
    let canonical_toml = canonical_config_toml(&config).map_err(|message| {
        AuthoringErrors::single(issue(
            "authoring-serialize",
            &relative_config,
            None::<String>,
            message,
        ))
    })?;
    Ok(CompiledFill {
        skeleton: contract.kind,
        destination: AuthoringDestination::RegistryObject {
            kind,
            id: destination_id,
            relative_config,
        },
        document: CompiledDocument::Registry(config),
        canonical_toml,
    })
}

fn resolve_capability_template(
    document: toml::Value,
    contract: &SkeletonContract,
    admitted_bindings: &[AdmittedBinding],
) -> Result<CapabilityToml, AuthoringErrors> {
    let mut table = document.as_table().cloned().ok_or_else(|| {
        AuthoringErrors::single(issue(
            "authoring-shape",
            &contract.template_path,
            None::<String>,
            "capability template must render as a TOML table",
        ))
    })?;
    let binding_id = table
        .remove("binding_id")
        .and_then(|value| value.as_str().map(str::to_owned))
        .ok_or_else(|| {
            AuthoringErrors::single(issue(
                "authoring-binding-id",
                &contract.template_path,
                Some("binding_id"),
                "capability fill must select one admitted binding ID",
            ))
        })?;
    let mut selected = None;
    for binding in admitted_bindings {
        let candidate_id = binding.binding_id().map_err(|error| {
            AuthoringErrors::single(issue(
                "authoring-binding-canonical",
                &contract.template_path,
                Some("binding_id"),
                format!("could not derive admitted binding ID: {error}"),
            ))
        })?;
        if candidate_id == binding_id {
            if selected.is_some() {
                return Err(AuthoringErrors::single(issue(
                    "authoring-binding-duplicate",
                    &contract.template_path,
                    Some("binding_id"),
                    format!("more than one admitted tuple uses binding ID {binding_id:?}"),
                )));
            }
            selected = Some(binding);
        }
    }
    let binding = selected.ok_or_else(|| {
        AuthoringErrors::single(issue(
            "authoring-binding-unknown",
            &contract.template_path,
            Some("binding_id"),
            format!("binding ID {binding_id:?} is not in the compiled admitted catalog"),
        ))
    })?;
    let insert =
        |table: &mut toml::Table, name: &str, value: toml::Value| -> Result<(), AuthoringErrors> {
            if table.insert(name.to_owned(), value).is_some() {
                return Err(AuthoringErrors::single(issue(
                    "authoring-binding-overwrite",
                    &contract.template_path,
                    Some(name),
                    "template attempted to override an admitted binding field",
                )));
            }
            Ok(())
        };
    insert(
        &mut table,
        "implementation",
        toml::Value::String(format!("admitted:{binding_id}")),
    )?;
    insert(
        &mut table,
        "version",
        toml::Value::Integer(i64::from(binding.version)),
    )?;
    insert(
        &mut table,
        "input_schema",
        toml::Value::String(binding.input_schema.clone()),
    )?;
    insert(
        &mut table,
        "output_schema",
        toml::Value::String(binding.output_schema.clone()),
    )?;
    insert(
        &mut table,
        "handler",
        toml::Value::try_from(&binding.handler).map_err(|error| {
            AuthoringErrors::single(issue(
                "authoring-binding-canonical",
                &contract.template_path,
                Some("binding_id"),
                format!("could not serialize admitted handler: {error}"),
            ))
        })?,
    )?;
    insert(
        &mut table,
        "evidence_extractor",
        toml::Value::try_from(&binding.evidence_extractor).map_err(|error| {
            AuthoringErrors::single(issue(
                "authoring-binding-canonical",
                &contract.template_path,
                Some("binding_id"),
                format!("could not serialize admitted evidence extractor: {error}"),
            ))
        })?,
    )?;
    deserialize_template::<CapabilityToml>(
        toml::Value::Table(table),
        contract,
        RegistryKind::Capability,
    )
}

fn deserialize_template<T: DeserializeOwned>(
    document: toml::Value,
    contract: &SkeletonContract,
    kind: RegistryKind,
) -> Result<T, AuthoringErrors> {
    T::deserialize(document).map_err(|error| {
        AuthoringErrors::single(issue(
            "authoring-shape",
            &contract.template_path,
            None::<String>,
            format!("filled template is not a strict {kind} document: {error}"),
        ))
    })
}

pub(super) fn canonical_config_toml(config: &ObjectConfig) -> Result<Vec<u8>, String> {
    match config {
        ObjectConfig::Seat(value) => canonical_toml_bytes(value.as_ref()),
        ObjectConfig::Project(value) => canonical_toml_bytes(value.as_ref()),
        ObjectConfig::Lane(value) => canonical_toml_bytes(value.as_ref()),
        ObjectConfig::Node(value) => canonical_toml_bytes(value.as_ref()),
        ObjectConfig::Provider(value) => canonical_toml_bytes(value.as_ref()),
        ObjectConfig::Capability(value) => canonical_toml_bytes(value.as_ref()),
        ObjectConfig::Slice(value) => canonical_toml_bytes(value.as_ref()),
        ObjectConfig::Container(value) => canonical_toml_bytes(value.as_ref()),
        ObjectConfig::Host(value) => canonical_toml_bytes(value.as_ref()),
        ObjectConfig::Workload(value) => canonical_toml_bytes(value.as_ref()),
        ObjectConfig::ClaudeCode(value) => canonical_toml_bytes(value.as_ref()),
        ObjectConfig::Routine(value) => canonical_toml_bytes(value.as_ref()),
        ObjectConfig::Harness(value) => canonical_toml_bytes(value.as_ref()),
        ObjectConfig::Environment(value) => canonical_toml_bytes(value.as_ref()),
        ObjectConfig::ContextProfile(value) => canonical_toml_bytes(value.as_ref()),
    }
}

pub(super) fn compile_patch(
    contract: &SkeletonContract,
    destination_id: String,
    filled: &BTreeMap<String, FilledValue>,
) -> Result<CompiledFill, AuthoringErrors> {
    let rendered = render_template(contract, filled)?;
    let patch = compile_patch_document(contract, filled).map_err(AuthoringErrors::single)?;
    let container = ContainerId::new(destination_id.clone()).map_err(|error| {
        AuthoringErrors::single(issue(
            "authoring-destination-id",
            &contract.variables_path,
            None::<String>,
            format!("container destination is invalid: {error}"),
        ))
    })?;
    let relative_config = canonical_relative_config(RegistryKind::Container, &destination_id);
    let canonical_toml = canonical_toml_bytes(&rendered).map_err(|message| {
        AuthoringErrors::single(issue(
            "authoring-serialize",
            &contract.template_path,
            None::<String>,
            message,
        ))
    })?;
    Ok(CompiledFill {
        skeleton: contract.kind,
        destination: AuthoringDestination::ContainerPatch {
            container,
            relative_config,
        },
        document: CompiledDocument::ContainerPatch(patch),
        canonical_toml,
    })
}

fn compile_patch_document(
    contract: &SkeletonContract,
    filled: &BTreeMap<String, FilledValue>,
) -> Result<ContainerPatch, AuthoringIssue> {
    match contract.kind {
        SkeletonKind::NewAlert => {
            let hits = u16::try_from(filled_integer(
                filled,
                "consecutive_hits",
                &contract.variables_path,
            )?)
            .ok()
            .and_then(NonZeroU16::new)
            .ok_or_else(|| {
                issue(
                    "authoring-value-invalid",
                    &contract.variables_path,
                    Some("consecutive_hits"),
                    "consecutive_hits is not representable as a nonzero u16",
                )
            })?;
            let cooldown_seconds = u32::try_from(filled_integer(
                filled,
                "cooldown_seconds",
                &contract.variables_path,
            )?)
            .map_err(|_| {
                issue(
                    "authoring-value-invalid",
                    &contract.variables_path,
                    Some("cooldown_seconds"),
                    "cooldown_seconds is not representable as u32",
                )
            })?;
            let slice_value = filled_string(filled, "slice", &contract.variables_path)?;
            let slice = SliceId::new(slice_value).map_err(|error| {
                issue(
                    "authoring-value-invalid",
                    &contract.variables_path,
                    Some("slice"),
                    format!("slice ID is invalid: {error}"),
                )
            })?;
            Ok(ContainerPatch::AppendWatchdog(
                ContainerWatchdogToml::Alert(ContainerAlertToml {
                    id: filled_string(filled, "alert_id", &contract.variables_path)?,
                    condition: filled_string(filled, "condition", &contract.variables_path)?,
                    consecutive_hits: hits,
                    cooldown_seconds,
                    severity: filled_typed::<ContainerAlertSeverityToml>(
                        filled,
                        "severity",
                        &contract.variables_path,
                    )?,
                    slice,
                    action: Default::default(),
                }),
            ))
        }
        SkeletonKind::NewSurface => {
            let refresh_seconds = u32::try_from(filled_integer(
                filled,
                "refresh_seconds",
                &contract.variables_path,
            )?)
            .map_err(|_| {
                issue(
                    "authoring-value-invalid",
                    &contract.variables_path,
                    Some("refresh_seconds"),
                    "refresh_seconds is not representable as u32",
                )
            })?;
            Ok(ContainerPatch::AppendSurface(
                ContainerSurfaceToml::Definition(ContainerSurfaceDefinitionToml {
                    id: filled_string(filled, "surface_id", &contract.variables_path)?,
                    kind: filled_typed::<ContainerSurfaceKindToml>(
                        filled,
                        "surface_kind",
                        &contract.variables_path,
                    )?,
                    source: filled_string(filled, "source", &contract.variables_path)?,
                    media_type: filled_string(filled, "media_type", &contract.variables_path)?,
                    refresh_seconds,
                    renderer: filled_optional_string(filled, "renderer", &contract.variables_path)?,
                }),
            ))
        }
        _ => Err(issue(
            "authoring-fill-mismatch",
            &contract.template_path,
            None::<String>,
            "structured patch compilation received a registry skeleton",
        )),
    }
}

fn filled_string(
    filled: &BTreeMap<String, FilledValue>,
    name: &str,
    path: &Path,
) -> Result<String, AuthoringIssue> {
    match filled.get(name) {
        Some(FilledValue::Value(toml::Value::String(value))) => Ok(value.clone()),
        _ => Err(issue(
            "authoring-value-invalid",
            path,
            Some(name),
            "compiled value is not the required string",
        )),
    }
}

fn filled_optional_string(
    filled: &BTreeMap<String, FilledValue>,
    name: &str,
    path: &Path,
) -> Result<Option<String>, AuthoringIssue> {
    match filled.get(name) {
        Some(FilledValue::Omitted) => Ok(None),
        Some(FilledValue::Value(toml::Value::String(value))) => Ok(Some(value.clone())),
        _ => Err(issue(
            "authoring-value-invalid",
            path,
            Some(name),
            "compiled value is not the required optional string",
        )),
    }
}

fn filled_integer(
    filled: &BTreeMap<String, FilledValue>,
    name: &str,
    path: &Path,
) -> Result<i64, AuthoringIssue> {
    match filled.get(name) {
        Some(FilledValue::Value(toml::Value::Integer(value))) => Ok(*value),
        _ => Err(issue(
            "authoring-value-invalid",
            path,
            Some(name),
            "compiled value is not the required integer",
        )),
    }
}

fn filled_typed<T: DeserializeOwned>(
    filled: &BTreeMap<String, FilledValue>,
    name: &str,
    path: &Path,
) -> Result<T, AuthoringIssue> {
    let Some(FilledValue::Value(value)) = filled.get(name) else {
        return Err(issue(
            "authoring-value-invalid",
            path,
            Some(name),
            "compiled value is missing or omitted",
        ));
    };
    T::deserialize(value.clone()).map_err(|error| {
        issue(
            "authoring-value-invalid",
            path,
            Some(name),
            format!("compiled value has the wrong strict shape: {error}"),
        )
    })
}

pub(super) fn canonical_relative_config(kind: RegistryKind, id: &str) -> PathBuf {
    PathBuf::from("registry")
        .join(kind.directory())
        .join(id)
        .join(kind.config_name())
}

pub(super) fn apply_container_patch(
    container: &mut ContainerToml,
    patch: &ContainerPatch,
    relative_config: &Path,
) -> Result<(), AuthoringIssue> {
    match patch {
        ContainerPatch::AppendWatchdog(watchdog) => {
            if let ContainerWatchdogToml::Alert(candidate) = watchdog {
                let duplicate_id = container.watchdogs.iter().any(|watchdog| {
                    matches!(
                        watchdog,
                        ContainerWatchdogToml::Alert(existing) if existing.id == candidate.id
                    )
                });
                if duplicate_id {
                    return Err(issue(
                        "authoring-patch-collision",
                        relative_config,
                        Some(&candidate.id),
                        "container already declares this watchdog alert ID",
                    ));
                }
            }
            if !container.watchdogs.insert(watchdog.clone()) {
                return Err(issue(
                    "authoring-patch-collision",
                    relative_config,
                    None::<String>,
                    "container already contains this watchdog",
                ));
            }
        }
        ContainerPatch::AppendSurface(surface) => {
            let candidate_id = surface_id(surface);
            if container
                .surface
                .iter()
                .any(|existing| surface_id(existing) == candidate_id)
            {
                return Err(issue(
                    "authoring-patch-collision",
                    relative_config,
                    Some(candidate_id),
                    "container already declares this surface ID",
                ));
            }
            container.surface.insert(surface.clone());
        }
    }
    Ok(())
}

/// Share patch application with staging so alert and surface ID collisions are rejected consistently.
pub fn patch_container_source(
    container_id: &str,
    relative_config: &Path,
    source: &str,
    patch: &ContainerPatch,
) -> Result<String, AuthoringErrors> {
    let mut container: ContainerToml = toml::from_str(source).map_err(|error| {
        AuthoringErrors::single(issue(
            "authoring-source-parse",
            relative_config,
            Some(container_id),
            format!("container declaration does not parse: {error}"),
        ))
    })?;
    apply_container_patch(&mut container, patch, relative_config)
        .map_err(AuthoringErrors::single)?;
    let bytes = canonical_toml_bytes(&container).map_err(|message| {
        AuthoringErrors::single(issue(
            "authoring-serialize",
            relative_config,
            Some(container_id),
            message,
        ))
    })?;
    String::from_utf8(bytes).map_err(|_| {
        AuthoringErrors::single(issue(
            "authoring-serialize",
            relative_config,
            Some(container_id),
            "canonical TOML bytes are not valid UTF-8",
        ))
    })
}

fn surface_id(surface: &ContainerSurfaceToml) -> &str {
    match surface {
        ContainerSurfaceToml::Id(id) => id,
        ContainerSurfaceToml::Definition(definition) => &definition.id,
    }
}

pub(super) fn canonical_toml_bytes<T: Serialize>(value: &T) -> Result<Vec<u8>, String> {
    let mut source = toml::to_string(value)
        .map_err(|error| format!("canonical TOML serialization failed: {error}"))?;
    if !source.ends_with('\n') {
        source.push('\n');
    }
    Ok(source.into_bytes())
}

#[cfg(test)]
mod claude_tests {
    use super::*;

    #[test]
    fn workload_authoring_dispatches_claude_and_roundtrips_canonical_toml() {
        let skeletons = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../skeletons");
        let catalog = SkeletonCatalog::load(skeletons).expect("load skeleton catalog");
        let mut contract = catalog
            .contract(SkeletonKind::NewWorkload)
            .expect("workload contract")
            .clone();
        contract.template = toml::from_str(
            r#"schema = "odin.registry.v1"
kind = "workload"
enabled = false
description = "Authored Claude driver"
harness = "claude-code"
account_kind = "claude-code"
accounts = "discovered"
image = { reference = "platform" }
resources = { cpu_request = "1", cpu_limit = "2", memory_request = "1Gi", memory_limit = "2Gi", storage_limit = "4Gi" }
"#,
        )
        .expect("Claude template");
        let compiled = compile_registry(&contract, "claude".to_owned(), &BTreeMap::new(), &[])
            .expect("compile Claude workload");
        let CompiledDocument::Registry(config) = &compiled.document else {
            panic!("workload authoring must produce registry config");
        };
        assert!(matches!(config, ObjectConfig::ClaudeCode(_)));
        assert_eq!(config.kind(), RegistryKind::Workload);
        assert!(!config.enabled());
        let source = std::str::from_utf8(&compiled.canonical_toml).expect("canonical UTF-8");
        let parsed = crate::schema::parse_object_toml(
            RegistryKind::Workload,
            "claude",
            "workloads/claude/profile.toml",
            source,
        )
        .expect("parse authored Claude workload");
        assert_eq!(&parsed.config, config);
    }
}
