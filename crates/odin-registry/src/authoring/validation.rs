//! Validate the combined registry so batch references are checked together.

use std::collections::BTreeSet;

use super::compile::{
    apply_container_patch, canonical_config_toml, canonical_relative_config, AuthoringDestination,
    CompiledDocument, CompiledFill, ContainerPatch,
};
use super::contracts::{issue, issue_from_finding, AuthoringErrors, AuthoringIssue, SkeletonKind};
use super::ValidatedFillBatch;
use crate::relational::{validate as validate_relations, RelationContext};
use crate::schema::{
    valid_id, validate_object, ContainerSurfaceToml, ContainerWatchdogToml, ObjectConfig,
    RegistryKind, RegistryObject,
};
use crate::RegistryFinding;

pub fn validate_fill_batch(
    fills: Vec<CompiledFill>,
    existing: &[RegistryObject],
    context: &RelationContext,
) -> Result<ValidatedFillBatch, AuthoringErrors> {
    if fills.is_empty() {
        return Err(AuthoringErrors::single(issue(
            "authoring-fill-empty",
            "registry",
            None::<String>,
            "authoring batch must contain at least one compiled fill",
        )));
    }
    let mut issues = Vec::new();
    let mut destinations = BTreeSet::new();
    for fill in &fills {
        issues.extend(validate_compiled_fill(fill));
        if !destinations.insert(fill.destination.relative_config().to_path_buf()) {
            issues.push(issue(
                "authoring-duplicate-destination",
                fill.destination.relative_config(),
                None::<String>,
                "batch contains more than one write to the same canonical destination",
            ));
        }
    }
    if !issues.is_empty() {
        return Err(AuthoringErrors::new(issues));
    }

    let mut combined = existing.to_vec();
    for fill in &fills {
        let changed = match (&fill.destination, &fill.document) {
            (
                AuthoringDestination::RegistryObject {
                    kind,
                    id,
                    relative_config,
                },
                CompiledDocument::Registry(config),
            ) => {
                if combined
                    .iter()
                    .any(|object| object.kind() == *kind && object.id == *id)
                {
                    issues.push(issue(
                        "authoring-id-collision",
                        relative_config,
                        None::<String>,
                        "canonical destination already contains this kind and ID",
                    ));
                }
                if combined
                    .iter()
                    .any(|object| object.relative_config == *relative_config)
                {
                    issues.push(issue(
                        "authoring-path-collision",
                        relative_config,
                        None::<String>,
                        "canonical destination path already belongs to a registry object",
                    ));
                }
                Some(RegistryObject {
                    id: id.clone(),
                    relative_config: relative_config.clone(),
                    config: config.clone(),
                })
            }
            (
                AuthoringDestination::ContainerPatch {
                    container,
                    relative_config,
                },
                CompiledDocument::ContainerPatch(patch),
            ) => match combined.iter().position(|object| {
                object.kind() == RegistryKind::Container && object.id == container.as_str()
            }) {
                Some(index) => {
                    let mut object = combined.remove(index);
                    match &mut object.config {
                        ObjectConfig::Container(value) => {
                            if let Err(problem) =
                                apply_container_patch(value, patch, relative_config)
                            {
                                issues.push(problem);
                            }
                        }
                        _ => issues.push(issue(
                            "authoring-fill-mismatch",
                            relative_config,
                            None::<String>,
                            "container patch destination resolved to a non-container object",
                        )),
                    }
                    Some(object)
                }
                None => {
                    issues.push(issue(
                        "authoring-patch-target-missing",
                        relative_config,
                        None::<String>,
                        "container patch target does not exist in the combined registry",
                    ));
                    None
                }
            },
            _ => {
                issues.push(issue(
                    "authoring-fill-mismatch",
                    fill.destination.relative_config(),
                    None::<String>,
                    "compiled document does not match its canonical destination",
                ));
                None
            }
        };
        if let Some(changed) = changed {
            issues.extend(
                validate_object(&changed)
                    .into_iter()
                    .filter(RegistryFinding::is_failure)
                    .map(issue_from_finding),
            );
            combined.push(changed);
        }
    }
    combined.sort_by(|left, right| {
        (left.kind(), left.id.as_str()).cmp(&(right.kind(), right.id.as_str()))
    });
    issues.extend(
        validate_relations(&combined, context)
            .into_iter()
            .filter(RegistryFinding::is_failure)
            .map(issue_from_finding),
    );
    if !issues.is_empty() {
        return Err(AuthoringErrors::new(issues));
    }
    Ok(ValidatedFillBatch {
        compiled: fills,
        combined,
    })
}
fn validate_compiled_fill(fill: &CompiledFill) -> Vec<AuthoringIssue> {
    let mut issues = Vec::new();
    match (&fill.destination, &fill.document) {
        (
            AuthoringDestination::RegistryObject {
                kind,
                id,
                relative_config,
            },
            CompiledDocument::Registry(config),
        ) => {
            if fill.skeleton.registry_kind() != Some(*kind) || config.kind() != *kind {
                issues.push(issue(
                    "authoring-fill-mismatch",
                    relative_config,
                    None::<String>,
                    "registry skeleton, destination kind, and document kind must agree",
                ));
            }
            if !valid_id(id) {
                issues.push(issue(
                    "authoring-destination-id",
                    relative_config,
                    None::<String>,
                    "registry destination ID is not stable",
                ));
            }
            if *relative_config != canonical_relative_config(*kind, id) {
                issues.push(issue(
                    "authoring-destination-path",
                    relative_config,
                    None::<String>,
                    "registry destination is not compiler-canonical",
                ));
            }
            match canonical_config_toml(config) {
                Ok(expected) if expected == fill.canonical_toml => {}
                Ok(_) => issues.push(issue(
                    "authoring-canonical-drift",
                    relative_config,
                    None::<String>,
                    "compiled TOML does not match the typed registry document",
                )),
                Err(message) => issues.push(issue(
                    "authoring-serialize",
                    relative_config,
                    None::<String>,
                    message,
                )),
            }
        }
        (
            AuthoringDestination::ContainerPatch {
                container,
                relative_config,
            },
            CompiledDocument::ContainerPatch(patch),
        ) => {
            let operation_matches = matches!(
                (fill.skeleton, patch),
                (
                    SkeletonKind::NewAlert,
                    ContainerPatch::AppendWatchdog(ContainerWatchdogToml::Alert(_))
                ) | (
                    SkeletonKind::NewSurface,
                    ContainerPatch::AppendSurface(ContainerSurfaceToml::Definition(_))
                )
            );
            if !operation_matches {
                issues.push(issue(
                    "authoring-fill-mismatch",
                    relative_config,
                    None::<String>,
                    "structured patch skeleton and operation must agree",
                ));
            }
            if *relative_config
                != canonical_relative_config(RegistryKind::Container, container.as_str())
            {
                issues.push(issue(
                    "authoring-destination-path",
                    relative_config,
                    None::<String>,
                    "container patch destination is not compiler-canonical",
                ));
            }
        }
        _ => {}
    }
    issues
}
