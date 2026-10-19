use std::ffi::OsStr;
use std::fs;
use std::path::{Path, PathBuf};

use crate::RegistryFinding;

use super::context::RelationContext;
use super::migration::MIGRATION_REGISTRY;
use super::paths::{ignored, relative_to_odin, sorted_paths};

pub(super) fn inspect_schema_catalog(context: &RelationContext) -> Vec<RegistryFinding> {
    let mut findings = Vec::new();
    match fs::symlink_metadata(&context.schemas_root) {
        Ok(metadata) if metadata.file_type().is_dir() => {}
        Ok(_) => {
            findings.push(RegistryFinding::fail(
                "schema-root-type",
                PathBuf::from("schemas"),
                "schemas root must be a regular directory",
            ));
            return findings;
        }
        Err(error) => {
            findings.push(RegistryFinding::fail(
                "schema-root-read",
                PathBuf::from("schemas"),
                format!("could not inspect schemas root: {error}"),
            ));
            return findings;
        }
    }
    let entries = match sorted_paths(&context.schemas_root) {
        Ok(entries) => entries,
        Err(error) => {
            findings.push(RegistryFinding::fail(
                "schema-root-read",
                PathBuf::from("schemas"),
                format!("could not read schemas root: {error}"),
            ));
            return findings;
        }
    };
    for path in entries {
        let name = path.file_name().unwrap_or_default();
        if ignored(name) {
            continue;
        }
        let relative = relative_to_odin(context, &path);
        let metadata = match fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) => {
                findings.push(RegistryFinding::fail(
                    "schema-entry-type",
                    &relative,
                    format!("could not inspect schema entry: {error}"),
                ));
                continue;
            }
        };
        if metadata.file_type().is_symlink() {
            findings.push(RegistryFinding::fail(
                "schema-entry-symlink",
                &relative,
                "schema authority cannot be supplied through a symlink",
            ));
        } else if metadata.file_type().is_dir() {
            if !matches!(name.to_str(), Some("capability" | "control" | "inventory")) {
                findings.push(RegistryFinding::flag(
                    "schema-unknown-kind",
                    &relative,
                    "unknown schema kind is not registry authority",
                ));
                continue;
            }
            inspect_schema_kind(context, &path, &mut findings);
        } else if !metadata.file_type().is_file() {
            findings.push(RegistryFinding::fail(
                "schema-entry-type",
                &relative,
                "schema-root entry must be a regular file or directory",
            ));
        } else if !MIGRATION_REGISTRY
            .iter()
            .any(|record| name == OsStr::new(record.file_name()))
        {
            findings.push(RegistryFinding::flag(
                "schema-anomalous-entry",
                &relative,
                "unexpected schema-root entry",
            ));
        }
    }
    findings
}

fn inspect_schema_kind(
    context: &RelationContext,
    directory: &Path,
    findings: &mut Vec<RegistryFinding>,
) {
    let entries = match sorted_paths(directory) {
        Ok(entries) => entries,
        Err(error) => {
            findings.push(RegistryFinding::fail(
                "schema-kind-read",
                relative_to_odin(context, directory),
                format!("could not read schema kind: {error}"),
            ));
            return;
        }
    };
    for path in entries {
        let name = path.file_name().unwrap_or_default();
        if ignored(name) {
            continue;
        }
        let relative = relative_to_odin(context, &path);
        let metadata = match fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) => {
                findings.push(RegistryFinding::fail(
                    "schema-entry-type",
                    &relative,
                    format!("could not inspect schema entry: {error}"),
                ));
                continue;
            }
        };
        if metadata.file_type().is_symlink() {
            findings.push(RegistryFinding::fail(
                "schema-entry-symlink",
                &relative,
                "JSON schema must be a regular file, not a symlink",
            ));
            continue;
        }
        if metadata.file_type().is_dir() {
            findings.push(RegistryFinding::flag(
                "schema-anomalous-folder",
                &relative,
                "nested schema folder is not an admitted schema kind",
            ));
            continue;
        }
        if !metadata.file_type().is_file() {
            findings.push(RegistryFinding::fail(
                "schema-entry-type",
                &relative,
                "schema kind entry must be a regular file",
            ));
            continue;
        }
        if path.extension() != Some(OsStr::new("json")) {
            findings.push(RegistryFinding::flag(
                "schema-anomalous-entry",
                &relative,
                "schema kind contains a non-JSON entry",
            ));
            continue;
        }
        let source = match fs::read_to_string(&path) {
            Ok(source) => source,
            Err(error) => {
                findings.push(RegistryFinding::fail(
                    "schema-read",
                    &relative,
                    format!("could not read JSON schema: {error}"),
                ));
                continue;
            }
        };
        match serde_json::from_str::<serde_json::Value>(&source) {
            Ok(serde_json::Value::Object(schema)) => {
                if schema
                    .get("$schema")
                    .and_then(serde_json::Value::as_str)
                    .is_none_or(str::is_empty)
                {
                    findings.push(RegistryFinding::fail(
                        "schema-dialect",
                        &relative,
                        "JSON schema requires a nonempty $schema dialect",
                    ));
                }
            }
            Ok(_) => findings.push(RegistryFinding::fail(
                "schema-shape",
                &relative,
                "JSON schema root must be an object",
            )),
            Err(error) => findings.push(RegistryFinding::fail(
                "schema-json",
                &relative,
                format!("malformed JSON schema: {error}"),
            )),
        }
    }
}
