use std::ffi::OsStr;
use std::fs;
use std::path::{Component, Path, PathBuf};

use crate::schema::RegistryObject;
use crate::RegistryFinding;

use super::context::RelationContext;

pub(super) fn validate_regular_file(
    object: &RegistryObject,
    field: &str,
    relative: &Path,
    absolute: &Path,
    context: &RelationContext,
    findings: &mut Vec<RegistryFinding>,
) -> bool {
    let metadata = match fs::symlink_metadata(absolute) {
        Ok(metadata) => metadata,
        Err(error) => {
            findings.push(relation_failure(
                object,
                format!(
                    "{field} reference {} cannot be resolved: {error}",
                    relative.display()
                ),
            ));
            return false;
        }
    };
    if !metadata.file_type().is_file() {
        findings.push(relation_failure(
            object,
            format!(
                "{field} reference {} is not a regular file",
                relative.display()
            ),
        ));
        return false;
    }
    let canonical_root = fs::canonicalize(&context.odin_root);
    let canonical_file = fs::canonicalize(absolute);
    match (canonical_root, canonical_file) {
        (Ok(root), Ok(file)) if file.starts_with(&root) => true,
        (Ok(_), Ok(_)) => {
            findings.push(relation_failure(
                object,
                format!(
                    "{field} reference {} escapes the Odin root",
                    relative.display()
                ),
            ));
            false
        }
        (Err(error), _) | (_, Err(error)) => {
            findings.push(relation_failure(
                object,
                format!(
                    "{field} reference {} cannot be canonicalized: {error}",
                    relative.display()
                ),
            ));
            false
        }
    }
}

pub(super) fn normalize_relative(reference: &str) -> Result<PathBuf, &'static str> {
    if reference.trim().is_empty() {
        return Err("reference is empty");
    }
    let path = Path::new(reference);
    if path.is_absolute() {
        return Err("absolute paths are not allowed");
    }
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Normal(value) => normalized.push(value),
            Component::CurDir => {}
            Component::ParentDir => return Err("parent traversal is not allowed"),
            Component::RootDir | Component::Prefix(_) => return Err("path is not relative"),
        }
    }
    Ok(normalized)
}

pub(crate) fn sorted_paths(path: &Path) -> std::io::Result<Vec<PathBuf>> {
    let mut entries = fs::read_dir(path)?
        .map(|entry| entry.map(|entry| entry.path()))
        .collect::<Result<Vec<_>, _>>()?;
    entries.sort();
    Ok(entries)
}

/// `path` below `root` as `<root's folder name>/<rest>`, `fallback` naming a nameless root.
pub(crate) fn display_path(root: &Path, path: &Path, fallback: &str) -> PathBuf {
    let prefix = root
        .file_name()
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(fallback));
    path.strip_prefix(root)
        .map(|relative| prefix.join(relative))
        .unwrap_or_else(|_| path.to_path_buf())
}

pub(crate) fn ignored(name: &OsStr) -> bool {
    name.as_encoded_bytes().starts_with(b".") || name == OsStr::new("_disabled")
}

pub(super) fn relative_to_odin(context: &RelationContext, path: &Path) -> PathBuf {
    path.strip_prefix(&context.odin_root)
        .map(Path::to_path_buf)
        .unwrap_or_else(|_| path.to_path_buf())
}

pub(super) fn relation_failure(
    object: &RegistryObject,
    message: impl Into<String>,
) -> RegistryFinding {
    RegistryFinding::fail("registry-broken-relation", &object.relative_config, message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::relational::fixtures::bound_capability;

    #[test]
    fn a_reference_through_a_symlinked_directory_out_of_the_root_is_refused() {
        let outside = tempfile::tempdir().unwrap();
        fs::write(outside.path().join("x.json"), "{}").unwrap();
        let root = tempfile::tempdir().unwrap();
        fs::create_dir_all(root.path().join("schemas")).unwrap();
        fs::write(root.path().join("schemas/inside.json"), "{}").unwrap();
        std::os::unix::fs::symlink(outside.path(), root.path().join("schemas/capability")).unwrap();
        let context = RelationContext::new(root.path());
        let (object, _) = bound_capability();
        let check = |relative: &str| {
            let relative = Path::new(relative);
            let mut findings = Vec::new();
            let admitted = validate_regular_file(
                &object,
                "input_schema",
                relative,
                &root.path().join(relative),
                &context,
                &mut findings,
            );
            (admitted, findings)
        };
        assert!(check("schemas/inside.json").0);
        let (admitted, findings) = check("schemas/capability/x.json");
        assert!(!admitted);
        assert!(
            findings[0].message.contains("escapes the Odin root"),
            "{findings:?}"
        );
    }
}
