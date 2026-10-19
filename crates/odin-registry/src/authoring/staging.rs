//! Stage validated fills privately so authoring cannot mutate the live registry.

use std::fmt::Write as _;
use std::fs::{self, OpenOptions};
use std::io::{ErrorKind, Write};
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use odin_domain::Digest;
use serde::Serialize;

use super::compile::{
    apply_container_patch, canonical_toml_bytes, AuthoringDestination, CompiledDocument,
};
use super::contracts::{issue, issue_from_finding, AuthoringErrors, AuthoringIssue, SkeletonKind};
use super::{ValidatedFill, ValidatedFillBatch};
use crate::schema::{parse_object_toml, validate_object, ObjectConfig, RegistryKind};
use crate::RegistryFinding;

static BATCH_STAGING_SEQUENCE: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum StagedChange {
    Create,
    Modify,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct StagedDiffMetadata {
    pub skeleton: SkeletonKind,
    pub destination: PathBuf,
    pub change: StagedChange,
    pub before_digest: Option<Digest>,
    pub after_digest: Digest,
    pub canonical_bytes: u64,
}

/// The unified diff can be applied with git apply.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StagedFill {
    pub staged_path: PathBuf,
    pub unified_diff: String,
    pub metadata: StagedDiffMetadata,
}

/// Write only below staging_root, never odin_root.
pub fn stage_fill(
    fill: &ValidatedFill,
    odin_root: &Path,
    staging_root: &Path,
) -> Result<StagedFill, AuthoringErrors> {
    let staging_root = validated_staging_root(odin_root, staging_root)?;
    let relative = fill.compiled.destination.relative_config().to_path_buf();
    validate_destination_path(&relative).map_err(AuthoringErrors::single)?;
    let source_path = odin_root.join(&relative);

    let (change, before, after) = match &fill.compiled.document {
        CompiledDocument::Registry(_) => {
            match fs::symlink_metadata(&source_path) {
                Err(error) if error.kind() == ErrorKind::NotFound => {}
                Ok(_) => {
                    return Err(AuthoringErrors::single(issue(
                        "authoring-source-collision",
                        &relative,
                        None::<String>,
                        "create destination already exists below the Odin root",
                    )));
                }
                Err(error) => {
                    return Err(AuthoringErrors::single(issue(
                        "authoring-source-read",
                        &relative,
                        None::<String>,
                        format!("could not inspect create destination: {error}"),
                    )));
                }
            }
            (
                StagedChange::Create,
                None,
                fill.compiled.canonical_toml.clone(),
            )
        }
        CompiledDocument::ContainerPatch(patch) => {
            let metadata = fs::symlink_metadata(&source_path).map_err(|error| {
                AuthoringErrors::single(issue(
                    "authoring-source-read",
                    &relative,
                    None::<String>,
                    format!("could not inspect patch target: {error}"),
                ))
            })?;
            if !metadata.file_type().is_file() {
                return Err(AuthoringErrors::single(issue(
                    "authoring-source-type",
                    &relative,
                    None::<String>,
                    "patch target must be a regular file",
                )));
            }
            let before = fs::read(&source_path).map_err(|error| {
                AuthoringErrors::single(issue(
                    "authoring-source-read",
                    &relative,
                    None::<String>,
                    format!("could not read patch target: {error}"),
                ))
            })?;
            let source = std::str::from_utf8(&before).map_err(|_| {
                AuthoringErrors::single(issue(
                    "authoring-source-utf8",
                    &relative,
                    None::<String>,
                    "patch target is not valid UTF-8 TOML",
                ))
            })?;
            let container_id = match &fill.compiled.destination {
                AuthoringDestination::ContainerPatch { container, .. } => container.as_str(),
                _ => {
                    return Err(AuthoringErrors::single(issue(
                        "authoring-fill-mismatch",
                        &relative,
                        None::<String>,
                        "container patch lacks a container destination",
                    )));
                }
            };
            let mut object = parse_object_toml(
                RegistryKind::Container,
                container_id.to_owned(),
                relative.clone(),
                source,
            )
            .map_err(|finding| AuthoringErrors::single(issue_from_finding(finding)))?;
            {
                let ObjectConfig::Container(container) = &mut object.config else {
                    return Err(AuthoringErrors::single(issue(
                        "authoring-fill-mismatch",
                        &relative,
                        None::<String>,
                        "patch target did not parse as a container",
                    )));
                };
                apply_container_patch(container, patch, &relative)
                    .map_err(AuthoringErrors::single)?;
            }
            let shape_failures: Vec<_> = validate_object(&object)
                .into_iter()
                .filter(RegistryFinding::is_failure)
                .map(issue_from_finding)
                .collect();
            if !shape_failures.is_empty() {
                return Err(AuthoringErrors::new(shape_failures));
            }
            let expected = fill.combined.iter().find(|candidate| {
                candidate.kind() == RegistryKind::Container && candidate.id == container_id
            });
            if expected.is_none_or(|expected| expected.config != object.config) {
                return Err(AuthoringErrors::single(issue(
                    "authoring-source-drift",
                    &relative,
                    None::<String>,
                    "patch target no longer matches the independently validated container state",
                )));
            }
            let after = match &object.config {
                ObjectConfig::Container(container) => {
                    canonical_toml_bytes(container).map_err(|message| {
                        AuthoringErrors::single(issue(
                            "authoring-serialize",
                            &relative,
                            None::<String>,
                            message,
                        ))
                    })?
                }
                _ => {
                    return Err(AuthoringErrors::single(issue(
                        "authoring-fill-mismatch",
                        &relative,
                        None::<String>,
                        "patched object is not a container",
                    )));
                }
            };
            (StagedChange::Modify, Some(before), after)
        }
    };

    let before_source = before
        .as_deref()
        .map(std::str::from_utf8)
        .transpose()
        .map_err(|_| {
            AuthoringErrors::single(issue(
                "authoring-source-utf8",
                &relative,
                None::<String>,
                "existing destination is not valid UTF-8",
            ))
        })?
        .unwrap_or_default();
    let after_source = std::str::from_utf8(&after).map_err(|_| {
        AuthoringErrors::single(issue(
            "authoring-serialize",
            &relative,
            None::<String>,
            "canonical TOML bytes are not valid UTF-8",
        ))
    })?;
    let unified_diff = build_unified_diff(before_source, after_source, &relative, change);
    let canonical_bytes = u64::try_from(after.len()).map_err(|_| {
        AuthoringErrors::single(issue(
            "authoring-size-overflow",
            &relative,
            None::<String>,
            "canonical TOML byte length is not representable as u64",
        ))
    })?;
    let metadata = StagedDiffMetadata {
        skeleton: fill.compiled.skeleton,
        destination: relative.clone(),
        change,
        before_digest: before.as_deref().map(Digest::hash),
        after_digest: Digest::hash(&after),
        canonical_bytes,
    };
    let staged_path = write_beneath(&staging_root, &relative, &after)?;
    Ok(StagedFill {
        staged_path,
        unified_diff,
        metadata,
    })
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StagedFillBatch {
    pub staging_root: PathBuf,
    pub changes: Vec<StagedFill>,
    pub batch_digest: Digest,
}

/// Rename the completed private tree atomically so failed staging cannot expose a partial batch.
pub fn stage_fill_batch(
    batch: &ValidatedFillBatch,
    odin_root: &Path,
    staging_root: &Path,
) -> Result<StagedFillBatch, AuthoringErrors> {
    if batch.compiled.is_empty() {
        return Err(AuthoringErrors::single(issue(
            "authoring-fill-empty",
            staging_root,
            None::<String>,
            "validated batch contains no fills",
        )));
    }
    match fs::symlink_metadata(staging_root) {
        Err(error) if error.kind() == ErrorKind::NotFound => {}
        Ok(_) => {
            return Err(AuthoringErrors::single(issue(
                "authoring-staging-collision",
                staging_root,
                None::<String>,
                "requested atomic staging root already exists",
            )));
        }
        Err(error) => {
            return Err(AuthoringErrors::single(issue(
                "authoring-staging-root-read",
                staging_root,
                None::<String>,
                format!("could not inspect requested staging root: {error}"),
            )));
        }
    }
    let parent = staging_root.parent().ok_or_else(|| {
        AuthoringErrors::single(issue(
            "authoring-staging-root-path",
            staging_root,
            None::<String>,
            "staging root must have a parent directory",
        ))
    })?;
    fs::create_dir_all(parent).map_err(|error| {
        AuthoringErrors::single(issue(
            "authoring-staging-root-write",
            parent,
            None::<String>,
            format!("could not create staging parent: {error}"),
        ))
    })?;
    let leaf = staging_root
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or_else(|| {
            AuthoringErrors::single(issue(
                "authoring-staging-root-path",
                staging_root,
                None::<String>,
                "staging root must have a UTF-8 leaf name",
            ))
        })?;
    let sequence = BATCH_STAGING_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let private_root = parent.join(format!(
        ".{leaf}.odin-private-{}-{sequence}",
        std::process::id()
    ));
    if private_root.try_exists().map_err(|error| {
        AuthoringErrors::single(issue(
            "authoring-staging-root-read",
            &private_root,
            None::<String>,
            format!("could not inspect private staging root: {error}"),
        ))
    })? {
        return Err(AuthoringErrors::single(issue(
            "authoring-staging-collision",
            &private_root,
            None::<String>,
            "private staging root already exists",
        )));
    }

    let materialize = || -> Result<Vec<StagedFill>, AuthoringErrors> {
        fs::create_dir(&private_root).map_err(|error| {
            AuthoringErrors::single(issue(
                "authoring-staging-root-write",
                &private_root,
                None::<String>,
                format!("could not create private staging root: {error}"),
            ))
        })?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&private_root, fs::Permissions::from_mode(0o700)).map_err(
                |error| {
                    AuthoringErrors::single(issue(
                        "authoring-staging-root-write",
                        &private_root,
                        None::<String>,
                        format!("could not make private staging root owner-only: {error}"),
                    ))
                },
            )?;
        }
        let mut changes = Vec::with_capacity(batch.compiled.len());
        for compiled in &batch.compiled {
            changes.push(stage_fill(
                &ValidatedFill {
                    compiled: compiled.clone(),
                    combined: batch.combined.clone(),
                },
                odin_root,
                &private_root,
            )?);
        }
        Ok(changes)
    };

    let mut changes = match materialize() {
        Ok(changes) => changes,
        Err(error) => {
            let _ = fs::remove_dir_all(&private_root);
            return Err(error);
        }
    };
    let metadata = changes
        .iter()
        .map(|change| &change.metadata)
        .collect::<Vec<_>>();
    let canonical = serde_json::to_vec(&metadata).map_err(|error| {
        let _ = fs::remove_dir_all(&private_root);
        AuthoringErrors::single(issue(
            "authoring-serialize",
            staging_root,
            None::<String>,
            format!("could not canonicalize batch receipt: {error}"),
        ))
    })?;
    let batch_digest = Digest::hash(&canonical);
    fs::rename(&private_root, staging_root).map_err(|error| {
        let _ = fs::remove_dir_all(&private_root);
        AuthoringErrors::single(issue(
            "authoring-staging-publish",
            staging_root,
            None::<String>,
            format!("could not atomically publish private staging tree: {error}"),
        ))
    })?;
    for change in &mut changes {
        let relative = change
            .staged_path
            .strip_prefix(&private_root)
            .map_err(|_| {
                AuthoringErrors::single(issue(
                    "authoring-staging-path",
                    &change.staged_path,
                    None::<String>,
                    "staged path escaped private root",
                ))
            })?
            .to_path_buf();
        change.staged_path = staging_root.join(relative);
    }
    Ok(StagedFillBatch {
        staging_root: staging_root.to_path_buf(),
        changes,
        batch_digest,
    })
}

fn validate_destination_path(relative: &Path) -> Result<(), AuthoringIssue> {
    if relative.as_os_str().is_empty() || relative.is_absolute() {
        return Err(issue(
            "authoring-destination-path",
            relative,
            None::<String>,
            "destination must be a nonempty relative path",
        ));
    }
    let mut components = relative.components();
    if components.next() != Some(Component::Normal(std::ffi::OsStr::new("registry"))) {
        return Err(issue(
            "authoring-destination-path",
            relative,
            None::<String>,
            "destination must be below the registry directory",
        ));
    }
    let mut remaining = 0usize;
    for component in components {
        if !matches!(component, Component::Normal(_)) {
            return Err(issue(
                "authoring-destination-path",
                relative,
                None::<String>,
                "destination must not contain root, current, or parent components",
            ));
        }
        remaining += 1;
    }
    if remaining != 3 {
        return Err(issue(
            "authoring-destination-path",
            relative,
            None::<String>,
            "destination must be registry/<kind>/<id>/<kind>.toml",
        ));
    }
    Ok(())
}

fn validated_staging_root(
    odin_root: &Path,
    staging_root: &Path,
) -> Result<PathBuf, AuthoringErrors> {
    let odin_metadata = fs::symlink_metadata(odin_root).map_err(|error| {
        AuthoringErrors::single(issue(
            "authoring-odin-root-read",
            odin_root,
            None::<String>,
            format!("could not inspect Odin root: {error}"),
        ))
    })?;
    if !odin_metadata.file_type().is_dir() {
        return Err(AuthoringErrors::single(issue(
            "authoring-odin-root-type",
            odin_root,
            None::<String>,
            "Odin root must be a regular directory",
        )));
    }
    let canonical_odin = fs::canonicalize(odin_root).map_err(|error| {
        AuthoringErrors::single(issue(
            "authoring-odin-root-read",
            odin_root,
            None::<String>,
            format!("could not canonicalize Odin root: {error}"),
        ))
    })?;

    match fs::symlink_metadata(staging_root) {
        Ok(metadata) if metadata.file_type().is_dir() => {}
        Ok(_) => {
            return Err(AuthoringErrors::single(issue(
                "authoring-staging-root-type",
                staging_root,
                None::<String>,
                "staging root must be a regular directory",
            )));
        }
        Err(error) if error.kind() == ErrorKind::NotFound => {
            fs::create_dir_all(staging_root).map_err(|error| {
                AuthoringErrors::single(issue(
                    "authoring-staging-root-write",
                    staging_root,
                    None::<String>,
                    format!("could not create staging root: {error}"),
                ))
            })?;
        }
        Err(error) => {
            return Err(AuthoringErrors::single(issue(
                "authoring-staging-root-read",
                staging_root,
                None::<String>,
                format!("could not inspect staging root: {error}"),
            )));
        }
    }
    let staging_metadata = fs::symlink_metadata(staging_root).map_err(|error| {
        AuthoringErrors::single(issue(
            "authoring-staging-root-read",
            staging_root,
            None::<String>,
            format!("could not re-inspect staging root: {error}"),
        ))
    })?;
    if !staging_metadata.file_type().is_dir() {
        return Err(AuthoringErrors::single(issue(
            "authoring-staging-root-type",
            staging_root,
            None::<String>,
            "staging root must remain a regular directory",
        )));
    }
    let canonical_staging = fs::canonicalize(staging_root).map_err(|error| {
        AuthoringErrors::single(issue(
            "authoring-staging-root-read",
            staging_root,
            None::<String>,
            format!("could not canonicalize staging root: {error}"),
        ))
    })?;
    if canonical_staging == canonical_odin || canonical_staging.starts_with(&canonical_odin) {
        return Err(AuthoringErrors::single(issue(
            "authoring-staging-root-overlap",
            staging_root,
            None::<String>,
            "staging root must not be Odin root or one of its descendants",
        )));
    }
    Ok(canonical_staging)
}

fn write_beneath(
    staging_root: &Path,
    relative: &Path,
    bytes: &[u8],
) -> Result<PathBuf, AuthoringErrors> {
    validate_destination_path(relative).map_err(AuthoringErrors::single)?;
    let parent = relative.parent().ok_or_else(|| {
        AuthoringErrors::single(issue(
            "authoring-destination-path",
            relative,
            None::<String>,
            "destination has no parent directory",
        ))
    })?;
    let mut current = staging_root.to_path_buf();
    for component in parent.components() {
        let Component::Normal(name) = component else {
            return Err(AuthoringErrors::single(issue(
                "authoring-destination-path",
                relative,
                None::<String>,
                "destination contains a non-normal component",
            )));
        };
        current.push(name);
        match fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.file_type().is_dir() => {}
            Ok(_) => {
                return Err(AuthoringErrors::single(issue(
                    "authoring-staging-path-type",
                    relative,
                    None::<String>,
                    "staging parent contains a symlink or non-directory entry",
                )));
            }
            Err(error) if error.kind() == ErrorKind::NotFound => {
                fs::create_dir(&current).map_err(|error| {
                    AuthoringErrors::single(issue(
                        "authoring-staging-write",
                        relative,
                        None::<String>,
                        format!("could not create staging directory: {error}"),
                    ))
                })?;
            }
            Err(error) => {
                return Err(AuthoringErrors::single(issue(
                    "authoring-staging-read",
                    relative,
                    None::<String>,
                    format!("could not inspect staging directory: {error}"),
                )));
            }
        }
    }
    let target = staging_root.join(relative);
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&target)
        .map_err(|error| {
            AuthoringErrors::single(issue(
                "authoring-staging-write",
                relative,
                None::<String>,
                format!("could not create staged file exclusively: {error}"),
            ))
        })?;
    if let Err(error) = file.write_all(bytes).and_then(|()| file.sync_all()) {
        drop(file);
        let _ = fs::remove_file(&target);
        return Err(AuthoringErrors::single(issue(
            "authoring-staging-write",
            relative,
            None::<String>,
            format!("could not write staged file durably: {error}"),
        )));
    }
    Ok(target)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DiffOp {
    Keep,
    Delete,
    Insert,
}

fn build_unified_diff(before: &str, after: &str, relative: &Path, change: StagedChange) -> String {
    let mut output = String::new();
    match change {
        StagedChange::Create => output.push_str("--- /dev/null\n"),
        StagedChange::Modify => {
            let _ = writeln!(&mut output, "--- a/{}", relative.display());
        }
    }
    let _ = writeln!(&mut output, "+++ b/{}", relative.display());

    let (old_lines, old_terminated) = split_diff_lines(before);
    let (new_lines, new_terminated) = split_diff_lines(after);
    let old_len = old_lines.len();
    let new_len = new_lines.len();
    let columns = new_len + 1;
    let mut lcs = vec![0u32; (old_len + 1) * columns];
    let index = |old: usize, new: usize| old * columns + new;
    for old in (0..old_len).rev() {
        for new in (0..new_len).rev() {
            lcs[index(old, new)] = if old_lines[old] == new_lines[new] {
                lcs[index(old + 1, new + 1)] + 1
            } else {
                lcs[index(old + 1, new)].max(lcs[index(old, new + 1)])
            };
        }
    }

    let mut operations = Vec::with_capacity(old_len + new_len);
    let mut old = 0usize;
    let mut new = 0usize;
    while old < old_len || new < new_len {
        if old < old_len && new < new_len && old_lines[old] == new_lines[new] {
            operations.push((DiffOp::Keep, old, new));
            old += 1;
            new += 1;
        } else if new >= new_len
            || (old < old_len && lcs[index(old + 1, new)] >= lcs[index(old, new + 1)])
        {
            operations.push((DiffOp::Delete, old, new));
            old += 1;
        } else {
            operations.push((DiffOp::Insert, old, new));
            new += 1;
        }
    }

    const CONTEXT: usize = 3;
    let changes: Vec<usize> = operations
        .iter()
        .enumerate()
        .filter_map(|(position, (operation, _, _))| {
            (!matches!(operation, DiffOp::Keep)).then_some(position)
        })
        .collect();
    let mut hunks = Vec::<(usize, usize)>::new();
    let mut previous_change = None;
    for change in changes {
        let start = change.saturating_sub(CONTEXT);
        let end = (change + CONTEXT + 1).min(operations.len());
        match (hunks.last_mut(), previous_change) {
            (Some(last), Some(previous)) if change.saturating_sub(previous + 1) <= CONTEXT * 2 => {
                last.1 = end;
            }
            _ => hunks.push((start, end)),
        }
        previous_change = Some(change);
    }

    for (start, end) in hunks {
        let old_count = operations[start..end]
            .iter()
            .filter(|(operation, _, _)| matches!(operation, DiffOp::Keep | DiffOp::Delete))
            .count();
        let new_count = operations[start..end]
            .iter()
            .filter(|(operation, _, _)| matches!(operation, DiffOp::Keep | DiffOp::Insert))
            .count();
        let (_, old_before, new_before) = operations[start];
        let old_start = if old_count == 0 {
            old_before
        } else {
            old_before + 1
        };
        let new_start = if new_count == 0 {
            new_before
        } else {
            new_before + 1
        };
        output.push_str("@@ -");
        write_diff_range(&mut output, old_start, old_count);
        output.push_str(" +");
        write_diff_range(&mut output, new_start, new_count);
        output.push_str(" @@\n");

        for (operation, old_index, new_index) in &operations[start..end] {
            match operation {
                DiffOp::Keep => {
                    output.push(' ');
                    output.push_str(old_lines[*old_index]);
                    output.push('\n');
                }
                DiffOp::Delete => {
                    output.push('-');
                    output.push_str(old_lines[*old_index]);
                    output.push('\n');
                    if *old_index + 1 == old_len && !old_terminated {
                        output.push_str("\\ No newline at end of file\n");
                    }
                }
                DiffOp::Insert => {
                    output.push('+');
                    output.push_str(new_lines[*new_index]);
                    output.push('\n');
                    if *new_index + 1 == new_len && !new_terminated {
                        output.push_str("\\ No newline at end of file\n");
                    }
                }
            }
        }
    }
    output
}

fn split_diff_lines(source: &str) -> (Vec<&str>, bool) {
    (source.lines().collect(), source.ends_with('\n'))
}

fn write_diff_range(output: &mut String, start: usize, count: usize) {
    let _ = write!(output, "{start}");
    if count != 1 {
        let _ = write!(output, ",{count}");
    }
}
