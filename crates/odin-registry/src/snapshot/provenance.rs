use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::Command;

use super::contract::Snapshot;
use super::contract::SnapshotError;
use super::store::{PublicationReceipt, RuntimeProjection, SnapshotStore};
use crate::relational::{validate as validate_relations, AdmittedBinding, RelationContext};
use crate::schema::{parse_object_toml, validate_object, RegistryKind, RegistryObject};
use crate::RegistryFinding;

/// Derive candidates from committed inputs or a registry delta over the verified active publication.
#[derive(Debug)]
pub struct ValidatedSnapshotCandidate {
    commit: String,
    tree: String,
    parents: Vec<String>,
    objects: Vec<RegistryObject>,
    worktree: PathBuf,
    _inputs: tempfile::TempDir,
    runtime: Option<RuntimeDerivation>,
}

#[derive(Debug)]
struct RuntimeDerivation {
    base: Snapshot,
    receipt: PublicationReceipt,
    projection: RuntimeProjection,
}

/// Limit first-parent traversal when locating the publication anchor.
const ANCHOR_LOOKBACK: usize = 1024;

impl ValidatedSnapshotCandidate {
    /// Parse committed Git objects, not working files, after checking the expected clean revision.
    pub fn from_committed_worktree(
        worktree: &Path,
        expected_commit: &str,
        admitted_bindings: impl IntoIterator<Item = AdmittedBinding>,
    ) -> Result<Self, SnapshotError> {
        let (commit, tree) = committed_head(worktree, expected_commit)?;
        let objects = committed_registry_objects(worktree, &commit)?;
        let parents = commit_parents(worktree, &commit)?;
        let inputs = committed_inputs(worktree, &commit)?;
        let context = RelationContext::new(inputs.path().join(INPUT_ROOT))
            .with_admitted_bindings(admitted_bindings)
            .map_err(|finding| {
                SnapshotError::Invalid(format!(
                    "admitted binding set is invalid: {}: {}",
                    finding.code, finding.message
                ))
            })?;
        let relation_findings = validate_relations(&objects, &context);
        reject_failures(&relation_findings)?;
        Ok(Self {
            commit,
            tree,
            parents,
            objects,
            worktree: worktree.to_path_buf(),
            _inputs: inputs,
            runtime: None,
        })
    }

    /// Intermediate commits need no publication because the candidate tree declares the complete desired state.
    pub fn publishes_on(&self, anchor: &str) -> Result<(), String> {
        if self.parents.iter().any(|parent| parent == anchor) {
            return Ok(());
        }
        let Some(first) = self.parents.first() else {
            return Err("the candidate has no parent".to_owned());
        };
        let history = run_git_stdout(
            &self.worktree,
            "rev-list first-parent",
            &[
                "rev-list",
                "--first-parent",
                &format!("--max-count={ANCHOR_LOOKBACK}"),
                first,
            ],
        )
        .map_err(|error| error.to_string())?;
        if history.lines().any(|commit| commit == anchor) {
            Ok(())
        } else {
            Err(format!(
                "it is not among the candidate's {ANCHOR_LOOKBACK} nearest first-parent ancestors"
            ))
        }
    }

    pub fn commit(&self) -> &str {
        &self.commit
    }

    pub fn tree(&self) -> &str {
        &self.tree
    }

    pub fn parents(&self) -> &[String] {
        &self.parents
    }

    pub fn objects(&self) -> &[RegistryObject] {
        &self.objects
    }

    pub(super) fn projection(&self) -> Option<&RuntimeProjection> {
        self.runtime.as_ref().map(|runtime| &runtime.projection)
    }

    pub(super) fn matches_receipt(&self, receipt: &PublicationReceipt) -> bool {
        self.commit == receipt.commit
            && self.tree == receipt.tree
            && self.projection() == receipt.runtime_projection.as_ref()
            && self
                .runtime
                .as_ref()
                .is_none_or(|runtime| receipt.previous_revision == Some(runtime.receipt.revision))
    }

    /// Recheck the captured base under the publication lock; allow only an exact installed replay.
    pub(super) fn check_runtime_base(&self, store: &SnapshotStore) -> Result<(), SnapshotError> {
        if let Some(runtime) = &self.runtime {
            let (active, receipt) = store.load_verified_publication()?;
            if (active != runtime.base || receipt != runtime.receipt)
                && !(self.matches_receipt(&receipt) && active.objects == self.objects)
            {
                return Err(SnapshotError::Invalid(
                    "runtime candidate's verified active publication changed".to_owned(),
                ));
            }
        }
        Ok(())
    }

    pub(super) fn publishes_on_receipt(
        &self,
        store: &SnapshotStore,
        receipt: &PublicationReceipt,
    ) -> Result<(), String> {
        if let Some(runtime) = &self.runtime {
            return if runtime.receipt == *receipt {
                Ok(())
            } else {
                Err("runtime candidate does not bind this publication".to_owned())
            };
        }
        if receipt.runtime_projection.is_some() {
            let (_, active_receipt) = store
                .load_verified_publication()
                .map_err(|error| error.to_string())?;
            if active_receipt != *receipt {
                return Err("projected anchor is not the verified active publication".to_owned());
            }
            store
                .effective_tree(&self.worktree, receipt)
                .map_err(|error| error.to_string())?;
            if self.commit == receipt.commit {
                return Ok(());
            }
        }
        self.publishes_on(&receipt.commit)
    }
}

impl SnapshotStore {
    /// Retain schemas and unrelated inputs while deriving and validating the registry delta before Git push.
    pub fn runtime_candidate(
        &self,
        worktree: &Path,
        expected_commit: &str,
        admitted_bindings: impl IntoIterator<Item = AdmittedBinding>,
    ) -> Result<ValidatedSnapshotCandidate, SnapshotError> {
        let (commit, tree) = committed_head(worktree, expected_commit)?;
        let (active, active_receipt) = self.load_verified_publication()?;
        // Resume from the original base so the same delta cannot be applied twice.
        let (base, receipt) = if active_receipt.commit == commit
            && active_receipt.runtime_projection.is_some()
        {
            self.publication_at(
                active_receipt
                    .previous_revision
                    .filter(|previous| {
                        active_receipt.revision.checked_sub(1) == Some(*previous) && *previous > 0
                    })
                    .ok_or_else(|| {
                        SnapshotError::Invalid(
                            "runtime receipt has no immediate predecessor".to_owned(),
                        )
                    })?,
            )?
        } else {
            (active, active_receipt)
        };
        let effective = self.effective_tree(worktree, &receipt)?;
        let projected = derive_runtime_tree(worktree, &commit, &receipt.commit, &effective)?;
        let objects = committed_registry_objects(worktree, &projected)?;
        let inputs = committed_inputs(worktree, &projected)?;
        let context = RelationContext::new(inputs.path().join(INPUT_ROOT))
            .with_admitted_bindings(admitted_bindings)
            .map_err(|finding| {
                SnapshotError::Invalid(format!(
                    "admitted binding set is invalid: {}: {}",
                    finding.code, finding.message
                ))
            })?;
        reject_failures(&validate_relations(&objects, &context))?;
        Ok(ValidatedSnapshotCandidate {
            parents: commit_parents(worktree, &commit)?,
            commit,
            tree,
            objects,
            worktree: worktree.to_path_buf(),
            _inputs: inputs,
            runtime: Some(RuntimeDerivation {
                base,
                receipt,
                projection: RuntimeProjection { tree: projected },
            }),
        })
    }

    /// Rebuild from immutable publication records so dangling Git trees are only a cache.
    fn effective_tree(
        &self,
        worktree: &Path,
        receipt: &PublicationReceipt,
    ) -> Result<String, SnapshotError> {
        let mut current = receipt.clone();
        let mut projections = Vec::new();
        while current.runtime_projection.is_some() {
            let previous = current
                .previous_revision
                .filter(|previous| {
                    current.revision.checked_sub(1) == Some(*previous) && *previous > 0
                })
                .ok_or_else(|| {
                    SnapshotError::Invalid(
                        "runtime receipt has no immediate predecessor".to_owned(),
                    )
                })?;
            projections.push(current);
            current = self.validate_retained_publication(previous)?;
        }
        let mut tree = receipt_commit_tree(worktree, &current)?;
        for projected in projections.iter().rev() {
            receipt_commit_tree(worktree, projected)?;
            tree = derive_runtime_tree(worktree, &projected.commit, &current.commit, &tree)?;
            if projected
                .runtime_projection
                .as_ref()
                .map(|projection| projection.tree.as_str())
                != Some(tree.as_str())
            {
                return Err(SnapshotError::Invalid(
                    "runtime receipt effective tree does not match its proven derivation"
                        .to_owned(),
                ));
            }
            current = projected.clone();
        }
        Ok(tree)
    }
}

fn receipt_commit_tree(
    worktree: &Path,
    receipt: &PublicationReceipt,
) -> Result<String, SnapshotError> {
    let tree = run_git_stdout(
        worktree,
        "resolve receipt tree",
        &["rev-parse", &format!("{}^{{tree}}", receipt.commit)],
    )?;
    if tree != receipt.tree {
        return Err(SnapshotError::Invalid(
            "publication receipt does not bind its committed tree".to_owned(),
        ));
    }
    Ok(tree)
}

fn derive_runtime_tree(
    worktree: &Path,
    commit: &str,
    anchor: &str,
    effective: &str,
) -> Result<String, SnapshotError> {
    let parents = commit_parents(worktree, commit)?;
    let [parent] = parents.as_slice() else {
        return Err(SnapshotError::Invalid(
            "runtime mutation must have exactly one parent".to_owned(),
        ));
    };
    run_git(
        worktree,
        "prove runtime ancestor",
        &["merge-base", "--is-ancestor", anchor, parent],
        None,
    )?;
    let paths = run_git_bytes(
        worktree,
        "inspect runtime paths",
        &["diff", "--name-only", "--no-renames", "-z", parent, commit],
    )?;
    if paths
        .split(|byte| *byte == 0)
        .filter(|path| !path.is_empty())
        .any(|path| !path.starts_with(b"registry/"))
    {
        return Err(SnapshotError::Invalid(
            "runtime mutation changes paths outside registry/".to_owned(),
        ));
    }
    let patch = run_git_bytes(
        worktree,
        "derive runtime delta",
        &[
            "diff",
            "--binary",
            "--full-index",
            "--no-ext-diff",
            "--no-textconv",
            "--no-renames",
            parent,
            commit,
            "--",
            "registry/",
        ],
    )?;
    let staging = tempfile::Builder::new()
        .prefix("odin-registry-projection-")
        .tempdir()
        .map_err(|source| SnapshotError::Io {
            action: "create runtime projection directory",
            path: std::env::temp_dir(),
            source,
        })?;
    let index = staging.path().join("index");
    run_git(
        worktree,
        "read runtime base",
        &["read-tree", effective],
        Some(&index),
    )?;
    if !patch.is_empty() {
        let patch_path = staging.path().join("mutation.patch");
        std::fs::write(&patch_path, patch).map_err(|source| SnapshotError::Io {
            action: "write runtime delta",
            path: patch_path.clone(),
            source,
        })?;
        let patch_path = patch_path
            .to_str()
            .ok_or_else(|| SnapshotError::Invalid("runtime delta path is not UTF-8".to_owned()))?;
        run_git(
            worktree,
            "apply runtime delta",
            &["apply", "--cached", "--binary", patch_path],
            Some(&index),
        )?;
    }
    let bytes = run_git(
        worktree,
        "write runtime tree",
        &["write-tree"],
        Some(&index),
    )?;
    String::from_utf8(bytes)
        .map(|tree| tree.trim().to_owned())
        .map_err(|_| SnapshotError::Invalid("runtime tree id is not UTF-8".to_owned()))
}

fn reject_failures(findings: &[RegistryFinding]) -> Result<(), SnapshotError> {
    let mut failures = findings
        .iter()
        .filter(|finding| finding.is_failure())
        .collect::<Vec<_>>();
    failures.sort();
    if failures.is_empty() {
        return Ok(());
    }
    let details = failures
        .into_iter()
        .map(|finding| {
            format!(
                "{} {}: {}",
                finding.code,
                finding.path.display(),
                finding.message
            )
        })
        .collect::<Vec<_>>()
        .join("; ");
    Err(SnapshotError::Invalid(format!(
        "committed registry validation failed: {details}"
    )))
}

/// Include ignored validation files in the clean-worktree check so they cannot affect publication.
fn committed_head(
    worktree: &Path,
    expected_commit: &str,
) -> Result<(String, String), SnapshotError> {
    let expected = expected_commit.trim();
    let valid = (expected.len() == 40 || expected.len() == 64)
        && expected
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase());
    if !valid {
        return Err(SnapshotError::Invalid(format!(
            "expected commit {expected_commit:?} is not a full lowercase hex object id"
        )));
    }
    let actual = run_git_stdout(worktree, "rev-parse", &["rev-parse", "HEAD"])?;
    if actual != expected {
        return Err(SnapshotError::HeadMismatch {
            expected: expected.to_owned(),
            actual,
        });
    }
    let status = run_git_stdout(
        worktree,
        "status",
        &["status", "--porcelain=v1", "--untracked-files=all"],
    )?;
    if !status.is_empty() {
        let detail = status.lines().take(8).collect::<Vec<_>>().join("; ");
        return Err(SnapshotError::DirtyWorktree {
            path: worktree.to_path_buf(),
            detail,
        });
    }
    let ignored = run_git_stdout(
        worktree,
        "status",
        &[
            "status",
            "--porcelain=v1",
            "--ignored=traditional",
            "--",
            "registry",
            "schemas",
        ],
    )?;
    if !ignored.is_empty() {
        let detail = ignored.lines().take(8).collect::<Vec<_>>().join("; ");
        return Err(SnapshotError::DirtyWorktree {
            path: worktree.to_path_buf(),
            detail: format!("ignored entries under validation roots: {detail}"),
        });
    }
    let tree = run_git_stdout(worktree, "rev-parse", &["rev-parse", "HEAD^{tree}"])?;
    Ok((actual, tree))
}

/// Distinguish an absent registry tree from a failed Git lookup.
fn committed_entry(
    worktree: &Path,
    commit: &str,
    name: &str,
) -> Result<Option<String>, SnapshotError> {
    let listing = run_git_bytes(
        worktree,
        "ls-tree entry",
        &["ls-tree", "-z", "--full-tree", commit, "--", name],
    )?;
    let Some(record) = listing
        .split(|byte| *byte == 0)
        .find(|record| !record.is_empty())
    else {
        return Ok(None);
    };
    let malformed = || SnapshotError::Git {
        operation: "ls-tree entry",
        path: worktree.to_path_buf(),
        message: "malformed ls-tree record".to_owned(),
    };
    let entry = parse_tree_entry(record).ok_or_else(malformed)?;
    if entry.path != name.as_bytes() {
        return Err(malformed());
    }
    std::str::from_utf8(entry.sha)
        .map(|sha| Some(sha.to_owned()))
        .map_err(|_| malformed())
}

const INPUT_ROOT: &str = "root";

/// Use a private index and committed bytes so skip-worktree or stale working files cannot affect validation.
fn committed_inputs(worktree: &Path, commit: &str) -> Result<tempfile::TempDir, SnapshotError> {
    let io = |action: &'static str, path: &Path| {
        let path = path.to_path_buf();
        move |source| SnapshotError::Io {
            action,
            path,
            source,
        }
    };
    let staging = tempfile::Builder::new()
        .prefix("odin-registry-inputs-")
        .tempdir()
        .map_err(io(
            "create committed input directory",
            &std::env::temp_dir(),
        ))?;
    let root = staging.path().join(INPUT_ROOT);
    std::fs::create_dir(&root).map_err(io("create committed input root", &root))?;
    let index = staging.path().join("index");
    for name in ["registry", "schemas"] {
        if committed_entry(worktree, commit, name)?.is_some() {
            run_git(
                worktree,
                "read-tree inputs",
                &[
                    "read-tree",
                    &format!("--prefix={name}/"),
                    &format!("{commit}:{name}"),
                ],
                Some(&index),
            )?;
        }
    }
    if index.exists() {
        let mut prefix = root.clone().into_os_string();
        prefix.push("/");
        let prefix = prefix.to_str().ok_or_else(|| SnapshotError::Git {
            operation: "checkout-index inputs",
            path: worktree.to_path_buf(),
            message: "committed input path is not UTF-8".to_owned(),
        })?;
        run_git(
            worktree,
            "checkout-index inputs",
            &["checkout-index", "-a", "-f", &format!("--prefix={prefix}")],
            Some(&index),
        )?;
    }
    Ok(staging)
}

fn commit_parents(worktree: &Path, commit: &str) -> Result<Vec<String>, SnapshotError> {
    let output = run_git_stdout(
        worktree,
        "show parents",
        &["show", "-s", "--format=%P", commit],
    )?;
    if output.is_empty() {
        return Ok(Vec::new());
    }
    let parents = output
        .split_whitespace()
        .map(str::to_owned)
        .collect::<Vec<_>>();
    if parents.iter().any(|parent| {
        parent.len() != commit.len()
            || !parent
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    }) {
        return Err(SnapshotError::Git {
            operation: "show parents",
            path: worktree.to_path_buf(),
            message: "git returned a malformed parent object id".to_owned(),
        });
    }
    Ok(parents)
}

/// Apply registry discovery rules to committed objects and reject any failure findings.
fn committed_registry_objects(
    worktree: &Path,
    commit: &str,
) -> Result<Vec<RegistryObject>, SnapshotError> {
    let listing = run_git_bytes(
        worktree,
        "ls-tree",
        &[
            "ls-tree",
            "-r",
            "-t",
            "-z",
            "--full-tree",
            commit,
            "--",
            "registry",
        ],
    )?;
    let mut findings = Vec::new();
    let mut object_configs: BTreeMap<(RegistryKind, String), Vec<(String, String)>> =
        BTreeMap::new();
    let mut kind_dirs = BTreeSet::new();
    let mut unknown_kinds: BTreeSet<String> = BTreeSet::new();
    for record in listing.split(|byte| *byte == 0) {
        if record.is_empty() {
            continue;
        }
        let Some(entry) = parse_tree_entry(record) else {
            return Err(SnapshotError::Git {
                operation: "ls-tree",
                path: worktree.to_path_buf(),
                message: "malformed ls-tree record".to_owned(),
            });
        };
        let TreeEntry {
            mode,
            object_type,
            sha,
            path,
        } = entry;
        let mut parts = path.split(|byte| *byte == b'/');
        if parts.next() != Some(b"registry") {
            continue;
        }
        let relative: Vec<&[u8]> = parts.collect();
        if relative.is_empty() {
            if object_type != b"tree" {
                findings.push(RegistryFinding::fail(
                    "registry-root-read",
                    PathBuf::from("registry"),
                    "committed registry root is not a directory",
                ));
            }
            continue;
        }
        if relative.iter().any(|component| {
            component.first().is_some_and(|first| *first == b'.') || *component == b"_disabled"
        }) {
            continue;
        }
        let Some(kind) = std::str::from_utf8(relative[0])
            .ok()
            .and_then(RegistryKind::from_directory)
        else {
            if relative.len() == 1 {
                match std::str::from_utf8(relative[0]) {
                    Ok(name) => {
                        unknown_kinds.insert(name.to_owned());
                    }
                    Err(_) => findings.push(RegistryFinding::flag(
                        "registry-non-utf8-entry",
                        PathBuf::from("registry")
                            .join(String::from_utf8_lossy(relative[0]).as_ref()),
                        "top-level registry entry is not valid UTF-8",
                    )),
                }
            }
            continue;
        };
        if relative.len() == 1 {
            if object_type == b"tree" {
                kind_dirs.insert(kind);
            } else {
                findings.push(RegistryFinding::fail(
                    "registry-kind-type",
                    PathBuf::from("registry").join(kind.directory()),
                    "required registry kind must be a regular directory, not a symlink or special file",
                ));
            }
            continue;
        }
        let id = match std::str::from_utf8(relative[1]) {
            Ok(id) => id.to_owned(),
            Err(_) => {
                findings.push(RegistryFinding::fail(
                    "registry-object-non-utf8",
                    PathBuf::from("registry")
                        .join(kind.directory())
                        .join(String::from_utf8_lossy(relative[1]).as_ref()),
                    "object folder name is not valid UTF-8",
                ));
                continue;
            }
        };
        let relative_dir = PathBuf::from("registry").join(kind.directory()).join(&id);
        match relative.len() {
            2 => match object_type {
                b"tree" => {
                    object_configs.entry((kind, id)).or_default();
                }
                b"commit" => {
                    // Gitlinks have no local committed contents and cannot supply a config.
                    object_configs.entry((kind, id)).or_default();
                }
                _ => findings.push(RegistryFinding::flag(
                    "registry-anomalous-entry",
                    relative_dir,
                    "registry kind entries must be object folders",
                )),
            },
            3 => {
                if object_type == b"tree" {
                    findings.push(RegistryFinding::flag(
                        "registry-anomalous-folder",
                        relative_dir.join(String::from_utf8_lossy(relative[2]).as_ref()),
                        "nested object folder is not a registry object and confers no authority",
                    ));
                    continue;
                }
                let name = match std::str::from_utf8(relative[2]) {
                    Ok(name) => name.to_owned(),
                    Err(_) => continue,
                };
                let is_symlink = mode == b"120000";
                if !name.as_bytes().ends_with(b".toml") {
                    continue;
                }
                if is_symlink {
                    findings.push(RegistryFinding::fail(
                        "registry-config-file-type",
                        relative_dir.join(&name),
                        "registry config must be a regular file, not a symlink or special file",
                    ));
                    continue;
                }
                let sha = std::str::from_utf8(sha)
                    .map_err(|_| SnapshotError::Git {
                        operation: "ls-tree",
                        path: worktree.to_path_buf(),
                        message: "object id is not UTF-8".to_owned(),
                    })?
                    .to_owned();
                object_configs
                    .entry((kind, id))
                    .or_default()
                    .push((name, sha));
            }
            _ => {
                // Nested folders were already reported and must not supply declaration content.
            }
        }
    }
    for kind in RegistryKind::ALL {
        if !kind_dirs.contains(&kind) {
            findings.push(RegistryFinding::fail(
                "registry-kind-missing",
                PathBuf::from("registry").join(kind.directory()),
                "required registry kind directory is absent from the committed tree",
            ));
        }
    }
    for name in unknown_kinds {
        findings.push(RegistryFinding::flag(
            "registry-unknown-kind",
            PathBuf::from("registry").join(name),
            "unknown registry kind is not authoritative",
        ));
    }

    let mut objects = Vec::new();
    for ((kind, id), configs) in object_configs {
        let relative_dir = PathBuf::from("registry").join(kind.directory()).join(&id);
        let [(name, sha)] = configs.as_slice() else {
            findings.push(RegistryFinding::fail(
                "registry-config-count",
                relative_dir,
                format!(
                    "object folder must contain exactly one TOML config, found {}",
                    configs.len()
                ),
            ));
            continue;
        };
        let relative_config = relative_dir.join(name);
        let expected = kind.config_name();
        if name != &expected {
            findings.push(RegistryFinding::fail(
                "registry-config-name",
                relative_config,
                format!("{kind} object config must be named {expected:?}"),
            ));
            continue;
        }
        let bytes = run_git_bytes(worktree, "cat-file", &["cat-file", "blob", sha])?;
        let source = match String::from_utf8(bytes) {
            Ok(source) => source,
            Err(_) => {
                findings.push(RegistryFinding::fail(
                    "registry-config-read",
                    relative_config,
                    "could not read config: committed bytes are not valid UTF-8",
                ));
                continue;
            }
        };
        match parse_object_toml(kind, id, relative_config, &source) {
            Ok(object) => {
                findings.extend(validate_object(&object));
                objects.push(object);
            }
            Err(finding) => findings.push(finding),
        }
    }
    objects.sort_by(|left, right| {
        (left.kind(), left.id.as_str()).cmp(&(right.kind(), right.id.as_str()))
    });
    reject_failures(&findings)?;
    Ok(objects)
}

struct TreeEntry<'a> {
    mode: &'a [u8],
    object_type: &'a [u8],
    sha: &'a [u8],
    path: &'a [u8],
}

fn parse_tree_entry(record: &[u8]) -> Option<TreeEntry<'_>> {
    let (meta, path) = split_once(record, b'\t')?;
    let (mode, rest) = split_once(meta, b' ')?;
    let (object_type, sha) = split_once(rest, b' ')?;
    Some(TreeEntry {
        mode,
        object_type,
        sha,
        path,
    })
}

fn split_once(bytes: &[u8], needle: u8) -> Option<(&[u8], &[u8])> {
    let position = bytes.iter().position(|byte| *byte == needle)?;
    Some((&bytes[..position], &bytes[position + 1..]))
}

fn run_git_stdout(
    worktree: &Path,
    operation: &'static str,
    args: &[&str],
) -> Result<String, SnapshotError> {
    let bytes = run_git_bytes(worktree, operation, args)?;
    String::from_utf8(bytes)
        .map(|output| output.trim_end().to_owned())
        .map_err(|_| SnapshotError::Git {
            operation,
            path: worktree.to_path_buf(),
            message: "git output is not valid UTF-8".to_owned(),
        })
}

fn run_git_bytes(
    worktree: &Path,
    operation: &'static str,
    args: &[&str],
) -> Result<Vec<u8>, SnapshotError> {
    run_git(worktree, operation, args, None)
}

fn run_git(
    worktree: &Path,
    operation: &'static str,
    args: &[&str],
    index: Option<&Path>,
) -> Result<Vec<u8>, SnapshotError> {
    let mut command = Command::new("git");
    command.arg("-C").arg(worktree).args(args);
    if let Some(index) = index {
        command.env("GIT_INDEX_FILE", index);
    }
    let output = command.output().map_err(|source| SnapshotError::Git {
        operation,
        path: worktree.to_path_buf(),
        message: format!("could not spawn git: {source}"),
    })?;
    if !output.status.success() {
        return Err(SnapshotError::Git {
            operation,
            path: worktree.to_path_buf(),
            message: String::from_utf8_lossy(&output.stderr).trim().to_owned(),
        });
    }
    Ok(output.stdout)
}
