use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command as ProcessCommand;

use clap::{Args, Subcommand};
use odin_registry::{
    compile_fill_documents, stage_fill_batch, validate_fill_batch, FillDocumentSource,
    RelationContext, SkeletonCatalog, SnapshotStore, StagedDiffMetadata,
    ValidatedSnapshotCandidate,
};
use serde::{Deserialize, Serialize};

use odin_cli::runtime_bindings::admitted_registry_bindings;

use crate::RunStatus;

/// Publish one committed authoring worktree as the next versioned registry
/// snapshot under an explicitly configured `SnapshotStore`.
#[derive(Debug, Args)]
pub(crate) struct RegistryArgs {
    #[command(subcommand)]
    command: RegistryCommand,
}

#[derive(Debug, Subcommand)]
enum RegistryCommand {
    /// Validate and publish the exact committed worktree state.
    Publish(PublishArgs),
}

#[derive(Debug, Args)]
struct PublishArgs {
    /// Strict JSON config: `{"schema":"odin.registry-publish-config.v1",
    /// "snapshot_store":"/absolute/path/snapshot.json"}`.
    #[arg(long, value_name = "FILE")]
    config: PathBuf,
    /// Clean committed authoring worktree to parse; HEAD must equal `--commit`.
    #[arg(long, value_name = "PATH")]
    worktree: PathBuf,
    /// Full lowercase hex commit the authoring worktree HEAD must equal.
    #[arg(long, value_name = "COMMIT")]
    commit: String,
    /// Expected next snapshot revision; the first publication expects 1.
    #[arg(long, value_name = "N")]
    expected_revision: u64,
    /// Write the per-call result and immutable publication receipt here in addition to stdout.
    #[arg(long, value_name = "FILE")]
    output: PathBuf,
}

/// Strict deny-unknown publish configuration; the snapshot store location is
/// always explicit and absolute, never a default under the operator's XDG
/// state.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PublishConfig {
    schema: String,
    snapshot_store: PathBuf,
}

const PUBLISH_CONFIG_SCHEMA: &str = "odin.registry-publish-config.v1";

pub(crate) fn registry_command(
    arguments: RegistryArgs,
    output: &mut impl Write,
) -> Result<RunStatus, String> {
    match arguments.command {
        RegistryCommand::Publish(arguments) => registry_publish(arguments, output),
    }
}

/// Authorized publication of one committed authoring worktree: the candidate
/// comes only from the clean committed parse/relations/bindings path, the
/// store enforces the active-revision check and atomic versioned install,
/// and the identical-content republish reports `Unchanged`.
fn registry_publish(arguments: PublishArgs, output: &mut impl Write) -> Result<RunStatus, String> {
    let config_bytes = fs::read(&arguments.config).map_err(|error| {
        format!(
            "could not read publish config {}: {error}",
            arguments.config.display()
        )
    })?;
    let config: PublishConfig = serde_json::from_slice(&config_bytes).map_err(|error| {
        format!(
            "publish config {} is invalid: {error}",
            arguments.config.display()
        )
    })?;
    if config.schema != PUBLISH_CONFIG_SCHEMA {
        return Err(format!(
            "publish config schema must be {PUBLISH_CONFIG_SCHEMA:?}, found {:?}",
            config.schema
        ));
    }
    if !config.snapshot_store.is_absolute() {
        return Err("publish config snapshot_store must be an absolute path".to_owned());
    }

    let admitted_catalog = admitted_registry_bindings();
    let candidate = ValidatedSnapshotCandidate::from_committed_worktree(
        &arguments.worktree,
        &arguments.commit,
        admitted_catalog,
    )
    .map_err(|error| format!("committed registry candidate is invalid: {error}"))?;
    let result = SnapshotStore::new(&config.snapshot_store)
        .publish_committed(&candidate, arguments.expected_revision)
        .map_err(|error| format!("registry publication failed: {error}"))?;

    let mut result_bytes = serde_json::to_vec_pretty(&result)
        .map_err(|error| format!("could not encode publication result: {error}"))?;
    result_bytes.push(b'\n');
    if let Some(parent) = arguments.output.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent).map_err(|error| {
                format!(
                    "could not create publication result directory {}: {error}",
                    parent.display()
                )
            })?;
        }
    }
    fs::write(&arguments.output, &result_bytes).map_err(|error| {
        format!(
            "could not write publication result {}: {error}",
            arguments.output.display()
        )
    })?;
    output
        .write_all(&result_bytes)
        .map_err(|error| format!("could not write publication result: {error}"))?;
    Ok(RunStatus::Success)
}

#[derive(Debug, Args)]
pub(crate) struct AuthorArgs {
    #[command(subcommand)]
    command: AuthorCommand,
}

#[derive(Debug, Subcommand)]
enum AuthorCommand {
    Stage(AuthorStageArgs),
}

#[derive(Debug, Args)]
struct AuthorStageArgs {
    #[arg(long, value_name = "FILE")]
    config: PathBuf,
    #[arg(long, value_name = "PATH")]
    worktree: PathBuf,
    #[arg(long, value_name = "FILE", required = true)]
    fill: Vec<PathBuf>,
    #[arg(long, value_name = "PATH")]
    staging_root: PathBuf,
    #[arg(long, value_name = "N")]
    expected_registry_revision: u64,
    #[arg(long, value_name = "FILE")]
    output: PathBuf,
}

#[derive(Debug, Serialize)]
#[serde(deny_unknown_fields)]
struct AuthorStageReceipt {
    schema: &'static str,
    base_commit: String,
    base_tree: String,
    expected_registry_revision: u64,
    batch_digest: odin_domain::Digest,
    staging_root: PathBuf,
    changes: Vec<StagedDiffMetadata>,
    unified_diffs: Vec<String>,
}

pub(crate) fn author_command(
    arguments: AuthorArgs,
    output: &mut impl Write,
) -> Result<RunStatus, String> {
    match arguments.command {
        AuthorCommand::Stage(arguments) => author_stage(arguments, output),
    }
}

fn author_stage(arguments: AuthorStageArgs, output: &mut impl Write) -> Result<RunStatus, String> {
    let config_bytes = fs::read(&arguments.config)
        .map_err(|error| format!("could not read author config: {error}"))?;
    let config: PublishConfig = serde_json::from_slice(&config_bytes)
        .map_err(|error| format!("author config is invalid: {error}"))?;
    if config.schema != PUBLISH_CONFIG_SCHEMA || !config.snapshot_store.is_absolute() {
        return Err(
            "author stage requires the strict publish config with an absolute snapshot_store"
                .to_owned(),
        );
    }
    let git_marker = arguments.worktree.join(".git");
    let git_metadata = fs::symlink_metadata(&git_marker)
        .map_err(|error| format!("authoring worktree has no .git marker: {error}"))?;
    if !git_metadata.file_type().is_file() {
        return Err("author stage is permitted only in an isolated linked Git worktree".to_owned());
    }
    let head = String::from_utf8(run_author_git(&arguments.worktree, &["rev-parse", "HEAD"])?)
        .map_err(|_| "git HEAD is not UTF-8".to_owned())?
        .trim()
        .to_owned();
    let admitted = admitted_registry_bindings();
    let base = ValidatedSnapshotCandidate::from_committed_worktree(
        &arguments.worktree,
        &head,
        admitted.iter().cloned(),
    )
    .map_err(|error| format!("authoring worktree is not a clean committed base: {error}"))?;
    let store = SnapshotStore::new(&config.snapshot_store);
    let next_revision = if config
        .snapshot_store
        .try_exists()
        .map_err(|error| format!("could not inspect snapshot store: {error}"))?
    {
        store
            .load_verified()
            .map_err(|error| format!("active registry publication is invalid: {error}"))?
            .revision
            .checked_add(1)
            .ok_or_else(|| "registry revision exhausted u64".to_owned())?
    } else {
        1
    };
    if arguments.expected_registry_revision != next_revision {
        return Err(format!(
            "stale author stage: expected registry revision {}, next verified revision is {next_revision}",
            arguments.expected_registry_revision
        ));
    }
    let canonical_worktree = fs::canonicalize(&arguments.worktree)
        .map_err(|error| format!("could not canonicalize authoring worktree: {error}"))?;
    let mut sources = Vec::new();
    for path in &arguments.fill {
        let absolute = if path.is_absolute() {
            path.clone()
        } else {
            canonical_worktree.join(path)
        };
        let canonical = fs::canonicalize(&absolute)
            .map_err(|error| format!("could not resolve fill {}: {error}", path.display()))?;
        let relative = canonical
            .strip_prefix(&canonical_worktree)
            .map_err(|_| format!("fill {} is outside the authoring worktree", path.display()))?
            .to_path_buf();
        let relative_text = relative
            .to_str()
            .ok_or_else(|| format!("fill path {} is not UTF-8", relative.display()))?;
        run_author_git(
            &arguments.worktree,
            &["ls-files", "--error-unmatch", "--", relative_text],
        )
        .map_err(|_| format!("fill {} is not committed", relative.display()))?;
        let object = format!("HEAD:{relative_text}");
        let source = String::from_utf8(run_author_git(&arguments.worktree, &["show", &object])?)
            .map_err(|_| format!("committed fill {} is not UTF-8", relative.display()))?;
        sources.push(FillDocumentSource {
            relative_path: relative,
            source,
        });
    }
    let catalog = SkeletonCatalog::load(arguments.worktree.join("skeletons"))
        .map_err(|error| format!("skeleton catalog is invalid: {error}"))?;
    let compiled = compile_fill_documents(&catalog, sources, &admitted)
        .map_err(|error| format!("typed fill compilation failed: {error}"))?;
    let context = RelationContext::new(&arguments.worktree)
        .with_admitted_bindings(admitted)
        .map_err(|finding| format!("admitted binding catalog is invalid: {}", finding.message))?;
    let validated = validate_fill_batch(compiled, base.objects(), &context)
        .map_err(|error| format!("combined authoring batch is invalid: {error}"))?;
    let staged = stage_fill_batch(&validated, &arguments.worktree, &arguments.staging_root)
        .map_err(|error| format!("atomic author staging failed: {error}"))?;

    // The shared install transaction (odin-registry): atomic replacement,
    // strict add, and an index that must carry exactly the generated set.
    let _generated = odin_registry::authoring::install_staged_batch(&arguments.worktree, &staged)
        .map_err(|error| format!("author install transaction failed: {error}"))?;

    let receipt = AuthorStageReceipt {
        schema: "odin.author-stage-receipt.v1",
        base_commit: base.commit().to_owned(),
        base_tree: base.tree().to_owned(),
        expected_registry_revision: arguments.expected_registry_revision,
        batch_digest: staged.batch_digest,
        staging_root: staged.staging_root.clone(),
        changes: staged
            .changes
            .iter()
            .map(|change| change.metadata.clone())
            .collect(),
        unified_diffs: staged
            .changes
            .iter()
            .map(|change| change.unified_diff.clone())
            .collect(),
    };
    let mut bytes = serde_json::to_vec_pretty(&receipt)
        .map_err(|error| format!("could not encode author stage receipt: {error}"))?;
    bytes.push(b'\n');
    if let Some(parent) = arguments.output.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)
                .map_err(|error| format!("could not create author output directory: {error}"))?;
        }
    }
    fs::write(&arguments.output, &bytes)
        .map_err(|error| format!("could not write author stage receipt: {error}"))?;
    output
        .write_all(&bytes)
        .map_err(|error| format!("could not write author stage stdout: {error}"))?;
    Ok(RunStatus::Success)
}

fn run_author_git(worktree: &Path, args: &[&str]) -> Result<Vec<u8>, String> {
    let result = ProcessCommand::new("git")
        .arg("-C")
        .arg(worktree)
        .args(args)
        .output()
        .map_err(|error| format!("could not spawn git: {error}"))?;
    if !result.status.success() {
        return Err(format!(
            "git {} failed in {}: {}",
            args.first().copied().unwrap_or("<unknown>"),
            worktree.display(),
            String::from_utf8_lossy(&result.stderr).trim()
        ));
    }
    Ok(result.stdout)
}
