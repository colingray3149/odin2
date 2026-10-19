//! Confine file operations and Git observations to the capsule root.

use std::env;
use std::fs::File;
use std::io::Read;
use std::path::Path;
use std::time::Duration;

use odin_confined_fs::{validate_relative_path, ConfinedError, PrivateCapability};
use odin_process::{
    CancellationToken, CommandSpec, EnvironmentBuilder, FrozenArgv, ProcessLimits,
    ProcessSupervisor,
};
use odin_sidecar_protocol::{EFFECTOR_BWRAP_ENV, EFFECTOR_TOOL_PATH_ENV};
use odin_types::hash::{hex_decode, hex_encode};
use serde::Serialize;
use sha2::{Digest, Sha256};

const MAX_READ_BYTES: usize = 1_048_576;
const MAX_PREIMAGE_BYTES: u64 = 8_388_608;
const MAX_WRITE_BYTES: usize = 65_536;
const MAX_PATCH_BYTES: usize = 262_144;
const MAX_UNTRACKED_BYTES: usize = 16_384;
const MAX_UNTRACKED_ENTRIES: usize = 64;
const GIT_TIMEOUT_MS: u64 = 10_000;
const GIT_TERM_GRACE_MS: u64 = 2_000;
const GIT_MAX_STDERR_BYTES: usize = 4_096;
const COMMIT_HEX_LEN: usize = 40;

#[derive(Serialize)]
pub(crate) struct CapsuleLocation {
    pub root: String,
    pub dev: u64,
    pub ino: u64,
}

#[derive(Serialize)]
pub(crate) struct ReadOutcome {
    pub capsule: CapsuleLocation,
    pub sha256: String,
    pub size: u64,
    pub bytes: usize,
    pub truncated: bool,
    pub content_hex: String,
}

#[derive(Serialize)]
pub(crate) struct WriteOutcome {
    pub capsule: CapsuleLocation,
    pub created: bool,
    pub bytes: usize,
    pub sha256: String,
}

pub(crate) struct WriteError {
    pub detail: String,
    pub phase: &'static str,
}

impl WriteError {
    fn unchanged(detail: String) -> Self {
        Self {
            detail,
            phase: "unchanged",
        }
    }
}

#[derive(Serialize)]
pub(crate) struct DiffOutcome {
    pub capsule: CapsuleLocation,
    pub status: &'static str,
    pub patch: String,
    pub patch_bytes: usize,
    pub patch_sha256: String,
    pub truncated: bool,
    pub untracked: Vec<String>,
    pub untracked_truncated: bool,
    pub source_commit: String,
}

fn location(root: &Path, capsule: &PrivateCapability) -> CapsuleLocation {
    let identity = capsule.root_identity();
    CapsuleLocation {
        root: root.to_string_lossy().into_owned(),
        dev: identity.dev,
        ino: identity.ino,
    }
}

fn seal(root: &Path) -> Result<PrivateCapability, String> {
    if !root.is_absolute() {
        return Err("capsule_root must be an absolute path".to_string());
    }
    PrivateCapability::seal(root).map_err(|error: ConfinedError| error.to_string())
}

fn validate_commit(commit: &str) -> Result<(), String> {
    if commit.len() == COMMIT_HEX_LEN && commit.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Ok(());
    }
    Err("source_commit must be a full 40-hex commit id".to_string())
}

pub(crate) use odin_sidecar_protocol::{SOURCE_KIND_GIT_COMMIT, SOURCE_KIND_KNOWLEDGE_ROOT};

/// Keep knowledge-root digests distinct from commits so they cannot satisfy source verification.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum CapsuleSourceIdentity {
    GitCommit(String),
    /// Hash the canonical root path rather than repository contents.
    KnowledgeRoot {
        root_digest: String,
    },
}

impl CapsuleSourceIdentity {
    pub(crate) fn parse(kind: &str, identity: &str) -> Result<Self, String> {
        match kind {
            SOURCE_KIND_GIT_COMMIT => {
                validate_commit(identity)?;
                Ok(Self::GitCommit(identity.to_owned()))
            }
            SOURCE_KIND_KNOWLEDGE_ROOT => {
                if identity.len() == 64 && identity.bytes().all(|byte| byte.is_ascii_hexdigit()) {
                    Ok(Self::KnowledgeRoot {
                        root_digest: identity.to_owned(),
                    })
                } else {
                    Err("knowledge-root identity must be a full 64-hex digest".to_owned())
                }
            }
            _ => Err(format!(
                "unknown source kind {kind:?}; expected git-commit or knowledge-root"
            )),
        }
    }

    /// Source-verified effects require a worktree commit, not a knowledge-root path digest.
    fn verified_commit(&self) -> Result<&str, String> {
        match self {
            Self::GitCommit(commit) => Ok(commit),
            Self::KnowledgeRoot { .. } => Err(
                "knowledge-root capsules take no source-verified effects: the capsule is a declared knowledge root with no git worktree identity"
                    .to_owned(),
            ),
        }
    }
}

fn validate_relative(path: &Path) -> Result<(), String> {
    let bytes = path.as_os_str().as_encoded_bytes();
    if bytes.is_empty() {
        return Err("path: empty path is denied".to_string());
    }
    if bytes.len() > 1_024 {
        return Err("path: exceeds 1024 bytes".to_string());
    }
    validate_relative_path(path).map_err(|error| match error {
        ConfinedError::AbsolutePath => "path: absolute path is denied".to_string(),
        ConfinedError::EmptyComponent => "path: empty path component is denied".to_string(),
        ConfinedError::DotSegment => "path: . component is denied".to_string(),
        ConfinedError::DotDotSegment => "path: .. component is denied".to_string(),
        ConfinedError::NulByte => "path: NUL byte is denied".to_string(),
        other => format!("path: {other}"),
    })
}

fn deny_git_path(path: &Path) -> Result<(), String> {
    let bytes = path.as_os_str().as_encoded_bytes();
    let first = bytes.split(|byte| *byte == b'/').next().unwrap_or(b"");
    if first == b".git" {
        return Err("path: writes under .git are denied".to_string());
    }
    for forbidden in [".mcp.json", "mcp.json", ".omp", ".claude"] {
        if first == forbidden.as_bytes() {
            return Err(format!(
                "path: writes under {forbidden} are agent-configuration surface and denied"
            ));
        }
    }
    Ok(())
}

fn open_read(capsule: &PrivateCapability, path: &Path) -> Result<Option<File>, String> {
    capsule.open_read(path).map_or_else(
        |error| match error {
            ConfinedError::ComponentMissing { .. } => Ok(None),
            other => Err(other.to_string()),
        },
        |file| Ok(Some(file)),
    )
}

fn stream_hash(file: &File, retain: usize) -> Result<(String, u64, Vec<u8>, bool), String> {
    let mut hasher = Sha256::new();
    let mut retained = Vec::new();
    let mut total: u64 = 0;
    let mut chunk = [0_u8; 65_536];
    let mut reader = file;
    loop {
        let count = reader.read(&mut chunk).map_err(|error| error.to_string())?;
        if count == 0 {
            break;
        }
        hasher.update(&chunk[..count]);
        total += count as u64;
        if retained.len() < retain {
            let take = (retain - retained.len()).min(count);
            retained.extend_from_slice(&chunk[..take]);
        }
    }
    Ok((
        hex_encode(&hasher.finalize()),
        total,
        retained,
        total > retain as u64,
    ))
}

pub(crate) fn git_run(
    git_bin: &Path,
    capsule_root: &Path,
    args: &[&str],
    max_stdout_bytes: usize,
) -> Result<(Vec<u8>, bool), String> {
    if !git_bin.is_absolute() {
        return Err("git_bin must be an absolute path".to_string());
    }
    let bwrap = env::var(EFFECTOR_BWRAP_ENV)
        .map_err(|_| format!("{EFFECTOR_BWRAP_ENV} is required for git observation"))?;
    let tool_path = env::var(EFFECTOR_TOOL_PATH_ENV)
        .map_err(|_| format!("{EFFECTOR_TOOL_PATH_ENV} is required for git observation"))?;
    if !Path::new(&bwrap).is_absolute()
        || tool_path.is_empty()
        || env::split_paths(&tool_path).any(|path| !path.is_absolute())
    {
        return Err("git observation sandbox binding is invalid".to_owned());
    }

    // Isolate Git hooks and helpers from host files; PDEATHSIG would track the short-lived broker thread.
    let mut argv = odin_process::capsule_sandbox_argv(bwrap, capsule_root, "--ro-bind");
    argv.extend([
        "--setenv".to_owned(),
        "PATH".to_owned(),
        tool_path,
        "--setenv".to_owned(),
        "HOME".to_owned(),
        "/tmp".to_owned(),
    ]);
    for (key, value) in GIT_ENV {
        argv.extend(["--setenv".to_owned(), key.to_owned(), value.to_owned()]);
    }
    argv.extend([
        "--chdir".to_owned(),
        "/workspace/project".to_owned(),
        "--".to_owned(),
        git_bin.display().to_string(),
        "--no-optional-locks".to_owned(),
        "-c".to_owned(),
        "core.fsmonitor=false".to_owned(),
        "-c".to_owned(),
        "core.hooksPath=/dev/null".to_owned(),
        "-c".to_owned(),
        "diff.external=".to_owned(),
        "-c".to_owned(),
        "core.attributesFile=/dev/null".to_owned(),
    ]);
    argv.extend(args.iter().map(|argument| (*argument).to_owned()));
    let frozen = FrozenArgv::new(argv, 128, 32_768)
        .map_err(|error| format!("git sandbox argv rejected: {error}"))?;
    let command = CommandSpec {
        argv: frozen,
        environment: EnvironmentBuilder::new(Vec::<&str>::new())
            .expect("empty environment is valid")
            .build(),
        current_dir: capsule_root.to_path_buf(),
    };
    let limits = ProcessLimits {
        timeout: Duration::from_millis(GIT_TIMEOUT_MS),
        termination_grace: Duration::from_millis(GIT_TERM_GRACE_MS),
        poll_interval: Duration::from_millis(5),
        max_stdout_bytes,
        max_stderr_bytes: GIT_MAX_STDERR_BYTES,
    };
    let transport = crate::process_transport()?;
    let mut supervisor = ProcessSupervisor::new(limits, transport)
        .map_err(|error| format!("supervisor rejected limits: {error}"))?;
    let token = CancellationToken::new();
    let name = args.first().copied().unwrap_or("");
    let outcome = supervisor
        .run(&command, &token)
        .map_err(|error| format!("git {name} failed: {error}"))?;
    let stderr_text = String::from_utf8_lossy(outcome.stderr.as_bytes());
    match outcome.disposition {
        odin_process::ExitDisposition::Exited(0) => Ok((
            outcome.stdout.as_bytes().to_vec(),
            outcome.stdout.truncated(),
        )),
        odin_process::ExitDisposition::Exited(code) => {
            Err(format!("git {name} exited {code}: {}", stderr_text.trim()))
        }
        disposition => Err(format!("git {name} did not complete: {disposition:?}")),
    }
}

const GIT_ENV: [(&str, &str); 7] = [
    ("GIT_CONFIG_GLOBAL", "/dev/null"),
    ("GIT_CONFIG_SYSTEM", "/dev/null"),
    ("GIT_CONFIG_NOSYSTEM", "1"),
    ("GIT_ALLOW_PROTOCOL", "none"),
    ("GIT_TERMINAL_PROMPT", "0"),
    ("GIT_PAGER", "cat"),
    ("LC_ALL", "C"),
];

fn head_commit(git_bin: &Path, capsule_root: &Path) -> Result<String, String> {
    let (stdout, truncated) = git_run(git_bin, capsule_root, &["rev-parse", "HEAD"], 256)?;
    if truncated {
        return Err("git rev-parse output exceeded its bound".to_string());
    }
    Ok(String::from_utf8_lossy(&stdout).trim().to_string())
}

fn verified_capsule(
    capsule_root: &Path,
    identity: &CapsuleSourceIdentity,
    git_bin: &Path,
) -> Result<PrivateCapability, String> {
    let source_commit = identity.verified_commit()?;
    let capsule = seal(capsule_root)?;
    let head = head_commit(git_bin, capsule_root)?;
    if head != source_commit {
        return Err(format!(
            "capsule HEAD {head} is not the declared source commit {source_commit}"
        ));
    }
    Ok(capsule)
}

pub(crate) fn verify(
    capsule_root: &Path,
    identity: &CapsuleSourceIdentity,
    git_bin: &Path,
) -> Result<CapsuleLocation, String> {
    let capsule = verified_capsule(capsule_root, identity, git_bin)?;
    Ok(location(capsule_root, &capsule))
}

/// A missing file has no digest; reads remain confined to the capsule root.
pub(crate) fn content_digest(capsule_root: &Path, path: &Path) -> Result<Option<String>, String> {
    validate_relative(path)?;
    let capsule = seal(capsule_root)?;
    let Some(file) = open_read(&capsule, path)? else {
        return Ok(None);
    };
    let mut reader = file;
    let mut hasher = blake3::Hasher::new();
    let mut total = 0_u64;
    let mut chunk = [0_u8; 65_536];
    loop {
        let count = reader.read(&mut chunk).map_err(|error| error.to_string())?;
        if count == 0 {
            break;
        }
        total = total.saturating_add(count as u64);
        if total > MAX_PREIMAGE_BYTES {
            return Err(format!(
                "path {} exceeds the observation ceiling",
                path.to_string_lossy()
            ));
        }
        hasher.update(&chunk[..count]);
    }
    Ok(Some(format!("blake3:{}", hasher.finalize().to_hex())))
}

pub(crate) fn preimage(capsule_root: &Path, path: &Path) -> Result<Option<(String, u64)>, String> {
    validate_relative(path)?;
    let capsule = seal(capsule_root)?;
    let file = open_read(&capsule, path)?
        .ok_or_else(|| format!("path {} is absent", path.to_string_lossy()))?;
    let (digest, size, _, _) = stream_hash(&file, 0)?;
    if size > MAX_PREIMAGE_BYTES {
        return Err(format!(
            "path {} exceeds the preimage hash ceiling",
            path.to_string_lossy()
        ));
    }
    Ok(Some((digest, size)))
}

pub(crate) fn read(
    capsule_root: &Path,
    path: &Path,
    max_bytes: usize,
) -> Result<ReadOutcome, String> {
    validate_relative(path)?;
    let capsule = seal(capsule_root)?;
    let retain = max_bytes.min(MAX_READ_BYTES);
    let file = open_read(&capsule, path)?
        .ok_or_else(|| format!("path {} is absent", path.to_string_lossy()))?;
    let (digest, size, retained, truncated) = stream_hash(&file, retain)?;
    Ok(ReadOutcome {
        capsule: location(capsule_root, &capsule),
        sha256: digest,
        size,
        bytes: retained.len(),
        truncated,
        content_hex: hex_encode(&retained),
    })
}

pub(crate) fn write(
    capsule_root: &Path,
    identity: &CapsuleSourceIdentity,
    git_bin: &Path,
    path: &Path,
    content_hex: &str,
    preimage_sha256: Option<&str>,
) -> Result<WriteOutcome, WriteError> {
    if let Err(error) = validate_relative(path).and_then(|()| deny_git_path(path)) {
        return Err(WriteError::unchanged(error));
    }
    let content = hex_decode(content_hex)
        .map_err(|error| WriteError::unchanged(format!("content_hex rejected: {error}")))?;
    if content.len() > MAX_WRITE_BYTES {
        return Err(WriteError::unchanged(format!(
            "content: {} bytes exceeds ceiling {MAX_WRITE_BYTES}",
            content.len()
        )));
    }
    let capsule =
        verified_capsule(capsule_root, identity, git_bin).map_err(WriteError::unchanged)?;
    let display = path.to_string_lossy().into_owned();
    let created = preimage_sha256.is_none();
    match preimage_sha256 {
        None => {
            if open_read(&capsule, path)
                .map_err(WriteError::unchanged)?
                .is_some()
            {
                return Err(WriteError::unchanged(format!(
                    "path {display} exists; a preimage hash is required"
                )));
            }
            create_new(&capsule, path, &content)?;
        }
        Some(expected) => {
            let file = open_read(&capsule, path)
                .map_err(WriteError::unchanged)?
                .ok_or_else(|| {
                    WriteError::unchanged(format!(
                        "path {display} does not exist but a preimage hash was declared"
                    ))
                })?;
            let (observed, _, _, _) = stream_hash(&file, 0).map_err(WriteError::unchanged)?;
            if observed != expected {
                return Err(WriteError::unchanged(format!(
                    "preimage hash mismatch for {display}: declared {expected}, observed {observed}"
                )));
            }
            replace_existing(&capsule, path, &content)?;
        }
    }
    Ok(WriteOutcome {
        capsule: location(capsule_root, &capsule),
        created,
        bytes: content.len(),
        sha256: hex_encode(&Sha256::digest(&content)),
    })
}

fn replace_existing(
    capsule: &PrivateCapability,
    path: &Path,
    content: &[u8],
) -> Result<(), WriteError> {
    capsule
        .write_atomic(path, content, 0o600)
        .map_err(|error| WriteError {
            detail: error.to_string(),
            phase: replaced_phase(capsule, path, content),
        })
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) enum ReplaceRefusal {
    EmptyOld,
    Absent,
    TooLarge,
    NotUtf8,
    OldNotFound,
    OldAmbiguous { occurrences: usize },
}

impl std::fmt::Display for ReplaceRefusal {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EmptyOld => {
                formatter.write_str("old_text is empty; name the exact text to replace")
            }
            Self::Absent => formatter.write_str(
                "the file does not exist; create it with content and preimage_sha256 null",
            ),
            Self::TooLarge => write!(
                formatter,
                "the file exceeds the {MAX_PREIMAGE_BYTES}-byte edit ceiling"
            ),
            Self::NotUtf8 => formatter.write_str("the file is not UTF-8 text"),
            Self::OldNotFound => formatter.write_str(
                "old_text does not occur in the file; read it again and copy the exact text, \
                 whitespace included",
            ),
            Self::OldAmbiguous { occurrences } => write!(
                formatter,
                "old_text occurs {occurrences} times in the file; include enough surrounding \
                 lines that it matches exactly once"
            ),
        }
    }
}

fn splice(current: &str, old: &str, new: &str) -> Result<String, ReplaceRefusal> {
    if old.is_empty() {
        return Err(ReplaceRefusal::EmptyOld);
    }
    let mut found = current.match_indices(old);
    let Some((at, _)) = found.next() else {
        return Err(ReplaceRefusal::OldNotFound);
    };
    let more = found.count();
    if more > 0 {
        return Err(ReplaceRefusal::OldAmbiguous {
            occurrences: more + 1,
        });
    }
    let mut post = String::with_capacity(current.len() - old.len() + new.len());
    post.push_str(&current[..at]);
    post.push_str(new);
    post.push_str(&current[at + old.len()..]);
    Ok(post)
}

fn spliced(
    capsule: &PrivateCapability,
    path: &Path,
    old: &str,
    new: &str,
) -> Result<Vec<u8>, String> {
    let refused = |refusal: ReplaceRefusal| format!("{}: {refusal}", path.to_string_lossy());
    let file = open_read(capsule, path)?.ok_or_else(|| refused(ReplaceRefusal::Absent))?;
    let mut current = Vec::new();
    file.take(MAX_PREIMAGE_BYTES + 1)
        .read_to_end(&mut current)
        .map_err(|error| error.to_string())?;
    if current.len() as u64 > MAX_PREIMAGE_BYTES {
        return Err(refused(ReplaceRefusal::TooLarge));
    }
    let current = String::from_utf8(current).map_err(|_| refused(ReplaceRefusal::NotUtf8))?;
    let post = splice(&current, old, new).map_err(refused)?;
    if post.len() as u64 > MAX_PREIMAGE_BYTES {
        return Err(refused(ReplaceRefusal::TooLarge));
    }
    Ok(post.into_bytes())
}

fn decode_text(field: &str, hex: &str) -> Result<String, String> {
    let bytes = hex_decode(hex).map_err(|error| format!("{field} rejected: {error}"))?;
    String::from_utf8(bytes).map_err(|_| format!("{field} is not UTF-8"))
}

/// Calculate the replacement content without modifying the capsule.
pub(crate) fn replaced_content(
    capsule_root: &Path,
    path: &Path,
    old_hex: &str,
    new_hex: &str,
) -> Result<Vec<u8>, String> {
    validate_relative(path).and_then(|()| deny_git_path(path))?;
    let old = decode_text("old_hex", old_hex)?;
    let new = decode_text("new_hex", new_hex)?;
    spliced(&seal(capsule_root)?, path, &old, &new)
}

/// Missing or ambiguous old text must leave the file unchanged.
pub(crate) fn replace(
    capsule_root: &Path,
    identity: &CapsuleSourceIdentity,
    git_bin: &Path,
    path: &Path,
    old_hex: &str,
    new_hex: &str,
) -> Result<WriteOutcome, WriteError> {
    validate_relative(path)
        .and_then(|()| deny_git_path(path))
        .map_err(WriteError::unchanged)?;
    let old = decode_text("old_hex", old_hex).map_err(WriteError::unchanged)?;
    let new = decode_text("new_hex", new_hex).map_err(WriteError::unchanged)?;
    let capsule =
        verified_capsule(capsule_root, identity, git_bin).map_err(WriteError::unchanged)?;
    let content = spliced(&capsule, path, &old, &new).map_err(WriteError::unchanged)?;
    replace_existing(&capsule, path, &content)?;
    Ok(WriteOutcome {
        capsule: location(capsule_root, &capsule),
        created: false,
        bytes: content.len(),
        sha256: hex_encode(&Sha256::digest(&content)),
    })
}

fn create_new(capsule: &PrivateCapability, path: &Path, content: &[u8]) -> Result<(), WriteError> {
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        capsule.create_dirs(parent, 0o755).map_err(|error| {
            WriteError::unchanged(format!("the directories of {}: {error}", path.display()))
        })?;
    }
    capsule
        .create_atomic(path, content, 0o600)
        .map_err(|error| WriteError {
            detail: error.to_string(),
            phase: replaced_phase(capsule, path, content),
        })
}

// Check whether a failed write landed before classifying the operation as unchanged or uncertain.
fn replaced_phase(capsule: &PrivateCapability, path: &Path, content: &[u8]) -> &'static str {
    let intended = hex_encode(&Sha256::digest(content));
    let observed = capsule
        .open_read(path)
        .ok()
        .and_then(|file| stream_hash(&file, 0).ok())
        .map(|(digest, _, _, _)| digest == intended);
    match observed {
        Some(true) => "replaced",
        Some(false) | None => "unknown",
    }
}

pub(crate) fn diff(
    capsule_root: &Path,
    identity: &CapsuleSourceIdentity,
    git_bin: &Path,
    max_patch_bytes: usize,
) -> Result<DiffOutcome, String> {
    let source_commit = identity.verified_commit()?;
    let capsule = verified_capsule(capsule_root, identity, git_bin)?;
    let patch_bound = max_patch_bytes.min(MAX_PATCH_BYTES);
    let (patch_bytes, patch_truncated) = git_run(
        git_bin,
        capsule_root,
        &[
            "diff",
            "HEAD",
            "--no-color",
            "--no-ext-diff",
            "--no-textconv",
        ],
        patch_bound,
    )?;
    let (untracked_bytes, untracked_truncated) = git_run(
        git_bin,
        capsule_root,
        &["ls-files", "--others", "--exclude-standard", "-z"],
        MAX_UNTRACKED_BYTES,
    )?;
    let untracked: Vec<String> = untracked_bytes
        .split(|byte| *byte == 0)
        .filter(|entry| !entry.is_empty())
        .map(|entry| String::from_utf8_lossy(entry).into_owned())
        .collect();
    let untracked_list: Vec<String> = untracked
        .iter()
        .take(MAX_UNTRACKED_ENTRIES)
        .cloned()
        .collect();
    let untracked_list_truncated = untracked_truncated || untracked.len() > MAX_UNTRACKED_ENTRIES;
    let dirty = !patch_bytes.is_empty() || !untracked.is_empty();
    Ok(DiffOutcome {
        capsule: location(capsule_root, &capsule),
        status: if dirty { "dirty" } else { "clean" },
        patch: String::from_utf8_lossy(&patch_bytes).into_owned(),
        patch_bytes: patch_bytes.len(),
        patch_sha256: hex_encode(&Sha256::digest(&patch_bytes)),
        truncated: patch_truncated,
        untracked: untracked_list,
        untracked_truncated: untracked_list_truncated,
        source_commit: source_commit.to_string(),
    })
}

const MAX_STATUS_BYTES: usize = 262_144;
const MAX_FS_CHANGES: usize = 64;

const SCRATCH_DIR: &str = ".odin-eval";

/// Exclude untracked eval scratch so it cannot change the tracked-state digest.
pub(crate) fn tracked_state_digest(
    git_bin: &Path,
    capsule_root: &Path,
    identity: &CapsuleSourceIdentity,
) -> Result<String, String> {
    let _capsule = verified_capsule(capsule_root, identity, git_bin)?;
    let head = head_commit(git_bin, capsule_root)?;
    let (status, truncated) = git_run(
        git_bin,
        capsule_root,
        &["status", "--porcelain", "-z", "--untracked-files=no"],
        MAX_STATUS_BYTES,
    )?;
    if truncated {
        return Err("capsule tracked status exceeded its bound".to_string());
    }
    let mut material = Vec::with_capacity(status.len() + head.len() + 1);
    material.extend_from_slice(head.as_bytes());
    material.push(0);
    material.extend_from_slice(&status);
    Ok(format!("blake3:{}", blake3::hash(&material).to_hex()))
}

/// Return absolute capsule paths so consumers need not reconstruct the root.
pub(crate) fn observed_changes(
    git_bin: &Path,
    capsule_root: &Path,
) -> Result<(Vec<(String, String)>, bool), String> {
    let (status, truncated) = git_run(
        git_bin,
        capsule_root,
        &["status", "--porcelain", "-z", "--untracked-files=all"],
        MAX_STATUS_BYTES,
    )?;
    let mut changes: Vec<(String, String)> = Vec::new();
    let mut truncated_changes = truncated;
    let mut entries = status.split(|byte| *byte == 0).filter(|e| !e.is_empty());
    while let Some(entry) = entries.next() {
        if entry.len() < 4 {
            return Err("capsule status entry is malformed".to_string());
        }
        // Porcelain -z puts a rename's original path in the next field; keep the destination.
        let state = &entry[..2];
        let path = String::from_utf8_lossy(&entry[3..]).into_owned();
        if state == b"R " || state == b"RM" || state == b"C " {
            let _origin = entries.next();
        }
        let op = match state {
            b"??" => "create",
            b"D " | b" D" | b"MD" | b"DM" | b"AD" | b"DA" => "unlink",
            _ => "write",
        };
        let change = (
            op.to_owned(),
            capsule_root.join(&path).display().to_string(),
        );
        if !changes.contains(&change) {
            changes.push(change);
        }
        if changes.len() >= MAX_FS_CHANGES {
            truncated_changes = true;
            break;
        }
    }
    Ok((changes, truncated_changes))
}

/// Restrict staging to the operation's path inside the configured scratch directory.
pub(crate) fn validate_scratch_path(scratch: &str) -> Result<String, String> {
    let path = Path::new(scratch);
    validate_relative(path)?;
    deny_git_path(path)?;
    let mut components = path.components();
    let first = components
        .next()
        .ok_or_else(|| "scratch: empty".to_string())?;
    if first.as_os_str() != SCRATCH_DIR {
        return Err(format!(
            "scratch must live under {SCRATCH_DIR}/ inside the sealed capsule"
        ));
    }
    if components.count() != 1 {
        return Err("scratch must be exactly one file beneath the scratch directory".to_string());
    }
    Ok(scratch.to_owned())
}

pub(crate) fn stage_scratch(
    capsule_root: &Path,
    scratch: &str,
    source: &str,
) -> Result<(), String> {
    let scratch = validate_scratch_path(scratch)?;
    let source_bytes = source.as_bytes();
    if source_bytes.len() > MAX_WRITE_BYTES {
        return Err(format!(
            "source: {} bytes exceeds ceiling {MAX_WRITE_BYTES}",
            source_bytes.len()
        ));
    }
    let capsule = seal(capsule_root)?;
    let relative = Path::new(&scratch);
    if open_read(&capsule, relative)?.is_some() {
        capsule
            .write_atomic(relative, source_bytes, 0o600)
            .map_err(|error| format!("scratch staging failed: {error}"))?;
    } else {
        // Evaluated code may have removed the scratch directory.
        capsule
            .create_dirs(Path::new(SCRATCH_DIR), 0o700)
            .map_err(|error| format!("scratch staging failed: {error}"))?;
        capsule
            .create_atomic(relative, source_bytes, 0o600)
            .map_err(|error| format!("scratch staging failed: {error}"))?;
    }
    Ok(())
}

/// Report removal failures so the receipt records leftover scratch files.
pub(crate) fn remove_scratch(capsule_root: &Path, scratch: &str) -> Result<(), String> {
    let scratch = validate_scratch_path(scratch)?;
    let capsule = seal(capsule_root)?;
    match capsule.remove(Path::new(&scratch)) {
        Ok(()) | Err(ConfinedError::ComponentMissing { .. }) => Ok(()),
        Err(error) => Err(format!("scratch removal failed: {error}")),
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;
    use std::path::Path;

    use odin_confined_fs::PrivateCapability;

    use super::create_new;

    #[test]
    fn a_new_file_in_a_new_directory_is_created_with_its_directories() {
        let root = std::env::temp_dir().join(format!(
            "odin-effector-capsule-{}-new-dir",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir(&root).unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        let capsule = PrivateCapability::seal(&root).unwrap();
        let content = b"def clamp(x, lo, hi):\n    return max(lo, min(x, hi))\n";
        let created = create_new(&capsule, Path::new("tools/math/clamp.py"), content);
        assert!(
            created.is_ok(),
            "{:?}",
            created.err().map(|error| error.detail)
        );
        assert_eq!(
            std::fs::read(root.join("tools/math/clamp.py")).unwrap(),
            content
        );
        let again = create_new(&capsule, Path::new("tools/math/clamp.py"), content);
        assert!(again.is_err(), "an existing file is never replaced");
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn an_exact_replacement_applies_once_and_refuses_absent_or_ambiguous_text() {
        use super::{splice, ReplaceRefusal};
        let current = "fn a() {}\nfn b() {}\nfn a() {}\n";
        assert_eq!(
            splice(current, "fn b() {}", "fn b() { todo!() }").unwrap(),
            "fn a() {}\nfn b() { todo!() }\nfn a() {}\n"
        );
        assert_eq!(
            splice(current, "fn c() {}", "x"),
            Err(ReplaceRefusal::OldNotFound)
        );
        assert_eq!(
            splice(current, "fn a() {}", "x"),
            Err(ReplaceRefusal::OldAmbiguous { occurrences: 2 })
        );
        assert_eq!(splice(current, "", "x"), Err(ReplaceRefusal::EmptyOld));

        let root = std::env::temp_dir().join(format!(
            "odin-effector-capsule-{}-replace",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir(&root).unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::write(root.join("lib.rs"), current).unwrap();
        let hex = |text: &str| odin_types::hash::hex_encode(text.as_bytes());
        let post = super::replaced_content(&root, Path::new("lib.rs"), &hex("fn b"), &hex("fn z"))
            .expect("declared post-image");
        assert_eq!(post, b"fn a() {}\nfn z() {}\nfn a() {}\n");
        let ambiguous =
            super::replaced_content(&root, Path::new("lib.rs"), &hex("fn a"), &hex("fn z"))
                .unwrap_err();
        assert!(
            ambiguous.contains("lib.rs: old_text occurs 2 times"),
            "{ambiguous}"
        );
        let absent =
            super::replaced_content(&root, Path::new("new.rs"), &hex("a"), &hex("b")).unwrap_err();
        assert!(absent.contains("does not exist"), "{absent}");
        assert_eq!(
            std::fs::read_to_string(root.join("lib.rs")).unwrap(),
            current
        );
        std::fs::remove_dir_all(&root).unwrap();
    }

    /// Programs may remove scratch themselves; cleanup tolerates absence and later evals recreate it.
    #[test]
    fn evals_survive_a_program_that_removes_the_scratch_directory() {
        let root = std::env::temp_dir().join(format!(
            "odin-effector-capsule-{}-scratch",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir(&root).unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        let scratch = ".odin-eval/op-1";
        super::stage_scratch(&root, scratch, "print(1)").expect("first stage");
        std::fs::remove_dir_all(root.join(".odin-eval")).unwrap();
        super::remove_scratch(&root, scratch).expect("an already removed scratch is removed");
        super::stage_scratch(&root, ".odin-eval/op-2", "print(2)").expect("staged again");
        assert_eq!(
            std::fs::read_to_string(root.join(".odin-eval/op-2")).unwrap(),
            "print(2)"
        );
        assert_eq!(
            std::fs::metadata(root.join(".odin-eval"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
        super::remove_scratch(&root, ".odin-eval/op-2").expect("removed");
        std::fs::remove_dir_all(&root).unwrap();
    }
}
