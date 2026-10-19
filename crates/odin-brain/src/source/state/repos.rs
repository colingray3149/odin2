//! The repository state source: one deterministic brain projection of the
//! declared project Git roots (fabric layer `state.repos`).
//!
//! Roots arrive ONLY from the parent composition — the published, enabled
//! `source_root` declarations of projects. This source never scans arbitrary
//! paths and never discovers roots itself; [`ReposSource::new`] validates
//! each declared root and fails typed when it is missing, is not a Git
//! worktree root, or has an unborn HEAD.
//!
//! The COMMITTED tree at the canonical HEAD commit is the
//! only code authority. Atlas parsing runs against an immutable temporary
//! snapshot materialized from Git object bytes (`ls-tree` + `cat-file`),
//! never against the live, possibly dirty worktree — so a dirty edit can
//! never be mislabeled as committed. The snapshot is bounded (file count and
//! total bytes, failing closed when exceeded), contains no symlinks and no
//! submodules (both are skipped and honestly counted), and is discarded
//! when the pin ends. No persistent store, no second index.
//!
//! Deterministic observations ([`TrustClass::Observed`]):
//! - One summary item per project under the natural key `repo/<project>/summary`
//!   and one AST item per Atlas node under `repo/<project>/ast/<node-id>`;
//!   every item is bound to its project with [`SourceItem::with_project`].
//!   The summary is the project's generated-knowledge page
//!   ([`SourceItem::with_summary_page`]); AST items never reach the vault.
//! - The summary records the exact commit SHA, branch (or an explicit
//!   `detached` statement), commit metadata, the most recent commits
//!   (bounded), and the tracked working-tree changes reported by
//!   `git status --untracked-files=no`. Untracked files are NOT observed:
//!   uncommitted files are not committed project authority, and the summary
//!   says so explicitly instead of implying coverage.
//! - The head digest binds the commit SHA and EVERY observation (branch,
//!   commit metadata, recent commits, tracked status entries, Atlas
//!   generation) in canonical length-prefixed order. A commit amend, a
//!   branch move at the same SHA, or a tracked dirty change each yields a
//!   new head, so a same-head dirty/branch change can never stale-serve.
//! - Freshness against a moving HEAD: the commit is resolved before and
//!   re-resolved after projection; any movement fails the WHOLE pin with a
//!   typed [`BrainError::StaleAuthority`] rather than serving mixed bytes.
//!
//! Every Git invocation is read-only plumbing
//! (`rev-parse`, `symbolic-ref`, `status`, `log`, `ls-tree`, `cat-file`),
//! which never fires repository hooks. Each child runs in an ISOLATED
//! environment: inherited `GIT_DIR`/`GIT_WORK_TREE`/`GIT_INDEX_FILE`/
//! `GIT_COMMON_DIR`, alternate object/config override variables, and
//! external diff/attr overrides are all stripped (`env_clear` plus an
//! explicit minimal environment), replace objects are disabled, system and
//! global config are refused, hooks point at `/dev/null`, `core.fsmonitor`
//! is off, and `GIT_OPTIONAL_LOCKS=0`. A foreign Git environment can never
//! substitute undeclared repository authority, refresh the index, start
//! helper daemons, or feed the watcher that triggers re-projection. Every
//! command's captured stdout is hard-capped; an excessive listing is a
//! typed error, never an unbounded read.
//!
//! Watcher contract ([`ReposSource::watch_paths`]): ABSOLUTE paths only —
//! the Git dir and common dir, their `refs` roots plus `refs/heads` and
//! every directory holding a nested ref, the worktree root, and every
//! existing ancestor directory of a tracked file. A nonrecursive watcher
//! on this set sees tracked churn and branch commits while remaining blind
//! to ignored output directories such as `target/`; the set is re-derived
//! on every call so the integration can refresh watches after events.
//! Exceeding the watch bound is a typed error, never silent coverage loss.
//!
//! Errors fail closed: every fallible step propagates; nothing is silently
//! skipped or defaulted.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::sync::{Arc, Mutex};

use crate::source::atlas::{node_text, scope_tags, AtlasSource, PinnedAtlas};
use odin_domain::knowledge::ids::AtlasId;
use odin_domain::knowledge::retrieval::TrustClass;
use odin_domain::Digest;
use odin_domain::ProjectId;

use crate::error::{BrainError, BrainResult};
use crate::index::model::ItemProvenance;
use crate::source::SourceItem;

/// Domain-separation prefix for the head digest material.
const HEAD_DOMAIN: &[u8] = b"odin-brain:repos-head:v1\x00";

/// Materialization bounds for one committed snapshot. Both fail closed.
const MAX_FILES_PER_SNAPSHOT: usize = 20_000;
const MAX_SNAPSHOT_BYTES: u64 = 64 * 1024 * 1024;

/// Recent commits reported and digested per project.
const MAX_RECENT_COMMITS: usize = 10;

/// Tracked status entries rendered into the summary; the full count is
/// always reported and always bound into the head digest.
const MAX_STATUS_ENTRIES: usize = 64;

/// Tracked-parent directories returned by [`ReposSource::watch_paths`];
/// exceeding the bound is a typed error, never silent coverage loss.
const MAX_WATCH_DIRS_PER_ROOT: usize = 4096;

/// Hard cap on any single Git command's captured stdout. Observation
/// listings (`ls-tree`, `status`, `log`) for one repository never approach
/// this; exceeding it is a typed error instead of an unbounded read.
const MAX_GIT_OUTPUT_BYTES: u64 = 16 * 1024 * 1024;

/// Field separator inside one Git log record (`%x01`); records are NUL
/// separated, so any field content survives verbatim.
const LOG_FIELD_SEPARATOR: u8 = 0x01;

/// One declared project root pair, validated at construction.
#[derive(Clone)]
pub struct ReposSource {
    atlas_id: AtlasId,
    projects: BTreeMap<ProjectId, PathBuf>,
    /// Cache immutable trees by commit SHA, shared across restricted views;
    /// each pin still rereads mutable ref, status, log, and branch observations.
    committed_atlas: Arc<Mutex<BTreeMap<ProjectId, CommittedAtlas>>>,
}

/// One memoized committed-tree Atlas build.
#[derive(Clone)]
struct CommittedAtlas {
    commit: String,
    atlas: PinnedAtlas,
    symlink_count: usize,
    submodule_count: usize,
}

impl ReposSource {
    /// Binds this source to one knowledge-source identity and the declared
    /// project roots. Roots MUST come from the published, enabled project
    /// `source_root` declarations; each is validated as an exact Git
    /// worktree root with a resolvable HEAD before the source exists. An
    /// empty map is a declared source with no rooted projects: it reads
    /// nothing, watches nothing, and pins the domain-separated empty head —
    /// exactly the semantics of an empty [`ReposSource::restrict_projects`].
    pub fn new(atlas_id: AtlasId, projects: BTreeMap<ProjectId, PathBuf>) -> BrainResult<Self> {
        for (project, root) in &projects {
            validate_git_root(project, root)?;
        }
        Ok(Self {
            atlas_id,
            projects,
            committed_atlas: Arc::new(Mutex::new(BTreeMap::new())),
        })
    }

    /// Composes valid roots and returns refusals separately so a missing or
    /// unborn repository does not prevent other sources from opening.
    pub fn new_available(
        atlas_id: AtlasId,
        projects: BTreeMap<ProjectId, PathBuf>,
    ) -> (Self, Vec<(ProjectId, BrainError)>) {
        let mut refused = Vec::new();
        let projects = projects
            .into_iter()
            .filter_map(|(project, root)| match validate_git_root(&project, &root) {
                Ok(()) => Some((project, root)),
                Err(error) => {
                    refused.push((project, error));
                    None
                }
            })
            .collect();
        let source = Self {
            atlas_id,
            projects,
            committed_atlas: Arc::new(Mutex::new(BTreeMap::new())),
        };
        (source, refused)
    }

    /// The knowledge source identity used for items and citations.
    pub const fn atlas_id(&self) -> &AtlasId {
        &self.atlas_id
    }

    /// The declared project roots this source projects (read-only view for
    /// composition and watcher wiring).
    pub const fn projects(&self) -> &BTreeMap<ProjectId, PathBuf> {
        &self.projects
    }

    /// Restricts this source to the declared subset of `projects`, keeping
    /// their declared roots. Unknown ids are ignored; an empty intersection
    /// is valid (a seat scoped to none of these projects) and pins the
    /// domain-separated empty head with no items.
    pub fn restrict_projects(&self, projects: &BTreeSet<ProjectId>) -> Self {
        Self {
            atlas_id: self.atlas_id.clone(),
            projects: self
                .projects
                .iter()
                .filter(|(project, _)| projects.contains(project))
                .map(|(project, root)| (project.clone(), root.clone()))
                .collect(),
            committed_atlas: Arc::clone(&self.committed_atlas),
        }
    }

    /// The filesystem paths a nonrecursive watcher must register to observe
    /// this source, all ABSOLUTE: the Git dir and common dir (for HEAD,
    /// index, and config), their `refs` roots plus `refs/heads` and every
    /// directory holding a nested ref (a flat `refs` watch misses branch
    /// commits under `refs/heads/…/…`), the worktree root, and every
    /// EXISTING ancestor directory of a tracked file (deepest parent back
    /// to the root, so a nonrecursive watch sees both file churn inside a
    /// directory and new directories appearing beside it). Ignored output
    /// directories (e.g. `target/`) contain no tracked files and are never
    /// returned, so ignored churn cannot loop the watcher; ancestor
    /// directories deleted in the worktree are skipped safely.
    ///
    /// Exceeding the watch bound is a typed ERROR, never a silent loss of
    /// coverage. Roots must still be valid Git worktrees; failures
    /// propagate typed.
    pub fn watch_paths(&self) -> BrainResult<Vec<PathBuf>> {
        self.watch_set(MAX_WATCH_DIRS_PER_ROOT)
    }

    fn watch_set(&self, max_paths: usize) -> BrainResult<Vec<PathBuf>> {
        let mut paths = BTreeSet::new();
        for root in self.projects.values() {
            let git = Git::at(root);
            let git_dir = absolute_git_dir(&git)?;
            let common_dir = absolute_common_dir(root, &git)?;
            paths.insert(root.clone());
            paths.insert(git_dir.clone());
            paths.insert(common_dir.clone());
            for base in [&git_dir, &common_dir] {
                paths.insert(base.join("refs"));
                paths.insert(base.join("refs/heads"));
                for ref_dir in ref_watch_dirs(base, &git)? {
                    paths.insert(ref_dir);
                }
            }
            for tracked in tracked_files(&git)? {
                let mut ancestor = root.clone();
                paths.insert(ancestor.clone());
                if let Some(parent) = tracked.parent() {
                    for component in parent.components() {
                        ancestor.push(component);
                        // Deleted-in-worktree directories are skipped: the
                        // watcher cannot register a path that does not
                        // exist, and the next pin re-derives the set.
                        if ancestor.is_dir() {
                            paths.insert(ancestor.clone());
                        }
                    }
                }
            }
        }
        // Linked worktrees keep refs in the common directory, not necessarily
        // in their per-worktree git directory. Existing parents observe creation.
        paths.retain(|path| path.is_dir());
        if paths.len() > max_paths {
            return Err(BrainError::InvalidRequest(format!(
                "watch path bound exceeded: {} paths needed, bound is {max_paths}",
                paths.len()
            )));
        }
        Ok(paths.into_iter().collect())
    }

    /// Pins every declared project and projects it into the head digest plus
    /// the full item set. Each call re-reads the authority; an unchanged
    /// world pins the identical head and identical items.
    pub fn pin(&self) -> BrainResult<(Digest, Vec<SourceItem>)> {
        let mut pins = Vec::with_capacity(self.projects.len());
        for (project, root) in &self.projects {
            pins.push(project_pin(
                self.atlas_id.clone(),
                project,
                root,
                &self.committed_atlas,
            )?);
        }

        let head = head_digest(&pins);
        let mut items = Vec::new();
        for pin in &pins {
            items.push(summary_item(pin, head)?);
            let mut ast_items = ast_items(pin, head)?;
            ast_items.sort_by_key(|item| item.item_id);
            items.append(&mut ast_items);
        }
        Ok((head, items))
    }
}

/// Manual [`Debug`]: declared roots are composition inputs, not secrets, but
/// only the identity is part of the debug contract.
impl fmt::Debug for ReposSource {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ReposSource")
            .field("atlas_id", &self.atlas_id)
            .field("projects", &self.projects.len())
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Copy, Debug)]
struct SnapshotBounds {
    max_files: usize,
    max_bytes: u64,
}

const DEFAULT_BOUNDS: SnapshotBounds = SnapshotBounds {
    max_files: MAX_FILES_PER_SNAPSHOT,
    max_bytes: MAX_SNAPSHOT_BYTES,
};

/// One tracked working-tree change, exactly as `git status --porcelain=v1`
/// reports it (`XY` codes; `orig_path` set for renames and copies).
#[derive(Clone, Debug, Eq, PartialEq)]
struct StatusEntry {
    code: [char; 2],
    path: String,
    orig_path: Option<String>,
}

/// One recent commit, exactly as `git log` reports it.
#[derive(Clone, Debug, Eq, PartialEq)]
struct RecentCommit {
    sha: String,
    author: String,
    committed_at: String,
    subject: String,
}

/// One pinned project: the resolved authority state and the Atlas build over
/// the immutable committed snapshot.
#[derive(Debug)]
struct ProjectPin {
    project: ProjectId,
    root: PathBuf,
    /// The canonical HEAD commit SHA (full, lowercase hex).
    commit: String,
    /// The branch name, or `None` for a detached HEAD (stated honestly).
    branch: Option<String>,
    recent: Vec<RecentCommit>,
    status: Vec<StatusEntry>,
    /// Total tracked changes, including any beyond `status`'s render bound.
    status_total: usize,
    /// Symlinks in the committed tree (skipped, never materialized).
    symlink_count: usize,
    /// Submodule gitlinks in the committed tree (skipped).
    submodule_count: usize,
    /// Atlas build over the committed snapshot.
    atlas: PinnedAtlas,
}

/// Pins one project: resolve the authority, observe it, snapshot the
/// committed tree, build Atlas over the snapshot, then re-verify the head.
fn project_pin(
    atlas_id: AtlasId,
    project: &ProjectId,
    root: &Path,
    memo: &Mutex<BTreeMap<ProjectId, CommittedAtlas>>,
) -> BrainResult<ProjectPin> {
    let git = Git::at(root);
    let commit = git.resolve_head()?;

    let status = git.status_tracked()?;
    let status_total = status.len();
    let status = status
        .into_iter()
        .take(MAX_STATUS_ENTRIES)
        .collect::<Vec<_>>();
    let recent = git.recent_commits(MAX_RECENT_COMMITS)?;
    let branch = git.current_branch()?;

    let memoized = memo
        .lock()
        .map_err(|_| BrainError::Corrupt {
            component: "state.repos",
            reason: "committed atlas memo mutex is poisoned".to_owned(),
        })?
        .get(project)
        .filter(|entry| entry.commit == commit && entry.atlas.atlas_id() == &atlas_id)
        .cloned();
    let (atlas, symlink_count, submodule_count) = match memoized {
        Some(entry) => (entry.atlas, entry.symlink_count, entry.submodule_count),
        None => {
            let (snapshot, symlink_count, submodule_count) =
                materialize_committed_tree(root, &git, &commit, DEFAULT_BOUNDS)?;
            let atlas = AtlasSource::new(snapshot.path(), atlas_id).pin()?;
            memo.lock()
                .map_err(|_| BrainError::Corrupt {
                    component: "state.repos",
                    reason: "committed atlas memo mutex is poisoned".to_owned(),
                })?
                .insert(
                    project.clone(),
                    CommittedAtlas {
                        commit: commit.clone(),
                        atlas: atlas.clone(),
                        symlink_count,
                        submodule_count,
                    },
                );
            (atlas, symlink_count, submodule_count)
        }
    };

    // Freshness guard: the commit is immutable, but the REF is not. Any head
    // movement during projection fails the whole pin instead of serving
    // bytes and observations read from different worlds.
    let repinned = git.resolve_head()?;
    if repinned != commit {
        return Err(BrainError::StaleAuthority {
            authority: "state.repos",
            detail: format!(
                "head of project {project} moved during projection ({commit} -> {repinned})"
            ),
        });
    }

    Ok(ProjectPin {
        project: project.clone(),
        root: root.to_path_buf(),
        commit,
        branch,
        recent,
        status,
        status_total,
        symlink_count,
        submodule_count,
        atlas,
    })
}

/// The head digest binds every observation of every project in canonical
/// (project id) order with length-prefixed fields — the exact identity of
/// the pinned repository world.
fn head_digest(pins: &[ProjectPin]) -> Digest {
    let mut material = Material::with_capacity(HEAD_DOMAIN.len() + 16 + pins.len() * 256);
    material.bytes(HEAD_DOMAIN);
    material.count(pins.len());
    for pin in pins {
        material.bytes(pin.project.as_str().as_bytes());
        material.bytes(pin.root.as_os_str().as_encoded_bytes());
        material.bytes(pin.commit.as_bytes());
        match &pin.branch {
            Some(branch) => {
                material.raw(&[0x01]);
                material.bytes(branch.as_bytes());
            }
            None => material.raw(&[0x00]),
        }
        material.count(pin.recent.len());
        for commit in &pin.recent {
            material.bytes(commit.sha.as_bytes());
            material.bytes(commit.author.as_bytes());
            material.bytes(commit.committed_at.as_bytes());
            material.bytes(commit.subject.as_bytes());
        }
        material.count(pin.status_total);
        material.count(pin.status.len());
        for entry in &pin.status {
            material.raw(&[entry.code[0] as u8, entry.code[1] as u8]);
            material.bytes(entry.path.as_bytes());
            match &entry.orig_path {
                Some(orig) => {
                    material.raw(&[0x01]);
                    material.bytes(orig.as_bytes());
                }
                None => material.raw(&[0x00]),
            }
        }
        material.raw(&[0x00]);
        material.bytes(pin.atlas.revision().as_bytes());
    }
    Digest::hash(&material.bytes)
}

/// Length-prefixed canonical byte material for content and head digests.
struct Material {
    bytes: Vec<u8>,
}

impl Material {
    fn with_capacity(capacity: usize) -> Self {
        Self {
            bytes: Vec::with_capacity(capacity),
        }
    }

    fn count(&mut self, count: usize) {
        self.bytes.extend_from_slice(&(count as u64).to_be_bytes());
    }

    fn raw(&mut self, bytes: &[u8]) {
        self.bytes.extend_from_slice(bytes);
    }

    fn bytes(&mut self, bytes: &[u8]) {
        self.bytes
            .extend_from_slice(&(bytes.len() as u64).to_be_bytes());
        self.bytes.extend_from_slice(bytes);
    }
}

/// The project summary item: exact commit SHA, branch, commit metadata,
/// recent commits, tracked working-tree observations, and the explicit
/// untracked-exclusion statement.
fn summary_item(pin: &ProjectPin, head: Digest) -> BrainResult<SourceItem> {
    let mut text = String::with_capacity(512);
    text.push_str(&format!(
        "project {} at {}\n",
        pin.project,
        pin.root.display()
    ));
    text.push_str(&format!("head {}\n", pin.commit));
    match &pin.branch {
        Some(branch) => text.push_str(&format!("branch {branch}\n")),
        None => text.push_str("branch: detached HEAD (no branch ref)\n"),
    }
    if let Some(commit) = pin.recent.first() {
        text.push_str(&format!("subject {}\n", commit.subject));
        text.push_str(&format!(
            "authored {} / committed {}\n",
            commit.author, commit.committed_at
        ));
    }
    text.push_str(&format!(
        "recent commits (newest first, limit {MAX_RECENT_COMMITS}):\n"
    ));
    for commit in &pin.recent {
        text.push_str(&format!(
            "  {} {} {}\n",
            commit.sha, commit.committed_at, commit.subject
        ));
    }
    if pin.status_total == 0 {
        text.push_str("working tree tracked changes: clean\n");
    } else {
        text.push_str(&format!(
            "working tree tracked changes: {} total (showing {})\n",
            pin.status_total,
            pin.status.len()
        ));
        for entry in &pin.status {
            text.push_str(&format!(
                "  {}{} {}{}\n",
                entry.code[0],
                entry.code[1],
                entry.path,
                match &entry.orig_path {
                    Some(orig) => format!(" (renamed from {orig})"),
                    None => String::new(),
                }
            ));
        }
    }
    text.push_str(
        "open work: untracked files are excluded by policy (--untracked-files=no); \
         uncommitted files are not committed project authority and are not observed\n",
    );
    if pin.symlink_count > 0 || pin.submodule_count > 0 {
        text.push_str(&format!(
            "committed tree skips {} symlink(s) and {} submodule(s)\n",
            pin.symlink_count, pin.submodule_count
        ));
    }
    text.push_str(&format!(
        "committed AST projection: {} atlas nodes, atlas generation {}",
        pin.atlas.atlas().nodes.len(),
        pin.atlas.revision()
    ));

    let item = SourceItem::new(
        pin.atlas.atlas_id().clone(),
        head,
        format!("repo/{}/summary", pin.project).as_bytes(),
        TrustClass::Observed,
        text,
    )?;
    Ok(item
        .with_project(pin.project.clone())
        .with_summary_page(pin.project.as_str()))
}

/// Keep the commit SHA in the summary only so unchanged nodes reuse their embeddings.
fn ast_items(pin: &ProjectPin, head: Digest) -> BrainResult<Vec<SourceItem>> {
    let mut items = Vec::with_capacity(pin.atlas.atlas().nodes.len());
    for node in &pin.atlas.atlas().nodes {
        let text = format!("{}\n{}", node.path, node_text(node));
        let provenance = ItemProvenance {
            node_id: node.id.clone(),
            path: node.path.clone(),
            source_class: node.source_class,
            scope_tags: scope_tags(node),
        };
        items.push(
            SourceItem::new(
                pin.atlas.atlas_id().clone(),
                head,
                format!("repo/{}/ast/{}", pin.project, node.id).as_bytes(),
                TrustClass::Observed,
                text,
            )?
            .with_project(pin.project.clone())
            .with_provenance(provenance),
        );
    }
    Ok(items)
}

/// Validates one declared root as an exact Git worktree root with a
/// resolvable HEAD, failing typed on missing paths, non-repositories,
/// non-root subdirectories, and unborn HEADs.
fn validate_git_root(project: &ProjectId, root: &Path) -> BrainResult<()> {
    if !root.exists() {
        return Err(BrainError::NotFound {
            kind: "declared project root",
            id: format!("{project}: {}", root.display()),
        });
    }
    if !root.is_dir() {
        return Err(BrainError::InvalidRequest(format!(
            "declared root of project {project} ({}) is not a directory",
            root.display()
        )));
    }
    let git = Git::at(root);
    let toplevel = git.run_text(&["rev-parse", "--show-toplevel"])?;
    let toplevel = PathBuf::from(toplevel);
    let declared = fs::canonicalize(root).map_err(|source| {
        BrainError::InvalidRequest(format!(
            "declared root of project {project} ({}) cannot be canonicalized: {source}",
            root.display()
        ))
    })?;
    let actual = fs::canonicalize(&toplevel).map_err(|source| {
        BrainError::InvalidRequest(format!(
            "git worktree root {} of project {project} cannot be canonicalized: {source}",
            toplevel.display()
        ))
    })?;
    if declared != actual {
        return Err(BrainError::InvalidRequest(format!(
            "declared root of project {project} ({}) is not a Git worktree root (actual root: {})",
            root.display(),
            toplevel.display()
        )));
    }
    git.resolve_head().map(|_| ())
}

/// Materializes the committed tree of `commit` into a fresh temporary
/// directory from Git object bytes only. Bounded by `bounds` (failing
/// closed), symlink-free (symlinks are skipped and counted, so nothing in
/// the snapshot can escape it), and submodule-free (gitlinks skipped).
///
/// The four Atlas source directories (`crates/`, `extension/`, `registry/`,
/// `skeletons/`) are fabricated empty when the committed tree has none, so
/// a project not shaped like the monorepo still pins with a zero-node AST
/// projection instead of failing Atlas root resolution.
fn materialize_committed_tree(
    root: &Path,
    git: &Git,
    commit: &str,
    bounds: SnapshotBounds,
) -> BrainResult<(tempfile::TempDir, usize, usize)> {
    const ATLAS_SOURCE_DIRS: [&str; 4] = ["crates", "extension", "registry", "skeletons"];

    let listing = git.run(&["ls-tree", "-r", "-z", &format!("{commit}^{{tree}}")])?;
    let snapshot = tempfile::TempDir::new()
        .map_err(|source| git.unavailable("could not create snapshot directory", source))?;

    let mut files = 0_usize;
    let mut total_bytes = 0_u64;
    let mut symlinks = 0_usize;
    let mut submodules = 0_usize;
    let mut blobs = BatchBlobs::spawn(root)?;

    for record in listing.split(|byte| *byte == 0).filter(|r| !r.is_empty()) {
        // `<mode> SP <type> SP <sha> TAB <path>`
        let tab = record
            .iter()
            .position(|byte| *byte == b'\t')
            .ok_or_else(|| git.invalid("malformed ls-tree record"))?;
        let (meta, path) = record.split_at(tab);
        let path = validate_tree_path(&path[1..])?;
        let mut meta = meta.split(|byte| *byte == b' ');
        let mode = meta.next().unwrap_or_default();
        let kind = meta.next().unwrap_or_default();
        let object = String::from_utf8(meta.next().unwrap_or_default().to_vec())
            .map_err(|_| git.invalid("ls-tree object id is not UTF-8"))?;
        match (mode, kind) {
            // Materialize only Atlas inputs so unrelated large blobs do not consume the snapshot budget.
            (b"100644", b"blob") | (b"100755", b"blob")
                if !ATLAS_SOURCE_DIRS
                    .iter()
                    .any(|directory| path.starts_with(directory)) => {}
            (b"100644", b"blob") | (b"100755", b"blob") => {
                files += 1;
                if files > bounds.max_files {
                    return Err(BrainError::InvalidRequest(format!(
                        "committed snapshot bound exceeded: more than {} files in {commit}",
                        bounds.max_files
                    )));
                }
                let bytes = blobs.blob(&object, bounds.max_bytes - total_bytes)?;
                total_bytes += bytes.len() as u64;
                let target = snapshot.path().join(&path);
                if let Some(parent) = target.parent() {
                    fs::create_dir_all(parent).map_err(|source| {
                        git.unavailable(
                            format!("could not create snapshot directory {}", parent.display()),
                            source,
                        )
                    })?;
                }
                fs::write(&target, &bytes).map_err(|source| {
                    git.unavailable(
                        format!("could not write snapshot file {}", target.display()),
                        source,
                    )
                })?;
            }
            (b"120000", _) => symlinks += 1,
            (b"160000", _) => submodules += 1,
            _ => return Err(git.invalid("unsupported tree entry mode")),
        }
    }
    for directory in ATLAS_SOURCE_DIRS {
        fs::create_dir_all(snapshot.path().join(directory)).map_err(|source| {
            git.unavailable(
                format!("could not prepare atlas source directory {directory}"),
                source,
            )
        })?;
    }
    Ok((snapshot, symlinks, submodules))
}

/// Validates one committed tree path for materialization: relative, no
/// empty, `.`, or `..` components, valid UTF-8 — so nothing can escape the
/// snapshot directory.
fn validate_tree_path(path: &[u8]) -> BrainResult<PathBuf> {
    let path = std::str::from_utf8(path)
        .map_err(|_| BrainError::InvalidRequest("committed tree path is not UTF-8".to_owned()))?;
    if path.is_empty() || path.starts_with('/') || path.contains('\0') {
        return Err(BrainError::InvalidRequest(format!(
            "committed tree path {path:?} is not a safe relative path"
        )));
    }
    for component in path.split('/') {
        if component.is_empty() || component == "." || component == ".." {
            return Err(BrainError::InvalidRequest(format!(
                "committed tree path {path:?} contains an unsafe component"
            )));
        }
    }
    Ok(PathBuf::from(path))
}

/// Reads blobs from one long-lived `git cat-file --batch` process, one
/// interleaved request at a time (no unbounded buffers, no per-blob spawn).
struct BatchBlobs {
    child: Child,
    stdin: Option<ChildStdin>,
    stdout: BufReader<ChildStdout>,
}

impl BatchBlobs {
    fn spawn(root: &Path) -> BrainResult<Self> {
        let mut child = Git::at(root)
            .command(&["cat-file", "--batch"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|source| BrainError::Unavailable {
                component: "git",
                reason: format!("could not spawn git cat-file --batch: {source}"),
            })?;
        let stdin = child.stdin.take();
        let stdout = child.stdout.take();
        let stdin = stdin.ok_or_else(|| BrainError::Unavailable {
            component: "git",
            reason: "git cat-file --batch has no stdin".to_owned(),
        })?;
        let stdout = stdout.ok_or_else(|| BrainError::Unavailable {
            component: "git",
            reason: "git cat-file --batch has no stdout".to_owned(),
        })?;
        Ok(Self {
            child,
            stdin: Some(stdin),
            stdout: BufReader::new(stdout),
        })
    }

    /// Reads exactly one blob's bytes. `max_bytes` is the REMAINING
    /// snapshot budget: an oversize blob is rejected from its header
    /// BEFORE any allocation, so an adversarially large object can never
    /// drive an unbounded allocation.
    fn blob(&mut self, object: &str, max_bytes: u64) -> BrainResult<Vec<u8>> {
        let stdin = self.stdin.as_mut().ok_or_else(|| BrainError::Unavailable {
            component: "git",
            reason: "git cat-file --batch stdin closed".to_owned(),
        })?;
        stdin
            .write_all(object.as_bytes())
            .and_then(|_| stdin.write_all(b"\n"))
            .and_then(|_| stdin.flush())
            .map_err(|source| BrainError::Unavailable {
                component: "git",
                reason: format!("git cat-file --batch request failed: {source}"),
            })?;

        let mut header = String::new();
        self.stdout
            .read_line(&mut header)
            .map_err(|source| BrainError::Unavailable {
                component: "git",
                reason: format!("git cat-file --batch response failed: {source}"),
            })?;
        let mut header = header.split_whitespace();
        let _oid = header.next();
        let kind = header.next().unwrap_or_default();
        let size: u64 = header
            .next()
            .and_then(|size| size.parse().ok())
            .ok_or_else(|| BrainError::Unavailable {
                component: "git",
                reason: format!("git cat-file --batch returned a malformed header: {header:?}"),
            })?;
        if kind != "blob" {
            return Err(BrainError::Unavailable {
                component: "git",
                reason: format!("git cat-file --batch returned a {kind}, expected blob"),
            });
        }
        if size > max_bytes {
            return Err(BrainError::InvalidRequest(format!(
                "committed snapshot bound exceeded: blob {object} is {size} bytes, \
                 {max_bytes} remain"
            )));
        }
        let mut bytes = vec![0_u8; size as usize];
        self.stdout
            .read_exact(&mut bytes)
            .map_err(|source| BrainError::Unavailable {
                component: "git",
                reason: format!("git cat-file --batch blob read failed: {source}"),
            })?;
        // Trailing LF after the blob body, read explicitly: a buffered
        // `consume` cannot be trusted to fill and skip past the buffer.
        let mut newline = [0_u8; 1];
        self.stdout
            .read_exact(&mut newline)
            .map_err(|source| BrainError::Unavailable {
                component: "git",
                reason: format!("git cat-file --batch terminator read failed: {source}"),
            })?;
        Ok(bytes)
    }
}

impl Drop for BatchBlobs {
    fn drop(&mut self) {
        // Close stdin AND kill: on an error path (oversize blob, broken
        // pipe) the child may still be streaming a body nobody reads, and
        // `wait` alone could block forever on a full stdout pipe.
        self.stdin.take();
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Read-only Git plumbing runner for one worktree. Every invocation runs in
/// the isolated child environment of [`Config`] and never fires repository
/// hooks, refreshes the index, or starts helper daemons — observing a
/// repository cannot feed the watcher that triggers re-projection.
struct Git<'a> {
    root: &'a Path,
}

impl<'a> Git<'a> {
    /// Repository-local config overrides applied to every invocation.
    const CONFIG: Config = Config;

    fn at(root: &'a Path) -> Self {
        Self { root }
    }

    /// One isolated, read-only Git command for this worktree: the child
    /// environment is cleared and rebuilt from a minimal safe set, so no
    /// inherited `GIT_DIR`/`GIT_WORK_TREE`/`GIT_INDEX_FILE`/`GIT_COMMON_DIR`,
    /// alternate object directory, config override (`GIT_CONFIG`,
    /// `GIT_CONFIG_PARAMETERS`, `GIT_CONFIG_COUNT`), or external diff/text
    /// filter variable can substitute undeclared repository authority.
    fn command(&self, args: &[&str]) -> Command {
        let mut command = Command::new(git_program());
        command.arg("-C").arg(self.root);
        command.args(Self::CONFIG.args());
        command.args(args);
        command.env_clear();
        for (key, value) in Config::ISOLATED_ENV {
            command.env(key, value);
        }
        if let Some(path) = std::env::var_os("PATH") {
            command.env("PATH", path);
        }
        command
    }

    fn run(&self, args: &[&str]) -> BrainResult<Vec<u8>> {
        let (stdout, stderr, status) = run_capped(
            self.command(args),
            args.first().copied().unwrap_or("git"),
            self.root,
        )?;
        if !status.success() {
            let trimmed = String::from_utf8_lossy(&stderr).trim().to_owned();
            if trimmed.contains("not a git repository") {
                return Err(BrainError::InvalidRequest(format!(
                    "declared root {} is not inside a Git worktree",
                    self.root.display()
                )));
            }
            if trimmed.contains("unknown revision")
                || trimmed.contains("ambiguous argument")
                || trimmed.contains("bad revision")
            {
                return Err(BrainError::InvalidRequest(format!(
                    "declared root {} has an unborn HEAD (no commits yet)",
                    self.root.display()
                )));
            }
            return Err(BrainError::InvalidRequest(format!(
                "git {} at {} failed: {trimmed}",
                args.first().unwrap_or(&""),
                self.root.display()
            )));
        }
        Ok(stdout)
    }

    fn run_text(&self, args: &[&str]) -> BrainResult<String> {
        let stdout = self.run(args)?;
        String::from_utf8(stdout)
            .map(|text| text.trim_end().to_owned())
            .map_err(|_| BrainError::InvalidRequest("git output is not valid UTF-8".to_owned()))
    }

    /// The canonical HEAD commit SHA, validated as a full lowercase hex
    /// object id (SHA-1 40 or SHA-256 64 digits).
    fn resolve_head(&self) -> BrainResult<String> {
        let sha = self.run_text(&["rev-parse", "--verify", "HEAD"])?;
        if !is_canonical_oid(&sha) {
            return Err(BrainError::InvalidRequest(format!(
                "git at {} returned a malformed HEAD object id: {sha:?}",
                self.root.display()
            )));
        }
        Ok(sha)
    }

    /// The short branch name HEAD symbolically points at, or `None` for a
    /// detached HEAD. Git answers detached with exit 1 and quiet output —
    /// an observation, not a failure.
    fn current_branch(&self) -> BrainResult<Option<String>> {
        let (stdout, stderr, status) = run_capped(
            self.command(&["symbolic-ref", "--short", "-q", "HEAD"]),
            "symbolic-ref",
            self.root,
        )?;
        if status.success() {
            let branch = String::from_utf8(stdout)
                .map_err(|_| self.invalid("git symbolic-ref output is not UTF-8"))?
                .trim_end()
                .to_owned();
            return Ok((!branch.is_empty()).then_some(branch));
        }
        // Exit 1 with quiet output is git's detached-HEAD answer, not a
        // failure.
        if status.code() == Some(1) && stdout.is_empty() {
            return Ok(None);
        }
        Err(self.invalid(&format!(
            "git symbolic-ref failed: {}",
            String::from_utf8_lossy(&stderr).trim()
        )))
    }

    /// Tracked working-tree changes only: untracked files are excluded at
    /// the source (`--untracked-files=no`) — uncommitted files are not
    /// committed project authority.
    fn status_tracked(&self) -> BrainResult<Vec<StatusEntry>> {
        let raw = self.run(&["status", "--porcelain=v1", "-z", "--untracked-files=no"])?;
        let mut entries = Vec::new();
        let mut records = raw.split(|byte| *byte == 0).filter(|r| !r.is_empty());
        while let Some(record) = records.next() {
            if record.len() < 4 || record[2] != b' ' {
                return Err(self.invalid("malformed git status record"));
            }
            let path = std::str::from_utf8(&record[3..])
                .map_err(|_| self.invalid("git status path is not UTF-8"))?
                .to_owned();
            let code = [record[0] as char, record[1] as char];
            // Rename/copy records carry the original path as the next record.
            let orig_path = matches!(code[0], 'R' | 'C')
                .then(|| records.next())
                .flatten()
                .map(|orig| {
                    std::str::from_utf8(orig)
                        .map(str::to_owned)
                        .map_err(|_| self.invalid("git status path is not UTF-8"))
                })
                .transpose()?;
            entries.push(StatusEntry {
                code,
                path,
                orig_path,
            });
        }
        Ok(entries)
    }

    /// The most recent commits reachable from HEAD, newest first, in a
    /// fixed bounded window with a fixed field order.
    fn recent_commits(&self, limit: usize) -> BrainResult<Vec<RecentCommit>> {
        let raw = self.run(&[
            "log",
            "-z",
            "-n",
            &limit.to_string(),
            "--format=%H%x01%an%x01%cI%x01%s",
        ])?;
        let mut commits = Vec::new();
        for record in raw.split(|byte| *byte == 0).filter(|r| !r.is_empty()) {
            let fields: Vec<&[u8]> = record.split(|byte| *byte == LOG_FIELD_SEPARATOR).collect();
            if fields.len() != 4 {
                return Err(self.invalid("malformed git log record"));
            }
            let field = |index: usize| {
                std::str::from_utf8(fields[index])
                    .map(str::to_owned)
                    .map_err(|_| self.invalid("git log field is not UTF-8"))
            };
            commits.push(RecentCommit {
                sha: field(0)?,
                author: field(1)?,
                committed_at: field(2)?,
                subject: field(3)?,
            });
        }
        if let Some(sha) = commits.first().map(|commit| commit.sha.clone()) {
            if !is_canonical_oid(&sha) {
                return Err(self.invalid("git log returned a malformed object id"));
            }
        }
        Ok(commits)
    }

    fn invalid(&self, message: &str) -> BrainError {
        BrainError::InvalidRequest(format!(
            "git output from {} is unusable: {message}",
            self.root.display()
        ))
    }

    fn unavailable(&self, detail: impl fmt::Display, source: impl fmt::Display) -> BrainError {
        BrainError::Unavailable {
            component: "git",
            reason: format!("{} at {}: {source}", detail, self.root.display()),
        }
    }
}

/// Runs one isolated Git command, capturing at most
/// [`MAX_GIT_OUTPUT_BYTES`] of stdout: the child's stdout is read through a
/// hard `take` bound and any excess is a typed error, never an unbounded
/// read into memory. Every failure path reaps the child (kill + wait) so a
/// streaming child can never outlive its reader or block the caller.
fn run_capped(
    mut command: Command,
    what: &str,
    root: &Path,
) -> BrainResult<(Vec<u8>, Vec<u8>, std::process::ExitStatus)> {
    let mut child = command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|source| BrainError::Unavailable {
            component: "git",
            reason: format!("could not spawn git {what}: {source}"),
        })?;
    let stdout = child.stdout.take().ok_or_else(|| BrainError::Unavailable {
        component: "git",
        reason: format!("git {what} has no stdout"),
    })?;
    let stderr = child.stderr.take().ok_or_else(|| BrainError::Unavailable {
        component: "git",
        reason: format!("git {what} has no stderr"),
    })?;
    let stderr_reader = std::thread::spawn(move || {
        let mut bytes = Vec::new();
        stderr
            .take(MAX_GIT_OUTPUT_BYTES + 1)
            .read_to_end(&mut bytes)?;
        Ok::<_, std::io::Error>(bytes)
    });

    let mut stdout_bytes = Vec::new();
    if let Err(source) = stdout
        .take(MAX_GIT_OUTPUT_BYTES + 1)
        .read_to_end(&mut stdout_bytes)
    {
        reap(&mut child);
        return Err(BrainError::Unavailable {
            component: "git",
            reason: format!(
                "git {what} stdout read failed at {}: {source}",
                root.display()
            ),
        });
    }
    if stdout_bytes.len() as u64 > MAX_GIT_OUTPUT_BYTES {
        reap(&mut child);
        return Err(BrainError::InvalidRequest(format!(
            "git {what} at {} output exceeded the {MAX_GIT_OUTPUT_BYTES} byte read cap",
            root.display()
        )));
    }
    let stderr_bytes = match stderr_reader.join() {
        Ok(Ok(bytes)) if bytes.len() as u64 <= MAX_GIT_OUTPUT_BYTES => bytes,
        _ => {
            reap(&mut child);
            return Err(BrainError::Unavailable {
                component: "git",
                reason: format!("git {what} stderr read failed or exceeded its byte bound"),
            });
        }
    };
    let status = child.wait().map_err(|source| BrainError::Unavailable {
        component: "git",
        reason: format!(
            "git {what} at {} did not exit cleanly: {source}",
            root.display()
        ),
    })?;
    Ok((stdout_bytes, stderr_bytes, status))
}

/// Best-effort kill + wait for a child on an error path.
fn reap(child: &mut Child) {
    let _ = child.kill();
    let _ = child.wait();
}

/// Repository-local config and child-environment policy that keeps every
/// Git invocation deterministic, hook-free, and side-effect free regardless
/// of the repository's own configuration or the caller's environment.
struct Config;

impl Config {
    /// Wrapper config: no hooks (pointed at an empty path), no fsmonitor
    /// daemon, no external diff (fail closed if anything ever diffs), no
    /// untracked-cache writes.
    const ARGS: [&'static str; 8] = [
        "-c",
        "core.fsmonitor=false",
        "-c",
        "core.hooksPath=/dev/null",
        "-c",
        "diff.external=/bin/false",
        "-c",
        "core.untrackedCache=false",
    ];

    /// Rebuilt child environment after `env_clear`: optional locks off (no
    /// index refresh writes), replace objects off (object bytes are
    /// canonical), system/global config refused, system attributes refused,
    /// and C locale so typed error matching never depends on the host
    /// locale.
    const ISOLATED_ENV: [(&'static str, &'static str); 6] = [
        ("GIT_OPTIONAL_LOCKS", "0"),
        ("GIT_NO_REPLACE_OBJECTS", "1"),
        ("GIT_CONFIG_NOSYSTEM", "1"),
        ("GIT_CONFIG_GLOBAL", "/dev/null"),
        ("GIT_ATTR_NOSYSTEM", "1"),
        ("LC_ALL", "C"),
    ];

    fn args(&self) -> [&'static str; 8] {
        Self::ARGS
    }
}

/// Resolve an absolute path so `env_clear` can use `posix_spawn` instead of
/// forking the daemon and copying its page tables.
fn git_program() -> &'static Path {
    static PROGRAM: std::sync::OnceLock<PathBuf> = std::sync::OnceLock::new();
    PROGRAM.get_or_init(|| {
        std::env::var_os("PATH")
            .iter()
            .flat_map(std::env::split_paths)
            .map(|directory| directory.join("git"))
            .find(|candidate| candidate.is_file())
            .unwrap_or_else(|| PathBuf::from("git"))
    })
}

fn is_canonical_oid(value: &str) -> bool {
    (value.len() == 40 || value.len() == 64)
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn absolute_git_dir(git: &Git) -> BrainResult<PathBuf> {
    let path = git.run_text(&["rev-parse", "--absolute-git-dir"])?;
    Ok(PathBuf::from(path))
}

/// The common dir (`git rev-parse --git-common-dir`) as an absolute path;
/// git may answer with a worktree-relative path.
fn absolute_common_dir(root: &Path, git: &Git) -> BrainResult<PathBuf> {
    let path = git.run_text(&["rev-parse", "--git-common-dir"])?;
    let path = PathBuf::from(path);
    Ok(if path.is_absolute() {
        path
    } else {
        root.join(path)
    })
}

/// Every directory under `base/refs` that holds at least one ref (e.g.
/// `refs/heads`, `refs/heads/feature` for `refs/heads/feature/x`): the set
/// a nonrecursive watcher needs so a commit updating a NESTED branch ref is
/// still seen. Only directories that exist on disk are returned.
fn ref_watch_dirs(base: &Path, git: &Git) -> BrainResult<Vec<PathBuf>> {
    let listing = git.run_text(&["for-each-ref", "--format=%(refname)"])?;
    let mut dirs = Vec::new();
    for reference in listing.lines() {
        let Some(relative) = reference.strip_prefix("refs/") else {
            continue;
        };
        let mut dir = base.join("refs");
        let components: Vec<_> = Path::new(relative).components().collect();
        // Skip the file-name component: only ancestor directories watch.
        for component in &components[..components.len().saturating_sub(1)] {
            dir.push(component);
            if dir.is_dir() {
                dirs.push(dir.clone());
            }
        }
    }
    Ok(dirs)
}

/// Every tracked file of the current HEAD, NUL-separated and validated like
/// the materialization listing.
fn tracked_files(git: &Git) -> BrainResult<Vec<PathBuf>> {
    let listing = git.run(&["ls-tree", "-r", "--name-only", "-z", "HEAD^{tree}"])?;
    listing
        .split(|byte| *byte == 0)
        .filter(|record| !record.is_empty())
        .map(validate_tree_path)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const ATLAS_ID: &str = "state.repos:test";

    /// One throwaway Git repository fixture, isolated from the host's Git
    /// configuration by explicit `-c` commits and tempdir isolation.
    struct TestRepo {
        _dir: tempfile::TempDir,
        root: PathBuf,
    }

    impl TestRepo {
        fn init(name: &str) -> Self {
            let dir = tempfile::TempDir::new().expect("temp dir");
            let root = dir.path().join(name);
            fs::create_dir_all(&root).expect("create repo root");
            git(&root, &["-c", "init.defaultBranch=main", "init"]);
            Self { _dir: dir, root }
        }

        fn write(&self, relative: &str, content: &str) {
            let path = self.root.join(relative);
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent).expect("create fixture directory");
            }
            fs::write(path, content).expect("write fixture file");
        }

        fn commit_all(&self, message: &str) -> String {
            git(&self.root, &["add", "-A"]);
            git(
                &self.root,
                &[
                    "-c",
                    "user.name=Odin Test",
                    "-c",
                    "user.email=odin-test@example.invalid",
                    "-c",
                    "commit.gpgsign=false",
                    "commit",
                    "-m",
                    message,
                ],
            );
            git(&self.root, &["rev-parse", "HEAD"])
        }
    }

    fn git(worktree: &Path, args: &[&str]) -> String {
        let output = Command::new("git")
            .arg("-C")
            .arg(worktree)
            .args(args)
            .output()
            .expect("spawn git");
        assert!(
            output.status.success(),
            "git {args:?} failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8(output.stdout)
            .expect("git output is UTF-8")
            .trim_end()
            .to_owned()
    }

    fn project_id(name: &str) -> ProjectId {
        ProjectId::new(name).expect("valid project id")
    }

    fn source_for(repos: &[(&str, &TestRepo)]) -> ReposSource {
        let projects = repos
            .iter()
            .map(|(project, repo)| (project_id(project), repo.root.clone()))
            .collect();
        ReposSource::new(AtlasId::new(ATLAS_ID).expect("valid atlas id"), projects)
            .expect("valid repos source")
    }

    fn joined_text(items: &[SourceItem]) -> String {
        items.iter().map(|item| item.text.as_str()).collect()
    }

    fn summary_of<'a>(items: &'a [SourceItem], project: &str) -> &'a SourceItem {
        items
            .iter()
            .find(|item| {
                item.project
                    .as_ref()
                    .is_some_and(|owner| owner.as_str() == project)
                    && item.text.contains("head ")
                    && item.text.contains("project ")
            })
            .expect("summary item")
    }

    /// A monorepo-shaped fixture: one committed Rust crate with a stable
    /// symbol, plus an untouched second tracked file.
    fn committed_repo(name: &str) -> TestRepo {
        let repo = TestRepo::init(name);
        repo.write(
            "crates/demo/src/lib.rs",
            "pub fn committed_greeting() -> &'static str {\n    \"committed\"\n}\n",
        );
        repo.write("crates/demo/README.md", "demo crate\n");
        repo.commit_all("fixture crate");
        repo
    }

    #[test]
    fn new_rejects_missing_root() {
        let holder = tempfile::TempDir::new().expect("temp dir");
        let missing = holder.path().join("missing");
        let error = ReposSource::new(
            AtlasId::new(ATLAS_ID).unwrap(),
            BTreeMap::from([(project_id("demo"), missing)]),
        )
        .unwrap_err();
        assert!(matches!(
            error,
            BrainError::NotFound {
                kind: "declared project root",
                ..
            }
        ));
    }

    #[test]
    fn new_rejects_non_repository_root() {
        let dir = tempfile::TempDir::new().unwrap();
        let error = ReposSource::new(
            AtlasId::new(ATLAS_ID).unwrap(),
            BTreeMap::from([(project_id("demo"), dir.path().to_path_buf())]),
        )
        .unwrap_err();
        assert!(matches!(&error, BrainError::InvalidRequest(message)
            if message.contains("not inside a Git worktree")));
    }

    #[test]
    fn new_rejects_non_root_subdirectory() {
        let repo = committed_repo("subdir");
        let error = ReposSource::new(
            AtlasId::new(ATLAS_ID).unwrap(),
            BTreeMap::from([(project_id("demo"), repo.root.join("crates"))]),
        )
        .unwrap_err();
        assert!(matches!(&error, BrainError::InvalidRequest(message)
            if message.contains("is not a Git worktree root")));
    }

    #[test]
    fn new_rejects_unborn_head() {
        let repo = TestRepo::init("unborn");
        let error = ReposSource::new(
            AtlasId::new(ATLAS_ID).unwrap(),
            BTreeMap::from([(project_id("demo"), repo.root.clone())]),
        )
        .unwrap_err();
        assert!(matches!(&error, BrainError::InvalidRequest(_)));
    }

    /// Spawning a bare `git` under a rebuilt PATH forces std's fork
    /// fallback (the whole daemon's page tables per call); an absolute
    /// program keeps `posix_spawn`.
    #[test]
    fn git_runs_from_an_absolute_path() {
        let repo = committed_repo("spawn");
        let command = Git::at(&repo.root).command(&["rev-parse", "HEAD"]);
        assert!(
            Path::new(command.get_program()).is_absolute(),
            "{:?}",
            command.get_program()
        );
    }

    /// A root without a resolvable HEAD (a clone in progress, an emptied
    /// repository) is refused alone; the readable roots still form the
    /// source, where `new` refuses the whole source.
    #[test]
    fn an_unreadable_root_drops_out_instead_of_failing_the_source() {
        let good = TestRepo::init("good");
        good.write("README.md", "good\n");
        good.commit_all("start");
        let cloning = TestRepo::init("cloning");
        let projects = BTreeMap::from([
            (ProjectId::new("good").unwrap(), good.root.clone()),
            (ProjectId::new("cloning").unwrap(), cloning.root.clone()),
        ]);
        let atlas = AtlasId::new(ATLAS_ID).unwrap();
        assert!(ReposSource::new(atlas.clone(), projects.clone()).is_err());
        let (source, refused) = ReposSource::new_available(atlas, projects);
        assert_eq!(source.projects().len(), 1);
        assert_eq!(refused.len(), 1);
        assert_eq!(refused[0].0.as_str(), "cloning");
        source.pin().expect("the readable project pins");
    }

    #[test]
    fn empty_declared_set_is_a_valid_no_root_source() {
        let source = ReposSource::new(AtlasId::new(ATLAS_ID).unwrap(), BTreeMap::new())
            .expect("a declared source may have no rooted projects");
        assert!(source.projects().is_empty());
        assert!(source.watch_paths().expect("no watch paths").is_empty());
        let (head, items) = source.pin().expect("pin empty source");
        assert!(items.is_empty());
        let (again, items_again) = source.pin().expect("pin empty source again");
        assert_eq!(head, again);
        assert!(items_again.is_empty());
    }

    #[test]
    fn foreign_roots_are_not_read() {
        let declared = committed_repo("declared");
        let foreign = TestRepo::init("foreign");
        foreign.write("src/foreign_only.rs", "pub fn foreign_only_symbol() {}\n");
        foreign.commit_all("FOREIGN_COMMIT_SUBJECT");

        let source = source_for(&[("declared", &declared)]);
        assert!(!source.projects().contains_key(&project_id("foreign")));
        let (_, items) = source.pin().expect("pin declared project");
        let text = joined_text(&items);
        assert!(text.contains("committed_greeting"));
        assert!(!text.contains("FOREIGN_COMMIT_SUBJECT"));
        assert!(!text.contains("foreign_only_symbol"));
        assert!(!text.contains("foreign_only.rs"));
    }

    #[test]
    fn a_commit_leaves_untouched_ast_text_unchanged() {
        let repo = committed_repo("stable");
        let source = source_for(&[("stable", &repo)]);
        let ast_texts = |items: &[SourceItem]| -> Vec<String> {
            items
                .iter()
                .filter(|item| item.text.starts_with("crates/demo/src/lib.rs"))
                .map(|item| item.text.clone())
                .collect()
        };
        let (before_head, before) = source.pin().expect("pin before");
        repo.write("crates/demo/README.md", "demo crate, revised\n");
        repo.commit_all("revise readme");
        let (after_head, after) = source.pin().expect("pin after");
        assert_ne!(before_head, after_head);
        assert!(!ast_texts(&before).is_empty());
        assert_eq!(ast_texts(&before), ast_texts(&after));
    }

    #[test]
    fn dirty_worktree_projects_committed_ast_only() {
        let repo = committed_repo("dirty");
        // Tracked dirty edit plus a second tracked dirty file; both remain
        // uncommitted.
        repo.write(
            "crates/demo/src/lib.rs",
            "pub fn committed_greeting() -> &'static str {\n    \"committed\"\n}\n\n\
             pub fn dirty_only_symbol() {}\n",
        );
        repo.write("crates/demo/README.md", "dirty readme\n");

        let source = source_for(&[("demo", &repo)]);
        let (_, items) = source.pin().expect("pin dirty repo");
        assert!(items.iter().all(|item| item.trust == TrustClass::Observed));
        assert!(items
            .iter()
            .all(|item| item.project == Some(project_id("demo"))));

        let text = joined_text(&items);
        assert!(text.contains("committed_greeting"));
        // The dirty symbol exists ONLY in the worktree: it must never be
        // projected as committed AST.
        assert!(!text.contains("dirty_only_symbol"));

        let expected_head = git(&repo.root, &["rev-parse", "HEAD"]);
        let summary = summary_of(&items, "demo");
        assert!(summary.text.contains(&format!("head {expected_head}")));
        // Tracked dirty observations are reported honestly...
        assert!(summary.text.contains("2 total"));
        assert!(summary.text.contains("M crates/demo/src/lib.rs"));
        assert!(summary.text.contains("M crates/demo/README.md"));
        // ...while untracked files are explicitly excluded, not implied.
        assert!(summary.text.contains("untracked files are excluded"));
    }

    #[test]
    fn untracked_open_work_never_enters_the_projection() {
        let repo = committed_repo("untracked");
        repo.write(
            "crates/demo/src/untracked_notes.rs",
            "pub fn untracked_only() {}\n",
        );

        let source = source_for(&[("demo", &repo)]);
        let (_, items) = source.pin().expect("pin with untracked file");
        let text = joined_text(&items);
        assert!(!text.contains("untracked_only"));
        assert!(!text.contains("untracked_notes.rs"));
        assert!(text.contains("working tree tracked changes: clean"));
    }

    #[test]
    fn same_head_tracked_change_moves_revision() {
        let repo = committed_repo("samehead");
        let source = source_for(&[("demo", &repo)]);
        let (first_head, first_items) = source.pin().expect("first pin");

        // Dirty a tracked file WITHOUT moving HEAD.
        repo.write("crates/demo/README.md", "dirtied after first pin\n");
        let (second_head, second_items) = source.pin().expect("second pin");

        let first_summary = summary_of(&first_items, "demo");
        let second_summary = summary_of(&second_items, "demo");
        let first_sha = first_summary
            .text
            .lines()
            .find_map(|line| line.strip_prefix("head "))
            .expect("first head line")
            .to_owned();
        let second_sha = second_summary
            .text
            .lines()
            .find_map(|line| line.strip_prefix("head "))
            .expect("second head line")
            .to_owned();
        assert_eq!(first_sha, second_sha, "HEAD never moved");
        assert_ne!(
            first_head, second_head,
            "same-head dirty change must move the revision"
        );
        // The old generation can never be served as the new head.
        assert!(first_items
            .iter()
            .all(|item| item.source_revision != second_head));
    }

    #[test]
    fn branch_move_at_same_sha_moves_revision() {
        let repo = committed_repo("branchmove");
        let source = source_for(&[("demo", &repo)]);
        let (main_head, main_items) = source.pin().expect("pin on main");
        let main_summary = summary_of(&main_items, "demo");
        assert!(main_summary.text.contains("branch main\n"));

        git(&repo.root, &["checkout", "-b", "topic"]);
        let (topic_head, topic_items) = source.pin().expect("pin on topic");
        assert_ne!(
            main_head, topic_head,
            "branch move at the same SHA moves the revision"
        );
        let topic_summary = summary_of(&topic_items, "demo");
        assert!(topic_summary.text.contains("branch topic\n"));
    }

    #[test]
    fn detached_head_is_stated_honestly() {
        let repo = committed_repo("detached");
        git(&repo.root, &["checkout", "--detach"]);
        let source = source_for(&[("demo", &repo)]);
        let (_, items) = source.pin().expect("pin detached");
        let summary = summary_of(&items, "demo");
        assert!(summary.text.contains("detached HEAD"));
        assert!(!summary.text.contains("branch main"));
    }

    #[test]
    fn head_move_moves_revision_and_sha() {
        let repo = committed_repo("headmove");
        let source = source_for(&[("demo", &repo)]);
        let (before_head, before_items) = source.pin().expect("pin before commit");
        let before_summary = summary_of(&before_items, "demo");

        repo.write("crates/demo/README.md", "new work\n");
        let commit = repo.commit_all("advance head");

        let (after_head, after_items) = source.pin().expect("pin after commit");
        assert_ne!(before_head, after_head);
        let after_summary = summary_of(&after_items, "demo");
        assert!(after_summary.text.contains(&format!("head {commit}")));
        assert!(!before_summary.text.contains(&format!("head {commit}")));
    }

    #[test]
    fn committed_atlas_memo_is_keyed_by_commit() {
        let repo = committed_repo("memo");
        let source = source_for(&[("demo", &repo)]);
        let (_, first) = source.pin().expect("first pin");
        let (_, memoized) = source.pin().expect("memoized pin at the same commit");
        assert_eq!(
            first, memoized,
            "a memo hit serves the identical projection"
        );

        repo.write(
            "crates/demo/src/lib.rs",
            "pub fn committed_greeting() -> &'static str {\n    \"committed\"\n}\n\n\
             pub fn memo_invalidated_symbol() {}\n",
        );
        let commit = repo.commit_all("add a symbol");
        let (_, after) = source.pin().expect("pin after commit");
        assert!(
            after
                .iter()
                .any(|item| item.text.contains("memo_invalidated_symbol")),
            "a new commit re-projects its committed tree; the memo never serves an older commit"
        );
        let memo = source.committed_atlas.lock().expect("memo");
        assert_eq!(memo.get(&project_id("demo")).expect("entry").commit, commit);
    }

    #[test]
    fn unchanged_pins_are_deterministic() {
        let repo = committed_repo("deterministic");
        let source = source_for(&[("demo", &repo)]);
        let (first_head, first_items) = source.pin().expect("first pin");
        let (second_head, second_items) = source.pin().expect("second pin");
        assert_eq!(first_head, second_head);
        assert_eq!(first_items, second_items);
    }

    #[test]
    fn restrict_projects_filters_declared_roots() {
        let alpha = committed_repo("alpha");
        alpha.write("crates/alpha/src/lib.rs", "pub fn alpha_only() {}\n");
        alpha.commit_all("alpha work");
        let beta = committed_repo("beta");
        beta.write("crates/beta/src/lib.rs", "pub fn beta_only() {}\n");
        beta.commit_all("beta work");

        let source = source_for(&[("alpha", &alpha), ("beta", &beta)]);
        let mut restricted = BTreeSet::new();
        restricted.insert(project_id("beta"));
        let restricted = source.restrict_projects(&restricted);

        assert_eq!(restricted.projects().len(), 1);
        assert!(restricted.projects().contains_key(&project_id("beta")));
        let (_, items) = restricted.pin().expect("pin restricted source");
        assert!(!items.is_empty());
        assert!(items
            .iter()
            .all(|item| item.project == Some(project_id("beta"))));
        let text = joined_text(&items);
        assert!(text.contains("beta_only"));
        assert!(!text.contains("alpha_only"));
    }

    /// A repository's non-Atlas content never enters the snapshot, so a
    /// large data or document tree cannot exceed the bound.
    #[test]
    fn only_atlas_inputs_are_materialized() {
        let repo = committed_repo("data-heavy");
        repo.write("data/big.bin", &"x".repeat(4_096));
        repo.write("paper.md", "notes\n");
        repo.commit_all("data next to the code");
        let git = Git::at(&repo.root);
        let commit = git.resolve_head().expect("resolve head");
        let (snapshot, _, _) = materialize_committed_tree(
            &repo.root,
            &git,
            &commit,
            SnapshotBounds {
                max_files: 2,
                max_bytes: 1_024,
            },
        )
        .expect("the data tree is not materialized");
        assert!(snapshot.path().join("crates/demo/src/lib.rs").is_file());
        assert!(!snapshot.path().join("data/big.bin").exists());
        assert!(!snapshot.path().join("paper.md").exists());
    }

    #[test]
    fn snapshot_bounds_fail_closed() {
        let repo = committed_repo("bounds");
        let git = Git::at(&repo.root);
        let commit = git.resolve_head().expect("resolve head");

        let error = materialize_committed_tree(
            &repo.root,
            &git,
            &commit,
            SnapshotBounds {
                max_files: 1,
                max_bytes: MAX_SNAPSHOT_BYTES,
            },
        )
        .unwrap_err();
        assert!(matches!(&error, BrainError::InvalidRequest(_)));

        let error = materialize_committed_tree(
            &repo.root,
            &git,
            &commit,
            SnapshotBounds {
                max_files: MAX_FILES_PER_SNAPSHOT,
                max_bytes: 1,
            },
        )
        .unwrap_err();
        assert!(matches!(&error, BrainError::InvalidRequest(_)));
    }

    #[test]
    fn watch_paths_cover_git_and_tracked_dirs_only() {
        let repo = committed_repo("watch");
        repo.write(".gitignore", "target/\n");
        repo.commit_all("ignore target");
        // Ignored output churn and untracked scratch files exist on disk but
        // are not tracked, so they must not enter the watch set.
        repo.write("target/build-artifact.bin", "junk\n");
        repo.write("scratch/untracked.txt", "junk\n");

        let source = source_for(&[("demo", &repo)]);
        let paths = source.watch_paths().expect("watch paths");
        let root = repo.root.clone();
        for expected in [
            root.clone(),
            root.join(".git"),
            root.join(".git/refs"),
            root.join(".git/refs/heads"),
            root.join("crates"),
            root.join("crates/demo"),
            root.join("crates/demo/src"),
        ] {
            assert!(
                paths.iter().any(|path| path == &expected),
                "watch paths missing {}: {paths:?}",
                expected.display()
            );
        }
        for excluded in [root.join("target"), root.join("scratch")] {
            assert!(
                !paths.iter().any(|path| path == &excluded),
                "watch paths must not include {}: {paths:?}",
                excluded.display()
            );
        }
    }

    #[test]
    fn watch_paths_bound_overflow_fails_closed() {
        let repo = committed_repo("watchbound");
        let source = source_for(&[("demo", &repo)]);
        let error = source.watch_set(2).unwrap_err();
        assert!(matches!(&error, BrainError::InvalidRequest(message)
            if message.contains("watch path bound exceeded")));
    }
}
