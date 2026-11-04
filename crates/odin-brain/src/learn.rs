//! The learning loop's state. Entries are the vault's memory pages (one page
//! per entry, served by the core and recalled by brain_search); every change
//! is one commit in the brain repo — its `.git` versions the vault's `memory/`
//! tree — so each edit carries its provenance and undoing one publishes only
//! that page's inverse.

use std::fmt;
use std::io::Read as _;
use std::os::unix::fs::MetadataExt as _;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;

use odin_confined_fs::{validate_relative_path, ConfinedError, GeneratedCapability};

use crate::config::MEMORY_NAMESPACE_PREFIX;

use serde::Deserialize;

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum EntryKind {
    Prompt,
    #[default]
    Memory,
    Skill,
    Subagent,
}

impl EntryKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Prompt => "prompt",
            Self::Memory => "memory",
            Self::Skill => "skill",
            Self::Subagent => "subagent",
        }
    }

    fn parse(name: &str) -> Option<Self> {
        match name {
            "prompt" => Some(Self::Prompt),
            "memory" => Some(Self::Memory),
            "skill" => Some(Self::Skill),
            "subagent" => Some(Self::Subagent),
            _ => None,
        }
    }

    /// The largest body one entry of this kind may hold.
    const fn max_bytes(self) -> usize {
        match self {
            Self::Skill | Self::Subagent => 4_000,
            Self::Prompt | Self::Memory => 600,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum EditAction {
    Add,
    Update,
    Retire,
    /// Undo the entry's last change.
    Revert,
}

/// Where an edit lands: the owner's profile, the seat's memory, or the session's project.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum EditScope {
    Owner,
    Seat,
    Project,
}

/// One edit a review proposes.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Edit {
    pub action: EditAction,
    #[serde(default)]
    pub kind: EntryKind,
    pub scope: EditScope,
    /// The page id of the entry an update or retire targets.
    #[serde(default)]
    pub id: Option<String>,
    #[serde(default)]
    pub title: String,
    #[serde(default)]
    pub content: String,
    pub evidence: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Entry {
    pub namespace: String,
    pub id: String,
    pub kind: EntryKind,
    pub title: Option<String>,
    pub body: String,
}

/// The memory namespaces one session's edits resolve to.
/// `writable` is the directory names this seat may change.
#[derive(Clone, Debug)]
pub struct Namespaces {
    pub colin: Option<String>,
    pub seat: String,
    pub project: Option<String>,
    /// Directory names this seat may change.
    pub writable: Vec<String>,
}

impl Namespaces {
    fn resolve(&self, scope: EditScope) -> Option<&str> {
        match scope {
            EditScope::Owner => self.colin.as_deref(),
            EditScope::Seat => Some(&self.seat),
            EditScope::Project => self.project.as_deref(),
        }
    }

    /// Whether this seat may change `namespace` (a directory name).
    pub fn grants(&self, namespace: &str) -> bool {
        self.writable.iter().any(|granted| granted == namespace)
    }

    pub fn writable(&self) -> impl Iterator<Item = &str> {
        self.writable.iter().map(String::as_str)
    }
}

/// Who learned what from where; carried in every commit message.
#[derive(Clone, Debug)]
pub struct Provenance {
    pub seat: String,
    pub session: String,
    pub trigger: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Learned {
    pub action: EditAction,
    pub kind: EntryKind,
    pub page: String,
    pub commit: String,
}

#[derive(Debug, thiserror::Error)]
pub enum LearnError {
    #[error("brain-state git {command} failed: {detail}")]
    Git { command: String, detail: String },
    #[error("brain-state io at {path}: {source}")]
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("brain repo not found: no git repository at {0}")]
    NoRepo(PathBuf),
    #[error("edit refused: {0}")]
    Refused(String),
}

pub type LearnResult<T> = Result<T, LearnError>;

/// Learned memory inside the brain repo: `work_tree` is the vault's memory
/// directory, `repo_root` the brain repo that versions it. Git runs from the
/// memory directory, so page names are relative to it and every commit is
/// limited to the pages it names.
#[derive(Clone, Debug)]
pub struct BrainState {
    work_tree: PathBuf,
    repo_root: PathBuf,
    git_dir: PathBuf,
    files: Arc<GeneratedCapability>,
}

/// The most edits one review may apply.
pub const MAX_EDITS: usize = 3;

/// The commit subject of owner edits synced apart from the loop.
const SYNC_SUBJECT: &str = "brain: sync vault edits";

/// The author of every loop commit; any other author is the owner's snapshot
/// (`brain-commit`), which counts as an owner sync.
const AUTHOR: &str = "odin-brain";

impl BrainState {
    /// Opens the memory directory of the brain repo at `repo_root`. The repo
    /// must already exist; `brain-commit` is its only pusher.
    pub fn open(work_tree: impl Into<PathBuf>, repo_root: impl Into<PathBuf>) -> LearnResult<Self> {
        let work_tree = work_tree.into();
        let repo_root = repo_root.into();
        let git_dir = repo_root.join(".git");
        if !git_dir.join("HEAD").exists() {
            return Err(LearnError::NoRepo(repo_root));
        }
        std::fs::create_dir_all(&work_tree).map_err(|source| LearnError::Io {
            path: work_tree.clone(),
            source,
        })?;
        Ok(Self {
            files: Arc::new(GeneratedCapability::seal(&work_tree).map_err(confined)?),
            work_tree,
            repo_root,
            git_dir,
        })
    }

    pub fn work_tree(&self) -> &Path {
        &self.work_tree
    }

    /// The entries of one namespace, sorted by id.
    pub fn entries(&self, namespace: &str) -> LearnResult<Vec<Entry>> {
        validate_relative_path(Path::new(namespace)).map_err(confined)?;
        self.files
            .verify_declared_root(&self.work_tree)
            .map_err(confined)?;
        let directory = self.work_tree.join(namespace);
        let io = |source| LearnError::Io {
            path: directory.clone(),
            source,
        };
        // Only a namespace that does not exist is empty; an unreadable or
        // unenumerable one is a failure, never an empty memory.
        let listing = match std::fs::read_dir(&directory) {
            Ok(listing) => listing,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(error) => return Err(io(error)),
        };
        let mut entries = Vec::new();
        for item in listing {
            let path = item.map_err(io)?.path();
            if path.extension().and_then(|extension| extension.to_str()) != Some("md") {
                continue;
            }
            let Some(id) = path.file_stem().and_then(|stem| stem.to_str()) else {
                continue;
            };
            let Some(text) = self.read_page(&format!("{namespace}/{id}.md"))? else {
                continue;
            };
            let (kind, title, body) = parse_page(&text);
            entries.push(Entry {
                namespace: namespace.to_owned(),
                id: id.to_owned(),
                kind,
                title,
                body,
            });
        }
        entries.sort_by(|left, right| left.id.cmp(&right.id));
        Ok(entries)
    }

    /// Validates and applies `edits` in order, one commit each. A refused
    /// edit is skipped and reported; nothing else is touched. A failure
    /// after earlier edits landed is reported beside them, so every commit
    /// reaches the caller's journal.
    pub fn apply(
        &self,
        namespaces: &Namespaces,
        edits: &[Edit],
        provenance: &Provenance,
    ) -> LearnResult<(Vec<Learned>, Vec<String>)> {
        let mut learned = Vec::new();
        let mut refused = Vec::new();
        for edit in edits.iter().take(MAX_EDITS) {
            match self.apply_one(namespaces, edit, provenance) {
                Ok(Some(applied)) => learned.push(applied),
                Ok(None) => {}
                Err(LearnError::Refused(reason)) => refused.push(reason),
                Err(error) if !learned.is_empty() => {
                    refused.push(error.to_string());
                    break;
                }
                Err(error) => return Err(error),
            }
        }
        if edits.len() > MAX_EDITS {
            refused.push(format!(
                "{} edits past the {MAX_EDITS}-edit bound",
                edits.len() - MAX_EDITS
            ));
        }
        Ok((learned, refused))
    }

    fn apply_one(
        &self,
        namespaces: &Namespaces,
        edit: &Edit,
        provenance: &Provenance,
    ) -> LearnResult<Option<Learned>> {
        let namespace = namespaces.resolve(edit.scope).ok_or_else(|| {
            LearnError::Refused(format!("this session serves no {:?} memory", edit.scope))
        })?;
        if !namespaces.grants(namespace) {
            return Err(LearnError::Refused(format!(
                "seat {} may not change namespace {}",
                provenance.seat,
                namespace_id(namespace)
            )));
        }
        validate_relative_path(Path::new(namespace)).map_err(confined)?;
        if edit.action != EditAction::Add {
            let id = edit.id.as_deref().unwrap_or_default();
            validate_relative_path(Path::new(id)).map_err(confined)?;
            if id.contains('/') {
                return Err(LearnError::Refused("entry id must be one leaf".to_owned()));
            }
        }
        if edit.evidence.trim().is_empty() {
            return Err(LearnError::Refused("an edit needs its evidence".to_owned()));
        }
        let existing = self.entries(namespace)?;
        let mut action = edit.action;
        let target = match edit.action {
            EditAction::Add => {
                validate_content(edit)?;
                let normalized = normalize(&edit.content);
                if existing
                    .iter()
                    .any(|entry| normalize(&entry.body) == normalized)
                {
                    return Ok(None);
                }
                // Remembering a fact under a title that has a page updates
                // that page when this seat wrote it last: the newer
                // statement replaces the older one. A page another seat or
                // the owner wrote is never overwritten; this seat's statement
                // gets its own page beside it.
                let mut id = format!("{}-{}", edit.kind.as_str(), slug(&edit.title));
                if existing.iter().any(|entry| entry.id == id)
                    && !self.learned_by(&format!("{namespace}/{id}.md"), &provenance.seat)?
                {
                    id = format!("{id}-{}", slug(&provenance.seat));
                }
                if existing.iter().any(|entry| entry.id == id) {
                    if !self.learned_by(&format!("{namespace}/{id}.md"), &provenance.seat)? {
                        return Err(LearnError::Refused(format!(
                            "{namespace}/{id} was last written by someone else; update it by id \
                             only if it is yours"
                        )));
                    }
                    action = EditAction::Update;
                }
                id
            }
            EditAction::Revert => {
                let id = edit.id.clone().unwrap_or_default();
                if !existing.iter().any(|entry| entry.id == id) {
                    return Err(LearnError::Refused(format!(
                        "no entry {namespace}/{id} to Revert"
                    )));
                }
                let page = format!("{namespace}/{id}.md");
                let commit = self
                    .revert_last(&page, &edit.evidence)?
                    .ok_or_else(|| LearnError::Refused(format!("{page} has no history")))?;
                return Ok(Some(Learned {
                    action: edit.action,
                    kind: edit.kind,
                    page,
                    commit,
                }));
            }
            EditAction::Update | EditAction::Retire => {
                let id = edit.id.clone().unwrap_or_default();
                if !existing.iter().any(|entry| entry.id == id) {
                    return Err(LearnError::Refused(format!(
                        "no entry {namespace}/{id} to {:?}",
                        edit.action
                    )));
                }
                if edit.action == EditAction::Update {
                    validate_content(edit)?;
                }
                id
            }
        };
        let page = format!("{namespace}/{target}.md");
        let current = self.read_page(&page)?;
        let next = (edit.action != EditAction::Retire).then(|| render_page(edit));
        if current == next {
            return Ok(None);
        }
        let message = format!(
            "brain: {} {} {page}\n\nEvidence: {}\nSeat: {}\nSession: {}\nTrigger: {}",
            action_name(action),
            edit.kind.as_str(),
            one_line(&edit.evidence),
            provenance.seat,
            provenance.session,
            provenance.trigger,
        );
        let commit = self
            .write_commit(&page, current.as_deref(), next.as_deref(), &message)?
            .ok_or_else(|| LearnError::Refused(format!("{page} did not change")))?;
        Ok(Some(Learned {
            action,
            kind: edit.kind,
            page,
            commit,
        }))
    }

    /// Commits the current state of `pages` (relative to the work tree) and
    /// nothing else, whatever else is staged in the brain repo; `None` when
    /// nothing changed. The caller holds the repo lock.
    fn commit(&self, pages: &[&str], message: &str) -> LearnResult<Option<String>> {
        let mut add = vec!["add", "--all", "--"];
        add.extend_from_slice(pages);
        self.git(&add)?;
        let mut unchanged = vec!["diff", "--cached", "--quiet", "--"];
        unchanged.extend_from_slice(pages);
        if self.git(&unchanged).is_ok() {
            return Ok(None);
        }
        let mut commit = vec!["commit", "--quiet", "-m", message, "--"];
        commit.extend_from_slice(pages);
        self.git(&commit)?;
        self.git(&["rev-parse", "HEAD"]).map(Some)
    }

    /// Holds the brain repo's write lock, the one `brain-commit` takes, so
    /// the two never interleave; released when the guard drops.
    fn lock(&self) -> LearnResult<std::fs::File> {
        let path = self.git_dir.join("brain-commit.lock");
        let io = |source| LearnError::Io {
            path: path.clone(),
            source,
        };
        let file = std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(&path)
            .map_err(io)?;
        file.lock().map_err(io)?;
        Ok(file)
    }

    /// Publishes `text` for `page` (see [`Self::publish_page`]) and commits
    /// it, under the repo lock.
    fn write_commit(
        &self,
        page: &str,
        expected: Option<&str>,
        text: Option<&str>,
        message: &str,
    ) -> LearnResult<Option<String>> {
        let _lock = self.lock()?;
        self.publish_page(page, expected, text)?;
        self.commit(&[page], message)
    }

    /// Commits whatever changed outside the loop (the owner's own edits in
    /// SilverBullet, pages synced from another host) so each loop commit
    /// carries only its own edit.
    pub fn commit_pending(&self) -> LearnResult<Option<String>> {
        let _lock = self.lock()?;
        self.sync_pending()
    }

    fn sync_pending(&self) -> LearnResult<Option<String>> {
        self.commit(&["."], SYNC_SUBJECT)
    }

    /// Whether the newest change to `page` was the loop's add or update on
    /// behalf of `seat`.
    fn learned_by(&self, page: &str, seat: &str) -> LearnResult<bool> {
        if self.git(&["diff", "--quiet", "HEAD", "--", page]).is_err() {
            return Ok(false);
        }
        let message = self.git(&["log", "-1", "--format=%B", "--", page])?;
        Ok(
            learning_kind(message.lines().next().unwrap_or_default(), page).is_some()
                && message
                    .lines()
                    .any(|line| line.strip_prefix("Seat: ") == Some(seat)),
        )
    }

    /// The newest learned add or update through intervening owner syncs.
    /// Owner-only history or a later loop revert or retire ends the search.
    fn learned_target(&self, page: &str) -> LearnResult<Option<String>> {
        let history = self.git(&["log", "--format=%H %an %s", "--", page])?;
        for line in history.lines() {
            let mut parts = line.splitn(3, ' ');
            let (commit, author, subject) = (
                parts.next().unwrap_or_default(),
                parts.next().unwrap_or_default(),
                parts.next().unwrap_or_default(),
            );
            if learning_kind(subject, page).is_some() {
                return Ok(Some(commit.to_owned()));
            }
            if author == AUTHOR && subject != SYNC_SUBJECT {
                break;
            }
        }
        Ok(None)
    }

    /// Whether forgetting the lowercase `phrase` must invert a learned edit
    /// instead of retiring the page. That edit must introduce the phrase in
    /// the page's visible title and body: absent before it, present after.
    /// Otherwise forgetting is refused, never a retirement. A conflicting
    /// inverse remains a refusal, never permission to discard the owner's
    /// replacement.
    pub fn learned_entry(&self, page: &str, phrase: &str) -> LearnResult<bool> {
        let Some(target) = self.learned_target(page)? else {
            return Ok(false);
        };
        let shows = |revision: &str| -> LearnResult<bool> {
            Ok(self
                .page_at(revision, page)?
                .is_some_and(|text| visible_contains(&text, phrase)))
        };
        if shows(&target)? && !shows(&format!("{target}^"))? {
            return Ok(true);
        }
        Err(LearnError::Refused(format!(
            "{page}: its newest learned edit did not introduce the phrase"
        )))
    }

    /// Reverts the page's newest learned add or update, through later owner
    /// syncs whose edits the inverse keeps. Owner-only changes and a later
    /// loop revert or retire are refused; `None` means the page has no history.
    pub fn revert_last(&self, page: &str, reason: &str) -> LearnResult<Option<String>> {
        self.read_page(page)?;
        let Some(last) = self.learned_target(page)? else {
            if self
                .git(&["log", "-1", "--format=%H", "--", page])?
                .is_empty()
            {
                return Ok(None);
            }
            return Err(LearnError::Refused(
                "no learning edit of this page precedes only owner syncs".to_owned(),
            ));
        };
        let patch = self.learned_patch(page, &last)?;
        let (expected, next) = self.prepare_inverse(page, &patch)?;
        self.write_commit(
            page,
            expected.as_deref(),
            next.as_deref(),
            &format!(
                "brain: revert {page}\n\nReverts: {last}\nReason: {}",
                one_line(reason)
            ),
        )
    }

    /// Undo exactly one labelled learning commit, never the latest page
    /// change. Callers serialize this with learning. A conflicting inverse
    /// is refused before any page or index mutation; unrelated later edits
    /// are retained. Retrying a committed inverse, exact or natural, returns
    /// its receipt with the reverted commit's kind.
    pub fn revert_exact(
        &self,
        page: &str,
        commit: &str,
        label: &str,
        seat: &str,
    ) -> LearnResult<Learned> {
        let refused = |reason: &str| LearnError::Refused(reason.to_owned());
        if commit.len() != 40 || !commit.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(refused("commit must be a full 40-character object id"));
        }
        if label.len() < 6 || label.len() > 500 || label.trim() != label {
            return Err(refused(
                "label must contain 6..=500 bytes of exact fixture text",
            ));
        }
        let current = self.read_page(page)?;
        let commit = self.git(&["rev-parse", "--verify", &format!("{commit}^{{commit}}")])?;
        self.git(&["merge-base", "--is-ancestor", &commit, "HEAD"])?;
        let message = self.git(&["show", "--no-patch", "--format=%B", &commit])?;
        let subject = message.lines().next().unwrap_or_default();
        let kind = learning_kind(subject, page)
            .filter(|_| {
                message
                    .lines()
                    .any(|line| line.strip_prefix("Seat: ") == Some(seat))
            })
            .ok_or_else(|| refused("commit is not a learning edit owned by the calling seat"))?;
        let patch = self.learned_patch(page, &commit)?;
        if !patch.lines().any(|line| {
            line.starts_with('+')
                && !line.starts_with("+++")
                && contains_exact_label(&line[1..], label)
        }) {
            return Err(refused("label is not in the commit's added text"));
        }
        let receipt = |inverse: String| Learned {
            action: EditAction::Revert,
            kind,
            page: page.to_owned(),
            commit: inverse,
        };
        let marker = format!("Reverts-Exact: {commit}");
        let natural_marker = format!("Reverts: {commit}");
        let history = self.git(&[
            "log",
            "--format=%H",
            "--fixed-strings",
            "--grep",
            &marker,
            "--grep",
            &natural_marker,
        ])?;
        for candidate in history.lines() {
            let message = self.git(&["show", "--no-patch", "--format=%B", candidate])?;
            let exact = message.lines().any(|line| line == marker);
            let natural = !exact
                && message.lines().any(|line| line == natural_marker)
                && self.reverses(page, candidate, &patch)?;
            if exact || natural {
                if !contains_exact_label(current.as_deref().unwrap_or_default(), label) {
                    return Ok(receipt(candidate.to_owned()));
                }
                return Err(refused(
                    "label remains after the recorded inverse; inspect later edits",
                ));
            }
        }
        let (expected, next) = self.prepare_inverse(page, &patch)?;
        self.write_commit(
            page,
            expected.as_deref(),
            next.as_deref(),
            &format!(
                "brain: revert exact {page}\n\n{marker}\nSeat: {seat}\nLabel: {}",
                one_line(label)
            ),
        )?
        .map(receipt)
        .ok_or_else(|| refused("exact inverse made no change"))
    }

    /// Whether `candidate` changed `page` exactly by reversing `patch`,
    /// whatever owner edits its parent already held.
    fn reverses(&self, page: &str, candidate: &str, patch: &str) -> LearnResult<bool> {
        let before = self.page_at(&format!("{candidate}^"), page)?;
        match self.inverse_of(page, before.as_deref(), patch) {
            Ok(next) => Ok(next == self.page_at(candidate, page)?),
            Err(LearnError::Refused(_)) => Ok(false),
            Err(error) => Err(error),
        }
    }

    /// `page` as committed at `revision`; `None` when it did not exist.
    fn page_at(&self, revision: &str, page: &str) -> LearnResult<Option<String>> {
        let listed = self.git_raw(&["ls-tree", "--name-only", "-z", revision, page])?;
        if listed.strip_suffix('\0') != Some(page) {
            return Ok(None);
        }
        self.git_raw(&["cat-file", "blob", &format!("{revision}:./{page}")])
            .map(Some)
    }

    fn read_page(&self, page: &str) -> LearnResult<Option<String>> {
        self.files
            .verify_declared_root(&self.work_tree)
            .map_err(confined)?;
        read_page(&self.files, page)
    }

    /// Publishes `text` only while the page still holds the `expected` bytes
    /// the edit was prepared from; a page changed since is refused before
    /// any sync. Once owner edits are synced, every failure is a hard error,
    /// never a refusal: the page or Git may already have changed.
    fn publish_page(
        &self,
        page: &str,
        expected: Option<&str>,
        text: Option<&str>,
    ) -> LearnResult<()> {
        if self.read_page(page)?.as_deref() != expected {
            return Err(LearnError::Refused(format!(
                "{page} changed since it was prepared"
            )));
        }
        self.sync_pending()?;
        let hard = |error: ConfinedError| LearnError::Io {
            path: self.work_tree.join(page),
            source: std::io::Error::other(error),
        };
        self.files
            .verify_declared_root(&self.work_tree)
            .map_err(hard)?;
        let path = Path::new(page);
        if let Some(text) = text {
            if let Some(parent) = path.parent() {
                self.files.create_dirs(parent, 0o755).map_err(hard)?;
            }
            self.files
                .write_atomic(path, text.as_bytes(), 0o644)
                .map_err(hard)
        } else {
            self.files.remove(path).map_err(hard)
        }
    }

    fn page_patch(&self, page: &str, parent: &str, commit: &str) -> LearnResult<String> {
        let pages = self.git_raw(&[
            "diff-tree",
            "--no-commit-id",
            "--relative",
            "--name-only",
            "-z",
            "-r",
            commit,
        ])?;
        if pages.strip_suffix('\0') != Some(page) {
            return Err(LearnError::Refused(
                "commit must change exactly the requested page".to_owned(),
            ));
        }
        self.git_raw(&[
            "diff",
            "--binary",
            "--relative",
            "--no-color",
            "--no-ext-diff",
            "--no-renames",
            parent,
            commit,
            "--",
            page,
        ])
    }

    /// The page-only patch of the learning `commit`.
    fn learned_patch(&self, page: &str, commit: &str) -> LearnResult<String> {
        let parent = self.git(&["rev-parse", &format!("{commit}^")])?;
        self.page_patch(page, &parent, commit)
    }

    /// The page's current bytes and its inverse-applied next image.
    fn prepare_inverse(
        &self,
        page: &str,
        patch: &str,
    ) -> LearnResult<(Option<String>, Option<String>)> {
        let current = self.read_page(page)?;
        let next = self.inverse_of(page, current.as_deref(), patch)?;
        Ok((current, next))
    }

    /// `text` as `page` with `patch` reversed, applied in a private tree.
    fn inverse_of(
        &self,
        page: &str,
        text: Option<&str>,
        patch: &str,
    ) -> LearnResult<Option<String>> {
        let scratch = tempfile::tempdir().map_err(|source| LearnError::Io {
            path: self.git_dir.clone(),
            source,
        })?;
        let work_tree = scratch.path().join("pages");
        std::fs::create_dir(&work_tree).map_err(|source| LearnError::Io {
            path: work_tree.clone(),
            source,
        })?;
        let files = GeneratedCapability::seal(&work_tree).map_err(confined)?;
        let path = Path::new(page);
        if let Some(parent) = path.parent() {
            files.create_dirs(parent, 0o700).map_err(confined)?;
        }
        if let Some(text) = text {
            files
                .write_atomic(path, text.as_bytes(), 0o600)
                .map_err(confined)?;
        }
        let patch_path = scratch.path().join("inverse.patch");
        std::fs::write(&patch_path, patch).map_err(|source| LearnError::Io {
            path: patch_path.clone(),
            source,
        })?;
        let isolated = Self {
            repo_root: work_tree.clone(),
            work_tree,
            git_dir: self.git_dir.clone(),
            files: Arc::new(files),
        };
        isolated
            .git(&[
                "apply",
                "--no-index",
                "--reverse",
                &patch_path.to_string_lossy(),
            ])
            .map_err(|error| {
                LearnError::Refused(format!("inverse conflicts with current page: {error}"))
            })?;
        isolated.read_page(page)
    }

    fn git(&self, args: &[&str]) -> LearnResult<String> {
        self.git_raw(args).map(|output| output.trim().to_owned())
    }

    fn git_raw(&self, args: &[&str]) -> LearnResult<String> {
        let output = Command::new("git")
            .arg("--literal-pathspecs")
            .env("GIT_OPTIONAL_LOCKS", "0")
            .arg("--git-dir")
            .arg(&self.git_dir)
            .arg("--work-tree")
            .arg(&self.repo_root)
            .args([
                "-c",
                &format!("user.name={AUTHOR}"),
                "-c",
                "user.email=odin-brain@localhost",
                "-c",
                "commit.gpgsign=false",
            ])
            .args(args)
            .current_dir(&self.work_tree)
            .output()
            .map_err(|source| LearnError::Io {
                path: self.git_dir.clone(),
                source,
            })?;
        if !output.status.success() {
            return Err(LearnError::Git {
                command: args.first().copied().unwrap_or_default().to_owned(),
                detail: String::from_utf8_lossy(&output.stderr).trim().to_owned(),
            });
        }
        Ok(String::from_utf8_lossy(&output.stdout).into_owned())
    }
}

fn confined(error: ConfinedError) -> LearnError {
    LearnError::Refused(format!("memory path refused: {error}"))
}

fn namespace_id(namespace: &str) -> String {
    if namespace.starts_with(MEMORY_NAMESPACE_PREFIX) {
        namespace.to_owned()
    } else {
        format!("{MEMORY_NAMESPACE_PREFIX}{namespace}")
    }
}

fn read_page(files: &GeneratedCapability, page: &str) -> LearnResult<Option<String>> {
    validate_relative_path(Path::new(page)).map_err(confined)?;
    if !page.contains('/') || !page.ends_with(".md") {
        return Err(LearnError::Refused(
            "page must be a namespaced memory page".to_owned(),
        ));
    }
    let mut file = match files.open_read(Path::new(page)) {
        Ok(file) => file,
        Err(ConfinedError::ComponentMissing { .. }) => return Ok(None),
        Err(error) => return Err(confined(error)),
    };
    let io = |source| LearnError::Io {
        path: PathBuf::from(page),
        source,
    };
    if file.metadata().map_err(io)?.nlink() != 1 {
        return Err(LearnError::Refused(
            "memory page has linked aliases".to_owned(),
        ));
    }
    let mut text = String::new();
    file.read_to_string(&mut text).map_err(io)?;
    Ok(Some(text))
}

/// The entry kind of the loop's add or update of `page` named by `subject`.
fn learning_kind(subject: &str, page: &str) -> Option<EntryKind> {
    let mut parts = subject.strip_prefix("brain: ")?.splitn(3, ' ');
    if !matches!(parts.next(), Some("add" | "update")) {
        return None;
    }
    let kind = parts.next().and_then(EntryKind::parse)?;
    (parts.next() == Some(page)).then_some(kind)
}

/// Splits a page into its kind, title and body. A page without front
/// matter (a remembered note) is a memory with no title.
pub fn parse_page(text: &str) -> (EntryKind, Option<String>, String) {
    let Some(rest) = text.strip_prefix("---\n") else {
        return (EntryKind::Memory, None, text.trim().to_owned());
    };
    let Some((front, body)) = rest.split_once("\n---\n") else {
        return (EntryKind::Memory, None, text.trim().to_owned());
    };
    let mut kind = EntryKind::Memory;
    let mut title = None;
    for line in front.lines() {
        match line.split_once(':') {
            Some(("kind", value)) => {
                kind = EntryKind::parse(value.trim()).unwrap_or(EntryKind::Memory);
            }
            Some(("title", value)) => title = Some(value.trim().to_owned()),
            _ => {}
        }
    }
    (kind, title, body.trim().to_owned())
}

fn render_page(edit: &Edit) -> String {
    format!(
        "---\nkind: {}\ntitle: {}\nevidence: {}\n---\n{}\n",
        edit.kind.as_str(),
        one_line(&edit.title),
        one_line(&edit.evidence),
        edit.content.trim()
    )
}

/// Where a credential begins.
const SECRET_PREFIXES: &[&str] = &["-----begin", "sk-", "ghp_", "github_pat_", "xoxb-", "akia"];

/// Credential field names: a sentence that names one ("the api_key lives in
/// sops") carries nothing; `name: value` does.
const SECRET_NAMES: &[&str] = &["password", "api_key", "apikey", "secret", "token"];

/// The shortest run that reads as a credential's value.
const SECRET_VALUE_CHARS: usize = 8;

/// A prefix counts only where it starts a token: "task-lesson" holds "sk-"
/// but carries no key.
fn starts_a_token(text: &str, marker: &str) -> bool {
    text.match_indices(marker).any(|(at, _)| {
        text[..at]
            .chars()
            .next_back()
            .is_none_or(|before| !before.is_ascii_alphanumeric())
    })
}

/// Whether `name` is followed by `:` or `=` and a value.
fn assigns_a_value(text: &str, name: &str) -> bool {
    text.match_indices(name).any(|(at, _)| {
        text[at + name.len()..]
            .trim_start()
            .strip_prefix([':', '='])
            .and_then(|value| value.split_whitespace().next())
            .is_some_and(|value| value.chars().count() >= SECRET_VALUE_CHARS)
    })
}

/// Phrases that report a condition rather than record a fact: a page lives
/// on after the outage it was written in, and then misleads every search.
const CONDITION_PHRASES: &[&str] = &[
    "is unavailable",
    "are unavailable",
    "is not available",
    "isn't available",
    "not working",
    "does not work",
    "doesn't work",
    "is broken",
    "keeps failing",
    "timed out",
    "is unreachable",
];

fn validate_content(edit: &Edit) -> LearnResult<()> {
    let title = edit.title.trim();
    if title.is_empty() || title.chars().count() > 80 || slug(title).is_empty() {
        return Err(LearnError::Refused(
            "a title is 1..=80 characters with a letter or digit".to_owned(),
        ));
    }
    let content = edit.content.trim();
    let limit = edit.kind.max_bytes();
    if content.is_empty() || content.len() > limit {
        return Err(LearnError::Refused(format!(
            "a {} entry holds 1..={limit} bytes; this one is {} bytes",
            edit.kind.as_str(),
            content.len()
        )));
    }
    let lowered = format!("{title}\n{content}").to_lowercase();
    if let Some(marker) = SECRET_PREFIXES
        .iter()
        .find(|marker| starts_a_token(&lowered, marker))
        .or_else(|| {
            SECRET_NAMES
                .iter()
                .find(|name| assigns_a_value(&lowered, name))
        })
    {
        return Err(LearnError::Refused(format!(
            "the entry looks like it carries a secret ({marker})"
        )));
    }
    if edit.kind == EntryKind::Memory || edit.kind == EntryKind::Prompt {
        if let Some(phrase) = CONDITION_PHRASES
            .iter()
            .find(|phrase| lowered.contains(*phrase))
        {
            return Err(LearnError::Refused(format!(
                "the entry reports a condition (\"{phrase}\"), which a page would outlive: \
                 record the lasting fact behind it, or nothing"
            )));
        }
    }
    Ok(())
}

fn action_name(action: EditAction) -> &'static str {
    match action {
        EditAction::Add => "add",
        EditAction::Update => "update",
        EditAction::Retire => "retire",
        EditAction::Revert => "revert",
    }
}

fn slug(text: &str) -> String {
    let mut slug = String::new();
    for character in text.chars().flat_map(char::to_lowercase) {
        if character.is_ascii_alphanumeric() {
            slug.push(character);
        } else if !slug.ends_with('-') && !slug.is_empty() {
            slug.push('-');
        }
        if slug.len() >= 48 {
            break;
        }
    }
    slug.trim_end_matches('-').to_owned()
}

/// ASCII-alphanumeric boundaries avoid partial label matches; non-ASCII bytes are boundaries.
fn contains_exact_label(text: &str, label: &str) -> bool {
    if label.is_empty() {
        return false;
    }
    let bytes = text.as_bytes();
    bytes
        .windows(label.len())
        .enumerate()
        .any(|(start, candidate)| {
            candidate == label.as_bytes()
                && (start == 0 || !bytes[start - 1].is_ascii_alphanumeric())
                && bytes
                    .get(start + label.len())
                    .is_none_or(|byte| !byte.is_ascii_alphanumeric())
        })
}

/// Whether the lowercase `phrase` is in the page's visible title and body.
fn visible_contains(text: &str, phrase: &str) -> bool {
    let (_, title, body) = parse_page(text);
    format!("{}\n{body}", title.as_deref().unwrap_or_default())
        .to_lowercase()
        .contains(phrase)
}

fn normalize(text: &str) -> String {
    text.split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .to_lowercase()
}

fn one_line(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

impl fmt::Display for EditScope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Owner => "owner",
            Self::Seat => "seat",
            Self::Project => "project",
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn git(root: &Path, args: &[&str]) {
        let status = Command::new("git")
            .args(["-c", "user.name=t", "-c", "user.email=t@t"])
            .args(args)
            .current_dir(root)
            .status()
            .unwrap();
        assert!(status.success(), "git {args:?}");
    }

    fn state() -> (tempfile::TempDir, BrainState) {
        let root = tempfile::tempdir().unwrap();
        git(root.path(), &["init", "--quiet"]);
        std::fs::create_dir_all(root.path().join("memory/sinmara")).unwrap();
        std::fs::write(
            root.path().join("memory/sinmara/abc.md"),
            "the owner's school calendar is owner@example.org",
        )
        .unwrap();
        git(root.path(), &["add", "--all"]);
        git(root.path(), &["commit", "--quiet", "-m", "brain: baseline"]);
        let state = BrainState::open(root.path().join("memory"), root.path()).unwrap();
        (root, state)
    }

    fn namespaces() -> Namespaces {
        Namespaces {
            colin: Some("profile".to_owned()),
            seat: "sinmara".to_owned(),
            project: None,
            writable: vec!["profile".to_owned(), "sinmara".to_owned()],
        }
    }

    fn provenance() -> Provenance {
        Provenance {
            seat: "sinmara".to_owned(),
            session: "s1".to_owned(),
            trigger: "turn".to_owned(),
        }
    }

    fn add(scope: EditScope, title: &str, content: &str) -> Edit {
        Edit {
            action: EditAction::Add,
            kind: EntryKind::Memory,
            scope,
            id: None,
            title: title.to_owned(),
            content: content.to_owned(),
            evidence: "the owner said so in turn k1".to_owned(),
        }
    }

    fn log(state: &BrainState) -> String {
        state.git(&["log", "--format=%s%n%b"]).unwrap()
    }

    #[test]
    fn an_added_entry_is_one_commit_with_its_provenance() {
        let (_root, state) = state();
        let (learned, refused) = state
            .apply(
                &namespaces(),
                &[add(
                    EditScope::Owner,
                    "Coffee",
                    "the owner drinks his coffee black",
                )],
                &provenance(),
            )
            .unwrap();
        assert!(refused.is_empty(), "{refused:?}");
        assert_eq!(learned.len(), 1);
        assert_eq!(learned[0].page, "profile/memory-coffee.md");
        let entries = state.entries("profile").unwrap();
        assert_eq!(entries[0].title.as_deref(), Some("Coffee"));
        assert_eq!(entries[0].body, "the owner drinks his coffee black");
        let log = log(&state);
        assert!(
            log.starts_with("brain: add memory profile/memory-coffee.md"),
            "{log}"
        );
        assert!(log.contains("Evidence: the owner said so in turn k1"));
        assert!(log.contains("Seat: sinmara") && log.contains("Session: s1"));
    }

    #[test]
    fn a_commit_never_takes_other_staged_files() {
        let (root, state) = state();
        std::fs::write(root.path().join("other.md"), "not memory").unwrap();
        git(root.path(), &["add", "other.md"]);
        state
            .apply(
                &namespaces(),
                &[add(
                    EditScope::Owner,
                    "Coffee",
                    "the owner drinks his coffee black",
                )],
                &provenance(),
            )
            .unwrap();
        let committed = state
            .git(&["ls-tree", "-r", "--name-only", "HEAD"])
            .unwrap();
        assert!(!committed.contains("other.md"), "{committed}");
        assert!(state
            .git(&["diff", "--cached", "--name-only"])
            .unwrap()
            .contains("other.md"));
    }

    #[test]
    fn remembering_under_an_existing_title_updates_that_page() {
        let (_root, state) = state();
        let first = add(
            EditScope::Owner,
            "Favourite tea",
            "the owner's favourite tea is oolong",
        );
        state.apply(&namespaces(), &[first], &provenance()).unwrap();
        let again = add(
            EditScope::Owner,
            "Favourite tea",
            "the owner's favourite tea is sencha",
        );
        let (learned, refused) = state.apply(&namespaces(), &[again], &provenance()).unwrap();
        assert!(refused.is_empty(), "{refused:?}");
        assert_eq!(learned.len(), 1);
        assert_eq!(learned[0].action, EditAction::Update);
        assert_eq!(learned[0].page, "profile/memory-favourite-tea.md");
        let entries = state.entries("profile").unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].body, "the owner's favourite tea is sencha");
        assert!(log(&state).starts_with("brain: update memory profile/memory-favourite-tea.md"));
    }

    #[test]
    fn an_oversized_entry_is_refused_with_its_byte_length_and_not_stored() {
        let (_root, state) = state();
        let content = "é".repeat(301);
        let (learned, refused) = state
            .apply(
                &namespaces(),
                &[add(EditScope::Owner, "Too long", &content)],
                &provenance(),
            )
            .unwrap();
        assert!(learned.is_empty());
        assert_eq!(refused.len(), 1, "{refused:?}");
        assert!(
            refused[0].contains("1..=600 bytes") && refused[0].contains("602 bytes"),
            "{}",
            refused[0]
        );
        assert!(state.entries("profile").unwrap().is_empty());
    }

    /// Adversarial review (d4, HIGH): project namespaces are shared across
    /// seats, and a title collision overwrote another seat's page.
    #[test]
    fn another_seats_page_under_the_same_title_is_never_overwritten() {
        let (_root, state) = state();
        let gungnir = Provenance {
            seat: "gungnir".to_owned(),
            ..provenance()
        };
        let first = add(
            EditScope::Owner,
            "Favourite tea",
            "the owner's favourite tea is oolong",
        );
        state.apply(&namespaces(), &[first], &gungnir).unwrap();
        let mine = add(
            EditScope::Owner,
            "Favourite tea",
            "the owner's favourite tea is sencha",
        );
        let (learned, refused) = state
            .apply(&namespaces(), std::slice::from_ref(&mine), &provenance())
            .unwrap();
        assert!(refused.is_empty(), "{refused:?}");
        assert_eq!(learned[0].action, EditAction::Add);
        assert_eq!(learned[0].page, "profile/memory-favourite-tea-sinmara.md");
        let entries = state.entries("profile").unwrap();
        let gungnirs = entries
            .iter()
            .find(|entry| entry.id == "memory-favourite-tea")
            .expect("gungnir's page");
        assert_eq!(gungnirs.body, "the owner's favourite tea is oolong");
        let newer = Edit {
            content: "the owner's favourite tea is genmaicha".to_owned(),
            ..mine
        };
        let (learned, _) = state.apply(&namespaces(), &[newer], &provenance()).unwrap();
        assert_eq!(learned[0].action, EditAction::Update);
        assert_eq!(learned[0].page, "profile/memory-favourite-tea-sinmara.md");
        // the owner's own edit of a page makes it his: the loop leaves it alone.
        std::fs::write(
            state
                .work_tree
                .join("profile/memory-favourite-tea-sinmara.md"),
            "the owner's favourite tea is hojicha",
        )
        .unwrap();
        state.commit_pending().unwrap();
        let after_colin = add(
            EditScope::Owner,
            "Favourite tea",
            "the owner's favourite tea is matcha",
        );
        let (_, refused) = state
            .apply(&namespaces(), &[after_colin], &provenance())
            .unwrap();
        assert_eq!(refused.len(), 1, "{refused:?}");
    }

    #[test]
    fn a_revert_undoes_the_last_edit_and_says_why() {
        let (_root, state) = state();
        state
            .apply(
                &namespaces(),
                &[add(EditScope::Seat, "Gym", "The gym locker code is 3-1-4")],
                &provenance(),
            )
            .unwrap();
        let page = "sinmara/memory-gym.md";
        assert!(state.work_tree().join(page).exists());
        let revert = state.revert_last(page, "the owner: that's wrong").unwrap();
        assert!(revert.is_some());
        assert!(!state.work_tree().join(page).exists());
        assert!(state.work_tree().join("sinmara/abc.md").exists());
        let log = log(&state);
        assert!(
            log.starts_with("brain: revert sinmara/memory-gym.md"),
            "{log}"
        );
        assert!(log.contains("Reason: the owner: that's wrong"));
    }

    #[test]
    fn a_credential_is_refused_but_a_sentence_naming_one_is_kept() {
        let (_root, state) = state();
        let (learned, refused) = state
            .apply(
                &namespaces(),
                &[
                    add(EditScope::Seat, "Key", "the api_key is sk-123"),
                    add(EditScope::Seat, "Login", "password: hunter2hunter2"),
                    add(
                        EditScope::Seat,
                        "Where keys live",
                        "the OpenRouter api_key and the token live in sops",
                    ),
                ],
                &provenance(),
            )
            .unwrap();
        assert_eq!(refused.len(), 2, "{refused:?}");
        assert!(refused[0].contains("secret") && refused[0].contains("sk-"));
        assert!(refused[1].contains("secret") && refused[1].contains("password"));
        assert_eq!(learned.len(), 1);
        assert_eq!(learned[0].page, "sinmara/memory-where-keys-live.md");
    }

    #[test]
    fn an_outage_report_is_refused_and_the_fact_behind_it_is_kept() {
        let (_root, state) = state();
        let (learned, refused) = state
            .apply(
                &namespaces(),
                &[
                    add(
                        EditScope::Seat,
                        "Kreate",
                        "Kreate is unavailable, so decline requests for it",
                    ),
                    add(
                        EditScope::Seat,
                        "Kreate lives on the vault",
                        "Kreate's code and data live on the encrypted vault SSD",
                    ),
                ],
                &provenance(),
            )
            .unwrap();
        assert_eq!(refused.len(), 1, "{refused:?}");
        assert!(refused[0].contains("is unavailable"), "{refused:?}");
        assert_eq!(learned.len(), 1);
    }

    #[test]
    fn fourth_edit_is_refused_and_first_three_commit() {
        let (_root, state) = state();
        let (learned, refused) = state
            .apply(
                &namespaces(),
                &[
                    add(EditScope::Seat, "Alpha", "alpha lesson"),
                    add(EditScope::Seat, "Beta", "beta lesson"),
                    add(EditScope::Seat, "Gamma", "gamma lesson"),
                    add(EditScope::Seat, "Delta", "delta lesson"),
                ],
                &provenance(),
            )
            .unwrap();
        assert_eq!(learned.len(), 3, "{learned:?}");
        assert_eq!(
            learned
                .iter()
                .map(|item| item.page.as_str())
                .collect::<Vec<_>>(),
            [
                "sinmara/memory-alpha.md",
                "sinmara/memory-beta.md",
                "sinmara/memory-gamma.md",
            ]
        );
        assert_eq!(refused, ["1 edits past the 3-edit bound".to_owned()]);
        let subjects = state.git(&["log", "--format=%s"]).unwrap();
        assert_eq!(
            subjects.lines().take(3).collect::<Vec<_>>(),
            [
                "brain: add memory sinmara/memory-gamma.md",
                "brain: add memory sinmara/memory-beta.md",
                "brain: add memory sinmara/memory-alpha.md",
            ]
        );
        assert!(!state.work_tree().join("sinmara/memory-delta.md").exists());
    }

    #[test]
    fn target_id_cannot_leave_the_namespace() {
        let (_root, state) = state();
        state
            .apply(
                &namespaces(),
                &[add(EditScope::Owner, "Escape", "protected fact")],
                &provenance(),
            )
            .unwrap();
        let escaped = state.work_tree().join("profile/memory-escape.md");
        let original = std::fs::read(&escaped).unwrap();
        let before = pending_owner_edit(&state);
        for action in [EditAction::Update, EditAction::Retire, EditAction::Revert] {
            let edit = Edit {
                action,
                id: Some("../profile/memory-escape".to_owned()),
                ..add(EditScope::Seat, "Escape", "must not land outside sinmara")
            };
            let (learned, refused) = state.apply(&namespaces(), &[edit], &provenance()).unwrap();
            assert!(learned.is_empty(), "{learned:?}");
            assert_eq!(refused.len(), 1, "{action:?}: {refused:?}");
            assert_eq!(std::fs::read(&escaped).unwrap(), original);
            assert_pending_owner_edit(&state, &before);
        }
        let invalid = Namespaces {
            seat: "../outside".to_owned(),
            ..namespaces()
        };
        let (learned, refused) = state
            .apply(
                &invalid,
                &[add(EditScope::Seat, "Escape", "no escape")],
                &provenance(),
            )
            .unwrap();
        assert!(learned.is_empty());
        assert_eq!(refused.len(), 1);
        assert!(!state.work_tree().join("../outside").exists());
        assert_pending_owner_edit(&state, &before);
    }

    #[test]
    fn a_seat_cannot_change_a_namespace_it_is_not_granted() {
        let (_root, state) = state();
        state
            .apply(
                &namespaces(),
                &[add(EditScope::Owner, "Tea", "the owner likes green tea")],
                &provenance(),
            )
            .unwrap();
        let foreign = Namespaces {
            colin: Some("profile".to_owned()),
            seat: "gungnir".to_owned(),
            project: None,
            writable: vec!["gungnir".to_owned()],
        };
        let gungnir = Provenance {
            seat: "gungnir".to_owned(),
            ..provenance()
        };
        for action in [EditAction::Update, EditAction::Retire, EditAction::Revert] {
            let edit = Edit {
                action,
                id: Some("memory-tea".to_owned()),
                ..add(EditScope::Owner, "Tea", "must not land")
            };
            let (learned, refused) = state.apply(&foreign, &[edit], &gungnir).unwrap();
            assert!(learned.is_empty(), "{action:?} {learned:?}");
            assert!(
                refused.iter().any(|reason| {
                    reason.contains("seat gungnir") && reason.contains("memory.profile")
                }),
                "{action:?} {refused:?}"
            );
        }
        std::fs::create_dir_all(state.work_tree().join("gungnir")).unwrap();
        let (learned, refused) = state
            .apply(
                &foreign,
                &[add(EditScope::Seat, "Build", "nix develop -c cargo test")],
                &gungnir,
            )
            .unwrap();
        assert!(refused.is_empty(), "{refused:?}");
        assert_eq!(learned[0].page, "gungnir/memory-build.md");
    }

    fn pending_owner_edit(state: &BrainState) -> (String, Vec<u8>) {
        let path = state.work_tree().join("sinmara/abc.md");
        std::fs::write(&path, "owner staged edit").unwrap();
        state.git(&["add", "--", "sinmara/abc.md"]).unwrap();
        std::fs::write(path, "owner unstaged edit").unwrap();
        (
            state.git(&["rev-parse", "HEAD"]).unwrap(),
            std::fs::read(state.git_dir.join("index")).unwrap(),
        )
    }

    fn assert_pending_owner_edit(state: &BrainState, before: &(String, Vec<u8>)) {
        assert_eq!(state.git(&["rev-parse", "HEAD"]).unwrap(), before.0);
        assert_eq!(
            std::fs::read(state.git_dir.join("index")).unwrap(),
            before.1
        );
        assert_eq!(
            std::fs::read_to_string(state.work_tree().join("sinmara/abc.md")).unwrap(),
            "owner unstaged edit"
        );
    }

    #[cfg(unix)]
    #[test]
    fn linked_entries_refuse_without_touching_targets_or_pending_owner_edits() {
        for hard_link in [false, true] {
            for action in [
                EditAction::Add,
                EditAction::Update,
                EditAction::Retire,
                EditAction::Revert,
            ] {
                let (root, state) = state();
                let (learned, _) = state
                    .apply(
                        &namespaces(),
                        &[add(EditScope::Seat, "Fixture", "fixture-linked-123")],
                        &provenance(),
                    )
                    .unwrap();
                let own = &learned[0];
                let path = state.work_tree().join(&own.page);
                let outside = root.path().join("outside.md");
                std::fs::write(&outside, "fixture-linked-123").unwrap();
                std::fs::remove_file(&path).unwrap();
                if hard_link {
                    std::fs::hard_link(&outside, &path).unwrap();
                } else {
                    std::os::unix::fs::symlink(&outside, &path).unwrap();
                }
                let before = pending_owner_edit(&state);
                let edit = Edit {
                    action,
                    id: Some("memory-fixture".to_owned()),
                    ..add(EditScope::Seat, "Fixture", "replacement fact")
                };
                let (learned, refused) =
                    state.apply(&namespaces(), &[edit], &provenance()).unwrap();
                assert!(learned.is_empty(), "{action:?}, hard_link={hard_link}");
                assert_eq!(refused.len(), 1);
                assert!(matches!(
                    state.revert_exact(&own.page, &own.commit, "fixture-linked-123", "sinmara"),
                    Err(LearnError::Refused(_))
                ));
                assert_eq!(
                    std::fs::read_to_string(&outside).unwrap(),
                    "fixture-linked-123"
                );
                assert_eq!(
                    std::fs::read_to_string(&path).unwrap(),
                    "fixture-linked-123"
                );
                assert_pending_owner_edit(&state, &before);
            }
        }
    }

    /// A correction inverts the page's newest learned edit even when a later,
    /// non-overlapping owner edit is already synced or still pending. The
    /// owner edit survives, and exact replay recognizes that one inverse.
    #[test]
    fn correction_inverts_the_learned_update_and_keeps_a_later_owner_edit() {
        let body = |first: &str| format!("{first}\n{}owner line", "steady line\n".repeat(8));
        let page = "sinmara/memory-fixture.md";
        for synced in [true, false] {
            let (_root, state) = state();
            let path = state.work_tree().join(page);
            let learn = |title: &str, content: &str| {
                state
                    .apply(
                        &namespaces(),
                        &[add(EditScope::Seat, title, content)],
                        &provenance(),
                    )
                    .unwrap()
                    .0
            };
            learn("Fixture", &body("learned v1"));
            let update = learn("Fixture", &body("fixture-update-m2b")).remove(0);
            assert_eq!(update.action, EditAction::Update);
            let owner = std::fs::read_to_string(&path)
                .unwrap()
                .replace("owner line", "owner newer line");
            std::fs::write(&path, &owner).unwrap();
            if synced {
                assert_eq!(learn("Other", "an independent learned fact").len(), 1);
            }
            let corrected = owner.replace("fixture-update-m2b", "learned v1");
            let foreign = state.work_tree().join("sinmara/abc.md");
            let foreign_bytes = std::fs::read(&foreign).unwrap();
            // Visible text the update introduced, including across the title
            // and body or into unchanged lines, binds the correction.
            for introduced in [
                "fixture-update-m2b",
                "fixture\nfixture-update-m2b",
                "fixture-update-m2b\nsteady line",
            ] {
                assert!(
                    state.learned_entry(page, introduced).unwrap(),
                    "synced={synced}: {introduced:?}"
                );
            }
            // Owner text, metadata, and text its predecessor already showed
            // are refused: inverting the update cannot remove them.
            for unlearned in [
                "owner newer line",
                "said so in turn k1",
                "steady line\nsteady line",
            ] {
                assert!(
                    matches!(
                        state.learned_entry(page, unlearned),
                        Err(LearnError::Refused(_))
                    ),
                    "synced={synced}: {unlearned:?} is not text the update introduced"
                );
            }
            assert!(!state
                .learned_entry("sinmara/abc.md", "school calendar")
                .unwrap());
            let head = state.git(&["rev-parse", "HEAD"]).unwrap();
            let revert = Edit {
                action: EditAction::Revert,
                id: Some("memory-fixture".to_owned()),
                evidence: "the owner: the update is wrong".to_owned(),
                ..add(EditScope::Seat, "", "")
            };
            let (learned, refused) = state
                .apply(&namespaces(), std::slice::from_ref(&revert), &provenance())
                .unwrap();
            assert!(refused.is_empty(), "synced={synced}: {refused:?}");
            let inverse = learned[0].commit.clone();
            assert_eq!(std::fs::read_to_string(&path).unwrap(), corrected);
            assert_eq!(state.git(&["rev-parse", "HEAD"]).unwrap(), inverse);
            assert_eq!(
                state
                    .git(&[
                        "diff-tree",
                        "--no-commit-id",
                        "--relative",
                        "--name-only",
                        "-r",
                        &inverse
                    ])
                    .unwrap(),
                page
            );
            assert_eq!(
                state
                    .git(&["rev-list", "--count", &format!("{head}..HEAD")])
                    .unwrap(),
                if synced { "1" } else { "2" },
                "one inverse, plus the pending owner sync"
            );
            assert_eq!(std::fs::read(&foreign).unwrap(), foreign_bytes);
            assert!(
                !state.learned_entry(page, "fixture-update-m2b").unwrap(),
                "a corrected entry is never walked back past its inverse"
            );

            assert_eq!(
                state
                    .revert_exact(page, &update.commit, "fixture-update-m2b", "sinmara")
                    .unwrap()
                    .commit,
                inverse,
                "synced={synced}"
            );
            let owner_only = Edit {
                id: Some("abc".to_owned()),
                ..revert
            };
            let (learned, refused) = state
                .apply(&namespaces(), &[owner_only], &provenance())
                .unwrap();
            assert!(learned.is_empty(), "{learned:?}");
            assert_eq!(refused.len(), 1);
            assert_eq!(state.git(&["rev-parse", "HEAD"]).unwrap(), inverse);
            assert_eq!(std::fs::read_to_string(&path).unwrap(), corrected);
            assert_eq!(std::fs::read(&foreign).unwrap(), foreign_bytes);
        }
    }

    #[test]
    fn retire_removes_the_page_in_one_commit() {
        let (_root, state) = state();
        state
            .apply(
                &namespaces(),
                &[add(EditScope::Seat, "Gym", "The gym locker code is 3-1-4")],
                &provenance(),
            )
            .unwrap();
        let retire = Edit {
            action: EditAction::Retire,
            id: Some("memory-gym".to_owned()),
            ..add(EditScope::Seat, "Gym", "")
        };
        let (learned, refused) = state
            .apply(&namespaces(), &[retire], &provenance())
            .unwrap();
        assert!(refused.is_empty(), "{refused:?}");
        assert_eq!(learned.len(), 1);
        assert!(!state.work_tree().join("sinmara/memory-gym.md").exists());
        assert!(state.work_tree().join("sinmara/abc.md").exists());
        let subjects = log(&state);
        assert!(
            subjects.starts_with("brain: retire memory sinmara/memory-gym.md"),
            "{subjects}"
        );
    }

    #[test]
    fn outside_edits_are_committed_apart_from_the_loop() {
        let (_root, state) = state();
        std::fs::write(state.work_tree().join("sinmara/abc.md"), "edited by the owner").unwrap();
        state
            .apply(
                &namespaces(),
                &[add(EditScope::Seat, "Tea", "the owner likes green tea")],
                &provenance(),
            )
            .unwrap();
        let subjects = state.git(&["log", "--format=%s"]).unwrap();
        assert_eq!(
            subjects.lines().collect::<Vec<_>>(),
            [
                "brain: add memory sinmara/memory-tea.md",
                "brain: sync vault edits",
                "brain: baseline"
            ]
        );
    }

    #[test]
    fn exact_inverse_restores_prior_page_and_preserves_foreign_edits() {
        let (_root, state) = state();
        let page = "sinmara/abc.md";
        let path = state.work_tree().join(page);
        let original = format!(
            "real standing fact\n{}foreign original\n",
            "unchanged\n".repeat(20)
        );
        std::fs::write(&path, &original).unwrap();
        state.commit_pending().unwrap();
        let fixture = original.replacen("real standing fact", "fixture-unique-123", 1);
        std::fs::write(&path, &fixture).unwrap();
        let own = state
            .commit(
                &[page],
                "brain: update memory sinmara/abc.md\n\nSeat: sinmara\nSession: fixture",
            )
            .unwrap()
            .unwrap();
        std::fs::write(&path, fixture.replace("foreign original", "foreign newer")).unwrap();
        let other = state.work_tree().join("sinmara/other.md");
        std::fs::write(&other, "foreign independent page").unwrap();
        let inverse = state
            .revert_exact(page, &own, "fixture-unique-123", "sinmara")
            .unwrap();
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            original.replace("foreign original", "foreign newer")
        );
        assert_eq!(
            std::fs::read_to_string(&other).unwrap(),
            "foreign independent page"
        );
        assert_eq!(
            state
                .revert_exact(page, &own, "fixture-unique-123", "sinmara")
                .unwrap(),
            inverse
        );
    }
}
