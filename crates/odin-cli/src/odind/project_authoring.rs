//! Runtime project creation constraints, enforced here and by registry validation:
//! - only the owner-facing conversation seat may create (the registry also
//!   refuses any other seat that lists a creation capability);
//! - a project created at runtime may bind only worker seats whose every
//!   capability is in the new-seat skeleton's bindable list — builder and judge work in
//!   isolated worktrees, never accounts, Colin's browser, the cluster, or
//!   creation itself;
//! - its root is a directory directly inside the projects directory (the
//!   declared odin repository's parent), never a symlink, never another
//!   project's root;
//! - a new root is a clone of Colin's existing repository of that name (the
//!   sibling of odin's `origin`) whenever one exists; an empty repository is
//!   made only on a definite "not found", never because GitHub was
//!   unreachable (an empty repository would shadow the real one);
//! - declarations share an authoring commit validated as a full registry candidate
//!   before push and publication.
//!
//! Composition reads project roots and lane bindings at start
//! (`OdindConfig::load` adopts runtime-created projects), so a publication
//! requests a reload that runs once no live session is mid-turn.

use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use odin_domain::huginn::OmpLivePlane as _;
use odin_hermes::runtime::projects::{
    ProjectCreateRequest, ProjectCreated, ProjectRoute, SeatCreateRequest, SeatCreated,
};
use odin_registry::{ObjectConfig, RegistryKind, SnapshotHandle, SnapshotStore};

use crate::workload_authoring::{git, AuthoringSync, WorktreeLock};

/// Capabilities a new project's seats may hold, from the new-seat skeleton.
pub(crate) fn bindable_capabilities(
    worktree: &Path,
    sync: &AuthoringSync,
) -> Result<Vec<String>, String> {
    // Admission may be the first use of the private authoring checkout.
    sync.ensure(worktree).map_err(|error| error.to_string())?;
    let path = worktree.join("skeletons/new-seat/bindable.toml");
    let text = std::fs::read_to_string(&path)
        .map_err(|error| format!("could not read {}: {error}", path.display()))?;
    let table: toml::Table = toml::from_str(&text).map_err(|error| {
        format!(
            "{} is not the bindable capability list: {error}",
            path.display()
        )
    })?;
    let listed = table
        .get("capabilities")
        .and_then(|value| value.as_array())
        .ok_or_else(|| format!("{} has no capabilities list", path.display()))?;
    listed
        .iter()
        .map(|value| {
            value
                .as_str()
                .map(str::to_owned)
                .ok_or_else(|| format!("{} capabilities must be strings", path.display()))
        })
        .collect()
}

/// Set by a publication that changed composed state; consumed by the reload
/// pump. One daemon per process.
static RELOAD_REQUESTED: AtomicBool = AtomicBool::new(false);

/// Asks the reload pump for one idle restart: every runtime publication
/// that changes composed state (projects, seats, lanes, workload profiles)
/// is only dispatchable — and conversation successors only admit — once
/// odind recomposes at the new revision.
pub(crate) fn request_reload() {
    RELOAD_REQUESTED.store(true, Ordering::Release);
}

/// What one publication asks of the reload pump.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ReloadDecision {
    /// Only live-read objects (routines) changed: odind's composed state,
    /// every session's bound generation and the conversation vehicle stay
    /// valid; nothing restarts and no delegation is deferred.
    CompositionUnchanged(odin_registry::CompositionDigest),
    /// Recompose at idle when a composed object changed or its digest is unavailable.
    Recompose,
}

/// Decides from the composition digests of the publication a transaction
/// started on and the one it adopted: only a composition change reloads.
pub(crate) fn reload_decision(
    previous: &odin_registry::Snapshot,
    published: &odin_registry::Snapshot,
) -> ReloadDecision {
    match (
        previous.composition_digest(),
        published.composition_digest(),
    ) {
        (Ok(before), Ok(after)) if before == after => {
            tracing::warn!(
                "publication composition unchanged; vehicle kept, no reload \
                 revision={} digest={after}",
                published.revision
            );
            ReloadDecision::CompositionUnchanged(after)
        }
        (Ok(before), Ok(after)) => {
            tracing::warn!(
                "publication composition changed; idle reload requested \
                 revision={} digest={before}->{after}",
                published.revision
            );
            ReloadDecision::Recompose
        }
        (before, after) => {
            let error = before.err().or(after.err()).map(|error| error.to_string());
            tracing::warn!(
                "publication composition digest unproven; idle reload requested \
                 revision={} error={error:?}",
                published.revision
            );
            ReloadDecision::Recompose
        }
    }
}

/// Requests the idle reload only for a publication that changed what odind
/// composes ([`reload_decision`]).
pub(crate) fn request_reload_for(
    previous: &odin_registry::Snapshot,
    published: &odin_registry::Snapshot,
) {
    if reload_decision(previous, published) == ReloadDecision::Recompose {
        request_reload();
    }
}

/// Whether an idle restart is pending: a session opened now could not run
/// a turn until it has happened.
pub(crate) fn reload_requested() -> bool {
    RELOAD_REQUESTED.load(Ordering::Acquire)
}

const LOCK_BOUND: Duration = Duration::from_secs(30);
/// Attempts of one authoring transaction when `main` moves under its push.
const PUSH_ATTEMPTS: u32 = 3;

pub(crate) struct DaemonProjectRoute {
    pub(crate) pin: Arc<SnapshotHandle>,
    pub(crate) admission_config: odin_huginn::OdindConfig,
    /// Each configured seat's slice: a created seat's delegation grant joins
    /// the caller's own slice.
    pub(crate) caller_slices: std::collections::BTreeMap<String, String>,
    /// The environments the daemon's configured seat launch options bind,
    /// by seat: composition refuses a launch option naming a missing
    /// environment, so a bound environment refuses its removal while the
    /// launch stands.
    pub(crate) harness_environments:
        std::collections::BTreeMap<String, std::collections::BTreeSet<String>>,
    pub(crate) snapshot_store: PathBuf,
    pub(crate) worktree: PathBuf,
    pub(crate) sync: AuthoringSync,
}

impl ProjectRoute for DaemonProjectRoute {
    fn create(
        &self,
        caller: &odin_domain::SeatId,
        request: ProjectCreateRequest,
    ) -> Result<ProjectCreated, String> {
        let run = || self.create_blocking(caller, &request);
        blocking(run)
    }

    fn create_seat(
        &self,
        caller: &odin_domain::SeatId,
        request: SeatCreateRequest,
    ) -> Result<SeatCreated, String> {
        blocking(|| self.create_seat_blocking(caller, &request))
    }

    fn propose_seat(
        &self,
        caller: &odin_domain::SeatId,
        request: odin_hermes::runtime::projects::SeatProposeRequest,
    ) -> Result<odin_hermes::runtime::projects::SeatProposed, String> {
        blocking(|| self.propose_seat_blocking(caller, &request))
    }

    fn ephemeral_seats(&self) -> Vec<(String, i64)> {
        self.declared_ephemeral_seats()
    }

    fn ephemeral_proposals(&self) -> Vec<(String, i64, Option<i64>)> {
        self.declared_ephemeral_proposals()
    }

    fn retire_seat(&self, seat: &str, reason: &str) -> Result<(u64, String), String> {
        blocking(|| self.retire_seat_blocking(seat, reason))
    }
}

/// The handlers run on a runtime worker: git and SQLite block, so the
/// worker parks instead of starving the runtime.
pub(crate) fn blocking<T>(run: impl FnOnce() -> T) -> T {
    match tokio::runtime::Handle::try_current() {
        Ok(handle) if handle.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread => {
            tokio::task::block_in_place(run)
        }
        _ => run(),
    }
}

/// How the project root comes to exist.
#[derive(Debug, Eq, PartialEq)]
enum RootSource {
    /// An existing directory in the projects directory.
    Existing,
    /// A clone of Colin's existing repository.
    Clone(String),
    /// A new repository with one empty commit.
    New,
}

const ACTIVATION: &str =
    "usable after Odin reloads itself at the next quiet moment (about half a minute)";

/// One declared file derived from `source` (the synced worktree's text, or
/// an earlier edit's) and written to `path`, under the lock.
pub(crate) struct Edit {
    source: String,
    path: String,
    apply: EditFn,
}

type EditFn = Box<dyn Fn(&str) -> Result<String, String>>;

impl Edit {
    /// Rewrites `path` from the synced text of `source` (the same file for
    /// an in-place change).
    pub(crate) fn new(
        source: String,
        path: String,
        apply: impl Fn(&str) -> Result<String, String> + 'static,
    ) -> Self {
        Self {
            source,
            path,
            apply: Box::new(apply),
        }
    }
}

/// A new project's root, how it comes to exist, and its declaration files.
type NewRoot = (PathBuf, RootSource, Vec<(String, String)>);

/// A creation plan validated before any project or registry mutation.
struct Plan {
    project: String,
    root: PathBuf,
    source: RootSource,
    files: Vec<(String, String)>,
    /// Seats whose `project_scope` gains the project (edited in the synced
    /// worktree, under the authoring lock).
    seats: Vec<String>,
    lanes: Vec<String>,
}

impl DaemonProjectRoute {
    fn create_blocking(
        &self,
        caller: &odin_domain::SeatId,
        request: &ProjectCreateRequest,
    ) -> Result<ProjectCreated, String> {
        let plan = self.plan(caller, request)?;
        match &plan.source {
            RootSource::Existing => {}
            RootSource::Clone(url) => self.sync.clone_into(url, &plan.root)?,
            RootSource::New => {
                std::fs::create_dir(&plan.root).map_err(|error| {
                    format!("could not create {}: {error}", plan.root.display())
                })?;
                git(&plan.root, &["init", "--quiet", "-b", "main"])?;
                // A repository with no commit has no HEAD, and the state.repos
                // brain source refuses an unborn HEAD at start.
                git(
                    &plan.root,
                    &[
                        "-c",
                        "user.name=Odin",
                        "-c",
                        "user.email=odin@localhost",
                        "-c",
                        "commit.gpgsign=false",
                        "commit",
                        "--quiet",
                        "--allow-empty",
                        "-m",
                        &format!("{}: start", plan.project),
                    ],
                )?;
            }
        }
        let edits: Vec<Edit> = plan
            .seats
            .iter()
            .map(|seat| {
                let project = plan.project.clone();
                let path = format!("registry/seats/{seat}/seat.toml");
                Edit {
                    source: path.clone(),
                    path,
                    apply: Box::new(move |text: &str| {
                        with_item_in_array(text, None, "project_scope", &project)
                    }),
                }
            })
            .collect();
        let verb = if matches!(plan.source, RootSource::Existing)
            && plan
                .files
                .iter()
                .all(|(path, _)| path.starts_with("registry/lanes/"))
        {
            "add seats to"
        } else {
            "create"
        };
        let message = format!(
            "project: {verb} '{}' (runtime, by seat {})",
            plan.project, caller
        );
        let (published_revision, commit) = self.publish(&message, plan.files, edits)?;
        Ok(ProjectCreated {
            project: plan.project,
            root: plan.root.display().to_string(),
            lanes: plan.lanes,
            published_revision,
            commit,
            activation: ACTIVATION.to_owned(),
        })
    }

    /// The shared authoring transaction: under the worktree lock, sync onto
    /// odin main, write `files`, apply `edits` to the synced text, commit
    /// one child of main, validate its registry and future brain policies,
    /// then push it to main, publish it, and request the idle reload. Any
    /// failure before the push discards the worktree change.
    fn publish(
        &self,
        message: &str,
        files: Vec<(String, String)>,
        edits: Vec<Edit>,
    ) -> Result<(u64, String), String> {
        self.transact(message, files, edits, &[])
    }

    /// [`Self::publish`] with `removals` deleted in the same commit.
    pub(crate) fn transact(
        &self,
        message: &str,
        files: Vec<(String, String)>,
        edits: Vec<Edit>,
        removals: &[String],
    ) -> Result<(u64, String), String> {
        self.transact_with_admission(message, files, edits, removals, |_| Ok(()))
    }

    /// Adds plan-specific invariants over the exact candidate that will publish.
    pub(crate) fn transact_with_admission(
        &self,
        message: &str,
        files: Vec<(String, String)>,
        edits: Vec<Edit>,
        removals: &[String],
        admit: impl Fn(&[odin_registry::RegistryObject]) -> Result<(), String>,
    ) -> Result<(u64, String), String> {
        let refused = |failure: odin_hermes::runtime::WorkloadAuthoringFailure| failure.to_string();
        self.sync.ensure(&self.worktree).map_err(refused)?;
        let _lock = WorktreeLock::acquire(&self.worktree, LOCK_BOUND).map_err(refused)?;
        let store = SnapshotStore::new(&self.snapshot_store);
        let active = store
            .load_verified()
            .map_err(|error| format!("active registry publication is invalid: {error}"))?;
        let next = active
            .revision
            .checked_add(1)
            .ok_or("registry revision space is exhausted")?;
        let anchor = store
            .publication_at(active.revision)
            .map_err(|error| format!("active publication receipt is unreadable: {error}"))?
            .1
            .commit;
        let mut attempt = 0;
        let candidate = loop {
            attempt += 1;
            let origin = self.sync.fetch(&self.worktree).map_err(refused)?;
            self.sync
                .sync(&self.worktree, &anchor, &origin, |_| false)
                .map_err(refused)?;
            let discard = || {
                if let Err(error) = git(
                    &self.worktree,
                    &["checkout", "--quiet", "--detach", "--force", &origin],
                ) {
                    tracing::error!(
                        "project-authoring discard-failed worktree={} origin={origin} \
                         reason={error}",
                        self.worktree.display()
                    );
                }
            };
            let mut files = files.clone();
            let staged = (|| {
                for edit in &edits {
                    let current = match files.iter().find(|(path, _)| *path == edit.source) {
                        Some((_, text)) => text.clone(),
                        None => std::fs::read_to_string(self.worktree.join(&edit.source))
                            .map_err(|error| format!("could not read {}: {error}", edit.source))?,
                    };
                    let text = (edit.apply)(&current)?;
                    match files.iter_mut().find(|(path, _)| *path == edit.path) {
                        Some(entry) => entry.1 = text,
                        None => files.push((edit.path.clone(), text)),
                    }
                }
                for (relative, text) in &files {
                    let path = self.worktree.join(relative);
                    path.parent()
                        .map_or(Ok(()), std::fs::create_dir_all)
                        .and_then(|()| std::fs::write(&path, text))
                        .map_err(|error| format!("could not write {relative}: {error}"))?;
                }
                for relative in removals {
                    git(&self.worktree, &["rm", "--quiet", "-r", "--", relative])?;
                }
                let paths: Vec<&str> = files
                    .iter()
                    .map(|(relative, _)| relative.as_str())
                    .collect();
                if !paths.is_empty() {
                    let mut add = vec!["add", "--"];
                    add.extend(paths.iter().copied());
                    git(&self.worktree, &add)?;
                }
                let mut commit_args = vec!["commit", "--quiet", "-m", message, "--"];
                commit_args.extend(paths.iter().copied());
                commit_args.extend(removals.iter().map(String::as_str));
                git(&self.worktree, &commit_args)?;
                let commit = git(&self.worktree, &["rev-parse", "HEAD"])?;
                let candidate = store
                    .runtime_candidate(
                        &self.worktree,
                        &commit,
                        odin_cli::runtime_bindings::admitted_registry_bindings(),
                    )
                    .map_err(|error| format!("the new declaration does not validate: {error}"))?;
                crate::projection::admit_brain_policies(
                    &self.admission_config,
                    next,
                    candidate.objects(),
                    &active.objects,
                )
                .and_then(|()| admit(candidate.objects()))
                .map_err(|error| {
                    tracing::error!(
                        "authoring-policy-refused commit={} reason={error}",
                        candidate.commit()
                    );
                    format!("the new declaration cannot serve: {error}")
                })?;
                Ok((commit, candidate))
            })();
            let (commit, candidate) = match staged {
                Ok(staged) => staged,
                Err(error) => {
                    discard();
                    return Err(error);
                }
            };
            let Err(failure) = self.sync.push(&self.worktree, &commit, &origin) else {
                break candidate;
            };
            // A rejected push means another commit landed on `main`: the
            // change is staged again on the new tip, never forced over it.
            let current = self.sync.fetch(&self.worktree);
            if current.as_ref().is_ok_and(|current| {
                git(
                    &self.worktree,
                    &["merge-base", "--is-ancestor", &commit, current],
                )
                .is_ok()
            }) {
                break candidate;
            }
            let moved = current.is_ok_and(|current| current != origin);
            if !moved || attempt >= PUSH_ATTEMPTS {
                return Err(refused(failure));
            }
            tracing::warn!(
                "authoring-sync retry attempt={attempt} origin={origin} reason=main_moved"
            );
        };
        let result = store
            .publish_committed(&candidate, next)
            .map_err(|error| format!("registry publication failed: {error}"))?;
        let adopted = self
            .pin
            .reload()
            .map_err(|error| format!("published snapshot adoption failed: {error}"))?;
        request_reload_for(&active, &adopted);
        Ok((result.receipt.revision, result.receipt.commit))
    }

    /// Validate before writing any files.
    fn plan(
        &self,
        caller: &odin_domain::SeatId,
        request: &ProjectCreateRequest,
    ) -> Result<Plan, String> {
        let snapshot = self.pin.current();
        let object = |kind: RegistryKind, id: &str| {
            snapshot
                .objects
                .iter()
                .find(|object| object.kind() == kind && object.id == id)
        };
        let seat_of = |id: &str| match object(RegistryKind::Seat, id).map(|object| &object.config) {
            Some(ObjectConfig::Seat(seat)) => Some(seat.as_ref()),
            _ => None,
        };
        match seat_of(caller.as_str()) {
            Some(seat) if seat.conversation.is_some() => {}
            _ => return Err("only the owner-facing conversation seat creates projects".to_owned()),
        }
        let project = request.project.as_str();
        let valid_id = (2..=41).contains(&project.len())
            && project.starts_with(|c: char| c.is_ascii_lowercase())
            && project
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-');
        if !valid_id || project.parse::<odin_domain::ProjectId>().is_err() {
            return Err(format!("{project:?} is not a valid project id"));
        }
        // An existing project gains the requested worker seats (their
        // lanes and scope); nothing else about it changes.
        let existing = match object(RegistryKind::Project, project).map(|object| &object.config) {
            Some(ObjectConfig::Project(declared)) if declared.enabled => Some(declared.as_ref()),
            Some(_) => return Err(format!("the project {project} is disabled")),
            None => None,
        };
        let mut seats: Vec<&str> = Vec::new();
        for seat_id in &request.seats {
            if seats.contains(&seat_id.as_str()) {
                continue;
            }
            let seat = seat_of(seat_id).ok_or_else(|| format!("there is no seat {seat_id}"))?;
            let lane = format!("{seat_id}-{project}");
            if existing.is_some() && object(RegistryKind::Lane, &lane).is_some() {
                continue;
            }
            if !seat.enabled || seat.conversation.is_some() {
                return Err(format!("{seat_id} cannot be bound to a new project"));
            }
            let allowed = bindable_capabilities(&self.worktree, &self.sync)?;
            if let Some(capability) = seat
                .tool_refs
                .iter()
                .find(|capability| !allowed.iter().any(|held| held == capability.as_str()))
            {
                return Err(format!(
                    "{seat_id} holds {capability}, beyond what a new project's seats may hold"
                ));
            }
            if lane.parse::<odin_domain::LaneId>().is_err()
                || object(RegistryKind::Lane, &lane).is_some()
            {
                return Err(format!("the lane {lane} cannot be declared"));
            }
            seats.push(seat_id);
        }
        let Some(&first) = seats.first() else {
            return Err(match existing {
                Some(_) => format!("those seats already work on {project}"),
                None => "a project needs at least one seat".to_owned(),
            });
        };
        let quoted = |text: &str| toml::Value::String(text.to_owned()).to_string();
        let (root, source, mut files) = match existing {
            Some(declared) => (
                PathBuf::from(&declared.source_root),
                RootSource::Existing,
                Vec::new(),
            ),
            None => self.new_root(request, project, first, &quoted)?,
        };
        let mut lanes = Vec::new();
        for seat_id in &seats {
            let lane = format!("{seat_id}-{project}");
            files.push((
                format!("registry/lanes/{lane}/lane.toml"),
                format!(
                    "schema = \"odin.registry.v1\"\nkind = \"lane\"\nenabled = true\n\
                     description = {}\nproject = \"{project}\"\nfamily = \"engine\"\n\
                     default_seat = \"{seat_id}\"\nqueue = \"interactive\"\n\
                     requires_independent_review = false\n",
                    quoted(&format!("{seat_id} work on {project}")),
                ),
            ));
            lanes.push(lane);
        }
        Ok(Plan {
            project: project.to_owned(),
            root,
            source,
            files,
            seats: seats.iter().map(|seat| (*seat).to_owned()).collect(),
            lanes,
        })
    }

    /// A new project's root (an existing directory, a clone of Colin's
    /// repository, or a new one) and its declaration.
    fn new_root(
        &self,
        request: &ProjectCreateRequest,
        project: &str,
        first: &str,
        quoted: &dyn Fn(&str) -> String,
    ) -> Result<NewRoot, String> {
        let snapshot = self.pin.current();
        // The kind's served Atlas corpus, where one exists; seats remember
        // into their own memory.
        let (atlas, artifact_policy) = match request.kind.as_str() {
            "code" => (Some("atlas.code"), "standard"),
            "research" | "operations" => (None, "standard"),
            "personal" => (Some("atlas.personal"), "private"),
            "scientific" => (None, "large-scientific"),
            other => return Err(format!("unknown project kind {other:?}")),
        };
        let memory_namespaces = atlas
            .map(|namespace| format!("\"{namespace}\""))
            .unwrap_or_default();
        let projects_root = self
            .sync
            .repository
            .parent()
            .ok_or("the authoring repository has no parent directory")?
            .canonicalize()
            .map_err(|error| format!("the projects directory is unreadable: {error}"))?;
        let (root, create_root) = confined_root(&projects_root, request.root.as_deref(), project)?;
        let source = match (&request.repository, create_root) {
            (Some(_), false) => {
                return Err(format!(
                    "{} already exists; name either a repository or a root",
                    root.display()
                ))
            }
            (repository, true) => {
                let name = repository.as_deref().unwrap_or(project);
                let valid = !name.is_empty()
                    && name.len() <= 100
                    && !name.starts_with(['-', '.'])
                    && name
                        .chars()
                        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'));
                if !valid {
                    return Err(format!("{name:?} is not a repository name"));
                }
                let url = self.sync.sibling_remote(name)?;
                match (self.sync.remote_exists(&url)?, repository) {
                    (true, _) => RootSource::Clone(url),
                    (false, None) => RootSource::New,
                    (false, Some(_)) => return Err(format!("there is no repository {url}")),
                }
            }
            (None, false) => RootSource::Existing,
        };
        let taken = snapshot.objects.iter().any(|object| match &object.config {
            ObjectConfig::Project(existing) => Path::new(&existing.source_root) == root,
            _ => false,
        });
        if taken {
            return Err(format!(
                "{} is already another project's root",
                root.display()
            ));
        }
        let root_text = root
            .to_str()
            .ok_or("the project root is not valid UTF-8")?
            .to_owned();
        let files = vec![(
            format!("registry/projects/{project}/project.toml"),
            format!(
                "schema = \"odin.registry.v1\"\nkind = \"project\"\nenabled = true\n\
                 description = {}\nsource_root = {}\ndefault_seat = \"{first}\"\n\
                 memory_namespaces = [{memory_namespaces}]\nartifact_policy = \"{artifact_policy}\"\n",
                quoted(&request.description),
                quoted(&root_text),
            ),
        )];
        Ok((root, source, files))
    }
}

/// The project root: a directory directly inside the projects directory
/// (absent → created there), or an existing non-symlink directory inside it.
fn confined_root(
    projects_root: &Path,
    requested: Option<&str>,
    project: &str,
) -> Result<(PathBuf, bool), String> {
    let root = requested.map_or_else(|| projects_root.join(project), PathBuf::from);
    if !root.is_absolute()
        || root
            .components()
            .any(|component| matches!(component, Component::ParentDir | Component::CurDir))
    {
        return Err(format!("{} is not a plain absolute path", root.display()));
    }
    match std::fs::symlink_metadata(&root) {
        Ok(metadata) if metadata.is_dir() => {
            let canonical = root
                .canonicalize()
                .map_err(|error| format!("{}: {error}", root.display()))?;
            if canonical == projects_root || !canonical.starts_with(projects_root) {
                return Err(format!(
                    "{} is outside the projects directory {}",
                    root.display(),
                    projects_root.display()
                ));
            }
            Ok((canonical, false))
        }
        Ok(_) => Err(format!("{} is not a plain directory", root.display())),
        Err(_) if root.parent() == Some(projects_root) => Ok((root, true)),
        Err(_) => Err(format!(
            "a new project's root is created directly in {}",
            projects_root.display()
        )),
    }
}

/// `text` with `item` appended to the string array `key` (top-level, or in
/// `[table]`), keeping the file's layout; parsing proves the result differs
/// from `text` by exactly that item. An item already present is a no-op.
pub(crate) fn with_item_in_array(
    text: &str,
    table: Option<&str>,
    key: &str,
    item: &str,
) -> Result<String, String> {
    let parse = |text: &str| -> Result<toml::Table, String> {
        toml::from_str(text).map_err(|error| format!("declaration: {error}"))
    };
    fn array<'a>(
        document: &'a mut toml::Table,
        table: Option<&str>,
        key: &str,
    ) -> Option<&'a mut Vec<toml::Value>> {
        let scope = match table {
            Some(name) => document.get_mut(name)?.as_table_mut()?,
            None => document,
        };
        scope.get_mut(key)?.as_array_mut()
    }
    let mut expected = parse(text)?;
    let values =
        array(&mut expected, table, key).ok_or_else(|| format!("no {key} list to extend"))?;
    if values.iter().any(|value| value.as_str() == Some(item)) {
        return Ok(text.to_owned());
    }
    values.push(item.into());
    // The array's opening line inside the right table; its first `]` closes
    // it (these arrays hold plain identifiers).
    let mut offset = 0;
    let mut in_scope = table.is_none();
    let mut open = None;
    for line in text.split_inclusive('\n') {
        let trimmed = line.trim();
        if trimmed.starts_with('[') && !trimmed.contains('=') {
            in_scope = table.is_some_and(|name| trimmed == format!("[{name}]"));
        } else if in_scope && trimmed.starts_with(&format!("{key} = [")) {
            open = Some(offset + line.find('[').unwrap_or(0));
            break;
        }
        offset += line.len();
    }
    let open = open.ok_or_else(|| format!("{key} is not a plain list"))?;
    let close = open + text[open..].find(']').ok_or("unterminated list")?;
    let before = text[open + 1..close].trim_end();
    let insert = if before.is_empty() {
        format!("\"{item}\"")
    } else if before.ends_with(',') {
        format!(" \"{item}\",")
    } else {
        format!(", \"{item}\"")
    };
    let at = open + 1 + before.len();
    let edited = format!("{}{insert}{}", &text[..at], &text[at..]);
    if parse(&edited)? != expected {
        return Err(format!("{key} could not be extended in place"));
    }
    Ok(edited)
}

/// The inverse of [`with_item_in_array`]: one plain list loses `item`,
/// in place (a missing item leaves the text as it is).
fn without_item_in_array(
    text: &str,
    table: Option<&str>,
    key: &str,
    item: &str,
) -> Result<String, String> {
    let parse = |text: &str| -> Result<toml::Table, String> {
        toml::from_str(text).map_err(|error| format!("declaration: {error}"))
    };
    let mut expected = parse(text)?;
    let scope = match table {
        Some(name) => expected
            .get_mut(name)
            .and_then(toml::Value::as_table_mut)
            .ok_or_else(|| format!("no [{name}] table"))?,
        None => &mut expected,
    };
    let values = scope
        .get_mut(key)
        .and_then(toml::Value::as_array_mut)
        .ok_or_else(|| format!("no {key} list to shorten"))?;
    let before = values.len();
    values.retain(|value| value.as_str() != Some(item));
    if values.len() == before {
        return Ok(text.to_owned());
    }
    let mut offset = 0;
    let mut in_scope = table.is_none();
    let mut open = None;
    for line in text.split_inclusive('\n') {
        let trimmed = line.trim();
        if trimmed.starts_with('[') && !trimmed.contains('=') {
            in_scope = table.is_some_and(|name| trimmed == format!("[{name}]"));
        } else if in_scope && trimmed.starts_with(&format!("{key} = [")) {
            open = Some(offset + line.find('[').unwrap_or(0));
            break;
        }
        offset += line.len();
    }
    let open = open.ok_or_else(|| format!("{key} is not a plain list"))?;
    let close = open + text[open..].find(']').ok_or("unterminated list")?;
    let quoted = format!("\"{item}\"");
    let inner = &text[open + 1..close];
    let at = inner
        .find(&quoted)
        .ok_or_else(|| format!("{item} is not written plainly in {key}"))?;
    // Drop the item with its separator: a following comma, else a
    // preceding one; then the line it sat on when it is left empty.
    let mut start = open + 1 + at;
    let mut end = start + quoted.len();
    let rest = &text[end..close];
    if let Some(comma) = rest.find(',').filter(|i| rest[..*i].trim().is_empty()) {
        end += comma + 1;
        // The space that separated it from an item before it on its line.
        while start > open + 1 && matches!(text.as_bytes()[start - 1], b' ' | b'\t') {
            start -= 1;
        }
    } else if let Some(comma) = text[open + 1..start].rfind(',') {
        if text[open + 1 + comma + 1..start].trim().is_empty() {
            start = open + 1 + comma;
        }
    }
    let mut edited = format!("{}{}", &text[..start], &text[end..]);
    // An item on its own line leaves a blank line: remove it.
    if let Some(line_start) = edited[..start].rfind('\n') {
        let line_end = edited[start..].find('\n').map(|i| start + i);
        if let Some(line_end) = line_end {
            if edited[line_start + 1..line_end].trim().is_empty() {
                edited.replace_range(line_start + 1..line_end + 1, "");
            }
        }
    }
    if parse(&edited)? != expected {
        return Err(format!("{key} could not be shortened in place"));
    }
    Ok(edited)
}

pub(crate) fn deferred_delegations_file(state_root: &Path) -> PathBuf {
    state_root.join("deferred-delegations.jsonl")
}

/// After a restart, wakes the conversation once with every delegation the
/// pending reload deferred, so it delegates them now (the refusal promised
/// this wake). The record is removed only once the wake is queued.
pub(crate) fn wake_deferred_delegations(
    runtime: &odin_hermes::runtime::HermesRuntime,
    state_root: &Path,
) {
    let path = deferred_delegations_file(state_root);
    let text = match std::fs::read_to_string(&path) {
        Ok(text) => text,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return,
        Err(error) => {
            tracing::warn!(
                "deferred delegations {} unreadable: {error}",
                path.display()
            );
            return;
        }
    };
    let deferred: Vec<odin_omp::host_tools::delegation::DeferredDelegation> = text
        .lines()
        .filter(|line| !line.trim().is_empty())
        .filter_map(|line| match serde_json::from_str(line) {
            Ok(entry) => Some(entry),
            Err(error) => {
                tracing::warn!("deferred delegation skipped (unreadable): {error}");
                None
            }
        })
        .collect();
    if deferred.is_empty() {
        let _ = std::fs::remove_file(&path);
        return;
    }
    let list = deferred
        .iter()
        .map(|entry| {
            format!(
                "- asked by {} for {}{}: {}",
                entry.caller_seat,
                entry
                    .target_seat
                    .as_ref()
                    .map_or("a worker".to_owned(), ToString::to_string),
                entry
                    .title
                    .as_ref()
                    .map_or(String::new(), |title| format!(" (\"{title}\")")),
                entry.prompt.chars().take(1_500).collect::<String>()
            )
        })
        .collect::<Vec<_>>()
        .join("\n");
    let wake = format!(
        "Odin has restarted and activated what was just published. These delegations were \
         refused while it reloaded and nothing of them started; delegate each again now, as \
         asked:\n{list}"
    );
    let key = format!(
        "deferred-delegations-{}",
        &blake3::hash(text.as_bytes()).to_hex()[..16]
    );
    match runtime.wake_once(&key, &wake) {
        Ok(_) => {
            tracing::warn!("deferred delegations woken count={}", deferred.len());
            if let Err(error) = std::fs::remove_file(&path) {
                tracing::error!(
                    "deferred delegations {} not removed: {error}",
                    path.display()
                );
            }
        }
        Err(error) => tracing::warn!("deferred delegations not woken: {error}"),
    }
}

/// Once a publication changed composed state, odind restarts itself (a
/// graceful `systemctl --user restart`) after the requesting turn finished
/// and no live session is mid-turn; the conversation survives restarts.
pub(crate) fn arm_reload_pump(
    pumps: &mut tokio::task::JoinSet<Result<(), String>>,
    plane: Arc<odin_omp::live::service::OmpLiveService>,
    conversation_seats: std::collections::BTreeSet<odin_domain::SeatId>,
    observers: std::collections::BTreeSet<String>,
) {
    pumps.spawn(async move {
        let (mut quiet, mut held) = (0_u32, 0_u32);
        loop {
            tokio::time::sleep(Duration::from_secs(5)).await;
            if !RELOAD_REQUESTED.load(Ordering::Acquire) {
                quiet = 0;
                continue;
            }
            let (blocked, busy) = match open_sessions(&plane).await {
                Ok(sessions) => {
                    let blocker = reload_blocked(&sessions, &conversation_seats, &observers);
                    // Say what holds it, once a minute.
                    if let Some(session) = blocker.filter(|_| held % 12 == 0) {
                        tracing::warn!(
                            "reload held by session={} seat={} state={:?}",
                            session.session_id, session.seat_id, session.state
                        );
                    }
                    match blocker {
                        Some(session)
                            if reload_forced(session, &conversation_seats, u64::from(held) * 5) =>
                        {
                            if held % 12 == 0 {
                                tracing::warn!(
                                    "reload forced after {} s held by session={} seat={} state={:?}",
                                    u64::from(held) * 5,
                                    session.session_id,
                                    session.seat_id,
                                    session.state
                                );
                            }
                            (true, false)
                        }
                        blocker => (blocker.is_some(), blocker.is_some()),
                    }
                }
                Err(error) => {
                    tracing::warn!("reload held: {error}");
                    (false, true)
                }
            };
            let fire;
            (held, quiet, fire) = reload_step(held, quiet, blocked, busy);
            // 20 quiet seconds: the requesting turn's reply has been sent.
            if fire {
                tracing::info!("reloading to activate newly published projects");
                let systemctl = ["/run/current-system/sw/bin/systemctl", "systemctl"]
                    .into_iter()
                    .find(|candidate| !candidate.starts_with('/') || Path::new(candidate).exists())
                    .unwrap_or("systemctl");
                match std::process::Command::new(systemctl)
                    .args(["--user", "restart", "--no-block", "odind.service"])
                    .status()
                {
                    Ok(status) if restart_accepted(status) => {
                        RELOAD_REQUESTED.store(false, Ordering::Release)
                    }
                    other => tracing::error!("reload request failed: {other:?}"),
                }
                quiet = 0;
            }
        }
    });
}

/// Every open session, across all pages: the durable scan is ordered by
/// session id over ended rows too, so one page can miss live children.
async fn open_sessions(
    plane: &odin_omp::live::service::OmpLiveService,
) -> Result<Vec<odin_domain::huginn::LiveSessionSummary>, String> {
    let mut sessions = Vec::new();
    let mut cursor = None;
    loop {
        let page = plane
            .sessions(odin_domain::huginn::SessionListQuery {
                seat_id: None,
                include_ended: false,
                cursor,
                limit: std::num::NonZeroU16::new(256).expect("non-zero"),
            })
            .await
            .map_err(|error| format!("live session listing failed: {error}"))?;
        sessions.extend(page.sessions);
        match page.next_cursor {
            Some(next) => cursor = Some(next),
            None => return Ok(sessions),
        }
    }
}

/// Why a temporary seat retires now, if it does: its expiry passed, or its
/// work is done — at least one of its sessions ended and none is open.
/// Only the sessions this proposal's seat started since it was proposed:
/// a reused temporary name still lists the ended sessions of the earlier
/// helper, which are not this one's finished work.
pub(crate) fn since_proposal(
    sessions: Vec<odin_domain::huginn::LiveSessionSummary>,
    proposed_at: Option<i64>,
) -> Vec<odin_domain::huginn::LiveSessionSummary> {
    match proposed_at {
        Some(since) => sessions
            .into_iter()
            .filter(|session| session.started_at.unix_timestamp() >= since)
            .collect(),
        None => sessions,
    }
}

pub(crate) fn retire_reason(
    now_unix: i64,
    expires_unix: i64,
    ended: usize,
    open: usize,
) -> Option<&'static str> {
    if now_unix >= expires_unix {
        Some("ttl")
    } else if ended > 0 && open == 0 {
        Some("completed")
    } else {
        None
    }
}

/// How often the retire pass looks at the temporary seats.
const SEAT_RETIRE_TICK: Duration = Duration::from_secs(300);

/// How long past its expiry a temporary seat's retirement waits for an
/// idle moment before it goes ahead anyway.
const RETIRE_IDLE_WAIT_SECONDS: i64 = 60 * 60;

/// Whether a due retirement publishes now. Its publication recomposes
/// odind, and the pending reload defers every delegation while any worker
/// turn runs. Retirement is housekeeping: it joins a reload already pending, or waits for a tick
/// where no session would hold one, and goes ahead anyway once its expiry
/// is [`RETIRE_IDLE_WAIT_SECONDS`] past.
pub(crate) fn retire_now(
    reload_pending: bool,
    reload_held: bool,
    now_unix: i64,
    expires_unix: i64,
) -> bool {
    reload_pending || !reload_held || now_unix >= expires_unix + RETIRE_IDLE_WAIT_SECONDS
}

/// The retire pass for temporary seats (`seat.propose`):
/// every five minutes, each `[ephemeral]` seat whose expiry passed or whose
/// delegated work is done has its open sessions ended and its declarations
/// removed by the exact inverse of its proposal (a publication, so odind
/// reloads at idle) — at a moment the reload holds no one ([`retire_now`]).
pub(crate) fn arm_seat_retire_pump(
    pumps: &mut tokio::task::JoinSet<Result<(), String>>,
    plane: Arc<odin_omp::live::service::OmpLiveService>,
    runtime: Arc<odin_hermes::runtime::HermesRuntime>,
    conversation_seats: std::collections::BTreeSet<odin_domain::SeatId>,
    observers: std::collections::BTreeSet<String>,
) {
    pumps.spawn(async move {
        loop {
            tokio::time::sleep(SEAT_RETIRE_TICK).await;
            let Some(route) = runtime.project_route() else {
                continue;
            };
            let seats = {
                let route = Arc::clone(&route);
                match tokio::task::spawn_blocking(move || route.ephemeral_proposals()).await {
                    Ok(seats) => seats,
                    Err(error) => {
                        tracing::error!("seat-retire scan failed: {error}");
                        continue;
                    }
                }
            };
            for (seat, expires, proposed_at) in seats {
                let Ok(seat_id) = seat.parse::<odin_domain::SeatId>() else {
                    continue;
                };
                let sessions = match seat_sessions(&plane, &seat_id).await {
                    Ok(sessions) => sessions,
                    Err(error) => {
                        tracing::error!("seat-retire seat={seat} sessions unreadable: {error}");
                        continue;
                    }
                };
                use odin_domain::huginn::LiveSessionState;
                let sessions = since_proposal(sessions, proposed_at);
                let open: Vec<_> = sessions
                    .iter()
                    .filter(|session| {
                        !matches!(
                            session.state,
                            LiveSessionState::Ended
                                | LiveSessionState::Failed
                                | LiveSessionState::Detached
                        )
                    })
                    .map(|session| session.session_id)
                    .collect();
                let ended = sessions
                    .iter()
                    .filter(|session| session.state == LiveSessionState::Ended)
                    .count();
                let now = time::OffsetDateTime::now_utc().unix_timestamp();
                let Some(reason) = retire_reason(now, expires, ended, open.len()) else {
                    continue;
                };
                let others = match open_sessions(&plane).await {
                    Ok(sessions) => sessions
                        .into_iter()
                        .filter(|session| session.seat_id != seat_id)
                        .collect::<Vec<_>>(),
                    Err(error) => {
                        tracing::error!("seat-retire seat={seat} sessions unreadable: {error}");
                        continue;
                    }
                };
                let blocker = reload_blocked(&others, &conversation_seats, &observers);
                if !retire_now(reload_requested(), blocker.is_some(), now, expires) {
                    if let Some(session) = blocker {
                        tracing::warn!(
                            "seat-retire seat={seat} reason={reason} waits for idle \
                             held_by_session={} held_by_seat={} state={:?}",
                            session.session_id,
                            session.seat_id,
                            session.state
                        );
                    }
                    continue;
                }
                for session in open {
                    let ended = match plane.supervisor().actor(session).await {
                        Ok(actor) => actor.end().await.map_err(|error| error.to_string()),
                        Err(error) => Err(error.to_string()),
                    };
                    if let Err(error) = ended {
                        tracing::error!(
                            "seat-retire seat={seat} session={session} not ended: {error}"
                        );
                    }
                }
                let retire = {
                    let (route, seat) = (Arc::clone(&route), seat.clone());
                    tokio::task::spawn_blocking(move || route.retire_seat(&seat, reason)).await
                };
                match retire {
                    Ok(Ok((revision, commit))) => tracing::info!(
                        "seat-retire seat={seat} reason={reason} revision={revision} \
                         commit={commit}"
                    ),
                    Ok(Err(error)) => {
                        tracing::error!("seat-retire seat={seat} reason={reason} failed: {error}")
                    }
                    Err(error) => tracing::error!("seat-retire seat={seat} panicked: {error}"),
                }
            }
        }
    });
}

/// Every session of one seat, ended ones included.
async fn seat_sessions(
    plane: &odin_omp::live::service::OmpLiveService,
    seat: &odin_domain::SeatId,
) -> Result<Vec<odin_domain::huginn::LiveSessionSummary>, String> {
    let mut sessions = Vec::new();
    let mut cursor = None;
    loop {
        let page = plane
            .sessions(odin_domain::huginn::SessionListQuery {
                seat_id: Some(seat.clone()),
                include_ended: true,
                cursor,
                limit: std::num::NonZeroU16::new(256).expect("non-zero"),
            })
            .await
            .map_err(|error| format!("live session listing failed: {error}"))?;
        sessions.extend(page.sessions);
        match page.next_cursor {
            Some(next) => cursor = Some(next),
            None => return Ok(sessions),
        }
    }
}

/// The session an idle reload must wait for, if any: a session mid-turn, or
/// an idle delegated child with a live process (a restart would end it, and
/// a child without a process can no longer be steered). A session without a
/// process lists Detached and never holds it.
fn reload_blocked<'a>(
    sessions: &'a [odin_domain::huginn::LiveSessionSummary],
    conversation_seats: &std::collections::BTreeSet<odin_domain::SeatId>,
    observers: &std::collections::BTreeSet<String>,
) -> Option<&'a odin_domain::huginn::LiveSessionSummary> {
    use odin_domain::huginn::LiveSessionState;
    let observed = |session: &odin_domain::huginn::LiveSessionSummary| {
        session
            .title
            .as_ref()
            .is_some_and(|title| observers.contains(title))
    };
    sessions
        .iter()
        .filter(|session| !observed(session))
        .find(|session| match session.state {
            LiveSessionState::Starting
            | LiveSessionState::Running
            | LiveSessionState::RequiresAction
            | LiveSessionState::Aborting => true,
            LiveSessionState::Idle => !conversation_seats.contains(&session.seat_id),
            LiveSessionState::Detached | LiveSessionState::Ended | LiveSessionState::Failed => {
                false
            }
        })
}

/// Whether a reload held this long by `blocker` goes ahead anyway: any worker
/// session, in a turn or an idle child its owner never stopped, is cut after
/// the limit. The conversation's own turn always holds it.
fn reload_forced(
    blocker: &odin_domain::huginn::LiveSessionSummary,
    conversation_seats: &std::collections::BTreeSet<odin_domain::SeatId>,
    held_seconds: u64,
) -> bool {
    !conversation_seats.contains(&blocker.seat_id) && held_seconds >= RELOAD_HOLD_LIMIT_SECONDS
}

/// How long a worker may hold a pending reload.
const RELOAD_HOLD_LIMIT_SECONDS: u64 = 20 * 60;

/// One reload-pump tick: `blocked` — a live session would hold the reload;
/// `busy` — it still does (not forced past the hold limit). The hold clock
/// runs while any session blocks, forced or not, so a forced tick stays
/// forced. Returns (held, quiet, fire).
pub(crate) fn reload_step(held: u32, quiet: u32, blocked: bool, busy: bool) -> (u32, u32, bool) {
    let held = if blocked { held.saturating_add(1) } else { 0 };
    let quiet = if busy { 0 } else { quiet.saturating_add(1) };
    (held, quiet, quiet >= 4)
}

/// `systemctl restart --no-block` returns at once; when the restart wins the
/// race it stops this daemon's cgroup and kills the client by SIGTERM, which
/// still means the job was queued.
fn restart_accepted(status: std::process::ExitStatus) -> bool {
    use std::os::unix::process::ExitStatusExt;
    status.success() || status.signal() == Some(15)
}

#[path = "seat_authoring.rs"]
mod seat_authoring;

#[cfg(test)]
#[path = "tests/project_authoring.rs"]
mod tests;
