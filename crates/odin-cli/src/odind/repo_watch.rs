//! Repository pushes as routine events: while a routine
//! follows `repo_push`, each declared project repository's remote heads are
//! read every few minutes (`git ls-remote --heads origin`, the same SSH
//! identity seat branches are pushed with) and every branch that appeared or
//! moved since the baseline taken when that routine was published is one event.

use std::time::Duration as StdDuration;

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{File, OpenOptions};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use odin_cli::live_authority::SessionAuthorityPool;
use odin_registry::schema::RoutineEvent;
use serde::{Deserialize, Serialize};

use crate::coding_route::{GitRunner, Lifecycle};

const REPO_WATCH_TICK: StdDuration = StdDuration::from_secs(300);

/// Finish a full pass well before the next tick.
const REPO_WATCH_PASS: StdDuration = StdDuration::from_secs(120);

/// Pump cancellation stops the current read and prevents subsequent reads.
struct CancelOnDrop(Arc<AtomicBool>);

impl Drop for CancelOnDrop {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Release);
    }
}

/// Branch → commit, per project.
type Heads = BTreeMap<String, BTreeMap<String, String>>;

/// Heads recorded for the routines that were published when the file was written.
/// An older shape is not read: the file is a cache and is rewritten.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct HeadsFile {
    routines: BTreeSet<String>,
    heads: Heads,
}

/// The `refs/heads/*` of one `git ls-remote --heads` listing.
fn parse_heads(listing: &str) -> BTreeMap<String, String> {
    listing
        .lines()
        .filter_map(|line| {
            let (commit, reference) = line.split_once('\t')?;
            let branch = reference.trim().strip_prefix("refs/heads/")?;
            Some((branch.to_owned(), commit.trim().to_owned()))
        })
        .collect()
}

/// The branches of `now` that are new or moved against `before`.
fn moved<'a>(
    before: &BTreeMap<String, String>,
    now: &'a BTreeMap<String, String>,
) -> Vec<(&'a str, &'a str)> {
    now.iter()
        .filter(|(branch, commit)| before.get(*branch) != Some(*commit))
        .map(|(branch, commit)| (branch.as_str(), commit.as_str()))
        .collect()
}

/// `None` when the cache is missing, unreadable, or not this shape. A missing
/// file is the first baseline; anything else is discarded and said so.
fn load(path: &Path) -> Option<HeadsFile> {
    let bytes = match std::fs::read(path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return None,
        Err(error) => {
            tracing::error!(
                "repo-watch heads discarded path={} reason=unreadable: {error}",
                path.display()
            );
            return None;
        }
    };
    match serde_json::from_slice(&bytes) {
        Ok(file) => Some(file),
        Err(error) => {
            tracing::error!(
                "repo-watch heads discarded path={} reason=invalid: {error}",
                path.display()
            );
            None
        }
    }
}

fn store(path: &Path, file: &HeadsFile) -> Result<(), String> {
    let bytes = serde_json::to_vec_pretty(file).map_err(|error| error.to_string())?;
    let staged = path.with_extension("json.odin-tmp");
    std::fs::write(&staged, bytes)
        .and_then(|()| std::fs::rename(&staged, path))
        .map_err(|error| format!("{}: {error}", path.display()))
}

/// Held across a heads-file read-modify-write, and across publication of a
/// `repo_push` routine, so a poll cannot rewrite the baseline underneath it.
pub(crate) struct HeadsLock {
    _file: File,
}

pub(crate) fn lock_heads(state: &Path) -> Result<HeadsLock, String> {
    let parent = state.parent().ok_or("repo-heads has no parent directory")?;
    std::fs::create_dir_all(parent)
        .map_err(|error| format!("repo-heads lock directory: {error}"))?;
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(state.with_extension("json.lock"))
        .map_err(|error| format!("repo-heads lock: {error}"))?;
    file.lock()
        .map_err(|error| format!("repo-heads lock: {error}"))?;
    Ok(HeadsLock { _file: file })
}

/// Records `fresh` only for projects that have no stored heads. A failed read
/// certifies nothing: the routine stays out of the covered set and the file
/// is left unchanged.
fn certify_baseline(
    file: &mut HeadsFile,
    routine: &str,
    fresh: &BTreeMap<String, BTreeMap<String, String>>,
    failed: &[String],
) -> Result<(), String> {
    if !failed.is_empty() {
        return Err(format!(
            "repository baseline unreadable: {}",
            failed.join(", ")
        ));
    }
    for (project, heads) in fresh {
        file.heads
            .entry(project.clone())
            .or_insert_with(|| heads.clone());
    }
    file.routines.insert(routine.to_owned());
    Ok(())
}

/// Enabled `repo_push` routines of this runtime's conversation seat.
fn repo_push_routines(runtime: &odin_hermes::runtime::HermesRuntime) -> BTreeSet<String> {
    let Some(pin) = runtime.registry_pin() else {
        return BTreeSet::new();
    };
    let Some(seat) = runtime
        .settings()
        .discord
        .as_ref()
        .map(|discord| &discord.seat)
    else {
        return BTreeSet::new();
    };
    pin.current()
        .objects
        .iter()
        .filter_map(|object| match &object.config {
            odin_registry::ObjectConfig::Routine(routine)
                if routine.enabled
                    && &routine.seat == seat
                    && routine.trigger.event == Some(RoutineEvent::RepoPush) =>
            {
                Some(object.id.clone())
            }
            _ => None,
        })
        .collect()
}

/// Startup roots, plus every enabled project the live registry roots at an
/// absolute path. Empty `source_root` projects stay on the startup map.
fn watched_projects(
    startup: &BTreeMap<String, PathBuf>,
    runtime: &odin_hermes::runtime::HermesRuntime,
) -> BTreeMap<String, PathBuf> {
    let mut projects = startup.clone();
    let Some(pin) = runtime.registry_pin() else {
        return projects;
    };
    for object in pin.current().objects.iter() {
        let odin_registry::ObjectConfig::Project(project) = &object.config else {
            continue;
        };
        let root = PathBuf::from(&project.source_root);
        if project.enabled && root.is_absolute() && has_origin(&root) {
            projects.insert(object.id.clone(), root);
        }
    }
    projects
}

/// Local-only projects have no remote to watch.
fn has_origin(root: &Path) -> bool {
    std::fs::read_to_string(root.join(".git/config"))
        .is_ok_and(|config| config.contains("[remote \"origin\"]"))
}

/// The remote heads of `root`'s `origin`, read by `runner`.
fn remote_heads(runner: &dyn GitRunner, root: &Path) -> Result<String, String> {
    runner.git_remote(root, &["ls-remote", "--heads", "origin"])
}

/// One pass. A cache that does not already cover every current `repo_push`
/// routine is a baseline: heads are recorded and nothing fires. Later passes
/// fire only branches that moved against that baseline.
fn pass(
    runtime: &odin_hermes::runtime::HermesRuntime,
    startup: &BTreeMap<String, PathBuf>,
    state: &Path,
    pool: &SessionAuthorityPool,
    cancel: &AtomicBool,
) -> Result<(), String> {
    let _lock = lock_heads(state)?;
    let runner = Lifecycle::new(Some(pool), cancel, REPO_WATCH_PASS);
    let mut projects = watched_projects(startup, runtime);
    projects.retain(|_, root| has_origin(root));
    let routines = repo_push_routines(runtime);
    let stored = load(state);
    let baseline = stored
        .as_ref()
        .is_none_or(|file| !routines.is_subset(&file.routines));
    let mut heads = stored.map(|file| file.heads).unwrap_or_default();
    let mut failed = Vec::new();
    for (project, root) in &projects {
        if !root.join(".git").exists() {
            continue;
        }
        if baseline && heads.contains_key(project) {
            continue;
        }
        let listing = match remote_heads(&runner, root) {
            Ok(listing) => listing,
            Err(error) => {
                tracing::error!("repo watch project={project} unreadable: {error}");
                if baseline {
                    failed.push(project.clone());
                }
                continue;
            }
        };
        let now = parse_heads(&listing);
        if let Some(before) = (!baseline).then(|| heads.get(project)).flatten() {
            let at =
                i64::try_from(time::OffsetDateTime::now_utc().unix_timestamp_nanos() / 1_000_000)
                    .unwrap_or(i64::MAX);
            for (branch, commit) in moved(before, &now) {
                let short: String = commit.chars().take(8).collect();
                let detail = format!("project {project}: branch {branch} was pushed (now {short})");
                tracing::info!("repo push project={project} branch={branch} commit={short}");
                if let Err(error) = runtime.routine_event(
                    RoutineEvent::RepoPush,
                    Some(project),
                    &format!("push:{project}:{branch}:{commit}"),
                    &detail,
                    at,
                ) {
                    tracing::error!("repo push routine event not queued: {error}");
                }
            }
        }
        heads.insert(project.clone(), now);
    }
    if !failed.is_empty() {
        return Err(format!(
            "repository baseline unreadable: {}",
            failed.join(", ")
        ));
    }
    if cancel.load(Ordering::Acquire) || pool.is_closed() {
        return Err("the watch stopped during its pass; its heads are not recorded".to_owned());
    }
    if baseline {
        tracing::info!(
            "repo-watch baseline routines={}",
            routines
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>()
                .join(",")
        );
    }
    store(state, &HeadsFile { routines, heads })
}
/// Stored heads are a continuing observation only while one of the routines
/// they cover is still an enabled `repo_push` routine. The routine being
/// published is not in the pin yet, and an enabled `repo_push` routine that
/// this file does not name does not count.
fn observation_continuing(file: &HeadsFile, pin: &odin_registry::Snapshot) -> bool {
    file.routines.iter().any(|id| {
        let Some(object) = pin.object(odin_registry::RegistryKind::Routine, id) else {
            return false;
        };
        let odin_registry::ObjectConfig::Routine(routine) = &object.config else {
            return false;
        };
        routine.enabled && routine.trigger.event == Some(RoutineEvent::RepoPush)
    })
}

/// Records a baseline for `routine` without firing. The caller holds `lock`
/// across the following pin publication, so a poll cannot see the routine
/// before this file does. Stored heads stay only while a published
/// `repo_push` routine remains enabled. After the last one is gone, origin
/// is read again and a failed read certifies nothing.
pub(crate) fn baseline_published(
    config: &odin_huginn::OdindConfig,
    pin: &odin_registry::SnapshotHandle,
    routine: &str,
    _lock: &HeadsLock,
) -> Result<(), String> {
    let state = config.paths.state_root.join("repo-heads.json");
    let mut projects: BTreeMap<String, PathBuf> = config
        .projects
        .iter()
        .map(|(id, project)| (id.clone(), project.root.clone()))
        .collect();
    for object in pin.current().objects.iter() {
        let odin_registry::ObjectConfig::Project(project) = &object.config else {
            continue;
        };
        let root = PathBuf::from(&project.source_root);
        if project.enabled && root.is_absolute() && has_origin(&root) {
            projects.insert(object.id.clone(), root);
        }
    }
    let mut file = load(&state).unwrap_or_default();
    if !observation_continuing(&file, &pin.current()) {
        file.heads.clear();
    }
    let mut fresh = BTreeMap::new();
    let mut failed = Vec::new();
    for (project, root) in &projects {
        if !root.join(".git").exists() || !has_origin(root) || file.heads.contains_key(project) {
            continue;
        }
        match list_remote(root) {
            Ok(listing) => {
                fresh.insert(project.clone(), parse_heads(&listing));
            }
            Err(error) => {
                tracing::error!("repo-watch baseline project={project} unreadable: {error}");
                failed.push(project.clone());
            }
        }
    }
    certify_baseline(&mut file, routine, &fresh, &failed)?;
    store(&state, &file)?;
    tracing::info!("repo-watch baseline routine={routine}");
    Ok(())
}

fn list_remote(root: &Path) -> Result<String, String> {
    odin_omp::live::capsules::bounded_git_in(
        root,
        &["ls-remote", "--heads", "origin"],
        StdDuration::from_secs(30),
    )
}

/// Read only while a routine follows repo_push; the pool tracks each read's lifecycle.
pub(super) fn arm_repo_watch(
    pumps: &mut tokio::task::JoinSet<Result<(), String>>,
    runtime: Arc<odin_hermes::runtime::HermesRuntime>,
    projects: BTreeMap<String, PathBuf>,
    state_root: PathBuf,
    pool: Arc<SessionAuthorityPool>,
) {
    pumps.spawn(async move {
        let cancel = Arc::new(AtomicBool::new(false));
        let _cancel = CancelOnDrop(Arc::clone(&cancel));
        let mut ticker = tokio::time::interval(REPO_WATCH_TICK);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let state = state_root.join("repo-heads.json");
        loop {
            ticker.tick().await;
            if !runtime.follows(RoutineEvent::RepoPush) {
                continue;
            }
            let (runtime, projects, state, pool, cancel) = (
                Arc::clone(&runtime),
                projects.clone(),
                state.clone(),
                Arc::clone(&pool),
                Arc::clone(&cancel),
            );
            let read = move || pass(&runtime, &projects, &state, &pool, &cancel);
            match tokio::task::spawn_blocking(read).await {
                Ok(Ok(())) => {}
                Ok(Err(error)) => tracing::error!("repo watch state not recorded: {error}"),
                Err(error) => tracing::error!("repo watch pass failed: {error}"),
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use std::time::Duration as StdDuration;

    use super::*;
    use crate::test_fixture::{LifecyclePool, SilentRemote};
    use odin_process::test_support::RegisteredWorkerFixture;

    /// A project whose `origin` is `remote`, and the lifecycle pool that owns
    /// the watch's reads on private registered workers.
    fn watched(remote: &SilentRemote) -> (tempfile::TempDir, PathBuf, LifecyclePool) {
        let fixture = tempfile::tempdir().expect("fixture");
        let project = fixture.path().join("project");
        std::fs::create_dir(&project).expect("project");
        crate::test_support::git(&project, &["init", "-q"]);
        crate::test_support::git(&project, &["remote", "add", "origin", &remote.url()]);
        let owner = LifecyclePool::new(
            &fixture.path().join("state"),
            RegisteredWorkerFixture::new().expect("private registered workers"),
        );
        (fixture, project, owner)
    }

    /// A watch read whose origin never answers ends by its lifecycle
    /// deadline, and its Git is gone: the connection it opened is closed.
    #[test]
    fn a_silent_origin_read_ends_by_its_deadline_and_its_git_is_gone() {
        let remote = SilentRemote::start();
        let (_fixture, project, owner) = watched(&remote);
        let cancel = AtomicBool::new(false);
        let runner = Lifecycle::new(Some(&*owner.pool), &cancel, StdDuration::from_secs(2));
        let started = std::time::Instant::now();
        let read = remote_heads(&runner, &project);
        let elapsed = started.elapsed();
        assert!(read.is_err(), "a silent origin lists no heads: {read:?}");
        assert!(remote.connections() >= 1, "the read reached the origin");
        assert!(
            remote.all_closed_within(StdDuration::from_secs(10)),
            "the expired read's Git is gone"
        );
        assert!(
            elapsed < StdDuration::from_secs(15),
            "the read outlived its deadline and proved stop: {elapsed:?}"
        );
    }

    /// The pump's abort (its drop at the daemon's stop) cancels the watch:
    /// the read in flight is stopped — its connection closes — and the
    /// watch launches no further read.
    #[test]
    fn a_dropped_watch_stops_its_read_and_reads_no_further() {
        let remote = SilentRemote::start();
        let (_fixture, project, owner) = watched(&remote);
        let cancel = Arc::new(AtomicBool::new(false));
        let pump = CancelOnDrop(Arc::clone(&cancel));
        let read = std::thread::scope(|scope| {
            let reading = scope.spawn(|| {
                let runner = Lifecycle::new(Some(&*owner.pool), &cancel, REPO_WATCH_PASS);
                remote_heads(&runner, &project)
            });
            let reached = remote.reached(1, StdDuration::from_secs(60));
            drop(pump);
            (reached, reading.join().expect("the read thread"))
        });
        assert!(read.0, "the read reached the origin");
        assert!(read.1.is_err(), "a cancelled read lists no heads");
        assert!(
            remote.all_closed_within(StdDuration::from_secs(10)),
            "the cancelled read's Git is gone"
        );
        let runner = Lifecycle::new(Some(&*owner.pool), &cancel, REPO_WATCH_PASS);
        assert!(remote_heads(&runner, &project).is_err());
        assert_eq!(remote.connections(), 1, "nothing read after the cancel");
    }

    /// A push is a branch that appeared or moved; an untouched branch and a
    /// deleted one are not pushes, and only refs/heads count.
    #[test]
    fn a_push_is_a_branch_that_appeared_or_moved() {
        let before =
            parse_heads("aaa\trefs/heads/main\nbbb\trefs/heads/dev\nccc\trefs/heads/old\n");
        let now = parse_heads(
            "aaa\trefs/heads/main\nddd\trefs/heads/dev\neee\trefs/heads/seat/gungnir/x\n\
             fff\trefs/tags/v1\n",
        );
        assert_eq!(
            moved(&before, &now),
            vec![("dev", "ddd"), ("seat/gungnir/x", "eee")]
        );
    }
    #[test]
    fn an_old_heads_file_is_discarded_and_a_missing_routine_is_a_baseline() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("repo-heads.json");
        std::fs::write(&path, r#"{"odin":{"main":"abc"}}"#).unwrap();
        assert!(load(&path).is_none(), "the old map is not a baseline");
        let stored = HeadsFile {
            routines: ["morning".to_owned()].into(),
            heads: Heads::new(),
        };
        store(&path, &stored).unwrap();
        let loaded = load(&path).unwrap();
        let current: BTreeSet<String> = ["morning".into(), "pushes".into()].into();
        assert!(
            !current.is_subset(&loaded.routines),
            "a routine published after the file is a new baseline"
        );
        assert!(BTreeSet::from(["morning".to_owned()]).is_subset(&loaded.routines));
    }
    #[test]
    fn a_new_routine_keeps_stored_heads_and_a_failed_read_certifies_nothing() {
        let mut file = HeadsFile {
            routines: ["morning".to_owned()].into(),
            heads: [(
                "surtr".to_owned(),
                [("main".to_owned(), "abc".to_owned())].into(),
            )]
            .into(),
        };
        let fresh = [(
            "surtr".to_owned(),
            [("main".to_owned(), "zzz".to_owned())].into(),
        )]
        .into();
        certify_baseline(&mut file, "pushes", &fresh, &["bagcore".to_owned()]).unwrap_err();
        assert!(!file.routines.contains("pushes"));
        assert_eq!(file.heads["surtr"]["main"], "abc");
        let fresh = [
            (
                "surtr".to_owned(),
                [("main".to_owned(), "zzz".to_owned())].into(),
            ),
            (
                "bagcore".to_owned(),
                [("main".to_owned(), "def".to_owned())].into(),
            ),
        ]
        .into();
        certify_baseline(&mut file, "pushes", &fresh, &[]).unwrap();
        assert!(file.routines.contains("pushes"));
        assert_eq!(file.heads["surtr"]["main"], "abc");
        assert_eq!(file.heads["bagcore"]["main"], "def");
    }

    fn push_routine(
        id: &str,
        enabled: bool,
        event: Option<odin_registry::schema::RoutineEvent>,
    ) -> odin_registry::RegistryObject {
        odin_registry::RegistryObject {
            id: id.to_owned(),
            relative_config: std::path::PathBuf::from(format!(
                "registry/routines/{id}/routine.toml"
            )),
            config: odin_registry::ObjectConfig::Routine(Box::new(
                odin_registry::schema::RoutineToml {
                    schema: "odin.registry.v1".into(),
                    kind: odin_registry::RegistryKind::Routine,
                    enabled,
                    description: "watch".into(),
                    seat: odin_domain::SeatId::new("seat").unwrap(),
                    trigger: odin_registry::schema::RoutineTriggerToml {
                        schedule: None,
                        event,
                        profile: None,
                        matches: None,
                        lead_minutes: None,
                        account: None,
                    },
                    action: odin_registry::schema::RoutineActionToml {
                        kind: odin_registry::schema::RoutineActionKind::Brief,
                        text: "watch".into(),
                    },
                },
            )),
        }
    }

    fn pin(objects: Vec<odin_registry::RegistryObject>) -> odin_registry::Snapshot {
        odin_registry::Snapshot::build(1, objects).unwrap()
    }

    #[test]
    fn a_restarted_observation_refreshes_cached_heads() {
        let cached = HeadsFile {
            routines: ["morning".to_owned()].into(),
            heads: [(
                "surtr".to_owned(),
                [("main".to_owned(), "abc".to_owned())].into(),
            )]
            .into(),
        };
        let fresh = [(
            "surtr".to_owned(),
            [("main".to_owned(), "zzz".to_owned())].into(),
        )]
        .into();
        let continuing = pin(vec![push_routine(
            "morning",
            true,
            Some(odin_registry::schema::RoutineEvent::RepoPush),
        )]);
        assert!(observation_continuing(&cached, &continuing));
        let mut kept = cached.clone();
        certify_baseline(&mut kept, "pushes", &fresh, &[]).unwrap();
        assert_eq!(kept.heads["surtr"]["main"], "abc");

        for stopped in [
            pin(vec![push_routine(
                "morning",
                false,
                Some(odin_registry::schema::RoutineEvent::RepoPush),
            )]),
            pin(vec![]),
            pin(vec![push_routine(
                "morning",
                true,
                Some(odin_registry::schema::RoutineEvent::WorkloadSucceeded),
            )]),
            pin(vec![push_routine(
                "evening",
                true,
                Some(odin_registry::schema::RoutineEvent::RepoPush),
            )]),
        ] {
            assert!(!observation_continuing(&cached, &stopped));
        }

        let fixture = crate::test_fixture::PublishedStore::new("laptop", true);
        let root = fixture.temporary.path();
        let project = root.join("project");
        std::fs::create_dir(&project).unwrap();
        crate::test_support::git(&project, &["init", "-q"]);
        crate::test_support::git(
            &project,
            &[
                "remote",
                "add",
                "origin",
                fixture.worktree.to_str().unwrap(),
            ],
        );
        std::fs::write(fixture.worktree.join("change"), "new head").unwrap();
        let head = crate::test_support::commit_all(&fixture.worktree, "Advance watched origin");
        let config = odin_huginn::OdindConfig::parse(&format!(
            "{}[projects.surtr]\nroot = '{}'\n",
            crate::test_fixture::fixture_config_text(root, &fixture.snapshot_path),
            project.display(),
        ))
        .unwrap();
        let published = odin_registry::SnapshotHandle::open(fixture.store()).unwrap();
        let state = config.paths.state_root.join("repo-heads.json");
        let lock = lock_heads(&state).unwrap();
        store(&state, &cached).unwrap();
        baseline_published(&config, &published, "pushes", &lock).unwrap();
        let restarted = load(&state).unwrap();
        assert_eq!(restarted.heads["surtr"]["main"], head);
        assert!(restarted.routines.contains("morning"));
        assert!(restarted.routines.contains("pushes"));

        crate::test_support::git(
            &project,
            &[
                "remote",
                "set-url",
                "origin",
                root.join("missing-origin").to_str().unwrap(),
            ],
        );
        store(&state, &cached).unwrap();
        assert!(baseline_published(&config, &published, "pushes", &lock).is_err());
        let failed = load(&state).unwrap();
        assert_eq!(failed.heads, cached.heads);
        assert!(!failed.routines.contains("pushes"));
    }
}
