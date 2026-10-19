//! The daemon-side state-source plumbing: the runtime [`TaskStateReader`]
//! adapter over the delegation links, the ledger and the read model, and the
//! rebuild pump that builds the state sources' brain generations.
//!
//! - [`OdindTaskStateReader`] hands the brain's `state.tasks` source one
//!   consistent [`TaskStateSnapshot`]: the link ledger and read-model versions
//!   are captured before and after the reads and the snapshot retries when
//!   either moved.
//! - [`arm_state_rebuild_pump`] subscribes every wired state head before the
//!   initial build, then rebuilds at most once per [`STATE_REBUILD_SPACING`]
//!   while heads move. It is the only builder of state generations; turns
//!   serve the newest one it sealed.
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::{Arc, Mutex};

use odin_brain::error::{BrainError, BrainResult};
use odin_brain::service::BrainService;

use odin_brain::source::state::tasks::{
    DelegationPhase as BrainDelegationPhase, DelegationTask, PendingBlocker, TaskStateReader,
    TaskStateSnapshot, WorkloadRun,
};
use odin_domain::{huginn::ObjectKind, SeatId};
use odin_huginn::read_model::{MaterializedReadModel, ReadModelError};
use odin_huginn::OdindConfig;
use odin_ledger::Ledger;
use odin_omp::host_tools::delegation::{
    DelegationLinkLedger, DelegationPhase as LinkDelegationPhase, PersistedLink,
};
use odin_registry::SnapshotHandle;
use tokio::sync::watch;

/// Bound contention rather than returning a snapshot spanning moving authorities.
const SNAPSHOT_FENCE_ATTEMPTS: usize = 8;

/// The runtime adapter behind `BrainSourceConfig::StateTasks`: reads the
/// daemon's real delegation links, the shared controller ledger, and the
/// materialized read model, and hands the brain one consistent snapshot.
pub(super) struct OdindTaskStateReader {
    ledger: Arc<Mutex<Ledger>>,
    links: DelegationLinkLedger,
    read_model: MaterializedReadModel,
}

impl OdindTaskStateReader {
    /// Binds the adapter to the daemon's own authorities. Every handle is
    /// shared: the factory, the serving surfaces, and this adapter observe
    /// the same links directory, the same SQLite ledger, and the same read
    /// model — never a forked copy.
    pub(super) fn new(
        ledger: Arc<Mutex<Ledger>>,
        links: DelegationLinkLedger,
        read_model: MaterializedReadModel,
    ) -> Self {
        Self {
            ledger,
            links,
            read_model,
        }
    }

    /// One fenced, internally consistent read of every task authority.
    fn consistent_snapshot(&self) -> BrainResult<TaskStateSnapshot> {
        for _ in 0..SNAPSHOT_FENCE_ATTEMPTS {
            let links_before = self
                .links
                .persist_version()
                .map_err(|error| task_unavailable("delegation-links", error))?;
            let persisted = self
                .links
                .all_rows()
                .map_err(|error| task_unavailable("delegation-links", error))?;
            let capture = self
                .read_model
                .capture_kinds(&[ObjectKind::Session])
                .map_err(read_model_error)?;
            let sessions = session_observations(&capture.objects);
            let runs = self.ledger_runs()?;
            if links_before
                == self
                    .links
                    .persist_version()
                    .map_err(|error| task_unavailable("delegation-links", error))?
                && capture.revision == self.read_model.revision().map_err(read_model_error)?
            {
                let delegations = persisted
                    .into_iter()
                    .map(|persisted| delegation_task(&persisted, &sessions))
                    .collect();
                return Ok(TaskStateSnapshot { delegations, runs });
            }
        }
        Err(task_unavailable(
            "task-state-fence",
            format!(
                "the task authorities kept moving across {SNAPSHOT_FENCE_ATTEMPTS} fenced \
                 reads; refusing to hand the brain a torn snapshot"
            ),
        ))
    }

    /// Reads runs, attribution, and pending approvals in one SQLite snapshot
    /// while holding the shared writer lock.
    fn ledger_runs(&self) -> BrainResult<Vec<WorkloadRun>> {
        let guard = self
            .ledger
            .lock()
            .map_err(|_| task_unavailable("controller-ledger", "lock poisoned"))?;
        let connection = guard
            .connection()
            .unchecked_transaction()
            .map_err(|error| task_unavailable("controller-ledger", error.to_string()))?;
        let mut runs = Vec::new();
        {
            let mut statement = connection
                .prepare(
                    "SELECT r.run_id, r.lane_id, l.seat_id, l.project_id, r.status, \
                            r.attempt_number, r.started_at, r.updated_at, r.ended_at \
                     FROM runs r JOIN lanes l ON l.lane_id = r.lane_id \
                     ORDER BY r.run_id ASC",
                )
                .and_then(|mut statement| {
                    let rows = statement
                        .query_map([], |row| {
                            Ok(WorkloadRun {
                                run_id: row.get(0)?,
                                lane_id: row.get(1)?,
                                seat: row.get::<_, Option<String>>(2)?,
                                project: row.get::<_, Option<String>>(3)?,
                                state: row.get(4)?,
                                attempt_number: row.get(5)?,
                                started_at: row.get(6)?,
                                updated_at: row.get(7)?,
                                ended_at: row.get(8)?,
                                blockers: Vec::new(),
                            })
                        })?
                        .collect::<Result<Vec<_>, _>>()?;
                    Ok(rows)
                })
                .map_err(|error| task_unavailable("controller-ledger", error.to_string()))?;
            runs.append(&mut statement);
        }
        {
            let mut blockers: HashMap<String, Vec<PendingBlocker>> = HashMap::new();
            let statement = connection
                .prepare(
                    "SELECT approval_id, target_id, capability_id, requested_at \
                     FROM approvals \
                     WHERE status = 'requested' AND target_kind = 'run' \
                     ORDER BY approval_id ASC",
                )
                .and_then(|mut statement| {
                    let rows = statement
                        .query_map([], |row| {
                            Ok((
                                row.get::<_, String>(0)?,
                                row.get::<_, String>(1)?,
                                row.get::<_, String>(2)?,
                                row.get::<_, String>(3)?,
                            ))
                        })?
                        .collect::<Result<Vec<_>, _>>()?;
                    Ok(rows)
                })
                .map_err(|error| task_unavailable("controller-ledger", error.to_string()))?;
            for (approval_id, target_id, capability_id, requested_at) in statement {
                blockers.entry(target_id).or_default().push(PendingBlocker {
                    approval_id,
                    capability_id,
                    requested_at,
                });
            }
            for run in &mut runs {
                if let Some(pending) = blockers.remove(&run.run_id) {
                    run.blockers = pending;
                }
            }
        }
        Ok(runs)
    }
}

impl TaskStateReader for OdindTaskStateReader {
    fn snapshot(&self) -> BrainResult<TaskStateSnapshot> {
        self.consistent_snapshot()
    }
}

fn delegation_task(
    persisted: &PersistedLink,
    sessions: &HashMap<String, String>,
) -> DelegationTask {
    let link = &persisted.link;
    DelegationTask {
        child: link.child.to_string(),
        parent: link.parent.to_string(),
        parent_seat: link.parent_seat.as_ref().map(|seat| seat.to_string()),
        parent_run: link.parent_run.to_string(),
        child_run: link.child_run.to_string(),
        project: link.project.to_string(),
        phase: match link.phase {
            LinkDelegationPhase::Provisioning => BrainDelegationPhase::Provisioning,
            LinkDelegationPhase::Running => BrainDelegationPhase::Running,
            LinkDelegationPhase::Ended => BrainDelegationPhase::Ended,
            LinkDelegationPhase::Failed => BrainDelegationPhase::Failed,
        },
        depth: link.depth,
        created_at_ms: link.created_at_ms,
        result_sequence: link.learning_result_sequence,
        child_state: sessions.get(&link.child.to_string()).cloned(),
        lanes: link.lanes().iter().map(ToString::to_string).collect(),
        stalls: link.stalls.clone(),
    }
}

/// The recorded state of every captured session, by session id.
fn session_observations(
    objects: &[odin_domain::huginn::ObjectSnapshot],
) -> HashMap<String, String> {
    objects
        .iter()
        .filter(|snapshot| snapshot.object.kind == ObjectKind::Session)
        .filter_map(|snapshot| {
            let state = snapshot.value.get("state")?.as_str()?;
            Some((snapshot.object.id.clone(), state.to_owned()))
        })
        .collect()
}

fn read_model_error(error: ReadModelError) -> BrainError {
    BrainError::Unavailable {
        component: "live-read-model",
        reason: error.to_string(),
    }
}

fn task_unavailable(component: &'static str, reason: impl Into<String>) -> BrainError {
    BrainError::Unavailable {
        component,
        reason: reason.into(),
    }
}

/// The head channels of every wired state source, subscribed by the
/// composer BEFORE the rebuild pump's initial generation, so an authority
/// that moves during the first build is already pending on its channel.
pub(super) struct StateRebuildHeads {
    registry: Option<watch::Receiver<u64>>,
    live: Option<watch::Receiver<u64>>,
    task_links: Option<watch::Receiver<u64>>,
    task_commits: Option<watch::Receiver<()>>,
    repos: Option<RepoHeads>,
}

/// Kernel filesystem notifications, not a repository polling interval.
pub(super) struct RepoHeads {
    watcher: notify::RecommendedWatcher,
    changed: watch::Receiver<Option<String>>,
    sources: Vec<odin_brain::source::state::repos::ReposSource>,
    watched: BTreeSet<std::path::PathBuf>,
}

impl RepoHeads {
    pub(super) fn from_sources(
        sources: &BTreeMap<odin_domain::knowledge::AtlasId, odin_brain::service::BrainSourceConfig>,
    ) -> Result<Option<Self>, String> {
        let sources: Vec<_> = sources
            .values()
            .filter_map(|source| match source {
                odin_brain::service::BrainSourceConfig::StateRepos { source } => {
                    Some(source.clone())
                }
                _ => None,
            })
            .collect();
        if sources.is_empty() {
            return Ok(None);
        }
        let (sender, changed) = watch::channel(None);
        let watcher = notify::recommended_watcher(move |event: notify::Result<notify::Event>| {
            match event {
                // Reads made by projection must not wake projection again.
                Ok(event) if !event.kind.is_access() => sender.send_modify(|_| {}),
                Ok(_) => {}
                Err(error) => sender.send_modify(|last| *last = Some(error.to_string())),
            }
        })
        .map_err(|error| format!("repository watcher: {error}"))?;
        let mut heads = Self {
            watcher,
            changed,
            sources,
            watched: BTreeSet::new(),
        };
        heads.refresh()?;
        Ok(Some(heads))
    }

    fn refresh(&mut self) -> Result<(), String> {
        use notify::Watcher;
        let mut paths = BTreeSet::new();
        for source in &self.sources {
            paths.extend(source.watch_paths().map_err(|error| error.to_string())?);
        }
        for path in paths.difference(&self.watched) {
            self.watcher
                .watch(path, notify::RecursiveMode::NonRecursive)
                .map_err(|error| format!("watch repository path {}: {error}", path.display()))?;
        }
        for path in self.watched.difference(&paths) {
            if let Err(error) = self.watcher.unwatch(path) {
                // The kernel removes watches for deleted directories itself.
                if path.exists() {
                    return Err(format!(
                        "unwatch repository path {}: {error}",
                        path.display()
                    ));
                }
            }
        }
        self.watched = paths;
        Ok(())
    }
}

/// Composes the rebuild pump's head subscriptions from the declared
/// `brain.sources` kinds: only the heads of actually wired state sources
/// are subscribed, and subscription happens at composition time — strictly
/// before the pump's initial generation. `Ok(None)` when no state source is
/// wired: the pump is state-source plumbing, not a general brain ticker.
pub(super) fn compose_state_heads(
    config: &OdindConfig,
    snapshot_handle: &Arc<SnapshotHandle>,
    read_model: &Arc<MaterializedReadModel>,
    links: &DelegationLinkLedger,
    bridge_ledger: &Arc<Mutex<Ledger>>,
    repos: Option<RepoHeads>,
) -> Result<Option<StateRebuildHeads>, String> {
    let Some(brain) = config.brain.as_ref() else {
        return Ok(None);
    };
    let kinds: BTreeSet<&str> = brain
        .sources
        .values()
        .map(|source| source.kind.as_str())
        .collect();
    let wired = |kind: &str| kinds.contains(kind);
    if !wired("state.registry")
        && !wired("state.live")
        && !wired("state.tasks")
        && !wired("state.repos")
        && !wired("ops.history")
    {
        return Ok(None);
    }
    let registry = wired("state.registry").then(|| snapshot_handle.subscribe());
    let live =
        if wired("state.live") || wired("state.tasks") {
            Some(read_model.subscribe_head().map_err(|error| {
                format!("could not subscribe the live read-model head: {error}")
            })?)
        } else {
            None
        };
    let task_links = wired("state.tasks").then(|| links.subscribe_persists());
    let task_commits = if wired("state.tasks") || wired("ops.history") {
        Some(
            bridge_ledger
                .lock()
                .map_err(|_| "controller ledger lock is poisoned".to_owned())?
                .subscribe_commits(),
        )
    } else {
        None
    };
    Ok(Some(StateRebuildHeads {
        registry,
        live,
        task_links,
        task_commits,
        repos,
    }))
}

/// The Atlas ids of the configured `state.*` sources: exactly the keys the
/// pump's seat filter and nothing else may authorize against.
pub(super) fn wired_state_source_ids(
    config: &OdindConfig,
) -> BTreeSet<odin_domain::knowledge::AtlasId> {
    config
        .brain
        .as_ref()
        .map(|brain| {
            brain
                .sources
                .iter()
                .filter(|(_, source)| {
                    source.kind.starts_with("state.") || source.kind == "ops.history"
                })
                .filter_map(|(key, _)| odin_domain::knowledge::AtlasId::new(key).ok())
                .collect()
        })
        .unwrap_or_default()
}

/// The served brain services whose published policy authorizes at least one
/// wired state source — the only services the rebuild pump refreshes.
pub(super) fn state_rebuild_seats(
    brains: &BTreeMap<SeatId, Arc<BrainService>>,
    wired_state_ids: &BTreeSet<odin_domain::knowledge::AtlasId>,
) -> BTreeMap<SeatId, Arc<BrainService>> {
    brains
        .iter()
        .filter(|(_, brain)| {
            brain
                .policy()
                .knowledge
                .as_ref()
                .map(|knowledge| {
                    knowledge
                        .atlas_sources
                        .iter()
                        .any(|id| wired_state_ids.contains(id))
                })
                .unwrap_or(false)
        })
        .map(|(seat, brain)| (seat.clone(), Arc::clone(brain)))
        .collect()
}

/// Rebuild on head changes. Closed head channels and task failures stop the pump;
/// per-seat rebuild errors retain the last generation and retry on the next change.
pub(super) fn arm_state_rebuild_pump(
    pumps: &mut tokio::task::JoinSet<Result<(), String>>,
    brains: BTreeMap<SeatId, Arc<BrainService>>,
    heads: StateRebuildHeads,
) {
    if brains.is_empty() {
        return;
    }
    pumps.spawn(state_rebuild_pump(brains, heads));
}

/// The rebuild pump body: initial generation first, then one rebuild per
/// coalesced head burst. `spawn_blocking` carries the synchronous brain
/// work so the async runtime never blocks on it.
async fn state_rebuild_pump(
    brains: BTreeMap<SeatId, Arc<BrainService>>,
    heads: StateRebuildHeads,
) -> Result<(), String> {
    state_rebuild_loop(heads, STATE_REBUILD_SPACING, || rebuild_once(&brains)).await
}

/// The least time between two state rebuilds: the live read model moves with
/// every streamed event, and each rebuild is a whole new generation.
const STATE_REBUILD_SPACING: std::time::Duration = if cfg!(test) {
    std::time::Duration::from_millis(50)
} else {
    std::time::Duration::from_secs(30)
};

async fn state_rebuild_loop<F, Fut>(
    mut heads: StateRebuildHeads,
    spacing: std::time::Duration,
    mut rebuild: F,
) -> Result<(), String>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<(), String>>,
{
    rebuild().await?;
    let mut last = tokio::time::Instant::now();
    loop {
        tokio::select! {
            changed = async { heads.registry.as_mut().expect("registry head").changed().await },
                if heads.registry.is_some() =>
            {
                head_wakeup(changed, "registry snapshot")?;
            }
            changed = async { heads.live.as_mut().expect("live head").changed().await },
                if heads.live.is_some() =>
            {
                head_wakeup(changed, "live read model")?;
            }
            changed = async { heads.task_links.as_mut().expect("task link head").changed().await },
                if heads.task_links.is_some() =>
            {
                head_wakeup(changed, "delegation link ledger")?;
            }
            changed = async { heads.task_commits.as_mut().expect("task commit head").changed().await },
                if heads.task_commits.is_some() =>
            {
                head_wakeup(changed, "controller ledger")?;
            }
            changed = async { heads.repos.as_mut().expect("repository heads").changed.changed().await },
                if heads.repos.is_some() =>
            {
                head_wakeup(changed, "repository filesystem")?;
                if let Some(error) = &*heads.repos.as_ref().expect("repository heads").changed.borrow() {
                    return Err(format!("repository filesystem watcher: {error}"));
                }
            }
            else => {
                return Err("every wired state head channel is closed".to_owned());
            }
        }
        // Spaced: every change arriving meanwhile coalesces into one rebuild.
        tokio::time::sleep_until(last + spacing).await;
        // Coalesce the burst: every channel with a pending change is drained
        // before one rebuild, so a fast-moving authority rebuilds the brain
        // once per burst, not once per event.
        if let Some(head) = &mut heads.registry {
            head.borrow_and_update();
        }
        if let Some(head) = &mut heads.live {
            head.borrow_and_update();
        }
        if let Some(head) = &mut heads.task_links {
            head.borrow_and_update();
        }
        if let Some(head) = &mut heads.task_commits {
            head.borrow_and_update();
        }
        if let Some(repos) = &mut heads.repos {
            repos.changed.borrow_and_update();
            // A root that vanished or lost its HEAD (a clone in progress,
            // a repository being replaced) degrades this round; the next
            // change retries.
            if let Err(error) = repos.refresh() {
                tracing::error!("repository watch refresh degraded: {error}");
            }
        }
        rebuild().await?;
        last = tokio::time::Instant::now();
    }
}

/// A closed authority channel is fatal rather than silently ending observation.
fn head_wakeup(
    changed: Result<(), tokio::sync::watch::error::RecvError>,
    name: &str,
) -> Result<(), String> {
    changed.map_err(|_| format!("the {name} head channel closed"))
}

/// One `ensure_state_generations` pass over the seats that serve a wired
/// state source; an unchanged head builds nothing.
async fn rebuild_once(brains: &BTreeMap<SeatId, Arc<BrainService>>) -> Result<(), String> {
    let brains = brains.clone();
    // A seat whose rebuild fails keeps serving its last generation; the
    // failure is logged and the next head change retries it.
    tokio::task::spawn_blocking(move || {
        for (seat, brain) in &brains {
            if let Err(error) = brain.ensure_state_generations() {
                tracing::error!("brain index rebuild for seat {seat} degraded: {error}");
            }
        }
        Ok(())
    })
    .await
    .map_err(|error| format!("brain index rebuild task failed: {error}"))?
}

#[cfg(test)]
mod tests {
    use super::*;
    use odin_brain::service::{BrainServiceConfig, BrainSourceConfig};
    use odin_brain::source::state::tasks::TasksSource;
    use odin_domain::knowledge::{AtlasId, RetrievalMode};
    use odin_registry::schema::{parse_object_toml, ObjectConfig, RegistryKind};

    /// A burst of head changes coalesces into at most one rebuild per spacing.
    #[tokio::test(start_paused = true)]
    async fn a_burst_of_state_changes_rebuilds_once_per_spacing() {
        let (live, receiver) = watch::channel(0_u64);
        let heads = StateRebuildHeads {
            registry: None,
            live: Some(receiver),
            task_links: None,
            task_commits: None,
            repos: None,
        };
        let rebuilds = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counted = Arc::clone(&rebuilds);
        let pump = tokio::spawn(state_rebuild_loop(
            heads,
            std::time::Duration::from_secs(30),
            move || {
                counted.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                async { Ok(()) }
            },
        ));
        // 100 changes over 10 s, then quiet past one spacing.
        for change in 1..=100_u64 {
            live.send(change).unwrap();
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
        tokio::time::sleep(std::time::Duration::from_secs(31)).await;
        let total = rebuilds.load(std::sync::atomic::Ordering::SeqCst);
        assert_eq!(
            total, 2,
            "the initial build plus one coalesced rebuild, not {total}"
        );
        pump.abort();
    }

    #[tokio::test]
    async fn repository_notifications_observe_tracked_edits_without_read_feedback() {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path();
        std::fs::create_dir_all(root.join("crates/demo/src")).unwrap();
        std::fs::write(root.join("crates/demo/src/lib.rs"), "pub fn before() {}\n").unwrap();
        for args in [
            vec!["init", "--quiet"],
            vec!["add", "."],
            vec![
                "-c",
                "user.name=Fixture",
                "-c",
                "user.email=fixture@example.invalid",
                "commit",
                "--quiet",
                "-m",
                "initial",
            ],
        ] {
            assert!(std::process::Command::new("git")
                .arg("-C")
                .arg(root)
                .args(args)
                .env("GIT_CONFIG_NOSYSTEM", "1")
                .env("GIT_CONFIG_GLOBAL", "/dev/null")
                .status()
                .unwrap()
                .success());
        }
        let id = AtlasId::new("state.repos").unwrap();
        let source = odin_brain::source::state::repos::ReposSource::new(
            id.clone(),
            BTreeMap::from([(
                odin_domain::ProjectId::new("demo").unwrap(),
                root.to_path_buf(),
            )]),
        )
        .unwrap();
        let sources = BTreeMap::from([(
            id,
            BrainSourceConfig::StateRepos {
                source: source.clone(),
            },
        )]);
        let mut heads = RepoHeads::from_sources(&sources).unwrap().unwrap();
        let before = source.pin().unwrap().0;
        assert!(
            tokio::time::timeout(
                std::time::Duration::from_millis(100),
                heads.changed.changed()
            )
            .await
            .is_err(),
            "read-only pinning must not wake a rebuild through Git index writes"
        );
        std::fs::write(root.join("crates/demo/src/lib.rs"), "pub fn after() {}\n").unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(5), heads.changed.changed())
            .await
            .unwrap()
            .unwrap();
        assert!(heads.changed.borrow_and_update().is_none());
        assert_ne!(source.pin().unwrap().0, before);
    }

    #[tokio::test]
    async fn task_commit_refreshes_scoped_retrieval_without_audit_feedback() {
        let directory = tempfile::tempdir().unwrap();
        let ledger = Arc::new(Mutex::new(Ledger::open_in_memory().unwrap()));
        ledger.lock().unwrap().connection().execute_batch(
            "INSERT INTO lanes(lane_id,seat_id,project_id,template_id,backend,created_by,created_at,updated_at)
             VALUES('lane-k1','sinmara','life','fixture','local_omp','fixture','2026-09-28T00:00:00Z','2026-09-28T00:00:00Z');
             INSERT INTO runs(run_id,lane_id,attempt_number,input_hash,created_at,updated_at,status)
             VALUES('task-k1','lane-k1',1,'fixture','2026-09-28T00:00:00Z','2026-09-28T00:00:00Z','running');"
        ).unwrap();
        let links = DelegationLinkLedger::open(directory.path().join("links")).unwrap();
        let read_model = MaterializedReadModel::new(16, time::OffsetDateTime::UNIX_EPOCH);
        let reader: Arc<dyn TaskStateReader> = Arc::new(OdindTaskStateReader::new(
            Arc::clone(&ledger),
            links,
            read_model,
        ));
        let id = AtlasId::new("state.tasks").unwrap();
        let source = TasksSource::new(id.clone(), reader);
        let first_head = source.pin().unwrap().0;
        let ObjectConfig::Seat(mut seat) = parse_object_toml(
            RegistryKind::Seat,
            "sinmara",
            "seats/sinmara/seat.toml",
            include_str!("../../../../registry/seats/sinmara/seat.toml"),
        )
        .unwrap()
        .config
        else {
            panic!("seat")
        };
        let ObjectConfig::Slice(mut slice) = parse_object_toml(
            RegistryKind::Slice,
            "sinmara-life",
            "slices/sinmara-life/slice.toml",
            include_str!("../../../../registry/slices/sinmara-life/slice.toml"),
        )
        .unwrap()
        .config
        else {
            panic!("slice")
        };
        seat.project_scope.clear();
        seat.brain_scope = [id.clone()].into();
        seat.knowledge.as_mut().unwrap().atlas_sources = [id.clone()].into();
        seat.context = None;
        slice.context = None;
        let knowledge = slice.knowledge.as_mut().unwrap();
        knowledge.atlas_sources = [id.clone()].into();
        knowledge.retrieval_mode = RetrievalMode::Lexical;
        knowledge.min_score_micros = 0;
        let policy = odin_brain::config::EffectiveBrainPolicy::resolve(
            1,
            &slice,
            &seat,
            &BTreeMap::new(),
            &std::collections::BTreeMap::new(),
            &odin_domain::knowledge::retrieval::ModelDescriptor {
                name: odin_domain::huginn::ids::ModelName::new("state-fixture").unwrap(),
                tokenizer: odin_brain::context::PinnedTokenizer::id().unwrap(),
                context_window_tokens: std::num::NonZeroU32::new(32768).unwrap(),
            },
        )
        .unwrap();
        let query = policy
            .knowledge
            .as_ref()
            .unwrap()
            .retrieval_query("task-k1 status".into())
            .unwrap();
        let brain = Arc::new(
            BrainService::open(
                BrainServiceConfig {
                    store_root: directory.path().join("brain"),
                    sources: BTreeMap::from([(
                        id.clone(),
                        BrainSourceConfig::StateTasks {
                            source: source.clone(),
                        },
                    )]),
                    embedding_available: false,
                    embedding_model: None,
                    archive_ingest_gate: None,
                    postgres: None,
                },
                policy,
                Arc::clone(&ledger),
            )
            .unwrap(),
        );
        let heads = StateRebuildHeads {
            registry: None,
            live: None,
            task_links: None,
            task_commits: Some(ledger.lock().unwrap().subscribe_commits()),
            repos: None,
        };
        let mut pumps = tokio::task::JoinSet::new();
        arm_state_rebuild_pump(
            &mut pumps,
            BTreeMap::from([(SeatId::new("sinmara").unwrap(), Arc::clone(&brain))]),
            heads,
        );
        wait_for_head(&brain, &id, first_head).await;
        let before = brain.retrieve(&query, None, None).unwrap();
        assert!(before
            .hits
            .iter()
            .any(|hit| hit.content.contains("status: running")
                && hit.content.contains("owner seat: sinmara")));
        assert_eq!(
            source.pin().unwrap().0,
            first_head,
            "index audit cannot dirty task authority"
        );
        ledger.lock().unwrap().connection().execute(
            "UPDATE runs SET status='completed', revision=revision+1, ended_at='2026-09-28T01:00:00Z', updated_at='2026-09-28T01:00:00Z' WHERE run_id='task-k1'",
            [],
        ).unwrap();
        let second_head = source.pin().unwrap().0;
        assert_ne!(first_head, second_head);
        wait_for_head(&brain, &id, second_head).await;
        let after = brain.retrieve(&query, None, None).unwrap();
        assert!(after
            .hits
            .iter()
            .any(|hit| hit.content.contains("status: completed")));
        assert!(after
            .hits
            .iter()
            .all(|hit| hit.citation.source_revision == second_head));
        let count: i64 = ledger
            .lock()
            .unwrap()
            .connection()
            .query_row(
                "SELECT COUNT(*) FROM audit_events WHERE kind='knowledge.index.rebuilt'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(
            count, 2,
            "exactly the initial build and changed-authority build"
        );
        println!(
            "task-k1 retrieved with brain://{}; commit event advanced head and no audit feedback",
            after.hits[0].item_id
        );
        pumps.abort_all();
        while pumps.join_next().await.is_some() {}
    }

    async fn wait_for_head(brain: &BrainService, source: &AtlasId, head: odin_domain::Digest) {
        tokio::time::timeout(std::time::Duration::from_secs(10), async {
            loop {
                if brain
                    .status()
                    .unwrap()
                    .generations
                    .get(source)
                    .is_some_and(|generation| generation.atlas_revision == head)
                {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("event pump publishes the changed head");
    }

    /// A vanished project root degrades the rebuild (logged); the seat keeps
    /// its generation and the daemon keeps running.
    #[tokio::test]
    async fn a_vanished_project_root_degrades_the_rebuild_instead_of_stopping() {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path().join("demo");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(root.join("lib.rs"), "pub fn demo() {}\n").unwrap();
        for args in [
            vec!["init", "--quiet"],
            vec!["add", "."],
            vec![
                "-c",
                "user.name=F",
                "-c",
                "user.email=f@example.invalid",
                "commit",
                "--quiet",
                "-m",
                "start",
            ],
        ] {
            assert!(std::process::Command::new("git")
                .arg("-C")
                .arg(&root)
                .args(args)
                .env("GIT_CONFIG_NOSYSTEM", "1")
                .env("GIT_CONFIG_GLOBAL", "/dev/null")
                .status()
                .unwrap()
                .success());
        }
        let ledger = Arc::new(Mutex::new(Ledger::open_in_memory().unwrap()));
        let id = AtlasId::new("state.repos").unwrap();
        let source = odin_brain::source::state::repos::ReposSource::new(
            id.clone(),
            BTreeMap::from([(odin_domain::ProjectId::new("demo").unwrap(), root.clone())]),
        )
        .unwrap();
        let ObjectConfig::Seat(mut seat) = parse_object_toml(
            RegistryKind::Seat,
            "gungnir",
            "seats/gungnir/seat.toml",
            include_str!("../../../../registry/seats/gungnir/seat.toml"),
        )
        .unwrap()
        .config
        else {
            panic!("seat")
        };
        let ObjectConfig::Slice(mut slice) = parse_object_toml(
            RegistryKind::Slice,
            "gungnir-build",
            "slices/gungnir-build/slice.toml",
            include_str!("../../../../registry/slices/gungnir-build/slice.toml"),
        )
        .unwrap()
        .config
        else {
            panic!("slice")
        };
        seat.project_scope.clear();
        seat.brain_scope = [id.clone()].into();
        seat.knowledge.as_mut().unwrap().atlas_sources = [id.clone()].into();
        seat.context = None;
        slice.context = None;
        let knowledge = slice.knowledge.as_mut().unwrap();
        knowledge.atlas_sources = [id.clone()].into();
        knowledge.retrieval_mode = RetrievalMode::Lexical;
        let policy = odin_brain::config::EffectiveBrainPolicy::resolve(
            1,
            &slice,
            &seat,
            &BTreeMap::new(),
            &std::collections::BTreeMap::new(),
            &odin_domain::knowledge::retrieval::ModelDescriptor {
                name: odin_domain::huginn::ids::ModelName::new("state-fixture").unwrap(),
                tokenizer: odin_brain::context::PinnedTokenizer::id().unwrap(),
                context_window_tokens: std::num::NonZeroU32::new(32768).unwrap(),
            },
        )
        .unwrap();
        let brain = Arc::new(
            BrainService::open(
                BrainServiceConfig {
                    store_root: directory.path().join("brain"),
                    sources: BTreeMap::from([(id, BrainSourceConfig::StateRepos { source })]),
                    embedding_available: false,
                    embedding_model: None,
                    archive_ingest_gate: None,
                    postgres: None,
                },
                policy,
                Arc::clone(&ledger),
            )
            .unwrap(),
        );
        let brains = BTreeMap::from([(SeatId::new("gungnir").unwrap(), brain)]);
        rebuild_once(&brains).await.expect("the first rebuild");
        std::fs::remove_dir_all(&root).unwrap();
        rebuild_once(&brains)
            .await
            .expect("a vanished root degrades, never stops the daemon");
    }
}
