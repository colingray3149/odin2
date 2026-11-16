//! The launch queue pump: a `kube.workload.create` that no node had room for, or a batch
//! item whose seat or lane cap was full, is held on disk (see `kube_runtime::LaunchQueue`).
//! Once an Odin Job has ended, or the backstop has passed, one pass runs held launches again
//! oldest first, lanes in turn, starting every one that fits, and tells the launching
//! session how that went: one line per single launch, one summary per batch.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::future::Future;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use odin_domain::huginn::KubeWorkloadState;
use odin_omp::host_tools::HostToolError;
use serde_json::Value;

use super::workload_watch::{launching_session, route_finding, Finding};
use crate::kube::KubeRuntimeCell;
use crate::kube_runtime::{KubeCommandCoordinator, LaunchQueue, QueuedLaunch};

const QUEUE_TICK: Duration = Duration::from_secs(15);
/// Fallbacks for the authority node card's `[launch_queue]`, used only when a key is absent.
const DEFAULT_SCAN: usize = 32;
const DEFAULT_BACKSTOP: Duration = Duration::from_secs(60);

static WAKE: tokio::sync::Notify = tokio::sync::Notify::const_new();

/// Retry held launches after placement authority changes, such as a node uncordon.
pub(crate) fn wake() {
    WAKE.notify_one();
}

/// How far one pass looks and how often it retries without a Job ending. A held launch is
/// retried at least every `backstop` even when no Odin Job ended: Claude pods and state
/// carriers free room too.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Pacing {
    pub scan: usize,
    pub backstop: Duration,
}

impl Default for Pacing {
    fn default() -> Self {
        Self {
            scan: DEFAULT_SCAN,
            backstop: DEFAULT_BACKSTOP,
        }
    }
}

impl Pacing {
    /// Reads the enabled authority node card's `[launch_queue]`.
    pub(crate) fn declared(snapshot: &odin_registry::Snapshot) -> Self {
        let declared = snapshot
            .objects
            .iter()
            .find_map(|object| match &object.config {
                odin_registry::ObjectConfig::Node(node)
                    if node.enabled && node.authoritative_state =>
                {
                    node.launch_queue
                }
                _ => None,
            });
        let defaults = Self::default();
        let Some(declared) = declared else {
            return defaults;
        };
        Self {
            scan: declared
                .scan
                .map_or(defaults.scan, |scan| scan.get() as usize),
            backstop: declared
                .backstop_seconds
                .map_or(defaults.backstop, |seconds| {
                    Duration::from_secs(u64::from(seconds.get()))
                }),
        }
    }
}

#[derive(Default)]
pub(crate) struct QueueState {
    tried: Option<Tried>,
    cursor: Option<String>,
    /// Batches with an item settled since odind started, until the batch drains.
    batches: BTreeMap<String, Tally>,
}

struct Tried {
    active: usize,
    at: Instant,
}

struct Tally {
    first: QueuedLaunch,
    started: usize,
    refused: usize,
}

/// What one pass did; the pump routes each to the launching session.
#[derive(Debug)]
pub(crate) enum Outcome {
    Started {
        held: QueuedLaunch,
        settlement: Value,
    },
    Refused {
        held: QueuedLaunch,
        reason: String,
    },
    /// Every item of a batch has left the queue.
    Drained {
        batch: String,
        first: QueuedLaunch,
        started: usize,
        refused: usize,
    },
}

/// Oldest first within each lane, lanes in turn by their oldest launch, at most `scan`.
fn in_turn(
    held: Vec<(PathBuf, QueuedLaunch)>,
    scan: usize,
    cursor: Option<&str>,
) -> Vec<(PathBuf, QueuedLaunch)> {
    let mut lanes: Vec<(String, VecDeque<(PathBuf, QueuedLaunch)>)> = Vec::new();
    for entry in held {
        let lane = entry.1.lane().to_owned();
        match lanes.iter_mut().find(|(name, _)| *name == lane) {
            Some((_, queue)) => queue.push_back(entry),
            None => lanes.push((lane, VecDeque::from([entry]))),
        }
    }
    let mut all = Vec::new();
    while lanes.iter().any(|(_, queue)| !queue.is_empty()) {
        for (_, queue) in &mut lanes {
            all.extend(queue.pop_front());
        }
    }
    if let Some(index) = cursor.and_then(|cursor| {
        all.iter()
            .position(|(_, launch)| launch.operation_id == cursor)
    }) {
        all.rotate_left(index + 1);
    }
    let mut order = Vec::with_capacity(scan.min(all.len()));
    for entry in all.into_iter().take(scan) {
        order.push(entry);
    }
    order
}

/// One pass over the queue. It runs only when a running Odin Job has ended since the last
/// pass, or the backstop has passed. Within the pass every held launch that fits starts; a
/// launch that still finds no room keeps its place, and its lane, profile and target are not
/// tried again in this pass. Any other answer removes it.
pub(crate) async fn pass<Active, ActiveFut, Retry, RetryFut>(
    queue: &LaunchQueue,
    state: &mut QueueState,
    pacing: Pacing,
    mut active: Active,
    mut retry: Retry,
) -> Result<Vec<Outcome>, String>
where
    Active: FnMut() -> ActiveFut,
    ActiveFut: Future<Output = Result<usize, String>>,
    Retry: FnMut(QueuedLaunch) -> RetryFut,
    RetryFut: Future<Output = Result<Value, HostToolError>>,
{
    let held = queue.held()?;
    if held.is_empty() {
        return Ok(drained(state, &BTreeSet::new()));
    }
    let running = active().await?;
    let due = state
        .tried
        .as_ref()
        .is_none_or(|tried| running < tried.active || tried.at.elapsed() >= pacing.backstop);
    if !due {
        return Ok(Vec::new());
    }
    let scanned = held.len() > pacing.scan;
    let entries = in_turn(held, pacing.scan, state.cursor.as_deref());
    state.cursor = entries
        .last()
        .map(|(_, launch)| launch.operation_id.clone());
    let mut outcomes = Vec::new();
    let mut full = BTreeSet::new();
    for (path, held) in entries {
        let key = (
            held.lane().to_owned(),
            held.profile().to_owned(),
            held.arguments["targetNode"].as_str().map(str::to_owned),
        );
        if full.contains(&key) {
            continue;
        }
        if !queue.claim(&path, &held)? {
            continue;
        }
        match retry(held.clone()).await {
            Ok(settlement) if settlement["status"] == "queued" => {
                queue.release(&held)?;
                full.insert(key);
            }
            Ok(settlement) => {
                // Keep the durable claim: dispatch may have reached the cluster.
                outcomes.push(Outcome::Started { held, settlement });
            }
            // Errors may occur after a request reached the cluster. Keep the claim and
            // reservation rather than replaying or refunding an uncertain dispatch.
            Err(error) => {
                outcomes.push(Outcome::Refused {
                    held,
                    reason: error.to_string(),
                });
            }
        }
    }
    // Started runs hold room now, so the next pass waits for one of them, or another, to end.
    let started = outcomes
        .iter()
        .any(|outcome| matches!(outcome, Outcome::Started { .. }));
    state.tried = if started && scanned {
        None
    } else {
        Some(Tried {
            active: if started { active().await? } else { running },
            at: Instant::now(),
        })
    };
    let mut routed = Vec::new();
    for outcome in outcomes {
        let (held, refused) = match &outcome {
            Outcome::Started { held, .. } => (held, false),
            Outcome::Refused { held, .. } => (held, true),
            Outcome::Drained { .. } => unreachable!("a pass settles items, not batches"),
        };
        let Some(batch) = held.batch.clone() else {
            routed.push(outcome);
            continue;
        };
        let tally = state.batches.entry(batch).or_insert_with(|| Tally {
            first: held.clone(),
            started: 0,
            refused: 0,
        });
        if refused {
            tally.refused += 1;
            routed.push(outcome);
        } else {
            tally.started += 1;
        }
    }
    let waiting: BTreeSet<String> = queue
        .held()?
        .into_iter()
        .filter_map(|(_, held)| held.batch)
        .collect();
    routed.extend(drained(state, &waiting));
    Ok(routed)
}

/// Every tallied batch with nothing left waiting, removed from the tally.
fn drained(state: &mut QueueState, waiting: &BTreeSet<String>) -> Vec<Outcome> {
    let done: Vec<String> = state
        .batches
        .keys()
        .filter(|batch| !waiting.contains(*batch))
        .cloned()
        .collect();
    done.into_iter()
        .filter_map(|batch| {
            let tally = state.batches.remove(&batch)?;
            Some(Outcome::Drained {
                batch,
                first: tally.first,
                started: tally.started,
                refused: tally.refused,
            })
        })
        .collect()
}

/// Odin Jobs whose pods are still pending, scheduling or running: the ones holding room.
async fn active_jobs(cell: &KubeRuntimeCell) -> Result<usize, String> {
    let (_, client) = cell.parts().await.map_err(|error| error.to_string())?;
    let jobs = client
        .jobs()
        .list(&::kube::api::ListParams::default().labels(odin_kube::job::KUBE_OWNED_SELECTOR))
        .await
        .map_err(|error| error.to_string())?;
    let cluster = &cell.kube_config().cluster;
    Ok(jobs
        .items
        .iter()
        .filter_map(|job| odin_kube::status::observe_job(cluster, job, 0).ok())
        .filter(|observed| {
            matches!(
                observed.workload.state,
                KubeWorkloadState::Pending
                    | KubeWorkloadState::Scheduling
                    | KubeWorkloadState::Running
            )
        })
        .count())
}

async fn announce(
    owner: &Arc<odin_omp::host_tools::delegation::GovernedTaskOwner>,
    runtime: &Arc<odin_hermes::runtime::HermesRuntime>,
    outcome: Outcome,
) {
    let (held, key, text) = match outcome {
        Outcome::Started { held, settlement } => {
            let text = format!(
                "your queued launch of {} started as run {}",
                held.profile(),
                settlement["runId"].as_str().unwrap_or("(unnamed)")
            );
            (held.clone(), held.operation_id, text)
        }
        Outcome::Refused { held, reason } => {
            let batch = held
                .batch
                .as_deref()
                .map_or(String::new(), |batch| format!(" (batch {batch})"));
            let text = format!(
                "your queued launch of {}{batch} has an uncertain dispatch outcome: {reason}",
                held.profile()
            );
            (held.clone(), held.operation_id, text)
        }
        Outcome::Drained {
            batch,
            first,
            started,
            refused,
        } => {
            let text = format!(
                "your batch {batch} of {} has left the queue: {started} started, {refused} unconfirmed",
                first.profile()
            );
            (first, format!("batch:{batch}"), text)
        }
    };
    let finding = Finding {
        key: format!("queued-launch:{key}"),
        session: held.scope.run.as_ref().and_then(launching_session),
        source: "launch queue",
        text,
        lane: held.scope.lane.clone(),
    };
    if let Err(error) = route_finding(owner, runtime, finding).await {
        tracing::error!("queued launch outcome not delivered: {error}");
    }
}

/// Arms the pump beside the workload watch. Without a configured queue there is nothing to pump.
pub(super) fn arm(
    pumps: &mut tokio::task::JoinSet<Result<(), String>>,
    coordinator: Arc<KubeCommandCoordinator>,
    cell: Arc<KubeRuntimeCell>,
    owner: Arc<odin_omp::host_tools::delegation::GovernedTaskOwner>,
    runtime: Arc<odin_hermes::runtime::HermesRuntime>,
) {
    let Some(queue) = coordinator.launch_queue() else {
        return;
    };
    pumps.spawn(async move {
        let mut state = QueueState::default();
        let mut ticker = tokio::time::interval(QUEUE_TICK);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                _ = ticker.tick() => {}
                _ = WAKE.notified() => { state.tried = None; }
            }
            let pacing = Pacing::declared(&cell.snapshot());
            let retry = |held: QueuedLaunch| {
                let coordinator = Arc::clone(&coordinator);
                async move { coordinator.retry_held(held).await }
            };
            match pass(&queue, &mut state, pacing, || active_jobs(&cell), retry).await {
                Ok(outcomes) => {
                    for outcome in outcomes {
                        announce(&owner, &runtime, outcome).await;
                    }
                }
                Err(error) => tracing::error!("launch queue: {error}"),
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    fn held_launch(operation: &str, profile: &str, lane: &str, at: i64) -> QueuedLaunch {
        QueuedLaunch {
            operation_id: operation.to_owned(),
            timeout_seconds: 60,
            scope: odin_domain::Scope {
                lane: Some(odin_domain::LaneId::new(lane).expect("lane id")),
                ..odin_domain::Scope::default()
            },
            arguments: serde_json::json!({"profile": profile}),
            held_at_ms: at,
            batch: None,
            queue_caps: false,
            campaign: None,
            campaign_stage_sha256: None,
        }
    }

    /// A queue directory holding `launches` with their own `held_at_ms`.
    fn queue_of(dir: &std::path::Path, launches: &[QueuedLaunch]) -> LaunchQueue {
        std::fs::create_dir_all(dir.join("batches")).expect("batch dir");
        for batch in launches.iter().filter_map(|launch| launch.batch.as_ref()) {
            std::fs::write(dir.join("batches").join(format!("{batch}.json")), b"{}")
                .expect("batch record");
        }
        for launch in launches {
            let bytes = serde_json::to_vec(launch).expect("json");
            std::fs::write(dir.join(format!("{}.json", launch.operation_id)), bytes)
                .expect("held file");
        }
        LaunchQueue::new(dir.to_path_buf())
    }

    fn answer(status: &str, held: &QueuedLaunch) -> Value {
        serde_json::json!({"status": status, "runId": format!("run:{}", held.operation_id)})
    }

    /// Answers `queued` for the profiles in `full`, `accepted` otherwise, recording the order.
    fn retrying<'a>(
        full: &'a [&'a str],
        tried: &'a RefCell<Vec<String>>,
    ) -> impl FnMut(QueuedLaunch) -> std::future::Ready<Result<Value, HostToolError>> + 'a {
        move |held| {
            tried.borrow_mut().push(held.operation_id.clone());
            let status = if full.contains(&held.profile()) {
                "queued"
            } else {
                "accepted"
            };
            std::future::ready(Ok(answer(status, &held)))
        }
    }

    fn started(outcomes: &[Outcome]) -> Vec<&str> {
        outcomes
            .iter()
            .filter_map(|outcome| match outcome {
                Outcome::Started { held, .. } => Some(held.operation_id.as_str()),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn declared_pacing_reads_the_authority_node_card_and_falls_back_per_key() {
        assert!(Pacing::default().scan > 0 && Pacing::default().backstop > Duration::ZERO);
        let node: odin_registry::schema::NodeToml = toml::from_str(
            r#"
schema = "odin.registry.v1"
kind = "node"
enabled = true
description = "authority"
host = "mini"
role = "control"
capabilities = []
allow_workloads = false
authoritative_state = true

[launch_queue]
scan = 5
"#,
        )
        .expect("node card");
        let snapshot = odin_registry::Snapshot {
            schema: "odin.registry.v1".to_owned(),
            revision: 1,
            hash: "fixture".to_owned(),
            objects: vec![odin_registry::RegistryObject {
                id: "mini".to_owned(),
                relative_config: "registry/nodes/mini/node.toml".into(),
                config: odin_registry::ObjectConfig::Node(Box::new(node)),
            }],
            tombstones: Vec::new(),
        };
        let pacing = Pacing::declared(&snapshot);
        assert_eq!(pacing.scan, 5);
        assert_eq!(pacing.backstop, Pacing::default().backstop);
    }

    #[tokio::test]
    async fn a_queued_launch_is_admitted_when_a_run_ends() {
        let dir = tempfile::tempdir().expect("queue dir");
        let queue = queue_of(
            dir.path(),
            &[held_launch("op-held", "cfd", "kubert-odin", 1)],
        );
        let mut state = QueueState::default();
        let tried = RefCell::new(Vec::new());

        // Still full with three runs active: the first try keeps the launch.
        let outcomes = pass(
            &queue,
            &mut state,
            Pacing::default(),
            || async { Ok(3) },
            retrying(&["cfd"], &tried),
        )
        .await
        .expect("pass");
        assert!(outcomes.is_empty());
        assert_eq!(tried.borrow().len(), 1);

        // No run ended since that try, and the backstop has not passed: nothing is retried.
        let outcomes = pass(
            &queue,
            &mut state,
            Pacing::default(),
            || async { Ok(3) },
            retrying(&[], &tried),
        )
        .await
        .expect("pass");
        assert!(outcomes.is_empty());
        assert_eq!(tried.borrow().len(), 1);

        // One run ended: the launch runs again through the create path and is admitted.
        let outcomes = pass(
            &queue,
            &mut state,
            Pacing::default(),
            || async { Ok(2) },
            retrying(&[], &tried),
        )
        .await
        .expect("pass");
        assert_eq!(started(&outcomes), ["op-held"]);
        assert!(
            queue.held().expect("queue").is_empty(),
            "an admitted launch leaves the queue"
        );
    }

    #[tokio::test]
    async fn uncertain_dispatch_keeps_claim_and_is_not_retried() {
        let dir = tempfile::tempdir().expect("queue dir");
        let queue = queue_of(dir.path(), &[held_launch("op", "cfd", "lane", 1)]);
        let mut state = QueueState::default();
        let outcomes = pass(
            &queue,
            &mut state,
            Pacing::default(),
            || async { Ok(0) },
            |_| async {
                Err(HostToolError::Unavailable {
                    tool: "test",
                    reason: "lost response".into(),
                })
            },
        )
        .await
        .expect("pass");
        assert!(matches!(outcomes.as_slice(), [Outcome::Refused { .. }]));
        assert!(queue.held().expect("held").is_empty());
        assert!(dir.path().join("claims/op.json").exists());
    }

    #[tokio::test]
    async fn a_cap_refused_batch_item_waits_and_starts_when_a_slot_frees() {
        let dir = tempfile::tempdir().expect("queue dir");
        let queue = queue_of(
            dir.path(),
            &[
                held_launch("op-1", "cfd", "worker-project", 1).in_batch("sweep"),
                held_launch("op-2", "cfd", "worker-project", 2).in_batch("sweep"),
            ],
        );
        let mut state = QueueState::default();
        let tried = RefCell::new(Vec::new());
        // The lane cap is full: the item stays held and its batch says nothing yet.
        let outcomes = pass(
            &queue,
            &mut state,
            Pacing::default(),
            || async { Ok(4) },
            retrying(&["cfd"], &tried),
        )
        .await
        .expect("pass");
        assert!(outcomes.is_empty());
        assert_eq!(queue.held().expect("queue").len(), 2);
        // A slot frees: both start in the one pass and the batch reports once, drained.
        let outcomes = pass(
            &queue,
            &mut state,
            Pacing::default(),
            || async { Ok(3) },
            retrying(&[], &tried),
        )
        .await
        .expect("pass");
        assert!(
            started(&outcomes).is_empty(),
            "batch items are summarised, not announced one by one"
        );
        assert!(
            matches!(
                outcomes.as_slice(),
                [Outcome::Drained { batch, started: 2, refused: 0, .. }] if batch == "sweep"
            ),
            "{outcomes:?}"
        );
        assert!(queue.held().expect("queue").is_empty());
    }

    #[tokio::test]
    async fn a_large_head_does_not_block_a_small_launch_that_fits() {
        let dir = tempfile::tempdir().expect("queue dir");
        let queue = queue_of(
            dir.path(),
            &[
                held_launch("op-big", "cfd-12cpu", "worker-project", 1),
                held_launch("op-big-2", "cfd-12cpu", "worker-project", 2),
                held_launch("op-small", "research", "kubert-odin", 3),
            ],
        );
        let mut state = QueueState::default();
        let tried = RefCell::new(Vec::new());
        let outcomes = pass(
            &queue,
            &mut state,
            Pacing::default(),
            || async { Ok(1) },
            retrying(&["cfd-12cpu"], &tried),
        )
        .await
        .expect("pass");
        assert_eq!(started(&outcomes), ["op-small"]);
        // The second large launch shares the first's refusal for this pass.
        assert!(!tried.borrow().contains(&"op-big-2".to_owned()));
        let left: Vec<String> = queue
            .held()
            .expect("queue")
            .into_iter()
            .map(|(_, held)| held.operation_id)
            .collect();
        assert_eq!(left, ["op-big", "op-big-2"]);
    }

    #[tokio::test]
    async fn the_pump_keeps_admitting_after_a_success_in_one_pass() {
        let dir = tempfile::tempdir().expect("queue dir");
        let launches: Vec<QueuedLaunch> = (0..5)
            .map(|index| held_launch(&format!("op-{index}"), "cfd", "worker-project", index))
            .collect();
        let queue = queue_of(dir.path(), &launches);
        let mut state = QueueState::default();
        let tried = RefCell::new(Vec::new());
        let pacing = Pacing {
            scan: 3,
            ..Pacing::default()
        };
        let outcomes = pass(
            &queue,
            &mut state,
            pacing,
            || async { Ok(0) },
            retrying(&[], &tried),
        )
        .await
        .expect("pass");
        assert_eq!(
            started(&outcomes),
            ["op-0", "op-1", "op-2"],
            "one pass starts up to its scan"
        );
        assert_eq!(queue.held().expect("queue").len(), 2);
    }

    #[tokio::test]
    async fn lanes_take_turns_so_a_sweep_cannot_starve_another_lane() {
        let dir = tempfile::tempdir().expect("queue dir");
        let mut launches: Vec<QueuedLaunch> = (0..4)
            .map(|index| held_launch(&format!("sweep-{index}"), "cfd", "worker-project", index))
            .collect();
        launches.push(held_launch("research", "research", "kubert-odin", 10));
        let queue = queue_of(dir.path(), &launches);
        let mut state = QueueState::default();
        let tried = RefCell::new(Vec::new());
        let pacing = Pacing {
            scan: 2,
            ..Pacing::default()
        };
        pass(
            &queue,
            &mut state,
            pacing,
            || async { Ok(0) },
            retrying(&[], &tried),
        )
        .await
        .expect("pass");
        assert_eq!(*tried.borrow(), ["sweep-0", "research"]);
    }
    #[test]
    fn scan_cursor_reaches_launches_beyond_a_blocked_window() {
        let entries = (0..5)
            .map(|index| {
                (
                    PathBuf::from(index.to_string()),
                    held_launch(&format!("op-{index}"), "cfd", "lane", index),
                )
            })
            .collect::<Vec<_>>();
        let first = in_turn(entries.clone(), 2, None);
        let second = in_turn(entries, 2, Some(&first.last().unwrap().1.operation_id));
        assert_eq!(
            first
                .iter()
                .map(|(_, held)| held.operation_id.as_str())
                .collect::<Vec<_>>(),
            ["op-0", "op-1"]
        );
        assert_eq!(
            second
                .iter()
                .map(|(_, held)| held.operation_id.as_str())
                .collect::<Vec<_>>(),
            ["op-2", "op-3"]
        );
    }
}
