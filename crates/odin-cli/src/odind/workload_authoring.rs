//! Draft workloads from declared skeletons and publish only after exact kernel approval.
//! The shared authoring transaction validates, stages, commits, publishes, and reloads
//! the active pin. Exact-revision replay requires the durable publication receipt;
//! stale approval scopes are refused rather than retried blindly.
//!
//! Blocking Git/SQLite work runs off async workers with a receive timeout.
//! Publication does not launch pods; that requires `kube.workload.create`.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::mpsc::RecvTimeoutError;
use std::sync::Arc;
use std::time::Duration as StdDuration;

use odin_hermes::runtime::WorkloadAuthoringFailure as Failure;

#[path = "authoring_sync.rs"]
mod authoring_sync;
pub(crate) use authoring_sync::{AuthoringSync, GIT_SSH};

/// Receive bounds per operation, under their capability timeouts (draft 30s,
/// publish 120s). Preparation is read-only owner resolution and takes the
/// draft bound.
const DRAFT_BOUND: StdDuration = StdDuration::from_secs(25);
const PUBLISH_BOUND: StdDuration = StdDuration::from_secs(110);
const PREPARE_BOUND: StdDuration = StdDuration::from_secs(25);

pub(super) struct DaemonWorkloadAuthoring {
    /// The daemon's active snapshot pin: the SAME handle the launch seams
    /// read. Drafts validate against `current()`; a successful publication
    /// advances it through the handle's verified in-chain reload.
    pin: Arc<odin_registry::SnapshotHandle>,
    /// Blocking state the bridge hands to each operation.
    worktree: PathBuf,
    snapshot_store: PathBuf,
    ledger_path: PathBuf,
    /// Durable compiled-draft retention: `workload_draft` retains the exact
    /// compiled declaration here; `workload_publish` consumes it instead of
    /// re-deriving anything from model answers.
    drafts: Arc<odin_omp::host_tools::WorkloadDraftStore>,
    /// The pinned workload image's deployment facts: drafts are completed
    /// from them, so the model never guesses an image digest or in-image
    /// path. `None` when no cluster surface is composed.
    deployment: Option<crate::kube::WorkloadDeploymentFacts>,
    /// The declared repository behind a private authoring worktree: present
    /// on a deployed authority, where publications commit to odin `main`.
    sync: Option<AuthoringSync>,
    /// Each configured seat's gateway launch lanes: a pod bound to a seat
    /// runs on one of them, so drafts refuse any other (the launch does).
    seat_lanes: Arc<BTreeMap<String, Vec<String>>>,
}

/// The outcome of one strict declaration compile.
enum DeclarationCompile {
    /// Every declared variable is present and valid.
    Complete(odin_registry::CompiledFill),
    /// Required declared variables are absent: the clarification list is
    /// the draft's honest answer, never a refusal.
    NeedsAnswers(Vec<odin_hermes::runtime::WorkloadClarification>),
    /// A value grammar, reference, or relation refused the declaration.
    Failed(Failure),
}

/// Preparation and execution use the same revision eligibility result.
enum RevisionScope {
    /// The bound revision is already installed: only the exact same
    /// publication may complete there, as `unchanged`, anchored by its
    /// durable receipt.
    Replay,
    /// The active registry is below the bound revision: this publication
    /// would install at exactly the bound revision.
    Fresh,
}

impl DaemonWorkloadAuthoring {
    /// `state_root` is the daemon's state root — NOT a pre-joined draft
    /// directory: `WorkloadDraftStore::seal` appends the store's own
    /// directory component, and the bridge runtime's publish pre-gate seals
    /// the same way from the same root, so the store that retains a draft is
    /// the store that consumes it.
    pub(super) fn new(
        pin: Arc<odin_registry::SnapshotHandle>,
        worktree: PathBuf,
        snapshot_store: PathBuf,
        ledger_path: PathBuf,
        state_root: PathBuf,
        deployment: Option<crate::kube::WorkloadDeploymentFacts>,
        sync: Option<AuthoringSync>,
    ) -> Result<Self, odin_omp::host_tools::WorkloadDraftStoreError> {
        Ok(Self {
            pin,
            worktree,
            snapshot_store,
            ledger_path,
            drafts: Arc::new(odin_omp::host_tools::WorkloadDraftStore::seal(&state_root)?),
            deployment,
            sync,
            seat_lanes: Arc::new(BTreeMap::new()),
        })
    }

    pub(super) fn with_seat_lanes(mut self, lanes: BTreeMap<String, Vec<String>>) -> Self {
        self.seat_lanes = Arc::new(lanes);
        self
    }

    /// Offload Git/SQLite work with a timeout that does not cancel irreversible steps.
    /// Replay the identical approved dispatch to reconcile its eventual outcome.
    fn bridge<T>(
        &self,
        name: &'static str,
        bound: StdDuration,
        operation: impl FnOnce(BridgeRoute) -> Result<T, Failure> + Send + 'static,
    ) -> Result<T, Failure>
    where
        T: Send + 'static,
    {
        let route = BridgeRoute {
            pin: Arc::clone(&self.pin),
            worktree: self.worktree.clone(),
            snapshot_store: self.snapshot_store.clone(),
            ledger_path: self.ledger_path.clone(),
            drafts: Arc::clone(&self.drafts),
            deployment: self.deployment.clone(),
            sync: self.sync.clone(),
            seat_lanes: Arc::clone(&self.seat_lanes),
        };
        // Multi-thread runtimes use block_in_place and spawn_blocking; other callers
        // synchronously wait on a dedicated thread with recv_timeout.
        let worker = tokio::runtime::Handle::try_current()
            .ok()
            .filter(|handle| handle.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread);
        if let Some(handle) = worker {
            tokio::task::block_in_place(|| {
                handle.block_on(async move {
                    let task = tokio::task::spawn_blocking(move || operation(route));
                    match tokio::time::timeout(bound, task).await {
                        Ok(joined) => joined.map_err(|error| Failure::WorktreeInvalid {
                            reason: format!("{name} bridge task failed: {error}"),
                        })?,
                        Err(_) => Err(Failure::BridgeTimeout { operation: name }),
                    }
                })
            })
        } else {
            let (sender, receiver) = std::sync::mpsc::channel();
            std::thread::Builder::new()
                .name(name.to_owned())
                .spawn(move || {
                    let _ = sender.send(operation(route));
                })
                .map_err(|error| Failure::WorktreeInvalid {
                    reason: format!("{name} bridge thread failed: {error}"),
                })?;
            receiver.recv_timeout(bound).map_err(|error| match error {
                RecvTimeoutError::Timeout => Failure::BridgeTimeout { operation: name },
                RecvTimeoutError::Disconnected => Failure::WorktreeInvalid {
                    reason: format!("{name} bridge thread panicked"),
                },
            })?
        }
    }
}

/// Receive bound for the authoring transaction lock, under the publish
/// capability timeout.
const LOCK_BOUND: StdDuration = StdDuration::from_secs(30);

/// The per-worktree authoring transaction lock: an exclusive advisory flock
/// on a lock file inside the worktree's real Git directory (never part of
/// the committed tree). It serializes the WHOLE effect transaction —
/// install, commit, store publication, adoption — so a concurrent retry of
/// the same approved operation waits and then reconciles, instead of
/// colliding on staging temporaries or racing the Git index. The store's
/// own publication lock stays the inner, narrower authority; this lock
/// covers everything it does not. The lock file is persistent — created
/// once and never unlinked — so waiters always lock the same inode.
#[derive(Debug)]
pub(crate) struct WorktreeLock {
    file: std::fs::File,
}

impl WorktreeLock {
    fn git_dir(worktree: &std::path::Path) -> Result<PathBuf, Failure> {
        let marker = worktree.join(".git");
        if marker.is_dir() {
            return Ok(marker);
        }
        // Linked worktree: `.git` is a file naming the real Git directory.
        // A malformed marker is a typed worktree fault — the lock never
        // falls back to a wrong parent.
        let content =
            std::fs::read_to_string(&marker).map_err(|error| Failure::WorktreeInvalid {
                reason: format!("could not read the .git marker: {error}"),
            })?;
        let Some(gitdir) = content.trim().strip_prefix("gitdir:") else {
            return Err(Failure::WorktreeInvalid {
                reason: "the .git marker does not name a Git directory".to_owned(),
            });
        };
        let path = PathBuf::from(gitdir.trim());
        Ok(if path.is_absolute() {
            path
        } else {
            worktree.join(path)
        })
    }

    /// Bounded acquisition with TYPED failure discrimination: contention
    /// (`WouldBlock`) retries until the bound and then reports a bridge
    /// timeout whose reconciliation is an identical replay; any permission
    /// or IO fault reports `WorktreeInvalid` immediately instead of being
    /// swallowed into a timeout. The lock file is PERSISTENT: it is never
    /// unlinked, so a waiter that raced a release keeps locking the same
    /// inode instead of silently switching to a fresh one.
    pub(crate) fn acquire(worktree: &std::path::Path, bound: StdDuration) -> Result<Self, Failure> {
        use std::fs::TryLockError;

        let lock_path = Self::git_dir(worktree)?.join("odin-authoring.lock");
        let deadline = std::time::Instant::now() + bound;
        loop {
            let file = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .truncate(false)
                .open(&lock_path)
                .map_err(|error| Failure::WorktreeInvalid {
                    reason: format!(
                        "could not open the authoring lock {}: {error}",
                        lock_path.display()
                    ),
                })?;
            match file.try_lock() {
                Ok(()) => {
                    return Ok(Self { file });
                }
                Err(TryLockError::WouldBlock) => {}
                Err(TryLockError::Error(error)) => {
                    return Err(Failure::WorktreeInvalid {
                        reason: format!("authoring lock {} failed: {error}", lock_path.display()),
                    });
                }
            }
            if std::time::Instant::now() >= deadline {
                return Err(Failure::BridgeTimeout {
                    operation: "authoring-lock",
                });
            }
            std::thread::sleep(StdDuration::from_millis(50));
        }
    }
}

impl Drop for WorktreeLock {
    fn drop(&mut self) {
        // Unlock ONLY. The lock file stays on disk forever: unlinking here
        // would let a waiter that raced the release hold the old inode while
        // a new entrant creates and locks a fresh one — two concurrent
        // transactions on one worktree.
        let _ = self.file.unlock();
    }
}

impl odin_hermes::runtime::WorkloadAuthoringRoute for DaemonWorkloadAuthoring {
    fn draft(
        &self,
        request: odin_hermes::runtime::WorkloadDraftRequest,
    ) -> Result<odin_hermes::runtime::WorkloadDraft, Failure> {
        self.bridge("odin-workload-draft", DRAFT_BOUND, move |route| {
            route.draft(&request)
        })
    }

    fn publish(
        &self,
        request: odin_hermes::runtime::WorkloadPublishRequest,
    ) -> Result<odin_hermes::runtime::WorkloadPublication, Failure> {
        self.bridge("odin-workload-publish", PUBLISH_BOUND, move |route| {
            route.publish(&request)
        })
    }

    fn prepare_publish(
        &self,
        request: &odin_hermes::runtime::WorkloadPublishRequest,
    ) -> Result<(), Failure> {
        let request = request.clone();
        self.bridge(
            "odin-workload-publish-prepare",
            PREPARE_BOUND,
            move |route| route.prepare_publish(&request),
        )
    }

    fn prepare_draft(
        &self,
        request: &odin_hermes::runtime::WorkloadDraftRequest,
    ) -> Result<(), Failure> {
        let request = request.clone();
        self.bridge("odin-workload-draft-prepare", PREPARE_BOUND, move |route| {
            route.prepare_draft(&request)
        })
    }
}

/// The blocking half of the route, executed wholly on the dedicated bridge
/// thread: plain data in, typed results out.
struct BridgeRoute {
    pin: Arc<odin_registry::SnapshotHandle>,
    worktree: PathBuf,
    snapshot_store: PathBuf,
    ledger_path: PathBuf,
    drafts: Arc<odin_omp::host_tools::WorkloadDraftStore>,
    deployment: Option<crate::kube::WorkloadDeploymentFacts>,
    sync: Option<AuthoringSync>,
    seat_lanes: Arc<BTreeMap<String, Vec<String>>>,
}

#[path = "workload_authoring/bridge.rs"]
mod bridge;

/// Why a pod bound to `seat` could never launch, if it could not: a pod
/// launches from a session of its own seat, so the seat must hold
/// `kube.workload.create`. Applies only where some seat can launch pods.
pub(crate) fn pod_launch_refusal(
    objects: &[odin_registry::RegistryObject],
    seat: &str,
) -> Option<String> {
    let launchers: Vec<&str> = objects
        .iter()
        .filter_map(|object| match &object.config {
            odin_registry::ObjectConfig::Seat(declared)
                if declared.enabled
                    && declared
                        .tool_refs
                        .iter()
                        .any(|capability| capability.as_str() == "kube.workload.create") =>
            {
                Some(object.id.as_str())
            }
            _ => None,
        })
        .collect();
    if launchers.is_empty() || launchers.contains(&seat) {
        return None;
    }
    Some(format!(
        "seat {seat} cannot launch pods (a pod launches from a session of its own seat); bind it \
         to a seat that can: {}",
        launchers.join(", ")
    ))
}

/// Every chat route of an enabled provider as (gateway lane, provider,
/// model); embedding providers (a declared embedding protocol) are not chat.
fn declared_gateway_routes(
    objects: &[odin_registry::RegistryObject],
) -> Vec<(String, String, String)> {
    let mut routes: Vec<(String, String, String)> = objects
        .iter()
        .filter_map(|object| match &object.config {
            odin_registry::ObjectConfig::Provider(provider)
                if provider.enabled && provider.protocol.is_none() =>
            {
                Some(provider.policy.routes.iter().map(|route| {
                    (
                        route.gateway_lane_id.clone(),
                        object.id.clone(),
                        route.gateway_model_id.clone(),
                    )
                }))
            }
            _ => None,
        })
        .flatten()
        .collect();
    routes.sort();
    routes.dedup_by(|left, right| left.0 == right.0);
    routes
}

/// Runs one git command in the authoring worktree, returning trimmed stdout.
pub(crate) fn git(worktree: &std::path::Path, args: &[&str]) -> Result<String, String> {
    let output = std::process::Command::new("git")
        .arg("-C")
        .arg(worktree)
        // Read-only observations (status, var, show) must never refresh or
        // write the index: without this, `git status` takes an optional
        // lock and mutates .git/index. Mandatory locks (add, commit) are
        // unaffected by this setting.
        .env("GIT_OPTIONAL_LOCKS", "0")
        .args(args)
        .output()
        .map_err(|error| format!("could not spawn git: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "git {} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    String::from_utf8(output.stdout)
        .map(|stdout| stdout.trim().to_owned())
        .map_err(|_| "git stdout is not UTF-8".to_owned())
}

/// Runs one git command and returns the RAW stdout bytes — content reads
/// (`git show`) must never pass through a trimming string transform, or the
/// canonical-byte digest comparison loses the trailing newline and diverges
/// from the staged file.
pub(crate) fn git_bytes(worktree: &std::path::Path, args: &[&str]) -> Result<Vec<u8>, String> {
    let output = std::process::Command::new("git")
        .arg("-C")
        .arg(worktree)
        .env("GIT_OPTIONAL_LOCKS", "0")
        .args(args)
        .output()
        .map_err(|error| format!("could not spawn git: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "git {} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    Ok(output.stdout)
}

/// Commit only approved paths, excluding unrelated staged work, then read back
/// committed bytes and verify the approved digest before returning HEAD.
fn git_commit(
    worktree: &std::path::Path,
    profile_id: &str,
    phase: &str,
    paths: &[String],
    expected_digest: &str,
) -> Result<String, Failure> {
    let message =
        format!("workload: {phase} approved profile '{profile_id}' via conversational authoring");
    let mut args: Vec<String> = vec![
        "commit".to_owned(),
        "-m".to_owned(),
        message,
        "--".to_owned(),
    ];
    args.extend(paths.iter().cloned());
    let refs: Vec<&str> = args.iter().map(String::as_str).collect();
    git(worktree, &refs).map_err(|reason| Failure::PublicationRefused { reason })?;
    let head = git(worktree, &["rev-parse", "HEAD"])
        .map_err(|reason| Failure::WorktreeInvalid { reason })?;
    for relative in paths {
        let committed = git_bytes(worktree, &["show", &format!("HEAD:{relative}")])
            .map_err(|reason| Failure::PublicationRefused { reason })?;
        if odin_domain::Digest::hash(&committed).to_string() != expected_digest {
            return Err(Failure::PublicationRefused {
                reason: format!(
                    "committed HEAD content for {relative} does not hash to the approved \
                     declaration; reconcile from durable evidence — never re-approve blind"
                ),
            });
        }
    }
    Ok(head)
}

#[cfg(test)]
#[path = "tests/workload_authoring.rs"]
mod tests;
