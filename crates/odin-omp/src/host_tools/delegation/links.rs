//! Atomic delegation rows used for parent-link verification and concurrency limits.

use odin_domain::huginn::{LiveCommand, LiveSessionId};
use odin_domain::{CommandId, Digest, LaneId, ProjectId, RunId, SeatId, SessionId};
use serde::{Deserialize, Serialize};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::PathBuf;
use std::sync::{Arc, RwLock};
use std::time::SystemTime;
use tokio::sync::watch;

pub const DELEGATION_LINK_SCHEMA: &str = "odin.delegation-link.v1";

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DelegationPhase {
    /// The link is durable; the child token/open has not completed.
    Provisioning,
    /// The child opened idle, inherited the plan, and was prompted.
    Running,
    /// The owner observed the child inactive after a running phase.
    Ended,
    /// Provisioning failed and any opened child was stopped.
    Failed,
}

impl DelegationLink {
    /// Every refused lane and its cause, in order: `lane:cause>lane:cause`.
    pub fn refusal_lineage(&self) -> String {
        self.refusals
            .iter()
            .map(|refusal| format!("{}:{}", refusal.lane, refusal.cause))
            .collect::<Vec<_>>()
            .join(">")
    }
}

impl DelegationPhase {
    /// A row whose child may still hold a slot, a lane wall or a worker.
    pub const fn is_live(self) -> bool {
        matches!(self, Self::Provisioning | Self::Running)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DelegationLink {
    /// Exact schema discriminant; rejects cross-version reads.
    pub schema: String,
    pub child: LiveSessionId,
    pub parent: SessionId,
    /// Parent seat from the dispatch scope; rows without one are not captured.
    #[serde(default)]
    pub parent_seat: Option<SeatId>,
    /// The parent run whose accepted plan the child inherited.
    pub parent_run: RunId,
    /// The child run (`run:live:<child>`), carrying the inherited plan.
    pub child_run: RunId,
    /// The host-minted open command id that derives the child session.
    pub command: CommandId,
    /// The validated in-scope child project.
    pub project: ProjectId,
    /// The worker's registry lane, whose declared `[limits]` this row is
    /// admitted against. Absent on rows written before lane budgets.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lane: Option<LaneId>,
    pub provider: String,
    /// The fixed configured worker model.
    pub model: String,
    /// BLAKE3 digest of the exact prompt bytes.
    pub prompt_digest: Digest,
    /// Delegation depth: 1 for a worker of a root session.
    pub depth: u8,
    pub phase: DelegationPhase,
    /// Creation instant in Unix milliseconds.
    pub created_at_ms: u64,
    /// Reviewed result sequence; `None` means pending. Absence of a result
    /// must not suppress capture of a later event.
    #[serde(default)]
    pub learning_capture_sequence: Option<u64>,
    /// Seat that may steer this worker. Answering does not clear it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub escalated_to: Option<SeatId>,
    /// True only while that seat has not yet applied a response.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub escalation_open: bool,
    /// Latest durably observed `Result` sequence; never lowered.
    #[serde(default)]
    pub learning_result_sequence: Option<u64>,
    /// Accepted on read but omitted when the row is rewritten.
    #[serde(default, skip_serializing)]
    pub learning_proposal_id: Option<String>,
    /// Stalled turns the kernel has cancelled and resumed (the Retry rung);
    /// past [`super::lifecycle::MAX_STALL_RETRIES`] the child is ended.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub stall_retries: u8,
    /// The model lane (`provider/model`) at each stall, in order.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub stalls: Vec<String>,
    /// The seat's declared launch option the kernel switched the child to
    /// after a repeated stall (the lane fallback); `None`: it still runs on
    /// its launch pair.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub switched_to: Option<WorkerLane>,
    /// The provider stream-stall error (its event sequence) the kernel last
    /// answered, so one stalled turn is retried once, not on every pass.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub handled_stall_event: Option<u64>,
    /// Provider refusals in order, including the resulting lane changes.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub refusals: Vec<LaneRefusal>,
    /// Requests answered by a gateway fallback rather than the requested lane,
    /// read from per-session gateway accounting.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub gateway_fallbacks: Vec<GatewayFallback>,
    /// The key of the child's last answer handed to a delegating worker
    /// seat's session, so each settled turn reaches it once.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reported_answer: Option<String>,
    /// Original prompt retained across conversation eviction and rollover.
    /// Empty when the row has no recorded assignment.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub assignment: String,
    /// Attempted rollovers, persisted before respawn; failed starts also count.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub rollover_admissions: u8,
    /// One unsettled report delivery: the EXACT journaled command and the
    /// answer key it carries, recorded BEFORE dispatch so a crash replays
    /// the same journal identity instead of minting a blind fresh one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pending_report: Option<PendingReportDelivery>,
    /// Typed `task.steer` raises of this worker's lane budget, above the
    /// declaration. Empty when nobody has raised it.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub budget_raises: Vec<odin_registry::LaneBudgetRaise>,
}

/// The command to replay and answer key to acknowledge after delivery.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PendingReportDelivery {
    pub command: LiveCommand,
    pub key: String,
}

/// One gateway fallback seen for a worker: the lane the worker asked for
/// (its lane when the fallback was first seen), the gateway model group
/// that really answered, and how many of the worker's requests it answered.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GatewayFallback {
    pub lane: String,
    pub served: String,
    pub requests: u64,
}

/// One provider refusal of a worker's request: the lane that refused, why,
/// the provider error event, and the declared lane its next request went to
/// (`None`: no untried lane was left and the worker was ended).
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LaneRefusal {
    pub lane: String,
    pub cause: String,
    pub event: u64,
    pub next: Option<String>,
}

/// One declared model lane of a worker: a seat launch option's pair.
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkerLane {
    pub provider: String,
    pub model: String,
}

impl std::fmt::Display for WorkerLane {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}/{}", self.provider, self.model)
    }
}

impl DelegationLink {
    /// The lane the child runs on now: the fallback it was switched to, or
    /// the pair it was launched with.
    pub fn current_lane(&self) -> WorkerLane {
        self.switched_to.clone().unwrap_or_else(|| WorkerLane {
            provider: self.provider.clone(),
            model: self.model.clone(),
        })
    }

    /// Points this live child at `successor`. A pending report whose command
    /// still names the retiring parent cannot replay there; clearing it lets
    /// the next scan deliver to the successor. Budget raises and every other
    /// field stay.
    pub fn hand_to(&mut self, successor: &SessionId) -> bool {
        let mut changed = false;
        if self.parent != *successor {
            self.parent = successor.clone();
            changed = true;
        }
        let aimed_at_successor = self.pending_report.as_ref().is_some_and(|pending| {
            super::contracts::live_session_id(successor).ok().as_ref()
                == Some(&pending.command.session_id)
        });
        if self.pending_report.is_some() && !aimed_at_successor {
            self.pending_report = None;
            changed = true;
        }
        changed
    }

    /// Every lane the child ran on, launch pair first.
    pub fn lanes(&self) -> Vec<WorkerLane> {
        let launch = WorkerLane {
            provider: self.provider.clone(),
            model: self.model.clone(),
        };
        match &self.switched_to {
            Some(next) if *next != launch => vec![launch, next.clone()],
            _ => vec![launch],
        }
    }
}

fn is_zero(count: &u8) -> bool {
    *count == 0
}

/// Atomic JSON rows; clones share the scan/persist gate and notification channel.
#[derive(Clone)]
pub struct DelegationLinkLedger {
    core: Arc<LinkLedgerCore>,
}

struct LinkLedgerCore {
    root: PathBuf,
    /// Scan/persist coordination: `persist` holds the write side across the
    /// atomic row replacement plus its notification, a full scan holds the
    /// read side, so a scan never observes a half-applied batch of writes.
    /// Single-row reads need no gate: the row rename is atomic.
    gate: RwLock<()>,
    /// Monotonic persist counter, bumped after every durable row commit;
    /// watch receivers are the native change notification. No callback ever
    /// runs under a lock: the send only marks receivers.
    persists: watch::Sender<u64>,
    /// The last full scan, reused while neither the persist counter nor the
    /// directory mtime moved, so a pass that reads the ledger twice parses
    /// it once.
    scans: parking_lot::Mutex<Option<ScanMemo>>,
}

/// The change stamp and rows of one completed full scan.
struct ScanMemo {
    version: u64,
    modified: Option<SystemTime>,
    rows: Vec<PersistedLink>,
}

/// One durable row as a scan returns it.
#[derive(Clone, Debug)]
pub struct PersistedLink {
    pub link: DelegationLink,
}

impl DelegationLinkLedger {
    /// Opens the ledger over an absolute directory, creating it if absent.
    pub fn open(root: impl Into<PathBuf>) -> Result<Self, String> {
        let root = root.into();
        if !root.is_absolute() {
            return Err("delegation link ledger root must be absolute".to_owned());
        }
        fs::create_dir_all(&root)
            .map_err(|error| format!("cannot create delegation link ledger: {error}"))?;
        let root = root
            .canonicalize()
            .map_err(|error| format!("cannot resolve delegation link ledger: {error}"))?;
        let (persists, _) = watch::channel(0);
        Ok(Self {
            core: Arc::new(LinkLedgerCore {
                root,
                gate: RwLock::new(()),
                persists,
                scans: parking_lot::Mutex::new(None),
            }),
        })
    }

    /// Compare before and after reads to detect concurrent persistence.
    pub fn persist_version(&self) -> Result<u64, String> {
        let _reader = self
            .core
            .gate
            .read()
            .map_err(|error| format!("delegation link gate: {error}"))?;
        Ok(*self.core.persists.borrow())
    }

    /// Subscribes to native persist notifications: the receiver's `u64` is
    /// the same counter [`Self::persist_version`] reads, bumped after every
    /// durable row commit. Wakeup only — read rows through the ledger, never
    /// treat the counter as row content.
    pub fn subscribe_persists(&self) -> tokio::sync::watch::Receiver<u64> {
        self.core.persists.subscribe()
    }

    /// The ledger directory. Its parent is the huginn root the lane-budget
    /// raise file shares with cargo-slot and kube admission.
    pub fn root(&self) -> &std::path::Path {
        &self.core.root
    }

    fn row_path(&self, child: &LiveSessionId) -> PathBuf {
        self.core.root.join(format!("{child}.json"))
    }

    /// Commits the row before notifying waiters, holding the write gate so scans
    /// cannot interleave. The row must be durable before token minting or opening.
    pub fn persist(&self, link: &DelegationLink) -> Result<(), String> {
        if link.schema != DELEGATION_LINK_SCHEMA {
            return Err("delegation link row carries a foreign schema".to_owned());
        }
        let _writer = self
            .core
            .gate
            .write()
            .map_err(|error| format!("delegation link gate: {error}"))?;
        // Lifecycle/report writers can hold an older row while a result
        // observer commits. Never erase its terminal or learning evidence.
        let mut link = std::borrow::Cow::Borrowed(link);
        if let Some(current) = self.load(&link.child)? {
            let result = current
                .learning_result_sequence
                .max(link.learning_result_sequence);
            let captured = current
                .learning_capture_sequence
                .max(link.learning_capture_sequence);
            let ended = current.phase == DelegationPhase::Ended;
            if result != link.learning_result_sequence
                || captured != link.learning_capture_sequence
                || (ended && link.phase != DelegationPhase::Ended)
            {
                let link = link.to_mut();
                link.learning_result_sequence = result;
                link.learning_capture_sequence = captured;
                if ended {
                    link.phase = DelegationPhase::Ended;
                }
            }
            // A stale whole-row write must not undo a handoff. The parent
            // moves only through `update`, which reloads under this gate.
            let parent_moved = link.parent != current.parent;
            // A newer delivered marker supersedes the old intent. Any other
            // clear of an unacknowledged report is stale unless `update`
            // applied it against the generation it observed.
            let superseded =
                link.reported_answer.is_some() && link.reported_answer != current.reported_answer;
            let restore_pending = !superseded
                && link.pending_report.is_none()
                && current.pending_report.as_ref().is_some_and(|pending| {
                    let aimed_here = super::contracts::live_session_id(&link.parent)
                        .ok()
                        .as_ref()
                        == Some(&pending.command.session_id);
                    let acknowledged =
                        link.reported_answer.as_deref() == Some(pending.key.as_str());
                    aimed_here && !acknowledged
                });
            let missing_raise = current
                .budget_raises
                .iter()
                .any(|raise| !link.budget_raises.contains(raise));
            let project_differs = link.project != current.project;
            if parent_moved || restore_pending || missing_raise || project_differs {
                let fresh = link.to_mut();
                if parent_moved {
                    fresh.parent = current.parent.clone();
                }
                if project_differs {
                    fresh.project = current.project.clone();
                }
                if restore_pending {
                    fresh.pending_report = current.pending_report.clone();
                }
                for raise in &current.budget_raises {
                    if !fresh.budget_raises.contains(raise) {
                        fresh.budget_raises.push(*raise);
                    }
                }
            }
        }
        self.commit_row(link.as_ref())?;
        self.committed();
        Ok(())
    }

    /// After a row is durable: refresh the published lane wall starts and wake waiters. A
    /// lease that cannot be published is logged, never returned, so an `Err` from a write
    /// always means the row did not commit.
    fn committed(&self) {
        let published = self.live_wall_starts().and_then(|starts| {
            let huginn = self.huginn_root();
            let current = odin_registry::LaneWallLease::load(huginn)
                .map_err(|error| format!("lane wall lease: {error}"))?
                .map(|lease| lease.lanes)
                .unwrap_or_default();
            if current != starts {
                odin_registry::LaneWallLease::publish(huginn, starts)
                    .map_err(|error| format!("lane wall lease: {error}"))?;
            }
            Ok(())
        });
        if let Err(error) = published {
            tracing::error!("odin-omp: delegation lane wall starts not published: {error}");
        }
        self.core
            .persists
            .send_modify(|version| *version = version.wrapping_add(1));
    }

    /// The huginn root the ledger directory sits in; the lane-wall lease and the
    /// lane-budget raise file live there.
    pub fn huginn_root(&self) -> &std::path::Path {
        self.core.root.parent().unwrap_or(&self.core.root)
    }

    /// Live-worker wall starts. The caller holds the write gate, so this
    /// scan does not take it again.
    fn live_wall_starts(&self) -> Result<std::collections::BTreeMap<String, u64>, String> {
        let mut starts = std::collections::BTreeMap::new();
        let entries = fs::read_dir(&self.core.root)
            .map_err(|error| format!("cannot list delegation link ledger: {error}"))?;
        for entry in entries {
            let entry =
                entry.map_err(|error| format!("delegation link listing failed: {error}"))?;
            let path = entry.path();
            if path.extension().and_then(|name| name.to_str()) != Some("json") {
                continue;
            }
            let bytes = match fs::read(&path) {
                Ok(bytes) => bytes,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                Err(error) => return Err(format!("cannot read delegation link row: {error}")),
            };
            let row: DelegationLink = serde_json::from_slice(&bytes).map_err(|error| {
                format!("delegation link row {} is invalid: {error}", path.display())
            })?;
            if !row.phase.is_live() {
                continue;
            }
            let Some(lane) = row.lane.as_ref() else {
                continue;
            };
            let slot = starts.entry(lane.as_str().to_owned()).or_insert(u64::MAX);
            *slot = (*slot).min(row.created_at_ms);
        }
        Ok(starts)
    }

    /// Reloads under the write gate and applies `mutate` to the committed row. A stale
    /// whole-row `persist` cannot undo this clear or reparent.
    pub fn update(
        &self,
        child: &LiveSessionId,
        mutate: impl FnOnce(&mut DelegationLink) -> bool,
    ) -> Result<bool, String> {
        let _writer = self
            .core
            .gate
            .write()
            .map_err(|error| format!("delegation link gate: {error}"))?;
        let Some(mut current) = self.load(child)? else {
            return Ok(false);
        };
        if !mutate(&mut current) {
            return Ok(false);
        }
        self.commit_row(&current)?;
        self.committed();
        Ok(true)
    }

    fn commit_row(&self, link: &DelegationLink) -> Result<(), String> {
        let path = self.row_path(&link.child);
        let temporary = self
            .core
            .root
            .join(format!(".{}.tmp-{}", link.child, std::process::id()));
        let bytes = serde_json::to_vec_pretty(link)
            .map_err(|error| format!("delegation link row is not serializable: {error}"))?;
        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&temporary)
            .map_err(|error| format!("cannot stage delegation link row: {error}"))?;
        file.write_all(&bytes)
            .and_then(|()| file.sync_all())
            .map_err(|error| format!("cannot write delegation link row: {error}"))?;
        drop(file);
        fs::rename(&temporary, path)
            .map_err(|error| format!("cannot commit delegation link row: {error}"))
    }

    /// Loads one row; `Ok(None)` when no link exists for the child.
    pub fn load(&self, child: &LiveSessionId) -> Result<Option<DelegationLink>, String> {
        let bytes = match fs::read(self.row_path(child)) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(format!("cannot read delegation link row: {error}")),
        };
        let link: DelegationLink = serde_json::from_slice(&bytes)
            .map_err(|error| format!("delegation link row for {child} is invalid: {error}"))?;
        if link.schema != DELEGATION_LINK_SCHEMA {
            return Err(format!(
                "delegation link row for {child} carries schema {:?}, not {DELEGATION_LINK_SCHEMA}",
                link.schema
            ));
        }
        if link.child != *child {
            return Err(format!(
                "delegation link row names child {}, not {child}",
                link.child
            ));
        }
        Ok(Some(link))
    }

    /// Rows ordered by creation time and child ID.
    /// The read gate excludes concurrent persists during the scan.
    /// Use [`Self::persist_version`] to detect changes across multiple reads.
    pub fn all_rows(&self) -> Result<Vec<PersistedLink>, String> {
        let _reader = self
            .core
            .gate
            .read()
            .map_err(|error| format!("delegation link gate: {error}"))?;
        let version = *self.core.persists.borrow();
        let modified = fs::metadata(&self.core.root)
            .and_then(|meta| meta.modified())
            .ok();
        {
            let scans = self.core.scans.lock();
            if let Some(scan) = scans.as_ref() {
                if scan.version == version && scan.modified == modified {
                    return Ok(scan.rows.clone());
                }
            }
        }
        let mut rows = Vec::new();
        let entries = match fs::read_dir(&self.core.root) {
            Ok(entries) => entries,
            Err(error) => return Err(format!("cannot list delegation link ledger: {error}")),
        };
        for entry in entries {
            let entry =
                entry.map_err(|error| format!("delegation link listing failed: {error}"))?;
            let path = entry.path();
            if path.extension().and_then(|name| name.to_str()) != Some("json") {
                continue;
            }
            let bytes = fs::read(&path)
                .map_err(|error| format!("cannot read delegation link row: {error}"))?;
            let link: DelegationLink = serde_json::from_slice(&bytes).map_err(|error| {
                format!("delegation link row {} is invalid: {error}", path.display())
            })?;
            if link.schema != DELEGATION_LINK_SCHEMA {
                return Err(format!(
                    "delegation link row {} carries schema {:?}",
                    path.display(),
                    link.schema
                ));
            }
            if path.file_stem().and_then(|name| name.to_str())
                != Some(link.child.to_string().as_str())
            {
                return Err(format!(
                    "delegation row {} does not match its child identity",
                    path.display()
                ));
            }
            rows.push(PersistedLink { link });
        }
        rows.sort_by(|left, right| {
            (left.link.created_at_ms, left.link.child)
                .cmp(&(right.link.created_at_ms, right.link.child))
        });
        *self.core.scans.lock() = Some(ScanMemo {
            version,
            modified,
            rows: rows.clone(),
        });
        Ok(rows)
    }

    /// Records that `predecessor`'s delegated children belong to `successor`
    /// once that vehicle is retired. The stop barrier reads this and
    /// re-points those children instead of stopping them. The file sits
    /// beside the rows, so every handle of this ledger root sees it.
    pub fn arm_successor(
        &self,
        predecessor: &SessionId,
        successor: &SessionId,
    ) -> Result<(), String> {
        if predecessor == successor {
            return Err("a vehicle cannot hand its children to itself".to_owned());
        }
        let path = self.handoff_path(predecessor);
        let temporary = self
            .core
            .root
            .join(format!(".{predecessor}.handoff-{}", std::process::id()));
        fs::write(&temporary, successor.as_str())
            .map_err(|error| format!("cannot record the successor handoff: {error}"))?;
        fs::rename(&temporary, &path)
            .map_err(|error| format!("cannot record the successor handoff: {error}"))?;
        Ok(())
    }

    /// The successor armed for `predecessor`, if a retirement handoff is pending.
    pub fn armed_successor(&self, predecessor: &SessionId) -> Result<Option<SessionId>, String> {
        match fs::read_to_string(self.handoff_path(predecessor)) {
            Ok(text) => {
                let successor = SessionId::new(text.trim()).map_err(|error| {
                    format!("successor handoff for {predecessor} is invalid: {error}")
                })?;
                Ok(Some(successor))
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(format!("cannot read the successor handoff: {error}")),
        }
    }

    /// Drops a handoff after its children have been re-pointed.
    pub fn clear_successor(&self, predecessor: &SessionId) -> Result<(), String> {
        match fs::remove_file(self.handoff_path(predecessor)) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(format!("cannot clear the successor handoff: {error}")),
        }
    }

    fn handoff_path(&self, predecessor: &SessionId) -> PathBuf {
        self.core.root.join(format!("{predecessor}.handoff"))
    }

    /// Moves live children of `from` onto `to` without stopping them.
    /// Already-ended rows stay. Idempotent if they already name `to`.
    pub fn repoint_children(
        &self,
        from: &SessionId,
        to: &SessionId,
    ) -> Result<Vec<LiveSessionId>, String> {
        if from == to {
            return Ok(Vec::new());
        }
        let mut moved = Vec::new();
        for link in self.children_of(from)? {
            if !link.phase.is_live() {
                continue;
            }
            if self.update(&link.child, |fresh| fresh.hand_to(to))? {
                moved.push(link.child);
            }
        }
        Ok(moved)
    }

    /// Loads every row naming `parent`, ordered by creation instant.
    pub fn children_of(&self, parent: &SessionId) -> Result<Vec<DelegationLink>, String> {
        Ok(self
            .all_rows()?
            .into_iter()
            .filter(|persisted| persisted.link.parent == *parent)
            .map(|persisted| persisted.link)
            .collect())
    }
}
