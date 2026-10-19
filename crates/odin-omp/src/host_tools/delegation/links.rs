//! Atomic delegation rows used for parent-link verification and concurrency limits.

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::PathBuf;
use std::sync::{Arc, RwLock};

use odin_domain::huginn::{LiveCommand, LiveSessionId};
use odin_domain::{CommandId, Digest, ProjectId, RunId, SeatId, SessionId};
use serde::{Deserialize, Serialize};
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
    /// The fixed configured worker provider.
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
}

/// One durable row plus the digest of its exact persisted bytes: the
/// content binding a projection head uses to observe file-backed changes.
#[derive(Clone, Debug)]
pub struct PersistedLink {
    pub link: DelegationLink,
    pub row_digest: String,
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
            }),
        })
    }

    /// Compare before and after reads to detect concurrent persistence.
    pub fn persist_version(&self) -> Result<u64, String> {
        let _reader = self
            .core
            .gate
            .read()
            .map_err(|_| "delegation link gate is poisoned".to_owned())?;
        Ok(*self.core.persists.borrow())
    }

    /// Subscribes to native persist notifications: the receiver's `u64` is
    /// the same counter [`Self::persist_version`] reads, bumped after every
    /// durable row commit. Wakeup only — read rows through the ledger, never
    /// treat the counter as row content.
    pub fn subscribe_persists(&self) -> tokio::sync::watch::Receiver<u64> {
        self.core.persists.subscribe()
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
        let path = self.row_path(&link.child);
        let temporary = self
            .core
            .root
            .join(format!(".{}.tmp-{}", link.child, std::process::id()));
        let _writer = self
            .core
            .gate
            .write()
            .map_err(|_| "delegation link gate is poisoned".to_owned())?;
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
        }
        let bytes = serde_json::to_vec_pretty(link.as_ref())
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
        fs::rename(&temporary, &path)
            .map_err(|error| format!("cannot commit delegation link row: {error}"))?;
        self.core
            .persists
            .send_modify(|version| *version = version.wrapping_add(1));
        Ok(())
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

    /// Rows and their digests, ordered by creation time and child ID.
    /// The read gate excludes concurrent persists during the scan.
    /// Use [`Self::persist_version`] to detect changes across multiple reads.
    pub fn all_rows(&self) -> Result<Vec<PersistedLink>, String> {
        let _reader = self
            .core
            .gate
            .read()
            .map_err(|_| "delegation link gate is poisoned".to_owned())?;
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
            rows.push(PersistedLink {
                row_digest: Digest::hash(&bytes).to_string(),
                link,
            });
        }
        rows.sort_by(|left, right| {
            (left.link.created_at_ms, left.link.child)
                .cmp(&(right.link.created_at_ms, right.link.child))
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
        for mut link in self.children_of(from)? {
            if !matches!(
                link.phase,
                DelegationPhase::Provisioning | DelegationPhase::Running
            ) {
                continue;
            }
            link.parent = to.clone();
            self.persist(&link)?;
            moved.push(link.child);
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
