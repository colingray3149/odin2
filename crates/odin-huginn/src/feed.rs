//! Durable feeds: the projection and stream producers that carry governed
//! live-session and approval facts from the durable ledgers into the shared
//! read model and the durable `stream_items` replay store.
//!
//! Three feeds, all cursor-driven and bounded page by page:
//!
//! * Feed A (sessions) adopts the bounded live roster snapshot the live
//!   plane exposes, projects it through the [`SessionProjectionStore`] with
//!   freshness derived deterministically from the adopted source state (so
//!   re-materializing an identical source state is a no-op, never a
//!   same-revision freshness conflict), and tombstones every session the
//!   roster evicted — terminal reclaim is the truth; history stays
//!   ledger-only.
//! * The durable change feed discovers session events INCREMENTALLY: the
//!   live ledger journals every event-head movement as one durable change
//!   frame in global arrival order; the pump consumes ONE bounded page per
//!   tick and advances the durable ordinal only AFTER the page's payload
//!   and frames are published. A session that appears and ends between
//!   ticks is delivered by its change entries; a restart mid-drain resumes
//!   from the durable replay head (frame sequence k is live event k), so
//!   nothing is lost and nothing is scanned cyclically.
//! * Feed B (approvals) consumes the ledger's durable monotonic approval
//!   event cursor through [`odin_ledger::Ledger::approval_feed_after`] and
//!   projects each committed transition — never a full-history scan.

use std::collections::{BTreeMap, BTreeSet};
use std::num::NonZeroU16;
use std::sync::Arc;

use odin_domain::huginn::{
    ArtifactRef, EventSeq, Freshness, FreshnessState, HistoryQuery, HuginnMessage,
    HuginnProtocolError, LiveError, LiveEvent, LiveSessionId, LiveSessionSummary, LiveStreamKind,
    ObjectKind, ObjectRef, OmpLivePlane, Revision, RevisionSource, RosterRevision, SeatRoster,
    Sequence, StreamBackpressureLimits, StreamFrame, StreamId,
};
use odin_ledger::Ledger;
use time::OffsetDateTime;

use crate::approvals::{ApprovalProjection, ApprovalView};
use crate::read_model::MaterializedReadModel;
use crate::service::FsPublishedArtifactStore;
use crate::sessions::SessionProjectionStore;
use crate::streams::{BoundedMultiplexer, MultiplexedItem};

mod terminal;

/// Bounded approval-feed page the consumer requests per tick.
pub const APPROVAL_FEED_PAGE: usize = 512;

/// The deterministic freshness of one adopted source state: observed and
/// source-updated at the newest durable fact the state carries, or the Unix
/// epoch when it carries no session facts at all. A pure function of the
/// adopted state — never of wall-clock observation time.
fn source_freshness<'a>(sessions: impl IntoIterator<Item = &'a LiveSessionSummary>) -> Freshness {
    let source_updated_at = sessions.into_iter().map(|session| session.updated_at).max();
    Freshness {
        state: FreshnessState::Fresh,
        observed_at: source_updated_at.unwrap_or(OffsetDateTime::UNIX_EPOCH),
        source_updated_at,
        stale_after_seconds: None,
    }
}

/// The deterministic wall-clock-free generated_at stamp of one adopted
/// roster: the newest durable session fact, or the Unix epoch for a
/// session-free roster.
fn source_generated_at(roster: &SeatRoster) -> OffsetDateTime {
    roster
        .seats
        .iter()
        .flat_map(|seat| {
            seat.active_sessions
                .iter()
                .map(|session| session.updated_at)
        })
        .max()
        .unwrap_or(OffsetDateTime::UNIX_EPOCH)
}

/// Assigns the strictly increasing projection revision for adopted roster
/// states. The plane's roster revision is a content digest — equal source
/// state yields an equal digest, which detects change but is not numerically
/// monotonic — so the feed maps it: unchanged digest keeps the current
/// revision (idempotent re-adoption), a changed digest takes the next one.
#[derive(Default)]
struct RosterRevisioner {
    last_digest: Option<[u8; 32]>,
    last_revision: u64,
}

impl RosterRevisioner {
    /// Assigns the adopted roster's revision. Registry-seeded object truth
    /// and runtime adoption share the read model's per-object revision
    /// space: at each GENUINELY CHANGED adopted state the next revision is
    /// at least the relevant read-model revision + 1 (checked), so a
    /// registry republish can never be regressed or wedged; an idempotent
    /// retry of the SAME adopted state keeps its revision. `floor` is the
    /// caller-computed maximum current read-model revision over the
    /// objects this adoption publishes.
    fn revision_for(
        &mut self,
        roster: &SeatRoster,
        floor: u64,
    ) -> Result<RosterRevision, HuginnProtocolError> {
        let canonical =
            serde_json::to_vec(roster).map_err(|_| HuginnProtocolError::InvalidRequest {
                code: "rosterFeedSerialization".to_owned(),
                message: "adopted roster could not be canonicalized".to_owned(),
            })?;
        let digest = *blake3::hash(&canonical).as_bytes();
        if self.last_digest == Some(digest) {
            // Idempotent retry of the same adopted source state — unless a
            // registry republish advanced the shared revision space past
            // our last adoption: the retry then clears the external head
            // at floor+1 instead of republishing a stale revision.
            if floor > self.last_revision {
                let next = floor
                    .checked_add(1)
                    .ok_or(HuginnProtocolError::ResourceLimit {
                        limit: "rosterFeedRevisions".to_owned(),
                    })?;
                self.last_revision = next;
                self.last_digest = Some(digest);
                return Ok(RosterRevision::new(next));
            }
            return Ok(RosterRevision::new(self.last_revision));
        }
        let next = self.last_revision.max(floor).checked_add(1).ok_or(
            HuginnProtocolError::ResourceLimit {
                limit: "rosterFeedRevisions".to_owned(),
            },
        )?;
        self.last_revision = next;
        self.last_digest = Some(digest);
        Ok(RosterRevision::new(next))
    }
}

/// One adopted roster tick.
pub struct AdoptedRoster {
    pub revision: RosterRevision,
    /// The live sessions the adopted roster exposes, in canonical order.
    pub live_sessions: Vec<LiveSessionSummary>,
    /// Sessions the roster evicted (terminal reclaim): already removed from
    /// the projection store and tombstoned in the read model.
    pub evicted: Vec<LiveSessionId>,
}

/// Feed A: the bounded roster/session projection.
pub struct RosterFeed {
    store: Arc<SessionProjectionStore>,
    revisioner: std::sync::Mutex<RosterRevisioner>,
}

impl RosterFeed {
    pub fn new(store: Arc<SessionProjectionStore>) -> Self {
        Self {
            store,
            revisioner: std::sync::Mutex::new(RosterRevisioner::default()),
        }
    }

    /// Adopts one plane roster snapshot: normalizes the wall-clock
    /// generated_at stamp deterministically from the adopted source state,
    /// assigns the monotonic feed revision BEFORE replacing, replaces the
    /// projection roster with the exact adopted set, tombstones the exact
    /// removed sessions, and materializes Seat/Session/roster objects with
    /// source-derived freshness. Re-adopting an identical source state is a
    /// full no-op that consumes no revision and re-publishes nothing.
    pub fn adopt(
        &self,
        read_model: &MaterializedReadModel,
        mut roster: SeatRoster,
    ) -> Result<AdoptedRoster, HuginnProtocolError> {
        roster.generated_at = source_generated_at(&roster);
        let freshness = source_freshness(
            roster
                .seats
                .iter()
                .flat_map(|seat| seat.active_sessions.iter()),
        );
        let live_sessions: Vec<LiveSessionSummary> = roster
            .seats
            .iter()
            .flat_map(|seat| seat.active_sessions.iter().cloned())
            .collect();
        let adopted: BTreeSet<LiveSessionId> = live_sessions
            .iter()
            .map(|session| session.session_id)
            .collect();
        let mut revision_floor = 0;
        for seat in &roster.seats {
            let current = read_model
                .current_revision(&ObjectRef {
                    kind: ObjectKind::Seat,
                    id: seat.seat_id.to_string(),
                })
                .map_err(|error| HuginnProtocolError::InvalidRequest {
                    code: "rosterFeedRevisionFloor".to_owned(),
                    message: error.to_string(),
                })?;
            if let Some(revision) = current {
                revision_floor = revision_floor.max(revision.get());
            }
        }
        let revision = self
            .revisioner
            .lock()
            .map_err(|_| HuginnProtocolError::InvalidRequest {
                code: "rosterFeedState".to_owned(),
                message: "roster feed state is unavailable".to_owned(),
            })?
            .revision_for(&roster, revision_floor)?;
        // The monotonic feed revision replaces the digest: the projection
        // store's revision gates compare it monotonically.
        roster.revision = revision;
        // Terminal removal is derived BEFORE the replacement, from the exact
        // prior working set, so a session removed without an Ended pass is
        // still tombstoned (and re-tombstoning an already-removed object is
        // an idempotent no-op if a previous tick failed mid-way).
        let prior = self.store.session_ids()?;
        let removed: Vec<LiveSessionId> = prior
            .iter()
            .copied()
            .filter(|session| !adopted.contains(session))
            .collect();
        let to_revision = Revision::new(revision.get());
        for object in read_model.objects_of_kind(ObjectKind::Terminal)? {
            if !live_sessions.iter().any(|session| {
                terminal::eligible(session) && session.session_id.to_string() == object.id
            }) {
                let revision = read_model
                    .current_revision(&object)?
                    .unwrap_or(Revision::new(0));
                let next = revision.get().checked_add(1).ok_or_else(|| {
                    HuginnProtocolError::InvalidRequest {
                        code: "terminalFeedRevision".to_owned(),
                        message: "terminal projection revision exhausted".to_owned(),
                    }
                })?;
                read_model.remove(
                    object,
                    Revision::new(next),
                    RevisionSource::Omp,
                    freshness.clone(),
                )?;
            }
        }
        for session_id in &removed {
            read_model.remove(
                ObjectRef {
                    kind: ObjectKind::Session,
                    id: session_id.to_string(),
                },
                to_revision,
                RevisionSource::Omp,
                freshness.clone(),
            )?;
        }
        self.store.replace_roster(roster)?;
        self.store
            .materialize_roster(read_model, freshness.clone())?;
        Ok(AdoptedRoster {
            revision,
            live_sessions,
            evicted: removed,
        })
    }
}

/// The durable agent-events stream of one live session is identified by the
/// session id itself — the identity `odin huginn watch --kind agent-events
/// --stream <session>` subscribes to.
pub fn agent_event_stream(session: LiveSessionId) -> StreamId {
    StreamId::parse(&session.to_string())
        .expect("a live session id is always a valid durable stream id")
}

/// One durable change entry: a session whose event head moved, at the
/// journal's durable ordinal. The consumer persists the last ordinal only
/// after publishing the entry's payload and frames.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SessionChange {
    pub position: u64,
    pub session_id: LiveSessionId,
    pub head: u64,
}

/// Durable incremental session discovery: ONE bounded page of the live
/// ledger's change journal, strictly after the durable ordinal `after`
/// (0 = the journal beginning), in arrival order. The daemon binds the live
/// ledger's own change-journal reader; the error is the live plane's typed
/// error.
#[async_trait::async_trait]
pub trait DurableSessionDiscovery: Send + Sync {
    async fn changes_after(
        &self,
        after: u64,
        limit: usize,
    ) -> Result<Vec<SessionChange>, LiveError>;
}

/// The result of one bounded tail call against one session's durable
/// history.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TailOutcome {
    /// Frames were published; more may remain on later ticks.
    Published(usize),
    /// The durable history is fully drained through its observed head.
    CaughtUp,
    /// The ledger holds no history for this session at all.
    Unknown,
}

/// Feed A stream producer: tails durable session history into the durable
/// agent-events replay store, one bounded page per call, never skipping an
/// event sequence. Frame sequence k is live event k, so the durable replay
/// head is the resume cursor across restarts.
pub struct SessionEventFeed {
    streams: Arc<BoundedMultiplexer>,
    artifacts: Arc<FsPublishedArtifactStore>,
    /// Single-frame payload ceiling: the declared stream frame bound.
    max_payload_bytes: u64,
    /// Next live-event sequence to publish per session. The map holds only
    /// sessions with observed change entries whose tail is not yet caught
    /// up: adopted live sessions, and terminal sessions mid-drain (released
    /// at CaughtUp; the next change entry re-seeds them if anything moves).
    cursors: BTreeMap<LiveSessionId, u64>,
    terminal_after: Option<LiveSessionId>,
}

impl SessionEventFeed {
    pub fn new(
        streams: Arc<BoundedMultiplexer>,
        artifacts: Arc<FsPublishedArtifactStore>,
        backpressure: StreamBackpressureLimits,
        max_payload_bytes: u64,
    ) -> Self {
        // The durable Event envelope has no status counters for these backpressure limits.
        let _ = backpressure;
        Self {
            streams,
            artifacts,
            max_payload_bytes,
            cursors: BTreeMap::new(),
            terminal_after: None,
        }
    }

    /// Resumes (or re-seeds) one session's cursor from the durable replay
    /// head, so a restart continues exactly after the last retained frame.
    pub fn resume_session(&mut self, session: LiveSessionId) -> Result<(), HuginnProtocolError> {
        let head = self.streams.durable_head(&agent_event_stream(session))?;
        self.cursors.insert(session, head.get());
        Ok(())
    }

    /// Releases every cursor NOT in `allowed`, keeping the map bounded to
    /// the adopted roster plus the pending discovery page. Progress is
    /// never lost: the durable replay head is the authoritative resume
    /// point and a later change entry re-seeds from it.
    pub fn prune_except(&mut self, allowed: &BTreeSet<LiveSessionId>) {
        self.cursors.retain(|session, _| allowed.contains(session));
    }

    /// Ensures every adopted live session has a cursor.
    pub fn adopt_sessions(
        &mut self,
        live_sessions: impl IntoIterator<Item = LiveSessionId>,
    ) -> Result<(), HuginnProtocolError> {
        for session in live_sessions {
            if !self.cursors.contains_key(&session) {
                self.resume_session(session)?;
            }
        }
        Ok(())
    }

    /// Applies one durable change entry: a session with a live cursor is
    /// already draining; otherwise the entry seeds a cursor from the
    /// durable replay head. Appears-and-ends-between-ticks sessions arrive
    /// through their change entries exactly like live ones.
    pub fn note_change(
        &mut self,
        session: LiveSessionId,
        head: u64,
    ) -> Result<(), HuginnProtocolError> {
        // Resume from persisted replay unless the cursor already covers this entry.
        // Errors keep the discovery cursor from advancing past unpublished data.
        match self.cursors.get(&session) {
            Some(cursor) if *cursor >= head => Ok(()),
            _ => self.resume_session(session),
        }
    }

    /// Tails at most one bounded history page for one session and publishes
    /// exactly one durable frame per event. On [`TailOutcome::CaughtUp`]
    /// (durable history fully drained through its observed head) or
    /// [`TailOutcome::Unknown`] (no durable history at all) the cursor is
    /// released: an adopted session simply re-seeds from the replay head
    /// later, a terminal session is dropped, and any later head movement
    /// arrives as a fresh durable change entry that re-seeds it.
    pub async fn tail(
        &mut self,
        plane: &dyn OmpLivePlane,
        session: LiveSessionId,
        control_revision: u64,
        target_head: u64,
        page_limit: NonZeroU16,
        now: OffsetDateTime,
    ) -> Result<TailOutcome, HuginnProtocolError> {
        let stream_id = agent_event_stream(session);
        let after = match self.cursors.get(&session) {
            Some(cursor) if *cursor >= target_head => {
                // Already replayed past the recorded target: the entry is
                // satisfied without any publication work.
                return Ok(TailOutcome::CaughtUp);
            }
            Some(cursor) => *cursor,
            None => {
                self.resume_session(session)?;
                self.cursors[&session]
            }
        };
        // A page never crosses the recorded target head: newer events stay
        // for the change entries that recorded them.
        let headroom = target_head.saturating_sub(after);
        let bound = page_limit
            .get()
            .min(u16::try_from(headroom).unwrap_or(u16::MAX))
            .max(1);
        let page = match plane
            .history(HistoryQuery {
                session_id: session,
                after: EventSeq::new(after),
                limit: NonZeroU16::new(bound).unwrap_or(page_limit),
            })
            .await
        {
            Ok(page) => page,
            Err(LiveError::NotFound { .. }) => {
                self.cursors.remove(&session);
                return Ok(TailOutcome::Unknown);
            }
            Err(error) => return Err(crate::state::live_error_into_protocol(error)),
        };
        let mut published = 0;
        for event in page.events {
            let content = self.publish_event_payload(&event).await?;
            let sequence = Sequence::new(event.sequence.get());
            // The frame's timestamp is the DURABLE event fact, never the
            // tick's wall clock: a retried publication of the same event is
            // byte-stable and cannot conflict at its sequence.
            let frame = StreamFrame {
                stream_id,
                kind: LiveStreamKind::AgentEvents,
                sequence,
                control_revision,
                produced_at: event.occurred_at,
                key_frame: true,
                content,
            };
            // The wire surface is the EXISTING Event envelope: the stock
            // client receives the actual durable agent event (whose body
            // carries the payload ArtifactRef), not counters alone.
            let message = HuginnMessage::Event(event.clone());
            self.streams
                .publish(MultiplexedItem::new(frame, message), now)?;
            self.cursors.insert(session, event.sequence.get());
            published += 1;
        }
        if page.head.get() < target_head {
            // The source's durable head is BEHIND a committed change head:
            // journal/ledger divergence is typed corruption, never success.
            return Err(HuginnProtocolError::InvalidRequest {
                code: "durable_history_behind_journal".to_owned(),
                message: format!(
                    "session {} durable head {} is behind journaled target {target_head}",
                    session, page.head
                ),
            });
        }
        if page.next_after >= page.head || self.cursors[&session] >= target_head {
            self.cursors.remove(&session);
            return Ok(TailOutcome::CaughtUp);
        }
        Ok(TailOutcome::Published(published))
    }

    /// Publishes the canonical event payload, or an honest omission marker
    /// when the payload exceeds the declared frame bound — the store stays
    /// dense either way, so replay ordering and resume cursors hold.
    async fn publish_event_payload(
        &self,
        event: &LiveEvent,
    ) -> Result<ArtifactRef, HuginnProtocolError> {
        let canonical =
            serde_json::to_vec(event).map_err(|_| HuginnProtocolError::InvalidRequest {
                code: "agentEventFeedSerialization".to_owned(),
                message: "live event could not be serialized for the durable stream".to_owned(),
            })?;
        let payload = if canonical.len() as u64 <= self.max_payload_bytes {
            canonical
        } else {
            let marker = serde_json::to_vec(&serde_json::json!({
                "schemaVersion": 1,
                "sessionId": event.session_id.to_string(),
                "eventId": event.event_id.to_string(),
                "sequence": event.sequence.get(),
                "omitted": true,
                "reason": "event payload exceeds the declared stream frame bound",
            }))
            .map_err(|_| HuginnProtocolError::InvalidRequest {
                code: "agentEventFeedSerialization".to_owned(),
                message: "omission marker could not be serialized".to_owned(),
            })?;
            // The marker itself must respect the configured ceiling, or the
            // ceiling is misconfigured and the feed refuses typed instead of
            // silently violating it.
            if marker.len() as u64 > self.max_payload_bytes {
                return Err(HuginnProtocolError::ResourceLimit {
                    limit: "maxStreamFrameBytes".to_owned(),
                });
            }
            marker
        };
        self.artifacts
            .publish_feed_payload(
                event.session_id,
                &format!("event-{}", event.sequence.get()),
                &payload,
            )
            .await
    }
}

/// Feed B consumer: projects committed approval changes through the
/// durable monotonic ledger cursor, with FAIR bounded interleaving per
/// tick: (1) one durable backfill page journals approval rows that predate
/// the feed, (2) one bounded history-replay page re-projects older
/// committed changes, and (3) one bounded live-tail page projects the
/// newest transitions from the baseline head forward — so the live tail is
/// never starved behind history replay, and no phase ever scans more than
/// its declared page. All three cursors are O(1) durable ordinals/ids.
pub struct ApprovalFeed {
    /// Live-tail cursor: initialized to the durable head at the first tick,
    /// then advanced exactly once per projected row.
    live_cursor: Option<i64>,
    /// History-replay cursor: walks the journal from zero, one page per
    /// tick, skipping projections already superseded by newer revisions.
    history_cursor: i64,
    /// Durable bootstrap backfill cursor over the approval row set.
    backfill_cursor: Option<String>,
}

impl Default for ApprovalFeed {
    fn default() -> Self {
        Self::new()
    }
}

impl ApprovalFeed {
    pub fn new() -> Self {
        Self {
            live_cursor: None,
            history_cursor: 0,
            backfill_cursor: Some(String::new()),
        }
    }

    fn project(
        rows: &[odin_ledger::approval_feed::ApprovalFeedRow],
        projection: &ApprovalProjection<impl crate::approvals::ProjectionPort>,
        cursor: &mut i64,
    ) -> Result<usize, HuginnProtocolError> {
        let mut projected = 0;
        for row in rows {
            let view = ApprovalView::try_from(&row.approval)?;
            match projection.publish(view.clone(), std::iter::empty(), std::iter::empty()) {
                Ok(_) => {
                    *cursor = row.sequence;
                    projected += 1;
                }
                // Skip replayed rows only when the read model is already at or past their revision.
                Err(HuginnProtocolError::RevisionMismatch { actual, expected }) => {
                    let row_revision = u64::try_from(row.approval.revision).unwrap_or(u64::MAX);
                    if actual.get() >= expected.get() && row_revision == expected.get() {
                        *cursor = row.sequence;
                    } else {
                        return Err(HuginnProtocolError::RevisionMismatch { actual, expected });
                    }
                }
                Err(error) => return Err(error),
            }
        }
        Ok(projected)
    }

    /// Drains at most one bounded page per phase, in fairness order: live
    /// tail first, then history replay, then bootstrap backfill. Returns
    /// the number of transitions projected; every cursor advances exactly
    /// once per applied row, so a restart can never skip a committed
    /// change.
    pub fn drain(
        &mut self,
        ledger: &mut Ledger,
        projection: &ApprovalProjection<impl crate::approvals::ProjectionPort>,
    ) -> Result<usize, HuginnProtocolError> {
        let mut projected = 0;
        // (3) Live tail: the baseline head is taken at the first tick, so
        // every transition committed after adoption projects immediately
        // and is never queued behind history replay.
        if self.live_cursor.is_none() {
            self.live_cursor = Some(ledger.approval_feed_head().map_err(|error| {
                HuginnProtocolError::InvalidRequest {
                    code: "approvalFeedRead".to_owned(),
                    message: error.to_string(),
                }
            })?);
        }
        let live_after = self.live_cursor.unwrap_or(0);
        let rows = ledger
            .approval_feed_after(live_after, APPROVAL_FEED_PAGE)
            .map_err(|error| HuginnProtocolError::InvalidRequest {
                code: "approvalFeedRead".to_owned(),
                message: error.to_string(),
            })?;
        projected += Self::project(
            &rows,
            projection,
            match &mut self.live_cursor {
                Some(cursor) => cursor,
                None => unreachable!("baseline established above"),
            },
        )?;
        // (2) History replay: one bounded page per tick from zero.
        if self.history_cursor
            <= ledger
                .approval_feed_head()
                .map_err(|error| HuginnProtocolError::InvalidRequest {
                    code: "approvalFeedRead".to_owned(),
                    message: error.to_string(),
                })?
        {
            let rows = ledger
                .approval_feed_after(self.history_cursor, APPROVAL_FEED_PAGE)
                .map_err(|error| HuginnProtocolError::InvalidRequest {
                    code: "approvalFeedRead".to_owned(),
                    message: error.to_string(),
                })?;
            projected += Self::project(&rows, projection, &mut self.history_cursor)?;
        }
        // (1) Bootstrap backfill: journal pre-feed rows, one bounded page.
        if let Some(after_id) = self.backfill_cursor.clone() {
            match ledger
                .backfill_approval_feed_page(&after_id, APPROVAL_FEED_PAGE)
                .map_err(|error| HuginnProtocolError::InvalidRequest {
                    code: "approvalFeedBackfill".to_owned(),
                    message: error.to_string(),
                })? {
                Some(last_id) => self.backfill_cursor = Some(last_id),
                None => self.backfill_cursor = None,
            }
        }
        Ok(projected)
    }
}

/// The one durable-feeds pump: Feed A (roster adoption, incremental change
/// consumption, per-session tails) then Feed B (fair approval drain). Every
/// source read is a bounded page; a typed failure is logged once per
/// CHANGED failure (never a repeating identical error every tick).
pub struct DurableFeedPump {
    posture: crate::state::NodePosture,
    plane: Arc<dyn OmpLivePlane>,
    ledger: Arc<std::sync::Mutex<Ledger>>,
    discovery: Arc<dyn DurableSessionDiscovery>,
    discovery_cursor_path: Option<std::path::PathBuf>,
    /// The durable discovery ordinal: the last journal position whose
    /// change entry was FULLY published. Loaded checked at startup; a
    /// fault freezes consumption until the operator repairs the file.
    discovery_cursor: tokio::sync::Mutex<u64>,
    /// Startup-loaded cursor fault: a corrupt or unreadable cursor file
    /// freezes discovery consumption for the whole process lifetime until
    /// the operator repairs the file and restarts. Never polled per tick.
    cursor_fault: std::sync::Mutex<Option<String>>,
    /// ONE bounded pending discovery page: entries whose recorded head is
    /// not yet fully published. A restart re-reads the same pending entry
    /// from the journal and replay-head dedup absorbs published frames.
    pending: tokio::sync::Mutex<std::collections::VecDeque<SessionChange>>,
    read_model: Arc<MaterializedReadModel>,
    roster_feed: Arc<RosterFeed>,
    event_feed: Arc<tokio::sync::Mutex<SessionEventFeed>>,
    approval_feed: Arc<std::sync::Mutex<ApprovalFeed>>,
    history_page: NonZeroU16,
    discovery_page: usize,
    last_errors: std::sync::Mutex<std::collections::BTreeMap<String, String>>,
}

impl DurableFeedPump {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        posture: crate::state::NodePosture,
        plane: Arc<dyn OmpLivePlane>,
        ledger: Arc<std::sync::Mutex<Ledger>>,
        discovery: Arc<dyn DurableSessionDiscovery>,
        discovery_cursor_path: Option<std::path::PathBuf>,
        read_model: Arc<MaterializedReadModel>,
        roster_feed: Arc<RosterFeed>,
        event_feed: Arc<tokio::sync::Mutex<SessionEventFeed>>,
        approval_feed: ApprovalFeed,
        history_page: NonZeroU16,
        discovery_page: usize,
    ) -> Self {
        let (initial_cursor, startup_fault) =
            match Self::load_discovery_cursor(&discovery_cursor_path) {
                Ok(position) => (position, None),
                Err(fault) => (0, Some(fault)),
            };
        Self {
            posture,
            plane,
            ledger,
            discovery,
            discovery_cursor: tokio::sync::Mutex::new(initial_cursor),
            cursor_fault: std::sync::Mutex::new(startup_fault),
            discovery_cursor_path,
            pending: tokio::sync::Mutex::new(std::collections::VecDeque::new()),
            read_model,
            roster_feed,
            event_feed,
            approval_feed: Arc::new(std::sync::Mutex::new(approval_feed)),
            history_page,
            discovery_page: discovery_page.max(1),
            last_errors: std::sync::Mutex::new(std::collections::BTreeMap::new()),
        }
    }

    /// Loads the durable discovery ordinal checked at startup: the file
    /// holds exactly one base-10 u64. A missing file is ordinal 0 (read
    /// from the journal beginning; replay-head dedup makes that safe). A
    /// corrupt or unreadable file is a fault: consumption stays frozen
    /// (typed, logged once) until the operator repairs it — silently
    /// restarting from 0 could re-publish and, worse, mask how far the
    /// feed had actually progressed.
    fn load_discovery_cursor(path: &Option<std::path::PathBuf>) -> Result<u64, String> {
        let Some(path) = path else {
            return Ok(0);
        };
        match std::fs::read_to_string(path) {
            Ok(text) => text.trim().parse::<u64>().map_err(|error| {
                format!("discovery cursor {path:?} is not a valid ordinal: {error}")
            }),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(0),
            Err(error) => Err(format!(
                "discovery cursor {path:?} could not be read: {error}"
            )),
        }
    }

    /// Logs a failure only when it CHANGES for the named source, so a stuck
    /// condition produces one line, not one line per tick.
    fn log_failure(&self, source: &str, message: String) {
        if let Ok(mut last) = self.last_errors.lock() {
            if last.get(source).map(String::as_str) != Some(message.as_str()) {
                tracing::warn!(%source, %message, "durable feed failure");
                last.insert(source.to_owned(), message);
            }
        }
    }

    /// Persists the durable change ordinal AFTER the page's payload/frames
    /// are published. Atomic single-record file (0600); absence means the
    /// journal is read from its beginning, which only re-delivers entries
    /// the idempotent per-session cursors deduplicate.
    /// Clears a source's recorded failure after a successful operation, so
    /// a later failure of that source logs again immediately.
    fn clear_failure(&self, source: &str) {
        if let Ok(mut last) = self.last_errors.lock() {
            last.remove(source);
        }
    }

    fn persist_discovery_cursor(
        path: &Option<std::path::PathBuf>,
        position: u64,
    ) -> Result<(), String> {
        let Some(path) = path else {
            return Ok(());
        };
        let temporary = path.with_extension("tmp");
        let persist = (|| -> std::io::Result<()> {
            #[cfg(unix)]
            let mut file = {
                use std::os::unix::fs::OpenOptionsExt as _;
                std::fs::OpenOptions::new()
                    .write(true)
                    .create(true)
                    .truncate(true)
                    .mode(0o600)
                    .open(&temporary)?
            };
            #[cfg(not(unix))]
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .open(&temporary)?;
            use std::io::Write as _;
            file.write_all(position.to_string().as_bytes())?;
            file.sync_all()?;
            drop(file);
            std::fs::rename(&temporary, path)?;
            if let Some(parent) = path.parent() {
                if let Ok(dir) = std::fs::File::open(parent) {
                    dir.sync_all()?;
                }
            }
            Ok(())
        })();
        persist.map_err(|error| format!("could not persist discovery cursor: {error}"))
    }

    pub async fn tick(&self) {
        if self.posture != crate::state::NodePosture::Authoritative {
            return;
        }
        let mut event_feed = self.event_feed.lock().await;
        let mut adopted: BTreeSet<LiveSessionId> = BTreeSet::new();
        let mut control_revision = 0;
        match self.plane.roster().await {
            Ok(roster) => match self.roster_feed.adopt(&self.read_model, roster) {
                Ok(adopted_roster) => {
                    adopted.extend(adopted_roster.live_sessions.iter().map(|s| s.session_id));
                    control_revision = adopted_roster.revision.get();
                    let eligible = || {
                        adopted_roster
                            .live_sessions
                            .iter()
                            .filter(|session| terminal::eligible(session))
                    };
                    let next = eligible()
                        .filter(|session| {
                            event_feed
                                .terminal_after
                                .is_none_or(|after| session.session_id > after)
                        })
                        .min_by_key(|session| session.session_id)
                        .or_else(|| eligible().min_by_key(|session| session.session_id));
                    if let Some(session) = next {
                        event_feed.terminal_after = Some(session.session_id);
                        // Keyed per session: captures rotate across sessions,
                        // so one shared key relogged each failing one per tick.
                        let source = format!("terminal:{}", session.session_id);
                        match event_feed
                            .terminal(self.plane.as_ref(), &self.read_model, session)
                            .await
                        {
                            Ok(()) => self.clear_failure(&source),
                            Err(error) => self.log_failure(
                                &source,
                                format!(
                                    "session {} terminal capture failed: {error}",
                                    session.session_id
                                ),
                            ),
                        }
                    }
                }
                Err(error) => {
                    self.log_failure("roster", format!("roster adoption failed: {error}"));
                }
            },
            Err(error) => self.log_failure("roster", format!("roster unavailable: {error}")),
        }
        if let Err(error) = event_feed.adopt_sessions(adopted.iter().copied()) {
            self.log_failure("roster", format!("could not seed session cursors: {error}"));
        }

        // Durable change consumption: ONE bounded pending page. An entry
        // leaves the page only when its recorded head is fully published
        // (CaughtUp/Unknown at or past that head) or the session has no
        // durable history at all; any error, publication failure, or
        // incomplete history keeps the entry pending and the ordinal
        // frozen, so a restart re-reads the same entry and the per-session
        // replay-head dedup absorbs already-published frames. Work per
        // tick is bounded: at most one tail page for the front entry plus
        // the single discovery page fetch.
        // Startup-checked sticky fault: a corrupt or unreadable cursor
        // file freezes discovery consumption for the whole process
        // lifetime; consuming from a default would silently lie about how
        // far the feed had progressed. Repair is explicit: fix the file,
        // restart the daemon. No per-tick disk polling.
        let cursor_fault = self
            .cursor_fault
            .lock()
            .map(|fault| fault.clone())
            .unwrap_or_else(|_| Some("cursor state poisoned".to_owned()));
        if let Some(fault) = cursor_fault {
            self.log_failure(
                "discovery-cursor",
                format!("discovery cursor unusable: {fault}"),
            );
        } else {
            let mut cursor = self.discovery_cursor.lock().await;
            let mut pending = self.pending.lock().await;
            if pending.is_empty() {
                match self
                    .discovery
                    .changes_after(*cursor, self.discovery_page)
                    .await
                {
                    Ok(page) => pending.extend(page),
                    Err(error) => self.log_failure(
                        "discovery",
                        format!("durable session discovery failed: {error}"),
                    ),
                }
            }
            // Tail one entry per tick; missing history releases the entry like a caught-up tail.
            // Later history commits add fresh change entries and resume the session.
            if let Some(change) = pending.front().copied() {
                if let Err(error) = event_feed.note_change(change.session_id, change.head) {
                    self.log_failure(
                        "discovery",
                        format!(
                            "could not resume session {} for change {}: {error}",
                            change.session_id, change.position
                        ),
                    );
                } else {
                    match event_feed
                        .tail(
                            self.plane.as_ref(),
                            change.session_id,
                            control_revision,
                            change.head,
                            self.history_page,
                            OffsetDateTime::now_utc(),
                        )
                        .await
                    {
                        Ok(TailOutcome::CaughtUp | TailOutcome::Unknown) => {
                            let position = change.position;
                            let path = self.discovery_cursor_path.clone();
                            let persisted = tokio::task::spawn_blocking(move || {
                                Self::persist_discovery_cursor(&path, position)
                            })
                            .await
                            .map_err(|error| error.to_string())
                            .and_then(|result| result);
                            if let Err(error) = persisted {
                                self.log_failure(
                                    "discovery-cursor",
                                    format!(
                                        "could not persist discovery cursor {}: {error}",
                                        position
                                    ),
                                );
                            } else {
                                pending.pop_front();
                                *cursor = position;
                            }
                        }
                        Ok(TailOutcome::Published(_)) => {}
                        Err(error) => {
                            self.log_failure(
                                "session-tail",
                                format!(
                                    "could not tail session {} for change {}: {error}",
                                    change.session_id, change.position
                                ),
                            );
                        }
                    }
                }
            }
            // Bounded cursor map: every cursor must belong to the adopted
            // live roster or to a pending discovery entry. Releasing the
            // rest loses no progress — the durable replay head is the
            // authoritative resume point and re-seeds on the next change.
            let mut allowed: BTreeSet<LiveSessionId> = adopted.clone();
            for change in pending.iter() {
                allowed.insert(change.session_id);
            }
            event_feed.prune_except(&allowed);
        }
        drop(event_feed);

        // Feed B: one fair bounded page per phase. The ledger lock is taken
        // on the blocking thread and dropped before the join.
        let ledger = Arc::clone(&self.ledger);
        let approval_feed = Arc::clone(&self.approval_feed);
        let read_model = Arc::clone(&self.read_model);
        let drained =
            tokio::task::spawn_blocking(move || -> Result<(), Option<HuginnProtocolError>> {
                let mut ledger = match ledger.lock() {
                    Ok(ledger) => ledger,
                    Err(_) => return Err(None),
                };
                let projection = ApprovalProjection::new(read_model);
                match approval_feed
                    .lock()
                    .map(|mut feed| feed.drain(&mut ledger, &projection))
                    .map_err(|_| HuginnProtocolError::InvalidRequest {
                        code: "approvalFeedState".to_owned(),
                        message: "approval feed state is unavailable".to_owned(),
                    })
                    .and_then(|drained| drained)
                {
                    Ok(_) => Ok(()),
                    Err(error) => Err(Some(error)),
                }
            })
            .await;
        match drained {
            Ok(Err(None)) => {
                self.log_failure("approval-feed", "ledger lock is unavailable".to_owned());
            }
            Ok(Err(Some(error))) => {
                self.log_failure(
                    "approval-feed",
                    format!("approval feed drain failed: {error}"),
                );
            }
            Ok(Ok(())) => self.clear_failure("approval-feed"),
            Err(error) => {
                self.log_failure(
                    "approval-feed",
                    format!("approval feed drain failed: {error}"),
                );
            }
        }
    }
}

#[cfg(test)]
mod tests;
