//! Feed tests use SQLite replay, filesystem payloads, and discovery cursors.
//! Fixtures model paged history and strictly-after change journals; assertions inspect published data.

use std::collections::BTreeMap;
use std::num::{NonZeroU16, NonZeroU32, NonZeroU64};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use odin_domain::huginn::{
    ArtifactReadRequest, ArtifactReadStream, ArtifactRef, CommandReceipt, DeviceId, EventSeq,
    HistoryPage, HistoryQuery, LiveCommand, LiveContentBlock, LiveError, LiveEvent, LiveEventBody,
    LiveEventStream, LiveMessage, LiveSessionId, LiveSessionState, LiveSessionSummary,
    LiveStreamKind, ModelName, ObjectKind, ObjectRef, OmpLivePlane, OpenSessionRequest,
    ProviderName, RosterRevision, Sequence, SessionEpoch, SessionListPage, SessionListQuery,
    StreamBackpressureLimits, StreamFrame, SubscribeRequest, TerminalControlLeaseId,
    TerminalControlRequest, TerminalControlStatus, TerminalInput, TerminalResize, TerminalSeq,
    TransferChunk, TransferId, TransferStatus, UploadManifest,
};
use odin_domain::EventId;
use odin_domain::{ApprovalId, CapabilityId, CommandId, Digest, LaneId, SeatId, SliceId};
use odin_ledger::approval::{ApprovalDecision, ApprovalScope, NewApproval};
use odin_ledger::Ledger;
use time::OffsetDateTime;

use super::SessionProjectionStore;
use super::{
    agent_event_stream, ApprovalFeed, DurableFeedPump, DurableFeedPumpInput,
    DurableSessionDiscovery, RosterFeed, SeatRoster, SessionChange, SessionEventFeed,
    APPROVAL_FEED_PAGE,
};
use crate::approvals::ApprovalProjection;
use crate::read_model::MaterializedReadModel;
use crate::service::FsPublishedArtifactStore;
use crate::state::NodePosture;
use crate::streams::{BoundedMultiplexer, DurableReplayStore};

fn at(seconds: i64) -> OffsetDateTime {
    OffsetDateTime::from_unix_timestamp(1_800_000_000 + seconds).unwrap()
}

/// The typed source state one adopted roster seat exposes; `Running` like
/// every session the live plane lists as active.
fn summary(session: LiveSessionId, updated_seconds: i64, event_head: u64) -> LiveSessionSummary {
    LiveSessionSummary {
        session_id: session,
        epoch: SessionEpoch::new(1),
        seat_id: SeatId::new("architect").unwrap(),
        provider: ProviderName::new("gateway").unwrap(),
        model: ModelName::new("glm-flash").unwrap(),
        title: None,
        state: LiveSessionState::Running,
        started_at: at(0),
        updated_at: at(updated_seconds),
        failed_at: None,
        event_head: EventSeq::new(event_head),
        terminal_head: TerminalSeq::new(0),
        pending_permission_count: 0,
        quiet_seconds: 600,
    }
}

/// One-seat roster listing at most one session, with a distinct digest
/// revision field per source state.
fn single_seat_roster(
    session: Option<(LiveSessionId, i64, u64)>,
    revision_field: u64,
) -> SeatRoster {
    use odin_domain::huginn::{SeatLiveState, SeatRosterEntry};

    let seat_id = SeatId::new("architect").unwrap();
    let sessions = session
        .map(|(session_id, updated, event_head)| vec![summary(session_id, updated, event_head)])
        .unwrap_or_default();
    let seats = if sessions.is_empty() {
        Vec::new()
    } else {
        vec![SeatRosterEntry {
            seat_id,
            slice_id: SliceId::new("architect-engine").unwrap(),
            display_name: "Architect".to_owned(),
            state: SeatLiveState::Running,
            active_sessions: sessions,
            launch_options: Vec::new(),
            diagnostic: None,
        }]
    };
    SeatRoster::new(RosterRevision::new(revision_field), at(99), seats)
}

/// Builds the adopted source state TYPED, never through invented wire JSON:
/// the fixture is a plain constructor call, so the assertions exercise the
/// feed, not a serde representation.
fn roster_typed(session: Option<(&str, i64)>, event_head: u64, revision_field: u64) -> SeatRoster {
    single_seat_roster(
        session.map(|(id, updated)| (LiveSessionId::parse(id).unwrap(), updated, event_head)),
        revision_field,
    )
}

fn empty_projection() -> Arc<MaterializedReadModel> {
    Arc::new(MaterializedReadModel::with_limits(
        1024,
        2048,
        OffsetDateTime::UNIX_EPOCH,
    ))
}

fn projection_store() -> Arc<SessionProjectionStore> {
    Arc::new(
        SessionProjectionStore::new(
            SeatRoster::new(
                RosterRevision::new(0),
                OffsetDateTime::UNIX_EPOCH,
                Vec::new(),
            ),
            32,
            100_u16.try_into().unwrap(),
        )
        .unwrap(),
    )
}

#[test]
fn roster_adoption_is_idempotent_across_revision_hash_changes_and_tombstones_evictions() {
    let feed = RosterFeed::new(projection_store());
    let read_model = empty_projection();
    const SESSION: &str = "11111111-2222-4333-8444-555555555555";
    let session_id = LiveSessionId::parse(SESSION).unwrap();

    // A HIGH digest revision field first…
    let first = feed
        .adopt(
            &read_model,
            roster_typed(Some((SESSION, 5)), 3, u64::MAX / 2),
        )
        .unwrap();
    assert_eq!(first.revision, RosterRevision::new(1));
    // …then a source change whose digest revision field is numerically
    // LOWER: the feed's monotonic revisioner absorbs it — no
    // RevisionConflict, no stale-revision rejection.
    let second = feed
        .adopt(&read_model, roster_typed(Some((SESSION, 9)), 4, 1))
        .unwrap();
    assert_eq!(second.revision, RosterRevision::new(2));
    assert!(second.evicted.is_empty());
    let object = ObjectRef {
        kind: ObjectKind::Session,
        id: session_id.to_string(),
    };
    assert!(read_model.current_revision(&object).unwrap().is_some());

    // Identical source state re-adopts at the SAME revision: nothing
    // re-published, no freshness drift.
    let third = feed
        .adopt(&read_model, roster_typed(Some((SESSION, 9)), 4, 1))
        .unwrap();
    assert_eq!(third.revision, second.revision);
    assert!(third.evicted.is_empty());

    // Terminal removal: the roster no longer lists the session, so the
    // projection tombstones its read-model object exactly once. The
    // tombstone rides the same monotonic feed revision and the same
    // `RevisionSource::Omp` the session object was materialized at — the
    // read model's per-object revision gate stays consistent.
    let fourth = feed.adopt(&read_model, roster_typed(None, 0, 7)).unwrap();
    assert_eq!(fourth.revision, RosterRevision::new(3));
    assert_eq!(fourth.evicted, vec![session_id]);
    assert!(read_model.current_revision(&object).unwrap().is_none());
    // Re-adopting a live session re-materializes it from nothing.
    let fifth = feed
        .adopt(&read_model, roster_typed(Some((SESSION, 12)), 5, 42))
        .unwrap();
    assert!(fifth.evicted.is_empty());
    assert!(read_model.current_revision(&object).unwrap().is_some());
}

#[test]
fn approval_feed_projects_committed_changes_once_and_idempotently() {
    let mut ledger = Ledger::open_in_memory().unwrap();
    let read_model = empty_projection();
    let projection = ApprovalProjection::new(Arc::clone(&read_model));
    let mut feed = ApprovalFeed::new();
    let scope = ApprovalScope {
        target_kind: "run".to_owned(),
        target_id: "run:feed-test".to_owned(),
        capability_id: CapabilityId::new("cap:write").unwrap(),
        arguments_digest: Digest::hash(b"args"),
    };

    assert_eq!(feed.drain(&mut ledger, &projection, at(0)).unwrap(), 0);
    ledger
        .request_approval(NewApproval {
            approval_id: ApprovalId::new("approval:feed-view").unwrap(),
            issuer: "seat:normal".to_owned(),
            scope,
            requested_at: at(0),
            expires_at: at(300),
        })
        .unwrap();
    // The live-tail cursor starts at the baseline head, so the new
    // committed change projects on the very next tick.
    // The projection is idempotent across the live tail and the history
    // replay, so the OBSERVABLE contract is the read-model state, not
    // the internal transition count.
    assert!(feed.drain(&mut ledger, &projection, at(0)).unwrap() >= 1);
    let object = ObjectRef {
        kind: ObjectKind::Approval,
        id: "approval:feed-view".to_owned(),
    };
    let requested_revision = read_model.current_revision(&object).unwrap().unwrap();

    ledger
        .decide_approval(
            &ApprovalId::new("approval:feed-view").unwrap(),
            ApprovalDecision::Approve { evidence_ref: None },
            "human:one",
            at(1),
            1,
        )
        .unwrap();
    assert!(feed.drain(&mut ledger, &projection, at(1)).unwrap() >= 1);
    assert!(
        read_model.current_revision(&object).unwrap().unwrap() > requested_revision,
        "the decision advanced the projected revision"
    );
    // The cursor sits at the durable head: nothing new to project.
    assert!(ledger
        .approval_feed_after(ledger.approval_feed_head().unwrap(), APPROVAL_FEED_PAGE)
        .unwrap()
        .is_empty());
    assert_eq!(feed.drain(&mut ledger, &projection, at(1)).unwrap(), 0);
}

// ---------------------------------------------------------------------------
// Deterministic pump harness
// ---------------------------------------------------------------------------

const REPLAY_MAX_PER_STREAM: usize = 4096;
const MAX_ITEM_BYTES: u64 = 64 * 1024;
const LIVE_SESSION: &str = "11111111-2222-4333-8444-555555555555";
fn backpressure() -> StreamBackpressureLimits {
    StreamBackpressureLimits {
        max_buffered_items: NonZeroU32::new(64).unwrap(),
        max_buffered_bytes: NonZeroU64::new(1 << 20).unwrap(),
        max_item_bytes: NonZeroU64::new(MAX_ITEM_BYTES).unwrap(),
        max_items_per_second: NonZeroU32::new(1024).unwrap(),
        max_in_flight_bytes: NonZeroU64::new(1 << 20).unwrap(),
    }
}

fn live_event(session: LiveSessionId, sequence: u64) -> LiveEvent {
    LiveEvent::new(
        1,
        EventId::new(format!("event:{session}-{sequence}")).expect("valid event id"),
        session,
        SessionEpoch::new(1),
        EventSeq::new(sequence),
        at(i64::try_from(sequence).expect("small sequence")),
        LiveEventBody::UserMessage(
            LiveMessage::new(vec![LiveContentBlock::Text(format!("frame {sequence}"))])
                .expect("nonempty message"),
        ),
    )
    .expect("valid live event")
}

#[derive(Default)]
struct SessionRecord {
    events: Vec<LiveEvent>,
    /// `false` models a session with NO durable history at all: the real
    /// ledger answers `NotFound`, the tail reports `Unknown`.
    present: bool,
}

struct PlaneState {
    roster: SeatRoster,
    sessions: BTreeMap<LiveSessionId, SessionRecord>,
    terminals: BTreeMap<LiveSessionId, odin_domain::huginn::TerminalSnapshot>,
    terminal_reads: usize,
}

/// Deterministic `OmpLivePlane`: a scripted roster plus a real-history
/// event store whose `history` mirrors the durable ledger's bounded page
/// contract (events strictly after the cursor, at most `limit`, `next_after`
/// the last returned sequence, `head` the durable source head).
struct FixturePlane {
    state: Mutex<PlaneState>,
}

impl FixturePlane {
    fn new() -> Self {
        Self {
            state: Mutex::new(PlaneState {
                roster: SeatRoster::new(RosterRevision::new(0), at(0), Vec::new()),
                sessions: BTreeMap::new(),
                terminals: BTreeMap::new(),
                terminal_reads: 0,
            }),
        }
    }

    fn set_roster(&self, roster: SeatRoster) {
        self.state.lock().expect("plane state").roster = roster;
    }

    /// Appends one event: the durable head advances by exactly one and the
    /// session's history becomes present (journal-after-commit).
    fn append_event(&self, session: LiveSessionId) -> u64 {
        let mut state = self.state.lock().expect("plane state");
        let record = state.sessions.entry(session).or_default();
        let sequence = record.events.len() as u64 + 1;
        record.events.push(live_event(session, sequence));
        record.present = true;
        sequence
    }

    fn seed_history(&self, session: LiveSessionId, count: u64) {
        for _ in 0..count {
            self.append_event(session);
        }
    }

    fn events(&self, session: LiveSessionId) -> Vec<LiveEvent> {
        self.state
            .lock()
            .expect("plane state")
            .sessions
            .get(&session)
            .map(|record| record.events.clone())
            .unwrap_or_default()
    }
}

fn plane_refusal() -> LiveError {
    LiveError::unavailable(
        "fixture_plane_operation_unwired",
        "the fixture plane does not wire this operation",
    )
}

#[async_trait]
impl OmpLivePlane for FixturePlane {
    async fn terminal_snapshot(
        &self,
        session: LiveSessionId,
    ) -> Result<odin_domain::huginn::TerminalSnapshot, LiveError> {
        let mut state = self.state.lock().expect("plane state");
        state.terminal_reads += 1;
        state
            .terminals
            .get(&session)
            .cloned()
            .ok_or_else(plane_refusal)
    }

    async fn roster(&self) -> Result<SeatRoster, LiveError> {
        Ok(self.state.lock().expect("plane state").roster.clone())
    }

    async fn sessions(&self, _query: SessionListQuery) -> Result<SessionListPage, LiveError> {
        Err(plane_refusal())
    }

    async fn history(&self, query: HistoryQuery) -> Result<HistoryPage, LiveError> {
        let state = self.state.lock().expect("plane state");
        let Some(record) = state
            .sessions
            .get(&query.session_id)
            .filter(|record| record.present)
        else {
            return Err(LiveError::NotFound {
                object_kind: "session".to_owned(),
                object_id: query.session_id.to_string(),
            });
        };
        let head = record
            .events
            .last()
            .map_or(EventSeq::new(0), |event| event.sequence);
        let events = record
            .events
            .iter()
            .filter(|event| event.sequence > query.after)
            .take(usize::from(query.limit.get()))
            .cloned()
            .collect::<Vec<_>>();
        let next_after = events
            .last()
            .map_or(EventSeq::new(query.after.get().min(head.get())), |event| {
                event.sequence
            });
        Ok(HistoryPage {
            events,
            next_after,
            head,
        })
    }

    async fn subscribe(&self, _request: SubscribeRequest) -> Result<LiveEventStream, LiveError> {
        Err(plane_refusal())
    }

    async fn open_session(
        &self,
        _request: OpenSessionRequest,
    ) -> Result<LiveSessionSummary, LiveError> {
        Err(plane_refusal())
    }

    async fn command(&self, _command: LiveCommand) -> Result<CommandReceipt, LiveError> {
        Err(plane_refusal())
    }

    async fn begin_upload(&self, _manifest: UploadManifest) -> Result<TransferStatus, LiveError> {
        Err(plane_refusal())
    }

    async fn upload_chunk(
        &self,
        _transfer: TransferId,
        _chunk: TransferChunk,
    ) -> Result<(), LiveError> {
        Err(plane_refusal())
    }

    async fn commit_upload(&self, _transfer: TransferId) -> Result<ArtifactRef, LiveError> {
        Err(plane_refusal())
    }

    async fn cancel_transfer(
        &self,
        _command_id: CommandId,
        _transfer: TransferId,
    ) -> Result<TransferStatus, LiveError> {
        Err(plane_refusal())
    }

    async fn grant_download_credit(
        &self,
        _command_id: CommandId,
        _transfer: odin_domain::huginn::TransferId,
        _chunks: NonZeroU16,
    ) -> Result<(), LiveError> {
        Err(plane_refusal())
    }

    async fn read_artifact(
        &self,
        _request: ArtifactReadRequest,
    ) -> Result<(ArtifactRef, ArtifactReadStream), LiveError> {
        Err(plane_refusal())
    }

    async fn acquire_terminal_control(
        &self,
        _command_id: CommandId,
        _device: DeviceId,
        _request: TerminalControlRequest,
    ) -> Result<TerminalControlStatus, LiveError> {
        Err(plane_refusal())
    }

    async fn write_terminal(
        &self,
        _command_id: CommandId,
        _session: LiveSessionId,
        _input: TerminalInput,
    ) -> Result<(), LiveError> {
        Err(plane_refusal())
    }

    async fn resize_terminal(
        &self,
        _command_id: CommandId,
        _session: LiveSessionId,
        _resize: TerminalResize,
    ) -> Result<(), LiveError> {
        Err(plane_refusal())
    }

    async fn release_terminal_control(
        &self,
        _command_id: CommandId,
        _session: LiveSessionId,
        _lease: TerminalControlLeaseId,
    ) -> Result<TerminalControlStatus, LiveError> {
        Err(plane_refusal())
    }
}

/// Deterministic change journal: 1-based ordinals in arrival order, pages
/// strictly after the cursor, at most `limit` entries — the real ledger's
/// `changes_after` contract.
#[derive(Default)]
struct FixtureDiscovery {
    journal: Mutex<Vec<SessionChange>>,
}

impl FixtureDiscovery {
    fn commit(&self, session: LiveSessionId, head: u64) -> u64 {
        let mut journal = self.journal.lock().expect("change journal");
        let position = journal.len() as u64 + 1;
        journal.push(SessionChange {
            position,
            session_id: session,
            head,
        });
        position
    }
}

#[async_trait]
impl DurableSessionDiscovery for FixtureDiscovery {
    async fn changes_after(
        &self,
        after: u64,
        limit: usize,
    ) -> Result<Vec<SessionChange>, LiveError> {
        let journal = self.journal.lock().expect("change journal");
        Ok(journal
            .iter()
            .filter(|change| change.position > after)
            .take(limit.max(1))
            .copied()
            .collect())
    }
}

/// The daemon-side state a feed-stack restart does NOT touch: the live
/// plane, its change journal, the authority ledger, and the shared
/// in-memory projections under test.
struct Fixture {
    _root: tempfile::TempDir,
    plane: Arc<FixturePlane>,
    discovery: Arc<FixtureDiscovery>,
    ledger: Arc<Mutex<Ledger>>,
    read_model: Arc<MaterializedReadModel>,
    projection_store: Arc<SessionProjectionStore>,
}

impl Fixture {
    fn new() -> Self {
        let root = tempfile::tempdir().expect("temporary feed root");
        let authority_dir = root.path().join("authority");
        std::fs::create_dir_all(&authority_dir).expect("authority directory");
        let ledger = Arc::new(Mutex::new(
            Ledger::open(authority_dir.join("authority.sqlite3")).expect("authority ledger opens"),
        ));
        Self {
            _root: root,
            plane: Arc::new(FixturePlane::new()),
            discovery: Arc::new(FixtureDiscovery::default()),
            ledger,
            read_model: empty_projection(),
            projection_store: projection_store(),
        }
    }

    /// Reopens the durable stores; the setup hook runs before startup reads the cursor file.
    fn harness_with_cursor_setup(
        &self,
        history_page: u16,
        discovery_page: usize,
        cursor_setup: &dyn Fn(&std::path::Path),
    ) -> FeedHarness {
        self.harness_impl(history_page, discovery_page, Some(&cursor_setup))
    }

    fn harness(&self, history_page: u16, discovery_page: usize) -> FeedHarness {
        self.harness_with_cursor_setup(history_page, discovery_page, &|_| {})
    }

    fn harness_impl(
        &self,
        history_page: u16,
        discovery_page: usize,
        cursor_setup: Option<&dyn Fn(&std::path::Path)>,
    ) -> FeedHarness {
        let root = self._root.path();
        let replay_path = root.join("replay").join("stream-items.sqlite3");
        let replay = DurableReplayStore::open(&replay_path, REPLAY_MAX_PER_STREAM, MAX_ITEM_BYTES)
            .expect("durable replay store opens");
        let multiplexer = Arc::new(BoundedMultiplexer::new(replay, 64, 64));
        let artifacts = Arc::new(
            FsPublishedArtifactStore::open(
                root.join("published"),
                LiveSessionId::parse("8f9c2ee3-85ec-46e9-a43a-a2cd6048c1e9")
                    .expect("valid render session"),
                LaneId::new("lane:feed-files").expect("valid file lane"),
                LaneId::new("lane:feed-renders").expect("valid render lane"),
            )
            .expect("published artifact store opens"),
        );
        std::fs::create_dir_all(root.join("feeds")).expect("feeds directory");
        if let Some(cursor_setup) = cursor_setup {
            cursor_setup(&root.join("feeds").join("change-cursor"));
        }
        let event_feed = SessionEventFeed::new(
            Arc::clone(&multiplexer),
            Arc::clone(&artifacts),
            backpressure(),
            MAX_ITEM_BYTES,
        );
        let pump = DurableFeedPump::new(DurableFeedPumpInput {
            posture: NodePosture::Authoritative,
            plane: Arc::clone(&self.plane) as Arc<dyn OmpLivePlane>,
            ledger: Arc::clone(&self.ledger),
            discovery: Arc::clone(&self.discovery) as Arc<dyn DurableSessionDiscovery>,
            discovery_cursor_path: Some(root.join("feeds").join("change-cursor")),
            read_model: Arc::clone(&self.read_model),
            roster_feed: Arc::new(RosterFeed::new(Arc::clone(&self.projection_store))),
            event_feed: Arc::new(tokio::sync::Mutex::new(event_feed)),
            approval_feed: ApprovalFeed::new(),
            history_page: NonZeroU16::new(history_page).expect("bounded history page"),
            discovery_page,
        });
        FeedHarness {
            pump,
            replay: DurableReplayStore::open(&replay_path, REPLAY_MAX_PER_STREAM, MAX_ITEM_BYTES)
                .expect("assertion replay connection opens"),
            cursor_path: root.join("feeds").join("change-cursor"),
            payloads_dir: root.join("published").join("payloads"),
        }
    }
}

/// One assembled pump plus the observation surface: the durable replay
/// (frames), the published payload files, and the discovery-cursor file.
struct FeedHarness {
    pump: DurableFeedPump,
    replay: DurableReplayStore,
    cursor_path: PathBuf,
    payloads_dir: PathBuf,
}

impl FeedHarness {
    async fn tick(&self) {
        self.pump.tick().await;
    }

    /// Limits ticks so a stalled drain fails instead of hanging.
    async fn drain(&self, journal_length: u64, budget: usize) {
        for _ in 0..budget {
            self.pump.tick().await;
            if self.ordinal() == Some(journal_length) {
                return;
            }
        }
        panic!("durable feed did not drain to ordinal {journal_length} within {budget} ticks");
    }

    /// The durable discovery ordinal exactly as the cursor file holds it.
    fn ordinal(&self) -> Option<u64> {
        std::fs::read_to_string(&self.cursor_path).ok().map(|text| {
            text.trim()
                .parse::<u64>()
                .expect("ordinal file holds a u64")
        })
    }

    fn replay_head(&self, session: LiveSessionId) -> u64 {
        self.replay
            .head(&agent_event_stream(session))
            .expect("durable replay head")
            .get()
    }

    /// Every retained frame for the session's durable stream, in sequence
    /// order — the replayed tail a reconnecting subscriber observes.
    fn frames(&self, session: LiveSessionId) -> Vec<StreamFrame> {
        let stream_id = agent_event_stream(session);
        let head = self.replay.head(&stream_id).expect("replay head").get();
        if head == 0 {
            return Vec::new();
        }
        let batch = self
            .replay
            .replay(
                &stream_id,
                Sequence::new(0),
                Sequence::new(head),
                REPLAY_MAX_PER_STREAM,
            )
            .expect("durable replay batch");
        batch.items.into_iter().map(|item| item.frame).collect()
    }

    /// The published payload bytes a frame's content resolves to.
    fn payload_bytes(&self, frame: &StreamFrame) -> Vec<u8> {
        let digest_hex = frame
            .content
            .content_digest
            .to_string()
            .strip_prefix("blake3:")
            .expect("blake3 digest")
            .to_owned();
        std::fs::read(self.payloads_dir.join(format!("{digest_hex}.blob")))
            .expect("published payload file")
    }
}

fn set_terminal(fixture: &Fixture, epoch: u64, sequence: u64, contents: &str) {
    let session = LiveSessionId::parse(LIVE_SESSION).unwrap();
    let mut roster = single_seat_roster(Some((session, sequence as i64, sequence)), sequence);
    roster.seats[0].active_sessions[0].epoch = SessionEpoch::new(epoch);
    roster.seats[0].active_sessions[0].terminal_head = TerminalSeq::new(sequence);
    let snapshot = odin_domain::huginn::TerminalSnapshot {
        session_id: session,
        epoch: SessionEpoch::new(epoch),
        sequence: TerminalSeq::new(sequence),
        recorded_at: at(sequence as i64),
        columns: NonZeroU16::new(80).unwrap(),
        rows: NonZeroU16::new(24).unwrap(),
        contents: contents.to_owned(),
        cursor: odin_domain::huginn::TerminalCursor {
            row: 0,
            column: 0,
            visible: true,
        },
    };
    let mut state = fixture.plane.state.lock().unwrap();
    state.roster = roster;
    state.terminals.insert(session, snapshot);
}

#[tokio::test]
async fn terminal_discovery_publishes_real_same_session_resets_and_retires_closed_sessions() {
    let fixture = Fixture::new();
    let session = LiveSessionId::parse(LIVE_SESSION).unwrap();
    set_terminal(&fixture, 1, 7, "takeover-marker actual-output");
    let harness = fixture.harness(8, 8);
    harness.tick().await;
    let object = ObjectRef {
        kind: ObjectKind::Terminal,
        id: session.to_string(),
    };
    let view = fixture.read_model.get(&object).unwrap().unwrap();
    let data = &view.value["data"];
    assert_eq!(data["sessionId"], LIVE_SESSION);
    assert_eq!(data["contents"], "takeover-marker actual-output");
    assert_eq!(data["epoch"], 1);
    assert_eq!(data["sequence"], 7);
    let stream = super::terminal::stream_id(session, SessionEpoch::new(1));
    assert_eq!(data["streamId"], stream.to_string());
    assert_ne!(stream, agent_event_stream(session));
    let replay = harness
        .replay
        .replay(&stream, Sequence::new(0), Sequence::new(1), 8)
        .unwrap();
    assert_eq!(replay.items.len(), 1);
    assert!(
        matches!(&replay.items[0].message, odin_domain::huginn::HuginnMessage::TerminalReset(snapshot)
        if snapshot.session_id == session && snapshot.sequence.get() == 7 && snapshot.contents == "takeover-marker actual-output")
    );
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&harness.payload_bytes(&replay.items[0].frame))
            .unwrap()["sequence"],
        7
    );
    harness.tick().await;
    assert_eq!(
        harness.replay.head(&stream).unwrap().get(),
        1,
        "unchanged output is not republished"
    );
    set_terminal(&fixture, 1, 7, "tampered at same sequence");
    harness.tick().await;
    assert_eq!(harness.replay.head(&stream).unwrap().get(), 1);
    assert_eq!(
        fixture.read_model.get(&object).unwrap().unwrap().value["data"]["contents"],
        "takeover-marker actual-output"
    );
    set_terminal(&fixture, 1, 6, "regressed snapshot");
    harness.tick().await;
    assert_eq!(harness.replay.head(&stream).unwrap().get(), 1);
    set_terminal(&fixture, 1, 8, "genuine next screen");
    // An unchanged screen paces its re-checks, so a change is picked up
    // within the pacing window, not necessarily on the very next tick.
    for visit in 0..=super::terminal::TERMINAL_SKIP_VISITS {
        harness.tick().await;
        if harness.replay.head(&stream).unwrap().get() == 2 {
            break;
        }
        assert!(
            visit < super::terminal::TERMINAL_SKIP_VISITS,
            "a changed screen is picked up within the pacing window"
        );
    }
    assert_eq!(harness.replay.head(&stream).unwrap().get(), 2);
    set_terminal(&fixture, 2, 8, "new incarnation");
    harness.tick().await;
    let next = super::terminal::stream_id(session, SessionEpoch::new(2));
    assert_ne!(next, stream);
    assert_eq!(harness.replay.head(&next).unwrap().get(), 1);
    let reads = fixture.plane.state.lock().unwrap().terminal_reads;
    fixture.plane.set_roster(single_seat_roster(None, 99));
    harness.tick().await;
    assert!(fixture.read_model.get(&object).unwrap().is_none());
    assert_eq!(fixture.plane.state.lock().unwrap().terminal_reads, reads);
}

/// The exactly-once contract, observed end to end on frames and payloads.
fn assert_delivered_exactly_once(
    harness: &FeedHarness,
    session: LiveSessionId,
    events: &[LiveEvent],
) {
    let frames = harness.frames(session);
    assert_eq!(
        frames.len(),
        events.len(),
        "exactly one durable frame per committed event"
    );
    for (frame, event) in frames.iter().zip(events) {
        assert_eq!(frame.stream_id, agent_event_stream(session));
        assert_eq!(frame.kind, LiveStreamKind::AgentEvents);
        assert_eq!(
            frame.sequence.get(),
            event.sequence.get(),
            "frame sequence k is live event k"
        );
        assert_eq!(
            frame.produced_at, event.occurred_at,
            "the frame timestamp is the durable event fact, not the tick clock"
        );
        assert!(frame.key_frame);
        let payload = harness.payload_bytes(frame);
        let canonical = serde_json::to_vec(event).expect("canonical event payload");
        assert_eq!(
            payload, canonical,
            "the frame payload resolves to the canonical event"
        );
        assert_eq!(frame.content.byte_len, canonical.len() as u64);
        assert_eq!(frame.content.session_id, session);
    }
}

// ---------------------------------------------------------------------------
// Mandated pump laws
// ---------------------------------------------------------------------------

#[tokio::test]
async fn restart_mid_drain_after_multiple_pages_delivers_every_frame_exactly_once() {
    let fixture = Fixture::new();
    let session = LiveSessionId::parse(LIVE_SESSION).unwrap();
    fixture.plane.seed_history(session, 7);
    fixture.discovery.commit(session, 7);

    let harness = fixture.harness(3, 8);
    harness.tick().await;
    assert_eq!(
        harness.replay_head(session),
        3,
        "one tick publishes exactly one bounded history page"
    );
    harness.tick().await;
    assert_eq!(
        harness.replay_head(session),
        6,
        "the next tick the next page"
    );
    assert_eq!(
        harness.ordinal(),
        None,
        "mid-drain: the change entry is not complete, so the ordinal never advanced"
    );

    // The feed stack dies mid-drain; replay, payloads, and the cursor file
    // survive on disk and a fresh pump resumes exactly after frame 6.
    drop(harness);
    let harness = fixture.harness(3, 8);
    harness.drain(1, 8).await;
    assert_delivered_exactly_once(&harness, session, &fixture.plane.events(session));
    assert_eq!(harness.ordinal(), Some(1));

    // A second restart re-reads from the persisted ordinal: no rescan, no
    // republication.
    drop(harness);
    let harness = fixture.harness(3, 8);
    harness.tick().await;
    assert_eq!(harness.replay_head(session), 7);
    assert_delivered_exactly_once(&harness, session, &fixture.plane.events(session));
}

#[tokio::test]
async fn publication_failure_does_not_advance_the_discovery_ordinal() {
    let fixture = Fixture::new();
    let session = LiveSessionId::parse(LIVE_SESSION).unwrap();
    fixture.plane.seed_history(session, 7);
    fixture.discovery.commit(session, 7);

    let harness = fixture.harness(3, 8);
    harness.tick().await;
    assert_eq!(harness.replay_head(session), 3);

    // Deterministic fs obstacle for any user, root included: the payloads
    // directory is renamed aside, so every payload write hits ENOENT until
    // it is restored.
    let payloads = harness.payloads_dir.clone();
    let payloads_hold = payloads.with_file_name("payloads.hold");
    std::fs::rename(&payloads, &payloads_hold).expect("payloads renamed aside");
    harness.tick().await;
    harness.tick().await;
    assert_eq!(
        harness.replay_head(session),
        3,
        "no frame publishes past the failed payload"
    );
    assert_eq!(
        harness.ordinal(),
        None,
        "a publication failure freezes the durable ordinal"
    );
    std::fs::rename(&payloads_hold, &payloads).expect("payloads restored");

    harness.drain(1, 8).await;
    assert_delivered_exactly_once(&harness, session, &fixture.plane.events(session));
    assert_eq!(harness.ordinal(), Some(1));
}

/// The ledger journals one change entry per event, so a busy session's
/// entries must drain a whole discovery page per tick; one entry per tick
/// left Sinmara's stream hundreds of events behind the roster head.
#[tokio::test]
async fn one_tick_drains_a_page_of_per_event_change_entries() {
    let fixture = Fixture::new();
    let session = LiveSessionId::parse(LIVE_SESSION).unwrap();
    for _ in 0..4 {
        let head = fixture.plane.append_event(session);
        fixture.discovery.commit(session, head);
    }

    let harness = fixture.harness(100, 32);
    harness.tick().await;
    assert_eq!(harness.replay_head(session), 4);
    assert_eq!(harness.ordinal(), Some(4));
    assert_delivered_exactly_once(&harness, session, &fixture.plane.events(session));
}

/// odind's Huginn runtime is multi-thread, so a current-thread feed test never
/// enters the durable append that yields the worker on that flavor.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn multi_thread_runtime_tails_publishes_and_appends_every_frame() {
    assert_eq!(
        tokio::runtime::Handle::current().runtime_flavor(),
        tokio::runtime::RuntimeFlavor::MultiThread
    );
    let fixture = Fixture::new();
    let session = LiveSessionId::parse(LIVE_SESSION).unwrap();
    fixture.plane.seed_history(session, 2);
    fixture.discovery.commit(session, 2);

    let harness = fixture.harness(8, 8);
    harness.drain(1, 4).await;
    assert_delivered_exactly_once(&harness, session, &fixture.plane.events(session));
    assert_eq!(harness.replay_head(session), 2);
}
