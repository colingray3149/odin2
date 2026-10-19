//! Feed tests use SQLite replay, filesystem payloads, and discovery cursors.
//! Fixtures model paged history and strictly-after change journals; assertions inspect published data.

use std::collections::BTreeMap;
use std::num::{NonZeroU16, NonZeroU32, NonZeroU64};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use odin_domain::huginn::{
    ArtifactReadRequest, ArtifactReadStream, ArtifactRef, CommandReceipt, DeviceId, EventSeq,
    HistoryPage, HistoryQuery, HuginnProtocolError, LiveCommand, LiveContentBlock, LiveError,
    LiveEvent, LiveEventBody, LiveEventStream, LiveMessage, LiveSessionId, LiveSessionState,
    LiveSessionSummary, LiveStreamKind, ModelName, ObjectKind, ObjectRef, OmpLivePlane,
    OpenSessionRequest, ProviderName, RosterRevision, Sequence, SessionEpoch, SessionListPage,
    SessionListQuery, StreamBackpressureLimits, StreamFrame, SubscribeRequest,
    TerminalControlLeaseId, TerminalControlRequest, TerminalControlStatus, TerminalInput,
    TerminalResize, TerminalSeq, TransferChunk, TransferId, TransferStatus, UploadManifest,
};
use odin_domain::EventId;
use odin_domain::{ApprovalId, CapabilityId, CommandId, Digest, LaneId, SeatId, SliceId};
use odin_ledger::approval::{ApprovalDecision, ApprovalScope, NewApproval};
use odin_ledger::Ledger;
use time::OffsetDateTime;

use super::SessionProjectionStore;
use super::{
    agent_event_stream, source_freshness, ApprovalFeed, DurableFeedPump, DurableSessionDiscovery,
    RosterFeed, SeatRoster, SessionChange, SessionEventFeed, APPROVAL_FEED_PAGE,
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
fn freshness_is_a_pure_function_of_adopted_source_state() {
    let sessions = roster_typed(Some(("11111111-2222-4333-8444-555555555555", 5)), 3, 900);
    let expected = source_freshness(
        sessions
            .seats
            .iter()
            .flat_map(|seat| seat.active_sessions.iter()),
    );
    assert_eq!(expected.observed_at, at(5));
    assert_eq!(expected.source_updated_at, Some(at(5)));
    let none = source_freshness(
        roster_typed(None, 0, 1)
            .seats
            .iter()
            .flat_map(|seat| seat.active_sessions.iter()),
    );
    assert_eq!(none.observed_at, OffsetDateTime::UNIX_EPOCH);
    assert_eq!(none.source_updated_at, None);
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
fn unchanged_roster_retry_clears_a_registry_republish_head() {
    use odin_domain::huginn::{
        Freshness, FreshnessState, ObjectSnapshot, Revision, RevisionSource,
    };
    const SESSION: &str = "11111111-2222-4333-8444-555555555555";
    let read_model = empty_projection();
    let store = projection_store();
    let feed = RosterFeed::new(store.clone());
    let seat_object = ObjectRef {
        kind: ObjectKind::Seat,
        id: "architect".to_owned(),
    };
    let registry_seed = |revision: u64| {
        read_model.upsert(ObjectSnapshot {
            object: seat_object.clone(),
            revision: Revision::new(revision),
            revision_source: RevisionSource::Registry,
            freshness: Freshness {
                state: FreshnessState::Fresh,
                observed_at: at(0),
                source_updated_at: Some(at(0)),
                stale_after_seconds: None,
            },
            content_digest: Digest::hash(format!("registry-{revision}").as_bytes()),
            value: serde_json::json!({ "kind": "registry-seed" }),
        })
    };

    // Registry seed at revision 1...
    registry_seed(1).unwrap();
    // ...first adoption takes floor+1 = 2...
    let first = feed
        .adopt(&read_model, roster_typed(Some((SESSION, 5)), 3, 1))
        .unwrap();
    assert_eq!(first.revision, RosterRevision::new(2));
    // ...the registry republishes the Seat at a HIGHER revision while the
    // adopted roster is unchanged...
    registry_seed(4).unwrap();
    // ...and the identical retry clears that external head at floor+1.
    let retried = feed
        .adopt(&read_model, roster_typed(Some((SESSION, 5)), 3, 1))
        .unwrap();
    assert_eq!(
        retried.revision,
        RosterRevision::new(5),
        "an identical retry after a registry republish must clear the external head"
    );
    assert!(retried.evicted.is_empty());
}

#[test]
fn revision_floor_read_model_failure_propagates() {
    let feed = RosterFeed::new(projection_store());
    let read_model = empty_projection();
    read_model.poison_state_lock_for_tests();

    let error = match feed.adopt(
        &read_model,
        roster_typed(Some(("11111111-2222-4333-8444-555555555555", 5)), 3, 1),
    ) {
        Ok(adopted) => panic!(
            "a failing revision-floor read must fail the adoption, not silently floor it at 0: adopted at {:?}",
            adopted.revision
        ),
        Err(error) => error,
    };
    match error {
        HuginnProtocolError::InvalidRequest { code, .. } => {
            assert_eq!(code, "rosterFeedRevisionFloor");
        }
        other => panic!("typed revision-floor refusal expected, got {other:?}"),
    }
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

    assert_eq!(feed.drain(&mut ledger, &projection).unwrap(), 0);
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
    assert!(feed.drain(&mut ledger, &projection).unwrap() >= 1);
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
    assert!(feed.drain(&mut ledger, &projection).unwrap() >= 1);
    assert!(
        read_model.current_revision(&object).unwrap().unwrap() > requested_revision,
        "the decision advanced the projected revision"
    );
    // The cursor sits at the durable head: nothing new to project.
    assert!(ledger
        .approval_feed_after(ledger.approval_feed_head().unwrap(), APPROVAL_FEED_PAGE)
        .unwrap()
        .is_empty());
    assert_eq!(feed.drain(&mut ledger, &projection).unwrap(), 0);
}

#[test]
fn discovery_ordinal_matches_the_durable_stream_identity() {
    // Frame sequence k is live event k, so the agent-events stream of a
    // session is keyed by the session id itself.
    let session = LiveSessionId::parse("11111111-2222-4333-8444-555555555555").unwrap();
    assert_eq!(agent_event_stream(session).to_string(), session.to_string());
}

// ---------------------------------------------------------------------------
// Deterministic pump harness
// ---------------------------------------------------------------------------

const REPLAY_MAX_PER_STREAM: usize = 4096;
const MAX_ITEM_BYTES: u64 = 64 * 1024;
const LIVE_SESSION: &str = "11111111-2222-4333-8444-555555555555";
const OTHER_SESSION: &str = "22222222-3333-4333-8444-555555555555";

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
    LiveError::Unavailable {
        code: "fixture_plane_operation_unwired".to_owned(),
    }
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
        let pump = DurableFeedPump::new(
            NodePosture::Authoritative,
            Arc::clone(&self.plane) as Arc<dyn OmpLivePlane>,
            Arc::clone(&self.ledger),
            Arc::clone(&self.discovery) as Arc<dyn DurableSessionDiscovery>,
            Some(root.join("feeds").join("change-cursor")),
            Arc::clone(&self.read_model),
            Arc::new(RosterFeed::new(Arc::clone(&self.projection_store))),
            Arc::new(tokio::sync::Mutex::new(event_feed)),
            ApprovalFeed::new(),
            NonZeroU16::new(history_page).expect("bounded history page"),
            discovery_page,
        );
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
    harness.tick().await;
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

#[tokio::test]
async fn wrong_terminal_binding_fails_without_blocking_agent_events() {
    let fixture = Fixture::new();
    let session = LiveSessionId::parse(LIVE_SESSION).unwrap();
    set_terminal(&fixture, 1, 1, "foreign screen");
    fixture
        .plane
        .state
        .lock()
        .unwrap()
        .terminals
        .get_mut(&session)
        .unwrap()
        .session_id = LiveSessionId::parse(OTHER_SESSION).unwrap();
    fixture.plane.append_event(session);
    fixture.discovery.commit(session, 1);
    let harness = fixture.harness(8, 8);
    harness.tick().await;
    assert_eq!(harness.replay_head(session), 1);
    assert!(fixture
        .read_model
        .get(&ObjectRef {
            kind: ObjectKind::Terminal,
            id: session.to_string()
        })
        .unwrap()
        .is_none());
    assert_eq!(
        harness
            .replay
            .head(&super::terminal::stream_id(session, SessionEpoch::new(1)))
            .unwrap()
            .get(),
        0
    );
}

#[tokio::test]
async fn terminal_polling_skips_ended_and_headless_sessions_and_bounds_work() {
    let fixture = Fixture::new();
    set_terminal(&fixture, 1, 1, "screen");
    let session = LiveSessionId::parse(LIVE_SESSION).unwrap();
    let other = LiveSessionId::parse(OTHER_SESSION).unwrap();
    {
        let mut state = fixture.plane.state.lock().expect("plane state");
        let mut second = state.roster.seats[0].active_sessions[0].clone();
        second.session_id = other;
        state.roster.seats[0].active_sessions.push(second);
        let mut snapshot = state.terminals[&session].clone();
        snapshot.session_id = other;
        state.terminals.insert(other, snapshot);
    }
    let harness = fixture.harness(8, 8);
    harness.tick().await;
    assert_eq!(
        fixture
            .plane
            .state
            .lock()
            .expect("plane state")
            .terminal_reads,
        1
    );
    harness.tick().await;
    assert_eq!(
        fixture
            .plane
            .state
            .lock()
            .expect("plane state")
            .terminal_reads,
        2
    );
    for id in [session, other] {
        assert!(fixture
            .read_model
            .get(&ObjectRef {
                kind: ObjectKind::Terminal,
                id: id.to_string()
            })
            .unwrap()
            .is_some());
    }
    {
        let mut state = fixture.plane.state.lock().expect("plane state");
        state.roster.revision = RosterRevision::new(9);
        state.roster.seats[0].active_sessions[0].state = LiveSessionState::Ended;
        state.roster.seats[0].active_sessions[1].terminal_head = TerminalSeq::new(0);
    }
    harness.tick().await;
    assert_eq!(
        fixture
            .plane
            .state
            .lock()
            .expect("plane state")
            .terminal_reads,
        2
    );
    assert!(fixture
        .read_model
        .objects_of_kind(ObjectKind::Terminal)
        .unwrap()
        .is_empty());
}

#[tokio::test]
async fn stale_terminal_epoch_and_failed_capture_publish_no_screen() {
    let fixture = Fixture::new();
    let session = LiveSessionId::parse(LIVE_SESSION).unwrap();
    set_terminal(&fixture, 2, 9, "stale incarnation");
    fixture
        .plane
        .state
        .lock()
        .expect("plane state")
        .terminals
        .get_mut(&session)
        .unwrap()
        .epoch = SessionEpoch::new(1);
    let harness = fixture.harness(8, 8);
    harness.tick().await;
    assert!(fixture
        .read_model
        .objects_of_kind(ObjectKind::Terminal)
        .unwrap()
        .is_empty());
    fixture
        .plane
        .state
        .lock()
        .expect("plane state")
        .terminals
        .clear();
    harness.tick().await;
    assert!(fixture
        .read_model
        .objects_of_kind(ObjectKind::Terminal)
        .unwrap()
        .is_empty());
    assert_eq!(
        harness
            .replay
            .head(&super::terminal::stream_id(session, SessionEpoch::new(2)))
            .unwrap()
            .get(),
        0
    );
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

#[tokio::test]
async fn cursor_file_failure_does_not_advance_the_discovery_ordinal() {
    let fixture = Fixture::new();
    let session = LiveSessionId::parse(LIVE_SESSION).unwrap();
    fixture.plane.seed_history(session, 7);
    fixture.discovery.commit(session, 7);

    let harness = fixture.harness(3, 8);
    // Deterministic fs obstacle for any user, root included: after startup
    // loaded the absent cursor as ordinal 0, the feeds directory is renamed
    // aside, so every cursor persist hits ENOENT until it is restored.
    let feeds = harness
        .cursor_path
        .parent()
        .expect("cursor parent")
        .to_path_buf();
    let feeds_hold = feeds.with_file_name("feeds.hold");
    std::fs::rename(&feeds, &feeds_hold).expect("feeds renamed aside");
    for _ in 0..4 {
        harness.tick().await;
    }
    assert_eq!(
        harness.replay_head(session),
        7,
        "every frame publishes despite the cursor-file failure"
    );
    assert_eq!(
        harness.ordinal(),
        None,
        "a cursor-file failure freezes the durable ordinal"
    );
    std::fs::rename(&feeds_hold, &feeds).expect("feeds restored");
    harness.tick().await;
    assert_eq!(
        harness.ordinal(),
        Some(1),
        "repair lets the ordinal persist"
    );
    assert_eq!(
        harness.replay_head(session),
        7,
        "no duplicate publication during the frozen window"
    );
    assert_delivered_exactly_once(&harness, session, &fixture.plane.events(session));

    // A restart after the repair reads the persisted ordinal: nothing
    // re-flows.
    drop(harness);
    let harness = fixture.harness(3, 8);
    harness.tick().await;
    assert_eq!(harness.replay_head(session), 7);
    assert_delivered_exactly_once(&harness, session, &fixture.plane.events(session));
}

#[tokio::test]
async fn corrupt_cursor_file_blocks_discovery_across_repeated_ticks_until_repaired() {
    let fixture = Fixture::new();
    let session = LiveSessionId::parse(LIVE_SESSION).unwrap();
    fixture.plane.seed_history(session, 7);
    fixture.discovery.commit(session, 7);
    let scope = ApprovalScope {
        target_kind: "run".to_owned(),
        target_id: "run:feed-test".to_owned(),
        capability_id: CapabilityId::new("cap:write").unwrap(),
        arguments_digest: Digest::hash(b"args"),
    };
    fixture
        .ledger
        .lock()
        .expect("ledger lock")
        .request_approval(NewApproval {
            approval_id: ApprovalId::new("approval:feed-view").unwrap(),
            issuer: "seat:normal".to_owned(),
            scope,
            requested_at: at(0),
            expires_at: at(300),
        })
        .expect("approval requested");

    // Corruption exists BEFORE the pump stack is constructed: the startup
    // checked load is what must catch it, sticky until repair + restart.
    let harness = fixture.harness_with_cursor_setup(3, 8, &|cursor_path| {
        std::fs::write(cursor_path, "not-an-ordinal").expect("corrupt cursor written");
    });
    for _ in 0..3 {
        harness.tick().await;
    }
    assert_eq!(
        harness.replay_head(session),
        0,
        "discovery consumption stays frozen on a corrupt cursor"
    );
    assert_eq!(
        std::fs::read_to_string(&harness.cursor_path).expect("cursor readable"),
        "not-an-ordinal",
        "the corrupt file is never overwritten by the frozen pump"
    );
    // The rest of the pump stays alive: Feed B projects the committed
    // approval while only discovery is frozen.
    let approval_object = ObjectRef {
        kind: ObjectKind::Approval,
        id: "approval:feed-view".to_owned(),
    };
    assert!(
        fixture
            .read_model
            .current_revision(&approval_object)
            .expect("read model query")
            .is_some(),
        "approval projection continues while discovery is frozen"
    );

    // Operator repair + feed-stack restart: consumption resumes from the
    // journal beginning and delivers everything exactly once.
    std::fs::write(&harness.cursor_path, "0").expect("operator repair");
    drop(harness);
    let harness = fixture.harness(3, 8);
    harness.drain(1, 8).await;
    assert_delivered_exactly_once(&harness, session, &fixture.plane.events(session));
    assert_eq!(harness.ordinal(), Some(1));
}

#[tokio::test]
async fn moving_source_head_drains_only_recorded_change_heads_without_starvation() {
    let fixture = Fixture::new();
    let session = LiveSessionId::parse(LIVE_SESSION).unwrap();
    let other = LiveSessionId::parse(OTHER_SESSION).unwrap();
    fixture
        .plane
        .set_roster(single_seat_roster(Some((session, 5, 2)), 900));
    fixture.plane.seed_history(session, 2);
    fixture.plane.seed_history(other, 1);
    fixture.discovery.commit(session, 2); // ordinal 1
    fixture.discovery.commit(other, 1); // ordinal 2, queued behind the live session

    let harness = fixture.harness(3, 2);
    harness.tick().await;
    assert_eq!(harness.replay_head(session), 2);
    assert_eq!(harness.ordinal(), Some(1));

    // The live source head moves PAST the next recorded target before the
    // next tick: the tail must still stop at the recorded change head.
    fixture.plane.seed_history(session, 3); // source head 5
    fixture.discovery.commit(session, 5); // ordinal 3
    fixture.plane.seed_history(session, 3); // source head 8, no change entry yet

    harness.tick().await;
    assert_eq!(
        harness.replay_head(other),
        1,
        "the second session gets its bounded slot right behind the first: no starvation"
    );
    assert_eq!(harness.ordinal(), Some(2));

    harness.tick().await;
    assert_eq!(
        harness.replay_head(session),
        5,
        "the tail drained only the recorded change head while the live head was 8"
    );
    assert_eq!(harness.ordinal(), Some(3));

    // The head movement is committed as its own change entry and drains next.
    fixture.discovery.commit(session, 8); // ordinal 4
    harness.tick().await;
    assert_eq!(harness.replay_head(session), 8);
    assert_eq!(harness.ordinal(), Some(4));

    assert_delivered_exactly_once(&harness, session, &fixture.plane.events(session));
    assert_delivered_exactly_once(&harness, other, &fixture.plane.events(other));
    let live_object = ObjectRef {
        kind: ObjectKind::Session,
        id: session.to_string(),
    };
    assert!(
        fixture
            .read_model
            .current_revision(&live_object)
            .expect("read model query")
            .is_some(),
        "the adopted live session is materialized"
    );
    let terminal_object = ObjectRef {
        kind: ObjectKind::Session,
        id: other.to_string(),
    };
    assert!(
        fixture
            .read_model
            .current_revision(&terminal_object)
            .expect("read model query")
            .is_none(),
        "a terminal session delivered by change entries never fakes a live object"
    );

    // Terminal reclaim through the real pump: the roster drops the adopted
    // session; the tombstone rides the same monotonic feed revision and
    // `RevisionSource` the object was materialized at, even though the
    // empty roster's source freshness is older than the session's last
    // materialized freshness.
    fixture.plane.set_roster(single_seat_roster(None, 901));
    harness.tick().await;
    assert!(
        fixture
            .read_model
            .current_revision(&live_object)
            .expect("read model query")
            .is_none(),
        "the evicted session is tombstoned from the read model"
    );
}

#[tokio::test]
async fn unknown_tail_entry_leaves_the_page_and_later_history_redelivers() {
    let fixture = Fixture::new();
    let ghost = LiveSessionId::parse(LIVE_SESSION).unwrap();
    let live = LiveSessionId::parse(OTHER_SESSION).unwrap();
    // Position 1 names a session with no durable history at all and sits
    // AHEAD of a perfectly tailable entry: the ledger's definitive
    // NotFound answer is terminal, so the pump advances past it instead
    // of head-of-line blocking the page forever.
    fixture.discovery.commit(ghost, 3);
    fixture.plane.seed_history(live, 2);
    fixture.discovery.commit(live, 2);

    let harness = fixture.harness(3, 8);
    harness.drain(2, 8).await;
    assert_eq!(
        harness.replay_head(ghost),
        0,
        "nothing publishes for a session with no durable history"
    );
    assert_eq!(
        harness.ordinal(),
        Some(2),
        "the unknown-tail entry leaves the page: the ordinal advances past it"
    );
    assert_delivered_exactly_once(&harness, live, &fixture.plane.events(live));

    // A later history commit adds a fresh change entry, so the missing entry need not stay pending.
    fixture.plane.seed_history(ghost, 3);
    fixture.discovery.commit(ghost, 3);
    harness.drain(3, 8).await;
    assert_delivered_exactly_once(&harness, ghost, &fixture.plane.events(ghost));
    assert_eq!(harness.ordinal(), Some(3));
}

#[tokio::test]
async fn terminal_session_appearing_and_ending_between_ticks_is_delivered() {
    let fixture = Fixture::new();
    let session = LiveSessionId::parse(LIVE_SESSION).unwrap();
    fixture.plane.seed_history(session, 3);
    fixture.discovery.commit(session, 2); // appeared at head 2
    fixture.discovery.commit(session, 3); // ended at head 3, before any tick

    // The roster stays EMPTY the whole test: the session appears and ends
    // entirely between adoption snapshots.
    let harness = fixture.harness(3, 1);
    harness.drain(2, 8).await;
    assert_delivered_exactly_once(&harness, session, &fixture.plane.events(session));
    assert_eq!(harness.ordinal(), Some(2));
    let object = ObjectRef {
        kind: ObjectKind::Session,
        id: session.to_string(),
    };
    assert!(
        fixture
            .read_model
            .current_revision(&object)
            .expect("read model query")
            .is_none(),
        "a session the roster never listed owns no read-model object"
    );
    let roster_object = ObjectRef {
        kind: ObjectKind::Status,
        id: "roster".to_owned(),
    };
    assert!(
        fixture
            .read_model
            .current_revision(&roster_object)
            .expect("read model query")
            .is_some(),
        "empty-roster adoption still ran every tick"
    );
}

#[test]
fn terminal_sessions_never_hold_roster_capacity() {
    use odin_domain::huginn::{SeatLiveState, SeatRosterEntry};

    let store = SessionProjectionStore::new(
        SeatRoster::new(
            RosterRevision::new(0),
            OffsetDateTime::UNIX_EPOCH,
            Vec::new(),
        ),
        2,
        100_u16.try_into().unwrap(),
    )
    .unwrap();
    let roster = |revision: u64, states: &[LiveSessionState]| {
        let sessions = states
            .iter()
            .enumerate()
            .map(|(index, state)| {
                let id = format!(
                    "11111111-2222-4333-8444-{:012}",
                    revision * 100 + index as u64
                );
                let mut row = summary(LiveSessionId::parse(&id).unwrap(), index as i64, 1);
                row.state = *state;
                row
            })
            .collect();
        SeatRoster::new(
            RosterRevision::new(revision),
            at(99),
            vec![SeatRosterEntry {
                seat_id: SeatId::new("architect").unwrap(),
                slice_id: SliceId::new("architect-engine").unwrap(),
                display_name: "Architect".to_owned(),
                state: SeatLiveState::Running,
                active_sessions: sessions,
                launch_options: Vec::new(),
                diagnostic: None,
            }],
        )
    };
    let failed = LiveSessionState::Failed;
    store
        .replace_roster(roster(
            1,
            &[failed, failed, failed, LiveSessionState::Running],
        ))
        .expect("three failed rows plus one live session fit a cap of two");
    let refused = store
        .replace_roster(roster(2, &[LiveSessionState::Running; 3]))
        .expect_err("three live sessions exceed a cap of two");
    assert!(matches!(refused, HuginnProtocolError::ResourceLimit { .. }));
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

#[test]
fn a_session_without_a_process_is_never_captured() {
    let mut session = summary(LiveSessionId::parse(LIVE_SESSION).unwrap(), 1, 1);
    session.terminal_head = TerminalSeq::new(3);
    session.state = LiveSessionState::Idle;
    assert!(super::terminal::eligible(&session));
    session.state = LiveSessionState::Detached;
    assert!(!super::terminal::eligible(&session));
}
