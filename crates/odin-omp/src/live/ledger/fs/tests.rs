//! Filesystem journal fault, restart, pagination, and corruption tests.
//! Every fault is a deterministic filesystem obstacle (a directory
//! standing in for a segment file, a renumbered or removed segment, a
//! torn or scribbled tail) — no privileges, no sleeps, no injected shims.

use std::num::NonZeroU16;
use std::path::{Path, PathBuf};

use odin_domain::huginn::{
    EventSeq, HistoryQuery, LiveEvent, LiveEventBody, LiveSessionId, LiveSessionState, ModelName,
    ProviderName, SessionEpoch, SessionManifest, SessionOpened, SessionStateChanged, TerminalSeq,
    TerminalSnapshotRef,
};
use odin_domain::{ArtifactId, EventId, NodeId, ProjectId, SeatId, SliceId};
use time::OffsetDateTime;

use super::{
    encode_cbor, ChangeRecord, FsLiveLedger, LedgerError, ResidentLimits, CHANGES_PREFIX,
    CHANGE_SEGMENT_MAX_RECORDS, ENDED_SESSION_RETENTION, EVENTS_PREFIX,
};
use crate::live::ledger::segment::{SegmentLayout, SegmentReader, SegmentWriter};
use crate::live::ledger::{
    BlobKind, BlobSource, LiveLedger, NewLiveEvent, SessionBlob, SessionChange,
};

fn session_a() -> LiveSessionId {
    LiveSessionId::parse("00000000-0000-4000-8000-00000000e6a5").expect("session a id")
}

fn session_b() -> LiveSessionId {
    LiveSessionId::parse("00000000-0000-4000-8000-00000000e6a6").expect("session b id")
}

/// A filler session that never exists in the ledger state, so crafted
/// journal frames are distinguishable from real ones at open.
fn session_filler() -> LiveSessionId {
    LiveSessionId::parse("00000000-0000-4000-8000-00000000ff01").expect("filler id")
}

fn fixture() -> tempfile::TempDir {
    tempfile::tempdir().expect("tempdir")
}

fn manifest(session_id: LiveSessionId) -> SessionManifest {
    SessionManifest {
        session_id,
        seat_id: SeatId::new("seat:journal-proof").expect("seat id"),
        slice_id: SliceId::new("slice:journal-proof").expect("slice id"),
        project_id: ProjectId::new("project:journal-proof").expect("project id"),
        provider: ProviderName::new("fixture").expect("provider name"),
        model: ModelName::new("fixture-model").expect("model name"),
        title: None,
        target_node: NodeId::new("node:journal-proof").expect("node id"),
        open_tab: false,
        workload: None,
        served_revision: None,
        harness: None,
    }
}

/// Appends one opened-event at the session's current epoch; the body
/// never carries a blob, so the write reaches the event segment commit
/// itself rather than a preflight blob refusal.
async fn commit_event(
    ledger: &FsLiveLedger,
    session_id: LiveSessionId,
    tag: &str,
) -> Result<LiveEvent, LedgerError> {
    ledger
        .append(
            SessionEpoch::new(1),
            NewLiveEvent {
                session_id,
                event_id: EventId::new(format!("journal-proof:{session_id}:{tag}"))
                    .expect("event id"),
                occurred_at: OffsetDateTime::UNIX_EPOCH,
                body: LiveEventBody::SessionOpened(SessionOpened {
                    manifest: Box::new(manifest(session_id)),
                }),
            },
        )
        .await
}

fn changes_layout(root: &Path) -> SegmentLayout {
    SegmentLayout::Numbered {
        dir: root.join("changes"),
        prefix: CHANGES_PREFIX,
    }
}

fn segment_path(root: &Path, index: u64) -> PathBuf {
    changes_layout(root).nth_path(index)
}

/// Builds a real ledger whose change journal spans the rotation ceiling:
/// segment 0 holds exactly `CHANGE_SEGMENT_MAX_RECORDS` frames (the two
/// creation hints and two event hints of real sessions plus filler) and
/// the final segment 1 holds three filler frames — 8195 durable ordinals
/// in total.
async fn craft_journal_across_the_rotation_boundary(root: &Path) {
    let ledger = FsLiveLedger::open(root).expect("fixture ledger opens");
    for session in [session_a(), session_b()] {
        ledger
            .create_session(manifest(session))
            .await
            .expect("fixture session");
    }
    commit_event(&ledger, session_a(), "a1")
        .await
        .expect("fixture event commits");
    commit_event(&ledger, session_b(), "b1")
        .await
        .expect("fixture event commits");
    drop(ledger);

    let filler = encode_cbor(&ChangeRecord {
        session_id: session_filler(),
        head: EventSeq::new(0),
    })
    .expect("filler frame encodes");
    let mut writer = SegmentWriter::resume(changes_layout(root)).expect("writer resumes");
    // 4 real + filler frames: segment 0 reaches exactly the ceiling.
    for _ in 4..CHANGE_SEGMENT_MAX_RECORDS {
        writer.append(&filler).expect("segment 0 fills");
    }
    writer.rotate().expect("segment 1 opens");
    for _ in 0..3 {
        writer.append(&filler).expect("segment 1 fills");
    }
    writer.commit().expect("segment 1 commits");
}

fn change_positions(changes: &[SessionChange]) -> Vec<u64> {
    changes.iter().map(|change| change.position).collect()
}

fn assert_strictly_ascending(changes: &[SessionChange]) {
    assert!(
        changes
            .windows(2)
            .all(|pair| pair[0].position < pair[1].position),
        "change ordinals must be strictly ascending: {:?}",
        change_positions(changes)
    );
}

/// After a degraded latch EVERY source read and mutation refuses with the
/// typed degraded error before touching any journal byte.
async fn assert_degraded_refusals(ledger: &FsLiveLedger, session: LiveSessionId) {
    let refused = ledger.session(session).await.expect_err("read refuses");
    assert!(
        matches!(refused, LedgerError::JournalDegraded),
        "session read: {refused}"
    );
    let refused = ledger.sessions().await.expect_err("read refuses");
    assert!(
        matches!(refused, LedgerError::JournalDegraded),
        "sessions read: {refused}"
    );
    let refused = ledger
        .sessions_after(None, 4)
        .await
        .expect_err("read refuses");
    assert!(
        matches!(refused, LedgerError::JournalDegraded),
        "sessions_after read: {refused}"
    );
    let refused = ledger.changes_after(0, 4).await.expect_err("read refuses");
    assert!(
        matches!(refused, LedgerError::JournalDegraded),
        "changes_after read: {refused}"
    );
    let refused = ledger.head(session).await.expect_err("read refuses");
    assert!(
        matches!(refused, LedgerError::JournalDegraded),
        "head read: {refused}"
    );
    let refused = ledger
        .history(HistoryQuery {
            session_id: session,
            after: EventSeq::new(0),
            limit: NonZeroU16::new(4).expect("history limit"),
        })
        .await
        .expect_err("read refuses");
    assert!(
        matches!(refused, LedgerError::JournalDegraded),
        "history read: {refused}"
    );
    let refused = ledger
        .create_session(manifest(session_filler()))
        .await
        .expect_err("mutation refuses");
    assert!(
        matches!(refused, LedgerError::JournalDegraded),
        "create_session: {refused}"
    );
    let refused = ledger.reclaim(session).await.expect_err("mutation refuses");
    assert!(
        matches!(refused, LedgerError::JournalDegraded),
        "reclaim: {refused}"
    );
    let refused = ledger
        .append(
            SessionEpoch::new(1),
            NewLiveEvent {
                session_id: session,
                event_id: EventId::new("journal-proof:degraded").expect("event id"),
                occurred_at: OffsetDateTime::UNIX_EPOCH,
                body: LiveEventBody::SessionOpened(SessionOpened {
                    manifest: Box::new(manifest(session)),
                }),
            },
        )
        .await
        .expect_err("mutation refuses");
    assert!(
        matches!(refused, LedgerError::JournalDegraded),
        "append: {refused}"
    );
}

/// A reopened ledger holds no event bodies, so history pages them from the
/// durable segments: same pages, same heads, and a fresh append continues
/// the durable sequence and re-seeds the resident tail.
#[tokio::test]
async fn a_reopened_ledger_pages_history_from_the_segments() {
    let dir = fixture();
    let session = session_a();
    {
        let ledger = FsLiveLedger::open(dir.path()).expect("ledger opens");
        ledger
            .create_session(manifest(session))
            .await
            .expect("session created");
        for tag in ["a1", "a2", "a3"] {
            commit_event(&ledger, session, tag)
                .await
                .expect("event commits");
        }
    }
    let reloaded = FsLiveLedger::open(dir.path()).expect("ledger reopens");
    assert_eq!(
        reloaded.head(session).await.expect("durable head").get(),
        3,
        "the reopened ledger reports the durable head without holding bodies"
    );
    let page = reloaded
        .history(HistoryQuery {
            session_id: session,
            after: EventSeq::new(1),
            limit: NonZeroU16::new(128).expect("history limit"),
        })
        .await
        .expect("history pages from the segments");
    assert_eq!(
        page.events
            .iter()
            .map(|event| event.sequence.get())
            .collect::<Vec<_>>(),
        [2, 3],
        "a page after the cursor returns the exact durable events"
    );
    commit_event(&reloaded, session, "a4")
        .await
        .expect("an append continues the durable sequence");
    let tail = reloaded
        .history(HistoryQuery {
            session_id: session,
            after: EventSeq::new(3),
            limit: NonZeroU16::new(128).expect("history limit"),
        })
        .await
        .expect("the resident tail serves pages past the reloaded head");
    assert_eq!(tail.events.len(), 1);
    assert_eq!(tail.events[0].sequence.get(), 4);
}

/// The reloaded id set still refuses a duplicate append of an event that
/// predates the restart.
#[tokio::test]
async fn a_reopened_ledger_refuses_a_duplicate_of_a_reloaded_event() {
    let dir = fixture();
    let session = session_a();
    {
        let ledger = FsLiveLedger::open(dir.path()).expect("ledger opens");
        ledger
            .create_session(manifest(session))
            .await
            .expect("session created");
        commit_event(&ledger, session, "dup")
            .await
            .expect("event commits");
    }
    let reloaded = FsLiveLedger::open(dir.path()).expect("ledger reopens");
    let refused = reloaded
        .append(
            SessionEpoch::new(1),
            NewLiveEvent {
                session_id: session,
                event_id: EventId::new(format!("journal-proof:{session}:dup")).expect("event id"),
                occurred_at: OffsetDateTime::UNIX_EPOCH,
                body: LiveEventBody::SessionOpened(SessionOpened {
                    manifest: Box::new(manifest(session)),
                }),
            },
        )
        .await
        .expect_err("a reloaded id is still refused");
    assert!(
        matches!(refused, LedgerError::DuplicateEvent(_)),
        "duplicate append: {refused}"
    );
}

/// Walks the whole durable history in bounded pages and returns each
/// event as (sequence, event-id): the exact-once, in-order view a lagging
/// reader must observe.
async fn walk_every_event(ledger: &FsLiveLedger, session: LiveSessionId) -> Vec<(u64, String)> {
    let mut after = EventSeq::new(0);
    let mut seen = Vec::new();
    loop {
        let page = ledger
            .history(HistoryQuery {
                session_id: session,
                after,
                limit: NonZeroU16::new(5).expect("history limit"),
            })
            .await
            .expect("history page");
        if page.events.is_empty() {
            return seen;
        }
        for event in &page.events {
            seen.push((event.sequence.get(), event.event_id.as_str().to_owned()));
        }
        after = page.next_after;
    }
}

/// Tails small enough that a few journaled events reach every paged read.
const SMALL_TAILS: ResidentLimits = ResidentLimits {
    events: 6,
    sessions: 2,
};

fn small_tails(root: &Path) -> FsLiveLedger {
    FsLiveLedger::open(root)
        .expect("ledger opens")
        .with_resident(SMALL_TAILS)
}

/// A reader lagging past the resident tail pages the durable segments and
/// receives every event exactly once and in order — while the session
/// runs, and again after a reopen that holds no tail.
#[tokio::test]
async fn a_reader_lagging_past_the_resident_tail_pages_every_event_once() {
    let dir = fixture();
    let session = session_a();
    let ledger = small_tails(dir.path());
    ledger
        .create_session(manifest(session))
        .await
        .expect("session created");
    let tail = SMALL_TAILS.events as u64;
    let total = tail * 2 + 3;
    for step in 1..=total {
        commit_event(&ledger, session, &format!("lag-{step}"))
            .await
            .expect("event commits");
    }
    let expected = (1..=total)
        .map(|step| (step, format!("journal-proof:{session}:lag-{step}")))
        .collect::<Vec<_>>();
    assert_eq!(walk_every_event(&ledger, session).await, expected);
    // One page straddling the tail's front serves from the segments: the
    // page starts exactly at the cursor, not at the tail's front.
    let straddling_query = HistoryQuery {
        session_id: session,
        after: EventSeq::new(total - tail - 2),
        limit: NonZeroU16::new(8).expect("history limit"),
    };
    let straddling = ledger
        .history(straddling_query.clone())
        .await
        .expect("straddling page");
    assert_eq!(
        straddling
            .events
            .first()
            .expect("page holds events")
            .sequence
            .get(),
        total - tail - 1,
        "the page begins at the cursor, not at the resident tail's front"
    );
    drop(ledger);

    let reloaded = small_tails(dir.path());
    assert_eq!(walk_every_event(&reloaded, session).await, expected);
    let straddling = reloaded
        .history(straddling_query)
        .await
        .expect("straddling page after reopen");
    assert_eq!(
        straddling
            .events
            .first()
            .expect("page holds events")
            .sequence
            .get(),
        total - tail - 1,
        "the reopened ledger serves the same page from the segments"
    );
}

/// An event commit that fails after admission must latch the degraded
/// gate until reopen reconciles from durable truth. The ambiguous event
/// resolves to absent (the obstacle never let the frame persist), the
/// session head does not move, and the reopened ledger is live again.
#[tokio::test]
async fn event_commit_failure_latches_degraded_until_reopen_resolves_durable_truth() {
    let dir = fixture();
    let ledger = FsLiveLedger::open(dir.path()).expect("ledger opens");
    let session = session_a();
    ledger
        .create_session(manifest(session))
        .await
        .expect("session created");

    // Deterministic obstacle for any user: the event segment path is a
    // directory, so the event frame commit fails the moment it opens.
    let obstacle = dir
        .path()
        .join("sessions")
        .join(session.to_string())
        .join("events")
        .join(format!("{EVENTS_PREFIX}-00000000.seg"));
    std::fs::create_dir_all(&obstacle).expect("obstacle stands");

    let failure = commit_event(&ledger, session, "ambiguous").await;
    assert!(
        failure.is_err(),
        "the event commit must fail on the obstacle"
    );
    assert_degraded_refusals(&ledger, session).await;

    // Reopen reconciles from durable truth: the ambiguous event never
    // persisted, so the session restarts at head 0 with only its
    // creation hint journaled — no phantom frame, no moved head.
    drop(ledger);
    std::fs::remove_dir_all(&obstacle).expect("obstacle removed");
    let reopened = FsLiveLedger::open(dir.path()).expect("reopen reconciles");
    assert_eq!(
        reopened.head(session).await.expect("head"),
        EventSeq::new(0)
    );
    let changes = reopened.changes_after(0, 16).await.expect("changes page");
    assert_eq!(change_positions(&changes), vec![1]);
    assert_eq!(changes[0].session_id, session);
    assert_eq!(changes[0].head, EventSeq::new(0));

    // The reopened ledger is live again and sequences from where the
    // durable truth stands.
    let event = commit_event(&reopened, session, "after-recovery")
        .await
        .expect("event commits after recovery");
    assert_eq!(event.sequence, EventSeq::new(1));
    let changes = reopened.changes_after(1, 16).await.expect("changes page");
    assert_eq!(change_positions(&changes), vec![2]);
    assert_eq!(changes[0].head, EventSeq::new(1));
}

#[tokio::test]
async fn fresh_handoff_is_atomic_recoverable_and_correlated_to_the_command() {
    let dir = fixture();
    let ledger = FsLiveLedger::open(dir.path()).unwrap();
    let session = session_a();
    ledger.create_session(manifest(session)).await.unwrap();
    let command = odin_domain::huginn::LiveCommand {
        command_id: odin_domain::CommandId::new("command:fresh").unwrap(),
        session_id: session,
        expected_epoch: SessionEpoch::new(1),
        expected_event_head: None,
        body: odin_domain::huginn::LiveCommandBody::Pause,
    };
    let bytes = b"exact owner information".to_vec();
    ledger
        .append_fresh_command(&command, bytes.clone())
        .await
        .unwrap();
    assert!(ledger
        .append_fresh_command(&command, b"different".to_vec())
        .await
        .is_err());
    drop(ledger);
    let reopened = FsLiveLedger::open(dir.path()).unwrap();
    assert_eq!(
        reopened.fresh_handoff(&command).await.unwrap(),
        Some(bytes.clone())
    );
    assert_eq!(
        reopened.pending_fresh_handoffs().await.unwrap(),
        vec![(command.clone(), bytes)]
    );
    let mut changed = command.clone();
    changed.body = odin_domain::huginn::LiveCommandBody::Resume;
    assert!(reopened.fresh_handoff(&changed).await.is_err());
    reopened
        .complete_command(
            command.command_id.clone(),
            odin_domain::huginn::CommandOutcome::Applied {
                command_id: command.command_id.clone(),
            },
        )
        .await
        .unwrap();
    assert!(reopened.pending_fresh_handoffs().await.unwrap().is_empty());
}

/// Pagination across the 8192-frame rotation boundary: ordinals map to
/// segment and in-segment position exactly (n / ceiling, n % ceiling),
/// pages are strictly ascending and complete across the seam, the page
/// past the durable end is empty, and the writer resumes at the true
/// tail.
#[tokio::test]
async fn change_pages_cross_the_rotation_boundary_in_order_and_end_empty() {
    let dir = fixture();
    craft_journal_across_the_rotation_boundary(dir.path()).await;

    let ledger = FsLiveLedger::open(dir.path()).expect("boundary journal opens");
    let first_page = ledger
        .changes_after(0, CHANGE_SEGMENT_MAX_RECORDS as usize)
        .await
        .expect("first page");
    assert_eq!(first_page.len() as u64, CHANGE_SEGMENT_MAX_RECORDS);
    assert_strictly_ascending(&first_page);
    assert_eq!(change_positions(&first_page)[0], 1);
    assert_eq!(first_page[8191].position, CHANGE_SEGMENT_MAX_RECORDS);
    // The four real frames lead the journal; the rest is filler.
    assert_eq!(first_page[0].session_id, session_a());
    assert_eq!(first_page[0].head, EventSeq::new(0));
    assert_eq!(first_page[1].session_id, session_b());
    assert_eq!(first_page[1].head, EventSeq::new(0));
    assert_eq!(first_page[2].head, EventSeq::new(1));
    assert_eq!(first_page[3].head, EventSeq::new(1));

    // The seam page: the last two ordinals of segment 0 and all three of
    // segment 1 arrive in one ascending, complete page.
    let seam = ledger.changes_after(8190, 8).await.expect("seam page");
    assert_eq!(change_positions(&seam), vec![8191, 8192, 8193, 8194, 8195]);
    assert!(
        seam.iter()
            .all(|change| change.session_id == session_filler()),
        "filler ordinals cross the seam untouched"
    );

    // The final entry and the empty tail beyond the durable end.
    let last = ledger.changes_after(8194, 8).await.expect("last page");
    assert_eq!(change_positions(&last), vec![8195]);
    let tail = ledger.changes_after(8195, 8).await.expect("tail page");
    assert!(
        tail.is_empty(),
        "the page past the durable end is empty: {tail:?}"
    );

    // The writer resumed at the true tail: the next real hint continues
    // the ordinal stream inside the final segment.
    commit_event(&ledger, session_a(), "a2")
        .await
        .expect("event commits");
    let next = ledger.changes_after(8195, 8).await.expect("post-seam page");
    assert_eq!(change_positions(&next), vec![8196]);
    assert_eq!(next[0].session_id, session_a());
    assert_eq!(next[0].head, EventSeq::new(2));
}

/// Corruption INSIDE a non-final segment is typed corruption, never a
/// recoverable tail: open refuses, and the refusal does not truncate or
/// rewrite the durable journal.
#[tokio::test]
async fn a_torn_middle_segment_is_typed_corruption_not_silent_recovery() {
    let dir = fixture();
    craft_journal_across_the_rotation_boundary(dir.path()).await;
    let seg0 = segment_path(dir.path(), 0);
    let before = std::fs::metadata(&seg0).expect("segment metadata").len();

    // Flip the final digest byte of the middle segment: the frame no
    // longer matches its digest, so the scan stops inside the segment.
    let mut corrupted = std::fs::read(&seg0).expect("segment bytes");
    let last = corrupted.len() - 1;
    corrupted[last] ^= 0xff;
    std::fs::write(&seg0, &corrupted).expect("corruption written");

    let error = FsLiveLedger::open(dir.path())
        .err()
        .expect("a torn middle segment must refuse to open");
    assert!(
        matches!(error, LedgerError::JournalInvariant(_)),
        "the refusal must be typed: {error}"
    );
    // The refusal never destroys the durable bytes.
    assert_eq!(
        std::fs::metadata(&seg0).expect("segment metadata").len(),
        before
    );
}

/// A torn FINAL segment is the recoverable case: open truncates to the
/// last whole frame, the committed ordinals page exactly (the torn write
/// is neither delivered nor duplicated), and writes continue from the
/// recovered tail.
#[tokio::test]
async fn a_torn_final_segment_truncates_to_the_last_whole_frame_and_continues() {
    let dir = fixture();
    craft_journal_across_the_rotation_boundary(dir.path()).await;
    let seg1 = segment_path(dir.path(), 1);

    // Saw five bytes off the tail: the last frame ends mid-digest.
    let pristine = std::fs::read(&seg1).expect("segment bytes");
    std::fs::write(&seg1, &pristine[..pristine.len() - 5]).expect("tail torn");

    let ledger = FsLiveLedger::open(dir.path()).expect("a torn tail is recoverable");
    // The recovery truncated the file back to the whole-frame boundary.
    let (records, valid_bytes) = SegmentReader::scan_file(&seg1).expect("segment scans");
    assert_eq!(records.len(), 2, "the torn third frame is gone");
    assert_eq!(
        std::fs::metadata(&seg1).expect("segment metadata").len(),
        valid_bytes
    );

    // Exactly the committed ordinals remain.
    let tail = ledger.changes_after(8192, 8).await.expect("tail page");
    assert_eq!(change_positions(&tail), vec![8193, 8194]);

    // The ledger continues writing from the recovered tail.
    commit_event(&ledger, session_a(), "a2")
        .await
        .expect("event commits");
    let next = ledger
        .changes_after(8194, 8)
        .await
        .expect("post-recovery page");
    assert_eq!(change_positions(&next), vec![8195]);
    assert_eq!(next[0].session_id, session_a());
    assert_eq!(next[0].head, EventSeq::new(2));
}

/// Opens `session`, holds each of `blobs` as a terminal snapshot, then goes `state` at `at`.
async fn session_with_blobs(
    ledger: &FsLiveLedger,
    session: LiveSessionId,
    blobs: &[&[u8]],
    state: LiveSessionState,
    at: OffsetDateTime,
) -> Vec<crate::live::ledger::BlobRef> {
    ledger
        .create_session(manifest(session))
        .await
        .expect("session");
    let mut stored = Vec::new();
    let mut bodies = Vec::new();
    for (index, bytes) in blobs.iter().enumerate() {
        let blob = ledger
            .store_blob(BlobSource::Bytes(SessionBlob {
                session_id: session,
                epoch: SessionEpoch::new(1),
                kind: BlobKind::Terminal,
                bytes: bytes.to_vec(),
            }))
            .await
            .expect("blob");
        bodies.push(LiveEventBody::TerminalSnapshot(TerminalSnapshotRef {
            session_id: session,
            epoch: SessionEpoch::new(1),
            sequence: TerminalSeq::new(index as u64 + 1),
            columns: NonZeroU16::new(80).expect("columns"),
            rows: NonZeroU16::new(24).expect("rows"),
            artifact_id: ArtifactId::new(format!("terminal:snapshot:{}", blob.digest.hex()))
                .expect("artifact id"),
            byte_len: blob.byte_len,
            content_digest: blob.digest,
        }));
        stored.push(blob);
    }
    bodies.push(LiveEventBody::SessionStateChanged(SessionStateChanged {
        previous: LiveSessionState::Running,
        current: state,
        reason: None,
    }));
    for (index, body) in bodies.into_iter().enumerate() {
        ledger
            .append(
                SessionEpoch::new(1),
                NewLiveEvent {
                    session_id: session,
                    event_id: EventId::new(format!("retention:{session}:{index}"))
                        .expect("event id"),
                    occurred_at: at,
                    body,
                },
            )
            .await
            .expect("event");
    }
    stored
}

/// A session that ended before the retention window leaves the ledger when it opens, with the
/// blobs only it held. A recent ended session, one still running however quiet, and a blob an
/// expired and a kept session both hold stay.
#[tokio::test]
async fn ended_sessions_past_retention_leave_on_open_with_their_blobs() {
    let dir = fixture();
    let now = OffsetDateTime::UNIX_EPOCH + time::Duration::days(100);
    let stale = now - ENDED_SESSION_RETENTION - time::Duration::days(1);
    let recent = now - time::Duration::days(1);
    let ledger = FsLiveLedger::open_at(dir.path(), now).expect("ledger");
    let (old, kept, running) = (session_a(), session_b(), session_filler());
    let ended = LiveSessionState::Ended;
    let old_blobs = session_with_blobs(&ledger, old, &[b"old only", b"shared"], ended, stale).await;
    let kept_blobs = session_with_blobs(&ledger, kept, &[b"shared"], ended, recent).await;
    let quiet = session_with_blobs(
        &ledger,
        running,
        &[b"quiet"],
        LiveSessionState::Running,
        stale,
    )
    .await;
    assert_eq!(old_blobs[1].digest, kept_blobs[0].digest);
    drop(ledger);

    let ledger = FsLiveLedger::open_at(dir.path(), now).expect("ledger reopens");
    assert!(matches!(
        ledger.session(old).await,
        Err(LedgerError::SessionMissing(_))
    ));
    assert!(!dir.path().join("sessions").join(old.to_string()).exists());
    for session in [kept, running] {
        ledger.session(session).await.expect("session stays");
    }
    assert!(matches!(
        ledger.read_blob(&old_blobs[0]).await,
        Err(LedgerError::BlobMissing(_))
    ));
    for blob in [&kept_blobs[0], &quiet[0]] {
        ledger.read_blob(blob).await.expect("blob stays");
    }
}
