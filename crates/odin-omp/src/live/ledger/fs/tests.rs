//! Filesystem journal fault, restart, pagination, and corruption tests.
//! Every fault is a deterministic filesystem obstacle (a directory
//! standing in for a segment file, a renumbered or removed segment, a
//! torn or scribbled tail) — no privileges, no sleeps, no injected shims.

use std::num::NonZeroU16;
use std::path::{Path, PathBuf};

use odin_domain::huginn::{
    EventSeq, HistoryQuery, LiveEvent, LiveEventBody, LiveSessionId, ModelName, ProviderName,
    SessionEpoch, SessionManifest, SessionOpened,
};
use odin_domain::{EventId, NodeId, ProjectId, SeatId, SliceId};
use time::OffsetDateTime;

use super::{
    encode_cbor, ChangeRecord, FsLiveLedger, LedgerError, CHANGES_PREFIX,
    CHANGE_SEGMENT_MAX_RECORDS, COMMANDS_PREFIX, EVENTS_PREFIX,
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

/// A command frame whose write fails is as ambiguous as an event frame:
/// the ledger refuses everything until reopen, instead of acknowledging
/// later commits beside it.
#[tokio::test]
async fn command_commit_failure_latches_degraded() {
    let dir = fixture();
    let ledger = FsLiveLedger::open(dir.path()).expect("ledger opens");
    let session = session_a();
    ledger
        .create_session(manifest(session))
        .await
        .expect("session created");
    let obstacle = dir
        .path()
        .join("sessions")
        .join(session.to_string())
        .join("commands")
        .join(format!("{COMMANDS_PREFIX}-00000000.seg"));
    std::fs::create_dir_all(&obstacle).expect("obstacle stands");
    let command = odin_domain::huginn::LiveCommand {
        command_id: odin_domain::CommandId::new("command:ambiguous").expect("command id"),
        session_id: session,
        expected_epoch: SessionEpoch::new(1),
        expected_event_head: None,
        body: odin_domain::huginn::LiveCommandBody::Pause,
    };
    ledger
        .append_command(&command)
        .await
        .expect_err("the command commit fails on the obstacle");
    assert_degraded_refusals(&ledger, session).await;
}

/// A hint commit failure after the event frame persisted must latch the
/// degraded gate, and reopen must synthesize exactly the one missing
/// change frame from the durable event head — no duplicate ordinal, no
/// missing sequence step, and the latch clears.
#[tokio::test]
async fn hint_commit_failure_latches_degraded_and_reopen_synthesizes_the_missing_head() {
    let dir = fixture();
    let ledger = FsLiveLedger::open(dir.path()).expect("ledger opens");
    let session = session_a();
    ledger
        .create_session(manifest(session))
        .await
        .expect("session created");
    commit_event(&ledger, session, "first")
        .await
        .expect("event commits");

    // Preserve the two committed frames, then stand a directory in the
    // segment's place so the next hint commit fails for any user.
    let seg0 = segment_path(dir.path(), 0);
    let durable_frames = std::fs::read(&seg0).expect("durable frames");
    std::fs::remove_file(&seg0).expect("segment lifted");
    std::fs::create_dir(&seg0).expect("obstacle stands");

    let failure = commit_event(&ledger, session, "second").await;
    assert!(
        failure.is_err(),
        "the hint commit must fail on the obstacle"
    );
    // The event frame IS durable; the latch refuses every source surface
    // until reopen reconciles the missing hint.
    assert_degraded_refusals(&ledger, session).await;

    // Restore the durable frames and reopen: open-time reconciliation
    // observes durable head 2 against journaled head 1 and synthesizes
    // exactly one change frame.
    std::fs::remove_dir(&seg0).expect("obstacle lifted");
    std::fs::write(&seg0, durable_frames).expect("frames restored");
    drop(ledger);
    let reopened = FsLiveLedger::open(dir.path()).expect("reopen reconciles the hint");
    assert_eq!(
        reopened.head(session).await.expect("head"),
        EventSeq::new(2)
    );
    let changes = reopened.changes_after(0, 16).await.expect("changes page");
    assert_strictly_ascending(&changes);
    assert_eq!(change_positions(&changes), vec![1, 2, 3]);
    assert!(changes.iter().all(|change| change.session_id == session));
    let heads: Vec<u64> = changes.iter().map(|change| change.head.get()).collect();
    assert_eq!(
        heads,
        vec![0, 1, 2],
        "one frame per sequence step: no duplicate, no gap"
    );

    // The reconciled ledger continues the journal without a hiccup.
    commit_event(&reopened, session, "third")
        .await
        .expect("event commits");
    let changes = reopened.changes_after(3, 16).await.expect("changes page");
    assert_eq!(change_positions(&changes), vec![4]);
    assert_eq!(changes[0].head, EventSeq::new(3));
}

/// A journal from before the change feed existed at all: reopening must
/// bootstrap hints for every durable session — the moved head AND the
/// untouched head-zero session — so no session is invisible to a change
/// consumer, and the bootstrap never duplicates on a further reopen.
#[tokio::test]
async fn legacy_journal_without_change_frames_bootstraps_hints_including_head_zero() {
    let dir = fixture();
    let ledger = FsLiveLedger::open(dir.path()).expect("ledger opens");
    let a = session_a();
    let b = session_b();
    ledger
        .create_session(manifest(a))
        .await
        .expect("session a created");
    ledger
        .create_session(manifest(b))
        .await
        .expect("session b created");
    commit_event(&ledger, a, "a1").await.expect("event commits");
    drop(ledger);

    // The legacy strip: the change journal has never existed here.
    std::fs::remove_dir_all(dir.path().join("changes")).expect("change journal stripped");

    let reopened = FsLiveLedger::open(dir.path()).expect("legacy journal bootstraps");
    let changes = reopened.changes_after(0, 16).await.expect("changes page");
    assert_strictly_ascending(&changes);
    assert_eq!(change_positions(&changes), vec![1, 2]);
    // Ordered session-id reconciliation: the moved head first, then the
    // untouched session's creation entry at head zero.
    assert_eq!(changes[0].session_id, a);
    assert_eq!(changes[0].head, EventSeq::new(1));
    assert_eq!(changes[1].session_id, b);
    assert_eq!(
        changes[1].head,
        EventSeq::new(0),
        "head-zero sessions are journaled too"
    );

    // The bootstrap is idempotent: a further reopen adds no frames.
    drop(reopened);
    let again = FsLiveLedger::open(dir.path()).expect("reopened ledger reopens");
    let changes = again.changes_after(0, 16).await.expect("changes page");
    assert_eq!(
        change_positions(&changes),
        vec![1, 2],
        "no duplicate bootstrap hints"
    );

    // And normal operation continues from the bootstrapped journal.
    commit_event(&again, b, "b1").await.expect("event commits");
    let changes = again.changes_after(2, 16).await.expect("changes page");
    assert_eq!(change_positions(&changes), vec![3]);
    assert_eq!(changes[0].session_id, b);
    assert_eq!(changes[0].head, EventSeq::new(1));
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

/// A segment gap fails typed at open; a segment that vanishes while the
/// open ledger still owes ordinals fails typed at the indexed read
/// instead of returning a silently short page.
#[tokio::test]
async fn a_segment_gap_fails_typed_at_open_and_a_missing_tail_fails_typed_at_read() {
    let dir = fixture();
    craft_journal_across_the_rotation_boundary(dir.path()).await;
    let seg1 = segment_path(dir.path(), 1);

    // A renumbered segment leaves a hole in the sequence: open refuses
    // typed instead of reading a reordered journal.
    std::fs::rename(&seg1, segment_path(dir.path(), 3)).expect("segment renumbered");
    let error = FsLiveLedger::open(dir.path())
        .err()
        .expect("the gap must refuse to open");
    assert!(
        matches!(error, LedgerError::JournalInvariant(_)),
        "typed: {error}"
    );
    std::fs::rename(segment_path(dir.path(), 3), &seg1).expect("numbering restored");

    // The intact journal reopens and owes 8195 ordinals.
    let ledger = FsLiveLedger::open(dir.path()).expect("intact journal opens");
    std::fs::remove_file(&seg1).expect("final segment vanishes after open");
    let error = ledger
        .changes_after(8192, 8)
        .await
        .expect_err("a missing tail segment must refuse typed");
    assert!(
        matches!(error, LedgerError::JournalInvariant(_)),
        "typed: {error}"
    );
    // A page that ends exactly at the surviving segment's boundary
    // still pages complete and ordered without entering the missing
    // segment.
    let kept = ledger.changes_after(8184, 8).await.expect("surviving page");
    assert_eq!(
        change_positions(&kept),
        vec![8185, 8186, 8187, 8188, 8189, 8190, 8191, 8192]
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

/// Scribbled bytes at the START of a final segment are not a torn tail:
/// no whole frame survives, so open refuses typed instead of silently
/// emptying the journal.
#[tokio::test]
async fn an_unusable_first_frame_in_the_final_segment_fails_typed() {
    let dir = fixture();
    let ledger = FsLiveLedger::open(dir.path()).expect("ledger opens");
    let session = session_a();
    ledger
        .create_session(manifest(session))
        .await
        .expect("session created");
    drop(ledger);

    let seg0 = segment_path(dir.path(), 0);
    std::fs::write(&seg0, [0xff_u8; 64]).expect("segment scribbled");

    let error = FsLiveLedger::open(dir.path())
        .err()
        .expect("scribbled journal refuses");
    assert!(
        matches!(error, LedgerError::JournalInvariant(_)),
        "typed: {error}"
    );
}

/// `read_blob` hashes the file and must hand back that same handle seeked
/// to 0. A missed seek returns an empty stream.
#[tokio::test]
async fn read_blob_returns_the_stored_bytes_from_the_start() {
    let dir = fixture();
    let ledger = FsLiveLedger::open(dir.path()).expect("ledger");
    let session = session_a();
    ledger
        .create_session(manifest(session))
        .await
        .expect("session");
    let bytes = b"transfer-bytes-from-the-start".to_vec();
    let stored = ledger
        .store_blob(BlobSource::Bytes(SessionBlob {
            session_id: session,
            epoch: SessionEpoch::new(1),
            kind: BlobKind::Transfer,
            bytes: bytes.clone(),
        }))
        .await
        .expect("store");
    let mut stream = ledger.read_blob(&stored).await.expect("read");
    let mut got = Vec::new();
    std::io::Read::read_to_end(&mut stream, &mut got).expect("read bytes");
    assert_eq!(got, bytes);
    assert_eq!(stream.byte_len(), bytes.len() as u64);
}
