use super::{
    decode_cbor, FsLiveLedger, LedgerError, LiveEvent, LiveSessionId, SegmentLayout, SegmentReader,
};
/// The next unread frame after a sequential page. Segments are append-only.
#[derive(Clone, Copy)]
pub(super) struct DiskCursor {
    pub(super) after: u64,
    segment: u64,
    offset: u64,
}

/// One bounded disk page and its next unread frame.
pub(super) struct DiskPage {
    pub(super) events: Vec<LiveEvent>,
    pub(super) resume: DiskCursor,
}

impl FsLiveLedger {
    /// Sequential pages seek to the preceding page's end. A different
    /// cursor scans from the start; no event bodies survive beyond a page.
    pub(super) fn page_events_on_disk(
        layout: &SegmentLayout,
        session: LiveSessionId,
        after: u64,
        limit: u16,
        head: u64,
        resume: Option<DiskCursor>,
    ) -> Result<DiskPage, LedgerError> {
        let mut cursor = resume
            .filter(|cursor| cursor.after == after)
            .unwrap_or(DiskCursor {
                after: 0,
                segment: 0,
                offset: 0,
            });
        let mut reader = SegmentReader::frames_at(&layout.nth_path(cursor.segment), cursor.offset)?;
        let mut events = Vec::new();
        while events.len() < usize::from(limit) && cursor.after < head {
            let event = match reader.next_frame()? {
                Some(record) => decode_cbor::<LiveEvent>(record)?,
                None => {
                    cursor.segment += 1;
                    reader = SegmentReader::frames_at(&layout.nth_path(cursor.segment), 0)?;
                    cursor.offset = 0;
                    continue;
                }
            };
            if event.session_id != session || event.sequence.get() != cursor.after + 1 {
                return Err(LedgerError::JournalInvariant(format!(
                    "session {session} expected event {} in segment {}, found session {} event {}",
                    cursor.after + 1,
                    cursor.segment,
                    event.session_id,
                    event.sequence.get()
                )));
            }
            cursor.after = event.sequence.get();
            cursor.offset = reader.offset();
            if cursor.after > after {
                events.push(event);
            }
        }
        Ok(DiskPage {
            events,
            resume: cursor,
        })
    }
}
