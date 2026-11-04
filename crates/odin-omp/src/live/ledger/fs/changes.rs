use std::collections::BTreeMap;
use std::path::Path;

use super::super::segment::SegmentReader;
use super::super::LedgerError;
use super::{FsState, CHANGE_INDEX_SEGMENTS};

/// One change segment's frame-start offsets, valid only while the file
/// length still equals `len`.
#[derive(Default)]
pub(super) struct ChangeIndex {
    segments: BTreeMap<u64, (u64, Vec<u64>)>,
}

impl ChangeIndex {
    pub(super) fn get(&self, segment: u64) -> Option<&(u64, Vec<u64>)> {
        self.segments.get(&segment)
    }

    pub(super) fn insert(&mut self, segment: u64, len: u64, starts: Vec<u64>) {
        self.segments.insert(segment, (len, starts));
        self.evict(segment);
    }

    /// Records one frame written at `start` ending at `end`. A gap means
    /// the remembered tail does not meet this frame; that segment is
    /// forgotten and the next page read scans it.
    pub(super) fn note(&mut self, segment: u64, start: u64, end: u64) {
        let can_extend = match self.segments.get(&segment) {
            None => start == 0,
            Some((len, starts)) => (starts.is_empty() && start == 0) || *len == start,
        };
        if !can_extend {
            self.segments.remove(&segment);
            return;
        }
        let entry = self
            .segments
            .entry(segment)
            .or_insert_with(|| (0, Vec::new()));
        if entry.1.last().copied() != Some(start) {
            entry.1.push(start);
        }
        entry.0 = end;
        self.evict(segment);
    }

    pub(super) fn evict(&mut self, newest: u64) {
        let oldest = newest.saturating_sub((CHANGE_INDEX_SEGMENTS as u64) - 1);
        self.segments.retain(|index, _| *index >= oldest);
    }
}

/// Frames of one change segment starting at in-segment position `skip`,
/// at most `limit`. A matching index seeks; anything else scans, which is
/// the same read the page used before the index existed.
pub(super) fn change_frames(
    state: &FsState,
    path: &Path,
    segment: u64,
    skip: usize,
    limit: usize,
) -> Result<Vec<Vec<u8>>, LedgerError> {
    let file_len = std::fs::metadata(path)?.len();
    if let Some((len, starts)) = state.change_index.get(segment) {
        if *len == file_len && skip <= starts.len() {
            let end = (skip + limit).min(starts.len());
            if let Some(frames) = read_indexed_frames(path, &starts[skip..end]) {
                return Ok(frames);
            }
        }
    }
    let (records, _) = SegmentReader::scan_file(path)?;
    Ok(records.into_iter().skip(skip).take(limit).collect())
}

/// Seeks to each recorded frame start and verifies the frame. `None` when
/// the index and the bytes disagree; the caller scans instead.
pub(super) fn read_indexed_frames(path: &Path, starts: &[u64]) -> Option<Vec<Vec<u8>>> {
    if starts.is_empty() {
        return Some(Vec::new());
    }
    let mut frames = SegmentReader::frames_at(path, starts[0]).ok()?;
    let mut out = Vec::with_capacity(starts.len());
    for (index, start) in starts.iter().enumerate() {
        if frames.offset() != *start {
            return None;
        }
        let record = frames.next_frame().ok()??;
        out.push(record.to_vec());
        if index + 1 < starts.len() && frames.offset() != starts[index + 1] {
            return None;
        }
    }
    Some(out)
}
