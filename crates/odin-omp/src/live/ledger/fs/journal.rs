use super::*;
use crate::live::ledger::{segment, state_after};

/// Read session state without repairs. Only an absent session directory is
/// absent evidence; malformed or incomplete session records fail closed.
pub fn journaled_state(
    root: &Path,
    session: LiveSessionId,
) -> Result<Option<LiveSessionState>, LedgerError> {
    read_journaled_state(root, session, None)
}

pub(super) fn read_journaled_state(
    root: &Path,
    session: LiveSessionId,
    expected_head: Option<u64>,
) -> Result<Option<LiveSessionState>, LedgerError> {
    let mut budget = JournalReadBudget::new();
    let session_dir = root.join("sessions").join(session.to_string());
    if !session_dir.try_exists()? {
        return Ok(None);
    }
    let mut manifest = None;
    strict_records(&session_dir.join(MANIFEST_FILE), &mut budget, |record| {
        if manifest.is_some() {
            return Err(LedgerError::JournalInvariant(
                "multiple session manifests".into(),
            ));
        }
        let decoded: SessionManifest = decode_cbor(record)?;
        if decoded.session_id != session {
            return Err(LedgerError::JournalInvariant(
                "session manifest identity mismatch".into(),
            ));
        }
        manifest = Some(decoded);
        Ok(())
    })?;
    let manifest =
        manifest.ok_or_else(|| LedgerError::JournalInvariant("missing session manifest".into()))?;
    let mut epoch = SessionEpoch::new(1);
    let mut saw_epoch = false;
    strict_records(&session_dir.join(STATE_FILE), &mut budget, |record| {
        let StateRecord::Epoch(next) = decode_cbor(record)?;
        if next < epoch {
            return Err(LedgerError::JournalInvariant(
                "session epoch regressed".into(),
            ));
        }
        epoch = next;
        saw_epoch = true;
        Ok(())
    })?;
    if !saw_epoch {
        return Err(LedgerError::JournalInvariant(
            "missing session epoch".into(),
        ));
    }
    let mut state = LiveSessionState::Starting;
    let mut expected = 1u64;
    let mut paths = Vec::new();
    let events_dir = session_dir.join("events");
    if events_dir.try_exists()? {
        for entry in fs::read_dir(&events_dir)? {
            budget.check()?;
            if paths.len() >= 1024 {
                return Err(journal_read_limit());
            }
            paths.push(entry?.path());
        }
    }
    let mut event_ids = HashSet::new();
    paths.sort();
    for (index, path) in paths.into_iter().enumerate() {
        budget.check()?;
        let expected_name = format!("{EVENTS_PREFIX}-{index:08}.seg");
        if !path
            .file_name()
            .is_some_and(|name| name == expected_name.as_str())
        {
            return Err(LedgerError::JournalInvariant(
                "session event segments are not contiguous".into(),
            ));
        }
        strict_records(&path, &mut budget, |record| {
            let event: LiveEvent = decode_cbor(record)?;
            if event.session_id != session
                || event.sequence.get() != expected
                || event.epoch > epoch
                || !event_ids.insert(event.event_id.clone())
            {
                return Err(LedgerError::JournalInvariant(
                    "session event binding is inconsistent".into(),
                ));
            }
            event.validate_binding(&manifest.session_id, &event.epoch)?;
            state = state_after(state, &event.body);
            expected = expected
                .checked_add(1)
                .ok_or(LedgerError::SequenceExhausted)?;
            Ok(())
        })?;
    }
    if expected_head.is_some_and(|head| head != expected - 1) {
        return Err(LedgerError::JournalInvariant(
            "session durable head changed".into(),
        ));
    }
    budget.check()?;
    Ok(Some(state))
}

fn strict_records(
    path: &Path,
    budget: &mut JournalReadBudget,
    mut visit: impl FnMut(&[u8]) -> Result<(), LedgerError>,
) -> Result<(), LedgerError> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_file() {
        return Err(LedgerError::JournalInvariant(
            "session journal is not a regular file".into(),
        ));
    }
    let length = metadata.len();
    budget.bytes = budget
        .bytes
        .checked_add(length)
        .ok_or_else(journal_read_limit)?;
    budget.check()?;
    let mut frames = SegmentReader::frames(path)?;
    while let Some(record) = frames.next_frame()? {
        budget.records += 1;
        budget.check()?;
        visit(record)?;
    }
    budget.check()?;
    if frames.valid_bytes() != length {
        return Err(LedgerError::JournalInvariant(format!(
            "incomplete journal frames in {}",
            path.display()
        )));
    }
    Ok(())
}

struct JournalReadBudget {
    started: std::time::Instant,
    bytes: u64,
    records: usize,
}

impl JournalReadBudget {
    fn new() -> Self {
        Self {
            started: std::time::Instant::now(),
            bytes: 0,
            records: 0,
        }
    }

    fn check(&self) -> Result<(), LedgerError> {
        if self.bytes > segment::MAX_SEGMENT_BYTES
            || self.records > MAX_JOURNAL_COMMANDS
            || self.started.elapsed() >= std::time::Duration::from_secs(2)
        {
            return Err(journal_read_limit());
        }
        Ok(())
    }
}

fn journal_read_limit() -> LedgerError {
    LedgerError::JournalInvariant("read-only session journal budget exceeded; keep capsule".into())
}
