//! Opening the journal: every session read back and validated, the expired ones deleted.

use super::*;

/// Loads every session, deleting the ones [`ENDED_SESSION_RETENTION`] has outlived as it goes.
pub(super) fn load_state(root: &Path, now: OffsetDateTime) -> Result<FsState, LedgerError> {
    let mut state = FsState {
        sessions: BTreeMap::new(),
        event_ids: HashSet::new(),
        commands: BTreeMap::new(),
        change_count: 0,
        change_segment_records: 0,
        writers: BTreeMap::new(),
        writer_uses: 0,
        degraded: false,
        change_index: ChangeIndex::default(),
        disk_cursors: HashMap::new(),
        resident_tails: VecDeque::new(),
        resident: ResidentLimits::LIVE,
    };
    let sessions_dir = root.join("sessions");
    // Blobs the deleted sessions held, and blobs the kept ones still do.
    let mut expired_blobs: HashSet<Digest> = HashSet::new();
    let mut kept_blobs: HashSet<Digest> = HashSet::new();
    for entry in fs::read_dir(&sessions_dir)? {
        let entry = entry?;
        if !entry.file_type()?.is_dir() {
            continue;
        }
        let session_dir = entry.path();
        let manifests = SegmentReader::scan(&SegmentLayout::Single {
            path: session_dir.join(MANIFEST_FILE),
        })?;
        if manifests.len() != 1 {
            return Err(LedgerError::Codec(format!(
                "session manifest {} has {} records",
                session_dir.display(),
                manifests.len()
            )));
        }
        let manifest: SessionManifest = decode_cbor(&manifests[0])?;
        if entry.file_name().to_string_lossy() != manifest.session_id.to_string() {
            return Err(LedgerError::Codec(format!(
                "session directory does not match manifest {}",
                manifest.session_id
            )));
        }
        let mut epoch = SessionEpoch::new(1);
        for record in SegmentReader::scan(&SegmentLayout::Single {
            path: session_dir.join(STATE_FILE),
        })? {
            let StateRecord::Epoch(next) = decode_cbor(&record)?;
            if next < epoch {
                return Err(LedgerError::Codec("session epoch regressed".to_owned()));
            }
            epoch = next;
        }
        // Validate every durable event (contiguity, binding, id uniqueness);
        // none stays resident: a session's tail refills as it appends.
        let mut head = EventSeq::new(0);
        let mut expected = 1u64;
        let mut folded = LiveSessionState::Starting;
        let mut last_event_at = None;
        let mut event_ids = Vec::new();
        let mut blobs = Vec::new();
        for_each_record(
            &SegmentLayout::Numbered {
                dir: session_dir.join("events"),
                prefix: EVENTS_PREFIX,
            },
            |record| {
                let event = decode_cbor::<LiveEvent>(record)?;
                if event.session_id != manifest.session_id || event.sequence.get() != expected {
                    return Err(LedgerError::Codec(format!(
                        "session {} event sequence is not contiguous",
                        manifest.session_id
                    )));
                }
                event.validate_binding(&manifest.session_id, &event.epoch)?;
                if event.epoch > epoch || !state.event_ids.insert(event.event_id.clone()) {
                    return Err(LedgerError::Codec(format!(
                        "session {} event binding is inconsistent",
                        manifest.session_id
                    )));
                }
                expected = expected
                    .checked_add(1)
                    .ok_or(LedgerError::SequenceExhausted)?;
                head = event.sequence;
                folded = state_after(folded, &event.body);
                last_event_at = Some(event.occurred_at);
                blobs.extend(event_blob_digest(&event.body));
                event_ids.push(event.event_id);
                Ok(())
            },
        )?;

        if !folded.holds_capacity()
            && last_event_at.is_some_and(|at| now - at > ENDED_SESSION_RETENTION)
        {
            for event_id in &event_ids {
                state.event_ids.remove(event_id);
            }
            expired_blobs.extend(blobs);
            fs::remove_dir_all(&session_dir)?;
            continue;
        }
        kept_blobs.extend(blobs);

        let mut command_count = 0usize;
        for_each_record(
            &SegmentLayout::Numbered {
                dir: session_dir.join("commands"),
                prefix: COMMANDS_PREFIX,
            },
            |record| {
                match decode_cbor::<CommandRecord>(record)? {
                    CommandRecord::Accepted {
                        command,
                        recorded_at,
                        dispatch_identity,
                        fresh_handoff,
                    } => {
                        if command.session_id != manifest.session_id
                            || state.commands.contains_key(&command.command_id)
                        {
                            return Err(LedgerError::Codec(
                                "duplicate or cross-session command journal row".to_owned(),
                            ));
                        }
                        command_count =
                            command_count
                                .checked_add(1)
                                .ok_or(LedgerError::JournalFull {
                                    limit: MAX_JOURNAL_COMMANDS,
                                })?;
                        state.commands.insert(
                            command.command_id.clone(),
                            PersistedCommand {
                                command,
                                recorded_at,
                                outcome: None,
                                dispatch_identity,
                                fresh_handoff,
                            },
                        );
                    }
                    CommandRecord::Completed {
                        command_id,
                        outcome,
                        recorded_at: _,
                    } => {
                        let command = state
                            .commands
                            .get_mut(&command_id)
                            .ok_or_else(|| LedgerError::CommandMissing(command_id.clone()))?;
                        if command.outcome.replace(outcome).is_some() {
                            return Err(LedgerError::OutcomeConflict(command_id));
                        }
                    }
                }
                Ok(())
            },
        )?;
        if command_count > MAX_JOURNAL_COMMANDS {
            return Err(LedgerError::JournalFull {
                limit: MAX_JOURNAL_COMMANDS,
            });
        }
        state.sessions.insert(
            manifest.session_id,
            SessionState {
                manifest,
                epoch,
                head,
                tail: VecDeque::new(),
                command_count,
            },
        );
    }
    for digest in expired_blobs.difference(&kept_blobs) {
        match fs::remove_file(blob_file(root, digest)) {
            Err(error) if error.kind() != std::io::ErrorKind::NotFound => return Err(error.into()),
            _ => {}
        }
    }
    Ok(state)
}
