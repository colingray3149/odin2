//! Per-session leftover detection for SYS-12: a terminal capture entry is
//! leftover exactly when its session's live journal is terminal or absent;
//! entry names that are not canonical session ids are never session state.

use super::*;

pub(in crate::syscheck) fn terminal_capture_root(state_root: &Path) -> PathBuf {
    state_root.join("huginn").join("terminal").join("terminal")
}

/// The session-named entries under one capture root; `None` when the root
/// is absent. Classified by name alone, so nothing follows a link.
pub(in crate::syscheck) fn session_capture_entries(
    capture_root: &Path,
) -> Result<Option<Vec<String>>, CheckFailure> {
    let entries = match fs::read_dir(capture_root) {
        Ok(entries) => entries,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(CheckFailure::fail(
                "capture-inventory-failed",
                format!(
                    "the terminal capture root {} could not be read: {error}",
                    capture_root.display()
                ),
            ));
        }
    };
    let mut sessions = Vec::new();
    for (examined, entry) in entries.enumerate() {
        let entry = entry.map_err(|error| {
            CheckFailure::fail(
                "capture-inventory-failed",
                format!(
                    "the terminal capture root {} could not be walked: {error}",
                    capture_root.display()
                ),
            )
        })?;
        if examined >= WALK_ENTRY_CAP {
            return Err(CheckFailure::fail(
                "capture-inventory-unbounded",
                "the terminal capture root exceeded its entry cap",
            ));
        }
        let name = entry.file_name();
        let is_session = name
            .to_str()
            .and_then(|name| odin_domain::huginn::LiveSessionId::parse(name).ok())
            .is_some();
        if is_session {
            sessions.push(name.to_string_lossy().into_owned());
        }
    }
    sessions.sort();
    Ok(Some(sessions))
}

pub(in crate::syscheck) fn live_journal_root(state_root: &Path) -> PathBuf {
    state_root.join("huginn").join("live")
}

/// The captured sessions whose live journal is terminal or holds no such
/// session.
pub(in crate::syscheck) fn leftover_captures(
    journal_root: &Path,
    captures: &[String],
) -> Result<Vec<String>, CheckFailure> {
    let mut leftover = Vec::new();
    for capture in captures {
        let session = odin_domain::huginn::LiveSessionId::parse(capture).map_err(|error| {
            CheckFailure::fail(
                "capture-inventory-failed",
                format!("capture entry {capture} is not a session id: {error}"),
            )
        })?;
        let state = odin_omp::live::ledger::fs::journaled_state(journal_root, session).map_err(
            |error| {
                CheckFailure::fail(
                    "session-journal-unreadable",
                    format!(
                        "the live journal of captured session {capture} under {} could not be read: {error}",
                        journal_root.display()
                    ),
                )
            },
        )?;
        if !state.is_some_and(|state| state.holds_capacity()) {
            leftover.push(capture.clone());
        }
    }
    Ok(leftover)
}

#[cfg(test)]
mod tests {
    use super::*;

    use odin_domain::huginn::{
        LiveEventBody, LiveSessionId, LiveSessionState, ModelName, ProviderName, SessionEpoch,
        SessionManifest, SessionStateChanged,
    };
    use odin_domain::{EventId, NodeId, ProjectId, SeatId, SliceId};
    use odin_omp::live::ledger::fs::FsLiveLedger;
    use odin_omp::live::ledger::{LiveLedger, NewLiveEvent};

    const RUNNING: &str = "0f1e2d3c-4b5a-4c7d-8e9f-000000000001";
    const ENDED: &str = "0f1e2d3c-4b5a-4c7d-8e9f-000000000003";
    const FAILED: &str = "0f1e2d3c-4b5a-4c7d-8e9f-000000000004";
    const ABSENT: &str = "0f1e2d3c-4b5a-4c7d-8e9f-000000000005";

    /// Journals each session's state transitions through the real ledger.
    fn journal(root: &Path, sessions: &[(&str, &[LiveSessionState])]) {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("runtime builds");
        runtime.block_on(async {
            let ledger = FsLiveLedger::open(root).expect("journal opens");
            for (session, states) in sessions {
                let session_id = LiveSessionId::parse(session).expect("session id");
                ledger
                    .create_session(SessionManifest {
                        session_id,
                        seat_id: SeatId::new("seat:kubert").expect("seat id"),
                        slice_id: SliceId::new("slice:kubert").expect("slice id"),
                        project_id: ProjectId::new("project:odin").expect("project id"),
                        provider: ProviderName::new("fixture").expect("provider"),
                        model: ModelName::new("fixture-model").expect("model"),
                        title: None,
                        target_node: NodeId::new("node:mini").expect("node id"),
                        open_tab: true,
                        workload: None,
                        served_revision: None,
                        harness: None,
                    })
                    .await
                    .expect("session journals");
                let mut previous = LiveSessionState::Starting;
                for (index, current) in states.iter().enumerate() {
                    ledger
                        .append(
                            SessionEpoch::new(1),
                            NewLiveEvent {
                                session_id,
                                event_id: EventId::new(format!("state:{session}:{index}"))
                                    .expect("event id"),
                                occurred_at: time::OffsetDateTime::UNIX_EPOCH,
                                body: LiveEventBody::SessionStateChanged(SessionStateChanged {
                                    previous,
                                    current: *current,
                                    reason: None,
                                }),
                            },
                        )
                        .await
                        .expect("state journals");
                    previous = *current;
                }
            }
        });
    }

    #[test]
    #[cfg(unix)]
    fn captures_of_ended_or_unjournaled_sessions_fail_then_pass_after_removal() {
        let root = tempfile::tempdir().expect("capture fixture root is creatable");
        let journal_root = live_journal_root(root.path());
        journal(
            &journal_root,
            &[
                (
                    RUNNING,
                    &[LiveSessionState::Idle, LiveSessionState::Running],
                ),
                (ENDED, &[LiveSessionState::Running, LiveSessionState::Ended]),
                (FAILED, &[LiveSessionState::Failed]),
            ],
        );
        let capture_root = terminal_capture_root(root.path());
        let entry = |name: &str| capture_root.join(name);
        fs::create_dir_all(entry(RUNNING)).expect("the running capture dir is creatable");
        fs::create_dir_all(entry(ENDED)).expect("the ended capture dir is creatable");
        fs::create_dir_all(entry(ABSENT)).expect("the absent capture dir is creatable");
        std::os::unix::fs::symlink(entry(ENDED), entry(FAILED))
            .expect("the symlinked capture entry is creatable");
        fs::create_dir_all(entry("not-a-session-id")).expect("the foreign entry is creatable");
        fs::write(entry(".terminal-capture-crashed.txt"), "screen")
            .expect("the stale dump is writable");

        let captures = session_capture_entries(&capture_root)
            .expect("the capture root inventories")
            .expect("the capture root exists");
        assert_eq!(
            captures,
            [RUNNING, ENDED, FAILED, ABSENT].map(str::to_owned),
            "foreign entries are never session state; a symlink is its session's state"
        );
        let leftover = leftover_captures(&journal_root, &captures).expect("the journal reads");
        assert_eq!(
            leftover,
            [ENDED.to_owned(), FAILED.to_owned(), ABSENT.to_owned()],
            "a running session with no controller row (a harness session) keeps its capture"
        );

        for leftover in &leftover {
            let path = entry(leftover);
            if fs::symlink_metadata(&path)
                .expect("the leftover entry stats")
                .is_symlink()
            {
                fs::remove_file(&path).expect("the leftover symlink is removable");
            } else {
                fs::remove_dir_all(&path).expect("the leftover dir is removable");
            }
        }
        let captures = session_capture_entries(&capture_root)
            .expect("the capture root inventories")
            .expect("the capture root exists");
        assert!(
            leftover_captures(&journal_root, &captures)
                .expect("the journal reads")
                .is_empty(),
            "the check passes once the leftovers are removed"
        );
    }

    #[test]
    fn an_unreadable_journal_is_a_typed_failure() {
        let root = tempfile::tempdir().expect("fixture root is creatable");
        let journal_root = live_journal_root(root.path());
        journal(&journal_root, &[(RUNNING, &[LiveSessionState::Running])]);
        let events = journal_root.join("sessions").join(RUNNING).join("events");
        fs::remove_dir_all(&events).expect("events dir is removable");
        fs::write(&events, "not a directory").expect("obstacle is writable");
        let error = leftover_captures(&journal_root, &[RUNNING.to_owned()])
            .expect_err("an unreadable journal never reads as live or leftover");
        assert_eq!(error.reason, "session-journal-unreadable");
    }

    #[test]
    fn absent_and_empty_roots_hold_no_session_state() {
        let root = tempfile::tempdir().expect("fixture root is creatable");
        let capture_root = root.path().join("terminal");
        assert_eq!(
            session_capture_entries(&capture_root).expect("the absent root inventories"),
            None
        );
        fs::create_dir_all(&capture_root).expect("the empty capture root is creatable");
        assert_eq!(
            session_capture_entries(&capture_root).expect("the empty root inventories"),
            Some(Vec::new())
        );
    }

    #[test]
    fn the_capture_walk_stays_bounded() {
        let root = tempfile::tempdir().expect("fixture root is creatable");
        let capture_root = root.path().join("terminal");
        fs::create_dir_all(&capture_root).expect("capture root is creatable");
        for index in 0..(WALK_ENTRY_CAP + 1) {
            fs::write(capture_root.join(format!("f{index}")), "").expect("entry is writable");
        }
        let error = session_capture_entries(&capture_root)
            .expect_err("an over-cap root is a typed failure");
        assert_eq!(error.reason, "capture-inventory-unbounded");
    }
}
