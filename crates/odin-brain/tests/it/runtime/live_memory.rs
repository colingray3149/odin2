//! What a session's live memory shows from the live read model and the ledger.

use super::*;
use odin_brain::source::state::live::LiveSource;
use odin_domain::huginn::{
    Freshness, FreshnessState, ObjectKind, ObjectRef, Revision, RevisionSource,
};
use odin_domain::ProjectId;
use odin_huginn::read_model::MaterializedReadModel;
use time::{Duration, OffsetDateTime};

const HOUR_MS: u64 = 3_600_000;

fn ms(at: OffsetDateTime) -> u64 {
    (at.unix_timestamp_nanos() / 1_000_000) as u64
}

fn session(id: &str, state: &str, updated: OffsetDateTime) -> odin_domain::huginn::ObjectSnapshot {
    let at = serde_json::to_value(updated).unwrap();
    let summary = serde_json::json!({
        "sessionId": "00000000-0000-4000-8000-000000000001", "epoch": 1,
        "seatId": "sinmara", "provider": "zai", "model": "glm-5", "title": null,
        "state": state, "startedAt": at, "updatedAt": at, "eventHead": 0,
        "terminalHead": 0, "pendingPermissionCount": 0,
    });
    odin_huginn::read_model::project_object(
        ObjectRef {
            kind: ObjectKind::Session,
            id: id.into(),
        },
        Revision::new(1),
        RevisionSource::Omp,
        Freshness {
            state: FreshnessState::Fresh,
            observed_at: updated,
            source_updated_at: Some(updated),
            stale_after_seconds: None,
        },
        &summary,
        &odin_huginn::read_model::ProjectionMetadata::new(id, "session"),
    )
    .unwrap()
}

#[test]
fn closed_work_leaves_a_day_after_it_closed_and_notes_pin_only_to_open_work() {
    let now = OffsetDateTime::UNIX_EPOCH + Duration::days(30);
    let read_model = MaterializedReadModel::new(16, now);
    for (id, state, updated) in [
        ("session-open", "running", now - Duration::minutes(5)),
        ("session-just-closed", "ended", now - Duration::hours(2)),
        ("session-long-closed", "ended", now - Duration::days(3)),
    ] {
        read_model.upsert(session(id, state, updated)).unwrap();
    }
    let id = AtlasId::new("state.live").unwrap();
    let mut declared_seat = seat(&["state.live"]);
    declared_seat.brain_scope = atlas_ids(&["state.live"]);
    let policy = EffectiveBrainPolicy::resolve(
        74,
        &slice(&["state.live"]),
        &declared_seat,
        &BTreeMap::new(),
        &BTreeMap::new(),
        &model(),
    )
    .unwrap();
    let (_cluster, configuration) = config(BTreeMap::from([(
        id.clone(),
        BrainSourceConfig::StateLive {
            source: LiveSource::new(id, read_model.clone()),
        },
    )]));
    let service = BrainService::open(configuration, policy, ledger()).unwrap();
    let project = ProjectId::new("garden").unwrap();
    let live = |at: OffsetDateTime| {
        service
            .live_memory(Some(&project), Vec::new(), ms(at), 4_000)
            .unwrap()
            .expect("live memory")
    };

    let text = live(now);
    assert!(text.contains("[session-open]"), "{text}");
    assert!(text.contains("[session-just-closed]"), "{text}");
    assert!(
        !text.contains("session-long-closed"),
        "work closed three days ago stays out: {text}"
    );
    assert!(text.find("## Open") < text.find("## Closed"), "{text}");

    service
        .pin_task_note(
            "sinmara",
            Some(&project),
            Vec::new(),
            "session-open",
            "ask the owner",
        )
        .unwrap();
    assert!(live(now).contains("note: ask the owner"));
    let refused = service
        .pin_task_note(
            "sinmara",
            Some(&project),
            Vec::new(),
            "session-just-closed",
            "late",
        )
        .unwrap_err();
    assert!(
        matches!(refused, BrainError::InvalidRequest(ref reason) if reason.contains("session-just-closed")),
        "{refused:?}"
    );

    // The producer prunes its recent view; the closed entry still shows for
    // the rest of its day, then goes.
    read_model
        .remove(
            ObjectRef {
                kind: ObjectKind::Session,
                id: "session-just-closed".into(),
            },
            Revision::new(2),
            RevisionSource::Omp,
            Freshness {
                state: FreshnessState::Fresh,
                observed_at: now,
                source_updated_at: Some(now),
                stale_after_seconds: None,
            },
        )
        .unwrap();
    assert!(live(now + Duration::hours(1)).contains("[session-just-closed]"));
    let later = live(now + Duration::milliseconds((26 * HOUR_MS) as i64));
    assert!(!later.contains("session-just-closed"), "{later}");
}

#[test]
fn a_fresh_session_gets_each_pinned_note_once_newest_last_and_only_its_projects() {
    let id = AtlasId::new("ops.history").unwrap();
    let ledger = ledger();
    let mut declared_seat = seat(&["ops.history"]);
    declared_seat.brain_scope = atlas_ids(&["ops.history"]);
    let policy = EffectiveBrainPolicy::resolve(
        74,
        &slice(&["ops.history"]),
        &declared_seat,
        &BTreeMap::new(),
        &BTreeMap::new(),
        &model(),
    )
    .unwrap();
    let (_cluster, configuration) = config(BTreeMap::from([(
        id.clone(),
        BrainSourceConfig::OpsHistory {
            source: odin_brain::source::ops::HistorySource::new(id, ledger.clone()),
        },
    )]));
    let service = BrainService::open(configuration, policy, ledger.clone()).unwrap();
    {
        let ledger = ledger.lock().unwrap();
        for (project, count) in [("garden", 20), ("odin", 2)] {
            for minute in 0..count {
                odin_ledger::task_note::add(
                    ledger.connection(),
                    &format!("task-{project}"),
                    "sinmara",
                    Some(project),
                    &format!("{project} note {minute}"),
                    OffsetDateTime::UNIX_EPOCH + Duration::minutes(minute),
                )
                .unwrap();
            }
        }
    }

    let garden = ProjectId::new("garden").unwrap();
    let gathered = service.fresh_knowledge(Some(&garden)).unwrap();
    assert!(
        gathered.unavailable.is_empty(),
        "{:?}",
        gathered.unavailable
    );
    let notes: Vec<&str> = gathered
        .notes
        .iter()
        .map(|note| note.note.as_str())
        .collect();
    assert_eq!(notes.len(), odin_brain::service::fresh_sources::NOTE_CAP);
    assert_eq!(notes.first(), Some(&"garden note 4"));
    assert_eq!(notes.last(), Some(&"garden note 19"));
}
