use std::collections::{BTreeMap, BTreeSet};
use std::num::NonZeroU16;
use std::sync::{Arc, RwLock};

use odin_domain::huginn::{
    Freshness, HuginnProtocolError, LiveSessionId, LiveSessionState, LiveSessionSummary,
    ObjectKind, ObjectRef, QueryScope, Revision, RevisionSource, RosterRevision, SeatRoster,
    SessionListCursor, SessionListPage, SessionListQuery,
};

use crate::read_model::{project_object, MaterializedReadModel, ProjectionMetadata};

#[derive(Clone)]
pub struct SessionProjectionStore {
    inner: Arc<RwLock<RosterState>>,
    max_sessions: usize,
    max_list_page: NonZeroU16,
}

/// A roster's sessions by id, each under its own seat and listed once.
fn session_index(
    roster: &SeatRoster,
) -> Result<BTreeMap<LiveSessionId, LiveSessionSummary>, HuginnProtocolError> {
    let mut sessions = BTreeMap::new();
    for seat in &roster.seats {
        for session in &seat.active_sessions {
            if session.seat_id != seat.seat_id {
                return Err(invalid_roster("session is attached to a different seat"));
            }
            if sessions
                .insert(session.session_id, session.clone())
                .is_some()
            {
                return Err(invalid_roster("session appears more than once"));
            }
        }
    }
    Ok(sessions)
}

struct RosterState {
    roster: SeatRoster,
    sessions: BTreeMap<odin_domain::huginn::LiveSessionId, LiveSessionSummary>,
}

impl SessionProjectionStore {
    pub fn new(
        initial: SeatRoster,
        max_sessions: usize,
        max_list_page: NonZeroU16,
    ) -> Result<Self, HuginnProtocolError> {
        let sessions = session_index(&initial)?;
        if held_slots(sessions.values()) > max_sessions.max(1) {
            return Err(HuginnProtocolError::ResourceLimit {
                limit: "sessions".to_owned(),
            });
        }
        let mut roster = initial;
        roster.canonicalize();
        Ok(Self {
            inner: Arc::new(RwLock::new(RosterState { roster, sessions })),
            max_sessions: max_sessions.max(1),
            max_list_page,
        })
    }

    pub fn roster(&self) -> Result<SeatRoster, HuginnProtocolError> {
        let state = self
            .inner
            .read()
            .map_err(|error| HuginnProtocolError::unavailable("session-roster-store", error))?;
        Ok(state.roster.clone())
    }

    pub fn session(
        &self,
        session_id: odin_domain::huginn::LiveSessionId,
    ) -> Result<Option<LiveSessionSummary>, HuginnProtocolError> {
        let state = self
            .inner
            .read()
            .map_err(|error| HuginnProtocolError::unavailable("session-roster-store", error))?;
        Ok(state.sessions.get(&session_id).cloned())
    }

    /// The held sessions a roster listing only `adopted` would drop.
    pub fn dropped_by(
        &self,
        adopted: &BTreeSet<LiveSessionId>,
    ) -> Result<Vec<LiveSessionId>, HuginnProtocolError> {
        let state = self
            .inner
            .read()
            .map_err(|error| HuginnProtocolError::unavailable("session-roster-store", error))?;
        Ok(state
            .sessions
            .values()
            .filter(|session| !adopted.contains(&session.session_id) && !stays_held(session))
            .map(|session| session.session_id)
            .collect())
    }

    pub fn replace_roster(&self, mut roster: SeatRoster) -> Result<bool, HuginnProtocolError> {
        roster.canonicalize();
        let mut replacement = session_index(&roster)?;
        let mut state = self
            .inner
            .write()
            .map_err(|error| HuginnProtocolError::unavailable("session-roster-store", error))?;
        if roster.revision < state.roster.revision {
            return Err(HuginnProtocolError::Conflict {
                code: "roster-revision".to_owned(),
                message: "roster revision moved backwards".to_owned(),
            });
        }
        if roster.revision == state.roster.revision {
            if roster == state.roster {
                return Ok(false);
            }
            return Err(HuginnProtocolError::Conflict {
                code: "roster-revision".to_owned(),
                message: "same roster revision has different content".to_owned(),
            });
        }
        for session in state
            .sessions
            .values()
            .filter(|session| stays_held(session))
        {
            replacement
                .entry(session.session_id)
                .or_insert_with(|| session.clone());
        }
        if held_slots(replacement.values()) > self.max_sessions {
            return Err(HuginnProtocolError::ResourceLimit {
                limit: "sessions".to_owned(),
            });
        }
        state.roster = roster;
        state.sessions = replacement;
        Ok(true)
    }

    pub fn list(&self, query: SessionListQuery) -> Result<SessionListPage, HuginnProtocolError> {
        if query.limit > self.max_list_page {
            return Err(HuginnProtocolError::ResourceLimit {
                limit: "session-list-page".to_owned(),
            });
        }
        let state = self
            .inner
            .read()
            .map_err(|error| HuginnProtocolError::unavailable("session-roster-store", error))?;
        let offset = decode_cursor(query.cursor.as_ref(), state.roster.revision)?;
        let matching: Vec<_> = state
            .sessions
            .values()
            .filter(|session| {
                query
                    .seat_id
                    .as_ref()
                    .is_none_or(|seat| &session.seat_id == seat)
            })
            .filter(|session| query.include_ended || session.state != LiveSessionState::Ended)
            .cloned()
            .collect();
        if offset > matching.len() {
            return Err(invalid_roster("session cursor lies beyond the result set"));
        }
        let limit = usize::from(query.limit.get());
        let next_offset = offset.saturating_add(limit);
        let next_cursor = if next_offset < matching.len() {
            Some(
                SessionListCursor::new(format!(
                    "session:{}:{next_offset}",
                    state.roster.revision.get()
                ))
                .map_err(|error| {
                    invalid_roster(format!("could not encode session cursor: {error}"))
                })?,
            )
        } else {
            None
        };
        Ok(SessionListPage::new(
            matching.into_iter().skip(offset).take(limit).collect(),
            next_cursor,
        ))
    }

    pub fn materialize_roster(
        &self,
        read_model: &MaterializedReadModel,
        freshness: Freshness,
    ) -> Result<(), HuginnProtocolError> {
        let roster = self.roster()?;
        if roster.revision.get() == 0 {
            return Err(invalid_roster(
                "materialized roster revision must start at one",
            ));
        }
        let revision = Revision::new(roster.revision.get());
        let seat_refs: Vec<_> = roster
            .seats
            .iter()
            .map(|seat| ObjectRef {
                kind: ObjectKind::Seat,
                id: seat.seat_id.to_string(),
            })
            .collect();
        let mut roster_metadata = ProjectionMetadata::new(
            "Live roster",
            format!("{} loaded seats", roster.seats.len()),
        );
        for seat_ref in &seat_refs {
            roster_metadata = roster_metadata.with_evidence(seat_ref.clone());
        }
        let roster_snapshot = project_object(
            ObjectRef {
                kind: ObjectKind::Status,
                id: "roster".to_owned(),
            },
            revision,
            RevisionSource::Omp,
            freshness.clone(),
            &roster,
            &roster_metadata,
        )
        .map_err(HuginnProtocolError::from)?;
        read_model
            .upsert_indexed(roster_snapshot, roster_metadata)
            .map_err(HuginnProtocolError::from)?;

        for seat in &roster.seats {
            let mut metadata =
                ProjectionMetadata::new(seat.display_name.clone(), format!("{:?}", seat.state))
                    .in_scope(QueryScope::Seat(seat.seat_id.clone()));
            for session in &seat.active_sessions {
                metadata = metadata.with_evidence(ObjectRef {
                    kind: ObjectKind::Session,
                    id: session.session_id.to_string(),
                });
            }
            let snapshot = project_object(
                ObjectRef {
                    kind: ObjectKind::Seat,
                    id: seat.seat_id.to_string(),
                },
                revision,
                RevisionSource::Omp,
                freshness.clone(),
                seat,
                &metadata,
            )
            .map_err(HuginnProtocolError::from)?;
            read_model
                .upsert_indexed(snapshot, metadata)
                .map_err(HuginnProtocolError::from)?;
        }
        for stale in read_model
            .objects_of_kind(ObjectKind::Seat)
            .map_err(HuginnProtocolError::from)?
            .into_iter()
            .filter(|object| !seat_refs.contains(object))
        {
            read_model
                .remove(stale, revision, RevisionSource::Omp, freshness.clone())
                .map_err(HuginnProtocolError::from)?;
        }

        let sessions: Vec<_> = self
            .inner
            .read()
            .map_err(|error| HuginnProtocolError::unavailable("session-roster-store", error))?
            .sessions
            .values()
            .map(|session| (session.session_id, session.seat_id.to_string()))
            .collect();
        for (session_id, seat_id) in sessions {
            self.materialize_session(
                read_model,
                session_id,
                revision,
                freshness.clone(),
                vec![ObjectRef {
                    kind: ObjectKind::Seat,
                    id: seat_id,
                }],
            )?;
        }
        Ok(())
    }

    pub fn materialize_session(
        &self,
        read_model: &MaterializedReadModel,
        session_id: odin_domain::huginn::LiveSessionId,
        revision: Revision,
        freshness: Freshness,
        mut evidence_links: Vec<ObjectRef>,
    ) -> Result<(), HuginnProtocolError> {
        let summary = self
            .session(session_id)?
            .ok_or_else(|| HuginnProtocolError::NotFound {
                object_kind: "session".to_owned(),
                object_id: session_id.to_string(),
            })?;
        evidence_links.sort();
        evidence_links.dedup();
        let mut metadata = ProjectionMetadata::new(
            summary
                .title
                .clone()
                .unwrap_or_else(|| summary.session_id.to_string()),
            format!("{} / {}", summary.provider, summary.model),
        )
        .in_scope(QueryScope::Seat(summary.seat_id.clone()))
        .in_scope(QueryScope::Session(summary.session_id));
        for evidence in evidence_links {
            metadata = metadata.with_evidence(evidence);
        }
        let snapshot = project_object(
            ObjectRef {
                kind: ObjectKind::Session,
                id: summary.session_id.to_string(),
            },
            revision,
            RevisionSource::Omp,
            freshness,
            &summary,
            &metadata,
        )
        .map_err(HuginnProtocolError::from)?;
        read_model
            .upsert_indexed(snapshot, metadata)
            .map(|_| ())
            .map_err(Into::into)
    }
}

fn decode_cursor(
    cursor: Option<&SessionListCursor>,
    revision: RosterRevision,
) -> Result<usize, HuginnProtocolError> {
    let Some(cursor) = cursor else {
        return Ok(0);
    };
    let mut parts = cursor.as_str().split(':');
    if parts.next() != Some("session") {
        return Err(invalid_roster("invalid session cursor prefix"));
    }
    let cursor_revision = parts
        .next()
        .and_then(|value| value.parse::<u64>().ok())
        .ok_or_else(|| invalid_roster("invalid session cursor revision"))?;
    let offset = parts
        .next()
        .and_then(|value| value.parse::<usize>().ok())
        .ok_or_else(|| invalid_roster("invalid session cursor offset"))?;
    if parts.next().is_some() {
        return Err(invalid_roster("invalid session cursor form"));
    }
    if cursor_revision != revision.get() {
        return Err(HuginnProtocolError::CursorExpired);
    }
    Ok(offset)
}

fn invalid_roster(message: impl Into<String>) -> HuginnProtocolError {
    HuginnProtocolError::InvalidRequest {
        code: "roster".to_owned(),
        message: message.into(),
    }
}

/// Terminal rows remain in history but no longer occupy capacity.
/// An Ended session stays held after the roster stops listing it.
fn stays_held(session: &LiveSessionSummary) -> bool {
    session.state == LiveSessionState::Ended
}

fn held_slots<'a>(sessions: impl Iterator<Item = &'a LiveSessionSummary>) -> usize {
    sessions
        .filter(|session| session.state.holds_capacity())
        .count()
}

#[cfg(test)]
mod tests {
    use std::num::NonZeroU16;

    use odin_domain::huginn::{HuginnProtocolError, RosterRevision, SeatRoster};
    use time::OffsetDateTime;

    use super::SessionProjectionStore;

    fn roster(revision: u64, generated_at: i64) -> SeatRoster {
        SeatRoster::new(
            RosterRevision::new(revision),
            OffsetDateTime::from_unix_timestamp(generated_at).unwrap(),
            Vec::new(),
        )
    }

    #[test]
    fn a_roster_that_goes_backwards_or_rewrites_its_revision_is_refused_and_the_held_one_stays() {
        let store =
            SessionProjectionStore::new(roster(2, 10), 8, NonZeroU16::new(10).unwrap()).unwrap();
        for refused in [roster(1, 10), roster(2, 99)] {
            let error = store.replace_roster(refused).unwrap_err();
            assert!(
                matches!(error, HuginnProtocolError::Conflict { ref code, .. } if code == "roster-revision"),
                "{error}"
            );
        }
        assert_eq!(store.roster().unwrap(), roster(2, 10));
        assert!(
            !store.replace_roster(roster(2, 10)).unwrap(),
            "the same roster is a no-op"
        );
        assert!(store.replace_roster(roster(3, 11)).unwrap());
        assert_eq!(store.roster().unwrap(), roster(3, 11));
    }
}
