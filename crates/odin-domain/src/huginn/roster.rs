use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::{ContainerId, SeatId, SliceId};

use super::ids::{
    EventSeq, LiveSessionId, ModelName, ProviderName, RosterRevision, SessionEpoch,
    SessionListCursor, TerminalSeq,
};
use super::read_model::PublicDiagnostic;

/// Revisioned, fresh snapshot of all configured live seats.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SeatRoster {
    pub revision: RosterRevision,
    pub generated_at: OffsetDateTime,
    pub seats: Vec<SeatRosterEntry>,
}

impl SeatRoster {
    /// Builds a snapshot in canonical seat/session/launch-option order.
    pub fn new(
        revision: RosterRevision,
        generated_at: OffsetDateTime,
        mut seats: Vec<SeatRosterEntry>,
    ) -> Self {
        for seat in &mut seats {
            seat.canonicalize();
        }
        seats.sort_by(|left, right| left.seat_id.cmp(&right.seat_id));
        Self {
            revision,
            generated_at,
            seats,
        }
    }

    /// Restores deterministic ordering after callers update public wire fields.
    pub fn canonicalize(&mut self) {
        for seat in &mut self.seats {
            seat.canonicalize();
        }
        self.seats
            .sort_by(|left, right| left.seat_id.cmp(&right.seat_id));
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SeatRosterEntry {
    pub seat_id: SeatId,
    pub slice_id: SliceId,
    pub display_name: String,
    pub state: SeatLiveState,
    pub active_sessions: Vec<LiveSessionSummary>,
    pub launch_options: Vec<LiveLaunchOption>,
    pub diagnostic: Option<PublicDiagnostic>,
}

impl SeatRosterEntry {
    /// Orders nested collections by stable identifiers rather than observation order.
    pub fn canonicalize(&mut self) {
        self.active_sessions
            .sort_by_key(|session| session.session_id);
        self.launch_options.sort_by(|left, right| {
            (
                &left.provider,
                &left.model,
                &left.skeleton_ref,
                &left.container_id,
            )
                .cmp(&(
                    &right.provider,
                    &right.model,
                    &right.skeleton_ref,
                    &right.container_id,
                ))
        });
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum SeatLiveState {
    ConfigurationError,
    Offline,
    Idle,
    Running,
    RequiresAction,
    Degraded,
}

impl SeatLiveState {
    /// Priority specified by the live roster contract; larger values dominate.
    pub const fn priority(self) -> u8 {
        match self {
            Self::ConfigurationError => 5,
            Self::Degraded => 4,
            Self::RequiresAction => 3,
            Self::Running => 2,
            Self::Idle => 1,
            Self::Offline => 0,
        }
    }

    /// Returns the highest-priority candidate, or `Offline` when no state is present.
    pub fn highest_priority(states: impl IntoIterator<Item = Self>) -> Self {
        states
            .into_iter()
            .max_by_key(|state| state.priority())
            .unwrap_or(Self::Offline)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LiveSessionSummary {
    pub session_id: LiveSessionId,
    pub epoch: SessionEpoch,
    pub seat_id: SeatId,
    pub provider: ProviderName,
    pub model: ModelName,
    pub title: Option<String>,
    pub state: LiveSessionState,
    pub started_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
    /// The start of the session's current continuous `Failed` interval: the
    /// instant it entered `Failed`, held across later journaled events, and
    /// cleared when it leaves `Failed`. Absent: the session is not failed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failed_at: Option<OffsetDateTime>,
    pub event_head: EventSeq,
    pub terminal_head: TerminalSeq,
    pub pending_permission_count: u16,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum LiveSessionState {
    Starting,
    Idle,
    Running,
    RequiresAction,
    Aborting,
    Ended,
    Failed,
    Detached,
}

impl LiveSessionState {
    /// Ended and Failed sessions do not consume `max_sessions` capacity.
    pub const fn holds_capacity(self) -> bool {
        !matches!(self, Self::Ended | Self::Failed)
    }
}

/// A launch choice already admitted by seat, slice, provider, and container policy.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LiveLaunchOption {
    pub provider: ProviderName,
    pub model: ModelName,
    pub skeleton_ref: String,
    pub container_id: ContainerId,
    /// A non-OMP harness and the environment it runs in (registry ids);
    /// absent: the pinned OMP.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub harness: Option<super::HarnessBinding>,
}

/// One deterministically ordered page of session summaries.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionListPage {
    pub sessions: Vec<LiveSessionSummary>,
    pub next_cursor: Option<SessionListCursor>,
}

impl SessionListPage {
    pub fn new(
        mut sessions: Vec<LiveSessionSummary>,
        next_cursor: Option<SessionListCursor>,
    ) -> Self {
        sessions.sort_by_key(|session| session.session_id);
        Self {
            sessions,
            next_cursor,
        }
    }
}

/// Revision-to-revision roster changes, including removals.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RosterDelta {
    pub from_revision: RosterRevision,
    pub to_revision: RosterRevision,
    pub generated_at: OffsetDateTime,
    pub upserted_seats: Vec<SeatRosterEntry>,
    pub removed_seat_ids: Vec<SeatId>,
}

impl RosterDelta {
    pub fn new(
        from_revision: RosterRevision,
        to_revision: RosterRevision,
        generated_at: OffsetDateTime,
        mut upserted_seats: Vec<SeatRosterEntry>,
        mut removed_seat_ids: Vec<SeatId>,
    ) -> Self {
        for seat in &mut upserted_seats {
            seat.canonicalize();
        }
        upserted_seats.sort_by(|left, right| left.seat_id.cmp(&right.seat_id));
        removed_seat_ids.sort();
        removed_seat_ids.dedup();
        Self {
            from_revision,
            to_revision,
            generated_at,
            upserted_seats,
            removed_seat_ids,
        }
    }
}
