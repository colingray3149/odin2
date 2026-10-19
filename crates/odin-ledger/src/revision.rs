use odin_domain::{LaneId, LaneStatus};
use rusqlite::{params, Connection, OptionalExtension};
use time::OffsetDateTime;

use crate::{encode_utc, LedgerError, LedgerResult};

pub fn guard_expected_revision(
    actor: impl Into<String>,
    expected_revision: i64,
    actual_revision: i64,
) -> LedgerResult<()> {
    if expected_revision == actual_revision {
        return Ok(());
    }

    Err(LedgerError::StaleActor {
        actor: actor.into(),
        expected_revision,
        actual_revision,
    })
}

pub fn transition_lane_at(
    connection: &Connection,
    lane_id: &LaneId,
    to: LaneStatus,
    expected_revision: i64,
    now: OffsetDateTime,
) -> LedgerResult<i64> {
    let actor = format!("lane:{lane_id}");
    let current = connection
        .query_row(
            "SELECT status, revision FROM lanes WHERE lane_id = ?1",
            [lane_id.to_string()],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?)),
        )
        .optional()?;
    let (current_status, actual_revision) = current.ok_or_else(|| LedgerError::NotFound {
        kind: "lane",
        id: lane_id.to_string(),
    })?;

    guard_expected_revision(&actor, expected_revision, actual_revision)?;
    let from = decode_lane_status(&current_status)?;
    if !from.can_transition_to(to) {
        return Err(LedgerError::invalid_data(format!(
            "illegal lane transition for {lane_id}: {} -> {}",
            encode_lane_status(from),
            encode_lane_status(to)
        )));
    }
    let next_revision = expected_revision
        .checked_add(1)
        .ok_or_else(|| LedgerError::invalid_data(format!("lane {lane_id} revision overflow")))?;

    let changed = connection.execute(
        "UPDATE lanes
         SET status = ?1, revision = ?2, updated_at = ?3
         WHERE lane_id = ?4 AND revision = ?5 AND status = ?6",
        params![
            encode_lane_status(to),
            next_revision,
            encode_utc(now)?,
            lane_id.to_string(),
            expected_revision,
            current_status,
        ],
    )?;
    if changed == 1 {
        return Ok(next_revision);
    }

    let actual_revision = connection
        .query_row(
            "SELECT revision FROM lanes WHERE lane_id = ?1",
            [lane_id.to_string()],
            |row| row.get(0),
        )
        .optional()?
        .ok_or_else(|| LedgerError::NotFound {
            kind: "lane",
            id: lane_id.to_string(),
        })?;
    guard_expected_revision(actor, expected_revision, actual_revision)?;
    Err(LedgerError::Conflict(format!(
        "lane {lane_id} changed during transition"
    )))
}

pub(crate) const fn encode_lane_status(status: LaneStatus) -> &'static str {
    match status {
        LaneStatus::Desired => "desired",
        LaneStatus::Provisioning => "provisioning",
        LaneStatus::Ready => "ready",
        LaneStatus::Running => "running",
        LaneStatus::WaitingApproval => "waitingApproval",
        LaneStatus::Paused => "paused",
        LaneStatus::Recovering => "recovering",
        LaneStatus::Succeeded => "succeeded",
        LaneStatus::Failed => "failed",
        LaneStatus::Blocked => "blocked",
        LaneStatus::Cancelled => "cancelled",
        LaneStatus::Retired => "retired",
    }
}

pub(crate) fn decode_lane_status(value: &str) -> LedgerResult<LaneStatus> {
    match value {
        "desired" => Ok(LaneStatus::Desired),
        "provisioning" => Ok(LaneStatus::Provisioning),
        "ready" => Ok(LaneStatus::Ready),
        "running" => Ok(LaneStatus::Running),
        "waitingApproval" => Ok(LaneStatus::WaitingApproval),
        "paused" => Ok(LaneStatus::Paused),
        "recovering" => Ok(LaneStatus::Recovering),
        "succeeded" => Ok(LaneStatus::Succeeded),
        "failed" => Ok(LaneStatus::Failed),
        "blocked" => Ok(LaneStatus::Blocked),
        "cancelled" => Ok(LaneStatus::Cancelled),
        "retired" => Ok(LaneStatus::Retired),
        other => Err(LedgerError::invalid_data(format!(
            "unknown lane status {other:?}"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use odin_domain::{LaneId, LaneStatus};
    use rusqlite::Connection;

    use super::{guard_expected_revision, transition_lane_at};
    use crate::LedgerError;
    fn now() -> time::OffsetDateTime {
        time::OffsetDateTime::from_unix_timestamp(1_767_312_000).expect("valid timestamp")
    }

    fn connection() -> Connection {
        let connection = Connection::open_in_memory().expect("open database");
        connection
            .execute_batch(
                "CREATE TABLE lanes (
                    lane_id TEXT PRIMARY KEY,
                    status TEXT NOT NULL,
                    revision INTEGER NOT NULL,
                    updated_at TEXT NOT NULL
                ) STRICT;
                INSERT INTO lanes VALUES ('lane:one', 'desired', 3, '2026-01-01T00:00:00Z');",
            )
            .expect("create lanes");
        connection
    }

    #[test]
    fn guard_reports_the_stale_actor() {
        let error = guard_expected_revision("run:one", 4, 5).expect_err("must be stale");
        assert!(matches!(
            error,
            LedgerError::StaleActor {
                actor,
                expected_revision: 4,
                actual_revision: 5,
            } if actor == "run:one"
        ));
    }

    #[test]
    fn transition_uses_the_domain_machine_and_increments_revision() {
        let connection = connection();
        let lane_id = LaneId::parse("lane:one").expect("lane id");
        let revision =
            transition_lane_at(&connection, &lane_id, LaneStatus::Provisioning, 3, now())
                .expect("transition");
        assert_eq!(revision, 4);
        let stored: (String, i64) = connection
            .query_row(
                "SELECT status, revision FROM lanes WHERE lane_id = ?1",
                [lane_id.to_string()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .expect("read lane");
        assert_eq!(stored, ("provisioning".to_owned(), 4));
    }

    #[test]
    fn stale_transition_cannot_overwrite() {
        let connection = connection();
        let lane_id = LaneId::parse("lane:one").expect("lane id");
        let error = transition_lane_at(&connection, &lane_id, LaneStatus::Provisioning, 2, now())
            .expect_err("must be stale");
        assert!(matches!(error, LedgerError::StaleActor { .. }));
        let stored: (String, i64) = connection
            .query_row(
                "SELECT status, revision FROM lanes WHERE lane_id = ?1",
                [lane_id.to_string()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .expect("read lane");
        assert_eq!(stored, ("desired".to_owned(), 3));
    }

    #[test]
    fn illegal_transition_does_not_mutate() {
        let connection = connection();
        let lane_id = LaneId::parse("lane:one").expect("lane id");
        let error = transition_lane_at(&connection, &lane_id, LaneStatus::Succeeded, 3, now())
            .expect_err("transition must be illegal");
        assert!(matches!(error, LedgerError::InvalidData { .. }));
        let revision: i64 = connection
            .query_row(
                "SELECT revision FROM lanes WHERE lane_id = ?1",
                [lane_id.to_string()],
                |row| row.get(0),
            )
            .expect("read lane");
        assert_eq!(revision, 3);
    }
}
