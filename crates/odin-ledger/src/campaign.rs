//! Durable owner-approved campaign bounds and per-operation reservations.
//!
//! Callers must derive reservations from the actual immutable workload and its
//! trusted resource profile, not from unverified descriptions of a workload.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{migration::Migration, LedgerError, LedgerResult};

const SCHEMA: &str = include_str!("../../../schemas/campaign/0001_campaign_store.sql");
const MIGRATIONS: [Migration<'static>; 1] = [Migration::register(
    1,
    "schemas/campaign/0001_campaign_store.sql",
    "caf991f135530ba977454d1e8b99fca1343da05f239c6214095a4e5e74a4dcc0",
    SCHEMA,
)];

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Approval {
    campaign: String,
    #[serde(rename = "box")]
    bounds: BTreeMap<String, [f64; 2]>,
    rung: String,
    cases: u64,
    core_hours: f64,
    nodes: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Reservation {
    pub operation_id: String,
    pub node: String,
    pub profile: String,
    pub rung: String,
    pub point: BTreeMap<String, f64>,
    pub core_hours: f64,
    pub stage_sha256: String,
}

fn invalid(message: &str) -> LedgerError {
    LedgerError::invalid_data(message.to_owned())
}

fn approval(args: &Value) -> LedgerResult<Approval> {
    let value: Approval = serde_json::from_value(args.clone())?;
    if value.campaign.trim().is_empty()
        || value.rung.trim().is_empty()
        || value.cases == 0
        || value.cases > i64::MAX as u64
        || !value.core_hours.is_finite()
        || value.core_hours <= 0.0
        || value.bounds.is_empty()
        || value.nodes.is_empty()
        || value.nodes.iter().any(|n| n.trim().is_empty())
        || value.bounds.iter().any(|(axis, b)| {
            axis.trim().is_empty() || !b[0].is_finite() || !b[1].is_finite() || b[0] > b[1]
        })
    {
        return Err(invalid("invalid approved campaign bounds"));
    }
    Ok(value)
}

/// Validate the exact campaign approval arguments before dispatch.
pub fn validate_approval(args: &Value) -> LedgerResult<()> {
    approval(args).map(|_| ())
}

fn open(state_dir: &Path) -> LedgerResult<Connection> {
    crate::open_database(state_dir.join("campaigns.sqlite"), &MIGRATIONS)
}

/// Capture the exact owner-approved input only after the adapter returns its campaign ID.
/// Repeating the same ID and input is safe; changing its authority is not.
pub fn record_approval(state_dir: &Path, campaign_id: &str, args: &Value) -> LedgerResult<()> {
    if campaign_id.trim().is_empty() {
        return Err(invalid("empty campaign ID"));
    }
    if approval(args)?.campaign != campaign_id {
        return Err(invalid("campaign ID does not match approved campaign"));
    }
    let encoded = serde_json::to_string(args)?;
    let mut db = open(state_dir)?;
    let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let existing: Option<String> = tx
        .query_row(
            "SELECT args FROM campaigns WHERE id=?1",
            [campaign_id],
            |r| r.get(0),
        )
        .optional()?;
    if let Some(existing) = existing {
        if serde_json::from_str::<Value>(&existing)? != *args {
            return Err(LedgerError::Conflict(format!(
                "campaign {campaign_id} already has different approved bounds"
            )));
        }
    } else {
        tx.execute(
            "INSERT INTO campaigns(id,args) VALUES (?1,?2)",
            params![campaign_id, encoded],
        )?;
    }
    tx.commit()?;
    Ok(())
}

/// Atomically reserve a complete batch. Each point contains the complete finite
/// parameter map; approved axes must be present and within their bounds.
/// Operation IDs are globally unique and replays must match their original
/// campaign and reservation exactly.
pub fn reserve(
    state_dir: &Path,
    campaign_id: &str,
    reservations: &[Reservation],
) -> LedgerResult<()> {
    if reservations.is_empty() {
        return Err(invalid("empty campaign reservation batch"));
    }
    let mut db = open(state_dir)?;
    let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let args: String = tx
        .query_row(
            "SELECT args FROM campaigns WHERE id=?1",
            [campaign_id],
            |r| r.get(0),
        )
        .optional()?
        .ok_or_else(|| LedgerError::NotFound {
            kind: "approved campaign",
            id: campaign_id.to_owned(),
        })?;
    let bounds = approval(&serde_json::from_str(&args)?)?;
    let (mut used_cases, mut used_hours): (i64, f64) = tx.query_row(
        "SELECT count(*), coalesce(sum(CASE WHEN state='settled' THEN actual_core_hours ELSE core_hours END),0.0) FROM campaign_reservations WHERE campaign_id=?1 AND state != 'refunded'",
        [campaign_id], |r| Ok((r.get(0)?, r.get(1)?)))?;
    let mut seen = BTreeSet::new();
    for request in reservations {
        if request.operation_id.trim().is_empty()
            || !seen.insert(&request.operation_id)
            || request.rung != bounds.rung
            || !bounds.nodes.contains(&request.node)
            || request.profile.trim().is_empty()
            || !request.core_hours.is_finite()
            || request.core_hours <= 0.0
            || request.stage_sha256.len() != 64
            || !request
                .stage_sha256
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            || request.point.values().any(|v| !v.is_finite())
            || bounds.bounds.iter().any(|(axis, b)| {
                request
                    .point
                    .get(axis)
                    .is_none_or(|v| *v < b[0] || *v > b[1])
            })
        {
            return Err(invalid("reservation outside approved campaign bounds"));
        }
        let encoded = serde_json::to_string(request)?;
        let existing: Option<(String, String, String)> = tx
            .query_row(
                "SELECT campaign_id,request,state FROM campaign_reservations WHERE operation_id=?1",
                [&request.operation_id],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()?;
        if let Some((id, old, state)) = existing {
            if id != campaign_id || old != encoded || state == "refunded" {
                return Err(LedgerError::Conflict(format!(
                    "campaign reservation {} conflicts with its original operation",
                    request.operation_id
                )));
            }
            continue;
        }
        used_cases += 1;
        used_hours += request.core_hours;
        if used_cases as u64 > bounds.cases
            || !used_hours.is_finite()
            || used_hours > bounds.core_hours
        {
            return Err(LedgerError::Conflict(format!(
                "campaign {campaign_id} reservation exceeds approved cases or core-hours"
            )));
        }
        tx.execute("INSERT INTO campaign_reservations(operation_id,campaign_id,request,core_hours,state) VALUES (?1,?2,?3,?4,'reserved')", params![request.operation_id, campaign_id, encoded, request.core_hours])?;
    }
    tx.commit()?;
    Ok(())
}

/// Reservations awaiting terminal evidence, keyed by the original create operation.
pub fn pending(state_dir: &Path) -> LedgerResult<Vec<String>> {
    let db = open(state_dir)?;
    let mut statement =
        db.prepare("SELECT operation_id FROM campaign_reservations WHERE state='reserved'")?;
    let rows = statement.query_map([], |row| row.get(0))?;
    Ok(rows.collect::<Result<Vec<_>, _>>()?)
}

/// Read the durable authority for an operation before dispatch.
pub fn lookup(state_dir: &Path, operation_id: &str) -> LedgerResult<(String, Reservation, String)> {
    let db = open(state_dir)?;
    let row: Option<(String, String, String)> = db
        .query_row(
            "SELECT campaign_id,request,state FROM campaign_reservations WHERE operation_id=?1",
            [operation_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()?;
    let (campaign, encoded, state) = row.ok_or_else(|| LedgerError::NotFound {
        kind: "campaign reservation",
        id: operation_id.to_owned(),
    })?;
    let request: Reservation = serde_json::from_str(&encoded)?;
    if request.operation_id != operation_id {
        return Err(invalid("campaign reservation operation mismatch"));
    }
    Ok((campaign, request, state))
}

/// Refund a reservation known never to have started. Never call for a running operation.
pub fn refund(state_dir: &Path, operation_id: &str) -> LedgerResult<()> {
    finish(state_dir, operation_id, None)
}

/// Settle a terminal operation to its measured core-hours; the case remains consumed.
/// An unavailable measurement must leave the original reservation intact.
pub fn settle(state_dir: &Path, operation_id: &str, actual_core_hours: f64) -> LedgerResult<()> {
    if !actual_core_hours.is_finite() || actual_core_hours < 0.0 {
        return Err(invalid("invalid measured core-hours"));
    }
    finish(state_dir, operation_id, Some(actual_core_hours))
}

fn finish(state_dir: &Path, operation_id: &str, actual: Option<f64>) -> LedgerResult<()> {
    let mut db = open(state_dir)?;
    let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let row: Option<(String, Option<f64>)> = tx
        .query_row(
            "SELECT state,actual_core_hours FROM campaign_reservations WHERE operation_id=?1",
            [operation_id],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;
    let (state, old_actual) = row.ok_or_else(|| LedgerError::NotFound {
        kind: "campaign reservation",
        id: operation_id.to_owned(),
    })?;
    let target = if actual.is_some() {
        "settled"
    } else {
        "refunded"
    };
    if state == "reserved" {
        tx.execute(
            "UPDATE campaign_reservations SET state=?1, actual_core_hours=?2 WHERE operation_id=?3",
            params![target, actual, operation_id],
        )?;
    } else if state != target || old_actual != actual {
        return Err(LedgerError::Conflict(format!(
            "campaign reservation {operation_id} already finished differently"
        )));
    }
    tx.commit()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn approved() -> Value {
        json!({"campaign":"id", "box":{"phi":[0.8,1.2]}, "rung":"coarse", "cases":2, "core_hours":10.0, "nodes":["mini"]})
    }

    fn request(id: &str, hours: f64) -> Reservation {
        Reservation {
            operation_id: id.to_owned(),
            node: "mini".to_owned(),
            profile: "cfd".to_owned(),
            rung: "coarse".to_owned(),
            point: BTreeMap::from([("phi".to_owned(), 1.0)]),
            core_hours: hours,
            stage_sha256: "a".repeat(64),
        }
    }

    #[test]
    fn schema_is_recorded_once_and_checksum_drift_fails_closed() {
        let dir = tempfile::tempdir().unwrap();
        record_approval(dir.path(), "id", &approved()).unwrap();
        let db = open(dir.path()).unwrap();
        let (name, checksum): (String, String) = db
            .query_row(
                "SELECT name, checksum FROM schema_migrations WHERE version = 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(name, MIGRATIONS[0].path);
        assert_eq!(name, "schemas/campaign/0001_campaign_store.sql");
        assert_eq!(
            blake3::hash(SCHEMA.as_bytes()).to_hex().as_str(),
            MIGRATIONS[0].checksum
        );
        assert_eq!(checksum, MIGRATIONS[0].checksum);
        db.execute(
            "UPDATE schema_migrations SET checksum = 'invalid' WHERE version = 1",
            [],
        )
        .unwrap();
        drop(db);
        assert!(matches!(
            open(dir.path()),
            Err(LedgerError::ChecksumDrift { version: 1, .. })
        ));
    }

    #[test]
    fn incomplete_untracked_schema_is_not_silently_accepted() {
        let dir = tempfile::tempdir().unwrap();
        let db = Connection::open(dir.path().join("campaigns.sqlite")).unwrap();
        db.execute_batch("CREATE TABLE campaigns (id TEXT PRIMARY KEY)")
            .unwrap();
        drop(db);
        assert!(matches!(open(dir.path()), Err(LedgerError::Sql(_))));
    }

    #[test]
    fn approval_is_durable_and_immutable() {
        let dir = tempfile::tempdir().unwrap();
        assert!(record_approval(dir.path(), "other", &approved()).is_err());
        record_approval(dir.path(), "id", &approved()).unwrap();
        record_approval(dir.path(), "id", &approved()).unwrap();
        let mut changed = approved();
        changed["cases"] = json!(3);
        assert!(record_approval(dir.path(), "id", &changed).is_err());
        reserve(dir.path(), "id", &[request("one", 2.0)]).unwrap();
        assert!(reserve(dir.path(), "missing", &[request("two", 1.0)]).is_err());
    }

    #[test]
    fn lookup_binds_stage_and_reports_reservation_state() {
        let dir = tempfile::tempdir().unwrap();
        record_approval(dir.path(), "id", &approved()).unwrap();
        let original = request("one", 2.0);
        reserve(dir.path(), "id", std::slice::from_ref(&original)).unwrap();
        assert_eq!(
            lookup(dir.path(), "one").unwrap(),
            ("id".to_owned(), original.clone(), "reserved".to_owned())
        );
        let mut changed = original;
        changed.stage_sha256 = "b".repeat(64);
        assert!(reserve(dir.path(), "id", &[changed]).is_err());
        refund(dir.path(), "one").unwrap();
        assert_eq!(lookup(dir.path(), "one").unwrap().2, "refunded");
        assert!(lookup(dir.path(), "missing").is_err());
    }

    #[test]
    fn batch_is_atomic_and_replays_are_idempotent() {
        let dir = tempfile::tempdir().unwrap();
        record_approval(dir.path(), "id", &approved()).unwrap();
        assert!(reserve(
            dir.path(),
            "id",
            &[request("one", 5.0), request("two", 6.0)]
        )
        .is_err());
        reserve(
            dir.path(),
            "id",
            &[request("one", 5.0), request("two", 5.0)],
        )
        .unwrap();
        reserve(
            dir.path(),
            "id",
            &[request("one", 5.0), request("two", 5.0)],
        )
        .unwrap();
        assert!(reserve(dir.path(), "id", &[request("one", 4.0)]).is_err());
        assert!(reserve(dir.path(), "id", &[request("three", 1.0)]).is_err());
        refund(dir.path(), "two").unwrap();
        refund(dir.path(), "two").unwrap();
        assert!(reserve(dir.path(), "id", &[request("two", 5.0)]).is_err());
        reserve(dir.path(), "id", &[request("three", 5.0)]).unwrap();
    }

    #[test]
    fn validates_bounds_and_settles_only_once() {
        let dir = tempfile::tempdir().unwrap();
        record_approval(dir.path(), "id", &approved()).unwrap();
        let mut bad = request("bad", 1.0);
        bad.point.insert("phi".to_owned(), 1.3);
        assert!(reserve(dir.path(), "id", &[bad]).is_err());
        let mut bad = request("bad", 1.0);
        bad.node = "pc".to_owned();
        assert!(reserve(dir.path(), "id", &[bad]).is_err());
        reserve(dir.path(), "id", &[request("one", 8.0)]).unwrap();
        assert_eq!(pending(dir.path()).unwrap(), vec!["one".to_owned()]);
        settle(dir.path(), "one", 2.0).unwrap();
        settle(dir.path(), "one", 2.0).unwrap();
        assert!(pending(dir.path()).unwrap().is_empty());
        assert!(settle(dir.path(), "one", 1.0).is_err());
        assert!(refund(dir.path(), "one").is_err());
        reserve(dir.path(), "id", &[request("two", 8.0)]).unwrap();
    }

    #[test]
    fn approved_axes_are_a_subset_of_finite_parameters() {
        let dir = tempfile::tempdir().unwrap();
        record_approval(dir.path(), "id", &approved()).unwrap();

        let mut missing = request("missing", 1.0);
        missing.point.remove("phi");
        missing.point.insert("temperature".to_owned(), 300.0);
        assert!(reserve(dir.path(), "id", &[missing]).is_err());

        for value in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY] {
            let mut bad_extra = request("bad-extra", 1.0);
            bad_extra.point.insert("temperature".to_owned(), value);
            assert!(reserve(dir.path(), "id", &[bad_extra]).is_err());
            let mut bad_axis = request("bad-axis", 1.0);
            bad_axis.point.insert("phi".to_owned(), value);
            assert!(reserve(dir.path(), "id", &[bad_axis]).is_err());
        }

        let mut lower = request("lower", 1.0);
        lower.point.insert("phi".to_owned(), 0.8);
        lower.point.insert("temperature".to_owned(), 300.0);
        reserve(dir.path(), "id", &[lower.clone()]).unwrap();
        reserve(dir.path(), "id", &[lower.clone()]).unwrap();
        lower.point.insert("temperature".to_owned(), 301.0);
        assert!(reserve(dir.path(), "id", &[lower]).is_err());

        let mut upper = request("upper", 1.0);
        upper.point.insert("phi".to_owned(), 1.2);
        upper.point.insert("temperature".to_owned(), 300.0);
        reserve(dir.path(), "id", &[upper]).unwrap();
    }

    #[test]
    fn competing_writers_cannot_overbook() {
        let dir = tempfile::tempdir().unwrap();
        record_approval(dir.path(), "id", &approved()).unwrap();
        let path = dir.path().to_owned();
        let other = path.clone();
        let thread = std::thread::spawn(move || reserve(&other, "id", &[request("other", 6.0)]));
        let first = reserve(&path, "id", &[request("first", 6.0)]);
        let second = thread.join().unwrap();
        assert!(matches!(
            (&first, &second),
            (Ok(()), Err(LedgerError::Conflict(_))) | (Err(LedgerError::Conflict(_)), Ok(()))
        ));
        assert_eq!(pending(dir.path()).unwrap().len(), 1);
    }
}
