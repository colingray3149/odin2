use odin_domain::LeaseId;
use rusqlite::{params, Connection, OptionalExtension, Transaction};
use serde_json::Value;
use time::OffsetDateTime;

use crate::revision::guard_expected_revision;
use crate::{decode_utc, encode_utc, LedgerError, LedgerResult};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NewLease {
    pub lease_id: LeaseId,
    pub object_kind: String,
    pub object_id: String,
    pub owner_id: String,
    pub acquired_at: OffsetDateTime,
    pub expires_at: OffsetDateTime,
    pub acquired_logical: u64,
    pub expires_logical: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LeaseRecord {
    pub lease_id: LeaseId,
    pub object_kind: String,
    pub object_id: String,
    pub owner_id: String,
    pub revision: i64,
    pub acquired_at: OffsetDateTime,
    pub expires_at: OffsetDateTime,
    pub last_heartbeat_at: OffsetDateTime,
    pub last_useful_progress_at: OffsetDateTime,
    pub released_at: Option<OffsetDateTime>,
    pub acquired_logical: u64,
    pub expires_logical: u64,
    pub last_heartbeat_logical: u64,
    pub last_useful_progress_logical: u64,
    pub released_logical: Option<u64>,
}

impl LeaseRecord {
    pub fn stale(&self, logical_now: u64) -> bool {
        self.released_logical.is_some() || logical_now >= self.expires_logical
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct NewHeartbeat {
    pub heartbeat_id: String,
    pub lease_id: LeaseId,
    pub owner_id: String,
    pub observed_at: OffsetDateTime,
    pub observed_logical: u64,
    pub health: Value,
    pub progress_marker: Option<String>,
}

pub fn acquire_lease(transaction: &Transaction<'_>, lease: &NewLease) -> LedgerResult<LeaseRecord> {
    if lease.object_kind.is_empty() || lease.object_id.is_empty() || lease.owner_id.is_empty() {
        return Err(LedgerError::invalid_data(
            "lease object kind, object id, and owner id must not be empty".to_owned(),
        ));
    }
    if lease.expires_at <= lease.acquired_at || lease.expires_logical <= lease.acquired_logical {
        return Err(LedgerError::invalid_data(
            "lease expiry must advance wall and logical acquisition time".to_owned(),
        ));
    }
    let inserted = transaction.execute(
        "INSERT INTO leases (lease_id,object_kind,object_id,owner_id,revision,acquired_at,expires_at,last_heartbeat_at,last_useful_progress_at,acquired_logical,expires_logical,last_heartbeat_logical,last_useful_progress_logical) SELECT ?1,?2,?3,?4,COALESCE((SELECT revision FROM leases WHERE object_kind=?2 AND object_id=?3 ORDER BY revision DESC LIMIT 1),0)+1,?5,?6,?5,?5,?7,?8,?7,?7 WHERE NOT EXISTS (SELECT 1 FROM leases WHERE object_kind=?2 AND object_id=?3 AND released_logical IS NULL AND expires_logical>?7)",
        params![lease.lease_id.to_string(),lease.object_kind,lease.object_id,lease.owner_id,encode_utc(lease.acquired_at)?,encode_utc(lease.expires_at)?,to_i64(lease.acquired_logical)?,to_i64(lease.expires_logical)?],
    )?;
    if inserted == 1 {
        return required_lease(transaction, &lease.lease_id);
    }
    let active = read_active_lease(
        transaction,
        &lease.object_kind,
        &lease.object_id,
        lease.acquired_logical,
    )?
    .ok_or_else(|| {
        LedgerError::Conflict(format!(
            "lease acquisition for {}/{} lost a concurrent race",
            lease.object_kind, lease.object_id
        ))
    })?;
    if active.owner_id == lease.owner_id {
        Ok(active)
    } else {
        Err(LedgerError::Conflict(format!(
            "active lease {} for {}/{} is owned by {} through logical time {}",
            active.lease_id,
            active.object_kind,
            active.object_id,
            active.owner_id,
            active.expires_logical
        )))
    }
}

pub fn read_lease(
    connection: &Connection,
    lease_id: &LeaseId,
) -> LedgerResult<Option<LeaseRecord>> {
    type Raw = (
        String,
        String,
        String,
        String,
        i64,
        String,
        String,
        String,
        String,
        Option<String>,
        i64,
        i64,
        i64,
        i64,
        Option<i64>,
    );
    let raw:Option<Raw>=connection.query_row("SELECT lease_id,object_kind,object_id,owner_id,revision,acquired_at,expires_at,last_heartbeat_at,last_useful_progress_at,released_at,acquired_logical,expires_logical,last_heartbeat_logical,last_useful_progress_logical,released_logical FROM leases WHERE lease_id=?1",[lease_id.to_string()],|row|Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?,row.get(4)?,row.get(5)?,row.get(6)?,row.get(7)?,row.get(8)?,row.get(9)?,row.get(10)?,row.get(11)?,row.get(12)?,row.get(13)?,row.get(14)?))).optional()?;
    raw.map(decode_lease).transpose()
}

pub struct LeaseExtension<'a> {
    pub connection: &'a Connection,
    pub lease_id: &'a LeaseId,
    pub owner_id: &'a str,
    pub expected_revision: i64,
}

pub fn extend_lease(
    ext: &LeaseExtension<'_>,
    now: OffsetDateTime,
    now_logical: u64,
    expires_at: OffsetDateTime,
    expires_logical: u64,
) -> LedgerResult<LeaseRecord> {
    let LeaseExtension {
        connection,
        lease_id,
        owner_id,
        expected_revision,
    } = *ext;
    if expires_at <= now || expires_logical <= now_logical {
        return Err(LedgerError::invalid_data(
            "extended lease expiry must advance wall and logical time".to_owned(),
        ));
    }
    let current = required_lease(connection, lease_id)?;
    guard_expected_revision(
        format!("lease:{lease_id}"),
        expected_revision,
        current.revision,
    )?;
    if current.owner_id != owner_id || current.stale(now_logical) {
        return Err(LedgerError::Conflict(format!(
            "lease {lease_id} is not live for owner {owner_id}"
        )));
    }
    if now_logical < current.last_heartbeat_logical || expires_logical <= current.expires_logical {
        return Err(LedgerError::Conflict(format!(
            "lease {lease_id} extension would regress logical time or shorten expiry"
        )));
    }
    let next = next_revision(lease_id, expected_revision)?;
    let changed=connection.execute("UPDATE leases SET expires_at=?1,expires_logical=?2,revision=?3 WHERE lease_id=?4 AND owner_id=?5 AND revision=?6 AND released_logical IS NULL AND expires_logical>?7 AND expires_logical<?2 AND last_heartbeat_logical<=?7",params![encode_utc(expires_at)?,to_i64(expires_logical)?,next,lease_id.to_string(),owner_id,expected_revision,to_i64(now_logical)?])?;
    finish_update(
        connection,
        lease_id,
        owner_id,
        expected_revision,
        next,
        changed,
        now_logical,
    )
}

pub fn release_lease(
    connection: &Connection,
    lease_id: &LeaseId,
    owner_id: &str,
    expected_revision: i64,
    now: OffsetDateTime,
    logical_at: u64,
) -> LedgerResult<LeaseRecord> {
    let current = required_lease(connection, lease_id)?;
    guard_expected_revision(
        format!("lease:{lease_id}"),
        expected_revision,
        current.revision,
    )?;
    if current.owner_id != owner_id || current.released_logical.is_some() {
        return Err(LedgerError::Conflict(format!(
            "lease {lease_id} is not held by {owner_id}"
        )));
    }
    if logical_at < current.last_heartbeat_logical
        || logical_at < current.last_useful_progress_logical
    {
        return Err(LedgerError::Conflict(format!(
            "lease {lease_id} release regresses logical time"
        )));
    }
    let next = next_revision(lease_id, expected_revision)?;
    let changed=connection.execute("UPDATE leases SET released_at=?1,released_logical=?2,revision=?3 WHERE lease_id=?4 AND owner_id=?5 AND revision=?6 AND released_logical IS NULL AND last_heartbeat_logical<=?2 AND last_useful_progress_logical<=?2",params![encode_utc(now)?,to_i64(logical_at)?,next,lease_id.to_string(),owner_id,expected_revision])?;
    finish_update(
        connection,
        lease_id,
        owner_id,
        expected_revision,
        next,
        changed,
        logical_at,
    )
}

pub fn record_heartbeat(
    transaction: &Transaction<'_>,
    heartbeat: &NewHeartbeat,
    expected_revision: i64,
) -> LedgerResult<LeaseRecord> {
    record_heartbeat_inner(transaction, heartbeat, expected_revision, false)
}

fn record_heartbeat_inner(
    transaction: &Transaction<'_>,
    heartbeat: &NewHeartbeat,
    expected_revision: i64,
    useful_progress: bool,
) -> LedgerResult<LeaseRecord> {
    if heartbeat.heartbeat_id.is_empty() {
        return Err(LedgerError::invalid_data(
            "heartbeat id must not be empty".to_owned(),
        ));
    }
    let current = required_lease(transaction, &heartbeat.lease_id)?;
    guard_expected_revision(
        format!("lease:{}", heartbeat.lease_id),
        expected_revision,
        current.revision,
    )?;
    if current.owner_id != heartbeat.owner_id || current.stale(heartbeat.observed_logical) {
        return Err(LedgerError::Conflict(format!(
            "lease {} is not live for owner {}",
            heartbeat.lease_id, heartbeat.owner_id
        )));
    }
    if heartbeat.observed_logical <= current.last_heartbeat_logical
        || (useful_progress && heartbeat.observed_logical <= current.last_useful_progress_logical)
    {
        return Err(LedgerError::Conflict(format!(
            "lease {} heartbeat/progress logical time did not advance",
            heartbeat.lease_id
        )));
    }
    let next = next_revision(&heartbeat.lease_id, expected_revision)?;
    let observed = encode_utc(heartbeat.observed_at)?;
    let changed = if useful_progress {
        transaction.execute("UPDATE leases SET last_heartbeat_at=?1,last_useful_progress_at=?1,last_heartbeat_logical=?2,last_useful_progress_logical=?2,revision=?3 WHERE lease_id=?4 AND owner_id=?5 AND revision=?6 AND released_logical IS NULL AND expires_logical>?2 AND last_heartbeat_logical<?2 AND last_useful_progress_logical<?2",params![observed,to_i64(heartbeat.observed_logical)?,next,heartbeat.lease_id.to_string(),heartbeat.owner_id,expected_revision])?
    } else {
        transaction.execute("UPDATE leases SET last_heartbeat_at=?1,last_heartbeat_logical=?2,revision=?3 WHERE lease_id=?4 AND owner_id=?5 AND revision=?6 AND released_logical IS NULL AND expires_logical>?2 AND last_heartbeat_logical<?2",params![observed,to_i64(heartbeat.observed_logical)?,next,heartbeat.lease_id.to_string(),heartbeat.owner_id,expected_revision])?
    };
    if changed != 1 {
        return finish_update(
            transaction,
            &heartbeat.lease_id,
            &heartbeat.owner_id,
            expected_revision,
            next,
            changed,
            heartbeat.observed_logical,
        );
    }
    transaction.execute("INSERT INTO heartbeats(heartbeat_id,lease_id,observed_at,health_json,useful_progress,progress_marker,observed_logical) VALUES(?1,?2,?3,?4,?5,?6,?7)",params![heartbeat.heartbeat_id,heartbeat.lease_id.to_string(),observed,serde_json::to_string(&heartbeat.health)?,i64::from(useful_progress),heartbeat.progress_marker,to_i64(heartbeat.observed_logical)?])?;
    required_lease(transaction, &heartbeat.lease_id)
}

fn read_active_lease(
    connection: &Connection,
    object_kind: &str,
    object_id: &str,
    logical_now: u64,
) -> LedgerResult<Option<LeaseRecord>> {
    let id:Option<String>=connection.query_row("SELECT lease_id FROM leases WHERE object_kind=?1 AND object_id=?2 AND released_logical IS NULL AND expires_logical>?3 ORDER BY revision DESC LIMIT 1",params![object_kind,object_id,to_i64(logical_now)?],|row|row.get(0)).optional()?;
    id.map(|id| {
        LeaseId::parse(&id)
            .map_err(|error| LedgerError::invalid_data_caused_by("invalid lease id", error))
            .and_then(|id| required_lease(connection, &id))
    })
    .transpose()
}
fn required_lease(connection: &Connection, lease_id: &LeaseId) -> LedgerResult<LeaseRecord> {
    read_lease(connection, lease_id)?.ok_or_else(|| LedgerError::NotFound {
        kind: "lease",
        id: lease_id.to_string(),
    })
}
type RawLeaseRow = (
    String,
    String,
    String,
    String,
    i64,
    String,
    String,
    String,
    String,
    Option<String>,
    i64,
    i64,
    i64,
    i64,
    Option<i64>,
);

fn decode_lease(raw: RawLeaseRow) -> LedgerResult<LeaseRecord> {
    Ok(LeaseRecord {
        lease_id: LeaseId::parse(&raw.0)
            .map_err(|error| LedgerError::invalid_data_caused_by("invalid lease id", error))?,
        object_kind: raw.1,
        object_id: raw.2,
        owner_id: raw.3,
        revision: raw.4,
        acquired_at: decode_utc(&raw.5)?,
        expires_at: decode_utc(&raw.6)?,
        last_heartbeat_at: decode_utc(&raw.7)?,
        last_useful_progress_at: decode_utc(&raw.8)?,
        released_at: raw.9.map(|v| decode_utc(&v)).transpose()?,
        acquired_logical: from_i64(raw.10)?,
        expires_logical: from_i64(raw.11)?,
        last_heartbeat_logical: from_i64(raw.12)?,
        last_useful_progress_logical: from_i64(raw.13)?,
        released_logical: raw.14.map(from_i64).transpose()?,
    })
}
fn next_revision(lease_id: &LeaseId, revision: i64) -> LedgerResult<i64> {
    revision
        .checked_add(1)
        .ok_or_else(|| LedgerError::invalid_data(format!("lease {lease_id} revision overflow")))
}
fn finish_update(
    connection: &Connection,
    lease_id: &LeaseId,
    owner_id: &str,
    expected_revision: i64,
    next_revision: i64,
    changed: usize,
    logical_now: u64,
) -> LedgerResult<LeaseRecord> {
    if changed == 1 {
        return required_lease(connection, lease_id);
    }
    let actual = required_lease(connection, lease_id)?;
    guard_expected_revision(
        format!("lease:{lease_id}"),
        expected_revision,
        actual.revision,
    )?;
    if actual.owner_id != owner_id || actual.stale(logical_now) {
        return Err(LedgerError::Conflict(format!(
            "lease {lease_id} is no longer held by {owner_id}"
        )));
    }
    Err(LedgerError::Conflict(format!(
        "lease {lease_id} failed to advance to revision {next_revision}"
    )))
}
fn to_i64(value: u64) -> LedgerResult<i64> {
    i64::try_from(value).map_err(|error| {
        LedgerError::invalid_data_caused_by("logical time exceeds SQLite INTEGER", error)
    })
}
fn from_i64(value: i64) -> LedgerResult<u64> {
    u64::try_from(value).map_err(|error| {
        LedgerError::invalid_data_caused_by("negative logical time in lease row", error)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    fn at(hour: i64) -> OffsetDateTime {
        OffsetDateTime::from_unix_timestamp(1_767_225_600 + hour * 3_600).unwrap()
    }
    const SCHEMA: &str = "CREATE TABLE leases(lease_id TEXT PRIMARY KEY,object_kind TEXT,object_id TEXT,owner_id TEXT,revision INTEGER,acquired_at TEXT,expires_at TEXT,last_heartbeat_at TEXT,last_useful_progress_at TEXT,released_at TEXT,acquired_logical INTEGER,expires_logical INTEGER,last_heartbeat_logical INTEGER,last_useful_progress_logical INTEGER,released_logical INTEGER,UNIQUE(object_kind,object_id,revision));CREATE TABLE heartbeats(heartbeat_id TEXT PRIMARY KEY,lease_id TEXT,observed_at TEXT,health_json TEXT,useful_progress INTEGER,progress_marker TEXT,observed_logical INTEGER);";

    fn db() -> Connection {
        let c = Connection::open_in_memory().unwrap();
        c.execute_batch(SCHEMA).unwrap();
        c
    }

    fn discard(path: &std::path::Path) {
        for suffix in ["", "-wal", "-shm"] {
            let mut candidate = path.as_os_str().to_owned();
            candidate.push(suffix);
            let _ = std::fs::remove_file(candidate);
        }
    }
    fn new(id: &str, owner: &str, expires: u64) -> NewLease {
        NewLease {
            lease_id: LeaseId::parse(id).unwrap(),
            object_kind: "lane".into(),
            object_id: "lane:one".into(),
            owner_id: owner.into(),
            acquired_at: at(0),
            expires_at: at(expires as i64),
            acquired_logical: 0,
            expires_logical: expires,
        }
    }
    #[test]
    fn active_owner_excludes_another() {
        let mut c = db();
        let tx = c.transaction().unwrap();
        acquire_lease(&tx, &new("lease:one", "owner:a", 1)).unwrap();
        tx.commit().unwrap();
        let tx = c.transaction().unwrap();
        assert!(matches!(
            acquire_lease(&tx, &new("lease:two", "owner:b", 2)),
            Err(LedgerError::Conflict(_))
        ));
    }
    #[test]
    fn expired_owner_cannot_extend() {
        let mut c = db();
        let tx = c.transaction().unwrap();
        let lease = acquire_lease(&tx, &new("lease:one", "owner:a", 1)).unwrap();
        tx.commit().unwrap();
        assert!(matches!(
            extend_lease(
                &LeaseExtension {
                    connection: &c,
                    lease_id: &lease.lease_id,
                    owner_id: "owner:a",
                    expected_revision: lease.revision,
                },
                at(1),
                1,
                at(2),
                2
            ),
            Err(LedgerError::Conflict(_))
        ));
    }
    #[test]
    fn heartbeat_does_not_move_useful_progress() {
        let mut c = db();
        let tx = c.transaction().unwrap();
        let lease = acquire_lease(&tx, &new("lease:one", "owner:a", 2)).unwrap();
        tx.commit().unwrap();
        let tx = c.transaction().unwrap();
        let got = record_heartbeat(
            &tx,
            &NewHeartbeat {
                heartbeat_id: "heartbeat:one".into(),
                lease_id: lease.lease_id,
                owner_id: "owner:a".into(),
                observed_at: at(1),
                observed_logical: 1,
                health: json!({"ok":true}),
                progress_marker: None,
            },
            lease.revision,
        )
        .unwrap();
        assert_eq!(got.last_useful_progress_logical, 0);
    }

    /// Released leases reject mutations even before expiry; successors use a new row.
    #[test]
    fn released_lease_is_terminal_across_reopen() {
        let path = std::env::temp_dir().join(format!(
            "odin-ledger-lease-terminal-{}.sqlite3",
            std::process::id()
        ));
        discard(&path);
        let mut c = Connection::open(&path).unwrap();
        c.execute_batch(SCHEMA).unwrap();
        let tx = c.transaction().unwrap();
        let lease = acquire_lease(&tx, &new("lease:one", "owner:a", 3)).unwrap();
        tx.commit().unwrap();
        let extended = extend_lease(
            &LeaseExtension {
                connection: &c,
                lease_id: &lease.lease_id,
                owner_id: "owner:a",
                expected_revision: lease.revision,
            },
            at(1),
            1,
            at(4),
            4,
        )
        .unwrap();
        let released =
            release_lease(&c, &lease.lease_id, "owner:a", extended.revision, at(2), 2).unwrap();
        let snapshot = read_lease(&c, &lease.lease_id).unwrap().unwrap();
        assert_eq!(released.revision, 3);
        assert_eq!(snapshot.released_logical, Some(2));
        assert_eq!(snapshot.expires_logical, 4);

        // The lease has not expired, so only the released-state guard can reject this extension.
        assert!(matches!(
            extend_lease(
                &LeaseExtension {
                    connection: &c,
                    lease_id: &lease.lease_id,
                    owner_id: "owner:a",
                    expected_revision: released.revision,
                },
                at(3),
                3,
                at(5),
                5
            ),
            Err(LedgerError::Conflict(_))
        ));
        let refused = c.transaction().unwrap();
        assert!(matches!(
            record_heartbeat(
                &refused,
                &NewHeartbeat {
                    heartbeat_id: "heartbeat:after-release".into(),
                    lease_id: lease.lease_id.clone(),
                    owner_id: "owner:a".into(),
                    observed_at: at(3),
                    observed_logical: 3,
                    health: json!({"ok": true}),
                    progress_marker: None,
                },
                released.revision,
            ),
            Err(LedgerError::Conflict(_))
        ));
        refused.commit().unwrap();
        assert!(matches!(
            release_lease(&c, &lease.lease_id, "owner:a", released.revision, at(3), 3),
            Err(LedgerError::Conflict(_))
        ));

        drop(c);
        let mut c = Connection::open(&path).unwrap();
        assert_eq!(read_lease(&c, &lease.lease_id).unwrap().unwrap(), snapshot);

        let tx = c.transaction().unwrap();
        let successor = acquire_lease(
            &tx,
            &NewLease {
                acquired_at: at(3),
                acquired_logical: 3,
                ..new("lease:two", "owner:b", 5)
            },
        )
        .unwrap();
        tx.commit().unwrap();
        assert_eq!(successor.revision, released.revision + 1);
        assert_eq!(read_lease(&c, &lease.lease_id).unwrap().unwrap(), snapshot);
        drop(c);
        discard(&path);
    }
}
