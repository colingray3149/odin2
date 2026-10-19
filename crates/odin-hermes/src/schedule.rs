//! Deterministic reminders and seat wakes. The model states WHAT and the
//! anchor ("at 20:00", "30 minutes before my first class tomorrow"); code
//! resolves WHEN in the owner's current zone, stores the row durably, and the
//! reconcile loop fires it: a plain owner DM (`notify`) or an unprompted turn
//! of the seat's own conversation (`wake`). Models never decide when.

use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use jiff::civil::{Date, DateTime};
use jiff::tz::TimeZone;
use jiff::Timestamp;
use serde::{Deserialize, Serialize};

/// Fired and cancelled rows are kept this long for `list` and audit.
const RETAIN_DONE_MS: i64 = 30 * 24 * 3600 * 1000;
const MAX_AHEAD_MS: i64 = 400 * 24 * 3600 * 1000;
/// Failed deliveries after which a row settles `Failed` instead of retrying.
pub const MAX_DELIVERY_ATTEMPTS: u32 = 8;
/// First retry delay after a failed delivery; doubles per attempt.
const RETRY_BASE_MS: i64 = 10_000;
const RETRY_MAX_MS: i64 = 10 * 60 * 1000;
pub const MAX_TEXT_CHARS: usize = 500;

/// How a due row is delivered.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScheduleKind {
    /// A plain DM to the owner, worded by code.
    Notify,
    /// An unprompted turn of the seat's conversation: the seat acts on it.
    Wake,
}

/// Lifecycle of one row. `Firing` is written before delivery. After a crash,
/// the runtime resumes its durable occurrence checkpoint, not a fresh send.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScheduleStatus {
    Pending,
    Firing,
    Fired,
    Cancelled,
    /// Delivery failed [`MAX_DELIVERY_ATTEMPTS`] times; terminal.
    Failed,
    /// The delivery may have reached Colin and may not have. Terminal:
    /// told once, never held open, never sent again.
    Uncertain,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ScheduledItem {
    pub id: String,
    pub kind: ScheduleKind,
    pub text: String,
    pub fire_at_ms: i64,
    /// What the time was resolved from, e.g. the anchoring calendar event.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub anchor: Option<String>,
    pub created_at_ms: i64,
    pub status: ScheduleStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fired_at_ms: Option<i64>,
    /// A repeating row fires again this many minutes later…
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub every_minutes: Option<i64>,
    /// …this many more times.
    #[serde(default)]
    pub repeats_left: u32,
    /// Failed delivery attempts of the current firing.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub attempts: u32,
    /// The next retry after a failed delivery waits until this instant.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retry_at_ms: Option<i64>,
    /// An observed event (a delegated report, a workload finding) rather
    /// than a wake the seat set itself.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub event: bool,
    /// The digest of the complete routine declaration that queued this
    /// row: it dispatches only while that exact declaration is current.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub routine_digest: Option<String>,
    /// Delivery was handed to the notify sink or the conversation route at
    /// least once, so its effect may have happened.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub dispatch_started: bool,
}

fn is_zero(value: &u32) -> bool {
    *value == 0
}

const MIGRATIONS: &[odin_ledger::migration::Migration<'_>] = &[
    odin_ledger::migration::Migration::register(
        1,
        "schemas/hermes/0001_schedule.sql",
        "a896e7f301fb17d53467add5d3d2af80b0c3e741dc176824e13a6e44f53e5c71",
        include_str!("../../../schemas/hermes/0001_schedule.sql"),
    ),
    odin_ledger::migration::Migration::register(
        2,
        "schemas/hermes/0002_settled_deadline.sql",
        "bb70ebb884b867d23fc6aa2b1860fa080f4033a2a7a832b81e261557c75889c5",
        include_str!("../../../schemas/hermes/0002_settled_deadline.sql"),
    ),
    odin_ledger::migration::Migration::register(
        3,
        "schemas/hermes/0003_routine_dispatch.sql",
        "b0b7aef8149cc686f583a346c4a012eb35cbf46ab8626a84d6f56e72b61b164c",
        include_str!("../../../schemas/hermes/0003_routine_dispatch.sql"),
    ),
    odin_ledger::migration::Migration::register(
        4,
        "schemas/hermes/0004_uncertain_delivery.sql",
        "9f869b911677367d17a641ada217f3202d88ff656f8fb28ffefab2ce9129c148",
        include_str!("../../../schemas/hermes/0004_uncertain_delivery.sql"),
    ),
];

macro_rules! columns {
    () => {
        "id, kind, text, fire_at_ms, anchor, created_at_ms, status, fired_at_ms, \
         every_minutes, repeats_left, attempts, retry_at_ms, event, routine_digest, \
         dispatch_started"
    };
}
const COLUMNS: &str = columns!();

/// The reconcile pass's statements. Each reads through a partial index on
/// open or settled rows, so a pass costs what is due, not the history kept.
const LEASE_DUE: &str =
    "UPDATE schedule_items SET status = 'firing' WHERE status = 'pending' AND fire_at_ms <= ?1";
const PURGE_SETTLED: [&str; 2] = [
    "DELETE FROM schedule_items WHERE status IN ('fired', 'cancelled', 'failed', 'uncertain') \
     AND fired_at_ms < ?1",
    "DELETE FROM schedule_items INDEXED BY schedule_items_settled_deadline \
     WHERE status IN ('fired', 'cancelled', 'failed', 'uncertain') \
     AND fired_at_ms IS NULL AND fire_at_ms < ?1",
];
const SELECT_FIRING: &str = concat!(
    "SELECT ",
    columns!(),
    " FROM schedule_items WHERE status = 'firing' \
     AND (retry_at_ms IS NULL OR retry_at_ms <= ?1) ORDER BY fire_at_ms, id"
);
const SPEND_RETRIES: &str =
    "UPDATE schedule_items SET retry_at_ms = NULL WHERE status = 'firing' AND retry_at_ms <= ?1";
const ROUTINE_ACTIVITY: &str = "SELECT routine, max(first_seen_ms), max(recorded_ms), \
     max(delivered_ms) FROM (SELECT routine, first_seen_ms, \
     CASE WHEN fired_at_ms IS NOT NULL AND fired_occurrence IS NOT NULL \
     THEN fired_at_ms END AS recorded_ms, NULL AS delivered_ms FROM routine_state \
     UNION ALL SELECT substr(anchor, 9), NULL, NULL, fired_at_ms FROM schedule_items \
     WHERE status = 'fired' AND anchor >= 'routine:' AND anchor < 'routine;' \
     AND fired_at_ms IS NOT NULL) GROUP BY routine";
const NEXT_DUE: [&str; 2] = [
    "SELECT min(fire_at_ms) FROM schedule_items WHERE status = 'pending'",
    "SELECT min(retry_at_ms) FROM schedule_items WHERE status = 'firing'",
];

/// The durable schedule: one SQLite table under the Hermes state directory
/// (`schedule.sqlite3`), indexed on the open rows' fire time, so a pass
/// touches only what is due and the reconcile loop sleeps to the next one.
pub struct ScheduleStore {
    db: Mutex<rusqlite::Connection>,
}

/// When each routine was first seen, and its newest delivered occurrence.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct RoutineSeen {
    pub first_seen: std::collections::BTreeMap<String, i64>,
    pub fired: std::collections::BTreeMap<String, (i64, String)>,
}

/// One routine's first seen time and its newest recorded and delivered
/// firing.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RoutineActivity {
    pub first_seen: Option<i64>,
    pub recorded: Option<i64>,
    pub delivered: Option<i64>,
}

fn sql_error(error: impl std::fmt::Display) -> String {
    format!("schedule store failed: {error}")
}

fn kind_name(kind: ScheduleKind) -> &'static str {
    match kind {
        ScheduleKind::Notify => "notify",
        ScheduleKind::Wake => "wake",
    }
}

fn status_name(status: ScheduleStatus) -> &'static str {
    match status {
        ScheduleStatus::Pending => "pending",
        ScheduleStatus::Firing => "firing",
        ScheduleStatus::Fired => "fired",
        ScheduleStatus::Cancelled => "cancelled",
        ScheduleStatus::Failed => "failed",
        ScheduleStatus::Uncertain => "uncertain",
    }
}

fn item_of(row: &rusqlite::Row<'_>) -> rusqlite::Result<ScheduledItem> {
    let text_enum = |index: usize| -> rusqlite::Result<serde_json::Value> {
        Ok(serde_json::Value::String(row.get(index)?))
    };
    let invalid = |index: usize, error: serde_json::Error| {
        rusqlite::Error::FromSqlConversionFailure(
            index,
            rusqlite::types::Type::Text,
            Box::new(error),
        )
    };
    Ok(ScheduledItem {
        id: row.get(0)?,
        kind: serde_json::from_value(text_enum(1)?).map_err(|error| invalid(1, error))?,
        text: row.get(2)?,
        fire_at_ms: row.get(3)?,
        anchor: row.get(4)?,
        created_at_ms: row.get(5)?,
        status: serde_json::from_value(text_enum(6)?).map_err(|error| invalid(6, error))?,
        fired_at_ms: row.get(7)?,
        every_minutes: row.get(8)?,
        repeats_left: row.get(9)?,
        attempts: row.get(10)?,
        retry_at_ms: row.get(11)?,
        event: row.get(12)?,
        routine_digest: row.get(13)?,
        dispatch_started: row.get(14)?,
    })
}

/// Inserts a row unless its id is taken; returns the rows inserted (0 or 1).
fn insert(db: &rusqlite::Connection, item: &ScheduledItem) -> rusqlite::Result<usize> {
    db.execute(
        &format!("INSERT INTO schedule_items ({COLUMNS}) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15) \
                  ON CONFLICT (id) DO NOTHING"),
        rusqlite::params![
            item.id,
            kind_name(item.kind),
            item.text,
            item.fire_at_ms,
            item.anchor,
            item.created_at_ms,
            status_name(item.status),
            item.fired_at_ms,
            item.every_minutes,
            item.repeats_left,
            item.attempts,
            item.retry_at_ms,
            item.event,
            item.routine_digest,
            item.dispatch_started,
        ],
    )
}

fn update(db: &rusqlite::Connection, item: &ScheduledItem) -> rusqlite::Result<usize> {
    db.execute(
        "UPDATE schedule_items SET fire_at_ms = ?2, status = ?3, fired_at_ms = ?4, \
         every_minutes = ?5, repeats_left = ?6, attempts = ?7, retry_at_ms = ?8, \
         dispatch_started = ?9 WHERE id = ?1",
        rusqlite::params![
            item.id,
            item.fire_at_ms,
            status_name(item.status),
            item.fired_at_ms,
            item.every_minutes,
            item.repeats_left,
            item.attempts,
            item.retry_at_ms,
            item.dispatch_started,
        ],
    )
}

fn get(db: &rusqlite::Connection, id: &str) -> rusqlite::Result<Option<ScheduledItem>> {
    use rusqlite::OptionalExtension as _;
    db.query_row(
        &format!("SELECT {COLUMNS} FROM schedule_items WHERE id = ?1"),
        [id],
        item_of,
    )
    .optional()
}

impl ScheduleStore {
    /// Imports `schedule.json` and `routines.json`, verifying each row before renaming
    /// the source files to `<name>.json.imported` after the transaction commits.
    pub fn open(state_dir: &Path) -> Result<Self, String> {
        let db = odin_ledger::open_database(state_dir.join("schedule.sqlite3"), MIGRATIONS)
            .map_err(sql_error)?;
        // Acknowledged reminders and deliveries must survive power loss.
        db.pragma_update(None, "synchronous", "FULL")
            .map_err(sql_error)?;
        let store = Self { db: Mutex::new(db) };
        store.import_files(state_dir)?;
        Ok(store)
    }

    fn import_files(&self, state_dir: &Path) -> Result<(), String> {
        let rows_file = state_dir.join("schedule.json");
        let routines_file = state_dir.join("routines.json");
        let read = |path: &Path| match std::fs::read(path) {
            Ok(bytes) => Ok(Some(bytes)),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(format!("{} is unreadable: {error}", path.display())),
        };
        let rows_bytes = read(&rows_file)?;
        let routines_bytes = read(&routines_file)?;
        if rows_bytes.is_none() && routines_bytes.is_none() {
            return Ok(());
        }
        let source: Vec<ScheduledItem> = match &rows_bytes {
            Some(bytes) => serde_json::from_slice(bytes)
                .map_err(|error| format!("{} is unreadable: {error}", rows_file.display()))?,
            None => Vec::new(),
        };
        #[derive(Deserialize)]
        struct RoutinesFile {
            routines: std::collections::BTreeMap<String, i64>,
            #[serde(default)]
            fired: std::collections::BTreeMap<String, FiredFile>,
        }
        #[derive(Deserialize)]
        struct FiredFile {
            at_ms: i64,
            occurrence: String,
        }
        let routines: Option<RoutinesFile> =
            match &routines_bytes {
                Some(bytes) => Some(serde_json::from_slice(bytes).map_err(|error| {
                    format!("{} is unreadable: {error}", routines_file.display())
                })?),
                None => None,
            };
        let refused = |what: String| {
            format!(
                "schedule import refused, legacy files kept in {}: {what}",
                state_dir.display()
            )
        };
        let source_rows = source.len();
        let (mut rows, reassigned) = distinct_ids(source);
        // Imported firing rows may have reached the recipient without a handoff record.
        for item in &mut rows {
            if item.status == ScheduleStatus::Firing {
                item.dispatch_started = true;
            }
        }
        let mut db = self.lock()?;
        let transaction = db.transaction().map_err(sql_error)?;
        for item in &rows {
            insert(&transaction, item).map_err(sql_error)?;
            if get(&transaction, &item.id).map_err(sql_error)?.as_ref() != Some(item) {
                return Err(refused(format!(
                    "row {} differs from the stored row of that id",
                    item.id
                )));
            }
        }
        let mut imported_routines = 0;
        if let Some(routines) = &routines {
            if let Some(orphan) = routines
                .fired
                .keys()
                .find(|routine| !routines.routines.contains_key(*routine))
            {
                return Err(refused(format!(
                    "routine {orphan} has a firing but no first-seen time"
                )));
            }
            for (routine, first_seen) in &routines.routines {
                let fired = routines.fired.get(routine);
                transaction
                    .execute(
                        "INSERT INTO routine_state \
                         (routine, first_seen_ms, fired_at_ms, fired_occurrence) VALUES (?1, ?2, ?3, ?4) \
                         ON CONFLICT (routine) DO NOTHING",
                        rusqlite::params![
                            routine,
                            first_seen,
                            fired.map(|fired| fired.at_ms),
                            fired.map(|fired| fired.occurrence.as_str()),
                        ],
                    )
                    .map_err(sql_error)?;
            }
            let stored = read_routines(&transaction)?;
            for (routine, first_seen) in &routines.routines {
                let fired = routines.fired.get(routine);
                if stored.first_seen.get(routine) != Some(first_seen)
                    || stored
                        .fired
                        .get(routine)
                        .map(|(at, occurrence)| (*at, occurrence.as_str()))
                        != fired.map(|fired| (fired.at_ms, fired.occurrence.as_str()))
                {
                    return Err(refused(format!(
                        "routine {routine} differs from its stored state"
                    )));
                }
                imported_routines += 1;
            }
        }
        if rows.len() != source_rows {
            return Err(refused(format!(
                "{} of {source_rows} rows would be imported",
                rows.len()
            )));
        }
        transaction.commit().map_err(sql_error)?;
        drop(db);
        let mut renamed = Vec::new();
        for path in [&rows_file, &routines_file] {
            let kept = path.with_extension("json.imported");
            match std::fs::rename(path, &kept) {
                Ok(()) => renamed.push(kept.display().to_string()),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(format!("{} not renamed: {error}", path.display())),
            }
        }
        tracing::info!(
            "odind: schedule imported rows={} source_rows={source_rows} reassigned={reassigned} \
             routines={imported_routines} renamed={}",
            rows.len(),
            renamed.join(",")
        );
        Ok(())
    }

    fn lock(&self) -> Result<std::sync::MutexGuard<'_, rusqlite::Connection>, String> {
        self.db
            .lock()
            .map_err(|_| "schedule store lock poisoned".to_owned())
    }

    /// Adds one pending row. The fire time must lie in the future and within
    /// `MAX_AHEAD_MS`.
    pub fn add(
        &self,
        kind: ScheduleKind,
        text: &str,
        fire_at: Timestamp,
        anchor: Option<String>,
        now: Timestamp,
    ) -> Result<ScheduledItem, String> {
        let text = text.trim();
        if text.is_empty() || text.chars().count() > MAX_TEXT_CHARS {
            return Err(format!(
                "reminder text must be 1..={MAX_TEXT_CHARS} characters"
            ));
        }
        let (fire_at_ms, now_ms) = (fire_at.as_millisecond(), now.as_millisecond());
        if fire_at_ms <= now_ms {
            return Err("that time has already passed".to_owned());
        }
        if fire_at_ms - now_ms > MAX_AHEAD_MS {
            return Err("reminders can be set at most 400 days ahead".to_owned());
        }
        let mut item = ScheduledItem {
            id: String::new(),
            kind,
            text: text.to_owned(),
            fire_at_ms,
            anchor,
            created_at_ms: now_ms,
            status: ScheduleStatus::Pending,
            fired_at_ms: None,
            every_minutes: None,
            repeats_left: 0,
            attempts: 0,
            retry_at_ms: None,
            event: false,
            routine_digest: None,
            dispatch_started: false,
        };
        let db = self.lock()?;
        // Random, not content-derived: the same reminder set twice at the
        // same instant is two rows. A drawn id already taken is redrawn.
        for _ in 0..8 {
            item.id = format!("r{}", &uuid::Uuid::new_v4().simple().to_string()[..10]);
            if insert(&db, &item).map_err(sql_error)? == 1 {
                return Ok(item);
            }
        }
        Err("no free reminder id after 8 draws".to_owned())
    }

    /// Adds a wake due now under a caller-chosen id, once: an id already
    /// present (pending, fired, or cancelled) adds nothing. Returns whether
    /// a row was added.
    pub fn wake_once(&self, id: &str, text: &str, now: Timestamp) -> Result<bool, String> {
        self.enqueue_once(id, ScheduleKind::Wake, text, None, true, now)
    }

    /// Queues one row due now; returns false if its id already exists.
    /// Optional routine metadata identifies the declaration that queued it.
    pub fn enqueue_once(
        &self,
        id: &str,
        kind: ScheduleKind,
        text: &str,
        routine: Option<(&str, String)>,
        event: bool,
        now: Timestamp,
    ) -> Result<bool, String> {
        let now_ms = now.as_millisecond();
        let (anchor, routine_digest) = match routine {
            Some((routine, digest)) => (Some(format!("routine:{routine}")), Some(digest)),
            None => (None, None),
        };
        let item = ScheduledItem {
            id: id.to_owned(),
            kind,
            text: text.to_owned(),
            fire_at_ms: now_ms,
            anchor,
            created_at_ms: now_ms,
            status: ScheduleStatus::Pending,
            fired_at_ms: None,
            every_minutes: None,
            repeats_left: 0,
            attempts: 0,
            retry_at_ms: None,
            event,
            routine_digest,
            dispatch_started: false,
        };
        Ok(insert(&*self.lock()?, &item).map_err(sql_error)? == 1)
    }

    /// Makes a pending row repeat every `every_minutes`, `times` more times.
    pub fn set_repeat(
        &self,
        id: &str,
        every_minutes: i64,
        times: u32,
        now: Timestamp,
    ) -> Result<(), String> {
        let _ = now;
        if !(1..=1_440).contains(&every_minutes) || !(1..=500).contains(&times) {
            return Err("repeat every 1..=1440 minutes, 1..=500 more times".to_owned());
        }
        let changed = self
            .lock()?
            .execute(
                "UPDATE schedule_items SET every_minutes = ?2, repeats_left = ?3 \
                 WHERE id = ?1 AND status = 'pending'",
                rusqlite::params![id, every_minutes, times],
            )
            .map_err(sql_error)?;
        if changed == 0 {
            return Err(format!("no pending reminder {id}"));
        }
        Ok(())
    }

    /// Every open row plus the settled ones of the last 30 days, by time.
    pub fn list(&self) -> Result<Vec<ScheduledItem>, String> {
        let db = self.lock()?;
        let mut statement = db
            .prepare_cached(&format!(
                "SELECT {COLUMNS} FROM schedule_items ORDER BY fire_at_ms, id"
            ))
            .map_err(sql_error)?;
        let rows = statement
            .query_map([], item_of)
            .map_err(sql_error)?
            .collect::<rusqlite::Result<Vec<_>>>()
            .map_err(sql_error);
        rows
    }

    /// Cancels one pending row.
    pub fn cancel(&self, id: &str, now: Timestamp) -> Result<ScheduledItem, String> {
        let db = self.lock()?;
        let mut item = get(&db, id)
            .map_err(sql_error)?
            .ok_or_else(|| format!("no reminder {id}"))?;
        if item.status != ScheduleStatus::Pending {
            return Err(format!("reminder {id} is no longer pending"));
        }
        item.status = ScheduleStatus::Cancelled;
        item.fired_at_ms = Some(now.as_millisecond());
        update(&db, &item).map_err(sql_error)?;
        Ok(item)
    }

    /// Leases every due pending row (`Firing`, written before delivery) and
    /// returns `Firing` rows whose retry delay has passed, including interrupted
    /// deliveries. Their durable occurrence checkpoints govern resumption.
    /// A returned row's elapsed retry delay is spent: a row the caller then
    /// defers (busy conversation, no route yet) waits for the loop's tick or
    /// wake, never a deadline already behind it. Settled rows older than 30
    /// days go in the same pass.
    pub fn take_due(&self, now: Timestamp) -> Result<Vec<ScheduledItem>, String> {
        let now_ms = now.as_millisecond();
        let mut db = self.lock()?;
        let transaction = db.transaction().map_err(sql_error)?;
        transaction
            .execute(LEASE_DUE, [now_ms])
            .map_err(sql_error)?;
        for purge in PURGE_SETTLED {
            transaction
                .execute(purge, [now_ms - RETAIN_DONE_MS])
                .map_err(sql_error)?;
        }
        let due = {
            let mut statement = transaction
                .prepare_cached(SELECT_FIRING)
                .map_err(sql_error)?;
            let rows = statement
                .query_map([now_ms], item_of)
                .map_err(sql_error)?
                .collect::<rusqlite::Result<Vec<_>>>()
                .map_err(sql_error)?;
            rows
        };
        transaction
            .execute(SPEND_RETRIES, [now_ms])
            .map_err(sql_error)?;
        transaction.commit().map_err(sql_error)?;
        Ok(due)
    }

    /// When the next row comes due: a pending fire time or a failed
    /// delivery's retry. A leased row waiting on a busy conversation is
    /// retried by the loop's tick, never spun on.
    pub fn next_due_ms(&self) -> Result<Option<i64>, String> {
        let db = self.lock()?;
        let mut next: Option<i64> = None;
        for query in NEXT_DUE {
            let due: Option<i64> = db
                .prepare_cached(query)
                .and_then(|mut statement| statement.query_row([], |row| row.get(0)))
                .map_err(sql_error)?;
            next = next.into_iter().chain(due).min();
        }
        Ok(next)
    }

    pub fn mark_fired(&self, id: &str, now: Timestamp) -> Result<(), String> {
        let now_ms = now.as_millisecond();
        let db = self.lock()?;
        let Some(mut item) = get(&db, id).map_err(sql_error)? else {
            return Ok(());
        };
        item.fired_at_ms = Some(now_ms);
        item.attempts = 0;
        item.retry_at_ms = None;
        match item.every_minutes {
            Some(every) if item.repeats_left > 0 => {
                // The next occurrence keeps the cadence; one missed while
                // down is skipped, never fired in a burst.
                let step = every * 60_000;
                while item.fire_at_ms <= now_ms {
                    item.fire_at_ms += step;
                }
                item.repeats_left -= 1;
                item.status = ScheduleStatus::Pending;
                item.dispatch_started = false;
            }
            _ => item.status = ScheduleStatus::Fired,
        }
        update(&db, &item).map_err(sql_error)?;
        Ok(())
    }

    /// Records one failed delivery: the row retries after an exponential
    /// delay, and settles `Failed` at [`MAX_DELIVERY_ATTEMPTS`]. Returns
    /// whether the row gave up.
    pub fn mark_failed(&self, id: &str, now: Timestamp) -> Result<bool, String> {
        let now_ms = now.as_millisecond();
        let db = self.lock()?;
        let Some(mut item) = get(&db, id).map_err(sql_error)? else {
            return Ok(false);
        };
        item.attempts += 1;
        let gave_up = item.attempts >= MAX_DELIVERY_ATTEMPTS;
        if gave_up {
            item.status = ScheduleStatus::Failed;
            item.fired_at_ms = Some(now_ms);
            item.retry_at_ms = None;
        } else {
            let delay = RETRY_BASE_MS
                .saturating_mul(1 << (item.attempts - 1).min(16))
                .min(RETRY_MAX_MS);
            item.retry_at_ms = Some(now_ms + delay);
        }
        update(&db, &item).map_err(sql_error)?;
        Ok(gave_up)
    }

    /// Records that a leased row's delivery is being handed to the notify
    /// sink or the conversation route, before it crosses either. Returns
    /// whether an earlier handoff was already recorded, or `None` when the
    /// row is no longer leased (nothing may be delivered).
    ///
    /// The marker is durable evidence that an effect may have happened, not
    /// a concurrency lease: this and [`Self::undo_dispatch`] assume the one
    /// serialized reconcile loop is the only caller, so two passes never
    /// hand off the same row at once.
    pub fn start_dispatch(&self, id: &str) -> Result<Option<bool>, String> {
        use rusqlite::OptionalExtension as _;
        let mut db = self.lock()?;
        let transaction = db.transaction().map_err(sql_error)?;
        let started: Option<bool> = transaction
            .query_row(
                "SELECT dispatch_started FROM schedule_items WHERE id = ?1 AND status = 'firing'",
                [id],
                |row| row.get(0),
            )
            .optional()
            .map_err(sql_error)?;
        if started == Some(false) {
            transaction
                .execute(
                    "UPDATE schedule_items SET dispatch_started = 1 WHERE id = ?1",
                    [id],
                )
                .map_err(sql_error)?;
        }
        transaction.commit().map_err(sql_error)?;
        Ok(started)
    }

    /// Clears the first handoff marker only when the route reports no effect.
    /// Callers must not clear uncertainty from an earlier attempt.
    pub fn undo_dispatch(&self, id: &str) -> Result<(), String> {
        self.lock()?
            .execute(
                "UPDATE schedule_items SET dispatch_started = 0 WHERE id = ?1 AND status = 'firing'",
                [id],
            )
            .map(drop)
            .map_err(sql_error)
    }

    /// Cancels an open row whose delivery was never handed off. Returns
    /// whether it was; a row whose delivery may have happened is never
    /// relabelled.
    pub fn cancel_undispatched(&self, id: &str, now: Timestamp) -> Result<bool, String> {
        let changed = self
            .lock()?
            .execute(
                "UPDATE schedule_items SET status = 'cancelled', fired_at_ms = ?2, \
                 retry_at_ms = NULL WHERE id = ?1 AND status IN ('pending', 'firing') \
                 AND dispatch_started = 0",
                rusqlite::params![id, now.as_millisecond()],
            )
            .map_err(sql_error)?;
        Ok(changed == 1)
    }

    /// Keeps an unresolved row firing, retrying after the longest delay rather than every pass.
    pub fn hold_unresolved(&self, id: &str, now: Timestamp) -> Result<(), String> {
        self.lock()?
            .execute(
                "UPDATE schedule_items SET retry_at_ms = ?2 WHERE id = ?1 AND status = 'firing'",
                rusqlite::params![id, now.as_millisecond() + RETRY_MAX_MS],
            )
            .map(drop)
            .map_err(sql_error)
    }

    /// Settles a leased row whose delivery outcome cannot be known. It leaves
    /// `firing`, so a later pass neither resends it nor holds it open.
    pub fn settle_uncertain(&self, id: &str, now: Timestamp) -> Result<(), String> {
        self.lock()?
            .execute(
                "UPDATE schedule_items SET status = 'uncertain', fired_at_ms = ?2, \
                 retry_at_ms = NULL WHERE id = ?1 AND status = 'firing'",
                rusqlite::params![id, now.as_millisecond()],
            )
            .map(drop)
            .map_err(sql_error)
    }

    /// Reads, changes and writes the routine state in one transaction.
    pub fn update_routines<T>(
        &self,
        change: impl FnOnce(&mut RoutineSeen) -> T,
    ) -> Result<(RoutineSeen, T), String> {
        let mut db = self.lock()?;
        let transaction = db.transaction().map_err(sql_error)?;
        let before = read_routines(&transaction)?;
        let mut seen = before.clone();
        let value = change(&mut seen);
        if seen != before {
            transaction
                .execute("DELETE FROM routine_state", [])
                .map_err(sql_error)?;
            for (routine, first_seen) in &seen.first_seen {
                let fired = seen.fired.get(routine);
                transaction
                    .execute(
                        "INSERT INTO routine_state \
                         (routine, first_seen_ms, fired_at_ms, fired_occurrence) VALUES (?1, ?2, ?3, ?4)",
                        rusqlite::params![
                            routine,
                            first_seen,
                            fired.map(|fired| fired.0),
                            fired.map(|fired| fired.1.as_str()),
                        ],
                    )
                    .map_err(sql_error)?;
            }
        }
        transaction.commit().map_err(sql_error)?;
        Ok((seen, value))
    }

    /// Every routine's [`RoutineActivity`], in one statement over the
    /// routine record and the fired rows' anchor index.
    pub fn routine_activity(
        &self,
    ) -> Result<std::collections::BTreeMap<String, RoutineActivity>, String> {
        let db = self.lock()?;
        let mut statement = db.prepare_cached(ROUTINE_ACTIVITY).map_err(sql_error)?;
        let rows = statement
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, Option<i64>>(1)?,
                    row.get::<_, Option<i64>>(2)?,
                    row.get::<_, Option<i64>>(3)?,
                ))
            })
            .map_err(sql_error)?;
        let mut activity = std::collections::BTreeMap::new();
        for row in rows {
            let (routine, first_seen, recorded, delivered) = row.map_err(sql_error)?;
            activity.insert(
                routine,
                RoutineActivity {
                    first_seen,
                    recorded,
                    delivered,
                },
            );
        }
        Ok(activity)
    }

    pub fn routines(&self) -> Result<RoutineSeen, String> {
        let db = self.lock()?;
        read_routines(&db)
    }
}

/// Assigns duplicate ids deterministic `<id>-<n>` suffixes so re-imports after
/// a crash between commit and rename compare equal. Returns rows and the rename count.
fn distinct_ids(source: Vec<ScheduledItem>) -> (Vec<ScheduledItem>, usize) {
    let mut kept: Vec<ScheduledItem> = Vec::with_capacity(source.len());
    let mut taken: std::collections::HashSet<String> =
        source.iter().map(|item| item.id.clone()).collect();
    let mut seen = std::collections::HashSet::new();
    let mut reassigned = 0;
    for mut item in source {
        if seen.insert(item.id.clone()) {
            kept.push(item);
            continue;
        }
        let base = item.id.clone();
        item.id = (2..)
            .map(|n| format!("{base}-{n}"))
            .find(|id| !taken.contains(id))
            .unwrap_or(base);
        taken.insert(item.id.clone());
        reassigned += 1;
        kept.push(item);
    }
    (kept, reassigned)
}

fn read_routines(db: &rusqlite::Connection) -> Result<RoutineSeen, String> {
    let mut statement = db
        .prepare_cached(
            "SELECT routine, first_seen_ms, fired_at_ms, fired_occurrence FROM routine_state",
        )
        .map_err(sql_error)?;
    let mut seen = RoutineSeen::default();
    let rows = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, Option<i64>>(2)?,
                row.get::<_, Option<String>>(3)?,
            ))
        })
        .map_err(sql_error)?;
    for row in rows {
        let (routine, first_seen, fired_at, occurrence) = row.map_err(sql_error)?;
        if let (Some(at), Some(occurrence)) = (fired_at, occurrence) {
            seen.fired.insert(routine.clone(), (at, occurrence));
        }
        seen.first_seen.insert(routine, first_seen);
    }
    Ok(seen)
}

/// The owner's current time zone: the host's declared zone, or the zone the
/// owner last said he is in (`clock.json`, written by `time.zone.set`).
/// Keep the `clock.lock` inode so concurrent writers cannot acquire different locks.
#[derive(Clone, Debug)]
pub struct OwnerClock {
    override_path: PathBuf,
    write_lock: PathBuf,
}

#[derive(Serialize, Deserialize)]
struct ZoneOverride {
    zone: String,
    /// When travel ends and the host's zone returns ("until Sunday").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    until_ms: Option<i64>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ZoneChange {
    pub zone: String,
    /// The owner-local instant the host's zone returns, rendered.
    pub until: Option<String>,
}

impl OwnerClock {
    pub fn new(state_dir: &Path) -> Self {
        Self {
            override_path: state_dir.join("clock.json"),
            write_lock: state_dir.join("clock.lock"),
        }
    }

    /// The zone every time resolution and clock line uses.
    pub fn zone(&self) -> TimeZone {
        self.zone_at(Timestamp::now())
    }

    /// The zone at `now`: the recorded travel zone until it lapses, then
    /// the host's.
    fn zone_at(&self, now: Timestamp) -> TimeZone {
        std::fs::read(&self.override_path)
            .ok()
            .and_then(|bytes| serde_json::from_slice::<ZoneOverride>(&bytes).ok())
            .filter(|found| {
                found
                    .until_ms
                    .is_none_or(|until| now.as_millisecond() < until)
            })
            .and_then(|found| TimeZone::get(&found.zone).ok())
            .unwrap_or_else(TimeZone::system)
    }

    /// Moves the owner's zone (travel). The name must be an IANA zone;
    /// `until`, a local wall time in the new zone (`YYYY-MM-DDTHH:MM`),
    /// ends the travel and returns the host's zone.
    pub fn set_zone(&self, name: &str, until: Option<&str>) -> Result<ZoneChange, String> {
        let zone = TimeZone::get(name.trim())
            .map_err(|_| format!("{name:?} is not a known time zone (e.g. America/New_York)"))?;
        let name = zone.iana_name().unwrap_or(name.trim()).to_owned();
        let until_ms = until
            .map(|local| {
                let civil: DateTime = local.trim().replace(' ', "T").parse().map_err(|_| {
                    format!("until {local:?} is not a local time like 2026-10-04T23:59")
                })?;
                let at = civil
                    .to_zoned(zone.clone())
                    .map_err(|error| error.to_string())?
                    .timestamp();
                if at <= Timestamp::now() {
                    return Err(format!("until {local:?} in {name} is already past"));
                }
                Ok(at.as_millisecond())
            })
            .transpose()?;
        let bytes = serde_json::to_vec(&ZoneOverride {
            zone: name.clone(),
            until_ms,
        })
        .map_err(|error| error.to_string())?;

        let lock = std::fs::File::from(
            rustix::fs::open(
                &self.write_lock,
                rustix::fs::OFlags::CREATE
                    | rustix::fs::OFlags::RDWR
                    | rustix::fs::OFlags::CLOEXEC
                    | rustix::fs::OFlags::NOFOLLOW
                    | rustix::fs::OFlags::NONBLOCK,
                rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
            )
            .map_err(|error| format!("could not open the clock writer lock: {error}"))?,
        );
        let metadata = lock
            .metadata()
            .map_err(|error| format!("could not inspect the clock writer lock: {error}"))?;
        if !metadata.is_file() || metadata.nlink() != 1 {
            return Err("clock writer lock is not one private regular file".to_owned());
        }
        lock.try_lock()
            .map_err(|error| format!("could not acquire clock writer custody: {error}"))?;
        std::fs::write(&self.override_path, bytes)
            .map_err(|error| format!("could not record the time zone: {error}"))?;
        let until = until_ms.and_then(|at| {
            Timestamp::from_millisecond(at).ok().map(|at| {
                at.to_zoned(zone.clone())
                    .strftime("%a %b %-d %H:%M %Z")
                    .to_string()
            })
        });
        Ok(ZoneChange { zone: name, until })
    }

    /// One human line naming the owner's local time, prefixed to each turn.
    pub fn line(&self, now: Timestamp) -> String {
        let zone = self.zone();
        let name = zone.iana_name().unwrap_or("local").to_owned();
        format!(
            "[Colin's local time: {} ({name})]",
            now.to_zoned(zone).strftime("%A %Y-%m-%d %H:%M %Z")
        )
    }

    /// A local wall time `YYYY-MM-DDTHH:MM` in the owner's zone.
    pub fn resolve_local(&self, local: &str) -> Result<Timestamp, String> {
        let civil: DateTime = local
            .trim()
            .replace(' ', "T")
            .parse()
            .map_err(|_| format!("{local:?} is not a local time like 2026-10-07T20:00"))?;
        civil
            .to_zoned(self.zone())
            .map(|zoned| zoned.timestamp())
            .map_err(|error| error.to_string())
    }

    /// The owner-local day `date` as an RFC 3339 `[start, end)` window.
    pub fn day_window(&self, date: &str) -> Result<(String, String), String> {
        let date: Date = date
            .trim()
            .parse()
            .map_err(|_| format!("{date:?} is not a date like 2026-10-07"))?;
        let zone = self.zone();
        let start = date
            .to_zoned(zone.clone())
            .map_err(|error| error.to_string())?;
        let end = date
            .tomorrow()
            .and_then(|next| next.to_zoned(zone))
            .map_err(|error| error.to_string())?;
        Ok((start.timestamp().to_string(), end.timestamp().to_string()))
    }

    /// Renders an instant as owner-local `Wed Oct 7 20:00 PDT`.
    pub fn render(&self, at_ms: i64) -> String {
        Timestamp::from_millisecond(at_ms)
            .map(|at| {
                at.to_zoned(self.zone())
                    .strftime("%a %b %-d %H:%M %Z")
                    .to_string()
            })
            .unwrap_or_else(|_| at_ms.to_string())
    }
}

/// The latest occurrence of a routine schedule at or before `now`, in
/// `zone` (Colin's current zone): what a routine fires for, once.
pub fn latest_occurrence(
    schedule: &odin_registry::schema::RoutineSchedule,
    zone: &TimeZone,
    now: Timestamp,
) -> Option<Timestamp> {
    use odin_registry::schema::RoutineSchedule;
    let today = now.to_zoned(zone.clone()).date();
    let at = |date: Date, hour: u8, minute: u8| {
        date.at(hour as i8, minute as i8, 0, 0)
            .to_zoned(zone.clone())
            .ok()
            .map(|zoned| zoned.timestamp())
            .filter(|instant| *instant <= now)
    };
    match schedule {
        RoutineSchedule::Weekly { days, at: time } => (0..8).find_map(|back| {
            let date = today.checked_sub(jiff::Span::new().days(back)).ok()?;
            let weekday = date.weekday().to_monday_one_offset() as u8;
            days.contains(&weekday)
                .then(|| at(date, time.hour, time.minute))
                .flatten()
        }),
        RoutineSchedule::Monthly { day, at: time } => (0..2).find_map(|back| {
            let month = today
                .first_of_month()
                .checked_sub(jiff::Span::new().months(back))
                .ok()?;
            let date = Date::new(month.year(), month.month(), *day as i8).ok()?;
            at(date, time.hour, time.minute)
        }),
        RoutineSchedule::Every { minutes } => {
            let midnight = today.to_zoned(zone.clone()).ok()?.timestamp();
            let step = i64::from(*minutes) * 60_000;
            let elapsed = now.as_millisecond() - midnight.as_millisecond();
            Timestamp::from_millisecond(midnight.as_millisecond() + elapsed / step * step).ok()
        }
    }
}

/// Picks the earliest timed event (optionally whose title contains `needle`,
/// case-insensitive) from `(title, rfc3339 start)` pairs. All-day entries
/// carry no time of day and are skipped.
pub fn first_timed_event<'a>(
    events: impl IntoIterator<Item = (Option<&'a str>, &'a str)>,
    needle: Option<&str>,
) -> Option<(Timestamp, String)> {
    let needle = needle.map(str::to_lowercase);
    events
        .into_iter()
        .filter_map(|(title, start)| {
            let at: Timestamp = start.parse().ok()?;
            let title = title.unwrap_or("(untitled)").to_owned();
            match &needle {
                Some(needle) if !title.to_lowercase().contains(needle) => None,
                _ => Some((at, title)),
            }
        })
        .min_by_key(|(at, _)| *at)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn clock_in(zone: &str) -> (tempfile::TempDir, OwnerClock) {
        let dir = tempfile::tempdir().expect("tempdir");
        let clock = OwnerClock::new(dir.path());
        clock.set_zone(zone, None).expect("zone");
        (dir, clock)
    }

    #[test]
    fn local_times_resolve_in_the_owner_zone_and_follow_travel() {
        let (_dir, clock) = clock_in("America/Los_Angeles");
        let at = clock.resolve_local("2026-10-07T20:00").expect("resolves");
        assert_eq!(at.to_string(), "2026-10-08T03:00:00Z");
        assert_eq!(clock.render(at.as_millisecond()), "Wed Oct 7 20:00 PDT");
        clock.set_zone("America/New_York", None).expect("travel");
        let at = clock.resolve_local("2026-10-07T20:00").expect("resolves");
        assert_eq!(at.to_string(), "2026-10-08T00:00:00Z");
        assert!(clock.set_zone("Mars/Olympus", None).is_err());
    }

    #[test]
    fn an_owned_clock_writer_refuses_while_an_inverse_holds_custody() {
        let (dir, clock) = clock_in("America/New_York");
        let before = std::fs::read(dir.path().join("clock.json")).unwrap();
        let inverse = std::fs::File::create(dir.path().join("clock.lock")).unwrap();
        inverse.lock().unwrap();
        assert!(clock.set_zone("Asia/Tokyo", None).is_err());
        assert_eq!(
            std::fs::read(dir.path().join("clock.json")).unwrap(),
            before
        );
        drop(inverse);
        clock.set_zone("Asia/Tokyo", None).unwrap();
        assert_eq!(
            clock.resolve_local("2026-10-07T20:00").unwrap().to_string(),
            "2026-10-07T11:00:00Z"
        );
    }

    #[test]
    fn a_travel_zone_lapses_back_to_the_host_zone_at_its_end() {
        let dir = tempfile::tempdir().expect("tempdir");
        let clock = OwnerClock::new(dir.path());
        let host = TimeZone::system();
        let away = if host.iana_name() == Some("Asia/Tokyo") {
            "Europe/Paris"
        } else {
            "Asia/Tokyo"
        };
        let end = Timestamp::now()
            .checked_add(jiff::SignedDuration::from_hours(48))
            .expect("end")
            .to_zoned(TimeZone::get(away).expect("zone"))
            .strftime("%Y-%m-%dT%H:%M")
            .to_string();
        let change = clock.set_zone(away, Some(&end)).expect("travel");
        assert_eq!(change.zone, away);
        assert!(change.until.is_some());
        let before = Timestamp::now()
            .checked_add(jiff::SignedDuration::from_hours(47))
            .expect("before");
        let after = Timestamp::now()
            .checked_add(jiff::SignedDuration::from_hours(49))
            .expect("after");
        assert_eq!(clock.zone_at(before).iana_name(), Some(away));
        assert_eq!(clock.zone_at(after).iana_name(), host.iana_name());
        assert!(clock.set_zone(away, Some("2001-01-01T00:00")).is_err());
    }

    #[test]
    fn routine_occurrences_resolve_in_the_owner_zone() {
        use odin_registry::schema::RoutineSchedule;
        let zone = TimeZone::get("America/Los_Angeles").expect("zone");
        let local = |text: &str| -> Timestamp {
            text.parse::<DateTime>()
                .expect("civil")
                .to_zoned(zone.clone())
                .expect("zoned")
                .timestamp()
        };
        let latest = |schedule: &str, now: &str| {
            latest_occurrence(
                &RoutineSchedule::parse(schedule).expect("schedule"),
                &zone,
                local(now),
            )
        };
        // On Saturday, the latest weekday occurrence is Friday's.
        assert_eq!(
            latest("weekdays 07:30", "2026-10-03T09:00"),
            Some(local("2026-10-02T07:30"))
        );
        // Friday 07:29: not yet today's — Thursday's.
        assert_eq!(
            latest("weekdays 07:30", "2026-10-02T07:29"),
            Some(local("2026-10-01T07:30"))
        );
        assert_eq!(
            latest("monthly 1 09:00", "2026-10-01T08:00"),
            Some(local("2026-09-01T09:00"))
        );
        assert_eq!(
            latest("every 30 minutes", "2026-10-02T10:44"),
            Some(local("2026-10-02T10:30"))
        );
    }

    #[test]
    fn day_window_spans_the_owner_local_day() {
        let (_dir, clock) = clock_in("America/Los_Angeles");
        let (start, end) = clock.day_window("2026-09-30").expect("window");
        assert_eq!(start, "2026-09-30T07:00:00Z");
        assert_eq!(end, "2026-10-01T07:00:00Z");
    }

    #[test]
    fn first_timed_event_skips_all_day_and_honors_the_match() {
        let events = [
            (Some("Holiday"), "2026-09-30"),
            (Some("Gym"), "2026-09-30T14:00:00Z"),
            (Some("ME 11 lecture"), "2026-09-30T17:00:00Z"),
            (Some("ChE 63a"), "2026-09-30T16:00:00Z"),
        ];
        let (at, title) = first_timed_event(events, None).expect("first");
        assert_eq!(
            (at.to_string().as_str(), title.as_str()),
            ("2026-09-30T14:00:00Z", "Gym")
        );
        let (_, title) = first_timed_event(events, Some("me 11")).expect("match");
        assert_eq!(title, "ME 11 lecture");
        assert!(first_timed_event(events, Some("nothing")).is_none());
    }

    #[test]
    fn rows_fire_once_survive_a_crash_mid_delivery_and_cancel() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = ScheduleStore::open(dir.path()).expect("open");
        let now = Timestamp::from_second(1_790_000_000).expect("now");
        let later = now + jiff::SignedDuration::from_mins(5);
        assert!(store
            .add(ScheduleKind::Notify, "past", now, None, now)
            .is_err());
        let glasses = store
            .add(ScheduleKind::Notify, "get your glasses", later, None, now)
            .expect("add");
        let other = store
            .add(ScheduleKind::Wake, "check the pod", later, None, now)
            .expect("add");
        assert!(store.take_due(now).expect("due").is_empty());
        store.cancel(&other.id, now).expect("cancel");
        let due = store.take_due(later).expect("due");
        assert_eq!(
            due.iter().map(|item| &item.id).collect::<Vec<_>>(),
            [&glasses.id]
        );
        // A crash before mark_fired: a fresh store re-delivers the same row.
        let reopened = ScheduleStore::open(dir.path()).expect("open");
        assert_eq!(reopened.take_due(later).expect("due").len(), 1);
        reopened.mark_fired(&glasses.id, later).expect("fired");
        assert!(reopened.take_due(later).expect("due").is_empty());
        // A repeating wake re-arms on the cadence until its count runs out.
        let cycle = reopened
            .add(ScheduleKind::Wake, "check the pod", later, None, now)
            .expect("add");
        reopened.set_repeat(&cycle.id, 3, 1, now).expect("repeat");
        let fire = |at: Timestamp| {
            let due = reopened.take_due(at).expect("due");
            for item in &due {
                reopened.mark_fired(&item.id, at).expect("fired");
            }
            due.len()
        };
        assert_eq!(fire(later), 1);
        assert_eq!(fire(later + jiff::SignedDuration::from_mins(1)), 0);
        assert_eq!(fire(later + jiff::SignedDuration::from_mins(3)), 1);
        assert_eq!(
            fire(later + jiff::SignedDuration::from_mins(6)),
            0,
            "count spent"
        );
        // An event wake is added once per id, however often it is observed.
        assert!(reopened
            .wake_once("child-a", "kubert finished", later)
            .expect("wake"));
        assert!(!reopened
            .wake_once("child-a", "kubert finished", later)
            .expect("wake"));
        assert_eq!(reopened.take_due(later).expect("due").len(), 1);
        let statuses: Vec<_> = reopened
            .list()
            .expect("list")
            .into_iter()
            .map(|item| item.status)
            .collect();
        assert!(statuses.contains(&ScheduleStatus::Fired));
        assert!(statuses.contains(&ScheduleStatus::Cancelled));
    }

    fn legacy_row(id: &str, text: &str) -> ScheduledItem {
        ScheduledItem {
            id: id.to_owned(),
            kind: ScheduleKind::Notify,
            text: text.to_owned(),
            fire_at_ms: 1_790_000_000_000,
            anchor: None,
            created_at_ms: 1_789_000_000_000,
            status: ScheduleStatus::Fired,
            fired_at_ms: Some(1_790_000_000_500),
            every_minutes: None,
            repeats_left: 0,
            attempts: 0,
            retry_at_ms: None,
            event: false,
            routine_digest: None,
            dispatch_started: false,
        }
    }

    #[test]
    fn legacy_import_keeps_every_row_and_refuses_a_conflict() {
        let dir = tempfile::tempdir().expect("tempdir");
        let rows = serde_json::to_vec(&[
            legacy_row("r1", "one"),
            legacy_row("r1", "two"),
            legacy_row("r1", "one"),
        ])
        .expect("json");
        let routines =
            br#"{"routines":{"weekly":5},"fired":{"weekly":{"at_ms":7,"occurrence":"2026-10-04"}}}"#;
        let write = |rows: &[u8]| {
            std::fs::write(dir.path().join("schedule.json"), rows).expect("write");
            std::fs::write(dir.path().join("routines.json"), routines).expect("write");
        };
        write(&rows);
        let texts = |store: &ScheduleStore| {
            store
                .list()
                .expect("list")
                .into_iter()
                .map(|item| (item.id, item.text))
                .collect::<Vec<_>>()
        };
        let expected = vec![
            ("r1".to_owned(), "one".to_owned()),
            ("r1-2".to_owned(), "two".to_owned()),
            ("r1-3".to_owned(), "one".to_owned()),
        ];
        let store = ScheduleStore::open(dir.path()).expect("open");
        assert_eq!(texts(&store), expected);
        assert!(!dir.path().join("schedule.json").exists());
        assert!(!dir.path().join("routines.json").exists());
        assert_eq!(
            std::fs::read(dir.path().join("schedule.json.imported")).expect("kept"),
            rows
        );
        assert!(dir.path().join("routines.json.imported").exists());
        let seen = store.routines().expect("routines");
        assert_eq!(seen.first_seen.get("weekly"), Some(&5));
        assert_eq!(
            seen.fired.get("weekly"),
            Some(&(7, "2026-10-04".to_owned()))
        );
        drop(store);
        // The renames lost after a durable commit: the same files verify
        // equal and go.
        write(&rows);
        let store = ScheduleStore::open(dir.path()).expect("re-import");
        assert_eq!(texts(&store), expected);
        assert!(!dir.path().join("schedule.json").exists());
        drop(store);
        // A legacy row differing from the stored row of its id is refused
        // and both copies stay.
        write(&serde_json::to_vec(&[legacy_row("r1", "changed")]).expect("json"));
        let refused = ScheduleStore::open(dir.path())
            .err()
            .expect("conflict refused");
        assert!(refused.contains("legacy files kept"), "{refused}");
        assert!(dir.path().join("schedule.json").exists());
        assert!(dir.path().join("routines.json").exists());
    }

    #[test]
    fn a_deferred_wake_waits_for_the_tick_not_a_spent_deadline() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = ScheduleStore::open(dir.path()).expect("open");
        let start = Timestamp::from_millisecond(1_790_000_000_000).unwrap();
        assert!(store.wake_once("w", "report", start).unwrap());
        assert_eq!(store.take_due(start).unwrap().len(), 1);
        store.mark_failed("w", start).unwrap();
        let later =
            Timestamp::from_millisecond(start.as_millisecond() + RETRY_BASE_MS + 1).unwrap();
        assert_eq!(store.take_due(later).unwrap().len(), 1, "retry due");
        assert_eq!(
            store.next_due_ms().unwrap(),
            None,
            "deferred: no deadline behind it"
        );
        drop(store);
        // A restart before the route binds still finds the leased row.
        let store = ScheduleStore::open(dir.path()).expect("reopen");
        assert_eq!(store.take_due(later).unwrap().len(), 1);
        assert_eq!(store.next_due_ms().unwrap(), None);
    }

    #[test]
    fn a_pass_reads_through_indexes_not_the_history() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = ScheduleStore::open(dir.path()).expect("open");
        let mut db = store.lock().expect("lock");
        let history = db.transaction().expect("transaction");
        for n in 0..10_000 {
            insert(&history, &legacy_row(&format!("h{n}"), "settled")).expect("insert");
        }
        history.commit().expect("commit");
        let statements = [LEASE_DUE, SELECT_FIRING, SPEND_RETRIES]
            .into_iter()
            .chain(PURGE_SETTLED)
            .chain(NEXT_DUE)
            .chain([ROUTINE_ACTIVITY]);
        for sql in statements {
            let mut plan = db
                .prepare(&format!("EXPLAIN QUERY PLAN {sql}"))
                .expect("plan");
            let details = plan
                .query_map(
                    rusqlite::params_from_iter(std::iter::repeat_n(0_i64, plan.parameter_count())),
                    |row| row.get::<_, String>(3),
                )
                .expect("rows")
                .collect::<rusqlite::Result<Vec<_>>>()
                .expect("details");
            assert!(
                details
                    .iter()
                    .filter(|detail| detail.contains("schedule_items"))
                    .all(|detail| detail.contains("INDEX schedule_items_")),
                "{sql}: {details:?}"
            );
        }
    }

    // Count statements to enforce a single routine-state read.
    thread_local! {
        static TRACED_STATEMENTS: std::cell::RefCell<Vec<String>> =
            const { std::cell::RefCell::new(Vec::new()) };
    }

    fn trace_statement(statement: &str) {
        TRACED_STATEMENTS.with(|traced| traced.borrow_mut().push(statement.to_owned()));
    }

    #[test]
    fn the_routine_read_is_one_statement_carrying_both_firings() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = ScheduleStore::open(dir.path()).expect("open");
        store
            .update_routines(|seen| {
                seen.first_seen.insert("recorded".to_owned(), 10);
                seen.fired
                    .insert("recorded".to_owned(), (500, "b".to_owned()));
                seen.first_seen.insert("delivered".to_owned(), 20);
                seen.fired
                    .insert("delivered".to_owned(), (200, "a".to_owned()));
                seen.first_seen.insert("never".to_owned(), 30);
            })
            .expect("seed");
        let mut db = store.lock().expect("lock");
        for (routine, at) in [("recorded", 400), ("delivered", 300), ("orphan", 123)] {
            let mut row = legacy_row(&format!("routine:{routine}:o"), "fired");
            row.anchor = Some(format!("routine:{routine}"));
            row.fired_at_ms = Some(at);
            insert(&db, &row).expect("delivered row");
        }
        db.trace(Some(trace_statement));
        drop(db);
        let activity = store.routine_activity().expect("activity");
        let traced = TRACED_STATEMENTS.with(std::cell::RefCell::take);
        assert_eq!(traced.len(), 1, "one statement, not two: {traced:?}");
        assert!(
            traced[0].contains("routine_state") && traced[0].contains("schedule_items"),
            "one statement over both sources: {traced:?}"
        );
        assert_eq!(
            activity.get("recorded"),
            Some(&RoutineActivity {
                first_seen: Some(10),
                recorded: Some(500),
                delivered: Some(400),
            })
        );
        assert_eq!(
            activity.get("delivered"),
            Some(&RoutineActivity {
                first_seen: Some(20),
                recorded: Some(200),
                delivered: Some(300),
            })
        );
        assert_eq!(
            activity.get("never"),
            Some(&RoutineActivity {
                first_seen: Some(30),
                recorded: None,
                delivered: None,
            })
        );
        assert_eq!(
            activity.get("orphan"),
            Some(&RoutineActivity {
                first_seen: None,
                recorded: None,
                delivered: Some(123),
            })
        );
        assert_eq!(activity.len(), 4, "{activity:?}");
    }

    #[test]
    fn failed_deliveries_back_off_and_give_up() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = ScheduleStore::open(dir.path()).expect("open");
        let start = Timestamp::from_millisecond(1_790_000_000_000).unwrap();
        assert!(store.wake_once("w", "report", start).unwrap());
        assert_eq!(store.take_due(start).unwrap().len(), 1);
        let mut now = start;
        for attempt in 1..MAX_DELIVERY_ATTEMPTS {
            assert!(!store.mark_failed("w", now).unwrap());
            assert!(
                store.take_due(now).unwrap().is_empty(),
                "backing off after attempt {attempt}"
            );
            now = Timestamp::from_millisecond(now.as_millisecond() + RETRY_MAX_MS).unwrap();
            assert_eq!(
                store.take_due(now).unwrap().len(),
                1,
                "retried after attempt {attempt}"
            );
        }
        assert!(
            store.mark_failed("w", now).unwrap(),
            "gives up at the bound"
        );
        assert!(store.take_due(now).unwrap().is_empty());
        assert_eq!(store.list().unwrap()[0].status, ScheduleStatus::Failed);
    }

    #[test]
    fn an_unknown_delivery_settles_uncertain_and_is_not_retried() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = ScheduleStore::open(dir.path()).expect("open");
        let start = Timestamp::from_millisecond(1_790_000_000_000).unwrap();
        assert!(store.wake_once("missed", "the 3pm note", start).unwrap());
        assert_eq!(store.take_due(start).unwrap().len(), 1);
        store.settle_uncertain("missed", start).unwrap();
        let row = store.list().unwrap().into_iter().next().unwrap();
        assert_eq!(row.status, ScheduleStatus::Uncertain);
        assert_eq!(row.attempts, 0, "settling unknown does not burn an attempt");
        let later = Timestamp::from_millisecond(start.as_millisecond() + RETRY_MAX_MS).unwrap();
        assert!(
            store.take_due(later).unwrap().is_empty(),
            "an uncertain row is not due again"
        );
    }

    /// A wake waiting on a down vehicle backs off without counting an attempt,
    /// and is due again after the wait.
    #[test]
    fn a_deferred_wake_keeps_its_attempt_count() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = ScheduleStore::open(dir.path()).expect("open");
        let start = Timestamp::from_millisecond(1_790_000_000_000).unwrap();
        assert!(store.wake_once("down", "morning brief", start).unwrap());
        assert_eq!(store.take_due(start).unwrap()[0].attempts, 0);
        store.hold_unresolved("down", start).unwrap();
        assert!(
            store.take_due(start).unwrap().is_empty(),
            "still backing off"
        );
        let later = Timestamp::from_millisecond(start.as_millisecond() + RETRY_MAX_MS).unwrap();
        let due = store.take_due(later).unwrap();
        assert_eq!(due.len(), 1);
        assert_eq!(due[0].attempts, 0, "the wait did not burn an attempt");
        assert_eq!(due[0].status, ScheduleStatus::Firing);
    }

    /// Purging rows without a delivery timestamp must seek by deadline, not scan retained rows.
    #[test]
    fn the_null_fired_purge_stays_bounded_by_the_deadline_not_the_history() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = ScheduleStore::open(dir.path()).expect("open");
        let mut db = store.lock().expect("lock");
        let history = db.transaction().expect("transaction");
        for n in 0..10_000 {
            let mut row = legacy_row(&format!("h{n}"), "settled");
            row.status = ScheduleStatus::Failed;
            row.fired_at_ms = None;
            insert(&history, &row).expect("insert");
        }
        history.commit().expect("commit");
        let deadline = 1_790_000_000_000 - RETAIN_DONE_MS;
        for purge in PURGE_SETTLED {
            let mut statement = db.prepare(purge).expect("prepare");
            let deleted = statement.execute([deadline]).expect("purge");
            assert_eq!(deleted, 0, "unexpired rows survive: {purge}");
            assert_eq!(
                statement.get_status(rusqlite::StatementStatus::FullscanStep),
                0,
                "seeks the deadline, never scans: {purge}"
            );
            assert!(
                statement.get_status(rusqlite::StatementStatus::VmStep) < 200,
                "cost is bounded, not proportional to the retained rows: {purge}"
            );
        }
        let kept = db
            .query_row("SELECT count(*) FROM schedule_items", [], |row| {
                row.get::<_, i64>(0)
            })
            .expect("count");
        assert_eq!(kept, 10_000);
    }
}
