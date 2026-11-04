//! Deterministic reminders and seat wakes. The model states WHAT and the
//! anchor ("at 20:00", "30 minutes before my first class tomorrow"); code
//! resolves WHEN in the owner's current zone, stores the row durably, and the
//! reconcile loop fires it: a plain owner DM (`notify`) or an unprompted turn
//! of the seat's own conversation (`wake`). Models never decide when.

use std::path::{Path, PathBuf};
use std::sync::Mutex;

use jiff::civil::{Date, DateTime};
use jiff::tz::TimeZone;
use jiff::Timestamp;
use serde::{Deserialize, Serialize};

/// Fired and cancelled rows are kept this long for `list` and audit.
const RETAIN_DONE_MS: i64 = 30 * 24 * 3600 * 1000;
const MAX_AHEAD_DAYS: i64 = 400;
const MAX_AHEAD_MS: i64 = MAX_AHEAD_DAYS * 24 * 3600 * 1000;
/// Bounds of a repeating row: its cadence in minutes and the firings after the first.
pub const REPEAT_MINUTES: std::ops::RangeInclusive<i64> = 1..=1_440;
pub const REPEAT_TIMES: std::ops::RangeInclusive<u32> = 1..=500;
/// Failed deliveries after which a row settles `Failed` instead of retrying.
pub const MAX_DELIVERY_ATTEMPTS: u32 = 8;
/// First retry delay after a failed delivery; doubles per attempt.
const RETRY_BASE_MS: i64 = 10_000;
const RETRY_MAX_MS: i64 = 10 * 60 * 1000;
/// How long a wake waits for a conversation that is mid-turn or settling
/// after a reload: it is back within seconds, so a long hold would only
/// leave the owner waiting on a report that already arrived.
pub const VEHICLE_BUSY_WAIT_MS: i64 = 15_000;
pub const MAX_TEXT_CHARS: usize = 500;
/// A background job report's row id starts with this; a routine occurrence's `anchor` does.
pub const JOB_ROW_PREFIX: &str = "job:";
pub const ROUTINE_ROW_PREFIX: &str = "routine:";

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
    /// The delivery may have reached the owner and may not have. Terminal:
    /// told once, never held open, never sent again.
    Uncertain,
}

/// What an event wake about one job came to.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EventWake {
    /// A wake was queued.
    Queued,
    /// That very event was queued before.
    Known,
    /// The same cause already woke the seat about this job inside the quiet
    /// window, so nothing was queued; `first` marks the first such repeat of
    /// that wake, the one worth a note on the job.
    Quiet { first: bool },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
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
    odin_ledger::migration::Migration::register(
        5,
        "schemas/hermes/0005_open_asks.sql",
        "eb75de4cca7df61194b85d9b25a89c75964e68a29203bdf242fd2fb913d7a655",
        include_str!("../../../schemas/hermes/0005_open_asks.sql"),
    ),
    odin_ledger::migration::Migration::register(
        6,
        "schemas/hermes/0006_quiet_wakes.sql",
        "ee5e6d5be4da28d1d66c3eeb88a7ab25e65a350214e3c8a582999a41b119da26",
        include_str!("../../../schemas/hermes/0006_quiet_wakes.sql"),
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
/// Job reports leased and held for a busy conversation (`JobBoard` wakes
/// them as `job:…`).
const SELECT_HELD_REPORTS: &str = concat!(
    "SELECT ",
    columns!(),
    " FROM schedule_items INDEXED BY schedule_items_firing \
     WHERE status = 'firing' AND retry_at_ms > ?1 \
     AND kind = 'wake' AND id >= 'job:' AND id < 'job;' ORDER BY fire_at_ms, id"
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
const NEXT_DUE: [&str; 3] = [
    "SELECT min(fire_at_ms) FROM schedule_items WHERE status = 'pending'",
    "SELECT min(retry_at_ms) FROM schedule_items WHERE status = 'firing'",
    "SELECT min(next_wake_ms) FROM open_asks",
];

/// The durable schedule: one SQLite table under the Hermes state directory
/// (`schedule.sqlite3`), indexed on the open rows' fire time, so a pass
/// touches only what is due and the reconcile loop sleeps to the next one.
pub struct ScheduleStore {
    db: Mutex<rusqlite::Connection>,
}

/// A request of the owner whose delegated jobs all ended without a delivered
/// result: it wakes the seat every interval until it is delivered, relaunched
/// or dropped.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OpenAsk {
    /// What `reminder_cancel` names to drop it.
    pub id: String,
    /// What the ask is about; a relaunch and its report carry the same one.
    pub subject: String,
    /// The newest job that ended unmet.
    pub job: String,
    /// What that job left undone, in one line.
    pub unmet: String,
    pub opened_ms: i64,
    pub next_wake_ms: i64,
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
    pub fn open(state_dir: &Path) -> Result<Self, String> {
        let db = odin_ledger::open_database(state_dir.join("schedule.sqlite3"), MIGRATIONS)
            .map_err(sql_error)?;
        // Acknowledged reminders and deliveries must survive power loss.
        db.pragma_update(None, "synchronous", "FULL")
            .map_err(sql_error)?;
        Ok(Self { db: Mutex::new(db) })
    }

    fn lock(&self) -> Result<std::sync::MutexGuard<'_, rusqlite::Connection>, String> {
        self.db
            .lock()
            .map_err(|error| format!("schedule store lock: {error}"))
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
            return Err(format!(
                "reminders can be set at most {MAX_AHEAD_DAYS} days ahead"
            ));
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

    /// Whether a row under `id` exists, whatever its status.
    pub fn has(&self, id: &str) -> Result<bool, String> {
        let db = self.lock()?;
        Ok(get(&db, id).map_err(sql_error)?.is_some())
    }

    /// [`Self::wake_once`] for an event about `job` for `cause`: the same
    /// cause waking the seat again about the same job inside `window_ms` of
    /// its last wake queues nothing. A new cause, or a quiet window that has
    /// passed, wakes again.
    pub fn wake_event_once(
        &self,
        id: &str,
        text: &str,
        (job, cause): (&str, &str),
        window_ms: i64,
        now: Timestamp,
    ) -> Result<EventWake, String> {
        use rusqlite::OptionalExtension as _;
        if self.has(id)? {
            return Ok(EventWake::Known);
        }
        let now_ms = now.as_millisecond();
        let db = self.lock()?;
        let last: Option<(String, i64, bool)> = db
            .query_row(
                "SELECT cause, woke_ms, noted FROM quiet_wakes WHERE job = ?1",
                [job],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()
            .map_err(sql_error)?;
        if let Some((last_cause, woke_ms, noted)) = last {
            if last_cause == cause && now_ms - woke_ms < window_ms {
                db.execute("UPDATE quiet_wakes SET noted = 1 WHERE job = ?1", [job])
                    .map_err(sql_error)?;
                return Ok(EventWake::Quiet { first: !noted });
            }
        }
        drop(db);
        if !self.wake_once(id, text, now)? {
            return Ok(EventWake::Known);
        }
        self.lock()?
            .execute(
                "INSERT INTO quiet_wakes (job, cause, wake_id, woke_ms, noted) \
                 VALUES (?1, ?2, ?3, ?4, 0) ON CONFLICT (job) DO UPDATE SET \
                 cause = ?2, wake_id = ?3, woke_ms = ?4, noted = 0",
                rusqlite::params![job, cause, id, now_ms],
            )
            .map_err(sql_error)?;
        Ok(EventWake::Queued)
    }

    /// The wake that last woke the seat about `job`.
    pub fn quiet_wake_id(&self, job: &str) -> Result<Option<String>, String> {
        use rusqlite::OptionalExtension as _;
        self.lock()?
            .query_row(
                "SELECT wake_id FROM quiet_wakes WHERE job = ?1",
                [job],
                |row| row.get(0),
            )
            .optional()
            .map_err(sql_error)
    }

    /// Claims the same once-only wake identity after its answer was delivered
    /// inline. The row is already fired, so deduplication wakes no model turn.
    pub fn acknowledge_wake_once(&self, id: &str, now: Timestamp) -> Result<bool, String> {
        self.enqueue_once_at_status(
            id,
            "Answer delivered inline.",
            None,
            true,
            now,
            (ScheduleKind::Wake, ScheduleStatus::Fired),
        )
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
        self.enqueue_once_at_status(
            id,
            text,
            routine,
            event,
            now,
            (kind, ScheduleStatus::Pending),
        )
    }

    fn enqueue_once_at_status(
        &self,
        id: &str,
        text: &str,
        routine: Option<(&str, String)>,
        event: bool,
        now: Timestamp,
        disposition: (ScheduleKind, ScheduleStatus),
    ) -> Result<bool, String> {
        let (kind, status) = disposition;
        let now_ms = now.as_millisecond();
        let (anchor, routine_digest) = match routine {
            Some((routine, digest)) => {
                (Some(format!("{ROUTINE_ROW_PREFIX}{routine}")), Some(digest))
            }
            None => (None, None),
        };
        let item = ScheduledItem {
            id: id.to_owned(),
            kind,
            text: text.to_owned(),
            fire_at_ms: now_ms,
            anchor,
            created_at_ms: now_ms,
            status,
            fired_at_ms: (status == ScheduleStatus::Fired).then_some(now_ms),
            every_minutes: None,
            repeats_left: 0,
            attempts: 0,
            retry_at_ms: None,
            event,
            routine_digest,
            dispatch_started: false,
        };
        let mut db = self.lock()?;
        let transaction = db.transaction().map_err(sql_error)?;
        let inserted = insert(&transaction, &item).map_err(sql_error)? == 1;
        if status == ScheduleStatus::Fired {
            transaction
                .execute(
                    "UPDATE schedule_items SET status = 'fired', fired_at_ms = ?2 \
                 WHERE id = ?1 AND dispatch_started = 0 AND status IN ('pending', 'firing')",
                    rusqlite::params![id, now_ms],
                )
                .map_err(sql_error)?;
        }
        transaction.commit().map_err(sql_error)?;
        Ok(inserted)
    }

    /// Makes a pending row repeat every `every_minutes`, `times` more times.
    pub fn set_repeat(&self, id: &str, every_minutes: i64, times: u32) -> Result<(), String> {
        if !REPEAT_MINUTES.contains(&every_minutes) || !REPEAT_TIMES.contains(&times) {
            return Err(format!(
                "repeat every {}..={} minutes, {}..={} more times",
                REPEAT_MINUTES.start(),
                REPEAT_MINUTES.end(),
                REPEAT_TIMES.start(),
                REPEAT_TIMES.end()
            ));
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

    /// Job reports already leased but held until later, mostly for a busy
    /// conversation: they ride the next report turn rather than wake their own.
    pub fn held_job_reports(&self, now: Timestamp) -> Result<Vec<ScheduledItem>, String> {
        let db = self.lock()?;
        let mut statement = db.prepare_cached(SELECT_HELD_REPORTS).map_err(sql_error)?;
        let rows = statement
            .query_map([now.as_millisecond()], item_of)
            .map_err(sql_error)?
            .collect::<rusqlite::Result<Vec<_>>>()
            .map_err(sql_error);
        rows
    }

    /// The event wakes due now, oldest first, that a turn of the owner's may
    /// carry: job reports batch among themselves, and routines and the
    /// seat's own reminders keep their own turns.
    pub fn due_events(&self, now: Timestamp) -> Result<Vec<ScheduledItem>, String> {
        let db = self.lock()?;
        let mut statement = db
            .prepare_cached(&format!(
                "SELECT {COLUMNS} FROM schedule_items WHERE kind = 'wake' AND event = 1 \
                 AND fire_at_ms <= ?1 \
                 AND (status = 'pending' OR (status = 'firing' AND retry_at_ms > ?1)) \
                 AND NOT (id >= 'job:' AND id < 'job;') ORDER BY fire_at_ms, id"
            ))
            .map_err(sql_error)?;
        let rows = statement
            .query_map([now.as_millisecond()], item_of)
            .map_err(sql_error)?
            .collect::<rusqlite::Result<Vec<_>>>()
            .map_err(sql_error);
        rows
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
        self.hold_for(id, now, RETRY_MAX_MS)
    }

    /// Holds a leased row for `wait_ms` without counting an attempt.
    pub fn hold_for(&self, id: &str, now: Timestamp, wait_ms: i64) -> Result<(), String> {
        self.lock()?
            .execute(
                "UPDATE schedule_items SET retry_at_ms = ?2 WHERE id = ?1 AND status = 'firing'",
                rusqlite::params![id, now.as_millisecond() + wait_ms],
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

    /// Opens an ask. One already open keeps the time it first opened; a newer
    /// unmet job replaces its job and unmet line and starts its wait again,
    /// while the same job observed again changes nothing.
    pub fn open_ask(&self, ask: &OpenAsk) -> Result<(), String> {
        self.lock()?
            .execute(
                "INSERT INTO open_asks (id, subject, job, unmet, opened_ms, next_wake_ms) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6) ON CONFLICT (id) DO UPDATE SET \
                 job = excluded.job, unmet = excluded.unmet, \
                 next_wake_ms = CASE WHEN open_asks.job = excluded.job \
                 THEN open_asks.next_wake_ms ELSE excluded.next_wake_ms END",
                rusqlite::params![
                    ask.id,
                    ask.subject,
                    ask.job,
                    ask.unmet,
                    ask.opened_ms,
                    ask.next_wake_ms
                ],
            )
            .map(drop)
            .map_err(sql_error)
    }

    /// Closes one ask; whether it was open.
    pub fn close_ask(&self, id: &str) -> Result<bool, String> {
        let closed = self
            .lock()?
            .execute("DELETE FROM open_asks WHERE id = ?1", [id])
            .map_err(sql_error)?;
        Ok(closed == 1)
    }

    /// Every open ask, oldest first.
    pub fn open_asks(&self) -> Result<Vec<OpenAsk>, String> {
        let db = self.lock()?;
        let mut statement = db
            .prepare_cached(
                "SELECT id, subject, job, unmet, opened_ms, next_wake_ms FROM open_asks \
                 ORDER BY opened_ms, id",
            )
            .map_err(sql_error)?;
        let rows = statement
            .query_map([], |row| {
                Ok(OpenAsk {
                    id: row.get(0)?,
                    subject: row.get(1)?,
                    job: row.get(2)?,
                    unmet: row.get(3)?,
                    opened_ms: row.get(4)?,
                    next_wake_ms: row.get(5)?,
                })
            })
            .map_err(sql_error)?
            .collect::<rusqlite::Result<Vec<_>>>()
            .map_err(sql_error);
        rows
    }

    /// Moves one open ask's next wake.
    pub fn wake_ask_at(&self, id: &str, next_wake_ms: i64) -> Result<(), String> {
        self.lock()?
            .execute(
                "UPDATE open_asks SET next_wake_ms = ?2 WHERE id = ?1",
                rusqlite::params![id, next_wake_ms],
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
#[derive(Clone, Debug)]
pub struct OwnerClock {
    override_path: PathBuf,
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
        }
    }

    /// The zone every time resolution and clock line uses.
    pub fn zone(&self) -> TimeZone {
        self.zone_at(Timestamp::now())
    }

    /// The zone at `now`: the recorded travel zone until it lapses, then
    /// the host's.
    fn zone_at(&self, now: Timestamp) -> TimeZone {
        let recorded = match std::fs::read(&self.override_path) {
            Ok(bytes) => serde_json::from_slice::<ZoneOverride>(&bytes)
                .map_err(|error| error.to_string())
                .and_then(|found| {
                    TimeZone::get(&found.zone)
                        .map(|zone| (found, zone))
                        .map_err(|error| error.to_string())
                }),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return TimeZone::system()
            }
            Err(error) => Err(error.to_string()),
        };
        match recorded {
            Ok((found, zone)) => {
                let lapsed = found
                    .until_ms
                    .is_some_and(|until| now.as_millisecond() >= until);
                if lapsed {
                    TimeZone::system()
                } else {
                    zone
                }
            }
            Err(error) => {
                tracing::warn!(
                    "odin-hermes: {} is unusable, so times follow the host zone; set the zone again: {error}",
                    self.override_path.display()
                );
                TimeZone::system()
            }
        }
    }

    /// Moves the owner's zone (travel). The name must be an IANA zone;
    /// `until`, a local wall time in the new zone (`YYYY-MM-DDTHH:MM`),
    /// ends the travel and returns the host's zone.
    pub fn set_zone(&self, name: &str, until: Option<&str>) -> Result<ZoneChange, String> {
        let zone = TimeZone::get(name.trim()).map_err(|error| {
            format!("{name:?} is not a known time zone (e.g. America/New_York): {error}")
        })?;
        let name = zone.iana_name().unwrap_or(name.trim()).to_owned();
        let until_ms = until
            .map(|local| {
                let civil: DateTime = local.trim().replace(' ', "T").parse().map_err(|error| {
                    format!("until {local:?} is not a local time like 2026-10-04T23:59: {error}")
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

        let staged = self
            .override_path
            .with_extension(format!("{}.tmp", std::process::id()));
        std::fs::write(&staged, bytes)
            .and_then(|()| std::fs::rename(&staged, &self.override_path))
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
            "[the owner's local time: {} ({name})]",
            now.to_zoned(zone).strftime("%A %Y-%m-%d %H:%M %Z")
        )
    }

    /// The instant of `local`: a wall time `YYYY-MM-DDTHH:MM` in the owner's
    /// zone, or an RFC 3339 time that names its own offset (`...-07:00`, `...Z`).
    pub fn resolve_local(&self, local: &str) -> Result<Timestamp, String> {
        let local = local.trim();
        if let Ok(instant) = local.parse::<Timestamp>() {
            return Ok(instant);
        }
        let civil: DateTime = local.replace(' ', "T").parse().map_err(|error| {
            format!("{local:?} is not a local time like 2026-10-07T20:00 or an RFC 3339 time with an offset: {error}")
        })?;
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
            .map_err(|error| format!("{date:?} is not a date like 2026-10-07: {error}"))?;
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
/// `zone` (the owner's current zone): what a routine fires for, once.
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
    fn a_damaged_zone_record_follows_the_host_zone_until_it_is_set_again() {
        let (dir, clock) = clock_in("Asia/Tokyo");
        let host = TimeZone::system();
        std::fs::write(dir.path().join("clock.json"), b"{\"zone\":\"Asia/To").unwrap();
        assert_eq!(clock.zone().iana_name(), host.iana_name());
        clock.set_zone("Asia/Tokyo", None).unwrap();
        assert_eq!(clock.zone().iana_name(), Some("Asia/Tokyo"));
        let files: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();
        assert_eq!(files, ["clock.json"], "no staging file is left behind");
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
        reopened.set_repeat(&cycle.id, 3, 1).expect("repeat");
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

    #[test]
    fn the_same_cause_about_a_job_wakes_once_inside_the_quiet_window() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = ScheduleStore::open(dir.path()).expect("a fresh store opens with migration 6");
        let start = Timestamp::from_millisecond(1_790_000_000_000).unwrap();
        let window = 30 * 60_000;
        let wake = |id, cause, at: i64| {
            let now = Timestamp::from_millisecond(start.as_millisecond() + at).unwrap();
            store.wake_event_once(id, "text", ("pod:a", cause), window, now)
        };
        assert_eq!(wake("w1", "stuck", 0), Ok(EventWake::Queued));
        assert_eq!(wake("w1", "stuck", 1_000), Ok(EventWake::Known));
        assert_eq!(
            wake("w2", "stuck", 2_000),
            Ok(EventWake::Quiet { first: true })
        );
        assert_eq!(
            wake("w3", "stuck", 3_000),
            Ok(EventWake::Quiet { first: false })
        );
        assert_eq!(store.quiet_wake_id("pod:a"), Ok(Some("w1".to_owned())));
        assert_eq!(wake("w4", "crashed", 4_000), Ok(EventWake::Queued));
        assert_eq!(wake("w5", "crashed", window + 5_000), Ok(EventWake::Queued));
    }

    #[test]
    fn only_events_not_in_delivery_can_ride_an_owner_message() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = ScheduleStore::open(dir.path()).expect("open");
        let start = Timestamp::from_millisecond(1_790_000_000_000).unwrap();
        let later = Timestamp::from_millisecond(start.as_millisecond() + 60_000).unwrap();
        for id in ["pending", "delivering", "held", "job:report"] {
            assert!(store.wake_once(id, id, start).unwrap());
        }
        store.take_due(start).unwrap();
        store.hold_for("held", start, 10 * 60_000).unwrap();
        let ids = |rows: Vec<ScheduledItem>| rows.into_iter().map(|row| row.id).collect::<Vec<_>>();
        // `pending` was leased by the pass too, so it is in delivery with the rest.
        assert_eq!(ids(store.due_events(later).unwrap()), ["held"]);
        let fresh = Timestamp::from_millisecond(later.as_millisecond() + 1).unwrap();
        assert!(store.wake_once("fresh", "fresh", fresh).unwrap());
        let after = Timestamp::from_millisecond(fresh.as_millisecond() + 1).unwrap();
        assert_eq!(ids(store.due_events(after).unwrap()), ["held", "fresh"]);
    }
}
