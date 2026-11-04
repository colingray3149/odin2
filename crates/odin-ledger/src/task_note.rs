//! Notes a seat pins to a task it can see open: its live memory shows them
//! while the task is open, and `ops.history` carries them once it closes.

use rusqlite::{params, Connection};
use time::OffsetDateTime;

use crate::{encode_utc, LedgerError, LedgerResult};

/// The longest note one call pins.
pub const MAX_NOTE_CHARS: usize = 600;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TaskNote {
    pub task: String,
    pub seat: String,
    /// The pinning session's project.
    pub project: Option<String>,
    pub noted_at: String,
    pub note: String,
}

/// Pins `note` to `task` for `seat` in `project`.
pub fn add(
    connection: &Connection,
    task: &str,
    seat: &str,
    project: Option<&str>,
    note: &str,
    at: OffsetDateTime,
) -> LedgerResult<()> {
    let note = note.trim();
    if note.is_empty() || note.chars().count() > MAX_NOTE_CHARS {
        return Err(LedgerError::invalid_data(format!(
            "a task note holds 1..={MAX_NOTE_CHARS} characters"
        )));
    }
    connection.execute(
        "INSERT INTO task_notes (task, seat, project, noted_at, note) VALUES (?1, ?2, ?3, ?4, ?5)",
        params![task, seat, project, encode_utc(at)?, note],
    )?;
    connection.execute(
        "UPDATE task_outcomes SET history_recorded = 0 WHERE task = ?1 AND project = ?2",
        params![task, project],
    )?;
    Ok(())
}

/// The notes on `tasks`, oldest first.
pub fn for_tasks(connection: &Connection, tasks: &[&str]) -> LedgerResult<Vec<TaskNote>> {
    let mut statement = connection.prepare_cached(
        "SELECT task, seat, project, noted_at, note FROM task_notes WHERE task = ?1 \
         ORDER BY noted_at",
    )?;
    let mut notes = Vec::new();
    for task in tasks {
        let rows = statement.query_map(params![task], |row| {
            Ok(TaskNote {
                task: row.get(0)?,
                seat: row.get(1)?,
                project: row.get(2)?,
                noted_at: row.get(3)?,
                note: row.get(4)?,
            })
        })?;
        for row in rows {
            notes.push(row?);
        }
    }
    Ok(notes)
}

/// Records the exact closed entry before live memory can retire it. Only a
/// changed outcome writes: observing history cannot wake itself forever.
pub fn record_outcome(
    connection: &Connection,
    task: &str,
    project: &str,
    outcome: &str,
    closed_at_ms: u64,
) -> LedgerResult<()> {
    let at = i64::try_from(closed_at_ms)
        .map_err(|_| LedgerError::invalid_data("closed task timestamp exceeds i64".to_owned()))?;
    connection.execute(
        "INSERT INTO task_outcomes (task, project, outcome, closed_at_ms) \
         VALUES (?1, ?2, ?3, ?4) \
         ON CONFLICT(task, project) DO UPDATE SET outcome = excluded.outcome, \
           closed_at_ms = excluded.closed_at_ms, history_recorded = 0 \
         WHERE task_outcomes.outcome <> excluded.outcome",
        params![task, project, outcome, at],
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {

}
