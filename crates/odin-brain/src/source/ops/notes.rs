//! The `ops.history` class of task notes: what seats pinned to a task with
//! `task.note`, attributed to the pinning session's recorded project.

use std::collections::BTreeMap;

use odin_domain::Digest;
use rusqlite::Transaction;

use super::{attribution_text, windowed_rows, Attribution, Material};
use crate::error::BrainResult;

const MAX_NOTES: usize = 4096;

/// The item identity `ops.history` files a task note under.
pub(crate) fn note_key(task: &str, seat: &str, noted_at: &str) -> String {
    format!("note/{task}/{seat}/{noted_at}")
}

/// One note a seat pinned to a task, under the pinning session's project.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct NoteRecord {
    task: String,
    seat: String,
    noted_at: String,
    note: String,
    pub(super) attribution: Attribution,
}

impl NoteRecord {
    pub(super) fn content_digest(&self) -> Digest {
        let mut material = Material::new(b"odin-brain:ops-note-record:v1\x00");
        material.str(&self.task);
        material.str(&self.seat);
        material.str(&self.noted_at);
        material.str(&self.note);
        material.str(&self.attribution.token());
        material.digest()
    }

    pub(super) fn key(&self) -> String {
        note_key(&self.task, &self.seat, &self.noted_at)
    }

    pub(super) fn text(&self) -> String {
        format!(
            "note on task {}\nby: {}\nnoted: {}\n{}\n{}",
            self.task,
            self.seat,
            self.noted_at,
            self.note,
            attribution_text(&self.attribution),
        )
    }
}

/// Reads the pinned task notes; a note's project is the one its session
/// recorded, and a recorded but invalid one is corrupt authority.
pub(super) fn read_notes(
    transaction: &Transaction<'_>,
    omitted: &mut BTreeMap<&'static str, u64>,
) -> BrainResult<Vec<NoteRecord>> {
    let rows = windowed_rows(
        transaction,
        omitted,
        "SELECT task, seat, project, noted_at, note FROM task_notes",
        "noted_at, task",
        MAX_NOTES,
        "task_notes",
        |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, Option<String>>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
            ))
        },
    )?;
    rows.into_iter()
        .map(|(task, seat, project, noted_at, note)| {
            let attribution = match project {
                Some(project) => {
                    super::project_attribution(&project, &format!("task note on {task}"))?
                }
                None => Attribution::Unscoped,
            };
            Ok(NoteRecord {
                task,
                seat,
                noted_at,
                note,
                attribution,
            })
        })
        .collect()
}

/// The exact closed live entry, durably recorded before it can retire.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct OutcomeRecord {
    pub(super) task: String,
    project: String,
    outcome: String,
    closed_at_ms: i64,
    result_summary: Option<String>,
    pub(super) attribution: Attribution,
}

impl OutcomeRecord {
    pub(super) fn key(&self) -> String {
        format!("outcome/{}/{}", self.project, self.task)
    }

    pub(super) fn text(&self) -> String {
        let mut text = format!(
            "outcome on task {}\nclosed at unix ms: {}\n{}\n{}",
            self.task,
            self.closed_at_ms,
            self.outcome,
            attribution_text(&self.attribution),
        );
        if let Some(summary) = &self.result_summary {
            text.push_str("\nrecorded session result:\n");
            text.push_str(summary);
        }
        text
    }

    pub(super) fn content_digest(&self) -> Digest {
        Digest::hash(self.text().as_bytes())
    }
}

pub(super) fn read_outcomes(
    transaction: &Transaction<'_>,
    omitted: &mut BTreeMap<&'static str, u64>,
) -> BrainResult<Vec<OutcomeRecord>> {
    windowed_rows(
        transaction,
        omitted,
        "SELECT task, project, outcome, closed_at_ms, \
           (SELECT json_extract(body_json, '$.payload.summary') FROM live_events \
            WHERE session_id = task_outcomes.task AND json_extract(body_json, '$.kind') = 'result' \
            ORDER BY sequence DESC LIMIT 1) \
         FROM task_outcomes",
        "closed_at_ms, project, task",
        MAX_NOTES,
        "task_outcomes",
        |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, i64>(3)?,
                row.get::<_, Option<String>>(4)?,
            ))
        },
    )?
    .into_iter()
    .map(|(task, project, outcome, closed_at_ms, result_summary)| {
        let attribution = super::project_attribution(&project, "task outcome project")?;
        Ok(OutcomeRecord {
            task,
            project,
            outcome,
            closed_at_ms,
            result_summary,
            attribution,
        })
    })
    .collect()
}
