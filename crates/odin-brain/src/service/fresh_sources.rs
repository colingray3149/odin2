//! The knowledge a fresh session starts from: the newest task notes pinned
//! in the ledger, `memory.project.*` pages in the seat's serving scope, and
//! `state.repos` summaries. Host-read. A missing source is stated, never
//! invented, and never silently dropped.

use odin_domain::ProjectId;

use super::{authority::KnowledgeSource, BrainService};
use crate::config::PROJECT_MEMORY_PREFIX;
use crate::error::BrainResult;

/// One note a seat pinned to a task.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GatheredNote {
    pub task: String,
    pub seat: String,
    pub noted_at: String,
    pub note: String,
}

/// One project-memory page.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GatheredMemory {
    pub source: String,
    pub text: String,
}

/// One repository observation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GatheredRepo {
    pub project: String,
    pub summary: String,
}

/// What the fresh brief is built from. `unavailable` names a source that
/// could not be read; the fields that were read stay.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct FreshKnowledge {
    pub notes: Vec<GatheredNote>,
    pub project_memory: Vec<GatheredMemory>,
    pub repos: Vec<GatheredRepo>,
    pub unavailable: Vec<String>,
}

/// The newest notes a fresh brief can show.
pub const NOTE_CAP: usize = 16;
const MEMORY_CAP: usize = 16;
const REPO_CAP: usize = 16;

impl BrainService {
    /// Reads the seat's task notes, project memory, and repository state
    /// for `project`. `None` reads every project the serving scope admits.
    /// A source the seat does not serve is absent, not an error.
    pub fn fresh_knowledge(&self, project: Option<&ProjectId>) -> BrainResult<FreshKnowledge> {
        let mut gathered = FreshKnowledge::default();
        let scope = self.policy.project_serving_scope(project);
        let mut notes_served = false;
        for (id, source) in &self.sources {
            if !scope.contains(id) {
                continue;
            }
            match source {
                KnowledgeSource::Memory(vault)
                    if id.as_str().starts_with(PROJECT_MEMORY_PREFIX) =>
                {
                    match vault.pin_scoped() {
                        Ok(pinned) => {
                            for page in pinned.pages().iter().filter(|page| page.withheld.is_none())
                            {
                                if gathered.project_memory.len() >= MEMORY_CAP {
                                    break;
                                }
                                gathered.project_memory.push(GatheredMemory {
                                    source: id.as_str().to_owned(),
                                    text: page.text.clone(),
                                });
                            }
                        }
                        Err(error) => {
                            gathered.unavailable.push(format!("{id}: {error}"));
                        }
                    }
                }
                KnowledgeSource::Tasks(_) | KnowledgeSource::History(_) => notes_served = true,
                KnowledgeSource::Repos(repos) => match repos.pin() {
                    Ok((_head, items)) => {
                        for item in items {
                            if gathered.repos.len() >= REPO_CAP {
                                break;
                            }
                            if project.is_some_and(|wanted| item.project.as_ref() != Some(wanted)) {
                                continue;
                            }
                            if !item.text.contains("branch") && !item.text.contains("head ") {
                                continue;
                            }
                            let project_name = item
                                .project
                                .as_ref()
                                .map(|id| id.as_str().to_owned())
                                .unwrap_or_else(|| item.item_id.to_string());
                            gathered.repos.push(GatheredRepo {
                                project: project_name,
                                summary: item.text,
                            });
                        }
                    }
                    Err(error) => gathered.unavailable.push(format!("state.repos: {error}")),
                },
                _ => {}
            }
        }
        if notes_served {
            match self.recent_notes(project) {
                Ok(notes) => gathered.notes = notes,
                Err(error) => gathered.unavailable.push(format!("task notes: {error}")),
            }
        }
        Ok(gathered)
    }

    /// The newest [`NOTE_CAP`] notes pinned in `project`, oldest first.
    fn recent_notes(&self, project: Option<&ProjectId>) -> BrainResult<Vec<GatheredNote>> {
        let ledger = self.ledger()?;
        let mut statement = ledger.connection().prepare_cached(
            "SELECT task, seat, noted_at, note FROM task_notes \
             WHERE ?1 IS NULL OR project = ?1 ORDER BY noted_at DESC, task DESC LIMIT ?2",
        )?;
        let mut notes = statement
            .query_map(
                rusqlite::params![project.map(ProjectId::as_str), NOTE_CAP as i64],
                |row| {
                    Ok(GatheredNote {
                        task: row.get(0)?,
                        seat: row.get(1)?,
                        noted_at: row.get(2)?,
                        note: row.get(3)?,
                    })
                },
            )?
            .collect::<Result<Vec<_>, _>>()?;
        notes.reverse();
        Ok(notes)
    }
}
