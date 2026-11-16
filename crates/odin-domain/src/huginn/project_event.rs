//! A project's own tooling reports an event it finished (a job done, a dataset registered); the paired device credential is the only authority.

use serde::{Deserialize, Serialize};

use crate::ProjectId;

pub const PROJECT_EVENT_KIND_MAX_CHARS: usize = 40;
pub const PROJECT_EVENT_KEY_MAX_CHARS: usize = 80;
pub const PROJECT_EVENT_DETAIL_MAX_BYTES: usize = 1_000;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProjectEventReport {
    pub project: ProjectId,
    /// What happened, one lowercase word like `job_done`.
    pub kind: String,
    /// Unique per occurrence on the reporting device; a retried report fires nothing new.
    pub key: String,
    /// One JSON value describing it, written by the project's tooling.
    pub detail: String,
}

impl ProjectEventReport {
    pub fn check(&self) -> Result<(), String> {
        let kind = &self.kind;
        if !kind.chars().next().is_some_and(|c| c.is_ascii_lowercase())
            || kind.chars().count() > PROJECT_EVENT_KIND_MAX_CHARS
            || !kind
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
        {
            return Err(format!(
                "a project event kind is 1..={PROJECT_EVENT_KIND_MAX_CHARS} characters of a-z, 0-9 and _, starting with a letter"
            ));
        }
        let key = &self.key;
        if key.is_empty()
            || key.chars().count() > PROJECT_EVENT_KEY_MAX_CHARS
            || !key
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | ':'))
        {
            return Err(format!(
                "a project event key is 1..={PROJECT_EVENT_KEY_MAX_CHARS} characters of A-Z, a-z, 0-9 and -_.:"
            ));
        }
        if self.detail.len() > PROJECT_EVENT_DETAIL_MAX_BYTES {
            return Err(format!(
                "a project event detail is at most {PROJECT_EVENT_DETAIL_MAX_BYTES} bytes"
            ));
        }
        serde_json::from_str::<serde_json::Value>(&self.detail)
            .map_err(|error| format!("a project event detail is one JSON value: {error}"))?;
        Ok(())
    }
}
