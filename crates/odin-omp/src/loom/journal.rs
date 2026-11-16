//! Loom's own session journal: one append-only JSONL file per session. The
//! journal is the truth; every request is rendered from it (and the ledger).
//! Opening or resuming a session is reading this file.

use std::fs::{self, DirBuilder, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// One model tool call exactly as the provider sent it.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Call {
    pub id: String,
    pub name: String,
    /// The raw JSON arguments text.
    pub arguments: String,
    /// Opaque per-call provider fields (Gemini's thought signature), sent back verbatim.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub opaque: Option<Value>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Entry {
    /// A fresh context epoch: a model switch, restart or clear. Nothing is
    /// lost; the provider cache key changes.
    Epoch { epoch: u64, model: String },
    /// The turn's message as the model reads it.
    User { turn: u64, side: bool, text: String },
    /// One model round.
    Assistant {
        turn: u64,
        side: bool,
        text: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        reasoning: Option<String>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        calls: Vec<Call>,
        /// Opaque message-level provider fields, sent back verbatim.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        opaque: Option<Value>,
    },
    /// One tool result. `text` is what the model saw in its own turn;
    /// `digest` replaces it in later requests when set.
    Result {
        turn: u64,
        side: bool,
        call_id: String,
        tool: String,
        text: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        digest: Option<String>,
        is_error: bool,
    },
    /// The turn ended: its reply, or why it stopped.
    Settled {
        turn: u64,
        side: bool,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        reply: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        failure: Option<String>,
        /// Refused over the turn budget: the turn leaves no trace in the
        /// window or the summary, so it cannot refuse the turns after it.
        #[serde(default, skip_serializing_if = "std::ops::Not::not")]
        dropped: bool,
    },
    /// A side turn's reply that reached the owner: the one thing it adds
    /// to the main window.
    Posted { turn: u64, text: String },
    /// Compaction: the model-written notes now cover every exchange up to
    /// and including `upto`.
    Notes { upto: u64, text: String },
    /// Exchanges up to `upto` left the window without a fold.
    Truncated { upto: u64 },
}

impl Entry {
    pub fn turn(&self) -> Option<u64> {
        match self {
            Self::User { turn, .. }
            | Self::Assistant { turn, .. }
            | Self::Result { turn, .. }
            | Self::Settled { turn, .. }
            | Self::Posted { turn, .. } => Some(*turn),
            _ => None,
        }
    }

    pub fn side(&self) -> bool {
        match self {
            Self::User { side, .. }
            | Self::Assistant { side, .. }
            | Self::Result { side, .. }
            | Self::Settled { side, .. } => *side,
            _ => false,
        }
    }
}

pub struct Journal {
    path: PathBuf,
    pub entries: Vec<Entry>,
}

impl Journal {
    /// Reads (or starts) the session's journal under `root`.
    pub fn open(root: &Path, session: &str) -> Result<Self, String> {
        DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(root)
            .map_err(|error| format!("loom journal directory {}: {error}", root.display()))?;
        let path = root.join(format!("{session}.jsonl"));
        let text = match fs::read_to_string(&path) {
            Ok(text) => text,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => String::new(),
            Err(error) => return Err(format!("loom journal {}: {error}", path.display())),
        };
        let mut entries = Vec::new();
        let mut kept = 0;
        let lines: Vec<&str> = text.split_inclusive('\n').collect();
        for (index, line) in lines.iter().enumerate() {
            if line.trim().is_empty() {
                kept += line.len();
                continue;
            }
            let last = index + 1 == lines.len();
            match serde_json::from_str::<Entry>(line) {
                Ok(entry) if line.ends_with('\n') => {
                    entries.push(entry);
                    kept += line.len();
                }
                Err(error) if !last => {
                    return Err(format!(
                        "loom journal {} has an unreadable line {}: {error}",
                        path.display(),
                        index + 1
                    ))
                }
                // A torn last line is the write a crash cut short: drop it.
                _ => {
                    tracing::warn!(
                        "odind: loom journal {} ends in a torn line ({} bytes); truncating it",
                        path.display(),
                        line.len()
                    );
                    OpenOptions::new()
                        .write(true)
                        .open(&path)
                        .and_then(|file| file.set_len(kept as u64))
                        .map_err(|error| {
                            format!("loom journal {} truncate: {error}", path.display())
                        })?;
                }
            }
        }
        Ok(Self { path, entries })
    }

    pub fn append(&mut self, entry: Entry) -> Result<(), String> {
        let mut line =
            serde_json::to_vec(&entry).map_err(|error| format!("loom journal encode: {error}"))?;
        line.push(b'\n');
        OpenOptions::new()
            .create(true)
            .append(true)
            .mode(0o600)
            .open(&self.path)
            .and_then(|mut file| file.write_all(&line))
            .map_err(|error| format!("loom journal {}: {error}", self.path.display()))?;
        self.entries.push(entry);
        Ok(())
    }

    /// Flushes the journal to disk; a settled turn survives a crash.
    pub fn sync(&self) -> Result<(), String> {
        fs::File::open(&self.path)
            .and_then(|file| file.sync_all())
            .map_err(|error| format!("loom journal {} sync: {error}", self.path.display()))
    }

    /// The next turn number.
    pub fn next_turn(&self) -> u64 {
        self.entries
            .iter()
            .filter_map(Entry::turn)
            .max()
            .map_or(1, |turn| turn + 1)
    }

    /// The current context epoch.
    pub fn epoch(&self) -> u64 {
        self.entries
            .iter()
            .rev()
            .find_map(|entry| match entry {
                Entry::Epoch { epoch, .. } => Some(*epoch),
                _ => None,
            })
            .unwrap_or(0)
    }

    /// The model-written notes and the last turn they (or a truncation) cover.
    pub fn notes(&self) -> (&str, u64) {
        let mut notes = "";
        let mut upto = 0;
        for entry in &self.entries {
            match entry {
                Entry::Notes { upto: at, text } => {
                    notes = text;
                    upto = upto.max(*at);
                }
                Entry::Truncated { upto: at } => upto = upto.max(*at),
                _ => {}
            }
        }
        (notes, upto)
    }
}
