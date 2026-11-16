//! What each injection put into a session's context: one JSON line per
//! injection, in `<state>/injected-context/<session>.jsonl` (directory 0700,
//! file 0600). A record names every block by label, its estimated tokens and
//! the record ids it carries. Each provider request adds a record with no
//! blocks: the sizes of its system prompt, tool definitions and injected
//! memory, and the hash of its system and tools, so a prefix that changed
//! between turns shows. The trace is removed with the session's capsule.
//! It lives beside the context root the sealed `context_read` tool reads, never
//! inside it, so no seat's model can read another session's injections.

use std::fs::{self, DirBuilder, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use odin_domain::huginn::LiveSessionId;
use odin_domain::Digest;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

/// The directory beneath the state root that holds one trace per session.
pub const DIR: &str = "injected-context";

/// What produced the record: a context epoch's opening, an owner turn's
/// per-turn tail, a rollover brief, a fresh supervisor brief, or a provider
/// request's measured prefix.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Kind {
    Epoch,
    Turn,
    Rollover,
    Fresh,
    Request,
}

/// One injected block: its label, the text sent, the record ids it carries.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Block {
    pub label: String,
    /// An estimate: characters divided by four, rounded up.
    pub tokens: u32,
    pub sources: Vec<String>,
    pub text: String,
}

impl Kind {
    /// The kind as the trace and the CLI spell it.
    pub fn label(self) -> &'static str {
        match self {
            Self::Epoch => "epoch",
            Self::Turn => "turn",
            Self::Rollover => "rollover",
            Self::Fresh => "fresh",
            Self::Request => "request",
        }
    }
}

impl Block {
    pub fn new(label: &str, text: &str, sources: Vec<String>) -> Self {
        Self {
            label: label.to_owned(),
            tokens: estimate(text),
            sources,
            text: text.to_owned(),
        }
    }
}

/// The estimated tokens of `text`: one per four characters, rounded up.
pub fn estimate(text: &str) -> u32 {
    u32::try_from(text.chars().count().div_ceil(4)).unwrap_or(u32::MAX)
}

/// What a provider request carried ahead of the conversation, summed from the
/// blocks the harness extension stored for it. The provider reuses its cached
/// prefix while `hash` is the same from one request to the next.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Prefix {
    /// Serialized bytes of the system prompt.
    pub system_bytes: u64,
    /// Serialized bytes of the tool definitions.
    pub tool_bytes: u64,
    /// Serialized bytes of the memory this request added to the conversation.
    pub injected_bytes: u64,
    /// The digest of the system and tool blocks' own digests.
    pub hash: Digest,
    /// What the request carried and what the provider reported for it,
    /// where the harness knows: the lane served, the bytes of conversation
    /// history and of tool results in it, and the provider's prompt and
    /// cached prompt tokens.
    #[serde(default, flatten)]
    pub measured: Measured,
}

/// A request's measured history and the provider's own token counts.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct Measured {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lane: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub history_bytes: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_result_bytes: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prompt_tokens: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cached_tokens: Option<u64>,
}

impl Prefix {
    /// The prefix of one stored request, or `None` when a block carries no
    /// size (the session still runs the extension from before sizes were
    /// stored). `blocks` are its `{role, sha256, bytes}` entries: system and
    /// guidance (system messages) and tools are the stable prefix, memory is
    /// what the request injected, history is neither.
    pub fn of(blocks: &[Value]) -> Option<Self> {
        let (mut system, mut tools, mut injected) = (0, 0, 0);
        let mut stable = String::new();
        for block in blocks {
            let role = block["role"].as_str().unwrap_or_default();
            if !matches!(role, "system" | "guidance" | "tools" | "memory") {
                continue;
            }
            let bytes = block["bytes"].as_u64()?;
            match role {
                "memory" => injected += bytes,
                "tools" => tools += bytes,
                _ => system += bytes,
            }
            if role != "memory" {
                stable.push_str(block["sha256"].as_str()?);
                stable.push('\n');
            }
        }
        Some(Self {
            system_bytes: system,
            tool_bytes: tools,
            injected_bytes: injected,
            hash: Digest::hash(stable.as_bytes()),
            measured: Measured::default(),
        })
    }
}

/// One line of a trace: when the injection was sent and what it carried.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Record {
    pub at: String,
    pub turn: Option<u64>,
    pub kind: Kind,
    pub blocks: Vec<Block>,
    /// Set on a request record, which names no blocks.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prefix: Option<Prefix>,
}

/// The trace directory beneath a state root.
pub fn root(state_root: &Path) -> PathBuf {
    state_root.join(DIR)
}

fn file(root: &Path, session: LiveSessionId) -> PathBuf {
    root.join(format!("{session}.jsonl"))
}

/// Appends one record of `blocks` to the session's trace.
pub fn record(
    root: &Path,
    session: LiveSessionId,
    kind: Kind,
    turn: Option<u64>,
    blocks: &[Block],
) -> Result<(), String> {
    append(root, session, kind, turn, blocks.to_vec(), None)
}

/// Appends one provider request's measured prefix to the session's trace.
pub fn record_request(root: &Path, session: LiveSessionId, prefix: Prefix) -> Result<(), String> {
    append(root, session, Kind::Request, None, Vec::new(), Some(prefix))
}

fn append(
    root: &Path,
    session: LiveSessionId,
    kind: Kind,
    turn: Option<u64>,
    blocks: Vec<Block>,
    prefix: Option<Prefix>,
) -> Result<(), String> {
    let at = OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .map_err(|error| format!("injected context time: {error}"))?;
    let mut line = serde_json::to_vec(&Record {
        at,
        turn,
        kind,
        blocks,
        prefix,
    })
    .map_err(|error| format!("injected context encode: {error}"))?;
    line.push(b'\n');
    DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(root)
        .map_err(|error| format!("injected context directory {}: {error}", root.display()))?;
    let path = file(root, session);
    let mut handle = OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .open(&path)
        .map_err(|error| format!("injected context {}: {error}", path.display()))?;
    handle
        .write_all(&line)
        .map_err(|error| format!("injected context {} write: {error}", path.display()))
}

/// Every record of `session` in order; `None` when none was recorded here.
pub fn read(root: &Path, session: LiveSessionId) -> Result<Option<Vec<Record>>, String> {
    let path = file(root, session);
    let text = match fs::read_to_string(&path) {
        Ok(text) => text,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(format!("injected context {}: {error}", path.display())),
    };
    text.lines()
        .map(|line| {
            serde_json::from_str(line).map_err(|error| {
                format!(
                    "injected context {} has an unreadable line: {error}",
                    path.display()
                )
            })
        })
        .collect::<Result<Vec<Record>, String>>()
        .map(Some)
}

/// Deletes the session's trace; a missing trace is not an error.
pub fn remove(root: &Path, session: LiveSessionId) -> io::Result<()> {
    match fs::remove_file(file(root, session)) {
        Err(error) if error.kind() != io::ErrorKind::NotFound => Err(error),
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    const SESSION: &str = "00000000-0000-4000-8000-000000000001";

    #[test]
    fn an_injection_with_two_blocks_writes_one_record_naming_both() {
        let state = tempfile::tempdir().expect("state root");
        let root = root(state.path());
        let session = LiveSessionId::parse(SESSION).expect("session");
        let blocks = [
            Block::new("live memory", "sixteen chars!!!", Vec::new()),
            Block::new(
                "named records",
                "person Ada: pilot",
                vec!["person:Ada".into()],
            ),
        ];
        record(&root, session, Kind::Turn, None, &blocks).expect("record");
        let records = read(&root, session).expect("read").expect("a trace");
        assert_eq!(records.len(), 1);
        let labels: Vec<&str> = records[0].blocks.iter().map(|b| b.label.as_str()).collect();
        assert_eq!(labels, ["live memory", "named records"]);
        assert_eq!(records[0].blocks[0].tokens, 4);
        assert_eq!(records[0].blocks[1].sources, ["person:Ada"]);
        let mode = fs::metadata(file(&root, session))
            .expect("trace file")
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
    }
}
