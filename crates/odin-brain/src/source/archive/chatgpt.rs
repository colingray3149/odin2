//! ChatGPT export parser: a zip archive read in place, never extracted.
//!
//! Conversations live in `conversations-*.json` entries (current exports
//! split the array across `conversations-000.json` ...); every matching
//! entry streams with a serde visitor, so at most one conversation is in
//! memory at a time and entry order is normalized, never trusted to zip
//! layout. A conversation is a parent-linked message *tree* (`mapping`)
//! with a declared `current_node`: the canonical thread is exactly the
//! current_node ancestor chain, walked through declared parent links —
//! never inferred from the first node. Alternate branches are counted as
//! structured provenance (branch-node count, per-message branch points,
//! parent links) and their bodies never become records.
//!
//! Broken ancestry is honest: an unknown `current_node`, a missing
//! ancestor, or a parent cycle truncates the chain at the break and is
//! counted in [`ArchiveStreamSummary::skip_reasons`]; the chain is never
//! healed by guessing a root. Conversations the export marks
//! `is_do_not_remember` are excluded by default through the declared
//! [`ArchiveSelectionPolicy::exclude_do_not_remember`] knob; a malformed
//! flag value is counted and never admitted, never coerced into `false`;
//! `is_archived` and `is_starred` are kept as provenance metadata. The
//! export's account identity comes from `user.json` and is never invented.
//!
//! Assets are metadata only: `*.dat` entries and
//! `conversation_asset_file_names.json` index declared filenames and
//! central-directory sizes, `library_files.json` entries become filename
//! records, and asset bodies are never read — not even buffered.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs::File;
use std::io::{BufReader, Read};

use odin_domain::knowledge::archive::ArchiveSourceDeclaration;
use serde::de::{SeqAccess, Visitor};
use serde::Deserialize;
use serde::Deserializer as _;
use time::OffsetDateTime;

use crate::error::{BrainError, BrainResult};
use crate::source::archive::{
    parse_timestamp, segment_and_deliver, since_skip_reason, ArchiveAssetOrigin, ArchiveProvenance,
    ArchiveRecord, ArchiveRecordKind, ArchiveStreamSummary,
};

/// Limit uncompressed entry bytes to reject decompression bombs.
const MAX_ENTRY_BYTES: u64 = 256 * 1024 * 1024;

const CONVERSATIONS_PREFIX: &str = "conversations-";
const USER_FILE: &str = "user.json";
const ASSET_NAMES_FILE: &str = "conversation_asset_file_names.json";
const LIBRARY_FILES_FILE: &str = "library_files.json";
const DAT_SUFFIX: &str = ".dat";

/// Export-scoped metadata resolved once per stream: the declared account
/// identity, real asset filenames, and asset sizes indexed from the zip
/// central directory. Bodies are never read.
struct StreamContext<'a> {
    since: Option<time::Date>,
    exclude_do_not_remember: bool,
    account: Option<&'a str>,
    asset_names: &'a HashMap<String, String>,
    asset_sizes: &'a HashMap<String, u64>,
    /// Exact `.dat` member names per asset stem, from the same central
    /// directory pass; the original binary locator for assets the export
    /// really ships.
    asset_members: &'a HashMap<String, Option<String>>,
}

/// One asset reference declared by a message (attachment entry or asset
/// pointer part), resolved against the export's own filename and size
/// indexes. Everything here is declared or central-directory fact.
struct AssetRef {
    id: String,
    name: String,
    size: Option<u64>,
    media: String,
}

pub(super) fn stream(
    declaration: &ArchiveSourceDeclaration,
    seen: &mut HashMap<String, String>,
    summary: &mut ArchiveStreamSummary,
    emit: &mut dyn FnMut(ArchiveRecord) -> BrainResult<()>,
) -> BrainResult<()> {
    let file = File::open(&declaration.path).map_err(|err| BrainError::Unavailable {
        component: "archive",
        reason: format!("cannot open {}: {err}", declaration.path.display()),
    })?;
    let mut archive =
        zip::ZipArchive::new(BufReader::new(file)).map_err(|err| BrainError::Unavailable {
            component: "archive",
            reason: format!(
                "{} is not a readable zip archive: {err}",
                declaration.path.display()
            ),
        })?;

    // One central-directory pass: conversation entry indices, auxiliary
    // metadata files, and asset sizes (metadata only; bodies never move).
    // Conversation entries are ordered by their declared numeric partition,
    // so record order is deterministic regardless of zip layout.
    let mut conversation_entries: Vec<(u64, String, usize)> = Vec::new();
    let mut user_index = None;
    let mut asset_names_index = None;
    let mut library_index = None;
    let mut asset_sizes: HashMap<String, u64> = HashMap::new();
    // Exact `.dat` member names per asset stem — the original binary
    // locator. UNIQUENESS, never first/last: a second DISTINCT-name
    // central-directory entry claiming an already-claimed stem marks it
    // ambiguous (counted) and drops BOTH the member and the
    // central-directory size (no bytes read or hashed to disambiguate);
    // the export's own declared attachment metadata stays the only
    // fallback. (Identical-name duplicates are a documented reader
    // limitation: the maintained zip reader's index coalesces
    // same-named entries to one before any parser sees them.)
    let mut asset_members: HashMap<String, Option<String>> = HashMap::new();
    for index in 0..archive.len() {
        let entry = archive
            .by_index(index)
            .map_err(|err| BrainError::Unavailable {
                component: "archive",
                reason: format!("cannot read zip entry {index}: {err}"),
            })?;
        let name = super::member_name(&entry)?;
        let base = name.rsplit('/').next().unwrap_or(&name);
        if let Some(rest) = base.strip_prefix(CONVERSATIONS_PREFIX) {
            if let Some(partition) = rest.strip_suffix(".json") {
                let order = partition.parse::<u64>().unwrap_or(u64::MAX);
                conversation_entries.push((order, base.to_owned(), index));
            }
        } else if base == USER_FILE {
            user_index = Some(index);
        } else if base == ASSET_NAMES_FILE {
            asset_names_index = Some(index);
        } else if base == LIBRARY_FILES_FILE {
            library_index = Some(index);
        }
        if let Some(stem) = base.strip_suffix(DAT_SUFFIX) {
            match asset_members.get_mut(stem) {
                None => {
                    asset_sizes.insert(stem.to_owned(), entry.size());
                    asset_members.insert(stem.to_owned(), Some(name.to_owned()));
                }
                Some(existing) => {
                    *existing = None;
                    asset_sizes.remove(stem);
                    summary.skip("ambiguous_asset_member");
                }
            }
        }
    }
    conversation_entries.sort();
    if conversation_entries.is_empty() {
        return Err(BrainError::Unavailable {
            component: "archive",
            reason: format!(
                "no {CONVERSATIONS_PREFIX}*.json entry found in {}",
                declaration.path.display()
            ),
        });
    }

    let account_id = match user_index {
        Some(index) => read_user_id(&mut archive, index)?,
        None => None,
    };
    let asset_names: HashMap<String, String> = match asset_names_index {
        Some(index) => serde_json::from_str(&read_entry(&mut archive, index)?)
            .map_err(BrainError::Serialization)?,
        None => HashMap::new(),
    };
    let mut excluded_conversations: HashSet<String> = HashSet::new();
    let context = StreamContext {
        since: declaration.selection.since,
        exclude_do_not_remember: declaration.selection.excludes_do_not_remember(),
        account: account_id.as_deref(),
        asset_names: &asset_names,
        asset_sizes: &asset_sizes,
        asset_members: &asset_members,
    };

    for (_, _, index) in conversation_entries {
        let entry = archive
            .by_index(index)
            .map_err(|err| BrainError::Unavailable {
                component: "archive",
                reason: format!("cannot open zip entry {index}: {err}"),
            })?;
        if entry.size() > MAX_ENTRY_BYTES {
            return Err(BrainError::Unavailable {
                component: "archive",
                reason: format!(
                    "zip entry {index} is {} bytes, exceeding the {MAX_ENTRY_BYTES} bound",
                    entry.size()
                ),
            });
        }
        let declared_in = super::member_name(&entry)?;
        let reader = BufReader::new(entry.take(MAX_ENTRY_BYTES));
        let mut deserializer = serde_json::Deserializer::from_reader(reader);
        let visitor = ConversationArray {
            seen: &mut *seen,
            summary: &mut *summary,
            emit: &mut *emit,
            ctx: &context,
            excluded: &mut excluded_conversations,
            declared_in,
        };
        deserializer
            .deserialize_seq(visitor)
            .map_err(BrainError::Serialization)?;
    }

    if let Some(index) = library_index {
        stream_library_files(
            &mut archive,
            index,
            &context,
            &excluded_conversations,
            seen,
            summary,
            emit,
        )?;
    }
    Ok(())
}

/// Reads one small UTF-8 JSON entry whole, under the entry-size bound.
fn read_entry(archive: &mut zip::ZipArchive<BufReader<File>>, index: usize) -> BrainResult<String> {
    let mut entry = archive
        .by_index(index)
        .map_err(|err| BrainError::Unavailable {
            component: "archive",
            reason: format!("cannot open zip entry {index}: {err}"),
        })?;
    if entry.size() > MAX_ENTRY_BYTES {
        return Err(BrainError::Unavailable {
            component: "archive",
            reason: format!(
                "zip entry {index} is {} bytes, exceeding the {MAX_ENTRY_BYTES} bound",
                entry.size()
            ),
        });
    }
    let mut text = String::with_capacity(entry.size() as usize);
    entry
        .read_to_string(&mut text)
        .map_err(|err| BrainError::Unavailable {
            component: "archive",
            reason: format!("cannot read zip entry {index}: {err}"),
        })?;
    Ok(text)
}

/// The declared account identity (`user.json` `id`); absent or empty
/// identities stay absent — identity is never invented.
fn read_user_id(
    archive: &mut zip::ZipArchive<BufReader<File>>,
    index: usize,
) -> BrainResult<Option<String>> {
    #[derive(Deserialize)]
    struct UserFile {
        #[serde(default)]
        id: Option<String>,
    }
    let user: UserFile =
        serde_json::from_str(&read_entry(archive, index)?).map_err(BrainError::Serialization)?;
    Ok(user
        .id
        .map(|id| id.trim().to_owned())
        .filter(|id| !id.is_empty()))
}

/// Streams the `library_files.json` array: one filename/size record per
/// declared library file, bodies never read. A malformed file fails the
/// stream typed rather than dropping declared metadata.
fn stream_library_files(
    archive: &mut zip::ZipArchive<BufReader<File>>,
    index: usize,
    context: &StreamContext,
    excluded_conversations: &HashSet<String>,
    seen: &mut HashMap<String, String>,
    summary: &mut ArchiveStreamSummary,
    emit: &mut dyn FnMut(ArchiveRecord) -> BrainResult<()>,
) -> BrainResult<()> {
    #[derive(Deserialize)]
    struct LibraryFile {
        #[serde(default)]
        file_id: Option<String>,
        #[serde(default)]
        file_name: Option<String>,
        #[serde(default)]
        file_size_bytes: Option<u64>,
        #[serde(default)]
        file_extension: Option<String>,
        #[serde(default)]
        created_at: Option<String>,
        #[serde(default)]
        initiating_conversation_id: Option<String>,
    }
    let declared_in =
        super::member_name(
            &archive
                .by_index(index)
                .map_err(|err| BrainError::Unavailable {
                    component: "archive",
                    reason: format!("cannot open zip entry {index}: {err}"),
                })?,
        )?;
    let files: Vec<LibraryFile> =
        serde_json::from_str(&read_entry(archive, index)?).map_err(BrainError::Serialization)?;
    for file in files {
        let Some(file_id) = file
            .file_id
            .as_deref()
            .map(str::trim)
            .filter(|id| !id.is_empty())
            .map(str::to_owned)
        else {
            summary.skip("library_file_unkeyed");
            continue;
        };
        let (created_at, raw_present) = match file.created_at.as_deref() {
            Some(raw) => (parse_timestamp(raw), true),
            None => (None, false),
        };
        if raw_present && created_at.is_none() {
            summary.skip("unparseable_timestamp");
        }
        // A library entry explicitly linked to a forget-flag-excluded
        // conversation is that conversation's metadata reaching in through
        // the side door: counted, never emitted. Unlinked entries, and
        // entries linked to admitted (or absent) conversations, stay.
        let linked = file
            .initiating_conversation_id
            .as_deref()
            .map(str::trim)
            .filter(|id| !id.is_empty());
        if linked.is_some_and(|id| excluded_conversations.contains(id)) {
            summary.skip("library_link_do_not_remember");
            continue;
        }
        let mut export_metadata = BTreeMap::new();
        export_metadata.insert(
            "library_file_id".to_owned(),
            serde_json::Value::from(file_id.as_str()),
        );
        if let Some(conversation) = linked {
            export_metadata.insert(
                "initiating_conversation_id".to_owned(),
                serde_json::Value::from(conversation),
            );
        }
        let name = file
            .file_name
            .as_deref()
            .filter(|name| !name.is_empty())
            .unwrap_or(&file_id);
        let size = file.file_size_bytes;
        let media = file
            .file_extension
            .as_deref()
            .filter(|ext| !ext.is_empty())
            .map(|ext| format!("application/x-chatgpt-library-{ext}"))
            .unwrap_or_else(|| "unknown".to_owned());
        let size_label = size
            .map(|size| size.to_string())
            .unwrap_or_else(|| "unknown".to_owned());
        segment_and_deliver(
            summary,
            seen,
            ArchiveRecord {
                natural_key: format!("library:{file_id}"),
                kind: ArchiveRecordKind::AssetMetadata,
                text: format!(
                    "uploaded asset: name={name} size_bytes={size_label} media_type={media}"
                ),
                provenance: ArchiveProvenance {
                    export_account: context.account.map(str::to_owned),
                    created_at,
                    export_metadata,
                    // Library records locate their declaration (the exact
                    // `library_files.json` member) and — only when the
                    // central directory carries a matching `.dat` entry —
                    // that member. Never the declared filename.
                    origin: Some(ArchiveAssetOrigin {
                        declared_in: Some(declared_in.clone()),
                        member: context.asset_members.get(&file_id).and_then(|m| m.clone()),
                        asset_id: Some(file_id),
                        ..ArchiveAssetOrigin::default()
                    }),
                    ..ArchiveProvenance::default()
                },
            },
            emit,
        )?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Conversation JSON shapes. Unknown fields are ignored: export builds add
// fields across releases, and only declared shapes are consumed.
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct ExportConversation {
    #[serde(default)]
    conversation_id: Option<String>,
    #[serde(default)]
    id: Option<String>,
    #[serde(default)]
    title: Option<String>,
    #[serde(default)]
    create_time: Option<f64>,
    #[serde(default)]
    update_time: Option<f64>,
    #[serde(default)]
    current_node: Option<String>,
    #[serde(default)]
    mapping: BTreeMap<String, MappingNode>,
    #[serde(default)]
    is_archived: Option<bool>,
    #[serde(default)]
    is_starred: Option<bool>,
    #[serde(default)]
    is_do_not_remember: Option<DoNotRemember>,
}

/// The export's forget flag, typed. `true` excludes by default, `false`
/// and a missing/null flag keep, and any other declared value is
/// malformed: counted, never admitted, never coerced into `false`.
#[derive(Deserialize)]
#[serde(untagged)]
enum DoNotRemember {
    Declared(bool),
    Malformed(serde_json::Value),
}

impl DoNotRemember {
    /// `Some(true)` only for a declared explicit `true`.
    fn declared_true(&self) -> bool {
        matches!(self, DoNotRemember::Declared(true))
    }

    /// `null` is the export's own not-flagged; anything non-boolean is a
    /// malformed typed value.
    fn malformed(&self) -> bool {
        match self {
            DoNotRemember::Declared(_) => false,
            DoNotRemember::Malformed(value) => !value.is_null(),
        }
    }
}

#[derive(Deserialize)]
struct MappingNode {
    /// `null` on structural ancestry nodes (the declared root); only nodes
    /// carrying a message are messages of the thread.
    #[serde(default)]
    message: Option<ExportMessage>,
    #[serde(default)]
    parent: Option<String>,
    // Some builds declare `children`; ancestry resolves through parent
    // links alone, so `children` is deliberately not declared and ignored.
}

#[derive(Deserialize)]
struct ExportMessage {
    #[serde(default)]
    id: Option<String>,
    #[serde(default)]
    author: Option<MessageAuthor>,
    #[serde(default)]
    content: Option<MessageContent>,
    #[serde(default)]
    create_time: Option<f64>,
    #[serde(default)]
    metadata: Option<MessageMetadata>,
}

#[derive(Deserialize)]
struct MessageAuthor {
    #[serde(default)]
    role: Option<String>,
}

#[derive(Deserialize)]
struct MessageContent {
    #[serde(default)]
    content_type: Option<String>,
    #[serde(default)]
    parts: Option<Vec<serde_json::Value>>,
    #[serde(default)]
    thoughts: Option<Vec<Thought>>,
    /// `reasoning_recap` recap text; a JSON value because export builds
    /// have shipped both strings and structured recaps.
    #[serde(default)]
    content: Option<serde_json::Value>,
    /// `code` block text.
    #[serde(default)]
    text: Option<String>,
    #[serde(default)]
    language: Option<String>,
}

#[derive(Deserialize)]
struct Thought {
    #[serde(default)]
    summary: Option<String>,
    #[serde(default)]
    content: Option<String>,
}

#[derive(Deserialize)]
struct MessageMetadata {
    #[serde(default)]
    model_slug: Option<String>,
    #[serde(default)]
    attachments: Option<Vec<ExportAttachment>>,
}

#[derive(Deserialize)]
struct ExportAttachment {
    #[serde(default)]
    id: Option<String>,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    size: Option<u64>,
    #[serde(default)]
    mime_type: Option<String>,
}

/// Streams one `conversations-*.json` array one conversation at a time.
struct ConversationArray<'a> {
    seen: &'a mut HashMap<String, String>,
    summary: &'a mut ArchiveStreamSummary,
    emit: &'a mut dyn FnMut(ArchiveRecord) -> BrainResult<()>,
    ctx: &'a StreamContext<'a>,
    /// Conversation ids the forget-flag excluded (declared `true`, or a
    /// malformed flag): their linked library entries are never emitted.
    excluded: &'a mut HashSet<String>,
    /// The exact zip member whose JSON array declared these conversations
    /// — the `declared_in` half of every asset locator below.
    declared_in: String,
}

impl<'a, 'de> Visitor<'de> for ConversationArray<'a> {
    type Value = ();

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str("a JSON array of ChatGPT export conversations")
    }

    fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        while let Some(conversation) = seq.next_element::<ExportConversation>()? {
            emit_conversation(
                self.ctx,
                &self.declared_in,
                conversation,
                self.excluded,
                self.seen,
                self.summary,
                self.emit,
            )
            .map_err(serde::de::Error::custom)?;
        }
        Ok(())
    }
}

fn emit_conversation(
    ctx: &StreamContext,
    declared_in: &str,
    conversation: ExportConversation,
    excluded: &mut HashSet<String>,
    seen: &mut HashMap<String, String>,
    summary: &mut ArchiveStreamSummary,
    emit: &mut dyn FnMut(ArchiveRecord) -> BrainResult<()>,
) -> BrainResult<()> {
    // The declared identity is resolved first so a flag-excluded
    // conversation can be remembered by id: nothing about it is emitted,
    // and its linked library entries are suppressed downstream.
    let declared_id = conversation
        .conversation_id
        .as_deref()
        .or(conversation.id.as_deref())
        .map(str::trim)
        .filter(|id| !id.is_empty());
    // The operator's own forget flag is honoured by default: an explicit
    // `true` excludes, `false` and a missing/null flag keep, and a
    // malformed typed value is counted and never admitted — it is never
    // coerced into `false`. Flipping the declared knob reads genuine
    // forgotten conversations back in with the flag recorded.
    if let Some(flag) = conversation.is_do_not_remember.as_ref() {
        let refused = flag.malformed();
        let excluded_by_flag = !refused && flag.declared_true() && ctx.exclude_do_not_remember;
        if refused || excluded_by_flag {
            summary.skip(if refused {
                "malformed_do_not_remember"
            } else {
                "excluded_do_not_remember"
            });
            if let Some(id) = declared_id {
                excluded.insert(id.to_owned());
            }
            return Ok(());
        }
    }
    let Some(conversation_id) = declared_id.map(str::to_owned) else {
        summary.skip("missing_conversation_id");
        return Ok(());
    };

    // Canonical thread: the declared current_node ancestor chain, walked
    // through parent links. Missing nodes and cycles truncate the chain
    // and are counted — the root is never inferred.
    let mut chain: Vec<&str> = Vec::new();
    let mut walked: HashSet<&str> = HashSet::new();
    let mut cursor = conversation
        .current_node
        .as_deref()
        .filter(|id| conversation.mapping.contains_key(*id));
    if cursor.is_none() {
        // Absent, null, or an id the mapping never carried: no declared
        // canonical thread exists, and none is inferred from the mapping.
        summary.skip("missing_current_node");
    }
    while let Some(node_id) = cursor {
        walked.insert(node_id);
        chain.push(node_id);
        let parent = conversation.mapping[node_id].parent.as_deref();
        cursor = match parent {
            None => None,
            Some(parent) if walked.contains(parent) => {
                summary.skip("ancestry_cycle");
                None
            }
            Some(parent) => match conversation.mapping.get(parent) {
                Some(_) => Some(parent),
                None => {
                    summary.skip("missing_ancestor");
                    None
                }
            },
        };
    }

    let mapping_node_count = conversation.mapping.len();
    let canonical_messages = chain
        .iter()
        .copied()
        .filter(|node_id| {
            conversation
                .mapping
                .get(*node_id)
                .and_then(|node| node.message.as_ref())
                .is_some()
        })
        .count();
    let branch_node_count = (mapping_node_count - chain.len()) as u64;
    // A message's parent carrying more than one declared child is a branch
    // point: the export forks there, and the fork bodies stay unrecorded.
    let mut parent_fanout: HashMap<&str, u64> = HashMap::new();
    for node in conversation.mapping.values() {
        if let Some(parent) = node.parent.as_deref() {
            *parent_fanout.entry(parent).or_default() += 1;
        }
    }

    let (created_at, raw_present) = match conversation.create_time {
        Some(seconds) => (parse_epoch_seconds(seconds), true),
        None => (None, false),
    };
    if raw_present && created_at.is_none() {
        summary.skip("unparseable_timestamp");
    }

    // The complete declared branch graph — current node, node and branch
    // counts, conversation flags — is conversation provenance, stored once
    // on the conversation and summary records, never cloned into every
    // message. Branch bodies are never preserved anywhere.
    let mut conversation_metadata = BTreeMap::new();
    if let Some(current_node) = conversation
        .current_node
        .as_deref()
        .filter(|id| !id.is_empty())
    {
        conversation_metadata.insert(
            "current_node".to_owned(),
            serde_json::Value::from(current_node),
        );
    }
    conversation_metadata.insert(
        "mapping_node_count".to_owned(),
        serde_json::Value::from(mapping_node_count as u64),
    );
    conversation_metadata.insert(
        "canonical_message_count".to_owned(),
        serde_json::Value::from(canonical_messages as u64),
    );
    conversation_metadata.insert(
        "branch_node_count".to_owned(),
        serde_json::Value::from(branch_node_count),
    );
    if let Some(flag) = conversation.is_archived {
        conversation_metadata.insert("is_archived".to_owned(), serde_json::Value::from(flag));
    }
    if let Some(flag) = conversation.is_starred {
        conversation_metadata.insert("is_starred".to_owned(), serde_json::Value::from(flag));
    }
    if conversation
        .is_do_not_remember
        .as_ref()
        .is_some_and(DoNotRemember::declared_true)
    {
        conversation_metadata.insert(
            "is_do_not_remember".to_owned(),
            serde_json::Value::from(true),
        );
    }
    let base = ArchiveProvenance {
        export_account: ctx.account.map(str::to_owned),
        conversation_id: Some(conversation_id.clone()),
        created_at,
        ..ArchiveProvenance::default()
    };

    // Conversation identity record: the export title, or a deterministic
    // derivation from the first canonical user message.
    let title = conversation
        .title
        .as_deref()
        .map(str::trim)
        .filter(|title| !title.is_empty())
        .map(str::to_owned)
        .unwrap_or_else(|| first_user_preview(&conversation, &chain));
    segment_and_deliver(
        summary,
        seen,
        ArchiveRecord {
            natural_key: conversation_id.clone(),
            kind: ArchiveRecordKind::Conversation,
            text: title.clone(),
            provenance: ArchiveProvenance {
                export_metadata: conversation_metadata.clone(),
                ..base.clone()
            },
        },
        emit,
    )?;

    // ChatGPT exports carry no per-conversation summary field; the
    // deterministic derived form is the norm, built only from counts,
    // timestamps, and message text — never model-invented facts.
    segment_and_deliver(
        summary,
        seen,
        ArchiveRecord {
            natural_key: format!("{conversation_id}:summary"),
            kind: ArchiveRecordKind::ConversationSummary,
            text: derived_summary(
                &conversation,
                &chain,
                &title,
                canonical_messages,
                branch_node_count,
            ),
            provenance: ArchiveProvenance {
                export_metadata: conversation_metadata,
                ..base.clone()
            },
        },
        emit,
    )?;

    // Canonical messages in thread order (root first). Alternate branches
    // are not here: their bodies are never duplicated as records.
    for node_id in chain.iter().rev() {
        let node = &conversation.mapping[*node_id];
        let Some(message) = node.message.as_ref() else {
            continue;
        };
        summary.messages_parsed += 1;

        let (body, part_assets) = message_body(message);
        let assets = resolve_assets(ctx, message, part_assets);
        let body = if body.trim().is_empty() {
            // Keep-all: a message whose export text is empty still carries
            // real identity and its declared attachment metadata, so it is
            // admitted as a metadata record — counted, never dropped.
            summary.skip("empty_body");
            let mut text = "[no text content]".to_owned();
            for asset in &assets {
                text.push_str(&format!(
                    "\n[attachment name={} size_bytes={} media_type={}]",
                    asset.name,
                    size_label(asset.size),
                    asset.media
                ));
            }
            text
        } else {
            body
        };
        let body = match (
            message
                .author
                .as_ref()
                .and_then(|author| author.role.as_deref()),
            message
                .metadata
                .as_ref()
                .and_then(|metadata| metadata.model_slug.as_deref())
                .filter(|slug| !slug.is_empty()),
        ) {
            (Some("assistant"), Some(model)) => format!("[model {model}]\n{body}"),
            _ => body,
        };

        let (created_at, raw_present) = match message.create_time {
            Some(seconds) => (parse_epoch_seconds(seconds), true),
            None => (None, false),
        };
        // Hard cutoff when declared: records without a usable timestamp
        // cannot be admitted under a declared cutoff. Without one,
        // keep-all preserves the record (an unparseable raw is counted
        // below and `created_at` stays `None`).
        if let Some(reason) = since_skip_reason(ctx.since, created_at, raw_present) {
            summary.skip(reason);
            continue;
        }
        if raw_present && created_at.is_none() {
            summary.skip("unparseable_timestamp");
        }

        let message_id = message
            .id
            .as_deref()
            .map(str::trim)
            .filter(|id| !id.is_empty())
            .map(str::to_owned)
            .unwrap_or_else(|| (*node_id).to_owned());
        // Per-message provenance carries only this node's own ancestry
        // facts; the branch graph lives once on the conversation records.
        let mut provenance_metadata = BTreeMap::new();
        provenance_metadata.insert("node_id".to_owned(), serde_json::Value::from(*node_id));
        provenance_metadata.insert(
            "parent_node".to_owned(),
            node.parent
                .as_deref()
                .map(serde_json::Value::from)
                .unwrap_or(serde_json::Value::Null),
        );
        let branch_point = node
            .parent
            .as_deref()
            .and_then(|parent| parent_fanout.get(parent).copied())
            .unwrap_or_default()
            > 1;
        provenance_metadata.insert(
            "branch_point".to_owned(),
            serde_json::Value::from(branch_point),
        );

        segment_and_deliver(
            summary,
            seen,
            ArchiveRecord {
                natural_key: format!("{conversation_id}:{node_id}"),
                kind: ArchiveRecordKind::Message,
                text: body,
                provenance: ArchiveProvenance {
                    message_id: Some(message_id.clone()),
                    created_at,
                    sent_by_user: message.author.as_ref().and_then(|a| a.role.as_deref())
                        == Some("user"),
                    export_metadata: provenance_metadata,
                    ..base.clone()
                },
            },
            emit,
        )?;

        for asset in &assets {
            deliver_asset(
                seen,
                summary,
                emit,
                ctx,
                &conversation_id,
                &message_id,
                asset,
                &base,
                declared_in,
            )?;
        }
    }
    Ok(())
}

/// One asset record: filename and declared size metadata only; bodies are
/// never read. Assets are conversation-scoped, so the same asset
/// referenced twice collapses through content addressing, never mutates.
/// The origin records the exact declaring member and — only when the
/// central directory UNIQUELY carries the asset's `.dat` entry — that
/// member; an ambiguous stem claims no member and no central-directory
/// size, and the declared filename is never claimed as a member.
#[allow(clippy::too_many_arguments)]
fn deliver_asset(
    seen: &mut HashMap<String, String>,
    summary: &mut ArchiveStreamSummary,
    emit: &mut dyn FnMut(ArchiveRecord) -> BrainResult<()>,
    ctx: &StreamContext,
    conversation_id: &str,
    message_id: &str,
    asset: &AssetRef,
    base: &ArchiveProvenance,
    declared_in: &str,
) -> BrainResult<()> {
    segment_and_deliver(
        summary,
        seen,
        ArchiveRecord {
            natural_key: format!("{conversation_id}:asset:{}", asset.id),
            kind: ArchiveRecordKind::AssetMetadata,
            text: format!(
                "uploaded asset: name={} size_bytes={} media_type={}",
                asset.name,
                size_label(asset.size),
                asset.media
            ),
            provenance: ArchiveProvenance {
                message_id: Some(message_id.to_owned()),
                origin: Some(ArchiveAssetOrigin {
                    declared_in: Some(declared_in.to_owned()),
                    member: ctx.asset_members.get(&asset.id).and_then(|m| m.clone()),
                    asset_id: Some(asset.id.clone()),
                    ..ArchiveAssetOrigin::default()
                }),
                ..base.clone()
            },
        },
        emit,
    )
}

fn size_label(size: Option<u64>) -> String {
    size.map(|size| size.to_string())
        .unwrap_or_else(|| "unknown".to_owned())
}

/// Resolves a message's declared assets (metadata attachments and asset
/// pointer parts) against the export's own filename index and the zip
/// central directory: names fall back through declaration, export index,
/// bare id; sizes prefer the archive's own central-directory fact.
fn resolve_assets(
    ctx: &StreamContext,
    message: &ExportMessage,
    part_assets: Vec<PartAsset>,
) -> Vec<AssetRef> {
    let mut assets: Vec<AssetRef> = Vec::new();
    for attachment in message
        .metadata
        .as_ref()
        .and_then(|metadata| metadata.attachments.as_deref())
        .into_iter()
        .flatten()
    {
        let Some(id) = attachment
            .id
            .as_deref()
            .or(attachment.name.as_deref())
            .map(plain_asset_id)
            .filter(|id| !id.is_empty())
            .map(str::to_owned)
        else {
            continue;
        };
        push_asset(
            ctx,
            &mut assets,
            id,
            attachment.name.as_deref(),
            attachment.size,
            attachment
                .mime_type
                .as_deref()
                .filter(|mime| !mime.is_empty())
                .unwrap_or("unknown")
                .to_owned(),
        );
    }
    for part in part_assets {
        push_asset(ctx, &mut assets, part.id, None, part.size, part.media);
    }
    assets
}

/// Names fall back through declaration, export index, bare id; sizes
/// prefer the archive's own central-directory fact.
fn push_asset(
    ctx: &StreamContext,
    assets: &mut Vec<AssetRef>,
    id: String,
    name: Option<&str>,
    size: Option<u64>,
    media: String,
) {
    let name = name
        .filter(|name| !name.is_empty())
        .or_else(|| ctx.asset_names.get(&id).map(String::as_str))
        .unwrap_or(&id)
        .to_owned();
    let size = ctx.asset_sizes.get(&id).copied().or(size);
    assets.push(AssetRef {
        id,
        name,
        size,
        media,
    });
}

/// An asset pointer part: the declared pointer id, size, and pointer kind.
struct PartAsset {
    id: String,
    size: Option<u64>,
    media: String,
}

/// Normalizes one chat message: text, reasoning thoughts and recaps, and
/// code blocks in full (keep-all — no truncation); asset pointer parts
/// become asset metadata, never bodies.
fn message_body(message: &ExportMessage) -> (String, Vec<PartAsset>) {
    let mut body = String::new();
    let mut assets: Vec<PartAsset> = Vec::new();
    let Some(content) = message.content.as_ref() else {
        return (body, assets);
    };
    match content.content_type.as_deref().unwrap_or("unknown") {
        "text" => {
            for part in content.parts.iter().flatten() {
                if let Some(text) = part.as_str() {
                    push_opt(&mut body, Some(text));
                }
            }
        }
        "multimodal_text" => {
            for part in content.parts.iter().flatten() {
                match part {
                    serde_json::Value::String(text) => push_opt(&mut body, Some(text)),
                    serde_json::Value::Object(fields) => {
                        match fields.get("asset_pointer").and_then(|p| p.as_str()) {
                            Some(pointer) => {
                                assets.push(PartAsset {
                                    id: plain_asset_id(pointer).to_owned(),
                                    size: fields.get("size_bytes").and_then(|s| s.as_u64()),
                                    media: fields
                                        .get("content_type")
                                        .and_then(|t| t.as_str())
                                        .unwrap_or("asset")
                                        .to_owned(),
                                });
                            }
                            None => {
                                // Textual parts without assets: audio
                                // transcriptions and future declared text.
                                if let Some(text) = fields.get("text").and_then(|t| t.as_str()) {
                                    push_opt(&mut body, Some(text));
                                }
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
        "thoughts" => {
            for thought in content.thoughts.iter().flatten() {
                push_opt(&mut body, thought.summary.as_deref());
                push_opt(&mut body, thought.content.as_deref());
            }
        }
        "reasoning_recap" => match content.content.as_ref() {
            Some(serde_json::Value::String(text)) => push_opt(&mut body, Some(text)),
            Some(other) if !other.is_null() => body.push_str(&other.to_string()),
            _ => {}
        },
        "code" => {
            let language = content
                .language
                .as_deref()
                .filter(|language| !language.is_empty())
                .unwrap_or("unknown");
            body.push_str(&format!("[code {language}] "));
            push_opt(&mut body, content.text.as_deref());
        }
        other => body.push_str(&format!("[unsupported content type: {other}]")),
    }
    (body, assets)
}

fn push_opt(body: &mut String, text: Option<&str>) {
    if let Some(text) = text {
        if !text.is_empty() {
            if !body.is_empty() {
                body.push('\n');
            }
            body.push_str(text);
        }
    }
}

/// The bare asset id declared by a pointer (`file-service://file-ABC`,
/// `sediment://...`) or a bare attachment id — the export ships both
/// forms, and the id is what the filename index and `.dat` entries key on.
fn plain_asset_id(pointer: &str) -> &str {
    match pointer.split_once("://") {
        Some((_, id)) => id,
        None => pointer,
    }
}

/// Deterministic derivation for a conversation with no export title: a
/// preview of the first canonical user message.
fn first_user_preview(conversation: &ExportConversation, chain: &[&str]) -> String {
    chain
        .iter()
        .rev()
        .filter_map(|node_id| conversation.mapping[*node_id].message.as_ref())
        .find(|message| {
            message
                .author
                .as_ref()
                .and_then(|author| author.role.as_deref())
                == Some("user")
        })
        .map(|message| {
            let (body, _) = message_body(message);
            let mut preview: String = body.chars().take(240).collect();
            if body.chars().count() > 240 {
                preview.push('…');
            }
            preview
        })
        .unwrap_or_else(|| "untitled conversation".to_owned())
}

/// Deterministic summary built only from the title, counts, timestamps,
/// and the first canonical user message — never model-invented facts.
fn derived_summary(
    conversation: &ExportConversation,
    chain: &[&str],
    title: &str,
    canonical_messages: usize,
    branch_node_count: u64,
) -> String {
    let range = match (conversation.create_time, conversation.update_time) {
        (Some(first), Some(last)) => format!("{} .. {}", format_epoch(first), format_epoch(last)),
        (Some(first), None) => format_epoch(first),
        _ => "unknown dates".to_owned(),
    };
    format!(
        "Export summary absent. Conversation '{title}': {canonical_messages} canonical \
         messages, {branch_node_count} branch nodes, {range}. First user message: {}",
        first_user_preview(conversation, chain)
    )
}

fn format_epoch(seconds: f64) -> String {
    parse_epoch_seconds(seconds)
        .map(|at| {
            at.format(&time::format_description::well_known::Rfc3339)
                .unwrap_or_default()
        })
        .unwrap_or_else(|| "unknown".to_owned())
}

/// Parses the export's Unix-epoch seconds (JSON numbers) into the typed
/// provenance form, keeping the declared sub-second precision. `None`
/// marks a value the calendar cannot carry; nothing is rounded into a
/// different instant and nothing is fabricated.
fn parse_epoch_seconds(seconds: f64) -> Option<OffsetDateTime> {
    if !seconds.is_finite() {
        return None;
    }
    let whole = seconds.trunc() as i64;
    let millis = ((seconds - seconds.trunc()) * 1000.0).round() as i64;
    OffsetDateTime::from_unix_timestamp(whole)
        .ok()
        .map(|at| at + time::Duration::milliseconds(millis))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::source::archive::{stream_archive, ArchiveStreamSummary};
    use odin_domain::knowledge::archive::{
        ArchiveDedupeKey, ArchiveFormat, ArchivePrivacyClass, ArchiveSelectionPolicy,
    };
    use std::io::Write as _;
    use time::macros::date;

    /// Fixture conversation epoch in seconds.
    const BASE: f64 = 1_788_256_800.0;

    fn policy(exclude_do_not_remember: Option<bool>) -> ArchiveSelectionPolicy {
        ArchiveSelectionPolicy {
            since: None,
            exclude_labels: Vec::new(),
            exclude_if_header: Vec::new(),
            keep_if_participant: false,
            participant_emails: Vec::new(),
            suspicious_rules: Vec::new(),
            exclude_do_not_remember,
        }
    }

    fn declaration(
        path: std::path::PathBuf,
        selection: ArchiveSelectionPolicy,
    ) -> ArchiveSourceDeclaration {
        ArchiveSourceDeclaration {
            format: ArchiveFormat::ChatGptExport,
            path,
            memory_namespace: "archive-test".to_owned(),
            privacy_class: ArchivePrivacyClass::Private,
            dedupe_key: ArchiveDedupeKey::ContentDigest,
            selection,
        }
    }

    fn collect(
        declaration: &ArchiveSourceDeclaration,
    ) -> (BrainResult<ArchiveStreamSummary>, Vec<ArchiveRecord>) {
        let mut records = Vec::new();
        let summary = {
            let mut emit = |record: ArchiveRecord| -> BrainResult<()> {
                records.push(record);
                Ok(())
            };
            stream_archive(declaration, &mut emit)
        };
        (summary, records)
    }

    fn node(parent: Option<&str>, message: Option<serde_json::Value>) -> serde_json::Value {
        serde_json::json!({ "message": message, "parent": parent })
    }

    fn text_message(role: &str, text: &str, create_time: f64) -> serde_json::Value {
        serde_json::json!({
            "author": {"role": role, "name": null},
            "content": {"content_type": "text", "parts": [text]},
            "create_time": create_time,
            "metadata": {}
        })
    }

    fn conversation(
        id: &str,
        title: &str,
        mapping: serde_json::Value,
        current_node: &str,
    ) -> serde_json::Value {
        serde_json::json!({
            "id": id,
            "conversation_id": id,
            "title": title,
            "create_time": BASE,
            "update_time": BASE,
            "current_node": current_node,
            "mapping": mapping,
            "is_archived": false,
            "is_starred": null,
            "is_do_not_remember": null
        })
    }

    /// Writes a synthetic export whose entries are all JSON values.
    fn export_zip(path: &std::path::Path, entries: &[(&str, serde_json::Value)]) {
        export_zip_raw(path, entries, &[]);
    }

    /// Writes a synthetic export: each named entry carries one JSON value
    /// (conversation arrays included); `raw` entries are byte-exact.
    fn export_zip_raw(
        path: &std::path::Path,
        entries: &[(&str, serde_json::Value)],
        raw: &[(&str, &str)],
    ) {
        let mut zip = zip::ZipWriter::new(std::fs::File::create(path).unwrap());
        let options = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Deflated);
        for (name, value) in entries {
            zip.start_file(*name, options).unwrap();
            zip.write_all(serde_json::to_vec(value).unwrap().as_slice())
                .unwrap();
        }
        for (name, bytes) in raw {
            zip.start_file(*name, options).unwrap();
            zip.write_all(bytes.as_bytes()).unwrap();
        }
        zip.finish().unwrap();
    }

    fn text_of(records: &[ArchiveRecord], natural_key: &str) -> String {
        records
            .iter()
            .find(|record| record.natural_key == natural_key)
            .unwrap_or_else(|| panic!("no record {natural_key}"))
            .text
            .clone()
    }

    fn metadata_of<'a>(
        records: &'a [ArchiveRecord],
        natural_key: &str,
    ) -> &'a BTreeMap<String, serde_json::Value> {
        &records
            .iter()
            .find(|record| record.natural_key == natural_key)
            .unwrap_or_else(|| panic!("no record {natural_key}"))
            .provenance
            .export_metadata
    }

    #[test]
    fn canonical_thread_is_the_declared_ancestry_never_the_branches() {
        let dir = tempfile::tempdir().unwrap();
        let zip_path = dir.path().join("export.zip");
        let branching = serde_json::json!({
            "root": node(None, None),
            "u1": node(Some("root"), Some(text_message("user", "first question", BASE + 1.0))),
            "a1": node(
                Some("u1"),
                Some(serde_json::json!({
                    "author": {"role": "assistant", "name": null},
                    "content": {"content_type": "text", "parts": ["first answer"]},
                    "create_time": BASE + 2.0,
                    "metadata": {"model_slug": "gpt-test"}
                }))
            ),
            "u2": node(Some("a1"), Some(text_message("user", "second question", BASE + 3.0))),
            "a2": node(Some("a1"), Some(text_message("assistant", "BRANCH ANSWER MUST NOT APPEAR", BASE + 4.0)))
        });
        export_zip(
            &zip_path,
            &[(
                "conversations-000.json",
                serde_json::json!([conversation("conv-1", "Branchy chat", branching, "u2")]),
            )],
        );
        let (summary, records) = collect(&declaration(zip_path, policy(None)));
        let summary = summary.unwrap();

        // Only the declared chain, in thread order; the sibling branch
        // body never becomes a record.
        let messages: Vec<&str> = records
            .iter()
            .filter(|record| record.kind == ArchiveRecordKind::Message)
            .map(|record| record.natural_key.as_str())
            .collect();
        assert_eq!(messages, ["conv-1:u1", "conv-1:a1", "conv-1:u2"]);
        assert!(records
            .iter()
            .all(|record| !record.text.contains("BRANCH ANSWER")));

        assert!(text_of(&records, "conv-1:a1").contains("[model gpt-test]"));
        assert!(text_of(&records, "conv-1:a1").contains("first answer"));
        assert!(
            records
                .iter()
                .find(|record| record.natural_key == "conv-1:u1")
                .unwrap()
                .provenance
                .sent_by_user
        );

        // The branch graph lives once on the conversation records.
        let graph = metadata_of(&records, "conv-1");
        assert_eq!(graph["current_node"], "u2");
        assert_eq!(graph["mapping_node_count"], 5);
        assert_eq!(graph["canonical_message_count"], 3);
        assert_eq!(graph["branch_node_count"], 1);
        assert_eq!(graph["is_archived"], false);
        assert!(metadata_of(&records, "conv-1:summary").contains_key("branch_node_count"));
        assert_eq!(graph.get("is_starred"), None);
        let u2 = records
            .iter()
            .find(|record| record.natural_key == "conv-1:u2")
            .unwrap();
        assert_eq!(u2.provenance.export_metadata["node_id"], "u2");
        assert_eq!(u2.provenance.export_metadata["branch_point"], true);
        let a1 = records
            .iter()
            .find(|record| record.natural_key == "conv-1:a1")
            .unwrap();
        assert_eq!(a1.provenance.export_metadata["parent_node"], "u1");
        assert_eq!(a1.provenance.export_metadata["branch_point"], false);

        assert!(text_of(&records, "conv-1:summary").contains("3 canonical messages"));
        assert_eq!(summary.records_emitted, records.len() as u64);
    }

    #[test]
    fn do_not_remember_is_excluded_by_default_and_opt_in() {
        let dir = tempfile::tempdir().unwrap();
        let zip_path = dir.path().join("export.zip");
        let keep = conversation(
            "conv-keep",
            "Kept",
            serde_json::json!({
                "n1": node(None, Some(text_message("user", "remembered content", BASE + 1.0)))
            }),
            "n1",
        );
        let mut forgotten = conversation(
            "conv-forgotten",
            "Forgotten",
            serde_json::json!({
                "n1": {"parent": null, "message": {
                    "id": "fn1",
                    "author": {"role": "user"},
                    "create_time": BASE + 1.0,
                    "content": {"content_type": "multimodal_text", "parts": [
                        {"content_type": "image_asset_pointer",
                         "asset_pointer": "file-service://file-FORGOTTEN",
                         "size_bytes": 10, "width": 1, "height": 1}
                    ]}
                }}
            }),
            "n1",
        );
        forgotten["is_do_not_remember"] = serde_json::json!(true);
        // A malformed typed flag is never admitted, never read as false —
        // under either knob state.
        let mut malformed = conversation(
            "conv-malformed",
            "Malformed flag",
            serde_json::json!({
                "n1": node(None, Some(text_message("user", "MALFORMED FLAG CONTENT", BASE + 1.0)))
            }),
            "n1",
        );
        malformed["is_do_not_remember"] = serde_json::json!("true");
        // Library entries explicitly linked to the forgotten conversation
        // are its metadata reaching in through the side door; unlinked and
        // kept-conversation links stay.
        let library = serde_json::json!([
            {
                "file_id": "file-link-forgotten",
                "file_name": "forgotten-artifact.png",
                "initiating_conversation_id": "conv-forgotten"
            },
            {
                "file_id": "file-link-kept",
                "file_name": "kept-artifact.png",
                "initiating_conversation_id": "conv-keep"
            },
            {"file_id": "file-standalone", "file_name": "standalone.png"}
        ]);
        export_zip_raw(
            &zip_path,
            &[
                (
                    "conversations-000.json",
                    serde_json::json!([keep, forgotten, malformed]),
                ),
                ("library_files.json", library),
            ],
            &[("file-FORGOTTEN.dat", "forgotten asset bytes never read")],
        );

        // Default: the export's own forget flag excludes the conversation.
        let (summary, records) = collect(&declaration(zip_path.clone(), policy(None)));
        let summary = summary.unwrap();
        assert_eq!(summary.skip_reasons["excluded_do_not_remember"], 1);
        assert_eq!(summary.skip_reasons["malformed_do_not_remember"], 1);
        assert_eq!(summary.skip_reasons["library_link_do_not_remember"], 1);
        assert!(records
            .iter()
            .all(|record| !record.text.contains("FORGOTTEN CONTENT")));
        assert!(records
            .iter()
            .all(|record| !record.text.contains("MALFORMED FLAG CONTENT")));
        assert!(records
            .iter()
            .all(|record| record.natural_key != "library:file-link-forgotten"));
        assert!(records
            .iter()
            .any(|record| record.natural_key == "library:file-link-kept"));
        assert!(records
            .iter()
            .any(|record| record.natural_key == "library:file-standalone"));
        assert!(records
            .iter()
            .any(|record| record.natural_key == "conv-keep"));
        // The forgotten conversation's locator-bearing asset metadata is
        // excluded with it, even though the `.dat` member exists in the
        // zip: exclusion covers locator metadata too.
        assert!(records
            .iter()
            .all(|record| !record.natural_key.starts_with("conv-forgotten:asset:")));
        assert!(records
            .iter()
            .all(|record| !record.natural_key.contains("file-FORGOTTEN")));

        // Opt-in: the declared knob reads the conversation back in, with
        // the flag recorded as metadata.
        let (summary, records) = collect(&declaration(zip_path, policy(Some(false))));
        let summary = summary.unwrap();
        assert!(!summary
            .skip_reasons
            .contains_key("excluded_do_not_remember"));
        assert_eq!(summary.skip_reasons["malformed_do_not_remember"], 1);
        assert!(!summary
            .skip_reasons
            .contains_key("library_link_do_not_remember"));
        assert!(records
            .iter()
            .any(|record| record.natural_key == "conv-forgotten:n1"));
        assert!(records
            .iter()
            .all(|record| !record.text.contains("MALFORMED FLAG CONTENT")));
        // Opted in, the forgotten conversation's library link is metadata
        // again, with the flag recorded on the conversation record.
        assert!(records
            .iter()
            .any(|record| record.natural_key == "library:file-link-forgotten"));
        assert_eq!(
            metadata_of(&records, "conv-forgotten")["is_do_not_remember"],
            true
        );
        // Opted in, the forgotten conversation's own asset locator is
        // metadata again: declaration member plus the exact `.dat` member
        // — never the pointer filename.
        let forgotten_asset = records
            .iter()
            .find(|record| record.natural_key == "conv-forgotten:asset:file-FORGOTTEN")
            .unwrap();
        let origin = forgotten_asset.provenance.origin.as_ref().unwrap();
        assert_eq!(origin.member.as_deref(), Some("file-FORGOTTEN.dat"));
        assert_eq!(origin.asset_id.as_deref(), Some("file-FORGOTTEN"));
    }

    #[test]
    fn malformed_ancestry_is_counted_and_never_healed() {
        let dir = tempfile::tempdir().unwrap();
        let zip_path = dir.path().join("export.zip");
        let missing_current = conversation(
            "conv-current",
            "Missing current",
            serde_json::json!({
                "n1": node(None, Some(text_message("user", "older message", BASE + 1.0)))
            }),
            "ghost",
        );
        let missing_parent = conversation(
            "conv-parent",
            "Missing parent",
            serde_json::json!({
                "m1": node(None, Some(text_message("user", "OLDER ANCESTOR", BASE + 1.0))),
                "m2": node(Some("gone"), Some(text_message("assistant", "newer message", BASE + 2.0)))
            }),
            "m2",
        );
        let cycle = conversation(
            "conv-cycle",
            "Cycle",
            serde_json::json!({
                "c1": node(Some("c2"), Some(text_message("user", "cycle one", BASE + 1.0))),
                "c2": node(Some("c1"), Some(text_message("assistant", "cycle two", BASE + 2.0)))
            }),
            "c1",
        );
        let unkeyed = serde_json::json!({
            "title": "No id",
            "current_node": "n1",
            "mapping": {"n1": node(None, Some(text_message("user", "orphaned identity", BASE + 1.0)))}
        });
        export_zip(
            &zip_path,
            &[(
                "conversations-000.json",
                serde_json::json!([missing_current, missing_parent, cycle, unkeyed]),
            )],
        );
        let (summary, records) = collect(&declaration(zip_path, policy(None)));
        let summary = summary.unwrap();

        // Every anomaly is counted; nothing is silently dropped or healed.
        assert_eq!(summary.skip_reasons["missing_current_node"], 1);
        assert_eq!(summary.skip_reasons["missing_ancestor"], 1);
        assert_eq!(summary.skip_reasons["ancestry_cycle"], 1);
        assert_eq!(summary.skip_reasons["missing_conversation_id"], 1);

        // Missing current_node: identity records survive, but the chain is
        // empty — the unwalked node is never promoted to a root.
        assert!(records
            .iter()
            .any(|record| record.natural_key == "conv-current"));
        assert!(records
            .iter()
            .all(|record| record.natural_key != "conv-current:n1"));
        assert_eq!(
            metadata_of(&records, "conv-current")["canonical_message_count"],
            0
        );

        // Missing ancestor: only the walkable chain suffix is admitted.
        assert!(records
            .iter()
            .any(|record| record.natural_key == "conv-parent:m2"));
        assert!(records
            .iter()
            .all(|record| !record.text.contains("OLDER ANCESTOR")));

        // Cycle: both declared ancestors are admitted; the walk terminates.
        assert!(records
            .iter()
            .any(|record| record.natural_key == "conv-cycle:c1"));
        assert!(records
            .iter()
            .any(|record| record.natural_key == "conv-cycle:c2"));

        assert_eq!(summary.records_emitted, records.len() as u64);
    }

    #[test]
    fn assets_and_library_files_are_metadata_only() {
        let dir = tempfile::tempdir().unwrap();
        let zip_path = dir.path().join("export.zip");
        let attachment = serde_json::json!({
            "n1": node(
                None,
                Some(serde_json::json!({
                    "author": {"role": "user", "name": null},
                    "content": {"content_type": "text", "parts": ["here is my file"]},
                    "create_time": BASE + 1.0,
                    "metadata": {"attachments": [{
                        "id": "file-ABC",
                        "name": "report.pdf",
                        "size": 777,
                        "mime_type": "application/pdf"
                    }]}
                }))
            ),
            "n2": node(
                Some("n1"),
                Some(serde_json::json!({
                    "author": {"role": "assistant", "name": null},
                    "content": {"content_type": "multimodal_text", "parts": [
                        "here is your image",
                        {"content_type": "image_asset_pointer", "asset_pointer": "file-service://file-IMG",
                         "size_bytes": 1234, "width": 64, "height": 64}
                    ]},
                    "create_time": BASE + 2.0,
                    "metadata": {}
                }))
            ),
            "n3": node(
                Some("n2"),
                Some(serde_json::json!({
                    "author": {"role": "assistant", "name": null},
                    "content": {"content_type": "text", "parts": [""]},
                    "create_time": BASE + 3.0,
                    "metadata": {"attachments": [{"id": "file-ABC", "mime_type": "application/pdf"}]}
                }))
            )
        });
        let library = serde_json::json!([{
            "file_id": "file-LIB",
            "file_name": "lib.png",
            "file_size_bytes": 99,
            "file_extension": "png",
            "created_at": "2026-09-01T00:00:00Z",
            "initiating_conversation_id": "conv-asset"
        }]);
        export_zip_raw(
            &zip_path,
            &[
                (
                    "conversations-000.json",
                    serde_json::json!([conversation("conv-asset", "Assets", attachment, "n3")]),
                ),
                (
                    "conversation_asset_file_names.json",
                    serde_json::json!({
                        "file-ABC": "quarterly-report.pdf",
                        "file-IMG": "dalle-image.png"
                    }),
                ),
                ("library_files.json", library),
                (
                    "user.json",
                    serde_json::json!({"id": "user-acc-1", "email": "x@y.z"}),
                ),
            ],
            &[
                ("file-ABC.dat", "RAW ASSET BYTES NEVER READ"),
                ("file-IMG.dat", "IMGRAW"),
            ],
        );
        let (summary, records) = collect(&declaration(zip_path, policy(None)));
        let summary = summary.unwrap();

        // Asset bodies never enter any record; the archive's own
        // central-directory size is the declared fact.
        assert!(records
            .iter()
            .all(|record| !record.text.contains("RAW ASSET BYTES")));
        assert!(records.iter().all(|record| !record.text.contains("IMGRAW")));
        let abc = text_of(&records, "conv-asset:asset:file-ABC");
        assert!(abc.contains("name=report.pdf"));
        assert!(abc.contains(&format!(
            "size_bytes={}",
            "RAW ASSET BYTES NEVER READ".len()
        )));
        assert!(abc.contains("media_type=application/pdf"));
        let img = text_of(&records, "conv-asset:asset:file-IMG");
        assert!(img.contains("name=dalle-image.png"));
        assert!(img.contains("media_type=image_asset_pointer"));

        // A non-empty message body never inlines asset metadata; the
        // image pointer is an asset record, not text.
        assert_eq!(text_of(&records, "conv-asset:n2"), "here is your image");

        // An empty body is admitted as identity plus attachment metadata.
        assert_eq!(summary.skip_reasons["empty_body"], 1);
        let empty = text_of(&records, "conv-asset:n3");
        assert!(empty.starts_with("[no text content]"));
        assert!(empty.contains("[attachment name=quarterly-report.pdf"));

        // The account identity comes from user.json and is never invented.
        assert_eq!(
            records
                .iter()
                .find(|record| record.natural_key == "conv-asset")
                .unwrap()
                .provenance
                .export_account
                .as_deref(),
            Some("user-acc-1")
        );

        // Library files are filename records with declared linkage.
        let library_record = records
            .iter()
            .find(|record| record.natural_key == "library:file-LIB")
            .unwrap();
        assert_eq!(library_record.kind, ArchiveRecordKind::AssetMetadata);
        assert!(library_record.text.contains("name=lib.png"));
        assert!(library_record.text.contains("size_bytes=99"));
        assert_eq!(
            library_record.provenance.export_metadata["initiating_conversation_id"],
            "conv-asset"
        );
        assert_eq!(
            library_record
                .provenance
                .created_at
                .unwrap()
                .unix_timestamp(),
            1_788_220_800
        );

        // The origin locator separates the declaration site from the
        // original bytes: the member is the exact `.dat` entry from the
        // central directory, never the declared filename.
        let abc_record = records
            .iter()
            .find(|record| record.natural_key == "conv-asset:asset:file-ABC")
            .unwrap();
        let abc_origin = abc_record.provenance.origin.as_ref().unwrap();
        assert_eq!(
            abc_origin.declared_in.as_deref(),
            Some("conversations-000.json")
        );
        assert_eq!(abc_origin.member.as_deref(), Some("file-ABC.dat"));
        assert_eq!(abc_origin.asset_id.as_deref(), Some("file-ABC"));
        let img_record = records
            .iter()
            .find(|record| record.natural_key == "conv-asset:asset:file-IMG")
            .unwrap();
        assert_eq!(
            img_record
                .provenance
                .origin
                .as_ref()
                .unwrap()
                .member
                .as_deref(),
            Some("file-IMG.dat")
        );
        // A library record locates its declaration and — when the export
        // carries a matching member — that member; otherwise no member is
        // claimed.
        let library_origin = library_record.provenance.origin.as_ref().unwrap();
        assert_eq!(
            library_origin.declared_in.as_deref(),
            Some("library_files.json")
        );
        assert_eq!(library_origin.member, None);
        assert_eq!(library_origin.asset_id.as_deref(), Some("file-LIB"));

        assert_eq!(summary.records_emitted, records.len() as u64);
    }

    #[test]
    fn ambiguous_dat_stem_claims_no_member_and_no_size() {
        let dir = tempfile::tempdir().unwrap();
        let zip_path = dir.path().join("export.zip");
        let attachment = serde_json::json!({
            "a1": node(None, Some(serde_json::json!({
                "author": {"role": "user", "name": null},
                "content": {"content_type": "multimodal_text", "parts": [
                    {"content_type": "image_asset_pointer",
                     "asset_pointer": "file-service://file-DUP",
                     "size_bytes": 77, "width": 1, "height": 1}
                ]},
                "create_time": BASE + 1.0,
                "metadata": {}
            })))
        });
        // TWO distinct members claim one stem: neither member nor
        // central-directory size may be claimed — the pointer's own
        // declared metadata is the only fallback. (IDENTICAL-name
        // duplicates are a documented reader limitation: the maintained
        // zip reader's index coalesces same-named entries to one before
        // any parser sees them, so identical-name ambiguity is not
        // observable here and is never claimed.)
        let conversations =
            serde_json::json!([conversation("conv-dup", "Duplicated", attachment, "a1")]);
        export_zip_raw(
            &zip_path,
            &[("conversations-000.json", conversations)],
            &[
                ("nested-a/file-DUP.dat", "bytes of unknown member a"),
                ("nested-b/file-DUP.dat", "bytes of unknown member b"),
            ],
        );
        let (summary, records) = collect(&declaration(zip_path, policy(None)));
        let summary = summary.unwrap();
        let asset = records
            .iter()
            .find(|record| record.natural_key == "conv-dup:asset:file-DUP")
            .unwrap();
        let origin = asset.provenance.origin.as_ref().unwrap();
        assert_eq!(origin.member, None);
        assert_eq!(origin.asset_id.as_deref(), Some("file-DUP"));
        assert_eq!(
            origin.declared_in.as_deref(),
            Some("conversations-000.json")
        );
        // The declared pointer size stands in; no central-directory size
        // was arbitrarily kept.
        assert!(asset.text.contains("size_bytes=77"));
        assert_eq!(summary.skip_reasons["ambiguous_asset_member"], 1);
    }

    #[test]
    fn partition_layout_and_repeats_keep_record_identity_stable() {
        let dir = tempfile::tempdir().unwrap();
        let turn = conversation(
            "conv-part",
            "Partitioned",
            serde_json::json!({
                "n1": node(None, Some(text_message("user", "same content", BASE + 1.0)))
            }),
            "n1",
        );
        let first = dir.path().join("first.zip");
        let second = dir.path().join("second.zip");
        export_zip(
            &first,
            &[
                ("conversations-000.json", serde_json::json!([turn])),
                ("user.json", serde_json::json!({"id": "user-acc-1"})),
            ],
        );
        export_zip(
            &second,
            &[
                ("conversations-007.json", serde_json::json!([turn])),
                ("user.json", serde_json::json!({"id": "user-acc-1"})),
            ],
        );

        // The same conversation under a different split-file partition
        // produces byte-identical records.
        let (_, first_records) = collect(&declaration(first, policy(None)));
        let (summary, second_records) = collect(&declaration(second, policy(None)));
        assert!(summary.unwrap().skip_reasons.is_empty());
        assert_eq!(first_records, second_records);

        // Repeating the identical conversation inside one stream collapses
        // every record into counted duplicates.
        let repeated = dir.path().join("repeated.zip");
        export_zip(
            &repeated,
            &[("conversations-000.json", serde_json::json!([turn, turn]))],
        );
        let (summary, _) = collect(&declaration(repeated, policy(None)));
        let summary = summary.unwrap();
        assert_eq!(summary.skip_reasons["duplicate_record"], 3);
        assert_eq!(summary.records_emitted, 3);
    }

    #[test]
    fn declared_cutoff_applies_to_messages_but_keeps_identity() {
        let dir = tempfile::tempdir().unwrap();
        let zip_path = dir.path().join("export.zip");
        let timed = conversation(
            "conv-since",
            "Timed",
            serde_json::json!({
                "n1": node(None, Some(text_message("user", "before cutoff", BASE + 1.0))),
                "n2": node(Some("n1"), Some(text_message("assistant", "after cutoff", 1_788_343_201.5))),
                "n3": node(Some("n2"), Some(serde_json::json!({
                    "author": {"role": "user", "name": null},
                    "content": {"content_type": "text", "parts": ["no timestamp"]},
                    "create_time": null,
                    "metadata": {}
                })))
            }),
            "n3",
        );
        export_zip(
            &zip_path,
            &[("conversations-000.json", serde_json::json!([timed]))],
        );
        let selection = ArchiveSelectionPolicy {
            since: Some(date!(2026 - 09 - 02)),
            ..policy(None)
        };
        let (summary, records) = collect(&declaration(zip_path, selection));
        let summary = summary.unwrap();

        assert_eq!(summary.skip_reasons["before_since"], 1);
        assert_eq!(summary.skip_reasons["date_missing"], 1);
        assert!(records
            .iter()
            .any(|record| record.natural_key == "conv-since"));
        // The pre-cutoff message record is gone; the derived summary may
        // still quote its preview, by declared keep-all rule.
        assert!(records
            .iter()
            .all(|record| record.natural_key != "conv-since:n1"));
        let admitted = records
            .iter()
            .find(|record| record.natural_key == "conv-since:n2")
            .unwrap();
        assert_eq!(
            admitted.provenance.created_at.unwrap().unix_timestamp(),
            1_788_343_201
        );
        assert_eq!(admitted.provenance.created_at.unwrap().millisecond(), 500);
    }

    #[test]
    fn conversation_identity_falls_back_to_the_declared_id() {
        let dir = tempfile::tempdir().unwrap();
        let zip_path = dir.path().join("export.zip");
        let mut identified = conversation(
            "conv-fallback",
            "Fallback",
            serde_json::json!({
                "n1": node(None, Some(text_message("user", "fallback content", BASE + 1.0)))
            }),
            "n1",
        );
        identified
            .as_object_mut()
            .unwrap()
            .remove("conversation_id");
        export_zip(
            &zip_path,
            &[("conversations-000.json", serde_json::json!([identified]))],
        );
        let (_, records) = collect(&declaration(zip_path, policy(None)));
        assert!(records
            .iter()
            .any(|record| record.natural_key == "conv-fallback"));
        assert!(records
            .iter()
            .any(|record| record.natural_key == "conv-fallback:n1"));
    }

    #[test]
    fn reasoning_and_code_content_normalize_in_full() {
        let dir = tempfile::tempdir().unwrap();
        let zip_path = dir.path().join("export.zip");
        let reasoned = conversation(
            "conv-mind",
            "Reasoning",
            serde_json::json!({
                "n1": node(None, Some(text_message("user", "think about it", BASE + 1.0))),
                "n2": node(Some("n1"), Some(serde_json::json!({
                    "author": {"role": "assistant", "name": null},
                    "content": {"content_type": "thoughts", "thoughts": [
                        {"summary": "weighing options", "content": "the RDE model says"}
                    ]},
                    "create_time": BASE + 2.0,
                    "metadata": {}
                }))),
                "n3": node(Some("n2"), Some(serde_json::json!({
                    "author": {"role": "assistant", "name": null},
                    "content": {"content_type": "reasoning_recap", "content": "settled on the nozzle"},
                    "create_time": BASE + 3.0,
                    "metadata": {}
                }))),
                "n4": node(Some("n3"), Some(serde_json::json!({
                    "author": {"role": "assistant", "name": null},
                    "content": {"content_type": "code", "language": "python", "text": "print(1)"},
                    "create_time": BASE + 4.0,
                    "metadata": {}
                })))
            }),
            "n4",
        );
        export_zip(
            &zip_path,
            &[("conversations-000.json", serde_json::json!([reasoned]))],
        );
        let (_, records) = collect(&declaration(zip_path, policy(None)));
        let thoughts = text_of(&records, "conv-mind:n2");
        assert!(thoughts.contains("weighing options"));
        assert!(thoughts.contains("the RDE model says"));
        assert!(text_of(&records, "conv-mind:n3").contains("settled on the nozzle"));
        let code = text_of(&records, "conv-mind:n4");
        assert!(code.contains("[code python]"));
        assert!(code.contains("print(1)"));
    }
}
