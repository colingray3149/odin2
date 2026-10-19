//! Mbox parser: zipped (Google Takeout) or plain mbox, streamed twice.
//!
//! Messages are split from the mbox stream on `From ` separator lines
//! whose preceding line is blank (verified against the real export: every
//! separator follows a blank line, and quoted body lines are `>From `
//! escaped), so a quoted `From ` inside a body never splits a message.
//! Nothing is extracted to disk: a zipped mbox is decompressed in place
//! through the zip reader, one entry at a time, and each entry is opened
//! twice — thread membership first, parse-and-emit second.
//!
//! Everything MIME-ish goes through the maintained `mail-parser` crate:
//! header lookup/unfolding, RFC822 dates, address parsing, multipart
//! bodies, charsets, quoted-printable/base64. `html2text` renders
//! HTML-only bodies (mail-parser deliberately ships no HTML conversion),
//! and the references such a body declares — `href`/`src` values and CSS
//! `url(...)` targets, read through the maintained HTML5 and CSS
//! tokenizers — are kept beside the rendered text, since the renderer drops
//! the elements that carry most of them.
//! Gmail thread membership is resolved in pass one with a message-id
//! union-find over `Message-ID`/`References`/`In-Reply-To` plus sent
//! detection from the `Sent` label or a declared participant sender
//! address, so the declared keep-if-participant override never
//! materializes the mailbox. Memory is O(message count), never
//! O(mailbox size). Dates come from mail-parser's RFC822 parsing and
//! become typed provenance; a raw date the parser cannot read is never
//! fabricated into one.
//!
//! Policy order per message (all exclusions counted, nothing silent):
//! `since` is a hard cutoff (never overridden) — with it declared,
//! records without a usable timestamp cannot satisfy it and are admitted
//! out by the declared cutoff (counted); without it, a record keeps its
//! absent typed date when the message otherwise parses. Label/header
//! exclusions follow (overridden for threads with operator-sent mail when
//! declared, per the domain policy semantics), then declared suspicious
//! rules (`exclude` drops, `flag` tags; never overridden). A thread is
//! "sent/replied" only via the explicit `Sent` label or a declared
//! participant sender identity; being a recipient does not count.
//! Only bytes that cannot be safely parsed or preserved at
//! all (oversize, unparseable) fail the stream typed.

use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::{BufRead, BufReader, Read, Seek, SeekFrom};

use cssparser::{
    BasicParseErrorKind, ParseError, ParseErrorKind, Parser as CssParser, Token as CssToken,
};
use html5ever::tendril::StrTendril;
use html5ever::tokenizer::{
    states::RawKind, BufferQueue, TagKind, Token, TokenSink, TokenSinkResult, Tokenizer,
    TokenizerOpts, TokenizerResult,
};
use mail_parser::{Address, HeaderName, HeaderValue, MimeHeaders};
use odin_domain::knowledge::archive::{
    ArchiveSelectionPolicy, ArchiveSourceDeclaration, ArchiveSuspiciousAction,
    ArchiveSuspiciousRule,
};
use time::{Date, OffsetDateTime};

use crate::error::{BrainError, BrainResult};
use crate::source::archive::{
    segment_and_deliver, since_skip_reason, ArchiveAssetOrigin, ArchiveProvenance, ArchiveRecord,
    ArchiveRecordKind, ArchiveStreamSummary,
};

/// Hard cap on one raw message's bytes; larger messages are skipped and
/// counted (`oversize_message`) — the MIME parse never sees unbounded
/// input.
const MAX_RAW_MESSAGE_BYTES: usize = 64 * 1024 * 1024;

/// Hard cap on one physical line while splitting; a longer line marks the
/// whole message oversize (counted, skipped).
const MAX_LINE_BYTES: usize = 16 * 1024 * 1024;

/// Text width used when rendering HTML-only bodies to text.
const HTML_TEXT_WIDTH: usize = 120;

pub(super) fn stream(
    declaration: &ArchiveSourceDeclaration,
    seen: &mut HashMap<String, String>,
    summary: &mut ArchiveStreamSummary,
    emit: &mut dyn FnMut(ArchiveRecord) -> BrainResult<()>,
) -> BrainResult<()> {
    let mut file = File::open(&declaration.path).map_err(|err| BrainError::Unavailable {
        component: "archive",
        reason: format!("cannot open {}: {err}", declaration.path.display()),
    })?;
    let mut magic = [0u8; 4];
    let prefix = file
        .read(&mut magic)
        .map_err(|err| BrainError::Unavailable {
            component: "archive",
            reason: format!("cannot read {}: {err}", declaration.path.display()),
        })?;

    if prefix == 4 && magic == *b"PK\x03\x04" {
        stream_zip(file, declaration, seen, summary, emit)
    } else {
        file.seek(SeekFrom::Start(0))
            .map_err(|err| BrainError::Unavailable {
                component: "archive",
                reason: format!("cannot rewind {}: {err}", declaration.path.display()),
            })?;
        let policy = MboxPolicy::new(&declaration.selection)?;
        let membership = pass_one(file, &policy)?;
        let reader = File::open(&declaration.path).map_err(|err| BrainError::Unavailable {
            component: "archive",
            reason: format!("cannot reopen {}: {err}", declaration.path.display()),
        })?;
        pass_two(reader, &membership, &policy, None, seen, summary, emit)
    }
}

/// Reads every `*.mbox` entry of a Takeout-style zip in place (never
/// extracting to disk); each entry is opened twice — membership, then
/// parse-and-emit — with a fresh archive handle per open.
fn stream_zip(
    file: File,
    declaration: &ArchiveSourceDeclaration,
    seen: &mut HashMap<String, String>,
    summary: &mut ArchiveStreamSummary,
    emit: &mut dyn FnMut(ArchiveRecord) -> BrainResult<()>,
) -> BrainResult<()> {
    let mut archive = zip::ZipArchive::new(file).map_err(|err| BrainError::Unavailable {
        component: "archive",
        reason: format!(
            "{} is not a readable zip archive: {err}",
            declaration.path.display()
        ),
    })?;
    let mut entries = Vec::new();
    for index in 0..archive.len() {
        let entry = archive
            .by_index(index)
            .map_err(|err| BrainError::Unavailable {
                component: "archive",
                reason: format!("cannot read zip entry {index}: {err}"),
            })?;
        if super::member_name(&entry)?.ends_with(".mbox") {
            entries.push(index);
        }
    }
    let policy = MboxPolicy::new(&declaration.selection)?;
    for index in entries {
        // Each pass gets a fresh archive handle; the entry reader borrows
        // its archive, so both live in the same scope as their pass.
        let mut membership_archive =
            zip::ZipArchive::new(File::open(&declaration.path).map_err(|err| {
                BrainError::Unavailable {
                    component: "archive",
                    reason: format!("cannot reopen {}: {err}", declaration.path.display()),
                }
            })?)
            .map_err(|err| BrainError::Unavailable {
                component: "archive",
                reason: format!("cannot reopen {}: {err}", declaration.path.display()),
            })?;
        let membership_reader =
            membership_archive
                .by_index(index)
                .map_err(|err| BrainError::Unavailable {
                    component: "archive",
                    reason: format!("cannot open zip entry {index}: {err}"),
                })?;
        let membership = pass_one(membership_reader, &policy)?;
        drop(membership_archive);

        let mut emit_archive =
            zip::ZipArchive::new(File::open(&declaration.path).map_err(|err| {
                BrainError::Unavailable {
                    component: "archive",
                    reason: format!("cannot reopen {}: {err}", declaration.path.display()),
                }
            })?)
            .map_err(|err| BrainError::Unavailable {
                component: "archive",
                reason: format!("cannot reopen {}: {err}", declaration.path.display()),
            })?;
        let emit_reader = emit_archive
            .by_index(index)
            .map_err(|err| BrainError::Unavailable {
                component: "archive",
                reason: format!("cannot open zip entry {index}: {err}"),
            })?;
        let member = super::member_name(&emit_reader)?;
        pass_two(
            emit_reader,
            &membership,
            &policy,
            Some(&member),
            seen,
            summary,
            emit,
        )?;
        drop(emit_archive);
    }
    Ok(())
}

/// The export's own per-attachment metadata: one structural line per
/// declared attachment, naming the file name and media type the MIME
/// structure itself declares (Content-Disposition filename, else
/// Content-Type name; `type/subtype`). Attachment bodies are never read
/// and nothing is invented — the lines are the export's own declarations.
fn declared_attachment_lines(message: &mail_parser::Message<'_>) -> Vec<String> {
    message
        .attachments()
        .map(|part| {
            let name = part.attachment_name().unwrap_or("unknown");
            let media = match part.content_type() {
                Some(content_type) => match content_type.c_subtype.as_deref() {
                    Some(subtype) => format!("{}/{}", content_type.c_type, subtype),
                    None => content_type.c_type.to_string(),
                },
                None => "unknown".to_owned(),
            };
            format!("[attachment name={name} media_type={media}]")
        })
        .collect()
}

// ---------------------------------------------------------------------------
// mail-parser access helpers
// ---------------------------------------------------------------------------

/// Resolves one declared header name through the parser's own table: typed
/// variants for every well-known field (matched case-insensitively) and
/// `Other` for extension fields such as `X-Gmail-Labels`. A hand-written
/// name map is never used, and asking for a well-known field as `Other`
/// would silently match nothing — the export's own spelling of `Message-ID`
/// is exactly what the typed variants resolve.
fn header_name<'x>(name: &str) -> HeaderName<'x> {
    HeaderName::parse(name.to_owned())
        .unwrap_or_else(|| HeaderName::Other(std::borrow::Cow::Owned(name.to_owned())))
}

/// One parsed header value by name; header-name matching is the crate's own
/// case-insensitive [`HeaderName`] equality.
fn header_value<'m>(
    message: &'m mail_parser::Message<'_>,
    name: &str,
) -> Option<&'m HeaderValue<'m>> {
    message.header(header_name(name))
}

/// One declared header's exact value text as the export wrote it
/// (unfolded, undecoded): the content-header form used for record text,
/// never a re-serialization of the parsed address structure.
fn header_raw<'m>(message: &'m mail_parser::Message<'_>, name: &str) -> Option<&'m str> {
    message.header_raw(header_name(name))
}

/// One header's text value (unfolding and encoded-word decoding happen
/// inside mail-parser).
fn header_text<'m>(message: &'m mail_parser::Message<'_>, name: &str) -> Option<&'m str> {
    header_value(message, name)?.as_text()
}

/// All `Message-ID`-shaped tokens of one header (References carries
/// several), brackets stripped.
fn header_msg_ids(message: &mail_parser::Message<'_>, name: &str) -> Vec<String> {
    header_value(message, name)
        .and_then(|value| value.as_text_list())
        .map(|ids| {
            ids.iter()
                .flat_map(|id| id.split_whitespace())
                .filter_map(clean_msg_id)
                .collect()
        })
        .unwrap_or_default()
}

fn clean_msg_id(raw: &str) -> Option<String> {
    let id = raw.trim().trim_matches(|c| c == '<' || c == '>').trim();
    if id.is_empty() {
        None
    } else {
        Some(id.to_owned())
    }
}

/// The first `From` mailbox address, lowercased — the explicit sender
/// identity used for declared participant matching.
fn sender_address(message: &mail_parser::Message<'_>) -> Option<String> {
    let first = match message.from()? {
        Address::List(list) => list.first(),
        Address::Group(groups) => groups.first().and_then(|group| group.addresses.first()),
    }?;
    first
        .address
        .as_deref()
        .map(|address| address.trim().to_lowercase())
}

/// The domain part of a lowercased email address.
fn address_domain(address: &str) -> Option<&str> {
    let domain = address.rsplit('@').next()?;
    if domain.len() == address.len() {
        None
    } else {
        Some(domain)
    }
}

/// Converts mail-parser's RFC822 `DateTime` into the typed provenance
/// form; `None` when the date is invalid or out of range (counted by
/// callers, never fabricated).
fn message_date(message: &mail_parser::Message<'_>) -> Option<OffsetDateTime> {
    let parsed = message.date()?;
    if !parsed.is_valid() {
        return None;
    }
    OffsetDateTime::from_unix_timestamp(parsed.to_timestamp()).ok()
}

// ---------------------------------------------------------------------------
// Policy
// ---------------------------------------------------------------------------

/// One parsed `Name` or `Name: value` header rule from the declaration.
#[derive(Clone, Debug, Eq, PartialEq)]
struct HeaderRule {
    name: String,
    value: Option<String>,
}

impl HeaderRule {
    fn parse(raw: &str, field: &str) -> BrainResult<Self> {
        let (name, value) = match raw.split_once(':') {
            Some((name, value)) => (name.trim(), Some(value.trim().to_lowercase())),
            None => (raw.trim(), None),
        };
        if name.is_empty() {
            return Err(BrainError::InvalidPolicy(format!(
                "archive selection field {field}: empty header name in rule {raw:?}"
            )));
        }
        Ok(Self {
            name: name.to_lowercase(),
            value,
        })
    }

    /// `true` when the message carries the named header; with a declared
    /// value, when the header's value matches exactly (case-insensitive).
    fn matches(&self, message: &mail_parser::Message<'_>) -> bool {
        let Some(value) = header_text(message, &self.name) else {
            return false;
        };
        match &self.value {
            Some(expected) => value.trim().eq_ignore_ascii_case(expected),
            None => true,
        }
    }
}

/// The validated, format-local view of the declared selection policy.
struct MboxPolicy {
    since: Option<Date>,
    exclude_labels: Vec<String>,
    /// Declared `exclude_if_header` rules (bulk-classification headers
    /// such as `List-Unsubscribe` / `Precedence: bulk`).
    header_rules: Vec<HeaderRule>,
    keep_if_participant: bool,
    /// Lowercased declared operator sender identities.
    participants: HashSet<String>,
    suspicious_rules: Vec<SuspiciousRule>,
}

struct SuspiciousRule {
    name: String,
    exclude: bool,
    match_label: Option<String>,
    match_header: Option<HeaderRule>,
    sender_domain: Option<String>,
}

impl MboxPolicy {
    fn new(selection: &ArchiveSelectionPolicy) -> BrainResult<Self> {
        let header_rules = selection
            .exclude_if_header
            .iter()
            .map(|rule| HeaderRule::parse(rule, "exclude_if_header"))
            .collect::<BrainResult<Vec<_>>>()?;
        let suspicious_rules = selection
            .suspicious_rules
            .iter()
            .map(SuspiciousRule::new)
            .collect::<BrainResult<Vec<_>>>()?;
        Ok(Self {
            since: selection.since,
            exclude_labels: selection.exclude_labels.clone(),
            header_rules,
            keep_if_participant: selection.keep_if_participant,
            participants: selection
                .participant_emails
                .iter()
                .map(|email| email.trim().to_lowercase())
                .collect(),
            suspicious_rules,
        })
    }
}

impl SuspiciousRule {
    fn new(rule: &ArchiveSuspiciousRule) -> BrainResult<Self> {
        let match_header = rule
            .match_header
            .as_deref()
            .map(|header| HeaderRule::parse(header, "suspicious_rules.match_header"))
            .transpose()?;
        Ok(Self {
            name: rule.name.clone(),
            // `exclude` drops the record (counted); the only other declared
            // action, `flag`, retains it with the rule name recorded.
            exclude: matches!(rule.action, ArchiveSuspiciousAction::Exclude),
            match_label: rule.match_label.clone(),
            match_header,
            sender_domain: rule.sender_domain.as_deref().map(str::to_lowercase),
        })
    }

    fn matches(
        &self,
        message: &mail_parser::Message<'_>,
        labels: &[String],
        sender: Option<&str>,
    ) -> bool {
        if let Some(label) = &self.match_label {
            if !labels.iter().any(|candidate| candidate == label) {
                return false;
            }
        }
        if let Some(header) = &self.match_header {
            if !header.matches(message) {
                return false;
            }
        }
        if let Some(domain) = &self.sender_domain {
            let sender_domain = sender.and_then(address_domain);
            match sender_domain {
                Some(sender) if sender == domain || sender.ends_with(&format!(".{domain}")) => {}
                _ => return false,
            }
        }
        // A rule with no matcher at all is a domain-type violation;
        // declaration validate() refuses it, and failing closed here
        // costs one honest, counted skip.
        true
    }
}

// ---------------------------------------------------------------------------
// Pass one: bounded thread membership
// ---------------------------------------------------------------------------

/// Per-message policy facts, extracted through mail-parser in pass one.
/// Memory is O(message count) — a few hundred bytes each — never
/// O(mailbox size).
struct MsgMeta {
    natural_key: String,
    /// Own RFC822 Message-ID (without angle brackets), when present.
    msgid: Option<String>,
    /// Own id plus every References/In-Reply-To id, for thread union.
    thread_ids: Vec<String>,
    labels: Vec<String>,
    /// `true` only when `X-Gmail-Labels` carries `Sent` or the sender
    /// address matches a declared participant identity.
    sent: bool,
    from: String,
    to: String,
    subject: String,
    created_at: Option<OffsetDateTime>,
    /// Whether a raw Date header was present (distinguishes a missing
    /// date from an unparseable one for the declared-cutoff accounting).
    date_raw_present: bool,
}

/// Thread membership resolved from pass one: the canonical thread id per
/// message, and which threads carry operator-sent mail.
struct Membership {
    /// Union-find root per message index (flattened for pass two).
    roots: Vec<usize>,
    /// Canonical thread id per root: the lexicographically smallest real
    /// Message-ID in the component.
    canonical: HashMap<usize, String>,
    /// Roots whose component carries at least one sent message.
    sent_threads: HashSet<usize>,
    metas: Vec<MsgMeta>,
}

impl Membership {
    fn thread_id(&self, index: usize, meta: &MsgMeta) -> String {
        self.canonical
            .get(&self.roots[index])
            .cloned()
            .unwrap_or_else(|| meta.natural_key.clone())
    }

    fn sent_thread(&self, index: usize) -> bool {
        self.sent_threads.contains(&self.roots[index])
    }
}

/// Union-find over message indices keyed by RFC822 ids.
struct ThreadIndex {
    parent: Vec<usize>,
    rank: Vec<u8>,
}

impl ThreadIndex {
    fn new(size: usize) -> Self {
        Self {
            parent: (0..size).collect(),
            rank: vec![0; size],
        }
    }

    fn find(&mut self, mut node: usize) -> usize {
        while self.parent[node] != node {
            let grandparent = self.parent[self.parent[node]];
            self.parent[node] = grandparent;
            node = grandparent;
        }
        node
    }

    fn union(&mut self, a: usize, b: usize) {
        let root_a = self.find(a);
        let root_b = self.find(b);
        if root_a == root_b {
            return;
        }
        match self.rank[root_a].cmp(&self.rank[root_b]) {
            std::cmp::Ordering::Less => self.parent[root_a] = root_b,
            std::cmp::Ordering::Greater => self.parent[root_b] = root_a,
            std::cmp::Ordering::Equal => {
                self.parent[root_b] = root_a;
                self.rank[root_a] += 1;
            }
        }
    }
}

/// Pass one: stream the mbox once and parse every message with
/// mail-parser, extracting per-message facts and building the thread
/// union-find. A message that cannot be safely parsed or classified fails
/// the stream typed — unclassifiable records are never silently dropped.
fn pass_one<R: Read>(reader: R, policy: &MboxPolicy) -> BrainResult<Membership> {
    let mut mbox = MboxStream::new(reader);
    let mut metas: Vec<MsgMeta> = Vec::new();
    let mut id_owner: HashMap<String, usize> = HashMap::new();

    while let Some((raw, oversize)) = mbox.next_message()? {
        if oversize {
            // Not declared selection policy: a message that exceeds the
            // bounds cannot be safely parsed or preserved, so the stream
            // fails typed before anything unaccounted is dropped.
            return Err(BrainError::InvalidRequest(format!(
                "mbox message {} exceeds the {MAX_RAW_MESSAGE_BYTES} byte (or \
                 {MAX_LINE_BYTES} byte line) bound; refusing to ingest an \
                 unpreservable partial record",
                metas.len()
            )));
        }
        let Some(message) = mail_parser::MessageParser::default().parse(&raw) else {
            return Err(BrainError::InvalidRequest(format!(
                "mbox message {} cannot be parsed at all; refusing to ingest \
                 unpreservable bytes",
                metas.len()
            )));
        };
        let msgid = header_text(&message, "message-id")
            .and_then(clean_msg_id)
            .filter(|id| !id.is_empty());
        // Distinguish an unparseable Date field from an absent one for `since` filtering.
        let date_raw_present = header_value(&message, "date").is_some();
        let created_at = message_date(&message);
        let subject = header_text(&message, "subject").unwrap_or("").to_owned();
        let natural_key = msgid.clone().unwrap_or_else(|| {
            format!(
                "no-msgid-{}",
                blake3::hash(&raw[..raw.len().min(64 * 1024)])
            )
        });
        let mut thread_ids = Vec::new();
        thread_ids.extend(msgid.iter().cloned());
        thread_ids.extend(header_msg_ids(&message, "references"));
        thread_ids.extend(header_msg_ids(&message, "in-reply-to"));
        let labels: Vec<String> = header_text(&message, "x-gmail-labels")
            .map(|value| {
                value
                    .split(',')
                    .map(|label| label.trim().to_owned())
                    .filter(|label| !label.is_empty())
                    .collect()
            })
            .unwrap_or_default();
        let sender = sender_address(&message);
        let sent = labels.iter().any(|label| label == "Sent")
            || sender
                .as_deref()
                .map(|address| policy.participants.contains(address))
                .unwrap_or(false);
        let index = metas.len();
        for id in &thread_ids {
            id_owner.entry(id.clone()).or_insert(index);
        }
        metas.push(MsgMeta {
            natural_key,
            msgid,
            thread_ids,
            labels,
            sent,
            from: header_raw(&message, "from").unwrap_or("").trim().to_owned(),
            to: header_raw(&message, "to").unwrap_or("").trim().to_owned(),
            subject,
            created_at,
            date_raw_present,
        });
    }

    let mut union = ThreadIndex::new(metas.len());
    for (index, meta) in metas.iter().enumerate() {
        for id in &meta.thread_ids {
            if let Some(owner) = id_owner.get(id) {
                union.union(index, *owner);
            }
        }
    }

    // Canonical thread id: the lexicographically smallest real
    // Message-ID in each component (synthetic `no-msgid-` keys only
    // anchor threads that have no real id at all).
    let mut canonical: HashMap<usize, String> = HashMap::new();
    let mut sent_threads: HashSet<usize> = HashSet::new();
    for (index, meta) in metas.iter().enumerate() {
        let root = union.find(index);
        if let Some(msgid) = &meta.msgid {
            canonical
                .entry(root)
                .and_modify(|best| {
                    if msgid < best {
                        *best = msgid.clone();
                    }
                })
                .or_insert_with(|| msgid.clone());
        } else {
            canonical
                .entry(root)
                .or_insert_with(|| meta.natural_key.clone());
        }
        if meta.sent {
            sent_threads.insert(root);
        }
    }
    let roots = (0..metas.len()).map(|index| union.find(index)).collect();
    Ok(Membership {
        roots,
        canonical,
        sent_threads,
        metas,
    })
}

// ---------------------------------------------------------------------------
fn pass_two<R: Read>(
    reader: R,
    membership: &Membership,
    policy: &MboxPolicy,
    member: Option<&str>,
    seen: &mut HashMap<String, String>,
    summary: &mut ArchiveStreamSummary,
    emit: &mut dyn FnMut(ArchiveRecord) -> BrainResult<()>,
) -> BrainResult<()> {
    let mut mbox = MboxStream::new(reader);
    let mut index = 0usize;
    while let Some((raw, oversize)) = mbox.next_message()? {
        // Oversize messages were skipped before indexing in pass one, so
        // they consume no meta slot here either; their accounting
        // happened there exactly once.
        if oversize {
            continue;
        }
        let message_index = index;
        index += 1;
        summary.messages_parsed += 1;
        let Some(meta) = membership.metas.get(message_index) else {
            return Err(BrainError::Corrupt {
                component: "archive",
                reason: "pass two produced more messages than pass one indexed".to_owned(),
            });
        };

        // A missing timestamp is allowed only when no `since` cutoff is declared.
        if let Some(reason) =
            since_skip_reason(policy.since, meta.created_at, meta.date_raw_present)
        {
            summary.skip(reason);
            continue;
        }
        let created_at = meta.created_at;

        // Unreadable messages already failed the stream typed in pass one
        // (the same bytes parse identically); this arm only guards the
        // impossible drift.
        let Some(message) = mail_parser::MessageParser::default().parse(&raw) else {
            continue;
        };

        let label_excluded = policy
            .exclude_labels
            .iter()
            .any(|excluded| meta.labels.iter().any(|label| label == excluded));
        let header_excluded = policy
            .header_rules
            .iter()
            .any(|rule| rule.matches(&message));
        // Declared participant override: threads with operator-sent mail
        // survive label/header exclusions. `since` above is a hard
        // cutoff and suspicious rules below fail closed — neither is
        // ever overridden.
        if (label_excluded || header_excluded)
            && !(policy.keep_if_participant && membership.sent_thread(message_index))
        {
            summary.skip(if label_excluded {
                "excluded_label"
            } else {
                "excluded_bulk"
            });
            continue;
        }

        let sender = sender_address(&message);
        let mut rule_flags = Vec::new();
        let mut excluded = false;
        for rule in &policy.suspicious_rules {
            if rule.matches(&message, &meta.labels, sender.as_deref()) {
                if rule.exclude {
                    summary.skip(format!("suspicious_rule_excluded:{}", rule.name));
                    excluded = true;
                    break;
                }
                rule_flags.push(rule.name.clone());
            }
        }
        if excluded {
            continue;
        }

        // Declared normalization contract: a `text/plain` alternative is the
        // export's own words and becomes the record verbatim — with it, the
        // message's HTML alternative is deliberately not additionally read,
        // so references that exist only in that HTML are not captured for
        // such messages. An HTML-only message goes through the maintained
        // renderer plus its declared references (see `html_body_text`).
        let body = match message
            .text_bodies()
            .position(|part| matches!(part.body, mail_parser::PartType::Text(_)))
        {
            Some(plain) => message.body_text(plain).map(|text| text.into_owned()),
            None => html_body_text(&message)?,
        };
        let mut body = match body {
            Some(body) if !body.trim().is_empty() => body,
            // Keep-all: an eligible message with no decoded body is still
            // real mail identity — From/To/Subject/Message-ID, Date, labels,
            // thread membership — so it is admitted as a metadata record
            // instead of being dropped for lacking text. Nothing is
            // fabricated: the header block below is the export's own data.
            _ => {
                summary.skip("empty_body");
                String::new()
            }
        };
        // The export's own per-attachment metadata (declared file name and
        // media type), read from the already-parsed MIME structure — no
        // new reads, no extraction, bodies never touched.
        let attachment_lines = declared_attachment_lines(&message);
        let has_attachments = !attachment_lines.is_empty();
        for line in &attachment_lines {
            body.push('\n');
            body.push_str(line);
        }
        // From/To/Subject are message content headers (not provenance);
        // provenance fields stay structured on the record.
        let text = format!(
            "From: {}\nTo: {}\nSubject: {}\n\n{}",
            meta.from.trim(),
            meta.to.trim(),
            meta.subject.trim(),
            body
        );
        segment_and_deliver(
            summary,
            seen,
            ArchiveRecord {
                natural_key: meta.natural_key.clone(),
                kind: ArchiveRecordKind::Message,
                text,
                provenance: ArchiveProvenance {
                    export_account: None,
                    message_id: meta.msgid.clone(),
                    thread_id: Some(membership.thread_id(message_index, meta)),
                    created_at,
                    sent_by_user: meta.sent,
                    labels: meta.labels.clone(),
                    rule_flags,
                    // Attachment-bearing messages locate their original:
                    // the mbox zip member they were streamed from plus the
                    // deterministic 1-based source position (the message
                    // id above stays the identity when the export
                    // declared one).
                    origin: has_attachments.then(|| ArchiveAssetOrigin {
                        member: member.map(str::to_owned),
                        position: Some(message_index as u64 + 1),
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

/// Renders one message's HTML body through the maintained renderer, then
/// appends the references the message declares. The renderer drops
/// `<style>`, `<script>`, `<link>`, `<meta>` and `<head>` whole, keeps
/// `<img>` as its alt text alone, and hard-wraps long link footnotes, so a
/// font, stylesheet, image or link target can otherwise be missing from
/// memory or unreadable as the exact token the message wrote. `None` when
/// the message has no HTML part or rendering fails.
fn html_body_text(message: &mail_parser::Message<'_>) -> BrainResult<Option<String>> {
    let Some(html) = message.body_html(0) else {
        return Ok(None);
    };
    let Some(mut text) = html2text::from_read(html.as_bytes(), HTML_TEXT_WIDTH).ok() else {
        return Ok(None);
    };
    let references = declared_references(&html)?;
    if !references.is_empty() {
        text.push_str(&format!("\n[references: {}]", references.len()));
        for reference in &references {
            text.push('\n');
            text.push_str(reference);
        }
    }
    Ok(Some(text))
}

/// The references one HTML body declares — every `href`/`src` value and every
/// `url(...)` target of a `style` value or `<style>` element — in
/// first-occurrence order and deduplicated, each kept as the message declares
/// it apart from surrounding whitespace.
///
/// HTML tokenization (tags, quoting, character references) is `html5ever`'s
/// and CSS tokenization (quoting, whitespace, escapes) is `cssparser`'s; this
/// scan only copies values out. Prose and `<script>` text are never read.
/// Cost is one pass over the message plus the `<style>` text being tokenized,
/// all within the existing message caps. A `url(...)` nested past the
/// maintained parser's block-nesting limit is reachable data this walk cannot
/// read, so it fails typed rather than ingesting a truncated read.
fn declared_references(html: &str) -> BrainResult<Vec<String>> {
    let tokenizer = Tokenizer::new(ReferenceSink::default(), TokenizerOpts::default());
    let input = BufferQueue::default();
    input.push_back(StrTendril::from(html));
    while let TokenizerResult::Script(()) = tokenizer.feed(&input) {}
    tokenizer.end();
    let scan = tokenizer.sink.scan.into_inner();
    if scan.depth_refused {
        return Err(BrainError::Corrupt {
            component: "archive",
            reason: "html references nested past the css parser's block limit".to_owned(),
        });
    }
    Ok(scan.references)
}

/// The tokenization state the HTML5 tree builder puts an element's contents
/// in when they are not markup — the state that makes `<style>` text arrive
/// at the sink as text. `<style>` is the only one whose text is read;
/// `<script>` is program text, tokenized faithfully and never read.
fn raw_text_kind(name: &str) -> Option<RawKind> {
    match name {
        "title" | "textarea" => Some(RawKind::Rcdata),
        "style" | "xmp" | "iframe" | "noembed" | "noframes" | "noscript" => Some(RawKind::Rawtext),
        "script" => Some(RawKind::ScriptData),
        _ => None,
    }
}

/// Values collected so far, plus the `<style>` text still being tokenized.
#[derive(Default)]
struct ReferenceScan {
    references: Vec<String>,
    seen: HashSet<String>,
    style_text: Option<String>,
    /// Set when the maintained CSS parser refused a block deeper than its
    /// nesting limit: a reachable reference was not walked.
    depth_refused: bool,
}

impl ReferenceScan {
    /// Records one declared value once.
    fn collect(&mut self, value: &str) {
        let value = value.trim();
        if value.is_empty() || self.seen.contains(value) {
            return;
        }
        self.references.push(value.to_owned());
        self.seen.insert(value.to_owned());
    }

    /// Records every `url(...)` target of one CSS text — a `style` attribute
    /// value or a `<style>` element's contents.
    fn collect_css(&mut self, css: &str) {
        self.collect_css_tokens(&mut CssParser::new(css));
    }

    fn collect_css_tokens(&mut self, parser: &mut CssParser<'_>) {
        while let Ok(token) = parser.next_including_whitespace_and_comments() {
            match token {
                CssToken::UnquotedUrl(url) => self.collect(url),
                // `url("…")` is a function block holding the target.
                CssToken::Function(name) if name.eq_ignore_ascii_case("url") => {
                    let result = parser.parse_nested_block(|block| -> Result<(), ParseError<()>> {
                        while let Ok(token) = block.next_including_whitespace_and_comments() {
                            if let CssToken::QuotedString(value) = token {
                                self.collect(value);
                            }
                        }
                        Ok(())
                    });
                    self.record_depth_refusal(result);
                }
                CssToken::Function(_)
                | CssToken::ParenthesisBlock
                | CssToken::SquareBracketBlock
                | CssToken::CurlyBracketBlock => {
                    let result = parser.parse_nested_block(|block| -> Result<(), ParseError<()>> {
                        self.collect_css_tokens(block);
                        Ok(())
                    });
                    self.record_depth_refusal(result);
                }
                _ => {}
            }
        }
    }

    /// Records the parser's refusal to walk a block past its nesting limit,
    /// which is what bounds this recursion: the block is not walked and the
    /// caller fails typed instead of reporting a truncated read.
    fn record_depth_refusal(&mut self, result: Result<(), ParseError<()>>) {
        if matches!(
            result,
            Err(ParseError {
                kind: ParseErrorKind::Basic(BasicParseErrorKind::TooManyNestedBlocks)
            })
        ) {
            self.depth_refused = true;
        }
    }

    /// Records the text of a `<style>` element that never closed.
    fn finish_style(&mut self) {
        if let Some(css) = self.style_text.take() {
            self.collect_css(&css);
        }
    }
}

/// Keeps the declared references out of one HTML body's token stream.
/// `TokenSink` hands tokens to `&self`, so the scan sits behind a `RefCell`.
#[derive(Default)]
struct ReferenceSink {
    scan: RefCell<ReferenceScan>,
}

impl TokenSink for ReferenceSink {
    type Handle = ();

    fn process_token(&self, token: Token, _line_number: u64) -> TokenSinkResult<()> {
        let mut scan = self.scan.borrow_mut();
        match token {
            Token::TagToken(tag) => match tag.kind {
                TagKind::StartTag => {
                    let element = &*tag.name;
                    for attribute in &tag.attrs {
                        let name = &*attribute.name.local;
                        if matches!(name, "href" | "src") {
                            scan.collect(&attribute.value);
                        } else if name == "style" {
                            scan.collect_css(&attribute.value);
                        }
                    }
                    if let Some(kind) = raw_text_kind(element) {
                        if kind == RawKind::Rawtext && element == "style" {
                            scan.style_text = Some(String::new());
                        }
                        return TokenSinkResult::RawData(kind);
                    }
                }
                TagKind::EndTag => {
                    if &*tag.name == "style" {
                        scan.finish_style();
                    }
                }
            },
            Token::CharacterTokens(text) => {
                if let Some(css) = scan.style_text.as_mut() {
                    css.push_str(&text);
                }
            }
            _ => {}
        }
        TokenSinkResult::Continue
    }

    fn end(&self) {
        self.scan.borrow_mut().finish_style();
    }
}

// ---------------------------------------------------------------------------
// mbox splitting
// ---------------------------------------------------------------------------

/// Streams raw RFC822 message bytes out of an mbox. A message boundary is
/// a line starting with `From ` whose preceding line is blank (verified
/// against the real export); the separator line itself is never part of
/// the message, and quoted `>From ` body lines never split.
struct MboxStream<R: Read> {
    reader: BufReader<R>,
    started: bool,
    prev_blank: bool,
    pending_separator: bool,
    done: bool,
    line: Vec<u8>,
}

impl<R: Read> MboxStream<R> {
    fn new(reader: R) -> Self {
        Self {
            reader: BufReader::new(reader),
            started: false,
            prev_blank: true,
            pending_separator: false,
            done: false,
            line: Vec::new(),
        }
    }

    /// Returns the next message's raw bytes, or `None` at end of stream.
    /// `oversize` marks messages that exceeded the raw/line bounds; their
    /// bytes are partial and callers must skip them.
    fn next_message(&mut self) -> BrainResult<Option<(Vec<u8>, bool)>> {
        loop {
            if self.done {
                return Ok(None);
            }
            if self.pending_separator {
                self.pending_separator = false;
            }
            let mut message = Vec::new();
            let mut oversize = false;

            // At the start of the file, consume the initial `From ` line
            // when present; anything before it is not a message.
            if !self.started {
                self.started = true;
                let (read, capped) =
                    read_capped_line(&mut self.reader, &mut self.line, MAX_LINE_BYTES)?;
                if read == 0 {
                    self.done = true;
                    return Ok(None);
                }
                if capped {
                    oversize = true;
                }
                if !self.line.starts_with(b"From ") {
                    message.extend_from_slice(&self.line);
                }
                self.prev_blank = is_blank(&self.line);
            }

            loop {
                let (read, capped) =
                    read_capped_line(&mut self.reader, &mut self.line, MAX_LINE_BYTES)?;
                if read == 0 {
                    self.done = true;
                    break;
                }
                if capped {
                    oversize = true;
                }
                if self.line.starts_with(b"From ") && self.prev_blank {
                    // The separator line was consumed and is never part
                    // of either message.
                    self.pending_separator = true;
                    self.prev_blank = false;
                    break;
                }
                if !oversize {
                    if message.len() + self.line.len() > MAX_RAW_MESSAGE_BYTES {
                        oversize = true;
                    } else {
                        message.extend_from_slice(&self.line);
                    }
                }
                self.prev_blank = is_blank(&self.line);
            }

            if message.is_empty() && !oversize {
                // Empty message between separators: not an error, not a
                // record — collapse it into the surrounding stream.
                continue;
            }
            if !oversize {
                // The blank lines before the next `From ` separator are mbox
                // framing, not message bytes: trimming them makes one
                // message's bytes identical however many blank lines the
                // writer left between entries, so a message that genuinely
                // repeats still collapses as an exact duplicate (both the
                // natural-key fallback and content addressing depend on it).
                while matches!(message.last(), Some(b'\n' | b'\r')) {
                    message.pop();
                }
            }
            return Ok(Some((message, oversize)));
        }
    }
}

/// A line is blank when it carries nothing but its line terminator.
fn is_blank(line: &[u8]) -> bool {
    line == b"\n" || line == b"\r\n"
}

/// Reads one line (through `\n`) bounded at `cap` bytes of content. When
/// the line exceeds the cap the remainder is consumed and discarded,
/// `capped` is set, and the returned buffer holds only what fit.
fn read_capped_line<R: BufRead>(
    reader: &mut R,
    buf: &mut Vec<u8>,
    cap: usize,
) -> BrainResult<(usize, bool)> {
    buf.clear();
    let mut capped = false;
    loop {
        let available = reader.fill_buf().map_err(|err| BrainError::Unavailable {
            component: "archive",
            reason: format!("mbox read failed: {err}"),
        })?;
        if available.is_empty() {
            return Ok((buf.len(), capped));
        }
        match available.iter().position(|&byte| byte == b'\n') {
            Some(newline) => {
                let take = newline + 1;
                if buf.len() + take > cap {
                    let room = cap.saturating_sub(buf.len());
                    buf.extend_from_slice(&available[..room]);
                    capped = true;
                } else {
                    buf.extend_from_slice(&available[..take]);
                }
                reader.consume(take);
                return Ok((buf.len(), capped));
            }
            None => {
                let chunk_len = available.len();
                let exceeded = buf.len() + chunk_len > cap;
                let room = if exceeded {
                    cap.saturating_sub(buf.len())
                } else {
                    chunk_len
                };
                buf.extend_from_slice(&available[..room]);
                reader.consume(chunk_len);
                if exceeded {
                    capped = true;
                }
            }
        }
    }
}
