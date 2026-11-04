//! Strict operator declarations for one generic archive knowledge source.
//!
//! An archive source is a read-only external export (chat export, mailbox)
//! that the brain ingests as normalized memory. Every selection rule is
//! declared here and validated at the owning seam — there is no per-person
//! or per-file policy in Rust, and formats are the only parser dispatch.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use time::Date;

use crate::DomainError;

/// Day-precision calendar date, explicit `YYYY-MM-DD`: the crate does not
/// rely on the `time` serde default encoding for `Date`, so the wire form is
/// declared here and nothing else is accepted.
const DATE_FORMAT: &[time::format_description::BorrowedFormatItem<'static>] =
    time::macros::format_description!("[year]-[month]-[day]");

fn serialize_since<S>(date: &Option<Date>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    match date {
        Some(date) => {
            let text = date
                .format(DATE_FORMAT)
                .map_err(serde::ser::Error::custom)?;
            serializer.serialize_some(text.as_str())
        }
        None => serializer.serialize_none(),
    }
}

fn deserialize_since<'de, D>(deserializer: D) -> Result<Option<Date>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = Option::<String>::deserialize(deserializer)?;
    value
        .map(|text| Date::parse(&text, DATE_FORMAT).map_err(serde::de::Error::custom))
        .transpose()
}

fn invalid(reason: impl Into<String>) -> DomainError {
    DomainError::InvalidEnvelope(format!("invalid archive declaration: {}", reason.into()))
}

/// Supported archive export formats. One parser per format behind the
/// generic ingest path; a new format is one new variant plus its parser,
/// never new config shape.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub enum ArchiveFormat {
    /// Claude (claude.ai) `conversations.json` export with its
    /// `memories/` and `projects/` JSON beside it.
    ClaudeExport,
    /// Grok export directory: the unpacked bundle holding
    /// `prod-grok-backend.json` and the `prod-mc-asset-server/` files.
    GrokExport,
    /// ChatGPT export directory: the unpacked export, whose
    /// `conversations-*.json` message trees are streamed, with `*.dat`
    /// asset files and `library_files.json` as metadata only.
    #[serde(rename = "chatgpt-export")]
    ChatGptExport,
    /// Gemini in Workspace Takeout transcripts (`Gemini in
    /// Workspace/Conversation History`).
    #[serde(rename = "gemini-workspace")]
    GeminiWorkspace,
    /// NotebookLM Takeout notebook sources (`NotebookLM/<notebook>`).
    #[serde(rename = "notebooklm")]
    NotebookLm,
    /// A directory tree of `*.md` / `*.txt` files, one document each.
    #[serde(rename = "text-tree")]
    TextTree,
}

/// Confidentiality class of one archive source. This governs which seats
/// may be served the ingested memory; it says nothing about record trust,
/// which stays independently `Observed`/`Untrusted` for all archive data.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum ArchivePrivacyClass {
    /// Single-operator confidential data (personal exports). Served only
    /// to seats explicitly scoped to the source namespace.
    Private,
    /// Data declared for a known set of seats beyond the operator.
    Shared,
}

/// Declared record identity/dedupe strategy. Dedupe is always content
/// addressing; an export UUID or RFC 822 Message-Id is the record's
/// natural key, never an alternative dedupe mode.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum ArchiveDedupeKey {
    /// Dedupe on the digest of normalized record content, its provenance,
    /// and the declared selection policy.
    ContentDigest,
}

/// Declared outcome for one suspicious/phishing heuristic match.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum ArchiveSuspiciousAction {
    /// Matched records are dropped from ingest entirely.
    Exclude,
    /// Matched records are retained with the rule name recorded in their
    /// provenance.
    Flag,
}

/// One declared suspicious/phishing heuristic. Heuristics are declared
/// rules, never model judgment, and every rule names its outcome.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ArchiveSuspiciousRule {
    /// Declared rule name (1..=64 bytes) recorded on flagged matches.
    pub name: String,
    pub action: ArchiveSuspiciousAction,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub match_label: Option<String>,
    /// Match records carrying this header, either bare (`List-Unsubscribe`)
    /// or as a `Name: value` prefix.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub match_header: Option<String>,
    /// Match records whose sender address is at this exact lowercased
    /// domain (no `@`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sender_domain: Option<String>,
}

/// Declared selection policy for one archive source. Every field is
/// inapplicable-for-format checked at validation; nothing here is
/// inferred at runtime.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ArchiveSelectionPolicy {
    /// Keep only records dated on or after this day (`YYYY-MM-DD`). All
    /// supported formats carry per-record timestamps.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        serialize_with = "serialize_since",
        deserialize_with = "deserialize_since"
    )]
    pub since: Option<Date>,
    /// Exclude records carrying any of these declared labels. Applicable
    /// only to label-bearing formats; for `chat-jsonl` the labels are
    /// Discord channel ids.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub exclude_labels: Vec<String>,
    /// Exclude records carrying any of these headers, either bare
    /// (`List-Unsubscribe`) or as a `Name: value` prefix. Applicable only
    /// to header-bearing formats.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub exclude_if_header: Vec<String>,
    /// Keep threads a declared participant sent or replied to, overriding
    /// label/header exclusions. Applicable only to thread-bearing formats.
    /// Participation comes from exported sent/thread metadata or declared
    /// [`Self::participant_emails`]; no addresses are required to keep exported sent threads.
    #[serde(default)]
    pub keep_if_participant: bool,
    /// Exact operator identity addresses used for participant matching.
    /// Explicit declarations; never inferred from the export and never
    /// required — an absent or empty list leaves matching to the export's
    /// own sent metadata.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub participant_emails: Vec<String>,
    /// Exclude conversations the export itself marks as forgotten
    /// (`is_do_not_remember`). Declared knob for the chatgpt-export
    /// format only; unset means excluded (the operator's own forget flag
    /// is honoured), `false` reads the forgotten conversations back in.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exclude_do_not_remember: Option<bool>,
    /// Absolute path of the operator's people registry (`people.toml`).
    /// Read by `mbox` and `chat-jsonl` only, which skip everything tied to
    /// a person marked `private = true`; other formats ignore it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub people_registry: Option<PathBuf>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub suspicious_rules: Vec<ArchiveSuspiciousRule>,
}

/// Strict operator declaration of one archive knowledge source. This is the
/// single config shape every supported format shares.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ArchiveSourceDeclaration {
    pub format: ArchiveFormat,
    /// Read-only export path: a file or directory root as the format
    /// defines. Must be absolute and free of parent components.
    pub path: PathBuf,
    /// Retrieval namespace for ingested memory: 1..=128 bytes, no path
    /// separator, NUL, or traversal.
    pub memory_namespace: String,
    pub privacy_class: ArchivePrivacyClass,
    pub dedupe_key: ArchiveDedupeKey,
    pub selection: ArchiveSelectionPolicy,
}

const MAX_NAMESPACE_BYTES: usize = 128;
const MAX_RULE_NAME_BYTES: usize = 64;
const MAX_LABELS: usize = 32;
const MAX_HEADERS: usize = 32;
const MAX_RULES: usize = 32;
const MAX_PARTICIPANTS: usize = 16;

/// RFC 7230 header-name token grammar.
fn is_header_token_char(ch: char) -> bool {
    ch.is_ascii_alphanumeric()
        || matches!(
            ch,
            '!' | '#'
                | '$'
                | '%'
                | '&'
                | '\''
                | '*'
                | '+'
                | '-'
                | '.'
                | '^'
                | '_'
                | '`'
                | '|'
                | '~'
        )
}

/// One header matcher entry: bare `Name` or `Name: value` with a token name
/// and a control-free value.
fn validate_header_matcher(field: &str, value: &str) -> Result<(), DomainError> {
    let (name, header_value) = match value.split_once(':') {
        Some((name, header_value)) => (name, Some(header_value)),
        None => (value, None),
    };
    let name_ok = !name.is_empty() && name.chars().all(is_header_token_char);
    let value_ok = header_value.is_none_or(|part| {
        !part.is_empty() && !part.chars().any(|ch| ch.is_control() || ch == '\0')
    });
    if !name_ok || !value_ok {
        return Err(invalid(format!(
            "{field} entry {value:?} must be a header token or `Name: value` with a \
             non-empty control-free value"
        )));
    }
    Ok(())
}

/// One declared label: non-empty, no surrounding whitespace, no control
/// characters. Interior spaces are legitimate export label text.
fn validate_label(field: &str, value: &str) -> Result<(), DomainError> {
    let trimmed = value.trim();
    if trimmed.is_empty()
        || trimmed.len() != value.len()
        || value.chars().any(|ch| ch.is_control() || ch == '\0')
    {
        return Err(invalid(format!(
            "{field} entry {value:?} must be a non-empty label without control characters \
             or surrounding whitespace"
        )));
    }
    Ok(())
}

/// Exact operator identity address shape: one `@`, no whitespace, non-empty
/// local part and domain.
fn validate_email(field: &str, value: &str) -> Result<(), DomainError> {
    let mut parts = value.split('@');
    let (Some(local), Some(domain), None) = (parts.next(), parts.next(), parts.next()) else {
        return Err(invalid(format!(
            "{field} entry {value:?} must be one exact email address"
        )));
    };
    if local.is_empty()
        || domain.is_empty()
        || value
            .chars()
            .any(|ch| ch.is_whitespace() || ch.is_control())
    {
        return Err(invalid(format!(
            "{field} entry {value:?} must be one exact email address"
        )));
    }
    Ok(())
}

impl ArchiveSourceDeclaration {
    /// Validates format support, field applicability, matcher syntax, the
    /// namespace, and explicit participant rules. Invalid policy rejects
    /// here at the owning seam, before any parser or store sees it.
    pub fn validate(&self) -> Result<(), DomainError> {
        if !self.path.is_absolute()
            || self
                .path
                .components()
                .any(|component| matches!(component, std::path::Component::ParentDir))
        {
            return Err(invalid(format!(
                "path {:?} must be absolute with no parent components",
                self.path
            )));
        }
        let namespace = &self.memory_namespace;
        if namespace.is_empty()
            || namespace.len() > MAX_NAMESPACE_BYTES
            || namespace
                .chars()
                .any(|ch| ch.is_whitespace() || ch.is_control() || ch == '\0')
            || namespace.contains('/')
            || namespace.contains("..")
        {
            return Err(invalid(format!(
                "memory_namespace {:?} must be 1..={MAX_NAMESPACE_BYTES} bytes, confined, \
                 with no whitespace, control characters, path separator, or traversal",
                self.memory_namespace
            )));
        }
        let selection = &self.selection;
        if let Some(registry) = &selection.people_registry {
            if !registry.is_absolute()
                || registry
                    .components()
                    .any(|component| matches!(component, std::path::Component::ParentDir))
            {
                return Err(invalid(format!(
                    "people_registry {registry:?} must be absolute with no parent components"
                )));
            }
        }
        if selection.exclude_labels.len() > MAX_LABELS {
            return Err(invalid(format!(
                "exclude_labels allows at most {MAX_LABELS} entries"
            )));
        }
        if selection.exclude_if_header.len() > MAX_HEADERS {
            return Err(invalid(format!(
                "exclude_if_header allows at most {MAX_HEADERS} entries"
            )));
        }
        if selection.suspicious_rules.len() > MAX_RULES {
            return Err(invalid(format!(
                "suspicious_rules allows at most {MAX_RULES} entries"
            )));
        }
        if selection.participant_emails.len() > MAX_PARTICIPANTS {
            return Err(invalid(format!(
                "participant_emails allows at most {MAX_PARTICIPANTS} entries"
            )));
        }
        let is_chatgpt = matches!(self.format, ArchiveFormat::ChatGptExport);
        if !is_chatgpt && selection.exclude_do_not_remember.is_some() {
            return Err(invalid(format!(
                "exclude_do_not_remember applies only to the chatgpt-export format, not {:?}",
                self.format
            )));
        }
        for label in &selection.exclude_labels {
            validate_label("exclude_labels", label)?;
        }
        for header in &selection.exclude_if_header {
            validate_header_matcher("exclude_if_header", header)?;
        }
        for email in &selection.participant_emails {
            validate_email("participant_emails", email)?;
        }
        let mut rule_names = std::collections::BTreeSet::new();
        for rule in &selection.suspicious_rules {
            if rule.name.is_empty()
                || rule.name.len() > MAX_RULE_NAME_BYTES
                || rule.name.chars().any(|ch| ch.is_control() || ch == '\0')
            {
                return Err(invalid(format!(
                    "suspicious rule name {:?} must be 1..={MAX_RULE_NAME_BYTES} control-free \
                     bytes",
                    rule.name
                )));
            }
            if !rule_names.insert(rule.name.as_str()) {
                return Err(invalid(format!(
                    "suspicious rule {:?} is declared twice",
                    rule.name
                )));
            }
            if rule.match_label.is_none()
                && rule.match_header.is_none()
                && rule.sender_domain.is_none()
            {
                return Err(invalid(format!(
                    "suspicious rule {:?} declares no matcher",
                    rule.name
                )));
            }
            if let Some(label) = &rule.match_label {
                validate_label(&format!("suspicious rule {:?}", rule.name), label)?;
            }
            if let Some(header) = &rule.match_header {
                validate_header_matcher(&format!("suspicious rule {:?}", rule.name), header)?;
            }
            if let Some(domain) = &rule.sender_domain {
                if domain.is_empty()
                    || domain.contains('@')
                    || domain
                        .chars()
                        .any(|ch| ch.is_whitespace() || ch.is_control() || ch == '\0')
                {
                    return Err(invalid(format!(
                        "suspicious rule {:?} sender_domain must be one exact domain",
                        rule.name
                    )));
                }
            }
        }
        Ok(())
    }
}

impl ArchiveSelectionPolicy {
    /// The effective `exclude_do_not_remember` policy at the typed seam:
    /// unset declarations exclude, because the export's own forget flag is
    /// the operator's decision until they explicitly flip the knob.
    pub fn excludes_do_not_remember(&self) -> bool {
        self.exclude_do_not_remember.unwrap_or(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use time::Month;

    fn since_2021() -> Date {
        Date::from_calendar_date(2021, Month::January, 1).expect("calendar date")
    }







    #[test]
    fn exclude_do_not_remember_defaults_to_excluded_at_the_typed_seam() {
        let mut policy = ArchiveSelectionPolicy {
            since: None,
            exclude_labels: Vec::new(),
            exclude_if_header: Vec::new(),
            keep_if_participant: false,
            participant_emails: Vec::new(),
            suspicious_rules: Vec::new(),
            exclude_do_not_remember: None,
            people_registry: None,
        };
        assert!(policy.excludes_do_not_remember());
        policy.exclude_do_not_remember = Some(false);
        assert!(!policy.excludes_do_not_remember());
        policy.exclude_do_not_remember = Some(true);
        assert!(policy.excludes_do_not_remember());
        // Unset is skipped on the wire, so old serialized declarations are
        // byte-identical.
        policy.exclude_do_not_remember = None;
        let serialized = serde_json::to_string(&policy).expect("serialize policy");
        assert!(!serialized.contains("do_not_remember"), "{serialized}");
    }

}
