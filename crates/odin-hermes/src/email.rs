//! Email search/read, durable drafts and organization, and approval-gated send.
//!
//! Draft and organization effects are reversible and ungated; sends require consumed kernel approval.
//! Private draft receipts freeze content: Gmail sends raw MIME, JMAP submits immutable Email,
//! and IMAP rejects changed bytes before SMTP. ID-only receipts cannot recover that snapshot remotely.
//! Public results expose identifiers, not message content. Uncertain dispatches are not retried.
//! Permanent deletion and unsubscribing are not supported.

use crate::account::{
    fault_into_life, lease_into_life, BatchFault, CredentialLeases, DurableEffect, EffectIdentity,
    EffectRoute, LifeError, ScopedCredentialLease, SettledEffect, TransportFault,
    MAX_ACCOUNT_CHARS,
};
use crate::jmap::{JmapCall, JmapExchange, JmapRequest, JMAP_CORE, JMAP_MAIL, JMAP_SUBMISSION};
use odin_domain::CapabilityId;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::sync::Arc;

pub const EMAIL_SEARCH_OPERATION: &str = "email.search";
pub const EMAIL_READ_OPERATION: &str = "email.read";
pub const EMAIL_DRAFT_OPERATION: &str = "email.draft";
pub const EMAIL_SEND_OPERATION: &str = "email.send";
pub const EMAIL_MANAGE_OPERATION: &str = "email.manage";

/// Longest search text accepted (Unicode scalar values).
pub const MAX_SEARCH_TEXT_CHARS: usize = 400;
pub const MIN_SEARCH_LIMIT: u32 = 1;
pub const MAX_SEARCH_LIMIT: u32 = 20;
pub const MAX_ID_CHARS: usize = 128;
pub const MAX_ADDRESS_CHARS: usize = 320;
/// Most recipients on one draft.
pub const MAX_RECIPIENTS: usize = 10;
pub const MAX_SUBJECT_CHARS: usize = 200;
/// Longest a caller-supplied or read body may be.
pub const MAX_BODY_CHARS: usize = 20_000;
pub const MAX_SUMMARY_SUBJECT_CHARS: usize = 512;
pub const MAX_PREVIEW_CHARS: usize = 256;
pub const MAX_TIMESTAMP_CHARS: usize = 64;
/// Most actions one manage intent may carry.
pub const MAX_MANAGEMENT_ACTIONS: usize = 25;
/// Most keywords one Label action may add or remove.
pub const MAX_KEYWORDS_PER_ACTION: usize = 10;
/// Longest one keyword (a JMAP/IMAP flag atom).
pub const MAX_KEYWORD_CHARS: usize = 64;
/// Most calendar invitation events extracted from one message.
pub const MAX_CALENDAR_INVITES: usize = 8;
/// Largest decoded iCalendar part accepted from one message.
pub const MAX_CALENDAR_INVITE_BYTES: usize = 262_144;
pub const MAX_CALENDAR_UID_CHARS: usize = 512;

const MSG_BOUND: &str = "the JMAP email response violated the declared output bounds";
const MSG_SHAPE: &str = "the JMAP email response was not the expected shape";
const MSG_METHOD_ERROR: &str = "the JMAP service reported an email method error";
const MSG_CONFIG: &str = "the JMAP mail account configuration is incomplete";
const MSG_MANAGEMENT_BOUND: &str = "the management action list is out of bounds";
const MSG_KEYWORD_BOUND: &str = "a keyword list is out of bounds";
const MSG_KEYWORD_CONFLICT: &str = "one action adds and removes the same keyword";
const MSG_MANAGEMENT_CONFLICT: &str = "two actions move the same message into different mailboxes";
const MSG_RECEIPT: &str = "the settled result is not a bounded management receipt";

/// Builds the capability id of one of this module's registry constants.
/// The ids are fixed above and known to satisfy the registry grammar.
fn capability(id: &'static str) -> CapabilityId {
    CapabilityId::new(id).expect("the reserved registry capability id is valid")
}

/// One email search request: the account selector, the free text, and
/// the page size. Bounds are enforced at the adapter boundary.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct EmailSearchQuery {
    pub account: String,
    pub text: String,
    pub limit: u32,
}

impl EmailSearchQuery {
    fn validate(&self) -> Result<(), LifeError> {
        if self.account.trim().is_empty() || self.account.len() > MAX_ACCOUNT_CHARS {
            return Err(LifeError::InvalidInput(
                "the account selector is out of bounds",
            ));
        }
        let text = self.text.trim();
        if text.is_empty() || text.chars().count() > MAX_SEARCH_TEXT_CHARS {
            return Err(LifeError::InvalidInput("the search text is out of bounds"));
        }
        if !(MIN_SEARCH_LIMIT..=MAX_SEARCH_LIMIT).contains(&self.limit) {
            return Err(LifeError::InvalidInput("the search limit is out of bounds"));
        }
        Ok(())
    }
}

/// One sanitized search hit. Only these bounded fields leave the
/// adapter; the message body never appears in a summary.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct EmailSummary {
    pub id: String,
    pub subject: Option<String>,
    pub from: Option<String>,
    pub received_at: Option<String>,
    pub preview: Option<String>,
}

/// The actionable iTIP method carried by a `text/calendar` MIME part.
#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum CalendarInviteMethod {
    Request,
    Cancel,
}

/// One bounded calendar invitation extracted from mail. Times stay in their
/// source iCalendar representation with explicit TZID metadata; the parser
/// never guesses a timezone. A caller may turn this read-only projection into
/// an ordinary governed `calendar.propose` mutation.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CalendarInvite {
    pub method: CalendarInviteMethod,
    pub uid: String,
    pub sequence: u32,
    pub title: Option<String>,
    pub description: Option<String>,
    pub location: Option<String>,
    pub organizer: Option<String>,
    pub start: Option<String>,
    pub end: Option<String>,
    pub start_timezone: Option<String>,
    pub end_timezone: Option<String>,
}

fn ical_property_name(line: &str) -> &str {
    line.split(':')
        .next()
        .unwrap_or("")
        .split(';')
        .next()
        .unwrap_or("")
}

fn ical_property_value(line: &str) -> &str {
    line.split_once(':').map(|(_, value)| value).unwrap_or("")
}

fn ical_property_param(line: &str, wanted: &str) -> Option<String> {
    let (head, _) = line.split_once(':')?;
    head.split(';').skip(1).find_map(|parameter| {
        let (name, value) = parameter.split_once('=')?;
        name.eq_ignore_ascii_case(wanted).then(|| {
            value
                .trim_matches('"')
                .chars()
                .take(MAX_TIMESTAMP_CHARS)
                .collect()
        })
    })
}

fn ical_text_unescape(value: &str, max: usize) -> String {
    let mut output = String::with_capacity(value.len().min(max));
    let mut escaped = false;
    let mut count = 0usize;
    for character in value.chars() {
        if count >= max {
            break;
        }
        if escaped {
            output.push(match character {
                'n' | 'N' => '\n',
                other => other,
            });
            escaped = false;
            count += 1;
        } else if character == '\\' {
            escaped = true;
        } else {
            output.push(character);
            count += 1;
        }
    }
    output
}

/// Parses bounded iTIP `REQUEST`/`CANCEL` payloads. Unsupported methods are
/// honest absence. Structural or bound violations refuse the containing mail
/// read instead of returning a partially trusted invitation.
pub(crate) fn parse_ical_invites(text: &str) -> Result<Vec<CalendarInvite>, &'static str> {
    if text.len() > MAX_CALENDAR_INVITE_BYTES {
        return Err("the calendar invitation exceeds its byte bound");
    }
    let mut lines: Vec<String> = Vec::new();
    for raw in text.split('\n') {
        let raw = raw.strip_suffix('\r').unwrap_or(raw);
        if raw.is_empty() {
            continue;
        }
        if raw.starts_with(' ') || raw.starts_with('\t') {
            let last = lines
                .last_mut()
                .ok_or("the calendar invitation starts with a folded line")?;
            last.push_str(&raw[1..]);
            if last.len() > 4_096 {
                return Err("a calendar invitation line exceeds its byte bound");
            }
        } else {
            if lines.len() >= 512 || raw.len() > 4_096 {
                return Err("the calendar invitation exceeds its line bound");
            }
            lines.push(raw.to_owned());
        }
    }
    let method = lines
        .iter()
        .find(|line| ical_property_name(line).eq_ignore_ascii_case("METHOD"))
        .map(|line| ical_property_value(line).trim().to_ascii_uppercase());
    let Some(method) = method else {
        return Ok(Vec::new());
    };
    let calendar_method = match method.as_str() {
        "REQUEST" => CalendarInviteMethod::Request,
        "CANCEL" => CalendarInviteMethod::Cancel,
        _ => return Ok(Vec::new()),
    };

    let mut invitations = Vec::new();
    let mut cursor = 0usize;
    while let Some(offset) = lines[cursor..]
        .iter()
        .position(|line| line.eq_ignore_ascii_case("BEGIN:VEVENT"))
    {
        let begin = cursor + offset;
        let end = lines[begin + 1..]
            .iter()
            .position(|line| line.eq_ignore_ascii_case("END:VEVENT"))
            .map(|offset| begin + 1 + offset)
            .ok_or("the calendar invitation has an unterminated event")?;
        if invitations.len() >= MAX_CALENDAR_INVITES {
            return Err("the calendar invitation event count exceeds its bound");
        }
        let mut uid = None;
        let mut sequence = 0u32;
        let mut title = None;
        let mut description = None;
        let mut location = None;
        let mut organizer = None;
        let mut start = None;
        let mut end_time = None;
        let mut start_timezone = None;
        let mut end_timezone = None;
        let mut cancelled = false;
        for line in &lines[begin + 1..end] {
            let name = ical_property_name(line);
            let value = ical_property_value(line).trim();
            if name.eq_ignore_ascii_case("UID") {
                if value.is_empty() || value.chars().count() > MAX_CALENDAR_UID_CHARS {
                    return Err("the calendar invitation UID is out of bounds");
                }
                uid = Some(value.to_owned());
            } else if name.eq_ignore_ascii_case("SEQUENCE") {
                sequence = value
                    .parse()
                    .map_err(|_| "the calendar invitation sequence is invalid")?;
            } else if name.eq_ignore_ascii_case("SUMMARY") {
                title = Some(ical_text_unescape(value, MAX_SUBJECT_CHARS));
            } else if name.eq_ignore_ascii_case("DESCRIPTION") {
                description = Some(ical_text_unescape(value, MAX_BODY_CHARS));
            } else if name.eq_ignore_ascii_case("LOCATION") {
                location = Some(ical_text_unescape(value, MAX_ADDRESS_CHARS));
            } else if name.eq_ignore_ascii_case("ORGANIZER") {
                organizer = Some(
                    value
                        .strip_prefix("mailto:")
                        .unwrap_or(value)
                        .chars()
                        .take(MAX_ADDRESS_CHARS)
                        .collect(),
                );
            } else if name.eq_ignore_ascii_case("DTSTART") {
                start = Some(value.chars().take(MAX_TIMESTAMP_CHARS).collect());
                start_timezone = ical_property_param(line, "TZID");
            } else if name.eq_ignore_ascii_case("DTEND") {
                end_time = Some(value.chars().take(MAX_TIMESTAMP_CHARS).collect());
                end_timezone = ical_property_param(line, "TZID");
            } else if name.eq_ignore_ascii_case("STATUS") && value.eq_ignore_ascii_case("CANCELLED")
            {
                cancelled = true;
            }
        }
        invitations.push(CalendarInvite {
            method: if cancelled {
                CalendarInviteMethod::Cancel
            } else {
                calendar_method
            },
            uid: uid.ok_or("the calendar invitation event has no UID")?,
            sequence,
            title,
            description,
            location,
            organizer,
            start,
            end: end_time,
            start_timezone,
            end_timezone,
        });
        cursor = end + 1;
    }
    Ok(invitations)
}

/// One sanitized message read. Structured invitations are read-only
/// projections; every calendar write still goes through `calendar.propose`.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct EmailMessage {
    pub id: String,
    pub subject: Option<String>,
    pub from: Option<String>,
    pub received_at: Option<String>,
    pub body_text: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub calendar_invites: Vec<CalendarInvite>,
}

/// One draft to save into the account's drafts mailbox. The body is
/// content by definition — it is the artifact the operator later
/// approves or edits — and it never enters any status envelope.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct EmailDraft {
    pub account: String,
    pub to: Vec<String>,
    pub subject: String,
    pub body_text: String,
}

impl EmailDraft {
    fn validate(&self) -> Result<(), LifeError> {
        if self.account.trim().is_empty() || self.account.len() > MAX_ACCOUNT_CHARS {
            return Err(LifeError::InvalidInput(
                "the account selector is out of bounds",
            ));
        }
        if self.to.is_empty() || self.to.len() > MAX_RECIPIENTS {
            return Err(LifeError::InvalidInput(
                "the recipient list is out of bounds",
            ));
        }
        for recipient in &self.to {
            let recipient = recipient.trim();
            if recipient.is_empty() || recipient.chars().count() > MAX_ADDRESS_CHARS {
                return Err(LifeError::InvalidInput(
                    "a recipient address is out of bounds",
                ));
            }
        }
        let subject = self.subject.trim();
        if subject.is_empty() || subject.chars().count() > MAX_SUBJECT_CHARS {
            return Err(LifeError::InvalidInput("the subject is out of bounds"));
        }
        if self.body_text.chars().count() > MAX_BODY_CHARS {
            return Err(LifeError::InvalidInput("the body is out of bounds"));
        }
        Ok(())
    }
}

/// One bounded mailbox-organization action. Label patches message
/// keywords only; Archive and Trash move the message into the
/// transport's configured archive/trash mailbox. There is deliberately
/// no variant that could express a permanent deletion or an
/// unsubscribe.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "action", rename_all = "camelCase")]
pub enum EmailManagementAction {
    Label {
        #[serde(rename = "emailId")]
        email_id: String,
        #[serde(rename = "addLabels")]
        add_labels: Vec<String>,
        #[serde(rename = "removeLabels")]
        remove_labels: Vec<String>,
    },
    Archive {
        #[serde(rename = "emailId")]
        email_id: String,
    },
    Trash {
        #[serde(rename = "emailId")]
        email_id: String,
    },
}

impl EmailManagementAction {
    fn validate(&self) -> Result<(), LifeError> {
        match self {
            Self::Label {
                email_id,
                add_labels,
                remove_labels,
            } => {
                Self::validate_email_id(email_id)?;
                Self::validate_keywords(add_labels)?;
                Self::validate_keywords(remove_labels)?;
                for keyword in add_labels {
                    if remove_labels.contains(keyword) {
                        return Err(LifeError::InvalidInput(MSG_KEYWORD_CONFLICT));
                    }
                }
                Ok(())
            }
            Self::Archive { email_id } | Self::Trash { email_id } => {
                Self::validate_email_id(email_id)
            }
        }
    }

    fn validate_email_id(email_id: &str) -> Result<(), LifeError> {
        if email_id.trim().is_empty() || email_id.chars().count() > MAX_ID_CHARS {
            return Err(LifeError::InvalidInput("the email id is out of bounds"));
        }
        Ok(())
    }

    fn validate_keywords(keywords: &[String]) -> Result<(), LifeError> {
        if keywords.len() > MAX_KEYWORDS_PER_ACTION {
            return Err(LifeError::InvalidInput(MSG_KEYWORD_BOUND));
        }
        for keyword in keywords {
            let keyword = keyword.trim();
            if keyword.is_empty() || keyword.chars().count() > MAX_KEYWORD_CHARS {
                return Err(LifeError::InvalidInput(MSG_KEYWORD_BOUND));
            }
        }
        Ok(())
    }
}

/// One bounded mailbox-organization intent: the account and the exact
/// reversible action list. Nothing here can express a permanent
/// deletion or an unsubscribe.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct EmailManagement {
    pub account: String,
    pub actions: Vec<EmailManagementAction>,
}

impl EmailManagement {
    pub fn validate(&self) -> Result<(), LifeError> {
        if self.account.trim().is_empty() || self.account.len() > MAX_ACCOUNT_CHARS {
            return Err(LifeError::InvalidInput(
                "the account selector is out of bounds",
            ));
        }
        if self.actions.is_empty() || self.actions.len() > MAX_MANAGEMENT_ACTIONS {
            return Err(LifeError::InvalidInput(MSG_MANAGEMENT_BOUND));
        }
        // At most one mailbox destination per message: two actions
        // moving the same message into different mailboxes contradict
        // each other, so they refuse before anything journals.
        let mut destinations: std::collections::BTreeMap<String, u8> =
            std::collections::BTreeMap::new();
        for action in &self.actions {
            action.validate()?;
            let (email_id, destination): (&str, u8) = match action {
                EmailManagementAction::Label { .. } => continue,
                EmailManagementAction::Archive { email_id } => (email_id.as_str(), 0),
                EmailManagementAction::Trash { email_id } => (email_id.as_str(), 1),
            };
            match destinations.get(email_id) {
                Some(existing) if *existing != destination => {
                    return Err(LifeError::InvalidInput(MSG_MANAGEMENT_CONFLICT));
                }
                _ => {
                    destinations.insert(email_id.to_owned(), destination);
                }
            }
        }
        Ok(())
    }
}

/// The bounded terminal ids of one managed organization effect: the
/// distinct messages actually updated, in first-action order.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct EmailManagementReceipt {
    pub email_ids: Vec<String>,
}

impl EmailManagementReceipt {
    fn validate(&self) -> Result<(), LifeError> {
        if self.email_ids.is_empty() || self.email_ids.len() > MAX_MANAGEMENT_ACTIONS {
            return Err(LifeError::InvalidInput(MSG_RECEIPT));
        }
        for id in &self.email_ids {
            if id.is_empty() || id.chars().count() > MAX_ID_CHARS {
                return Err(LifeError::InvalidInput(MSG_RECEIPT));
            }
        }
        Ok(())
    }

    /// The canonical result string the durable effect engine records:
    /// the bounded id list encoded as a JSON array text under the
    /// settled result key — the module's single canonical receipt wire
    /// form, decoded only by [`EmailManagementReceipt::from_settled`].
    pub(crate) fn to_result_string(&self) -> Result<String, TransportFault> {
        self.validate()
            .map_err(|_| TransportFault::Protocol(MSG_RECEIPT))?;
        serde_json::to_string(&self.email_ids).map_err(|_| TransportFault::Protocol(MSG_RECEIPT))
    }

    /// Decodes the settled result document of an `email.manage` effect
    /// (fresh or replayed) into its typed receipt. Bounds are
    /// re-verified on read.
    pub fn from_settled(settled: &SettledEffect) -> Result<Self, LifeError> {
        let encoded = settled
            .result
            .get("emailIds")
            .and_then(Value::as_str)
            .ok_or(LifeError::InvalidInput(MSG_RECEIPT))?;
        let email_ids: Vec<String> =
            serde_json::from_str(encoded).map_err(|_| LifeError::InvalidInput(MSG_RECEIPT))?;
        let receipt = Self { email_ids };
        receipt.validate()?;
        Ok(receipt)
    }
}

/// Private transport binding captured at creation, never reconstructed from a
/// mutable remote draft. JMAP Email content is immutable; Gmail sends these
/// exact raw bytes; IMAP must fetch bytes with this digest before SMTP.
#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "transport", rename_all = "camelCase", deny_unknown_fields)]
pub enum DraftContentBinding {
    Jmap { account_id: String },
    Gmail { raw: String },
    Imap { raw_digest: odin_domain::Digest },
}

impl std::fmt::Debug for DraftContentBinding {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Jmap { .. } => "Jmap(immutable Email)",
            Self::Gmail { .. } => "Gmail([REDACTED MIME])",
            Self::Imap { .. } => "Imap(content digest)",
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EmailDraftReceipt {
    pub draft_id: String,
    pub binding: DraftContentBinding,
}

/// The account transport port. Implementations receive only the scoped
/// lease — the credential value is resolved behind it — and report
/// typed faults with static sanitized messages.
pub trait EmailTransport: Send + Sync {
    /// Checks local account and credential readiness without contacting the provider, refreshing, or writing.
    fn readiness(&self, account: &str) -> Result<(), TransportFault>;
    /// At most `query.limit` hits, newest first.
    fn search(
        &self,
        lease: &ScopedCredentialLease,
        query: &EmailSearchQuery,
        now: time::OffsetDateTime,
    ) -> Result<Vec<EmailSummary>, TransportFault>;
    fn read(
        &self,
        lease: &ScopedCredentialLease,
        email_id: &str,
        now: time::OffsetDateTime,
    ) -> Result<Option<EmailMessage>, TransportFault>;
    /// Returns binding evidence from the actual creation exchange, not a later
    /// mutable draft lookup. The adapter persists it privately before exposure.
    fn save_draft(
        &self,
        lease: &ScopedCredentialLease,
        draft: &EmailDraft,
        now: time::OffsetDateTime,
    ) -> Result<EmailDraftReceipt, TransportFault>;
    /// Submits only the receipt's frozen content; refuses another backend's
    /// binding. No implementation may silently fall back to an unbound ID.
    fn send_draft(
        &self,
        lease: &ScopedCredentialLease,
        receipt: &EmailDraftReceipt,
        now: time::OffsetDateTime,
    ) -> Result<String, TransportFault>;
    /// Validates the whole batch before mutation and reports known applied ids on partial failure.
    /// Uncertain outcomes remain in-doubt; implementations must never destroy messages.
    fn manage(
        &self,
        lease: &ScopedCredentialLease,
        management: &EmailManagement,
        now: time::OffsetDateTime,
    ) -> Result<EmailManagementReceipt, BatchFault>;
}

/// Deployment facts of one JMAP mail account, all rendered from
/// Nix/dotfiles configuration. No field has a default.
#[derive(Clone)]
pub struct JmapMailConfig {
    /// The JMAP account id the operations address.
    pub account_id: String,
    /// The submission identity used to send.
    pub identity_id: String,
    /// The From address stamped on saved drafts (the identity's
    /// address, as a deployment fact).
    pub from_address: String,
    /// The drafts mailbox id drafts are created in.
    pub drafts_mailbox_id: String,
    /// The archive mailbox id archived messages move into.
    pub archive_mailbox_id: String,
    /// The trash mailbox id trashed messages move into.
    pub trash_mailbox_id: String,
    /// The account exchange.
    pub exchange: Arc<dyn JmapExchange>,
}

impl JmapMailConfig {
    fn validated(&self) -> Result<(), TransportFault> {
        for field in [
            self.account_id.as_str(),
            self.identity_id.as_str(),
            self.from_address.as_str(),
            self.drafts_mailbox_id.as_str(),
            self.archive_mailbox_id.as_str(),
            self.trash_mailbox_id.as_str(),
        ] {
            if field.trim().is_empty() {
                return Err(TransportFault::Protocol(MSG_CONFIG));
            }
        }
        Ok(())
    }
}

/// The production JMAP email transport: real request builders and
/// response parsers for `Email/query` + `Email/get`, `Email/set`
/// draft creation, and `EmailSubmission/set`. Every response is
/// sanitized against the declared output bounds; anything off-shape is
/// a typed protocol fault, never a fabricated or reduced success.
pub struct JmapEmailTransport {
    config: JmapMailConfig,
}

impl JmapEmailTransport {
    pub fn new(config: JmapMailConfig) -> Result<Self, TransportFault> {
        config.validated()?;
        Ok(Self { config })
    }

    fn using(&self, submission: bool) -> Vec<String> {
        if submission {
            vec![
                JMAP_CORE.to_owned(),
                JMAP_MAIL.to_owned(),
                JMAP_SUBMISSION.to_owned(),
            ]
        } else {
            vec![JMAP_CORE.to_owned(), JMAP_MAIL.to_owned()]
        }
    }
}

fn sanitize_text(
    value: Option<&Value>,
    max_chars: usize,
) -> Result<Option<String>, TransportFault> {
    match value {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(text)) => {
            if text.chars().count() > max_chars {
                Err(TransportFault::Protocol(MSG_BOUND))
            } else {
                Ok(Some(text.clone()))
            }
        }
        Some(_) => Err(TransportFault::Protocol(MSG_SHAPE)),
    }
}

fn required_id(value: Option<&Value>) -> Result<String, TransportFault> {
    match value {
        Some(Value::String(id)) if !id.is_empty() && id.chars().count() <= MAX_ID_CHARS => {
            Ok(id.clone())
        }
        _ => Err(TransportFault::Protocol(MSG_BOUND)),
    }
}

/// The first address of an `EmailAddress[]` field, bounded.
fn first_address(value: Option<&Value>) -> Result<Option<String>, TransportFault> {
    let Some(Value::Array(entries)) = value else {
        return if matches!(value, None | Some(Value::Null)) {
            Ok(None)
        } else {
            Err(TransportFault::Protocol(MSG_SHAPE))
        };
    };
    let Some(entry) = entries.first() else {
        return Ok(None);
    };
    sanitize_text(entry.get("email"), MAX_ADDRESS_CHARS)
}

/// Rechecks capability, account, and expiry before credential-bearing transport calls.
fn check_lease(
    lease: &ScopedCredentialLease,
    operation: &'static str,
    account: &str,
    now: time::OffsetDateTime,
) -> Result<(), TransportFault> {
    lease
        .admits(&capability(operation), account, now)
        .map_err(|_| TransportFault::Refused(MSG_LEASE_REFUSED))
}

const MSG_LEASE_REFUSED: &str = "the credential lease does not bind this operation";

fn method_call<'a>(
    response: &'a crate::jmap::JmapResponse,
    call_id: &str,
) -> Result<&'a Value, TransportFault> {
    let found = response
        .find(call_id)
        .ok_or(TransportFault::Protocol(MSG_SHAPE))?;
    if found.name == "error" {
        return Err(crate::jmap::method_fault(&found.arguments));
    }
    Ok(&found.arguments)
}

impl EmailTransport for JmapEmailTransport {
    /// The exchange holds the bearer file, so it alone can say whether the
    /// bearer is usable.
    fn readiness(&self, _account: &str) -> Result<(), TransportFault> {
        self.config.exchange.readiness()
    }

    fn search(
        &self,
        lease: &ScopedCredentialLease,
        query: &EmailSearchQuery,
        now: time::OffsetDateTime,
    ) -> Result<Vec<EmailSummary>, TransportFault> {
        check_lease(lease, EMAIL_SEARCH_OPERATION, &query.account, now)?;
        let request = JmapRequest {
            using: self.using(false),
            method_calls: vec![
                JmapCall::new(
                    "Email/query",
                    serde_json::json!({
                        "accountId": self.config.account_id,
                        "filter": { "text": query.text.trim() },
                        "sort": [{ "property": "receivedAt", "isAscending": false }],
                        "position": 0,
                        "limit": query.limit,
                    }),
                    "q",
                ),
                JmapCall::new(
                    "Email/get",
                    serde_json::json!({
                        "accountId": self.config.account_id,
                        "#ids": { "resultOf": "q", "name": "Email/query", "path": "/ids" },
                        "properties": ["id", "subject", "receivedAt", "from", "preview"],
                    }),
                    "g",
                ),
            ],
        };
        let response = self.config.exchange.exchange(&request, lease)?;
        let ids: Vec<String> = method_call(&response, "q")?
            .get("ids")
            .and_then(Value::as_array)
            .ok_or(TransportFault::Protocol(MSG_SHAPE))?
            .iter()
            .map(|id| required_id(Some(id)))
            .collect::<Result<_, _>>()?;
        let list = method_call(&response, "g")?
            .get("list")
            .and_then(Value::as_array)
            .ok_or(TransportFault::Protocol(MSG_SHAPE))?;
        if list.len() > ids.len() {
            return Err(TransportFault::Protocol(MSG_SHAPE));
        }
        let mut summaries = Vec::with_capacity(list.len());
        for entry in list {
            summaries.push(EmailSummary {
                id: required_id(entry.get("id"))?,
                subject: sanitize_text(entry.get("subject"), MAX_SUMMARY_SUBJECT_CHARS)?,
                from: first_address(entry.get("from"))?,
                received_at: sanitize_text(entry.get("receivedAt"), MAX_TIMESTAMP_CHARS)?,
                preview: sanitize_text(entry.get("preview"), MAX_PREVIEW_CHARS)?,
            });
        }
        Ok(summaries)
    }

    fn read(
        &self,
        lease: &ScopedCredentialLease,
        email_id: &str,
        now: time::OffsetDateTime,
    ) -> Result<Option<EmailMessage>, TransportFault> {
        check_lease(lease, EMAIL_READ_OPERATION, lease.account(), now)?;
        if email_id.is_empty() || email_id.chars().count() > MAX_ID_CHARS {
            return Err(TransportFault::Protocol(MSG_BOUND));
        }
        let request = JmapRequest {
            using: self.using(false),
            method_calls: vec![JmapCall::new(
                "Email/get",
                serde_json::json!({
                    "accountId": self.config.account_id,
                    "ids": [email_id],
                    "properties": ["id", "subject", "receivedAt", "from", "bodyValues", "textBody"],
                    "bodyProperties": ["partId", "type"],
                    "fetchTextBodyValues": true,
                }),
                "g",
            )],
        };
        let response = self.config.exchange.exchange(&request, lease)?;
        let list = method_call(&response, "g")?
            .get("list")
            .and_then(Value::as_array)
            .ok_or(TransportFault::Protocol(MSG_SHAPE))?
            .clone();
        let Some(entry) = list.first() else {
            // The id is in the notFound set: an absent message is an
            // honest empty answer, never a failure.
            return Ok(None);
        };
        let body_text = match entry
            .get("textBody")
            .and_then(Value::as_array)
            .and_then(|parts| {
                parts
                    .iter()
                    .find(|part| part.get("type").and_then(Value::as_str) == Some("text/plain"))
                    .and_then(|part| part.get("partId").and_then(Value::as_str))
                    .and_then(|part_id| {
                        entry
                            .get("bodyValues")
                            .and_then(|values| values.get(part_id))
                    })
                    .and_then(|body| body.get("value"))
            }) {
            Some(value) => sanitize_text(Some(value), MAX_BODY_CHARS)?,
            None => None,
        };
        Ok(Some(EmailMessage {
            id: required_id(entry.get("id"))?,
            subject: sanitize_text(entry.get("subject"), MAX_SUMMARY_SUBJECT_CHARS)?,
            from: first_address(entry.get("from"))?,
            received_at: sanitize_text(entry.get("receivedAt"), MAX_TIMESTAMP_CHARS)?,
            body_text,
            calendar_invites: Vec::new(),
        }))
    }

    fn save_draft(
        &self,
        lease: &ScopedCredentialLease,
        draft: &EmailDraft,
        now: time::OffsetDateTime,
    ) -> Result<EmailDraftReceipt, TransportFault> {
        check_lease(lease, EMAIL_DRAFT_OPERATION, lease.account(), now)?;
        let mut mailboxes = serde_json::Map::new();
        mailboxes.insert(self.config.drafts_mailbox_id.clone(), Value::Bool(true));
        let request = JmapRequest {
            using: self.using(false),
            method_calls: vec![JmapCall::new(
                "Email/set",
                serde_json::json!({
                    "accountId": self.config.account_id,
                    "create": {
                        "draft": {
                            "mailboxIds": Value::Object(mailboxes),
                            "keywords": { "$draft": true },
                            "from": [{ "email": self.config.from_address }],
                            "to": draft.to.iter()
                                .map(|address| serde_json::json!({ "email": address.trim() }))
                                .collect::<Vec<_>>(),
                            "subject": draft.subject.trim(),
                            "textBody": [{ "partId": "body", "type": "text/plain" }],
                            "bodyValues": { "body": { "value": draft.body_text } },
                        }
                    },
                }),
                "s",
            )],
        };
        let response = self.config.exchange.exchange(&request, lease)?;
        let arguments = method_call(&response, "s")?;
        if arguments
            .get("notCreated")
            .and_then(Value::as_object)
            .is_some_and(|not| !not.is_empty())
        {
            return Err(TransportFault::Protocol(MSG_METHOD_ERROR));
        }
        let draft_id = required_id(
            arguments
                .get("created")
                .and_then(|created| created.get("draft"))
                .and_then(|draft| draft.get("id")),
        )?;
        Ok(EmailDraftReceipt {
            draft_id,
            binding: DraftContentBinding::Jmap {
                account_id: self.config.account_id.clone(),
            },
        })
    }

    fn send_draft(
        &self,
        lease: &ScopedCredentialLease,
        receipt: &EmailDraftReceipt,
        now: time::OffsetDateTime,
    ) -> Result<String, TransportFault> {
        check_lease(lease, EMAIL_SEND_OPERATION, lease.account(), now)?;
        if !matches!(&receipt.binding, DraftContentBinding::Jmap { account_id } if account_id == &self.config.account_id)
        {
            return Err(TransportFault::Refused(
                "the draft content binding does not match this transport",
            ));
        }
        let request = JmapRequest {
            using: self.using(true),
            method_calls: vec![JmapCall::new(
                "EmailSubmission/set",
                serde_json::json!({
                    "accountId": self.config.account_id,
                    "create": {
                        "send": {
                            "identityId": self.config.identity_id,
                            "emailId": receipt.draft_id,
                        }
                    },
                }),
                "m",
            )],
        };
        let response = self.config.exchange.exchange(&request, lease)?;
        let arguments = method_call(&response, "m")?;
        if arguments
            .get("notCreated")
            .and_then(Value::as_object)
            .is_some_and(|not| !not.is_empty())
        {
            return Err(TransportFault::Protocol(MSG_METHOD_ERROR));
        }
        required_id(
            arguments
                .get("created")
                .and_then(|created| created.get("send"))
                .and_then(|submission| submission.get("id")),
        )
    }

    fn manage(
        &self,
        lease: &ScopedCredentialLease,
        management: &EmailManagement,
        now: time::OffsetDateTime,
    ) -> Result<EmailManagementReceipt, BatchFault> {
        check_lease(lease, EMAIL_MANAGE_OPERATION, lease.account(), now)?;
        management
            .validate()
            .map_err(|_| TransportFault::Protocol(MSG_MANAGEMENT_BOUND))?;
        // One `Email/set` whose update map folds the whole recorded
        // intent: Label actions become per-keyword JSON Pointer patches
        // (existing flags are preserved); Archive/Trash replace the
        // mailbox set with exactly the configured destination mailbox.
        // No `destroy` argument is ever built.
        let mut order: Vec<String> = Vec::new();
        let mut keywords: std::collections::BTreeMap<
            String,
            std::collections::BTreeMap<String, Value>,
        > = std::collections::BTreeMap::new();
        let mut mailboxes: std::collections::BTreeMap<String, String> =
            std::collections::BTreeMap::new();
        for action in &management.actions {
            let (id, destination): (&str, Option<&str>) = match action {
                EmailManagementAction::Label {
                    email_id,
                    add_labels,
                    remove_labels,
                } => {
                    let id = email_id.trim().to_owned();
                    if !order.contains(&id) {
                        order.push(id.clone());
                    }
                    let entry = keywords.entry(id).or_default();
                    for keyword in add_labels {
                        entry.insert(keyword.trim().to_owned(), Value::Bool(true));
                    }
                    for keyword in remove_labels {
                        entry.insert(keyword.trim().to_owned(), Value::Null);
                    }
                    continue;
                }
                EmailManagementAction::Archive { email_id } => (
                    email_id.as_str(),
                    Some(self.config.archive_mailbox_id.as_str()),
                ),
                EmailManagementAction::Trash { email_id } => (
                    email_id.as_str(),
                    Some(self.config.trash_mailbox_id.as_str()),
                ),
            };
            let id = id.trim().to_owned();
            if !order.contains(&id) {
                order.push(id.clone());
            }
            if let Some(mailbox) = destination {
                mailboxes.insert(id, mailbox.to_owned());
            }
        }
        let mut update = serde_json::Map::new();
        for id in &order {
            let mut patch = serde_json::Map::new();
            if let Some(keyword_map) = keywords.get(id) {
                for (keyword, value) in keyword_map {
                    patch.insert(
                        format!("keywords/{}", json_pointer_token(keyword)),
                        value.clone(),
                    );
                }
            }
            if let Some(mailbox) = mailboxes.get(id) {
                let mut mailbox_ids = serde_json::Map::new();
                mailbox_ids.insert(mailbox.clone(), Value::Bool(true));
                patch.insert("mailboxIds".to_owned(), Value::Object(mailbox_ids));
            }
            update.insert(id.clone(), Value::Object(patch));
        }
        let request = JmapRequest {
            using: self.using(false),
            method_calls: vec![JmapCall::new(
                "Email/set",
                serde_json::json!({
                    "accountId": self.config.account_id,
                    "update": Value::Object(update),
                }),
                "o",
            )],
        };
        let response = self.config.exchange.exchange(&request, lease)?;
        let arguments = method_call(&response, "o")?;
        // RFC 8620 §5.3: each object is an independent atomic unit, so
        // a rejected id may have shipped beside applied ones — never a
        // reduced success. The ids the reply proves updated stay known.
        let updated = arguments.get("updated").and_then(Value::as_object);
        let applied: Vec<String> = order
            .iter()
            .filter(|id| updated.is_some_and(|updated| updated.contains_key(id.as_str())))
            .cloned()
            .collect();
        if arguments
            .get("notUpdated")
            .and_then(Value::as_object)
            .is_some_and(|not| !not.is_empty())
        {
            return Err(BatchFault::after(
                applied,
                TransportFault::Protocol(MSG_METHOD_ERROR),
            ));
        }
        if updated.is_none() || applied.len() != order.len() {
            return Err(BatchFault::after(
                applied,
                TransportFault::Protocol(MSG_SHAPE),
            ));
        }
        Ok(EmailManagementReceipt { email_ids: applied })
    }
}

/// Escapes one keyword into its JSON Pointer token (RFC 6901): `~`
/// first, then `/`.
fn json_pointer_token(keyword: &str) -> String {
    keyword.replace('~', "~0").replace('/', "~1")
}

/// The email life adapter: the production handler surface for the
/// `email.*` capabilities. Constructed by the runtime with the shared
/// durable ledger, the account transport, and the lease issuer.
pub struct EmailAdapter {
    ledger: Arc<parking_lot::Mutex<odin_ledger::Ledger>>,
    transport: Arc<dyn EmailTransport>,
    leases: Arc<dyn CredentialLeases>,
    issuer: String,
}

impl EmailAdapter {
    pub fn new(
        ledger: Arc<parking_lot::Mutex<odin_ledger::Ledger>>,
        transport: Arc<dyn EmailTransport>,
        leases: Arc<dyn CredentialLeases>,
        issuer: impl Into<String>,
    ) -> Self {
        Self {
            ledger,
            transport,
            leases,
            issuer: issuer.into(),
        }
    }

    /// Checks local credential and provider readiness without issuing a lease; execution rechecks it.
    pub fn credential_readiness(&self, account: &str) -> Result<(), LifeError> {
        self.leases.availability(account).map_err(lease_into_life)?;
        self.transport
            .readiness(account)
            .map_err(crate::account::readiness_into_life)
    }

    /// `email.search` — read-only. No durable effect is recorded.
    pub fn search(
        &self,
        query: &EmailSearchQuery,
        now: time::OffsetDateTime,
    ) -> Result<Vec<EmailSummary>, LifeError> {
        query.validate()?;
        let lease = self
            .leases
            .issue(&capability(EMAIL_SEARCH_OPERATION), &query.account, now)
            .map_err(lease_into_life)?;
        let summaries = self
            .transport
            .search(&lease, query, now)
            .map_err(fault_into_life)?;
        if summaries.len() > query.limit as usize {
            return Err(LifeError::Protocol(MSG_BOUND));
        }
        Ok(summaries)
    }

    /// `email.read` — read-only. `Ok(None)` is an absent message.
    pub fn read(
        &self,
        account: &str,
        email_id: &str,
        now: time::OffsetDateTime,
    ) -> Result<Option<EmailMessage>, LifeError> {
        if account.trim().is_empty() || account.len() > MAX_ACCOUNT_CHARS {
            return Err(LifeError::InvalidInput(
                "the account selector is out of bounds",
            ));
        }
        if email_id.is_empty() || email_id.chars().count() > MAX_ID_CHARS {
            return Err(LifeError::InvalidInput("the email id is out of bounds"));
        }
        let lease = self
            .leases
            .issue(&capability(EMAIL_READ_OPERATION), account, now)
            .map_err(lease_into_life)?;
        self.transport
            .read(&lease, email_id, now)
            .map_err(fault_into_life)
    }

    fn validate_send_account(account: &str) -> Result<(), LifeError> {
        if account.trim().is_empty() || account.len() > MAX_ACCOUNT_CHARS {
            return Err(LifeError::InvalidInput(
                "the account selector is out of bounds",
            ));
        }
        Ok(())
    }

    /// `email.manage` — an ungated durable, reversible organization
    /// effect: record → accept → dispatch → complete under the caller's
    /// identity. The recorded canonical management binds the exact
    /// account and actions, so the same identity with another intent
    /// refuses; a replay returns the recorded receipt and an accepted,
    /// unsettled dispatch stays in doubt. Validation precedes journaling.
    pub fn manage(
        &self,
        identity: &EffectIdentity,
        management: &EmailManagement,
        now: time::OffsetDateTime,
    ) -> Result<SettledEffect, LifeError> {
        management.validate()?;
        let arguments = serde_json::to_value(management)
            .map_err(|_| LifeError::InvalidInput("the management could not be canonicalized"))?;
        crate::account::run_ungated_effect(
            DurableEffect {
                ledger: &self.ledger,
                issuer: &self.issuer,
                identity,
            },
            self.leases.as_ref(),
            EffectRoute {
                capability: &capability(EMAIL_MANAGE_OPERATION),
                account: &management.account,
                result_key: "emailIds",
            },
            arguments,
            now,
            |lease, _arguments| -> Result<String, BatchFault> {
                let receipt = self.transport.manage(lease, management, now)?;
                Ok(receipt.to_result_string()?)
            },
        )
    }

    /// The ledger handle, for the runtime's gate-integration reads.
    pub fn ledger(&self) -> &Arc<parking_lot::Mutex<odin_ledger::Ledger>> {
        &self.ledger
    }
}

mod draft;
pub(crate) use draft::completed_draft;

#[cfg(test)]
mod dispatch_intent_tests {
    //! Intent recording is idempotent, issues no approval, and rejects conflicting effect details.

    use super::*;
    use crate::account::{
        run_ungated_effect, AccountSecretRef, AccountUnavailable, EffectStatus,
        FileCredentialLeases, GateRedirect, HostConsumeProof,
    };
    use odin_domain::{huginn::OpaqueCredentialHandle, ApprovalId, CommandId, EffectClass};
    use odin_kernel::{
        arguments_digest, ApprovalCommand, ApprovalDecision, ApprovalGate, ApprovalScope,
        ConsumeOutcome, DecisionOutcome, NewApproval,
    };
    use odin_ledger::command::CommandTerminalStatus;
    use odin_ledger::Ledger;
    use std::collections::BTreeMap;
    use std::sync::Arc;
    use time::OffsetDateTime;

    const ACCOUNT: &str = "sinmara";
    const SECRET_VALUE: &str = "test-rendered-credential-material";

    fn now() -> OffsetDateTime {
        OffsetDateTime::now_utc()
    }

    /// A deterministic scripted provider: only the settlement calls
    /// run, record their invocations, honor the injected post-accept
    /// fault, and otherwise return fixed ids.
    #[derive(Default)]
    struct ScriptedSend {
        lease_scopes: parking_lot::Mutex<Vec<(String, String)>>,
        draft_calls: parking_lot::Mutex<usize>,
        send_fault: parking_lot::Mutex<Option<TransportFault>>,
        draft_fault: parking_lot::Mutex<Option<TransportFault>>,
    }

    impl EmailTransport for ScriptedSend {
        fn readiness(&self, _account: &str) -> Result<(), TransportFault> {
            Ok(())
        }

        fn search(
            &self,
            _lease: &ScopedCredentialLease,
            _query: &EmailSearchQuery,
            _now: OffsetDateTime,
        ) -> Result<Vec<EmailSummary>, TransportFault> {
            panic!("the send regression never searches")
        }

        fn read(
            &self,
            _lease: &ScopedCredentialLease,
            _email_id: &str,
            _now: OffsetDateTime,
        ) -> Result<Option<EmailMessage>, TransportFault> {
            panic!("the send regression never reads")
        }

        fn save_draft(
            &self,
            _lease: &ScopedCredentialLease,
            _draft: &EmailDraft,
            _now: OffsetDateTime,
        ) -> Result<EmailDraftReceipt, TransportFault> {
            *self.draft_calls.lock() += 1;
            if let Some(fault) = *self.draft_fault.lock() {
                return Err(fault);
            }
            Ok(EmailDraftReceipt {
                draft_id: "draft-1".to_owned(),
                binding: DraftContentBinding::Jmap {
                    account_id: ACCOUNT.to_owned(),
                },
            })
        }

        fn send_draft(
            &self,
            lease: &ScopedCredentialLease,
            receipt: &EmailDraftReceipt,
            _now: OffsetDateTime,
        ) -> Result<String, TransportFault> {
            self.lease_scopes.lock().push((
                lease.capability().as_str().to_owned(),
                lease.account().to_owned(),
            ));
            if let Some(fault) = *self.send_fault.lock() {
                return Err(fault);
            }
            assert_eq!(
                receipt.draft_id, "draft-1",
                "the intent's draft reference dispatches"
            );
            Ok("submission-1".to_owned())
        }

        fn manage(
            &self,
            _lease: &ScopedCredentialLease,
            _management: &EmailManagement,
            _now: time::OffsetDateTime,
        ) -> Result<EmailManagementReceipt, BatchFault> {
            panic!("the send regression never manages")
        }
    }

    fn adapter_world() -> (
        tempfile::TempDir,
        Arc<parking_lot::Mutex<Ledger>>,
        EmailAdapter,
        Arc<ScriptedSend>,
    ) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sinmara-email.secret");
        std::fs::write(&path, SECRET_VALUE).unwrap();
        let leases: Arc<dyn CredentialLeases> =
            Arc::new(FileCredentialLeases::new(BTreeMap::from([(
                ACCOUNT.to_owned(),
                AccountSecretRef::new(
                    OpaqueCredentialHandle::new("cred:sinmara-email").unwrap(),
                    path,
                )
                .unwrap(),
            )])));
        let ledger = Arc::new(parking_lot::Mutex::new(Ledger::open_in_memory().unwrap()));
        let transport = Arc::new(ScriptedSend::default());
        let adapter = EmailAdapter::new(Arc::clone(&ledger), transport.clone(), leases, "test");
        (dir, ledger, adapter, transport)
    }

    fn draft_digest(adapter: &EmailAdapter) -> String {
        adapter
            .save_draft(
                &EffectIdentity {
                    idempotency_key: "bound-fixture".into(),
                    correlation_id: "bound-fixture".into(),
                },
                &EmailDraft {
                    account: ACCOUNT.into(),
                    to: vec!["to@example.invalid".into()],
                    subject: "Approved subject".into(),
                    body_text: "Approved content".into(),
                },
                now(),
            )
            .unwrap()
            .result["draftDigest"]
            .as_str()
            .unwrap()
            .to_owned()
    }

    #[test]
    fn produced_binding_survives_reopen_and_rejects_changed_scope() {
        let (dir, _, original, transport) = adapter_world();
        let path = dir.path().join("bound.sqlite");
        let ledger = Arc::new(parking_lot::Mutex::new(Ledger::open(&path).unwrap()));
        let adapter = EmailAdapter::new(
            ledger.clone(),
            transport.clone(),
            original.leases.clone(),
            "test",
        );
        let digest = draft_digest(&adapter);
        let approved = adapter.approved_draft(ACCOUNT, "draft-1", &digest).unwrap();
        assert_eq!(approved.body_text, "Approved content");
        assert!(adapter
            .approved_draft("other-account", "draft-1", &digest)
            .is_err());
        assert!(adapter
            .approved_draft(ACCOUNT, "draft-changed", &digest)
            .is_err());
        assert!(adapter
            .approved_draft(
                ACCOUNT,
                "draft-1",
                &odin_domain::Digest::hash(b"different bytes").to_string()
            )
            .is_err());
        drop(adapter);
        drop(ledger);
        let ledger = Arc::new(parking_lot::Mutex::new(Ledger::open(&path).unwrap()));
        let adapter = EmailAdapter::new(
            ledger.clone(),
            transport.clone(),
            original.leases.clone(),
            "test",
        );
        assert_eq!(draft_digest(&adapter), digest);
        assert_eq!(
            *transport.draft_calls.lock(),
            1,
            "reopened producer replays privately stored receipt"
        );
        let identity = EffectIdentity {
            idempotency_key: "reopened-send".into(),
            correlation_id: "reopened-send".into(),
        };
        adapter
            .record_send_intent(ACCOUNT, &identity, "draft-1", &digest, now())
            .unwrap();
        let (approval_id, command_id, scope) = dispatch_proof(&ledger);
        let proof = HostConsumeProof {
            approval_id: Some(&approval_id),
            command_id: &command_id,
            scope: &scope,
        };
        let first = adapter
            .settle_send(ACCOUNT, &identity, &proof, now())
            .unwrap();
        assert_eq!(first.result["sentId"], "submission-1");
        assert!(
            adapter
                .settle_send(ACCOUNT, &identity, &proof, now())
                .unwrap()
                .replayed
        );
        assert!(adapter
            .settle_send("other-account", &identity, &proof, now())
            .is_err());
        assert_eq!(transport.lease_scopes.lock().len(), 1);
    }

    #[test]
    fn same_remote_id_never_selects_a_different_content_snapshot() {
        let (_dir, _, adapter, _) = adapter_world();
        let first_digest = draft_digest(&adapter);
        let mut changed = adapter
            .approved_draft(ACCOUNT, "draft-1", &first_digest)
            .unwrap();
        changed.to = vec!["different@example.invalid".into()];
        changed.body_text = "Changed content".into();
        let second = adapter
            .save_draft(
                &EffectIdentity {
                    idempotency_key: "changed-snapshot".into(),
                    correlation_id: "changed-snapshot".into(),
                },
                &changed,
                now(),
            )
            .unwrap();
        let second_digest = second.result["draftDigest"].as_str().unwrap();
        assert_ne!(first_digest, second_digest);
        assert_eq!(
            adapter
                .approved_draft(ACCOUNT, "draft-1", &first_digest)
                .unwrap()
                .body_text,
            "Approved content"
        );
        assert_eq!(
            adapter
                .approved_draft(ACCOUNT, "draft-1", second_digest)
                .unwrap()
                .body_text,
            "Changed content"
        );
        let send = EffectIdentity {
            idempotency_key: "exact-snapshot-send".into(),
            correlation_id: "exact-snapshot-send".into(),
        };
        adapter
            .record_send_intent(ACCOUNT, &send, "draft-1", &first_digest, now())
            .unwrap();
        assert!(adapter
            .record_send_intent(ACCOUNT, &send, "draft-1", second_digest, now())
            .is_err());
    }

    #[test]
    fn historical_id_only_draft_is_not_upgraded_from_remote_state() {
        let (_dir, ledger, adapter, transport) = adapter_world();
        let identity = EffectIdentity {
            idempotency_key: "old-draft".into(),
            correlation_id: "old-draft".into(),
        };
        let draft = EmailDraft {
            account: ACCOUNT.into(),
            to: vec!["to@example.invalid".into()],
            subject: "old".into(),
            body_text: "old".into(),
        };
        run_ungated_effect(
            DurableEffect {
                ledger: &ledger,
                issuer: "test",
                identity: &identity,
            },
            adapter.leases.as_ref(),
            EffectRoute {
                capability: &capability(EMAIL_DRAFT_OPERATION),
                account: ACCOUNT,
                result_key: "draftId",
            },
            serde_json::to_value(&draft).unwrap(),
            now(),
            |_lease, _arguments| Ok::<_, TransportFault>("draft-1".into()),
        )
        .unwrap();
        assert!(adapter.save_draft(&identity, &draft, now()).is_err());
        assert!(adapter
            .approved_draft(ACCOUNT, "draft-1", "unknown")
            .is_err());
        assert_eq!(*transport.draft_calls.lock(), 0);
        assert!(transport.lease_scopes.lock().is_empty());
    }

    #[test]
    fn dispatch_intent_record_mints_no_approval_and_refuses_conflicts() {
        let (_dir, ledger, adapter, _transport) = adapter_world();
        let identity = EffectIdentity {
            idempotency_key: "key-send-1".to_owned(),
            correlation_id: "corr-send-1".to_owned(),
        };

        // The dispatch-path record mints NO approval row: the host
        // kernel gate owns the human decision.
        adapter
            .record_send_intent(
                ACCOUNT,
                &identity,
                "draft-1",
                &draft_digest(&adapter),
                now(),
            )
            .unwrap();
        assert!(
            ledger.lock().approvals().unwrap().is_empty(),
            "the dispatch-path record must never mint an approval row"
        );
        let recorded = ledger
            .lock()
            .command(&identity.command_id().unwrap())
            .unwrap()
            .expect("the intent row is durable");
        assert_eq!(recorded.arguments["account"], serde_json::json!(ACCOUNT));
        assert_eq!(recorded.arguments["draftId"], serde_json::json!("draft-1"));

        // Idempotent under the identity key; conflicting facts refuse.
        adapter
            .record_send_intent(
                ACCOUNT,
                &identity,
                "draft-1",
                &draft_digest(&adapter),
                now(),
            )
            .unwrap_or_else(|error| panic!("the identical record is idempotent: {error}"));
        assert!(
            adapter
                .record_send_intent(
                    ACCOUNT,
                    &identity,
                    "draft-2",
                    &draft_digest(&adapter),
                    now()
                )
                .is_err(),
            "a conflicting draft under one idempotency key must refuse"
        );
    }

    /// The owner's decision request for one journaled host retry, at the
    /// retry's exact scope; returns the requested revision.
    fn request_owner(
        ledger: &Arc<parking_lot::Mutex<Ledger>>,
        approval_id: &ApprovalId,
        scope: &ApprovalScope,
    ) -> i64 {
        ledger
            .lock()
            .request_approval(NewApproval {
                approval_id: approval_id.clone(),
                issuer: "operator:fixture".to_owned(),
                scope: scope.clone(),
                requested_at: now(),
                expires_at: now() + time::Duration::hours(1),
            })
            .unwrap()
            .revision
    }

    /// The operator's decision through the real approval gate.
    fn decide(
        ledger: &Arc<parking_lot::Mutex<Ledger>>,
        approval_id: &ApprovalId,
        revision: i64,
        decision: ApprovalDecision,
    ) -> DecisionOutcome {
        ApprovalGate::new(&mut ledger.lock())
            .decide(approval_id, revision, decision, "operator:fixture", now())
            .unwrap()
    }

    /// The kernel gate leg exactly as the host dispatch consumes: the
    /// operator's decision is requested, decided, and consumed by the
    /// real approval gate at the exact revision — the ONLY consumption.
    fn request_decide_consume(
        ledger: &Arc<parking_lot::Mutex<Ledger>>,
        approval_id: &ApprovalId,
        command_id: &CommandId,
        scope: &ApprovalScope,
    ) {
        let requested = request_owner(ledger, approval_id, scope);
        let approved_revision = match decide(
            ledger,
            approval_id,
            requested,
            ApprovalDecision::Approve { evidence_ref: None },
        ) {
            DecisionOutcome::Approved(approval) => approval.revision,
            other => panic!("the approval must settle, got {other:?}"),
        };
        let mut guard = ledger.lock();
        match ApprovalGate::new(&mut guard)
            .authorize_command(
                EffectClass::R3,
                ApprovalCommand {
                    command_id,
                    approval_id: Some(approval_id),
                    scope,
                    expected_revision: Some(approved_revision),
                    now: now(),
                },
            )
            .unwrap()
        {
            ConsumeOutcome::Consumed(_) => {}
            other => panic!("the host gate must consume exactly this approval, got {other:?}"),
        }
    }

    /// Consumes a fixture approval and returns its command and scope.
    fn dispatch_proof(
        ledger: &Arc<parking_lot::Mutex<Ledger>>,
    ) -> (ApprovalId, CommandId, ApprovalScope) {
        let (approval_id, command_id, scope) = journal_host_retry(ledger, "fixture-dispatch");
        request_decide_consume(ledger, &approval_id, &command_id, &scope);
        (approval_id, command_id, scope)
    }

    /// Journals one host send retry for the recorded intent's draft and
    /// returns the permit coordinates its approval binds; nothing is
    /// requested, decided, or consumed.
    fn journal_host_retry(
        ledger: &Arc<parking_lot::Mutex<Ledger>>,
        tag: &str,
    ) -> (ApprovalId, CommandId, ApprovalScope) {
        let approval_id = ApprovalId::new(format!("approval:r3:email.send:{tag}")).unwrap();
        let command_id = CommandId::new(format!("odin.omp.host_tool:{tag}")).unwrap();
        let digest = ledger
            .lock()
            .commands()
            .unwrap()
            .into_iter()
            .find(|command| {
                command.capability_id.as_str() == EMAIL_SEND_OPERATION
                    && command.target_kind == EMAIL_DRAFT_OPERATION
            })
            .unwrap()
            .arguments["draftDigest"]
            .as_str()
            .unwrap()
            .to_owned();
        let retry_arguments = serde_json::json!({
            "draft_id": "draft-1",
            "account": ACCOUNT,
            "draft_digest": digest,
            "approvalId": approval_id.to_string(),
        });
        let scope = ApprovalScope {
            target_kind: "run".to_owned(),
            target_id: format!("run:{tag}"),
            capability_id: capability(EMAIL_SEND_OPERATION),
            arguments_digest: arguments_digest(&retry_arguments),
        };
        // Production journals the invocation command BEFORE the gate
        // consumes: approvals.consumed_by_command_id is a foreign key
        // into commands.
        ledger
            .lock()
            .record_command(&odin_ledger::command::CommandSpec {
                id: command_id.clone(),
                idempotency_key: command_id.to_string(),
                correlation_id: format!("corr:{tag}"),
                causation_id: None,
                issuer: "operator:fixture".to_owned(),
                approval_id: None,
                target_kind: scope.target_kind.clone(),
                target_id: scope.target_id.clone(),
                capability_id: scope.capability_id.clone(),
                capability_version: 1,
                arguments_hash: scope.arguments_digest,
                arguments: retry_arguments,
                expected_desired_revision: None,
                issued_at: now(),
                expires_at: now() + time::Duration::hours(1),
            })
            .unwrap();
        (approval_id, command_id, scope)
    }

    /// Unconsumed approvals never dispatch; denial and cancellation settle without draft content.
    #[test]
    fn unconsumed_host_approvals_never_dispatch() {
        const DENY_EVIDENCE: &str = "ledger://approvals/deny-fixture";
        let (_dir, ledger, adapter, transport) = adapter_world();
        let digest = draft_digest(&adapter);
        for case in ["requested", "denied", "cancelled"] {
            let identity = EffectIdentity {
                idempotency_key: format!("key-unconsumed-{case}"),
                correlation_id: format!("corr-unconsumed-{case}"),
            };
            adapter
                .record_send_intent(ACCOUNT, &identity, "draft-1", &digest, now())
                .unwrap();
            let (approval_id, command_id, scope) =
                journal_host_retry(&ledger, &format!("unconsumed-{case}"));
            let requested = request_owner(&ledger, &approval_id, &scope);
            if case == "denied" {
                let decision = ApprovalDecision::Deny {
                    evidence_ref: DENY_EVIDENCE.to_owned(),
                };
                assert!(matches!(
                    decide(&ledger, &approval_id, requested, decision),
                    DecisionOutcome::Denied(_)
                ));
            } else if case == "cancelled" {
                let approve = ApprovalDecision::Approve { evidence_ref: None };
                let DecisionOutcome::Approved(approved) =
                    decide(&ledger, &approval_id, requested, approve)
                else {
                    panic!("the fixture approval must settle");
                };
                assert!(ledger
                    .lock()
                    .cancel_unconsumed_approval(&approval_id, now(), approved.revision)
                    .unwrap());
            }
            let proof = HostConsumeProof {
                approval_id: Some(&approval_id),
                command_id: &command_id,
                scope: &scope,
            };
            let outcome = adapter.settle_send(ACCOUNT, &identity, &proof, now());
            let row = ledger
                .lock()
                .command(&identity.command_id().unwrap())
                .unwrap()
                .expect("the intent row");
            match (case, outcome) {
                (
                    "requested",
                    Err(LifeError::Gate(GateRedirect::NeedsApproval {
                        approval_id: Some(named),
                    })),
                ) => {
                    assert_eq!(named, approval_id);
                    assert_eq!(row.terminal_status, None, "an open request settles nothing");
                }
                ("denied", Err(LifeError::Denied(denial))) => {
                    assert_eq!(denial.approval_id, approval_id);
                    assert_eq!(denial.evidence_ref, DENY_EVIDENCE);
                    assert_eq!(denial.decided_by, "operator:fixture");
                    assert_eq!(row.terminal_status, Some(CommandTerminalStatus::Rejected));
                    let result = row.terminal_result.expect("denial result");
                    assert_eq!(result["denied"], true);
                    assert_eq!(result["evidenceRef"], DENY_EVIDENCE);
                    let serialized = result.to_string();
                    assert!(!serialized.contains("Approved content"));
                    assert!(!serialized.contains("Approved subject"));
                }
                (
                    "cancelled",
                    Err(LifeError::Gate(GateRedirect::Cancelled { approval_id: named })),
                ) => {
                    assert_eq!(named, approval_id);
                    assert_eq!(row.terminal_status, Some(CommandTerminalStatus::Rejected));
                    let result = row.terminal_result.expect("cancellation result");
                    assert_eq!(result["cancelled"], true);
                    assert_eq!(result["approvalId"], approval_id.to_string());
                }
                (case, other) => panic!("{case}: unexpected settlement {other:?}"),
            }
        }
        assert!(
            transport.lease_scopes.lock().is_empty(),
            "an unconsumed approval never reaches the provider"
        );
    }

    #[test]
    fn a_missing_credential_settles_rejected_before_any_dispatch() {
        let (dir, ledger, adapter, transport) = adapter_world();
        let identity = EffectIdentity {
            idempotency_key: "key-send-nocred".to_owned(),
            correlation_id: "corr-send-nocred".to_owned(),
        };
        adapter
            .record_send_intent(
                ACCOUNT,
                &identity,
                "draft-1",
                &draft_digest(&adapter),
                now(),
            )
            .unwrap();
        let (approval_id, command_id, scope) = dispatch_proof(&ledger);
        std::fs::remove_file(dir.path().join("sinmara-email.secret")).unwrap();
        let proof = HostConsumeProof {
            approval_id: Some(&approval_id),
            command_id: &command_id,
            scope: &scope,
        };
        assert_eq!(
            adapter.settle_send(ACCOUNT, &identity, &proof, now()),
            Err(LifeError::Unavailable(AccountUnavailable::Credentials))
        );
        let row = ledger
            .lock()
            .command(&identity.command_id().unwrap())
            .unwrap()
            .expect("the intent row");
        assert_eq!(row.terminal_status, Some(CommandTerminalStatus::Rejected));
        let result = row.terminal_result.expect("provably-not-dispatched result");
        assert_eq!(result["executed"], false);
        assert_eq!(result["reason"], "credential-unavailable");
        assert!(transport.lease_scopes.lock().is_empty());
    }

    #[test]
    fn post_accept_unavailable_settles_terminal_failed_gated_and_ungated() {
        let (_dir, ledger, adapter, transport) = adapter_world();

        // Gated leg: the consumed permit's settle reaches an
        // unreachable service AFTER acceptance.
        let identity = EffectIdentity {
            idempotency_key: "key-post-unavailable-gated".to_owned(),
            correlation_id: "corr-post-unavailable-gated".to_owned(),
        };
        adapter
            .record_send_intent(
                ACCOUNT,
                &identity,
                "draft-1",
                &draft_digest(&adapter),
                now(),
            )
            .unwrap();
        let (approval_id, command_id, scope) = dispatch_proof(&ledger);
        *transport.send_fault.lock() =
            Some(TransportFault::Unavailable(AccountUnavailable::Service));
        let proof = crate::account::HostConsumeProof {
            approval_id: Some(&approval_id),
            command_id: &command_id,
            scope: &scope,
        };
        adapter
            .settle_send(ACCOUNT, &identity, &proof, now())
            .unwrap_err();
        let row = ledger
            .lock()
            .command(&identity.command_id().unwrap())
            .unwrap()
            .expect("the gated intent row");
        assert!(
            row.accepted_at.is_some(),
            "the dispatch was accepted before the fault"
        );
        assert_eq!(
            row.terminal_status,
            Some(CommandTerminalStatus::Failed),
            "provably-not-dispatched settles terminal failed"
        );
        assert_eq!(
            row.terminal_result.as_ref().expect("terminal result")["reason"],
            serde_json::json!("service-unavailable")
        );
        let replay = adapter
            .settle_send(ACCOUNT, &identity, &proof, now())
            .expect("the recorded failure replays");
        assert!(replay.replayed);
        assert_eq!(replay.status, EffectStatus::Failed);
        assert_eq!(
            transport.lease_scopes.lock().len(),
            1,
            "a replay never re-dispatches"
        );

        let draft_identity = EffectIdentity {
            idempotency_key: "key-post-unavailable-draft".to_owned(),
            correlation_id: "corr-post-unavailable-draft".to_owned(),
        };
        let draft = EmailDraft {
            account: ACCOUNT.to_owned(),
            to: vec!["to@example.invalid".to_owned()],
            subject: "s".to_owned(),
            body_text: "b".to_owned(),
        };
        *transport.draft_fault.lock() =
            Some(TransportFault::Unavailable(AccountUnavailable::Service));
        adapter
            .save_draft(&draft_identity, &draft, now())
            .unwrap_err();
        let row = ledger
            .lock()
            .command(&draft_identity.command_id().unwrap())
            .unwrap()
            .expect("the ungated intent row");
        assert!(row.accepted_at.is_some());
        assert_eq!(row.terminal_status, Some(CommandTerminalStatus::Failed));
        assert_eq!(
            row.terminal_result.as_ref().expect("terminal result")["reason"],
            serde_json::json!("service-unavailable")
        );
        assert_eq!(*transport.draft_calls.lock(), 2);
        let replay = adapter
            .save_draft(&draft_identity, &draft, now())
            .expect("the recorded failure replays");
        assert!(replay.replayed);
        assert_eq!(
            *transport.draft_calls.lock(),
            2,
            "a replay never re-dispatches"
        );
    }

    #[test]
    fn post_accept_timeout_stays_in_doubt_and_never_repeats_gated_and_ungated() {
        let (_dir, ledger, adapter, transport) = adapter_world();

        // Gated leg.
        let identity = EffectIdentity {
            idempotency_key: "key-post-timeout-gated".to_owned(),
            correlation_id: "corr-post-timeout-gated".to_owned(),
        };
        adapter
            .record_send_intent(
                ACCOUNT,
                &identity,
                "draft-1",
                &draft_digest(&adapter),
                now(),
            )
            .unwrap();
        let (approval_id, command_id, scope) = dispatch_proof(&ledger);
        *transport.send_fault.lock() = Some(TransportFault::Timeout);
        let proof = crate::account::HostConsumeProof {
            approval_id: Some(&approval_id),
            command_id: &command_id,
            scope: &scope,
        };
        assert!(matches!(
            adapter.settle_send(ACCOUNT, &identity, &proof, now()),
            Err(LifeError::Timeout)
        ));
        let row = ledger
            .lock()
            .command(&identity.command_id().unwrap())
            .unwrap()
            .expect("the gated intent row");
        assert!(
            row.accepted_at.is_some(),
            "the dispatch was accepted before the fault"
        );
        assert_eq!(
            row.terminal_status, None,
            "an ambiguous outcome stays nonterminal in-doubt"
        );
        assert_eq!(transport.lease_scopes.lock().len(), 1);
        assert!(matches!(
            adapter.settle_send(ACCOUNT, &identity, &proof, now()),
            Err(LifeError::InDoubt)
        ));
        assert_eq!(
            transport.lease_scopes.lock().len(),
            1,
            "an in-doubt retry never repeats the dispatch"
        );

        // Ungated leg.
        let draft_identity = EffectIdentity {
            idempotency_key: "key-post-timeout-draft".to_owned(),
            correlation_id: "corr-post-timeout-draft".to_owned(),
        };
        let draft = EmailDraft {
            account: ACCOUNT.to_owned(),
            to: vec!["to@example.invalid".to_owned()],
            subject: "s".to_owned(),
            body_text: "b".to_owned(),
        };
        *transport.draft_fault.lock() = Some(TransportFault::Timeout);
        assert!(matches!(
            adapter.save_draft(&draft_identity, &draft, now()),
            Err(LifeError::Timeout)
        ));
        let row = ledger
            .lock()
            .command(&draft_identity.command_id().unwrap())
            .unwrap()
            .expect("the ungated intent row");
        assert!(row.accepted_at.is_some());
        assert_eq!(row.terminal_status, None);
        assert_eq!(*transport.draft_calls.lock(), 2);
        assert!(matches!(
            adapter.save_draft(&draft_identity, &draft, now()),
            Err(LifeError::InDoubt)
        ));
        assert_eq!(
            *transport.draft_calls.lock(),
            2,
            "an in-doubt retry never repeats the save"
        );
    }
}
