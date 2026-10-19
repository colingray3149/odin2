//! The Gmail API v1 mail port of the Google provider: search, read, frozen
//! raw-MIME drafts and their exact submission, and label/archive/trash
//! management, with the message parsing and encoding only mail needs.

use serde_json::Value;
use time::format_description::well_known::Rfc3339;
use time::{OffsetDateTime, UtcOffset};

use super::{
    bounded_text, required_id, GoogleMethod, GoogleProvider, MAX_ATTACHMENT_NAME_CHARS,
    MAX_MIME_DEPTH, MAX_MIME_PARTS, MSG_BODY, MSG_INPUT, MSG_NOT_FOUND, MSG_PARSE, MSG_REJECTED,
};
use crate::account::{BatchFault, ScopedCredentialLease, TransportFault};
use crate::calendar::MAX_TIMESTAMP_CHARS;
use crate::email::{
    parse_ical_invites, CalendarInvite, EmailDraft, EmailManagement, EmailManagementReceipt,
    EmailMessage, EmailSearchQuery, EmailSummary, EmailTransport, EMAIL_DRAFT_OPERATION,
    EMAIL_MANAGE_OPERATION, EMAIL_READ_OPERATION, EMAIL_SEARCH_OPERATION, EMAIL_SEND_OPERATION,
    MAX_CALENDAR_INVITES,
};

const MSG_MIME: &str = "the Gmail message MIME could not be decoded";
const MSG_HEADER: &str = "the draft header contains a line break";

/// The first address of an RFC 5322 From header value: the
/// angle-bracket addr-spec when present, the raw value otherwise.
fn address_of(raw: &str) -> Result<Option<String>, TransportFault> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }
    let address = match (trimmed.find('<'), trimmed.rfind('>')) {
        (Some(open), Some(close)) if close > open => trimmed[open + 1..close].trim(),
        _ => trimmed,
    };
    if address.is_empty() || address.chars().count() > crate::email::MAX_ADDRESS_CHARS {
        return Err(TransportFault::Protocol(MSG_BODY));
    }
    Ok(Some(address.to_owned()))
}

/// One bounded Gmail message header by name. Gmail returns these under
/// `payload.headers` for both `metadata` and `full` formats.
fn header<'a>(message: &'a Value, name: &str) -> Option<&'a str> {
    message
        .get("payload")?
        .get("headers")?
        .as_array()?
        .iter()
        .find_map(|entry| {
            let matches = entry.get("name").and_then(Value::as_str)? == name;
            matches.then(|| entry.get("value").and_then(Value::as_str))?
        })
}

/// The Gmail `internalDate` field: decimal milliseconds (string or
/// number).
fn internal_date_ms(message: &Value) -> Option<i64> {
    match message.get("internalDate") {
        Some(Value::String(text)) => text.parse::<i64>().ok(),
        Some(Value::Number(number)) => number.as_i64(),
        _ => None,
    }
}

/// [`internal_date_ms`] rendered as a bounded RFC 3339 UTC instant.
fn received_at(message: &Value) -> Result<Option<String>, TransportFault> {
    let Some(milliseconds) = internal_date_ms(message) else {
        return Ok(None);
    };
    let instant = OffsetDateTime::from_unix_timestamp(milliseconds.div_euclid(1_000))
        .map_err(|_| TransportFault::Protocol(MSG_PARSE))?
        + time::Duration::milliseconds(milliseconds.rem_euclid(1_000));
    let rendered = instant
        .to_offset(UtcOffset::UTC)
        .format(&Rfc3339)
        .map_err(|_| TransportFault::Protocol(MSG_PARSE))?;
    if rendered.chars().count() > MAX_TIMESTAMP_CHARS {
        return Err(TransportFault::Protocol(MSG_BODY));
    }
    Ok(Some(rendered))
}

/// Parses the Gmail `payload` MIME tree far enough for provider use:
/// the first inline `text/plain` part becomes the bounded body text;
/// attachment parts are recognized by filename and skipped (metadata
/// only — attachment bytes are never fetched or ingested); the tree is
/// depth- and node-bounded.
fn parse_body_text(payload: &Value) -> Result<Option<String>, TransportFault> {
    struct Walk {
        nodes: usize,
        body_text: Option<String>,
    }
    fn walk(part: &Value, state: &mut Walk, depth: usize) -> Result<(), TransportFault> {
        state.nodes += 1;
        if depth > MAX_MIME_DEPTH || state.nodes > MAX_MIME_PARTS {
            return Err(TransportFault::Protocol(MSG_BODY));
        }
        let filename = part
            .get("filename")
            .and_then(Value::as_str)
            .unwrap_or_default();
        if !filename.is_empty() && filename.chars().count() > MAX_ATTACHMENT_NAME_CHARS {
            return Err(TransportFault::Protocol(MSG_BODY));
        }
        let mime_type = part
            .get("mimeType")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let data = part
            .get("body")
            .and_then(|body| body.get("data"))
            .and_then(Value::as_str);
        if filename.is_empty() && mime_type == "text/plain" && state.body_text.is_none() {
            if let Some(data) = data {
                let decoded = base64url_decode(data).ok_or(TransportFault::Protocol(MSG_MIME))?;
                let text =
                    String::from_utf8(decoded).map_err(|_| TransportFault::Protocol(MSG_MIME))?;
                if text.chars().count() > crate::email::MAX_BODY_CHARS {
                    return Err(TransportFault::Protocol(MSG_BODY));
                }
                state.body_text = Some(text);
            }
        }
        if let Some(parts) = part.get("parts").and_then(Value::as_array) {
            for child in parts {
                walk(child, state, depth + 1)?;
            }
        }
        Ok(())
    }
    let mut state = Walk {
        nodes: 0,
        body_text: None,
    };
    walk(payload, &mut state, 0)?;
    Ok(state.body_text)
}

/// Extracts bounded inline `text/calendar` parts from Gmail's MIME tree.
/// Attachment ids are never fetched implicitly; an invite already carried in
/// the full-message payload becomes a structured read-only projection.
fn parse_calendar_invites(payload: &Value) -> Result<Vec<CalendarInvite>, TransportFault> {
    fn walk(
        part: &Value,
        invitations: &mut Vec<CalendarInvite>,
        nodes: &mut usize,
        depth: usize,
    ) -> Result<(), TransportFault> {
        *nodes += 1;
        if depth > MAX_MIME_DEPTH || *nodes > MAX_MIME_PARTS {
            return Err(TransportFault::Protocol(MSG_BODY));
        }
        let mime_type = part
            .get("mimeType")
            .and_then(Value::as_str)
            .unwrap_or_default();
        if mime_type.eq_ignore_ascii_case("text/calendar") {
            if let Some(data) = part
                .get("body")
                .and_then(|body| body.get("data"))
                .and_then(Value::as_str)
            {
                let decoded = base64url_decode(data).ok_or(TransportFault::Protocol(MSG_MIME))?;
                let text =
                    String::from_utf8(decoded).map_err(|_| TransportFault::Protocol(MSG_MIME))?;
                invitations.extend(
                    parse_ical_invites(&text).map_err(|_| TransportFault::Protocol(MSG_MIME))?,
                );
                if invitations.len() > MAX_CALENDAR_INVITES {
                    return Err(TransportFault::Protocol(MSG_BODY));
                }
            }
        }
        if let Some(parts) = part.get("parts").and_then(Value::as_array) {
            for child in parts {
                walk(child, invitations, nodes, depth + 1)?;
            }
        }
        Ok(())
    }

    let mut invitations = Vec::new();
    let mut nodes = 0usize;
    walk(payload, &mut invitations, &mut nodes, 0)?;
    Ok(invitations)
}

/// RFC 4648 §5 base64url encode with padding (the Gmail `raw` shape).
fn base64url_encode(data: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let value = (u32::from(chunk[0]) << 16)
            | (u32::from(*chunk.get(1).unwrap_or(&0)) << 8)
            | u32::from(*chunk.get(2).unwrap_or(&0));
        out.push(ALPHABET[(value >> 18) as usize & 63] as char);
        out.push(ALPHABET[(value >> 12) as usize & 63] as char);
        if chunk.len() > 1 {
            out.push(ALPHABET[(value >> 6) as usize & 63] as char);
        } else {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(ALPHABET[value as usize & 63] as char);
        } else {
            out.push('=');
        }
    }
    out
}

/// Strict base64url decode (Gmail payload `data`): no whitespace, no
/// standard-alphabet characters; padding terminates the input.
fn base64url_decode(text: &str) -> Option<Vec<u8>> {
    let mut accumulator: u32 = 0;
    let mut bits: u32 = 0;
    let mut out = Vec::with_capacity(text.len() / 4 * 3);
    for byte in text.bytes() {
        let value = match byte {
            b'A'..=b'Z' => byte - b'A',
            b'a'..=b'z' => byte - b'a' + 26,
            b'0'..=b'9' => byte - b'0' + 52,
            b'-' => 62,
            b'_' => 63,
            b'=' => break,
            _ => return None,
        };
        accumulator = (accumulator << 6) | u32::from(value);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((accumulator >> bits) as u8);
        }
    }
    Some(out)
}

/// Builds the RFC 5322 text/plain draft message Gmail stores as the
/// `raw` draft. Header values are line-break guarded; the body is the
/// operator-visible content and is carried verbatim.
fn draft_mime(draft: &EmailDraft) -> Result<String, TransportFault> {
    let line_break = |value: &str| value.contains('\r') || value.contains('\n');
    if line_break(&draft.subject) {
        return Err(TransportFault::Protocol(MSG_HEADER));
    }
    for address in &draft.to {
        if line_break(address) {
            return Err(TransportFault::Protocol(MSG_HEADER));
        }
    }
    let mut mime = String::new();
    mime.push_str("MIME-Version: 1.0\r\n");
    let recipients = draft
        .to
        .iter()
        .map(|address| address.trim())
        .collect::<Vec<_>>()
        .join(", ");
    mime.push_str(&format!("To: {recipients}\r\n"));
    mime.push_str(&format!("Subject: {}\r\n", draft.subject.trim()));
    mime.push_str("Content-Type: text/plain; charset=\"UTF-8\"\r\n");
    mime.push_str("Content-Transfer-Encoding: 8bit\r\n");
    mime.push_str("\r\n");
    mime.push_str(&draft.body_text);
    Ok(mime)
}

impl EmailTransport for GoogleProvider {
    fn readiness(&self, account: &str) -> Result<(), TransportFault> {
        self.token_readiness(account)
    }

    fn search(
        &self,
        lease: &ScopedCredentialLease,
        query: &EmailSearchQuery,
        now: OffsetDateTime,
    ) -> Result<Vec<EmailSummary>, TransportFault> {
        use crate::email::{
            MAX_ID_CHARS, MAX_PREVIEW_CHARS, MAX_SEARCH_TEXT_CHARS, MAX_SUMMARY_SUBJECT_CHARS,
        };
        self.check_lease(lease, EMAIL_SEARCH_OPERATION, &query.account, now)?;
        let text = query.text.trim();
        if text.is_empty() || text.chars().count() > MAX_SEARCH_TEXT_CHARS {
            return Err(TransportFault::Protocol(MSG_INPUT));
        }
        let access = self.access_token(now)?;
        let max_results = query.limit.to_string();
        let url = self.gmail_url(
            &["users", "me", "messages"],
            &[("q", text), ("maxResults", max_results.as_str())],
        )?;
        let response = self.call(GoogleMethod::Get, url, None, &access)?;
        if response.status != 200 {
            return Err(TransportFault::Protocol(MSG_REJECTED));
        }
        let ids: Vec<String> = match response.body.get("messages").and_then(Value::as_array) {
            Some(entries) => {
                let ids = entries
                    .iter()
                    .map(|entry| required_id(entry.get("id"), MAX_ID_CHARS))
                    .collect::<Result<Vec<_>, _>>()?;
                if ids.len() > query.limit as usize {
                    return Err(TransportFault::Protocol(MSG_BODY));
                }
                ids
            }
            // An absent result list is an honest empty page.
            None => Vec::new(),
        };
        let mut hits = Vec::with_capacity(ids.len());
        for id in &ids {
            let url = self.gmail_url(
                &["users", "me", "messages", id],
                &[
                    ("format", "metadata"),
                    ("metadataHeaders", "Subject"),
                    ("metadataHeaders", "From"),
                ],
            )?;
            let response = self.call(GoogleMethod::Get, url, None, &access)?;
            if response.status != 200 {
                return Err(TransportFault::Protocol(MSG_REJECTED));
            }
            let message = &response.body;
            let subject = header(message, "Subject").map(|value| Value::String(value.to_owned()));
            let from = match header(message, "From") {
                Some(raw) => address_of(raw)?,
                None => None,
            };
            hits.push((
                internal_date_ms(message),
                EmailSummary {
                    id: required_id(message.get("id"), MAX_ID_CHARS)?,
                    subject: bounded_text(subject.as_ref(), MAX_SUMMARY_SUBJECT_CHARS)?,
                    from,
                    received_at: received_at(message)?,
                    preview: bounded_text(message.get("snippet"), MAX_PREVIEW_CHARS)?,
                },
            ));
        }
        // Newest first, as the JMAP adapter sorts: Gmail documents no list
        // order, and Sinmara reads the first hit as "the most recent"
        // (production 10-04: a 2023 registrar mail was answered as the
        // latest while a Sep 29 one was in the same page).
        hits.sort_by_key(|(received, _)| std::cmp::Reverse(*received));
        Ok(hits.into_iter().map(|(_, summary)| summary).collect())
    }

    fn read(
        &self,
        lease: &ScopedCredentialLease,
        email_id: &str,
        now: OffsetDateTime,
    ) -> Result<Option<EmailMessage>, TransportFault> {
        use crate::email::{MAX_ID_CHARS, MAX_SUMMARY_SUBJECT_CHARS};
        self.check_lease(lease, EMAIL_READ_OPERATION, lease.account(), now)?;
        if email_id.is_empty() || email_id.chars().count() > MAX_ID_CHARS {
            return Err(TransportFault::Protocol(MSG_INPUT));
        }
        let access = self.access_token(now)?;
        let url = self.gmail_url(
            &["users", "me", "messages", email_id],
            &[("format", "full")],
        )?;
        let response = self.call(GoogleMethod::Get, url, None, &access)?;
        if response.status == 404 {
            // An absent message is an honest empty answer.
            return Ok(None);
        }
        if response.status != 200 {
            return Err(TransportFault::Protocol(MSG_REJECTED));
        }
        let message = &response.body;
        let subject = header(message, "Subject").map(|value| Value::String(value.to_owned()));
        let from = match header(message, "From") {
            Some(raw) => address_of(raw)?,
            None => None,
        };
        let payload = message
            .get("payload")
            .ok_or(TransportFault::Protocol(MSG_PARSE))?;
        let body_text = parse_body_text(payload)?;
        let calendar_invites = parse_calendar_invites(payload)?;
        Ok(Some(EmailMessage {
            id: required_id(message.get("id"), MAX_ID_CHARS)?,
            subject: bounded_text(subject.as_ref(), MAX_SUMMARY_SUBJECT_CHARS)?,
            from,
            received_at: received_at(message)?,
            body_text,
            calendar_invites,
        }))
    }

    fn save_draft(
        &self,
        lease: &ScopedCredentialLease,
        draft: &EmailDraft,
        now: OffsetDateTime,
    ) -> Result<crate::email::EmailDraftReceipt, TransportFault> {
        use crate::email::{MAX_ADDRESS_CHARS, MAX_ID_CHARS, MAX_RECIPIENTS};
        self.check_lease(lease, EMAIL_DRAFT_OPERATION, lease.account(), now)?;
        if draft.to.is_empty() || draft.to.len() > MAX_RECIPIENTS {
            return Err(TransportFault::Protocol(MSG_INPUT));
        }
        for address in &draft.to {
            if address.trim().is_empty() || address.chars().count() > MAX_ADDRESS_CHARS {
                return Err(TransportFault::Protocol(MSG_INPUT));
            }
        }
        let mime = draft_mime(draft)?;
        let raw = base64url_encode(mime.as_bytes());
        let access = self.effect_access_token(now)?;
        let url = self.gmail_url(&["users", "me", "drafts"], &[])?;
        let response = self.call(
            GoogleMethod::Post,
            url,
            Some(serde_json::json!({
                "message": { "raw": raw },
            })),
            &access,
        )?;
        if response.status != 200 {
            return Err(TransportFault::Protocol(MSG_REJECTED));
        }
        Ok(crate::email::EmailDraftReceipt {
            draft_id: required_id(response.body.get("id"), MAX_ID_CHARS)?,
            binding: crate::email::DraftContentBinding::Gmail { raw },
        })
    }

    fn send_draft(
        &self,
        lease: &ScopedCredentialLease,
        receipt: &crate::email::EmailDraftReceipt,
        now: OffsetDateTime,
    ) -> Result<String, TransportFault> {
        use crate::email::MAX_ID_CHARS;
        self.check_lease(lease, EMAIL_SEND_OPERATION, lease.account(), now)?;
        let crate::email::DraftContentBinding::Gmail { raw } = &receipt.binding else {
            return Err(TransportFault::Refused(
                "the draft content binding does not match this transport",
            ));
        };
        let draft_id = &receipt.draft_id;
        if draft_id.is_empty() || draft_id.chars().count() > MAX_ID_CHARS {
            return Err(TransportFault::Protocol(MSG_INPUT));
        }
        let access = self.effect_access_token(now)?;
        let url = self.gmail_url(&["users", "me", "drafts", "send"], &[])?;
        let response = self.call(
            GoogleMethod::Post,
            url,
            Some(serde_json::json!({ "id": draft_id, "message": { "raw": raw } })),
            &access,
        )?;
        if response.status != 200 {
            return Err(TransportFault::Protocol(MSG_REJECTED));
        }
        required_id(response.body.get("id"), MAX_ID_CHARS)
    }

    fn manage(
        &self,
        lease: &ScopedCredentialLease,
        management: &EmailManagement,
        now: OffsetDateTime,
    ) -> Result<EmailManagementReceipt, BatchFault> {
        use crate::email::{
            EmailManagementAction, MAX_KEYWORDS_PER_ACTION, MAX_KEYWORD_CHARS,
            MAX_MANAGEMENT_ACTIONS,
        };
        self.check_lease(lease, EMAIL_MANAGE_OPERATION, &management.account, now)?;
        if management.actions.is_empty() || management.actions.len() > MAX_MANAGEMENT_ACTIONS {
            return Err(TransportFault::Protocol(MSG_INPUT).into());
        }
        // The whole batch validates before the first call: a partial
        // batch only ever follows an action that applied.
        for action in &management.actions {
            match action {
                EmailManagementAction::Label {
                    email_id,
                    add_labels,
                    remove_labels,
                } => {
                    self.check_manage_id(email_id)?;
                    for label in add_labels.iter().chain(remove_labels.iter()) {
                        if label.is_empty() || label.chars().count() > MAX_KEYWORD_CHARS {
                            return Err(TransportFault::Protocol(MSG_INPUT).into());
                        }
                    }
                    if add_labels.len() > MAX_KEYWORDS_PER_ACTION
                        || remove_labels.len() > MAX_KEYWORDS_PER_ACTION
                        || add_labels.iter().any(|label| remove_labels.contains(label))
                    {
                        return Err(TransportFault::Protocol(MSG_INPUT).into());
                    }
                }
                EmailManagementAction::Archive { email_id }
                | EmailManagementAction::Trash { email_id } => self.check_manage_id(email_id)?,
            }
        }
        let access = self.effect_access_token(now)?;
        let mut email_ids = Vec::with_capacity(management.actions.len());
        for action in &management.actions {
            let id = self
                .manage_one(action, &access)
                .map_err(|fault| BatchFault::after(std::mem::take(&mut email_ids), fault))?;
            email_ids.push(id);
        }
        Ok(EmailManagementReceipt { email_ids })
    }
}

impl GoogleProvider {
    /// Applies one validated mailbox action; its id is known only from a
    /// 200 reply.
    fn manage_one(
        &self,
        action: &crate::email::EmailManagementAction,
        access: &super::AccessToken,
    ) -> Result<String, TransportFault> {
        use crate::email::{EmailManagementAction, MAX_ID_CHARS};
        let response = match action {
            EmailManagementAction::Label {
                email_id,
                add_labels,
                remove_labels,
            } => {
                let url = self.gmail_url(&["users", "me", "messages", email_id, "modify"], &[])?;
                self.call(
                    GoogleMethod::Post,
                    url,
                    Some(serde_json::json!({
                        "addLabelIds": add_labels,
                        "removeLabelIds": remove_labels,
                    })),
                    access,
                )?
            }
            EmailManagementAction::Archive { email_id } => {
                let url = self.gmail_url(&["users", "me", "messages", email_id, "modify"], &[])?;
                self.call(
                    GoogleMethod::Post,
                    url,
                    Some(serde_json::json!({ "removeLabelIds": ["INBOX"] })),
                    access,
                )?
            }
            EmailManagementAction::Trash { email_id } => {
                let url = self.gmail_url(&["users", "me", "messages", email_id, "trash"], &[])?;
                self.call(GoogleMethod::Post, url, None, access)?
            }
        };
        if response.status == 404 {
            return Err(TransportFault::Protocol(MSG_NOT_FOUND));
        }
        if response.status != 200 {
            return Err(TransportFault::Protocol(MSG_REJECTED));
        }
        required_id(response.body.get("id"), MAX_ID_CHARS)
    }

    /// Builds an absolute Gmail API URL from path segments and query
    /// pairs, percent-encoding each segment.
    fn gmail_url(
        &self,
        segments: &[&str],
        query: &[(&str, &str)],
    ) -> Result<String, TransportFault> {
        self.build_url(&self.config.gmail_api_url, segments, query)
    }

    fn check_manage_id(&self, email_id: &str) -> Result<(), TransportFault> {
        use crate::email::MAX_ID_CHARS;
        if email_id.is_empty() || email_id.chars().count() > MAX_ID_CHARS {
            return Err(TransportFault::Protocol(MSG_INPUT));
        }
        Ok(())
    }
}
