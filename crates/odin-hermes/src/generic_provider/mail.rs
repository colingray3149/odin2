//! The generic provider's IMAP/SMTP mail port: search, read, draft append,
//! frozen-draft submission and non-destructive management over the
//! provider's own IMAP and SMTP sessions.

use super::{
    bounded_chars, build_draft_mime, decode_rfc2047, extract_address, extract_calendar_invites,
    extract_text_body, parse_header_block, parse_message_bounded, resolve_mail_credentials,
    validate_address, validate_keyword, GenericLifeProvider, ImapSession, MailCredentials,
    SmtpSession, MAX_MESSAGE_ID_CHARS, MAX_SMTP_MESSAGE_BYTES, MSG_BOUND, MSG_LEASE_REFUSED,
    MSG_MIME,
};
use crate::account::{BatchFault, ScopedCredentialLease, TransportFault, MAX_ACCOUNT_CHARS};
use crate::email::{
    EmailDraft, EmailManagement, EmailManagementAction, EmailManagementReceipt, EmailMessage,
    EmailSearchQuery, EmailSummary, EmailTransport, EMAIL_DRAFT_OPERATION, EMAIL_MANAGE_OPERATION,
    EMAIL_READ_OPERATION, EMAIL_SEARCH_OPERATION, EMAIL_SEND_OPERATION, MAX_ID_CHARS,
    MAX_KEYWORDS_PER_ACTION, MAX_MANAGEMENT_ACTIONS, MAX_RECIPIENTS, MAX_SEARCH_LIMIT,
    MAX_SEARCH_TEXT_CHARS, MAX_SUMMARY_SUBJECT_CHARS, MIN_SEARCH_LIMIT,
};
use TransportFault::Protocol;

const MSG_DRAFT_MISSING: &str = "the draft message is not present in the drafts mailbox";
const MSG_DRAFT_ORIGIN: &str = "the draft origin does not match the configured from address";
const MSG_MANAGE_EMPTY: &str = "the email management request has no actions";

impl GenericLifeProvider {
    /// Runs one IMAP exchange: lease check, credential resolution,
    /// TLS'd connect, XOAUTH2 authenticate, the caller's flow, and a
    /// best-effort logout.
    fn with_imap<T>(
        &self,
        lease: &ScopedCredentialLease,
        operation: &'static str,
        account: &str,
        now: time::OffsetDateTime,
        flow: impl FnOnce(&mut ImapSession, &MailCredentials) -> Result<T, TransportFault>,
    ) -> Result<T, TransportFault> {
        // This provider serves exactly its configured account; the
        // resolver then re-binds handle, capability, account, and
        // time at the lease.
        if account != self.config.account {
            return Err(TransportFault::Refused(MSG_LEASE_REFUSED));
        }
        let credentials = resolve_mail_credentials(
            &self.config.account,
            &self.config.credential,
            lease,
            operation,
            now,
            self.config.deadline(),
        )?;
        let mut session = ImapSession::connect(
            &self.config.imap,
            self.config.deadline(),
            self.config.max_response_bytes,
        )?;
        let result = session
            .authenticate_xoauth2(&credentials)
            .and_then(|()| flow(&mut session, &credentials));
        session.logout();
        result
    }
}

fn parse_uid(id: &str) -> Result<u32, TransportFault> {
    if id.is_empty() || id.chars().count() > MAX_ID_CHARS {
        return Err(Protocol(MSG_BOUND));
    }
    id.parse::<u32>().map_err(|_| Protocol(MSG_BOUND))
}

/// One management action resolved against the configuration before any
/// connection exists: store patches stay keyword patches, relocations
/// name the configured mailbox. Nothing here can destroy.
enum ManagedOp {
    Store {
        add: Vec<String>,
        remove: Vec<String>,
    },
    MoveTo(String),
}

impl EmailTransport for GenericLifeProvider {
    fn readiness(&self, account: &str) -> Result<(), TransportFault> {
        self.credential_readiness(account)
    }

    fn search(
        &self,
        lease: &ScopedCredentialLease,
        query: &EmailSearchQuery,
        now: time::OffsetDateTime,
    ) -> Result<Vec<EmailSummary>, TransportFault> {
        let text = query.text.trim();
        if text.is_empty()
            || text.chars().count() > MAX_SEARCH_TEXT_CHARS
            || !(MIN_SEARCH_LIMIT..=MAX_SEARCH_LIMIT).contains(&query.limit)
        {
            return Err(Protocol(MSG_BOUND));
        }
        let text = text.to_owned();
        let limit = query.limit as usize;
        self.with_imap(
            lease,
            EMAIL_SEARCH_OPERATION,
            &query.account,
            now,
            |session, _| {
                session.select_mailbox(&self.config.inbox_mailbox_id)?;
                let mut uids = session.uid_search(&text)?;
                if uids.is_empty() {
                    return Ok(Vec::new());
                }
                uids.sort_unstable();
                uids.dedup();
                let start = uids.len().saturating_sub(limit);
                let newest_first: Vec<u32> = uids[start..].iter().rev().copied().collect();
                let fetched = session.uid_fetch_headers(&newest_first)?;
                let mut summaries = Vec::with_capacity(newest_first.len());
                for uid in newest_first {
                    let Some((_, received_at, headers)) =
                        fetched.iter().find(|(found, _, _)| *found == uid)
                    else {
                        continue;
                    };
                    let parsed = parse_header_block(&String::from_utf8_lossy(headers));
                    summaries.push(EmailSummary {
                        id: uid.to_string(),
                        subject: parsed
                            .subject
                            .as_deref()
                            .map(decode_rfc2047)
                            .map(|value| bounded_chars(&value, MAX_SUMMARY_SUBJECT_CHARS)),
                        from: parsed.from.as_deref().and_then(extract_address),
                        received_at: received_at.clone(),
                        preview: None,
                    });
                }
                Ok(summaries)
            },
        )
    }

    fn read(
        &self,
        lease: &ScopedCredentialLease,
        email_id: &str,
        now: time::OffsetDateTime,
    ) -> Result<Option<EmailMessage>, TransportFault> {
        let uid = parse_uid(email_id)?;
        self.with_imap(
            lease,
            EMAIL_READ_OPERATION,
            lease.account(),
            now,
            |session, _| {
                session.select_mailbox(&self.config.inbox_mailbox_id)?;
                let Some((raw, received_at)) = session.uid_fetch_full(uid)? else {
                    return Ok(None);
                };
                let headers = parse_message_bounded(&raw)?;
                let body_text = extract_text_body(&raw, 0)?;
                let calendar_invites = extract_calendar_invites(&raw, 0)?;
                Ok(Some(EmailMessage {
                    id: email_id.to_owned(),
                    subject: headers
                        .subject
                        .as_deref()
                        .map(decode_rfc2047)
                        .map(|value| bounded_chars(&value, MAX_SUMMARY_SUBJECT_CHARS)),
                    from: headers.from.as_deref().and_then(extract_address),
                    received_at,
                    body_text,
                    calendar_invites,
                }))
            },
        )
    }

    fn save_draft(
        &self,
        lease: &ScopedCredentialLease,
        draft: &EmailDraft,
        now: time::OffsetDateTime,
    ) -> Result<crate::email::EmailDraftReceipt, TransportFault> {
        if draft.account.trim().is_empty() || draft.account.len() > MAX_ACCOUNT_CHARS {
            return Err(Protocol(MSG_BOUND));
        }
        if draft.to.is_empty() || draft.to.len() > MAX_RECIPIENTS {
            return Err(Protocol(MSG_BOUND));
        }
        for recipient in &draft.to {
            validate_address(recipient)?;
        }
        self.with_imap(
            lease,
            EMAIL_DRAFT_OPERATION,
            lease.account(),
            now,
            |session, _| {
                let mime = build_draft_mime(
                    &self.config.from_address,
                    &draft.to,
                    &draft.subject,
                    &draft.body_text,
                    now,
                )?;
                let uid = session.uid_append(
                    &self.config.drafts_mailbox_id,
                    "\\Seen \\Draft",
                    mime.bytes.as_bytes(),
                )?;
                Ok(crate::email::EmailDraftReceipt {
                    draft_id: uid.to_string(),
                    binding: crate::email::DraftContentBinding::Imap {
                        raw_digest: odin_domain::Digest::hash(mime.bytes.as_bytes()),
                    },
                })
            },
        )
    }

    fn send_draft(
        &self,
        lease: &ScopedCredentialLease,
        receipt: &crate::email::EmailDraftReceipt,
        now: time::OffsetDateTime,
    ) -> Result<String, TransportFault> {
        let crate::email::DraftContentBinding::Imap { raw_digest } = &receipt.binding else {
            return Err(TransportFault::Refused(
                "the draft content binding does not match this transport",
            ));
        };
        let uid = parse_uid(&receipt.draft_id)?;
        let (raw, _) = self
            .with_imap(
                lease,
                EMAIL_SEND_OPERATION,
                lease.account(),
                now,
                |session, _| {
                    session.select_mailbox(&self.config.drafts_mailbox_id)?;
                    session.uid_fetch_full(uid)
                },
            )?
            .ok_or(Protocol(MSG_DRAFT_MISSING))?;
        submit_bound_draft(&raw, *raw_digest, &self.config.from_address, || {
            let credentials = resolve_mail_credentials(
                &self.config.account,
                &self.config.credential,
                lease,
                EMAIL_SEND_OPERATION,
                now,
                self.config.deadline(),
            )?;
            let mut smtp = SmtpSession::connect(
                &self.config.smtp,
                &self.config.helo_name,
                self.config.deadline(),
            )?;
            if let Err(fault) = smtp.authenticate_xoauth2(&credentials) {
                smtp.quit();
                return Err(fault);
            }
            Ok(smtp)
        })
    }

    fn manage(
        &self,
        lease: &ScopedCredentialLease,
        management: &EmailManagement,
        now: time::OffsetDateTime,
    ) -> Result<EmailManagementReceipt, BatchFault> {
        if management.actions.is_empty() {
            return Err(Protocol(MSG_MANAGE_EMPTY).into());
        }
        if management.actions.len() > MAX_MANAGEMENT_ACTIONS {
            return Err(Protocol(MSG_BOUND).into());
        }
        // Resolve the whole plan first: any invalid action is a typed
        // pre-dispatch refusal, before a single connection exists.
        let mut plan: Vec<(u32, ManagedOp)> = Vec::with_capacity(management.actions.len());
        for action in &management.actions {
            match action {
                EmailManagementAction::Label {
                    email_id,
                    add_labels,
                    remove_labels,
                } => {
                    if add_labels.len() > MAX_KEYWORDS_PER_ACTION
                        || remove_labels.len() > MAX_KEYWORDS_PER_ACTION
                    {
                        return Err(Protocol(MSG_BOUND).into());
                    }
                    for keyword in add_labels.iter().chain(remove_labels.iter()) {
                        validate_keyword(keyword)?;
                    }
                    plan.push((
                        parse_uid(email_id)?,
                        ManagedOp::Store {
                            add: add_labels.clone(),
                            remove: remove_labels.clone(),
                        },
                    ));
                }
                EmailManagementAction::Archive { email_id } => {
                    plan.push((
                        parse_uid(email_id)?,
                        ManagedOp::MoveTo(self.config.archive_mailbox_id.clone()),
                    ));
                }
                EmailManagementAction::Trash { email_id } => {
                    plan.push((
                        parse_uid(email_id)?,
                        ManagedOp::MoveTo(self.config.trash_mailbox_id.clone()),
                    ));
                }
            }
        }
        // Keep each acknowledged mutation's message id, even when a later
        // subcommand of the same label action fails.
        let mut email_ids: Vec<String> = Vec::with_capacity(plan.len());
        self.with_imap(
            lease,
            EMAIL_MANAGE_OPERATION,
            &management.account,
            now,
            |session, _| {
                apply_manage_plan(session, &self.config.inbox_mailbox_id, plan, &mut email_ids)
            },
        )
        .map_err(|fault| BatchFault::after(std::mem::take(&mut email_ids), fault))?;
        Ok(EmailManagementReceipt { email_ids })
    }
}

fn apply_manage_plan(
    session: &mut ImapSession,
    mailbox: &str,
    plan: Vec<(u32, ManagedOp)>,
    email_ids: &mut Vec<String>,
) -> Result<(), TransportFault> {
    session.select_mailbox(mailbox)?;
    for (uid, op) in plan {
        let mut recorded = false;
        let mut record = || {
            if !recorded {
                let id = uid.to_string();
                if !email_ids.contains(&id) {
                    email_ids.push(id);
                }
                recorded = true;
            }
        };
        match &op {
            ManagedOp::Store { add, remove } => {
                session.uid_store(uid, true, add)?;
                if !add.is_empty() {
                    record();
                }
                session.uid_store(uid, false, remove)?;
            }
            ManagedOp::MoveTo(mailbox) => {
                session.uid_move(uid, mailbox)?;
            }
        }
        record();
    }
    Ok(())
}

/// The exact fetched buffer is validated before opening SMTP, then submitted
/// unchanged. The session factory keeps the existing scripted socket seam
/// usable without weakening production TLS or credential checks.
fn submit_bound_draft(
    raw: &[u8],
    raw_digest: odin_domain::Digest,
    from_address: &str,
    open_smtp: impl FnOnce() -> Result<SmtpSession, TransportFault>,
) -> Result<String, TransportFault> {
    if odin_domain::Digest::hash(raw) != raw_digest {
        return Err(TransportFault::Refused(
            "the fetched draft differs from the approved content",
        ));
    }
    if raw.len() > MAX_SMTP_MESSAGE_BYTES {
        return Err(Protocol(MSG_BOUND));
    }
    let message = std::str::from_utf8(raw).map_err(|_| Protocol(MSG_MIME))?;
    let headers = parse_message_bounded(raw)?;
    let message_id = headers
        .message_id
        .filter(|value| !value.is_empty() && value.chars().count() <= MAX_MESSAGE_ID_CHARS)
        .ok_or(Protocol(MSG_MIME))?;
    let envelope_from = headers
        .from
        .as_deref()
        .and_then(extract_address)
        .ok_or(Protocol(MSG_MIME))?;
    if envelope_from != from_address {
        return Err(Protocol(MSG_DRAFT_ORIGIN));
    }
    let recipients: Vec<String> = headers
        .to
        .iter()
        .filter_map(|value| extract_address(value))
        .collect();
    if recipients.is_empty() || recipients.len() > MAX_RECIPIENTS {
        return Err(Protocol(MSG_BOUND));
    }
    for recipient in &recipients {
        validate_address(recipient)?;
    }
    let mut smtp = open_smtp()?;
    let result = smtp.send_message(from_address, &recipients, message);
    smtp.quit();
    result?;
    Ok(message_id)
}

#[cfg(test)]
mod bound_submission_tests {
    use super::submit_bound_draft;
    use crate::account::TransportFault;
    use crate::generic_provider::{
        build_draft_mime, dot_stuff, AccessToken, ImapSession, MailCredentials, SmtpSession,
    };
    use std::io::{BufRead, BufReader, Write};
    use std::net::{TcpListener, TcpStream};

    fn pair() -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        (client, listener.accept().unwrap().0)
    }

    #[test]
    fn acknowledged_label_addition_survives_a_failed_removal() {
        let (client, mut server) = pair();
        client
            .set_read_timeout(Some(std::time::Duration::from_secs(5)))
            .unwrap();
        server
            .set_read_timeout(Some(std::time::Duration::from_secs(5)))
            .unwrap();
        let upstream = std::thread::spawn(move || {
            let mut flags = std::collections::BTreeSet::from(["old".to_owned()]);
            server.write_all(b"* PREAUTH local\r\n").unwrap();
            let mut reader = BufReader::new(server.try_clone().unwrap());
            for step in 0..3 {
                let mut line = String::new();
                reader.read_line(&mut line).unwrap();
                let (tag, command) = line.trim_end().split_once(' ').unwrap();
                match step {
                    0 => {
                        assert!(command.starts_with("SELECT "));
                        write!(server, "* 1 EXISTS\r\n{tag} OK selected\r\n").unwrap();
                    }
                    1 => {
                        assert_eq!(command, "UID STORE 7 +FLAGS.SILENT (new)");
                        flags.insert("new".to_owned());
                        write!(server, "{tag} OK stored\r\n").unwrap();
                    }
                    _ => {
                        assert_eq!(command, "UID STORE 7 -FLAGS.SILENT (old)");
                        write!(server, "{tag} NO removal refused\r\n").unwrap();
                    }
                }
            }
            flags
        });
        let mut session = ImapSession::over_insecure_stream(client, 65_536).unwrap();
        let mut applied = Vec::new();
        let result = super::apply_manage_plan(
            &mut session,
            "INBOX",
            vec![(
                7,
                super::ManagedOp::Store {
                    add: vec!["new".to_owned()],
                    remove: vec!["old".to_owned()],
                },
            )],
            &mut applied,
        );
        let flags = upstream.join().unwrap();
        assert_eq!(
            flags,
            std::collections::BTreeSet::from(["old".to_owned(), "new".to_owned()])
        );
        assert!(result.is_err(), "the full action did not complete");
        assert_eq!(
            applied,
            ["7"],
            "the acknowledged mutation keeps its message id"
        );
    }

    #[test]
    fn fetched_changed_bytes_refuse_before_smtp_and_exact_bytes_are_submitted() {
        let mime = build_draft_mime(
            "from@example.test",
            &["to@example.test".into()],
            "Approved",
            "Exact body",
            time::OffsetDateTime::UNIX_EPOCH,
        )
        .unwrap();
        let digest = odin_domain::Digest::hash(mime.bytes.as_bytes());
        for changed in [true, false] {
            let raw = if changed {
                mime.bytes.replace("Subject: Approved", "Subject: Changed")
            } else {
                mime.bytes.clone()
            };
            let (client, mut server) = pair();
            let script_raw = raw.clone();
            let imap_server = std::thread::spawn(move || {
                server.write_all(b"* PREAUTH local\r\n").unwrap();
                let mut reader = BufReader::new(server.try_clone().unwrap());
                let mut line = String::new();
                reader.read_line(&mut line).unwrap();
                assert_eq!(line, "A001 UID FETCH 7 (UID INTERNALDATE BODY.PEEK[])\r\n");
                write!(
                    server,
                    "* 1 FETCH (UID 7 BODY[] {{{}}}\r\n{})\r\nA001 OK fetched\r\n",
                    script_raw.len(),
                    script_raw
                )
                .unwrap();
            });
            let mut imap = ImapSession::over_insecure_stream(client, 1_000_000).unwrap();
            let (fetched, _) = imap.uid_fetch_full(7).unwrap().unwrap();
            imap_server.join().unwrap();
            if changed {
                assert!(matches!(
                    submit_bound_draft(&fetched, digest, "from@example.test", || panic!(
                        "changed content must never open SMTP"
                    )),
                    Err(TransportFault::Refused(_))
                ));
                continue;
            }
            let (smtp_client, mut smtp_server) = pair();
            let expected = dot_stuff(&raw);
            let smtp_thread = std::thread::spawn(move || {
                smtp_server.write_all(b"220 ready\r\n").unwrap();
                let mut reader = BufReader::new(smtp_server.try_clone().unwrap());
                for (prefix, reply) in [
                    ("EHLO ", "250-AUTH XOAUTH2\r\n250 OK\r\n"),
                    ("AUTH XOAUTH2 ", "235 authenticated\r\n"),
                    ("MAIL FROM:<from@example.test>", "250 sender\r\n"),
                    ("RCPT TO:<to@example.test>", "250 recipient\r\n"),
                    ("DATA", "354 data\r\n"),
                ] {
                    let mut line = String::new();
                    reader.read_line(&mut line).unwrap();
                    assert!(line.starts_with(prefix));
                    smtp_server.write_all(reply.as_bytes()).unwrap();
                }
                let mut data = String::new();
                loop {
                    let mut line = String::new();
                    assert!(reader.read_line(&mut line).unwrap() > 0);
                    if line == ".\r\n" {
                        break;
                    }
                    data.push_str(&line);
                }
                assert_eq!(data, expected);
                smtp_server.write_all(b"250 sent\r\n").unwrap();
                let mut quit = String::new();
                reader.read_line(&mut quit).unwrap();
                assert_eq!(quit, "QUIT\r\n");
            });
            submit_bound_draft(&fetched, digest, "from@example.test", || {
                let mut session = SmtpSession::over_insecure_stream(smtp_client)?;
                session.ehlo("local")?;
                session.authenticate_xoauth2(&MailCredentials {
                    account: "local".into(),
                    user: "local".into(),
                    access_token: AccessToken("local-token".into()),
                    caldav_basic: None,
                })?;
                Ok(session)
            })
            .unwrap();
            smtp_thread.join().unwrap();
        }
    }
}
