//! Approval changes and feed entries commit together so sequence cursors cannot skip transitions.

use odin_domain::{ApprovalId, ApprovalStatus, EventId};
use rusqlite::{params, Connection, OptionalExtension};
use std::str::FromStr;
use time::OffsetDateTime;

use crate::approval::{Approval, ApprovalWire};
use crate::{decode_utc, encode_utc, Ledger, LedgerError, LedgerResult};

/// Page reads filter by this namespace to exclude unrelated events.
pub const APPROVAL_EVENT_NAMESPACE: &str = "approval.";

pub const MAX_APPROVAL_FEED_PAGE: usize = 10_000;

#[derive(Clone, Debug, PartialEq)]
pub struct ApprovalFeedRow {
    pub sequence: i64,
    pub event_id: EventId,
    pub kind: String,
    pub occurred_at: OffsetDateTime,
    pub approval: Approval,
}

pub fn approval_event_kind(status: ApprovalStatus) -> &'static str {
    match status {
        ApprovalStatus::Requested => "approval.requested",
        ApprovalStatus::Approved => "approval.approved",
        ApprovalStatus::Denied => "approval.denied",
        ApprovalStatus::Expired => "approval.expired",
        ApprovalStatus::Consumed => "approval.consumed",
        ApprovalStatus::Cancelled => "approval.cancelled",
    }
}

/// Hash long approval IDs to keep deterministic event IDs within the 128-byte limit.
pub(crate) fn approval_event_id(approval_id: &ApprovalId, revision: i64) -> LedgerResult<EventId> {
    let readable = format!("approval-change:{approval_id}:{revision}");
    EventId::new(readable.as_str())
        .or_else(|_| {
            let digest = odin_domain::Digest::hash(approval_id.to_string().as_bytes()).to_string();
            let short = digest.trim_start_matches("blake3:");
            EventId::new(format!("approval-change:{}:{revision}", &short[..48]).as_str())
        })
        .map_err(|error| {
            LedgerError::invalid_data_caused_by("invalid approval feed event id", error)
        })
}

pub(crate) fn journal_approval_change(
    connection: &Connection,
    approval: &Approval,
    occurred_at: OffsetDateTime,
) -> LedgerResult<()> {
    let wire = ApprovalWire::try_from(approval)?;
    let payload = serde_json::to_string(&wire)?;
    let event_id = approval_event_id(&approval.approval_id, approval.revision)?;
    let actor = serde_json::json!({
        "system": "odin-ledger:approval-feed",
    });
    let kind = approval_event_kind(approval.status);
    let occurred_at = encode_utc(occurred_at)?;
    let inserted = connection.execute(
        "INSERT INTO events
             (event_id, kind, correlation_id, causation_id, actor_json, payload_json, occurred_at)
         VALUES (?1, ?2, ?3, NULL, ?4, ?5, ?6)
         ON CONFLICT(event_id) DO NOTHING",
        params![
            event_id.to_string(),
            kind,
            approval.approval_id.to_string(),
            actor.to_string(),
            payload,
            occurred_at,
        ],
    )?;
    if inserted == 0 {
        // A duplicate ID must have identical data to avoid hiding a divergent transition.
        let existing: (String, String) = connection
            .query_row(
                "SELECT kind, payload_json FROM events WHERE event_id = ?1",
                [event_id.to_string()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?
            .ok_or_else(|| {
                LedgerError::invalid_data(format!(
                    "approval feed event {} conflicted but is unreadable",
                    event_id
                ))
            })?;
        if existing.0 != kind || existing.1 != payload {
            return Err(LedgerError::Conflict(format!(
                "approval feed event {} is already bound to different content",
                event_id
            )));
        }
    }
    Ok(())
}

impl Ledger {
    /// An empty feed returns zero so consumers can use the same cursor for their first page.
    pub fn approval_feed_head(&self) -> LedgerResult<i64> {
        let head: Option<i64> = self
            .connection()
            .query_row(
                "SELECT MAX(sequence) FROM events WHERE kind LIKE 'approval.%'",
                [],
                |row| row.get(0),
            )
            .optional()?
            .flatten();
        Ok(head.unwrap_or(0))
    }

    /// Resume after the last applied sequence to avoid replaying earlier entries.
    pub fn approval_feed_after(
        &self,
        after_sequence: i64,
        limit: usize,
    ) -> LedgerResult<Vec<ApprovalFeedRow>> {
        if after_sequence < 0 {
            return Err(LedgerError::invalid_data(
                "approval feed cursor must be nonnegative".to_owned(),
            ));
        }
        if limit == 0 {
            return Err(LedgerError::invalid_data(
                "approval feed page limit must be positive".to_owned(),
            ));
        }
        let limit = limit.min(MAX_APPROVAL_FEED_PAGE) as i64;
        let mut statement = self.connection().prepare(
            "SELECT sequence, event_id, kind, payload_json, occurred_at
                 FROM events WHERE sequence > ?1 AND kind LIKE 'approval.%'
                 ORDER BY sequence ASC LIMIT ?2",
        )?;
        let rows = statement
            .query_map(params![after_sequence, limit], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                ))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        rows.into_iter()
            .map(|(sequence, event_id, kind, payload, occurred_at)| {
                if !kind.starts_with(APPROVAL_EVENT_NAMESPACE) {
                    return Err(LedgerError::invalid_data(format!(
                        "approval feed row {sequence} has non-approval kind {kind:?}"
                    )));
                }
                let wire: ApprovalWire = serde_json::from_str(&payload)?;
                Ok(ApprovalFeedRow {
                    sequence,
                    event_id: EventId::from_str(&event_id).map_err(|error| {
                        LedgerError::invalid_data_caused_by("invalid approval feed event id", error)
                    })?,
                    kind,
                    occurred_at: decode_utc(&occurred_at)?,
                    approval: wire.into_approval()?,
                })
            })
            .collect()
    }
}

impl Ledger {
    /// Deterministic event IDs prevent backfilling existing approvals from duplicating transitions.
    pub fn backfill_approval_feed_page(
        &mut self,
        after_approval_id: &str,
        limit: usize,
    ) -> LedgerResult<Option<String>> {
        if limit == 0 {
            return Err(LedgerError::invalid_data(
                "approval feed backfill limit must be positive".to_owned(),
            ));
        }
        let limit = limit.min(MAX_APPROVAL_FEED_PAGE) as i64;
        self.with_tx(|transaction| {
            let ids: Vec<String> = {
                let mut statement = transaction.prepare(
                    "SELECT approval_id FROM approvals
                     WHERE approval_id > ?1 ORDER BY approval_id ASC LIMIT ?2",
                )?;
                let rows = statement
                    .query_map(params![after_approval_id, limit], |row| row.get(0))?
                    .collect::<Result<Vec<_>, _>>()?;
                rows
            };
            for id in &ids {
                let approval_id = ApprovalId::from_str(id).map_err(|error| {
                    LedgerError::invalid_data_caused_by("invalid approval id", error)
                })?;
                let approval = crate::approval::load_approval(transaction, &approval_id)?
                    .ok_or_else(|| {
                        LedgerError::invalid_data(format!(
                            "approval {id} disappeared during feed backfill"
                        ))
                    })?;
                let occurred_at = approval.decided_at.unwrap_or(approval.requested_at);
                journal_approval_change(transaction, &approval, occurred_at)?;
            }
            Ok(ids.last().cloned())
        })
    }
}

#[cfg(test)]
mod tests {
    use odin_domain::{ApprovalId, CapabilityId, CommandId, Digest};
    use time::Duration;

    use super::{
        approval_event_kind, params, ApprovalFeedRow, Ledger, APPROVAL_EVENT_NAMESPACE,
        MAX_APPROVAL_FEED_PAGE,
    };
    use crate::approval::{
        ApprovalDecision, ApprovalScope, ConsumeApproval, DecideApproval, NewApproval,
    };
    use crate::LedgerError;

    fn now() -> time::OffsetDateTime {
        time::OffsetDateTime::from_unix_timestamp(1_800_000_000).unwrap()
    }

    fn scope(arguments: &[u8]) -> ApprovalScope {
        ApprovalScope {
            target_kind: "lane".to_owned(),
            target_id: "lane:one".to_owned(),
            capability_id: CapabilityId::new("cap:write").unwrap(),
            arguments_digest: Digest::hash(arguments),
        }
    }

    fn request(ledger: &mut Ledger, id: &str, approval_scope: ApprovalScope) {
        ledger
            .request_approval(NewApproval {
                approval_id: ApprovalId::new(id).unwrap(),
                issuer: "seat:normal".to_owned(),
                scope: approval_scope,
                requested_at: now(),
                expires_at: now() + Duration::minutes(5),
            })
            .unwrap();
    }

    fn approve(ledger: &mut Ledger, id: &str, expected_revision: i64) {
        let result = ledger
            .decide_approval(
                &ApprovalId::new(id).unwrap(),
                ApprovalDecision::Approve { evidence_ref: None },
                "human:one",
                now() + Duration::seconds(1),
                expected_revision,
            )
            .unwrap();
        assert!(matches!(result, DecideApproval::Decided(_)));
    }

    /// Derived feed event IDs must fit within 128 bytes even for long approval IDs.
    #[test]
    fn a_long_approval_id_still_journals_its_request() {
        let mut ledger = Ledger::open_in_memory().unwrap();
        let long = format!(
            "approval:r3:seat.ask.surtr-readme-summary:{}",
            Digest::hash(b"seed")
        );
        assert!(long.len() > 110, "{}", long.len());
        request(&mut ledger, &long, scope(b"long"));
        let stored = ledger
            .approval(&ApprovalId::new(long.as_str()).unwrap())
            .unwrap()
            .expect("the request is stored");
        assert_eq!(stored.revision, 1);
        let short =
            super::approval_event_id(&ApprovalId::new("approval:feed").unwrap(), 2).unwrap();
        assert_eq!(short.to_string(), "approval-change:approval:feed:2");
    }

    #[test]
    fn every_transition_journals_in_order_with_round_tripping_payload() {
        let mut ledger = Ledger::open_in_memory().unwrap();
        let approval_scope = scope(b"payload");
        request(&mut ledger, "approval:feed", approval_scope.clone());
        approve(&mut ledger, "approval:feed", 1);
        let command_id = CommandId::new("command:feed").unwrap();
        // Create the command row required by consumed_by_command_id's foreign key.
        ledger
            .record_command(&crate::command::CommandSpec {
                id: command_id.clone(),
                idempotency_key: format!("idempotency:{command_id}"),
                correlation_id: "correlation:feed".to_owned(),
                causation_id: None,
                issuer: "seat:normal".to_owned(),
                approval_id: Some(ApprovalId::new("approval:feed").unwrap()),
                target_kind: "run".to_owned(),
                target_id: "run:feed-test".to_owned(),
                capability_id: CapabilityId::new("cap:write").unwrap(),
                capability_version: 1,
                arguments_hash: Digest::hash(b"payload"),
                arguments: serde_json::json!({}),
                expected_desired_revision: None,
                issued_at: now(),
                expires_at: now() + Duration::minutes(5),
            })
            .unwrap();
        let consumed = ledger
            .consume_approval(
                &ApprovalId::new("approval:feed").unwrap(),
                &approval_scope,
                &command_id,
                now() + Duration::seconds(2),
                2,
            )
            .unwrap();
        assert!(matches!(consumed, ConsumeApproval::Consumed(_)));

        let rows = ledger.approval_feed_after(0, 100).unwrap();
        assert_eq!(
            rows.iter().map(|row| row.kind.as_str()).collect::<Vec<_>>(),
            vec![
                "approval.requested",
                "approval.approved",
                "approval.consumed"
            ]
        );
        assert!(rows
            .windows(2)
            .all(|pair| pair[0].sequence < pair[1].sequence));
        assert_eq!(rows[0].approval.revision, 1);
        assert_eq!(rows[1].approval.revision, 2);
        assert_eq!(rows[2].approval.revision, 3);
        assert_eq!(rows[2].approval.consumed_by_command_id, Some(command_id));
        assert_eq!(
            ledger.approval_feed_head().unwrap(),
            rows[2].sequence,
            "the durable cursor is the last committed feed sequence"
        );
        for row in &rows {
            assert!(row.kind.starts_with(APPROVAL_EVENT_NAMESPACE));
            assert_eq!(row.kind, approval_event_kind(row.approval.status));
        }
    }

    #[test]
    fn feed_pages_are_bounded_and_the_cursor_walks_every_change_exactly_once() {
        let mut ledger = Ledger::open_in_memory().unwrap();
        for index in 0..25 {
            request(
                &mut ledger,
                &format!("approval:page-{index}"),
                scope(format!("page-{index}").as_bytes()),
            );
        }
        // Mid-life updates move the cursor forward without disturbing order.
        approve(&mut ledger, "approval:page-3", 1);
        approve(&mut ledger, "approval:page-7", 1);

        let head = ledger.approval_feed_head().unwrap();
        assert_eq!(head, 27);
        assert!(matches!(
            ledger.approval_feed_after(-1, 10),
            Err(LedgerError::InvalidData { .. })
        ));

        assert!(matches!(
            ledger.approval_feed_after(0, 0),
            Err(LedgerError::InvalidData { .. })
        ));

        let mut cursor = 0;
        let mut seen = Vec::new();
        loop {
            let page = ledger.approval_feed_after(cursor, 10).unwrap();
            assert!(page.len() <= 10, "one page read stays bounded");
            if page.is_empty() {
                break;
            }
            cursor = page.last().expect("nonempty page").sequence;
            seen.extend(page);
        }
        assert_eq!(seen.len(), 27);
        assert!(seen
            .windows(2)
            .all(|pair| pair[0].sequence < pair[1].sequence));
        // The walk observed every committed change exactly once.
        let approvals_seen = seen
            .iter()
            .filter(|row| row.approval.approval_id.as_str() == "approval:page-3")
            .map(|row| row.kind.as_str())
            .collect::<Vec<_>>();
        // Event sequence order follows commit order.
        assert_eq!(
            approvals_seen,
            vec!["approval.requested", "approval.approved"]
        );
    }

    #[test]
    fn feed_pages_skip_unrelated_events_and_use_the_partial_index() {
        let mut ledger = Ledger::open_in_memory().unwrap();
        request(&mut ledger, "approval:mixed-1", scope(b"mixed-1"));
        // Unrelated journal traffic between approval events: the feed page
        // must skip it without mistaking it for feed input.
        for index in 0..5 {
            ledger
                .connection()
                .execute(
                    "INSERT INTO events
                         (event_id, kind, correlation_id, actor_json, payload_json, occurred_at)
                     VALUES (?1, 'recovery.tick', 'correlation:recovery', '{}', '{}', ?2)",
                    params![
                        format!("event:recovery-{index}"),
                        crate::encode_utc(now()).unwrap(),
                    ],
                )
                .unwrap();
        }
        request(&mut ledger, "approval:mixed-2", scope(b"mixed-2"));
        assert_eq!(ledger.approval_feed_head().unwrap(), 7);

        let plan: Vec<String> = ledger
            .connection()
            .prepare("EXPLAIN QUERY PLAN SELECT sequence, event_id, kind, payload_json, occurred_at FROM events WHERE sequence > 0 AND kind LIKE 'approval.%' ORDER BY sequence ASC LIMIT 10")
            .unwrap()
            .query_map([], |row| row.get::<_, String>(3))
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert!(
            plan.iter()
                .any(|line| line.contains("events_approval_feed_idx")),
            "the feed page must run on the partial index, got: {plan:?}"
        );

        let rows = ledger.approval_feed_after(0, 100).unwrap();
        assert_eq!(
            rows.len(),
            2,
            "unrelated events never masquerade as feed rows"
        );
        assert!(rows
            .iter()
            .all(|row| row.kind.starts_with(super::APPROVAL_EVENT_NAMESPACE)));
        assert_eq!(
            rows.iter()
                .map(|row| row.approval.approval_id.as_str())
                .collect::<Vec<_>>(),
            vec!["approval:mixed-1", "approval:mixed-2"]
        );
    }

    #[test]
    fn ten_thousand_rows_read_bounded_in_one_page() {
        let mut ledger = Ledger::open_in_memory().unwrap();
        for index in 0..10_000i64 {
            request(
                &mut ledger,
                &format!("approval:bulk-{index}"),
                scope(index.to_le_bytes().as_slice()),
            );
        }
        assert_eq!(ledger.approval_feed_head().unwrap(), 10_000);
        let page = ledger.approval_feed_after(0, 100_000).unwrap();
        assert_eq!(page.len(), 10_000);
        assert_eq!(page[0].approval.approval_id.as_str(), "approval:bulk-0");
        assert_eq!(
            page[9_999].approval.approval_id.as_str(),
            "approval:bulk-9999"
        );
        assert_eq!(
            ledger.approval_feed_after(0, 500).unwrap().len(),
            500,
            "the requested page bound is honored verbatim"
        );
        let clamped = ledger
            .approval_feed_after(9_950, MAX_APPROVAL_FEED_PAGE)
            .unwrap();
        assert_eq!(clamped.len(), 50);
    }

    #[test]
    fn feed_cursor_survives_reopen_without_skipping_committed_changes() {
        let path = std::env::temp_dir().join(format!(
            "odin-ledger-approval-feed-{}-{}.sqlite3",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let cursor = {
            let mut ledger = Ledger::open(&path).unwrap();
            request(&mut ledger, "approval:restart", scope(b"restart"));
            let rows: Vec<ApprovalFeedRow> = ledger.approval_feed_after(0, 10).unwrap();
            assert_eq!(rows.len(), 1);
            let cursor = rows[0].sequence;
            // A change committed after the consumer's cursor is durable in
            // the same transaction as its row.
            approve(&mut ledger, "approval:restart", 1);
            cursor
        };
        let ledger = Ledger::open(&path).unwrap();
        assert_eq!(
            ledger.approval_feed_head().unwrap(),
            cursor + 1,
            "restart cannot skip a committed change"
        );
        let missed = ledger.approval_feed_after(cursor, 10).unwrap();
        assert_eq!(missed.len(), 1);
        assert_eq!(missed[0].kind, "approval.approved");
        assert_eq!(missed[0].approval.approval_id.as_str(), "approval:restart");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn backfill_journals_predating_rows_idempotently_in_id_order() {
        let mut ledger = Ledger::open_in_memory().unwrap();
        let digest = Digest::hash(b"legacy").to_string();
        ledger
            .connection()
            .execute(
                "INSERT INTO approvals (
                    approval_id, status, issuer, target_kind, target_id, capability_id,
                    arguments_hash, requested_at, expires_at, revision
                 ) VALUES ('approval:legacy', 'requested', 'seat:normal', 'lane', 'lane:one',
                           'cap:write', ?1, ?2, ?3, 1)",
                params![
                    digest,
                    crate::encode_utc(now()).unwrap(),
                    crate::encode_utc(now() + Duration::minutes(5)).unwrap(),
                ],
            )
            .unwrap();
        assert_eq!(ledger.approval_feed_head().unwrap(), 0);

        // Bounded page: journals the pre-feed row through the same cursor
        // path, then a second pass is a no-op on the deterministic id.
        assert_eq!(
            ledger.backfill_approval_feed_page("", 10).unwrap(),
            Some("approval:legacy".to_owned())
        );
        let head = ledger.approval_feed_head().unwrap();
        let rows = ledger.approval_feed_after(0, 10).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].approval.approval_id.as_str(), "approval:legacy");
        assert_eq!(rows[0].kind, "approval.requested");
        // A second pass re-walks the same rows but the deterministic event
        // ids make it a no-op on the journal.
        assert_eq!(
            ledger.backfill_approval_feed_page("", 10).unwrap(),
            Some("approval:legacy".to_owned())
        );
        assert_eq!(ledger.approval_feed_head().unwrap(), head);
        assert_eq!(ledger.approval_feed_after(0, 10).unwrap().len(), 1);
        // Past the page end: nothing more to discover.
        assert_eq!(
            ledger
                .backfill_approval_feed_page("approval:legacy", 10)
                .unwrap(),
            None
        );
    }
}
