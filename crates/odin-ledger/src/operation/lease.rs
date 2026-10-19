//! Durable capsule leases: open, strictly-newer verified-authority rebind,
//! one-shot issuance pinning, the single rebind audit event, observation,
//! and close.

use odin_domain::{Actor, Digest, EventId, Redaction, Scope, SeatId, SessionId};
use rusqlite::{params, Connection, OptionalExtension, Transaction};
use time::OffsetDateTime;

use super::row::{STATE_EFFECT_STARTED, STATE_IN_DOUBT, STATE_PREPARED};
use crate::audit::{append_audit_event_in_tx, NewAuditEvent, RedactedPayload};
use crate::{encode_utc, LedgerError, LedgerResult};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CapsuleLeaseRow {
    pub capsule_id: String,
    pub seat_id: String,
    pub token_id: String,
    pub session_id: String,
    pub policy_digest: String,
    pub listing_digest: String,
    pub lease_id: String,
    pub state: String,
    pub close_mode: Option<String>,
    pub drained: i64,
    /// Verified issuance of the bound token in epoch milliseconds, recorded
    /// at open/rebind time from the token's signed claims. `None` marks a
    /// pre-migration row whose issuance is unknown; `Some(0)` is a valid
    /// known issuance (the epoch itself), never a sentinel.
    pub token_issued_at_ms: Option<u64>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LeaseOutcome {
    Opened,
    AlreadyOpen,
    Rebound,
}

/// The exact authority a lease or stop intent is bound to.
///
/// `token_issued_at_ms` is trusted recency evidence, not arbitrary caller
/// input: the type is constructed only by the kernel verification boundary
/// from a fresh verified `SeatAuthority`, whose signed claims
/// (`SeatToken::verify_at`) prove the issuance. Recency is never parsed
/// from the token id.
#[derive(Clone, Copy, Debug)]
pub struct LeaseAuthority<'a> {
    pub seat_id: &'a str,
    pub token_id: &'a str,
    pub session_id: &'a str,
    pub policy_digest: &'a str,
    pub listing_digest: &'a str,
    pub token_issued_at_ms: u64,
}

#[doc(hidden)]
pub fn open_lease(
    tx: &Transaction<'_>,
    capsule_id: &str,
    authority: &LeaseAuthority<'_>,
    lease_id: &str,
    now: OffsetDateTime,
) -> LedgerResult<LeaseOutcome> {
    if let Some(existing) = lease_row(tx, capsule_id)? {
        // Closed is terminal: a newer verified authority never revives it.
        // This typed error is the ONLY closed-lease signal; the kernel maps
        // it — and nothing else — to its CapsuleClosed rejection.
        if existing.state != "open" {
            return Err(LedgerError::LeaseClosed {
                capsule_id: capsule_id.to_owned(),
            });
        }
        let same = existing.seat_id == authority.seat_id
            && existing.token_id == authority.token_id
            && existing.session_id == authority.session_id
            && existing.policy_digest == authority.policy_digest
            && existing.listing_digest == authority.listing_digest;
        if !same {
            return rebind_open_lease(tx, capsule_id, &existing, authority, now);
        }
        // The identical bound token may pin its exact signed issuance on a
        // pre-migration row — including a genuine epoch-0 issuance: no
        // authority field changes, so this is evidence repair, not a
        // rotation, and journals no event.
        if existing.token_issued_at_ms.is_none() {
            bind_token_issuance(tx, capsule_id, authority.token_issued_at_ms)?;
        }
        return Ok(LeaseOutcome::AlreadyOpen);
    }
    tx.execute(
        "INSERT INTO capsule_lease (capsule_id, seat_id, token_id, session_id, policy_digest, \
         listing_digest, lease_id, state, close_mode, drained, opened_at, closed_at, \
         token_issued_at_ms) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 'open', NULL, 0, ?8, NULL, ?9)",
        params![
            capsule_id,
            authority.seat_id,
            authority.token_id,
            authority.session_id,
            authority.policy_digest,
            authority.listing_digest,
            lease_id,
            encode_utc(now)?,
            token_issued_at_param(authority.token_issued_at_ms)?,
        ],
    )?;
    Ok(LeaseOutcome::Opened)
}

/// Atomically re-binds one OPEN lease to a strictly newer verified authority
/// of the same seat and same session, journaling exactly one durable event.
/// Everything else is refused with a typed authority mismatch: a foreign
/// seat or session can never take a lease, and a token that is not provably
/// newer can never rotate it. Unresolved prepared/started/in-doubt effects
/// block the rotation until settled — a lease never changes hands underneath
/// an in-flight effect. Closed leases never reach this path.
fn rebind_open_lease(
    tx: &Transaction<'_>,
    capsule_id: &str,
    existing: &CapsuleLeaseRow,
    authority: &LeaseAuthority<'_>,
    now: OffsetDateTime,
) -> LedgerResult<LeaseOutcome> {
    if existing.seat_id != authority.seat_id || existing.session_id != authority.session_id {
        return Err(LedgerError::LeaseAuthorityMismatch {
            capsule_id: capsule_id.to_owned(),
            reason: format!(
                "lease is bound to seat {:?} session {:?}, not seat {:?} session {:?}",
                existing.seat_id, existing.session_id, authority.seat_id, authority.session_id
            ),
        });
    }
    if existing.token_issued_at_ms.is_none() {
        // Pre-migration row with unknown issuance. Nothing durable proves
        // the bound token's recency (the verifier clock and the authority
        // clock are separately injected, so no watermark can be derived),
        // and unknown issuance must never be treated as older than the
        // presenter. The safe transition: the identical bound token binds
        // its exact signed issuance (no rotation), then strict recency
        // governs; or the bound authority closes the capsule itself.
        return Err(LedgerError::LeaseAuthorityMismatch {
            capsule_id: capsule_id.to_owned(),
            reason: "lease issuance is unknown (pre-migration row); present the \
                     identical bound token once to bind its signed issuance, or \
                     close the capsule with its bound authority"
                .to_owned(),
        });
    }
    let recorded = existing.token_issued_at_ms.unwrap_or(0);
    if authority.token_issued_at_ms <= recorded {
        return Err(LedgerError::LeaseAuthorityMismatch {
            capsule_id: capsule_id.to_owned(),
            reason: format!(
                "presented token issued at {} ms is not newer than the lease token \
                 issued at {recorded} ms",
                authority.token_issued_at_ms
            ),
        });
    }
    let pending = tx.query_row(
        "SELECT COUNT(*) FROM operation_journal \
         WHERE capsule_id = ?1 AND effect_state IN (?2, ?3, ?4)",
        params![
            capsule_id,
            STATE_PREPARED,
            STATE_EFFECT_STARTED,
            STATE_IN_DOUBT
        ],
        |row| row.get::<_, i64>(0),
    )?;
    if pending > 0 {
        return Err(LedgerError::LeaseRebindBlocked {
            capsule_id: capsule_id.to_owned(),
            pending,
        });
    }
    let rebound = tx.execute(
        "UPDATE capsule_lease SET token_id = ?2, policy_digest = ?3, listing_digest = ?4, \
         token_issued_at_ms = ?5 WHERE capsule_id = ?1 AND state = 'open'",
        params![
            capsule_id,
            authority.token_id,
            authority.policy_digest,
            authority.listing_digest,
            token_issued_at_param(authority.token_issued_at_ms)?,
        ],
    )?;
    if rebound != 1 {
        return Err(LedgerError::invalid_data(format!(
            "capsule {capsule_id} lease rebind updated {rebound} rows"
        )));
    }
    journal_lease_rebind(tx, capsule_id, existing, authority, now)?;
    Ok(LeaseOutcome::Rebound)
}

/// Pins the exact signed issuance of the identical bound token on a
/// pre-migration lease row — including a genuine epoch-0 issuance. The
/// compare-and-set on `token_issued_at_ms IS NULL` makes the repair
/// one-shot; a second presentation replays harmlessly.
fn bind_token_issuance(
    tx: &Transaction<'_>,
    capsule_id: &str,
    token_issued_at_ms: u64,
) -> LedgerResult<()> {
    let bound = tx.execute(
        "UPDATE capsule_lease SET token_issued_at_ms = ?2 \
         WHERE capsule_id = ?1 AND state = 'open' AND token_issued_at_ms IS NULL",
        params![capsule_id, token_issued_at_param(token_issued_at_ms)?],
    )?;
    if bound != 1 {
        return Err(LedgerError::invalid_data(format!(
            "capsule {capsule_id} issuance repair updated {bound} rows"
        )));
    }
    Ok(())
}

/// NULL for a legacy unknown row is never written by this module; opens and
/// rotations always record the verified claims issuance.
fn token_issued_at_param(token_issued_at_ms: u64) -> LedgerResult<Option<i64>> {
    i64::try_from(token_issued_at_ms)
        .map(Some)
        .map_err(|error| {
            LedgerError::invalid_data_caused_by(
                "token issuance exceeds the representable range",
                error,
            )
        })
}

/// The single durable journal event for one rebind. The lease UPDATE and
/// the event share one transaction.
fn journal_lease_rebind(
    tx: &Transaction<'_>,
    capsule_id: &str,
    existing: &CapsuleLeaseRow,
    authority: &LeaseAuthority<'_>,
    now: OffsetDateTime,
) -> LedgerResult<()> {
    // The event id is a canonical digest of a NUL-separated tuple: bounded
    // under EventId's length limit and free of delimiter collisions (token
    // ids themselves contain colons). Content-bound to the generation, so a
    // replayed rebind of the same generation is a no-op on the idempotent
    // audit insert.
    let digest = Digest::hash(
        format!(
            "odin.capsule_lease_rebind.v1\0{capsule_id}\0{}\0{}",
            authority.session_id, authority.token_id
        )
        .as_bytes(),
    )
    .to_string();
    let fingerprint = digest.trim_start_matches("blake3:");
    let fingerprint = fingerprint.get(..32).unwrap_or(fingerprint);
    let event_id =
        EventId::new(format!("capsule-lease-rebind-{fingerprint}")).map_err(|error| {
            LedgerError::invalid_data_caused_by("invalid capsule lease rebind event id", error)
        })?;
    let seat = SeatId::new(existing.seat_id.as_str()).map_err(|error| {
        LedgerError::invalid_data_caused_by("invalid capsule lease seat id", error)
    })?;
    let session = SessionId::new(authority.session_id).map_err(|error| {
        LedgerError::invalid_data_caused_by("invalid capsule lease session id", error)
    })?;
    let payload = serde_json::json!({
        "capsule_id": capsule_id,
        "previous": {
            "token_id": existing.token_id,
            "policy_digest": existing.policy_digest,
            "listing_digest": existing.listing_digest,
            "token_issued_at_ms": existing.token_issued_at_ms,
        },
        "new": {
            "token_id": authority.token_id,
            "policy_digest": authority.policy_digest,
            "listing_digest": authority.listing_digest,
            "token_issued_at_ms": authority.token_issued_at_ms,
        },
    });
    let event = NewAuditEvent {
        event_id,
        kind: "capsule.lease.rebound".to_owned(),
        actor: Actor::Seat {
            seat: seat.clone(),
            session: Some(session.clone()),
        },
        scope: Scope {
            seat: Some(seat),
            session: Some(session),
            ..Scope::default()
        },
        evidence: Vec::new(),
        payload: RedactedPayload::new(payload, Redaction::None)?,
        occurred_at: now,
    };
    append_audit_event_in_tx(tx, event)?;
    Ok(())
}

pub fn lease_row(conn: &Connection, capsule_id: &str) -> LedgerResult<Option<CapsuleLeaseRow>> {
    conn.query_row(
        "SELECT capsule_id, seat_id, token_id, session_id, policy_digest, listing_digest, \
         lease_id, state, close_mode, drained, token_issued_at_ms \
         FROM capsule_lease WHERE capsule_id = ?1",
        [capsule_id],
        |row| {
            Ok(CapsuleLeaseRow {
                capsule_id: row.get(0)?,
                seat_id: row.get(1)?,
                token_id: row.get(2)?,
                session_id: row.get(3)?,
                policy_digest: row.get(4)?,
                listing_digest: row.get(5)?,
                lease_id: row.get(6)?,
                state: row.get(7)?,
                close_mode: row.get(8)?,
                drained: row.get(9)?,
                token_issued_at_ms: row.get(10)?,
            })
        },
    )
    .optional()
    .map_err(LedgerError::from)
}

/// Closes an open capsule lease. Returns false when it was already closed.
#[doc(hidden)]
pub fn close_lease(
    tx: &Transaction<'_>,
    capsule_id: &str,
    close_mode: &str,
    drained: i64,
    now: OffsetDateTime,
) -> LedgerResult<bool> {
    let updated = tx.execute(
        "UPDATE capsule_lease SET state = 'closed', close_mode = ?2, drained = ?3, \
         closed_at = ?4 WHERE capsule_id = ?1 AND state = 'open'",
        params![capsule_id, close_mode, drained, encode_utc(now)?],
    )?;
    Ok(updated == 1)
}

#[cfg(test)]
mod lease_rebind {
    use super::*;
    use crate::migration;

    const CAPSULE: &str = "capsule-rebind";

    fn journal() -> Connection {
        let mut connection = Connection::open_in_memory().unwrap();
        migration::migrate(&mut connection).unwrap();
        connection
    }

    fn now_at(millisecond: i64) -> OffsetDateTime {
        OffsetDateTime::from_unix_timestamp(millisecond / 1_000)
            .unwrap()
            .replace_millisecond((millisecond % 1_000) as u16)
            .unwrap()
    }

    fn authority<'a>(
        seat: &'a str,
        token: &'a str,
        session: &'a str,
        policy: &'a str,
        listing: &'a str,
        issued_at_ms: u64,
    ) -> LeaseAuthority<'a> {
        LeaseAuthority {
            seat_id: seat,
            token_id: token,
            session_id: session,
            policy_digest: policy,
            listing_digest: listing,
            token_issued_at_ms: issued_at_ms,
        }
    }

    /// The bound generation: seat.one / token.one / session.one with no
    /// recorded issuance policy of its own generation.
    fn bound() -> LeaseAuthority<'static> {
        authority(
            "seat.one",
            "token.one",
            "session.one",
            "policy.one",
            "listing.one",
            0,
        )
    }

    /// A newer or stale challenger of the same seat and session.
    fn challenger(issued_at_ms: u64) -> LeaseAuthority<'static> {
        authority(
            "seat.one",
            "token.two",
            "session.one",
            "policy.two",
            "listing.two",
            issued_at_ms,
        )
    }

    fn foreign_seat() -> LeaseAuthority<'static> {
        authority(
            "seat.two",
            "token.two",
            "session.one",
            "policy.two",
            "listing.two",
            9_000_000,
        )
    }

    fn foreign_session() -> LeaseAuthority<'static> {
        authority(
            "seat.one",
            "token.two",
            "session.two",
            "policy.two",
            "listing.two",
            9_000_000,
        )
    }
    /// Opens a lease at a fixed wall-clock moment, then resets its recorded
    /// issuance to NULL — the durable shape of every pre-migration lease
    /// row (issuance unknown).
    fn open_legacy_lease(connection: &mut Connection, opened_at_ms: i64) {
        let first = bound();
        let tx = connection.transaction().unwrap();
        open_lease(&tx, CAPSULE, &first, "lease-test", now_at(opened_at_ms)).unwrap();
        tx.commit().unwrap();
        connection
            .execute(
                "UPDATE capsule_lease SET token_issued_at_ms = NULL WHERE capsule_id = ?1",
                [CAPSULE],
            )
            .unwrap();
    }

    fn lease(connection: &Connection) -> CapsuleLeaseRow {
        lease_row(connection, CAPSULE)
            .unwrap()
            .expect("lease exists")
    }

    fn rebind_events(connection: &Connection) -> usize {
        let count: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM audit_events WHERE kind = 'capsule.lease.rebound'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        count as usize
    }

    /// Opens a lease whose issuance is durably recorded (the shape every
    /// post-migration open produces).
    fn open_known_lease(connection: &mut Connection) {
        let first = authority(
            "seat.one",
            "token.one",
            "session.one",
            "policy.one",
            "listing.one",
            100_000,
        );
        let tx = connection.transaction().unwrap();
        open_lease(&tx, CAPSULE, &first, "lease-test", now_at(1_000_000)).unwrap();
        tx.commit().unwrap();
    }

    /// A token strictly newer than the recorded issuance re-binds, journals
    /// exactly one event, and then replays as `AlreadyOpen` with no second
    /// event.
    #[test]
    fn known_recency_rebinds_by_exact_issuance_and_journals_once() {
        let mut connection = journal();
        open_known_lease(&mut connection);
        assert_eq!(lease(&connection).token_issued_at_ms, Some(100_000));
        let newer = challenger(2_000_000);
        {
            let tx = connection.transaction().unwrap();
            assert!(matches!(
                open_lease(&tx, CAPSULE, &newer, "lease-test", now_at(2_500_000)).unwrap(),
                LeaseOutcome::Rebound
            ));
            tx.commit().unwrap();
        }
        let rebound = lease(&connection);
        assert_eq!(rebound.token_id, "token.two");
        assert_eq!(rebound.token_issued_at_ms, Some(2_000_000));
        assert_eq!(rebound.state, "open");
        assert_eq!(rebind_events(&connection), 1);
        {
            let tx = connection.transaction().unwrap();
            assert!(matches!(
                open_lease(&tx, CAPSULE, &newer, "lease-test", now_at(2_600_000)).unwrap(),
                LeaseOutcome::AlreadyOpen
            ));
            tx.commit().unwrap();
        }
        assert_eq!(rebind_events(&connection), 1);
    }

    /// Unknown issuance is never treated as older than the presenter: any
    /// differing token is a typed mismatch with the explicit safe
    /// transition (identical-token repair), and the lease stays put.
    #[test]
    fn legacy_lease_refuses_differing_token_while_issuance_unknown() {
        let mut connection = journal();
        open_legacy_lease(&mut connection, 1_000_000);
        let stale = challenger(500_000);
        let tx = connection.transaction().unwrap();
        let error = open_lease(&tx, CAPSULE, &stale, "lease-test", now_at(1_500_000)).unwrap_err();
        tx.commit().unwrap();
        assert!(matches!(error, LedgerError::LeaseAuthorityMismatch { .. }));
        assert_eq!(lease(&connection).token_id, "token.one");
        assert!(lease(&connection).token_issued_at_ms.is_none());
        assert_eq!(rebind_events(&connection), 0);
    }

    /// A token that is not strictly newer than the recorded issuance is a
    /// typed mismatch and the lease stays put.
    #[test]
    fn known_lease_refuses_token_not_newer_than_recorded_issuance() {
        let mut connection = journal();
        open_known_lease(&mut connection);
        let stale = challenger(100_000);
        let tx = connection.transaction().unwrap();
        let error = open_lease(&tx, CAPSULE, &stale, "lease-test", now_at(1_500_000)).unwrap_err();
        tx.commit().unwrap();
        assert!(matches!(error, LedgerError::LeaseAuthorityMismatch { .. }));
        assert_eq!(lease(&connection).token_id, "token.one");
        assert_eq!(lease(&connection).token_issued_at_ms, Some(100_000));
        assert_eq!(rebind_events(&connection), 0);
    }

    /// A foreign seat or session never takes the lease, whatever its
    /// recency, and journals nothing.
    #[test]
    fn foreign_identity_is_a_typed_mismatch() {
        let mut connection = journal();
        open_legacy_lease(&mut connection, 1_000_000);
        let foreign_seat = foreign_seat();
        let foreign_session = foreign_session();
        for intruder in [foreign_seat, foreign_session] {
            let tx = connection.transaction().unwrap();
            let error =
                open_lease(&tx, CAPSULE, &intruder, "lease-test", now_at(9_500_000)).unwrap_err();
            tx.commit().unwrap();
            assert!(matches!(error, LedgerError::LeaseAuthorityMismatch { .. }));
        }
        assert_eq!(lease(&connection).token_id, "token.one");
        assert_eq!(rebind_events(&connection), 0);
    }

    /// A closed lease is terminal at the gate itself: every authority meets
    /// the typed closed error and no rebind path can fire.
    #[test]
    fn closed_lease_refuses_every_authority_with_typed_closed() {
        let mut connection = journal();
        open_legacy_lease(&mut connection, 1_000_000);
        {
            let tx = connection.transaction().unwrap();
            close_lease(&tx, CAPSULE, "drain", 0, now_at(1_100_000)).unwrap();
            tx.commit().unwrap();
        }
        let newer = challenger(9_000_000);
        let tx = connection.transaction().unwrap();
        let error = open_lease(&tx, CAPSULE, &newer, "lease-test", now_at(9_500_000)).unwrap_err();
        tx.commit().unwrap();
        assert!(matches!(error, LedgerError::LeaseClosed { .. }));
        assert_eq!(lease(&connection).state, "closed");
        assert_eq!(rebind_events(&connection), 0);
    }

    /// The identical bound token pins its exact signed issuance on a legacy
    /// row without any rotation event — and that repair is what lets the
    /// next genuinely newer generation rotate by exact recency.
    #[test]
    fn identical_token_binds_missing_issuance_without_rotation() {
        let mut connection = journal();
        open_legacy_lease(&mut connection, 1_000_000);
        let same = authority(
            "seat.one",
            "token.one",
            "session.one",
            "policy.one",
            "listing.one",
            100_000,
        );
        {
            let tx = connection.transaction().unwrap();
            assert!(matches!(
                open_lease(&tx, CAPSULE, &same, "lease-test", now_at(1_100_000)).unwrap(),
                LeaseOutcome::AlreadyOpen
            ));
            tx.commit().unwrap();
        }
        assert_eq!(lease(&connection).token_issued_at_ms, Some(100_000));
        assert_eq!(rebind_events(&connection), 0);
        let newer = challenger(2_000_000);
        let tx = connection.transaction().unwrap();
        assert!(matches!(
            open_lease(&tx, CAPSULE, &newer, "lease-test", now_at(2_500_000)).unwrap(),
            LeaseOutcome::Rebound
        ));
        tx.commit().unwrap();
        assert_eq!(rebind_events(&connection), 1);
    }
    /// Zero is a known epoch issuance; only NULL means unknown and prevents rotation.
    #[test]
    fn known_zero_issuance_rotates_while_unknown_null_refuses() {
        let mut connection = journal();
        let zero = authority(
            "seat.one",
            "token.one",
            "session.one",
            "policy.one",
            "listing.one",
            0,
        );
        {
            let tx = connection.transaction().unwrap();
            open_lease(&tx, CAPSULE, &zero, "lease-test", now_at(1_000_000)).unwrap();
            tx.commit().unwrap();
        }
        assert_eq!(lease(&connection).token_issued_at_ms, Some(0));
        let newer = challenger(2_000_000);
        {
            let tx = connection.transaction().unwrap();
            assert!(matches!(
                open_lease(&tx, CAPSULE, &newer, "lease-test", now_at(2_500_000)).unwrap(),
                LeaseOutcome::Rebound
            ));
            tx.commit().unwrap();
        }
        assert_eq!(lease(&connection).token_issued_at_ms, Some(2_000_000));
        assert_eq!(rebind_events(&connection), 1);

        // The same newer token against a legacy NULL row: unknown issuance
        // is never assumed older, so the takeover is refused.
        let legacy_capsule = "capsule-rebind-null";
        let bound = bound();
        {
            let tx = connection.transaction().unwrap();
            open_lease(
                &tx,
                legacy_capsule,
                &bound,
                "lease-legacy",
                now_at(1_000_000),
            )
            .unwrap();
            tx.commit().unwrap();
        }
        connection
            .execute(
                "UPDATE capsule_lease SET token_issued_at_ms = NULL WHERE capsule_id = ?1",
                [legacy_capsule],
            )
            .unwrap();
        {
            let tx = connection.transaction().unwrap();
            let error = open_lease(
                &tx,
                legacy_capsule,
                &newer,
                "lease-legacy",
                now_at(2_600_000),
            )
            .unwrap_err();
            tx.commit().unwrap();
            assert!(matches!(error, LedgerError::LeaseAuthorityMismatch { .. }));
        }
        let refused = lease_row(&connection, legacy_capsule)
            .unwrap()
            .expect("legacy lease exists");
        assert_eq!(refused.token_id, "token.one");
        assert!(refused.token_issued_at_ms.is_none());
    }
}
