use odin_domain::{ApprovalId, ApprovalStatus, CapabilityId, CommandId, Digest};
use rusqlite::{params, Connection, OptionalExtension, Transaction};
use serde::{Deserialize, Deserializer, Serialize};
use time::OffsetDateTime;

use crate::{decode_utc, encode_utc, parse_id, Ledger, LedgerError, LedgerResult};

pub const APPROVAL_SCHEMA_VERSION: u16 = 1;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ApprovalScope {
    pub target_kind: String,
    pub target_id: String,
    pub capability_id: CapabilityId,
    pub arguments_digest: Digest,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NewApproval {
    pub approval_id: ApprovalId,
    pub issuer: String,
    pub scope: ApprovalScope,
    pub requested_at: OffsetDateTime,
    pub expires_at: OffsetDateTime,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Approval {
    pub approval_id: ApprovalId,
    pub status: ApprovalStatus,
    pub issuer: String,
    pub scope: ApprovalScope,
    pub requested_at: OffsetDateTime,
    pub expires_at: OffsetDateTime,
    pub decided_at: Option<OffsetDateTime>,
    pub decided_by: Option<String>,
    pub consumed_by_command_id: Option<CommandId>,
    pub decision_evidence_ref: Option<String>,
    pub revision: i64,
}

/// An approval decision. A denial always carries durable evidence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ApprovalDecision {
    Approve { evidence_ref: Option<String> },
    Deny { evidence_ref: String },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DecideApproval {
    Decided(Approval),
    NotFound,
    NotRequested(Approval),
    /// Owner consent to this scope needs the complete question delivered to
    /// the owner; nothing was decided and the request stays pending.
    PreviewRequired(Approval),
}

/// Records delivery of the complete approval question to the owner's conversation.
pub const OWNER_PREVIEW_DELIVERY_KIND: &str = "hermes.approval.question_delivered";

/// Decision evidence naming one canonical delivery record by event id.
pub const OWNER_PREVIEW_EVIDENCE_PREFIX: &str = "delivery:";

/// Whether owner consent to this exact run scope must bind a complete
/// delivery. `owner_preview` is the capability's declared preview kind,
/// resolved by the caller that holds the contract.
pub fn requires_owner_preview(scope: &ApprovalScope, owner_preview: bool) -> bool {
    scope.target_kind == "run" && owner_preview
}

/// The authenticated inbound message identity one conversation decision
/// consumes exactly once, atomically with its settlement. The consumer
/// names the authenticated surface (e.g. `discord-owner:<user id>`), the
/// message id the transport's own durable identity for the decision
/// message; both must be stable schema ids.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DecisionIntake {
    pub consumer_id: String,
    pub message_id: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ExpireApproval {
    Expired(Approval),
    NotFound,
    NotDue(Approval),
    Final(Approval),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ConsumeApproval {
    Consumed(Approval),
    NotFound,
    ScopeMismatch(Approval),
    NotAuthorized(Approval),
    Expired(Approval),
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ApprovalScopeWire {
    pub target_kind: String,
    pub target_id: String,
    pub capability_id: CapabilityId,
    pub arguments_digest: Digest,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ApprovalWire {
    pub schema_version: u16,
    pub approval_id: ApprovalId,
    pub status: ApprovalStatus,
    pub issuer: String,
    pub scope: ApprovalScopeWire,
    pub requested_at: String,
    pub expires_at: String,
    pub decided_at: Option<String>,
    pub decided_by: Option<String>,
    pub consumed_by_command_id: Option<CommandId>,
    pub decision_evidence_ref: Option<String>,
    pub revision: i64,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ApprovalWireParts {
    schema_version: u16,
    approval_id: ApprovalId,
    status: ApprovalStatus,
    issuer: String,
    scope: ApprovalScopeWire,
    requested_at: String,
    expires_at: String,
    #[serde(deserialize_with = "crate::required_nullable")]
    decided_at: Option<String>,
    #[serde(deserialize_with = "crate::required_nullable")]
    decided_by: Option<String>,
    #[serde(deserialize_with = "crate::required_nullable")]
    consumed_by_command_id: Option<CommandId>,
    #[serde(deserialize_with = "crate::required_nullable")]
    decision_evidence_ref: Option<String>,
    revision: i64,
}

impl<'de> Deserialize<'de> for ApprovalWire {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let parts = ApprovalWireParts::deserialize(deserializer)?;
        if parts.schema_version != APPROVAL_SCHEMA_VERSION {
            return Err(serde::de::Error::custom(format!(
                "unsupported approval schema version {}",
                parts.schema_version
            )));
        }
        let requested_at = decode_utc(&parts.requested_at).map_err(serde::de::Error::custom)?;
        let expires_at = decode_utc(&parts.expires_at).map_err(serde::de::Error::custom)?;
        let decided_at = parts
            .decided_at
            .as_deref()
            .map(decode_utc)
            .transpose()
            .map_err(serde::de::Error::custom)?;
        validate_approval_invariants(&ApprovalInvariants {
            status: parts.status,
            requested_at,
            expires_at,
            decided_at,
            decision_evidence_ref: parts.decision_evidence_ref.as_deref(),
            has_consuming_command: parts.consumed_by_command_id.is_some(),
            issuer: &parts.issuer,
            decided_by: parts.decided_by.as_deref(),
            target_kind: &parts.scope.target_kind,
            target_id: &parts.scope.target_id,
            revision: parts.revision,
        })
        .map_err(serde::de::Error::custom)?;
        Ok(Self {
            schema_version: parts.schema_version,
            approval_id: parts.approval_id,
            status: parts.status,
            issuer: parts.issuer,
            scope: parts.scope,
            requested_at: parts.requested_at,
            expires_at: parts.expires_at,
            decided_at: parts.decided_at,
            decided_by: parts.decided_by,
            consumed_by_command_id: parts.consumed_by_command_id,
            decision_evidence_ref: parts.decision_evidence_ref,
            revision: parts.revision,
        })
    }
}

impl TryFrom<&Approval> for ApprovalWire {
    type Error = LedgerError;

    fn try_from(approval: &Approval) -> LedgerResult<Self> {
        validate_approval_record(approval)?;
        Ok(Self {
            schema_version: APPROVAL_SCHEMA_VERSION,
            approval_id: approval.approval_id.clone(),
            status: approval.status,
            issuer: approval.issuer.clone(),
            scope: ApprovalScopeWire {
                target_kind: approval.scope.target_kind.clone(),
                target_id: approval.scope.target_id.clone(),
                capability_id: approval.scope.capability_id.clone(),
                arguments_digest: approval.scope.arguments_digest,
            },
            requested_at: encode_utc(approval.requested_at)?,
            expires_at: encode_utc(approval.expires_at)?,
            decided_at: approval.decided_at.map(encode_utc).transpose()?,
            decided_by: approval.decided_by.clone(),
            consumed_by_command_id: approval.consumed_by_command_id.clone(),
            decision_evidence_ref: approval.decision_evidence_ref.clone(),
            revision: approval.revision,
        })
    }
}

impl ApprovalWire {
    pub fn into_approval(self) -> LedgerResult<Approval> {
        if self.schema_version != APPROVAL_SCHEMA_VERSION {
            return Err(LedgerError::invalid_data(format!(
                "unsupported approval schema version {}",
                self.schema_version
            )));
        }
        let approval = Approval {
            approval_id: self.approval_id,
            status: self.status,
            issuer: self.issuer,
            scope: ApprovalScope {
                target_kind: self.scope.target_kind,
                target_id: self.scope.target_id,
                capability_id: self.scope.capability_id,
                arguments_digest: self.scope.arguments_digest,
            },
            requested_at: decode_utc(&self.requested_at)?,
            expires_at: decode_utc(&self.expires_at)?,
            decided_at: self.decided_at.as_deref().map(decode_utc).transpose()?,
            decided_by: self.decided_by,
            consumed_by_command_id: self.consumed_by_command_id,
            decision_evidence_ref: self.decision_evidence_ref,
            revision: self.revision,
        };
        validate_approval_record(&approval)?;
        Ok(approval)
    }
}

fn validate_approval_record(approval: &Approval) -> LedgerResult<()> {
    validate_approval_invariants(&ApprovalInvariants {
        status: approval.status,
        requested_at: approval.requested_at,
        expires_at: approval.expires_at,
        decided_at: approval.decided_at,
        decision_evidence_ref: approval.decision_evidence_ref.as_deref(),
        has_consuming_command: approval.consumed_by_command_id.is_some(),
        issuer: &approval.issuer,
        decided_by: approval.decided_by.as_deref(),
        target_kind: &approval.scope.target_kind,
        target_id: &approval.scope.target_id,
        revision: approval.revision,
    })
}

/// Schema `id` pattern: `^[a-zA-Z0-9][a-zA-Z0-9._:-]{0,127}$`.
fn is_schema_id(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.is_empty() || bytes.len() > 128 {
        return false;
    }
    bytes[0].is_ascii_alphanumeric()
        && bytes[1..]
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-'))
}

struct ApprovalInvariants<'a> {
    status: ApprovalStatus,
    requested_at: OffsetDateTime,
    expires_at: OffsetDateTime,
    decided_at: Option<OffsetDateTime>,
    decision_evidence_ref: Option<&'a str>,
    has_consuming_command: bool,
    issuer: &'a str,
    decided_by: Option<&'a str>,
    target_kind: &'a str,
    target_id: &'a str,
    revision: i64,
}

fn validate_approval_invariants(inv: &ApprovalInvariants<'_>) -> LedgerResult<()> {
    let ApprovalInvariants {
        status,
        requested_at,
        expires_at,
        decided_at,
        decision_evidence_ref,
        has_consuming_command,
        issuer,
        decided_by,
        target_kind,
        target_id,
        revision,
    } = *inv;
    if expires_at <= requested_at {
        return Err(LedgerError::invalid_data(
            "approval expiry must be later than its request time".into(),
        ));
    }
    match status {
        ApprovalStatus::Approved | ApprovalStatus::Denied | ApprovalStatus::Consumed
            if decided_at.is_none() =>
        {
            return Err(LedgerError::invalid_data(
                "approved, denied, and consumed approvals must record a decision time".into(),
            ));
        }
        ApprovalStatus::Requested if decided_at.is_some() => {
            return Err(LedgerError::invalid_data(
                "a requested approval must not record a decision time".into(),
            ));
        }
        _ => {}
    }
    if let Some(evidence) = decision_evidence_ref {
        if evidence.is_empty() {
            return Err(LedgerError::invalid_data(
                "approval decision evidence must be null or a nonempty string".into(),
            ));
        }
    }
    if status == ApprovalStatus::Denied && decision_evidence_ref.unwrap_or_default().is_empty() {
        return Err(LedgerError::invalid_data(
            "a denied approval must carry durable evidence".into(),
        ));
    }
    if has_consuming_command && status != ApprovalStatus::Consumed {
        return Err(LedgerError::invalid_data(
            "only consumed approvals may name their consuming command".into(),
        ));
    }
    if !is_schema_id(issuer) {
        return Err(LedgerError::invalid_data(
            "approval issuer must be a schema id".into(),
        ));
    }
    if let Some(decided_by) = decided_by {
        if !is_schema_id(decided_by) {
            return Err(LedgerError::invalid_data(
                "approval decidedBy must be null or a schema id".into(),
            ));
        }
    }
    if target_kind.is_empty() || !is_schema_id(target_id) {
        return Err(LedgerError::invalid_data(
            "approval scope must name a target".into(),
        ));
    }
    if revision < 1 {
        return Err(LedgerError::invalid_data(
            "approval revision must be positive".into(),
        ));
    }
    Ok(())
}

impl Ledger {
    /// Creates an exact-scope request at revision one.
    pub fn request_approval(&mut self, request: NewApproval) -> LedgerResult<Approval> {
        self.with_tx(|transaction| insert_requested(transaction, &request))
    }

    /// Inserts a request and decides it in ONE transaction: no other
    /// connection ever reads it as `requested`, so a kernel-decided
    /// approval can never be put to the owner.
    pub fn request_decided_approval(
        &mut self,
        request: NewApproval,
        decision: ApprovalDecision,
        decided_by: &str,
        decided_at: OffsetDateTime,
    ) -> LedgerResult<DecideApproval> {
        self.with_tx(|transaction| {
            let requested = insert_requested(transaction, &request)?;
            decide_in_tx(
                transaction,
                &requested.approval_id,
                &decision,
                decided_by,
                decided_at,
                requested.revision,
                false,
                false,
            )
        })
    }

    pub fn approval(&self, approval_id: &ApprovalId) -> LedgerResult<Option<Approval>> {
        load_approval(self.connection(), approval_id)
    }

    /// Proves this exact approval was decided through authenticated owner intake,
    /// not merely by a caller supplying an owner-looking actor or evidence string.
    /// Consent that needs the complete preview must also name the canonical
    /// delivery of exactly this approval's content.
    pub fn approval_has_owner_decision(
        &self,
        approval: &Approval,
        owner_preview: bool,
    ) -> LedgerResult<bool> {
        if !matches!(
            approval.status,
            ApprovalStatus::Approved | ApprovalStatus::Consumed
        ) {
            return Ok(false);
        }
        if requires_owner_preview(&approval.scope, owner_preview) {
            let Some(event) = preview_event(approval.decision_evidence_ref.as_deref()) else {
                return Ok(false);
            };
            if delivered_preview(self.connection(), approval, approval.revision, Some(event))?
                .is_none()
            {
                return Ok(false);
            }
        }
        let decided_at = approval.decided_at.map(encode_utc).transpose()?;
        Ok(self.connection().query_row(
            "SELECT EXISTS (
               SELECT 1 FROM approval_owner_decisions w
               JOIN approvals a ON a.approval_id = w.approval_id
               WHERE a.approval_id = ?1 AND a.revision = ?2
                 AND a.status IN ('approved', 'consumed')
                 AND w.decision_revision <= a.revision
                 AND w.issuer = a.issuer AND w.issuer = ?3
                 AND w.target_kind = a.target_kind AND w.target_kind = ?4
                 AND w.target_id = a.target_id AND w.target_id = ?5
                 AND w.capability_id = a.capability_id AND w.capability_id = ?6
                 AND w.arguments_hash = a.arguments_hash AND w.arguments_hash = ?7
                 AND w.decided_by = a.decided_by AND w.decided_by = ?8
                 AND w.decided_at = a.decided_at AND w.decided_at = ?9
                 AND a.decision_evidence_ref IS ?10
             )",
            params![
                approval.approval_id.as_str(),
                approval.revision,
                approval.issuer,
                approval.scope.target_kind,
                approval.scope.target_id,
                approval.scope.capability_id.as_str(),
                approval.scope.arguments_digest.to_string(),
                approval.decided_by,
                decided_at,
                approval.decision_evidence_ref,
            ],
            |row| row.get(0),
        )?)
    }

    /// Whether approving this pending owner question needs a complete
    /// delivered preview that does not exist yet. Surfaces refuse before
    /// journaling or consuming anything, so the same request and intake
    /// decide once the question reaches the owner's conversation.
    pub fn owner_preview_missing(
        &self,
        approval_id: &ApprovalId,
        owner_preview: bool,
    ) -> LedgerResult<bool> {
        Ok(match self.approval(approval_id)? {
            Some(approval)
                if approval.status == ApprovalStatus::Requested
                    && requires_owner_preview(&approval.scope, owner_preview) =>
            {
                self.owner_preview_evidence(&approval)?.is_none()
            }
            _ => false,
        })
    }

    /// The decision evidence naming the newest complete question delivered
    /// for this exact approval, so a surface that cannot render the preview
    /// itself decides the question the owner's conversation already showed.
    /// `None` when no complete delivery exists.
    pub fn owner_preview_evidence(&self, approval: &Approval) -> LedgerResult<Option<String>> {
        Ok(
            delivered_preview(self.connection(), approval, approval.revision, None)?
                .map(|event| format!("{OWNER_PREVIEW_EVIDENCE_PREFIX}{event}")),
        )
    }

    /// Every durable approval row in id order. Read-only projection feed:
    /// the Hermes status bus scans the whole row set, so a decision
    /// recorded before its bus tracking step still projects.
    pub fn approvals(&self) -> LedgerResult<Vec<Approval>> {
        let mut statement = self.connection().prepare(
            "SELECT approval_id, status, issuer, target_kind, target_id, capability_id,
                    arguments_hash, requested_at, expires_at, decided_at, decided_by,
                    consumed_by_command_id, decision_evidence_ref, revision
             FROM approvals ORDER BY approval_id",
        )?;
        let rows = statement.query_map([], read_approval_row)?;
        rows.map(|row| {
            let mut raw = row?;
            // Preserve the enumeration's InvalidData error for malformed primary IDs.
            let approval_id =
                ApprovalId::new(std::mem::take(&mut raw.approval_id)).map_err(|error| {
                    LedgerError::invalid_data_caused_by("invalid approval id", error)
                })?;
            decode_approval(approval_id, raw)
        })
        .collect()
    }

    /// Pending decisions for one exact target, filtered before decoding or
    /// exposing any other target's records.
    pub fn requested_approvals_for_target(
        &self,
        target_kind: &str,
        target_id: &str,
    ) -> LedgerResult<Vec<Approval>> {
        let mut statement = self.connection().prepare(
            "SELECT approval_id, status, issuer, target_kind, target_id, capability_id,
                    arguments_hash, requested_at, expires_at, decided_at, decided_by,
                    consumed_by_command_id, decision_evidence_ref, revision
             FROM approvals
             WHERE status = 'requested' AND target_kind = ?1 AND target_id = ?2
             ORDER BY approval_id",
        )?;
        let rows = statement.query_map([target_kind, target_id], read_approval_row)?;
        rows.map(|row| Approval::try_from(row?)).collect()
    }

    /// Moves every open (requested or approved, unexpired) approval of one
    /// target onto its successor target: a conversation vehicle that rolls
    /// to a new session keeps the approvals Colin was asked — or already
    /// granted — for the action its predecessor requested. The scope's
    /// capability and exact arguments are untouched, so nothing new is
    /// authorized; only the binding follows the conversation. Returns the
    /// approvals moved.
    pub fn follow_approval_target(
        &mut self,
        target_kind: &str,
        from_target_id: &str,
        to_target_id: &str,
        now: OffsetDateTime,
    ) -> LedgerResult<Vec<ApprovalId>> {
        self.with_tx(|transaction| {
            let ids: Vec<String> = {
                let mut statement = transaction.prepare(
                    "SELECT approval_id FROM approvals
                     WHERE status IN ('requested', 'approved')
                       AND target_kind = ?1 AND target_id = ?2
                     ORDER BY approval_id",
                )?;
                let rows = statement.query_map([target_kind, from_target_id], |row| row.get(0))?;
                rows.collect::<Result<_, _>>()?
            };
            let mut moved = Vec::new();
            for id in ids {
                let approval_id = ApprovalId::new(id.as_str()).map_err(|error| {
                    LedgerError::invalid_data_caused_by("invalid approval id", error)
                })?;
                let current = load_existing_approval(transaction, &approval_id)?;
                if now >= current.expires_at {
                    continue;
                }
                let changed = transaction.execute(
                    "UPDATE approvals
                     SET target_id = ?1, revision = revision + 1
                     WHERE approval_id = ?2 AND revision = ?3
                       AND status IN ('requested', 'approved')",
                    params![to_target_id, approval_id.to_string(), current.revision],
                )?;
                ensure_guarded_update(transaction, &approval_id, current.revision, changed)?;
                transaction.execute(
                    "UPDATE approval_owner_decisions SET target_id = ?1
                     WHERE approval_id = ?2 AND target_kind = ?3 AND target_id = ?4",
                    params![
                        to_target_id,
                        approval_id.as_str(),
                        target_kind,
                        from_target_id
                    ],
                )?;
                let followed = load_existing_approval(transaction, &approval_id)?;
                crate::approval_feed::journal_approval_change(transaction, &followed, now)?;
                moved.push(approval_id);
            }
            Ok(moved)
        })
    }

    /// Decides a requested approval. Any revision mismatch wins over state checks.
    pub fn decide_approval(
        &mut self,
        approval_id: &ApprovalId,
        decision: ApprovalDecision,
        decided_by: &str,
        decided_at: OffsetDateTime,
        expected_revision: i64,
    ) -> LedgerResult<DecideApproval> {
        self.with_tx(|transaction| {
            decide_in_tx(
                transaction,
                approval_id,
                &decision,
                decided_by,
                decided_at,
                expected_revision,
                false,
                false,
            )
        })
    }

    /// Decides a requested approval while consuming the authenticated
    /// inbound message identity exactly once — in the SAME transaction, so
    /// the consumption commits or rolls back with the settlement itself. A
    /// redelivered decision message is refused durably, across reopen, and
    /// can never settle a replacement request; a settlement that fails
    /// leaves the identity unconsumed.
    /// `None` means the intake was already consumed; `Some` retains the
    /// ordinary decision or refusal without allocating a wrapper.
    #[allow(clippy::too_many_arguments)]
    pub fn decide_approval_consuming_intake(
        &mut self,
        approval_id: &ApprovalId,
        decision: ApprovalDecision,
        decided_by: &str,
        decided_at: OffsetDateTime,
        expected_revision: i64,
        intake: &DecisionIntake,
        owner_preview: bool,
    ) -> LedgerResult<Option<DecideApproval>> {
        let transaction = self
            .connection
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        match crate::inbox::claim(
            &transaction,
            &intake.consumer_id,
            &intake.message_id,
            decided_at,
        )? {
            crate::inbox::InboxClaim::Duplicate => {
                return Ok(None);
            }
            crate::inbox::InboxClaim::Inserted => {}
        }
        let outcome = decide_in_tx(
            &transaction,
            approval_id,
            &decision,
            decided_by,
            decided_at,
            expected_revision,
            true,
            owner_preview,
        )?;
        if let DecideApproval::Decided(approval) = &outcome {
            if approval.status == ApprovalStatus::Approved {
                transaction.execute(
                    "INSERT INTO approval_owner_decisions (
                       approval_id, consumer_id, message_id, issuer, target_kind, target_id,
                       capability_id, arguments_hash, decision_revision, decided_by, decided_at
                     )
                     SELECT approval_id, ?2, ?3, issuer, target_kind, target_id,
                            capability_id, arguments_hash, revision, decided_by, decided_at
                     FROM approvals WHERE approval_id = ?1 AND status = 'approved'",
                    params![approval_id.as_str(), intake.consumer_id, intake.message_id],
                )?;
            }
            transaction.commit()?;
        }
        // Non-settlement outcomes drop the transaction and its intake claim.
        Ok(Some(outcome))
    }

    /// Withdraws an unused approval before its reservation is returned.
    /// Consumption or any intervening revision prevents cancellation.
    pub fn cancel_unconsumed_approval(
        &mut self,
        approval_id: &ApprovalId,
        now: OffsetDateTime,
        expected_revision: i64,
    ) -> LedgerResult<bool> {
        self.with_tx(|transaction| {
            let Some(current) = load_approval(transaction, approval_id)? else {
                return Ok(false);
            };
            require_revision(&current, expected_revision)?;
            if current.status != ApprovalStatus::Approved
                || current.consumed_by_command_id.is_some()
            {
                return Ok(false);
            }
            let changed = transaction.execute(
                "UPDATE approvals
                 SET status = 'cancelled', revision = revision + 1
                 WHERE approval_id = ?1 AND revision = ?2
                   AND status = 'approved' AND consumed_by_command_id IS NULL",
                params![approval_id.as_str(), expected_revision],
            )?;
            ensure_guarded_update(transaction, approval_id, expected_revision, changed)?;
            let cancelled = load_existing_approval(transaction, approval_id)?;
            crate::approval_feed::journal_approval_change(transaction, &cancelled, now)?;
            Ok(true)
        })
    }

    /// Expires a requested or approved record once its deadline has passed.
    pub fn expire_approval(
        &mut self,
        approval_id: &ApprovalId,
        now: OffsetDateTime,
        expected_revision: i64,
    ) -> LedgerResult<ExpireApproval> {
        self.with_tx(|transaction| {
            let Some(current) = load_approval(transaction, approval_id)? else {
                return Ok(ExpireApproval::NotFound);
            };
            require_revision(&current, expected_revision)?;
            if !matches!(
                current.status,
                ApprovalStatus::Requested | ApprovalStatus::Approved
            ) {
                return Ok(ExpireApproval::Final(current));
            }
            if now < current.expires_at {
                return Ok(ExpireApproval::NotDue(current));
            }

            let changed = transaction.execute(
                "UPDATE approvals
                 SET status = 'expired', revision = revision + 1
                 WHERE approval_id = ?1 AND revision = ?2
                   AND status IN ('requested', 'approved')",
                params![approval_id.to_string(), expected_revision],
            )?;
            ensure_guarded_update(transaction, approval_id, expected_revision, changed)?;
            let expired = load_existing_approval(transaction, approval_id)?;
            crate::approval_feed::journal_approval_change(transaction, &expired, now)?;
            Ok(ExpireApproval::Expired(expired))
        })
    }

    /// Compare parsed deadlines because differing fractional-second precision breaks timestamp text ordering.
    pub fn expire_due_approvals(&mut self, now: OffsetDateTime) -> LedgerResult<Vec<Approval>> {
        let due: Vec<(ApprovalId, i64)> = self
            .approvals()?
            .into_iter()
            .filter(|approval| {
                matches!(
                    approval.status,
                    ApprovalStatus::Requested | ApprovalStatus::Approved
                ) && approval.expires_at <= now
            })
            .map(|approval| (approval.approval_id, approval.revision))
            .collect();
        let mut expired = Vec::new();
        for (approval_id, revision) in due {
            if let ExpireApproval::Expired(approval) =
                self.expire_approval(&approval_id, now, revision)?
            {
                expired.push(approval);
            }
        }
        Ok(expired)
    }

    /// Consumes an approved record once and only for the exact approved scope.
    ///
    /// If the record has reached its deadline, this call atomically expires it
    /// instead of authorizing the command.
    pub fn consume_approval(
        &mut self,
        approval_id: &ApprovalId,
        scope: &ApprovalScope,
        command_id: &CommandId,
        now: OffsetDateTime,
        expected_revision: i64,
    ) -> LedgerResult<ConsumeApproval> {
        self.with_tx(|transaction| {
            let Some(current) = load_approval(transaction, approval_id)? else {
                return Ok(ConsumeApproval::NotFound);
            };
            require_revision(&current, expected_revision)?;
            if current.scope != *scope {
                return Ok(ConsumeApproval::ScopeMismatch(current));
            }
            if current.status != ApprovalStatus::Approved {
                return Ok(ConsumeApproval::NotAuthorized(current));
            }
            if now >= current.expires_at {
                let changed = transaction.execute(
                    "UPDATE approvals
                     SET status = 'expired', revision = revision + 1
                     WHERE approval_id = ?1 AND revision = ?2 AND status = 'approved'",
                    params![approval_id.to_string(), expected_revision],
                )?;
                ensure_guarded_update(transaction, approval_id, expected_revision, changed)?;
                let expired = load_existing_approval(transaction, approval_id)?;
                crate::approval_feed::journal_approval_change(transaction, &expired, now)?;
                return Ok(ConsumeApproval::Expired(expired));
            }

            // Use the parsed deadline check above: "…:00.5Z" sorts before "…:00Z" despite being later.
            let changed = transaction.execute(
                "UPDATE approvals
                 SET status = 'consumed', consumed_by_command_id = ?1,
                     revision = revision + 1
                 WHERE approval_id = ?2 AND revision = ?3 AND status = 'approved'
                   AND target_kind = ?4 AND target_id = ?5 AND capability_id = ?6
                   AND arguments_hash = ?7",
                params![
                    command_id.to_string(),
                    approval_id.to_string(),
                    expected_revision,
                    scope.target_kind,
                    scope.target_id,
                    scope.capability_id.to_string(),
                    scope.arguments_digest.to_string(),
                ],
            )?;
            ensure_guarded_update(transaction, approval_id, expected_revision, changed)?;
            let consumed = load_existing_approval(transaction, approval_id)?;
            crate::approval_feed::journal_approval_change(transaction, &consumed, now)?;
            Ok(ConsumeApproval::Consumed(consumed))
        })
    }
}

fn insert_requested(
    transaction: &Transaction<'_>,
    request: &NewApproval,
) -> LedgerResult<Approval> {
    if request.expires_at <= request.requested_at {
        return Err(LedgerError::invalid_data(
            "approval expiry must be later than its request time".into(),
        ));
    }
    if !is_schema_id(&request.issuer) {
        return Err(LedgerError::invalid_data(
            "approval issuer must be a schema id".into(),
        ));
    }
    if request.scope.target_kind.is_empty() || !is_schema_id(&request.scope.target_id) {
        return Err(LedgerError::invalid_data(
            "approval scope must name a target".into(),
        ));
    }
    transaction.execute(
        "INSERT INTO approvals (
                approval_id, status, issuer, target_kind, target_id, capability_id,
                arguments_hash, requested_at, expires_at, revision
             ) VALUES (?1, 'requested', ?2, ?3, ?4, ?5, ?6, ?7, ?8, 1)",
        params![
            request.approval_id.to_string(),
            request.issuer,
            request.scope.target_kind,
            request.scope.target_id,
            request.scope.capability_id.to_string(),
            request.scope.arguments_digest.to_string(),
            encode_utc(request.requested_at)?,
            encode_utc(request.expires_at)?,
        ],
    )?;
    let approval = load_approval(transaction, &request.approval_id)?.ok_or_else(|| {
        LedgerError::invalid_data(
            "inserted approval was not readable in its transaction".to_owned(),
        )
    })?;
    crate::approval_feed::journal_approval_change(transaction, &approval, approval.requested_at)?;
    Ok(approval)
}

/// `owner_witnessed` marks the authenticated owner-intake settlement: its
/// approval of a scope that needs the complete preview must name the
/// canonical delivery of exactly this content, or nothing is decided.
#[allow(clippy::too_many_arguments)]
fn decide_in_tx(
    transaction: &Transaction<'_>,
    approval_id: &ApprovalId,
    decision: &ApprovalDecision,
    decided_by: &str,
    decided_at: OffsetDateTime,
    expected_revision: i64,
    owner_witnessed: bool,
    owner_preview: bool,
) -> LedgerResult<DecideApproval> {
    if !is_schema_id(decided_by) {
        return Err(LedgerError::invalid_data(
            "approval decidedBy must be null or a schema id".into(),
        ));
    }
    let evidence_ref = match decision {
        ApprovalDecision::Approve { evidence_ref } => evidence_ref.as_deref(),
        ApprovalDecision::Deny { evidence_ref } => Some(evidence_ref.as_str()),
    };
    if evidence_ref.is_some_and(str::is_empty) {
        return Err(LedgerError::invalid_data(
            "approval decision evidence must be null or a nonempty string".into(),
        ));
    }
    let Some(current) = load_approval(transaction, approval_id)? else {
        return Ok(DecideApproval::NotFound);
    };
    require_revision(&current, expected_revision)?;
    if current.status != ApprovalStatus::Requested {
        return Ok(DecideApproval::NotRequested(current));
    }
    if owner_witnessed
        && matches!(decision, ApprovalDecision::Approve { .. })
        && requires_owner_preview(&current.scope, owner_preview)
    {
        let delivered = match preview_event(evidence_ref) {
            Some(event) => {
                delivered_preview(transaction, &current, expected_revision, Some(event))?.is_some()
            }
            None => false,
        };
        if !delivered {
            return Ok(DecideApproval::PreviewRequired(current));
        }
    }

    let status = match decision {
        ApprovalDecision::Approve { .. } => "approved",
        ApprovalDecision::Deny { .. } => "denied",
    };
    let changed = transaction.execute(
        "UPDATE approvals
         SET status = ?1, decided_at = ?2, decided_by = ?3,
             decision_evidence_ref = ?4, revision = revision + 1
         WHERE approval_id = ?5 AND revision = ?6 AND status = 'requested'",
        params![
            status,
            encode_utc(decided_at)?,
            decided_by,
            evidence_ref,
            approval_id.to_string(),
            expected_revision,
        ],
    )?;
    ensure_guarded_update(transaction, approval_id, expected_revision, changed)?;
    let decided = load_existing_approval(transaction, approval_id)?;
    crate::approval_feed::journal_approval_change(transaction, &decided, decided_at)?;
    Ok(DecideApproval::Decided(decided))
}

fn preview_event(evidence_ref: Option<&str>) -> Option<&str> {
    evidence_ref?.strip_prefix(OWNER_PREVIEW_EVIDENCE_PREFIX)
}

/// The newest canonical complete delivery of exactly this approval's
/// immutable content (id, capability, arguments digest) shown no later than
/// `revision`; `event` restricts it to one named record. Its lineage must be
/// the approval's own: the delivered revision and target are this
/// approval's journaled pending state at that revision, so a later
/// authorized carry keeps the evidence and no other target can lend it.
fn delivered_preview(
    connection: &Connection,
    approval: &Approval,
    revision: i64,
    event: Option<&str>,
) -> LedgerResult<Option<String>> {
    let mut statement = connection.prepare(
        "SELECT event_id, json_extract(payload_json, '$.revision'),
                json_extract(payload_json, '$.session')
         FROM audit_events
         WHERE kind = ?1
           AND json_extract(payload_json, '$.approvalId') = ?2
           AND json_extract(payload_json, '$.capabilityId') = ?3
           AND json_extract(payload_json, '$.argumentsDigest') = ?4
           AND json_extract(payload_json, '$.completeSnapshot') = 1
           AND json_extract(payload_json, '$.revision') <= ?5
           AND (?6 IS NULL OR event_id = ?6)
         ORDER BY sequence DESC",
    )?;
    let deliveries = statement.query_map(
        params![
            OWNER_PREVIEW_DELIVERY_KIND,
            approval.approval_id.as_str(),
            approval.scope.capability_id.as_str(),
            approval.scope.arguments_digest.to_string(),
            revision,
            event,
        ],
        |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, Option<i64>>(1)?,
                row.get::<_, Option<String>>(2)?,
            ))
        },
    )?;
    for delivery in deliveries {
        let (event_id, Some(shown), Some(session)) = delivery? else {
            continue;
        };
        let pending = crate::approval_feed::approval_event_id(&approval.approval_id, shown)?;
        let lineage: bool = connection.query_row(
            "SELECT EXISTS (SELECT 1 FROM events
               WHERE event_id = ?1 AND kind = 'approval.requested'
                 AND json_extract(payload_json, '$.scope.targetKind') = ?2
                 AND json_extract(payload_json, '$.scope.targetId') = ?3
                 AND json_extract(payload_json, '$.scope.capabilityId') = ?4
                 AND json_extract(payload_json, '$.scope.argumentsDigest') = ?5)",
            params![
                pending.to_string(),
                approval.scope.target_kind,
                session,
                approval.scope.capability_id.as_str(),
                approval.scope.arguments_digest.to_string(),
            ],
            |row| row.get(0),
        )?;
        if lineage {
            return Ok(Some(event_id));
        }
    }
    Ok(None)
}

struct RawApproval {
    approval_id: String,
    status: String,
    issuer: String,
    target_kind: String,
    target_id: String,
    capability_id: String,
    arguments_hash: String,
    requested_at: String,
    expires_at: String,
    decided_at: Option<String>,
    decided_by: Option<String>,
    consumed_by_command_id: Option<String>,
    decision_evidence_ref: Option<String>,
    revision: i64,
}

pub(crate) fn load_approval(
    connection: &Connection,
    approval_id: &ApprovalId,
) -> LedgerResult<Option<Approval>> {
    let raw = connection
        .query_row(
            "SELECT approval_id, status, issuer, target_kind, target_id, capability_id,
                    arguments_hash, requested_at, expires_at, decided_at, decided_by,
                    consumed_by_command_id, decision_evidence_ref, revision
             FROM approvals WHERE approval_id = ?1",
            [approval_id.to_string()],
            read_approval_row,
        )
        .optional()?;
    raw.map(Approval::try_from).transpose()
}

fn read_approval_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<RawApproval> {
    Ok(RawApproval {
        approval_id: row.get(0)?,
        status: row.get(1)?,
        issuer: row.get(2)?,
        target_kind: row.get(3)?,
        target_id: row.get(4)?,
        capability_id: row.get(5)?,
        arguments_hash: row.get(6)?,
        requested_at: row.get(7)?,
        expires_at: row.get(8)?,
        decided_at: row.get(9)?,
        decided_by: row.get(10)?,
        consumed_by_command_id: row.get(11)?,
        decision_evidence_ref: row.get(12)?,
        revision: row.get(13)?,
    })
}

fn load_existing_approval(
    connection: &Connection,
    approval_id: &ApprovalId,
) -> LedgerResult<Approval> {
    load_approval(connection, approval_id)?.ok_or_else(|| {
        LedgerError::invalid_data("approval vanished during guarded mutation".to_owned())
    })
}

impl TryFrom<RawApproval> for Approval {
    type Error = LedgerError;

    fn try_from(raw: RawApproval) -> LedgerResult<Self> {
        let approval_id = parse_id(&raw.approval_id, 0)?;
        decode_approval(approval_id, raw)
    }
}

fn decode_approval(approval_id: ApprovalId, raw: RawApproval) -> LedgerResult<Approval> {
    let approval = Approval {
        approval_id,
        status: parse_status(&raw.status)?,
        issuer: raw.issuer,
        scope: ApprovalScope {
            target_kind: raw.target_kind,
            target_id: raw.target_id,
            capability_id: parse_id(&raw.capability_id, 5)?,
            arguments_digest: parse_id(&raw.arguments_hash, 6)?,
        },
        requested_at: decode_utc(&raw.requested_at)?,
        expires_at: decode_utc(&raw.expires_at)?,
        decided_at: raw.decided_at.as_deref().map(decode_utc).transpose()?,
        decided_by: raw.decided_by,
        consumed_by_command_id: raw
            .consumed_by_command_id
            .as_deref()
            .map(|value| parse_id(value, 11))
            .transpose()?,
        decision_evidence_ref: raw.decision_evidence_ref,
        revision: raw.revision,
    };
    validate_approval_record(&approval)?;
    Ok(approval)
}

fn parse_status(value: &str) -> LedgerResult<ApprovalStatus> {
    match value {
        "requested" => Ok(ApprovalStatus::Requested),
        "approved" => Ok(ApprovalStatus::Approved),
        "denied" => Ok(ApprovalStatus::Denied),
        "expired" => Ok(ApprovalStatus::Expired),
        "consumed" => Ok(ApprovalStatus::Consumed),
        "cancelled" => Ok(ApprovalStatus::Cancelled),
        other => Err(LedgerError::invalid_data(format!(
            "unknown approval status {other:?}"
        ))),
    }
}

fn require_revision(approval: &Approval, expected_revision: i64) -> LedgerResult<()> {
    if approval.revision == expected_revision {
        Ok(())
    } else {
        Err(LedgerError::StaleActor {
            actor: format!("approval:{}", approval.approval_id),
            expected_revision,
            actual_revision: approval.revision,
        })
    }
}

fn ensure_guarded_update(
    connection: &Connection,
    approval_id: &ApprovalId,
    expected_revision: i64,
    changed: usize,
) -> LedgerResult<()> {
    if changed == 1 {
        return Ok(());
    }
    let current = load_existing_approval(connection, approval_id)?;
    Err(LedgerError::StaleActor {
        actor: format!("approval:{approval_id}"),
        expected_revision,
        actual_revision: current.revision,
    })
}

#[cfg(test)]
mod tests {
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };

    use rusqlite::hooks::{AuthAction, AuthContext, Authorization};

    use odin_domain::{ApprovalId, CapabilityId, CommandId, Digest};
    use rusqlite::params;
    use time::{Duration, OffsetDateTime};

    use super::{ApprovalDecision, ApprovalScope, ConsumeApproval, DecideApproval, NewApproval};
    use crate::{encode_utc, Ledger};

    fn now() -> OffsetDateTime {
        OffsetDateTime::from_unix_timestamp(1_800_000_000).unwrap()
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

    fn approve(ledger: &mut Ledger, id: &str) {
        let result = ledger
            .decide_approval(
                &ApprovalId::new(id).unwrap(),
                ApprovalDecision::Approve { evidence_ref: None },
                "human:one",
                now() + Duration::seconds(1),
                1,
            )
            .unwrap();
        assert!(matches!(result, DecideApproval::Decided(_)));
    }

    #[test]
    fn approvals_use_one_select_and_preserve_rows_on_every_poll() {
        for count in [0, 1, 8, 32] {
            let mut ledger = Ledger::open_in_memory().unwrap();
            let mut expected = Vec::new();
            // Reverse insertion order also exercises every nullable approval field.
            for index in (0..count).rev() {
                let id = format!("approval:poll-{index:03}");
                let approval_id = ApprovalId::new(id.as_str()).unwrap();
                let approval_scope = scope(id.as_bytes());
                request(&mut ledger, &id, approval_scope.clone());
                if index % 4 != 3 {
                    let decision = if index % 4 == 2 {
                        ApprovalDecision::Deny {
                            evidence_ref: format!("artifact:denial-{index}"),
                        }
                    } else {
                        ApprovalDecision::Approve {
                            evidence_ref: Some(format!("artifact:approval-{index}")),
                        }
                    };
                    ledger
                        .decide_approval(
                            &approval_id,
                            decision,
                            "human:one",
                            now() + Duration::seconds(1),
                            1,
                        )
                        .unwrap();
                    if index % 4 == 0 {
                        let command_id =
                            CommandId::new(format!("command:poll-{index:03}")).unwrap();
                        insert_command(&ledger, &command_id, &approval_scope);
                        assert!(matches!(
                            ledger
                                .consume_approval(
                                    &approval_id,
                                    &approval_scope,
                                    &command_id,
                                    now() + Duration::seconds(2),
                                    2,
                                )
                                .unwrap(),
                            ConsumeApproval::Consumed(_)
                        ));
                    }
                }
                expected.push(ledger.approval(&approval_id).unwrap().unwrap());
            }
            expected
                .sort_by(|left, right| left.approval_id.as_str().cmp(right.approval_id.as_str()));

            let selects = Arc::new(AtomicUsize::new(0));
            let observed = Arc::clone(&selects);
            // These paths prepare uncached statements, so Select counts each query.
            ledger
                .connection()
                .authorizer(Some(move |context: AuthContext<'_>| {
                    if matches!(context.action, AuthAction::Select) {
                        observed.fetch_add(1, Ordering::Relaxed);
                    }
                    Authorization::Allow
                }));
            for _ in 0..2 {
                selects.store(0, Ordering::Relaxed);
                assert_eq!(ledger.approvals().unwrap(), expected);
                assert_eq!(selects.load(Ordering::Relaxed), 1, "row count {count}");
            }

            request(&mut ledger, "approval:added", scope(b"added"));
            let added_id = ApprovalId::new("approval:added").unwrap();
            expected.insert(0, ledger.approval(&added_id).unwrap().unwrap());
            selects.store(0, Ordering::Relaxed);
            assert_eq!(ledger.approvals().unwrap(), expected);
            assert_eq!(selects.load(Ordering::Relaxed), 1);

            approve(&mut ledger, "approval:added");
            expected[0] = ledger.approval(&added_id).unwrap().unwrap();
            selects.store(0, Ordering::Relaxed);
            assert_eq!(ledger.approvals().unwrap(), expected);
            assert_eq!(selects.load(Ordering::Relaxed), 1);
        }
    }

    #[test]
    fn approvals_preserve_single_row_decode_errors_and_validation() {
        for update in [
            "UPDATE approvals SET capability_id = 'invalid id'",
            "UPDATE approvals SET arguments_hash = 'invalid digest'",
            "UPDATE approvals SET requested_at = 'invalid time'",
            "UPDATE approvals SET expires_at = requested_at",
            "UPDATE approvals SET decided_at = requested_at",
            "UPDATE approvals SET status = 'approved'",
            "UPDATE approvals SET decision_evidence_ref = ''",
            "UPDATE approvals SET issuer = 'invalid id'",
        ] {
            let mut ledger = Ledger::open_in_memory().unwrap();
            request(&mut ledger, "approval:invalid", scope(b"invalid"));
            ledger.connection().execute(update, []).unwrap();
            let single = ledger
                .approval(&ApprovalId::new("approval:invalid").unwrap())
                .unwrap_err();
            let bulk = ledger.approvals().unwrap_err();
            assert_eq!(
                std::mem::discriminant(&bulk),
                std::mem::discriminant(&single)
            );
            assert_eq!(bulk.to_string(), single.to_string(), "{update}");
        }

        let mut ledger = Ledger::open_in_memory().unwrap();
        request(&mut ledger, "approval:invalid", scope(b"invalid"));
        ledger
            .connection()
            .execute("UPDATE approvals SET approval_id = 'invalid id'", [])
            .unwrap();
        assert!(matches!(
            ledger.approvals(),
            Err(crate::LedgerError::InvalidData { .. })
        ));
    }

    #[test]
    fn unknown_approval_status_is_invalid_data() {
        let mut ledger = Ledger::open_in_memory().unwrap();
        request(&mut ledger, "approval:bogus", scope(b"bogus"));
        // Bypass the write constraint to exercise a corrupt stored status.
        ledger
            .connection()
            .pragma_update(None, "ignore_check_constraints", "ON")
            .unwrap();
        ledger
            .connection()
            .execute("UPDATE approvals SET status = 'bogus'", [])
            .unwrap();
        ledger
            .connection()
            .pragma_update(None, "ignore_check_constraints", "OFF")
            .unwrap();
        let error = ledger
            .approval(&ApprovalId::new("approval:bogus").unwrap())
            .expect_err("bogus status");
        let crate::LedgerError::InvalidData { source, .. } = error else {
            panic!("expected invalid data, got {error}");
        };
        assert!(source.is_none());
    }

    fn insert_command(ledger: &Ledger, id: &CommandId, approval_scope: &ApprovalScope) {
        ledger
            .connection()
            .execute(
                "INSERT INTO commands (
                    command_id, idempotency_key, correlation_id, issuer, target_kind,
                    target_id, capability_id, capability_version, arguments_hash,
                    arguments_json, issued_at, expires_at
                 ) VALUES (?1, ?2, ?3, 'seat:normal', ?4, ?5, ?6, 1, ?7, '{}', ?8, ?9)",
                params![
                    id.to_string(),
                    format!("key:{id}"),
                    format!("correlation:{id}"),
                    approval_scope.target_kind,
                    approval_scope.target_id,
                    approval_scope.capability_id.to_string(),
                    approval_scope.arguments_digest.to_string(),
                    encode_utc(now()).unwrap(),
                    encode_utc(now() + Duration::minutes(5)).unwrap(),
                ],
            )
            .unwrap();
    }

    /// Only open approvals follow the target; their exact arguments stay unchanged.
    #[test]
    fn open_approvals_follow_their_target_and_stay_consumable_there() {
        let mut ledger = Ledger::open_in_memory().unwrap();
        let at = |target: &str, arguments: &[u8]| ApprovalScope {
            target_kind: "run".to_owned(),
            target_id: target.to_owned(),
            capability_id: CapabilityId::new("cap:write").unwrap(),
            arguments_digest: Digest::hash(arguments),
        };
        request(&mut ledger, "approval:asked", at("run:live:old", b"asked"));
        request(
            &mut ledger,
            "approval:granted",
            at("run:live:old", b"granted"),
        );
        approve(&mut ledger, "approval:granted");
        request(&mut ledger, "approval:spent", at("run:live:old", b"spent"));
        approve(&mut ledger, "approval:spent");
        let spent_command = CommandId::new("command:spent").unwrap();
        insert_command(&ledger, &spent_command, &at("run:live:old", b"spent"));
        assert!(matches!(
            ledger
                .consume_approval(
                    &ApprovalId::new("approval:spent").unwrap(),
                    &at("run:live:old", b"spent"),
                    &spent_command,
                    now() + Duration::seconds(2),
                    2,
                )
                .unwrap(),
            ConsumeApproval::Consumed(_)
        ));
        request(
            &mut ledger,
            "approval:other",
            at("run:live:elsewhere", b"other"),
        );

        let moved = ledger
            .follow_approval_target(
                "run",
                "run:live:old",
                "run:live:new",
                now() + Duration::seconds(3),
            )
            .unwrap();
        let moved: Vec<String> = moved.iter().map(ToString::to_string).collect();
        assert_eq!(moved, vec!["approval:asked", "approval:granted"]);
        let target = |id: &str| {
            ledger
                .approval(&ApprovalId::new(id).unwrap())
                .unwrap()
                .unwrap()
                .scope
                .target_id
        };
        assert_eq!(target("approval:spent"), "run:live:old");
        assert_eq!(target("approval:other"), "run:live:elsewhere");

        let retry = CommandId::new("command:retry").unwrap();
        insert_command(&ledger, &retry, &at("run:live:new", b"granted"));
        let revision = ledger
            .approval(&ApprovalId::new("approval:granted").unwrap())
            .unwrap()
            .unwrap()
            .revision;
        assert!(matches!(
            ledger
                .consume_approval(
                    &ApprovalId::new("approval:granted").unwrap(),
                    &at("run:live:new", b"granted"),
                    &retry,
                    now() + Duration::seconds(4),
                    revision,
                )
                .unwrap(),
            ConsumeApproval::Consumed(_)
        ));

        // Past its expiry an open approval stays where it was.
        request(&mut ledger, "approval:late", at("run:live:new", b"late"));
        let moved = ledger
            .follow_approval_target(
                "run",
                "run:live:new",
                "run:live:next",
                now() + Duration::minutes(10),
            )
            .unwrap();
        assert!(moved.is_empty());
    }

    #[test]
    fn changed_scope_cannot_consume_and_consumption_is_once() {
        let mut ledger = Ledger::open_in_memory().unwrap();
        let approved_scope = scope(b"original");
        request(&mut ledger, "approval:scope", approved_scope.clone());
        approve(&mut ledger, "approval:scope");

        let command_id = CommandId::new("command:one").unwrap();
        insert_command(&ledger, &command_id, &approved_scope);
        let mismatch = ledger
            .consume_approval(
                &ApprovalId::new("approval:scope").unwrap(),
                &scope(b"changed"),
                &command_id,
                now() + Duration::seconds(2),
                2,
            )
            .unwrap();
        assert!(matches!(mismatch, ConsumeApproval::ScopeMismatch(_)));
        assert_eq!(
            ledger
                .approval(&ApprovalId::new("approval:scope").unwrap())
                .unwrap()
                .unwrap()
                .revision,
            2
        );

        let consumed = ledger
            .consume_approval(
                &ApprovalId::new("approval:scope").unwrap(),
                &approved_scope,
                &command_id,
                now() + Duration::seconds(2),
                2,
            )
            .unwrap();
        assert!(matches!(consumed, ConsumeApproval::Consumed(_)));
        let second = ledger
            .consume_approval(
                &ApprovalId::new("approval:scope").unwrap(),
                &approved_scope,
                &command_id,
                now() + Duration::seconds(3),
                3,
            )
            .unwrap();
        assert!(matches!(second, ConsumeApproval::NotAuthorized(_)));
    }

    #[test]
    fn due_approvals_expire_and_live_ones_stay() {
        let mut ledger = Ledger::open_in_memory().unwrap();
        request(&mut ledger, "approval:stale", scope(b"stale"));
        request(&mut ledger, "approval:decided", scope(b"decided"));
        approve(&mut ledger, "approval:decided");
        let consumed_later = ledger
            .approval(&ApprovalId::new("approval:stale").unwrap())
            .unwrap()
            .unwrap();
        let before = consumed_later.expires_at - Duration::seconds(1);
        assert!(
            ledger.expire_due_approvals(before).unwrap().is_empty(),
            "nothing is due yet"
        );
        let after = consumed_later.expires_at + Duration::seconds(1);
        let expired = ledger.expire_due_approvals(after).unwrap();
        let ids: Vec<String> = expired.iter().map(|a| a.approval_id.to_string()).collect();
        assert!(ids.contains(&"approval:stale".to_owned()), "{ids:?}");
        assert_eq!(
            ledger
                .approval(&ApprovalId::new("approval:stale").unwrap())
                .unwrap()
                .unwrap()
                .status,
            odin_domain::ApprovalStatus::Expired
        );
        assert!(
            ledger.expire_due_approvals(after).unwrap().is_empty(),
            "expired once"
        );
    }

    #[test]
    fn expired_and_denied_approvals_never_authorize() {
        let mut ledger = Ledger::open_in_memory().unwrap();
        let approval_scope = scope(b"same");
        request(&mut ledger, "approval:expired", approval_scope.clone());
        approve(&mut ledger, "approval:expired");
        let command_id = CommandId::new("command:expired").unwrap();
        insert_command(&ledger, &command_id, &approval_scope);
        let expired = ledger
            .consume_approval(
                &ApprovalId::new("approval:expired").unwrap(),
                &approval_scope,
                &command_id,
                now() + Duration::minutes(5),
                2,
            )
            .unwrap();
        assert!(matches!(expired, ConsumeApproval::Expired(_)));

        request(&mut ledger, "approval:denied", approval_scope.clone());
        let denied = ledger
            .decide_approval(
                &ApprovalId::new("approval:denied").unwrap(),
                ApprovalDecision::Deny {
                    evidence_ref: "artifact:denial".to_owned(),
                },
                "human:one",
                now() + Duration::seconds(1),
                1,
            )
            .unwrap();
        let DecideApproval::Decided(denied) = denied else {
            panic!("denial was not recorded");
        };
        assert_eq!(
            denied.decision_evidence_ref.as_deref(),
            Some("artifact:denial")
        );
        let denied_consumption = ledger
            .consume_approval(
                &ApprovalId::new("approval:denied").unwrap(),
                &approval_scope,
                &command_id,
                now() + Duration::seconds(2),
                2,
            )
            .unwrap();
        assert!(matches!(
            denied_consumption,
            ConsumeApproval::NotAuthorized(_)
        ));
    }

    /// Fractional RFC3339 deadlines must follow time order, not text order.
    #[test]
    fn same_second_fractional_expiry_follows_the_parsed_law() {
        fn half_second_out(ledger: &mut Ledger, id: &str, approval_scope: &ApprovalScope) {
            ledger
                .request_approval(NewApproval {
                    approval_id: ApprovalId::new(id).unwrap(),
                    issuer: "seat:normal".to_owned(),
                    scope: approval_scope.clone(),
                    requested_at: now(),
                    expires_at: now() + Duration::milliseconds(500),
                })
                .unwrap();
            let decided = ledger
                .decide_approval(
                    &ApprovalId::new(id).unwrap(),
                    ApprovalDecision::Approve { evidence_ref: None },
                    "human:one",
                    now(),
                    1,
                )
                .unwrap();
            assert!(matches!(decided, DecideApproval::Decided(_)));
        }

        let mut ledger = Ledger::open_in_memory().unwrap();
        let approval_scope = scope(b"half-second");
        half_second_out(&mut ledger, "approval:half", &approval_scope);
        let command_id = CommandId::new("command:half").unwrap();
        insert_command(&ledger, &command_id, &approval_scope);

        // The deadline sits 500 ms inside the SAME second as the
        // whole-second `now`: parsed time says it is still valid, so the
        // approval consumes exactly once.
        let consumed = ledger
            .consume_approval(
                &ApprovalId::new("approval:half").unwrap(),
                &approval_scope,
                &command_id,
                now(),
                2,
            )
            .unwrap();
        assert!(matches!(consumed, ConsumeApproval::Consumed(_)));
        let replay = ledger
            .consume_approval(
                &ApprovalId::new("approval:half").unwrap(),
                &approval_scope,
                &command_id,
                now(),
                3,
            )
            .unwrap();
        assert!(matches!(replay, ConsumeApproval::NotAuthorized(_)));

        half_second_out(&mut ledger, "approval:exact", &approval_scope);
        let exact_command = CommandId::new("command:exact").unwrap();
        insert_command(&ledger, &exact_command, &approval_scope);
        // Scope and revision guards run before expiry checks without changing the row.
        let mismatch = ledger
            .consume_approval(
                &ApprovalId::new("approval:exact").unwrap(),
                &scope(b"changed"),
                &exact_command,
                now(),
                2,
            )
            .unwrap();
        assert!(matches!(mismatch, ConsumeApproval::ScopeMismatch(_)));
        assert!(
            ledger
                .consume_approval(
                    &ApprovalId::new("approval:exact").unwrap(),
                    &approval_scope,
                    &exact_command,
                    now(),
                    1,
                )
                .is_err(),
            "a stale revision is refused without touching the row"
        );

        // The exact expiry instant expires rather than authorizes.
        let expired = ledger
            .consume_approval(
                &ApprovalId::new("approval:exact").unwrap(),
                &approval_scope,
                &exact_command,
                now() + Duration::milliseconds(500),
                2,
            )
            .unwrap();
        assert!(matches!(expired, ConsumeApproval::Expired(_)));
        let row = ledger
            .approval(&ApprovalId::new("approval:exact").unwrap())
            .unwrap()
            .unwrap();
        assert_eq!(row.status, odin_domain::ApprovalStatus::Expired);
        assert_eq!(row.revision, 3);
    }

    #[test]
    fn owner_witness_requires_authenticated_intake_and_preserves_exact_target_carry() {
        let mut ledger = Ledger::open_in_memory().unwrap();
        let id = ApprovalId::new("approval:owner-plan").unwrap();
        let lookalike = ApprovalId::new("approval:lookalike").unwrap();
        let decision = || ApprovalDecision::Approve {
            evidence_ref: Some("delivery:one".to_owned()),
        };
        request(&mut ledger, lookalike.as_str(), scope(b"plan"));
        ledger
            .decide_approval(&lookalike, decision(), "discord-owner:one", now(), 1)
            .unwrap();
        let plain = ledger.approval(&lookalike).unwrap().unwrap();
        assert!(!ledger.approval_has_owner_decision(&plain, false).unwrap());

        request(&mut ledger, id.as_str(), scope(b"plan"));
        ledger
            .decide_approval_consuming_intake(
                &id,
                decision(),
                "discord-owner:one",
                now(),
                1,
                &super::DecisionIntake {
                    consumer_id: "discord-owner:one".to_owned(),
                    message_id: "message:one".to_owned(),
                },
                false,
            )
            .unwrap();
        let approved = ledger.approval(&id).unwrap().unwrap();
        assert!(ledger
            .approval_has_owner_decision(&approved, false)
            .unwrap());
        let mut altered = approved.clone();
        altered.scope.arguments_digest = Digest::hash(b"changed plan");
        assert!(!ledger.approval_has_owner_decision(&altered, false).unwrap());
        altered = approved.clone();
        altered.scope.target_id = "lane:unrelated".to_owned();
        assert!(!ledger.approval_has_owner_decision(&altered, false).unwrap());

        ledger
            .follow_approval_target("lane", "lane:one", "lane:successor", now())
            .unwrap();
        let followed = ledger.approval(&id).unwrap().unwrap();
        assert!(ledger
            .approval_has_owner_decision(&followed, false)
            .unwrap());
        assert!(!ledger
            .approval_has_owner_decision(&approved, false)
            .unwrap());
        let command = CommandId::new("command:owner-plan").unwrap();
        insert_command(&ledger, &command, &followed.scope);
        ledger
            .consume_approval(&id, &followed.scope, &command, now(), followed.revision)
            .unwrap();
        let consumed = ledger.approval(&id).unwrap().unwrap();
        assert!(ledger
            .approval_has_owner_decision(&consumed, false)
            .unwrap());
        assert!(!ledger
            .approval_has_owner_decision(&ledger.approval(&lookalike).unwrap().unwrap(), false)
            .unwrap());
    }

    /// Records the delivery audit event emitted by Hermes.
    fn deliver(ledger: &Ledger, event: &str, approval: &super::Approval, complete: bool) {
        let payload = serde_json::json!({
            "approvalId": approval.approval_id.as_str(),
            "revision": approval.revision,
            "capabilityId": approval.scope.capability_id.as_str(),
            "argumentsDigest": approval.scope.arguments_digest.to_string(),
            "session": approval.scope.target_id,
            "completeSnapshot": complete,
        });
        ledger
            .append_audit_event(crate::audit::NewAuditEvent {
                event_id: odin_domain::EventId::new(event).unwrap(),
                kind: super::OWNER_PREVIEW_DELIVERY_KIND.to_owned(),
                actor: odin_domain::Actor::System {
                    name: "odin-hermes.runtime".to_owned(),
                },
                scope: odin_domain::Scope::default(),
                evidence: Vec::new(),
                payload: crate::audit::RedactedPayload::new(payload, odin_domain::Redaction::None)
                    .unwrap(),
                occurred_at: now(),
            })
            .unwrap();
    }

    #[test]
    fn preview_consent_binds_only_the_complete_delivery_of_this_content_and_survives_carry() {
        let mut ledger = Ledger::open_in_memory().unwrap();
        let id = ApprovalId::new("approval:preview").unwrap();
        request(
            &mut ledger,
            id.as_str(),
            ApprovalScope {
                target_kind: "run".to_owned(),
                target_id: "run:live:one".to_owned(),
                capability_id: CapabilityId::new("email.send").unwrap(),
                arguments_digest: Digest::hash(b"exact send"),
            },
        );
        let requested = ledger.approval(&id).unwrap().unwrap();
        let mut other = requested.clone();
        other.approval_id = ApprovalId::new("approval:other").unwrap();
        let mut changed = requested.clone();
        changed.scope.arguments_digest = Digest::hash(b"changed send");
        // Same content, but shown for a target this approval never had.
        let mut elsewhere = requested.clone();
        elsewhere.scope.target_id = "run:live:elsewhere".to_owned();
        deliver(&ledger, "event:clipped", &requested, false);
        deliver(&ledger, "event:other", &other, true);
        deliver(&ledger, "event:changed", &changed, true);
        deliver(&ledger, "event:elsewhere", &elsewhere, true);
        let intake = super::DecisionIntake {
            consumer_id: "huginn-owner:one".to_owned(),
            message_id: "message:one".to_owned(),
        };
        for evidence in [
            None,
            Some("event:clipped"),
            Some("delivery:event:clipped"),
            Some("delivery:event:other"),
            Some("delivery:event:changed"),
            Some("delivery:event:elsewhere"),
            Some("delivery:event:absent"),
        ] {
            let decision = ApprovalDecision::Approve {
                evidence_ref: evidence.map(str::to_owned),
            };
            let refused = ledger
                .decide_approval_consuming_intake(
                    &id,
                    decision,
                    "owner:one",
                    now(),
                    1,
                    &intake,
                    true,
                )
                .unwrap();
            assert!(
                matches!(refused, Some(DecideApproval::PreviewRequired(_))),
                "{evidence:?}"
            );
        }
        assert_eq!(ledger.owner_preview_evidence(&requested).unwrap(), None);
        deliver(&ledger, "event:complete", &requested, true);
        let evidence = ledger.owner_preview_evidence(&requested).unwrap();
        assert_eq!(evidence.as_deref(), Some("delivery:event:complete"));
        // Every refusal left the same request pending and its intake unspent.
        let decided = ledger
            .decide_approval_consuming_intake(
                &id,
                ApprovalDecision::Approve {
                    evidence_ref: evidence,
                },
                "owner:one",
                now(),
                1,
                &intake,
                true,
            )
            .unwrap();
        assert!(matches!(decided, Some(DecideApproval::Decided(_))));
        let approved = ledger.approval(&id).unwrap().unwrap();
        assert!(ledger.approval_has_owner_decision(&approved, true).unwrap());
        let mut forged = approved.clone();
        forged.decision_evidence_ref = Some("delivery:event:other".to_owned());
        assert!(!ledger.approval_has_owner_decision(&forged, true).unwrap());
        // An authorized carry moves only the conversation binding.
        ledger
            .follow_approval_target("run", "run:live:one", "run:live:two", now())
            .unwrap();
        let carried = ledger.approval(&id).unwrap().unwrap();
        assert_eq!(carried.scope.target_id, "run:live:two");
        assert!(ledger.approval_has_owner_decision(&carried, true).unwrap());
    }

    #[test]
    fn failed_owner_witness_rolls_back_decision_and_intake_together() {
        let mut ledger = Ledger::open_in_memory().unwrap();
        let id = ApprovalId::new("approval:owner-write-failure").unwrap();
        request(&mut ledger, id.as_str(), scope(b"plan"));
        let intake = super::DecisionIntake {
            consumer_id: "discord-owner:one".to_owned(),
            message_id: "message:retry".to_owned(),
        };
        ledger
            .connection()
            .execute_batch(
                "CREATE TRIGGER refuse_owner_witness BEFORE INSERT ON approval_owner_decisions
             BEGIN SELECT RAISE(ABORT, 'fixture owner witness failure'); END;",
            )
            .unwrap();
        assert!(ledger
            .decide_approval_consuming_intake(
                &id,
                ApprovalDecision::Approve { evidence_ref: None },
                "discord-owner:one",
                now(),
                1,
                &intake,
                false,
            )
            .is_err());
        let requested = ledger.approval(&id).unwrap().unwrap();
        assert_eq!(requested.status, odin_domain::ApprovalStatus::Requested);
        assert!(!ledger
            .approval_has_owner_decision(&requested, false)
            .unwrap());
        ledger
            .connection()
            .execute_batch("DROP TRIGGER refuse_owner_witness;")
            .unwrap();
        let settled = ledger
            .decide_approval_consuming_intake(
                &id,
                ApprovalDecision::Approve { evidence_ref: None },
                "discord-owner:one",
                now(),
                1,
                &intake,
                false,
            )
            .unwrap();
        assert!(matches!(settled, Some(DecideApproval::Decided(_))));
        assert!(ledger
            .approval_has_owner_decision(&ledger.approval(&id).unwrap().unwrap(), false)
            .unwrap());
    }

    #[test]
    fn refused_decision_does_not_consume_its_intake_identity() {
        let mut ledger = Ledger::open_in_memory().unwrap();
        let approval_id = ApprovalId::new("approval:intake-refusal").unwrap();
        let intake = super::DecisionIntake {
            consumer_id: "discord-owner:one".to_owned(),
            message_id: "message:one".to_owned(),
        };
        let absent = ledger
            .decide_approval_consuming_intake(
                &approval_id,
                ApprovalDecision::Approve { evidence_ref: None },
                "human:one",
                now(),
                1,
                &intake,
                false,
            )
            .unwrap();
        assert!(matches!(absent, Some(DecideApproval::NotFound)));
        request(&mut ledger, approval_id.as_str(), scope(b"write"));
        let settled = ledger
            .decide_approval_consuming_intake(
                &approval_id,
                ApprovalDecision::Approve { evidence_ref: None },
                "human:one",
                now(),
                1,
                &intake,
                false,
            )
            .unwrap();
        assert!(matches!(settled, Some(DecideApproval::Decided(_))));
    }
}
